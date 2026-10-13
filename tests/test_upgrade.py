"""Upgrade transactions on a real temporary filesystem; native/systemd calls stubbed."""
from contextlib import redirect_stdout
import importlib.machinery
import hashlib
import io
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_project_layout as layout
import test_installer as baseline
from test_installer import r, i, load


u = load('upgrade_transactions_test', 'vpn-stack-upgrade.py')


class UpgradeTests(unittest.TestCase):
    setUp = baseline.TemporaryRuntimeTests.setUp

    def fixture(self):
        project, package, _ = layout.InstallationTests.fixture(self)
        with redirect_stdout(io.StringIO()):
            i.install(package, '8.8.8.8', False)
        self.project, self.package = project, package
        self.enterContext(patch.object(u.sys, 'platform', 'linux'))
        self.enterContext(patch.object(u.os, 'geteuid', return_value=0))
        # PID 1 descriptor storage and guardian death/restart are exercised in
        # disposable Linux/systemd containers, not this mocked service fixture.
        self.enterContext(patch.object(u, 'arm_guardian'))
        self.s = SimpleNamespace(core=load('upgrade_policy_fixture', 'personal-policy.py'),
                                 parser=load('upgrade_parser_fixture', 'source-parser.py'),
                                 setup=load('upgrade_setup_fixture', 'transport-probes.py'))
        self.enterContext(patch.object(r, 'modules', return_value=self.s))
        self.enterContext(patch.object(r, 'unit_state', side_effect=lambda name:
            {'ActiveState': 'active' if name in (*u.CORE, *u.TRIGGERS, 'vpn-stack-device-recover.service') else 'inactive'}))
        old = r.DATA / 'generations/gen-old'
        old.mkdir()
        r.atomic(old / 'owner.json', r.dump({'schema': 1, 'kind': 'vpn-stack-generation'}))
        r.pointer(old)
        r.atomic(r.CONFIG, b'legacy verified backend\n', 0o640)
        r.atomic(r.DATA / 'last-result.json', r.dump({'status': 'legacy'}))
        self.previous = {'ip': {'source_CIDRs': ['104.16.0.0/13']}, 'counts': {'smart': 1, 'direct': 1, 'ads': 1}}
        self.enterContext(patch.object(r, 'wait_backend'))
        self.enterContext(patch.object(u, 'ready_dns'))
        self.enterContext(patch.object(u, 'ready_policy', return_value={'scope': 'stubbed'}))
        self.old = old
        self.enterContext(patch.object(r, 'active', return_value=(old, self.previous)))
        state = r.record(i.STATE)
        # Simulate an older public bundle and watcher from before ads.txt.
        path = r.CODE / 'vpn-stack-runtime.py'
        r.atomic(path, path.read_bytes() + b'\n# Previous installed revision\n', 0o644)
        state['package_files'][path.name] = r.digest(path)
        r.atomic(r.CODE / 'code-manifest.json', r.dump({'files': state['package_files']}), 0o644)
        path = i.UNIT_ROOT / 'vpn-stack-personal.path'
        r.atomic(path, path.read_bytes().replace(('PathChanged=' + str(r.ETC / 'ads.txt') + '\n').encode(), b''), 0o644)
        state['units'][path.name] = r.digest(path)
        r.atomic(i.STATE, r.dump(state))
        (r.ETC / 'ads.txt').unlink()
        r.atomic(r.ETC / 'proxy.txt', '# Мои правила\nexample.org\n'.encode())
        config = r.record(r.ETC / 'xray.json')
        registry = r.record(r.ETC / 'devices.json')
        config['inbounds'][0]['settings']['clients'].append(
            {'email': 'phone', 'id': '00000000-0000-4000-8000-000000000002', 'flow': 'xtls-rprx-vision'})
        registry['devices']['phone'] = {'uuid': '00000000-0000-4000-8000-000000000002', 'platform': 'universal'}
        r.atomic(r.ETC / 'xray.json', r.dump(config))
        registry['xray_sha256'] = r.digest(r.ETC / 'xray.json')
        r.atomic(r.ETC / 'devices.json', r.dump(registry))
        r.atomic(i.PROFILE_ROOT / 'phone-smart.json', b'manually customized client profile')
        self.preserved = {path: path.read_bytes() for path in
            (i.ROOT / 'identity.json', r.ETC / 'xray.json', r.ETC / 'devices.json',
             r.ETC / 'probe-client.json', r.ETC / 'settings.json', r.ETC / 'proxy.txt',
             i.PROFILE_ROOT / 'phone-smart.json')}
        self.before = {path: path.read_bytes() for path in (r.CONFIG, i.STATE, i.CLI,
            i.UNIT_ROOT / 'vpn-stack-personal.path', r.DATA / 'last-result.json')}
        self.stage = self.enterContext(patch.object(u, 'stage_policy', side_effect=self.stage_policy))
        self.activation = self.enterContext(patch.object(r, 'activate', side_effect=self.activate))
        r.run.reset_mock()
        return project, package

    def stage_policy(self, _i, runtime, _code, _work, _previous):
        values, snapshots = runtime.personal(self.s)
        return runtime, self.s, {'personal': values, 'personal_sha256': snapshots}

    def activate(self, s, work, manifest):
        config, _ = s.core.compose(r.base_config(s, work), manifest['personal'])
        r.atomic(r.CONFIG, config.encode(), 0o640)
        r.atomic(r.DATA / 'transaction.json', r.dump({'status': 'committed', 'before_source': str(self.old),
                                                    'after_source': str(work)}))
        r.pointer(work)
        result = {'status': 'active', 'source': work.name}
        r.atomic(r.DATA / 'last-result.json', r.dump(result))
        return result

    def assert_preserved(self):
        for path, raw in self.preserved.items():
            self.assertEqual(path.read_bytes(), raw, str(path))

    def run_upgrade(self, recover=False):
        with redirect_stdout(io.StringIO()):
            return u.upgrade(self.package, i, recover)

    def test_upgrade_preserves_identity_profiles_rules_and_switches_public_bundle(self):
        self.fixture()
        i.host_audit.reset_mock()
        result = self.run_upgrade()
        self.assertEqual(result['status'], 'upgraded')
        i.host_audit.assert_called_once_with(r, resume=True, minimum_memory_mib=512)
        self.assert_preserved()
        self.assertEqual(r.record(i.STATE)['package_files'], r.record(self.package / 'code-manifest.json')['files'])
        self.assertEqual(r.record(u.journal_path(i))['status'], 'committed')
        self.assertTrue((Path(result['backup']) / 'old-lib/bin/mihomo').is_file())
        self.assertEqual(r.CODE.stat().st_mode & 0o777, 0o755)
        self.assertEqual((r.CODE / 'bin').stat().st_mode & 0o777, 0o755)
        self.assertEqual((r.ETC / 'ads.txt').stat().st_mode & 0o777, 0o600)
        self.assertIn(str(r.ETC / 'ads.txt'), (i.UNIT_ROOT / 'vpn-stack-personal.path').read_text())
        self.assertEqual(self.run_upgrade()['status'], 'unchanged')

    def test_preflight_refuses_modified_code_unit_binary_and_cli_before_stopping(self):
        for target in ('code', 'unit', 'binary', 'cli'):
            with self.subTest(target=target):
                # Isolate each fixture's monkeypatches and directory setup.
                case = UpgradeTests()
                try:
                    case.setUp()
                    case.fixture()
                    path = {'code': r.CODE / 'personal-policy.py', 'unit': i.UNIT_ROOT / 'vpn-stack-dns.service',
                            'binary': r.CODE / 'bin/xray', 'cli': i.CLI}[target]
                    path.write_bytes(path.read_bytes() + b'edited externally')
                    with case.assertRaises(Exception):
                        case.run_upgrade()
                    self.assertFalse(any(call.args[0][:2] == ['systemctl', 'stop'] for call in r.run.call_args_list))
                    case.assert_preserved()
                finally:
                    case.doCleanups()

    def test_failed_policy_build_never_switches_code_or_stops_vpn(self):
        self.fixture()
        self.stage.side_effect = r.StackError('NEW_POLICY_REJECTED')
        old_manifest = (r.CODE / 'code-manifest.json').read_bytes()
        with self.assertRaisesRegex(r.StackError, 'NEW_POLICY_REJECTED'):
            self.run_upgrade()
        self.assertEqual((r.CODE / 'code-manifest.json').read_bytes(), old_manifest)
        self.assertFalse(any(call.args[0][:2] == ['systemctl', 'stop'] for call in r.run.call_args_list))
        self.assert_preserved()

    def test_failed_activation_restores_code_units_state_policy_and_triggers(self):
        self.fixture()
        def fail(s, work, manifest):
            self.activate(s, work, manifest)
            raise r.StackError('NEW_TRANSPORT_PROBE_FAILED')
        self.activation.side_effect = fail
        with self.assertRaisesRegex(r.StackError, 'NEW_TRANSPORT_PROBE_FAILED'):
            self.run_upgrade()
        self.assertEqual((r.DATA / 'current').resolve(), self.old)
        for path, raw in self.before.items():
            self.assertEqual(path.read_bytes(), raw, str(path))
        self.assertEqual(r.record(u.journal_path(i))['status'], 'rolled_back')
        self.assert_preserved()
        commands = [call.args[0] for call in r.run.call_args_list]
        self.assertIn(['systemctl', 'start', *u.TRIGGERS], commands)

    def test_commit_failure_after_state_write_restores_original_installation(self):
        self.fixture()
        save = u.save_journal
        def fail(i, r, journal):
            if journal['status'] == 'committed':
                raise r.StackError('UPGRADE_COMMIT_WRITE_FAILED')
            return save(i, r, journal)
        with patch.object(u, 'save_journal', side_effect=fail), self.assertRaisesRegex(r.StackError, 'UPGRADE_COMMIT_WRITE_FAILED'):
            self.run_upgrade()
        for path, raw in self.before.items():
            self.assertEqual(path.read_bytes(), raw, str(path))
        self.assert_preserved()
        self.assertEqual(r.record(u.journal_path(i))['status'], 'rolled_back')

    def interrupt_swap(self, destination_name):
        original_rename, original_recover = u.sync_rename, u.recover
        def rename(source, destination):
            original_rename(source, destination)
            if destination.name == destination_name:
                raise SystemExit('SIMULATED_PROCESS_LOSS')
        calls = 0
        def recovery(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls > 1:
                raise SystemExit('PROCESS_UNAVAILABLE_FOR_ROLLBACK')
            return original_recover(*args, **kwargs)
        with patch.object(u, 'sync_rename', side_effect=rename), patch.object(u, 'recover', side_effect=recovery):
            with self.assertRaises(SystemExit):
                self.run_upgrade()

    def test_recovery_after_gap_between_directory_renames_needs_no_host_audit(self):
        self.fixture()
        self.interrupt_swap('old-lib')
        self.assertFalse(r.CODE.exists())
        i.host_audit.reset_mock()
        self.assertEqual(self.run_upgrade(recover=True)['status'], 'recovered')
        i.host_audit.assert_not_called()
        self.assertEqual((r.DATA / 'current').resolve(), self.old)
        self.assertEqual(self.run_upgrade(recover=True)['status'], 'unchanged')
        self.assert_preserved()

    def test_boot_recovery_after_new_code_swap_restores_without_starting_dependents(self):
        self.fixture()
        self.interrupt_swap('lib')
        r.run.reset_mock()
        with u.deploy_lock(i), u.policy_lock(i, r):
            self.assertTrue(u.recover(i, r, boot=True))
        self.assertEqual(r.record(u.journal_path(i))['status'], 'rolled_back')
        self.assertEqual((r.DATA / 'current').resolve(), self.old)
        for call in r.run.call_args_list:
            self.assertNotIn(call.args[0][1], ('start', 'stop', 'restart'))
        self.assert_preserved()

    def test_recovery_refuses_external_config_edit_and_preserves_backup(self):
        self.fixture()
        self.interrupt_swap('lib')
        r.CONFIG.write_bytes(b'edited during outage')
        with self.assertRaisesRegex(u.UpgradeError, 'UPGRADE_EXTERNAL_FILE_EDIT'):
            self.run_upgrade(recover=True)
        self.assertEqual(r.CONFIG.read_bytes(), b'edited during outage')
        self.assertEqual(r.record(u.journal_path(i))['status'], 'applying')
        self.assert_preserved()

    def test_interrupted_rollback_can_be_repeated_with_live_library_missing(self):
        self.fixture()
        self.interrupt_swap('lib')
        rename = u.sync_rename
        def fail(source, destination):
            rename(source, destination)
            if destination.name == 'failed-lib':
                raise SystemExit('ROLLBACK_PROCESS_LOSS')
        with patch.object(u, 'sync_rename', side_effect=fail), u.deploy_lock(i), u.policy_lock(i, r):
            with self.assertRaises(SystemExit):
                u.recover(i, r, boot=True)
        self.assertFalse(r.CODE.exists())
        self.assertEqual(r.record(u.journal_path(i))['status'], 'rolling_back')
        self.assertEqual(self.run_upgrade(recover=True)['status'], 'recovered')
        self.assert_preserved()

    def test_symlinked_live_library_is_refused_before_any_mutation(self):
        self.fixture()
        actual = r.CODE.with_name('foreign-code')
        r.CODE.rename(actual)
        r.CODE.symlink_to(actual, target_is_directory=True)
        with self.assertRaisesRegex(u.UpgradeError, 'UPGRADE_LIBRARY_DIRECTORY_INVALID'):
            self.run_upgrade()
        self.assertFalse(any(call.args[0][:2] == ['systemctl', 'stop'] for call in r.run.call_args_list))
        self.assert_preserved()

    def test_recovery_infrastructure_is_independent_of_live_library_and_gates_all_units(self):
        self.fixture()
        self.run_upgrade()
        self.assertEqual((self.project / 'state/upgrade/recover.py').read_bytes(), u.BOOTSTRAP)
        body = (i.UNIT_ROOT / u.BOOT_UNIT).read_text()
        self.assertIn('/state/upgrade/' + u.LOADER, body)
        self.assertNotIn('/lib/', body)
        for name in i.units(r):
            self.assertEqual((i.UNIT_ROOT / (name + '.d') / '20-vpn-upgrade-recovery.conf').read_bytes(), u.GATE)

    def test_installer_dispatches_upgrade_with_configured_project_and_recovery_flag(self):
        self.fixture()
        calls = []
        class Loader:
            def create_module(self, spec):
                return None
            def exec_module(self, module):
                module.upgrade = lambda folder, installer, recover: calls.append((folder, installer.PROJECT, recover))
        original = i.importlib.util.spec_from_file_location
        def spec(name, path):
            return importlib.machinery.ModuleSpec(name, Loader()) if Path(path).name == 'vpn-stack-upgrade.py' else original(name, path)
        previous_umask = os.umask(0o077)
        try:
            with patch.object(i.sys, 'argv', ['install-vpn.py', 'upgrade', '--recover']), \
                 patch.object(i.signal, 'signal'), patch.object(i.importlib.util, 'spec_from_file_location', side_effect=spec):
                i.main(self.package, project=self.project)
        finally:
            os.umask(previous_umask)
        self.assertEqual(calls, [(self.package, self.project, True)])


if __name__ == '__main__':
    unittest.main()
