"""Current build: project paths, private defaults and fresh installation."""
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_installer as baseline
from test_installer import r, i, m, b, load



class ProjectTests(unittest.TestCase):
    setUp = baseline.TemporaryRuntimeTests.setUp
    identity_runtime = baseline.TemporaryRuntimeTests.identity_runtime
    device_revoke_fixture = baseline.TemporaryRuntimeTests.device_revoke_fixture

    def test_fresh_install_has_only_internal_probe_and_empty_profiles(self):
        runtime, state, calls = self.identity_runtime()
        i.create_transport(runtime, state)
        self.assertEqual(r.record(self.etc / 'devices.json')['devices'], {})
        clients = r.record(self.etc / 'xray.json')['inbounds'][0]['settings']['clients']
        self.assertEqual([c['email'] for c in clients], ['probe'])
        self.assertEqual(list(i.PROFILE_ROOT.iterdir()), [])
        self.assertEqual(list(i.ROOT.glob('profile-check-*')), [])
        checks = [a[-1].name for a in calls if a[1] == 'check']
        self.assertEqual(checks, ['smart.json', 'full.json', 'probe-client.json'])
        self.assertEqual(i.PROFILE_ROOT.stat().st_mode & 0o777, 0o700)
        for path in self.etc.iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_temporary_profile_cleanup_on_native_failure_preserves_checkpoint(self):
        runtime, state, _ = self.identity_runtime()
        original = runtime.run
        def fail(args, code, **kwargs):
            if Path(args[-1]).name == 'full.json':
                raise r.StackError('CLIENT_NATIVE_CONFIG_FAILED')
            return original(args, code, **kwargs)
        runtime.run = fail
        with self.assertRaises(r.StackError):
            i.create_transport(runtime, state)
        identity = (i.ROOT / 'identity.json').read_bytes()
        self.assertEqual(list(i.PROFILE_ROOT.iterdir()), [])
        self.assertEqual(list(i.ROOT.glob('profile-check-*')), [])
        runtime.run = original
        i.create_transport(runtime, state)
        self.assertEqual((i.ROOT / 'identity.json').read_bytes(), identity)

    def test_project_paths_are_bound_to_installer_location_not_cwd_or_package(self):
        project = self.root / 'project with spaces'
        project.mkdir()
        for name in ('PROJECT', 'ROOT', 'STATE', 'PROFILE_ROOT', 'CLI_BODY'):
            self.enterContext(patch.object(i, name, getattr(i, name)))
        i.configure_project(project)
        runtime = i.load_runtime(b.HERE)
        self.assertEqual(runtime.CODE, project / 'lib')
        self.assertEqual(runtime.ETC, project / 'config')
        self.assertEqual(runtime.HOME, project / 'cache/backend')
        self.assertEqual(i.STATE, project / 'state/install/installation.json')
        self.assertIn(str(project / 'lib/vpn-stack-manage.py').encode(), i.CLI_BODY)
        self.assertIn(b"'", i.CLI_BODY)
        body = '\n'.join(i.units(runtime).values())
        for old in ('/usr/local/lib/vpn-stack', '/etc/vpn-stack', '/var/lib/vpn-stack',
                    '/var/lib/vpn-stack-backend', '/root/vpn-stack-profiles'):
            self.assertNotIn(old, body)
        self.assertNotIn('@', body)
        self.assertIn('PathChanged=' + str(project / 'config/direct.txt'), body)
        self.assertIn('WorkingDirectory=' + str(project / 'cache/backend'), body)
        self.assertIn('"' + str(project / 'profiles') + '"', body)
        self.assertNotIn('\\x20', body)

    def test_russian_instructions_are_comments_and_resume_never_rewrites_rules(self):
        i.create_rule_files(r)
        core = load('instructions_core', 'personal-policy.py')
        parser = load('instructions_parser', 'source-parser.py')
        for name in (*r.FILES.values(), r.IP_FILE):
            raw = (r.ETC / name).read_bytes()
            self.assertTrue(all(row.startswith('#') for row in raw.decode().splitlines()))
            self.assertEqual((r.ETC / name).stat().st_mode & 0o777, 0o600)
            parse = r.parse_personal_ips if name == r.IP_FILE else lambda data: core.parse_personal(data, parser)
            self.assertEqual(parse(raw), [])
            body = raw + (b'8.8.8.8\n' if name == r.IP_FILE else b'example.org\n')
            r.atomic(r.ETC / name, body)
            i.create_rule_files(r)
            self.assertEqual((r.ETC / name).read_bytes(), body)
            self.assertEqual(len(parse(body)), 1)

    def test_IP_parser_ignores_russian_comments_but_rejects_multicast_and_active_nonascii(self):
        self.assertEqual([str(n) for n in r.parse_personal_ips('# Русский комментарий\n8.8.8.8 # пример\n'.encode())],
                         ['8.8.8.8/32'])
        for raw in (b'224.0.0.0/12', b'239.1.2.3', 'адрес\n'.encode()):
            with self.assertRaises(r.StackError):
                r.parse_personal_ips(raw)

    def test_list_prints_only_user_names_and_names_never_select_platform(self):
        self.device_revoke_fixture()
        output = io.StringIO()
        with redirect_stdout(output):
            m.device(r, 'list')
        self.assertEqual(output.getvalue().splitlines(), ['android-phone', 'ios-phone', 'laptop-macos', 'laptop-windows'])
        for entry in r.record(self.etc / 'devices.json')['devices'].values():
            self.assertEqual(entry['platform'], 'universal')

    def test_export_restores_missing_pair_with_same_uuid_and_rejects_manual_edit(self):
        self.device_revoke_fixture()
        path = i.PROFILE_ROOT / 'android-phone-smart.json'
        original = path.read_bytes()
        identity = r.record(self.etc / 'devices.json')['devices']['android-phone']['uuid']
        path.unlink()
        m.device(r, 'export', 'android-phone')
        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(json.loads(original)['outbounds'][0]['uuid'], identity)
        path.write_bytes(b'manual edit')
        with self.assertRaisesRegex(r.StackError, 'EXPORTED_PROFILE_MODIFIED_EXTERNALLY'):
            m.device(r, 'export', 'android-phone')
        self.assertEqual(path.read_bytes(), b'manual edit')


class InstallationTests(unittest.TestCase):
    setUp = baseline.TemporaryRuntimeTests.setUp

    def fixture(self):
        project = self.root / 'project'
        project.mkdir(mode=0o755)
        for key in ('PROJECT', 'CODE', 'ETC', 'DATA', 'HOME', 'CONFIG'):
            self.enterContext(patch.object(r, key, getattr(r, key, project)))
        r.configure_paths(project)
        for key in ('PROJECT', 'ROOT', 'STATE', 'PROFILE_ROOT', 'CLI_BODY'):
            self.enterContext(patch.object(i, key, getattr(i, key)))
        i.configure_project(project)
        package = self.root / 'package'
        package.mkdir()
        for name, body in b.package()[1].items():
            r.atomic(package / name, body)
        system = self.root / 'system'
        system.mkdir()
        self.enterContext(patch.object(i, 'UNIT_ROOT', system))
        self.enterContext(patch.object(i, 'CLI', self.root / 'vpnctl'))
        self.enterContext(patch.object(i, 'load_runtime', return_value=r))
        self.enterContext(patch.object(i, 'host_audit', return_value={}))
        self.enterContext(patch.object(i.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=123, pw_gid=os.getgid() or 123)))
        def binary(runtime, name, item):
            runtime.atomic(runtime.CODE / 'bin' / name, b'verified binary', 0o755)
            return runtime.digest(runtime.CODE / 'bin' / name)
        self.enterContext(patch.object(i, 'download_binary', side_effect=binary))
        def run(args, *unused, **kwargs):
            if args[1:3] == ['generate', 'reality-keypair']:
                return b'PrivateKey: ' + b'P' * 43 + b'\nPublicKey: ' + b'Q' * 43 + b'\n'
            return b''
        self.enterContext(patch.object(r, 'run', side_effect=run))
        self.enterContext(patch.object(i.subprocess, 'run'))
        self.enterContext(patch.object(r, 'report'))
        generation = self.enterContext(patch.object(i, 'initial_generation', return_value={'status': 'verified'}))
        return project, package, generation

    def test_install_flow_creates_only_project_data_and_reports_rules_and_profiles(self):
        project, package, generation = self.fixture()
        with redirect_stdout(io.StringIO()):
            i.install(package, '8.8.8.8', False)
        self.assertEqual(r.record(i.STATE)['status'], 'installed')
        self.assertEqual(r.record(r.ETC / 'devices.json')['devices'], {})
        self.assertEqual(list(i.PROFILE_ROOT.iterdir()), [])
        self.assertEqual((project / 'cache').stat().st_mode & 0o777, 0o755)
        self.assertEqual((project / 'state').stat().st_mode & 0o777, 0o700)
        self.assertEqual((r.CODE / 'bin/sing-box').stat().st_mode & 0o777, 0o755)
        self.assertEqual(i.CLI.read_bytes(), i.CLI_BODY)
        for name, body in i.units(r).items():
            self.assertEqual((i.UNIT_ROOT / name).read_text(), body)
        installed = r.report.call_args.kwargs
        self.assertEqual(installed['profiles'], str(project / 'profiles'))
        self.assertEqual(set(installed['rule_files']), {str(project / 'config' / n) for n in i.RULE_INSTRUCTIONS})

    def test_failed_install_resume_keeps_rules_keys_and_probe_uuid(self):
        project, package, generation = self.fixture()
        generation.side_effect = r.StackError('SIMULATED_POLICY_FAILURE')
        with redirect_stdout(io.StringIO()), self.assertRaises(r.StackError):
            i.install(package, '8.8.8.8', False)
        checkpoint = (i.ROOT / 'identity.json').read_bytes()
        rules = '# Моя правка после сбоя\nexample.org\n'.encode()
        r.atomic(r.ETC / 'proxy.txt', rules)
        generation.side_effect = None
        with redirect_stdout(io.StringIO()):
            i.install(package, '8.8.8.8', True)
        self.assertEqual((r.ETC / 'proxy.txt').read_bytes(), rules)
        self.assertEqual((i.ROOT / 'identity.json').read_bytes(), checkpoint)
        self.assertEqual(r.record(i.STATE)['status'], 'installed')
        self.assertEqual(list(i.PROFILE_ROOT.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
