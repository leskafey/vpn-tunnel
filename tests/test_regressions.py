"""Review regressions: credentials, failed generations, probes and diagnostics."""
from contextlib import contextmanager, nullcontext
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import test_installer as baseline
from test_installer import load, r, i, m


class ReviewTests(unittest.TestCase):
    setUp = baseline.TemporaryRuntimeTests.setUp
    identity_runtime = baseline.TemporaryRuntimeTests.identity_runtime
    device_revoke_fixture = baseline.TemporaryRuntimeTests.device_revoke_fixture

    def owned(self, name, assets=None, applied=False):
        path = self.data / 'generations' / ('gen-' + name)
        path.mkdir()
        r.atomic(path / 'owner.json', r.dump({'schema': 1, 'kind': 'vpn-stack-generation'}))
        (path / 'download.raw').write_bytes(b'x' * 4096)
        if assets or applied:
            r.atomic(path / 'manifest.json', r.dump({'status': 'verified',
                'activation': 'applied' if applied else 'candidate', 'assets_source': str(assets or path)}))
        return path

    def test_cleanup_retains_all_assets_rollback_and_pending_transaction_data(self):
        assets = self.owned('00-assets', applied=True)
        old = self.owned('10-old', assets=assets, applied=True)
        current = self.owned('20-current', assets=assets, applied=True)
        candidate = self.owned('30-candidate', assets=assets)
        stale = self.owned('40-stale')
        unknown = self.data / 'generations' / 'gen-foreign'
        unknown.mkdir()
        (unknown / 'download.raw').write_bytes(b'foreign')
        r.pointer(current)
        r.atomic(self.data / 'transaction.json', r.dump({'status': 'prepared',
                 'before_source': str(old), 'after_source': str(candidate)}))
        # No metadata writes or resource gate are needed to free space.
        with patch.object(r, 'atomic', side_effect=OSError('ENOSPC')), patch.object(r.shutil, 'disk_usage') as disk:
            r.cleanup()
        disk.assert_not_called()
        self.assertFalse(stale.exists())
        for path in (old, current, assets, candidate, unknown):
            self.assertTrue(path.exists())
        for path in (old, candidate):
            self.assertTrue((path / 'download.raw').exists())
        r.atomic(self.data / 'transaction.json', r.dump({'status': 'rolled_back',
                 'before_source': str(old), 'after_source': str(candidate)}))
        r.cleanup()
        self.assertFalse(candidate.exists())
        self.assertTrue(assets.exists())
        self.assertFalse((old / 'download.raw').exists())

    def test_cleanup_retains_assets_of_each_of_three_successful_generations(self):
        assets = [self.owned('0' + str(n), applied=True) for n in range(3)]
        retained = [self.owned('2' + str(n), assets=assets[n], applied=True) for n in range(3)]
        r.pointer(retained[-1])
        failed = [self.owned('9' + str(n)) for n in range(5)]
        r.cleanup()
        self.assertTrue(all(p.exists() for p in assets + retained))
        self.assertTrue(all(not p.exists() for p in failed))

    def test_cleanup_preserves_assets_used_by_config_without_current(self):
        used = self.owned('used')
        r.atomic(used / 'manifest.json', r.dump({'activation': 'candidate', 'assets_source': str(used)}))
        failed = self.owned('failed')
        r.atomic(r.CONFIG, ('rule-providers: ' + json.dumps({'smart': {'type': 'file', 'path': str(used / 'assets/smart.mrs')}})).encode())
        r.cleanup()
        self.assertTrue(used.exists())
        self.assertFalse((used / 'download.raw').exists())
        self.assertFalse(failed.exists())

    def test_cleanup_removes_rolled_back_generation_even_after_publication(self):
        old, failed = self.owned('old', applied=True), self.owned('new', applied=True)
        r.pointer(old)
        r.atomic(self.data / 'transaction.json', r.dump({'status': 'rolled_back',
            'before_source': str(old), 'after_source': str(failed)}))
        r.cleanup()
        self.assertTrue(old.exists())
        self.assertFalse(failed.exists())

    def test_cleanup_never_follows_foreign_symlinks(self):
        outside = self.root / 'foreign'
        outside.mkdir()
        (outside / 'private').write_bytes(b'keep')
        stale = self.owned('stale')
        (stale / 'link').symlink_to(outside, target_is_directory=True)
        (self.data / 'generations/gen-link').symlink_to(outside, target_is_directory=True)
        r.cleanup()
        self.assertEqual((outside / 'private').read_bytes(), b'keep')
        self.assertTrue((self.data / 'generations/gen-link').is_symlink())

    def test_failed_download_and_compile_do_not_accumulate(self):
        source = self.owned('old', applied=True)
        r.pointer(source)
        (source / 'proxy-ipv4.json').write_bytes(b'{}')
        previous = {'personal_sha256': {}, 'ip': {}, 'files': {}}
        def build(_, work, __):
            (work / 'large-download.raw').write_bytes(b'x' * 8192)
            raise r.StackError('SOURCE_DOWNLOAD_FAILED')
        with patch.object(r, 'modules'), patch.object(r, 'lock', return_value=nullcontext()), \
             patch.object(r, 'recover', return_value=False), patch.object(r, 'active', return_value=(source, previous)), \
             patch.object(r, 'personal', return_value=({}, {})), patch.object(r, 'combined_ips', return_value=(b'{}', {})), \
             patch.object(Path, 'read_text', return_value='MemAvailable: 1048576 kB\n'), \
             patch.object(r.shutil, 'disk_usage', return_value=SimpleNamespace(free=10 * 1024**3)), \
             patch.object(r, 'make_full', side_effect=build):
            for code in ('SOURCE_DOWNLOAD_FAILED', 'MRS_COMPILE_FAILED'):
                def fail(_, work, __, code=code):
                    (work / 'large-download.raw').write_bytes(b'x' * 8192)
                    raise r.StackError(code)
                with patch.object(r, 'make_full', side_effect=fail), self.assertRaisesRegex(r.StackError, code):
                    r.apply('daily')
                self.assertEqual(list((self.data / 'generations').iterdir()), [source])

    def test_cleanup_runs_before_disk_gate_and_on_unchanged_personal_policy(self):
        previous = {'personal_sha256': {}}
        stale = self.owned('crashed')
        with patch.object(r, 'modules'), patch.object(r, 'lock', return_value=nullcontext()), \
             patch.object(r, 'recover', return_value=False), patch.object(r, 'active', return_value=(self.root, previous)), \
             patch.object(r, 'personal', return_value=({}, {})), \
             patch.object(r.shutil, 'disk_usage', side_effect=AssertionError('disk gate reached')):
            self.assertEqual(r.apply('personal')['status'], 'unchanged')
        self.assertFalse(stale.exists())

    def test_runtime_check_failure_cleans_generation_after_build_and_delivery_files(self):
        source = self.owned('old', applied=True)
        r.pointer(source)
        (source / 'proxy-ipv4.json').write_bytes(b'{}')
        previous = {'personal_sha256': {}, 'ip': {}, 'files': {}}
        checked = Mock(side_effect=r.StackError('PERSONAL_NATIVE_CONFIG_REJECTED'))
        s = SimpleNamespace(core=None, pilot=None, personal=SimpleNamespace(runtime_check=checked))
        def build(_, work, __):
            (work / 'compiled.mrs').write_bytes(b'candidate compiled data')
            return {'assets_source': str(work), 'files': {'fixture.mrs': {}}}
        with patch.object(r, 'modules', return_value=s), patch.object(r, 'lock', return_value=nullcontext()), \
             patch.object(r, 'recover', return_value=False), patch.object(r, 'active', return_value=(source, previous)), \
             patch.object(r, 'personal', return_value=({'direct': [], 'ads-exceptions': []}, {})), \
             patch.object(r, 'combined_ips', return_value=(b'{}', {})), patch.object(r, 'base_config', return_value='fixture'), \
             patch.object(Path, 'read_text', return_value='MemAvailable: 1048576 kB\n'), \
             patch.object(r.shutil, 'disk_usage', return_value=SimpleNamespace(free=10 * 1024**3)), \
             patch.object(r, 'make_full', side_effect=build), self.assertRaisesRegex(r.StackError, 'PERSONAL_NATIVE_CONFIG_REJECTED'):
            r.apply('daily')
        checked.assert_called_once()
        self.assertEqual(list((self.data / 'generations').iterdir()), [source])

    def test_generation_with_pending_rollback_failure_is_not_deleted(self):
        old = self.owned('old', applied=True)
        r.pointer(old)
        work = None
        with self.assertRaisesRegex(r.StackError, 'RECOVERY_FAILED'):
            with r.generation_work() as work:
                r.atomic(self.data / 'transaction.json', r.dump({'status': 'prepared',
                    'before_source': str(old), 'after_source': str(work)}))
                (work / 'probe.private.log').write_bytes(b'keep for recovery')
                raise r.StackError('RECOVERY_FAILED')
        self.assertTrue((work / 'probe.private.log').exists())

    def test_revoke_has_no_public_probe_or_active_policy_dependency(self):
        self.device_revoke_fixture()
        identity = r.record(self.etc / 'devices.json')['devices']['laptop-macos']['uuid']
        with patch.object(r, 'probes', side_effect=OSError('DNS HTTPS STUN unavailable')) as public, \
             patch.object(r, 'active', side_effect=OSError('backend unavailable')), \
             patch.object(r, 'local_access') as local:
            m.device(r, 'revoke', 'laptop-macos')
        public.assert_not_called()
        self.assertEqual(local.call_args.args[-1], identity)
        clients = r.record(self.etc / 'xray.json')['inbounds'][0]['settings']['clients']
        self.assertNotIn(identity, [c['id'] for c in clients])
        self.assertEqual(len(clients), 4)  # three other devices plus probe

    def test_local_apply_failure_restores_access_and_profiles(self):
        files = self.device_revoke_fixture()
        before = (self.etc / 'xray.json').read_bytes()
        with patch.object(r, 'local_access', side_effect=r.StackError('REVOKED_UUID_STILL_ACCEPTED')):
            with self.assertRaisesRegex(r.StackError, 'REVOKED_UUID_STILL_ACCEPTED'):
                m.device(r, 'revoke', 'laptop-macos')
        self.assertEqual((self.etc / 'xray.json').read_bytes(), before)
        self.assertEqual({p: p.read_bytes() for p in files}, files)

    def test_revoke_profile_changed_during_check_is_preserved(self):
        self.device_revoke_fixture()
        path = i.PROFILE_ROOT / 'laptop-macos-full.json'
        with patch.object(r, 'local_access', side_effect=lambda *_: path.write_bytes(b'edited during operation')):
            m.device(r, 'revoke', 'laptop-macos')
        self.assertEqual(path.read_bytes(), b'edited during operation')
        self.assertNotIn('laptop-macos', r.record(self.etc / 'devices.json')['devices'])

    def test_recovery_preserves_manual_profile_and_restores_missing_profile(self):
        files = self.device_revoke_fixture()
        edited = i.PROFILE_ROOT / 'laptop-macos-smart.json'
        deleted = i.PROFILE_ROOT / 'laptop-macos-full.json'
        original_atomic = r.atomic
        def power_loss(path, raw, *args, **kwargs):
            if path == self.etc / 'devices.json':
                edited.write_bytes(b'manual recovery edit')
                raise r.StackError('INTERRUPTED')
            return original_atomic(path, raw, *args, **kwargs)
        with patch.object(r, 'atomic', side_effect=power_loss), patch.object(m, 'recover', side_effect=lambda *_: None):
            with self.assertRaisesRegex(r.StackError, 'INTERRUPTED'):
                m.device(r, 'revoke', 'laptop-macos')
        self.assertFalse(deleted.exists())
        self.assertTrue(m.recover(r))
        self.assertEqual(edited.read_bytes(), b'manual recovery edit')
        self.assertEqual(deleted.read_bytes(), files[deleted])
        self.assertIn('laptop-macos', r.record(self.etc / 'devices.json')['devices'])

    def test_local_access_requires_positive_control_denies_revoked_and_rechecks(self):
        r.atomic(self.etc / 'probe-client.json', r.dump({'outbounds': [{'uuid': 'probe'}]}))
        clients = []
        @contextmanager
        def client(s, work, probe_config=None, local=False):
            self.assertTrue(local)
            clients.append('probe' if probe_config is None else probe_config['outbounds'][0]['uuid'])
            yield 1234
        s = SimpleNamespace(wire=SimpleNamespace(PilotError=ValueError))
        work = self.root / 'local-check'
        work.mkdir()
        with patch.object(r, 'probe_client', client), \
             patch.object(r, 'private_http', side_effect=[None, ConnectionResetError(), None]):
            r.local_access(s, work, 'revoked')
        self.assertEqual(clients, ['probe', 'revoked', 'probe'])
        work2 = self.root / 'bad-check'
        work2.mkdir()
        with patch.object(r, 'probe_client', client), patch.object(r, 'private_http'):
            with self.assertRaisesRegex(r.StackError, 'REVOKED_UUID_STILL_ACCEPTED'):
                r.local_access(s, work2, 'revoked')

    def test_public_probes_never_resolve_synthetic_ads_witness_with_exception(self):
        personal = load('review_personal_runtime', 'personal-runtime.py')
        synthetic = 'random-child.ads.example'
        manifest = {'personal': {'proxy': [], 'direct': [], 'ads-exceptions': ['ads.example']}}
        work = self.root / 'probe'
        work.mkdir()
        r.atomic(work / 'witnesses.json', r.dump({'ads-child': synthetic}))
        r.atomic(self.etc / 'settings.json', r.dump({'server_ip': '8.8.8.8'}))
        for tag in ('smart', 'direct', 'ads'):
            (work / (tag + '.normalized.txt')).write_text('+.ads.example\n' if tag == 'ads' else '')
        names = []
        def dns(_, port, name, proto):
            self.assertNotEqual(name, synthetic, 'NXDOMAIN witness reached public DNS')
            names.append(name)
            return ['198.18.0.2'] if name in ('api.ipify.org', 'stun.l.google.com') else ['8.8.8.8']
        setup = SimpleNamespace(dns_vless=dns, require_fake=lambda v: v[0], require_real=Mock(),
                                https_ip=Mock(), stun_socks=Mock())
        s = SimpleNamespace(personal=personal, setup=setup, wire=None,
                            closed=SimpleNamespace(closed_destination=Mock()))
        with patch.object(r, 'probe_client', return_value=nullcontext(1234)), patch.object(r, 'private_http'):
            result = r.probes(s, work, manifest)
        self.assertEqual(result['VLESS_DNS_TCP_UDP_checks'], 8)
        self.assertEqual(set(names), {'api.ipify.org', 'checkip.amazonaws.com', 'www.instagram.com', 'stun.l.google.com'})
        # The same synthetic name is still included in isolated policy checks.
        witness = {key: synthetic for key in ('apex', 'child', 'deep-child', 'direct-apex', 'direct-child', 'ads-child', 'default')}
        witness['public_names'] = []
        self.assertIn(synthetic, personal.runtime_cases(witness, manifest['personal']))
        self.assertEqual(personal.expected_route(synthetic, {'ads': True, 'smart': False, 'direct': False},
                        manifest['personal']), ('real', 'default-direct'))

    def test_status_reports_failed_required_service_even_with_verified_policy(self):
        baseline.transport_status_fixture(self.etc)
        manifest = {'assets_source': '/assets', 'counts': {}, 'personal': {}, 'personal_sha256': {},
                    'ip': {}, 'applied_utc': '2026-10-11T12:00:00+00:00',
                    'config_sha256': hashlib.sha256(b'fixture').hexdigest()}
        r.atomic(r.CONFIG, b'fixture')
        for name in (*r.FILES.values(), r.IP_FILE):
            r.atomic(self.etc / name, b'')
        s = SimpleNamespace(personal=SimpleNamespace(loaded_counts=Mock()), checker=None)
        def unit(name):
            return {'LoadState': 'loaded', 'ActiveState': 'failed' if name.endswith('xray.service') else 'active'}
        with patch.object(r, 'unit_state', side_effect=unit), patch.object(r, 'active', return_value=(self.root, manifest)), \
             patch.object(r, 'modules', return_value=s), patch.object(r, 'report') as report, \
             patch.object(r.socket, 'create_connection'), patch.object(r.http.client, 'HTTPConnection') as http:
            response = http.return_value.getresponse.return_value
            response.status, response.read.return_value = 200, b'{"status":"ok"}\n'
            self.assertEqual(r.status(), 1)
        value = report.call_args.kwargs
        self.assertEqual(value['saved_policy']['status'], 'verified')
        self.assertEqual(value['saved_policy']['last_successful_apply_utc'], manifest['applied_utc'])
        self.assertIn('xray_service', value['faults'])
        self.assertIn('proxy-ip.txt', value['unapplied_personal_files'])

    def test_status_oneshot_idle_is_healthy_and_manual_edits_are_reported(self):
        baseline.transport_status_fixture(self.etc)
        r.atomic(r.CONFIG, b'fixture')
        for name in (*r.FILES.values(), r.IP_FILE):
            r.atomic(self.etc / name, b'')
        manifest = {'assets_source': '/assets', 'counts': {}, 'personal': {}, 'ip': {},
                    'personal_sha256': {k: hashlib.sha256(b'').hexdigest() for k in (*r.FILES, 'proxy-ip')},
                    'config_sha256': hashlib.sha256(b'fixture').hexdigest()}
        r.atomic(self.etc / 'proxy.txt', b'# pending manual edit\n')
        s = SimpleNamespace(personal=SimpleNamespace(loaded_counts=Mock()), checker=None)
        def unit(name):
            idle = name.endswith(('daily.service', 'ip.service', 'personal.service'))
            return {'LoadState': 'loaded', 'ActiveState': 'inactive' if idle else 'active', 'Result': 'success'}
        with patch.object(r, 'unit_state', side_effect=unit), patch.object(r, 'active', return_value=(self.root, manifest)), \
             patch.object(r, 'modules', return_value=s), patch.object(r, 'report') as report, \
             patch.object(r.socket, 'create_connection'), patch.object(r.http.client, 'HTTPConnection') as http:
            response = http.return_value.getresponse.return_value
            response.status, response.read.return_value = 200, b'{"status":"ok"}\n'
            self.assertEqual(r.status(), 0)
        self.assertEqual(report.call_args.kwargs['unapplied_personal_files'], ['proxy.txt'])

    def test_status_unavailable_policy_still_reports_all_unit_states_and_http_fault(self):
        with patch.object(r, 'unit_state', return_value={'ActiveState': 'inactive'}), \
             patch.object(r, 'active', side_effect=r.StackError('ACTIVE_GENERATION_REQUIRED')), \
             patch.object(r.http.client, 'HTTPConnection', side_effect=OSError()), patch.object(r, 'report') as report:
            self.assertEqual(r.status(), 1)
        value = report.call_args.kwargs
        self.assertEqual(set(value['services']), {'xray', 'dns', 'http'})
        self.assertEqual(len(value['updates']), 6)
        self.assertIn('http_check', value['faults'])
        self.assertEqual(value['saved_policy']['status'], 'unavailable')

    def test_status_keeps_saved_policy_when_backend_config_is_changed(self):
        baseline.transport_status_fixture(self.etc)
        for name in (*r.FILES.values(), r.IP_FILE):
            r.atomic(self.etc / name, b'')
        r.atomic(r.CONFIG, b'external config edit')
        manifest = {'assets_source': '/assets', 'counts': {}, 'personal': {}, 'ip': {},
                    'personal_sha256': {}, 'config_sha256': hashlib.sha256(b'previous config').hexdigest()}
        with patch.object(r, 'active', return_value=(self.root, manifest)) as active, \
             patch.object(r, 'unit_state', return_value={'LoadState': 'loaded', 'ActiveState': 'active'}), \
             patch.object(r.socket, 'create_connection'), patch.object(r.http.client, 'HTTPConnection') as http, \
             patch.object(r, 'report') as report:
            response = http.return_value.getresponse.return_value
            response.status, response.read.return_value = 200, b'{"status":"ok"}\n'
            self.assertEqual(r.status(), 1)
        active.assert_called_once_with(check_config=False)
        self.assertEqual(report.call_args.kwargs['saved_policy']['status'], 'verified')
        self.assertEqual(report.call_args.kwargs['saved_policy']['diagnostic'], 'ACTIVE_BACKEND_CONFIG_CHANGED')
