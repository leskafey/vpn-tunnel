"""Regressions for absent exports and saved transport integrity; no VPS access."""
import hashlib
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import test_installer as baseline
from test_installer import r, i, m


class RevokeWithoutProfilesTests(unittest.TestCase):
    setUp = baseline.TemporaryRuntimeTests.setUp
    identity_runtime = baseline.TemporaryRuntimeTests.identity_runtime
    device_revoke_fixture = baseline.TemporaryRuntimeTests.device_revoke_fixture

    def test_revoke_without_profile_directory_removes_uuid_and_checks_locally(self):
        files = self.device_revoke_fixture()
        for path in files:
            path.unlink()
        i.PROFILE_ROOT.rmdir()
        registry = r.record(self.etc / 'devices.json')
        identity = registry['devices'].pop('laptop-macos')['uuid']
        clients = r.record(self.etc / 'xray.json')['inbounds'][0]['settings']['clients']
        with patch.object(m, 'profile_outputs', side_effect=AssertionError('profiles accessed')), \
             patch.object(r, 'local_access') as local:
            m.device(r, 'revoke', 'laptop-macos')
        local.assert_called_once()
        self.assertEqual(local.call_args.args[-1], identity)
        updated = r.record(self.etc / 'devices.json')
        self.assertEqual(updated['devices'], registry['devices'])
        self.assertEqual(r.record(self.etc / 'xray.json')['inbounds'][0]['settings']['clients'],
                         [client for client in clients if client['id'] != identity])
        self.assertEqual(updated['xray_sha256'], r.digest(self.etc / 'xray.json'))
        self.assertFalse(i.PROFILE_ROOT.exists())
        self.assertEqual(r.report.call_args.kwargs['removed_profiles'], [])
        self.assertEqual(r.record(self.data / 'device-transaction.json')['status'], 'committed')

    def test_local_check_failure_without_profiles_restores_config_and_registry(self):
        files = self.device_revoke_fixture()
        moved = self.root / 'moved-profiles'
        i.PROFILE_ROOT.rename(moved)
        config = (self.etc / 'xray.json').read_bytes()
        registry = (self.etc / 'devices.json').read_bytes()
        identity = r.record(self.etc / 'devices.json')['devices']['laptop-macos']['uuid']
        def fail_check(*args):
            self.assertEqual(args[-1], identity)
            self.assertNotIn(identity, [client['id'] for client in
                r.record(self.etc / 'xray.json')['inbounds'][0]['settings']['clients']])
            raise r.StackError('REVOKED_UUID_STILL_ACCEPTED')
        with patch.object(r, 'local_access', side_effect=fail_check) as local, \
             self.assertRaisesRegex(r.StackError, 'REVOKED_UUID_STILL_ACCEPTED'):
            m.device(r, 'revoke', 'laptop-macos')
        local.assert_called_once()
        self.assertEqual((self.etc / 'xray.json').read_bytes(), config)
        self.assertEqual((self.etc / 'devices.json').read_bytes(), registry)
        self.assertEqual({path.name: path.read_bytes() for path in moved.iterdir()},
                         {path.name: raw for path, raw in files.items()})
        self.assertFalse(i.PROFILE_ROOT.exists())
        journal = r.record(self.data / 'device-transaction.json')
        self.assertEqual(journal['status'], 'rolled_back')
        self.assertEqual(journal['created_profiles'], {})
        self.assertNotIn('removed_profiles', journal)

    def test_revoke_still_rejects_unsafe_existing_profile_paths(self):
        self.device_revoke_fixture()
        i.PROFILE_ROOT.rename(self.root / 'moved-profiles')
        config = (self.etc / 'xray.json').read_bytes()
        registry = (self.etc / 'devices.json').read_bytes()
        for kind in ('file', 'public-directory', 'symlink', 'dangling-symlink'):
            with self.subTest(kind=kind):
                if kind == 'file':
                    i.PROFILE_ROOT.write_bytes(b'not a directory')
                elif kind == 'public-directory':
                    i.PROFILE_ROOT.mkdir()
                    i.PROFILE_ROOT.chmod(0o755)
                else:
                    target = self.root / ('moved-profiles' if kind == 'symlink' else 'missing')
                    i.PROFILE_ROOT.symlink_to(target, target_is_directory=True)
                with self.assertRaisesRegex(r.StackError, 'PRIVATE_PROFILE_DIRECTORY_REQUIRED'):
                    m.device(r, 'revoke', 'laptop-macos')
                self.assertEqual((self.etc / 'xray.json').read_bytes(), config)
                self.assertEqual((self.etc / 'devices.json').read_bytes(), registry)
                if kind == 'public-directory':
                    i.PROFILE_ROOT.rmdir()
                else:
                    i.PROFILE_ROOT.unlink()
        r.local_access.assert_not_called()


class TransportStatusTests(unittest.TestCase):
    def setUp(self):
        baseline.TemporaryRuntimeTests.setUp(self)
        baseline.transport_status_fixture(self.etc)
        r.atomic(r.CONFIG, b'backend fixture')
        for name in (*r.FILES.values(), r.IP_FILE):
            r.atomic(self.etc / name, b'')
        self.manifest = {'assets_source': '/assets', 'counts': {'smart': 3},
            'personal': {'proxy': ['example.org']}, 'ip': {},
            'applied_utc': '2026-10-11T12:00:00+00:00',
            'personal_sha256': {key: hashlib.sha256(b'').hexdigest() for key in (*r.FILES, 'proxy-ip')},
            'config_sha256': r.digest(r.CONFIG)}
        self.s = SimpleNamespace(personal=SimpleNamespace(loaded_counts=Mock()), checker=None)

    def check_status(self, diagnostic=None):
        self.s.personal.loaded_counts.reset_mock()
        before = {path: path.read_bytes() for path in self.etc.iterdir() if path.is_file()}
        with patch.object(r, 'unit_state', return_value={'LoadState': 'loaded', 'ActiveState': 'active'}) as unit, \
             patch.object(r, 'active', return_value=(self.root, self.manifest)) as active, \
             patch.object(r, 'modules', return_value=self.s), patch.object(r, 'report') as report, \
             patch.object(r.socket, 'create_connection') as connect, \
             patch.object(r.http.client, 'HTTPConnection') as http:
            response = http.return_value.getresponse.return_value
            response.status, response.read.return_value = 200, b'{"status":"ok"}\n'
            self.assertEqual(r.status(), 1 if diagnostic else 0)
        value = report.call_args.kwargs
        self.assertEqual(value['status'], 'degraded' if diagnostic else 'healthy')
        self.assertEqual(value['faults'], ['xray_config_check'] if diagnostic else [])
        self.assertEqual(value['transport_config'],
                         {'status': 'degraded', 'diagnostic': diagnostic} if diagnostic else {'status': 'verified'})
        self.assertEqual(value['saved_policy']['status'], 'verified')
        self.assertEqual(value['saved_policy']['counts'], self.manifest['counts'])
        self.assertEqual(value['saved_policy']['last_successful_apply_utc'], self.manifest['applied_utc'])
        self.assertEqual(set(value['services']), {'xray', 'dns', 'http'})
        self.assertEqual(len(value['updates']), 6)
        self.assertEqual(unit.call_count, 9)
        active.assert_called_once_with(check_config=False)
        self.s.personal.loaded_counts.assert_called_once()
        self.assertEqual(connect.call_count, 2)
        http.return_value.request.assert_called_once_with('GET', '/probe.json')
        self.assertEqual({path: path.read_bytes() for path in self.etc.iterdir() if path.is_file()}, before)

    def test_correct_transport_configuration_is_healthy(self):
        self.check_status()

    def test_changed_allowed_uuid_is_degraded(self):
        path = self.etc / 'xray.json'
        config = r.record(path)
        config['inbounds'][0]['settings']['clients'].append(
            {'id': '00000000-0000-4000-8000-000000000002', 'flow': 'xtls-rprx-vision'})
        r.atomic(path, r.dump(config))
        self.check_status('STATUS_XRAY_CHECKSUM_MISMATCH')

    def test_missing_transport_files_are_degraded(self):
        for name, code in (('xray.json', 'STATUS_XRAY_CONFIG'), ('devices.json', 'STATUS_DEVICE_REGISTRY')):
            with self.subTest(file=name):
                baseline.transport_status_fixture(self.etc)
                (self.etc / name).unlink()
                self.check_status(code + '_MISSING')

    def test_corrupt_transport_files_are_degraded(self):
        for name, code in (('xray.json', 'STATUS_XRAY_CONFIG'), ('devices.json', 'STATUS_DEVICE_REGISTRY')):
            for kind, body in (('json', b'{broken json'), ('encoding', b'\xff'),
                               ('array', b'[]'), ('null', b'null')):
                with self.subTest(file=name, corruption=kind):
                    baseline.transport_status_fixture(self.etc)
                    r.atomic(self.etc / name, body)
                    # Even a matching digest must not bless malformed Xray JSON.
                    if name == 'xray.json':
                        registry = r.record(self.etc / 'devices.json')
                        registry['xray_sha256'] = hashlib.sha256(body).hexdigest()
                        r.atomic(self.etc / 'devices.json', r.dump(registry))
                    self.check_status(code + '_INVALID')

    def test_json_decoder_recursion_failure_still_reports_policy_and_services(self):
        nested = b'{"nested":' + b'[' * 1100 + b'0' + b']' * 1100 + b'}'
        loads = r.json.loads
        def decode(raw):
            # Python versions differ in their decoder depth limit. Model the
            # failure explicitly so this regression is independent of the host.
            if raw == nested:
                raise RecursionError('decoder depth exceeded')
            return loads(raw)
        for name, code in (('xray.json', 'STATUS_XRAY_CONFIG'), ('devices.json', 'STATUS_DEVICE_REGISTRY')):
            with self.subTest(file=name):
                baseline.transport_status_fixture(self.etc)
                r.atomic(self.etc / name, nested)
                with patch.object(r.json, 'loads', side_effect=decode):
                    self.check_status(code + '_INVALID')

    def test_invalid_registry_checksum_or_shape_is_degraded(self):
        for checksum in (None, '', 'not-a-checksum', 'g' * 64, 123):
            with self.subTest(checksum=checksum):
                baseline.transport_status_fixture(self.etc)
                registry = r.record(self.etc / 'devices.json')
                if checksum is None:
                    registry.pop('xray_sha256')
                else:
                    registry['xray_sha256'] = checksum
                r.atomic(self.etc / 'devices.json', r.dump(registry))
                self.check_status('STATUS_DEVICE_REGISTRY_INVALID')
        for registry in ({}, {'schema': 1, 'devices': [], 'xray_sha256': r.digest(self.etc / 'xray.json')}):
            with self.subTest(registry=registry):
                r.atomic(self.etc / 'devices.json', r.dump(registry))
                self.check_status('STATUS_DEVICE_REGISTRY_INVALID')

    def test_symlinked_transport_files_are_degraded(self):
        for name, code in (('xray.json', 'STATUS_XRAY_CONFIG'), ('devices.json', 'STATUS_DEVICE_REGISTRY')):
            with self.subTest(file=name):
                baseline.transport_status_fixture(self.etc)
                path, target = self.etc / name, self.root / name
                path.rename(target)
                path.symlink_to(target)
                self.check_status(code + '_UNREADABLE')
                path.unlink()
