"""Standalone installer failure/recovery contracts; no host services or downloads."""
import ast
from contextlib import nullcontext
import gzip
import hashlib
import importlib.util
import io
import http.client
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import zipfile


HERE = Path(__file__).resolve().parent.parent / "src"


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


r = load('installer_runtime_test', 'vpn-stack-runtime.py')
i = load('installer_bootstrap_test', 'vpn-stack-install.py')
b = load('installer_package_test', HERE.parent / 'scripts/build.py')
m = load('installer_admin_test', 'vpn-stack-manage.py')


def transport_status_fixture(etc):
    config = r.dump(r.xray_config('P' * 43, 'abcd', {'probe': '00000000-0000-4000-8000-000000000001'}))
    r.atomic(etc / 'xray.json', config)
    r.atomic(etc / 'devices.json', r.dump({'schema': 1, 'devices': {},
        'xray_sha256': hashlib.sha256(config).hexdigest()}))


class PackageTests(unittest.TestCase):
    def test_package_deterministic_and_manifest_complete(self):
        first, files = b.package()
        self.assertEqual(first, b.package()[0])
        manifest = json.loads(files['code-manifest.json'])['files']
        self.assertEqual(set(files), set(manifest) | {'code-manifest.json'})
        for name, checksum in manifest.items():
            self.assertEqual(hashlib.sha256(files[name]).hexdigest(), checksum)
            if name.endswith('.py'):
                ast.parse(files[name])

    def test_package_contains_no_existing_profiles_or_server_identity(self):
        _, files = b.package()
        for raw in files.values():
            self.assertNotIn(b'/var/lib/vpn-awg', raw)
            self.assertNotIn(b'/Users/', raw)
            self.assertNotIn(b'/var/lib/vpn-server-policy-text/', raw)
        self.assertEqual([name for name in files if name.endswith('.json')], ['code-manifest.json'])
        self.assertEqual(len(files), 17 + len(b.BASELINE_FILES))

    def test_unmodified_helpers_match_historical_baseline(self):
        _, files = b.package()
        baseline = json.loads((HERE.parent / 'verification/helper-baseline.json').read_bytes())['files']
        self.assertEqual(len(baseline), 11)
        for name, checksum in baseline.items():
            if name in ('personal-runtime.py', 'personal-policy.py', 'domain-extras.py', 'ip-source.py'):
                continue  # Current socket, advertising and local baseline changes have semantic regression tests.
            self.assertEqual(hashlib.sha256(files[name]).hexdigest(), checksum, name)

    def test_standalone_help_never_runs_host_audit(self):
        output = subprocess.run(['python3', str(HERE.parent / 'install-vpn.py'), '--help'], capture_output=True, timeout=10)
        self.assertEqual(output.returncode, 0)
        self.assertIn(b'--resume', output.stdout)

    def test_tampered_payload_refused_before_host_code(self):
        text = (HERE.parent / 'install-vpn.py').read_text()
        tree = ast.parse(text)
        constants = {n.targets[0].id: ast.literal_eval(n.value) for n in tree.body
                     if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name)
                     and n.targets[0].id in ('PAYLOAD', 'PAYLOAD_SHA')}
        text = text.replace(repr(constants['PAYLOAD_SHA']), repr('0' * 64), 1)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'tampered.py'
            path.write_text(text)
            output = subprocess.run(['python3', str(path), 'audit'], capture_output=True, timeout=10)
        self.assertEqual(output.returncode, 1)
        self.assertIn(b'PACKAGE_PAYLOAD_CHANGED', output.stdout)

    def test_archive_member_selection_never_extracts_other_paths(self):
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode='w:gz') as archive:
            for name, raw in (('../../escape', b'never'), ('bin/core', b'actual')):
                member = tarfile.TarInfo(name)
                member.size = len(raw)
                archive.addfile(member, io.BytesIO(raw))
        self.assertEqual(i.extract_binary(out.getvalue(), {'kind': 'tar', 'member': 'bin/core'}), b'actual')
        with self.assertRaisesRegex(i.InstallError, 'ARCHIVE_BINARY_MEMBER_INVALID'):
            i.extract_binary(out.getvalue(), {'kind': 'tar', 'member': 'missing'})

    def test_archive_duplicate_and_compression_bomb_refused(self):
        out = io.BytesIO()
        with zipfile.ZipFile(out, 'w') as archive:
            archive.writestr('core', b'first')
            # A duplicate executable must not silently select the last entry.
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                archive.writestr('core', b'second')
        with self.assertRaises(i.InstallError):
            i.extract_binary(out.getvalue(), {'kind': 'zip', 'member': 'core'})
        with patch.object(i, 'BIN_LIMIT', 10), self.assertRaisesRegex(i.InstallError, 'BINARY_SIZE_LIMIT'):
            i.extract_binary(gzip.compress(b'a' * 11), {'kind': 'gz'})


class HostAuditTests(unittest.TestCase):
    def audit(self, available_kib, *, free_bytes=2 * 1024**3, **kwargs):
        root = Path(self.enterContext(tempfile.TemporaryDirectory(dir='/tmp')))
        root_info = root.stat()
        runtime = SimpleNamespace(CODE=root / 'lib', ETC=root / 'config', DATA=root / 'data')
        original_read, original_is_dir, original_is_file = Path.read_text, Path.is_dir, Path.is_file
        def read(path, *args, **kw):
            if str(path) == '/etc/os-release':
                return 'ID=ubuntu\nVERSION_ID="24.04"\n'
            if str(path) == '/proc/meminfo':
                return f'MemAvailable: {available_kib} kB\n'
            return original_read(path, *args, **kw)
        with patch.object(i, 'PROJECT', root), patch.object(i, 'ROOT', root / 'state'), \
             patch.object(i, 'PROFILE_ROOT', root / 'profiles'), patch.object(i, 'CLI', root / 'vpnctl'), \
             patch.object(i.sys, 'platform', 'linux'), patch.object(i.os, 'geteuid', return_value=0), \
             patch.object(i.platform, 'machine', return_value='x86_64'), \
             patch.object(Path, 'read_text', read), patch.object(Path, 'exists', return_value=False), \
             patch.object(Path, 'is_dir', lambda p: str(p) == '/run/systemd/system' or original_is_dir(p)), \
             patch.object(Path, 'is_file', lambda p: str(p) == '/sys/fs/cgroup/cgroup.controllers' or original_is_file(p)), \
             patch.object(Path, 'stat', return_value=SimpleNamespace(st_uid=0, st_mode=root_info.st_mode)), \
             patch.object(i.shutil, 'disk_usage', return_value=SimpleNamespace(free=free_bytes)), \
             patch.object(i.subprocess, 'run', return_value=SimpleNamespace(stdout=b'not-found\n')), \
             patch.object(i, 'audit_policy_namespace', return_value={}), patch.object(i, 'units', return_value={}), \
             patch.object(i.socket, 'socket'):
            return i.host_audit(runtime, **kwargs)

    def test_memory_boundary_for_install_resume_and_upgrade(self):
        for action, kwargs, minimum in (('install', {}, 650), ('resume', {'resume': True}, 650),
                                       ('upgrade', {'resume': True, 'minimum_memory_mib': 512}, 512)):
            with self.subTest(action=action):
                with self.assertRaisesRegex(i.InstallError, 'MEMORY_OR_DISK_HEADROOM_LOW'):
                    self.audit(minimum * 1024 - 1, **kwargs)
                self.assertEqual(self.audit(minimum * 1024, **kwargs)['status'], 'compatible')

    def test_upgrade_accepts_605_mib_while_installation_still_refuses(self):
        self.assertEqual(self.audit(605 * 1024, resume=True, minimum_memory_mib=512)['status'], 'compatible')
        with self.assertRaisesRegex(i.InstallError, 'MEMORY_OR_DISK_HEADROOM_LOW'):
            self.audit(605 * 1024)

    def test_upgrade_still_requires_two_gib_free_disk(self):
        with self.assertRaisesRegex(i.InstallError, 'MEMORY_OR_DISK_HEADROOM_LOW'):
            self.audit(512 * 1024, free_bytes=2 * 1024**3 - 1, resume=True, minimum_memory_mib=512)


class ProfileTests(unittest.TestCase):
    def test_per_device_cache_namespace_does_not_share_fake_mapping(self):
        first = r.profile({'type': 'vless', 'tag': 'vps', 'uuid': 'one'}, 'macos')
        second = r.profile({'type': 'vless', 'tag': 'vps', 'uuid': 'two'}, 'macos')
        self.assertNotEqual(first['experimental']['cache_file']['cache_id'], second['experimental']['cache_file']['cache_id'])

    def test_smart_DIRECT_before_proxy_and_stale_fake_resolution(self):
        for platform in ('macos', 'windows', 'ios', 'android'):
            p = r.profile({'type': 'vless', 'tag': 'vps'}, platform)
            rules = p['route']['rules']
            self.assertEqual(rules[2]['action'], 'resolve')
            self.assertTrue(rules[2]['disable_cache'])
            self.assertEqual(rules[3]['ip_cidr'], ['198.18.0.0/16'])
            self.assertEqual(rules[4]['rule_set'], ['personal-direct'])
            self.assertEqual(rules[4]['outbound'], 'direct')
            self.assertEqual(rules[5]['rule_set'], ['proxy-ipv4'])
            self.assertEqual([s['update_interval'] for s in p['route']['rule_set']], ['1h', '5m'])
            self.assertTrue(p['experimental']['cache_file']['store_fakeip'])
            self.assertLess(len(r.dump(p)), 8192)

    def test_full_has_no_rule_sets_and_private_dns_still_uses_vless(self):
        for platform in ('macos', 'windows', 'ios', 'android'):
            p = r.profile({'type': 'vless', 'tag': 'vps'}, platform, True)
            self.assertNotIn('rule_set', p['route'])
            self.assertEqual(p['route']['final'], 'vps')
            self.assertEqual(p['dns']['servers'][0]['detour'], 'vps')
            self.assertEqual(p['route']['rules'][1]['action'], 'reject')

    def test_universal_profiles_preserve_routing_and_legacy_exports(self):
        transport = {'type': 'vless', 'tag': 'vps', 'uuid': 'one'}
        for full in (False, True):
            universal = r.profile(transport, full=full)
            self.assertTrue(universal['inbounds'][0]['strict_route'])
            self.assertEqual(universal, r.profile(transport, 'windows', full))
            self.assertEqual(universal, r.profile(transport, 'android', full))
            del universal['inbounds'][0]['strict_route']
            self.assertEqual(universal, r.profile(transport, 'macos', full))
            self.assertEqual(universal, r.profile(transport, 'ios', full))

    def test_device_CLI_add_without_platform_selects_universal(self):
        runtime = SimpleNamespace(require=Mock(), modules=Mock())
        with patch.object(m.sys, 'argv', ['vpnctl', 'device', 'add', 'laptop-macos']), \
             patch.object(m.sys, 'platform', 'linux'), patch.object(m.os, 'geteuid', return_value=0), \
             patch.object(m.os, 'umask'), patch.object(m.importlib.util, 'module_from_spec', return_value=runtime), \
             patch.object(m.importlib.machinery.SourceFileLoader, 'exec_module'), patch.object(m, 'device') as device:
            m.main()
        device.assert_called_once_with(runtime, 'add', 'laptop-macos', 'universal')

    def test_xray_only_explicit_private_controls_precede_private_block(self):
        cfg = r.xray_config('private', 'short', {'laptop-macos': 'one', 'probe': 'two'})
        rules = cfg['routing']['rules']
        self.assertEqual([row['port'] for row in rules[1:3]], ['19053', '8080'])
        self.assertEqual(rules[3]['outboundTag'], 'server-dns')
        self.assertEqual(rules[-1]['outboundTag'], 'block')
        self.assertIn('127.0.0.0/8', rules[-1]['ip'])
        self.assertFalse(cfg['inbounds'][0]['sniffing']['enabled'])


class TemporaryRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='vpn-installer-tests-', dir='/tmp')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.etc, self.data, self.code = [self.root / n for n in ('etc', 'data', 'code')]
        for path in (self.etc, self.data, self.code, self.data / 'generations'):
            path.mkdir()
        for key, value in {'ETC': self.etc, 'DATA': self.data, 'CODE': self.code,
                           'CONFIG': self.etc / 'backend.yaml', 'GROUP': 'unused'}.items():
            p = patch.object(r, key, value)
            p.start()
            self.addCleanup(p.stop)
        # Host permissions are checked natively on Linux. The Mac tests own only
        # this temporary directory and model uid=0 without requiring sudo.
        original_stat, original_fstat = Path.stat, os.fstat
        def root_stat(path, *args, **kwargs):
            fields = list(original_stat(path, *args, **kwargs))
            fields[4] = 0
            return os.stat_result(fields)
        def root_fstat(fd):
            fields = list(original_fstat(fd))
            fields[4] = 0
            return os.stat_result(fields)
        for p in (patch.object(Path, 'stat', root_stat), patch.object(os, 'fstat', root_fstat),
                  patch.object(os, 'fchown'), patch.object(os, 'chown'),
                  patch.object(r.grp, 'getgrnam', return_value=SimpleNamespace(gr_gid=os.getgid()))):
            p.start()
            self.addCleanup(p.stop)

    def test_raw_file_symlink_and_size_limits(self):
        actual = self.root / 'actual'
        actual.write_bytes(b'preserved')
        link = self.root / 'link'
        link.symlink_to(actual)
        with self.assertRaises(OSError):
            r.raw_file(link)
        with self.assertRaisesRegex(r.StackError, 'OWNED_BOUNDED_FILE_REQUIRED'):
            r.raw_file(actual, 2)
        with self.assertRaisesRegex(r.StackError, 'OUTPUT_SYMLINK_REFUSED'):
            r.atomic(link, b'replaced')
        self.assertEqual(actual.read_bytes(), b'preserved')

    def test_generation_group_traversal_survives_private_umask(self):
        old_umask = os.umask(0o077)
        try:
            work = r.work_directory()
        finally:
            os.umask(old_umask)
        self.assertEqual(work.stat().st_mode & 0o777, 0o750)
        self.assertEqual(r.record(work / 'owner.json')['kind'], 'vpn-stack-generation')

    def test_private_HTTP_serves_committed_small_JSON_with_ETag_HEAD_and_304(self):
        old = self.data / 'generations' / 'gen-old'
        new = self.data / 'generations' / 'gen-new'
        old.mkdir()
        new.mkdir()
        first, second = r.direct_body([]), r.direct_body(['api.ipify.org'])
        r.atomic(old / 'personal-direct-domains.json', first)
        r.atomic(new / 'personal-direct-domains.json', second)
        r.pointer(old)
        server = r.HTTPServer(('127.0.0.1', 0), r.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        def request(path, method='GET', headers=None):
            conn = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=4)
            conn.request(method, path, headers=headers or {})
            answer = conn.getresponse()
            result = answer.status, dict(answer.headers), answer.read()
            conn.close()
            return result
        try:
            status, headers, raw = request('/personal-direct-domains.json')
            self.assertEqual((status, raw), (200, first))
            status, _, raw = request('/personal-direct-domains.json', 'HEAD')
            self.assertEqual((status, raw), (200, b''))
            status, _, raw = request('/personal-direct-domains.json', headers={'If-None-Match': headers['ETag']})
            self.assertEqual((status, raw), (304, b''))
            # Unpublished candidates never leak through the public pointer.
            self.assertEqual(request('/personal-direct-domains.json')[2], first)
            r.pointer(new)
            self.assertEqual(request('/personal-direct-domains.json')[2], second)
            for path in ('/../settings.json', '/xray.json', '/personal-direct-domains.json?x=1'):
                self.assertEqual(request(path)[0], 404)
            r.atomic(new / 'personal-direct-domains.json', b'x' * 32769)
            self.assertEqual(request('/personal-direct-domains.json')[0], 503)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)

    def identity_runtime(self):
        root, profiles = self.root / 'install', self.root / 'profiles'
        root.mkdir()
        for key, value in {'ROOT': root, 'STATE': root / 'installation.json', 'PROFILE_ROOT': profiles}.items():
            p = patch.object(i, key, value)
            p.start()
            self.addCleanup(p.stop)
        calls = []
        def command(args, code, **kw):
            calls.append(args)
            return (b'PrivateKey: ' + b'P' * 43 + b'\nPublicKey: ' + b'Q' * 43 + b'\n') if args[1] == 'generate' else b''
        runtime = SimpleNamespace(**{n: getattr(r, n) for n in ('ETC', 'CODE', 'atomic', 'dump', 'record', 'digest', 'profile', 'xray_config')},
                                  run=command)
        state = {'server_ip': '8.8.8.8', 'private_files': {}}
        return runtime, state, calls

    def test_interrupted_identity_outputs_resume_with_same_keys_and_UUIDs(self):
        runtime, state, calls = self.identity_runtime()
        actual = runtime.atomic
        def interrupt(path, raw, *args):
            if path.name == 'probe-client.json':
                raise RuntimeError('simulated power loss')
            actual(path, raw, *args)
        runtime.atomic = interrupt
        with self.assertRaisesRegex(RuntimeError, 'simulated power loss'):
            i.create_transport(runtime, state)
        before = (self.etc / 'xray.json').read_bytes()
        checkpoint = json.loads((i.ROOT / 'identity.json').read_bytes())
        runtime.atomic = actual
        i.create_transport(runtime, state)
        self.assertEqual((self.etc / 'xray.json').read_bytes(), before)
        self.assertEqual(len(set(checkpoint['identities'].values())), 1)
        self.assertEqual(len(list(i.PROFILE_ROOT.glob('*.json'))), 0)
        self.assertEqual(sum(args[1] == 'generate' for args in calls), 1)

    def test_resume_refuses_modified_private_probe_without_rotating_identity(self):
        runtime, state, calls = self.identity_runtime()
        i.create_transport(runtime, state)
        before = (i.ROOT / 'identity.json').read_bytes()
        (self.etc / 'probe-client.json').write_bytes(b'changed')
        with self.assertRaisesRegex(i.InstallError, 'RESUME_PRIVATE_CONFIG_CHANGED'):
            i.create_transport(runtime, state)
        self.assertEqual((i.ROOT / 'identity.json').read_bytes(), before)
        self.assertEqual(sum(args[1] == 'generate' for args in calls), 1)

    def test_recover_prepared_transaction_restores_pointer_and_config(self):
        old, new = [self.data / 'generations' / name for name in ('gen-old', 'gen-new')]
        old.mkdir()
        new.mkdir()
        r.atomic(old / 'manifest.json', r.dump({'counts': {'smart': 3}}))
        before, after = b'previous backend', b'uncommitted backend'
        r.atomic(r.CONFIG, after)
        r.pointer(new)
        import base64
        journal = {'status': 'prepared', 'before_source': str(old), 'after_source': str(new),
                   'before_config': base64.b64encode(before).decode(),
                   'before_sha256': hashlib.sha256(before).hexdigest(), 'after_sha256': hashlib.sha256(after).hexdigest()}
        r.atomic(self.data / 'transaction.json', r.dump(journal))
        with patch.object(r, 'run') as command, patch.object(r, 'wait_backend') as wait:
            self.assertTrue(r.recover(None))
            command.assert_called_once_with(['systemctl', 'restart', r.UNIT], 'RECOVERY_BACKEND_RESTART_FAILED')
            wait.assert_called_once_with(None, {'smart': 3})
        self.assertEqual(r.CONFIG.read_bytes(), before)
        self.assertEqual((self.data / 'current').resolve(), old)
        self.assertEqual(r.record(self.data / 'transaction.json')['status'], 'rolled_back')
        self.assertFalse(r.recover(None))

    def test_recovery_refuses_external_config_change(self):
        r.atomic(r.CONFIG, b'external edit')
        import base64
        r.atomic(self.data / 'transaction.json', r.dump({'status': 'prepared',
                 'before_config': base64.b64encode(b'old').decode(), 'before_sha256': hashlib.sha256(b'old').hexdigest(),
                 'after_sha256': hashlib.sha256(b'new').hexdigest()}))
        with patch.object(r, 'run') as command, self.assertRaisesRegex(r.StackError, 'RECOVERY_CONFIG_CHANGED_EXTERNALLY'):
            r.recover(None)
        command.assert_not_called()
        self.assertEqual(r.CONFIG.read_bytes(), b'external edit')

    def test_failed_activation_rolls_back_config_and_keeps_old_public_pointer(self):
        old, work = [self.data / 'generations' / name for name in ('gen-old', 'gen-new')]
        for directory, content in ((old, b'old'), (work, b'new')):
            directory.mkdir()
            (directory / 'assets').mkdir()
            for tag in ('smart', 'direct', 'ads'):
                (directory / 'assets' / (tag + '.mrs')).write_bytes(content)
                (directory / (tag + '.normalized.txt')).write_bytes(content)
            (directory / 'witnesses.json').write_text('{}')
            (directory / 'proxy-ipv4.json').write_bytes(r.ip_body([r.ipaddress.ip_network('104.16.0.0/13')])[0])
            (directory / 'personal-direct-domains.json').write_bytes(r.direct_body([]))
        before = b'old backend'
        r.atomic(r.CONFIG, before)
        previous = {'schema': 1, 'status': 'verified', 'checksums': {}, 'assets_source': str(old),
                    'counts': {'smart': 1, 'direct': 1, 'ads': 1}, 'config_sha256': hashlib.sha256(before).hexdigest()}
        r.atomic(old / 'manifest.json', r.dump(previous))
        r.pointer(old)
        manifest = {'assets_source': str(work), 'personal': {'proxy': [], 'direct': [], 'ads-exceptions': []},
                    'personal_sha256': {}, 'files': {tag + '.mrs': {'normalized_patterns': 1}
                                                    for tag in ('smart', 'direct', 'ads')}}
        setup = SimpleNamespace(local_dns=lambda *_: ['198.18.0.4'], require_fake=lambda values: values[0])
        s = SimpleNamespace(core=SimpleNamespace(compose=lambda *_: ('new backend', {})), wire=None,
                            personal=SimpleNamespace(within=lambda *_: False), setup=setup)
        def failed_probe(*_):
            self.assertEqual(r.CONFIG.read_bytes(), b'new backend')
            self.assertEqual((self.data / 'current').resolve(), old)
            raise r.StackError('VLESS_PROBE_FAILED')
        with patch.object(r, 'base_config', return_value='fixture'), patch.object(r, 'run') as commands, \
             patch.object(r, 'wait_backend'), patch.object(r, 'probes', side_effect=failed_probe):
            with self.assertRaisesRegex(r.StackError, 'VLESS_PROBE_FAILED'):
                r.activate(s, work, manifest)
        check_command = commands.call_args_list[0].args[0]
        self.assertEqual(check_command[check_command.index('-d') + 1], work / 'native-check')
        self.assertNotIn(r.HOME, check_command)
        self.assertEqual(r.CONFIG.read_bytes(), before)
        self.assertEqual((self.data / 'current').resolve(), old)
        self.assertEqual(r.record(self.data / 'transaction.json')['status'], 'rolled_back')

    def test_personal_noop_never_downloads_builds_or_restarts(self):
        previous = {'personal_sha256': {'proxy': 'same'}}
        with patch.object(r, 'modules'), patch.object(r, 'lock', return_value=nullcontext()), \
             patch.object(r, 'recover', return_value=False), patch.object(r, 'active', return_value=(self.root, previous)), \
             patch.object(r, 'personal', return_value=({}, previous['personal_sha256'])), \
             patch.object(r, 'make_full') as build, patch.object(r, 'fetch_ips') as ips, patch.object(r, 'run') as command:
            result = r.apply('personal')
        self.assertEqual(result['status'], 'unchanged')
        build.assert_not_called()
        ips.assert_not_called()
        command.assert_not_called()

    def test_unchanged_IP_refresh_updates_only_metadata(self):
        source = self.data / 'generations' / 'gen-old'
        source.mkdir()
        body = r.ip_body([r.ipaddress.ip_network('104.16.0.0/13')])[0]
        r.atomic(source / 'proxy-ipv4.json', body)
        previous = {'personal_sha256': {'proxy': 'same'}, 'ip': {'CIDRs': 1, 'source_CIDRs': ['104.16.0.0/13']}}
        r.atomic(self.etc / r.IP_FILE, b'')
        with patch.object(r, 'modules'), patch.object(r, 'lock', return_value=nullcontext()), \
             patch.object(r, 'recover', return_value=False), patch.object(r, 'active', return_value=(source, previous)), \
             patch.object(r, 'personal', return_value=({}, previous['personal_sha256'])), \
             patch.object(r, 'work_directory') as work, patch.object(r, 'fetch_ips', return_value=(body, previous['ip'])), \
             patch.object(r, 'run') as command:
            result = r.apply('ip')
        self.assertEqual(result['status'], 'unchanged')
        work.assert_not_called()
        command.assert_not_called()

    def test_personal_provider_is_strict_and_bounded(self):
        _, files = b.package()
        modules = {}
        for name in ('source-parser.py', 'personal-policy.py'):
            module = SimpleNamespace()
            exec(compile(files[name], name, 'exec'), module.__dict__)
            modules[name] = module
        s = SimpleNamespace(core=modules['personal-policy.py'], parser=modules['source-parser.py'])
        for name in (*r.FILES.values(), r.IP_FILE):
            r.atomic(self.etc / name, b'')
        r.atomic(self.etc / 'direct.txt', b'api.ipify.org\n')
        self.assertEqual(r.personal(s)[0]['direct'], ['api.ipify.org'])
        r.atomic(self.etc / 'direct.txt', b'http://invalid.example/\n')
        with self.assertRaises(s.core.PolicyError):
            r.personal(s)
        r.atomic(self.etc / 'direct.txt', ''.join('d%d.example\n' % n for n in range(257)).encode())
        with self.assertRaisesRegex(r.StackError, 'PERSONAL_DIRECT_SIZE_LIMIT'):
            r.personal(s)

    def test_personal_ips_reject_private_ipv6_host_bits_and_oversized_sets(self):
        for raw in (b'10.0.0.0/8', b'104.16.0.1/13', b'2001:4860::/32', b'8.0.0.0/6', b'0.0.0.0/0'):
            with self.assertRaises(r.StackError):
                r.parse_personal_ips(raw)
        self.assertEqual([str(n) for n in r.parse_personal_ips(b'8.8.8.8\n')], ['8.8.8.8/32'])

    def test_personal_ip_removal_preserves_automatic_source_only(self):
        r.atomic(self.etc / r.IP_FILE, b'8.8.8.8\n')
        automatic = {'source_CIDRs': ['104.16.0.0/13']}
        body, info = r.combined_ips(automatic)
        self.assertEqual(info['personal_CIDRs'], 1)
        self.assertIn('8.8.8.8/32', json.loads(body)['rules'][0]['ip_cidr'])
        r.atomic(self.etc / r.IP_FILE, b'')
        body, info = r.combined_ips(automatic)
        self.assertEqual(json.loads(body)['rules'][0]['ip_cidr'], ['104.16.0.0/13'])
        self.assertEqual(info['personal_CIDRs'], 0)

    def test_rule_command_preserves_comments_and_triggers_only_file_edit(self):
        _, files = b.package()
        core, parser = SimpleNamespace(), SimpleNamespace()
        exec(compile(files['personal-policy.py'], 'core', 'exec'), core.__dict__)
        exec(compile(files['source-parser.py'], 'parser', 'exec'), parser.__dict__)
        r.atomic(self.etc / 'proxy.txt', b'# keep this comment\noriginal.example\n')
        with patch.object(r, 'modules', return_value=SimpleNamespace(core=core, parser=parser)), \
             patch.object(r, 'run') as run, patch.object(r, 'report'):
            m.rule(r, 'add', 'proxy', 'new.example')
            self.assertIn(b'# keep this comment\n', (self.etc / 'proxy.txt').read_bytes())
            self.assertIn(b'new.example\n', (self.etc / 'proxy.txt').read_bytes())
            m.rule(r, 'remove', 'proxy', 'new.example')
            self.assertEqual((self.etc / 'proxy.txt').read_bytes(), b'# keep this comment\noriginal.example\n')
        run.assert_not_called()

    def test_device_failure_restores_config_registry_and_preserves_other_UUIDs(self):
        runtime, state, _ = self.identity_runtime()
        i.create_transport(runtime, state)
        before = (self.etc / 'xray.json').read_bytes()
        old_registry = (self.etc / 'devices.json').read_bytes()
        source = self.root / 'fixture'
        source.mkdir()
        for filename in ('witnesses.json', 'smart.normalized.txt', 'direct.normalized.txt', 'ads.normalized.txt'):
            (source / filename).write_bytes(b'fixture')
        with patch.object(m, 'PROFILES', i.PROFILE_ROOT), patch.object(r, 'lock', return_value=nullcontext()), \
             patch.object(r, 'run'), patch.object(r, 'modules'), \
             patch.object(r, 'active', return_value=(source, {})), \
             patch.object(r, 'probes', side_effect=r.StackError('NEW_IDENTITY_PROBE_FAILED')):
            with self.assertRaisesRegex(r.StackError, 'NEW_IDENTITY_PROBE_FAILED'):
                m.device(r, 'add', 'laptop-macos')
        self.assertEqual((self.etc / 'xray.json').read_bytes(), before)
        self.assertEqual((self.etc / 'devices.json').read_bytes(), old_registry)
        self.assertFalse((i.PROFILE_ROOT / 'laptop-macos-smart.json').exists())
        self.assertEqual(r.record(self.data / 'device-transaction.json')['status'], 'rolled_back')

    def test_device_add_and_revoke_keep_existing_UUIDs(self):
        runtime, state, _ = self.identity_runtime()
        i.create_transport(runtime, state)
        old_ids = r.record(self.etc / 'devices.json')['devices']
        source = self.root / 'fixture'
        source.mkdir()
        for filename in ('witnesses.json', 'smart.normalized.txt', 'direct.normalized.txt', 'ads.normalized.txt'):
            (source / filename).write_bytes(b'fixture')
        with patch.object(m, 'PROFILES', i.PROFILE_ROOT), patch.object(r, 'lock', return_value=nullcontext()), \
             patch.object(r, 'run'), patch.object(r, 'modules'), patch.object(r, 'report'), \
             patch.object(r, 'active', return_value=(source, {})), patch.object(r, 'probes') as probes, patch.object(r, 'local_access'):
            m.device(r, 'add', 'laptop-macos')
            current = r.record(self.etc / 'devices.json')['devices']
            self.assertEqual({k: current[k] for k in old_ids}, old_ids)
            new_id = current['laptop-macos']['uuid']
            self.assertEqual(current['laptop-macos']['platform'], 'universal')
            files = {p: p.read_bytes() for p in i.PROFILE_ROOT.glob('laptop-macos-*.json')}
            self.assertEqual(len(files), 2)
            for raw in files.values():
                profile = json.loads(raw)
                self.assertTrue(profile['inbounds'][0]['strict_route'])
                self.assertEqual(profile['outbounds'][0]['uuid'], new_id)
            config_before_export = (self.etc / 'xray.json').read_bytes()
            m.device(r, 'export', 'laptop-macos')
            self.assertEqual({p: p.read_bytes() for p in files}, files)
            self.assertEqual((self.etc / 'xray.json').read_bytes(), config_before_export)
            self.assertNotIn(new_id, [v['uuid'] for v in old_ids.values()])
            self.assertEqual(probes.call_args.kwargs['probe_config']['outbounds'][0]['uuid'], new_id)
            m.device(r, 'revoke', 'laptop-macos')
            self.assertTrue(all(not path.exists() for path in files))
            self.assertNotIn('removed_profiles', r.record(self.data / 'device-transaction.json'))
        self.assertEqual(r.record(self.etc / 'devices.json')['devices'], old_ids)
        self.assertNotIn(new_id, [v['id'] for v in r.record(self.etc / 'xray.json')['inbounds'][0]['settings']['clients']])
    def device_revoke_fixture(self):
        runtime, state, _ = self.identity_runtime()
        i.create_transport(runtime, state)
        source = self.root / 'fixture'
        source.mkdir()
        for filename in ('witnesses.json', 'smart.normalized.txt', 'direct.normalized.txt', 'ads.normalized.txt'):
            (source / filename).write_bytes(b'fixture')
        for context in (patch.object(m, 'PROFILES', i.PROFILE_ROOT),
                        patch.object(r, 'lock', return_value=nullcontext()),
                        patch.object(r, 'run'), patch.object(r, 'modules'), patch.object(r, 'report'),
                        patch.object(r, 'active', return_value=(source, {})), patch.object(r, 'probes'), patch.object(r, 'local_access')):
            self.enterContext(context)
        for name in ('laptop-macos', 'laptop-windows', 'ios-phone', 'android-phone'):
            m.device(r, 'add', name)
        return {p: p.read_bytes() for p in i.PROFILE_ROOT.glob('*.json')}

    def test_revoke_with_one_profile_missing_removes_remaining_only(self):
        files = self.device_revoke_fixture()
        (i.PROFILE_ROOT / 'laptop-macos-smart.json').unlink()
        m.device(r, 'revoke', 'laptop-macos')
        self.assertFalse((i.PROFILE_ROOT / 'laptop-macos-full.json').exists())
        self.assertNotIn('laptop-macos', r.record(self.etc / 'devices.json')['devices'])
        for path, raw in files.items():
            if not path.name.startswith('laptop-macos-'):
                self.assertEqual(path.read_bytes(), raw)

    def test_revoke_preserves_external_profile_changes_and_revokes_UUID(self):
        self.device_revoke_fixture()
        other = r.record(self.etc / 'devices.json')['devices']['laptop-windows']
        path = i.PROFILE_ROOT / 'laptop-macos-smart.json'
        path.write_bytes(b'user-modified-profile')
        m.device(r, 'revoke', 'laptop-macos')
        self.assertEqual(path.read_bytes(), b'user-modified-profile')
        self.assertNotIn('laptop-macos', r.record(self.etc / 'devices.json')['devices'])
        self.assertEqual(r.record(self.etc / 'devices.json')['devices']['laptop-windows'], other)
        report = r.report.call_args.kwargs
        self.assertIn(str(path), report['preserved_profiles'])
        self.assertIn('UUID', report['profile_message'])

    def test_revoke_partial_deletion_failure_restores_profiles_and_access(self):
        files = self.device_revoke_fixture()
        config = (self.etc / 'xray.json').read_bytes()
        registry = (self.etc / 'devices.json').read_bytes()
        unlink = Path.unlink
        def fail_second(path, *args, **kwargs):
            if path == i.PROFILE_ROOT / 'laptop-macos-full.json':
                self.assertFalse((i.PROFILE_ROOT / 'laptop-macos-smart.json').exists())
                raise OSError('simulated deletion failure')
            return unlink(path, *args, **kwargs)
        with patch.object(Path, 'unlink', fail_second), self.assertRaisesRegex(OSError, 'simulated deletion failure'):
            m.device(r, 'revoke', 'laptop-macos')
        self.assertEqual({p: p.read_bytes() for p in files}, files)
        self.assertEqual((self.etc / 'xray.json').read_bytes(), config)
        self.assertEqual((self.etc / 'devices.json').read_bytes(), registry)
        journal = r.record(self.data / 'device-transaction.json')
        self.assertEqual(journal['status'], 'rolled_back')
        self.assertNotIn('removed_profiles', journal)

    def test_existing_vpn_audit_refuses_without_service_mutation(self):
        original = Path.read_text
        def read(path, *args, **kw):
            if str(path) == '/etc/os-release':
                return 'ID=ubuntu\nVERSION_ID="24.04"\n'
            if str(path) == '/proc/meminfo':
                return 'MemAvailable: 1000000 kB\n'
            return original(path, *args, **kw)
        with patch.object(i.sys, 'platform', 'linux'), patch.object(i.os, 'geteuid', return_value=0), \
             patch.object(i.platform, 'machine', return_value='x86_64'), patch.object(Path, 'read_text', read), \
             patch.object(Path, 'is_dir', return_value=True), patch.object(Path, 'is_file', return_value=True), \
             patch.object(i.subprocess, 'run', return_value=SimpleNamespace(stdout=b'loaded\n')) as commands:
            with self.assertRaisesRegex(i.InstallError, 'EXISTING_VPN_INSTALLATION_REFUSING_TO_OVERWRITE'):
                i.host_audit(r)
        self.assertTrue(all(call.args[0][:2] == ['systemctl', 'show'] for call in commands.call_args_list))


if __name__ == '__main__':
    unittest.main()
