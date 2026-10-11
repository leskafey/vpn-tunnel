"""Root-home installation contracts with filesystem/syscall stubs, not live systemd."""
from contextlib import redirect_stdout
import io
import os
from pathlib import Path
import shlex
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from test_installer import i, r
import test_project_layout as layout


class RootAccessTests(layout.InstallationTests):
    def test_closed_project_and_parent_install_resume_preserve_identity_and_permissions(self):
        project, package, generation = self.fixture()
        project.chmod(0o700)
        parent_mode = project.parent.stat().st_mode
        generation.side_effect = r.StackError('INTERRUPTED_AFTER_UNITS')
        with redirect_stdout(io.StringIO()), self.assertRaises(r.StackError):
            i.install(package, '8.8.8.8', False)
        identity = (i.ROOT / 'identity.json').read_bytes()
        rules = b'# preserved\nexample.org\n'
        r.atomic(r.ETC / 'proxy.txt', rules)
        r.ETC.chmod(0o700)
        r.HOME.chmod(0o755)
        generation.side_effect = None
        with redirect_stdout(io.StringIO()):
            i.install(package, '8.8.8.8', True)
        self.assertEqual(project.stat().st_mode & 0o777, 0o700)
        self.assertEqual(project.parent.stat().st_mode, parent_mode)
        self.assertEqual((i.ROOT / 'identity.json').read_bytes(), identity)
        self.assertEqual((r.ETC / 'proxy.txt').read_bytes(), rules)
        self.assertEqual(r.ETC.stat().st_mode & 0o777, 0o750)
        self.assertEqual(r.HOME.stat().st_mode & 0o777, 0o700)
        self.assertEqual(r.record(i.STATE)['status'], 'installed')

    def test_resume_after_partial_directory_preparation(self):
        project, package, generation = self.fixture()
        actual = i.os.chown
        interrupted = False
        def chown(path, *owner):
            nonlocal interrupted
            if path == r.DATA and not interrupted:
                interrupted = True
                raise OSError('PARTIAL_DIRECTORY_SETUP')
            return actual(path, *owner)
        with patch.object(i.os, 'chown', side_effect=chown), redirect_stdout(io.StringIO()), \
             self.assertRaisesRegex(OSError, 'PARTIAL_DIRECTORY_SETUP'):
            i.install(package, '8.8.8.8', False)
        self.assertFalse((i.ROOT / 'identity.json').exists())
        generation.assert_not_called()
        with redirect_stdout(io.StringIO()):
            i.install(package, '8.8.8.8', True)
        self.assertEqual(r.record(i.STATE)['status'], 'installed')
        self.assertEqual(list(i.PROFILE_ROOT.iterdir()), [])

    def test_read_only_audit_plans_closed_parent_namespace_without_account_or_permission_changes(self):
        project, _, _ = self.fixture()
        project.chmod(0o700)
        before = {path: path.stat().st_mode for path in (project, *project.parents)}
        original = Path.read_text
        def read(path, *args, **kwargs):
            if str(path) == '/proc/filesystems':
                return 'nodev\ttmpfs\n'
            if str(path) == '/proc/self/status':
                return 'CapEff:\t0000000000200000\n'
            return original(path, *args, **kwargs)
        original_exists = Path.exists
        def exists(path):
            return True if str(path) == '/proc/self/ns/mnt' else original_exists(path)
        with patch.object(Path, 'read_text', read), patch.object(Path, 'exists', exists), \
             patch.object(i.pwd, 'getpwnam') as account, patch.object(i.os, 'chown') as chown, \
             patch.object(Path, 'chmod') as chmod, patch.object(i.subprocess, 'run') as commands:
            result = i.audit_policy_namespace()
        self.assertEqual(result['model'], 'systemd-bind-mounts')
        self.assertEqual(Path(result['view_root']), self.root)
        self.assertFalse(result['host_permissions_changed'])
        for spy in (account, chown, chmod, commands):
            spy.assert_not_called()
        self.assertEqual({path: path.stat().st_mode for path in before}, before)

    def test_audit_requires_mount_namespace_tmpfs_and_capability(self):
        self.fixture()
        for ns, filesystems, capabilities, code in (
                (False, 'nodev\ttmpfs\n', '200000', 'SYSTEMD_MOUNT_NAMESPACE_REQUIRED'),
                (True, 'nodev\tproc\n', '200000', 'SYSTEMD_MOUNT_NAMESPACE_REQUIRED'),
                (True, 'nodev\ttmpfs\n', '0', 'MOUNT_NAMESPACE_CAPABILITY_REQUIRED')):
            original = Path.read_text
            def read(path, *args, **kwargs):
                if str(path) == '/proc/filesystems':
                    return filesystems
                if str(path) == '/proc/self/status':
                    return 'CapEff:\t' + capabilities + '\n'
                return original(path, *args, **kwargs)
            original_exists = Path.exists
            def exists(path):
                return ns if str(path) == '/proc/self/ns/mnt' else original_exists(path)
            with patch.object(Path, 'read_text', read), patch.object(Path, 'exists', exists), \
                 self.assertRaisesRegex(i.InstallError, code):
                i.audit_policy_namespace()

    def test_private_directories_and_symlinks_refused_before_overwrite(self):
        self.fixture()
        with self.assertRaisesRegex(i.InstallError, 'NON_ROOT_POLICY_ACCOUNT_REQUIRED'):
            i.prepare_service_directories(r, SimpleNamespace(pw_uid=0, pw_gid=123), False)
        self.assertFalse((i.PROJECT / 'cache').exists())
        target = self.root / 'foreign'
        target.mkdir()
        (i.PROJECT / 'cache').symlink_to(target)
        with self.assertRaisesRegex(i.InstallError, 'INSTALL_PATH_SYMLINK_REFUSED'):
            i.prepare_service_directories(r, SimpleNamespace(pw_uid=123, pw_gid=123), True)
        self.assertEqual(list(target.iterdir()), [])


class RootUnitTests(unittest.TestCase):
    def test_complex_paths_keep_original_service_units_and_actual_access_is_audited(self):
        for name in ('vpn "quoted"', "vpn 'quoted'", 'vpn:colon', 'vpn\\folder', 'vpn\tproject'):
            project = Path('/opt') / name
            runtime = SimpleNamespace(CODE=project / 'lib', ETC=project / 'config', DATA=project / 'data',
                                      HOME=project / 'cache/backend')
            units = i.units(runtime)
            for tag in ('dns', 'http'):
                body = units['vpn-stack-' + tag + '.service']
                self.assertNotIn('BindPaths=', body)
                self.assertNotIn('BindReadOnlyPaths=', body)
                self.assertNotIn('TemporaryFileSystem=', body)
                self.assertIn('ProtectHome=read-only', body)
        account = SimpleNamespace(pw_name='vpn-policy', pw_uid=123, pw_gid=456)
        with patch.object(i, 'PROJECT', Path('/root/vpn "quoted"')), \
             patch.object(i.pwd, 'getpwnam', return_value=account), \
             patch.object(i.os, 'getgrouplist', return_value=[456, 789]), \
             patch.object(i.subprocess, 'run', return_value=SimpleNamespace(returncode=1)) as probe, \
             self.assertRaisesRegex(i.InstallError, 'POLICY_USER_PROJECT_TRAVERSAL_REQUIRED'):
            i.audit_policy_traversal()
        command = probe.call_args.args[0]
        self.assertEqual(command[:2], ['/usr/bin/python3', '-c'])
        self.assertIn('os.setgroups([456, 789])', command[2])
        self.assertIn('os.setuid(123)', command[2])
        self.assertEqual(command[3:], ['/root/vpn "quoted"', '/root', '/'])

    def test_root_home_units_expose_only_selected_directories_at_same_absolute_paths(self):
        project = Path('/root/vpn-tunnel')
        runtime = SimpleNamespace(CODE=project / 'lib', ETC=project / 'config', DATA=project / 'data',
                                  HOME=project / 'cache/backend')
        with patch.object(i, 'policy_view_root', return_value=Path('/root')):
            units = i.units(runtime)
        def values(body, key):
            return [line.split('=', 1)[1] for line in body.splitlines() if line.startswith(key + '=')]
        for tag in ('dns', 'http'):
            body = units['vpn-stack-' + tag + '.service']
            self.assertEqual(values(body, 'User'), ['vpn-policy'])
            self.assertEqual(values(body, 'Group'), ['vpn-policy'])
            self.assertEqual(values(body, 'ProtectHome'), ['no'])
            self.assertEqual(values(body, 'ProtectSystem'), ['strict'])
            self.assertEqual(values(body, 'TemporaryFileSystem'),
                             ['"/root:ro,mode=0755,size=1M" "/home:ro,mode=0755,size=1M" '
                              '"/run/user:ro,mode=0755,size=1M" "/root/vpn-tunnel:ro,mode=0755,size=1M"'])
            exposed = [p for v in values(body, 'BindReadOnlyPaths') for p in shlex.split(v)]
            self.assertEqual(set(exposed), {str(runtime.CODE), str(runtime.DATA)}
                             | ({str(runtime.ETC)} if tag == 'dns' else set()))
            self.assertFalse(any('/profiles' in p or '/state' in p for p in exposed))
            self.assertEqual(values(body, 'ReadWritePaths'), ['"' + str(runtime.HOME) + '"'] if tag == 'dns' else [])
            self.assertEqual(values(body, 'BindPaths'), ['"' + str(runtime.HOME) + '"'] if tag == 'dns' else [])
        self.assertNotIn('TemporaryFileSystem=', units['vpn-stack-daily.service'])
        self.assertIn('ProtectHome=read-only', units['vpn-stack-daily.service'])


if __name__ == '__main__':
    unittest.main()
