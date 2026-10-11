"""Filesystem and stubbed-runtime regressions; native checks are separate."""
from contextlib import nullcontext, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import socketserver
import subprocess
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import test_installer as baseline
from test_installer import r, i, load
import test_project_layout as layout


class UnitPathTests(unittest.TestCase):
    setUp = baseline.TemporaryRuntimeTests.setUp

    def test_each_directive_preserves_spaces_quotes_backslashes_dollars_and_unicode(self):
        for root in ('/opt/vpn project', '/opt/vpn "quote" $HOME\\folder', '/opt/vpn проект', '/opt/vpn\tproject'):
            project = Path(root)
            runtime = SimpleNamespace(CODE=project / 'lib', ETC=project / 'config',
                                      DATA=project / 'data', HOME=project / 'cache/backend')
            with patch.object(i, 'PROFILE_ROOT', project / 'profiles'), \
                 patch.object(i, 'policy_view_root', return_value=project):
                units = i.units(runtime)
            for body in units.values():
                for line in body.splitlines():
                    directive, _, value = line.partition('=')
                    if directive == 'WorkingDirectory':
                        self.assertEqual(value, str(runtime.HOME))
                    elif directive == 'PathChanged':
                        self.assertTrue(value.startswith(str(runtime.ETC)))
                        self.assertNotIn('\\x20', value)
                    elif directive in ('ReadWritePaths', 'BindPaths', 'BindReadOnlyPaths'):
                        paths = shlex.split(value)
                        self.assertTrue(all(path.startswith(root + '/') for path in paths))
                        self.assertTrue(all(Path(path).name in ('lib', 'config', 'data', 'backend', 'profiles') for path in paths))
                    elif directive == 'ExecStart':
                        self.assertTrue(value.startswith(':'))  # Disable environment expansion of literal '$'.
                        args = shlex.split(value[1:])
                        # ExecStart has C-unescaping, unlike the path-list parser.
                        args = [arg.replace('\\t', '\t') for arg in args]
                        self.assertTrue(any(arg.startswith(root + '/lib/') for arg in args))
                    elif directive == 'Environment':
                        values = [word.replace('\\t', '\t') for word in shlex.split(value)]
                        self.assertIn('SAFE_PATHS=' + str(runtime.DATA / 'generations'), values)
            paths = shlex.split(next(row.split('=', 1)[1] for row in units['vpn-stack-daily.service'].splitlines()
                                     if row.startswith('ReadWritePaths=')))
            self.assertEqual(paths, [str(runtime.ETC), str(runtime.DATA), str(runtime.HOME)])
            for name in ('vpn-stack-dns.service', 'vpn-stack-xray.service'):
                command = next(row.split('=', 1)[1] for row in units[name].splitlines() if row.startswith('ExecStart='))
                self.assertEqual(shlex.split(command[1:])[:2], ['/usr/bin/env', '--'])

    def test_cli_executes_exact_project_path_and_literal_arguments_from_other_cwd(self):
        project = self.root / 'vpn "quoted" $HOME'
        (project / 'lib').mkdir(parents=True)
        for key in ('PROJECT', 'ROOT', 'STATE', 'PROFILE_ROOT', 'CLI_BODY'):
            self.enterContext(patch.object(i, key, getattr(i, key)))
        i.configure_project(project)
        manager = project / 'lib/vpn-stack-manage.py'
        manager.write_text('import json,sys\nprint(json.dumps(sys.argv))\n')
        cli = self.root / 'test-vpnctl'
        cli.write_bytes(i.CLI_BODY)
        argument = 'literal $HOME; $(echo hidden)'
        result = subprocess.run(['sh', str(cli), 'device', 'export', argument], cwd=self.root,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), [str(manager), 'device', 'export', argument])

    def test_invalid_project_symbols_still_refused(self):
        for suffix in ('percent%', 'line\nbreak', 'carriage\rreturn'):
            project = self.root / suffix
            project.mkdir()
            with patch.object(i, 'PROJECT', i.PROJECT), self.assertRaisesRegex(i.InstallError, 'PROJECT_PATH_INVALID'):
                i.configure_project(project)


class InitialCheckpointTests(unittest.TestCase):
    setUp = baseline.TemporaryRuntimeTests.setUp
    fixture = layout.InstallationTests.fixture

    def interrupted_initialization(self, phase):
        project, package, _ = self.fixture()
        mkdir, atomic = Path.mkdir, r.atomic
        def interrupt_mkdir(path, *args, **kwargs):
            mkdir(path, *args, **kwargs)
            if '.vpn-initialize-' in str(path) and path.name == phase:
                raise i.InstallError('INTERRUPTED')
        def interrupt_atomic(path, body, *args, **kwargs):
            if phase == 'journal' and path.name == 'installation.json':
                # Interrupt the actual atomic writer after its temporary file has
                # been written, before durability and publication of the journal.
                with patch.object(r.os, 'fsync', side_effect=i.InstallError('INTERRUPTED')):
                    atomic(path, body, *args, **kwargs)
            else:
                atomic(path, body, *args, **kwargs)
        with patch.object(Path, 'mkdir', interrupt_mkdir), patch.object(r, 'atomic', interrupt_atomic), \
             self.assertRaisesRegex(i.InstallError, 'INTERRUPTED'):
            i.install(package, '8.8.8.8', False)
        self.assertFalse((project / 'state').exists())
        self.assertFalse((project / 'config').exists())
        self.assertEqual(list(project.glob('.vpn-initialize-*')), [])
        self.assertFalse(any(call.args[0][1:3] == ['generate', 'reality-keypair'] for call in r.run.call_args_list))
        with redirect_stdout(io.StringIO()):
            i.install(package, '8.8.8.8', True)
        i.host_audit.assert_called_with(r, False)
        self.assertEqual(r.record(i.STATE)['status'], 'installed')
        self.assertEqual(r.record(r.ETC / 'devices.json')['devices'], {})

    def test_interruption_after_unpublished_state_directory_can_resume(self):
        self.interrupted_initialization('state')

    def test_interruption_after_unpublished_install_directory_can_resume(self):
        self.interrupted_initialization('install')

    def test_interruption_during_first_journal_write_can_resume(self):
        self.interrupted_initialization('journal')

    def test_publication_never_replaces_an_existing_empty_directory(self):
        project, package, _ = self.fixture()
        publish = i.publish_initial_state
        inode = []
        def conflict(source, destination):
            destination.mkdir(mode=0o700)
            inode.append(destination.stat().st_ino)
            publish(source, destination)
        with patch.object(i, 'publish_initial_state', side_effect=conflict), \
             self.assertRaisesRegex(i.InstallError, 'INITIAL_STATE_PUBLICATION_REFUSED'):
            i.install(package, '8.8.8.8', False)
        self.assertEqual((project / 'state').stat().st_ino, inode[0])
        self.assertEqual(list((project / 'state').iterdir()), [])

    def test_foreign_state_without_journal_is_refused_and_files_preserved(self):
        project, package, _ = self.fixture()
        i.ROOT.mkdir(mode=0o700, parents=True)
        (project / 'state').chmod(0o700)
        foreign = i.ROOT / 'user-file'
        foreign.write_bytes(b'must remain')
        with self.assertRaisesRegex(i.InstallError, 'INITIAL_CHECKPOINT_REQUIRED'):
            i.install(package, '8.8.8.8', True)
        self.assertEqual(foreign.read_bytes(), b'must remain')
        self.assertFalse(i.STATE.exists())
        r.run.assert_not_called()

    def test_missing_journal_never_regenerates_existing_identity(self):
        project, package, generation = self.fixture()
        generation.side_effect = r.StackError('SIMULATED_POLICY_FAILURE')
        with redirect_stdout(io.StringIO()), self.assertRaises(r.StackError):
            i.install(package, '8.8.8.8', False)
        identity = (i.ROOT / 'identity.json').read_bytes()
        config = (r.ETC / 'xray.json').read_bytes()
        i.STATE.unlink()
        r.run.reset_mock()
        with self.assertRaisesRegex(i.InstallError, 'INITIAL_CHECKPOINT_REQUIRED'):
            i.install(package, '8.8.8.8', True)
        self.assertEqual((i.ROOT / 'identity.json').read_bytes(), identity)
        self.assertEqual((r.ETC / 'xray.json').read_bytes(), config)
        r.run.assert_not_called()

    def test_existing_config_without_state_is_not_adopted_on_resume(self):
        project, package, _ = self.fixture()
        r.ETC.mkdir(mode=0o700)
        path = r.ETC / 'settings.json'
        path.write_bytes(b'private identity must remain')
        with self.assertRaisesRegex(i.InstallError, 'INITIAL_CHECKPOINT_REQUIRED'):
            i.install(package, '8.8.8.8', True)
        self.assertEqual(path.read_bytes(), b'private identity must remain')
        self.assertFalse(i.STATE.exists())
        r.run.assert_not_called()

    def test_unpublished_or_foreign_staging_is_preserved_and_never_adopted(self):
        project, package, _ = self.fixture()
        orphan = project / '.vpn-initialize-foreign'
        orphan.mkdir()
        (orphan / 'user-file').write_bytes(b'private user file')
        with redirect_stdout(io.StringIO()):
            i.install(package, '8.8.8.8', True)
        self.assertEqual((orphan / 'user-file').read_bytes(), b'private user file')
        self.assertEqual(r.record(i.STATE)['status'], 'installed')


class SocketPathTests(unittest.TestCase):
    setUp = baseline.TemporaryRuntimeTests.setUp

    def test_long_root_runtime_check_uses_short_private_unix_socket_and_cleans_it(self):
        self.check_short_socket()

    def test_short_socket_is_cleaned_when_native_config_check_fails(self):
        self.check_short_socket(fail_native=True)

    def check_short_socket(self, fail_native=False):
        personal = load('socket_personal_runtime', 'personal-runtime.py')
        core = load('socket_core', 'personal-policy.py')
        setup = load('socket_setup', 'transport-probes.py')
        checker = load('socket_checker', 'runtime-checker.py')
        project = self.root / 'project'
        work = project / 'data/generations/gen-20261012T130000Z-12345678'
        (work / 'assets').mkdir(parents=True)
        self.assertGreaterEqual(len(os.fsencode(work / 'personal-test/api.sock')), 104)
        manifest = {'files': {}}
        for tag in ('smart', 'direct', 'ads'):
            raw = b'synthetic MRS fixture'
            (work / 'assets' / (tag + '.mrs')).write_bytes(raw)
            (work / (tag + '.normalized.txt')).write_bytes(b'')
            manifest['files'][tag + '.mrs'] = {'sha256': hashlib.sha256(raw).hexdigest(), 'normalized_patterns': 1}
        witness = {'default': 'default.example', 'ads-child': 'default.example'}
        checker.SOURCE = work
        checker.witnesses = lambda: witness
        servers = []
        sockets = []
        class API(socketserver.StreamRequestHandler):
            def handle(self):
                while self.rfile.readline().strip():
                    pass
                body = json.dumps({'providers': {tag: {'ruleCount': 1} for tag in ('smart', 'direct', 'ads')}}).encode()
                self.wfile.write(b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)
        def start(args, **kwargs):
            config = Path(args[args.index('-f') + 1]).read_text()
            api = Path(core.line_value(config, 'external-controller-unix: '))
            sockets.append(api)
            self.assertEqual(api.parent.parent, project / 'data')
            self.assertLess(len(os.fsencode(api)), 104)
            self.assertEqual(api.parent.stat().st_mode & 0o777, 0o700)
            server = socketserver.UnixStreamServer(str(api), API)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            servers.append((server, thread))
            return SimpleNamespace(poll=lambda: None, pid=123)
        def stop(process):
            for server, thread in servers:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)
        checker.stop_process = stop
        checker.rss = lambda _: {}
        wire = SimpleNamespace(local_server=lambda *_: nullcontext(53000), spare_port=Mock(side_effect=[53001, 53002]),
                               lookup=Mock(return_value=['8.8.8.8']), check_listeners=Mock())
        s = SimpleNamespace(checker=checker, wire=wire, refresh=SimpleNamespace(BINARY=Path('/unused/mihomo')),
                            setup=setup, core=core, builder=SimpleNamespace(atomic_json=lambda p, v: p.write_text(json.dumps(v))))
        pilot = SimpleNamespace(MockDNS=SimpleNamespace(), check_dns_answer=Mock())
        values = {'proxy': [], 'direct': [], 'ads-exceptions': []}
        with patch.object(personal, 'runtime_cases', return_value=['default.example']), \
             patch.object(personal.subprocess, 'run', return_value=SimpleNamespace(returncode=1 if fail_native else 0)), \
             patch.object(personal.subprocess, 'Popen', side_effect=start), patch.object(personal.time, 'sleep'), \
             redirect_stdout(io.StringIO()):
            if fail_native:
                with self.assertRaisesRegex(personal.BuildError, 'PERSONAL_NATIVE_CONFIG_REJECTED'):
                    personal.runtime_check(s, core, pilot, work, manifest, values, r.base_config(s, work))
            else:
                result = personal.runtime_check(s, core, pilot, work, manifest, values, r.base_config(s, work))
                self.assertEqual(result['status'], 'ok')
                self.assertEqual(result['DNS_TCP_UDP_policy_checks'], 2)
                self.assertTrue(sockets)
        self.assertEqual(list((project / 'data').glob('.s-*')), [])

    def test_configure_and_audit_reject_overlong_root_before_any_host_commands(self):
        # Production controller.sock is the longest remaining absolute socket.
        max_bytes = 103 - len('/cache/backend/controller.sock'.encode())
        project = self.root / ('p' * (max_bytes + 1 - len(os.fsencode(self.root)) - 1))
        project.mkdir()
        with patch.object(i, 'PROJECT', i.PROJECT), self.assertRaisesRegex(i.InstallError, 'PROJECT_UNIX_SOCKET_PATH_TOO_LONG'):
            i.configure_project(project)
        with patch.object(i, 'PROJECT', project), patch.object(i.subprocess, 'run') as command, \
             self.assertRaisesRegex(i.InstallError, 'PROJECT_UNIX_SOCKET_PATH_TOO_LONG'):
            i.host_audit(r)
        command.assert_not_called()
        self.assertFalse((project / 'state').exists())

    def test_socket_limit_counts_utf8_bytes_and_accepts_exact_boundary(self):
        max_bytes = 103 - len('/cache/backend/controller.sock'.encode())
        for name, accepted in [('p' * (max_bytes - len(os.fsencode(self.root)) - 1), True),
                               ('я' * ((max_bytes - len(os.fsencode(self.root)) - 1) // 2 + 1), False)]:
            project = self.root / name
            project.mkdir()
            with patch.object(i, 'PROJECT', i.PROJECT), patch.object(i, 'ROOT', i.ROOT), \
                 patch.object(i, 'STATE', i.STATE), patch.object(i, 'PROFILE_ROOT', i.PROFILE_ROOT), \
                 patch.object(i, 'CLI_BODY', i.CLI_BODY):
                if accepted:
                    i.configure_project(project)
                    self.assertEqual(len(os.fsencode(project / 'cache/backend/controller.sock')), 103)
                else:
                    with self.assertRaisesRegex(i.InstallError, 'PROJECT_UNIX_SOCKET_PATH_TOO_LONG'):
                        i.configure_project(project)


if __name__ == '__main__':
    unittest.main()
