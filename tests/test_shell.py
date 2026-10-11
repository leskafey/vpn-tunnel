"""Exercise shell argument forwarding without root or host service changes."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent


class ShellTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(prefix='vpn-shell-tests-')
        self.addCleanup(self.folder.cleanup)
        self.home = Path(self.folder.name).resolve()
        self.repo = self.home / 'repository with spaces'
        self.bin = self.home / 'fake-bin'
        self.repo.mkdir()
        self.bin.mkdir()
        for name in ('install.sh', 'audit.sh', 'vpnctl.sh'):
            shutil.copy2(ROOT / name, self.repo / name)
        (self.repo / 'install-vpn.py').write_text('# Never executed by these tests.\n')
        self.log = self.home / 'calls.jsonl'
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ['PATH'],
                        SHELL_TEST_LOG=str(self.log))
        self.fake('id', '#!/bin/sh\nprintf "0\\n"\n')
        for name in ('python3', 'systemd-run'):
            # An absolute real interpreter avoids recursively calling the fake.
            import sys
            self.fake(name, '#!' + sys.executable + '\n'
                      'import json,os,sys\n'
                      'with open(os.environ["SHELL_TEST_LOG"],"a") as f:\n'
                      ' f.write(json.dumps(sys.argv) + "\\n")\n'
                      'sys.exit(int(os.environ.get("SHELL_TEST_EXIT", "0")))\n')

    def fake(self, name, body):
        path = self.bin / name
        path.write_text(body)
        path.chmod(0o755)

    def run_shell(self, *arguments, script='install.sh'):
        return subprocess.run(['bash', str(self.repo / script), *arguments],
                              env=self.env, capture_output=True, text=True, timeout=10,
                              cwd=self.home)

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def test_help_runs_no_python_or_services(self):
        self.fake('id', '#!/bin/sh\nexit 99\n')
        for script in ('install.sh', 'audit.sh', 'vpnctl.sh'):
            result = self.run_shell('--help', script=script)
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls(), [])

    def test_audit_only_calls_python_without_systemd(self):
        result = self.run_shell(script='audit.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls(), [[str(self.bin / 'python3'), str(self.repo / 'install-vpn.py'), 'audit']])

    def test_install_uses_bounded_unit_and_preserves_space_in_path(self):
        result = self.run_shell('--server-ip', '8.8.8.8')
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls()
        self.assertEqual(len(calls), 1)
        argv = calls[0]
        self.assertEqual(argv[0], str(self.bin / 'systemd-run'))
        for item in ('--wait', '--pipe', '--collect', 'MemoryMax=768M', 'MemorySwapMax=0', 'RuntimeMaxSec=1800'):
            self.assertIn(item, argv)
        self.assertEqual(argv[-5:], [str(self.bin / 'python3'), str(self.repo / 'install-vpn.py'),
                                     'install', '--server-ip', '8.8.8.8'])

    def test_resume_and_equals_argument_forwarded(self):
        result = self.run_shell('install', '--server-ip=8.8.8.8', '--resume')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls()[0][-4:], ['install', '--server-ip', '8.8.8.8', '--resume'])

    def test_invalid_arguments_never_start_services(self):
        for args in ((), ('--server-ip',), ('--server-ip', '--resume'), ('--server-ip=',),
                     ('--server-ip', '8.8.8.8', '--server-ip', '9.9.9.9'),
                     ('audit', '--resume'), ('--unknown',)):
            with self.subTest(args=args):
                self.assertEqual(self.run_shell(*args).returncode, 2)
                self.assertEqual(self.calls(), [])

    def test_non_root_never_calls_python_or_systemd(self):
        self.fake('id', '#!/bin/sh\nprintf "1000\\n"\n')
        self.assertEqual(self.run_shell('--server-ip', '8.8.8.8').returncode, 2)
        self.assertEqual(self.calls(), [])

    def test_argument_is_literal_and_no_shell_interpolation(self):
        marker = self.home / 'should-not-exist'
        value = '$(touch "' + str(marker) + '")'
        self.assertEqual(self.run_shell('--server-ip', value).returncode, 0)
        self.assertEqual(self.calls()[0][-1], value)
        self.assertFalse(marker.exists())

    def test_subprocess_exit_code_preserved(self):
        self.env['SHELL_TEST_EXIT'] = '75'
        self.assertEqual(self.run_shell('--server-ip', '8.8.8.8').returncode, 75)
        self.assertEqual(self.run_shell(script='audit.sh').returncode, 75)


if __name__ == '__main__':
    unittest.main()
