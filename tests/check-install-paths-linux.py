#!/usr/bin/env python3
"""Real systemd 255 parsing/execution with diagnostic programs, disposable Docker only.

No VPN credentials, upstream sources, public network, full installer or native
VPN binaries are used here. Native configuration/transport checks are separate.
"""
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import zipfile


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(*args):
    result = subprocess.run(list(args), capture_output=True, text=True, timeout=45)
    if result.returncode:
        raise RuntimeError('TEST_COMMAND_FAILED:' + args[0] + ':' + result.stderr.strip())
    return result.stdout.strip()


def wait(predicate):
    end = time.monotonic() + 15
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(.1)
    raise RuntimeError('PATH_TEST_TIMEOUT')


DIAGNOSTIC = '''#!/usr/bin/python3
import json,os,sys,time
from pathlib import Path
root = Path(ROOT_LITERAL)
receipt = {'argv': sys.argv, 'cwd': os.getcwd(), 'safe_paths': os.environ.get('SAFE_PATHS')}
print('PATH_RECEIPT=' + json.dumps(receipt), flush=True)
mode = Path(__file__).name
if mode == 'mihomo':
    (root / 'cache/backend/dns-receipt.json').write_text(json.dumps(receipt))
elif mode == 'vpn-stack-manage.py':
    (root / 'profiles/recover-receipt.json').write_text(json.dumps(receipt))
    sys.exit(0)
elif mode == 'vpn-stack-runtime.py' and sys.argv[1] != 'http':
    action = sys.argv[1]
    with (root / ('data/' + action + '-runs')).open('a') as stream:
        stream.write('applied\\n')
    if action == 'daily':
        for directory in ('config', 'data', 'cache/backend'):
            (root / directory / 'write-probe').write_text('ok')
    sys.exit(0)
while True:
    time.sleep(1)
'''


def check_project(installer, root):
    root.mkdir(mode=0o755, parents=True)
    installer.configure_project(root)
    runtime = SimpleNamespace(CODE=root / 'lib', ETC=root / 'config', DATA=root / 'data', HOME=root / 'cache/backend')
    account = pwd.getpwnam('vpn-policy')
    for path in (runtime.CODE, runtime.CODE / 'bin', runtime.ETC, runtime.DATA, root / 'cache', runtime.HOME, root / 'profiles'):
        path.mkdir(mode=0o755)
    runtime.HOME.chmod(0o700)
    os.chown(runtime.HOME, account.pw_uid, account.pw_gid)
    (root / 'profiles').chmod(0o700)
    for name in ('proxy.txt', 'proxy-ip.txt', 'direct.txt', 'ads-exceptions.txt'):
        (runtime.ETC / name).write_text('# synthetic rules\n')
    program = DIAGNOSTIC.replace('ROOT_LITERAL', repr(str(root)))
    for path in (runtime.CODE / 'bin/mihomo', runtime.CODE / 'bin/xray',
                 runtime.CODE / 'vpn-stack-runtime.py', runtime.CODE / 'vpn-stack-manage.py'):
        path.write_text(program)
        path.chmod(0o755)
    units = installer.units(runtime)
    system = Path('/etc/systemd/system')
    for name, body in units.items():
        (system / name).write_text(body)
    try:
        run('systemd-analyze', 'verify', *[str(system / name) for name in units])
        run('systemctl', 'daemon-reload')
        run('systemctl', 'start', 'vpn-stack-xray.service', 'vpn-stack-daily.service')
        receipt_path = runtime.HOME / 'dns-receipt.json'
        wait(receipt_path.exists)
        receipt = json.loads(receipt_path.read_text())
        assert receipt['cwd'] == str(runtime.HOME)
        assert receipt['argv'] == [str(runtime.CODE / 'bin/mihomo'), '-d', str(runtime.HOME), '-f', str(runtime.ETC / 'backend.yaml')]
        assert receipt['safe_paths'] == str(runtime.DATA / 'generations')
        assert run('systemctl', 'show', 'vpn-stack-dns.service', '-p', 'WorkingDirectory', '--value') == str(runtime.HOME)
        for directory in ('config', 'data', 'cache/backend'):
            assert (root / directory / 'write-probe').read_text() == 'ok'
        recovery = json.loads((root / 'profiles/recover-receipt.json').read_text())
        assert recovery['argv'] == [str(runtime.CODE / 'vpn-stack-manage.py'), 'recover']
        run('systemctl', 'start', 'vpn-stack-personal.path')
        counter = runtime.DATA / 'personal-runs'
        before = counter.read_text().count('\n') if counter.exists() else 0
        with (runtime.ETC / 'proxy.txt').open('a') as stream:
            stream.write('# watcher canary\n')
        wait(lambda: counter.exists() and counter.read_text().count('\n') > before)
        # CLI's shell quoting is exercised outside the project directory.
        cli = root / 'test-vpnctl'
        cli.write_bytes(installer.CLI_BODY)
        receipt = json.loads(run('sh', str(cli), 'recover').split('PATH_RECEIPT=', 1)[1])
        assert receipt['argv'] == [str(runtime.CODE / 'vpn-stack-manage.py'), 'recover']
        # Publication uses Linux renameat2(RENAME_NOREPLACE), not a mocked rename.
        staged = root / 'staged-state'
        staged.mkdir()
        (staged / 'journal').write_text('checkpoint')
        target = root / 'state'
        installer.publish_initial_state(staged, target)
        assert (target / 'journal').read_text() == 'checkpoint'
        staged.mkdir()
        try:
            installer.publish_initial_state(staged, target)
        except installer.InstallError:
            pass
        else:
            raise AssertionError('EXCLUSIVE_RENAME_DID_NOT_REFUSE')
        assert (target / 'journal').read_text() == 'checkpoint'
        return {'root': str(root), 'systemd_verify': True, 'literal_working_directory': True,
                'exec_argv_and_environment': True, 'sandbox_writable_paths': True,
                'watcher_triggered': True, 'cli_outside_project': True, 'exclusive_linux_state_publication': True}
    finally:
        subprocess.run(['systemctl', 'stop', *units], capture_output=True, timeout=45)
        for name in units:
            (system / name).unlink()
        run('systemctl', 'daemon-reload')
        run('systemctl', 'reset-failed')
        shutil.rmtree(root)


def main():
    assert sys.platform == 'linux' and os.geteuid() == 0 and Path('/.dockerenv').exists(), 'DISPOSABLE_DOCKER_ONLY'
    assert Path('/proc/1/comm').read_text().strip() == 'systemd', 'LIVE_SYSTEMD_REQUIRED'
    version = run('systemctl', '--version').splitlines()[0]
    assert version.split()[1] == '255', 'SYSTEMD_255_REQUIRED'
    artifact = Path('/repo/install-vpn.py')
    bundle = load('paths_bundle', artifact)
    raw = base64.b85decode(bundle.PAYLOAD)
    assert hashlib.sha256(raw).hexdigest() == bundle.PAYLOAD_SHA
    folder = Path(tempfile.mkdtemp(prefix='path-package-', dir='/tmp'))
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        for name in archive.namelist():
            assert Path(name).name == name
            (folder / name).write_bytes(archive.read(name))
    installer = load('paths_installer', folder / 'vpn-stack-install.py')
    try:
        pwd.getpwnam('vpn-policy')
    except KeyError:
        run('useradd', '--system', '--no-create-home', 'vpn-policy')
    root_mode = Path('/root').stat().st_mode
    assert root_mode & 0o777 == 0o700, 'ROOT_MUST_ALREADY_BE_0700'
    cases = [check_project(installer, Path(root)) for root in
             ('/root/vpn-tunnel', '/opt/vpn project', '/opt/vpn "quoted" $HOME\\folder',
              '/opt/vpn:colon', '/srv/deployments/vpn-projects/vpn-tunel')]
    assert Path('/root').stat().st_mode == root_mode, 'ROOT_PERMISSIONS_CHANGED'
    report = {'status': 'passed', 'systemd': version, 'scope': 'real systemd parser and sandbox; diagnostic executables',
              'cases': cases, 'standalone_SHA256': hashlib.sha256(artifact.read_bytes()).hexdigest(),
              'VPN_native_binaries': False, 'full_installation': False, 'physical_devices': False,
              'working_VPS_contacted': False}
    Path('/results/systemd-paths.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report), flush=True)


if __name__ == '__main__':
    main()
