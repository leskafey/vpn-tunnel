#!/usr/bin/env python3
"""Real Mihomo/HTTP and filesystem isolation under systemd in disposable Ubuntu.

Requires /repo, pinned ARM64 binaries in /native-binaries and their checksums in
/native-checksums.json. No external sources, public VPN ingress or full install.
Never changes the permissions of /root, even inside the container.
"""
import atexit
import base64
import hashlib
import importlib.util
import io
import ipaddress
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import time
from types import SimpleNamespace
import urllib.request
import zipfile


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(*args):
    result = subprocess.run([str(a) for a in args], capture_output=True, text=True, timeout=45)
    if result.returncode:
        raise RuntimeError('TEST_COMMAND_FAILED:' + str(args[0]) + ':' + result.stderr.strip())
    return result.stdout.strip()


def wait(predicate):
    end = time.monotonic() + 20
    while time.monotonic() < end:
        try:
            if predicate():
                return
        except (OSError, ValueError):
            pass
        time.sleep(.1)
    raise RuntimeError('SERVICE_ACCESS_TEST_TIMEOUT')


ACCESS_PROBE = '''import errno,json,os,sys
from pathlib import Path
root = Path('/root/vpn-tunnel')
tag = sys.argv[1]
def readable(path):
    try:
        path.read_bytes()
        return True
    except OSError:
        return False
assert os.geteuid() != 0
assert readable(root / 'lib/vpn-stack-runtime.py')
assert readable(root / 'data/current/proxy-ipv4.json')
for name in ('config/xray.json', 'config/probe-client.json', 'config/settings.json',
             'config/devices.json', 'config/proxy.txt', 'config/proxy-ip.txt',
             'config/direct.txt', 'config/ads-exceptions.txt', 'profiles/phone-smart.json',
             'state/install/identity.json'):
    assert not readable(root / name), name
assert not readable(Path('/root/namespace-unrelated-canary'))
for name in ('lib/write-canary', 'data/current/write-canary', 'config/write-canary'):
    try:
        (root / name).write_text('must fail')
    except OSError as error:
        assert error.errno in (errno.EACCES, errno.EROFS, errno.ENOENT)
    else:
        raise AssertionError('UNEXPECTED_WRITE:' + name)
if tag == 'dns':
    assert readable(root / 'config/backend.yaml')
    (root / 'cache/backend/access-write-canary').write_text('ok')
else:
    assert not readable(root / 'config/backend.yaml')
    assert not readable(root / 'cache/backend/access-write-canary')
print('ACCESS_RECEIPT=' + json.dumps({'service': tag, 'uid': os.geteuid(),
      'private_data_denied': True, 'read_only_data': True}), flush=True)
'''


def main():
    assert sys.platform == 'linux' and os.geteuid() == 0 and Path('/.dockerenv').exists(), 'DISPOSABLE_DOCKER_ONLY'
    assert Path('/proc/1/comm').read_text().strip() == 'systemd', 'LIVE_SYSTEMD_REQUIRED'
    assert run('systemctl', '--version').split()[1] == '255', 'SYSTEMD_255_REQUIRED'
    root_home = Path('/root')
    original = root_home.stat()
    assert original.st_mode & 0o777 == 0o700, 'ROOT_MUST_ALREADY_BE_0700'
    root = root_home / 'vpn-tunnel'
    assert not root.exists(), 'TEST_PROJECT_ALREADY_EXISTS'
    artifact = Path('/repo/install-vpn.py')
    bundle = load('root_bundle', artifact)
    raw = base64.b85decode(bundle.PAYLOAD)
    assert hashlib.sha256(raw).hexdigest() == bundle.PAYLOAD_SHA
    root.mkdir(mode=0o700)
    atexit.register(shutil.rmtree, root, ignore_errors=True)
    os.umask(0o077)
    package = root / 'package'
    package.mkdir()
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        for name in archive.namelist():
            assert Path(name).name == name
            (package / name).write_bytes(archive.read(name))
    installer = load('root_installer', package / 'vpn-stack-install.py')
    installer.configure_project(root)
    runtime = installer.load_runtime(package)
    # Real read-only prerequisite audit before the account and data exist.
    access = installer.audit_policy_namespace()
    assert access['view_root'] == '/root'
    try:
        account = pwd.getpwnam('vpn-policy')
    except KeyError:
        run('useradd', '--system', '--no-create-home', '--home-dir', '/nonexistent',
            '--shell', '/usr/sbin/nologin', 'vpn-policy')
        account = pwd.getpwnam('vpn-policy')
    installer.prepare_service_directories(runtime, account, False)
    # Repeat directory preparation with partial/wrong service modes: real
    # chown/chmod are used, but the complete installer is deliberately not run.
    runtime.ETC.chmod(0o700)
    runtime.HOME.chmod(0o755)
    installer.prepare_service_directories(runtime, account, True)
    assert runtime.ETC.stat().st_gid == account.pw_gid and runtime.ETC.stat().st_mode & 0o777 == 0o750
    assert runtime.HOME.stat().st_uid == account.pw_uid and runtime.HOME.stat().st_mode & 0o777 == 0o700
    for name in archive.namelist():
        runtime.atomic(runtime.CODE / name, (package / name).read_bytes(), 0o644)
    checksums = json.loads(Path('/native-checksums.json').read_bytes())
    binary = Path('/native-binaries/mihomo').read_bytes()
    assert hashlib.sha256(binary).hexdigest() == checksums['mihomo']
    runtime.atomic(runtime.CODE / 'bin/mihomo', binary, 0o755)
    assert '1.19.31' in run(runtime.CODE / 'bin/mihomo', '-v')
    for name in ('xray.json', 'probe-client.json', 'settings.json', 'devices.json', *installer.RULE_INSTRUCTIONS):
        runtime.atomic(runtime.ETC / name, b'private canary\n')
    (root / 'profiles').mkdir(mode=0o700)
    runtime.atomic(root / 'profiles/phone-smart.json', b'private profile canary\n')
    (root / 'state/install').mkdir(parents=True, mode=0o700)
    (root / 'state').chmod(0o700)
    runtime.atomic(root / 'state/install/identity.json', b'private key canary\n')
    canary = root_home / 'namespace-unrelated-canary'
    assert not canary.exists()
    canary.write_text('outside the installed project\n')
    atexit.register(canary.unlink, missing_ok=True)
    canary.chmod(0o644)
    runtime.atomic(runtime.CODE / 'access-probe.py', ACCESS_PROBE.encode(), 0o644)
    setup = load('root_setup', runtime.CODE / 'transport-probes.py')
    core = load('root_core', runtime.CODE / 'personal-policy.py')
    wire = load('root_wire', runtime.CODE / 'dns-wire.py')
    def generation(name, domain):
        work = runtime.DATA / 'generations' / name
        work.mkdir(mode=0o750)
        work.chmod(0o750)
        os.chown(work, 0, account.pw_gid)
        (work / 'assets').mkdir(mode=0o750)
        (work / 'assets').chmod(0o750)
        os.chown(work / 'assets', 0, account.pw_gid)
        for tag, entry in (('smart', domain), ('direct', 'direct.invalid'), ('ads', 'ads.invalid')):
            source = work / (tag + '.txt')
            source.write_text('+.' + entry + '\n')
            output = work / 'assets' / (tag + '.mrs')
            run(runtime.CODE / 'bin/mihomo', 'convert-ruleset', 'domain', 'text', source, output)
            output.chmod(0o640)
            os.chown(output, 0, account.pw_gid)
        runtime.atomic(work / 'proxy-ipv4.json', runtime.ip_body([ipaddress.ip_network('8.8.8.8/32')])[0], 0o640, account.pw_gid)
        runtime.atomic(work / 'personal-direct-domains.json', runtime.direct_body([domain]), 0o640, account.pw_gid)
        runtime.atomic(work / 'manifest.json', b'private manifest canary\n')
        return work
    first = generation('gen-first', 'first.example')
    runtime.pointer(first)
    runtime.atomic(runtime.CONFIG, runtime.base_config(SimpleNamespace(setup=setup, core=core), first).encode(), 0o640, account.pw_gid)
    all_units = installer.units(runtime)
    units = {name: all_units[name] for name in ('vpn-stack-dns.service', 'vpn-stack-http.service')}
    system = Path('/etc/systemd/system')
    for name, body in units.items():
        assert not (system / name).exists(), 'FOREIGN_UNIT_EXISTS'
        tag = name.split('-')[2].split('.')[0]
        post = 'ExecStartPost=/usr/bin/python3 ' + str(runtime.CODE / 'access-probe.py') + ' ' + tag + '\n'
        (system / name).write_text(body.replace('[Install]', post + '[Install]'))
    try:
        run('systemd-analyze', 'verify', *[system / name for name in units])
        run('systemctl', 'daemon-reload')
        run('systemctl', 'start', *units)
        for name in units:
            assert run('systemctl', 'is-active', name) == 'active'
            assert 'ACCESS_RECEIPT=' in run('journalctl', '-u', name, '-o', 'cat', '--no-pager')
            assert run('systemctl', 'show', name, '-p', 'User', '--value') == 'vpn-policy'
        assert run('systemctl', 'show', 'vpn-stack-dns.service', '-p', 'WorkingDirectory', '--value') == str(runtime.HOME)
        wait(lambda: bool(wire.lookup(19053, 'first.example', 'tcp')))
        for protocol in ('tcp', 'udp'):
            address = wire.lookup(19053, 'first.example', protocol)
            assert ipaddress.ip_address(address) in runtime.FAKE
        def document(name):
            with urllib.request.urlopen('http://127.0.0.1:8080/' + name, timeout=2) as response:
                return response.read()
        assert document('proxy-ipv4.json') == (first / 'proxy-ipv4.json').read_bytes()
        assert document('personal-direct-domains.json') == (first / 'personal-direct-domains.json').read_bytes()
        pid = run('systemctl', 'show', 'vpn-stack-http.service', '-p', 'MainPID', '--value')
        second = generation('gen-second', 'second.example')
        runtime.pointer(second)
        assert document('personal-direct-domains.json') == (second / 'personal-direct-domains.json').read_bytes()
        assert run('systemctl', 'show', 'vpn-stack-http.service', '-p', 'MainPID', '--value') == pid
        runtime.atomic(runtime.CONFIG, runtime.base_config(SimpleNamespace(setup=setup, core=core), second).encode(), 0o640, account.pw_gid)
        run('systemctl', 'restart', 'vpn-stack-dns.service')
        address = wire.lookup(19053, 'second.example', 'tcp')
        assert ipaddress.ip_address(address) in runtime.FAKE
        denied = subprocess.run(['runuser', '-u', 'vpn-policy', '--', 'cat', str(runtime.CODE / 'vpn-stack-runtime.py')],
                                capture_output=True, timeout=5)
        assert denied.returncode != 0, 'HOST_ROOT_TRAVERSAL_WAS_GRANTED'
        assert root_home.stat().st_mode == original.st_mode and root_home.stat().st_uid == original.st_uid
        assert root.stat().st_mode & 0o777 == 0o700
        report = {'status': 'passed', 'architecture': run('uname', '-m'), 'systemd': run('systemctl', '--version').splitlines()[0],
                  'root_mode_before_and_after': '0700', 'project_mode': '0700',
                  'services': 'real pinned Mihomo 1.19.31 and project HTTP under vpn-policy',
                  'private_data_read_and_policy_data_write_denied': True, 'DNS_TCP_UDP': True,
                  'HTTP_generation_switch_without_restart': True, 'atomic_DNS_config_replacement': True,
                  'directory_preparation_resume': True, 'full_installer_resume': False,
                  'standalone_SHA256': hashlib.sha256(artifact.read_bytes()).hexdigest(),
                  'full_installation': False, 'public_ingress_and_physical_clients': False, 'working_VPS_contacted': False}
        Path('/tmp/root-access-results.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report), flush=True)
    finally:
        subprocess.run(['systemctl', 'stop', *units], capture_output=True, timeout=45)
        for name in units:
            (system / name).unlink()
        run('systemctl', 'daemon-reload')
        shutil.rmtree(root)
        canary.unlink()


if __name__ == '__main__':
    main()
