#!/usr/bin/env python3
"""Native bootstrap acceptance in a DISPOSABLE Docker Ubuntu container only.

This is deliberately NOT bundled in install-vpn.py. The endpoint is a synthetic
local public-address alias; expected WAN exit is the container's NAT exit. It
proves Linux services and VLESS locally, not public ingress into a fresh VPS.
"""
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import urllib.request
import zipfile


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def main():
    assert sys.platform == 'linux' and os.geteuid() == 0 and Path('/.dockerenv').is_file(), 'DISPOSABLE_CONTAINER_ONLY'
    os.umask(0o077)
    artifact = module('linux_test_standalone', Path('/root/vpn-tunnel/install-vpn.py'))
    payload = base64.b85decode(artifact.PAYLOAD)
    assert hashlib.sha256(payload).hexdigest() == artifact.PAYLOAD_SHA
    with tempfile.TemporaryDirectory(prefix='installer-acceptance-') as directory:
        folder = Path(directory)
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            for name in archive.namelist():
                assert Path(name).name == name
                (folder / name).write_bytes(archive.read(name))
        installer = module('linux_test_bootstrap', folder / 'vpn-stack-install.py')
        installer.configure_project(Path('/root/vpn-tunnel'))
        runtime = installer.load_runtime(folder)
        if '--binary-cache' in sys.argv[1:]:
            checksums = json.loads(Path('/root/native-binary-checksums.json').read_bytes())
            def verified_cache(r, name, item):
                raw = (Path('/root/native-binaries') / name).read_bytes()
                assert hashlib.sha256(raw).hexdigest() == checksums[name]
                r.atomic(r.CODE / 'bin' / name, raw, 0o755)
                return checksums[name]
            installer.download_binary = verified_cache
        original_modules = runtime.modules
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open('https://api.ipify.org', timeout=20) as response:
            expected_exit = response.read(64).decode().strip()
        def test_modules():
            s = original_modules()
            s.setup.PUBLIC_IP = expected_exit
            return s
        runtime.modules = test_modules
        installer.load_runtime = lambda _: runtime
        signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(RuntimeError('SOURCE_DOWNLOAD_TIMEOUT')))
        alias = '9.9.9.9'
        resume = '--resume' in sys.argv[1:]
        if not resume:
            subprocess.run(['ip', 'address', 'add', alias + '/32', 'dev', 'lo'], check=True, capture_output=True)
        # Home-network UDP/NAT is not a public-VPS egress test. Exercise real
        # VLESS XUDP and fake-destination return mapping with a local STUN peer.
        class DNS(socketserver.BaseRequestHandler):
            def handle(self):
                packet, sock = self.request
                end = 12
                while packet[end]:
                    end += 1 + packet[end]
                end += 1
                question = packet[12:end + 4]
                answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 1, 4) + socket.inet_aton(alias)
                sock.sendto(packet[:2] + struct.pack('!HHHHH', 0x8180, 1, 1, 0, 0) + question + answer, self.client_address)
        class STUN(socketserver.BaseRequestHandler):
            def handle(self):
                packet, sock = self.request
                cookie = 0x2112a442
                mapped = bytes(a ^ b for a, b in zip(socket.inet_aton(self.client_address[0]), struct.pack('!I', cookie)))
                attribute = struct.pack('!HHBBH', 0x0020, 8, 0, 1, self.client_address[1] ^ (cookie >> 16)) + mapped
                sock.sendto(struct.pack('!HHI', 0x0101, len(attribute), cookie) + packet[8:20] + attribute, self.client_address)
        dns = socketserver.UDPServer(('127.0.0.1', 0), DNS)
        stun = socketserver.UDPServer((alias, 19302), STUN)
        for server in (dns, stun):
            threading.Thread(target=server.serve_forever, daemon=True).start()
        original_base = runtime.base_config
        runtime.base_config = lambda s, source: original_base(s, source).replace('  nameserver:\n',
            '  nameserver-policy: {"stun.l.google.com": ["udp://127.0.0.1:' + str(dns.server_address[1]) + '"]}\n  nameserver:\n')
        def local_modules():
            s = test_modules()
            original_stun = s.setup.stun_socks
            def local_stun(*args):
                old = s.setup.PUBLIC_IP
                s.setup.PUBLIC_IP = alias
                try:
                    original_stun(*args)
                finally:
                    s.setup.PUBLIC_IP = old
            s.setup.stun_socks = local_stun
            return s
        runtime.modules = local_modules
        installer.install(folder, alias, resume)
        source, manifest = runtime.active()
        for user in ('vpn-stack-xray.service', 'vpn-stack-dns.service', 'vpn-stack-http.service'):
            assert runtime.run(['systemctl', 'is-active', user], 'SERVICE_NOT_ACTIVE').strip() == b'active'
        admin = module('linux_test_admin', runtime.CODE / 'vpn-stack-manage.py')
        original = runtime.raw_file(runtime.ETC / 'xray.json', 1048576)
        assert runtime.record(runtime.ETC / 'devices.json')['devices'] == {}
        assert list((runtime.PROJECT / 'profiles').iterdir()) == []
        admin.device(runtime, 'add', 'laptop-macos')
        assert 'laptop-macos' in runtime.record(runtime.ETC / 'devices.json')['devices']
        admin.device(runtime, 'revoke', 'laptop-macos')
        assert runtime.raw_file(runtime.ETC / 'xray.json', 1048576) == original
        # No generated profiles/keys enter this public report.
        output = {'status': 'passed', 'scope': 'Ubuntu 24.04 amd64 emulation, isolated Docker/systemd; synthetic local endpoint',
                  'bootstrap': 'passed', 'native_temporary_SMART_FULL_profiles': 2, 'real_VLESS_new_device_and_revoke': 'passed',
                  'native_DNS_TCP_UDP_real_HTTPS': 'passed', 'local_VLESS_fake_UDP_STUN': 'passed',
                  'external_UDP_STUN_tested': False, 'counts': manifest['counts'],
                  'JSON_bytes': manifest['ip']['JSON_bytes'], 'CIDRs': manifest['ip']['CIDRs'],
                  'public_VPS_ingress_tested': False, 'working_VPS_contacted': False,
                  'standalone_SHA256': hashlib.sha256(Path('/root/vpn-tunnel/install-vpn.py').read_bytes()).hexdigest()}
        Path('/root/installer-acceptance-report.json').write_text(json.dumps(output, indent=2) + '\n')
        print('NATIVE_BOOTSTRAP_ACCEPTANCE=' + json.dumps(output), flush=True)


if __name__ == '__main__':
    try:
        main()
    except BaseException as error:
        value = {'status': 'failed', 'error_type': type(error).__name__}
        code = str(error)
        if code and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789' for c in code):
            value['code'] = code
        print('NATIVE_BOOTSTRAP_ACCEPTANCE=' + json.dumps(value), flush=True)
        import traceback
        print('FAILURE_LOCATIONS=' + json.dumps([{'file': Path(f.filename).name, 'line': f.lineno, 'function': f.name}
              for f in traceback.extract_tb(error.__traceback__)]), flush=True)
        sys.exit(1)
