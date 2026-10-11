#!/usr/bin/env python3
"""Targeted native regressions in a disposable Ubuntu Docker container.

Run with /repo read-only, /native-binaries read-only and CAP_NET_ADMIN for a
synthetic public IP on loopback. No public DNS, VPS, HTTPS or STUN is needed.
This does not run the full installer or test real-device import/public ingress.
"""
import base64
from contextlib import ExitStack, nullcontext
import hashlib
import importlib.util
import io
import json
import os
import platform
from pathlib import Path
import shutil
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import uuid
import zipfile


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def main():
    assert sys.platform == 'linux' and os.geteuid() == 0 and Path('/.dockerenv').is_file(), 'DISPOSABLE_CONTAINER_ONLY'
    os.umask(0o077)
    artifact = Path('/repo/install-vpn.py')
    bundled = load('native_bundle', artifact)
    payload = base64.b85decode(bundled.PAYLOAD)
    assert hashlib.sha256(payload).hexdigest() == bundled.PAYLOAD_SHA
    with tempfile.TemporaryDirectory(prefix='review-', dir='/tmp') as folder, ExitStack() as stack:
        root = Path(folder)
        if '--long-project-root' in sys.argv[1:]:
            root = Path('/srv/deployments/vpn-projects/vpn-tunel')
            assert not root.exists(), 'TEST_PROJECT_ALREADY_EXISTS'
            root.mkdir(parents=True, mode=0o700)
            stack.callback(shutil.rmtree, root)
        code, etc, data, profiles = [root / n for n in ('code', 'etc', 'data', 'profiles')]
        def debug_failure():
            if sys.exc_info()[0] is not None:
                debug = Path('/results/private-debug')
                debug.mkdir(mode=0o700, exist_ok=True)
                for log in root.rglob('*.private.log'):
                    shutil.copyfile(log, debug / log.name)
        stack.callback(debug_failure)
        for path in (code, etc, data, profiles, code / 'bin', data / 'generations'):
            path.mkdir()
        checksums = json.loads(Path('/native-checksums.json').read_bytes())
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            for name in archive.namelist():
                assert Path(name).name == name
                (code / name).write_bytes(archive.read(name))
        for name in ('xray', 'sing-box', 'mihomo'):
            raw = (Path('/native-binaries') / name).read_bytes()
            assert hashlib.sha256(raw).hexdigest() == checksums[name]
            (code / 'bin' / name).write_bytes(raw)
            (code / 'bin' / name).chmod(0o755)
        r = load('native_review_runtime', code / 'vpn-stack-runtime.py')
        m = load('native_review_manage', code / 'vpn-stack-manage.py')
        r.CODE, r.ETC, r.DATA, r.CONFIG = code, etc, data, etc / 'backend.yaml'
        r.GROUP, m.PROFILES = 'root', profiles
        wire = load('native_review_wire', code / 'dns-wire.py')
        checker = load('native_review_checker', code / 'runtime-checker.py')
        personal = load('native_review_personal', code / 'personal-runtime.py')
        core = load('native_review_core', code / 'personal-policy.py')
        pilot = load('native_review_pilot', code / 'personal-checker.py')
        setup = load('native_review_setup', code / 'transport-probes.py')
        r.atomic(data / 'update.lock', b'')
        r.atomic(etc / 'settings.json', r.dump({'server_ip': '9.9.9.9'}))
        alias = '9.9.9.9'
        subprocess.run(['ip', 'address', 'add', alias + '/32', 'dev', 'lo'], check=True, capture_output=True)
        keypair = r.run([code / 'bin/sing-box', 'generate', 'reality-keypair'], 'KEYPAIR_FAILED').decode()
        keys = dict(line.split(':', 1) for line in keypair.splitlines() if ':' in line)
        identities = {name: str(uuid.uuid4()) for name in ('probe', 'laptop-macos', 'android-phone')}
        short = '0123456789abcdef'
        transport = {'type': 'vless', 'tag': 'vps', 'server': '127.0.0.1', 'server_port': 443,
                     'uuid': identities['probe'], 'flow': 'xtls-rprx-vision', 'packet_encoding': 'xudp',
                     'tls': {'enabled': True, 'server_name': 'example.org',
                             'utls': {'enabled': True, 'fingerprint': 'chrome'},
                             'reality': {'enabled': True, 'public_key': keys['PublicKey'].strip(), 'short_id': short}}}
        # An entirely local TLS 1.3 REALITY camouflage target.
        cert, key = root / 'cert.pem', root / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                        '-nodes', '-keyout', str(key), '-out', str(cert), '-days', '1',
                        '-subj', '/CN=example.org'], check=True, capture_output=True)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
        tls.minimum_version = ssl.TLSVersion.TLSv1_3
        class TLS(socketserver.BaseRequestHandler):
            def handle(self):
                try:
                    with tls.wrap_socket(self.request, server_side=True) as stream:
                        stream.settimeout(2)
                        stream.recv(4096)
                except (OSError, ssl.SSLError):
                    pass
        class TCP(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True
        target = stack.enter_context(TCP(('127.0.0.1', 0), TLS))
        threading.Thread(target=target.serve_forever, daemon=True).start()
        stack.callback(target.shutdown)
        http = stack.enter_context(r.HTTPServer(('127.0.0.1', 8080), r.Handler))
        threading.Thread(target=http.serve_forever, daemon=True).start()
        stack.callback(http.shutdown)
        # A listener proves a denied request didn't just hit a closed port.
        seen_private = []
        class Canary(socketserver.BaseRequestHandler):
            def handle(self):
                seen_private.append(True)
                self.request.sendall(b'private-service')
        canary = stack.enter_context(TCP(('127.0.0.1', 2222), Canary))
        threading.Thread(target=canary.serve_forever, daemon=True).start()
        stack.callback(canary.shutdown)
        # A public-number canary is confined to this container's loopback.
        class Public(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.sendall(b'public-service')
        public = stack.enter_context(TCP((alias, 18080), Public))
        threading.Thread(target=public.serve_forever, daemon=True).start()
        stack.callback(public.shutdown)
        dns_queries = []
        class Rebinding(socketserver.BaseRequestHandler):
            def handle(self):
                packet, sock = self.request
                dns_queries.append(True)
                _, end = wire.read_name(packet, 12)
                question = packet[12:end + 4]
                ip = alias if len(dns_queries) == 1 else '127.0.0.1'
                answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 0, 4) + socket.inet_aton(ip)
                sock.sendto(packet[:2] + struct.pack('!5H', 0x8180, 1, 1, 0, 0) + question + answer, self.client_address)
        upstream = stack.enter_context(socketserver.ThreadingUDPServer(('127.0.0.1', 0), Rebinding))
        threading.Thread(target=upstream.serve_forever, daemon=True).start()
        stack.callback(upstream.shutdown)
        Path('/etc/hosts').open('a').write('\n127.0.0.1 private.test\n9.9.9.9 public.test\n')
        cfg = r.xray_config(keys['PrivateKey'].strip(), short, identities)
        cfg['inbounds'][0]['streamSettings']['realitySettings'].update(
            target='127.0.0.1:' + str(target.server_address[1]), serverNames=['example.org'])
        cfg['dns'] = {'servers': [{'address': '127.0.0.1', 'port': upstream.server_address[1]}]}
        raw = r.dump(cfg)
        r.atomic(etc / 'xray.json', raw)
        r.atomic(etc / 'devices.json', r.dump({'schema': 1, 'xray_sha256': hashlib.sha256(raw).hexdigest(),
            'devices': {n: {'uuid': identities[n], 'platform': 'universal'} for n in ('laptop-macos', 'android-phone')}}))
        r.atomic(etc / 'probe-client.json', r.dump({'outbounds': [transport], 'route': {'final': 'vps'}}))
        r.run([code / 'bin/xray', 'run', '-test', '-config', etc / 'xray.json'], 'XRAY_CONFIG_FAILED')
        # Each real client profile must remain acceptable to the pinned core.
        for profile_platform in ('universal', 'macos', 'windows', 'ios', 'android'):
            for full in (False, True):
                path = root / (profile_platform + ('-full.json' if full else '-smart.json'))
                r.atomic(path, r.dump(r.profile(transport, profile_platform, full)))
                r.run([code / 'bin/sing-box', 'check', '-c', path], 'PROFILE_CHECK_FAILED')
        server = [None]
        def stop():
            checker.stop_process(server[0])
            server[0] = None
        stack.callback(stop)
        def restart():
            stop()
            log = stack.enter_context((root / ('xray-' + uuid.uuid4().hex + '.private.log')).open('wb'))
            server[0] = subprocess.Popen([str(code / 'bin/xray'), 'run', '-config', str(etc / 'xray.json')],
                                         stdout=log, stderr=log)
            deadline = time.monotonic() + 8
            while True:
                assert server[0].poll() is None, 'XRAY_EXITED'
                try:
                    with socket.create_connection(('127.0.0.1', 443), timeout=.2):
                        break
                except OSError:
                    assert time.monotonic() < deadline, 'XRAY_NOT_READY'
                    time.sleep(.1)
        restart()
        s = SimpleNamespace(wire=wire, checker=checker)
        # The normal numeric DNS exception and fake-IP->SOCKS path also remain
        # usable. Only the test upstream changes; runtime private-IP rules stay.
        class StaticDNS(Rebinding):
            def handle(self):
                packet, sock = self.request
                _, end = wire.read_name(packet, 12)
                answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 1, 4) + socket.inet_aton(alias)
                sock.sendto(packet[:2] + struct.pack('!5H', 0x8180, 1, 1, 0, 0)
                            + packet[12:end + 4] + answer, self.client_address)
        static = stack.enter_context(socketserver.ThreadingUDPServer(('127.0.0.1', 0), StaticDNS))
        threading.Thread(target=static.serve_forever, daemon=True).start()
        stack.callback(static.shutdown)
        backend_home = root / 'backend'
        backend_home.mkdir()
        backend_config = setup.backend_config().replace('https://1.1.1.1/dns-query',
                            '127.0.0.1:' + str(static.server_address[1])).replace(
                            '    - 1.1.1.1', '    - 127.0.0.1:' + str(static.server_address[1]))
        path = backend_home / 'config.yaml'
        path.write_text(backend_config)
        log = stack.enter_context((root / 'backend.private.log').open('wb'))
        backend = subprocess.Popen([str(code / 'bin/mihomo'), '-d', str(backend_home), '-f', str(path)],
                                   stdout=log, stderr=log)
        stack.callback(checker.stop_process, backend)
        deadline = time.monotonic() + 10
        while True:
            assert backend.poll() is None, 'BACKEND_EXITED'
            try:
                wire.lookup(19053, 'api.ipify.org', 'tcp')
                break
            except (OSError, wire.PilotError):
                assert time.monotonic() < deadline, 'BACKEND_NOT_READY'
                time.sleep(.1)
        # Domain SOCKS encoding preserves the VLESS wire domain; IPv4 helper
        # intentionally used numeric-only requests in historical acceptance.
        def request(port, host, dest_port, force_domain=False):
            if not force_domain:
                return wire.socks_request(port, 1, host, dest_port)[0]
            stream = socket.create_connection(('127.0.0.1', port), timeout=4)
            stream.sendall(b'\x05\x01\x00')
            assert wire.recv_exact(stream, 2) == b'\x05\x00'
            encoded = host.encode()
            stream.sendall(b'\x05\x01\x00\x03' + bytes([len(encoded)]) + encoded + struct.pack('!H', dest_port))
            header = wire.recv_exact(stream, 4)
            assert header[:3] == b'\x05\x00\x00'
            wire.recv_exact(stream, (4 if header[3] == 1 else 16) + 2)
            return stream
        work = root / 'destinations'
        work.mkdir()
        with r.probe_client(s, work, local=True) as port:
            r.private_http(s, port)
            for protocol in ('tcp', 'udp'):
                fake = setup.require_fake(setup.dns_vless(wire, port, 'api.ipify.org', protocol))
            with request(port, fake, 18080) as stream:
                assert stream.recv(32) == b'public-service'
            with request(port, alias, 18080) as stream:
                assert stream.recv(32) == b'public-service'
            denied = [('127.0.0.1', 2222, False), ('10.0.0.1', 22, False),
                      ('localhost', 2222, True), ('private.test', 2222, True),
                      ('public.test', 18080, True), ('rebind.test', 2222, True),
                      ('localhost', 8080, True), ('localhost', 19053, True)]
            for host, dest_port, domain in denied:
                try:
                    with request(port, host, dest_port, domain) as stream:
                        stream.settimeout(3)
                        stream.sendall(b'hello')
                        try:
                            value = stream.recv(64)
                        except ConnectionResetError:
                            value = b''
                        assert not value, 'FORBIDDEN_DESTINATION_ACCEPTED'
                except wire.PilotError as error:
                    assert str(error) in ('SOCKS_REQUEST_FAILED', 'UNEXPECTED_SOCKET_EOF')
        assert not seen_private and not dns_queries, 'DOMAIN_RESOLUTION_OR_PRIVATE_DIAL_OCCURRED'
        # Revoke is tested against real local Xray, while public checks fail hard.
        for name in ('laptop-macos', 'android-phone'):
            entry = r.record(etc / 'devices.json')['devices'][name]
            for path, body in m.profile_outputs(r, name, entry).items():
                r.atomic(path, body)
        edited = profiles / 'laptop-macos-smart.json'
        edited.write_bytes(b'manually edited profile')
        real_run = r.run
        def command(args, code, **kwargs):
            if args[0] == 'systemctl':
                assert args == ['systemctl', 'restart', 'vpn-stack-xray.service']
                restart()
                return b''
            return real_run(args, code, **kwargs)
        r.run, r.modules = command, lambda: s
        r.probes = lambda *_a, **_k: (_ for _ in ()).throw(OSError('External DNS HTTPS STUN offline'))
        m.device(r, 'revoke', 'laptop-macos')
        assert edited.read_bytes() == b'manually edited profile'
        assert not (profiles / 'laptop-macos-full.json').exists()
        assert 'laptop-macos' not in r.record(etc / 'devices.json')['devices']
        remaining = r.record(etc / 'probe-client.json')
        remaining['outbounds'][0]['uuid'] = identities['android-phone']
        work = root / 'remaining-device'
        work.mkdir()
        with r.probe_client(s, work, remaining, local=True) as port:
            r.private_http(s, port)
        # Real MRS, isolated DNS and ads-exceptions with a nonexistent child.
        policy = data / 'generations/gen-policy'
        policy.mkdir()
        (policy / 'assets').mkdir()
        files = {}
        for tag, domain in (('smart', 'proxy.example'), ('direct', 'direct.example'), ('ads', 'ads.example')):
            (policy / (tag + '.normalized.txt')).write_text('+.' + domain + '\n')
            source = policy / (tag + '.txt')
            source.write_text('+.' + domain + '\n')
            r.run([code / 'bin/mihomo', 'convert-ruleset', 'domain', 'text', source,
                   policy / 'assets' / (tag + '.mrs')], 'MRS_COMPILE_FAILED')
            files[tag + '.mrs'] = {'normalized_patterns': 1, 'sha256': r.digest(policy / 'assets' / (tag + '.mrs'))}
        native = SimpleNamespace(wire=wire, checker=checker, builder=SimpleNamespace(atomic_json=lambda p, v: r.atomic(p, r.dump(v))),
                                 refresh=SimpleNamespace(BINARY=code / 'bin/mihomo'))
        witness = {'apex': 'proxy.example', 'child': 'child.proxy.example', 'deep-child': 'deep.child.proxy.example',
                   'direct-apex': 'direct.example', 'direct-child': 'child.direct.example',
                   'ads-child': 'nonexistent-child.ads.example', 'default': 'default.example', 'public_names': []}
        checker.witnesses = lambda: witness
        checker.SOURCE = policy
        values = {'proxy': [], 'direct': [], 'ads-exceptions': ['ads.example']}
        result = personal.runtime_check(native, core, pilot, policy, {'files': files}, values,
            r.base_config(SimpleNamespace(setup=setup, core=core), policy))
        assert result['status'] == 'ok'
        output = {'status': 'passed', 'scope': 'targeted native regressions; Ubuntu 24.04 ' + platform.machine() + ' in disposable Docker',
                  'standalone_SHA256': hashlib.sha256(artifact.read_bytes()).hexdigest(),
                  'binary_SHA256': checksums,
                  'native_profile_checks': 10, 'denied_destination_checks': len(denied),
                  'numeric_public_and_private_HTTP': 'passed', 'domain_resolution_attempts': len(dns_queries),
                  'numeric_VLESS_DNS_TCP_UDP_and_fake_IP': 'passed',
                  'real_local_VLESS_revoke_and_remaining_device': 'passed',
                  'isolated_ads_exception_DNS_TCP_UDP': 'passed', 'full_installation_tested': False,
                  'long_project_root_socket_tested': '--long-project-root' in sys.argv[1:],
                  'live_systemd_tested': False, 'public_VPS_ingress_tested': False,
                  'physical_device_import_tested': False, 'working_VPS_contacted': False}
        Path('/results/review-linux-regressions.json').write_text(json.dumps(output, indent=2) + '\n')
        print('NATIVE_REVIEW_REGRESSIONS=' + json.dumps(output), flush=True)


if __name__ == '__main__':
    main()
