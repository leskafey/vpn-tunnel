#!/usr/bin/env python3
"""Read-only VLESS/remote-provider acceptance in the disposable container."""
import http.client
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time


def main():
    assert Path('/.dockerenv').is_file() and os.geteuid() == 0, 'DISPOSABLE_CONTAINER_ONLY'
    spec = importlib.util.spec_from_file_location('small_native_runtime', '/root/vpn-tunnel/lib/vpn-stack-runtime.py')
    r = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(r)
    s = r.modules()
    source, manifest = r.active()
    with tempfile.TemporaryDirectory(prefix='small-providers-') as folder:
        home = Path(folder)
        outbound = r.record(r.ETC / 'probe-client.json')['outbounds'][0]
        cfg = r.profile(outbound)
        port = s.wire.spare_port()
        cfg['inbounds'] = [{'type': 'socks', 'listen': '127.0.0.1', 'listen_port': port}]
        cfg['route']['auto_detect_interface'] = False  # Local alias fixture, no TUN.
        cfg['route']['rules'].insert(2, {'ip_cidr': ['127.0.0.1/32'], 'port': 8080, 'action': 'route', 'outbound': 'vps'})
        cfg['experimental']['cache_file']['path'] = str(home / 'new-empty-cache.db')
        path = home / 'client.json'
        r.atomic(path, r.dump(cfg))
        r.run([r.CODE / 'bin/sing-box', 'check', '-c', path], 'NATIVE_PROFILE_REJECTED')
        with (home / 'private.log').open('wb') as log:
            process = subprocess.Popen([str(r.CODE / 'bin/sing-box'), 'run', '-c', str(path)], stdout=log, stderr=log,
                                       env=dict(os.environ, GOMEMLIMIT='64MiB', GOMAXPROCS='1'))
        def request(name, method='GET', etag=None):
            stream, _, _ = s.wire.socks_request(port, 1, '127.0.0.1', 8080)
            with stream:
                headers = (('If-None-Match: ' + etag + '\r\n') if etag else '')
                stream.sendall((method + ' /' + name + ' HTTP/1.1\r\nHost: localhost\r\n' + headers
                                + 'Connection: close\r\n\r\n').encode())
                response = http.client.HTTPResponse(stream, method=method)
                response.begin()
                return response.status, response.getheader('ETag'), response.read(32769)
        try:
            deadline = time.monotonic() + 20
            while True:
                assert process.poll() is None, 'NATIVE_REMOTE_PROVIDER_START_FAILED'
                try:
                    status, _, raw = request('probe.json')
                    assert status == 200 and raw == b'{"status":"ok"}\n'
                    break
                except (OSError, s.wire.PilotError):
                    assert time.monotonic() < deadline, 'REMOTE_PROVIDERS_NOT_READY'
                    time.sleep(.1)
            # A fresh cache and live SOCKS listener prove both remote rule sets
            # completed their initial download/parse before client startup.
            for filename in ('proxy-ipv4.json', 'personal-direct-domains.json'):
                status, etag, body = request(filename)
                assert status == 200 and body == r.raw_file(source / filename), 'PRIVATE_JSON_MISMATCH'
                assert request(filename, 'HEAD')[0] == 200
                assert request(filename, etag=etag)[0] == 304
            print('NATIVE_SMALL_PROVIDERS=' + json.dumps({'status': 'passed', 'CIDRs': manifest['ip']['CIDRs'],
                  'personal_DIRECT_domains': len(manifest['personal']['direct']), 'fresh_empty_cache': True,
                  'native_remote_JSON_initialization': 'passed', 'VLESS_JSON_HTTP_200_HEAD_304': 'passed',
                  'TUN_or_device_test': False}), flush=True)
        finally:
            s.checker.stop_process(process)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        value = {'status': 'failed', 'error_type': type(error).__name__}
        code = str(error)
        if code and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789' for c in code):
            value['code'] = code
        print('NATIVE_SMALL_PROVIDERS=' + json.dumps(value), flush=True)
        raise SystemExit(1)
