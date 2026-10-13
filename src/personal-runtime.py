"""Verified helper functions; historical entrypoints excluded."""
from contextlib import ExitStack, closing


from datetime import datetime, timezone


import fcntl


import hashlib


import http.client


import importlib.util


import json


import os


from pathlib import Path


import secrets


import shutil


import signal


import socketserver


import subprocess


import sys
import tempfile


import time


import traceback


STEP = 'start'


class BuildError(Exception):
    pass


def require(value, code):
    if not value:
        raise BuildError(code)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def step(name):
    global STEP
    STEP = name
    print('PERSONAL_REFRESH_STEP=' + name, flush=True)


def within(name, roots):
    labels = name.split('.')
    return any('.'.join(labels[index:]) in roots for index in range(len(labels)))


def base_matches(work, names):
    """Stream full witnesses; retain only the ancestors of sampled DNS names."""
    ancestors = {name: ['.'.join(name.split('.')[index:])
                        for index in range(len(name.split('.')))] for name in names}
    wanted = {root for roots in ancestors.values() for root in roots}
    matches = {name: {} for name in names}
    tags = ('smart', 'direct', 'ads') + tuple(tag for tag in ('ads-allow', 'ads-important')
                                            if (work / (tag + '.normalized.txt')).is_file())
    for tag in tags:
        exact, suffix, children = set(), set(), set()
        with (work / (tag + '.normalized.txt')).open(encoding='ascii') as stream:
            for row in stream:
                require(row.endswith('\n'), 'WITNESS_LINE_TRUNCATED')
                pattern = row[:-1]
                if pattern.startswith('+.'):
                    root, bucket = pattern[2:], suffix
                elif pattern.startswith('.'):
                    root, bucket = pattern[1:], children
                else:
                    root, bucket = pattern, exact
                if root in wanted:
                    bucket.add(root)
        for name, roots in ancestors.items():
            matches[name][tag] = (name in exact or any(root in suffix for root in roots)
                                   or any(root in children for root in roots[1:]))
    return matches


def expected_route(name, base, personal):
    blocked = (base['ads'] and not base.get('ads-allow', False)
               or base.get('ads-important', False) or within(name, personal.get('ads', [])))
    if blocked and not within(name, personal['ads-exceptions']):
        return 'fake', 'ads-reject'
    if within(name, personal['direct']):
        return 'real', 'personal-direct'
    if within(name, personal['proxy']):
        return 'fake', 'personal-proxy'
    if base['direct']:
        return 'real', 'automatic-direct'
    if name in ('api.ipify.org', 'stun.l.google.com'):
        return 'fake', 'control-proxy'
    if base['smart']:
        return 'fake', 'automatic-proxy'
    return 'real', 'default-direct'


def runtime_cases(witness, personal):
    names = {witness[key] for key in ('apex', 'child', 'deep-child', 'direct-apex',
                                    'direct-child', 'ads-child', 'default')}
    names.update(witness['public_names'])
    names.update(('api.ipify.org', 'checkip.amazonaws.com', 'stun.l.google.com'))
    # Full providers are loaded and counted. DNS samples are bounded explicitly;
    # this does not trim the personal rules or the production coverage.
    for roots in personal.values():
        for root in roots[:8]:
            names.add(root)
            child = 'personal-child.' + root
            if len(child) <= 253:
                names.add(child)
    return sorted(names)


def isolate(checker, text, home, dns_port, socks_port, upstream, api=None):
    for old, new in (('  listen: 127.0.0.1:19053', '  listen: 127.0.0.1:' + str(dns_port)),
                     ('socks-port: 19080', 'socks-port: ' + str(socks_port)),
                     ('  store-fake-ip: true', '  store-fake-ip: false'),
                     ('    - https://1.1.1.1/dns-query', '    - 127.0.0.1:' + str(upstream)),
                     ('    - 1.1.1.1', '    - 127.0.0.1:' + str(upstream))):
        require(text.splitlines().count(old) == 1, 'ISOLATION_FRAGMENT_CHANGED')
        text = text.replace(old + '\n', new + '\n', 1)
    require(not any(row.startswith(('external-controller:', 'external-controller-tls:'))
                    for row in text.splitlines()), 'PUBLIC_CONTROLLER_REFUSED')
    return checker.replace_line(text, 'external-controller-unix: ',
                                'external-controller-unix: ' + json.dumps(str(api if api is not None else home / 'api.sock')))


def loaded_counts(checker, api, expected):
    # Inline providers may expose their payload in the API response. The four
    # personal files are each bounded at 64 KiB, so keep a bounded larger read
    # than the old MRS-only checker and never emit payloads or personal names.
    limit = 1024 * 1024
    with closing(checker.UnixHTTP(api)) as client:
        client.request('GET', '/providers/rules')
        response = client.getresponse()
        require(response.status == 200, 'PROVIDER_API_UNAVAILABLE')
        raw = response.read(limit + 1)
    require(len(raw) <= limit, 'PROVIDER_RESPONSE_TOO_LARGE')
    providers = json.loads(raw).get('providers')
    if not isinstance(providers, dict) or set(providers) != set(expected):
        raise checker.CheckError('PROVIDERS_NOT_READY')
    counts = {tag: providers[tag].get('ruleCount') for tag in expected}
    if not all(type(counts[tag]) is int and counts[tag] == expected[tag] for tag in expected):
        raise checker.CheckError('PROVIDERS_NOT_FULLY_LOADED')
    return counts


def runtime_check(s, core, pilot, work, manifest, personal, baseline_text=None):
    step('isolated-full-runtime-with-personal-policy')
    previous_source = s.checker.SOURCE
    s.checker.SOURCE = work
    try:
        witness = s.checker.witnesses()
    finally:
        s.checker.SOURCE = previous_source
    names = runtime_cases(witness, personal)
    # Probe both automatic exception holes and important overrides; the entire
    # providers still load even though DNS samples are bounded.
    for tag in ('ads-allow', 'ads-important'):
        path = work / (tag + '.normalized.txt')
        if path.is_file():
            with path.open(encoding='ascii') as stream:
                for index, row in enumerate(stream):
                    if index >= 8:
                        break
                    require(row.endswith('\n') and row != '\n', 'ADS_PATTERN_INVALID')
                    root = row[2:-1] if row.startswith('+.') else row[:-1]
                    names.append(root)
                    if len(root) <= 238:
                        names.append('allowed-child.' + root)
    names = sorted(set(names))
    s.builder.atomic_json(work / 'witnesses.json', witness)
    hits = base_matches(work, names)
    expected_dns = {name: expected_route(name, hits[name], personal) for name in names}
    home = work / 'personal-test'
    rules = home / 'rules'
    rules.mkdir(parents=True, mode=0o700)
    providers, expected = {}, {}
    tags = ('smart', 'direct', 'ads') + tuple(tag for tag in ('ads-allow', 'ads-important')
                                            if tag + '.mrs' in manifest['files'])
    for tag in tags:
        source = work / 'assets' / (tag + '.mrs')
        shutil.copyfile(source, rules / source.name)
        require(digest(rules / source.name) == manifest['files'][source.name]['sha256'], 'TEST_MRS_COPY_CHANGED')
        providers[tag] = {'type': 'file', 'behavior': 'domain', 'format': 'mrs', 'path': './rules/' + source.name}
        expected[tag] = manifest['files'][source.name]['normalized_patterns']
    base = s.checker.replace_line(baseline_text if baseline_text is not None else s.refresh.BACKEND_CONFIG.read_text(), 'rule-providers: ',
                                  'rule-providers: ' + json.dumps(providers))
    candidate, inline_counts = core.compose(base, personal)
    expected.update(inline_counts)
    (work / 'candidate-baseline.yaml').write_text(candidate)
    pilot.MockDNS.helper = s.wire
    env = dict(os.environ, GOMEMLIMIT='64MiB', GOGC='50', GOMAXPROCS='1')
    # Short, private controller path inside data/, independent of generation depth.
    with tempfile.TemporaryDirectory(prefix='.s-', dir=work.parent.parent) as socket_home:
        process = None
        try:
            with s.wire.local_server(socketserver.ThreadingUDPServer, pilot.MockDNS) as upstream:
                dns_port, socks_port = s.wire.spare_port(), s.wire.spare_port()
                require(dns_port != socks_port, 'TEMP_PORT_COLLISION')
                api = Path(socket_home) / 'api.sock'
                require(len(str(api).encode()) < 104, 'UNIX_SOCKET_PATH_TOO_LONG')
                config = home / 'config.yaml'
                config.write_text(isolate(s.checker, candidate, home, dns_port, socks_port, upstream, api=api))
                with (work / 'personal-native.private.log').open('xb') as log:
                    native = subprocess.run([str(s.refresh.BINARY), '-t', '-d', str(home), '-f', str(config)],
                                            stdout=log, stderr=subprocess.STDOUT, timeout=30, env=env)
                require(native.returncode == 0, 'PERSONAL_NATIVE_CONFIG_REJECTED')
                with (work / 'personal-runtime.private.log').open('xb') as log:
                    process = subprocess.Popen([str(s.refresh.BINARY), '-d', str(home), '-f', str(config)],
                                               stdout=log, stderr=subprocess.STDOUT, env=env)
                deadline, loaded = time.monotonic() + 30, None
                while time.monotonic() < deadline:
                    require(process.poll() is None, 'ISOLATED_RUNTIME_EXITED')
                    try:
                        loaded = loaded_counts(s.checker, api, expected)
                        s.wire.lookup(dns_port, witness['default'], 'tcp')
                        break
                    except (OSError, s.checker.CheckError, s.wire.PilotError, http.client.HTTPException) as error:
                        if str(error) == 'INTERRUPTED':
                            raise
                        loaded = None
                        time.sleep(.1)
                require(loaded == expected, 'PERSONAL_RUNTIME_PROVIDERS_NOT_READY')
                s.wire.check_listeners(process.pid, {dns_port, socks_port})
                class_counts = {}
                for index, name in enumerate(names):
                    kind, reason = expected_dns[name]
                    for protocol in ('tcp', 'udp'):
                        answer = s.wire.lookup(dns_port, name, protocol)
                        pilot.check_dns_answer(answer, kind, 'sample-' + str(index), protocol)
                    class_counts[reason] = class_counts.get(reason, 0) + 1
                # The prior full personal pilot proves allowed/blocked TCP/UDP paths.
                # Here a blocked synthetic DNS sample additionally checks socket close.
                blocked = next((name for name in names if expected_dns[name][1] == 'ads-reject'), None)
                if blocked is not None:
                    ad_ip = s.wire.lookup(dns_port, blocked, 'tcp')
                    s.checker.reject_destination(s.wire, socks_port, ad_ip)
                for _ in range(20):
                    require(process.poll() is None, 'ISOLATED_RUNTIME_EXITED_DURING_OBSERVATION')
                    time.sleep(.1)
                memory = s.checker.rss(process.pid)
        finally:
            s.checker.stop_process(process)
    return {'status': 'ok', 'loaded_provider_rule_counts': loaded,
            'DNS_TCP_UDP_policy_checks': len(names) * 2, 'classification_sample_counts': class_counts,
            'personal_DNS_samples_per_file': 8, 'all_personal_entries_loaded': True,
            'temporary_backend_stopped': True, 'process_memory': memory,
            'scope': 'full source-text MRS plus actual personal snapshot, isolated synthetic upstream; not VLESS/device'}


