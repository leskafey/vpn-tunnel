#!/usr/bin/env python3
"""Runtime for the standalone clean-server installer. Never imports private profiles."""
import argparse
import base64
from contextlib import contextmanager
import copy
from datetime import datetime, timezone
import fcntl
import grp
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace

sys.dont_write_bytecode = True
def configure_paths(project):
    global PROJECT, CODE, ETC, DATA, HOME, CONFIG
    PROJECT = Path(project).resolve()
    CODE = PROJECT / 'lib'
    ETC = PROJECT / 'config'
    DATA = PROJECT / 'data'
    HOME = PROJECT / 'cache' / 'backend'
    CONFIG = ETC / 'backend.yaml'


configure_paths(Path(__file__).resolve().parent.parent)
GROUP = 'vpn-policy'
UNIT = 'vpn-stack-dns.service'
FILES = {'proxy': 'proxy.txt', 'direct': 'direct.txt', 'ads-exceptions': 'ads-exceptions.txt'}
IP_FILE = 'proxy-ip.txt'
SOURCES = {'rulist': 'https://raw.githubusercontent.com/bol-van/rulist/main/reestr_hostname.txt',
           'antifilter': 'https://antifilter.download/list/domains.lst',
           'oisd-small': 'https://raw.githubusercontent.com/sjhgvr/oisd/main/domainswild2_small.txt'}
IP_GROUPS = ('telegram', 'discord', 'whatsapp', 'cloudflare')
FAKE = ipaddress.ip_network('198.18.0.0/16')
PINNED_VERSIONS = {'xray': '26.3.27', 'sing-box': '1.14.2', 'mihomo': '1.19.31'}


class StackError(Exception):
    """Fixed codes only; command output can contain private transport material."""


def require(condition, code):
    if not condition:
        raise StackError(code)


def report(action, **values):
    print('VPN_STACK_REPORT=' + json.dumps(dict(action=action, **values), ensure_ascii=False), flush=True)


def digest(path):
    require(path.is_file() and not path.is_symlink(), 'REGULAR_FILE_REQUIRED')
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def raw_file(path, limit=65536):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_size <= limit,
                'OWNED_BOUNDED_FILE_REQUIRED')
        raw = stream.read(limit + 1)
        require(len(raw) == info.st_size <= limit, 'INPUT_CHANGED_WHILE_READING')
        return raw


def record(path):
    result = json.loads(raw_file(path, 1048576))
    require(isinstance(result, dict), 'STATE_OBJECT_REQUIRED')
    return result


def dump(value):
    return (json.dumps(value, indent=2, ensure_ascii=True) + '\n').encode('ascii')


def atomic(path, raw, mode=0o600, gid=0):
    require(not path.is_symlink(), 'OUTPUT_SYMLINK_REFUSED')
    fd, name = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            os.fchmod(stream.fileno(), mode)
            os.fchown(stream.fileno(), 0, gid)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def run(arguments, code, timeout=30):
    result = subprocess.run([str(a) for a in arguments], capture_output=True, timeout=timeout,
                            env=dict(os.environ, LC_ALL='C', TZ='UTC', GOMEMLIMIT='64MiB', GOGC='50', GOMAXPROCS='1',
                                     SAFE_PATHS=str(DATA / 'generations')))
    require(result.returncode == 0, code)
    return result.stdout


def modules():
    manifest = record(CODE / 'code-manifest.json')['files']
    result = {}
    for name, checksum in manifest.items():
        require(Path(name).name == name and name.endswith('.py') and digest(CODE / name) == checksum,
                'INSTALLED_CODE_CHANGED')
        if name in ('vpn-stack-runtime.py', 'vpn-stack-install.py', 'vpn-stack-manage.py'):
            continue
        spec = importlib.util.spec_from_file_location('stack_' + name.replace('-', '_').replace('.', '_'), CODE / name)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        result[name] = module
    s = SimpleNamespace(builder=result['text-builder.py'], checker=result['runtime-checker.py'],
                        wire=result['dns-wire.py'], core=result['personal-policy.py'],
                        personal=result['personal-runtime.py'], pilot=result['personal-checker.py'],
                        setup=result['transport-probes.py'], extras=result['domain-extras.py'],
                        parser=result['source-parser.py'], ip=result['ip-source.py'], closed=result['closed-probe.py'])
    s.builder.MIHOMO = CODE / 'bin/mihomo'
    s.builder.updater_idle = lambda: None  # All callers hold our single shared policy lock.
    s.builder.load_parser = lambda: s.parser
    s.refresh = SimpleNamespace(BINARY=CODE / 'bin/mihomo')
    s.setup.PUBLIC_IP = record(ETC / 'settings.json')['server_ip']
    return s


@contextmanager
def lock():
    path = DATA / 'update.lock'
    require(path.is_file() and not path.is_symlink(), 'POLICY_LOCK_REQUIRED')
    with path.open('r') as stream:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def personal(s):
    values, snapshots = {}, {}
    for key, name in FILES.items():
        raw = raw_file(ETC / name)
        values[key] = s.core.parse_personal(raw, s.parser)
        snapshots[key] = hashlib.sha256(raw).hexdigest()
    require(len(values['direct']) <= 256 and len(direct_body(values['direct'])) <= 32768,
            'PERSONAL_DIRECT_SIZE_LIMIT')
    raw = raw_file(ETC / IP_FILE)
    parse_personal_ips(raw)
    snapshots['proxy-ip'] = hashlib.sha256(raw).hexdigest()
    return values, snapshots


def parse_personal_ips(raw):
    require(isinstance(raw, bytes) and len(raw) <= 32768, 'PERSONAL_IP_SIZE_LIMIT')
    try:
        names = [row.split('#', 1)[0].strip() for row in raw.decode('utf-8').splitlines()]
        for name in names:
            name.encode('ascii')  # Russian comments are allowed; active IP rules remain ASCII.
        networks = [ipaddress.ip_network(row, strict=True) for row in names if row]
    except (UnicodeError, ValueError):
        raise StackError('PERSONAL_IP_INVALID') from None
    require(len(networks) <= 256 and all(n.version == 4 and n.prefixlen >= 12 and n.is_global
            and not n.network_address.is_multicast and not n.broadcast_address.is_multicast and n.network_address.is_global
            and n.broadcast_address.is_global for n in networks), 'PERSONAL_PUBLIC_IPV4_REQUIRED')
    return sorted(set(networks))


def direct_body(names):
    return json.dumps({'version': 3, 'rules': [{'domain_suffix': names}] if names else []},
                      separators=(',', ':')).encode('ascii') + b'\n'


def ip_body(networks):
    values = [str(n) for n in ipaddress.collapse_addresses(networks)]
    raw = json.dumps({'version': 3, 'rules': [{'ip_cidr': values}]}, separators=(',', ':')).encode('ascii') + b'\n'
    require(1 <= len(values) <= 256 and len(raw) <= 32768, 'IP_DELIVERY_SIZE_LIMIT')
    return raw, len(values)


def fetch_ips(s, previous=None):
    commit = json.loads(s.ip.download('https://api.github.com/repos/GubernievS/AntiZapret-VPN/git/ref/heads/main'))['object']['sha']
    require(len(commit) == 40 and all(c in '0123456789abcdef' for c in commit), 'IP_COMMIT_INVALID')
    networks = []
    for name in IP_GROUPS:
        raw = s.ip.download('https://raw.githubusercontent.com/GubernievS/AntiZapret-VPN/' + commit
                            + '/setup/root/antizapret/download/' + name + '-ips.txt')
        ipv4, _ = s.ip.parse_source(raw)
        networks.extend(ipv4)
    ipv4, _ = s.ip.parse_source(s.ip.download('https://core.telegram.org/resources/cidr.txt'), official=True)
    networks.extend(ipv4)
    raw, count = ip_body(networks)
    if previous:
        old = [ipaddress.ip_network(c) for rule in json.loads(previous)['rules'] for c in rule['ip_cidr']]
        fresh = [ipaddress.ip_network(c) for rule in json.loads(raw)['rules'] for c in rule['ip_cidr']]
        require(all(any(n.subnet_of(f) for f in fresh) for n in old), 'IP_PREVIOUS_COVERAGE_REMOVED')
        require(sum(n.num_addresses for n in fresh) <= sum(n.num_addresses for n in old) * 1.25,
                'IP_COVERAGE_GROWTH_GUARD')
    return raw, {'CIDRs': count, 'JSON_bytes': len(raw), 'commit': commit,
                 'source_CIDRs': [str(n) for n in ipaddress.collapse_addresses(networks)]}


def combined_ips(info):
    automatic = [ipaddress.ip_network(c) for c in info['source_CIDRs']]
    personal_networks = parse_personal_ips(raw_file(ETC / IP_FILE, 32768))
    raw, count = ip_body(automatic + personal_networks)
    return raw, dict(info, CIDRs=count, JSON_bytes=len(raw), personal_CIDRs=len(personal_networks))


def providers(source):
    return {tag: {'type': 'file', 'behavior': 'domain', 'format': 'mrs',
                  'path': str(source / 'assets' / (tag + '.mrs'))} for tag in ('smart', 'direct', 'ads')}


def base_config(s, source):
    text = s.setup.backend_config()
    start = text.index('  fake-ip-filter:\n')
    end = text.index('  default-nameserver:\n', start)
    text = text[:start] + '  fake-ip-filter: ' + json.dumps(s.core.BASE_FILTERS) + '\n' + text[end:]
    return text.replace('rules:\n', 'external-controller-unix: ' + json.dumps(str(HOME / 'controller.sock'))
                        + '\nrule-providers: ' + json.dumps(providers(source)) + '\nrules:\n', 1).replace(
                            '  - MATCH,DIRECT\n', '  - RULE-SET,ads,REJECT\n  - MATCH,DIRECT\n')


def profile(transport, platform='universal', full=False):
    require(platform in ('universal', 'macos', 'windows', 'ios', 'android'), 'PLATFORM_INVALID')
    tun = {'type': 'tun', 'tag': 'tun-in', 'address': ['172.19.0.1/30', 'fdfe:dcba:9876::1/126'],
           'mtu': 1400, 'auto_route': True, 'dns_mode': 'hijack', 'stack': 'mixed'}
    # Windows uses strict_route for DNS protection; Apple/Android apps ignore it.
    # Explicit legacy platforms retain their original export bytes.
    if platform in ('universal', 'windows', 'android'):
        tun['strict_route'] = True
    result = {'log': {'level': 'warn', 'timestamp': True},
              'dns': {'servers': [{'type': 'tcp', 'tag': 'server-dns', 'server': '127.0.0.1',
                                   'server_port': 19053, 'detour': 'vps'}],
                      'final': 'server-dns', 'strategy': 'ipv4_only', 'reverse_mapping': False, 'cache_capacity': 1024},
              'inbounds': [tun], 'outbounds': [copy.deepcopy(transport), {'type': 'direct', 'tag': 'direct'}],
              'route': {'auto_detect_interface': True,
                        'default_domain_resolver': {'server': 'server-dns', 'strategy': 'ipv4_only'},
                        'rules': [{'port': 53, 'action': 'hijack-dns'}, {'ip_version': 6, 'action': 'reject'}],
                        'final': 'vps' if full else 'direct'}}
    if full:
        return result
    result['dns']['servers'].append({'type': 'fakeip', 'tag': 'personal-direct-fake', 'inet4_range': '198.19.0.0/22'})
    result['dns']['rules'] = [{'rule_set': ['personal-direct'], 'query_type': ['A'],
                             'action': 'route', 'server': 'personal-direct-fake'}]
    result['route']['rules'] += [
        {'domain_regex': ['.+'], 'action': 'resolve', 'server': 'server-dns', 'strategy': 'ipv4_only', 'disable_cache': True},
        {'ip_cidr': ['198.18.0.0/16'], 'action': 'route', 'outbound': 'vps'},
        {'rule_set': ['personal-direct'], 'action': 'route', 'outbound': 'direct'},
        {'rule_set': ['proxy-ipv4'], 'action': 'route', 'outbound': 'vps'}]
    result['route']['rule_set'] = [
        {'type': 'remote', 'tag': tag, 'format': 'source', 'url': 'http://127.0.0.1:8080/' + name,
         'http_client': {'engine': 'go', 'version': 1, 'detour': 'vps'}, 'update_interval': interval}
        for tag, name, interval in (('proxy-ipv4', 'proxy-ipv4.json', '1h'),
                                    ('personal-direct', 'personal-direct-domains.json', '5m'))]
    identity = hashlib.sha256(transport.get('uuid', '').encode()).hexdigest()[:16]
    result['experimental'] = {'cache_file': {'enabled': True, 'cache_id': 'vpn-stack-' + identity + '-v1',
                                            'store_fakeip': True, 'store_dns': False}}
    return result


def xray_config(private_key, short_id, identities):
    return {'log': {'loglevel': 'warning'},
            'inbounds': [{'tag': 'vless', 'listen': '0.0.0.0', 'port': 443, 'protocol': 'vless',
                          'settings': {'clients': [{'id': value, 'email': name, 'flow': 'xtls-rprx-vision'}
                                                   for name, value in identities.items()], 'decryption': 'none'},
                          'streamSettings': {'network': 'tcp', 'security': 'reality',
                                             'realitySettings': {'show': False, 'target': 'gateway.icloud.com:443',
                                                'xver': 0, 'serverNames': ['gateway.icloud.com'], 'privateKey': private_key,
                                                'shortIds': [short_id]}},
                          'sniffing': {'enabled': False}}],
            'outbounds': [{'tag': 'direct', 'protocol': 'freedom'}, {'tag': 'block', 'protocol': 'blackhole'},
                          {'tag': 'server-dns', 'protocol': 'socks',
                           'settings': {'servers': [{'address': '127.0.0.1', 'port': 19080}]}}],
            'routing': {'domainStrategy': 'AsIs', 'rules': [
                # Profiles resolve through our DNS and send numeric destinations.
                # Reject wire domains before the loopback exceptions: routing DNS
                # alone cannot pin freedom's later resolution against rebinding.
                {'type': 'field', 'domain': ['regexp:.*'], 'outboundTag': 'block'},
                {'type': 'field', 'ip': ['127.0.0.1/32'], 'port': '19053', 'network': 'tcp,udp', 'outboundTag': 'direct'},
                {'type': 'field', 'ip': ['127.0.0.1/32'], 'port': '8080', 'network': 'tcp', 'outboundTag': 'direct'},
                {'type': 'field', 'ip': ['198.18.0.0/16'], 'network': 'tcp,udp', 'outboundTag': 'server-dns'},
                {'type': 'field', 'ip': ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
                    '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.168.0.0/16',
                    '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4',
                    '::/128', '::1/128', 'fc00::/7', 'fe80::/10', 'ff00::/8'], 'outboundTag': 'block'}]}}


def active(check_config=True):
    path = DATA / 'current'
    require(path.is_symlink(), 'ACTIVE_GENERATION_REQUIRED')
    source = path.resolve(strict=True)
    require(source.parent == DATA / 'generations' and source.name.startswith('gen-'), 'ACTIVE_PATH_INVALID')
    manifest = record(source / 'manifest.json')
    require(manifest.get('schema') == 1 and manifest.get('status') == 'verified', 'ACTIVE_MANIFEST_INVALID')
    assets = Path(manifest['assets_source'])
    require(assets.parent == DATA / 'generations' and assets.name.startswith('gen-')
            and assets.is_dir() and not assets.is_symlink(), 'ACTIVE_ASSETS_PATH_INVALID')
    for name, checksum in manifest['checksums'].items():
        require(not Path(name).is_absolute() and '..' not in Path(name).parts and digest(source / name) == checksum,
                'ACTIVE_GENERATION_CONTENT_CHANGED')
    if check_config:
        require(digest(CONFIG) == manifest['config_sha256'], 'ACTIVE_BACKEND_CONFIG_CHANGED')
    return source, manifest


def pointer(source):
    require(source.parent == DATA / 'generations' and source.is_dir(), 'GENERATION_TARGET_INVALID')
    temporary = DATA / ('.current-' + secrets.token_hex(4))
    try:
        temporary.symlink_to(source)
        os.replace(temporary, DATA / 'current')
        directory = os.open(DATA, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary.is_symlink():
            temporary.unlink()


def work_directory():
    path = DATA / 'generations' / ('gen-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + secrets.token_hex(4))
    path.mkdir(mode=0o750)
    try:
        os.chown(path, 0, grp.getgrnam(GROUP).gr_gid)
        path.chmod(0o750)
        atomic(path / 'owner.json', dump({'schema': 1, 'kind': 'vpn-stack-generation'}))
    except BaseException:
        shutil.rmtree(path)
        raise
    return path


def make_full(s, work, previous=None):
    (work / 'assets').mkdir(mode=0o750)
    os.chown(work / 'assets', 0, grp.getgrnam(GROUP).gr_gid)
    (work / 'assets').chmod(0o750)
    manifest = {'source_metadata': {}, 'source_entries': {}, 'files': {}}
    commit = json.loads(s.extras.download(s.extras.REF))['object']['sha']
    require(isinstance(commit, str) and len(commit) == 40 and all(c in '0123456789abcdef' for c in commit),
            'EXTRA_COMMIT_INVALID')
    tlds = s.extras.delegated_tlds(s.extras.download(s.extras.IANA))
    extras = {}
    for name in ('extra-proxy', 'extra-direct'):
        raw = s.extras.download(s.extras.source_url(commit, name))
        roots, zones, valid = s.extras.parse(raw, s.parser, tlds)
        if previous:
            s.extras.no_lost_coverage(previous['extras'][name]['roots'], roots)
        extras[name] = {'roots': sorted(roots), 'TLD_suffixes': sorted(zones), 'valid': valid}
        (work / (name + '.domains.txt')).write_text(''.join(n + '\n' for n in sorted(roots)))
    original_guard = s.builder.guard_count
    if previous is None:
        # The first installation has no previous snapshot. Keep absolute format/
        # count limits; percentage-change guards begin at its first good commit.
        s.builder.guard_count = lambda name, count, discarded, _: original_guard(name, count, discarded, count)
    try:
        with (work / 'registry.raw.txt').open('x') as combined:
            for name in s.builder.NAMES:
                old_count = previous['source_metadata'][name]['valid'] if previous else 1
                if name in SOURCES:
                    raw = work / (name + '.source.txt')
                    info = s.builder.download(SOURCES[name], raw)
                    info.update(s.builder.normalize_source(s.parser, name, raw, work / (name + '.domains.txt'), old_count))
                else:
                    count = extras[name]['valid']
                    s.builder.guard_count(name, count, 0, old_count)
                    info = {'valid': count, 'discarded': 0}
                manifest['source_metadata'][name] = info
                if name in ('rulist', 'antifilter'):
                    with (work / (name + '.domains.txt')).open() as incoming:
                        shutil.copyfileobj(incoming, combined, 65536)
                else:
                    s.builder.sorted_unique(work / (name + '.domains.txt'), work / (name + '.unique.txt'), work, 'sort-' + name)
        s.builder.sorted_unique(work / 'registry.raw.txt', work / 'registry.unique.txt', work, 'sort-registry')
        count, rewritten = s.builder.promote_registry(work / 'registry.unique.txt', work / 'smart.raw.txt')
        require(500000 <= count <= 5000000, 'REGISTRY_SIZE_LIMIT')
        if previous:
            require(previous['registry_domains'] * .75 <= count <= previous['registry_domains'] * 1.25,
                    'REGISTRY_CHANGE_GUARD')
        with (work / 'smart.raw.txt').open('a') as output:
            s.builder.append_suffixes(work / 'extra-proxy.unique.txt', output)
        for tag, name in (('direct', 'extra-direct'), ('ads', 'oisd-small')):
            with (work / (tag + '.raw.txt')).open('x') as output:
                s.builder.append_suffixes(work / (name + '.unique.txt'), output)
        for tag in ('smart', 'direct', 'ads'):
            manifest['files'][tag + '.mrs'] = s.builder.compile_and_verify(tag, work / (tag + '.raw.txt'), work / 'assets', work)
            os.chown(work / 'assets' / (tag + '.mrs'), 0, grp.getgrnam(GROUP).gr_gid)
            (work / 'assets' / (tag + '.mrs')).chmod(0o640)
    finally:
        s.builder.guard_count = original_guard
    manifest.update(registry_domains=count, upstream_prefix_rewrites=rewritten, extras=extras, commit=commit,
                    assets_source=str(work))
    return manifest


def reuse(source, previous, work):
    result = {k: copy.deepcopy(previous[k]) for k in ('source_metadata', 'source_entries', 'files',
              'registry_domains', 'upstream_prefix_rewrites', 'extras', 'commit', 'assets_source')}
    (work / 'assets').mkdir(mode=0o750)
    os.chown(work / 'assets', 0, grp.getgrnam(GROUP).gr_gid)
    (work / 'assets').chmod(0o750)
    for tag in ('smart', 'direct', 'ads'):
        for name in ('assets/' + tag + '.mrs', tag + '.normalized.txt'):
            os.link(source / name, work / name, follow_symlinks=False)
    return result


def wait_backend(s, counts, timeout=35):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            s.personal.loaded_counts(s.checker, HOME / 'controller.sock', counts)
            return
        except (OSError, s.checker.CheckError, http.client.HTTPException):
            time.sleep(.25)
    raise StackError('BACKEND_PROVIDERS_NOT_READY')


@contextmanager
def probe_client(s, work, probe_config=None, local=False):
    p = copy.deepcopy(probe_config) if probe_config is not None else record(ETC / 'probe-client.json')
    if local:
        p['outbounds'][0]['server'] = '127.0.0.1'
    port = s.wire.spare_port()
    p['inbounds'] = [{'type': 'socks', 'tag': 'probe', 'listen': '127.0.0.1', 'listen_port': port}]
    cfg = work / 'probe-client.json'
    atomic(cfg, dump(p))
    run([CODE / 'bin/sing-box', 'check', '-c', cfg], 'PROBE_CONFIG_REJECTED')
    process = None
    try:
        with (work / 'vless.private.log').open('xb') as log:
            process = subprocess.Popen([str(CODE / 'bin/sing-box'), 'run', '-c', str(cfg)], stdout=log, stderr=log,
                                       env=dict(os.environ, GOMEMLIMIT='48MiB', GOGC='50', GOMAXPROCS='1'))
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            require(process.poll() is None, 'VLESS_PROBE_CLIENT_EXITED')
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=.5):
                    pass
                break
            except OSError:
                time.sleep(.25)
        else:
            raise StackError('VLESS_PROBE_CLIENT_NOT_READY')
        yield port
    finally:
        s.checker.stop_process(process)


def private_http(s, port):
    stream, _, _ = s.wire.socks_request(port, 1, '127.0.0.1', 8080)
    with stream:
        stream.sendall(b'GET /probe.json HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n')
        response = http.client.HTTPResponse(stream)
        response.begin()
        require(response.status == 200, 'VLESS_PRIVATE_HTTP_FAILED')
        require(response.read(4096) == b'{"status":"ok"}\n', 'VLESS_PRIVATE_HTTP_BODY_FAILED')


def wait_private_http(s, port):
    deadline = time.monotonic() + 15
    while True:
        try:
            private_http(s, port)
            return
        except (OSError, http.client.HTTPException, s.wire.PilotError):
            require(time.monotonic() < deadline, 'VLESS_PRIVATE_HTTP_FAILED')
            time.sleep(.25)


def local_access(s, work, revoked):
    """Positive control and revoked credential use the same loopback transport.

    No public address, DNS, HTTPS, STUN, policy witnesses or downloads are used.
    The native config check and restart have already succeeded.
    """
    with probe_client(s, work, local=True) as port:
        wait_private_http(s, port)
    denied = work / 'revoked'
    denied.mkdir(mode=0o700)
    p = record(ETC / 'probe-client.json')
    p['outbounds'][0]['uuid'] = revoked
    with probe_client(s, denied, probe_config=p, local=True) as port:
        try:
            private_http(s, port)
        except (OSError, http.client.HTTPException, s.wire.PilotError):
            pass
        else:
            raise StackError('REVOKED_UUID_STILL_ACCEPTED')
    # Recheck the positive control so an unrelated transport outage cannot pass.
    allowed = work / 'allowed'
    allowed.mkdir(mode=0o700)
    with probe_client(s, allowed, local=True) as port:
        wait_private_http(s, port)


def probes(s, work, manifest, probe_config=None):
    settings = record(ETC / 'settings.json')
    with probe_client(s, work, probe_config) as port:
        wait_private_http(s, port)
        samples = ['api.ipify.org', 'checkip.amazonaws.com', 'www.instagram.com', 'stun.l.google.com']
        # Public probes use existing controls. Random list witnesses use the
        # synthetic upstream only in the isolated runtime check.
        hits = s.personal.base_matches(work, samples)
        dns_checks = 0
        for name in samples:
            expected, _ = s.personal.expected_route(name, hits[name], manifest['personal'])
            for protocol in ('tcp', 'udp'):
                values = s.setup.dns_vless(s.wire, port, name, protocol)
                (s.setup.require_fake if expected == 'fake' else s.setup.require_real)(values)
                dns_checks += 1
        if not s.personal.within('api.ipify.org', manifest['personal']['direct']):
            address = s.setup.require_fake(s.setup.dns_vless(s.wire, port, 'api.ipify.org', 'tcp'))
            s.setup.https_ip(s.wire, port, address)
        if not s.personal.within('stun.l.google.com', manifest['personal']['direct']):
            address = s.setup.require_fake(s.setup.dns_vless(s.wire, port, 'stun.l.google.com', 'udp'))
            s.setup.stun_socks(s.wire, port, address)
        s.closed.closed_destination(s.wire, port, '127.0.0.1', 22)
        s.closed.closed_destination(s.wire, port, '198.18.0.0', 443)
        # Synthetic ad witnesses (including exceptions) are tested by runtime_check
        # with MockDNS. They need not exist in public DNS.
        return {'VLESS_DNS_TCP_UDP_checks': dns_checks, 'HTTPS_and_UDP_STUN': 'passed',
                'private_HTTP': 'passed', 'closed_destinations': 'passed', 'expected_exit': settings['server_ip']}


def recover(s):
    path = DATA / 'transaction.json'
    if not path.exists():
        return False
    state = record(path)
    if state['status'] in ('committed', 'rolled_back'):
        return False
    before = base64.b64decode(state['before_config'], validate=True)
    require(hashlib.sha256(before).hexdigest() == state['before_sha256']
            and digest(CONFIG) in (state['before_sha256'], state['after_sha256']), 'RECOVERY_CONFIG_CHANGED_EXTERNALLY')
    old, new = Path(state['before_source']), Path(state['after_source'])
    require(old.parent == new.parent == DATA / 'generations' and old.is_dir() and new.is_dir()
            and not old.is_symlink() and not new.is_symlink(), 'RECOVERY_GENERATION_INVALID')
    require((DATA / 'current').resolve(strict=True) in (old, new), 'RECOVERY_POINTER_CHANGED_EXTERNALLY')
    atomic(CONFIG, before, 0o640, grp.getgrnam(GROUP).gr_gid)
    pointer(old)
    run(['systemctl', 'restart', UNIT], 'RECOVERY_BACKEND_RESTART_FAILED')
    wait_backend(s, record(old / 'manifest.json')['counts'])
    state['status'] = 'rolled_back'
    atomic(path, dump(state))
    return True


def activate(s, work, manifest, initial=False):
    _, inline = s.core.compose(base_config(s, Path(manifest['assets_source'])), manifest['personal'])
    manifest['counts'] = {tag: manifest['files'][tag + '.mrs']['normalized_patterns'] for tag in ('smart', 'direct', 'ads')}
    manifest['counts'].update(inline)
    config, _ = s.core.compose(base_config(s, Path(manifest['assets_source'])), manifest['personal'])
    atomic(work / 'backend.yaml', config.encode(), 0o640, grp.getgrnam(GROUP).gr_gid)
    raw = raw_file(work / 'backend.yaml', 1048576)
    manifest['config_sha256'] = hashlib.sha256(raw).hexdigest()
    manifest.update(schema=1, status='verified', activation='candidate')
    names = ['assets/' + t + '.mrs' for t in ('smart', 'direct', 'ads')]
    names += [t + '.normalized.txt' for t in ('smart', 'direct', 'ads')]
    names += ['backend.yaml', 'witnesses.json', 'proxy-ipv4.json', 'personal-direct-domains.json']
    manifest['checksums'] = {name: digest(work / name) for name in names}
    atomic(work / 'manifest.json', dump(manifest), 0o640, grp.getgrnam(GROUP).gr_gid)
    check_home = work / 'native-check'
    check_home.mkdir(mode=0o700)
    run([CODE / 'bin/mihomo', '-t', '-d', check_home, '-f', work / 'backend.yaml'], 'BACKEND_NATIVE_CONFIG_FAILED')
    old = previous = None
    before_map = {}
    if not initial:
        old, previous = active()
        for name in ('api.ipify.org', 'stun.l.google.com'):
            if not s.personal.within(name, manifest['personal']['direct']):
                values = s.setup.local_dns(s.wire, name)
                if len(values) == 1 and ipaddress.ip_address(values[0]) in FAKE:
                    before_map[name] = values[0]
        state = {'status': 'prepared', 'before_source': str(old), 'after_source': str(work),
                 'before_config': base64.b64encode(raw_file(CONFIG, 1048576)).decode(),
                 'before_sha256': digest(CONFIG), 'after_sha256': manifest['config_sha256']}
        atomic(DATA / 'transaction.json', dump(state))
    changed = not CONFIG.exists() or digest(CONFIG) != manifest['config_sha256']
    try:
        if changed:
            atomic(CONFIG, raw, 0o640, grp.getgrnam(GROUP).gr_gid)
            run(['systemctl', 'restart', UNIT], 'BACKEND_RESTART_FAILED')
        wait_backend(s, manifest['counts'])
        require(all(s.setup.require_fake(s.setup.local_dns(s.wire, name)) == value for name, value in before_map.items()),
                'PERSISTENT_FAKE_MAP_CHANGED')
        checks = probes(s, work, manifest)
        # Edited input must still match the tested snapshot before publishing it.
        require(personal(s)[1] == manifest['personal_sha256'], 'PERSONAL_EDIT_DURING_APPLY')
        manifest.update(activation='applied', applied_utc=datetime.now(timezone.utc).isoformat())
        atomic(work / 'manifest.json', dump(manifest), 0o640, grp.getgrnam(GROUP).gr_gid)
        pointer(work)  # HTTP sees only a verified generation, after successful probes.
        if old:
            state['status'] = 'committed'
            atomic(DATA / 'transaction.json', dump(state))
        result = {'status': 'active', 'source': work.name, 'counts': manifest['counts'],
                  'DNS_backend_restarted': changed, 'fake_map_preserved': True,
                  'applied_utc': manifest['applied_utc'], **checks}
        atomic(DATA / 'last-result.json', dump(result))
        return result
    except BaseException:
        if old:
            # Rollback must finish even if systemd sent SIGTERM during activation.
            handlers = {sig: signal.signal(sig, signal.SIG_IGN) for sig in (signal.SIGTERM, signal.SIGINT)}
            try:
                recover(s)
            finally:
                for sig, handler in handlers.items():
                    signal.signal(sig, handler)
        raise


def trim_files(work):
    keep = {'assets', 'owner.json', 'manifest.json', 'backend.yaml', 'witnesses.json', 'proxy-ipv4.json',
            'personal-direct-domains.json', 'smart.normalized.txt', 'direct.normalized.txt', 'ads.normalized.txt'}
    for path in work.iterdir():
        if path.name not in keep:
            # rmtree does not follow internal symlinks; top-level links are unlinked.
            shutil.rmtree(path) if path.is_dir() and not path.is_symlink() else path.unlink()


def cleanup():
    """Caller holds lock. Read/unlink only: works even when the disk is full.

    Unknown directories are never adopted. A malformed reference stops cleanup
    before deleting anything. Pending transactions retain all their work files.
    """
    root = DATA / 'generations'
    require(root.is_dir() and not root.is_symlink() and root.stat().st_uid == 0,
            'CLEANUP_ROOT_INVALID')
    protected, pending, rolled_back = set(), set(), set()
    def generation(value):
        path = Path(value)
        require(path.parent == root and path.name.startswith('gen-') and path.is_dir()
                and not path.is_symlink(), 'CLEANUP_GENERATION_REFERENCE_INVALID')
        return path
    if (DATA / 'current').is_symlink():
        protected.add(generation((DATA / 'current').resolve(strict=True)))
    transaction = DATA / 'transaction.json'
    if transaction.exists():
        state = record(transaction)
        protected.add(generation(state['before_source']))
        if state['status'] not in ('committed', 'rolled_back'):
            pending.update(generation(state[key]) for key in ('before_source', 'after_source'))
            protected.update(pending)
        elif state['status'] == 'rolled_back':
            rolled_back.add(Path(state['after_source']))
    # Includes assets installed during a failed initial activation without current.
    if CONFIG.exists():
        for line in raw_file(CONFIG, 1048576).decode().splitlines():
            if line.startswith('rule-providers: '):
                for provider in json.loads(line.split(': ', 1)[1]).values():
                    require(isinstance(provider, dict) and provider.get('type') in ('file', 'inline'),
                            'CLEANUP_PROVIDER_TYPE_INVALID')
                    if provider['type'] == 'file':
                        require(isinstance(provider.get('path'), str) and provider['path'],
                                'CLEANUP_PROVIDER_PATH_INVALID')
                        protected.add(generation(Path(provider['path']).parent.parent))
    owned, successful = [], []
    for path in sorted(root.iterdir(), reverse=True):
        if not path.name.startswith('gen-') or path.is_symlink() or not path.is_dir():
            continue
        owner = path / 'owner.json'
        if not owner.is_file() or owner.is_symlink():
            continue
        if record(owner) != {'schema': 1, 'kind': 'vpn-stack-generation'}:
            continue
        owned.append(path)
        if (path / 'manifest.json').is_file():
            manifest = record(path / 'manifest.json')
            if path not in rolled_back and manifest.get('status') == 'verified' and manifest.get('activation') != 'candidate':
                successful.append(path)
    protected.update(successful[:3])
    # Retain assets for *every* retained generation, including older rollback ones.
    queue = list(protected)
    while queue:
        path = queue.pop()
        if (path / 'manifest.json').is_file():
            assets = generation(record(path / 'manifest.json')['assets_source'])
            if assets not in protected:
                protected.add(assets)
                queue.append(assets)
    removed = []
    for path in owned:
        if path not in protected:
            shutil.rmtree(path)
            removed.append(path.name)
        elif path not in pending and (path / 'manifest.json').is_file():
            trim_files(path)
    return {'removed_generations': removed, 'retained_generations': sorted(p.name for p in protected)}


def trim(work):
    trim_files(work)
    return cleanup()


@contextmanager
def generation_work():
    work = work_directory()
    try:
        yield work
    finally:
        # Recovery must finish first. cleanup keeps both sides if it could not.
        cleanup()


def apply(action):
    s = modules()
    with lock():
        cleanup()  # Free unrelated leftovers before recovery needs atomic writes.
        recovered = recover(s)
        cleanup()
        source, previous = active()
        values, snapshots = personal(s)
        if action == 'personal' and previous['personal_sha256'] == snapshots:
            return {'status': 'unchanged', 'downloads': 0, 'MRS_compilation': False, 'recovered': recovered}
        body, ip_info = raw_file(source / 'proxy-ipv4.json'), previous['ip']
        if action == 'ip':
            old_base = ip_body([ipaddress.ip_network(c) for c in ip_info['source_CIDRs']])[0]
            _, ip_info = fetch_ips(s, old_base)
            fresh, ip_info = combined_ips(ip_info)
            if fresh == body and snapshots == previous['personal_sha256']:
                atomic(DATA / 'last-ip-check.json', dump(ip_info))
                return {'status': 'unchanged', 'ip': ip_info, 'MRS_compilation': False, 'DNS_backend_restarted': False}
            body = fresh
        else:
            body, ip_info = combined_ips(ip_info)
        available = next(int(row.split()[1]) for row in Path('/proc/meminfo').read_text().splitlines()
                         if row.startswith('MemAvailable:'))
        if available < (450 if action == 'daily' else 256) * 1024:
            raise BlockingIOError('RESOURCE_HEADROOM_LOW')
        if shutil.disk_usage(DATA).free < 2 * 1024**3:
            raise BlockingIOError('DISK_HEADROOM_LOW')
        with generation_work() as work:
            manifest = make_full(s, work, previous) if action == 'daily' else reuse(source, previous, work)
            manifest.update(personal=values, personal_sha256=snapshots, ip=ip_info,
                            source_entries={'ads-exceptions': {'inline_domain_suffixes': len(values['ads-exceptions'])}})
            gid = grp.getgrnam(GROUP).gr_gid
            atomic(work / 'proxy-ipv4.json', body, 0o640, gid)
            atomic(work / 'personal-direct-domains.json', direct_body(values['direct']), 0o640, gid)
            # Preserve old MRS paths for an unchanged daily policy: avoid an unnecessary restart.
            if action == 'daily' and manifest['files'] == previous['files']:
                manifest['assets_source'] = previous['assets_source']
            manifest['runtime'] = s.personal.runtime_check(s, s.core, s.pilot, work, manifest, values,
                                                          base_config(s, Path(manifest['assets_source'])))
            result = activate(s, work, manifest)
            result.update(downloads=0 if action == 'personal' else 'source-text', MRS_compilation=action == 'daily')
            trim(work)
            return result


def fingerprint():
    result = []
    for name in (*FILES.values(), IP_FILE):
        path = ETC / name
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_size <= 65536, 'PERSONAL_FILE_INVALID')
        result.append((info.st_ino, info.st_size, info.st_mtime_ns))
    return result


def unit_state(name):
    properties = ('LoadState', 'ActiveState', 'SubState', 'Result', 'ExecMainCode', 'ExecMainStatus',
                  'ExecMainStartTimestamp', 'LastTriggerUSec', 'NextElapseUSecRealtime', 'UnitFileState')
    try:
        output = run(['systemctl', 'show', name, *['--property=' + p for p in properties]],
                     'STATUS_SYSTEMD_QUERY_FAILED', timeout=5).decode('utf-8')
        return dict(line.split('=', 1) for line in output.splitlines() if '=' in line)
    except (OSError, subprocess.TimeoutExpired, StackError):
        return {'ActiveState': 'unknown', 'error': 'STATUS_SYSTEMD_QUERY_FAILED'}


def update_health(tag, state):
    """Interpret systemd properties, including the result retained in auto-restart.

    Exit 75 is our deliberate deferral, only when CLD_EXITED (ExecMainCode=1).
    A signal with the same number, or a timeout/OOM followed by exit 75, is a fault.
    systemd resets Result and main exit status when the next invocation starts.
    """
    active, sub, result = (state.get(key) for key in ('ActiveState', 'SubState', 'Result'))
    if state.get('LoadState') != 'loaded':
        return {'status': 'failed', 'reason': 'UNIT_NOT_LOADED'}
    if tag.endswith(('.timer', '.path')):
        return {'status': 'ready' if active == 'active' else 'failed',
                'reason': 'UNIT_' + str(active).upper()}
    if (result == 'exit-code' and state.get('ExecMainCode') == '1' and state.get('ExecMainStatus') == '75'
            and (active == 'activating' and sub in ('auto-restart', 'auto-restart-queued')
                 or active == 'inactive' and sub == 'dead')):
        return {'status': 'deferred', 'reason': 'TEMPORARY_FAILURE_EXIT_75'}
    if result not in (None, '', 'success'):
        return {'status': 'failed', 'reason': 'SERVICE_RESULT_' + result.upper().replace('-', '_')}
    if active == 'inactive':
        return {'status': 'idle', 'reason': 'SUCCESSFUL_OR_NOT_YET_RUN_ONESHOT'}
    if active in ('active', 'activating', 'deactivating'):
        return {'status': 'running', 'reason': 'UPDATE_IN_PROGRESS'}
    return {'status': 'failed', 'reason': 'UNIT_' + str(active).upper()}


def transport_health():
    """Check saved transport bytes without exposing config or device identities."""
    documents = {}
    for name, code in (('xray.json', 'STATUS_XRAY_CONFIG'), ('devices.json', 'STATUS_DEVICE_REGISTRY')):
        try:
            raw = raw_file(ETC / name, 1048576)
            value = json.loads(raw)
            if not isinstance(value, dict):
                return {'status': 'degraded', 'diagnostic': code + '_INVALID'}
            documents[name] = (raw, value)
        except FileNotFoundError:
            return {'status': 'degraded', 'diagnostic': code + '_MISSING'}
        except (ValueError, RecursionError):
            return {'status': 'degraded', 'diagnostic': code + '_INVALID'}
        except (OSError, StackError):
            return {'status': 'degraded', 'diagnostic': code + '_UNREADABLE'}
    registry = documents['devices.json'][1]
    checksum = registry.get('xray_sha256')
    if (registry.get('schema') != 1 or not isinstance(registry.get('devices'), dict)
            or not isinstance(checksum, str) or len(checksum) != 64
            or any(c not in '0123456789abcdef' for c in checksum)):
        return {'status': 'degraded', 'diagnostic': 'STATUS_DEVICE_REGISTRY_INVALID'}
    if hashlib.sha256(documents['xray.json'][0]).hexdigest() != checksum:
        return {'status': 'degraded', 'diagnostic': 'STATUS_XRAY_CHECKSUM_MISMATCH'}
    return {'status': 'verified'}


def status():
    """Read-only local health, independently from the saved policy report."""
    services = {tag: unit_state('vpn-stack-' + tag + '.service') for tag in ('xray', 'dns', 'http')}
    updates = {tag: unit_state('vpn-stack-' + tag) for tag in
               ('daily.timer', 'daily.service', 'ip.timer', 'ip.service', 'personal.path', 'personal.service')}
    faults = [tag + '_service' for tag, state in services.items() if state.get('ActiveState') != 'active']
    update_states = {tag: update_health(tag, state) for tag, state in updates.items()}
    update_faults = [tag for tag, state in update_states.items() if state['status'] == 'failed']
    saved, pending = {}, None
    try:
        with socket.create_connection(('127.0.0.1', 443), timeout=2):
            pass
    except OSError:
        faults.append('xray_listener')
    transport = transport_health()
    if transport['status'] != 'verified':
        faults.append('xray_config_check')
    try:
        source, manifest = active(check_config=False)
        saved = {'status': 'verified', 'generation': source.name, 'assets_source': manifest['assets_source'],
                 'counts': manifest['counts'], 'ip': manifest['ip'],
                 'last_successful_apply_utc': manifest.get('applied_utc'),
                 'personal_counts': {k: len(v) for k, v in manifest['personal'].items()}}
        pending = [name for key, name in {**FILES, 'proxy-ip': IP_FILE}.items()
                   if hashlib.sha256(raw_file(ETC / name)).hexdigest() != manifest['personal_sha256'].get(key)]
        require(digest(CONFIG) == manifest['config_sha256'], 'ACTIVE_BACKEND_CONFIG_CHANGED')
        s = modules()
        s.personal.loaded_counts(s.checker, HOME / 'controller.sock', manifest['counts'])
        with socket.create_connection(('127.0.0.1', 19053), timeout=2):
            pass
    except Exception as error:
        faults.append('policy_or_dns_check')
        saved.setdefault('status', 'unavailable')
        saved['diagnostic'] = str(error) if isinstance(error, StackError) else type(error).__name__
    try:
        client = http.client.HTTPConnection('127.0.0.1', 8080, timeout=2)
        try:
            client.request('GET', '/probe.json')
            response = client.getresponse()
            require(response.status == 200 and response.read(4096) == b'{"status":"ok"}\n', 'STATUS_HTTP_FAILED')
        finally:
            client.close()
    except (OSError, http.client.HTTPException, StackError):
        faults.append('http_check')
    transactions = {}
    for name in ('transaction.json', 'device-transaction.json'):
        path = DATA / name
        if path.exists():
            try:
                transactions[name] = record(path)['status']
                if transactions[name] not in ('committed', 'rolled_back'):
                    faults.append('unfinished_' + name)
            except Exception:
                transactions[name] = 'unreadable'
                faults.append('invalid_' + name)
    report('status', status='healthy' if not faults and not update_faults else 'degraded',
           services=services, updates=updates, saved_policy=saved, transport_config=transport,
           unapplied_personal_files=pending, transactions=transactions,
           faults=faults, update_faults=update_faults, update_states=update_states,
           scope='local checks; public VPN reachability not tested')
    return 1 if faults or update_faults else 0


def deferred_reason(error):
    reason = str(error)
    return reason if reason in ('RESOURCE_HEADROOM_LOW', 'DISK_HEADROOM_LOW') else 'POLICY_LOCK_BUSY'


def watcher():
    previous, stable, start = fingerprint(), time.monotonic(), time.monotonic()
    while time.monotonic() - stable < 3:
        time.sleep(.25)
        current = fingerprint()
        if current != previous:
            previous, stable = current, time.monotonic()
        if time.monotonic() - start > 20:
            return 75
    try:
        result = apply('personal')
    except BlockingIOError as error:
        report('personal', status='deferred', reason=deferred_reason(error))
        return 75
    except Exception:
        if fingerprint() != previous:
            return 75
        raise
    report('personal', **result)
    return 75 if fingerprint() != previous else 0


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def setup(self):
        super().setup()
        self.connection.settimeout(3)
    def log_message(self, *_):
        pass

    def do_HEAD(self):
        self.send_document(head=True)

    def do_GET(self):
        self.send_document()

    def send_document(self, head=False):
        self.connection.settimeout(3)
        names = {'/proxy-ipv4.json': 'proxy-ipv4.json', '/personal-direct-domains.json': 'personal-direct-domains.json'}
        if self.path == '/probe.json':
            body = b'{"status":"ok"}\n'
        elif self.path in names:
            try:
                # Holding the generation directory fd prevents a mixed-pointer read.
                directory = os.open(DATA / 'current', os.O_RDONLY | os.O_DIRECTORY)
                try:
                    fd = os.open(names[self.path], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
                    with os.fdopen(fd, 'rb') as stream:
                        info = os.fstat(stream.fileno())
                        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and 0 < info.st_size <= 32768,
                                'HTTP_DOCUMENT_INVALID')
                        body = stream.read(32769)
                        require(len(body) == info.st_size, 'HTTP_DOCUMENT_CHANGED')
                finally:
                    os.close(directory)
            except (OSError, StackError):
                self.send_error(503)
                return
        else:
            self.send_error(404)
            return
        etag = '"sha256-' + hashlib.sha256(body).hexdigest() + '"'
        modified = self.headers.get('If-None-Match') != etag
        self.send_response(200 if modified else 304)
        self.send_header('ETag', etag)
        self.send_header('Cache-Control', 'no-cache')
        self.send_header('Content-Type', 'application/json')
        self.send_header('Connection', 'close')
        self.close_connection = True
        if modified:
            self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        if modified and not head:
            self.wfile.write(body)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('daily', 'personal', 'ip', 'http', 'status', 'cleanup'))
    action = parser.parse_args().action
    os.environ.update(LC_ALL='C', TZ='UTC')
    if action == 'http':
        HTTPServer(('127.0.0.1', 8080), Handler).serve_forever()
        return 0
    require(sys.platform == 'linux' and os.geteuid() == 0, 'ROOT_LINUX_REQUIRED')
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(StackError('DOWNLOAD_TIMEOUT')))
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: (_ for _ in ()).throw(StackError('INTERRUPTED')))
    if action == 'personal':
        return watcher()
    if action == 'status':
        return status()
    if action == 'cleanup':
        with lock():
            report('cleanup', **cleanup())
        return 0
    try:
        report(action, **apply(action))
    except BlockingIOError as error:
        report(action, status='deferred', reason=deferred_reason(error))
        return 75
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        value = {'status': 'failed', 'error_type': type(error).__name__}
        code = str(error)
        if code and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789' for c in code):
            value['code'] = code
        report('runtime', **value)
        sys.exit(1)
