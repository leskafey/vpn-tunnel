#!/usr/bin/env python3
"""Small root-only administration CLI for fresh installations."""
import argparse
import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import sys
import tempfile
import uuid

PROFILES = Path(__file__).resolve().parent.parent / 'profiles'


def recover(r, restart=True):
    journal = r.DATA / 'device-transaction.json'
    if not journal.exists():
        return False
    record = r.record(journal)
    if record['status'] in ('committed', 'rolled_back'):
        return False
    config = r.ETC / 'xray.json'
    registry = r.ETC / 'devices.json'
    before = base64.b64decode(record['before_config'], validate=True)
    old_devices = base64.b64decode(record['before_devices'], validate=True)
    r.require(hashlib.sha256(before).hexdigest() == record['before_sha256']
              and r.digest(config) in (record['before_sha256'], record['after_sha256']),
              'DEVICE_RECOVERY_EXTERNAL_CONFIG_EDIT')
    r.require(r.digest(registry) in (hashlib.sha256(old_devices).hexdigest(), record['after_devices_sha256']),
              'DEVICE_RECOVERY_EXTERNAL_REGISTRY_EDIT')
    for name, checksum in record['created_profiles'].items():
        path = PROFILES / name
        r.require(Path(name).name == name and name.endswith('.json'), 'DEVICE_RECOVERY_PROFILE_PATH_INVALID')
        if path.exists() or path.is_symlink():
            if path.is_symlink() or r.digest(path) != checksum:
                r.report('device-recovery', status='profile_preserved', profile=str(path),
                         reason='modified_externally')
    removed = {}
    for name, snapshot in record.get('removed_profiles', {}).items():
        path = PROFILES / name
        r.require(Path(name).name == name and name.endswith('.json'), 'DEVICE_RECOVERY_PROFILE_PATH_INVALID')
        body = base64.b64decode(snapshot['body'], validate=True)
        checksum = snapshot['sha256']
        r.require(hashlib.sha256(body).hexdigest() == checksum, 'DEVICE_RECOVERY_PROFILE_SNAPSHOT_INVALID')
        removed[path] = body
        if path.exists() or path.is_symlink():
            if path.is_symlink() or r.digest(path) != checksum:
                r.report('device-recovery', status='profile_preserved', profile=str(path),
                         reason='modified_externally')
    for path, body in removed.items():
        if not path.exists():
            if not path.is_symlink():
                r.atomic(path, body)
    r.atomic(config, before)
    r.atomic(registry, old_devices)
    for name in record['created_profiles']:
        path = PROFILES / name
        if path.exists() and not path.is_symlink() and r.digest(path) == record['created_profiles'][name]:
            path.unlink()
    if restart:
        r.run(['systemctl', 'restart', 'vpn-stack-xray.service'], 'DEVICE_RECOVERY_RESTART_FAILED')
    record['status'] = 'rolled_back'
    record.pop('removed_profiles', None)
    r.atomic(journal, r.dump(record))
    return True


def transport(r, identity):
    outbound = r.record(r.ETC / 'probe-client.json')['outbounds'][0]
    outbound['uuid'] = identity
    return outbound


def device(r, operation, name=None, platform=None):
    with r.lock():
        recover(r)
        registry = r.record(r.ETC / 'devices.json')
        r.require(registry['schema'] == 1 and r.digest(r.ETC / 'xray.json') == registry['xray_sha256'],
                  'DEVICE_CONFIG_CHANGED_EXTERNALLY')
        if operation == 'list':
            for label, entry in sorted(registry['devices'].items()):
                print(label, flush=True)
            return
        r.require(isinstance(name, str) and re.fullmatch(r'[a-z][a-z0-9-]{0,39}', name)
                  and name != 'probe', 'DEVICE_NAME_INVALID')
        if operation == 'add':
            r.require(name not in registry['devices'], 'DEVICE_ALREADY_EXISTS')
            platform = 'universal' if platform is None else platform
            r.require(platform in ('universal', 'macos', 'windows', 'ios', 'android'), 'PLATFORM_INVALID')
            r.require(len(registry['devices']) < 256, 'DEVICE_COUNT_LIMIT')
        else:
            r.require(name in registry['devices'], 'DEVICE_NOT_FOUND')
        current = registry['devices'].get(name)
        if operation == 'export':
            paths = export(r, name, current)
            r.report('device', status='exported', device=name, profiles=paths)
            return
        before = r.raw_file(r.ETC / 'xray.json', 1048576)
        before_devices = r.raw_file(r.ETC / 'devices.json', 1048576)
        config = json.loads(before)
        clients = config['inbounds'][0]['settings']['clients']
        updated = copy.deepcopy(registry)
        outputs = {}
        removed = {}
        preserved = []
        deleted = []
        if operation == 'add':
            entry = {'platform': platform, 'uuid': str(uuid.uuid4())}
            updated['devices'][name] = entry
            clients.append({'id': entry['uuid'], 'email': name, 'flow': 'xtls-rprx-vision'})
            outputs = profile_outputs(r, name, entry)
        else:
            r.require(sum(client['id'] == current['uuid'] for client in clients) == 1, 'DEVICE_IDENTITY_MISMATCH')
            config['inbounds'][0]['settings']['clients'] = [c for c in clients if c['id'] != current['uuid']]
            del updated['devices'][name]
            # Exported files may have been moved off the server. Only inspect an
            # existing directory; profile_outputs still rejects unsafe paths.
            profiles = (profile_outputs(r, name, current, existing=True)
                        if PROFILES.exists() or PROFILES.is_symlink() else {})
            for path, body in profiles.items():
                if path.exists() or path.is_symlink():
                    if path.is_symlink() or r.digest(path) != hashlib.sha256(body).hexdigest():
                        preserved.append(str(path))
                    else:
                        removed[path] = body
        raw = r.dump(config)
        updated['xray_sha256'] = hashlib.sha256(raw).hexdigest()
        registry_raw = r.dump(updated)
        journal = {'status': 'prepared', 'before_config': base64.b64encode(before).decode(),
                   'before_devices': base64.b64encode(before_devices).decode(),
                   'before_sha256': hashlib.sha256(before).hexdigest(), 'after_sha256': hashlib.sha256(raw).hexdigest(),
                   'after_devices_sha256': hashlib.sha256(registry_raw).hexdigest(),
                   'created_profiles': {p.name: hashlib.sha256(body).hexdigest() for p, body in outputs.items()},
                   'removed_profiles': {p.name: {'body': base64.b64encode(body).decode(),
                                                 'sha256': hashlib.sha256(body).hexdigest()}
                                        for p, body in removed.items()}}
        with tempfile.TemporaryDirectory(prefix='device-', dir=r.DATA) as folder:
            work = Path(folder)
            candidate = work / 'xray.json'
            r.atomic(candidate, raw)
            r.run([r.CODE / 'bin/xray', 'run', '-test', '-config', candidate], 'DEVICE_NATIVE_CONFIG_FAILED')
            r.atomic(r.DATA / 'device-transaction.json', r.dump(journal))
            try:
                r.atomic(r.ETC / 'xray.json', raw)
                r.run(['systemctl', 'restart', 'vpn-stack-xray.service'], 'DEVICE_TRANSPORT_RESTART_FAILED')
                if operation == 'add':
                    source, manifest = r.active()
                    for filename in ('witnesses.json', *(tag + '.normalized.txt' for tag in r.provider_tags(source))):
                        os.link(source / filename, work / filename, follow_symlinks=False)
                    probe = r.record(r.ETC / 'probe-client.json')
                    probe['outbounds'][0]['uuid'] = entry['uuid']
                    r.probes(r.modules(), work, manifest, probe_config=probe)
                else:
                    r.local_access(r.modules(), work, current['uuid'])
                for path, body in outputs.items():
                    r.atomic(path, body)
                for path, body in removed.items():
                    if path.is_symlink() or path.exists() and r.digest(path) != hashlib.sha256(body).hexdigest():
                        preserved.append(str(path))
                    elif path.exists():
                        path.unlink()
                        deleted.append(str(path))
                r.atomic(r.ETC / 'devices.json', registry_raw)
                journal['status'] = 'committed'
                journal.pop('removed_profiles', None)
                r.atomic(r.DATA / 'device-transaction.json', r.dump(journal))
            except BaseException:
                handlers = {sig: signal.signal(sig, signal.SIG_IGN) for sig in (signal.SIGINT, signal.SIGTERM)}
                try:
                    recover(r)
                finally:
                    for sig, handler in handlers.items():
                        signal.signal(sig, handler)
                raise
        r.report('device', status='added' if operation == 'add' else 'revoked', device=name,
                 profiles=[str(p) for p in outputs], removed_profiles=deleted,
                 preserved_profiles=preserved,
                 profile_message='Изменённые вручную файлы сохранены; их UUID отозван.' if preserved else None,
                 other_device_UUIDs_preserved=True,
                 transport_restarted=True)


def profile_outputs(r, name, entry, existing=False):
    r.require(PROFILES.is_dir() and not PROFILES.is_symlink() and PROFILES.stat().st_uid == 0
              and PROFILES.stat().st_mode & 0o077 == 0, 'PRIVATE_PROFILE_DIRECTORY_REQUIRED')
    outputs = {}
    for full in (False, True):
        path = PROFILES / (name + ('-full.json' if full else '-smart.json'))
        raw = r.dump(r.profile(transport(r, entry['uuid']), entry['platform'], full))
        r.require(existing or not path.exists() and not path.is_symlink(), 'DEVICE_PROFILE_PATH_ALREADY_EXISTS')
        outputs[path] = raw
    return outputs


def export(r, name, entry):
    outputs = profile_outputs(r, name, entry, existing=True)
    for path, raw in outputs.items():
        if path.exists() or path.is_symlink():
            r.require(not path.is_symlink() and r.digest(path) == hashlib.sha256(raw).hexdigest(),
                      'EXPORTED_PROFILE_MODIFIED_EXTERNALLY')
        else:
            r.atomic(path, raw)
    return [str(path) for path in outputs]


def rule(r, operation, kind, value):
    r.require(kind in (*r.FILES, 'proxy-ip'), 'RULE_KIND_INVALID')
    s = r.modules()
    path = r.ETC / (r.IP_FILE if kind == 'proxy-ip' else r.FILES[kind])
    raw = r.personal_raw(kind, path.name)
    if kind == 'proxy-ip':
        parse = r.parse_personal_ips
        canonical = lambda line: str(parse(line.encode())[0])
    else:
        parse = lambda body: s.core.parse_personal(body, s.parser)
        canonical = lambda line: parse(line.encode())[0]
    entries = parse(raw)
    r.require(len(parse(value.encode())) == 1, 'ONE_RULE_REQUIRED')
    item = canonical(value)
    present = any(str(row) == item for row in entries)
    if operation == 'add' and present or operation == 'remove' and not present:
        r.report('rule', status='unchanged', kind=kind)
        return
    lines = raw.decode('utf-8').splitlines(keepends=True)
    if operation == 'add':
        candidate = raw + (b'\n' if raw and not raw.endswith(b'\n') else b'') + item.encode() + b'\n'
    else:
        candidate = ''.join(line for line in lines if not parse(line.encode()) or canonical(line) != item).encode()
    parse(candidate)
    if kind == 'direct':
        r.require(len(parse(candidate)) <= 256 and len(r.direct_body(parse(candidate))) <= 32768,
                  'PERSONAL_DIRECT_SIZE_LIMIT')
    if kind == 'proxy-ip':
        _, active = r.active()
        r.ip_body([r.ipaddress.ip_network(c) for c in active['ip']['source_CIDRs']] + parse(candidate))
    r.require(r.personal_raw(kind, path.name) == raw, 'RULE_FILE_CHANGED_DURING_EDIT')
    r.atomic(path, candidate)
    r.report('rule', status='saved', kind=kind, application='automatic watcher',
             device_DIRECT_interval='5m', device_IP_interval='1h')


def main():
    parser = argparse.ArgumentParser(prog='vpnctl', description='Устройства и личные правила VPN')
    commands = parser.add_subparsers(dest='command', required=True)
    dev = commands.add_parser('device', help='Отдельный UUID и SMART/FULL для устройства',
        description='add: новый UUID; export: пути файлов и восстановление отсутствующих без смены UUID, ручные правки не перезаписываются; revoke: локально проверенный отзыв UUID, изменённые JSON сохраняются. Добавление и отзыв перезапускают Xray.')
    dev.add_argument('operation', choices=('add', 'list', 'export', 'revoke'))
    dev.add_argument('name', nargs='?')
    dev.add_argument('--platform', choices=('universal', 'macos', 'windows', 'ios', 'android'),
                     default='universal', help='Необязательно: по умолчанию общий профиль для всех устройств')
    rules = commands.add_parser('rule')
    rules.add_argument('operation', choices=('add', 'remove'))
    rules.add_argument('kind', choices=('proxy', 'direct', 'ads', 'ads-exceptions', 'proxy-ip'))
    rules.add_argument('value')
    commands.add_parser('status', help='Локальные службы, обновления, последняя политика и неприменённые правки; код 1 при неисправности')
    commands.add_parser('cleanup', help='Удалить остатки обновлений, сохранив активные данные, транзакцию и откат; работает при полном диске')
    commands.add_parser('recover')
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('vpn_admin_runtime', Path(__file__).with_name('vpn-stack-runtime.py'))
    r = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(r)
    r.require(os.geteuid() == 0 and sys.platform == 'linux', 'ROOT_LINUX_REQUIRED')
    os.umask(0o077)
    if args.command != 'status':
        r.modules()  # Validate the complete installed public bundle before mutation.
    if args.command == 'device':
        device(r, args.operation, args.name, args.platform)
    elif args.command == 'rule':
        with r.lock():
            rule(r, args.operation, args.kind, args.value)
    elif args.command == 'recover':
        with r.lock():
            r.report('device', recovered=recover(r, restart=False))
    elif args.command == 'cleanup':
        with r.lock():
            r.report('cleanup', **r.cleanup())
    else:
        return r.status()
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except BlockingIOError:
        print('VPN_STACK_REPORT=' + json.dumps({'status': 'deferred', 'code': 'POLICY_BUSY_RETRY_LATER'}), flush=True)
        sys.exit(75)
    except Exception as error:
        value = {'status': 'failed', 'error_type': type(error).__name__}
        if re.fullmatch(r'[A-Z0-9_]+', str(error)):
            value['code'] = str(error)
        print('VPN_STACK_REPORT=' + json.dumps(value), flush=True)
        sys.exit(1)
