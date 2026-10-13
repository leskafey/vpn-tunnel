#!/usr/bin/env python3
"""Ubuntu 24.04 amd64 installation, transactional upgrade and read-only audit."""
import argparse
import base64
import ctypes
import gzip
import grp
import hashlib
import importlib.util
import io
import ipaddress
import json
import os
from pathlib import Path
import platform
import pwd
import secrets
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tarfile
import time
import tempfile
import urllib.request
import uuid
import zipfile
from types import SimpleNamespace

ARTIFACTS = {
    'mihomo': {'version': '1.19.31', 'kind': 'gz',
               'url': 'https://github.com/MetaCubeX/mihomo/releases/download/v1.19.31/mihomo-linux-amd64-compatible-v1.19.31.gz',
               'sha256': '04cf9f09671704f839ddbee2e93069dc831a4123a75281e725d1d96ab9ac1afc'},
    'sing-box': {'version': '1.14.2', 'kind': 'tar', 'member': 'sing-box-1.14.2-linux-amd64/sing-box',
                 'url': 'https://github.com/SagerNet/sing-box/releases/download/v1.14.2/sing-box-1.14.2-linux-amd64.tar.gz',
                 'sha256': 'a684484d7477d1437282ee411f4d131d0340aaad60a7868841ebd5d87dd8a0c6'},
    'xray': {'version': '26.3.27', 'kind': 'zip', 'member': 'xray',
             'url': 'https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-64.zip',
             'sha256': '23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae'},
}
PROJECT = Path(__file__).resolve().parent.parent
ROOT = PROJECT / 'state' / 'install'
STATE = ROOT / 'installation.json'
UNIT_ROOT = Path('/etc/systemd/system')
PROFILE_ROOT = PROJECT / 'profiles'
CLI = Path('/usr/local/sbin/vpnctl')
CLI_BODY = None
BIN_LIMIT = 150 * 1048576
RUNTIME = None

RULE_INSTRUCTIONS = {
    'ads.txt': '''Дополнительные домены для блокировки рекламы на сервере.
Формат: одна запись на строку, без схемы, порта и пути; домен и поддомены.
До 2048 уникальных доменов, файл до 64 КиБ, строка до 4096 байт.
Личные блокировки имеют приоритет над исключениями источников и DIRECT/PROXY.
Личные ads-exceptions.txt снимают в том числе эти блокировки.
Примеры (не действуют):
ads.example.org
Изменения применяются автоматически к новым DNS-запросам; профиль не менять.
''',
    'proxy.txt': '''Домены, которые серверный DNS направляет через VPS в SMART.
Формат: одна запись на строку, без схемы, порта и пути; домен и его поддомены.
Ограничения: до 2048 уникальных доменов, файл до 64 КиБ, строка до 4096 байт.
Примеры (не действуют):
example.org
video.example.org
После сохранения правило действует на сервере для новых DNS-запросов.
FULL уже отправляет разрешённый IPv4 через VPS; PROXY не меняет его маршрут.
Клиентские IP обновляются раз в час, личный DIRECT — раз в пять минут.
''',
    'proxy-ip.txt': '''Публичные IPv4 и сети CIDR, которые SMART направляет через VPS.
Формат: один IPv4 или IPv4/CIDR на строку; адрес без маски означает /32.
Ограничения: маски /12–/32, нулевые биты хоста у CIDR; IPv6 не принимается.
Парсер Python ipaddress проверяет is_global сети, первого и последнего адреса.
Приватные, служебные, multicast и зарезервированные сети не поддерживаются.
До 256 записей (до удаления дублей), файл до 32 КиБ, включая комментарии.
Итоговый список вместе с автоматическими IP: до 256 CIDR и 32 КиБ JSON.
Примеры (не действуют):
8.8.8.8
8.8.4.0/24
После применения SMART получит IP-правила в течение часа; профиль не менять.
FULL уже отправляет разрешённый IPv4 через VPS; личный DIRECT обновляется за 5 минут.
''',
    'direct.txt': '''Личный DIRECT для доменов; приоритет выше личного и автоматического PROXY.
Формат: одна запись на строку, без схемы, порта и пути; домен и его поддомены.
Ограничения: до 256 доменов, клиентский JSON до 32 КиБ; файл до 64 КиБ.
Строка до 4096 байт. Блокировка рекламы имеет приоритет над DIRECT.
SMART выводит соответствующий трафик из туннеля после обновления списка.
FULL оставляет трафик через VPS; DIRECT влияет только на серверную обработку.
Соединение непосредственно по IP не сообщает домен: DIRECT не отменяет
произвольное IP-правило. Используйте DNS профиля; сторонний DoH/Private DNS
может обойти доменные правила.
Примеры (не действуют):
example.org
local.example.org
После применения личный DIRECT на SMART обновится в течение пяти минут.
Клиентские IP-правила обновляются раз в час; профиль пересоздавать не нужно.
''',
    'ads-exceptions.txt': '''Доменные исключения из блокировки рекламы на сервере.
Формат: одна запись на строку, без схемы, порта и пути; домен и его поддомены.
Ограничения: до 2048 уникальных доменов, файл до 64 КиБ, строка до 4096 байт.
Исключение снимает блокировку рекламы, но само не выбирает маршрут.
Далее применяются DIRECT/PROXY; для доменных правил используйте DNS профиля.
Примеры (не действуют):
ads.example.org
После сохранения исключение применяется на сервере для новых DNS-запросов.
Клиентские IP обновляются раз в час, личный DIRECT — раз в пять минут.
''',
}


def create_rule_files(runtime):
    for name, instructions in RULE_INSTRUCTIONS.items():
        path = runtime.ETC / name
        require(not path.is_symlink(), 'PERSONAL_RULE_SYMLINK_REFUSED')
        if path.exists():
            runtime.raw_file(path)  # Validate ownership/type without changing user bytes.
            require(not path.stat().st_mode & 0o077, 'PRIVATE_RULE_FILE_REQUIRED')
            continue
        footer = ('Изменения: сохраните файл или используйте vpnctl rule add/remove.\n'
                  'Применение после 3 секунд покоя; при занятости повтор через 15 секунд.\n'
                  'Невалидные правки не заменяют последнюю рабочую политику.\n'
                  'Все строки ниже — комментарии; удалите # у своего правила для включения.\n')
        runtime.atomic(path, ''.join('# ' + row + '\n' for row in (instructions + footer).splitlines()).encode('utf-8'))


class InstallError(Exception):
    pass


def require(value, code):
    if not value:
        raise InstallError(code)


def load_runtime(folder):
    path = folder / 'vpn-stack-runtime.py'
    spec = importlib.util.spec_from_file_location('vpn_stack_install_runtime', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.configure_paths(PROJECT)
    return module


def configure_project(project):
    global PROJECT, ROOT, STATE, PROFILE_ROOT, CLI_BODY
    PROJECT = Path(project).resolve()
    validate_project_paths()
    ROOT = PROJECT / 'state' / 'install'
    STATE = ROOT / 'installation.json'
    PROFILE_ROOT = PROJECT / 'profiles'
    CLI_BODY = ('#!/bin/sh\nexec /usr/bin/python3 ' + shlex.quote(str(PROJECT / 'lib' / 'vpn-stack-manage.py')) + ' "$@"\n').encode()


def validate_project_paths():
    require(PROJECT.is_dir() and not any(c in str(PROJECT) for c in '\n\r%'), 'PROJECT_PATH_INVALID')
    # Use the portable limit (including the NUL) for both Linux and local checks.
    # The isolated probe's data/.s-XXXXXXXX/api.sock is shorter than this path.
    require(len(os.fsencode(PROJECT / 'cache/backend/controller.sock')) < 104,
            'PROJECT_UNIX_SOCKET_PATH_TOO_LONG')


def policy_view_root(project):
    """Hide the project, and any non-traversable ancestors, only inside units.

    Bind mounts expose selected subdirectories at their original absolute paths.
    No host directory needs chmod or ACL changes, even with a 0700 /root.
    """
    project = Path(project)
    closed = [path for path in (project, *project.parents)
              if not path.stat().st_mode & 0o001]
    view = closed[-1] if closed else project
    require(view not in map(Path, ('/', '/usr', '/etc', '/bin', '/sbin', '/lib',
                                  '/lib64', '/proc', '/sys', '/dev', '/run')),
            'POLICY_NAMESPACE_ROOT_UNSAFE')
    return view


def policy_bind_view(project):
    # systemd 255's executor serializes bind/tmpfs paths differently from its
    # unit parser. Keep the established DAC model for these literal paths;
    # otherwise quoted/escaped names can be truncated when the unit starts.
    return not any(c in str(project) for c in '\'"\\:\t')


def audit_policy_traversal():
    paths = (PROJECT, *PROJECT.parents)
    try:
        account = pwd.getpwnam('vpn-policy')
    except KeyError:
        require(all(path.stat().st_mode & 0o001 for path in paths),
                'POLICY_USER_PROJECT_TRAVERSAL_REQUIRED')
        return
    require(account.pw_uid != 0 and account.pw_gid != 0, 'NON_ROOT_POLICY_ACCOUNT_REQUIRED')
    # Check actual access, including supplementary groups and existing ACLs,
    # in a child. The audit never changes host permissions or creates users.
    probe = ('import os,sys; os.setgroups(' + repr(os.getgrouplist(account.pw_name, account.pw_gid))
             + '); os.setgid(' + str(account.pw_gid) + '); os.setuid(' + str(account.pw_uid)
             + '); sys.exit(0 if all(os.access(p, os.X_OK) for p in sys.argv[1:]) else 1)')
    result = subprocess.run(['/usr/bin/python3', '-c', probe, *map(str, paths)], capture_output=True, timeout=10)
    require(result.returncode == 0, 'POLICY_USER_PROJECT_TRAVERSAL_REQUIRED')


def audit_policy_namespace():
    """Read-only prerequisites; do not create accounts, units or mounts."""
    require(Path('/proc/self/ns/mnt').exists()
            and any(row.split()[-1:] == ['tmpfs'] for row in Path('/proc/filesystems').read_text().splitlines()),
            'SYSTEMD_MOUNT_NAMESPACE_REQUIRED')
    fields = dict(row.split(':', 1) for row in Path('/proc/self/status').read_text().splitlines() if ':' in row)
    require(int(fields.get('CapEff', '0'), 16) & (1 << 21), 'MOUNT_NAMESPACE_CAPABILITY_REQUIRED')
    if not policy_bind_view(PROJECT):
        audit_policy_traversal()
        return {'model': 'posix-service-access', 'host_permissions_changed': False}
    view = policy_view_root(PROJECT)
    return {'model': 'systemd-bind-mounts', 'view_root': str(view), 'host_permissions_changed': False}


def prepare_service_directories(runtime, account, resume):
    require(account.pw_uid != 0 and account.pw_gid != 0, 'NON_ROOT_POLICY_ACCOUNT_REQUIRED')
    require(not (PROJECT / 'cache').is_symlink() and not (PROJECT / 'state').is_symlink(),
            'INSTALL_PATH_SYMLINK_REFUSED')
    (PROJECT / 'cache').mkdir(mode=0o755, exist_ok=resume)
    require((PROJECT / 'cache').stat().st_uid == 0, 'ROOT_OWNED_CACHE_DIRECTORY_REQUIRED')
    (PROJECT / 'cache').chmod(0o755)
    for path, mode, owner in ((runtime.CODE, 0o755, (0, 0)), (runtime.CODE / 'bin', 0o755, (0, 0)),
                              (runtime.ETC, 0o750, (0, account.pw_gid)), (runtime.DATA, 0o750, (0, account.pw_gid)),
                              (runtime.DATA / 'generations', 0o750, (0, account.pw_gid)),
                              (runtime.HOME, 0o700, (account.pw_uid, account.pw_gid))):
        require(not path.is_symlink(), 'INSTALL_PATH_SYMLINK_REFUSED')
        path.mkdir(mode=mode, exist_ok=resume)
        os.chown(path, *owner)
        path.chmod(mode)


def host_audit(runtime, resume=False, *, minimum_memory_mib=650):
    validate_project_paths()
    require(sys.platform == 'linux' and os.geteuid() == 0, 'ROOT_LINUX_REQUIRED')
    release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    require(release.get('ID', '').strip('"') == 'ubuntu' and release.get('VERSION_ID', '').strip('"') == '24.04',
            'UBUNTU_24_04_REQUIRED')
    require(platform.machine() == 'x86_64' and Path('/run/systemd/system').is_dir(), 'AMD64_SYSTEMD_REQUIRED')
    require(Path('/sys/fs/cgroup/cgroup.controllers').is_file(), 'CGROUP_V2_REQUIRED')
    available = next(int(row.split()[1]) for row in Path('/proc/meminfo').read_text().splitlines() if row.startswith('MemAvailable:'))
    conflicts = []
    for name in ('xray.service', 'vpn-server-dns-trial.service', 'vpn-lists-http.service',
                 'vpn-awg31-public-pilot.service', 'amnezia-awg.service'):
        result = subprocess.run(['systemctl', 'show', name, '-p', 'LoadState', '--value'], capture_output=True, timeout=10)
        if result.stdout.strip() not in (b'', b'not-found'):
            conflicts.append(name)
    for path in (Path('/etc/xray'), Path('/etc/vpn-lists'), Path('/usr/local/lib/vpn-lists')):
        if path.exists() or path.is_symlink():
            conflicts.append(str(path))
    require(not conflicts, 'EXISTING_VPN_INSTALLATION_REFUSING_TO_OVERWRITE')
    require(available >= minimum_memory_mib * 1024 and shutil.disk_usage(PROJECT).free >= 2 * 1024**3,
            'MEMORY_OR_DISK_HEADROOM_LOW')
    require(PROJECT.stat().st_uid == 0 and not PROJECT.stat().st_mode & 0o022,
            'ROOT_OWNED_PROJECT_REQUIRED')
    policy_access = audit_policy_namespace()
    if not resume:
        for legacy in (Path('/etc/vpn-stack'), Path('/var/lib/vpn-stack-install'),
                       Path('/usr/local/lib/vpn-stack'), Path('/var/lib/vpn-stack'),
                       Path('/var/lib/vpn-stack-backend'), Path('/root/vpn-stack-profiles')):
            require(not legacy.exists() and not legacy.is_symlink(), 'EXISTING_VPN_INSTALLATION_REFUSING_TO_OVERWRITE')
        for path in (runtime.CODE, runtime.ETC, runtime.DATA, PROJECT / 'cache', PROJECT / 'state', ROOT,
                     PROFILE_ROOT, CLI):
            require(not path.exists() and not path.is_symlink(), 'MANAGED_PATH_ALREADY_EXISTS')
        for name in units(runtime):
            require(not (UNIT_ROOT / name).exists() and not (UNIT_ROOT / name).is_symlink(), 'UNIT_ALREADY_EXISTS')
        for port, kind in ((443, socket.SOCK_STREAM), (8080, socket.SOCK_STREAM),
                           (19080, socket.SOCK_STREAM), (19053, socket.SOCK_STREAM), (19053, socket.SOCK_DGRAM)):
            with socket.socket(socket.AF_INET, kind) as stream:
                try:
                    stream.bind(('0.0.0.0', port))
                except OSError:
                    raise InstallError('REQUIRED_PORT_ALREADY_IN_USE') from None
    return {'status': 'compatible', 'OS': 'Ubuntu 24.04', 'architecture': 'x86_64',
            'memory_available_MiB': round(available / 1024), 'DIRECT_interval': '5m',
            'IP_interval': '1h', 'large_domain_lists': 'VPS', 'firewall_changed': False,
            'policy_access': policy_access}


def units(runtime):
    common = '''NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
UMask=0077
Environment=LC_ALL=C TZ=UTC GOMEMLIMIT=64MiB GOGC=50 GOMAXPROCS=1 @SAFE_PATHS@
'''
    # A read-only tmpfs hides the project (or a closed ancestor) in each
    # unprivileged unit. Bind directories, not backend.yaml: atomic replacement
    # and new policy generations must remain visible to already running units.
    # ProtectHome's built-in /root mounts override an explicit tmpfs at the
    # same path (and its tmpfs variant uses mode 0700). Use explicit read-only
    # home overlays instead; the host home directories are never exposed.
    policy_common = common.replace('ProtectHome=read-only', 'ProtectHome=no') + '''TemporaryFileSystem=@VIEW@
BindReadOnlyPaths=@CODE@ @DATA@
'''
    result = {}
    result['vpn-stack-xray.service'] = '''[Unit]
Description=VLESS REALITY VPN transport
After=network-online.target vpn-stack-dns.service vpn-stack-http.service vpn-stack-device-recover.service
Wants=network-online.target vpn-stack-dns.service vpn-stack-http.service
Requires=vpn-stack-device-recover.service
[Service]
Type=simple
ExecStart=/usr/bin/env -- @CODE@/bin/xray run -config @CONFIG@/xray.json
Restart=on-failure
RestartSec=3
MemoryMax=128M
TasksMax=64
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
''' + common + '[Install]\nWantedBy=multi-user.target\n'
    result['vpn-stack-dns.service'] = '''[Unit]
Description=Private server DNS and domain policy
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=vpn-policy
Group=vpn-policy
WorkingDirectory=@BACKEND@
ExecStart=/usr/bin/env -- @CODE@/bin/mihomo -d @BACKEND@ -f @CONFIG@/backend.yaml
Restart=on-failure
RestartSec=3
MemoryHigh=160M
MemoryMax=192M
MemorySwapMax=0
TasksMax=64
ReadWritePaths=@BACKEND@
BindReadOnlyPaths=@CONFIG@
BindPaths=@BACKEND@
CapabilityBoundingSet=
''' + (policy_common if policy_bind_view(runtime.CODE.parent) else common) + '[Install]\nWantedBy=multi-user.target\n'
    result['vpn-stack-http.service'] = '''[Unit]
Description=Private bounded VPN rule delivery
After=network-online.target
[Service]
Type=simple
User=vpn-policy
Group=vpn-policy
ExecStart=/usr/bin/python3 @CODE@/vpn-stack-runtime.py http
Restart=on-failure
RestartSec=3
MemoryMax=64M
TasksMax=16
CapabilityBoundingSet=
''' + (policy_common if policy_bind_view(runtime.CODE.parent) else common) + '[Install]\nWantedBy=multi-user.target\n'
    for action, size in (('daily', 384), ('ip', 256), ('personal', 256)):
        result['vpn-stack-' + action + '.service'] = f'''[Unit]
Description=Verified VPN {action} policy update
After=vpn-stack-xray.service vpn-stack-dns.service vpn-stack-http.service
StartLimitIntervalSec=0
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 @CODE@/vpn-stack-runtime.py {action}
MemoryHigh={size}M
MemoryMax={size}M
MemorySwapMax=0
TasksMax=64
TimeoutStartSec=900
TimeoutStopSec=60
Restart=on-failure
RestartPreventExitStatus=1
RestartSec=15
ReadWritePaths=@CONFIG@ @DATA@ @BACKEND@
''' + common
        # Personal startup reconciles edits made while the host was down.
        if action == 'personal':
            result['vpn-stack-' + action + '.service'] += '[Install]\nWantedBy=multi-user.target\n'
    for action, schedule in (('daily', '*-*-* 03:00:00 UTC'), ('ip', '*-*-* 03:20:00 UTC')):
        result['vpn-stack-' + action + '.timer'] = f'''[Unit]
Description=Daily VPN {action} source refresh
[Timer]
OnCalendar={schedule}
RandomizedDelaySec=10min
Persistent=true
Unit=vpn-stack-{action}.service
[Install]
WantedBy=timers.target
'''
    result['vpn-stack-personal.path'] = '''[Unit]
Description=Apply edited personal VPN rules
[Path]
PathChanged=@CONFIG@/proxy.txt
PathChanged=@CONFIG@/direct.txt
PathChanged=@CONFIG@/ads-exceptions.txt
PathChanged=@CONFIG@/ads.txt
PathChanged=@CONFIG@/proxy-ip.txt
PathChanged=@CONFIG@
Unit=vpn-stack-personal.service
[Install]
WantedBy=multi-user.target
'''
    result['vpn-stack-device-recover.service'] = '''[Unit]
Description=Recover interrupted device configuration before transport startup
Before=vpn-stack-xray.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/python3 @CODE@/vpn-stack-manage.py recover
MemoryMax=64M
TasksMax=16
ReadWritePaths=@CONFIG@ @DATA@ @PROFILES@
ProtectHome=no
UMask=0077
'''
    # systemd 255: single paths are literal, path lists use EXTRACT_UNQUOTE,
    # whereas ExecStart and Environment also use EXTRACT_CUNESCAPE.
    def quoted(value, c_unescape=False):
        text = str(value).replace('\\', '\\\\').replace('"', '\\"')
        if c_unescape:
            text = text.replace('\t', '\\t')
        return '"' + text + '"'
    paths = {'@CODE@': runtime.CODE,
             '@CONFIG@': runtime.ETC, '@BACKEND@': runtime.HOME,
             '@DATA@': runtime.DATA, '@PROFILES@': PROFILE_ROOT}
    # The DAC variant uses the original units, without bind mounts/overlays.
    if not policy_bind_view(runtime.CODE.parent):
        for name in ('vpn-stack-dns.service', 'vpn-stack-http.service'):
            result[name] = '\n'.join(row for row in result[name].splitlines()
                                     if not row.startswith(('BindPaths=', 'BindReadOnlyPaths='))) + '\n'
    project = runtime.CODE.parent
    view = policy_view_root(project) if policy_bind_view(project) else project
    # systemd otherwise copies host modes onto intermediate mount targets.
    # A 0700 project (or any nested parent) must also be replaced by a visible
    # placeholder, without exposing its original contents.
    views = list(dict.fromkeys([Path('/root'), Path('/home'), Path('/run/user')]
                              + [path for path in reversed((project, *project.parents))
                                 if path == view or view in path.parents]))
    def substitute(value):
        for token, path in paths.items():
            value = value.replace(token, str(path))
        return value
    for name, body in result.items():
        lines = []
        for line in body.splitlines():
            directive, separator, value = line.partition('=')
            if directive == 'ExecStart':
                # No environment interpolation: a '$' in a project path is literal.
                value = ':' + ' '.join(quoted(substitute(word), True) for word in value.split())
            elif directive in ('ReadWritePaths', 'BindPaths', 'BindReadOnlyPaths'):
                value = ' '.join(quoted(substitute(word)) for word in value.split())
            elif directive == 'TemporaryFileSystem':
                # systemd parses this twice: whitespace/quotes first, then ':'
                # with another backslash-unescape pass. Preserve literal ':'
                # and backslashes in arbitrary supported project paths.
                value = ' '.join(quoted(str(path).replace('\\', '\\\\').replace(':', '\\:')
                                        + ':ro,mode=0755,size=1M') for path in views)
            elif directive == 'Environment':
                value = value.replace('@SAFE_PATHS@', quoted('SAFE_PATHS=' + str(runtime.DATA / 'generations'), True))
            else:
                value = substitute(value)  # WorkingDirectory/PathChanged: no quotes or C escapes.
            lines.append(directive + separator + value)
        result[name] = '\n'.join(lines) + '\n'
    return result


def extract_binary(raw, item):
    if item['kind'] == 'gz':
        stream = gzip.GzipFile(fileobj=io.BytesIO(raw))
    elif item['kind'] == 'tar':
        archive = tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz')
        members = [m for m in archive.getmembers() if m.name == item['member']]
        require(len(members) == 1 and members[0].isfile() and members[0].size <= BIN_LIMIT,
                'ARCHIVE_BINARY_MEMBER_INVALID')
        stream = archive.extractfile(members[0])
    else:
        archive = zipfile.ZipFile(io.BytesIO(raw))
        members = [m for m in archive.infolist() if m.filename == item['member']]
        require(len(members) == 1 and members[0].file_size <= BIN_LIMIT and not members[0].is_dir(),
                'ARCHIVE_BINARY_MEMBER_INVALID')
        stream = archive.open(members[0])
    with stream:
        body = stream.read(BIN_LIMIT + 1)
    require(0 < len(body) <= BIN_LIMIT, 'BINARY_SIZE_LIMIT')
    return body


def download_binary(runtime, name, item):
    request = urllib.request.Request(item['url'], headers={'User-Agent': 'vpn-stack-installer/1', 'Accept-Encoding': 'identity'})
    started = last = time.monotonic()
    with urllib.request.urlopen(request, timeout=30) as response, (ROOT / (name + '.archive')).open('wb') as output:
        require(response.status == 200 and response.url.startswith('https://'), 'BINARY_DOWNLOAD_STATUS')
        size = 0
        checksum = hashlib.sha256()
        while True:
            raw = response.read(65536)
            if not raw:
                break
            size += len(raw)
            require(size <= 100 * 1048576 and time.monotonic() - started < 300, 'BINARY_DOWNLOAD_LIMIT')
            checksum.update(raw)
            output.write(raw)
            if time.monotonic() - last >= 15:
                runtime.report('download', component=name, bytes=size)
                last = time.monotonic()
    require(checksum.hexdigest() == item['sha256'], 'OFFICIAL_ARCHIVE_SHA256_MISMATCH')
    archive = ROOT / (name + '.archive')
    body = extract_binary(archive.read_bytes(), item)
    runtime.atomic(runtime.CODE / 'bin' / name, body, 0o755)
    archive.unlink()
    return hashlib.sha256(body).hexdigest()


def create_transport(runtime, state):
    settings = runtime.ETC / 'settings.json'
    identity_path = ROOT / 'identity.json'
    if identity_path.exists():
        identity = runtime.record(identity_path)
        require(identity['server_ip'] == state['server_ip'], 'RESUME_SERVER_IP_CHANGED')
    else:
        require(not settings.exists() and not state['private_files'], 'IDENTITY_CHECKPOINT_REQUIRED')
        raw = runtime.run([runtime.CODE / 'bin/sing-box', 'generate', 'reality-keypair'], 'REALITY_KEY_GENERATION_FAILED')
        fields = dict(row.split(':', 1) for row in raw.decode('ascii').splitlines() if ':' in row)
        private, public = fields.get('PrivateKey', '').strip(), fields.get('PublicKey', '').strip()
        require(len(private) == len(public) == 43, 'REALITY_KEY_OUTPUT_INVALID')
        identity = {'server_ip': state['server_ip'], 'private_key': private, 'public_key': public,
                    'short_id': secrets.token_hex(8),
                    'identities': {'probe': str(uuid.uuid4())}}
        runtime.atomic(identity_path, runtime.dump(identity))
    private, public = identity['private_key'], identity['public_key']
    short_id, identities = identity['short_id'], identity['identities']
    require(set(identities) == {'probe'} and len(set(identities.values())) == 1,
            'IDENTITY_CHECKPOINT_INVALID')
    outputs = {settings: runtime.dump({k: identity[k] for k in ('server_ip', 'identities', 'public_key', 'short_id')}),
               runtime.ETC / 'xray.json': runtime.dump(runtime.xray_config(private, short_id, identities))}
    outputs[runtime.ETC / 'devices.json'] = runtime.dump({'schema': 1,
        'xray_sha256': hashlib.sha256(outputs[runtime.ETC / 'xray.json']).hexdigest(),
        'devices': {}})
    profile_dir = PROFILE_ROOT
    require(not profile_dir.is_symlink(), 'PROFILE_DIRECTORY_SYMLINK_REFUSED')
    profile_dir.mkdir(mode=0o700, exist_ok=True)
    require(profile_dir.stat().st_uid == 0 and stat.S_IMODE(profile_dir.stat().st_mode) == 0o700,
            'PRIVATE_PROFILE_DIRECTORY_REQUIRED')
    for name, identity in identities.items():
        outbound = {'type': 'vless', 'tag': 'vps', 'server': state['server_ip'], 'server_port': 443,
                    'uuid': identity, 'flow': 'xtls-rprx-vision', 'packet_encoding': 'xudp',
                    'tls': {'enabled': True, 'server_name': 'gateway.icloud.com',
                            'utls': {'enabled': True, 'fingerprint': 'chrome'},
                            'reality': {'enabled': True, 'public_key': public, 'short_id': short_id}}}
        probe = {'log': {'level': 'warn'}, 'outbounds': [outbound], 'route': {'final': 'vps'}}
        outputs[runtime.ETC / 'probe-client.json'] = runtime.dump(probe)
        # Native SMART/FULL checks use temporary files, never user profiles.
        with tempfile.TemporaryDirectory(prefix='profile-check-', dir=ROOT) as directory:
            for full in (False, True):
                path = Path(directory) / ('full.json' if full else 'smart.json')
                payload = runtime.dump(runtime.profile(outbound, 'universal', full))
                require(len(payload) <= 8192, 'CLIENT_PROFILE_SIZE_LIMIT')
                runtime.atomic(path, payload)
                runtime.run([runtime.CODE / 'bin/sing-box', 'check', '-c', path], 'CLIENT_NATIVE_CONFIG_FAILED')
    expected = {str(path): hashlib.sha256(body).hexdigest() for path, body in outputs.items()}
    require(not state['private_files'] or state['private_files'] == expected, 'RESUME_PRIVATE_CONFIG_CHANGED')
    state['private_files'] = expected
    # Checkpoint before the first output: interruptions cannot generate a second identity.
    runtime.atomic(STATE, runtime.dump(state))
    for path, body in outputs.items():
        if path.exists() or path.is_symlink():
            require(not path.is_symlink() and runtime.digest(path) == expected[str(path)]
                    and path.stat().st_uid == 0 and stat.S_IMODE(path.stat().st_mode) == 0o600,
                    'RESUME_PRIVATE_CONFIG_CHANGED')
        else:
            runtime.atomic(path, body)
        if path.name not in ('settings.json', 'xray.json', 'devices.json'):
            runtime.run([runtime.CODE / 'bin/sing-box', 'check', '-c', path], 'CLIENT_NATIVE_CONFIG_FAILED')
    runtime.run([runtime.CODE / 'bin/xray', 'run', '-test', '-config', runtime.ETC / 'xray.json'], 'XRAY_NATIVE_CONFIG_FAILED')


def initial_generation(runtime):
    s = runtime.modules()
    with runtime.lock():
        runtime.cleanup()
        runtime.recover(s)
        runtime.cleanup()
        with runtime.generation_work() as work:
            if (runtime.DATA / 'current').is_symlink():
                _, manifest = runtime.active()
                manifest = runtime.reuse((runtime.DATA / 'current').resolve(), manifest, work)
                old = runtime.record((runtime.DATA / 'current').resolve() / 'manifest.json')
                values, snapshots = runtime.personal(s)
                manifest.update(personal=values, personal_sha256=snapshots, ip=old['ip'])
                body = runtime.raw_file((runtime.DATA / 'current').resolve() / 'proxy-ipv4.json')
            else:
                manifest = runtime.make_full(s, work)
                values, snapshots = runtime.personal(s)
                body, ip_info = runtime.fetch_ips(s)
                manifest.update(personal=values, personal_sha256=snapshots, ip=ip_info)
            body, manifest['ip'] = runtime.combined_ips(manifest['ip'])
            gid = grp.getgrnam(runtime.GROUP).gr_gid
            runtime.atomic(work / 'proxy-ipv4.json', body, 0o640, gid)
            runtime.atomic(work / 'personal-direct-domains.json', runtime.direct_body(values['direct']), 0o640, gid)
            manifest['runtime'] = s.personal.runtime_check(s, s.core, s.pilot, work, manifest, values,
                                                          runtime.base_config(s, Path(manifest['assets_source'])))
            result = runtime.activate(s, work, manifest, initial=not (runtime.DATA / 'current').is_symlink())
            runtime.trim(work)
            return result


def publish_initial_state(source, destination):
    """Atomically publish a directory without replacing even an empty target."""
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == 'linux':
        rename = libc.renameat2
        rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
        rename.restype = ctypes.c_int
        result = rename(-100, os.fsencode(source), -100, os.fsencode(destination), 1)  # RENAME_NOREPLACE
    elif sys.platform == 'darwin':  # Local filesystem regression tests only.
        rename = libc.renamex_np
        rename.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
        rename.restype = ctypes.c_int
        result = rename(os.fsencode(source), os.fsencode(destination), 4)  # RENAME_EXCL
    else:
        raise InstallError('ROOT_LINUX_REQUIRED')
    if result != 0:
        raise InstallError('INITIAL_STATE_PUBLICATION_REFUSED')
    fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def initialize_state(runtime, address, expected_files):
    # No managed data (especially identity.json) may precede the first journal.
    # Unknown directories are preserved and refused, even when they are empty.
    for path in (PROJECT / 'state', runtime.CODE, runtime.ETC, runtime.DATA,
                 PROJECT / 'cache', PROFILE_ROOT, CLI):
        require(not path.exists() and not path.is_symlink(), 'INITIAL_CHECKPOINT_REQUIRED')
    state = {'status': 'installing', 'server_ip': address, 'package_files': expected_files,
             'binaries': {}, 'units': {}, 'private_files': {}}
    # The only pre-checkpoint files live in this private, unpublished staging
    # directory. A killed process may leave it behind; it is never adopted.
    with tempfile.TemporaryDirectory(prefix='.vpn-initialize-', dir=PROJECT) as directory:
        staged_state = Path(directory) / 'state'
        staged_state.mkdir(mode=0o700)
        staged_root = staged_state / 'install'
        staged_root.mkdir(mode=0o700)
        runtime.atomic(staged_root / STATE.name, runtime.dump(state))
        fd = os.open(staged_state, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        publish_initial_state(staged_state, PROJECT / 'state')
    return state


def install(folder, address, resume):
    runtime = load_runtime(folder)
    # With no published state, --resume must pass every clean-host check before
    # starting again. It must not silently generate keys over existing data.
    published = (PROJECT / 'state').exists() or (PROJECT / 'state').is_symlink()
    host_audit(runtime, resume and published)
    ip = ipaddress.IPv4Address(address)
    require(ip.is_global, 'PUBLIC_IPV4_REQUIRED')
    expected_files = runtime.record(folder / 'code-manifest.json')['files']
    for name, checksum in expected_files.items():
        require(Path(name).name == name and runtime.digest(folder / name) == checksum, 'PACKAGE_CODE_CHANGED')
    if resume and published:
        require(all(path.is_dir() and not path.is_symlink() and path.stat().st_uid == 0
                    and not path.stat().st_mode & 0o077 for path in (PROJECT / 'state', ROOT)),
                'PRIVATE_INSTALL_STATE_REQUIRED')
        require(STATE.is_file() and not STATE.is_symlink(), 'INITIAL_CHECKPOINT_REQUIRED')
        state = runtime.record(STATE)
        require(state['status'] in ('installing', 'failed') and state['server_ip'] == address
                and state['package_files'] == expected_files, 'RESUME_INSTALLATION_MISMATCH')
    else:
        state = initialize_state(runtime, address, expected_files)
    # Separate deployment lock: policy workers have their own shared lock.
    fd = os.open(ROOT / 'install.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    import fcntl
    with os.fdopen(fd, 'r+b') as deploy_lock:
        fcntl.flock(deploy_lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        runtime.report('install', status='starting', versions=runtime.PINNED_VERSIONS)
        try:
            try:
                account = pwd.getpwnam(runtime.GROUP)
            except KeyError:
                runtime.run(['useradd', '--system', '--no-create-home', '--home-dir', '/nonexistent',
                             '--shell', '/usr/sbin/nologin', runtime.GROUP], 'POLICY_USER_CREATE_FAILED')
                account = pwd.getpwnam(runtime.GROUP)
            prepare_service_directories(runtime, account, resume)
            for name, checksum in expected_files.items():
                destination = runtime.CODE / name
                if destination.exists():
                    require(runtime.digest(destination) == checksum, 'RESUME_INSTALLED_CODE_CHANGED')
                else:
                    runtime.atomic(destination, (folder / name).read_bytes(), 0o644)
            runtime.atomic(runtime.CODE / 'code-manifest.json', runtime.dump({'files': expected_files}), 0o644)
            if CLI.exists() or CLI.is_symlink():
                require(not CLI.is_symlink() and CLI.read_bytes() == CLI_BODY, 'RESUME_CLI_CHANGED')
            else:
                runtime.atomic(CLI, CLI_BODY, 0o755)
            create_rule_files(runtime)
            if not (runtime.DATA / 'update.lock').exists():
                runtime.atomic(runtime.DATA / 'update.lock', b'')
            for name, item in ARTIFACTS.items():
                path = runtime.CODE / 'bin' / name
                if name in state['binaries']:
                    require(runtime.digest(path) == state['binaries'][name], 'RESUME_BINARY_CHANGED')
                else:
                    state['binaries'][name] = download_binary(runtime, name, item)
                    runtime.atomic(STATE, runtime.dump(state))
            runtime.run([runtime.CODE / 'bin/sing-box', 'version'], 'SINGBOX_BINARY_FAILED')
            create_transport(runtime, state)
            for name, text in units(runtime).items():
                path, payload = UNIT_ROOT / name, text.encode()
                checksum = hashlib.sha256(payload).hexdigest()
                if path.exists():
                    require(state['units'].get(name) == runtime.digest(path) == checksum, 'RESUME_UNIT_CHANGED')
                else:
                    # Record ownership before creating the unit, for interruption recovery.
                    state['units'][name] = checksum
                    runtime.atomic(STATE, runtime.dump(state))
                    runtime.atomic(path, payload, 0o644)
            runtime.run(['systemd-analyze', 'verify', *[UNIT_ROOT / n for n in units(runtime)]], 'SYSTEMD_UNIT_VALIDATION_FAILED')
            runtime.run(['systemctl', 'daemon-reload'], 'SYSTEMD_RELOAD_FAILED')
            runtime.run(['systemctl', 'start', 'vpn-stack-http.service', 'vpn-stack-xray.service'], 'TRANSPORT_SERVICE_START_FAILED')
            result = initial_generation(runtime)
            enable = ('vpn-stack-dns.service', 'vpn-stack-http.service', 'vpn-stack-xray.service',
                      'vpn-stack-daily.timer', 'vpn-stack-ip.timer', 'vpn-stack-personal.service', 'vpn-stack-personal.path')
            runtime.run(['systemctl', 'enable', '--now', *enable], 'BOOT_UNITS_ENABLE_FAILED', timeout=60)
            state.update(status='installed', policy=result, installed_utc=datetime_utc())
            runtime.atomic(STATE, runtime.dump(state))
            runtime.report('install', status='installed', policy=result, profiles=str(PROFILE_ROOT), rules=str(runtime.ETC),
                           rule_files=[str(runtime.ETC / name) for name in (*runtime.FILES.values(), runtime.IP_FILE)],
                           DIRECT_interval='5m', IP_interval='1h', domain_lists_on_VPS=True,
                           device_connections_tested=False, firewall_changed=False)
            print('VPN_STACK_INSTALL_OK', flush=True)
        except BaseException:
            # Stop only units whose bytes still match this installation's journal.
            for name, checksum in state['units'].items():
                path = UNIT_ROOT / name
                if path.is_file() and not path.is_symlink() and runtime.digest(path) == checksum:
                    subprocess.run(['systemctl', 'disable', '--now', name], capture_output=True, timeout=60)
            state['status'] = 'failed'
            runtime.atomic(STATE, runtime.dump(state))
            raise


def datetime_utc():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def main(folder=None, project=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('audit', 'install', 'upgrade'))
    parser.add_argument('--server-ip')
    parser.add_argument('--resume', action='store_true')
    parser.add_argument('--recover', action='store_true')
    args = parser.parse_args()
    if args.action == 'upgrade':
        require(not args.server_ip and not args.resume, 'UPGRADE_ARGUMENTS_INVALID')
    else:
        require(not args.recover and (args.action != 'audit' or not args.server_ip and not args.resume),
                'INSTALL_ARGUMENTS_INVALID')
    folder = folder or Path(__file__).resolve().parent
    configure_project(project or Path(__file__).resolve().parent.parent)
    runtime = load_runtime(folder)
    os.umask(0o077)
    os.environ.update(LC_ALL='C', TZ='UTC')
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(InstallError('DOWNLOAD_TIMEOUT')))
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: (_ for _ in ()).throw(InstallError('INTERRUPTED')))
    if args.action == 'audit':
        runtime.report('audit', **host_audit(runtime))
    elif args.action == 'upgrade':
        spec = importlib.util.spec_from_file_location('vpn_stack_upgrade', folder / 'vpn-stack-upgrade.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.upgrade(folder, SimpleNamespace(**globals()), args.recover)
    else:
        require(args.server_ip, 'SERVER_IP_ARGUMENT_REQUIRED')
        install(folder, args.server_ip, args.resume)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        value = {'status': 'failed', 'error_type': type(error).__name__}
        code = str(error)
        if code and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789' for c in code):
            value['code'] = code
        print('VPN_STACK_REPORT=' + json.dumps(dict(action='install', **value)), flush=True)
        sys.exit(1)
