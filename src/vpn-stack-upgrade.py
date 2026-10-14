#!/usr/bin/env python3
"""Transactional code/unit upgrade; transport identities and profiles are preserved."""
from contextlib import contextmanager
import array
import fcntl
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import shutil
import signal
import select
import socket
import stat
import struct
import sys
import tempfile
import time
from types import SimpleNamespace

BOOT_UNIT = 'vpn-stack-upgrade-recover.service'
GATE = b'[Unit]\nRequires=vpn-stack-upgrade-recover.service\nAfter=vpn-stack-upgrade-recover.service\n'
PENDING = ('prepared', 'applying', 'rolling_back')
CORE = ('vpn-stack-dns.service', 'vpn-stack-http.service', 'vpn-stack-xray.service')
WORKERS = ('vpn-stack-daily.service', 'vpn-stack-ip.service', 'vpn-stack-personal.service')
TRIGGERS = ('vpn-stack-daily.timer', 'vpn-stack-ip.timer', 'vpn-stack-personal.path')
SERVICES = (*TRIGGERS, *WORKERS, 'vpn-stack-device-recover.service', *CORE)
FINISH_UNIT = 'vpn-stack-upgrade-services.service'
GUARDIAN_UNIT = 'vpn-stack-upgrade-guardian.service'
HOLD_UNIT = 'vpn-stack-upgrade-hold.target'
LOADER = 'recover-v2.py'
# Exact loader shipped in a62ad73; migration refuses locally edited infrastructure.
LEGACY_BOOTSTRAP = rb'''#!/usr/bin/python3
"""Recover an interrupted upgrade without importing the replaceable live lib/."""
import hashlib, importlib.util, json, os, re, stat, sys
from pathlib import Path
sys.dont_write_bytecode = True
root = Path(__file__).resolve().parent
def read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        assert stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_size <= 1048576
        data = stream.read(1048577)
        assert len(data) == info.st_size
        return data
path = root / 'transaction.json'
if not path.exists():
    sys.exit(0)
journal = json.loads(read(path))
if journal['status'] in ('committed', 'rolled_back'):
    sys.exit(0)
assert journal['status'] in ('prepared', 'applying', 'rolling_back')
assert re.fullmatch(r'up-[a-f0-9]{16}', journal['transaction'])
package = root / journal['transaction'] / 'package'
for directory in (root, package.parent, package):
    info = directory.lstat()
    assert stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_mode & 0o077 == 0
for name, checksum in journal['target_files'].items():
    assert Path(name).name == name and name.endswith('.py')
    assert hashlib.sha256(read(package / name)).hexdigest() == checksum
spec = importlib.util.spec_from_file_location('vpn_upgrade_recovery', package / 'vpn-stack-upgrade.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.boot_recover(root.parent.parent, package)
'''
PREVIOUS_BOOTSTRAP = b'''#!/usr/bin/python3
"""Recovery engine is durable and independent of the replaceable live lib/."""
import hashlib, importlib.util, json, os, re, stat, subprocess, sys
from pathlib import Path
sys.dont_write_bytecode = True
root = Path(__file__).resolve().parent
def read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        assert stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_size <= 1048576
        data = stream.read(1048577)
        assert len(data) == info.st_size
        return data
path = root / 'transaction.json'
fenced = (root.parent.parent / 'data/update.lock').is_symlink()
if '--services' not in sys.argv:
    if not path.exists() and not fenced:
        sys.exit(0)
    if path.exists():
        journal = json.loads(read(path))
        if journal.get('status') in ('committed', 'rolled_back') and not fenced:
            if not journal.get('services_restored', False):
                subprocess.run(['systemctl', '--no-block', 'start', 'vpn-stack-upgrade-services.service'], check=True)
            sys.exit(0)
pointer = json.loads(read(root / 'engine.json'))['directory']
assert re.fullmatch(r'engine-[a-f0-9]{64}', pointer)
package = root / pointer
for directory in (root, package):
    info = directory.lstat()
    assert stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_mode & 0o077 == 0
raw_manifest = read(package / 'code-manifest.json')
assert hashlib.sha256(raw_manifest).hexdigest() == pointer.removeprefix('engine-')
manifest = json.loads(raw_manifest)['files']
for name, checksum in manifest.items():
    assert Path(name).name == name and name.endswith('.py')
    assert hashlib.sha256(read(package / name)).hexdigest() == checksum
spec = importlib.util.spec_from_file_location('vpn_upgrade_recovery', package / 'vpn-stack-upgrade.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.boot_recover(root.parent.parent, package, services='--services' in sys.argv)
'''
FDSTORE_BOOTSTRAP = PREVIOUS_BOOTSTRAP.replace(
    b"fenced = (root.parent.parent / 'data/update.lock').is_symlink()",
    b"fenced = (root.parent.parent / 'data/update.lock').is_symlink() or subprocess.run(\n"
    b"    ['systemctl', 'show', 'vpn-stack-upgrade-guardian.service', '--property=NFileDescriptorStore', '--value'],\n"
    b"    capture_output=True, check=True).stdout.strip() == b'1'").replace(
    b"if '--services' not in sys.argv:",
    b"if '--services' not in sys.argv and '--guardian' not in sys.argv:").replace(
    b"module.boot_recover(root.parent.parent, package, services='--services' in sys.argv)",
    b"if '--guardian' in sys.argv:\n    module.guardian(root.parent.parent, package)\nelse:\n    module.boot_recover(root.parent.parent, package, services='--services' in sys.argv)")
VERIFIED_BOOTSTRAP = FDSTORE_BOOTSTRAP.replace(
    b"if not journal.get('services_restored', False):",
    b"if not journal.get('services_restored', False) or not journal.get('service_verification'):")
BOOTSTRAP = VERIFIED_BOOTSTRAP.replace(
    b"assert Path(name).name == name and name.endswith('.py')",
    b"assert Path(name).name == name and (name.endswith('.py') or name in "
    b"('include-hosts.txt', 'exclude-hosts.txt', 'include-adblock-hosts.txt', 'exclude-adblock-hosts.txt'))")



def require(value, code):
    if not value:
        raise UpgradeError(code)


class UpgradeError(Exception):
    pass


def checksum(raw):
    return hashlib.sha256(raw).hexdigest()


def private_directory(path, create=True):
    require(not path.is_symlink(), 'UPGRADE_DIRECTORY_SYMLINK_REFUSED')
    if create:
        path.mkdir(mode=0o700, exist_ok=True)
    require(path.is_dir(), 'UPGRADE_DIRECTORY_REQUIRED')
    info = path.stat()
    require(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700, 'PRIVATE_UPGRADE_DIRECTORY_REQUIRED')


@contextmanager
def deploy_lock(i, wait=False):
    for path in (i.PROJECT / 'state', i.ROOT):
        require(path.is_dir() and not path.is_symlink() and path.stat().st_uid == 0
                and path.stat().st_mode & 0o077 == 0, 'PRIVATE_INSTALL_STATE_REQUIRED')
    fd = os.open(i.ROOT / 'install.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'r+b') as stream:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX | (0 if wait else fcntl.LOCK_NB))
        yield


def bundle(r, folder, expected):
    require(folder.is_dir() and not folder.is_symlink() and folder.stat().st_uid == 0
            and folder.stat().st_mode & 0o022 == 0, 'UPGRADE_LIBRARY_DIRECTORY_INVALID')
    require(isinstance(expected, dict) and 1 <= len(expected) <= 64, 'UPGRADE_MANIFEST_INVALID')
    require(r.record(folder / 'code-manifest.json') == {'files': expected}, 'UPGRADE_MANIFEST_CHANGED')
    for name, digest in expected.items():
        require(r.package_member(name) and
                re.fullmatch(r'[a-f0-9]{64}', digest) is not None, 'UPGRADE_MANIFEST_INVALID')
        require(checksum(r.raw_file(folder / name, 1048576)) == digest, 'UPGRADE_CODE_CHANGED')


def binaries(r, folder, expected):
    directory = folder / 'bin'
    require(directory.is_dir() and not directory.is_symlink() and directory.stat().st_uid == 0
            and directory.stat().st_mode & 0o022 == 0, 'UPGRADE_BINARY_DIRECTORY_INVALID')
    require(set(expected) == {'mihomo', 'sing-box', 'xray'}, 'UPGRADE_BINARIES_REQUIRED')
    for name, digest in expected.items():
        require(r.digest(folder / 'bin' / name) == digest, 'UPGRADE_BINARY_CHANGED')


def sync_rename(source, destination):
    require(not destination.exists() and not destination.is_symlink(), 'UPGRADE_RENAME_TARGET_EXISTS')
    os.rename(source, destination)
    for parent in {source.parent, destination.parent}:
        fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def boot_unit(project, legacy=False, previous=False):
    # Match the installer's literal ExecStart convention (no $ expansion).
    loader = 'recover.py' if legacy or previous else LOADER
    path = str(project / 'state/upgrade' / loader).replace('\\', '\\\\').replace('"', '\\"').replace('\t', '\\t')
    ordering = '' if legacy else ('DefaultDependencies=no\nAfter=local-fs.target\n'
        'RequiresMountsFor="' + path.removesuffix('/state/upgrade/' + loader) + '"\n'
        'Before=shutdown.target\nConflicts=shutdown.target\n')
    if not legacy and not previous:
        ordering += 'Wants=' + HOLD_UNIT + '\n'
    return ('[Unit]\nDescription=Recover interrupted VPN code upgrade\n' + ordering +
            '[Service]\nType=oneshot\nRemainAfterExit=yes\n'
            'ExecStart=:/usr/bin/python3 "' + path + '"\n'
            'UMask=0077\nMemoryMax=128M\nTasksMax=16\nTimeoutStartSec=120\n').encode()


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def sync_tree(path):
    # Atomic file writes sync files and their containing directories, but not
    # the ancestors which name newly created directories or hard links.
    for directory, children, files in os.walk(path, topdown=False):
        for name in files:
            fd = os.open(Path(directory) / name, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        sync_directory(directory)
    sync_directory(path.parent)


def finish_unit(project, previous=False):
    return boot_unit(project, legacy=True).replace(b'Description=Recover interrupted VPN code upgrade',
        b'Description=Restore VPN services after upgrade\nAfter=' + BOOT_UNIT.encode()).replace(
        b'RemainAfterExit=yes\n', b'').replace(b'recover.py"',
            (b'recover.py' if previous else LOADER.encode()) + b'" --services')


def guardian_unit(project):
    return boot_unit(project).replace(('Wants=' + HOLD_UNIT + '\n').encode(), b'').replace(b'Description=Recover interrupted VPN code upgrade',
        b'Description=Hold VPN policy lock and recover a lost upgrade\nStartLimitIntervalSec=0').replace(
        b'Type=oneshot\nRemainAfterExit=yes\n',
        b'Type=notify\nNotifyAccess=main\nRestart=on-failure\nRestartSec=1\n'
        b'FileDescriptorStoreMax=1\nFileDescriptorStorePreserve=yes\n').replace(
        (LOADER + '"').encode(), (LOADER + '" --guardian').encode())


def hold_unit():
    # An active target pins the guardian unit in PID 1 even if BOTH the boot
    # recovery oneshot and guardian process are stopped during recovery.
    return ('[Unit]\nDescription=Retain VPN upgrade policy descriptor\n'
            'DefaultDependencies=no\nAfter=local-fs.target\nBefore=shutdown.target\n'
            'Conflicts=shutdown.target\nWants=' + GUARDIAN_UNIT + '\n').encode()


def infrastructure_variants(i, path, raw):
    if path.name == 'recover.py':
        return (raw, VERIFIED_BOOTSTRAP, FDSTORE_BOOTSTRAP, PREVIOUS_BOOTSTRAP, LEGACY_BOOTSTRAP)
    if path.name == LOADER:
        return (raw, VERIFIED_BOOTSTRAP, FDSTORE_BOOTSTRAP)
    if path.name == BOOT_UNIT:
        return (raw, boot_unit(i.PROJECT, legacy=True), boot_unit(i.PROJECT, previous=True))
    if path.name == FINISH_UNIT:
        return (raw, finish_unit(i.PROJECT, previous=True))
    return (raw,)


def infrastructure(i, r, units, folder, activate=True, policy_fd=None):
    root = i.PROJECT / 'state/upgrade'
    private_directory(root)
    # Validate every existing output before changing loaders, selection or units.
    # Cached systemd commands may still refer to recover.py until daemon-reload.
    loaders = {root / LOADER: BOOTSTRAP, root / 'recover.py': BOOTSTRAP}
    outputs = {**loaders,
               i.UNIT_ROOT / FINISH_UNIT: finish_unit(i.PROJECT),
               i.UNIT_ROOT / GUARDIAN_UNIT: guardian_unit(i.PROJECT),
               i.UNIT_ROOT / HOLD_UNIT: hold_unit(),
               i.UNIT_ROOT / BOOT_UNIT: boot_unit(i.PROJECT)}
    for name in units:
        require(re.fullmatch(r'vpn-stack-[a-z-]+\.(service|timer|path)', name) is not None, 'UPGRADE_UNIT_NAME_INVALID')
        if name not in (BOOT_UNIT, FINISH_UNIT, GUARDIAN_UNIT):
            directory = i.UNIT_ROOT / (name + '.d')
            require(not directory.is_symlink(), 'UPGRADE_DROPIN_SYMLINK_REFUSED')
            directory.mkdir(mode=0o755, exist_ok=True)
            outputs[directory / '20-vpn-upgrade-recovery.conf'] = GATE
    for path, raw in outputs.items():
        if path.exists() or path.is_symlink():
            allowed = infrastructure_variants(i, path, raw)
            require(r.raw_file(path, 1048576) in allowed, 'UPGRADE_RECOVERY_INFRASTRUCTURE_CHANGED')
    expected = r.record(folder / 'code-manifest.json')['files']
    engine = root / ('engine-' + checksum(r.raw_file(folder / 'code-manifest.json', 1048576)))
    if engine.exists() or engine.is_symlink():
        bundle(r, engine, expected)
    else:
        staged = Path(tempfile.mkdtemp(prefix='.engine-', dir=root))
        for name in (*expected, 'code-manifest.json'):
            r.atomic(staged / name, r.raw_file(folder / name, 1048576))
        bundle(r, staged, expected)
        sync_tree(staged)
        sync_rename(staged, engine)
    pointer = root / 'engine.json'
    if pointer.exists() or pointer.is_symlink():
        prior = r.record(pointer)['directory']
        require(re.fullmatch(r'engine-[a-f0-9]{64}', prior) is not None, 'UPGRADE_RECOVERY_ENGINE_INVALID')
        prior_path = root / prior
        raw = r.raw_file(prior_path / 'code-manifest.json', 1048576)
        require(checksum(raw) == prior.removeprefix('engine-'), 'UPGRADE_RECOVERY_ENGINE_CHANGED')
        bundle(r, prior_path, r.record(prior_path / 'code-manifest.json')['files'])
    else:
        # The original legacy loader reads the transaction package directly and
        # has no engine pointer. Seed a complete engine before replacing it;
        # it ignores this pointer, while the first new loader can already use it.
        # Pointer-based historical loaders must never lack their selected engine.
        require(all(not path.exists() or r.raw_file(path, 1048576) == LEGACY_BOOTSTRAP
                    for path in loaders), 'UPGRADE_RECOVERY_ENGINE_REQUIRED')
        r.atomic(pointer, r.dump({'directory': engine.name}))
    # New loaders support BOTH Python-only historical engines and the new data
    # files. Sync both entry points before selecting an engine an old loader
    # cannot read. Until then, remaining old loaders still use the old engine.
    for path, raw in loaders.items():
        if not path.exists() or r.raw_file(path, 1048576) != raw:
            r.atomic(path, raw, 0o600 if path.name == 'recover.py' else 0o644)
        sync_directory(path.parent)
    sync_directory(root.parent)
    r.atomic(pointer, r.dump({'directory': engine.name}))
    # Only now may units change, including commands cached at either loader path.
    for path, raw in outputs.items():
        if path in loaders:
            continue
        if not path.exists() or r.raw_file(path, 1048576) != raw:
            r.atomic(path, raw, 0o644)
        sync_directory(path.parent)
    sync_directory(root.parent)
    sync_directory(i.UNIT_ROOT)
    r.run(['systemd-analyze', 'verify', i.UNIT_ROOT / BOOT_UNIT, i.UNIT_ROOT / FINISH_UNIT], 'UPGRADE_RECOVERY_UNIT_INVALID')
    r.run(['systemctl', 'daemon-reload'], 'UPGRADE_SYSTEMD_RELOAD_FAILED')
    if activate:
        r.run(['systemctl', 'start', BOOT_UNIT], 'UPGRADE_RECOVERY_GUARD_START_FAILED')
    if policy_fd is not None:
        arm_guardian(i, r, policy_fd)


def fence_path(i):
    return i.PROJECT / 'state/upgrade/policy.lock'


def notify(message, fd=None):
    """sd_notify with a reception barrier, not merely a successful send()."""
    address = os.environ['NOTIFY_SOCKET']
    if address.startswith('@'):
        address = '\0' + address[1:]
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as channel:
        channel.connect(address)
        rights = [] if fd is None else [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [fd]))]
        channel.sendmsg([message], rights)
        reader, writer = os.pipe()
        try:
            channel.sendmsg([b'BARRIER=1'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [writer]))])
            os.close(writer)
            writer = None
            require(select.select([reader], [], [], 10)[0] and os.read(reader, 1) == b'',
                    'UPGRADE_GUARDIAN_NOTIFY_TIMEOUT')
        finally:
            os.close(reader)
            if writer is not None:
                os.close(writer)


def guardian_stored(r):
    return r.run(['systemctl', 'show', GUARDIAN_UNIT, '--property=NFileDescriptorStore', '--value'],
                 'UPGRADE_GUARDIAN_STATE_FAILED').strip() == b'1'


def wait_guardian(r):
    # No deployment lock here: the guardian needs that lock to roll back.
    if not guardian_stored(r):
        return
    r.run(['systemctl', '--no-block', 'restart', GUARDIAN_UNIT], 'UPGRADE_GUARDIAN_START_FAILED')
    deadline = time.monotonic() + 120
    while guardian_stored(r):
        require(time.monotonic() < deadline, 'UPGRADE_GUARDIAN_RECOVERY_REQUIRED')
        time.sleep(.1)


def arm_guardian(i, r, fd):
    if getattr(r, '_UPGRADE_GUARDIAN_ARMED', False):
        require(guardian_stored(r), 'UPGRADE_GUARDIAN_STORE_FAILED')
        return
    require(not guardian_stored(r), 'UPGRADE_GUARDIAN_ALREADY_ARMED')
    preserve = r.run(['systemctl', 'show', GUARDIAN_UNIT, '--property=FileDescriptorStorePreserve', '--value'],
                     'UPGRADE_GUARDIAN_STATE_FAILED')
    require(preserve.strip() == b'yes', 'UPGRADE_GUARDIAN_FDSTORE_UNSUPPORTED')
    r.run(['systemctl', 'start', HOLD_UNIT], 'UPGRADE_GUARDIAN_HOLD_FAILED')
    r.run(['systemctl', 'stop', GUARDIAN_UNIT], 'UPGRADE_GUARDIAN_STOP_FAILED')
    root = i.PROJECT / 'state/upgrade'
    path = root / 'guardian.sock'
    if path.exists() or path.is_symlink():
        info = path.lstat()
        require(stat.S_ISSOCK(info.st_mode) and info.st_uid == 0, 'UPGRADE_GUARDIAN_SOCKET_CHANGED')
        path.unlink()
    # /proc/self/fd keeps Unix socket addresses short for long project roots.
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.settimeout(30)
            server.bind('/proc/self/fd/' + str(directory) + '/guardian.sock')
            server.listen(1)
            r.run(['systemctl', '--no-block', 'start', GUARDIAN_UNIT], 'UPGRADE_GUARDIAN_START_FAILED')
            with server.accept()[0] as peer:
                peer.settimeout(30)
                pid, uid, _ = struct.unpack('3i', peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                main = r.run(['systemctl', 'show', GUARDIAN_UNIT, '--property=MainPID', '--value'],
                             'UPGRADE_GUARDIAN_STATE_FAILED')
                require(uid == 0 and str(pid).encode() == main.strip(), 'UPGRADE_GUARDIAN_PEER_INVALID')
                peer.sendmsg([b'L'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [fd]))])
                require(peer.recv(1) == b'1' and guardian_stored(r), 'UPGRADE_GUARDIAN_STORE_FAILED')
                r._UPGRADE_GUARDIAN_ARMED = True
    finally:
        os.close(directory)
        if path.exists():
            path.unlink()


def guardian(project, package):
    """PID 1 retains the SAME flock description during guardian death/restart."""
    i, r = recovery_modules(project, package)
    inherited = int(os.environ.get('LISTEN_PID', '0')) == os.getpid()
    if inherited and int(os.environ.get('LISTEN_FDS', '0')) == 1:
        fd = 3
    else:
        root = project / 'state/upgrade'
        if not (root / 'guardian.sock').exists():
            # Fresh boot: no old process/descriptor survives PID 1. The boot
            # recovery unit acquires the normal inode lock before core starts.
            notify(b'READY=1')
            return
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
                peer.settimeout(30)
                try:
                    peer.connect('/proc/self/fd/' + str(directory) + '/guardian.sock')
                except (FileNotFoundError, ConnectionRefusedError):
                    # A reboot can leave the socket pathname, but no old
                    # processes or flock descriptions. Boot recovery owns it.
                    notify(b'READY=1')
                    return
                _, uid, _ = struct.unpack('3i', peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                require(uid == 0, 'UPGRADE_GUARDIAN_PEER_INVALID')
                message, rights, flags, _ = peer.recvmsg(1, socket.CMSG_SPACE(array.array('i').itemsize))
                require(message == b'L' and not flags and len(rights) == 1 and
                        rights[0][:2] == (socket.SOL_SOCKET, socket.SCM_RIGHTS), 'UPGRADE_GUARDIAN_FD_INVALID')
                descriptors = array.array('i')
                descriptors.frombytes(rights[0][2])
                require(len(descriptors) == 1, 'UPGRADE_GUARDIAN_FD_INVALID')
                fd = descriptors[0]
                notify(b'FDSTORE=1\nFDNAME=policy\nFDPOLL=0', fd)
                require(guardian_stored(r), 'UPGRADE_GUARDIAN_STORE_FAILED')
                notify(b'READY=1')
                peer.sendall(b'1')
        finally:
            os.close(directory)
    info = os.fstat(fd)
    path = fence_path(i) if (r.DATA / 'update.lock').is_symlink() else r.DATA / 'update.lock'
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and os.path.samestat(info, path.stat()),
            'UPGRADE_GUARDIAN_INODE_CHANGED')
    notify(b'READY=1')
    # Closing another reference does not drop flock; never LOCK_UN on error.
    # Nonblocking retries keep the deployment lock out of the handoff and avoid
    # deadlock with both the updater and externally requested recovery.
    while True:
        try:
            with deploy_lock(i):
                r._UPGRADE_ALLOWED = True
                # A running guardian can be awaited by the boot guard while
                # core start jobs wait for that guard. Do not cancel/wait on
                # those jobs here: the finish unit restarts after the guard.
                recover(i, r, defer_stop=True)
                unfence(i, r)
                fcntl.flock(fd, fcntl.LOCK_UN)
                r.run(['systemctl', '--no-block', 'start', FINISH_UNIT], 'UPGRADE_SERVICE_RECOVERY_QUEUE_FAILED')
            notify(b'FDSTOREREMOVE=1\nFDNAME=policy')
            r.run(['systemctl', 'stop', HOLD_UNIT], 'UPGRADE_GUARDIAN_HOLD_FAILED')
            return
        except BlockingIOError:
            time.sleep(.1)


@contextmanager
def policy_lock(i, r):
    path = r.DATA / 'update.lock'
    if path.is_symlink():
        require(os.readlink(path) == str(fence_path(i).parent), 'UPGRADE_POLICY_FENCE_CHANGED')
        path = fence_path(i)
    require(path.is_file() and not path.is_symlink() and path.stat().st_uid == 0,
            'UPGRADE_POLICY_LOCK_REQUIRED')
    with path.open('r') as stream:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        previous = getattr(r, '_UPGRADE_ALLOWED', False)
        r._UPGRADE_ALLOWED = True
        try:
            yield stream.fileno()
        finally:
            r._UPGRADE_ALLOWED = previous
            if getattr(r, '_UPGRADE_GUARDIAN_ARMED', False):
                journal = journal_path(i)
                if not journal.exists() or r.record(journal).get('status') in ('committed', 'rolled_back'):
                    unfence(i, r)
                    fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
                    r.run(['systemctl', 'stop', GUARDIAN_UNIT], 'UPGRADE_GUARDIAN_STOP_FAILED')
                    r.run(['systemctl', 'clean', '--what=fdstore', GUARDIAN_UNIT], 'UPGRADE_GUARDIAN_CLEAN_FAILED')
                    r.run(['systemctl', 'stop', HOLD_UNIT], 'UPGRADE_GUARDIAN_HOLD_FAILED')
                    r._UPGRADE_GUARDIAN_ARMED = False


def fence(i, r):
    # Old runtimes refuse symlinked update.lock; pointing at a directory also
    # refuses opens which race the old pre-open is_symlink check. Preserve its inode so
    # any worker which opened it before publication still contends on our flock.
    path, saved = r.DATA / 'update.lock', fence_path(i)
    if saved.exists() or saved.is_symlink():
        require(not saved.is_symlink() and os.path.samestat(saved.stat(), path.stat()), 'UPGRADE_POLICY_FENCE_CHANGED')
    else:
        os.link(path, saved, follow_symlinks=False)
        sync_directory(saved.parent)
    temporary = path.with_name('.upgrade-fence')
    if temporary.is_symlink():
        require(os.readlink(temporary) == str(saved.parent), 'UPGRADE_POLICY_FENCE_CHANGED')
    else:
        require(not temporary.exists(), 'UPGRADE_POLICY_FENCE_CHANGED')
        temporary.symlink_to(saved.parent, target_is_directory=True)
    os.replace(temporary, path)
    sync_directory(path.parent)


def unfence(i, r):
    path, saved = r.DATA / 'update.lock', fence_path(i)
    if not path.is_symlink():
        return
    require(os.readlink(path) == str(saved.parent) and saved.is_file() and not saved.is_symlink()
            and saved.stat().st_uid == 0, 'UPGRADE_POLICY_FENCE_CHANGED')
    temporary = path.with_name('.upgrade-unfence')
    if temporary.exists():
        require(not temporary.is_symlink() and os.path.samestat(temporary.stat(), saved.stat()), 'UPGRADE_POLICY_FENCE_CHANGED')
    else:
        os.link(saved, temporary, follow_symlinks=False)
    os.replace(temporary, path)
    sync_directory(path.parent)


def finish_services(i, r):
    path = journal_path(i)
    if not path.exists():
        unfence(i, r)  # Crash before prepared: no managed state was changed.
        return False
    journal = r.record(path)
    require(journal.get('status') in ('committed', 'rolled_back'), 'UPGRADE_RECOVERY_REQUIRED')
    if services_complete(journal):
        unfence(i, r)  # Crash after final journal, before releasing the fence.
        return False
    # Prior engines marked success without checking the loaded policy. Adopt
    # their terminal journal without replaying any file backups or user inputs.
    if journal.get('services_restored', False):
        journal['services_restored'] = False
        save_journal(i, r, journal)
    # Deployment lock is held, policy lock is released. Device recovery and
    # triggered workers can take it once the files are settled.
    unfence(i, r)
    r.run(['systemctl', 'start', BOOT_UNIT], 'UPGRADE_RECOVERY_GUARD_START_FAILED')
    if journal['status'] == 'rolled_back':
        # Idempotent even if a previous finish process died during restart.
        # BOOT_UNIT has returned; no policy lock is held and dependent jobs
        # cannot deadlock waiting for us to release either prerequisite.
        r.run(['systemctl', 'stop', *TRIGGERS, *WORKERS], 'UPGRADE_WORKERS_STOP_FAILED', timeout=120)
        names = [name for name in CORE if journal['services'].get(name)]
        if names:
            # A lost finish process followed by repeated recovery can exhaust
            # systemd's start burst. This explicit recovery must be able to
            # start the now-restored services instead of retaining that failure.
            r.run(['systemctl', 'reset-failed', *names], 'UPGRADE_SERVICES_RESET_FAILED')
            r.run(['systemctl', 'restart', *names], 'UPGRADE_SERVICES_START_FAILED', timeout=60)
    start(r, journal['services'], triggers=False)
    ready_dns()
    evidence = ready_policy(r)
    names = [name for name in TRIGGERS if journal['services'].get(name)]
    if names:
        r.run(['systemctl', 'start', *names], 'UPGRADE_TRIGGERS_START_FAILED', timeout=60)
    journal['services_restored'] = True
    journal['service_verification'] = evidence
    save_journal(i, r, journal)
    return True


def services_complete(journal):
    return journal.get('services_restored', False) and bool(journal.get('service_verification'))


def service_snapshot(r):
    states = {}
    for name in SERVICES:
        state = r.unit_state(name)
        require(state.get('ActiveState') in ('active', 'inactive', 'failed'), 'UPGRADE_SERVICE_BUSY')
        states[name] = state['ActiveState'] == 'active'
    require(all(states[name] for name in CORE), 'UPGRADE_RUNNING_VPN_REQUIRED')
    require(states['vpn-stack-device-recover.service'], 'UPGRADE_DEVICE_RECOVERY_REQUIRED')
    require(not any(states[name] for name in WORKERS), 'UPGRADE_SERVICE_BUSY')
    return states


def stop(r):
    r.run(['systemctl', 'stop', *TRIGGERS, *WORKERS], 'UPGRADE_WORKERS_STOP_FAILED', timeout=120)
    # The device-recovery oneshot already completed before Xray started. Keep
    # it active: re-running its CLI while holding the policy lock would fail.
    r.run(['systemctl', 'stop', CORE[2], *CORE[:2]],
          'UPGRADE_SERVICES_STOP_FAILED', timeout=60)


def start(r, states, triggers=True):
    names = [name for name in (*CORE[:2], 'vpn-stack-device-recover.service', CORE[2]) if states.get(name)]
    if names:
        r.run(['systemctl', 'start', *names], 'UPGRADE_SERVICES_START_FAILED', timeout=60)
    if triggers:
        names = [name for name in TRIGGERS if states.get(name)]
        if names:
            r.run(['systemctl', 'start', *names], 'UPGRADE_TRIGGERS_START_FAILED', timeout=60)


def ready_dns():
    # Load from the same immutable recovery/target package as this module, never
    # from live lib/. An accepting TCP listener alone does not prove DNS works.
    spec = importlib.util.spec_from_file_location('upgrade_dns_wire', Path(__file__).parent / 'dns-wire.py')
    wire = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(wire)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            wire.lookup(19053, 'api.ipify.org', 'tcp')
            return
        except (OSError, wire.PilotError):
            time.sleep(.1)
    raise UpgradeError('UPGRADE_DNS_NOT_READY')


def ready_policy(r):
    """Verify the restored files AND the real, running backend before success.

    Counts alone cannot distinguish two MRS files with different rules. A
    rollback first restarts the backend from the restored config; active()
    validates that config and every generation checksum. Live DNS/REJECT
    probes then check policy behavior against that saved personal snapshot.
    Never rebuild from current user inputs or write to the cache here.
    """
    source, manifest = r.active()
    # Recovery may restore a historical lib/ lacking newer optional modules.
    # Use the same checksum-verified engine helpers as the recovery command.
    s = policy_modules()
    r.wait_backend(s, manifest['counts'])
    witness = r.record(source / 'witnesses.json')
    controls = ('api.ipify.org', 'checkip.amazonaws.com', 'stun.l.google.com')
    names = sorted(set((*controls,
                        witness['apex'], witness['child'], witness['ads-child'])))
    hits = s.personal.base_matches(source, names)
    checks, rejects = 0, 0
    for name in names:
        kind, reason = s.personal.expected_route(name, hits[name], manifest['personal'])
        for protocol in ('tcp', 'udp'):
            values = policy_dns(s, name, protocol, allow_empty=kind == 'real' and name not in controls)
            if kind == 'fake':
                s.setup.require_fake(values)
            else:
                require(all(s.setup.ipaddress.ip_address(value) not in s.setup.FAKE_POOL for value in values),
                        'UPGRADE_UNEXPECTED_FAKE_IP')
            checks += 1
        if reason == 'ads-reject':
            s.checker.reject_destination(s.wire, 19080, values[0])
            rejects += 1
    # Recheck after the probes: an edit must not be recorded as verified.
    require(r.active()[0] == source, 'UPGRADE_POLICY_CHANGED_DURING_VERIFICATION')
    return {'generation': source.name, 'config_sha256': manifest['config_sha256'],
            'checksums': manifest['checksums'], 'provider_counts': manifest['counts'],
            'DNS_TCP_UDP_checks': checks, 'REJECT_checks': rejects}


def policy_modules():
    result = {}
    for tag, name in (('personal', 'personal-runtime'), ('checker', 'runtime-checker'),
                      ('wire', 'dns-wire'), ('setup', 'transport-probes')):
        spec = importlib.util.spec_from_file_location('upgrade_policy_' + tag, Path(__file__).parent / (name + '.py'))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        result[tag] = module
    return SimpleNamespace(**result)


def policy_dns(s, name, protocol, allow_empty=False):
    # Production direct answers can contain multiple A records or NXDOMAIN
    # for a sampled child. Neither may be mistaken for a fake-IP answer.
    query = s.wire.dns_query(name)
    if protocol == 'tcp':
        with socket.create_connection(('127.0.0.1', 19053), timeout=3) as stream:
            stream.sendall(struct.pack('!H', len(query)) + query)
            response = s.wire.recv_exact(stream, struct.unpack('!H', s.wire.recv_exact(stream, 2))[0])
    else:
        with socket.socket(type=socket.SOCK_DGRAM) as stream:
            stream.settimeout(3)
            stream.connect(('127.0.0.1', 19053))
            stream.send(query)
            response = stream.recv(65535)
    if allow_empty and len(response) >= 12 and response[:2] == query[:2]:
        _, flags, questions, answers, _, _ = struct.unpack('!6H', response[:12])
        if flags & 0x8000 and not flags & 0x0200 and flags & 15 in (0, 3) and questions == 1 and answers == 0:
            question, end = s.wire.read_name(response, 12)
            require(question == name and response[end:end + 4] == b'\x00\x01\x00\x01', 'UPGRADE_DNS_QUESTION_CHANGED')
            return []
    return s.setup.dns_reply_ips(s.wire, query, response)


def save_file(r, transaction, path, after, files):
    exists = path.exists() or path.is_symlink()
    raw = r.raw_file(path, 1048576) if exists else None
    info = path.stat() if exists else None
    name = str(len(files))
    if exists:
        r.atomic(transaction / 'backups' / name, raw)
    files.append({'path': str(path), 'backup': name, 'before': checksum(raw) if exists else None,
                  'after': checksum(after) if after is not None else None,
                  'mode': stat.S_IMODE(info.st_mode) if exists else 0o600,
                  'gid': info.st_gid if exists else 0})


def journal_path(i):
    return i.PROJECT / 'state/upgrade/transaction.json'


def save_journal(i, r, journal):
    r.atomic(journal_path(i), r.dump(journal))


def recovery_plan(i, r, journal):
    require(journal.get('schema') == 1 and journal.get('status') in (*PENDING, 'committed', 'rolled_back'),
            'UPGRADE_JOURNAL_INVALID')
    require(re.fullmatch(r'up-[a-f0-9]{16}', journal.get('transaction', '')) is not None, 'UPGRADE_TRANSACTION_INVALID')
    transaction = i.PROJECT / 'state/upgrade' / journal['transaction']
    for path in (transaction, transaction / 'package', transaction / 'backups'):
        private_directory(path, create=False)
    bundle(r, transaction / 'package', journal['target_files'])
    old = Path(journal['old_generation'])
    require(old.parent == r.DATA / 'generations' and old.name.startswith('gen-')
            and old.is_dir() and not old.is_symlink(), 'UPGRADE_OLD_GENERATION_INVALID')
    allowed = {i.STATE, i.CLI, r.CONFIG, r.DATA / 'transaction.json', r.DATA / 'last-result.json'}
    allowed.update(i.UNIT_ROOT / name for name in journal['unit_names'])
    require(all(re.fullmatch(r'vpn-stack-[a-z-]+\.(service|timer|path)', name)
                for name in journal['unit_names']), 'UPGRADE_UNIT_NAME_INVALID')
    require(len(journal['files']) <= 64 and len({row['path'] for row in journal['files']}) == len(journal['files']),
            'UPGRADE_BACKUPS_INVALID')
    plan = []
    for row in journal['files']:
        path = Path(row['path'])
        require(path in allowed and re.fullmatch(r'[0-9]+', row['backup']) is not None, 'UPGRADE_BACKUP_PATH_INVALID')
        raw = r.raw_file(transaction / 'backups' / row['backup'], 1048576) if row['before'] is not None else None
        require(raw is None or checksum(raw) == row['before'], 'UPGRADE_BACKUP_CHANGED')
        current = r.digest(path) if path.exists() or path.is_symlink() else None
        # Policy activation creates its own transactional metadata/results. They
        # are mutable only while the shared policy lock is held.
        if path not in (r.DATA / 'transaction.json', r.DATA / 'last-result.json'):
            replacement = (boot_unit(i.PROJECT) if path == i.UNIT_ROOT / BOOT_UNIT else
                           finish_unit(i.PROJECT) if path == i.UNIT_ROOT / FINISH_UNIT else None)
            migrated_guard = (replacement is not None and raw in infrastructure_variants(i, path, replacement)
                              and current == checksum(replacement))
            require(current in (row['before'], row['after']) or migrated_guard, 'UPGRADE_EXTERNAL_FILE_EDIT')
            if migrated_guard:
                # Keep the reviewed infrastructure migration on rollback; the
                # legacy backup remains intact and is still checksum-validated.
                raw = replacement
        plan.append((path, raw, row))
    return transaction, old, plan


def recover(i, r, boot=False, defer_stop=False):
    path = journal_path(i)
    if not path.exists() and not path.is_symlink():
        return False
    journal = r.record(path)
    if journal.get('status') in ('committed', 'rolled_back'):
        return not services_complete(journal)
    transaction, old, plan = recovery_plan(i, r, journal)
    backup = transaction / 'old-lib'
    if backup.exists() or backup.is_symlink():
        require(backup.is_dir() and not backup.is_symlink(), 'UPGRADE_OLD_LIBRARY_INVALID')
        bundle(r, backup, journal['old_files'])
        binaries(r, backup, journal['binaries'])
        if r.CODE.exists() or r.CODE.is_symlink():
            require(r.CODE.is_dir() and not r.CODE.is_symlink(), 'UPGRADE_LIVE_LIBRARY_INVALID')
            bundle(r, r.CODE, journal['target_files'])
            binaries(r, r.CODE, journal['binaries'])
    else:
        require(r.CODE.is_dir() and not r.CODE.is_symlink(), 'UPGRADE_OLD_LIBRARY_MISSING')
        bundle(r, r.CODE, journal['old_files'])
        binaries(r, r.CODE, journal['binaries'])
    journal['status'] = 'rolling_back'
    save_journal(i, r, journal)
    if not boot and not defer_stop:
        stop(r)
    if backup.exists():
        if r.CODE.exists():
            sync_rename(r.CODE, transaction / 'failed-lib')
        sync_rename(backup, r.CODE)
    for path, raw, row in plan:
        if raw is None:
            if path.exists():
                path.unlink()
                sync_directory(path.parent)
        else:
            r.atomic(path, raw, row['mode'], row['gid'])
    r.pointer(old)
    r.run(['systemctl', 'daemon-reload'], 'UPGRADE_ROLLBACK_RELOAD_FAILED')
    journal['status'] = 'rolled_back'
    journal['services_restored'] = False
    save_journal(i, r, journal)
    # The caller still holds the policy lock; leave workers stopped until it
    # releases it. Timers/path watches are restored by the caller afterwards.
    return True


def stage_policy(i, r, code, work, previous):
    staged = i.load_runtime(code)
    staged.CODE = code
    s = staged.modules()
    values, snapshots = staged.personal(s)
    manifest = staged.make_full(s, work, previous)
    body, ip = staged.combined_ips(previous['ip'])
    manifest.update(personal=values, personal_sha256=snapshots, ip=ip)
    gid = i.grp.getgrnam(staged.GROUP).gr_gid
    staged.atomic(work / 'proxy-ipv4.json', body, 0o640, gid)
    staged.atomic(work / 'personal-direct-domains.json', staged.direct_body(values['direct']), 0o640, gid)
    manifest['runtime'] = s.personal.runtime_check(s, s.core, s.pilot, work, manifest, values, staged.base_config(s, work))
    return staged, s, manifest


def upgrade(folder, i, recover_only=False):
    require(sys.platform == 'linux' and os.geteuid() == 0, 'ROOT_LINUX_REQUIRED')
    r = i.load_runtime(folder)
    recovered_by_guardian = guardian_stored(r)
    wait_guardian(r)
    with deploy_lock(i, wait=recover_only or recovered_by_guardian):
        try:
            result = upgrade_locked(folder, i, recover_only or recovered_by_guardian)
            if recovered_by_guardian:
                result['status'] = 'recovered'
        finally:
            path = journal_path(i)
            if not path.exists() or r.record(path).get('status') in ('committed', 'rolled_back'):
                finish_services(i, r)
    r.report('upgrade', **result)
    if result['status'] == 'upgraded':
        print('VPN_STACK_UPGRADE_OK', flush=True)
    return result


def upgrade_locked(folder, i, recover_only):
    r = i.load_runtime(folder)
    root = i.PROJECT / 'state/upgrade'
    with policy_lock(i, r) as policy_fd:
        if journal_path(i).is_file():
            infrastructure(i, r, i.units(r), folder, activate=False, policy_fd=policy_fd)
            if r.record(journal_path(i)).get('status') in PENDING and not (r.DATA / 'update.lock').is_symlink():
                fence(i, r)  # Adopt the same durable exclusion for legacy journals.
        recovered = recover(i, r)
        if recover_only or recovered:
            result = {'status': 'recovered' if recovered else 'unchanged'}
        else:
            i.host_audit(r, resume=True, minimum_memory_mib=512)
            state = r.record(i.STATE)
            require(state['status'] == 'installed', 'UPGRADE_INSTALLED_STATE_REQUIRED')
            old_files = state['package_files']
            target = r.record(folder / 'code-manifest.json')['files']
            r.require_baseline(target)
            bundle(r, folder, target)
            bundle(r, r.CODE, old_files)
            old_r = i.load_runtime(r.CODE)
            require(old_r.PINNED_VERSIONS == r.PINNED_VERSIONS, 'UPGRADE_BINARY_VERSION_CHANGE_UNSUPPORTED')
            old_r.modules()
            require(old_r.transport_health()['status'] == 'verified', 'UPGRADE_TRANSPORT_CONFIG_INVALID')
            old, previous = old_r.active()
            binaries(r, r.CODE, state['binaries'])
            target_units = {name: body.encode() for name, body in i.units(r).items()}
            target_units[BOOT_UNIT] = boot_unit(i.PROJECT)
            target_units[FINISH_UNIT] = finish_unit(i.PROJECT)
            for name, digest in state['units'].items():
                current = r.digest(i.UNIT_ROOT / name)
                migrated_guard = (name == BOOT_UNIT and digest in
                                  tuple(checksum(raw) for raw in infrastructure_variants(i, i.UNIT_ROOT / name, boot_unit(i.PROJECT)))
                                  and current == checksum(boot_unit(i.PROJECT)))
                migrated_guard |= (name == FINISH_UNIT and digest == checksum(finish_unit(i.PROJECT, previous=True))
                                   and current == checksum(finish_unit(i.PROJECT)))
                require(name in target_units and (current == digest or migrated_guard), 'UPGRADE_INSTALLED_UNIT_CHANGED')
            for name in target_units:
                if name not in state['units'] and name not in (BOOT_UNIT, FINISH_UNIT):
                    require(not (i.UNIT_ROOT / name).exists() and not (i.UNIT_ROOT / name).is_symlink(),
                            'UPGRADE_UNOWNED_UNIT_EXISTS')
            require(r.raw_file(i.CLI) == i.CLI_BODY, 'UPGRADE_INSTALLED_CLI_CHANGED')
            if old_files == target and all(state['units'].get(name) == checksum(raw) for name, raw in target_units.items()):
                result = {'status': 'unchanged', 'recovered': recovered}
            else:
                states = service_snapshot(r)
                infrastructure(i, r, target_units, folder, policy_fd=policy_fd)
                private_directory(root)
                transaction = Path(tempfile.mkdtemp(prefix='up-', dir=root))
                # Stable, restrictive names are also checked by the boot loader.
                import secrets
                renamed = root / ('up-' + secrets.token_hex(8))
                sync_rename(transaction, renamed)
                transaction = renamed
                for name in ('package', 'backups'):
                    private_directory(transaction / name)
                code = transaction / 'code'
                code.mkdir(mode=0o755)
                code.chmod(0o755)
                (code / 'bin').mkdir(mode=0o755)
                (code / 'bin').chmod(0o755)
                for name, digest in target.items():
                    raw = r.raw_file(folder / name, 1048576)
                    r.atomic(transaction / 'package' / name, raw)
                    r.atomic(code / name, raw, 0o644)
                raw_manifest = r.dump({'files': target})
                r.atomic(transaction / 'package/code-manifest.json', raw_manifest)
                r.atomic(code / 'code-manifest.json', raw_manifest, 0o644)
                for name in state['binaries']:
                    os.link(r.CODE / 'bin' / name, code / 'bin' / name, follow_symlinks=False)
                work = r.work_directory()
                published = False
                try:
                    i.create_rule_files(r)
                    staged, s, manifest = stage_policy(i, r, code, work, previous)
                    config, _ = s.core.compose(staged.base_config(s, work), manifest['personal'])
                    files = []
                    save_file(r, transaction, r.CONFIG, config.encode(), files)
                    for name in ('transaction.json', 'last-result.json'):
                        save_file(r, transaction, r.DATA / name, None, files)
                    for name, raw in target_units.items():
                        save_file(r, transaction, i.UNIT_ROOT / name, raw, files)
                    save_file(r, transaction, i.CLI, i.CLI_BODY, files)
                    save_file(r, transaction, i.STATE, None, files)
                    journal = {'schema': 1, 'status': 'prepared', 'transaction': transaction.name,
                               'old_generation': str(old), 'new_generation': str(work),
                               'old_files': old_files, 'target_files': target, 'unit_names': list(target_units),
                               'binaries': state['binaries'],
                               'files': files, 'services': states, 'services_restored': False}
                    sync_tree(transaction)
                    sync_tree(work)
                    fence(i, r)
                    save_journal(i, r, journal)
                    published = True
                    stop(r)
                    journal['status'] = 'applying'
                    save_journal(i, r, journal)
                    sync_rename(r.CODE, transaction / 'old-lib')
                    sync_rename(code, r.CODE)
                    for name, raw in target_units.items():
                        r.atomic(i.UNIT_ROOT / name, raw, 0o644)
                    r.atomic(i.CLI, i.CLI_BODY, 0o755)
                    i.create_rule_files(r)
                    r.run(['systemd-analyze', 'verify', *[i.UNIT_ROOT / name for name in target_units]], 'UPGRADE_UNITS_INVALID')
                    r.run(['systemctl', 'daemon-reload'], 'UPGRADE_SYSTEMD_RELOAD_FAILED')
                    staged.CODE = r.CODE
                    start(r, states, triggers=False)
                    staged.wait_backend(s, previous['counts'])
                    ready_dns()
                    policy = staged.activate(s, work, manifest)
                    staged.trim_files(work)
                    updated = dict(state, package_files=target, units={name: checksum(raw) for name, raw in target_units.items()},
                                   policy=policy, upgraded_utc=i.datetime_utc())
                    raw = r.dump(updated)
                    files[-1]['after'] = checksum(raw)
                    save_journal(i, r, journal)
                    r.atomic(i.STATE, raw)
                    journal['status'] = 'committed'
                    journal['services_restored'] = False
                    save_journal(i, r, journal)
                    result = {'status': 'upgraded', 'backup': str(transaction), 'policy': policy,
                              'keys_and_profiles_preserved': True, 'recovered': recovered}
                except BaseException:
                    handlers = {sig: signal.signal(sig, signal.SIG_IGN) for sig in (signal.SIGINT, signal.SIGTERM)}
                    try:
                        # atomic() may have replaced the journal before raising
                        # (signal, directory fsync, or close). Its return is not
                        # the publication boundary. Unknown results retain data.
                        path = journal_path(i)
                        if not published and (path.exists() or path.is_symlink()):
                            published = r.record(path).get('transaction') == transaction.name
                        if published:
                            recover(i, r)
                        else:
                            unfence(i, r)
                            shutil.rmtree(transaction)
                            shutil.rmtree(work)
                    finally:
                        for sig, handler in handlers.items():
                            signal.signal(sig, handler)
                    raise
    return result


def recovery_modules(project, package):
    require(sys.platform == 'linux' and os.geteuid() == 0, 'ROOT_LINUX_REQUIRED')
    spec = importlib.util.spec_from_file_location('vpn_upgrade_installer', package / 'vpn-stack-install.py')
    i = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(i)
    i.configure_project(project)
    r = i.load_runtime(package)
    return i, r


def boot_recover(project, package, services=False):
    i, r = recovery_modules(project, package)
    wait_guardian(r)
    with deploy_lock(i, wait=services):
        if services:
            recovered = finish_services(i, r)
        else:
            with policy_lock(i, r):
                recovered = recover(i, r, boot=True)
            # The guard must release the durable fence before dependent device
            # recovery/old workers may start, and after dropping the policy lock.
            unfence(i, r)
            # Never synchronously start a unit ordered after this boot guard.
            # A separate oneshot completes only after the guard has returned.
            r.run(['systemctl', '--no-block', 'start', FINISH_UNIT], 'UPGRADE_SERVICE_RECOVERY_QUEUE_FAILED')
    r.report('upgrade-recovery', recovered=recovered)
