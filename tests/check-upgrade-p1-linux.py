#!/usr/bin/env python3
"""Second-review regressions. Invoked by check-upgrade-systemd-linux.py.

Requires a disposable systemd/PID 1 container and real historical archives.
Filesystem, flock, process death, FDSTORE, systemd graph, Mihomo and DNS are
real. Fixture sources/DNS are local; Xray/workers and host audit are diagnostic.
These process failures do not simulate filesystem power loss.
"""
import fcntl
import faulthandler
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time
import traceback
from unittest.mock import patch


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def until(predicate, label, seconds=120):
    deadline = time.monotonic() + seconds
    while not predicate():
        assert time.monotonic() < deadline, label
        time.sleep(.05)


def pause_guardian(u, r):
    assert u.guardian_stored(r)
    r.run(['systemctl', 'kill', '--kill-whom=main', '--signal=SIGSTOP', u.GUARDIAN_UNIT], 'PAUSE_FAILED')


def locked(u, i, r):
    path = u.fence_path(i) if (r.DATA / 'update.lock').is_symlink() else r.DATA / 'update.lock'
    with path.open('r') as stream:
        try:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
    return False


def settled(u, i, r):
    until(lambda: r.record(u.journal_path(i)).get('services_restored') is True, 'SERVICES_NOT_RESTORED')
    until(lambda: not u.guardian_stored(r), 'GUARDIAN_NOT_RELEASED')
    for name in (*u.CORE, *u.TRIGGERS):
        assert r.unit_state(name)['ActiveState'] == 'active', name
    u.ready_dns()


def guardian_rollback_loss(u, i, r):
    """Diagnostic checkpoint after the REAL guardian publishes rolling_back.

    The verified engine and its manifest stay unchanged. A service shim adds
    only SIGSTOP after save_journal; PID 1 passes the real stored fd to it.
    """
    loader = i.PROJECT / 'state/upgrade' / u.LOADER
    marker = i.PROJECT / 'guardian-rollback-checkpoint'
    shim = i.PROJECT / 'guardian-fault.py'
    injected = ('    save = module.save_journal\n'
                '    def stopped(installer, runtime, journal):\n'
                '        save(installer, runtime, journal)\n'
                "        if journal['status'] == 'rolling_back':\n"
                '            Path(' + repr(str(marker)) + ').write_text("ready")\n'
                '            os.kill(os.getpid(), 19)\n'
                '    module.save_journal = stopped\n'
                '    module.guardian(root.parent.parent, package)')
    r.atomic(shim, ('from pathlib import Path\n'
        'loader = Path(' + repr(str(loader)) + ')\n'
        'text = loader.read_text().replace("    module.guardian(root.parent.parent, package)", ' + repr(injected) + ')\n'
        'exec(compile(text, str(loader), "exec"), {"__file__": str(loader)})\n').encode())
    override = i.UNIT_ROOT / (u.GUARDIAN_UNIT + '.d')
    override.mkdir(exist_ok=True)
    dropin = override / '99-checkpoint.conf'
    r.atomic(dropin, ('[Service]\nExecStart=\nExecStart=/usr/bin/python3 ' + str(shim) + ' --guardian\n').encode(), 0o644)
    r.run(['systemctl', 'daemon-reload'], 'CHECKPOINT_RELOAD_FAILED')
    r.run(['systemctl', '--no-block', 'start', u.GUARDIAN_UNIT], 'CHECKPOINT_START_FAILED')
    until(marker.exists, 'GUARDIAN_ROLLBACK_CHECKPOINT_NOT_REACHED')
    assert r.record(u.journal_path(i))['status'] == 'rolling_back'
    assert u.guardian_stored(r) and locked(u, i, r)
    dropin.unlink()
    r.run(['systemctl', 'daemon-reload'], 'CHECKPOINT_RELOAD_FAILED')
    r.run(['systemctl', 'kill', '--kill-whom=main', '--signal=SIGKILL', u.GUARDIAN_UNIT], 'CHECKPOINT_KILL_FAILED')
    assert u.guardian_stored(r) and locked(u, i, r)


def preopen(u, i, r, package, originals, upstream):
    assert os.environ['PREVIOUS_REVISION'] in ('a62ad73', '4e643dc')
    matrix = []
    points = ('handoff', 'prepared', 'lib-absent', 'lib-published', 'rolling-back', 'rollback-file')
    if os.environ.get('P1_PREOPEN_POINT'):
        points = (os.environ['P1_PREOPEN_POINT'],)
    for point in points:
        before = {p: p.read_bytes() for p in (r.CONFIG, i.STATE, r.CODE / 'code-manifest.json')}
        old_generation = (r.DATA / 'current').resolve()
        ready_r, ready_w = os.pipe()
        resume_r, resume_w = os.pipe()
        worker = os.fork()
        if worker == 0:
            flock = r.fcntl.flock
            def delayed(fd, flags):
                os.write(ready_w, b'1')
                os.read(resume_r, 1)
                return flock(fd, flags)
            modules = r.modules
            def historical_modules():
                services = modules()
                checker = services.personal.runtime_check
                services.personal.runtime_check = lambda *a: checker(*a[:-1], a[-1].replace(upstream, 'https://1.1.1.1/dns-query'))
                return services
            with patch.object(r.fcntl, 'flock', side_effect=delayed), patch.object(r, 'modules', side_effect=historical_modules):
                try:
                    r.apply('personal')  # Actual installed historical runtime.
                except BlockingIOError:
                    os._exit(90)
                except BaseException:
                    os._exit(91)
            os._exit(0)
        assert os.read(ready_r, 1) == b'1'
        updater = os.fork()
        if updater == 0:
            save, rename = u.save_journal, u.sync_rename
            rollback_injected = False
            def die():
                pause_guardian(u, r)
                os._exit(73)
            def journal(installer, runtime, value):
                save(installer, runtime, value)
                if value['status'] == 'prepared' and point == 'prepared':
                    die()
                if value['status'] == 'rolling_back' and point == 'rolling-back':
                    die()
            def swap(source, destination):
                nonlocal rollback_injected
                rename(source, destination)
                if destination.name == 'old-lib' and point == 'lib-absent':
                    die()
                if destination == r.CODE:
                    if point == 'lib-published':
                        die()
                    if point in ('rolling-back', 'rollback-file') and not rollback_injected:
                        rollback_injected = True
                        raise u.UpgradeError('INJECT_ROLLBACK')
            infrastructure = u.infrastructure
            arm = u.arm_guardian
            def handoff(*args):
                arm(*args)
                if point == 'handoff':
                    die()
            def with_file_fault(installer, runtime, *args, **kwargs):
                atomic = runtime.atomic
                def restored(path, raw, *a, **kw):
                    atomic(path, raw, *a, **kw)
                    if point == 'rollback-file' and path == r.CONFIG and u.journal_path(i).exists() and runtime.record(u.journal_path(i))['status'] == 'rolling_back':
                        die()
                runtime.atomic = restored
                return infrastructure(installer, runtime, *args, **kwargs)
            try:
                with patch.object(u, 'save_journal', side_effect=journal), patch.object(u, 'sync_rename', side_effect=swap), patch.object(u, 'infrastructure', side_effect=with_file_fault), patch.object(u, 'arm_guardian', side_effect=handoff):
                    u.upgrade(package, i)
            except BaseException:
                # A forked child must not unwind the parent's DNS server
                # context: its serving thread does not exist in the child.
                traceback.print_exc()
                os._exit(98)
            os._exit(99)
        _, status = os.waitpid(updater, 0)
        assert os.waitstatus_to_exitcode(status) == 73, point
        assert u.guardian_stored(r) and locked(u, i, r), point
        pending = {p: p.read_bytes() for p in (r.CONFIG, i.STATE)}
        personal = r.ETC / 'direct.txt'
        r.atomic(personal, personal.read_bytes() + ('\nuser-edit-' + point + '.example\n').encode())
        originals[personal] = personal.read_bytes()
        # Also kill the guardian while the updater is dead. PID 1 is the only
        # holder during the restart gap; stop/start proves retained storage.
        r.run(['systemctl', 'kill', '--kill-whom=main', '--signal=SIGKILL', u.GUARDIAN_UNIT], 'KILL_FAILED')
        r.run(['systemctl', 'stop', u.GUARDIAN_UNIT], 'STOP_FAILED')
        assert u.guardian_stored(r) and locked(u, i, r), point
        os.write(resume_w, b'1')
        _, status = os.waitpid(worker, 0)
        assert os.waitstatus_to_exitcode(status) == 90, (point, status)
        for p, raw in pending.items():
            assert p.read_bytes() == raw, (point, p)
        for fd in (ready_r, ready_w, resume_r, resume_w):
            os.close(fd)
        if point == 'prepared':
            # A real external edit must still fail closed, retaining PID 1's
            # lock through repeated guardian failures. No checksum bypass.
            raw = r.CONFIG.read_bytes()
            r.CONFIG.write_bytes(raw + b'# external managed edit\n')
            r.run(['systemctl', '--no-block', 'start', u.GUARDIAN_UNIT], 'NEGATIVE_START_FAILED')
            until(lambda: b'UPGRADE_EXTERNAL_FILE_EDIT' in subprocess.check_output(
                ['journalctl', '-u', u.GUARDIAN_UNIT, '--no-pager']), 'EXTERNAL_EDIT_NOT_REFUSED')
            assert u.guardian_stored(r) and locked(u, i, r)
            assert r.record(u.journal_path(i))['status'] == 'prepared'
            r.CONFIG.write_bytes(raw)
        if point == 'lib-published':
            guardian_rollback_loss(u, i, r)
        # Recovery through the real Xray -> recovery service systemd graph.
        r.run(['systemctl', 'stop', u.BOOT_UNIT], 'BOOT_STOP_FAILED')
        r.run(['systemctl', 'start', 'vpn-stack-xray.service'], 'GRAPH_START_FAILED', timeout=120)
        # Stopping the boot guard also stops dependent enabled triggers. Their
        # boot jobs are independent of the Xray job (as on multi-user boot).
        r.run(['systemctl', 'start', *u.TRIGGERS], 'GRAPH_TRIGGERS_FAILED')
        if point == 'handoff':
            u.wait_guardian(r)
            u.ready_dns()
        else:
            settled(u, i, r)
        assert u.upgrade(package, i, True)['status'] == 'unchanged'
        for p, raw in {**originals, **before}.items():
            assert p.read_bytes() == raw, (point, p)
        assert (r.DATA / 'current').resolve() == old_generation
        matrix.append({'point': point, 'historical_apply_exit': 90, 'PID1_only_flock': True,
                       'guardian_killed_and_started': True, 'graph_recovery_and_repeat': True,
                       'guardian_loss_inside_rollback': point == 'lib-published'})
    return matrix


def migration(u, i, r, package, originals, stage_policy):
    assert os.environ['PREVIOUS_REVISION'] == '4e643dc'
    legacy_source = Path(os.environ['LEGACY_PACKAGE'])
    legacy_build = load('authentic_previous_build', legacy_source / 'scripts/build.py')
    legacy_package = i.PROJECT / 'legacy-package'
    legacy_package.mkdir(mode=0o700)
    for name, raw in legacy_build.package()[1].items():
        r.atomic(legacy_package / name, raw)
    legacy_i = load('authentic_a62ad73_installer', legacy_package / 'vpn-stack-install.py')
    legacy_i.configure_project(i.PROJECT)
    legacy_u = load('authentic_a62ad73_upgrade', legacy_package / 'vpn-stack-upgrade.py')
    previous_review = os.environ.get('P1_PREVIOUS_INFRASTRUCTURE') == '1'
    previous_fdstore = previous_review and hasattr(legacy_u, 'guardian_stored')
    assert legacy_u.BOOTSTRAP in ((u.PREVIOUS_BOOTSTRAP, u.FDSTORE_BOOTSTRAP) if previous_review else (u.LEGACY_BOOTSTRAP,))
    child = os.fork()
    if child == 0:
        rename = legacy_u.sync_rename
        def loss(source, destination):
            rename(source, destination)
            if destination.name == 'old-lib':
                if hasattr(legacy_u, 'guardian_stored') and legacy_u.guardian_stored(r):
                    pause_guardian(legacy_u, r)
                os._exit(72)
        with patch.object(legacy_u, 'sync_rename', side_effect=loss), patch.object(legacy_u, 'stage_policy', side_effect=stage_policy), patch.object(legacy_i, 'host_audit', return_value={}):
            legacy_u.upgrade(legacy_package, legacy_i)
        os._exit(99)
    _, status = os.waitpid(child, 0)
    assert os.waitstatus_to_exitcode(status) == 72 and not r.CODE.exists()
    journal = r.record(u.journal_path(i))
    assert ('services_restored' in journal) == previous_review
    transaction = i.PROJECT / 'state/upgrade' / journal['transaction']
    # Verify the journal's target package is byte-for-byte the real old build.
    for name, raw in legacy_build.package()[1].items():
        assert (transaction / 'package' / name).read_bytes() == raw
    # One genuinely missing old timer drop-in exercises its publication too.
    dropin = i.UNIT_ROOT / 'vpn-stack-ip.timer.d/20-vpn-upgrade-recovery.conf'
    dropin.unlink()
    archive = Path('/root/p1-migration-pending.tar')
    unit_paths = sorted(i.UNIT_ROOT.glob('vpn-stack-*'))
    subprocess.run(['tar', '-cpf', str(archive), '-C', '/', str(i.PROJECT).lstrip('/'),
                    *[str(p).lstrip('/') for p in unit_paths]], check=True)
    points = ['engine-file:' + name for name in r.record(package / 'code-manifest.json')['files']]
    points += ['engine-file:code-manifest.json', 'engine-published', 'pointer', 'loader-versioned',
               'loader-compatible', 'guardian-unit', 'hold-target', 'recovery-unit', 'finish-unit',
               'dropin', 'reload-final']
    if previous_fdstore:
        # The real immediately previous FDSTORE package already has these
        # byte-identical units. Migration correctly performs no publication.
        points = [point for point in points if point not in
                  ('guardian-unit', 'hold-target', 'recovery-unit', 'finish-unit')]
    if os.environ.get('P1_MIGRATION_FROM'):
        points = points[points.index(os.environ['P1_MIGRATION_FROM']):]
    matrix = []
    for index, point in enumerate(points):
        if index:
            r.run(['systemctl', 'stop', *u.TRIGGERS, *u.WORKERS, *u.CORE, u.BOOT_UNIT, u.FINISH_UNIT, u.GUARDIAN_UNIT, u.HOLD_UNIT], 'RESET_STOP_FAILED', timeout=120)
            r.run(['systemctl', 'clean', '--what=fdstore', u.GUARDIAN_UNIT], 'RESET_CLEAN_FAILED')
            shutil.rmtree(i.PROJECT)
            for path in i.UNIT_ROOT.glob('vpn-stack-*'):
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    path.unlink()
            subprocess.run(['tar', '-xpf', str(archive), '-C', '/'], check=True)
            r.run(['systemctl', 'daemon-reload'], 'RESET_RELOAD_FAILED')
            r.run(['systemctl', 'reset-failed'], 'RESET_FAILED')
        assert not r.CODE.exists()
        child = os.fork()
        if child == 0:
            infrastructure = u.infrastructure
            def interrupted(installer, runtime, *args, **kwargs):
                atomic, rename, run = runtime.atomic, u.sync_rename, runtime.run
                reloads = 0
                def boundary(name):
                    if name == point:
                        if u.guardian_stored(runtime):
                            pause_guardian(u, runtime)
                        os._exit(75)
                def write(path, raw, *a, **kw):
                    atomic(path, raw, *a, **kw)
                    if path.parent.name.startswith('.engine-'):
                        boundary('engine-file:' + path.name)
                    for name, location in [('pointer', 'engine.json'), ('loader-versioned', u.LOADER), ('loader-compatible', 'recover.py'), ('guardian-unit', u.GUARDIAN_UNIT), ('hold-target', u.HOLD_UNIT), ('recovery-unit', u.BOOT_UNIT), ('finish-unit', u.FINISH_UNIT), ('dropin', dropin.name)]:
                        if path.name == location:
                            boundary(name)
                def publish(source, destination):
                    rename(source, destination)
                    if destination.name.startswith('engine-'):
                        boundary('engine-published')
                def command(args, *a, **kw):
                    nonlocal reloads
                    result = run(args, *a, **kw)
                    if args[:2] == ['systemctl', 'daemon-reload']:
                        reloads += 1
                        boundary('reload-final')
                    return result
                with patch.object(runtime, 'atomic', side_effect=write), patch.object(u, 'sync_rename', side_effect=publish), patch.object(runtime, 'run', side_effect=command):
                    return infrastructure(installer, runtime, *args, **kwargs)
            with patch.object(u, 'infrastructure', side_effect=interrupted):
                u.upgrade(package, i, True)
            os._exit(99)
        _, status = os.waitpid(child, 0)
        assert os.waitstatus_to_exitcode(status) == 75, (point, status)
        if previous_fdstore and index == 0:
            # upgrade waits for the already armed historical guardian before
            # migrating its infrastructure. It legitimately repairs lib/ first.
            assert r.CODE.is_dir() and r.record(u.journal_path(i))['status'] == 'rolled_back', point
        else:
            assert not r.CODE.exists(), point
        # Reload models an independently restarted systemd reading disk units.
        # Cached ExecStart's recover.py is also directly exercised after death.
        if u.guardian_stored(r):
            r.run(['systemctl', 'kill', '--kill-whom=main', '--signal=SIGKILL', u.GUARDIAN_UNIT], 'KILL_FAILED')
        cached = subprocess.run(['/usr/bin/python3', str(i.PROJECT / 'state/upgrade/recover.py')], capture_output=True)
        assert cached.returncode == 0, (point, cached.stderr.decode())
        until(lambda: r.unit_state(u.FINISH_UNIT)['ActiveState'] not in ('active', 'activating', 'deactivating'),
              'CACHED_SERVICE_RECOVERY_RUNNING')
        r.run(['systemctl', 'daemon-reload'], 'GRAPH_RELOAD_FAILED')
        r.run(['systemctl', 'stop', u.BOOT_UNIT], 'GRAPH_STOP_FAILED')
        r.run(['systemctl', 'start', 'vpn-stack-xray.service'], 'GRAPH_START_FAILED', timeout=120)
        r.run(['systemctl', 'start', *u.TRIGGERS], 'GRAPH_TRIGGERS_FAILED')
        assert r.CODE.is_dir() and r.record(u.journal_path(i))['status'] == 'rolled_back', point
        # Finish service restoration with the new engine even at boundaries
        # where the historical loader did the first file recovery itself.
        u.upgrade(package, i, True)
        settled(u, i, r)
        assert u.upgrade(package, i, True)['status'] == 'unchanged'
        for path, raw in originals.items():
            assert path.read_bytes() == raw, (point, path)
        matrix.append({'point': point, 'cached_loader_and_systemd_graph': True,
                       'authentic_previous_transaction': 'previous-review' if previous_review else 'a62ad73', 'repeat_recovery': True})
        print('P1_MIGRATION_BOUNDARY=' + point, flush=True)
    return matrix


def check(u, i, r, package, originals, stage_policy, upstream):
    faulthandler.register(signal.SIGUSR1)
    assert Path('/.dockerenv').is_file() and os.geteuid() == 0 and os.readlink('/proc/1/exe').endswith('/systemd')
    scenario = os.environ['P1_SCENARIO']
    if scenario == 'preopen':
        matrix = preopen(u, i, r, package, originals, upstream)
    elif scenario == 'migration':
        matrix = migration(u, i, r, package, originals, stage_policy)
    else:
        raise AssertionError(scenario)
    report = {'scenario': scenario, 'status': 'passed', 'matrix': matrix,
              'systemd': subprocess.check_output(['systemctl', '--version'], text=True).splitlines()[0],
              'previous_revision': os.environ['PREVIOUS_REVISION'],
              'scope': __doc__}
    Path('/tmp/p1-' + scenario + '-results.json').write_text(json.dumps(report, indent=2) + '\n')
    print('P1_NATIVE_RESULT=' + json.dumps(report), flush=True)
