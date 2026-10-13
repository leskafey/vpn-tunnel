#!/usr/bin/env python3
"""Disposable ARM64 Ubuntu/systemd upgrade check with native Mihomo.

Requires /repo, /previous (actual git archive), /native-binaries and /native-checksums.json. Uses synthetic
policy sources and local MockDNS. Xray is a diagnostic TCP listener; policy
workers are diagnostic oneshots. No full installer, VLESS, public VPS or client.
"""
from contextlib import ExitStack
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import pwd
import shutil
import signal
import socket
import socketserver
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
from unittest.mock import patch


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def freeze_guardian(u, r):
    if u.guardian_stored(r):
        r.run(['systemctl', 'kill', '--kill-whom=main', '--signal=SIGSTOP', u.GUARDIAN_UNIT], 'TEST_GUARDIAN_PAUSE_FAILED')


def previous_worker_fence(u, i, r, package, originals):
    """Kill new upgrade at prepared while lib/ is the actual historical bundle."""
    before = {path: path.read_bytes() for path in (r.CONFIG, i.STATE, r.CODE / 'code-manifest.json')}
    child = os.fork()
    if child == 0:
        save = u.save_journal
        def prepared(installer, runtime, journal):
            save(installer, runtime, journal)
            if journal['status'] == 'prepared':
                freeze_guardian(u, runtime)
                os._exit(71)
        with patch.object(u, 'save_journal', side_effect=prepared):
            u.upgrade(package, i)
        os._exit(99)
    _, status = os.waitpid(child, 0)
    assert os.waitstatus_to_exitcode(status) == 71
    # A user edit is input, not an unauthorized managed backend edit. Preserve
    # it while rejecting all automatic activation and managed CLI mutations.
    personal = r.ETC / 'direct.txt'
    r.atomic(personal, personal.read_bytes() + b'\npending-user-edit.example\n')
    originals[personal] = personal.read_bytes()
    try:
        r.apply('personal')  # Actual installed previous runtime and helpers.
        raise AssertionError('PREVIOUS_WORKER_MUTATED_PENDING_UPGRADE')
    except r.StackError as error:
        assert str(error) == 'POLICY_LOCK_REQUIRED'
    for args in (['cleanup'], ['rule', 'add', 'direct', 'refused.example']):
        result = subprocess.run([str(i.CLI), *args], capture_output=True)
        assert result.returncode != 0 and b'POLICY_LOCK_REQUIRED' in result.stdout
        assert personal.read_bytes() == originals[personal]
    for path, raw in before.items():
        assert path.read_bytes() == raw
    assert u.upgrade(package, i, True)['status'] == 'recovered'
    assert u.upgrade(package, i, True)['status'] == 'unchanged'
    for path, raw in {**originals, **before}.items():
        assert path.read_bytes() == raw
    return True


def crash_matrix(u, i, r, variant, originals):
    """Actual process death, historical worker locks, real systemd/DNS retries."""
    cases = []
    journal_path = u.journal_path(i)
    for point in ('publication_signal', 'publication_exception', 'prepared', 'committed', 'rolled_back', 'service_error'):
        before = {path: path.read_bytes() for path in (r.CONFIG, i.STATE, r.CODE / 'code-manifest.json')}
        active = (r.DATA / 'current').resolve()
        child = os.fork()
        if child == 0:
            if point.startswith('publication_'):
                replace = os.replace
                fired = False
                def after_replace(source, destination):
                    nonlocal fired
                    replace(source, destination)
                    if not fired and Path(destination) == journal_path and r.record(destination)['status'] == 'prepared':
                        fired = True
                        if point == 'publication_signal':
                            os.kill(os.getpid(), signal.SIGTERM)
                        raise OSError('injected failure before directory fsync')
                def terminated(*_):
                    raise u.UpgradeError('INTERRUPTED')
                signal.signal(signal.SIGTERM, terminated)
                try:
                    with patch.object(os, 'replace', side_effect=after_replace):
                        u.upgrade(variant, i)
                except (OSError, u.UpgradeError):
                    assert fired
                    os._exit(73)
                os._exit(99)
            save = u.save_journal
            def interrupted(installer, runtime, journal):
                save(installer, runtime, journal)
                if point in ('rolled_back', 'service_error') and journal['status'] == 'applying':
                    raise u.UpgradeError('INJECT_ROLLBACK')
                if journal['status'] == point or point == 'service_error' and journal['status'] == 'rolled_back':
                    freeze_guardian(u, runtime)
                    os._exit(73)
            u.save_journal = interrupted
            u.upgrade(variant, i)
            os._exit(99)
        _, status = os.waitpid(child, 0)
        assert os.waitstatus_to_exitcode(status) == 73, point
        if point == 'prepared':
            # Live triggers from the old installed package are still active.
            # Run the actual previous worker and manual CLI cleanup as well.
            previous_r = load('old_worker_pending', Path('/previous/src/vpn-stack-runtime.py'))
            previous_r.configure_paths(i.PROJECT)
            try:
                with previous_r.lock():
                    raise AssertionError('OLD_WORKER_CROSSED_FENCE')
            except previous_r.StackError as error:
                assert str(error) == 'POLICY_LOCK_REQUIRED'
            # Run historical apply with the real managed project paths.
            command = 'import importlib.util; from pathlib import Path; '
            command += "spec=importlib.util.spec_from_file_location('old', '/previous/src/vpn-stack-runtime.py'); "
            command += "m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m); "
            command += 'm.configure_paths(' + repr(str(i.PROJECT)) + '); m.apply("personal")'
            worker = subprocess.run(['/usr/bin/python3', '-c', command], capture_output=True)
            assert worker.returncode != 0 and r.CONFIG.read_bytes() == before[r.CONFIG]
            cleanup = subprocess.run([str(i.CLI), 'cleanup'], capture_output=True)
            assert cleanup.returncode != 0 and r.CONFIG.read_bytes() == before[r.CONFIG]
        if point == 'service_error':
            dropin = i.UNIT_ROOT / 'vpn-stack-dns.service.d/99-fail-start.conf'
            r.atomic(dropin, b'[Service]\nExecStartPre=/usr/bin/false\n', 0o644)
            r.run(['systemctl', 'daemon-reload'], 'TEST_RELOAD_FAILED')
            try:
                u.upgrade(variant, i, True)
                raise AssertionError('SERVICE_ERROR_NOT_REACHED')
            except Exception as error:
                assert str(error) == 'UPGRADE_SERVICES_START_FAILED'
            assert not r.record(journal_path)['services_restored']
            dropin.unlink()
            r.run(['systemctl', 'daemon-reload'], 'TEST_RELOAD_FAILED')
            r.run(['systemctl', 'reset-failed'], 'TEST_RESET_FAILED')
        result = u.upgrade(variant, i, True)
        assert result['status'] == ('unchanged' if point.startswith('publication_') else 'recovered'), point
        transaction = i.PROJECT / 'state/upgrade' / r.record(journal_path)['transaction']
        assert (transaction / 'backups').is_dir(), point
        assert r.record(journal_path)['services_restored']
        for name in (*u.CORE, *u.TRIGGERS):
            assert r.unit_state(name)['ActiveState'] == 'active', (point, name)
        u.ready_dns()
        for path, raw in originals.items():
            assert path.read_bytes() == raw, (point, path)
        if point != 'committed':
            for path, raw in before.items():
                assert path.read_bytes() == raw, (point, path)
            assert (r.DATA / 'current').resolve() == active
        assert u.upgrade(variant, i, True)['status'] == 'unchanged'
        cases.append(point)
        # The committed variant is now live. A different target is needed for
        # the next fault injection; historical starting code was never faked.
        if point == 'committed':
            target = variant / 'vpn-stack-runtime.py'
            target.write_bytes(target.read_bytes() + b'\n# Next fault-injection target\n')
            files = r.record(variant / 'code-manifest.json')['files']
            files[target.name] = r.digest(target)
            r.atomic(variant / 'code-manifest.json', r.dump({'files': files}))
    return cases


def main():
    assert sys.platform == 'linux' and os.geteuid() == 0 and Path('/.dockerenv').is_file(), 'DISPOSABLE_CONTAINER_ONLY'
    os.umask(0o077)
    project = Path('/root/vpn-upgrade-native')
    assert not project.exists(), 'TEST_PROJECT_ALREADY_EXISTS'
    project.mkdir(mode=0o700)
    repo = Path(__file__).resolve().parent.parent
    build = load('systemd_upgrade_build', repo / 'scripts/build.py')
    package = project / 'target-package'
    package.mkdir(mode=0o700)
    for name, body in build.package()[1].items():
        (package / name).write_bytes(body)
    i = load('systemd_upgrade_installer', package / 'vpn-stack-install.py')
    i.configure_project(project)
    r = i.load_runtime(package)
    u = load('systemd_upgrade_transaction', package / 'vpn-stack-upgrade.py')
    for path in (project / 'state', i.ROOT):
        path.mkdir(mode=0o700)
    try:
        account = pwd.getpwnam(r.GROUP)
    except KeyError:
        subprocess.run(['useradd', '--system', '--no-create-home', '--shell', '/usr/sbin/nologin', r.GROUP], check=True)
        account = pwd.getpwnam(r.GROUP)
    i.prepare_service_directories(r, account, False)
    i.PROFILE_ROOT.mkdir(mode=0o700)
    previous_build = load('actual_previous_build', Path('/previous/scripts/build.py'))
    for name, body in previous_build.package()[1].items():
        r.atomic(r.CODE / name, body, 0o644)
    previous_i = load('actual_previous_installer', r.CODE / 'vpn-stack-install.py')
    previous_i.configure_project(project)
    r = previous_i.load_runtime(r.CODE)
    checksums = json.loads(Path('/native-checksums.json').read_bytes())
    for name, digest in checksums.items():
        raw = (Path('/native-binaries') / name).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == digest
        r.atomic(r.CODE / 'bin' / name, raw, 0o755)
    old_files = r.record(r.CODE / 'code-manifest.json')['files']
    previous_i.create_rule_files(r)
    if (r.ETC / 'ads.txt').exists():
        (r.ETC / 'ads.txt').unlink()
    r.atomic(r.DATA / 'update.lock', b'')
    probe = '00000000-0000-4000-8000-000000000001'
    phone = '00000000-0000-4000-8000-000000000002'
    r.atomic(r.ETC / 'settings.json', r.dump({'server_ip': '9.9.9.9'}))
    r.atomic(r.ETC / 'xray.json', r.dump(r.xray_config('P' * 43, '0123456789abcdef', {'probe': probe, 'phone': phone})))
    r.atomic(r.ETC / 'devices.json', r.dump({'schema': 1, 'xray_sha256': r.digest(r.ETC / 'xray.json'),
        'devices': {'phone': {'uuid': phone, 'platform': 'universal'}}}))
    r.atomic(r.ETC / 'probe-client.json', r.dump({'outbounds': [{'uuid': probe}]}))
    r.atomic(i.ROOT / 'identity.json', r.dump({'private_key': 'P' * 43, 'probe_uuid': probe}))
    r.atomic(i.PROFILE_ROOT / 'phone-smart.json', b'user-customized profile; preserve bytes')
    r.atomic(r.HOME / 'preserve-cache', b'cached user backend state')
    r.atomic(r.ETC / 'proxy.txt', b'# user rules\ncustom.example\n')
    r.atomic(i.CLI, i.CLI_BODY, 0o755)
    unit_bodies = previous_i.units(r)
    for name, body in unit_bodies.items():
        r.atomic(i.UNIT_ROOT / name, body.encode(), 0o644)
    diagnostic = project / 'diagnostic.py'
    r.atomic(diagnostic, b'import socket,signal\ns=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("127.0.0.1",443));s.listen();signal.pause()\n')
    for name in (*u.WORKERS, 'vpn-stack-xray.service'):
        directory = i.UNIT_ROOT / (name + '.d')
        directory.mkdir(exist_ok=True)
        command = '/usr/bin/python3 ' + str(diagnostic) if name == 'vpn-stack-xray.service' else '/usr/bin/true'
        r.atomic(directory / '10-test-diagnostic.conf', ('[Service]\nExecStart=\nExecStart=' + command + '\n').encode(), 0o644)
    originals = {path: path.read_bytes() for path in
        (i.ROOT / 'identity.json', r.ETC / 'xray.json', r.ETC / 'devices.json',
         r.ETC / 'probe-client.json', r.ETC / 'settings.json', r.ETC / 'proxy.txt', i.PROFILE_ROOT / 'phone-smart.json', r.HOME / 'preserve-cache')}
    with ExitStack() as stack:
        s = r.modules()
        # Forked failure injectors must not inherit a threaded DNS server's
        # Python locks. Run the same local MockDNS in a separate systemd unit;
        # it also remains available for the cold-boot follow-up.
        upstream = s.wire.spare_port()
        dns_script = project / 'diagnostic-dns.py'
        r.atomic(dns_script, ('import importlib.util, socketserver\nfrom pathlib import Path\n'
            'root = Path(' + repr(str(package)) + ')\n'
            'def load(name):\n'
            '    spec = importlib.util.spec_from_file_location(name, root / (name + ".py"))\n'
            '    module = importlib.util.module_from_spec(spec)\n'
            '    spec.loader.exec_module(module)\n'
            '    return module\n'
            'pilot = load("personal-checker")\npilot.MockDNS.helper = load("dns-wire")\n'
            'with socketserver.UDPServer(("127.0.0.1", ' + str(upstream) + '), pilot.MockDNS) as server:\n'
            '    server.serve_forever()\n').encode())
        dns_unit = 'vpn-test-dns-upstream.service'
        r.atomic(i.UNIT_ROOT / dns_unit, ('[Unit]\nDefaultDependencies=no\nAfter=local-fs.target\n'
            'Before=' + u.BOOT_UNIT + ' shutdown.target\nConflicts=shutdown.target\n'
            'RequiresMountsFor=' + str(project) + '\n'
            '[Service]\nExecStart=/usr/bin/python3 ' + str(dns_script) + '\n'
            '[Install]\nWantedBy=multi-user.target\n').encode(), 0o644)
        r.run(['systemctl', 'daemon-reload'], 'DNS_FIXTURE_RELOAD_FAILED')
        r.run(['systemctl', 'enable', '--now', dns_unit], 'DNS_FIXTURE_START_FAILED')
        deadline = time.monotonic() + 10
        while True:
            try:
                assert s.wire.lookup(upstream, 'fixture.example', 'udp') == '127.0.0.1'
                break
            except OSError:
                assert time.monotonic() < deadline, 'DNS_FIXTURE_NOT_READY'
                time.sleep(.05)
        upstream_address = '127.0.0.1:' + str(upstream)
        def local_config(runtime):
            original = runtime.base_config
            runtime.test_original_base_config = original
            runtime.base_config = lambda *a: original(*a).replace('https://1.1.1.1/dns-query', upstream_address)
        local_config(r)
        def make_policy(runtime, services, work, extended):
            (work / 'assets').mkdir(mode=0o750)
            os.chown(work / 'assets', 0, account.pw_gid)
            (work / 'assets').chmod(0o750)
            sources = {'smart': '+.instagram.com\n+.proxy.example\n', 'direct': '+.direct.example\n',
                       'ads': '+.ads.example\n'}
            if extended == 'same-counts':
                sources['direct'] = '+.proxy.example\n'
                sources['ads'] = '+.otherads.example\n'
            elif extended:
                sources.update({'ads-allow': '+.allowed.ads.example\nexact.ads.example\n',
                                'ads-important': '+.important.ads.example\n'})
            files = {}
            for tag, body in sources.items():
                raw = work / (tag + '.raw.txt')
                raw.write_text(body)
                files[tag + '.mrs'] = services.builder.compile_and_verify(tag, raw, work / 'assets', work)
                os.chown(work / 'assets' / (tag + '.mrs'), 0, account.pw_gid)
                (work / 'assets' / (tag + '.mrs')).chmod(0o640)
            values, snapshots = runtime.personal(services)
            manifest = {'files': files, 'assets_source': str(work), 'personal': values, 'personal_sha256': snapshots,
                        'source_metadata': {}, 'source_entries': {}, 'extras': {}, 'commit': 'synthetic',
                        'registry_domains': 2, 'upstream_prefix_rewrites': 0, 'ip': {'source_CIDRs': ['104.16.0.0/13']}}
            raw, manifest['ip'] = runtime.combined_ips(manifest['ip'])
            runtime.atomic(work / 'proxy-ipv4.json', raw, 0o640, account.pw_gid)
            runtime.atomic(work / 'personal-direct-domains.json', runtime.direct_body(values['direct']), 0o640, account.pw_gid)
            manifest['runtime'] = services.personal.runtime_check(services, services.core, services.pilot,
                work, manifest, values, runtime.test_original_base_config(services, work))
            return manifest
        def probes(runtime, services, work, manifest, *_a, **_k):
            # The native policy checker already uses TCP/UDP and blocked SOCKS.
            deadline = time.monotonic() + 10
            while True:
                client = http.client.HTTPConnection('127.0.0.1', 8080, timeout=3)
                try:
                    client.request('GET', '/probe.json')
                    response = client.getresponse()
                    assert response.status == 200 and response.read() == b'{"status":"ok"}\n'
                    break
                except OSError:
                    assert time.monotonic() < deadline, 'HTTP_FIXTURE_NOT_READY'
                    time.sleep(.05)
                finally:
                    client.close()
            return {'HTTP': 'passed', 'VLESS': 'not_tested'}
        r.probes = lambda *a, **k: probes(r, *a, **k)
        old = r.work_directory()
        manifest = make_policy(r, s, old, False)
        text, _ = s.core.compose(r.base_config(s, old), manifest['personal'])
        r.atomic(r.CONFIG, text.encode(), 0o640, account.pw_gid)
        r.run(['systemctl', 'daemon-reload'], 'TEST_RELOAD_FAILED')
        r.run(['systemctl', 'start', *u.CORE], 'TEST_START_FAILED', timeout=60)
        r.activate(s, old, manifest, initial=True)
        r.run(['systemctl', 'enable', '--now', *u.TRIGGERS], 'TEST_TRIGGER_START_FAILED')
        r.atomic(i.STATE, r.dump({'status': 'installed', 'server_ip': '9.9.9.9', 'package_files': old_files,
            'binaries': checksums, 'units': {name: hashlib.sha256(body.encode()).hexdigest() for name, body in unit_bodies.items()},
            'private_files': {}}))
        def stage_policy(installer, _r, code, work, _previous):
            staged = installer.load_runtime(code)
            staged.CODE = code
            local_config(staged)
            services = staged.modules()
            staged.probes = lambda *a, **k: probes(staged, *a, **k)
            return staged, services, make_policy(staged, services, work, True)
        stack.enter_context(patch.object(u, 'stage_policy', side_effect=stage_policy))
        # The fixture is ARM64 and already provisioned; the real host audit is
        # amd64-only. All upgrade filesystem/systemd/native calls remain real.
        stack.enter_context(patch.object(i, 'host_audit', return_value={'scope': 'ARM64 fixture'}))
        if os.environ.get('ACTIVATION_SCENARIO'):
            regression = load('activation_regression', repo / 'tests/check-upgrade-activation-linux.py')
            regression.check(u, i, r, package, originals, make_policy, local_config, probes)
            return
        if os.environ.get('P1_SCENARIO'):
            regression = load('second_review_regression', repo / 'tests/check-upgrade-p1-linux.py')
            regression.check(u, i, r, package, originals, stage_policy, upstream_address)
            return
        previous_worker_blocked = previous_worker_fence(u, i, r, package, originals)
        legacy_pending = False
        if os.environ.get('LEGACY_PACKAGE'):
            legacy_build = load('legacy_target_build', Path(os.environ['LEGACY_PACKAGE']) / 'scripts/build.py')
            legacy_package = project / 'legacy-package'
            legacy_package.mkdir(mode=0o700)
            for name, body in legacy_build.package()[1].items():
                r.atomic(legacy_package / name, body)
            legacy_i = load('legacy_pending_installer', legacy_package / 'vpn-stack-install.py')
            legacy_i.configure_project(project)
            legacy_u = load('legacy_pending_upgrade', legacy_package / 'vpn-stack-upgrade.py')
            assert legacy_u.BOOTSTRAP == u.LEGACY_BOOTSTRAP
            r.atomic(project / 'state/upgrade/recover.py', legacy_u.BOOTSTRAP)
            r.atomic(i.UNIT_ROOT / u.BOOT_UNIT, u.boot_unit(project, legacy=True), 0o644)
            child = os.fork()
            if child == 0:
                rename = legacy_u.sync_rename
                def interrupted_legacy(source, destination):
                    rename(source, destination)
                    if destination.name == 'old-lib':
                        os._exit(72)
                with patch.object(legacy_u, 'sync_rename', side_effect=interrupted_legacy), \
                     patch.object(legacy_i, 'host_audit', return_value={'scope': 'ARM64 fixture'}), \
                     patch.object(legacy_u, 'stage_policy', side_effect=stage_policy):
                    legacy_u.upgrade(legacy_package, legacy_i)
                os._exit(99)
            _, status = os.waitpid(child, 0)
            assert os.waitstatus_to_exitcode(status) == 72 and not r.CODE.exists()
            assert 'services_restored' not in r.record(u.journal_path(i))
            assert u.upgrade(package, i, True)['status'] == 'recovered'
            assert r.record(u.journal_path(i))['services_restored']
            assert (project / 'state/upgrade/recover.py').read_bytes() == u.BOOTSTRAP
            for path, raw in originals.items():
                assert path.read_bytes() == raw
            legacy_pending = True
        if (r.CODE / 'vpn-stack-upgrade.py').exists():
            previous_u = load('actual_previous_upgrade', r.CODE / 'vpn-stack-upgrade.py')
            # The original a62ad73 infrastructure predates the new durable
            # fence fixture. Reinstall its exact loader to exercise migration.
            r.atomic(project / 'state/upgrade/recover.py', u.LEGACY_BOOTSTRAP)
            r.atomic(i.UNIT_ROOT / u.BOOT_UNIT, u.boot_unit(project, legacy=True), 0o644)
            previous_u.infrastructure(previous_i, r, unit_bodies)
            assert (project / 'state/upgrade/recover.py').read_bytes() == u.LEGACY_BOOTSTRAP
        # Install state, units and code above come from the real historical bundle.
        r = i.load_runtime(package)
        local_config(r)
        r.probes = lambda *a, **k: probes(r, *a, **k)
        result = u.upgrade(package, i)
        assert result['status'] == 'upgraded'
        for path, raw in originals.items():
            assert path.read_bytes() == raw, 'IDENTITY_OR_PROFILE_CHANGED'
        assert r.record(u.journal_path(i))['status'] == 'committed'
        graph = subprocess.run(['systemd-analyze', 'verify', 'multi-user.target'], capture_output=True, check=True)
        assert b'ordering cycle' not in graph.stderr.lower(), graph.stderr.decode()
        variant = project / 'next-package'
        shutil.copytree(package, variant)
        path = variant / 'vpn-stack-runtime.py'
        path.write_bytes(path.read_bytes() + b'\n# Interrupted target fixture\n')
        variants = r.record(variant / 'code-manifest.json')['files']
        variants[path.name] = r.digest(path)
        r.atomic(variant / 'code-manifest.json', r.dump({'files': variants}))
        before = {path: path.read_bytes() for path in (r.CONFIG, i.STATE, r.CODE / 'code-manifest.json')}
        active = (r.DATA / 'current').resolve()
        original_rename = u.sync_rename
        child = os.fork()
        if child == 0:
            def interrupted(source, destination):
                original_rename(source, destination)
                if destination.name == 'old-lib':
                    freeze_guardian(u, r)
                    os._exit(73)
            u.sync_rename = interrupted
            u.upgrade(variant, i)
            os._exit(99)
        _, status = os.waitpid(child, 0)
        assert os.waitstatus_to_exitcode(status) == 73 and not r.CODE.exists(), 'GAP_INTERRUPTION_NOT_REACHED'
        # Starting Xray through its actual dependency graph invokes the durable
        # bootstrap, which must work even though lib/ is currently missing.
        r.run(['systemctl', 'stop', u.BOOT_UNIT], 'TEST_GUARD_STOP_FAILED')
        r.run(['systemctl', 'start', 'vpn-stack-xray.service'], 'TEST_BOOT_RECOVERY_FAILED', timeout=120)
        deadline = time.monotonic() + 60
        while not r.record(u.journal_path(i)).get('services_restored', False) and time.monotonic() < deadline:
            time.sleep(.1)
        assert r.record(u.journal_path(i))['services_restored']
        assert r.record(u.journal_path(i))['status'] == 'rolled_back'
        assert (r.DATA / 'current').resolve() == active
        for path, raw in {**originals, **before}.items():
            assert path.read_bytes() == raw, 'BOOT_RECOVERY_CHANGED_SNAPSHOT'
        for name in u.CORE:
            assert r.unit_state(name)['ActiveState'] == 'active', 'SERVICE_NOT_RESTORED'
        # Emulate the remainder of multi-user boot for the enabled timers/path.
        r.run(['systemctl', 'start', *u.TRIGGERS], 'TEST_BOOT_TRIGGERS_FAILED')
        r.wait_backend(r.modules(), r.active()[1]['counts'])
        u.ready_dns()
        status = subprocess.run([str(i.CLI), 'status'], check=True, capture_output=True, text=True)
        status_report = json.loads(status.stdout.split('VPN_STACK_REPORT=', 1)[1])
        assert status_report['status'] == 'healthy' and status_report['upgrade']['status'] == 'rolled_back'
        matrix = crash_matrix(u, i, r, variant, originals)
        report = {'actual_installed_previous_worker_and_CLI_blocked': previous_worker_blocked, 'legacy_pending_journal_recovered': legacy_pending, 'crash_matrix': matrix, 'previous_revision': os.environ.get('PREVIOUS_REVISION'), 'status': 'passed', 'systemd': subprocess.check_output(['systemctl', '--version'], text=True).splitlines()[0],
                  'architecture': os.uname().machine, 'successful_upgrade': True, 'boot_graph_has_no_ordering_cycles': True, 'native_MRS_and_DNS': True,
                  'boot_guard_recovers_missing_lib': True, 'keys_profiles_personal_rules_preserved': True,
                  'CLI_status_after_recovery': 'healthy',
                  'scope': 'ARM64 systemd, native Mihomo and HTTP, synthetic sources/local DNS; diagnostic Xray/workers; no VLESS/VPS/TUN'}
        Path('/tmp/upgrade-systemd-results.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report))


if __name__ == '__main__':
    main()
