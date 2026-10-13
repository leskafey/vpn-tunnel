#!/usr/bin/env python3
"""Lost upgrade/guardian/finish processes with real systemd, Mihomo and DNS.

Called by check-upgrade-systemd-linux.py with ACTIVATION_SCENARIO=1.
Uses the authentic installed a62ad73 package, local synthetic sources/upstream,
diagnostic Xray/workers and fault-injection shims around unchanged engines.
No VPS, power loss or full VLESS test.
"""
import json
import os
from pathlib import Path
import subprocess
from unittest.mock import patch

from importlib.util import spec_from_file_location, module_from_spec


def load(path):
    spec = spec_from_file_location('activation_p1_helpers', path)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def checkpoint(u, i, r, unit, body):
    """Instrument the loader command, without changing the verified engine."""
    marker = i.PROJECT / 'activation-checkpoint'
    if marker.exists():
        marker.unlink()
    loader = i.PROJECT / 'state/upgrade' / u.LOADER
    invocation = ('    module.guardian(root.parent.parent, package)' if unit == u.GUARDIAN_UNIT
                  else "    module.boot_recover(root.parent.parent, package, services='--services' in sys.argv)")
    shim = i.PROJECT / 'activation-fault.py'
    r.atomic(shim, ('from pathlib import Path\n'
        'loader = Path(' + repr(str(loader)) + ')\n'
        'text = loader.read_text().replace(' + repr(invocation) + ', ' + repr(body + '\n' + invocation) + ')\n'
        'exec(compile(text, str(loader), "exec"), {"__file__": str(loader)})\n').encode())
    directory = i.UNIT_ROOT / (unit + '.d')
    directory.mkdir(exist_ok=True)
    dropin = directory / '99-activation-checkpoint.conf'
    flag = '--guardian' if unit == u.GUARDIAN_UNIT else '--services'
    r.atomic(dropin, ('[Service]\nExecStart=\nExecStart=/usr/bin/python3 ' + str(shim) + ' ' + flag + '\n').encode(), 0o644)
    r.run(['systemctl', 'daemon-reload'], 'CHECKPOINT_RELOAD_FAILED')
    return marker, dropin


def check(u, i, r, package, originals, make_policy, local_config, probes):
    assert Path('/.dockerenv').is_file() and os.geteuid() == 0
    assert os.environ['PREVIOUS_REVISION'] == 'a62ad73'
    helpers = load(Path(__file__).with_name('check-upgrade-p1-linux.py'))
    matrix = []
    for variant in ('provider-set', 'same-counts'):
        for point in ('dns-config', 'mihomo-start', 'activate', 'rollback-file', 'service-restart', 'service-verification'):
            before = {p: p.read_bytes() for p in (r.CONFIG, i.STATE, r.CODE / 'code-manifest.json')}
            old, old_manifest = r.active()
            def stage(installer, runtime, code, work, previous):
                staged = installer.load_runtime(code)
                staged.CODE = code
                local_config(staged)
                services = staged.modules()
                staged.probes = lambda *a, **kw: probes(staged, *a, **kw)
                manifest = make_policy(staged, services, work, 'same-counts' if variant == 'same-counts' else True)
                atomic, run, activate = staged.atomic, staged.run, staged.activate
                def die():
                    helpers.pause_guardian(u, staged)
                    os._exit(73)
                def write(path, raw, *a, **kw):
                    atomic(path, raw, *a, **kw)
                    if path == staged.CONFIG and point == 'dns-config':
                        die()
                def command(args, *a, **kw):
                    result = run(args, *a, **kw)
                    if args == ['systemctl', 'restart', staged.UNIT] and point == 'mihomo-start':
                        die()
                    return result
                def activated(*a, **kw):
                    result = activate(*a, **kw)
                    assert result['status'] == 'active'
                    die()
                staged.atomic, staged.run, staged.activate = write, command, activated
                return staged, services, manifest
            child = os.fork()
            if child == 0:
                try:
                    with patch.object(u, 'stage_policy', side_effect=stage):
                        u.upgrade(package, i)
                except BaseException:
                    import traceback
                    traceback.print_exc()
                    os._exit(98)
                os._exit(99)
            _, status = os.waitpid(child, 0)
            assert os.waitstatus_to_exitcode(status) == 73, (variant, point)
            assert r.record(u.journal_path(i))['status'] == 'applying'
            assert u.guardian_stored(r) and helpers.locked(u, i, r)
            def pid():
                return r.run(['systemctl', 'show', r.UNIT, '--property=MainPID', '--value'], 'PID_QUERY').strip()
            pid_before = pid()
            if point != 'dns-config':
                services = r.modules()
                if variant == 'same-counts':
                    r.wait_backend(services, old_manifest['counts'])
                    # Counts falsely accept this policy. DNS and REJECT differ.
                    for protocol in ('tcp', 'udp'):
                        values = u.policy_dns(services, 'ads.example', protocol)
                        assert all(services.setup.ipaddress.ip_address(value) not in services.setup.FAKE_POOL for value in values)
                else:
                    helpers.until(lambda: r.unit_state(r.UNIT)['ActiveState'] == 'active', 'NEW_BACKEND_INACTIVE')
            dropin = None
            if point == 'rollback-file':
                body = ('    original = module.recovery_modules\n'
                    '    def modules(*args):\n'
                    '        i, r = original(*args)\n'
                    '        atomic = r.atomic\n'
                    '        def write(path, raw, *a, **kw):\n'
                    '            atomic(path, raw, *a, **kw)\n'
                    '            if path == r.CONFIG:\n'
                    '                Path(' + repr(str(i.PROJECT / 'activation-checkpoint')) + ').write_text("ready")\n'
                    '                os.kill(os.getpid(), 19)\n'
                    '        r.atomic = write\n'
                    '        return i, r\n'
                    '    module.recovery_modules = modules')
                marker, dropin = checkpoint(u, i, r, u.GUARDIAN_UNIT, body)
            elif point == 'service-restart':
                body = ('    original = module.recovery_modules\n'
                    '    def modules(*args):\n'
                    '        i, r = original(*args)\n'
                    '        run = r.run\n'
                    '        def command(args, *a, **kw):\n'
                    '            result = run(args, *a, **kw)\n'
                    '            if args[:2] == ["systemctl", "restart"] and "vpn-stack-dns.service" in args:\n'
                    '                Path(' + repr(str(i.PROJECT / 'activation-checkpoint')) + ').write_text("ready")\n'
                    '                os.kill(os.getpid(), 19)\n'
                    '            return result\n'
                    '        r.run = command\n'
                    '        return i, r\n'
                    '    module.recovery_modules = modules')
                marker, dropin = checkpoint(u, i, r, u.FINISH_UNIT, body)
            elif point == 'service-verification':
                body = ('    original = module.ready_policy\n'
                    '    def verify(r):\n'
                    '        result = original(r)\n'
                    '        Path(' + repr(str(i.PROJECT / 'activation-checkpoint')) + ').write_text("ready")\n'
                    '        os.kill(os.getpid(), 19)\n'
                    '        return result\n'
                    '    module.ready_policy = verify')
                marker, dropin = checkpoint(u, i, r, u.FINISH_UNIT, body)
            r.run(['systemctl', 'kill', '--kill-whom=main', '--signal=SIGKILL', u.GUARDIAN_UNIT], 'GUARDIAN_KILL_FAILED')
            if dropin:
                helpers.until(marker.exists, 'RECOVERY_CHECKPOINT_NOT_REACHED')
                assert not r.record(u.journal_path(i)).get('services_restored', False)
                unit = u.GUARDIAN_UNIT if point == 'rollback-file' else u.FINISH_UNIT
                if point == 'rollback-file':
                    assert u.guardian_stored(r) and helpers.locked(u, i, r)
                else:
                    with r.lock():
                        pass  # dependent workers can take it during finish.
                dropin.unlink()
                r.run(['systemctl', 'daemon-reload'], 'CHECKPOINT_RELOAD_FAILED')
                r.run(['systemctl', 'kill', '--kill-whom=main', '--signal=SIGKILL', unit], 'CHECKPOINT_KILL_FAILED')
                if point in ('service-restart', 'service-verification'):
                    helpers.until(lambda: r.unit_state(unit)['ActiveState'] == 'failed', 'FINISH_NOT_FAILED')
                    personal = r.ETC / 'direct.txt'
                    r.atomic(personal, personal.read_bytes() + b'\n# user annotation during service retry\n')
                    originals[personal] = personal.read_bytes()
                    assert u.upgrade(package, i, True)['status'] == 'recovered'
            helpers.settled(u, i, r)
            assert pid() != pid_before
            assert r.active()[0] == old
            evidence = u.ready_policy(r)
            assert evidence['DNS_TCP_UDP_checks'] >= 12 and evidence['REJECT_checks'] > 0
            services = r.modules()
            for protocol in ('tcp', 'udp'):
                values = u.policy_dns(services, 'ads.example', protocol)
                services.setup.require_fake(values)
                services.checker.reject_destination(services.wire, 19080, values[0])
                services.setup.require_fake(u.policy_dns(services, 'proxy.example', protocol))
            for p, raw in {**before, **originals}.items():
                assert p.read_bytes() == raw, (variant, point, p)
            assert u.upgrade(package, i, True)['status'] == 'unchanged'
            row = {'variant': variant, 'point': point, 'status': 'passed', 'new_PID': True,
                   'restored_generation': evidence, 'repeat_recovery': True}
            matrix.append(row)
            print('ACTIVATION_BOUNDARY=' + variant + ':' + point, flush=True)
    report = {'status': 'passed', 'previous_revision': 'a62ad73', 'matrix': matrix,
              'systemd': subprocess.check_output(['systemctl', '--version'], text=True).splitlines()[0], 'scope': __doc__}
    Path('/tmp/activation-results.json').write_text(json.dumps(report, indent=2) + '\n')
    print('ACTIVATION_NATIVE_RESULT=' + json.dumps(report), flush=True)
