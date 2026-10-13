#!/usr/bin/env python3
"""Reboot follow-up for check-upgrade-systemd-linux.py in the SAME disposable container.

python3 /repo/tests/check-upgrade-container-boot.py prepare
# From host: docker restart <disposable-container>
python3 /repo/tests/check-upgrade-container-boot.py check

The retained real rollback journal is relabeled prepared with its unchanged
before files/code/pointer. This injects a consistent pending filesystem state;
it is not a new upgrade, a filesystem crash, or a power-loss simulation.
"""
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    assert sys.platform == 'linux' and os.geteuid() == 0 and Path('/.dockerenv').is_file()
    assert Path('/proc/1/comm').read_text().strip() == 'systemd'
    project = Path('/root/vpn-upgrade-native')
    r = load('boot_runtime', project / 'target-package/vpn-stack-runtime.py')
    r.configure_paths(project)
    u = load('boot_upgrade', project / 'target-package/vpn-stack-upgrade.py')
    path = project / 'state/upgrade/transaction.json'
    snapshot = project / 'boot-check-snapshot.json'
    if sys.argv[1] == 'prepare':
        journal = r.record(path)
        assert journal['status'] == 'rolled_back' and journal['services_restored']
        watched = (r.CONFIG, project / 'state/install/installation.json', r.CODE / 'code-manifest.json',
                   project / 'state/install/identity.json', r.ETC / 'xray.json', r.ETC / 'devices.json',
                   r.ETC / 'direct.txt', r.ETC / 'proxy.txt', project / 'profiles/phone-smart.json',
                   r.HOME / 'preserve-cache')
        r.atomic(snapshot, r.dump({'hashes': {str(p): r.digest(p) for p in watched},
                                 'current': str((r.DATA / 'current').resolve())}))
        # The original fixture's local DNS thread exited with its test process.
        # Recreate that diagnostic upstream across PID 1 restart so REAL DNS
        # controls in finish_services are exercised as well as fake-IP.
        upstream = re.findall(r'^    - 127\.0\.0\.1:([0-9]+)$', r.CONFIG.read_text(), re.MULTILINE)
        assert upstream and len(set(upstream)) == 1
        script = project / 'boot-diagnostic-dns.py'
        r.atomic(script, ('import importlib.util, socketserver\nfrom pathlib import Path\n'
            'root = Path(' + repr(str(project / 'target-package')) + ')\n'
            'def load(name):\n'
            '    spec = importlib.util.spec_from_file_location(name, root / (name + ".py"))\n'
            '    module = importlib.util.module_from_spec(spec)\n'
            '    spec.loader.exec_module(module)\n'
            '    return module\n'
            'pilot = load("personal-checker")\npilot.MockDNS.helper = load("dns-wire")\n'
            'with socketserver.ThreadingUDPServer(("127.0.0.1", ' + upstream[0] + '), pilot.MockDNS) as server:\n'
            '    server.serve_forever()\n').encode())
        unit = 'vpn-test-dns-upstream.service'
        r.atomic(Path('/etc/systemd/system') / unit, ('[Unit]\nDefaultDependencies=no\nAfter=local-fs.target\n'
            'Before=' + u.BOOT_UNIT + ' shutdown.target\nConflicts=shutdown.target\n'
            'RequiresMountsFor=' + str(project) + '\n'
            '[Service]\nExecStart=/usr/bin/python3 ' + str(script) + '\n'
            '[Install]\nWantedBy=multi-user.target\n').encode(), 0o644)
        subprocess.run(['systemctl', 'daemon-reload'], check=True)
        subprocess.run(['systemctl', 'enable', '--now', unit], check=True)
        journal.update(status='prepared', services_restored=False)
        # The same files and code as the saved before snapshots are still live.
        r.atomic(path, r.dump(journal))
        print('DISPOSABLE_CONTAINER_READY_FOR_RESTART')
    else:
        assert sys.argv[1] == 'check'
        deadline = time.monotonic() + 60
        while not r.record(path).get('services_restored') and time.monotonic() < deadline:
            time.sleep(.1)
        journal = r.record(path)
        assert journal['status'] == 'rolled_back' and journal['services_restored'], journal['status']
        before = r.record(snapshot)
        for name, digest in before['hashes'].items():
            assert r.digest(Path(name)) == digest, name
        assert str((r.DATA / 'current').resolve()) == before['current']
        for name in (*u.CORE, *u.TRIGGERS):
            assert r.unit_state(name)['ActiveState'] == 'active', name
        u.ready_dns()
        evidence = u.ready_policy(r)
        graph = subprocess.run(['systemd-analyze', 'verify', 'multi-user.target'], capture_output=True, check=True)
        assert b'ordering cycle' not in graph.stderr.lower()
        report = {'status': 'passed', 'systemd_PID1_restarted': True, 'core_and_triggers_restored': True,
                  'DNS_response_verified': True, 'snapshot_hashes_preserved': True,
                  'policy_verification': evidence,
                  'no_boot_ordering_cycles': True,
                  'scope': 'real container restart, injected consistent pending state from retained rollback journal; no FS power loss'}
        r.atomic(project / 'boot-check-report.json', r.dump(report))
        print(json.dumps(report))


if __name__ == '__main__':
    main()
