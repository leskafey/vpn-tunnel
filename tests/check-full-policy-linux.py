#!/usr/bin/env python3
"""Build full public policies with native binaries in a DISPOSABLE Linux container.

Requires /repo, /native-binaries, /native-checksums.json and /results.
Downloads real domain/ad and official IP sources. Uses the packaged baselines.
Compiles every MRS and verifies the complete roundtrip; does not activate a
policy or run systemd/VLESS/TUN. Keeps failed inputs/logs inside the container.
Run in a fresh container: /root/full-policy-check must not already exist.
"""
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import zipfile


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def main():
    assert Path('/.dockerenv').is_file() and os.geteuid() == 0
    os.umask(0o077)
    project = Path('/root/full-policy-check')
    project.mkdir(mode=0o700)
    bundle = load('bundle', Path('/repo/install-vpn.py'))
    code = project / 'lib'
    code.mkdir()
    payload = base64.b85decode(bundle.PAYLOAD)
    assert hashlib.sha256(payload).hexdigest() == bundle.PAYLOAD_SHA
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        for name in archive.namelist():
            assert Path(name).name == name
            (code / name).write_bytes(archive.read(name))
    (code / 'bin').mkdir()
    checksums = json.loads(Path('/native-checksums.json').read_bytes())
    for name, expected in checksums.items():
        source = Path('/native-binaries') / name
        assert hashlib.sha256(source.read_bytes()).hexdigest() == expected
        shutil.copyfile(source, code / 'bin' / name)
        (code / 'bin' / name).chmod(0o755)
    r = load('runtime', code / 'vpn-stack-runtime.py')
    r.configure_paths(project)
    r.GROUP = 'root'
    for path in (r.ETC, r.DATA, r.HOME):
        path.mkdir(parents=True)
    r.atomic(r.ETC / 'settings.json', r.dump({'server_ip': '9.9.9.9'}))
    i = load('installer', code / 'vpn-stack-install.py')
    i.create_rule_files(r)
    s = r.modules()
    work = r.DATA / 'full-generation'
    work.mkdir()
    manifest = r.make_full(s, work)
    raw, ip = r.fetch_ips(s)
    manifest['ip'] = ip
    r.atomic(work / 'manifest.json', r.dump(manifest))
    report = {
        'status': 'passed',
        'scope': 'full domain/ad MRS build and complete roundtrip with live external sources and verified binaries; live official IP sources; no activation/systemd/VLESS',
        'reported_architecture': os.uname().machine,
        'standalone_sha256': hashlib.sha256(Path('/repo/install-vpn.py').read_bytes()).hexdigest(),
        'binary_sha256': checksums,
        'files': manifest['files'],
        'source_metadata': manifest['source_metadata'],
        'ip': ip,
    }
    Path('/results/full-policy.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report), flush=True)


if __name__ == '__main__':
    main()
