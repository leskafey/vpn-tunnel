#!/usr/bin/env python3
"""Deterministically package public code only into one shareable Python script."""
import ast
import base64
import hashlib
import io
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parent.parent
HERE = ROOT / 'src'
FILES = ('closed-probe.py', 'dns-wire.py', 'domain-extras.py', 'ip-source.py', 'personal-checker.py', 'personal-policy.py', 'personal-runtime.py', 'runtime-checker.py', 'source-parser.py', 'text-builder.py', 'transport-probes.py', 'vpn-stack-install.py', 'vpn-stack-manage.py', 'vpn-stack-runtime.py')


def package():
    files = {name: (HERE / name).read_bytes() for name in FILES}
    for raw in files.values():
        ast.parse(raw)
    manifest = {'files': {name: hashlib.sha256(raw).hexdigest() for name, raw in files.items()}}
    files['code-manifest.json'] = (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, raw in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=(2026, 10, 11, 0, 0, 0))
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, raw)
    return buf.getvalue(), files


HEADER = '''#!/usr/bin/env python3
"""Standalone VPN installer: Ubuntu 24.04 x86_64. Public code; no embedded keys.

python3 install-vpn.py audit
python3 install-vpn.py install --server-ip PUBLIC_IPV4
"""
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import zipfile
sys.dont_write_bytecode = True
'''
FOOTER = '''
def main():
    if len(sys.argv) == 1 or any(a in ('-h', '--help') for a in sys.argv[1:]):
        print(__doc__ + "\\n--resume: continue this script's interrupted installation, preserving identities.")
        return 0
    raw = base64.b85decode(PAYLOAD)
    if hashlib.sha256(raw).hexdigest() != PAYLOAD_SHA:
        raise ValueError('PACKAGE_PAYLOAD_CHANGED')
    project = Path(__file__).resolve().parent
    with tempfile.TemporaryDirectory(prefix='.vpn-package-', dir=project) as directory:
        folder = Path(directory)
        folder.chmod(0o700)
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            names = archive.namelist()
            if len(names) != len(set(names)) or any(Path(n).name != n for n in names):
                raise ValueError('PACKAGE_MEMBER_INVALID')
            if sum(a.file_size for a in archive.infolist()) > 1048576:
                raise ValueError('PACKAGE_SIZE_LIMIT')
            for name in names:
                path = folder / name
                path.write_bytes(archive.read(name))
                path.chmod(0o600)
        expected = json.loads((folder / 'code-manifest.json').read_bytes())['files']
        if set(names) != set(expected) | {'code-manifest.json'}:
            raise ValueError('PACKAGE_MANIFEST_MISMATCH')
        for name, checksum in expected.items():
            if hashlib.sha256((folder / name).read_bytes()).hexdigest() != checksum:
                raise ValueError('PACKAGE_CODE_CHANGED')
        spec = importlib.util.spec_from_file_location('vpn_standalone_installer', folder / 'vpn-stack-install.py')
        installer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(installer)
        installer.main(folder, project=project)
    return 0

if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        report = {'status': 'failed', 'error_type': type(error).__name__}
        code = str(error)
        if code and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789' for c in code):
            report['code'] = code
        print('VPN_STACK_REPORT=' + json.dumps(report), flush=True)
        sys.exit(1)
'''


def build(check=False):
    raw, _ = package()
    encoded = base64.b85encode(raw).decode('ascii')
    body = HEADER + '\nPAYLOAD_SHA = ' + repr(hashlib.sha256(raw).hexdigest()) + '\nPAYLOAD = (\n'
    body += ''.join('    ' + repr(encoded[i:i + 100]) + '\n' for i in range(0, len(encoded), 100)) + ')\n' + FOOTER
    ast.parse(body)
    path = ROOT / 'install-vpn.py'
    if check:
        if not path.is_file() or path.read_bytes() != body.encode():
            raise SystemExit('STANDALONE_INSTALLER_OUT_OF_DATE: run ./scripts/build.sh')
    else:
        path.write_text(body)
        path.chmod(0o644)
    print('STANDALONE_INSTALLER_BUILT; bytes=' + str(path.stat().st_size)
          + '; sha256=' + hashlib.sha256(path.read_bytes()).hexdigest())


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='Verify that the committed installer matches source')
    build(parser.parse_args().check)
