#!/usr/bin/env python3
"""Isolated Mihomo 1.19.31 DNS/SOCKS check on macOS or Linux; no VPS access.

python3 tests/check-ad-policy-native.py --mihomo /path/to/mihomo [--output report.json]
The only upstream is local MockDNS. macOS has no /proc: process RSS and Linux
listener ownership checks are omitted there. No TUN, systemd or YouTube test.
"""
import argparse
from contextlib import ExitStack
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parent.parent


def load(name):
    spec = importlib.util.spec_from_file_location('native_ad_' + name.replace('-', '_'), ROOT / 'src' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument('--mihomo', type=Path, required=True)
    args.add_argument('--output', type=Path)
    options = args.parse_args()
    binary = options.mihomo.resolve(strict=True)
    version = subprocess.run([str(binary), '-v'], check=True, capture_output=True, text=True).stdout
    assert 'v1.19.31 ' in version, 'PINNED_MIHOMO_REQUIRED'
    r, core, personal, checker, wire, pilot, setup, ad, parser = [load(name) for name in (
        'vpn-stack-runtime', 'personal-policy', 'personal-runtime', 'runtime-checker', 'dns-wire',
        'personal-checker', 'transport-probes', 'ad-policy', 'source-parser')]
    s = SimpleNamespace(setup=setup, core=core, wire=wire, checker=checker,
                        builder=SimpleNamespace(atomic_json=lambda path, value: path.write_text(json.dumps(value))),
                        refresh=SimpleNamespace(BINARY=binary))
    scenarios = []
    with tempfile.TemporaryDirectory(prefix='vpn-ad-native-') as folder, ExitStack() as stack:
        root = Path(folder)
        if sys.platform != 'linux':
            stack.enter_context(patch.object(wire, 'check_listeners'))
            stack.enter_context(patch.object(checker, 'rss', return_value={}))
        original_witnesses = checker.witnesses
        def witnesses():
            values = original_witnesses()
            values['public_names'] = (*values['public_names'], 'disabled.example',
                'allowed.ads.example', 'child.allowed.ads.example', 'exact.ads.example',
                'child.exact.ads.example', 'important.ads.example', 'child.important.ads.example',
                'manual.example', 'child.manual.example', 'collision.example', 'child.collision.example')
            return values
        stack.enter_context(patch.object(checker, 'witnesses', side_effect=witnesses))
        cases = [
            ('legacy', False, {'proxy': [], 'direct': [], 'ads-exceptions': []}),
            ('upstream-exceptions-important-badfilter', True,
             {'proxy': [], 'direct': [], 'ads': [], 'ads-exceptions': []}),
            ('personal-block-overrides-upstream-and-direct', True,
             {'proxy': [], 'direct': ['manual.example'], 'ads': ['allowed.ads.example', 'manual.example'], 'ads-exceptions': []}),
            ('personal-exceptions-override-all-blocks', True,
             {'proxy': [], 'direct': ['manual.example'], 'ads': ['manual.example'],
              'ads-exceptions': ['important.ads.example', 'manual.example']})]
        for index, (label, extended, values) in enumerate(cases):
            work = root / 'generations' / ('gen-' + str(index))
            (work / 'assets').mkdir(parents=True)
            # The production parser is exercised here, including exact/suffix
            # exceptions and a disabled rule preceding the original block.
            raw = work / 'source.txt'
            raw.write_text('||ads.example^\n||disabled.example^$badfilter\n||disabled.example^\n'
                '||collision.example^\n||collision.example^|\n||collision.example^$badfilter\n'
                '@@||allowed.ads.example^|\n@@|exact.ads.example^|\n'
                '@@||important.ads.example^\n||important.ads.example^$important\n'
                + ''.join('||padding' + str(n) + '.example^\n' for n in range(10000)))
            paths, counts = ad.normalize(parser, 'adguard-dns', raw, work)
            assert '+.collision.example' in paths['block'].read_text().splitlines()
            assert '+.disabled.example' not in paths['block'].read_text().splitlines()
            assert counts['disabled'] == 2
            sources = {'smart': '+.instagram.com\n+.proxy.example\n', 'direct': '+.direct.example\n',
                       'ads': paths['block'].read_text()}
            if extended:
                sources.update({'ads-allow': paths['allow'].read_text(), 'ads-important': paths['important'].read_text()})
            files = {}
            for tag, body in sources.items():
                source = work / (tag + '.normalized.txt')
                source.write_text(body)
                target = work / 'assets' / (tag + '.mrs')
                subprocess.run([str(binary), 'convert-ruleset', 'domain', 'text', str(source), str(target)],
                               check=True, capture_output=True)
                # Count converted rules rather than assume native normalization.
                recovered = work / (tag + '.roundtrip.txt')
                subprocess.run([str(binary), 'convert-ruleset', 'domain', 'mrs', str(target), str(recovered)],
                               check=True, capture_output=True)
                assert set(recovered.read_text().splitlines()) == set(body.splitlines()), 'MRS_ROUNDTRIP_CHANGED'
                files[tag + '.mrs'] = {'normalized_patterns': len(body.splitlines()),
                                      'sha256': hashlib.sha256(target.read_bytes()).hexdigest()}
            result = personal.runtime_check(s, core, pilot, work, {'files': files}, values, r.base_config(s, work))
            scenarios.append({'scenario': label, **result})
    report = {'status': 'passed', 'platform': sys.platform, 'mihomo_version': version.strip(),
              'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'scenarios': scenarios,
              'scope': 'local synthetic DNS TCP/UDP and blocked SOCKS; no VPS/systemd/TUN/YouTube'}
    if options.output:
        options.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
