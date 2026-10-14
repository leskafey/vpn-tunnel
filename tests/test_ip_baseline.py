"""Task 3: real IP parsers, installed packages and policy transactions; offline native fixtures."""
import ast
import base64
from contextlib import redirect_stdout
import hashlib
import io
import ipaddress
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import zipfile

from test_installer import b, i, load, r
import test_installer as installer
import test_local_baseline as baseline
import test_project_layout as layout
import test_repeat_review as repeat
import test_recovery_engine_migration as migration
import test_upgrade as upgrade

ROOT = Path(__file__).resolve().parent.parent
SNAPSHOTS = ROOT / 'tests/fixtures/antizapret-independence/2026-10-14'
IP = load('independent_ip_sources', 'ip-source.py')
MODULES, INITIAL, STAGE, LOAD_RUNTIME = r.modules, i.initial_generation, upgrade.u.stage_policy, i.load_runtime
OFFICIAL = {r.IP_SOURCES['telegram']: (SNAPSHOTS / 'official/telegram-cidr.txt').read_bytes(),
            r.IP_SOURCES['cloudflare']: (SNAPSHOTS / 'official/cloudflare-ips-v4.txt').read_bytes()}


def intervals(networks):
    """Independent interval union, including nested/overlapping input CIDRs."""
    result = []
    for start, end in sorted((int(n.network_address), int(n.broadcast_address)) for n in networks):
        if result and start <= result[-1][1] + 1:
            result[-1] = (result[-1][0], max(end, result[-1][1]))
        else:
            result.append((start, end))
    return result


def json_networks(raw):
    return [ipaddress.ip_network(c) for rule in json.loads(raw)['rules'] for c in rule['ip_cidr']]


def historical_package(destination):
    fixture = ROOT / 'tests/fixtures/previous-packages'
    raw = (fixture / 'f6e5d85.zip').read_bytes()
    metadata = json.loads((fixture / 'f6e5d85.json').read_bytes())
    assert metadata['commit'] == 'f6e5d85a677014a566b8c9772095280520ccbfb7'
    assert hashlib.sha256(raw).hexdigest() == metadata['package_sha256']
    destination.mkdir(mode=0o700)
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        for name in archive.namelist():
            assert Path(name).name == name
            r.atomic(destination / name, archive.read(name))
    return destination


class SourceTests(unittest.TestCase):
    def test_only_official_IP_endpoints_and_redirects_allowed(self):
        for url in (*OFFICIAL, 'https://www.cloudflare.com/ips-v4'):
            IP.allowed_url(url)
        for url in ('http://core.telegram.org/resources/cidr.txt',
                    'https://core.telegram.org/other', 'https://www.cloudflare.com/ips-v6/',
                    'https://core.telegram.org/resources/cidr.txt?x=1',
                    'https://www.cloudflare.com:444/ips-v4/',
                    'https://user@core.telegram.org/resources/cidr.txt',
                    'https://api.github.com/repos/GubernievS/AntiZapret-VPN/git/ref/heads/main',
                    'https://raw.githubusercontent.com/GubernievS/AntiZapret-VPN/main/file'):
            with self.subTest(url=url), self.assertRaisesRegex(IP.CandidateError, 'SOURCE_URL_NOT_ALLOWED'):
                IP.allowed_url(url)
            with self.assertRaises(IP.CandidateError):
                IP.Redirect().redirect_request(None, None, 302, '', {}, url)

    def test_download_validates_HTTP_final_URL_and_bounded_nonempty_body(self):
        for status, url, raw in ((503, next(iter(OFFICIAL)), b'error'),
                                 (200, 'https://example.org/file', b'8.8.8.0/24'),
                                 (200, next(iter(OFFICIAL)), b''),
                                 (200, next(iter(OFFICIAL)), b'x' * (IP.SOURCE_LIMIT + 1)),
                                 (200, next(iter(OFFICIAL)), OFFICIAL[next(iter(OFFICIAL))])):
            response = Mock(status=status, url=url)
            response.read.return_value = raw
            response.__enter__ = Mock(return_value=response)
            response.__exit__ = Mock(return_value=False)
            opener = Mock()
            opener.open.return_value = response
            with patch.object(IP.urllib.request, 'build_opener', return_value=opener):
                if status == 200 and url in OFFICIAL and raw == OFFICIAL[url]:
                    self.assertEqual(IP.download(url), raw)
                    response.read.assert_called_once_with(IP.SOURCE_LIMIT + 1)
                else:
                    with self.assertRaises(IP.CandidateError):
                        IP.download(next(iter(OFFICIAL)))

    def test_official_telegram_IPv6_validated_and_ignored_cloudflare_is_IPv4_only(self):
        tg4, tg6 = IP.parse_source(OFFICIAL[r.IP_SOURCES['telegram']], official='telegram')
        self.assertEqual((len(tg4), len(tg6)), (9, 5))
        cf4, cf6 = IP.parse_source(OFFICIAL[r.IP_SOURCES['cloudflare']], official='cloudflare')
        self.assertEqual((len(cf4), len(cf6)), (15, 0))
        for name, suffix in (('telegram', b'\n::1/128\n'), ('telegram', b'\n2001::/16\n'),
                             ('cloudflare', b'\n2606:4700::/32\n')):
            with self.subTest(name=name, suffix=suffix), self.assertRaises(IP.CandidateError):
                IP.parse_source(OFFICIAL[r.IP_SOURCES[name]] + suffix, official=name)

    def test_invalid_empty_nonpublic_duplicate_and_oversized_sources_rejected(self):
        for raw in (b'', b'# comments only\n', b'\xff', b'<html>maintenance</html>',
                    b'8.8.8.1/24', b'8.8.8.0', b'8.8.8.0 /24', b'10.0.0.0/12',
                    b'224.0.0.0/12', b'240.0.0.0/12', b'198.18.0.0/16', b'8.0.0.0/8',
                    b'8.8.8.0/24\n8.8.8.0/24', b'2606:4700::/32', b'x' * (IP.SOURCE_LIMIT + 1),
                    b''.join(f'8.8.{n // 256}.{n % 256}/32\n'.encode() for n in range(257))):
            with self.subTest(raw=raw[:45]), self.assertRaises(IP.CandidateError):
                IP.parse_source(raw)
        for name in r.IP_SOURCES:
            with self.assertRaises(IP.CandidateError):
                IP.parse_source(b'8.8.8.0/24', official=name)


class CoverageTests(unittest.TestCase):
    setUp = installer.TemporaryRuntimeTests.setUp
    package = baseline.BaselineTests.package

    def services(self):
        s = self.package()
        s.ip = IP
        return s

    def test_snapshot_per_service_and_total_address_coverage_is_unchanged(self):
        s = self.services()
        old = []
        for name in ('telegram', 'cloudflare', 'discord', 'whatsapp'):
            path = (SNAPSHOTS / 'upstream' / (name + '-ips.txt')) if name in r.IP_SOURCES else (ROOT / 'lists/baseline' / (name + '-ips.txt'))
            before = IP.parse_source(path.read_bytes())[0]
            if name in r.IP_SOURCES:
                after = IP.parse_source(OFFICIAL[r.IP_SOURCES[name]], official=name)[0]
                after += IP.parse_source(s.baseline_source(name + '-extra-ips.txt')[0])[0]
            else:
                after = IP.parse_source(s.baseline_source(name + '-ips.txt')[0])[0]
            self.assertEqual(intervals(after), intervals(before), name)
            old.extend(before)
        with patch.object(IP, 'download', side_effect=OFFICIAL.__getitem__) as download:
            raw, info = r.fetch_ips(s, r.ip_body(old)[0])
        self.assertEqual(intervals(json_networks(raw)), intervals(old))
        self.assertEqual(sum(end - start + 1 for start, end in intervals(old)), 3699968)
        self.assertEqual([c.args[0] for c in download.call_args_list], list(r.IP_SOURCES.values()))
        self.assertNotIn('commit', info)
        self.assertEqual(set(info['sources']), {*r.IP_SOURCES, *r.IP_BASELINES})
        self.assertEqual(info['sources']['telegram']['ignored_IPv6_CIDRs'], 5)
        for name, filename in r.IP_BASELINES.items():
            self.assertEqual(info['sources'][name]['sha256'], r.digest(self.code / filename))
        self.assertTrue(all(n.version == 4 for n in json_networks(raw)))

    def test_nested_overlapping_adjacent_and_duplicate_networks_merge_by_coverage(self):
        networks = IP.parse_source(b'8.8.0.0/16\n8.8.8.0/24\n8.9.0.0/16\n')[0]
        raw, count = r.ip_body(networks + networks)
        self.assertEqual((count, [str(n) for n in json_networks(raw)]), (1, ['8.8.0.0/15']))
        s = self.services()
        with patch.object(IP, 'download', side_effect=OFFICIAL.__getitem__):
            raw, _ = r.fetch_ips(s)
            # A noncanonical historical representation must not double-count
            # overlaps or make equivalent subnet splitting appear as a change.
            nets = json_networks(raw)
            rows = [str(n) for n in nets] + [str(n) for n in nets[0].subnets()]
            prior = json.dumps({'rules': [{'ip_cidr': rows}]}).encode()
            self.assertEqual(r.fetch_ips(s, prior)[0], raw)

    def test_loss_and_growth_guards_compare_address_coverage(self):
        s = self.services()
        with patch.object(IP, 'download', side_effect=OFFICIAL.__getitem__):
            raw, _ = r.fetch_ips(s)
            with self.assertRaisesRegex(r.StackError, 'IP_PREVIOUS_COVERAGE_REMOVED'):
                r.fetch_ips(s, r.ip_body(json_networks(raw) + [ipaddress.ip_network('8.8.8.0/24')])[0])
            with self.assertRaisesRegex(r.StackError, 'IP_COVERAGE_GROWTH_GUARD'):
                r.fetch_ips(s, r.ip_body([ipaddress.ip_network('104.16.0.0/13')])[0])

    def test_personal_rules_merge_without_polluting_automatic_metadata_or_legacy_commit(self):
        s = self.services()
        with patch.object(IP, 'download', side_effect=OFFICIAL.__getitem__):
            automatic, info = r.fetch_ips(s)
        info['commit'] = 'a' * 40  # Accepted historical generation metadata.
        personal = '# Личные правила\n8.8.8.0/24\n8.8.8.8/32\n104.16.0.0/16\n8.8.8.0/24\n'.encode()
        r.atomic(r.ETC / r.IP_FILE, personal)
        raw, combined = r.combined_ips(info)
        self.assertEqual(intervals(json_networks(raw)), intervals(json_networks(automatic) + [ipaddress.ip_network('8.8.8.0/24')]))
        self.assertEqual(combined['source_CIDRs'], info['source_CIDRs'])
        self.assertEqual(combined['commit'], 'a' * 40)
        self.assertEqual(combined['personal_CIDRs'], 3)
        self.assertEqual((r.ETC / r.IP_FILE).read_bytes(), personal)
        r.atomic(r.ETC / r.IP_FILE, b'')
        self.assertEqual(r.combined_ips(info)[0], automatic)

    def test_each_local_IP_input_is_mandatory_integrity_checked_and_parsed(self):
        s = self.services()
        with patch.object(IP, 'download', side_effect=OFFICIAL.__getitem__):
            for filename in r.IP_BASELINES.values():
                path = self.code / filename
                original = path.read_bytes()
                manifest = r.record(self.code / 'code-manifest.json')
                path.unlink()
                with self.assertRaises(OSError):
                    r.fetch_ips(s)
                path.write_bytes(b'8.8.8.0/24')
                with self.assertRaisesRegex(r.StackError, 'BASELINE_DATA_CHANGED'):
                    r.fetch_ips(s)
                for raw in (b'bad data', b'', b'# empty\n', b'10.0.0.0/12', b'\xff'):
                    path.write_bytes(raw)
                    changed = dict(manifest['files'], **{filename: hashlib.sha256(raw).hexdigest()})
                    r.atomic(self.code / 'code-manifest.json', r.dump({'files': changed}))
                    with self.assertRaises((r.StackError, IP.CandidateError)):
                        r.fetch_ips(s)
                path.write_bytes(original)
                r.atomic(self.code / 'code-manifest.json', r.dump(manifest))

    def test_result_CIDR_and_JSON_limits_include_personal_rules(self):
        s = self.services()
        with patch.object(IP, 'download', side_effect=OFFICIAL.__getitem__):
            body, info = r.fetch_ips(s)
            self.assertLessEqual(len(body), 32768)
            self.assertLessEqual(info['CIDRs'], 256)
            personal = b''.join(f'8.8.{n}.1/32\n'.encode() for n in range(256))
            r.atomic(r.ETC / r.IP_FILE, personal)
            with self.assertRaisesRegex(r.StackError, 'IP_DELIVERY_SIZE_LIMIT'):
                r.combined_ips(info)
            # Each individual source is within its bound; the union is not.
            path = self.code / 'discord-ips.txt'
            path.write_bytes(personal)
            manifest = r.record(self.code / 'code-manifest.json')
            manifest['files'][path.name] = r.digest(path)
            r.atomic(self.code / 'code-manifest.json', r.dump(manifest))
            with self.assertRaisesRegex(r.StackError, 'IP_DELIVERY_SIZE_LIMIT'):
                r.fetch_ips(s)

    def test_active_source_and_unpacked_installer_have_no_AntiZapret_network_URLs(self):
        tree = ast.parse((ROOT / 'install-vpn.py').read_bytes())
        payload = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
                       and isinstance(n.targets[0], ast.Name) and n.targets[0].id == 'PAYLOAD')
        with zipfile.ZipFile(io.BytesIO(base64.b85decode(payload))) as archive:
            for filename in b.FILES:
                for raw in ((ROOT / 'src' / filename).read_bytes(), archive.read(filename)):
                    self.assertNotIn(b'GubernievS', raw, filename)
                    self.assertNotIn(b'AntiZapret-VPN', raw, filename)


class UpdateIPTests(unittest.TestCase):
    full = repeat.ComposedCleanupTests.full
    runtime_check = repeat.ComposedCleanupTests.runtime_check

    def setUp(self):
        repeat.ComposedCleanupTests.setUp(self)
        for name, raw in b.package()[1].items():
            r.atomic(self.code / name, raw, 0o644)
        self.s.ip, self.s.baseline_source = IP, r.baseline_source
        self.download = self.enterContext(patch.object(IP, 'download', side_effect=OFFICIAL.__getitem__))
        raw, info = r.fetch_ips(self.s)
        info['commit'] = 'a' * 40
        manifest = r.record(self.assets / 'manifest.json')
        manifest['ip'] = info
        r.atomic(self.assets / 'proxy-ipv4.json', raw)
        manifest['checksums']['proxy-ipv4.json'] = r.digest(self.assets / 'proxy-ipv4.json')
        r.atomic(self.assets / 'manifest.json', r.dump(manifest))

    def watched(self):
        return {p: p.read_bytes() for p in (r.CONFIG, self.assets / 'manifest.json',
                self.assets / 'proxy-ipv4.json', r.DATA / 'last-result.json')}

    def test_daily_IP_errors_keep_whole_policy_and_never_activate_partial_sources(self):
        before = self.watched()
        old = r.active()[0]
        for failing_url in OFFICIAL:
            for failure in (OSError('source unavailable'), b'', b'<html>error</html>', b'8.8.8.0/24', b'\xff'):
                def download(url):
                    if url == failing_url:
                        if isinstance(failure, Exception):
                            raise failure
                        return failure
                    return OFFICIAL[url]
                self.download.side_effect = download
                with self.subTest(source=failing_url, failure=failure), patch.object(r, 'activate') as activate:
                    with self.assertRaises((OSError, IP.CandidateError)):
                        r.apply('ip')
                    activate.assert_not_called()
                self.assertEqual(r.active()[0], old)
                self.assertEqual(self.watched(), before)
        self.download.side_effect = OFFICIAL.__getitem__
        self.assertEqual(r.apply('ip')['status'], 'unchanged')

    def test_daily_IP_and_personal_changes_preserve_each_other_and_legacy_metadata(self):
        personal = '# Мой IP\n8.8.8.8/32\n'.encode()
        r.atomic(r.ETC / r.IP_FILE, personal)
        self.download.reset_mock()
        self.assertEqual(r.apply('personal')['status'], 'active')
        self.download.assert_not_called()
        source, manifest = r.active()
        self.assertEqual(manifest['ip']['commit'], 'a' * 40)
        urls = []
        def updated(url):
            urls.append(url)
            return OFFICIAL[url] + (b'\n8.8.4.0/24\n' if url == r.IP_SOURCES['cloudflare'] else b'')
        self.download.side_effect = updated
        self.assertEqual(r.apply('ip')['status'], 'active')
        current, updated_manifest = r.active()
        self.assertNotIn('commit', updated_manifest['ip'])
        nets = json_networks((current / 'proxy-ipv4.json').read_bytes())
        self.assertTrue(any(ipaddress.ip_address('8.8.8.8') in n for n in nets))
        self.assertTrue(any(ipaddress.ip_address('8.8.4.1') in n for n in nets))
        self.assertEqual((r.ETC / r.IP_FILE).read_bytes(), personal)
        self.assertEqual(urls, list(OFFICIAL))
        r.atomic(r.ETC / r.IP_FILE, b'')
        self.assertEqual(r.apply('personal')['status'], 'active')
        current, manifest = r.active()
        self.assertEqual((current / 'proxy-ipv4.json').read_bytes(), r.ip_body([ipaddress.ip_network(c) for c in manifest['ip']['source_CIDRs']])[0])

    def test_daily_missing_corrupt_or_invalid_local_IP_inputs_keep_whole_policy(self):
        before = self.watched()
        source = r.active()[0]
        manifest_path = self.code / 'code-manifest.json'
        original_manifest = manifest_path.read_bytes()
        manifest = r.record(manifest_path)
        for filename in r.IP_BASELINES.values():
            path = self.code / filename
            original = path.read_bytes()
            for kind in ('missing', 'corrupt', 'invalid'):
                with self.subTest(filename=filename, kind=kind):
                    if kind == 'missing':
                        path.unlink()
                    else:
                        path.write_bytes(b'bad CIDR\n')
                        if kind == 'invalid':
                            changed = dict(manifest['files'], **{filename: r.digest(path)})
                            r.atomic(manifest_path, r.dump({'files': changed}))
                    with patch.object(r, 'activate') as activate:
                        with self.assertRaises((OSError, r.StackError, IP.CandidateError)):
                            r.apply('ip')
                        activate.assert_not_called()
                    self.assertEqual(r.active()[0], source)
                    self.assertEqual(self.watched(), before)
                    path.write_bytes(original)
                    r.atomic(manifest_path, original_manifest)


class InstallIPTests(unittest.TestCase):
    setUp = installer.TemporaryRuntimeTests.setUp
    fixture = layout.InstallationTests.fixture
    full = repeat.ComposedCleanupTests.full
    runtime_check = repeat.ComposedCleanupTests.runtime_check

    def initial_fixture(self):
        project, package, generation = self.fixture()
        self.enterContext(patch.object(r, 'make_full', side_effect=self.full))
        self.enterContext(patch.object(r, 'wait_backend'))
        self.enterContext(patch.object(r, 'probes', return_value={}))
        def modules():
            s = MODULES()
            s.ip = IP
            s.personal.runtime_check = self.runtime_check
            return s
        self.enterContext(patch.object(r, 'modules', side_effect=modules))
        generation.side_effect = INITIAL
        download = self.enterContext(patch.object(IP, 'download', side_effect=OFFICIAL.__getitem__))
        return package, download

    def test_install_builds_official_and_local_IP_policy_and_delivers_all_data(self):
        package, download = self.initial_fixture()
        with redirect_stdout(io.StringIO()):
            i.install(package, '8.8.8.8', False)
        source, manifest = r.active()
        self.assertEqual(len(manifest['ip']['sources']), 6)
        self.assertNotIn('commit', manifest['ip'])
        for filename in r.IP_BASELINES.values():
            self.assertEqual((r.CODE / filename).read_bytes(), (ROOT / 'lists/baseline' / filename).read_bytes())
            self.assertFalse((r.ETC / filename).exists())
        self.assertTrue((source / 'proxy-ipv4.json').is_file())
        self.assertEqual([c.args[0] for c in download.call_args_list], list(OFFICIAL))

    def test_first_install_source_failure_is_explicit_resume_preserves_identity_and_personal_IP(self):
        package, download = self.initial_fixture()
        download.side_effect = lambda url: OFFICIAL[url] if url == r.IP_SOURCES['telegram'] else b''
        with redirect_stdout(io.StringIO()), self.assertRaisesRegex(IP.CandidateError, 'SOURCE_SIZE_LIMIT'):
            i.install(package, '8.8.8.8', False)
        self.assertFalse((r.DATA / 'current').exists())
        self.assertEqual(r.record(i.STATE)['status'], 'failed')
        identity = (i.ROOT / 'identity.json').read_bytes()
        personal = b'8.8.8.8/32\n'
        r.atomic(r.ETC / r.IP_FILE, personal)
        download.side_effect = OFFICIAL.__getitem__
        with redirect_stdout(io.StringIO()):
            i.install(package, '8.8.8.8', True)
        source, manifest = r.active()
        self.assertEqual((i.ROOT / 'identity.json').read_bytes(), identity)
        self.assertEqual((r.ETC / r.IP_FILE).read_bytes(), personal)
        self.assertEqual(manifest['ip']['personal_CIDRs'], 1)
        self.assertTrue(any(ipaddress.ip_address('8.8.8.8') in n for n in json_networks((source / 'proxy-ipv4.json').read_bytes())))


class UpgradeIPTests(unittest.TestCase):
    setUp = installer.TemporaryRuntimeTests.setUp
    fixture = upgrade.UpgradeTests.fixture
    stage_policy = upgrade.UpgradeTests.stage_policy
    activate = upgrade.UpgradeTests.activate
    run_upgrade = upgrade.UpgradeTests.run_upgrade
    assert_preserved = upgrade.UpgradeTests.assert_preserved

    def ip_fixture(self, step2=True):
        self.fixture()
        if step2:
            package = historical_package(self.root / 'step2')
            expected = r.record(package / 'code-manifest.json')['files']
            for name in r.record(r.CODE / 'code-manifest.json')['files']:
                if name not in expected:
                    (r.CODE / name).unlink()
            for name in (*expected, 'code-manifest.json'):
                r.atomic(r.CODE / name, (package / name).read_bytes(), 0o644)
            state = r.record(i.STATE)
            state['package_files'] = expected
            r.atomic(i.STATE, r.dump(state))
            self.before[i.STATE] = i.STATE.read_bytes()
            old = LOAD_RUNTIME(r.CODE)
            old.active = lambda: (self.old, self.previous)
            # Run the historical modules integrity checks with its actual manifest.
            live_code = r.CODE
            i.load_runtime.side_effect = lambda folder: old if folder == live_code else r
            root = i.PROJECT / 'state/upgrade'
            root.mkdir(mode=0o700)
            engine = root / ('engine-' + upgrade.u.checksum((package / 'code-manifest.json').read_bytes()))
            engine.mkdir(mode=0o700)
            for name in (*expected, 'code-manifest.json'):
                r.atomic(engine / name, (package / name).read_bytes())
            historical = load('step2_upgrade_engine', package / 'vpn-stack-upgrade.py')
            self.assertEqual(historical.BOOTSTRAP, upgrade.u.DOMAIN_BASELINE_BOOTSTRAP)
            for name in ('recover.py', upgrade.u.LOADER):
                r.atomic(root / name, historical.BOOTSTRAP)
            r.atomic(root / 'engine.json', r.dump({'directory': engine.name}))
        else:
            # Only the baseline edit, with code and units otherwise unchanged.
            state = r.record(i.STATE)
            for name, raw in b.package()[1].items():
                r.atomic(r.CODE / name, raw, 0o644)
            state['package_files'] = r.record(self.package / 'code-manifest.json')['files']
            for name, body in i.units(r).items():
                r.atomic(i.UNIT_ROOT / name, body.encode(), 0o644)
                state['units'][name] = r.digest(i.UNIT_ROOT / name)
            r.atomic(i.STATE, r.dump(state))
            self.before[i.STATE] = i.STATE.read_bytes()
        self.old_code = {name: (r.CODE / name).read_bytes() for name in r.record(i.STATE)['package_files']}
        self.old_manifest = (r.CODE / 'code-manifest.json').read_bytes()
        r.atomic(r.ETC / r.IP_FILE, '# Моя сеть\n8.8.8.8/32\n'.encode())
        self.preserved[r.ETC / r.IP_FILE] = (r.ETC / r.IP_FILE).read_bytes()
        self.download = self.enterContext(patch.object(IP, 'download', side_effect=OFFICIAL.__getitem__))
        services = SimpleNamespace(ip=IP, baseline_source=lambda filename:
            ((ROOT / 'lists/baseline' / filename).read_bytes(), {}))
        raw, info = r.fetch_ips(services)
        self.previous['ip'] = dict(info, commit='a' * 40)
        self.previous['ip'].pop('sources')
        r.atomic(self.old / 'proxy-ipv4.json', r.combined_ips(self.previous['ip'])[0])
        def modules():
            s = MODULES()
            s.ip = IP
            s.personal.runtime_check = lambda *args: repeat.ComposedCleanupTests.runtime_check(self, *args)
            return s
        r.modules.side_effect = modules
        self.enterContext(patch.object(r, 'make_full', side_effect=lambda *args:
            repeat.ComposedCleanupTests.full(self, *args)))
        def stage(installer, runtime, code, work, previous):
            with patch.object(r, 'CODE', code):
                return STAGE(installer, runtime, code, work, previous)
        self.stage.side_effect = stage
        def activate(s, work, manifest):
            r.atomic(work / 'manifest.json', r.dump(manifest))
            return self.activate(s, work, manifest)
        self.activation.side_effect = activate

    def change(self, filename='discord-ips.txt', suffix=b'\n8.8.4.0/24\n'):
        path = self.package / filename
        path.write_bytes(path.read_bytes() + suffix)
        manifest = r.record(self.package / 'code-manifest.json')
        manifest['files'][filename] = r.digest(path)
        r.atomic(self.package / 'code-manifest.json', r.dump(manifest))

    def test_upgrade_from_exact_step2_package_applies_new_inputs_and_preserves_personal(self):
        self.ip_fixture()
        self.change()
        self.assertEqual(self.run_upgrade()['status'], 'upgraded')
        self.assert_preserved()

        current = (r.DATA / 'current').resolve()
        nets = json_networks((current / 'proxy-ipv4.json').read_bytes())
        for address in ('8.8.4.1', '8.8.8.8'):
            self.assertTrue(any(ipaddress.ip_address(address) in n for n in nets))
        info = r.record(current / 'manifest.json')['ip']
        self.assertNotIn('commit', info)
        self.assertEqual(info['sources']['discord']['sha256'], r.digest(r.CODE / 'discord-ips.txt'))
        self.assertEqual((i.PROJECT / 'state/upgrade/recover.py').read_bytes(), upgrade.u.BOOTSTRAP)

    def test_only_baseline_IP_file_change_is_delivered_and_applied_by_upgrade(self):
        self.ip_fixture(step2=False)
        self.change('telegram-extra-ips.txt')
        target = r.record(self.package / 'code-manifest.json')['files']
        old = r.record(i.STATE)['package_files']
        self.assertEqual([n for n in target if target[n] != old[n]], ['telegram-extra-ips.txt'])
        self.assertEqual(self.run_upgrade()['status'], 'upgraded')
        current = (r.DATA / 'current').resolve()
        self.assertTrue(any(ipaddress.ip_address('8.8.4.1') in n for n in json_networks((current / 'proxy-ipv4.json').read_bytes())))
        self.assert_preserved()
        self.assertEqual(self.run_upgrade()['status'], 'unchanged')

    def test_source_and_local_parse_errors_fail_before_switching_or_stopping(self):
        self.ip_fixture()
        before = (self.old / 'proxy-ipv4.json').read_bytes()
        for url in OFFICIAL:
            self.download.side_effect = lambda requested: b'' if requested == url else OFFICIAL[requested]
            r.run.reset_mock()
            with self.assertRaises(IP.CandidateError):
                self.run_upgrade()
            self.assertEqual((r.CODE / 'code-manifest.json').read_bytes(), self.old_manifest)
            self.assertEqual((r.DATA / 'current').resolve(), self.old)
            self.assertEqual((self.old / 'proxy-ipv4.json').read_bytes(), before)
            self.activation.assert_not_called()
            self.assertFalse(any(c.args[0][:2] == ['systemctl', 'stop'] for c in r.run.call_args_list))
        self.download.side_effect = OFFICIAL.__getitem__
        self.change(suffix=b'\nbad data\n')
        with self.assertRaises(IP.CandidateError):
            self.run_upgrade()
        self.assertEqual((r.CODE / 'code-manifest.json').read_bytes(), self.old_manifest)
        self.assert_preserved()

    def test_failure_after_IP_activation_restores_step2_code_lists_and_whole_policy(self):
        self.ip_fixture()
        self.change()
        before = (self.old / 'proxy-ipv4.json').read_bytes()
        activate = self.activation.side_effect
        def fail(*args):
            activate(*args)
            raise RuntimeError('AFTER_IP_ACTIVATION')
        self.activation.side_effect = fail
        with self.assertRaisesRegex(RuntimeError, 'AFTER_IP_ACTIVATION'):
            self.run_upgrade()
        self.assertEqual((r.DATA / 'current').resolve(), self.old)
        self.assertEqual((self.old / 'proxy-ipv4.json').read_bytes(), before)
        self.assertEqual({n: (r.CODE / n).read_bytes() for n in self.old_code}, self.old_code)
        self.assertTrue(all(not (r.CODE / n).exists() for n in r.IP_BASELINES.values()))
        for path, raw in self.before.items():
            self.assertEqual(path.read_bytes(), raw)
        self.assert_preserved()

    def test_upgrade_rejects_baseline_coverage_loss_and_excess_growth_before_switch(self):
        self.ip_fixture()
        path = self.package / 'discord-ips.txt'
        original = path.read_bytes()
        before = (self.old / 'proxy-ipv4.json').read_bytes()
        for raw, error in ((original.replace(b'35.212.0.0/14', b'# 35.212.0.0/14'), 'IP_PREVIOUS_COVERAGE_REMOVED'),
                           (original + b'\n1.0.0.0/12\n', 'IP_COVERAGE_GROWTH_GUARD')):
            path.write_bytes(raw)
            manifest = r.record(self.package / 'code-manifest.json')
            manifest['files'][path.name] = r.digest(path)
            r.atomic(self.package / 'code-manifest.json', r.dump(manifest))
            r.run.reset_mock()
            with self.assertRaisesRegex(r.StackError, error):
                self.run_upgrade()
            self.activation.assert_not_called()
            self.assertEqual((r.DATA / 'current').resolve(), self.old)
            self.assertEqual((self.old / 'proxy-ipv4.json').read_bytes(), before)
            self.assertEqual((r.CODE / 'code-manifest.json').read_bytes(), self.old_manifest)
            self.assertFalse(any(c.args[0][:2] == ['systemctl', 'stop'] for c in r.run.call_args_list))
            self.assert_preserved()



class Step2RecoveryTests(unittest.TestCase):
    """Execute loaders surviving each publication boundary with the exact step 2 engine."""
    snapshot = 'f6e5d85'
    snapshot_commit = 'f6e5d85a677014a566b8c9772095280520ccbfb7'
    snapshot_bootstrap = upgrade.u.DOMAIN_BASELINE_BOOTSTRAP
    legacy_package_baselines = ('include-hosts.txt', 'exclude-hosts.txt',
                                'include-adblock-hosts.txt', 'exclude-adblock-hosts.txt')
    setUp = installer.TemporaryRuntimeTests.setUp
    fixture = upgrade.UpgradeTests.fixture
    stage_policy = upgrade.UpgradeTests.stage_policy
    activate = upgrade.UpgradeTests.activate
    assert_preserved = upgrade.UpgradeTests.assert_preserved
    pending_fixture = migration.MigrationTests.pending_fixture
    infrastructure = migration.MigrationTests.infrastructure
    run_disk_loader = migration.MigrationTests.run_disk_loader
    assert_recovered = migration.MigrationTests.assert_recovered
    test_every_loader_and_pointer_publication_boundary_runs_surviving_loader = migration.MigrationTests.test_every_loader_and_pointer_publication_boundary_runs_surviving_loader
    test_new_loaders_recover_with_exact_step2_engine = migration.MigrationTests.test_new_loaders_recover_with_exact_python_only_old_engine
    test_unknown_or_edited_infrastructure_is_refused_before_any_selection_change = migration.MigrationTests.test_unknown_or_edited_infrastructure_is_refused_before_any_selection_change
    test_new_engine_is_verified_before_loader_or_pointer_publication = migration.MigrationTests.test_new_engine_is_verified_before_loader_or_pointer_publication
    test_old_loader_rejects_IP_data_engine_until_both_loaders_are_updated = migration.MigrationTests.test_exact_previous_loader_reproduces_reported_failure_before_repaired_migration
    test_pointer_based_old_loaders_missing_engine_selection_are_refused = migration.MigrationTests.test_pointer_based_old_loaders_missing_engine_selection_are_refused
