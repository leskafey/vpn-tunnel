"""Task 2: real baseline data/parsers and filesystem delivery; native services mocked."""
import ast
import base64
import hashlib
import io
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

from test_installer import b, i, load, r
import test_installer as installer
import test_project_layout as layout
import test_repeat_review as repeat
import test_upgrade as upgrade

ROOT = Path(__file__).resolve().parent.parent
extras = load('baseline_extras', 'domain-extras.py')
ad = load('baseline_ads', 'ad-policy.py')
parser = load('baseline_parser', 'source-parser.py')
builder = load('baseline_builder', 'text-builder.py')
personal = load('baseline_personal', 'personal-runtime.py')
setup = load('baseline_setup', 'transport-probes.py')
core = load('baseline_core', 'personal-policy.py')
FULL_BUILD = r.make_full
TLD_BYTES = (ROOT / 'docs/antizapret-independence/2026-10-14/official/iana-tlds.txt').read_bytes()


class BaselineTests(unittest.TestCase):
    setUp = installer.TemporaryRuntimeTests.setUp

    def package(self):
        for name, body in b.package()[1].items():
            r.atomic(self.code / name, body, 0o644)
        r.atomic(self.etc / 'settings.json', r.dump({'server_ip': '8.8.8.8'}))
        return r.modules()

    def test_standalone_payload_contains_exact_prepared_data(self):
        tree = ast.parse((ROOT / 'install-vpn.py').read_bytes())
        payload = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
                       and isinstance(n.targets[0], ast.Name) and n.targets[0].id == 'PAYLOAD')
        provenance = json.loads((ROOT / 'lists/baseline/PROVENANCE.json').read_bytes())
        recorded = {Path(row['path']).name: row for row in provenance['downloaded_files']}
        with zipfile.ZipFile(io.BytesIO(base64.b85decode(payload))) as archive:
            manifest = json.loads(archive.read('code-manifest.json'))['files']
            self.assertEqual(set(r.BASELINE_FILES), set(b.BASELINE_FILES))
            for name in r.BASELINE_FILES:
                raw = archive.read(name)
                self.assertEqual(raw, (ROOT / 'lists/baseline' / name).read_bytes())
                self.assertEqual(hashlib.sha256(raw).hexdigest(), recorded[name]['sha256'])
                self.assertEqual(manifest[name], recorded[name]['sha256'])

    def test_installed_modules_load_data_and_reject_missing_tampered_and_symlink_files(self):
        s = self.package()
        for name in r.BASELINE_FILES:
            raw, metadata = s.baseline_source(name)
            self.assertEqual(raw, (ROOT / 'lists/baseline' / name).read_bytes())
            self.assertEqual(metadata['path'], 'lib/' + name)
            path = self.code / name
            path.write_bytes(raw + b'broken')
            with self.assertRaisesRegex(r.StackError, 'INSTALLED_CODE_CHANGED'):
                r.modules()
            with self.assertRaisesRegex(r.StackError, 'BASELINE_DATA_CHANGED'):
                s.baseline_source(name)
            path.unlink()
            with self.assertRaisesRegex(r.StackError, 'REGULAR_FILE_REQUIRED'):
                r.modules()
            path.symlink_to(ROOT / 'lists/baseline' / name)
            with self.assertRaisesRegex(r.StackError, 'REGULAR_FILE_REQUIRED'):
                r.modules()
            path.unlink()
            path.write_bytes(raw)
        manifest = r.record(self.code / 'code-manifest.json')
        manifest['files'].pop(r.BASELINE_FILES[0])
        r.atomic(self.code / 'code-manifest.json', r.dump(manifest))
        with self.assertRaisesRegex(r.StackError, 'BASELINE_FILES_REQUIRED'):
            r.modules()

    def test_prepared_suffix_coverage_and_routing_priorities(self):
        s = self.package()
        zones = extras.delegated_tlds(TLD_BYTES)
        expected = {}
        for name, filename in extras.FILES.items():
            raw, _ = s.baseline_source(filename)
            roots, tlds, count = extras.parse(raw, parser, zones)
            active = {row.strip() for row in raw.decode().splitlines() if row.strip() and not row.strip().startswith('#')}
            self.assertEqual(roots, active)
            self.assertEqual(count, 1183 if name == 'extra-proxy' else 17)
            self.assertEqual(tlds, {'ua', 'google', 'goog'} if name == 'extra-proxy' else set())
            tag = 'smart' if name == 'extra-proxy' else 'direct'
            (self.root / (tag + '.normalized.txt')).write_text(''.join('+.' + n + '\n' for n in sorted(roots)))
            for domain in roots:
                expected[domain] = tag
                expected['child.' + domain] = tag
            # Existing historical roots feed the same coverage guard.
            extras.no_lost_coverage(sorted(active), roots)
        (self.root / 'ads.normalized.txt').write_text('')
        hits = personal.base_matches(self.root, list(expected))
        empty = {'proxy': [], 'direct': [], 'ads': [], 'ads-exceptions': []}
        for name, tag in expected.items():
            self.assertTrue(hits[name][tag], name)
            direct = hits[name]['direct']
            self.assertEqual(personal.expected_route(name, hits[name], empty),
                ('real', 'automatic-direct') if direct else ('fake', 'automatic-proxy'))
        # Force a collision and exercise personal and automatic precedence.
        collision = dict(ads=False, smart=True, direct=True)
        self.assertEqual(personal.expected_route('child.example.org', collision, empty), ('real', 'automatic-direct'))
        self.assertEqual(personal.expected_route('child.example.org', collision, dict(empty, proxy=['example.org'])),
                         ('fake', 'personal-proxy'))
        self.assertEqual(personal.expected_route('child.example.org', collision,
                         dict(empty, proxy=['example.org'], direct=['example.org'])), ('real', 'personal-direct'))

    def test_prepared_ads_with_oisd_adguard_and_personal_overrides(self):
        s = self.package()
        (self.root / 'oisd-small.unique.txt').write_text('oisd.example\n')
        raw_allow, _ = s.baseline_source('exclude-adblock-hosts.txt')
        allow_roots = {row.strip() for row in raw_allow.decode().splitlines() if row.strip() and not row.startswith('#')}
        raw_block, _ = s.baseline_source('include-adblock-hosts.txt')
        block_roots = {row.strip() for row in raw_block.decode().splitlines() if row.strip() and not row.startswith('#')}
        urls = []
        def download(url, path):
            urls.append(url)
            path.write_text(''.join('||' + name + '^\n' for name in sorted(allow_roots))
                            + '||important.example^$important\n' + '||adguard.example^\n')
            return {'bytes': path.stat().st_size, 'sha256': r.digest(path)}
        with patch.dict(s.ad_policy.LIMITS, {'adguard-dns': (1, 1000000)}), patch.object(s.builder, 'download', side_effect=download):
            tags, metadata = s.ad_policy.build(s, self.root)
        self.assertEqual(urls, [ad.ADGUARD_URL])
        self.assertEqual(metadata['antizapret-ads']['valid'], 11)
        self.assertEqual(metadata['antizapret-ads-allow']['valid'], 5)
        self.assertEqual(set((self.root / 'antizapret-ads.block.txt').read_text().splitlines()), {'+.' + n for n in block_roots})
        self.assertEqual(set((self.root / 'antizapret-ads-allow.allow.txt').read_text().splitlines()), {'+.' + n for n in allow_roots})
        for tag in tags:
            (self.root / (tag + '.normalized.txt')).write_bytes((self.root / (tag + '.raw.txt')).read_bytes())
        (self.root / 'smart.normalized.txt').write_text('+.example\n')
        (self.root / 'direct.normalized.txt').write_text('')
        names = [n for root in block_roots | allow_roots for n in (root, 'child.' + root)]
        hits = personal.base_matches(self.root, names)
        empty = {'proxy': [], 'direct': [], 'ads': [], 'ads-exceptions': []}
        for name in names:
            in_allow = extras.covered(name, allow_roots)
            if in_allow:
                self.assertTrue(hits[name]['ads-allow'])
                self.assertNotEqual(personal.expected_route(name, hits[name], empty)[1], 'ads-reject')
                self.assertEqual(personal.expected_route(name, hits[name], dict(empty, ads=[name]))[1], 'ads-reject')
                important = dict(hits[name], **{'ads-important': True})
                self.assertEqual(personal.expected_route(name, important, empty)[1], 'ads-reject')
                self.assertNotEqual(personal.expected_route(name, important,
                    dict(empty, **{'ads-exceptions': [name]}))[1], 'ads-reject')
            else:
                self.assertTrue(hits[name]['ads'])
                self.assertEqual(personal.expected_route(name, hits[name], empty)[1], 'ads-reject')

    def test_invalid_syntax_tld_and_source_guards_still_fail(self):
        self.package()
        for raw in (b'bad..example\n', b'not-a-delegated-tld\n', b'<html>error</html>\n', b'', b'x' * (extras.CAP + 1)):
            with self.subTest(raw=raw[:20]), self.assertRaises(extras.ExtrasError):
                extras.parse(raw, parser, extras.delegated_tlds(TLD_BYTES))
        with self.assertRaisesRegex(extras.ExtrasError, 'COVERAGE_REMOVED'):
            extras.no_lost_coverage(['removed.example'], {'other.example'})
        with self.assertRaisesRegex(builder.BuildError, 'SOURCE_CHANGE_OVER_25_PERCENT'):
            builder.guard_count('extra-proxy', 1183, 0, 2000)
        path = self.root / 'broken-ad.txt'
        path.write_text('bad..example\n')
        with self.assertRaisesRegex(ad.AdPolicyError, 'ADS_SOURCE_DOMAIN_INVALID'):
            ad.normalize(parser, 'antizapret-ads', path, self.root)


class InstallationDataTests(unittest.TestCase):
    setUp = layout.InstallationTests.setUp
    fixture = layout.InstallationTests.fixture

    def test_install_delivers_data_independent_of_package_directory(self):
        _, package, _ = self.fixture()
        i.install(package, '8.8.8.8', False)
        import shutil
        shutil.rmtree(package)
        s = r.modules()
        for name in r.BASELINE_FILES:
            self.assertEqual(s.baseline_source(name)[0], (ROOT / 'lists/baseline' / name).read_bytes())
            self.assertFalse((r.ETC / name).exists())
        self.assertEqual(set(r.record(i.STATE)['package_files']), set(b.package()[1]) - {'code-manifest.json'})

    def test_install_refuses_missing_or_changed_required_data_before_checkpoint(self):
        project, package, _ = self.fixture()
        name = r.BASELINE_FILES[0]
        body = (package / name).read_bytes()
        (package / name).unlink()
        with self.assertRaises(r.StackError):
            i.install(package, '8.8.8.8', False)
        self.assertFalse(i.STATE.exists())
        (package / name).write_bytes(body + b'changed')
        with self.assertRaisesRegex(i.InstallError, 'PACKAGE_CODE_CHANGED'):
            i.install(package, '8.8.8.8', False)
        self.assertFalse(i.STATE.exists())
        (package / name).write_bytes(body)
        manifest = r.record(package / 'code-manifest.json')
        manifest['files'].pop(name)
        r.atomic(package / 'code-manifest.json', r.dump(manifest))
        with self.assertRaisesRegex(r.StackError, 'BASELINE_FILES_REQUIRED'):
            i.install(package, '8.8.8.8', False)
        self.assertFalse(i.STATE.exists())


class UpgradeDataTests(unittest.TestCase):
    setUp = upgrade.UpgradeTests.setUp
    fixture = upgrade.UpgradeTests.fixture
    stage_policy = upgrade.UpgradeTests.stage_policy
    activate = upgrade.UpgradeTests.activate
    run_upgrade = upgrade.UpgradeTests.run_upgrade
    assert_preserved = upgrade.UpgradeTests.assert_preserved
    interrupt_swap = upgrade.UpgradeTests.interrupt_swap

    def target_change(self):
        name = 'include-adblock-hosts.txt'
        path = self.package / name
        raw = path.read_bytes() + b'\nnew.ads.example\n'
        path.write_bytes(raw)
        manifest = r.record(self.package / 'code-manifest.json')
        manifest['files'][name] = hashlib.sha256(raw).hexdigest()
        r.atomic(self.package / 'code-manifest.json', r.dump(manifest))
        return name, raw

    def test_upgrade_delivers_new_data_and_rolls_it_back_on_activation_failure(self):
        self.fixture()
        before = {name: (r.CODE / name).read_bytes() for name in r.BASELINE_FILES}
        name, raw = self.target_change()
        def fail(*args):
            self.assertEqual((r.CODE / name).read_bytes(), raw)
            raise RuntimeError('INJECTED_ACTIVATION_FAILURE')
        self.activation.side_effect = fail
        with self.assertRaisesRegex(RuntimeError, 'INJECTED_ACTIVATION_FAILURE'):
            self.run_upgrade()
        self.assertEqual({n: (r.CODE / n).read_bytes() for n in before}, before)
        self.assert_preserved()
        self.activation.side_effect = self.activate
        self.assertEqual(self.run_upgrade()['status'], 'upgraded')
        self.assertEqual((r.CODE / name).read_bytes(), raw)
        self.assert_preserved()

    def test_upgrade_rejects_corrupt_or_missing_target_data_preserving_working_policy(self):
        self.fixture()
        before = {name: (r.CODE / name).read_bytes() for name in r.BASELINE_FILES}
        path = self.package / r.BASELINE_FILES[0]
        body = path.read_bytes()
        for corrupt in (False, True):
            if path.exists():
                path.unlink()
            if corrupt:
                path.write_bytes(body + b'broken')
            with self.assertRaises((OSError, upgrade.u.UpgradeError)):
                self.run_upgrade()
            self.assertEqual({n: (r.CODE / n).read_bytes() for n in before}, before)
            self.assertEqual(r.CONFIG.read_bytes(), self.before[r.CONFIG])
            self.assert_preserved()
            self.stage.assert_not_called()

    def test_upgrade_from_bundle_without_baselines_and_interrupted_swap_restores_old_set(self):
        self.fixture()
        u = upgrade.u
        state = r.record(i.STATE)
        for name in r.BASELINE_FILES:
            (r.CODE / name).unlink()
            state['package_files'].pop(name)
        r.atomic(r.CODE / 'code-manifest.json', r.dump({'files': state['package_files']}), 0o644)
        r.atomic(i.STATE, r.dump(state))
        self.before[i.STATE] = i.STATE.read_bytes()
        # The existing fixture models the historical runtime API. Its bundle
        # contains only code; new recovery must accept that old manifest.
        old_manifest = (r.CODE / 'code-manifest.json').read_bytes()
        self.interrupt_swap('lib')
        self.assertTrue(all((r.CODE / name).is_file() for name in r.BASELINE_FILES))
        self.assertEqual(self.run_upgrade(True)['status'], 'recovered')
        self.assertEqual((r.CODE / 'code-manifest.json').read_bytes(), old_manifest)
        self.assertTrue(all(not (r.CODE / name).exists() for name in r.BASELINE_FILES))
        self.assert_preserved()
        self.assertEqual(self.run_upgrade()['status'], 'upgraded')
        self.assertTrue(all((r.CODE / name).is_file() for name in r.BASELINE_FILES))
        self.assert_preserved()

    def test_malformed_baseline_with_valid_package_hash_fails_staging_preserving_policy(self):
        self.fixture()
        path = self.package / 'include-hosts.txt'
        path.write_bytes(b'bad..example\n')
        manifest = r.record(self.package / 'code-manifest.json')
        manifest['files'][path.name] = r.digest(path)
        r.atomic(self.package / 'code-manifest.json', r.dump(manifest))
        def stage(_i, runtime, code, work, previous):
            with patch.object(runtime, 'CODE', code):
                services = SimpleNamespace(extras=extras, parser=parser, baseline_source=runtime.baseline_source)
                with patch.object(extras, 'download', return_value=TLD_BYTES):
                    return FULL_BUILD(services, work, previous)
        self.stage.side_effect = stage
        with self.assertRaisesRegex(extras.ExtrasError, 'EXTRA_INVALID_DOMAIN'):
            self.run_upgrade()
        self.activation.assert_not_called()
        self.assertEqual(r.CONFIG.read_bytes(), self.before[r.CONFIG])
        self.assertEqual((r.CODE / 'include-hosts.txt').read_bytes(), (ROOT / 'lists/baseline/include-hosts.txt').read_bytes())
        self.assert_preserved()

    def test_previous_loader_migration_and_new_loader_validate_baseline_members(self):
        self.fixture()
        u = upgrade.u
        for name in ('recover.py', u.LOADER):
            path = i.PROJECT / 'state/upgrade' / name
            self.assertIn(u.VERIFIED_BOOTSTRAP, u.infrastructure_variants(i, path, u.BOOTSTRAP))
        # Execute the delivered loader, not just its bundle helper, with a
        # harmless recovery entrypoint. It must validate all four text members.
        root = self.root / 'loader-project/state/upgrade'
        root.mkdir(parents=True, mode=0o700)
        files = {name: (ROOT / 'lists/baseline' / name).read_bytes() for name in r.BASELINE_FILES}
        receipt = self.root / 'loader-receipt'
        files['vpn-stack-upgrade.py'] = ('from pathlib import Path\n'
            'def boot_recover(*a, **kw): Path(' + repr(str(receipt)) + ').write_text("ok")\n').encode()
        manifest = r.dump({'files': {name: hashlib.sha256(raw).hexdigest() for name, raw in files.items()}})
        engine = root / ('engine-' + hashlib.sha256(manifest).hexdigest())
        engine.mkdir(mode=0o700)
        for name, raw in files.items():
            (engine / name).write_bytes(raw)
        (engine / 'code-manifest.json').write_bytes(manifest)
        (root / 'engine.json').write_bytes(r.dump({'directory': engine.name}))
        loader = root / u.LOADER
        loader.write_bytes(u.BOOTSTRAP)
        original_lstat = Path.lstat
        def root_lstat(path, *a, **kw):
            fields = list(original_lstat(path, *a, **kw))
            fields[4] = 0
            import os
            return os.stat_result(fields)
        self.enterContext(patch.object(Path, 'lstat', root_lstat))
        # Run in-process to model uid=0 on macOS; no systemd branch (--services).
        with patch.object(sys, 'argv', [str(loader), '--services']):
            exec(compile(u.BOOTSTRAP, str(loader), 'exec'), {'__file__': str(loader)})
        self.assertEqual(receipt.read_text(), 'ok')
        receipt.unlink()
        (engine / r.BASELINE_FILES[0]).write_bytes(b'corrupt')
        with patch.object(sys, 'argv', [str(loader), '--services']), self.assertRaises(AssertionError):
            exec(compile(u.BOOTSTRAP, str(loader), 'exec'), {'__file__': str(loader)})
        self.assertFalse(receipt.exists())


class FullBuildTests(unittest.TestCase):
    setUp = installer.TemporaryRuntimeTests.setUp
    package = BaselineTests.package

    def test_full_build_reads_all_local_inputs_without_github_and_reuses_both_metadata_versions(self):
        s = self.package()
        urls = []
        def tld_download(url):
            urls.append(url)
            self.assertEqual(url, extras.IANA)
            return TLD_BYTES
        def download(url, path):
            urls.append(url)
            self.assertIn(url, [*r.SOURCES.values(), ad.ADGUARD_URL])
            path.write_text('||ads.external.example^\n' if url == ad.ADGUARD_URL else 'external.example\n')
            return {'bytes': path.stat().st_size, 'sha256': r.digest(path)}
        # External registry size and native compilation are fixtures. The local
        # input read, parsers, guards, assembly and metadata below are production.
        def normalize(_parser, name, source, destination, baseline):
            count = 500000 if name in ('rulist', 'antifilter') else 30000
            s.builder.guard_count(name, count, 0, baseline)
            destination.write_text('external.example\n')
            return {'valid': count, 'discarded': 0}
        def sorted_unique(source, destination, *_):
            destination.write_text(''.join(sorted(set(source.read_text().splitlines(True)))))
        promote = s.builder.promote_registry
        def registry(source, destination):
            _, rewritten = promote(source, destination)
            return 500000, rewritten
        def compile_fixture(tag, raw, assets, work):
            # Exercise production suffix reduction without launching native MRS.
            patterns = list(s.builder.reduce_events(sorted(set(s.builder.event_rows(s.builder.pattern_rows(raw))))))
            body = ''.join(row + '\n' for row in patterns).encode()
            (work / (tag + '.normalized.txt')).write_bytes(body)
            (assets / (tag + '.mrs')).write_bytes(body)
            return {'normalized_patterns': len(patterns), 'sha256': hashlib.sha256(body).hexdigest()}
        with patch.object(s.extras, 'download', side_effect=tld_download), \
             patch.object(s.builder, 'download', side_effect=download), \
             patch.object(s.builder, 'normalize_source', side_effect=normalize), \
             patch.object(s.builder, 'sorted_unique', side_effect=sorted_unique), \
             patch.object(s.builder, 'promote_registry', side_effect=registry), \
             patch.object(s.builder, 'compile_and_verify', side_effect=compile_fixture), \
             patch.dict(s.ad_policy.LIMITS, {'adguard-dns': (1, 1000000)}):
            first_work = r.work_directory()
            first = FULL_BUILD(s, first_work)
            self.assertNotIn('commit', first)
            legacy = dict(first, commit='a' * 40)
            # Previous source metadata had no local hash/source markers.
            legacy['source_metadata'] = {name: {'valid': info['valid']} for name, info in first['source_metadata'].items()}
            second_work = r.work_directory()
            second = FULL_BUILD(s, second_work, legacy)
        self.assertNotIn('commit', second)
        self.assertEqual(first['files'], second['files'])
        self.assertEqual(set(urls), {*r.SOURCES.values(), extras.IANA, ad.ADGUARD_URL})
        self.assertFalse(any('AntiZapret' in url for url in urls))
        for name, filename in {**extras.FILES, **ad.EXTRA_FILES}.items():
            info = second['source_metadata'][name]
            self.assertEqual(info['source'], 'local-baseline')
            self.assertEqual(info['sha256'], r.digest(self.code / filename))
        for source, previous in ((first_work, legacy), (second_work, second)):
            reused_work = r.work_directory()
            reused = r.reuse(source, previous, reused_work)
            self.assertEqual('commit' in reused, 'commit' in previous)
            self.assertEqual(reused['source_metadata'], previous['source_metadata'])
        patterns = (second_work / 'smart.normalized.txt').read_text().splitlines()
        self.assertTrue({'+.ua', '+.goog', '+.google'} <= set(patterns))


class FailedDataPolicyTests(unittest.TestCase):
    setUp = repeat.ComposedCleanupTests.setUp
    full = repeat.ComposedCleanupTests.full
    runtime_check = repeat.ComposedCleanupTests.runtime_check

    def test_daily_invalid_or_missing_new_data_keeps_current_policy_and_deliveries(self):
        # This fixture creates a verified filesystem policy; native activation
        # and external source services are mocked. New-data parsing is real.
        before_source, _ = r.active()
        watched = [r.CONFIG, self.assets / 'manifest.json', self.assets / 'proxy-ipv4.json']
        before = {path: path.read_bytes() for path in watched}
        self.s.extras, self.s.parser = extras, parser
        def baseline(filename):
            return (self.code / filename).read_bytes(), {}
        self.s.baseline_source = baseline
        for name in r.BASELINE_FILES:
            (self.code / name).write_bytes((ROOT / 'lists/baseline' / name).read_bytes())
        self.s.builder, self.s.ad_policy = builder, ad
        path = self.code / 'include-hosts.txt'
        with patch.object(extras, 'download', return_value=TLD_BYTES), patch.object(r, 'make_full', side_effect=FULL_BUILD), \
             patch.object(r, 'activate') as activate:
            path.write_bytes(b'bad..example\n')
            with self.assertRaisesRegex(extras.ExtrasError, 'EXTRA_INVALID_DOMAIN'):
                r.apply('daily')
            path.unlink()
            with self.assertRaises(FileNotFoundError):
                r.apply('daily')
        activate.assert_not_called()
        self.assertEqual(r.active()[0], before_source)
        self.assertEqual({p: p.read_bytes() for p in watched}, before)
        self.assertEqual(set((self.data / 'generations').iterdir()), {self.assets})
