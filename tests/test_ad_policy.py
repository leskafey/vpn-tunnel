"""Advertising source semantics, user overrides and atomic policy refreshes."""
from pathlib import Path
import os
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from test_installer import load, r, i, m
import test_repeat_review as repeat


ad = load('advertising_sources_test', 'ad-policy.py')
parser = load('advertising_parser_test', 'source-parser.py')
core = load('advertising_core_test', 'personal-policy.py')
personal = load('advertising_runtime_test', 'personal-runtime.py')
setup = load('advertising_setup_test', 'transport-probes.py')


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.work = Path(self.folder.name)
        self.enterContext(patch.dict(ad.LIMITS, {'adguard-dns': (1, 1000000)}))

    def normalize(self, body, name='adguard-dns', previous=None):
        source = self.work / 'source.txt'
        source.write_text(body)
        paths, counts = ad.normalize(parser, name, source, self.work, previous)
        return {kind: path.read_text().splitlines() for kind, path in paths.items()}, counts

    def test_badfilter_cancels_only_matching_rule_independent_of_order(self):
        rules, counts = self.normalize('||ads.example^$badfilter\n||ads.example^\n'
            '||ads.example^$important\n@@||allowed.ads.example^\n')
        self.assertEqual(rules, {'block': [], 'allow': ['+.allowed.ads.example'], 'important': ['+.ads.example']})
        self.assertEqual(counts['disabled'], 1)

    def test_badfilter_preserves_distinct_source_rules_before_dns_deduplication(self):
        import itertools
        for prefix, suffix, kind, expected in (
            ('||', '', 'block', '+.ads.example'),
            ('@@||', '', 'allow', '+.ads.example'),
            ('||', '$important', 'important', '+.ads.example'),
        ):
            original = prefix + 'ads.example^' + suffix
            independent = prefix + 'ads.example^|' + suffix
            cancel = original + (',badfilter' if suffix else '$badfilter')
            for rows in itertools.permutations((original, independent, cancel)):
                with self.subTest(rows=rows):
                    rules, counts = self.normalize('\n'.join(rows) + '\n')
                    self.assertEqual(rules[kind], [expected])
                    self.assertEqual(counts['disabled'], 1)

    def test_badfilter_exact_exceptions_and_important_modifier_positions(self):
        rows = ['@@|ads.example^|', '@@|ads.example^|$badfilter', '@@||ads.example^',
                '||important.example^$important', '||important.example^$badfilter,important',
                '||ordinary.example^', '||ordinary.example^$important,badfilter']
        for ordered in (rows, list(reversed(rows))):
            rules, counts = self.normalize('\n'.join(ordered) + '\n')
            self.assertEqual(rules, {'block': ['+.ordinary.example'], 'allow': ['+.ads.example'], 'important': []})
            self.assertEqual(counts['disabled'], 2)

    def test_badfilter_never_matches_normalized_domain_or_unsupported_rule(self):
        rules, counts = self.normalize('||ADS.example^\n||ads.example^$badfilter\n'
            '||url.example/path^$badfilter\n||limited.example^$dnstype=A\n'
            '@@|exact.example^|$important\n||wild*.example^$badfilter\n')
        self.assertEqual(rules, {'block': ['+.ads.example'], 'allow': [], 'important': []})
        self.assertEqual(counts['unsupported'], 4)
        self.assertEqual(counts['disabled'], 0)

    def test_paths_modifiers_regex_and_wildcards_never_become_domain_blocks(self):
        rules, counts = self.normalize('||good.example^\n||site.example/path^\n'
            '||other.example^$third-party\n||ads*.example^\n/^ads/\n')
        self.assertEqual(rules['block'], ['+.good.example'])
        self.assertEqual(counts['unsupported'], 4)

    def test_suffix_and_exact_exceptions_keep_their_original_scope(self):
        rules, counts = self.normalize('||ads.example^\n@@||suffix.ads.example^|\n@@|exact.ads.example^|\n')
        self.assertEqual(rules['allow'], ['+.suffix.ads.example', 'exact.ads.example'])
        self.assertEqual(counts['unsupported'], 0)
        for tag, rows in (('ads', rules['block']), ('ads-allow', rules['allow']), ('smart', []), ('direct', [])):
            (self.work / (tag + '.normalized.txt')).write_text(''.join(row + '\n' for row in rows))
        hits = personal.base_matches(self.work, ['exact.ads.example', 'child.exact.ads.example', 'child.suffix.ads.example'])
        self.assertTrue(hits['exact.ads.example']['ads-allow'])
        self.assertFalse(hits['child.exact.ads.example']['ads-allow'])
        self.assertTrue(hits['child.suffix.ads.example']['ads-allow'])

    def test_invalid_domain_and_format_shift_fail_closed(self):
        with self.assertRaisesRegex(ad.AdPolicyError, 'ADS_SOURCE_DOMAIN_INVALID'):
            self.normalize('||bad..example^\n')
        with self.assertRaisesRegex(ad.AdPolicyError, 'ADS_SOURCE_COUNT_OR_FORMAT_GUARD'):
            self.normalize('||site.example/path^\n' * 11)
        with self.assertRaisesRegex(ad.AdPolicyError, 'ADS_SOURCE_CHANGE_OVER_25_PERCENT'):
            self.normalize('||ads.example^\n', previous={'valid': 100})

    def test_empty_author_lists_and_small_updates_are_valid(self):
        rules, counts = self.normalize('# Empty intentional list\n', name='antizapret-ads-allow', previous={'valid': 5})
        self.assertEqual(rules['allow'], [])
        self.assertEqual(counts['valid'], 0)
        rules, _ = self.normalize('*.allowed.example\n', name='antizapret-ads-allow', previous={'valid': 0})
        self.assertEqual(rules['allow'], ['+.allowed.example'])

    def test_sources_are_combined_and_only_adguard_is_downloaded(self):
        (self.work / 'oisd-small.unique.txt').write_text('oisd.example\n')
        urls = []
        def download(url, path):
            urls.append(url)
            body = ('||adguard.example^\n@@||allowed.adguard.example^\n||important.example^$important\n'
                    if url == ad.ADGUARD_URL else 'author.example\n' if 'include-adblock' in url else 'allowed.author.example\n')
            path.write_text(body)
            return {'bytes': len(body), 'sha256': 'fixture'}
        def baseline(filename):
            body = b'author.example\n' if filename.startswith('include-') else b'allowed.author.example\n'
            return body, {'source': 'local-baseline', 'bytes': len(body), 'sha256': 'fixture'}
        s = SimpleNamespace(builder=SimpleNamespace(download=download), parser=parser, baseline_source=baseline)
        tags, metadata = ad.build(s, self.work)
        self.assertEqual(tags, ['ads', 'ads-allow', 'ads-important'])
        self.assertEqual(set((self.work / 'ads.raw.txt').read_text().splitlines()),
                         {'+.oisd.example', '+.adguard.example', '+.author.example'})
        self.assertEqual(set((self.work / 'ads-allow.raw.txt').read_text().splitlines()),
                         {'+.allowed.adguard.example', '+.allowed.author.example'})
        self.assertEqual(urls, [ad.ADGUARD_URL])
        self.assertEqual(metadata['antizapret-ads']['source'], 'local-baseline')
        self.assertEqual(metadata['adguard-dns']['allow'], 1)


class PolicyTests(unittest.TestCase):
    def values(self, **changes):
        return dict({'proxy': [], 'direct': [], 'ads': [], 'ads-exceptions': []}, **changes)

    def test_automatic_exceptions_preserve_routing_and_personal_overrides(self):
        hits = {'ads': True, 'ads-allow': True, 'ads-important': False, 'smart': True, 'direct': False}
        self.assertEqual(personal.expected_route('child.ads.example', hits, self.values()), ('fake', 'automatic-proxy'))
        self.assertEqual(personal.expected_route('child.ads.example', hits, self.values(ads=['ads.example'])), ('fake', 'ads-reject'))
        hits['ads-important'] = True
        self.assertEqual(personal.expected_route('child.ads.example', hits, self.values()), ('fake', 'ads-reject'))
        self.assertEqual(personal.expected_route('child.ads.example', hits,
            self.values(ads=['ads.example'], **{'ads-exceptions': ['ads.example']})), ('fake', 'automatic-proxy'))

    def test_personal_block_beats_direct_and_personal_exception_releases_it(self):
        hits = {'ads': False, 'smart': False, 'direct': False}
        values = self.values(ads=['ads.example'], direct=['ads.example'])
        self.assertEqual(personal.expected_route('child.ads.example', hits, values), ('fake', 'ads-reject'))
        values['ads-exceptions'] = ['child.ads.example']
        self.assertEqual(personal.expected_route('child.ads.example', hits, values), ('real', 'personal-direct'))
        self.assertEqual(personal.expected_route('other.ads.example', hits, values), ('fake', 'ads-reject'))

    def test_legacy_three_provider_policy_still_composes(self):
        s = SimpleNamespace(setup=setup, core=core)
        text, counts = core.compose(r.base_config(s, Path('/missing/legacy')),
                                  {'proxy': [], 'direct': [], 'ads-exceptions': []})
        self.assertIn('  - RULE-SET,ads,REJECT\n', text)
        self.assertEqual(counts, {})


class RefreshTests(unittest.TestCase):
    setUp = repeat.ComposedCleanupTests.setUp
    runtime_check = repeat.ComposedCleanupTests.runtime_check

    def full(self, s, work, previous=None):
        manifest = repeat.ComposedCleanupTests.full(self, s, work, previous)
        for tag in ('ads-allow', 'ads-important'):
            r.atomic(work / 'assets' / (tag + '.mrs'), b'fixture optional MRS')
            r.atomic(work / (tag + '.normalized.txt'), ('+.' + tag + '.example\n').encode())
            manifest['files'][tag + '.mrs'] = {'normalized_patterns': 1}
        return manifest

    def test_personal_ad_block_survives_cleanup_and_next_daily_refresh(self):
        r.atomic(self.etc / 'ads.txt', b'custom.ads.example\n')
        self.assertEqual(r.apply('personal')['status'], 'active')
        providers = self.s.core.line_value(r.CONFIG.read_text(), 'rule-providers: ')
        self.assertEqual(providers['personal-ads']['payload'], ['+.custom.ads.example'])
        r.cleanup()
        self.assertEqual(r.apply('personal')['status'], 'unchanged')
        self.assertEqual(r.apply('daily')['status'], 'active')
        current, manifest = r.active()
        self.assertEqual(manifest['personal']['ads'], ['custom.ads.example'])
        for tag in ('ads-allow', 'ads-important'):
            self.assertTrue((current / (tag + '.normalized.txt')).is_file())
            self.assertIn(tag, manifest['counts'])
            self.assertIn(tag + '.normalized.txt', manifest['checksums'])

    def test_cli_preserves_comments_and_removes_only_requested_block(self):
        self.s.core.parse_personal = core.parse_personal
        r.atomic(self.etc / 'ads.txt', '# Мои правила\nfirst.example\n'.encode())
        m.rule(r, 'add', 'ads', 'second.example')
        m.rule(r, 'remove', 'ads', 'first.example')
        self.assertEqual((self.etc / 'ads.txt').read_text(), '# Мои правила\nsecond.example\n')

    def test_missing_new_file_means_empty_and_cli_creates_it(self):
        (self.etc / 'ads.txt').unlink()
        self.assertEqual(r.personal(self.s)[0]['ads'], [])
        lstat = Path.lstat
        def owned_lstat(path):
            fields = list(lstat(path))
            fields[4] = 0
            return os.stat_result(fields)
        with patch.object(Path, 'lstat', owned_lstat):
            self.assertEqual(r.fingerprint()[-2], (0, 0, 0))
        m.rule(r, 'add', 'ads', 'new.example')
        self.assertEqual((self.etc / 'ads.txt').read_text(), 'new.example\n')

    def test_failed_optional_provider_refresh_keeps_working_generation(self):
        old, _ = r.active()
        before = r.CONFIG.read_bytes()
        with patch.object(r, 'make_full', side_effect=ad.AdPolicyError('ADS_SOURCE_COUNT_OR_FORMAT_GUARD')):
            with self.assertRaises(ad.AdPolicyError):
                r.apply('daily')
        self.assertEqual(r.active()[0], old)
        self.assertEqual(r.CONFIG.read_bytes(), before)
        self.assertTrue((old / 'assets/ads-allow.mrs').is_file())

    def test_installer_creates_private_blocklist_and_watches_edits(self):
        i.create_rule_files(r)
        self.assertEqual((self.etc / 'ads.txt').stat().st_mode & 0o777, 0o600)
        self.assertIn('PathChanged=' + str(self.etc / 'ads.txt'), i.units(r)['vpn-stack-personal.path'])
