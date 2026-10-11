"""Repeat review: composed inline policies and systemd update results, offline."""
from contextlib import ExitStack
import errno
import hashlib
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import test_installer as baseline
from test_installer import load, r


class ComposedCleanupTests(unittest.TestCase):
    def setUp(self):
        baseline.TemporaryRuntimeTests.setUp(self)
        core = load('repeat_core', 'personal-policy.py')
        parser = load('repeat_parser', 'source-parser.py')
        setup = load('repeat_setup', 'transport-probes.py')
        personal = load('repeat_personal', 'personal-runtime.py')
        self.s = SimpleNamespace(core=core, parser=parser, pilot=None, wire=None,
            setup=SimpleNamespace(backend_config=setup.backend_config,
                                  local_dns=lambda *_: ['198.18.0.4'], require_fake=lambda values: values[0]),
            personal=SimpleNamespace(within=personal.within, runtime_check=self.runtime_check))
        for name in (*r.FILES.values(), r.IP_FILE):
            r.atomic(self.etc / name, b'')
        r.atomic(self.data / 'update.lock', b'')
        stack = self.enterContext(ExitStack())
        for context in (patch.object(r, 'modules', return_value=self.s), patch.object(r, 'run'),
                        patch.object(r, 'wait_backend'), patch.object(r, 'probes', return_value={}),
                        patch.object(r.shutil, 'disk_usage', return_value=SimpleNamespace(free=10 * 1024**3)),
                        patch.object(r, 'make_full', side_effect=self.full)):
            stack.enter_context(context)
        original_read = Path.read_text
        stack.enter_context(patch.object(Path, 'read_text', lambda path, *a, **k:
            'MemAvailable: 1048576 kB\n' if str(path) == '/proc/meminfo' else original_read(path, *a, **k)))
        work = r.work_directory()
        manifest = self.full(self.s, work)
        values, snapshots = r.personal(self.s)
        body, ip_info = r.combined_ips({'source_CIDRs': ['104.16.0.0/13']})
        manifest.update(personal=values, personal_sha256=snapshots, ip=ip_info)
        r.atomic(work / 'proxy-ipv4.json', body)
        r.atomic(work / 'personal-direct-domains.json', r.direct_body(values['direct']))
        self.runtime_check(self.s, self.s.core, None, work, manifest, values, '')
        r.activate(self.s, work, manifest, initial=True)
        self.assets = work

    def full(self, _s, work, _previous=None):
        (work / 'assets').mkdir()
        for tag in ('smart', 'direct', 'ads'):
            r.atomic(work / 'assets' / (tag + '.mrs'), b'fixture MRS; native checks stubbed')
            r.atomic(work / (tag + '.normalized.txt'), ('+.' + tag + '.example\n').encode())
        return {'assets_source': str(work), 'files': {tag + '.mrs': {'normalized_patterns': 1}
                for tag in ('smart', 'direct', 'ads')}, 'source_metadata': {}, 'source_entries': {},
                'registry_domains': 1, 'upstream_prefix_rewrites': 0, 'extras': {}, 'commit': 'offline'}

    def runtime_check(self, _s, _core, _pilot, work, _manifest, _values, _base):
        r.atomic(work / 'witnesses.json', b'{}')
        return {'status': 'ok'}

    def apply_rule(self, kind):
        r.atomic(self.etc / r.FILES[kind], b'personal.example\n')
        result = r.apply('personal')
        self.assertEqual(result['status'], 'active')
        providers = self.s.core.line_value(r.CONFIG.read_text(), 'rule-providers: ')
        tag = {'proxy': 'personal-proxy', 'direct': 'personal-direct', 'ads-exceptions': 'ads-exceptions'}[kind]
        self.assertEqual(providers[tag]['type'], 'inline')
        self.assertNotIn('path', providers[tag])
        self.assertEqual(providers[tag]['payload'], ['+.personal.example'])
        if kind == 'ads-exceptions':
            self.assertEqual(providers['ads-effective']['type'], 'inline')
            self.assertNotIn('path', providers['ads-effective'])
        return r.active()[0]

    def cycle(self, kind):
        applied = self.apply_rule(kind)
        stale = r.work_directory()
        (stale / 'large.raw').write_bytes(b'x' * 4096)
        r.cleanup()
        self.assertFalse(stale.exists())
        self.assertTrue(self.assets.exists())
        self.assertTrue(applied.exists())
        self.assertEqual(r.apply('personal')['status'], 'unchanged')
        # Real apply/reuse/compose/activate/cleanup, with only native/network work stubbed.
        self.assertEqual(r.apply('daily')['status'], 'active')
        current, manifest = r.active()
        self.assertNotEqual(current, applied)
        self.assertEqual(manifest['personal'][kind], ['personal.example'])
        self.assertEqual(manifest['assets_source'], str(self.assets))
        self.assertTrue((self.assets / 'assets/smart.mrs').exists())
        self.assertEqual(r.record(self.data / 'transaction.json')['status'], 'committed')

    def test_proxy_apply_cleanup_next_update(self):
        self.cycle('proxy')

    def test_direct_apply_cleanup_next_update(self):
        self.cycle('direct')

    def test_ads_exceptions_apply_cleanup_next_update(self):
        self.cycle('ads-exceptions')

    def test_failed_update_with_inline_providers_cleans_candidate(self):
        current = self.apply_rule('proxy')
        before = r.CONFIG.read_bytes()
        def fail(_s, work, _previous):
            (work / 'large.raw').write_bytes(b'x' * 4096)
            raise r.StackError('MRS_COMPILE_FAILED')
        with patch.object(r, 'make_full', side_effect=fail), self.assertRaisesRegex(r.StackError, 'MRS_COMPILE_FAILED'):
            r.apply('daily')
        self.assertEqual(r.active()[0], current)
        self.assertEqual(r.CONFIG.read_bytes(), before)
        self.assertEqual(set((self.data / 'generations').iterdir()), {self.assets, current})
        self.assertEqual(r.apply('daily')['status'], 'active')

    def test_rollback_with_inline_providers_then_next_update(self):
        old = self.apply_rule('ads-exceptions')
        before = r.CONFIG.read_bytes()
        r.atomic(self.etc / 'direct.txt', b'another.example\n')
        candidates = []
        def fail(_s, work, _manifest):
            providers = self.s.core.line_value(r.CONFIG.read_text(), 'rule-providers: ')
            self.assertEqual(providers['personal-direct']['type'], 'inline')
            self.assertEqual(providers['ads-effective']['type'], 'inline')
            candidates.append(work)
            raise r.StackError('VLESS_PROBE_FAILED')
        with patch.object(r, 'probes', side_effect=fail), self.assertRaisesRegex(r.StackError, 'VLESS_PROBE_FAILED'):
            r.apply('personal')
        self.assertEqual(r.active()[0], old)
        self.assertEqual(r.CONFIG.read_bytes(), before)
        self.assertEqual(r.record(self.data / 'transaction.json')['status'], 'rolled_back')
        self.assertFalse(candidates[0].exists())
        self.assertTrue(self.assets.exists())
        self.assertEqual(r.apply('personal')['status'], 'active')

    def test_pending_transaction_with_inline_config_protects_both_generations(self):
        old = self.apply_rule('direct')
        candidate = r.work_directory()
        manifest = self.full(self.s, candidate)
        config, _ = self.s.core.compose(r.base_config(self.s, self.assets),
                                      {'proxy': ['candidate.example'], 'direct': [], 'ads-exceptions': []})
        r.atomic(r.CONFIG, config.encode())
        r.atomic(candidate / 'manifest.json', r.dump(dict(manifest, activation='candidate', status='verified')))
        r.atomic(candidate / 'probe.private.log', b'needed for recovery')
        r.atomic(self.data / 'transaction.json', r.dump({'status': 'prepared',
            'before_source': str(old), 'after_source': str(candidate)}))
        stale = r.work_directory()
        r.cleanup()
        self.assertFalse(stale.exists())
        self.assertTrue((candidate / 'probe.private.log').exists())
        self.assertTrue(old.exists())
        self.assertTrue(self.assets.exists())

    def test_inline_cleanup_and_next_update_at_full_disk(self):
        current = self.apply_rule('ads-exceptions')
        before = r.CONFIG.read_bytes()
        stale = r.work_directory()
        (stale / 'large.raw').write_bytes(b'x' * 4096)
        with patch.object(r, 'atomic', side_effect=OSError(errno.ENOSPC, 'full')) as writes, \
             patch.object(r.shutil, 'disk_usage', return_value=SimpleNamespace(free=0)) as disk:
            result = r.cleanup()
            writes.assert_not_called()
            disk.assert_not_called()
            self.assertIn(stale.name, result['removed_generations'])
            self.assertEqual(r.apply('personal')['status'], 'unchanged')
            with self.assertRaisesRegex(BlockingIOError, 'DISK_HEADROOM_LOW'):
                r.apply('daily')
        self.assertEqual(r.CONFIG.read_bytes(), before)
        self.assertEqual(r.active()[0], current)
        self.assertTrue(self.assets.exists())
        self.assertEqual(r.apply('daily')['status'], 'active')

    def test_memory_shortage_defers_with_inline_policy_after_cleanup(self):
        current = self.apply_rule('proxy')
        stale = r.work_directory()
        with patch.object(Path, 'read_text', return_value='MemAvailable: 1 kB\n'), \
             self.assertRaisesRegex(BlockingIOError, 'RESOURCE_HEADROOM_LOW'):
            r.apply('daily')
        self.assertFalse(stale.exists())
        self.assertEqual(r.active()[0], current)
        self.assertTrue(self.assets.exists())
        self.assertEqual(r.apply('daily')['status'], 'active')

    def test_malformed_file_references_with_inline_providers_stop_before_deletion(self):
        self.apply_rule('direct')
        providers = self.s.core.line_value(r.CONFIG.read_text(), 'rule-providers: ')
        original = r.CONFIG.read_text()
        for bad in ({'type': 'file'}, {'type': 'file', 'path': '../outside/assets/smart.mrs'},
                    {'type': 'file', 'path': str(self.root / 'outside/assets/smart.mrs')},
                    {'type': 'file', 'path': str(self.data / 'generations/gen-missing/assets/smart.mrs')},
                    {'path': providers['smart']['path']}):
            with self.subTest(provider=bad):
                modified = dict(providers, smart=bad)
                r.atomic(r.CONFIG, self.s.core.replace_line(original, 'rule-providers: ', modified).encode())
                stale = r.work_directory()
                with self.assertRaisesRegex(r.StackError, 'CLEANUP_'):
                    r.cleanup()
                self.assertTrue(stale.exists())


class UpdateStatusTests(unittest.TestCase):
    setUp = baseline.TemporaryRuntimeTests.setUp

    def check_status(self, properties, expected_status, expected_health, expected_reason):
        baseline.transport_status_fixture(self.etc)
        r.atomic(r.CONFIG, b'fixture')
        for name in (*r.FILES.values(), r.IP_FILE):
            r.atomic(self.etc / name, b'')
        manifest = {'assets_source': '/assets', 'counts': {}, 'personal': {}, 'ip': {},
                    'personal_sha256': {key: hashlib.sha256(b'').hexdigest() for key in (*r.FILES, 'proxy-ip')},
                    'config_sha256': hashlib.sha256(b'fixture').hexdigest()}
        s = SimpleNamespace(personal=SimpleNamespace(loaded_counts=Mock()), checker=None)
        def systemctl(args, _code, **_kwargs):
            self.assertEqual(args[:2], ['systemctl', 'show'])
            self.assertIn('--property=ExecMainCode', args)
            unit = args[2]
            state = dict(LoadState='loaded', ActiveState='active', SubState='running', Result='success',
                         ExecMainCode='0', ExecMainStatus='0')
            if unit.endswith('daily.service'):
                state.update(properties)
            elif unit.endswith(('ip.service', 'personal.service')):
                state.update(ActiveState='inactive', SubState='dead', ExecMainCode='1')
            return ''.join(key + '=' + value + '\n' for key, value in state.items()).encode()
        with patch.object(r, 'run', side_effect=systemctl), patch.object(r, 'active', return_value=(self.root, manifest)), \
             patch.object(r, 'modules', return_value=s), patch.object(r, 'report') as report, \
             patch.object(r.socket, 'create_connection'), patch.object(r.http.client, 'HTTPConnection') as http:
            response = http.return_value.getresponse.return_value
            response.status, response.read.return_value = 200, b'{"status":"ok"}\n'
            self.assertEqual(r.status(), 0 if expected_status == 'healthy' else 1)
        value = report.call_args.kwargs
        self.assertEqual(value['status'], expected_status)
        self.assertEqual(value['faults'], [])
        self.assertEqual(value['update_faults'], [] if expected_status == 'healthy' else ['daily.service'])
        self.assertEqual(value['update_states']['daily.service'], {'status': expected_health, 'reason': expected_reason})

    def test_oom_auto_restart_is_degraded(self):
        self.check_status(dict(ActiveState='activating', SubState='auto-restart', Result='oom-kill',
                               ExecMainCode='2', ExecMainStatus='9'),
                          'degraded', 'failed', 'SERVICE_RESULT_OOM_KILL')

    def test_timeout_even_if_main_exits_75_is_degraded(self):
        for active, sub in (('activating', 'auto-restart'), ('failed', 'failed'), ('inactive', 'dead')):
            with self.subTest(active=active):
                self.check_status(dict(ActiveState=active, SubState=sub, Result='timeout',
                                       ExecMainCode='1', ExecMainStatus='75'),
                                  'degraded', 'failed', 'SERVICE_RESULT_TIMEOUT')

    def test_signal_and_core_dump_auto_restart_are_degraded(self):
        for result, code in (('signal', '2'), ('core-dump', '3')):
            with self.subTest(result=result):
                self.check_status(dict(ActiveState='activating', SubState='auto-restart', Result=result,
                                       ExecMainCode=code, ExecMainStatus='75'),
                                  'degraded', 'failed', 'SERVICE_RESULT_' + result.upper().replace('-', '_'))

    def test_normal_oneshot_start_is_healthy(self):
        self.check_status(dict(ActiveState='activating', SubState='start', Result='success'),
                          'healthy', 'running', 'UPDATE_IN_PROGRESS')

    def test_successful_inactive_oneshot_is_healthy(self):
        self.check_status(dict(ActiveState='inactive', SubState='dead', Result='success',
                               ExecMainCode='1', ExecMainStatus='0'),
                          'healthy', 'idle', 'SUCCESSFUL_OR_NOT_YET_RUN_ONESHOT')

    def test_expected_deferral_is_healthy(self):
        for sub in ('auto-restart', 'auto-restart-queued'):
            with self.subTest(substate=sub):
                self.check_status(dict(ActiveState='activating', SubState=sub, Result='exit-code',
                                       ExecMainCode='1', ExecMainStatus='75'),
                                  'healthy', 'deferred', 'TEMPORARY_FAILURE_EXIT_75')

    def test_other_exit_codes_and_manager_resource_failures_are_degraded(self):
        for result, code in (('exit-code', '1'), ('resources', '75'), ('start-limit-hit', '75')):
            with self.subTest(result=result):
                self.check_status(dict(ActiveState='activating', SubState='auto-restart', Result=result,
                                       ExecMainCode='1', ExecMainStatus=code),
                                  'degraded', 'failed', 'SERVICE_RESULT_' + result.upper().replace('-', '_'))

    def test_actual_new_invocation_resets_failure_to_success(self):
        # systemd resets Result and ExecMainCode before entering start (v255 service_start).
        self.check_status(dict(ActiveState='activating', SubState='start', Result='success',
                               ExecMainCode='0', ExecMainStatus='0'),
                          'healthy', 'running', 'UPDATE_IN_PROGRESS')

    def test_runtime_deferrals_report_reason_and_exit_75(self):
        for error, reason in ((BlockingIOError(errno.EAGAIN, 'lock'), 'POLICY_LOCK_BUSY'),
                              (BlockingIOError('RESOURCE_HEADROOM_LOW'), 'RESOURCE_HEADROOM_LOW'),
                              (BlockingIOError('DISK_HEADROOM_LOW'), 'DISK_HEADROOM_LOW')):
            with self.subTest(reason=reason), patch.object(r.sys, 'argv', ['runtime', 'daily']), \
                 patch.object(r.sys, 'platform', 'linux'), patch.object(r.os, 'geteuid', return_value=0), \
                 patch.object(r.signal, 'signal'), patch.object(r, 'apply', side_effect=error), \
                 patch.object(r, 'report') as report:
                self.assertEqual(r.main(), 75)
                report.assert_called_once_with('daily', status='deferred', reason=reason)

    def test_personal_watcher_preserves_resource_deferral_reason(self):
        with patch.object(r, 'fingerprint', return_value=[]), \
             patch.object(r.time, 'monotonic', side_effect=[0, 0, 4]), \
             patch.object(r, 'apply', side_effect=BlockingIOError('RESOURCE_HEADROOM_LOW')), \
             patch.object(r, 'report') as report:
            self.assertEqual(r.watcher(), 75)
        report.assert_called_once_with('personal', status='deferred', reason='RESOURCE_HEADROOM_LOW')
