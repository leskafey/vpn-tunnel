"""Behavioral verification logic; DNS/provider API/systemd are stubbed here."""
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from test_installer import load
import test_upgrade as fixtures
from test_installer import r, i


u = load('upgrade_policy_verification_tests', 'vpn-stack-upgrade.py')


class PolicyVerificationTests(unittest.TestCase):
    def setUp(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        for tag, body in {'smart': '+.proxy.example\n', 'direct': '+.direct.example\n',
                          'ads': '+.ads.example\n'}.items():
            (root / (tag + '.normalized.txt')).write_text(body)
        (root / 'witnesses.json').write_text(json.dumps({'apex': 'proxy.example',
            'child': 'child.proxy.example', 'ads-child': 'child.ads.example'}))
        self.s = SimpleNamespace(personal=load('verification_personal', 'personal-runtime.py'),
            setup=load('verification_setup', 'transport-probes.py'),
            checker=SimpleNamespace(reject_destination=Mock()), wire=object())
        self.manifest = {'personal': {'direct': [], 'proxy': [], 'ads-exceptions': []},
            'counts': {'smart': 1, 'direct': 1, 'ads': 1}, 'config_sha256': 'verified',
            'checksums': {'assets/ads.mrs': 'verified-content'}}
        self.runtime = SimpleNamespace(active=Mock(return_value=(root, self.manifest)),
            modules=lambda: self.s, record=lambda p: json.loads(p.read_bytes()), wait_backend=Mock())
        self.enterContext(patch.object(u, 'policy_modules', return_value=self.s))
        self.dns = self.enterContext(patch.object(u, 'policy_dns', side_effect=lambda s, name, protocol, **kw:
            ['127.0.0.1' if name == 'checkip.amazonaws.com' else '198.18.0.10']))

    def test_live_dns_and_reject_checked_in_addition_to_provider_counts(self):
        evidence = u.ready_policy(self.runtime)
        self.assertEqual(evidence['DNS_TCP_UDP_checks'], 12)
        self.assertEqual(evidence['REJECT_checks'], 1)
        self.runtime.wait_backend.assert_called_once_with(self.s, self.manifest['counts'])
        self.s.checker.reject_destination.assert_called_once_with(self.s.wire, 19080, '198.18.0.10')
        self.assertEqual(evidence['checksums'], self.manifest['checksums'])

    def test_same_counts_with_wrong_ad_rules_are_rejected(self):
        correct = self.dns.side_effect
        self.dns.side_effect = lambda s, name, protocol, **kw: (['127.0.0.1'] if name == 'child.ads.example'
                                                              else correct(s, name, protocol, **kw))
        with self.assertRaisesRegex(self.s.setup.TrialError, 'EXPECTED_ONE_FAKE_IP'):
            u.ready_policy(self.runtime)

    def test_wrong_direct_fake_response_and_failed_reject_do_not_pass(self):
        correct = self.dns.side_effect
        self.dns.side_effect = lambda *a, **kw: ['198.18.0.10']
        with self.assertRaisesRegex(u.UpgradeError, 'UPGRADE_UNEXPECTED_FAKE_IP'):
            u.ready_policy(self.runtime)
        self.dns.side_effect = correct
        self.s.checker.reject_destination.side_effect = RuntimeError('ADVERTISEMENT_DESTINATION_ACCEPTED')
        with self.assertRaisesRegex(RuntimeError, 'ADVERTISEMENT_DESTINATION_ACCEPTED'):
            u.ready_policy(self.runtime)

    def test_provider_failure_and_generation_change_propagate(self):
        self.runtime.wait_backend.side_effect = RuntimeError('BACKEND_PROVIDERS_NOT_READY')
        with self.assertRaisesRegex(RuntimeError, 'BACKEND_PROVIDERS_NOT_READY'):
            u.ready_policy(self.runtime)
        self.runtime.wait_backend.side_effect = None
        before = self.runtime.active.return_value
        self.runtime.active.side_effect = (before, (before[0] / 'different-generation', self.manifest))
        with self.assertRaisesRegex(u.UpgradeError, 'UPGRADE_POLICY_CHANGED_DURING_VERIFICATION'):
            u.ready_policy(self.runtime)


class FinishVerificationTests(unittest.TestCase):
    setUp = fixtures.UpgradeTests.setUp
    fixture = fixtures.UpgradeTests.fixture
    stage_policy = fixtures.UpgradeTests.stage_policy
    activate = fixtures.UpgradeTests.activate
    run_upgrade = fixtures.UpgradeTests.run_upgrade
    assert_preserved = fixtures.UpgradeTests.assert_preserved
    interrupt_swap = fixtures.UpgradeTests.interrupt_swap

    def test_previous_terminal_success_without_policy_evidence_is_rechecked(self):
        self.fixture()
        self.interrupt_swap('lib')
        upgrade = fixtures.u
        self.run_upgrade(True)
        journal = r.record(upgrade.journal_path(i))
        journal.pop('service_verification')
        upgrade.save_journal(i, r, journal)
        before = r.CONFIG.read_bytes()
        with patch.object(upgrade, 'ready_policy', side_effect=RuntimeError('STALE_POLICY')):
            with self.assertRaisesRegex(RuntimeError, 'STALE_POLICY'):
                self.run_upgrade(True)
        self.assertFalse(r.record(upgrade.journal_path(i))['services_restored'])
        self.assertEqual(r.CONFIG.read_bytes(), before)
        self.assertEqual(self.run_upgrade(True)['status'], 'recovered')
        self.assertEqual(r.CONFIG.read_bytes(), before)
    def test_failed_policy_verification_retries_restart_preserving_user_edits(self):
        self.fixture()
        self.interrupt_swap('lib')
        upgrade = fixtures.u
        with upgrade.deploy_lock(i), upgrade.policy_lock(i, r):
            upgrade.recover(i, r, defer_stop=True)
        before = r.CONFIG.read_bytes()
        commands = []
        original = r.run.side_effect
        def command(args, *a, **kw):
            if args[:2] == ['systemctl', 'restart']:
                with r.lock():
                    pass
            commands.append(args)
            return original(args, *a, **kw) if original else b''
        with patch.object(r, 'run', side_effect=command), patch.object(upgrade, 'ready_policy',
                side_effect=RuntimeError('STALE_POLICY')):
            with self.assertRaisesRegex(RuntimeError, 'STALE_POLICY'):
                self.run_upgrade(True)
        self.assertFalse(r.record(upgrade.journal_path(i))['services_restored'])
        self.assertIn(['systemctl', 'restart', *upgrade.CORE], commands)
        self.assertLess(commands.index(['systemctl', 'reset-failed', *upgrade.CORE]),
                        commands.index(['systemctl', 'restart', *upgrade.CORE]))
        personal = r.ETC / 'direct.txt'
        personal.write_bytes(b'preserved-on-retry.example\n')
        self.assertEqual(self.run_upgrade(True)['status'], 'recovered')
        self.assertEqual(personal.read_bytes(), b'preserved-on-retry.example\n')
        self.assertEqual(r.CONFIG.read_bytes(), before)
        self.assertTrue(r.record(upgrade.journal_path(i))['services_restored'])
        self.assert_preserved()
