"""Real temporary filesystem and publication faults; service/native calls stubbed."""
import hashlib
import json
import os
from pathlib import Path
import signal
import unittest
from unittest.mock import patch

from test_installer import r, i, load
import test_upgrade as fixtures
u = fixtures.u


class ReviewTests(unittest.TestCase):
    setUp = fixtures.UpgradeTests.setUp
    fixture = fixtures.UpgradeTests.fixture
    stage_policy = fixtures.UpgradeTests.stage_policy
    activate = fixtures.UpgradeTests.activate
    run_upgrade = fixtures.UpgradeTests.run_upgrade
    assert_preserved = fixtures.UpgradeTests.assert_preserved
    interrupt_swap = fixtures.UpgradeTests.interrupt_swap

    def assert_restored(self):
        self.assert_preserved()
        self.assertEqual((r.DATA / 'current').resolve(), self.old)
        for path, raw in self.before.items():
            self.assertEqual(path.read_bytes(), raw, str(path))
        self.assertFalse((r.DATA / 'update.lock').is_symlink())
        self.assertTrue(r.record(u.journal_path(i))['services_restored'])
        self.assertEqual(self.run_upgrade(True)['status'], 'unchanged')

    def test_signal_and_io_error_after_replace_before_directory_fsync(self):
        for fault in ('signal', 'io'):
            with self.subTest(fault=fault):
                case = ReviewTests()
                try:
                    case.setUp()
                    case.fixture()
                    replace = os.replace
                    def interrupted(source, destination):
                        replace(source, destination)
                        if Path(destination) == u.journal_path(i) and r.record(destination)['status'] == 'prepared':
                            if fault == 'signal':
                                os.kill(os.getpid(), signal.SIGTERM)
                            raise OSError('directory fsync unavailable')
                    def terminated(*_):
                        raise r.StackError('INTERRUPTED')
                    handler = signal.signal(signal.SIGTERM, terminated)
                    try:
                        with patch.object(os, 'replace', side_effect=interrupted):
                            with self.assertRaises((OSError, r.StackError)):
                                case.run_upgrade()
                    finally:
                        signal.signal(signal.SIGTERM, handler)
                    journal = r.record(u.journal_path(i))
                    self.assertTrue((case.project / 'state/upgrade' / journal['transaction'] / 'backups').is_dir())
                    case.assert_restored()
                finally:
                    case.doCleanups()

    def test_unknown_publication_and_failed_recovery_keep_backups(self):
        self.fixture()
        save = u.save_journal
        def fail(installer, runtime, journal):
            save(installer, runtime, journal)
            if journal['status'] == 'prepared':
                raise OSError('after publication')
            raise RuntimeError('recovery unavailable')
        with patch.object(u, 'save_journal', side_effect=fail):
            with self.assertRaises(RuntimeError):
                self.run_upgrade()
        journal = r.record(u.journal_path(i))
        self.assertTrue((self.project / 'state/upgrade' / journal['transaction'] / 'backups').is_dir())
        self.assertEqual(self.run_upgrade(True)['status'], 'recovered')
        self.assert_restored()

    def test_real_previous_runtimes_and_manual_cleanup_refuse_durable_fence(self):
        snapshots = Path(__file__).resolve().parent / 'fixtures/previous-runtimes'
        manifest = json.loads((snapshots / 'manifest.json').read_bytes())
        self.assertEqual(set(manifest), {'4e643dc', 'a62ad73'})
        self.fixture()
        previous_runtimes = []
        # Exact historical sources are fixtures: shallow clones and source
        # archives need not retain commits removed by a history rewrite.
        for revision, entry in manifest.items():
            raw = (snapshots / entry['file']).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), entry['sha256'], revision)
            path = self.project / (revision + '.py')
            path.write_bytes(raw)
            previous = load('real_previous_' + revision, path)
            previous.configure_paths(self.project)
            with previous.lock():
                pass  # The historical lock works before the upgrade fence.
            previous_runtimes.append(previous)
        self.interrupt_swap('lib')
        # Execute actual historical lock implementations, not a new-code fixture.
        for previous in previous_runtimes:
            with self.assertRaisesRegex(previous.StackError, 'POLICY_LOCK_REQUIRED'):
                with previous.lock():
                    self.fail('old worker crossed fence')
        with self.assertRaisesRegex(BlockingIOError, 'UPGRADE_RECOVERY_REQUIRED'):
            r.cleanup()
        with self.assertRaisesRegex(BlockingIOError, 'UPGRADE_RECOVERY_REQUIRED'):
            with r.lock():
                r.cleanup()
        self.assertEqual(self.run_upgrade(True)['status'], 'recovered')
        self.assert_restored()

    def test_failure_after_files_restored_retries_services_without_rewriting_files(self):
        self.fixture()
        self.interrupt_swap('lib')
        with u.deploy_lock(i), u.policy_lock(i, r):
            self.assertTrue(u.recover(i, r, boot=True))
        self.assertFalse(r.record(u.journal_path(i))['services_restored'])
        original = r.run.side_effect
        def start_failure(args, *a, **kw):
            if args[:2] == ['systemctl', 'restart'] and 'vpn-stack-dns.service' in args:
                # A dependent CLI must be able to take the policy lock here.
                with r.lock():
                    pass
                raise r.StackError('UPGRADE_SERVICES_START_FAILED')
            if original:
                return original(args, *a, **kw)
            return b''
        with patch.object(r, 'run', side_effect=start_failure):
            with self.assertRaisesRegex(r.StackError, 'UPGRADE_SERVICES_START_FAILED'):
                self.run_upgrade(True)
        personal = r.ETC / 'direct.txt'
        personal.write_bytes(b'user-edit-after-rollback.example\n')
        self.assertEqual(self.run_upgrade(True)['status'], 'recovered')
        self.assertEqual(personal.read_bytes(), b'user-edit-after-rollback.example\n')
        self.assert_preserved()
        self.assertTrue(r.record(u.journal_path(i))['services_restored'])
        self.assertEqual(self.run_upgrade(True)['status'], 'unchanged')

    def test_committed_with_unrestored_triggers_and_dns_failure_is_retryable(self):
        self.fixture()
        with patch.object(u, 'finish_services', side_effect=SystemExit('PROCESS_LOSS')):
            with self.assertRaises(SystemExit):
                self.run_upgrade()
        self.assertEqual(r.record(u.journal_path(i))['status'], 'committed')
        current = (r.DATA / 'current').resolve()
        with patch.object(u, 'ready_dns', side_effect=u.UpgradeError('UPGRADE_DNS_NOT_READY')):
            with self.assertRaisesRegex(u.UpgradeError, 'UPGRADE_DNS_NOT_READY'):
                self.run_upgrade(True)
        self.assertFalse(r.record(u.journal_path(i))['services_restored'])
        self.assertEqual(self.run_upgrade(True)['status'], 'recovered')
        self.assertEqual((r.DATA / 'current').resolve(), current)
        self.assert_preserved()
        self.assertEqual(self.run_upgrade(True)['status'], 'unchanged')

    def test_legacy_loader_migrates_exact_bytes_and_refuses_external_edit(self):
        self.fixture()
        self.interrupt_swap('lib')
        loader = self.project / 'state/upgrade/recover.py'
        r.atomic(loader, u.LEGACY_BOOTSTRAP)
        journal = r.record(u.journal_path(i))
        journal.pop('services_restored', None)
        u.save_journal(i, r, journal)
        self.assertEqual(self.run_upgrade(True)['status'], 'recovered')
        self.assertEqual(loader.read_bytes(), u.BOOTSTRAP)
        self.assert_restored()
        loader.write_bytes(loader.read_bytes() + b'# local edit\n')
        with self.assertRaisesRegex(u.UpgradeError, 'UPGRADE_RECOVERY_INFRASTRUCTURE_CHANGED'):
            self.run_upgrade(True)

    def test_legacy_guard_migration_survives_rollback_and_next_upgrade(self):
        self.fixture()
        self.interrupt_swap('lib')
        journal = r.record(u.journal_path(i))
        transaction = self.project / 'state/upgrade' / journal['transaction']
        legacy = u.boot_unit(self.project, legacy=True)
        for row in journal['files']:
            if row['path'] == str(i.UNIT_ROOT / u.BOOT_UNIT):
                r.atomic(transaction / 'backups' / row['backup'], legacy)
                row.update(before=u.checksum(legacy), after=u.checksum(legacy))
                r.atomic(i.UNIT_ROOT / u.BOOT_UNIT, legacy, 0o644)
            if row['path'] == str(i.STATE):
                state = r.record(transaction / 'backups' / row['backup'])
                state['units'][u.BOOT_UNIT] = u.checksum(legacy)
                raw = r.dump(state)
                r.atomic(transaction / 'backups' / row['backup'], raw)
                row['before'] = u.checksum(raw)
                r.atomic(i.STATE, raw)
        u.save_journal(i, r, journal)
        self.assertEqual(self.run_upgrade(True)['status'], 'recovered')
        self.assertEqual((i.UNIT_ROOT / u.BOOT_UNIT).read_bytes(), u.boot_unit(self.project))
        self.assertEqual(r.record(i.STATE)['units'][u.BOOT_UNIT], u.checksum(legacy))
        self.assertEqual(self.run_upgrade()['status'], 'upgraded')
        # The only exception is the exact reviewed legacy/current pair.
        (i.UNIT_ROOT / u.BOOT_UNIT).write_bytes(u.boot_unit(self.project) + b'# external edit\n')
        with self.assertRaisesRegex(u.UpgradeError, 'UPGRADE_RECOVERY_INFRASTRUCTURE_CHANGED'):
            self.run_upgrade(True)
        self.assert_preserved()

    def test_migration_publishes_compatible_loaders_before_service_units(self):
        self.fixture()
        atomic = r.atomic
        def publish(path, raw, *args, **kwargs):
            if path == i.UNIT_ROOT / u.BOOT_UNIT and raw == u.boot_unit(self.project):
                for name in ('recover.py', u.LOADER):
                    self.assertEqual((self.project / 'state/upgrade' / name).read_bytes(), u.BOOTSTRAP)
                pointer = r.record(self.project / 'state/upgrade/engine.json')['directory']
                self.assertTrue((self.project / 'state/upgrade' / pointer / 'vpn-stack-upgrade.py').is_file())
            return atomic(path, raw, *args, **kwargs)
        with patch.object(r, 'atomic', side_effect=publish):
            self.run_upgrade()

    def test_prepared_tree_syncs_new_directories_and_binary_links_before_journal(self):
        self.fixture()
        synced = []
        sync = u.sync_directory
        def track(path):
            sync(path)
            synced.append(Path(path))
        save = u.save_journal
        def prepared(installer, runtime, journal):
            if journal['status'] == 'prepared':
                transaction = self.project / 'state/upgrade' / journal['transaction']
                for relative in ('package', 'backups', 'code/bin', 'code', '.'):
                    self.assertIn(transaction / relative, synced)
                self.assertIn(transaction.parent, synced)
                self.assertIn(Path(journal['new_generation']), synced)
            save(installer, runtime, journal)
        with patch.object(u, 'sync_directory', side_effect=track), patch.object(u, 'save_journal', side_effect=prepared):
            self.run_upgrade()
