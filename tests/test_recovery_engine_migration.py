"""Real loaders/engines, locks and rollback files; macOS ownership/systemd modeled."""
from contextlib import redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

from test_installer import i, r, load
import test_upgrade as fixtures

u = fixtures.u
SNAPSHOT = Path(__file__).parent / 'fixtures/previous-packages'


class PublicationLost(BaseException):
    pass


class MigrationTests(unittest.TestCase):
    snapshot = 'b04a3df'
    snapshot_commit = 'b04a3dfa6ab21ba99ca42f170784875aa0f6405e'
    snapshot_bootstrap = u.VERIFIED_BOOTSTRAP
    setUp = fixtures.UpgradeTests.setUp
    fixture = fixtures.UpgradeTests.fixture
    stage_policy = fixtures.UpgradeTests.stage_policy
    activate = fixtures.UpgradeTests.activate
    assert_preserved = fixtures.UpgradeTests.assert_preserved

    def pending_fixture(self):
        self.fixture()
        raw = (SNAPSHOT / (self.snapshot + '.zip')).read_bytes()
        metadata = json.loads((SNAPSHOT / (self.snapshot + '.json')).read_bytes())
        self.assertEqual(metadata['commit'], self.snapshot_commit)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), metadata['package_sha256'])
        self.legacy_package = self.project / 'legacy-package'
        self.legacy_package.mkdir(mode=0o700)
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            for name in archive.namelist():
                self.assertEqual(Path(name).name, name)
                r.atomic(self.legacy_package / name, archive.read(name))
        self.legacy = load(self.snapshot + '_engine', self.legacy_package / 'vpn-stack-upgrade.py')
        self.assertEqual(hashlib.sha256(self.legacy.BOOTSTRAP).hexdigest(), metadata['loader_sha256'])
        self.assertEqual(self.legacy.BOOTSTRAP, self.snapshot_bootstrap)
        expected = r.record(self.legacy_package / 'code-manifest.json')['files']
        self.assertEqual({name for name in expected if not name.endswith('.py')},
                         set() if self.snapshot == 'b04a3df' else set(self.legacy_package_baselines))
        self.legacy.bundle(r, self.legacy_package, expected)
        # Model the historical installed file set. The pending transaction is
        # created by the exact historical upgrade code with its exact package.
        state = r.record(i.STATE)
        for name in r.BASELINE_FILES:
            if name not in expected:
                (r.CODE / name).unlink()
                state['package_files'].pop(name)
        r.atomic(r.CODE / 'code-manifest.json', r.dump({'files': state['package_files']}), 0o644)
        r.atomic(i.STATE, r.dump(state))
        self.before[i.STATE] = i.STATE.read_bytes()
        self.old_manifest = (r.CODE / 'code-manifest.json').read_bytes()
        self.enterContext(patch.object(self.legacy, 'arm_guardian'))
        self.enterContext(patch.object(self.legacy, 'stage_policy', side_effect=self.stage_policy))
        rename, recover = self.legacy.sync_rename, self.legacy.recover
        recovery_calls = 0
        def lost(source, destination):
            rename(source, destination)
            if destination.name == 'old-lib':
                raise PublicationLost()
        def cannot_recover(*a, **kw):
            nonlocal recovery_calls
            recovery_calls += 1
            if recovery_calls > 1:
                raise PublicationLost()
            return recover(*a, **kw)
        historical_runtime = load(self.snapshot + '_runtime', self.legacy_package / 'vpn-stack-runtime.py')
        with patch.object(self.legacy, 'sync_rename', side_effect=lost), \
             patch.object(r, 'require_baseline', side_effect=getattr(historical_runtime, 'require_baseline', r.require_baseline)), \
             patch.object(self.legacy, 'recover', side_effect=cannot_recover), redirect_stdout(io.StringIO()):
            with self.assertRaises(PublicationLost):
                self.legacy.upgrade(self.legacy_package, i)
        self.root_upgrade = self.project / 'state/upgrade'
        self.old_pointer = (self.root_upgrade / 'engine.json').read_bytes()
        self.assertFalse(r.CODE.exists())
        journal = r.record(u.journal_path(i))
        self.assertEqual(journal['status'], 'applying')
        transaction = self.root_upgrade / journal['transaction']
        self.assertEqual(journal['target_files'], expected)
        for name in (*expected, 'code-manifest.json'):
            self.assertEqual((transaction / 'package' / name).read_bytes(), (self.legacy_package / name).read_bytes())
        for name in (u.LOADER, 'recover.py'):
            self.assertEqual((self.root_upgrade / name).read_bytes(), self.legacy.BOOTSTRAP)
        # lstat/fstat/stat model root ownership on macOS; production loader checks
        # still execute. No bytes, digests, modes, paths or locks are bypassed.
        lstat = Path.lstat
        def owned(path, *a, **kw):
            fields = list(lstat(path, *a, **kw))
            fields[4] = 0
            return os.stat_result(fields)
        self.enterContext(patch.object(Path, 'lstat', owned))
        self.executed_engines = []

    def infrastructure(self):
        return u.infrastructure(i, r, i.units(r), self.package, activate=False)

    def run_disk_loader(self, name, services=False):
        path = self.root_upgrade / name
        specification = importlib.util.spec_from_file_location
        def instrument(module_name, location, *a, **kw):
            spec = specification(module_name, location, *a, **kw)
            if module_name == 'vpn_upgrade_recovery':
                execute = spec.loader.exec_module
                def load_engine(module):
                    execute(module)  # Run exact selected engine bytes from disk.
                    self.executed_engines.append(Path(location).parent.name)
                    # Native services and the runtime driver use the existing
                    # fixture; boot_recover/recover/finish_services remain real.
                    module.recovery_modules = lambda *_: (i, r)
                    module.ready_dns = lambda: None
                    module.ready_policy = lambda *_: {'scope': 'mocked-native-services'}
                spec.loader.exec_module = load_engine
            return spec
        argv = [str(path)] + (['--services'] if services else [])
        with patch.object(sys, 'argv', argv), \
             patch.object(importlib.util, 'spec_from_file_location', side_effect=instrument), \
             patch('subprocess.run', return_value=SimpleNamespace(stdout=b'')), redirect_stdout(io.StringIO()):
            # Execute the loader that actually survived publication loss. Do not
            # use BOOTSTRAP from the working tree or call recover directly.
            try:
                exec(compile(path.read_bytes(), str(path), 'exec'), {'__file__': str(path)})
            except SystemExit as error:
                self.assertEqual(error.code, 0)

    def assert_recovered(self, loader):
        selected = r.record(self.root_upgrade / 'engine.json')['directory']
        executions = len(self.executed_engines)
        self.run_disk_loader(loader)
        if len(self.executed_engines) > executions:
            self.assertEqual(self.executed_engines[-1], selected)
        self.assertEqual(r.record(u.journal_path(i))['status'], 'rolled_back')
        self.assertEqual((r.DATA / 'current').resolve(), self.old)
        self.assertEqual((r.CODE / 'code-manifest.json').read_bytes(), self.old_manifest)
        self.assertFalse((r.DATA / 'update.lock').is_symlink())
        r.run.assert_any_call(['systemctl', '--no-block', 'start', u.FINISH_UNIT],
                             'UPGRADE_SERVICE_RECOVERY_QUEUE_FAILED')
        self.run_disk_loader(loader, services=True)
        self.assertEqual(self.executed_engines[-1], selected)
        self.assertTrue(r.record(u.journal_path(i))['services_restored'])
        self.assert_preserved()
        for path, raw in self.before.items():
            self.assertEqual(path.read_bytes(), raw, str(path))
        expected = r.record(i.STATE)['package_files']
        self.assertEqual({name for name in r.BASELINE_FILES if (r.CODE / name).exists()},
                         set(expected) & set(r.BASELINE_FILES))

    def test_every_loader_and_pointer_publication_boundary_runs_surviving_loader(self):
        for boundary in (u.LOADER, 'recover.py', 'engine.json'):
            for timing in ('before', 'after'):
                for loader in (u.LOADER, 'recover.py'):
                    with self.subTest(boundary=boundary, timing=timing, loader=loader):
                        case = type(self)()
                        try:
                            case.setUp()
                            case.pending_fixture()
                            atomic = r.atomic
                            synced = []
                            sync = u.sync_directory
                            def directory(path):
                                sync(path)
                                synced.append(Path(path))
                            def publish(path, raw, *a, **kw):
                                if path.name == 'engine.json':
                                    for entry in (u.LOADER, 'recover.py'):
                                        case.assertEqual((case.root_upgrade / entry).read_bytes(), u.BOOTSTRAP)
                                    case.assertGreaterEqual(synced.count(case.root_upgrade), 2)
                                    case.assertIn(case.root_upgrade.parent, synced)
                                if path.parent == case.root_upgrade and path.name == boundary and timing == 'before':
                                    raise PublicationLost()
                                atomic(path, raw, *a, **kw)
                                if path.parent == case.root_upgrade and path.name == boundary and timing == 'after':
                                    raise PublicationLost()
                            with patch.object(r, 'atomic', side_effect=publish), \
                                 patch.object(u, 'sync_directory', side_effect=directory), case.assertRaises(PublicationLost):
                                case.infrastructure()
                            if boundary != 'engine.json' or timing == 'before':
                                case.assertEqual((case.root_upgrade / 'engine.json').read_bytes(), case.old_pointer)
                            else:
                                case.assertNotEqual((case.root_upgrade / 'engine.json').read_bytes(), case.old_pointer)
                            case.assert_recovered(loader)
                        finally:
                            case.doCleanups()

    def test_new_loaders_recover_with_exact_python_only_old_engine(self):
        self.pending_fixture()
        for name in (u.LOADER, 'recover.py'):
            r.atomic(self.root_upgrade / name, u.BOOTSTRAP, 0o600 if name == 'recover.py' else 0o644)
        self.assert_recovered('recover.py')
        # The other entry point also reaches this exact old engine for services.
        self.run_disk_loader(u.LOADER, services=True)
        self.assertEqual(self.executed_engines[-1], r.record(self.root_upgrade / 'engine.json')['directory'])

    def test_unknown_or_edited_infrastructure_is_refused_before_any_selection_change(self):
        for target in (u.LOADER, 'recover.py', u.BOOT_UNIT, u.FINISH_UNIT, u.GUARDIAN_UNIT,
                       '20-vpn-upgrade-recovery.conf', 'engine.json', 'selected-engine'):
            for mutation in ('unknown', 'edit'):
                with self.subTest(target=target, mutation=mutation):
                    case = type(self)()
                    try:
                        case.setUp()
                        case.pending_fixture()
                        if target in (u.LOADER, 'recover.py', 'engine.json'):
                            path = case.root_upgrade / target
                        elif target == 'selected-engine':
                            path = case.root_upgrade / r.record(case.root_upgrade / 'engine.json')['directory'] / 'vpn-stack-upgrade.py'
                        elif target == '20-vpn-upgrade-recovery.conf':
                            path = i.UNIT_ROOT / 'vpn-stack-ip.timer.d' / target
                        else:
                            path = i.UNIT_ROOT / target
                        path.write_bytes(b'UNKNOWN_INFRASTRUCTURE' if mutation == 'unknown' else path.read_bytes() + b'\n# edited\n')
                        pointer = (case.root_upgrade / 'engine.json').read_bytes()
                        loaders = {name: (case.root_upgrade / name).read_bytes() for name in (u.LOADER, 'recover.py')}
                        with case.assertRaises((u.UpgradeError, r.StackError, ValueError)):
                            case.infrastructure()
                        case.assertEqual((case.root_upgrade / 'engine.json').read_bytes(), pointer)
                        case.assertEqual({name: (case.root_upgrade / name).read_bytes() for name in loaders}, loaders)
                        case.assertEqual(r.record(u.journal_path(i))['status'], 'applying')
                        case.assertFalse(r.CODE.exists())
                    finally:
                        case.doCleanups()

    def test_new_engine_is_verified_before_loader_or_pointer_publication(self):
        self.pending_fixture()
        target = self.package / 'include-hosts.txt'
        target.write_bytes(target.read_bytes() + b'broken')
        with self.assertRaisesRegex(u.UpgradeError, 'UPGRADE_CODE_CHANGED'):
            self.infrastructure()
        self.assertEqual((self.root_upgrade / 'engine.json').read_bytes(), self.old_pointer)
        for name in (u.LOADER, 'recover.py'):
            self.assertEqual((self.root_upgrade / name).read_bytes(), self.legacy.BOOTSTRAP)
        self.assert_recovered('recover.py')

    def test_exact_previous_loader_reproduces_reported_failure_before_repaired_migration(self):
        self.pending_fixture()
        atomic = r.atomic
        def first_loader(path, raw, *a, **kw):
            if path == self.root_upgrade / u.LOADER:
                raise PublicationLost()
            atomic(path, raw, *a, **kw)
        with patch.object(r, 'atomic', side_effect=first_loader), self.assertRaises(PublicationLost):
            self.infrastructure()
        new_engine = 'engine-' + u.checksum(r.raw_file(self.package / 'code-manifest.json', 1048576))
        # Recreate the reported bad state without changing old loader bytes.
        r.atomic(self.root_upgrade / 'engine.json', r.dump({'directory': new_engine}))
        for loader in (u.LOADER, 'recover.py'):
            with self.assertRaises(AssertionError):
                self.run_disk_loader(loader)
        self.assertEqual(self.executed_engines, [])  # Failure precedes recovery.
        self.assertEqual(r.record(u.journal_path(i))['status'], 'applying')
        self.assertFalse(r.CODE.exists())
        # Restore the prior selection and exercise the corrected migration.
        r.atomic(self.root_upgrade / 'engine.json', self.old_pointer)
        self.infrastructure()
        self.assert_recovered('recover.py')

    def test_legacy_loader_without_pointer_stays_recoverable_during_first_engine_bootstrap(self):
        for boundary in ('engine.json', u.LOADER, 'recover.py'):
            loaders = ('recover.py',) if boundary == 'engine.json' else (u.LOADER, 'recover.py')
            for loader in loaders:
                with self.subTest(boundary=boundary, loader=loader):
                    case = type(self)()
                    try:
                        case.setUp()
                        case.pending_fixture()
                        r.atomic(case.root_upgrade / 'recover.py', u.LEGACY_BOOTSTRAP)
                        (case.root_upgrade / u.LOADER).unlink()
                        (case.root_upgrade / 'engine.json').unlink()
                        atomic = r.atomic
                        def publish(path, raw, *a, **kw):
                            atomic(path, raw, *a, **kw)
                            if path.parent == case.root_upgrade and path.name == boundary:
                                raise PublicationLost()
                        with patch.object(r, 'atomic', side_effect=publish), case.assertRaises(PublicationLost):
                            case.infrastructure()
                        # A surviving legacy loader ignores the seeded engine
                        # selection and reads the Python transaction package.
                        case.run_disk_loader(loader)
                        case.assertEqual(r.record(u.journal_path(i))['status'], 'rolled_back')
                        case.assertEqual((r.CODE / 'code-manifest.json').read_bytes(), case.old_manifest)
                        case.assert_preserved()
                        case.infrastructure()
                        case.assert_recovered(loader)
                    finally:
                        case.doCleanups()

    def test_pointer_based_old_loaders_missing_engine_selection_are_refused(self):
        self.pending_fixture()
        (self.root_upgrade / 'engine.json').unlink()
        with self.assertRaisesRegex(u.UpgradeError, 'UPGRADE_RECOVERY_ENGINE_REQUIRED'):
            self.infrastructure()
        self.assertFalse((self.root_upgrade / 'engine.json').exists())
        for name in (u.LOADER, 'recover.py'):
            self.assertEqual((self.root_upgrade / name).read_bytes(), self.legacy.BOOTSTRAP)
