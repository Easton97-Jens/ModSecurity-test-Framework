"""Current product bytes must survive the historical Traefik capture variants."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock


REPOSITORY = connector_root()


def load(name, path):
    module = load_source(path)
    return module


ADAPTER = load('traefik_current_capture', REPOSITORY / 'connectors/traefik/harness/i12/current_capture.py')
CENTRAL = load('traefik_current_central', REPOSITORY / 'ci/runtime/lifecycle/i12/capture_sources.py')
EXPORT = load('traefik_current_export', REPOSITORY / 'connectors/traefik/harness/i12/source_export.py')


class CurrentCaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        storage = os.environ.get('CODEX_TEMP_ROOT', '/var/tmp/codex/ModSecurity-conector')
        cls.temporary = tempfile.TemporaryDirectory(prefix='traefik-current-capture-', dir=storage)
        cls.root = Path(cls.temporary.name)
        cls.snapshot = cls.root / 'snapshot'
        EXPORT.export(REPOSITORY, cls.snapshot)
        registry = CENTRAL.Registry(REPOSITORY / 'ci/runtime/lifecycle/i12', REPOSITORY)
        targets = {ADAPTER.PROVENANCE, CENTRAL.MARKER, CENTRAL.SNAPSHOT, 'unknown-file'}
        for profile in ADAPTER.PROFILE_HASHES:
            targets.update(registry.manifest['profiles'][profile]['source_targets'])
        cls.originals = {name: (cls.snapshot / name).read_bytes() if (cls.snapshot / name).exists()
                         else None for name in targets}

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        self.source = self.snapshot
        for name, original in self.originals.items():
            path = self.source / name
            if original is None:
                path.unlink(missing_ok=True)
            else:
                path.write_bytes(original)
        (self.source / CENTRAL.RECEIPT).unlink(missing_ok=True)
        capture = self.source / '.i12-capture'
        if capture.exists():
            shutil.rmtree(capture)
        self.registry = CENTRAL.Registry(REPOSITORY / 'ci/runtime/lifecycle/i12', REPOSITORY)

    def rebind_changed_file(self, relative):
        snapshot_path = self.source / CENTRAL.SNAPSHOT
        snapshot = json.loads(snapshot_path.read_text())
        snapshot['files'][relative]['sha256'] = ADAPTER.digest((self.source / relative).read_bytes())
        snapshot_path.write_text(json.dumps(snapshot) + '\n')
        marker_path = self.source / CENTRAL.MARKER
        marker = json.loads(marker_path.read_text())
        marker['snapshot_manifest_sha256'] = ADAPTER.digest(snapshot_path.read_bytes())
        marker_path.write_text(json.dumps(marker) + '\n')

    def apply(self, profile='traefik-forwardauth'):
        return ADAPTER.apply(CENTRAL, self.registry, profile, self.source)

    def assert_unwritten(self):
        self.assertFalse((self.source / CENTRAL.RECEIPT).exists())
        self.assertFalse((self.source / '.i12-capture').exists())

    def test_native_preserves_current_runtime_and_authorization(self):
        receipt = self.apply('traefik-native')
        for relative in (ADAPTER.RUNTIME, ADAPTER.AUTHORIZATION):
            self.assertEqual(ADAPTER.digest((self.source / relative).read_bytes()), ADAPTER.CURRENT[relative])
            self.assertEqual(receipt['transformations'][relative]['strategy'], 'current-product-preserved')
        self.assertEqual(receipt['profile_sha256'], ADAPTER.PROFILE_HASHES['traefik-native'])
        self.assert_declared_fixtures(receipt)

    def test_forwardauth_rebases_all_product_observations(self):
        receipt = self.apply()
        for relative, expected in ADAPTER.REBASED.items():
            self.assertEqual(ADAPTER.digest((self.source / relative).read_bytes()), expected)
            self.assertEqual(receipt['actual_before_sha256'][relative], ADAPTER.CURRENT[relative])
            self.assertEqual(receipt['exact_written_sha256'][relative], expected)
            self.assertRegex(receipt['transformations'][relative]['applied_delta_sha256'], '^[0-9a-f]{64}$')
        provenance = (self.source / ADAPTER.PROVENANCE).read_text()
        self.assertIn('openSession(i12ObservedContext(w.request), w.parent.config, handle)', provenance)
        self.assertIn('openSession(context.WithValue(ctx, i12ObserverContextKey{}, i12RequestProbeID(w.request))', provenance)
        self.assertIn('context.WithTimeout(context.Background(), time.Duration(w.parent.config.TimeoutMillis)*time.Millisecond)', provenance)
        runtime = (self.source / ADAPTER.RUNTIME).read_text()
        for hook in ('companion_retired', 'companion_registered', 'companion_claimed'):
            self.assertEqual(runtime.count('msconnector_lifecycle_' + hook + '('), 1)
        authorization = (self.source / ADAPTER.AUTHORIZATION).read_text()
        self.assertEqual(authorization.count('msconnector_lifecycle_authorization_request_eos('), 1)
        self.assertIn('remaining -= received_size;\n    }\n    (void)msconnector_lifecycle_authorization_request_eos(', authorization)
        self.assertIn('msconnector_runtime_transaction_destroy(&entry->transaction);\n        (void)msconnector_lifecycle_companion_retired(', runtime)
        self.assertIn('transaction->response_companion_handed_off = 1;\n    (void)msconnector_lifecycle_companion_registered(', runtime)
        self.assert_declared_fixtures(receipt)

    def test_old_absolute_offsets_do_not_describe_current_observation_placement(self):
        profile = self.registry.manifest['profiles']['traefik-forwardauth']
        for name in (ADAPTER.RUNTIME, ADAPTER.AUTHORIZATION):
            original = (self.source / name).read_bytes()
            entry = self.registry.manifest['objects'][profile['source_targets'][name]['sha256']]
            absolute = CENTRAL.exact_patch(original, CENTRAL.plain(self.registry.root / entry['patch']))
            self.assertNotEqual(ADAPTER.digest(absolute), ADAPTER.REBASED[name])
            if name == ADAPTER.AUTHORIZATION:
                self.assertIn(b'received_size, error) != 1) return 0;\n    (void)msconnector_lifecycle_authorization_request_eos(', absolute)
            else:
                self.assertIn(b'MSCONNECTOR_DECISION_ACTION_ABORT_CONNECTION :\n        msconnector_runtime_transaction *observed_transaction', absolute)

    def assert_declared_fixtures(self, receipt):
        profile = self.registry.manifest['profiles'][receipt['profile']]
        for name, entry in profile['capture_files'].items():
            relative = '.i12-capture/' + receipt['profile'] + '/' + name
            self.assertEqual(receipt['exact_written_sha256'][relative], entry['sha256'])
        for name in ('ci/runtime/lifecycle/native-lifecycle-observer.c',
                     'ci/runtime/lifecycle/native-lifecycle-observer.h'):
            self.assertEqual(receipt['exact_written_sha256'][name], profile['source_targets'][name]['sha256'])
            self.assertEqual(receipt['transformations'][name]['strategy'], 'central-declared-output')

    def test_rejects_v1_even_with_valid_historical_marker(self):
        marker = {'format': 'i12-disposable-source-copy-v1', 'path': str(self.source),
                  'disposable': True, 'parent_sha': self.registry.manifest['delivery_product_baseline']}
        (self.source / CENTRAL.MARKER).write_text(json.dumps(marker) + '\n')
        with self.assertRaisesRegex(ValueError, 'complete v2 export'):
            self.apply()
        self.assert_unwritten()

    def test_rejects_unknown_profile(self):
        with self.assertRaisesRegex(ValueError, 'Only sealed Traefik'):
            self.apply('haproxy-native')
        self.assert_unwritten()

    def test_current_before_only_cannot_authorize_historical_product_rollback(self):
        profile = self.registry.manifest['profiles']['traefik-forwardauth']
        profile['source_targets'][ADAPTER.RUNTIME]['current_before_sha256'] = ADAPTER.CURRENT[ADAPTER.RUNTIME]
        with self.assertRaisesRegex(ValueError, 'profile differs'):
            self.apply()
        self.assertEqual(ADAPTER.digest((self.source / ADAPTER.RUNTIME).read_bytes()), ADAPTER.CURRENT[ADAPTER.RUNTIME])
        self.assert_unwritten()

    def test_rejects_unknown_current_input_after_valid_full_export_binding(self):
        path = self.source / ADAPTER.AUTHORIZATION
        path.write_bytes(path.read_bytes() + b'\n/* unknown source */\n')
        self.rebind_changed_file(ADAPTER.AUTHORIZATION)
        with self.assertRaisesRegex(ValueError, 'Exact current source-copy base differs'):
            self.apply()
        self.assert_unwritten()

    def test_rejects_unlisted_export_file(self):
        (self.source / 'unknown-file').write_text('unlisted\n')
        with self.assertRaisesRegex(ValueError, 'Unexpected export object'):
            self.apply()
        self.assert_unwritten()

    def test_rejects_tampered_sealed_central_delta_before_writes(self):
        profile = self.registry.manifest['profiles']['traefik-forwardauth']
        object_entry = self.registry.manifest['objects'][profile['source_targets'][ADAPTER.RUNTIME]['sha256']]
        patch = self.registry.root / object_entry['patch']
        original_plain = CENTRAL.plain
        def tampered(path):
            data = original_plain(path)
            return data + b'changed\n' if path == patch else data
        with mock.patch.object(CENTRAL, 'plain', side_effect=tampered):
            with self.assertRaisesRegex(ValueError, 'Source delta hash mismatch'):
                self.apply()
        self.assert_unwritten()

    def test_rejects_different_pinned_result_before_writes(self):
        with mock.patch.dict(ADAPTER.REBASED, {ADAPTER.RUNTIME: '0' * 64}):
            with self.assertRaisesRegex(ValueError, 'Pinned current observation output differs'):
                self.apply()
        self.assert_unwritten()

    def test_rejects_unknown_provenance_input(self):
        path = self.source / ADAPTER.PROVENANCE
        path.write_bytes(path.read_bytes() + b'\n// unknown provenance\n')
        self.rebind_changed_file(ADAPTER.PROVENANCE)
        with self.assertRaisesRegex(ValueError, 'Exact current provenance source differs'):
            self.apply()
        self.assert_unwritten()

    def test_observation_delta_rejects_overlap_with_product_edit(self):
        before = b'a\nb\nc\nd\ne\nf\n'
        observed = b'a\nb\nc\nprobe\nd\ne\nf\n'
        with self.assertRaisesRegex(ValueError, 'overlaps changed current product'):
            ADAPTER.observation_delta(CENTRAL, before, observed, b'a\nb\nc\nnew product\nd\ne\nf\n')



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == '__main__':
    unittest.main()
