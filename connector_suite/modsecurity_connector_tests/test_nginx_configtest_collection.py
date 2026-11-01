"""A config receipt must survive collection without becoming request proof."""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import argparse
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = connector_root()
collector = load_source(source_path('ci/runtime/lifecycle/collect-no-crs-source.py', root=ROOT))


class ConfigtestCollectionTest(unittest.TestCase):
    BUNDLE_FILES = ('nginx-binary', 'nginx-module.so', 'nginx.conf', 'stdout.log', 'stderr.log')

    def collect_bundle(self, row: dict[str, object], root: Path | None) -> dict[str, object]:
        cases, _ = collector.case_row_observations(
            row, 'nginx', {'invalid_boolean': (1, None, 0)}, root, None, None)
        return cases[0]

    def make_bundle(self, root: Path) -> Path:
        bundle = root / 'configtest'
        bundle.mkdir()
        for name in self.BUNDLE_FILES:
            (bundle / name).write_text('unit artifact', encoding='utf-8')
        return bundle

    def test_explicit_contained_bundle_reference_survives_collection(self) -> None:
        with tempfile.TemporaryDirectory(prefix='configtest-collector-') as temporary:
            root = Path(temporary)
            bundle = self.make_bundle(root)
            row = self.row()
            row['artifacts'] = {'configtest_dir': str(bundle)}
            observation = self.collect_bundle(row, root)
            self.assertEqual(observation.get('artifacts'), row['artifacts'])
            self.assertEqual(observation['configtest_receipt'], row['configtest_receipt'])

    def test_bundle_references_require_authority_and_closed_existing_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix='configtest-collector-') as temporary:
            root = Path(temporary)
            bundle = self.make_bundle(root)
            row = self.row()
            row['artifacts'] = {'configtest_dir': str(bundle)}
            with self.assertRaises(ValueError):
                self.collect_bundle(row, None)
            for reference in ('relative/bundle', str(root / 'missing'), str(root.parent),
                              'x' * 4097, 1):
                with self.subTest(reference=reference):
                    row['artifacts'] = {'configtest_dir': reference}
                    with self.assertRaises(ValueError):
                        self.collect_bundle(row, root)
            row['artifacts'] = {'configtest_dir': str(bundle), 'unknown_ref': str(bundle)}
            with self.assertRaises(ValueError):
                self.collect_bundle(row, root)
            row['artifacts'] = {'configtest_dir': str(bundle)}
            alias = root / 'alias'
            alias.symlink_to(bundle, target_is_directory=True)
            row['artifacts'] = {'configtest_dir': str(alias)}
            with self.assertRaises(ValueError):
                self.collect_bundle(row, root)
            row['artifacts'] = {'configtest_dir': str(bundle)}
            for name in self.BUNDLE_FILES:
                with self.subTest(missing=name):
                    artifact = bundle / name
                    artifact.unlink()
                    with self.assertRaises(ValueError):
                        self.collect_bundle(row, root)
                    artifact.symlink_to(bundle / 'not-present')
                    with self.assertRaises(ValueError):
                        self.collect_bundle(row, root)
                    artifact.unlink()
                    artifact.write_text('unit artifact', encoding='utf-8')

    def row(self) -> dict[str, object]:
        return {
            'case_id': 'invalid_boolean', 'status': 'PASS', 'actual_status': 1,
            'live_executed': True, 'run_id': 'unit-configtest',
            'integration_mode': 'native-nginx-http-module',
            'observed_result': 'config_rejected',
            # Unit receipt payload only; full canonical validation is Framework-owned.
            'configtest_receipt': {'operation': 'configtest', 'case_id': 'invalid_boolean'},
        }

    def test_actual_source_receipt_and_identity_survive_without_event(self) -> None:
        row = self.row()
        cases, events = collector.case_row_observations(
            row, 'nginx', {'invalid_boolean': (1, None, 0)}, None, None, None)
        self.assertEqual(len(cases), 1)
        self.assertEqual(events, [])
        observation = cases[0]
        for field in ('configtest_receipt', 'run_id', 'integration_mode', 'observed_result'):
            self.assertEqual(observation.get(field), row[field])
        self.assertEqual(observation['transaction_ids'], [])
        self.assertEqual(observation['observed_rule_ids'], [])
        self.assertIs(observation['event_metadata_verified'], False)
        self.assertNotIn('artifacts', observation)

    def test_target_path_fixture_metadata_is_retained_only_for_declared_cases(self) -> None:
        for case_id, leaf, state in (
            ('missing_rules_file', 'missing-rules.conf', 'absent'),
            ('unsafe_event_path', 'unsafe-event-directory', 'directory'),
        ):
            row = self.row()
            row['case_id'] = case_id
            row['configtest_receipt'] = {
                'operation': 'configtest', 'case_id': case_id,
                'fixture_leaf': leaf, 'fixture_state': state,
            }
            observation = collector.configtest_source_fields(row, 0)
            self.assertEqual(observation['configtest_receipt'], row['configtest_receipt'])
            row['case_id'] = 'invalid_boolean'
            with self.assertRaises(ValueError):
                collector.configtest_source_fields(row, 0)

    def test_closed_startup_bundle_retains_probe_without_promoting_a_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = self.make_bundle(root)
            names = ('no-crs-baseline.conf', 'phase1-events.jsonl', 'request-result.json', 'roles.json', 'cleanup.json')
            for name in names:
                (bundle/name).write_text('unit artifact')
            row = self.row()
            row['case_id'] = 'valid_rules_file'
            row['transaction_ids'] = ['unit-tx']
            row['observed_rule_ids'] = [1100001]
            row['configtest_receipt'] = {
                'case_id': 'valid_rules_file', 'operation': 'startup', 'process_started': True,
                'listener_created': True, 'cleanup_verified': True, 'listen_port': 18080,
                'docroot_projection_parent': '/var/tmp/codex/unit-projection',
                'docroot_projection_root': '/var/tmp/codex/unit-projection/child',
                'request_probe': {'run_id': 'unit-configtest', 'transaction_id': 'unit-tx',
                                  'client_exit_code': 0, 'observed_http_status': 403, 'phase': 1, 'rule_id': 1100001},
                **{field: '0'*64 for field in ('rules_sha256', 'events_sha256', 'request_sha256', 'roles_sha256', 'cleanup_sha256')},
            }
            row['artifacts'] = {'configtest_dir': str(bundle)}
            retained = collector.configtest_source_fields(row, 0, root)
            self.assertEqual(retained['configtest_receipt'], row['configtest_receipt'])
            row['case_id'] = 'invalid_boolean'
            with self.assertRaises(ValueError):
                collector.configtest_source_fields(row, 0, root)
            row['case_id'] = 'valid_rules_file'
            for name in names:
                (bundle/name).unlink()
                with self.subTest(missing=name), self.assertRaises(ValueError):
                    collector.configtest_source_fields(row, 0, root)
                (bundle/name).write_text('unit artifact')

    def test_artifact_reference_cannot_turn_request_into_configuration_proof(self) -> None:
        row = self.row()
        row['artifacts'] = {'configtest_dir': '/not-authorized'}
        with self.assertRaises(ValueError):
            collector.configtest_source_fields(row, 1)
        del row['configtest_receipt']
        self.assertEqual(collector.configtest_source_fields(row, 0), {})

    def test_compound_native_transaction_survives_without_phase_zero_event_claim(self) -> None:
        row = {**self.row(), 'case_id': 'valid_rules_file', 'actual_status': 0,
               'observed_rule_ids': [1100001], 'transaction_ids': ['unit-native-tx'],
               'configtest_receipt': {'case_id': 'valid_rules_file', 'operation': 'startup',
                   'request_probe': {'transaction_id': 'unit-native-tx'}}}
        cases, events = collector.case_row_observations(
            row, 'nginx', {'valid_rules_file': (0, '1100001', 0)}, None, None, None)
        self.assertEqual(events, [])
        self.assertEqual(cases[0]['transaction_ids'], ['unit-native-tx'])
        self.assertEqual(cases[0]['observed_rule_ids'], [1100001])
        self.assertEqual(cases[0]['observed_event_fields'], [])
        self.assertIs(cases[0]['event_metadata_verified'], False)
        for values in ([], ['foreign'], ['unit-native-tx', 'foreign'], ['unit-native-tx'] * 2,
                       [True], [1], ['x' * 257]):
            with self.subTest(values=values), self.assertRaises(ValueError):
                collector.configtest_source_fields({**row, 'transaction_ids': values}, 0)
        for values in ([], ['1100001'], [1100002], [1100001, 1100002], [True]):
            with self.subTest(rules=values), self.assertRaises(ValueError):
                collector.configtest_source_fields({**row, 'observed_rule_ids': values}, 0)

    def test_config_only_cases_cannot_claim_host_start_or_request(self) -> None:
        cases, _ = collector.case_row_observations(
            self.row(), 'nginx', {'invalid_boolean': (1, None, 0)}, None, None, None)
        self.assertFalse(collector.request_runtime_observed(None, None, cases, False))
        events = {'transaction_ids': [], 'event_metadata_verified': False,
                  'body_payload_absent_from_events': True, 'event_records': 0,
                  'event_validation_errors': [], 'forbidden_event_keys': []}
        payload = collector.collector_payload(
            argparse.Namespace(connector='nginx', stage_rc=0), 'FAIL', False,
            False, None, None, [], False, cases, events)
        self.assertIs(payload['started'], False)
        self.assertIs(payload['requests_sent'], False)
        self.assertEqual(payload['status'], 'FAIL')

    def test_actual_http_case_remains_request_runtime(self) -> None:
        self.assertTrue(collector.request_runtime_observed(
            200, None, [{'case_id': 'allow_without_marker', 'actual_status': 200}], False))

    def test_closed_startup_probe_is_an_actual_request_not_configtest_only(self) -> None:
        row = {'case_id': 'valid_rules_file', 'status': 'PASS', 'live_executed': True,
               'configtest_receipt': {'case_id': 'valid_rules_file', 'operation': 'startup',
                   'process_started': True, 'listener_created': True,
                   'request_probe': {'client_exit_code': 0, 'observed_http_status': 403}}}
        self.assertTrue(collector.request_runtime_observed(None, None, [row], False))
        for field, value in (('case_id', 'invalid_boolean'), ('live_executed', False)):
            altered = {**row, field: value}
            self.assertFalse(collector.request_runtime_observed(None, None, [altered], False))
        for field, value in (('operation', 'configtest'), ('process_started', False),
                             ('listener_created', False), ('request_probe', {})):
            altered = {**row, 'configtest_receipt': {**row['configtest_receipt'], field: value}}
            self.assertFalse(collector.request_runtime_observed(None, None, [altered], False))



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == '__main__':
    unittest.main()
