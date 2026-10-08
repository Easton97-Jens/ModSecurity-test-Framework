"""Compound configuration proof units; fixtures are never host runtime evidence."""
from __future__ import annotations

import copy
import importlib.util
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('valid_rules_contract', ROOT / 'ci/checks/catalog/no_crs_baseline.py')
assert SPEC and SPEC.loader
contract = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(contract)


class ValidRulesFileReceiptTest(unittest.TestCase):
    def setUp(self) -> None:
        self.case = next(case for case in contract.catalog_cases(contract.load_catalog())
                         if case['case_id'] == 'valid_rules_file')
        self.temporary = tempfile.TemporaryDirectory(prefix='valid-rules-unit-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def unit_bundle(self) -> dict[str, object]:
        """Unit-only observations; not an invocation or published runtime evidence."""
        bundle = self.root / 'inventory/configtests/valid_rules_file'
        bundle.mkdir(parents=True, exist_ok=True)
        projection_parent = self.root / 'projection'
        projection_root = projection_parent / 'invocation'
        projection_root.mkdir(parents=True, exist_ok=True)
        probe = {'observed_http_status': 403, 'client_exit_code': 0, 'phase': 1,
                 'rule_id': 1100001, 'run_id': 'unit-valid-config', 'transaction_id': 'unit-tx'}
        receipt = {'schema_version': 1, 'case_id': 'valid_rules_file', 'connector': 'nginx',
                   **self.case['config_invocations']['nginx'], 'run_id': 'unit-valid-config',
                   'integration_mode': 'native-nginx-http-module', 'parent_sha': '1' * 40,
                   'framework_sha': '2' * 40, 'mrts_sha': '3' * 40,
                   'observed_exit_code': 0, 'observed_outcome': 'config_accepted',
                   'process_started': True, 'listener_created': True, 'cleanup_verified': True,
                   'listen_port': 18088, 'docroot_projection_parent': str(projection_parent),
                   'docroot_projection_root': str(projection_root), 'request_probe': probe,
                   'timestamp': '2026-10-08T08:00:00Z'}
        event = {'connector': 'nginx', 'integration_mode': 'native-nginx-http-module',
                 'event': 'engine_decision', 'message_id': 'MSCONN_EVENT_ENGINE_DECISION',
                 'actual_action': '', 'visible_http_status': 0, 'transport_result': 'not_observable',
                 'phase': 1, 'rule_id': 1100001,
                 'transaction_id': 'unit-tx', 'method': 'GET', 'uri': '/no-crs/deny',
                 'http_status': 403, 'status': 'blocked', 'requested_action': 'deny'}
        request = {'case_id': 'valid_rules_file', 'run_id': 'unit-valid-config',
                   'operation': 'request', 'method': 'GET', 'path': '/no-crs/deny',
                   'header_name': 'X-Modsec-Smoke', 'header_value': 'block',
                   'client_exit_code': 0, 'observed_http_status': 403, 'transaction_id': 'unit-tx'}
        roles = {'run_id': 'unit-valid-config', 'master_pid': 1001, 'worker_pid': 1002,
                 'master_uid': 0, 'worker_uid': 65534}
        cleanup = {'run_id': 'unit-valid-config', 'master_pid': 1001, 'worker_pid': 1002,
                   'master_running': False, 'worker_running': False, 'listener_open': False, 'verified': True}
        files = {'nginx-binary': b'unit binary', 'nginx-module.so': b'unit module',
                 'nginx.conf': contract.valid_rules_config_template(bundle, 18088, str(projection_root)).encode(),
                 'stdout.log': b'', 'stderr.log': f'{bundle}/nginx.conf syntax is ok\n{bundle}/nginx.conf test is successful\n'.encode(),
                 'no-crs-baseline.conf': (ROOT / 'tests/rules/no-crs-baseline.conf').read_bytes(),
                 'phase1-events.jsonl': json.dumps(event).encode() + b'\n',
                 'request-result.json': json.dumps(request).encode(),
                 'roles.json': json.dumps(roles).encode(), 'cleanup.json': json.dumps(cleanup).encode()}
        for name, (field, _) in contract.configtest_artifacts_for_record({'case_id': 'valid_rules_file'}).items():
            (bundle / name).write_bytes(files[name])
            receipt[field] = ('sha256:' if name == 'nginx.conf' else '') + hashlib.sha256(files[name]).hexdigest()
        return {'case_id': 'valid_rules_file', 'status': 'PASS', 'live_executed': True,
                'run_id': 'unit-valid-config', 'integration_mode': 'native-nginx-http-module',
                'actual_status': 0, 'observed_result': 'config_accepted',
                'observed_rule_ids': [1100001], 'transaction_ids': ['unit-tx'],
                'configtest_receipt': receipt, 'artifacts': {'configtest_dir': 'inventory/configtests/valid_rules_file'}}

    def normalize(self, raw: dict[str, object]) -> dict[str, object]:
        return contract.normalize_case_record(raw, 'nginx', {'valid_rules_file': self.case}, [],
                                               'native-nginx-http-module', configtest_artifact_root=self.root)

    def test_exact_compound_raw_bundle_is_revalidated_without_relabeling_phase(self) -> None:
        raw = self.unit_bundle()
        normalized = self.normalize(raw)
        self.assertEqual(normalized['status'], 'PASS', normalized['reason'])
        self.assertEqual(normalized['phase'], 0)
        self.assertEqual(normalized['configtest_receipt']['request_probe']['phase'], 1)
        self.assertTrue(contract.live_http_request_executed(normalized, {'valid_rules_file': self.case}))
        self.assertEqual(contract.pass_case_completeness_errors(normalized, [], 'nginx',
                         'native-nginx-http-module', artifact_root=self.root), [])
        for field, value in (('observed_event_fields', ['phase', 'rule_id']), ('event_metadata_verified', True),
                             ('observed_rule_ids', [1100001, 1100002]), ('transaction_ids', ['unit-tx', 'foreign'])):
            corrupted = copy.deepcopy(normalized)
            corrupted[field] = value
            self.assertTrue(contract.pass_case_completeness_errors(corrupted, [], 'nginx',
                            'native-nginx-http-module', artifact_root=self.root), field)

    def test_foreign_operation_identity_module_and_missing_probe_fail(self) -> None:
        for field, value in (('operation', 'configtest'), ('run_id', 'foreign'),
                             ('case_id', 'invalid_boolean'), ('module_sha256', '0' * 64),
                             ('observed_exit_code', 1), ('process_started', False),
                             ('request_probe', {}), ('cleanup_verified', False)):
            with self.subTest(field=field):
                raw = self.unit_bundle()
                raw['configtest_receipt'][field] = value
                self.assertEqual(self.normalize(raw)['status'], 'FAIL')

    def test_hashes_cannot_promote_wrong_raw_operation_rule_run_or_cleanup(self) -> None:
        mutations = [('request-result.json', 'request_sha256', 'operation', 'reload'),
                     ('request-result.json', 'request_sha256', 'observed_http_status', 200),
                     ('phase1-events.jsonl', 'events_sha256', 'rule_id', 1100002),
                     ('phase1-events.jsonl', 'events_sha256', 'phase', 0),
                     ('phase1-events.jsonl', 'events_sha256', 'transaction_id', 'foreign-tx'),
                     ('phase1-events.jsonl', 'events_sha256', 'run_id', 'foreign-run'),
                     ('phase1-events.jsonl', 'events_sha256', 'method', 'POST'),
                     ('phase1-events.jsonl', 'events_sha256', 'uri', '/unrelated'),
                     ('phase1-events.jsonl', 'events_sha256', 'event', 'phase4_intervention'),
                     ('phase1-events.jsonl', 'events_sha256', 'message_id', 'MSCONN_EVENT_HOST_DECISION'),
                     ('phase1-events.jsonl', 'events_sha256', 'actual_action', 'deny'),
                     ('phase1-events.jsonl', 'events_sha256', 'visible_http_status', 403),
                     ('phase1-events.jsonl', 'events_sha256', 'transport_result', 'complete'),
                     ('phase1-events.jsonl', 'events_sha256', 'http_status', 200),
                     ('phase1-events.jsonl', 'events_sha256', 'status', 'allowed'),
                     ('phase1-events.jsonl', 'events_sha256', 'connector', 'apache'),
                     ('phase1-events.jsonl', 'events_sha256', 'integration_mode', 'compatibility-nginx'),
                     ('roles.json', 'roles_sha256', 'worker_uid', 0),
                     ('cleanup.json', 'cleanup_sha256', 'listener_open', True)]
        for name, field, key, value in mutations:
            with self.subTest(name=name, key=key):
                raw = self.unit_bundle()
                path = self.root / raw['artifacts']['configtest_dir'] / name
                data = json.loads(path.read_bytes())
                data[key] = value
                path.write_bytes(json.dumps(data).encode())
                raw['configtest_receipt'][field] = hashlib.sha256(path.read_bytes()).hexdigest()
                self.assertEqual(self.normalize(raw)['status'], 'FAIL')

    def test_every_raw_leaf_is_required_and_tampering_is_rejected(self) -> None:
        for name in contract.configtest_artifacts_for_record({'case_id': 'valid_rules_file'}):
            with self.subTest(name=name):
                raw = self.unit_bundle()
                path = self.root / raw['artifacts']['configtest_dir'] / name
                path.write_bytes(path.read_bytes() + b'changed')
                self.assertEqual(self.normalize(raw)['status'], 'FAIL')
                raw = self.unit_bundle()
                path.unlink()
                self.assertEqual(self.normalize(raw)['status'], 'FAIL')

    def test_rehashed_ambiguous_or_foreign_native_bundle_cannot_select_one_good_event(self) -> None:
        for key, value in (('transaction_id', 'second-native-tx'), ('run_id', 'foreign-run')):
            with self.subTest(key=key):
                raw = self.unit_bundle()
                path = self.root / raw['artifacts']['configtest_dir'] / 'phase1-events.jsonl'
                original = json.loads(path.read_bytes())
                path.write_bytes(path.read_bytes() + json.dumps({**original, key: value}).encode() + b'\n')
                raw['configtest_receipt']['events_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
                self.assertEqual(self.normalize(raw)['status'], 'FAIL')

    def test_different_rules_even_with_updated_digest_do_not_prove_file_contract(self) -> None:
        raw = self.unit_bundle()
        path = self.root / raw['artifacts']['configtest_dir'] / 'no-crs-baseline.conf'
        path.write_bytes(b'SecRuleEngine Off\n')
        raw['configtest_receipt']['rules_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.assertEqual(self.normalize(raw)['status'], 'FAIL')

    def test_rehashed_duplicate_json_keys_wrong_config_and_missing_fields_fail(self) -> None:
        for name, field, data in (('request-result.json', 'request_sha256', b'{"operation":"request","operation":"reload"}'),
                                  ('phase1-events.jsonl', 'events_sha256', b'{"rule_id":1100001,"rule_id":1100002}\n'),
                                  ('nginx.conf', 'config_path_identity', b'events {}\nhttp { modsecurity off; }\n')):
            raw = self.unit_bundle()
            path = self.root / raw['artifacts']['configtest_dir'] / name
            path.write_bytes(data)
            raw['configtest_receipt'][field] = ('sha256:' if name == 'nginx.conf' else '') + hashlib.sha256(data).hexdigest()
            self.assertEqual(self.normalize(raw)['status'], 'FAIL')
        for key in self.unit_bundle()['configtest_receipt']:
            raw = self.unit_bundle()
            del raw['configtest_receipt'][key]
            self.assertEqual(self.normalize(raw)['status'], 'FAIL', key)

    def test_published_conditional_schema_preserves_both_operation_boundaries(self) -> None:
        schema = contract.load_json(ROOT / 'tests/schemas/no-crs-baseline/configtest-receipt.schema.json')
        receipt = self.unit_bundle()['configtest_receipt']
        self.assertEqual(contract.json_schema_errors(receipt, schema), [])
        for key in ('request_probe', 'cleanup_verified', 'rules_sha256'):
            altered = copy.deepcopy(receipt)
            del altered[key]
            self.assertTrue(contract.json_schema_errors(altered, schema), key)
        for key, value in (('operation', 'configtest'), ('process_started', False), ('expected_exit_code', 1)):
            altered = copy.deepcopy(receipt)
            altered[key] = value
            self.assertTrue(contract.json_schema_errors(altered, schema), key)

    def test_minimal_schema_composition_enforces_negations_and_branch_requirements(self) -> None:
        schema = {'allOf': [{'if': {'properties': {'operation': {'const': 'startup'}}},
                             'then': {'required': ['probe']}, 'else': {'not': {'required': ['probe']}}}]}
        self.assertTrue(contract.json_schema_errors({'operation': 'startup'}, schema))
        self.assertTrue(contract.json_schema_errors({'operation': 'configtest', 'probe': {}}, schema))
        self.assertEqual(contract.json_schema_errors({'operation': 'startup', 'probe': {}}, schema), [])
        self.assertEqual(contract.json_schema_errors({'operation': 'configtest'}, schema), [])
        self.assertTrue(contract.json_schema_errors('foreign', {'anyOf': [{'const': 'a'}, {'const': 'b'}]}))
        self.assertEqual(contract.json_schema_errors('a', {'anyOf': [{'const': 'a'}, {'const': 'b'}]}), [])

    def test_required_config_acceptance_keeps_rule_and_has_closed_startup(self) -> None:
        self.assertEqual(self.case['phase'], 0)
        self.assertEqual(self.case['expected_status'], 0)
        self.assertEqual(self.case['expected_rule_id'], 1100001)
        invocation = self.case.get('config_invocations', {}).get('nginx')
        self.assertIsNotNone(invocation, 'config acceptance lacks actual startup/request contract')
        self.assertEqual(invocation['operation'], 'startup')
        self.assertEqual(contract.config_invocation_contract_errors(self.case), [])

    def test_configtest_zero_alone_is_not_compound_evidence(self) -> None:
        raw = {'case_id': 'valid_rules_file', 'status': 'PASS', 'live_executed': True,
               'run_id': 'unit-valid-config', 'integration_mode': 'native-nginx-http-module',
               'actual_status': 0, 'observed_result': 'config_accepted', 'observed_rule_ids': [1100001]}
        normalized = contract.normalize_case_record(raw, 'nginx', {'valid_rules_file': self.case}, [],
                                                     'native-nginx-http-module')
        self.assertEqual(normalized['status'], 'FAIL')

    def test_arbitrary_phase_zero_receipt_cannot_claim_the_valid_contract(self) -> None:
        case = copy.deepcopy(self.case)
        case['case_id'] = 'arbitrary_config'
        case['config_invocations'] = {'nginx': {
            'operation': 'startup', 'directive': 'modsecurity_rules_file',
            'value': 'no-crs-baseline.conf', 'expected_exit_code': 0,
            'expected_outcome': 'config_accepted', 'error_class': 'none',
            'diagnostic_fragments': ['syntax is ok', 'test is successful'],
        }}
        self.assertTrue(contract.config_invocation_contract_errors(case))


if __name__ == '__main__':
    unittest.main()
