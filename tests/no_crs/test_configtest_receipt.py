"""Configuration evidence is a real host operation, not HTTP or an event alias.

These are unit boundary inputs only; no runtime artifact or native event is
created by this test module.
"""
from __future__ import annotations

import importlib.util
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "no_crs_configtest", ROOT / "ci/checks/catalog/no_crs_baseline.py"
)
assert SPEC is not None and SPEC.loader is not None
no_crs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(no_crs)


class ConfigtestReceiptTest(unittest.TestCase):
    def setUp(self) -> None:
        self.cases = {case['case_id']: case for case in no_crs.catalog_cases(no_crs.load_catalog())}
        self.case = self.cases['invalid_boolean']
        self.temporary = tempfile.TemporaryDirectory(prefix='config-receipt-unit-')
        self.addCleanup(self.temporary.cleanup)
        self.artifact_root = Path(self.temporary.name)

    def valid_raw(self) -> dict[str, object]:
        """Isolated unit fixture only, never a runtime evidence producer."""
        bundle = self.artifact_root / 'inventory/configtests/invalid_boolean'
        bundle.mkdir(parents=True, exist_ok=True)
        config = (f'load_module "{bundle}/nginx-module.so";\n'
                  f'pid "{bundle}/nginx.pid";\n'
                  f'error_log "{bundle}/nginx-error.log";\n'
                  'events {}\nhttp {\n  modsecurity maybe;\n}\n').encode()
        files = {'nginx-binary': ('binary_sha256', b'unit binary'),
                 'nginx-module.so': ('module_sha256', b'unit module'),
                 'nginx.conf': ('config_path_identity', config),
                 'stdout.log': ('stdout_sha256', b''),
                 'stderr.log': ('stderr_sha256', b'"modsecurity" directive invalid boolean value\n')}
        receipt = self.receipt()
        for name, (field, data) in files.items():
            (bundle / name).write_bytes(data)
            receipt[field] = ('sha256:' if name == 'nginx.conf' else '') + hashlib.sha256(data).hexdigest()
        raw = self.raw()
        raw['configtest_receipt'] = receipt
        raw['artifacts'] = {'configtest_dir': 'inventory/configtests/invalid_boolean'}
        return raw

    @staticmethod
    def raw() -> dict[str, object]:
        return {
            'case_id': 'invalid_boolean', 'status': 'PASS', 'live_executed': True,
            'run_id': 'unit-config-run', 'integration_mode': 'native-nginx-http-module',
            'observed_result': 'config_rejected', 'actual_status': 1,
        }

    @staticmethod
    def receipt() -> dict[str, object]:
        return {
            'schema_version': 1, 'case_id': 'invalid_boolean', 'connector': 'nginx',
            'operation': 'configtest', 'run_id': 'unit-config-run',
            'integration_mode': 'native-nginx-http-module',
            'parent_sha': '1' * 40, 'framework_sha': '2' * 40, 'mrts_sha': '3' * 40,
            'binary_sha256': '4' * 64, 'module_sha256': '5' * 64,
            'config_path_identity': 'sha256:' + '6' * 64,
            'directive': 'modsecurity', 'value': 'maybe',
            'expected_outcome': 'config_rejected', 'expected_exit_code': 1,
            'observed_exit_code': 1, 'observed_outcome': 'config_rejected',
            'error_class': 'invalid_boolean',
            'diagnostic_fragments': ['"modsecurity" directive', 'invalid boolean value'],
            'stdout_sha256': '7' * 64, 'stderr_sha256': '8' * 64,
            'process_started': False, 'listener_created': False,
            'timestamp': '2026-10-01T12:00:00Z',
        }

    def test_selected_required_config_has_an_explicit_host_invocation(self) -> None:
        capabilities = {name: {'state': 'verified', 'reason': 'unit host capability'}
                        for name in no_crs.CAPABILITIES}
        selection = no_crs.select_catalog_case(self.case, capabilities, 'http1')
        self.assertEqual(selection['selection_status'], 'SELECTED')
        self.assertIs(self.case['evidence_requirement']['requires_real_host'], True)
        # No capability exclusion or HTTP YAML is an acceptable substitute.
        self.assertEqual(selection['required_capabilities'], ['config_inline_rules'])
        invocation = self.case.get('config_invocations', {}).get('nginx')
        self.assertIsNotNone(invocation, 'selected required configuration has no host invocation contract')
        self.assertEqual(invocation['operation'], 'configtest')
        self.assertEqual(invocation['directive'], 'modsecurity')
        self.assertEqual(invocation['value'], 'maybe')

    def test_claimed_config_rejection_without_receipt_is_not_pass(self) -> None:
        record = no_crs.normalize_case_record(self.raw(), 'nginx', self.cases, [], 'native-nginx-http-module')
        self.assertIsNotNone(record)
        self.assertEqual(record['status'], 'FAIL', 'exit/status assertion is not actual configuration evidence')
        self.assertIn('configuration receipt', record['reason'])

    def test_exact_config_receipt_is_complete_without_synthetic_event(self) -> None:
        raw = self.valid_raw()
        record = no_crs.normalize_case_record(raw, 'nginx', self.cases, [], 'native-nginx-http-module',
                                             configtest_artifact_root=self.artifact_root)
        self.assertIsNotNone(record)
        self.assertEqual(record['status'], 'PASS', record['reason'])
        self.assertEqual(record.get('configtest_receipt'), raw['configtest_receipt'])
        self.assertEqual(record['observed_rule_ids'], [])
        self.assertEqual(record['transaction_ids'], [])
        self.assertIs(record['event_metadata_verified'], False)
        self.assertEqual(no_crs.pass_case_completeness_errors(
            record, [], 'nginx', 'native-nginx-http-module', artifact_root=self.artifact_root), [])

    def test_wrong_or_incomplete_receipts_remain_fail(self) -> None:
        changes = {
            'case_id': 'invalid_size', 'connector': 'apache', 'operation': 'startup',
            'run_id': 'another-run', 'integration_mode': 'compatibility-nginx',
            'directive': 'modsecurity_phase4_mode', 'value': 'on',
            'error_class': 'module_missing', 'observed_exit_code': 0,
            'observed_outcome': 'config_accepted', 'expected_exit_code': 2,
            'diagnostic_fragments': ['"modsecurity" directive'],
            'process_started': True, 'listener_created': True,
            'config_path_identity': 'unknown', 'binary_sha256': 'unknown',
            'parent_sha': 'unknown', 'timestamp': 'unknown',
        }
        for field, value in changes.items():
            with self.subTest(field=field):
                raw = self.valid_raw()
                receipt = raw['configtest_receipt']
                receipt[field] = value
                raw['configtest_receipt'] = receipt
                record = no_crs.normalize_case_record(raw, 'nginx', self.cases, [], 'native-nginx-http-module',
                                                     configtest_artifact_root=self.artifact_root)
                self.assertEqual(record['status'], 'FAIL', record)
        for field in self.receipt():
            with self.subTest(missing=field):
                raw = self.valid_raw()
                receipt = raw['configtest_receipt']
                del receipt[field]
                raw['configtest_receipt'] = receipt
                record = no_crs.normalize_case_record(raw, 'nginx', self.cases, [], 'native-nginx-http-module',
                                                     configtest_artifact_root=self.artifact_root)
                self.assertEqual(record['status'], 'FAIL', record)

    def test_configtest_receipt_cannot_fulfil_http_request_case(self) -> None:
        raw = self.raw()
        raw.update(case_id='empty_header_value', actual_status=200)
        raw['configtest_receipt'] = self.receipt()
        record = no_crs.normalize_case_record(raw, 'nginx', self.cases, [], 'native-nginx-http-module')
        self.assertEqual(record['status'], 'FAIL')
        self.assertIn('configuration receipt has no declared case/host contract', record['reason'])

    def test_complete_record_is_revalidated_against_actual_catalog(self) -> None:
        raw = self.valid_raw()
        record = no_crs.normalize_case_record(raw, 'nginx', self.cases, [], 'native-nginx-http-module',
                                             configtest_artifact_root=self.artifact_root)
        for field, value in (('phase', 1), ('expected_status', 2), ('actual_status', 2),
                             ('observed_rule_ids', [1100001]), ('http_status', 200),
                             ('observed_event_fields', ['rule_id'])):
            with self.subTest(field=field):
                corrupted = copy.deepcopy(record)
                corrupted[field] = value
                self.assertTrue(no_crs.pass_case_completeness_errors(
                    corrupted, [], 'nginx', 'native-nginx-http-module', artifact_root=self.artifact_root))

    def test_configuration_metadata_cannot_relabel_request_contract(self) -> None:
        catalog = copy.deepcopy(no_crs.load_catalog())
        target = next(case for case in catalog['cases'] if case['case_id'] == 'empty_header_value')
        target['config_invocations'] = copy.deepcopy(self.case['config_invocations'])
        self.assertTrue(any('configtest contract' in error for error in no_crs.validate_catalog(catalog)))

    def test_nginx_selection_exposes_action_without_reducing_required_scope(self) -> None:
        capabilities = {name: {'state': 'verified', 'reason': 'unit host capability'}
                        for name in no_crs.CAPABILITIES}
        selection = no_crs.select_catalog_case(self.case, capabilities, 'http1', 'nginx')
        self.assertEqual(selection['selection_status'], 'SELECTED')
        self.assertEqual(selection['config_invocation'], self.case['config_invocations']['nginx'])
        non_nginx = no_crs.select_catalog_case(self.case, capabilities, 'http1', 'apache')
        self.assertEqual(non_nginx['selection_status'], 'SELECTED')
        self.assertNotIn('config_invocation', non_nginx)

    def test_canonical_run_identity_cannot_borrow_foreign_config_receipt(self) -> None:
        raw = self.valid_raw()
        record = no_crs.normalize_case_record(raw, 'nginx', self.cases, [], 'native-nginx-http-module',
                                             configtest_artifact_root=self.artifact_root)
        result = {'connector': 'nginx', 'connector_commit': '1' * 40,
                  'framework_commit': '2' * 40, 'run_id': 'unit-config-run',
                  'integration_mode': 'native-nginx-http-module'}
        self.assertEqual(no_crs.configtest_run_identity_errors(record, result, '3' * 40), [])
        for field in result:
            with self.subTest(field=field):
                foreign = dict(result)
                foreign[field] = 'another-identity'
                self.assertTrue(no_crs.configtest_run_identity_errors(record, foreign, '3' * 40))
        self.assertTrue(no_crs.configtest_run_identity_errors(record, result, '4' * 40))


if __name__ == '__main__':
    unittest.main()
