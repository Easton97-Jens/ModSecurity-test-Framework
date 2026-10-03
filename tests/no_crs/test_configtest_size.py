"""Configuration contract regressions; fixture bytes are unit data, not host proof."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('size_config_contract', ROOT / 'ci/checks/catalog/no_crs_baseline.py')
assert SPEC
assert SPEC.loader
contract = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(contract)
FIXTURE_SPEC = importlib.util.spec_from_file_location('size_receipt_fixture', Path(__file__).with_name('test_configtest_receipt.py'))
assert FIXTURE_SPEC
assert FIXTURE_SPEC.loader
fixture = importlib.util.module_from_spec(FIXTURE_SPEC)
FIXTURE_SPEC.loader.exec_module(fixture)
ARTIFACT_SPEC = importlib.util.spec_from_file_location('size_artifact_fixture', Path(__file__).with_name('test_configtest_artifacts.py'))
assert ARTIFACT_SPEC
assert ARTIFACT_SPEC.loader
artifact_fixture = importlib.util.module_from_spec(ARTIFACT_SPEC)
ARTIFACT_SPEC.loader.exec_module(artifact_fixture)

EXPECTED = {'operation': 'configtest', 'directive': 'modsecurity_phase4_body_limit', 'value': 'maybe',
            'expected_exit_code': 1, 'expected_outcome': 'config_rejected', 'error_class': 'invalid_size',
            'diagnostic_fragments': ['"modsecurity_phase4_body_limit" directive',
                                     'invalid value for modsecurity_phase4_body_limit']}


class ConfigtestSizeTest(unittest.TestCase):
    def setUp(self):
        self.cases = {case['case_id']: case for case in contract.catalog_cases(contract.load_catalog())}
        self.temporary = tempfile.TemporaryDirectory(prefix='size-config-unit-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def raw(self):
        case_id = 'invalid_size'
        bundle = self.root / 'inventory/configtests' / case_id
        bundle.mkdir(parents=True, exist_ok=True)
        config = (f'load_module "{bundle}/nginx-module.so";\n'
                  f'pid "{bundle}/nginx.pid";\n'
                  f'error_log "{bundle}/nginx-error.log";\n'
                  'events {}\nhttp {\n  modsecurity_phase4_body_limit maybe;\n}\n').encode()
        files = {'nginx-binary': ('binary_sha256', b'unit binary'),
                 'nginx-module.so': ('module_sha256', b'unit module'),
                 'nginx.conf': ('config_path_identity', config),
                 'stdout.log': ('stdout_sha256', b''),
                 'stderr.log': ('stderr_sha256', b'"modsecurity_phase4_body_limit" directive invalid value for modsecurity_phase4_body_limit\n')}
        receipt = fixture.ConfigtestReceiptTest.receipt()
        receipt.update(EXPECTED, case_id=case_id)
        for name, (field, data) in files.items():
            (bundle / name).write_bytes(data)
            receipt[field] = ('sha256:' if name == 'nginx.conf' else '') + hashlib.sha256(data).hexdigest()
        raw = fixture.ConfigtestReceiptTest.raw()
        raw.update(case_id=case_id, configtest_receipt=receipt,
                   artifacts={'configtest_dir': 'inventory/configtests/' + case_id})
        return raw

    def normalize(self, raw):
        return contract.normalize_case_record(raw, 'nginx', self.cases, [], 'native-nginx-http-module',
                                              configtest_artifact_root=self.root)

    def test_required_size_case_exposes_exact_host_configtest(self):
        capabilities = {name: {'state': 'verified', 'reason': 'unit host capability'} for name in contract.CAPABILITIES}
        selection = contract.select_catalog_case(self.cases['invalid_size'], capabilities, 'http1', 'nginx')
        self.assertEqual(selection['selection_status'], 'SELECTED')
        self.assertEqual(selection.get('config_invocation'), EXPECTED,
                         'selected required configuration has no real host input contract')

    def test_size_bundle_is_complete_without_boolean_or_http_relabel(self):
        raw = self.raw()
        record = self.normalize(raw)
        self.assertEqual(record['status'], 'PASS', record['reason'])
        self.assertEqual(contract.pass_case_completeness_errors(record, [], 'nginx', 'native-nginx-http-module',
                                                                artifact_root=self.root), [])
        self.assertEqual(record['observed_rule_ids'], [])
        self.assertEqual(record['transaction_ids'], [])

    def test_size_receipt_metadata_alone_cannot_pass(self):
        raw = self.raw()
        record = contract.normalize_case_record(raw, 'nginx', self.cases, [], 'native-nginx-http-module')
        self.assertEqual(record['status'], 'FAIL')

    def test_boolean_or_float_exit_in_descriptor_is_not_exact_integer(self):
        for value in (True, 1.0):
            with self.subTest(value=value):
                case = copy.deepcopy(self.cases['invalid_size'])
                case['config_invocations']['nginx']['expected_exit_code'] = value
                self.assertTrue(contract.config_invocation_contract_errors(case))

    def test_boolean_wrong_error_exit_or_case_cannot_certify_size(self):
        for field, value in (('directive', 'modsecurity'), ('value', 'other'), ('case_id', 'invalid_boolean'),
                             ('error_class', 'invalid_boolean'), ('observed_exit_code', 0),
                             ('diagnostic_fragments', ['invalid boolean value'])):
            with self.subTest(field=field):
                raw = copy.deepcopy(self.raw())
                raw['configtest_receipt'][field] = value
                self.assertEqual(self.normalize(raw)['status'], 'FAIL')

    def test_config_tamper_rehash_cannot_hide_wrong_directive(self):
        raw = self.raw()
        path = self.root / raw['artifacts']['configtest_dir'] / 'nginx.conf'
        data = path.read_bytes().replace(b'modsecurity_phase4_body_limit maybe', b'modsecurity maybe')
        path.write_bytes(data)
        raw['configtest_receipt']['config_path_identity'] = 'sha256:' + hashlib.sha256(data).hexdigest()
        self.assertEqual(self.normalize(raw)['status'], 'FAIL')

    def test_two_cases_retain_distinct_bundles_and_reject_alias_and_reuse(self):
        raw_size = self.raw()
        raw_boolean = artifact_fixture.unit_bundle(self.root)
        for raw in (raw_boolean, raw_size):
            raw['artifacts']['configtest_dir'] = str(self.root / raw['artifacts']['configtest_dir'])
        output = self.root / 'canonical'
        output.mkdir()
        context = SimpleNamespace(case_by_id=self.cases, connector='nginx', run_dir=output,
                                  event_integration_mode=None,
                                  configtest_source_roots={id(raw): self.root for raw in (raw_boolean, raw_size)},
                                  configtest_copied_cases=set(),
                                  manifest={'artifacts': {}, 'integration_mode': 'native-nginx-http-module'})
        records = contract.normalized_finalize_case_records(context, [raw_boolean, raw_size], [])
        self.assertEqual([row['status'] for row in records], ['PASS', 'PASS'])
        self.assertEqual(len(context.manifest['artifacts']), 10)
        self.assertEqual({row['artifacts']['configtest_dir'] for row in records},
                         {'inventory/configtests/invalid_boolean', 'inventory/configtests/invalid_size'})
        for row in records:
            self.assertEqual(contract.configtest_artifact_errors(row, output), [])
        alias = copy.deepcopy(records[1])
        alias['artifacts'] = records[0]['artifacts']
        self.assertTrue(contract.configtest_artifact_errors(alias, output))
        with self.assertRaises(contract.ContractError):
            contract.retain_finalize_configtest_bundle(context, raw_size)


if __name__ == '__main__':
    unittest.main()
