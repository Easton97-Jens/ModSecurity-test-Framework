"""Unit artifacts are not runtime proof; exercise the closed receipt boundary."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('config_artifact_contract', ROOT / 'ci/checks/catalog/no_crs_baseline.py')
assert SPEC and SPEC.loader
contract = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(contract)
RECEIPT_SPEC = importlib.util.spec_from_file_location('config_receipt_unit', Path(__file__).with_name('test_configtest_receipt.py'))
assert RECEIPT_SPEC and RECEIPT_SPEC.loader
receipt_unit = importlib.util.module_from_spec(RECEIPT_SPEC)
RECEIPT_SPEC.loader.exec_module(receipt_unit)


def unit_bundle(root: Path) -> dict[str, object]:
    """Build isolated fixture bytes; never publish these as host evidence."""
    bundle = root / 'inventory/configtests/invalid_boolean'
    bundle.mkdir(parents=True)
    config = (f'load_module "{bundle}/nginx-module.so";\n'
              f'pid "{bundle}/nginx.pid";\n'
              f'error_log "{bundle}/nginx-error.log";\n'
              'events {}\nhttp {\n  modsecurity maybe;\n}\n').encode()
    files = {'nginx-binary': b'unit binary', 'nginx-module.so': b'unit module',
             'nginx.conf': config, 'stdout.log': b'',
             'stderr.log': b'nginx: [emerg] "modsecurity" directive invalid boolean value\n'}
    receipt = receipt_unit.ConfigtestReceiptTest.receipt()
    keys = {'nginx-binary': 'binary_sha256', 'nginx-module.so': 'module_sha256',
            'nginx.conf': 'config_path_identity', 'stdout.log': 'stdout_sha256', 'stderr.log': 'stderr_sha256'}
    for name, data in files.items():
        (bundle / name).write_bytes(data)
        receipt[keys[name]] = ('sha256:' if name == 'nginx.conf' else '') + hashlib.sha256(data).hexdigest()
    raw = receipt_unit.ConfigtestReceiptTest.raw()
    raw['configtest_receipt'] = receipt
    raw['artifacts'] = {'configtest_dir': 'inventory/configtests/invalid_boolean'}
    return raw


class ConfigtestArtifactsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix='config-artifact-unit-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.raw = unit_bundle(self.root)
        self.cases = {case['case_id']: case for case in contract.catalog_cases(contract.load_catalog())}

    def normalize(self, raw: dict[str, object]) -> dict[str, object]:
        return contract.normalize_case_record(raw, 'nginx', self.cases, [],
                                              'native-nginx-http-module', configtest_artifact_root=self.root)

    def test_closed_retained_bundle_is_complete_without_http_or_event(self) -> None:
        record = self.normalize(self.raw)
        self.assertEqual(record['status'], 'PASS', record['reason'])
        self.assertEqual(contract.pass_case_completeness_errors(
            record, [], 'nginx', 'native-nginx-http-module', artifact_root=self.root), [])
        self.assertEqual(record['transaction_ids'], [])

    def test_every_receipt_digest_is_checked_against_actual_bytes(self) -> None:
        for field in ('binary_sha256', 'module_sha256', 'config_path_identity', 'stdout_sha256', 'stderr_sha256'):
            with self.subTest(field=field):
                raw = copy.deepcopy(self.raw)
                raw['configtest_receipt'][field] = ('sha256:' if field == 'config_path_identity' else '') + '0' * 64
                self.assertEqual(self.normalize(raw)['status'], 'FAIL')

    def test_missing_or_foreign_bundle_cannot_be_complete(self) -> None:
        record = self.normalize(self.raw)
        self.assertTrue(contract.pass_case_completeness_errors(record, [], 'nginx', 'native-nginx-http-module'))
        for path in ('../outside', '/etc', 'inventory/configtests/other-case'):
            with self.subTest(path=path):
                raw = copy.deepcopy(self.raw)
                raw['artifacts']['configtest_dir'] = path
                self.assertEqual(self.normalize(raw)['status'], 'FAIL')
        (self.root / self.raw['artifacts']['configtest_dir'] / 'stdout.log').unlink()
        self.assertEqual(self.normalize(self.raw)['status'], 'FAIL')

    def test_matching_hashes_cannot_hide_wrong_diagnostic_or_sensitive_config(self) -> None:
        bundle = self.root / self.raw['artifacts']['configtest_dir']
        for name, data, field in (('stderr.log', b'module missing\n', 'stderr_sha256'),
                                  ('nginx.conf', b'password secret;\n', 'config_path_identity')):
            with self.subTest(name=name):
                original = (bundle / name).read_bytes()
                raw = copy.deepcopy(self.raw)
                (bundle / name).write_bytes(data)
                raw['configtest_receipt'][field] = ('sha256:' if name == 'nginx.conf' else '') + hashlib.sha256(data).hexdigest()
                self.assertEqual(self.normalize(raw)['status'], 'FAIL')
                (bundle / name).write_bytes(original)

    def test_symlinked_file_is_rejected(self) -> None:
        capture = self.root / self.raw['artifacts']['configtest_dir'] / 'stdout.log'
        capture.unlink()
        capture.symlink_to(self.root / 'missing')
        self.assertEqual(self.normalize(self.raw)['status'], 'FAIL')

    def test_fifo_leaf_is_rejected_without_waiting_for_a_writer(self) -> None:
        leaf = self.root / 'fifo-control'
        os.mkfifo(leaf)
        code = ('import importlib.util, pathlib; '
                f's=importlib.util.spec_from_file_location("fifo_contract", {str(ROOT / "ci/checks/catalog/no_crs_baseline.py")!r}); '
                'm=importlib.util.module_from_spec(s); s.loader.exec_module(m); '
                f'm.configtest_file_observation(pathlib.Path({str(leaf)!r}), 8)')
        try:
            process = subprocess.run([sys.executable, '-c', code], capture_output=True, timeout=2, check=False)
        except subprocess.TimeoutExpired:
            self.fail('FIFO artifact read blocked before regular-file validation')
        self.assertNotEqual(process.returncode, 0)
        self.assertIn(b'not bounded/regular', process.stderr)

    def test_secure_copy_enforces_its_bound_not_only_a_prior_stat(self) -> None:
        source = self.root / 'bounded-copy-input'
        source.write_bytes(b'x' * 33)
        with self.assertRaises(contract.ContractError):
            contract.copy_artifact(source, self.root / 'bounded-copy-output', maximum_bytes=32)

    def test_finalizer_copies_only_closed_files_under_per_source_authority(self) -> None:
        output = self.root / 'canonical'
        output.mkdir()
        raw = copy.deepcopy(self.raw)
        raw['artifacts']['configtest_dir'] = str(self.root / self.raw['artifacts']['configtest_dir'])
        context = SimpleNamespace(case_by_id=self.cases, connector='nginx', run_dir=output,
                                  configtest_source_roots={id(raw): self.root},
                                  configtest_copied_cases=set(), manifest={'artifacts': {}})
        normalized = contract.retain_finalize_configtest_bundle(context, raw)
        self.assertEqual(normalized['artifacts'], {'configtest_dir': contract.CONFIGTEST_BUNDLE_PATH})
        self.assertEqual(len(context.manifest['artifacts']), 5)
        self.assertEqual(contract.configtest_artifact_errors(normalized, output), [])
        with self.assertRaises(contract.ContractError):
            contract.retain_finalize_configtest_bundle(context, raw)

    def test_generic_event_mode_does_not_erase_explicit_configuration_host(self) -> None:
        output = self.root / 'generic-canonical'
        output.mkdir()
        raw = copy.deepcopy(self.raw)
        raw['artifacts']['configtest_dir'] = str(self.root / self.raw['artifacts']['configtest_dir'])
        context = SimpleNamespace(case_by_id=self.cases, connector='nginx', run_dir=output,
                                  event_integration_mode=None,
                                  configtest_source_roots={id(raw): self.root}, configtest_copied_cases=set(),
                                  manifest={'artifacts': {}, 'integration_mode': 'native-nginx-http-module'})
        records = contract.normalized_finalize_case_records(context, [raw], [])
        self.assertEqual(records[0]['status'], 'PASS', records[0]['reason'])
        context.configtest_copied_cases.clear()
        context.configtest_source_roots[id(raw)] = self.root / 'unrelated-source'
        with self.assertRaises(contract.ContractError):
            contract.retain_finalize_configtest_bundle(context, raw)


if __name__ == '__main__':
    unittest.main()
