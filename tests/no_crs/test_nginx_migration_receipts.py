"""Closed unit bundles are not runtime proof; preserve mismatch controls."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from tests.no_crs import test_configtest_receipt as unit


class MigrationReceiptsTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="migration-receipt-unit-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.core = unit.no_crs
        self.cases = {case["case_id"]: case for case in self.core.catalog_cases(self.core.load_catalog())}

    def raw(self, case_id):
        invocation = self.core.NGINX_CONFIGTEST_CONTRACTS[case_id]
        bundle = self.root / "inventory/configtests" / case_id
        bundle.mkdir(parents=True, exist_ok=True)
        receipt = {**unit.ConfigtestReceiptTest.receipt(), **invocation, "case_id": case_id}
        value = json.dumps(invocation["value"])
        fixture = self.core.CONFIGTEST_PATH_FIXTURES.get(case_id)
        files = {"nginx-binary": b"unit binary", "nginx-module.so": b"unit module", "stdout.log": b""}
        if fixture:
            leaf, state = fixture
            files[leaf] = (self.core.FRAMEWORK_ROOT / "tests/fixtures/no-crs-baseline" / leaf).read_bytes()
            receipt.update(fixture_leaf=leaf, fixture_state=state,
                           fixture_sha256=hashlib.sha256(files[leaf]).hexdigest())
            value = json.dumps(str(bundle / leaf))
        files["nginx.conf"] = (f'load_module "{bundle}/nginx-module.so";\n'
            f'pid "{bundle}/nginx.pid";\nerror_log "{bundle}/nginx-error.log";\n'
            f'events {{}}\nhttp {{\n  {invocation["directive"]} {value};\n}}\n').encode()
        files["stderr.log"] = (" ".join(invocation["diagnostic_fragments"])
                               + f" in {bundle}/nginx.conf:6\n").encode()
        for leaf, data in files.items():
            (bundle / leaf).write_bytes(data)
            (bundle / leaf).chmod(0o600)
        for leaf, (field, _) in self.core.configtest_artifacts_for_record({"case_id": case_id}).items():
            receipt[field] = ("sha256:" if leaf == "nginx.conf" else "") + hashlib.sha256(files[leaf]).hexdigest()
        return {**unit.ConfigtestReceiptTest.raw(), "case_id": case_id,
                "configtest_receipt": receipt, "artifacts": {"configtest_dir": f"inventory/configtests/{case_id}"}}

    def normalize(self, raw):
        return self.core.normalize_case_record(raw, "nginx", self.cases, [], "native-nginx-http-module",
                                               configtest_artifact_root=self.root)

    def test_three_closed_bundles_require_no_synthetic_request_event(self):
        for case_id in ("invalid_status", "phase4_invalid_scope_file", "phase4_wildcard_scope_rejected"):
            with self.subTest(case_id=case_id):
                record = self.normalize(self.raw(case_id))
                self.assertEqual(record["status"], "PASS", record["reason"])
                self.assertEqual(record["transaction_ids"], [])
                self.assertEqual(record["observed_rule_ids"], [])
                self.assertEqual(self.core.pass_case_completeness_errors(
                    record, [], "nginx", "native-nginx-http-module", artifact_root=self.root), [])

    def test_rehashed_wrong_fixture_diagnostic_and_foreign_identity_still_fail(self):
        case_id = "phase4_wildcard_scope_rejected"
        raw = self.raw(case_id)
        leaf = raw["configtest_receipt"]["fixture_leaf"]
        bundle = self.root / raw["artifacts"]["configtest_dir"]
        (bundle / leaf).write_bytes(b"application/json\n")
        raw["configtest_receipt"]["fixture_sha256"] = hashlib.sha256((bundle / leaf).read_bytes()).hexdigest()
        self.assertEqual(self.normalize(raw)["status"], "FAIL")
        raw = self.raw(case_id)
        diagnostic = b'unknown directive "modsecurity_phase4_content_types_file" in /foreign/nginx.conf:6\n'
        (bundle / "stderr.log").write_bytes(diagnostic)
        raw["configtest_receipt"]["stderr_sha256"] = hashlib.sha256(diagnostic).hexdigest()
        self.assertEqual(self.normalize(raw)["status"], "FAIL")
        for field, value in (("case_id", "invalid_status"), ("observed_exit_code", 0),
                             ("module_sha256", "0" * 64), ("run_id", "foreign")):
            changed = self.raw(case_id)
            changed["configtest_receipt"][field] = value
            self.assertEqual(self.normalize(changed)["status"], "FAIL")

    def test_finalizer_retains_exact_regular_fixture_and_revalidates_it(self):
        raws = [self.raw(case_id) for case_id in ("invalid_status", "phase4_invalid_scope_file",
                                                 "phase4_wildcard_scope_rejected")]
        for raw in raws:
            raw["artifacts"]["configtest_dir"] = str(self.root / raw["artifacts"]["configtest_dir"])
        output = self.root / "canonical"
        output.mkdir()
        context = SimpleNamespace(case_by_id=self.cases, connector="nginx", run_dir=output,
            event_integration_mode=None, configtest_source_roots={id(raw): self.root for raw in raws},
            configtest_copied_cases=set(), manifest={"artifacts": {}, "integration_mode": "native-nginx-http-module"})
        records = self.core.normalized_finalize_case_records(context, raws, [])
        self.assertEqual([record["status"] for record in records], ["PASS"] * 3)
        for record in records:
            self.assertEqual(self.core.configtest_artifact_errors(record, output), [])
        copied = output / "inventory/configtests/phase4_wildcard_scope_rejected/wildcard-content-type-scope.txt"
        copied.write_bytes(b"changed")
        self.assertTrue(self.core.configtest_artifact_errors(records[2], output))


if __name__ == "__main__":
    unittest.main()
