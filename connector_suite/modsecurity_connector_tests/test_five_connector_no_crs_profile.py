"""Hermetic contract tests for the closed five-connector No-CRS profile."""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import hashlib
import importlib.util
import io
import json
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path


ROOT = connector_root()


def load_module(name: str, relative: str):
    module = load_source(ROOT / relative)
    return module


PROFILE = load_module("five_connector_no_crs_profile_test", "ci/runtime/lifecycle/five-connector-no-crs-profile.py")
AGGREGATE = load_module("aggregate_five_connector_no_crs_test", "ci/runtime/lifecycle/aggregate-five-connector-no-crs.py")
COMMIT = "a" * 40
FRAMEWORK_COMMIT = "b" * 40
RUN_ID = "profile-contract-101"


class FiveConnectorNoCrsProfileTest(unittest.TestCase):
    def manifest(self, connector: str) -> dict[str, object]:
        row = PROFILE.profile_row(connector)
        state = "implemented_not_asserted" if row["phase4_mode"] == "safe" else "not_implemented"
        return {"connector": connector, "integration_mode": row["integration_mode"], "capabilities": {
            "phase4": {"state": state}, "http1_content_length": {"state": "configured_not_exercised"},
        }}

    def test_exact_mapping_and_unknown_connector_rejection(self) -> None:
        self.assertEqual(tuple(row["connector"] for row in PROFILE.ROWS), PROFILE.CONNECTORS)
        self.assertNotIn("nginx", PROFILE.CONNECTORS)
        with self.assertRaisesRegex(ValueError, "closed no-crs profile"):
            PROFILE.profile_row("nginx")
        self.assertEqual(PROFILE.main(["--profile", "no-crs", "--emit-connectors"]), 0)
        for unsupported in ("unknown", "with-crs", "with-mrts"):
            with self.subTest(profile=unsupported), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                PROFILE.parse_args(["--profile", unsupported, "--emit-connectors"])
            with self.subTest(aggregate_profile=unsupported), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                AGGREGATE.parse_args(["--profile", unsupported])

    def test_row_and_connector_checks_are_closed_without_capability_paths(self) -> None:
        row = PROFILE.profile_row("apache")
        self.assertEqual(PROFILE.verify_row(row), row)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "capabilities.json"
            path.write_text(json.dumps(self.manifest("apache")), encoding="utf-8")
            original_path = PROFILE.canonical_capabilities_path
            self.addCleanup(setattr, PROFILE, "canonical_capabilities_path", original_path)
            PROFILE.canonical_capabilities_path = lambda _: path
            self.assertEqual(PROFILE.verify_connector("apache"), row)
            wrong = dict(row)
            wrong["protocol"] = "h2"
            with self.assertRaisesRegex(ValueError, "protocol"):
                PROFILE.verify_row(wrong)
            manifest = self.manifest("apache")
            manifest["capabilities"]["http1_content_length"] = {"state": "not_implemented"}  # type: ignore[index]
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "http1_content_length"):
                PROFILE.verify_connector("apache")
        with self.assertRaisesRegex(ValueError, "closed no-crs profile"):
            PROFILE.verify_connector("nginx")
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            PROFILE.parse_args(["--profile", "no-crs", "--verify-connector", "--connector", "apache",
                                "--capabilities", "connectors/apache/capabilities.json"])

    def _write_run(self, root: Path, connector: str, *, bad_identity: bool = False,
                   omit_artifact: bool = False, cleanup_status: str = "passed",
                   artifact_state: str = "produced") -> None:
        run = root / connector / RUN_ID
        runtime = root.parent / "runtime" / connector
        receipt = PROFILE.write_receipt(runtime, runtime / PROFILE.RECEIPT_PATH,
            connector=connector, run_id=RUN_ID, connector_commit=COMMIT,
            framework_commit=FRAMEWORK_COMMIT, cleanup_status=cleanup_status)
        receipt_destination = run / PROFILE.RECEIPT_PATH
        receipt_destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(receipt, receipt_destination)
        result = {
            "connector": connector,
            "run_id": RUN_ID,
            "connector_commit": "c" * 40 if bad_identity else COMMIT,
            "framework_commit": FRAMEWORK_COMMIT,
            "integration_mode": PROFILE.profile_row(connector)["integration_mode"],
            "status": "PASS",
            "artifacts": {},
        }
        if not omit_artifact:
            result["artifacts"][PROFILE.RECEIPT_KEY] = PROFILE.RECEIPT_PATH
        (run / "result.json").write_text(json.dumps(result), encoding="utf-8")
        (run / "manifest.json").write_text(json.dumps({
            "connector": connector, "run_id": RUN_ID, "connector_commit": COMMIT,
            "framework_commit": FRAMEWORK_COMMIT,
            "integration_mode": PROFILE.profile_row(connector)["integration_mode"],
            "artifacts": {PROFILE.RECEIPT_KEY: {
                "path": PROFILE.RECEIPT_PATH, "state": artifact_state,
                "sha256": hashlib.sha256(receipt_destination.read_bytes()).hexdigest(),
            }},
        }), encoding="utf-8")

    def _success_root(self, root: Path) -> Path:
        evidence = root / "evidence"
        for connector in PROFILE.CONNECTORS:
            self._write_run(evidence, connector)
        return evidence

    def test_receipt_is_payload_free_and_bound_to_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "runtime"
            receipt = PROFILE.write_receipt(root, root / PROFILE.RECEIPT_PATH,
                connector="apache", run_id=RUN_ID, connector_commit=COMMIT,
                framework_commit=FRAMEWORK_COMMIT, cleanup_status="passed")
            payload = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual(payload["profile"], "no-crs")
        self.assertEqual(payload["cleanup_status"], "passed")
        self.assertEqual(set(payload), {"schema_version", "profile", "connector", "run_id", "connector_commit", "framework_commit", "cleanup_status", "integration_mode", "protocol", "phase4_mode", "connector_profile", "evidence_scope"})

    def test_five_pass_results_create_result_only_summaries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = self._success_root(root)
            output = evidence / "summary.json"
            markdown = evidence / "summary.md"
            german = evidence / "summary.de.md"
            rc = AGGREGATE.main(["--profile", "no-crs", "--evidence-root", str(evidence),
                "--canonical-validation-status", "passed",
                "--run-id", RUN_ID, "--connector-commit", COMMIT, "--framework-commit", FRAMEWORK_COMMIT,
                "--output-json", str(output), "--output-md", str(markdown), "--output-md-de", str(german)])
            payload = json.loads(output.read_text(encoding="utf-8"))
            german_text = german.read_text(encoding="utf-8")
        self.assertEqual(rc, 0)
        self.assertEqual(payload["status"], "PASS")
        self.assertEqual([row["connector"] for row in payload["results"]], list(PROFILE.CONNECTORS))
        self.assertNotIn("artifacts", payload)
        self.assertIn("Fünf-Connector", german_text)

    def test_failed_canonical_validation_cannot_emit_pass_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            evidence = self._success_root(Path(temporary))
            output = evidence / "summary.json"
            rc = AGGREGATE.main(["--profile", "no-crs", "--evidence-root", str(evidence),
                "--canonical-validation-status", "failed",
                "--run-id", RUN_ID, "--connector-commit", COMMIT, "--framework-commit", FRAMEWORK_COMMIT,
                "--output-json", str(output), "--output-md", str(evidence / "summary.md"),
                "--output-md-de", str(evidence / "summary.de.md")])
            payload = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(rc, 1)
        self.assertEqual(payload["status"], "FAIL")
        self.assertEqual(payload["results"], [])
        self.assertIn("canonical evidence validation did not pass", payload["errors"])

    def test_receipt_preserves_failed_cleanup_for_aggregate_rejection(self) -> None:
        payload = PROFILE.receipt_payload(connector="apache", run_id=RUN_ID,
            connector_commit=COMMIT, framework_commit=FRAMEWORK_COMMIT, cleanup_status="failed")
        self.assertEqual(payload["cleanup_status"], "failed")

    def test_missing_artifact_bad_identity_cleanup_or_manifest_state_fail(self) -> None:
        for label, options in (("missing", {"omit_artifact": True}), ("identity", {"bad_identity": True}),
                               ("cleanup", {"cleanup_status": "failed"}), ("state", {"artifact_state": "present"})):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                evidence = self._success_root(root)
                self._write_run(evidence, "apache", **options)
                rc = AGGREGATE.main(["--profile", "no-crs", "--evidence-root", str(evidence),
                    "--canonical-validation-status", "passed",
                    "--run-id", RUN_ID, "--connector-commit", COMMIT, "--framework-commit", FRAMEWORK_COMMIT,
                    "--output-json", str(evidence / "summary.json"), "--output-md", str(evidence / "summary.md"),
                    "--output-md-de", str(evidence / "summary.de.md")])
                self.assertEqual(rc, 1)
                failure = json.loads((evidence / "summary.json").read_text(encoding="utf-8"))
                self.assertEqual(failure["status"], "FAIL")
                self.assertTrue(failure["errors"])
                self.assertIn("FAIL", (evidence / "summary.md").read_text(encoding="utf-8"))
                self.assertIn("Error:", (evidence / "summary.md").read_text(encoding="utf-8"))
                self.assertIn("FEHLER", (evidence / "summary.de.md").read_text(encoding="utf-8"))
                self.assertIn("Fehler:", (evidence / "summary.de.md").read_text(encoding="utf-8"))

    def test_missing_or_extra_connector_directory_fails_closed(self) -> None:
        for label in ("missing", "extra"):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                evidence = self._success_root(Path(temporary))
                if label == "missing":
                    shutil.rmtree(evidence / "lighttpd")
                else:
                    (evidence / "nginx").mkdir()
                rc = AGGREGATE.main(["--profile", "no-crs", "--evidence-root", str(evidence),
                    "--canonical-validation-status", "passed",
                    "--run-id", RUN_ID, "--connector-commit", COMMIT, "--framework-commit", FRAMEWORK_COMMIT,
                    "--output-json", str(evidence / "summary.json"), "--output-md", str(evidence / "summary.md"),
                    "--output-md-de", str(evidence / "summary.de.md")])
                self.assertEqual(rc, 1)
                self.assertEqual(json.loads((evidence / "summary.json").read_text(encoding="utf-8"))["status"], "FAIL")



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
