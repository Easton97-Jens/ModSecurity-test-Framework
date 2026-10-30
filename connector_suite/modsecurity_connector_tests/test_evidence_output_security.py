from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import contextlib
from pathlib import Path
import sys
import tempfile
import unittest
from urllib.parse import urlunsplit
from unittest import mock


ROOT = connector_root()


def load_module(relative_path: str, module_name: str):
    module = load_source(source_path(relative_path, root=ROOT))
    return module


AUDIT = load_module(
    "ci/evidence/reports/audit-full-lifecycle-runtime-roots.py",
    "evidence_output_security_audit",
)
CAPABILITIES = load_module(
    "ci/evidence/collectors/connector_capabilities.py",
    "evidence_output_security_capabilities",
)
SYSTEM_PROOF = load_module(
    "ci/evidence/reports/generate-system-environment-proof.py",
    "evidence_output_security_system_proof",
)
CRITICAL_BATCH = load_module(
    "ci/evidence/reports/generate-remaining-critical-batch-analysis.py",
    "evidence_output_security_critical_batch",
)
PATH_SAFETY = load_source(source_path("ci/lib/report_path_safety.py", root=ROOT), fresh=False)


class EvidenceOutputSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.safe_roots = set(PATH_SAFETY.SAFE_ROOTS)
        PATH_SAFETY.SAFE_ROOTS.clear()

    def tearDown(self) -> None:
        PATH_SAFETY.SAFE_ROOTS.clear()
        PATH_SAFETY.SAFE_ROOTS.update(self.safe_roots)

    def test_audit_writes_only_within_current_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            run_root = workspace / "run"
            argv = [
                "audit",
                "--verified-run-root",
                str(run_root),
                "--run-id",
                "valid-run",
                "--output-json",
                "output/audit.json",
                "--output-md",
                "output/audit.md",
                "--output-md-de",
                "output/audit.de.md",
            ]
            with contextlib.chdir(workspace), mock.patch.object(sys, "argv", argv):
                self.assertEqual(AUDIT.main(), 0)
            self.assertTrue((workspace / "output/audit.json").is_file())
            self.assertTrue((workspace / "output/audit.md").is_file())
            self.assertTrue((workspace / "output/audit.de.md").is_file())

    def test_audit_rejects_output_outside_current_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            outside = workspace.parent / "outside-audit.json"
            argv = [
                "audit",
                "--verified-run-root",
                str(workspace / "run"),
                "--run-id",
                "valid-run",
                "--output-json",
                str(outside),
                "--output-md",
                "output/audit.md",
                "--output-md-de",
                "output/audit.de.md",
            ]
            with contextlib.chdir(workspace), mock.patch.object(sys, "argv", argv):
                with self.assertRaisesRegex(SystemExit, "output paths must remain"):
                    AUDIT.main()
            self.assertFalse(outside.exists())

    def test_audit_rejects_symlinked_output_outside_current_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            outside = Path(temporary) / "outside"
            workspace.mkdir()
            outside.mkdir()
            (workspace / "escape").symlink_to(outside, target_is_directory=True)
            argv = [
                "audit",
                "--verified-run-root",
                str(workspace / "run"),
                "--run-id",
                "valid-run",
                "--output-json",
                "escape/audit.json",
                "--output-md",
                "output/audit.md",
                "--output-md-de",
                "output/audit.de.md",
            ]
            with contextlib.chdir(workspace), mock.patch.object(sys, "argv", argv):
                with self.assertRaisesRegex(SystemExit, "output paths must remain"):
                    AUDIT.main()
            self.assertFalse((outside / "audit.json").exists())

    def test_capability_output_is_owner_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "capabilities.json"
            CAPABILITIES._atomic_write(output, "{}\n")
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_repository_url_policy_rejects_non_https_github_url(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            unsafe_url = urlunsplit(("http", "github.com", "/owner/repository", "", ""))
            (root / "README.md").write_text(f"source {unsafe_url}\n", encoding="utf-8")
            policy = SYSTEM_PROOF.https_repo_url_policy(root, root)
            self.assertEqual(policy["status"], "FAIL")
            self.assertEqual(policy["findings"][0]["pattern"], "http")

            (root / "README.md").write_text("source https://github.com/owner/repository\n", encoding="utf-8")
            policy = SYSTEM_PROOF.https_repo_url_policy(root, root)
            self.assertEqual(policy["status"], "PASS")

    def test_nginx_inventory_executes_only_a_validated_contract_binary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "managed/nginx"
            binary.parent.mkdir(parents=True)
            binary.write_text("#!/bin/sh\nprintf 'nginx/1.31.6\\n'\n", encoding="utf-8")
            binary.chmod(0o755)
            digest = SYSTEM_PROOF.hashlib.sha256(binary.read_bytes()).hexdigest()
            passed_contract = {
                "nginx_runtime_contract": {
                    "status": "PASS",
                    "fields": {
                        "binary_path": str(binary),
                        "binary_sha256": digest,
                    },
                    "issues": [],
                }
            }
            run_result = {
                "output_excerpt": "nginx version: nginx/1.31.6",
                "return_code": 0,
                "output_sha256": digest,
            }

            with mock.patch.object(SYSTEM_PROOF, "run", return_value=run_result) as run:
                record = SYSTEM_PROOF.resolve_nginx_tool(root, passed_contract)

            self.assertEqual(record["status"], "present")
            self.assertEqual(record["resolved_command"], str(binary))
            self.assertEqual(record["source"], "validated NGINX runtime contract")
            run.assert_called_once_with([str(binary), "-v"], root, timeout=60)

    def test_nginx_inventory_blocks_before_any_binary_lookup_or_execution(self) -> None:
        unvalidated_contract = {
            "nginx_runtime_contract": {
                "status": "BLOCKED",
                "fields": {"binary_path": "/untrusted/nginx", "binary_sha256": "0" * 64},
                "issues": ["missing required NGINX runtime contract fields: source_ref"],
            }
        }

        with (
            mock.patch.object(
                SYSTEM_PROOF,
                "command_exists",
                side_effect=AssertionError("NGINX binary lookup must not run before validation"),
            ),
            mock.patch.object(
                SYSTEM_PROOF,
                "run",
                side_effect=AssertionError("NGINX binary execution must not run before validation"),
            ),
        ):
            record = SYSTEM_PROOF.resolve_nginx_tool(Path.cwd(), unvalidated_contract)

        self.assertEqual(record["status"], "blocked")
        self.assertEqual(record["return_code"], 125)
        self.assertEqual(record["source"], "validated NGINX runtime contract")
        self.assertIn("was not executed before runtime-contract validation", record["version_output"])

    def test_nginx_inventory_rechecks_binary_digest_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "managed/nginx"
            binary.parent.mkdir(parents=True)
            binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            binary.chmod(0o755)
            stale_digest = "0" * 64
            passed_contract = {
                "nginx_runtime_contract": {
                    "status": "PASS",
                    "fields": {"binary_path": str(binary), "binary_sha256": stale_digest},
                    "issues": [],
                }
            }

            with mock.patch.object(
                SYSTEM_PROOF,
                "run",
                side_effect=AssertionError("digest-mismatched NGINX binary must not execute"),
            ):
                record = SYSTEM_PROOF.resolve_nginx_tool(root, passed_contract)

            self.assertEqual(record["status"], "blocked")
            self.assertIn("binary_sha256 no longer matches", record["version_output"])

    def test_critical_batch_rejects_output_outside_generated_reports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            argv = [
                "critical-batch",
                "--connector-root",
                str(root),
                "--output-dir",
                str(root.parent / "outside-generated-reports"),
            ]
            with mock.patch.object(sys, "argv", argv):
                with self.assertRaisesRegex(ValueError, "output directory must be inside"):
                    CRITICAL_BATCH.main()



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
