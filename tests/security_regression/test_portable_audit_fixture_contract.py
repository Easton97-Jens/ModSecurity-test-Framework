"""Regression coverage for portable required-audit fixture materialization."""

from __future__ import annotations

import copy
import importlib
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
RUNNERS = ROOT / "tests" / "runners"
FIXTURE = ROOT / "tests" / "cases" / "phases" / "phase1" / "action_status_401_phase1_block.yaml"

if str(RUNNERS) not in sys.path:
    sys.path.insert(0, str(RUNNERS))

runner_core = importlib.import_module("runner_core")


class PortableAuditFixtureContractTests(unittest.TestCase):
    def _case(self):
        return copy.deepcopy(runner_core.load_case(FIXTURE))

    def _audit_paths(self, root: Path) -> tuple[Path, Path]:
        logs = root / "logs"
        audit_dir = logs / "audit"
        logs.mkdir(parents=True, mode=0o700)
        audit_dir.mkdir(mode=0o700)
        return logs / "audit.log", audit_dir

    def _write_rules(self, case, root: Path, audit_log: Path, audit_dir: Path) -> Path:
        rules = root / "conf" / "modsecurity-smoke.conf"
        runner_core.write_rules_file(
            case,
            rules,
            output_root=root,
            audit_log_file=audit_log,
            audit_log_dir=audit_dir,
        )
        return rules

    def test_fixture_uses_canonical_serial_directives_and_request_identity(self) -> None:
        case = self._case()
        rules = case["rules"]
        self.assertIn("SecAuditEngine RelevantOnly", rules)
        self.assertIn("SecAuditLogType Serial", rules)
        self.assertIn("SecAuditLogParts ABHZ", rules)
        self.assertIn('SecAuditLog "@@AUDIT_LOG@@"', rules)
        self.assertIn('SecAuditLogStorageDir "@@AUDIT_LOG_DIR@@"', rules)
        self.assertEqual(
            case["expect"]["audit_log"],
            {
                "required": True,
                "rule_id": 2320,
                "uri": "/?what=block401",
                "message": "shared imported status 401 block",
            },
        )

    def test_required_audit_rejects_missing_engine_or_noncanonical_destination(self) -> None:
        case = self._case()
        case["rules"] = case["rules"].replace("SecAuditEngine RelevantOnly\n", "")
        with self.assertRaisesRegex(ValueError, "SecAuditEngine On or RelevantOnly"):
            runner_core.validate_case(case)

        case = self._case()
        case["rules"] = case["rules"].replace(
            'SecAuditLog "@@AUDIT_LOG@@"',
            'SecAuditLog "/var/log/modsecurity/audit.log"',
        )
        with self.assertRaisesRegex(ValueError, 'SecAuditLog "@@AUDIT_LOG@@"'):
            runner_core.validate_case(case)

    def test_required_audit_requires_a_boolean_required_flag(self) -> None:
        case = self._case()
        case["expect"]["audit_log"]["required"] = "true"
        with self.assertRaisesRegex(ValueError, "audit_log.required must be a boolean"):
            runner_core.validate_case(case)

    def test_materialization_substitutes_private_paths_without_creating_an_audit_file(self) -> None:
        case = self._case()
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "output"
            root.mkdir(mode=0o700)
            audit_log, audit_dir = self._audit_paths(root)
            rules = self._write_rules(case, root, audit_log, audit_dir)
            content = rules.read_text(encoding="utf-8")
            self.assertIn(f'SecAuditLog "{audit_log}"', content)
            self.assertIn(f'SecAuditLogStorageDir "{audit_dir}"', content)
            self.assertNotIn("@@AUDIT_LOG@@", content)
            self.assertFalse(audit_log.exists())

    def test_materialization_rejects_missing_outside_and_symlinked_audit_paths(self) -> None:
        case = self._case()
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            root = temporary / "output"
            root.mkdir(mode=0o700)
            audit_log, audit_dir = self._audit_paths(root)

            with self.assertRaisesRegex(ValueError, "audit log placeholders require audit log paths"):
                runner_core.write_rules_file(case, root / "rules.conf", output_root=root)

            outside = temporary / "outside" / "audit.log"
            outside.parent.mkdir(mode=0o700)
            with self.assertRaisesRegex(ValueError, "audit log file must stay below audit output root"):
                self._write_rules(case, root, outside, audit_dir)

            audit_log.symlink_to(outside)
            with self.assertRaisesRegex(ValueError, "audit log file must not contain a symlink component"):
                self._write_rules(case, root, audit_log, audit_dir)

    def test_materialization_rejects_a_preexisting_audit_file_from_another_run(self) -> None:
        case = self._case()
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "output"
            root.mkdir(mode=0o700)
            audit_log, audit_dir = self._audit_paths(root)
            audit_log.write_text("stale audit evidence\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "must not already exist before runtime"):
                self._write_rules(case, root, audit_log, audit_dir)

    def test_materialization_requires_owner_private_audit_directories(self) -> None:
        case = self._case()
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "output"
            root.mkdir(mode=0o700)
            audit_log, audit_dir = self._audit_paths(root)
            audit_dir.chmod(0o770)
            with self.assertRaisesRegex(ValueError, "audit log directory must not be group- or world-writable"):
                self._write_rules(case, root, audit_log, audit_dir)

    def test_assertion_requires_401_and_matching_rule_request_and_message(self) -> None:
        case = self._case()
        with tempfile.TemporaryDirectory() as temporary_directory:
            audit_log = Path(temporary_directory) / "audit.log"
            self.assertIn(
                "audit log file missing or empty",
                runner_core.assert_audit_log(case, audit_log, timeout_seconds=0.0)[0],
            )

            matching = (
                "GET /?what=block401 HTTP/1.1\n"
                "Message: shared imported status 401 block [id \"2320\"]\n"
            )
            audit_log.write_text(matching, encoding="utf-8")
            self.assertEqual(
                runner_core.assert_case_artifacts(
                    case,
                    {"status": 401},
                    audit_log_file=audit_log,
                ),
                [],
            )
            wrong_status = runner_core.assert_case_artifacts(
                case,
                {"status": 200},
                audit_log_file=audit_log,
            )
            self.assertTrue(any("expected HTTP 401" in error for error in wrong_status), wrong_status)

            audit_log.write_text(
                "GET /?what=another-run HTTP/1.1\n"
                "Message: stale or replaced audit record [id \"949110\"]\n",
                encoding="utf-8",
            )
            replaced = runner_core.assert_case_artifacts(
                case,
                {"status": 401},
                audit_log_file=audit_log,
            )
            self.assertTrue(any("uri" in error for error in replaced), replaced)
            self.assertTrue(any("rule_id" in error for error in replaced), replaced)
            self.assertTrue(any("message" in error for error in replaced), replaced)

    def test_assertion_rejects_an_explicit_wrong_transaction_identity(self) -> None:
        case = self._case()
        case["expect"]["audit_log"]["transaction_id"] = "action-401-run-1"
        with tempfile.TemporaryDirectory() as temporary_directory:
            audit_log = Path(temporary_directory) / "audit.log"
            audit_log.write_text(
                "GET /?what=block401 HTTP/1.1\n"
                "Message: shared imported status 401 block [id \"2320\"]\n"
                "transaction_id=another-run\n",
                encoding="utf-8",
            )
            errors = runner_core.assert_case_artifacts(
                case,
                {"status": 401},
                audit_log_file=audit_log,
            )
            self.assertTrue(any("transaction_id" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
