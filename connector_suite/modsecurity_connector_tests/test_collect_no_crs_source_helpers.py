"""Framework-independent contracts for no-CRS collector helper boundaries."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import argparse
import importlib.util
import json
import sys
from pathlib import Path
import tempfile
import unittest


ROOT = connector_root()
CI_LIB = source_path('ci/lib', root=ROOT)



def load_collector() -> object:
    module = load_source(source_path('ci/runtime/lifecycle/collect-no-crs-source.py', root=ROOT))
    return module


COLLECTOR = load_collector()


class CollectNoCrsSourceHelpersTest(unittest.TestCase):
    def test_catalog_uses_the_explicit_framework_root_without_path_aliases(self) -> None:
        with tempfile.TemporaryDirectory(prefix="no-crs-catalog-root-") as temporary:
            root = Path(temporary)
            framework = root / "selected-framework"
            catalog = framework / "tests/cases/no-crs-baseline/catalog.json"
            catalog.parent.mkdir(parents=True)
            catalog.write_text("{}\n", encoding="utf-8")
            candidate_framework = root / "candidate/modules/ModSecurity-test-Framework"
            candidate_framework.mkdir(parents=True)

            self.assertEqual(
                COLLECTOR.canonical_catalog_path(catalog, framework), catalog
            )

            outside = root / "outside-catalog.json"
            outside.write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Framework source root"):
                COLLECTOR.canonical_catalog_path(outside, framework)

            traversal = catalog.parent / ".." / "no-crs-baseline" / "catalog.json"
            with self.assertRaisesRegex(ValueError, "unsafe path component"):
                COLLECTOR.canonical_catalog_path(traversal, framework)

            final_alias = framework / "catalog-alias.json"
            final_alias.symlink_to(catalog)
            with self.assertRaisesRegex(ValueError, "symbolic links"):
                COLLECTOR.canonical_catalog_path(final_alias, framework)

            source_directory = framework / "catalog-source"
            source_directory.mkdir()
            source_catalog = source_directory / "catalog.json"
            source_catalog.write_text("{}\n", encoding="utf-8")
            directory_alias = framework / "catalog-alias-directory"
            directory_alias.symlink_to(source_directory, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symbolic links"):
                COLLECTOR.canonical_catalog_path(
                    directory_alias / source_catalog.name, framework
                )

            framework_alias = root / "framework-alias"
            framework_alias.symlink_to(framework, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symbolic links"):
                COLLECTOR.canonical_catalog_path(catalog, framework_alias)

    def test_collector_cli_requires_explicit_framework_and_catalog_roots(self) -> None:
        parser = COLLECTOR.collector_argument_parser()
        actions = {action.dest: action for action in parser._actions}
        self.assertTrue(actions["framework_root"].required)
        self.assertTrue(actions["catalog"].required)

    def test_closed_profile_collector_boundary_uses_the_fixed_connector_source(self) -> None:
        self.assertIsNone(
            COLLECTOR.verify_closed_five_connector_profile("no-crs", "traefik")
        )
        with self.assertRaisesRegex(ValueError, "unsupported closed five-connector profile"):
            COLLECTOR.verify_closed_five_connector_profile("with-crs", "traefik")
        with self.assertRaisesRegex(ValueError, "closed no-crs profile"):
            COLLECTOR.verify_closed_five_connector_profile("no-crs", "nginx")

    def test_collector_arguments_keep_lifecycle_logs_in_their_log_root(self) -> None:
        with tempfile.TemporaryDirectory(prefix="no-crs-collector-roots-") as temporary:
            root = Path(temporary)
            source_root = root / "runs" / "traefik" / "current-run"
            log_root = root / "logs" / "traefik" / "current-run"
            framework = root / "framework"
            catalog = framework / "tests/cases/no-crs-baseline/catalog.json"
            source_root.mkdir(parents=True)
            log_root.mkdir(parents=True)
            catalog.parent.mkdir(parents=True)
            catalog.write_text("{}\n", encoding="utf-8")
            stdout = log_root / "stdout.log"
            stderr = log_root / "stderr.log"
            scrub_log = log_root / "source-event-scrub.log"
            stdout.write_text("status=PASS\n", encoding="utf-8")
            stderr.write_text("", encoding="utf-8")

            parser = COLLECTOR.collector_argument_parser()
            args = parser.parse_args(
                [
                    "--connector", "traefik",
                    "--stage-rc", "0",
                    "--framework-root", str(framework),
                    "--catalog", str(catalog),
                    "--allowed-source-root", str(source_root),
                    "--allowed-log-root", str(log_root),
                    "--stdout", str(stdout),
                    "--stderr", str(stderr),
                    "--source-event-scrub-log", str(scrub_log),
                    "--output", str(source_root / "source-result.json"),
                    "--events-output", str(source_root / "events.jsonl"),
                ]
            )

            self.assertEqual(
                COLLECTOR.prepare_collector_arguments(parser, args), source_root
            )
            self.assertEqual(args.stdout, stdout)
            self.assertEqual(args.stderr, stderr)
            self.assertEqual(args.source_event_scrub_log, scrub_log)

    def test_metadata_dispatch_retains_allow_lists_and_scalar_rejection(self) -> None:
        self.assertEqual(
            COLLECTOR.safe_metadata_value("actual_action", "connection_abort"),
            "abort_connection",
        )
        self.assertEqual(
            COLLECTOR.safe_metadata_value("requested_protocol", "http2"), "h2"
        )
        self.assertEqual(
            COLLECTOR.safe_metadata_value("transport_case_id", "case-1"), "case-1"
        )
        self.assertIsNone(COLLECTOR.safe_metadata_value("actual_action", True))
        self.assertIsNone(
            COLLECTOR.safe_metadata_value("late_intervention_mode", "late-403")
        )
        self.assertIsNone(
            COLLECTOR.safe_metadata_value("transport_case_id", "../outside")
        )

    def test_first_byte_record_requires_real_host_contract_and_normalizes_counters(self) -> None:
        record = {
            "evidence_type": "synchronized_first_byte",
            "evidence_origin": "real_host",
            "promotion_eligible": True,
            "outcome": "PASS",
            "body_payload_persisted": False,
            "client_first_byte_received": True,
            "first_byte_before_response_end": True,
            "first_chunk_size": "7",
            "upstream_paused": True,
            "upstream_eos_sent_at_first_byte": False,
            "upstream_response_finished_at_first_byte": False,
            "response_committed": True,
            "body_bytes_seen": "11",
            "body_bytes_inspected": 7,
            "no_full_response_buffering": True,
            "connector_owned_full_response_buffer": False,
        }

        self.assertTrue(COLLECTOR.first_byte_evidence_identity_is_valid(record))
        self.assertTrue(COLLECTOR.first_byte_evidence_contract_is_valid(record))
        self.assertTrue(COLLECTOR.normalize_first_byte_counters(record))
        self.assertEqual(record["first_chunk_size"], 7)
        self.assertEqual(record["body_bytes_seen"], 11)

        record["body_bytes_inspected"] = 12
        self.assertFalse(COLLECTOR.normalize_first_byte_counters(record))

    def test_event_evidence_rejects_hidden_payload_and_preserves_valid_metadata(self) -> None:
        valid = {
            "connector": "apache",
            "transaction_id": "tx-1",
            "rule_id": 1100001,
            "phase": 1,
            "status": "blocked",
        }
        hidden_payload = {**valid, "nested": {"body": "secret-payload"}}

        clean_result = COLLECTOR.event_evidence([], "1100001", [valid])
        result = COLLECTOR.event_evidence([], "1100001", [valid, hidden_payload])

        self.assertTrue(clean_result["event_metadata_verified"])
        self.assertFalse(result["event_metadata_verified"])
        self.assertFalse(result["body_payload_absent_from_events"])
        self.assertEqual(result["event_records"], 1)
        self.assertIn("nested", " ".join(result["forbidden_event_keys"]))

    def test_case_pass_requires_selected_rule_and_phase(self) -> None:
        record = {"phase": 4, "rule_id": 1100301}
        self.assertTrue(
            COLLECTOR.case_passes(
                "PASS", True, 200, 200, "1100301", 4,
                "phase4_deny_after_commit_log_only", {"1100301"}, [record],
            )
        )
        self.assertFalse(
            COLLECTOR.case_passes(
                "PASS", True, 200, 200, "1100301", 4,
                "phase4_deny_after_commit_log_only", {"1100301"}, [],
            )
        )

    def test_case_observations_retain_transaction_binding(self) -> None:
        with tempfile.TemporaryDirectory(prefix="no-crs-helper-transaction-") as temporary:
            root = Path(temporary)
            decision_path = root / "decision.jsonl"
            decision_path.write_text(
                "\n".join(
                    json.dumps(event)
                    for event in (
                        {
                            "connector": "apache",
                            "transaction_id": "tx-current",
                            "rule_id": 1100201,
                            "phase": "response_headers",
                            "status": "blocked",
                            "headers_sent": False,
                        },
                        {
                            "connector": "apache",
                            "transaction_id": "tx-other",
                            "rule_id": 1100201,
                            "phase": "response_headers",
                            "status": "blocked",
                            "headers_sent": True,
                        },
                    )
                )
                + "\n",
                encoding="utf-8",
            )
            results_path = root / "results.jsonl"
            results_path.write_text(
                json.dumps(
                    {
                        "case_id": "phase3_deny_before_commit",
                        "status": "PASS",
                        "live_executed": True,
                        "actual_status": 403,
                        "transaction_id": "tx-current",
                        "decision_log_path": str(decision_path),
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            cases, events = COLLECTOR.case_observations(
                [results_path],
                "apache",
                "1100001",
                {"phase3_deny_before_commit": (403, "1100201", 3)},
                allowed_source_root=root,
            )

        self.assertEqual(cases[0]["status"], "PASS")
        self.assertEqual(cases[0]["transaction_ids"], ["tx-current"])
        self.assertFalse(cases[0]["headers_sent"])
        self.assertEqual(len(events), 1)

    def test_phase4_audit_fallback_remains_forbidden(self) -> None:
        with tempfile.TemporaryDirectory(prefix="no-crs-helper-phase4-") as temporary:
            root = Path(temporary)
            audit_path = root / "audit.log"
            audit_path.write_text(
                '[id "1100301"] (phase 4) [unique_id "tx-audit"]\n',
                encoding="utf-8",
            )
            results_path = root / "results.jsonl"
            results_path.write_text(
                json.dumps(
                    {
                        "case_id": "phase4_rule_observed",
                        "status": "PASS",
                        "live_executed": True,
                        "actual_status": 200,
                        "audit_log_path": str(audit_path),
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            cases, events = COLLECTOR.case_observations(
                [results_path],
                "apache",
                "1100001",
                {"phase4_rule_observed": (None, "1100301", 4)},
                allowed_source_root=root,
            )

        self.assertEqual(events, [])
        self.assertEqual(cases[0]["status"], "FAIL")
        self.assertFalse(cases[0]["event_metadata_verified"])

    def test_collector_status_preserves_terminal_precedence(self) -> None:
        events = {
            "event_metadata_verified": True,
            "body_payload_absent_from_events": True,
        }
        self.assertEqual(
            COLLECTOR.collector_status(
                77, False, False, [], True, "1100001", ["1100001"], events
            ),
            "BLOCKED",
        )
        self.assertEqual(
            COLLECTOR.collector_status(
                77, True, False, [], True, "1100001", ["1100001"], events
            ),
            "FAIL",
        )
        self.assertEqual(
            COLLECTOR.collector_status(
                0,
                False,
                True,
                [],
                True,
                "1100001",
                ["1100001"],
                events,
            ),
            "NOT_EXECUTED",
        )
        self.assertEqual(
            COLLECTOR.collector_status(
                0,
                True,
                False,
                [],
                True,
                "1100001",
                ["1100001"],
                events,
            ),
            "PASS",
        )

    def test_core_response_statuses_keep_case_evidence_precedence(self) -> None:
        allowed, blocked = COLLECTOR.core_response_statuses(
            [
                {
                    "allowed_request_status": 201,
                    "baseline_status": 200,
                    "blocked_request_status": 401,
                    "block_status": 403,
                }
            ],
            [
                {"case_id": "allow_without_marker", "actual_status": 200},
                {"case_id": "deny_header_marker_403", "actual_status": 403},
            ],
        )

        self.assertEqual((allowed, blocked), (200, 403))

    def test_explicit_core_cases_suppress_only_duplicate_summary_projection(self) -> None:
        explicit_cases = [
            {"case_id": "allow_without_marker", "actual_status": 200},
            {"case_id": "deny_header_marker_403", "actual_status": 403},
        ]
        self.assertEqual(
            COLLECTOR.reported_core_response_statuses(False, 200, 403, explicit_cases),
            (None, None),
        )
        self.assertEqual(
            COLLECTOR.reported_core_response_statuses(
                False,
                200,
                403,
                [{"case_id": "transaction_id_present", "actual_status": 200}],
            ),
            (200, 403),
        )
        self.assertEqual(
            COLLECTOR.reported_core_response_statuses(False, 200, 403, []),
            (200, 403),
        )

    def test_collector_payload_avoids_duplicate_core_case_derivation(self) -> None:
        payload = COLLECTOR.collector_payload(
            argparse.Namespace(connector="traefik", stage_rc=0),
            "PASS",
            True,
            False,
            200,
            403,
            ["1100001"],
            True,
            [
                {
                    "case_id": "allow_without_marker",
                    "actual_status": 200,
                },
                {
                    "case_id": "deny_header_marker_403",
                    "actual_status": 403,
                },
            ],
            {
                "transaction_ids": [],
                "event_metadata_verified": True,
                "body_payload_absent_from_events": True,
                "event_records": [],
                "event_validation_errors": [],
                "forbidden_event_keys": [],
            },
        )

        self.assertIsNone(payload["allowed_request_status"])
        self.assertIsNone(payload["blocked_request_status"])

    def test_scrub_uses_no_follow_artifact_removal_and_log_writer(self) -> None:
        with tempfile.TemporaryDirectory(prefix="no-crs-helper-scrub-") as temporary:
            root = Path(temporary)
            source_root = root / "raw"
            log_root = root / "logs"
            source_root.mkdir()
            log_root.mkdir()
            event = source_root / "decision.jsonl"
            event.write_text('{"transaction_id":"tx-one"}\n', encoding="utf-8")
            log = log_root / "scrub.log"
            removed = COLLECTOR.scrub_source_event_paths(
                [event], source_root, log, log_root
            )

            self.assertEqual(removed, [event])
            self.assertFalse(event.exists())
            self.assertEqual(
                log.read_text(encoding="utf-8"),
                f"removed_after_allowlist_normalization={event}\n",
            )

    def test_scrub_rejects_final_symlink_without_touching_target(self) -> None:
        with tempfile.TemporaryDirectory(prefix="no-crs-helper-scrub-") as temporary:
            root = Path(temporary)
            target = root / "target.jsonl"
            target.write_text("unchanged\n", encoding="utf-8")
            event = root / "decision.jsonl"
            event.symlink_to(target)

            with self.assertRaisesRegex(ValueError, "contains a symlink"):
                COLLECTOR.scrub_source_event_paths([event], root)
            self.assertEqual(target.read_text(encoding="utf-8"), "unchanged\n")



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
