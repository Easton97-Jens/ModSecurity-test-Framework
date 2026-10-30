"""Targeted regressions for request-bound results and distinct-case accounting.

These cases are explicitly invoked specialist checks, not a default catalogue.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import yaml

import modsecurity_test_framework.runners.case_cli as case_cli
import modsecurity_test_framework.runners.msconnector_models as msconnector_models
import modsecurity_test_framework.runners.runner_core as runner_core
from modsecurity_test_framework.connector_context import test_root
BINDING = {
    "run_id": "run-one",
    "case_id": "allow-without-marker",
    "request_id": "request-one",
    "transaction_id": "transaction-one",
    "source_revision": "a" * 40,
}


class ResultIdentityContractTests(unittest.TestCase):
    def test_different_cases_cannot_union_capabilities_across_runs_or_revisions(self) -> None:
        first = self.entry(capabilities=["query-args"])
        for changes in ({"run_id": "run-two"}, {"source_revision": "b" * 40}):
            with self.subTest(field=next(iter(changes))):
                second = self.entry(name="second-case", case_id="second-case", request_id="request-two",
                                    transaction_id="transaction-two", capabilities=["request-body"], **changes)
                with self.assertRaisesRegex(ValueError, "summary.*(?:run|revision)"):
                    msconnector_models.connector_summary(connector="nginx", entries=[first, second])

    def test_summary_context_cannot_relabel_a_bound_run_or_revision(self) -> None:
        for context in (msconnector_models.SummaryContext(run_id="other-run"),
                        msconnector_models.SummaryContext(source_revision="b" * 40)):
            with self.subTest(context=context):
                entries = [self.entry()]
                with self.assertRaisesRegex(ValueError, "summary.*identity"):
                    msconnector_models.connector_summary(connector="nginx", entries=entries, context=context)

    def test_bound_and_unbound_cases_keep_results_without_promoting_either(self) -> None:
        summary = msconnector_models.connector_summary(connector="nginx", entries=[
            self.entry(capabilities=["query-args"]),
            {"name": "legacy", "status": "pass", "actual_status": 200,
             "live_executed": True, "capabilities": ["request-body"]},
        ])
        self.assertEqual(summary["summary"]["pass"], 2)
        self.assertEqual(summary["verified_variables"], [])
        self.assertFalse(summary["promotion_allowed"])
        self.assertEqual(summary["evidence_identity"], "mixed")
        self.assertTrue(all(case["promotion_allowed"] is False for case in summary["cases"].values()))

    def test_summary_cli_rejects_a_requested_run_that_differs_from_bound_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "rows.jsonl"
            source.write_text(json.dumps(self.entry()) + "\n")
            with contextlib.redirect_stderr(io.StringIO()):
                result = case_cli.main([
                    "summarize-results", "--connector", "nginx", "--input-jsonl", str(source),
                    "--run-id", "other-run", "--summary-json", str(root / "summary.json"),
                    "--source-revision", BINDING["source_revision"],
                    "--summary-text", str(root / "summary.txt"),
                ])
            self.assertNotEqual(result, 0)
            self.assertFalse((root / "summary.json").exists())

    def test_one_bound_run_and_revision_preserve_valid_capabilities_and_retry_counts(self) -> None:
        first = self.entry(capabilities=["query-args"])
        second = self.entry(name="second-case", case_id="second-case", request_id="request-two",
                            transaction_id="transaction-two", capabilities=["request-body"])
        summary = msconnector_models.connector_summary(connector="nginx", entries=[first, first, second],
            context=msconnector_models.SummaryContext(run_id=BINDING["run_id"], source_revision=BINDING["source_revision"]))
        self.assertEqual(summary["summary"]["pass"], 2)
        self.assertEqual(summary["attempted"], 3)
        self.assertEqual(summary["verified_variables"], ["ARGS", "REQUEST_BODY"])
        self.assertEqual(summary["run_id"], BINDING["run_id"])
        self.assertEqual(summary["source_revision"], BINDING["source_revision"])
        self.assertTrue(summary["promotion_allowed"])

    def test_summary_cli_uses_the_checked_identity_without_overwriting_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "rows.jsonl"
            source.write_text(json.dumps(self.entry()) + "\n")
            self.assertEqual(case_cli.main([
                "summarize-results", "--connector", "nginx", "--input-jsonl", str(source),
                "--run-id", BINDING["run_id"], "--source-revision", BINDING["source_revision"],
                "--summary-json", str(root / "summary.json"), "--summary-text", str(root / "summary.txt"),
            ]), 0)
            summary = json.loads((root / "summary.json").read_text())["nginx"]
            self.assertEqual(summary["run_id"], BINDING["run_id"])
            self.assertEqual(summary["source_revision"], BINDING["source_revision"])
            self.assertEqual(summary["summary"]["pass"], 1)

    def test_request_window_excludes_earlier_same_uri_transactions_and_retains_no_query_payload(self) -> None:
        source = test_root() / "tests/cases/no-crs-baseline/allow_without_marker.yaml"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            case = runner_core.load_case(source)
            case["request"]["path"] = "/no-crs/allow?private=do-not-retain"
            case_file = root / "case.yaml"
            case_file.write_text(yaml.safe_dump(case))
            log = self.log(root, {"method": "GET", "uri": "/no-crs/allow?<redacted>", "transaction_id": "foreign-before-call"})
            receipt = root / "request-window.json"
            command = ["request-window", "--case", str(case_file), "--event-log", str(log),
                       "--receipt", str(receipt), "--output-root", str(root),
                       "--run-id", BINDING["run_id"], "--source-revision", BINDING["source_revision"]]
            self.assertEqual(case_cli.main(command + ["--phase", "begin"]), 0)
            with log.open("a") as stream:
                stream.write(json.dumps({"method": "GET", "uri": "/no-crs/allow?<redacted>",
                                         "transaction_id": "actual-current-call"}) + "\n")
            self.assertEqual(case_cli.main(command + ["--phase", "end"]), 0)
            window = json.loads(receipt.read_text())
            self.assertEqual(case_cli.captured_request_transaction(case, str(log), root, window=window), "actual-current-call")
            self.assertNotIn("do-not-retain", receipt.read_text())
            self.assertNotEqual(window["request_id"], "actual-current-call")
            changed = log.read_bytes().replace(b"foreign-before-call", b"rewritten-old-event")
            log.write_bytes(changed)
            with self.assertRaisesRegex(ValueError, "interval"):
                case_cli.captured_request_transaction(case, str(log), root, window=window)

    def test_request_capture_rejects_missing_ambiguous_and_wrong_request_transactions(self) -> None:
        case = {"request": {"method": "GET", "path": "/allow"}}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for entries in (
                [], [{"method": "GET", "uri": "/deny", "transaction_id": "foreign"}],
                [{"method": "GET", "uri": "/allow", "transaction_id": tx} for tx in ("one", "two")],
            ):
                with self.subTest(entries=len(entries)):
                    log = self.log(root, *entries)
                    with self.assertRaisesRegex(ValueError, "exactly one"):
                        case_cli.captured_request_transaction(case, str(log), root)

    def test_failed_or_blocked_request_without_a_host_identity_remains_nonpromoting(self) -> None:
        for status, live in (("fail", True), ("blocked", False)):
            with self.subTest(status=status):
                summary = msconnector_models.connector_summary(connector="nginx", entries=[{
                    "name": "no-host-id", "case_id": "no-host-id", "status": status,
                    "run_id": BINDING["run_id"], "source_revision": BINDING["source_revision"],
                    "live_executed": live,
                }])
                self.assertEqual(summary["summary"][status], 1)
                self.assertFalse(summary["cases"]["no-host-id"]["promotion_allowed"])

    def log(self, root: Path, *entries: dict) -> Path:
        path = root / "interventions.jsonl"
        path.write_text("".join(json.dumps(entry) + "\n" for entry in entries), encoding="utf-8")
        return path

    def event(self, **changes) -> dict:
        return {"event": "phase4_intervention", **BINDING, "http_status": 403,
                "action": "deny", "rule_id": 1100301, **changes}

    def entry(self, **changes) -> dict:
        return {"name": BINDING["case_id"], **BINDING, "status": "pass",
                "actual_status": 200, "live_executed": True, **changes}

    def test_unbound_shared_log_cannot_supply_another_request_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            log = self.log(Path(temporary), self.event(transaction_id="foreign"))
            self.assertEqual(runner_core.phase4_log_metadata(log), {})

    def test_bound_selection_ignores_later_foreign_intervention(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            expected = self.event()
            log = self.log(Path(temporary), expected, self.event(transaction_id="foreign"))
            self.assertEqual(runner_core.phase4_log_metadata(log, binding=BINDING), expected)

    def test_same_transaction_cannot_borrow_another_run_case_or_revision(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            for field in ("run_id", "case_id", "request_id", "source_revision"):
                with self.subTest(field=field):
                    log = self.log(Path(temporary), self.event(**{field: "foreign"}))
                    with self.assertRaisesRegex(ValueError, "identity mismatch"):
                        runner_core.phase4_log_metadata(log, binding=BINDING)

    def test_conflicting_events_for_the_same_transaction_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            log = self.log(Path(temporary), self.event(), self.event(http_status=200))
            with self.assertRaisesRegex(ValueError, "conflicting"):
                runner_core.phase4_log_metadata(log, binding=BINDING)

    def test_intervention_never_replaces_observed_client_status(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            log = self.log(Path(temporary), self.event(visible_http_status=403))
            info = {**BINDING, "actual_status": 200, "observed_status": 200}
            case_cli._add_phase4_log_evidence(info, str(log))
            self.assertEqual(info["actual_status"], 200)
            self.assertEqual(info["observed_status"], 200)
            self.assertEqual(info["visible_http_status"], 200)
            self.assertEqual(info["intervention_http_status"], 403)

    def test_required_result_source_must_exist_and_contain_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "results.jsonl"
            command = ["summarize-results", "--connector", "nginx", "--input-jsonl", str(source),
                       "--summary-json", str(root / "summary.json"),
                       "--summary-text", str(root / "summary.txt")]
            for exists in (False, True):
                with self.subTest(exists=exists):
                    if exists:
                        source.write_text("\n", encoding="utf-8")
                    with contextlib.redirect_stderr(io.StringIO()):
                        self.assertNotEqual(case_cli.main(command), 0)
                    self.assertFalse((root / "summary.json").exists())

    def test_repeated_attempt_does_not_inflate_distinct_case_counts(self) -> None:
        entry = self.entry()
        summary = msconnector_models.connector_summary(connector="apache", entries=[entry, entry])
        self.assertEqual(summary["summary"]["pass"], 1)
        self.assertEqual(len(summary["cases"]), 1)
        self.assertEqual(summary["attempted"], 2)
        self.assertEqual(len(summary["attempts"]), 2)

    def test_conflicting_observations_of_one_attempt_fail(self) -> None:
        entries = [self.entry(), self.entry(actual_status=403)]
        with self.assertRaisesRegex(ValueError, "conflicting"):
            msconnector_models.connector_summary(connector="apache", entries=entries)

    def test_retry_keeps_failed_traffic_and_counts_one_case(self) -> None:
        summary = msconnector_models.connector_summary(connector="envoy", entries=[
            self.entry(status="fail", actual_status=500),
            self.entry(request_id="request-two", transaction_id="transaction-two"),
        ])
        self.assertEqual(summary["summary"]["fail"], 1)
        self.assertEqual(summary["summary"]["pass"], 0)
        self.assertEqual(len(summary["cases"]), 1)
        self.assertEqual(len(summary["attempts"]), 2)
        self.assertTrue(summary["attempts"][0]["live_executed"])

    def test_selected_case_completeness_rejects_missing_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "results.jsonl"
            source.write_text(json.dumps(self.entry()) + "\n", encoding="utf-8")
            with contextlib.redirect_stderr(io.StringIO()):
                result = case_cli.main([
                    "summarize-results", "--connector", "nginx", "--input-jsonl", str(source),
                    "--summary-json", str(root / "summary.json"),
                    "--summary-text", str(root / "summary.txt"),
                    "--expected-case", BINDING["case_id"], "--expected-case", "missing-case",
                    "--run-id", BINDING["run_id"], "--source-revision", BINDING["source_revision"],
                ])
            self.assertNotEqual(result, 0)
            self.assertFalse((root / "summary.json").exists())

    def test_request_transaction_cannot_be_reassigned_to_another_case(self) -> None:
        entries = [self.entry(), self.entry(case_id="different-case", name="different-case")]
        with self.assertRaisesRegex(ValueError, "conflicting request/transaction"):
            msconnector_models.connector_summary(connector="apache", entries=entries)

    def test_partial_or_invalid_source_identity_cannot_be_promoted(self) -> None:
        for field, value in (("source_revision", "not-a-revision"), ("request_id", "")):
            with self.subTest(field=field):
                entries = [self.entry(**{field: value})]
                with self.assertRaisesRegex(ValueError, "result identity"):
                    msconnector_models.connector_summary(connector="nginx", entries=entries)

    def test_legacy_unbound_result_cannot_promote_runtime_capabilities(self) -> None:
        summary = msconnector_models.connector_summary(connector="apache", entries=[{
            "name": "legacy", "status": "pass", "actual_status": 200,
            "live_executed": True, "capabilities": ["request-headers"],
        }])
        self.assertEqual(summary["summary"]["pass"], 1)
        self.assertEqual(summary["verified_variables"], [])
        self.assertFalse(summary["cases"]["legacy"]["promotion_allowed"])
        self.assertFalse(msconnector_models.is_verified_runtime_pass({
            "status": "pass", "live_executed": True,
        }))

    def test_bound_live_pass_retains_legitimate_capability_promotion(self) -> None:
        summary = msconnector_models.connector_summary(connector="apache", entries=[
            self.entry(capabilities=["request-headers"]),
        ])
        self.assertEqual(summary["verified_variables"], ["REQUEST_HEADERS", "REQUEST_HEADERS_NAMES"])

    def test_case_info_cli_keeps_allow200_separate_from_foreign_deny403(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            log = self.log(root, self.event(transaction_id="foreign"))
            output = root / "result.json"
            command = ["case-info", "--case", str(test_root() /
                       "tests/cases/no-crs-baseline/allow_without_marker.yaml"),
                       "--connector", "apache", "--actual-status", "200", "--status", "pass",
                       "--phase4-log-file", str(log), "--output", str(output), "--output-root", str(root)]
            for field, value in BINDING.items():
                command.extend(("--" + field.replace("_", "-"), value))
            self.assertEqual(case_cli.main(command), 0)
            observed = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(observed["actual_status"], 200)
            self.assertEqual(observed["visible_http_status"], 200)
            self.assertNotIn("actual_action", observed)
            self.assertNotIn("intervention_http_status", observed)
            self.assertEqual(observed["transaction_ids"], [BINDING["transaction_id"]])
            self.assertEqual(observed["run_id"], BINDING["run_id"])
            self.assertEqual(observed["source_revision"], BINDING["source_revision"])

    def test_case_info_writer_failure_is_a_nonzero_cli_result(self) -> None:
        command = ["case-info", "--case", str(test_root() /
                   "tests/cases/no-crs-baseline/allow_without_marker.yaml"), "--actual-status", "200"]
        with mock.patch.object(case_cli, "_write_or_print_case_info", side_effect=OSError("write failed")):
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertNotEqual(case_cli.main(command), 0)

    def test_explicit_blocked_preparation_still_has_its_own_empty_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.assertEqual(case_cli.main([
                "summarize-empty", "--connector", "nginx", "--status", "blocked",
                "--message", "prerequisite unavailable", "--summary-json", str(root / "summary.json"),
                "--summary-text", str(root / "summary.txt"),
            ]), 0)
            self.assertEqual(json.loads((root / "summary.json").read_text())["nginx"]["summary"]["blocked"], 1)

    def test_empty_preparation_cannot_claim_a_passing_case(self) -> None:
        with self.assertRaisesRegex(ValueError, "cannot report a passing"):
            msconnector_models.empty_connector_summary(connector="nginx", status="pass")

    def test_apache_native_materialization_preserves_the_original_oracle(self) -> None:
        source = test_root() / "tests/cases/no-crs-baseline/duplicate_header_names.yaml"
        original = source.read_bytes()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rules = root / "rules.conf"
            (root / "audit-parts").mkdir(mode=0o700)
            self.assertEqual(case_cli.main([
                "materialize", "--case", str(source), "--native-profile", "apache-native",
                "--output-root", str(root), "--rules-file", str(rules),
                "--env-file", str(root / "case.env"), "--audit-log-file", str(root / "audit.log"),
                "--audit-log-dir", str(root / "audit-parts"),
                "--rules-preamble-file", str(test_root() / "tests/rules/no-crs-baseline.conf"),
            ]), 0)
            archived = Path(str(rules) + ".original-oracle").read_text()
            native = rules.read_text()
            receipt = json.loads(Path(str(rules) + ".native-profile.json").read_text())
            self.assertIn('SecRule &REQUEST_HEADERS:X-No-Crs-Duplicate "@eq 2"', archived)
            self.assertIn('SecRule &REQUEST_HEADERS:X-No-Crs-Duplicate "@eq 1"', native)
            self.assertIn('"@streq one, two"', native)
            self.assertIn("id:1100504", archived)
            self.assertIn("id:1100504", native)
            self.assertTrue(receipt["unchanged_expectations"]["audit_required"])
            self.assertIsNone(receipt["runtime_retest"])
        self.assertEqual(source.read_bytes(), original)


class RequestObservationContractTests(unittest.TestCase):
    def window(self, root, *, exists=True, events=(), completed=True, revision=None):
        revision = revision or BINDING["source_revision"]
        source = test_root() / "tests/cases/no-crs-baseline/allow_without_marker.yaml"
        case = root / "case.yaml"
        case.write_bytes(source.read_bytes())
        log, receipt, output = root / "events.jsonl", root / "request-window.json", root / "result.json"
        if exists:
            log.write_text("")
        bracket = ["request-window", "--case", str(case), "--event-log", str(log),
                   "--receipt", str(receipt), "--output-root", str(root),
                   "--run-id", BINDING["run_id"], "--source-revision", revision]
        self.assertEqual(case_cli.main(bracket + ["--phase", "begin"]), 0)
        if events:
            log.write_text("".join((entry if isinstance(entry, str) else json.dumps(entry)) + "\n" for entry in events))
        if completed:
            self.assertEqual(case_cli.main(bracket + ["--phase", "end"]), 0)
        command = ["case-info", "--case", str(case), "--connector", "apache", "--status", "pass",
                   "--actual-status", "200", "--capture-request-log", str(log),
                   "--capture-request-window", str(receipt), "--phase4-log-file", str(log),
                   "--output", str(output), "--output-root", str(root),
                   "--run-id", BINDING["run_id"], "--source-revision", revision]
        return command, receipt, output, bracket

    def result(self, root, *, revision=None):
        command, _, output, _ = self.window(root, revision=revision)
        self.assertEqual(case_cli.main(command), 0)
        return json.loads(output.read_text())

    def test_completed_empty_or_absent_log_retains_client_only_200(self):
        for exists in (True, False):
            with self.subTest(log_exists=exists), tempfile.TemporaryDirectory() as temporary:
                command, receipt, output, _ = self.window(Path(temporary), exists=exists)
                self.assertEqual(case_cli.main(command), 0)
                row = json.loads(output.read_text())
                self.assertEqual(row["request_id"], json.loads(receipt.read_text())["request_id"])
                self.assertEqual(row["evidence_identity"], "request_bound")
                self.assertIsNone(row["transaction_id"])
                self.assertEqual(row["transaction_ids"], [])
                self.assertEqual(row["actual_status"], 200)
                self.assertEqual(row["visible_http_status"], 200)
                self.assertTrue(row["live_executed"])
                self.assertFalse(row["runtime_verified"])
                self.assertFalse(row["promotion_allowed"])
                summary = msconnector_models.connector_summary(connector="apache", entries=[row, row])
                self.assertEqual(summary["summary"]["pass"], 1)
                self.assertEqual(summary["attempted"], 2)
                self.assertEqual(summary["evidence_identity"], "request_bound")
                self.assertEqual(summary["verified_variables"], [])
                self.assertFalse(summary["promotion_allowed"])

    def test_no_matching_transaction_cannot_enrich_from_foreign_host_event(self):
        with tempfile.TemporaryDirectory() as temporary:
            command, _, output, _ = self.window(Path(temporary), events=[{
                "method": "GET", "uri": "/foreign", "transaction_id": "foreign-tx",
                "event": "phase4_intervention", "http_status": 403, "phase": 4, "action": "deny"}])
            self.assertEqual(case_cli.main(command), 0)
            row = json.loads(output.read_text())
            self.assertEqual(row["evidence_identity"], "request_bound")
            self.assertEqual(row["actual_status"], 200)
            self.assertNotIn("intervention_http_status", row)
            self.assertNotIn("actual_action", row)
            self.assertNotIn("phase", row)

    def test_unfinished_tampered_or_borrowed_window_is_rejected(self):
        mutations = {
            "unfinished": {"state": "begun"}, "nonce": {"request_id": "request-" + "a" * 32},
            "run": {"run_id": "borrowed-run"}, "case": {"case_id": "borrowed-case"},
            "revision": {"source_revision": "b" * 40}, "case-digest": {"case_sha256": "0" * 64},
            "prefix-digest": {"prefix_sha256": "0" * 64}, "interval-digest": {"interval_sha256": "0" * 64},
            "offset": {"end_offset": 1}, "begin-digest": {"begin_sha256": "0" * 64},
            "log-path": {"event_log": "/foreign/events.jsonl"}, "schema": {"schema_version": 1},
        }
        for name, changes in mutations.items():
            with self.subTest(mutation=name), tempfile.TemporaryDirectory() as temporary:
                command, receipt, output, _ = self.window(Path(temporary))
                value = json.loads(receipt.read_text()); value.update(changes)
                receipt.write_text(json.dumps(value))
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertNotEqual(case_cli.main(command), 0)
                self.assertFalse(output.exists())

    def test_missing_anchor_explicit_foreign_nonce_and_changed_case_are_rejected(self):
        for mutation in ("missing-anchor", "explicit-foreign-nonce", "changed-case", "borrowed-anchor", "unfinished-begin"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                command, receipt, output, _ = self.window(root, completed=mutation != "unfinished-begin")
                if mutation == "missing-anchor":
                    case_cli._window_anchor(receipt).unlink()
                elif mutation == "explicit-foreign-nonce":
                    command += ["--request-id", "request-" + "b" * 32]
                elif mutation == "changed-case":
                    (root / "case.yaml").write_text((root / "case.yaml").read_text() + "\n# changed\n")
                elif mutation == "borrowed-anchor":
                    other = root / "other"; other.mkdir()
                    _, foreign, _, _ = self.window(other)
                    case_cli._window_anchor(receipt).write_bytes(case_cli._window_anchor(foreign).read_bytes())
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertNotEqual(case_cli.main(command), 0)
                self.assertFalse(output.exists())

    def test_malformed_ambiguous_or_conflicting_host_events_never_fall_back(self):
        own = {"method": "GET", "uri": "/no-crs/allow", "transaction_id": "own-tx"}
        variants = [[{**own, "transaction_id": tx} for tx in ("one", "two")],
                    [{**own, "run_id": "foreign-run"}], [{**own, "case_id": "foreign-case"}],
                    [{**own, "source_revision": "b" * 40}], [{**own, "transaction_id": None}],
                    [{**own, "transaction_id": "bad transaction"}], ["not-json"], [["not-an-object"]]]
        for index, events in enumerate(variants):
            with self.subTest(variant=index), tempfile.TemporaryDirectory() as temporary:
                command, _, output, _ = self.window(Path(temporary), events=events)
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertNotEqual(case_cli.main(command), 0)
                self.assertFalse(output.exists())

    def test_begin_nonce_cannot_be_reused_or_completed_twice(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, _, _, bracket = self.window(Path(temporary))
            for phase in ("begin", "end"):
                with self.subTest(phase=phase), contextlib.redirect_stderr(io.StringIO()):
                    self.assertNotEqual(case_cli.main(bracket + ["--phase", phase]), 0)

    def test_request_only_summary_keeps_ownership_run_revision_and_failed_retries(self):
        with tempfile.TemporaryDirectory() as temporary:
            row = self.result(Path(temporary))
            for changes in ({"case_id": "borrowed-case", "name": "borrowed-case"},
                            {"run_id": "foreign-run"}, {"source_revision": "b" * 40}):
                with self.subTest(changes=changes), self.assertRaises(ValueError):
                    msconnector_models.connector_summary(connector="apache", entries=[row, {**row, **changes}])
            retry_root = Path(temporary) / "retry"; retry_root.mkdir()
            retry = {**self.result(retry_root), "status": "fail", "actual_status": 500}
            summary = msconnector_models.connector_summary(connector="apache", entries=[row, row, retry])
            self.assertEqual(summary["summary"]["fail"], 1)
            self.assertEqual(summary["summary"]["pass"], 0)
            self.assertEqual(summary["attempted"], 3)
            self.assertFalse(summary["promotion_allowed"])
            with self.assertRaisesRegex(ValueError, "conflicting"):
                msconnector_models.connector_summary(connector="apache", entries=[row, {**row, "actual_status": 403}])

    def test_request_observation_marker_cannot_authorize_partial_or_promoting_rows(self):
        with tempfile.TemporaryDirectory() as temporary:
            row = self.result(Path(temporary))
            for changes in ({"request_id": ""}, {"request_observation": {}}, {"promotion_allowed": True},
                            {"runtime_verified": True}, {"transaction_id": "borrowed-tx"},
                            {"transaction_ids": ["borrowed-tx"]}, {"live_executed": False},
                            {"request_id": "request-" + "c" * 32},
                            {"request_observation": {**row["request_observation"], "receipt_sha256": "0" * 64}},
                            {"request_observation": {**row["request_observation"], "case_sha256": "0" * 64}}):
                with self.subTest(changes=changes), self.assertRaises(ValueError):
                    msconnector_models.connector_summary(connector="apache", entries=[{**row, **changes}])


if os.environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)


if __name__ == "__main__":
    unittest.main()
