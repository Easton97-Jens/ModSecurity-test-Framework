from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


REPO_ROOT = connector_root()
HARNESS = source_path('connectors/lighttpd/harness', root=REPO_ROOT)
FIRST_BYTE_WRITER = HARNESS / "write_patched_first_byte_metadata.py"
LIFECYCLE_WRITER = HARNESS / "write_patched_lifecycle_results.py"
ENTITY_FIXTURE = HARNESS / "lighttpd_http1_entity_fixture_upstream.py"
CI_LIB = source_path('ci/lib', root=REPO_ROOT)


from modsecurity_connector_ci.lib.verified_run_id import VERIFIED_RUN_ID_PATTERN  # noqa: E402


def safe_p4_event(
    *,
    phase: object = "response_body",
    body_bytes_seen: object = 31,
    body_bytes_inspected: object = 31,
    transaction_id: str = "tx-safe",
    run_id: object | None = None,
) -> dict[str, object]:
    event: dict[str, object] = {
        "connector": "lighttpd",
        "integration_mode": "patched-native-lighttpd",
        "event": "response_blocked",
        "message_id": "response_blocked",
        "transaction_id": transaction_id,
        "rule_id": "1100301",
        "phase": phase,
        "status": "blocked",
        "http_status": 403,
        "original_http_status": 200,
        "visible_http_status": 200,
        "requested_action": "deny",
        "actual_action": "log_only",
        "late_intervention": True,
        "late_intervention_mode": "safe",
        "headers_sent": True,
        "body_started": True,
        "response_committed": True,
        "connection_aborted": False,
        "transport_result": "log_only",
        "body_bytes_seen": body_bytes_seen,
        "body_bytes_inspected": body_bytes_inspected,
    }
    if run_id is not None:
        event["run_id"] = run_id
    return event


def write_jsonl(
    path: Path, events: list[object], *, surrounding_blank_lines: bool = False
) -> None:
    content = "".join(f"{json.dumps(event)}\n" for event in events)
    if surrounding_blank_lines:
        content = "\n \n" + content + "\t\n"
    path.write_text(content, encoding="utf-8")


def lifecycle_arguments(
    *,
    events: Path,
    output: Path,
    barrier: Path,
    projection: Path,
    first_byte_evidence: Path,
    content_length: Path,
    chunked: Path,
    fixture: Path,
    summary: Path,
    selected_case_ids: str = "",
    run_id: str = "lighttpd-current-run",
) -> list[str]:
    arguments = [
        "--events",
        str(events),
        "--run-id",
        run_id,
        "--output",
        str(output),
        "--allow-status",
        "200",
        "--deny-status",
        "403",
        "--alternative-status",
        "429",
        "--request-body-status",
        "403",
        "--response-header-status",
        "403",
        "--phase4-safe-events",
        str(barrier),
        "--phase4-projected-events-output",
        str(projection),
        "--phase4-safe-status",
        "200",
        "--phase4-first-byte-evidence",
        str(first_byte_evidence),
        "--content-length-events",
        str(content_length),
        "--chunked-events",
        str(chunked),
        "--entity-fixture-result",
        str(fixture),
        "--phase4-summary-output",
        str(summary),
    ]
    if selected_case_ids:
        arguments.extend(["--selected-case-ids", selected_case_ids])
    return arguments


def with_replaced_argument(
    arguments: list[str], option: str, value: Path | str
) -> list[str]:
    replacement = list(arguments)
    replacement[replacement.index(option) + 1] = str(value)
    return replacement


def without_argument(arguments: list[str], option: str) -> list[str]:
    replacement = list(arguments)
    index = replacement.index(option)
    del replacement[index : index + 2]
    return replacement


def write_lifecycle_inputs(
    root: Path, barrier_events: list[object], *, selected_case_ids: str = ""
) -> tuple[list[str], dict[str, Path]]:
    root.mkdir(parents=True, exist_ok=True)
    events = root / "events.jsonl"
    barrier = root / "barrier.jsonl"
    content_length = root / "content-length.jsonl"
    chunked = root / "chunked.jsonl"
    fixture = root / "fixture.json"
    first_byte_evidence = root / "first-byte.json"
    output = root / "published" / "results.jsonl"
    projection = root / "published" / "projection.json"
    summary = root / "published" / "summary.json"

    write_jsonl(events, [], surrounding_blank_lines=True)
    write_jsonl(barrier, barrier_events, surrounding_blank_lines=True)
    write_jsonl(
        content_length,
        [
            safe_p4_event(
                phase="response-body",
                body_bytes_seen=29.9,
                body_bytes_inspected=29.1,
                transaction_id="tx-content-length",
            )
        ],
    )
    write_jsonl(
        chunked,
        [
            safe_p4_event(
                phase=4,
                body_bytes_seen=24.9,
                body_bytes_inspected=24.1,
                transaction_id="tx-chunked",
            )
        ],
    )
    fixture.write_text(
        json.dumps(
            {
                "evidence_type": "lighttpd_http1_entity_fixture_result",
                "body_payload_persisted": False,
                "content_length_requests": 1,
                "chunked_requests": 1,
                "content_length_entity_bytes": 29,
                "chunked_entity_bytes": 24,
            }
        ),
        encoding="utf-8",
    )
    first_byte_evidence.write_text("{}\n", encoding="utf-8")

    return (
        lifecycle_arguments(
            events=events,
            output=output,
            barrier=barrier,
            projection=projection,
            first_byte_evidence=first_byte_evidence,
            content_length=content_length,
            chunked=chunked,
            fixture=fixture,
            summary=summary,
            selected_case_ids=selected_case_ids,
        ),
        {
            "output": output,
            "projection": projection,
            "runtime_root": root,
            "summary": summary,
            "barrier": barrier,
        },
    )


class PatchedEventValidationTest(unittest.TestCase):
    def run_writer(
        self,
        writer: Path,
        arguments: list[str],
        *,
        runtime_output_root: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        output = Path(arguments[arguments.index("--output") + 1])
        root = runtime_output_root or output.parent
        completed_arguments = [
            *arguments,
            "--runtime-output-root",
            str(root),
        ]
        return subprocess.run(
            ["python3", str(writer), *completed_arguments],
            cwd=REPO_ROOT,
            env=environment,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def test_first_byte_writer_accepts_phase_aliases_and_preserves_schema(self) -> None:
        aliases = ("4", "phase4", "response_body", "response-body")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, phase in enumerate(aliases):
                with self.subTest(phase=phase):
                    event = safe_p4_event(
                        phase=phase,
                        body_bytes_seen=9.9,
                        body_bytes_inspected=8.1,
                        transaction_id=f"tx-{index}",
                    )
                    event.pop("http_status")
                    events = root / f"events-{index}.jsonl"
                    output = root / "nested" / str(index) / "metadata.json"
                    write_jsonl(events, [event], surrounding_blank_lines=True)

                    result = self.run_writer(
                        FIRST_BYTE_WRITER,
                        ["--events", str(events), "--output", str(output)],
                    )

                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertTrue(output.parent.is_dir())
                    self.assertEqual(
                        json.loads(output.read_text(encoding="utf-8")),
                        {
                            "body_bytes_inspected": 8,
                            "body_bytes_seen": 9,
                            "connector_owned_full_response_buffer": False,
                            "no_full_response_buffering": True,
                            "response_committed": True,
                        },
                    )

    def test_first_byte_writer_rejects_invalid_counters_and_candidate_counts(self) -> None:
        candidate_error = (
            "synchronized Lighttpd barrier requires exactly one safe P4 host-action event"
        )
        wrong_candidate = safe_p4_event()
        wrong_candidate["actual_action"] = "deny"
        cases = (
            (
                "boolean-counter",
                [safe_p4_event(body_bytes_seen=True)],
                "body_bytes_seen must be a non-negative integer",
            ),
            (
                "negative-counter",
                [safe_p4_event(body_bytes_inspected=-1)],
                "body_bytes_inspected must be a non-negative integer",
            ),
            (
                "inspected-over-seen",
                [safe_p4_event(body_bytes_seen=1, body_bytes_inspected=2)],
                "body_bytes_inspected cannot exceed body_bytes_seen",
            ),
            ("zero-candidates", [], candidate_error),
            (
                "multiple-candidates",
                [safe_p4_event(), safe_p4_event(transaction_id="tx-second")],
                candidate_error,
            ),
            ("wrong-candidate", [wrong_candidate], candidate_error),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, events_value, expected_error in cases:
                with self.subTest(name=name):
                    events = root / f"{name}.jsonl"
                    output = root / name / "metadata.json"
                    write_jsonl(events, events_value)

                    result = self.run_writer(
                        FIRST_BYTE_WRITER,
                        ["--events", str(events), "--output", str(output)],
                    )

                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(expected_error, result.stderr)
                    self.assertFalse(output.exists())

    def test_first_byte_writer_rejects_escaped_and_symlink_output_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            events = root / "events.jsonl"
            write_jsonl(events, [safe_p4_event()])
            trusted_root = root / "trusted"
            escaped = root / "escaped" / "metadata.json"
            result = self.run_writer(
                FIRST_BYTE_WRITER,
                ["--events", str(events), "--output", str(escaped)],
                runtime_output_root=trusted_root,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must be below the runtime output root", result.stderr)
            self.assertFalse(escaped.exists())

            symlink = trusted_root / "escaped-link"
            symlink.symlink_to(root / "escaped")
            linked_output = symlink / "metadata.json"
            result = self.run_writer(
                FIRST_BYTE_WRITER,
                ["--events", str(events), "--output", str(linked_output)],
                runtime_output_root=trusted_root,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must be below the runtime output root", result.stderr)
            self.assertFalse((root / "escaped" / "metadata.json").exists())

    def test_entity_fixture_rejects_escaped_control_artifacts_before_listening(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            trusted_root = root / "trusted"
            cases = (
                (root / "escaped-ready.json", trusted_root / "result.json"),
                (trusted_root / "ready.json", root / "escaped-result.json"),
            )
            for ready_file, result_file in cases:
                with self.subTest(ready_file=ready_file, result_file=result_file):
                    result = subprocess.run(
                        [
                            "python3",
                            str(ENTITY_FIXTURE),
                            "--ready-file",
                            str(ready_file),
                            "--result-file",
                            str(result_file),
                            "--runtime-output-root",
                            str(trusted_root),
                        ],
                        cwd=REPO_ROOT,
                        check=False,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("must be below the runtime output root", result.stderr)
                    self.assertFalse(ready_file.exists())
                    self.assertFalse(result_file.exists())

    def test_load_events_preserves_parser_failures_and_caller_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            metadata_malformed = root / "metadata-malformed.jsonl"
            metadata_malformed.write_text("{\n", encoding="utf-8")
            metadata_result = self.run_writer(
                FIRST_BYTE_WRITER,
                [
                    "--events",
                    str(metadata_malformed),
                    "--output",
                    str(root / "metadata.json"),
                ],
            )
            self.assertNotEqual(metadata_result.returncode, 0)
            self.assertIn("JSONDecodeError", metadata_result.stderr)

            metadata_non_object = root / "metadata-non-object.jsonl"
            metadata_non_object.write_text("[]\n", encoding="utf-8")
            metadata_result = self.run_writer(
                FIRST_BYTE_WRITER,
                [
                    "--events",
                    str(metadata_non_object),
                    "--output",
                    str(root / "metadata-non-object.json"),
                ],
            )
            self.assertNotEqual(metadata_result.returncode, 0)
            self.assertIn(
                f"{metadata_non_object}:1: event must be an object",
                metadata_result.stderr,
            )

            lifecycle_root = root / "lifecycle-malformed"
            lifecycle_arguments_value, lifecycle_artifacts = write_lifecycle_inputs(
                lifecycle_root, [safe_p4_event()]
            )
            lifecycle_malformed = lifecycle_root / "lifecycle-malformed.jsonl"
            lifecycle_malformed.write_text("{\n", encoding="utf-8")
            lifecycle_result = self.run_writer(
                LIFECYCLE_WRITER,
                with_replaced_argument(
                    lifecycle_arguments_value, "--events", lifecycle_malformed
                ),
                runtime_output_root=lifecycle_artifacts["runtime_root"],
            )
            self.assertNotEqual(lifecycle_result.returncode, 0)
            self.assertIn("JSONDecodeError", lifecycle_result.stderr)

            lifecycle_non_object = lifecycle_root / "lifecycle-non-object.jsonl"
            lifecycle_non_object.write_text("[]\n", encoding="utf-8")
            lifecycle_result = self.run_writer(
                LIFECYCLE_WRITER,
                with_replaced_argument(
                    lifecycle_arguments_value, "--events", lifecycle_non_object
                ),
                runtime_output_root=lifecycle_artifacts["runtime_root"],
            )
            self.assertNotEqual(lifecycle_result.returncode, 0)
            self.assertIn(
                f"{lifecycle_non_object}:1 is not an object",
                lifecycle_result.stderr,
            )

    def test_lifecycle_writer_preserves_aliases_schema_and_candidate_controls(self) -> None:
        candidate_error = "synchronized first-byte barrier requires exactly one safe patched-lighttpd P4 host action"
        wrong_candidate = safe_p4_event()
        wrong_candidate.pop("http_status")
        candidates = (
            ("zero", []),
            ("multiple", [safe_p4_event(), safe_p4_event(transaction_id="tx-second")]),
            ("wrong", [wrong_candidate]),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            arguments, artifacts = write_lifecycle_inputs(
                root / "valid",
                [
                    safe_p4_event(
                        phase="phase4",
                        body_bytes_seen=31.9,
                        body_bytes_inspected=31.1,
                    )
                ],
                selected_case_ids="phase4_rule_observed",
            )
            result = self.run_writer(
                LIFECYCLE_WRITER,
                arguments,
                runtime_output_root=artifacts["runtime_root"],
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            rows = [
                json.loads(line)
                for line in artifacts["output"].read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["case_id"], "phase4_rule_observed")
            self.assertEqual(rows[0]["status"], "PASS")
            self.assertEqual(
                set(rows[0]),
                {
                    "case_id",
                    "status",
                    "actual_status",
                    "live_executed",
                    "observed_rule_ids",
                    "transaction_ids",
                    "decision_log_path",
                    "observed_transport_result",
                    "reason",
                    "http_status",
                    "original_http_status",
                    "visible_http_status",
                    "requested_action",
                    "actual_action",
                    "late_intervention",
                    "late_intervention_mode",
                    "headers_sent",
                    "body_started",
                    "response_committed",
                    "connection_aborted",
                    "transport_result",
                    "body_bytes_seen",
                    "body_bytes_inspected",
                    "eos_seen",
                    "end_of_stream_evaluation",
                    "first_byte_evidence_path",
                },
            )
            self.assertTrue(artifacts["projection"].is_file())
            self.assertTrue(artifacts["summary"].is_file())

            for name, barrier_events in candidates:
                with self.subTest(candidate=name):
                    arguments, artifacts = write_lifecycle_inputs(
                        root / name,
                        barrier_events,
                        selected_case_ids="phase4_rule_observed",
                    )
                    result = self.run_writer(
                        LIFECYCLE_WRITER,
                        arguments,
                        runtime_output_root=artifacts["runtime_root"],
                    )

                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(candidate_error, result.stderr)
                    self.assertFalse(artifacts["output"].exists())

    def test_lifecycle_writer_binds_selected_run_id_only_to_derived_eos_projection(
        self,
    ) -> None:
        selected_run_id = "lighttpd-current-run"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for label, raw_run_id in (
                ("missing-raw-identity", None),
                ("matching-raw-identity", selected_run_id),
            ):
                with self.subTest(raw_identity=label):
                    raw_event = safe_p4_event(run_id=raw_run_id)
                    raw_event.update(
                        {
                            "sequence": 7,
                            "previous_event_hash": "a" * 64,
                            "event_hash": "b" * 64,
                        }
                    )
                    arguments, artifacts = write_lifecycle_inputs(
                        root / label,
                        [raw_event],
                        selected_case_ids="phase4_rule_observed",
                    )
                    raw_before = artifacts["barrier"].read_bytes()

                    result = self.run_writer(
                        LIFECYCLE_WRITER,
                        arguments,
                        runtime_output_root=artifacts["runtime_root"],
                    )

                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(artifacts["barrier"].read_bytes(), raw_before)
                    projection = json.loads(
                        artifacts["projection"].read_text(encoding="utf-8")
                    )
                    self.assertEqual(projection["run_id"], selected_run_id)
                    self.assertNotIn("sequence", projection)
                    self.assertNotIn("previous_event_hash", projection)
                    self.assertNotIn("event_hash", projection)
                    rows = [
                        json.loads(line)
                        for line in artifacts["output"].read_text(
                            encoding="utf-8"
                        ).splitlines()
                    ]
                    self.assertTrue(rows)
                    self.assertTrue(all("run_id" not in row for row in rows))

    def test_lifecycle_writer_rejects_missing_or_invalid_selected_run_id_before_output(
        self,
    ) -> None:
        invalid_values = (
            "",
            " ",
            "safe/child",
            r"safe\child",
            "..",
            "with..dots",
            "a" * 129,
            "bad:id",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            arguments, artifacts = write_lifecycle_inputs(
                root / "missing", [safe_p4_event()]
            )
            result = self.run_writer(
                LIFECYCLE_WRITER,
                without_argument(arguments, "--run-id"),
                runtime_output_root=artifacts["runtime_root"],
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("the following arguments are required: --run-id", result.stderr)
            self.assertFalse(artifacts["output"].exists())
            self.assertFalse(artifacts["projection"].exists())
            self.assertFalse(artifacts["summary"].exists())

            for index, invalid_run_id in enumerate(invalid_values):
                with self.subTest(run_id=invalid_run_id):
                    arguments, artifacts = write_lifecycle_inputs(
                        root / f"invalid-{index}", [safe_p4_event()]
                    )
                    result = self.run_writer(
                        LIFECYCLE_WRITER,
                        with_replaced_argument(
                            arguments, "--run-id", invalid_run_id
                        ),
                        runtime_output_root=artifacts["runtime_root"],
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("verified_run_id", result.stderr)
                    self.assertFalse(artifacts["output"].exists())
                    self.assertFalse(artifacts["projection"].exists())
                    self.assertFalse(artifacts["summary"].exists())

    def test_lifecycle_writer_rejects_conflicting_raw_run_id_before_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            arguments, artifacts = write_lifecycle_inputs(
                root,
                [safe_p4_event(run_id="lighttpd-foreign-run")],
                selected_case_ids="phase4_rule_observed",
            )
            raw_before = artifacts["barrier"].read_bytes()

            result = self.run_writer(
                LIFECYCLE_WRITER,
                arguments,
                runtime_output_root=artifacts["runtime_root"],
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "raw Common event run_id conflicts with the selected Lighttpd run identity",
                result.stderr,
            )
            self.assertEqual(artifacts["barrier"].read_bytes(), raw_before)
            self.assertFalse(artifacts["output"].exists())
            self.assertFalse(artifacts["projection"].exists())
            self.assertFalse(artifacts["summary"].exists())

    def test_verified_run_id_contract_matches_the_existing_shared_pattern(self) -> None:
        self.assertTrue(VERIFIED_RUN_ID_PATTERN.fullmatch("lighttpd-current-run"))

    def test_lifecycle_writer_rejects_escaped_and_symlink_input_paths(self) -> None:
        options = (
            "--events",
            "--phase4-safe-events",
            "--phase4-first-byte-evidence",
            "--content-length-events",
            "--chunked-events",
            "--entity-fixture-result",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            trusted_root = root / "trusted"
            arguments, artifacts = write_lifecycle_inputs(
                trusted_root, [safe_p4_event()]
            )
            escaped = root / "escaped.json"
            escaped.write_text("{}\n", encoding="utf-8")

            for label, input_path in (
                ("escaped", escaped),
                ("symlink", trusted_root / "escaped-link.json"),
            ):
                if label == "symlink":
                    input_path.symlink_to(escaped)
                for option in options:
                    with self.subTest(path=label, option=option):
                        result = self.run_writer(
                            LIFECYCLE_WRITER,
                            with_replaced_argument(arguments, option, input_path),
                            runtime_output_root=artifacts["runtime_root"],
                        )
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn("must be below the runtime root", result.stderr)
                        self.assertFalse(artifacts["output"].exists())
                        self.assertFalse(artifacts["projection"].exists())
                        self.assertFalse(artifacts["summary"].exists())

    def test_lifecycle_writer_rejects_missing_or_nonregular_fixture_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            arguments, artifacts = write_lifecycle_inputs(root, [safe_p4_event()])
            fixture_directory = root / "fixture-directory"
            fixture_directory.mkdir()
            for fixture in (root / "missing-fixture.json", fixture_directory):
                with self.subTest(fixture=fixture):
                    result = self.run_writer(
                        LIFECYCLE_WRITER,
                        with_replaced_argument(
                            arguments, "--entity-fixture-result", fixture
                        ),
                        runtime_output_root=artifacts["runtime_root"],
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("must be an existing regular file", result.stderr)
                    self.assertFalse(artifacts["output"].exists())



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
