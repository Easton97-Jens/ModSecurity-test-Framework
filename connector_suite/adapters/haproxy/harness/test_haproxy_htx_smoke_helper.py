#!/usr/bin/env python3
"""Focused tests for the payload-free HAProxy HTX host-runtime helper."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import importlib.util
from email.message import Message
import json
import os
from pathlib import Path
import socket
import stat
import sys
import tempfile
import threading
import unittest
from unittest import mock


HELPER_PATH = Path(__file__).with_name("haproxy_htx_smoke_helper.py")
RUNTIME_PATH = Path(__file__).with_name("run_haproxy_htx_runtime.sh")
MAKEFILE_PATH = source_path('connectors/haproxy') / "Makefile"
HELPER = load_source(HELPER_PATH)
COLLECTOR_PATH = HELPER.REPO_ROOT / "ci/runtime/lifecycle/collect-no-crs-source.py"
COLLECTOR = load_source(COLLECTOR_PATH)
SYNCHRONIZED_UPSTREAM_PATH = (
    Path(os.environ.get("FRAMEWORK_ROOT", str(HELPER.REPO_ROOT / "modules/ModSecurity-test-Framework")))
    / "tests/runners/synchronized_upstream.py"
)
FRAMEWORK_ROOT_PATH = SYNCHRONIZED_UPSTREAM_PATH.parents[2]
CANONICAL_RULES_PATH = FRAMEWORK_ROOT_PATH / "tests/rules/no-crs-baseline.conf"
EVENT_SCHEMA_PATH = FRAMEWORK_ROOT_PATH / "tests/schemas/no-crs-baseline/event.schema.json"
SYNCHRONIZED_UPSTREAM = load_source(SYNCHRONIZED_UPSTREAM_PATH)


class HAProxyHTXSmokeHelperTest(unittest.TestCase):
    def test_fixture_creation_requires_explicit_engine_limit_and_action(self) -> None:
        with self.assertRaisesRegex(TypeError, "response_body_limit"):
            HELPER.write_rules("unused", "unused", response_body_limit_action="Reject")
        with self.assertRaisesRegex(TypeError, "response_body_limit_action"):
            HELPER.write_rules("unused", "unused", response_body_limit=8)
        with self.assertRaisesRegex(ValueError, "explicit positive response limit"):
            HELPER.write_rules("unused", "unused", request_body_limit=32, request_body_no_files_limit=32, request_body_limit_action="Reject", response_body_limit=0,
                               response_body_limit_action="Reject")

    def test_runtime_uses_explicit_framework_root_and_preserves_default(self) -> None:
        runtime = RUNTIME_PATH.read_text(encoding="utf-8")
        self.assertIn(
            "FRAMEWORK_ROOT=${FRAMEWORK_ROOT:-$REPO_ROOT/modules/ModSecurity-test-Framework}",
            runtime,
        )
        self.assertIn('SYNCHRONIZED_UPSTREAM="$FRAMEWORK_ROOT/tests/runners/synchronized_upstream.py"', runtime)
        self.assertIn(
            'CANONICAL_RULES_FILE=${HAPROXY_HTX_CANONICAL_RULES_FILE:-$FRAMEWORK_ROOT/tests/rules/no-crs-baseline.conf}',
            runtime,
        )
        self.assertIn(
            '"$PYTHON_BIN" "$HELPER" serve-upstream --port "$upstream_port"',
            runtime,
        )
        self.assertNotIn(
            'helper serve-upstream --port "$upstream_port"',
            runtime,
        )
        self.assertIn(
            'helper write-rules --path "$rules_file" --canonical-rules "$CANONICAL_RULES_FOR_HELPER" --request-body-limit 32 --request-body-no-files-limit 32 --request-body-limit-action Reject --response-body-limit 1048576 --response-body-limit-action Reject',
            runtime,
        )

        makefile = MAKEFILE_PATH.read_text(encoding="utf-8")
        self.assertIn(
            "FRAMEWORK_ROOT ?= $(REPO_ROOT)/modules/ModSecurity-test-Framework",
            makefile,
        )
        self.assertIn('FRAMEWORK_ROOT="$(FRAMEWORK_ROOT)" \\', makefile)

    def test_missing_framework_root_is_a_harness_blocker(self) -> None:
        import subprocess

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime_root = root / "runtime"
            fake_haproxy = root / "haproxy"
            fake_haproxy.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            fake_haproxy.chmod(0o755)
            completed = subprocess.run(
                [str(RUNTIME_PATH)],
                env={
                    **os.environ,
                    "FRAMEWORK_ROOT": str(root / "missing-framework"),
                    "HAPROXY_BIN": str(fake_haproxy),
                    "RUNTIME_ROOT": str(runtime_root),
                    "BUILD_ROOT": str(root / "build"),
                },
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 77)
            self.assertIn("Framework root is not an existing directory", completed.stderr)

    def test_phase2_upstream_profile_is_isolated_from_ordinary_requests(self) -> None:
        self.assertEqual(
            HELPER.upstream_profile("/no-crs/request-body?trace=ignored"),
            ("phase2", None, HELPER.UPSTREAM_OK_BODY),
        )

    def test_runtime_summary_uses_collector_recognized_phase_keys(self) -> None:
        runtime = RUNTIME_PATH.read_text(encoding="utf-8")
        self.assertIn("FULL_LIFECYCLE_EVIDENCE_OUTPUT", runtime)
        self.assertIn("streaming-probe", runtime)
        self.assertIn("phase2_deny_status=403", runtime)
        self.assertIn("phase2_bodyless_eos_status=200", runtime)
        self.assertIn("phase2_bodyless_eos_host_action=observed_only", runtime)
        self.assertIn("phase4_bodyless_eos_status=200", runtime)
        self.assertIn("phase4_bodyless_eos_host_action=observed_only", runtime)
        self.assertIn("phase2_bodyless_eos", runtime)
        self.assertIn("phase4_bodyless_eos", runtime)
        self.assertIn('--published-path "$FIRST_BYTE_EVIDENCE_PATH"', runtime)
        for key in (
            "phase4_safe_status=%s",
            "phase4_end_of_stream_evaluation_status=%s",
            "phase4_first_byte_before_response_end_status=%s",
            "phase4_no_full_response_buffering_status=%s",
        ):
            with self.subTest(key=key):
                self.assertIn(key, runtime)

    def test_bodyless_eos_controls_are_observation_only(self) -> None:
        runtime = RUNTIME_PATH.read_text(encoding="utf-8")
        self.assertIn(
            "run_case phase2_bodyless_eos 2 0 200 phase2 1 observed_only",
            runtime,
        )
        self.assertIn(
            "run_case phase4_bodyless_eos 4 0 200 phase4 1 observed_only",
            runtime,
        )
        self.assertIn("        observed_only)", runtime)
        self.assertIn(
            "phase2_bodyless_eos:2:0:200:1|phase4_bodyless_eos:4:0:200:1)",
            runtime,
        )
        # These controls prove the HTTP/1.1 EOS path only; their host action is
        # explicitly observation-only and therefore cannot synthesize a policy
        # decision or capability promotion.
        self.assertEqual(runtime.count("phase2_bodyless_eos 2 0 200"), 1)
        self.assertEqual(runtime.count("phase4_bodyless_eos 4 0 200"), 1)

    def test_runtime_diagnostic_range_is_centralized_without_changing_sed_calls(self) -> None:
        runtime = RUNTIME_PATH.read_text(encoding="utf-8")
        HTX_DIAGNOSTIC_RANGE = "1,160p"
        diagnostic_variable = "HAPROXY_HTX_DIAGNOSTIC_RANGE"
        declaration = f"readonly {diagnostic_variable}='{HTX_DIAGNOSTIC_RANGE}'"
        config_check_log = "$case_root/config-check.stderr.log"
        haproxy_log = "$log_file"
        synchronized_upstream_log = "$case_root/synchronized-upstream.stderr.log"
        streaming_client_log = "$case_root/streaming-client.stderr.log"
        diagnostic_sed = f'sed -n "${diagnostic_variable}"'

        self.assertEqual(runtime.count(declaration), 1)
        self.assertNotIn(f"sed -n '{HTX_DIAGNOSTIC_RANGE}'", runtime)

        expected_sed_invocations = [
            "sed -n '1,40p' \"$VERSION_FILE\" >&2 || true",
            f'{diagnostic_sed} "{config_check_log}" >&2 || true',
            f'{diagnostic_sed} "{haproxy_log}" >&2 || true',
            f'{diagnostic_sed} "{haproxy_log}" >&2 || true',
            f'{diagnostic_sed} "{synchronized_upstream_log}" >&2 || true',
            f'{diagnostic_sed} "{config_check_log}" >&2 || true',
            f'{diagnostic_sed} "{haproxy_log}" >&2 || true',
            f'{diagnostic_sed} "{streaming_client_log}" >&2 || true',
            f'{diagnostic_sed} "{synchronized_upstream_log}" >&2 || true',
            f'{diagnostic_sed} "{haproxy_log}" >&2 || true',
            f'{diagnostic_sed} "{streaming_client_log}" >&2 || true',
            f'{diagnostic_sed} "{streaming_client_log}" >&2 || true',
            f'{diagnostic_sed} "{synchronized_upstream_log}" >&2 || true',
            f'{diagnostic_sed} "{haproxy_log}" >&2 || true',
        ]
        actual_sed_invocations = [
            line.strip() for line in runtime.splitlines() if line.strip().startswith("sed -n ")
        ]

        self.assertEqual(actual_sed_invocations, expected_sed_invocations)

    def test_generated_config_selects_only_native_htx_filter(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rules = root / "rules.conf"
            config = root / "haproxy.cfg"
            certificate = root / "loopback-tls.pem"
            canonical_rules = root / "canonical-rules.conf"
            canonical_rules.write_text(CANONICAL_RULES_PATH.read_text(encoding="utf-8"), encoding="utf-8")
            certificate.write_text("private test certificate", encoding="utf-8")
            self.assertEqual(HELPER.write_rules(str(root), str(rules), str(canonical_rules), request_body_limit=32, request_body_no_files_limit=32, request_body_limit_action="Reject", response_body_limit=1048576, response_body_limit_action="Reject"), 0)
            self.assertEqual(
                HELPER.write_config(
                    str(root), str(config), 18080, 18081, str(rules), str(certificate),
                ),
                0,
            )
            content = config.read_text(encoding="utf-8")
            self.assertIn("filter modsecurity-htx rules-file", content)
            self.assertIn("bind 127.0.0.1:18080 ssl crt", content)
            for forbidden in ("filter spoe", "send-spoe", "http-buffer-request", "wait-for-body", "res.body"):
                self.assertNotIn(forbidden, content)
            generated_rules = rules.read_text(encoding="utf-8")
            self.assertEqual(
                generated_rules,
                HELPER.canonical_rules_content(root, str(canonical_rules))
                + "\nSecRequestBodyLimit 32\nSecRequestBodyNoFilesLimit 32\nSecRequestBodyLimitAction Reject\n"
                + "\nSecResponseBodyLimit 1048576\nSecResponseBodyLimitAction Reject\n",
            )
            for rule_id in (1100001, 1100002, 1100101, 1100201, 1100301):
                self.assertIn(f"id:{rule_id}", generated_rules)
            self.assertNotIn("91000", generated_rules)

    def test_event_contains_only_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            events = root / "events.jsonl"
            decision_log = root / "haproxy.stderr.log"
            decision_log.write_text(
                "modsecurity-htx: request intervention observed; "
                "transaction_id=haproxy-htx-phase1 phase=1 status=403 "
                "rule_id=1100001 action=deny\n",
                encoding="utf-8",
            )
            self.assertEqual(
                HELPER.write_event(
                    str(root),
                    str(events),
                    "phase1_403",
                    str(decision_log),
                    1,
                    1100001,
                    403,
                    "enforced_reply",
                ),
                0,
            )
            record = json.loads(events.read_text(encoding="utf-8"))
            self.assertEqual(record["connector"], "haproxy")
            self.assertEqual(record["message_id"], "HAPROXY_HTX_NATIVE_PRECOMMIT_DENY")
            self.assertEqual(record["status"], "blocked")
            self.assertEqual(record["integration_mode"], "native-htx-filter")
            self.assertEqual(record["evaluation_mode"], "native_host_runtime_nonpromoted")
            self.assertEqual(record["actual_action"], "deny")
            self.assertEqual(record["visible_http_status"], 403)
            self.assertFalse(record["headers_sent"])
            self.assertNotIn("body", record)
            self.assertNotIn("headers", record)
            self.assertEqual(stat.S_IMODE(events.stat().st_mode), 0o600)

            probe = Path(temporary) / "client-probe.json"
            host_evidence = Path(temporary) / "host-runtime-evidence.jsonl"
            probe.write_text(
                json.dumps({"status": 403, "response_bytes": 93, "content_type": "text/html"}),
                encoding="utf-8",
            )
            self.assertEqual(
                HELPER.write_host_evidence(
                    str(root),
                    str(host_evidence),
                    "phase1_403",
                    1,
                    1100001,
                    str(probe),
                    0,
                    "enforced_reply",
                    str(decision_log),
                ),
                0,
            )
            raw_record = json.loads(host_evidence.read_text(encoding="utf-8"))
            self.assertEqual(raw_record["upstream_requests"], 0)
            self.assertEqual(raw_record["client_response_bytes"], 93)
            self.assertNotIn("no-crs-request-body-marker", host_evidence.read_text(encoding="utf-8"))

    def test_host_decision_log_requires_exactly_one_matching_record(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            decision_log = root / "haproxy.stderr.log"
            records = (
                (
                    HELPER.decision_from_log,
                    1,
                    1100001,
                    "modsecurity-htx: request intervention observed; "
                    "transaction_id=haproxy-htx-unique phase=1 status=403 "
                    "rule_id=1100001 action=deny\n",
                ),
                (
                    HELPER.late_decision_from_log,
                    4,
                    1100301,
                    "modsecurity-htx: response-body late intervention observed; "
                    "transaction_id=haproxy-htx-unique phase=4 status=403 "
                    "rule_id=1100301 requested_action=deny "
                    "resolved_policy_action=log_only host_action=log_only\n",
                ),
            )
            for parser, phase, rule_id, record in records:
                with self.subTest(parser=parser.__name__):
                    duplicate = record.replace(
                        "transaction_id=haproxy-htx-unique",
                        "transaction_id=haproxy-htx-duplicate",
                    )
                    for duplicate_records in (record + duplicate, record.rstrip() + " " + duplicate):
                        decision_log.write_text(duplicate_records, encoding="utf-8")
                        with self.assertRaisesRegex(ValueError, "exactly one"):
                            parser(str(root), str(decision_log), phase, rule_id)

    def test_host_evidence_rejects_noncanonical_case_shapes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            probe = root / "client-probe.json"
            decision_log = root / "haproxy.stderr.log"
            evidence = root / "host-runtime-evidence.jsonl"
            probe.write_text(
                json.dumps({"status": 403, "response_bytes": 93, "content_type": "text/html"}),
                encoding="utf-8",
            )
            decision_log.write_text(
                "modsecurity-htx: request intervention observed; "
                "transaction_id=haproxy-htx-phase1 phase=1 status=403 "
                "rule_id=1100001 action=deny\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "closed contract"):
                HELPER.write_host_evidence(
                    str(root), str(evidence), "phase1_403", 2, 1100001,
                    str(probe), 0, "enforced_reply", str(decision_log),
                )
            self.assertFalse(evidence.exists())
            with self.assertRaisesRegex(ValueError, "decision-log presence"):
                HELPER.write_host_evidence(
                    str(root), str(evidence), "phase1_403", 1, 1100001,
                    str(probe), 0, "enforced_reply",
                )
            self.assertFalse(evidence.exists())
            for malformed_decision in (
                "modsecurity-htx: request intervention observed; "
                "transaction_id=haproxy-htx-phase1 phase=1 status=403 "
                "rule_id=1100001 action=allow\n",
                "modsecurity-htx: request intervention observed; "
                "transaction_id=haproxy-htx-phase1 phase=1 status=200 "
                "rule_id=1100001 action=deny\n",
            ):
                decision_log.write_text(malformed_decision, encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "host decision does not match"):
                    HELPER.write_host_evidence(
                        str(root), str(evidence), "phase1_403", 1, 1100001,
                        str(probe), 0, "enforced_reply", str(decision_log),
                    )
                self.assertFalse(evidence.exists())

    def test_private_harness_limits_request_framing_and_headers(self) -> None:
        exact_length_headers = Message()
        exact_length_headers["Content-Length"] = str(HELPER.MAX_HARNESS_REQUEST_BODY_BYTES)
        self.assertEqual(
            HELPER.upstream_content_length(exact_length_headers),
            HELPER.MAX_HARNESS_REQUEST_BODY_BYTES,
        )
        for description, configure in (
            (
                "oversized",
                lambda headers: headers.__setitem__(
                    "Content-Length", str(HELPER.MAX_HARNESS_REQUEST_BODY_BYTES + 1),
                ),
            ),
            ("duplicate", lambda headers: (headers.__setitem__("Content-Length", "0"), headers.__setitem__("Content-Length", "0"))),
            (
                "conflicting",
                lambda headers: (
                    headers.__setitem__("Transfer-Encoding", "chunked"),
                    headers.__setitem__("Content-Length", "0"),
                ),
            ),
        ):
            with self.subTest(description=description):
                headers = Message()
                configure(headers)
                with self.assertRaises(ValueError):
                    HELPER.upstream_content_length(headers)
        with self.assertRaisesRegex(ValueError, "headers exceed"):
            HELPER.probe_headers(["X-Large: " + "x" * HELPER.MAX_HARNESS_HEADER_BYTES])

    def test_upstream_rejects_oversized_aggregate_headers(self) -> None:
        server = HELPER.http.server.ThreadingHTTPServer(("127.0.0.1", 0), HELPER.UpstreamHandler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            request = (
                b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nX-Large: "
                + b"x" * HELPER.MAX_HARNESS_HEADER_BYTES
                + b"\r\n\r\n"
            )
            with socket.create_connection(("127.0.0.1", server.server_port), timeout=2) as client:
                client.sendall(request)
                client.shutdown(socket.SHUT_WR)
                response = client.recv(1024)
            self.assertIn(b" 431 ", response)
        finally:
            server.shutdown()
            worker.join(timeout=2)
            server.server_close()

    def test_probes_reject_bounded_request_and_response_overflow(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / "client-probe.json"
            with self.assertRaisesRegex(ValueError, "request body exceeds"):
                HELPER.probe(
                    str(root), "https://127.0.0.1:1/", [], "POST",
                    "x" * (HELPER.MAX_HARNESS_REQUEST_BODY_BYTES + 1), str(root / "missing.crt"),
                    str(evidence),
                )
            self.assertFalse(evidence.exists())

            class OverflowResponse:
                status = 200
                headers = {"content-type": "text/plain"}

                def __init__(self) -> None:
                    self.read_amount: int | None = None

                def read(self, amount: int | None = None) -> bytes:
                    self.read_amount = amount
                    assert amount is not None
                    return b"x" * amount

                def close(self) -> None:
                    return None

            class OverflowConnection:
                def __init__(self, response: OverflowResponse) -> None:
                    self.response = response

                def request(self, *args: object, **kwargs: object) -> None:
                    del args, kwargs

                def getresponse(self) -> OverflowResponse:
                    return self.response

                def close(self) -> None:
                    return None

            response = OverflowResponse()
            connection = OverflowConnection(response)
            with (
                mock.patch.object(HELPER, "trusted_loopback_tls_context", return_value=object()),
                mock.patch.object(HELPER.http.client, "HTTPSConnection", return_value=connection),
            ):
                with self.assertRaisesRegex(ValueError, "response body exceeds"):
                    HELPER.probe(
                        str(root), "https://127.0.0.1:1/", [], "GET", None,
                        str(root / "missing.crt"), str(evidence),
                    )
            self.assertEqual(response.read_amount, HELPER.MAX_HARNESS_RESPONSE_BODY_BYTES + 1)
            self.assertFalse(evidence.exists())

    def test_streaming_probe_rejects_cumulative_response_overflow(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            release = root / "release"
            first_byte = root / "first-byte.json"
            evidence = root / "streaming-probe.json"
            release.touch()

            class OverflowResponse:
                status = 200

                def __init__(self) -> None:
                    self.read_count = 0

                def read(self, amount: int | None = None) -> bytes:
                    self.read_count += 1
                    if self.read_count == 1:
                        return b"x"
                    if self.read_count <= 9:
                        assert amount == 8192
                        return b"x" * 8192
                    return b""

                def getheader(self, name: str, default: object = None) -> object:
                    del name
                    return default

                def close(self) -> None:
                    return None

            class OverflowConnection:
                def __init__(self, response: OverflowResponse) -> None:
                    self.response = response

                def request(self, *args: object, **kwargs: object) -> None:
                    del args, kwargs

                def getresponse(self) -> OverflowResponse:
                    return self.response

                def close(self) -> None:
                    return None

            with (
                mock.patch.object(HELPER, "trusted_loopback_tls_context", return_value=object()),
                mock.patch.object(
                    HELPER.http.client, "HTTPSConnection", return_value=OverflowConnection(OverflowResponse()),
                ),
            ):
                with self.assertRaisesRegex(ValueError, "response body exceeds"):
                    HELPER.streaming_probe(
                        str(root), "https://127.0.0.1:1/", str(release), str(first_byte),
                        str(evidence), str(root / "missing.crt"), 1.0,
                    )
            self.assertTrue(first_byte.is_file())
            self.assertFalse(evidence.exists())

    def test_allow_event_binds_completed_client_and_upstream_transaction(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            events = root / "events.jsonl"
            probe = root / "client-probe.json"
            upstream = root / "upstream-requests.jsonl"
            probe.write_text(
                json.dumps({"status": 200, "response_bytes": 24, "content_type": "text/plain"}),
                encoding="utf-8",
            )
            upstream.write_text(
                json.dumps({
                    "method": "GET",
                    "response_status": 200,
                    "profile": "ordinary",
                    "request_id": "haproxy-htx-allow",
                }) + "\n",
                encoding="utf-8",
            )
            self.assertEqual(
                HELPER.write_allow_event(
                    str(root), str(events), str(probe), str(upstream), "haproxy-htx-allow",
                ),
                0,
            )
            record = json.loads(events.read_text(encoding="utf-8"))
            self.assertEqual(record["message_id"], "HAPROXY_HTX_NATIVE_P1_ALLOW")
            self.assertEqual(record["transaction_id"], "haproxy-htx-allow")
            self.assertEqual(record["phase"], 1)
            self.assertEqual(record["status"], "allowed")
            self.assertEqual(record["visible_http_status"], 200)
            self.assertNotIn("requested_action", record)
            self.assertNotIn("actual_action", record)
            schema = json.loads((
                EVENT_SCHEMA_PATH
            ).read_text(encoding="utf-8"))
            self.assertTrue(set(record).issubset(set(schema["properties"])))
            self.assertTrue(set(record).issubset(COLLECTOR.APPROVED_RAW_EVENT_KEYS))
            self.assertNotIn("no-crs-request-body-marker", events.read_text(encoding="utf-8"))

    def test_allow_event_rejects_noncausal_or_nonallow_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            events = root / "events.jsonl"
            probe = root / "client-probe.json"
            upstream = root / "upstream-requests.jsonl"
            probe.write_text(
                json.dumps({"status": 403, "response_bytes": 24, "content_type": "text/plain"}),
                encoding="utf-8",
            )
            upstream.write_text(
                json.dumps({
                    "profile": "ordinary", "request_id": "haproxy-htx-allow",
                }) + "\n",
                encoding="utf-8",
            )
            events_path = str(events)
            probe_path = str(probe)
            upstream_path = str(upstream)
            runtime_root = str(root)
            allow_transaction_id = "haproxy-htx-allow"
            with self.assertRaisesRegex(ValueError, "preserve HTTP 200"):
                HELPER.write_allow_event(
                    runtime_root, events_path, probe_path, upstream_path, allow_transaction_id,
                )

            probe.write_text(
                json.dumps({"status": 200, "response_bytes": 24, "content_type": "text/plain"}),
                encoding="utf-8",
            )
            upstream.write_text(
                json.dumps({"profile": "ordinary", "request_id": "wrong-id"}) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "not observed exactly once upstream"):
                HELPER.write_allow_event(
                    runtime_root, events_path, probe_path, upstream_path, allow_transaction_id,
                )
            invalid_transaction_id = "haproxy:htx-allow"
            with self.assertRaisesRegex(ValueError, "invalid HTX transaction id"):
                HELPER.write_allow_event(
                    runtime_root, events_path, probe_path, upstream_path, invalid_transaction_id,
                )

    def test_first_byte_evidence_binds_client_byte_to_paused_upstream(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paused = root / "upstream-paused.json"
            client = root / "client-first-byte.json"
            evidence = root / "first-byte-evidence.json"
            paused.write_text(
                json.dumps({
                    "schema_version": 1,
                    "evidence_type": "synchronized_upstream_paused",
                    "first_chunk_size": 37,
                    "upstream_paused": True,
                    "upstream_eos_sent": False,
                    "body_payload_persisted": False,
                }),
                encoding="utf-8",
            )
            client.write_text(
                json.dumps({
                    "status": 200,
                    "client_first_byte_received": True,
                    "first_chunk_size": 1,
                    "response_committed": True,
                    "body_payload_persisted": False,
                }),
                encoding="utf-8",
            )
            self.assertEqual(
                HELPER.write_first_byte_evidence(
                    str(root), str(evidence), str(paused), str(client),
                ),
                0,
            )
            record = json.loads(evidence.read_text(encoding="utf-8"))
            self.assertEqual(record["evidence_origin"], "real_host")
            self.assertTrue(record["promotion_eligible"])
            self.assertTrue(record["client_first_byte_received"])
            self.assertTrue(record["upstream_paused"])
            self.assertFalse(record["upstream_eos_sent_at_first_byte"])
            self.assertFalse(record["upstream_response_finished_at_first_byte"])
            self.assertTrue(record["no_full_response_buffering"])
            self.assertFalse(record["connector_owned_full_response_buffer"])
            self.assertEqual(record["body_bytes_seen"], 37)
            self.assertEqual(record["body_bytes_inspected"], 37)
            self.assertEqual(
                SYNCHRONIZED_UPSTREAM.first_byte_evidence_errors(
                    record, require_real_host=True, require_complete_proof=True,
                ),
                [],
            )
            self.assertNotIn("no-crs-response-body-marker", evidence.read_text(encoding="utf-8"))
            outside = root / "other-case"
            outside.mkdir()
            outside_client = outside / "client-first-byte.json"
            outside_client.write_text(client.read_text(encoding="utf-8"), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "share one private case root"):
                HELPER.write_first_byte_evidence(
                    str(root), str(evidence), str(paused), str(outside_client),
                )

    def test_phase4_safe_event_requires_real_barrier_and_native_late_decision(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            events = root / "events.jsonl"
            decision_log = root / "haproxy.stderr.log"
            probe = root / "client-probe.json"
            first_byte = root / "first-byte-evidence.json"
            decision_log.write_text(
                "modsecurity-htx: response-body late intervention observed; "
                "transaction_id=haproxy-htx-phase4 phase=4 status=403 "
                "rule_id=1100301 requested_action=deny "
                "resolved_policy_action=log_only host_action=log_only\n",
                encoding="utf-8",
            )
            probe.write_text(
                json.dumps({"status": 200, "response_bytes": 81, "content_type": "text/plain"}),
                encoding="utf-8",
            )
            first_byte.write_text(
                json.dumps({
                    "schema_version": 1,
                    "evidence_type": "synchronized_first_byte",
                    "evidence_origin": "real_host",
                    "promotion_eligible": True,
                    "client_first_byte_received": True,
                    "first_byte_before_response_end": True,
                    "first_chunk_size": 19,
                    "upstream_paused": True,
                    "upstream_eos_sent_at_first_byte": False,
                    "upstream_response_finished_at_first_byte": False,
                    "response_committed": True,
                    "body_bytes_seen": 19,
                    "body_bytes_inspected": 19,
                    "no_full_response_buffering": True,
                    "connector_owned_full_response_buffer": False,
                    "body_payload_persisted": False,
                    "outcome": "PASS",
                }),
                encoding="utf-8",
            )
            outside = root / "other-case"
            outside.mkdir()
            outside_first_byte = outside / "first-byte-evidence.json"
            outside_first_byte.write_text(first_byte.read_text(encoding="utf-8"), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "share one private case root"):
                HELPER.phase4_safe_event(
                    str(root), str(events), str(decision_log), str(probe),
                    str(outside_first_byte), "run-42", "phase4_first_byte_before_response_end",
                )
            self.assertEqual(
                HELPER.phase4_safe_event(
                    str(root),
                    str(events),
                    str(decision_log),
                    str(probe),
                    str(first_byte),
                    "run-42",
                    "phase4_first_byte_before_response_end",
                ),
                0,
            )
            record = json.loads(events.read_text(encoding="utf-8"))
            self.assertEqual(record["integration_mode"], "native-htx-filter")
            self.assertEqual(record["transaction_id"], "haproxy-htx-phase4")
            self.assertEqual(record["phase"], 4)
            self.assertEqual(record["rule_id"], 1100301)
            self.assertEqual(record["requested_action"], "deny")
            self.assertEqual(record["actual_action"], "log_only")
            self.assertEqual(record["visible_http_status"], 200)
            self.assertTrue(record["late_intervention"])
            self.assertTrue(record["eos_seen"])
            self.assertTrue(record["end_of_stream_evaluation"])
            self.assertTrue(record["first_byte_before_response_end"])
            self.assertTrue(record["no_full_response_buffering"])
            self.assertNotIn("connector_owned_full_response_buffer", record)
            schema = json.loads((
                EVENT_SCHEMA_PATH
            ).read_text(encoding="utf-8"))
            self.assertTrue(set(record).issubset(set(schema["properties"])))
            self.assertTrue(set(record).issubset(COLLECTOR.APPROVED_RAW_EVENT_KEYS))
            self.assertNotIn("no-crs-response-body-marker", events.read_text(encoding="utf-8"))



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
