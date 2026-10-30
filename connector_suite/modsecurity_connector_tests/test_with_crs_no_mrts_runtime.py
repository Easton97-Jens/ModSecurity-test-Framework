"""Focused behavioral contracts for Parent CRS/no-MRTS runtime evidence."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import ast
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = connector_root()
RUNNER_PATH = source_path('ci/runtime/lifecycle/run-with-crs-no-mrts.sh', root=ROOT)
NORMALIZER_PATH = source_path('ci/runtime/lifecycle/normalize-with-crs-no-mrts.py', root=ROOT)
SUMMARY_PATH = source_path('ci/runtime/lifecycle/summarize-with-crs-no-mrts-workflow.py', root=ROOT)
UPLOAD_PREPARER_PATH = source_path('ci/runtime/lifecycle/prepare-with-crs-no-mrts-upload.py', root=ROOT)


def load_normalizer():
    module = load_source(NORMALIZER_PATH)
    return module


NORMALIZER = load_normalizer()


def load_summary():
    module = load_source(SUMMARY_PATH)
    return module


SUMMARY = load_summary()
NO_MRTS = {
    "runner_invoked": False,
    "case_inventory_loaded": False,
    "process_started": False,
    "socket_or_listener_created": False,
    "artifact_used": False,
}


def private_file(path: Path, content: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, str):
        path.write_text(content, encoding="utf-8")
    else:
        path.write_bytes(content)
    path.chmod(0o600)


def private_json(path: Path, value: object) -> None:
    private_file(path, json.dumps(value, sort_keys=True) + "\n")


def read_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError(f"expected object fixture: {path}")
    return value


class WithCrsNoMrtsRuntimeContractTest(unittest.TestCase):
    def run_upload_preparer(
        self, root: Path, connector: str, run_id: str, parent_sha: str, outcome: str
    ) -> subprocess.CompletedProcess[str]:
        receipt = root / "failure-receipt.json"
        return subprocess.run(
            [
                sys.executable,
                "-I",
                str(UPLOAD_PREPARER_PATH),
                "--connector",
                connector,
                "--run-id",
                run_id,
                "--parent-sha",
                parent_sha,
                "--verified-root",
                str(root),
                "--receipt",
                str(receipt),
                "--runtime-outcome",
                outcome,
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

    def make_generic_pass_evidence(
        self, root: Path, connector: str, run_id: str, parent_sha: str
    ) -> None:
        # Produce the same complete canonical observation that the helper
        # receives from the Parent normalizer.  A minimal JSON PASS marker is
        # intentionally no longer a valid success fixture.
        if parent_sha != "b" * 40:
            raise AssertionError("normalizer fixture Parent SHA is fixed")
        runtime = root / "runtime"
        self.make_observation(runtime, connector=connector)
        if connector == "envoy":
            self.make_envoy_host_evidence(runtime)
            summary = runtime / "runtime-summary.txt"
            private_file(
                summary,
                summary.read_text(encoding="utf-8").replace("run_id=envoy-run", f"run_id={run_id}"),
            )
        elif connector == "traefik":
            self.make_traefik_host_evidence(runtime)
            result = read_json(runtime / "result.json")
            result["run_id"] = run_id
            private_json(runtime / "result.json", result)
        elif connector == "lighttpd":
            self.make_lighttpd_host_evidence(runtime, run_id=run_id)
        else:
            raise AssertionError(connector)
        self.normalize(connector, root, runtime, run_id=run_id)

    def test_failed_generic_runtime_retains_bounded_payload_free_receipt(self) -> None:
        with tempfile.TemporaryDirectory(prefix="crs-upload-failure-") as temporary:
            root = Path(temporary)
            result = self.run_upload_preparer(root, "lighttpd", "run-1", "a" * 40, "failure")
            self.assertEqual(result.returncode, 0, result.stderr)
            receipt = read_json(root / "failure-receipt.json")
            self.assertEqual(receipt["record_type"], "crs_no_mrts_runtime_failure_receipt")
            self.assertEqual(receipt["connector"], "lighttpd")
            self.assertEqual(receipt["run_id"], "run-1")
            self.assertEqual(receipt["connector_commit"], "a" * 40)
            self.assertEqual(receipt["evidence_status"], "not_available")
            self.assertLess((root / "failure-receipt.json").stat().st_size, 4096)
            self.assertNotIn("payload", receipt)

    def test_failed_generic_runtime_rejects_a_stale_failure_receipt(self) -> None:
        with tempfile.TemporaryDirectory(prefix="crs-upload-stale-receipt-") as temporary:
            root = Path(temporary)
            first = self.run_upload_preparer(root, "lighttpd", "run-1", "a" * 40, "failure")
            self.assertEqual(first.returncode, 0, first.stderr)
            second = self.run_upload_preparer(root, "lighttpd", "run-1", "a" * 40, "failure")
            self.assertEqual(second.returncode, 1)
            self.assertIn("unable to retain", second.stderr)

    def test_failed_generic_runtime_rejects_a_symlinked_root(self) -> None:
        with tempfile.TemporaryDirectory(prefix="crs-upload-root-symlink-") as temporary:
            parent = Path(temporary)
            target = parent / "target"
            target.mkdir(mode=0o700)
            root = parent / "root-alias"
            root.symlink_to(target, target_is_directory=True)
            result = self.run_upload_preparer(root, "lighttpd", "run-1", "a" * 40, "failure")
            self.assertEqual(result.returncode, 1)
            self.assertIn("unsafe runtime evidence root", result.stderr)
            self.assertFalse((target / "failure-receipt.json").exists())

    def test_failed_generic_runtime_rejects_a_symlinked_root_ancestor(self) -> None:
        with tempfile.TemporaryDirectory(prefix="crs-upload-ancestor-symlink-") as temporary:
            parent = Path(temporary)
            outside = parent / "outside"
            target = outside / "verified"
            target.mkdir(parents=True, mode=0o700)
            alias = parent / "outside-alias"
            alias.symlink_to(outside, target_is_directory=True)
            result = self.run_upload_preparer(
                alias / "verified", "lighttpd", "run-1", "a" * 40, "failure"
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("unsafe runtime evidence root", result.stderr)
            self.assertFalse((target / "failure-receipt.json").exists())

    def test_generic_upload_accepts_current_bound_pass_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="crs-upload-pass-") as temporary:
            root = Path(temporary)
            self.make_generic_pass_evidence(root, "lighttpd", "run-1", "b" * 40)
            result = self.run_upload_preparer(root, "lighttpd", "run-1", "b" * 40, "success")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((root / "failure-receipt.json").exists())

    def test_non_successful_generic_runtime_retains_only_a_failure_receipt(self) -> None:
        with tempfile.TemporaryDirectory(prefix="crs-upload-late-failure-") as temporary:
            root = Path(temporary)
            self.make_generic_pass_evidence(root, "traefik", "run-1", "b" * 40)
            result = self.run_upload_preparer(root, "traefik", "run-1", "b" * 40, "failure")
            self.assertEqual(result.returncode, 0, result.stderr)
            receipt = read_json(root / "failure-receipt.json")
            self.assertEqual(receipt["connector"], "traefik")
            self.assertEqual(receipt["runtime_outcome"], "failure")

    def test_non_successful_apache_runtime_retains_a_failure_receipt(self) -> None:
        with tempfile.TemporaryDirectory(prefix="crs-upload-apache-failure-") as temporary:
            root = Path(temporary)
            result = self.run_upload_preparer(root, "apache", "run-1", "a" * 40, "failure")
            self.assertEqual(result.returncode, 0, result.stderr)
            receipt = read_json(root / "failure-receipt.json")
            self.assertEqual(receipt["connector"], "apache")
            self.assertEqual(receipt["runtime_outcome"], "failure")

    def test_generic_upload_rejects_mismatched_pass_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="crs-upload-mismatch-") as temporary:
            root = Path(temporary)
            self.make_generic_pass_evidence(root, "envoy", "run-1", "b" * 40)
            result = self.run_upload_preparer(root, "envoy", "run-1", "a" * 40, "success")
            self.assertEqual(result.returncode, 1)
            self.assertIn("binding", result.stderr)
            self.assertFalse((root / "failure-receipt.json").exists())

    def workflow_outcomes(self, **overrides: str) -> dict[str, str]:
        outcomes = {stage: "success" for stage, _label, _environment_name in SUMMARY.STAGES}
        outcomes.update(overrides)
        return outcomes

    def test_workflow_summary_counts_actual_haproxy_evidence_upload(self) -> None:
        summary = SUMMARY.render_summary("haproxy", self.workflow_outcomes())
        self.assertIn("| Stages passed | `10` |", summary)
        self.assertIn("| Stages failed | `0` |", summary)
        self.assertIn("| Security-policy skips | `0` |", summary)
        self.assertIn("| Evidence publication | `success` |", summary)
        self.assertIn("| First non-passing stage | `none` |", summary)

    def test_workflow_summary_treats_skipped_haproxy_upload_as_nonpassing(self) -> None:
        summary = SUMMARY.render_summary(
            "haproxy", self.workflow_outcomes(upload_evidence="skipped")
        )
        self.assertIn("| Stages passed | `9` |", summary)
        self.assertIn("| Stages skipped | `1` |", summary)
        self.assertIn("| Security-policy skips | `0` |", summary)
        self.assertIn("| Evidence publication | `skipped` |", summary)
        self.assertIn("| First non-passing stage | `Evidence publication` |", summary)

    def test_workflow_summary_exposes_failed_runtime_without_promoting_capability(self) -> None:
        summary = SUMMARY.render_summary(
            "lighttpd", self.workflow_outcomes(runtime="failure", upload_evidence="skipped")
        )
        self.assertIn("| Stages failed | `1` |", summary)
        self.assertIn("| First non-passing stage | `Real connector runtime target` |", summary)
        self.assertIn("| Real connector runtime target | `failure` |", summary)
        self.assertIn("`FAIL — runtime assertions did not complete`", summary)
        self.assertNotIn("skipped_by_security_policy", summary)

    def test_workflow_summary_rejects_missing_outcome(self) -> None:
        environment = {
            environment_name: "success" for _stage, _label, environment_name in SUMMARY.STAGES
        }
        environment.pop("RUNTIME_OUTCOME")
        with self.assertRaisesRegex(ValueError, "RUNTIME_OUTCOME"):
            SUMMARY.outcomes_from_environment(environment)

    def test_workflow_summary_requires_a_runner_owned_step_summary_file(self) -> None:
        with tempfile.TemporaryDirectory(prefix="crs-workflow-summary-runner-") as temporary:
            root = Path(temporary)
            runner_temp = root / "runner-temp"
            summary_directory = runner_temp / "_runner_file_commands"
            summary_directory.mkdir(parents=True)
            target = summary_directory / "step_summary_abc123"
            target.touch()
            target.chmod(0o600)
            environment = {
                **{
                    environment_name: "success"
                    for _stage, _label, environment_name in SUMMARY.STAGES
                },
                "RUNNER_TEMP": str(runner_temp),
                "GITHUB_STEP_SUMMARY": str(target),
            }
            SUMMARY.append_github_step_summary(environment, "first\n")
            self.assertEqual(target.read_text(encoding="utf-8"), "first\n")
            with mock.patch.dict(SUMMARY.os.environ, environment, clear=True):
                self.assertEqual(SUMMARY.main(["--connector", "apache"]), 0)
            self.assertIn("### apache", target.read_text(encoding="utf-8"))

            outside = root / "outside.md"
            outside.touch()
            outside.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "path is unsafe"):
                SUMMARY.append_github_step_summary(
                    {**environment, "GITHUB_STEP_SUMMARY": str(outside)}, "must-not-write\n"
                )
            with self.assertRaisesRegex(ValueError, "path is unsafe"):
                SUMMARY.append_github_step_summary(
                    {
                        **environment,
                        "GITHUB_STEP_SUMMARY": str(
                            summary_directory / ".." / "step_summary_abc123"
                        ),
                    },
                    "must-not-write\n",
                )
            target.unlink()
            target.symlink_to(outside)
            with self.assertRaisesRegex(ValueError, "path is unsafe"):
                SUMMARY.append_github_step_summary(environment, "must-not-follow\n")
            with mock.patch.object(SUMMARY.os, "O_NOFOLLOW", None):
                with self.assertRaisesRegex(ValueError, "safe-open capability"):
                    SUMMARY.append_github_step_summary(environment, "must-not-write\n")
            with mock.patch.object(SUMMARY.os, "O_NONBLOCK", None):
                with self.assertRaisesRegex(ValueError, "safe-open capability"):
                    SUMMARY.append_github_step_summary(environment, "must-not-write\n")

    def run_runner(
        self, connector: str, run_id: str = "valid-run", *, environment: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["sh", str(RUNNER_PATH), connector, run_id],
            cwd=ROOT,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def make_framework_and_source(self, root: Path) -> tuple[Path, Path]:
        framework = root / "framework"
        rule = b'SecRule ARGS "@rx union" "id:942270,phase:2,deny,status:403"\n'
        digest = hashlib.sha256(rule).hexdigest()
        private_file(
            framework / "ci/lib/common.sh",
            "\n".join(
                (
                    'CRS_APPROVED_REPO_URL="https://github.com/coreruleset/coreruleset.git"',
                    'CRS_RELEASE_TAG="v-test"',
                    'CRS_APPROVED_COMMIT="' + "a" * 40 + '"',
                    'CRS_RULE_FILE_SHA256="' + digest + '"',
                )
            )
            + "\n",
        )
        source = root / "source"
        private_file(source / "coreruleset" / NORMALIZER.RULE_FILE, rule)
        return framework, source

    def make_observation(
        self,
        runtime: Path,
        *,
        connector: str = "envoy",
        no_mrts: dict[str, bool] | None = None,
    ) -> None:
        modes = {
            "envoy": "ext_proc",
            "traefik": "native-traefik-middleware",
            "lighttpd": "patched-native-lighttpd",
        }
        private_json(
            runtime / "runtime-observation.json",
            {
                "status": "PASS",
                "cleanup_status": "PASS",
                # Unit-only input to exercise the Parent normalizer's Traefik
                # cleanup contract. This is never emitted by a host harness.
                "external_socket_parent_cleanup": (
                    "verified" if connector == "traefik" else "not-applicable"
                ),
                "no_mrts": NO_MRTS if no_mrts is None else no_mrts,
                "cleanup": {
                    "processes_remaining": 0,
                    "host_processes_remaining": 0,
                    "helper_processes_remaining": 0,
                    "listeners_remaining": 0,
                    "sockets_remaining": 0,
                    "pid_files_remaining": 0,
                    "runtime_fixtures_remaining": 0,
                    "temporary_paths_remaining": 0,
                    "paths": [],
                    "listener_records": [],
                },
                "dispatch": {
                    "source": "parent-runner",
                    "connector": connector,
                    "integration_mode": modes[connector],
                    "test_variant": "with-crs",
                    "mrts_variant": "no-mrts",
                },
            },
        )

    def make_envoy_host_evidence(self, runtime: Path, *, final_visible: bool = True) -> None:
        private_file(
            runtime / "runtime-summary.txt",
            "status=PASS\nconnector=envoy\nintegration_mode=ext_proc\nrun_id=envoy-run\n"
            "config_test_status=PASS\nhost_start_status=PASS\nreachability_status=PASS\n"
            "cleanup_status=PASS\nallow_request_id=allow-envoy\nblock_request_id=block-envoy\n"
            "bypass_request_id=bypass-envoy\nallow_observed_status=200\nblock_observed_status=403\n"
            "bypass_observed_status=403\nblock_trigger_rule_id=942270\n"
            "bypass_trigger_rule_id=942270\nblock_intervention_rule_id=949110\n"
            "bypass_intervention_rule_id=949110\nblock_observed_action=deny\n"
            "bypass_observed_action=deny\n",
        )
        private_json(runtime / "crs-allow-probe.json", {"http_status": 200})
        private_json(runtime / "crs-block-probe.json", {"http_status": 403})
        private_json(runtime / "crs-bypass-probe.json", {"http_status": 403})
        private_file(
            runtime / "ext-proc.stderr.log",
            '[unique_id "block-envoy"] [id "942270"]\n'
            '[unique_id "bypass-envoy"] [id "942270"]\n',
        )
        events: list[dict[str, object]] = []
        for transaction_id in ("block-envoy", "bypass-envoy"):
            # Common emits a decision event and then the host-action
            # completion. Both are denials, but only the latter proves the
            # status visible through Envoy's real response path.
            events.append(
                {
                    "connector": "envoy",
                    "integration_mode": "ext_proc",
                    "transaction_id": transaction_id,
                    "actual_action": "deny",
                    "http_status": 403,
                    "visible_http_status": 0,
                    "transport_result": "pending_host_action",
                    "rule_id": "949110",
                }
            )
            events.append(
                {
                    "connector": "envoy",
                    "integration_mode": "ext_proc",
                    "transaction_id": transaction_id,
                    "actual_action": "deny",
                    "http_status": 403,
                    "visible_http_status": 403 if final_visible else 0,
                    "transport_result": "http_status" if final_visible else "pending_host_action",
                    "rule_id": "949110",
                }
            )
        private_file(runtime / "events.jsonl", "".join(json.dumps(event) + "\n" for event in events))
        private_file(
            runtime / "completion-events.jsonl",
            json.dumps(
                {
                    "event": "ext_proc_stream_complete",
                    "integration_mode": "ext_proc",
                    "transaction_id": "allow-envoy",
                    "evaluation_mode": "common_libmodsecurity_nonpromoted",
                    "rule_evaluation": "libmodsecurity",
                    "late_action": "none",
                    "close_reason": "response_end_of_stream",
                    "response_body_bytes": 1,
                }
            )
            + "\n",
        )

    def make_traefik_host_evidence(self, runtime: Path) -> None:
        block_event = {
            "connector": "traefik",
            "integration_mode": "native-traefik-middleware",
            "transaction_id": "block-traefik",
            "actual_action": "deny",
            "visible_http_status": 403,
            "transport_result": "http_status",
            "rule_id": 949110,
        }
        bypass_event = {
            "connector": "traefik",
            "integration_mode": "native-traefik-middleware",
            "transaction_id": "bypass-traefik",
            "actual_action": "deny",
            "visible_http_status": 403,
            "transport_result": "http_status",
            "rule_id": 949110,
        }
        private_json(
            runtime / "result.json",
            {
                "status": "PASS",
                "connector": "traefik",
                "integration_mode": "native-traefik-middleware",
                "run_id": "traefik-run",
                "config_test_status": "PASS",
                "host_start_status": "PASS",
                "reachability_status": "PASS",
                "cleanup_status": "PASS",
                "allow": {"status": 200, "request_id": "allow-traefik"},
                "block": {
                    "status": 403,
                    "request_id": "block-traefik",
                    "trigger_rule_id": 942270,
                    "intervention_rule_id": 949110,
                    "observed_action": "deny",
                    "observed_event": block_event,
                },
                "bypass": {
                    "status": 403,
                    "request_id": "bypass-traefik",
                    "trigger_rule_id": 942270,
                    "intervention_rule_id": 949110,
                    "observed_action": "deny",
                    "observed_event": bypass_event,
                },
            },
        )
        private_file(
            runtime / "logs/engine.stderr.log",
            '[unique_id "block-traefik"] [id "942270"]\n'
            '[unique_id "bypass-traefik"] [id "942270"]\n',
        )
        private_file(
            runtime / "logs/events.jsonl",
            json.dumps(block_event) + "\n" + json.dumps(bypass_event) + "\n",
        )

    @staticmethod
    def make_lighttpd_curl_trace(request_lines: list[str]) -> str:
        """Render curl --trace-ascii header rows with real 64-byte offsets."""
        offset = 0
        rows: list[tuple[int, str]] = []
        for logical_line in request_lines:
            fragments = [logical_line[index:index + 64] for index in range(0, len(logical_line), 64)] or [""]
            for index, fragment in enumerate(fragments):
                rows.append((offset, fragment))
                offset += len(fragment)
                if index == len(fragments) - 1:
                    # curl does not display CRLF but preserves its two bytes
                    # in the next logical offset.
                    offset += 2
        return (
            "*   Trying 127.0.0.1:8080...\n"
            "* Established connection to 127.0.0.1 (127.0.0.1 port 8080)\n"
            f"=> Send header, {offset} bytes (0x{offset:x})\n"
            + "".join(f"{row_offset:04x}: {fragment}\n" for row_offset, fragment in rows)
            + "* Request completely sent off\n"
        )

    def make_lighttpd_wire_evidence(
        self,
        runtime: Path,
        *,
        request_ids: dict[str, str],
        transaction_ids: dict[str, str],
        run_id: str,
    ) -> dict[str, Path]:
        """Create strict, harness-shaped private curl/header evidence."""
        wire_root = runtime / "crs-request-evidence"
        wire_root.mkdir(parents=True, mode=0o700)
        wire_root.chmod(0o700)
        uris = {
            "allow": "/?id=42",
            "block": "/?id=1%20UNION%20SELECT",
            "bypass": "/?id=1%20uNiOn%20SeLeCt",
        }
        statuses = {"allow": (200, "OK"), "block": (403, "Forbidden"), "bypass": (403, "Forbidden")}
        paths: dict[str, Path] = {}
        for case in ("allow", "block", "bypass"):
            trace_path = wire_root / f"{case}.curl.trace"
            headers_path = wire_root / f"{case}.response.headers"
            private_file(
                trace_path,
                self.make_lighttpd_curl_trace(
                    [
                        f"GET {uris[case]} HTTP/1.1",
                        "Host: crs-runtime.test",
                        f"X-Framework-Run-ID: {run_id}",
                        f"X-Framework-Request-ID: {request_ids[case]}",
                        "Accept: */*",
                        "",
                    ]
                ),
            )
            status, phrase = statuses[case]
            private_file(
                headers_path,
                f"HTTP/1.1 {status} {phrase}\r\n"
                f"X-Msconnector-Host-Transaction-Id: {transaction_ids[case]}\r\n"
                "Content-Length: 0\r\n\r\n",
            )
            paths[f"{case}_request_trace"] = trace_path
            paths[f"{case}_response_headers"] = headers_path
        return paths

    def make_lighttpd_host_evidence(
        self,
        runtime: Path,
        *,
        reuse_request_ids_as_transactions: bool = False,
        run_id: str = "lighttpd-run",
        request_ids_override: dict[str, str] | None = None,
    ) -> None:
        request_ids = (
            dict(request_ids_override)
            if request_ids_override is not None
            else {
                "allow": "allow-request-lighttpd",
                "block": "block-request-lighttpd",
                "bypass": "bypass-request-lighttpd",
            }
        )
        if set(request_ids) != {"allow", "block", "bypass"}:
            raise AssertionError("Lighttpd request fixture requires allow/block/bypass labels")
        block_request_id = request_ids["block"]
        bypass_request_id = request_ids["bypass"]
        transaction_ids = {
            "allow": "lighttpd-1-101",
            "block": "lighttpd-1-102",
            "bypass": "lighttpd-1-103",
        }
        if reuse_request_ids_as_transactions:
            transaction_ids["block"] = block_request_id
            transaction_ids["bypass"] = bypass_request_id
        # The reported Common IDs are wire-derived and must be the exact host
        # IDs returned by the response headers.
        block_transaction_id = transaction_ids["block"]
        bypass_transaction_id = transaction_ids["bypass"]
        wire_paths = self.make_lighttpd_wire_evidence(
            runtime,
            request_ids=request_ids,
            transaction_ids=transaction_ids,
            run_id=run_id,
        )
        private_file(
            runtime / "runtime-summary.txt",
            "status=PASS\nconnector=lighttpd\nintegration_mode=patched-native-lighttpd\n"
            f"run_id={run_id}\n"
            "config_test_status=PASS\nhost_start_status=PASS\nreachability_status=PASS\n"
            "cleanup_status=PASS\n"
            f"allow_request_id={request_ids['allow']}\nallow_transaction_id={transaction_ids['allow']}\n"
            f"allow_response_transaction_id={transaction_ids['allow']}\n"
            "allow_request_uri=/?id=42\n"
            f"block_request_id={block_request_id}\nblock_transaction_id={block_transaction_id}\n"
            f"block_response_transaction_id={transaction_ids['block']}\n"
            "block_request_uri=/?id=1%20UNION%20SELECT\n"
            f"bypass_request_id={bypass_request_id}\nbypass_transaction_id={bypass_transaction_id}\n"
            f"bypass_response_transaction_id={transaction_ids['bypass']}\n"
            "bypass_request_uri=/?id=1%20uNiOn%20SeLeCt\n"
            "response_transaction_header_name=X-Msconnector-Host-Transaction-Id\n"
            "response_transaction_header_origin=server_generated_lighttpd_host\n"
            "allow_request_status=200\nblock_request_status=403\nbypass_request_status=403\n"
            "block_trigger_rule_id=942270\nbypass_trigger_rule_id=942270\n"
            "block_intervention_rule_id=949110\nbypass_intervention_rule_id=949110\n"
            "block_observed_action=deny\nbypass_observed_action=deny\n"
            f"allow_request_trace={wire_paths['allow_request_trace']}\n"
            f"allow_response_headers={wire_paths['allow_response_headers']}\n"
            f"block_request_trace={wire_paths['block_request_trace']}\n"
            f"block_response_headers={wire_paths['block_response_headers']}\n"
            f"bypass_request_trace={wire_paths['bypass_request_trace']}\n"
            f"bypass_response_headers={wire_paths['bypass_response_headers']}\n",
        )
        private_file(
            runtime / "events.jsonl",
            json.dumps(
                {
                    "connector": "lighttpd",
                    "integration_mode": "patched-native-lighttpd",
                    "request_id": block_request_id,
                    "transaction_id": block_transaction_id,
                    "method": "GET",
                    "rule_id": 949110,
                    "status": "blocked",
                    "actual_action": "deny",
                    "http_status": 403,
                    "visible_http_status": 403,
                    "transport_result": "http_status",
                    "uri": "/?<redacted>",
                    "redacted": True,
                }
            )
            + "\n"
            + json.dumps(
                {
                    "connector": "lighttpd",
                    "integration_mode": "patched-native-lighttpd",
                    "request_id": bypass_request_id,
                    "transaction_id": bypass_transaction_id,
                    "method": "GET",
                    "rule_id": 949110,
                    "status": "blocked",
                    "actual_action": "deny",
                    "http_status": 403,
                    "visible_http_status": 403,
                    "transport_result": "http_status",
                    "uri": "/?<redacted>",
                    "redacted": True,
                }
            )
            + "\n",
        )
        private_file(
            runtime / "runtime-smoke.stderr",
            f'[unique_id "{transaction_ids["block"]}"] [id "942270"]\n'
            f'[unique_id "{transaction_ids["bypass"]}"] [id "942270"]\n',
        )

    def populate_host_evidence(self, connector: str, runtime: Path) -> None:
        if connector == "envoy":
            self.make_envoy_host_evidence(runtime)
        elif connector == "traefik":
            self.make_traefik_host_evidence(runtime)
        elif connector == "lighttpd":
            self.make_lighttpd_host_evidence(runtime)
        else:
            raise AssertionError(connector)

    def normalize(
        self,
        connector: str,
        root: Path,
        runtime: Path,
        *,
        run_id: str | None = None,
    ) -> tuple[Path, Path]:
        framework, source = self.make_framework_and_source(root)
        evidence = root / "evidence"
        if not evidence.exists():
            evidence.mkdir(mode=0o700)
        args = SimpleNamespace(
            connector=connector,
            run_id=run_id or f"{connector}-run",
            runtime_root=runtime,
            evidence_root=evidence,
            source_root=source,
            connector_root=root / "parent",
            framework_root=framework,
        )
        with mock.patch.object(
            NORMALIZER,
            "commit_identity",
            side_effect=("b" * 40, "c" * 40, "d" * 40),
        ):
            event = NORMALIZER.normalize(args)
        return event, evidence

    def framework_raw_record(self, path: Path) -> dict[str, str]:
        fields: dict[str, str] = {}
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            name, separator, value = line.partition("=")
            self.assertTrue(separator, f"missing '=' in {path} line {line_number}")
            self.assertTrue(name, f"missing key in {path} line {line_number}")
            self.assertTrue(value, f"missing value in {path} line {line_number}")
            self.assertNotIn(name, fields, f"duplicate key in {path} line {line_number}")
            fields[name] = value
        return fields

    def test_closed_dispatcher_rejects_every_unlisted_connector_before_setup(self) -> None:
        result = self.run_runner("nginx")

        self.assertEqual(result.returncode, 2)
        self.assertIn("connector must be envoy, traefik, or lighttpd", result.stderr)

    def test_closed_dispatcher_allows_only_listed_connectors_to_reach_prerequisites(self) -> None:
        with tempfile.TemporaryDirectory(prefix="crs-dispatcher-") as temporary:
            environment = os.environ | {
                "CONNECTOR_ROOT": str(ROOT),
                "FRAMEWORK_ROOT": str(Path(temporary) / "missing-framework"),
                "VERIFIED_RUN_ROOT": str(Path(temporary) / "task"),
                "EVIDENCE_ROOT": str(Path(temporary) / "task" / "evidence"),
            }
            for connector in ("envoy", "traefik", "lighttpd"):
                with self.subTest(connector=connector):
                    result = self.run_runner(connector, environment=environment)
                    self.assertEqual(result.returncode, 77)
                    self.assertIn("Framework CRS fetch helper missing", result.stderr)
                    self.assertNotIn("connector must be", result.stderr)

    def test_runner_rejects_unsafe_run_ids_before_runtime_setup(self) -> None:
        for run_id, expected in (("_invalid", "must start"), ("valid;bad", "unsafe run id"), ("a" * 49, "too long")):
            with self.subTest(run_id=run_id):
                result = self.run_runner("envoy", run_id)
                self.assertEqual(result.returncode, 2)
                self.assertIn(expected, result.stderr)

    def test_runner_rejects_reused_runtime_and_build_roots(self) -> None:
        with tempfile.TemporaryDirectory(prefix="crs-runner-reuse-") as temporary:
            root = Path(temporary)
            framework = root / "framework"
            for relative in (
                "ci/provisioning/fetch-crs.sh",
                "ci/provisioning/prepare-crs.sh",
                "ci/checks/catalog/five_connectors_with_crs_no_mrts.py",
            ):
                private_file(framework / relative, "#!/bin/sh\nexit 0\n")
            task_root = root / "task"
            run_root = task_root
            (run_root / "runs/envoy/reused").mkdir(parents=True)
            environment = os.environ | {
                "CONNECTOR_ROOT": str(ROOT),
                "FRAMEWORK_ROOT": str(framework),
                "VERIFIED_RUN_ROOT": str(task_root),
                "EVIDENCE_ROOT": str(task_root / "evidence"),
            }
            result = subprocess.run(
                ["sh", str(RUNNER_PATH), "envoy", "reused"],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("runtime run already exists", result.stderr)

    def test_runner_rejects_external_evidence_root_before_provisioning(self) -> None:
        with tempfile.TemporaryDirectory(prefix="crs-runner-evidence-root-") as temporary:
            root = Path(temporary)
            untrusted_evidence_root = root / "externally-selected-evidence"
            environment = os.environ | {
                "CONNECTOR_ROOT": str(ROOT),
                "FRAMEWORK_ROOT": str(root / "missing-framework"),
                "VERIFIED_RUN_ROOT": str(root / "task"),
                "EVIDENCE_ROOT": str(untrusted_evidence_root),
            }
            result = self.run_runner("envoy", "evidence-root-override", environment=environment)

            self.assertEqual(result.returncode, 77, result.stderr)
            self.assertIn("external EVIDENCE_ROOT is not allowed", result.stderr)
            self.assertFalse(untrusted_evidence_root.exists())
            self.assertNotIn("Framework CRS fetch helper missing", result.stderr)

    def test_normalizer_rejects_uncreated_evidence_root_without_creating_it(self) -> None:
        with tempfile.TemporaryDirectory(prefix="crs-normalizer-evidence-root-") as temporary:
            root = Path(temporary)
            evidence = root / "uncreated-evidence"
            args = SimpleNamespace(
                connector="envoy",
                run_id="valid-run",
                runtime_root=root / "runtime",
                evidence_root=evidence,
                source_root=root / "source",
                connector_root=root / "parent",
                framework_root=root / "framework",
            )

            with self.assertRaisesRegex(RuntimeError, "evidence root is missing"):
                NORMALIZER.normalize(args)

            self.assertFalse(evidence.exists())
            evidence.mkdir(mode=0o700)
            NORMALIZER.ensure_private_evidence_root(evidence)

    def test_atomic_evidence_create_is_private_and_rejects_reuse_and_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="crs-normalizer-atomic-") as temporary:
            root = Path(temporary)
            evidence = root / "evidence"
            evidence.mkdir(mode=0o700)
            target = evidence / "record.json"
            NORMALIZER.atomic_write(target, b"first\n", evidence)
            self.assertEqual(target.read_bytes(), b"first\n")
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            with self.assertRaisesRegex(RuntimeError, "refusing to overwrite"):
                NORMALIZER.atomic_write(target, b"second\n", evidence)
            link = evidence / "linked.json"
            link.symlink_to(target)
            with self.assertRaisesRegex(RuntimeError, "symlink|overwrite"):
                NORMALIZER.atomic_write(link, b"nope\n", evidence)

    def test_raw_evidence_reader_rejects_hardlinked_or_writable_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="crs-normalizer-file-properties-") as temporary:
            root = Path(temporary)
            evidence = root / "evidence"
            evidence.mkdir(mode=0o700)
            target = evidence / "record.json"
            private_file(target, b"original\n")
            os.link(target, evidence / "record-alias.json")
            with self.assertRaisesRegex(RuntimeError, "must not be hard-linked"):
                NORMALIZER.open_contained_regular(target, evidence)
            (evidence / "record-alias.json").unlink()
            target.chmod(0o620)
            with self.assertRaisesRegex(RuntimeError, "group- or world-writable"):
                NORMALIZER.open_contained_regular(target, evidence)

    def test_raw_evidence_reader_rejects_foreign_owner_metadata(self) -> None:
        with tempfile.TemporaryDirectory(prefix="crs-normalizer-file-owner-") as temporary:
            target = Path(temporary) / "record.json"
            private_file(target, b"original\n")
            details = target.lstat()
            with mock.patch.object(NORMALIZER.os, "geteuid", return_value=os.geteuid() + 1):
                with self.assertRaisesRegex(RuntimeError, "owned by the current user"):
                    NORMALIZER.require_safe_read_file(details, "runtime evidence")

    def test_raw_evidence_reader_rejects_writable_component_directory(self) -> None:
        with tempfile.TemporaryDirectory(prefix="crs-normalizer-directory-properties-") as temporary:
            root = Path(temporary)
            evidence = root / "evidence"
            evidence.mkdir(mode=0o700)
            nested = evidence / "nested"
            nested.mkdir(mode=0o700)
            target = nested / "record.json"
            private_file(target, b"original\n")
            nested.chmod(0o720)
            with self.assertRaisesRegex(RuntimeError, "group- or world-writable"):
                NORMALIZER.open_contained_regular(target, evidence)

    def test_raw_evidence_fifo_replacement_uses_nonblocking_open_and_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="crs-normalizer-fifo-race-") as temporary:
            root = Path(temporary)
            evidence = root / "evidence"
            evidence.mkdir(mode=0o700)
            target = evidence / "record.json"
            private_file(target, b"original\n")
            displaced = evidence / "record.original"
            real_open = NORMALIZER.os.open
            replaced = False

            def replace_before_open(path, flags, mode=0o777, *, dir_fd=None):
                nonlocal replaced
                if path == target.name and dir_fd is not None and not replaced:
                    self.assertTrue(flags & os.O_NONBLOCK)
                    replaced = True
                    target.rename(displaced)
                    os.mkfifo(target, mode=0o600)
                return real_open(path, flags, mode, dir_fd=dir_fd)

            with mock.patch.object(NORMALIZER.os, "open", side_effect=replace_before_open):
                with self.assertRaisesRegex(RuntimeError, "not a regular file"):
                    NORMALIZER.open_contained_regular(target, evidence)
            self.assertTrue(replaced)

    def test_raw_evidence_reader_requires_nonblocking_open_support(self) -> None:
        with tempfile.TemporaryDirectory(prefix="crs-normalizer-nonblocking-") as temporary:
            root = Path(temporary)
            evidence = root / "evidence"
            evidence.mkdir(mode=0o700)
            target = evidence / "record.json"
            private_file(target, b"original\n")
            with mock.patch.object(NORMALIZER.os, "O_NONBLOCK", None):
                with self.assertRaisesRegex(RuntimeError, "no-follow non-blocking support"):
                    NORMALIZER.open_contained_regular(target, evidence)

    def test_evidence_replacement_between_lstat_and_open_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="crs-normalizer-identity-") as temporary:
            root = Path(temporary)
            evidence = root / "evidence"
            evidence.mkdir(mode=0o700)
            target = evidence / "record.json"
            private_file(target, b"original\n")
            displaced = evidence / "record.original"
            real_open = NORMALIZER.os.open
            replaced = False

            def replace_before_open(path, flags, mode=0o777, *, dir_fd=None):
                nonlocal replaced
                if path == target.name and dir_fd is not None and not replaced:
                    replaced = True
                    target.rename(displaced)
                    private_file(target, b"replacement\n")
                return real_open(path, flags, mode, dir_fd=dir_fd)

            with mock.patch.object(NORMALIZER.os, "open", side_effect=replace_before_open):
                with self.assertRaisesRegex(RuntimeError, "between validation and open"):
                    NORMALIZER.open_contained_regular(target, evidence)
            self.assertTrue(replaced)
            self.assertEqual(displaced.read_bytes(), b"original\n")
            self.assertEqual(target.read_bytes(), b"replacement\n")

    def test_runtime_root_replacement_between_validation_and_open_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="crs-normalizer-root-identity-") as temporary:
            parent = Path(temporary)
            runtime = parent / "runtime"
            runtime.mkdir(mode=0o700)
            displaced = parent / "runtime.original"
            real_open = NORMALIZER.os.open
            replaced = False

            def replace_before_open(path, flags, mode=0o777, *, dir_fd=None):
                nonlocal replaced
                if Path(path) == runtime and dir_fd is None and not replaced:
                    replaced = True
                    runtime.rename(displaced)
                    runtime.mkdir(mode=0o700)
                return real_open(path, flags, mode, dir_fd=dir_fd)

            with mock.patch.object(NORMALIZER.os, "open", side_effect=replace_before_open):
                with self.assertRaisesRegex(RuntimeError, "changed between validation and open"):
                    NORMALIZER.open_trusted_directory(runtime, "runtime evidence root")
            self.assertTrue(replaced)
            self.assertTrue(displaced.is_dir())
            self.assertTrue(runtime.is_dir())

    def test_normalizer_rejects_pass_marker_without_host_evidence(self) -> None:
        for connector in ("envoy", "traefik", "lighttpd"):
            with self.subTest(connector=connector), tempfile.TemporaryDirectory(prefix="crs-static-evidence-") as temporary:
                root = Path(temporary)
                runtime = root / "runtime"
                self.make_observation(runtime, connector=connector)
                completion = "result.json" if connector == "traefik" else "runtime-summary.txt"
                private_json(runtime / completion, {"status": "PASS"})
                with self.assertRaises((FileNotFoundError, RuntimeError, json.JSONDecodeError)):
                    self.normalize(connector, root, runtime)

    def test_normalizer_rejects_missing_structured_host_facts(self) -> None:
        mutations = {
            "envoy": ("runtime-summary.txt", "reachability_status", "explicit reachability_status"),
            "traefik": ("result.json", "cleanup_status", "explicit cleanup_status"),
            "lighttpd": ("runtime-summary.txt", "block_observed_action", "explicit block_observed_action"),
        }
        for connector, (name, field, message) in mutations.items():
            with self.subTest(connector=connector), tempfile.TemporaryDirectory(
                prefix="crs-missing-structured-fact-"
            ) as temporary:
                root = Path(temporary)
                runtime = root / "runtime"
                self.make_observation(runtime, connector=connector)
                self.populate_host_evidence(connector, runtime)
                path = runtime / name
                if name.endswith(".json"):
                    record = read_json(path)
                    record.pop(field, None)
                    private_json(path, record)
                else:
                    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if not line.startswith(f"{field}=")]
                    private_file(path, "\n".join(lines) + "\n")
                with self.assertRaisesRegex(RuntimeError, message):
                    self.normalize(connector, root, runtime)

    def test_normalizer_rejects_duplicate_summary_fields(self) -> None:
        with tempfile.TemporaryDirectory(prefix="crs-duplicate-summary-field-") as temporary:
            root = Path(temporary)
            runtime = root / "runtime"
            self.make_observation(runtime, connector="envoy")
            self.make_envoy_host_evidence(runtime)
            summary = runtime / "runtime-summary.txt"
            private_file(summary, summary.read_text(encoding="utf-8") + "status=PASS\n")
            with self.assertRaisesRegex(RuntimeError, "duplicate field: status"):
                self.normalize("envoy", root, runtime)

    def test_normalizer_requires_pairwise_distinct_envoy_request_ids(self) -> None:
        with tempfile.TemporaryDirectory(prefix="crs-envoy-duplicate-request-ids-") as temporary:
            root = Path(temporary)
            runtime = root / "runtime"
            self.make_observation(runtime, connector="envoy")
            self.make_envoy_host_evidence(runtime)
            summary = runtime / "runtime-summary.txt"
            lines = summary.read_text(encoding="utf-8").splitlines()
            lines = [
                "allow_request_id=shared-request" if line.startswith("allow_request_id=") else line
                for line in lines
            ]
            lines = [
                "block_request_id=shared-request" if line.startswith("block_request_id=") else line
                for line in lines
            ]
            private_file(summary, "\n".join(lines) + "\n")
            with self.assertRaisesRegex(RuntimeError, "allow, block, and bypass"):
                self.normalize("envoy", root, runtime)

    def test_normalizer_requires_pairwise_distinct_traefik_request_ids(self) -> None:
        with tempfile.TemporaryDirectory(prefix="crs-traefik-duplicate-request-ids-") as temporary:
            root = Path(temporary)
            runtime = root / "runtime"
            self.make_observation(runtime, connector="traefik")
            self.make_traefik_host_evidence(runtime)
            result = read_json(runtime / "result.json")
            result["allow"]["request_id"] = "shared-request"
            result["block"]["request_id"] = "shared-request"
            private_json(runtime / "result.json", result)
            with self.assertRaisesRegex(RuntimeError, "distinct allow/block/bypass"):
                self.normalize("traefik", root, runtime)

    def test_framework_pins_reject_duplicate_assignments(self) -> None:
        with tempfile.TemporaryDirectory(prefix="crs-duplicate-framework-pins-") as temporary:
            framework = Path(temporary)
            common = framework / "ci/lib/common.sh"
            private_file(
                common,
                "CRS_APPROVED_REPO_URL='https://github.com/coreruleset/coreruleset'\n"
                "CRS_RELEASE_TAG='v4.20.0'\n"
                "CRS_APPROVED_COMMIT='0123456789abcdef0123456789abcdef01234567'\n"
                "CRS_RULE_FILE_SHA256='0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'\n"
                "CRS_RELEASE_TAG='v4.20.0'\n",
            )
            with self.assertRaisesRegex(RuntimeError, "incomplete or duplicated"):
                NORMALIZER.framework_pins(framework)

    def test_normalizer_derives_real_host_fields_for_every_connector(self) -> None:
        for connector in ("envoy", "traefik", "lighttpd"):
            with self.subTest(connector=connector), tempfile.TemporaryDirectory(prefix="crs-host-evidence-") as temporary:
                root = Path(temporary)
                runtime = root / "runtime"
                self.make_observation(runtime, connector=connector)
                self.populate_host_evidence(connector, runtime)
                event_path, evidence = self.normalize(connector, root, runtime)

                event = json.loads(event_path.read_text(encoding="utf-8"))
                parent = json.loads(
                    (evidence / "runtime" / connector / f"{connector}-run" / "runtime.json").read_text(encoding="utf-8")
                )
                canonical_path = (
                    evidence
                    / "normalized"
                    / connector
                    / f"{connector}-run"
                    / "runtime-observation.json"
                )
                canonical = json.loads(canonical_path.read_text(encoding="utf-8"))
                canonical_result = NORMALIZER.validate_runtime_observation(
                    canonical,
                    canonical["identity"],
                    {"name": "strict", "evidence_root": evidence},
                )
                self.assertEqual(event["connector"], connector)
                self.assertEqual(
                    event["adapter_id"],
                    {
                        "envoy": "envoy-ext-proc-service",
                        "traefik": "traefik-native-middleware",
                        "lighttpd": "lighttpd-patched-native-module",
                    }[connector],
                )
                self.assertEqual(event["expected_rule_id"], 942270)
                self.assertEqual(event["observed_rule_id"], 942270)
                self.assertEqual(event["observed_status"], 403)
                self.assertEqual(parent["canonical_trigger_rule_id"], 942270)
                self.assertEqual(parent["actual_intervention_rule_id"], 949110)
                self.assertEqual(parent["observed_statuses"], {"allow": 200, "block": 403, "bypass": 403})
                self.assertEqual(parent["no_mrts"], NO_MRTS)
                self.assertNotIn("raw_runtime_root", parent)
                framework = canonical["framework"]
                case = framework["cases"][0]
                self.assertEqual(framework["execution_status"], "RUN")
                self.assertEqual(framework["validation_status"], NORMALIZER.CONTRACT_VALIDATED)
                self.assertTrue(case["executed"])
                self.assertTrue(case["live_executed"])
                self.assertEqual(case["result"], "PASS")
                self.assertEqual(
                    canonical["runtime"]["reachability"]["observed"],
                    {"status": "PASS"},
                )
                # event.json is the existing strict Framework-compatibility
                # artifact.  The richer Parent-only case remains solely in
                # the canonical observation above.
                self.assertNotIn("framework_case", event)
                self.assertEqual(
                    set(event["host_configuration"]),
                    {
                        "config_test_status",
                        "host_start_status",
                        "evidence_path",
                        "evidence_sha256",
                    },
                )
                self.assertEqual(
                    event["host_configuration"]["config_test_status"], "passed"
                )
                self.assertEqual(
                    event["host_configuration"]["host_start_status"], "passed"
                )
                self.assertNotIn("reachability_status", event["host_configuration"])
                self.assertNotIn("framework_execution_status", event["host_configuration"])
                self.assertNotIn("framework_validation_status", event["host_configuration"])
                self.assertEqual(event["cleanup"]["status"], "passed")
                self.assertEqual(canonical["identity"]["profile"], "with-crs-no-mrts")
                self.assertEqual(
                    canonical["identity"]["adapter_id"], event["adapter_id"]
                )
                self.assertEqual(
                    canonical["identity"]["mrts_commit"],
                    "d" * 40,
                )
                self.assertEqual(canonical_result.status, "PASS")
                self.assertEqual(
                    canonical_result["validation_status"], NORMALIZER.CONTRACT_VALIDATED
                )
                self.assertEqual(
                    parent["canonical_observation"]["evidence_path"],
                    f"normalized/{connector}/{connector}-run/runtime-observation.json",
                )
                self.assertEqual(list((evidence / "normalized").rglob("event.json")), [event_path])

    def test_normalizer_rejects_missing_or_invalid_structured_intervention_ids(self) -> None:
        mutations = {
            "envoy": ("runtime-summary.txt", "block_intervention_rule_id", "summary"),
            "lighttpd": ("runtime-summary.txt", "block_intervention_rule_id", "summary"),
            "traefik": ("result.json", "intervention_rule_id", "result"),
        }
        for replacement in (None, "not-a-rule", "949111"):
            for connector, (name, field, format_kind) in mutations.items():
                with self.subTest(connector=connector, replacement=replacement), tempfile.TemporaryDirectory(
                    prefix="crs-invalid-intervention-id-"
                ) as temporary:
                    root = Path(temporary)
                    runtime = root / "runtime"
                    self.make_observation(runtime, connector=connector)
                    self.populate_host_evidence(connector, runtime)
                    path = runtime / name
                    if format_kind == "summary":
                        lines = path.read_text(encoding="utf-8").splitlines()
                        lines = [line for line in lines if not line.startswith(f"{field}=")]
                        if replacement is not None:
                            lines.append(f"{field}={replacement}")
                        private_file(path, "\n".join(lines) + "\n")
                    else:
                        result = read_json(path)
                        block = result["block"]
                        if replacement is None:
                            block.pop(field, None)
                        else:
                            block[field] = replacement
                        private_json(path, result)
                    with self.assertRaisesRegex(RuntimeError, "intervention rule"):
                        self.normalize(connector, root, runtime)

    def test_host_producers_derive_intervention_ids_from_validated_events(self) -> None:
        envoy = (source_path('connectors/envoy/harness/run_envoy_ext_proc_runtime.sh', root=ROOT)).read_text(
            encoding="utf-8"
        )
        self.assertIn('and record.get("transport_result") == "http_status"', envoy)
        self.assertIn("return matches[0]", envoy)
        self.assertIn("block_intervention_rule_id=%s", envoy)
        self.assertNotIn("block_intervention_rule_id=949110", envoy)
        self.assertNotIn("bypass_intervention_rule_id=949110", envoy)

        lighttpd = (source_path('connectors/lighttpd/harness/run_patched_full_lifecycle.sh', root=ROOT)).read_text(
            encoding="utf-8"
        )
        self.assertIn('return transaction_id, event["rule_id"]', lighttpd)
        self.assertIn('print(f"block_intervention_rule_id={block_intervention_rule_id}")', lighttpd)
        self.assertNotIn('print("block_intervention_rule_id=949110")', lighttpd)
        self.assertNotIn('print("bypass_intervention_rule_id=949110")', lighttpd)

    def test_envoy_intervention_rule_id_accepts_only_canonical_json_values(self) -> None:
        """Exercise the exact harness parser used for correlated final events."""
        harness_path = source_path('connectors/envoy/harness/run_envoy_ext_proc_runtime.sh', root=ROOT)
        harness = harness_path.read_text(encoding="utf-8")
        start = harness.index("def intervention_rule_id(record):")
        end = harness.index("\ndef canonical_trigger", start)
        parser_program = (
            "import json\nimport sys\n"
            + harness[start:end]
            + "\nprint(intervention_rule_id(json.loads(sys.argv[1])))\n"
        )

        def invoke(value: object) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [sys.executable, "-", json.dumps({"rule_id": value})],
                input=parser_program,
                text=True,
                capture_output=True,
                check=False,
            )

        for value, expected in ((1, 1), (949110, 949110), ("949110", 949110), ("9999999", 9999999)):
            with self.subTest(value=value):
                result = invoke(value)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), str(expected))

        for value in (True, False, 0, 10_000_000, None, 1.0, "", "0", "01", "+949110", " 949110", "949110 ", "1.0", "١"):
            with self.subTest(value=value):
                result = invoke(value)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("bounded intervention rule id", result.stderr)

    def test_observed_http_status_accepts_lighttpd_semantic_state_only_with_numeric_evidence(self) -> None:
        self.assertEqual(
            NORMALIZER.observed_http_status(
                {"status": "blocked", "http_status": 403, "visible_http_status": 403},
                "Lighttpd block",
                403,
            ),
            403,
        )
        for record, message in (
            ({"status": "blocked"}, "lacks an observed HTTP status"),
            ({"status": "blocked", "http_status": "denied"}, "not a safe HTTP status"),
            ({"status": "blocked", "http_status": "403"}, "not a safe HTTP status"),
            ({"status": "blocked", "http_status": 403.9}, "not a safe HTTP status"),
            ({"status": "PASS", "http_status": 403}, "not a safe HTTP status"),
            ({"status": "blocked", "http_status": 403, "visible_http_status": 200}, "do not match"),
            ({"status": "blocked", "http_status": True}, "not a safe HTTP status"),
        ):
            with self.subTest(record=record):
                with self.assertRaisesRegex(RuntimeError, message):
                    NORMALIZER.observed_http_status(record, "Lighttpd block", 403)

    def test_framework_passed_status_requires_an_explicit_parent_pass(self) -> None:
        self.assertEqual(NORMALIZER.framework_passed_status("PASS", "test"), "passed")
        for value in (None, "passed", "FAIL", True):
            with self.subTest(value=value):
                with self.assertRaisesRegex(RuntimeError, "verified Parent PASS"):
                    NORMALIZER.framework_passed_status(value, "test")

    def test_normalizer_emits_exact_framework_key_value_raw_records(self) -> None:
        """Lock Parent raw files to Framework's non-JSON record grammar."""
        for connector in ("envoy", "traefik", "lighttpd"):
            with self.subTest(connector=connector), tempfile.TemporaryDirectory(
                prefix="crs-framework-raw-records-"
            ) as temporary:
                root = Path(temporary)
                runtime = root / "runtime"
                self.make_observation(runtime, connector=connector)
                self.populate_host_evidence(connector, runtime)
                event_path, evidence = self.normalize(connector, root, runtime)
                event = json.loads(event_path.read_text(encoding="utf-8"))
                run_id = f"{connector}-run"
                raw_dir = evidence / "raw" / connector / run_id
                allow = event["allow_case"]
                cleanup = event["cleanup"]
                self.assertIsInstance(allow, dict)
                self.assertIsInstance(cleanup, dict)
                expected = {
                    "host-configuration.log": {
                        "schema_version": "1",
                        "record_type": "host_configuration",
                        "profile": "five-connectors-with-crs-no-mrts",
                        "connector": connector,
                        "integration_mode": event["integration_mode"],
                        "run_id": run_id,
                        "config_test_status": "passed",
                        "host_start_status": "passed",
                    },
                    "allow-request.log": {
                        "schema_version": "1",
                        "record_type": "allow_request",
                        "profile": "five-connectors-with-crs-no-mrts",
                        "connector": connector,
                        "integration_mode": event["integration_mode"],
                        "fixture_id": "crs_sqli_anomaly_block:allow",
                        "run_id": run_id,
                        "request_id": allow["request_id"],
                        "transaction_id": allow["transaction_id"],
                        "method": "GET",
                        "path": "/?id=42",
                        "correlation_header": "X-Framework-Run-ID",
                        "correlation_value": run_id,
                        "payload_length": "0",
                        "status": "200",
                    },
                    "block-audit.log": {
                        "schema_version": "1",
                        "record_type": "block_audit",
                        "profile": "five-connectors-with-crs-no-mrts",
                        "connector": connector,
                        "integration_mode": event["integration_mode"],
                        "fixture_id": "crs_sqli_anomaly_block",
                        "run_id": run_id,
                        "request_id": event["request_id"],
                        "transaction_id": event["transaction_id"],
                        "method": "GET",
                        "path": "/?id=1%20UNION%20SELECT%20password%20FROM%20users",
                        "correlation_header": "X-Framework-Run-ID",
                        "correlation_value": run_id,
                        "payload_length": "0",
                        "expected_rule_id": "942270",
                        "observed_rule_id": "942270",
                        "expected_status": "403",
                        "observed_status": "403",
                        "intervention": "deny",
                        "evidence_type": event["evidence_type"],
                    },
                    "cleanup.log": {
                        "schema_version": "1",
                        "record_type": "cleanup",
                        "profile": "five-connectors-with-crs-no-mrts",
                        "connector": connector,
                        "run_id": run_id,
                        "status": "passed",
                        "host_processes_remaining": "0",
                        "helper_processes_remaining": "0",
                        "listeners_remaining": "0",
                        "sockets_remaining": "0",
                        "pid_files_remaining": "0",
                        "runtime_fixtures_remaining": "0",
                        "temporary_paths_remaining": "0",
                        "mrts_runner_invoked": "false",
                        "mrts_case_inventory_loaded": "false",
                        "mrts_process_started": "false",
                        "mrts_socket_or_listener_created": "false",
                        "mrts_artifact_used": "false",
                    },
                }
                for name, expected_fields in expected.items():
                    with self.subTest(connector=connector, record=name):
                        content = (raw_dir / name).read_text(encoding="utf-8")
                        self.assertFalse(content.startswith("{"), content)
                        actual = self.framework_raw_record(raw_dir / name)
                        self.assertEqual(actual, expected_fields)

    def test_normalizer_rejects_nonclean_no_mrts_observation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="crs-no-mrts-observation-") as temporary:
            root = Path(temporary)
            runtime = root / "runtime"
            observed = dict(NO_MRTS)
            observed["process_started"] = True
            self.make_observation(runtime, no_mrts=observed)
            self.make_envoy_host_evidence(runtime)
            with self.assertRaisesRegex(RuntimeError, "cleanup/no-MRTS"):
                self.normalize("envoy", root, runtime)

    def test_traefik_rejects_missing_or_forged_external_socket_parent_cleanup(self) -> None:
        for mutation in ("missing", "forged"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(
                prefix="crs-traefik-socket-parent-"
            ) as temporary:
                root = Path(temporary)
                runtime = root / "runtime"
                self.make_observation(runtime, connector="traefik")
                self.make_traefik_host_evidence(runtime)
                observation_path = runtime / "runtime-observation.json"
                observation = read_json(observation_path)
                if mutation == "missing":
                    observation.pop("external_socket_parent_cleanup")
                else:
                    observation["external_socket_parent_cleanup"] = "unverified"
                private_json(observation_path, observation)

                with self.assertRaisesRegex(RuntimeError, "external socket parent cleanup"):
                    self.normalize("traefik", root, runtime)

    def test_envoy_does_not_promote_raw_final_event_to_an_observation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="crs-envoy-final-event-") as temporary:
            root = Path(temporary)
            runtime = root / "runtime"
            self.make_observation(runtime)
            self.make_envoy_host_evidence(runtime, final_visible=False)
            event_path, _ = self.normalize("envoy", root, runtime)
            self.assertEqual(json.loads(event_path.read_text(encoding="utf-8"))["status"], "PASS")

    def test_normalizer_ignores_duplicate_raw_crs_trigger_when_structured_facts_are_valid(self) -> None:
        for case, transaction_id in (("block", "block-envoy"), ("bypass", "bypass-envoy")):
            with self.subTest(case=case), tempfile.TemporaryDirectory(
                prefix="crs-envoy-duplicate-trigger-"
            ) as temporary:
                root = Path(temporary)
                runtime = root / "runtime"
                self.make_observation(runtime, connector="envoy")
                self.make_envoy_host_evidence(runtime)
                raw_log = runtime / "ext-proc.stderr.log"
                original_line = f'[unique_id "{transaction_id}"] [id "942270"]\n'
                duplicated_line = f'[id "942270"] [unique_id "{transaction_id}"]\n'
                raw_content = raw_log.read_text(encoding="utf-8")
                self.assertIn(original_line, raw_content)
                private_file(raw_log, raw_content.replace(original_line, duplicated_line * 2))

                event_path, _ = self.normalize("envoy", root, runtime)
                self.assertEqual(json.loads(event_path.read_text(encoding="utf-8"))["status"], "PASS")

    def test_lighttpd_ignores_malformed_raw_crs_rule_marker_when_structured_facts_are_valid(self) -> None:
        with tempfile.TemporaryDirectory(prefix="crs-lighttpd-malformed-trigger-") as temporary:
            root = Path(temporary)
            runtime = root / "runtime"
            self.make_observation(runtime, connector="lighttpd")
            self.make_lighttpd_host_evidence(runtime)
            raw_log = runtime / "runtime-smoke.stderr"
            expected_marker = '[unique_id "lighttpd-1-102"] [id "942270"]\n'
            malformed_marker = '[unique_id "lighttpd-1-102"] [id "942270"x]\n'
            raw_content = raw_log.read_text(encoding="utf-8")
            self.assertIn(expected_marker, raw_content)
            private_file(raw_log, raw_content.replace(expected_marker, malformed_marker))

            event_path, _ = self.normalize("lighttpd", root, runtime)
            self.assertEqual(json.loads(event_path.read_text(encoding="utf-8"))["status"], "PASS")

    def test_lighttpd_preserves_distinct_request_and_transaction_ids(self) -> None:
        with tempfile.TemporaryDirectory(prefix="crs-lighttpd-identities-") as temporary:
            root = Path(temporary)
            runtime = root / "runtime"
            self.make_observation(runtime, connector="lighttpd")
            self.make_lighttpd_host_evidence(runtime)
            event_path, evidence = self.normalize("lighttpd", root, runtime)

            event = json.loads(event_path.read_text(encoding="utf-8"))
            parent = json.loads(
                (evidence / "runtime" / "lighttpd" / "lighttpd-run" / "runtime.json").read_text(encoding="utf-8")
            )
            self.assertEqual(event["request_id"], "block-request-lighttpd")
            self.assertEqual(event["transaction_id"], "lighttpd-1-102")
            self.assertNotEqual(event["request_id"], event["transaction_id"])
            self.assertEqual(parent["block_request_id"], event["request_id"])
            self.assertEqual(parent["block_transaction_id"], event["transaction_id"])

    def test_lighttpd_binds_private_wire_evidence_to_server_response_transactions(self) -> None:
        with tempfile.TemporaryDirectory(prefix="crs-lighttpd-wire-accept-") as temporary:
            root = Path(temporary)
            runtime = root / "runtime"
            self.make_observation(runtime, connector="lighttpd")
            self.make_lighttpd_host_evidence(runtime)
            summary = NORMALIZER.summary_values(runtime / "runtime-summary.txt", runtime)
            wire_root = runtime / "crs-request-evidence"

            self.assertEqual(stat.S_IMODE(wire_root.stat().st_mode), 0o700)
            self.assertEqual(
                summary["response_transaction_header_name"],
                "X-Msconnector-Host-Transaction-Id",
            )
            self.assertEqual(
                summary["response_transaction_header_origin"],
                "server_generated_lighttpd_host",
            )
            for case, expected_status, expected_transaction_id in (
                ("allow", 200, "lighttpd-1-101"),
                ("block", 403, "lighttpd-1-102"),
                ("bypass", 403, "lighttpd-1-103"),
            ):
                with self.subTest(case=case):
                    trace_path = Path(summary[f"{case}_request_trace"])
                    headers_path = Path(summary[f"{case}_response_headers"])
                    self.assertEqual(trace_path.parent, wire_root)
                    self.assertEqual(headers_path.parent, wire_root)
                    self.assertEqual(stat.S_IMODE(trace_path.stat().st_mode), 0o600)
                    self.assertEqual(stat.S_IMODE(headers_path.stat().st_mode), 0o600)
                    trace = trace_path.read_text(encoding="ascii")
                    self.assertIn("=> Send header,", trace)
                    self.assertIn("* Request completely sent off", trace)
                    self.assertIn(f"X-Framework-Request-ID: {summary[f'{case}_request_id']}", trace)
                    headers = headers_path.read_bytes()
                    self.assertTrue(headers.endswith(b"\r\n\r\n"))
                    self.assertIn(f"HTTP/1.1 {expected_status} ".encode("ascii"), headers)
                    self.assertIn(
                        (
                            "X-Msconnector-Host-Transaction-Id: "
                            f"{expected_transaction_id}\r\n"
                        ).encode("ascii"),
                        headers,
                    )
                    self.assertEqual(summary[f"{case}_response_transaction_id"], expected_transaction_id)

            event_path, evidence = self.normalize("lighttpd", root, runtime)
            event = json.loads(event_path.read_text(encoding="utf-8"))
            parent = json.loads(
                (evidence / "runtime" / "lighttpd" / "lighttpd-run" / "runtime.json").read_text(encoding="utf-8")
            )
            self.assertEqual(event["transaction_id"], "lighttpd-1-102")
            self.assertTrue(
                {
                    "crs-request-evidence/allow.curl.trace",
                    "crs-request-evidence/allow.response.headers",
                    "crs-request-evidence/block.curl.trace",
                    "crs-request-evidence/block.response.headers",
                    "crs-request-evidence/bypass.curl.trace",
                    "crs-request-evidence/bypass.response.headers",
                }.issubset(parent["raw_inputs"]),
                parent["raw_inputs"],
            )
            self.assertTrue(
                {
                    "runtime-summary.txt",
                    "events.jsonl",
                    "runtime-smoke.stderr",
                }.issubset(parent["raw_inputs"]),
                parent["raw_inputs"],
            )

    def test_lighttpd_accepts_current_curl_connected_loopback_trace(self) -> None:
        with tempfile.TemporaryDirectory(prefix="crs-lighttpd-curl-connected-") as temporary:
            root = Path(temporary)
            runtime = root / "runtime"
            self.make_observation(runtime, connector="lighttpd")
            self.make_lighttpd_host_evidence(runtime)
            for case in ("allow", "block", "bypass"):
                trace_path = runtime / "crs-request-evidence" / f"{case}.curl.trace"
                trace_path.write_text(
                    trace_path.read_text(encoding="ascii").replace(
                        "* Established connection to 127.0.0.1 (127.0.0.1 port 8080)",
                        "* Connected to 127.0.0.1 (127.0.0.1) port 8080",
                    ),
                    encoding="ascii",
                )
            event_path, _evidence = self.normalize("lighttpd", root, runtime)
            self.assertEqual(
                json.loads(event_path.read_text(encoding="utf-8"))["transaction_id"],
                "lighttpd-1-102",
            )

    def test_lighttpd_trace_numeric_patterns_remain_ascii_only(self) -> None:
        """Sonar regex cleanup must not admit Unicode digits into wire evidence."""
        self.assertIsNone(NORMALIZER.LIGHTTPD_HOST_TRANSACTION.fullmatch("lighttpd-١-2"))
        self.assertIsNone(
            NORMALIZER.CURL_TRACE_SEND_HEADER.fullmatch("=> Send header, ١ bytes (0x1)")
        )
        self.assertIsNone(
            NORMALIZER.CURL_TRACE_RECEIVE_HEADER.fullmatch("<= Recv header, ١ bytes (0x1)")
        )
        self.assertIsNone(
            NORMALIZER.CURL_TRACE_LOOPBACK_TRY.fullmatch(
                "== Info:   Trying 127.0.0.1:٨٠٨٠..."
            )
        )

    def test_lighttpd_accepts_curl_info_loopback_trace(self) -> None:
        """Curl's ``== Info:`` trace family still proves one local connection."""
        with tempfile.TemporaryDirectory(prefix="crs-lighttpd-curl-info-loopback-") as temporary:
            root = Path(temporary)
            runtime = root / "runtime"
            self.make_observation(runtime, connector="lighttpd")
            self.make_lighttpd_host_evidence(runtime)
            for case in ("allow", "block", "bypass"):
                trace_path = runtime / "crs-request-evidence" / f"{case}.curl.trace"
                trace_path.write_text(
                    trace_path.read_text(encoding="ascii").replace(
                        "*   Trying 127.0.0.1:8080...\n"
                        "* Established connection to 127.0.0.1 (127.0.0.1 port 8080)",
                        "== Info:   Trying 127.0.0.1:8080...\n"
                        "== Info: Connected to 127.0.0.1 (127.0.0.1) port 8080",
                    ),
                    encoding="ascii",
                )
            event_path, _evidence = self.normalize("lighttpd", root, runtime)
            self.assertEqual(
                json.loads(event_path.read_text(encoding="utf-8"))["transaction_id"],
                "lighttpd-1-102",
            )

    def test_lighttpd_rejects_curl_info_loopback_port_mismatch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="crs-lighttpd-curl-info-mismatch-") as temporary:
            root = Path(temporary)
            runtime = root / "runtime"
            self.make_observation(runtime, connector="lighttpd")
            self.make_lighttpd_host_evidence(runtime)
            trace_path = runtime / "crs-request-evidence" / "block.curl.trace"
            trace_path.write_text(
                trace_path.read_text(encoding="ascii").replace(
                    "*   Trying 127.0.0.1:8080...\n"
                    "* Established connection to 127.0.0.1 (127.0.0.1 port 8080)",
                    "== Info:   Trying 127.0.0.1:8080...\n"
                    "== Info: Connected to 127.0.0.1 (127.0.0.1) port 8081",
                ),
                encoding="ascii",
            )
            with self.assertRaisesRegex(RuntimeError, "one private loopback connection"):
                self.normalize("lighttpd", root, runtime)

    def test_lighttpd_accepts_ubuntu_curl_established_loopback_trace(self) -> None:
        """Curl 8.18 on Ubuntu adds a verified local source endpoint."""
        with tempfile.TemporaryDirectory(prefix="crs-lighttpd-curl-established-") as temporary:
            root = Path(temporary)
            runtime = root / "runtime"
            self.make_observation(runtime, connector="lighttpd")
            self.make_lighttpd_host_evidence(runtime)
            for case in ("allow", "block", "bypass"):
                trace_path = runtime / "crs-request-evidence" / f"{case}.curl.trace"
                trace_path.write_text(
                    trace_path.read_text(encoding="ascii").replace(
                        "* Established connection to 127.0.0.1 (127.0.0.1 port 8080)",
                        "* Established connection to 127.0.0.1 (127.0.0.1 port 8080) "
                        "from 127.0.0.1 port 49152 ",
                    ),
                    encoding="ascii",
                )
            event_path, _evidence = self.normalize("lighttpd", root, runtime)
            self.assertEqual(
                json.loads(event_path.read_text(encoding="utf-8"))["transaction_id"],
                "lighttpd-1-102",
            )

    def test_lighttpd_rejects_ubuntu_curl_mismatched_or_nonlocal_loopback_trace(self) -> None:
        for replacement in (
            "* Established connection to 127.0.0.1 (127.0.0.1 port 8081) "
            "from 127.0.0.1 port 49152 ",
            "* Established connection to 127.0.0.1 (127.0.0.1 port 8080) "
            "from 192.0.2.1 port 49152 ",
        ):
            with self.subTest(replacement=replacement), tempfile.TemporaryDirectory(
                prefix="crs-lighttpd-curl-established-reject-"
            ) as temporary:
                root = Path(temporary)
                runtime = root / "runtime"
                self.make_observation(runtime, connector="lighttpd")
                self.make_lighttpd_host_evidence(runtime)
                trace_path = runtime / "crs-request-evidence" / "block.curl.trace"
                trace_path.write_text(
                    trace_path.read_text(encoding="ascii").replace(
                        "* Established connection to 127.0.0.1 (127.0.0.1 port 8080)",
                        replacement,
                    ),
                    encoding="ascii",
                )
                with self.assertRaisesRegex(RuntimeError, "one private loopback connection"):
                    self.normalize("lighttpd", root, runtime)

    def test_lighttpd_rejects_multiple_loopback_connections(self) -> None:
        with tempfile.TemporaryDirectory(prefix="crs-lighttpd-curl-loopback-reject-") as temporary:
            root = Path(temporary)
            runtime = root / "runtime"
            self.make_observation(runtime, connector="lighttpd")
            self.make_lighttpd_host_evidence(runtime)
            trace_path = runtime / "crs-request-evidence" / "block.curl.trace"
            trace_path.write_text(
                trace_path.read_text(encoding="ascii").replace(
                    "* Established connection to 127.0.0.1 (127.0.0.1 port 8080)",
                    "* Connected to 127.0.0.1 (127.0.0.1) port 8080\n"
                    "* Connected to 127.0.0.1 (127.0.0.1) port 8080",
                ),
                encoding="ascii",
            )
            with self.assertRaisesRegex(RuntimeError, "one private loopback connection"):
                self.normalize("lighttpd", root, runtime)

    def test_lighttpd_rejects_client_supplied_transaction_id_in_request_trace(self) -> None:
        with tempfile.TemporaryDirectory(prefix="crs-lighttpd-wire-injected-tx-") as temporary:
            root = Path(temporary)
            runtime = root / "runtime"
            self.make_observation(runtime, connector="lighttpd")
            self.make_lighttpd_host_evidence(runtime)
            trace_path = runtime / "crs-request-evidence" / "block.curl.trace"
            private_file(
                trace_path,
                self.make_lighttpd_curl_trace(
                    [
                        "GET /?id=1%20UNION%20SELECT HTTP/1.1",
                        "Host: crs-runtime.test",
                        "X-Framework-Run-ID: lighttpd-run",
                        "X-Framework-Request-ID: block-request-lighttpd",
                        "X-Modsec-Transaction-Id: client-forged",
                        "Accept: */*",
                        "",
                    ]
                ),
            )

            with self.assertRaisesRegex(RuntimeError, "client transaction id"):
                self.normalize("lighttpd", root, runtime)

    def test_lighttpd_accepts_64_byte_folded_run_and_request_headers(self) -> None:
        with tempfile.TemporaryDirectory(prefix="crs-lighttpd-wire-folded-") as temporary:
            root = Path(temporary)
            runtime = root / "runtime"
            long_run_id = "lighttpd-run-" + "r" * 80
            request_ids = {
                "allow": "allow-request-lighttpd",
                "block": "block-request-" + "b" * 80,
                "bypass": "bypass-request-lighttpd",
            }
            self.make_observation(runtime, connector="lighttpd")
            self.make_lighttpd_host_evidence(
                runtime,
                run_id=long_run_id,
                request_ids_override=request_ids,
            )
            trace_path = runtime / "crs-request-evidence" / "block.curl.trace"
            trace = trace_path.read_text(encoding="ascii")
            request_lines = NORMALIZER.lighttpd_request_lines(trace, "block")

            self.assertIn(f"X-Framework-Run-ID: {long_run_id}", request_lines)
            self.assertIn(f"X-Framework-Request-ID: {request_ids['block']}", request_lines)
            self.assertGreater(
                max(
                    len(f"X-Framework-Run-ID: {long_run_id}"),
                    len(f"X-Framework-Request-ID: {request_ids['block']}"),
                ),
                64,
            )
            event_path, _ = self.normalize("lighttpd", root, runtime, run_id=long_run_id)
            event = json.loads(event_path.read_text(encoding="utf-8"))
            self.assertEqual(event["run_id"], long_run_id)
            self.assertEqual(event["request_id"], request_ids["block"])

    def test_lighttpd_accepts_curl_info_framing_without_relaxing_exchange_checks(self) -> None:
        with tempfile.TemporaryDirectory(prefix="crs-lighttpd-wire-info-") as temporary:
            root = Path(temporary)
            runtime = root / "runtime"
            self.make_observation(runtime, connector="lighttpd")
            self.make_lighttpd_host_evidence(runtime)
            trace_path = runtime / "crs-request-evidence" / "block.curl.trace"
            trace = trace_path.read_text(encoding="ascii")
            info_trace = trace.replace(
                "* Request completely sent off\n",
                "== Info: sent request bytes\n"
                "== Info: Request completely sent off\n",
            )
            private_file(trace_path, info_trace)

            event_path, _ = self.normalize("lighttpd", root, runtime)
            event = json.loads(event_path.read_text(encoding="utf-8"))
            self.assertEqual(event["request_id"], "block-request-lighttpd")

            duplicate_completion_trace = info_trace.replace(
                "== Info: Request completely sent off\n",
                "== Info: Request completely sent off\n"
                "== Info: Request completely sent off\n",
            )
            private_file(trace_path, duplicate_completion_trace)
            with self.assertRaisesRegex(RuntimeError, "exactly one request exchange"):
                self.normalize("lighttpd", root, runtime)

    def test_lighttpd_accepts_received_header_boundary_without_relaxing_wire_validation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="crs-lighttpd-wire-recv-header-") as temporary:
            root = Path(temporary)
            runtime = root / "runtime"
            self.make_observation(runtime, connector="lighttpd")
            self.make_lighttpd_host_evidence(runtime)
            trace_path = runtime / "crs-request-evidence" / "block.curl.trace"
            trace = trace_path.read_text(encoding="ascii")
            receive_boundary_trace = trace.replace(
                "* Request completely sent off\n",
                "<= Recv header, 26 bytes (0x1a)\n",
            )
            private_file(trace_path, receive_boundary_trace)

            event_path, _ = self.normalize("lighttpd", root, runtime)
            event = json.loads(event_path.read_text(encoding="utf-8"))
            self.assertEqual(event["request_id"], "block-request-lighttpd")

            invalid_receive_trace = receive_boundary_trace.replace(
                "<= Recv header, 26 bytes (0x1a)",
                "<= Recv data, 26 bytes (0x1a)",
            )
            private_file(trace_path, invalid_receive_trace)
            with self.assertRaisesRegex(RuntimeError, "unexpected outgoing-header row"):
                self.normalize("lighttpd", root, runtime)

            trace_lines = receive_boundary_trace.splitlines()
            last_data_row = max(
                index
                for index, line in enumerate(trace_lines)
                if NORMALIZER.CURL_TRACE_DATA_ROW.fullmatch(line) is not None
            )
            trace_lines.insert(last_data_row, "<= Recv header, 26 bytes (0x1a)")
            private_file(trace_path, "\n".join(trace_lines) + "\n")
            with self.assertRaisesRegex(
                RuntimeError,
                "invalid outgoing-header byte span|unterminated outgoing-header block",
            ):
                self.normalize("lighttpd", root, runtime)

    def test_lighttpd_rejects_arbitrary_curl_info_row(self) -> None:
        with tempfile.TemporaryDirectory(prefix="crs-lighttpd-wire-info-reject-") as temporary:
            root = Path(temporary)
            runtime = root / "runtime"
            self.make_observation(runtime, connector="lighttpd")
            self.make_lighttpd_host_evidence(runtime)
            trace_path = runtime / "crs-request-evidence" / "block.curl.trace"
            trace = trace_path.read_text(encoding="ascii").replace(
                "* Request completely sent off\n",
                "* attacker-controlled note\n* Request completely sent off\n",
            )
            with self.assertRaisesRegex(RuntimeError, "unexpected outgoing-header row"):
                NORMALIZER.lighttpd_request_lines(trace, "block")

    def test_lighttpd_rejects_noncontiguous_or_invalid_wire_offset_span(self) -> None:
        for mutation, expected in (
            ("noncontiguous", "non-contiguous outgoing-header offset"),
            ("invalid-span", "invalid outgoing-header byte span"),
        ):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(
                prefix="crs-lighttpd-wire-offset-"
            ) as temporary:
                root = Path(temporary)
                runtime = root / "runtime"
                self.make_observation(runtime, connector="lighttpd")
                self.make_lighttpd_host_evidence(runtime)
                trace_path = runtime / "crs-request-evidence" / "block.curl.trace"
                trace_lines = trace_path.read_text(encoding="ascii").splitlines()
                if mutation == "noncontiguous":
                    row_indices = [
                        index
                        for index, line in enumerate(trace_lines)
                        if NORMALIZER.CURL_TRACE_DATA_ROW.fullmatch(line) is not None
                    ]
                    self.assertGreaterEqual(len(row_indices), 2)
                    first_index = row_indices[0]
                    row = NORMALIZER.CURL_TRACE_DATA_ROW.fullmatch(trace_lines[first_index])
                    self.assertIsNotNone(row)
                    assert row is not None
                    trace_lines[first_index] = f"0001: {row.group(2)}"
                else:
                    for index, line in enumerate(trace_lines):
                        declaration = NORMALIZER.CURL_TRACE_SEND_HEADER.fullmatch(line)
                        if declaration is not None:
                            declared_length = int(declaration.group(1)) + 1
                            trace_lines[index] = f"=> Send header, {declared_length} bytes (0x{declared_length:x})"
                            break
                    else:
                        self.fail("test fixture is missing curl's send-header declaration")
                private_file(trace_path, "\n".join(trace_lines) + "\n")

                with self.assertRaisesRegex(RuntimeError, expected):
                    self.normalize("lighttpd", root, runtime)

    def test_lighttpd_rejects_forged_response_transaction_id(self) -> None:
        with tempfile.TemporaryDirectory(prefix="crs-lighttpd-wire-forged-tx-") as temporary:
            root = Path(temporary)
            runtime = root / "runtime"
            self.make_observation(runtime, connector="lighttpd")
            self.make_lighttpd_host_evidence(runtime)
            headers_path = runtime / "crs-request-evidence" / "block.response.headers"
            private_file(
                headers_path,
                headers_path.read_bytes().replace(b"lighttpd-1-102", b"lighttpd-1-999"),
            )

            with self.assertRaisesRegex(RuntimeError, "summary response transaction id"):
                self.normalize("lighttpd", root, runtime)

    def test_lighttpd_rejects_unprivate_or_replaced_wire_evidence(self) -> None:
        for mutation in ("unprivate", "symlink-replacement"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(
                prefix="crs-lighttpd-wire-private-"
            ) as temporary:
                root = Path(temporary)
                runtime = root / "runtime"
                self.make_observation(runtime, connector="lighttpd")
                self.make_lighttpd_host_evidence(runtime)
                trace_path = runtime / "crs-request-evidence" / "block.curl.trace"
                if mutation == "unprivate":
                    trace_path.chmod(0o644)
                    expected = "not a private regular file"
                else:
                    replacement = runtime / "replacement.curl.trace"
                    private_file(replacement, trace_path.read_bytes())
                    trace_path.unlink()
                    trace_path.symlink_to(replacement)
                    expected = "contains a symlink"

                with self.assertRaisesRegex(RuntimeError, expected):
                    self.normalize("lighttpd", root, runtime)

    def test_lighttpd_rejects_request_id_substituted_for_actual_transaction_id(self) -> None:
        with tempfile.TemporaryDirectory(prefix="crs-lighttpd-substitution-") as temporary:
            root = Path(temporary)
            runtime = root / "runtime"
            self.make_observation(runtime, connector="lighttpd")
            self.make_lighttpd_host_evidence(runtime, reuse_request_ids_as_transactions=True)
            with self.assertRaises(RuntimeError):
                self.normalize("lighttpd", root, runtime)

    def test_normalizer_rejects_missing_or_forged_parent_dispatch_identity(self) -> None:
        for mutation in ("missing", "forged"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(prefix="crs-dispatch-identity-") as temporary:
                root = Path(temporary)
                runtime = root / "runtime"
                self.make_observation(runtime, connector="envoy")
                self.make_envoy_host_evidence(runtime)
                observation_path = runtime / "runtime-observation.json"
                observation = read_json(observation_path)
                dispatch = observation["dispatch"]
                self.assertIsInstance(dispatch, dict)
                if mutation == "missing":
                    dispatch.pop("source")
                else:
                    dispatch["source"] = "framework-generated"
                private_json(observation_path, observation)
                with self.assertRaisesRegex(RuntimeError, "dispatch identity"):
                    self.normalize("envoy", root, runtime)

    def test_normalizer_rejects_missing_cleanup_counter_and_listener_diff_mismatch(self) -> None:
        for mutation in ("missing-counter", "forged-listener-diff"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(prefix="crs-cleanup-contract-") as temporary:
                root = Path(temporary)
                runtime = root / "runtime"
                self.make_observation(runtime, connector="envoy")
                self.make_envoy_host_evidence(runtime)
                observation_path = runtime / "runtime-observation.json"
                observation = read_json(observation_path)
                cleanup = observation["cleanup"]
                self.assertIsInstance(cleanup, dict)
                if mutation == "missing-counter":
                    cleanup.pop("listeners_remaining")
                else:
                    cleanup["listener_records"] = ["LISTEN 0 1 127.0.0.1:12345"]
                private_json(observation_path, observation)
                with self.assertRaises(RuntimeError):
                    self.normalize("envoy", root, runtime)

    def test_envoy_binds_raw_completion_inventory_without_deriving_outcomes_from_it(self) -> None:
        for mutation in ("missing", "forged"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(prefix="crs-envoy-completion-") as temporary:
                root = Path(temporary)
                runtime = root / "runtime"
                self.make_observation(runtime, connector="envoy")
                self.make_envoy_host_evidence(runtime)
                completion_path = runtime / "completion-events.jsonl"
                if mutation == "missing":
                    completion_path.unlink()
                else:
                    record = json.loads(completion_path.read_text(encoding="utf-8"))
                    record["close_reason"] = "request_headers"
                    private_file(completion_path, json.dumps(record) + "\n")
                if mutation == "missing":
                    with self.assertRaises(RuntimeError):
                        self.normalize("envoy", root, runtime)
                else:
                    event_path, _ = self.normalize("envoy", root, runtime)
                    self.assertEqual(
                        json.loads(event_path.read_text(encoding="utf-8"))["status"], "PASS"
                    )

    def test_traefik_ignores_embedded_raw_event_when_structured_fields_match(self) -> None:
        with tempfile.TemporaryDirectory(prefix="crs-traefik-binding-") as temporary:
            root = Path(temporary)
            runtime = root / "runtime"
            self.make_observation(runtime, connector="traefik")
            self.make_traefik_host_evidence(runtime)
            result_path = runtime / "result.json"
            result = read_json(result_path)
            block = result["block"]
            self.assertIsInstance(block, dict)
            observed_event = block["observed_event"]
            self.assertIsInstance(observed_event, dict)
            observed_event["transaction_id"] = "forged-traefik-transaction"
            private_json(result_path, result)
            event_path, _ = self.normalize("traefik", root, runtime)
            self.assertEqual(json.loads(event_path.read_text(encoding="utf-8"))["status"], "PASS")

    def test_lighttpd_rejects_forged_uri_to_transaction_binding(self) -> None:
        with tempfile.TemporaryDirectory(prefix="crs-lighttpd-uri-") as temporary:
            root = Path(temporary)
            runtime = root / "runtime"
            self.make_observation(runtime, connector="lighttpd")
            self.make_lighttpd_host_evidence(runtime)
            events_path = runtime / "events.jsonl"
            events = [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines()]
            events[0]["uri"] = "/?id=1%20UNION%20SELECT"
            events[0]["redacted"] = False
            private_file(events_path, "".join(json.dumps(event) + "\n" for event in events))
            with self.assertRaisesRegex(RuntimeError, "correlated 949110 intervention"):
                self.normalize("lighttpd", root, runtime)

    def test_lighttpd_uses_the_common_query_redaction_representation(self) -> None:
        self.assertEqual(
            NORMALIZER.lighttpd_serialized_event_uri("/path?canary=secret"),
            ("/path?<redacted>", True),
        )
        self.assertEqual(
            NORMALIZER.lighttpd_serialized_event_uri("/path"),
            ("/path", False),
        )
        self.assertEqual(
            NORMALIZER.lighttpd_serialized_event_uri("/path?"),
            ("/path?", False),
        )

    def test_framework_compatibility_is_reported_but_not_promoted_to_parent_runtime(self) -> None:
        arguments = SimpleNamespace(
            connector="envoy",
            run_id="run",
            runtime_root=Path("/runtime"),
            evidence_root=Path("/evidence"),
            source_root=Path("/source"),
            connector_root=Path("/parent"),
            framework_root=Path("/framework"),
        )
        captured = io.StringIO()
        with mock.patch.object(NORMALIZER.argparse.ArgumentParser, "parse_args", return_value=arguments), mock.patch.object(
            NORMALIZER, "normalize", return_value=Path("/evidence/normalized/event.json")
        ), contextlib.redirect_stdout(captured):
            self.assertEqual(NORMALIZER.main(), 0)
        report = json.loads(captured.getvalue())
        self.assertEqual(report["runtime_status"], "PASS")
        self.assertEqual(report["framework_compatibility"], "UNATTESTED")
        self.assertNotEqual(report["framework_compatibility"], report["runtime_status"])

    def test_runner_invokes_framework_validator_after_parent_normalizer(self) -> None:
        source = RUNNER_PATH.read_text(encoding="utf-8")
        normalize_index = source.index('"$PYTHON" "$NORMALIZER"')
        validator_index = source.index('"$PYTHON" "$CONTRACT" validate')
        self.assertLess(normalize_index, validator_index)

    def test_runner_subreaper_forces_a_fixed_tar_options_child_environment(self) -> None:
        source = RUNNER_PATH.read_text(encoding="utf-8")
        subreaper_index = source.index("PR_SET_CHILD_SUBREAPER = 36")
        heredoc_start = source.rfind("<<'PY'\n", 0, subreaper_index)
        self.assertNotEqual(heredoc_start, -1)
        python_start = heredoc_start + len("<<'PY'\n")
        python_end = source.index("\nPY\n", subreaper_index)
        subreaper = ast.parse(source[python_start:python_end])

        copy_assignments = [
            node
            for node in ast.walk(subreaper)
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == "child_env"
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Attribute)
            and node.value.func.attr == "copy"
            and isinstance(node.value.func.value, ast.Attribute)
            and node.value.func.value.attr == "environ"
            and isinstance(node.value.func.value.value, ast.Name)
            and node.value.func.value.value.id == "os"
        ]
        tar_assignments = [
            node
            for node in ast.walk(subreaper)
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Subscript)
            and isinstance(node.targets[0].value, ast.Name)
            and node.targets[0].value.id == "child_env"
            and isinstance(node.targets[0].slice, ast.Constant)
            and node.targets[0].slice.value == "TAR_OPTIONS"
            and isinstance(node.value, ast.Constant)
            and node.value.value == "--no-same-owner"
        ]
        popen_calls = [
            node
            for node in ast.walk(subreaper)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "Popen"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "subprocess"
            and any(
                keyword.arg == "env"
                and isinstance(keyword.value, ast.Name)
                and keyword.value.id == "child_env"
                for keyword in node.keywords
            )
        ]
        tar_references = [
            node
            for node in ast.walk(subreaper)
            if isinstance(node, ast.Constant) and node.value == "TAR_OPTIONS"
        ]

        self.assertEqual(len(copy_assignments), 1)
        self.assertEqual(len(tar_assignments), 1)
        self.assertEqual(len(popen_calls), 1)
        self.assertEqual(len(tar_references), 1)
        self.assertLess(copy_assignments[0].lineno, tar_assignments[0].lineno)
        self.assertLess(tar_assignments[0].lineno, popen_calls[0].lineno)

    def test_runner_owns_and_nonrecursively_cleans_private_traefik_uds_parent(self) -> None:
        source = RUNNER_PATH.read_text(encoding="utf-8")
        cleanup_start = source.index("cleanup_traefik_socket_parent() {")
        cleanup_end = source.index("\n}\n", cleanup_start) + len("\n}\n")
        cleanup = source[cleanup_start:cleanup_end]
        setup_start = source.index('if [ "$CONNECTOR" = traefik ]; then', cleanup_end)
        setup_end = source.index("\nfi\n", setup_start) + len("\nfi\n")
        setup = source[setup_start:setup_end]

        self.assertIn("TRAEFIK_SOCKET_PARENT=\n", source[:cleanup_start])
        self.assertEqual(source.count("TRAEFIK_ENGINE_SOCKET_PARENT"), 1)
        self.assertIn("for socket_parent_base in /dev/shm /tmp; do", setup)
        self.assertIn(
            'candidate=$(mktemp -d "$socket_parent_base/msconnector-traefik-uds.XXXXXX" 2>/dev/null)',
            setup,
        )
        self.assertIn("TRAEFIK_SOCKET_PARENT=$candidate", setup)
        self.assertIn(
            "[ -n \"$TRAEFIK_SOCKET_PARENT\" ] || { echo 'BLOCKED: no safe Traefik socket-parent filesystem available' >&2; exit 77; }",
            setup,
        )
        self.assertIn('export TRAEFIK_ENGINE_SOCKET_PARENT="$TRAEFIK_SOCKET_PARENT"', setup)
        self.assertNotIn("${TRAEFIK_ENGINE_SOCKET_PARENT", setup)
        self.assertNotIn("TMPDIR", setup)
        exit_trap = "trap 'status=$?; cleanup_traefik_socket_parent || status=1; exit \"$status\"' EXIT"
        self.assertIn(exit_trap, setup)
        allocation_index = setup.index(
            "[ -n \"$TRAEFIK_SOCKET_PARENT\" ] || { echo 'BLOCKED: no safe Traefik socket-parent filesystem available' >&2; exit 77; }"
        )
        trap_index = setup.index(exit_trap)
        validation_index = setup.index('[ -d "$TRAEFIK_SOCKET_PARENT" ] && [ ! -L "$TRAEFIK_SOCKET_PARENT" ]')
        self.assertLess(allocation_index, trap_index)
        self.assertLess(trap_index, validation_index)
        between = [line.strip() for line in setup[allocation_index:trap_index].splitlines()[1:] if line.strip()]
        self.assertEqual(between, ["status=0"])
        for contract in (
            '[ -d "$TRAEFIK_SOCKET_PARENT" ] && [ ! -L "$TRAEFIK_SOCKET_PARENT" ]',
            '[ "$(stat -c \'%u\' "$TRAEFIK_SOCKET_PARENT")" = "$(id -u)" ]',
            '[ "$(stat -c \'%a\' "$TRAEFIK_SOCKET_PARENT")" = 700 ]',
        ):
            with self.subTest(contract=contract):
                self.assertIn(contract, setup)
                self.assertIn(contract, cleanup)
        self.assertIn('rmdir -- "$TRAEFIK_SOCKET_PARENT"', cleanup)
        self.assertNotIn("rm -r", cleanup)

    def test_runner_prepares_crs_under_its_private_build_root(self) -> None:
        source = RUNNER_PATH.read_text(encoding="utf-8")
        runtime_assignment = source.index("CRS_RUNTIME_DIR=$BUILD_ROOT/crs")
        preamble_assignment = source.index(
            "RULE_PREAMBLE=$CRS_RUNTIME_DIR/modsecurity-crs-preamble.conf"
        )
        prepare_index = source.index('sh "$FRAMEWORK_ROOT/ci/provisioning/prepare-crs.sh"')
        self.assertLess(runtime_assignment, prepare_index)
        self.assertLess(preamble_assignment, prepare_index)
        self.assertIn(
            '[ -f "$RULE_PREAMBLE" ] || { echo "FAIL: Framework did not produce canonical CRS preamble" >&2; exit 1; }',
            source,
        )
        self.assertNotIn("CRS_RUNTIME_DIR=$BUILD_ROOT/crs-runtime", source)
        self.assertNotIn("CRS_RUNTIME_DIR=$RUNTIME_ROOT/crs-runtime", source)
        self.assertIn(
            '[ ! -e "$BUILD_ROOT/crs-runtime" ] && [ ! -L "$BUILD_ROOT/crs-runtime" ] || {',
            source,
        )
        self.assertIn(
            'echo "FAIL: ambiguous legacy CRS runtime directory exists: $BUILD_ROOT/crs-runtime" >&2',
            source,
        )
        self.assertEqual(
            [line.strip() for line in source.splitlines() if "$BUILD_ROOT/crs-runtime" in line],
            [
                '[ ! -e "$BUILD_ROOT/crs-runtime" ] && [ ! -L "$BUILD_ROOT/crs-runtime" ] || {',
                'echo "FAIL: ambiguous legacy CRS runtime directory exists: $BUILD_ROOT/crs-runtime" >&2',
            ],
        )



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
