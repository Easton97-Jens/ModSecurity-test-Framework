"""Offline synthetic packets exercise real Envoy review joins, never host proof."""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = connector_root()
HERE = source_path('ci/runtime/lifecycle/i12/envoy', root=ROOT)
PARENT = "a" * 40
REVISION = "b" * 40


def load_review():
    previous = list(sys.path)
    sys.path.insert(0, str(HERE))
    try:
        module = load_source(HERE / 'review_runs.py')
        return module
    finally:
        sys.path[:] = previous


REVIEW = load_review()


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def write(path: Path, value) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value if isinstance(value, bytes) else json.dumps(value).encode())
    return path


def log_row(text, connection="0", stream="101"):
    return ('[2026-10-20T17:28:03.249+00:00] [285] [debug] [http] '
            '[Tags: "ConnectionId":"' + connection + '","StreamId":"' + stream + '"] ' + text)


class EnvoyOfflineOrchestrationTests(unittest.TestCase):
    def setUp(self):
        parent = os.environ.get("RUNNER_TEMP") or os.environ.get("TMPDIR")
        self.assertTrue(parent, "offline packet requires an explicit private external temporary root")
        self.temporary = tempfile.TemporaryDirectory(prefix="envoy-offline-packet-", dir=parent)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.assertFalse(self.root.is_relative_to(ROOT))
        # Only the external storage boundary is substituted. Every file, ledger,
        # hash, source-inventory reconstruction and semantic parser stays real.
        self.storage = mock.patch.object(REVIEW, "STORAGE", self.root)
        self.storage.start()
        self.addCleanup(self.storage.stop)
        self.cache = mock.patch.dict(REVIEW.BINDING_CACHE, {}, clear=True)
        self.cache.start()
        self.addCleanup(self.cache.stop)
        self.source = self.root / "inputs/source"
        self.fixture = self.root / "inputs/fixtures"
        self.images = self.root / "inputs/artifacts"
        self.data = self.root / "attempt/data"
        self.data.mkdir(parents=True)
        self.case = {"label": "offline-packet", "route": "envoy-ext-proc",
                     "original_case_ids": [], "oracle_review_sha256": "c" * 64,
                     "expected_http_status": 200, "spec": str(self.root / "admission.json")}
        self.record = {"case": self.case, "exit_code": 0,
                       "controller_result": {"attempt": str(self.data.parent)}}
        self._source_inputs()
        self._physical_data()
        self._seal_inputs()

    def _source_inputs(self):
        originals = {"ci/runtime/lifecycle/i12/manifest.json":
                     json.dumps({"delivery_product_baseline": PARENT}).encode(),
                     "common/runtime/msconnector_runtime.c": b"synthetic source bytes, never compiled\n"}
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w") as stream:
            for name, body in originals.items():
                member = tarfile.TarInfo(name)
                member.size = len(body)
                stream.addfile(member, io.BytesIO(body))
                write(self.source / name, body)
        write(self.source.parent / "native-build/source-archive.stdout", archive.getvalue())
        self.proof = {"source_copy": str(self.source), "actual_source_commit": REVISION,
                      "checks": [{"label": "source-archive", "exit_code": 0,
                                  "argv": ["rtk", "proxy", "git", "archive", "--format=tar", REVISION],
                                  "stdout_sha256": sha(archive.getvalue())}],
                      "capture_application": {"exact_written_sha256": {}}}
        write(self.source / ".i12-disposable-source-copy.json",
              {"format": "i12-disposable-source-copy-v1", "path": str(self.source),
               "disposable": True, "parent_sha": PARENT})
        write(self.source / "i12-source-application-receipt.json",
              (json.dumps(self.proof["capture_application"], indent=2) + "\n").encode())
        inventory = {str(path.relative_to(self.source)): sha(path.read_bytes())
                     for path in self.source.rglob("*") if path.is_file()}
        write(self.fixture / "actual-build-provenance-v1.json", self.proof)
        write(self.fixture / "scoped-product-source-a9.json",
              {"parent_sha": PARENT, "source_inputs": inventory, "approved_test_overlays": {}})
        write(self.data / "scoped-product-source-equality.json",
              [{"path": name, "baseline_a9_sha256": digest, "actual_source_sha256": digest,
                "verified": True} for name, digest in inventory.items()])
        write(self.fixture / "shape.json", {"case_id": "I12-ENVOY-HOST::offline-packet",
              "leg": self.case["route"], "parent_sha": PARENT,
              "original_case_ids": [], "oracle_review_sha256": self.case["oracle_review_sha256"],
              "target": "target", "neighbor": "neighbor"})
        write(self.fixture / "backend.py", b"# synthetic early .request-line.raw capture fixture\n")
        write(self.fixture / "runtime.conf", b"offline configuration bytes\n")
        write(self.images / "engine-image", b"synthetic image bytes, never executed\n")

    def _command(self, label, stdout):
        write(self.data / (label + ".stdout"), stdout)
        write(self.data / (label + ".stderr"), b"")
        write(self.data / (label + ".command.json"), {"exit_code": 0,
              "stdout_sha256": sha(stdout), "stderr_sha256": sha(b"")})

    def _physical_data(self):
        host, engine, sdk = (sha(value) for value in (b"synthetic host", b"synthetic engine", b"synthetic SDK"))
        write(self.data / "cache/envoy", b"synthetic host")
        write(self.data / "cache/msconnector_envoy_ext_proc", b"synthetic engine")
        write(self.data / "runtime/config", b"config")
        write(self.data / "build-manifest.json", {"source_git_baseline": REVISION,
              "product_contract": "offline synthetic parser fixture", "source_scope_count": 4,
              "host_sha256": host, "engine_sha256": engine,
              "actual_external_build_provenance": {"sdk_library": {"sha256": sdk}},
              "fixture_configuration": {"/task/runtime/config": sha(b"config"),
                  "/mnt/fixtures/runtime.conf": sha((self.fixture / "runtime.conf").read_bytes())}})
        write(self.data / "result.json", {"failure": None, "remaining_owned_processes": [],
              "processes": {"engine": {"waited_exit_code": 0, "forced_kill": False, "signal_sent": None}},
              "actual_runtime_copies_hashes": {"cache/envoy": host}})
        for name in ("before-request", "after-target", "after-neighbor"):
            write(self.data / (name + ".json"), {"processes": {
                "envoy": {"pid": 101, "executable_sha256": host, "identity": "synthetic", "fd_count": 3},
                "engine": {"pid": 102, "executable_sha256": engine, "identity": "synthetic", "fd_count": 4,
                           "native_libraries": [{"sha256": sdk}]}}})
        backend = []
        for sequence, label in enumerate(("target", "neighbor"), 1):
            body = b"abc"
            response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 3\r\n\r\nabc"
            request = b"POST /" + label.encode() + b" HTTP/1.1\r\nContent-Type: text/plain\r\nContent-Length: 3\r\n\r\nabc"
            write(self.data / ("client/" + label + ".request.raw"), request)
            write(self.data / ("client/" + label + ".response.raw"), response)
            write(self.data / ("client/" + label + ".body.raw"), body)
            barrier = {"monotonic_ns": sequence * 100 + 5, "wall_ns": sequence * 1000}
            write(self.data / ("client/" + label + ".first-entity.json"), barrier)
            write(self.data / ("client/" + label + ".receipt.json"), {
                "status": 200, "request_bytes": 3, "request_sha256": sha(body), "bytes": 3,
                "sha256": sha(body), "wire_body_bytes": 3, "actual_send_calls": [{"bytes": len(request)}],
                "chunk_sizes": [3], "started_ns": sequence * 100, "completed_ns": sequence * 100 + 10,
                "first_entity_clock": barrier, "tcp_eof_observed": True, "tcp_reset_observed": False,
                "deliberate_cancel": False, "proposed_process_exit": 0})
            prefix = self.data / ("backend/" + str(sequence))
            write(prefix.with_suffix(".request-line.raw"), request.split(b"\r\n", 1)[0] + b"\r\n")
            write(prefix.with_suffix(".parsed-headers.json"), [["Content-Length", "3"]])
            write(prefix.with_suffix(".request-body.raw"), body)
            write(prefix.with_suffix(".response-body.raw"), body)
            backend.append({"sequence": sequence, "path": "/" + label, "request_bytes": 3,
                "request_sha256": sha(body), "response_bytes": 3, "response_sha256": sha(body),
                "response_status": 200, "request_framing": {"end_of_framing": True},
                "response_eos_written": True, "response_written_ns": sequence * 100 + 3,
                "actual_response_send_calls": [{"bytes": 3}]})
        write(self.data / "backend/receipts.jsonl", ("\n".join(json.dumps(row) for row in backend) + "\n").encode())
        rows = [
            {"sequence": 1, "edge": "enter", "function": "runtime_finish_request_body", "call": 10},
            {"sequence": 2, "edge": "return", "function": "native_process_request_body", "call": 11, "result": 1},
            {"sequence": 3, "edge": "return", "function": "runtime_finish_request_body", "call": 10, "result": 1,
             "runtime_eos_handoff": True},
            {"sequence": 4, "edge": "enter", "function": "common_finish", "call": 12, "contract_state": {"status": 2}},
            {"sequence": 5, "edge": "return", "function": "common_finish", "call": 12, "contract_state": {"status": 3}},
            {"sequence": 6, "edge": "return", "function": "common_cleanup", "call": 13,
             "contract_state": {"status": 3, "cleanup_complete": 1}},
        ]
        for row in rows:
            row.update(pid=102, allocation_scope_call=7, allocation_join_verified=True)
        write(self.data / "runtime/native-lifecycle.jsonl", ("\n".join(json.dumps(row) for row in rows) + "\n").encode())
        write(self.data / "runtime/host-lifecycle.jsonl", (json.dumps({"pid": 102, "allocation_scope_call": 7,
              "operation": "request_body", "body_size": 3, "declared_size": 3,
              "body_end_of_stream_argument": True, "actual_result": 1}) + "\n").encode())
        for name in ("common-events", "adapter-events", "envoy-access"):
            write(self.data / ("runtime/" + name + ".jsonl"), (json.dumps({"phase": 2,
                "status": "error", "action": "error", "event": "abort", "http_status": 502,
                "sequence": 1, "message": "untrusted-body-secret"}) + "\n").encode())
        write(self.data / "runtime/native-debug.log",
              b'Starting phase\nAppending request body: 3 bytes. Limit set to: 12.0\n[id "1000001"]\n')
        write(self.data / "runtime/native-audit.log", b'untrusted-body-secret\n[id "1000001"]\n')
        for label, value in (("host-version", b"envoy 1.37.0\n"), ("go-version", b"go1.27.1\n"),
                             ("sdk-who", b"ModSecurity 3.0.17\n")):
            self._command(label, value)
        lines = [log_row('source/common/http/conn_manager_impl.cc:1 request headers complete (end_stream=false):', '1', '20'),
            "':path', '/target'",
            log_row("source/common/router/router.cc:1 cluster 'composite' match for URL '/envoy.service.auth.v3.Authorization/Check'"),
            log_row('source/common/http/http2/codec_impl.cc:1 Http2Visitor: remaining data payload: 180, stream_id: 1, end_stream: false', '2', '0'),
            log_row('source/common/http/async_client_impl.cc:230 async http request response trailers:'),
            "'grpc-status', '0'", "'grpc-message', ''", '',
            log_row('source/common/http/http2/codec_impl.cc:1 stream 1 closed: 0', '2', '0')]
        write(self.data / "envoy.stderr", "\n".join(lines).encode())

    def _seal_inputs(self):
        bindings = []
        for name, source in (("src", self.source), ("fixtures", self.fixture), ("artifacts", self.images)):
            ledger = write(self.root / (name + "-ledger.json"), {"files": {
                str(path.relative_to(source)): sha(path.read_bytes()) for path in source.rglob("*") if path.is_file()}})
            bindings.append({"target": "/mnt/" + name, "source": str(source), "ledger": str(ledger),
                             "ledger_sha256": sha(ledger.read_bytes())})
        spec = write(Path(self.case["spec"]), {"bindings": bindings})
        write(self.data.parent / "controller-result.json", {"spec_sha256": sha(spec.read_bytes()),
            "exitcode": 0, "controller_exitcode": 0, "timeout": False, "supervisor_reaped": True,
            "errors": [], "surviving_namespace_pids": [], "outside_mount_leaks": [],
            "namespace_pin_verified": True,
            "executed_input_hashes_before": {item["target"]: item["ledger_sha256"] for item in bindings},
            "executed_input_hashes_after": {item["target"]: item["ledger_sha256"] for item in bindings}})
        write(self.data.parent / "retained-original-ownership.json", {"offline_fixture": True})

    def review(self):
        return REVIEW.review_run(self.record, REVIEW.maintained_transport, REVIEW.maintained_capture, PARENT)

    def test_complete_packet_verifies_real_joins_without_host_qualification(self):
        result = self.review()
        self.assertEqual(result["observation_state"], "driver_result_observed")
        self.assertEqual(result["artifact_integrity_issues"], [])
        self.assertTrue(result["admission_spec_hash_verified"])
        self.assertTrue(result["controller"]["executed_input_hashes_unchanged"])
        self.assertEqual(result["controller"]["surviving_namespace_pid_count"], 0)
        self.assertTrue(result["source_equality"]["complete_archived_build_inventory_verified"])
        self.assertTrue(result["source_equality"]["independent_sealed_baseline_overlay_contract_verified"])
        self.assertEqual(result["source_equality"]["row_count"], 4)
        self.assertTrue(all(item["all_file_hashes_verified"] for item in result["sealed_inputs"].values()))
        self.assertTrue(result["loaded_images"]["before-request"]["engine"]["sdk_matches_native_build"])
        self.assertTrue(result["loaded_images"]["after-neighbor"]["envoy"]["matches_build_manifest"])
        self.assertFalse(result["client_time_overlap_observed"])
        self.assertTrue(result["clients"]["target"]["request_body_hash_verified"])
        self.assertTrue(result["clients"]["neighbor"]["response_body_hash_verified"])
        self.assertEqual(result["clients"]["target"]["independent_raw_response"]["entity_sha256"], sha(b"abc"))
        self.assertTrue(result["clients"]["target"]["status_agrees_with_raw"])
        self.assertTrue(result["clients"]["target"]["first_entity_barrier_matches_client"])
        self.assertEqual(result["backend"]["request_count"], 2)
        self.assertEqual(result["backend"]["completed_receipt_role_counts"], {"neighbor": 1, "target": 1})
        scope = result["native"]["scopes"][0]
        self.assertEqual(scope["completed_transition_count"], 1)
        self.assertEqual(scope["native_finish_spans"][0]["native_body_returns_inside_span"], {"native_process_request_body": 1})
        self.assertEqual(result["command_exit_codes"], {"host-version": 0, "go-version": 0, "sdk-who": 0})
        self.assertEqual(result["versions"]["host-version"]["identity"], "envoy 1.37.0")
        self.assertEqual(result["grpc_transport"]["target"]["authorization"]["remote_grpc_status"], 0)
        self.assertFalse(result["grpc_transport"]["target"]["process"]["successful_grpc_completion"])
        self.assertIsNone(result["grpc_transport"]["neighbor"]["authorization"]["remote_grpc_status"])
        self.assertEqual(result["physical_files"]["client/target.response.raw"]["sha256"],
                         sha((self.data / "client/target.response.raw").read_bytes()))
        self.assertFalse(result["host_lifecycle_qualified"])
        self.assertIn("original_exact_id_oracle_review", result["unknown"])
        self.assertNotIn("untrusted-body-secret", json.dumps(result))

    def test_altered_ledger_hash_invalidates_sealed_scope(self):
        ledger = self.root / "fixtures-ledger.json"
        ledger.write_bytes(ledger.read_bytes() + b" ")
        result = self.review()
        self.assertEqual(result["observation_state"], "sealed_input_mismatch")
        self.assertFalse(result["sealed_inputs"]["/mnt/fixtures"]["ledger_hash_verified"])
        self.assertIsNone(result["route"])
        self.assertFalse(result["host_lifecycle_qualified"])

    def test_resealed_shape_rejects_a_different_parent_identity(self):
        path = self.fixture / "shape.json"
        shape = json.loads(path.read_text())
        shape["parent_sha"] = "d" * 40
        write(path, shape)
        self._seal_inputs()
        result = self.review()
        self.assertEqual(result["observation_state"], "fixture_identity_mismatch")
        self.assertTrue(result["sealed_inputs"]["/mnt/fixtures"]["all_file_hashes_verified"])
        self.assertIsNone(result["route"])

    def test_resealed_extra_source_is_not_a_complete_archived_inventory(self):
        write(self.source / "unexpected.c", b"unapproved compilation input\n")
        self._seal_inputs()
        result = self.review()
        self.assertEqual(result["observation_state"], "complete_build_source_mismatch")
        self.assertFalse(result["source_equality"]["complete_archived_build_inventory_verified"])
        self.assertTrue(result["sealed_inputs"]["/mnt/src"]["all_file_hashes_verified"])
        self.assertIsNone(result["route"])

    def test_command_receipt_cannot_substitute_stdout_identity(self):
        path = self.data / "host-version.command.json"
        receipt = json.loads(path.read_text())
        receipt["stdout_sha256"] = "0" * 64
        write(path, receipt)
        result = self.review()
        self.assertIn({"path": "host-version.stdout", "kind": "receipt_hash_mismatch"}, result["artifact_integrity_issues"])
        self.assertFalse(result["host_lifecycle_qualified"])

    def test_response_replaced_after_hashing_loses_raw_status_evidence(self):
        original = REVIEW.Artifacts.__init__
        response = self.data / "client/target.response.raw"
        before = sha(response.read_bytes())

        def replace_after_snapshot(instance, root):
            original(instance, root)
            response.write_bytes(b"HTTP/1.1 500 changed\r\n\r\n")

        with mock.patch.object(REVIEW.Artifacts, "__init__", new=replace_after_snapshot):
            result = self.review()
        self.assertEqual(result["physical_files"]["client/target.response.raw"]["sha256"], before)
        self.assertIn({"path": "client/target.response.raw", "kind": "changed_after_hash"}, result["artifact_integrity_issues"])
        self.assertFalse(result["clients"]["target"]["status_agrees_with_raw"])
        self.assertIsNone(result["clients"]["target"]["independent_raw_response"]["framing_complete"])
        self.assertFalse(result["host_lifecycle_qualified"])


# Parent default discovery uses the one admitted active-case inventory.
if os.environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)


if __name__ == "__main__":
    unittest.main()
