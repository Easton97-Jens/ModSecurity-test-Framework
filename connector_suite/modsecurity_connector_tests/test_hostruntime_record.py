from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import importlib.util
import hashlib
import json
from pathlib import Path
import tempfile
import unittest


ROOT = connector_root()
writer = load_source(source_path('ci/runtime/lifecycle/write-hostruntime-record.py', root=ROOT))


class HostRuntimeRecordTest(unittest.TestCase):
    def write_result(self, directory: Path, payload: dict[str, object]) -> Path:
        path = directory / "result.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def invoke(self, root: Path, result: Path, output: Path, summary: Path) -> dict[str, object]:
        self.assertEqual(writer.main([
            "--result", str(result), "--output", str(output), "--summary", str(summary),
            "--runtime-root", str(root),
            "--connector", "haproxy", "--profile", "native-htx",
            "--runtime-lock-id", "haproxy-htx-3.2.21",
            "--expected-version", "3.2.21", "--actual-version", "3.2.21",
            "--timestamp", "2026-08-14T00:00:00Z",
        ]), 0)
        return json.loads(output.read_text(encoding="utf-8"))

    def complete(self) -> dict[str, object]:
        return {
            "status": "PASS",
            "hostruntime_evidence": {
                "host_process_verified": True,
                "config_loaded": True,
                "readiness_verified": True,
                "real_interaction": True,
                "result_verified": True,
                "cleanup_verified": True,
            },
        }

    def test_complete_record_is_pass(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            record = self.invoke(root, self.write_result(root, self.complete()), root / "record.json", root / "summary.md")
            self.assertEqual(record["status"], "PASS")
            self.assertEqual(record["evidence"]["interaction"], "PASS")

    def test_result_outside_runtime_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            parent = Path(name)
            root = parent / "runtime"
            outside = parent / "outside"
            root.mkdir()
            outside.mkdir()
            source = self.write_result(outside, self.complete())
            with self.assertRaises(SystemExit) as raised:
                writer.main([
                    "--result", str(source), "--output", str(root / "record.json"),
                    "--summary", str(root / "summary.md"), "--runtime-root", str(root),
                    "--connector", "haproxy", "--profile", "native-htx",
                ])
            self.assertEqual(raised.exception.code, 2)

    def test_symlink_escape_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            parent = Path(name)
            root = parent / "runtime"
            outside = parent / "outside"
            root.mkdir()
            outside.mkdir()
            source = self.write_result(outside, self.complete())
            (root / "escape").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(SystemExit) as raised:
                writer.main([
                    "--result", str(root / "escape" / source.name),
                    "--output", str(root / "record.json"),
                    "--summary", str(root / "summary.md"), "--runtime-root", str(root),
                    "--connector", "haproxy", "--profile", "native-htx",
                ])
            self.assertEqual(raised.exception.code, 2)

    def test_incomplete_record_cannot_pass(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            result = self.complete()
            del result["hostruntime_evidence"]["cleanup_verified"]
            record = self.invoke(root, self.write_result(root, result), root / "record.json", root / "summary.md")
            self.assertEqual(record["status"], "BLOCKED")
            self.assertIn("cleanup", record["reason"])

    def test_blocked_source_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            result = self.complete()
            result["hostruntime_evidence"]["readiness_verified"] = "BLOCKED"
            record = self.invoke(root, self.write_result(root, result), root / "record.json", root / "summary.md")
            self.assertEqual(record["status"], "BLOCKED")

    def test_body_safe_existing_result_fields_are_not_copied(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            result = self.complete()
            result["request_body_verified"] = True
            result["body_payload_absent_from_events"] = True
            result["response_body"] = "sensitive-payload"
            record = self.invoke(root, self.write_result(root, result), root / "record.json", root / "summary.md")
            self.assertEqual(record["status"], "PASS")
            serialized = json.dumps(record)
            self.assertNotIn("sensitive-payload", serialized)
            self.assertNotIn("request_body_verified", serialized)

    def test_existing_result_and_unsafe_versions_do_not_break_projection(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            result = self.complete()
            del result["hostruntime_evidence"]["readiness_verified"]
            source = self.write_result(root, result)
            output = root / "record.json"
            self.assertEqual(writer.main([
                "--result", str(source), "--output", str(output),
                "--runtime-root", str(root),
                "--connector", "haproxy", "--profile", "native-htx",
                "--expected-version", "HAProxy /usr/local/bin/haproxy",
                "--actual-version", "HAProxy /tmp/host runtime",
            ]), 0)
            record = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(record["status"], "BLOCKED")
            self.assertIsNone(record["expected_version"])
            self.assertIsNone(record["actual_version"])

    def test_source_fail_with_incomplete_host_evidence_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            result = self.complete()
            result["status"] = "FAIL"
            del result["hostruntime_evidence"]["cleanup_verified"]
            record = self.invoke(root, self.write_result(root, result), root / "record.json", root / "summary.md")
            self.assertEqual(record["status"], "BLOCKED")
            self.assertIn("incomplete_hostruntime_evidence", record["reason"])

    def test_source_fail_with_complete_evidence_remains_fail(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            result = self.complete()
            result["status"] = "FAIL"
            record = self.invoke(root, self.write_result(root, result), root / "record.json", root / "summary.md")
            self.assertEqual(record["status"], "FAIL")

    def test_status_schema_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            record = self.invoke(root, self.write_result(root, self.complete()), root / "record.json", root / "summary.md")
            self.assertIn(record["status"], writer.STATUS_VALUES)
            self.assertNotIn("response_body", json.dumps(record))
            self.assertNotIn("/tmp", json.dumps(record))

    def test_runner_writes_projection_after_finalization(self) -> None:
        runner = (source_path('ci/runtime/lifecycle/run-no-crs-baseline.sh', root=ROOT)).read_text(encoding="utf-8")
        self.assertIn("write-hostruntime-record.py", runner)
        self.assertIn("FINAL_RESULT=", runner)
        self.assertIn('if [ "$finalize_rc" -ne 0 ]; then', runner)
        self.assertLess(runner.index("FINAL_RESULT="), runner.index("latest_file="))

    def projection_fixture(self, root: Path) -> tuple[Path, Path, Path, Path]:
        result = self.write_result(root, {**self.complete(), "artifacts": {
            "log": "logs/run.log", "result": "result.json", "manifest": "manifest.json",
        }})
        (root / "logs").mkdir()
        (root / "logs/run.log").write_text("payload-free\n", encoding="utf-8")
        manifest = root / "manifest.json"
        manifest.write_text(json.dumps({
            "artifacts": {
                "log": {
                    "path": "logs/run.log",
                    "state": "produced",
                    "sha256": hashlib.sha256(b"payload-free\n").hexdigest(),
                },
                "result": {
                    "path": "result.json",
                    "state": "produced",
                    "sha256": hashlib.sha256(result.read_bytes()).hexdigest(),
                },
                "manifest": {"path": "manifest.json", "state": "produced"},
                "optional": {"state": "not_produced"},
                "not-applicable": {"state": "not_applicable"},
            }
        }), encoding="utf-8")
        output = root / "hostruntime-record.json"
        summary = root / "hostruntime-summary.txt"
        return result, manifest, output, summary

    def invoke_projection(self, root: Path, result: Path, manifest: Path,
                          output: Path, summary: Path) -> None:
        self.assertEqual(writer.main([
            "--result", str(result), "--output", str(output),
            "--summary", str(summary), "--manifest", str(manifest),
            "--runtime-root", str(root), "--connector", "haproxy",
            "--profile", "native-htx", "--timestamp", "2026-08-14T00:00:00Z",
        ]), 0)

    def test_manifest_projection_updates_both_canonical_maps(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            result, manifest, output, summary = self.projection_fixture(root)
            self.invoke_projection(root, result, manifest, output, summary)
            result_payload = json.loads(result.read_text(encoding="utf-8"))
            manifest_payload = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertEqual(result_payload["artifacts"]["hostruntime_record"], output.name)
            self.assertEqual(result_payload["artifacts"]["hostruntime_summary"], summary.name)
            for key, path in (("hostruntime_record", output), ("hostruntime_summary", summary)):
                self.assertEqual(manifest_payload["artifacts"][key]["path"], path.name)
                self.assertEqual(manifest_payload["artifacts"][key]["state"], "produced")
                self.assertEqual(
                    manifest_payload["artifacts"][key]["sha256"],
                    hashlib.sha256(path.read_bytes()).hexdigest(),
                )
            self.assertEqual(
                manifest_payload["artifacts"]["result"]["sha256"],
                hashlib.sha256(result.read_bytes()).hexdigest(),
            )
            self.assertEqual(manifest_payload["artifacts"]["optional"], {"state": "not_produced"})
            self.assertEqual(manifest_payload["artifacts"]["not-applicable"], {"state": "not_applicable"})

    def binary_projection_fixture(self, root: Path, data: bytes) -> tuple[Path, Path, Path, Path]:
        result, manifest, output, summary = self.projection_fixture(root)
        binary = root / "logs/run.log"
        binary.write_bytes(data)
        payload = json.loads(manifest.read_text(encoding="utf-8"))
        payload["artifacts"]["log"]["sha256"] = hashlib.sha256(data).hexdigest()
        manifest.write_text(json.dumps(payload), encoding="utf-8")
        return result, manifest, output, summary

    def test_manifest_projection_accepts_non_utf8_binary_bytes(self) -> None:
        data = b"\x7fELF\x00\xb3\xff\x80\r\n"
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            result, manifest, output, summary = self.binary_projection_fixture(root, data)
            self.invoke_projection(root, result, manifest, output, summary)
            projected = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertEqual(projected["artifacts"]["log"]["sha256"], hashlib.sha256(data).hexdigest())
            self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["status"], "PASS")

    def test_artifact_digest_changes_with_binary_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            artifact = root / "binary"
            first = b"\x7fELF\xff\x00" * ((1 << 20) // 6 + 1)
            second = first[:-1] + b"\x80"
            artifact.write_bytes(first)
            first_digest = writer.artifact_sha256(root, artifact, "binary")
            self.assertEqual(first_digest, hashlib.sha256(first).hexdigest())
            artifact.write_bytes(second)
            second_digest = writer.artifact_sha256(root, artifact, "binary")
            self.assertEqual(second_digest, hashlib.sha256(second).hexdigest())
            self.assertNotEqual(first_digest, second_digest)

    def test_manifest_projection_hashes_original_text_line_endings(self) -> None:
        data = b"payload-free\r\nsecond line\r\n"
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            result, manifest, output, summary = self.binary_projection_fixture(root, data)
            self.invoke_projection(root, result, manifest, output, summary)
            projected = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertEqual(projected["artifacts"]["log"]["sha256"], hashlib.sha256(data).hexdigest())

    def test_manifest_projection_rejects_changed_binary_identity(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            result, manifest, output, summary = self.binary_projection_fixture(root, b"\x7fELF\xff")
            (root / "logs/run.log").write_bytes(b"\x7fELF\x80")
            with self.assertRaises(SystemExit) as raised:
                self.invoke_projection(root, result, manifest, output, summary)
            self.assertEqual(raised.exception.code, 2)
            self.assertFalse(output.exists())
            self.assertFalse(summary.exists())

    def test_manifest_projection_rejects_missing_binary(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            result, manifest, output, summary = self.binary_projection_fixture(root, b"\x7fELF\xff")
            (root / "logs/run.log").unlink()
            with self.assertRaises(SystemExit) as raised:
                self.invoke_projection(root, result, manifest, output, summary)
            self.assertEqual(raised.exception.code, 2)
            self.assertFalse(output.exists())

    def test_manifest_projection_still_requires_json_text(self) -> None:
        for filename in ("result.json", "manifest.json"):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                result, manifest, output, summary = self.binary_projection_fixture(root, b"\x7fELF\xff")
                (root / filename).write_bytes(b"\xff\x80")
                with self.assertRaises(SystemExit) as raised:
                    self.invoke_projection(root, result, manifest, output, summary)
                self.assertEqual(raised.exception.code, 2)
                self.assertFalse(output.exists())

    def test_manifest_projection_rejects_existing_non_produced_target(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            result, manifest, output, summary = self.projection_fixture(root)
            (root / "present.log").write_text("unexpected\n", encoding="utf-8")
            manifest_payload = json.loads(manifest.read_text(encoding="utf-8"))
            manifest_payload["artifacts"]["optional"]["path"] = "present.log"
            manifest.write_text(json.dumps(manifest_payload), encoding="utf-8")
            with self.assertRaises(SystemExit) as raised:
                self.invoke_projection(root, result, manifest, output, summary)
            self.assertEqual(raised.exception.code, 2)

    def test_manifest_projection_requires_produced_self_entries(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            result, manifest, output, summary = self.projection_fixture(root)
            manifest_payload = json.loads(manifest.read_text(encoding="utf-8"))
            manifest_payload["artifacts"]["result"]["state"] = "not_produced"
            manifest.write_text(json.dumps(manifest_payload), encoding="utf-8")
            with self.assertRaises(SystemExit) as raised:
                self.invoke_projection(root, result, manifest, output, summary)
            self.assertEqual(raised.exception.code, 2)

    def test_manifest_projection_rejects_noncanonical_self_paths(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            result, manifest, output, summary = self.projection_fixture(root)
            manifest_payload = json.loads(manifest.read_text(encoding="utf-8"))
            manifest_payload["artifacts"]["manifest"]["path"] = "alternate-manifest.json"
            manifest.write_text(json.dumps(manifest_payload), encoding="utf-8")
            with self.assertRaises(SystemExit) as raised:
                self.invoke_projection(root, result, manifest, output, summary)
            self.assertEqual(raised.exception.code, 2)

    def test_manifest_projection_rejects_reserved_artifact_paths(self) -> None:
        for artifact_map in ("result", "manifest"):
            with self.subTest(artifact_map=artifact_map), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                result, manifest, output, summary = self.projection_fixture(root)
                if artifact_map == "result":
                    result_payload = json.loads(result.read_text(encoding="utf-8"))
                    result_payload["artifacts"]["log"] = writer.SELF_ARTIFACT_PATHS["result"]
                    result.write_text(json.dumps(result_payload), encoding="utf-8")
                else:
                    manifest_payload = json.loads(manifest.read_text(encoding="utf-8"))
                    manifest_payload["artifacts"]["log"]["path"] = writer.SELF_ARTIFACT_PATHS["result"]
                    manifest.write_text(json.dumps(manifest_payload), encoding="utf-8")
                with self.assertRaises(SystemExit) as raised:
                    self.invoke_projection(root, result, manifest, output, summary)
                self.assertEqual(raised.exception.code, 2)

    def test_manifest_projection_rejects_invalid_checksum_and_state(self) -> None:
        for field, value in (("sha256", "not-a-checksum"), ("state", "unknown")):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                result, manifest, output, summary = self.projection_fixture(root)
                manifest_payload = json.loads(manifest.read_text(encoding="utf-8"))
                manifest_payload["artifacts"]["log"][field] = value
                manifest.write_text(json.dumps(manifest_payload), encoding="utf-8")
                with self.assertRaises(SystemExit) as raised:
                    self.invoke_projection(root, result, manifest, output, summary)
                self.assertEqual(raised.exception.code, 2)

    def test_manifest_projection_rejects_existing_output_destination(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            result, manifest, output, summary = self.projection_fixture(root)
            output.write_text("stale\n", encoding="utf-8")
            with self.assertRaises(SystemExit) as raised:
                self.invoke_projection(root, result, manifest, output, summary)
            self.assertEqual(raised.exception.code, 2)

    def test_manifest_projection_rejects_malformed_artifact_maps(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            result, manifest, output, summary = self.projection_fixture(root)
            json_payload = json.loads(result.read_text(encoding="utf-8"))
            json_payload["artifacts"] = []
            result.write_text(json.dumps(json_payload), encoding="utf-8")
            with self.assertRaises(SystemExit) as raised:
                self.invoke_projection(root, result, manifest, output, summary)
            self.assertEqual(raised.exception.code, 2)

    def test_manifest_projection_rejects_artifact_outside_run_directory(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            result, manifest, output, summary = self.projection_fixture(root)
            manifest_payload = json.loads(manifest.read_text(encoding="utf-8"))
            manifest_payload["artifacts"]["log"]["path"] = "../outside.log"
            manifest.write_text(json.dumps(manifest_payload), encoding="utf-8")
            with self.assertRaises(SystemExit) as raised:
                self.invoke_projection(root, result, manifest, output, summary)
            self.assertEqual(raised.exception.code, 2)

    def test_manifest_projection_rejects_symlink_and_nonregular_artifacts(self) -> None:
        for kind in ("symlink", "directory"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                result, manifest, output, summary = self.projection_fixture(root)
                artifact = root / "unsafe"
                if kind == "symlink":
                    artifact.symlink_to(root / "logs" / "run.log")
                else:
                    artifact.mkdir()
                result_payload = json.loads(result.read_text(encoding="utf-8"))
                result_payload["artifacts"]["log"] = artifact.name
                result.write_text(json.dumps(result_payload), encoding="utf-8")
                manifest_payload = json.loads(manifest.read_text(encoding="utf-8"))
                manifest_payload["artifacts"]["log"]["path"] = artifact.name
                manifest.write_text(json.dumps(manifest_payload), encoding="utf-8")
                with self.assertRaises(SystemExit) as raised:
                    self.invoke_projection(root, result, manifest, output, summary)
                self.assertEqual(raised.exception.code, 2)

    def test_manifest_projection_rejects_hash_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            result, manifest, output, summary = self.projection_fixture(root)
            manifest_payload = json.loads(manifest.read_text(encoding="utf-8"))
            manifest_payload["artifacts"]["log"]["sha256"] = "0" * 64
            manifest.write_text(json.dumps(manifest_payload), encoding="utf-8")
            with self.assertRaises(SystemExit) as raised:
                self.invoke_projection(root, result, manifest, output, summary)
            self.assertEqual(raised.exception.code, 2)

    def test_manifest_projection_rejects_stale_result_checksum_before_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            result, manifest, output, summary = self.projection_fixture(root)
            manifest_payload = json.loads(manifest.read_text(encoding="utf-8"))
            manifest_payload["artifacts"]["result"]["sha256"] = "0" * 64
            manifest.write_text(json.dumps(manifest_payload), encoding="utf-8")
            with self.assertRaises(SystemExit) as raised:
                self.invoke_projection(root, result, manifest, output, summary)
            self.assertEqual(raised.exception.code, 2)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
