from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = connector_root()
SCRIPT = source_path('ci/runtime/common/hostruntime_preflight.py', root=ROOT)
WORKFLOW_SCRIPT = source_path('ci/runtime/common/hostruntime-preflight.py', root=ROOT)


class HostruntimePreflightTests(unittest.TestCase):
    @staticmethod
    def runtime_root(tmp_path: Path) -> Path:
        return tmp_path / "runtime-root"

    def evidence_dir(self, tmp_path: Path) -> Path:
        return self.runtime_root(tmp_path) / "evidence"

    def run_preflight(self, tmp_path, *args):
        runtime_root = self.runtime_root(tmp_path)
        output = self.evidence_dir(tmp_path)
        command = [
            sys.executable,
            str(SCRIPT),
            "--connector",
            "test",
            "--profile",
            "unit",
            "--runtime-root",
            str(runtime_root),
            "--output-dir",
            str(output),
            *args,
        ]
        completed = subprocess.run(command, check=False, capture_output=True, text=True)
        result = json.loads((output / "status.json").read_text(encoding="utf-8"))
        return completed, result

    def write_lock(self, path, **overrides):
        profile = {
            "id": "unit",
            "os": "linux",
            "arch": "amd64",
            "version": "9.7",
            "sha256": "a" * 64,
            "asset_name": "runtime-9.7.tar.gz",
            "download_url": "https://example.invalid/runtime-9.7.tar.gz",
            "source_provenance": "unit:test",
        }
        profile.update(overrides)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"schema_version": 1, "profiles": [profile]}), encoding="utf-8")

    def test_missing_binary_is_blocked(self):
        with tempfile.TemporaryDirectory() as temporary:
            tmp_path = Path(temporary)
            completed, result = self.run_preflight(
                tmp_path,
                "--expected-version",
                "1.0",
                "--binary",
                str(self.runtime_root(tmp_path) / "missing"),
            )
            self.assertEqual(completed.returncode, 77)
            self.assertEqual(result["status"], "BLOCKED")
            self.assertEqual(result["reason_code"], "prerequisite_missing")
            self.assertTrue(any(item["reason_code"] == "binary_missing" for item in result["checks"]))
            self.assertTrue((self.evidence_dir(tmp_path) / "summary.md").is_file())

    def test_incomplete_identity_evidence_cannot_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            completed, result = self.run_preflight(Path(temporary))
            self.assertEqual(completed.returncode, 77)
            self.assertEqual(result["status"], "BLOCKED")
            self.assertTrue(any(item["reason_code"] == "binary_missing" for item in result["checks"]))
            self.assertTrue(any(item["reason_code"] == "expected_version_missing" for item in result["checks"]))

    def test_missing_requested_host_prerequisite_is_blocked(self):
        with tempfile.TemporaryDirectory() as temporary:
            tmp_path = Path(temporary)
            completed, result = self.run_preflight(tmp_path, "--expected-version", "1.0", "--binary", "/bin/sh", "--header", str(tmp_path / "missing.h"), "--tool", "definitely-not-a-host-tool")
            self.assertEqual(completed.returncode, 77)
            self.assertEqual(result["status"], "BLOCKED")
            self.assertTrue(any(item["reason_code"] == "header_missing" for item in result["checks"]))
            self.assertTrue(any(item["reason_code"] == "tool_missing" for item in result["checks"]))

    def test_safe_outputs_are_bounded_and_have_exact_statuses(self):
        with tempfile.TemporaryDirectory() as temporary:
            completed, result = self.run_preflight(Path(temporary), "--expected-version", "not-the-shell-version", "--binary", "/bin/sh")
            self.assertEqual(completed.returncode, 77)
            self.assertEqual(result["status"], "BLOCKED")
            self.assertIn(result["status"], {"PASS", "FAIL", "BLOCKED", "NOT_RUN", "NOT_APPLICABLE"})
            self.assertTrue(all(len(item["remediation"]) <= 240 for item in result["checks"]))
            self.assertNotIn(
                "not-the-shell-version",
                (self.evidence_dir(Path(temporary)) / "summary.md").read_text(encoding="utf-8"),
            )

    def test_workflow_compatibility_entrypoint_accepts_output_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            tmp_path = Path(temporary)
            output = tmp_path / "status.json"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(WORKFLOW_SCRIPT),
                    "--profile",
                    "nginx",
                    "--runtime-root",
                    str(tmp_path),
                    "--output",
                    str(output),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            result = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(completed.returncode, 77)
            self.assertEqual(result["connector"], "nginx")
            self.assertEqual(result["status"], "BLOCKED")
            self.assertTrue((tmp_path / "summary.md").is_file())

    def test_valid_lock_drives_version_and_safe_artifact_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            tmp_path = Path(temporary)
            lock = self.runtime_root(tmp_path) / "runtime-component-lock.json"
            binary_root = tmp_path / "trusted-binaries"
            binary_root.mkdir()
            binary = binary_root / "unit-runtime"
            shutil.copy2(sys.executable, binary)
            fixture_version = ".".join(str(component) for component in sys.version_info[:3])
            self.write_lock(lock, version=fixture_version)
            completed, result = self.run_preflight(
                tmp_path,
                "--runtime-lock",
                str(lock),
                "--binary-root",
                str(binary_root),
                "--binary",
                str(binary),
            )
            self.assertEqual(completed.returncode, 0)
            self.assertEqual(result["status"], "PASS")
            self.assertEqual(result["runtime_lock"]["lock_profile"], "unit")
            self.assertEqual(result["runtime_lock"]["expected_version"], fixture_version)
            self.assertEqual(result["runtime_lock"]["actual_version"], fixture_version)
            self.assertEqual(result["evidence_kind"], "preflight")
            self.assertEqual(result["runtime_status"], "NOT_RUN")
            self.assertEqual(result["reason_code"], "preflight_pass")
            self.assertNotIn("download_url", json.dumps(result))

    def test_missing_lock_is_blocked_with_stable_reason(self):
        with tempfile.TemporaryDirectory() as temporary:
            tmp_path = Path(temporary)
            completed, result = self.run_preflight(
                tmp_path,
                "--runtime-lock",
                str(self.runtime_root(tmp_path) / "missing.json"),
                "--binary",
                "/bin/true",
            )
            self.assertEqual(completed.returncode, 77)
            self.assertEqual(result["status"], "BLOCKED")
            self.assertEqual(result["reason_code"], "runtime_lock_missing")

    def test_bad_lock_shape_is_blocked(self):
        with tempfile.TemporaryDirectory() as temporary:
            tmp_path = Path(temporary)
            lock = self.runtime_root(tmp_path) / "bad.json"
            lock.parent.mkdir(parents=True, exist_ok=True)
            lock.write_text(json.dumps({"schema_version": 1, "profiles": [{"id": "unit"}]}), encoding="utf-8")
            completed, result = self.run_preflight(tmp_path, "--runtime-lock", str(lock), "--binary", "/bin/true")
            self.assertEqual(completed.returncode, 77)
            self.assertEqual(result["reason_code"], "runtime_lock_invalid")

    def test_lock_platform_and_version_drift_cannot_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            tmp_path = Path(temporary)
            lock = self.runtime_root(tmp_path) / "drift.json"
            self.write_lock(lock, os="windows")
            completed, result = self.run_preflight(tmp_path, "--runtime-lock", str(lock), "--binary", "/bin/true")
            self.assertEqual(completed.returncode, 77)
            self.assertEqual(result["reason_code"], "runtime_lock_platform_mismatch")
            self.write_lock(lock, version="99.9")
            completed, result = self.run_preflight(tmp_path, "--runtime-lock", str(lock), "--binary", "/bin/true")
            self.assertEqual(completed.returncode, 77)
            self.assertEqual(result["status"], "BLOCKED")
            self.assertNotEqual(result["status"], "PASS")

    def test_architecture_mismatch_is_blocked_not_product_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            completed, result = self.run_preflight(
                Path(temporary), "--expected-version", "9.7", "--expected-arch", "arm64", "--binary", "/bin/true"
            )
            self.assertEqual(completed.returncode, 77)
            self.assertEqual(result["status"], "BLOCKED")
            self.assertTrue(any(item["reason_code"] == "arch_mismatch" for item in result["checks"]))

    def test_lock_asset_sha_and_profile_drift_are_blocked(self):
        with tempfile.TemporaryDirectory() as temporary:
            tmp_path = Path(temporary)
            lock = self.runtime_root(tmp_path) / "drift.json"
            self.write_lock(lock, asset_name="../escape.tar.gz")
            completed, result = self.run_preflight(tmp_path, "--runtime-lock", str(lock), "--binary", "/bin/true")
            self.assertEqual(completed.returncode, 77)
            self.assertEqual(result["reason_code"], "runtime_lock_invalid")
            self.write_lock(lock, sha256="not-a-digest")
            completed, result = self.run_preflight(tmp_path, "--runtime-lock", str(lock), "--binary", "/bin/true")
            self.assertEqual(result["reason_code"], "runtime_lock_invalid")
            lock.write_text(json.dumps({"schema_version": 1, "profiles": []}), encoding="utf-8")
            completed, result = self.run_preflight(tmp_path, "--runtime-lock", str(lock), "--lock-profile", "unknown", "--binary", "/bin/true")
            self.assertEqual(result["reason_code"], "runtime_lock_invalid")

    def test_port_preflight_checks_free_then_busy_binding(self):
        import socket

        with tempfile.TemporaryDirectory() as temporary:
            tmp_path = Path(temporary)
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            probe.bind(("127.0.0.1", 0))
            busy_port = probe.getsockname()[1]
            completed, result = self.run_preflight(tmp_path, "--port", str(busy_port))
            self.assertEqual(completed.returncode, 77)
            self.assertTrue(any(item["reason_code"] == "port_in_use" for item in result["checks"]))
            probe.close()
            completed, result = self.run_preflight(tmp_path, "--port", str(busy_port))
            self.assertTrue(any(item["reason_code"] == "port_free" for item in result["checks"]))

    def test_lock_profile_requirements_are_checked(self):
        with tempfile.TemporaryDirectory() as temporary:
            tmp_path = Path(temporary)
            lock = self.runtime_root(tmp_path) / "requirements.json"
            self.write_lock(lock, requirements={"headers": [str(tmp_path / "missing.h")]})
            completed, result = self.run_preflight(tmp_path, "--runtime-lock", str(lock), "--binary", "/bin/true")
            self.assertEqual(completed.returncode, 77)
            self.assertEqual(result["status"], "BLOCKED")
            self.assertTrue(any(item["reason_code"] == "header_missing" for item in result["checks"]))

    def test_output_outside_runtime_root_is_rejected_without_writing(self):
        with tempfile.TemporaryDirectory() as temporary:
            tmp_path = Path(temporary)
            runtime_root = self.runtime_root(tmp_path)
            outside_output = tmp_path / "outside" / "preflight"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--profile",
                    "unit",
                    "--runtime-root",
                    str(runtime_root),
                    "--output-dir",
                    str(outside_output),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 77)
            self.assertIn("must be below the runtime root", completed.stderr)
            self.assertFalse(outside_output.exists())

    def test_symlinked_output_ancestor_is_rejected_without_writing(self):
        with tempfile.TemporaryDirectory() as temporary:
            tmp_path = Path(temporary)
            runtime_root = self.runtime_root(tmp_path)
            runtime_root.mkdir()
            outside = tmp_path / "outside"
            outside.mkdir()
            (runtime_root / "escaped").symlink_to(outside, target_is_directory=True)
            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--profile",
                    "unit",
                    "--runtime-root",
                    str(runtime_root),
                    "--output-dir",
                    str(runtime_root / "escaped" / "preflight"),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 77)
            self.assertIn("runtime root", completed.stderr)
            self.assertEqual(list(outside.iterdir()), [])

    def test_lock_outside_runtime_or_source_root_is_blocked(self):
        with tempfile.TemporaryDirectory() as temporary:
            tmp_path = Path(temporary)
            outside_lock = tmp_path / "outside-lock.json"
            self.write_lock(outside_lock)
            completed, result = self.run_preflight(
                tmp_path,
                "--runtime-lock",
                str(outside_lock),
                "--binary",
                "/bin/true",
            )
            self.assertEqual(completed.returncode, 77)
            self.assertEqual(result["reason_code"], "runtime_lock_untrusted")
            self.assertTrue(
                any(item["reason_code"] == "runtime_lock_untrusted" for item in result["checks"])
            )

    def test_untrusted_binary_is_not_executed(self):
        with tempfile.TemporaryDirectory() as temporary:
            tmp_path = Path(temporary)
            marker = tmp_path / "outside-binary-ran"
            outside_binary = tmp_path / "outside-runtime"
            outside_binary.write_text(
                f"#!/bin/sh\n: > {marker}\nprintf 'unit 9.7\\n'\n",
                encoding="utf-8",
            )
            outside_binary.chmod(0o755)
            completed, result = self.run_preflight(
                tmp_path,
                "--expected-version",
                "9.7",
                "--binary",
                str(outside_binary),
            )
            self.assertEqual(completed.returncode, 77)
            self.assertTrue(any(item["reason_code"] == "binary_path_untrusted" for item in result["checks"]))
            self.assertFalse(marker.exists())

    def test_private_binary_root_preserves_the_version_probe(self):
        with tempfile.TemporaryDirectory() as temporary:
            tmp_path = Path(temporary)
            binary_root = tmp_path / "trusted-binaries"
            binary_root.mkdir()
            binary = binary_root / "unit-runtime"
            binary.write_text("#!/bin/sh\nprintf 'unit 9.7\\n'\n", encoding="utf-8")
            binary.chmod(0o755)
            completed, result = self.run_preflight(
                tmp_path,
                "--expected-version",
                "9.7",
                "--binary-root",
                str(binary_root),
                "--binary",
                str(binary),
            )
            self.assertEqual(completed.returncode, 77)
            self.assertTrue(any(item["reason_code"] == "binary_present" for item in result["checks"]))
            self.assertTrue(any(item["reason_code"] == "version_match" for item in result["checks"]))
            self.assertTrue(any(item["reason_code"] == "ldd_failed" for item in result["checks"]))

    def test_group_writable_binary_root_is_rejected_without_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            tmp_path = Path(temporary)
            binary_root = tmp_path / "shared-binaries"
            binary_root.mkdir()
            binary_root.chmod(0o777)
            marker = tmp_path / "shared-binary-ran"
            binary = binary_root / "unit-runtime"
            binary.write_text(
                f"#!/bin/sh\n: > {marker}\nprintf 'unit 9.7\\n'\n",
                encoding="utf-8",
            )
            binary.chmod(0o755)
            completed, result = self.run_preflight(
                tmp_path,
                "--expected-version",
                "9.7",
                "--binary-root",
                str(binary_root),
                "--binary",
                str(binary),
            )
            self.assertEqual(completed.returncode, 77)
            self.assertTrue(any(item["reason_code"] == "binary_path_untrusted" for item in result["checks"]))
            self.assertFalse(marker.exists())

    def test_invalid_binary_format_is_a_bounded_blocker(self):
        with tempfile.TemporaryDirectory() as temporary:
            tmp_path = Path(temporary)
            runtime_root = self.runtime_root(tmp_path)
            runtime_root.mkdir()
            binary = runtime_root / "invalid-format"
            binary.write_text("not an executable format\n", encoding="utf-8")
            binary.chmod(0o755)
            completed, result = self.run_preflight(
                tmp_path,
                "--expected-version",
                "9.7",
                "--binary",
                str(binary),
            )
            self.assertEqual(completed.returncode, 77)
            self.assertEqual(result["status"], "BLOCKED")
            self.assertTrue(any(item["reason_code"] == "version_mismatch" for item in result["checks"]))

    def test_nonpositive_timeout_is_rejected_before_a_probe_runs(self):
        with tempfile.TemporaryDirectory() as temporary:
            tmp_path = Path(temporary)
            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--profile",
                    "unit",
                    "--runtime-root",
                    str(self.runtime_root(tmp_path)),
                    "--output-dir",
                    str(self.evidence_dir(tmp_path)),
                    "--timeout",
                    "-1",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 2)
            self.assertIn("timeout must be between", completed.stderr)
            self.assertFalse(self.runtime_root(tmp_path).exists())

    def test_version_probe_does_not_inherit_the_caller_environment(self):
        with tempfile.TemporaryDirectory() as temporary:
            tmp_path = Path(temporary)
            runtime_root = self.runtime_root(tmp_path)
            runtime_root.mkdir()
            marker = tmp_path / "inherited-environment-ran"
            binary = runtime_root / "environment-probe"
            binary.write_text(
                "#!/bin/sh\n"
                f"if [ -n \"${{HOSTRUNTIME_TEST_MARKER:-}}\" ]; then : > {marker}; fi\n"
                "printf 'unit 9.7\\n'\n",
                encoding="utf-8",
            )
            binary.chmod(0o755)
            with mock.patch.dict(os.environ, {"HOSTRUNTIME_TEST_MARKER": "set"}):
                completed, result = self.run_preflight(
                    tmp_path,
                    "--expected-version",
                    "9.7",
                    "--binary",
                    str(binary),
                )
            self.assertEqual(completed.returncode, 77)
            self.assertTrue(any(item["reason_code"] == "version_match" for item in result["checks"]))
            self.assertFalse(marker.exists())

    def test_dynamic_library_probe_uses_the_fixed_ldd_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            tmp_path = Path(temporary)
            runtime_root = self.runtime_root(tmp_path)
            runtime_root.mkdir()
            binary = runtime_root / "trusted-true"
            shutil.copy2("/bin/true", binary)
            fake_path = tmp_path / "fake-path"
            fake_path.mkdir()
            marker = tmp_path / "fake-ldd-ran"
            fake_ldd = fake_path / "ldd"
            fake_ldd.write_text(f"#!/bin/sh\n: > {marker}\n", encoding="utf-8")
            fake_ldd.chmod(0o755)
            with mock.patch.dict(os.environ, {"PATH": str(fake_path)}):
                completed, result = self.run_preflight(
                    tmp_path,
                    "--expected-version",
                    "true",
                    "--binary",
                    str(binary),
                )
            self.assertEqual(completed.returncode, 0)
            self.assertTrue(
                any(item["reason_code"] == "dynamic_libraries_resolved" for item in result["checks"])
            )
            self.assertFalse(marker.exists())

    def test_make_target_has_no_raw_preflight_argument_sink(self):
        makefile = (source_path('Makefile', root=ROOT)).read_text(encoding="utf-8")
        self.assertNotIn("HOSTRUNTIME_PREFLIGHT_ARGS", makefile)
        self.assertIn("hostruntime_shell_quote", makefile)
        for option in (
            "HOSTRUNTIME_HEADER",
            "HOSTRUNTIME_SOURCE",
            "HOSTRUNTIME_TOOL",
            "HOSTRUNTIME_PORT",
            "HOSTRUNTIME_WRITE_DIR",
            "HOSTRUNTIME_DISK_PATH",
            "HOSTRUNTIME_MIN_FREE_BYTES",
            "HOSTRUNTIME_CONFIG",
            "HOSTRUNTIME_FIXTURE",
        ):
            self.assertIn(option, makefile)

    def test_make_target_keeps_hostruntime_override_in_one_shell_argument(self):
        with tempfile.TemporaryDirectory() as temporary:
            tmp_path = Path(temporary)
            runtime_root = self.runtime_root(tmp_path)
            output_dir = self.evidence_dir(tmp_path)
            marker = tmp_path / "make-override-ran"
            hostile_binary = f'/tmp/runtime"; : > "{marker}"; #'
            completed = subprocess.run(
                [
                    "make",
                    "hostruntime-preflight",
                    f"HOSTRUNTIME_RUNTIME_ROOT={runtime_root}",
                    f"HOSTRUNTIME_PREFLIGHT_OUTPUT_DIR={output_dir}",
                    "HOSTRUNTIME_EXPECTED_VERSION=9.7",
                    f"HOSTRUNTIME_BINARY={hostile_binary}",
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            result = json.loads((output_dir / "status.json").read_text(encoding="utf-8"))
            self.assertNotEqual(completed.returncode, 0)
            self.assertEqual(result["status"], "BLOCKED")
            self.assertTrue(any(item["reason_code"] == "binary_path_untrusted" for item in result["checks"]))
            self.assertFalse(marker.exists())

    def test_make_target_does_not_expand_make_syntax_from_environment(self):
        with tempfile.TemporaryDirectory() as temporary:
            tmp_path = Path(temporary)
            runtime_root = self.runtime_root(tmp_path)
            output_dir = self.evidence_dir(tmp_path)
            completed = subprocess.run(
                [
                    "make",
                    "hostruntime-preflight",
                    f"HOSTRUNTIME_RUNTIME_ROOT={runtime_root}",
                    f"HOSTRUNTIME_PREFLIGHT_OUTPUT_DIR={output_dir}",
                    "HOSTRUNTIME_EXPECTED_VERSION=9.7",
                ],
                cwd=ROOT,
                env={**os.environ, "HOSTRUNTIME_BINARY": "$(error hostruntime-make-injection)"},
                check=False,
                capture_output=True,
                text=True,
            )
            result = json.loads((output_dir / "status.json").read_text(encoding="utf-8"))
            self.assertNotEqual(completed.returncode, 0)
            self.assertNotIn("hostruntime-make-injection", completed.stderr)
            self.assertEqual(result["status"], "BLOCKED")
            self.assertTrue(any(item["reason_code"] == "binary_path_untrusted" for item in result["checks"]))

    def test_connector_wrappers_preserve_environment_make_syntax_as_data_in_dry_run(self):
        wrappers = (
            ("haproxy", "HAPROXY", "hostruntime-preflight-haproxy"),
            ("envoy", "ENVOY", "hostruntime-preflight-envoy"),
            ("traefik", "TRAEFIK", "hostruntime-preflight-traefik"),
        )
        for connector, prefix, target in wrappers:
            with self.subTest(connector=connector), tempfile.TemporaryDirectory() as temporary:
                tmp_path = Path(temporary)
                runtime_root = tmp_path / "runtime-root"
                output_dir = runtime_root / "preflight"
                completed = subprocess.run(
                    ["make", "-n", "-C", f"connectors/{connector}", target],
                    cwd=ROOT,
                    env={
                        **os.environ,
                        f"{prefix}_HOSTRUNTIME_PROFILE": "$(error wrapper-make-injection)",
                        f"{prefix}_HOSTRUNTIME_RUNTIME_ROOT": str(runtime_root),
                        f"{prefix}_HOSTRUNTIME_PREFLIGHT_OUTPUT_DIR": str(output_dir),
                    },
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertIn("hostruntime_preflight.py", completed.stdout)
                self.assertIn("wrapper-make-injection", completed.stdout)
                self.assertNotIn("wrapper-make-injection", completed.stderr)
                self.assertFalse(runtime_root.exists())



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
