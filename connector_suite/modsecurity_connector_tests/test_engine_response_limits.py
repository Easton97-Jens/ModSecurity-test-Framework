"""Executable Common runtime policy evidence using genuine libModSecurity."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
from dataclasses import dataclass
from pathlib import Path
import os
import re
import shlex
import subprocess
import tempfile
import unittest

ROOT = connector_root()


def native_compile_command(source, binary, *, extra_sources=(), extra_flags=()):
    """Use the same selected libModSecurity paths as native bridge builds."""
    prefix = os.environ.get("MODSECURITY_PREFIX", "")
    include = os.environ.get("MODSECURITY_INCLUDE_DIR") or (str(Path(prefix) / "include") if prefix else "")
    library = os.environ.get("MODSECURITY_LIB_FILE", "")
    library_dir = os.environ.get("MODSECURITY_LIB_DIR") or (str(Path(prefix) / "lib") if prefix else "")
    if include and not (Path(include) / "modsecurity/modsecurity.h").is_file():
        raise ValueError("selected MODSECURITY_INCLUDE_DIR has no modsecurity/modsecurity.h")
    if library:
        if not Path(library).is_file():
            raise ValueError("selected MODSECURITY_LIB_FILE is not a file")
        library = str(Path(library).resolve())
        library_dir = str(Path(library).parent)
        link = [library]
    elif library_dir:
        if not (Path(library_dir) / "libmodsecurity.so").is_file():
            raise ValueError("selected MODSECURITY_LIB_DIR has no libmodsecurity.so")
        library_dir = str(Path(library_dir).resolve())
        link = ["-L" + library_dir, "-lmodsecurity"]
    else:
        link = ["-lmodsecurity"]
    if library_dir:
        link.append("-Wl,-rpath," + library_dir)
    return shlex.split(os.environ.get("CC", "cc")) + [
        "-std=c17", "-Wall", "-Wextra", "-Werror", "-I.", "-Icommon/include",
    ] + (["-I" + include] if include else []) + list(extra_flags) + [
        source, "common/runtime/msconnector_runtime.c",
    ] + list(extra_sources) + [str(p.relative_to(ROOT)) for p in sorted((source_path('common/src', root=ROOT)).glob("*.c"))] + [
        "connectors/profile_registry.c",
    ] + link + ["-pthread", "-o", str(binary)]


def engine_fixture_arguments(directory, limit, action, mode, length, chunk, marker):
    if limit is None or action is None:
        raise ValueError("response fixture requires explicit SecResponseBodyLimit and SecResponseBodyLimitAction")
    if limit <= 0 or action not in ("Reject", "ProcessPartial"):
        raise ValueError("invalid explicit engine response policy")
    return [str(directory), str(limit), action, mode, str(length), str(chunk), str(marker)]


@dataclass(frozen=True)
class NativeRequestPolicy:
    limit: int
    no_files_limit: int
    action: str
    engine_mode: str


@dataclass(frozen=True)
class RequestPayload:
    body_mode: str
    length: int
    chunk: int
    marker: int
    input_kind: str


def request_fixture_arguments(directory, policy, payload):
    if policy.limit is None or policy.no_files_limit is None or policy.action is None:
        raise ValueError("request fixture requires explicit SecRequestBodyLimit, SecRequestBodyNoFilesLimit and SecRequestBodyLimitAction")
    if policy.limit <= 0 or policy.no_files_limit <= 0 or policy.action not in ("Reject", "ProcessPartial"):
        raise ValueError("invalid explicit engine request policy")
    return ["--request", str(directory), str(policy.limit), str(policy.no_files_limit), policy.action,
            policy.engine_mode, payload.body_mode, str(payload.length), str(payload.chunk),
            str(payload.marker), payload.input_kind]


class EngineResponseLimits(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(os.environ.get("CODEX_RUN_ROOT", "/var/tmp/codex/ModSecurity-conector/runs"))
        root.mkdir(parents=True, exist_ok=True)
        cls.temp = tempfile.TemporaryDirectory(prefix="engine-response-limits-", dir=root)
        cls.addClassCleanup(cls.temp.cleanup)
        cls.directory = Path(cls.temp.name)
        cls.binary = cls.directory / "engine-limit"
        command = native_compile_command("tests/engine_response_limit_test.c", cls.binary)
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=90)
        if result.returncode:
            raise AssertionError("real libModSecurity test compilation failed:\n" + result.stdout + result.stderr)

    def run_case(self, limit, action, mode, length, chunk, marker):
        with tempfile.TemporaryDirectory(dir=self.directory) as directory:
            args = engine_fixture_arguments(directory, limit, action, mode, length, chunk, marker)
            result = subprocess.run([str(self.binary)] + args, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            print(result.stdout.strip())

    def test_native_transaction_companion_serialization_and_phase_contracts(self):
        """Exercise genuine engine/Runtime chaining, lossless bytes and overflow.

        This deliberately belongs to the libModSecurity suite; lightweight
        serializer protocol tests keep their existing dependency boundary.
        """
        binary = self.directory / "transaction-companion"
        command = native_compile_command("tests/transaction_phase_runtime_companion_test.c", binary,
            extra_sources=["connectors/traefik/src/traefik_provenance.c"],
            extra_flags=["-Icommon/runtime"])
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        with tempfile.TemporaryDirectory(dir=self.directory) as directory:
            result = subprocess.run([str(binary)], cwd=directory, capture_output=True,
                                    text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_native_response_transport_precommit_release_and_reuse(self):
        """Real MRC1 client/server P3 deny cleanup without fabricated CANCEL."""
        short_root = Path("/var/tmp/codex/ModSecurity-conector/t")
        short_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="mrc1-", dir=short_root) as directory:
            binary = Path(directory) / "transport"
            command = native_compile_command(
                "tests/response_companion_transport_test.c", binary,
                extra_flags=['-DMSCONNECTOR_TEST_TEMPORARY_DIRECTORY="' + directory + '"'],
                extra_sources=["common/runtime/response_companion_client.c",
                               "common/runtime/response_companion_transport.c"],
            )
            result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=90)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = subprocess.run([str(binary)], cwd=directory,
                                    capture_output=True, text=True, timeout=90)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_trusted_preclaim_missing_refresh_negative_control(self):
        """A success-only MTP1 confirmation cannot substitute for registry TTL.

        Omit only the actual expiry update in a compiled negative control;
        the physical query succeeds but the >5-second trusted claim must fail.
        """
        source = (source_path('common/runtime/msconnector_runtime.c', root=ROOT)).read_text()
        anchor = "entry->expires_at_ms = entry->preclaim_deadline_ms;"
        self.assertEqual(source.count(anchor), 1)
        candidate = self.directory / "missing-preclaim-refresh.c"
        candidate.write_text(source.replace(anchor,
            "(void)entry->preclaim_deadline_ms; /* negative control */", 1))
        binary = self.directory / "missing-preclaim-refresh"
        command = native_compile_command("tests/transaction_phase_runtime_companion_test.c", binary,
            extra_sources=["connectors/traefik/src/traefik_provenance.c"],
            extra_flags=["-Icommon/runtime"])
        command[command.index("common/runtime/msconnector_runtime.c")] = str(candidate)
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        with tempfile.TemporaryDirectory(dir=self.directory) as directory:
            result = subprocess.run([str(binary)], cwd=directory, capture_output=True,
                                    text=True, timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("test_trusted_preclaim_refresh", result.stderr)
            self.assertIn("claim_handle(&registry, trusted", result.stderr)

    def test_boundaries_actions_chunking_and_modes(self):
        for limit in (128, 1024):
            for action in ("Reject", "ProcessPartial"):
                for mode in ("off", "safe", "strict"):
                    for delta in (-1, 0, 1):
                        for chunk in (17, 65536):
                            with self.subTest(limit=limit, action=action, mode=mode, delta=delta, chunk=chunk):
                                self.run_case(limit, action, mode, limit + delta, chunk, 0)

    def test_engine_partial_prefix_excludes_marker_after_limit(self):
        for mode in ("off", "safe", "strict"):
            self.run_case(128, "ProcessPartial", mode, 256, 17, 160)

    def test_marker_after_old_one_megabyte_connector_default(self):
        for mode in ("off", "safe", "strict"):
            self.run_case(3 * 1024 * 1024, "Reject", mode, 2 * 1024 * 1024, 65536, 1536 * 1024)
            self.run_case(1536 * 1024, "ProcessPartial", mode, 2 * 1024 * 1024, 65536, 1200 * 1024)

    def run_request_case(self, policy, payload):
        with tempfile.TemporaryDirectory(dir=self.directory) as directory:
            arguments = request_fixture_arguments(directory, policy, payload)
            result = subprocess.run([str(self.binary)] + arguments,
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            print(result.stdout.strip())
            return result.stdout

    def test_detection_only_native_actions_have_different_observed_prefixes(self):
        payload = RequestPayload("streaming", 256, 17, 160, "memory")
        observed = {}
        for action in ("Reject", "ProcessPartial"):
            output = self.run_request_case(NativeRequestPolicy(128, 128, action, "DetectionOnly"), payload)
            match = re.search(r"native_prefix=(\d+)", output)
            self.assertIsNotNone(match)
            observed[action] = int(match.group(1))
        self.assertEqual(observed, {"Reject": 120, "ProcessPartial": 128})

    def test_native_request_retained_and_evaluated_prefix_telemetry(self):
        binary = self.directory / "request-telemetry"
        command = native_compile_command("tests/request_body_telemetry_test.c", binary,
            extra_flags=["-Wl,--wrap=msc_get_request_body_length", "-Wl,--wrap=msc_process_request_body",
                         "-Wl,--wrap=fflush"])
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for scenario in ("reject", "partial", "full", "disabled", "accessor-error", "phase-error", "sink-error"):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory(dir=self.directory) as directory:
                result = subprocess.run([str(binary), directory, scenario], capture_output=True,
                                        text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_request_boundaries_actions_modes_and_chunking(self):
        for limit in (128, 1024):
            for action in ("Reject", "ProcessPartial"):
                for engine_mode in ("On", "DetectionOnly"):
                    for body_mode in ("buffered", "streaming"):
                        for delta in (-1, 0, 1):
                            for chunk in (17, 65536):
                                with self.subTest(limit=limit, action=action, engine=engine_mode,
                                                  mode=body_mode, delta=delta, chunk=chunk):
                                    self.run_request_case(NativeRequestPolicy(limit, limit, action, engine_mode), RequestPayload(body_mode, limit + delta, chunk, 0, "memory"))

    def test_genuine_http_service_large_request_before_companion_handoff(self):
        binary = self.directory / "http-stream"
        command = native_compile_command("tests/engine_http_request_stream_test.c", binary)
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for limit, action, marker, expected_status in (
            (3 * 1024 * 1024, "Reject", 1536 * 1024, 451),
            (1024 * 1024, "ProcessPartial", 1536 * 1024, 200),
            (3 * 1024 * 1024, "Reject", 0, 200),
            (1024 * 1024, "Reject", 0, 403),
        ):
            with tempfile.TemporaryDirectory(dir=self.directory) as directory:
                result = subprocess.run([str(binary), directory, str(limit), str(limit), action,
                    str(2 * 1024 * 1024), str(marker), str(expected_status)],
                    capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_native_multipart_no_files_limit_eos(self):
        for engine_mode in ("On", "DetectionOnly"):
            for action in ("Reject", "ProcessPartial"):
                self.run_request_case(NativeRequestPolicy(1024, 128, action, engine_mode),
                    RequestPayload("streaming", 256, 17, 160, "multipart"))

    def test_request_no_files_limit_differs_from_total_limit(self):
        for engine_mode in ("On", "DetectionOnly"):
            for action in ("Reject", "ProcessPartial"):
                self.run_request_case(NativeRequestPolicy(1024, 128, action, engine_mode), RequestPayload("streaming", 256, 17, 160, "urlencoded"))

    def test_request_file_input_and_two_engine_limits_for_same_payload(self):
        for engine_mode in ("On", "DetectionOnly"):
            for action in ("Reject", "ProcessPartial"):
                for limit in (128, 1024):
                    self.run_request_case(NativeRequestPolicy(limit, limit, action, engine_mode), RequestPayload("buffered", 256, 17, 160, "file"))

    def test_request_markers_after_old_connector_limit(self):
        for input_kind in ("memory", "file"):
            for engine_mode in ("On", "DetectionOnly"):
                for limit in (1536 * 1024, 3 * 1024 * 1024):
                    self.run_request_case(NativeRequestPolicy(limit, limit, "ProcessPartial", engine_mode), RequestPayload("streaming", 2 * 1024 * 1024, 65536, 1700 * 1024, input_kind))

    def test_request_helpers_require_each_native_policy_parameter(self):
        for limit, no_files_limit, action in ((None, 128, "Reject"), (128, None, "Reject"), (128, 128, None)):
            policy = NativeRequestPolicy(limit, no_files_limit, action, "On")
            payload = RequestPayload("buffered", 128, 17, 0, "memory")
            with self.assertRaisesRegex(ValueError, "requires explicit"):
                request_fixture_arguments(self.directory, policy, payload)
        result = subprocess.run([str(self.binary), "--request"], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertIn("request required:", result.stderr)

    def test_product_configuration_allows_omitted_engine_directives_without_inspection(self):
        result = subprocess.run([str(self.binary), "--config-only", str(self.directory)],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("no response inspection", result.stdout)

    def test_missing_policy_parameters_fail_readably(self):
        for limit, action in ((None, "Reject"), (128, None)):
            with self.assertRaisesRegex(ValueError, "requires explicit"):
                engine_fixture_arguments(self.directory, limit, action, "safe", 128, 17, 0)
        result = subprocess.run([str(self.binary)], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertIn("required:", result.stderr)


# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
