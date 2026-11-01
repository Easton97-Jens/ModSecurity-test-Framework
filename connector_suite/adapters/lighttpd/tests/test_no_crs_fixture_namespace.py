"""Contract and Linux integration tests for the No-CRS fixture namespace."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import test_root

import base64
import importlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from unittest import mock


REPO_ROOT = test_root()
HELPER_PATH = REPO_ROOT / 'connector_suite/adapters/lighttpd/harness/run_no_crs_fixture_trusted_namespace.py'
FIXTURE_IO_PATH = REPO_ROOT / 'connector_suite/adapters/lighttpd/harness/no_crs_fixture_descriptor_io.py'
PYTHON = "/usr/bin/python3"
UNPRIVILEGED_UID = 65534
UNPRIVILEGED_GID = 65534
TEST_TEMP_PARENT_ENV = "LIGHTTPD_NAMESPACE_TEST_TEMP_PARENT"


def _configured_test_temp_parent(value: str | None = None) -> Path:
    """Accept a CI temporary root only when its ownership is unambiguous."""

    configured = os.environ.get(TEST_TEMP_PARENT_ENV) if value is None else value
    if configured is None:
        return Path("/var/tmp")
    candidate = Path(configured)
    if not candidate.is_absolute():
        raise RuntimeError("configured namespace test temporary parent must be absolute")
    try:
        details = candidate.lstat()
    except OSError as error:
        raise RuntimeError(
            "configured namespace test temporary parent is unavailable"
        ) from error
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode):
        raise RuntimeError(
            "configured namespace test temporary parent is not a real directory"
        )
    if details.st_uid != os.geteuid() or details.st_gid != os.getegid():
        raise RuntimeError(
            "configured namespace test temporary parent has the wrong owner"
        )
    if stat.S_IMODE(details.st_mode) != 0o700:
        raise RuntimeError(
            "configured namespace test temporary parent must be mode 0700"
        )
    return candidate


TEST_TEMP_PARENT = _configured_test_temp_parent()


def _mountinfo_for_mountpoint(mountpoint: Path) -> list[str]:
    """Return the host's exact mountinfo rows for one fixed mountpoint."""

    rows: list[str] = []
    for row in Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines():
        before, separator, _after = row.partition(" - ")
        fields = before.split()
        if separator and len(fields) >= 6 and fields[4] == str(mountpoint):
            rows.append(row)
    return rows


def _proc_status_value(name: str) -> str:
    """Return one exact value from proc status or reject incomplete evidence."""

    for row in Path("/proc/self/status").read_text(encoding="utf-8").splitlines():
        key, separator, value = row.partition(":")
        if separator and key == name:
            return value.strip()
    raise RuntimeError(f"missing {name} in /proc/self/status")


def _host_path_snapshot(path: Path) -> tuple[int, int, int, int] | None:
    """Capture host identity without following an optional fixture path."""

    try:
        details = path.lstat()
    except FileNotFoundError:
        return None
    return (details.st_dev, details.st_ino, details.st_mode, details.st_nlink)


def _processes_containing_marker(marker: str) -> list[int]:
    """Find only still-running task helpers carrying a unique test marker."""

    marker_bytes = marker.encode("utf-8")
    result: list[int] = []
    for candidate in Path("/proc").iterdir():
        if not candidate.name.isdecimal():
            continue
        try:
            command_line = (candidate / "cmdline").read_bytes()
        except OSError:
            continue
        if marker_bytes in command_line:
            result.append(int(candidate.name))
    return sorted(result)


def _load_helper():
    return importlib.import_module('connector_suite.adapters.lighttpd.harness.run_no_crs_fixture_trusted_namespace')


HELPER = _load_helper()


def _production_smoke_root(environment: dict[str, str]) -> Path:
    """Resolve and validate the production smoke root as one asserted operation."""

    paths = HELPER._production_runtime_paths(environment)
    return HELPER._expected_production_smoke_root(paths)


_ENCODED_PYTHON_PAYLOAD_RUNNER = (
    "import base64,subprocess,sys;"
    "raise SystemExit(subprocess.run("
    "['/usr/bin/python3','-'],input=base64.b64decode(sys.argv[1],validate=True),"
    "check=False).returncode)"
)

_LIVE_DESCRIPTOR_SNAPSHOT_SOURCE = textwrap.dedent(
    """
    import errno
    import os

    def _live_descriptor_snapshot():
        snapshot = []
        for entry in os.listdir("/proc/self/fd"):
            if not entry.isdecimal():
                continue
            descriptor = int(entry, 10)
            try:
                os.fstat(descriptor)
            except OSError as error:
                if error.errno == errno.EBADF:
                    continue
                raise
            snapshot.append(descriptor)
        return sorted(snapshot)
    """
)


def _one_line_python_command(payload: str) -> list[str]:
    """Encode a test-only multi-line Python payload without control chars."""

    encoded_payload = base64.b64encode(payload.encode("utf-8")).decode("ascii")
    return [PYTHON, "-c", _ENCODED_PYTHON_PAYLOAD_RUNNER, encoded_payload]


def _runner_source(
    payload: str,
    *,
    timeout: float = 3.0,
    patch: str = "",
    writable_roots: tuple[Path, ...] = (),
) -> str:
    encoded_roots = repr([str(root) for root in writable_roots])
    command = _one_line_python_command(_LIVE_DESCRIPTOR_SNAPSHOT_SOURCE + payload)
    return textwrap.dedent(
        f"""
        import importlib
        from pathlib import Path
        import sys
        helper = importlib.import_module('connector_suite.adapters.lighttpd.harness.run_no_crs_fixture_trusted_namespace')
        {patch}
        command = {command!r}
        writable_roots = tuple(Path(value) for value in {encoded_roots})
        # The unit/integration harness must not inherit a potentially unrelated
        # checkout path from the test runner. The fixture helper uses only the
        # explicitly selected Framework TEST_ROOT and supplies a safe child
        # environment itself.
        helper._emit_probe_phase(True, "runner-start")
        try:
            probe_status = helper.run_isolated(
                command,
                timeout_seconds={timeout!r},
                environment={{}},
                writable_roots=writable_roots,
                emit_probe_phase_markers=True,
            )
        except Exception:
            helper._emit_probe_phase(True, "helper-raised-before-return")
            raise
        helper._emit_probe_phase(True, "helper-returned")
        raise SystemExit(probe_status)
        """
    )


def _drop_runner_to_unprivileged_identity() -> None:
    """Make the launcher caller a real host user, never host root."""

    if os.geteuid() == 0:
        os.setgroups([])
        os.setgid(UNPRIVILEGED_GID)
        os.setuid(UNPRIVILEGED_UID)


def _run_runner(
    source: str, *, timeout: float = 10.0, unprivileged: bool = True
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [PYTHON, "-c", source],
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=timeout,
        preexec_fn=_drop_runner_to_unprivileged_identity if unprivileged else None,
    )


def _bounded_namespace_probe_failure_reason(
    stderr: str, stdout: str, returncode: int
) -> str:
    """Classify only fixed namespace-probe failures, never relay child output."""

    normalized = f"{stderr}\n{stdout}".lower()
    if "probe phase setup-attestation-failed" in normalized:
        if "probe phase bwrap-exec" in normalized:
            return "bubblewrap namespace setup failed before attestation"
        if "probe phase outer-unshare-entered" in normalized:
            return "outer private namespace setup failed before bubblewrap"
        if "probe phase setup-wait-started" in normalized:
            return "unshare namespace setup failed before entry"
        return "namespace setup attestation failed"
    if "probe phase final-state-verified" in normalized:
        return "namespace payload failed after final-state verification"
    if "probe phase setup-attested" in normalized:
        return "namespace child failed after setup attestation"
    if "probe phase helper-raised-before-return" in normalized:
        if "probe phase namespace-child-forked" in normalized:
            return "namespace helper failed after namespace child fork before setup wait"
        if "probe phase namespace-fork-started" in normalized:
            return "namespace child fork failed"
        if "probe phase namespace-command-build-started" in normalized:
            return "namespace command construction failed"
        if "probe phase setup-pipe-inheritable" in normalized:
            return "namespace pre-fork setup failed"
        if "probe phase setup-pipe-created" in normalized:
            return "namespace setup pipe inheritance failed"
        if "probe phase trusted-binaries-validated" in normalized:
            return "namespace setup pipe creation failed"
        if "probe phase caller-identity-validated" in normalized:
            return "trusted namespace binary validation failed"
        return "namespace caller identity validation failed"
    for marker, reason in (
        ("operation not permitted", "unshare operation not permitted"),
        ("permission denied", "namespace operation permission denied"),
        ("cannot set groups", "namespace group mapping unavailable"),
        ("gid_map", "namespace group mapping unavailable"),
        ("trusted namespace setup attestation", "namespace setup attestation failed"),
        ("trusted namespace setup did not attest", "namespace setup attestation failed"),
        ("namespace final verifier", "namespace final-state verification failed"),
        ("bwrap", "bubblewrap namespace setup failed"),
        ("unshare", "unshare namespace setup failed"),
        ("no-crs namespace blocked", "trusted namespace setup blocked"),
    ):
        if marker in normalized:
            return reason
    if returncode == HELPER.EXIT_BLOCKED:
        return "trusted namespace helper blocked"
    if returncode == HELPER.EXIT_TIMEOUT:
        return "namespace probe timed out"
    if returncode == 126:
        return "namespace setup execution failed"
    if 1 <= returncode <= 255:
        return f"namespace probe exited with status {returncode}"
    return "namespace probe exited with an invalid status"


def _namespace_probe_result() -> tuple[bool, str]:
    """Probe the real launch path without exposing arbitrary helper output."""

    if os.name != "posix" or sys.platform != "linux":
        return False, "Linux user/mount/PID namespaces are required"
    # This uses the actual launch sequence as the capability/kernel probe.
    # It intentionally runs from an unprivileged host identity; the new
    # launcher must reject host root rather than borrowing its capabilities.
    try:
        probe = _run_runner(
            _runner_source("pass", timeout=1.0), timeout=8, unprivileged=True
        )
    except (OSError, subprocess.SubprocessError):
        # Some nested containers map only host UID 0 and consequently cannot
        # create a non-root subprocess at all.  That is not a reason to run
        # this security boundary as root; leave the real test gated there.
        return False, "namespace probe could not start"
    if probe.returncode == 0:
        return True, "namespace probe succeeded"

    # The helper's stderr may contain path, environment, or other runtime
    # details. Keep failure evidence useful without relaying unbounded output.
    probe_stderr = str(probe.stderr or "")
    probe_stdout = str(probe.stdout or "")
    probe_output = f"{probe_stderr}\n{probe_stdout}".lower()
    if "no such file or directory" in probe_output:
        return False, "required namespace binary unavailable"
    if probe.returncode < 0:
        return False, "namespace probe terminated by signal"
    return False, _bounded_namespace_probe_failure_reason(
        probe_stderr, probe_stdout, probe.returncode
    )


def _user_namespace_available() -> bool:
    """Return only the availability bit for unittest's capability gate."""

    return _namespace_probe_result()[0]


def _namespace_integration_is_required() -> bool:
    """Make hosted security evidence fail closed instead of silently skipping."""

    value = os.environ.get("LIGHTTPD_REQUIRE_NAMESPACE_INTEGRATION")
    if value not in {None, "1"}:
        raise RuntimeError(
            "LIGHTTPD_REQUIRE_NAMESPACE_INTEGRATION must be unset or exactly 1"
        )
    return value == "1"


@unittest.skipUnless(os.name == "posix" and sys.platform == "linux", "Linux only")
class NamespaceContractTest(unittest.TestCase):
    @staticmethod
    def _no_crs_production_environment(
        run_id: str = "lighttpd-current-run",
    ) -> dict[str, str]:
        verified_root = Path("/verified-runtime")
        smoke_root = (
            verified_root / "runs" / "lighttpd" / run_id / "lighttpd-runtime"
        )
        return {
            "RUNTIME_ROOT": "/stage-runtime",
            "LIGHTTPD_PATCHED_SMOKE_DIR": str(smoke_root),
            "VERIFIED_RUN_ROOT": str(verified_root),
            "FULL_LIFECYCLE_EVIDENCE_OUTPUT": str(
                smoke_root / "first-byte-evidence.json"
            ),
            "NO_CRS_RUN_ID": run_id,
        }

    @staticmethod
    def _failed_namespace_probe(
        stderr: str, returncode: int = 1, stdout: str = ""
    ) -> tuple[bool, str]:
        completed = subprocess.CompletedProcess(
            args=[PYTHON, "-c", "pass"],
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
        )
        with mock.patch(__name__ + "._run_runner", return_value=completed):
            return _namespace_probe_result()

    def test_configured_temporary_parent_must_be_private_and_owned(self) -> None:
        """The CI-owned outer temporary root cannot be a shared path."""

        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary)
            self.assertEqual(_configured_test_temp_parent(str(candidate)), candidate)
            candidate.chmod(0o755)
            with self.assertRaisesRegex(RuntimeError, "mode 0700"):
                _configured_test_temp_parent(str(candidate))

    def test_production_no_crs_smoke_root_matches_the_exact_resolver_path(self) -> None:
        environment = self._no_crs_production_environment()
        paths = HELPER._production_runtime_paths(environment)
        expected = Path(
            "/verified-runtime/runs/lighttpd/lighttpd-current-run/lighttpd-runtime"
        )
        self.assertEqual(paths.run_id, "lighttpd-current-run")
        self.assertEqual(HELPER._expected_production_smoke_root(paths), expected)

    def test_production_no_crs_smoke_root_rejects_other_namespaces_and_run_ids(self) -> None:
        cases = (
            ("wrong-connector", "lighttpd-current-run", "/verified-runtime/runs/apache/lighttpd-current-run/lighttpd-runtime"),
            ("wrong-run", "lighttpd-current-run", "/verified-runtime/runs/lighttpd/lighttpd-foreign-run/lighttpd-runtime"),
            ("legacy-root", "lighttpd-current-run", "/verified-runtime/lighttpd-runtime"),
            ("unsafe-run-id", "../outside", "/verified-runtime/runs/lighttpd/../outside/lighttpd-runtime"),
        )
        for label, run_id, smoke_root in cases:
            with self.subTest(case=label):
                environment = self._no_crs_production_environment(run_id)
                environment["LIGHTTPD_PATCHED_SMOKE_DIR"] = smoke_root
                environment["FULL_LIFECYCLE_EVIDENCE_OUTPUT"] = str(
                    Path(smoke_root) / "first-byte-evidence.json"
                )
                with self.assertRaises(HELPER.NamespaceUnavailable):
                    _production_smoke_root(environment)

    def test_production_paths_reject_parent_traversal_before_namespace_binding(self) -> None:
        base_environment = self._no_crs_production_environment()
        cases = (
            "RUNTIME_ROOT",
            "LIGHTTPD_PATCHED_SMOKE_DIR",
            "VERIFIED_RUN_ROOT",
            "FULL_LIFECYCLE_EVIDENCE_OUTPUT",
        )
        for name in cases:
            with self.subTest(name=name):
                environment = dict(base_environment)
                environment[name] = f"{environment[name]}/.."
                with self.assertRaisesRegex(
                    HELPER.NamespaceUnavailable,
                    "normalized absolute paths",
                ):
                    HELPER._production_runtime_paths(environment)

        with_crs_environment = self._no_crs_production_environment()
        with_crs_environment["PARENT_HOST_RUNTIME_ROOT"] = "/stage-runtime/host/.."
        with self.assertRaisesRegex(
            HELPER.NamespaceUnavailable,
            "normalized absolute paths",
        ):
            HELPER._production_runtime_paths(with_crs_environment)

    def test_production_with_crs_smoke_root_remains_exact(self) -> None:
        environment = self._no_crs_production_environment()
        environment["RUNTIME_ROOT"] = "/stage-runtime"
        environment["LIGHTTPD_PATCHED_SMOKE_DIR"] = "/stage-runtime/host"
        environment["PARENT_HOST_RUNTIME_ROOT"] = "/stage-runtime/host"
        environment["FULL_LIFECYCLE_EVIDENCE_OUTPUT"] = (
            "/stage-runtime/host/first-byte-evidence.json"
        )
        paths = HELPER._production_runtime_paths(environment)
        self.assertEqual(
            HELPER._expected_production_smoke_root(paths), Path("/stage-runtime/host")
        )

    def test_required_workflow_identity_is_non_root_and_restricted(self) -> None:
        """Hosted evidence must attest the outer test identity before isolation."""

        required = os.environ.get("LIGHTTPD_REQUIRE_UNPRIVILEGED_TEST_RUNNER")
        if required is None:
            return
        self.assertEqual(required, "1")
        expected_uid = int(os.environ["LIGHTTPD_NAMESPACE_TEST_UID"])
        expected_gid = int(os.environ["LIGHTTPD_NAMESPACE_TEST_GID"])
        self.assertNotEqual(expected_uid, 0)
        self.assertNotEqual(expected_gid, 0)
        self.assertEqual((os.getuid(), os.geteuid()), (expected_uid, expected_uid))
        self.assertEqual((os.getgid(), os.getegid()), (expected_gid, expected_gid))
        self.assertEqual(os.getgroups(), [])
        self.assertEqual(_proc_status_value("NoNewPrivs"), "1")
        docker_socket = Path("/var/run/docker.sock")
        if docker_socket.exists():
            self.assertFalse(os.access(docker_socket, os.R_OK))
            self.assertFalse(os.access(docker_socket, os.W_OK))

    def test_required_namespace_integration_is_available(self) -> None:
        """A CI caller selecting this gate cannot treat skipped integration as proof."""

        if _namespace_integration_is_required():
            available, reason = _namespace_probe_result()
            self.assertTrue(
                available,
                "required unprivileged user/mount/PID namespace integration is unavailable: "
                f"{reason}",
            )

    def test_multiline_test_payload_keeps_command_validator_strict(self) -> None:
        """Test code transports newlines without weakening the argv boundary."""

        payload = 'print("encoded payload executed")\n'
        command = _one_line_python_command(payload)
        self.assertEqual(command[:3], [PYTHON, "-c", _ENCODED_PYTHON_PAYLOAD_RUNNER])
        self.assertNotIn("exec(", command[2])
        for argument in command:
            self.assertNotIn("\x00", argument)
            self.assertNotIn("\n", argument)
            self.assertNotIn("\r", argument)
            self.assertLessEqual(len(argument), HELPER.MAX_ARGUMENT_LENGTH)
        self.assertEqual(HELPER._validate_command(command), command)
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, "encoded payload executed\n")
        with self.assertRaises(HELPER.NamespaceUnavailable):
            HELPER._validate_command([PYTHON, "-c", payload])
        malformed = [PYTHON, "-c", _ENCODED_PYTHON_PAYLOAD_RUNNER, "###"]
        malformed_completed = subprocess.run(
            malformed, capture_output=True, text=True, check=False
        )
        self.assertNotEqual(malformed_completed.returncode, 0)

    def test_live_descriptor_snapshot_ignores_only_its_procfs_reader(self) -> None:
        """Keep the no-inherited-FD test strict without counting its scanner."""

        payload = _LIVE_DESCRIPTOR_SNAPSHOT_SOURCE + textwrap.dedent(
            """
            import json

            before = _live_descriptor_snapshot()
            read_descriptor, write_descriptor = os.pipe()
            try:
                with_pipe = _live_descriptor_snapshot()
            finally:
                os.close(read_descriptor)
                os.close(write_descriptor)
            print(json.dumps({
                "before": before,
                "pipe": [read_descriptor, write_descriptor],
                "with_pipe": with_pipe,
            }, sort_keys=True))
            """
        )
        completed = subprocess.run(
            _one_line_python_command(payload), capture_output=True, text=True, check=False
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        observed = json.loads(completed.stdout)
        self.assertEqual(observed["before"], [0, 1, 2])
        self.assertEqual(
            set(observed["with_pipe"]) - {0, 1, 2}, set(observed["pipe"])
        )

    def test_namespace_probe_diagnostic_is_bounded(self) -> None:
        """A forced gate explains capability failure without echoing helper output."""

        available, reason = self._failed_namespace_probe(
            "unshare: Operation not permitted; sensitive fixture path"
        )
        self.assertFalse(available)
        self.assertEqual(reason, "unshare operation not permitted")
        self.assertNotIn("sensitive", reason)

    def test_namespace_probe_diagnostic_uses_only_fixed_categories(self) -> None:
        """Nested setup diagnostics remain useful without exposing child stderr."""

        cases = (
            ("unshare: cannot set groups; sensitive fixture path", "", 1, "namespace group mapping unavailable"),
            ("No-CRS namespace blocked: trusted namespace setup attestation timed out", "", 1, "namespace setup attestation failed"),
            ("No-CRS namespace blocked: trusted namespace setup did not attest readiness", "", 1, "namespace setup attestation failed"),
            ("lighttpd_no_crs_fixture_namespace: BLOCKED: namespace final verifier retained CapBnd", "", 1, "namespace final-state verification failed"),
            ("bwrap: creating namespace failed; sensitive fixture path", "", 1, "bubblewrap namespace setup failed"),
            ("unshare: unsupported flag; sensitive fixture path", "", 1, "unshare namespace setup failed"),
            ("No-CRS namespace blocked: unexpected setup detail", "", 1, "trusted namespace setup blocked"),
            ("lighttpd_no_crs_fixture_namespace: probe phase setup-attested", "", 1, "namespace child failed after setup attestation"),
            ("lighttpd_no_crs_fixture_namespace: probe phase final-state-verified", "", 1, "namespace payload failed after final-state verification"),
            (
                "lighttpd_no_crs_fixture_namespace: probe phase helper-raised-before-return",
                "",
                1,
                "namespace caller identity validation failed",
            ),
            (
                "\n".join(
                    (
                        "lighttpd_no_crs_fixture_namespace: probe phase caller-identity-validated",
                        "lighttpd_no_crs_fixture_namespace: probe phase helper-raised-before-return",
                    )
                ),
                "",
                1,
                "trusted namespace binary validation failed",
            ),
            (
                "\n".join(
                    (
                        "lighttpd_no_crs_fixture_namespace: probe phase trusted-binaries-validated",
                        "lighttpd_no_crs_fixture_namespace: probe phase helper-raised-before-return",
                    )
                ),
                "",
                1,
                "namespace setup pipe creation failed",
            ),
            (
                "\n".join(
                    (
                        "lighttpd_no_crs_fixture_namespace: probe phase setup-pipe-created",
                        "lighttpd_no_crs_fixture_namespace: probe phase helper-raised-before-return",
                    )
                ),
                "",
                1,
                "namespace setup pipe inheritance failed",
            ),
            (
                "\n".join(
                    (
                        "lighttpd_no_crs_fixture_namespace: probe phase namespace-command-build-started",
                        "lighttpd_no_crs_fixture_namespace: probe phase helper-raised-before-return",
                    )
                ),
                "",
                1,
                "namespace command construction failed",
            ),
            (
                "\n".join(
                    (
                        "lighttpd_no_crs_fixture_namespace: probe phase namespace-fork-started",
                        "lighttpd_no_crs_fixture_namespace: probe phase helper-raised-before-return",
                    )
                ),
                "",
                1,
                "namespace child fork failed",
            ),
            (
                "\n".join(
                    (
                        "lighttpd_no_crs_fixture_namespace: probe phase namespace-child-forked",
                        "lighttpd_no_crs_fixture_namespace: probe phase helper-raised-before-return",
                    )
                ),
                "",
                1,
                "namespace helper failed after namespace child fork before setup wait",
            ),
            (
                "\n".join(
                    (
                        "lighttpd_no_crs_fixture_namespace: probe phase setup-wait-started",
                        "lighttpd_no_crs_fixture_namespace: probe phase setup-attestation-failed",
                    )
                ),
                "",
                1,
                "unshare namespace setup failed before entry",
            ),
            (
                "\n".join(
                    (
                        "lighttpd_no_crs_fixture_namespace: probe phase outer-unshare-entered",
                        "lighttpd_no_crs_fixture_namespace: probe phase setup-attestation-failed",
                    )
                ),
                "",
                1,
                "outer private namespace setup failed before bubblewrap",
            ),
            (
                "\n".join(
                    (
                        "lighttpd_no_crs_fixture_namespace: probe phase bwrap-exec",
                        "lighttpd_no_crs_fixture_namespace: probe phase setup-attestation-failed",
                    )
                ),
                "",
                1,
                "bubblewrap namespace setup failed before attestation",
            ),
            ("", "AppArmor: Permission denied; sensitive fixture path", 1, "namespace operation permission denied"),
            ("", "bwrap: setup failed; sensitive fixture path", 1, "bubblewrap namespace setup failed"),
            ("", "", HELPER.EXIT_BLOCKED, "trusted namespace helper blocked"),
            ("", "", HELPER.EXIT_TIMEOUT, "namespace probe timed out"),
            ("", "", 126, "namespace setup execution failed"),
            ("unrecognized sensitive fixture path", "", 1, "namespace probe exited with status 1"),
            ("", "", 255, "namespace probe exited with status 255"),
        )
        for stderr, stdout, returncode, expected in cases:
            with self.subTest(stderr=stderr, stdout=stdout, returncode=returncode):
                available, reason = self._failed_namespace_probe(stderr, returncode, stdout)
                self.assertFalse(available)
                self.assertEqual(reason, expected)
                self.assertNotIn("sensitive", reason)

    def test_namespace_probe_phase_markers_are_explicit_and_opt_in(self) -> None:
        """Only the bounded probe enables its fixed helper phase markers."""

        ordinary_environment = HELPER._child_environment({})
        diagnostic_environment = HELPER._child_environment(
            {}, emit_probe_phase_markers=True
        )
        self.assertNotIn("LIGHTTPD_NAMESPACE_PROBE_PHASES", ordinary_environment)
        self.assertEqual(diagnostic_environment["LIGHTTPD_NAMESPACE_PROBE_PHASES"], "1")
        self.assertIn("probe phase final-state-verified", HELPER.FINAL_NAMESPACE_STATE_VERIFIER)
        self.assertIn("LIGHTTPD_NAMESPACE_PROBE_PHASES", HELPER.PRIVATE_TMPFS_SETUP)
        self.assertIn("probe phase outer-unshare-entered", HELPER.PRIVATE_TMPFS_SETUP)
        self.assertIn("probe phase outer-tmpfs-mounted", HELPER.PRIVATE_TMPFS_SETUP)
        self.assertIn("probe phase bwrap-exec", HELPER.PRIVATE_TMPFS_SETUP)
        self.assertEqual(
            HELPER._PROBE_PHASES,
            frozenset(
                {
                    "runner-start",
                    "helper-raised-before-return",
                    "helper-returned",
                    "caller-identity-validated",
                    "trusted-binaries-validated",
                    "setup-pipe-created",
                    "setup-pipe-inheritable",
                    "namespace-command-build-started",
                    "namespace-command-built",
                    "namespace-fork-started",
                    "namespace-child-forked",
                    "setup-wait-started",
                    "setup-attestation-failed",
                    "setup-attested",
                    "child-exited-after-setup",
                }
            ),
        )
        source = _runner_source("pass")
        self.assertIn('helper._emit_probe_phase(True, "runner-start")', source)
        self.assertIn('helper._emit_probe_phase(True, "helper-raised-before-return")', source)
        self.assertIn('helper._emit_probe_phase(True, "helper-returned")', source)
        self.assertIn('"namespace-command-build-started"', HELPER_PATH.read_text(encoding="utf-8"))
        self.assertIn('"namespace-child-forked"', HELPER_PATH.read_text(encoding="utf-8"))
        with self.assertRaises(HELPER.NamespaceUnavailable):
            HELPER._emit_probe_phase(True, "untrusted diagnostic content")

    def test_trusted_namespace_boundary_and_no_unsafe_rmdir_path_exist(self) -> None:
        source = HELPER_PATH.read_text(encoding="utf-8")
        fixture_io = FIXTURE_IO_PATH.read_text(encoding="utf-8")
        fixture_directory = (
            REPO_ROOT / 'connector_suite/adapters/lighttpd/harness/namespace_fixture_directory.py'
        ).read_text(encoding="utf-8")
        self.assertIn('TRUSTED_UNSHARE = SYSTEM_BIN_ROOT / "unshare"', source)
        self.assertIn('TRUSTED_BWRAP = SYSTEM_BIN_ROOT / "bwrap"', source)
        self.assertIn('TRUSTED_DASH = SYSTEM_BIN_ROOT / "dash"', source)
        self.assertIn('TRUSTED_MOUNT = SYSTEM_BIN_ROOT / "mount"', source)
        self.assertIn("PRIVATE_TMPFS_SETUP = (", source)
        self.assertIn(
            'f"{TRUSTED_MOUNT} -t tmpfs -o mode=0755,nosuid,nodev,noexec,size=64m "',
            source,
        )
        self.assertIn('"--user"', source)
        self.assertIn('"--map-root-user"', source)
        self.assertIn('"--propagation"', source)
        self.assertIn('"private"', source)
        self.assertIn('"--unshare-user"', source)
        self.assertIn('"--unshare-pid"', source)
        self.assertIn('"--disable-userns"', source)
        self.assertIn('"--assert-userns-disabled"', source)
        self.assertIn('"--bind"', source)
        self.assertIn('"--clearenv"', source)
        self.assertIn('"--cap-drop"', source)
        self.assertIn('"ALL"', source)
        self.assertIn("def _seal_inherited_descriptors", source)
        self.assertIn("_seal_inherited_descriptors({0, 1, 2, setup_write})", source)
        self.assertIn("PR_SET_PDEATHSIG = 1", source)
        self.assertIn("_arm_parent_death_signal()", source)
        self.assertIn('"--kill-child=SIGKILL"', source)
        self.assertIn('"--die-with-parent"', source)
        self.assertIn("FINAL_NAMESPACE_STATE_VERIFIER", source)
        self.assertIn("LIGHTTPD_NO_CRS_FIXTURE_ROOT_IDENTITY", source)
        self.assertNotIn('"--tmpfs"', source)
        self.assertIn("host-root caller", source)
        self.assertIn('PRIVATE_TMPFS_MOUNT = _ROOT / "tmp"', source)
        self.assertNotIn("os.rmdir(", source)
        self.assertNotIn("os.unlink(", source)
        self.assertNotIn("AT_EMPTY_PATH", source)
        self.assertNotIn("os.rmdir(", fixture_io)
        self.assertNotIn("os.rmdir(", fixture_directory)
        self.assertNotIn("os.unlink(", fixture_directory)
        self.assertIn("leaves-retained-for-namespace-lifecycle", fixture_io)
        self.assertIn('f"{_FIXTURE_ROOT_LABEL} identity changed"', fixture_directory)
        self.assertIn("verify_allowed_leaves", fixture_directory)

    def test_missing_trusted_binary_fails_closed(self) -> None:
        original_identity = HELPER._caller_identity
        original_binaries = HELPER._require_trusted_system_binaries
        try:
            HELPER._caller_identity = lambda: HELPER.CallerIdentity(uid=1001, gid=1002)
            HELPER._require_trusted_system_binaries = lambda: (_ for _ in ()).throw(
                HELPER.NamespaceUnavailable("trusted binary missing")
            )
            with self.assertRaises(HELPER.NamespaceUnavailable):
                HELPER.run_isolated([PYTHON, "-c", "pass"])
        finally:
            HELPER._caller_identity = original_identity
            HELPER._require_trusted_system_binaries = original_binaries

    def test_direct_root_entry_cannot_become_a_fallback(self) -> None:
        if os.geteuid() != 0:
            self.skipTest("direct-root guard is only meaningful when running as root")
        with self.assertRaises(HELPER.NamespaceUnavailable):
            HELPER.run_isolated([PYTHON, "-c", "pass"])

    def test_descriptor_fixture_server_uses_the_available_one_shot_api(self) -> None:
        """Catch API drift even when the kernel namespace tests are gated."""

        import connector_suite.adapters.lighttpd.harness.lighttpd_http1_entity_fixture_upstream as fixture

        calls: list[tuple[str, str, str]] = []
        case = self

        class Directory:
            def require_absent(self, name: str, label: str) -> None:
                calls.append(("absent", name, label))

            def write_text_fresh(self, name: str, value: str, label: str) -> None:
                decoded = json.loads(value)
                case.assertEqual(decoded["schema_version"], 1)
                calls.append(("write", name, label))

        directory = Directory()

        def fake_exchange(**kwargs: object) -> None:
            publish_ready = kwargs["publish_ready"]
            publish_result = kwargs["publish_result"]
            self.assertTrue(callable(publish_ready))
            self.assertTrue(callable(publish_result))
            publish_ready({"schema_version": 1})
            publish_result({"schema_version": 1})

        with mock.patch.object(fixture, "serve_exchange", side_effect=fake_exchange):
            fixture.serve_bound(
                directory=directory,
                ready_name="upstream-ready.json",
                result_name="result.json",
                host="127.0.0.1",
                port=0,
                timeout=1,
                inter_part_delay=0.1,
            )
        self.assertEqual(
            calls,
            [
                ("absent", "upstream-ready.json", "ready file"),
                ("absent", "result.json", "result file"),
                ("write", "upstream-ready.json", "ready file"),
                ("write", "result.json", "result file"),
            ],
        )



@unittest.skipUnless(_user_namespace_available(), "requires unprivileged user/mount/PID namespaces")
class NamespaceIntegrationTest(unittest.TestCase):
    def _assert_host_tmpfs_restored(self, before: list[str]) -> None:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if _mountinfo_for_mountpoint(HELPER.PRIVATE_TMPFS_MOUNT) == before:
                return
            time.sleep(0.05)
        self.assertEqual(_mountinfo_for_mountpoint(HELPER.PRIVATE_TMPFS_MOUNT), before)

    def _assert_host_fixture_unchanged(
        self, before: tuple[int, int, int, int] | None
    ) -> None:
        self.assertEqual(_host_path_snapshot(HELPER.FIXTURE_ROOT), before)

    def _assert_task_temp_root_removed(self, temporary: str) -> None:
        self.assertFalse(Path(temporary).exists(), f"task temporary root remained: {temporary}")

    def _assert_no_task_helper_process(self, marker: str) -> None:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if not _processes_containing_marker(marker):
                return
            time.sleep(0.05)
        self.assertEqual(_processes_containing_marker(marker), [])

    def _payload(self, output: Path, *, mode: str = "success") -> str:
        return textwrap.dedent(
            f"""
            import json, os, pathlib, signal, time
            root = pathlib.Path(os.environ["LIGHTTPD_NO_CRS_FIXTURE_ROOT"])
            result = {{"uid": os.getuid(), "gid": os.getgid(), "root": str(root)}}
            root_details = root.stat()
            result["fixture_root"] = {{
                "mode": root_details.st_mode & 0o777,
                "uid": root_details.st_uid,
                "gid": root_details.st_gid,
                "is_directory": root.is_dir(),
                "identity": f"{{root_details.st_dev}}:{{root_details.st_ino}}",
            }}
            result["fixture_root_attestation"] = os.environ.get(
                "LIGHTTPD_NO_CRS_FIXTURE_ROOT_IDENTITY"
            )
            result["open_fds"] = _live_descriptor_snapshot()
            status = {{}}
            for line in pathlib.Path("/proc/self/status").read_text().splitlines():
                key, sep, value = line.partition(":")
                if sep and key in {{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs"}}:
                    status[key] = value.strip()
            result["status"] = status
            mount_rows = pathlib.Path("/proc/self/mountinfo").read_text().splitlines()
            selected_mounts = []
            for row in mount_rows:
                before, separator, after = row.partition(" - ")
                fields = before.split()
                if separator and len(fields) >= 6 and fields[4] in {{"/", "/tmp"}}:
                    selected_mounts.append((fields, after.split(), row))
            result["mountinfo"] = [row for _fields, _after, row in selected_mounts]
            result["private_propagation"] = all(
                not any(field.startswith(("shared:", "master:")) for field in fields[6:])
                for fields, _after, _row in selected_mounts
            )
            result["private_tmpfs"] = any(
                fields[4] == "/tmp"
                and after and after[0] == "tmpfs"
                and {{"nosuid", "nodev", "noexec"}}.issubset(set(fields[5].split(",")))
                for fields, after, _row in selected_mounts
            )
            if {mode!r} == "race":
                candidate = root / "candidate"
                candidate.mkdir()
                sentinel = candidate / "attacker-sentinel"
                sentinel.write_text("preserve")
                for index in range(250):
                    moved = root / ("candidate.old." + str(index))
                    try:
                        candidate.rename(moved)
                        candidate = root / "candidate"
                        candidate.mkdir()
                        (candidate / "attacker-sentinel").write_text("preserve")
                    except OSError:
                        pass
                result["sentinel"] = any(path.name.startswith("candidate.old.") for path in root.iterdir())
            pathlib.Path({str(output)!r}).write_text(json.dumps(result), encoding="utf-8")
            if {mode!r} == "nonzero":
                raise SystemExit(23)
            if {mode!r} == "crash":
                os._exit(42)
            if {mode!r} == "sleep":
                time.sleep(30)
            """
        )

    def _run(self, temporary: str, *, mode: str = "success", timeout: float = 3.0) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
        output = Path(temporary) / f"result-{mode}.json"
        # The candidate sees a private tmpfs on /tmp, so evidence is written
        # to this task-owned /var/tmp directory, made traversable solely for
        # the mapped unprivileged caller.
        os.chmod(temporary, 0o777)
        result = _run_runner(
            _runner_source(
                self._payload(output, mode=mode),
                timeout=timeout,
                writable_roots=(Path(temporary),),
            ),
            timeout=timeout + 8,
        )
        data = json.loads(output.read_text(encoding="utf-8")) if output.exists() else {}
        return result, data

    def test_private_mount_drops_identity_capabilities_and_hides_fixture_from_host(self) -> None:
        before = _mountinfo_for_mountpoint(HELPER.PRIVATE_TMPFS_MOUNT)
        host_fixture_before = _host_path_snapshot(HELPER.FIXTURE_ROOT)
        self.assertIsNone(host_fixture_before, "host has a stale private fixture root")
        with tempfile.TemporaryDirectory(prefix="lighttpd-namespace-test-", dir=TEST_TEMP_PARENT) as temporary:
            result, data = self._run(temporary)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(data["uid"], 0)
            self.assertEqual(data["gid"], 0)
            self.assertTrue(data["fixture_root"]["is_directory"])
            self.assertEqual(data["fixture_root"]["mode"], 0o700)
            self.assertEqual(data["fixture_root"]["uid"], 0)
            self.assertEqual(data["fixture_root"]["gid"], 0)
            self.assertEqual(
                data["fixture_root"]["identity"], data["fixture_root_attestation"]
            )
            self.assertEqual(data["open_fds"], [0, 1, 2])
            self.assertEqual(data["status"]["NoNewPrivs"], "1")
            for field in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
                self.assertEqual(data["status"][field], "0000000000000000")
            self.assertTrue(any(" - tmpfs " in line for line in data["mountinfo"]))
            self.assertTrue(data["private_propagation"])
            self.assertTrue(data["private_tmpfs"])
            self._assert_host_tmpfs_restored(before)
            self._assert_no_task_helper_process(str(Path(temporary) / "result-success.json"))
        self._assert_host_fixture_unchanged(host_fixture_before)
        self._assert_task_temp_root_removed(temporary)

    def test_same_uid_replacement_race_stays_inside_private_mount(self) -> None:
        before = _mountinfo_for_mountpoint(HELPER.PRIVATE_TMPFS_MOUNT)
        host_fixture_before = _host_path_snapshot(HELPER.FIXTURE_ROOT)
        self.assertIsNone(host_fixture_before, "host has a stale private fixture root")
        with tempfile.TemporaryDirectory(prefix="lighttpd-namespace-race-", dir=TEST_TEMP_PARENT) as temporary:
            os.chmod(temporary, 0o777)
            old_smoke_root = Path(temporary) / "old-smoke"
            old_smoke_root.mkdir(mode=0o777)
            old_smoke_root.chmod(0o777)
            old_fixture = old_smoke_root / ".entity-fixtures-race"
            old_fixture.mkdir(mode=0o777)
            old_fixture.chmod(0o777)
            attacker_sentinel = old_smoke_root / "attacker-sentinel"
            attacker_sentinel.write_text("must-survive", encoding="utf-8")
            attacker_sentinel.chmod(0o666)
            attacker_source = textwrap.dedent(
                """
                import pathlib, sys, time
                root = pathlib.Path(sys.argv[1])
                for index in range(1000):
                    moved = root.parent / (root.name + ".old." + str(index))
                    try:
                        root.rename(moved)
                    except OSError:
                        pass
                    try:
                        root.mkdir(mode=0o777)
                        (root / "attacker-sentinel").write_text("must-survive", encoding="utf-8")
                    except OSError:
                        pass
                """
            )
            attacker = subprocess.Popen(
                [PYTHON, "-c", attacker_source, str(old_fixture)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                preexec_fn=_drop_runner_to_unprivileged_identity,
            )
            try:
                result, data = self._run(temporary, mode="race")
            finally:
                attacker.terminate()
                attacker.wait(timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn(str(old_smoke_root), data["root"])
            self.assertEqual(data["open_fds"], [0, 1, 2])
            self.assertTrue(attacker_sentinel.exists())
            self.assertEqual(attacker_sentinel.read_text(encoding="utf-8"), "must-survive")
            self.assertTrue(any(path.name.startswith(old_fixture.name + ".old.") for path in old_smoke_root.iterdir()))
            self._assert_no_task_helper_process(str(Path(temporary) / "result-race.json"))
        self._assert_host_tmpfs_restored(before)
        self._assert_host_fixture_unchanged(host_fixture_before)
        self._assert_task_temp_root_removed(temporary)

    def _fixture_lifecycle_payload(self, output: Path) -> str:
        """Exercise the real descriptor I/O CLI entirely inside the tmpfs."""

        return textwrap.dedent(
            f"""
            import json, os, pathlib, re, subprocess, sys

            root = pathlib.Path(os.environ["LIGHTTPD_NO_CRS_FIXTURE_ROOT"])
            io = {str(FIXTURE_IO_PATH)!r}

            def invoke(*arguments, expected=0):
                completed = subprocess.run(
                    [{PYTHON!r}, io, *arguments],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                )
                if completed.returncode != expected:
                    raise RuntimeError(
                        "fixture command {{!r}} returned {{}}: {{}}".format(
                            arguments, completed.returncode, completed.stderr
                        )
                    )
                return completed

            created = invoke("create", "--runtime-output-root", str(root))
            name, identity = created.stdout.strip().split("\\t")
            if not re.fullmatch(r"\\.entity-fixtures-[a-f0-9]{{32}}", name):
                raise RuntimeError("fixture name is not opaque")
            fixture = root / name
            server = subprocess.Popen(
                [
                    {PYTHON!r}, io, "serve", "--runtime-output-root", str(root),
                    "--fixture-name", name, "--fixture-identity", identity,
                    "--timeout", "10",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                ready = invoke(
                    "wait-ready", "--runtime-output-root", str(root),
                    "--fixture-name", name, "--fixture-identity", identity,
                    "--fixture-pid", str(server.pid), "--timeout", "10",
                )
                port = ready.stdout.strip()
                if not re.fullmatch(r"[1-9][0-9]{{0,4}}", port):
                    raise RuntimeError("fixture did not publish a port")
                for case in ("content-length", "chunked"):
                    response = invoke(
                        "curl-case", "--runtime-output-root", str(root),
                        "--fixture-name", name, "--fixture-identity", identity,
                        "--case", case, "--port", port,
                    )
                    if response.stdout.strip() != "200":
                        raise RuntimeError("fixture curl case did not receive 200")
                _stdout, stderr = server.communicate(timeout=12)
                if server.returncode != 0:
                    raise RuntimeError("fixture server failed: " + stderr)
                invoke(
                    "verify", "--runtime-output-root", str(root),
                    "--fixture-name", name, "--fixture-identity", identity,
                )
                leaves = {{entry.name: entry.stat().st_mode & 0o777 for entry in fixture.iterdir()}}
                result = json.loads((fixture / "result.json").read_text(encoding="utf-8"))
                headers = {{
                    "content_length": (fixture / "content-length.headers").read_text(encoding="ascii"),
                    "chunked": (fixture / "chunked.headers").read_text(encoding="ascii"),
                }}
                cleaned = invoke(
                    "cleanup", "--runtime-output-root", str(root),
                    "--fixture-name", name, "--fixture-identity", identity,
                )
                if cleaned.stdout.strip() != "leaves-retained-for-namespace-lifecycle":
                    raise RuntimeError("fixture cleanup used an unexpected path")
                retained_leaves = {{entry.name for entry in fixture.iterdir()}}
                if retained_leaves != set({{
                    "upstream-ready.json", "result.json", "upstream.stdout",
                    "upstream.stderr", "content-length.headers", "chunked.headers",
                }}):
                    raise RuntimeError("namespace cleanup did not retain exactly the verified leaves")
                open_fds = _live_descriptor_snapshot()
                pathlib.Path({str(output)!r}).write_text(
                    json.dumps({{
                        "root": str(root), "name": name, "identity": identity,
                        "fixture_mode": fixture.stat().st_mode & 0o777,
                        "leaves": leaves, "result": result, "headers": headers,
                        "server_returncode": server.returncode,
                        "open_fds": open_fds,
                        "cleanup_retained_verified_leaves": retained_leaves == set(leaves),
                    }}, sort_keys=True),
                    encoding="utf-8",
                )
            finally:
                if server.poll() is None:
                    server.terminate()
                    server.wait(timeout=5)
            """
        )

    def test_descriptor_fixture_io_lifecycle_is_real_private_and_host_mount_disappears(self) -> None:
        mountpoint = HELPER.PRIVATE_TMPFS_MOUNT
        before = _mountinfo_for_mountpoint(mountpoint)
        host_fixture_before = _host_path_snapshot(HELPER.FIXTURE_ROOT)
        self.assertIsNone(host_fixture_before, "host has a stale private fixture root")
        with tempfile.TemporaryDirectory(prefix="lighttpd-namespace-fixture-io-", dir=TEST_TEMP_PARENT) as temporary:
            output = Path(temporary) / "lifecycle.json"
            os.chmod(temporary, 0o777)
            result = _run_runner(
                _runner_source(
                    self._fixture_lifecycle_payload(output),
                    timeout=30,
                    writable_roots=(Path(temporary),),
                ),
                timeout=40,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(data["root"], str(HELPER.FIXTURE_ROOT))
            self.assertRegex(data["name"], r"^\.entity-fixtures-[a-f0-9]{32}$")
            self.assertEqual(data["fixture_mode"], 0o700)
            self.assertEqual(data["server_returncode"], 0)
            self.assertEqual(data["open_fds"], [0, 1, 2])
            self.assertTrue(data["cleanup_retained_verified_leaves"])
            self.assertEqual(
                set(data["leaves"]),
                {
                    "upstream-ready.json", "result.json", "upstream.stdout", "upstream.stderr",
                    "content-length.headers", "chunked.headers",
                },
            )
            self.assertTrue(all(mode == 0o600 for mode in data["leaves"].values()))
            self.assertEqual(data["result"]["content_length_requests"], 1)
            self.assertEqual(data["result"]["chunked_requests"], 1)
            self.assertIn("Content-Length:", data["headers"]["content_length"])
            self.assertIn("Transfer-Encoding: chunked", data["headers"]["chunked"])
            self._assert_no_task_helper_process(str(output))
        self._assert_host_tmpfs_restored(before)
        self._assert_host_fixture_unchanged(host_fixture_before)
        self._assert_task_temp_root_removed(temporary)

    def _rejection_and_race_payload(self, output: Path) -> str:
        """Migrate legacy arbitrary-root negative cases into the fixed tmpfs."""

        return textwrap.dedent(
            f"""
            import json, os, pathlib, subprocess, sys, time

            root = pathlib.Path(os.environ["LIGHTTPD_NO_CRS_FIXTURE_ROOT"])
            io = {str(FIXTURE_IO_PATH)!r}

            def invoke(*arguments):
                return subprocess.run(
                    [{PYTHON!r}, io, *arguments], stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, text=True, check=False,
                )

            def create():
                completed = invoke("create", "--runtime-output-root", str(root))
                if completed.returncode != 0:
                    raise RuntimeError("create failed: " + completed.stderr)
                return completed.stdout.strip().split("\\t")

            def fixture_args(name, identity):
                return ("--runtime-output-root", str(root), "--fixture-name", name,
                        "--fixture-identity", identity)

            outside = root / "outside"
            outside.mkdir(mode=0o700)
            outside_marker = outside / "outside-sentinel"
            outside_marker.write_text("must-survive", encoding="utf-8")
            legacy = root / "entity-fixtures"
            legacy.mkdir(mode=0o700)
            legacy_directory_rejected = invoke("create", "--runtime-output-root", str(root)).returncode != 0
            legacy.rename(root / "legacy-directory-held")
            legacy.symlink_to(outside, target_is_directory=True)
            legacy_symlink_rejected = invoke("create", "--runtime-output-root", str(root)).returncode != 0
            legacy.unlink()

            name, identity = create()
            device, inode = identity.split(":", 1)
            fixture = root / name
            wrong_identity_rejected = invoke("verify", *fixture_args(name, f"{{device}}:{{int(inode) + 1}}")).returncode != 0

            fixture.rename(root / (name + ".original"))
            fixture.mkdir(mode=0o700)
            replacement_sentinel = fixture / "replacement-sentinel"
            replacement_sentinel.write_text("must-survive", encoding="utf-8")
            replacement_verify_rejected = invoke("verify", *fixture_args(name, identity)).returncode != 0
            replacement_cleanup_rejected = invoke("cleanup", *fixture_args(name, identity)).returncode != 0
            replacement_survives = replacement_sentinel.read_text(encoding="utf-8") == "must-survive"
            fixture.rename(root / (name + ".replacement-held"))
            fixture.symlink_to(outside, target_is_directory=True)
            symlink_verify_rejected = invoke("verify", *fixture_args(name, identity)).returncode != 0
            symlink_cleanup_rejected = invoke("cleanup", *fixture_args(name, identity)).returncode != 0
            symlink_outside_survives = outside_marker.read_text(encoding="utf-8") == "must-survive"
            fixture.unlink()

            name, identity = create()
            fixture = root / name
            unexpected = fixture / "unexpected"
            unexpected.write_text("must-survive", encoding="utf-8")
            unexpected_cleanup_rejected = invoke("cleanup", *fixture_args(name, identity)).returncode != 0
            unexpected_survives = unexpected.read_text(encoding="utf-8") == "must-survive"
            unexpected.unlink()
            ordinary_cleanup = invoke("cleanup", *fixture_args(name, identity)).returncode == 0
            traversal_verify_rejected = invoke("verify", "--runtime-output-root", str(root), "--fixture-name", "../outside", "--fixture-identity", "1:1").returncode != 0
            traversal_cleanup_rejected = invoke("cleanup", "--runtime-output-root", str(root), "--fixture-name", "../outside", "--fixture-identity", "1:1").returncode != 0

            race_successes = 0
            for index in range(10):
                name, identity = create()
                stop = root / ("race-stop-" + str(index))
                # The attacker is a distinct process at the same namespace UID.
                attacker_source = (
                    "import os, pathlib, sys, time\\n"
                    "root = pathlib.Path(sys.argv[1])\\n"
                    "name = sys.argv[2]\\n"
                    "stop = pathlib.Path(sys.argv[3])\\n"
                    "def replace(counter):\\n"
                    "    target = root / name\\n"
                    "    try:\\n"
                    "        target.rename(root / (name + '.attacker.' + str(counter)))\\n"
                    "    except OSError:\\n"
                    "        pass\\n"
                    "    try:\\n"
                    "        target.mkdir(mode=0o700)\\n"
                    "        (target / 'attacker-sentinel').write_text('must-survive', encoding='utf-8')\\n"
                    "    except OSError:\\n"
                    "        pass\\n"
                    "replace('initial')\\n"
                    "print('ready', flush=True)\\n"
                    "counter = 0\\n"
                    "while not stop.exists():\\n"
                    "    replace(counter)\\n"
                    "    counter += 1\\n"
                    "replace('final')\\n"
                )
                process = subprocess.Popen(
                    [{PYTHON!r}, "-c", attacker_source, str(root), name, str(stop)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                )
                try:
                    if process.stdout is None or process.stdout.readline().strip() != "ready":
                        raise RuntimeError("same-UID attacker did not start")
                    cleanup = invoke("cleanup", *fixture_args(name, identity))
                    if cleanup.returncode == 0:
                        raise RuntimeError("cleanup accepted a same-UID replacement")
                    stop.write_text("stop", encoding="utf-8")
                    _stdout, stderr = process.communicate(timeout=5)
                    if process.returncode != 0:
                        raise RuntimeError("same-UID attacker failed: " + stderr)
                    sentinel = root / name / "attacker-sentinel"
                    if sentinel.read_text(encoding="utf-8") != "must-survive":
                        raise RuntimeError("cleanup deleted attacker replacement")
                    race_successes += 1
                finally:
                    if process.poll() is None:
                        process.terminate()
                        process.wait(timeout=5)

            # The fixed root itself is separately attested by the trusted
            # final verifier.  A same-UID replacement must fail before a
            # fixture operation can even resolve a child name.
            original_root = root.parent / (root.name + ".original")
            root.rename(original_root)
            root.mkdir(mode=0o700)
            root_replacement_sentinel = root / "root-replacement-sentinel"
            root_replacement_sentinel.write_text("must-survive", encoding="utf-8")
            root_replacement_create_rejected = invoke(
                "create", "--runtime-output-root", str(root)
            ).returncode != 0
            root_replacement_verify_rejected = invoke(
                "verify", "--runtime-output-root", str(root),
                "--fixture-name", ".entity-fixtures-" + "0" * 32,
                "--fixture-identity", "1:1",
            ).returncode != 0
            root_replacement_survives = (
                root_replacement_sentinel.read_text(encoding="utf-8") == "must-survive"
            )

            pathlib.Path({str(output)!r}).write_text(json.dumps({{
                "legacy_directory_rejected": legacy_directory_rejected,
                "legacy_symlink_rejected": legacy_symlink_rejected,
                "wrong_identity_rejected": wrong_identity_rejected,
                "replacement_verify_rejected": replacement_verify_rejected,
                "replacement_cleanup_rejected": replacement_cleanup_rejected,
                "replacement_survives": replacement_survives,
                "symlink_verify_rejected": symlink_verify_rejected,
                "symlink_cleanup_rejected": symlink_cleanup_rejected,
                "symlink_outside_survives": symlink_outside_survives,
                "unexpected_cleanup_rejected": unexpected_cleanup_rejected,
                "unexpected_survives": unexpected_survives,
                "ordinary_cleanup": ordinary_cleanup,
                "traversal_verify_rejected": traversal_verify_rejected,
                "traversal_cleanup_rejected": traversal_cleanup_rejected,
                "race_iterations": race_successes,
                "root_replacement_create_rejected": root_replacement_create_rejected,
                "root_replacement_verify_rejected": root_replacement_verify_rejected,
                "root_replacement_survives": root_replacement_survives,
            }}, sort_keys=True), encoding="utf-8")
            """
        )

    def test_private_descriptor_rejections_and_same_uid_actual_fixture_race(self) -> None:
        mountpoint = HELPER.PRIVATE_TMPFS_MOUNT
        before = _mountinfo_for_mountpoint(mountpoint)
        host_fixture_before = _host_path_snapshot(HELPER.FIXTURE_ROOT)
        self.assertIsNone(host_fixture_before, "host has a stale private fixture root")
        with tempfile.TemporaryDirectory(prefix="lighttpd-namespace-rejections-", dir=TEST_TEMP_PARENT) as temporary:
            output = Path(temporary) / "negative.json"
            os.chmod(temporary, 0o777)
            result = _run_runner(
                _runner_source(
                    self._rejection_and_race_payload(output),
                    timeout=55,
                    writable_roots=(Path(temporary),),
                ),
                timeout=65,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads(output.read_text(encoding="utf-8"))
            for key, value in data.items():
                if key == "race_iterations":
                    self.assertGreaterEqual(value, 10)
                else:
                    self.assertTrue(value, key)
            self._assert_no_task_helper_process(str(output))
        self._assert_host_tmpfs_restored(before)
        self._assert_host_fixture_unchanged(host_fixture_before)
        self._assert_task_temp_root_removed(temporary)

    def _fixed_root_create_race_payload(self, output: Path) -> str:
        """Race the fixed root exactly after its create identity attestation."""

        return textwrap.dedent(
            f"""
            import json, os, pathlib, subprocess, sys, time

            import connector_suite.adapters.lighttpd.harness.namespace_fixture_directory as fixture_directory

            root = pathlib.Path(os.environ["LIGHTTPD_NO_CRS_FIXTURE_ROOT"])
            barrier = root.parent / ".fixed-root-race-attested"
            replaced = root.parent / ".fixed-root-race-replaced"
            original_root = root.parent / (root.name + ".race-original")
            for path in (barrier, replaced, original_root):
                if path.exists() or path.is_symlink():
                    raise RuntimeError("fixed root race setup unexpectedly exists: " + str(path))

            attacker_source = (
                "import pathlib, sys, time\\n"
                "root = pathlib.Path(sys.argv[1])\\n"
                "barrier = pathlib.Path(sys.argv[2])\\n"
                "replaced = pathlib.Path(sys.argv[3])\\n"
                "original = pathlib.Path(sys.argv[4])\\n"
                "print('ready', flush=True)\\n"
                "deadline = time.monotonic() + 10\\n"
                "while not barrier.exists() and time.monotonic() < deadline:\\n"
                "    time.sleep(0.01)\\n"
                "if not barrier.exists():\\n"
                "    raise SystemExit('fixture root was never attested')\\n"
                "root.rename(original)\\n"
                "root.mkdir(mode=0o700)\\n"
                "(root / 'attacker-root-sentinel').write_text('must-survive', encoding='utf-8')\\n"
                "replaced.write_text('replaced', encoding='ascii')\\n"
            )
            attacker = subprocess.Popen(
                [{PYTHON!r}, "-c", attacker_source, str(root), str(barrier),
                 str(replaced), str(original_root)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            original_fixture_root = fixture_directory._fixture_root

            def after_attestation(value):
                accepted = original_fixture_root(value)
                barrier.write_text("attested", encoding="ascii")
                deadline = time.monotonic() + 10
                while not replaced.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                if not replaced.exists():
                    raise RuntimeError("same-UID attacker did not replace fixed root")
                return accepted

            fixture_directory._fixture_root = after_attestation
            created = None
            create_rejected = False
            try:
                created = fixture_directory.create_namespace_fixture_directory(
                    root,
                    prefix=".entity-fixtures-",
                    rejected_names=("entity-fixtures",),
                )
            except (OSError, ValueError):
                create_rejected = True
            finally:
                fixture_directory._fixture_root = original_fixture_root
            _stdout, stderr = attacker.communicate(timeout=10)
            if attacker.returncode != 0:
                raise RuntimeError("same-UID root attacker failed: " + stderr)

            created_name = None
            held_original_descriptor = False
            if created is not None:
                created_name = created.name
                held_original_descriptor = (
                    isinstance(created_name, str)
                    and (original_root / created_name).is_dir()
                    and not (root / created_name).exists()
                )
                created.close()
            sentinel = root / "attacker-root-sentinel"
            result = {{
                "create_rejected_or_held_original_descriptor": create_rejected or held_original_descriptor,
                "attacker_sentinel_survives": sentinel.read_text(encoding="utf-8") == "must-survive",
                "attacker_root_never_received_fixture": (
                    created_name is None or not (root / created_name).exists()
                ),
                "open_fds": _live_descriptor_snapshot(),
            }}
            pathlib.Path({str(output)!r}).write_text(json.dumps(result, sort_keys=True), encoding="utf-8")
            """
        )

    def test_same_uid_fixed_root_create_race_never_uses_attacker_root(self) -> None:
        before = _mountinfo_for_mountpoint(HELPER.PRIVATE_TMPFS_MOUNT)
        host_fixture_before = _host_path_snapshot(HELPER.FIXTURE_ROOT)
        self.assertIsNone(host_fixture_before, "host has a stale private fixture root")
        with tempfile.TemporaryDirectory(prefix="lighttpd-namespace-root-race-", dir=TEST_TEMP_PARENT) as temporary:
            output = Path(temporary) / "root-race.json"
            os.chmod(temporary, 0o777)
            result = _run_runner(
                _runner_source(
                    self._fixed_root_create_race_payload(output),
                    timeout=25,
                    writable_roots=(Path(temporary),),
                ),
                timeout=35,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads(output.read_text(encoding="utf-8"))
            self.assertTrue(data["create_rejected_or_held_original_descriptor"])
            self.assertTrue(data["attacker_sentinel_survives"])
            self.assertTrue(data["attacker_root_never_received_fixture"])
            self.assertEqual(data["open_fds"], [0, 1, 2])
            self._assert_no_task_helper_process(str(output))
        self._assert_host_tmpfs_restored(before)
        self._assert_host_fixture_unchanged(host_fixture_before)
        self._assert_task_temp_root_removed(temporary)

    def _fixed_root_open_race_payload(self, output: Path) -> str:
        """Race a fixed-root replacement between open attestation and child open."""

        return textwrap.dedent(
            f"""
            import json, os, pathlib, subprocess, sys, time

            import connector_suite.adapters.lighttpd.harness.namespace_fixture_directory as fixture_directory

            root = pathlib.Path(os.environ["LIGHTTPD_NO_CRS_FIXTURE_ROOT"])
            expected_root = root.stat()
            expected_root_identity = f"{{expected_root.st_dev}}:{{expected_root.st_ino}}"
            baseline = fixture_directory.create_namespace_fixture_directory(
                root,
                prefix=".entity-fixtures-",
                rejected_names=("entity-fixtures",),
            )
            fixture_name, fixture_identity = baseline.name, baseline.identity
            baseline.close()
            barrier = root.parent / ".fixed-root-open-race-attested"
            replaced = root.parent / ".fixed-root-open-race-replaced"
            original_root = root.parent / (root.name + ".open-race-original")
            for path in (barrier, replaced, original_root):
                if path.exists() or path.is_symlink():
                    raise RuntimeError("fixed root open race setup unexpectedly exists: " + str(path))

            attacker_source = (
                "import pathlib, sys, time\\n"
                "root = pathlib.Path(sys.argv[1])\\n"
                "barrier = pathlib.Path(sys.argv[2])\\n"
                "replaced = pathlib.Path(sys.argv[3])\\n"
                "original = pathlib.Path(sys.argv[4])\\n"
                "name = sys.argv[5]\\n"
                "print('ready', flush=True)\\n"
                "deadline = time.monotonic() + 10\\n"
                "while not barrier.exists() and time.monotonic() < deadline:\\n"
                "    time.sleep(0.01)\\n"
                "if not barrier.exists():\\n"
                "    raise SystemExit('fixture root was never attested for open')\\n"
                "root.rename(original)\\n"
                "root.mkdir(mode=0o700)\\n"
                "replacement = root / name\\n"
                "replacement.mkdir(mode=0o700)\\n"
                "(replacement / 'attacker-child-sentinel').write_text('must-survive', encoding='utf-8')\\n"
                "replaced.write_text('replaced', encoding='ascii')\\n"
            )
            attacker = subprocess.Popen(
                [{PYTHON!r}, "-c", attacker_source, str(root), str(barrier),
                 str(replaced), str(original_root), fixture_name],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            original_fixture_root = fixture_directory._fixture_root
            original_open = fixture_directory.os.open
            observed = {{"parent_identity": None}}

            def after_attestation(value):
                accepted = original_fixture_root(value)
                barrier.write_text("attested", encoding="ascii")
                deadline = time.monotonic() + 10
                while not replaced.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                if not replaced.exists():
                    raise RuntimeError("same-UID attacker did not replace fixed root for open")
                return accepted

            def observing_open(path, *args, **kwargs):
                parent = kwargs.get("dir_fd")
                if path == fixture_name and isinstance(parent, int):
                    details = os.fstat(parent)
                    observed["parent_identity"] = f"{{details.st_dev}}:{{details.st_ino}}"
                return original_open(path, *args, **kwargs)

            fixture_directory._fixture_root = after_attestation
            fixture_directory.os.open = observing_open
            opened = None
            open_rejected = False
            try:
                opened = fixture_directory.open_namespace_fixture_directory(
                    root, name=fixture_name, identity=fixture_identity
                )
            except (OSError, ValueError):
                open_rejected = True
            finally:
                fixture_directory._fixture_root = original_fixture_root
                fixture_directory.os.open = original_open
            _stdout, stderr = attacker.communicate(timeout=10)
            if attacker.returncode != 0:
                raise RuntimeError("same-UID root open attacker failed: " + stderr)

            held_original_descriptor = False
            if opened is not None:
                held_details = os.fstat(opened._directory)
                held_original_descriptor = (
                    f"{{held_details.st_dev}}:{{held_details.st_ino}}" == fixture_identity
                )
                opened.close()
            attacker_sentinel = root / fixture_name / "attacker-child-sentinel"
            result = {{
                "open_parent_is_attested_root": observed["parent_identity"] == expected_root_identity,
                "open_rejected_or_held_original_descriptor": open_rejected or held_original_descriptor,
                "attacker_child_sentinel_survives": (
                    attacker_sentinel.read_text(encoding="utf-8") == "must-survive"
                ),
                "open_fds": _live_descriptor_snapshot(),
            }}
            pathlib.Path({str(output)!r}).write_text(json.dumps(result, sort_keys=True), encoding="utf-8")
            """
        )

    def test_same_uid_fixed_root_open_race_uses_only_attested_root_descriptor(self) -> None:
        before = _mountinfo_for_mountpoint(HELPER.PRIVATE_TMPFS_MOUNT)
        host_fixture_before = _host_path_snapshot(HELPER.FIXTURE_ROOT)
        self.assertIsNone(host_fixture_before, "host has a stale private fixture root")
        with tempfile.TemporaryDirectory(prefix="lighttpd-namespace-root-open-race-", dir=TEST_TEMP_PARENT) as temporary:
            output = Path(temporary) / "root-open-race.json"
            os.chmod(temporary, 0o777)
            result = _run_runner(
                _runner_source(
                    self._fixed_root_open_race_payload(output),
                    timeout=25,
                    writable_roots=(Path(temporary),),
                ),
                timeout=35,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads(output.read_text(encoding="utf-8"))
            self.assertTrue(data["open_parent_is_attested_root"])
            self.assertTrue(data["open_rejected_or_held_original_descriptor"])
            self.assertTrue(data["attacker_child_sentinel_survives"])
            self.assertEqual(data["open_fds"], [0, 1, 2])
            self._assert_no_task_helper_process(str(output))
        self._assert_host_tmpfs_restored(before)
        self._assert_host_fixture_unchanged(host_fixture_before)
        self._assert_task_temp_root_removed(temporary)

    def test_nonzero_payload_and_timeout_are_propagated(self) -> None:
        before = _mountinfo_for_mountpoint(HELPER.PRIVATE_TMPFS_MOUNT)
        host_fixture_before = _host_path_snapshot(HELPER.FIXTURE_ROOT)
        self.assertIsNone(host_fixture_before, "host has a stale private fixture root")
        with tempfile.TemporaryDirectory(prefix="lighttpd-namespace-errors-", dir=TEST_TEMP_PARENT) as temporary:
            result, data = self._run(temporary, mode="nonzero")
            self.assertEqual(result.returncode, 23, result.stderr)
            self.assertEqual(data["open_fds"], [0, 1, 2])
            self._assert_no_task_helper_process(str(Path(temporary) / "result-nonzero.json"))
            result, data = self._run(temporary, mode="sleep", timeout=0.2)
            self.assertEqual(result.returncode, HELPER.EXIT_TIMEOUT, result.stderr)
            self.assertEqual(data["open_fds"], [0, 1, 2])
            self._assert_no_task_helper_process(str(Path(temporary) / "result-sleep.json"))
        self._assert_host_tmpfs_restored(before)
        self._assert_host_fixture_unchanged(host_fixture_before)
        self._assert_task_temp_root_removed(temporary)

    def test_helper_crash_and_partial_setup_fail_closed_without_host_mount(self) -> None:
        before = _mountinfo_for_mountpoint(HELPER.PRIVATE_TMPFS_MOUNT)
        host_fixture_before = _host_path_snapshot(HELPER.FIXTURE_ROOT)
        self.assertIsNone(host_fixture_before, "host has a stale private fixture root")
        with tempfile.TemporaryDirectory(prefix="lighttpd-namespace-failure-", dir=TEST_TEMP_PARENT) as temporary:
            output = Path(temporary) / "crash.json"
            os.chmod(temporary, 0o777)
            crash = _run_runner(
                _runner_source(
                    self._payload(output, mode="crash"),
                    writable_roots=(Path(temporary),),
                )
            )
            self.assertEqual(crash.returncode, 42, crash.stderr)
            crash_data = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(crash_data["open_fds"], [0, 1, 2])
            self._assert_no_task_helper_process(str(output))
            for patch in (
                "helper._require_trusted_system_binaries = lambda: (_ for _ in ()).throw(helper.NamespaceUnavailable('trusted binary failure'))",
                "helper.build_trusted_namespace_command = lambda *args, **kwargs: [str(helper.TRUSTED_UNSHARE), '--invalid-namespace-option']",
                "helper.PRIVATE_TMPFS_SETUP = 'exit 125'",
                "helper._read_setup_attestation = lambda *args, **kwargs: (_ for _ in ()).throw(helper.NamespaceUnavailable('partial setup'))",
            ):
                failed = _run_runner(_runner_source("pass", patch=patch))
                self.assertNotEqual(failed.returncode, 0, failed.stderr)
        self._assert_host_tmpfs_restored(before)
        self._assert_host_fixture_unchanged(host_fixture_before)
        self._assert_task_temp_root_removed(temporary)

    def test_signal_to_supervisor_does_not_leave_mount(self) -> None:
        before = _mountinfo_for_mountpoint(HELPER.PRIVATE_TMPFS_MOUNT)
        host_fixture_before = _host_path_snapshot(HELPER.FIXTURE_ROOT)
        self.assertIsNone(host_fixture_before, "host has a stale private fixture root")
        with tempfile.TemporaryDirectory(prefix="lighttpd-namespace-sigterm-", dir=TEST_TEMP_PARENT) as temporary:
            output = Path(temporary) / "signal.json"
            os.chmod(temporary, 0o777)
            source = _runner_source(
                self._payload(output, mode="sleep"),
                timeout=20,
                writable_roots=(Path(temporary),),
            )
            process = subprocess.Popen(
                [PYTHON, "-c", source],
                cwd=REPO_ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                preexec_fn=_drop_runner_to_unprivileged_identity,
            )
            try:
                deadline = time.monotonic() + 5
                while not output.exists() and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertTrue(output.exists(), "candidate never reached the unprivileged payload")
                process.send_signal(signal.SIGTERM)
                process.communicate(timeout=8)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()
            self.assertIn(process.returncode, (128 + signal.SIGTERM, -signal.SIGTERM))
            signal_data = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(signal_data["open_fds"], [0, 1, 2])
            self._assert_no_task_helper_process(str(output))
        self._assert_host_tmpfs_restored(before)
        self._assert_host_fixture_unchanged(host_fixture_before)
        self._assert_task_temp_root_removed(temporary)

    def test_sigkill_of_unprivileged_supervisor_does_not_leak_private_tmpfs(self) -> None:
        before = _mountinfo_for_mountpoint(HELPER.PRIVATE_TMPFS_MOUNT)
        host_fixture_before = _host_path_snapshot(HELPER.FIXTURE_ROOT)
        self.assertIsNone(host_fixture_before, "host has a stale private fixture root")
        with tempfile.TemporaryDirectory(prefix="lighttpd-namespace-sigkill-", dir=TEST_TEMP_PARENT) as temporary:
            output = Path(temporary) / "signal.json"
            os.chmod(temporary, 0o777)
            process = subprocess.Popen(
                [
                    PYTHON,
                    "-c",
                    _runner_source(
                        self._payload(output, mode="sleep"),
                        timeout=20,
                        writable_roots=(Path(temporary),),
                    ),
                ],
                cwd=REPO_ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                preexec_fn=_drop_runner_to_unprivileged_identity,
            )
            try:
                deadline = time.monotonic() + 5
                while not output.exists() and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertTrue(output.exists(), "candidate never reached the unprivileged payload")
                process.kill()
                process.communicate(timeout=8)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()
            self.assertEqual(process.returncode, -signal.SIGKILL)
            signal_data = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(signal_data["open_fds"], [0, 1, 2])
            self._assert_no_task_helper_process(str(output))
        self._assert_host_tmpfs_restored(before)
        self._assert_host_fixture_unchanged(host_fixture_before)
        self._assert_task_temp_root_removed(temporary)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
