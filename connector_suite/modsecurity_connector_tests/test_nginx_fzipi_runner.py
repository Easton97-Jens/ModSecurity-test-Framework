"""On-demand behavior checks for the native review runner's input boundaries.

These tests execute its real validators, renderers, argv construction, scenario
assertions and process cleanup. HTTP and audit storage are controlled I/O seams;
they do not establish a native NGINX/ModSecurity runtime result.
"""
from __future__ import annotations

from contextlib import redirect_stdout
from functools import partial
import copy
import ctypes
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock

from modsecurity_test_framework.connector_context import connector_root, test_root
from modsecurity_connector_tests import run_nginx_fzipi_review as runner



def _owned_server_fixture(marker: Path, mode: str) -> None:
    """A real disposable master/worker/listener, never a connector runtime."""
    signal.signal(signal.SIGQUIT, lambda *_: sys.exit(0))
    if os.fork() == 0:
        signal.signal(signal.SIGQUIT, signal.SIG_IGN)
        if mode == "stubborn":
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            pending = marker.with_suffix(".pending")
            pending.write_text(json.dumps({
                "worker": os.getpid(), "group": os.getpgrp(),
                "port": listener.getsockname()[1],
                "sigterm_blocked": signal.SIGTERM in signal.pthread_sigmask(signal.SIG_BLOCK, []),
            }))
            pending.replace(marker)
            while True:
                signal.pause()
    _wait_fixture_marker(marker)
    if mode in ("orphan", "stubborn"):
        raise SystemExit(0)
    while True:
        signal.pause()


def _wait_fixture_marker(marker: Path) -> None:
    deadline = time.monotonic() + 3
    while not marker.exists():
        if time.monotonic() >= deadline:
            raise RuntimeError("controlled worker readiness timed out")
        time.sleep(0.01)


def _fixture_subreaper() -> None:
    if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "private process subreaper unavailable")


def _fixture_group_exists(group: int) -> bool:
    try:
        os.killpg(group, 0)
    except ProcessLookupError:
        return False
    return True


def _launch_controlled_process(pidfile, marker, mode, actual_popen, *arguments, **keywords):
    process = actual_popen(*arguments, **keywords)
    pidfile.write_text(json.dumps({"group": process.pid}))
    if mode == "spawn":
        _wait_fixture_marker(marker)
        # A real child exists, but managed_server has not received Popen's
        # return value. The scoped handler must defer cancellation.
        os.kill(os.getpid(), signal.SIGTERM)
    return process


def _install_controlled_signal(mode, repeated, actual_signal, signum, handler):
    if (mode in ("before-ignore", "normal-before-ignore") and
            signum == signal.SIGTERM and handler == signal.SIG_IGN):
        repeated.append(True)
        # Deliver before the real installation, not from inside stop().
        os.kill(os.getpid(), signal.SIGTERM)
    return actual_signal(signum, handler)


def _observe_controlled_stop(cleanup_started, actual_stop, *arguments, **keywords):
    cleanup_started.set()
    return actual_stop(*arguments, **keywords)


def _reap_controlled_worker(marker: Path, observed_exit: list[int]) -> None:
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        if marker.exists():
            worker = json.loads(marker.read_text())["worker"]
            try:
                pid, status = os.waitpid(worker, os.WNOHANG)
            except ChildProcessError:
                pass  # The master has not exited/reparented it yet.
            else:
                if pid:
                    observed_exit.append(os.waitstatus_to_exitcode(status))
                    return
        time.sleep(0.01)


def _repeat_controlled_cancellation(cleanup_started, repeated: list) -> None:
    if cleanup_started.wait(3):
        for _ in range(10):
            os.kill(os.getpid(), signal.SIGTERM)
            repeated.append(True)
            time.sleep(0.01)


def _trigger_process_control(mode, process, cleanup_started, repeated) -> None:
    if mode == "normal-before-ignore":
        return
    if mode in ("orphan", "stubborn"):
        process.wait(timeout=3)  # A genuinely already-reaped master.
        return
    if mode == "repeat":
        threading.Thread(target=_repeat_controlled_cancellation,
                         args=(cleanup_started, repeated), daemon=True).start()
    os.kill(os.getpid(), signal.SIGTERM)
    raise AssertionError("SIGTERM did not cancel the controlled runner")


def _record_process_control(base, result, receipt, worker_exit, previous, repeated) -> None:
    result.update(cleanup=receipt["cleanup"], worker_exit=worker_exit,
                  handler_restored=signal.getsignal(signal.SIGTERM) == previous,
                  repeated_signals=len(repeated))
    marker = base / "controlled-worker.json"
    if marker.exists():
        observed = json.loads(marker.read_text())
        result["sigterm_blocked_in_child"] = observed["sigterm_blocked"]
        with socket.socket() as probe:
            probe.settimeout(0.2)
            result["listener_closed"] = probe.connect_ex(("127.0.0.1", observed["port"])) != 0
    (base / "controlled-result.json").write_text(json.dumps(result))


def _run_process_controller(base: Path, mode: str, binary: Path, runtime: Path) -> None:
    _fixture_subreaper()
    marker, pidfile = base / "controlled-worker.json", base / "controlled-group.json"
    receipt, worker_exit, repeated = {"cleanup": {}}, [], []
    cleanup_started = threading.Event()
    actual_popen, actual_stop = runner.subprocess.Popen, runner.stop
    actual_signal = runner.signal.signal
    reaper = threading.Thread(target=_reap_controlled_worker, args=(marker, worker_exit), daemon=True)
    reaper.start()
    previous = signal.getsignal(signal.SIGTERM)
    runner.subprocess.Popen = partial(_launch_controlled_process, pidfile, marker, mode, actual_popen)
    runner.stop = partial(_observe_controlled_stop, cleanup_started, actual_stop)
    runner.signal.signal = partial(_install_controlled_signal, mode, repeated, actual_signal)
    result = {}
    try:
        admitted = runner.AdmittedRunner(base, "a" * 40, binary, None, runtime, {})
        with runner.managed_server(admitted, runner.RuntimePaths(runtime), receipt) as process:
            _wait_fixture_marker(marker)
            _trigger_process_control(mode, process, cleanup_started, repeated)
    except SystemExit as error:
        result["cancellation_exit"] = error.code
    except BaseException as error:
        result["error"] = type(error).__name__ + ": " + str(error)[:256]
    finally:
        runner.subprocess.Popen, runner.stop = actual_popen, actual_stop
        runner.signal.signal = actual_signal
        reaper.join(timeout=1)
        _record_process_control(base, result, receipt, worker_exit, previous, repeated)
    os._exit(0)


def _wait_controlled_controller(controller: int) -> int:
    deadline = time.monotonic() + 30
    while True:
        completed, status = os.waitpid(controller, os.WNOHANG)
        if completed:
            return status
        if time.monotonic() >= deadline:
            os.kill(controller, signal.SIGKILL)
            return os.waitpid(controller, 0)[1]
        time.sleep(0.02)


def _reap_fixture_descendants() -> None:
    deadline = time.monotonic() + 5
    while True:
        try:
            child, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if not child:
            if time.monotonic() >= deadline:
                raise RuntimeError("controlled descendants were not reaped")
            time.sleep(0.02)


def _guardian_cleanup(base: Path) -> tuple[int | None, bool]:
    pidfile = base / "controlled-group.json"
    group = json.loads(pidfile.read_text())["group"] if pidfile.exists() else None
    forced = False
    if group is not None:
        if type(group) is not int or group <= 0 or group == os.getpgrp():
            raise RuntimeError("invalid controlled group identity")
        forced = _fixture_group_exists(group)
        if forced:
            try:
                os.killpg(group, signal.SIGKILL)
            except ProcessLookupError:
                pass
    # Only this fresh guardian's adopted fixture descendants are reaped here.
    _reap_fixture_descendants()
    return group, forced


def _real_process_control() -> None:
    """An outer private subreaper also cleans up when testing the old defect."""
    base, mode, binary, runtime = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3]), Path(sys.argv[4])
    _fixture_subreaper()
    controller = os.fork()
    if controller == 0:
        _run_process_controller(base, mode, binary, runtime)
    status = _wait_controlled_controller(controller)
    group, forced = _guardian_cleanup(base)
    resultfile = base / "controlled-result.json"
    print(json.dumps({
        "controller_exit": os.waitstatus_to_exitcode(status),
        "forced_guardian_cleanup": forced,
        "owned_group_absent": group is not None and not _fixture_group_exists(group),
        "result": json.loads(resultfile.read_text()) if resultfile.exists() else None,
    }))


class FzipiRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="fzipi-runner-", dir=os.environ.get("RUNNER_TEMP"))
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.source = self.base / "source"
        self.source.mkdir(mode=0o700)
        names = (
            "common/include/msconnector/fixture.h", "common/src/fixture.c",
            "connectors/nginx/src/fixture.c", "connectors/nginx/config",
            "connectors/nginx/metadata.c", "connectors/nginx/metadata.h",
            "connectors/profile_registry.c", "connectors/profile_registry.h",
        )
        self.source_hashes = {}
        for name in names:
            leaf = self.source / name
            leaf.parent.mkdir(parents=True, exist_ok=True)
            content = ("fixture input " + name).encode()
            leaf.write_bytes(content)
            self.source_hashes[name] = hashlib.sha256(content).hexdigest()
        self.binary = self.base / 'admitted nginx; $literal "über binary'
        self.binary.write_text("#!" + sys.executable + "\nimport json,sys\nprint(json.dumps(sys.argv[1:]))\n")
        self.binary.chmod(0o700)
        self.manifest_path = self.base / "artifact.json"
        fixture = test_root() / "connector_suite/modsecurity_connector_tests/nginx_body_buffer_fixture/ngx_http_body_buffer_fixture_module.c"
        self.head = "a" * 40
        self.manifest = {
            "connector_head": self.head, "source_sha256": self.source_hashes,
            "nginx_binary_sha256": hashlib.sha256(self.binary.read_bytes()).hexdigest(),
            "nginx_module_sha256": None,
            "fixture_source_sha256": hashlib.sha256(fixture.read_bytes()).hexdigest(),
        }
        self.write_manifest(self.manifest)

    def write_manifest(self, manifest: dict) -> None:
        self.manifest_path.write_text(json.dumps(manifest))

    def identity(self) -> dict:
        return runner.admit_artifacts(
            self.source, self.head, runner.checked_file(self.binary, "fixture binary"),
            None, runner.checked_file(self.manifest_path, "fixture manifest"))

    def admitted(self, output: Path | None = None) -> runner.AdmittedRunner:
        return runner.AdmittedRunner(self.source, self.head, self.binary, None,
                                     output or self.base / "runtime", self.identity())

    def paths(self, name: str = "runtime") -> runner.RuntimePaths:
        paths = runner.create_runtime(runner.validate_output_root(self.base / name))
        paths.state.mkdir(mode=0o700)
        return paths

    @staticmethod
    def disabled_processes() -> SimpleNamespace:
        return SimpleNamespace(
            run=mock.Mock(side_effect=AssertionError("execution reached before rejection")),
            Popen=mock.Mock(side_effect=AssertionError("process started before rejection")))

    def cli(self, binary: Path, output: Path) -> list[str]:
        return ["--connector-root", str(connector_root()), "--expected-head", os.environ["CONNECTOR_REVISION"],
                "--nginx-binary", str(binary), "--artifact-manifest", str(self.manifest_path),
                "--output-root", str(output)]

    def test_cli_rejects_a_symlink_binary_before_any_execution(self) -> None:
        link = self.base / "binary-link"
        link.symlink_to(self.binary)
        processes = self.disabled_processes()
        output = self.base / "output"
        arguments = self.cli(link, output)
        with mock.patch.object(runner, "subprocess", processes):
            with self.assertRaises(runner.FixtureFailure):
                runner.main(arguments)
        self.assertFalse(output.exists())
        processes.run.assert_not_called()
        processes.Popen.assert_not_called()

    def test_checked_artifact_paths_preserve_canonical_ownership_and_link_controls(self) -> None:
        self.assertEqual(runner.checked_file(self.binary, "binary"), self.binary)
        with self.assertRaises(runner.FixtureFailure):
            runner.checked_file(Path("relative"), "binary")
        hard_link = self.base / "hard-link"
        os.link(self.binary, hard_link)
        with self.assertRaises(runner.FixtureFailure):
            runner.checked_file(hard_link, "binary")
        hard_link.unlink()
        self.binary.chmod(0o722)
        with self.assertRaises(runner.FixtureFailure):
            runner.checked_file(self.binary, "binary")
        self.binary.chmod(0o700)
        # Effective identity is an OS input; the actual owner validator runs.
        with mock.patch.object(os, "geteuid", return_value=os.geteuid() + 1):
            with self.assertRaises(runner.FixtureFailure):
                runner.checked_file(self.binary, "binary")

    def test_artifacts_reject_replaceable_ancestors_before_any_execution(self) -> None:
        shared = self.base / "replaceable"
        shared.mkdir(mode=0o777)
        shared.chmod(0o777)
        parent = shared / "root-owned-parent"
        parent.mkdir(mode=0o700)
        binary = parent / "nginx"
        binary.write_bytes(self.binary.read_bytes())
        binary.chmod(0o700)
        # These are the actual previous admission primitives: a safe file and
        # immediate parent alone do not protect a replaceable ancestor.
        self.assertEqual(runner.require_absolute_directory(parent, "parent"), parent)
        self.assertEqual(runner.require_regular_file(binary, "binary"), binary)
        processes = self.disabled_processes()
        arguments = self.cli(binary, self.base / "output")
        with mock.patch.object(runner, "subprocess", processes):
            with self.assertRaisesRegex(runner.FixtureFailure, "unsafe ancestry"):
                runner.checked_file(binary, "binary")
            with self.assertRaisesRegex(runner.FixtureFailure, "unsafe ancestry"):
                runner.main(arguments)
        processes.run.assert_not_called()
        processes.Popen.assert_not_called()
        # The filesystem substitution mechanism itself works at the unsafe
        # boundary; no replacement program is executed by this test.
        parent.rename(shared / "original")
        parent.mkdir(mode=0o700)
        binary.write_text("controlled substituted artifact")
        self.assertNotEqual(hashlib.sha256(binary.read_bytes()).hexdigest(),
                            self.manifest["nginx_binary_sha256"])
        with self.assertRaisesRegex(runner.FixtureFailure, "unsafe ancestry"):
            runner.checked_file(binary, "binary")

    def test_output_root_retains_safe_root_owned_sticky_ancestor_support(self) -> None:
        sticky = self.base / "sticky"
        sticky.mkdir(mode=0o700)
        sticky.chmod(0o1777)
        if sticky.stat().st_uid != 0:
            self.skipTest("this legitimate control requires a root-owned sticky ancestor")
        output = sticky / "new-private-runtime"
        self.assertEqual(runner.validate_output_root(output), output)
        self.assertFalse(output.exists())
        paths = runner.create_runtime(output)
        self.assertEqual(paths.root, output)
        self.assertEqual(paths.private.stat().st_mode & 0o777, 0o700)

    def test_manifest_rejects_head_source_binary_and_fixture_mismatches(self) -> None:
        self.assertEqual(self.identity()["source_sha256"], self.source_hashes)
        invalid = []
        for key in ("connector_head", "nginx_binary_sha256", "fixture_source_sha256"):
            candidate = copy.deepcopy(self.manifest)
            candidate[key] = "0" * (40 if key == "connector_head" else 64)
            invalid.append(candidate)
        candidate = copy.deepcopy(self.manifest)
        del candidate["source_sha256"]["connectors/nginx/src/fixture.c"]
        invalid.append(candidate)
        for candidate in invalid:
            with self.subTest(changed=next(key for key in candidate if candidate[key] != self.manifest[key])):
                self.write_manifest(candidate)
                with self.assertRaises(runner.FixtureFailure):
                    self.identity()
        self.write_manifest(self.manifest)
        (self.source / "common/src/fixture.c").write_text("changed after build")
        with self.assertRaises(runner.FixtureFailure):
            self.identity()

    def test_output_root_rejects_source_overlap_symlinks_and_shared_ancestors(self) -> None:
        overlapping_output = connector_root() / "uncreated-fzipi-output"
        with self.assertRaises(runner.FixtureFailure):
            runner.validate_output_root(overlapping_output)
        linked = self.base / "linked-parent"
        linked.symlink_to(self.source, target_is_directory=True)
        with self.assertRaises(runner.FixtureFailure):
            runner.validate_output_root(linked / "new-output")
        shared = self.base / "shared"
        shared.mkdir(mode=0o777)
        shared.chmod(0o777)
        destination = shared / "new-output"
        with self.assertRaises(runner.FixtureFailure):
            runner.validate_output_root(destination)
        self.assertFalse(destination.exists())

    def test_cli_rejects_the_selected_checkout_and_linked_git_metadata_before_writes(self) -> None:
        # The CLI checkout deliberately differs from the roots frozen from the
        # environment at import. Both ordinary and linked Git layouts are real.
        runner.git_output(self.source, "init", "-q")
        runner.git_output(self.source, "add", ".")
        runner.git_output(self.source, "-c", "user.name=Fixture",
                          "-c", "user.email=fixture@example.invalid",
                          "commit", "-q", "-m", "controlled source fixture")
        self.head = runner.git_output(self.source, "rev-parse", "HEAD")
        self.manifest["connector_head"] = self.head
        self.write_manifest(self.manifest)
        linked = self.base / "linked-checkout"
        runner.git_output(self.source, "worktree", "add", "--detach",
                          str(linked), self.head)
        self.assertNotIn(self.source, runner.canonical_project_roots())
        self.assertNotIn(linked, runner.canonical_project_roots())
        for root in (self.source, linked):
            metadata = [
                Path(runner.git_output(root, "rev-parse", "--path-format=absolute", flag))
                for flag in ("--git-dir", "--git-common-dir")
            ]
            for protected in dict.fromkeys((root, *metadata)):
                output = protected / "uncreated-runner-output"
                arguments = self.cli(self.binary, output)
                arguments[arguments.index("--connector-root") + 1] = str(root)
                arguments[arguments.index("--expected-head") + 1] = self.head
                with self.subTest(root=root.name, protected=protected):
                    with self.assertRaisesRegex(runner.FixtureFailure, "overlaps"):
                        runner.admit(runner.parse_arguments(arguments))
                    self.assertFalse(output.exists())
                    self.assertEqual(runner.git_output(root, "status", "--porcelain=v1"), "")
            sibling = self.base / ("external-output-" + root.name)
            arguments = self.cli(self.binary, sibling)
            arguments[arguments.index("--connector-root") + 1] = str(root)
            arguments[arguments.index("--expected-head") + 1] = self.head
            admitted = runner.admit(runner.parse_arguments(arguments))
            self.assertEqual(admitted.output_root, sibling)
            self.assertFalse(sibling.exists())

    def test_configuration_grammar_rejections_happen_before_execution_or_output_creation(self) -> None:
        processes = self.disabled_processes()
        for component in ('quote"name', "single'quote", "dollar$var", "new\nline", "semi;colon", "über"):
            output = self.base / component
            arguments = self.cli(self.binary, output)
            with self.subTest(component=repr(component)):
                with mock.patch.object(runner, "subprocess", processes):
                    with self.assertRaises(runner.FixtureFailure):
                        runner.main(arguments)
                self.assertFalse(output.exists())
        processes.run.assert_not_called()
        processes.Popen.assert_not_called()

    def test_nginx_quoting_preserves_literal_space_quote_backslash_unicode_and_dollar(self) -> None:
        path = Path('/external/sp ace/"quoted"/back\\slash/$literal-über.so')
        expected = '"/external/sp ace/\\"quoted\\"/back\\\\slash/$literal-über.so"'
        self.assertEqual(runner.nginx_path(path), expected)
        configuration = runner.write_configuration(self.base, path, 12345, self.base / "rules.conf")
        self.assertTrue(configuration.startswith("load_module " + expected + ";\n"))
        with self.assertRaises(runner.FixtureFailure):
            runner.nginx_path(Path("/external/line\nbreak"))
        with self.assertRaises(runner.FixtureFailure):
            runner.nginx_path(Path("/external/$variable"), variable_aware=True)

    def test_modsecurity_audit_path_uses_its_own_literal_backslash_grammar(self) -> None:
        path = Path("/external/sp ace/back\\slash/server-logs/audit.json")
        self.assertEqual(runner.modsecurity_audit_path(path),
                         '"/external/sp ace/back\\slash/server-logs/audit.json"')
        self.assertNotEqual(runner.modsecurity_audit_path(path), runner.nginx_path(path))
        output = self.base / "sp ace" / "back\\slash"
        self.assertEqual(runner.validate_output_root(output), output)
        private = output / "private"
        private.mkdir(parents=True, mode=0o700)
        paths = runner.RuntimePaths(output)
        runner.write_rules(paths)
        self.assertIn("SecAuditLog " + runner.modsecurity_audit_path(paths.audit) + "\n",
                      paths.rules.read_text())

    def test_admitted_executable_and_generated_config_are_passed_as_literal_argv(self) -> None:
        paths = self.paths()
        config = paths.private / 'space "quote" config.conf'
        config.write_text("# generated fixture\n")
        log = paths.private / "configtest.log"
        result = runner.configuration_check(self.admitted(), paths, config, log)
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(json.loads(log.read_text()),
                         ["-t", "-p", str(paths.state), "-c", str(config)])
        self.assertFalse((self.base / "literal").exists())

    def test_preflight_has_fixed_options_literal_values_and_rejects_bad_ports(self) -> None:
        paths = self.paths("sp ace")
        calls = []
        def run(command, **keywords):
            calls.append((command, keywords))
            return subprocess.CompletedProcess(command, 0, "", "")
        processes = SimpleNamespace(run=run)
        with mock.patch.object(runner, "subprocess", processes):
            runner.preflight(paths, 12345, prepared=True)
        command, keywords = calls[0]
        self.assertEqual(command[0], sys.executable)
        self.assertIn("--runtime-root=" + str(paths.root), command)
        self.assertIn("--worker-read=" + str(paths.docroot / "ok.html"), command)
        self.assertIn("--port=12345", command)
        self.assertNotIn("shell", keywords)
        for port in ("12345", "-exec", 0, -1, 65536, True):
            with self.subTest(port=port):
                with mock.patch.object(runner, "subprocess", self.disabled_processes()):
                    with self.assertRaises(runner.FixtureFailure):
                        runner.preflight(paths, port, prepared=False)

    def test_credentials_accept_the_real_positive_pid_and_reject_malformed_inputs_before_io(self) -> None:
        observed = runner.credentials(os.getpid())
        self.assertEqual(observed["pid"], os.getpid())
        self.assertEqual(observed["uid"][1], os.geteuid())
        for pid in (None, 0, -1, True, 1.0, "1", "../../etc/passwd"):
            with self.subTest(pid=pid):
                with mock.patch.object(Path, "read_text", side_effect=AssertionError("unexpected proc read")):
                    with self.assertRaises(runner.FixtureFailure):
                        runner.credentials(pid)

    @staticmethod
    def audit_records() -> list[dict]:
        rows = []
        definitions = (
            ("phase2-error-page", 403, "910001"),
            ("try-files-same-policy", 200, None),
            ("changed-target-policy", 0, None),
            ("changed-target-policy", 200, "910003"),
            ("disabled-target-policy", 0, None),
            ("ordinary-host-error-page", 403, "910001"),
            ("replacement-stale-followups", 302, "910005"),
        )
        for case, status_code, identifier in definitions:
            messages = [] if identifier is None else [{"details": {"ruleId": identifier}}]
            rows.append({"transaction": {"unique_id": case, "response": {"http_code": status_code},
                                         "messages": messages}})
        return rows

    @staticmethod
    def client_response(port, uri, case, *, blocked_header=False):
        del port, uri, blocked_header
        responses = {
            "phase2-error-page": (403, runner.CUSTOM_PAGE, {"X-Fzipi-Preserved": "yes"}),
            "try-files-same-policy": (200, b"SAME-POLICY\n", {}),
            "changed-target-policy": (200, b"CHANGED-POLICY\n", {}),
            "disabled-target-policy": (200, b"OFF-TARGET\n", {}),
            "ordinary-host-error-page": (403, b"BUILTIN-403", {}),
            "replacement-stale-followups": (302, b"", {"Location": "/replacement"}),
        }
        return responses[case]

    def test_success_scenarios_traverse_real_response_audit_and_receipt_assertions(self) -> None:
        receipt = {"cases": {}}
        # Only the external HTTP/storage seams are replaced. JSON parsing,
        # correlation, original status/rule checks and all scenario assertions run.
        with mock.patch.object(runner, "request", side_effect=self.client_response):
            with mock.patch.object(runner, "read_server_file", return_value=json.dumps(self.audit_records()[0]) +
                                   "\n" + "\n".join(json.dumps(row) for row in self.audit_records()[1:])):
                runner.run_scenarios(runner.RuntimePaths(self.base), 12345, receipt)
        self.assertEqual(len(receipt["cases"]), 6)
        self.assertEqual(receipt["cases"]["changed-target-policy"]["native_audit_records"], 2)
        self.assertEqual(receipt["cases"]["phase2-error-page"]["rule_ids"], ["910001"])

    def test_lost_original_audit_status_is_a_failure_not_a_success_receipt(self) -> None:
        rows = self.audit_records()
        rows[0]["transaction"]["response"]["http_code"] = 200
        receipt = {"cases": {}}
        with mock.patch.object(runner, "request", side_effect=self.client_response):
            with mock.patch.object(runner, "read_server_file", return_value="\n".join(json.dumps(row) for row in rows)):
                with self.assertRaisesRegex(runner.FixtureFailure, "original native block status"):
                    runner.run_scenarios(runner.RuntimePaths(self.base), 12345, receipt)
        self.assertEqual(receipt["cases"], {})

    def completed_scenario_receipt(self) -> dict:
        receipt = {"cases": {}, "cleanup": {"process_group_absent": True, "exit_code": 0}}
        early_audit = "\n".join(json.dumps(row) for row in self.audit_records())
        with mock.patch.object(runner, "request", side_effect=self.client_response):
            with mock.patch.object(runner, "read_server_file", return_value=early_audit):
                runner.run_scenarios(runner.RuntimePaths(self.base), 12345, receipt)
        return receipt

    def completion_storage(self, rows: list[dict]) -> mock.Mock:
        audit = "\n".join(json.dumps(row) for row in rows)

        def read(path, *, owner):
            if path.name == "audit.json":
                self.assertEqual(owner, 65534)
                return audit
            self.assertEqual(path.name, "error.log")
            self.assertEqual(owner, 0)
            return "stale-followup-callbacks=2 null-callback=1"

        return mock.Mock(side_effect=read)

    @staticmethod
    def closed_listener() -> mock.MagicMock:
        probe = mock.MagicMock()
        probe.__enter__.return_value = probe
        probe.connect_ex.return_value = 111
        return probe

    def test_final_completion_rejects_a_late_duplicate_for_every_scenario(self) -> None:
        paths = runner.RuntimePaths(self.base)
        for scenario in runner.SCENARIOS:
            with self.subTest(scenario=scenario.name):
                receipt = self.completed_scenario_receipt()
                rows = self.audit_records()
                duplicate = next(row for row in rows
                                 if row["transaction"]["unique_id"] == scenario.name)
                rows.append(copy.deepcopy(duplicate))
                storage = self.completion_storage(rows)
                probe = self.closed_listener()
                with mock.patch.object(runner, "read_server_file", storage):
                    with mock.patch.object(runner.socket, "socket", return_value=probe):
                        with self.assertRaisesRegex(runner.FixtureFailure, "native audit ownership"):
                            runner.verify_native_completion(paths, 12345, receipt)
                self.assertEqual(storage.call_count, 1)
                self.assertEqual(receipt["cases"][scenario.name]["native_audit_records"],
                                 scenario.audit_count + 1)
                self.assertEqual(receipt["cases"][scenario.name]["status"], "failed")

    def test_final_completion_rechecks_the_original_native_status(self) -> None:
        paths = runner.RuntimePaths(self.base)
        receipt = self.completed_scenario_receipt()
        rows = self.audit_records()
        rows[0]["transaction"]["response"]["http_code"] = 200
        storage = self.completion_storage(rows)
        probe = self.closed_listener()
        with mock.patch.object(runner, "read_server_file", storage):
            with mock.patch.object(runner.socket, "socket", return_value=probe):
                with self.assertRaisesRegex(runner.FixtureFailure, "original native block status"):
                    runner.verify_native_completion(paths, 12345, receipt)
        self.assertEqual(storage.call_count, 1)

    def test_final_completion_refreshes_receipt_metadata_from_one_final_audit_read(self) -> None:
        paths = runner.RuntimePaths(self.base)
        receipt = self.completed_scenario_receipt()
        for result in receipt["cases"].values():
            result["native_audit_records"] = -1
            result["rule_ids"] = ["stale"]
        storage = self.completion_storage(self.audit_records())
        probe = self.closed_listener()
        with mock.patch.object(runner, "read_server_file", storage):
            with mock.patch.object(runner.socket, "socket", return_value=probe):
                runner.verify_native_completion(paths, 12345, receipt)
        self.assertEqual(storage.call_args_list, [mock.call(paths.audit, owner=65534),
                                                mock.call(paths.logs / "error.log", owner=0)])
        for scenario in runner.SCENARIOS:
            self.assertEqual(receipt["cases"][scenario.name]["native_audit_records"], scenario.audit_count)
            expected_ids = [] if scenario.rule is None else [scenario.rule]
            self.assertEqual(receipt["cases"][scenario.name]["rule_ids"], expected_ids)
        self.assertTrue(receipt["cleanup"]["listener_closed"])

    def real_cleanup_control(self, mode: str) -> dict:
        paths = self.paths()
        paths.config.write_text("# controlled process configuration\n")
        marker = self.base / "controlled-worker.json"
        self.binary.write_text(
            "#!" + sys.executable + "\n"
            "from pathlib import Path\n"
            "from modsecurity_connector_tests.test_nginx_fzipi_runner import _owned_server_fixture\n"
            "_owned_server_fixture(Path(" + repr(str(marker)) + "), " + repr(mode) + ")\n")
        command = [sys.executable, "-B", "-P", "-c",
                   "from modsecurity_connector_tests.test_nginx_fzipi_runner import "
                   "_real_process_control; _real_process_control()",
                   str(self.base), mode, str(self.binary), str(paths.root)]
        completed = subprocess.run(command, capture_output=True, text=True, timeout=40, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        report = json.loads(completed.stdout)
        self.assertEqual(report["controller_exit"], 0, report)
        self.assertFalse(report["forced_guardian_cleanup"], report)
        self.assertTrue(report["owned_group_absent"], report)
        result = report["result"]
        self.assertNotIn("error", result)
        self.assertEqual(result["cleanup"], {"master_reaped": True, "exit_code": 0,
                                             "process_group_absent": True})
        self.assertTrue(result["handler_restored"])
        self.assertFalse(result["sigterm_blocked_in_child"])
        self.assertTrue(result["listener_closed"])
        self.assertEqual(result["worker_exit"], [-9 if mode == "stubborn" else -15])
        return result

    def test_sigterm_cleans_its_real_owned_group_and_restores_the_previous_handler(self) -> None:
        result = self.real_cleanup_control("cancel")
        self.assertEqual(result["cancellation_exit"], 128 + signal.SIGTERM)

    def test_sigterm_during_real_spawn_handoff_is_deferred_until_owned_cleanup(self) -> None:
        result = self.real_cleanup_control("spawn")
        self.assertEqual(result["cancellation_exit"], 128 + signal.SIGTERM)

    def test_repeated_sigterm_cannot_interrupt_the_real_group_cleanup(self) -> None:
        result = self.real_cleanup_control("repeat")
        self.assertEqual(result["cancellation_exit"], 128 + signal.SIGTERM)
        self.assertEqual(result["repeated_signals"], 10)

    def test_repeated_sigterm_before_ignore_transition_cannot_skip_real_owned_cleanup(self) -> None:
        result = self.real_cleanup_control("before-ignore")
        self.assertEqual(result["cancellation_exit"], 128 + signal.SIGTERM)
        self.assertEqual(result["repeated_signals"], 1)

    def test_first_sigterm_during_normal_exit_still_cleans_and_reports_cancellation(self) -> None:
        result = self.real_cleanup_control("normal-before-ignore")
        self.assertEqual(result["cancellation_exit"], 128 + signal.SIGTERM)
        self.assertEqual(result["repeated_signals"], 1)

    def test_cleanup_stops_a_real_worker_after_the_master_has_already_been_reaped(self) -> None:
        result = self.real_cleanup_control("orphan")
        self.assertNotIn("cancellation_exit", result)

    def test_cleanup_escalates_for_a_real_remaining_worker_that_ignores_term(self) -> None:
        result = self.real_cleanup_control("stubborn")
        self.assertNotIn("cancellation_exit", result)

    def test_managed_process_reaps_its_real_child_even_when_scenario_execution_fails(self) -> None:
        paths = self.paths()
        paths.config.write_text("# fixture configuration\n")
        marker = self.base / "child-ready"
        self.binary.write_text("#!" + sys.executable + "\nimport pathlib,signal,sys\n"
                               "signal.signal(signal.SIGQUIT, lambda *_: sys.exit(0))\n"
                               "pathlib.Path(" + repr(str(marker)) + ").write_text('ready')\n"
                               "while True: signal.pause()\n")
        self.manifest["nginx_binary_sha256"] = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        self.write_manifest(self.manifest)
        receipt = {"cleanup": {}}
        admitted = self.admitted()

        def fail_scenario() -> None:
            with runner.managed_server(admitted, paths, receipt) as process:
                deadline = time.monotonic() + 3
                while not marker.exists() and time.monotonic() < deadline:
                    self.assertIsNone(process.poll())
                    time.sleep(0.02)
                self.assertTrue(marker.exists())
                raise runner.FixtureFailure("controlled scenario failure")

        with self.assertRaisesRegex(runner.FixtureFailure, "controlled scenario failure"):
            fail_scenario()
        self.assertEqual(receipt["cleanup"], {"master_reaped": True, "exit_code": 0,
                                              "process_group_absent": True})

    def test_preflight_failure_still_writes_a_bounded_failed_receipt(self) -> None:
        admitted = self.admitted()
        processes = SimpleNamespace(
            run=lambda command, **_: subprocess.CompletedProcess(command, 77, "BLOCKED", ""),
            SubprocessError=subprocess.SubprocessError)
        with redirect_stdout(io.StringIO()):
            with mock.patch.object(runner, "subprocess", processes):
                result = runner.run_admitted(admitted)
        self.assertEqual(result, 1)
        receipt = json.loads((admitted.output_root / "private/result.json").read_text())
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual(receipt["cases"], {})
        self.assertLessEqual(len(receipt["failure_reason"]), 256)


if os.environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
