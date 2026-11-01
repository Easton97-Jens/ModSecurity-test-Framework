"""Focused contracts for the protected Lighttpd runtime supervisor."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import hashlib
import http.server
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any
import unittest
from unittest import mock


ROOT = connector_root()
SUPERVISOR_PATH = source_path('ci/runtime/lifecycle/trusted_lighttpd_runtime_supervisor.py', root=ROOT)
SUPERVISOR = load_source(SUPERVISOR_PATH)


def digest(path: Path) -> str:
    """Return one test artifact digest."""

    return hashlib.sha256(path.read_bytes()).hexdigest()


class ProbeHandler(http.server.BaseHTTPRequestHandler):
    """Return the fixed status set with server-generated transaction IDs."""

    counter = 0
    reflect_transaction = False

    def do_OPTIONS(self) -> None:  # noqa: N802 - stdlib callback spelling
        ProbeHandler.counter += 1
        marker = self.headers.get("X-Modsec-Smoke")
        status = {"block": 403, "alternative-status": 429}.get(marker, 200)
        request_id = self.headers.get("X-Modsec-Transaction-Id", "")
        transaction_id = (
            request_id
            if ProbeHandler.reflect_transaction
            else f"lighttpd-101-{ProbeHandler.counter}"
        )
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.send_header("X-Msconnector-Host-Transaction-Id", transaction_id)
        self.end_headers()

    def log_message(self, _format: str, *_arguments: object) -> None:
        """Keep focused test output deterministic."""


class TrustedLighttpdRuntimeSupervisorTest(unittest.TestCase):
    """Exercise the narrow master-owned process and receipt boundary."""

    def private_directory(self, path: Path, mode: int = 0o700) -> Path:
        path.mkdir(parents=True, mode=mode)
        path.chmod(mode)
        return path

    def sealed_directory(self, path: Path) -> Path:
        return self.private_directory(path, 0o755)

    def write_artifact(self, path: Path, data: bytes, mode: int) -> Path:
        path.write_bytes(data)
        path.chmod(mode)
        return path

    def plan(self, root: Path, **overrides: object) -> object:
        sealed = self.sealed_directory(root / "sealed")
        libraries = self.sealed_directory(sealed / "lib")
        receipts = self.private_directory(root / "receipts")
        binary = self.write_artifact(sealed / "lighttpd", b"sealed binary\n", 0o500)
        module = self.write_artifact(sealed / "mod_msconnector.so", b"sealed module\n", 0o400)
        library = self.write_artifact(libraries / "libmodsecurity.so", b"sealed library\n", 0o400)
        config = self.write_artifact(
            sealed / "lighttpd.conf",
            b'server.bind = "127.0.0.1"\nserver.port = 18484\n',
            0o400,
        )
        values: dict[str, object] = {
            "target_sha": "a" * 40,
            "run_id": "trusted-lighttpd-101",
            "sealed_root": sealed,
            "receipt_root": receipts,
            "binary": SUPERVISOR.ArtifactSpec(binary, digest(binary), "Lighttpd binary"),
            "module": SUPERVISOR.ArtifactSpec(module, digest(module), "Lighttpd connector module"),
            "config": SUPERVISOR.ArtifactSpec(config, digest(config), "Lighttpd configuration"),
            "sealed_artifacts": (
                SUPERVISOR.ArtifactSpec(binary, digest(binary), "Lighttpd binary"),
                SUPERVISOR.ArtifactSpec(module, digest(module), "Lighttpd connector module"),
                SUPERVISOR.ArtifactSpec(config, digest(config), "Lighttpd configuration"),
                SUPERVISOR.ArtifactSpec(library, digest(library), "libmodsecurity"),
            ),
            "library_directories": (libraries,),
            "port": 18484,
            "runtime_uid": 65534,
            "runtime_gid": 65534,
        }
        values.update(overrides)
        return SUPERVISOR.RuntimePlan(**values)

    def plan_with_artifact_replacements(
        self,
        plan: Any,
        replacements: tuple[Any, ...],
        additions: tuple[Any, ...] = (),
    ) -> Any:
        """Return a plan whose matching sealed artifacts use new test identities."""

        replacement_by_path = {artifact.path: artifact for artifact in replacements}
        return SUPERVISOR.RuntimePlan(
            **{
                **plan.__dict__,
                "binary": replacement_by_path.get(plan.binary.path, plan.binary),
                "module": replacement_by_path.get(plan.module.path, plan.module),
                "config": replacement_by_path.get(plan.config.path, plan.config),
                "sealed_artifacts": tuple(
                    replacement_by_path.get(artifact.path, artifact) for artifact in plan.sealed_artifacts
                )
                + additions,
            }
        )

    def running_server(self) -> tuple[http.server.ThreadingHTTPServer, threading.Thread]:
        ProbeHandler.counter = 0
        ProbeHandler.reflect_transaction = False
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), ProbeHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, thread

    def test_valid_sealed_plan_accepts_closed_no_crs_contract(self) -> None:
        with tempfile.TemporaryDirectory(prefix="trusted-lighttpd-plan-") as temporary:
            plan = self.plan(Path(temporary))

            SUPERVISOR.validate_runtime_plan(plan)

    def test_plan_rejects_crs_configuration_and_untrusted_ruleset(self) -> None:
        with tempfile.TemporaryDirectory(prefix="trusted-lighttpd-plan-") as temporary:
            root = Path(temporary)
            plan = self.plan(root)
            plan.config.path.chmod(0o600)
            plan.config.path.write_text("include \"/crs/rules.conf\"\n", encoding="utf-8")
            plan.config.path.chmod(0o400)
            changed_config = SUPERVISOR.ArtifactSpec(
                plan.config.path,
                digest(plan.config.path),
                plan.config.label,
            )
            plan = self.plan_with_artifact_replacements(plan, (changed_config,))

            with self.assertRaisesRegex(SUPERVISOR.SupervisorError, "OWASP CRS"):
                SUPERVISOR.validate_runtime_plan(plan)
            with self.assertRaisesRegex(SUPERVISOR.SupervisorError, "must not select CRS"):
                SUPERVISOR.validate_no_crs_configuration("server.port = 18484\n", {"MODSECURITY_RULESET": "crs"})

    def test_plan_rejects_artifact_digest_and_symlink_substitution(self) -> None:
        with tempfile.TemporaryDirectory(prefix="trusted-lighttpd-plan-") as temporary:
            root = Path(temporary)
            plan = self.plan(root)
            bad_binary = SUPERVISOR.ArtifactSpec(plan.binary.path, "0" * 64, plan.binary.label)
            bad_digest = self.plan_with_artifact_replacements(plan, (bad_binary,))
            with self.assertRaisesRegex(SUPERVISOR.SupervisorError, "digest does not match"):
                SUPERVISOR.validate_runtime_plan(bad_digest)

            plan.module.path.unlink()
            plan.module.path.symlink_to(plan.binary.path)
            with self.assertRaisesRegex(SUPERVISOR.SupervisorError, "symbolic links"):
                SUPERVISOR.validate_runtime_plan(plan)

    def test_plan_rejects_privileged_binary_and_receipt_overlap(self) -> None:
        with tempfile.TemporaryDirectory(prefix="trusted-lighttpd-plan-") as temporary:
            root = Path(temporary)
            plan = self.plan(root)
            plan.binary.path.chmod(0o4500)
            with self.assertRaisesRegex(SUPERVISOR.SupervisorError, "sealed owner-controlled"):
                SUPERVISOR.validate_runtime_plan(plan)

            plan.binary.path.chmod(0o500)
            overlapping_receipts = self.private_directory(plan.sealed_root / "receipts")
            overlapping_plan = SUPERVISOR.RuntimePlan(
                **{**plan.__dict__, "receipt_root": overlapping_receipts}
            )
            with self.assertRaisesRegex(SUPERVISOR.SupervisorError, "must not overlap"):
                SUPERVISOR.validate_runtime_plan(overlapping_plan)

    def test_manifest_rejects_unlisted_loader_file_and_uncontracted_rule_reference(self) -> None:
        with tempfile.TemporaryDirectory(prefix="trusted-lighttpd-manifest-") as temporary:
            root = Path(temporary)
            plan = self.plan(root)
            unlisted = plan.library_directories[0] / "libunlisted.so"
            self.write_artifact(unlisted, b"unlisted library\n", 0o400)
            with self.assertRaisesRegex(SUPERVISOR.SupervisorError, "outside its digest manifest"):
                SUPERVISOR.validate_runtime_plan(plan)

        with tempfile.TemporaryDirectory(prefix="trusted-lighttpd-config-") as temporary:
            root = Path(temporary)
            plan = self.plan(root)
            plan.config.path.chmod(0o600)
            plan.config.path.write_text("rules_file=/tmp/not-sealed.conf\n", encoding="utf-8")
            plan.config.path.chmod(0o400)
            changed_config = SUPERVISOR.ArtifactSpec(
                plan.config.path,
                digest(plan.config.path),
                plan.config.label,
            )
            plan = self.plan_with_artifact_replacements(plan, (changed_config,))
            with self.assertRaisesRegex(SUPERVISOR.SupervisorError, "must not use rules_file"):
                SUPERVISOR.validate_runtime_plan(plan)

        with tempfile.TemporaryDirectory(prefix="trusted-lighttpd-rule-") as temporary:
            root = Path(temporary)
            plan = self.plan(root)
            rule = self.write_artifact(
                plan.sealed_root / "rules.conf",
                b"SecRule ARGS '@rx test' 'id:1000,deny'\n",
                0o400,
            )
            plan.config.path.chmod(0o600)
            plan.config.path.write_text(f"rules_file={rule}\n", encoding="utf-8")
            plan.config.path.chmod(0o400)
            changed_config = SUPERVISOR.ArtifactSpec(
                plan.config.path,
                digest(plan.config.path),
                plan.config.label,
            )
            plan = self.plan_with_artifact_replacements(
                plan,
                (changed_config,),
                (SUPERVISOR.ArtifactSpec(rule, digest(rule), "sealed rules"),),
            )
            with self.assertRaisesRegex(SUPERVISOR.SupervisorError, "must not use rules_file"):
                SUPERVISOR.validate_runtime_plan(plan)

    def test_private_receipt_is_atomic_owner_private_and_not_replaceable(self) -> None:
        with tempfile.TemporaryDirectory(prefix="trusted-lighttpd-receipt-") as temporary:
            root = self.private_directory(Path(temporary) / "receipts")
            receipt = SUPERVISOR.write_receipt(root, {"runtime_status": "BLOCKED", "blocker": "test"})

            self.assertEqual(json.loads(receipt.read_text(encoding="utf-8"))["runtime_status"], "BLOCKED")
            self.assertEqual(stat.S_IMODE(receipt.stat().st_mode), 0o600)
            with self.assertRaisesRegex(SUPERVISOR.SupervisorError, "already exists"):
                SUPERVISOR.write_receipt(root, {"runtime_status": "PASS"})
            self.assertEqual(
                [entry.name for entry in root.iterdir() if entry.name.startswith(".")],
                [],
            )

    def test_listener_must_be_exact_loopback_socket_owned_by_current_process(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            port = listener.getsockname()[1]

            inode = SUPERVISOR.listener_inode(port)

            self.assertIn(inode, SUPERVISOR.process_socket_inodes(os.getpid()))
            self.assertFalse(SUPERVISOR.listener_released(port))
        self.assertTrue(SUPERVISOR.listener_released(port))

    def test_process_executable_and_module_observation_use_proc_identities(self) -> None:
        with tempfile.TemporaryDirectory(prefix="trusted-lighttpd-process-") as temporary:
            sealed = self.sealed_directory(Path(temporary) / "sealed")
            copied_python = sealed / "lighttpd"
            shutil.copyfile(sys.executable, copied_python)
            copied_python.chmod(0o500)
            artifact = SUPERVISOR.ArtifactSpec(copied_python, digest(copied_python), "Lighttpd binary")
            process = subprocess.Popen([str(copied_python), "-c", "import time; time.sleep(30)"], start_new_session=True)
            try:
                time.sleep(0.1)
                SUPERVISOR.process_uses_artifact(process.pid, artifact, sealed)
                SUPERVISOR.module_is_mapped(process.pid, artifact, sealed)
                self.assertGreater(SUPERVISOR.process_start_ticks(process.pid), 0)
            finally:
                process.terminate()
                process.wait(timeout=5)

    def test_fixed_probes_cover_control_detection_and_alternate_negative(self) -> None:
        server, thread = self.running_server()
        try:
            with tempfile.TemporaryDirectory(prefix="trusted-lighttpd-probe-") as temporary:
                plan = self.plan(Path(temporary), port=server.server_port)

                observations = SUPERVISOR.run_fixed_probes(plan)

            self.assertEqual(
                [(item.case_id, item.status) for item in observations],
                [("control", 200), ("detection", 403), ("alternate-negative", 429)],
            )
            self.assertEqual(len({item.transaction_id for item in observations}), 3)
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()

    def test_child_environment_fixes_the_no_crs_ruleset(self) -> None:
        with tempfile.TemporaryDirectory(prefix="trusted-lighttpd-environment-") as temporary:
            plan = self.plan(Path(temporary))

            environment = SUPERVISOR.child_environment(plan)

            self.assertEqual(environment["MSCONNECTOR_CRS_RUNTIME"], "0")
            self.assertEqual(environment["MODSECURITY_RULESET"], "no-crs")
            self.assertNotIn("GITHUB_TOKEN", environment)

    def test_runtime_start_requires_the_private_pid_namespace_init(self) -> None:
        with mock.patch.object(SUPERVISOR.os, "getpid", return_value=2):
            with self.assertRaisesRegex(SUPERVISOR.SupervisorError, "PID 1"):
                SUPERVISOR.require_private_pid_namespace_init()
        with mock.patch.object(SUPERVISOR.os, "getpid", return_value=1):
            SUPERVISOR.require_private_pid_namespace_init()

    def test_fixed_probe_rejects_reflected_or_reused_transaction_identifier(self) -> None:
        server, thread = self.running_server()
        try:
            ProbeHandler.reflect_transaction = True
            reflected_case = SUPERVISOR.ProbeCase(
                case_id="reflected-transaction",
                headers=(("X-Modsec-Transaction-Id", "lighttpd-1-1"),),
                expected_status=200,
            )
            with self.assertRaisesRegex(SUPERVISOR.SupervisorError, "reflected"):
                SUPERVISOR.run_fixed_probe(server.server_port, reflected_case)
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()

    def test_supervisor_blocks_before_start_without_runtime_no_crs_provenance(self) -> None:
        with tempfile.TemporaryDirectory(prefix="trusted-lighttpd-blocked-") as temporary:
            plan = self.plan(Path(temporary))
            with mock.patch.object(SUPERVISOR, "start_lighttpd") as start, mock.patch.object(
                SUPERVISOR, "private_pid_namespace_is_clean", return_value=True
            ):
                with self.assertRaisesRegex(SUPERVISOR.SupervisorError, "runtime no-CRS provenance"):
                    SUPERVISOR.supervise(plan)

            receipt = json.loads((plan.receipt_root / SUPERVISOR.RECEIPT_NAME).read_text(encoding="utf-8"))
            start.assert_not_called()
            self.assertEqual(receipt["runtime_status"], "BLOCKED")
            self.assertEqual(receipt["blocker"], "independent runtime no-CRS provenance is not implemented")
            self.assertEqual(receipt["profile"], "no-crs")
            self.assertEqual(receipt["mrts"], {"executed": False, "status": "NOT_INVOKED"})
            self.assertEqual(
                receipt["no_crs"],
                {
                    "msconnector_crs_runtime": "0",
                    "modsecurity_ruleset": "no-crs",
                    "static_configuration_checked": True,
                    "runtime_provenance_status": "NOT_VERIFIED",
                },
            )
            self.assertTrue(receipt["cleanup_passed"])

    def test_early_process_identity_failure_cleanup_helper_terminates_the_live_child(self) -> None:
        process = mock.Mock()
        process.pid = 12345
        process.poll.side_effect = (None, 0)
        with mock.patch.object(SUPERVISOR.os, "killpg") as kill_process_group:
            self.assertTrue(SUPERVISOR.terminate_lighttpd(process, None))

        kill_process_group.assert_called_once_with(12345, SUPERVISOR.signal.SIGTERM)
        process.wait.assert_called_once_with(timeout=SUPERVISOR.STOP_TIMEOUT_SECONDS)

# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)
