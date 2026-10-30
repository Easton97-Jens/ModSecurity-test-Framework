from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import argparse
import importlib.util
import json
import os
import socket
import stat
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock


ROOT = connector_root()
RUNNER = load_source(source_path('connectors/traefik/scripts/runtime_smoke.py', root=ROOT))


class TraefikRuntimeSmokeSecurityTest(unittest.TestCase):
    @staticmethod
    def make_executable(path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        return path

    @staticmethod
    def runtime_args(connector_binary: Path, traefik_binary: Path) -> argparse.Namespace:
        return argparse.Namespace(
            connector_binary=connector_binary,
            traefik_binary=traefik_binary,
        )

    def test_missing_runtime_root_is_blocked_without_a_shared_temporary_default(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"BUILD_ROOT": "", "CONNECTOR_COMPONENT_CACHE": ""},
            clear=False,
        ):
            with self.assertRaisesRegex(RUNNER.MissingDependency, "BUILD_ROOT must be set"):
                RUNNER.require_runtime_root_from_environment("BUILD_ROOT", ROOT)

    def test_group_or_world_writable_runtime_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="traefik-runtime-root-") as temporary:
            root = Path(temporary) / "runtime-root"
            root.mkdir(mode=0o700)
            root.chmod(stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
            with self.assertRaisesRegex(RUNNER.MissingDependency, "must not be group or world writable"):
                RUNNER.require_trusted_runtime_root(root, "BUILD_ROOT", ROOT)

        filesystem_root = Path(os.sep)
        with self.assertRaisesRegex(RUNNER.MissingDependency, "too broad"):
            RUNNER.require_trusted_runtime_root(filesystem_root, "BUILD_ROOT", ROOT)

    def test_symlinked_runtime_root_and_binary_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="traefik-runtime-root-") as temporary:
            temporary_root = Path(temporary)
            build_root = temporary_root / "build"
            build_root.mkdir(mode=0o700)
            root_alias = temporary_root / "build-alias"
            root_alias.symlink_to(build_root, target_is_directory=True)
            with self.assertRaisesRegex(RUNNER.MissingDependency, "symlink"):
                RUNNER.require_trusted_runtime_root(root_alias, "BUILD_ROOT", ROOT)

            target = self.make_executable(temporary_root / "outside" / "runner")
            binary_alias = build_root / "runner"
            binary_alias.symlink_to(target)
            with self.assertRaisesRegex(RUNNER.MissingDependency, "symlink"):
                RUNNER.require_local_executable(binary_alias, "Traefik connector binary", build_root)

    def test_cross_user_writable_binary_ancestor_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="traefik-runtime-root-") as temporary:
            build_root = Path(temporary) / "build"
            build_root.mkdir(mode=0o700)
            untrusted_directory = build_root / "untrusted"
            untrusted_directory.mkdir(mode=0o777)
            untrusted_directory.chmod(0o777)
            binary = self.make_executable(untrusted_directory / "traefik-forwardauth")
            with self.assertRaisesRegex(
                RUNNER.MissingDependency, "permits cross-user replacement"
            ):
                RUNNER.require_local_executable(binary, "Traefik connector binary", build_root)

    def test_runtime_binaries_must_be_contained_and_a_legitimate_pair_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory(prefix="traefik-runtime-root-") as temporary:
            temporary_root = Path(temporary)
            build_root = temporary_root / "build"
            component_cache = temporary_root / "cache"
            # Owner-controlled roots may be searchable by other users; only
            # group/world write access would let another user replace binaries.
            build_root.mkdir(mode=0o755)
            component_cache.mkdir(mode=0o755)
            build_root.chmod(0o755)
            component_cache.chmod(0o755)
            connector_binary = self.make_executable(build_root / "traefik-forwardauth")
            traefik_binary = self.make_executable(component_cache / "traefik")
            outside_binary = self.make_executable(temporary_root / "outside" / "traefik")
            with mock.patch.dict(
                os.environ,
                {
                    "BUILD_ROOT": str(build_root),
                    "CONNECTOR_COMPONENT_CACHE": str(component_cache),
                },
                clear=False,
            ):
                resolved_build_root, connector, traefik = RUNNER.resolve_runtime_paths(
                    self.runtime_args(connector_binary, traefik_binary), ROOT
                )
                self.assertEqual(resolved_build_root, build_root)
                self.assertEqual(connector.path, connector_binary)
                self.assertEqual(traefik.path, traefik_binary)
                outside_arguments = self.runtime_args(outside_binary, traefik_binary)
                with self.assertRaisesRegex(RUNNER.MissingDependency, "must remain below"):
                    RUNNER.resolve_runtime_paths(outside_arguments, ROOT)

    def test_provisioned_host_binary_is_accepted_without_trusting_other_build_paths(self) -> None:
        with tempfile.TemporaryDirectory(prefix="traefik-staged-host-") as temporary:
            root = Path(temporary)
            build_root = root / "build"
            component_cache = root / "cache"
            build_root.mkdir(mode=0o700)
            component_cache.mkdir(mode=0o700)
            connector = self.make_executable(build_root / "traefik-forwardauth")
            staged = self.make_executable(build_root / "traefik-connector/bin/traefik")
            unexpected = self.make_executable(build_root / "other/traefik")
            outside = self.make_executable(root / "outside/traefik")
            with mock.patch.dict(os.environ, {
                "BUILD_ROOT": str(build_root),
                "CONNECTOR_COMPONENT_CACHE": str(component_cache),
            }):
                _, _, trusted_host = RUNNER.resolve_runtime_paths(
                    self.runtime_args(connector, staged), ROOT
                )
                self.assertEqual(trusted_host.path, staged)
                for rejected in (unexpected, outside, staged.parent / ".." / ".." / ".." / "other/traefik"):
                    rejected_arguments = self.runtime_args(connector, rejected)
                    with self.subTest(path=rejected), self.assertRaisesRegex(
                        RUNNER.MissingDependency, "must remain below"
                    ):
                        RUNNER.resolve_runtime_paths(rejected_arguments, ROOT)
                staged.unlink()
                staged.symlink_to(outside)
                symlink_arguments = self.runtime_args(connector, staged)
                with self.assertRaisesRegex(RUNNER.MissingDependency, "symlink"):
                    RUNNER.resolve_runtime_paths(symlink_arguments, ROOT)

    def test_trusted_executable_rejects_control_characters_before_process_start(self) -> None:
        with tempfile.TemporaryDirectory(prefix="traefik-runtime-root-") as temporary:
            build_root = Path(temporary) / "build"
            build_root.mkdir(mode=0o700)
            binary = self.make_executable(build_root / "traefik-forwardauth")
            executable = RUNNER.require_local_executable(
                binary, "Traefik connector binary", build_root
            )
            self.assertEqual(
                executable.arguments("--check-config"),
                (str(binary), "--check-config"),
            )
            with self.assertRaisesRegex(RUNNER.MissingDependency, "control characters"):
                executable.arguments("--config", "unsafe\nvalue")

    def test_private_socket_override_keeps_long_artifact_roots_and_rejects_unsafe_roots(self) -> None:
        with tempfile.TemporaryDirectory(prefix="uds-") as temporary:
            root = Path(temporary)
            result_root = root / ("a" * 40) / ("b" * 40) / "runtime"
            sockets = root / "s"
            sockets.mkdir(mode=0o700)
            with mock.patch.dict(os.environ, {"MSCONNECTOR_PRIVATE_SOCKET_ROOT": str(sockets)}):
                self.assertEqual(RUNNER.private_companion_directory(result_root, ROOT), sockets)
                sockets.chmod(0o755)
                with self.assertRaisesRegex(RUNNER.MissingDependency, "mode 0700"):
                    RUNNER.private_companion_directory(result_root, ROOT)
                sockets.chmod(0o777)
                with self.assertRaisesRegex(RUNNER.MissingDependency, "writable"):
                    RUNNER.private_companion_directory(result_root, ROOT)
                sockets.chmod(0o700)
                alias = root / "alias"
                alias.symlink_to(sockets)
                os.environ["MSCONNECTOR_PRIVATE_SOCKET_ROOT"] = str(alias)
                with self.assertRaisesRegex(RUNNER.MissingDependency, "symlink"):
                    RUNNER.private_companion_directory(result_root, ROOT)
            with mock.patch.dict(os.environ, {"MSCONNECTOR_PRIVATE_SOCKET_ROOT": ""}):
                with self.assertRaisesRegex(RUNNER.MissingDependency, "too long"):
                    RUNNER.private_companion_directory(result_root, ROOT)

    def test_runtime_artifact_writers_keep_fixed_names_below_validated_directories(self) -> None:
        with tempfile.TemporaryDirectory(prefix="traefik-runtime-root-") as temporary:
            runtime_root = Path(temporary) / "runtime"
            config_dir = runtime_root / "config"
            config_dir.mkdir(parents=True, mode=0o700)
            template = runtime_root / "template.conf"
            rules_file = runtime_root / "rules.conf"
            event_path = runtime_root / "logs" / "events.jsonl"
            template.write_text("rules_file=old\nevent_path=old\n", encoding="utf-8")
            rules_file.write_text("SecRuleEngine On\n", encoding="utf-8")

            service_config = RUNNER.write_concrete_service_config(
                template, config_dir, rules_file, event_path
            )
            result_path = RUNNER.write_runtime_result(runtime_root, {"status": "PASS"})

            self.assertEqual(service_config, config_dir / RUNNER.SERVICE_CONFIG_FILE_NAME)
            self.assertEqual(result_path, runtime_root / RUNNER.RESULT_FILE_NAME)
            self.assertIn(f"rules_file={rules_file}", service_config.read_text(encoding="utf-8"))
            self.assertIn(f"event_path={event_path}", service_config.read_text(encoding="utf-8"))
            result_path.unlink()
            result_path.symlink_to(runtime_root / "outside-result.json")
            with self.assertRaisesRegex(RUNNER.MissingDependency, "runtime artifact path is unsafe"):
                RUNNER.write_runtime_result(runtime_root, {"status": "PASS"})

    def test_result_root_must_be_a_private_build_root_descendant(self) -> None:
        with tempfile.TemporaryDirectory(prefix="traefik-runtime-root-") as temporary:
            temporary_root = Path(temporary)
            build_root = temporary_root / "build"
            build_root.mkdir(mode=0o700)
            output_root = build_root / "traefik-connector" / "runtime-smoke"
            self.assertEqual(
                RUNNER.require_private_result_root(output_root, build_root), output_root
            )

            with self.assertRaisesRegex(RUNNER.MissingDependency, "must remain below"):
                RUNNER.require_private_result_root(temporary_root / "outside", build_root)
            with self.assertRaisesRegex(RUNNER.MissingDependency, "must not be the build root"):
                RUNNER.require_private_result_root(build_root, build_root)

            replaceable = build_root / "replaceable"
            replaceable.mkdir(mode=0o777)
            replaceable.chmod(0o777)
            with self.assertRaisesRegex(RUNNER.MissingDependency, "must not be group or world writable"):
                RUNNER.require_private_result_root(replaceable / "result", build_root)

    def test_canonical_lifecycle_keeps_traefik_results_below_the_stage_build_root(self) -> None:
        lifecycle = (source_path('ci/runtime/lifecycle/run-no-crs-baseline.sh', root=ROOT)).read_text(
            encoding="utf-8"
        )
        self.assertIn("TRAEFIK_RUNTIME_ROOT=$STAGE_BUILD_ROOT/traefik-runtime", lifecycle)
        self.assertNotIn("TRAEFIK_RUNTIME_ROOT=$CONNECTOR_RUN_ROOT/traefik-runtime", lifecycle)

    def test_no_crs_consumer_uses_the_canonical_parent_lifecycle_path(self) -> None:
        with tempfile.TemporaryDirectory(prefix="traefik-no-crs-consumer-") as temporary:
            repo_root = Path(temporary) / "checkout"
            consumer = (
                repo_root
                / "ci"
                / "runtime"
                / "lifecycle"
                / "consume-no-crs-selected-cases.sh"
            )
            self.make_executable(consumer)
            with mock.patch.dict(os.environ, {"MSCONNECTOR_NO_CRS_BASELINE": "1"}, clear=False):
                RUNNER.consume_no_crs_selected_cases(repo_root)

    def test_no_crs_consumer_is_not_required_for_non_baseline_runtime_smoke(self) -> None:
        with tempfile.TemporaryDirectory(prefix="traefik-no-crs-control-") as temporary:
            with mock.patch.dict(os.environ, {"MSCONNECTOR_NO_CRS_BASELINE": ""}, clear=False):
                RUNNER.consume_no_crs_selected_cases(Path(temporary) / "checkout")

    def test_forwardauth_runtime_chain_requires_the_private_response_observer(self) -> None:
        dynamic = RUNNER.dynamic_config(
            18081,
            18082,
            Path("/run/modsecurity/traefik-forwardauth-companion.sock"),
        )
        start_smoke = (source_path('connectors/traefik/scripts/start-smoke.sh', root=ROOT)).read_text(
            encoding="utf-8"
        )
        service = (source_path('connectors/traefik/src/traefik_forwardauth_service_main.c', root=ROOT)).read_text(
            encoding="utf-8"
        )

        self.assertIn("- modsecurity-forwardauth\n      - modsecurity-response-observer", dynamic)
        self.assertIn("authResponseHeaders:\n        - X-Msconnector-Response-Handle", dynamic)
        self.assertIn("socketPath: /run/modsecurity/traefik-forwardauth-companion.sock", dynamic)
        self.assertIn("MSCONNECTOR_TRAEFIK_FORWARDAUTH_COMPANION_SOCKET", start_smoke)
        self.assertIn('getenv(\n        "MSCONNECTOR_TRAEFIK_FORWARDAUTH_COMPANION_SOCKET")', service)
        self.assertIn("plugins-local/src/$OBSERVER_MODULE", start_smoke)
        self.assertIn("__COMPANION_SOCKET__", start_smoke)

    def test_response_observer_restricted_imports_are_scoped_and_loader_failure_aborts(self) -> None:
        command = RUNNER.traefik_command(
            RUNNER.TrustedExecutable(Path("/var/tmp/trusted-traefik")), 18080,
            Path("/var/tmp/dynamic.yml"), Path("/var/tmp/access.log"),
        )
        opt_in = "--experimental.localPlugins.modsecurityResponseObserver.settings.useUnsafe=true"
        self.assertEqual([argument for argument in command if ".settings.useUnsafe=" in argument], [opt_in])
        self.assertIn("--experimental.abortOnPluginFailure=true", command)
        observer = source_path('connectors/traefik/response_observer', root=ROOT)
        self.assertIn("\nuseUnsafe: true", (observer / ".traefik.yml").read_text())
        static = (source_path('connectors/traefik/config/traefik-response-observer-static.yaml', root=ROOT)).read_text()
        self.assertIn("abortOnPluginFailure: true", static)
        self.assertEqual(static.count("useUnsafe: true"), 1)
        self.assertIn("modsecurityResponseObserver:", static)
        startup = (source_path('connectors/traefik/scripts/start-smoke.sh', root=ROOT)).read_text()
        self.assertIn(opt_in, startup)
        self.assertIn("--experimental.abortOnPluginFailure=true", startup)

    def test_real_host_loads_response_observer_and_rejects_missing_import_opt_in(self) -> None:
        host_selection = os.environ.get("TRAEFIK_BIN")
        if not host_selection:
            self.skipTest("TRAEFIK_BIN must provide an already provisioned host for loader verification")
        host = Path(host_selection)
        binary = RUNNER.require_local_executable(host, "test Traefik binary", host.parent)
        with tempfile.TemporaryDirectory(prefix="traefik-loader-") as temporary:
            runtime = Path(temporary)
            RUNNER.stage_response_observer(source_path('connectors/traefik/response_observer', root=ROOT), runtime)
            config = runtime / "dynamic.yml"
            config.write_text(RUNNER.dynamic_config(1, 2, runtime / "companion.sock"))
            port = RUNNER.free_port()
            command = RUNNER.traefik_command(binary, port, config, runtime / "access.log")
            with (runtime / "host.log").open("wb") as log:
                process = subprocess.Popen(command, cwd=runtime, stdout=log, stderr=subprocess.STDOUT)
                try:
                    RUNNER.wait_for_traefik(port, process)
                finally:
                    RUNNER.stop_process(process)
            self.assertNotIn("Plugins are disabled", (runtime / "host.log").read_text())
            # A missing explicit operator opt-in must fail host startup. The
            # manifest continues to declare its restricted import requirement.
            missing_opt_in = tuple(argument for argument in command if ".settings.useUnsafe=" not in argument)
            rejected = subprocess.run(
                missing_opt_in, cwd=runtime, capture_output=True, text=True, timeout=15,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("restricted imports", rejected.stdout + rejected.stderr)
            # The operator setting alone must not grant restricted imports to
            # a plugin that has not explicitly declared that requirement.
            manifest = runtime / "plugins-local/src" / RUNNER.OBSERVER_MODULE / ".traefik.yml"
            manifest.write_text("\n".join(
                line for line in manifest.read_text().splitlines()
                if not line.startswith("useUnsafe:")
            ) + "\n")
            undeclared = subprocess.run(
                command, cwd=runtime, capture_output=True, text=True, timeout=15,
            )
            self.assertNotEqual(undeclared.returncode, 0)
            self.assertIn("syscall", undeclared.stdout + undeclared.stderr)

    def test_peer_credential_platform_constraints_support_native_go_and_host_interpreter(self) -> None:
        observer = source_path('connectors/traefik/response_observer', root=ROOT)
        for name, constraint in (("peercred_linux.go", "linux"), ("peercred_other.go", "!linux")):
            with self.subTest(source=name):
                self.assertTrue((observer / name).read_text().startswith(
                    f"//go:build {constraint}\n// +build {constraint}\n\n"
                ))

    def test_real_host_authenticates_peer_before_sending_companion_claim(self) -> None:
        host_selection = os.environ.get("TRAEFIK_BIN")
        if not host_selection:
            self.skipTest("TRAEFIK_BIN must provide an already provisioned Linux host")
        host = Path(host_selection)
        binary = RUNNER.require_local_executable(host, "test Traefik binary", host.parent)
        for expected_uid in (os.geteuid(), os.geteuid() + 1):
            with self.subTest(expected_uid=expected_uid), tempfile.TemporaryDirectory(
                prefix="traefik-peer-"
            ) as temporary:
                runtime = Path(temporary)
                companion_socket = runtime / "peer.sock"
                frames: list[bytes] = []
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                    listener.bind(str(companion_socket))
                    os.chmod(companion_socket, 0o600)
                    listener.listen(1)
                    listener.settimeout(5)

                    def receive_claim() -> None:
                        connection, _ = listener.accept()
                        with connection:
                            connection.settimeout(5)
                            header = b""
                            while len(header) < 12:
                                chunk = connection.recv(12 - len(header))
                                if not chunk:
                                    break
                                header += chunk
                            frames.append(header)

                    receiver = threading.Thread(target=receive_claim)
                    receiver.start()
                    RUNNER.stage_response_observer(source_path('connectors/traefik/response_observer', root=ROOT), runtime)
                    config = runtime / "dynamic.yml"
                    # Isolate the observer's peer-authentication boundary;
                    # no forwardAuth service or real engine is involved here.
                    dynamic = RUNNER.dynamic_config(1, 2, companion_socket).replace(
                        "      - modsecurity-forwardauth\n", ""
                    ).replace(
                        "          timeoutMillis: 5000",
                        f"          timeoutMillis: 5000\n          expectedPeerUID: {expected_uid}\n"
                        f"          expectedPeerGID: {os.getegid()}",
                    )
                    config.write_text(dynamic)
                    port = RUNNER.free_port()
                    command = RUNNER.traefik_command(binary, port, config, runtime / "access.log")
                    with (runtime / "host.log").open("wb") as log:
                        process = subprocess.Popen(command, cwd=runtime, stdout=log, stderr=subprocess.STDOUT)
                        try:
                            RUNNER.wait_for_traefik(port, process)
                            # The deliberately incomplete companion closes
                            # after CLAIM; neither case may reach upstream.
                            self.assertEqual(RUNNER.http_status(
                                f"http://127.0.0.1:{port}/peer",
                                {"X-Msconnector-Response-Handle": "0" * 64},
                            ), 503)
                        finally:
                            RUNNER.stop_process(process)
                            receiver.join(timeout=6)
                    self.assertFalse(receiver.is_alive())
                    if expected_uid == os.geteuid():
                        self.assertEqual(frames, [b"MRC1\x02\x01\x00\x00\x00\x00\x00\x40"])
                    else:
                        self.assertEqual(frames, [b""])

    def test_forwardauth_preserves_common_header_limit_for_actual_mrc1_framing(self) -> None:
        service = (source_path('connectors/traefik/src/traefik_forwardauth_service_main.c', root=ROOT)).read_text(
            encoding="utf-8"
        )
        observer = (source_path('connectors/traefik/response_observer/observer.go', root=ROOT)).read_text(
            encoding="utf-8"
        )
        compact = "".join(service.split())

        self.assertNotIn("traefik_response_wire_header_limit", service)
        self.assertIn(
            "msconnector_traefik_forwardauth_response_companion_set_limits(companion,"
            "msconnector_runtime_header_count_limit(runtime),"
            "msconnector_runtime_total_header_limit(runtime))",
            compact,
        )
        self.assertNotIn("max_response_body_bytes", service)
        self.assertRegex(observer, r"maxHeaderCount\s*=\s*256")
        self.assertRegex(
            observer,
            r'maxResponseHeaderPayload\s*=\s*maxPayload\s*\+\s*2\s*\+\s*2\s*\+'
            r'\s*len\("HTTP/1\.1"\)\s*\+\s*2\s*\+\s*4\*maxHeaderCount',
        )
        self.assertIn(
            "headerBytes > maxPayload || total > maxResponseHeaderPayload", observer
        )

    def test_response_phase_evidence_requires_precommit_p3_and_safe_p4_without_bodies(self) -> None:
        with tempfile.TemporaryDirectory(prefix="traefik-response-phase-events-") as temporary:
            event_path = Path(temporary) / "events.jsonl"
            records = [
                {
                    "connector": "traefik",
                    "transaction_id": "traefik-forwardauth-p3-block",
                    "rule_id": "1000003",
                    "phase": "response_headers",
                    "status": "blocked",
                    "actual_action": "deny",
                    "response_committed": False,
                },
                {
                    "connector": "traefik",
                    "transaction_id": "traefik-forwardauth-p4-safe",
                    "rule_id": "1000004",
                    "phase": "response_body",
                    "status": "blocked",
                    "actual_action": "log_only",
                    "response_committed": True,
                    "body_bytes_seen": 28,
                },
            ]
            event_path.write_text(
                "\n".join(json.dumps(record) for record in records) + "\n",
                encoding="utf-8",
            )
            RUNNER.verify_response_phase_events(event_path)

            records[1]["response_body"] = "must-not-appear"
            event_path.write_text(
                "\n".join(json.dumps(record) for record in records) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(RuntimeError, "forbidden body payload"):
                RUNNER.verify_response_phase_events(event_path)

    def test_response_observer_staging_is_private_and_rejects_symlinks(self) -> None:
        with tempfile.TemporaryDirectory(prefix="traefik-response-observer-") as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir(mode=0o700)
            (source / "go.mod").write_text("module example.test/observer\n", encoding="utf-8")
            runtime_root = root / "runtime"
            runtime_root.mkdir(mode=0o700)

            RUNNER.stage_response_observer(source, runtime_root)

            staged = runtime_root / "plugins-local" / "src" / RUNNER.OBSERVER_MODULE
            self.assertTrue((staged / "go.mod").is_file())
            self.assertEqual(stat.S_IMODE((runtime_root / "plugins-local").stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((staged / "go.mod").stat().st_mode), 0o600)

            unsafe = root / "unsafe-source"
            unsafe.mkdir(mode=0o700)
            (unsafe / "linked").symlink_to(source / "go.mod")
            with self.assertRaisesRegex(RUNNER.MissingDependency, "contains a symlink"):
                RUNNER.stage_response_observer(unsafe, runtime_root)

    def test_start_smoke_rejects_dotdot_before_cleanup(self) -> None:
        with tempfile.TemporaryDirectory(prefix="traefik-start-root-") as temporary:
            temporary_root = Path(temporary)
            build_root = temporary_root / "build"
            allowed_root = build_root / "traefik-connector"
            target = allowed_root / "other-target"
            target.mkdir(parents=True, mode=0o700)
            sentinel = target / "must-survive"
            sentinel.write_text("keep", encoding="utf-8")
            unsafe_start_root = allowed_root / "owned" / ".." / "other-target"

            result = subprocess.run(
                ["sh", str(source_path('connectors/traefik/scripts/start-smoke.sh', root=ROOT))],
                cwd=ROOT,
                env={
                    **os.environ,
                    "BUILD_ROOT": str(build_root),
                    "TRAEFIK_CONNECTOR_START_ROOT": str(unsafe_start_root),
                },
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 77)
            self.assertIn("dot components", result.stderr)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep")

    def test_default_start_config_uses_run_local_event_path_before_validation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="traefik-start-config-") as temporary:
            root = Path(temporary)
            build = root / "build"
            (build / "traefik-connector").mkdir(parents=True, mode=0o700)
            connector = self.make_executable(root / "connector")
            connector.write_text("#!/bin/sh\nexit 19\n")
            host = self.make_executable(root / "traefik")
            observer_build = self.make_executable(root / "observer-build")
            environment = {**os.environ, "BUILD_ROOT": str(build),
                           "TRAEFIK_CONNECTOR_BIN": str(connector), "TRAEFIK_BIN": str(host),
                           "TRAEFIK_RESPONSE_OBSERVER_BUILD": str(observer_build)}
            environment.pop("TRAEFIK_CONNECTOR_CONFIG", None)
            result = subprocess.run(
                ["sh", str(source_path('connectors/traefik/scripts/start-smoke.sh', root=ROOT))],
                cwd=ROOT, env=environment, capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 19)
            self.assertIn("config check failed", result.stderr)
            start = build / "traefik-connector/start-smoke"
            generated = (start / "traefik-forwardauth.conf").read_text()
            source = (source_path('connectors/traefik/config/traefik-forwardauth.conf', root=ROOT)).read_text()
            self.assertEqual(generated, "\n".join(
                f"event_path={start}/events.jsonl" if line.startswith("event_path=") else
                f"rules_file={source_path('common/rules/modsecurity_targeted_smoke.conf', root=ROOT)}" if line.startswith("rules_file=") else line
                for line in source.splitlines()
            ) + "\n")

# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)
