"""Regression coverage for root NGINX harness output-path authority."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import os
import json
import shlex
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = connector_root()
VALIDATOR = source_path('ci/runtime/common/validate-nginx-harness-paths.py', root=ROOT)
PROJECTOR = source_path('ci/runtime/common/prepare-nginx-docroot-projection.py', root=ROOT)
HARNESS = source_path('connectors/nginx/harness/run_nginx_smoke.sh', root=ROOT)


class NginxHarnessPathAuthorityTests(unittest.TestCase):
    maxDiff = None

    def run_validator(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(VALIDATOR), *arguments],
            cwd=ROOT,
            check=False,
            text=True,
            capture_output=True,
        )

    def run_projector(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(PROJECTOR), *arguments],
            cwd=ROOT,
            check=False,
            text=True,
            capture_output=True,
        )

    @staticmethod
    def directory_identity_and_mode(path: Path) -> tuple[int, int, int]:
        metadata = path.lstat()
        return metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode)

    @staticmethod
    def worker_traversable_temporary_directory() -> tempfile.TemporaryDirectory[str]:
        candidates = (Path(tempfile.gettempdir()), Path("/tmp"), Path("/dev/shm"))
        attempted: set[Path] = set()
        failures: list[str] = []

        for candidate in candidates:
            if candidate in attempted:
                continue
            attempted.add(candidate)
            current = Path("/")
            for component in candidate.parts[1:]:
                current /= component
                try:
                    metadata = current.lstat()
                except OSError as exc:
                    failures.append(f"{candidate}: {exc}")
                    break
                if not stat.S_ISDIR(metadata.st_mode) or not metadata.st_mode & stat.S_IXOTH:
                    failures.append(f"{candidate}: non-traversable ancestor")
                    break
            else:
                try:
                    return tempfile.TemporaryDirectory(
                        prefix="nginx-path-authority-", dir=candidate
                    )
                except OSError as exc:
                    failures.append(f"{candidate}: {exc}")

        raise RuntimeError(
            "no worker-traversable temporary directory available: " + "; ".join(failures)
        )

    def run_parent_harness_with_output_override(
        self,
        verified_root: Path,
        variable: str,
        outside_path: Path,
    ) -> subprocess.CompletedProcess[str]:
        build_root = verified_root / "build"
        environment = os.environ.copy()
        for inherited in (
            "NGINX_HARNESS_WORK_ROOT",
            "RUNTIME_ROOT",
            "PERMISSIONS_LOG",
            "NGINX_WORKER_PREFLIGHT_FILE",
        ):
            environment.pop(inherited, None)
        environment.update(
            {
                "PYTHON": sys.executable,
                "PYTHONDONTWRITEBYTECODE": "1",
                "VERIFIED_RUN_ROOT": str(verified_root),
                "VERIFIED_BUILD_ROOT": str(build_root),
                "BUILD_ROOT": str(build_root),
                "NGINX_HARNESS_PARENT": str(build_root / "nginx-harness"),
                "RUNTIME_BASE": str(build_root / "runtime"),
                "RESULTS_DIR": str(build_root / "results"),
                "RUN_ONE_CASE": "0",
                "MSCONNECTOR_SMOKE_STAGE": "config_load",
                variable: str(outside_path),
            }
        )
        return subprocess.run(
            ["sh", str(HARNESS)],
            cwd=ROOT,
            check=False,
            text=True,
            capture_output=True,
            env=environment,
        )

    def test_case_metadata_uses_validated_private_work_root_and_rejects_escapes(self) -> None:
        framework = source_path('modules/ModSecurity-test-Framework', root=ROOT)
        case = framework / "tests/cases/phases/phase2/phase2_args_block.yaml"
        source = HARNESS.read_text()
        function = "write_case_result() {" + source.split("write_case_result() {", 1)[1].split(
            "\nrequire_bounded_positive_decimal", 1
        )[0]
        with tempfile.TemporaryDirectory(prefix="nginx-case-output-root-") as temporary:
            verified = Path(temporary) / "verified"
            build = verified / "build"
            parent = verified / "nginx-harness"
            private = parent / "private-work"
            logs = private / "logs"
            validator = self.run_validator("--verified-run-root", str(verified),
                "--directory", "BUILD_ROOT", str(build),
                "--directory", "NGINX_HARNESS_PARENT", str(parent),
                "--directory", "NGINX_HARNESS_WORK_ROOT", str(private),
                "--directory", "LOG_DIR", str(logs), "--quiet")
            self.assertEqual(validator.returncode, 0, validator.stderr)
            env = {**os.environ, "PYTHON_BIN": sys.executable,
                   "CASE_CLI": str(framework / "tests/runners/case_cli.py"),
                   "BUILD_ROOT": str(build), "NGINX_HARNESS_WORK_ROOT": str(private),
                   "MODSECURITY_TEST_VARIANT": "no-crs", "PYTHONDONTWRITEBYTECODE": "1"}

            def write_metadata(output: Path, actual_status: str) -> subprocess.CompletedProcess[str]:
                arguments = (str(case), "blocked" if not actual_status else "pass", actual_status,
                             str(output), "http_status", "host preflight blocked" if not actual_status else "")
                return subprocess.run(["sh", "-eu", "-c", function + "\nwrite_case_result " +
                    " ".join(shlex.quote(argument) for argument in arguments)],
                    cwd=ROOT, env=env, capture_output=True, text=True, timeout=30)

            for actual_status in ("", "403"):
                output = logs / ("blocked" if not actual_status else "observed") / "result.json"
                result = write_metadata(output, actual_status)
                with self.subTest(actual_status=actual_status):
                    self.assertEqual(result.returncode, 0, result.stderr)
                    data = json.loads(output.read_text())
                    self.assertEqual(data["status"], "blocked" if not actual_status else "pass")
                    self.assertEqual(data["executed_connector"], "nginx")
            outside = verified / "outside-private-work"
            escape = private / "escape"
            escape.symlink_to(outside, target_is_directory=True)
            for output in (outside / "result.json", escape / "result.json"):
                result = write_metadata(output, "")
                with self.subTest(output=output):
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("write path escapes output root", result.stderr)
                    self.assertFalse(outside.exists())
            self.assertTrue(escape.is_symlink())
        # The real entrypoint validates the work root before the multi-case
        # parent can project metadata for a blocked child process.
        entry = source.split("initialize_nginx_harness_paths\n", 1)[1]
        self.assertLess(entry.index("if [ \"$RUN_ONE_CASE\" != \"1\" ]"), entry.index("TEST_CASE=$(resolve_case_path"))
        self.assertIn("validate_nginx_harness_outer_paths", source.split("initialize_nginx_harness_paths() {", 1)[1].split("\n}\n", 1)[0])

    def test_system_root_is_rejected_before_any_output_is_authorized(self) -> None:
        result = self.run_validator(
            "--verified-run-root",
            "/etc",
            "--directory",
            "LOG_DIR",
            "/etc/codex-nginx-harness-regression",
            "--quiet",
        )

        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("runtime root is unsafe for writes: /etc", result.stderr)

    def test_sibling_and_symlink_escape_are_rejected_without_creating_targets(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nginx-path-authority-") as temporary:
            base = Path(temporary)
            verified_root = base / "ModSecurity-conector-verified"
            sibling = base / "outside"
            escaped = verified_root / "escape"
            verified_root.mkdir()
            escaped.symlink_to(sibling, target_is_directory=True)

            sibling_result = self.run_validator(
                "--verified-run-root",
                str(verified_root),
                "--directory",
                "LOG_DIR",
                str(sibling / "logs"),
                "--quiet",
            )
            self.assertEqual(sibling_result.returncode, 2, sibling_result.stderr)
            self.assertFalse(sibling.exists())

            escape_result = self.run_validator(
                "--verified-run-root",
                str(verified_root),
                "--directory",
                "LOG_DIR",
                str(escaped / "logs"),
                "--quiet",
            )
            self.assertEqual(escape_result.returncode, 2, escape_result.stderr)
            self.assertFalse(sibling.exists())

    def test_synchronized_upstream_control_root_escape_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nginx-path-authority-") as temporary:
            base = Path(temporary)
            verified_root = base / "ModSecurity-conector-verified"
            outside_root = base / "outside-synchronized-control"
            verified_root.mkdir()

            result = self.run_validator(
                "--verified-run-root",
                str(verified_root),
                "--directory",
                "SYNCHRONIZED_UPSTREAM_CONTROL_ROOT",
                str(outside_root),
                "--quiet",
            )

            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("must be below the runtime root", result.stderr)
            self.assertFalse(outside_root.exists())

    def test_verified_runtime_descendants_and_direct_log_child_are_accepted(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nginx-path-authority-") as temporary:
            verified_root = Path(temporary) / "ModSecurity-conector-verified"
            build_root = verified_root / "build"
            log_dir = build_root / "logs"
            config_file = build_root / "runtime" / "nginx.conf"
            permissions_log = log_dir / "permissions.log"

            result = self.run_validator(
                "--verified-run-root",
                str(verified_root),
                "--directory",
                "BUILD_ROOT",
                str(build_root),
                "--directory",
                "LOG_DIR",
                str(log_dir),
                "--path",
                "CONFIG_FILE",
                str(config_file),
                "--direct-child",
                "PERMISSIONS_LOG",
                str(permissions_log),
                str(log_dir),
                "--quiet",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(verified_root.is_dir())
            self.assertTrue(build_root.is_dir())
            self.assertTrue(log_dir.is_dir())
            self.assertTrue(config_file.parent.is_dir())
            self.assertFalse(config_file.exists())
            self.assertFalse(permissions_log.exists())

    def test_explicit_external_projection_parent_is_narrowly_authorized(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nginx-path-authority-") as temporary:
            base = Path(temporary)
            verified_root = base / "verified"
            projection_parent = base / "worker-visible-projection"
            projection_root = projection_parent / "nginx-docroot"
            projection_parent.mkdir(mode=0o711)
            projection_parent.chmod(0o711)

            result = self.run_validator(
                "--verified-run-root",
                str(verified_root),
                "--existing-private-directory",
                "NGINX_DOCROOT_PROJECTION_PARENT",
                str(projection_parent),
                "--existing-direct-child",
                "NGINX_DOCROOT_PROJECTION_ROOT",
                str(projection_root),
                str(projection_parent),
                "--quiet",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(projection_parent.is_dir())
            self.assertFalse(projection_root.exists())

    def test_validator_and_projector_keep_external_projection_narrow(self) -> None:
        """Exercise the real CLI boundary without starting a privileged NGINX runtime."""

        with self.worker_traversable_temporary_directory() as temporary:
            base = Path(temporary)
            # The helper checks every ancestor for worker traversal.  Keep the
            # test-owned outer directory non-enumerable but traversable.
            base.chmod(0o711)
            verified_root = base / "verified"
            generic_output_directory = verified_root / "generic-output"
            generic_output = generic_output_directory / "status.txt"
            private_root = verified_root / "build"
            source_docroot = private_root / "runtime" / "htdocs"
            projection_parent = base / "worker-visible-projection"
            projection_root = projection_parent / "explicit-docroot"
            projection_parent.mkdir(mode=0o711)
            projection_parent.chmod(0o711)
            parent_before = self.directory_identity_and_mode(projection_parent)

            validation = self.run_validator(
                "--verified-run-root",
                str(verified_root),
                "--directory",
                "GENERIC_OUTPUT_DIRECTORY",
                str(generic_output_directory),
                "--path",
                "GENERIC_OUTPUT",
                str(generic_output),
                "--existing-private-directory",
                "NGINX_DOCROOT_PROJECTION_PARENT",
                str(projection_parent),
                "--existing-direct-child",
                "NGINX_DOCROOT_PROJECTION_ROOT",
                str(projection_root),
                str(projection_parent),
                "--quiet",
            )

            self.assertEqual(validation.returncode, 0, validation.stderr)
            self.assertTrue(generic_output_directory.is_dir())
            self.assertEqual(
                generic_output.relative_to(verified_root),
                Path("generic-output") / "status.txt",
            )
            self.assertFalse(generic_output.exists())
            self.assertFalse(projection_root.exists())
            self.assertEqual(self.directory_identity_and_mode(projection_parent), parent_before)

            generic_output.write_text("verified generic output\n", encoding="utf-8")
            source_docroot.mkdir(parents=True, mode=0o700)
            (source_docroot / "index.html").write_text("projected index\n", encoding="utf-8")
            (source_docroot / "__modsec_smoke_ready").write_text("ready\n", encoding="utf-8")
            (source_docroot / "not-projected.txt").write_text("private\n", encoding="utf-8")

            projection = self.run_projector(
                "--source-docroot",
                str(source_docroot),
                "--private-root",
                str(private_root),
                "--worker-gid",
                str(os.getegid()),
                "--projection-parent",
                str(projection_parent),
                "--projection-root",
                str(projection_root),
                "--avoid-root",
                str(verified_root),
            )

            self.assertEqual(projection.returncode, 0, projection.stderr)
            self.assertEqual(projection.stdout.strip(), str(projection_root))
            self.assertEqual(projection_root.parent, projection_parent)
            self.assertEqual(
                {entry.name for entry in projection_parent.iterdir()},
                {projection_root.name},
            )
            self.assertEqual(
                {entry.name for entry in projection_root.iterdir()},
                {"index.html", "__modsec_smoke_ready"},
            )
            self.assertEqual(
                (projection_root / "index.html").read_text(encoding="utf-8"),
                "projected index\n",
            )
            self.assertEqual(
                (projection_root / "__modsec_smoke_ready").read_text(encoding="utf-8"),
                "ready\n",
            )
            self.assertFalse((projection_root / "not-projected.txt").exists())
            self.assertEqual(stat.S_IMODE(projection_root.lstat().st_mode), 0o710)
            self.assertEqual(projection_root.lstat().st_gid, os.getegid())
            for filename in ("index.html", "__modsec_smoke_ready"):
                projected_file = projection_root / filename
                self.assertEqual(stat.S_IMODE(projected_file.lstat().st_mode), 0o640)
                self.assertEqual(projected_file.lstat().st_gid, os.getegid())
            self.assertTrue(generic_output.is_file())
            self.assertEqual(
                generic_output.relative_to(verified_root),
                Path("generic-output") / "status.txt",
            )
            self.assertFalse((projection_parent / generic_output.name).exists())
            self.assertEqual(self.directory_identity_and_mode(projection_parent), parent_before)

    def test_stale_external_projection_child_is_rejected_before_projection(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nginx-path-authority-") as temporary:
            base = Path(temporary)
            base.chmod(0o711)
            verified_root = base / "verified"
            projection_parent = base / "worker-visible-projection"
            projection_root = projection_parent / "explicit-docroot"
            projection_parent.mkdir(mode=0o711)
            projection_parent.chmod(0o711)
            projection_root.mkdir(mode=0o700)
            marker = projection_root / "existing-marker"
            marker.write_text("keep\n", encoding="utf-8")
            parent_before = self.directory_identity_and_mode(projection_parent)

            result = self.run_validator(
                "--verified-run-root",
                str(verified_root),
                "--existing-private-directory",
                "NGINX_DOCROOT_PROJECTION_PARENT",
                str(projection_parent),
                "--existing-direct-child",
                "NGINX_DOCROOT_PROJECTION_ROOT",
                str(projection_root),
                str(projection_parent),
                "--quiet",
            )

            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("must be a fresh non-symlink child", result.stderr)
            self.assertEqual(marker.read_text(encoding="utf-8"), "keep\n")
            self.assertEqual(
                {entry.name for entry in projection_parent.iterdir()},
                {projection_root.name},
            )
            self.assertEqual(self.directory_identity_and_mode(projection_parent), parent_before)

    def test_system_projection_parent_is_rejected_without_creating_a_child(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nginx-path-authority-") as temporary:
            result = self.run_validator(
                "--verified-run-root",
                str(Path(temporary) / "verified"),
                "--existing-private-directory",
                "NGINX_DOCROOT_PROJECTION_PARENT",
                "/etc",
                "--existing-direct-child",
                "NGINX_DOCROOT_PROJECTION_ROOT",
                "/etc/codex-nginx-harness-regression",
                "/etc",
                "--quiet",
            )

            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("unsafe for runtime writes: /etc", result.stderr)

    def test_parent_multi_case_outputs_are_rejected_before_their_first_write(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nginx-path-authority-") as temporary:
            base = Path(temporary)
            for variable, suffix in (
                ("LOG_DIR", "logs"),
                ("RESULTS_DIR", "results"),
            ):
                with self.subTest(variable=variable):
                    verified_root = base / f"verified-{suffix}"
                    outside_path = base / f"outside-{suffix}" / suffix
                    result = self.run_parent_harness_with_output_override(
                        verified_root,
                        variable,
                        outside_path,
                    )

                    self.assertEqual(result.returncode, 77, result.stderr)
                    self.assertIn("outside verified runtime storage", result.stdout)
                    self.assertFalse(outside_path.parent.exists())

    def test_harness_validates_authority_before_root_mutation_sinks(self) -> None:
        harness = HARNESS.read_text(encoding="utf-8")

        for fragment in (
            "validate-nginx-harness-paths.py",
            "validate_nginx_harness_bootstrap_paths",
            "validate_nginx_harness_outer_paths",
            "validate_nginx_generated_path_authority",
            "validate_nginx_external_projection_authority",
            "--verified-run-root \"$VERIFIED_RUN_ROOT\"",
            "--directory RESULTS_DIR \"$RESULTS_DIR\"",
            "--direct-child PERMISSIONS_LOG \"$PERMISSIONS_LOG\" \"$LOG_DIR\"",
            "--direct-child NGINX_WORKER_PREFLIGHT_FILE \"$NGINX_WORKER_PREFLIGHT_FILE\" \"$LOG_DIR\"",
            "--existing-private-directory NGINX_DOCROOT_PROJECTION_PARENT \"$NGINX_DOCROOT_PROJECTION_PARENT\"",
            "--existing-direct-child NGINX_DOCROOT_PROJECTION_ROOT \"$NGINX_DOCROOT_PROJECTION_ROOT\" \"$NGINX_DOCROOT_PROJECTION_PARENT\"",
            "validate_nginx_request_output_path SEND_CASE_RESPONSE_BODY \"$response_output\"",
            "validate_nginx_request_output_path SEND_CASE_CURL_ERROR_LOG \"$curl_error_output\"",
            "NGINX_PATHS_VALIDATED=1",
            "write_harness_status",
        ):
            self.assertIn(fragment, harness)

        authority_call = harness.rindex("validate_nginx_generated_path_authority")
        projection_authority_call = harness.rindex("validate_nginx_external_projection_authority")
        first_root_mutation = harness.index('ensure_dir_755 "$NGINX_HARNESS_WORK_ROOT"')
        self.assertLess(authority_call, first_root_mutation)
        self.assertLess(projection_authority_call, first_root_mutation)
        outer_authority_call = harness.rindex("validate_nginx_harness_outer_paths")
        all_case_root_mutation = harness.index('mkdir -p "$LOG_DIR" "$RESULTS_DIR"')
        self.assertLess(outer_authority_call, all_case_root_mutation)
        blocked_definition = harness[
            harness.index("blocked() {") : harness.index("fail() {")
        ]
        self.assertNotIn("mkdir", blocked_definition)

    def test_worker_path_authority_precedes_the_non_root_handoff(self) -> None:
        """Keep generic current-owner validation before worker-owned leaves exist."""

        harness = HARNESS.read_text(encoding="utf-8")
        worker_state_path_assigned = harness.index(
            'NGINX_WORKER_STATE_ROOT="$NGINX_HARNESS_WORK_ROOT/worker-state/$case_name"'
        )
        server_log_path_assigned = harness.index(
            'NGINX_SERVER_LOG_ROOT="$NGINX_HARNESS_WORK_ROOT/server-logs/$case_name"'
        )
        authority_call = harness.rindex("validate_nginx_generated_path_authority")
        first_root_mutation = harness.index('ensure_dir_755 "$NGINX_HARNESS_WORK_ROOT"')
        first_worker_handoff = harness.index(
            "prepare_nginx_worker_paths", first_root_mutation
        )

        self.assertLess(worker_state_path_assigned, authority_call)
        self.assertLess(server_log_path_assigned, authority_call)
        self.assertLess(authority_call, first_root_mutation)
        self.assertLess(authority_call, first_worker_handoff)
        self.assertEqual(
            harness.find("validate_nginx_generated_path_authority", first_worker_handoff),
            -1,
        )

        authority_function_start = harness.index(
            "validate_nginx_generated_path_authority() {"
        )
        authority_function = harness[
            authority_function_start : harness.index(
                "\n}\n\nvalidate_nginx_external_projection_authority()",
                authority_function_start,
            )
        ]
        self.assertIn(
            '--directory NGINX_WORKER_STATE_ROOT "$NGINX_WORKER_STATE_ROOT"',
            authority_function,
        )
        self.assertIn(
            '--directory NGINX_SERVER_LOG_ROOT "$NGINX_SERVER_LOG_ROOT"',
            authority_function,
        )
        self.assertLess(
            authority_function.index('if ! "$@"; then'),
            authority_function.index('chown root:root "$NGINX_HARNESS_PARENT"'),
        )

        worker_handoff = harness[
            harness.index("prepare_nginx_worker_paths() {") : harness.index(
                "\n}\n\nresolve_nginx_worker_identity()"
            )
        ]
        self.assertIn(
            'chown "$NGINX_WORKER_RESOLVED_USER:$worker_group" "$path"',
            worker_handoff,
        )
        self.assertIn('chmod 700 "$path"', worker_handoff)

    def test_worker_preflight_uses_the_rendered_nginx_group(self) -> None:
        harness = HARNESS.read_text(encoding="utf-8")
        worker_access = harness[
            harness.index("nginx_worker_can_access() {") : harness.index(
                "\n}\n\nnginx_worker_identity_is_verifiable()"
            )
        ]
        render_config = harness[
            harness.index("render_config() {") : harness.index("\n}\n\n", harness.index("render_config() {"))
        ]

        self.assertIn(
            'nginx_worker_runuser -u "$NGINX_WORKER_USER" -g "$NGINX_WORKER_RESOLVED_GROUP" --',
            worker_access,
        )
        self.assertIn(
            'user $NGINX_WORKER_RESOLVED_USER $NGINX_WORKER_RESOLVED_GROUP;',
            render_config,
        )

    def test_worker_helpers_use_only_fixed_runuser_capabilities(self) -> None:
        harness = HARNESS.read_text(encoding="utf-8")
        availability = harness[
            harness.index("nginx_worker_runuser_is_available() {") : harness.index(
                "\n}\n\nnginx_worker_runuser()"
            )
        ]
        invocation = harness[
            harness.index("nginx_worker_runuser() {") : harness.index(
                "\n}\n\nnginx_worker_can_access()"
            )
        ]

        self.assertIn("[ -x /usr/sbin/runuser ] || [ -x /usr/bin/runuser ]", availability)
        self.assertIn('/usr/sbin/runuser "$@"', invocation)
        self.assertIn('/usr/bin/runuser "$@"', invocation)
        worker_helpers = availability + invocation
        self.assertNotIn("command -v runuser", worker_helpers)
        self.assertNotIn("PATH=", worker_helpers)
        self.assertNotIn("RUNUSER_BIN", worker_helpers)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
