"""Static and local-contract coverage for the opt-in NGINX Memcheck path."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = connector_root()
HARNESS = source_path('connectors/nginx/harness/run_nginx_smoke.sh', root=ROOT)
TEMPLATE = source_path('connectors/nginx/harness/nginx_smoke.conf', root=ROOT)
MAKEFILE = source_path('Makefile', root=ROOT)
SUMMARIZER = source_path('ci/runtime/common/summarize-nginx-memcheck.py', root=ROOT)
SUPPRESSIONS = source_path('connectors/nginx/harness/valgrind-nginx-core-1.31.2.supp', root=ROOT)


def load_summarizer_module():
    module = load_source(SUMMARIZER)
    return module


SUMMARIZER_MODULE = load_summarizer_module()


class NginxMemcheckHarnessContractTests(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls) -> None:
        cls.harness = HARNESS.read_text(encoding="utf-8")
        cls.template = TEMPLATE.read_text(encoding="utf-8")
        cls.makefile = MAKEFILE.read_text(encoding="utf-8")
        cls.summarizer = SUMMARIZER.read_text(encoding="utf-8")
        cls.suppressions = SUPPRESSIONS.read_text(encoding="utf-8")

    @staticmethod
    def private_evidence_directory(temporary: str) -> Path:
        """Keep the direct parent private even though TemporaryDirectory lives below /tmp."""

        private_parent = Path(temporary) / "private-parent"
        private_parent.mkdir(mode=0o700)
        private_parent.chmod(0o700)
        evidence_directory = private_parent / "nginx-memcheck-evidence"
        evidence_directory.mkdir(mode=0o700)
        evidence_directory.chmod(0o700)
        return evidence_directory

    @staticmethod
    def write_private(path: Path, contents: str) -> None:
        path.write_text(contents, encoding="utf-8")
        path.chmod(0o600)

    @classmethod
    def create_clean_evidence(
        cls,
        log_dir: Path,
        *,
        master_pid: int,
        worker_pid: int,
        log_contents: str | None = None,
    ) -> tuple[Path, Path, Path, Path]:
        roles = log_dir / "nginx-memcheck-roles.txt"
        lifecycle = log_dir / "nginx-memcheck-lifecycle.txt"
        output = log_dir / "nginx-memcheck-summary.json"
        text_output = log_dir / "nginx-memcheck-summary.txt"
        cls.write_private(
            roles, f"master_pid={master_pid}\nworker_pid={worker_pid}\n"
        )
        cls.write_private(
            lifecycle,
            "shutdown=graceful\nwait=exited\nwrapper_exit_code=0\ncontainment=isolated\n",
        )
        if log_contents is None:
            log_contents = (
                f"=={master_pid}== definitely lost: 0 bytes in 0 blocks\n"
                f"=={master_pid}== indirectly lost: 0 bytes in 0 blocks\n"
                f"=={master_pid}== possibly lost: 0 bytes in 0 blocks\n"
                f"=={master_pid}== still reachable: 0 bytes in 0 blocks\n"
                f"=={master_pid}== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)\n"
            )
        cls.write_private(log_dir / f"valgrind.{master_pid}.log", log_contents)
        cls.write_private(log_dir / f"valgrind.{worker_pid}.log", log_contents)
        return roles, lifecycle, output, text_output

    @staticmethod
    def run_summarizer(
        log_dir: Path,
        roles: Path,
        lifecycle: Path,
        output: Path,
        text_output: Path,
        *,
        verified_run_root: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        del roles, lifecycle, output, text_output
        return subprocess.run(
            [
                sys.executable,
                str(SUMMARIZER),
                "--verified-run-root",
                str(verified_run_root or log_dir.parent),
                "--log-dir",
                str(log_dir),
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_memcheck_is_explicitly_opt_in_and_bounded_to_soak(self) -> None:
        self.assertIn('NGINX_MEMCHECK="${NGINX_MEMCHECK:-0}"', self.harness)
        self.assertIn('VALGRIND_BIN="${VALGRIND_BIN:-valgrind}"', self.harness)
        self.assertIn(
            'NGINX_MEMCHECK_SUPPRESSIONS="$SCRIPT_DIR/valgrind-nginx-core-1.31.2.supp"',
            self.harness,
        )
        self.assertNotIn("${NGINX_MEMCHECK_SUPPRESSIONS:-", self.harness)
        self.assertIn('NGINX_MEMCHECK=1 requires MSCONNECTOR_SMOKE_STAGE=bounded_soak', self.harness)
        self.assertIn('NGINX_MEMCHECK=1 requires NGINX_PROTOCOL_PROFILE=h1', self.harness)
        self.assertIn('NGINX_MEMCHECK=1 requires exactly one canonical NGINX_SOAK_CASES id', self.harness)
        self.assertIn('NGINX_MEMCHECK_WAIT_SECONDS=30', self.harness)
        self.assertIn('validate_nginx_memcheck_mode', self.harness)
        self.assertIn('blocked "missing executable Valgrind;', self.harness)

    def test_memcheck_suppression_is_bound_to_verified_nginx_1_31_2_identity(self) -> None:
        self.assertIn('NGINX_BINARY="${NGINX_BINARY:-$NGINX_PREFIX/sbin/nginx}"', self.harness)
        self.assertIn("NGINX_MEMCHECK_EXPECTED_VERSION=1.31.2", self.harness)
        self.assertIn(
            'NGINX_MEMCHECK_NGINX_BINARY="$NGINX_PREFIX/sbin/nginx"',
            self.harness,
        )
        self.assertIn(
            'NGINX_MEMCHECK_NGINX_ARCHIVE="$NGINX_BUILD_DIR/verified-archives/nginx-1.31.2.tar.gz"',
            self.harness,
        )
        self.assertIn(
            "NGINX_MEMCHECK_NGINX_ARCHIVE_SHA256="
            "af2a957c41da636ddc4f883e4523c6d140b4784dbce42000c364ae5092aa473c",
            self.harness,
        )
        identity = self.harness.split("validate_nginx_memcheck_binary_identity() {", 1)[1].split(
            "\n}\n\nvalidate_nginx_memcheck_mode()", 1
        )[0]
        self.assertIn('[ "$NGINX_BINARY" = "$NGINX_MEMCHECK_NGINX_BINARY" ]', identity)
        self.assertIn('"$NGINX_BINARY" -v 2>&1', identity)
        self.assertIn(
            '"nginx version: nginx/$NGINX_MEMCHECK_EXPECTED_VERSION"', identity
        )
        self.assertIn('command -v sha256sum >/dev/null 2>&1', identity)
        self.assertIn('sha256sum "$NGINX_MEMCHECK_NGINX_ARCHIVE"', identity)
        self.assertIn(
            '[ "$NGINX_MEMCHECK_NGINX_ARCHIVE_ACTUAL_SHA256" = '
            '"$NGINX_MEMCHECK_NGINX_ARCHIVE_SHA256" ]',
            identity,
        )
        mode = self.harness.split("validate_nginx_memcheck_mode() {", 1)[1].split(
            "\n}\n\nvalidate_nginx_protocol_request()", 1
        )[0]
        self.assertIn("validate_nginx_memcheck_binary_identity", mode)
        self.assertLess(
            mode.index("0) return 0 ;;"),
            mode.index("validate_nginx_memcheck_binary_identity"),
        )

    def test_default_harness_parent_is_contained_by_build_root(self) -> None:
        self.assertIn(
            'NGINX_HARNESS_PARENT="${NGINX_HARNESS_PARENT:-$BUILD_ROOT/nginx-harness}"',
            self.harness,
        )
        self.assertIn("NGINX_HARNESS_PARENT ?= $(BUILD_ROOT)/nginx-harness", self.makefile)
        self.assertNotIn('fallback_parent="/var/tmp"', self.harness)
        self.assertIn("not silently reroute the default parent", self.harness)

    def test_configtest_stays_uninstrumented_and_runtime_uses_required_flags(self) -> None:
        configtest = '"$NGINX_BINARY" -t -p "$RUNTIME_ROOT" -c "$CONFIG_FILE"'
        valgrind_start = 'exec "$SETSID_BIN" "$VALGRIND_BIN"'
        self.assertIn(configtest, self.harness)
        self.assertIn(valgrind_start, self.harness)
        start_server = self.harness.split("start_server() {", 1)[1].split(
            "\n}\n\nsend_case_request()", 1
        )[0]
        self.assertLess(start_server.index(configtest), start_server.index("start_nginx_process"))
        for flag in (
            "--trace-children=yes",
            "--vgdb=no",
            "--leak-check=full",
            "--show-leak-kinds=definite,indirect,possible",
            "--errors-for-leak-kinds=definite,indirect",
            "--error-exitcode=99",
            "--num-callers=24",
            '--log-file="$NGINX_MEMCHECK_EVIDENCE_DIR/valgrind.%p.log"',
        ):
            self.assertIn(flag, self.harness)
        self.assertNotIn("--child-silent-after-fork", self.harness)
        self.assertIn('--suppressions="$NGINX_MEMCHECK_SUPPRESSIONS"', self.harness)
        self.assertIn("daemon off;", self.template)
        self.assertIn("worker_processes 1;", self.template)

    def test_nginx_core_exit_suppression_is_exact_and_definite_only(self) -> None:
        self.assertEqual(
            [line.strip() for line in self.suppressions.splitlines() if line.strip()],
            [
                "{",
                "nginx_1_31_2_worker_environment_exit_lifetime",
                "Memcheck:Leak",
                "match-leak-kinds: definite",
                "fun:malloc",
                "fun:ngx_alloc",
                "fun:ngx_set_environment",
                "fun:ngx_worker_process_init",
                "fun:ngx_worker_process_cycle",
                "fun:ngx_spawn_process",
                "fun:ngx_start_worker_processes",
                "fun:ngx_master_process_cycle",
                "fun:main",
                "}",
            ],
        )
        self.assertNotIn("...", self.suppressions)
        self.assertNotIn("ngx_http_modsecurity", self.suppressions)
        self.assertNotIn("libmodsecurity", self.suppressions)
        self.assertNotIn("Memcheck:Addr", self.suppressions)

    def test_lifecycle_uses_graceful_quit_bounded_wait_and_payload_free_summary(self) -> None:
        self.assertIn('"$NGINX_BINARY" -p "$RUNTIME_ROOT" -c "$CONFIG_FILE" -s quit', self.harness)
        self.assertIn('wait_for_nginx_memcheck_exit "$NGINX_MEMCHECK_WAIT_SECONDS"', self.harness)
        self.assertIn('exec "$SETSID_BIN" "$VALGRIND_BIN"', self.harness)
        self.assertIn("signal_nginx_memcheck_processes TERM", self.harness)
        self.assertIn("signal_nginx_memcheck_processes KILL", self.harness)
        self.assertIn("NGINX_MEMCHECK_CONTAINMENT", self.harness)
        self.assertIn('record_nginx_memcheck_process_group "$NGINX_PID"', self.harness)
        self.assertIn("nginx_memcheck_process_group_alive", self.harness)
        self.assertIn('kill -0 "-$NGINX_MEMCHECK_PROCESS_GROUP"', self.harness)
        self.assertIn("umask 077", self.harness)
        self.assertIn("NGINX_MEMCHECK_EVIDENCE_DIR", self.harness)
        self.assertIn(
            'NGINX_MEMCHECK_EVIDENCE_DIR="$LOG_DIR/memcheck-evidence/$case_name"',
            self.harness,
        )
        self.assertIn('--verified-run-root "$VERIFIED_RUN_ROOT"', self.harness)
        self.assertIn('--log-dir "$NGINX_MEMCHECK_EVIDENCE_DIR"', self.harness)
        self.assertIn('( umask 077; : > "$NGINX_MEMCHECK_ROLE_FILE" )', self.harness)
        self.assertIn('chmod 600 "$NGINX_MEMCHECK_ROLE_FILE"', self.harness)
        self.assertIn('} > "$NGINX_MEMCHECK_LIFECYCLE_FILE"', self.harness)
        self.assertIn('chmod 600 "$NGINX_MEMCHECK_LIFECYCLE_FILE"', self.harness)
        for variable in (
            "NGINX_MEMCHECK_ROLE_FILE",
            "NGINX_MEMCHECK_LIFECYCLE_FILE",
            "NGINX_MEMCHECK_SUMMARY_JSON",
            "NGINX_MEMCHECK_SUMMARY_TEXT",
        ):
            assignment = self.harness.split(f"{variable}=", 1)[1].split("\n", 1)[0]
            self.assertIn("NGINX_MEMCHECK_EVIDENCE_DIR", assignment)
        self.assertIn("graceful_shutdown_incomplete", self.summarizer)
        self.assertIn("process_group_unverified", self.summarizer)
        self.assertIn("validate_evidence_root", self.summarizer)
        self.assertIn("verified_runtime_artifact_root", self.summarizer)
        self.assertIn("runtime_artifact_path", self.summarizer)
        self.assertIn("evidence_artifact_paths", self.summarizer)
        self.assertIn("O_NOFOLLOW", self.summarizer)
        self.assertIn("_permissions_unsafe", self.summarizer)
        self.assertIn("error_incomplete", self.summarizer)
        self.assertIn("possibly_lost_bytes", self.summarizer)
        self.assertIn("still_reachable_bytes", self.summarizer)
        self.assertNotIn("kill -9", self.harness)
        self.assertNotIn('parser.add_argument("--roles-file"', self.summarizer)
        self.assertNotIn('parser.add_argument("--lifecycle-file"', self.summarizer)
        self.assertNotIn('parser.add_argument("--output"', self.summarizer)
        self.assertNotIn('parser.add_argument("--text-output"', self.summarizer)
        self.assertNotIn("--suppressions", self.summarizer)
        self.assertIn("raw-payload-free", self.summarizer)

    def test_make_target_is_opt_in_h1_and_uses_existing_wrapper(self) -> None:
        self.assertIn(".PHONY: memcheck-nginx", self.makefile)
        target = self.makefile.split("memcheck-nginx: check-framework prepare-runtime-components", 1)[1]
        target = target.split("\n\nsmoke-envoy:", 1)[0]
        self.assertIn("NGINX_MEMCHECK=1", target)
        self.assertIn("MSCONNECTOR_SMOKE_STAGE=bounded_soak", target)
        self.assertIn("NGINX_PROTOCOL_PROFILE=h1", target)
        self.assertIn("NGINX_DOWNSTREAM_PROTOCOL=http1", target)
        self.assertIn("NGINX_SOAK_CONCURRENCY=1", target)
        self.assertIn('sh "$(FRAMEWORK_ROOT)/ci/runtime/run-nginx-smoke.sh"', target)
        self.assertNotIn("memcheck-nginx", self.makefile.split("test:", 1)[1].split("\n", 1)[0])

    def test_summarizer_keeps_log_pid_matching_ascii_only(self) -> None:
        self.assertIsNotNone(SUMMARIZER_MODULE.LOG_NAME_RE.fullmatch("valgrind.101.log"))
        self.assertIsNone(SUMMARIZER_MODULE.LOG_NAME_RE.fullmatch("valgrind.١٠١.log"))

    def test_summarizer_reports_clean_and_never_copies_log_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            log_dir = self.private_evidence_directory(temporary)
            complete_log = (
                "request-body=must-not-appear-in-summary\n"
                "==101== definitely lost: 0 bytes in 0 blocks\n"
                "==101== indirectly lost: 0 bytes in 0 blocks\n"
                "==101== possibly lost: 0 bytes in 0 blocks\n"
                "==101== still reachable: 0 bytes in 0 blocks\n"
                "==101== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)\n"
            )
            roles, lifecycle, output, text_output = self.create_clean_evidence(
                log_dir,
                master_pid=101,
                worker_pid=102,
                log_contents=complete_log,
            )
            result = self.run_summarizer(log_dir, roles, lifecycle, output, text_output)

            self.assertEqual(
                result.returncode,
                0,
                result.stderr + output.read_text(encoding="utf-8"),
            )
            summary = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(summary["status"], "clean")
            self.assertEqual(summary["logs_seen"], 2)
            self.assertEqual(summary["private_log_inputs"], 2)
            self.assertNotIn("must-not-appear-in-summary", output.read_text(encoding="utf-8"))
            self.assertNotIn("must-not-appear-in-summary", text_output.read_text(encoding="utf-8"))
            for output_path in (output, text_output):
                output_stat = output_path.lstat()
                self.assertEqual(output_stat.st_uid, os.geteuid())
                self.assertEqual(output_stat.st_nlink, 1)
                self.assertFalse(output_stat.st_mode & 0o077)

    def test_summarizer_marks_missing_worker_evidence_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            log_dir = self.private_evidence_directory(temporary)
            roles = log_dir / "nginx-memcheck-roles.txt"
            lifecycle = log_dir / "nginx-memcheck-lifecycle.txt"
            output = log_dir / "nginx-memcheck-summary.json"
            text_output = log_dir / "nginx-memcheck-summary.txt"
            self.write_private(roles, "master_pid=201\nworker_pid=202\n")
            self.write_private(
                lifecycle,
                "shutdown=graceful\nwait=exited\nwrapper_exit_code=0\ncontainment=isolated\n",
            )
            master_log = log_dir / "valgrind.201.log"
            self.write_private(
                master_log, "==201== ERROR SUMMARY: 0 errors from 0 contexts\n"
            )
            result = self.run_summarizer(log_dir, roles, lifecycle, output, text_output)

            self.assertEqual(result.returncode, 99, result.stderr)
            summary = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(summary["status"], "incomplete")
            self.assertEqual(summary["logs_with_final_summary"], 1)
            self.assertIn("worker_log_missing", summary["incomplete_reasons"])

    def test_summarizer_marks_uncontained_or_forced_shutdown_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            log_dir = self.private_evidence_directory(temporary)
            roles = log_dir / "nginx-memcheck-roles.txt"
            lifecycle = log_dir / "nginx-memcheck-lifecycle.txt"
            output = log_dir / "nginx-memcheck-summary.json"
            text_output = log_dir / "nginx-memcheck-summary.txt"
            self.write_private(roles, "master_pid=251\nworker_pid=252\n")
            self.write_private(
                lifecycle,
                "shutdown=forced_kill\nwait=exited\nwrapper_exit_code=0\ncontainment=unverified\n",
            )
            complete_log = "==251== ERROR SUMMARY: 0 errors from 0 contexts\n"
            for pid in (251, 252):
                log_path = log_dir / f"valgrind.{pid}.log"
                self.write_private(log_path, complete_log)

            result = self.run_summarizer(log_dir, roles, lifecycle, output, text_output)

            self.assertEqual(result.returncode, 99, result.stderr)
            summary = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(summary["status"], "incomplete")
            self.assertIn("graceful_shutdown_incomplete", summary["incomplete_reasons"])
            self.assertIn("process_group_unverified", summary["incomplete_reasons"])

    def test_summarizer_counts_valgrind_error_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            log_dir = self.private_evidence_directory(temporary)
            roles, lifecycle, output, text_output = self.create_clean_evidence(
                log_dir, master_pid=271, worker_pid=272
            )
            self.write_private(
                lifecycle,
                "shutdown=graceful\nwait=exited\nwrapper_exit_code=99\ncontainment=isolated\n",
            )

            result = self.run_summarizer(log_dir, roles, lifecycle, output, text_output)

            self.assertEqual(result.returncode, 99, result.stderr)
            summary = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(summary["status"], "error")
            self.assertTrue(summary["errors_detected"])
            self.assertEqual(summary["error_count"], 1)

    def test_summarizer_marks_non_private_raw_log_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            log_dir = self.private_evidence_directory(temporary)
            roles, lifecycle, output, text_output = self.create_clean_evidence(
                log_dir, master_pid=301, worker_pid=302
            )
            master_log = log_dir / "valgrind.301.log"
            worker_log = log_dir / "valgrind.302.log"
            master_log.chmod(0o600)
            worker_log.chmod(0o644)
            result = self.run_summarizer(log_dir, roles, lifecycle, output, text_output)

            self.assertEqual(result.returncode, 99, result.stderr)
            summary = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(summary["status"], "incomplete")
            self.assertIn("valgrind_log_permissions_unsafe", summary["incomplete_reasons"])

    def test_summarizer_marks_unsafe_metadata_inputs_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            log_dir = self.private_evidence_directory(temporary)
            roles, lifecycle, output, text_output = self.create_clean_evidence(
                log_dir, master_pid=351, worker_pid=352
            )
            roles.chmod(0o640)
            lifecycle.unlink()
            lifecycle.symlink_to(roles.name)

            result = self.run_summarizer(log_dir, roles, lifecycle, output, text_output)

            self.assertEqual(result.returncode, 99, result.stderr)
            summary = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(summary["status"], "incomplete")
            self.assertIn("roles_file_permissions_unsafe", summary["incomplete_reasons"])
            self.assertIn("lifecycle_file_symlink", summary["incomplete_reasons"])

    def test_summarizer_rejects_private_logs_below_an_unsafe_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            unsafe_parent = Path(temporary)
            unsafe_parent.chmod(0o777)
            try:
                log_dir = unsafe_parent / "nginx-memcheck-evidence"
                log_dir.mkdir(mode=0o700)
                log_dir.chmod(0o700)
                roles, lifecycle, output, text_output = self.create_clean_evidence(
                    log_dir, master_pid=401, worker_pid=402
                )

                result = self.run_summarizer(
                    log_dir, roles, lifecycle, output, text_output
                )

                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn(
                    "group- or world-writable", result.stderr
                )
                self.assertFalse(output.exists())
                self.assertFalse(text_output.exists())
            finally:
                unsafe_parent.chmod(0o700)

    def test_summarizer_rejects_symlinked_evidence_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            log_dir = self.private_evidence_directory(temporary)
            evidence_link = log_dir.parent / "evidence-link"
            evidence_link.symlink_to(log_dir, target_is_directory=True)
            roles = evidence_link / "nginx-memcheck-roles.txt"
            lifecycle = evidence_link / "nginx-memcheck-lifecycle.txt"
            output = evidence_link / "nginx-memcheck-summary.json"
            text_output = evidence_link / "nginx-memcheck-summary.txt"

            result = self.run_summarizer(
                evidence_link, roles, lifecycle, output, text_output
            )

            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("symbolic links", result.stderr)

    def test_summarizer_marks_symlinked_valgrind_input_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            log_dir = self.private_evidence_directory(temporary)
            roles, lifecycle, output, text_output = self.create_clean_evidence(
                log_dir, master_pid=451, worker_pid=452
            )
            worker_log = log_dir / "valgrind.452.log"
            worker_log.unlink()
            worker_log.symlink_to("valgrind.451.log")

            result = self.run_summarizer(log_dir, roles, lifecycle, output, text_output)

            self.assertEqual(result.returncode, 99, result.stderr)
            summary = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(summary["status"], "incomplete")
            self.assertIn("valgrind_log_symlink", summary["incomplete_reasons"])

    def test_summarizer_marks_hardlinked_valgrind_input_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            log_dir = self.private_evidence_directory(temporary)
            roles, lifecycle, output, text_output = self.create_clean_evidence(
                log_dir, master_pid=501, worker_pid=502
            )
            master_log = log_dir / "valgrind.501.log"
            worker_log = log_dir / "valgrind.502.log"
            worker_log.unlink()
            os.link(master_log, worker_log)

            result = self.run_summarizer(log_dir, roles, lifecycle, output, text_output)

            self.assertEqual(result.returncode, 99, result.stderr)
            summary = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(summary["status"], "incomplete")
            self.assertIn("valgrind_log_hardlink", summary["incomplete_reasons"])

    def test_summarizer_rejects_existing_hardlinked_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            log_dir = self.private_evidence_directory(temporary)
            roles, lifecycle, output, text_output = self.create_clean_evidence(
                log_dir, master_pid=551, worker_pid=552
            )
            existing_output = log_dir / "existing-output.json"
            self.write_private(existing_output, "{}\n")
            os.link(existing_output, output)

            result = self.run_summarizer(log_dir, roles, lifecycle, output, text_output)

            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("JSON output is unsafe", result.stderr)
            self.assertFalse(text_output.exists())

    def test_summarizer_rejects_evidence_outside_verified_run_root_before_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            verified_run_root = temporary_root / "verified-run"
            verified_run_root.mkdir(mode=0o700)
            verified_run_root.chmod(0o700)
            log_dir = self.private_evidence_directory(temporary)
            roles, lifecycle, output, text_output = self.create_clean_evidence(
                log_dir, master_pid=571, worker_pid=572
            )

            result = self.run_summarizer(
                log_dir,
                roles,
                lifecycle,
                output,
                text_output,
                verified_run_root=verified_run_root,
            )

            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("must be below the runtime root", result.stderr)
            self.assertFalse(output.exists())
            self.assertFalse(text_output.exists())

    def test_summarizer_rejects_removed_caller_selected_output_flags(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            log_dir = self.private_evidence_directory(temporary)
            self.create_clean_evidence(log_dir, master_pid=581, worker_pid=582)
            protected = log_dir.parent / "protected-output.json"
            self.write_private(protected, "keep\n")

            result = subprocess.run(
                [
                    sys.executable,
                    str(SUMMARIZER),
                    "--verified-run-root",
                    str(log_dir.parent),
                    "--log-dir",
                    str(log_dir),
                    "--output",
                    str(protected),
                ],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("unrecognized arguments: --output", result.stderr)
            self.assertEqual(protected.read_text(encoding="utf-8"), "keep\n")

    def test_foreign_owner_simulation_is_never_accepted_as_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            log_dir = self.private_evidence_directory(temporary)
            roles, _, _, _ = self.create_clean_evidence(
                log_dir, master_pid=601, worker_pid=602
            )
            simulated_foreign_uid = os.geteuid() + 1
            with mock.patch.object(
                SUMMARIZER_MODULE.os, "geteuid", return_value=simulated_foreign_uid
            ):
                masters, workers, reasons = SUMMARIZER_MODULE.parse_roles(log_dir, roles)
                with self.assertRaisesRegex(
                    ValueError, "runtime directory is not owned by the current user"
                ):
                    SUMMARIZER_MODULE.validate_evidence_root(log_dir.parent, log_dir)

            self.assertEqual(masters, set())
            self.assertEqual(workers, set())
            self.assertEqual(reasons, ["roles_file_owner_unsafe"])



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
