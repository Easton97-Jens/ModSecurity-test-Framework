from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = connector_root()
SCRIPT = source_path('ci/provisioning/components/nginx_exact_head_diagnostics.py', root=ROOT)


def load_diagnostics_module():
    return load_source(SCRIPT)

DIAGNOSTICS = load_diagnostics_module()


class NginxExactHeadDiagnosticsTest(unittest.TestCase):
    def make_fixture(self, root: Path, *, build_log: str | None = None) -> tuple[Path, Path]:
        report = root / DIAGNOSTICS.REPORT_RELATIVE_PATH
        log = root / DIAGNOSTICS.BUILD_LOG_RELATIVE_PATH
        report.parent.mkdir(parents=True, exist_ok=True)
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text("configure succeeded\ncompiler failure: missing module\n", encoding="utf-8")
        record = {
            "nginx": {
                "status": "failed",
                "blocker_reason": "missing_nginx_modsecurity_module",
                "build_exit_code": 1,
                "missing_files": ["ngx_http_modsecurity_module.so"],
                "build_log": build_log if build_log is not None else str(log),
            }
        }
        report.write_text(json.dumps(record), encoding="utf-8")
        return report, log

    def test_in_root_failure_keeps_useful_bounded_metadata_and_tail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "run"
            root.mkdir()
            self.make_fixture(root)

            output = "\n".join(DIAGNOSTICS.diagnostic_lines(root))

        self.assertIn("status=failed", output)
        self.assertIn("blocker_reason=missing_nginx_modsecurity_module", output)
        self.assertIn("missing_files_count=1", output)
        self.assertIn("build/logs/runtime-components/nginx-build.log", output)
        self.assertIn("compiler failure: missing module", output)
        self.assertNotIn(str(root), output)

    def test_public_bounded_log_tail_rejects_path_escape_and_sanitizes_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "run"
            root.mkdir()
            nested = root / "inner/logs"
            nested.mkdir(parents=True)
            make_log = nested / "make.log"
            make_log.write_text("::warning:: \x1b[31mcompiler failure\n", encoding="utf-8")

            lines, truncated = DIAGNOSTICS.bounded_fixed_log_tail(
                root,
                Path("inner/logs/make.log"),
                "inner_make_log",
                output_prefix="",
            )
            with self.assertRaises(DIAGNOSTICS.DiagnosticInputError):
                DIAGNOSTICS.bounded_fixed_log_tail(
                    root,
                    Path("../outside"),
                    "inner_make_log",
                    output_prefix="",
                )

        self.assertFalse(truncated)
        self.assertEqual(lines, [": :warning: : ?[31mcompiler failure"])

    def test_public_bounded_log_tail_rejects_replaced_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "run"
            root.mkdir()
            nested = root / "inner/logs"
            nested.mkdir(parents=True)
            make_log = nested / "make.log"
            make_log.write_text("original\n", encoding="utf-8")
            replacement = nested / "replacement"
            original_open = DIAGNOSTICS.os.open
            replaced = False

            def replace_before_open(path, flags, mode=0o777, *, dir_fd=None):
                nonlocal replaced
                if path == "make.log" and dir_fd is not None and not replaced:
                    replacement.write_text("replacement-canary\n", encoding="utf-8")
                    os.replace(replacement, make_log)
                    replaced = True
                return original_open(path, flags, mode, dir_fd=dir_fd)

            with mock.patch.object(DIAGNOSTICS.os, "open", side_effect=replace_before_open):
                with self.assertRaises(DIAGNOSTICS.DiagnosticInputError) as captured:
                    DIAGNOSTICS.bounded_fixed_log_tail(
                        root,
                        Path("inner/logs/make.log"),
                        "inner_make_log",
                        output_prefix="",
                    )

        self.assertEqual(captured.exception.reason, "inner_make_log_changed")

    def test_environment_poisoning_cannot_change_the_explicit_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "run"
            root.mkdir()
            self.make_fixture(root)
            with mock.patch.dict(
                os.environ,
                {"VERIFIED_RUN_ROOT": "/", "RUNTIME_REPORT_OUTPUT_ROOT": "/etc"},
                clear=False,
            ):
                output = "\n".join(DIAGNOSTICS.diagnostic_lines(root))

        self.assertIn("status=failed", output)
        self.assertNotIn("/etc", output)
        self.assertNotIn("/etc/passwd", output)

    def test_symlinked_report_and_build_log_are_rejected_without_following_targets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            outside = parent / "outside"
            outside.write_text("outside-canary", encoding="utf-8")
            root = parent / "run"
            root.mkdir()
            report, log = self.make_fixture(root)
            report.unlink()
            report.symlink_to(outside)
            report_output = "\n".join(DIAGNOSTICS.diagnostic_lines(root))
            report.unlink()
            self.make_fixture(root)
            log.unlink()
            log.symlink_to(outside)
            log_output = "\n".join(DIAGNOSTICS.diagnostic_lines(root))

        self.assertIn("unavailable=report_symlink", report_output)
        self.assertNotIn("outside-canary", report_output)
        self.assertIn("build_log_unavailable=build_log_symlink", log_output)
        self.assertNotIn("outside-canary", log_output)

    def test_symlinked_run_root_ancestor_is_rejected_without_following_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            outside = parent / "outside"
            outside.mkdir()
            outside_root = outside / "run"
            outside_root.mkdir()
            self.make_fixture(outside_root)
            poisoned_parent = parent / "poisoned-runner-temp"
            poisoned_parent.symlink_to(outside, target_is_directory=True)

            output = "\n".join(DIAGNOSTICS.diagnostic_lines(poisoned_parent / "run"))

        self.assertIn("unavailable=run_root_symlink", output)
        self.assertNotIn("status=failed", output)

    def test_reported_outside_build_log_is_not_opened(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            outside = parent / "outside.log"
            outside.write_text("outside-log-canary", encoding="utf-8")
            root = parent / "run"
            root.mkdir()
            self.make_fixture(root, build_log=str(outside))

            output = "\n".join(DIAGNOSTICS.diagnostic_lines(root))

        self.assertIn("build_log=untrusted_path", output)
        self.assertNotIn("outside-log-canary", output)

    def test_hardlinked_report_is_rejected_without_reading_the_link_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            outside = parent / "outside-report.json"
            outside.write_text('{"canary":"outside-report-canary"}', encoding="utf-8")
            root = parent / "run"
            root.mkdir()
            report, _ = self.make_fixture(root)
            report.unlink()
            os.link(outside, report)

            output = "\n".join(DIAGNOSTICS.diagnostic_lines(root))

        self.assertIn("unavailable=report_hardlink", output)
        self.assertNotIn("outside-report-canary", output)

    def test_malformed_or_non_mapping_report_is_fail_soft(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "run"
            root.mkdir()
            report, _ = self.make_fixture(root)
            report.write_text("[", encoding="utf-8")
            malformed_output = "\n".join(DIAGNOSTICS.diagnostic_lines(root))
            report.write_text("[]", encoding="utf-8")
            mapping_output = "\n".join(DIAGNOSTICS.diagnostic_lines(root))

        self.assertEqual(malformed_output, "nginx exact-head diagnostics: unavailable=report_malformed")
        self.assertEqual(mapping_output, "nginx exact-head diagnostics: unavailable=nginx_record_invalid")

    def test_oversized_report_keeps_fixed_log_diagnostics_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "run"
            root.mkdir()
            report, log = self.make_fixture(root)
            forged_log = Path(temporary) / "forged-log"
            forged_log.write_text("forged-log-canary", encoding="utf-8")
            report.write_bytes(
                (
                    f'{{"nginx":{{"build_log":"{forged_log}"}},'
                    '"marker":"forged-report-canary",'
                ).encode("utf-8")
                + b"x" * DIAGNOSTICS.MAX_REPORT_BYTES
            )
            report_output = "\n".join(DIAGNOSTICS.diagnostic_lines(root))
            self.make_fixture(root)
            log.write_text(
                "older-canary\n"
                + ("x" * (DIAGNOSTICS.MAX_LOG_TAIL_BYTES + 2048))
                + "\nfinal-compiler-error\n",
                encoding="utf-8",
            )
            log_output = "\n".join(DIAGNOSTICS.diagnostic_lines(root))

        self.assertIn("unavailable=report_too_large", report_output)
        self.assertIn("compiler failure: missing module", report_output)
        self.assertNotIn("forged-log-canary", report_output)
        self.assertNotIn("forged-report-canary", report_output)
        self.assertIn("build_log_tail_truncated=true", log_output)
        self.assertIn("final-compiler-error", log_output)
        self.assertNotIn("older-canary", log_output)
        self.assertLessEqual(len(log_output), DIAGNOSTICS.MAX_LOG_LINES * DIAGNOSTICS.MAX_LOG_LINE_CHARS + 4096)

    def test_terminal_controls_and_overlong_lines_cannot_expand_or_control_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "run"
            root.mkdir()
            _, log = self.make_fixture(root)
            log.write_bytes(
                b"compiler \x1b[31mfailure\x00\r ::error::spoof \xff "
                + b"z" * 4096
                + b"\n"
            )

            output = "\n".join(DIAGNOSTICS.diagnostic_lines(root))

        rendered_line = next(line for line in output.splitlines() if "compiler" in line)
        self.assertNotIn("\x1b", output)
        self.assertNotIn("\x00", output)
        self.assertNotIn("::error::", output)
        self.assertIn("compiler ?[31mfailure?", rendered_line)
        self.assertIn(": :error: :spoof ?", output)
        self.assertTrue(rendered_line.startswith(DIAGNOSTICS.LOG_LINE_PREFIX))
        self.assertLessEqual(len(rendered_line), DIAGNOSTICS.MAX_LOG_LINE_CHARS)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
