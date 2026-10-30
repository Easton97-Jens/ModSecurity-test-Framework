from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = connector_root()
WRITER_PATH = source_path('common/scripts/write_smoke_result.py', root=ROOT)
WRITER = load_source(WRITER_PATH)


class WriteSmokeResultSecurityTest(unittest.TestCase):
    @staticmethod
    def writer_arguments(
        runtime_root: Path,
        *,
        connector: str = "envoy",
        evidence_root: Path | None = None,
    ) -> list[str]:
        evidence = evidence_root or runtime_root / "evidence"
        return [
            "--connector",
            connector,
            "--integration-mode",
            "local",
            "--evidence-root",
            str(evidence),
            "--results-dir",
            str(runtime_root / "results"),
            "--connector-root",
            str(ROOT),
            "--source-root",
            str(runtime_root / "source"),
            "--build-root",
            str(runtime_root / "build"),
            "--tmp-root",
            str(runtime_root / "tmp"),
            "--log-root",
            str(runtime_root / "logs"),
            "--log-dir",
            str(runtime_root / "logs" / "envoy"),
            "--harness-path",
            "common/scripts/write_smoke_result.py",
            "--skipped-reason",
            "security-test",
        ]

    def invoke_writer(self, runtime_root: Path, arguments: list[str]) -> int:
        with (
            mock.patch.object(sys, "argv", [str(WRITER_PATH), *arguments]),
            mock.patch.dict(os.environ, {"VERIFIED_RUN_ROOT": str(runtime_root)}, clear=True),
        ):
            return WRITER.main()

    def test_writer_accepts_private_paths_below_verified_runtime_root(self) -> None:
        with tempfile.TemporaryDirectory(prefix="write-smoke-result-security-") as temporary:
            runtime_root = Path(temporary) / "verified-runtime"

            self.assertEqual(self.invoke_writer(runtime_root, self.writer_arguments(runtime_root)), 0)

            self.assertTrue((runtime_root / "evidence" / "result.json").is_file())
            self.assertTrue((runtime_root / "results" / "envoy-results.jsonl").is_file())
            self.assertTrue((runtime_root / "logs" / "envoy" / "status.log").is_file())

    def test_writer_rejects_evidence_path_outside_verified_runtime_root(self) -> None:
        with tempfile.TemporaryDirectory(prefix="write-smoke-result-security-") as temporary:
            temporary_root = Path(temporary)
            runtime_root = temporary_root / "verified-runtime"
            outside_root = temporary_root / "outside-runtime"
            arguments = self.writer_arguments(
                runtime_root, evidence_root=outside_root / "evidence"
            )

            with self.assertRaisesRegex(SystemExit, "outside the verified runtime root"):
                self.invoke_writer(runtime_root, arguments)

            self.assertFalse(outside_root.exists())

    def test_writer_rejects_symlinked_output_directory(self) -> None:
        with tempfile.TemporaryDirectory(prefix="write-smoke-result-security-") as temporary:
            temporary_root = Path(temporary)
            runtime_root = temporary_root / "verified-runtime"
            runtime_root.mkdir(mode=0o700)
            outside_root = temporary_root / "outside-runtime"
            outside_root.mkdir(mode=0o700)
            alias = runtime_root / "output-alias"
            alias.symlink_to(outside_root, target_is_directory=True)
            arguments = self.writer_arguments(runtime_root, evidence_root=alias / "evidence")

            with self.assertRaisesRegex(SystemExit, "outside the verified runtime root"):
                self.invoke_writer(runtime_root, arguments)

            self.assertFalse((outside_root / "evidence").exists())

    def test_writer_rejects_symlinked_output_file_inside_runtime_root(self) -> None:
        with tempfile.TemporaryDirectory(prefix="write-smoke-result-security-") as temporary:
            temporary_root = Path(temporary)
            runtime_root = temporary_root / "verified-runtime"
            evidence_root = runtime_root / "evidence"
            runtime_root.mkdir(mode=0o700)
            evidence_root.mkdir(mode=0o700)
            outside_target = temporary_root / "outside-result.json"
            (evidence_root / "result.json").symlink_to(outside_target)
            arguments = self.writer_arguments(runtime_root, evidence_root=evidence_root)

            with self.assertRaisesRegex(SystemExit, "cannot open safe output file"):
                self.invoke_writer(runtime_root, arguments)

            self.assertFalse(outside_target.exists())

    def test_writer_rejects_connector_path_traversal_before_writing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="write-smoke-result-security-") as temporary:
            runtime_root = Path(temporary) / "verified-runtime"
            arguments = self.writer_arguments(runtime_root, connector="../outside")

            with self.assertRaisesRegex(SystemExit, "safe output filename component"):
                self.invoke_writer(runtime_root, arguments)

            self.assertFalse(runtime_root.exists())



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
