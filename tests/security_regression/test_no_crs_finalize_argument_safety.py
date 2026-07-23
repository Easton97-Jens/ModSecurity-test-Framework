"""Regression coverage for the No-CRS finalizer Make argument boundary."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[2]
MAKEFILE = ROOT / "Makefile"
FINALIZE_WRAPPER = ROOT / "ci/tools/run-no-crs-finalize.py"

FAKE_FINALIZER = """
import json
import os
from pathlib import Path
import sys

Path(os.environ["FAKE_FINALIZER_CAPTURE"]).write_text(
    json.dumps(sys.argv[1:]), encoding="utf-8"
)
raise SystemExit(int(os.environ.get("FAKE_FINALIZER_EXIT_CODE", "0")))
"""


class NoCrsFinalizeArgumentSafetyTests(unittest.TestCase):
    """Exercise the real Make target against an isolated fake finalizer."""

    def make_environment(self, capture: Path, temporary_root: Path) -> dict[str, str]:
        environment = os.environ.copy()
        for name in (
            "NO_CRS_TOOL",
            "CONNECTOR",
            "NO_CRS_RUN_DIR",
            "CONNECTOR_ROOT",
            "CAPABILITIES_FILE",
            "NO_CRS_STAGE_RC",
            "NO_CRS_STAGE_REASON",
            "NO_CRS_FINALIZE_ARGS",
            "NO_CRS_PROTOCOL_CLIENT_ARTIFACT_DIR",
        ):
            environment.pop(name, None)
        environment.update(
            {
                "FAKE_FINALIZER_CAPTURE": str(capture),
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONNOUSERSITE": "1",
                "PYTHONPYCACHEPREFIX": str(temporary_root / "pycache"),
            }
        )
        return environment

    @staticmethod
    def write_fake_finalizer(temporary_root: Path) -> Path:
        finalizer = temporary_root / "fake_finalizer.py"
        finalizer.write_text(textwrap.dedent(FAKE_FINALIZER), encoding="utf-8")
        return finalizer

    def run_make(
        self,
        *,
        temporary_root: Path,
        finalizer: Path,
        capture: Path,
        extra_arguments: str,
        stage_reason: str = "controlled test reason",
        protocol_artifact: str = "",
        exit_code: int = 0,
        connector: str = "validation",
        use_default_connector_paths: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        environment = self.make_environment(capture, temporary_root)
        environment["FAKE_FINALIZER_EXIT_CODE"] = str(exit_code)
        command = [
            "make",
            "--no-print-directory",
            "-f",
            str(MAKEFILE),
            "no-crs-finalize",
            f"PYTHON={sys.executable}",
            f"NO_CRS_TOOL={finalizer}",
            f"CONNECTOR={connector}",
            f"CONNECTOR_ROOT={temporary_root / 'connector root'}",
            "NO_CRS_STAGE_RC=17",
            f"NO_CRS_STAGE_REASON={stage_reason}",
            f"NO_CRS_PROTOCOL_CLIENT_ARTIFACT_DIR={protocol_artifact}",
            f"NO_CRS_FINALIZE_ARGS={extra_arguments}",
        ]
        if use_default_connector_paths:
            command.extend(
                [
                    f"EVIDENCE_ROOT={temporary_root / 'evidence root'}",
                    "NO_CRS_RUN_ID=derived",
                ]
            )
        else:
            command.extend(
                [
                    f"NO_CRS_RUN_DIR={temporary_root / 'run directory'}",
                    f"CAPABILITIES_FILE={temporary_root / 'capabilities file.json'}",
                ]
            )
        return subprocess.run(
            command,
            cwd=ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
        )

    def test_semicolon_payload_is_literal_argv_data_not_a_make_shell_command(self) -> None:
        with tempfile.TemporaryDirectory(prefix="no-crs-finalize-argument-safety-") as temporary:
            temporary_root = Path(temporary)
            finalizer = self.write_fake_finalizer(temporary_root)
            capture = temporary_root / "argv.json"
            marker = temporary_root / "MAKE_INTERPOLATION_CONFIRMED"
            connector_marker = temporary_root / "CONNECTOR_INTERPOLATION_CONFIRMED"
            run_dir = temporary_root / "run directory"
            connector_root = temporary_root / "connector root"
            capabilities_file = temporary_root / "capabilities file.json"
            protocol_artifact = temporary_root / "protocol artifact"
            stage_reason = f"reason; marker remains {marker}"
            payload = f"; printf MAKE_INTERPOLATION_CONFIRMED > {marker}"
            connector = (
                "validation; printf CONNECTOR_INTERPOLATION_CONFIRMED > "
                f"{connector_marker}"
            )

            result = self.run_make(
                temporary_root=temporary_root,
                finalizer=finalizer,
                capture=capture,
                extra_arguments=payload,
                stage_reason=stage_reason,
                protocol_artifact=str(protocol_artifact),
                connector=connector,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse(marker.exists(), result.stdout + result.stderr)
            self.assertFalse(connector_marker.exists(), result.stdout + result.stderr)
            arguments = json.loads(capture.read_text(encoding="utf-8"))
            self.assertEqual(arguments[0], "finalize")
            self.assertEqual(str(run_dir), arguments[arguments.index("--run-dir") + 1])
            self.assertEqual(
                str(connector_root), arguments[arguments.index("--connector-root") + 1]
            )
            self.assertEqual(
                str(capabilities_file), arguments[arguments.index("--capabilities") + 1]
            )
            self.assertEqual(arguments[arguments.index("--stage-reason") + 1], stage_reason)
            self.assertEqual(
                str(protocol_artifact),
                arguments[arguments.index("--protocol-client-artifact-dir") + 1],
            )
            expected_marker_arguments = [
                ";", "printf", "MAKE_INTERPOLATION_CONFIRMED", ">", str(marker)
            ]
            self.assertEqual(arguments[-5:], expected_marker_arguments)

    def test_quoted_extra_options_remain_individual_arguments(self) -> None:
        with tempfile.TemporaryDirectory(prefix="no-crs-finalize-quoted-options-") as temporary:
            temporary_root = Path(temporary)
            finalizer = self.write_fake_finalizer(temporary_root)
            capture = temporary_root / "argv.json"
            quoted_path = temporary_root / "quoted artifact path.json"
            extra_arguments = f'--artifact-label "{quoted_path}" --mode "strict finalize"'

            result = self.run_make(
                temporary_root=temporary_root,
                finalizer=finalizer,
                capture=capture,
                extra_arguments=extra_arguments,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            arguments = json.loads(capture.read_text(encoding="utf-8"))
            expected_quoted_option_arguments = [
                "--artifact-label", str(quoted_path), "--mode", "strict finalize"
            ]
            self.assertEqual(arguments[-4:], expected_quoted_option_arguments)

    def test_connector_derived_defaults_keep_make_syntax_as_argv_data(self) -> None:
        with tempfile.TemporaryDirectory(prefix="no-crs-finalize-derived-paths-") as temporary:
            temporary_root = Path(temporary)
            finalizer = self.write_fake_finalizer(temporary_root)
            capture = temporary_root / "argv.json"
            connector = "$(shell printf derived-connector)"

            result = self.run_make(
                temporary_root=temporary_root,
                finalizer=finalizer,
                capture=capture,
                extra_arguments="",
                connector=connector,
                use_default_connector_paths=True,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            arguments = json.loads(capture.read_text(encoding="utf-8"))
            self.assertEqual(
                str(temporary_root / "evidence root" / connector / "derived"),
                arguments[arguments.index("--run-dir") + 1],
            )
            self.assertEqual(
                str(
                    temporary_root
                    / "connector root"
                    / "connectors"
                    / connector
                    / "capabilities.json"
                ),
                arguments[arguments.index("--capabilities") + 1],
            )

    def test_make_function_syntax_remains_literal_finalizer_data(self) -> None:
        with tempfile.TemporaryDirectory(prefix="no-crs-finalize-make-function-") as temporary:
            temporary_root = Path(temporary)
            finalizer = self.write_fake_finalizer(temporary_root)
            capture = temporary_root / "argv.json"
            marker = temporary_root / "MAKE_FUNCTION_INTERPOLATION_CONFIRMED"
            payload = (
                "$(shell printf MAKE_FUNCTION_INTERPOLATION_CONFIRMED > "
                f"{marker})"
            )

            result = self.run_make(
                temporary_root=temporary_root,
                finalizer=finalizer,
                capture=capture,
                extra_arguments=payload,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse(marker.exists(), result.stdout + result.stderr)
            arguments = json.loads(capture.read_text(encoding="utf-8"))
            self.assertIn("$(shell", arguments)

    def test_wrapper_preserves_the_finalizer_exit_code(self) -> None:
        with tempfile.TemporaryDirectory(prefix="no-crs-finalize-exit-code-") as temporary:
            temporary_root = Path(temporary)
            finalizer = self.write_fake_finalizer(temporary_root)
            capture = temporary_root / "argv.json"
            environment = self.make_environment(capture, temporary_root)
            environment.update(
                {
                    "FAKE_FINALIZER_EXIT_CODE": "37",
                    "NO_CRS_TOOL": str(finalizer),
                    "CONNECTOR": "validation",
                    "NO_CRS_RUN_DIR": str(temporary_root / "run"),
                    "CONNECTOR_ROOT": str(temporary_root / "connector"),
                    "CAPABILITIES_FILE": str(temporary_root / "capabilities.json"),
                    "NO_CRS_STAGE_RC": "17",
                    "NO_CRS_STAGE_REASON": "controlled failure",
                    "NO_CRS_FINALIZE_ARGS": "",
                    "NO_CRS_PROTOCOL_CLIENT_ARTIFACT_DIR": "",
                }
            )

            result = subprocess.run(
                [sys.executable, str(FINALIZE_WRAPPER)],
                cwd=ROOT,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=15,
            )

            self.assertEqual(result.returncode, 37, result.stdout + result.stderr)

    def test_make_target_keeps_the_connector_requirement_in_the_wrapper(self) -> None:
        with tempfile.TemporaryDirectory(prefix="no-crs-finalize-connector-required-") as temporary:
            temporary_root = Path(temporary)
            finalizer = self.write_fake_finalizer(temporary_root)
            capture = temporary_root / "argv.json"

            result = self.run_make(
                temporary_root=temporary_root,
                finalizer=finalizer,
                capture=capture,
                extra_arguments="",
                connector="",
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("CONNECTOR is required", result.stderr)
            self.assertFalse(capture.exists())


if __name__ == "__main__":
    unittest.main()
