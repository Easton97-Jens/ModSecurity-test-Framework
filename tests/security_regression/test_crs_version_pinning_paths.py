"""Regression coverage for CRS-pinning checker pathname handling.

Each test invokes the real checker against an isolated temporary repository
root.  The real Framework CI helper library remains the trusted checker
dependency; only the discovered ``ci`` tree is disposable test input.
"""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "ci/checks/catalog/check-crs-version-pinning.sh"


class CrsVersionPinningPathTests(unittest.TestCase):
    def run_checker(self, files: dict[str, str]) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory(prefix="crs-version-pinning-paths-") as temporary:
            temporary_root = Path(temporary)
            repository = temporary_root / "repository"
            for relative_path, contents in files.items():
                path = repository / relative_path
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(contents, encoding="utf-8")

            runtime_root = temporary_root / "runtime"
            environment = os.environ.copy()
            for variable in (
                "CRS_APPROVED_REPO_URL",
                "CRS_APPROVED_COMMIT",
                "CRS_RELEASE_TAG",
                "CRS_REPO_URL",
                "CRS_GIT_REF",
            ):
                environment.pop(variable, None)
            environment.update(
                {
                    "CI_ROOT": str(ROOT / "ci"),
                    "FRAMEWORK_ROOT": str(ROOT),
                    "CONNECTOR_ROOT": str(repository),
                    "REPO_ROOT": str(repository),
                    "VERIFIED_RUN_ROOT": str(runtime_root / "verified"),
                    "BUILD_ROOT": str(runtime_root / "build"),
                    "SOURCE_ROOT": str(runtime_root / "source"),
                    "TMP_ROOT": str(runtime_root / "tmp"),
                    "LOG_ROOT": str(runtime_root / "logs"),
                    "XDG_STATE_HOME": str(runtime_root / "state"),
                    "XDG_CACHE_HOME": str(runtime_root / "cache"),
                }
            )

            return subprocess.run(
                ["sh", str(CHECKER)],
                cwd=repository,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
            )

    def test_rejects_provenance_assignments_in_space_and_newline_paths(self) -> None:
        result = self.run_checker(
            {
                "ci/ordinary.sh": "#!/bin/sh\nprintf '%s\\n' ordinary\n",
                "ci/space name.sh": "CRS_REPO_URL=https://attacker.invalid/crs.git\n",
                "ci/line\nbreak.sh": "CRS_GIT_REF=main\n",
            }
        )

        self.assertEqual(1, result.returncode, result.stdout + result.stderr)
        self.assertIn("ci/space name.sh", result.stderr)
        self.assertIn("ci/line\nbreak.sh", result.stderr)

    def test_accepts_an_ordinary_shell_file_without_crs_provenance(self) -> None:
        result = self.run_checker(
            {"ci/ordinary.sh": "#!/bin/sh\nprintf '%s\\n' ordinary\n"}
        )

        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_preserves_the_ordinary_path_provenance_check(self) -> None:
        result = self.run_checker(
            {"ci/ordinary.sh": "CRS_RELEASE_TAG=v0.0.0\n"}
        )

        self.assertEqual(1, result.returncode, result.stdout + result.stderr)
        self.assertIn("ci/ordinary.sh", result.stderr)


if __name__ == "__main__":
    unittest.main()
