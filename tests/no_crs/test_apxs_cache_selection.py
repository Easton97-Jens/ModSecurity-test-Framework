from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


FRAMEWORK_ROOT = Path(__file__).resolve().parents[2]
COMMON_SH = FRAMEWORK_ROOT / "ci" / "lib" / "common.sh"


class ApxsCacheSelectionTest(unittest.TestCase):
    def write_apxs(self, path: Path, include_dir: Path, marker: Path | None = None) -> None:
        path.parent.mkdir(parents=True)
        marker_command = ""
        if marker is not None:
            marker_command = f"touch '{marker}'\\n"
        path.write_text(
            "#!/bin/sh\n"
            + marker_command
            + "if [ \"${1:-}\" = \"-q\" ] && [ \"${2:-}\" = \"INCLUDEDIR\" ]; then\n"
            f"    printf '%s\\n' '{include_dir}'\n"
            "    exit 0\n"
            "fi\n"
            "exit 1\n",
            encoding="utf-8",
        )
        path.chmod(0o755)

    def test_cached_apxs_is_never_probed_or_executed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="framework-apxs-cache-") as temporary:
            root = Path(temporary)
            cache = root / "cache"
            poisoned = cache / "builds/connectors/apache/poisoned/httpd/bin/apxs"
            include_dir = root / "poisoned/include"
            marker = root / "poisoned-executed"
            include_dir.mkdir(parents=True)
            (include_dir / "httpd.h").write_text("/* httpd */\n", encoding="utf-8")
            self.write_apxs(poisoned, include_dir, marker)

            result = subprocess.run(
                ["sh", "-eu", "-c", '. "$1"; framework_find_apxs', "sh", str(COMMON_SH)],
                env={
                    **os.environ,
                    "CONNECTOR_COMPONENT_CACHE": str(cache),
                    "BUILD_ROOT": str(root / "build"),
                    "APXS_BIN": "",
                    "APXS": "",
                    "CI_APXS_BIN_CANDIDATES": "definitely-not-an-apxs-binary",
                },
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), "")
        self.assertFalse(marker.exists())

    def test_explicit_apxs_remains_usable(self) -> None:
        with tempfile.TemporaryDirectory(prefix="framework-apxs-explicit-") as temporary:
            root = Path(temporary)
            explicit = root / "explicit/bin/apxs"
            include_dir = root / "explicit/include"
            include_dir.mkdir(parents=True)
            (include_dir / "httpd.h").write_text("/* httpd */\n", encoding="utf-8")
            self.write_apxs(explicit, include_dir)

            result = subprocess.run(
                ["sh", "-eu", "-c", '. "$1"; framework_find_apxs', "sh", str(COMMON_SH)],
                env={
                    **os.environ,
                    "CONNECTOR_COMPONENT_CACHE": str(root / "cache"),
                    "BUILD_ROOT": str(root / "build"),
                    "APXS_BIN": str(explicit),
                    "APXS": "",
                    "CI_APXS_BIN_CANDIDATES": "definitely-not-an-apxs-binary",
                },
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(str(explicit), result.stdout.strip())


if __name__ == "__main__":
    unittest.main()
