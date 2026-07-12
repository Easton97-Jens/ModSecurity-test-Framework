from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


FRAMEWORK_ROOT = Path(__file__).resolve().parents[2]
COMMON_SH = FRAMEWORK_ROOT / "ci" / "common.sh"


class ApxsCacheSelectionTest(unittest.TestCase):
    def write_apxs(self, path: Path, include_dir: Path) -> None:
        path.parent.mkdir(parents=True)
        path.write_text(
            "#!/bin/sh\n"
            "if [ \"${1:-}\" = \"-q\" ] && [ \"${2:-}\" = \"INCLUDEDIR\" ]; then\n"
            f"    printf '%s\\n' '{include_dir}'\n"
            "    exit 0\n"
            "fi\n"
            "exit 1\n",
            encoding="utf-8",
        )
        path.chmod(0o755)

    def test_unusable_cached_apxs_does_not_hide_later_complete_entry(self) -> None:
        with tempfile.TemporaryDirectory(prefix="framework-apxs-cache-") as temporary:
            root = Path(temporary)
            cache = root / "cache"
            stale = cache / "builds/connectors/apache/a-stale/httpd/bin/apxs"
            usable = cache / "builds/connectors/apache/z-usable/httpd/bin/apxs"
            stale_include = root / "stale/include"
            usable_include = root / "usable/include"
            stale_include.mkdir(parents=True)
            usable_include.mkdir(parents=True)
            (usable_include / "httpd.h").write_text("/* httpd */\n", encoding="utf-8")
            self.write_apxs(stale, stale_include)
            self.write_apxs(usable, usable_include)

            result = subprocess.run(
                ["sh", "-eu", "-c", '. "$1"; framework_find_apxs', "sh", str(COMMON_SH)],
                env={
                    **os.environ,
                    "CONNECTOR_COMPONENT_CACHE": str(cache),
                    "BUILD_ROOT": str(root / "build"),
                    "APXS_BIN": str(stale),
                    "APXS": "",
                    "CI_APXS_BIN_CANDIDATES": "definitely-not-an-apxs-binary",
                },
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual(str(usable), result.stdout.strip())


if __name__ == "__main__":
    unittest.main()
