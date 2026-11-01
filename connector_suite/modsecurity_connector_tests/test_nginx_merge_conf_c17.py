"""Compile the actual NGINX module with explicitly supplied native headers.

Set NGINX_SOURCE_DIR to a configured NGINX source tree, supply the installed
MODSECURITY_INCLUDE_DIR, and select an external TMPDIR. No fake headers or
warning suppressions are used; absent optional native prerequisites are SKIPs.
"""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = connector_root()
MODULE = source_path('connectors/nginx/src/ngx_http_modsecurity_module.c', root=ROOT)


class NginxMergeConfC17Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        required = ("NGINX_SOURCE_DIR", "MODSECURITY_INCLUDE_DIR", "TMPDIR")
        missing = [name for name in required if not os.environ.get(name)]
        if missing:
            raise unittest.SkipTest(
                "native compile prerequisites absent: " + ", ".join(missing)
            )
        cls.nginx = Path(os.environ["NGINX_SOURCE_DIR"]).resolve()
        cls.modsecurity = Path(os.environ["MODSECURITY_INCLUDE_DIR"]).resolve()
        cls.temporary_parent = Path(os.environ["TMPDIR"]).resolve()
        if cls.temporary_parent == ROOT or ROOT in cls.temporary_parent.parents:
            raise AssertionError("TMPDIR must be outside the source checkout")
        for header in (
            cls.nginx / "src/core/ngx_config.h",
            cls.nginx / "src/core/ngx_core.h",
            cls.nginx / "src/http/ngx_http.h",
            cls.nginx / "objs/ngx_auto_config.h",
            cls.modsecurity / "modsecurity/modsecurity.h",
        ):
            if not header.is_file():
                raise AssertionError(f"explicit native header missing: {header}")
        if not cls.temporary_parent.is_dir():
            raise AssertionError("explicit TMPDIR must exist")
        compiler = shutil.which(os.environ.get("CC", "cc"))
        if compiler is None:
            raise unittest.SkipTest("native C compiler unavailable")
        cls.compiler = compiler
        cls.includes = [
            ROOT,
            source_path('common/include', root=ROOT),
            MODULE.parent,
            cls.modsecurity,
            *(
                cls.nginx / suffix
                for suffix in (
                    "src/core", "src/http", "src/http/modules", "src/http/v2",
                    "src/http/v3", "src/event", "src/os/unix", "objs",
                )
            ),
        ]

    def command(self, source: Path, debug: int) -> list[str]:
        return [
            self.compiler, "-std=c17", "-Wall", "-Wextra", "-Werror",
            f"-DMODSECURITY_DDEBUG={debug}",
            *(f"-I{directory}" for directory in self.includes), str(source),
        ]

    def compile(
        self, source: Path, debug: int, output: Path
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [*self.command(source, debug), "-c", "-o", str(output)],
            capture_output=True, text=True, check=False, timeout=60,
            env={**os.environ, "LC_ALL": "C"},
        )

    def test_full_module_compiles_with_debug_disabled_and_enabled(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="nginx-merge-c17-", dir=self.temporary_parent
        ) as raw:
            for debug in (0, 1):
                with self.subTest(debug=debug):
                    output = Path(raw) / f"module-debug-{debug}.o"
                    result = self.compile(MODULE, debug, output)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertGreater(output.stat().st_size, 0)

    def test_removing_unused_parameter_treatment_restores_compiler_error(self) -> None:
        text = MODULE.read_text(encoding="utf-8")
        signature = (
            "ngx_http_modsecurity_merge_conf(ngx_conf_t *cf, "
            "void *parent, void *child)\n{"
        )
        start = text.index(signature)
        end = text.index("\nstatic void", start)
        merge, count = re.subn(
            r"(?m)^[ \t]*\(void\)[ \t]*cf[ \t]*;[ \t]*$", "", text[start:end]
        )
        self.assertEqual(
            count, 1, "expected local unused-cf treatment in merge callback"
        )
        with tempfile.TemporaryDirectory(
            prefix="nginx-merge-c17-negative-", dir=self.temporary_parent
        ) as raw:
            source = Path(raw) / MODULE.name
            source.write_text(text[:start] + merge + text[end:], encoding="utf-8")
            result = self.compile(source, 0, Path(raw) / "negative.o")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unused parameter", result.stderr)
            self.assertRegex(result.stderr, r"unused parameter[^\n]*\bcf\b")
            self.assertIn("ngx_http_modsecurity_merge_conf", result.stderr)

    def test_preprocessor_preserves_supported_merge_debug_trace(self) -> None:
        marker = "merging loc config"
        for debug in (0, 1):
            with self.subTest(debug=debug):
                result = subprocess.run(
                    [*self.command(MODULE, debug), "-E", "-P"],
                    capture_output=True, text=True, check=False, timeout=60,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                if debug:
                    self.assertIn(marker, result.stdout)
                    self.assertIn("msc_rules_dump(c->rules_set)", result.stdout)
                else:
                    self.assertNotIn(marker, result.stdout)
                    self.assertNotIn("msc_rules_dump(c->rules_set)", result.stdout)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
