"""Native Framework tests keep their checks and side effects under -DNDEBUG.

assert() expands to nothing when NDEBUG is defined. Several native tests used
assert() around fixture I/O, resource release and the operation under test, so
an NDEBUG build skipped that work and could still report success. Covered
sources undefine NDEBUG before any preprocessor include and use TEST_REQUIRE()
where the asserted expression itself performs required work.
"""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path
from pathlib import Path
import os
import re
import shlex
import subprocess
import tempfile
import unittest

ROOT = connector_root()
FRAMEWORK = test_root()
ASSERT_INCLUDE = re.compile(r"^\s*#\s*include\s*<assert\.h>", re.MULTILINE)
GUARD = re.compile(r"^\s*#\s*undef\s+NDEBUG\b", re.MULTILINE)
INCLUDE = re.compile(r"^\s*#\s*include\b", re.MULTILINE)
BUDGET_TEST = "connector_suite/modsecurity_connector_tests/test_nginx_engine_call_budget.c"


def is_i12_scoped(relative: str) -> bool:
    """I12 harness sources stay frozen under the I12 work stop."""
    return "/i12/" in relative or "_i12_" in Path(relative).name


def native_assert_sources() -> list[str]:
    listed = subprocess.run(
        ["git", "-C", str(FRAMEWORK), "ls-files", "-z", "--", "connector_suite"],
        capture_output=True, check=True).stdout.decode().split("\0")
    selected = []
    for relative in listed:
        if not relative.endswith((".c", ".cc", ".cpp", ".h")) or is_i12_scoped(relative):
            continue
        if ASSERT_INCLUDE.search((FRAMEWORK / relative).read_text(encoding="utf-8")):
            selected.append(relative)
    return selected


class NativeAssertNdebugContract(unittest.TestCase):
    def test_assert_users_undefine_ndebug_before_any_include(self):
        sources = native_assert_sources()
        self.assertGreater(len(sources), 0)
        for relative in sources:
            with self.subTest(source=relative):
                text = (FRAMEWORK / relative).read_text(encoding="utf-8")
                guard = GUARD.search(text)
                self.assertIsNotNone(guard, "missing #undef NDEBUG")
                self.assertLess(guard.start(), INCLUDE.search(text).start(),
                                "#undef NDEBUG must precede the first include")

    def compile_and_run(self, directory: Path, source: Path, name: str):
        binary = directory / name
        compiled = subprocess.run(
            [*shlex.split(os.environ.get("CC", "cc")), "-std=c17", "-Wall", "-Wextra", "-Werror", "-DNDEBUG",
             "-I", str(ROOT), "-I", str(source_path("common/include", root=ROOT)),
             str(source), "-o", str(binary)],
            capture_output=True, text=True)
        self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
        return subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)

    def test_ndebug_build_executes_and_detects_broken_expectations(self):
        original = FRAMEWORK / BUDGET_TEST
        text = original.read_text(encoding="utf-8")
        require_line = "TEST_REQUIRE(ngx_http_modsecurity_engine_budget_begin(&budget, 10, &start) == 1);"
        assert_line = "assert(budget.elapsed_ns == UINT64_C(10000000));"
        self.assertIn(require_line, text)
        self.assertIn(assert_line, text)
        parent = Path(os.environ.get("TMPDIR", "/var/tmp/codex/ModSecurity-conector/tmp"))
        parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="native-assert-ndebug-", dir=parent) as directory:
            work = Path(directory)
            self.assertEqual(self.compile_and_run(work, original, "control").returncode, 0)
            mutations = {
                "require": text.replace(require_line, require_line.replace("== 1", "== 0"), 1),
                "assert": text.replace(assert_line, assert_line.replace("10000000", "10000001"), 1),
            }
            for label, mutated_text in mutations.items():
                with self.subTest(mutation=label):
                    mutated = work / f"{label}.c"
                    mutated.write_text(mutated_text, encoding="utf-8")
                    result = self.compile_and_run(work, mutated, label)
                    self.assertNotEqual(result.returncode, 0, "broken expectation passed under NDEBUG")


# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)
