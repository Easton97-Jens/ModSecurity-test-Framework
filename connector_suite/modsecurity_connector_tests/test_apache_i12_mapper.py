"""Compile the production Apache mapper with genuine Apache/APR dependencies.

These observations concern the mapper boundary, not a running httpd or Engine.
Set RUNNER_TEMP to external task storage; optionally retain JSON evidence with
I12_APACHE_MAPPER_EVIDENCE_DIR.
"""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest

ROOT = connector_root()


class ApacheI12RealMapperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shlex.split(os.environ.get("CC", "cc"))
        apr = shutil.which("apr-1-config")
        apxs = shutil.which("apxs") or shutil.which("apxs2")
        if not compiler or not shutil.which(compiler[0]) or not apr or not apxs:
            raise unittest.SkipTest("real compiler, Apache SDK and APR SDK required")
        temporary_root = os.environ.get("RUNNER_TEMP")
        if not temporary_root:
            raise unittest.SkipTest("RUNNER_TEMP must select external task storage")
        directory = tempfile.TemporaryDirectory(prefix="apache-i12-mapper-", dir=temporary_root)
        cls.addClassCleanup(directory.cleanup)
        cls.binary = Path(directory.name) / "mapper"

        def query(command):
            return subprocess.run(command, check=True, capture_output=True,
                                  text=True, timeout=10).stdout.strip()

        includes = query([apxs, "-q", "INCLUDEDIR"])
        sources = [source_path('tests/apache_i12_mapper_probe.c', root=ROOT),
                   source_path('connectors/apache/src/msc_apache_mapper.c', root=ROOT)]
        sources += [source_path('common/src', root=ROOT) / (name + ".c") for name in (
            "headers", "resource_limits", "request_helpers", "response_helpers",
            "request_mapper_contract", "response_mapper_contract", "http_status")]
        command = [*compiler, "-std=c17", "-Wall", "-Wextra", "-Werror",
                   "-I", includes, "-I", str(source_path('common/include', root=ROOT)),
                   "-I", str(source_path('connectors/apache/src', root=ROOT)),
                   *shlex.split(query([apr, "--includes", "--cppflags", "--cflags"])),
                   *map(str, sources),
                   *shlex.split(query([apr, "--link-ld", "--libs"])),
                   "-o", str(cls.binary)]
        compiled = subprocess.run(command, capture_output=True, text=True, timeout=90)
        cls.evidence = None
        if os.environ.get("I12_APACHE_MAPPER_EVIDENCE_DIR"):
            cls.evidence = Path(os.environ["I12_APACHE_MAPPER_EVIDENCE_DIR"])
            cls.evidence.mkdir(parents=True, exist_ok=True)
            if compiled.returncode == 0:
                shutil.copy2(cls.binary, cls.evidence / "mapper-probe")
            (cls.evidence / "compile.json").write_text(json.dumps({
                "command": command, "exit": compiled.returncode,
                "stdout": compiled.stdout, "stderr": compiled.stderr,
                "sources_sha256": {str(path.relative_to(ROOT)):
                    hashlib.sha256(path.read_bytes()).hexdigest() for path in sources},
                "binary_sha256": hashlib.sha256(cls.binary.read_bytes()).hexdigest()
                    if compiled.returncode == 0 else None,
                "apache_include_dir": includes,
                "apache_httpd_header_sha256": hashlib.sha256(
                    (Path(includes) / "httpd.h").read_bytes()).hexdigest(),
                "apr_version": query([apr, "--version"]),
                "compiler_version": query([compiler[0], "--version"]),
            }, indent=2) + "\n")
        if compiled.returncode:
            raise AssertionError("real mapper compile failed:\n" + compiled.stderr)

    def observe(self, values, *, merge=True, mixed_case=False, name="X-No-Crs-Duplicate"):
        command = [str(self.binary), "merge" if merge else "raw"]
        for index, value in enumerate(values):
            command.extend((name.lower() if mixed_case and index % 2 else name, value))
        completed = subprocess.run(command, capture_output=True, text=True, timeout=10)
        if self.evidence:
            key = hashlib.sha256(json.dumps(command[1:]).encode()).hexdigest()[:16]
            (self.evidence / (key + ".json")).write_text(json.dumps({
                "layer": "real_apr_production_mapper_boundary",
                "command": command, "exit": completed.returncode,
                "stdout": completed.stdout, "stderr": completed.stderr,
                "wire_execution": None, "native_engine_execution": None,
            }, indent=2) + "\n")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        facts = {}
        for line in completed.stdout.splitlines():
            key, value = line.split("=", 1)
            if key in ("apr_header", "request_header", "response_header"):
                facts.setdefault(key, []).append(value.split("\t"))
            else:
                facts[key] = value
        apr_headers = facts["apr_header"]
        self.assertEqual([row[:2] for row in facts["request_header"]], apr_headers)
        for stage in ("request_header", "response_header"):
            for row in facts[stage]:
                self.assertEqual(int(row[2]), len(row[0].encode()))
                self.assertEqual(int(row[3]), len(row[1].encode()))
        self.assertEqual(facts["response_header"][0][:2], ["X-I12-Error-Table", "retained"])
        return facts

    def duplicates(self, facts, stage="request_header"):
        return [row[1] for row in facts[stage] if row[0].lower() == "x-no-crs-duplicate"]

    def test_raw_duplicates_are_preserved_by_mapper(self):
        facts = self.observe(("one", "two"), merge=False, mixed_case=True)
        self.assertEqual(self.duplicates(facts), ["one", "two"])
        self.assertEqual(self.duplicates(facts, "response_header"), ["one", "two"])

    def test_merge_order_case_and_empty_values(self):
        for values, expected in ((("one", "two"), "one, two"),
                                 (("two", "one"), "two, one"),
                                 (("", "two"), ", two"),
                                 (("one", ""), "one, "), (("", ""), ", ")):
            for mixed_case in (False, True):
                with self.subTest(values=values, mixed_case=mixed_case):
                    facts = self.observe(values, mixed_case=mixed_case)
                    self.assertEqual(self.duplicates(facts), [expected])
                    self.assertEqual(self.duplicates(facts, "response_header"), [expected])

    def test_literal_comma_is_indistinguishable_at_mapper_boundary(self):
        merged = self.observe(("one", "two"))
        literal = self.observe(("one, two",))
        self.assertEqual(merged["request_header"], literal["request_header"])

    def test_absent_and_single_empty_values(self):
        self.assertEqual(self.duplicates(self.observe(())), [])
        self.assertEqual(self.duplicates(self.observe(("",))), [""])

    def test_response_content_type_fallback_preserves_charset(self):
        facts = self.observe(())
        self.assertEqual(facts["response_header"][-1][:2],
                         ["Content-Type", "text/plain; charset=utf-8"])
        explicit = self.observe(("application/json; charset=us-ascii",), name="Content-Type")
        content_types = [row[1] for row in explicit["response_header"]
                         if row[0].lower() == "content-type"]
        self.assertEqual(content_types, ["application/json; charset=us-ascii"])



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
