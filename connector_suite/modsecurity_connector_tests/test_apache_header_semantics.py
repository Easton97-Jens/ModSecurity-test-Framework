"""Observe real APR/native SDK semantics and reject unbound oracle corrections."""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from modsecurity_connector_tests import header_driver_test_support

ROOT = connector_root()
OVERRIDES = load_source(source_path('connectors/apache/harness/apache_oracle_overrides.py', root=ROOT))


class ApacheHeaderWireTests(header_driver_test_support.RealHeaderDriverCase):
    harness = source_path('connectors/apache/harness/run_apache_smoke.sh', root=ROOT)
    environment_options = {"CURL_HTTP_STATUS_FORMAT": "%{http_code}"}

    def test_case_variants_and_empty_values_keep_their_wire_order(self):
        for values in (("one", "two"), ("two", "one"), ("", "two"), ("one", ""), ("", "")):
            with self.subTest(values=values):
                received = self.send_headers(
                    f"X-No-Crs-Duplicate: {values[0]}\n"
                    f"x-no-crs-duplicate: {values[1]}\n")
                self.assertEqual(received["duplicate"], list(values))


class ApacheNativeHeaderSemanticsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shlex.split(os.environ.get("CC", "cc"))
        apr = shutil.which("apr-1-config")
        include = os.environ.get("MODSECURITY_INCLUDE_DIR", "/usr/include")
        library = os.environ.get("MODSECURITY_LIB_FILE")
        if library is None:
            raise unittest.SkipTest("native SDK component requires explicit MODSECURITY_LIB_FILE; guard and wire controls still execute")
        if not compiler or shutil.which(compiler[0]) is None or apr is None:
            raise RuntimeError("real C compiler and APR development files are required")
        directory = tempfile.TemporaryDirectory(prefix="apache-header-native-", dir=os.environ.get("RUNNER_TEMP"))
        cls.addClassCleanup(directory.cleanup)
        cls.binary = Path(directory.name) / "header-semantics"
        def flags(*arguments):
            return shlex.split(subprocess.run(
                [apr, *arguments], check=True,
                capture_output=True, text=True, timeout=10).stdout)
        cls.include = Path(include)
        command = [*compiler, "-std=c17", "-Wall", "-Wextra", "-Werror",
                   "-I", include, *flags("--includes", "--cppflags", "--cflags"),
                   str(source_path('tests/apache_header_semantics_probe.c', root=ROOT)), library,
                   "-Wl,-rpath," + str(Path(library).parent), *flags("--link-ld", "--libs"), "-ldl",
                   "-o", str(cls.binary)]
        cls.compile_command = command
        cls.work = Path(directory.name)
        completed = subprocess.run(command, capture_output=True, text=True, timeout=90)
        if completed.returncode:
            raise AssertionError("native header probe compile failed:\n" + completed.stderr)

    def test_public_legacy_header_needs_no_cleanup_symbol(self):
        # Compile the complete APR/native probe with the selected public header
        # minus the newer optional helper declaration. This models the legacy
        # API boundary; execution still uses the explicitly selected SDK image.
        include = self.work / "legacy-public-headers" / "modsecurity"
        include.mkdir(parents=True)
        header = (self.include / "modsecurity/transaction.h").read_text()
        declaration = "void msc_intervention_cleanup(ModSecurityIntervention *it);"
        (include / "transaction.h").write_text(header.replace(declaration, ""))
        command = list(self.compile_command)
        command[1:1] = ["-I", str(include.parent)]
        binary = self.work / "header-semantics-legacy"
        command[command.index("-o") + 1] = str(binary)
        result = subprocess.run(command, capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, result.stderr)
        observation = subprocess.run([str(binary), "raw", "original",
            "X-No-Crs-Duplicate", "one", "X-No-Crs-Duplicate", "two"],
            capture_output=True, text=True, timeout=10)
        self.assertEqual(observation.returncode, 0, observation.stderr)
        self.assertIn("matched=1\nstatus=451", observation.stdout)

    def observe(self, values, *, original=False, raw=False, mixed_case=False):
        command = [str(self.binary), "raw" if raw else "merge",
                   "original" if original else "corrected"]
        for index, value in enumerate(values):
            name = "x-no-crs-duplicate" if mixed_case and index % 2 else "X-No-Crs-Duplicate"
            command.extend((name, value))
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        facts = dict(line.split("=", 1) for line in lines if not line.startswith("header="))
        facts["headers"] = [line.split("=", 1)[1].split("\t", 1) for line in lines if line.startswith("header=")]
        return facts

    def test_original_rule_matches_raw_duplicates_but_not_apache_merged_view(self):
        self.assertEqual(self.observe(("one", "two"), original=True, raw=True)["matched"], "1")
        self.assertEqual(self.observe(("one", "two"), original=True)["matched"], "0")

    def test_corrected_rule_requires_one_exact_ordered_merged_value(self):
        for mixed_case in (False, True):
            facts = self.observe(("one", "two"), mixed_case=mixed_case)
            self.assertEqual(facts["count"], "1")
            self.assertEqual(facts["headers"][0][1], "one, two")
            self.assertEqual(facts["matched"], "1")
            self.assertEqual(facts["status"], "451")

    def test_reversed_empty_absent_and_single_values_are_negative_controls(self):
        for values, merged in ((("two", "one"), "two, one"), (("", "two"), ", two"),
                               (("one", ""), "one, "), (("", ""), ", "), (("one",), "one"), ((), None)):
            with self.subTest(values=values):
                facts = self.observe(values, mixed_case=True)
                self.assertEqual(facts["matched"], "0")
                self.assertEqual(facts["count"], str(int(merged is not None)))
                self.assertEqual(facts["headers"][0][1] if merged is not None else None, merged)

    def test_singleton_comma_value_is_indistinguishable_from_merged_duplicates(self):
        self.assertEqual(self.observe(("one, two",))["headers"], self.observe(("one", "two"))["headers"])
        self.assertEqual(self.observe(("one, two",))["matched"], "1")


class ApacheOracleOverrideGuardTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="apache-oracle-guard-", dir=os.environ.get("RUNNER_TEMP"))
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        environment = patch.dict(os.environ, {"CODEX_TEMP_ROOT": str(self.directory)})
        environment.start()
        self.addCleanup(environment.stop)
        registry = json.loads(OVERRIDES.REGISTRY.read_text())
        record = registry["overrides"]["duplicate_header_names_core_merge"]
        relative_case = Path(record["case_relative_path"])
        self.assertFalse(relative_case.is_absolute())
        self.assertNotIn("..", relative_case.parts)
        source_framework = Path(os.environ.get(
            "FRAMEWORK_ROOT", source_path('modules/ModSecurity-test-Framework', root=ROOT)))
        case_bytes = (source_framework / relative_case).read_bytes()
        self.assertEqual(hashlib.sha256(case_bytes).hexdigest(), record["original_case_sha256"])
        self.framework = self.directory / "framework"
        self.case = self.framework / relative_case
        self.case.parent.mkdir(parents=True)
        self.case.write_bytes(case_bytes)
        self.rules = self.directory / "rules.conf"
        self.rules.write_text("SecRuleEngine On\n" + OVERRIDES.ORIGINAL_RULE + "\n")
        self.identity = self.directory / "identity.json"
        self.receipt = self.directory / "receipt.json"

    def prepare(self, selection="duplicate_header_names_core_merge"):
        return OVERRIDES.prepare(selection, self.case, self.framework, self.rules, self.identity, self.receipt)

    def test_unknown_selection_rejects_before_mutating_rules(self):
        original = self.rules.read_bytes()
        with self.assertRaisesRegex(ValueError, "unknown"):
            self.prepare("unknown")
        self.assertEqual(self.rules.read_bytes(), original)

    def test_mismatched_original_case_rejects_before_identity_or_mutation(self):
        self.case = self.directory / "different.yaml"
        self.case.write_text("different")
        with self.assertRaisesRegex(ValueError, "selected case"):
            self.prepare()

    def guard_fixture(self):
        # Synthetic guard inputs test admission, not native/header semantics.
        # Native semantics are independently executed above with genuine APR/SDK.
        registry = json.loads(OVERRIDES.REGISTRY.read_text())
        record = registry["overrides"]["duplicate_header_names_core_merge"]
        facts = {key: record[key] for key in
                 ("profile", "apache_version", "apr_version", "sdk_version")}
        for key in ("apache_binary", "sdk_library"):
            artifact = self.directory / key
            artifact.write_bytes(key.encode())
            facts[key] = str(artifact)
            record[key + "_sha256"] = OVERRIDES.digest(artifact)
        proof = self.directory / "independent-proof.stdout"
        proof.write_text("apr=1.7.6\nsdk=ModSecurity v3.0.14 (Linux)\ncount=1\n"
                         "header=X-No-Crs-Duplicate\tone, two\nmatched=1\nstatus=451\n"
                         "sdk_image=" + facts["sdk_library"] + "\n")
        record["core_merge_proof_sha256"] = OVERRIDES.digest(proof)
        facts["independent_proofs"] = [
            {"kind": kind, "path": str(proof), "sha256": OVERRIDES.digest(proof)}
            for kind in ("apache_core_merge", "apr_native_sdk_regression")]
        registry_path = self.directory / "registry.json"
        registry_path.write_text(json.dumps(registry))
        return record, facts, registry_path

    def test_approved_correction_preserves_original_and_cannot_repeat(self):
        record, facts, registry = self.guard_fixture()
        self.identity.write_text(json.dumps(facts))
        original = self.rules.read_bytes()
        with patch.object(OVERRIDES, "REGISTRY", registry), patch.object(
                OVERRIDES.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, record["framework_revision"])):
            receipt = self.prepare()
            self.assertEqual(Path(receipt["original_rules"]).read_bytes(), original)
            self.assertIn(OVERRIDES.CORRECTED_RULE, self.rules.read_text())
            self.assertIsNone(receipt["runtime_retest"])
            self.assertIsNone(receipt["lifecycle_qualification"])
            with self.assertRaisesRegex(ValueError, "original rendered rule block does not match"):
                self.prepare()

    def test_identity_artifact_and_proof_negatives_never_change_original_rules(self):
        record, baseline, registry = self.guard_fixture()
        expected_errors = {
            "profile": "override identity mismatch: profile",
            "apache_version": "override identity mismatch: apache_version",
            "apr_version": "override identity mismatch: apr_version",
            "sdk_version": "override identity mismatch: sdk_version",
            "apache_binary": "override artifact mismatch: apache_binary",
            "sdk_library": "override artifact mismatch: sdk_library",
            "missing_proof": "independent core and real APR/native SDK proofs are required",
            "proof_hash": "independent proof SHA mismatch",
            "native_observation": "actual APR/native SDK probe does not establish the correction",
        }
        for change in ("profile", "apache_version", "apr_version", "sdk_version",
                       "apache_binary", "sdk_library", "missing_proof", "proof_hash", "native_observation"):
            with self.subTest(change=change):
                facts = json.loads(json.dumps(baseline))
                if change == "missing_proof":
                    facts["independent_proofs"] = []
                elif change == "proof_hash":
                    facts["independent_proofs"][0]["sha256"] = "0" * 64
                elif change == "native_observation":
                    missing = self.directory / "missing-native.stdout"
                    missing.write_text("apr=1.7.6\n")
                    facts["independent_proofs"][1].update(path=str(missing), sha256=OVERRIDES.digest(missing))
                elif change in ("apache_binary", "sdk_library"):
                    facts[change] = str(self.identity)
                else:
                    facts[change] = "wrong"
                self.identity.write_text(json.dumps(facts))
                original = self.rules.read_bytes()
                with patch.object(OVERRIDES, "REGISTRY", registry), patch.object(
                        OVERRIDES.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, record["framework_revision"])):
                    with self.assertRaises(ValueError) as error:
                        self.prepare()
                self.assertEqual(str(error.exception), expected_errors[change])
                self.assertEqual(self.rules.read_bytes(), original)
                self.assertFalse(self.receipt.exists())



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
