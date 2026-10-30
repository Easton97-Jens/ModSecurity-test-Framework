"""Compiled fixture controls use simulated process IDs, never native evidence."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = connector_root()


class InputFaultScopeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix="input-fault-scope-", dir=os.environ.get("RUNNER_TEMP"))
        cls.addClassCleanup(temporary.cleanup)
        cls.root = Path(temporary.name)
        cls.binary = cls.root / "probe"
        flags = ["/usr/bin/cc", "-std=c17", "-Wall", "-Wextra", "-Werror", "-I", str(source_path('common/include', root=ROOT))]
        obj = cls.root / "guard.o"
        subprocess.run(flags + ["-Dmsconnector_request_mapper_validate_output=actual_common_guard", "-c",
                        str(source_path('common/src/request_mapper_contract.c', root=ROOT)), "-o", str(obj)],
                       check=True, capture_output=True, timeout=30)
        subprocess.run(flags + [str(source_path('tests/fixtures/nginx_common_input_fault_scope.c', root=ROOT)), str(obj),
                                 "-o", str(cls.binary)], check=True, capture_output=True, timeout=30)

    def invoke(self, case, control, argument, descriptors=(), extra_environment=None):
        environment = dict(os.environ)
        for name in tuple(environment):
            if name.startswith("MSCONNECTOR_OWNED_INPUT_"):
                environment.pop(name)
        environment.update(extra_environment or {})
        result = subprocess.run([str(self.binary), case, control, str(argument)],
                                env=environment, pass_fds=descriptors, check=True,
                                capture_output=True, text=True, timeout=5)
        return result.stdout.strip()

    def probe(self, case, control):
        ledger = self.root / (case + "-" + control + ".jsonl")
        ledger.touch(mode=0o600)
        descriptor = os.open(ledger, os.O_RDWR | os.O_NOFOLLOW)
        try:
            result = self.invoke(case, control, descriptor, (descriptor,))
        finally:
            os.close(descriptor)
        rows = [json.loads(line) for line in ledger.read_text().splitlines() if line]
        return result, rows

    def test_exact_target_reaches_real_common_guard_once(self):
        for case in ("body_size_nonzero_with_null_data", "header_count_nonzero_with_null_headers"):
            with self.subTest(case=case):
                result, rows = self.probe(case, "exact")
                self.assertEqual(result, "0 1")
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["validator_return"], 0)
                self.assertIs(rows[0]["diagnostic_match"], True)

    def test_wrong_transaction_uid_parent_uri_or_method_never_inject(self):
        for control in ("transaction", "uid", "parent", "uri", "method", "foreign-after-match"):
            with self.subTest(control=control):
                result, rows = self.probe("body_size_nonzero_with_null_data", control)
                self.assertEqual(result, "1 1")
                self.assertEqual(rows, [])

    def test_bad_or_non_decimal_descriptor_never_arms(self):
        for descriptor in ("", "-1", "0", "2", "+3", " 3", "3x", "2147483648", "99999999999", "99999"):
            with self.subTest(descriptor=descriptor):
                self.assertEqual(self.invoke("body_size_nonzero_with_null_data", "exact", descriptor), "1 1")

    def test_read_only_hardlink_nonempty_mode_and_foreign_owner_never_arm(self):
        for control in ("readonly", "hardlink", "nonempty", "mode", "owner"):
            with self.subTest(control=control):
                leaf = self.root / (control + ".jsonl")
                leaf.touch(mode=0o600)
                if control == "hardlink":
                    os.link(leaf, self.root / "linked.jsonl")
                if control == "nonempty":
                    leaf.write_bytes(b"retained\n")
                if control == "mode":
                    leaf.chmod(0o644)
                before = leaf.read_bytes()
                descriptor = os.open(leaf, os.O_RDONLY if control == "readonly" else os.O_RDWR)
                try:
                    self.assertEqual(self.invoke("body_size_nonzero_with_null_data",
                        "owner" if control == "owner" else "exact", descriptor, (descriptor,)), "1 1")
                finally:
                    os.close(descriptor)
                self.assertEqual(leaf.read_bytes(), before)

    def test_nonregular_descriptor_never_arms(self):
        reader, writer = os.pipe()
        try:
            self.assertEqual(self.invoke("body_size_nonzero_with_null_data", "exact", writer, (writer,)), "1 1")
        finally:
            os.close(reader)
            os.close(writer)

    def test_legacy_path_is_not_reopened(self):
        leaf = self.root / "legacy.jsonl"
        leaf.touch(mode=0o600)
        self.assertEqual(self.invoke("body_size_nonzero_with_null_data", "legacy", leaf), "1 1")
        self.assertEqual(leaf.read_bytes(), b"")

    def test_replaced_path_and_legacy_alias_cannot_redirect_open_inode(self):
        leaf = self.root / "original.jsonl"
        leaf.touch(mode=0o600)
        descriptor = os.open(leaf, os.O_RDWR | os.O_NOFOLLOW)
        retained = self.root / "retained.jsonl"
        leaf.rename(retained)
        leaf.touch(mode=0o600)
        alias = self.root / "alias.jsonl"
        alias.symlink_to(leaf)
        try:
            self.assertEqual(self.invoke("body_size_nonzero_with_null_data", "exact", descriptor, (descriptor,),
                {"MSCONNECTOR_OWNED_INPUT_LEDGER": str(alias)}), "0 1")
        finally:
            os.close(descriptor)
        rows = [json.loads(line) for line in retained.read_text().splitlines()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["validator_return"], 0)
        self.assertIs(rows[0]["diagnostic_match"], True)
        self.assertEqual(leaf.read_bytes(), b"")

# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)
