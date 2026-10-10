"""Private local authority fixtures, not native build/runtime authority."""
from copy import deepcopy
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

from tests.runners import nginx_native_operation_authority as authority


class NativeAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="native-authority-", dir=os.environ["TMPDIR"])
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.parent = self.root / "parent"
        self.framework = self.parent / "modules/framework"
        self.framework.mkdir(parents=True)
        self.artifacts = self.root / "artifacts"
        self.artifacts.mkdir()
        self.path = self.root / "authority.json"
        self.expected = {"run_id": "unit-authority", "parent_sha": "a" * 40, "framework_sha": "b" * 40, "mrts_sha": "c" * 40}
        self.document = {"schema_version": 1, "connector": "nginx", **self.expected,
                         "parent_root": str(self.parent), "framework_root": str(self.framework), "artifact_root": str(self.artifacts),
                         "binary_sha256": "d" * 64, "module_sha256": "e" * 64,
                         "fault_library_sha256": {"engine_timeout_before_commit": "f" * 64}}
        self.write()

    def write(self):
        raw = json.dumps(self.document, indent=2).encode() + b"\n"
        self.path.write_bytes(raw)
        self.path.chmod(0o600)
        return raw

    def load(self):
        return authority.load_native_operation_authority(self.path, self.expected)

    def test_explicit_nested_source_roots_and_original_retention_bytes(self):
        raw = self.path.read_bytes()
        result = self.load()
        self.assertEqual(result["artifact_root"], self.artifacts)
        self.assertEqual(result["sources"]["framework_root"], self.framework)
        self.assertEqual(result["authority_bytes"], raw)
        self.assertEqual(authority.serialized_mapping(result), self.document)
        self.assertEqual(self.path.read_bytes(), raw)

    def test_expected_tuple_cannot_be_derived_from_manifest_or_receipt(self):
        for field in self.expected:
            changed = deepcopy(self.expected)
            changed[field] = "foreign" if field == "run_id" else "0" * 40
            with self.subTest(field=field), self.assertRaises(ValueError):
                authority.load_native_operation_authority(self.path, changed)
        for expected in (None, {}, {**self.expected, "receipt": self.document}, {**self.expected, "run_id": True}):
            with self.assertRaises(ValueError):
                authority.load_native_operation_authority(self.path, expected)

    def test_closed_schema_types_sha_and_fault_case_controls(self):
        mutations = (("schema_version", True), ("connector", "apache"), ("unexpected", {}), ("run_id", "foreign"),
                     ("parent_sha", "a" * 39), ("framework_sha", "B" * 40), ("mrts_sha", None),
                     ("binary_sha256", "d" * 63), ("module_sha256", 1),
                     ("fault_library_sha256", {"invented": "f" * 64}), ("fault_library_sha256", []),
                     ("fault_library_sha256", {"engine_timeout_before_commit": "F" * 64}))
        original = deepcopy(self.document)
        for field, value in mutations:
            self.document = {**original, field: value}
            self.write()
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.load()
        self.document = original
        self.document["fault_library_sha256"] = {}
        self.write()
        self.assertEqual(dict(self.load()["sources"]["fault_library_sha256"]), {})

    def test_duplicate_nonfinite_nonobject_and_oversized_json_fail(self):
        original = self.path.read_bytes()
        for raw in (original.replace(b'"schema_version": 1,', b'"schema_version": 1,"schema_version": 1,'),
                    original.replace(b'"schema_version": 1', b'"schema_version": NaN'),
                    original.replace(b'"schema_version": 1', b'"schema_version": 1e999'), b'[]',
                    b' ' * (authority.AUTHORITY_LIMIT + 1)):
            self.path.write_bytes(raw)
            with self.subTest(raw=raw[:40]), self.assertRaises(ValueError):
                self.load()

    def test_file_symlink_hardlink_fifo_and_permissions_fail(self):
        alias = self.root / "alias.json"
        alias.symlink_to(self.path)
        with self.assertRaises(ValueError):
            authority.load_native_operation_authority(alias, self.expected)
        alias.unlink()
        os.link(self.path, alias)
        with self.assertRaises(ValueError):
            self.load()
        alias.unlink()
        self.path.chmod(0o622)
        with self.assertRaises(ValueError):
            self.load()
        self.path.chmod(0o600)
        fifo = self.root / "fifo"
        os.mkfifo(fifo, 0o600)
        with self.assertRaises(ValueError):
            authority.load_native_operation_authority(fifo, self.expected)
        self.root.chmod(0o777)
        with self.assertRaises(ValueError):
            self.load()
        self.root.chmod(0o700)

    def test_root_symlink_missing_overlap_alias_and_path_controls(self):
        original = deepcopy(self.document)
        alias = self.root / "source-alias"
        alias.symlink_to(self.parent, target_is_directory=True)
        mutations = (("parent_root", str(alias)), ("framework_root", str(alias / "modules/framework")),
                     ("framework_root", str(self.parent)), ("artifact_root", str(self.parent)),
                     ("artifact_root", str(self.framework / "artifacts")), ("artifact_root", str(self.root)),
                     ("parent_root", str(self.root / "missing")), ("parent_root", "/"),
                     ("parent_root", "relative"), ("parent_root", str(self.parent) + "/.."),
                     ("parent_root", str(self.parent) + "/"), ("parent_root", "/" + str(self.parent)))
        (self.framework / "artifacts").mkdir()
        for field, value in mutations:
            self.document = {**original, field: value}
            self.write()
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.load()

    def test_writable_source_and_artifact_directories_fail(self):
        for directory in (self.parent, self.framework, self.artifacts):
            original = directory.stat().st_mode & 0o777
            directory.chmod(0o777)
            with self.subTest(directory=directory), self.assertRaises(ValueError):
                self.load()
            directory.chmod(original)

    def test_foreign_file_owner_is_rejected_by_real_descriptor_predicate(self):
        actual_fstat = os.fstat

        def foreign_owner(descriptor):
            metadata = actual_fstat(descriptor)
            if authority.bundle.stat.S_ISREG(metadata.st_mode):
                return types.SimpleNamespace(st_mode=metadata.st_mode, st_uid=os.geteuid() + 1,
                                             st_nlink=metadata.st_nlink, st_size=metadata.st_size)
            return metadata

        with mock.patch.object(authority.os, "fstat", side_effect=foreign_owner):
            with self.assertRaises(ValueError):
                self.load()

    def test_immutable_context_plain_copies_and_retention_seal_controls(self):
        loaded = self.load()
        for target, field, value in ((loaded, "run_id", "foreign"), (loaded["sources"], "module_sha256", "0" * 64),
                                      (loaded["sources"]["fault_library_sha256"], "engine_timeout_before_commit", "0" * 64)):
            with self.subTest(field=field), self.assertRaises(TypeError):
                target[field] = value
        copied_sources = dict(loaded["sources"])
        copied_sources["module_sha256"] = "0" * 64
        self.assertEqual(loaded["sources"]["module_sha256"], "e" * 64)
        serialized = authority.serialized_mapping(loaded)
        serialized["fault_library_sha256"]["engine_timeout_before_commit"] = "0" * 64
        self.assertEqual(authority.serialized_mapping(loaded), self.document)
        for field, value in (("authority_sha256", "0" * 64), ("authority_bytes", b"{}"),
                             ("artifact_root", self.parent), ("binary_sha256", "0" * 64)):
            changed = {**loaded, field: value}
            with self.subTest(field=field), self.assertRaises(ValueError):
                authority.serialized_mapping(changed)
        retained = self.root / "retained.json"
        retained.write_bytes(loaded["authority_bytes"])
        retained.chmod(0o600)
        self.assertEqual(authority.load_native_operation_authority(retained, self.expected)["authority_sha256"], loaded["authority_sha256"])


if __name__ == "__main__":
    unittest.main()
