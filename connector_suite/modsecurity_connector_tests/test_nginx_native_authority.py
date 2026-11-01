"""Controlled Git fixtures are unit evidence, not native runtime evidence."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

MODULE = load_source(connector_root() / 'ci/runtime/lifecycle/nginx_native_authority.py')


class AuthorityTests(unittest.TestCase):
    def test_fixed_storage_is_exact_and_environment_independent(self):
        with patch.dict(os.environ, {'TMPDIR': '/foreign', 'TEMP': '/foreign', 'RUNNER_TEMP': '/foreign'}):
            self.assertEqual(MODULE.EXTERNAL_ROOT, Path('/var/tmp/codex/ModSecurity-conector'))

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir="/var/tmp/codex/ModSecurity-conector/tmp")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.p = self.root / "parent"
        self.f = self.p / "modules/ModSecurity-test-Framework"
        self.m = self.f / "tools/MRTS"
        for root in (self.m, self.f, self.p):
            root.mkdir(parents=True, exist_ok=True)
            self.git(root, "init", "-q")
            (root / "tracked").write_text("fixture")
            self.git(root, "add", "tracked")
            if root == self.f:
                self.pin(root, "tools/MRTS", self.m)
            elif root == self.p:
                self.pin(root, "modules/ModSecurity-test-Framework", self.f)
            self.git(root, "commit", "-qm", "fixture")
        self.artifacts = self.root / "artifacts"
        self.artifacts.mkdir(mode=0o700)
        self.output = self.artifacts / "authority"
        self.output.mkdir(mode=0o700)
        self.files = {}
        for name in ("binary", "module", "input", "begin", "finish", "write", "budget"):
            path = self.artifacts / name
            path.write_bytes(name.encode())
            path.chmod(0o400)
            self.files[name] = path

    def git(self, root, *args):
        env = dict(os.environ, GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1")
        result = subprocess.run(["rtk", "proxy", "git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "-C", str(root), *args], env=env, capture_output=True, check=True)
        return result.stdout.decode().strip()

    def pin(self, root, name, target):
        self.git(root, "update-index", "--add", "--cacheinfo", "160000," + self.git(target, "rev-parse", "HEAD") + "," + name)

    def kwargs(self):
        return dict(parent_root=self.p, framework_root=self.f, mrts_root=self.m, run_id="unit-run", artifact_root=self.artifacts, binary_path=self.files["binary"], module_path=self.files["module"], fault_libraries={key: self.files[key] for key in MODULE.FAULT_LIBRARIES}, output_parent=self.output)

    def test_current_tuple_and_eight_actual_digests(self):
        result = MODULE.produce_native_authority(**self.kwargs())
        path = result["authority_path"]
        document = json.loads(path.read_bytes())
        self.assertEqual(path.stat().st_mode & 0o777, 0o400)
        self.assertEqual(document["parent_sha"], self.git(self.p, "rev-parse", "HEAD"))
        self.assertEqual(len(document["fault_library_sha256"]), 8)
        for library, cases in MODULE.FAULT_LIBRARIES.items():
            for case in cases:
                self.assertEqual(document["fault_library_sha256"][case], hashlib.sha256(library.encode()).hexdigest())
        self.assertEqual(result["authority_sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
        kwargs = self.kwargs()
        with self.assertRaises((ValueError, FileExistsError)):
            MODULE.produce_native_authority(**kwargs)

    def test_dirty_source_rejected(self):
        for source in (self.p, self.f, self.m):
            with self.subTest(source=source):
                dirty = source / "untracked"
                dirty.write_text("dirty")
                kwargs = self.kwargs()
                with self.assertRaises(ValueError):
                    MODULE.produce_native_authority(**kwargs)
                dirty.unlink()

    def test_changed_clean_child_pin_rejected(self):
        (self.m / "tracked").write_text("new")
        self.git(self.m, "commit", "-qam", "new")
        kwargs = self.kwargs()
        with self.assertRaises(ValueError):
            MODULE.produce_native_authority(**kwargs)

    def test_artifact_link_write_and_bounds_rejected(self):
        binary = self.files["binary"]
        for mode in (0o420, 0o402):
            binary.chmod(mode)
            kwargs = self.kwargs()
            with self.assertRaises(ValueError):
                MODULE.produce_native_authority(**kwargs)
        binary.chmod(0o400)
        link = self.artifacts / "link"
        os.link(binary, link)
        kwargs = self.kwargs()
        with self.assertRaises(ValueError):
            MODULE.produce_native_authority(**kwargs)
        link.unlink()
        link.symlink_to(binary)
        kwargs = self.kwargs()
        kwargs["binary_path"] = link
        with self.assertRaises(ValueError):
            MODULE.produce_native_authority(**kwargs)
        with self.assertRaises(ValueError):
            MODULE.hash_artifact(binary, maximum_bytes=1)

    def test_closed_inputs_and_external_output(self):
        for key, value in (("run_id", "../run"), ("output_parent", self.p), ("artifact_root", self.p), ("framework_root", self.p)):
            kwargs = self.kwargs()
            kwargs[key] = value
            with self.assertRaises(ValueError):
                MODULE.produce_native_authority(**kwargs)
        kwargs = self.kwargs()
        kwargs["fault_libraries"].pop("begin")
        with self.assertRaises(ValueError):
            MODULE.produce_native_authority(**kwargs)

    def test_symlink_ancestor_fifo_and_owner_rejected(self):
        link = self.root / "linked-artifacts"
        link.symlink_to(self.artifacts, target_is_directory=True)
        with self.assertRaises(ValueError):
            MODULE.hash_artifact(link / "binary")
        fifo = self.artifacts / "fifo"
        os.mkfifo(fifo, 0o600)
        with self.assertRaises(ValueError):
            MODULE.hash_artifact(fifo)
        original = os.fstat
        def foreign_file(descriptor):
            details = original(descriptor)
            if stat.S_ISREG(details.st_mode):
                fields = {name: getattr(details, name) for name in dir(details) if name.startswith("st_")}
                fields["st_uid"] = os.geteuid() + 1
                return SimpleNamespace(**fields)
            return details
        with patch.object(MODULE.os, "fstat", side_effect=foreign_file):
            with self.assertRaises(ValueError):
                MODULE.hash_artifact(self.files["binary"])

    def test_source_and_digest_recheck_rejected(self):
        original = MODULE.hash_artifact
        calls = 0
        def dirty_after_hash(path, **kwargs):
            nonlocal calls
            digest = original(path, **kwargs)
            calls += 1
            if calls == 1:
                (self.p / "late-change").write_text("changed")
            return digest
        with patch.object(MODULE, "hash_artifact", side_effect=dirty_after_hash):
            kwargs = self.kwargs()
            with self.assertRaises(ValueError):
                MODULE.produce_native_authority(**kwargs)
        (self.p / "late-change").unlink()
        calls = 0
        def changed_digest(path, **kwargs):
            nonlocal calls
            calls += 1
            return original(path, **kwargs) if calls <= 7 else "0" * 64
        with patch.object(MODULE, "hash_artifact", side_effect=changed_digest):
            kwargs = self.kwargs()
            with self.assertRaises(ValueError):
                MODULE.produce_native_authority(**kwargs)
        self.assertFalse((self.output / "native-operation-authority.json").exists())



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
