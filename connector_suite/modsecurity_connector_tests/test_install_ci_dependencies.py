"""Protect the reviewed PyYAML source exception and its installation boundary."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import importlib.util
from contextlib import contextmanager
import hashlib
import io
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = connector_root()
INSTALL = load_source(source_path('ci/tools/install-ci-dependencies.py', root=ROOT))


class CiDependencyInstallTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=os.environ.get("RUNNER_TEMP"))
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.repository = self.directory / "repository"
        self.repository.mkdir()
        self.build = self.directory / "build"
        self.build.mkdir()
        self.framework_lock = self.repository / INSTALL.FRAMEWORK_LOCK
        self.framework_lock.parent.mkdir(parents=True)
        self.version = ".".join(map(str, sys.version_info[:3]))
        (self.repository / ".python-version").write_text(self.version + "\n")
        self.toolcache = self.directory / "toolcache"
        self.toolcache_python = self.toolcache / "bin/python"
        self.toolcache_python.parent.mkdir(parents=True)
        self.toolcache_python.write_text("fixture interpreter identity\n")
        self.toolcache_python.chmod(0o700)

    @contextmanager
    def selected_toolcache(self):
        with (patch.object(INSTALL.sys, "prefix", str(self.toolcache)),
              patch.object(INSTALL.sys, "base_prefix", str(self.toolcache)),
              patch.object(INSTALL.sys, "executable", str(self.toolcache_python)),
              patch.dict(os.environ, {"GITHUB_ACTIONS": "true", "RUNNER_TEMP": str(self.build),
                                     "pythonLocation": str(self.toolcache)})):
            yield

    def write_framework_lock(self, requirement="PyYAML==6.0.3"):
        self.framework_lock.write_text(
            "# existing reviewed Framework contract\n" + requirement + " \\\n"
            "    --hash=sha256:" + "a" * 64 + "\n")

    def validate_framework_lock(self):
        with patch.object(INSTALL, "ROOT", self.repository):
            INSTALL.framework_contract(INSTALL.FRAMEWORK_LOCK, "6.0.3")

    def archive(self, name, link=False):
        archive = self.build / "source.tar.gz"
        with tarfile.open(archive, "w:gz") as output:
            member = tarfile.TarInfo(name)
            if link:
                member.type = tarfile.SYMTYPE
                member.linkname = "../../outside"
            output.addfile(member, io.BytesIO())
        return archive

    def wheel(self, native=False):
        path = self.build / "pyyaml-6.0.3-py3-none-any.whl"
        with zipfile.ZipFile(path, "w") as output:
            output.writestr("pyyaml-6.0.3.dist-info/METADATA", "Name: PyYAML\nVersion: 6.0.3\n")
            output.writestr("pyyaml-6.0.3.dist-info/WHEEL",
                            "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n")
            output.writestr("yaml/__init__.py", "__version__ = '6.0.3'\n")
            if native:
                output.writestr("yaml/_yaml.so", b"unexpected native extension")
        return path

    def test_source_hash_failure_prevents_backend_or_target_installation(self):
        source = INSTALL.locked_artifacts(source_path('requirements-ci.lock', root=ROOT))[0]
        with (patch.object(INSTALL, "validate_target", return_value=self.build),
              patch.object(INSTALL, "urlopen") as request,
              patch.object(INSTALL.venv, "EnvBuilder") as builder,
              patch.object(INSTALL, "run_stage") as execute):
            response = request.return_value.__enter__.return_value
            response.geturl.return_value = source.url
            response.read.return_value = b"corrupted source"
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                INSTALL.install(self.build, False, None)
            builder.assert_not_called()
            execute.assert_not_called()

    def test_archive_parent_traversal_is_rejected_before_extraction(self):
        archive = self.archive("../outside")
        with self.assertRaisesRegex(ValueError, "unsafe member"):
            INSTALL.extract_source(archive, self.build, "pyyaml-6.0.3")
        self.assertFalse((self.directory / "outside").exists())

    def test_corrupt_build_tool_prevents_execution_after_source_hash_passes(self):
        data = b"reviewed test source"
        source = INSTALL.Artifact("PyYAML", "https://files.pythonhosted.org/packages/pyyaml-6.0.3.tar.gz",
                                  hashlib.sha256(data).hexdigest())
        tools = INSTALL.locked_artifacts(source_path('requirements-ci-build.lock', root=ROOT))
        with (patch.object(INSTALL, "validate_target", return_value=self.build),
              patch.object(INSTALL, "locked_artifacts", side_effect=[[source], tools]),
              patch.object(INSTALL, "urlopen") as request,
              patch.object(INSTALL.venv, "EnvBuilder") as builder,
              patch.object(INSTALL, "run_stage") as execute):
            response = request.return_value.__enter__.return_value
            response.geturl.side_effect = [source.url, tools[0].url]
            response.read.side_effect = [data, b"corrupt build tool"]
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                INSTALL.install(self.build, False, None)
            self.assertEqual(request.call_count, 2)
            builder.assert_not_called()
            execute.assert_not_called()

    def test_archive_symlink_is_rejected_before_extraction(self):
        archive = self.archive("pyyaml-6.0.3/link", link=True)
        with self.assertRaisesRegex(ValueError, "unsafe member"):
            INSTALL.extract_source(archive, self.build, "pyyaml-6.0.3")
        self.assertFalse((self.build / "pyyaml-6.0.3").exists())

    def test_reviewed_pure_wheel_is_accepted(self):
        INSTALL.pure_wheel(self.wheel(), "6.0.3")

    def test_native_payload_cannot_hide_behind_a_pure_wheel_tag(self):
        wheel = self.wheel(native=True)
        with self.assertRaisesRegex(ValueError, "native extension"):
            INSTALL.pure_wheel(wheel, "6.0.3")

    def test_build_environment_drops_credentials_and_forces_pure_python(self):
        with patch.dict(os.environ, {"GITHUB_TOKEN": "test-secret", "GH_TOKEN": "test-secret",
                                     "PIP_EXTRA_INDEX_URL": "https://unreviewed.invalid",
                                     "PYTHONPATH": "/unreviewed"}):
            environment = INSTALL.child_environment(self.build)
        self.assertTrue({"GITHUB_TOKEN", "GH_TOKEN", "PIP_EXTRA_INDEX_URL", "PYTHONPATH"}.isdisjoint(environment))
        self.assertEqual(environment["PYYAML_FORCE_LIBYAML"], "0")
        self.assertEqual(environment["PIP_NO_INDEX"], "1")
        self.assertEqual(environment["PIP_REQUIRE_VIRTUALENV"], "true")

    def test_framework_lock_accepts_only_the_existing_single_version_contract(self):
        self.write_framework_lock()
        self.validate_framework_lock()

    def test_framework_lock_rejects_a_different_version(self):
        self.write_framework_lock("PyYAML==6.0.2")
        with self.assertRaisesRegex(ValueError, "single reviewed"):
            self.validate_framework_lock()

    def test_framework_lock_cannot_add_another_dependency(self):
        self.write_framework_lock()
        with self.framework_lock.open("a") as output:
            output.write("another-package==1.0 --hash=sha256:" + "b" * 64 + "\n")
        with self.assertRaisesRegex(ValueError, "single reviewed"):
            self.validate_framework_lock()

    def test_framework_lock_cannot_inject_pip_flags(self):
        self.write_framework_lock("--extra-index-url https://unreviewed.invalid PyYAML==6.0.3")
        with self.assertRaisesRegex(ValueError, "single reviewed"):
            self.validate_framework_lock()

    def test_framework_lock_symlink_is_not_a_regular_input(self):
        actual = self.directory / "other.lock"
        actual.write_text("PyYAML==6.0.3")
        self.framework_lock.symlink_to(actual)
        with self.assertRaisesRegex(ValueError, "regular file"):
            self.validate_framework_lock()

    def test_local_system_python_is_never_an_install_target(self):
        with (patch.object(INSTALL, "ROOT", self.repository),
              patch.object(INSTALL.sys, "prefix", "/system"),
              patch.object(INSTALL.sys, "base_prefix", "/system")):
            with self.assertRaisesRegex(ValueError, "virtual environment"):
                INSTALL.validate_target(False, self.build)

    def test_toolcache_flag_requires_the_github_actions_environment(self):
        with (patch.object(INSTALL, "ROOT", self.repository),
              patch.dict(os.environ, {"GITHUB_ACTIONS": "false", "RUNNER_TEMP": str(self.build)})):
            with self.assertRaisesRegex(ValueError, "GitHub Actions"):
                INSTALL.validate_target(True, self.build)

    def test_explicit_actions_toolcache_target_preserves_selected_interpreter(self):
        with (patch.object(INSTALL, "ROOT", self.repository),
              self.selected_toolcache()):
            INSTALL.validate_target(True, self.build)

    def test_same_version_foreign_interpreter_is_not_the_selected_toolcache(self):
        foreign = self.directory / "foreign-python"
        foreign.write_text("foreign fixture interpreter\n")
        foreign.chmod(0o700)
        with (patch.object(INSTALL, "ROOT", self.repository), self.selected_toolcache(),
              patch.object(INSTALL.sys, "executable", str(foreign))):
            with self.assertRaisesRegex(ValueError, "toolcache identity"):
                INSTALL.validate_target(True, self.build)

    def test_build_root_must_be_explicit_when_runner_temp_is_missing(self):
        with (patch.dict(os.environ, {}, clear=True), patch.object(sys, "argv", ["installer"]),
              patch.object(INSTALL, "install") as install, patch("sys.stderr", new=io.StringIO())):
            with self.assertRaisesRegex(SystemExit, "2"):
                INSTALL.main()
            install.assert_not_called()

    def test_existing_private_build_root_is_accepted(self):
        self.assertEqual(INSTALL.external_directory(self.build), self.build)

    def test_public_build_root_is_rejected_before_hash_or_backend(self):
        self.build.chmod(0o777)
        with (patch.object(INSTALL, "ROOT", self.repository),
              patch.object(INSTALL.sys, "prefix", "/fixture/venv"),
              patch.object(INSTALL.sys, "base_prefix", "/fixture/base"),
              patch.object(INSTALL, "reviewed_pins") as pins,
              patch.object(INSTALL, "prepare_builder") as builder):
            with self.assertRaisesRegex(ValueError, "adversary-writable"):
                INSTALL.install(self.build, False, None)
            pins.assert_not_called()
            builder.assert_not_called()

    def test_writable_ancestor_cannot_hide_behind_private_build_root(self):
        unsafe = self.directory / "unsafe-parent"
        unsafe.mkdir()
        build = unsafe / "private-build"
        build.mkdir(mode=0o700)
        unsafe.chmod(0o777)
        with self.assertRaisesRegex(ValueError, "adversary-writable"):
            INSTALL.external_directory(build)

    def test_symlink_ancestor_is_rejected(self):
        alias = self.directory / "build-alias"
        alias.symlink_to(self.build, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "non-symlink"):
            INSTALL.external_directory(alias)

    def test_foreign_owned_build_root_is_rejected(self):
        observed = self.build.lstat()
        fields = list(observed)
        fields[4] = os.geteuid() + 1
        foreign = os.stat_result(fields)
        with patch.object(INSTALL.Path, "lstat", return_value=foreign):
            with self.assertRaisesRegex(ValueError, "trusted non-symlink"):
                INSTALL.trusted_directory_component(self.build, True)

    def test_nested_symlink_ancestor_is_rejected(self):
        nested = self.build / "nested"
        nested.mkdir()
        alias = self.directory / "ancestor-alias"
        alias.symlink_to(self.build, target_is_directory=True)
        selected = alias / "nested"
        with self.assertRaisesRegex(ValueError, "non-symlink"):
            INSTALL.external_directory(selected)

    def candidate_target(self, expected, actual):
        with (patch.object(INSTALL, "ROOT", self.repository),
              patch.object(INSTALL.sys, "version_info", actual),
              self.selected_toolcache()):
            INSTALL.validate_target(True, self.build, expected)

    def test_next_patch_candidate_is_accepted_without_rewriting_canonical_input(self):
        major, minor, patch_version = map(int, self.version.split("."))
        actual = (major, minor, patch_version + 1)
        self.candidate_target(".".join(map(str, actual)), actual)
        self.assertEqual((self.repository / ".python-version").read_text(), self.version + "\n")

    def test_candidate_cannot_change_the_canonical_minor(self):
        major, minor, patch_version = map(int, self.version.split("."))
        actual = (major, minor + 1, patch_version)
        expected = ".".join(map(str, actual))
        with self.assertRaisesRegex(ValueError, "canonical minor"):
            self.candidate_target(expected, actual)

    def test_candidate_cannot_downgrade_the_canonical_patch(self):
        major, minor, patch_version = map(int, self.version.split("."))
        (self.repository / ".python-version").write_text(f"{major}.{minor}.{patch_version + 1}\n")
        with self.assertRaisesRegex(ValueError, "downgrade"):
            self.candidate_target(self.version, (major, minor, patch_version))

    def test_selected_candidate_must_match_the_actual_interpreter(self):
        major, minor, patch_version = map(int, self.version.split("."))
        with self.assertRaisesRegex(ValueError, "selected interpreter"):
            self.candidate_target(f"{major}.{minor}.{patch_version + 1}",
                                  (major, minor, patch_version))



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
