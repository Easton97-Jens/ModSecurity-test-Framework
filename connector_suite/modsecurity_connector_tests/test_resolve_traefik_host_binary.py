from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import importlib.util
import os
import subprocess
import sys
from pathlib import Path
import stat
import tempfile
import unittest


ROOT = connector_root()
resolver = load_source(source_path('ci/runtime/lifecycle/resolve-traefik-host-binary.py', root=ROOT))


class ResolveTraefikHostBinaryTest(unittest.TestCase):
    def executable(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return path

    def test_accepts_regular_executable_below_current_build_root(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            build_root = Path(name) / "build"
            binary = self.executable(build_root / "traefik-connector/bin/traefik")
            self.assertEqual(
                resolver.resolve_traefik_host_binary(build_root), binary
            )

    def test_rejects_missing_staged_binary_or_relative_build_root(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            build_root = Path(name) / "build"
            build_root.mkdir()
            with self.assertRaises(ValueError):
                resolver.resolve_traefik_host_binary(build_root)
            with self.assertRaises(ValueError):
                resolver.resolve_traefik_host_binary(Path("relative-build-root"))

    def test_does_not_accept_an_arbitrary_in_tree_executable(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            build_root = Path(name) / "build"
            self.executable(build_root / "other-tool")
            with self.assertRaises(ValueError):
                resolver.resolve_traefik_host_binary(build_root)

    def test_rejects_symlink_directory_and_non_executable_staged_path(self) -> None:
        for kind in ("symlink", "directory", "non_executable"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as name:
                build_root = Path(name) / "build"
                expected = build_root / "traefik-connector/bin/traefik"
                expected.parent.mkdir(parents=True)
                if kind == "symlink":
                    expected.symlink_to(self.executable(build_root / "real-traefik"))
                elif kind == "directory":
                    expected.mkdir()
                else:
                    expected.write_text("data\n", encoding="utf-8")
                with self.assertRaises(ValueError):
                    resolver.resolve_traefik_host_binary(build_root)

    def test_rejects_writable_and_hardlinked_staged_binary(self) -> None:
        for kind in ("writable", "hardlink"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as name:
                build = Path(name) / "build"
                binary = self.executable(build / "traefik-connector/bin/traefik")
                if kind == "writable":
                    binary.chmod(0o775)
                else:
                    os.link(binary, build / "other-alias")
                with self.assertRaisesRegex(ValueError, "current-user owned, singly linked"):
                    resolver.resolve_traefik_host_binary(build)

    def test_executed_inventory_uses_current_stage_native_version_and_preserves_native_profile(self) -> None:
        source = (source_path('ci/runtime/lifecycle/run-no-crs-baseline.sh', root=ROOT)).read_text()
        inventory = "case \"$connector\" in\n" + source.split(
            'BUILD_ROOT=$CONNECTOR_BUILD_ROOT\ncase "$connector" in\n', 1
        )[1].split('\nlibmodsecurity_version=', 1)[0]
        with tempfile.TemporaryDirectory(prefix="traefik-inventory-") as name:
            build = Path(name) / "current stage build"
            build.mkdir()
            staged = self.executable(build / "traefik-connector/bin/traefik")
            staged.write_text('#!/bin/sh\n[ "$1" = version ] || exit 99\nprintf "Version: current-stage-native-output\\n"\n')
            inherited = self.executable(Path(name) / "another-host")
            inherited.write_text('#!/bin/sh\nprintf "Version: separate-native-profile\\n"\n')
            environment = {**os.environ, "connector": "traefik", "NO_CRS_ARTIFACT_PROFILE": "generic",
                "host_version": "not_provisioned", "host_binary": "", "PYTHON": sys.executable,
                "CONNECTOR_BUILD_ROOT": str(build), "BUILD_ROOT": str(build),
                "TRAEFIK_HOST_BINARY_RESOLVER": str(source_path('ci/runtime/lifecycle/resolve-traefik-host-binary.py', root=ROOT)),
                "TRAEFIK_BIN": str(inherited), "CONNECTOR_COMPONENT_CACHE": str(Path(name) / "cache"),
                "FIRST_NONEMPTY_OUTPUT_LINE_SED_SCRIPT": "/./{p;q;}"}
            command = inventory + '\nprintf "%s\\n%s\\n" "$host_binary" "$host_version"'
            generic = subprocess.run(["sh", "-eu", "-c", command], env=environment,
                                     capture_output=True, text=True, timeout=30)
            self.assertEqual(generic.returncode, 0, generic.stderr)
            self.assertEqual(generic.stdout.splitlines(), [str(staged), "Version: current-stage-native-output"])
            environment["NO_CRS_ARTIFACT_PROFILE"] = "full_lifecycle"
            native = subprocess.run(["sh", "-eu", "-c", command], env=environment,
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(native.returncode, 0, native.stderr)
            self.assertEqual(native.stdout.splitlines(), [str(inherited), "Version: separate-native-profile"])
            environment["NO_CRS_ARTIFACT_PROFILE"] = "generic"
            staged.unlink()
            missing = subprocess.run(["sh", "-eu", "-c", command], env=environment,
                                     capture_output=True, text=True, timeout=30)
            self.assertEqual(missing.returncode, 0, missing.stderr)
            self.assertEqual(missing.stdout.splitlines(), ["", "not_provisioned"])
            self.assertIn("unavailable or unsafe", missing.stderr)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
