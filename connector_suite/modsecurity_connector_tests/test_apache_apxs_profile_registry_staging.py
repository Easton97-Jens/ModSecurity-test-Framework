"""Regression coverage for APXS profile-registry staging containment."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest


ROOT = connector_root()
WRAPPER_TEMPLATE = source_path('connectors/apache/build/apxs-wrapper.in', root=ROOT)
AUTOTOOLS_BOOTSTRAP = (
    source_path('ci/checks/connectors/apache/check-apache-autotools-bootstrap.sh', root=ROOT)
)


class ApacheApxsProfileRegistryStagingTest(unittest.TestCase):
    def _write_wrapper(self, destination: Path, apxs: Path) -> Path:
        rendered = WRAPPER_TEMPLATE.read_text(encoding="utf-8")
        rendered = rendered.replace("#!@SHELL@", "#!/bin/sh", 1)
        rendered = rendered.replace("@APXS@", str(apxs))
        rendered = rendered.replace("@V3INCLUDE@", "/synthetic/include")
        rendered = rendered.replace("@V3LIB@", "/synthetic/lib")
        destination.write_text(rendered, encoding="utf-8")
        destination.chmod(destination.stat().st_mode | stat.S_IXUSR)
        return destination

    def _write_fake_apxs(self, destination: Path) -> Path:
        destination.write_text(
            "#!/bin/sh\n"
            "set -eu\n"
            "for argument in \"$@\"; do\n"
            "    case \"$argument\" in\n"
            "        */connectors/profile_registry.c)\n"
            "            directory=$(dirname \"$argument\")\n"
            "            mkdir -p \"$directory/.libs\"\n"
            "            : > \"$directory/profile_registry.o\"\n"
            "            : > \"$directory/profile_registry.lo\"\n"
            "            : > \"$directory/profile_registry.slo\"\n"
            "            : > \"$directory/.libs/profile_registry.o\"\n"
            "            printf '%s\\n' \"$argument\" > \"$APXS_ARGUMENT_LOG\"\n"
            "            exit 0\n"
            "            ;;\n"
            "    esac\n"
            "done\n"
            "echo 'profile registry argument missing' >&2\n"
            "exit 1\n",
            encoding="utf-8",
        )
        destination.chmod(destination.stat().st_mode | stat.S_IXUSR)
        return destination

    def _run_wrapper(self, cwd: Path, connector_root: Path, build_root: Path) -> subprocess.CompletedProcess[str]:
        apxs = self._write_fake_apxs(cwd / "fake-apxs")
        wrapper = self._write_wrapper(cwd / "apxs-wrapper", apxs)
        environment = os.environ.copy()
        environment.update(
            {
                "CONNECTOR_ROOT": str(connector_root),
                "MSCONNECTOR_PROFILE_REGISTRY_BUILD_ROOT": str(build_root),
                "APXS_ARGUMENT_LOG": str(cwd / "apxs-argument.log"),
                "PYTHONDONTWRITEBYTECODE": "1",
            }
        )
        return subprocess.run(
            [str(wrapper)], cwd=cwd, env=environment, capture_output=True, text=True, check=False
        )

    def _make_connector_root(self, temporary: Path) -> Path:
        connector_root = temporary / "canonical-checkout"
        sources = connector_root / "connectors"
        sources.mkdir(parents=True)
        (sources / "profile_registry.c").write_text("int registry(void) { return 0; }\n", encoding="utf-8")
        (sources / "profile_registry.h").write_text("#pragma once\n", encoding="utf-8")
        return connector_root

    def test_apxs_receives_staged_registry_and_cannot_dirty_canonical_checkout(self) -> None:
        with tempfile.TemporaryDirectory(prefix="apache-apxs-profile-registry-") as temporary:
            root = Path(temporary)
            connector_root = self._make_connector_root(root)
            build_root = root / "external-build" / "profile-registry"
            workdir = root / "external-build" / "apache"
            workdir.mkdir(parents=True)

            result = self._run_wrapper(workdir, connector_root, build_root)

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            staged = build_root / "connectors"
            self.assertEqual(
                (workdir / "apxs-argument.log").read_text(encoding="utf-8").strip(),
                str(staged / "profile_registry.c"),
            )
            self.assertEqual((staged / "profile_registry.c").read_text(encoding="utf-8"), "int registry(void) { return 0; }\n")
            self.assertEqual((staged / "profile_registry.h").read_text(encoding="utf-8"), "#pragma once\n")
            for artifact in ("profile_registry.o", "profile_registry.lo", "profile_registry.slo", ".libs/profile_registry.o"):
                self.assertTrue((staged / artifact).is_file(), artifact)
                self.assertFalse((connector_root / "connectors" / artifact).exists(), artifact)

    def test_refuses_a_profile_registry_build_root_inside_the_canonical_checkout(self) -> None:
        with tempfile.TemporaryDirectory(prefix="apache-apxs-profile-registry-") as temporary:
            root = Path(temporary)
            connector_root = self._make_connector_root(root)
            workdir = root / "external-build" / "apache"
            workdir.mkdir(parents=True)

            result = self._run_wrapper(workdir, connector_root, connector_root / "build" / "profile-registry")

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must be outside the canonical connector checkout", result.stderr)
            self.assertFalse((connector_root / "connectors" / "profile_registry.o").exists())

    def test_refuses_a_symlinked_build_root_before_it_can_create_checkout_content(self) -> None:
        with tempfile.TemporaryDirectory(prefix="apache-apxs-profile-registry-") as temporary:
            root = Path(temporary)
            connector_root = self._make_connector_root(root)
            workdir = root / "external-build" / "apache"
            workdir.mkdir(parents=True)
            symlinked_root = root / "external-build" / "staging-link"
            symlinked_root.symlink_to(connector_root, target_is_directory=True)

            result = self._run_wrapper(workdir, connector_root, symlinked_root / "profile-registry")

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must be outside the canonical connector checkout", result.stderr)
            self.assertFalse((connector_root / "profile-registry").exists())

    def test_autotools_bootstrap_uses_a_private_stage_outside_its_source_snapshot(self) -> None:
        bootstrap = AUTOTOOLS_BOOTSTRAP.read_text(encoding="utf-8")
        stage_assignment = (
            'MSCONNECTOR_PROFILE_REGISTRY_BUILD_ROOT="$WORK_ROOT/profile-registry" \\'
        )

        self.assertIn("umask 077", bootstrap)
        self.assertIn(
            'WORK_ROOT=$(mktemp -d "$TEST_PARENT/f-gs-001-apache-autotools.XXXXXX")',
            bootstrap,
        )
        self.assertIn('SOURCE_ROOT="$WORK_ROOT/source"', bootstrap)
        self.assertIn(stage_assignment, bootstrap)
        self.assertEqual(bootstrap.count(stage_assignment), 1)
        self.assertNotIn(
            'MSCONNECTOR_PROFILE_REGISTRY_BUILD_ROOT="$APACHE_ROOT/', bootstrap
        )
        self.assertNotIn(
            'MSCONNECTOR_PROFILE_REGISTRY_BUILD_ROOT="$SOURCE_ROOT/', bootstrap
        )
        self.assertLess(
            bootstrap.index(stage_assignment),
            bootstrap.index("    make\n", bootstrap.index(stage_assignment)),
        )



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
