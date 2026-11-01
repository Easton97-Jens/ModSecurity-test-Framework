from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

from modsecurity_connector_tests.framework_test_trust import trusted_framework_root


ROOT = connector_root()
MATRIX_RUNNER = source_path('ci/runtime/lifecycle/run-full-matrix-parallel.sh', root=ROOT)
WITH_RUNTIME_COMPONENTS = source_path('ci/provisioning/cache/with-runtime-components.sh', root=ROOT)
FRAMEWORK_ROOT = source_path('modules/ModSecurity-test-Framework', root=ROOT)


class FullMatrixCacheOwnerRootTest(unittest.TestCase):
    def setUp(self) -> None:
        framework_root, error = trusted_framework_root(ROOT, FRAMEWORK_ROOT)
        if framework_root is None:
            self.skipTest(error)
        self.framework_root = framework_root

    def write_fake_make(self, bin_dir: Path) -> None:
        fake_make = bin_dir / "make"
        fake_make.write_text(
            """#!/bin/sh
set -eu

case "$*" in
    *smoke-apache*)
        connector=apache
        connector_build_root=$APACHE_BUILD_ROOT
        owner_root=$APACHE_BUILD_OWNER_ROOT
        ;;
    *smoke-nginx*)
        connector=nginx
        connector_build_root=$NGINX_BUILD_DIR
        owner_root=$NGINX_BUILD_OWNER_ROOT
        ;;
    *)
        echo "unexpected fake make invocation: $*" >&2
        exit 97
        ;;
esac

printf '%s|%s|%s|%s|%s|%s\\n' \\
    "$connector" "$REFRESH" "$BUILD_ROOT" "$connector_build_root" "$owner_root" "${MSCONNECTOR_COMMON_SRC:-}" \\
    >> "$CAPTURE_FILE"
""",
            encoding="utf-8",
        )
        fake_make.chmod(fake_make.stat().st_mode | stat.S_IXUSR)

    def write_fake_python(self, bin_dir: Path) -> Path:
        fake_python = bin_dir / "python"
        fake_python.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fake_python.chmod(fake_python.stat().st_mode | stat.S_IXUSR)
        return fake_python

    def matrix_environment(
        self,
        root: Path,
        bin_dir: Path,
        capture_file: Path,
        *,
        connectors: str,
        apache_build_root: Path,
        nginx_build_root: Path,
    ) -> tuple[dict[str, str], Path, Path]:
        verified_root = root / "verified"
        component_cache = verified_root / "cache-v2" / "shared"
        owner_root = component_cache / "builds" / "connectors"
        owner_root.mkdir(parents=True)
        apache_build_root.mkdir(parents=True)
        nginx_build_root.mkdir(parents=True)

        environment = os.environ.copy()
        environment.update(
            {
                "PATH": f"{bin_dir}{os.pathsep}{environment['PATH']}",
                "CAPTURE_FILE": str(capture_file),
                "CONNECTOR_ROOT": str(ROOT),
                "FRAMEWORK_ROOT": str(self.framework_root),
                "VERIFIED_RUN_ROOT": str(verified_root),
                "VERIFIED_BUILD_ROOT": str(verified_root / "build"),
                "BUILD_ROOT": str(verified_root / "build"),
                "TMP_ROOT": str(verified_root / "tmp"),
                "LOG_ROOT": str(verified_root / "logs"),
                "CONNECTOR_COMPONENT_CACHE": str(component_cache),
                "VERIFIED_COMPONENT_CACHE": str(component_cache),
                "MATRIX_ROOT": str(verified_root / "matrix"),
                "MRTS_BUILD_ROOT": str(verified_root / "mrts"),
                "NGINX_HARNESS_PARENT": str(verified_root / "nginx-harness"),
                "FULL_MATRIX_VARIANTS": "no-crs/no-mrts",
                "FULL_MATRIX_CONNECTORS": connectors,
                "FULL_MATRIX_SKIP_REPORTS": "1",
                "FULL_MATRIX_REPORT_DIR": str(verified_root / "reports"),
                "FULL_MATRIX_MANIFEST": str(verified_root / "matrix" / "runs.jsonl"),
                "APACHE_BUILD_ROOT": str(apache_build_root),
                "NGINX_BUILD_DIR": str(nginx_build_root),
                "APACHE_HTTPD": "",
                "APACHE_MODULE": "",
                "APACHE_MRTS_MODSECURITY_LIB_DIR": "",
                "MRTS_NATIVE_NGINX_BIN": "",
                "MRTS_NATIVE_NGINX_MODULE_DIR": "",
                "MRTS_NATIVE_NGINX_MODSECURITY_LIB_DIR": "",
            }
        )
        return environment, owner_root, verified_root

    def assert_owner_root_records(
        self,
        capture_file: Path,
        expected_owner_root: Path,
        *,
        expected_job_build_root: Path | None = None,
        expected_job_build_parent: Path | None = None,
        expected_nginx_common_source_root: Path | None = None,
    ) -> None:
        records = {
            fields[0]: fields
            for fields in (
                line.split("|") for line in capture_file.read_text(encoding="utf-8").splitlines()
            )
        }
        self.assertEqual(set(records), {"apache", "nginx"})
        for connector, fields in records.items():
            with self.subTest(connector=connector):
                _, refresh, job_build_root, connector_build_root, owner_root_text, common_source_root = fields
                self.assertEqual(refresh, "1")
                self.assertEqual(owner_root_text, str(expected_owner_root))
                self.assertTrue(Path(connector_build_root).is_relative_to(expected_owner_root))
                if expected_job_build_root is not None:
                    self.assertEqual(job_build_root, str(expected_job_build_root))
                if expected_job_build_parent is not None:
                    self.assertTrue(Path(job_build_root).is_relative_to(expected_job_build_parent))
                self.assertNotEqual(job_build_root, owner_root_text)
                if connector == "nginx" and expected_nginx_common_source_root is not None:
                    self.assertEqual(common_source_root, str(expected_nginx_common_source_root))

    def test_cache_backed_refreshes_receive_one_narrow_explicit_owner_root(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="full-matrix-owner-root-") as temporary:
            root = Path(temporary)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            self.write_fake_make(bin_dir)
            capture_file = root / "make-capture.txt"
            owner_root = root / "verified" / "cache-v2" / "shared" / "builds" / "connectors"
            apache_build_root = owner_root / "apache" / "cache-key" / "build"
            nginx_build_root = owner_root / "nginx" / "cache-key" / "build"
            environment, expected_owner_root, verified_root = self.matrix_environment(
                root,
                bin_dir,
                capture_file,
                connectors="apache nginx",
                apache_build_root=apache_build_root,
                nginx_build_root=nginx_build_root,
            )

            process = subprocess.run(
                ["sh", str(MATRIX_RUNNER)],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
            self.assert_owner_root_records(
                capture_file,
                expected_owner_root,
                expected_job_build_parent=verified_root / "matrix",
            )

    def test_outside_connector_cache_build_is_rejected_before_make(self) -> None:
        with tempfile.TemporaryDirectory(prefix="full-matrix-owner-root-reject-") as temporary:
            root = Path(temporary)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            self.write_fake_make(bin_dir)
            capture_file = root / "make-capture.txt"
            outside_build_root = root / "verified" / "outside" / "apache-build"
            nginx_build_root = (
                root
                / "verified"
                / "cache-v2"
                / "shared"
                / "builds"
                / "connectors"
                / "nginx"
                / "cache-key"
                / "build"
            )
            environment, expected_owner_root, verified_root = self.matrix_environment(
                root,
                bin_dir,
                capture_file,
                connectors="apache",
                apache_build_root=outside_build_root,
                nginx_build_root=nginx_build_root,
            )

            process = subprocess.run(
                ["sh", str(MATRIX_RUNNER)],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(process.returncode, 2, process.stdout + process.stderr)
            self.assertFalse(capture_file.exists())
            run_log = verified_root / "matrix" / "no-crs" / "no-mrts" / "apache" / "run.log"
            self.assertIn(
                f"apache matrix build root must stay under {expected_owner_root}",
                run_log.read_text(encoding="utf-8"),
            )

    def test_direct_runtime_matrix_consumes_snapshot_owner_roots(self) -> None:
        """The direct runtime-matrix target must not fall back to job BUILD_ROOT."""
        with tempfile.TemporaryDirectory(prefix="runtime-matrix-owner-root-") as temporary:
            root = Path(temporary)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            self.write_fake_make(bin_dir)
            fake_python = self.write_fake_python(bin_dir)
            capture_file = root / "make-capture.txt"
            owner_root = root / "verified" / "cache-v2" / "shared" / "builds" / "connectors"
            apache_build_root = owner_root / "apache" / "cache-key" / "build"
            nginx_build_root = owner_root / "nginx" / "cache-key" / "build"
            environment, expected_owner_root, verified_root = self.matrix_environment(
                root,
                bin_dir,
                capture_file,
                connectors="apache nginx",
                apache_build_root=apache_build_root,
                nginx_build_root=nginx_build_root,
            )
            build_root = verified_root / "build"
            component_cache = expected_owner_root.parents[1]
            output_root = build_root / "runtime-component-reports"
            snapshot = output_root / "runtime-env-snapshot.matrix.sh"
            snapshot.parent.mkdir(parents=True)
            snapshot.write_text(
                "\n".join(
                    (
                        f"export CONNECTOR_COMPONENT_CACHE='{component_cache}'",
                        f"export APACHE_BUILD_ROOT='{apache_build_root}'",
                        f"export APACHE_BUILD_OWNER_ROOT='{owner_root}'",
                        f"export NGINX_BUILD_DIR='{nginx_build_root}'",
                        f"export NGINX_BUILD_OWNER_ROOT='{owner_root}'",
                        f"export MSCONNECTOR_COMMON_SRC='{source_path('common/src', root=ROOT)}'",
                        "export RUNTIME_COMPONENT_ENV_SNAPSHOT_TARGET='all'",
                        f"export RUNTIME_COMPONENT_ENV_SNAPSHOT_CACHE='{component_cache}'",
                        "export RUNTIME_COMPONENT_ENV_SNAPSHOT_SCHEMA='1'",
                        "",
                    )
                ),
                encoding="utf-8",
            )
            environment.update(
                {
                    "RUNTIME_REPORT_OUTPUT_ROOT": str(output_root),
                    "RUNTIME_COMPONENT_TARGET": "all",
                    "RUNTIME_COMPONENT_ENV_SNAPSHOT": str(snapshot),
                    "SKIP_RUNTIME_COMPONENT_PREPARE": "1",
                    "PYTHON": str(fake_python),
                    "FORCE_ALL_CASES": "0",
                    "MODSECURITY_MRTS_VARIANT": "no-mrts",
                }
            )

            process = subprocess.run(
                [
                    "sh",
                    str(WITH_RUNTIME_COMPONENTS),
                    "sh",
                    str(self.framework_root / "ci/runtime/run-runtime-matrix.sh"),
                ],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
            self.assert_owner_root_records(
                capture_file,
                expected_owner_root,
                expected_job_build_root=build_root,
                expected_nginx_common_source_root=source_path('common/src', root=ROOT),
            )



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
