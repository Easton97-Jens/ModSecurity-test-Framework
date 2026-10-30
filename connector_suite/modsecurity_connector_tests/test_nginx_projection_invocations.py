"""Real projection guards exercised through Parent invocation dispatch seams."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = connector_root()
HARNESS = source_path('connectors/nginx/harness/run_nginx_smoke.sh', root=ROOT)
FIRST_BYTE = source_path('ci/runtime/lifecycle/run-native-first-byte.sh', root=ROOT)
VALIDATOR = source_path('ci/runtime/common/validate-nginx-harness-paths.py', root=ROOT)
PROJECTOR = source_path('ci/runtime/common/prepare-nginx-docroot-projection.py', root=ROOT)


class NginxProjectionInvocationsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="projection-invocations-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.base.chmod(0o711)
        self.parent = self.base / "projections"
        self.parent.mkdir(mode=0o711)
        self.seed = self.parent / ("s" * 128)
        self.build = self.base / "verified/build"
        self.source = self.build / "source/htdocs"
        self.source.mkdir(parents=True)
        for filename in ("index.html", "__modsec_smoke_ready"):
            (self.source / filename).write_text(filename + "\n", encoding="utf-8")
        self.records = self.base / "invocations.jsonl"
        self.child = self.base / "child.sh"
        self.child.write_text(
            '#!/bin/sh\nset -eu\n'
            '"$PYTHON" -c \'import json,os; from pathlib import Path; '
            'p=Path(os.environ["NGINX_DOCROOT_PROJECTION_ROOT"]); '
            'record={k:os.environ.get(k, "") for k in '
            '("NGINX_DOCROOT_PROJECTION_ROOT", "NGINX_DOCROOT_PROJECTION_PARENT", '
            '"NO_CRS_RUN_ID", "TEST_CASE", "MSCONNECTOR_FULL_LIFECYCLE_SYNC")}; '
            'record["fresh"]=not p.exists() and not p.is_symlink(); '
            'with_record=open(os.environ["RECORDS"], "a"); '
            'with_record.write(json.dumps(record)+"\\n"); with_record.close()\'\n'
            '"$PYTHON" "$VALIDATOR" --quiet --verified-run-root "$VERIFIED_RUN_ROOT" '
            '--existing-private-directory parent "$NGINX_DOCROOT_PROJECTION_PARENT" '
            '--existing-direct-child root "$NGINX_DOCROOT_PROJECTION_ROOT" "$NGINX_DOCROOT_PROJECTION_PARENT"\n'
            'exec "$PYTHON" "$PROJECTOR" --source-docroot "$SOURCE_DOCROOT" '
            '--private-root "$BUILD_ROOT" --worker-gid "' + str(os.getegid()) + '" '
            '--projection-parent "$NGINX_DOCROOT_PROJECTION_PARENT" '
            '--projection-root "$NGINX_DOCROOT_PROJECTION_ROOT"\n',
            encoding="utf-8",
        )
        self.child.chmod(0o700)
        self.environment = {
            "PATH": os.defpath, "PYTHON": sys.executable,
            "PYTHON_BIN": sys.executable, "PYTHONDONTWRITEBYTECODE": "1",
            "REPO_ROOT": str(ROOT), "CONNECTOR_ROOT": str(ROOT),
            "VERIFIED_RUN_ROOT": str(self.base / "verified"),
            "BUILD_ROOT": str(self.build), "RUNTIME_BASE": str(self.build / "runtime"),
            "LOG_DIR": str(self.build / "logs"), "RESULTS_DIR": str(self.build / "results"),
            "NGINX_DOCROOT_PROJECTION": "1",
            "NGINX_DOCROOT_PROJECTION_PARENT": str(self.parent),
            "NGINX_DOCROOT_PROJECTION_ROOT": str(self.seed),
            "NGINX_PATH_AUTHORITY_VALIDATOR": str(VALIDATOR),
            "VALIDATOR": str(VALIDATOR), "PROJECTOR": str(PROJECTOR),
            "SOURCE_DOCROOT": str(self.source), "RECORDS": str(self.records),
            "NO_CRS_RUN_ID": "run-" + "r" * 124,
        }

    def run_batch(self) -> subprocess.CompletedProcess[str]:
        source = HARNESS.read_text(encoding="utf-8")
        functions = "\n".join(
            source[source.index(name + "() {"):source.index("\n}\n", source.index(name + "() {")) + 3]
            for name in ("validate_nginx_docroot_projection_mode",
                         "validate_nginx_external_projection_authority", "run_all_cases")
        )
        summary = self.base / "summary.py"
        summary.write_text("# summary boundary: no runtime evidence\n", encoding="utf-8")
        environment = self.environment | {
            "MSCONNECTOR_SMOKE_STAGE": "minimal_runtime_smoke",
            "MSCONNECTOR_SMOKE_STAGE_BOUNDED_SOAK": "bounded_soak",
            "BASE_PORT": "18081", "CASE_CLI": str(summary),
            **{name: "" for name in (
                "NGINX_BINARY", "NGINX_MODULE", "MODSECURITY_RUNTIME_LIBRARY",
                "CONNECTOR_ORIGIN_SOURCE", "CONNECTOR_ORIGIN_SOURCE_REPO",
                "CONNECTOR_ORIGIN_SOURCE_URL", "CONNECTOR_ORIGIN_SOURCE_COMMIT",
                "CONNECTOR_ORIGIN_SOURCE_VERSION", "CONNECTOR_ORIGIN_LICENSE",
                "CONNECTOR_ORIGIN_IMPORTED_PATH")},
        }
        script = (
            'set -eu\nrequire_absolute_generated_path() { :; }\n'
            'blocked() { echo "$*" >&2; exit 77; }\n'
            'fail() { echo "$*" >&2; exit 1; }\n'
            'append_selected_phase4_fixtures() { :; }\n'
            'list_case_files() { printf "%s\\n" /cases/allow.yaml /cases/deny.yaml; }\n'
            'write_case_result() { :; }\n' + functions + '\nrun_all_cases\n'
        )
        return subprocess.run(["sh", "-c", script, str(self.child)], env=environment,
                              capture_output=True, text=True, check=False)

    def run_first_byte(self, *, default_verified_root: bool = False) -> subprocess.CompletedProcess[str]:
        connector = self.base / "connector"
        connector.mkdir(exist_ok=True)
        (connector / "Makefile").write_text("# fixture repository boundary\n", encoding="utf-8")
        wrapper = connector / "ci/provisioning/cache/with-runtime-components.sh"
        wrapper.parent.mkdir(parents=True, exist_ok=True)
        wrapper.write_text('#!/bin/sh\n'
                           'VERIFIED_RUN_ROOT=${VERIFIED_RUN_ROOT:-$RUNNER_TEMP/ModSecurity-conector-verified}\n'
                           'export VERIFIED_RUN_ROOT\nexec "$@"\n', encoding="utf-8")
        wrapper.chmod(0o700)
        harness = connector / "connectors/nginx/harness/run_nginx_smoke.sh"
        harness.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(self.child, harness)
        harness.chmod(0o700)
        common = connector / "ci/runtime/common"
        common.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(VALIDATOR, common / VALIDATOR.name)
        library = connector / "ci/lib"
        library.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_path('ci/lib/runtime_path_utils.py', root=ROOT), library / "runtime_path_utils.py")
        framework = source_path('modules/ModSecurity-test-Framework', root=ROOT)
        environment = self.environment | {
            "CONNECTOR_ROOT": str(connector), "FRAMEWORK_ROOT": str(framework),
            "HOST_RUNTIME_ROOT": str(self.build / "runtime"),
            "NO_CRS_RULES_FILE": str(framework / "tests/rules/no-crs-baseline.conf"),
            "FULL_LIFECYCLE_EVIDENCE_OUTPUT": str(self.build / "first-byte.json"),
        }
        if default_verified_root:
            environment.pop("VERIFIED_RUN_ROOT")
            environment["RUNNER_TEMP"] = str(self.base)
        return subprocess.run(["sh", str(FIRST_BYTE), "nginx"], env=environment,
                              capture_output=True, text=True, check=False)

    def assert_projections(self, count: int) -> list[Path]:
        records = [json.loads(line) for line in self.records.read_text().splitlines()]
        self.assertEqual(len(records), count)
        paths = [Path(record["NGINX_DOCROOT_PROJECTION_ROOT"]) for record in records]
        self.assertEqual(len(set(paths)), count)
        for record, path in zip(records, paths):
            self.assertTrue(record["fresh"], record)
            self.assertEqual(Path(record["NGINX_DOCROOT_PROJECTION_PARENT"]), self.parent)
            self.assertEqual(path.parent, self.parent)
            self.assertRegex(path.name, re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"))
            self.assertFalse(path.is_symlink())
            self.assertEqual({item.name for item in path.iterdir()},
                             {"index.html", "__modsec_smoke_ready"})
        self.assertFalse(self.seed.exists())
        return paths

    def test_two_batches_use_distinct_fresh_direct_children_and_reuse_stays_rejected(self) -> None:
        for _ in range(2):
            result = self.run_batch()
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        paths = self.assert_projections(4)
        replay = subprocess.run(["sh", str(self.child)],
                                env=self.environment | {"NGINX_DOCROOT_PROJECTION_ROOT": str(paths[0])},
                                capture_output=True, text=True, check=False)
        self.assertEqual(replay.returncode, 2, replay.stderr)
        self.assertIn("fresh non-symlink child", replay.stderr)
        self.assertEqual((paths[0] / "index.html").read_text(), "index.html\n")

    def test_first_byte_has_its_own_fresh_child_on_each_invocation(self) -> None:
        for _ in range(2):
            result = self.run_first_byte()
            # Stop after the real projection, before any host/request evidence.
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("without a Phase-4 event", result.stderr)
        self.assert_projections(2)

    def test_first_byte_does_not_reuse_a_batch_child(self) -> None:
        batch = self.run_batch()
        self.assertEqual(batch.returncode, 0, batch.stdout + batch.stderr)
        result = self.run_first_byte()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("without a Phase-4 event", result.stderr)
        self.assert_projections(3)

    def test_invalid_caller_seed_is_not_repaired_by_allocation(self) -> None:
        for invocation in (self.run_batch, self.run_first_byte):
            for seed in (self.parent / "nested/docroot", self.parent / "occupied",
                         self.parent / "unsafe name", self.parent / ("s" * 129)):
                with self.subTest(invocation=invocation.__name__, seed=seed):
                    if seed.name == "occupied":
                        seed.mkdir(exist_ok=True)
                    self.environment["NGINX_DOCROOT_PROJECTION_ROOT"] = str(seed)
                    result = invocation()
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(self.records.exists())

    def test_first_byte_preserves_default_verified_root(self) -> None:
        result = self.run_first_byte(default_verified_root=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("without a Phase-4 event", result.stderr)
        self.assert_projections(1)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
