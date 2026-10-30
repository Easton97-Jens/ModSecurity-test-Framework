"""Real projection helper via controlled dispatcher collaborators, not host proof."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from modsecurity_connector_tests.test_nginx_native_operation_dispatch import load

ROOT = connector_root()
DISPATCH = load("run-selected-nginx-native-operations.py")
PROJECTOR = load_source(source_path('ci/runtime/common/prepare-nginx-docroot-projection.py', root=ROOT))


class SelectedNativeProjectionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="native-projection-",
                                               dir="/var/tmp/codex/ModSecurity-conector")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.base.chmod(0o711)
        self.private = self.base / "verified-run"
        self.private.mkdir(mode=0o700)
        self.build = self.private / "build"
        self.build.mkdir(mode=0o700)
        self.results = self.build / "results"
        self.results.mkdir(mode=0o700)
        self.parent = self.base / "shared-projection-parent"
        self.parent.mkdir(mode=0o711)
        self.framework = self.base / "framework"
        catalog = self.framework / "tests/cases/no-crs-baseline"
        catalog.mkdir(parents=True)
        self.cases = sorted(DISPATCH.POINTER)
        (catalog / "catalog.json").write_text(json.dumps({"cases": [
            {"case_id": case, "native_invocations": {"nginx": DISPATCH.CONTRACTS[case]}}
            for case in self.cases]}))
        runners = self.framework / "tests/runners"
        runners.mkdir()
        (runners / "nginx_native_operation_bundle.py").write_text(
            'def required_source_paths(case):\n return frozenset({"parent:ci/runtime/lifecycle/run-selected-nginx-native-operations.py"})\n')
        self.environment = dict(FRAMEWORK_ROOT=str(self.framework), BUILD_ROOT=str(self.build),
            RESULTS_DIR=str(self.results), VERIFIED_RUN_ROOT=str(self.private),
            NGINX_PREFIX=str(self.base / "prefix"), NO_CRS_RUN_ID="projection-run",
            NO_CRS_SELECTED_CASE_IDS=" ".join(self.cases),
            NGINX_DOCROOT_PROJECTION_PARENT=str(self.parent),
            NGX_NATIVE_INPUT_FAULT_LIBRARY=str(self.base / "fixture.so"))
        self.projections = []

    def prepare(self, output, parent, child):
        source = output / "docroot"
        source.mkdir(mode=0o700)
        for name in PROJECTOR.PROJECTED_FILENAMES:
            (source / name).write_bytes(b"controlled docroot\n")
        return PROJECTOR.prepare_projection(source_docroot=source, private_root=output,
            projection_parent=parent, projection_root=child, worker_gid=os.getegid(),
            avoid_roots=[self.build, ROOT, self.framework])

    def driver(self, argv, **kwargs):
        self.assertEqual(kwargs, {"check": False, "timeout": 180})
        case = argv[argv.index("--case-id") + 1]
        run_id = argv[argv.index("--run-id") + 1]
        self.assertEqual(run_id, self.environment["NO_CRS_RUN_ID"])
        output = Path(argv[argv.index("--output-root") + 1])
        output.mkdir(mode=0o700)
        parent = Path(argv[argv.index("--projection-parent") + 1])
        self.assertEqual(parent, self.parent)
        token = hashlib.sha256((run_id + ":" + case).encode()).hexdigest()[:32]
        self.projections.append(self.prepare(output, parent, parent / ("common-input-" + token)))
        receipt = {"case_id": case, "run_id": run_id, "operation": "common_mapper_input_fault",
                   "parent_sha": "a" * 40, "framework_sha": "a" * 40, "mrts_sha": "a" * 40}
        path = output / "input-fault-source.json"
        row = {"case_id": case, "run_id": run_id, "operation": "common_mapper_input_fault",
               "input_fault_receipt": receipt}
        path.write_text(json.dumps({"cases": [row]}))
        path.chmod(0o600)
        return SimpleNamespace(returncode=0)

    def test_shared_explicit_parent_supports_two_actual_fresh_direct_preparations(self):
        with patch.object(DISPATCH, "identity", return_value="a" * 40), \
             patch.object(DISPATCH.subprocess, "run", side_effect=self.driver):
            self.assertEqual(DISPATCH.run(self.environment), 0)
        self.assertEqual(len(self.projections), 2)
        self.assertEqual(len(set(self.projections)), 2)
        self.assertTrue(all(child.parent == self.parent for child in self.projections))
        self.assertEqual(stat.S_IMODE(self.parent.stat().st_mode), 0o711)
        output = self.build / "host-runtime/native-operations-projection-run"
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
        self.assertFalse((output / "projections").exists())
        rows = [json.loads(line) for line in (self.results / "nginx-results.jsonl").read_text().splitlines()]
        self.assertEqual([row["run_id"] for row in rows], ["projection-run"] * 2)
        self.assertEqual([row["status"] for row in rows], ["NOT_EXECUTED"] * 2)
        for row in rows:
            receipt = output / row["case_id"] / "input-fault-source.json"
            invocation = row["native_operation_receipt"]["invocations"][0]
            self.assertEqual(invocation["receipt_sha256"], DISPATCH.SOURCE.digest(receipt.read_bytes()))
        source_docroot = output / self.cases[0] / "docroot"
        worker_gid = os.getegid()
        avoid_roots = [self.build]
        for projected in self.projections:
            with self.assertRaisesRegex(ValueError, "already exists"):
                PROJECTOR.prepare_projection(source_docroot=source_docroot,
                    private_root=output, projection_parent=self.parent, projection_root=projected,
                    worker_gid=worker_gid, avoid_roots=avoid_roots)

    def test_old_private_parent_topology_is_rejected_by_unchanged_helper(self):
        output = self.build / "old-output"
        output.mkdir(mode=0o700)
        private_parent = output / "projections"
        private_parent.mkdir(mode=0o700)
        with self.assertRaisesRegex(ValueError, "worker-traversable"):
            self.prepare(output, private_parent, private_parent / "old-child")
        self.assertFalse((private_parent / "old-child").exists())

    def test_missing_relative_traversal_root_and_unsafe_modes_reject_before_dispatch(self):
        candidates = (None, "relative", str(self.parent / ".." / self.parent.name), "/")
        for value in candidates:
            with self.subTest(parent=value), patch.object(DISPATCH.subprocess, "run") as invocation:
                env = self.environment.copy()
                if value is None:
                    env.pop("NGINX_DOCROOT_PROJECTION_PARENT")
                else:
                    env["NGINX_DOCROOT_PROJECTION_PARENT"] = value
                with self.assertRaises((KeyError, ValueError, OSError)):
                    DISPATCH.run(env)
                invocation.assert_not_called()
                self.assertFalse((self.build / "host-runtime").exists())
        for mode in (0o700, 0o755, 0o777):
            self.parent.chmod(mode)
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                DISPATCH.projection_parent(self.environment, self.build, self.results, self.framework)

    def test_symlink_and_overlap_are_rejected_without_changing_authorities(self):
        link = self.base / "projection-link"
        link.symlink_to(self.parent, target_is_directory=True)
        candidates = [link, self.base, self.private, self.build, self.results, self.framework, ROOT]
        for parent in candidates:
            env = self.environment | {"NGINX_DOCROOT_PROJECTION_PARENT": str(parent)}
            with self.subTest(parent=parent), self.assertRaises((ValueError, OSError)):
                DISPATCH.projection_parent(env, self.build, self.results, self.framework)
        for key in ("VERIFIED_RUN_ROOT", "CACHE_ROOT", "EVIDENCE_ROOT", "LOG_ROOT", "RUN_ROOT"):
            env = self.environment | {key: str(self.parent)}
            with self.subTest(authority=key), self.assertRaises(ValueError):
                DISPATCH.projection_parent(env, self.build, self.results, self.framework)
        self.assertEqual(stat.S_IMODE(self.parent.stat().st_mode), 0o711)
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_missing_verified_root_and_nonroot_coordinator_are_rejected(self):
        environment = self.environment.copy()
        environment.pop("VERIFIED_RUN_ROOT")
        with self.assertRaisesRegex(ValueError, "explicit VERIFIED_RUN_ROOT"):
            DISPATCH.projection_parent(environment, self.build, self.results, self.framework)
        with patch.object(DISPATCH.os, "geteuid", return_value=1000), \
             self.assertRaisesRegex(ValueError, "actual Root coordinator"):
            DISPATCH.projection_parent(self.environment, self.build, self.results, self.framework)

    def test_all_nonraw_commands_preserve_the_exact_shared_parent_and_global_run(self):
        identities = {key: "a" * 40 for key in ("parent_sha", "framework_sha", "mrts_sha")}
        paths = {"prefix": self.base / "prefix", "framework": self.framework,
                 "output": self.build / "not-created", "projection": self.parent}
        environment = {key: str(self.base / "fixture.so") for key in DISPATCH.FAULT_ENV.values()}
        for case in DISPATCH.CONTRACTS:
            with self.subTest(case=case):
                argv = DISPATCH.command(case, paths, "projection-run", identities, environment)
                self.assertEqual(argv[argv.index("--run-id") + 1], "projection-run")
                if case in DISPATCH.RAW:
                    self.assertNotIn("--projection-parent", argv)
                else:
                    self.assertEqual(argv[argv.index("--projection-parent") + 1], str(self.parent))

    def test_existing_separate_firstbyte_child_remains_untouched(self):
        seed = self.build / "firstbyte-private"
        seed.mkdir(mode=0o700)
        firstbyte = self.prepare(seed, self.parent, self.parent / "firstbyte-independent")
        retained = {name: (firstbyte / name).read_bytes() for name in PROJECTOR.PROJECTED_FILENAMES}
        with patch.object(DISPATCH, "identity", return_value="a" * 40), \
             patch.object(DISPATCH.subprocess, "run", side_effect=self.driver):
            self.assertEqual(DISPATCH.run(self.environment), 0)
        self.assertTrue(all(projected != firstbyte for projected in self.projections))
        self.assertEqual({name: (firstbyte / name).read_bytes() for name in PROJECTOR.PROJECTED_FILENAMES}, retained)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
