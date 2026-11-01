"""Pure closed-dispatch/security checks; no NGINX process is started."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import importlib.util
from copy import deepcopy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

ROOT = connector_root()
SOURCE_SEAL = {"parent:fixture.py": "b" * 64}


def load(leaf):
    module = load_source(source_path('ci/runtime/lifecycle', root=ROOT) / leaf)
    return module


class DispatcherTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.driver = load("run-selected-nginx-native-operations.py")
        cls.source = load("nginx-native-operation-source.py")

    def test_closed_registry_and_selection(self):
        d = self.driver
        self.assertEqual(len(d.CONTRACTS), 42)
        rows = [{"case_id": key, "native_invocations": {"nginx": value}}
                for key, value in d.CONTRACTS.items()]
        self.assertEqual(len(d.selected_invocations(rows, list(d.CONTRACTS))), 42)
        self.assertEqual(d.selected_invocations(rows, ["allow_without_marker"]), [])
        for missing in ([], [{"case_id": "single_request_cleanup"}]):
            with self.assertRaises(ValueError):
                d.selected_invocations(missing, ["single_request_cleanup"])
        for changed in ({"operation": "arbitrary", "contract_case_id": rows[0]["case_id"]},
                        dict(rows[0]["native_invocations"]["nginx"], command="evil")):
            with self.assertRaises(ValueError):
                d.selected_invocations([dict(rows[0], native_invocations={"nginx": changed})], [rows[0]["case_id"]])
        for selection in (["../evil"], ["single_request_cleanup"] * 2):
            with self.assertRaises(ValueError):
                d.selected_invocations(rows, selection)

    def test_current_native_phase_and_clean_shutdown_overrides(self):
        expected = {
            "body_size_nonzero_with_null_data": {"phase": 1, "expected_status": 500},
            "engine_timeout_before_commit": {"phase": 1, "expected_status": 504, "expected_rule_id": None,
                                             "expected_native_status": 504, "expected_engine_error_class": "engine_timeout"},
            "clean_shutdown": {"expected_status": 200},
        }
        for case, overrides in expected.items():
            with self.subTest(case=case):
                descriptor = {"operation": "common_mapper_input_fault" if case.startswith("body_size_") else "request_sequence",
                              "contract_case_id": case, "expected_overrides": overrides}
                self.assertEqual(self.driver.CONTRACTS[case], descriptor)
                row = {"case_id": case, "native_invocations": {"nginx": descriptor}}
                self.assertEqual(self.driver.selected_invocations([row], [case]), [case])
                degraded = deepcopy(descriptor)
                degraded["expected_overrides"].pop("phase" if "phase" in overrides else "expected_status")
                wrong = deepcopy(descriptor)
                wrong["expected_overrides"]["phase" if "phase" in overrides else "expected_status"] = 4 if "phase" in overrides else 0
                boolean = deepcopy(descriptor)
                boolean["expected_overrides"]["phase" if "phase" in overrides else "expected_status"] = True
                for changed in (degraded, wrong, boolean):
                    with self.assertRaises(ValueError):
                        self.driver.selected_invocations([{"case_id": case, "native_invocations": {"nginx": changed}}], [case])

    def test_exact_current_framework_registry_selects_all42(self):
        framework = Path(os.environ.get("NGINX_NATIVE_REGISTRY_FRAMEWORK_ROOT", source_path('modules/ModSecurity-test-Framework', root=ROOT)))
        catalog = framework / "tests/cases/no-crs-baseline/catalog.json"
        if not catalog.is_file():
            self.skipTest("current Framework registry checkout or explicit NGINX_NATIVE_REGISTRY_FRAMEWORK_ROOT required")
        rows = [row for row in json.loads(catalog.read_text())["cases"] if "nginx" in row.get("native_invocations", {})]
        self.assertEqual(len(rows), 42)
        self.assertEqual(set(self.driver.selected_invocations(rows, [row["case_id"] for row in rows])), set(self.driver.CONTRACTS))

    def test_actual_closed_command_and_fault_requirements(self):
        d = self.driver
        paths = dict(prefix=Path("/native"), framework=Path("/framework"), output=Path("/owned/out"),
                     projection=Path("/owned/projection"))
        identities = {key: "a" * 40 for key in ("parent_sha", "framework_sha", "mrts_sha")}
        for case, envkey in d.FAULT_ENV.items():
            with self.assertRaises(ValueError):
                d.command(case, paths, "run", identities, {})
            args = d.command(case, paths, "run", identities, {envkey: "/owned/fault.so"})
            self.assertIn("--fault-library", args)
            self.assertNotIn("--fault-negative-control", args)
        for case in d.CONTRACTS:
            args = d.command(case, paths, "run", identities,
                             {key: "/owned/fault.so" for key in d.FAULT_ENV.values()})
            self.assertEqual(args[args.index("--case-id") + 1], case)
            if case not in d.RAW:
                self.assertIn("--projection-parent", args)

    def test_source_preserves_bytes_and_never_passes(self):
        s = self.source
        with tempfile.TemporaryDirectory(prefix="dispatch-test-", dir="/var/tmp/codex/ModSecurity-conector") as temporary:
            root = Path(temporary)
            identity = {key: "a" * 40 for key in ("parent_sha", "framework_sha", "mrts_sha")}
            receipt = dict(identity, case_id="single_request_cleanup", run_id="run", operation="request_sequence")
            raw = json.dumps({"cases": [{"case_id": receipt["case_id"], "run_id": "run",
                              "operation": "request_sequence", "sequence_receipt": receipt}]}).encode()
            leaf = root / "sequence-source.json"
            leaf.write_bytes(raw)
            leaf.chmod(0o600)
            row = s.build_source(receipt["case_id"], "run", "request_sequence", root, identity, 7,
                                 source_sha256=SOURCE_SEAL)
            self.assertEqual(row["status"], "NOT_EXECUTED")
            self.assertEqual(row["driver_exit_code"], 7)
            self.assertEqual(leaf.read_bytes(), raw)
            self.assertEqual(row["native_operation_receipt"]["invocations"][0]["receipt_path"], leaf.name)
            conflicting = dict(identity, case_id='foreign')
            with self.assertRaises(TypeError):
                s.build_source(receipt["case_id"], "run", "request_sequence", root, conflicting, 0,
                               source_sha256=SOURCE_SEAL)
            leaf.unlink()
            leaf.symlink_to(root / "absent")
            with self.assertRaises((OSError, ValueError)):
                s.build_source(receipt["case_id"], "run", "request_sequence", root, identity, 0,
                               source_sha256=SOURCE_SEAL)

    def test_source_json_and_identity_rejections_keep_diagnostic_order(self):
        source = self.source
        for raw, message in [(b'{"x":1,"x":2}', 'duplicate source JSON key'),
                             (b'{"x":NaN}', 'invalid JSON number'),
                             (b'{"x":Infinity}', 'invalid JSON number')]:
            with self.subTest(raw=raw), self.assertRaisesRegex(ValueError, '^' + message + '$'):
                source.decode(raw)
        identity = {key: 'a' * 40 for key in ('parent_sha', 'framework_sha', 'mrts_sha')}
        for case, run, revisions, exit_code, seals, message in [
                ('../case', 'run', identity, 0, SOURCE_SEAL, 'invalid source identity or actual driver exit'),
                ('case', 'run', identity, True, SOURCE_SEAL, 'invalid source identity or actual driver exit'),
                ('case', 'run', {}, 0, SOURCE_SEAL, 'source identities require exact Git SHAs'),
                ('case', 'run', identity, 0, {}, 'actual namespaced source SHA seals required')]:
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, '^' + message + '$'):
                source.build_source(case, run, 'request_sequence', Path('/nonexistent'), revisions,
                                    exit_code, source_sha256=seals)

    def test_fixed_source_storage_is_policy_exact_and_environment_independent(self):
        with patch.dict(os.environ, {'TMPDIR': '/foreign', 'TEMP': '/foreign', 'RUNNER_TEMP': '/foreign'}):
            source = load('nginx-native-operation-source.py')
        self.assertEqual(source.STORAGE, Path('/var/tmp/codex/ModSecurity-conector'))

    def test_owned_read_rejects_links_and_permissions(self):
        s = self.source
        with tempfile.TemporaryDirectory(prefix="dispatch-test-", dir="/var/tmp/codex/ModSecurity-conector") as temporary:
            root = Path(temporary)
            leaf = root / "raw.json"
            leaf.write_bytes(b"{}")
            leaf.chmod(0o600)
            self.assertEqual(s.read_owned(root, "raw.json"), b"{}")
            os.link(leaf, root / "other")
            with self.assertRaises(ValueError):
                s.read_owned(root, "raw.json")
            (root / "other").unlink()
            leaf.chmod(0o644)
            with self.assertRaises(ValueError):
                s.read_owned(root, "raw.json")
            for path in ("../raw.json", "/raw.json", "a//raw.json"):
                with self.assertRaises(ValueError):
                    s.read_owned(root, path)

    def test_event_children_are_independent_and_parent_sealed(self):
        s = self.source
        with tempfile.TemporaryDirectory(prefix="dispatch-test-", dir="/var/tmp/codex/ModSecurity-conector") as temporary:
            root = Path(temporary)
            identity = {key: "a" * 40 for key in ("parent_sha", "framework_sha", "mrts_sha")}
            base = dict(identity, case_id="event_json_limit", operation="native_event_boundary_request")
            children = []
            for variant in ("at255", "over256"):
                (root / variant).mkdir(mode=0o700)
                raw = json.dumps(dict(base, run_id="run-" + variant)).encode()
                leaf = root / variant / "source-result.json"
                leaf.write_bytes(raw)
                leaf.chmod(0o600)
                children.append(dict(variant=variant, directory=variant, run_id="run-" + variant,
                                     receipt_sha256=s.digest(raw)))
            parent = root / "source-result.json"
            parent.write_text(json.dumps(dict(base, run_id="run", children=children)))
            parent.chmod(0o600)
            row = s.build_source(base["case_id"], "run", base["operation"], root, identity, 0,
                                 source_sha256=SOURCE_SEAL)
            wrapper = row["native_operation_receipt"]
            self.assertEqual([item["name"] for item in wrapper["invocations"]], ["at", "over"])
            self.assertEqual(wrapper["parent_receipt_sha256"], s.digest(parent.read_bytes()))
            (root / "at255/source-result.json").write_bytes((root / "over256/source-result.json").read_bytes())
            with self.assertRaises(ValueError):
                s.build_source(base["case_id"], "run", base["operation"], root, identity, 0,
                               source_sha256=SOURCE_SEAL)

    def test_result_append_preserves_other_cases_and_rejects_duplicates(self):
        d = self.driver
        with tempfile.TemporaryDirectory(prefix="dispatch-test-", dir="/var/tmp/codex/ModSecurity-conector") as temporary:
            result = Path(temporary) / "nginx-results.jsonl"
            previous = b'{"case_id":"allow_without_marker","status":"PASS"}\n'
            result.write_bytes(previous)
            result.chmod(0o600)
            self.assertEqual(d.append_results(result, ["single_request_cleanup"], lambda case:
                {"case_id": case, "status": "NOT_EXECUTED", "driver_exit_code": 4}), 1)
            self.assertTrue(result.read_bytes().startswith(previous))
            retained = result.read_bytes()
            with self.assertRaises(ValueError):
                d.append_results(result, ["single_request_cleanup"], lambda _: self.fail("must not invoke"))
            self.assertEqual(result.read_bytes(), retained)
            result.chmod(0o644)
            with self.assertRaises(ValueError):
                d.append_results(result, ["new_case"], lambda _: self.fail("must not invoke"))

    def test_source_hash_whitelist_and_symlink_denial(self):
        s = self.source
        with tempfile.TemporaryDirectory(prefix="dispatch-test-", dir="/var/tmp/codex/ModSecurity-conector") as temporary:
            root = Path(temporary)
            leaf = root / "source.py"
            leaf.write_bytes(b"actual-source")
            self.assertEqual(s.source_hashes({"parent:source.py"}, root, root),
                             {"parent:source.py": s.digest(b"actual-source")})
            for bad in ("parent:../source.py", "other:source.py", "parent:/source.py"):
                with self.assertRaises(ValueError):
                    s.source_hashes({bad}, root, root)
            leaf.unlink()
            leaf.symlink_to(root / "absent")
            with self.assertRaises(OSError):
                s.source_hashes({"parent:source.py"}, root, root)

            intermediate = root / "ci"
            nested = intermediate / "lib/source.py"
            nested.parent.mkdir(parents=True, mode=0o700)
            nested.write_bytes(b"bounded nested source")
            intermediate.chmod(0o770)
            with self.subTest(boundary="group writable intermediate"), self.assertRaises(ValueError):
                s.source_hashes({"parent:ci/lib/source.py"}, root, root)
            intermediate.chmod(0o700)
            original_fstat = os.fstat
            identity = intermediate.stat()
            def foreign_intermediate(descriptor):
                metadata = original_fstat(descriptor)
                if (metadata.st_dev, metadata.st_ino) == (identity.st_dev, identity.st_ino):
                    return SimpleNamespace(st_mode=metadata.st_mode, st_uid=os.geteuid() + 1)
                return metadata
            with self.subTest(boundary="foreign owned intermediate"), \
                    patch.object(s.os, "fstat", side_effect=foreign_intermediate), self.assertRaises(ValueError):
                s.source_hashes({"parent:ci/lib/source.py"}, root, root)

    def test_dispatch_orchestration_retains_actual_exit_and_fresh_outputs(self):
        d = self.driver
        with tempfile.TemporaryDirectory(prefix="dispatch-test-", dir="/var/tmp/codex/ModSecurity-conector") as temporary:
            root = Path(temporary)
            framework = root / "framework"
            catalog_dir = framework / "tests/cases/no-crs-baseline"
            catalog_dir.mkdir(parents=True, mode=0o700)
            cases = ["invalid_content_length", "content_length_overflow"]
            (catalog_dir / "catalog.json").write_text(json.dumps({"cases": [
                {"case_id": case, "native_invocations": {"nginx": d.CONTRACTS[case]}} for case in cases]}))
            runners = framework / "tests/runners"
            runners.mkdir(mode=0o700)
            reviewed_reader = test_root() / "tests/runners/nginx_native_operation_bundle.py"
            reader = load_source(reviewed_reader)
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            for name in set().union(*(reader.required_source_paths(case) for case in cases)):
                owner, relative = name.split(":", 1)
                original = (source_path(relative, root=ROOT) if owner == "parent"
                            else test_root() / relative)
                copy = (parent if owner == "parent" else framework) / relative
                copy.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                copy.write_bytes(original.read_bytes())
            fixture_reader = runners / "nginx_native_operation_bundle.py"
            def reviewed_reader_api(path):
                self.assertEqual(path, fixture_reader)
                self.assertEqual(path.read_bytes(), reviewed_reader.read_bytes())
                return reader
            build = root / "build"
            build.mkdir(mode=0o700)
            results = build / "results"
            results.mkdir(mode=0o700)
            environment = dict(FRAMEWORK_ROOT=str(framework), BUILD_ROOT=str(build), RESULTS_DIR=str(results),
                NGINX_PREFIX=str(root / "prefix"), NO_CRS_RUN_ID="test-run", NO_CRS_SELECTED_CASE_IDS=" ".join(cases))
            commands = []
            def actual_command(args, **kwargs):
                commands.append(args)
                output = Path(args[args.index("--output-root") + 1])
                output.mkdir(mode=0o700)
                case = args[args.index("--case-id") + 1]
                receipt = dict(case_id=case, run_id="test-run", operation="native_h1_parser_rejection",
                               parent_sha="a" * 40, framework_sha="a" * 40, mrts_sha="a" * 40)
                path = output / "source-result.json"
                path.write_text(json.dumps(receipt))
                path.chmod(0o600)
                return SimpleNamespace(returncode=7 if len(commands) == 1 else 0)
            with patch.object(d, "ROOT", parent), \
                    patch.object(d, "load_source", side_effect=reviewed_reader_api), \
                    patch.object(d, "identity", return_value="a" * 40), \
                    patch.object(d.subprocess, "run", side_effect=actual_command):
                self.assertEqual(d.run(environment), 1)
                with self.assertRaises(FileExistsError):
                    d.run(environment)
            self.assertEqual(len(commands), 2)
            rows = [json.loads(line) for line in (results / "nginx-results.jsonl").read_text().splitlines()]
            self.assertEqual([row["driver_exit_code"] for row in rows], [7, 0])
            self.assertEqual({row["status"] for row in rows}, {"NOT_EXECUTED"})
            self.assertEqual(len({row["native_operation_receipt"]["bundle_root"] for row in rows}), 2)
            self.assertTrue(all(row["native_operation_receipt"]["source_sha256"] for row in rows))



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
