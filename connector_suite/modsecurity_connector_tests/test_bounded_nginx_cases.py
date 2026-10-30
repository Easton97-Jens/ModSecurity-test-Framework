"""Contracts for complete ordinary NGINX Functional-A case coordination."""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import importlib.util
from contextlib import contextmanager
import json
import os
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = connector_root()
COORDINATOR = load_source(source_path('ci/runtime/lifecycle/run-bounded-nginx-cases.py', root=ROOT))


def record(case, variant="no-crs", **changes):
    value = {"path": str(case), "name": case.stem, "scope": "common", "executed_connector": "nginx",
             "variant": variant, "status": "pass", "operation_status": "ok", "live_executed": True,
             "expected_status": 200, "actual_status": 200, "observed_transport_result": "http_status"}
    value.update(changes)
    return value


class BoundedNginxCasesTests(unittest.TestCase):
    @contextmanager
    def simulated_root_log(self, case_root, *, uid=0, gid=0):
        # CI runs these filesystem/process tests without root. Simulate only
        # privileged ownership; file kind, modes, size and no-follow I/O stay real.
        original_fstat = os.fstat
        fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        def metadata(descriptor):
            actual = original_fstat(descriptor)
            values = {key: getattr(actual, key) for key in fields}
            return SimpleNamespace(**values, st_uid=uid, st_gid=gid)
        with mock.patch.object(COORDINATOR, "contained_directory", return_value=case_root), mock.patch.object(COORDINATOR.os, "fstat", side_effect=metadata):
            yield

    def test_missing_record_retains_real_exit_and_private_escaped_harness_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            case_root = root / "case-000"
            receipt = root / "receipt"
            case_root.mkdir(mode=0o711)
            receipt.mkdir(mode=0o700)
            harness = root / "harness.sh"
            harness.write_text("printf 'native setup blocked\\n'\nprintf '\\033[31m::error::payload\\n' >&2\nexit 77\n")
            case = COORDINATOR.FRAMEWORK / "tests/cases/request/headers/phase1_header_block.yaml"
            environment = dict(COORDINATOR.SAFE_ENV)
            deadline = time.monotonic() + 10
            owner = os.geteuid()
            group = os.getegid()
            with self.simulated_root_log(case_root), mock.patch.object(COORDINATOR, "HARNESS", harness):
                with self.assertRaisesRegex(COORDINATOR.CaseRunError, "native harness exit=77; private diagnostic:"):
                    COORDINATOR.execute_case_record(case, case_root, environment, deadline,
                                                    receipt, "no-crs", 0, "a" * 40, owner, group)
            target = receipt / "case-000-failure.json"
            body = target.read_bytes()
            diagnostic = json.loads(body)
            self.assertEqual(diagnostic["harness_exit"], 77)
            self.assertEqual(diagnostic["parent_sha"], "a" * 40)
            self.assertIn("native setup blocked", diagnostic["harness_output"])
            self.assertNotIn(b"\x1b", body)
            self.assertNotIn("status", diagnostic)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertEqual(target.stat().st_uid, os.geteuid())
            self.assertLessEqual(len(body), COORDINATOR.MAX_RECORD_BYTES)
            self.assertFalse((receipt / "case-000.json").exists())

    def test_failure_log_rejects_symlink_fifo_hardlink_permissions_and_oversize(self):
        for kind in ("symlink", "fifo", "hardlink", "public", "oversize"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                case_root = root / "case-000"
                receipt = root / "receipt"
                case_root.mkdir(mode=0o711)
                receipt.mkdir(mode=0o700)
                log = case_root / "harness-output.log"
                if kind == "fifo":
                    os.mkfifo(log, 0o600)
                elif kind == "symlink":
                    log.symlink_to(root / "outside")
                else:
                    log.write_bytes(b"x" * (COORDINATOR.MAX_RECORD_BYTES + 1) if kind == "oversize" else b"failure")
                    log.chmod(0o644 if kind == "public" else 0o600)
                    if kind == "hardlink":
                        os.link(log, root / "alias")
                case = COORDINATOR.FRAMEWORK / "tests/cases/fixture.yaml"
                owner = os.geteuid()
                group = os.getegid()
                with self.simulated_root_log(case_root), self.assertRaises(ValueError):
                    COORDINATOR.project_case_failure(case_root, receipt, case,
                                                     "no-crs", 0, 77, "a" * 40, owner, group)
                self.assertEqual(list(receipt.iterdir()), [])

    def test_failure_log_rejects_nonroot_owner_and_group(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            log = root / "harness-output.log"
            log.write_bytes(b"failure")
            log.chmod(0o600)
            case = COORDINATOR.FRAMEWORK / "tests/cases/fixture.yaml"
            owner = os.geteuid()
            group = os.getegid()
            for uid, gid in ((1001, 0), (0, 1001)):
                with self.subTest(uid=uid, gid=gid), self.simulated_root_log(root, uid=uid, gid=gid), self.assertRaises(COORDINATOR.CaseRunError):
                    COORDINATOR.project_case_failure(root, root, case,
                                                     "no-crs", 0, 77, "a" * 40, owner, group)

    def test_failure_projection_bounds_payload_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            log = root / "harness-output.log"
            log.write_bytes(b"\x00" * COORDINATOR.MAX_RECORD_BYTES)
            log.chmod(0o600)
            case = COORDINATOR.FRAMEWORK / "tests/cases/fixture.yaml"
            owner = os.geteuid()
            group = os.getegid()
            with self.simulated_root_log(root):
                target = COORDINATOR.project_case_failure(root, root, case, "no-crs", 0, 1, "a" * 40, owner, group)
                with self.assertRaises(FileExistsError):
                    COORDINATOR.project_case_failure(root, root, case, "no-crs", 0, 1, "a" * 40, owner, group)
            self.assertLessEqual(target.stat().st_size, COORDINATOR.MAX_RECORD_BYTES)
            self.assertTrue(json.loads(target.read_bytes())["excerpt_truncated"])

    def test_failure_log_metadata_change_rejected_before_projection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            log = root / "harness-output.log"
            log.write_bytes(b"failure")
            log.chmod(0o600)
            actual = log.stat()
            fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
            values = {key: getattr(actual, key) for key in fields}
            before = SimpleNamespace(**values, st_uid=0, st_gid=0)
            changed = dict(values, st_mtime_ns=actual.st_mtime_ns + 1)
            after = SimpleNamespace(**changed, st_uid=0, st_gid=0)
            case = COORDINATOR.FRAMEWORK / "tests/cases/fixture.yaml"
            owner = os.geteuid()
            group = os.getegid()
            with mock.patch.object(COORDINATOR, "contained_directory", return_value=root), mock.patch.object(COORDINATOR.os, "fstat", side_effect=[before, after]):
                with self.assertRaisesRegex(COORDINATOR.CaseRunError, "changed during bounded projection"):
                    COORDINATOR.project_case_failure(root, root, case,
                                                     "no-crs", 0, 77, "a" * 40, owner, group)
            self.assertFalse((root / "case-000-failure.json").exists())

    def test_live_passing_record_remains_required_and_has_no_failure_projection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            case_root = root / "case-000"
            receipt = root / "receipt"
            case_root.mkdir(mode=0o711)
            receipt.mkdir(mode=0o700)
            harness = root / "harness.sh"
            harness.write_text('mkdir -p "$CASE_ROOT/harness/logs"\nprintf "%s\\n" "$RECORD_JSON" > "$CASE_ROOT/harness/logs/result.json"\n')
            case = COORDINATOR.FRAMEWORK / "tests/cases/request/headers/phase1_header_block.yaml"
            expected = record(case)
            environment = dict(COORDINATOR.SAFE_ENV, CASE_ROOT=str(case_root), RECORD_JSON=json.dumps(expected))
            with mock.patch.object(COORDINATOR, "HARNESS", harness):
                code, observed = COORDINATOR.execute_case_record(case, case_root, environment, time.monotonic() + 10,
                                                               receipt, "no-crs", 0, "a" * 40, os.geteuid(), os.getegid())
            self.assertEqual(code, 0)
            self.assertEqual(observed, expected)
            self.assertEqual(list(receipt.iterdir()), [])

    def test_native_complete_catalog_counts_and_variants(self):
        for variant, count in (("no-crs", 60), ("with-crs", 61)):
            with self.subTest(variant=variant):
                cases = COORDINATOR.discover_cases(variant)
                self.assertEqual(len(cases), count)
                self.assertEqual(len(set(cases)), count)
                self.assertEqual(len(COORDINATOR.catalog_digest(cases)), 64)

    def test_discovery_clears_ambient_catalog_selectors(self):
        with mock.patch.dict(os.environ, {"FORCE_ALL_CASES": "1", "NO_CRS_BASELINE": "1", "LD_PRELOAD": "evil"}):
            env = COORDINATOR.native_environment("no-crs")
        self.assertEqual(env["FORCE_ALL_CASES"], "")
        self.assertEqual(env["NO_CRS_BASELINE"], "")
        self.assertNotIn("LD_PRELOAD", env)

    def test_discovery_rejects_wrong_count_duplicate_and_escaping_case(self):
        safe = COORDINATOR.FRAMEWORK / "tests/cases/request/headers/phase1_header_block.yaml"
        for cases in ([safe], [safe] * 60,
                      [COORDINATOR.FRAMEWORK / "tests/cases" / f"case-{index}.yaml" for index in range(59)] + [Path("/etc/passwd.yaml")]):
            with self.subTest(cases=cases[-1]), mock.patch.object(COORDINATOR, "run_fixed", return_value=("\n".join(map(str, cases)) + "\n").encode()), mock.patch.object(COORDINATOR, "regular_bytes", return_value=b"name: fixture"):
                with self.assertRaises((COORDINATOR.CaseRunError, COORDINATOR.LAUNCHER.FunctionalALaunchError)):
                    COORDINATOR.discover_cases("no-crs")

    def test_regular_input_refuses_symlink_hardlink_and_oversize(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.write_bytes(b"fixture")
            symlink = root / "symlink"
            symlink.symlink_to(source)
            with self.assertRaises(COORDINATOR.LAUNCHER.FunctionalALaunchError):
                COORDINATOR.regular_bytes(symlink)
            with self.assertRaises(COORDINATOR.CaseRunError):
                COORDINATOR.regular_bytes(source, limit=3)
            os.link(source, root / "alias")
            with self.assertRaises(COORDINATOR.CaseRunError):
                COORDINATOR.regular_bytes(source)

    def test_case_environment_keeps_fixed_entry_and_private_paths(self):
        case = COORDINATOR.FRAMEWORK / "tests/cases/request/headers/phase1_header_block.yaml"
        values = COORDINATOR.case_environment({"LD_PRELOAD": "evil", "PYTHONPATH": "evil", "BASH_ENV": "evil",
                                               "PYTHON": "/evil/python", "CURL": "/evil/curl", "TEST_CASE": "/evil/case"},
                                              case, Path("/private/cases/case-000"), 0)
        self.assertEqual(values["TEST_CASE"], str(case))
        self.assertEqual(values["PYTHON"], "/usr/bin/python3")
        self.assertEqual(values["CURL"], "/usr/bin/curl")
        self.assertEqual(values["RUN_ONE_CASE"], "1")
        self.assertEqual(values["NGINX_HOSTED_FUNCTIONAL_A"], "1")
        self.assertEqual(values["LOG_DIR"], "/private/cases/case-000/harness/logs")
        for key in ("LD_PRELOAD", "PYTHONPATH", "BASH_ENV"):
            self.assertNotIn(key, values)

    def test_closed_cli_rejects_generic_commands_paths_and_variants(self):
        for arguments in (["--variant", "other"], ["--variant", "no-crs", "--command", "id"],
                          ["--variant", "no-crs", "--framework-root", "/foreign"],
                          ["--variant", "no-crs", "--test-case", "/foreign"]):
            with self.subTest(arguments=arguments), self.assertRaises(SystemExit):
                COORDINATOR.main(arguments)

    def test_decode_rejects_wrong_path_variant_missing_live_and_http_mismatch(self):
        case = Path("/fixture/case.yaml")
        for changed in ({"path": "/other/case.yaml"}, {"variant": "with-crs"}, {"live_executed": False},
                        {"executed_connector": "apache"}, {"actual_status": None}, {"actual_status": 403},
                        {"operation_status": "error"}, {"status": "fail"}):
            body = json.dumps(record(case, **changed)).encode()
            with self.subTest(changed=changed), self.assertRaises(COORDINATOR.CaseRunError):
                COORDINATOR.decode_record(body, case, "no-crs", 0)
        self.assertEqual(COORDINATOR.decode_record(json.dumps(record(case)).encode(), case, "no-crs", 0)["status"], "pass")

    def test_native_duplicate_json_keys_rejected(self):
        with self.assertRaises(COORDINATOR.CaseRunError):
            COORDINATOR.decode_record(b"{\"status\":\"pass\",\"status\":\"pass\"}", Path("/fixture/case.yaml"), "no-crs", 0)

    def fixture_receipts(self, root, cases):
        for index, case in enumerate(cases):
            value = record(case, catalog_case=str(case.relative_to(COORDINATOR.FRAMEWORK)))
            target = root / f"case-{index:03d}.json"
            target.write_text(json.dumps(value))
            target.chmod(0o600)

    def test_receipts_require_exact_complete_catalog_and_case_identity(self):
        cases = [COORDINATOR.FRAMEWORK / "tests/cases/request/headers/phase1_header_block.yaml"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(COORDINATOR.CaseRunError):
                COORDINATOR.complete_records(root, cases, "no-crs")
            self.fixture_receipts(root, cases)
            self.assertEqual(len(COORDINATOR.complete_records(root, cases, "no-crs")), 1)
            (root / "extra.json").write_text("{}")
            with self.assertRaises(COORDINATOR.CaseRunError):
                COORDINATOR.complete_records(root, cases, "no-crs")
            (root / "extra.json").unlink()
            target = root / "case-000.json"
            value = json.loads(target.read_text())
            value["catalog_case"] = "tests/cases/other.yaml"
            target.write_text(json.dumps(value))
            with self.assertRaises(COORDINATOR.CaseRunError):
                COORDINATOR.complete_records(root, cases, "no-crs")

    def test_receipt_mode_and_symlink_changes_rejected(self):
        cases = [COORDINATOR.FRAMEWORK / "tests/cases/request/headers/phase1_header_block.yaml"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture_receipts(root, cases)
            target = root / "case-000.json"
            target.chmod(0o644)
            with self.assertRaises(COORDINATOR.CaseRunError):
                COORDINATOR.complete_records(root, cases, "no-crs")
            target.chmod(0o600)
            outside = root.parent / (root.name + "-outside")
            try:
                outside.write_bytes(target.read_bytes())
                outside.chmod(0o600)
                target.unlink()
                target.symlink_to(outside)
                with self.assertRaises((COORDINATOR.CaseRunError, COORDINATOR.LAUNCHER.FunctionalALaunchError)):
                    COORDINATOR.complete_records(root, cases, "no-crs")
            finally:
                outside.unlink()

    def test_fresh_projection_never_overwrites_existing_file_or_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "record.json"
            owner = os.geteuid()
            group = os.getegid()
            COORDINATOR.write_fresh(target, b"original", owner=owner, group=group)
            with self.assertRaises(FileExistsError):
                COORDINATOR.write_fresh(target, b"replacement", owner=owner, group=group)
            self.assertEqual(target.read_bytes(), b"original")
            link = root / "link"
            link.symlink_to(target)
            with self.assertRaises(FileExistsError):
                COORDINATOR.write_fresh(link, b"replacement", owner=owner, group=group)
            self.assertEqual(target.read_bytes(), b"original")

    def test_committed_input_failure_stops_before_privileged_execution(self):
        with mock.patch.object(COORDINATOR.os, "geteuid", return_value=1001), mock.patch.dict(os.environ, {"EXPECTED_PARENT_SHA": "a" * 40}), mock.patch.object(COORDINATOR, "verify_committed_inputs", side_effect=COORDINATOR.CaseRunError("identity mismatch")), mock.patch.object(COORDINATOR.subprocess, "run") as execute:
            self.assertEqual(COORDINATOR.main(["--variant", "no-crs"]), 1)
            execute.assert_not_called()

    def test_root_entry_rejects_nonroot_and_variant_mismatch(self):
        with mock.patch.object(COORDINATOR.os, "geteuid", return_value=1001), self.assertRaises(COORDINATOR.CaseRunError):
            COORDINATOR.root_runtime({}, "no-crs")
        with mock.patch.object(COORDINATOR.os, "geteuid", return_value=0), self.assertRaises(COORDINATOR.CaseRunError):
            COORDINATOR.root_runtime({"MODSECURITY_TEST_VARIANT": "with-crs"}, "no-crs")

    def test_root_command_uses_clean_fixed_sudo_handoff(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build = root / "build"
            source = root / "source"
            build.mkdir()
            source.mkdir()
            values = dict(COORDINATOR.SAFE_ENV, NGINX_WORKER_USER="nobody", NGINX_WORKER_GROUP="nogroup", NGINX_BINARY="/fixed/nginx")
            base = ["/usr/bin/sudo", "-n", "/usr/bin/env", "-i", *[f"{key}={value}" for key, value in values.items()], "/bin/sh", "/fixed/script"]
            with mock.patch.object(COORDINATOR.LAUNCHER, "build_root_command", return_value=base), mock.patch.object(COORDINATOR, "runtime_digest", return_value="1" * 64), mock.patch.object(COORDINATOR, "catalog_digest", return_value="2" * 64):
                command = COORDINATOR.build_root_command({"VERIFIED_RUN_ROOT": str(root), "BUILD_ROOT": str(build), "SOURCE_ROOT": str(source), "SECRET": "must-not-cross"}, "no-crs", [])
            self.assertEqual(command[:4], ["/usr/bin/sudo", "-n", "/usr/bin/env", "-i"])
            self.assertEqual(command[-6:], ["/usr/bin/python3", "-I", str(source_path('ci/runtime/lifecycle/run-bounded-nginx-cases.py', root=ROOT)), "--root-runtime", "--variant", "no-crs"])
            self.assertFalse(any("SECRET" in item or "must-not-cross" in item for item in command))

    def test_invalid_root_variant_is_rejected_before_launcher_or_path_actions(self):
        with mock.patch.object(COORDINATOR.LAUNCHER, "build_root_command") as launcher:
            for variant in ("", "other", "--command=id", "no-crs\n", " with-crs"):
                with self.subTest(variant=variant), self.assertRaises(COORDINATOR.CaseRunError):
                    COORDINATOR.build_root_command({}, variant, [])
            launcher.assert_not_called()

    def test_native_summary_and_schema_validation_produce_complete_owned_receipt(self):
        cases = [COORDINATOR.FRAMEWORK / "tests/cases/request/headers/phase1_header_block.yaml"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            receipt = root / "receipt"
            results = root / "results"
            receipt.mkdir(mode=0o700)
            results.mkdir(mode=0o700)
            self.fixture_receipts(receipt, cases)
            (results / "apache.rc").write_text("0\n")
            env = {"VERIFIED_RUN_ROOT": str(root), "NGINX_FUNCTIONAL_A_EVIDENCE_ROOT": str(receipt),
                   "RESULTS_DIR": str(results), "NGINX_PREFIX": "/prepared/nginx", "MODSECURITY_LIB_DIR": "/prepared/lib"}
            COORDINATOR.summarize(env, cases, "no-crs")
            summary = json.loads((results / "nginx-summary.json").read_bytes())["nginx"]
            self.assertEqual(summary["attempted"], 1)
            self.assertEqual(summary["summary"]["pass"], 1)
            self.assertEqual((results / "nginx.rc").read_text(), "0\n")
            self.assertEqual((results / "apache.rc").read_text(), "0\n")
            with self.assertRaises(COORDINATOR.CaseRunError):
                COORDINATOR.summarize(env, cases, "no-crs")

    def test_summary_refuses_failed_or_absent_live_record(self):
        cases = [COORDINATOR.FRAMEWORK / "tests/cases/request/headers/phase1_header_block.yaml"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            receipt = root / "receipt"
            results = root / "results"
            receipt.mkdir(mode=0o700)
            results.mkdir(mode=0o700)
            self.fixture_receipts(receipt, cases)
            target = receipt / "case-000.json"
            value = json.loads(target.read_text())
            value["status"] = "fail"
            target.write_text(json.dumps(value))
            env = {"VERIFIED_RUN_ROOT": str(root), "NGINX_FUNCTIONAL_A_EVIDENCE_ROOT": str(receipt),
                   "RESULTS_DIR": str(results), "NGINX_PREFIX": "/prepared/nginx", "MODSECURITY_LIB_DIR": "/prepared/lib"}
            with self.assertRaises(COORDINATOR.CaseRunError):
                COORDINATOR.summarize(env, cases, "no-crs")
            self.assertEqual(list(results.iterdir()), [])

    def test_prepared_crs_source_and_literal_include_tree_are_bound(self):
        import re
        common = (COORDINATOR.FRAMEWORK / "ci/lib/common.sh").read_text()
        pins = {key: re.search(r"^" + key + r"=\"([^\"]+)\"$", common, re.MULTILINE).group(1)
                for key in ("CRS_APPROVED_REPO_URL", "CRS_APPROVED_COMMIT", "CRS_RELEASE_TAG")}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build = root / "build"
            source = root / "source"
            runtime = build / "crs"
            crs = source / "coreruleset"
            runtime.mkdir(parents=True)
            (crs / "rules").mkdir(parents=True)
            (crs / "crs-setup.conf.example").write_text("# pinned setup\n")
            (crs / "rules/REQUEST-TEST.conf").write_text("# pinned rule\n")
            setup = runtime / "crs-setup.conf"
            setup.write_text("# pinned setup\n")
            preamble = runtime / "modsecurity-crs-preamble.conf"
            body = ("# Generated by ci/provisioning/prepare-crs.sh. Do not edit.\n"
                    f"Include \"{setup}\"\nInclude \"{crs}/rules/*.conf\"\n")
            preamble.write_text(body)
            env = {"BOUNDED_INPUT_ROOT": str(root), "BOUNDED_BUILD_ROOT": str(build), "BOUNDED_SOURCE_ROOT": str(source)}
            def git_value(repository, *args):
                if args == ("rev-parse", "--show-toplevel"):
                    return (str(crs) + "\n").encode()
                if args == ("config", "--get", "remote.origin.url"):
                    return (pins["CRS_APPROVED_REPO_URL"] + "\n").encode()
                if args[0] == "rev-parse":
                    return (pins["CRS_APPROVED_COMMIT"] + "\n").encode()
                if args == ("ls-tree", "-r", "-z", "HEAD"):
                    return b"100644 blob " + b"a" * 40 + b"\tcrs-setup.conf.example\0" + b"100644 blob " + b"b" * 40 + b"\trules/REQUEST-TEST.conf\0"
                if args == ("cat-file", "blob", "a" * 40):
                    return b"# pinned setup\n"
                if args == ("cat-file", "blob", "b" * 40):
                    return b"# pinned rule\n"
                raise AssertionError(args)
            with mock.patch.object(COORDINATOR, "git_value", side_effect=git_value):
                original = COORDINATOR.crs_digest(env)
                self.assertEqual(len(original), 64)
                preamble.write_text(body + "Include \"/foreign/*.conf\"\n")
                with self.assertRaises(COORDINATOR.CaseRunError):
                    COORDINATOR.crs_digest(env)
                preamble.write_text(body)
                setup.write_text("# unreviewed setup\n")
                with self.assertRaises(COORDINATOR.CaseRunError):
                    COORDINATOR.crs_digest(env)
                setup.write_text("# pinned setup\n")
                rule = crs / "rules/REQUEST-TEST.conf"
                rule.unlink()
                rule.symlink_to(setup)
                with self.assertRaises((COORDINATOR.CaseRunError, COORDINATOR.LAUNCHER.FunctionalALaunchError)):
                    COORDINATOR.crs_digest(env)

    def test_clean_case_exit_does_not_require_terminating_a_live_group(self):
        with tempfile.TemporaryDirectory() as temporary:
            process = mock.Mock(pid=1234, returncode=0)
            process.wait.return_value = 0
            with mock.patch.object(COORDINATOR.subprocess, "Popen", return_value=process), mock.patch.object(COORDINATOR.GROUPS, "stop_group", return_value=False), mock.patch.object(COORDINATOR.GROUPS, "live_group_members", return_value=[]):
                self.assertEqual(COORDINATOR.run_case(Path("/fixed/case.yaml"), Path(temporary), {}, COORDINATOR.time.monotonic() + 10), 0)

    def test_successful_case_with_orphan_processes_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            case = Path("/fixed/case.yaml")
            case_root = Path(temporary)
            deadline = COORDINATOR.time.monotonic() + 10
            process = mock.Mock(pid=1234, returncode=0)
            process.wait.return_value = 0
            with mock.patch.object(COORDINATOR.subprocess, "Popen", return_value=process), mock.patch.object(COORDINATOR.GROUPS, "stop_group", return_value=True), mock.patch.object(COORDINATOR.GROUPS, "live_group_members", return_value=[]):
                with self.assertRaises(COORDINATOR.CaseRunError):
                    COORDINATOR.run_case(case, case_root, {}, deadline)

    def test_git_safe_directory_is_exact_and_provenance_uses_same_adapter(self):
        with mock.patch.object(COORDINATOR, "run_fixed", return_value=b"fixture") as run:
            COORDINATOR.git_value(COORDINATOR.FRAMEWORK, "rev-parse", "HEAD")
            command = run.call_args.args[0]
            self.assertIn("safe.directory=" + str(COORDINATOR.FRAMEWORK), command)
            self.assertNotIn("safe.directory=*", command)
            self.assertIn("core.fsmonitor=false", command)
        with mock.patch.object(COORDINATOR.PINS, "verify_framework_revision_pins"), mock.patch.object(COORDINATOR, "verify_source_blobs"):
            COORDINATOR.verify_committed_inputs("a" * 40)
            self.assertIs(COORDINATOR.PINS._git, COORDINATOR.git_value)

    def test_modified_transitive_runtime_path_helper_blocks_before_root_handoff(self):
        relative = Path("ci/lib/runtime_path_utils.py")
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            target = repository / relative
            target.parent.mkdir(parents=True)
            target.write_bytes(b"modified helper")
            with mock.patch.object(COORDINATOR, "source_tree", return_value=[("100644", "a" * 40, relative)]), mock.patch.object(COORDINATOR, "git_value", return_value=b"committed helper"):
                with self.assertRaises(COORDINATOR.CaseRunError):
                    COORDINATOR.verify_source_blobs(repository, ("ci/lib/runtime_path_utils.py",))
        with mock.patch.object(COORDINATOR.PINS, "verify_framework_revision_pins"), mock.patch.object(COORDINATOR, "verify_source_blobs") as verify:
            COORDINATOR.verify_committed_inputs("a" * 40)
            parent_call = verify.call_args_list[0]
            self.assertIn("ci/lib/runtime_path_utils.py", parent_call.args[1])

    def test_crs_include_tree_refuses_untracked_fifo_before_native_configuration(self):
        with tempfile.TemporaryDirectory() as temporary:
            rules = Path(temporary)
            safe = rules / "tracked.conf"
            safe.write_text("# pinned rule")
            fifo = rules / "extra.conf"
            os.mkfifo(fifo)
            with self.assertRaises(COORDINATOR.CaseRunError):
                COORDINATOR.validate_include_tree(rules, {safe})
            fifo.unlink()
            fifo.write_text("# ignored extra rule")
            with self.assertRaises(COORDINATOR.CaseRunError):
                COORDINATOR.validate_include_tree(rules, {safe})

    def test_case_group_is_terminated_on_native_timeout(self):
        with tempfile.TemporaryDirectory() as temporary:
            case_root = Path(temporary)
            case = Path("/fixed/case.yaml")
            deadline = COORDINATOR.time.monotonic() + 10
            process = mock.Mock(pid=1234)
            process.wait.side_effect = [COORDINATOR.subprocess.TimeoutExpired("fixed", 120), 0]
            with mock.patch.object(COORDINATOR.subprocess, "Popen", return_value=process), mock.patch.object(COORDINATOR.GROUPS, "stop_group", return_value=True) as stop:
                with self.assertRaises(COORDINATOR.CaseRunError):
                    COORDINATOR.run_case(case, case_root, {}, deadline)
                stop.assert_called_once_with(1234)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
