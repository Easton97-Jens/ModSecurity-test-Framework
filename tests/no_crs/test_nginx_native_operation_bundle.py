"""Unit controls for bounded retained-file authority; not native runtime proof."""
import importlib.util
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock
from tests.no_crs import test_nginx_common_input_faults as input_tests

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("native_bundle", ROOT / "tests/runners/nginx_native_operation_bundle.py")
assert SPEC is not None
assert SPEC.loader is not None
bundle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bundle)


class SecureBundleFileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="native-bundle-", dir=os.environ["TMPDIR"])
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.leaf = self.root / "receipt.json"
        self.leaf.write_bytes(b'{"value":1}')
        self.leaf.chmod(0o600)

    def test_exact_owned_regular_bytes(self):
        self.assertEqual(bundle.read_bounded_file(self.root, "receipt.json", 32), b'{"value":1}')

    def test_traversal_absolute_and_empty_paths_fail(self):
        for value in ("../receipt.json", str(self.leaf), "", "./receipt.json", "child//receipt.json"):
            with self.subTest(path=value), self.assertRaises(ValueError):
                bundle.read_bounded_file(self.root, value, 32)

    def test_final_and_directory_symlinks_fail(self):
        (self.root / "link").symlink_to(self.leaf)
        (self.root / "directory").symlink_to(self.root, target_is_directory=True)
        for value in ("link", "directory/receipt.json"):
            with self.subTest(path=value), self.assertRaises(ValueError):
                bundle.read_bounded_file(self.root, value, 32)

    def test_symlink_authority_ancestor_fails(self):
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            bundle.read_bounded_file(alias, "receipt.json", 32)

    def test_hardlink_writable_oversized_and_fifo_fail(self):
        os.link(self.leaf, self.root / "hardlink")
        with self.assertRaises(ValueError):
            bundle.read_bounded_file(self.root, "receipt.json", 32)
        (self.root / "hardlink").unlink()
        self.leaf.chmod(0o620)
        with self.assertRaises(ValueError):
            bundle.read_bounded_file(self.root, "receipt.json", 32)
        self.leaf.chmod(0o600)
        with self.assertRaises(ValueError):
            bundle.read_bounded_file(self.root, "receipt.json", 2)
        os.mkfifo(self.root / "fifo", 0o600)
        with self.assertRaises(ValueError):
            bundle.read_bounded_file(self.root, "fifo", 32)

    def test_writable_directory_and_foreign_owner_fail(self):
        child = self.root / "child"
        child.mkdir()
        (child / "receipt.json").write_bytes(b"{}")
        child.chmod(0o777)
        with self.assertRaises(ValueError):
            bundle.read_bounded_file(self.root, "child/receipt.json", 32)
        child.chmod(0o700)
        original_fstat = os.fstat

        def foreign_file_owner(descriptor):
            metadata = original_fstat(descriptor)
            if bundle.stat.S_ISREG(metadata.st_mode):
                return types.SimpleNamespace(st_mode=metadata.st_mode, st_nlink=metadata.st_nlink,
                                             st_uid=os.geteuid() + 1, st_size=metadata.st_size)
            return metadata

        with mock.patch.object(bundle.os, "fstat", side_effect=foreign_file_owner):
            with self.assertRaises(ValueError):
                bundle.read_bounded_file(self.root, "receipt.json", 32)

    def test_duplicate_keys_and_nonfinite_numbers_fail(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e999}', b'[]'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                bundle.json_object(raw)

    def test_bundle_authority_and_intermediate_directory_must_be_private(self):
        intermediate = self.root / "intermediate"
        intermediate.mkdir()
        child = intermediate / "bundle"
        child.mkdir()
        for directory in (self.root, intermediate):
            directory.chmod(0o777)
            with self.subTest(directory=directory), self.assertRaises(ValueError):
                bundle.BundleReader(self.root, str(child))
            directory.chmod(0o700)
        self.assertEqual(bundle.BundleReader(self.root, "intermediate/bundle").root, child)


class NativeBundleRouterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="native-bundle-router-", dir=os.environ["TMPDIR"])
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.artifact = self.root / "artifacts"
        self.artifact.mkdir()
        self.output = self.artifact / "operation"
        self.output.mkdir()
        self.case = "body_size_nonzero_with_null_data"
        self.run_id = "unit"
        self.parent = self.root / "parent"
        self.framework = self.root / "framework"
        self.sources = {"parent_root": self.parent, "framework_root": self.framework,
                        "parent_sha": "1" * 40, "framework_sha": "2" * 40, "mrts_sha": "3" * 40,
                        "binary_sha256": bundle.digest(b"unit binary"), "module_sha256": bundle.digest(b"unit module"),
                        "fault_library_sha256": {self.case: bundle.digest(b"unit fault")}}
        source_hashes = {}
        for name in bundle.required_source_paths(self.case):
            owner, relative = name.split(":", 1)
            destination = self.sources[owner + "_root"] / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            actual = ROOT / relative
            content = actual.read_bytes() if owner == "framework" else b"# synthetic unit source, not runtime proof\n"
            destination.write_bytes(content)
            destination.chmod(0o600)
            source_hashes[name] = bundle.digest(content)
        self.observed = input_tests.CommonInputFaultContractTest.observation(self, self.case)
        self.observed["native_events"][0]["uri"] = self.observed["native_access"]["uri"]
        self.cleanup_event = {"event": "transaction_cleanup", "message_id": "MSCONN_TRANSACTION_CLEANUP",
                              "connector": "nginx", "integration_mode": bundle.MODE, "phase": "logging", "rule_id": "",
                              "status": "ok", "action": "allow", "actual_action": "allow", "transaction_id": "a" * 32,
                              "uri": self.observed["native_access"]["uri"],
                              "reason": "common_return=0;common_complete=1;native_cleanup_completed=1;error_class=protocol_error",
                              "cleanup_reason": "protocol_error"}
        projection_parent = self.root / "projections"
        token = hashlib.sha256((self.run_id + ":" + self.case).encode()).hexdigest()[:32]
        projection = projection_parent / ("common-input-" + token)
        config = (f'load_module "{self.output}/nginx-module.so";\nuser nobody nogroup;\nworker_processes 1;\ndaemon off;\n'
                  f'modsecurity on;\nroot "{projection}";\nmodsecurity_transaction_id "' + "a" * 32 + '";\n').encode()
        self.raw = {"nginx-binary": b"unit binary", "nginx-module.so": b"unit module", "native-input-fault.so": b"unit fault",
                    "no-crs-baseline.conf": (ROOT / "tests/rules/no-crs-baseline.conf").read_bytes(), "nginx.conf": config,
                    "native-access.jsonl": self.encode(self.observed["native_access"]), "native-input-fault.jsonl": self.encode(self.observed["native_fault"]),
                    "phase1-events.jsonl": self.encode(self.observed["native_events"][0]) + b"\n" + self.encode(self.cleanup_event),
                    "worker-maps.log": (str(self.output / "nginx-module.so") + "\n" + str(self.output / "nginx-binary")).encode(),
                    "nginx-error.log": self.observed["native_diagnostic"].encode(), "configtest.stdout": b"",
                    "configtest.stderr": (str(self.output / "nginx.conf") + " syntax is ok\ntest is successful\n").encode(),
                    "client.stdout": b"400", "client.stderr": b"", "startup.stdout": b"", "startup.stderr": b""}
        self.receipt = {"schema_version": 1, "case_id": self.case, "run_id": self.run_id, "operation": "common_mapper_input_fault",
                        **{field: self.sources[field] for field in ("parent_sha", "framework_sha", "mrts_sha")},
                        "configtest_exit_code": 0, "projection_parent": str(projection_parent), "projection_root": str(projection)}
        self.record = {"case_id": self.case, "run_id": self.run_id, "connector": "nginx", "integration_mode": bundle.MODE,
                       "operation": "common_mapper_input_fault", "driver_exit_code": 0, "status": "NOT_EXECUTED",
                       **{field: self.sources[field] for field in ("parent_sha", "framework_sha", "mrts_sha")},
                       "native_operation_receipt": {"schema_version": 1, "case_id": self.case, "run_id": self.run_id,
                            "operation": "common_mapper_input_fault", "integration_mode": bundle.MODE,
                            "bundle_root": str(self.output), "source_sha256": source_hashes,
                            "invocations": [{"name": "main", "receipt_path": "input-fault-source.json", "receipt_sha256": ""}]}}
        self.seal()

    @staticmethod
    def encode(value):
        return json.dumps(value, sort_keys=True).encode()

    def seal(self):
        self.raw["input-fault-observation.json"] = self.encode(self.observed)
        artifact_leaves = {"nginx-binary", "nginx-module.so", "no-crs-baseline.conf", "native-input-fault.so"}
        self.receipt["artifacts_sha256"] = {leaf: bundle.digest(self.raw[leaf]) for leaf in artifact_leaves}
        self.receipt["raw_artifacts_sha256"] = {leaf: bundle.digest(raw) for leaf, raw in self.raw.items()
                                                   if leaf not in artifact_leaves | {"nginx.conf", "input-fault-observation.json"}}
        self.receipt["observed_sha256"] = bundle.digest(self.raw["input-fault-observation.json"])
        self.receipt["config_sha256"] = bundle.digest(self.raw["nginx.conf"])
        source = {"cases": [{"case_id": self.case, "run_id": self.run_id, "operation": "common_mapper_input_fault",
                              "live_executed": True, "errors": [], "input_fault_receipt": self.receipt}]}
        original = self.encode(source)
        for leaf, raw in {**self.raw, "input-fault-source.json": original}.items():
            (self.output / leaf).write_bytes(raw)
            (self.output / leaf).chmod(0o600)
        self.record["native_operation_receipt"]["invocations"][0]["receipt_sha256"] = bundle.digest(original)

    def validate(self):
        return bundle.validate_native_operation_bundle(self.record, self.artifact, self.sources)

    def test_original_sealed_pointer_layer_not_canonical_pass(self):
        proof = self.validate()
        self.assertEqual(proof["errors"], [])
        self.assertEqual(proof["actual_status"], 400)
        self.assertEqual(proof["transaction_ids"], ["a" * 32])
        self.assertEqual(len(proof["events"]), 2)
        self.assertTrue(proof["layer_verified"])
        self.assertNotIn("status", proof)
        self.assertNotIn("canonical_status", proof)
        self.assertEqual(self.record["status"], "NOT_EXECUTED")
        self.assertIn("input-fault-source.json", proof["files"])

    def test_role_phase_rule_and_fault_scope_mismatches_fail_after_resealing(self):
        for target, field, value in (("roles", "worker_uid", 0), ("roles", "master_pid", True),
                                     ("cleanup", "worker_pid", 999), ("native_fault", "ppid", 999)):
            saved = copy.deepcopy(self.observed)
            self.observed[target][field] = value
            self.seal()
            with self.subTest(target=target, field=field), self.assertRaises(ValueError):
                self.validate()
            self.observed = saved
        for field, value in (("phase", "response_body"), ("rule_id", "1100001"), ("transaction_id", "b" * 32)):
            saved = copy.deepcopy(self.observed)
            self.observed["native_events"][0][field] = value
            self.raw["phase1-events.jsonl"] = self.encode(self.observed["native_events"][0]) + b"\n" + self.encode(self.cleanup_event)
            self.seal()
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate()
            self.observed = saved

    def test_source_revision_binary_module_and_fault_authority_fail(self):
        for field in ("parent_sha", "framework_sha", "mrts_sha", "binary_sha256", "module_sha256"):
            old = self.sources[field]
            self.sources[field] = "f" * len(old)
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate()
            self.sources[field] = old
        self.sources["fault_library_sha256"] = {}
        with self.assertRaises(ValueError):
            self.validate()

    def test_reopened_raw_digest_and_source_map_controls_fail(self):
        (self.output / "native-access.jsonl").write_bytes(b"{}")
        with self.assertRaises(ValueError):
            self.validate()
        self.seal()
        mapping = self.record["native_operation_receipt"]["source_sha256"]
        key = next(iter(mapping))
        mapping[key] = "f" * 64
        with self.assertRaises(ValueError):
            self.validate()

    def test_mapper_terminal_allows_only_actual_p1_error_then_preserved_cleanup(self):
        original = self.raw["phase1-events.jsonl"]
        for change in (
                {"event": "engine_timeout", "message_id": "MSCONN_EVENT_ENGINE_TIMEOUT", "phase": "response_body", "status": "error", "http_status": 504},
                {"event": "phase4_append", "message_id": "MSCONN_PHASE4_APPEND", "phase": "response_body", "status": "ok"},
                {"event": "protocol_error", "message_id": "MSCONN_EVENT_PROTOCOL_ERROR", "phase": "response_headers", "status": "error"}):
            extra = {"connector": "nginx", "integration_mode": bundle.MODE,
                     "transaction_id": self.observed["transaction_id"], "rule_id": "",
                     "uri": self.observed["native_access"]["uri"], **change}
            self.raw["phase1-events.jsonl"] = original + b"\n" + self.encode(extra)
            self.seal()
            with self.subTest(event=extra["event"], phase=extra["phase"]), self.assertRaises(ValueError):
                self.validate()
        self.raw["phase1-events.jsonl"] = original
        self.seal()
        self.assertTrue(self.validate()["layer_verified"])

    def test_source_event_optional_scalar_types_and_bounds_are_real(self):
        original = copy.deepcopy(self.cleanup_event)
        for field, wrong in (("eos_seen", 1), ("http_status", "200"),
                             ("body_bytes_seen", False), ("sequence", False), ("message", "m" * 256)):
            self.cleanup_event = {**original, field: wrong}
            self.raw["phase1-events.jsonl"] = self.encode(self.observed["native_events"][0]) + b"\n" + self.encode(self.cleanup_event)
            self.seal()
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate()
        self.cleanup_event = original
        self.raw["phase1-events.jsonl"] = self.encode(self.observed["native_events"][0]) + b"\n" + self.encode(original)
        self.seal()

    def test_reused_projection_wrong_run_operation_and_h2_h3_fail(self):
        original = self.receipt["projection_root"]
        self.receipt["projection_root"] = str(Path(original).parent / "reused")
        self.seal()
        with self.assertRaises(ValueError):
            self.validate()
        self.receipt["projection_root"] = original
        self.seal()
        for field, value in (("run_id", "foreign"), ("operation", "request_sequence"),
                              ("driver_exit_code", False), ("driver_exit_code", 1), ("downstream_protocol", "h2"), ("downstream_protocol", "h3")):
            saved = copy.deepcopy(self.record)
            self.record[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.validate()
            self.record = saved

    def test_missing_cleanup_source_event_is_not_http400_proof(self):
        self.raw["phase1-events.jsonl"] = self.encode(self.observed["native_events"][0])
        self.seal()
        with self.assertRaisesRegex(ValueError, "cleanup source event"):
            self.validate()

    def test_payload_nested_metadata_and_cleanup_taxonomy_fail(self):
        for field, value in (("response_body", "unit payload"), ("data", {"nested": "unit"}),
                             ("reason", "common_return=0;common_complete=1;native_cleanup_completed=0;error_class=none")):
            event = {**self.cleanup_event, field: value}
            self.raw["phase1-events.jsonl"] = self.encode(self.observed["native_events"][0]) + b"\n" + self.encode(event)
            self.seal()
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate()

    def test_wrapper_receipt_missing_seal_directory_symlink_and_outside_authority_fail(self):
        envelope = self.record["native_operation_receipt"]
        saved = copy.deepcopy(envelope)
        envelope["invocations"][0]["receipt_sha256"] = None
        with self.assertRaises(ValueError):
            self.validate()

        self.record["native_operation_receipt"] = copy.deepcopy(saved)
        self.record["native_operation_receipt"]["bundle_root"] = str(self.parent)
        with self.assertRaises(ValueError):
            self.validate()
        self.record["native_operation_receipt"] = saved
        original = self.output / "input-fault-source.json"
        moved = self.output / "original.json"
        original.rename(moved)
        original.symlink_to(moved)
        with self.assertRaises(ValueError):
            self.validate()

    def test_foreign_group_envelope_fields_are_rejected(self):
        envelope = self.record["native_operation_receipt"]
        for field in ("source_record_id", "parent_receipt_path", "parent_receipt_sha256"):
            envelope[field] = "foreign"
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate()
            envelope.pop(field)

    def test_exact_42_routes_and_closed_source_paths(self):
        self.assertEqual(len(bundle.CASE_IDS), 42)
        for case in bundle.CASE_IDS:
            self.assertTrue(bundle.required_source_paths(case))
            self.assertTrue(bundle.route(case)[0])
        with self.assertRaises(ValueError):
            bundle.route("transport_http2")

    def prepare_case(self, case, run_id):
        self.case, self.run_id = case, run_id
        self.output = self.artifact / ("operation-" + case)
        self.output.mkdir(exist_ok=True)
        mapping = {}
        for name in bundle.required_source_paths(case):
            owner, relative = name.split(":", 1)
            destination = self.sources[owner + "_root"] / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            content = (ROOT / relative).read_bytes() if owner == "framework" else b"# synthetic unit source, not runtime proof\n"
            destination.write_bytes(content)
            destination.chmod(0o600)
            mapping[name] = bundle.digest(content)
        operation = bundle.route(case)[0]
        self.record = {"case_id": case, "run_id": run_id, "connector": "nginx", "integration_mode": bundle.MODE,
                       "operation": operation, "driver_exit_code": 0, "status": "NOT_EXECUTED",
                       **{field: self.sources[field] for field in ("parent_sha", "framework_sha", "mrts_sha")},
                       "native_operation_receipt": {"schema_version": 1, "case_id": case, "run_id": run_id,
                            "operation": operation, "integration_mode": bundle.MODE, "bundle_root": str(self.output),
                            "source_sha256": mapping, "invocations": []}}

    def source_digest(self, name):
        owner, relative = name.split(":", 1)
        return bundle.digest((self.sources[owner + "_root"] / relative).read_bytes())

    def decorate_phase4(self, receipt, raw, output):
        run_id, case = receipt["run_id"], receipt["case_id"]
        parent = self.root / "projections"
        projection = parent / ("phase4-" + hashlib.sha256((run_id + ":" + case).encode()).hexdigest()[:24])
        header = (f'load_module "{output}/nginx-module.so";\nuser nobody nogroup;\nworker_processes 1;\ndaemon off;\n'
                  f'root "{projection}";\n').encode()
        if b"modsecurity on;" not in raw["nginx.conf"]:
            header += b"modsecurity on;\n"
        raw["nginx.conf"] = header + raw["nginx.conf"]
        raw.update({"nginx-binary": b"unit binary", "nginx-module.so": b"unit module", "configtest.stdout": b"",
                    "configtest.stderr": (str(output / "nginx.conf") + " syntax is ok\ntest is successful\n").encode(),
                    "startup.stdout": b"", "startup.stderr": b""})
        receipt.update({field: self.sources[field] for field in ("parent_sha", "framework_sha", "mrts_sha", "binary_sha256", "module_sha256")})
        receipt["docroot_projection_parent"], receipt["docroot_projection_root"] = str(parent), str(projection)
        receipt["roles"] = {**self.observed["roles"], "run_id": run_id}
        receipt["cleanup"] = {**self.observed["cleanup"], "run_id": run_id}
        receipt["driver_sha256"] = self.source_digest("parent:ci/runtime/lifecycle/run-nginx-phase4-cases.py")
        helper = "nginx_phase4_contracts" if case in bundle.PHASE4_CASES else bundle.route(case)[1]
        receipt["closed_inputs_sha256"] = self.source_digest("framework:tests/runners/" + helper + ".py")
        upstream = "parent:ci/runtime/common/nginx_phase4_upstream.py"
        if case in bundle.MIME_CASES:
            upstream = "parent:ci/runtime/lifecycle/run-nginx-mime-cases.py"
            receipt["backend_contract_sha256"] = self.source_digest("parent:ci/runtime/common/response-header-test-backend.py")
            receipt["backend_omission_contract_sha256"] = self.source_digest("parent:ci/runtime/common/response_fixture_omission.py")
        elif case in bundle.EVENT_CASES:
            upstream = "parent:ci/runtime/lifecycle/run-nginx-event-boundary-cases.py"
        receipt["upstream_driver_sha256"] = self.source_digest(upstream)
        error_class = "body_limit" if case == "phase4_body_reject" else "none"
        for event in receipt["native_events"]:
            event.setdefault("rule_id", "")
            event.setdefault("status", "blocked" if event["event"] in {"phase4_intervention", "body_limit"} else "ok")
        raw["phase4-events.jsonl"] = b"\n".join(self.encode(event) for event in receipt["native_events"])
        cleanup = {**self.cleanup_event, "transaction_id": receipt["native_events"][0]["transaction_id"],
                   "uri": receipt["native_events"][0]["uri"],
                   "cleanup_reason": "normal" if error_class == "none" else error_class,
                   "reason": "common_return=0;common_complete=1;native_cleanup_completed=1;error_class=" + error_class}
        raw["phase4-events.jsonl"] += b"\n" + self.encode(cleanup)
        receipt["raw_sha256"] = {leaf: bundle.digest(data) for leaf, data in raw.items() if leaf not in {"nginx-binary", "nginx-module.so"}}

    def write_child(self, receipt, raw, output, name, relative):
        output.mkdir(exist_ok=True)
        for leaf, data in raw.items():
            (output / leaf).write_bytes(data)
            (output / leaf).chmod(0o600)
        serialized = self.encode(receipt)
        (output / "source-result.json").write_bytes(serialized)
        (output / "source-result.json").chmod(0o600)
        self.record["native_operation_receipt"]["invocations"].append(
            {"name": name, "receipt_path": relative, "receipt_sha256": bundle.digest(serialized)})
        return serialized

    def reorder_sealed_invocation_events(self, name):
        """Change original bytes and every real parent/child seal, not helpers."""
        envelope = self.record["native_operation_receipt"]
        descriptor = next(item for item in envelope["invocations"] if item["name"] == name)
        path = self.output / descriptor["receipt_path"]
        receipt = json.loads(path.read_bytes())
        event_path = path.parent / "phase4-events.jsonl"
        lines = event_path.read_bytes().splitlines()
        cleanup_index = next(index for index, line in enumerate(lines)
                             if json.loads(line).get("event") == "transaction_cleanup")
        changed = b"\n".join([lines[cleanup_index]] + lines[:cleanup_index] + lines[cleanup_index + 1:])
        event_path.write_bytes(changed)
        receipt["raw_sha256"]["phase4-events.jsonl"] = bundle.digest(changed)
        original = self.encode(receipt)
        path.write_bytes(original)
        descriptor["receipt_sha256"] = bundle.digest(original)
        if self.case in bundle.EVENT_CASES:
            parent_path = self.output / "source-result.json"
            parent = json.loads(parent_path.read_bytes())
            child = next(item for item in parent["children"] if item["run_id"] == receipt["run_id"])
            child["receipt_sha256"] = bundle.digest(original)
            original = self.encode(parent)
            parent_path.write_bytes(original)
            envelope["parent_receipt_sha256"] = bundle.digest(original)

    def test_phase4_mime_cleanup_cannot_precede_actual_native_work(self):
        from tests.runners import test_nginx_phase4_operations as phase4_tests
        from tests.no_crs import test_nginx_mime_operations as mime_tests
        for case in ("phase4_body_at_limit", "phase4_body_reject", "phase4_out_of_scope_content_type"):
            receipt, raw = (mime_tests.unit_operation(case) if case in bundle.MIME_CASES else
                            phase4_tests.rejection_fixture() if case == "phase4_body_reject" else phase4_tests.fixture(case))
            self.prepare_case(case, receipt["run_id"])
            self.decorate_phase4(receipt, raw, self.output)
            self.write_child(receipt, raw, self.output, "main", "source-result.json")
            self.assertTrue(self.validate()["layer_verified"])
            self.reorder_sealed_invocation_events("main")
            with self.subTest(case=case), self.assertRaises(ValueError):
                self.validate()

    def test_all_phase4_and_mime_routes_use_real_closed_helpers(self):
        from tests.runners import test_nginx_phase4_operations as phase4_tests
        from tests.no_crs import test_nginx_mime_operations as mime_tests
        for case in sorted(bundle.PHASE4_CASES | bundle.MIME_CASES):
            if case in bundle.MIME_CASES:
                receipt, raw = mime_tests.unit_operation(case)
            elif case == "phase4_body_reject":
                receipt, raw = phase4_tests.rejection_fixture()
            else:
                receipt, raw = phase4_tests.fixture(case)
            self.prepare_case(case, receipt["run_id"])
            self.decorate_phase4(receipt, raw, self.output)
            self.write_child(receipt, raw, self.output, "main", "source-result.json")
            with self.subTest(case=case):
                proof = self.validate()
                self.assertEqual(proof["actual_status"], 200)
                self.assertEqual(proof["events"][-1]["event"], "transaction_cleanup")

    def test_all_raw_h1_routes_reopen_wire_without_inventing_transactions(self):
        from tests.runners import nginx_raw_h1
        for case in sorted(bundle.RAW_CASES):
            self.prepare_case(case, "raw-unit")
            config = (f'load_module "{self.output}/nginx-module.so"; user nobody nogroup; '
                      'worker_processes 1; daemon off; modsecurity on;').encode()
            accesses = [{"method": "POST", "uri": nginx_raw_h1.request_path(case, run), "status": status}
                        for run, status in ((self.run_id, 400), (self.run_id + "-control", 200))]
            raw = {"nginx.conf": config, "nginx-binary": b"unit binary", "nginx-module.so": b"unit module",
                   "no-crs-baseline.conf": (ROOT / "tests/rules/no-crs-baseline.conf").read_bytes(),
                   "roles.json": self.encode({**self.observed["roles"], "run_id": self.run_id}),
                   "cleanup.json": self.encode({**self.observed["cleanup"], "run_id": self.run_id}),
                   "fault-request.bin": nginx_raw_h1.request_bytes(case, self.run_id),
                   "control-request.bin": nginx_raw_h1.request_bytes(case, self.run_id + "-control", control=True),
                   "fault-response.bin": b"HTTP/1.1 400 Bad Request\r\nContent-Length: 1\r\n\r\nx",
                   "control-response.bin": b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx",
                   "access.jsonl": b"\n".join(self.encode(row) for row in accesses),
                   "native-events.jsonl": self.encode({**self.cleanup_event, "transaction_id": "c" * 32,
                        "uri": nginx_raw_h1.request_path(case, self.run_id + "-control"), "cleanup_reason": "normal",
                        "reason": "common_return=0;common_complete=1;native_cleanup_completed=1;error_class=none"}),
                   "nginx-error.log": nginx_raw_h1.DIAGNOSTICS[case].encode(),
                   "stdout.log": b"", "stderr.log": (str(self.output / "nginx.conf") + " syntax is ok\ntest is successful").encode(),
                   "startup.stdout": b"", "startup.stderr": b""}
            receipt = {"schema_version": 1, "case_id": case, "run_id": self.run_id, "operation": bundle.route(case)[0],
                       "connector": "nginx", "integration_mode": bundle.MODE, "configtest_exit_code": 0,
                       "host_observation_valid": True, "failure": None,
                       **{field: self.sources[field] for field in ("parent_sha", "framework_sha", "mrts_sha", "binary_sha256", "module_sha256")},
                       "requests": {name: {"client_exit_code": 0, "http_status": status} for name, status in (("fault", 400), ("control", 200))}}

            def save():
                receipt["raw_sha256"] = {leaf: bundle.digest(data) for leaf, data in raw.items()}
                self.record["native_operation_receipt"]["invocations"] = []
                self.write_child(receipt, raw, self.output, "main", "source-result.json")

            save()
            with self.subTest(case=case):
                proof = self.validate()
                self.assertEqual(proof["actual_status"], 400)
                self.assertEqual(proof["transaction_ids"], [])
                self.assertEqual(proof["events"], [])
            original = raw["fault-response.bin"]
            for corrupt in (original[:-1], original.replace(b"400", b"200", 1)):
                raw["fault-response.bin"] = corrupt
                save()
                with self.subTest(case=case, corrupt=corrupt), self.assertRaises(ValueError):
                    self.validate()
            raw["fault-response.bin"] = original
            raw["nginx-error.log"] = b"unrelated diagnostic"
            save()
            with self.assertRaises(ValueError):
                self.validate()

    def test_e_parent_and_distinct_sealed_children_routes(self):
        from tests.no_crs import test_nginx_event_boundaries as event_tests
        for case in sorted(bundle.EVENT_CASES):
            self.prepare_case(case, "unit")
            parent = {"schema_version": 1, "case_id": case, "run_id": "unit", "operation": "native_event_boundary_request",
                      "uri_buffer_bytes": 256, "writer_buffer_bytes": 4096,
                      **{field: self.sources[field] for field in ("parent_sha", "framework_sha", "mrts_sha")}, "children": [],
                      "driver_sha256": self.source_digest("parent:ci/runtime/lifecycle/run-nginx-event-boundary-cases.py"),
                      "closed_inputs_sha256": self.source_digest("framework:tests/runners/nginx_event_boundary_operations.py"),
                      "closed_input_dependencies_sha256": {name + ".py": self.source_digest("framework:tests/runners/" + name + ".py")
                            for name in ("nginx_common_input_faults", "nginx_mime_operations")}}
            variants = (("at", "at255"), ("over", "over256")) if case == "event_json_limit" else (("main", "long-query"),)
            for name, variant in variants:
                child, raw = event_tests.child(case, variant, "unit-" + variant)
                output = self.output / variant
                self.decorate_phase4(child, raw, output)
                serialized = self.write_child(child, raw, output, name, variant + "/source-result.json")
                parent["children"].append({"variant": variant, "directory": variant, "run_id": child["run_id"], "receipt_sha256": bundle.digest(serialized)})
            serialized = self.encode(parent)
            (self.output / "source-result.json").write_bytes(serialized)
            (self.output / "source-result.json").chmod(0o600)
            self.record["native_operation_receipt"].update(parent_receipt_path="source-result.json", parent_receipt_sha256=bundle.digest(serialized))
            with self.subTest(case=case):
                self.assertEqual(len(self.validate()["transaction_ids"]), len(variants))
            self.reorder_sealed_invocation_events(variants[-1][0])
            with self.subTest(case=case, corruption="cleanup-before-source-callback"), self.assertRaises(ValueError):
                self.validate()
            self.record["native_operation_receipt"]["parent_receipt_sha256"] = "f" * 64
            with self.assertRaises(ValueError):
                self.validate()

    def test_sequence_deny_rule_and_cleanup_require_actual_raw_events(self):
        from tests.no_crs import test_nginx_lifecycle_sequence as sequence_tests
        observed = sequence_tests.SequenceContractTests.observation(self)
        case, run_id = observed["case_id"], observed["run_id"]
        self.prepare_case(case, run_id)
        observed["roles"]["run_id"] = run_id
        observed["cleanup"].update(run_id=run_id, master_pid=observed["roles"]["master_pid"], worker_pid=observed["roles"]["worker_pid"])
        deny = {"event": "engine_decision", "message_id": "MSCONN_EVENT_ENGINE_DECISION", "connector": "nginx",
                "integration_mode": bundle.MODE, "phase": "request_headers", "status": "blocked", "action": "deny",
                "requested_action": "deny", "actual_action": "", "http_status": 403, "visible_http_status": 0, "transport_result": "not_observable",
                "rule_id": "1100001", "transaction_id": "b" * 32,
                "uri": observed["requests"][1]["path"]}
        events = [deny] + [{**self.cleanup_event, "transaction_id": row["transaction_id"], "cleanup_reason": "normal",
                           "uri": row["uri"],
                           "reason": "common_return=0;common_complete=1;native_cleanup_completed=1;error_class=none"}
                          for row in observed["native_access"]]
        observed["native_events"] = events
        token = hashlib.sha256((run_id + ":" + case).encode()).hexdigest()[:24]
        parent = self.root / "projections"
        projection = parent / ("sequence-" + token)
        raw = {"nginx-binary": b"unit binary", "nginx-module.so": b"unit module",
               "no-crs-baseline.conf": (ROOT / "tests/rules/no-crs-baseline.conf").read_bytes(),
               "sequence-observation.json": self.encode(observed), "native-access.jsonl": b"\n".join(self.encode(row) for row in observed["native_access"]),
               "phase1-events.jsonl": b"\n".join(self.encode(event) for event in events),
               "nginx.conf": (f'load_module "{self.output}/nginx-module.so"; user nobody nogroup; worker_processes 1; daemon off; '
                              f'modsecurity on; root "{projection}"; modsecurity_transaction_id "$request_id";').encode(),
               "worker-maps.log": (str(self.output / "nginx-module.so") + "\n" + str(self.output / "nginx-binary")).encode(),
               "configtest.stdout": b"", "configtest.stderr": (str(self.output / "nginx.conf") + " syntax is ok\ntest is successful").encode(),
               "startup.stdout": b"", "startup.stderr": b"", "nginx-error.log": b""}
        receipt = {"schema_version": 1, "case_id": case, "run_id": run_id, "operation": "request_sequence",
                   **{field: self.sources[field] for field in ("parent_sha", "framework_sha", "mrts_sha")},
                   "observed_exit_code": 0, "client_exit_code": 0, "projection_parent": str(parent), "projection_root": str(projection)}

        def write_source():
            raw["phase1-events.jsonl"] = b"\n".join(self.encode(event) for event in events)
            raw["sequence-observation.json"] = self.encode(observed)
            for field, leaf in bundle.SEQUENCE_HASHES.items():
                if leaf in raw:
                    receipt[field] = bundle.digest(raw[leaf])
            source = {"cases": [{"case_id": case, "run_id": run_id, "operation": "request_sequence", "live_executed": True,
                                  "errors": [], "sequence_receipt": receipt}]}
            for leaf, data in raw.items():
                (self.output / leaf).write_bytes(data)
                (self.output / leaf).chmod(0o600)
            original = self.encode(source)
            (self.output / "sequence-source.json").write_bytes(original)
            (self.output / "sequence-source.json").chmod(0o600)
            self.record["native_operation_receipt"]["invocations"] = [{"name": "main", "receipt_path": "sequence-source.json", "receipt_sha256": bundle.digest(original)}]

        write_source()
        self.assertEqual(self.validate()["actual_statuses"], [200, 403, 200])
        original_deny = copy.deepcopy(deny)
        for field, wrong in (("event", "request_rule_match"), ("message_id", "MSCONN_EVENT_RULE_MATCHED"),
                             ("actual_action", "allow"), ("actual_action", "deny"), ("http_status", 200),
                             ("http_status", True), ("visible_http_status", 403), ("rule_id", "1100402")):
            deny.clear()
            deny.update(original_deny)
            deny[field] = wrong
            write_source()
            with self.subTest(field=field, wrong=wrong), self.assertRaises(ValueError):
                self.validate()

    def test_early_mapping_and_begin_bridges_require_real_scoped_source_facts(self):
        from tests.no_crs import test_nginx_lifecycle_sequence as sequence_tests
        from tests.runners import nginx_lifecycle_sequence
        for case in ("early_mapping_failure_cleanup", "transaction_begin_failure_cleanup"):
            observed = sequence_tests.SequenceContractTests.observation(self)
            observed["case_id"] = case
            observed["requests"] = [dict(observed["requests"][0], observed_status=500)]
            observed["native_access"] = [dict(observed["native_access"][0], status=500)]
            observed["roles"]["run_id"] = observed["run_id"]
            observed["cleanup"].update(run_id=observed["run_id"], master_pid=10, worker_pid=11)
            early = case == "early_mapping_failure_cleanup"
            observed["fault"] = {"requested": "early_mapping_failure" if early else "transaction_begin_failure", "triggered": True,
                                 "native_diagnostic": "ModSecurity: invalid canonical transaction identifier" if early else "ModSecurity: failed to create transaction"}
            event = {"connector": "nginx", "integration_mode": bundle.MODE, "event": "protocol_error" if early else "connector_error",
                     "message_id": "MSCONN_EVENT_PROTOCOL_ERROR" if early else "MSCONN_EVENT_CONNECTOR_ERROR",
                     "phase": "request_headers", "status": "error", "rule_id": "", "http_status": 500,
                     "uri": observed["requests"][0]["path"], "transaction_id": "" if early else "a" * 32}
            events = [event]
            raw = {"worker-maps.log": b"unit mappings"}
            if not early:
                events.append({**self.cleanup_event, "transaction_id": "a" * 32, "cleanup_reason": "connector_error",
                               "uri": observed["requests"][0]["path"],
                               "reason": "common_return=0;common_complete=1;native_cleanup_completed=0;error_class=connector_error"})
                observed["native_begin"] = [{"native_operation": "msc_new_transaction_with_id", "observed_return": None,
                    "worker_pid": 11, "worker_uid": 65534, "master_pid": 10, "transaction_id": "a" * 32, "injected": True}]

            def captures():
                observed["native_events"] = events
                raw["sequence-observation.json"] = self.encode(observed)
                raw["native-access.jsonl"] = b"\n".join(self.encode(row) for row in observed["native_access"])
                raw["phase1-events.jsonl"] = b"\n".join(self.encode(row) for row in events)
                if not early:
                    raw["native-begin-observations.jsonl"] = self.encode(observed["native_begin"][0])

            captures()
            with self.subTest(case=case):
                proof = bundle.validate_sequence(nginx_lifecycle_sequence, {}, raw, case, observed["run_id"])
                self.assertEqual(proof["transaction_ids"], [] if early else ["a" * 32])
            event["rule_id"] = "invented-rule"
            captures()
            with self.assertRaises(ValueError):
                bundle.validate_sequence(nginx_lifecycle_sequence, {}, raw, case, observed["run_id"])
            event["rule_id"] = ""
            if not early:
                for field, value in (("worker_uid", 0), ("master_pid", 99), ("transaction_id", "b" * 32), ("observed_return", 1), ("invented", 1)):
                    ledger = observed["native_begin"][0]
                    saved = copy.deepcopy(ledger)
                    ledger[field] = value
                    captures()
                    with self.subTest(field=field), self.assertRaises(ValueError):
                        bundle.validate_sequence(nginx_lifecycle_sequence, {}, raw, case, observed["run_id"])
                    observed["native_begin"][0] = saved


if __name__ == "__main__":
    unittest.main()
