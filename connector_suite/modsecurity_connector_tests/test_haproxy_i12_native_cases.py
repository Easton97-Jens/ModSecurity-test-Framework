"""Fixture integrity tests; runtime qualification remains an independent step."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import hashlib
import ast
import io
import importlib.util
import json
import shlex
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = connector_root()
CASES = load_source(source_path('connectors/haproxy/harness/i12_native_cases.py', root=ROOT))
CAPTURE = load_source(source_path('ci/runtime/lifecycle/i12/capture_sources.py', root=ROOT))
OBSERVER = load_source(source_path('connectors/haproxy/harness/i12_native_observe.py', root=ROOT))
CONTRACT_SPEC = importlib.util.spec_from_file_location(
    "i12_native_contracts", source_path('connectors/haproxy/harness/i12_native_contracts.py', root=ROOT)
)
CONTRACTS = importlib.util.module_from_spec(CONTRACT_SPEC)
ORACLES = load_source(source_path('connectors/haproxy/harness/i12_oracle_fixture.py', root=ROOT))
with patch.dict("sys.modules", {"i12_native_cases": CASES, "i12_oracle_fixture": ORACLES}):
    CONTRACT_SPEC.loader.exec_module(CONTRACTS)


class NativeFixtureIntegrity(unittest.TestCase):
    def setUp(self):
        Path("/var/tmp/codex/ModSecurity-conector").mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(
            prefix="i12-native-fixture-test-", dir="/var/tmp/codex/ModSecurity-conector"
        )
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.capture = self.base / "capture"
        self.capture.mkdir()
        registry = CAPTURE.Registry()
        for name, digest in CASES.CAPTURE_HASHES.items():
            (self.capture / name).write_bytes(registry.content(digest))

    def make(self, name):
        return CASES.materialize(self.capture, self.base / name, name, CASES.cases()[name])

    def tearDown(self):
        # Fixture sealing is intentional; make only this test's private files
        # writable again so TemporaryDirectory can remove its own artifacts.
        for path in self.base.rglob("*"):
            path.chmod(0o755 if path.is_dir() else 0o644)

    def test_future_native_fixture_configures_exactly_one_physical_common_sink(self):
        fixture = Path(self.make("response-single-chunk")["source"])
        parsed = ast.parse((fixture / "launch.py").read_text())
        configuration = [node.value for node in ast.walk(parsed)
                         if isinstance(node, ast.Constant) and isinstance(node.value, str)
                         and "filter modsecurity-htx " in node.value]
        lines = [line.strip() for text in configuration for line in text.splitlines()
                 if line.strip().startswith("filter modsecurity-htx ")]
        self.assertEqual(len(lines), 1)
        tokens = shlex.split(lines[0])
        self.assertEqual(tokens.count("events-file"), 1)
        self.assertEqual(tokens[tokens.index("events-file") + 1], "/task/common-events.jsonl")
        self.assertEqual(list(fixture.rglob("common-events.jsonl")), [])

    def test_physical_sink_patch_rejects_missing_or_duplicate_filter_anchor(self):
        launch = (self.capture / CASES.LAUNCH_FILE).read_text()
        case = CASES.cases()["response-single-chunk"]
        for altered in (launch.replace(CASES.NATIVE_FILTER_DIRECTIVE, "changed-filter"),
                        launch + "\n" + CASES.NATIVE_FILTER_DIRECTIVE):
            with self.subTest(altered=altered[-100:]), self.assertRaisesRegex(ValueError, "capture boundary changed"):
                CASES.prepare_launch(altered, "response-single-chunk", case, case["request"], case["response"])

    def test_full_original_identity_is_bound_once_without_need_substring_replacement(self):
        launch = (self.capture / CASES.LAUNCH_FILE).read_text()
        for suffix in ("allow", "NEED-request-eos-once", "NEED-p3-redirect"):
            original = "I12::haproxy-native-htx::" + suffix
            case = dict(CASES.cases()["request-empty"], original_id=original)
            prepared, _, selected, _ = CASES.prepare_launch(launch, suffix, case, case["request"], case["response"])
            self.assertEqual(selected, original)
            self.assertEqual(prepared.count("MSCONNECTOR_LIFECYCLE_CASE=" + repr(original)), 1)
            self.assertEqual(prepared.count("'selected_id':" + repr(original)), 1)
            self.assertNotIn("NEED-NEED-", prepared)
        for anchor in ("MSCONNECTOR_LIFECYCLE_CASE='NEED-request-eos-once'",
                       "'selected_id':'I12::haproxy-native-htx::NEED-request-eos-once'"):
            for altered in (launch.replace(anchor, "changed"), launch + "\n" + anchor):
                with self.assertRaisesRegex(ValueError, "capture boundary changed"):
                    CASES.prepare_launch(altered, "allow", case, case["request"], case["response"])

    def test_redirect_client_requires_exact_one_source_location_and_none_for_neighbor(self):
        case = CASES.cases()["p3-redirect"]
        client = CASES.prepare_client((self.capture / CASES.CLIENT_FILE).read_text(), case, case["request"])
        self.assertIn("row['status']!=(302 if name=='main' else 200)", client)
        self.assertIn("or not redirect_location_matches(row,name):", client)
        predicate = next(node for node in ast.parse(client).body if isinstance(node, ast.FunctionDef)
                         and node.name == "redirect_location_matches")
        scope = {}
        exec(compile(ast.Module(body=[predicate], type_ignores=[]), "actual-header-predicate", "exec"), scope)
        matches = scope["redirect_location_matches"]
        location = case["expected_location"]
        self.assertTrue(matches({"headers": [["location", location]]}, "main"))
        self.assertTrue(matches({"headers": [["Location", " \t" + location + "\t"]]}, "main"))
        for headers in ([], [["Location", "wrong"]], [["Location", location], ["LOCATION", location]]):
            self.assertFalse(matches({"headers": headers}, "main"))
        self.assertTrue(matches({"headers": [["Content-Length", "8"]]}, "neighbor"))
        self.assertFalse(matches({"headers": [["Location", location]]}, "neighbor"))

    def test_named_p3_redirect_uses_canonical_rule_and_preserves_original_oracle(self):
        name = "phase3_redirect_before_commit"
        location = "https://no-crs.invalid/phase3-redirect"
        document = self.base / "redirect.yaml"
        document.write_text("request:\n  method: GET\n  path: /source-redirect\nresponse:\n  headers: {X-Modsec-Upstream: redirect}\n  body: source-body\nfull_lifecycle:\n  redirect_location: " + location + "\n")
        catalog = {name: {"request": {"method": "GET", "path": "/source-redirect", "fixture": "redirect.yaml"}, "expected_status": 302}}
        oracle = {"rule_id": None, "phase": None, "unresolved_expected_value_reason": "original unresolved"}
        row = {"run_scoped_case_id": "I12::haproxy-native-htx::NEED-p3-redirect",
               "original_selected_requirement": {"case_id": "NEED-p3-redirect", "execution_kind": "actual_host"},
               "original_selected_requirement_sha256": "a" * 64,
               "original_oracle": oracle, "required_measurement_contract": []}
        rules = 'SecRule RESPONSE_HEADERS:X-Modsec-Upstream "@streq redirect" "id:1100202,phase:3,redirect:' + location + ',status:302"\n'
        plan, case = CONTRACTS.bind_row(row, catalog, self.base, rules, [])
        self.assertEqual(plan["original_oracle"], oracle)
        self.assertEqual(case["expected_status"], 302)
        self.assertEqual(case["expected_location"], location)
        self.assertFalse(case["response_inspected"])
        self.assertEqual(case["response_headers"], [{"name": "X-Modsec-Upstream", "value": "redirect"}])
        launch, _, _, _ = CASES.prepare_launch((self.capture / CASES.LAUNCH_FILE).read_text(), "NEED-p3-redirect", case, case["request"], case["response"])
        self.assertIn("id:1100202", launch)
        self.assertNotIn("id:1999474", launch)
        self.assertNotIn("id:1999472", launch)

    def test_reference_rejects_outside_and_traversal_before_any_open(self):
        for source in (Path("/etc/passwd"), self.base / ".." / "source.txt", Path("relative.txt")):
            with self.subTest(source=source), patch.object(CONTRACTS.os, "open") as opened:
                with self.assertRaises(ValueError):
                    CONTRACTS.reference(source, "negative-source-control")
                opened.assert_not_called()

    def test_reference_reads_regular_file_and_rejects_symlinks_and_special_files(self):
        source = self.base / "regular.txt"
        source.write_bytes(b"bounded independent source")
        self.assertEqual(CONTRACTS.read_source(source), b"bounded independent source")
        link = self.base / "link.txt"
        link.symlink_to(source)
        fifo = self.base / "fifo"
        CONTRACTS.os.mkfifo(fifo)
        directory_link = self.base / "directory-link"
        directory_link.symlink_to(self.base, target_is_directory=True)
        for candidate in (link, directory_link / source.name, fifo, self.base):
            with self.subTest(candidate=candidate), self.assertRaises((OSError, ValueError)):
                CONTRACTS.reference(candidate, "negative-source-control")

    def test_reference_parent_replacement_cannot_redirect_pinned_input(self):
        parent = self.base / "input-parent"
        parent.mkdir()
        source = parent / "source.txt"
        source.write_bytes(b"original admitted bytes")
        other = self.base / "other-parent"
        other.mkdir()
        (other / source.name).write_bytes(b"different bytes through raced symlink")
        original_open = CONTRACTS.os.open
        swapped = False

        def replace_parent(path, flags, *args, **kwargs):
            nonlocal swapped
            if Path(path).name == source.name and not swapped:
                swapped = True
                parent.rename(self.base / "held-original-parent")
                parent.symlink_to(other, target_is_directory=True)
            return original_open(path, flags, *args, **kwargs)

        with patch.object(CONTRACTS.os, "open", side_effect=replace_parent):
            observed = CONTRACTS.reference(source, "race-control")
        self.assertTrue(swapped)
        self.assertEqual(observed["sha256"], hashlib.sha256(b"original admitted bytes").hexdigest())

    def test_capture_mutation_rejected_before_fixture_creation(self):
        source = self.capture / "launch.py"
        source.write_text(source.read_text() + "\n# changed input\n")
        with self.assertRaisesRegex(ValueError, "immutable capture hash differs"):
            self.make("response-single-chunk")
        self.assertFalse((self.base / "response-single-chunk").exists())

    def test_output_rejects_traversal_symlink_ancestors_and_existing_data(self):
        target = self.base / "output"
        created = CASES.fresh_output(target)
        self.assertEqual(created.stat().st_mode & 0o777, 0o700)
        sentinel = created / "sentinel"
        sentinel.write_text("preserve")
        with self.assertRaises(FileExistsError):
            CASES.fresh_output(target)
        self.assertEqual(sentinel.read_text(), "preserve")
        link = self.base / "link"
        link.symlink_to(target, target_is_directory=True)
        through_link = link / "child"
        with self.assertRaises(ValueError):
            CASES.fresh_output(through_link)
        traversal = self.base / ".." / "escape"
        with self.assertRaises(ValueError):
            CASES.fresh_output(traversal)
        self.assertFalse((target / "child").exists())

    def test_native_partial_limit_has_independent_prefix_oracle(self):
        record = self.make("response-process-partial")
        launch = (Path(record["source"]) / "launch.py").read_text()
        self.assertIn("SecResponseBodyLimit 16\n", launch)
        self.assertIn("SecResponseBodyLimitAction ProcessPartial", launch)
        prefix_digest = hashlib.sha1(CASES.BASE_RESPONSE[:16]).hexdigest()
        whole_digest = hashlib.sha1(CASES.BASE_RESPONSE).hexdigest()
        self.assertIn("RESPONSE_BODY \"@streq " + prefix_digest, launch)
        self.assertNotIn("RESPONSE_BODY \"@streq " + whole_digest, launch)

    def test_response_deny_excludes_the_health_neighbor(self):
        record = self.make("p3-deny")
        fixture = Path(record["source"])
        self.assertIn("RESPONSE_HEADERS:X-I12-Main", (fixture / "launch.py").read_text())
        self.assertIn("self.path=='/i12-main' else 'neighbor'", (fixture / "backend.py").read_text())

    def test_each_fixture_is_sealed_bound_and_unqualified(self):
        for name in CASES.cases():
            record = self.make(name)
            fixture = Path(record["source"])
            contract = json.loads((fixture / "case-contract.json").read_text())
            self.assertIsNone(contract["full_lifecycle_pass"])
            self.assertTrue(contract["private_host_execution_required"])
            if name in CASES.DIAGNOSTIC_CASES:
                self.assertIsNone(contract["original_id"])
                self.assertFalse(contract["original_obligation_eligible"])
                self.assertTrue(contract["diagnostic_id"].startswith("DIAG::"))
            else:
                self.assertIsNone(contract["diagnostic_id"])
                self.assertTrue(contract["original_obligation_eligible"])
            self.assertEqual(fixture.stat().st_mode & 0o222, 0)
            ledger = json.loads(Path(record["ledger"]).read_text())
            for filename, expected in ledger["files"].items():
                self.assertEqual(hashlib.sha256((fixture / filename).read_bytes()).hexdigest(), expected)
            for filename in ("launch.py", "client.py", "backend.py"):
                compile((fixture / filename).read_text(), filename, "exec")

    def test_fragmented_host_writes_match_independent_client_wire(self):
        wire = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
        chunks = [wire[:17], wire[17:-3], wire[-3:]]
        writes = [{"actual_result": len(chunk), "positive_output_sha256": hashlib.sha256(chunk).hexdigest()} for chunk in chunks]
        segments, complete = OBSERVER.match_wire_segments(writes, wire)
        self.assertTrue(complete)
        self.assertTrue(all(segment["digest_matches"] for segment in segments))
        # Equal total byte counts do not qualify reordered/damaged output.
        writes[0]["positive_output_sha256"] = "0" * 64
        segments, complete = OBSERVER.match_wire_segments(writes, wire)
        self.assertTrue(complete)
        self.assertFalse(segments[0]["digest_matches"])

    def test_truncated_client_wire_cannot_match_complete_host_write(self):
        writes = [{"actual_result": 5, "positive_output_sha256": hashlib.sha256(b"hello").hexdigest()}]
        segments, complete = OBSERVER.match_wire_segments(writes, b"hell")
        self.assertFalse(complete)
        self.assertFalse(segments[0]["digest_matches"])

    def test_current_completion_seal_and_namespace_sdk_bind_physical_images(self):
        artifacts = self.base / "artifacts"
        artifacts.mkdir()
        sources = self.base / "sources"
        sources.mkdir()
        names = {"direct": "haproxy-direct", "agent": "haproxy-spop",
                 "companion": "haproxy", "native_engine": "libmodsecurity.so.3"}
        images = {}
        for role, name in names.items():
            source = sources / name
            source.write_bytes(("source-" + role).encode())
            sealed = artifacts / name
            sealed.write_bytes(source.read_bytes())
            images[role] = {"role": role, "source": str(source), "sealed_copy": str(sealed),
                            "sha256": hashlib.sha256(sealed.read_bytes()).hexdigest()}
        binary = artifacts / "haproxy-direct"
        sdk = artifacts / "libmodsecurity.so.3"
        receipt = self.base / "completion-seal.json"
        receipt.write_text(json.dumps({"required_head": "a" * 40, "host_runs": 0,
                          "runtime_qualified": False,
                          "binaries": {role: {"path": image["source"], "sha256": image["sha256"]}
                                       for role, image in images.items() if role != "native_engine"}}) + "\n")
        provenance = {"schema": "haproxy-i12-host-input-provenance-v1",
                      "build_completion_seal": str(receipt),
                      "build_completion_seal_sha256": hashlib.sha256(receipt.read_bytes()).hexdigest(),
                      "product_and_capture_revision": "a" * 40,
                      "images": list(images.values())}
        provenance_path = artifacts / "source-provenance.json"
        provenance_path.write_text(json.dumps(provenance) + "\n")
        artifact_ledger = self.base / "artifact-ledger.json"
        artifact_ledger.write_text(json.dumps({"files": {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in artifacts.iterdir()
        }}) + "\n")
        fixture = self.base / "fixture"
        fixture.mkdir()
        contract = fixture / "case-contract.json"
        contract.write_text("{}\n")
        launch = fixture / "launch.py"
        launch.write_text("pass\n")
        fixture_ledger = self.base / "fixture-ledger.json"
        fixture_ledger.write_text(json.dumps({"files": {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in fixture.iterdir()
        }}) + "\n")
        spec = self.base / "spec.json"
        argv = ["/usr/local/bin/python3", "-B", "/mnt/fixtures/launch.py"]
        spec.write_text(json.dumps({"argv": argv, "bindings": [
            {"source": str(artifacts), "target": "/mnt/artifacts", "ledger": str(artifact_ledger),
             "ledger_sha256": hashlib.sha256(artifact_ledger.read_bytes()).hexdigest()},
            {"source": str(fixture), "target": "/mnt/fixtures", "ledger": str(fixture_ledger),
             "ledger_sha256": hashlib.sha256(fixture_ledger.read_bytes()).hexdigest()},
        ]}) + "\n")
        attempt = self.base / "attempt"
        attempt.mkdir()
        admission = attempt / "admission.original.json"
        admission.write_text(json.dumps({"argv": argv}) + "\n")
        spec_hash = hashlib.sha256(spec.read_bytes()).hexdigest()
        controller = {"spec_sha256": spec_hash,
                      "admission_sha256": hashlib.sha256(admission.read_bytes()).hexdigest(),
                      "executed_input_hashes_before": {str(spec): spec_hash},
                      "executed_input_hashes_after": {str(spec): spec_hash}}
        (attempt / "controller-result.json").write_text(json.dumps(controller) + "\n")

        binding = OBSERVER.verified_attempt_inputs(attempt, spec, fixture, binary, receipt)
        self.assertEqual(binding["source_binary_binding"]["required_head"], "a" * 40)
        image = OBSERVER.resolve_sdk_image("/mnt/artifacts/libmodsecurity.so.3", binding)
        self.assertEqual(image["physical_path"], str(sdk))
        self.assertEqual(image["sha256"], hashlib.sha256(sdk.read_bytes()).hexdigest())
        other = self.base / "other-direct"
        other.write_bytes(binary.read_bytes())
        with self.assertRaisesRegex(ValueError, "explicit Direct binary differs"):
            OBSERVER.verified_attempt_inputs(attempt, spec, fixture, other, receipt)
        sdk.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "sealed input hash differs"):
            OBSERVER.verified_attempt_inputs(attempt, spec, fixture, binary, receipt)
        alias = self.base / "sdk-alias"
        alias.symlink_to(sdk)
        sdk_hash = hashlib.sha256(sdk.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, "physical absolute regular file"):
            OBSERVER.require_hash(alias, sdk_hash)
        with self.assertRaisesRegex(ValueError, "unexpected"):
            OBSERVER.resolve_sdk_image("/other/libmodsecurity.so.3", binding)

    def test_canonical_source_request_keeps_duplicate_headers_and_exact_original_id(self):
        name = "duplicate_header_names"
        catalog = {name: {"request": {"method": "GET", "path": "/no-crs/headers/duplicate",
                    "headers": [{"name": "X-No-Crs-Duplicate", "value": "one"},
                                {"name": "X-No-Crs-Duplicate", "value": "two"}]}, "expected_status": 200}}
        case, document = CONTRACTS.canonical_case(name, catalog, self.base, "")
        self.assertIsNone(document)
        expected_headers = b"X-No-Crs-Duplicate: one\r\nX-No-Crs-Duplicate: two\r\n"
        self.assertIn(expected_headers, case["request_wire"])
        original = "I12::haproxy-native-htx::duplicate_header_names"
        case["original_id"] = original
        case["original_requirement_binding"] = {"selected_requirement_sha256": "a" * 64}
        record = CASES.materialize(self.capture, self.base / name, name, case)
        fixture = Path(record["source"])
        contract = json.loads((fixture / "case-contract.json").read_text())
        self.assertEqual(contract["original_id"], original)
        self.assertEqual(contract["request_method"], "GET")
        self.assertEqual(contract["request_path"], "/no-crs/headers/duplicate")
        self.assertIsNone(contract["full_lifecycle_pass"])
        self.assertIn("do_GET = do_POST", (fixture / "backend.py").read_text())

    def test_declarative_chunk_lengths_are_not_replaced_by_default_eights(self):
        case = CASES.cases()["request-streaming"]
        case["request"] = b"no-crs-request-body-marker"
        case["request_chunk_sizes"] = [15, len(case["request"]) - 15]
        record = CASES.materialize(self.capture, self.base / "source-chunks", "source-chunks", case)
        client = (Path(record["source"]) / "client.py").read_text()
        self.assertIn("body[:15],body[15:]", client)
        self.assertNotIn("body[:8],body[8:]", client)

    def test_missing_main_allocation_does_not_borrow_the_neighbor(self):
        client = {"started_wall_ns": 10, "completed_wall_ns": 20}
        contract = {"original_requirement_binding": {}}
        neighbor = {"wall_ns": 30, "allocation_scope_call": 4}
        self.assertIsNone(OBSERVER.select_main_allocation([neighbor], client, contract))
        actual_main = {"wall_ns": 15, "allocation_scope_call": 1}
        self.assertEqual(OBSERVER.select_main_allocation([actual_main, neighbor], client, contract), actual_main)
        ambiguous = [actual_main, {"wall_ns": 16, "allocation_scope_call": 2}]
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            OBSERVER.select_main_allocation(ambiguous, client, contract)

    def test_replaced_inventory_and_source_reuse_cycles_fail_before_preparation(self):
        inventory = {"rows": []}
        with self.assertRaisesRegex(ValueError, "inventory identity differs"):
            CONTRACTS.native_rows(inventory)
        catalog = {"a": {"request": {"reuses": "b"}}, "b": {"request": {"reuses": "a"}}}
        with self.assertRaisesRegex(ValueError, "reuse cycle"):
            CONTRACTS.resolve_request("a", catalog)

    def test_source_barrier_waits_for_actual_client_body_and_rejects_changed_chunks(self):
        response = b"first-byte-prefix no-crs-response-body-marker"
        case = CASES.cases()["response-single-chunk"]
        case["response"] = response
        case["request_path"] = "/i12-main"
        lifecycle = {"synchronization": {"upstream_waits_for_test_barrier": True}}
        CONTRACTS.apply_source_chunks(case, lifecycle, case["request"], response)
        record = CASES.materialize(self.capture, self.base / "causal-barrier", "causal-barrier", case)
        client = (Path(record["source"]) / "client.py").read_text()
        backend = (Path(record["source"]) / "backend.py").read_text()
        self.assertIn("data.split(b'\\r\\n\\r\\n',1)[1]", client)
        self.assertIn("source':'actual_SSLSocket_recv_body_before_backend_release'", client)
        self.assertLess(backend.index("self.wfile.write(prefix)"), backend.index("while not barrier.exists()"))
        self.assertLess(backend.index("while not barrier.exists()"), backend.index("self.wfile.write(response[len(prefix):])"))
        changed = {"request_chunks": ["wrong", "source"]}
        with self.assertRaisesRegex(ValueError, "chunks differ"):
            CONTRACTS.apply_source_chunks({}, changed, case["request"], response)

    def test_common_sink_requires_exact_transaction_identity_and_keeps_other_rows(self):
        sink = self.base / "common-events.jsonl"
        rows = [{"transaction_id": "main", "event": "observed"},
                {"transaction_id": "neighbor", "event": "observed"},
                {"transaction_id": None, "event": "unassociated"}]
        sink.write_text("".join(json.dumps(row) + "\n" for row in rows))
        observed = OBSERVER.common_sink_rows(sink, "main", None)
        self.assertEqual(observed["all_physical_rows"], rows)
        self.assertEqual(observed["exact_main_transaction_rows"], [rows[0]])
        absent = OBSERVER.common_sink_rows(sink, None, None)
        self.assertEqual(absent["exact_main_transaction_rows"], [])

    def test_canonical_p3_response_marker_is_never_added_to_health_neighbor(self):
        case = CASES.cases()["response-single-chunk"]
        case["request_path"] = "/no-crs/full-lifecycle/response-header-deny"
        case["request_method"] = "GET"
        case["response_headers"] = [{"name": "X-Modsec-Upstream", "value": "block"}]
        record = CASES.materialize(self.capture, self.base / "p3-neighbor", "p3-neighbor", case)
        source = (Path(record["source"]) / "backend.py").read_text()
        handler = next(node for node in ast.parse(source).body if isinstance(node, ast.ClassDef) and node.name == "Handler")
        namespace = {"BaseHTTPRequestHandler": object, "hashlib": hashlib, "json": json,
                     "time": __import__("time"), "Path": lambda value: self.base / Path(value).name}
        exec(compile(ast.Module(body=[handler], type_ignores=[]), "p3-backend-handler", "exec"), namespace)
        for path, expected in ((case["request_path"], True), ("/i12-neighbor", False)):
            request = namespace["Handler"]()
            request.path, request.command = path, "GET"
            request.headers, request.rfile, request.wfile = {"Content-Length": "0"}, io.BytesIO(), io.BytesIO()
            emitted = []
            request.send_response = lambda status: None
            request.send_header = lambda name, value: emitted.append((name, value))
            request.end_headers = lambda: None
            request.do_GET()
            self.assertEqual(("X-Modsec-Upstream", "block") in emitted, expected)
            if not expected:
                self.assertEqual(request.wfile.getvalue(), b"healthy\n")



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
