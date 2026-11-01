"""Negative controls for Root-reviewed original I12 host acceptance packets."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from unittest import mock
import tempfile
import unittest


ROOT = connector_root()
LEDGER = load_source(source_path('ci/evidence/reports/generate-pr382-i12-lifecycle-ledger.py', root=ROOT))


class LifecycleLedgerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="i12-lifecycle-ledger-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        authorization = mock.patch.dict(os.environ, {"I12_TEST_ROOT": str(self.root)})
        authorization.start()
        self.addCleanup(authorization.stop)
        self.raw = self.root / "physical-observation.json"
        self.raw.write_text('{"actual_measurement":1}\n')
        self.raw_ref = {"path": str(self.raw), "sha256": hashlib.sha256(self.raw.read_bytes()).hexdigest()}
        self.case = "I12::traefik-native-uds::NEED-request-eos-once"
        self.row = {"run_scoped_case_id": self.case, "leg_id": "traefik-native-uds"}
        self.oracle = {"native_result": "allow", "visible_status": 200, "phase": 2,
                       "physical_evidence_not_projection": True}
        self.packet = {"run_scoped_case_id": self.case, "leg_id": "traefik-native-uds",
                       "reviewed_by": "root", "execution_observed": True, "execution_kind": "host_http",
                       "run_id": "synthetic-validator-control", "parent_sha": "control-parent",
                       "framework_sha": "control-framework", "mrts_sha": "control-mrts",
                       "effective_config_sha256": "control-config", "oracle_evaluated": True,
                       "oracle_sha256": LEDGER.ORACLES.canonical_digest(self.oracle), "outcome": "PASS",
                       "observations": {field: {"value": 1, "evidence": [{**self.raw_ref, "role": role} for role in sorted(roles)]}
                                        for field, roles in LEDGER.ROLES.items()}}

    def review(self, packet=None, oracle=None):
        path = self.root / "reviewed-packet.json"
        path.write_text(json.dumps(self.packet if packet is None else packet))
        ref = LEDGER.ORACLES.reference(path)
        return LEDGER.reviewed_packet(ref, self.row, self.oracle if oracle is None else oracle)

    def test_complete_validator_control_and_measured_failure_are_distinct(self):
        self.assertTrue(self.review()["full_lifecycle_qualified"])
        self.packet["outcome"] = "FAIL"
        self.assertEqual(self.review()["outcome"], "FAIL")

    def test_missing_native_eos_never_uses_client_eof_as_replacement(self):
        self.packet["observations"]["native_eos"] = {"value": None, "reason": "Native EOS was not measured."}
        result = self.review()
        self.assertFalse(result["full_lifecycle_qualified"])
        self.assertIsNone(result["outcome"])
        self.assertEqual(result["unknown_fields"], ["native_eos"])
        self.packet["full_lifecycle_qualified"] = True
        with self.assertRaisesRegex(ValueError, "prevents full qualification"):
            self.review()

    def test_transport_receipt_cannot_prove_native_free(self):
        self.packet["observations"]["native_free_calls"]["evidence"][0]["role"] = "client_process"
        with self.assertRaisesRegex(ValueError, "suitable physical producer"):
            self.review()

    def test_native_call_without_independent_host_eos_producer_is_partial(self):
        self.packet["observations"]["native_eos"]["evidence"] = [{**self.raw_ref, "role": "native_api"}]
        with self.assertRaisesRegex(ValueError, "Independent producers are missing"):
            self.review()

    def test_direct_sdk_mime_accessor_is_native_api_and_transport_cannot_replace_it(self):
        self.packet["observations"]["mime_gate"] = {
            "value": {"native_mime_selection": {"content_type": "text/plain", "selected": True}},
            "evidence": [{**self.raw_ref, "role": "native_api"}]}
        self.assertTrue(self.review()["full_lifecycle_qualified"])
        self.packet["observations"]["mime_gate"]["evidence"][0]["role"] = "client_process"
        with self.assertRaisesRegex(ValueError, "suitable physical producer"):
            self.review()

    def test_unknown_without_reason_is_rejected(self):
        self.packet["observations"]["mime_gate"] = {"value": None}
        with self.assertRaisesRegex(ValueError, "exact missing reason"):
            self.review()

    def test_sibling_case_or_route_cannot_inherit_packet(self):
        for field, replacement in (("leg_id", "traefik-forwardauth-request"),
                                   ("run_scoped_case_id", "I12::traefik-native-uds::allow_without_marker")):
            packet = copy.deepcopy(self.packet)
            packet[field] = replacement
            with self.assertRaisesRegex(ValueError, "sibling route or case"):
                self.review(packet)

    def test_parser_pass_and_driver_exit_are_not_host_verdicts(self):
        self.packet["execution_kind"] = "configuration_parser"
        with self.assertRaisesRegex(ValueError, "actual host HTTP"):
            self.review()
        self.packet["execution_kind"] = "host_http"
        self.packet["outcome"] = "EXIT_0"
        with self.assertRaisesRegex(ValueError, "not a lifecycle verdict"):
            self.review()

    def test_unresolved_oracle_and_missing_root_review_rejected(self):
        self.packet["oracle_sha256"] = "unresolved-oracle"
        with self.assertRaisesRegex(ValueError, "independently reviewed"):
            self.review()
        self.packet["oracle_sha256"] = LEDGER.ORACLES.canonical_digest(self.oracle)
        self.packet["reviewed_by"] = "worker"
        with self.assertRaisesRegex(ValueError, "Root review"):
            self.review()

    def test_nonapplicability_needs_capability_and_never_hides_backend_count(self):
        self.packet["observations"]["mime_gate"] = {
            "value": None, "applicable": False, "reason": "Request-only control, no response engine path.",
            "capability_proof": [{**self.raw_ref, "role": "source_contract"}]}
        self.assertTrue(self.review()["full_lifecycle_qualified"])
        self.packet["observations"]["backend_request_count"] = copy.deepcopy(self.packet["observations"]["mime_gate"])
        with self.assertRaisesRegex(ValueError, "Invalid nonapplicability"):
            self.review()

    def test_altered_physical_evidence_or_symlink_rejected(self):
        self.raw.write_text('{"actual_measurement":2}\n')
        with self.assertRaisesRegex(ValueError, "SHA256"):
            self.review()
        self.raw.write_text('{"actual_measurement":1}\n')
        alias = self.root / "alias.json"
        alias.symlink_to(self.raw)
        self.packet["observations"]["native_free_calls"]["evidence"][0]["path"] = str(alias)
        with self.assertRaisesRegex(ValueError, "physical absolute regular file"):
            self.review()

    def parser_control(self):
        """Synthetic validator control; never exported as host evidence."""
        row, packet, self.oracle = configuration_control(self.root)
        return row, packet

    def parser_review(self, row, packet):
        path = self.root / "parser-packet.json"
        path.write_text(json.dumps(packet))
        return LEDGER.reviewed_configuration_packet(LEDGER.ORACLES.reference(path), row, self.oracle)

    def test_parser_scope_never_becomes_a_host_lifecycle_or_covers_an_http_id(self):
        row, packet = self.parser_control()
        result = self.parser_review(row, packet)
        self.assertTrue(result["full_case_qualified"])
        self.assertFalse(result["full_lifecycle_qualified"])
        self.assertEqual(result["qualification_scope"], "configuration_control")
        row["selected_requirement"]["execution_kind"] = "host_case_or_missing_fixture"
        with self.assertRaisesRegex(ValueError, "original actual_configtest"):
            self.parser_review(row, packet)

    def test_parser_scope_requires_actual_process_image_and_independent_oracle(self):
        row, packet = self.parser_control()
        del packet["actual_observations"]["parser_process"]["waited_exit"]
        with self.assertRaisesRegex(ValueError, "actual argv/cwd"):
            self.parser_review(row, packet)
        row, packet = self.parser_control()
        packet["measurement_evidence"] = [item for item in packet["measurement_evidence"]
                                          if item["role"] != "invoked_image"]
        with self.assertRaisesRegex(ValueError, "independent process, image"):
            self.parser_review(row, packet)
        row, packet = self.parser_control()
        packet["actual_observations"]["parser_process"]["waited_exit"] = 1
        with self.assertRaisesRegex(ValueError, "differs from physical process"):
            self.parser_review(row, packet)


def configuration_control(root):
    """A synthetic control for the existing configuration_parser packet API."""
    def write(name, content, role):
        path = root / name
        path.write_bytes(content if isinstance(content, bytes) else json.dumps(content).encode())
        return {**LEDGER.ORACLES.reference(path), "role": role}

    oracle = {"native_result": "config_accepted", "visible_status": 0, "phase": 0,
              "rule_id": 1100001, "physical_evidence_not_projection": True}
    case_id = "I12::haproxy-spop-request::valid_rules_file"
    row = {"run_scoped_case_id": case_id, "leg_id": "haproxy-spop-request", "required_leg": True,
           "status": "NOT_EXECUTED_UNQUALIFIED", "execution_observed": None,
           "selected_requirement": {"execution_kind": "actual_configtest", "expected_oracle": oracle,
                                    "mandatory_missing_observations": list(LEDGER.CONFIGURATION_FIELDS)}}
    refs = {role: write(role, content, role) for role, content in (
        ("invoked_image", b"synthetic host"), ("native_module", b"synthetic module"),
        ("effective_configuration", b"synthetic config"), ("rules_file", b"synthetic rules"),
        ("parser_stdout", b""), ("parser_stderr", b""),
        ("source_manifest", {"parent_sha": "control-parent"}),
        ("cleanup_observer", {"processes_remaining": 0}), ("isolation_receipt", {"synthetic_isolation": True}),
        ("expectation_source", {"official_contract": "independent synthetic expectation"}))}
    refs["expectation_source"].update(kind="official_host_contract", revision="synthetic-1")
    packet = {"run_scoped_case_id": case_id, "leg_id": row["leg_id"], "reviewed_by": "root",
              "execution_kind": "configuration_parser", "execution_observed": True,
              "run_id": "synthetic-parser-run", "parent_sha": "control-parent",
              "effective_config_sha256": refs["effective_configuration"]["sha256"],
              "rules_sha256": refs["rules_file"]["sha256"], "oracle_evaluated": True,
              "oracle_sha256": LEDGER.ORACLES.canonical_digest(oracle), "outcome": "PASS"}
    process = {"argv": ["/synthetic/parser", "-c", "-f", "/synthetic/config"], "cwd": str(root),
               "waited_exit": 0, "waited_signal": None, "stdout": "", "stderr": "",
               "executable_sha256": refs["invoked_image"]["sha256"]}
    packet["actual_observations"] = {
        "parser_process": process,
        "invocation_identity": {"host_binary_sha256": refs["invoked_image"]["sha256"],
                                "module_sha256": refs["native_module"]["sha256"]},
        "source_config_binding": {name: packet[name] for name in ("parent_sha", "effective_config_sha256", "rules_sha256")},
        "cleanup": {"processes_remaining": 0}}
    actual = {name: packet[name] for name in ("run_scoped_case_id", "leg_id", "run_id", "parent_sha",
             "effective_config_sha256", "rules_sha256", "execution_kind", "execution_observed")}
    refs["parser_process"] = write("process.json", {**actual, **process}, "parser_process")
    packet["measurement_evidence"] = list(refs.values())
    return row, packet, oracle


class ConfigurationLedgerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="i12-configuration-ledger-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        authorization = mock.patch.dict(os.environ, {"I12_TEST_ROOT": str(self.root)})
        authorization.start()
        self.addCleanup(authorization.stop)
        self.row, self.packet, self.oracle = configuration_control(self.root)

    def review(self):
        path = self.root / "packet.json"
        path.write_text(json.dumps(self.packet))
        return LEDGER.reviewed_configuration_packet(LEDGER.ORACLES.reference(path), self.row, self.oracle)

    def process(self):
        return self.packet["actual_observations"]["parser_process"]

    def rebind_process(self):
        ref = next(item for item in self.packet["measurement_evidence"] if item["role"] == "parser_process")
        path = Path(ref["path"])
        actual = json.loads(path.read_text())
        actual.update(self.process())
        path.write_text(json.dumps(actual))
        ref.update(LEDGER.ORACLES.reference(path))

    def bind_rejection_expectation(self):
        process = self.process()
        process.update(first_cause="rules_rejected", stderr="source-bound rules rejection")
        stream = next(item for item in self.packet["measurement_evidence"] if item["role"] == "parser_stderr")
        Path(stream["path"]).write_text(process["stderr"])
        stream.update(LEDGER.ORACLES.reference(Path(stream["path"])))
        ref = next(item for item in self.packet["measurement_evidence"] if item["role"] == "expectation_source")
        Path(ref["path"]).write_text(json.dumps({"reviewed_by": "root", "expected_parser_rejection": {
            "original_contract_sha256": LEDGER.ORACLES.canonical_digest(self.row["selected_requirement"]),
            "oracle_sha256": self.packet["oracle_sha256"], "diagnostic_stream": "stderr",
            "diagnostic_contains": "source-bound rules rejection", "first_cause": "rules_rejected"}}))
        ref.update(LEDGER.ORACLES.reference(Path(ref["path"])))
        self.rebind_process()

    def test_exact_three_original_observations_without_lifecycle_fabrication(self):
        result = self.review()
        self.assertEqual(set(result["mandatory_observations"]), set(LEDGER.CONFIGURATION_FIELDS))
        self.assertTrue(result["full_case_qualified"])
        self.assertFalse(result["full_lifecycle_qualified"])
        self.assertEqual(result["qualification_scope"], "configuration_control")

    def test_exact_rejection_exit_and_truthful_failure(self):
        self.oracle.update(native_result="config_rejected", visible_status=1, rule_id=None)
        self.packet["oracle_sha256"] = LEDGER.ORACLES.canonical_digest(self.oracle)
        self.bind_rejection_expectation()
        self.process()["waited_exit"] = 1
        self.rebind_process()
        self.assertEqual(self.review()["outcome"], "PASS")
        self.process()["waited_exit"] = 77
        self.rebind_process()
        with self.assertRaises(ValueError):
            self.review()
        self.packet["outcome"] = "FAIL"
        self.assertEqual(self.review()["outcome"], "FAIL")

    def test_exact_source_reviewed_rejection_exit_255_is_not_normalized(self):
        self.oracle.update(native_result="config_rejected", visible_status=255, rule_id=None)
        self.packet["oracle_sha256"] = LEDGER.ORACLES.canonical_digest(self.oracle)
        self.bind_rejection_expectation()
        self.process()["waited_exit"] = 255
        self.rebind_process()
        self.assertEqual(self.review()["outcome"], "PASS")
        self.process()["waited_exit"] = 1
        self.rebind_process()
        with self.assertRaisesRegex(ValueError, "contradicts actual exit"):
            self.review()
        self.packet["outcome"] = "FAIL"
        self.assertEqual(self.review()["outcome"], "FAIL")

    def test_parser_expected_exit_must_be_an_exact_posix_code(self):
        for result, code in (("config_rejected", 0), ("config_rejected", -1),
                             ("config_rejected", 256), ("config_rejected", True),
                             ("config_rejected", 1.0), ("config_accepted", 255)):
            with self.subTest(result=result, code=code):
                self.oracle.update(native_result=result, visible_status=code)
                self.packet["oracle_sha256"] = LEDGER.ORACLES.canonical_digest(self.oracle)
                with self.assertRaisesRegex(ValueError, "explicit acceptance or rejection oracle"):
                    self.review()

    def test_missing_rules_file_binds_absence_without_inventing_file_hash(self):
        identity = "I12::haproxy-spop-request::missing_rules_file"
        self.row["run_scoped_case_id"] = identity
        self.packet["run_scoped_case_id"] = identity
        self.oracle.update(native_result="config_rejected", visible_status=1, rule_id=None)
        self.packet["oracle_sha256"] = LEDGER.ORACLES.canonical_digest(self.oracle)
        self.packet["rules_sha256"] = None
        absence = {name: self.packet[name] for name in ("run_scoped_case_id", "leg_id", "run_id", "parent_sha")}
        absence.update(type="physical_path_absence", rules_path="/synthetic/missing.conf", exists=False,
                       measurement="lstat", errno=2, symlink_components=[])
        path = self.root / "absence.json"
        path.write_text(json.dumps(absence))
        ref = {**LEDGER.ORACLES.reference(path), "role": "rules_absence"}
        self.packet["rules_absence_sha256"] = ref["sha256"]
        self.packet["measurement_evidence"] = [item for item in self.packet["measurement_evidence"] if item["role"] != "rules_file"] + [ref]
        binding = self.packet["actual_observations"]["source_config_binding"]
        binding.update(rules_sha256=None, rules_absence_sha256=ref["sha256"])
        process_ref = next(item for item in self.packet["measurement_evidence"] if item["role"] == "parser_process")
        actual_path = Path(process_ref["path"])
        actual = json.loads(actual_path.read_text())
        actual.update(run_scoped_case_id=identity, rules_sha256=None, rules_path=absence["rules_path"], rules_exists=False,
                      rules_lstat_errno=2, rules_absence_sha256=ref["sha256"])
        self.process()["waited_exit"] = 1
        actual.update(self.process())
        actual_path.write_text(json.dumps(actual))
        process_ref.update(LEDGER.ORACLES.reference(actual_path))
        self.bind_rejection_expectation()
        self.assertEqual(self.review()["outcome"], "PASS")
        self.packet["rules_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            self.review()
        self.packet["rules_sha256"] = None
        actual["rules_path"] = "/synthetic/other-missing.conf"
        actual_path.write_text(json.dumps(actual))
        process_ref.update(LEDGER.ORACLES.reference(actual_path))
        with self.assertRaises(ValueError):
            self.review()

    def test_wrong_profile_id_review_kind_and_oracle_rejected(self):
        for name, value in (("run_scoped_case_id", "other"), ("leg_id", "haproxy-native-htx"),
                            ("reviewed_by", "worker"), ("execution_kind", "driver_exit"),
                            ("oracle_sha256", "0" * 64), ("execution_observed", False),
                            ("full_lifecycle_qualified", True)):
            with self.subTest(name=name):
                original = copy.deepcopy(self.packet)
                self.packet[name] = value
                with self.assertRaises(ValueError):
                    self.review()
                self.packet = original

    def test_projected_process_fields_rejected(self):
        for name, value in (("argv", ["driver"]), ("cwd", "/wrong"), ("waited_exit", 1),
                            ("waited_signal", 9), ("stderr", "invented"), ("executable_sha256", "0" * 64)):
            with self.subTest(name=name):
                original = copy.deepcopy(self.packet)
                self.process()[name] = value
                with self.assertRaises(ValueError):
                    self.review()
                self.packet = original

    def test_signal_and_false_pass_fail_without_lifecycle_credit(self):
        self.process()["waited_signal"] = 9
        self.rebind_process()
        with self.assertRaises(ValueError):
            self.review()
        self.packet["outcome"] = "FAIL"
        self.assertFalse(self.review()["full_lifecycle_qualified"])

    def test_missing_required_physical_producers_rejected(self):
        for ref in self.packet["measurement_evidence"][:]:
            with self.subTest(role=ref["role"]):
                original = copy.deepcopy(self.packet)
                self.packet["measurement_evidence"].remove(ref)
                with self.assertRaises(ValueError):
                    self.review()
                self.packet = original

    def test_corrupt_and_symlink_evidence_rejected(self):
        ref = self.packet["measurement_evidence"][0]
        original = copy.deepcopy(ref)
        ref["sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            self.review()
        ref.update(original)
        alias = self.root / "alias"
        alias.symlink_to(Path(ref["path"]))
        ref["path"] = str(alias)
        with self.assertRaises(ValueError):
            self.review()

    def test_independent_expectation_cannot_be_implementation_or_unversioned(self):
        ref = next(item for item in self.packet["measurement_evidence"] if item["role"] == "expectation_source")
        del ref["revision"]
        with self.assertRaises(ValueError):
            self.review()
        ref["revision"] = "synthetic-1"
        ref.update({name: self.packet["measurement_evidence"][0][name] for name in ("path", "sha256", "bytes")})
        with self.assertRaises(ValueError):
            self.review()

    def test_configuration_and_source_identity_changes_rejected(self):
        for name in ("parent_sha", "effective_config_sha256", "rules_sha256"):
            with self.subTest(name=name):
                original = self.packet[name]
                self.packet[name] = "0" * 64
                with self.assertRaises(ValueError):
                    self.review()
                self.packet[name] = original

    def test_physical_stdout_stderr_and_executable_cannot_be_substituted(self):
        for name, value in (("stdout", "invented"), ("stderr", "invented"),
                            ("executable_sha256", "0" * 64), ("cwd", "relative")):
            with self.subTest(name=name):
                original = copy.deepcopy(self.packet)
                self.process()[name] = value
                self.rebind_process()
                with self.assertRaises(ValueError):
                    self.review()
                self.packet = original
                self.rebind_process()

    def test_build_ledger_dispatches_parser_and_preserves_historical_contract(self):
        requirements = {"rows": [self.row]}
        reconciliation = {"original_selected_contracts": [self.row["selected_requirement"]],
                          "oracle_matrix": [], "supplemental_dispositions": [], "summary": {}}
        original = copy.deepcopy(requirements)
        path = self.root / "packet.json"
        path.write_text(json.dumps(self.packet))
        with mock.patch.object(LEDGER.ORACLES, "original_contracts", return_value=requirements["rows"]):
            result = LEDGER.build_ledger(requirements, {}, reconciliation, [LEDGER.ORACLES.reference(path)])
        self.assertEqual(requirements, original)
        row = result["rows"][0]
        self.assertEqual(row["historical_status"], "NOT_EXECUTED_UNQUALIFIED")
        self.assertTrue(row["qualified_configuration_pass"])
        self.assertFalse(row["qualified_host_lifecycle_pass"])
        self.assertIsNone(row["current_lifecycle_packet"])
        self.assertEqual(result["summary"]["current_configuration_pass"], 1)
        self.assertEqual(result["summary"]["full_lifecycle_pass"], 0)


class PreNativeRejectionTests(unittest.TestCase):
    """Physical synthetic controls using actual Apache client/native row shapes."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="i12-pre-native-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        authorization = mock.patch.dict(os.environ, {"I12_TEST_ROOT": str(self.root)})
        authorization.start()
        self.addCleanup(authorization.stop)
        self.name = "invalid_content_length"
        self.case = "I12::apache-native::" + self.name
        self.oracle = copy.deepcopy(LEDGER.PRE_NATIVE_ORACLE)
        self.row = {"run_scoped_case_id": self.case, "leg_id": "apache-native", "required_leg": True,
                    "status": "NOT_EXECUTED_UNQUALIFIED", "execution_observed": False,
                    "selected_requirement": {"case_id": self.name, "run_scoped_case_id": self.case,
                        "requirement_mapping": copy.deepcopy(LEDGER.PRE_NATIVE_MAPPING[self.name]),
                        "expected_oracle": copy.deepcopy(self.oracle)}}
        self.packet = {"run_scoped_case_id": self.case, "leg_id": "apache-native", "reviewed_by": "root",
                       "execution_kind": "host_pre_native_rejection", "execution_observed": True,
                       "oracle_evaluated": True, "oracle_sha256": LEDGER.ORACLES.canonical_digest(self.oracle),
                       "full_lifecycle_qualified": False, "native_transaction_id": None, "outcome": "PASS",
                       "run_id": "control-run", "parent_sha": "control-parent", "framework_sha": "control-framework",
                       "mrts_sha": "control-mrts", "host_pid": 100, "uid": 65534, "host_starttime": 17,
                       "request_id": "main-control", "connection_id": "127.0.0.1:12345"}
        self.contents = {role: {"physical": role} for role in LEDGER.PRE_NATIVE_ROLES}
        self.contents.update({"effective_configuration": b"effective-control-config", "rules_file": b"control-rules",
                              "loaded_image": b"control-host-binary", "native_module": b"control-module",
                              "observer_image": b"control-observer", "request_wire": b"GET /main HTTP/1.1\r\nHost: localhost\r\nX-I12-ID: main-control\r\nContent-Length: invalid\r\n\r\n",
                              "response_wire": b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n",
                              "core_diagnostic": b"[Thu Jan 01 00:00:01.500000 1970] [pid 100] [client 127.0.0.1:12345] AH02429: invalid Content-Length\n",
                              "client_receipt": {"pid": 101, "started_ns": 100, "completed_ns": 200,
                                                 "status": 400, "error": None, "path": "/main"},
                              "client_process": {"argv": ["control-client"], "cwd": str(self.root), "wrapper_pid": 102,
                                                 "waited_exit": 0, "started_unix_ns": 1_000_000_000, "ended_unix_ns": 2_000_000_000},
                              "host_callback": b""})
        self.backend = [{"kind": "request", "request_id": "before-control", "monotonic_ns": 40},
                        {"kind": "request", "request_id": "after-control", "monotonic_ns": 240}]
        self.api = []
        def native(function, edge, timestamp, **extra):
            return {"schema": "native-lifecycle-v1", "pid": 100, "uid": 65534, "run": "control-run",
                    "profile": "apache-native", "invalid": False, "monotonic_ns": timestamp,
                    "function": function, "edge": edge, **extra}
        self.api.append(native("observer", "admitted", 1))
        for timestamp, transaction in ((30, "before-native"), (230, "after-native")):
            # Exercise both actual constructors. No constructor exists for the rejected main request.
            ctor = "native_new" if timestamp == 30 else "native_new_with_id"
            for offset, function in enumerate((ctor, "native_process_request_headers", "native_process_request_body")):
                self.api.append(native(function, "return", timestamp + offset, result=1, transaction_id=transaction))
        self.api.append(native("observer", "final", 300, pending_calls=0, live_mappings=0))
        before_event = json.dumps({"transaction_id": "before-native", "connector": "apache", "message_id": "MSCONN_EVENT_REQUEST_BLOCKED"}).encode() + b"\n"
        after_event = json.dumps({"transaction_id": "after-native", "connector": "apache", "message_id": "MSCONN_EVENT_REQUEST_BLOCKED"}).encode() + b"\n"
        self.sink = self.write("sink", before_event + after_event)
        self.before_event_size, self.sink_size = len(before_event), len(before_event + after_event)
        self.proofs = [self.write("host-source", {"independent_host": "control"}, kind="official_host_contract", revision="control-1"),
                       self.write("protocol-source", {"independent_protocol": "control"}, kind="protocol_contract", revision="control-1")]
        self.event = {"execution_observed": True, "window_complete": True, "observed_from_ns": 90, "observed_through_ns": 210,
                      "sink": self.sink, "before_offset": self.before_event_size, "after_offset": self.before_event_size,
                      "before_control": {"start_offset": 0, "end_offset": self.before_event_size},
                      "after_control": {"start_offset": self.before_event_size, "end_offset": self.sink_size}}
        self.cleanup = {"execution_observed": True, "descriptor_cleanup_observed": True, "process_cleanup_observed": True,
                        "listener_cleanup_observed": True, "remaining_processes": [], "remaining_listeners": [], "unexpected_fd_targets": []}
        self.controls = {}
        for label, start, end in (("before", 20, 50), ("after", 220, 260)):
            self.controls[label] = {"request_id": label + "-control",
                "client_receipt": self.write(label + "-client", {"status": 200, "started_ns": start, "completed_ns": end, "path": "/" + label}),
                "client_process": self.write(label + "-process", {"argv": ["control-client", label], "cwd": str(self.root), "waited_exit": 0})}

    def write(self, name, value, **metadata):
        path = self.root / name
        path.write_bytes(value if isinstance(value, bytes) else json.dumps(value).encode())
        return {**LEDGER.ORACLES.reference(path), **metadata}

    def _bind(self):
        for index, record in enumerate(self.api, 1):
            record["sequence"] = index
            record["case"] = self.name
        self.contents["native_api"] = ("\n".join(json.dumps(r) for r in self.api) + "\n").encode()
        self.contents["backend_process"] = ("\n".join(json.dumps(r) for r in self.backend) + "\n").encode()
        for key, role in (("effective_config_sha256", "effective_configuration"), ("rules_sha256", "rules_file"),
                          ("request_sha256", "request_wire")):
            self.packet[key] = self.write(role, self.contents[role])["sha256"]
        image = {key: self.write(role, self.contents[role])["sha256"] for key, role in
                 (("host_binary_sha256", "loaded_image"), ("module_sha256", "native_module"), ("observer_sha256", "observer_image"))}
        self.contents["source_manifest"] = {"parent_sha": "control-parent", **image}
        mapped_paths = {role: "/loaded/" + role for role in ("loaded_image", "native_module", "observer_image")}
        maps = self.write("process-maps", ("\n".join(mapped_paths.values()) + "\n").encode())
        status = self.write("process-status", b"Pid: 100\nUid: 65534 65534 65534 65534\n")
        self.contents["isolation_receipt"] = {**self.packet, **image, "loaded_images_observed": True,
            "exclusive_request_window": True, "maps": maps, "status": status, "mapped_paths": mapped_paths}
        self.contents["host_callback"] = ("\n".join(json.dumps({"pid": 100, "monotonic_ns": stamp,
            "kind": "host_context_associated", "native_transaction_present": True, "owner_request_matches": True,
            "request_uri": "/" + label}) for stamp, label in ((33, "before"), (233, "after"))) + "\n").encode()
        self.contents["event_observer"] = {**self.packet, **self.event}
        self.contents["cleanup_observer"] = {**self.packet, **self.cleanup}
        self.contents["healthy_controls"] = {**self.packet, **self.controls}
        self.contents["driver_observation"] = {"case_id": self.name, "original_id": self.case, "actual_principal_execution": True,
            "executed_case_contract": True, "missing_operations": [], "clients": [{"role": "main", "request_id": "main-control",
                "actual_waited_exit": self.contents["client_process"]["waited_exit"], "command": self.contents["client_process"]}]}
        self.packet["source_approval"] = {"reviewed_by": "root", "scope": "host_pre_native_rejection",
            "run_scoped_case_id": self.case, "reason": "Independent synthetic source control", "proof": self.proofs,
            "selected_requirement_sha256": LEDGER.ORACLES.canonical_digest(self.row["selected_requirement"]),
            "requirement_mapping_sha256": LEDGER.ORACLES.canonical_digest(self.row["selected_requirement"]["requirement_mapping"]),
            "oracle_sha256": self.packet["oracle_sha256"], "request_sha256": self.packet["request_sha256"], "core_diagnostic_code": "AH02429"}
        self.packet["measurement_evidence"] = [self.write(role, value, role=role) for role, value in self.contents.items()]
        return self.write("packet", self.packet)

    def review(self):
        return LEDGER.reviewed_pre_native_packet(self._bind(), self.row, self.oracle)

    def test_separate_pre_native_scope_preserves_native_alternative_and_no_fake_lifecycle(self):
        result = self.review()
        self.assertTrue(result["full_case_qualified"])
        self.assertFalse(result["full_lifecycle_qualified"])
        self.assertIsNone(result["observations"]["main_native_transaction_id"])
        self.assertEqual(self.oracle["native_result"], "rejected_by_host_before_connector_or_connector_rejection")
        self.assertEqual(len(LEDGER.ROLES), 35)

    def test_untrusted_long_process_status_cannot_supply_pid_or_uid(self):
        """I12-SONAR-STATUS: bound physical status rejects hostile whitespace."""
        self._bind()
        producers = {item["role"]: item for item in self.packet["measurement_evidence"]}
        source = json.loads(Path(producers["source_manifest"]["path"]).read_text())
        isolation = copy.deepcopy(self.contents["isolation_receipt"])
        for field in ("Pid:", "Uid:"):
            status = (field + " " * 200_000 + "not-a-number\n").encode()
            isolation["status"] = self.write("hostile-status", status)
            producers["isolation_receipt"] = self.write("hostile-isolation", isolation)
            with self.subTest(field=field), self.assertRaises(ValueError):
                LEDGER.pre_native_isolation_binding(self.packet, producers, source)

    def test_unterminated_long_pid_diagnostic_cannot_qualify_another_process(self):
        """I12-SONAR-PID: an unterminated PID token never joins a sibling."""
        self.contents["core_diagnostic"] = (
            b"[Thu Jan 01 00:00:01.500000 1970] " + b"[pid 100" * 20_000
            + b" [pid 1000] [client 127.0.0.1:12345] AH02429: invalid Content-Length\n")
        with self.assertRaises(ValueError):
            self.review()

    def test_each_of_four_original_mappings_can_use_only_the_dedicated_scope(self):
        for name, mapping in LEDGER.PRE_NATIVE_MAPPING.items():
            self.name = name
            self.case = "I12::apache-native::" + name
            self.row["run_scoped_case_id"] = self.case
            self.row["selected_requirement"].update(case_id=name, run_scoped_case_id=self.case,
                                                     requirement_mapping=copy.deepcopy(mapping))
            self.packet["run_scoped_case_id"] = self.case
            with self.subTest(name=name):
                self.assertFalse(self.review()["full_lifecycle_qualified"])

    def test_only_four_original_id_mappings_and_unchanged_oracle_are_eligible(self):
        for mutation in ("id", "mapping", "oracle", "native-id", "lifecycle", "phase", "phase-bool", "status-float", "root"):
            original_packet, original_row, original_oracle = copy.deepcopy(self.packet), copy.deepcopy(self.row), copy.deepcopy(self.oracle)
            if mutation == "id":
                self.row["selected_requirement"]["case_id"] = "other"
            elif mutation == "mapping":
                self.row["selected_requirement"]["requirement_mapping"] = []
            elif mutation == "oracle":
                self.row["selected_requirement"]["expected_oracle"]["visible_status"] = 200
            elif mutation == "native-id":
                self.packet["native_transaction_id"] = "invented"
            elif mutation == "lifecycle":
                self.packet["full_lifecycle_qualified"] = True
            elif mutation == "phase":
                self.oracle["phase"] = 2
            elif mutation == "phase-bool":
                self.oracle["phase"] = True
            elif mutation == "status-float":
                self.oracle["visible_status"] = 400.0
            else:
                self.packet["reviewed_by"] = "worker"
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.review()
            self.packet, self.row, self.oracle = original_packet, original_row, original_oracle

    def test_observer_admission_final_zero_window_and_positive_api_controls_are_mandatory(self):
        original = copy.deepcopy(self.api)
        for mutation in ("empty", "no-before", "no-after", "no-admission", "no-final", "main-call", "pid", "uid", "bool-result"):
            self.api = copy.deepcopy(original)
            if mutation == "empty":
                self.api = []
            elif mutation == "no-before":
                self.api = [r for r in self.api if r["monotonic_ns"] >= 100 or r["function"] == "observer"]
            elif mutation == "no-after":
                self.api = [r for r in self.api if r["monotonic_ns"] <= 200 or r["function"] == "observer"]
            elif mutation == "no-admission":
                self.api = [r for r in self.api if r["edge"] != "admitted"]
            elif mutation == "no-final":
                self.api = [r for r in self.api if r["edge"] != "final"]
            elif mutation == "main-call":
                self.api.append({**self.api[1], "monotonic_ns": 150})
            elif mutation == "pid":
                for r in self.api: r["pid"] = 999
            elif mutation == "uid":
                self.api[0]["uid"] = 0
            else:
                self.api[1]["result"] = True
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.review()
        self.api = original

    def test_client400_core_diagnostic_backend_and_physical_event_window_are_independent(self):
        original_contents, original_event, original_backend = copy.deepcopy(self.contents), copy.deepcopy(self.event), copy.deepcopy(self.backend)
        for mutation in ("wire", "client", "exit", "core", "core-pid", "core-stale", "backend", "event-gap", "event-positive", "event-bytes", "event-unrelated"):
            self.contents, self.event, self.backend = copy.deepcopy(original_contents), copy.deepcopy(original_event), copy.deepcopy(original_backend)
            if mutation == "wire":
                self.contents["response_wire"] = b"HTTP/1.1 200 OK\r\n\r\n"
            elif mutation == "client":
                self.contents["client_receipt"]["status"] = 200
            elif mutation == "exit":
                self.contents["client_process"]["waited_exit"] = 1
            elif mutation == "core":
                self.contents["core_diagnostic"] = b"Apache configured only"
            elif mutation == "core-pid":
                self.contents["core_diagnostic"] = self.contents["core_diagnostic"].replace(b"pid 100", b"pid 1000")
            elif mutation == "core-stale":
                self.contents["core_diagnostic"] = self.contents["core_diagnostic"].replace(b"00:00:01", b"00:00:03")
            elif mutation == "backend":
                self.backend.append({"kind": "request", "request_id": "main-control", "monotonic_ns": 150})
            elif mutation == "event-gap":
                self.event["window_complete"] = False
            elif mutation == "event-positive":
                self.event["before_control"]["end_offset"] = 0
            elif mutation == "event-unrelated":
                self.event["sink"] = self.write("unrelated-event", b"{}\n")
            else:
                self.event["after_offset"] = self.before_event_size + 1
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.review()
        self.contents, self.event, self.backend = original_contents, original_event, original_backend

    def test_cleanup_and_healthy_controls_cannot_be_projected(self):
        self.cleanup["unexpected_fd_targets"] = ["leaked-file"]
        with self.assertRaises(ValueError): self.review()
        self.cleanup["unexpected_fd_targets"] = []
        self.controls["before"]["request_id"] = "unobserved-request"
        with self.assertRaises(ValueError): self.review()

    def test_missing_stale_sibling_source_and_image_producers_are_rejected(self):
        ref = self._bind()
        original = copy.deepcopy(self.packet)
        for mutation in ("source-approval", "source-alias", "missing", "hash", "source", "isolation", "stub", "cleanup-id"):
            self.packet = copy.deepcopy(original)
            if mutation == "source-approval":
                self.packet["source_approval"]["reviewed_by"] = "worker"
            elif mutation == "source-alias":
                proof = self.packet["source_approval"]["proof"]
                proof[1] = {**proof[0], "kind": "protocol_contract"}
            elif mutation == "missing":
                self.packet["measurement_evidence"].pop()
            elif mutation == "hash":
                self.packet["measurement_evidence"][0]["sha256"] = "0" * 64
            else:
                role = {"source": "source_manifest", "isolation": "isolation_receipt", "stub": "driver_observation", "cleanup-id": "cleanup_observer"}[mutation]
                item = next(p for p in self.packet["measurement_evidence"] if p["role"] == role)
                actual = json.loads(Path(item["path"]).read_text())
                if mutation == "source": actual["parent_sha"] = "other-parent"
                elif mutation == "isolation": actual["module_sha256"] = "wrong-image"
                elif mutation == "stub": actual["executed_case_contract"] = False
                else: actual["request_id"] = "sibling-request"
                self.packet["measurement_evidence"] = [self.write(role, actual, role=role) if p["role"] == role else p for p in self.packet["measurement_evidence"]]
            packet_ref = self.write("packet", self.packet)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                LEDGER.reviewed_pre_native_packet(packet_ref, self.row, self.oracle)
            self._bind()

    def test_build_ledger_counts_full_case_without_host_lifecycle_or_configuration_credit(self):
        ref = self._bind()
        requirements = {"rows": [self.row]}
        reconciliation = {"original_selected_contracts": [self.row["selected_requirement"]],
                          "oracle_matrix": [], "supplemental_dispositions": [], "summary": {}}
        with mock.patch.object(LEDGER.ORACLES, "original_contracts", return_value=requirements["rows"]):
            result = LEDGER.build_ledger(requirements, {}, reconciliation, [ref])
        row = result["rows"][0]
        self.assertEqual(row["qualification_scope"], "host_pre_native_rejection")
        self.assertTrue(row["qualified_full_case_pass"])
        self.assertFalse(row["qualified_host_lifecycle_pass"])
        self.assertFalse(row["qualified_configuration_pass"])
        self.assertIsNone(row["current_lifecycle_packet"])
        self.assertEqual(result["summary"]["pre_native_rejection_pass"], 1)
        self.assertEqual(result["summary"]["full_lifecycle_pass"], 0)
        self.assertEqual(result["summary"]["required_qualified_pass"], 1)


class LighttpdPreNativeRejectionTests(unittest.TestCase):
    """Separate lighttpd source/log/FD contract; no Apache format fallback."""

    write = PreNativeRejectionTests.write
    review = PreNativeRejectionTests.review

    def setUp(self):
        PreNativeRejectionTests.setUp(self)
        self.leg = "lighttpd-stock-native-control"
        self.case = "I12::" + self.leg + "::" + self.name
        self.row.update(run_scoped_case_id=self.case, leg_id=self.leg, required_leg=False)
        self.row["selected_requirement"].update(run_scoped_case_id=self.case,
            requirement_mapping=copy.deepcopy(LEDGER.LIGHTTPD_PRE_NATIVE_MAPPING[self.name]))
        self.packet.update(run_scoped_case_id=self.case, leg_id=self.leg)
        for record in self.api:
            record["profile"] = self.leg
            record["allocation_scope_call"] = 30 if record["monotonic_ns"] < 100 else 230
        self.backend = [{"schema": "apache-independent-backend-v1", "pid": 111, "uid": 65534,
                         "path": "/" + label, "monotonic_ns": stamp}
                        for label, stamp in (("before", 40), ("after", 240))]
        for label in ("before", "after"):
            self.controls[label]["request_id"] = "/" + label
        raw = Path(self.sink["path"]).read_bytes().replace(b'"connector": "apache"', b'"connector": "lighttpd"')
        self.event["sink"] = self.write("lighttpd-sink", raw)
        boundary = len(raw.splitlines(keepends=True)[0])
        self.event.update(before_offset=boundary, after_offset=boundary,
            before_control={"start_offset": 0, "end_offset": boundary},
            after_control={"start_offset": boundary, "end_offset": len(raw)})
        self.message = "invalid Content-Length header -> 400"
        self.core = ("1970-01-01 00:00:01.500000000: (/official/src/request.c.327) " + self.message + "\n"
            "1970-01-01 00:00:01.500000001: (/official/src/request.c.1414) rqst: POST /main HTTP/1.1\n"
            "1970-01-01 00:00:01.500000002: (/official/src/request.c.1414) rqst: X-I12-ID: main-control\n").encode()
        self.fd = {"device": 1, "inode": 2, "mode": 0o600, "owner_uid": 65534, "nlink": 1}
        self.point = {**self.fd, "path": "/task/control/host-error.log", "uid": 65534}
        self.hosts = [{"pid": 100, "starttime": 17, "fds": {"3": self.point["path"]}, "fd_metadata": {"3": self.fd}}]
        self.host_callbacks = [{"schema": "lighttpd-stock-diagnostic-host-v1", "pid": 100, "uid": 65534,
            "kind": "request_decision_returned", "runtime_allocation_scope_call": scope,
            "host_transaction_id": label + "-native", "technical_failed": 0, "api_failed": 0,
            "request_intervened": 0, "monotonic_ns": stamp}
            for label, scope, stamp in (("before", 30, 33), ("after", 230, 233))]
        self.window_changes = {}

    def _bind(self):
        PreNativeRejectionTests._bind(self)
        self.contents["core_diagnostic"] = self.core
        self.contents["host_callback"] = ("\n".join(json.dumps(r) for r in self.host_callbacks) + "\n").encode()
        core = self.write("core_diagnostic", self.core)
        keys = ("run_scoped_case_id", "leg_id", "run_id", "parent_sha", "effective_config_sha256", "rules_sha256",
                "host_pid", "host_starttime", "uid", "request_id", "request_sha256")
        window = {key: self.packet[key] for key in keys}
        window.update(execution_observed=True, exclusive_request_window=True, core_sha256=core["sha256"],
            before={**self.point, "monotonic_ns": 90, "size": 0},
            after={**self.point, "monotonic_ns": 210, "size": len(self.core)},
            actual_host_identity=self.write("actual-host-identity", self.hosts))
        window.update(self.window_changes)
        self.contents["core_diagnostic_window"] = window
        self.packet["source_approval"]["core_diagnostic_code"] = self.message
        self.packet["measurement_evidence"] = [self.write(role, value, role=role) for role, value in self.contents.items()]
        return self.write("packet", self.packet)

    def test_exact_three_diagnostic_contracts_preserve_false_lifecycle_credit(self):
        for name, mapping in LEDGER.LIGHTTPD_PRE_NATIVE_MAPPING.items():
            self.name = name
            self.case = "I12::" + self.leg + "::" + name
            self.row["run_scoped_case_id"] = self.case
            self.row["selected_requirement"].update(case_id=name, run_scoped_case_id=self.case, requirement_mapping=copy.deepcopy(mapping))
            self.packet["run_scoped_case_id"] = self.case
            message = "duplicate Content-Length header -> 400" if name == "conflicting_content_length" else "invalid Content-Length header -> 400"
            self.core = self.core.replace(self.message.encode(), message.encode())
            self.message = message
            with self.subTest(case=name):
                result = self.review()
                self.assertTrue(result["full_case_qualified"])
                self.assertFalse(result["full_lifecycle_qualified"])
                self.assertIsNone(result["observations"]["main_native_transaction_id"])

    def test_no_duplicate_te_sibling_or_changed_original_mapping(self):
        self.row["selected_requirement"]["case_id"] = "duplicate_transfer_encoding"
        with self.assertRaises(ValueError):
            self.review()
        self.row["selected_requirement"]["case_id"] = self.name
        self.row["selected_requirement"]["requirement_mapping"] = LEDGER.PRE_NATIVE_MAPPING[self.name]
        with self.assertRaises(ValueError):
            self.review()
        self.row["selected_requirement"]["requirement_mapping"] = LEDGER.LIGHTTPD_PRE_NATIVE_MAPPING[self.name]
        self.row["leg_id"] = "lighttpd-patched-native"
        with self.assertRaises(ValueError):
            self.review()

    def test_pidless_core_requires_actual_host_fd_and_private_complete_window(self):
        original_point, original_hosts = copy.deepcopy(self.point), copy.deepcopy(self.hosts)
        for mutation in ("inode", "uid", "mode", "pid", "fd", "gap", "wrong-core"):
            self.point, self.hosts, self.window_changes = copy.deepcopy(original_point), copy.deepcopy(original_hosts), {}
            if mutation == "inode": self.hosts[0]["fd_metadata"]["3"]["inode"] += 1
            elif mutation == "uid": self.point["owner_uid"] = 0
            elif mutation == "mode": self.point["mode"] = 0o644
            elif mutation == "pid": self.hosts[0]["pid"] = 999
            elif mutation == "fd": self.hosts[0]["fds"]["3"] = "/another/log"
            elif mutation == "gap": self.window_changes["after"] = {**self.point, "monotonic_ns": 199, "size": len(self.core)}
            else: self.window_changes["core_sha256"] = "0" * 64
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.review()

    def test_apache_log_schema_stale_clock_and_other_request_cannot_substitute(self):
        original = self.core
        for mutation in ("apache", "stale", "path", "request-id", "precision"):
            self.core = original
            if mutation == "apache": self.core = b"[Thu Jan 01 00:00:01.500000 1970] [pid 100] [client 127.0.0.1:12345] AH02429\n"
            elif mutation == "stale": self.core = original.replace(b"00:00:01", b"00:00:03")
            elif mutation == "path": self.core = original.replace(b"POST /main", b"POST /other")
            elif mutation == "request-id": self.core = original.replace(b"main-control", b"other-control")
            else: self.core = original.replace(b".500000000", b".500000")
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.review()

    def test_apache_host_backend_or_event_aliases_do_not_validate_lighttpd(self):
        self.host_callbacks[0]["schema"] = "apache-host-v1"
        with self.assertRaises(ValueError):
            self.review()
        self.host_callbacks[0]["schema"] = "lighttpd-stock-diagnostic-host-v1"
        self.backend[0]["uid"] = 0
        with self.assertRaises(ValueError):
            self.review()
        self.backend[0]["uid"] = 65534
        raw = Path(self.event["sink"]["path"]).read_bytes().replace(b'"connector": "lighttpd"', b'"connector": "apache"')
        self.event["sink"] = self.write("wrong-connector", raw)
        with self.assertRaises(ValueError):
            self.review()



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
