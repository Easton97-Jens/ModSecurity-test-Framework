#!/usr/bin/env python3
"""Bind reviewed Parent I12 host measurements to the unchanged original catalog.

This acceptance ledger does not create observations. A Root-reviewed verdict
requires physical evidence for every applicable field. Parser-only passes and
historical partial executions remain separate from full host lifecycle results.
"""
from modsecurity_test_framework.connector_context import load_source
import argparse
import copy
import datetime
import hashlib
import importlib.util
import json
import re
from pathlib import Path


def oracle_module():
    path = Path(__file__).with_name("generate-pr382-i12-oracle-reconciliation.py")
    module = load_source(path)
    return module


ORACLES = oracle_module()
PATHS = ORACLES.PATHS
CONFIGURATION_FIELDS = (
    "actual-config-parser-argv-cwd-exit-signal-stderr",
    "source-host-module-effective-config-identity",
    "expected-parser-acceptance-or-rejection",
)
ROLES = {
    "product_host_identity": {"loaded_image", "isolation_receipt"},
    "source_config_binding": {"source_manifest", "effective_configuration"},
    "capability": {"host_callback", "source_contract"},
    "client_exit": {"client_process"},
    "client_signal": {"client_process"},
    "client_headers": {"client_process"},
    "client_bytes": {"client_process"},
    "client_sha256": {"client_process"},
    "backend_request_count": {"backend_process"},
    "backend_payload_identity": {"backend_process", "client_process"},
    "client_backend_correlation": {"backend_process", "client_process"},
    "native_events": {"physical_event_sink"},
    "native_api_returns": {"native_api"},
    "native_transaction_id": {"native_api"},
    "common_transaction_id": {"native_api"},
    "observed_handle_association": {"native_api"},
    "native_phases": {"native_api", "native_debug"},
    "native_body_chunks": {"native_api"},
    "native_intervention_or_first_cause": {"native_api"},
    "host_eos": {"host_callback"},
    "native_eos": {"native_api", "host_callback"},
    "commit_order": {"host_callback", "client_process"},
    "mime_gate": {"native_debug", "physical_event_sink", "native_api"},
    "finish_calls": {"native_api"},
    "finish_transitions": {"native_api"},
    "native_free_calls": {"native_api"},
    "cleanup_receipts": {"cleanup_observer", "isolation_receipt"},
    "descriptor_cleanup": {"cleanup_observer"},
    "process_listener_cleanup": {"cleanup_observer", "isolation_receipt"},
    "neighbor_health": {"client_process", "backend_process"},
    "transport_framing": {"client_process"},
    "transport_reset_scope": {"client_process", "host_callback"},
    "host_action": {"host_callback", "client_process"},
    "physical_event_order": {"physical_event_sink"},
    "terminal_event_count": {"physical_event_sink"},
}
# These observations are required even for a request-only route or an early deny.
ALWAYS_APPLICABLE = frozenset((
    "product_host_identity", "source_config_binding", "capability", "client_exit",
    "client_signal", "client_headers", "client_bytes", "client_sha256",
    "backend_request_count", "native_api_returns", "native_transaction_id",
    "observed_handle_association", "native_phases", "native_intervention_or_first_cause",
    "finish_calls", "native_free_calls", "cleanup_receipts", "descriptor_cleanup",
    "process_listener_cleanup", "neighbor_health", "transport_framing", "host_action",
))
REQUIRED_ROLES = {
    "product_host_identity": {"loaded_image", "isolation_receipt"},
    "source_config_binding": {"source_manifest", "effective_configuration"},
    "capability": {"host_callback", "source_contract"},
    "backend_payload_identity": {"backend_process", "client_process"},
    "client_backend_correlation": {"backend_process", "client_process"},
    "native_eos": {"native_api", "host_callback"},
    "commit_order": {"host_callback", "client_process"},
    "cleanup_receipts": {"cleanup_observer", "isolation_receipt"},
    "process_listener_cleanup": {"cleanup_observer", "isolation_receipt"},
    "neighbor_health": {"client_process", "backend_process"},
}


def nonapplicable_measurement(field, item):
    value = item.get("value")
    if field in ALWAYS_APPLICABLE or value is not None or not item.get("reason"):
        raise ValueError(f"Invalid nonapplicability for {field}")
    proofs = [ORACLES.verify_reference(ref) for ref in item.get("capability_proof", [])]
    if not proofs or any(ref.get("role") != "source_contract" for ref in proofs):
        raise ValueError(f"Nonapplicability needs a source-bound capability proof: {field}")
    item["capability_proof"] = proofs


def measurement_proofs(field, item, packet_path):
    proofs = [ORACLES.verify_reference(ref) for ref in item.get("evidence", [])]
    if not proofs or any(ref.get("role") not in ROLES[field] for ref in proofs):
        raise ValueError(f"Observation has no suitable physical producer: {field}")
    if not REQUIRED_ROLES.get(field, set()) <= {ref.get("role") for ref in proofs}:
        raise ValueError(f"Independent producers are missing for {field}")
    if any(ref["path"] == str(packet_path) for ref in proofs):
        raise ValueError("A reviewed packet cannot be its own measurement")
    if field != "capability" and all(ref.get("role") == "source_contract" for ref in proofs):
        raise ValueError("A source contract does not prove actual execution")
    return proofs


def measurement(field, supplied, packet_path):
    """Missing data stays unknown; source contracts cannot substitute for calls."""
    item = copy.deepcopy(supplied)
    applicable = item.get("applicable", True)
    value = item.get("value")
    if applicable is False:
        nonapplicable_measurement(field, item)
        return item, True
    if applicable is not True:
        raise ValueError("Applicability must be a literal boolean")
    if value is None:
        if not item.get("reason"):
            raise ValueError(f"Unknown observation needs an exact missing reason: {field}")
        return item, False
    proofs = measurement_proofs(field, item, packet_path)
    item["evidence"] = proofs
    return item, True


def validate_host_packet_identity(packet, row):
    if packet.get("reviewed_by") != "root":
        raise ValueError("Host packet requires explicit Root review")
    if (packet.get("run_scoped_case_id") != row["run_scoped_case_id"] or
            packet.get("leg_id") != row["leg_id"]):
        raise ValueError("Packet cannot transfer to a sibling route or case")
    if packet.get("execution_observed") is not True or packet.get("execution_kind") != "host_http":
        raise ValueError("A full lifecycle packet requires an actual host HTTP transaction")
    for name in ("run_id", "parent_sha", "framework_sha", "mrts_sha", "effective_config_sha256"):
        if not packet.get(name):
            raise ValueError(f"Missing actual packet identity: {name}")
    if set(packet.get("observations", {})) != set(ROLES):
        raise ValueError("Packet must preserve every prescribed observation field")


def reviewed_packet(supplied, row, effective_oracle):
    ref = ORACLES.verify_reference(supplied)
    path = Path(ref["path"])
    packet = json.loads(PATHS.read_text(path))
    validate_host_packet_identity(packet, row)
    values, known = {}, []
    for name, observation in packet["observations"].items():
        values[name], complete = measurement(name, observation, path)
        known.append(complete)
    evaluated = packet.get("oracle_evaluated") is True
    if evaluated and (effective_oracle is None or
                      packet.get("oracle_sha256") != ORACLES.canonical_digest(effective_oracle)):
        raise ValueError("Evaluation does not bind the independently reviewed effective oracle")
    verdict = packet.get("outcome")
    if verdict not in (None, "PASS", "FAIL"):
        raise ValueError("A driver exit or transport result is not a lifecycle verdict")
    full = all(known) and evaluated and verdict is not None
    if packet.get("full_lifecycle_qualified") is True and not full:
        raise ValueError("A missing observation or unresolved oracle prevents full qualification")
    return {"receipt": ref, "observations": values, "execution_observed": True,
            "full_lifecycle_qualified": full, "outcome": verdict if full else None,
            "unknown_fields": [name for name, item in values.items()
                               if item.get("applicable", True) and item.get("value") is None]}


def validate_configuration_rules(packet, row):
    absent_rules = packet.get("rules_absence_sha256")
    if absent_rules:
        if (row["run_scoped_case_id"].split("::")[-1] != "missing_rules_file"
                or "rules_sha256" not in packet or packet["rules_sha256"] is not None):
            raise ValueError("Rules absence is only valid for the original missing-rules contract; unloaded rules stay null")
    elif not packet.get("rules_sha256"):
        raise ValueError("Missing parser identity: rules_sha256")


def validate_configuration_identity(packet, row, effective_oracle):
    selected = row["selected_requirement"]
    if selected.get("execution_kind") != "actual_configtest":
        raise ValueError("Only an original actual_configtest contract permits parser qualification")
    if set(selected.get("mandatory_missing_observations", [])) != set(CONFIGURATION_FIELDS):
        raise ValueError("Parser qualification must preserve the original three observations")
    if (packet.get("reviewed_by") != "root"
            or packet.get("run_scoped_case_id") != row["run_scoped_case_id"]
            or packet.get("leg_id") != row["leg_id"]):
        raise ValueError("Configuration packet requires Root review of the exact original ID")
    if packet.get("execution_kind") != "configuration_parser" or packet.get("execution_observed") is not True:
        raise ValueError("Configuration qualification requires an observed parser process")
    if packet.get("full_lifecycle_qualified") is True:
        raise ValueError("Configuration qualification cannot claim a host lifecycle")
    for name in ("run_id", "parent_sha", "effective_config_sha256"):
        if not packet.get(name):
            raise ValueError(f"Missing parser identity: {name}")
    validate_configuration_rules(packet, row)
    if (packet.get("oracle_evaluated") is not True or effective_oracle is None
            or packet.get("oracle_sha256") != ORACLES.canonical_digest(effective_oracle)):
        raise ValueError("Parser evaluation must bind the independently reviewed effective oracle")


def configuration_measurements(packet, ref):
    roles = {"parser_process", "source_manifest", "effective_configuration", "invoked_image",
             "cleanup_observer", "isolation_receipt", "native_module",
             "parser_stdout", "parser_stderr", "expectation_source"}
    roles.add("rules_absence" if packet.get("rules_absence_sha256") else "rules_file")
    evidence = [ORACLES.verify_reference(item) for item in packet.get("measurement_evidence", [])]
    if roles != {item.get("role") for item in evidence} or len(evidence) != len(roles):
        raise ValueError("Parser packet lacks independent process, image, source/config or cleanup producers")
    if any(item["path"] == ref["path"] for item in evidence):
        raise ValueError("Parser packet cannot be its own measurement")
    observed = packet.get("actual_observations", {})
    process = observed.get("parser_process", {})
    if (not process.get("argv") or not process.get("cwd")
            or type(process.get("waited_exit")) is not int
            or "waited_signal" not in process or "stdout" not in process or "stderr" not in process):
        raise ValueError("Parser packet needs actual argv/cwd/exit/signal/stdout/stderr")
    for name in ("invocation_identity", "source_config_binding", "cleanup"):
        if not observed.get(name):
            raise ValueError(f"Parser packet lacks actual {name}")
    producers = {item["role"]: item for item in evidence}
    configuration_process_binding(packet, process, producers)
    configuration_source_binding(packet, observed, producers)
    independent = producers["expectation_source"]
    implementation_hashes = {item["sha256"] for item in evidence if item["role"] != "expectation_source"}
    if (independent.get("kind") not in ORACLES.INDEPENDENT_KINDS or not independent.get("revision")
            or independent["sha256"] in implementation_hashes):
        raise ValueError("Parser expectation requires a separate revisioned independent source")
    return observed


def configuration_process_binding(packet, process, producers):
    """Match a physical parser receipt; the driver's exit cannot substitute."""
    actual = json.loads(PATHS.read_text(producers["parser_process"]["path"]))
    for name in ("run_scoped_case_id", "leg_id", "run_id", "parent_sha", "effective_config_sha256", "rules_sha256",
                 "execution_kind", "execution_observed"):
        if actual.get(name) != packet[name]:
            raise ValueError(f"Parser process identity differs: {name}")
    if packet.get("rules_absence_sha256"):
        configuration_rules_absence(packet, actual, producers["rules_absence"])
    for name in ("argv", "cwd", "waited_exit", "waited_signal", "stdout", "stderr", "executable_sha256"):
        if name not in process or actual.get(name) != process[name]:
            raise ValueError(f"Parser observation differs from physical process: {name}")
    if (not isinstance(process["argv"], list) or not process["argv"]
            or any(not isinstance(arg, str) or not arg for arg in process["argv"])
            or not isinstance(process["cwd"], str) or not Path(process["cwd"]).is_absolute()
            or process["executable_sha256"] != producers["invoked_image"]["sha256"]):
        raise ValueError("Actual parser argv/cwd/executable identity is required")
    for stream in ("stdout", "stderr"):
        content = process[stream]
        if not isinstance(content, str) or hashlib.sha256(content.encode()).hexdigest() != producers["parser_" + stream]["sha256"]:
            raise ValueError(f"Parser {stream} differs from physical stream bytes")


def configuration_rules_absence(packet, actual, ref):
    """The attempted missing path has an absence receipt, never a file hash."""
    absence = json.loads(PATHS.read_text(ref["path"]))
    if (absence.get("type") != "physical_path_absence" or absence.get("exists") is not False
            or absence.get("measurement") != "lstat" or absence.get("errno") != 2
            or absence.get("symlink_components") != [] or actual.get("rules_lstat_errno") != 2
            or not isinstance(absence.get("rules_path"), str) or not Path(absence["rules_path"]).is_absolute()
            or actual.get("rules_path") != absence["rules_path"] or actual.get("rules_exists") is not False
            or actual.get("rules_absence_sha256") != packet["rules_absence_sha256"]
            or ref["sha256"] != packet["rules_absence_sha256"]):
        raise ValueError("Missing rules need the actual attempted absolute path and physical absence measurement")
    for name in ("run_scoped_case_id", "leg_id", "run_id", "parent_sha"):
        if absence.get(name) != packet[name]:
            raise ValueError(f"Rules absence belongs to a different execution: {name}")


def configuration_source_binding(packet, observed, producers):
    """Bind every invoked image and effective parser input to physical bytes."""
    identity = observed["invocation_identity"]
    binding = observed["source_config_binding"]
    for field, role in (("host_binary_sha256", "invoked_image"), ("module_sha256", "native_module")):
        if identity.get(field) != producers[role]["sha256"]:
            raise ValueError(f"Parser image identity differs: {field}")
    rules_binding = (("rules_absence_sha256", "rules_absence") if packet.get("rules_absence_sha256")
                     else ("rules_sha256", "rules_file"))
    for field, role in (("effective_config_sha256", "effective_configuration"), rules_binding):
        if packet[field] != producers[role]["sha256"] or binding.get(field) != packet[field]:
            raise ValueError(f"Parser effective input identity differs: {field}")
    if packet.get("rules_absence_sha256") and binding.get("rules_sha256", "missing") is not None:
        raise ValueError("An unloaded missing rules file has no rules SHA256")
    source = json.loads(PATHS.read_text(producers["source_manifest"]["path"]))
    if binding.get("parent_sha") != packet["parent_sha"] or source.get("parent_sha") != packet["parent_sha"]:
        raise ValueError("Parser source revision differs from actual source manifest")
    cleanup = json.loads(PATHS.read_text(producers["cleanup_observer"]["path"]))
    if observed["cleanup"] != cleanup:
        raise ValueError("Parser cleanup differs from physical observer")


def configuration_rejection_matches(packet, row, observed):
    """An unrelated loader failure with exit 1 never proves the named rejection."""
    refs = {item["role"]: item for item in packet["measurement_evidence"]}
    source = json.loads(PATHS.read_text(refs["expectation_source"]["path"]))
    expected = source.get("expected_parser_rejection")
    if (not isinstance(expected, dict) or source.get("reviewed_by") != "root"
            or expected.get("original_contract_sha256") != ORACLES.canonical_digest(row["selected_requirement"])
            or expected.get("oracle_sha256") != packet["oracle_sha256"]
            or expected.get("diagnostic_stream") not in ("stdout", "stderr")
            or not isinstance(expected.get("diagnostic_contains"), str)
            or not expected["diagnostic_contains"].strip()
            or not isinstance(expected.get("first_cause"), str) or not expected["first_cause"].strip()):
        raise ValueError("Configuration rejection needs a source-bound diagnostic and first-cause expectation")
    actual = json.loads(PATHS.read_text(refs["parser_process"]["path"]))
    process = observed["parser_process"]
    if not isinstance(process.get("first_cause"), str) or actual.get("first_cause") != process["first_cause"]:
        raise ValueError("Configuration first cause must match the actual parser receipt")
    return (process["first_cause"] == expected["first_cause"]
            and expected["diagnostic_contains"] in process[expected["diagnostic_stream"]])


def reviewed_configuration_packet(supplied, row, effective_oracle):
    """Qualify an original parser contract without fabricating an HTTP lifecycle.

    This separate scope can only cover an original actual_configtest selection.
    It never contributes a full_host_lifecycle result or substitutes for body,
    transport, native transaction, finish or free measurements.
    """
    ref = ORACLES.verify_reference(supplied)
    packet = json.loads(PATHS.read_text(ref["path"]))
    validate_configuration_identity(packet, row, effective_oracle)
    observed = configuration_measurements(packet, ref)
    verdict = packet.get("outcome")
    if verdict not in ("PASS", "FAIL"):
        raise ValueError("Parser exit alone is not an evaluated configuration verdict")
    expected = effective_oracle.get("native_result")
    expected_exit = effective_oracle.get("visible_status")
    explicit_exit = (type(expected_exit) is int and
                     ((expected == "config_accepted" and expected_exit == 0) or
                      (expected == "config_rejected" and 1 <= expected_exit <= 255)))
    if (effective_oracle.get("phase") != 0
            or effective_oracle.get("physical_evidence_not_projection") is not True
            or effective_oracle.get("unresolved_expected_value_reason")
            or not explicit_exit):
        raise ValueError("Parser scope requires an explicit acceptance or rejection oracle")
    process = observed["parser_process"]
    matched = (process["waited_signal"] is None and process["waited_exit"] >= 0
               and process["waited_exit"] == effective_oracle["visible_status"])
    if expected == "config_rejected":
        matched = configuration_rejection_matches(packet, row, observed) and matched
    if verdict != ("PASS" if matched else "FAIL"):
        raise ValueError("Parser verdict contradicts actual exit/signal/first cause and independent oracle")
    return {"receipt": ref, "observations": observed, "execution_observed": True,
            "mandatory_observations": dict(zip(CONFIGURATION_FIELDS, (
                observed["parser_process"],
                {"invocation_identity": observed["invocation_identity"], "source_config_binding": observed["source_config_binding"]},
                {"expected_oracle": copy.deepcopy(effective_oracle), "oracle_sha256": packet["oracle_sha256"]}), strict=True)),
            "qualification_scope": "configuration_control", "full_case_qualified": True,
            "full_lifecycle_qualified": False, "outcome": verdict, "unknown_fields": []}


# These are original Traefik contracts, not a new general exemption for early exits.
TRAEFIK_REQUEST_ROUTES = frozenset(("traefik-native-uds", "traefik-forwardauth-request"))
TRAEFIK_ROUTES = TRAEFIK_REQUEST_ROUTES | {"traefik-forwardauth-response-companion"}
PARSER_REJECTIONS = frozenset(("invalid_content_length", "conflicting_content_length",
                               "duplicate_transfer_encoding", "content_length_overflow"))
MAPPING_REJECTIONS = frozenset(("body_size_nonzero_with_null_data", "header_count_nonzero_with_null_headers"))
EARLY_CLEANUP_CASES = frozenset(("early_mapping_failure_cleanup", "transaction_begin_failure_cleanup"))
PREALLOCATION_NULL_FIELDS = frozenset((
    "native_events", "native_transaction_id", "common_transaction_id",
    "observed_handle_association", "native_phases", "native_body_chunks",
    "native_intervention_or_first_cause", "host_eos", "native_eos", "commit_order", "mime_gate",
    "finish_calls", "finish_transitions", "native_free_calls", "physical_event_order", "terminal_event_count"))


def bound_json(selector, packet_path, roles):
    """Read an exact existing producer field without treating packet data as a measurement."""
    if not isinstance(selector, dict):
        raise ValueError("Missing physical preallocation selector")
    ref = ORACLES.verify_reference(selector.get("reference", {}))
    if ref.get("role") not in roles or ref["path"] == str(packet_path):
        raise ValueError("Preallocation measurement has an unsuitable or self-referential producer")
    raw = PATHS.read_text(ref["path"])
    if "line" in selector:
        line = selector["line"]
        if type(line) is not int or not 0 <= line < len(raw.splitlines()):
            raise ValueError("Invalid exact physical JSONL line selector")
        raw = raw.splitlines()[line]
    value = json.loads(raw)
    pointer = selector.get("pointer")
    if not isinstance(pointer, str) or (pointer and not pointer.startswith("/")):
        raise ValueError("Preallocation selector needs an exact JSON pointer")
    return json_pointer_value(value, pointer)


def json_pointer_value(value, pointer):
    """Follow an already validated JSON pointer without changing its value."""
    try:
        for part in pointer.split("/")[1:] if pointer else ():
            key = part.replace("~1", "/").replace("~0", "~")
            value = value[int(key)] if isinstance(value, list) else value[key]
    except (KeyError, IndexError, TypeError, ValueError) as error:
        raise ValueError("Physical preallocation selector does not exist") from error
    return value


def preallocation_expected_operation(expected, case):
    if case in PARSER_REJECTIONS:
        expected_kind = "http_parser"
    elif case == "NEED-physical-event-sink-open":
        expected_kind = "service_startup"
    else:
        expected_kind = "mapping_or_begin"
    if expected.get("failure_class") != expected_kind:
        raise ValueError("Preallocation failure class does not match the original ID")
    if expected_kind != "http_parser" and (not isinstance(expected.get("operation"), str) or not expected["operation"]
            or "errno" not in expected or (expected["errno"] is not None and type(expected["errno"]) is not int)
            or type(expected.get("failure_result")) is not int):
        raise ValueError("Preallocation operation, return and errno expectation must be explicit")
    if expected_kind == "mapping_or_begin" and (expected["errno"] is not None or expected.get("errno_scope") != "not_an_os_operation"
            or expected["failure_result"] not in (0, -1)):
        raise ValueError("Mapper/native API results must not invent an OS errno")


def preallocation_packet_identity(packet, row, oracle, route):
    if (packet.get("reviewed_by") != "root" or packet.get("run_scoped_case_id") != row["run_scoped_case_id"]
            or packet.get("leg_id") != route or packet.get("execution_observed") is not True
            or packet.get("execution_kind") != "host_preallocation_control"
            or packet.get("full_lifecycle_qualified") is not False):
        raise ValueError("Preallocation control needs exact Root-reviewed identity and cannot claim a lifecycle")
    if (oracle is None or packet.get("oracle_evaluated") is not True
            or packet.get("oracle_sha256") != ORACLES.canonical_digest(oracle)
            or oracle.get("unresolved_expected_value_reason") or oracle.get("phase", "missing") is not None
            or oracle.get("physical_evidence_not_projection") is not True):
        raise ValueError("Preallocation control needs an independently reviewed effective oracle with absent native phase")


def preallocation_contract(packet, row, oracle, path):
    route, case = row["leg_id"], row["run_scoped_case_id"].split("::")[-1]
    eligible = ((route in TRAEFIK_REQUEST_ROUTES and case in PARSER_REJECTIONS | MAPPING_REJECTIONS)
                or (route in TRAEFIK_ROUTES and case in EARLY_CLEANUP_CASES | {"NEED-physical-event-sink-open"}))
    if not eligible or row["selected_requirement"].get("execution_kind") != "host_case_or_missing_fixture":
        raise ValueError("Original ID does not permit preallocation qualification")
    preallocation_packet_identity(packet, row, oracle, route)
    ref = ORACLES.verify_reference(packet.get("preallocation_contract", {}))
    if (ref.get("kind") not in ORACLES.INDEPENDENT_KINDS or not ref.get("revision")
            or ref.get("role") != "expectation_source" or ref["path"] == str(path)):
        raise ValueError("Preallocation contract requires a separate revisioned expectation source")
    expected = json.loads(PATHS.read_text(ref["path"]))
    validate_preallocation_approval(expected, row, packet)
    preallocation_expected_operation(expected, case)
    return expected


def validate_preallocation_approval(expected, row, packet):
    if (expected.get("reviewed_by") != "root" or expected.get("run_scoped_case_id") != row["run_scoped_case_id"]
            or expected.get("original_contract_sha256") != ORACLES.canonical_digest(row["selected_requirement"])
            or expected.get("oracle_sha256") != packet["oracle_sha256"]
            or type(expected.get("native_allocation_count")) is not int or expected["native_allocation_count"] != 0
            or not isinstance(expected.get("first_cause"), str) or not expected["first_cause"]):
        raise ValueError("Preallocation approval does not bind the exact original contract and oracle")


def preallocation_observations(packet, path):
    if set(packet.get("observations", {})) != set(ROLES):
        raise ValueError("Preallocation controls must retain all 35 original observation fields")
    result = {}
    for field, item in packet["observations"].items():
        if field in PREALLOCATION_NULL_FIELDS:
            if item.get("value", "missing") is not None or not item.get("reason"):
                raise ValueError("Unallocated lifecycle observations must remain explicitly null")
            result[field] = copy.deepcopy(item)
        else:
            result[field], complete = measurement(field, item, path)
            if not complete:
                raise ValueError("Missing physical preallocation observation: " + field)
    if result["backend_request_count"]["value"] != 0:
        raise ValueError("Preallocation rejection requires backend exclusion")
    return result


def preallocation_source_binding(packet, observations):
    binding = observations["source_config_binding"]
    refs = {ref["role"]: ref for ref in binding["evidence"]}
    source = json.loads(PATHS.read_text(refs["source_manifest"]["path"]))
    value = binding["value"]
    if (not isinstance(value, dict) or source.get("parent_sha") != packet.get("parent_sha")
            or value.get("parent_sha") != packet.get("parent_sha")
            or value.get("effective_config_sha256") != packet.get("effective_config_sha256")
            or refs["effective_configuration"]["sha256"] != packet.get("effective_config_sha256")):
        raise ValueError("Preallocation source revision and effective configuration must bind actual bytes")


def observer_records(ref, path):
    ref = ORACLES.verify_reference(ref)
    if ref.get("role") != "native_api" or ref["path"] == str(path):
        raise ValueError("Preallocation needs the physical native observer stream")
    rows = [json.loads(line) for line in PATHS.read_text(ref["path"]).splitlines() if line]
    if not rows:
        raise ValueError("An empty observer stream cannot prove zero allocations")
    by_pid = {}
    for record in rows:
        if (record.get("schema") != "native-lifecycle-v1" or type(record.get("pid")) is not int or record["pid"] <= 0 or record.get("uid") != 65534
                or record.get("invalid") is not False or type(record.get("sequence")) is not int
                or type(record.get("monotonic_ns")) is not int):
            raise ValueError("Invalid native observer record")
        by_pid.setdefault(record["pid"], []).append(record)
    for records in by_pid.values():
        if ([item["sequence"] for item in records] != list(range(1, len(records)+1))
                or records[0].get("function") != "observer" or records[0].get("edge") not in ("admitted", "fork")
                or records[-1].get("function") != "observer" or records[-1].get("edge") not in ("final", "snapshot")
                or any(a["monotonic_ns"] > b["monotonic_ns"] for a, b in zip(records, records[1:]))):
            raise ValueError("Observer activation, sequence and terminal coverage are mandatory")
    return by_pid


def observed_allocations(records):
    constructors = [row for row in records if row.get("function") in ("native_new", "native_new_with_id")]
    returns = [row for row in constructors if row.get("edge") == "return"]
    enters = [row for row in constructors if row.get("edge") == "enter"]
    if (len(returns) != len(enters)
            or [(row.get("function"), row.get("call")) for row in enters] != [(row.get("function"), row.get("call")) for row in returns]
            or any(type(row.get("result")) is not int or row["result"] not in (0, 1) for row in returns)):
        raise ValueError("Incomplete native allocation call pairs")
    return len(enters), sum(row["result"] for row in returns)


def physical_window(value, pid):
    if not isinstance(value, dict):
        raise ValueError("Missing actual client/controller window")
    return {**value, "pid": pid,
            "start_monotonic_ns": value.get("start_monotonic_ns", value.get("started_ns", value.get("monotonic_ns"))),
            "end_monotonic_ns": value.get("end_monotonic_ns", value.get("completed_ns"))}


def backend_headers(packet, path, key):
    ref = ORACLES.verify_reference(packet.get("backend_log", {}))
    if ref.get("role") != "backend_process" or ref["path"] == str(path) or not isinstance(key, str) or not key:
        raise ValueError("Physical independent early-header backend receipts and client key are mandatory")
    rows = [json.loads(line) for line in PATHS.read_text(ref["path"]).splitlines() if line]
    if not rows or any(not isinstance(row, dict) for row in rows):
        raise ValueError("Empty backend stream cannot establish a monitored exclusion")
    return sum((row.get("event") == "parsed_headers" and row.get("probe") == key)
               or (row.get("operation") == "headers-arrived" and row.get("key") == key) for row in rows)


def control_status(control):
    if "status" in control:
        return control["status"]
    requests = control.get("requests")
    if not isinstance(requests, list) or len(requests) != 1:
        raise ValueError("Healthy control needs one actual client response")
    return requests[0].get("client_framing", {}).get("status")


def observed_window(value, by_pid, packet):
    if (not isinstance(value, dict) or type(value.get("pid")) is not int
            or type(value.get("start_monotonic_ns")) is not int or type(value.get("end_monotonic_ns")) is not int
            or value["start_monotonic_ns"] >= value["end_monotonic_ns"]):
        raise ValueError("Preallocation needs an exact physical process/time window")
    rows = by_pid.get(value["pid"], [])
    if (not rows or rows[0]["monotonic_ns"] > value["start_monotonic_ns"]
            or rows[-1]["monotonic_ns"] < value["end_monotonic_ns"]
            or any(row.get("run") != packet["run_id"] or row.get("profile") != packet["leg_id"] for row in rows)):
        raise ValueError("Observer does not cover the actual process/run/window")
    return [row for row in rows if value["start_monotonic_ns"] <= row["monotonic_ns"] <= value["end_monotonic_ns"]]


def preallocation_images(packet, path):
    identities = []
    for name in ("target_identity", "before_identity", "after_identity"):
        identity = bound_json(packet["preallocation_measurements"].get(name), path, {"loaded_image"})
        if (not isinstance(identity, dict) or identity.get("run_id") != packet["run_id"]
                or identity.get("parent_sha") != packet["parent_sha"] or identity.get("uid") != 65534
                or any(not isinstance(identity.get(key), str) or re.fullmatch(r"[a-f0-9]{64}", identity[key]) is None
                       for key in ("host_binary_sha256", "module_sha256", "observer_sha256"))):
            raise ValueError("Loaded observer/image/source/UID identity is missing")
        identities.append(identity)
    image_keys = ("host_binary_sha256", "module_sha256", "observer_sha256")
    if any(any(identity[key] != identities[0][key] for key in image_keys) for identity in identities):
        raise ValueError("Healthy controls do not use the same loaded instrumented images")
    return identities


def preallocation_controls(packet, path, expected):
    bindings = packet.get("preallocation_measurements", {})
    by_pid = observer_records(packet.get("observer_log", {}), path)
    identities = preallocation_images(packet, path)
    target = physical_window(bound_json(bindings.get("target_window"), path, {"client_process", "host_callback"}), identities[0].get("pid"))
    rows = observed_window(target, by_pid, packet)
    attempts, allocated = observed_allocations(rows)
    if allocated != 0:
        raise ValueError("A native allocation prevents preallocation qualification")
    target_key = target.get("key", target.get("probe"))
    if backend_headers(packet, path, target_key) != 0:
        raise ValueError("Target reached the independent backend before body processing")
    windows = []
    for index, name in enumerate(("before_control", "after_control"), 1):
        control = physical_window(bound_json(bindings.get(name), path, {"client_process", "host_callback"}), identities[index].get("pid"))
        records = observed_window(control, by_pid, packet)
        if (identities[index].get("pid") != control["pid"] or control_status(control) != 200
                or backend_headers(packet, path, control.get("key", control.get("probe"))) != 1 or observed_allocations(records)[1] != 1
                or sum(row.get("function") == "native_cleanup" and row.get("edge") == "enter" for row in records) != 1):
            raise ValueError("Healthy controls need actual native allocation/free, client and backend evidence")
        windows.append(control)
    if (identities[0].get("pid") != target["pid"] or windows[0]["end_monotonic_ns"] >= target["start_monotonic_ns"]
            or target["end_monotonic_ns"] >= windows[1]["start_monotonic_ns"]):
        raise ValueError("Healthy controls must bracket the target execution")
    if expected["failure_class"] != "service_startup" and any(control["pid"] != target["pid"] for control in windows):
        raise ValueError("HTTP/parser/mapping controls require the same live native process")
    if any(str(row.get("function", "")).startswith("native_") and row.get("function") not in ("native_new", "native_new_with_id") for row in rows):
        raise ValueError("A native transaction call in the target window contradicts nonallocation")
    return {"native_constructor_attempts": attempts, "native_allocations": allocated,
            "target_window": target, "controls": windows,
            "native_api_returns": [{"function": row["function"], "call": row["call"], "result": row["result"]}
                for row in rows if row.get("edge") == "return" and str(row.get("function", "")).startswith(("native_", "runtime_"))],
            "native_runtime_begin_returns": [row["result"] for row in rows
                if row.get("function") in ("runtime_begin", "runtime_begin_request_stream") and row.get("edge") == "return"]}


def response_header_length(line, lengths):
    if b":" not in line or line.startswith((b" ", b"\t")):
        raise ValueError("Invalid preallocation response header")
    name, value = line.split(b":", 1)
    if re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) is None:
        raise ValueError("Invalid preallocation response field name")
    if any((byte < 32 and byte != 9) or byte == 127 for byte in value):
        raise ValueError("Invalid preallocation response field value")
    if name.lower() == b"transfer-encoding":
        raise ValueError("Preallocation raw framing needs an independently supported entity decoder")
    if name.lower() == b"content-length":
        value = value.strip(b" \t")
        if not value.isdigit() or len(value) > 19 or int(value) > 9223372036854775807:
            raise ValueError("Invalid or oversized preallocation response Content-Length")
        lengths.append(int(value))


def response_entity_framing(head, body):
    lengths = []
    if b"\n" in head.replace(b"\r\n", b"") or b"\r" in head.replace(b"\r\n", b""):
        raise ValueError("Invalid preallocation response header line framing")
    for line in head.split(b"\r\n")[1:]:
        response_header_length(line, lengths)
    if lengths and (len(lengths) != 1 or lengths[0] != len(body)):
        raise ValueError("Incomplete or ambiguous preallocation response body framing")


def preallocation_wire(packet, row, oracle, path):
    request = ORACLES.verify_reference(packet.get("client_request", {}))
    response = ORACLES.verify_reference(packet.get("client_response", {}))
    if any(ref.get("role") != "client_process" or ref["path"] == str(path) for ref in (request, response)):
        raise ValueError("Actual client request and response bytes are mandatory")
    raw = PATHS.read_bytes(response["path"])
    match = re.match(rb"HTTP/1\.[01] (\d{3})[^\r\n]*\r\n", raw)
    if (not match or b"\r\n\r\n" not in raw or int(match[1]) != oracle.get("visible_status")
            or len(re.findall(rb"(?m)^HTTP/1\.[01] \d{3}", raw)) != 1):
        raise ValueError("Raw client response does not match the independently reviewed status")
    head, body = raw.split(b"\r\n\r\n", 1)
    response_entity_framing(head, body)
    if (packet["observations"]["client_sha256"]["value"] != hashlib.sha256(body).hexdigest()
            or packet["observations"]["client_bytes"]["value"] != len(body)):
        raise ValueError("Client entity byte count/digest differs from the physical raw response")
    target = bound_json(packet["preallocation_measurements"].get("target_window"), path, {"client_process", "host_callback"})
    key = target.get("key", target.get("probe"))
    request_bytes = PATHS.read_bytes(request["path"])
    headers = request_bytes.split(b"\r\n\r\n", 1)[0].split(b"\r\n")[1:]
    keys = [line.split(b":", 1)[1].strip().decode("ascii") for line in headers
            if line.lower().startswith((b"x-i12-probe:", b"x-i12-acceptance-key:"))]
    if keys != [key]:
        raise ValueError("Raw client request key differs from its physical time window/backend correlation")
    case = row["run_scoped_case_id"].split("::")[-1]
    if case in PARSER_REJECTIONS:
        headers = PATHS.read_bytes(request["path"]).split(b"\r\n\r\n", 1)[0].split(b"\r\n")[1:]
        lengths = [line.split(b":", 1)[1].strip() for line in headers if line.lower().startswith(b"content-length:")]
        transfers = [line for line in headers if line.lower().startswith(b"transfer-encoding:")]
        valid = {"invalid_content_length": bool(lengths) and any(not value.isdigit() for value in lengths),
                 "conflicting_content_length": len(set(lengths)) > 1,
                 "duplicate_transfer_encoding": len(transfers) > 1,
                 "content_length_overflow": any(value.isdigit() and int(value) > 9223372036854775807 for value in lengths)}
        if not valid[case] or int(match[1]) != 400:
            raise ValueError("Physical malformed request does not exercise the exact original parser case")
    return int(match[1])


def mapping_failure_boundary(row, expected, controls, fault, case):
    suffix = "body-null" if case == "body_size_nonzero_with_null_data" else "headers-null"
    prefix = "native-request-" if row["leg_id"] == "traefik-native-uds" else "mapper-"
    if fault["operation"] != prefix + suffix:
        raise ValueError("Wrong actual pointer-injection boundary for the original mapper contract")
    count_key, null_key = (("input_size", "body_data_null") if suffix == "body-null" else ("header_count", "headers_null"))
    if type(fault.get(count_key)) is not int or fault[count_key] <= 0 or fault.get(null_key) is not True:
        raise ValueError("Mapper contract needs actual nonzero count and actual NULL pointer measurements")
    if prefix == "native-request-":
        if (fault["result"] != expected["failure_result"]
                or controls["native_runtime_begin_returns"] != [fault["result"]]):
            raise ValueError("Native pointer rejection needs its actual independently observed begin return")
        return True
    return False


def preallocation_failure(packet, row, expected, controls, path):
    bindings = packet["preallocation_measurements"]
    fault = bound_json(bindings.get("fault"), path, {"host_callback"})
    window = controls["target_window"]
    if (not isinstance(fault, dict) or fault.get("operation") != expected["operation"]
            or fault.get("pid") != window["pid"] or type(fault.get("result")) is not int
            or not window["start_monotonic_ns"] <= fault.get("monotonic_ns", -1) <= window["end_monotonic_ns"]):
        raise ValueError("Preallocation rejection needs its actual failing operation/process/window")
    if expected["failure_class"] == "service_startup":
        preallocation_startup_failure(packet, expected, fault, path)
        return
    case = row["run_scoped_case_id"].split("::")[-1]
    if case in MAPPING_REJECTIONS:
        if mapping_failure_boundary(row, expected, controls, fault, case):
            return
    if fault["result"] != expected["failure_result"]:
        raise ValueError("Actual mapper/native failure return differs from its independent contract")


def preallocation_startup_failure(packet, expected, fault, path):
    if (fault["operation"] not in ("open", "open64", "openat", "openat64")
            or type(fault.get("errno")) is not int or fault["errno"] <= 0
            or fault["errno"] != expected["errno"] or fault["result"] != -1 or expected["failure_result"] != -1):
        raise ValueError("Startup rejection requires a real failing open syscall and actual errno")
    process = bound_json(packet["preallocation_measurements"].get("startup_process"), path, {"host_callback"})
    if (not isinstance(process, dict) or process.get("actual_pid") != fault["pid"]
            or type(expected.get("process_exit")) is not int or process.get("exit_code") != expected["process_exit"]
            or process.get("signal") is not None):
        raise ValueError("Startup rejection requires the actual failed service process exit")
    diagnostic = bound_json(packet["preallocation_measurements"].get("startup_diagnostic"), path, {"host_callback"})
    if (not isinstance(diagnostic, str) or not isinstance(expected.get("diagnostic_contains"), str)
            or not expected["diagnostic_contains"] or expected["diagnostic_contains"] not in diagnostic):
        raise ValueError("Startup rejection requires its source-bound actual diagnostic")


def reviewed_preallocation_packet(supplied, row, effective_oracle):
    ref = ORACLES.verify_reference(supplied)
    path = Path(ref["path"])
    packet = json.loads(PATHS.read_text(path))
    expected = preallocation_contract(packet, row, effective_oracle, path)
    observations = preallocation_observations(packet, path)
    preallocation_source_binding(packet, observations)
    controls = preallocation_controls(packet, path, expected)
    if observations["native_api_returns"]["value"] != controls["native_api_returns"]:
        raise ValueError("Actual native/runtime API returns must agree with the physical target observer stream")
    status = preallocation_wire(packet, row, effective_oracle, path)
    if expected["failure_class"] != "http_parser":
        preallocation_failure(packet, row, expected, controls, path)
    cleanup = bound_json(packet["preallocation_measurements"].get("cleanup"), path, {"cleanup_observer"})
    if (not isinstance(cleanup, dict) or cleanup.get("run_id") != packet["run_id"]
            or any(type(cleanup.get(key)) is not int or cleanup[key] != 0
                   for key in ("descriptors_remaining", "sockets_remaining", "processes_remaining"))
            or cleanup.get("cleanup_calls") != 1):
        raise ValueError("Exact once-cleanup and FD/socket/process receipts are mandatory")
    if type(cleanup.get("cleanup_calls")) is not int:
        raise ValueError("Cleanup call count must be an observed integer")
    if packet.get("outcome") != "PASS":
        raise ValueError("Preallocation proof cannot substitute a driver exit for a qualified verdict")
    return {"receipt": ref, "observations": observations, "execution_observed": True,
            "qualification_scope": "preallocation_control", "full_case_qualified": True,
            "full_lifecycle_qualified": False, "outcome": "PASS", "unknown_fields": [],
            "preallocation_measurements": controls, "visible_status": status}


PRE_NATIVE_MAPPING = {
    "invalid_content_length": ["invalid_content_length", "I12::apache-native::obligation::invalid-header"],
    "conflicting_content_length": ["conflicting_content_length"],
    "duplicate_transfer_encoding": ["duplicate_transfer_encoding"],
    "content_length_overflow": ["content_length_overflow", "I12::apache-native::obligation::size-overflow"],
}
LIGHTTPD_PRE_NATIVE_MAPPING = {
    "invalid_content_length": ["invalid_content_length", "I12::lighttpd-stock-native-control::obligation::invalid-header"],
    "conflicting_content_length": ["conflicting_content_length"],
    "content_length_overflow": ["content_length_overflow", "I12::lighttpd-stock-native-control::obligation::size-overflow"],
}
PRE_NATIVE_ORACLE = {"native_result": "rejected_by_host_before_connector_or_connector_rejection",
                     "visible_status": 400, "rule_id": None, "phase": 1, "event_fields": [],
                     "physical_evidence_not_projection": True, "unresolved_expected_value_reason": None}
PRE_NATIVE_ROLES = frozenset((
    "client_process", "client_receipt", "request_wire", "response_wire", "native_api", "host_callback",
    "backend_process", "core_diagnostic", "event_observer", "source_manifest", "effective_configuration",
    "rules_file", "loaded_image", "native_module", "observer_image", "isolation_receipt", "cleanup_observer",
    "healthy_controls", "driver_observation",
))


def pre_native_profile(leg):
    if leg == "apache-native":
        return PRE_NATIVE_MAPPING, "apache", PRE_NATIVE_ROLES
    if leg == "lighttpd-stock-native-control":
        return LIGHTTPD_PRE_NATIVE_MAPPING, "lighttpd", PRE_NATIVE_ROLES | {"core_diagnostic_window"}
    raise ValueError("Pre-native scope has no contract for this host/profile")


def pre_native_selected_contract(row, oracle):
    selected = row["selected_requirement"]
    name = selected.get("case_id")
    mapping, _, _ = pre_native_profile(row.get("leg_id"))
    if (name not in mapping
            or row.get("run_scoped_case_id") != f'I12::{row["leg_id"]}::{name}'
            or selected.get("run_scoped_case_id") != row["run_scoped_case_id"]
            or selected.get("requirement_mapping") != mapping[name]
            or selected.get("expected_oracle") != PRE_NATIVE_ORACLE or oracle != PRE_NATIVE_ORACLE
            or type(oracle.get("phase")) is not int or type(oracle.get("visible_status")) is not int):
        raise ValueError("Pre-native scope requires an exact original selected host rejection contract")
    return selected


def pre_native_packet_identity(packet, row, oracle):
    if (packet.get("reviewed_by") != "root" or packet.get("execution_kind") != "host_pre_native_rejection"
            or packet.get("execution_observed") is not True or packet.get("oracle_evaluated") is not True
            or packet.get("oracle_sha256") != ORACLES.canonical_digest(oracle)
            or packet.get("full_lifecycle_qualified") is not False
            or packet.get("native_transaction_id") is not None):
        raise ValueError("Pre-native rejection cannot fabricate a native transaction or full lifecycle")
    for key in ("run_scoped_case_id", "leg_id"):
        if packet.get(key) != row[key]:
            raise ValueError("Pre-native packet belongs to another case/profile")
    for key in ("run_id", "parent_sha", "framework_sha", "mrts_sha", "effective_config_sha256", "rules_sha256",
                "request_id", "host_starttime"):
        if not packet.get(key):
            raise ValueError(f"Pre-native packet lacks actual identity: {key}")
    for key in ("host_pid", "uid"):
        if type(packet.get(key)) is not int or packet[key] <= 0:
            raise ValueError("Pre-native execution requires an actual isolated non-root host process")


def pre_native_source_approval(packet, row, selected):
    approval = packet.get("source_approval", {})
    digests = {"selected_requirement_sha256": ORACLES.canonical_digest(selected),
               "requirement_mapping_sha256": ORACLES.canonical_digest(selected["requirement_mapping"]),
               "oracle_sha256": packet["oracle_sha256"], "request_sha256": packet.get("request_sha256")}
    if (approval.get("reviewed_by") != "root" or approval.get("scope") != "host_pre_native_rejection"
            or approval.get("run_scoped_case_id") != row["run_scoped_case_id"] or not approval.get("reason")
            or any(not value or approval.get(key) != value for key, value in digests.items())):
        raise ValueError("Pre-native rejection needs separate exact-contract/request Root source approval")
    sources = [ORACLES.verify_reference(ref) for ref in approval.get("proof", [])]
    if (not {"official_host_contract", "protocol_contract"} <= {ref.get("kind") for ref in sources}
            or any(ref.get("kind") not in ORACLES.INDEPENDENT_KINDS or not ref.get("revision") for ref in sources)):
        raise ValueError("Pre-native approval lacks versioned independent host and protocol sources")
    if {p["sha256"] for p in sources if p.get("kind") == "official_host_contract"} & {
            p["sha256"] for p in sources if p.get("kind") == "protocol_contract"}:
        raise ValueError("Independent host and protocol approval must bind separate source bytes")
    return sources


def pre_native_identity(packet, row, oracle):
    selected = pre_native_selected_contract(row, oracle)
    pre_native_packet_identity(packet, row, oracle)
    sources = pre_native_source_approval(packet, row, selected)
    return sources


def pre_native_json(ref):
    return json.loads(PATHS.read_text(ref["path"]))


def pre_native_rows(ref):
    return [json.loads(line) for line in PATHS.read_text(ref["path"]).splitlines() if line.strip()]


def validate_native_window_rows(packet, rows, start, end):
    if (not rows or any(row.get("schema") != "native-lifecycle-v1" or row.get("run") != packet["run_id"]
                        or row.get("profile") != packet["leg_id"]
                        or row.get("case") != packet["run_scoped_case_id"].split("::")[-1]
                        or row.get("uid") != packet["uid"]
                        or row.get("invalid") is not False or type(row.get("monotonic_ns")) is not int for row in rows)):
        raise ValueError("Pre-native negative allocation needs actual matching native observer records")
    if (any(type(r.get("sequence")) is not int for r in rows)
            or [r["sequence"] for r in rows] != list(range(1, len(rows) + 1))):
        raise ValueError("Pre-native observer capture must preserve the complete process sequence")
    if (not any(r.get("function") == "observer" and r.get("edge") == "admitted" and r["monotonic_ns"] < start for r in rows)
            or not any(r.get("function") == "observer" and r.get("edge") == "final" and r["monotonic_ns"] > end
                       and type(r.get("pending_calls")) is int and r["pending_calls"] == 0
                       and type(r.get("live_mappings")) is int and r["live_mappings"] == 0 for r in rows)
            or any(start <= r["monotonic_ns"] <= end and r.get("function") != "observer" for r in rows)):
        raise ValueError("Pre-native window must be complete with no main allocation/API/P2/EOS/finish/free")


def native_window_control(rows, start, end, before):
    controls = [r for r in rows if (r["monotonic_ns"] < start if before else r["monotonic_ns"] > end)]
    constructors = [r for r in controls if r.get("function") in ("native_new", "native_new_with_id")
                    and r.get("edge") == "return" and type(r.get("result")) is int and r["result"] == 1
                    and r.get("transaction_id")]
    if not any(all(any(r.get("function") == function and r.get("edge") == "return"
                           and r.get("transaction_id") == c["transaction_id"]
                           and type(r.get("result")) is int and r["result"] == 1 for r in controls)
                   for function in ("native_process_request_headers", "native_process_request_body"))
               for c in constructors):
        raise ValueError("Zero main calls require actual positive constructor/API controls before and after")


def pre_native_native_window(packet, producers, client):
    """Read the existing native-lifecycle-v1 and Apache host observer captures."""
    rows = pre_native_rows(producers["native_api"])
    rows = [row for row in rows if row.get("pid") == packet["host_pid"]]
    start, end = client["started_ns"], client["completed_ns"]
    validate_native_window_rows(packet, rows, start, end)
    for before in (True, False):
        native_window_control(rows, start, end, before)
    host = pre_native_rows(producers["host_callback"])
    if any(r.get("pid") == packet["host_pid"] and start <= r.get("monotonic_ns", start) <= end for r in host):
        raise ValueError("A host callback during the main window contradicts pre-native rejection")
    return {"main_native_allocation": False, "main_native_api_calls": 0, "main_native_transaction_id": None,
            "window_started_ns": start, "window_completed_ns": end}


def pre_native_isolation_binding(packet, producers, source):
    isolation = pre_native_json(producers["isolation_receipt"])
    for key in ("run_id", "parent_sha", "effective_config_sha256", "rules_sha256", "host_pid", "host_starttime", "uid"):
        if isolation.get(key) != packet[key]:
            raise ValueError("Pre-native image/isolation belongs to a different actual host")
    for key, role in (("host_binary_sha256", "loaded_image"), ("module_sha256", "native_module"),
                      ("observer_sha256", "observer_image")):
        if isolation.get(key) != producers[role]["sha256"] or source.get(key) != producers[role]["sha256"]:
            raise ValueError("Pre-native actual loaded host/module/observer image differs from source manifest")
    maps = PATHS.read_text(ORACLES.verify_reference(isolation["maps"])["path"])
    status = PATHS.read_text(ORACLES.verify_reference(isolation["status"])["path"])
    status_fields = [line.split() for line in status.splitlines()]
    if (["Pid:", str(packet["host_pid"])] not in status_fields
            or ["Uid:", *([str(packet["uid"])] * 4)] not in status_fields):
        raise ValueError("Pre-native actual process status must bind all four isolated UIDs and PID")
    for role in ("loaded_image", "native_module", "observer_image"):
        mapped = isolation.get("mapped_paths", {}).get(role)
        if not isinstance(mapped, str) or not Path(mapped).is_absolute() or mapped not in maps:
            raise ValueError("Pre-native image must be observed in the actual host process maps")
    if isolation.get("loaded_images_observed") is not True or isolation.get("exclusive_request_window") is not True:
        raise ValueError("Pre-native negative observation needs actual loaded images and an exclusive request window")


def pre_native_sink_control(packet, producers, client, event, content, offsets, label):
    control = event.get(label, {})
    begin, finish = control.get("start_offset"), control.get("end_offset")
    if (type(begin) is not int or type(finish) is not int or not 0 <= begin < finish <= len(content)
            or not content[begin:finish].strip()
            or (finish > offsets[0] if label == "before_control" else begin < offsets[1])):
        raise ValueError("Independent event observer needs actual positive sink bytes before and after")
    positive = [json.loads(line) for line in content[begin:finish].splitlines() if line.strip()]
    native = pre_native_rows(producers["native_api"])
    identities = {r.get(key) for r in native for key in ("transaction_id", "canonical_transaction_id")
                  if r.get("pid") == packet["host_pid"] and r.get("function") in ("native_new", "native_new_with_id")
                  and r.get("edge") == "return" and type(r.get("result")) is int and r["result"] == 1
                  and (r["monotonic_ns"] < client["started_ns"] if label == "before_control"
                       else r["monotonic_ns"] > client["completed_ns"])}
    if (not positive or any(not isinstance(r, dict) or not r.get("transaction_id")
            or r["transaction_id"] not in identities or r.get("connector") != pre_native_profile(packet["leg_id"])[1]
            or not isinstance(r.get("message_id"), str) or not r["message_id"].startswith("MSCONN_EVENT_") for r in positive)):
        raise ValueError("Positive sink controls must be actual selected-host events joined to observed native allocations")


def pre_native_cleanup_binding(producers):
    cleanup = pre_native_json(producers["cleanup_observer"])
    if (cleanup.get("execution_observed") is not True
            or any(cleanup.get(key) is not True for key in ("descriptor_cleanup_observed", "process_cleanup_observed", "listener_cleanup_observed"))
            or cleanup.get("remaining_processes") != [] or cleanup.get("remaining_listeners") != []
            or cleanup.get("unexpected_fd_targets") != []):
        raise ValueError("Pre-native rejection requires actual FD/process/listener cleanup")


def pre_native_healthy_controls(packet, producers, client):
    controls = pre_native_json(producers["healthy_controls"])
    for label in ("before", "after"):
        control = controls.get(label, {})
        receipt = pre_native_json(ORACLES.verify_reference(control["client_receipt"]))
        process = pre_native_json(ORACLES.verify_reference(control["client_process"]))
        if (receipt.get("status") != 200 or type(process.get("waited_exit")) is not int or process["waited_exit"] != 0
                or not process.get("argv") or not process.get("cwd") or not control.get("request_id")
                or control["request_id"] == packet["request_id"]
                or (receipt.get("completed_ns", client["started_ns"]) >= client["started_ns"] if label == "before"
                    else receipt.get("started_ns", 0) <= client["completed_ns"])):
            raise ValueError("Pre-native rejection needs actual healthy client controls before and after")
        native = pre_native_rows(producers["native_api"])
        host = pre_native_rows(producers["host_callback"])
        begin, finish = receipt.get("started_ns"), receipt.get("completed_ns")
        if (type(begin) is not int or type(finish) is not int or begin >= finish
                or not any(r.get("pid") == packet["host_pid"] and begin <= r.get("monotonic_ns", 0) <= finish
                           and r.get("function") in ("native_new", "native_new_with_id") and r.get("edge") == "return"
                           and r.get("transaction_id") for r in native)
                or not receipt.get("path") or not pre_native_control_host(packet, host, native, receipt, begin, finish)):
            raise ValueError("Healthy controls must join actual native constructor and host association in their windows")
        backend = pre_native_rows(producers["backend_process"])
        if not pre_native_control_backend(packet, backend, control, receipt, begin, finish):
            raise ValueError("Healthy controls need an independent actual backend request")


def pre_native_sink_binding(packet, producers, client):
    event = pre_native_json(producers["event_observer"])
    sink = ORACLES.verify_reference(event["sink"])
    content = PATHS.read_bytes(sink["path"])
    offsets = event.get("before_offset"), event.get("after_offset")
    if (event.get("execution_observed") is not True or event.get("window_complete") is not True
            or type(event.get("observed_from_ns")) is not int or type(event.get("observed_through_ns")) is not int
            or event.get("observed_from_ns", client["started_ns"] + 1) > client["started_ns"]
            or event.get("observed_through_ns", 0) < client["completed_ns"]
            or any(type(v) is not int or v < 0 or v > len(content) for v in offsets)
            or offsets[0] != offsets[1]):
        raise ValueError("Zero physical events need an actual complete independent sink window")
    for label in ("before_control", "after_control"):
        pre_native_sink_control(packet, producers, client, event, content, offsets, label)


def pre_native_producer_binding(packet, producers, client):
    source = pre_native_json(producers["source_manifest"])
    if (source.get("parent_sha") != packet["parent_sha"]
            or packet["effective_config_sha256"] != producers["effective_configuration"]["sha256"]
            or packet["rules_sha256"] != producers["rules_file"]["sha256"]
            or packet["request_sha256"] != producers["request_wire"]["sha256"]):
        raise ValueError("Pre-native source/config/rules/request bytes differ from actual sealed inputs")
    pre_native_isolation_binding(packet, producers, source)
    for role in ("event_observer", "cleanup_observer", "healthy_controls"):
        actual = pre_native_json(producers[role])
        for key in ("run_scoped_case_id", "leg_id", "run_id", "parent_sha", "effective_config_sha256", "rules_sha256",
                    "host_pid", "host_starttime", "uid", "request_id", "request_sha256"):
            if actual.get(key) != packet[key]:
                raise ValueError(f"Pre-native {role} correlation differs: {key}")
    pre_native_sink_binding(packet, producers, client)
    pre_native_cleanup_binding(producers)
    pre_native_healthy_controls(packet, producers, client)


def pre_native_control_host(packet, host, native, receipt, begin, finish):
    if packet["leg_id"] == "apache-native":
        return any(r.get("pid") == packet["host_pid"] and r.get("kind") == "host_context_associated"
            and r.get("native_transaction_present") is True and r.get("owner_request_matches") is True
            and r.get("request_uri") == receipt["path"] and begin <= r.get("monotonic_ns", 0) <= finish for r in host)
    if packet["leg_id"] != "lighttpd-stock-native-control":
        raise ValueError("No healthy-control host observer contract for this profile")
    constructors = [r for r in native if r.get("pid") == packet["host_pid"] and r.get("edge") == "return"
        and r.get("function") in ("native_new", "native_new_with_id") and r.get("result") == 1
        and begin <= r.get("monotonic_ns", 0) <= finish]
    return any(r.get("schema") == "lighttpd-stock-diagnostic-host-v1" and r.get("pid") == packet["host_pid"]
        and r.get("uid") == packet["uid"] and r.get("kind") == "request_decision_returned"
        and r.get("technical_failed") == 0 and r.get("api_failed") == 0 and r.get("request_intervened") == 0
        and begin <= r.get("monotonic_ns", 0) <= finish
        and any(type(r.get("runtime_allocation_scope_call")) is int and r["runtime_allocation_scope_call"] > 0
            and r["runtime_allocation_scope_call"] == c.get("allocation_scope_call")
            and r.get("host_transaction_id") in (c.get("transaction_id"), c.get("canonical_transaction_id")) for c in constructors)
        for r in host)


def pre_native_control_backend(packet, backend, control, receipt, begin, finish):
    if packet["leg_id"] == "apache-native":
        return any(r.get("kind") in ("request", "request_arrival") and r.get("request_id") == control["request_id"] for r in backend)
    if packet["leg_id"] != "lighttpd-stock-native-control":
        raise ValueError("No healthy-control backend contract for this profile")
    return control["request_id"] == receipt["path"] and any(r.get("schema") == "apache-independent-backend-v1"
        and r.get("uid") == packet["uid"] and type(r.get("pid")) is int
        and r["pid"] > 0 and r["pid"] not in (packet["host_pid"], receipt.get("pid"))
        and r.get("path") == receipt["path"] and begin <= r.get("monotonic_ns", 0) <= finish for r in backend)


def lighttpd_pre_native_log_window(packet, producers, client):
    window = pre_native_json(producers["core_diagnostic_window"])
    for key in ("run_scoped_case_id", "leg_id", "run_id", "parent_sha", "effective_config_sha256", "rules_sha256",
                "host_pid", "host_starttime", "uid", "request_id", "request_sha256"):
        if window.get(key) != packet[key]:
            raise ValueError("Lighttpd Core window belongs to another actual execution")
    before, after = window.get("before", {}), window.get("after", {})
    identity = ("device", "inode", "mode", "owner_uid", "nlink", "path")
    raw = PATHS.read_bytes(producers["core_diagnostic"]["path"])
    if (window.get("execution_observed") is not True or window.get("exclusive_request_window") is not True
            or window.get("core_sha256") != producers["core_diagnostic"]["sha256"]
            or any(before.get(key) != after.get(key) for key in identity)
            or any(type(before.get(key)) is not int for key in ("device", "inode", "mode", "owner_uid", "nlink"))
            or before.get("owner_uid") != packet["uid"] or before.get("mode") != 0o600 or before.get("nlink") != 1
            or any(type(point.get("monotonic_ns")) is not int or point.get("uid") != packet["uid"] for point in (before, after))
            or before["monotonic_ns"] > client["started_ns"] or after["monotonic_ns"] < client["completed_ns"]
            or any(type(point.get("size")) is not int for point in (before, after))
            or not 0 <= before["size"] < after["size"] <= len(raw)):
        raise ValueError("Lighttpd diagnostic needs a complete physical private log window")
    hosts = pre_native_json(ORACLES.verify_reference(window["actual_host_identity"]))
    hosts = [host for host in hosts if host.get("pid") == packet["host_pid"]
             and host.get("starttime") == packet["host_starttime"]]
    fields = ("device", "inode", "mode", "owner_uid", "nlink")
    if not any(any(target == before["path"] and all(host.get("fd_metadata", {}).get(fd, {}).get(key) == before[key]
                    for key in fields) for fd, target in host.get("fds", {}).items()) for host in hosts):
        raise ValueError("PID-less lighttpd Core log must bind the actual host-owned descriptor inode")
    return raw[before["size"]:after["size"]].decode()


def lighttpd_pre_native_core(packet, producers, client, process):
    text = lighttpd_pre_native_log_window(packet, producers, client)
    case = packet["run_scoped_case_id"].split("::")[-1]
    message = ("duplicate Content-Length header -> 400" if case == "conflicting_content_length"
               else "invalid Content-Length header -> 400")
    if packet["source_approval"].get("core_diagnostic_code") != message:
        raise ValueError("Lighttpd source approval must select its exact parser diagnostic")
    patterns = (r"request\.c\.327\) " + re.escape(message) + r"$",
                r"request\.c\.1414\) rqst: POST " + re.escape(client["path"]) + r" HTTP/1\.1$",
                r"request\.c\.1414\) rqst: X-I12-ID: " + re.escape(packet["request_id"]) + r"$")
    for pattern in patterns:
        matching = [line for line in text.splitlines() if re.search(pattern, line)]
        in_window = False
        for line in matching:
            stamp = re.match(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)\.(\d{9}): ", line)
            if stamp is None:
                continue
            try:
                delta = datetime.datetime.strptime(stamp[1], "%Y-%m-%d %H:%M:%S") - datetime.datetime(1970, 1, 1)
                timestamp = (delta.days * 86400 + delta.seconds) * 1_000_000_000 + int(stamp[2])
            except ValueError:
                continue
            in_window |= process["started_unix_ns"] <= timestamp <= process["ended_unix_ns"]
        if not in_window:
            raise ValueError("Actual nanosecond lighttpd Core diagnostic/request must be inside the waited UTC window")


def apache_pid_matches(text, pid):
    """Match a literal Apache PID token in linear time without dynamic regex."""
    prefix = "[pid " + str(pid)
    return prefix + "]" in text or prefix + ":" in text


def apache_pre_native_core(packet, producers, process):
    diagnostic = PATHS.read_text(producers["core_diagnostic"]["path"])
    code = packet["source_approval"].get("core_diagnostic_code")
    if (not isinstance(code, str) or not re.fullmatch(r"AH\d{5}", code, re.ASCII) or code not in diagnostic
            or not apache_pid_matches(diagnostic, packet["host_pid"])
            or not packet.get("connection_id") or "[client " + packet["connection_id"] + "]" not in diagnostic):
        raise ValueError("A raw Apache Core diagnostic must independently bind the actual process and connection")
    matching_lines = [line for line in diagnostic.splitlines() if code in line
                      and apache_pid_matches(line, packet["host_pid"])
                      and "[client " + packet["connection_id"] + "]" in line]
    in_window = False
    for line in matching_lines:
        try:
            stamp = datetime.datetime.strptime(line.split("]", 1)[0][1:], "%a %b %d %H:%M:%S.%f %Y")
            delta = stamp - datetime.datetime(1970, 1, 1)
            timestamp = ((delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds) * 1000
            in_window |= process["started_unix_ns"] <= timestamp <= process["ended_unix_ns"]
        except (ValueError, IndexError):
            continue
    if not in_window:
        raise ValueError("Actual Apache Core diagnostic must fall inside the waited client UTC window")


def pre_native_physical_producers(packet, ref, sources):
    evidence = [ORACLES.verify_reference(item) for item in packet.get("measurement_evidence", [])]
    roles = pre_native_profile(packet["leg_id"])[2]
    if (len(evidence) != len(roles) or {p.get("role") for p in evidence} != roles
            or any(p["path"] == ref["path"] for p in evidence)
            or {p["sha256"] for p in evidence} & {p["sha256"] for p in sources}):
        raise ValueError("Pre-native rejection needs distinct physical producers for every dedicated role")
    for item in evidence:
        aliases = {p["role"] for p in evidence if p["path"] == item["path"]}
        if len(aliases) > 1 and aliases != {"native_module", "observer_image"}:
            raise ValueError("Pre-native producers cannot alias independent physical measurements")
    producers = {p["role"]: p for p in evidence}
    return producers, evidence


def pre_native_client_receipts(packet, row, producers):
    actual = pre_native_json(producers["driver_observation"])
    if (actual.get("original_id") != row["run_scoped_case_id"] or actual.get("case_id") != row["selected_requirement"]["case_id"]
            or actual.get("actual_principal_execution") is not True or actual.get("executed_case_contract") is not True
            or actual.get("missing_operations") != []):
        raise ValueError("A driver stub or sibling execution cannot qualify pre-native rejection")
    client = pre_native_json(producers["client_receipt"])
    process = pre_native_json(producers["client_process"])
    if (type(client.get("pid")) is not int or client["pid"] <= 0
            or type(client.get("started_ns")) is not int or type(client.get("completed_ns")) is not int
            or client["started_ns"] >= client["completed_ns"] or client.get("error") is not None
            or not process.get("argv") or not process.get("cwd") or type(process.get("wrapper_pid")) is not int
            or type(process.get("waited_exit")) is not int or process["waited_exit"] != 0
            or type(process.get("started_unix_ns")) is not int or type(process.get("ended_unix_ns")) is not int
            or process["started_unix_ns"] >= process["ended_unix_ns"]):
        raise ValueError("Pre-native rejection needs the actual completed client process and wire receipt")
    main = [item for item in actual.get("clients", []) if item.get("role") == "main"]
    if (len(main) != 1 or main[0].get("request_id") != packet["request_id"]
            or main[0].get("actual_waited_exit") != process["waited_exit"] or main[0].get("command") != process):
        raise ValueError("The actual waited client command must bind the exact original main request")
    return client, process


def pre_native_wire_binding(packet, producers, client):
    raw = PATHS.read_bytes(producers["response_wire"]["path"])
    if type(client.get("status")) is not int or client["status"] != 400 or not re.match(rb"HTTP/1\.[01] 400 [^\r\n]*\r\n", raw) or b"\r\n\r\n" not in raw:
        raise ValueError("Pre-native client status must bind an actual complete HTTP400 header block")
    request = PATHS.read_bytes(producers["request_wire"]["path"])
    if (not isinstance(client.get("path"), str) or not client["path"]
            or packet["request_id"].encode() not in request or client["path"].encode() not in request):
        raise ValueError("Pre-native main request cannot transfer from another physical client")


def reviewed_pre_native_packet(supplied, row, effective_oracle):
    """Qualify a host parser rejection, preserving the original native alternative.

    Logical phase1 does not assert a native phase call. No absent native
    transaction, P2/EOS, finish or free is replaced with a fabricated identity.
    """
    ref = ORACLES.verify_reference(supplied)
    packet = pre_native_json(ref)
    sources = pre_native_identity(packet, row, effective_oracle)
    producers, evidence = pre_native_physical_producers(packet, ref, sources)
    client, process = pre_native_client_receipts(packet, row, producers)
    pre_native_wire_binding(packet, producers, client)
    native = pre_native_native_window(packet, producers, client)
    backend = pre_native_rows(producers["backend_process"])
    if any(r.get("request_id") == packet["request_id"] or client["started_ns"] <= r.get("monotonic_ns", client["started_ns"]) <= client["completed_ns"] for r in backend):
        raise ValueError("Pre-native host rejection must have zero actual main backend activity")
    if packet["leg_id"] == "apache-native":
        apache_pre_native_core(packet, producers, process)
    elif packet["leg_id"] == "lighttpd-stock-native-control":
        lighttpd_pre_native_core(packet, producers, client, process)
    else:
        raise ValueError("Pre-native Core diagnostic has no selected host format")
    pre_native_producer_binding(packet, producers, client)
    if packet.get("outcome") != "PASS":
        raise ValueError("Only a physically established host-before-native rejection is qualified in this scope")
    return {"receipt": ref, "observations": {"client_process": process, "client": client, **native},
            "measurement_evidence": evidence, "source_approval": copy.deepcopy(packet["source_approval"]),
            "execution_observed": True, "qualification_scope": "host_pre_native_rejection",
            "full_case_qualified": True, "full_lifecycle_qualified": False, "outcome": "PASS", "unknown_fields": []}


def packet_reviewer(by_id, identity, packet):
    if by_id[identity]["selected_requirement"].get("execution_kind") == "actual_configtest":
        reviewer = reviewed_configuration_packet
    elif packet.get("execution_kind") == "host_preallocation_control":
        reviewer = reviewed_preallocation_packet
    else:
        reviewer = reviewed_packet
    if packet.get("execution_kind") == "host_pre_native_rejection":
        reviewer = reviewed_pre_native_packet
    return reviewer


def ledger_observations(packets, by_id, reviews):
    observations = {}
    for ref in packets:
        packet = json.loads(PATHS.read_text(ORACLES.verify_reference(ref)["path"]))
        identity = packet["run_scoped_case_id"]
        if identity not in by_id or identity in observations:
            raise ValueError("Unknown or duplicate original packet ID")
        review = reviews.get(identity)
        oracle = review["effective_oracle"] if review else by_id[identity]["selected_requirement"]["expected_oracle"]
        if oracle and oracle.get("unresolved_expected_value_reason"):
            oracle = None
        reviewer = packet_reviewer(by_id, identity, packet)
        observations[identity] = reviewer(ref, by_id[identity], oracle)
    return observations


def apply_observed_result(row, observations, identity, configuration, preallocation, pre_native):
    observation = observations[identity]
    row["execution_observed"] = True
    if configuration:
        row["status"] = observation["outcome"]
        row["qualified_full_case_pass"] = observation["outcome"] == "PASS"
        row["qualified_configuration_pass"] = observation["outcome"] == "PASS"
        row["qualification_scope"] = "configuration_control"
    elif preallocation:
        row["status"] = observation["outcome"]
        row["qualified_full_case_pass"] = observation["outcome"] == "PASS"
        row["qualified_preallocation_pass"] = observation["outcome"] == "PASS"
        row["qualification_scope"] = "preallocation_control"


    elif pre_native:
        row["status"] = observation["outcome"]
        row["qualified_full_case_pass"] = observation["outcome"] == "PASS"
        row["qualification_scope"] = "host_pre_native_rejection"
    elif observation["full_lifecycle_qualified"]:
        row["status"] = observation["outcome"]
        row["qualified_full_case_pass"] = observation["outcome"] == "PASS"
        row["qualified_host_lifecycle_pass"] = observation["outcome"] == "PASS"
        row["qualification_scope"] = "full_host_lifecycle"
    else:
        row["status"] = "PARTIAL_HOST_MEASUREMENTS"
        row["qualified_full_case_pass"] = False


def ledger_row(original_row, reviews, observations):
    row = copy.deepcopy(original_row)
    identity = row["run_scoped_case_id"]
    row["historical_status"] = row["status"]
    row["historical_execution_observed"] = row["execution_observed"]
    row["oracle_reconciliation"] = copy.deepcopy(reviews.get(identity))
    observation = observations.get(identity)
    configuration = observation is not None and observation.get("qualification_scope") == "configuration_control"
    preallocation = observation is not None and observation.get("qualification_scope") == "preallocation_control"
    pre_native = observation is not None and observation.get("qualification_scope") == "host_pre_native_rejection"
    row["current_lifecycle_packet"] = None if configuration or preallocation or pre_native else observation
    row["current_preallocation_packet"] = observation if preallocation else None
    row["qualified_preallocation_pass"] = False
    row["current_pre_native_packet"] = observation if pre_native else None
    row["current_configuration_packet"] = observation if configuration else None
    row["qualified_host_lifecycle_pass"] = False
    row["qualified_configuration_pass"] = False
    row["qualification_scope"] = "historical_configuration_only" if row["status"] == "PASS" else None
    if identity in observations:
        apply_observed_result(row, observations, identity, configuration, preallocation, pre_native)
    return row


def ledger_rows(original, reviews, observations):
    rows = []
    for original_row in original:
        rows.append(ledger_row(original_row, reviews, observations))
    return rows


def build_ledger(requirements, selection, reconciliation, packets):
    original = ORACLES.original_contracts(requirements, selection)
    if reconciliation["original_selected_contracts"] != [row["selected_requirement"] for row in original]:
        raise ValueError("Reconciliation does not preserve the original selected catalog")
    reviews = {row["run_scoped_case_id"]: row for row in
               reconciliation["oracle_matrix"] + reconciliation["supplemental_dispositions"]}
    by_id = {row["run_scoped_case_id"]: row for row in original}
    observations = ledger_observations(packets, by_id, reviews)
    rows = ledger_rows(original, reviews, observations)
    full = [row for row in rows if row["qualification_scope"] == "full_host_lifecycle"]
    required_full_pass = [row for row in full if row["required_leg"] and row["status"] == "PASS"]
    return {"schema_version": 1, "original_ordered_id_sha256": ORACLES.ID_SHA256,
            "original_selected_contract_sha256": ORACLES.CONTRACT_SHA256,
            "summary": {
                "original_ids": len(rows), "actually_executed_ids": sum(row["execution_observed"] is True for row in rows),
                "configuration_only_pass": sum(row["qualification_scope"] == "historical_configuration_only" for row in rows),
                "current_configuration_pass": sum(row["qualification_scope"] == "configuration_control" and row["status"] == "PASS" for row in rows),
                "current_configuration_fail": sum(row["qualification_scope"] == "configuration_control" and row["status"] == "FAIL" for row in rows),
                "current_preallocation_pass": sum(row["qualification_scope"] == "preallocation_control" and row["status"] == "PASS" for row in rows),


                "pre_native_rejection_pass": sum(row["qualification_scope"] == "host_pre_native_rejection" and row["status"] == "PASS" for row in rows),
                "full_lifecycle_pass": sum(row["status"] == "PASS" for row in full),
                "full_lifecycle_fail": sum(row["status"] == "FAIL" for row in full),
                "required_full_lifecycle_pass": len(required_full_pass),
                "required_full_lifecycle_fail": sum(row["required_leg"] and row["status"] == "FAIL" for row in full),
                "required_qualified_pass": sum(row["required_leg"] and row["status"] == "PASS" for row in rows),
                "required_qualified_fail": sum(row["required_leg"] and row["status"] == "FAIL" for row in rows),
                "required_routes_with_full_case": len({row["leg_id"] for row in required_full_pass}),
                "unqualified_ids": sum(row["qualification_scope"] is None for row in rows),
                "oracle_counts": copy.deepcopy(reconciliation["summary"]),
            }, "rows": rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("requirements", "original-selection", "reconciliation", "reviewed-packets", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    result = build_ledger(json.loads(PATHS.read_text(args.requirements)), json.loads(PATHS.read_text(args.original_selection)),
                          json.loads(PATHS.read_text(args.reconciliation)),
                          json.loads(PATHS.read_text(args.reviewed_packets))["packets"])
    PATHS.create_text(args.output, json.dumps(result, indent=2, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()
