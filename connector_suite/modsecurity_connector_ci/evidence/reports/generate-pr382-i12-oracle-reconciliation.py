#!/usr/bin/env python3
"""Reconcile the immutable PR382 I12 oracle inventory without qualifying runtime."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import argparse
import collections
import copy
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

_CHECKOUT_ROOT = connector_root()
_CI_LIB = _CHECKOUT_ROOT / "ci" / "lib"

import modsecurity_connector_ci.lib.i12_path_safety as PATHS

ID_SHA256 = "a74761d9722b646873325ecd27ea99661f00bee67052980fa04ede0e1f1a0f6f"
CONTRACT_SHA256 = "c493e0a5d270121f65a6cd6a1f37bdf81f8d1304c2dd770322e5a9d017b2f8e2"
SELECTION_SHA256 = "c55de04134a31f0a6a4a64ac2af930a882b180c68e3da1855daf7972b90afa84"
CATEGORIES = frozenset((
    "SOURCE_CONFIRMED_EXPECTATION", "HOST_SEMANTICS_CONFIRMED",
    "ORACLE_DEFECT_CONFIRMED", "PRODUCT_DEFECT_CONFIRMED",
    "HARNESS_DEFECT_CONFIRMED", "UNSUPPORTED_CAPABILITY",
    "UNRESOLVED_ORACLE", "BLOCKED_ENVIRONMENT",
))
UNRESOLVED = frozenset(("UNRESOLVED_ORACLE", "BLOCKED_ENVIRONMENT"))
INDEPENDENT_KINDS = frozenset((
    "official_host_contract", "native_engine_contract", "protocol_contract",
    "independent_host_probe", "independent_engine_probe",
))


def canonical_digest(value):
    content = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(content.encode()).hexdigest()


def reference(path):
    """Bind only a physical regular file, including all parent path components."""
    path = Path(path)
    if not path.is_absolute():
        raise ValueError(f"Evidence is not a physical absolute regular file: {path}")
    try:
        admitted = PATHS.input_path(path)
    except ValueError as error:
        raise ValueError(f"Evidence is not a physical absolute regular file: {path}") from error
    data = PATHS.read_bytes(admitted)
    return {"path": str(path), "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


def ensure_output_directory(path):
    """Materialize only an independently admitted runtime report directory."""
    return PATHS.ensure_directory(path)


def verify_reference(supplied):
    observed = reference(supplied["path"])
    if observed["sha256"] != supplied.get("sha256"):
        raise ValueError("Evidence content does not match its recorded SHA256")
    if "bytes" in supplied and observed["bytes"] != supplied["bytes"]:
        raise ValueError("Evidence byte length changed")
    return {**supplied, **observed}


def original_contracts(requirements, selection):
    rows = requirements["rows"]
    ids = [row["run_scoped_case_id"] for row in rows]
    if len(ids) != 1484 or len(set(ids)) != 1484:
        raise ValueError("Original I12 catalog must contain exactly 1484 unique IDs")
    if hashlib.sha256(("\n".join(ids) + "\n").encode()).hexdigest() != ID_SHA256:
        raise ValueError("Original ordered ID stream changed")
    contracts = [row["selected_requirement"] for row in rows]
    if canonical_digest(contracts) != CONTRACT_SHA256:
        raise ValueError("Original selected contracts or original oracles changed")
    selected = [case for leg in selection["legs"] for case in leg["required_cases"]]
    if selected != contracts:
        raise ValueError("Catalog no longer matches the original source selection")
    membership = [(leg["leg_id"], leg["required_leg"]) for leg in selection["legs"] for _ in leg["required_cases"]]
    for row, (leg_id, required_leg) in zip(rows, membership, strict=True):
        if row["leg_id"] != leg_id or row["required_leg"] is not required_leg:
            raise ValueError("Original selected profile or diagnostic membership changed")
        if row["selected_requirement"]["run_scoped_case_id"] != row["run_scoped_case_id"]:
            raise ValueError("Selected ID differs from catalog row ID")
        if row["run_scoped_case_id"].split("::")[1] != row["leg_id"]:
            raise ValueError("Catalog profile identity changed")
    if sum(row["required_leg"] is True for row in rows) != 1406:
        raise ValueError("Original required/diagnostic membership changed")
    return rows


def group_requirement(contract):
    """Inventory groups describe missing work; they never supply expected values."""
    name = contract["case_id"].lower()
    if contract["origin"] == "historical_reproduction":
        return "historical_fixture_binding"
    groups = (
        ("correlation_lease", ("correlation", "lease", "ttl", "companion")),
        ("physical_event_sink", ("event-sink",)),
        ("native_body_semantics", ("request-", "response-", "body-", "native-body", "native-file", "native-memory")),
        ("commit_action", ("commit", "redirect", "profile-", "first-byte", "second-response")),
        ("transport_cleanup", ("cancel", "eos", "reset", "rst", "neighbor", "reentry", "callback", "cleanup", "reuse")),
        ("resource_identity", ("capacity", "spool", "uid", "nobody", "binary", "provenance", "reserve", "readmission")),
        ("sample_frame_scope", ("sample", "frame", "buffer", "32768", "metadata")),
    )
    for group, terms in groups:
        if any(term in name for term in terms):
            return group
    return "missing_effective_fixture_and_oracle"


def evidence_sources(record):
    independent = [verify_reference(item) for item in record.get("independent_sources", [])]
    if not independent or any(item.get("kind") not in INDEPENDENT_KINDS for item in independent):
        raise ValueError("Resolution needs a supported independent source")
    if any(not item.get("revision") for item in independent):
        raise ValueError("Independent source revision/version is missing")
    implementation = [verify_reference(item) for item in record.get("implementation_sources", [])]
    if {item["sha256"] for item in independent} & {item["sha256"] for item in implementation}:
        raise ValueError("Implementation bytes cannot also serve as independent confirmation")
    return independent, implementation


def validate_retest(supplied, case_id, leg_id, expectation):
    receipt_ref = verify_reference(supplied)
    receipt = json.loads(PATHS.read_text(receipt_ref["path"]))
    if receipt.get("execution_observed") is not True:
        raise ValueError("Retest requires an observed actual execution")
    if receipt.get("run_scoped_case_id") != case_id or receipt.get("leg_id") != leg_id:
        raise ValueError("Retest cannot transfer from another case or sibling profile")
    if receipt.get("oracle_sha256") != canonical_digest(expectation):
        raise ValueError("Retest was not evaluated against the reviewed effective oracle")
    for field in ("run_id", "parent_sha", "effective_config_sha256", "rules_sha256"):
        if not receipt.get(field):
            raise ValueError(f"Retest lacks actual identity binding: {field}")
    if receipt.get("oracle_evaluated") is not True or receipt.get("outcome") not in ("PASS", "FAIL"):
        raise ValueError("Retest needs explicit observed oracle evaluation")
    if not receipt.get("actual_observations") or not receipt.get("measurement_evidence"):
        raise ValueError("Retest lacks independent actual measurements")
    measurements = [verify_reference(item) for item in receipt["measurement_evidence"]]
    return {"receipt": receipt_ref, "measurement_evidence": measurements,
            "outcome": receipt["outcome"], "full_lifecycle_qualified": False}


def validate_unsupported_applicability(supplied, row, independent):
    receipt_ref = verify_reference(supplied)
    receipt = json.loads(PATHS.read_text(receipt_ref["path"]))
    if receipt.get("run_scoped_case_id") != row["run_scoped_case_id"] or receipt.get("leg_id") != row["leg_id"]:
        raise ValueError("Unsupported applicability cannot transfer between IDs or profiles")
    if receipt.get("capability_supported") is not False:
        raise ValueError("Unsupported disposition needs an explicit negative capability proof")
    if not receipt.get("parent_sha") or not receipt.get("effective_config_sha256"):
        raise ValueError("Unsupported applicability lacks source/config identity")
    proof = [verify_reference(item) for item in receipt.get("capability_evidence", [])]
    if not proof or not {item["sha256"] for item in proof} & {item["sha256"] for item in independent}:
        raise ValueError("Unsupported applicability lacks independent capability evidence")
    return {"receipt": receipt_ref, "capability_evidence": proof}


def validate_traefik_expected_absence(record, row, effective, independent, missing):
    """Review known absence without supplying a status, phase or runtime fact.

    Ordinary unresolved nulls remain errors. Only separately approved primary
    host/protocol sources can establish absence for an exact Traefik contract.
    Host execution and all applicable lifecycle observations remain separate.
    """
    approval = record.get("expected_absence")
    routes = {"traefik-native-uds", "traefik-forwardauth-request",
              "traefik-forwardauth-response-companion"}
    selected = row["selected_requirement"]
    identity = row["run_scoped_case_id"]
    if (not isinstance(approval, dict) or row.get("leg_id") not in routes
            or identity != f"I12::{row['leg_id']}::{selected.get('case_id')}"
            or selected.get("run_scoped_case_id") != identity
            or record.get("run_scoped_case_id") != identity):
        raise ValueError("Effective oracle still lacks an applicable expectation; exact absence approval required")
    expected = {"schema_version": 1, "reviewed_by": "root", "run_scoped_case_id": identity,
                "leg_id": row["leg_id"], "selected_requirement_sha256": canonical_digest(selected),
                "original_oracle_sha256": canonical_digest(selected["expected_oracle"])}
    if (type(approval.get("schema_version")) is not int
            or any(approval.get(name) != value for name, value in expected.items())
            or set(approval) != {*expected, "fields"}):
        raise ValueError("Expected absence needs separate Root review of the exact original contract")
    fields = approval.get("fields")
    if not isinstance(fields, dict) or not missing or set(fields) != missing:
        raise ValueError("Expected absence must cover exactly the literal null expectation fields")
    kinds = {"native_result": "no_native_decision", "phase": "no_native_phase",
             "visible_status": "no_http_response"}
    sources = {(p["path"], p["sha256"], p.get("kind"), p.get("revision")) for p in independent}
    reviewed = copy.deepcopy(approval)
    for field, supplied in fields.items():
        if (field not in effective or not isinstance(supplied, dict)
                or set(supplied) != {"kind", "reason", "proof"}
                or supplied.get("kind") != kinds[field]
                or not isinstance(supplied.get("reason"), str) or not supplied["reason"].strip()):
            raise ValueError("Expected absence needs an explicit typed reason for each literal null")
        proof = [verify_reference(item) for item in supplied.get("proof", [])]
        if (not proof or any((p["path"], p["sha256"], p.get("kind"), p.get("revision"))
                             not in sources for p in proof)
                or any(p.get("kind") not in {"official_host_contract", "protocol_contract",
                                              "native_engine_contract"} for p in proof)
                or not {"official_host_contract", "protocol_contract"} <= {p.get("kind") for p in proof}):
            raise ValueError("Expected absence requires independently reviewed primary host and protocol sources")
        reviewed["fields"][field]["proof"] = proof
    return reviewed


def intentional_null_fields(record, original, effective, independent, implementation):
    """Preserve an explicitly unspecified original status, never missing evidence."""
    supplied = record.get("intentional_null_fields")
    if supplied is None:
        return {}
    if (not isinstance(supplied, dict) or set(supplied) != {"visible_status"} or
            record.get("category") not in ("SOURCE_CONFIRMED_EXPECTATION", "HOST_SEMANTICS_CONFIRMED") or
            record.get("approved_correction") is not None or record.get("resolved_expectation") is not None):
        raise ValueError("Intentional null permits only the unchanged original visible_status contract")
    if (original.get("unresolved_expected_value_reason") or "visible_status" not in original or
            original["visible_status"] is not None or "visible_status" not in effective or
            effective["visible_status"] is not None or canonical_digest(original) != canonical_digest(effective) or
            any(field not in original or original[field] is None for field in ("native_result", "phase"))):
        raise ValueError("Intentional null cannot replace an unresolved, missing or changed original expectation")
    item = copy.deepcopy(supplied["visible_status"])
    if not isinstance(item, dict) or item.get("reviewed_by") != "root" or not item.get("interpretation"):
        raise ValueError("Intentional null needs a separate Root interpretation")
    proofs = [verify_reference(ref) for ref in item.get("proof", [])]
    independent_bindings = {(ref["path"], ref["sha256"], ref.get("kind"), ref.get("revision")) for ref in independent}
    implementation_hashes = {ref["sha256"] for ref in implementation}
    for proof in proofs:
        binding = (proof["path"], proof["sha256"], proof.get("kind"), proof.get("revision"))
        if (proof.get("kind") not in ("official_host_contract", "native_engine_contract", "protocol_contract") or
                not proof.get("revision") or binding not in independent_bindings or
                proof["sha256"] in implementation_hashes):
            raise ValueError("Intentional null proof must bind the same independent primary source and revision")
    if not proofs:
        raise ValueError("Intentional null needs independently verified primary proof")
    item["proof"] = proofs
    return {"visible_status": item}


APACHE_ABSENCE_CASES = frozenset(("NEED-missing-eos", "NEED-cancel", "NEED-client-exit-signal",
                                 "NEED-incomplete-framing", "NEED-abort-reset-observation"))


def apache_scope_approval(approval, row, scope):
    """An explicit exact-contract source review; never supplies runtime facts."""
    selected = row["selected_requirement"]
    name = selected.get("case_id")
    allowed = APACHE_ABSENCE_CASES if scope == "visible_status_absence" else frozenset()
    if (row.get("leg_id") != "apache-native" or name not in allowed
            or row.get("run_scoped_case_id") != f"I12::apache-native::{name}"
            or selected.get("run_scoped_case_id") != row["run_scoped_case_id"]
            or selected.get("requirement_mapping") != [f"I12::apache-native::obligation::{name.removeprefix('NEED-')}"]):
        raise ValueError("Apache scope requires an exact original supported ID")
    if (approval.get("reviewed_by") != "root" or approval.get("scope") != scope
            or approval.get("run_scoped_case_id") != row["run_scoped_case_id"]
            or approval.get("selected_requirement_sha256") != canonical_digest(selected)
            or approval.get("requirement_mapping_sha256") != canonical_digest(selected.get("requirement_mapping"))
            or not approval.get("reason")):
        raise ValueError("Apache scope needs separate Root approval of the original contract and mapping")
    proofs = [verify_reference(item) for item in approval.get("proof", [])]
    if (not proofs or any(item.get("kind") not in INDEPENDENT_KINDS or not item.get("revision") for item in proofs)
            or not any(item.get("kind") == "official_host_contract" for item in proofs)):
        raise ValueError("Apache scope lacks a version-bound independent host contract")
    if scope == "visible_status_absence" and not any(item.get("kind") == "protocol_contract" for item in proofs):
        raise ValueError("Expected status absence also needs an independent protocol contract")
    if {p["sha256"] for p in proofs if p.get("kind") == "official_host_contract"} & {
            p["sha256"] for p in proofs if p.get("kind") == "protocol_contract"}:
        raise ValueError("Independent Apache and protocol approval must bind separate source bytes")
    return {**copy.deepcopy(approval), "proof": proofs}


def validate_visible_status_absence(record, row, effective, independent):
    if effective.get("expected_absence") != {"visible_status": {"kind": "no_complete_http_status_line"}}:
        raise ValueError("Only explicitly typed visible-status absence is supported")
    original = row["selected_requirement"]["expected_oracle"]
    if ("visible_status" not in effective or "visible_status" not in original
            or original["visible_status"] is not None or not original.get("unresolved_expected_value_reason")
            or record.get("category") not in ("SOURCE_CONFIRMED_EXPECTATION", "HOST_SEMANTICS_CONFIRMED")):
        raise ValueError("Typed absence cannot replace an existing status oracle or hide a defect")
    approval = apache_scope_approval(record.get("expected_absence_approval", {}), row, "visible_status_absence")
    if not {p["sha256"] for p in approval["proof"]} <= {p["sha256"] for p in independent}:
        raise ValueError("Absence approval must use the independently reviewed source bytes")
    if record.get("retest") is None:
        raise ValueError("Expected absence requires an independently observed physical retest")
    return approval


def successful_absence_control(record, client, before):
    timestamp = record.get("monotonic_ns")
    return (record.get("schema") == "native-lifecycle-v1" and record.get("run") == client["run_id"]
            and record.get("profile") == "apache-native"
            and record.get("case") == client["run_scoped_case_id"].split("::")[-1]
            and record.get("pid") == client["host_pid"] and record.get("invalid") is False
            and record.get("function") in ("native_new", "native_new_with_id")
            and record.get("edge") == "return" and type(record.get("result")) is int
            and record["result"] == 1 and type(timestamp) is int
            and (timestamp < client["started_ns"] if before else timestamp > client["completed_ns"]))


def absence_control_identities(observations, client, before):
    """Read actual successful native allocations, separate from the main request."""
    identities = set()
    for proof in observations["native_api_returns"].get("evidence", []):
        if proof.get("role") != "native_api":
            continue
        source = verify_reference(proof)
        for line in PATHS.read_bytes(source["path"]).splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            if not isinstance(record, dict):
                raise ValueError("Native control evidence must contain observer records")
            if successful_absence_control(record, client, before):
                identities.update(record[key] for key in ("transaction_id", "canonical_transaction_id")
                                  if isinstance(record.get(key), str) and record[key]
                                  and record[key] != client["native_transaction_id"])
    return identities


def validate_absence_sink_control(observer, content, offsets, observations, client, before, label):
    control = observer.get(label, {})
    begin, finish = control.get("start_offset"), control.get("end_offset")
    if (type(begin) is not int or type(finish) is not int or not 0 <= begin < finish <= len(content)
            or not content[begin:finish].strip()
            or (finish > offsets[0] if before else begin < offsets[1])):
        raise ValueError("Zero events need nonempty physical control ranges before and after the window")
    identities = absence_control_identities(observations, client, before)
    positive = [json.loads(line) for line in content[begin:finish].splitlines() if line.strip()]
    if (not positive or any(not isinstance(record, dict) or record.get("transaction_id") not in identities
            or record.get("connector") != "apache" or not isinstance(record.get("message_id"), str)
            or not record["message_id"].startswith("MSCONN_EVENT_") for record in positive)):
        raise ValueError("Positive physical sink controls must join actual native allocations before and after")


def validate_absence_sink_window(observer, events, observations, client):
    """A sealed sink window and allocated positive controls prove observer liveness."""
    start, end = client.get("started_ns"), client.get("completed_ns")
    observed_start, observed_end = observer.get("observed_from_ns"), observer.get("observed_through_ns")
    if (any(type(value) is not int or value < 0 for value in (start, end, observed_start, observed_end))
            or not observed_start <= start <= end <= observed_end):
        raise ValueError("Zero event observation must cover the actual typed client execution window")
    sink = verify_reference(observer["sink"])
    sink_hashes = {proof["sha256"] for proof in events.get("evidence", [])
                   if proof.get("role") == "physical_event_sink"}
    if sink_hashes != {sink["sha256"]} or set(observer.get("sink_sha256", [])) != sink_hashes:
        raise ValueError("Zero event window must cover the packet's physical sink bytes")
    content = PATHS.read_bytes(sink["path"])
    offsets = observer.get("before_offset"), observer.get("after_offset")
    if (any(type(value) is not int or not 0 <= value <= len(content) for value in offsets)
            or offsets[0] != offsets[1]):
        raise ValueError("Zero events need equal typed offsets inside the immutable sink")
    for before, label in ((True, "before_control"), (False, "after_control")):
        validate_absence_sink_control(observer, content, offsets, observations, client, before, label)


def validate_absence_process_wait(client):
    signal = client["actual_waited_signal"]
    if (signal is not None and (type(signal) is not int or signal <= 0)
            or signal is not None and client["actual_waited_exit"] != -signal
            or signal is None and client["actual_waited_exit"] < 0
            or client["termination_kind"] == "client_signalled" and signal is None):
        raise ValueError("Client termination needs a consistent actual process wait/signal")


def validate_absence_client_identity(receipt, client, host, physical):
    for key in ("run_scoped_case_id", "leg_id", "run_id", "parent_sha", "effective_config_sha256", "rules_sha256"):
        if (not receipt.get(key) or client.get(key) != receipt[key]
                or physical.get(key) != receipt[key] or host.get(key) != receipt[key]):
            raise ValueError("Status absence receipts must bind the same actual case/run/source/config")
    if (client.get("execution_observed") is not True or client.get("executed_case_contract") is not True
            or client.get("status", "missing") is not None or not client.get("request_id")
            or type(client.get("host_pid")) is not int or client["host_pid"] <= 0
            or not client.get("native_transaction_id")
            or client.get("termination_kind") not in ("client_signalled", "client_reset", "server_abort")
            or type(client.get("actual_waited_exit")) is not int
            or "actual_waited_signal" not in client or not client.get("argv") or not client.get("cwd")
            or type(client.get("client_pid")) is not int or client["client_pid"] <= 0):
        raise ValueError("EOF or an unimplemented/uncorrelated client operation cannot prove expected absence")
    validate_absence_process_wait(client)
    for key in ("request_id", "client_pid", "host_pid", "native_transaction_id"):
        if host.get(key) != client[key] or physical.get(key) != client[key]:
            raise ValueError("Absence requires exact request/process/native correlation")
    if (host.get("execution_observed") is not True or host.get("termination_observed") is not True
            or host.get("termination_kind") != client["termination_kind"]):
        raise ValueError("Client EOF cannot replace independent actual host termination")


def validate_absence_native_identity(packet, client):
    native_identity = packet["observations"]["native_transaction_id"]["value"]
    if (not isinstance(native_identity, dict) or not isinstance(native_identity.get("transaction_id"), str)
            or client["native_transaction_id"] != native_identity["transaction_id"]):
        raise ValueError("Absence must join the actual allocated native transaction")


def validate_absence_events(witness, observations, client, client_ref, host_ref, capture):
    events = observations["native_events"]
    event_value = events.get("value")
    if (events.get("applicable", True) is not True or not isinstance(event_value, dict)
            or event_value.get("native_transaction_id") != client["native_transaction_id"]
            or not isinstance(event_value.get("native_audit_lines"), list)
            or not isinstance(event_value.get("physical_common_rows"), list)):
        raise ValueError("Expected absence needs measured physical event presence or absence")
    if not event_value["native_audit_lines"] and not event_value["physical_common_rows"]:
        observer_ref = verify_reference(witness["event_observer_receipt"])
        observer = json.loads(PATHS.read_text(observer_ref["path"]))
        for key in ("run_scoped_case_id", "leg_id", "run_id", "parent_sha", "effective_config_sha256",
                    "rules_sha256", "request_id", "host_pid", "native_transaction_id"):
            if observer.get(key) != client.get(key):
                raise ValueError("Zero physical events need a correlated independent observer")
        sink_hashes = {p["sha256"] for p in events.get("evidence", []) if p.get("role") == "physical_event_sink"}
        if (observer.get("execution_observed") is not True or observer.get("window_complete") is not True
                or observer.get("positive_control_observed") is not True
                or set(observer.get("sink_sha256", [])) != sink_hashes or not sink_hashes
                or observer_ref["sha256"] in {client_ref["sha256"], host_ref["sha256"], capture["sha256"]}):
            raise ValueError("Zero physical events need actual complete sink observation with a positive control")
        validate_absence_sink_window(observer, events, observations, client)


def validate_absence_lifetime(observations, capture, client_ref, host_ref):
    for name, counters in (("finish_calls", {"common_finish", "native_logging"}),
                           ("native_free_calls", {"native_cleanup", "common_cleanup", "host_association_retire"})):
        value = observations[name].get("value")
        if (not isinstance(value, dict) or set(value) != counters
                or any(type(value[key]) is not int or value[key] != 1 for key in counters)):
            raise ValueError("Expected absence needs exactly one actual finish and native free")
    native_proofs = {p["sha256"] for name in ("native_api_returns", "native_transaction_id", "finish_calls", "native_free_calls")
                     for p in observations[name].get("evidence", []) if p.get("role") == "native_api"}
    if not native_proofs or native_proofs & {capture["sha256"], client_ref["sha256"], host_ref["sha256"]}:
        raise ValueError("Native lifecycle measurements must be independent of wire and host/client receipts")
    client_proofs = {p["sha256"] for name in ("client_exit", "client_headers", "transport_framing")
                     for p in observations[name].get("evidence", []) if p.get("role") == "client_process"}
    if not {capture["sha256"], client_ref["sha256"]} <= client_proofs:
        raise ValueError("Wire and termination captures must independently support the normal lifecycle packet")


def validate_absence_reset(observations, host_ref, client_ref):
    reset = observations["transport_reset_scope"]
    if reset.get("applicable", True) is not True or reset.get("value") is None:
        raise ValueError("Expected absence needs actual independently observed host/client termination scope")
    roles = {p.get("role") for p in reset.get("evidence", [])}
    host_proofs = {p["sha256"] for p in reset.get("evidence", []) if p.get("role") == "host_callback"}
    if (not {"host_callback", "client_process"} <= roles or host_ref["sha256"] not in host_proofs
            or host_ref["sha256"] == client_ref["sha256"]):
        raise ValueError("Client EOF alone cannot prove host termination scope")


def validate_absence_retest(supplied, row, effective):
    """Require the unchanged full lifecycle contract plus physical negative wire evidence.

    This does not exempt native calls, identities, finish/free or cleanup from
    the normal 35-field ledger. A failing full packet remains a failing retest.
    """
    receipt = json.loads(PATHS.read_text(verify_reference(supplied)["path"]))
    witness = receipt.get("visible_status_absence", {})
    ledger = load_source(Path(__file__).with_name('generate-pr382-i12-lifecycle-ledger.py'))
    packet = ledger.reviewed_packet(witness["lifecycle_packet"], row, effective)
    if not packet["full_lifecycle_qualified"] or packet["outcome"] != receipt["outcome"]:
        raise ValueError("Expected absence cannot bypass native lifecycle or cleanup qualification")
    physical = json.loads(PATHS.read_text(verify_reference(witness["lifecycle_packet"])["path"]))
    client_ref = verify_reference(witness["client_termination_receipt"])
    capture = verify_reference(witness["response_capture"])
    host_ref = verify_reference(witness["host_termination_receipt"])
    if len({client_ref["path"], capture["path"], host_ref["path"]}) != 3:
        raise ValueError("Client, wire and independent host witnesses must be separate files")
    client = json.loads(PATHS.read_text(client_ref["path"]))
    host = json.loads(PATHS.read_text(host_ref["path"]))
    validate_absence_client_identity(receipt, client, host, physical)
    validate_absence_native_identity(packet, client)
    raw = PATHS.read_bytes(capture["path"])
    if re.search(rb"(?:^|\n)HTTP/\d+\.\d+ \d{3}(?: [^\r\n]*)?\r?\n", raw):
        raise ValueError("An actual received HTTP status contradicts expected status absence")
    if client.get("response_capture_sha256") != capture["sha256"]:
        raise ValueError("Negative wire observation is not bound to the actual client capture")
    observations = packet["observations"]
    for name in ("native_api_returns", "cleanup_receipts"):
        item = observations[name]
        if item.get("applicable", True) is not True or not item.get("value"):
            raise ValueError("Expected absence needs actual API returns and cleanup")
    validate_absence_events(witness, observations, client, client_ref, host_ref, capture)
    validate_absence_lifetime(observations, capture, client_ref, host_ref)
    validate_absence_reset(observations, host_ref, client_ref)
    return {"client_termination_receipt": client_ref, "host_termination_receipt": host_ref, "response_capture": capture,
            "lifecycle_packet": packet, "visible_status": None}


def corrected_expectation(category, original, correction, resolution, independent, effective):
    if correction is not None:
        if category != "ORACLE_DEFECT_CONFIRMED":
            raise ValueError("Only an independently confirmed oracle defect permits correction")
        if correction.get("reviewed_by") != "root" or not correction.get("reason"):
            raise ValueError("Correction lacks a separate Root approval and reason")
        proof = [verify_reference(item) for item in correction.get("proof", [])]
        if not proof or not {item["sha256"] for item in proof} & {item["sha256"] for item in independent}:
            raise ValueError("Correction lacks independently verified proof")
        effective = copy.deepcopy(correction["expected_oracle"])
    elif category == "ORACLE_DEFECT_CONFIRMED":
        raise ValueError("Confirmed oracle defect requires a separately approved correction")
    if resolution is not None:
        if category not in ("SOURCE_CONFIRMED_EXPECTATION", "HOST_SEMANTICS_CONFIRMED"):
            raise ValueError("Resolution cannot conceal product/harness defects or unresolved conflicts")
        if not original.get("unresolved_expected_value_reason"):
            raise ValueError("An existing oracle requires explicit correction rather than replacement")
        effective = copy.deepcopy(resolution)
    return effective


def resolved_expectation_absence(record, row, effective, category, null_fields, independent):
    resolved = category not in UNRESOLVED
    absence, traefik_absence = None, None
    if resolved and category != "UNSUPPORTED_CAPABILITY":
        if effective.get("unresolved_expected_value_reason"):
            raise ValueError("A resolved oracle must provide an independently bound expectation")
        if effective.get("physical_evidence_not_projection") is not True:
            raise ValueError("Effective oracle must preserve physical evidence requirement")
        missing = {field for field in ("native_result", "visible_status", "phase")
                   if effective.get(field) is None and field not in null_fields}
        if record.get("expected_absence") is not None:
            traefik_absence = validate_traefik_expected_absence(record, row, effective, independent, missing)
        elif missing == {"visible_status"} and effective.get("expected_absence") is not None:
            absence = validate_visible_status_absence(record, row, effective, independent)
        elif missing:
            raise ValueError("Effective oracle still lacks an applicable expectation: "
                             + ", ".join(sorted(missing)) + "; exact absence approval required")
    return absence, traefik_absence


def reviewed_retest(record, row, category, resolved, effective, absence):
    retest = None
    if record.get("retest") is not None:
        if not resolved or category == "UNSUPPORTED_CAPABILITY":
            raise ValueError("Unresolved or unsupported expectation cannot receive a passing retest")
        retest = validate_retest(record["retest"], row["run_scoped_case_id"], row["leg_id"], effective)
    if absence is not None:
        retest["visible_status_absence"] = validate_absence_retest(record["retest"], row, effective)
    elif effective.get("expected_absence") is not None:
        raise ValueError("Expected absence must describe a literal null visible status")
    return retest


def review_record(record, row):
    category = record.get("category")
    if category not in CATEGORIES:
        raise ValueError("Unsupported oracle category")
    if record.get("reviewed_by") != "root" or record.get("leg_id") != row["leg_id"]:
        raise ValueError("Oracle disposition requires Root review of the exact profile")
    if not record.get("interpretation") or not record.get("scope"):
        raise ValueError("Oracle disposition needs an interpretation and scope")
    original = row["selected_requirement"]["expected_oracle"]
    effective = copy.deepcopy(original)
    independent, implementation = [], []
    if category not in UNRESOLVED or record.get("independent_sources"):
        independent, implementation = evidence_sources(record)
    applicability = None
    if category == "UNSUPPORTED_CAPABILITY":
        if not record.get("applicability_receipt"):
            raise ValueError("Unsupported capability needs an independently bound per-ID applicability receipt")
        applicability = validate_unsupported_applicability(record["applicability_receipt"], row, independent)
    correction = record.get("approved_correction")
    resolution = record.get("resolved_expectation")
    effective = corrected_expectation(category, original, correction, resolution, independent, effective)
    resolved = category not in UNRESOLVED
    null_fields = intentional_null_fields(record, original, effective, independent, implementation)
    absence = None
    traefik_absence = None
    absence, traefik_absence = resolved_expectation_absence(record, row, effective, category, null_fields, independent)
    retest = reviewed_retest(record, row, category, resolved, effective, absence)
    return {"category": category, "resolved": resolved,
            "interpretation": record["interpretation"], "scope": record["scope"],
            "independent_sources": independent, "implementation_sources": implementation,
            "unsupported_applicability": applicability, "expected_absence_approval": absence,
            "approved_correction": copy.deepcopy(correction), "effective_oracle": effective,
            "intentional_null_fields": null_fields,
            "retest": retest, "full_lifecycle_qualified": False,
            **({"expected_absence": traefik_absence} if traefik_absence is not None else {})}


def reconcile(requirements, selection, records):
    rows = original_contracts(requirements, selection)
    unresolved_ids = [row["run_scoped_case_id"] for row in rows
                      if row["selected_requirement"]["expected_oracle"].get("unresolved_expected_value_reason")]
    if len(unresolved_ids) != 596:
        raise ValueError("Original 596-member unresolved subset changed")
    reviews = {}
    row_by_id = {row["run_scoped_case_id"]: row for row in rows}
    for record in records:
        case_id = record["run_scoped_case_id"]
        if case_id not in row_by_id or case_id in reviews:
            raise ValueError("Reviewed record has an unknown or duplicate original case ID")
        reviews[case_id] = review_record(record, row_by_id[case_id])
    inventory, supplemental = [], []
    for row in rows:
        case_id = row["run_scoped_case_id"]
        in_subset = case_id in unresolved_ids
        if not in_subset and case_id not in reviews:
            continue
        contract = row["selected_requirement"]
        entry = {"run_scoped_case_id": case_id, "leg_id": row["leg_id"],
                 "required_leg": row["required_leg"], "original_596_member": in_subset,
                 "original_oracle": copy.deepcopy(contract["expected_oracle"]),
                 "original_selected_requirement": copy.deepcopy(contract),
                 "original_source_revision": copy.deepcopy(selection["revisions"]),
                 "original_source_hashes": copy.deepcopy(selection["source_hashes"]),
                 "rootcause_group": group_requirement(contract),
                 "category": "UNRESOLVED_ORACLE", "resolved": False,
                 "interpretation": "No independently approved exact selected fixture/oracle binding.",
                 "scope": row["leg_id"], "independent_sources": [],
                 "implementation_sources": [], "approved_correction": None,
                 "effective_oracle": None, "retest": None,
                 "full_lifecycle_qualified": False}
        if case_id in reviews:
            entry.update(reviews[case_id])
        (inventory if in_subset else supplemental).append(entry)
    resolved = sum(entry["resolved"] for entry in inventory)
    return {"schema_version": 1, "original_ordered_ids": list(row_by_id),
            "original_selected_contracts": [copy.deepcopy(row["selected_requirement"]) for row in rows],
            "original_ordered_id_sha256": ID_SHA256,
            "original_selected_contract_sha256": CONTRACT_SHA256,
            "original_596_ordered_ids": unresolved_ids,
            "original_596_membership_sha256": canonical_digest(unresolved_ids),
            "summary": {"original_ids": 1484, "original_required_ids": 1406,
                        "original_diagnostic_ids": 78, "original_open_oracles": 596,
                        "resolved_original_oracles": resolved, "unresolved_original_oracles": 596 - resolved,
                        "actually_retested_original_oracles": sum(entry["retest"] is not None for entry in inventory),
                        "unsupported_original_oracles": sum(entry["category"] == "UNSUPPORTED_CAPABILITY" for entry in inventory),
                        "supplemental_original_oracle_dispositions": len(supplemental),
                        "full_lifecycle_qualification_performed": False,
                        "baseline_config_parser_pass": sum(row["status"] == "PASS" for row in rows),
                        "baseline_observed_ids": sum(row.get("execution_observed") is True for row in rows),
                        "categories": dict(collections.Counter(entry["category"] for entry in inventory)),
                        "rootcause_groups": dict(collections.Counter(entry["rootcause_group"] for entry in inventory)),
                        "by_profile": dict(collections.Counter(entry["leg_id"] for entry in inventory))},
            "oracle_matrix": inventory, "supplemental_dispositions": supplemental}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--requirements", type=Path, required=True)
    parser.add_argument("--original-selection", type=Path, required=True)
    parser.add_argument("--reviewed-records", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    inputs = [reference(path) for path in (args.requirements, args.original_selection, args.reviewed_records)]
    if inputs[1]["sha256"] != SELECTION_SHA256:
        raise ValueError("Immutable original source selection bytes changed")
    matrix = reconcile(json.loads(PATHS.read_text(args.requirements)), json.loads(PATHS.read_text(args.original_selection)),
                       json.loads(PATHS.read_text(args.reviewed_records))["records"])
    matrix["input_evidence"] = inputs
    ensure_output_directory(args.output_dir)
    output = args.output_dir / "oracle-reconciliation.json"
    PATHS.create_text(output, json.dumps(matrix, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({"output": reference(output.absolute()), "summary": matrix["summary"]}))


if __name__ == "__main__":
    main()
