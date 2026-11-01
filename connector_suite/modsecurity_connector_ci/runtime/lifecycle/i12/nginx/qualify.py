#!/usr/bin/env python3
"""Materialize explicit Root decisions against physical NGINX observations.

This tool supplies no semantic expectations. Every selected measurement must
match a decision's checks; independent oracle review remains a separate input.
An empty list in a required checks field explicitly requests no such checks.
Root remains responsible for choosing native result, phase, rule and event
checks that substantiate the independently reviewed oracle's meaning.
"""
from modsecurity_test_framework.connector_context import load_source

import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile


LEDGER = load_source(Path(__file__).with_name('ledger.py'))
REQUIRED_CHECKS = {
    "http_status", "client_exit", "client_signal", "framing_complete", "backend_count",
    "required_native_functions", "forbidden_native_functions", "required_events", "forbidden_events",
    "request_eos", "response_eos", "common_finish_count", "native_logging_count", "native_free_count",
    "body", "neighbor_success", "scoped_fixture_events", "allowed_absent_phases",
    "client_error", "socket_eof", "socket_reset", "request_body",
    "request_append_count", "request_append_bytes", "response_append_count", "response_append_bytes",
    "require_request_temp_file", "require_response_in_file", "required_content_type", "forbidden_event_fields",
    "required_request_content_type", "required_mime_debug_fragments", "required_sdk_mime_semantics",
    "oracle_event_fields", "oracle_event_fields_in_single_event", "native_return_checks",
}
TERMINALS = {2: "request_terminal_to_p2_once", 4: "response_terminal_to_p4_once"}
PHASE_FUNCTIONS = {2: "native_process_request_body", 4: "native_process_response_body"}
REQUIRED_ASSERTIONS = {
    "raw_artifact_digests_match", "config_loaded", "receipt_errors_empty", "selected_transaction_unique",
    "selected_allocation_unique", "native_invalid_rows_absent", "selected_native_nobody",
    "callbacks_owned_by_worker", "actual_loaded_image_binding", "client_body_digest_size_match",
    "scoped_fixture_traces_bind_selected_transaction", "request_terminal_to_p2_once",
    "response_terminal_to_p4_once", "native_cleanup_once", "native_logging_once", "common_finish_once",
    "host_cleanup_verified",
}


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def evidence_root():
    """Require an existing private run root configured by the operator."""
    value = os.environ.get("CODEX_RUN_ROOT")
    require(bool(value), "CODEX_RUN_ROOT must name a protected project directory")
    root = Path(value)
    require(root.is_absolute() and root.parent != root and root == root.resolve() and root.is_dir(),
            "Canonical existing CODEX_RUN_ROOT required")
    info = root.lstat()
    require(info.st_uid in (0, os.geteuid()) and not info.st_mode & 0o022,
            "CODEX_RUN_ROOT must be operator-owned and protected")
    return root


def publication_path(path):
    """Keep approved packets inside project runs, with no link traversal."""
    path = Path(path).absolute()
    root = evidence_root()
    require(".." not in path.parts and path.is_relative_to(root) and path != root,
            "Approved output must be inside the project run root")
    trusted_ancestry(path, allow_missing=True)
    require(not path.exists(), "Approved output directory must be fresh")
    return path


def trusted_ancestry(path, *, regular=False, allow_missing=False):
    """Trust only root/operator-owned paths with protected ancestry."""
    root = evidence_root()
    for component in reversed((path, *path.parents)):
        try:
            info = component.lstat()
        except FileNotFoundError:
            require(allow_missing, "Evidence file does not exist")
            continue
        require(info.st_uid in (0, os.geteuid()) and not stat.S_ISLNK(info.st_mode),
                "Path requires root/operator ownership without symlinks")
        transit = (component != path and not component.is_relative_to(root) and
                   info.st_uid == 0 and stat.S_ISDIR(info.st_mode) and info.st_mode & stat.S_ISVTX)
        require(not info.st_mode & 0o022 or transit, "Path has a group/world-writable component")
        require(component == path or stat.S_ISDIR(info.st_mode), "Path ancestor must be a directory")
        require(component != path or not regular or stat.S_ISREG(info.st_mode),
                "Evidence must be a regular file")


def evidence_path(path):
    path = Path(path).absolute()
    require(".." not in path.parts and path.is_relative_to(evidence_root()),
            "Evidence path must remain inside the project run root")
    trusted_ancestry(path, regular=True)
    return path


def validate_references(value):
    """Check nested hash references before unchanged shared readers use them."""
    if isinstance(value, dict):
        if "path" in value and "sha256" in value:
            evidence_path(value["path"])
        for child in value.values():
            validate_references(child)
    elif isinstance(value, list):
        for child in value:
            validate_references(child)


def subset(actual, expected):
    """Exact scalar/list equality, recursive dictionary subset for named fields."""
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(key in actual and subset(actual[key], value)
                                                for key, value in expected.items())
    return type(actual) is type(expected) and actual == expected


def expect(actual, expected, label):
    require(subset(actual, expected), f"Measurement differs from explicit check: {label}")


def check_events(actual, requested, label):
    require(isinstance(requested, list), label + " must be an explicit list")
    for rule in requested:
        require(isinstance(rule, dict) and isinstance(rule.get("event"), str), label + " needs an event name")
        require(set(rule) <= {"event", "fields", "count"}, "Unknown event expectation field")
        fields = rule.get("fields", {})
        require(isinstance(fields, dict) and "event" not in fields,
                "Event fields must be a dictionary without an event override")
        expected = {"event": rule["event"], **fields}
        matches = [event for event in actual if subset(event, expected)]
        if "count" in rule:
            expect(len(matches), rule["count"], label + " count " + rule["event"])
        else:
            require(bool(matches), label + " missing " + rule["event"])


def check_body(actual, check, label):
    require(isinstance(check, dict) and set(check) in ({"exact_hex"}, {"min_bytes"}),
            label + " needs exact_hex or min_bytes explicitly")
    if "exact_hex" in check:
        expect(actual.hex(), check["exact_hex"], label)
    else:
        require(type(check["min_bytes"]) is int and check["min_bytes"] >= 0 and
                len(actual) >= check["min_bytes"], label + " shorter than explicit minimum")


def verify_integrity_assertions(candidate, checks):
    allowed = checks["allowed_absent_phases"]
    require(isinstance(allowed, list) and len(allowed) == len(set(allowed)) and
            all(type(phase) is int and phase in TERMINALS for phase in allowed), "Invalid absent phase declaration")
    assertions = candidate["measured_assertions"]
    require(REQUIRED_ASSERTIONS <= set(assertions), "Missing base integrity assertions")
    for name, value in assertions.items():
        exceptions = [phase for phase in allowed if TERMINALS[phase] == name]
        require(value is True or (value is False and exceptions), "Base integrity assertion failed: " + name)


def verify_client_transport(obs, checks):
    expect(obs["client_headers"]["http_status"], checks["http_status"], "HTTP status")
    exit_info, signal_info = obs["client_exit"], obs["client_signal"]
    require(exit_info.get("direct_child_wait") is True and signal_info.get("direct_child_wait") is True and
            type(exit_info.get("pid")) is int and exit_info["pid"] > 0 and
            exit_info["pid"] == exit_info.get("observation_pid") == signal_info.get("pid") and
            signal_info.get("process_waited") is True, "Client PID/exit/signal lacks a direct wait binding")
    expect(exit_info["exit"], checks["client_exit"], "client exit")
    expect(signal_info["signal"], checks["client_signal"], "client signal")
    expect(obs["transport_framing"]["framing_complete"], checks["framing_complete"], "framing")
    for actual_key, expected_key in (("error", "client_error"), ("socket_eof", "socket_eof"),
                                     ("socket_reset", "socket_reset")):
        expect(obs["transport_framing"][actual_key], checks[expected_key], expected_key)
    expect(obs["backend_request_count"]["selected"], checks["backend_count"], "backend count")


def verify_native_returns(native, checks):
    return_checks = checks["native_return_checks"]
    require(isinstance(return_checks, list), "Native return checks must be an explicit list")
    for expected in return_checks:
        require(isinstance(expected, dict) and {"function", "result", "count"} <= set(expected) and
                set(expected) <= {"function", "result", "count", "input_size"},
                "Native return checks require function/result/count and optional input_size")
        require(isinstance(expected["function"], str) and bool(expected["function"]) and
                (expected["result"] is None or type(expected["result"]) is int) and
                type(expected["count"]) is int and expected["count"] >= 0 and
                ("input_size" not in expected or (type(expected["input_size"]) is int and expected["input_size"] >= 0)),
                "Invalid native return check values")
        match = {key: value for key, value in expected.items() if key != "count"}
        expect(sum(subset(row, match) for row in native), expected["count"],
               "native return subset count " + expected["function"])


def verify_native_functions(native, checks):
    allowed = checks["allowed_absent_phases"]
    functions = [call["function"] for call in native]
    required, forbidden = checks["required_native_functions"], checks["forbidden_native_functions"]
    require(isinstance(required, (list, dict)) and bool(required) and isinstance(forbidden, list),
            "Native function checks must be explicit and include reached functions")
    for name in required:
        require(name in functions, "Missing native function: " + name)
        if isinstance(required, dict):
            expect(functions.count(name), required[name], "native count " + name)
    require(not set(forbidden).intersection(functions), "Forbidden native function reached")
    for phase in allowed:
        require(PHASE_FUNCTIONS[phase] in forbidden, "Absent phase must explicitly forbid its native function")
        require(checks["request_eos" if phase == 2 else "response_eos"] is False,
                "Absent phase cannot claim a native EOS")


def verify_native_eos(obs, checks):
    for side, phase in (("request", 2), ("response", 4)):
        key = side + "_terminal_precedes_single_p" + str(phase)
        expect(obs["native_eos"][key], checks[side + "_eos"], side + " EOS")


def verify_oracle_event_fields(events, checks, oracle, outcome):
    event_fields = oracle.get("event_fields", [])
    require(isinstance(event_fields, list) and all(isinstance(field, str) and field for field in event_fields),
            "Effective oracle event_fields must be a field-name list")
    expect(checks["oracle_event_fields"], event_fields, "exact effective oracle event_fields")
    declared_fields_present = checks["oracle_event_fields_in_single_event"]
    require(type(declared_fields_present) is bool, "Oracle event-field presence must be an explicit boolean")
    if outcome == "PASS":
        require(declared_fields_present is True, "PASS requires all oracle fields in one physical event")
    # No event fields is a vacuous requirement; fields may never be assembled
    # from different events or supplemented by native/API/source projections.
    actual_fields_present = not event_fields or any(all(field in event for field in event_fields) for event in events)
    expect(actual_fields_present, declared_fields_present, "oracle fields in one physical event")


def selected_event_receipts(packet, candidate):
    observations = packet["observations"]
    request = LEDGER.ORACLES.reference(candidate["request_identity"]["physical_request_path"])
    receipts = []
    for proof in observations["client_exit"].get("evidence", []):
        path = Path(LEDGER.ORACLES.verify_reference(proof)["path"])
        receipt = LEDGER.client_receipt(path)
        if not isinstance(receipt, dict) or receipt.get("selected_id") != packet["run_scoped_case_id"]:
            continue
        for client in receipt.get("clients", []):
            if LEDGER.client_matches_request(client, path, request):
                receipts.append((receipt, client))
    require(bool(receipts), "Event provenance requires the selected physical client receipt")
    return receipts


def add_receipt_event_identity(expected, source):
    for field in ("connection_id", "request_id"):
        if field in source:
            value = source[field]
            require(isinstance(value, str) and bool(value), "Invalid receipt event identity: " + field)
            if field in expected:
                expect(value, expected[field], "conflicting receipt " + field)
            expected[field] = value


def expected_event_identity(packet, receipts):
    observations = packet["observations"]
    expected = {"run_id": packet["run_id"], "transport_case_id": packet["run_scoped_case_id"]}
    transaction = observations["native_transaction_id"]["value"]
    if isinstance(transaction, dict):
        transaction = transaction.get("value")
    require(isinstance(transaction, str) and bool(transaction), "Event provenance needs a native transaction")
    expected["transaction_id"] = transaction
    for receipt, client in receipts:
        run = receipt.get("run_id") or receipt.get("roles", {}).get("run_id")
        expect(run, expected["run_id"], "event receipt run_id")
        # Optional identities must come from the independent receipt, rather
        # than request_identity or a Root decision copying the event itself.
        for source in (receipt, client, client.get("observation", {})):
            add_receipt_event_identity(expected, source)
    return expected


def physical_event_rows(observations):
    physical = []
    seen_sinks = set()
    for proof in observations["native_events"].get("evidence", []):
        if proof.get("role") != "physical_event_sink":
            continue
        path = Path(LEDGER.ORACLES.verify_reference(proof)["path"])
        if path in seen_sinks:
            continue
        seen_sinks.add(path)
        for line in path.read_text().splitlines():
            if line.strip():
                physical.append(json.loads(line))
    return physical


def verify_event_provenance(packet, candidate, events):
    """Join exact physical rows to the selected receipt, never caller labels."""
    require(isinstance(events, list) and all(isinstance(event, dict) for event in events),
            "Physical events must be a list of objects")
    if not events:
        return
    receipts = selected_event_receipts(packet, candidate)
    observations = packet["observations"]
    expected = expected_event_identity(packet, receipts)
    physical = physical_event_rows(observations)
    for event in events:
        matches = [index for index, row in enumerate(physical)
                   if subset(row, event) and subset(event, row)]
        require(bool(matches), "Selected event is not an exact physical event-sink row")
        physical.pop(matches[0])
        for field, value in expected.items():
            expect(event.get(field), value, "physical event provenance " + field)


def verify_forbidden_events(events, checks):
    check_events(events, checks["required_events"], "required events")
    require(isinstance(checks["forbidden_events"], list), "Forbidden events must be explicit")
    for forbidden_event in checks["forbidden_events"]:
        require(isinstance(forbidden_event, (str, dict)), "Invalid forbidden event")
        match = {"event": forbidden_event} if isinstance(forbidden_event, str) else forbidden_event
        require(not any(subset(event, match) for event in events), "Forbidden event observed")
    require(isinstance(checks["forbidden_event_fields"], list), "Forbidden event fields must be explicit")
    for field in checks["forbidden_event_fields"]:
        require(isinstance(field, str) and all(field not in event for event in events),
                "Forbidden event field observed: " + str(field))


def verify_cleanup_and_bodies(obs, candidate, checks):
    expect(len(obs["finish_calls"]["common_finish"]), checks["common_finish_count"], "Common finish count")
    expect(len(obs["finish_calls"]["native_logging"]), checks["native_logging_count"], "native logging count")
    expect(obs["native_free_calls"]["count"], checks["native_free_count"], "native free count")
    actual_body = obs["client_bytes"]
    check_body(bytes.fromhex(actual_body["body_hex"]), checks["body"], "Client body")
    wire = evidence_path(candidate["request_identity"]["physical_request_path"]).read_bytes()
    request_headers, request_body = wire.split(b"\r\n\r\n", 1)
    check_body(request_body, checks["request_body"], "Request body")
    return request_headers


def verify_request_content_type(request_headers, checks):
    request_types = []
    for line in request_headers.split(b"\r\n")[1:]:
        name, separator, value = line.partition(b":")
        if separator and name.lower() == b"content-type":
            request_types.append(value.strip(b" \t").decode("latin1"))
    require(len(request_types) <= 1, "Selected request has duplicate Content-Type headers")
    expected_type = checks["required_request_content_type"]
    require(expected_type is None or isinstance(expected_type, str), "Invalid request Content-Type expectation")
    expect(request_types, [] if expected_type is None else [expected_type], "actual request Content-Type")


def verify_mime_debug(obs, checks):
    fragments = checks["required_mime_debug_fragments"]
    require(isinstance(fragments, list) and all(isinstance(fragment, str) and fragment for fragment in fragments),
            "MIME debug fragments must be an explicit list of nonempty strings")
    debug_lines = obs["mime_gate"]["selected_debug"]
    require(isinstance(debug_lines, list) and all(isinstance(line, str) for line in debug_lines),
            "Missing physical selected MIME debug lines")
    for fragment in fragments:
        require(any(fragment in line for line in debug_lines), "Missing requested MIME debug fragment: " + fragment)
    require(isinstance(checks["required_sdk_mime_semantics"], str) and bool(checks["required_sdk_mime_semantics"]),
            "SDK MIME semantics must be an explicit nonempty string")
    expect(obs["mime_gate"]["sdk_fixture_semantics"], checks["required_sdk_mime_semantics"], "SDK MIME semantics")


def verify_body_buffers(obs, checks):
    chunks = obs["native_body_chunks"]
    for side in ("request", "response"):
        expect(len(chunks[side]), checks[side + "_append_count"], side + " append count")
        expect(sum(row["input_size"] for row in chunks[side]), checks[side + "_append_bytes"], side + " append bytes")
    for key, field, operation in (("require_request_temp_file", "temp_file_present", "request_body_path"),
                                  ("require_response_in_file", "in_file", "response_buffer")):
        require(type(checks[key]) is bool, key + " must be a boolean")
        actual = any(row.get("operation") == operation and row.get(field) == 1
                     for row in chunks["host_buffer_state"])
        expect(actual, checks[key], key)


def verify_response_content_type(obs, checks):
    content_type = checks["required_content_type"]
    require(content_type is None or isinstance(content_type, str), "Invalid content type expectation")
    if content_type is not None:
        header_lines = obs["client_headers"]["raw_latin1"].split("\r\n")
        types = [line.split(":", 1)[1].strip() for line in header_lines
                 if line.split(":", 1)[0].lower() == "content-type"]
        expect(types, [content_type], "actual response Content-Type")


def verify_neighbor(obs, checks):
    neighbors = obs["neighbor_health"]["actual_followup_clients"]
    require(checks["neighbor_success"] is True and len(neighbors) == 1, "One successful neighbor is required")
    neighbor = neighbors[0]
    require(neighbor.get("exit_code") == 0 and neighbor.get("signal") is None and
            neighbor.get("direct_child_wait") is True and type(neighbor.get("pid")) is int and neighbor["pid"] > 0 and
            neighbor["pid"] == neighbor.get("observation", {}).get("pid") and
            neighbor["observation"].get("status") == 200 and neighbor["observation"].get("framing_complete") is True,
            "Neighbor health/direct wait failed")


def verify_scoped_fixtures(obs, checks):
    fixture_checks = checks["scoped_fixture_events"]
    actual_fixture = obs["native_api_returns"].get("scoped_fixture_events", {})
    require(isinstance(fixture_checks, dict) and set(fixture_checks) == set(actual_fixture),
            "Every scoped fixture label must be explicitly checked")
    for label, expected_rows in fixture_checks.items():
        require(isinstance(expected_rows, list) and bool(expected_rows) and
                len(expected_rows) == len(actual_fixture[label]), "Scoped fixture count differs")
        for actual, expected in zip(actual_fixture[label], expected_rows):
            require(isinstance(expected, dict) and bool(expected), "Scoped fixture fields cannot be empty")
            expect(actual, expected, "scoped fixture " + label)


def verify_checks(packet, candidate, checks, oracle, outcome):
    require(isinstance(checks, dict) and set(checks) == REQUIRED_CHECKS,
            "Every semantic checks field must be explicit; unknown fields are rejected")
    obs = {name: measurement["value"] for name, measurement in packet["observations"].items()}
    verify_integrity_assertions(candidate, checks)
    verify_client_transport(obs, checks)
    native = obs["native_api_returns"]["measured_calls"]
    verify_native_returns(native, checks)
    verify_native_functions(native, checks)
    verify_native_eos(obs, checks)
    events = obs["native_events"]
    verify_event_provenance(packet, candidate, events)
    verify_oracle_event_fields(events, checks, oracle, outcome)
    verify_forbidden_events(events, checks)
    request_headers = verify_cleanup_and_bodies(obs, candidate, checks)
    verify_request_content_type(request_headers, checks)
    verify_mime_debug(obs, checks)
    verify_body_buffers(obs, checks)
    verify_response_content_type(obs, checks)
    verify_neighbor(obs, checks)
    verify_scoped_fixtures(obs, checks)


def candidate_index(candidates):
    by_id = {}
    for candidate in candidates["cases"]:
        identity = candidate.get("run_scoped_case_id")
        if identity:
            require(identity not in by_id, "Duplicate candidate ID")
            by_id[identity] = candidate
    return by_id


def materialize(baseline, candidates, decisions, output):
    """Validate all decisions before creating any approved packet."""
    output = publication_path(output)
    require(type(candidates.get("controller_exit")) is int and candidates["controller_exit"] == 0 and
            type(candidates.get("driver_exit")) is int and candidates["driver_exit"] == 0,
            "Controller and driver must exit zero")
    require(isinstance(decisions, list) and bool(decisions), "Explicit decisions list required")
    originals = {row["run_scoped_case_id"]: row for row in LEDGER.selected_rows(baseline)}
    by_id = candidate_index(candidates)
    prepared, ids, requests, transactions = [], set(), set(), set()
    for decision in decisions:
        require(isinstance(decision, dict) and set(decision) <= {
            "run_scoped_case_id", "outcome", "checks", "effective_oracle"}, "Invalid decision fields")
        identity = decision.get("run_scoped_case_id")
        require(identity in originals and identity not in ids, "Unknown, diagnostic or duplicate original ID")
        ids.add(identity)
        require(decision.get("outcome") in ("PASS", "FAIL"), "Explicit PASS/FAIL required")
        candidate = by_id.get(identity)
        require(candidate and candidate.get("packet") and candidate.get("unknown_fields") == [] and candidate.get("gaps") == [],
                "Candidate needs a physical packet without unknown fields or gaps")
        validate_references(candidate["packet"])
        reference = LEDGER.ORACLES.verify_reference(candidate["packet"])
        packet = json.loads(evidence_path(reference["path"]).read_text())
        validate_references(packet)
        validate_references(decision.get("effective_oracle"))
        require(packet.get("run_scoped_case_id") == identity and packet.get("leg_id") == "nginx-native",
                "Candidate packet identity mismatch")
        _, oracle = LEDGER.effective_review(originals[identity], decision.get("effective_oracle"))
        require(oracle is not None, "Unresolved or fake effective oracle")
        verify_checks(packet, candidate, decision.get("checks"), oracle, decision["outcome"])
        # A null oracle status deliberately leaves transport status unspecified;
        # the Root decision must still declare and check the actual HTTP status.
        if decision["outcome"] == "PASS" and oracle.get("visible_status") is not None:
            expect(decision["checks"]["http_status"], oracle.get("visible_status"), "PASS oracle visible status")
        packet.update(reviewed_by="root", oracle_evaluated=True,
                      oracle_sha256=LEDGER.ORACLES.canonical_digest(oracle), outcome=decision["outcome"],
                      full_lifecycle_qualified=True)
        request = candidate["request_identity"]
        physical = str(evidence_path(request["physical_request_path"]))
        transaction = (packet["run_id"], request["transaction_id"])
        require(physical not in requests and transaction not in transactions, "Duplicate physical request or native transaction")
        requests.add(physical)
        transactions.add(transaction)
        prepared.append((identity, packet, request, decision))
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Recheck after parent creation before using it as a temporary directory.
    output = publication_path(output)
    # A private sibling keeps incomplete Root packets out of the published
    # output and permits one same-filesystem rename after all shared guards.
    with tempfile.TemporaryDirectory(prefix=".nginx-qualification-", dir=output.parent) as scratch:
        staging = Path(scratch)
        records = []
        for number, (identity, packet, request, decision) in enumerate(prepared):
            path = staging / f"{number:03d}-reviewed.json"
            path.write_text(json.dumps(packet, indent=2) + "\n")
            reference = LEDGER.ORACLES.reference(path)
            _, oracle = LEDGER.effective_review(originals[identity], decision.get("effective_oracle"))
            reviewed = LEDGER.SHARED.reviewed_packet(reference, originals[identity], oracle)
            LEDGER.physical_identity(request, packet, reviewed)
            record = {"packet": reference, "request_identity": copy.deepcopy(request)}
            if "effective_oracle" in decision:
                record["effective_oracle"] = copy.deepcopy(decision["effective_oracle"])
            records.append(record)
        # Includes protection against historical request/transaction reuse.
        LEDGER.build_ledger(baseline, records)
        published = copy.deepcopy(records)
        for record in published:
            record["packet"]["path"] = str(output / Path(record["packet"]["path"]).name)
        output = publication_path(output)
        staging.rename(output)
    return published


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ("baseline", "candidates", "decisions", "output", "packets"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    args.packets = publication_path(args.packets)
    args.baseline = evidence_path(args.baseline)
    args.candidates = evidence_path(args.candidates)
    args.decisions = evidence_path(args.decisions)
    require(LEDGER.ORACLES.reference(args.baseline)["sha256"] == LEDGER.BASELINE_SHA256,
            "Immutable PR410 baseline SHA256 changed")
    records = materialize(json.loads(args.baseline.read_text()), json.loads(args.candidates.read_text()),
                          json.loads(args.decisions.read_text()), args.output)
    args.packets = publication_path(args.packets)
    with args.packets.open("x") as stream:
        json.dump(records, stream, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    main()
