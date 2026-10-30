#!/usr/bin/env python3
"""Extract partial SPOP/companion facts into the existing I12 observation API.

No host traffic, Root approval, oracle evaluation or lifecycle verdict is produced.
Namespace image names resolve only through the explicitly supplied sealed spec.
"""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import argparse
import hashlib
import importlib.util
import json
import re
from pathlib import Path
import struct


HERE = Path(__file__).parent
ROOT = connector_root()
COMPANION = "haproxy-spop-htx-response-companion"
REQUEST = "haproxy-spop-request"
ROLE_API = 'native_api'
ROLE_HOST = 'host_callback'
ROLE_CLIENT = 'client_process'
ROLE_SINK = 'physical_event_sink'
ROLE_SOURCE = 'source_manifest'
ROLE_CONTRACT = 'source_contract'
ROLE_CONFIG = 'effective_configuration'
ROLE_CLEANUP = 'cleanup_observer'
ROLE_ISOLATION = 'isolation_receipt'
ROLE_IMAGE = 'loaded_image'
ROLE_DEBUG = 'native_debug'
ROLE_BACKEND = 'backend_process'
AGENT_STDERR = 'agent.stderr'
HOST_STDERR = 'host.stderr'
DECISION_FILE = 'decision.jsonl'
CLIENT_FILE = 'client.jsonl'
BACKEND_FILE = 'backend.jsonl'
NATIVE_AUDIT = 'native-audit.log'
REQUEST_BODY_CALL = 'native_process_request_body'
REQUEST_FINISH_CALL = 'common_finish_request_authorization'
NEW_NATIVE_CALL = 'native_new_with_id'
ALLOCATION_CALL = 'host_allocation'
AGENT_CONFIG = 'agent.conf'
NATIVE_DEBUG = 'native-debug.log'
NEIGHBOR_PATH = '/i12-neighbor'
BACKEND_HEADER_LIMIT = 65536
BACKEND_BODY_LIMIT = 8 * 1024 * 1024
HTTP_TOKEN = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
BACKEND_KINDS = frozenset(("backend_request", "backend_chunk", "backend_body_finished", "backend_disconnect", "backend_paused_before_eos", "backend_resumed"))


def module_at(_name, path):
    module = load_source(path)
    return module


CAPTURE = module_at("route_capture", HERE / "i12_current_capture.py")
NATIVE = module_at("route_native", HERE / "i12_native_observe.py")
WIRE = module_at("route_wire", HERE / "i12_spop_wire.py")
CASES = module_at("route_companion", HERE / "i12_companion_cases.py")
LEDGER = module_at("route_measurement_schema", source_path('ci/evidence/reports/generate-pr382-i12-lifecycle-ledger.py', root=ROOT))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_bytes(path):
    with CAPTURE.storage_parent(path) as (parent, name):
        return CAPTURE.regular_bytes(parent, name)


def reference(path, role):
    data = read_bytes(path)
    return {"path": str(path), "sha256": digest(data), "bytes": len(data), "role": role}


def read_json(path):
    return json.loads(read_bytes(path))


def require_hash(path, expected):
    if digest(read_bytes(path)) != expected:
        raise ValueError("sealed input hash differs: " + str(path))


class Bindings:
    """Resolve namespace files beneath the sealed external source roots."""
    def __init__(self, spec):
        self.rows = []
        for item in spec["bindings"]:
            ledger_path = Path(item["ledger"])
            require_hash(ledger_path, item["ledger_sha256"])
            source, target = Path(item["source"]), Path(item["target"])
            CAPTURE.storage_parts(source)
            if not target.is_absolute() or ".." in target.parts:
                raise ValueError("invalid namespace binding target")
            self.rows.append((source, target, read_json(ledger_path)["files"], ledger_path))

    def resolve(self, namespace):
        path = Path(namespace)
        if not path.is_absolute() or ".." in path.parts:
            raise ValueError("invalid namespace image path")
        matches = []
        for source, target, files, ledger in self.rows:
            if path.is_relative_to(target):
                relative = str(path.relative_to(target))
                if relative not in files:
                    raise ValueError("namespace image absent from sealed ledger")
                actual = source / relative
                require_hash(actual, files[relative])
                matches.append((actual, ledger))
        if len(matches) != 1:
            raise ValueError("namespace path has missing or ambiguous sealed binding")
        return matches[0]


def option(argv, name):
    values = [argv[index + 1] for index, value in enumerate(argv[:-1]) if value == name]
    if len(values) > 1:
        raise ValueError("ambiguous source option " + name)
    return values[0] if values else None


def executed_fixture(spec, bindings, fixture_path, attempt, data):
    namespace = option(spec["argv"], "--fixture")
    if namespace is not None:
        actual, _ = bindings.resolve(namespace)
        if actual != fixture_path:
            raise ValueError("explicit fixture differs from executed source fixture")
        return None
    queue_name = option(spec["argv"], "--queue")
    if queue_name is None:
        actual, _ = bindings.resolve("/mnt/fixtures/selected.json")
        if actual != fixture_path or data != attempt / "data":
            raise ValueError("default SPOP fixture/data root differs from executed source")
        return None
    queue_path, _ = bindings.resolve(queue_name)
    require_hash(queue_path, option(spec["argv"], "--sha256"))
    queue = read_json(queue_path)
    matches = []
    for member in queue["cases"]:
        namespace = "/mnt/fixtures/" + member["member"] + "/" + member["fixture"]["path"]
        actual, _ = bindings.resolve(namespace)
        if actual == fixture_path:
            matches.append(member)
    if len(matches) != 1:
        raise ValueError("explicit fixture has no unique sealed batch member")
    member = matches[0]
    expected = attempt / "data" / Path(member["data_root"]).relative_to("/task")
    if data != expected:
        raise ValueError("case data root differs from sealed batch member")
    result_path = attempt / "data/batch-result.json"
    result = read_json(result_path)
    if result["queue_sha256"] != digest(read_bytes(queue_path)):
        raise ValueError("actual batch result differs from sealed queue")
    actual = [row for row in result["members"] if row["original_id"] == member["original_id"] and row["argv"] == member["argv"] and row["cwd"] == member["data_root"]]
    if len(actual) != 1:
        raise ValueError("actual batch execution member missing or ambiguous")
    return {"sealed_member": member, "actual_execution": actual[0],
            "queue_reference": reference(queue_path, ROLE_SOURCE),
            "result_reference": reference(result_path, ROLE_CLEANUP)}


def verify_completion_images(provenance, build_path, build, images):
    if provenance.get("build_completion_seal") != str(build_path):
        raise ValueError("source provenance names a different build completion seal")
    require_hash(build_path, provenance.get("build_completion_seal_sha256"))
    revision = provenance.get("product_and_capture_revision")
    if build.get("required_head") != revision:
        raise ValueError("build completion seal differs from source provenance revision")
    binaries = build.get("binaries")
    if not isinstance(binaries, dict) or set(binaries) != {"direct", "agent", "companion"}:
        raise ValueError("build completion seal has an unexpected binary inventory")
    roles = [image.get("role") for image in images if isinstance(image, dict)]
    if len(images) != 4 or set(roles) != {"direct", "agent", "companion", "native_engine"} or len(set(roles)) != len(roles):
        raise ValueError("current source provenance has an unexpected image inventory")
    for image in images:
        require_hash(Path(image["source"]), image["sha256"])
        require_hash(Path(image["sealed_copy"]), image["sha256"])
        if image["role"] != "native_engine" and binaries[image["role"]].get("sha256") != image["sha256"]:
            raise ValueError("sealed image differs from build completion seal")


def verified_provenance_images(provenance, build_path):
    build = read_json(build_path)
    images = provenance.get("images")
    if not isinstance(images, list):
        raise ValueError("source provenance images must be an array")
    if provenance.get("schema") == "haproxy-i12-host-input-provenance-v1":
        verify_completion_images(provenance, build_path, build, images)
        return build, images
    if provenance.get("build_receipt") != str(build_path):
        raise ValueError("source provenance names a different build receipt")
    require_hash(build_path, provenance.get("build_receipt_sha256"))
    for image in images:
        require_hash(Path(image["source"]), image["sha256"])
        require_hash(Path(image["sealed_copy"]), image["sha256"])
        expected = build["sdk"]["image_sha256"] if image["role"] == "native_engine" else build[image["role"]]["sha256"]
        if expected != image["sha256"]:
            raise ValueError("sealed image differs from source build receipt")
    return build, images


def bind_inputs(attempt, data, spec_path, build_path, fixture_path):
    data.relative_to(attempt / "data")
    controller_path = attempt / "controller-result.json"
    controller = read_json(controller_path)
    require_hash(spec_path, controller["spec_sha256"])
    for key in ("executed_input_hashes_before", "executed_input_hashes_after"):
        if controller[key].get(str(spec_path)) != controller["spec_sha256"]:
            raise ValueError("controller does not bind explicit source spec")
    admission_path = attempt / "admission.original.json"
    require_hash(admission_path, controller["admission_sha256"])
    admission = read_json(admission_path)
    spec = read_json(spec_path)
    if admission["argv"] != spec["argv"]:
        raise ValueError("admitted argv differs from explicit source spec")
    bindings = Bindings(spec)
    provenance_path, _ = bindings.resolve("/mnt/artifacts/source-provenance.json")
    provenance = read_json(provenance_path)
    build, images = verified_provenance_images(provenance, build_path)
    batch = executed_fixture(spec, bindings, fixture_path, attempt, data)
    return {"controller": controller, "admission": admission, "spec": spec, "build": build, "provenance": provenance,
            "images": images, "bindings": bindings, "batch": batch, "fixture": read_json(fixture_path),
            "references": [reference(spec_path, ROLE_SOURCE), reference(build_path, ROLE_SOURCE),
                           reference(provenance_path, ROLE_SOURCE), reference(fixture_path, ROLE_CONTRACT)],
            "controller_reference": reference(controller_path, ROLE_ISOLATION)}


class Readings:
    """Retain optional-file failures and raw references without inventing rows."""
    def __init__(self, root):
        self.root, self.problems, self.artifacts = root, {}, {}

    def get(self, name, role, kind="json"):
        path = self.root / name
        try:
            data = read_bytes(path)
            self.artifacts[name] = {"path": str(path), "sha256": digest(data), "bytes": len(data), "role": role}
            if kind == "bytes":
                return data
            if kind == "text":
                return data.decode()
            if kind == "jsonl":
                rows = [json.loads(line) for line in data.splitlines() if line.strip()]
                if not all(isinstance(row, dict) for row in rows):
                    raise ValueError("JSONL records must be objects")
                return rows
            value = json.loads(data)
            expected = list if kind == "array" else dict
            if not isinstance(value, expected):
                raise ValueError("unexpected stored JSON container")
            return value
        except (OSError, ValueError) as error:
            self.problems[name] = type(error).__name__ + ": " + str(error)
            return None

    def ref(self, name, role):
        return {**self.artifacts[name], "role": role}


def callback_rows(text):
    rows, errors = [], []
    for line in (text or "").splitlines():
        if line.startswith("HAPROXY_"):
            try:
                value = json.loads(line.split(" ", 1)[1])
                if not isinstance(value, dict):
                    raise ValueError("host callback must be an object")
                rows.append(value)
            except (ValueError, IndexError) as error:
                errors.append(str(error))
    return rows, errors


def decode_spop_record(record):
    raw = bytes.fromhex(record["hex"])
    if digest(raw) != record["sha256"]:
        raise ValueError("frame digest differs")
    return {**record, "decoded": WIRE.decode_frame(raw)}


def decode_spop_stream(raw, name):
    pending, frames = bytearray(raw), []
    while pending:
        if len(pending) < 4:
            raise ValueError("trailing SPOP length bytes")
        length = struct.unpack("!I", pending[:4])[0] + 4
        if length > len(pending):
            raise ValueError("truncated SPOP frame")
        frame = bytes(pending[:length])
        del pending[:length]
        frames.append({"file": name, "forwarded": name.endswith(".forwarded.bin"),
                       "sha256": digest(frame), "decoded": WIRE.decode_frame(frame)})
    return frames


def spop_frames(readings, companion):
    frames, errors = [], []
    if not companion:
        records = readings.get("frames.jsonl", ROLE_HOST, "jsonl")
        for record in records or []:
            try:
                frames.append(decode_spop_record(record))
            except (KeyError, ValueError) as error:
                errors.append(str(error))
        return frames, errors
    for path in sorted(readings.root.glob("spop-*.bin")):
        raw = readings.get(path.name, ROLE_HOST, "bytes")
        try:
            frames.extend(decode_spop_stream(raw, path.name))
        except (TypeError, ValueError) as error:
            errors.append(path.name + ": " + str(error))
    return frames, errors


def mrc_frames(readings):
    streams, errors = [], []
    for path in sorted(readings.root.glob("mrc1-*.bin")):
        raw = readings.get(path.name, ROLE_HOST, "bytes")
        try:
            pending = bytearray(raw)
            frames = CASES.complete_mrc_frames(pending)
            if pending:
                raise ValueError("incomplete MRC1 frame bytes")
            decoded = []
            for frame in frames:
                item = {"opcode": frame[5], "payload_hex": frame[12:].hex(), "sha256": digest(frame)}
                if frame[5] == 1:
                    item["capability_sha256"] = digest(frame[12:])
                if frame[5] == 8 and len(frame) == 16:
                    item["actual_action"], item["connection_aborted"] = frame[12], frame[13] & 1
                    item["visible_status"] = struct.unpack("!H", frame[14:16])[0]
                decoded.append(item)
            streams.append({"file": path.name, "frames": decoded})
        except (TypeError, ValueError) as error:
            errors.append(path.name + ": " + str(error))
    return streams, errors


def notify_messages(frames):
    rows = []
    for frame in frames:
        if frame.get("forwarded") is False or frame["decoded"]["kind"] != 3:
            continue
        for message in frame["decoded"].get("messages", []):
            arguments = message["arguments"]
            names = [item["name"] for item in arguments]
            if len(names) == len(set(names)):
                rows.append({"frame": frame, "arguments": {item["name"]: item["value"] for item in arguments}})
    return rows


def notify_selection(messages, path, client, request_body):
    if "request_send_started_wall_ns" in client and client["request_send_started_wall_ns"] is None:
        return None, "actual child capture records no request send start"
    matches = [row for row in messages if row["arguments"].get("path") == path]
    endpoint = client.get("connection_local")
    if endpoint is not None:
        if not isinstance(endpoint, list) or len(endpoint) < 2:
            return None, "actual client endpoint representation is invalid"
        matches = [row for row in matches if row["arguments"].get("client_ip") == endpoint[0] and row["arguments"].get("client_port") == endpoint[1]]
    if len(matches) != 1:
        return None, "actual request path has missing or ambiguous NOTIFY mapping"
    if request_body is not None and matches[0]["arguments"].get("body") != request_body.hex():
        return None, "actual client payload differs from physical NOTIFY sample bytes"
    identity = matches[0]["arguments"].get("request_id")
    if not isinstance(identity, str) or not identity:
        return None, "NOTIFY has no actual nonempty request UUID"
    return matches[0], None


def allocation_scope(native, identity):
    candidates = [row for row in native if row.get("function") == NEW_NATIVE_CALL and row.get("edge") == "return" and row.get("transaction_id") == identity]
    if len(candidates) != 1:
        return None, "request UUID has missing or ambiguous verified allocation scope"
    owner = candidates[0]
    scope, pid = owner.get("allocation_scope_call"), owner.get("pid")
    if type(scope) is not int or type(pid) is not int:
        return None, "allocation lacks actual process/scope identity"
    selected = [row for row in native if row.get("pid") == pid and row.get("allocation_scope_call") == scope]
    allocations = [row for row in selected if row.get("function") == ALLOCATION_CALL and row.get("edge") == "return" and row.get("result") == 1 and row.get("allocation_join_verified")]
    if len(allocations) != 1:
        return None, "allocation scope has no unique verified host allocation return"
    native_ids = {row.get("transaction_id") for row in selected if row.get("function") == NEW_NATIVE_CALL and row.get("edge") == "return"}
    if native_ids != {identity}:
        return None, "actual allocation scope carries conflicting native identities"
    canonical = {row.get("canonical_transaction_id") for row in selected if row.get("canonical_transaction_id")}
    if len(canonical) != 1:
        return None, "allocation lacks unique actual Common identity"
    return {"owner": owner, "rows": selected, "pid": pid, "scope": scope, "common_id": canonical.pop()}, None


def transaction_join(native, messages, path, client, request_body=None):
    notify, reason = notify_selection(messages, path, client, request_body)
    if notify is None:
        return None, reason
    identity = notify["arguments"]["request_id"]
    allocated, reason = allocation_scope(native, identity)
    if allocated is None:
        return None, reason
    end = client.get("completed_wall_ns", client.get("finished_ns", client.get("time_ns")))
    begin = client.get("started_wall_ns", client.get("started_ns"))
    allocation_time = allocated["owner"].get("wall_ns")
    if any(value is not None and type(value) is not int for value in (begin, end, allocation_time)):
        return None, "client/allocation timestamp representation is invalid"
    if allocation_time is None or (end is not None and allocation_time > end) or (begin is not None and allocation_time < begin):
        return None, "allocation timestamp conflicts with selected client interval"
    return {"native_id": identity, "common_id": allocated["common_id"], "pid": allocated["pid"], "scope": allocated["scope"],
            "rows": allocated["rows"], "notify": notify, "client_endpoint_verified": client.get("connection_local") is not None, "client_window": {"start_ns": begin, "end_ns": end},
            "complete_time_window": begin is not None and end is not None,
            "time_window_reason": None if begin is not None and end is not None else "client start and/or completion timestamp was not physically captured"}, None


def calls(rows, function):
    return [row for row in rows if row.get("function") == function and row.get("edge") == "return"]


def transitions(rows):
    functions = {"common_complete_phase", "common_finish", REQUEST_FINISH_CALL, "common_cleanup"}
    result = []
    for enter in rows:
        if enter.get("function") not in functions or enter.get("edge") != "enter":
            continue
        returned = [row for row in rows if row.get("pid") == enter.get("pid") and row.get("call") == enter.get("call") and row.get("edge") == "return"]
        if len(returned) != 1:
            result.append({"function": enter["function"], "before": enter.get("contract_state"), "after": None, "reason": "call return is missing or ambiguous", "return_count": len(returned)})
            continue
        if enter["function"] != REQUEST_FINISH_CALL:
            result.extend(NATIVE.phase_transitions([enter, *returned]))
            continue
        result.append({"function": enter["function"], "before": enter.get("contract_state"),
                       "after": returned[0].get("contract_state") if len(returned) == 1 else None,
                       "return_count": len(returned)})
    return result


def unknown(reason, partial=None):
    value = {"applicable": True, "value": None, "reason": reason}
    if partial is not None:
        value["partial_facts"] = partial
    return value


def measured(value, evidence):
    return {"applicable": True, "value": value, "evidence": evidence}


def select_client(rows, index):
    if rows is None:
        return None
    matches = [row for row in rows if row.get("index") == index]
    if len(matches) == 1:
        return matches[0]
    if len(rows) == 1 and "index" not in rows[0] and index == 0:
        return rows[0]
    return None


def client_files(companion, indexed, index):
    if companion:
        return "client-" + str(index) + ".response", "client-" + str(index) + ".request"
    if indexed:
        return "response-" + str(index) + ".raw", "request-" + str(index) + ".raw"
    return "response.raw", "request.raw"


def verified_client_bytes(readings, name, value, client, field):
    if client is not None and value is not None and client.get(field) not in (None, digest(value)):
        label = "request" if field == "request_sha256" else "response"
        readings.problems[name] = "captured " + label + " differs from independent client digest"
        return None
    return value


def receipt_commands(readings, commands, name, companion):
    if companion and commands:
        commands = commands.get("commands")
        if not isinstance(commands, list):
            readings.problems[name] = "host receipt has no actual command array"
            return None
    return commands


def load_route(readings, companion, index):
    prefix = "agent-native.jsonl" if companion else "agent-native-api.jsonl"
    native = readings.get(prefix, ROLE_API, "jsonl")
    host_name = "host-native.jsonl" if companion else "host-native-api.jsonl"
    host_native = readings.get(host_name, ROLE_API, "jsonl")
    client_name = "client-" + str(index) + ".json" if companion else CLIENT_FILE
    client_value = readings.get(client_name, ROLE_CLIENT, "json" if companion else "jsonl")
    client = client_value if companion else select_client(client_value, index)
    indexed = not companion and client is not None and "index" in client
    wire_name, request_name = client_files(companion, indexed, index)
    wire = readings.get(wire_name, ROLE_CLIENT, "bytes")
    request = readings.get(request_name, ROLE_CLIENT, "bytes")
    request = verified_client_bytes(readings, request_name, request, client, "request_sha256")
    wire = verified_client_bytes(readings, wire_name, wire, client, "response_sha256")
    backend_name = "observations.json" if companion else BACKEND_FILE
    backend = readings.get(backend_name, ROLE_BACKEND, "array" if companion else "jsonl")
    commands_name = "receipt.json" if companion else "commands.jsonl"
    commands = readings.get(commands_name, ROLE_CLEANUP, "json" if companion else "jsonl")
    capture_receipt = commands if companion else None
    commands = receipt_commands(readings, commands, commands_name, companion)
    agent_text = readings.get(AGENT_STDERR, ROLE_HOST, "text")
    host_text = readings.get(HOST_STDERR, ROLE_HOST, "text")
    agent_callbacks, agent_errors = callback_rows(agent_text)
    host_callbacks, host_errors = callback_rows(host_text)
    frames, frame_errors = spop_frames(readings, companion)
    streams, mrc_errors = mrc_frames(readings) if companion else ([], [])
    sink = readings.get(DECISION_FILE, ROLE_SINK, "jsonl")
    audit = readings.get(NATIVE_AUDIT, ROLE_SINK, "text")
    return {"native_name": prefix, "native": native, "host_native": host_native, "client_name": client_name,
            "client": client, "all_clients": client_value, "wire_name": wire_name, "wire": wire, "request_name": request_name,
            "request": request, "backend_name": backend_name, "backend": backend, "commands_name": commands_name,
            "commands": commands, "capture_receipt": capture_receipt, "agent_callbacks": agent_callbacks, "host_callbacks": host_callbacks,
            "frames": frames, "mrc_streams": streams, "physical_sink": sink, "native_audit": audit,
            "decode_errors": agent_errors + host_errors + frame_errors + mrc_errors}


def native_measurements(observations, route, readings, joined):
    rows = joined["rows"]
    api = [readings.ref(route["native_name"], ROLE_API)]
    observations["native_api_returns"] = measured(rows, api)
    observations["native_transaction_id"] = measured(joined["native_id"], api)
    observations["common_transaction_id"] = measured(joined["common_id"], api)
    association = {key: value for key, value in joined.items() if key != "rows"}
    observations["observed_handle_association"] = measured(association, api) if joined["complete_time_window"] else unknown(joined["time_window_reason"], association)
    observations["native_body_chunks"] = measured({"request": calls(rows, "native_append_request_body"), "response": calls(rows, "native_append_response_body"), "no_EOS_argument": True}, api)
    observations["native_intervention_or_first_cause"] = measured(calls(rows, "native_intervention"), api)
    observations["finish_calls"] = measured({"native_logging": calls(rows, "native_process_logging"), "common_finish": calls(rows, "common_finish"), REQUEST_FINISH_CALL: calls(rows, REQUEST_FINISH_CALL)}, api)
    states = transitions(rows)
    observations["finish_transitions"] = unknown("Common transition state or paired return missing/ambiguous", states) if any(row["after"] is None for row in states) else measured(states, api)
    observations["native_free_calls"] = measured({"actual_native_cleanup_returns": calls(rows, "native_cleanup"), "common_cleanup_is_not_a_second_native_free": True}, api)
    debug = readings.get(NATIVE_DEBUG, ROLE_DEBUG, "text")
    if debug is not None:
        phases = ("native_process_request_headers", REQUEST_BODY_CALL, "native_process_response_headers", "native_process_response_body", "native_process_logging")
        observations["native_phases"] = measured({phase: calls(rows, phase) for phase in phases}, api + [readings.ref(NATIVE_DEBUG, ROLE_DEBUG)])
    selections = [row for row in rows if row.get("native_mime_selection") is not None]
    if selections:
        observations["mime_gate"] = measured(selections, api)


def configured_sink(readings, attempt):
    configuration = readings.get(AGENT_CONFIG, ROLE_CONFIG, "text")
    namespace = Path("/task") / readings.root.relative_to(attempt / "data") / DECISION_FILE
    options = []
    for line in (configuration or "").splitlines():
        key, separator, value = line.partition("=")
        if separator and key.strip() == "decision-log":
            options.append(value.strip())
    valid = options == [str(namespace)]
    return {"actual_decision_log_options": options, "effective_agent_config_sha256": readings.artifacts.get(AGENT_CONFIG, {}).get("sha256"), "expected_case_namespace_path": str(namespace),
            "physical_path": str(readings.root / DECISION_FILE), "configuration_matches": valid,
            "reason": None if valid else "effective decision-log option is missing, ambiguous or outside this case data root"}


def sink_measurements(observations, route, readings, joined):
    sink, audit = route["physical_sink"], route["native_audit"]
    if sink is None:
        return
    if not route["sink_binding"]["configuration_matches"]:
        for field in ("native_events", "physical_event_order", "terminal_event_count"):
            observations[field] = unknown(route["sink_binding"]["reason"], {"unbound_physical_rows": sink, "configured_sink": route["sink_binding"]})
        return
    identities = {joined["native_id"], joined["common_id"]}
    selected = [row for row in sink if row.get("transaction_id") in identities]
    events = [row for row in selected if row.get("event") is not None]
    refs = [readings.ref(DECISION_FILE, ROLE_SINK)]
    value = {"configured_sink": route["sink_binding"], "actual_common_rows": events, "actual_decision_rows": [row for row in selected if row not in events], "unmatched_physical_rows": [row for row in sink if row not in selected], "native_audit_is_not_common_sink": True}
    if audit is not None:
        value["native_audit_lines"] = [line for line in audit.splitlines() if '[unique_id "' + joined["native_id"] + '"]' in line]
        refs.append(readings.ref(NATIVE_AUDIT, ROLE_SINK))
    observations["native_events"] = measured(value, refs)
    observations["physical_event_order"] = measured(value, refs)
    observations["terminal_event_count"] = unknown("physical Common rows retained; terminal-event classification needs independent product-contract review", value)


def client_measurements(observations, route, readings, index):
    client, wire = route["client"], route["wire"]
    if client is None:
        return
    ref = [readings.ref(route["client_name"], ROLE_CLIENT)]
    observations["transport_framing"] = measured(client, ref)
    if wire is not None:
        wire_ref = ref + [readings.ref(route["wire_name"], ROLE_CLIENT)]
        observations["client_bytes"] = measured(len(wire), wire_ref)
        observations["client_sha256"] = measured(digest(wire), wire_ref)
        boundary = wire.find(b"\r\n\r\n")
        observations["client_headers"] = measured(wire[:boundary + 4].hex(), wire_ref) if boundary >= 0 else unknown("actual client wire contains no complete HTTP/1 headers; no HTTP/2 projection", {"captured_bytes": len(wire)})
    client_process_measurements(observations, route, readings, index)


def client_process_measurements(observations, route, readings, index):
    process_name = "client-" + str(index) + ".process.json"
    process = readings.get(process_name, ROLE_CLIENT)
    if process is not None:
        if process.get("schema") != "i12-companion-client-process-v1" or type(process.get("exit")) is not int:
            observations["client_exit"] = unknown("specific client process receipt has no verified waited exit", process)
            observations["client_signal"] = unknown("specific client process receipt has no verified termination", process)
            return
        observations["client_exit"] = measured({"actual_waited_process": process}, [readings.ref(process_name, ROLE_CLIENT)])
        observations["client_signal"] = measured({"signal": process.get("signal"), "exit": process.get("exit"), "timed_out": process.get("timed_out")}, [readings.ref(process_name, ROLE_CLIENT)])
        return
    commands = route["commands"] or []
    matches = [row for row in commands if row.get("label") == "client-" + str(index)]
    if not matches:
        shared = [row for row in commands if row.get("role") == "independent-client"]
        if len(shared) == 1 and type(shared[0].get("exit")) is int:
            proof = [readings.ref(route["commands_name"], ROLE_CLIENT)]
            observations["client_exit"] = measured({"shared_client_driver": shared[0], "individual_request_exit_not_recorded": True}, proof)
            observations["client_signal"] = measured({"actual_driver_exit": shared[0]["exit"], "actual_driver_signal": shared[0].get("signal"), "signal_field_captured": "signal" in shared[0], "individual_request_signal_not_recorded": True}, proof)
    if len(matches) == 1:
        command = matches[0]
        proof = [readings.ref(route["commands_name"], ROLE_CLIENT)]
        code = command.get("exit")
        if type(code) is not int:
            observations["client_exit"] = unknown("client command has no captured waited exit", command)
            return
        observations["client_exit"] = measured(code, proof)
        observations["client_signal"] = measured({"signal": -code if code is not None and code < 0 else None, "exit": code}, proof)


def backend_hex(value, limit, label):
    if not isinstance(value, str) or len(value) > limit * 2 or len(value) % 2 or re.fullmatch("[0-9a-fA-F]*", value) is None:
        raise ValueError("invalid or oversized backend " + label + " hex")
    return bytes.fromhex(value)


def backend_headers(lines):
    result = []
    for line in lines:
        name, separator, value = line.partition(b":")
        if not separator or HTTP_TOKEN.fullmatch(name) is None:
            raise ValueError("invalid backend HTTP header name")
        if any(byte < 32 and byte != 9 or byte == 127 for byte in value):
            raise ValueError("invalid backend HTTP header value")
        result.append([name.decode("ascii"), value.strip(b" \t").decode("latin1")])
    return result


def spop_backend_request(raw):
    if type(raw.get("neighbor")) is not bool or type(raw.get("wall_ns")) is not int or raw["wall_ns"] <= 0:
        raise ValueError("invalid backend neighbor or physical timestamp")
    header = backend_hex(raw.get("header_hex"), BACKEND_HEADER_LIMIT, "header")
    body = backend_hex(raw.get("body_hex"), BACKEND_BODY_LIMIT, "body")
    lines = header.split(b"\r\n")
    parts = lines[0].split(b" ")
    if len(parts) != 3 or HTTP_TOKEN.fullmatch(parts[0]) is None or parts[2] not in (b"HTTP/1.0", b"HTTP/1.1"):
        raise ValueError("invalid backend HTTP request line")
    if not parts[1] or any(byte < 33 or byte > 126 for byte in parts[1]):
        raise ValueError("invalid backend HTTP request target")
    headers = backend_headers(lines[1:])
    lengths = [value for name, value in headers if name.lower() == "content-length"]
    if any(name.lower() == "transfer-encoding" for name, _ in headers):
        raise ValueError("backend transfer coding is not a complete length-framed capture")
    if len(lengths) > 1 or any(not value.isascii() or not value.isdigit() or len(value) > 20 for value in lengths):
        raise ValueError("ambiguous backend Content-Length")
    length = int(lengths[0]) if lengths else 0
    if len(body) != length:
        raise ValueError("backend body differs from declared Content-Length")
    path = parts[1].decode("ascii")
    if raw["neighbor"] != (path == NEIGHBOR_PATH):
        raise ValueError("backend neighbor marker conflicts with request path")
    return {"method": parts[0].decode("ascii"), "path": path, "http_version": parts[2].decode("ascii"),
            "headers": headers, "body_bytes": len(body), "body_sha256": digest(body), "body_hex": body.hex(),
            "neighbor": path == NEIGHBOR_PATH, "raw_record": raw}


def normalized_backend_rows(route):
    rows, errors = [], []
    for index, raw in enumerate(route["backend"] or []):
        try:
            if not isinstance(raw, dict):
                raise ValueError("physical backend row is not an object")
            if "header_hex" in raw:
                rows.append(spop_backend_request(raw))
            elif raw.get("kind") in BACKEND_KINDS or "method" in raw and "path" in raw:
                rows.append(raw)
            elif raw.get("kind") not in ("client", "capture_cleanup"):
                raise ValueError("unknown physical backend row shape")
        except (TypeError, ValueError) as error:
            errors.append({"row": index, "reason": str(error), "raw_record": raw})
    return rows, errors


def actual_backend_rows(route):
    rows, errors = normalized_backend_rows(route)
    return rows if not errors else None


def backend_zero_control(route, readings, requests):
    raw = read_bytes(readings.root / route["backend_name"])
    if raw and not raw.endswith(b"\n"):
        return None, "backend log has no complete final JSONL line"
    ready = readings.get("backend.ready", ROLE_BACKEND, "bytes")
    cleanup = readings.get("cleanup.jsonl", ROLE_CLEANUP, "jsonl")
    if ready is None or not any(row.get("backend_joined") is True for row in cleanup or []):
        return None, "backend readiness or joined-producer receipt is missing"
    neighbors = [row for row in route["all_clients"] or [] if row.get("neighbor") is True]
    actual_neighbor = [row for row in requests if row.get("path") == NEIGHBOR_PATH]
    wire = readings.get("response-neighbor.raw", ROLE_CLIENT, "bytes")
    if len(neighbors) != 1 or len(actual_neighbor) != 1 or wire is None:
        return None, "zero main count needs one independently captured positive neighbor"
    measured_wire = CASES.response_measurements(wire)
    if neighbors[0].get("response_sha256") != digest(wire) or measured_wire.get("status") != 200 or measured_wire.get("complete_length_framing") is not True:
        return None, "positive neighbor wire/hash/framing is incomplete"
    return {"backend_log_opened": True, "backend_joined": True, "positive_neighbor_backend_rows": actual_neighbor,
            "actual_neighbor_client": neighbors[0], "actual_neighbor_wire_sha256": digest(wire),
            "actual_neighbor_response": measured_wire}, None


def backend_measurements(observations, route, readings, path):
    if route["backend"] is None or route["client"] is None:
        return
    rows, errors = normalized_backend_rows(route)
    requests = [row for row in rows if row.get("kind") == "backend_request" or "method" in row]
    selected = [row for row in requests if row.get("path") == path]
    value = {"matching_path": len(selected), "all_actual_requests": requests, "raw_physical_rows": route["backend"]}
    if route["backend_name"] == BACKEND_FILE:
        raw = read_bytes(readings.root / route["backend_name"])
        if raw and not raw.endswith(b"\n"):
            errors.append({"reason": "backend log has no complete final JSONL line"})
    if errors:
        observations["backend_request_count"] = unknown("unknown or corrupt backend rows prevent an exact request count", {**value, "decode_errors": errors})
        return
    if not selected and route["backend_name"] == BACKEND_FILE:
        control, reason = backend_zero_control(route, readings, requests)
        if control is None:
            observations["backend_request_count"] = unknown(reason, value)
            return
        value["zero_main_positive_control"] = control
    backend_ref = [readings.ref(route["backend_name"], ROLE_BACKEND)]
    observations["backend_request_count"] = measured(value, backend_ref)
    refs = backend_ref + [readings.ref(route["client_name"], ROLE_CLIENT)]
    partial = {"path": path, "matching_backend_rows": selected, "actual_client": route["client"], "path_only_is_not_unique_transaction_correlation": True}
    for field in ("backend_payload_identity", "client_backend_correlation"):
        observations[field] = unknown("independent raw client/backend facts retained; exact payload and per-client correlation review pending", partial)
        observations[field]["partial_evidence"] = refs


def mapped_image_paths(maps):
    return sorted({line.split()[-1] for line in maps.splitlines()
                   if "libmodsecurity.so" in line or line.rstrip().endswith(("/haproxy", "/haproxy-spop"))})


def resolve_mapped_image(binding, expected, owner, namespace):
    actual, ledger = binding["bindings"].resolve(namespace)
    actual_hash = digest(read_bytes(actual))
    if expected.get(str(actual)) != actual_hash:
        raise ValueError("actual mapped image differs from sealed source provenance")
    return {"process": owner, "namespace_path": namespace, "physical_path": str(actual),
            "sha256": actual_hash, "ledger": str(ledger)}


def mapped_images(readings, binding, companion):
    images, reasons, refs = [], [], []
    expected = {image["sealed_copy"]: image["sha256"] for image in binding["images"]}
    for owner in ("agent", "host"):
        name = owner + ("-before-main.maps" if companion else "-before.maps")
        maps = readings.get(name, ROLE_IMAGE, "text")
        if maps is None:
            reasons.append("missing " + name)
            continue
        refs.append(readings.ref(name, ROLE_IMAGE))
        paths = mapped_image_paths(maps)
        if not paths:
            reasons.append("no SDK/binary mapping in " + name)
        for namespace in paths:
            try:
                images.append(resolve_mapped_image(binding, expected, owner, namespace))
            except (OSError, ValueError) as error:
                reasons.append(str(error))
    return images, reasons, refs


def image_measurements(observations, readings, binding, companion):
    images, reasons, refs = mapped_images(readings, binding, companion)
    value = {"actual_loaded_images": images, "sealed_images": binding["images"], "actual_admission": binding["admission"]}
    observations["product_host_identity"] = measured(value, [*refs, binding["controller_reference"]]) if images and not reasons else unknown("loaded image mapping incomplete: " + "; ".join(reasons), value)


def companion_association(route, joined):
    handoffs = [row for row in route["agent_callbacks"] if row.get("kind") == "spop_registry_handoff" and row.get("scope_call") == joined["scope"]]
    if len(handoffs) != 1:
        return None, "no unique capability handoff for actual native scope"
    capability = handoffs[0].get("capability_sha256")
    streams = [stream for stream in route["mrc_streams"] if stream["file"].endswith("-host.forwarded.bin") and any(frame.get("capability_sha256") == capability for frame in stream["frames"])]
    callbacks = [row for row in route["host_callbacks"] if row.get("capability_sha256") == capability]
    if capability is None or len(streams) != 1 or not callbacks:
        return None, "capability lacks unique physical CLAIM and host callback association"
    stream = streams[0]
    owner_file = stream["file"].replace("-host.forwarded.bin", "-owner.forwarded.bin")
    owners = [row for row in route["mrc_streams"] if row["file"] == owner_file]
    if len(owners) != 1:
        return None, "physical MRC1 owner replies missing or ambiguous"
    return {"capability_sha256": capability, "host_callbacks": callbacks,
            "host_frames": stream, "owner_frames": owners[0], "agent_handoff": handoffs[0]}, None


def host_measurements(observations, route, readings, joined, companion, fixture_ref):
    scope = joined["scope"]
    agent = [row for row in route["agent_callbacks"] if row.get("scope_call") == scope]
    api = readings.ref(route["native_name"], ROLE_API)
    if not agent or AGENT_STDERR not in readings.artifacts:
        return
    callback = readings.ref(AGENT_STDERR, ROLE_HOST)
    observations["capability"] = measured({"actual_scope_callbacks": agent, "bounded_authorization_sample": True,
                                           "unbounded_streaming_proven": False, "fully_inspected_http2": False}, [callback, fixture_ref])
    eos = {"actual_scope_callbacks": agent, "not_inferred_from_client_close": True}
    native_eos = {"request": calls(joined["rows"], REQUEST_BODY_CALL),
                  "response": calls(joined["rows"], "native_process_response_body"),
                  "no_invented_request_or_response_EOS": True}
    if not companion:
        eos["streaming_eos_argument"] = None
        eos["streaming_eos_reason"] = "bounded SPOP sample callback has no streaming EOS argument"
        native_eos["actual_finite_P2_completion"] = calls(joined["rows"], REQUEST_BODY_CALL)
        native_eos["actual_request_authorization_finish"] = calls(joined["rows"], REQUEST_FINISH_CALL)
        native_eos["actual_runtime_eos_handoffs"] = [row for row in joined["rows"] if row.get("runtime_eos_handoff") is not None]
        native_eos["actual_contract_transitions"] = transitions(joined["rows"])
        native_eos["streaming_eos_argument"] = None
        native_eos["streaming_eos_reason"] = "finite native P2 processing/finalization retained; no streaming EOS argument is invented"
        observations["host_eos"] = measured(eos, [callback])
        observations["native_eos"] = measured(native_eos, [api, callback])
        return
    association, reason = companion_association(route, joined)
    if association is None:
        observations["host_eos"] = unknown(reason, eos)
        return
    eos["physical_companion"] = association
    callback = readings.ref(HOST_STDERR, ROLE_HOST)
    observations["host_eos"] = measured(eos, [callback])
    observations["native_eos"] = measured(native_eos, [api, callback])
    client_ref = readings.ref(route["client_name"], ROLE_CLIENT)
    partial = {"actual_client": route["client"], "actual_capability_callbacks": eos,
               "actual_common_commit_returns": calls(joined["rows"], "common_set_response_committed")}
    reason = "exact client start and host SSL_write transaction binding not captured" if not joined["complete_time_window"] else "host SSL_write has no independent per-transaction identity"
    observations["commit_order"] = unknown(reason, partial)
    observations["commit_order"]["partial_evidence"] = [callback, client_ref]
    observations["host_action"] = unknown("client transport and host operation facts retained; exact action correlation review pending", partial)
    observations["transport_reset_scope"] = unknown("connection reset scope requires independent host connection association", partial)


def companion_cleanup_captures(observations, route, readings):
    captures = {}
    for owner in ("agent", "host"):
        captures[owner] = {stage: readings.get(owner + "-" + stage + ".fds.json", ROLE_CLEANUP) for stage in ("before-main", "after-main", "after-neighbor")}
    neighbor = readings.get("client-100.json", ROLE_CLIENT)
    if neighbor is not None and route["backend"] is not None:
        observations["neighbor_health"] = measured({"actual_neighbor_client": neighbor, "actual_backend_rows": actual_backend_rows(route)}, [readings.ref("client-100.json", ROLE_CLIENT), readings.ref(route["backend_name"], ROLE_BACKEND)])
    return captures


def request_cleanup_captures(observations, route, readings):
    captures = {}
    rows = readings.get("process-identity.jsonl", ROLE_CLEANUP, "jsonl")
    if rows is not None:
        captures["actual_process_snapshots"] = rows
    neighbors = [row for row in route["all_clients"] or [] if row.get("neighbor") is True]
    if len(neighbors) == 1 and route["backend"] is not None:
        observations["neighbor_health"] = measured({"actual_neighbor_client": neighbors[0], "actual_backend_rows": actual_backend_rows(route)}, [readings.ref(route["client_name"], ROLE_CLIENT), readings.ref(route["backend_name"], ROLE_BACKEND)])
    return captures


def cleanup_and_neighbor(observations, route, readings, companion):
    captures = (companion_cleanup_captures(observations, route, readings) if companion
                else request_cleanup_captures(observations, route, readings))
    if captures:
        proofs = [readings.ref(name, ROLE_CLEANUP) for name in readings.artifacts if name.endswith(".fds.json") or name == "process-identity.jsonl"]
        if proofs:
            value = {"actual_captures": captures, "descriptor_targets_are_not_listener_leak_verdicts": True}
            complete = not companion or all(value is not None for owner in captures.values() for value in owner.values())
            observations["descriptor_cleanup"] = measured(value, proofs) if complete else unknown("required descriptor stage missing", value)


def associate_route(route, case_id, leg):
    client = route["client"]
    if client is not None and "request_send_started_wall_ns" in client and client["request_send_started_wall_ns"] is None:
        return None, "actual child capture records no request send start; stale native rows are not associated", None
    request = route["request"]
    path, request_body = None, None
    if request:
        first_line = request.split(b"\r\n", 1)[0].split()
        if len(first_line) == 3:
            path = first_line[1].decode("ascii")
            if b"\r\n\r\n" in request:
                request_body = request.split(b"\r\n\r\n", 1)[1]
    joined, reason = None, "actual captured client request/client measurement missing"
    if route["decode_errors"]:
        reason = "physical frame/callback decoding incomplete; association withheld"
    if path and route["client"] is not None and route["native"] is not None and not route["decode_errors"]:
        same_case = [row for row in route["native"] if row.get("case") == case_id and row.get("profile") == leg]
        joined, reason = transaction_join(same_case, notify_messages(route["frames"]), path, route["client"], request_body)
    return joined, reason, path


def execution_fact(route, joined, path):
    client = route["client"]
    if client is None:
        return False, "actual client measurement is missing"
    if "request_send_started_wall_ns" in client and client["request_send_started_wall_ns"] is None:
        return False, "actual client capture records no request send start"
    if joined is not None or route["wire"]:
        return True, None
    selected, reason = notify_selection(notify_messages(route["frames"]), path, client, None)
    if path is not None and selected is not None:
        return True, None
    return False, "no unambiguous client-specific host/native or received-wire observation: " + str(reason)


def source_configuration(observations, readings, binding):
    config = readings.get("haproxy.cfg", ROLE_CONFIG, "bytes")
    rules = readings.get("rules.conf", ROLE_CONFIG, "bytes")
    additional_configs = {name: readings.get(name, ROLE_CONFIG, "bytes") for name in (AGENT_CONFIG, "spoe.cfg")}
    if config is not None and rules is not None:
        observations["source_config_binding"] = measured({"source_provenance": binding["provenance"], "effective_config_sha256": digest(config), "rules_sha256": digest(rules), "additional_effective_config_sha256": {name: digest(value) if value is not None else None for name, value in additional_configs.items()}, "source_fixture": binding["fixture"]}, [*binding["references"][:3], readings.ref("haproxy.cfg", ROLE_CONFIG), readings.ref("rules.conf", ROLE_CONFIG), *[readings.ref(name, ROLE_CONFIG) for name, value in additional_configs.items() if value is not None]])
    return config


def verify_capture_artifacts(route, readings):
    capture_receipt = route["capture_receipt"]
    if capture_receipt is not None:
        for name, identity in readings.artifacts.items():
            expected = capture_receipt.get("files", {}).get(name)
            if expected is not None and expected != identity["sha256"]:
                raise ValueError("actual raw artifact differs from host receipt seal: " + name)


def unmatched_sink_rows(route, joined):
    return [row for row in route["physical_sink"] or []
            if not joined or row.get("transaction_id") not in (joined["native_id"], joined["common_id"])]


def observe(attempt, data, spec, build_receipt, fixture, leg, case_id, index=0, original_contract=None):
    if index < 0:
        raise ValueError("nonnegative explicit client index required")
    if leg not in (REQUEST, COMPANION) or not case_id.startswith("I12::" + leg + "::"):
        raise ValueError("explicit route and exact case ID must agree")
    binding = bind_inputs(attempt, data, spec, build_receipt, fixture)
    fixture_id = binding["fixture"].get("case_id")
    if isinstance(fixture_id, str) and fixture_id.startswith("I12::") and fixture_id != case_id:
        raise ValueError("explicit case differs from sealed source fixture")
    readings = Readings(data)
    companion = leg == COMPANION
    route = load_route(readings, companion, index)
    route["sink_binding"] = configured_sink(readings, attempt)
    observations = {field: unknown("required physical observation not yet associated") for field in LEDGER.ROLES}
    config = source_configuration(observations, readings, binding)
    client_measurements(observations, route, readings, index)
    joined, reason, path = associate_route(route, case_id, leg)
    if joined:
        native_measurements(observations, route, readings, joined)
        sink_measurements(observations, route, readings, joined)
        host_measurements(observations, route, readings, joined, companion, binding["references"][-1])
    backend_measurements(observations, route, readings, path)
    image_measurements(observations, readings, binding, companion)
    cleanup_and_neighbor(observations, route, readings, companion)
    controller = binding["controller"]
    cleanup_ref = [binding["controller_reference"]]
    commands = route["commands"]
    if commands is not None:
        cleanup_ref.append(readings.ref(route["commands_name"], ROLE_CLEANUP))
        observations["cleanup_receipts"] = measured({"controller": controller, "commands": commands, "actual_final_native_rows": [row for row in route["native"] or [] if row.get("edge") == "final"]}, cleanup_ref)
        observations["process_listener_cleanup"] = measured({key: controller.get(key) for key in ("surviving_namespace_pids", "outside_mount_leaks", "supervisor_reaped")}, cleanup_ref)
    original = read_json(original_contract) if original_contract else None
    execution_observed, execution_reason = execution_fact(route, joined, path)
    verify_capture_artifacts(route, readings)
    raw_rows = route["native"] or []
    matched = joined["rows"] if joined else []
    return {"run_scoped_case_id": case_id, "leg_id": leg, "run_id": attempt.name,
            "execution_kind": "host_http", "execution_observed": execution_observed, "execution_observed_reason": execution_reason,
            "reviewed_by": "pending_root", "parent_sha": binding["provenance"].get("product_revision", binding["provenance"].get("product_and_capture_revision")),
            "framework_sha": None, "mrts_sha": None, "effective_config_sha256": digest(config) if config is not None else None,
            "source_bound_fixture_contract": binding["fixture"], "original_contract": original, "batch_execution_binding": binding["batch"],
            "oracle_evaluated": None, "outcome": None, "full_lifecycle_qualified": None,
            "observations": observations, "partial_association": {"join": {key: value for key, value in joined.items() if key != "rows"} if joined else None, "reason": reason},
            "unmatched_agent_native_rows": [row for row in raw_rows if row not in matched],
            "unmatched_physical_sink_rows": unmatched_sink_rows(route, joined),
            "unmatched_host_native_rows": route["host_native"], "actual_host_callbacks": route["host_callbacks"],
            "actual_agent_callbacks": route["agent_callbacks"], "physical_SPOP_frames": route["frames"],
            "physical_MRC1_streams": route["mrc_streams"], "physical_common_sink_binding": route["sink_binding"], "decode_errors": route["decode_errors"],
            "missing_or_corrupt_files": readings.problems, "raw_artifacts": list(readings.artifacts.values())}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("attempt", "case-data-root", "spec", "build-receipt", "fixture", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--leg", choices=(REQUEST, COMPANION), required=True)
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--client-index", type=int, default=0)
    parser.add_argument("--original-contract", type=Path)
    args = parser.parse_args()
    result = observe(args.attempt, args.case_data_root, args.spec, args.build_receipt, args.fixture,
                     args.leg, args.case_id, args.client_index, args.original_contract)
    with CAPTURE.storage_parent(args.output) as (parent, name):
        CAPTURE.write_upstream_member(parent, (name,), (json.dumps(result, indent=2) + "\n").encode(), 0o600)
    print(json.dumps({"case_id": args.case_id, "fields": len(result["observations"]), "outcome": None}))


if __name__ == "__main__":
    main()
