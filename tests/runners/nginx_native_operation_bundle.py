"""Read original native operation receipts under explicit artifact/source authority.

Empty errors prove only the selected observation layer, never canonical PASS or
a trusted build. No artifacts are written and no native events are manufactured.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import threading
import types

RAW_LIMIT = 1024 * 1024
ARTIFACT_LIMIT = 64 * 1024 * 1024
MODE = "native-nginx-http-module"
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
RUN_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_HELPER_LOCK = threading.RLock()
RAW_CASES = frozenset({"invalid_content_length", "conflicting_content_length", "duplicate_transfer_encoding", "content_length_overflow"})
INPUT_CASES = frozenset({"body_size_nonzero_with_null_data", "header_count_nonzero_with_null_headers"})
MIME_CASES = frozenset({"phase4_in_scope_content_type", "phase4_content_type_with_charset", "phase4_out_of_scope_content_type", "phase4_missing_content_type"})
PHASE4_CASES = frozenset({"phase4_marker_split_across_chunks", "phase4_end_of_stream_evaluation", "phase4_deny_after_commit_log_only_minimal", "phase4_body_at_limit", "phase4_body_over_limit", "phase4_body_process_partial", "phase4_body_reject", "full_lifecycle_event_metadata_bounded"})
EVENT_CASES = frozenset({"event_metadata_truncation", "event_json_limit"})
SEQUENCE_CASES = frozenset({"single_request_cleanup", "multiple_sequential_requests", "keep_alive_requests_if_supported", "clean_shutdown", "keepalive_allow_allow", "keepalive_allow_deny_allow", "early_mapping_failure_cleanup", "transaction_begin_failure_cleanup", "phase4_strict_http1_client_abort", "phase4_strict_host_survives", "phase4_strict_followup_request_succeeds", "keepalive_after_strict_new_connection", "keepalive_safe_followup", "response_short_write_resume", "response_write_would_block_resume", "transport_keep_alive", "transport_sequential_requests", "finish_failure_propagation", "engine_timeout_before_commit", "engine_timeout_after_commit", "transport_http11_content_length", "transport_http11_chunked"})
CASE_IDS = RAW_CASES | INPUT_CASES | MIME_CASES | PHASE4_CASES | EVENT_CASES | SEQUENCE_CASES
FAULT_SOURCES = {
    "transaction_begin_failure_cleanup": "nginx_transaction_fault.c",
    "finish_failure_propagation": "nginx_finish_fault.c",
    "response_short_write_resume": "nginx_write_fault.c",
    "response_write_would_block_resume": "nginx_write_fault.c",
    "engine_timeout_before_commit": "nginx_engine_budget_fault.c",
    "engine_timeout_after_commit": "nginx_engine_budget_fault.c",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def relative_parts(value):
    require(isinstance(value, str) and value and not value.startswith("/")
            and all(part not in ("", ".", "..") for part in value.split("/")), "unsafe relative artifact path")
    require("\x00" not in value and "\\" not in value, "unsafe artifact path character")
    return value.split("/")


def open_directory(path):
    """Walk every absolute component with NOFOLLOW, including authority ancestors."""
    require(isinstance(path, Path) and path.is_absolute() and ".." not in path.parts, "absolute artifact authority required")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = following
        return descriptor
    except OSError as exc:
        os.close(descriptor)
        raise ValueError("unsafe artifact directory") from exc


def read_bounded_file(authority, relative, limit=RAW_LIMIT):
    """Return original bytes from a pinned, owned, single-link regular file."""
    parts = relative_parts(relative)
    require(type(limit) is int and limit > 0, "positive artifact bound required")
    directory = open_directory(authority)
    descriptor = None
    try:
        metadata = os.fstat(directory)
        require(metadata.st_uid == os.geteuid() and not metadata.st_mode & 0o022, "owned non-writable artifact authority required")
        for part in parts[:-1]:
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = following
            metadata = os.fstat(directory)
            require(metadata.st_uid == os.geteuid() and not metadata.st_mode & 0o022, "owned non-writable retained directory required")
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_uid == os.geteuid() and not before.st_mode & 0o022
                and before.st_size <= limit, "artifact must be owned bounded single-link non-writable regular file")
        chunks = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        require(len(data) == before.st_size and len(data) <= limit
                and all(getattr(before, field) == getattr(after, field) for field in fields), "artifact changed during bounded read")
        return data
    except OSError as exc:
        raise ValueError("unsafe or missing retained artifact: " + relative) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory)


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "duplicate JSON object key")
        value[key] = item
    return value


def json_object(raw):
    try:
        value = json.loads(raw, object_pairs_hook=unique_object,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON number")),
                           parse_float=finite_float)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid retained JSON") from exc
    require(isinstance(value, dict), "retained JSON object required")
    return value


def finite_float(value):
    number = float(value)
    require(math.isfinite(number), "nonfinite JSON number")
    return number


def json_lines(raw):
    return [json_object(line) for line in raw.splitlines() if line.strip()]


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def route(case_id):
    require(isinstance(case_id, str), "bounded native case identity required")
    for cases, operation, helper in (
        (RAW_CASES, "native_h1_parser_rejection", "nginx_raw_h1"),
        (INPUT_CASES, "common_mapper_input_fault", "nginx_common_input_faults"),
        (MIME_CASES, "native_phase4_request", "nginx_mime_operations"),
        (PHASE4_CASES, "native_phase4_request", "nginx_phase4_operations"),
        (EVENT_CASES, "native_event_boundary_request", "nginx_event_boundary_operations"),
        (SEQUENCE_CASES, "request_sequence", "nginx_lifecycle_sequence"),
    ):
        if case_id in cases:
            return operation, helper
    raise ValueError("unknown closed native operation case")


def required_source_paths(case_id):
    """Exact source whitelist; wrapper computes these bytes, never supplies paths."""
    _, helper = route(case_id)
    parent = {"ci/runtime/lifecycle/run-nginx-valid-rules.py", "ci/runtime/lifecycle/run-nginx-configtest.py",
              "ci/runtime/lifecycle/run-selected-nginx-native-operations.py", "ci/runtime/lifecycle/nginx-native-operation-source.py",
              "ci/runtime/common/prepare-nginx-docroot-projection.py", "ci/lib/runtime_path_utils.py",
              "ci/runtime/lifecycle/collect-no-crs-source.py", "ci/runtime/lifecycle/nginx_native_collection.py",
              "ci/runtime/lifecycle/nginx_native_authority.py", "ci/runtime/lifecycle/run-no-crs-baseline.sh",
              "ci/runtime/lifecycle/run-nginx-selected-host.sh", "ci/runtime/lifecycle/run-connector-stage.sh"}
    framework = {"tests/runners/" + helper + ".py", "tests/runners/nginx_native_operation_bundle.py",
                 "tests/runners/nginx_native_operation_projection.py", "tests/runners/nginx_native_operation_contract.py",
                 "tests/runners/nginx_native_operation_authority.py", "tests/runners/nginx_http11_framing.py",
                 "tests/runners/nginx_lifecycle_sequence.py", "tests/runners/nginx_phase4_contracts.py",
                 "tests/runners/msconnector_models.py", "ci/checks/catalog/no_crs_baseline.py",
                 "tests/cases/no-crs-baseline/catalog.json"}
    framework.update("tests/schemas/no-crs-baseline/" + name + ".schema.json"
                     for name in ("case-catalog", "case-result", "result", "manifest", "inventory", "event"))
    drivers = {"nginx_raw_h1": "run-nginx-raw-h1.py", "nginx_common_input_faults": "run-nginx-common-input-fault.py",
               "nginx_mime_operations": "run-nginx-mime-cases.py", "nginx_phase4_operations": "run-nginx-phase4-cases.py",
               "nginx_event_boundary_operations": "run-nginx-event-boundary-cases.py", "nginx_lifecycle_sequence": "run-nginx-lifecycle-sequences.py"}
    parent.add("ci/runtime/lifecycle/" + drivers[helper])
    if case_id not in PHASE4_CASES | EVENT_CASES:
        framework.add("tests/rules/no-crs-baseline.conf")
    if case_id in MIME_CASES | PHASE4_CASES | EVENT_CASES:
        parent.update({"ci/runtime/lifecycle/run-nginx-phase4-cases.py", "ci/runtime/common/nginx_phase4_upstream.py"})
    if case_id in PHASE4_CASES:
        framework.add("tests/runners/nginx_phase4_contracts.py")
    if case_id in MIME_CASES:
        parent.update({"ci/runtime/common/response-header-test-backend.py", "ci/runtime/common/response_fixture_omission.py"})
    if case_id in EVENT_CASES:
        framework.update({"tests/runners/nginx_mime_operations.py", "tests/runners/nginx_common_input_faults.py"})
    if case_id in SEQUENCE_CASES:
        parent.update({"ci/runtime/lifecycle/nginx_sequence_client.py", "ci/runtime/lifecycle/nginx_sequence_upstream.py"})
        framework.add("tests/runners/nginx_http11_framing.py")
    if case_id in INPUT_CASES:
        parent.add("tests/fixtures/nginx_common_input_fault.c")
    if case_id in FAULT_SOURCES:
        parent.add("tests/fixtures/" + FAULT_SOURCES[case_id])
    return frozenset({"parent:" + item for item in parent} | {"framework:" + item for item in framework})


def verify_source_authority(record, envelope, sources):
    require(isinstance(sources, dict), "explicit source authority required")
    for field in ("parent_sha", "framework_sha", "mrts_sha"):
        expected = sources.get(field)
        require(isinstance(expected, str) and SHA40.fullmatch(expected), "exact source revision required: " + field)
        require(record.get(field) == expected, "outer source revision mismatch: " + field)
    for field in ("binary_sha256", "module_sha256"):
        require(isinstance(sources.get(field), str) and SHA256.fullmatch(sources[field]), "explicit actual build digest required: " + field)
    mapping = envelope.get("source_sha256")
    required = required_source_paths(record["case_id"])
    require(isinstance(mapping, dict) and set(mapping) == required, "closed producer/source path set mismatch")
    captured = {}
    for name in sorted(required):
        owner, relative = name.split(":", 1)
        root = sources.get(owner + "_root")
        raw = read_bounded_file(root, relative)
        require(mapping[name] == digest(raw), "actual producer/source bytes mismatch: " + name)
        captured[name] = raw
    for container in (record.get("provenance"), record.get("result")):
        if container is not None:
            require(isinstance(container, dict), "source provenance/result object required")
            for field in ("parent_sha", "framework_sha", "mrts_sha"):
                require(container.get(field) == sources[field], "nested source revision mismatch: " + field)
    return captured


def load_helpers(case_id, source_bytes, framework_root):
    """Execute only caller-authorized, independently reopened source bytes."""
    _, main = route(case_id)
    dependencies = []
    if case_id in PHASE4_CASES:
        dependencies.append("nginx_phase4_contracts")
    if case_id in EVENT_CASES:
        dependencies.extend(("nginx_mime_operations", "nginx_common_input_faults"))
    if case_id in SEQUENCE_CASES:
        require("framework:tests/runners/nginx_http11_framing.py" in source_bytes,
                "captured HTTP/1.1 framing source is required")
        dependencies.append("nginx_http11_framing")
    modules = {}
    previous = {}
    # Imports are scoped under the lock and restored, not taken from arbitrary
    # already-imported modules or receipt-controlled sys.path entries.
    with _HELPER_LOCK:
        try:
            for name in dependencies + [main]:
                relative = "tests/runners/" + name + ".py"
                module = types.ModuleType(name)
                module.__file__ = str(framework_root / relative)
                previous[name] = sys.modules.get(name)
                sys.modules[name] = module
                if case_id in SEQUENCE_CASES and name == main:
                    module._AUTHENTICATED_WIRE = modules["nginx_http11_framing"]
                exec(compile(source_bytes["framework:" + relative], module.__file__, "exec"), module.__dict__)
                modules[name] = module
        finally:
            for name, original in previous.items():
                if original is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = original
    return modules[main]


class BundleReader:
    def __init__(self, authority, root):
        require(isinstance(authority, Path) and authority.is_absolute() and authority != Path("/"), "bounded artifact authority required")
        require(isinstance(root, str) and root, "bundle root required")
        candidate = Path(root)
        if not candidate.is_absolute():
            relative_parts(root)
            candidate = authority / candidate
        require(".." not in candidate.parts, "unsafe bundle root")
        try:
            relative = candidate.relative_to(authority)
        except ValueError as exc:
            raise ValueError("bundle root is outside artifact authority") from exc
        descriptor = open_directory(authority)
        try:
            metadata = os.fstat(descriptor)
            require(metadata.st_uid == os.geteuid() and not metadata.st_mode & 0o022, "private owned artifact authority required")
            for part in relative.parts:
                following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = following
                metadata = os.fstat(descriptor)
                require(metadata.st_uid == os.geteuid() and not metadata.st_mode & 0o022, "private owned bundle path required")
        finally:
            os.close(descriptor)
        self.root = candidate
        self.files = {}

    def read(self, relative, expected=None, limit=RAW_LIMIT):
        raw = read_bounded_file(self.root, relative, limit)
        actual = digest(raw)
        if expected is not None:
            require(isinstance(expected, str) and SHA256.fullmatch(expected) and actual == expected, "retained raw digest mismatch: " + relative)
        self.files[relative] = {"sha256": actual, "size": len(raw), "limit": limit}
        return raw


COMMON_RAW = frozenset({"nginx.conf", "nginx-binary", "nginx-module.so", "no-crs-baseline.conf", "rules.conf",
                        "configtest.stdout", "configtest.stderr", "stdout.log", "stderr.log", "startup.stdout", "startup.stderr",
                        "nginx-error.log", "worker-maps.log", "roles.json", "cleanup.json", "client.stdout", "client.stderr",
                        "response.bin", "response.headers", "phase4-events.jsonl", "phase1-events.jsonl", "native-events.jsonl",
                        "native-access.jsonl", "access.jsonl", "fault-request.bin", "fault-response.bin", "control-request.bin", "control-response.bin",
                        "native-input-fault.jsonl", "native-input-fault.so", "response-header-fixture.json"})
SEQUENCE_HASHES = {
    "binary_sha256": "nginx-binary", "module_sha256": "nginx-module.so", "rules_sha256": "no-crs-baseline.conf",
    "observed_sha256": "sequence-observation.json", "config_sha256": "nginx.conf", "native_access_sha256": "native-access.jsonl",
    "events_sha256": "phase1-events.jsonl", "worker_maps_sha256": "worker-maps.log",
    "native_writes_sha256": "native-write-observations.jsonl", "native_finish_sha256": "native-finish-observations.jsonl",
    "native_budget_sha256": "native-budget-observations.jsonl", "request_wire_sha256": "request-wire.bin", "response_wire_sha256": "response-wire.bin",
    "native_begin_sha256": "native-begin-observations.jsonl",
    "upstream_request_wire_sha256": "upstream-request-wire.bin", "upstream_response_wire_sha256": "upstream-response-wire.bin",
}


def read_hash_map(reader, prefix, mapping, allowed):
    require(isinstance(mapping, dict) and set(mapping) <= allowed, "closed raw artifact hash mapping required")
    require(all(isinstance(value, str) and SHA256.fullmatch(value) for value in mapping.values()), "exact raw artifact seals required")
    return {leaf: reader.read(prefix + leaf, expected, ARTIFACT_LIMIT if leaf in {"nginx-binary", "nginx-module.so"} else RAW_LIMIT)
            for leaf, expected in mapping.items()}


def receipt_seal(receipt, field):
    value = receipt.get(field)
    require(isinstance(value, str) and SHA256.fullmatch(value), "required actual receipt seal absent: " + field)
    return value


def read_invocation(reader, descriptor, case_id, operation, sources):
    path = descriptor.get("receipt_path")
    parts = relative_parts(path)
    expected_leaf = "sequence-source.json" if case_id in SEQUENCE_CASES else "input-fault-source.json" if case_id in INPUT_CASES else "source-result.json"
    require(parts[-1] == expected_leaf, "original producer receipt leaf required")
    require(case_id in EVENT_CASES or parts == [expected_leaf], "main invocation must use the fixed original receipt leaf")
    original = reader.read(path, descriptor.get("receipt_sha256"))
    document = json_object(original)
    row = None
    if case_id in SEQUENCE_CASES | INPUT_CASES:
        require(isinstance(document.get("cases"), list) and len(document["cases"]) == 1, "one original producer source row required")
        row = document["cases"][0]
        require(isinstance(row, dict) and row.get("case_id") == case_id and row.get("operation") == operation
                and row.get("live_executed") is True and row.get("errors") == [], "failed/foreign original producer row")
        receipt = row.get("sequence_receipt" if case_id in SEQUENCE_CASES else "input_fault_receipt")
    else:
        receipt = document
    require(isinstance(receipt, dict) and receipt.get("case_id") == case_id and receipt.get("operation") == operation, "original receipt identity mismatch")
    for field in ("parent_sha", "framework_sha", "mrts_sha"):
        require(receipt.get(field) == sources[field], "original source revision mismatch: " + field)
    run_id = receipt.get("run_id")
    require(isinstance(run_id, str) and RUN_ID.fullmatch(run_id), "original bounded run identity required")
    if row is not None:
        require(row.get("run_id") == run_id, "source/receipt run identity mismatch")
    prefix = "/".join(parts[:-1])
    prefix = prefix + "/" if prefix else ""
    raw = {}
    if case_id in SEQUENCE_CASES:
        for field, leaf in SEQUENCE_HASHES.items():
            if field in receipt and receipt[field] is not None:
                raw[leaf] = reader.read(prefix + leaf, receipt[field], ARTIFACT_LIMIT if field in {"binary_sha256", "module_sha256"} else RAW_LIMIT)
        require({"nginx-binary", "nginx-module.so", "no-crs-baseline.conf", "sequence-observation.json", "nginx.conf", "native-access.jsonl"} <= set(raw), "sequence receipt omits required raw seals")
        if case_id in FAULT_SOURCES:
            leaf = {"nginx_transaction_fault.c": "native-transaction-fault.so", "nginx_finish_fault.c": "native-finish-fault.so", "nginx_write_fault.c": "native-write-fault.so", "nginx_engine_budget_fault.c": "native-budget-fault.so"}[FAULT_SOURCES[case_id]]
            raw[leaf] = reader.read(prefix + leaf, receipt_seal(receipt, "fault_library_sha256"), ARTIFACT_LIMIT)
        # Original sequence producer retains these actual captures but has no
        # individual receipt seal for them. They are reopened and manifest-sealed
        # here rather than inventing fields in its original receipt.
        for leaf in ("configtest.stdout", "configtest.stderr", "startup.stdout", "startup.stderr", "nginx-error.log", "phase1-events.jsonl"):
            if leaf not in raw:
                raw[leaf] = reader.read(prefix + leaf)
    elif case_id in INPUT_CASES:
        raw.update(read_hash_map(reader, prefix, receipt.get("artifacts_sha256"), COMMON_RAW))
        raw.update(read_hash_map(reader, prefix, receipt.get("raw_artifacts_sha256"), COMMON_RAW))
        raw["input-fault-observation.json"] = reader.read(prefix + "input-fault-observation.json", receipt_seal(receipt, "observed_sha256"))
        raw["nginx.conf"] = reader.read(prefix + "nginx.conf", receipt_seal(receipt, "config_sha256"))
    else:
        raw.update(read_hash_map(reader, prefix, receipt.get("raw_sha256"), COMMON_RAW))
        for field, leaf in (("binary_sha256", "nginx-binary"), ("module_sha256", "nginx-module.so")):
            if field in receipt:
                raw[leaf] = reader.read(prefix + leaf, receipt[field], ARTIFACT_LIMIT)
    for field, leaf in (("binary_sha256", "nginx-binary"), ("module_sha256", "nginx-module.so")):
        require(leaf in raw and digest(raw[leaf]) == sources[field], "actual build snapshot mismatch: " + leaf)
    return receipt, raw, original


def require_leaves(raw, leaves):
    require(set(leaves) <= set(raw), "missing actual raw artifacts: " + ",".join(sorted(set(leaves) - set(raw))))


def exact(value, expected, label):
    require(isinstance(value, dict) and all(type(value.get(key)) is type(wanted) and value.get(key) == wanted
                                          for key, wanted in expected.items()), label + " mismatch")


def observed_roles(roles, cleanup, run_id):
    exact(roles, {"run_id": run_id, "master_uid": 0, "worker_uid": 65534}, "actual root/nobody roles")
    pids = [roles.get(name) for name in ("master_pid", "worker_pid")]
    require(all(type(pid) is int and pid > 0 for pid in pids) and pids[0] != pids[1], "distinct actual master/worker PIDs required")
    exact(cleanup, {"run_id": run_id, "master_pid": pids[0], "worker_pid": pids[1], "verified": True,
                    "master_running": False, "worker_running": False, "listener_open": False}, "actual bounded cleanup")


def projection_and_config(receipt, raw, case_id, run_id, sources):
    config = raw["nginx.conf"]
    require(re.findall(rb'\bload_module\s+"([^"\r\n]+)"\s*;', config)
            and re.findall(rb'\bload_module\s+"([^"\r\n]+)"\s*;', config)[0].endswith(b"/nginx-module.so"), "actual snapshotted module configuration required")
    require(re.findall(rb'\buser\s+([^;]+);', config) == [b"nobody nogroup"]
            and re.findall(rb'\bworker_processes\s+([^;]+);', config) == [b"1"]
            and re.findall(rb'\bdaemon\s+([^;]+);', config) == [b"off"]
            and re.findall(rb'\bmodsecurity\s+([^;]+);', config) == [b"on"], "closed owned native host configuration required")
    if case_id in RAW_CASES:
        return
    parent_field = "docroot_projection_parent" if case_id in PHASE4_CASES | MIME_CASES | EVENT_CASES else "projection_parent"
    root_field = "docroot_projection_root" if case_id in PHASE4_CASES | MIME_CASES | EVENT_CASES else "projection_root"
    parent_value, root_value = receipt.get(parent_field), receipt.get(root_field)
    require(isinstance(parent_value, str) and isinstance(root_value, str), "actual projection binding required")
    parent, root = Path(parent_value), Path(root_value)
    require(parent.is_absolute() and root.is_absolute() and ".." not in parent.parts and ".." not in root.parts
            and root.parent == parent and root != Path("/"), "projection must be an exact direct child")
    token = hashlib.sha256((run_id + ":" + case_id).encode()).hexdigest()
    expected = "sequence-" + token[:24] if case_id in SEQUENCE_CASES else "common-input-" + token[:32] if case_id in INPUT_CASES else run_id
    require(root.name == expected, "projection does not bind the actual driver run/case")
    for source in (sources["parent_root"], sources["framework_root"]):
        require(root != source and source not in root.parents and root not in source.parents, "projection overlaps source authority")
    require(re.findall(rb'\broot\s+"([^"\r\n]+)"\s*;', config) == [str(root).encode()], "configured docroot differs from actual projection")
    # No stat of arbitrary external paths is performed from receipt claims.
    # Fresh creation is the authenticated producer's prepare_projection contract;
    # the closed direct-child/run binding rejects cross-case and E child reuse.


def producer_fields(receipt, case_id, source_bytes):
    if case_id not in PHASE4_CASES | MIME_CASES | EVENT_CASES:
        return
    runtime = "parent:ci/runtime/lifecycle/run-nginx-phase4-cases.py"
    helper = "framework:tests/runners/" + ("nginx_phase4_contracts" if case_id in PHASE4_CASES else route(case_id)[1]) + ".py"
    exact(receipt, {"driver_sha256": digest(source_bytes[runtime]),
                    "closed_inputs_sha256": digest(source_bytes[helper])}, "actual runtime/input source bytes")
    upstream = "parent:ci/runtime/common/nginx_phase4_upstream.py"
    if case_id in MIME_CASES:
        upstream = "parent:ci/runtime/lifecycle/run-nginx-mime-cases.py"
        exact(receipt, {"backend_contract_sha256": digest(source_bytes["parent:ci/runtime/common/response-header-test-backend.py"]),
                        "backend_omission_contract_sha256": digest(source_bytes["parent:ci/runtime/common/response_fixture_omission.py"])}, "actual backend source bytes")
    elif case_id in EVENT_CASES:
        upstream = "parent:ci/runtime/lifecycle/run-nginx-event-boundary-cases.py"
    exact(receipt, {"upstream_driver_sha256": digest(source_bytes[upstream])}, "actual upstream source bytes")


def build_artifacts(receipt, raw, case_id, sources, source_bytes):
    if case_id in INPUT_CASES | SEQUENCE_CASES | RAW_CASES:
        require_leaves(raw, {"no-crs-baseline.conf"})
        rules = source_bytes["framework:tests/rules/no-crs-baseline.conf"]
        if case_id in {"engine_timeout_before_commit", "engine_timeout_after_commit"}:
            rules += b"\n# Technical soft-budget probe has no rule-deny premise.\nSecRuleRemoveById 1100301\n"
        require(raw["no-crs-baseline.conf"] == rules, "effective snapshotted rules differ from authenticated source")
    if case_id in INPUT_CASES | set(FAULT_SOURCES):
        leaf = "native-input-fault.so" if case_id in INPUT_CASES else {
            "nginx_transaction_fault.c": "native-transaction-fault.so", "nginx_finish_fault.c": "native-finish-fault.so",
            "nginx_write_fault.c": "native-write-fault.so", "nginx_engine_budget_fault.c": "native-budget-fault.so"}[FAULT_SOURCES[case_id]]
        expected = sources.get("fault_library_sha256", {}).get(case_id)
        require(isinstance(expected, str) and SHA256.fullmatch(expected) and leaf in raw and digest(raw[leaf]) == expected,
                "explicit actual compiled fault artifact authority required")


def cleanup_events(events, transactions, native_completed=1, error_class="none", uris=None):
    for transaction in transactions:
        rows = [event for event in events if event.get("event") == "transaction_cleanup" and event.get("transaction_id") == transaction]
        require(len(rows) == 1, "one actual transaction cleanup source event required")
        event = rows[0]
        cleanup_index = events.index(event)
        require(not any(later.get("transaction_id") == transaction for later in events[cleanup_index + 1:]),
                "actual native transaction work must precede cleanup")
        if uris is not None:
            require(event.get("uri") == uris[transaction], "actual cleanup request URI mismatch")
        exact(event, {"connector": "nginx", "integration_mode": MODE, "phase": "logging", "message_id": "MSCONN_TRANSACTION_CLEANUP",
                      "rule_id": "", "status": "ok", "action": "allow", "actual_action": "allow"}, "actual cleanup source classification")
        require(event.get("reason") == "common_return=0;common_complete=1;native_cleanup_completed=" + str(native_completed) + ";error_class=" + error_class,
                "actual successful Common/native cleanup facts required")
        require(event.get("cleanup_reason") == ("normal" if error_class == "none" else error_class), "cleanup taxonomy mismatch")


# The actual Common serializer emits flat strings in its 256-byte safe field
# buffers, JSON booleans for flags, unsigned counters and integer HTTP status.
# These are source scalars, not permissive canonical coercion inputs.
EVENT_STRING_FIELDS = frozenset("timestamp level message_id message event connector integration_mode run_id transport_case_id transaction_id phase status action requested_action actual_action transport_result http_reason_phrase http_default_message rule_id reason method uri client_ip content_type body_limit_outcome late_intervention_mode requested_protocol downstream_protocol upstream_protocol negotiated_protocol transport alpn stream_id connection_id quic_version stream_reset_code reset_by reset_code timeout_stage write_result cleanup_reason".split())
EVENT_BOOLEAN_FIELDS = frozenset("late_intervention response_started response_committed headers_sent body_started body_truncated connection_aborted client_disconnected upstream_disconnected cancelled eos_seen redacted truncated connection_reused quic_connection_id_present fallback_used stream_reset".split())
EVENT_COUNTER_FIELDS = frozenset("body_bytes_seen body_bytes_inspected sequence previous_event_hash event_hash".split())
EVENT_HTTP_FIELDS = frozenset({"http_status", "original_http_status", "visible_http_status"})
EVENT_PHASES = frozenset({"connection", "uri", "request_headers", "request_body", "response_headers", "response_body", "logging"})


def native_event_shape(event):
    fields = EVENT_STRING_FIELDS | EVENT_BOOLEAN_FIELDS | EVENT_COUNTER_FIELDS | EVENT_HTTP_FIELDS
    require(set(event) <= fields, "unknown native source event field")
    require({"event", "message_id", "connector", "integration_mode", "transaction_id", "phase", "status", "rule_id"} <= set(event),
            "actual native event identity/phase/status fields required")
    for field, value in event.items():
        if field in EVENT_STRING_FIELDS:
            require(type(value) is str and "\x00" not in value and len(value.encode("utf-8")) <= 255,
                    "bounded actual source string required: " + field)
        elif field in EVENT_BOOLEAN_FIELDS:
            require(type(value) is bool, "actual source boolean required: " + field)
        else:
            limit = 999 if field in EVENT_HTTP_FIELDS else (1 << 64) - 1
            require(type(value) is int and 0 <= value <= limit, "bounded actual source integer required: " + field)
    require(event["phase"] in EVENT_PHASES, "actual source phase name required")
    require(event["status"] in {"ok", "blocked", "error", "unsupported"}, "actual source status name required")


def actual_events(raw, leaf):
    require_leaves(raw, {leaf})
    require(all(len(line) + 1 <= 8192 for line in raw[leaf].splitlines() if line.strip()), "bounded native JSONL records required")
    events = json_lines(raw[leaf])
    forbidden = re.compile(r"payload|password|secret|authorization|cookie|request_body|response_body|raw_query", re.IGNORECASE)
    for event in events:
        exact(event, {"connector": "nginx", "integration_mode": MODE}, "actual native event producer")
        require(isinstance(event.get("rule_id"), str) and isinstance(event.get("transaction_id"), str)
                and isinstance(event.get("event"), str) and isinstance(event.get("message_id"), str), "actual native event identity/rule fields required")
        require(not any(forbidden.search(key) or key in {"data", "metadata", "query", "query_string"} for key in event), "native event contains forbidden payload/secret metadata")
        require(not any(isinstance(value, (dict, list)) for value in event.values()), "native event must retain flat bounded metadata")
        native_event_shape(event)
    return events


def validate_raw_h1(helper, receipt, raw, case_id, run_id):
    require_leaves(raw, {"fault-request.bin", "fault-response.bin", "control-request.bin", "control-response.bin", "access.jsonl",
                         "nginx-error.log", "native-events.jsonl", "roles.json", "cleanup.json", "stdout.log", "stderr.log", "startup.stdout", "startup.stderr"})
    exact(receipt, {"schema_version": 1, "connector": "nginx", "integration_mode": MODE, "configtest_exit_code": 0,
                    "host_observation_valid": True, "failure": None}, "actual raw H1 receipt")
    roles, cleanup = json_object(raw["roles.json"]), json_object(raw["cleanup.json"])
    observed_roles(roles, cleanup, run_id)
    control_run = run_id[:119] + "-control"
    require(raw["fault-request.bin"] == helper.request_bytes(case_id, run_id)
            and raw["control-request.bin"] == helper.request_bytes(case_id, control_run, control=True), "actual closed wire request mismatch")
    accesses = json_lines(raw["access.jsonl"])
    fault = [row for row in accesses if row.get("uri") == helper.request_path(case_id, run_id)]
    control = [row for row in accesses if row.get("uri") == helper.request_path(case_id, control_run)]
    require(len(fault) == len(control) == 1, "one actual fault and positive control access required")
    errors = helper.validate_host_rejection(case_id, run_id, raw["fault-response.bin"], fault[0], raw["nginx-error.log"])
    require(not errors, "; ".join(errors))
    require(helper.response_status(raw["control-response.bin"]) == 200 and control[0].get("status") == 200, "positive H1 control must remain successful")
    for name, status in (("fault", 400), ("control", 200)):
        exact(receipt.get("requests", {}).get(name), {"client_exit_code": 0, "http_status": status}, "actual raw client " + name)
    events = actual_events(raw, "native-events.jsonl")
    require(not any(event.get("uri") == helper.request_path(case_id, run_id) for event in events), "preconnector rejected request must not admit native events")
    control_transactions = sorted({event["transaction_id"] for event in events
                                   if event.get("uri") == helper.request_path(case_id, control_run)})
    # The real default module mapper uses connection/request numbers, not a
    # request_id SHA. Read its actual event identity rather than inventing one.
    require(len(control_transactions) == 1 and RUN_ID.fullmatch(control_transactions[0]),
            "actual native positive control transaction required")
    cleanup_events(events, control_transactions, uris={control_transactions[0]: helper.request_path(case_id, control_run)})
    return {"events": [], "all_native_events": events, "transaction_ids": [], "actual_status": 400}


def validate_input(helper, receipt, raw, case_id, run_id):
    require_leaves(raw, {"native-access.jsonl", "native-input-fault.jsonl", "phase1-events.jsonl", "worker-maps.log", "nginx-error.log",
                         "configtest.stdout", "configtest.stderr", "client.stdout", "client.stderr", "startup.stdout", "startup.stderr"})
    exact(receipt, {"configtest_exit_code": 0}, "actual input configtest")
    observed = json_object(raw["input-fault-observation.json"])
    errors = helper.observation_errors(observed, case_id, run_id)
    require(not errors, "; ".join(errors))
    require(json_lines(raw["native-access.jsonl"]) == [observed["native_access"]]
            and json_lines(raw["native-input-fault.jsonl"]) == [observed["native_fault"]], "actual fault/access ledger projection mismatch")
    events = actual_events(raw, "phase1-events.jsonl")
    protocol = [event for event in events if event.get("phase") in (1, "1", "request_headers") and event.get("event") == "protocol_error"]
    require(protocol == observed["native_events"], "actual native protocol event projection mismatch")
    require(len(events) == 2 and events[0] == protocol[0] and events[1].get("event") == "transaction_cleanup",
            "terminal P1 mapper failure permits only its protocol error then cleanup source event")
    exact(events[0], {"transaction_id": observed["transaction_id"], "uri": observed["native_access"]["uri"]},
          "actual terminal mapper source identity")
    require(re.findall(rb'\bmodsecurity_transaction_id\s+"([^"\r\n]+)"\s*;', raw["nginx.conf"]) == [observed["transaction_id"].encode()], "actual configured mapper transaction differs from native ledger")
    require(observed["native_diagnostic"].encode() in raw["nginx-error.log"] and raw["client.stdout"] == b"400"
            and raw["client.stderr"] == b"", "actual diagnostic/client bytes mismatch")
    cleanup_events(events, [observed["transaction_id"]], error_class="protocol_error",
                   uris={observed["transaction_id"]: observed["native_access"]["uri"]})
    observed_roles(observed["roles"], observed["cleanup"], run_id)
    return {"events": events, "transaction_ids": [observed["transaction_id"]], "actual_status": 400, "observation": observed}


def validate_configtest(receipt, raw, case_id):
    exit_field = "observed_exit_code" if case_id in SEQUENCE_CASES else "configtest_exit_code"
    exact(receipt, {exit_field: 0}, "actual configtest outcome")
    leaf = "stderr.log" if case_id in RAW_CASES else "configtest.stderr"
    require_leaves(raw, {leaf, "stdout.log" if case_id in RAW_CASES else "configtest.stdout", "startup.stdout", "startup.stderr"})
    modules = re.findall(rb'\bload_module\s+"([^"\r\n]+)"\s*;', raw["nginx.conf"])
    require(len(modules) == 1, "one actual module load required")
    configuration_path = modules[0].rsplit(b"/", 1)[0] + b"/nginx.conf"
    require(configuration_path in raw[leaf] and b"syntax is ok" in raw[leaf] and b"test is successful" in raw[leaf], "actual successful configtest diagnostics must bind configuration")
    if "worker-maps.log" in raw:
        require(modules[0] in raw["worker-maps.log"]
                and modules[0].rsplit(b"/", 1)[0] + b"/nginx-binary" in raw["worker-maps.log"], "actual worker mappings do not bind snapshots")


def native_error(events, name, message_id, phase, transaction, path):
    rows = [event for event in events if event.get("event") == name and event.get("transaction_id") == transaction]
    require(len(rows) == 1, "one actual source technical error required: " + name)
    exact(rows[0], {"connector": "nginx", "integration_mode": MODE, "message_id": message_id, "phase": phase,
                    "rule_id": "", "status": "error", "uri": path}, "actual technical error source")


def sequence_fault_ledgers(observed, raw):
    for leaf, field in (("native-write-observations.jsonl", "native_writes"), ("native-finish-observations.jsonl", "native_finish")):
        if field in observed:
            require_leaves(raw, {leaf})
            require(json_lines(raw[leaf]) == observed[field], "actual sequence fault ledger projection mismatch")
    if "native_budget" in observed:
        require_leaves(raw, {"native-budget-observations.jsonl"})
        ledger = json_lines(raw["native-budget-observations.jsonl"])
        require([item for item in ledger if item.get("native_operation") != "msconnector_transaction_contract_cleanup"] == observed["native_budget"]
                and [item for item in ledger if item.get("native_operation") == "msconnector_transaction_contract_cleanup"] == observed["native_cleanup"], "actual timing/cleanup ledger projection mismatch")


def sequence_wire(observed, raw):
    for field, leaf in (("wire", "response-wire.bin"),):
        if field in observed:
            require_leaves(raw, {leaf, "request-wire.bin"})
            require(raw[leaf] == bytes.fromhex(observed[field]["response_hex"])
                    and raw["request-wire.bin"] == bytes.fromhex(observed[field]["request_hex"]), "actual downstream wire projection mismatch")
    if "upstream_wire" in observed:
        require(raw["upstream-request-wire.bin"] == bytes.fromhex(observed["upstream_wire"]["request_hex"])
                and raw["upstream-response-wire.bin"] == bytes.fromhex(observed["upstream_wire"]["response_hex"]), "actual upstream wire projection mismatch")


def sequence_denials(observed, accesses, events):
    for request, access in zip(observed["requests"], accesses):
        if request["observed_status"] == 403:
            deny = [event for event in events if event.get("transaction_id") == access["transaction_id"]
                    and event.get("uri") == request["path"] and event.get("status") == "blocked"]
            require(len(deny) == 1, "actual native request deny must bind rule1100001 and request transaction")
            # Common's actual protocol view serializes an intervention with
            # no host observation as engine_decision, not the source struct's
            # phase1_intervention. A non-disruptive rule_match cannot prove it.
            exact(deny[0], {"event": "engine_decision", "message_id": "MSCONN_EVENT_ENGINE_DECISION",
                            "phase": "request_headers", "status": "blocked", "action": "deny",
                            "requested_action": "deny", "actual_action": "", "rule_id": "1100001",
                            "http_status": 403, "visible_http_status": 0, "transport_result": "not_observable",
                            "connector": "nginx", "integration_mode": MODE},
                  "actual native request denial source fields")


def sequence_cleanup(case_id, observed, accesses, events, raw):
    transactions = [item["transaction_id"] for item in accesses]
    uris = {item["transaction_id"]: item["uri"] for item in accesses}
    if case_id == "early_mapping_failure_cleanup":
        native_error(events, "protocol_error", "MSCONN_EVENT_PROTOCOL_ERROR", "request_headers", "", observed["requests"][0]["path"])
        exact(next(event for event in events if event.get("event") == "protocol_error"), {"http_status": 500}, "actual pre-admission error status")
        require(not any(event.get("event") == "transaction_cleanup" for event in events), "pre-admission mapping failure must not invent transaction cleanup")
        transactions = []
    elif case_id == "transaction_begin_failure_cleanup":
        native_error(events, "connector_error", "MSCONN_EVENT_CONNECTOR_ERROR", "request_headers", transactions[0], observed["requests"][0]["path"])
        exact(next(event for event in events if event.get("event") == "connector_error"), {"http_status": 500}, "actual allocation error status")
        cleanup_events(events, transactions, native_completed=0, error_class="connector_error", uris=uris)
        require_leaves(raw, {"native-begin-observations.jsonl"})
        ledger = json_lines(raw["native-begin-observations.jsonl"])
        require(ledger == observed.get("native_begin") and len(ledger) == 1, "actual scoped native allocation ledger required")
        require(set(ledger[0]) == {"native_operation", "observed_return", "worker_pid", "worker_uid", "master_pid", "transaction_id", "injected"},
                "closed native allocation ledger fields required")
        exact(ledger[0], {"native_operation": "msc_new_transaction_with_id", "observed_return": None,
                          "worker_pid": observed["roles"]["worker_pid"], "worker_uid": 65534,
                          "master_pid": observed["roles"]["master_pid"], "transaction_id": transactions[0], "injected": True}, "actual native NULL return scope")
    else:
        error_class = "engine_timeout" if case_id in {"engine_timeout_before_commit", "engine_timeout_after_commit"} else "invalid_engine_response" if case_id == "finish_failure_propagation" else "none"
        cleanup_events(events, transactions, error_class=error_class, uris=uris)
        if case_id == "finish_failure_propagation":
            native_error(events, "invalid_engine_response", "MSCONN_EVENT_INVALID_ENGINE_RESPONSE", "logging", transactions[0], observed["requests"][0]["path"])
            exact(next(event for event in events if event.get("event") == "invalid_engine_response"),
                  {"http_status": 0, "original_http_status": 200, "visible_http_status": 200}, "actual post-response finish status")
    return transactions


def validate_sequence(helper, receipt, raw, case_id, run_id):
    require_leaves(raw, {"worker-maps.log"})
    observed = json_object(raw["sequence-observation.json"])
    errors = helper.observation_errors(observed, case_id, run_id)
    require(not errors, "; ".join(errors))
    observed_roles(observed["roles"], observed["cleanup"], run_id)
    accesses = json_lines(raw["native-access.jsonl"])
    require(accesses == observed["native_access"], "actual sequence access projection mismatch")
    events = actual_events(raw, "phase1-events.jsonl")
    if "native_events" in observed:
        require(events == observed["native_events"], "actual sequence native event projection mismatch")
    sequence_fault_ledgers(observed, raw)
    sequence_wire(observed, raw)
    sequence_denials(observed, accesses, events)
    transactions = sequence_cleanup(case_id, observed, accesses, events, raw)
    return {"events": events, "transaction_ids": transactions, "actual_status": observed["requests"][0]["observed_status"],
            "actual_statuses": [request["observed_status"] for request in observed["requests"]], "observation": observed}


def bundle_envelope(record):
    require(isinstance(record, dict), "native source record required")
    case_id, run_id = record.get("case_id"), record.get("run_id")
    operation, _ = route(case_id)
    require(isinstance(run_id, str) and RUN_ID.fullmatch(run_id), "bounded outer run identity required")
    exact(record, {"connector": "nginx", "integration_mode": MODE, "operation": operation, "driver_exit_code": 0}, "native source invocation")
    for field in ("protocol", "downstream_protocol", "requested_protocol"):
        if field in record:
            require(record[field] in ("http1", "http1.1", "HTTP/1.1"), "H2/H3/fallback source cannot satisfy native H1 operations")
    envelope = record.get("native_operation_receipt")
    exact(envelope, {"schema_version": 1, "case_id": case_id, "run_id": run_id, "operation": operation, "integration_mode": MODE}, "native bundle envelope")
    allowed = {"schema_version", "case_id", "run_id", "operation", "integration_mode", "bundle_root", "invocations", "source_sha256"}
    if case_id in PHASE4_CASES:
        allowed.add("source_record_id")
    if case_id in EVENT_CASES:
        allowed.update({"parent_receipt_path", "parent_receipt_sha256"})
    require(set(envelope) <= allowed, "unknown native bundle envelope fields")
    return case_id, run_id, operation, envelope


def invocation_artifacts(reader, envelope, case_id, run_id, operation, sources, source_bytes):
    descriptors = envelope.get("invocations")
    names = ["at", "over"] if case_id == "event_json_limit" else ["main"]
    require(isinstance(descriptors, list) and len(descriptors) == len(names), "closed invocation count mismatch")
    receipts, raws, originals = {}, {}, {}
    for descriptor, name in zip(descriptors, names):
        require(isinstance(descriptor, dict) and set(descriptor) == {"name", "receipt_path", "receipt_sha256"}
                and descriptor.get("name") == name and isinstance(descriptor.get("receipt_sha256"), str)
                and SHA256.fullmatch(descriptor["receipt_sha256"]), "closed invocation descriptor/seal mismatch")
        receipt, raw, original = read_invocation(reader, descriptor, case_id, operation, sources)
        variant = "at255" if name == "at" else "over256" if name == "over" else "long-query" if case_id in EVENT_CASES else None
        expected_run = run_id + "-" + variant if variant else run_id
        require(receipt["run_id"] == expected_run, "original invocation run differs from enclosing run")
        if variant:
            require(descriptor["receipt_path"] == variant + "/source-result.json", "actual fixed child receipt path required")
        if "source_record_id" in envelope:
            require(receipt.get("source_record_id") == envelope["source_record_id"], "actual source record alias mismatch")
        projection_and_config(receipt, raw, case_id, expected_run, sources)
        validate_configtest(receipt, raw, case_id)
        build_artifacts(receipt, raw, case_id, sources, source_bytes)
        producer_fields(receipt, case_id, source_bytes)
        receipts[name], raws[name], originals[name] = receipt, raw, original
    return names, receipts, raws, originals


def validate_phase4_layer(helper, receipt, raw, case_id, run_id):
    validator = helper.validate_phase4_operation if case_id in PHASE4_CASES else helper.validate_mime_operation
    errors = validator(case_id, receipt, raw)
    require(not errors, "; ".join(errors))
    observed_roles(receipt.get("roles"), receipt.get("cleanup"), run_id)
    require(raw["response.headers"].startswith(b"HTTP/1.1 "), "actual downstream HTTP1.1 required")
    events = actual_events(raw, "phase4-events.jsonl")
    transactions = sorted({event["transaction_id"] for event in receipt["native_events"]})
    cleanup_events(events, transactions, error_class="body_limit" if case_id == "phase4_body_reject" else "none",
                   uris={event["transaction_id"]: event["uri"] for event in receipt["native_events"]})
    return {"events": events, "transaction_ids": transactions, "actual_status": receipt["observed_http_status"]}


def validate_event_layer(reader, envelope, helper, case_id, run_id, sources, source_bytes, names, receipts, raws, originals):
    require(envelope.get("parent_receipt_path") == "source-result.json"
                and isinstance(envelope.get("parent_receipt_sha256"), str) and SHA256.fullmatch(envelope["parent_receipt_sha256"]), "sealed original E parent receipt required")
    receipt = json_object(reader.read("source-result.json", envelope["parent_receipt_sha256"]))
    exact(receipt, {"case_id": case_id, "run_id": run_id, "parent_sha": sources["parent_sha"], "framework_sha": sources["framework_sha"], "mrts_sha": sources["mrts_sha"]}, "actual E enclosing source")
    exact(receipt, {"driver_sha256": digest(source_bytes["parent:ci/runtime/lifecycle/run-nginx-event-boundary-cases.py"]),
                        "closed_inputs_sha256": digest(source_bytes["framework:tests/runners/nginx_event_boundary_operations.py"])}, "actual E enclosing producer")
    expected_dependencies = {name + ".py": digest(source_bytes["framework:tests/runners/" + name + ".py"])
                                 for name in ("nginx_common_input_faults", "nginx_mime_operations")}
    require(receipt.get("closed_input_dependencies_sha256") == expected_dependencies, "actual E dependency source mismatch")
    variants = ("at255", "over256") if case_id == "event_json_limit" else ("long-query",)
    children = {variant: {"receipt_bytes": originals[name], "raw_artifacts": raws[name]} for variant, name in zip(variants, names)}
    errors = helper.validate_event_boundary_operation(case_id, receipt, children)
    require(not errors, "; ".join(errors))
    events, transactions = [], []
    for name in names:
        child_events = actual_events(raws[name], "phase4-events.jsonl")
        child_transactions = sorted({event["transaction_id"] for event in receipts[name]["native_events"]})
        cleanup_events(child_events, child_transactions,
                       uris={event["transaction_id"]: event["uri"] for event in receipts[name]["native_events"]})
        require(not set(child_transactions) & set(transactions), "E children reused actual transaction")
        events.extend(child_events)
        transactions.extend(child_transactions)
    return receipt, {"events": events, "transaction_ids": transactions, "actual_status": 200}


def _validate_native_operation_bundle(record, authority: Path, sources: dict, canonical=False):
    """Validate one sealed operation layer; never canonical PASS or trusted build.

    Sources are explicit coordinator authority, not receipt paths or discovered
    Git history. Files seal retained bytes for a caller that reopens/compares
    them when copying. Canonical never relaxes checks or promotes status.
    """
    case_id, run_id, operation, envelope = bundle_envelope(record)
    source_bytes = verify_source_authority(record, envelope, sources)
    reader = BundleReader(authority, envelope.get("bundle_root"))
    helper = load_helpers(case_id, source_bytes, sources["framework_root"])
    names, receipts, raws, originals = invocation_artifacts(reader, envelope, case_id, run_id, operation, sources, source_bytes)
    receipt, raw = receipts[names[0]], raws[names[0]]
    if case_id in EVENT_CASES:
        receipt, facts = validate_event_layer(reader, envelope, helper, case_id, run_id, sources, source_bytes, names, receipts, raws, originals)
    else:
        validators = {"native_h1_parser_rejection": validate_raw_h1, "common_mapper_input_fault": validate_input,
                      "request_sequence": validate_sequence, "native_phase4_request": validate_phase4_layer}
        facts = validators[operation](helper, receipt, raw, case_id, run_id)
    # Recheck source bytes after helper execution; concurrent source changes must
    # not produce a successful proof under a stale producer seal.
    verify_source_authority(record, envelope, sources)
    return {"case_id": case_id, "run_id": run_id, "operation": operation, "errors": [], "layer_verified": True,
            "receipt": receipt, "invocation_receipts": receipts, "raw_artifacts": raws,
            "bundle_root": reader.root, "files": reader.files, **facts}


def validate_native_operation_bundle(record, authority: Path, sources: dict, canonical=False):
    """Public fail-closed reader. See implementation docstring for proof limits."""
    try:
        return _validate_native_operation_bundle(record, authority, sources, canonical)
    except (OSError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError, ImportError, SyntaxError) as exc:
        raise ValueError("invalid native operation bundle: " + str(exc)) from exc
