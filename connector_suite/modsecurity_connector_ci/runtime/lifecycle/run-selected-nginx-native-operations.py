#!/usr/bin/env python3
"""Dispatch exactly 42 selected native contracts; never generate PASS."""
from __future__ import annotations
from modsecurity_test_framework.connector_context import load_source, connector_root

import importlib.util
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = connector_root()
SOURCE = load_source(HERE / 'nginx-native-operation-source.py')
PROJECTION = load_source(HERE.parent / 'common/prepare-nginx-docroot-projection.py')
RAW = frozenset({"invalid_content_length", "conflicting_content_length",
                 "duplicate_transfer_encoding", "content_length_overflow"})
POINTER = frozenset({"header_count_nonzero_with_null_headers", "body_size_nonzero_with_null_data"})
PHASE4 = frozenset({"phase4_marker_split_across_chunks", "phase4_end_of_stream_evaluation",
    "phase4_deny_after_commit_log_only_minimal", "phase4_body_at_limit", "phase4_body_over_limit",
    "phase4_body_process_partial", "phase4_body_reject", "full_lifecycle_event_metadata_bounded"})
MIME = frozenset({"phase4_in_scope_content_type", "phase4_content_type_with_charset",
                  "phase4_out_of_scope_content_type", "phase4_missing_content_type"})
SEQUENCES = frozenset({"single_request_cleanup", "multiple_sequential_requests",
    "keep_alive_requests_if_supported", "clean_shutdown", "keepalive_allow_allow",
    "keepalive_allow_deny_allow", "early_mapping_failure_cleanup", "transaction_begin_failure_cleanup",
    "phase4_strict_http1_client_abort", "phase4_strict_host_survives",
    "phase4_strict_followup_request_succeeds", "keepalive_after_strict_new_connection",
    "keepalive_safe_followup", "response_short_write_resume", "response_write_would_block_resume",
    "transport_keep_alive", "transport_sequential_requests", "finish_failure_propagation",
    "engine_timeout_before_commit", "engine_timeout_after_commit",
    "transport_http11_content_length", "transport_http11_chunked"})
EVENTS = frozenset({"event_metadata_truncation", "event_json_limit"})
GROUPS = {"native_h1_parser_rejection": RAW, "common_mapper_input_fault": POINTER,
          "native_phase4_request": PHASE4 | MIME, "request_sequence": SEQUENCES,
          "native_event_boundary_request": EVENTS}
CONTRACTS = {case: {"operation": operation, "contract_case_id": case}
             for operation, cases in GROUPS.items() for case in cases}
for case, source in SOURCE.ALIASES.items():
    CONTRACTS[case]["source_record_id"] = source
OVERRIDES = {
    **{case: {"expected_status": 500} for case in POINTER},
    "body_size_nonzero_with_null_data": {"phase": 1, "expected_status": 500},
    "finish_failure_propagation": {"expected_status": 200},
    "clean_shutdown": {"expected_status": 200},
    "phase4_deny_after_commit_log_only_minimal": {"expected_status": 200,
        "expected_result": "late_intervention_log_only_safe", "nginx_phase4_mode": "safe"},
    **{case: {"expected_status": 200, "expected_rule_id": None}
       for case in ("phase4_out_of_scope_content_type", "phase4_missing_content_type")},
    "phase4_body_reject": {"expected_status": 200, "expected_rule_id": None,
        "expected_native_status": 403, "expected_engine_error_class": "body_limit"},
    **{case: {"expected_status": 504 if case.endswith("before_commit") else 200,
              "expected_rule_id": None, "expected_native_status": 504,
              "expected_engine_error_class": "engine_timeout"}
       for case in ("engine_timeout_before_commit", "engine_timeout_after_commit")},
    "engine_timeout_before_commit": {"phase": 1, "expected_status": 504, "expected_rule_id": None,
        "expected_native_status": 504, "expected_engine_error_class": "engine_timeout"},
}
for case, override in OVERRIDES.items():
    CONTRACTS[case]["expected_overrides"] = override
FAULT_ENV = {**dict.fromkeys(POINTER, "NGX_NATIVE_INPUT_FAULT_LIBRARY"),
    "transaction_begin_failure_cleanup": "NGX_NATIVE_BEGIN_FAULT_LIBRARY",
    "finish_failure_propagation": "NGX_NATIVE_FINISH_FAULT_LIBRARY",
    **dict.fromkeys(("response_short_write_resume", "response_write_would_block_resume"),
                    "NGX_NATIVE_WRITE_FAULT_LIBRARY"),
    **dict.fromkeys(("engine_timeout_before_commit", "engine_timeout_after_commit"),
                    "NGX_NATIVE_ENGINE_BUDGET_FAULT_LIBRARY")}
SCRIPT_BY_CASE = {
    case: script
    for cases, script in (
        (RAW, "run-nginx-raw-h1.py"),
        (POINTER, "run-nginx-common-input-fault.py"),
        (MIME, "run-nginx-mime-cases.py"),
        (PHASE4, "run-nginx-phase4-cases.py"),
        (SEQUENCES, "run-nginx-lifecycle-sequences.py"),
        (EVENTS, "run-nginx-event-boundary-cases.py"),
    )
    for case in cases
}


def has_native_descriptor(record, case):
    descriptor = record.get("native_invocations", {}).get("nginx")
    if descriptor is None:
        if case in CONTRACTS:
            raise ValueError("selected native case lacks its required registry descriptor")
        return False  # Existing52 and configuration3 remain other owners' work.
    if case not in CONTRACTS or json.dumps(descriptor, sort_keys=True) != json.dumps(CONTRACTS[case], sort_keys=True):
        raise ValueError("catalog native invocation differs from the closed host contract")
    return True


def selected_invocations(records, selected):
    if len(selected) != len(set(selected)) or any(
            not re.fullmatch(r"[a-z][a-z0-9_]{0,127}", case) for case in selected):
        raise ValueError("selected case IDs must be unique and path-safe")
    found, catalog_ids = [], set()
    for record in records:
        case = record["case_id"]
        if case in catalog_ids:
            raise ValueError("duplicate catalog case identity")
        catalog_ids.add(case)
        if case not in selected:
            continue
        if has_native_descriptor(record, case):
            found.append(case)
    if (set(selected) & set(CONTRACTS)) - set(found):
        raise ValueError("selected native case missing from registry")
    return found


def fault_arguments(case, environment):
    if case not in FAULT_ENV:
        return []
    library = environment.get(FAULT_ENV[case])
    if not library or not Path(library).is_absolute():
        raise ValueError("required native fault library missing: " + FAULT_ENV[case])
    return ["--fault-library", library]


def command(case, paths, run_id, identities, environment):
    if case not in CONTRACTS:
        raise ValueError("unknown native case")
    script = SCRIPT_BY_CASE[case]
    args = [sys.executable, str(HERE / script), "--case-id", case,
            "--nginx-binary", str(paths["prefix"] / "sbin/nginx"),
            "--module", str(paths["prefix"] / "modules/ngx_http_modsecurity_module.so"),
            "--output-root", str(paths["output"]), "--run-id", run_id,
            "--framework-root", str(paths["framework"])]
    for key in ("parent_sha", "framework_sha", "mrts_sha"):
        args += ["--" + key.replace("_", "-"), identities[key]]
    if case not in RAW:
        args += ["--projection-parent", str(paths["projection"])]
    if environment.get("MODSECURITY_LIB_DIR"):
        args += ["--library-dir", environment["MODSECURITY_LIB_DIR"]]
    args += fault_arguments(case, environment)
    return args


def identity(root, expression):
    result = subprocess.run(["git", "-C", str(root), "rev-parse", expression], check=True,
                            capture_output=True, text=True, timeout=10).stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", result):
        raise ValueError("Git identity must be an exact SHA")
    return result


def child(parent, name):
    descriptor = SOURCE.directory(parent)
    try:
        os.mkdir(name, 0o700, dir_fd=descriptor)  # Fresh only; never reuse retained runtime state.
    finally:
        os.close(descriptor)
    return parent / name


def safe_build(build, results):
    for path in (build, results):
        if not path.is_absolute() or ".." in path.parts:
            raise ValueError("absolute runtime paths required")
        if any((ancestor / ".git").is_file() or (ancestor / ".git/HEAD").is_file()
               for ancestor in (path, *path.parents) if SOURCE.STORAGE in ancestor.parents):
            raise ValueError("runtime output cannot be in a checkout")
    results.relative_to(build)
    os.close(SOURCE.directory(build))
    os.close(SOURCE.directory(results))


def projection_parent(environment, build, results, framework):
    """Use the existing projection authority; never create or relax its parent."""
    if os.geteuid() != 0:
        raise ValueError("selected native projection requires the actual Root coordinator")
    value = environment.get("NGINX_DOCROOT_PROJECTION_PARENT")
    if not value or ".." in Path(value).parts:
        raise ValueError("explicit absolute traversal-free NGINX projection parent required")
    parent = PROJECTION.normalized_absolute(value, "projection parent")
    os.close(SOURCE.directory(parent, external=False))
    PROJECTION.ensure_private_parent(parent, "projection parent")
    verified = environment.get("VERIFIED_RUN_ROOT")
    if not verified:
        raise ValueError("explicit VERIFIED_RUN_ROOT required for projection separation")
    roots = [ROOT, framework, build, results,
             PROJECTION.normalized_absolute(verified, "verified run root")]
    roots.extend(PROJECTION.normalized_absolute(environment[key], "private runtime root")
        for key in ("CACHE_ROOT", "EVIDENCE_ROOT", "LOG_ROOT", "RUN_ROOT", "CONNECTOR_ROOT",
                    "CONNECTOR_BUILD_ROOT", "REPORTS_DIR") if environment.get(key))
    if any(PROJECTION.overlaps(parent, root) for root in roots):
        raise ValueError("NGINX projection parent overlaps source or private runtime authority")
    return parent


def append_results(result_path, cases, invoke):
    descriptor = SOURCE.directory(result_path.parent)
    try:
        leaf = os.open(result_path.name, os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK,
                       0o600, dir_fd=descriptor)
    finally:
        os.close(descriptor)
    with os.fdopen(leaf, "a+", encoding="utf-8") as stream:
        metadata = os.fstat(stream.fileno())
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) & 0o077
                or metadata.st_size > SOURCE.MAX_BYTES):
            raise ValueError("result stream must be bounded owner-only single-link regular file")
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        stream.seek(0)
        existing = [SOURCE.decode(line) for line in stream if line.strip()]
        if any(row.get("case_id") in cases for row in existing):
            raise ValueError("selected native result already exists")
        failed = False
        for case in cases:
            row = invoke(case)
            raw = json.dumps(row, sort_keys=True) + "\n"
            if os.fstat(stream.fileno()).st_size + len(raw.encode()) > SOURCE.MAX_BYTES:
                raise ValueError("result append exceeds bound")
            stream.write(raw)
            stream.flush()
            failed = failed or row["driver_exit_code"] != 0
        return int(failed)


def run(environment):
    framework = Path(environment["FRAMEWORK_ROOT"])
    catalog = framework / "tests/cases/no-crs-baseline/catalog.json"
    # Versioned catalog is readable source, not an owner-only runtime receipt.
    descriptor = SOURCE.directory(catalog.parent, external=False)
    try:
        leaf = os.open(catalog.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
        with os.fdopen(leaf, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > SOURCE.MAX_BYTES:
                raise ValueError("catalog must be bounded regular source")
            raw = stream.read(SOURCE.MAX_BYTES + 1)
            if len(raw) > SOURCE.MAX_BYTES:
                raise ValueError("catalog exceeds bound")
    finally:
        os.close(descriptor)
    cases = selected_invocations(SOURCE.decode(raw)["cases"], environment.get("NO_CRS_SELECTED_CASE_IDS", "").split())
    if not cases:
        return 0
    run_id = environment["NO_CRS_RUN_ID"]
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,96}", run_id):
        raise ValueError("bounded native run ID required")
    build, results = Path(environment["BUILD_ROOT"]), Path(environment["RESULTS_DIR"])
    safe_build(build, results)
    projections = projection_parent(environment, build, results, framework) if any(case not in RAW for case in cases) else None
    host = build / "host-runtime"
    if not host.exists():
        child(build, "host-runtime")
    os.close(SOURCE.directory(host))
    output = child(host, "native-operations-" + run_id)
    identities = {"parent_sha": identity(ROOT, "HEAD"), "framework_sha": identity(framework, "HEAD"),
                  "mrts_sha": identity(framework, "HEAD:tools/MRTS"),
                  "parent_framework_gitlink": identity(ROOT, "HEAD:modules/ModSecurity-test-Framework")}
    reader_path = framework / "tests/runners/nginx_native_operation_bundle.py"
    # Import only the explicitly owned reader API, never a catalog-selected script.
    SOURCE.source_hashes({"framework:tests/runners/nginx_native_operation_bundle.py"}, ROOT, framework)
    reader = load_source(reader_path)
    prefix = Path(environment["NGINX_PREFIX"])
    if not prefix.is_absolute() or ".." in prefix.parts:
        raise ValueError("absolute NGINX prefix required")
    # Reject missing required fixtures before any actual host invocation.
    for case in cases:
        command(case, {"prefix": prefix, "framework": framework, "output": output / case,
                       "projection": projections}, run_id, identities, environment)
    def invoke(case):
        paths = {"prefix": prefix, "framework": framework, "output": output / case, "projection": projections}
        args = command(case, paths, run_id, identities, environment)
        completed = subprocess.run(args, check=False, timeout=180)
        print(f"nginx native case={case} driver_exit_code={completed.returncode}", file=sys.stderr)
        row = SOURCE.build_source(case, run_id, CONTRACTS[case]["operation"], paths["output"],
                                  identities, completed.returncode, source_sha256=SOURCE.source_hashes(
                                      reader.required_source_paths(case), ROOT, framework))
        return row
    return append_results(results / "nginx-results.jsonl", cases, invoke)


def main():
    try:
        return run(os.environ)
    except (KeyError, ValueError, OSError, subprocess.SubprocessError) as error:
        print("selected native NGINX invocation rejected: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
