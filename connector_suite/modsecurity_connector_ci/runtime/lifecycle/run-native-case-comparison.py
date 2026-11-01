#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

# CI helpers are shared from ci/lib even when this file is executed directly.

from typing import Any

from modsecurity_connector_ci.lib.evidence_inputs import EvidenceInputs
from modsecurity_connector_ci.lib.generated_report_utils import DATA_SOURCE_POLICY, GENERATED_REPORTS, build_metadata, generated_json_text, generated_markdown_text, input_status_summary, report_path
from modsecurity_connector_ci.lib.runtime_path_utils import canonical_project_roots, DEFAULT_RUN_BASENAME, ensure_safe_runtime_directory, fixed_runtime_temp_parent, prepare_verified_runtime_artifact_root, runtime_artifact_path, verified_runtime_paths, write_runtime_artifact_text_atomic

try:
    import yaml
except Exception:  # pragma: no cover - runner reports missing PyYAML.
    yaml = None


DEFAULT_CASES = (
    "unicode_whitespace_normalization_gap",
    "unicode_double_encoded_uri_runtime_difference",
    "xml_namespace_edge_connector_gap",
    "xml_request_body_malformed_connector_gap",
    "v2_transformation_url_decode_invalid_sequence_mapped_candidate",
)
CONNECTORS = ("apache", "nginx", "haproxy")
VARIANTS = ("no-crs/no-mrts", "no-crs/with-mrts", "with-crs/no-mrts", "with-crs/with-mrts")
DEFAULT_VERIFIED_RUN_ROOT = fixed_runtime_temp_parent() / DEFAULT_RUN_BASENAME
NATIVE_CASE_RUN_FILENAME = "native-case-run.json"
NATIVE_ORACLE_SOURCE = Path("ci/tools/native_modsecurity_oracle.c")
NATIVE_RUNNER_PATH = "ci/runtime/lifecycle/run-native-case-comparison.py"
NATIVE_ACTUAL_LABEL = "Native Actual"
NATIVE_RESULT_LABEL = "native result"
GENERATED_MANIFEST_COMPONENTS = ("reports", "testing", "generated", "manifest")
SAFE_REPORT_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")


@dataclass(frozen=True)
class NativeCaseContext:
    """Validated paths and immutable inputs for one native comparison."""

    case: str
    connector_root: Path
    framework_root: Path
    run_root: Path
    run_dir: Path
    logs_dir: Path
    env: dict[str, str]
    started: datetime


@dataclass(frozen=True)
class NativeCaseInputs:
    """Materialized request/rules inputs for the native oracle."""

    request: dict[str, Any]
    rules_path: Path
    request_paths: dict[str, str]
    expected: int


@dataclass(frozen=True)
class NativeOracleExecution:
    """Native oracle result and its observable execution metadata."""

    native_result: dict[str, Any]
    compile_info: dict[str, Any]
    return_code: int
    native_result_path: Path


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_utc(value: datetime) -> str:
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip()).strip("-") or "unknown"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def write_json(root: Path, path: Path, data: dict[str, Any], label: str) -> None:
    """Atomically write a JSON artifact beneath one verified private root."""

    write_runtime_artifact_text_atomic(
        root,
        path,
        json.dumps(data, indent=2, sort_keys=True) + "\n",
        label,
    )


def runtime_component_paths(env: dict[str, str]) -> tuple[Path, Path] | None:
    """Return verified build and component-cache roots when available."""

    try:
        paths = verified_runtime_paths(env)
    except ValueError:
        return None
    return Path(paths["BUILD_ROOT"]), Path(paths["VERIFIED_COMPONENT_CACHE"])


def invocation_runtime_environment(
    build_root: Path,
    report_root_value: str,
    snapshot_value: str,
) -> Path | None:
    """Return the validated invocation-local environment snapshot, if present."""

    if not report_root_value:
        return None
    try:
        report_root = runtime_artifact_path(
            build_root, report_root_value, "runtime report output root"
        )
        if not report_root.is_dir() or report_root.is_symlink():
            return None
        return runtime_artifact_path(
            report_root,
            snapshot_value,
            "runtime environment snapshot",
            must_exist=True,
        )
    except ValueError:
        return None


def shared_runtime_environment(component_cache: Path) -> Path | None:
    """Return the validated compatibility export for direct/report-only callers."""

    try:
        return runtime_artifact_path(
            component_cache,
            component_cache / "runtime-env.sh",
            "shared runtime environment",
            must_exist=True,
        )
    except ValueError:
        return None


def runtime_environment_path(env: dict[str, str]) -> Path | None:
    """Choose the invocation snapshot or direct-caller compatibility export."""

    paths = runtime_component_paths(env)
    if paths is None:
        return None
    build_root, component_cache = paths
    snapshot_value = env.get("RUNTIME_COMPONENT_ENV_SNAPSHOT", "").strip()
    if snapshot_value:
        # The with-runtime wrapper already validates and materializes this
        # file for its exact invocation.  Do not reopen shared/runtime-env.sh
        # here: another target may republish that compatibility export while
        # this native comparison is compiling or running a case.
        report_root_value = env.get("RUNTIME_REPORT_OUTPUT_ROOT", "").strip()
        return invocation_runtime_environment(
            build_root, report_root_value, snapshot_value
        )
    # Retain the documented shared export only for direct/report-only callers
    # that are outside a with-runtime invocation.
    return shared_runtime_environment(component_cache)


def imported_environment(runtime_env: Path) -> dict[str, str] | None:
    """Read exports from one validated shell file without sharing its process."""

    if not runtime_env.is_file() or runtime_env.is_symlink():
        return None
    command = f". {sh_quote(str(runtime_env))}; env"
    proc = subprocess.run(
        ["sh", "-c", command],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return None
    return {
        key: value
        for line in proc.stdout.splitlines()
        if "=" in line
        for key, value in (line.split("=", 1),)
    }


def load_runtime_env() -> dict[str, str]:
    """Overlay verified runtime exports on the inherited environment."""

    env = dict(os.environ)
    runtime_env = runtime_environment_path(env)
    if runtime_env is None:
        return env
    imported = imported_environment(runtime_env)
    if imported is None:
        return env
    env.update(imported)
    return env


def sh_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def find_case_path(framework_root: Path, case: str) -> Path | None:
    if not SAFE_REPORT_COMPONENT.fullmatch(case):
        return None
    cases_root = framework_root / "tests/cases"
    if not cases_root.is_dir():
        return None
    matches = sorted(cases_root.rglob(f"{case}.yaml"))
    if not matches:
        return None
    candidate = matches[0]
    if candidate.is_symlink() or not candidate.resolve().is_relative_to(cases_root.resolve()):
        raise ValueError("case fixture escaped the canonical cases root")
    return candidate


def load_case(case_path: Path) -> dict[str, Any]:
    if yaml is None:
        raise RuntimeError("PyYAML is required for native case comparison")
    data = yaml.safe_load(case_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise RuntimeError(f"case YAML is not an object: {case_path}")
    return data


def normalize_request(case_data: dict[str, Any]) -> dict[str, Any]:
    request = case_data.get("request")
    if not isinstance(request, dict):
        request = {}
    headers = request.get("headers")
    if not isinstance(headers, dict):
        headers = {}
    normalized_headers = {str(key): str(value) for key, value in headers.items()}
    if "Host" not in normalized_headers and "host" not in {key.lower() for key in normalized_headers}:
        normalized_headers["Host"] = "127.0.0.1"
    body = request.get("body", "")
    if body is None:
        body = ""
    return {
        "method": str(request.get("method") or "GET"),
        "path": str(request.get("path") or request.get("uri") or request.get("url") or "/"),
        "headers": normalized_headers,
        "body": str(body),
    }


def expected_status(case_data: dict[str, Any]) -> int:
    expect = case_data.get("expect")
    if isinstance(expect, dict):
        try:
            return int(expect.get("status") or 200)
        except (TypeError, ValueError):
            return 200
    return 200


def materialize_rules(raw_rules: str, run_dir: Path) -> str:
    logs_dir = run_dir / "logs"
    audit_log = logs_dir / "audit.log"
    debug_log = logs_dir / "debug.log"
    audit_dir = logs_dir / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)
    rules = raw_rules.replace("@@AUDIT_LOG@@", str(audit_log)).replace("@@AUDIT_LOG_DIR@@", str(audit_dir))
    preamble = "\n".join(
        [
            "SecRequestBodyAccess On",
            f"SecDebugLog {debug_log}",
            "SecDebugLogLevel 9",
            "SecAuditEngine RelevantOnly",
            "SecAuditLogType Serial",
            f"SecAuditLog {audit_log}",
            "SecAuditLogParts ABHZ",
            "",
        ]
    )
    return preamble + rules.strip() + "\n"


def write_request_artifacts(request: dict[str, Any], run_dir: Path) -> dict[str, str]:
    body_bytes = str(request.get("body", "")).encode("utf-8")
    body_path = run_dir / "body.bin"
    headers_path = run_dir / "headers.tsv"
    request_path = run_dir / "request.json"
    body_path.write_bytes(body_bytes)
    with headers_path.open("w", encoding="utf-8") as handle:
        for key, value in request.get("headers", {}).items():
            handle.write(f"{key}\t{value}\n")
    request_payload = {
        "method": request.get("method", "GET"),
        "path": request.get("path", "/"),
        "headers": request.get("headers", {}),
        "body_sha256": hashlib.sha256(body_bytes).hexdigest(),
        "body_bytes": len(body_bytes),
        "body_preview": body_bytes[:200].decode("utf-8", errors="replace"),
    }
    write_json(run_dir, request_path, request_payload, "native request")
    return {"body": str(body_path), "headers": str(headers_path), "request": str(request_path)}


def compile_oracle(connector_root: Path, run_root: Path, env: dict[str, str]) -> tuple[Path | None, dict[str, Any]]:
    source = connector_root / NATIVE_ORACLE_SOURCE
    include_dir = env.get("MODSECURITY_INCLUDE_DIR")
    lib_dir = env.get("MODSECURITY_LIB_DIR")
    cc = env.get("CC", "cc")
    bin_dir = run_root / "native-oracle-bin"
    binary = bin_dir / "native_modsecurity_oracle"
    log_path = bin_dir / "compile.log"
    bin_dir = ensure_safe_runtime_directory(bin_dir)
    if not source.is_file():
        return None, {"status": "blocked", "reason": f"missing source {source}", "compile_log": str(log_path)}
    if not include_dir or not Path(include_dir).is_dir():
        return None, {"status": "blocked", "reason": "MODSECURITY_INCLUDE_DIR missing", "compile_log": str(log_path)}
    if not lib_dir or not (Path(lib_dir) / "libmodsecurity.so").exists():
        return None, {"status": "blocked", "reason": "MODSECURITY_LIB_DIR missing libmodsecurity.so", "compile_log": str(log_path)}
    needs_build = not binary.is_file() or binary.stat().st_mtime < source.stat().st_mtime
    if not needs_build:
        return binary, {"status": "reused", "binary": str(binary), "compile_log": str(log_path)}
    cmd = [
        cc,
        "-Wall",
        "-Wextra",
        "-I",
        include_dir,
        str(source),
        "-L",
        lib_dir,
        f"-Wl,-rpath,{lib_dir}",
        "-lmodsecurity",
        "-o",
        str(binary),
    ]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False, env=env)
    log_path.write_text("$ " + " ".join(cmd) + "\n" + proc.stdout, encoding="utf-8")
    if proc.returncode != 0:
        return None, {"status": "blocked", "reason": "oracle compile failed", "compile_log": str(log_path), "return_code": proc.returncode}
    return binary, {"status": "compiled", "binary": str(binary), "compile_log": str(log_path), "return_code": 0}


def extract_log_evidence(text: str) -> dict[str, Any]:
    rule_ids = sorted(
        set(
            re.findall(r'\[id "(\d+)"\]', text, flags=re.ASCII)
            + re.findall(r"\bid:(\d+)", text, flags=re.ASCII)
        )
    )
    matched = matched_data_values(text)
    messages = re.findall(r'\[msg "([^"]+)"\]', text)
    return {
        "rule_ids": rule_ids,
        "matched_data": matched[:5],
        "messages": messages[:5],
    }


def matched_data_values(text: str) -> list[str]:
    """Extract same-line audit values without an unbounded regex wildcard."""

    prefix = "Matched Data:"
    suffix = " found within"
    values: list[str] = []
    for line in text.splitlines():
        if not line.startswith(prefix):
            continue
        candidate, separator, _ = line[len(prefix) :].partition(suffix)
        if separator:
            values.append(candidate.strip())
    return values


def native_case_runtime_directories(
    verified_run_root: Path,
    case: str,
    started: datetime,
) -> tuple[Path, Path, Path]:
    """Create the private directories for one native comparison run."""

    run_root = ensure_safe_runtime_directory(verified_run_root / "native-case-runs")
    run_dir = ensure_safe_runtime_directory(
        run_root / f"{started.strftime('%Y%m%dT%H%M%SZ')}-{safe_name(case)}"
    )
    logs_dir = ensure_safe_runtime_directory(run_dir / "logs")
    return run_root, run_dir, logs_dir


def native_case_context(
    case: str,
    connector_root: Path,
    framework_root: Path,
    verified_run_root: Path,
    env: dict[str, str],
    started: datetime,
) -> NativeCaseContext:
    """Create the immutable context after validating this run's directories."""

    run_root, run_dir, logs_dir = native_case_runtime_directories(
        verified_run_root, case, started
    )
    return NativeCaseContext(
        case=case,
        connector_root=connector_root,
        framework_root=framework_root,
        run_root=run_root,
        run_dir=run_dir,
        logs_dir=logs_dir,
        env=env,
        started=started,
    )


def blocked_native_case_report(
    context: NativeCaseContext,
    reason: str,
    case_path: Path | None = None,
) -> dict[str, Any]:
    """Persist the established blocked-case result shape."""

    result = {
        "case": context.case,
        "status": "blocked",
        "native_actual": None,
        "reason": reason,
        "run_dir": str(context.run_dir),
    }
    if case_path is not None:
        result["case_path"] = str(case_path)
    write_json(
        context.run_dir,
        context.run_dir / NATIVE_CASE_RUN_FILENAME,
        result,
        "native case run",
    )
    return result


def load_native_case_or_block(
    context: NativeCaseContext,
) -> tuple[Path, dict[str, Any]] | dict[str, Any]:
    """Load the requested Framework case or persist its blocked result."""

    case_path = find_case_path(context.framework_root, context.case)
    if case_path is None:
        return blocked_native_case_report(context, "case YAML not found")
    try:
        return case_path, load_case(case_path)
    except Exception as exc:
        return blocked_native_case_report(context, str(exc), case_path)


def prepare_native_case_inputs(
    case_data: dict[str, Any],
    run_dir: Path,
) -> NativeCaseInputs:
    """Materialize the request and rules used by the native oracle."""

    request = normalize_request(case_data)
    rules_path = run_dir / "rules.conf"
    rules_path.write_text(
        materialize_rules(str(case_data.get("rules") or ""), run_dir),
        encoding="utf-8",
    )
    request_paths = write_request_artifacts(request, run_dir)
    return NativeCaseInputs(
        request=request,
        rules_path=rules_path,
        request_paths=request_paths,
        expected=expected_status(case_data),
    )


def native_oracle_environment(env: dict[str, str]) -> dict[str, str]:
    """Add the verified libmodsecurity directory for the oracle process."""

    run_env = dict(env)
    lib_dir = env.get("MODSECURITY_LIB_DIR", "")
    existing_ld = run_env.get("LD_LIBRARY_PATH", "")
    if lib_dir:
        run_env["LD_LIBRARY_PATH"] = lib_dir + (":" + existing_ld if existing_ld else "")
    return run_env


def unavailable_native_result(compile_info: dict[str, Any], expected: int) -> dict[str, Any]:
    """Return the canonical record when the native oracle cannot be built."""

    return {
        "status": "blocked",
        "reason": compile_info.get("reason", "oracle binary unavailable"),
        "expected_status": expected,
        "actual_status": None,
        "native_match": False,
    }


def missing_native_result(expected: int) -> dict[str, Any]:
    """Return the canonical record when the oracle omits its JSON output."""

    return {
        "status": "blocked",
        "reason": "oracle did not produce native-result.json",
        "expected_status": expected,
        "actual_status": None,
        "native_match": False,
    }


def normalize_unavailable_native_result(
    run_dir: Path,
    native_result_path: Path,
    native_result: dict[str, Any],
) -> dict[str, Any]:
    """Keep unavailable-oracle records distinct from executable observations."""

    status = str(native_result.get("status") or "")
    if status in {"blocked", "setup_error", "not_executable"}:
        native_result["actual_status"] = None
        native_result["native_match"] = False
        write_json(run_dir, native_result_path, native_result, NATIVE_RESULT_LABEL)
    return native_result


def execute_native_oracle(
    context: NativeCaseContext,
    inputs: NativeCaseInputs,
) -> NativeOracleExecution:
    """Compile and run the list-form native oracle command for one case."""

    binary, compile_info = compile_oracle(
        context.connector_root, context.run_root, context.env
    )
    native_result_path = context.run_dir / "native-result.json"
    server_log_path = context.logs_dir / "server-log.log"
    if binary is None:
        native_result = unavailable_native_result(compile_info, inputs.expected)
        write_json(context.run_dir, native_result_path, native_result, NATIVE_RESULT_LABEL)
        return NativeOracleExecution(native_result, compile_info, 77, native_result_path)

    cmd = [
        str(binary),
        str(inputs.rules_path),
        inputs.request_paths["headers"],
        inputs.request_paths["body"],
        inputs.request["method"],
        inputs.request["path"],
        str(inputs.expected),
        str(native_result_path),
        str(server_log_path),
    ]
    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
        env=native_oracle_environment(context.env),
    )
    (context.logs_dir / "command.log").write_text(
        "$ " + " ".join(cmd) + "\n" + proc.stdout,
        encoding="utf-8",
    )
    native_result = read_json(native_result_path)
    if not native_result:
        native_result = missing_native_result(inputs.expected)
        write_json(context.run_dir, native_result_path, native_result, NATIVE_RESULT_LABEL)
    return NativeOracleExecution(
        normalize_unavailable_native_result(
            context.run_dir,
            native_result_path,
            native_result,
        ),
        compile_info,
        proc.returncode,
        native_result_path,
    )


def native_case_log_evidence(logs_dir: Path) -> dict[str, Any]:
    """Extract report evidence from the established log file selection."""

    log_text_parts = []
    for path in sorted(logs_dir.rglob("*")):
        if path.is_file() and path.suffix in {".log", ".txt"}:
            log_text_parts.append(path.read_text(encoding="utf-8", errors="replace"))
    return extract_log_evidence("\n".join(log_text_parts))


def write_native_case_report(
    context: NativeCaseContext,
    case_path: Path,
    inputs: NativeCaseInputs,
    execution: NativeOracleExecution,
    log_evidence: dict[str, Any],
) -> dict[str, Any]:
    """Persist one complete native-case report with its comparison context."""

    official = official_context(context.connector_root, context.case)
    comparison = compare_native_to_connectors(execution.native_result, official)
    ended = utc_now()
    report = {
        "schema_version": 1,
        "report_kind": "native-case-run",
        "case": context.case,
        "case_path": str(case_path),
        "run_dir": str(context.run_dir),
        "started_at": iso_utc(context.started),
        "ended_at": iso_utc(ended),
        "duration_seconds": round((ended - context.started).total_seconds(), 3),
        "expected_status": inputs.expected,
        "native_actual": execution.native_result.get("actual_status"),
        "native_match": bool(execution.native_result.get("native_match")),
        "status": execution.native_result.get("status", "unknown"),
        "return_code": execution.return_code,
        "reason": execution.native_result.get("reason", ""),
        "request": read_json(Path(inputs.request_paths["request"])),
        "rules_sha256": sha256_file(inputs.rules_path),
        "request_sha256": sha256_file(Path(inputs.request_paths["request"])),
        "input_hash": combined_hash(
            [case_path, inputs.rules_path, Path(inputs.request_paths["request"])]
        ),
        "rules_path": str(inputs.rules_path),
        "request_path": inputs.request_paths["request"],
        "native_result_path": str(execution.native_result_path),
        "logs_dir": str(context.logs_dir),
        "compile": execution.compile_info,
        "libmodsecurity": execution.native_result.get("libmodsecurity")
        or context.env.get("MODSECURITY_SOURCE_SHA")
        or "unknown",
        "log_evidence": log_evidence,
        "official_mismatch_context": official,
        "connector_comparison": comparison["rows"],
        "classification_hint": comparison["classification_hint"],
        "decision": comparison["decision"],
        "full_matrix_refresh_needed": any(
            bool(row.get("full_matrix_refresh_needed")) for row in comparison["rows"]
        ),
    }
    write_json(
        context.run_dir,
        context.run_dir / NATIVE_CASE_RUN_FILENAME,
        report,
        "native case report",
    )
    (context.run_dir / "native-case-run.md").write_text(
        render_case_markdown(report),
        encoding="utf-8",
    )
    return report


def run_native_case(
    case: str,
    connector_root: Path,
    framework_root: Path,
    verified_run_root: Path,
    env: dict[str, str],
) -> dict[str, Any]:
    started = utc_now()
    context = native_case_context(
        case,
        connector_root,
        framework_root,
        verified_run_root,
        env,
        started,
    )
    case_input = load_native_case_or_block(context)
    if isinstance(case_input, dict):
        return case_input
    case_path, case_data = case_input
    inputs = prepare_native_case_inputs(case_data, context.run_dir)
    execution = execute_native_oracle(context, inputs)
    return write_native_case_report(
        context,
        case_path,
        inputs,
        execution,
        native_case_log_evidence(context.logs_dir),
    )


def combined_hash(paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in paths:
        digest.update(str(path).encode("utf-8"))
        digest.update(b"\0")
        digest.update(sha256_file(path).encode("ascii"))
        digest.update(b"\0")
    return digest.hexdigest()


def official_context(connector_root: Path, case: str) -> dict[str, Any]:
    path = report_path(connector_root, "verified_runtime_mismatch_analysis", "json")
    data = read_json(path)
    rows = [row for row in data.get("mismatches", []) if isinstance(row, dict) and row.get("case") == case]
    compact_rows = []
    for row in rows:
        compact_rows.append(
            {
                "case": row.get("case"),
                "connector": row.get("connector"),
                "variant": row.get("variant"),
                "expected": row.get("expected"),
                "actual": row.get("actual"),
                "classification": row.get("classification"),
                "category": row.get("category"),
                "full_matrix_refresh_needed": bool(row.get("full_matrix_refresh_needed", False)),
                "evidence_file": row.get("evidence_file") or row.get("evidence_path"),
            }
        )
    return {
        "report": str(path),
        "rows": compact_rows,
        "row_count": len(compact_rows),
        "classifications": dict(Counter(str(row.get("classification") or "unknown") for row in compact_rows)),
    }


def normalize_status(value: Any) -> str:
    if value is None:
        return "-"
    text = str(value)
    if text.endswith(".0"):
        text = text[:-2]
    return text


def compare_native_to_connectors(native_result: dict[str, Any], official: dict[str, Any]) -> dict[str, Any]:
    native_actual = normalize_status(native_result.get("actual_status"))
    expected = normalize_status(native_result.get("expected_status"))
    rows = []
    connector_actuals: dict[str, set[str]] = defaultdict(set)
    for row in official.get("rows", []):
        actual = normalize_status(row.get("actual"))
        connector_actuals[str(row.get("connector") or "-")].add(actual)
        same = actual == native_actual and native_actual != "-"
        if native_actual == "-":
            meaning = "native_comparison_missing"
        elif same:
            meaning = "same_as_native"
        elif native_actual == expected:
            meaning = "connector_differs_from_native_expected"
        else:
            meaning = "connector_differs_from_native"
        rows.append(
            {
                "connector": row.get("connector"),
                "variant": row.get("variant"),
                "connector_actual": actual,
                "native_actual": native_actual,
                "same": same,
                "meaning": meaning,
                "classification": row.get("classification"),
                "full_matrix_refresh_needed": bool(row.get("full_matrix_refresh_needed", False)),
                "evidence_file": row.get("evidence_file"),
            }
        )
    all_actuals = {actual for values in connector_actuals.values() for actual in values}
    all_three = all(connector in connector_actuals for connector in CONNECTORS)
    all_same_as_native = bool(rows) and all(row["same"] for row in rows)
    any_same_as_native = any(row["same"] for row in rows)
    all_connectors_same = len(all_actuals) == 1 and all_three
    all_refresh_needed = bool(rows) and all(bool(row.get("full_matrix_refresh_needed")) for row in official.get("rows", []))
    hint, decision = comparison_decision(
        str(native_result.get("status") or ""),
        native_actual,
        expected,
        all_refresh_needed,
        all_same_as_native,
        any_same_as_native,
        all_connectors_same,
    )
    return {"rows": rows, "classification_hint": hint, "decision": decision}


def comparison_decision(
    status: str,
    native_actual: str,
    expected: str,
    all_refresh_needed: bool,
    all_same_as_native: bool,
    any_same_as_native: bool,
    all_connectors_same: bool,
) -> tuple[str, str]:
    """Classify connector divergence without changing observed result values."""

    if status in {"blocked", "setup_error", "not_executable"} or native_actual == "-":
        return "native_comparison_missing", "DEFER"
    if all_refresh_needed and native_actual == expected:
        return "full_matrix_refresh_needed", "REFRESH"
    if all_same_as_native and native_actual != expected:
        return "likely_framework_expected_behavior_gap_or_libmodsecurity_semantics", "DOCUMENT"
    if native_actual == expected and not any_same_as_native and all_connectors_same:
        return "common_harness_or_input_issue_possible", "DEFER"
    if native_actual == expected and not all_same_as_native:
        return "connector_bug_or_harness_gap_possible", "DEFER"
    return "unknown", "DEFER"


def latest_case_runs(verified_run_root: Path, cases: tuple[str, ...]) -> list[dict[str, Any]]:
    runs_root = verified_run_root / "native-case-runs"
    reader = EvidenceInputs((runs_root,))
    output = []
    for case in cases:
        candidates = sorted(runs_root.glob(f"*-{safe_name(case)}/{NATIVE_CASE_RUN_FILENAME}"))
        if not candidates:
            output.append({"case": case, "status": "missing", "reason": "no native case run found"})
            continue
        report = reader.json(candidates[-1])
        if not report or report.get("case") != case:
            raise ValueError("native case record does not match its selected case")
        # The loaded file supplies provenance; its contents cannot redirect it.
        report["run_dir"] = str(candidates[-1].parent)
        output.append(report)
    return output


def refresh_official_context(connector_root: Path, reports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    refreshed = []
    for report in reports:
        item = dict(report)
        case = str(item.get("case") or "")
        if not case or item.get("status") == "missing":
            refreshed.append(item)
            continue
        official = official_context(connector_root, case)
        native_result = {
            "actual_status": item.get("native_actual"),
            "expected_status": item.get("expected_status"),
            "status": item.get("status"),
        }
        comparison = compare_native_to_connectors(native_result, official)
        item["official_mismatch_context"] = official
        item["connector_comparison"] = comparison["rows"]
        item["classification_hint"] = comparison["classification_hint"]
        item["decision"] = comparison["decision"]
        item["full_matrix_refresh_needed"] = any(
            bool(row.get("full_matrix_refresh_needed")) for row in comparison["rows"]
        )
        refreshed.append(item)
    return refreshed


def reclassified_rows(reports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output = []
    for report in reports:
        rows = [
            row
            for row in report.get("connector_comparison", [])
            if row.get("classification") == "libmodsecurity_transformation_semantics"
        ]
        if not rows:
            continue
        output.append(
            {
                "case": report.get("case"),
                "rows": len(rows),
                "classification": "libmodsecurity_transformation_semantics",
                "native_actual": normalize_status(report.get("native_actual")),
                "decision": report.get("decision"),
            }
        )
    return output


def inventory() -> list[dict[str, str]]:
    return [
        {
            "tool_target": "tools/MRTS/mrts/generate-rules.py",
            "purpose": "Generate MRTS rules and go-ftw tests from upstream MRTS YAML definitions.",
            "inputs": "MRTS config_tests YAML",
            "outputs": "$BUILD_ROOT/mrts/*/rules and ftw",
            "single_case": "no; corpus generator",
        },
        {
            "tool_target": "framework Makefile mrts-generate/mrts-import/mrts-ftw",
            "purpose": "Prepare/import MRTS corpora and optionally run go-ftw.",
            "inputs": "MRTS corpus definitions and infra config",
            "outputs": "generated framework cases, rules, go-ftw results",
            "single_case": "not for framework YAML cases",
        },
        {
            "tool_target": "ci/runtime/lifecycle/run-mrts-native-full.sh",
            "purpose": "Stage native Apache/NGINX MRTS infra and run the MRTS suite through go-ftw.",
            "inputs": "MRTS generated corpus, native Apache/NGINX binaries, libmodsecurity",
            "outputs": "$BUILD_ROOT/mrts-native/*/job.json and logs",
            "single_case": "no; suite-oriented MRTS evidence",
        },
        {
            "tool_target": "framework:ci/reporting/generate-mrts-native-report.py",
            "purpose": "Summarize native MRTS jobs into generated reports.",
            "inputs": "$MRTS_NATIVE_ROOT/apache2_ubuntu/job.json and nginx-pr24/job.json",
            "outputs": "reports/testing/generated/mrts-native/*.generated.*",
            "single_case": "no; summarizes completed native MRTS jobs",
        },
        {
            "tool_target": NATIVE_RUNNER_PATH,
            "purpose": "Run one framework YAML case through connector-free libmodsecurity C API.",
            "inputs": "framework case YAML, native_modsecurity_oracle.c, libmodsecurity runtime-env",
            "outputs": "$VERIFIED_RUN_ROOT/native-case-runs/<timestamp>-<case>/ and native-semantics-comparison.generated.*",
            "single_case": "yes",
        },
    ]


def render_case_markdown(report: dict[str, Any]) -> str:
    return "\n\n".join(
        [
            "# Native Case Run",
            md_table(
                ["Field", "Value"],
                [
                    ["Case", report.get("case", "-")],
                    ["Expected Status", report.get("expected_status", "-")],
                    [NATIVE_ACTUAL_LABEL, report.get("native_actual", "-")],
                    ["Native Match", "yes" if report.get("native_match") else "no"],
                    ["Status", report.get("status", "-")],
                    ["Rule ID", ", ".join(report.get("log_evidence", {}).get("rule_ids", [])) or "-"],
                    ["Matched Data", ", ".join(report.get("log_evidence", {}).get("matched_data", [])) or "-"],
                    ["Classification Hint", report.get("classification_hint", "-")],
                    ["Full-Matrix Refresh Needed", "yes" if report.get("full_matrix_refresh_needed") else "no"],
                ],
            ),
            "## Connector Comparison",
            md_table(
                ["Connector", "Variant", "Connector Actual", NATIVE_ACTUAL_LABEL, "Same", "Meaning"],
                [
                    [row["connector"], row["variant"], row["connector_actual"], row["native_actual"], row["same"], row["meaning"]]
                    for row in report.get("connector_comparison", [])
                ]
                or [["-", "-", "-", "-", "-", "no official Full-Matrix row found"]],
            ),
            "## Artifacts",
            md_table(
                ["Artifact", "Path"],
                [
                    ["request.json", report.get("request_path", "-")],
                    ["rules.conf", report.get("rules_path", "-")],
                    ["native-result.json", report.get("native_result_path", "-")],
                    ["logs", report.get("logs_dir", "-")],
                ],
            ),
        ]
    ) + "\n"


def md_table(headers: list[str], rows: list[list[Any]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    if not rows:
        lines.append("| " + " | ".join("_No rows available. Reason: no data._" for _ in headers) + " |")
    for row in rows:
        lines.append("| " + " | ".join(str(item).replace("|", "\\|").replace("\n", " ") for item in row) + " |")
    return "\n".join(lines)


def render_summary_markdown(payload: dict[str, Any]) -> str:
    comparison_rows = []
    for item in payload.get("cases", []):
        connector_actuals = Counter(
            f"{row.get('connector')}:{row.get('variant')}={row.get('connector_actual')}"
            for row in item.get("connector_comparison", [])
        )
        comparison_rows.append(
            [
                item.get("case", "-"),
                item.get("native_actual", "-"),
                ", ".join(sorted(connector_actuals)) or "-",
                "yes" if item.get("native_match") else "no",
                item.get("decision", "-"),
                item.get("classification_hint", "-"),
                "yes" if item.get("full_matrix_refresh_needed") else "no",
            ]
        )
    reclassified = payload.get("reclassified", [])
    reclassified_table = (
        md_table(
            ["Case", "Rows", "Classification", NATIVE_ACTUAL_LABEL, "Decision"],
            [
                [
                    item.get("case", "-"),
                    item.get("rows", "-"),
                    item.get("classification", "-"),
                    item.get("native_actual", "-"),
                    item.get("decision", "-"),
                ]
                for item in reclassified
            ],
        )
        if reclassified
        else "_No rows available. Reason: no current official rows are classified from native semantics evidence._"
    )
    return "\n\n".join(
        [
            "# Native Semantics Comparison",
            "## Tool Inventory",
            md_table(
                ["Tool/Target", "Purpose", "Inputs", "Outputs", "Usable for Single Case?"],
                [
                    [row["tool_target"], row["purpose"], row["inputs"], row["outputs"], row["single_case"]]
                    for row in payload.get("tool_inventory", [])
                ],
            ),
            "## Native Comparisons",
            md_table(
                [
                    "Case",
                    NATIVE_ACTUAL_LABEL,
                    "Connector Actuals",
                    "Native Match",
                    "Decision",
                    "Classification Hint",
                    "Full-Matrix Refresh Needed",
                ],
                comparison_rows,
            ),
            "## Reclassified",
            reclassified_table,
            "## Fixed",
            "_No rows available. Reason: this pass added native comparison tooling only._",
            "## Deferred",
            md_table(
                ["Case", "Reason"],
                [
                    [item.get("case", "-"), item.get("classification_hint", item.get("reason", "-"))]
                    for item in payload.get("cases", [])
                    if item.get("decision") == "DEFER"
                ],
            ),
            "## Notes",
            f"- Data source policy: `{DATA_SOURCE_POLICY}`.",
            "- Native comparison rows are refreshed from the current verified runtime mismatch analysis; no PASS/FAIL values are invented.",
        ]
    )


def write_summary_report(
    connector_root: Path,
    framework_root: Path,
    verified_run_root: Path,
    cases: tuple[str, ...],
    run_reports: list[dict[str, Any]] | None,
    output_dir: Path,
) -> dict[str, Any]:
    reports = run_reports if run_reports is not None else latest_case_runs(verified_run_root, cases)
    reports = refresh_official_context(connector_root, reports)
    inv = inventory()
    inputs: list[Path | str] = [
        connector_root / NATIVE_RUNNER_PATH,
        connector_root / NATIVE_ORACLE_SOURCE,
        report_path(connector_root, "verified_runtime_mismatch_analysis", "json"),
    ]
    runtime_inputs = []
    reader = EvidenceInputs((verified_run_root / "native-case-runs",))
    for item in reports:
        case = str(item.get("case") or "")
        if case not in cases or not SAFE_REPORT_COMPONENT.fullmatch(case):
            raise ValueError("native summary contains an unselected case")
        fixture = find_case_path(framework_root, case)
        if fixture is not None:
            inputs.append(fixture)
        if item.get("run_dir"):
            run_json = reader.path(Path(str(item["run_dir"])) / NATIVE_CASE_RUN_FILENAME)
            # Never pass JSON-selected paths to the generic metadata reader.
            # Hash the actual bytes through the confined no-follow descriptor.
            try:
                digest, _ = reader.file_proof(run_json)
            except FileNotFoundError:
                runtime_inputs.append({"path": str(run_json), "status": "missing"})
            else:
                runtime_inputs.append({"path": str(run_json), "status": "present",
                                       "sha256": digest, "source_hash": digest})
    payload = {
        "report_kind": "native-semantics-comparison",
        "data_source_policy": DATA_SOURCE_POLICY,
        "verified_run_id": os.environ.get("VERIFIED_RUN_ID") or "",
        "tool_inventory": inv,
        "native_tool": {
            "source": str(NATIVE_ORACLE_SOURCE),
            "runner": NATIVE_RUNNER_PATH,
        },
        "cases": reports,
        "reclassified": reclassified_rows(reports),
        "fixed": [],
        "full_matrix_refresh_needed": any(bool(item.get("full_matrix_refresh_needed")) for item in reports),
    }
    metadata = build_metadata(
        generated_by=GENERATED_REPORTS["native_semantics_comparison"].generator,
        make_target=GENERATED_REPORTS["native_semantics_comparison"].make_target,
        connector_root=connector_root,
        framework_root=framework_root,
        inputs=inputs,
        report_key="native_semantics_comparison",
    )
    metadata.setdefault("inputs", []).extend(runtime_inputs)
    metadata["input_status"] = input_status_summary(metadata["inputs"])
    metadata.setdefault("missing_inputs", []).extend(item["path"] for item in runtime_inputs if item["status"] == "missing")
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / GENERATED_REPORTS["native_semantics_comparison"].filename("json")
    md_path = output_dir / GENERATED_REPORTS["native_semantics_comparison"].filename("md")
    json_path.write_text(generated_json_text(payload, metadata), encoding="utf-8")
    md_path.write_text(generated_markdown_text(render_summary_markdown(payload), metadata), encoding="utf-8")
    return {"json": str(json_path), "md": str(md_path), "payload": payload}


def canonical_roots(connector_root: str, framework_root: str | None) -> tuple[Path, Path]:
    """Bind CLI source roots to the checked-out Parent/Framework pair."""

    canonical_connector, canonical_framework = canonical_project_roots()
    requested_connector = Path(connector_root).resolve(strict=True)
    requested_framework = (
        Path(framework_root).resolve(strict=True)
        if framework_root
        else canonical_framework
    )
    if requested_connector != canonical_connector:
        raise ValueError(f"connector root must be this checkout: {requested_connector}")
    if requested_framework != canonical_framework:
        raise ValueError(f"framework root must be the pinned checkout: {requested_framework}")
    return canonical_connector, canonical_framework


def report_output_dir(connector_root: Path, verified_run_root: Path, value: str) -> Path:
    """Constrain reports to the generated manifest tree or a verified runtime root."""

    if os.path.isabs(value):
        return ensure_safe_runtime_directory(
            runtime_artifact_path(verified_run_root, value, "report output directory")
        )

    components = tuple(value.split("/"))
    if (
        components[: len(GENERATED_MANIFEST_COMPONENTS)] != GENERATED_MANIFEST_COMPONENTS
        or not all(SAFE_REPORT_COMPONENT.fullmatch(component) for component in components)
    ):
        raise ValueError(
            "relative report output directory must be below reports/testing/generated/manifest"
        )
    candidate = connector_root.joinpath(*components)
    generated_root = connector_root.joinpath(*GENERATED_MANIFEST_COMPONENTS)
    candidate.relative_to(generated_root)
    if candidate.exists() and candidate.is_symlink():
        raise ValueError(f"report output directory must not be a symlink: {candidate}")
    candidate.mkdir(parents=True, exist_ok=True)
    return candidate


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run connector-free native libmodsecurity comparison for framework cases.")
    parser.add_argument("--case", action="append", dest="cases")
    parser.add_argument("--connector-root", default=".")
    parser.add_argument("--framework-root", default=None)
    parser.add_argument("--build-root", default=None)
    parser.add_argument("--verified-run-root", default=None)
    parser.add_argument("--output-dir", default="reports/testing/generated/manifest")
    parser.add_argument("--report-only", action="store_true")
    return parser.parse_args()


def accumulated_case_return_code(current: int, status: str) -> int:
    """Preserve a blocked result over an unavailable case result."""

    if status in {"blocked", "setup_error"}:
        return 77 if current == 0 else current
    if status == "not_executable" and current == 0:
        return 2
    return current


def run_requested_cases(
    cases: tuple[str, ...],
    connector_root: Path,
    framework_root: Path,
    verified_run_root: Path,
) -> tuple[list[dict[str, Any]], int]:
    """Run requested native cases and retain the most actionable nonzero result."""

    reports: list[dict[str, Any]] = []
    result = 0
    env = load_runtime_env()
    for case in cases:
        report = run_native_case(case, connector_root, framework_root, verified_run_root, env)
        reports.append(report)
        print(f"native-case-run: {report.get('run_dir')}")
        print(f"case={case} status={report.get('status')} native_actual={report.get('native_actual')} decision={report.get('decision')}")
        result = accumulated_case_return_code(result, str(report.get("status") or ""))
    return reports, result


def main() -> int:
    args = parse_args()
    try:
        connector_root, framework_root = canonical_roots(
            args.connector_root, args.framework_root
        )
        verified_run_root = prepare_verified_runtime_artifact_root(
            args.verified_run_root,
            fallback=DEFAULT_VERIFIED_RUN_ROOT,
        )
        output_dir = report_output_dir(
            connector_root, verified_run_root, args.output_dir
        )
    except ValueError as exc:
        print(f"native-case-comparison: {exc}", file=sys.stderr)
        return 77
    cases = tuple(args.cases or DEFAULT_CASES)
    run_reports: list[dict[str, Any]] | None = None
    rc = 0
    if not args.report_only:
        run_reports, rc = run_requested_cases(
            cases, connector_root, framework_root, verified_run_root
        )
    summary = write_summary_report(connector_root, framework_root, verified_run_root, cases, run_reports, output_dir)
    print(summary["md"])
    print(summary["json"])
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
