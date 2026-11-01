#!/usr/bin/env python3
"""Write connector-neutral runtime smoke evidence.

This helper intentionally lives outside the public C headers. It centralizes
the JSON/text evidence contract used by open connector harnesses without
turning harness metadata into a runtime ABI.
"""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


_CI_LIB = connector_root() / "ci" / "lib"


from modsecurity_connector_ci.lib.runtime_path_utils import ensure_safe_runtime_directory, is_safe_runtime_root, verified_runtime_paths


DEFAULT_NOTE = (
    "Build/self-test starter evidence is available via make connector-starter-checks "
    "but is not runtime smoke evidence."
)
DEFAULT_CLAIMS_NOT_ALLOWED = (
    "production_ready=true",
    "full_matrix_ready=true",
    "crs_complete=true",
    "response_body_verified=true",
)
COMMON_COMPONENTS = (
    "msconnector/request.h",
    "msconnector/response.h",
    "msconnector/intervention.h",
    "msconnector/status.h",
    "msconnector/logging.h",
    "msconnector/capabilities.h",
    "msconnector/origin.h",
    "msconnector/transaction.h",
)
OUTPUT_PATH_ARGUMENTS = (
    ("evidence_root", "evidence_root"),
    ("results_dir", "results_dir"),
    ("tmp_root", "tmp_root"),
    ("log_root", "log_root"),
    ("log_dir", "log_dir"),
)
CONNECTOR_NAME_PATTERN = re.compile(r"[a-z0-9][a-z0-9_-]*")


def optional_int(value: str | None) -> int | None:
    if value in (None, "", "null", "none", "not-run"):
        return None
    return int(value)


def bool_text(value: str) -> bool:
    return value.lower() in {"1", "true", "yes", "on"}


def normalize_status(status: str) -> str:
    return status.upper()


def runtime_status_for(status: str, runtime_verified: bool) -> str:
    if runtime_verified:
        return "verified"
    if status == "BLOCKED":
        return "blocked"
    if status == "PASS":
        return "ok"
    return "error"


def require_safe_connector_name(value: str) -> str:
    if CONNECTOR_NAME_PATTERN.fullmatch(value) is None:
        raise SystemExit(f"BLOCKED: connector is not a safe output filename component: {value}")
    return value


def require_verified_output_directory(path: Path, label: str, runtime_root: Path) -> Path:
    text = str(path)
    if not path.is_absolute():
        raise SystemExit(f"BLOCKED: {label} must be absolute: {text}")
    try:
        resolved = path.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise SystemExit(f"BLOCKED: {label} cannot be resolved: {text}: {exc}") from exc
    try:
        resolved.relative_to(runtime_root)
    except ValueError as exc:
        raise SystemExit(
            f"BLOCKED: {label} is outside the verified runtime root: {resolved}"
        ) from exc
    try:
        return ensure_safe_runtime_directory(path)
    except ValueError as exc:
        raise SystemExit(f"BLOCKED: {label} is not a safe runtime directory: {text}: {exc}") from exc


def verified_output_directories(args: argparse.Namespace) -> dict[str, Path]:
    try:
        verified_paths = verified_runtime_paths(os.environ)
    except ValueError as exc:
        raise SystemExit(f"BLOCKED: invalid verified runtime paths: {exc}") from exc
    runtime_root = Path(verified_paths["VERIFIED_RUN_ROOT"])
    if not is_safe_runtime_root(runtime_root):
        raise SystemExit(f"BLOCKED: VERIFIED_RUN_ROOT is unsafe: {runtime_root}")
    return {
        name: require_verified_output_directory(Path(getattr(args, name)), label, runtime_root)
        for name, label in OUTPUT_PATH_ARGUMENTS
    }


def open_private_output_file(path: Path):
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise SystemExit("BLOCKED: safe output files require O_NOFOLLOW support")
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | no_follow, 0o600)
    except OSError as exc:
        raise SystemExit(f"BLOCKED: cannot open safe output file: {path}: {exc}") from exc
    os.fchmod(descriptor, 0o600)
    return os.fdopen(descriptor, "w", encoding="utf-8")


def write_json(path: Path, data: object) -> None:
    with open_private_output_file(path) as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.write("\n")


def write_jsonl(path: Path, record: object) -> None:
    with open_private_output_file(path) as handle:
        handle.write(json.dumps(record, sort_keys=True))
        handle.write("\n")


def write_text(path: Path, text: str) -> None:
    with open_private_output_file(path) as handle:
        handle.write(text)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--connector", required=True)
    parser.add_argument("--integration-mode", required=True)
    parser.add_argument("--status", default="BLOCKED")
    parser.add_argument("--exit-code", type=int, default=77)
    parser.add_argument("--runtime-verified", default="false")
    parser.add_argument("--response-body-verified", default="false")
    parser.add_argument("--allowed-request-status")
    parser.add_argument("--blocked-request-status")
    parser.add_argument("--decision-backend", default="simple")
    parser.add_argument("--modsecurity-ruleset", default="")
    parser.add_argument("--modsecurity-smoke-case", default="")
    parser.add_argument("--modsecurity-backend-verified", default="false")
    parser.add_argument("--modsecurity-rule-file", default="")
    parser.add_argument("--modsecurity-rule-id", default="")
    parser.add_argument("--modsecurity-rule-loaded", default="false")
    parser.add_argument("--request-body-smoke-verified", default="false")
    parser.add_argument("--request-body-access-enabled", default="false")
    parser.add_argument("--request-body-rule-file", default="")
    parser.add_argument("--request-body-rule-id", default="")
    parser.add_argument("--request-body-rule-loaded", default="false")
    parser.add_argument("--request-method", default="")
    parser.add_argument("--blocked-body-marker", default="")
    parser.add_argument("--intervention-status")
    parser.add_argument("--audit-log-path", default="")
    parser.add_argument("--decision-log-path", default="")
    parser.add_argument("--lighttpd-binary-verified", default="false")
    parser.add_argument("--lighttpd-http-verified", default="false")
    parser.add_argument("--sidecar-proxy-verified", default="false")
    parser.add_argument("--lighttpd-log-path", default="")
    parser.add_argument("--upstream-log-path", default="")
    parser.add_argument("--request-transcript-path", default="")
    parser.add_argument("--modsecurity-include-dir", default="")
    parser.add_argument("--modsecurity-lib-dir", default="")
    parser.add_argument("--modsecurity-lib-file", default="")
    parser.add_argument("--modsecurity-pkg-config-path", default="")
    parser.add_argument("--modsecurity-prefix", default="")
    parser.add_argument("--modsecurity-manifest", default="")
    parser.add_argument("--evidence-root", required=True)
    parser.add_argument("--results-dir", required=True)
    parser.add_argument("--connector-root", required=True)
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--build-root", required=True)
    parser.add_argument("--tmp-root", required=True)
    parser.add_argument("--log-root", required=True)
    parser.add_argument("--log-dir", required=True)
    parser.add_argument("--harness-path", required=True)
    parser.add_argument("--skipped-reason", required=True)
    parser.add_argument("--resolved-runtime-binary", default="")
    parser.add_argument("--runtime-binary-env-var", default="")
    parser.add_argument("--runtime-binary-name", default="")
    parser.add_argument("--runtime-lookup-root", action="append", default=[])
    parser.add_argument("--note", default=DEFAULT_NOTE)
    parser.add_argument("--starter-checks-available", default="false")
    parser.add_argument("--missing-dependency", action="append", default=[])
    parser.add_argument("--claim-not-allowed", action="append", default=[])
    parser.add_argument("--architecture-decision", default="")
    parser.add_argument("--crs-repo-url", default="")
    parser.add_argument("--crs-git-ref", default="")
    parser.add_argument("--crs-source-dir", default="")
    parser.add_argument("--crs-runtime-dir", default="")
    parser.add_argument("--crs-version", default="")
    parser.add_argument("--crs-smoke-case", default="")
    parser.add_argument("--crs-minimal-smoke-verified", default="false")
    parser.add_argument("--crs-secondary-smoke-verified", default="false")
    parser.add_argument("--crs-rule-id", default="")
    parser.add_argument("--crs-rule-message", default="")
    return parser


def optional_text(value: str) -> str | None:
    return value or None


def writer_flags(args: argparse.Namespace) -> dict[str, bool]:
    return {
        "crs_minimal_smoke_verified": bool_text(args.crs_minimal_smoke_verified),
        "crs_secondary_smoke_verified": bool_text(args.crs_secondary_smoke_verified),
        "lighttpd_binary_verified": bool_text(args.lighttpd_binary_verified),
        "lighttpd_http_verified": bool_text(args.lighttpd_http_verified),
        "modsecurity_backend_verified": bool_text(args.modsecurity_backend_verified),
        "modsecurity_rule_loaded": bool_text(args.modsecurity_rule_loaded),
        "request_body_access_enabled": bool_text(args.request_body_access_enabled),
        "request_body_rule_loaded": bool_text(args.request_body_rule_loaded),
        "request_body_smoke_verified": bool_text(args.request_body_smoke_verified),
        "response_body_verified": bool_text(args.response_body_verified),
        "runtime_verified": bool_text(args.runtime_verified),
        "sidecar_proxy_verified": bool_text(args.sidecar_proxy_verified),
        "starter_checks_available": bool_text(args.starter_checks_available),
    }


def disallowed_claims(args: argparse.Namespace, flags: dict[str, bool]) -> list[str]:
    claims = list(args.claim_not_allowed or DEFAULT_CLAIMS_NOT_ALLOWED)
    for flag, claim in (
        ("runtime_verified", "runtime_verified=true"),
        ("modsecurity_backend_verified", "modsecurity_backend_verified=true"),
        ("request_body_smoke_verified", "request_body_smoke_verified=true"),
        ("crs_minimal_smoke_verified", "crs_minimal_smoke_verified=true"),
        ("crs_secondary_smoke_verified", "crs_secondary_smoke_verified=true"),
    ):
        if not flags[flag] and claim not in claims:
            claims.append(claim)
    return claims


def runtime_inventory(args: argparse.Namespace) -> dict[str, object]:
    roots: list[str] = []
    for root in args.runtime_lookup_root:
        if root and root not in roots:
            roots.append(root)
    binary = optional_text(args.resolved_runtime_binary)
    return {
        "binary_env_var": optional_text(args.runtime_binary_env_var),
        "binary_name": optional_text(args.runtime_binary_name),
        "lookup_roots": roots,
        "resolved_runtime_binary": binary,
        "state": "resolved" if binary else "missing",
    }


def smoke_result_payload(
    args: argparse.Namespace,
    connector: str,
    evidence_root: Path,
    status: str,
    timestamp: str,
    flags: dict[str, bool],
) -> dict[str, object]:
    return {
        "allowed_request_status": optional_int(args.allowed_request_status),
        "architecture_decision": optional_text(args.architecture_decision),
        "audit_log_path": optional_text(args.audit_log_path),
        "blocked_body_marker": optional_text(args.blocked_body_marker),
        "blocked_request_status": optional_int(args.blocked_request_status),
        "claims_not_allowed": disallowed_claims(args, flags),
        "common_msconnector_components": list(COMMON_COMPONENTS),
        "connector": connector,
        "crs_complete": False,
        "crs_git_ref": optional_text(args.crs_git_ref),
        "crs_minimal_smoke_verified": flags["crs_minimal_smoke_verified"],
        "crs_repo_url": optional_text(args.crs_repo_url),
        "crs_rule_id": optional_text(args.crs_rule_id),
        "crs_rule_message": optional_text(args.crs_rule_message),
        "crs_runtime_dir": optional_text(args.crs_runtime_dir),
        "crs_secondary_smoke_verified": flags["crs_secondary_smoke_verified"],
        "crs_smoke_case": optional_text(args.crs_smoke_case),
        "crs_source_dir": optional_text(args.crs_source_dir),
        "crs_version": optional_text(args.crs_version),
        "decision_backend": args.decision_backend,
        "decision_log_path": optional_text(args.decision_log_path),
        "evidence_root": str(evidence_root),
        "exit_code": args.exit_code,
        "full_matrix_ready": False,
        "integration_mode": args.integration_mode,
        "intervention_status": optional_int(args.intervention_status),
        "lighttpd_binary_verified": flags["lighttpd_binary_verified"],
        "lighttpd_http_verified": flags["lighttpd_http_verified"],
        "lighttpd_log_path": optional_text(args.lighttpd_log_path),
        "missing_dependencies": args.missing_dependency,
        "modsecurity_backend_verified": flags["modsecurity_backend_verified"],
        "modsecurity_dependency_inventory": {
            "include_dir": optional_text(args.modsecurity_include_dir),
            "lib_dir": optional_text(args.modsecurity_lib_dir),
            "lib_file": optional_text(args.modsecurity_lib_file),
            "manifest": optional_text(args.modsecurity_manifest),
            "pkg_config_path": optional_text(args.modsecurity_pkg_config_path),
            "prefix": optional_text(args.modsecurity_prefix),
        },
        "modsecurity_rule_file": optional_text(args.modsecurity_rule_file),
        "modsecurity_rule_id": optional_text(args.modsecurity_rule_id),
        "modsecurity_rule_loaded": flags["modsecurity_rule_loaded"],
        "modsecurity_ruleset": optional_text(args.modsecurity_ruleset),
        "modsecurity_smoke_case": optional_text(args.modsecurity_smoke_case),
        "production_ready": False,
        "request_body_access_enabled": flags["request_body_access_enabled"],
        "request_body_rule_file": optional_text(args.request_body_rule_file),
        "request_body_rule_id": optional_text(args.request_body_rule_id),
        "request_body_rule_loaded": flags["request_body_rule_loaded"],
        "request_body_smoke_verified": flags["request_body_smoke_verified"],
        "request_method": optional_text(args.request_method),
        "request_transcript_path": optional_text(args.request_transcript_path),
        "resolved_runtime_binary": optional_text(args.resolved_runtime_binary),
        "response_body_verified": flags["response_body_verified"],
        "runtime_inventory": runtime_inventory(args),
        "runtime_status": runtime_status_for(status, flags["runtime_verified"]),
        "runtime_verified": flags["runtime_verified"],
        "sidecar_proxy_verified": flags["sidecar_proxy_verified"],
        "skipped_reason": args.skipped_reason,
        "status": status,
        "timestamp": timestamp,
        "upstream_log_path": optional_text(args.upstream_log_path),
    }


def smoke_record(result: dict[str, object], args: argparse.Namespace, timestamp: str) -> dict[str, object]:
    return {
        **result,
        "check": "runtime-smoke-entrypoint",
        "command": f"make smoke-{result['connector']}",
        "generated_at": timestamp,
        "harness_path": args.harness_path,
        "installs_global_artifacts": False,
        "note": args.note,
        "starter_checks_available": bool_text(args.starter_checks_available),
        "test_type": "runtime-smoke",
    }


def smoke_summary(
    args: argparse.Namespace,
    result: dict[str, object],
    record: dict[str, object],
    results_dir: Path,
    timestamp: str,
) -> dict[str, object]:
    status = str(result["status"])
    counts = {"PASS": 0, "FAIL": 0, "BLOCKED": 0, "NOT_RUN": 0}
    counts[status] = counts.get(status, 0) + 1
    return {
        "build_root": args.build_root,
        "connector": result["connector"],
        "connector_root": args.connector_root,
        "counts": counts,
        "evidence_root": result["evidence_root"],
        "generated_at": timestamp,
        "harness_path": args.harness_path,
        "installs_global_artifacts": False,
        "integration_mode": args.integration_mode,
        "lighttpd_binary_verified": result["lighttpd_binary_verified"],
        "lighttpd_http_verified": result["lighttpd_http_verified"],
        "log_dir": args.log_dir,
        "log_root": args.log_root,
        "note": args.note,
        "reason": args.skipped_reason,
        "response_body_verified": result["response_body_verified"],
        "results": [record],
        "results_dir": str(results_dir),
        "runtime_status": result["runtime_status"],
        "runtime_verified": result["runtime_verified"],
        "sidecar_proxy_verified": result["sidecar_proxy_verified"],
        "source_root": args.source_root,
        "starter_checks_available": bool_text(args.starter_checks_available),
        "status": status,
        "tmp_root": args.tmp_root,
    }


def specialized_result_name(args: argparse.Namespace) -> str | None:
    if args.modsecurity_ruleset == "crs":
        return "crs-secondary-result.json" if args.crs_smoke_case == "secondary" else "crs-result.json"
    if args.modsecurity_ruleset == "targeted" and args.modsecurity_smoke_case == "request_body":
        return "request-body-result.json"
    if args.modsecurity_ruleset == "targeted" and args.decision_backend == "libmodsecurity":
        return "targeted-result.json"
    return "runtime-result.json" if args.decision_backend == "simple" else None


def write_result_documents(
    args: argparse.Namespace,
    result: dict[str, object],
    record: dict[str, object],
    summary: dict[str, object],
    evidence_root: Path,
    results_dir: Path,
    log_dir: Path,
) -> None:
    runtime_text = "Runtime verified" if result["runtime_verified"] else "Runtime not verified"
    status_text = (
        f"{result['status']} {result['connector']}-runtime-smoke {args.skipped_reason}\n"
        f"{runtime_text}\n"
        f"Evidence root: {evidence_root}\n"
        f"{args.note}\n"
    )
    write_json(evidence_root / "result.json", result)
    specialized_name = specialized_result_name(args)
    if specialized_name is not None:
        write_json(evidence_root / specialized_name, result)
    write_jsonl(evidence_root / "results.jsonl", record)
    write_json(evidence_root / "summary.json", summary)
    write_text(evidence_root / "summary.txt", status_text)
    write_text(log_dir / "status.log", status_text)
    connector = str(result["connector"])
    write_jsonl(results_dir / f"{connector}-results.jsonl", record)
    write_json(results_dir / f"{connector}-summary.json", summary)
    write_text(results_dir / f"{connector}-summary.txt", status_text)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    connector = require_safe_connector_name(args.connector)
    output_directories = verified_output_directories(args)
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    flags = writer_flags(args)
    result = smoke_result_payload(
        args,
        connector,
        output_directories["evidence_root"],
        normalize_status(args.status),
        timestamp,
        flags,
    )
    record = smoke_record(result, args, timestamp)
    summary = smoke_summary(args, result, record, output_directories["results_dir"], timestamp)
    write_result_documents(
        args,
        result,
        record,
        summary,
        output_directories["evidence_root"],
        output_directories["results_dir"],
        output_directories["log_dir"],
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
