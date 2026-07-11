"""CLI bridge for shared YAML cases used by connector harnesses."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from msconnector_models import (
    RESULT_STATUSES,
    SummaryContext,
    connector_summary as build_connector_summary,
    empty_connector_summary,
)
from runner_core import (
    CONNECTORS,
    assert_case_artifacts,
    case_info as build_case_info,
    discover_case_files,
    effective_expect,
    expected_audit_log,
    phase4_log_metadata,
    load_case,
    write_body_file,
    write_headers_file,
    write_response_fixture,
    write_rules_file,
    write_shell_env,
    write_nginx_runtime_files,
)

CONNECTOR_CHOICES = tuple(sorted(connector for connector in CONNECTORS if connector != "common"))


def _phase4_bool(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
    return None


def _phase4_action(value: object, allowed: set[str]) -> str | None:
    if value in (None, ""):
        return None
    action = str(value).strip().lower().replace("-", "_")
    if action == "connection_abort":
        action = "abort_connection"
    return action if action in allowed else None


def phase4_runtime_evidence(metadata: dict[str, object]) -> dict[str, object]:
    """Project only reviewed, payload-free late-intervention log fields.

    Missing values intentionally remain absent.  In particular, a case default
    such as ``response_committed=false`` is not runtime evidence for an
    uncommitted pre-commit deny.
    """
    output: dict[str, object] = {}

    def first(*names: str) -> object | None:
        for name in names:
            if name in metadata:
                return metadata[name]
        return None

    requested = _phase4_action(
        first("requested_action", "wanted_action"),
        {"deny", "redirect", "drop", "log_only", "abort_connection"},
    )
    actual = _phase4_action(
        first("actual_action"),
        {"deny", "redirect", "log_only", "abort_connection"},
    )
    if requested is not None:
        output["requested_action"] = requested
    if actual is not None:
        output["actual_action"] = actual
    for canonical, aliases in {
        "http_status": ("http_status", "waf_status", "intervention_status"),
        "original_http_status": ("original_http_status", "upstream_status"),
        "visible_http_status": ("visible_http_status", "client_status"),
    }.items():
        value = first(*aliases)
        if value is not None:
            output[canonical] = value
    for canonical, aliases in {
        "late_intervention": ("late_intervention", "intervention"),
        "headers_sent": ("headers_sent", "header_sent"),
        "response_started": ("response_started",),
        "body_started": ("body_started", "response_body_seen"),
        "body_truncated": ("body_truncated", "response_body_truncated"),
        "response_committed": ("response_committed",),
        "connection_aborted": ("connection_aborted", "strict_abort"),
    }.items():
        value = _phase4_bool(first(*aliases))
        if value is not None:
            output[canonical] = value
    transport = first("transport_result", "observed_transport_result")
    if transport is not None:
        normalized_transport = str(transport).strip().lower().replace("-", "_")
        if normalized_transport == "aborted":
            normalized_transport = "connection_aborted"
        if normalized_transport in {
            "http_status", "log_only", "connection_aborted", "not_observable",
        }:
            output["transport_result"] = normalized_transport
    mode = first("late_intervention_mode", "phase4_mode")
    if mode is not None:
        normalized_mode = str(mode).strip().lower()
        if normalized_mode in {"minimal", "safe", "strict"}:
            output["late_intervention_mode"] = normalized_mode
    scope = first("content_type_scope", "scope_result")
    if scope is not None:
        normalized_scope = str(scope).strip().lower().replace("-", "_")
        if normalized_scope in {"in_scope", "out_of_scope", "missing"}:
            output["content_type_scope"] = normalized_scope
    limit_outcome = first("body_limit_outcome", "limit_outcome")
    if limit_outcome is not None:
        normalized_limit = str(limit_outcome).strip().lower().replace("-", "_")
        if normalized_limit in {"at_limit", "over_limit", "process_partial", "reject"}:
            output["body_limit_outcome"] = normalized_limit
    for canonical, aliases in {
        "marker_split_across_chunks": ("marker_split_across_chunks",),
        "end_of_stream_evaluation": ("end_of_stream_evaluation",),
        "no_full_response_buffering": ("no_full_response_buffering",),
        "first_byte_before_response_end": ("first_byte_before_response_end",),
        "upstream_response_finished_at_first_byte": (
            "upstream_response_finished_at_first_byte",
            "upstream_response_complete_at_first_byte",
        ),
        "client_first_byte_received": ("client_first_byte_received",),
        "upstream_paused": ("upstream_paused",),
        "upstream_eos_sent_at_first_byte": ("upstream_eos_sent_at_first_byte",),
        "connection_reused": ("connection_reused", "keep_alive_reused"),
        "client_aborted": ("client_aborted",),
        "upstream_aborted": ("upstream_aborted",),
    }.items():
        value = _phase4_bool(first(*aliases))
        if value is not None:
            output[canonical] = value
    first_chunk_size = first("first_chunk_size")
    if first_chunk_size is not None:
        try:
            normalized_first_chunk_size = int(first_chunk_size)
        except (TypeError, ValueError):
            normalized_first_chunk_size = -1
        if normalized_first_chunk_size >= 0:
            output["first_chunk_size"] = normalized_first_chunk_size
    protocol = first("transport_protocol", "protocol")
    if protocol is not None:
        normalized_protocol = str(protocol).strip().lower().replace("/", "").replace(".", "")
        if normalized_protocol in {"http1", "http11"}:
            output["transport_protocol"] = "http1"
        elif normalized_protocol == "http2":
            output["transport_protocol"] = "http2"
    transfer_encoding = first("transfer_encoding",)
    if transfer_encoding is not None:
        normalized_encoding = str(transfer_encoding).strip().lower().replace("-", "_")
        if normalized_encoding in {"content_length", "chunked", "none"}:
            output["transfer_encoding"] = normalized_encoding
    return output


def materialize(args: argparse.Namespace) -> int:
    case = load_case(args.case)
    write_rules_file(
        case,
        args.rules_file,
        args.audit_log_file,
        args.audit_log_dir,
        args.rules_preamble_file or None,
    )
    if args.headers_file:
        write_headers_file(case, args.headers_file)
    if args.body_file:
        write_body_file(case, args.body_file)
    if args.docroot:
        write_response_fixture(case, args.docroot)
    write_nginx_runtime_files(
        case,
        args.nginx_location_directives_file,
        args.nginx_runtime_config_dir,
        args.nginx_phase4_log_file,
    )
    write_shell_env(
        case,
        args.env_file,
        args.headers_file,
        args.body_file,
        args.audit_log_file,
        args.audit_log_dir,
    )
    return 0


def assert_status(args: argparse.Namespace) -> int:
    case = load_case(args.case)
    phase4_log_file = args.phase4_log_file or args.nginx_phase4_log_file
    errors = assert_case_artifacts(
        case,
        {
            "status": int(args.actual_status),
            "transport": args.observed_transport_result or "http_status",
        },
        args.response_body_file,
        args.audit_log_file,
        phase4_log_file,
    )
    status_file = Path(args.status_file) if args.status_file else None
    if errors:
        message = "; ".join(errors)
        if status_file is not None:
            with status_file.open("a", encoding="utf-8") as handle:
                handle.write(f"fail: {message}\n")
        print(message, file=sys.stderr)
        return 1
    expected = effective_expect(case)["status"]
    if status_file is not None:
        with status_file.open("a", encoding="utf-8") as handle:
            handle.write(f"pass: {case['name']} HTTP {expected} observed\n")
    print(f"pass: {case['name']} HTTP {expected} observed")
    return 0


def write_audit_log_fixture(args: argparse.Namespace) -> int:
    case = load_case(args.case)
    audit_log = expected_audit_log(case)
    content = "\n".join(
        str(value)
        for key, value in audit_log.items()
        if key != "required" and value not in (None, "")
    )
    output = Path(args.audit_log_file)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(content + ("\n" if content else ""), encoding="utf-8")
    return 0


def list_cases(args: argparse.Namespace) -> int:
    cases = discover_case_files(
        args.connector_root or args.repo_root,
        args.connector,
        args.scope,
        args.smoke_cases or "",
        args.test_case or "",
        args.framework_root,
    )
    for case_path in cases:
        print(case_path)
    return 0


def case_info(args: argparse.Namespace) -> int:
    case = load_case(args.case)
    actual_status = int(args.actual_status) if args.actual_status not in (None, "") else None
    phase4_log_file = args.phase4_log_file or args.nginx_phase4_log_file
    info = build_case_info(
        case,
        args.case,
        args.connector,
        args.status,
        actual_status,
    )
    capabilities = set(str(value) for value in info.get("capabilities", []))
    phase4_related = (
        str(info.get("category", "")).strip() == "response-body"
        or "phase4" in capabilities
        or "response-body" in capabilities
    )
    if phase4_related:
        info.setdefault("phase", 4)
    info["observed_status"] = actual_status
    info["observed_transport_result"] = args.observed_transport_result or "http_status"
    if args.reason:
        info["reason"] = args.reason
    if args.output:
        info["evidence_path"] = args.output
    if args.audit_log_file:
        info["audit_log_path"] = args.audit_log_file
    if args.response_body_file:
        info["response_body_path"] = args.response_body_file
    if args.access_log_file:
        key = f"{args.connector}_access_log_path" if args.connector else "access_log_path"
        info[key] = args.access_log_file
    if args.error_log_file:
        key = f"{args.connector}_error_log_path" if args.connector else "error_log_path"
        info[key] = args.error_log_file
    if phase4_log_file:
        info["connector_phase4_log_path"] = phase4_log_file
        metadata = phase4_log_metadata(phase4_log_file)
        for key in (
            "phase",
            "response_headers_seen",
            "response_started",
            "response_body_seen",
            "response_body_truncated",
            "body_truncated",
            "observed_transport_result",
            "rule_id",
            "body_bytes_seen",
            "body_bytes_inspected",
            "truncated",
            "content_type",
        ):
            if key in metadata:
                info[key] = metadata[key]
        info.update(phase4_runtime_evidence(metadata))
    output = Path(args.output) if args.output else None
    content = (
        json.dumps(info, sort_keys=True) + "\n"
        if output is not None
        else json.dumps(info, indent=2, sort_keys=True) + "\n"
    )
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(content, encoding="utf-8")
    else:
        print(content, end="")
    return 0


def read_jsonl(path: Path) -> list[dict[str, object]]:
    entries = []
    if path.exists():
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    entries.append(json.loads(line))
    return entries


def connector_summary(args: argparse.Namespace, entries: list[dict[str, object]]) -> dict[str, object]:
    context = summary_context(args)
    summary = build_connector_summary(
        connector=args.connector,
        entries=entries,
        import_status_file=args.import_status_file,
        context=context,
    )
    counts = summary.get("summary", {})
    summary["runtime_mode"] = args.runtime_mode
    summary["attempted"] = len(entries)
    summary["total_cases"] = len(entries)
    summary["evidence_root"] = str(Path(args.summary_json).parent)
    summary["jsonl_path"] = args.input_jsonl
    summary["per_case_result_root"] = args.per_case_result_root or ""
    summary["command"] = args.command or ""
    summary["exit_status"] = args.exit_status
    summary["run_id"] = args.run_id or os.environ.get("SMOKE_RUN_ID", "")
    summary["run_started_at"] = args.run_started_at or os.environ.get("SMOKE_RUN_STARTED_AT", "")
    if isinstance(counts, dict):
        summary["failed_due_to_live_mismatches"] = bool(counts.get("fail", 0))
    return summary


def summary_context(args: argparse.Namespace) -> SummaryContext:
    return SummaryContext(
        connector_path=args.connector_path,
        validation_mode=args.validation_mode,
        environment=args.environment,
        server=args.server or "",
        server_binary=args.server_binary or "",
        module=args.module or "",
        libmodsecurity=args.libmodsecurity or "",
        origin_source=args.origin_source or "",
        origin_source_repo=args.origin_source_repo or "",
        origin_source_url=args.origin_source_url or "",
        origin_source_commit=args.origin_source_commit or "",
        origin_source_version=args.origin_source_version or "",
        origin_license=args.origin_license or "",
        origin_imported_path=args.origin_imported_path or "",
    )


def write_summary_text(entries: list[dict[str, object]], path: Path) -> None:
    lines = []
    for entry in entries:
        status = str(entry.get("status", "fail")).upper()
        scope = str(entry.get("scope", "unknown"))
        name = str(entry.get("name", "unknown"))
        expected = entry.get("expected_status")
        actual = entry.get("actual_status")
        suffix = f"expected={expected}" if actual is None else f"expected={expected} actual={actual}"
        lines.append(f"{status} {scope} {name} {suffix}\n")
    path.write_text("".join(lines), encoding="utf-8")


def summarize_results(args: argparse.Namespace) -> int:
    entries = read_jsonl(Path(args.input_jsonl))
    summary = {args.connector: connector_summary(args, entries)}
    summary_json = Path(args.summary_json)
    summary_json.parent.mkdir(parents=True, exist_ok=True)
    summary_json.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_summary_text(entries, Path(args.summary_text))
    return 0


def summarize_empty(args: argparse.Namespace) -> int:
    summary = {
        args.connector: empty_connector_summary(
            connector=args.connector,
            status=args.status,
            context=summary_context(args),
        )
    }
    summary_json = Path(args.summary_json)
    summary_json.parent.mkdir(parents=True, exist_ok=True)
    summary_json.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    summary_text = Path(args.summary_text)
    summary_text.parent.mkdir(parents=True, exist_ok=True)
    summary_text.write_text(
        f"{args.status.upper()} {args.connector}-build {args.message}\n",
        encoding="utf-8",
    )
    return 0


def validate_expected_summary_fields(summary: dict[str, object], args: argparse.Namespace) -> list[str]:
    errors: list[str] = []
    expected_fields = {
        "connector_path": args.connector_path,
        "validation_mode": args.validation_mode,
        "server": args.server,
    }
    for key, expected in expected_fields.items():
        if summary.get(key) != expected:
            errors.append(f"{key} expected {expected!r}, got {summary.get(key)!r}")
    return errors


def validate_summary_schema(summary: dict[str, object]) -> list[str]:
    errors: list[str] = []
    environment = summary.get("environment")
    if not (environment in {"local", "github-actions"} or environment):
        errors.append("environment is empty")
    if summary.get("audit_behavior") not in {"stable", "unstable", "unexpected"}:
        errors.append(f"unexpected audit_behavior: {summary.get('audit_behavior')!r}")
    if summary.get("verified_variables") != []:
        errors.append(f"verified_variables expected [], got {summary.get('verified_variables')!r}")
    return errors


def validate_required_summary_keys(summary: dict[str, object]) -> list[str]:
    required_keys = ("server_binary", "module", "libmodsecurity", "summary", "cases")
    return [f"missing summary key: {key}" for key in required_keys if key not in summary]


def validate_real_world_summary(args: argparse.Namespace) -> int:
    data = json.loads(Path(args.summary_json).read_text(encoding="utf-8"))
    summary = data.get(args.connector)
    errors: list[str] = []
    if not isinstance(summary, dict):
        errors.append(f"missing connector summary: {args.connector}")
    else:
        errors.extend(validate_expected_summary_fields(summary, args))
        errors.extend(validate_summary_schema(summary))
        errors.extend(validate_required_summary_keys(summary))
    if errors:
        print("; ".join(errors), file=sys.stderr)
        return 1
    print(f"pass: {args.connector} real-world summary schema")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    materialize_parser = subparsers.add_parser(
        "materialize",
        help="write connector runtime files from a shared YAML case",
    )
    materialize_parser.add_argument("--case", required=True)
    materialize_parser.add_argument("--rules-file", required=True)
    materialize_parser.add_argument("--env-file", required=True)
    materialize_parser.add_argument("--headers-file")
    materialize_parser.add_argument("--body-file")
    materialize_parser.add_argument("--docroot")
    materialize_parser.add_argument("--audit-log-file")
    materialize_parser.add_argument("--audit-log-dir")
    materialize_parser.add_argument(
        "--rules-preamble-file",
        default=os.environ.get("MODSECURITY_RULE_PREAMBLE_FILE", ""),
    )
    materialize_parser.add_argument("--nginx-location-directives-file")
    materialize_parser.add_argument("--nginx-runtime-config-dir")
    materialize_parser.add_argument("--nginx-phase4-log-file")
    materialize_parser.set_defaults(func=materialize)

    assert_parser = subparsers.add_parser(
        "assert-status",
        help="compare an observed HTTP status with a shared YAML case expectation",
    )
    assert_parser.add_argument("--case", required=True)
    assert_parser.add_argument("--actual-status", required=True)
    assert_parser.add_argument("--observed-transport-result", default="http_status")
    assert_parser.add_argument("--status-file")
    assert_parser.add_argument("--response-body-file")
    assert_parser.add_argument("--audit-log-file")
    assert_parser.add_argument("--phase4-log-file")
    assert_parser.add_argument("--nginx-phase4-log-file")
    assert_parser.set_defaults(func=assert_status)

    audit_parser = subparsers.add_parser(
        "write-audit-log-fixture",
        help="write audit-log fixture content from a shared YAML case",
    )
    audit_parser.add_argument("--case", required=True)
    audit_parser.add_argument("--audit-log-file", required=True)
    audit_parser.set_defaults(func=write_audit_log_fixture)

    list_parser = subparsers.add_parser(
        "list-cases",
        help="list applicable YAML case paths for a connector and scope",
    )
    list_parser.add_argument("--repo-root", required=True)
    list_parser.add_argument("--framework-root")
    list_parser.add_argument("--connector-root")
    list_parser.add_argument("--connector", required=True, choices=CONNECTOR_CHOICES)
    list_parser.add_argument("--scope", default="all", choices=("common", "connector", "all"))
    list_parser.add_argument("--smoke-cases")
    list_parser.add_argument("--test-case")
    list_parser.set_defaults(func=list_cases)

    info_parser = subparsers.add_parser(
        "case-info",
        help="write normalized case metadata as JSON",
    )
    info_parser.add_argument("--case", required=True)
    info_parser.add_argument("--connector", choices=CONNECTOR_CHOICES)
    info_parser.add_argument("--status")
    info_parser.add_argument("--actual-status")
    info_parser.add_argument("--observed-transport-result", default="http_status")
    info_parser.add_argument("--reason", default="")
    info_parser.add_argument("--response-body-file")
    info_parser.add_argument("--audit-log-file")
    info_parser.add_argument("--access-log-file")
    info_parser.add_argument("--error-log-file")
    info_parser.add_argument("--phase4-log-file")
    info_parser.add_argument("--nginx-phase4-log-file")
    info_parser.add_argument("--output")
    info_parser.set_defaults(func=case_info)

    summarize_parser = subparsers.add_parser(
        "summarize-results",
        help="write connector summary files from JSONL case results",
    )
    summarize_parser.add_argument("--connector", required=True, choices=CONNECTOR_CHOICES)
    summarize_parser.add_argument("--input-jsonl", required=True)
    summarize_parser.add_argument("--summary-json", required=True)
    summarize_parser.add_argument("--summary-text", required=True)
    summarize_parser.add_argument("--import-status-file")
    summarize_parser.add_argument("--connector-path", default="real-world")
    summarize_parser.add_argument("--validation-mode", default="real-world-connector-path")
    summarize_parser.add_argument("--environment")
    summarize_parser.add_argument("--server")
    summarize_parser.add_argument("--server-binary")
    summarize_parser.add_argument("--module")
    summarize_parser.add_argument("--libmodsecurity")
    summarize_parser.add_argument("--origin-source")
    summarize_parser.add_argument("--origin-source-repo")
    summarize_parser.add_argument("--origin-source-url")
    summarize_parser.add_argument("--origin-source-commit")
    summarize_parser.add_argument("--origin-source-version")
    summarize_parser.add_argument("--origin-license")
    summarize_parser.add_argument("--origin-imported-path")
    summarize_parser.add_argument("--runtime-mode", default="default")
    summarize_parser.add_argument("--command", default="")
    summarize_parser.add_argument("--exit-status", default="")
    summarize_parser.add_argument("--run-id", default="")
    summarize_parser.add_argument("--run-started-at", default="")
    summarize_parser.add_argument("--per-case-result-root", default="")
    summarize_parser.set_defaults(func=summarize_results)

    validate_parser = subparsers.add_parser(
        "validate-real-world-summary",
        help="validate the lightweight real-world connector summary schema",
    )
    validate_parser.add_argument("--summary-json", required=True)
    validate_parser.add_argument("--connector", required=True, choices=CONNECTOR_CHOICES)
    validate_parser.add_argument("--connector-path", default="real-world")
    validate_parser.add_argument("--validation-mode", default="real-world-connector-path")
    validate_parser.add_argument("--server", required=True)
    validate_parser.set_defaults(func=validate_real_world_summary)

    empty_parser = subparsers.add_parser(
        "summarize-empty",
        help="write an empty connector summary for blocked or failed preparation",
    )
    empty_parser.add_argument("--connector", required=True, choices=CONNECTOR_CHOICES)
    empty_parser.add_argument("--status", required=True, choices=RESULT_STATUSES)
    empty_parser.add_argument("--message", required=True)
    empty_parser.add_argument("--summary-json", required=True)
    empty_parser.add_argument("--summary-text", required=True)
    empty_parser.add_argument("--connector-path", default="real-world")
    empty_parser.add_argument("--validation-mode", default="real-world-connector-path")
    empty_parser.add_argument("--environment")
    empty_parser.add_argument("--server")
    empty_parser.add_argument("--server-binary")
    empty_parser.add_argument("--module")
    empty_parser.add_argument("--libmodsecurity")
    empty_parser.add_argument("--origin-source")
    empty_parser.add_argument("--origin-source-repo")
    empty_parser.add_argument("--origin-source-url")
    empty_parser.add_argument("--origin-source-commit")
    empty_parser.add_argument("--origin-source-version")
    empty_parser.add_argument("--origin-license")
    empty_parser.add_argument("--origin-imported-path")
    empty_parser.set_defaults(func=summarize_empty)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
