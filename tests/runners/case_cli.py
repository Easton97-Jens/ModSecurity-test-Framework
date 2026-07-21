"""CLI bridge for shared YAML cases used by connector harnesses."""

from __future__ import annotations

import argparse
import json
import os
import re
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
    write_contained_text_file,
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


def _protocol(value: object) -> str | None:
    """Normalize only explicit protocol-observation fields.

    The legacy ``transport_protocol`` field is intentionally handled
    separately below.  In particular, an ambiguous historical ``protocol``
    field must not manufacture negotiated H2/H3 evidence.
    """
    if value in (None, ""):
        return None
    normalized = str(value).strip().lower().replace("_", "").replace(" ", "")
    return {
        "http1": "http1",
        "http/1": "http1",
        "http/1.0": "http1",
        "http/1.1": "http1",
        "http10": "http1",
        "http11": "http1",
        "h1": "http1",
        "h2": "h2",
        "http2": "h2",
        "http/2": "h2",
        "http/2.0": "h2",
        "h2c": "h2c",
        "http2c": "h2c",
        "http/2c": "h2c",
        "h3": "h3",
        "http3": "h3",
        "http/3": "h3",
        "http/3.0": "h3",
    }.get(normalized)


def _transport(value: object) -> str | None:
    if value in (None, ""):
        return None
    normalized = str(value).strip().lower().replace("/", "_").replace("-", "_")
    return {
        "tcp": "tcp",
        "tls_tcp": "tls_tcp",
        "tlstcp": "tls_tcp",
        "quic_udp": "quic_udp",
        "quicudp": "quic_udp",
    }.get(normalized)


def _bounded_token(value: object, *, maximum: int, allow_slash: bool = False) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    pattern = r"[A-Za-z0-9:._/-]+" if allow_slash else r"[A-Za-z0-9:._-]+"
    if not normalized or len(normalized) > maximum or re.fullmatch(pattern, normalized) is None:
        return None
    return normalized


def _first_metadata_value(metadata: dict[str, object], *names: str) -> object | None:
    return next((metadata[name] for name in names if name in metadata), None)


def _project_values(
    output: dict[str, object], metadata: dict[str, object], aliases: dict[str, tuple[str, ...]], normalize
) -> None:
    for canonical, names in aliases.items():
        value = normalize(_first_metadata_value(metadata, *names))
        if value is not None:
            output[canonical] = value


def _identity(value: object | None) -> object | None:
    return value


def _allowed_value(value: object | None, allowed: set[str], *, spaces: bool = False) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip().lower().replace("-", "_")
    if spaces:
        normalized = normalized.replace(" ", "_")
    return normalized if normalized in allowed else None


def _lowercase_allowed_value(value: object | None, allowed: set[str]) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip().lower()
    return normalized if normalized in allowed else None


def _project_phase4_actions(output: dict[str, object], metadata: dict[str, object]) -> None:
    actions = {
        "requested_action": (("requested_action", "wanted_action"), {"deny", "redirect", "drop", "log_only", "abort_connection"}),
        "actual_action": (("actual_action",), {"deny", "redirect", "log_only", "abort_connection", "stream_reset"}),
    }
    for canonical, (aliases, allowed) in actions.items():
        value = _phase4_action(_first_metadata_value(metadata, *aliases), allowed)
        if value is not None:
            output[canonical] = value


def _project_phase4_enums(output: dict[str, object], metadata: dict[str, object]) -> None:
    fields = (
        ("transport_result", ("transport_result", "observed_transport_result"), {"aborted", "completed", "log_only", "connection_aborted", "stream_reset", "client_cancelled", "client_disconnected", "upstream_reset", "upstream_disconnected", "timeout", "short_write", "write_would_block", "engine_error", "host_error", "http_status", "not_observable"}),
        ("late_intervention_mode", ("late_intervention_mode", "phase4_mode"), {"minimal", "safe", "strict"}),
        ("content_type_scope", ("content_type_scope", "scope_result"), {"in_scope", "out_of_scope", "missing"}),
        ("body_limit_outcome", ("body_limit_outcome", "limit_outcome"), {"at_limit", "over_limit", "process_partial", "reject"}),
        ("transfer_encoding", ("transfer_encoding",), {"content_length", "chunked", "none"}),
    )
    for canonical, aliases, allowed in fields:
        raw_value = _first_metadata_value(metadata, *aliases)
        value = (
            _lowercase_allowed_value(raw_value, allowed)
            if canonical == "late_intervention_mode"
            else _allowed_value(raw_value, allowed)
        )
        if canonical == "transport_result" and value == "aborted":
            value = "connection_aborted"
        if value is not None:
            output[canonical] = value


def _project_phase4_protocols(output: dict[str, object], metadata: dict[str, object]) -> None:
    legacy = _first_metadata_value(metadata, "transport_protocol", "protocol")
    normalized_legacy = (
        str(legacy).strip().lower().replace("/", "").replace(".", "")
        if legacy is not None
        else None
    )
    if normalized_legacy not in {"http1", "http11", "http2"}:
        normalized_legacy = None
    if normalized_legacy is not None:
        output["transport_protocol"] = "http1" if normalized_legacy == "http11" else normalized_legacy
    _project_values(output, metadata, {name: (name,) for name in ("requested_protocol", "downstream_protocol", "upstream_protocol", "negotiated_protocol")}, _protocol)
    transport = _transport(_first_metadata_value(metadata, "transport", "network_transport"))
    if transport is not None:
        output["transport"] = transport


def _nonnegative_integer(value: object | None, *, maximum: int | None = None, reject_bool: bool = False) -> int | None:
    if value is None or (reject_bool and isinstance(value, bool)):
        return None
    try:
        normalized = int(value)
    except (TypeError, ValueError):
        return None
    return normalized if normalized >= 0 and (maximum is None or normalized <= maximum) else None


def _project_phase4_identifiers(output: dict[str, object], metadata: dict[str, object]) -> None:
    _project_values(output, metadata, {"alpn": ("alpn", "negotiated_alpn")}, lambda value: _bounded_token(value, maximum=64, allow_slash=True))
    _project_values(output, metadata, {"transport_case_id": ("transport_case_id", "protocol_case_id"), "barrier_id": ("barrier_id",)}, lambda value: _bounded_token(value, maximum=128))
    _project_values(output, metadata, {"quic_version": ("quic_version",)}, lambda value: _bounded_token(value, maximum=64))
    stream_id = _nonnegative_integer(_first_metadata_value(metadata, "stream_id", "http2_stream_id", "http3_stream_id"), maximum=4_611_686_018_427_387_903, reject_bool=True)
    if stream_id is not None:
        output["stream_id"] = stream_id
    for name in ("stream_reset_code", "reset_code"):
        value = _first_metadata_value(metadata, name)
        output_value = _nonnegative_integer(value, reject_bool=True)
        if output_value is None:
            output_value = _bounded_token(value, maximum=64)
        if output_value is not None:
            output[name] = output_value


def _project_phase4_connection(output: dict[str, object], metadata: dict[str, object]) -> None:
    connection_id = _bounded_token(_first_metadata_value(metadata, "connection_id"), maximum=128)
    is_quic = output.get("negotiated_protocol") == "h3" or output.get("downstream_protocol") == "h3" or output.get("transport") == "quic_udp"
    if connection_id is not None and (not is_quic or re.fullmatch(r"sha256:[0-9a-f]{16,64}", connection_id) is not None):
        output["connection_id"] = connection_id


def phase4_runtime_evidence(metadata: dict[str, object]) -> dict[str, object]:
    """Project only reviewed, payload-free late-intervention log fields."""
    output: dict[str, object] = {}
    _project_phase4_actions(output, metadata)
    _project_values(output, metadata, {"http_status": ("http_status", "waf_status", "intervention_status"), "original_http_status": ("original_http_status", "upstream_status"), "visible_http_status": ("visible_http_status", "client_status")}, _identity)
    _project_values(output, metadata, {"late_intervention": ("late_intervention", "intervention"), "headers_sent": ("headers_sent", "header_sent"), "response_started": ("response_started",), "body_started": ("body_started", "response_body_seen"), "body_truncated": ("body_truncated", "response_body_truncated"), "response_committed": ("response_committed",), "connection_aborted": ("connection_aborted", "strict_abort"), "marker_split_across_chunks": ("marker_split_across_chunks",), "end_of_stream_evaluation": ("end_of_stream_evaluation",), "no_full_response_buffering": ("no_full_response_buffering",), "first_byte_before_response_end": ("first_byte_before_response_end",), "upstream_response_finished_at_first_byte": ("upstream_response_finished_at_first_byte", "upstream_response_complete_at_first_byte"), "client_first_byte_received": ("client_first_byte_received",), "upstream_paused": ("upstream_paused",), "upstream_eos_sent_at_first_byte": ("upstream_eos_sent_at_first_byte",), "connection_reused": ("connection_reused", "keep_alive_reused"), "quic_connection_id_present": ("quic_connection_id_present",), "fallback_used": ("fallback_used",), "stream_reset": ("stream_reset", "stream_reset_observed"), "client_aborted": ("client_aborted",), "upstream_aborted": ("upstream_aborted",), "client_disconnected": ("client_disconnected", "client_disconnect"), "upstream_disconnected": ("upstream_disconnected", "upstream_disconnect"), "cancelled": ("cancelled", "client_cancelled"), "eos_seen": ("eos_seen", "eos_received")}, _phase4_bool)
    _project_phase4_enums(output, metadata)
    first_chunk_size = _nonnegative_integer(_first_metadata_value(metadata, "first_chunk_size"))
    if first_chunk_size is not None:
        output["first_chunk_size"] = first_chunk_size
    _project_phase4_protocols(output, metadata)
    _project_phase4_identifiers(output, metadata)
    for canonical, aliases, allowed in (("reset_by", ("reset_by",), {"client", "upstream", "engine", "host", "strict_intervention", "timeout"}), ("timeout_stage", ("timeout_stage",), {"engine", "request_body", "response_body", "upstream", "client_idle", "before_commit", "after_commit"}), ("write_result", ("write_result",), {"completed", "short_write", "write_would_block", "engine_error", "host_error"}), ("cleanup_reason", ("cleanup_reason",), {"normal", "cancelled", "client_disconnected", "upstream_disconnected", "stream_reset", "timeout", "engine_error", "host_error", "strict_abort"})):
        value = _allowed_value(_first_metadata_value(metadata, *aliases), allowed, spaces=True)
        if value is not None:
            output[canonical] = value
    _project_phase4_connection(output, metadata)
    return output


def materialize(args: argparse.Namespace) -> int:
    case = load_case(args.case)
    output_root = _materialize_output_root(args)
    write_rules_file(
        case,
        args.rules_file,
        output_root=output_root,
        audit_log_file=args.audit_log_file,
        audit_log_dir=args.audit_log_dir,
        rules_preamble_file=args.rules_preamble_file or None,
    )
    if args.headers_file:
        write_headers_file(case, args.headers_file, output_root=output_root)
    if args.body_file:
        write_body_file(case, args.body_file, output_root=output_root)
    if args.docroot:
        write_response_fixture(case, args.docroot, output_root=output_root)
    write_nginx_runtime_files(
        case,
        args.nginx_location_directives_file,
        args.nginx_runtime_config_dir,
        output_root=output_root,
        phase4_log_file=args.nginx_phase4_log_file,
    )
    write_shell_env(
        case,
        args.env_file,
        output_root=output_root,
        headers_file=args.headers_file,
        body_file=args.body_file,
        audit_log_file=args.audit_log_file,
        audit_log_dir=args.audit_log_dir,
    )
    return 0


def _materialize_output_root(args: argparse.Namespace) -> Path:
    return _required_output_root(args, "materialize")


def _required_output_root(args: argparse.Namespace, operation: str) -> Path:
    configured_root = (
        getattr(args, "output_root", "")
        or os.environ.get("BUILD_ROOT", "")
        or os.environ.get("VERIFIED_RUN_ROOT", "")
    )
    if not configured_root:
        raise ValueError(
            f"{operation} requires --output-root or BUILD_ROOT or VERIFIED_RUN_ROOT"
        )
    return Path(configured_root).resolve()


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


def _add_case_info_context(info: dict[str, object], args: argparse.Namespace, actual_status: int | None) -> None:
    capabilities = {str(value) for value in info.get("capabilities", [])}
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


def _add_phase4_log_evidence(info: dict[str, object], phase4_log_file: str | None) -> None:
    if not phase4_log_file:
        return
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


def _write_or_print_case_info(info: dict[str, object], args: argparse.Namespace) -> None:
    output = args.output or None
    content = (
        json.dumps(info, sort_keys=True) + "\n"
        if output is not None
        else json.dumps(info, indent=2, sort_keys=True) + "\n"
    )
    if output is not None:
        write_contained_text_file(
            output,
            content,
            output_root=_required_output_root(args, "case-info"),
        )
    else:
        print(content, end="")


def case_info(args: argparse.Namespace) -> int:
    case = load_case(args.case)
    actual_status = int(args.actual_status) if args.actual_status not in (None, "") else None
    info = build_case_info(case, args.case, args.connector, args.status, actual_status)
    _add_case_info_context(info, args, actual_status)
    _add_phase4_log_evidence(info, args.phase4_log_file or args.nginx_phase4_log_file)
    _write_or_print_case_info(info, args)
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
    materialize_parser.add_argument("--output-root")
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
    info_parser.add_argument("--output-root")
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
