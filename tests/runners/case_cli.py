"""CLI bridge for shared YAML cases used by connector harnesses."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from msconnector_models import (
    RESULT_STATUSES,
    SummaryContext,
    connector_summary as build_connector_summary,
    empty_connector_summary,
)
from runner_core import (
    assert_case_artifacts,
    case_info as build_case_info,
    discover_case_files,
    expected_audit_log,
    load_case,
    write_body_file,
    write_headers_file,
    write_response_fixture,
    write_rules_file,
    write_shell_env,
    write_nginx_runtime_files,
)


def materialize(args: argparse.Namespace) -> int:
    case = load_case(args.case)
    write_rules_file(case, args.rules_file, args.audit_log_file, args.audit_log_dir)
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
    errors = assert_case_artifacts(
        case,
        {"status": int(args.actual_status)},
        args.response_body_file,
        args.audit_log_file,
        args.nginx_phase4_log_file,
    )
    status_file = Path(args.status_file) if args.status_file else None
    if errors:
        message = "; ".join(errors)
        if status_file is not None:
            with status_file.open("a", encoding="utf-8") as handle:
                handle.write(f"fail: {message}\n")
        print(message, file=sys.stderr)
        return 1
    expected = case["expect"]["status"]
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
    info = build_case_info(
        case,
        args.case,
        args.connector,
        args.status,
        actual_status,
    )
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
    return build_connector_summary(
        connector=args.connector,
        entries=entries,
        import_status_file=args.import_status_file,
        context=context,
    )


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
    assert_parser.add_argument("--status-file")
    assert_parser.add_argument("--response-body-file")
    assert_parser.add_argument("--audit-log-file")
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
    list_parser.add_argument("--connector", required=True, choices=("apache", "nginx"))
    list_parser.add_argument("--scope", default="all", choices=("common", "connector", "all"))
    list_parser.add_argument("--smoke-cases")
    list_parser.add_argument("--test-case")
    list_parser.set_defaults(func=list_cases)

    info_parser = subparsers.add_parser(
        "case-info",
        help="write normalized case metadata as JSON",
    )
    info_parser.add_argument("--case", required=True)
    info_parser.add_argument("--connector", choices=("apache", "nginx"))
    info_parser.add_argument("--status")
    info_parser.add_argument("--actual-status")
    info_parser.add_argument("--output")
    info_parser.set_defaults(func=case_info)

    summarize_parser = subparsers.add_parser(
        "summarize-results",
        help="write connector summary files from JSONL case results",
    )
    summarize_parser.add_argument("--connector", required=True, choices=("apache", "nginx"))
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
    summarize_parser.set_defaults(func=summarize_results)

    validate_parser = subparsers.add_parser(
        "validate-real-world-summary",
        help="validate the lightweight real-world connector summary schema",
    )
    validate_parser.add_argument("--summary-json", required=True)
    validate_parser.add_argument("--connector", required=True, choices=("apache", "nginx"))
    validate_parser.add_argument("--connector-path", default="real-world")
    validate_parser.add_argument("--validation-mode", default="real-world-connector-path")
    validate_parser.add_argument("--server", required=True)
    validate_parser.set_defaults(func=validate_real_world_summary)

    empty_parser = subparsers.add_parser(
        "summarize-empty",
        help="write an empty connector summary for blocked or failed preparation",
    )
    empty_parser.add_argument("--connector", required=True, choices=("apache", "nginx"))
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
