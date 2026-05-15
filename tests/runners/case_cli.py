"""CLI bridge for shared YAML cases used by connector harnesses."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from runner_core import (
    assert_case_artifacts,
    case_info as build_case_info,
    discover_case_files,
    load_case,
    write_body_file,
    write_headers_file,
    write_response_fixture,
    write_rules_file,
    write_shell_env,
)

RESULT_STATUSES = ("pass", "fail", "blocked", "skipped", "xfail")
IMPORT_STATUS_KEYS = (
    "fully_imported_common",
    "connector_specific",
    "mapped_only",
    "blocked",
    "xfail",
    "v2_imported",
    "v3_imported",
)
VARIABLE_CAPABILITIES = {
    "ARGS": {"query-args", "form-urlencoded"},
    "ARGS_NAMES": {"args-names"},
    "REQUEST_COOKIES": {"request-cookies"},
    "REQUEST_HEADERS": {"request-headers"},
    "REQUEST_URI": {"request-uri"},
    "REQUEST_BODY": {"request-body", "json", "body-processors"},
    "FILES": {"files"},
    "XML": {"xml"},
    "AUDIT_LOG": {"audit-log"},
    "RESPONSE_HEADERS": {"response-headers"},
}


def materialize(args: argparse.Namespace) -> int:
    case = load_case(args.case)
    write_rules_file(case, args.rules_file, args.audit_log_file, args.audit_log_dir)
    if args.headers_file:
        write_headers_file(case, args.headers_file)
    if args.body_file:
        write_body_file(case, args.body_file)
    if args.docroot:
        write_response_fixture(case, args.docroot)
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


def list_cases(args: argparse.Namespace) -> int:
    cases = discover_case_files(
        args.repo_root,
        args.connector,
        args.scope,
        args.smoke_cases or "",
        args.test_case or "",
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


def verified_variables(entries: list[dict[str, object]]) -> list[str]:
    variables = []
    for names in passing_capability_sets(entries):
        for variable, capabilities in VARIABLE_CAPABILITIES.items():
            if names.intersection(capabilities):
                variables.append(variable)
    return sorted(dict.fromkeys(variables))


def passing_capability_sets(entries: list[dict[str, object]]) -> list[set[str]]:
    sets = []
    for entry in entries:
        if str(entry.get("status", "")) != "pass":
            continue
        capabilities = entry.get("capabilities", [])
        if isinstance(capabilities, list):
            sets.append({str(item) for item in capabilities})
    return sets


def read_jsonl(path: Path) -> list[dict[str, object]]:
    entries = []
    if path.exists():
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    entries.append(json.loads(line))
    return entries


def result_counts(entries: list[dict[str, object]]) -> dict[str, int]:
    counts = dict.fromkeys(RESULT_STATUSES, 0)
    for entry in entries:
        status = str(entry.get("status", "fail"))
        counts.setdefault(status, 0)
        counts[status] += 1
    return counts


def import_status_counts(path: str | None) -> dict[str, int]:
    if not path:
        return {}
    import_status_path = Path(path)
    if not import_status_path.exists():
        return {}
    manifest = json.loads(import_status_path.read_text(encoding="utf-8"))
    return {
        key: len(manifest.get(key, []))
        for key in IMPORT_STATUS_KEYS
        if isinstance(manifest.get(key, []), list)
    }


def audit_behavior(entries: list[dict[str, object]], import_status: dict[str, int]) -> str:
    for entry in entries:
        capabilities = entry.get("capabilities", [])
        if str(entry.get("status", "")) == "fail" and isinstance(capabilities, list):
            if {"audit-log", "audit-log-absent"}.intersection({str(item) for item in capabilities}):
                return "unexpected"
    if import_status.get("xfail", 0):
        return "unstable"
    return "stable"


def default_environment() -> str:
    configured = os.environ.get("SMOKE_ENVIRONMENT", "").strip()
    if configured:
        return configured
    if os.environ.get("GITHUB_ACTIONS", "").lower() == "true":
        return "github-actions"
    return "local"


def connector_summary(args: argparse.Namespace, entries: list[dict[str, object]]) -> dict[str, object]:
    cases = {str(entry.get("name", "")): entry for entry in entries}
    import_status = import_status_counts(args.import_status_file)
    summary = {
        "connector_path": args.connector_path,
        "validation_mode": args.validation_mode,
        "environment": args.environment or default_environment(),
        "audit_behavior": audit_behavior(entries, import_status),
        "server": args.server or args.connector,
        "server_binary": args.server_binary or "",
        "module": args.module or "",
        "libmodsecurity": args.libmodsecurity or "",
        "verified_variables": verified_variables(entries),
        "summary": result_counts(entries),
        "cases": cases,
    }
    if import_status:
        summary["import_status"] = import_status
    return summary


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
    assert_parser.set_defaults(func=assert_status)

    list_parser = subparsers.add_parser(
        "list-cases",
        help="list applicable YAML case paths for a connector and scope",
    )
    list_parser.add_argument("--repo-root", required=True)
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
    summarize_parser.set_defaults(func=summarize_results)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
