#!/usr/bin/env python3
"""Update the tracked local runtime validation snapshot from smoke summaries."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import yaml


FRAMEWORK_ROOT = Path(__file__).resolve().parents[1]
CONNECTOR_ROOT = Path.cwd()
OUTPUT_ROOT = CONNECTOR_ROOT
REPORT_ROOT = OUTPUT_ROOT / "docs/testing"
SNAPSHOT = REPORT_ROOT / "runtime-validation-snapshot.json"
sys.path.insert(0, str(FRAMEWORK_ROOT / "tests" / "runners"))

from runner_core import case_group, load_case  # noqa: E402


def default_build_root() -> Path:
    state_home = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    return Path(os.environ.get("BUILD_ROOT", state_home / "ModSecurity-conector-build"))


def configure_paths(framework_root: str | Path, connector_root: str | Path, output_root: str | Path | None) -> None:
    global FRAMEWORK_ROOT, CONNECTOR_ROOT, OUTPUT_ROOT, REPORT_ROOT, SNAPSHOT
    FRAMEWORK_ROOT = Path(framework_root).resolve()
    CONNECTOR_ROOT = Path(connector_root).resolve()
    OUTPUT_ROOT = Path(output_root).resolve() if output_root is not None else CONNECTOR_ROOT
    REPORT_ROOT = OUTPUT_ROOT / ("docs/testing" if OUTPUT_ROOT == FRAMEWORK_ROOT else "reports/testing")
    SNAPSHOT = REPORT_ROOT / "runtime-validation-snapshot.json"


def git_value(*args: str) -> str:
    try:
        return subprocess.check_output(["git", *args], cwd=CONNECTOR_ROOT, text=True).strip()
    except Exception:
        return "unknown"


def load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def normalize_case(path: str, build_root: Path) -> str:
    try:
        resolved = Path(path).resolve()
        for root in (CONNECTOR_ROOT, FRAMEWORK_ROOT):
            try:
                return str(resolved.relative_to(root))
            except ValueError:
                continue
        return str(resolved)
    except Exception:
        return path


def case_metadata(path: str) -> dict[str, str]:
    relative = normalize_case(path, default_build_root())
    candidate_paths = [CONNECTOR_ROOT / relative, FRAMEWORK_ROOT / relative]
    case_path = next((candidate for candidate in candidate_paths if candidate.exists()), candidate_paths[0])
    try:
        case = load_case(case_path)
    except Exception:
        try:
            raw = yaml.safe_load(case_path.read_text(encoding="utf-8"))
            case = raw if isinstance(raw, dict) else {}
        except Exception:
            case = {}
    status = str(case.get("status", "") or "")
    text = " ".join(
        [
            relative,
            status,
            str(case.get("category", "") or ""),
            str(case.get("notes", "") or ""),
            str(case.get("source", "") or ""),
        ]
    ).lower()
    group = case_group(case_path)
    if "connector_gap" in text or "connector-gap" in text:
        classification = "connector_gap"
    elif "runtime_difference" in text or "runtime-difference" in text or "runtime_diff" in text:
        classification = "runtime_difference"
    elif "future" in text or "experimental" in text:
        classification = "future"
    elif "pending" in text:
        classification = "pending"
    elif group == "xfail" or status == "xfail":
        classification = "xfail"
    else:
        classification = "active"
    return {
        "yaml_status": status or "unknown",
        "case_group": group,
        "classification": classification,
    }


def matrix_status(result_status: str, classification: str) -> str:
    status = result_status.strip().lower()
    if status == "blocked":
        return "BLOCKED"
    if status == "skipped":
        return "NOT_EXECUTABLE"
    if status not in {"pass", "fail"}:
        return status.upper() if status else "UNKNOWN"
    suffix = "PASS" if status == "pass" else "FAIL"
    if classification == "active":
        return suffix
    if classification == "connector_gap":
        return f"CONNECTOR_GAP_{suffix}"
    if classification == "runtime_difference":
        return f"RUNTIME_DIFFERENCE_{suffix}"
    if classification == "pending":
        return f"PENDING_{suffix}"
    if classification == "future":
        return f"FUTURE_{suffix}"
    return f"XFAIL_{suffix}"


def case_rows(summary: dict, connector: str, build_root: Path, summary_path: Path) -> list[dict]:
    connector_summary = summary.get(connector)
    if not isinstance(connector_summary, dict):
        return []
    cases = connector_summary.get("cases", {})
    if not isinstance(cases, dict):
        return []
    rows = []
    for name, item in sorted(cases.items()):
        if not isinstance(item, dict):
            continue
        status = str(item.get("status", "unknown"))
        metadata = case_metadata(str(item.get("path", "")))
        expected = item.get("expected_status")
        actual = item.get("actual_status")
        evidence = f"{summary_path}; case={name}; status={status}"
        if expected is not None or actual is not None:
            evidence += f"; expected={expected}; actual={actual}"
        rows.append(
            {
                "case": str(name),
                "path": normalize_case(str(item.get("path", "")), build_root),
                "status": status,
                "matrix_status": matrix_status(status, metadata["classification"]),
                "runtime_attempted": True,
                "operation_status": item.get("operation_status", "unknown"),
                "expected_status": expected,
                "actual_status": actual,
                "scope": item.get("scope", "unknown"),
                "group": item.get("group", "unknown"),
                "yaml_status": metadata["yaml_status"],
                "runtime_classification": metadata["classification"],
                "capabilities": item.get("capabilities", []),
                "evidence": evidence,
                "not_auto_promoted": metadata["classification"] != "active",
            }
        )
    return rows


def connector_smoke(
    connector: str,
    command: str,
    exit_code: str,
    summary_path: Path,
    text_summary_path: Path,
    build_root: Path,
) -> dict:
    summary_data = load_json(summary_path)
    connector_summary = summary_data.get(connector, {}) if isinstance(summary_data, dict) else {}
    counts = connector_summary.get("summary", {}) if isinstance(connector_summary, dict) else {}
    if not isinstance(counts, dict):
        counts = {}
    rows = case_rows(summary_data, connector, build_root, summary_path)
    status = "NOT_RUN"
    if exit_code not in {"not_run", ""}:
        try:
            status = "PASS" if int(exit_code) == 0 else "FAIL"
        except ValueError:
            status = "UNKNOWN"
    if counts.get("blocked", 0):
        status = "BLOCKED" if status == "PASS" else status
    failed_cases = [
        {
            "case": row["case"],
            "expected": row.get("expected_status"),
            "actual": row.get("actual_status"),
            "assessment": "runtime summary reported non-pass",
        }
        for row in rows
        if row.get("status") not in {"pass"}
    ]
    return {
        "command": command,
        "connector": connector,
        "status": status,
        "exit_code": int(exit_code) if exit_code.isdigit() else exit_code,
        "summary_path": str(summary_path),
        "text_summary_path": str(text_summary_path),
        "counts": {
            "pass": counts.get("pass", 0),
            "fail": counts.get("fail", 0),
            "blocked": counts.get("blocked", 0),
            "skipped": counts.get("skipped", 0),
            "xfail": counts.get("xfail", 0),
        },
        "verified_variables": connector_summary.get("verified_variables", []) if isinstance(connector_summary, dict) else [],
        "failed_cases": failed_cases,
        "cases": rows,
        "details": "Per-case results are copied from the local smoke summary JSON; they are runtime evidence only and do not promote YAML xfail/pending status.",
    }


def load_existing_snapshot() -> dict:
    data = load_json(SNAPSHOT)
    return data if data else {}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-root", default=str(default_build_root()))
    parser.add_argument("--framework-root", default=str(FRAMEWORK_ROOT))
    parser.add_argument("--connector-root", default=str(Path.cwd()))
    parser.add_argument("--output-root")
    parser.add_argument("--apache-exit-code", default="not_run")
    parser.add_argument("--nginx-exit-code", default="not_run")
    parser.add_argument("--apache-command", default="REFRESH=1 make smoke-apache")
    parser.add_argument("--nginx-command", default="REFRESH=1 make smoke-nginx")
    parser.add_argument("--force-all", action="store_true")
    args = parser.parse_args()
    configure_paths(args.framework_root, args.connector_root, args.output_root)

    build_root = Path(args.build_root)
    results_dir = build_root / "results"
    existing = load_existing_snapshot()
    now = datetime.now(ZoneInfo("Europe/Berlin"))

    snapshot = {
        "snapshot_date": now.date().isoformat(),
        "captured_at": now.strftime("%Y-%m-%d %H:%M:%S %Z"),
        "branch": git_value("branch", "--show-current"),
        "commit": git_value("rev-parse", "--short", "HEAD"),
        "build_root": str(build_root),
        "force_all_cases": args.force_all,
        "notes": [
            "Runtime matrix snapshot generated from local Apache and NGINX smoke summary JSON files.",
            "Per-case PASS/FAIL/BLOCKED/XFAIL values are runtime evidence for this local run only.",
            "No xfail/pending YAML case is promoted by this snapshot.",
            "RESPONSE_BODY remains non-verified/non-promoted, including pass-through response-body probes.",
            "Mapped-only import inventory entries remain visible but are not executed runtime cases.",
            "make smoke-all is not implied by separate Apache/NGINX runtime matrix runs.",
        ],
        "framework_checks": existing.get("framework_checks", []),
        "readiness_checks": existing.get("readiness_checks", []),
        "runtime_smokes": [
            connector_smoke(
                "apache",
                f"FORCE_ALL_CASES=1 {args.apache_command}" if args.force_all else args.apache_command,
                str(args.apache_exit_code),
                results_dir / "apache-summary.json",
                results_dir / "apache-summary.txt",
                build_root,
            ),
            connector_smoke(
                "nginx",
                f"FORCE_ALL_CASES=1 {args.nginx_command}" if args.force_all else args.nginx_command,
                str(args.nginx_exit_code),
                results_dir / "nginx-summary.json",
                results_dir / "nginx-summary.txt",
                build_root,
            ),
            {
                "command": "REFRESH=1 make smoke-all",
                "connector": "all",
                "status": "NOT_RUN",
                "exit_code": "not_run",
                "summary_path": "not available",
                "counts": {
                    "pass": "unknown",
                    "fail": "unknown",
                    "blocked": "unknown",
                    "skipped": "unknown",
                    "xfail": "unknown",
                },
                "failed_cases": [],
                "cases": [],
                "details": "Not run by runtime-matrix; no full-smoke PASS numbers claimed.",
            },
        ],
        "runtime_verified_status": [
            "Runtime matrix records current local Apache and NGINX per-case smoke evidence.",
            "PASS in this snapshot means the case was executed by that connector's smoke harness and matched the case expectation in the summary JSON.",
            "XFAIL, pending, connector-gap, runtime-difference, future, and mapped-only inventory are not promoted by this snapshot.",
            "FORCE_ALL_CASES=1 attempts xfail/pending/future/gap YAML cases where they are applicable to the connector.",
            "RESPONSE_BODY remains non-verified/non-promoted.",
            "make smoke-all was not run by runtime-matrix; full-smoke PASS counts remain unknown.",
        ],
        "open_issues": [
            "Mapped-only import inventory entries are not executable YAML runtime cases.",
            "XFAIL/pending/future/connector-gap/runtime-difference cases require separate evidence before any status change.",
            "RESPONSE_BODY remains experimental/non-verified.",
        ],
    }
    SNAPSHOT.parent.mkdir(parents=True, exist_ok=True)
    SNAPSHOT.write_text(json.dumps(snapshot, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
