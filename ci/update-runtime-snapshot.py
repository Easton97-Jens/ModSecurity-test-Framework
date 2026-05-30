#!/usr/bin/env python3
"""Update the tracked local runtime validation snapshot from smoke summaries."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime
from dataclasses import dataclass
from pathlib import Path
from zoneinfo import ZoneInfo

import yaml


FRAMEWORK_ROOT = Path(__file__).resolve().parents[1]
CONNECTOR_ROOT = Path.cwd()
OUTPUT_ROOT = CONNECTOR_ROOT
FRAMEWORK_REPORT_DIR = "docs/testing"
CONNECTOR_REPORT_DIR = "reports/testing"
REPORT_ROOT = OUTPUT_ROOT / FRAMEWORK_REPORT_DIR
SNAPSHOT_FILENAME = "runtime-validation-snapshot.json"
SNAPSHOT = REPORT_ROOT / SNAPSHOT_FILENAME
SNAPSHOT_LAYOUT: "SnapshotLayout | None" = None
sys.path.insert(0, str(FRAMEWORK_ROOT / "tests" / "runners"))

from runner_core import case_group, load_case  # noqa: E402
from response_body_status import (  # noqa: E402
    RESPONSE_BODY_RUNTIME_NOTE,
    is_response_body_related,
    matrix_status_for_result,
    response_body_non_promotion_fields,
)


def default_build_root() -> Path:
    state_home = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    return Path(os.environ.get("BUILD_ROOT", state_home / "ModSecurity-conector-build"))


@dataclass(frozen=True)
class SnapshotLayout:
    output_root: Path
    report_root: Path
    snapshot: Path

    def write(self, snapshot_data: dict) -> None:
        if self.snapshot != build_safe_snapshot_path(self.output_root):
            raise ValueError(f"snapshot path must be the configured report snapshot: {self.snapshot}")
        self.snapshot.parent.mkdir(parents=True, exist_ok=True)
        self.snapshot.write_text(json.dumps(snapshot_data, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def resolve_root(root: str | Path, *, label: str) -> Path:
    try:
        return Path(root).expanduser().resolve()
    except Exception as exc:
        raise ValueError(f"{label} is not a valid path: {root}") from exc


def resolve_under_root(root: Path, candidate: Path, *, label: str) -> Path:
    root = root.resolve()
    candidate = candidate.resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"{label} must stay under {root}: {candidate}") from exc
    return candidate


def resolve_allowed_output_root(output_root: str | Path | None) -> Path:
    requested = resolve_root(output_root, label="output root") if output_root is not None else CONNECTOR_ROOT
    if requested == FRAMEWORK_ROOT:
        return FRAMEWORK_ROOT
    if requested == CONNECTOR_ROOT:
        return CONNECTOR_ROOT
    raise ValueError(f"output root must resolve exactly to the framework root ({FRAMEWORK_ROOT}) or connector root ({CONNECTOR_ROOT}): {requested}")


def report_root_for(output_root: Path) -> Path:
    if output_root == FRAMEWORK_ROOT:
        return resolve_under_root(FRAMEWORK_ROOT, FRAMEWORK_ROOT / FRAMEWORK_REPORT_DIR, label="framework report root")
    if output_root == CONNECTOR_ROOT:
        return resolve_under_root(CONNECTOR_ROOT, CONNECTOR_ROOT / CONNECTOR_REPORT_DIR, label="connector report root")
    raise ValueError(f"unsupported output root: {output_root}")


def build_safe_snapshot_path(output_root: Path) -> Path:
    report_root = report_root_for(output_root)
    return resolve_under_root(report_root, report_root / SNAPSHOT_FILENAME, label="runtime snapshot path")


def build_safe_snapshot_layout(output_root: Path) -> SnapshotLayout:
    report_root = report_root_for(output_root)
    return SnapshotLayout(
        output_root=output_root,
        report_root=report_root,
        snapshot=resolve_under_root(report_root, report_root / SNAPSHOT_FILENAME, label="runtime snapshot path"),
    )


def active_snapshot_layout() -> SnapshotLayout:
    if SNAPSHOT_LAYOUT is None:
        raise RuntimeError("snapshot layout has not been configured")
    return SNAPSHOT_LAYOUT


def configure_paths(framework_root: str | Path, connector_root: str | Path, output_root: str | Path | None) -> None:
    global FRAMEWORK_ROOT, CONNECTOR_ROOT, OUTPUT_ROOT, REPORT_ROOT, SNAPSHOT, SNAPSHOT_LAYOUT
    FRAMEWORK_ROOT = resolve_root(framework_root, label="framework root")
    CONNECTOR_ROOT = resolve_root(connector_root, label="connector root")
    OUTPUT_ROOT = resolve_allowed_output_root(output_root)
    SNAPSHOT_LAYOUT = build_safe_snapshot_layout(OUTPUT_ROOT)
    REPORT_ROOT = SNAPSHOT_LAYOUT.report_root
    SNAPSHOT = SNAPSHOT_LAYOUT.snapshot


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


def first_text_summary_line(path: Path) -> str:
    if not path.exists():
        return ""
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line:
                return line
    except Exception:
        return ""
    return ""


def normalize_case(path: str) -> str:
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


def resolve_case_path(relative: str) -> Path:
    candidate_paths = [CONNECTOR_ROOT / relative, FRAMEWORK_ROOT / relative]
    return next((candidate for candidate in candidate_paths if candidate.exists()), candidate_paths[0])


def load_case_metadata(case_path: Path) -> dict:
    try:
        return load_case(case_path)
    except Exception:
        try:
            raw = yaml.safe_load(case_path.read_text(encoding="utf-8"))
            return raw if isinstance(raw, dict) else {}
        except Exception:
            return {}


def classify_case(relative: str, status: str, case: dict, group: str) -> str:
    text = " ".join(
        [
            relative,
            status,
            str(case.get("category", "") or ""),
            str(case.get("notes", "") or ""),
            str(case.get("source", "") or ""),
        ]
    ).lower()
    if "connector_gap" in text or "connector-gap" in text:
        return "connector_gap"
    if "runtime_difference" in text or "runtime-difference" in text or "runtime_diff" in text:
        return "runtime_difference"
    if "future" in text or "experimental" in text:
        return "future"
    if "pending" in text:
        return "pending"
    if group == "xfail" or status == "xfail":
        return "xfail"
    return "active"


def case_metadata(path: str) -> dict[str, object]:
    relative = normalize_case(path)
    case_path = resolve_case_path(relative)
    case = load_case_metadata(case_path)
    status = str(case.get("status", "active") or "active").strip().lower()
    group = case_group(case_path, case)
    classification = classify_case(relative, status, case, group)
    return {
        "yaml_status": status,
        "case_group": group,
        "classification": classification,
        "response_body_related": is_response_body_related(case, relative),
    }


def matrix_status(result_status: str, classification: str, response_body_related: bool = False) -> str:
    return matrix_status_for_result(
        result_status,
        classification,
        response_body_related=response_body_related,
    )


def case_rows(summary: dict, connector: str, summary_path: Path) -> list[dict]:
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
        response_body_related = bool(metadata["response_body_related"])
        row = {
            "case": str(name),
            "path": normalize_case(str(item.get("path", ""))),
            "status": status,
            "matrix_status": matrix_status(status, metadata["classification"], response_body_related),
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
        }
        row.update(response_body_non_promotion_fields(response_body_related, metadata["classification"]))
        if response_body_related:
            row["response_body_related"] = True
            if status.strip().lower() == "pass":
                row["reason"] = RESPONSE_BODY_RUNTIME_NOTE
        rows.append(row)
    return rows


def connector_smoke(
    connector: str,
    command: str,
    exit_code: str,
    summary_path: Path,
    text_summary_path: Path,
) -> dict:
    summary_data = load_json(summary_path)
    connector_summary = summary_data.get(connector, {}) if isinstance(summary_data, dict) else {}
    counts = connector_summary.get("summary", {}) if isinstance(connector_summary, dict) else {}
    if not isinstance(counts, dict):
        counts = {}
    rows = case_rows(summary_data, connector, summary_path)
    status = "NOT_RUN"
    if exit_code not in {"not_run", ""}:
        try:
            status = "PASS" if int(exit_code) == 0 else "FAIL"
        except ValueError:
            status = "UNKNOWN"
    if counts.get("blocked", 0):
        status = "BLOCKED" if status == "PASS" else status
    build_status = (
        str(connector_summary.get("build", "")).strip()
        if isinstance(connector_summary, dict) and connector_summary.get("build") is not None
        else ""
    )
    per_case_results = "available" if rows else "unavailable"
    evidence_note = first_text_summary_line(text_summary_path)
    unavailable_reason = ""
    blocker: dict[str, object] = {}
    if not rows and status in {"FAIL", "BLOCKED", "UNKNOWN"}:
        reason_parts = [f"{connector.upper()} did not complete per-case runtime execution"]
        if build_status:
            reason_parts.append(f"build={build_status}")
        if exit_code not in {"", "not_run"}:
            reason_parts.append(f"exit_code={exit_code}")
        if evidence_note:
            reason_parts.append(evidence_note)
        unavailable_reason = "; ".join(reason_parts)
        blocker = {
            "reason": unavailable_reason,
            "summary_path": str(summary_path),
            "text_summary_path": str(text_summary_path),
            "evidence_note": evidence_note,
        }
    failed_cases = [
        {
            "case": row["case"],
            "expected": row.get("expected_status"),
            "actual": row.get("actual_status"),
            "assessment": "runtime summary reported non-pass",
            "evidence": row.get("evidence", str(summary_path)),
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
        "build_status": build_status or "unknown",
        "per_case_results": per_case_results,
        "per_case_unavailable_reason": unavailable_reason,
        "per_case_unavailable_evidence": evidence_note,
        "blocker": blocker,
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


def validated_snapshot_path() -> Path:
    snapshot_path = SNAPSHOT.resolve()
    if snapshot_path.name != SNAPSHOT_FILENAME:
        raise ValueError(f"unexpected snapshot file name: {snapshot_path}")
    expected_snapshot_path = build_safe_snapshot_path(OUTPUT_ROOT)
    if snapshot_path != expected_snapshot_path:
        raise ValueError(f"snapshot path must be the configured report snapshot: {snapshot_path}")
    return snapshot_path


def write_snapshot(snapshot: dict) -> None:
    if validated_snapshot_path() != active_snapshot_layout().snapshot:
        raise ValueError("snapshot path validation mismatch")
    active_snapshot_layout().write(snapshot)


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
            "Runtime-passing RESPONSE_BODY cases are marked non-promotable pass-through evidence.",
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
            ),
            connector_smoke(
                "nginx",
                f"FORCE_ALL_CASES=1 {args.nginx_command}" if args.force_all else args.nginx_command,
                str(args.nginx_exit_code),
                results_dir / "nginx-summary.json",
                results_dir / "nginx-summary.txt",
            ),
            {
                "command": "REFRESH=1 make smoke-all",
                "connector": "all",
                "status": "NOT_RUN",
                "exit_code": "not_run",
                "summary_path": "not available",
                "text_summary_path": "not available",
                "build_status": "not_run",
                "per_case_results": "not_run",
                "per_case_unavailable_reason": "Full smoke-all was not run by runtime-matrix.",
                "per_case_unavailable_evidence": "",
                "blocker": {},
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
            "Runtime passed, but this does not verify RESPONSE_BODY support.",
            "make smoke-all was not run by runtime-matrix; full-smoke PASS counts remain unknown.",
        ],
        "open_issues": [
            "Mapped-only import inventory entries are not executable YAML runtime cases.",
            "XFAIL/pending/future/connector-gap/runtime-difference cases require separate evidence before any status change.",
            "RESPONSE_BODY remains experimental/non-verified.",
        ],
    }
    write_snapshot(snapshot)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
