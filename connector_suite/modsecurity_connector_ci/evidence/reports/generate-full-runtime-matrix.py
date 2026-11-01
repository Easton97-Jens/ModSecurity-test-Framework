#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# CI helpers are shared from ci/lib even when this file is executed directly.
import sys

from typing import Any

from modsecurity_connector_ci.lib.generated_report_utils import GENERATED_ROOT, build_metadata, generated_json_text, generated_markdown_text, report_path_from_root, report_relpath
from modsecurity_connector_ci.lib.runtime_path_utils import verified_runtime_paths


CONNECTORS = ("apache", "nginx", "haproxy")
TEST_VARIANTS = ("no-crs", "with-crs")
MRTS_VARIANTS = ("no-mrts", "with-mrts")
DEFAULT_PATHS = verified_runtime_paths(os.environ)
DEFAULT_BUILD_ROOT = Path(os.environ.get("BUILD_ROOT", DEFAULT_PATHS["BUILD_ROOT"])).resolve()
MRTS_BUILD_ROOT = Path(os.environ.get("MRTS_BUILD_ROOT", str(DEFAULT_BUILD_ROOT / "mrts"))).resolve()
MRTS_UPSTREAM_CASE_MARKER = "/upstream-config-tests/framework-cases/"
MRTS_FEATURE_DEMO_CASE_MARKER = "/feature-demo/framework-cases/"
_UTC_OFFSET = "+00:00"
NATIVE_EVIDENCE_REPORTS = {
    "apache": report_relpath("mrts_native_apache", "md"),
    "nginx": report_relpath("mrts_native_nginx", "md"),
    "summary": report_relpath("mrts_native_summary", "md"),
    "combined": report_relpath("mrts_native_full", "md"),
}


@dataclass
class RunRecord:
    connector: str
    test_variant: str
    mrts_variant: str
    return_code: int | None
    results_dir: Path
    summary_path: Path
    log_path: Path
    started_at: str = ""
    ended_at: str = ""
    duration_seconds: int | None = None
    attempted: int = 0
    passed: int = 0
    failed: int = 0
    blocked: int = 0
    not_executable: int = 0
    pending: int = 0
    outcome: str = "NOT_RUN"
    missing_summary: bool = False
    missing_summary_reason: str = ""
    cases: dict[str, dict[str, Any]] = field(default_factory=dict)
    mrts_upstream: Counter[str] = field(default_factory=Counter)
    feature_demo_cases: int = 0


def read_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def manifest_record(item: dict[str, Any]) -> RunRecord:
    return RunRecord(
        connector=item["connector"],
        test_variant=item["test_variant"],
        mrts_variant=item["mrts_variant"],
        return_code=item.get("return_code", item.get("exit_code")),
        results_dir=Path(item["results_dir"]),
        summary_path=Path(item.get("summary_path") or item.get("runtime_summary_path")),
        log_path=Path(item["log_path"]),
        started_at=item.get("started_at", ""),
        ended_at=item.get("ended_at", ""),
        duration_seconds=item.get("duration_seconds"),
    )


def default_record(build_root: Path, log_root: Path, test_variant: str, mrts_variant: str, connector: str) -> RunRecord:
    results_dir = build_root / "results" / "full-matrix" / test_variant / mrts_variant / connector
    return RunRecord(
        connector=connector,
        test_variant=test_variant,
        mrts_variant=mrts_variant,
        return_code=None,
        results_dir=results_dir,
        summary_path=results_dir / f"{connector}-summary.json",
        log_path=log_root / "full-matrix" / test_variant / mrts_variant / f"{connector}.log",
    )


def manifest_records(path: Path) -> list[RunRecord]:
    if not path.is_file():
        return []

    records: list[RunRecord] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        records.append(manifest_record(json.loads(line)))
    return records


def append_missing_manifest_records(records: list[RunRecord], build_root: Path, log_root: Path) -> None:
    by_key = {(record.test_variant, record.mrts_variant, record.connector) for record in records}

    for test_variant in TEST_VARIANTS:
        for mrts_variant in MRTS_VARIANTS:
            for connector in CONNECTORS:
                key = (test_variant, mrts_variant, connector)
                if key in by_key:
                    continue
                records.append(default_record(build_root, log_root, test_variant, mrts_variant, connector))


def load_manifest(path: Path, build_root: Path, log_root: Path) -> list[RunRecord]:
    records = manifest_records(path)
    append_missing_manifest_records(records, build_root, log_root)
    return records


def case_status(case: dict[str, Any]) -> str:
    return str(case.get("status") or case.get("result") or "").lower()


def case_is_pending(case: dict[str, Any]) -> bool:
    values = [
        case.get("case_status"),
        case.get("yaml_status"),
        case.get("framework_status"),
        case.get("metadata", {}).get("status") if isinstance(case.get("metadata"), dict) else None,
    ]
    return any(str(value).lower() == "pending" for value in values if value is not None)


def case_is_mrts_upstream(case: dict[str, Any]) -> bool:
    path = str(case.get("path") or case.get("test_case") or "")
    metadata = case.get("metadata") if isinstance(case.get("metadata"), dict) else {}
    return (
        MRTS_UPSTREAM_CASE_MARKER in path
        or metadata.get("mrts_corpus") == "upstream-config-tests"
    )


def case_is_feature_demo(case: dict[str, Any]) -> bool:
    path = str(case.get("path") or case.get("test_case") or "")
    metadata = case.get("metadata") if isinstance(case.get("metadata"), dict) else {}
    return (
        MRTS_FEATURE_DEMO_CASE_MARKER in path
        or metadata.get("mrts_corpus") == "feature-demo"
    )


def parse_time(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", _UTC_OFFSET))
    except ValueError:
        return None


def duration_seconds(started_at: str, ended_at: str) -> int | None:
    start = parse_time(started_at)
    end = parse_time(ended_at)
    if start is None or end is None:
        return None
    seconds = int((end - start).total_seconds())
    return seconds if seconds >= 0 else None


def summarize_cases(cases: dict[str, dict[str, Any]]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for case in cases.values():
        status = case_status(case)
        if status == "pass":
            counts["pass"] += 1
        elif status == "fail":
            counts["fail"] += 1
        elif status == "blocked":
            counts["blocked"] += 1
        elif status in {"not_executable", "not-executable"}:
            counts["not_executable"] += 1
        if case_is_pending(case):
            counts["pending"] += 1
    return counts


def load_summary_data(record: RunRecord) -> dict[str, Any]:
    raw = read_json(record.summary_path)
    data = raw.get(record.connector, raw) if isinstance(raw, dict) else {}
    if not isinstance(data, dict):
        return {}
    return data


def mark_missing_summary(record: RunRecord) -> None:
    if record.return_code is None and not record.started_at:
        return

    record.outcome = "BLOCKED"
    record.blocked = 1
    record.missing_summary = True
    record.missing_summary_reason = f"summary JSON missing: {record.summary_path}"


def apply_case_counts(record: RunRecord, data: dict[str, Any]) -> None:
    summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    cases = data.get("cases") if isinstance(data.get("cases"), dict) else {}
    record.cases = {str(name): case for name, case in cases.items() if isinstance(case, dict)}
    derived = summarize_cases(record.cases)

    record.attempted = int(data.get("attempted") or data.get("total_cases") or len(record.cases) or 0)
    record.passed = int(summary.get("pass", derived["pass"]) or 0)
    record.failed = int(summary.get("fail", derived["fail"]) or 0)
    record.blocked = int(summary.get("blocked", derived["blocked"]) or 0)
    record.not_executable = int(summary.get("not_executable", derived["not_executable"]) or 0)
    record.pending = int(derived["pending"] or 0)


def apply_mrts_counts(record: RunRecord) -> None:
    for case in record.cases.values():
        if case_is_feature_demo(case):
            record.feature_demo_cases += 1
        if not case_is_mrts_upstream(case):
            continue
        status = case_status(case)
        if status == "pass":
            record.mrts_upstream["pass"] += 1
        elif status == "fail":
            record.mrts_upstream["fail"] += 1
        elif status == "blocked":
            record.mrts_upstream["blocked"] += 1
        elif status in {"not_executable", "not-executable"}:
            record.mrts_upstream["not_executable"] += 1
        if case_is_pending(case):
            record.mrts_upstream["pending"] += 1
        record.mrts_upstream["attempted"] += 1


def apply_record_outcome(record: RunRecord) -> None:
    if record.blocked and record.attempted == 0:
        record.outcome = "BLOCKED"
    elif record.failed or (record.return_code not in (None, 0) and record.return_code != 77):
        record.outcome = "FAIL"
    elif record.return_code == 77:
        record.outcome = "BLOCKED"
    else:
        record.outcome = "PASS"


def populate_record(record: RunRecord) -> None:
    if record.duration_seconds is None:
        record.duration_seconds = duration_seconds(record.started_at, record.ended_at)
    if not record.summary_path.is_file():
        mark_missing_summary(record)
        return

    apply_case_counts(record, load_summary_data(record))
    apply_mrts_counts(record)
    apply_record_outcome(record)


def record_to_json(record: RunRecord) -> dict[str, Any]:
    return {
        "connector": record.connector,
        "test_variant": record.test_variant,
        "mrts_variant": record.mrts_variant,
        "return_code": record.return_code,
        "outcome": record.outcome,
        "attempted": record.attempted,
        "pass": record.passed,
        "fail": record.failed,
        "blocked": record.blocked,
        "not_executable": record.not_executable,
        "pending": record.pending,
        "runtime_summary_path": str(record.summary_path),
        "log_path": str(record.log_path),
        "started_at": record.started_at,
        "ended_at": record.ended_at,
        "duration_seconds": record.duration_seconds,
        "missing_summary": record.missing_summary,
        "missing_summary_reason": record.missing_summary_reason,
        "mrts_upstream_config_tests": dict(record.mrts_upstream),
        "feature_demo_runtime_cases": record.feature_demo_cases,
    }


def markdown(records: list[RunRecord], totals: Counter[str], generated_at: str) -> str:
    lines: list[str] = []
    lines.extend([
        "# Full MRTS Runtime Matrix",
        "",
        "Generated file - do not edit manually.",
        "",
        f"- Generated at: `{generated_at}`",
        f"- Variant runs: **{len(records)}**",
        f"- Total attempted: **{totals['attempted']}**",
        f"- Total PASS/FAIL/BLOCKED/NOT_EXECUTABLE: **{totals['pass']}** / **{totals['fail']}** / **{totals['blocked']}** / **{totals['not_executable']}**",
        f"- Pending metadata rows observed in runtime summaries: **{totals['pending']}**",
        "",
        "## Variant Results",
        "| Connector | Test variant | MRTS variant | Outcome | Attempted | PASS | FAIL | BLOCKED | NOT_EXECUTABLE | Pending | Duration seconds | Summary | Log |",
        "|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|---|---|",
    ])
    for record in records:
        lines.append(
            "| {connector} | {test_variant} | {mrts_variant} | {outcome} | {attempted} | {passed} | {failed} | {blocked} | {not_executable} | {pending} | {duration} | {summary} | {log} |".format(
                connector=record.connector,
                test_variant=record.test_variant,
                mrts_variant=record.mrts_variant,
                outcome=record.outcome,
                attempted=record.attempted,
                passed=record.passed,
                failed=record.failed,
                blocked=record.blocked,
                not_executable=record.not_executable,
                pending=record.pending,
                duration=record.duration_seconds if record.duration_seconds is not None else "-",
                summary=record.summary_path,
                log=record.log_path,
            )
        )
    lines.extend([
        "",
        "## MRTS Upstream Config Tests",
        "| Connector | Variant | Attempted | PASS | FAIL | BLOCKED | NOT_EXECUTABLE | Pending |",
        "|---|---|---:|---:|---:|---:|---:|---:|",
    ])
    for record in records:
        if record.mrts_variant != "with-mrts":
            continue
        counts = record.mrts_upstream
        lines.append(
            f"| {record.connector} | {record.test_variant}/{record.mrts_variant} | {counts['attempted']} | {counts['pass']} | {counts['fail']} | {counts['blocked']} | {counts['not_executable']} | {counts['pending']} |"
        )
    lines.extend([
        "",
        "## Guardrails",
        "- `feature-demo` is visible in reports but not runtime-executed unless `MODSECURITY_MRTS_INCLUDE_FEATURE_DEMO=1` is set.",
        "- MRTS golden outputs under the submodule are golden/reference/drift input only and are not runtime case roots.",
        "- `no-mrts` variants should have zero MRTS runtime cases.",
        "- Runtime PASS/FAIL/BLOCKED values come from connector summary JSON, not classification overlays.",
        "",
        "## MRTS Native Infrastructure Evidence",
        f"- Apache native: `{NATIVE_EVIDENCE_REPORTS['apache']}`",
        f"- NGINX PR24 native: `{NATIVE_EVIDENCE_REPORTS['nginx']}`",
        f"- Native summary: `{NATIVE_EVIDENCE_REPORTS['summary']}`",
        f"- Combined native report: `{NATIVE_EVIDENCE_REPORTS['combined']}`",
        "",
        "These native MRTS reports are separate from connector full-matrix evidence.",
    ])
    return "\n".join(lines) + "\n"


def missing_manifest_markdown(manifest: Path, generated_at: str, status: str, reason: str) -> str:
    return "\n".join(
        [
            "# Full MRTS Runtime Matrix",
            "",
            f"- Generated at: `{generated_at}`",
            f"- Status: `{status}`",
            f"- Reason: {reason}",
            f"- Manifest: `{manifest}`",
            "",
            "## Variant Results",
            "",
            "| Connector | Test variant | MRTS variant | Outcome | Attempted | PASS | FAIL | BLOCKED | NOT_EXECUTABLE | Pending | Duration seconds | Summary | Log |",
            "|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|---|---|",
            "",
            "_No rows available. Reason: producer command was not run or manifest input is missing/empty._",
            "",
            "## Guardrails",
            "- Runtime PASS/FAIL/BLOCKED values are not inferred when the manifest is unavailable.",
        ]
    ) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--connector-root", default=".")
    parser.add_argument("--framework-root", default=None)
    parser.add_argument("--build-root", default=os.environ.get("BUILD_ROOT", str(DEFAULT_BUILD_ROOT)))
    parser.add_argument("--log-root", default=os.environ.get("LOG_ROOT"))
    parser.add_argument("--manifest", default=None)
    parser.add_argument("--output-dir", default=None)
    args = parser.parse_args()

    connector_root = Path(args.connector_root).resolve()
    build_root = Path(args.build_root).resolve()
    log_root = Path(args.log_root).resolve() if args.log_root else build_root / "logs"
    output_dir = Path(args.output_dir).resolve() if args.output_dir else connector_root / GENERATED_ROOT
    manifest = Path(args.manifest).resolve() if args.manifest else build_root / "results/full-matrix/full-runtime-matrix-runs.jsonl"

    if not manifest.is_file() or manifest.stat().st_size == 0:
        generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(_UTC_OFFSET, "Z")
        status = "skipped_missing_input"
        reason = "full-runtime-matrix manifest is missing" if not manifest.exists() else "full-runtime-matrix manifest is empty"
        payload = {
            "generated_at": generated_at,
            "status": status,
            "reason": reason,
            "manifest": str(manifest),
            "build_root": str(build_root),
            "log_root": str(log_root),
            "totals": {
                "attempted": "unknown",
                "pass": "unknown",
                "fail": "unknown",
                "blocked": "unknown",
                "not_executable": "unknown",
                "pending": "unknown",
            },
            "runs": [],
            "empty_reason": "producer command was not run or manifest input is missing/empty",
        }
        metadata = build_metadata(
            generated_by="ci/evidence/reports/generate-full-runtime-matrix.py",
            make_target="generate-full-runtime-matrix",
            connector_root=connector_root,
            framework_root=Path(args.framework_root).resolve() if args.framework_root else None,
            inputs=[manifest],
            generated_at=generated_at,
            extra={"run_status": status, "blocked_reason": reason},
        )
        json_path = report_path_from_root(output_dir, "full_runtime_matrix", "json")
        md_path = report_path_from_root(output_dir, "full_runtime_matrix", "md")
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(generated_json_text(payload, metadata), encoding="utf-8")
        md_path.write_text(
            generated_markdown_text(missing_manifest_markdown(manifest, generated_at, status, reason), metadata),
            encoding="utf-8",
        )
        return 2

    records = load_manifest(manifest, build_root, log_root)
    records.sort(key=lambda item: (TEST_VARIANTS.index(item.test_variant), MRTS_VARIANTS.index(item.mrts_variant), CONNECTORS.index(item.connector)))
    for record in records:
        populate_record(record)

    totals: Counter[str] = Counter()
    for record in records:
        totals["attempted"] += record.attempted
        totals["pass"] += record.passed
        totals["fail"] += record.failed
        totals["blocked"] += record.blocked
        totals["not_executable"] += record.not_executable
        totals["pending"] += record.pending

    generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(_UTC_OFFSET, "Z")
    payload = {
        "generated_at": generated_at,
        "manifest": str(manifest),
        "build_root": str(build_root),
        "log_root": str(log_root),
        "totals": dict(totals),
        "runs": [record_to_json(record) for record in records],
        "native_evidence_reports": NATIVE_EVIDENCE_REPORTS,
        "guardrails": {
            "feature_demo_runtime_cases": sum(record.feature_demo_cases for record in records),
            "no_mrts_mrts_runtime_cases": sum(record.mrts_upstream["attempted"] for record in records if record.mrts_variant == "no-mrts"),
        },
    }

    metadata = build_metadata(
        generated_by="ci/evidence/reports/generate-full-runtime-matrix.py",
        make_target="generate-full-runtime-matrix",
        connector_root=connector_root,
        framework_root=Path(args.framework_root).resolve() if args.framework_root else None,
        inputs=[manifest],
        generated_at=generated_at,
    )
    json_path = report_path_from_root(output_dir, "full_runtime_matrix", "json")
    md_path = report_path_from_root(output_dir, "full_runtime_matrix", "md")
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(generated_json_text(payload, metadata), encoding="utf-8")
    md_path.write_text(generated_markdown_text(markdown(records, totals, generated_at), metadata), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
