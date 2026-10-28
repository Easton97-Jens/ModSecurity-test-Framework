"""Observed MRTS outcomes shared by the native producer and report consumer.

go-ftw JSON RunStats supplies explicit IDs, including skipped/forced results.
Aggregate counts and successful process exits never supply missing PASS records.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from typing import Any

MAX_RESULT_BYTES = 1024 * 1024
CASE_ID = re.compile(r"[0-9]+-[0-9]+\Z")
RESULT_FIELDS = {
    "success": "PASS", "failed": "FAIL", "skipped": "SKIP",
    "ignored": "IGNORED", "forced-pass": "FORCED_PASS", "forced-fail": "FORCED_FAIL",
}


def observed_results(selected: list[str], stats: dict[str, Any]) -> dict[str, Any]:
    """Validate the selection and retain a single observed outcome per case ID."""
    errors: list[str] = []
    if not selected:
        errors.append("required case selection is empty or unavailable")
    if any(not isinstance(item, str) or not CASE_ID.fullmatch(item) for item in selected):
        raise ValueError("invalid selected MRTS case ID")
    if len(set(selected)) != len(selected):
        errors.append("duplicate selected case ID")
    observed: dict[str, list[str]] = {}
    for field, outcome in RESULT_FIELDS.items():
        items = stats.get(field, [])
        if items is None:
            items = []
        if not isinstance(items, list) or any(not isinstance(item, str) or not CASE_ID.fullmatch(item) for item in items):
            raise ValueError(f"invalid go-ftw {field} result IDs")
        for case_id in items:
            observed.setdefault(case_id, []).append(outcome)
    expected = set(selected)
    outcomes = {}
    for case_id, values in observed.items():
        if len(values) != 1:
            errors.append(f"duplicate or conflicting result: {case_id}")
            outcomes[case_id] = "INVALID"
        else:
            outcomes[case_id] = values[0]
        if selected and case_id not in expected:
            errors.append(f"unexpected result: {case_id}")
            outcomes[case_id] = "UNEXPECTED"
    reported = stats.get("run", 0)
    if type(reported) is not int or reported < 0:
        raise ValueError("invalid go-ftw run count")
    if reported != sum(len(values) for values in observed.values()):
        errors.append("go-ftw total does not match explicit result IDs")
    missing = sorted(expected - observed.keys())
    counts = Counter(outcomes.values())
    if counts["FORCED_PASS"] or counts["FORCED_FAIL"]:
        errors.append("forced outcomes are not runtime test results")
    complete = bool(selected) and not errors and not missing
    return {
        "selected": len(expected), "selected_cases": sorted(expected),
        "attempted": reported,
        "executed": counts["PASS"] + counts["FAIL"],
        "passed": counts["PASS"], "failed": counts["FAIL"],
        "skipped": counts["SKIP"], "ignored": counts["IGNORED"],
        "forced": counts["FORCED_PASS"] + counts["FORCED_FAIL"],
        "missing": len(missing), "missing_cases": missing,
        "failed_cases": sorted(case_id for case_id, value in outcomes.items() if value == "FAIL"),
        "outcomes": dict(sorted(outcomes.items())), "errors": errors,
        "complete": complete,
    }


def results_from_log(text: str) -> dict[str, Any]:
    """Read legacy explicit outcomes without treating totals as observations."""
    stats: dict[str, Any] = {field: [] for field in RESULT_FIELDS}
    current = None
    for line in text.splitlines():
        running = re.search(r"\brunning ([0-9]+-[0-9]+):", line)
        if running:
            current = running.group(1)
        failed = re.search(r"\b([0-9]+-[0-9]+)\s+failed\b", line)
        if failed:
            stats["failed"].append(failed.group(1))
            current = None
        elif current and "passed in" in line:
            stats["success"].append(current)
            current = None
    payload = re.search(r"failed to run:\s*\[(.*?)\]", text)
    if payload:
        for case_id in re.findall(r"[0-9]+-[0-9]+", payload.group(1)):
            if case_id not in stats["failed"]:
                stats["failed"].append(case_id)
    stats["run"] = sum(len(stats[field]) for field in RESULT_FIELDS)
    result = observed_results([], stats)
    total = re.search(r"\brun\s+([0-9]+)\s+total tests", text)
    result["attempted"] = int(total.group(1)) if total else stats["run"]
    return result


def read_bounded(path: Path) -> str:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_RESULT_BYTES:
        raise ValueError(f"missing, linked or oversized MRTS result: {path.name}")
    return path.read_text(encoding="utf-8")


def selected_ftw_ids(root: Path) -> list[str]:
    import yaml

    selected = []
    for path in sorted(root.rglob("*.yaml")):
        try:
            data = yaml.safe_load(read_bounded(path))
        except yaml.YAMLError as exc:
            raise ValueError("invalid FTW YAML selection") from exc
        if not isinstance(data, dict) or not isinstance(data.get("tests"), list):
            raise ValueError("invalid FTW case selection")
        for case in data["tests"]:
            selected.append(f"{case['ruleid']}-{case['test_id']}")
    if len(selected) != len(set(selected)):
        raise ValueError("duplicate selected FTW case ID")
    return selected


def attach_corpora(results: dict[str, Any], ftw_root: Path) -> None:
    """Retain corpus origin for the private, combined native selection."""
    corpora = {}
    for corpus in ("upstream-config-tests", "feature-demo"):
        root = ftw_root / corpus
        if not root.is_dir():
            continue
        selected = selected_ftw_ids(root)
        outcomes = {case_id: results["outcomes"].get(case_id, "MISSING") for case_id in selected}
        counts = Counter(outcomes.values())
        corpora[corpus] = {
            "selected": len(selected), "executed": counts["PASS"] + counts["FAIL"],
            "passed": counts["PASS"], "failed": counts["FAIL"], "skipped": counts["SKIP"],
            "missing": counts["MISSING"], "outcomes": outcomes,
        }
    results["corpora"] = corpora


def read_results(stats_file: Path, selected: list[str], ftw_root: Path | None = None) -> dict[str, Any]:
    stats = json.loads(read_bounded(stats_file))
    if not isinstance(stats, dict):
        raise ValueError("go-ftw result is not an object")
    results = observed_results(selected, stats)
    if ftw_root is not None:
        attach_corpora(results, ftw_root)
    return results


def write_job(args: argparse.Namespace) -> int:
    log = read_bounded(args.run_log)
    selected: list[str] = []
    try:
        selected = selected_ftw_ids(args.ftw_dir)
        results = read_results(args.stats_file, selected, args.ftw_dir)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        results = observed_results(selected, {}) if selected else results_from_log(log)
        results["errors"].append(str(exc))
    status, reason = args.status, args.reason
    if status == "PASS" and (args.exit_code != 0 or results["failed"]):
        status, reason = "FAIL", "native process or observed MRTS case failed despite requested PASS"
    elif status == "PASS" and (not results["complete"] or results["skipped"] or results["ignored"]):
        status, reason = "INCOMPLETE", "required native MRTS results are missing, skipped, invalid or failed"
    classification = {
        "PASS": "optional_native_evidence_pass", "FAIL": "optional_native_go_ftw_case_failure",
        "BLOCKED": "optional_native_infrastructure_blocked",
    }.get(status, "optional_native_evidence_incomplete")
    data = {
        "target": args.target, "status": status, "reason": reason,
        "exit_code": args.exit_code if status == args.status else 2,
        "duration_seconds": args.duration, "run_log": str(args.run_log),
        "summary_path": str(args.summary_path), "job_json": str(args.output),
        "evidence_role": "optional_native_mrts", "optional": True,
        "critical_merge_blocker": False, "classification": classification,
        "classification_notes": reason, "native_runtime_reached": "Received default request" in log,
        "go_ftw": results,
    }
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=args.output.parent, prefix=".mrts-job-", delete=False) as handle:
            temporary = Path(handle.name)
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(temporary, args.output)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return 2 if args.status == "PASS" and status != "PASS" else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("output", "run-log", "summary-path", "ftw-dir", "stats-file"):
        parser.add_argument("--" + flag, type=Path, required=True)
    for flag in ("target", "status", "reason"):
        parser.add_argument("--" + flag, required=True)
    parser.add_argument("--exit-code", type=int, required=True)
    parser.add_argument("--duration", type=int, required=True)
    args = parser.parse_args()
    try:
        return write_job(args)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"ERROR: MRTS result writer failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
