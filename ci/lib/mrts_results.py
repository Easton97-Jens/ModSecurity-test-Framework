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
import runpy
import sys
import stat
import tempfile
from typing import Any

_runtime_safety = runpy.run_path(
    str(Path(__file__).with_name("runtime_path_safety.py"))
)
absolute_path_without_traversal = _runtime_safety["absolute_path_without_traversal"]
has_symlink_component = _runtime_safety["has_symlink_component"]
_mrts_safety = runpy.run_path(str(Path(__file__).with_name("mrts_path_safety.py")))
approved_runtime_root = _mrts_safety["approved_runtime_root"]

MAX_RESULT_BYTES = 1024 * 1024
CASE_ID = re.compile(r"\d+-\d+\Z", re.ASCII)
RESULT_FIELDS = {
    "success": "PASS",
    "failed": "FAIL",
    "skipped": "SKIP",
    "ignored": "IGNORED",
    "forced-pass": "FORCED_PASS",
    "forced-fail": "FORCED_FAIL",
}


def valid_case_ids(items: object) -> bool:
    return isinstance(items, list) and all(
        isinstance(item, str) and CASE_ID.fullmatch(item) for item in items
    )


def collect_observed_ids(stats: dict[str, Any]) -> dict[str, list[str]]:
    observed: dict[str, list[str]] = {}
    for field, outcome in RESULT_FIELDS.items():
        items = stats.get(field, [])
        if items is None:
            items = []
        if not valid_case_ids(items):
            raise ValueError(f"invalid go-ftw {field} result IDs")
        for case_id in items:
            observed.setdefault(case_id, []).append(outcome)
    return observed


def classify_observed_ids(
    observed: dict[str, list[str]], expected: set[str], errors: list[str]
) -> dict[str, str]:
    outcomes = {}
    for case_id, values in observed.items():
        outcome = values[0]
        if len(values) != 1:
            errors.append(f"duplicate or conflicting result: {case_id}")
            outcome = "INVALID"
        if expected and case_id not in expected:
            errors.append(f"unexpected result: {case_id}")
            outcome = "UNEXPECTED"
        outcomes[case_id] = outcome
    return outcomes


def observed_results(selected: list[str], stats: dict[str, Any]) -> dict[str, Any]:
    """Validate the selection and retain a single observed outcome per case ID."""
    errors: list[str] = []
    if not selected:
        errors.append("required case selection is empty or unavailable")
    if not valid_case_ids(selected):
        raise ValueError("invalid selected MRTS case ID")
    expected = set(selected)
    if len(expected) != len(selected):
        errors.append("duplicate selected case ID")
    observed = collect_observed_ids(stats)
    outcomes = classify_observed_ids(observed, expected, errors)
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
        "selected": len(expected),
        "selected_cases": sorted(expected),
        "attempted": reported,
        "executed": counts["PASS"] + counts["FAIL"],
        "passed": counts["PASS"],
        "failed": counts["FAIL"],
        "skipped": counts["SKIP"],
        "ignored": counts["IGNORED"],
        "forced": counts["FORCED_PASS"] + counts["FORCED_FAIL"],
        "missing": len(missing),
        "missing_cases": missing,
        "failed_cases": sorted(
            case_id for case_id, value in outcomes.items() if value == "FAIL"
        ),
        "outcomes": dict(sorted(outcomes.items())),
        "errors": errors,
        "complete": complete,
    }


def results_from_log(text: str) -> dict[str, Any]:
    """Read legacy explicit outcomes without treating totals as observations."""
    stats: dict[str, Any] = {field: [] for field in RESULT_FIELDS}
    current = None
    for line in text.splitlines():
        running = re.search(r"\brunning (\d+-\d+):", line, re.ASCII)
        if running:
            current = running.group(1)
        failed = re.search(r"\b(\d+-\d+)\s+failed\b", line, re.ASCII)
        if failed:
            stats["failed"].append(failed.group(1))
            current = None
        elif current and "passed in" in line:
            stats["success"].append(current)
            current = None
    payload = re.search(r"failed to run:\s*\[(.*?)\]", text)
    if payload:
        failed_ids = set(stats["failed"])
        for item in re.split(r"[\s,]+", payload.group(1)):
            case_id = item.strip("\"'")
            if CASE_ID.fullmatch(case_id) and case_id not in failed_ids:
                stats["failed"].append(case_id)
                failed_ids.add(case_id)
    stats["run"] = sum(len(stats[field]) for field in RESULT_FIELDS)
    result = observed_results([], stats)
    total = re.search(r"\brun\s+(\d+)\s+total tests", text, re.ASCII)
    result["attempted"] = int(total.group(1)) if total else stats["run"]
    return result


def private_owned_directory(path: Path) -> None:
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid():
        raise ValueError("MRTS result directories must be owned by the current user")
    if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ValueError(
            "MRTS result directories must not allow group or public writes"
        )


def approved_result_root(value: Path | str | None = None) -> Path:
    """Authorize a dedicated external runtime root, never an input-derived parent."""
    configured = value if value is not None else os.environ.get("BUILD_ROOT")
    if not configured:
        raise ValueError("BUILD_ROOT is required to authorize MRTS result paths")
    return approved_runtime_root(configured, "MRTS result root")


def safe_result_path(path: Path, approved_root: Path | str | None = None) -> Path:
    root = approved_result_root(approved_root)
    candidate = absolute_path_without_traversal(path, "MRTS result path")
    if has_symlink_component(candidate):
        raise ValueError("MRTS result path must not contain a symlink component")
    resolved = candidate.resolve(strict=False)
    if resolved == root or not str(resolved).startswith(str(root) + os.sep):
        raise ValueError("MRTS result path is outside the approved runtime root")
    private_owned_directory(resolved.parent)
    for directory in resolved.parent.relative_to(root).parents:
        private_owned_directory(root / directory)
    return resolved


def read_bounded(path: Path, approved_root: Path | str | None = None) -> str:
    validated = safe_result_path(path, approved_root)
    descriptor = os.open(validated, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as handle:
        metadata = os.fstat(handle.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_RESULT_BYTES:
            raise ValueError(
                f"missing, non-regular or oversized MRTS result: {validated.name}"
            )
        content = handle.read(MAX_RESULT_BYTES + 1)
    if len(content) > MAX_RESULT_BYTES:
        raise ValueError(f"oversized MRTS result: {validated.name}")
    return content.decode("utf-8")


def selected_ftw_ids(root: Path, approved_root: Path | str | None = None) -> list[str]:
    import yaml

    allowed = approved_result_root(approved_root)
    root = safe_result_path(root, allowed)
    if root.exists():
        private_owned_directory(root)
    selected = []
    for path in sorted(root.rglob("*.yaml")):
        try:
            data = yaml.safe_load(read_bounded(path, allowed))
        except yaml.YAMLError as exc:
            raise ValueError("invalid FTW YAML selection") from exc
        if not isinstance(data, dict) or not isinstance(data.get("tests"), list):
            raise ValueError("invalid FTW case selection")
        for case in data["tests"]:
            selected.append(f"{case['ruleid']}-{case['test_id']}")
    if len(selected) != len(set(selected)):
        raise ValueError("duplicate selected FTW case ID")
    return selected


def attach_corpora(
    results: dict[str, Any], ftw_root: Path, approved_root: Path | str | None = None
) -> None:
    """Retain corpus origin for the private, combined native selection."""
    corpora = {}
    for corpus in ("upstream-config-tests", "feature-demo"):
        root = safe_result_path(ftw_root / corpus, approved_root)
        if not root.is_dir():
            continue
        selected = selected_ftw_ids(root, approved_root)
        outcomes = {
            case_id: results["outcomes"].get(case_id, "MISSING") for case_id in selected
        }
        counts = Counter(outcomes.values())
        corpora[corpus] = {
            "selected": len(selected),
            "executed": counts["PASS"] + counts["FAIL"],
            "passed": counts["PASS"],
            "failed": counts["FAIL"],
            "skipped": counts["SKIP"],
            "missing": counts["MISSING"],
            "outcomes": outcomes,
        }
    results["corpora"] = corpora


def read_results(
    stats_file: Path,
    selected: list[str],
    ftw_root: Path | None = None,
    approved_root: Path | str | None = None,
) -> dict[str, Any]:
    stats = json.loads(read_bounded(stats_file, approved_root))
    if not isinstance(stats, dict):
        raise ValueError("go-ftw result is not an object")
    results = observed_results(selected, stats)
    if ftw_root is not None:
        attach_corpora(results, ftw_root, approved_root)
    return results


def write_job(args: argparse.Namespace, approved_root: Path | str | None = None) -> int:
    allowed = approved_result_root(approved_root)
    output = safe_result_path(args.output, allowed)
    safe_result_path(args.summary_path, allowed)
    if output.exists() and not stat.S_ISREG(output.lstat().st_mode):
        raise ValueError("MRTS job output must be a regular file")
    log = read_bounded(args.run_log, allowed)
    selected: list[str] = []
    try:
        selected = selected_ftw_ids(args.ftw_dir, allowed)
        results = read_results(args.stats_file, selected, args.ftw_dir, allowed)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        results = observed_results(selected, {}) if selected else results_from_log(log)
        results["errors"].append(str(exc))
    status, reason = args.status, args.reason
    if status == "PASS" and (args.exit_code != 0 or results["failed"]):
        status, reason = (
            "FAIL",
            "native process or observed MRTS case failed despite requested PASS",
        )
    elif status == "PASS" and (
        not results["complete"] or results["skipped"] or results["ignored"]
    ):
        status, reason = (
            "INCOMPLETE",
            "required native MRTS results are missing, skipped, invalid or failed",
        )
    classification = {
        "PASS": "optional_native_evidence_pass",
        "FAIL": "optional_native_go_ftw_case_failure",
        "BLOCKED": "optional_native_infrastructure_blocked",
    }.get(status, "optional_native_evidence_incomplete")
    data = {
        "target": args.target,
        "status": status,
        "reason": reason,
        "exit_code": args.exit_code if status == args.status else 2,
        "duration_seconds": args.duration,
        "run_log": str(args.run_log),
        "summary_path": str(args.summary_path),
        "job_json": str(args.output),
        "evidence_role": "optional_native_mrts",
        "optional": True,
        "critical_merge_blocker": False,
        "classification": classification,
        "classification_notes": reason,
        "native_runtime_reached": "Received default request" in log,
        "go_ftw": results,
    }
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=output.parent,
            prefix=".mrts-job-",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(temporary, output)
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
