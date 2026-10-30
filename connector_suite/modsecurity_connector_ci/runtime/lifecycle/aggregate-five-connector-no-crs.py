#!/usr/bin/env python3
"""Fail-closed, result-only aggregate for the five-connector no-CRS profile."""
from __future__ import annotations
from modsecurity_test_framework.connector_context import load_source

import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any, Sequence

_THIS = Path(__file__).resolve()
profile = load_source(_THIS.with_name('five-connector-no-crs-profile.py'))

from modsecurity_connector_ci.lib.runtime_path_utils import prepare_verified_runtime_artifact_root, read_runtime_artifact_text, runtime_artifact_path, write_runtime_artifact_text_atomic


def digest(root: Path, path: Path) -> str:
    data = read_runtime_artifact_text(root, path, "profile receipt").encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def load(root: Path, path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(read_runtime_artifact_text(root, path, label))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot parse {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def artifact_record(result: dict[str, Any], manifest: dict[str, Any]) -> dict[str, str]:
    artifacts = result.get("artifacts")
    if not isinstance(artifacts, dict):
        raise ValueError("result artifacts are missing")
    if artifacts.get(profile.RECEIPT_KEY) != profile.RECEIPT_PATH:
        raise ValueError("result profile receipt artifact path is not canonical")
    manifest_artifacts = manifest.get("artifacts")
    if not isinstance(manifest_artifacts, dict):
        raise ValueError("manifest artifacts are missing")
    record = manifest_artifacts.get(profile.RECEIPT_KEY)
    if not isinstance(record, dict):
        raise ValueError("profile receipt artifact is missing")
    if record.get("path") != profile.RECEIPT_PATH:
        raise ValueError("profile receipt artifact path is not canonical")
    checksum = record.get("sha256")
    if not isinstance(checksum, str) or not profile.SHA256.fullmatch(checksum):
        raise ValueError("profile receipt artifact checksum is invalid")
    if record.get("state") != "produced":
        raise ValueError("profile receipt artifact is not produced")
    return {"path": profile.RECEIPT_PATH, "sha256": checksum}


def validate_run(root: Path, connector: str, *, run_id: str, connector_commit: str,
                 framework_commit: str) -> dict[str, str]:
    if connector not in profile.CONNECTORS:
        raise ValueError(f"unexpected connector directory: {connector}")
    run = root / connector / run_id
    if run.is_symlink() or not run.is_dir():
        raise ValueError(f"{connector}: canonical run directory is missing or unsafe")
    result = load(root, run / "result.json", f"{connector} result.json")
    manifest = load(root, run / "manifest.json", f"{connector} manifest.json")
    row = profile.profile_row(connector)
    expected = {"connector": connector, "run_id": run_id,
                "connector_commit": connector_commit, "framework_commit": framework_commit,
                "integration_mode": row["integration_mode"]}
    for name, value in expected.items():
        if result.get(name) != value:
            raise ValueError(f"{connector}: result {name} does not match aggregate identity")
        if manifest.get(name) != value:
            raise ValueError(f"{connector}: manifest {name} does not match aggregate identity")
    if result.get("status") != "PASS":
        raise ValueError(f"{connector}: result is not PASS")
    artifact = artifact_record(result, manifest)
    receipt_path = run / artifact["path"]
    receipt = load(root, receipt_path, f"{connector} profile receipt")
    if digest(root, receipt_path) != artifact["sha256"]:
        raise ValueError(f"{connector}: profile receipt checksum does not match result")
    expected_receipt = dict(expected)
    expected_receipt["profile"] = profile.PROFILE
    expected_receipt["protocol"] = row["protocol"]
    expected_receipt["phase4_mode"] = row["phase4_mode"]
    expected_receipt["connector_profile"] = row["connector_profile"]
    expected_receipt["evidence_scope"] = row["evidence_scope"]
    expected_receipt["cleanup_status"] = "passed"
    expected_receipt["schema_version"] = 1
    for name, value in expected_receipt.items():
        if receipt.get(name) != value:
            raise ValueError(f"{connector}: profile receipt {name} does not match result identity")
    return {"connector": connector, "status": "PASS"}


def aggregate(evidence_root: Path, *, run_id: str, connector_commit: str,
              framework_commit: str, canonical_validation_status: str) -> dict[str, Any]:
    if canonical_validation_status != "passed":
        raise ValueError("canonical evidence validation did not pass")
    evidence_root = prepare_verified_runtime_artifact_root(evidence_root)
    if evidence_root.is_symlink() or not evidence_root.is_dir():
        raise ValueError("evidence root is missing or unsafe")
    actual = [child.name for child in evidence_root.iterdir() if child.is_dir() or child.is_symlink()]
    if len(actual) != len(set(actual)) or set(actual) != set(profile.CONNECTORS):
        raise ValueError("evidence root must contain exactly the five canonical connector directories")
    rows = [validate_run(evidence_root, connector, run_id=run_id, connector_commit=connector_commit, framework_commit=framework_commit) for connector in profile.CONNECTORS]
    return {"schema_version": 1, "profile": profile.PROFILE, "run_id": run_id,
            "connector_commit": connector_commit, "framework_commit": framework_commit,
            "status": "PASS", "results": rows}


def rendered_status(summary: dict[str, Any], german: bool) -> str:
    passed = summary.get("status") == "PASS"
    if german:
        return "BESTANDEN" if passed else "FEHLER"
    return str(summary.get("status", "FAIL"))


def render(summary: dict[str, Any], german: bool = False) -> str:
    title = "Fünf-Connector-No-CRS-Ergebnis" if german else "Five-connector No-CRS result"
    passed = summary.get("status") == "PASS"
    status = rendered_status(summary, german)
    lines = [f"# {title}", "", f"Status: **{status}**", "", "| Connector | Status |", "| --- | --- |"]
    lines.extend(f"| {row['connector']} | {row['status']} |" for row in summary["results"])
    errors = summary.get("errors")
    if not passed and isinstance(errors, list) and errors:
        heading = "Fehler" if german else "Error"
        lines.extend(["", f"{heading}: {errors[0]}"])
    return "\n".join(lines) + "\n"


def write_outputs(root: Path, args: argparse.Namespace, summary: dict[str, Any]) -> None:
    for output, value in ((args.output_json, json.dumps(summary, sort_keys=True) + "\n"),
                          (args.output_md, render(summary)), (args.output_md_de, render(summary, german=True))):
        destination = runtime_artifact_path(root, output, "five-connector aggregate output")
        write_runtime_artifact_text_atomic(root, destination, value, "five-connector aggregate output")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, choices=(profile.PROFILE,))
    parser.add_argument("--canonical-validation-status", required=True,
                        choices=("passed", "failed"))
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--connector-commit", required=True)
    parser.add_argument("--framework-commit", required=True)
    parser.add_argument("--output-json", type=Path, required=True)
    parser.add_argument("--output-md", type=Path, required=True)
    parser.add_argument("--output-md-de", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        output_root = prepare_verified_runtime_artifact_root(args.evidence_root)
        profile.receipt_payload(connector=profile.CONNECTORS[0], run_id=args.run_id,
                                connector_commit=args.connector_commit,
                                framework_commit=args.framework_commit, cleanup_status="passed")
        summary = aggregate(args.evidence_root, run_id=args.run_id,
                            connector_commit=args.connector_commit,
                            framework_commit=args.framework_commit,
                            canonical_validation_status=args.canonical_validation_status)
        write_outputs(output_root, args, summary)
        return 0
    except ValueError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        try:
            output_root = prepare_verified_runtime_artifact_root(args.evidence_root)
            write_outputs(output_root, args, {"schema_version": 1, "profile": profile.PROFILE,
                "run_id": args.run_id, "connector_commit": args.connector_commit,
                "framework_commit": args.framework_commit, "status": "FAIL", "errors": [str(exc)], "results": []})
        except (OSError, ValueError):
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
