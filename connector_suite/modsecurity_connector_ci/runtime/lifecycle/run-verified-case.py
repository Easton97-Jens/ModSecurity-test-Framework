#!/usr/bin/env python3
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# CI helpers are shared from ci/lib even when this file is executed directly.


from modsecurity_connector_ci.lib.runtime_path_utils import canonical_project_roots, DEFAULT_RUN_BASENAME, ensure_safe_runtime_directory, fixed_runtime_temp_parent, is_read_only_source_path, prepare_verified_runtime_artifact_root, runtime_artifact_path


CONNECTORS = {"apache", "nginx", "haproxy"}
DEFAULT_VERIFIED_RUN_ROOT = fixed_runtime_temp_parent() / DEFAULT_RUN_BASENAME
RESULT_FILENAME = "result.json"
LOG_EXTENSIONS = {".err", ".json", ".jsonl", ".log", ".txt"}
RESULT_REFERENCE_KEYS = {"decision_log", "evidence_path"}
LOG_NAME_FRAGMENTS = (
    "access",
    "audit",
    "case-assert",
    "configtest",
    "curl",
    "decision",
    "error",
    "haproxy",
    "nginx",
    "observed",
    "phase4",
    "result",
    "spoa",
    "stderr",
    "stdout",
    "status",
)
EXCERPT_PATTERNS = re.compile(
    r"(ModSecurity|Access denied|Matched Data|\[id \"|\[msg \"|"
    r"intervention|decision|rule|rule_id|audit|error|fail|denied|status)",
    re.IGNORECASE,
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_utc(value: datetime) -> str:
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def safe_name(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip())
    return value.strip("-") or "unknown"


def read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def write_json(root: Path, path: Path, data: dict[str, Any]) -> None:
    path = runtime_artifact_path(root, path, "case-run JSON output")
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def canonical_roots(connector_root: str, framework_root: str) -> tuple[Path, Path]:
    """Reject CLI attempts to select a different Parent or Framework tree."""

    canonical_connector, canonical_framework = canonical_project_roots()
    requested_connector = Path(connector_root).resolve(strict=True)
    requested_framework = Path(framework_root).resolve(strict=True)
    if requested_connector != canonical_connector:
        raise ValueError(f"connector root must be this checkout: {requested_connector}")
    if requested_framework != canonical_framework:
        raise ValueError(f"framework root must be the pinned checkout: {requested_framework}")
    return canonical_connector, canonical_framework


def verified_case_tokens(case: str, crs: str, mrts: str) -> tuple[str, str, str]:
    """Return path- and shell-safe case matrix identifiers."""

    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", case):
        raise ValueError("case must be a bounded identifier")
    if crs not in {"no-crs", "with-crs"}:
        raise ValueError("CRS variant must be no-crs or with-crs")
    if mrts not in {"no-mrts", "with-mrts"}:
        raise ValueError("MRTS variant must be no-mrts or with-mrts")
    return case, crs, mrts


def try_load_yaml(path: Path) -> dict[str, Any]:
    try:
        import yaml  # type: ignore
    except Exception:
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def find_case_path(framework_root: Path, case: str) -> Path | None:
    cases_root = framework_root / "tests/cases"
    if not cases_root.is_dir():
        return None
    matches = sorted(cases_root.rglob(f"{case}.yaml"))
    return matches[0] if matches else None


def matching_mapping_value(value: dict[Any, Any], names: set[str]) -> tuple[bool, Any]:
    """Return the first direct matching key while preserving a ``None`` value."""

    for key, item in value.items():
        if str(key) in names:
            return True, item
    return False, None


def first_key_in_items(items: Any, names: set[str]) -> Any:
    for item in items:
        found = find_first_key(item, names)
        if found is not None:
            return found
    return None


def find_first_key(value: Any, names: set[str]) -> Any:
    if isinstance(value, dict):
        matched, direct_value = matching_mapping_value(value, names)
        return direct_value if matched else first_key_in_items(value.values(), names)
    if isinstance(value, list):
        return first_key_in_items(value, names)
    return None


def summarize_case_definition(case_path: Path | None) -> dict[str, Any]:
    if not case_path or not case_path.is_file():
        return {
            "path": str(case_path) if case_path else "-",
            "status": "missing",
            "request": {},
            "rule_ids": [],
            "transforms": [],
        }

    data = try_load_yaml(case_path)
    rules_text = str(data.get("rules") or "")
    request = data.get("request") if isinstance(data.get("request"), dict) else {}
    if not request:
        request = find_first_key(data, {"request"}) if isinstance(find_first_key(data, {"request"}), dict) else {}
    headers = request.get("headers") if isinstance(request, dict) else None
    request_summary = {
        "method": request.get("method", "-") if isinstance(request, dict) else "-",
        "path": request.get("path") or request.get("uri") or request.get("url") or "-",
        "headers": headers if isinstance(headers, dict) else {},
        "body": request.get("body", "") if isinstance(request, dict) else "",
    }
    transforms = sorted(set(re.findall(r"\bt:(\w+)", rules_text, flags=re.ASCII)))
    rule_ids = sorted(set(re.findall(r"\bid:(\d+)", rules_text)), key=lambda item: int(item))
    return {
        "path": str(case_path),
        "status": "present",
        "request": request_summary,
        "rule_ids": rule_ids,
        "transforms": transforms,
        "expect": data.get("expect") if isinstance(data.get("expect"), dict) else {},
        "category": data.get("category"),
        "capabilities": data.get("capabilities"),
    }


def harness_paths(connector: str, build_root: Path, crs: str, mrts: str) -> dict[str, Path]:
    base = build_root / f"verified-{connector}-case"
    variant_work = base / f"{crs}-{mrts}-{connector}"
    if connector == "apache":
        return {
            "results": base / crs / mrts / "results",
            "work": variant_work,
            "logs": variant_work / "logs/apache-runtime",
            "runtime": variant_work / "apache-runtime",
        }
    if connector == "nginx":
        return {
            "results": base / crs / mrts / "results",
            "work": variant_work,
            "logs": variant_work / "logs",
            "runtime": variant_work / "runtime",
        }
    return {
        "results": base / crs / mrts / "results",
        "work": variant_work,
        "logs": variant_work / "logs/haproxy-runtime",
        "runtime": variant_work / "haproxy-runtime-cases",
        "tmp": variant_work / "tmp",
    }


def build_harness_command(
    connector: str,
    connector_root: Path,
    framework_root: Path,
    build_root: Path,
    source_root: Path,
    tmp_root: Path,
    py: str,
    case: str,
    crs: str,
    mrts: str,
) -> tuple[list[str], dict[str, str], dict[str, Path]]:
    paths = harness_paths(connector, build_root, crs, mrts)
    env = os.environ.copy()
    env.update(
        {
            "PYTHON": py,
            "FRAMEWORK_ROOT": str(framework_root),
            "CONNECTOR_ROOT": str(connector_root),
            "FORCE_ALL_CASES": "1",
            "MODSECURITY_TEST_VARIANT": crs,
            "MODSECURITY_MRTS_VARIANT": mrts,
            "TEST_CASE": case,
            "CASE_SCOPE": "all",
            "RESULTS_DIR": str(paths["results"]),
            "BUILD_ROOT": str(build_root),
            "SOURCE_ROOT": str(source_root),
            "TMP_ROOT": str(tmp_root),
        }
    )
    if connector == "apache":
        env["APACHE_RUNTIME_LOG_DIR"] = str(paths["logs"])
        env["RUNTIME_BASE"] = str(paths["runtime"])
        harness = framework_root / "ci/runtime/run-apache-smoke.sh"
    elif connector == "nginx":
        env["NGINX_HARNESS_WORK_ROOT"] = str(paths["work"])
        harness = framework_root / "ci/runtime/run-nginx-smoke.sh"
    else:
        env["TMP_ROOT"] = str(paths["tmp"])
        env["LOG_ROOT"] = str(paths["work"] / "logs")
        env["RUNTIME_BASE"] = str(paths["runtime"])
        env["RUN_ONE_CASE"] = "1"
        harness = framework_root / "ci/runtime/run-haproxy-smoke.sh"

    cmd = ["sh", "ci/provisioning/cache/with-runtime-components.sh", "env"]
    for key in sorted(env):
        if key in {
            "APACHE_RUNTIME_LOG_DIR",
            "BUILD_ROOT",
            "CASE_SCOPE",
            "CONNECTOR_ROOT",
            "FORCE_ALL_CASES",
            "FRAMEWORK_ROOT",
            "LOG_ROOT",
            "MODSECURITY_MRTS_VARIANT",
            "MODSECURITY_TEST_VARIANT",
            "NGINX_HARNESS_WORK_ROOT",
            "PYTHON",
            "RESULTS_DIR",
            "RUNTIME_BASE",
            "RUN_ONE_CASE",
            "SOURCE_ROOT",
            "TEST_CASE",
            "TMP_ROOT",
        }:
            cmd.append(f"{key}={env[key]}")
    cmd.extend(["sh", str(harness)])
    return cmd, env, paths


def find_result_json(paths: dict[str, Path], case: str, started_at_ts: float) -> Path | None:
    candidates: list[Path] = []
    for root in {paths.get("logs"), paths.get("results"), paths.get("work")}:
        if root and root.exists():
            candidates.extend(root.rglob(RESULT_FILENAME))
    filtered = [path for path in candidates if case in str(path)]
    if not filtered and candidates:
        filtered = candidates
    recent = [path for path in filtered if path.stat().st_mtime >= started_at_ts - 5]
    chosen = recent or filtered
    if not chosen:
        return None
    return max(chosen, key=lambda path: path.stat().st_mtime)


def result_referenced_log_files(result: dict[str, Any]) -> set[Path]:
    found: set[Path] = set()
    for key, value in result.items():
        if key.endswith("_path") or key in RESULT_REFERENCE_KEYS:
            path = Path(str(value))
            if path.is_file():
                found.add(path)
    return found


def case_log_roots(root: Path, case: str) -> list[Path]:
    roots = [path for path in root.rglob(case) if path.is_dir()]
    if root.name == "haproxy-runtime":
        roots.append(root)
    return roots


def is_relevant_log_file(path: Path) -> bool:
    if not path.is_file():
        return False
    lower = path.name.lower()
    return path.suffix.lower() in LOG_EXTENSIONS or any(fragment in lower for fragment in LOG_NAME_FRAGMENTS)


def case_log_files(root: Path, case: str) -> set[Path]:
    found: set[Path] = set()
    for case_root in case_log_roots(root, case):
        found.update(path for path in case_root.rglob("*") if is_relevant_log_file(path))
    return found


def relevant_log_files(paths: dict[str, Path], case: str, result: dict[str, Any]) -> list[Path]:
    found = result_referenced_log_files(result)
    for root in {paths.get("logs"), paths.get("runtime"), paths.get("work")}:
        if root and root.exists():
            found.update(case_log_files(root, case))
    return sorted(found)


def copy_or_excerpt_logs(logs: list[Path], output_dir: Path, limit_bytes: int = 2_000_000) -> list[dict[str, Any]]:
    output_dir.mkdir(parents=True, exist_ok=True)
    artifacts: list[dict[str, Any]] = []
    used_names: set[str] = set()
    for source in logs:
        name = safe_name("-".join(source.parts[-4:]))
        if name in used_names:
            name = f"{source.stat().st_mtime_ns}-{name}"
        used_names.add(name)
        dest = output_dir / name
        size = source.stat().st_size
        copied = False
        if size <= limit_bytes:
            shutil.copy2(source, dest)
            copied = True
        else:
            text = source.read_text(encoding="utf-8", errors="replace")
            excerpt = text[: limit_bytes // 2] + "\n\n[... log truncated ...]\n\n" + text[-limit_bytes // 2 :]
            dest = dest.with_suffix(dest.suffix + ".excerpt")
            dest.write_text(excerpt, encoding="utf-8")
        artifacts.append({"source": str(source), "path": str(dest), "bytes": size, "copied": copied})
    return artifacts


def collect_log_excerpt(artifacts: list[dict[str, Any]], max_lines: int = 160) -> list[str]:
    lines: list[str] = []
    for artifact in artifacts:
        path = Path(str(artifact["path"]))
        if not path.is_file():
            continue
        try:
            text_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            continue
        for line in text_lines:
            if EXCERPT_PATTERNS.search(line):
                lines.append(f"{path.name}: {line[:500]}")
                if len(lines) >= max_lines:
                    return lines
    return lines


def base_rule_evidence(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "rule_id": result.get("rule_id") or result.get("matched_rule_id") or "-",
        "matched_data": result.get("matched_data") or result.get("matched_value_snippet") or "-",
        "matched_variable": result.get("matched_variable") or "-",
        "reason": result.get("reason") or "-",
        "decision": {},
    }


def last_decision_json(path: Path) -> dict[str, Any]:
    last_json: dict[str, Any] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            candidate = json.loads(line)
        except Exception:
            continue
        if isinstance(candidate, dict):
            last_json = candidate
    return last_json


def first_decision_artifact(artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    for artifact in artifacts:
        path = Path(str(artifact["path"]))
        if "decision" in path.name and path.is_file():
            decision = last_decision_json(path)
            if decision:
                return decision
    return {}


def apply_decision_evidence(evidence: dict[str, Any], decision: dict[str, Any]) -> None:
    evidence["decision"] = decision
    if "rule_id" in decision:
        evidence["rule_id"] = decision.get("rule_id")
    evidence["matched_data"] = (
        decision.get("matched_data")
        or decision.get("matched_value_snippet")
        or decision.get("matched_var_value")
        or evidence["matched_data"]
    )


def result_rule_evidence(result: dict[str, Any], artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    evidence = base_rule_evidence(result)
    decision = first_decision_artifact(artifacts)
    if decision:
        apply_decision_evidence(evidence, decision)
    return evidence


def case_mismatch_rows(data: dict[str, Any], case: str) -> list[dict[str, Any]]:
    return [
        row
        for row in data.get("mismatches", [])
        if isinstance(row, dict) and str(row.get("case")) == case
    ]


def exact_mismatch_rows(
    rows: list[dict[str, Any]], connector: str, crs: str, mrts: str
) -> list[dict[str, Any]]:
    variants = {f"{crs}/{mrts}", crs, f"{crs}-{mrts}"}
    return [
        row
        for row in rows
        if row.get("connector") == connector and str(row.get("variant") or "") in variants
    ]


def mismatch_variant_parts(variant: str) -> tuple[str, str]:
    if "/" in variant:
        crs, mrts = variant.split("/", 1)
        return crs, mrts
    if "-" not in variant:
        return variant, ""
    parts = variant.split("-")
    if len(parts) >= 4:
        return "-".join(parts[:2]), "-".join(parts[2:])
    return variant, ""


def affected_mismatch_jobs(
    rows: list[dict[str, Any]], connector: str, crs: str, mrts: str
) -> set[tuple[str, str, str]]:
    affected_jobs: set[tuple[str, str, str]] = {(connector, crs, mrts)}
    for row in rows:
        row_connector = str(row.get("connector") or "")
        variant = str(row.get("variant") or "")
        if not row_connector:
            continue
        row_crs, row_mrts = mismatch_variant_parts(variant)
        if row_crs and row_mrts:
            affected_jobs.add((row_connector, row_crs, row_mrts))
    return affected_jobs


def mismatch_evidence_files(rows: list[dict[str, Any]]) -> list[str]:
    evidence_files: list[str] = []
    for row in rows:
        for key in ("evidence_file", "evidence_path"):
            value = row.get(key)
            if value:
                evidence_files.append(str(value))
        evidence = row.get("evidence")
        if isinstance(evidence, dict):
            evidence_files.extend(
                value
                for value in evidence.values()
                if isinstance(value, str) and value.endswith((".json", ".log", ".jsonl"))
            )
    return sorted(set(evidence_files))


def mismatch_job_rows(affected_jobs: set[tuple[str, str, str]]) -> list[dict[str, str]]:
    return [
        {
            "connector": item[0],
            "crs": item[1],
            "mrts": item[2],
            "command": f"make verified-full-matrix-job CONNECTOR={item[0]} CRS={item[1]} MRTS={item[2]}",
        }
        for item in sorted(affected_jobs)
    ]


def load_mismatch_rows(connector_root: Path, case: str, connector: str, crs: str, mrts: str) -> dict[str, Any]:
    path = connector_root / "reports/testing/generated/manifest/verified-runtime-mismatch-analysis.generated.json"
    data = read_json(path)
    rows = case_mismatch_rows(data, case)
    exact = exact_mismatch_rows(rows, connector, crs, mrts)
    affected_jobs = affected_mismatch_jobs(rows, connector, crs, mrts)
    return {
        "report": str(path),
        "case_rows": rows,
        "exact_rows": exact,
        "affected_jobs": mismatch_job_rows(affected_jobs),
        "evidence_files": mismatch_evidence_files(exact or rows),
    }


def resolve_evidence_path(path_value: str, connector_root: Path, build_root: Path, verified_run_root: Path) -> Path:
    path = Path(path_value)
    if path.is_absolute():
        return path
    for root in (connector_root, build_root, verified_run_root):
        candidate = root / path
        if candidate.exists():
            return candidate
    return connector_root / path


def full_matrix_refresh_needed(
    mismatch: dict[str, Any],
    connector_root: Path,
    build_root: Path,
    verified_run_root: Path,
    case_run_mtime: float,
) -> bool:
    evidence_files = mismatch.get("evidence_files") or []
    existing: list[Path] = []
    for item in evidence_files:
        path = resolve_evidence_path(str(item), connector_root, build_root, verified_run_root)
        if path.exists():
            existing.append(path)
    if not existing:
        return bool(mismatch.get("case_rows"))
    return all(case_run_mtime > path.stat().st_mtime for path in existing)


def markdown_table(headers: list[str], rows: list[list[Any]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(str(item).replace("|", "\\|").replace("\n", " ") for item in row) + " |")
    return "\n".join(lines)


def render_markdown(report: dict[str, Any]) -> str:
    result = report["result"]
    request = report["case_definition"].get("request", {})
    official = report["official_mismatch_report"]
    exact_rows = official.get("exact_rows") or []
    case_rows = official.get("case_rows") or []
    official_rows = exact_rows or case_rows
    row_table = markdown_table(
        ["Classification", "Category", "Connector", "Variant", "Expected", "Actual", "Critical", "Evidence"],
        [
            [
                row.get("classification", "-"),
                row.get("category", "-"),
                row.get("connector", "-"),
                row.get("variant", "-"),
                row.get("expected", "-"),
                row.get("actual", "-"),
                row.get("critical", row.get("is_critical", "-")),
                row.get("evidence_file") or row.get("evidence_path") or "-",
            ]
            for row in official_rows
        ]
        or [["-", "-", "-", "-", "-", "-", "-", "-"]],
    )
    affected_jobs = markdown_table(
        ["Connector", "CRS", "MRTS", "Command"],
        [[job["connector"], job["crs"], job["mrts"], f"`{job['command']}`"] for job in official.get("affected_jobs", [])],
    )
    artifacts = markdown_table(
        ["Artifact", "Path"],
        [[Path(item["path"]).name, item["path"]] for item in report["evidence_artifacts"][:40]]
        or [["-", "-"]],
    )
    rule = report.get("rule_evidence", {})
    excerpt = "\n".join(f"- `{line}`" for line in report.get("log_excerpt", [])[:40]) or "- No focused log excerpt found."
    return "\n\n".join(
        [
            "# Verified Case Run",
            "## Summary",
            markdown_table(
                ["Field", "Value"],
                [
                    ["Connector", report["connector"]],
                    ["Case", report["case"]],
                    ["Variant", f"{report['crs']}/{report['mrts']}"],
                    ["Status", result.get("status", "-")],
                    ["Expected", result.get("expected_status", "-")],
                    ["Actual", result.get("actual_status", result.get("observed_status", "-"))],
                    ["Return Code", report["return_code"]],
                    ["Full-Matrix Refresh Needed", report["full_matrix_refresh_needed"]],
                ],
            ),
            "## Request",
            markdown_table(
                ["Field", "Value"],
                [
                    ["Case Definition", report["case_definition"].get("path", "-")],
                    ["Method", request.get("method", "-")],
                    ["URI", request.get("path", "-")],
                    ["Headers", json.dumps(request.get("headers", {}), sort_keys=True)],
                    ["Body", repr(request.get("body", ""))[:500]],
                    ["Transforms", ", ".join(report["case_definition"].get("transforms", [])) or "-"],
                    ["Rule IDs", ", ".join(report["case_definition"].get("rule_ids", [])) or "-"],
                ],
            ),
            "## Evidence",
            artifacts,
            "## Official Mismatch Context",
            row_table,
            "## Affected Full-Matrix Jobs",
            affected_jobs,
            "## Rule Evidence",
            markdown_table(
                ["Field", "Value"],
                [
                    ["Rule ID", rule.get("rule_id", "-")],
                    ["Matched Data", rule.get("matched_data", "-")],
                    ["Matched Variable", rule.get("matched_variable", "-")],
                    ["Reason", rule.get("reason", "-")],
                ],
            ),
            "## Log Excerpt",
            excerpt,
            "## Next Step",
            "\n".join(
                [
                    f"- Re-run this case: `make verified-case CONNECTOR={report['connector']} CASE={report['case']} CRS={report['crs']} MRTS={report['mrts']}`",
                    f"- Re-run the matching Full-Matrix job: `make verified-full-matrix-job CONNECTOR={report['connector']} CRS={report['crs']} MRTS={report['mrts']}`",
                ]
            ),
        ]
    )


def explain(args: argparse.Namespace, case_def: dict[str, Any], mismatch: dict[str, Any]) -> int:
    rows = mismatch.get("exact_rows") or mismatch.get("case_rows") or []
    print("Verified case explain")
    print(f"case: {args.case}")
    print(f"connector: {args.connector}")
    print(f"variant: {args.crs}/{args.mrts}")
    print(f"case_definition: {case_def.get('path', '-')}")
    print(f"would_run: make verified-case CONNECTOR={args.connector} CASE={args.case} CRS={args.crs} MRTS={args.mrts}")
    print(f"matching_report: {mismatch.get('report')}")
    print(f"listed_in_report: {'yes' if rows else 'no'}")
    if rows:
        print("official_rows:")
        for row in rows:
            print(
                "  "
                + json.dumps(
                    {
                        "classification": row.get("classification"),
                        "category": row.get("category"),
                        "connector": row.get("connector"),
                        "variant": row.get("variant"),
                        "expected": row.get("expected"),
                        "actual": row.get("actual"),
                        "critical": row.get("critical", row.get("is_critical")),
                        "evidence_file": row.get("evidence_file") or row.get("evidence_path"),
                    },
                    sort_keys=True,
                )
            )
    print("affected_full_matrix_jobs:")
    for job in mismatch.get("affected_jobs", []):
        print(f"  {job['command']}")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run one verified runtime case and write focused local evidence.")
    parser.add_argument("--connector", required=True, choices=sorted(CONNECTORS))
    parser.add_argument("--case", required=True)
    parser.add_argument("--crs", required=True)
    parser.add_argument("--mrts", required=True)
    parser.add_argument("--connector-root", default=".")
    parser.add_argument("--framework-root", required=True)
    parser.add_argument("--build-root", required=True)
    parser.add_argument("--source-root", default=None)
    parser.add_argument("--tmp-root", default=None)
    parser.add_argument("--verified-run-root", default=None)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--explain", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        connector_root, framework_root = canonical_roots(
            args.connector_root, args.framework_root
        )
        args.case, args.crs, args.mrts = verified_case_tokens(
            args.case, args.crs, args.mrts
        )
    except (OSError, ValueError) as exc:
        print(f"run-verified-case: {exc}", file=sys.stderr)
        return 77
    case_path = find_case_path(framework_root, args.case)
    case_def = summarize_case_definition(case_path)
    mismatch = load_mismatch_rows(connector_root, args.case, args.connector, args.crs, args.mrts)
    if args.explain:
        return explain(args, case_def, mismatch)
    try:
        build_root = ensure_safe_runtime_directory(Path(os.path.abspath(args.build_root)))
        source_root = Path(args.source_root).resolve(strict=True) if args.source_root else connector_root
        if not is_read_only_source_path(source_root):
            raise ValueError(f"source root must be a canonical read-only source path: {source_root}")
        tmp_value = Path(os.path.abspath(args.tmp_root)) if args.tmp_root else build_root / "tmp"
        tmp_root = ensure_safe_runtime_directory(
            runtime_artifact_path(build_root, tmp_value, "temporary root")
        )
        verified_run_root = prepare_verified_runtime_artifact_root(
            args.verified_run_root,
            fallback=DEFAULT_VERIFIED_RUN_ROOT,
        )
    except ValueError as exc:
        print(f"run-verified-case: {exc}", file=sys.stderr)
        return 77

    started_at = utc_now()
    run_id = f"{started_at.strftime('%Y%m%dT%H%M%SZ')}-{safe_name(args.connector)}-{safe_name(args.case)}-{safe_name(args.crs)}-{safe_name(args.mrts)}"
    run_dir = ensure_safe_runtime_directory(verified_run_root / "case-runs" / run_id)
    logs_dir = ensure_safe_runtime_directory(run_dir / "logs")

    cmd, env, paths = build_harness_command(
        args.connector,
        connector_root,
        framework_root,
        build_root,
        source_root,
        tmp_root,
        args.python,
        args.case,
        args.crs,
        args.mrts,
    )
    command_log = run_dir / "command.log"
    return_code = 1
    with command_log.open("w", encoding="utf-8") as handle:
        handle.write("$ " + " ".join(cmd) + "\n")
        handle.flush()
        proc = subprocess.run(
            cmd,
            cwd=connector_root,
            env=env,
            stdout=handle,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        return_code = proc.returncode

    result_path = find_result_json(paths, args.case, started_at.timestamp())
    case_result_path = run_dir / RESULT_FILENAME
    if result_path and result_path.is_file():
        result = read_json(result_path)
        shutil.copy2(result_path, case_result_path)
    else:
        result = {
            "status": "missing_result",
            "expected_status": case_def.get("expect", {}).get("status") if isinstance(case_def.get("expect"), dict) else None,
            "actual_status": None,
            "reason": f"Harness completed without a discoverable {RESULT_FILENAME}.",
        }
        write_json(verified_run_root, case_result_path, result)
    result.setdefault("status", "unknown")

    logs = relevant_log_files(paths, args.case, result)
    logs.append(command_log)
    artifacts = copy_or_excerpt_logs(sorted(set(logs)), logs_dir)
    rule_evidence = result_rule_evidence(result, artifacts)
    log_excerpt = collect_log_excerpt(artifacts)
    case_run_mtime = case_result_path.stat().st_mtime
    refresh_needed = full_matrix_refresh_needed(mismatch, connector_root, build_root, verified_run_root, case_run_mtime)
    ended_at = utc_now()

    report = {
        "schema_version": 1,
        "report_kind": "verified-case-run",
        "started_at": iso_utc(started_at),
        "ended_at": iso_utc(ended_at),
        "duration_seconds": round((ended_at - started_at).total_seconds(), 3),
        "connector": args.connector,
        "case": args.case,
        "crs": args.crs,
        "mrts": args.mrts,
        "return_code": return_code,
        "command": cmd,
        "case_definition": case_def,
        "result": result,
        "result_source": str(result_path) if result_path else "-",
        "evidence_artifacts": artifacts,
        "log_excerpt": log_excerpt,
        "rule_evidence": rule_evidence,
        "official_mismatch_report": mismatch,
        "full_matrix_refresh_needed": refresh_needed,
        "next_steps": {
            "case_rerun": f"make verified-case CONNECTOR={args.connector} CASE={args.case} CRS={args.crs} MRTS={args.mrts}",
            "full_matrix_job": f"make verified-full-matrix-job CONNECTOR={args.connector} CRS={args.crs} MRTS={args.mrts}",
        },
    }
    write_json(verified_run_root, run_dir / "case-run.json", report)
    (run_dir / "case-run.md").write_text(render_markdown(report) + "\n", encoding="utf-8")

    print(f"case-run: {run_dir}")
    print(f"case-run.json: {run_dir / 'case-run.json'}")
    print(f"case-run.md: {run_dir / 'case-run.md'}")
    print(f"{RESULT_FILENAME}: {case_result_path}")
    print(f"status: {result.get('status')} return_code={return_code}")
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
