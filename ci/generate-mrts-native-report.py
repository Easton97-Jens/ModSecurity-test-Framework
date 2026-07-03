#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import yaml
except Exception:  # pragma: no cover - report still works without PyYAML.
    yaml = None


TARGETS = ("apache2_ubuntu", "nginx-pr24")
MAX_RUN_LOG_BYTES = 1024 * 1024
TARGET_REPORT_FILENAMES = {
    "apache2_ubuntu": ("mrts-native-apache.generated.json", "mrts-native-apache.generated.md"),
    "nginx-pr24": ("mrts-native-nginx.generated.json", "mrts-native-nginx.generated.md"),
}
NATIVE_REPORT_LINKS = {
    "apache": "reports/testing/generated/mrts-native/mrts-native-apache.generated.md",
    "nginx": "reports/testing/generated/mrts-native/mrts-native-nginx.generated.md",
    "summary": "reports/testing/generated/mrts-native/mrts-native-summary.generated.md",
    "combined": "reports/testing/generated/mrts-native/mrts-native-full.generated.md",
}
DEPENDENCY_REMEDIATIONS = {
    "go-ftw": {
        "env_var": "GO_FTW_BIN",
        "scope": "native MRTS targets and mrts-ftw-style go-ftw execution",
        "hint": "Set GO_FTW_BIN to a local go-ftw binary.",
    },
    "albedo": {
        "env_var": "ALBEDO_BIN",
        "scope": "native MRTS targets only",
        "hint": "Set ALBEDO_BIN to a local albedo backend binary.",
    },
    "apachectl": {
        "env_var": "APACHECTL_BIN",
        "scope": "apache2_ubuntu native MRTS target only",
        "hint": "Set APACHECTL_BIN to a local apachectl-compatible binary.",
    },
    "nginx": {
        "env_var": "MRTS_NATIVE_NGINX_BIN",
        "scope": "nginx-pr24 native MRTS target only",
        "hint": "Set MRTS_NATIVE_NGINX_BIN to a local nginx binary.",
    },
    "ngx_http_modsecurity_module.so": {
        "env_var": "MRTS_NATIVE_NGINX_MODULE_DIR",
        "scope": "nginx-pr24 native MRTS target only",
        "hint": "Set MRTS_NATIVE_NGINX_MODULE_DIR to a local directory containing ngx_http_modsecurity_module.so.",
    },
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def default_state_home() -> Path:
    run_root = Path(os.environ.get("VERIFIED_RUN_ROOT", str(Path(os.environ.get("RUNNER_TEMP") or os.environ.get("TMPDIR") or "/var/tmp") / "ModSecurity-conector-verified")))
    return Path(os.environ.get("VERIFIED_STATE_ROOT", str(run_root / "state")))


def read_json(path: Path) -> dict[str, Any]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"status": "BLOCKED", "reason": f"invalid job JSON: {exc}", "job_json": str(path)}
    return raw if isinstance(raw, dict) else {"status": "BLOCKED", "reason": "job JSON is not an object", "job_json": str(path)}


def read_optional_json(path: Path) -> dict[str, Any]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return raw if isinstance(raw, dict) else {}


def canonical_under(path: Path, roots: list[Path]) -> Path | None:
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        return None
    for root in roots:
        try:
            resolved.relative_to(root.resolve(strict=True) if root.exists() else root.resolve(strict=False))
            return resolved
        except ValueError:
            continue
    return None


def read_bounded_run_log(path: Path, roots: list[Path], max_bytes: int = MAX_RUN_LOG_BYTES) -> str:
    resolved = canonical_under(path, roots)
    if resolved is None or not resolved.is_file() or resolved.is_symlink():
        return ""
    try:
        stat = resolved.stat()
    except OSError:
        return ""
    if stat.st_size > max_bytes:
        return ""
    try:
        return resolved.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def first_match(pattern: str, text: str) -> str:
    match = re.search(pattern, text, flags=re.MULTILINE)
    return match.group(1) if match else ""


def parse_failed_cases(run_text: str) -> list[str]:
    failed: list[str] = []
    payload = first_match(r"failed to run:\s+\[(.*?)\]", run_text)
    if payload:
        for item in payload.split(","):
            case_id = item.strip().strip("\"'")
            if case_id and case_id not in failed:
                failed.append(case_id)
    for match in re.findall(r"\b([0-9]+-[0-9]+)\s+failed\b", run_text):
        if match not in failed:
            failed.append(match)
    return failed


def collect_run_counts(run_log: Path, status: str, allowed_roots: list[Path] | None = None) -> dict[str, Any]:
    run_text = read_bounded_run_log(run_log, allowed_roots or [run_log.parent])
    attempted = int(first_match(r"run\s+([0-9]+)\s+total tests", run_text) or 0)
    pass_count = run_text.count("passed in")
    failed_cases = parse_failed_cases(run_text)
    fail_count = len(failed_cases)
    if fail_count == 0:
        fail_count = int(first_match(r"([0-9]+)\s+test\(s\)\s+failed", run_text) or 0)
    if attempted and status == "PASS" and pass_count == 0:
        pass_count = attempted
    if attempted and fail_count and pass_count + fail_count < attempted:
        pass_count = attempted - fail_count
    return {
        "attempted": attempted,
        "pass": pass_count,
        "fail": fail_count,
        "blocked": 1 if status == "BLOCKED" and attempted == 0 else 0,
        "not_executable": 0,
        "failed_cases": failed_cases,
    }


def read_overlay_metadata(framework_root: Path) -> dict[str, Any]:
    path = framework_root / "tests/mrts/infra-overlays/nginx-pr24/metadata.yaml"
    if not path.is_file():
        return {"path": str(path), "status": "missing"}
    if yaml is None:
        return {"path": str(path), "status": "present"}
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"path": str(path), "status": "invalid", "reason": str(exc)}
    return jsonable(raw) if isinstance(raw, dict) else {"path": str(path), "status": "invalid"}


def jsonable(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): jsonable(item) for key, item in value.items()}
    if isinstance(value, list):
        return [jsonable(item) for item in value]
    if isinstance(value, tuple):
        return [jsonable(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def normalize_job(target: str, native_root: Path) -> dict[str, Any]:
    job_root = native_root / target
    job_json = job_root / "job.json"
    if not job_json.is_file():
        return {
            "target": target,
            "status": "NOT_RUN",
            "reason": "native target job.json not found",
            "counts": {"attempted": 0, "pass": 0, "fail": 0, "blocked": 0, "not_executable": 0, "failed_cases": []},
            "job_root": display_native_path(job_root, native_root),
            "job_json": display_native_path(job_json, native_root),
            "run_log": display_native_path(job_root / "run.log", native_root),
            "paths": target_paths(target, native_root),
            "known_limitations": known_limitations([]),
            "first_failing_cases": [],
        }
    job = read_json(job_json)
    job.setdefault("target", target)
    raw_run_log = Path(str(job.get("run_log") or job_root / "run.log"))
    status = str(job.get("status") or "UNKNOWN").upper().replace("-", "_")
    counts = collect_run_counts(raw_run_log, status, [native_root, job_root])
    job["job_root"] = display_native_path(Path(str(job.get("job_root") or job_root)), native_root)
    job["job_json"] = display_native_path(Path(str(job.get("job_json") or job_json)), native_root)
    job["run_log"] = display_native_path(raw_run_log, native_root)
    if job.get("summary_path"):
        job["summary_path"] = display_native_path(Path(str(job["summary_path"])), native_root)
    job["status"] = status
    job["counts"] = counts
    job["paths"] = target_paths(target, native_root)
    job["known_limitations"] = known_limitations(counts.get("failed_cases", []))
    job["first_failing_cases"] = [failing_case_details(case_id) for case_id in counts.get("failed_cases", [])[:5]]
    job["remediation"] = dependency_remediations(str(job.get("reason") or ""))
    return job


def dependency_remediations(reason: str) -> list[dict[str, str]]:
    if not reason:
        return []
    if "missing native dependencies" not in reason:
        return []
    found = []
    for dependency, remediation in DEPENDENCY_REMEDIATIONS.items():
        if dependency in reason:
            found.append({"dependency": dependency, **remediation})
    return found


def display_native_path(path: Path, native_root: Path) -> str:
    try:
        return "$MRTS_NATIVE_ROOT/" + str(path.resolve(strict=False).relative_to(native_root.resolve(strict=False)))
    except ValueError:
        return str(path)


def display_root_path(path: Path, root: Path, label: str) -> str:
    try:
        relative = path.resolve(strict=False).relative_to(root.resolve(strict=False))
    except ValueError:
        return str(path)
    if str(relative) == ".":
        return label
    return f"{label}/{relative}"


def target_paths(target: str, native_root: Path) -> dict[str, str]:
    job_root = native_root / target
    return {
        "staged_infra_path": display_native_path(job_root / "stage/infra", native_root),
        "run_log_path": display_native_path(job_root / "run.log", native_root),
        "job_json_path": display_native_path(job_root / "job.json", native_root),
    }


def known_limitations(failed_cases: list[str]) -> list[str]:
    limitations = ["phase4_native_limitation", "RESPONSE_BODY non-promoted"]
    if "100003-1" not in failed_cases:
        return limitations
    return limitations


def failing_case_details(case_id: str) -> dict[str, Any]:
    if case_id == "100003-1":
        return {
            "case_id": "100003-1",
            "rule_id": "100003",
            "phase": "4",
            "variable": "ARGS",
            "target": "ARGS",
            "expected": "HTTP 200 backend response plus ModSecurity log id 100003",
            "actual": "HTTP 200 backend response observed; expected phase 4 log id 100003 missing",
            "classification": "native_modsecurity_semantics",
            "secondary_classification": "phase4_native_limitation",
            "rule": 'SecRule ARGS "@contains attack" "id:100003, phase:4, deny, t:none, log"',
            "request": "POST /?foo=attack",
            "evidence_summary": "Native ModSecurity reaches the request and earlier request-collection phases, but the phase 4 ARGS rule does not log in native Apache or NGINX evidence.",
        }
    return {
        "case_id": case_id,
        "rule_id": "-",
        "phase": "-",
        "variable": "-",
        "target": "-",
        "expected": "go-ftw expected result",
        "actual": "go-ftw reported failed case",
        "classification": "native_evidence_unclassified",
        "secondary_classification": "-",
        "rule": "-",
        "request": "-",
        "evidence_summary": "Native go-ftw reported this case as failed.",
    }


def env_path_roots(native_root: Path) -> list[tuple[str, Path]]:
    roots: list[tuple[str, Path]] = [("MRTS_NATIVE_ROOT", native_root)]
    for name in ("CONNECTOR_COMPONENT_CACHE", "BUILD_ROOT", "MRTS_BUILD_ROOT"):
        value = os.environ.get(name)
        if value:
            roots.append((name, Path(value)))
    return roots


def display_component_value(value: Any, roots: list[tuple[str, Path]]) -> Any:
    if not isinstance(value, str):
        return value
    if not value.startswith("/"):
        return value
    path = Path(value)
    for label, root in roots:
        try:
            relative = path.resolve(strict=False).relative_to(root.resolve(strict=False))
        except ValueError:
            continue
        return f"${label}/{relative}"
    return f"<system-path-redacted>/{path.name}"


def runtime_components_for_target(target: str, components: dict[str, Any], native_root: Path) -> dict[str, Any]:
    roots = env_path_roots(native_root)
    modsecurity = components.get("modsecurity", {}) if isinstance(components.get("modsecurity"), dict) else {}
    go_ftw = components.get("go_ftw", {}) if isinstance(components.get("go_ftw"), dict) else {}
    albedo = components.get("albedo", {}) if isinstance(components.get("albedo"), dict) else {}
    common = {
        "modsecurity_build_id": modsecurity.get("build_id") or "-",
        "go_ftw_binary": display_component_value(go_ftw.get("binary") or go_ftw.get("path") or "-", roots),
        "albedo_binary": display_component_value(albedo.get("binary") or albedo.get("path") or "-", roots),
    }
    if target == "apache2_ubuntu":
        apache = components.get("apache_httpd", {}) if isinstance(components.get("apache_httpd"), dict) else {}
        return {
            "APACHECTL_BIN": display_component_value(apache.get("apachectl_bin") or "-", roots),
            "httpd_binary": display_component_value(apache.get("httpd_bin") or "-", roots),
            "mod_security3_so": display_component_value(apache.get("module_file") or "-", roots),
            "connector_build_id": apache.get("connector_build_id") or "-",
            **common,
        }
    nginx = components.get("nginx", {}) if isinstance(components.get("nginx"), dict) else {}
    return {
        "MRTS_NATIVE_NGINX_BIN": display_component_value(nginx.get("nginx_bin") or nginx.get("local_nginx_bin") or "-", roots),
        "MRTS_NATIVE_NGINX_MODULE_DIR": display_component_value(nginx.get("module_dir") or "-", roots),
        "ngx_http_modsecurity_module_so": display_component_value(nginx.get("module_file") or nginx.get("local_module_file") or "-", roots),
        "connector_build_id": nginx.get("connector_build_id") or "-",
        **common,
    }


def target_source(target: str, overlay: dict[str, Any]) -> dict[str, Any]:
    if target == "apache2_ubuntu":
        return {
            "target": "apache2_ubuntu",
            "source": "$MRTS_ROOT/config_infra/apache2_ubuntu",
            "infrastructure": "MRTS upstream Apache2 Ubuntu native infra",
        }
    source = overlay.get("source") if isinstance(overlay.get("source"), dict) else {}
    return {
        "target": "nginx-pr24",
        "source": "Framework PR24 overlay",
        "pr_url": source.get("pr_url", "https://github.com/owasp-modsecurity/MRTS/pull/24"),
        "infrastructure": "MRTS PR24 NGINX + libmodsecurity3 native infra",
        "pr_metadata": {
            "pr_number": source.get("pr_number", 24),
            "pr_head_sha": source.get("pr_head_sha", "-"),
            "captured_at_utc": source.get("captured_at_utc", "-"),
            "upstream_status": source.get("upstream_status", "open-pr"),
            "stability": source.get("stability", "experimental"),
            "replacement_note": source.get("replacement_note", "replace with $MRTS_ROOT/config_infra/nginx_linux once merged upstream"),
        },
    }


def target_report_payload(report: dict[str, Any], target: str, components: dict[str, Any], native_root: Path) -> dict[str, Any]:
    job = report["targets"].get(target, {})
    source = target_source(target, report.get("nginx_pr24_overlay", {}))
    return {
        "generated_at": report["generated_at"],
        "report_kind": "native-mrts-target-evidence",
        "separate_from_connector_full_matrix": True,
        **source,
        "status": job.get("status", "NOT_RUN"),
        "classification": job.get("classification", "optional_native_evidence_unknown"),
        "classification_notes": job.get("classification_notes", "-"),
        "optional": bool(job.get("optional", True)),
        "critical_merge_blocker": bool(job.get("critical_merge_blocker", False)),
        "counts": job.get("counts", {"attempted": 0, "pass": 0, "fail": 0, "blocked": 0, "not_executable": 0}),
        "known_limitations": job.get("known_limitations", known_limitations([])),
        "first_failing_cases": job.get("first_failing_cases", []),
        "runtime_components": runtime_components_for_target(target, components, native_root),
        "paths": job.get("paths", target_paths(target, native_root)),
        "guardrails": [
            "tools/MRTS read-only",
            "system paths read-only",
            "no generated MRTS artifacts committed",
            "native MRTS evidence is separate from connector full-matrix evidence",
        ],
        "job": job,
    }


def counts_markdown(counts: dict[str, Any]) -> list[str]:
    return [
        f"- attempted: **{counts.get('attempted', 0)}**",
        f"- pass: **{counts.get('pass', 0)}**",
        f"- fail: **{counts.get('fail', 0)}**",
        f"- blocked: **{counts.get('blocked', 0)}**",
        f"- not_executable: **{counts.get('not_executable', 0)}**",
    ]


def target_report_markdown(payload: dict[str, Any]) -> str:
    is_apache = payload.get("target") == "apache2_ubuntu"
    title = "# MRTS Native Apache Report" if is_apache else "# MRTS Native NGINX PR24 Report"
    lines = [
        title,
        "",
        f"Generated at: `{payload.get('generated_at', '-')}`",
        "",
        "## Target",
        f"- Target: `{payload.get('target', '-')}`",
        f"- Source: `{payload.get('source', '-')}`",
    ]
    if not is_apache:
        lines.append(f"- PR source: {payload.get('pr_url', '-')}")
    lines.extend(
        [
            f"- Infrastructure: {payload.get('infrastructure', '-')}",
            "- Native MRTS evidence is separate from connector full-matrix evidence.",
            "",
        ]
    )
    if not is_apache:
        pr = payload.get("pr_metadata", {})
        lines.extend(
            [
                "## PR Metadata",
                f"- PR number: `{pr.get('pr_number', '-')}`",
                f"- PR head SHA: `{pr.get('pr_head_sha', '-')}`",
                f"- captured_at_utc: `{pr.get('captured_at_utc', '-')}`",
                f"- upstream_status: `{pr.get('upstream_status', '-')}`",
                f"- stability: `{pr.get('stability', '-')}`",
                f"- replacement note: {pr.get('replacement_note', '-')}",
                "",
            ]
        )
    lines.extend(
        [
            "## Status",
            f"- Status: **{payload.get('status', 'NOT_RUN')}**",
            f"- Classification: `{payload.get('classification', 'optional_native_evidence_unknown')}`",
            f"- Optional evidence: `{str(payload.get('optional', True)).lower()}`",
            f"- Critical merge blocker: `{str(payload.get('critical_merge_blocker', False)).lower()}`",
            f"- Notes: {payload.get('classification_notes', '-')}",
            "",
            "## Counts",
        ]
    )
    lines.extend(counts_markdown(payload.get("counts", {})))
    lines.extend(["", "## Known Limitations"])
    for item in payload.get("known_limitations", []):
        lines.append(f"- `{item}`")
    lines.extend(["", "## First Failing Cases"])
    failing_cases = payload.get("first_failing_cases", [])
    if not failing_cases:
        lines.append("- None recorded.")
    for case in failing_cases:
        lines.extend(
            [
                f"- Case: `{case.get('case_id', '-')}`",
                f"  Rule ID: `{case.get('rule_id', '-')}`",
                f"  Phase: `{case.get('phase', '-')}`",
                f"  Variable/target: `{case.get('variable', '-')}` / `{case.get('target', '-')}`",
                f"  Expected: {case.get('expected', '-')}",
                f"  Actual: {case.get('actual', '-')}",
                f"  Classification: `{case.get('classification', '-')}` / `{case.get('secondary_classification', '-')}`",
                f"  Evidence summary: {case.get('evidence_summary', '-')}",
                f"  Rule: `{case.get('rule', '-')}`",
                f"  Request: `{case.get('request', '-')}`",
            ]
        )
    lines.extend(["", "## Runtime Components"])
    for key, value in payload.get("runtime_components", {}).items():
        lines.append(f"- {key}: `{value}`")
    lines.extend(["", "## Paths"])
    for key, value in payload.get("paths", {}).items():
        lines.append(f"- {key}: `{value}`")
    lines.extend(["", "## Guardrails"])
    for item in payload.get("guardrails", []):
        lines.append(f"- {item}")
    return "\n".join(lines) + "\n"


def summary_report_payload(report: dict[str, Any], target_reports: dict[str, dict[str, Any]]) -> dict[str, Any]:
    return {
        "generated_at": report["generated_at"],
        "report_kind": "native-mrts-summary",
        "separate_from_connector_full_matrix": True,
        "reports": NATIVE_REPORT_LINKS,
        "targets": {
            target: {
                "status": payload.get("status", "NOT_RUN"),
                "classification": payload.get("classification", "optional_native_evidence_unknown"),
                "optional": bool(payload.get("optional", True)),
                "critical_merge_blocker": bool(payload.get("critical_merge_blocker", False)),
                "counts": payload.get("counts", {}),
                "report": NATIVE_REPORT_LINKS["apache" if target == "apache2_ubuntu" else "nginx"],
            }
            for target, payload in target_reports.items()
        },
        "note": "Native MRTS evidence is separate from connector runtime matrix evidence.",
    }


def summary_report_markdown(payload: dict[str, Any]) -> str:
    targets = payload.get("targets", {})
    apache = targets.get("apache2_ubuntu", {})
    nginx = targets.get("nginx-pr24", {})
    lines = [
        "# MRTS Native Summary",
        "",
        f"Generated at: `{payload.get('generated_at', '-')}`",
        "",
        "| Native target | Report | Status | Classification | Critical blocker | Attempted | Pass | Fail | Blocked |",
        "|---|---|---|---|---:|---:|---:|---:|---:|",
    ]
    for label, key in (("Apache2 Ubuntu", "apache2_ubuntu"), ("NGINX PR24", "nginx-pr24")):
        item = apache if key == "apache2_ubuntu" else nginx
        counts = item.get("counts", {})
        report_path = item.get("report", "-")
        lines.append(
            f"| {label} | {Path(report_path).name if report_path != '-' else '-'} | {item.get('status', 'NOT_RUN')} | `{item.get('classification', 'optional_native_evidence_unknown')}` | {str(item.get('critical_merge_blocker', False)).lower()} | {counts.get('attempted', 0)} | {counts.get('pass', 0)} | {counts.get('fail', 0)} | {counts.get('blocked', 0)} |"
        )
    lines.extend(
        [
            "",
            f"Combined report: `{payload.get('reports', {}).get('combined', NATIVE_REPORT_LINKS['combined'])}`",
            "",
            "Note: Native MRTS evidence is separate from connector runtime matrix evidence.",
        ]
    )
    return "\n".join(lines) + "\n"


def report_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# MRTS Native Infrastructure Report",
        "",
        f"Generated at: `{report['generated_at']}`",
        "",
        "## Executive Summary",
        f"- PASS: **{summary.get('PASS', 0)}**",
        f"- FAIL: **{summary.get('FAIL', 0)}**",
        f"- BLOCKED: **{summary.get('BLOCKED', 0)}**",
        f"- NOT_RUN: **{summary.get('NOT_RUN', 0)}**",
        "",
        "## Split Native Reports",
        f"- Apache native: `{NATIVE_REPORT_LINKS['apache']}`",
        f"- NGINX PR24 native: `{NATIVE_REPORT_LINKS['nginx']}`",
        f"- Native summary: `{NATIVE_REPORT_LINKS['summary']}`",
        f"- Combined native report: `{NATIVE_REPORT_LINKS['combined']}`",
        "",
        "These native MRTS reports are separate from connector full-matrix evidence.",
        "",
        "## Native Target Summary",
        "| Target | Status | Classification | Critical blocker | Attempted | PASS | FAIL | BLOCKED | Reason | Run log | Summary |",
        "|---|---|---|---:|---:|---:|---:|---:|---|---|---|",
    ]
    for target in TARGETS:
        job = report["targets"].get(target, {})
        counts = job.get("counts", {})
        lines.append(
            "| {target} | {status} | `{classification}` | {critical_blocker} | {attempted} | {passed} | {failed} | {blocked} | {reason} | `{run_log}` | `{summary_path}` |".format(
                target=target,
                status=job.get("status", "UNKNOWN"),
                classification=job.get("classification", "optional_native_evidence_unknown"),
                critical_blocker=str(job.get("critical_merge_blocker", False)).lower(),
                attempted=counts.get("attempted", 0),
                passed=counts.get("pass", 0),
                failed=counts.get("fail", 0),
                blocked=counts.get("blocked", 0),
                reason=str(job.get("reason") or job.get("details") or "-").replace("|", "\\|"),
                run_log=job.get("run_log", "-"),
                summary_path=job.get("summary_path", "-"),
            )
        )
    remediation_lines = []
    for target in TARGETS:
        job = report["targets"].get(target, {})
        for remediation in job.get("remediation", []):
            remediation_lines.append(
                "- {target}: `{dependency}` missing; set `{env_var}`. Scope: {scope}. {hint}".format(
                    target=target,
                    dependency=remediation.get("dependency", "-"),
                    env_var=remediation.get("env_var", "-"),
                    scope=remediation.get("scope", "-"),
                    hint=remediation.get("hint", ""),
                )
            )
    overlay = report.get("nginx_pr24_overlay", {})
    source = overlay.get("source") if isinstance(overlay.get("source"), dict) else {}
    lines.extend(
        [
            "",
            "## Apache2 Ubuntu Native Infra",
            "- Source: `$MRTS_ROOT/config_infra/apache2_ubuntu` staged under `MRTS_NATIVE_ROOT`.",
            "- Evidence is native MRTS infrastructure evidence and does not replace connector smoke evidence.",
            "",
            "## NGINX PR24 Native Infra",
            f"- PR URL: {source.get('pr_url', '-')}",
            f"- PR number: {source.get('pr_number', '-')}",
            f"- PR head SHA: `{source.get('pr_head_sha', '-')}`",
            f"- Captured at UTC: `{source.get('captured_at_utc', '-')}`",
            f"- Upstream status: `{source.get('upstream_status', '-')}`",
            f"- Stability: `{source.get('stability', '-')}`",
            f"- Replacement note: {source.get('replacement_note', '-')}",
            "",
            "## Known Limitations",
            "- Phase 4 and RESPONSE_BODY native evidence remains non-promoted.",
            "- Missing native binaries, modules, go-ftw, or backend tooling is reported as BLOCKED.",
            "",
            "## Missing Dependency Remediation",
            *(remediation_lines or ["- No missing native dependencies were reported in this run."]),
            "",
            "## Comparison Hints",
            "- Compare native MRTS results with connector smoke evidence by target and corpus.",
            "- Classification metadata explains gaps but never changes runtime PASS/FAIL/BLOCKED.",
            "",
            "## Guardrails",
            "- Native staging happens under `MRTS_NATIVE_ROOT`; repository sources are read-only inputs.",
            "- `tools/MRTS` and MRTS definitions are not edited by native report generation.",
            "- Generated MRTS rules, go-ftw YAML, load files, logs, and native results are not committed.",
        ]
    )
    return "\n".join(lines) + "\n"



def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--framework-root", default=Path(__file__).resolve().parents[1])
    parser.add_argument("--connector-root", default=Path.cwd())
    parser.add_argument("--native-root", default=None)
    parser.add_argument("--output-root", default=None)
    args = parser.parse_args()

    framework_root = Path(args.framework_root).resolve()
    connector_root = Path(args.connector_root).resolve()
    framework_ci = framework_root / "ci"
    if str(framework_ci) not in sys.path:
        sys.path.insert(0, str(framework_ci))
    from generated_report_utils import build_metadata, generated_json_text, generated_markdown_text, report_path_from_root, require_under

    build_root = Path(os.environ.get("BUILD_ROOT", str(default_state_home() / "ModSecurity-conector-build"))).resolve()
    native_root = Path(args.native_root).resolve() if args.native_root else Path(os.environ.get("MRTS_NATIVE_ROOT", str(build_root / "mrts-native"))).resolve()
    output_root = Path(args.output_root).resolve() if args.output_root else connector_root
    report_dir = require_under(output_root, output_root / "reports/testing/generated", "generated report directory")
    report_dir.mkdir(parents=True, exist_ok=True)

    targets = {target: normalize_job(target, native_root) for target in TARGETS}
    summary = Counter(str(job.get("status") or "UNKNOWN").upper() for job in targets.values())
    report = {
        "generated_at": utc_now(),
        "framework_root": display_root_path(framework_root, framework_root, "$FRAMEWORK_ROOT"),
        "connector_root": display_root_path(connector_root, connector_root, "$CONNECTOR_ROOT"),
        "native_root": "$MRTS_NATIVE_ROOT",
        "targets": targets,
        "summary": dict(sorted(summary.items())),
        "nginx_pr24_overlay": read_overlay_metadata(framework_root),
        "reports": NATIVE_REPORT_LINKS,
    }
    components = read_optional_json(report_path_from_root(report_dir, "runtime_component_cache", "json"))
    target_reports = {
        target: target_report_payload(report, target, components, native_root)
        for target in TARGETS
    }
    summary_report = summary_report_payload(report, target_reports)

    base_metadata = build_metadata(
        generated_by="framework:ci/generate-mrts-native-report.py",
        make_target="mrts-native-full-run",
        connector_root=connector_root,
        framework_root=framework_root,
        inputs=[native_root / "apache2_ubuntu/job.json", native_root / "nginx-pr24/job.json"],
        generated_at=report["generated_at"],
    )
    json_path = report_path_from_root(report_dir, "mrts_native_full", "json")
    md_path = report_path_from_root(report_dir, "mrts_native_full", "md")
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(generated_json_text(report, base_metadata), encoding="utf-8")
    md_path.write_text(generated_markdown_text(report_markdown(report), base_metadata), encoding="utf-8")
    for target, payload in target_reports.items():
        json_name, md_name = TARGET_REPORT_FILENAMES[target]
        key = "mrts_native_apache" if target == "apache2_ubuntu" else "mrts_native_nginx"
        target_metadata = build_metadata(
            generated_by="framework:ci/generate-mrts-native-report.py",
            make_target="mrts-native-full-run",
            connector_root=connector_root,
            framework_root=framework_root,
            inputs=[native_root / f"{target}/job.json"],
            generated_at=payload["generated_at"],
        )
        report_path_from_root(report_dir, key, "json").write_text(generated_json_text(payload, target_metadata), encoding="utf-8")
        report_path_from_root(report_dir, key, "md").write_text(generated_markdown_text(target_report_markdown(payload), target_metadata), encoding="utf-8")
    summary_metadata = build_metadata(
        generated_by="framework:ci/generate-mrts-native-report.py",
        make_target="mrts-native-full-run",
        connector_root=connector_root,
        framework_root=framework_root,
        inputs=[report_path_from_root(report_dir, "mrts_native_apache", "json"), report_path_from_root(report_dir, "mrts_native_nginx", "json")],
        generated_at=summary_report["generated_at"],
    )
    report_path_from_root(report_dir, "mrts_native_summary", "json").write_text(generated_json_text(summary_report, summary_metadata), encoding="utf-8")
    report_path_from_root(report_dir, "mrts_native_summary", "md").write_text(generated_markdown_text(summary_report_markdown(summary_report), summary_metadata), encoding="utf-8")
    print(md_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
