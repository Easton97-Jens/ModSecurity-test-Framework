#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import yaml
except Exception:  # pragma: no cover - report still works without PyYAML.
    yaml = None


TARGETS = ("apache2_ubuntu", "nginx-pr24")
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
    return Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local/state")))


def read_json(path: Path) -> dict[str, Any]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"status": "BLOCKED", "reason": f"invalid job JSON: {exc}", "job_json": str(path)}
    return raw if isinstance(raw, dict) else {"status": "BLOCKED", "reason": "job JSON is not an object", "job_json": str(path)}


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
            "job_root": display_native_path(job_root, native_root),
            "job_json": display_native_path(job_json, native_root),
            "run_log": display_native_path(job_root / "run.log", native_root),
        }
    job = read_json(job_json)
    job.setdefault("target", target)
    job["job_root"] = display_native_path(Path(str(job.get("job_root") or job_root)), native_root)
    job["job_json"] = display_native_path(Path(str(job.get("job_json") or job_json)), native_root)
    job["run_log"] = display_native_path(Path(str(job.get("run_log") or job_root / "run.log")), native_root)
    if job.get("summary_path"):
        job["summary_path"] = display_native_path(Path(str(job["summary_path"])), native_root)
    job["status"] = str(job.get("status") or "UNKNOWN").upper().replace("-", "_")
    job["remediation"] = dependency_remediations(str(job.get("reason") or ""))
    return job


def dependency_remediations(reason: str) -> list[dict[str, str]]:
    if not reason:
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
        "## Native Target Summary",
        "| Target | Status | Reason | Run log | Summary |",
        "|---|---|---|---|---|",
    ]
    for target in TARGETS:
        job = report["targets"].get(target, {})
        lines.append(
            "| {target} | {status} | {reason} | `{run_log}` | `{summary_path}` |".format(
                target=target,
                status=job.get("status", "UNKNOWN"),
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
    build_root = Path(os.environ.get("BUILD_ROOT", str(default_state_home() / "ModSecurity-conector-build"))).resolve()
    native_root = Path(args.native_root).resolve() if args.native_root else Path(os.environ.get("MRTS_NATIVE_ROOT", str(build_root / "mrts-native"))).resolve()
    output_root = Path(args.output_root).resolve() if args.output_root else connector_root
    report_dir = output_root / "reports/testing/generated"
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
    }

    json_path = report_dir / "mrts-native-full.generated.json"
    md_path = report_dir / "mrts-native-full.generated.md"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(report_markdown(report), encoding="utf-8")
    print(md_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
