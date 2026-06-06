#!/usr/bin/env python3
"""Write HAProxy runtime-matrix evidence from existing framework YAML cases.

The current HAProxy harness has a very narrow live surface. This writer keeps
that distinction explicit: only exact live HAProxy evidence is written as pass
or fail. YAML cases outside the current HAProxy harness are recorded as blocked
or skipped with a matrix_status of BLOCKED or NOT_EXECUTABLE.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


def add_runner_path(framework_root: Path) -> None:
    runner_path = framework_root / "tests" / "runners"
    if str(runner_path) not in sys.path:
        sys.path.insert(0, str(runner_path))


def bool_value(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return loaded if isinstance(loaded, dict) else {}


def rel_path(path: Path, *roots: Path) -> str:
    resolved = path.resolve()
    for root in roots:
        try:
            return str(resolved.relative_to(root.resolve()))
        except ValueError:
            continue
    return str(resolved)


def all_case_files(framework_root: Path) -> list[Path]:
    case_root = framework_root / "tests" / "cases"
    return sorted(path for path in case_root.rglob("*.yaml") if path.is_file())


def response_related(capabilities: set[str], path_text: str) -> bool:
    if capabilities.intersection({"response-body", "response-headers", "response-filters", "phase3", "phase4"}):
        return True
    lowered = path_text.lower()
    return "/response/" in lowered or "/response-" in lowered or "response_body" in lowered


def unsupported_capability_reason(capabilities: set[str], path_text: str) -> str | None:
    if response_related(capabilities, path_text):
        return "HAProxy harness does not support response header/body phases; RESPONSE_BODY is not verified"
    unsupported = {
        "request-body": "request body is not mapped by the current HAProxy harness",
        "body-processors": "body processors are not mapped by the current HAProxy harness",
        "form-urlencoded": "request body form data is not mapped by the current HAProxy harness",
        "json": "JSON request body processing is not mapped by the current HAProxy harness",
        "multipart": "multipart and FILES collections are not mapped by the current HAProxy harness",
        "files": "FILES collections are not mapped by the current HAProxy harness",
        "xml": "XML request body processing is not mapped by the current HAProxy harness",
        "request-cookies": "request cookies are not mapped by the current HAProxy harness",
        "audit-log": "audit log behavior is not mapped by the current HAProxy harness",
        "audit-log-absent": "audit log absence is not mapped by the current HAProxy harness",
        "logging": "logging/audit assertions are not mapped by the current HAProxy harness",
        "redirect": "redirect intervention mapping is not implemented by the current HAProxy harness",
    }
    for capability, reason in unsupported.items():
        if capability in capabilities:
            return reason
    if "multipart" in path_text.lower() or "/body/" in path_text.lower():
        return "request body, multipart, JSON, XML, and FILES cases are outside the current HAProxy harness scope"
    if "/audit-log/" in path_text.lower():
        return "audit/log cases are outside the current HAProxy harness scope"
    return None


def connector_scope_not_applicable(scope: str) -> bool:
    return scope not in {"common", "unknown"} and not scope.startswith("haproxy/")


def matrix_promotion(matrix_status: str, response_body: bool) -> str:
    if response_body:
        return "RESPONSE_BODY non-verified; non-promotable"
    if matrix_status == "PASS":
        return "promotion eligible for this HAProxy-scoped case only"
    return "not promoted"


def live_crs_result(smoke: dict[str, Any], expected_status: int) -> tuple[str, int | None, str, str]:
    with_crs = smoke.get("with_crs") if isinstance(smoke.get("with_crs"), dict) else {}
    evidence = with_crs.get("modsecurity_evidence") or with_crs.get("spoe_set_var_ack_evidence")
    block_status = with_crs.get("block_probe_status")
    try:
        actual = int(block_status)
    except (TypeError, ValueError):
        actual = None
    if with_crs.get("status") == "PASS" and with_crs.get("crs_loaded") is True and actual == expected_status:
        return (
            "pass",
            actual,
            "PASS",
            str(evidence or "with-crs SQLi live probe returned expected status"),
        )
    return (
        "fail",
        actual,
        "FAIL",
        str(with_crs.get("blocked_reason") or "with-crs SQLi live probe did not produce PASS evidence"),
    )


def case_entry(
    *,
    case_path: Path,
    case: Mapping[str, Any],
    connector_root: Path,
    framework_root: Path,
    variant: str,
    smoke: dict[str, Any],
) -> dict[str, Any]:
    from runner_core import _capability_names, case_group, case_requires_crs, case_scope, effective_expect
    from msconnector_models import intervention_from_expect, operation_status

    name = str(case["name"])
    variant_for_expect = "with-crs" if variant == "with-crs" or (variant == "combined" and name == "crs_sqli_anomaly_block") else "no-crs"
    os.environ["MODSECURITY_TEST_VARIANT"] = variant_for_expect
    path_text = rel_path(case_path, connector_root, framework_root)
    scope = case_scope(case_path)
    group = case_group(case_path, case)
    capabilities = set(_capability_names(case))
    expect = effective_expect(case)
    expected_status = int(expect["status"])
    response_body = response_related(capabilities, path_text)
    connector_specific_elsewhere = connector_scope_not_applicable(scope)
    requires_crs = case_requires_crs(case)
    actual_status: int | None = None
    status = "skipped"
    matrix_status = "NOT_EXECUTABLE"
    reason = "outside current HAProxy harness scope"
    evidence = "not live-executed by HAProxy"
    live_executed = False

    if connector_specific_elsewhere:
        reason = f"{scope}-specific case is not applicable to HAProxy"
    elif variant == "no-crs" and requires_crs:
        reason = "case requires CRS and this is the No-CRS HAProxy matrix"
    elif variant in {"with-crs", "combined"} and name == "crs_sqli_anomaly_block":
        status, actual_status, matrix_status, evidence = live_crs_result(smoke, expected_status)
        live_executed = True
        reason = "live HAProxy With-CRS SQLi probe matched framework YAML request and expectation"
    else:
        unsupported_reason = unsupported_capability_reason(capabilities, path_text)
        if unsupported_reason is not None:
            reason = unsupported_reason
        elif name == "phase1_header_block":
            status = "blocked"
            matrix_status = "BLOCKED"
            reason = (
                "current HAProxy no-CRS smoke verifies alias haproxy_phase1_header_block, "
                "but it does not execute this YAML rule/header exactly"
            )
            evidence = str(smoke.get("evidence_path") or smoke.get("harness_path") or "HAProxy smoke summary")
        else:
            status = "blocked"
            matrix_status = "BLOCKED"
            reason = (
                "current HAProxy harness cannot materialize arbitrary framework YAML rules "
                "or request data for this relevant phase/request case"
            )
            evidence = str(smoke.get("evidence_path") or smoke.get("harness_path") or "HAProxy smoke summary")

    return {
        "name": name,
        "case": name,
        "path": str(case_path),
        "relative_path": path_text,
        "scope": scope,
        "group": group,
        "category": str(case.get("category", "")),
        "variant": variant,
        "requires_crs": requires_crs,
        "capabilities": sorted(capabilities),
        "expected_status": expected_status,
        "actual_status": actual_status,
        "expected_intervention": str(expect.get("intervention", "")),
        "intervention": intervention_from_expect(expect),
        "status": status,
        "operation_status": operation_status(status),
        "matrix_status": matrix_status,
        "reason": reason,
        "evidence": evidence,
        "promotion": matrix_promotion(matrix_status, response_body),
        "live_executed": live_executed,
        "response_body_non_verified": response_body,
        "crs_verified": variant in {"with-crs", "combined"} and name == "crs_sqli_anomaly_block" and matrix_status == "PASS",
    }


def mapped_only_rows(connector_root: Path) -> list[dict[str, str]]:
    import_status = load_json(connector_root / "config" / "testing" / "import-status.json")
    raw_rows = import_status.get("mapped_only", [])
    if not isinstance(raw_rows, list):
        return []
    rows = []
    for item in raw_rows:
        if not isinstance(item, dict):
            continue
        rows.append(
            {
                "source": str(item.get("source", "unknown")),
                "reason": str(item.get("reason", "")),
                "matrix_status": "MAPPED_ONLY",
            }
        )
    return rows


def uppercase_counts(rows: list[dict[str, Any]], mapped_count: int = 0) -> dict[str, int]:
    counts: Counter[str] = Counter(str(row.get("matrix_status", "NOT_EXECUTABLE")) for row in rows)
    if mapped_count:
        counts["MAPPED_ONLY"] = mapped_count
    return {
        "PASS": counts.get("PASS", 0),
        "FAIL": counts.get("FAIL", 0),
        "BLOCKED": counts.get("BLOCKED", 0),
        "NOT_EXECUTABLE": counts.get("NOT_EXECUTABLE", 0),
        "MAPPED_ONLY": counts.get("MAPPED_ONLY", 0),
    }


def lowercase_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts: Counter[str] = Counter(str(row.get("status", "skipped")) for row in rows)
    return {
        "pass": counts.get("pass", 0),
        "fail": counts.get("fail", 0),
        "blocked": counts.get("blocked", 0),
        "skipped": counts.get("skipped", 0),
        "xfail": counts.get("xfail", 0),
    }


def smoke_aliases(smoke: dict[str, Any], variant: str) -> dict[str, Any]:
    no_crs = smoke.get("no_crs") if isinstance(smoke.get("no_crs"), dict) else {}
    with_crs = smoke.get("with_crs") if isinstance(smoke.get("with_crs"), dict) else {}
    aliases = {
        "no_crs": {
            "name": "haproxy_phase1_header_block",
            "status": no_crs.get("status", "NOT_RUN"),
            "verified": no_crs.get("status") == "PASS",
            "yaml_case": None,
            "reason": "live HAProxy diagnostic alias; no exact YAML case is claimed",
            "expected_status": 403,
            "actual_status": no_crs.get("block_probe_status"),
            "pass_expected_status": 200,
            "pass_actual_status": no_crs.get("pass_probe_status"),
            "block_probe_status": no_crs.get("block_probe_status"),
            "pass_probe_status": no_crs.get("pass_probe_status"),
        },
        "with_crs": {
            "name": "haproxy_crs_sqli_anomaly_block",
            "status": with_crs.get("status", "NOT_RUN"),
            "verified": with_crs.get("status") == "PASS" and with_crs.get("crs_loaded") is True,
            "yaml_case": "crs_sqli_anomaly_block",
            "reason": "live HAProxy CRS SQLi alias maps to the existing framework YAML case",
            "expected_status": 403,
            "actual_status": with_crs.get("block_probe_status"),
            "pass_expected_status": 200,
            "pass_actual_status": with_crs.get("pass_probe_status"),
            "block_probe_status": with_crs.get("block_probe_status"),
            "pass_probe_status": with_crs.get("pass_probe_status"),
        },
    }
    if variant == "no-crs":
        aliases["with_crs"].update(
            {
                "status": "NOT_APPLICABLE",
                "verified": False,
                "reason": "not part of the No-CRS HAProxy matrix; see with-crs or combined evidence",
            }
        )
    elif variant == "with-crs":
        aliases["no_crs"].update(
            {
                "status": "NOT_APPLICABLE",
                "verified": False,
                "reason": "not part of the With-CRS HAProxy matrix; see no-crs or combined evidence",
            }
        )
    return aliases


def summary_status(counts: dict[str, int], aliases: dict[str, Any]) -> str:
    if counts.get("FAIL", 0):
        return "FAIL"
    if aliases["no_crs"].get("verified") or aliases["with_crs"].get("verified") or counts.get("PASS", 0):
        return "PARTIAL"
    if counts.get("BLOCKED", 0):
        return "BLOCKED"
    return "NOT_RUN"


def write_outputs(
    *,
    connector_root: Path,
    framework_root: Path,
    build_root: Path,
    results_dir: Path,
    variant: str,
    smoke_summary: Path,
) -> int:
    add_runner_path(framework_root)
    from msconnector_models import STATUS_MODEL, ORIGIN_MODEL, INTERVENTION_MODEL
    from runner_core import load_case

    smoke = load_json(smoke_summary)
    smoke["evidence_path"] = str(smoke_summary)
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    rows = [
        case_entry(
            case_path=case_path,
            case=load_case(case_path),
            connector_root=connector_root,
            framework_root=framework_root,
            variant=variant,
            smoke=smoke,
        )
        for case_path in all_case_files(framework_root)
    ]
    mapped_rows = mapped_only_rows(connector_root)
    counts = uppercase_counts(rows, len(mapped_rows))
    raw_counts = lowercase_counts(rows)
    aliases = smoke_aliases(smoke, variant)
    status = summary_status(counts, aliases)
    cases = {str(row["name"]): row for row in rows}
    verified_cases = [
        row["name"]
        for row in rows
        if row.get("matrix_status") == "PASS" and row.get("live_executed") is True
    ]
    if aliases["no_crs"].get("verified"):
        verified_cases.insert(0, "haproxy_phase1_header_block")
    verified_cases = list(dict.fromkeys(str(item) for item in verified_cases))
    crs_verified = any(row.get("crs_verified") for row in rows)
    connector_summary = {
        "status_model": STATUS_MODEL,
        "origin_model": ORIGIN_MODEL,
        "intervention_model": INTERVENTION_MODEL,
        "connector_path": "real-world",
        "validation_mode": "haproxy-runtime-matrix",
        "environment": "local",
        "audit_behavior": "unstable",
        "server": "haproxy",
        "server_binary": str(build_root / "haproxy-runtime" / "haproxy" / "sbin" / "haproxy"),
        "module": "diagnostic-spoa-runtime",
        "libmodsecurity": "local libmodsecurity from prepared connector build",
        "origin": {
            "source": "repo-authored diagnostic HAProxy runtime",
            "source_repo": "",
            "source_url": "",
            "source_commit": "",
            "source_version": "",
            "license": "",
            "imported_path": "connectors/haproxy",
        },
        "verified_variables": [],
        "summary": raw_counts,
        "cases": cases,
        "mapped_only": mapped_rows,
        "matrix_counts": counts,
        "attempted_yaml_cases": len(rows),
        "variant": variant,
        "response_body_verified": False,
        "crs_verified": crs_verified,
        "full_matrix_verified": False,
        "smoke_aliases": aliases,
    }
    top_level = {
        "connector": "haproxy",
        "generated_at": now,
        "connector_root": str(connector_root),
        "framework_root": str(framework_root),
        "source_root": os.environ.get("SOURCE_ROOT", "/src"),
        "build_root": str(build_root),
        "results_dir": str(results_dir),
        "variant": variant,
        "status": status,
        "runtime_status": "runtime-matrix-partial",
        "runtime_verified": bool(verified_cases),
        "matrix_full": False,
        "full_matrix_verified": False,
        "response_body_verified": False,
        "crs_verified": crs_verified,
        "counts": counts,
        "attempted_yaml_cases": len(rows),
        "verified_cases": verified_cases,
        "crs_verified_scope": ["crs_sqli_anomaly_block"] if crs_verified else [],
        "smoke_aliases": aliases,
        "mapped_only": mapped_rows,
        "haproxy": connector_summary,
        "note": (
            "HAProxy matrix is partial. PASS/FAIL rows require live HAProxy execution; "
            "BLOCKED and NOT_EXECUTABLE rows are intentionally not promoted."
        ),
    }

    results_dir.mkdir(parents=True, exist_ok=True)
    summary_json = results_dir / "haproxy-summary.json"
    results_jsonl = results_dir / "haproxy-results.jsonl"
    summary_text = results_dir / "haproxy-summary.txt"
    with results_jsonl.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True))
            handle.write("\n")
    summary_json.write_text(json.dumps(top_level, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = [
        f"HAProxy runtime matrix variant={variant}",
        f"status={status}",
        f"attempted_yaml_cases={len(rows)}",
        f"PASS={counts['PASS']} FAIL={counts['FAIL']} BLOCKED={counts['BLOCKED']} NOT_EXECUTABLE={counts['NOT_EXECUTABLE']} MAPPED_ONLY={counts['MAPPED_ONLY']}",
        "response_body_verified=false",
        f"crs_verified={str(crs_verified).lower()}",
        "full_matrix_verified=false",
    ]
    for alias_scope, alias in aliases.items():
        lines.append(
            f"alias.{alias_scope}={alias.get('name')} status={alias.get('status')} verified={str(alias.get('verified')).lower()} yaml_case={alias.get('yaml_case')}"
        )
    summary_text.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 1 if counts.get("FAIL", 0) else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--framework-root", required=True)
    parser.add_argument("--connector-root", required=True)
    parser.add_argument("--build-root", default="/src/ModSecurity-conector-build")
    parser.add_argument("--results-dir", required=True)
    parser.add_argument("--variant", required=True, choices=("no-crs", "with-crs", "combined"))
    parser.add_argument("--smoke-summary", required=True)
    args = parser.parse_args(argv)
    return write_outputs(
        connector_root=Path(args.connector_root).resolve(),
        framework_root=Path(args.framework_root).resolve(),
        build_root=Path(args.build_root).resolve(),
        results_dir=Path(args.results_dir).resolve(),
        variant=args.variant,
        smoke_summary=Path(args.smoke_summary).resolve(),
    )


if __name__ == "__main__":
    raise SystemExit(main())
