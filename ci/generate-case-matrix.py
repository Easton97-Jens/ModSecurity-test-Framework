#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import sys
import argparse
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import yaml

RUNNER_DIR = Path(__file__).resolve().parents[1] / "tests" / "runners"
if str(RUNNER_DIR) not in sys.path:
    sys.path.insert(0, str(RUNNER_DIR))

from case_roots import all_case_files, infer_report_scope
from response_body_status import (
    RESPONSE_BODY_EVIDENCE_NOTE,
    RESPONSE_BODY_RUNTIME_NOTE,
    is_response_body_related,
    matrix_status_for_result,
)

FRAMEWORK_ROOT = Path(__file__).resolve().parents[1]
CONNECTOR_ROOT = Path.cwd()
OUTPUT_ROOT = CONNECTOR_ROOT
IMPORT_STATUS = CONNECTOR_ROOT / "config/testing/import-status.json"
FRAMEWORK_REPORT_DIR = "docs/testing"
CONNECTOR_REPORT_DIR = "reports/testing"
GENERATED_DIR = "generated"
RUNTIME_SNAPSHOT_FILENAME = "runtime-validation-snapshot.json"
OVERVIEW_FILENAME = "test-coverage-overview.md"
ROOT_SUMMARY_FILENAME = "TEST-COVERAGE-SUMMARY.md"
REPORT_ROOT = OUTPUT_ROOT / FRAMEWORK_REPORT_DIR
RUNTIME_SNAPSHOT = REPORT_ROOT / RUNTIME_SNAPSHOT_FILENAME
OUT = REPORT_ROOT / GENERATED_DIR
GENERATED_REPORT_ROOT = OUT
OVERVIEW_REPORT = REPORT_ROOT / OVERVIEW_FILENAME
ROOT_SUMMARY_REPORT = FRAMEWORK_ROOT / ROOT_SUMMARY_FILENAME
ALLOWED_OUTPUT_PATHS: set[Path] = set()
REPORT_LAYOUT: "ReportLayout | None" = None

RULE_RE = re.compile(r'^\s*SecRule\s+([^\s]+)\s+"(@[^\s"]+)')
PHASE_RE = re.compile(r"phase:(\d)")
# \w keeps transformation tokens concise; current test corpus uses ASCII-style names.
TRANS_RE = re.compile(r"t:(\w+)")
GAP_TAG_RE = re.compile(r"(connector[_-]?gap|runtime[_-]?difference|future|experimental|pending|mapped[_-]?only)", re.I)
TABLE_SEPARATOR_2COL = "|---|---|"
TABLE_STATUS_COUNT_HEADER = "| Status | Count |"
TABLE_STATUS_COUNT_SEPARATOR = "|---|---:|"
NOT_EXECUTED = "NOT EXECUTED"

ROOT_COLLECTIONS = [
    "ARGS",
    "ARGS_NAMES",
    "REQUEST_HEADERS",
    "REQUEST_HEADERS_NAMES",
    "REQUEST_COOKIES",
    "REQUEST_COOKIES_NAMES",
    "REQUEST_URI",
    "REQUEST_BODY",
    "FILES",
    "FILES_NAMES",
    "XML",
    "RESPONSE_HEADERS",
    "RESPONSE_BODY",
    "AUDIT_LOG",
]

ROOT_COMMANDS = [
    "make quick-check",
    "make quick-all",
    "make cloud-quick-check",
    "make installed-readiness",
    "make runtime-matrix",
    "make runtime-matrix-all",
    "make runtime-matrix-haproxy",
    "make smoke-apache",
    "make smoke-nginx",
    "make smoke-haproxy",
    "make smoke-all",
    "make generate-test-matrix",
    "make check-test-matrix",
]

NEW_CONNECTOR_SMOKE_CONNECTORS = ["envoy", "haproxy", "lighttpd", "traefik"]

MATRIX_STATUS_ORDER = [
    "PASS",
    "FAIL",
    "BLOCKED",
    "NOT_EXECUTABLE",
    "MAPPED_ONLY",
    NOT_EXECUTED,
]

ACTIVE_RUNTIME_STATUSES = {
    "active",
    "fully-imported-common",
    "imported",
    "minimal",
    "pass",
    "v2-imported",
    "v3-imported",
}

NON_EXECUTABLE_STATUSES = {"blocked", "mapped-only", "skipped", "todo"}
GENERATED_REPORT_NAMES = {
    "apache-runtime-results.generated.md",
    "case-matrix.generated.md",
    "connector-gap-summary.generated.md",
    "coverage-summary.generated.md",
    "haproxy-runtime-results.generated.md",
    "nginx-runtime-results.generated.md",
    "phase-coverage.generated.md",
    "runtime-matrix.generated.md",
    "xfail-summary.generated.md",
}

RUNTIME_CONNECTORS = ("apache", "nginx", "haproxy")


def warn(message: str) -> None:
    print(f"[matrix-generator] WARN: {message}", file=sys.stderr)


@dataclass(frozen=True)
class ReportLayout:
    output_root: Path
    report_root: Path
    generated_root: Path
    runtime_snapshot: Path
    overview: Path
    root_summary: Path
    generated_reports: dict[str, Path]

    def write_generated(self, name: str, body: str) -> None:
        if name not in self.generated_reports:
            raise ValueError(f"unsupported generated report name: {name}")
        self._write_known(self.generated_reports[name], body)

    def write_overview(self, body: str) -> None:
        self._write_known(self.overview, body)

    def write_root_summary(self, body: str) -> None:
        self._write_known(self.root_summary, body)

    def _write_known(self, path: Path, body: str) -> None:
        if path not in self.allowed_outputs():
            raise ValueError(f"unsupported generated report output path: {path}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("Generated file — do not edit manually.\n\n" + body.rstrip() + "\n", encoding="utf-8")

    def allowed_outputs(self) -> set[Path]:
        return set(self.generated_reports.values()) | {self.overview, self.root_summary}


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


def build_safe_report_layout(output_root: Path) -> ReportLayout:
    report_root = report_root_for(output_root)
    generated_root = resolve_under_root(report_root, report_root / GENERATED_DIR, label="generated report root")
    generated_reports = {
        name: resolve_under_root(generated_root, generated_root / name, label="generated report path")
        for name in GENERATED_REPORT_NAMES
    }
    root_summary = resolve_under_root(
        FRAMEWORK_ROOT,
        FRAMEWORK_ROOT / ROOT_SUMMARY_FILENAME,
        label="framework coverage summary path",
    )
    return ReportLayout(
        output_root=output_root,
        report_root=report_root,
        generated_root=generated_root,
        runtime_snapshot=resolve_under_root(report_root, report_root / RUNTIME_SNAPSHOT_FILENAME, label="runtime snapshot path"),
        overview=resolve_under_root(report_root, report_root / OVERVIEW_FILENAME, label="coverage overview path"),
        root_summary=root_summary,
        generated_reports=generated_reports,
    )


def active_report_layout() -> ReportLayout:
    if REPORT_LAYOUT is None:
        raise RuntimeError("report layout has not been configured")
    return REPORT_LAYOUT


def configure_paths(framework_root: str | Path | None, connector_root: str | Path | None, output_root: str | Path | None) -> None:
    global FRAMEWORK_ROOT, CONNECTOR_ROOT, OUTPUT_ROOT, REPORT_ROOT, IMPORT_STATUS, RUNTIME_SNAPSHOT, OUT
    global GENERATED_REPORT_ROOT, OVERVIEW_REPORT, ROOT_SUMMARY_REPORT, ALLOWED_OUTPUT_PATHS, REPORT_LAYOUT
    if framework_root is not None:
        FRAMEWORK_ROOT = resolve_root(framework_root, label="framework root")
    if connector_root is not None:
        CONNECTOR_ROOT = resolve_root(connector_root, label="connector root")
    else:
        CONNECTOR_ROOT = FRAMEWORK_ROOT
    OUTPUT_ROOT = resolve_allowed_output_root(output_root)
    REPORT_LAYOUT = build_safe_report_layout(OUTPUT_ROOT)
    REPORT_ROOT = REPORT_LAYOUT.report_root
    IMPORT_STATUS = CONNECTOR_ROOT / "config/testing/import-status.json"
    RUNTIME_SNAPSHOT = REPORT_LAYOUT.runtime_snapshot
    OUT = REPORT_LAYOUT.generated_root
    GENERATED_REPORT_ROOT = REPORT_LAYOUT.generated_root
    OVERVIEW_REPORT = REPORT_LAYOUT.overview
    ROOT_SUMMARY_REPORT = REPORT_LAYOUT.root_summary
    ALLOWED_OUTPUT_PATHS = REPORT_LAYOUT.allowed_outputs()


def load_json_dict(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def load_haproxy_connector_summary(results_dir: Path, root_path: Path) -> dict:
    root_data = load_json_dict(root_path)
    if isinstance(root_data.get("haproxy"), dict):
        summary = dict(root_data["haproxy"])
        cases = summary.get("cases") if isinstance(summary.get("cases"), dict) else {}
        counts = summary.get("summary") if isinstance(summary.get("summary"), dict) else {}
        verified_cases = [
            str(name)
            for name, row in cases.items()
            if isinstance(row, dict) and str(row.get("status", "")).lower() == "pass"
        ]
        crs_verified_scope = [
            str(name)
            for name, row in cases.items()
            if isinstance(row, dict)
            and row.get("requires_crs") is True
            and str(row.get("status", "")).lower() == "pass"
        ]
        summary.update(
            {
                "connector": "haproxy",
                "status": "PARTIAL" if verified_cases else ("BLOCKED" if counts.get("blocked", 0) else "NOT_RUN"),
                "runtime_status": "live-yaml-runtime",
                "runtime_verified": bool(verified_cases),
                "response_body_verified": False,
                "crs_verified": bool(crs_verified_scope),
                "crs_verified_scope": crs_verified_scope,
                "full_matrix_verified": False,
                "matrix_full": False,
                "counts": counts,
                "verified_cases": verified_cases,
                "evidence_path": str(root_path),
            }
        )
        return summary
    if root_data.get("validation_mode") == "haproxy-runtime-matrix":
        root_data = dict(root_data)
        root_data["evidence_path"] = str(root_path)
        return root_data

    no_crs_path = results_dir / "no-crs" / "haproxy-summary.json"
    with_crs_path = results_dir / "with-crs" / "haproxy-summary.json"
    no_crs_data = load_json_dict(no_crs_path)
    with_crs_data = load_json_dict(with_crs_path)
    if not no_crs_data and not with_crs_data:
        if root_data:
            root_data = dict(root_data)
            root_data["evidence_path"] = str(root_path)
            return root_data
        return {
            "connector": "haproxy",
            "status": "NOT_RUN",
            "runtime_verified": False,
            "runtime_status": "not-verified",
            "response_body_verified": False,
            "crs_verified": False,
            "evidence_path": str(root_path),
        }

    verified_cases: list[str] = []
    for data in (no_crs_data, with_crs_data):
        values = data.get("verified_cases") if isinstance(data.get("verified_cases"), list) else []
        verified_cases.extend(str(value) for value in values)
    verified_cases = list(dict.fromkeys(verified_cases))
    crs_verified = with_crs_data.get("crs_verified") is True
    matrix_counts = with_crs_data.get("counts") if isinstance(with_crs_data.get("counts"), dict) else no_crs_data.get("counts", {})
    return {
        "connector": "haproxy",
        "status": "PARTIAL" if verified_cases else "BLOCKED",
        "runtime_status": "runtime-matrix-partial",
        "runtime_verified": bool(verified_cases),
        "response_body_verified": False,
        "crs_verified": crs_verified,
        "crs_verified_scope": ["crs_sqli_anomaly_block"] if crs_verified else [],
        "full_matrix_verified": False,
        "matrix_full": False,
        "counts": matrix_counts if isinstance(matrix_counts, dict) else {},
        "verified_cases": verified_cases,
        "evidence_path": f"{no_crs_path}; {with_crs_path}",
    }


DEFAULT_BUILD_ROOT = Path("/src/ModSecurity-conector-build")


def new_connector_default_evidence_path(connector: str) -> Path:
    return DEFAULT_BUILD_ROOT / "results" / f"{connector}-summary.json"


def blocked_new_connector_summary(connector: str) -> dict:
    return {
        "connector": connector,
        "status": "BLOCKED",
        "runtime_verified": False,
        "runtime_status": "blocked",
        "response_body_verified": False,
        "crs_verified": False,
        "evidence_path": str(new_connector_default_evidence_path(connector)),
    }


def new_connector_summary_from_snapshot(connector: str, runtime_snapshot: dict) -> dict:
    smoke = runtime_summary_by_connector(runtime_snapshot).get(connector, {})
    if not isinstance(smoke, dict) or not smoke:
        return {}

    summary = dict(smoke)
    summary["connector"] = connector
    summary["response_body_verified"] = smoke.get("response_body_verified") is True
    summary["crs_verified"] = smoke.get("crs_verified") is True
    summary["evidence_path"] = str(smoke.get("summary_path") or new_connector_default_evidence_path(connector))

    if connector == "haproxy":
        verified_cases = smoke.get("verified_cases") if isinstance(smoke.get("verified_cases"), list) else []
        if not verified_cases and isinstance(smoke.get("cases"), list):
            verified_cases = [
                str(row.get("case"))
                for row in smoke.get("cases", [])
                if isinstance(row, dict) and str(row.get("status", "")).lower() == "pass"
            ]
        summary["status"] = "PARTIAL" if verified_cases else str(smoke.get("status", "BLOCKED"))
        summary["runtime_verified"] = bool(verified_cases)
        summary["runtime_status"] = str(smoke.get("runtime_status", "live-yaml-runtime" if verified_cases else "not-verified"))
        summary["verified_cases"] = verified_cases
        summary["full_matrix_verified"] = False
        summary["matrix_full"] = False
        summary["counts"] = smoke.get("matrix_counts") if isinstance(smoke.get("matrix_counts"), dict) else smoke.get("counts", {})
        summary_path = Path(str(smoke.get("summary_path") or new_connector_default_evidence_path(connector)))
        summary["evidence_path"] = str(summary_path)
    return summary


def load_new_connector_smoke_summaries(runtime_snapshot: dict | None = None) -> dict[str, dict]:
    runtime_snapshot = runtime_snapshot if isinstance(runtime_snapshot, dict) else {}
    build_root = Path(os.environ.get("BUILD_ROOT", "/src/ModSecurity-conector-build"))
    results_dir = build_root / "results"
    summaries: dict[str, dict] = {}
    for connector in NEW_CONNECTOR_SMOKE_CONNECTORS:
        test_variant = os.environ.get("MODSECURITY_TEST_VARIANT", "no-crs")
        mrts_variant = os.environ.get("MODSECURITY_MRTS_VARIANT", "no-mrts")
        variant_path = results_dir / test_variant / mrts_variant / connector / f"{connector}-summary.json"
        path = variant_path if variant_path.exists() else results_dir / f"{connector}-summary.json"
        if connector == "haproxy":
            summary = load_haproxy_connector_summary(results_dir, path)
            if summary.get("status") == "NOT_RUN":
                summary = new_connector_summary_from_snapshot(connector, runtime_snapshot) or summary
            summaries[connector] = summary
            continue
        if not path.exists():
            summaries[connector] = new_connector_summary_from_snapshot(connector, runtime_snapshot) or blocked_new_connector_summary(connector)
            continue
        try:
            with path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            summaries[connector] = {
                "connector": connector,
                "status": "BLOCKED",
                "runtime_verified": False,
                "runtime_status": "not-verified",
                "response_body_verified": False,
                "crs_verified": False,
                "reason": f"could not read smoke summary: {exc}",
                "evidence_path": str(path),
            }
            continue
        if isinstance(data, dict):
            data = dict(data)
            data["evidence_path"] = str(path)
            summaries[connector] = data
        else:
            summaries[connector] = {
                "connector": connector,
                "status": "BLOCKED",
                "runtime_verified": False,
                "runtime_status": "not-verified",
                "response_body_verified": False,
                "crs_verified": False,
                "reason": "smoke summary did not contain a JSON object",
                "evidence_path": str(path),
            }
    return summaries


def render_new_connector_smoke_evidence(runtime_snapshot: dict) -> list[str]:
    summaries = load_new_connector_smoke_summaries(runtime_snapshot)
    lines = [
        "",
        "## New Connector Runtime-Smoke Evidence",
        "",
        "This generated section reads local connector smoke/matrix summaries from `$BUILD_ROOT/results` when present, then falls back to tracked snapshot evidence or BLOCKED/not-verified status. It is reporting only and does not invent PASS values.",
        "",
        "| Connector | Status | Runtime status | Runtime verified | CRS verified | RESPONSE_BODY verified | Verified cases | CRS/split detail | Evidence |",
        "|---|---|---|---:|---:|---:|---|---|---|",
    ]
    for connector in NEW_CONNECTOR_SMOKE_CONNECTORS:
        data = summaries.get(connector, {})
        status = str(data.get("status", "NOT_RUN"))
        runtime_status = str(data.get("runtime_status", "not-verified"))
        runtime_verified = "yes" if data.get("runtime_verified") is True else "no"
        crs_verified = "yes" if data.get("crs_verified") is True else "no"
        response_body_verified = "yes" if data.get("response_body_verified") is True else "no"
        verified_cases_value = data.get("verified_cases") or data.get("verified_case") or "-"
        if isinstance(verified_cases_value, list):
            verified_cases = ", ".join(str(item) for item in verified_cases_value) or "-"
        else:
            verified_cases = str(verified_cases_value) if verified_cases_value else "-"
        with_crs_data = data.get("with_crs")
        if isinstance(with_crs_data, dict):
            with_crs = str(with_crs_data.get("status", "not-run"))
            if with_crs_data.get("crs_loaded") is True:
                with_crs += " crs_loaded=true"
            if with_crs_data.get("block_probe_status") not in (None, "not-run"):
                with_crs += f" block={with_crs_data.get('block_probe_status')}"
            if with_crs_data.get("pass_probe_status") not in (None, "not-run"):
                with_crs += f" pass={with_crs_data.get('pass_probe_status')}"
            if with_crs_data.get("blocked_reason"):
                with_crs += f" reason={with_crs_data.get('blocked_reason')}"
        else:
            with_crs = "-"
        evidence = data.get("evidence_path", "-")
        lines.append(
            f"| {connector} | {status} | {runtime_status} | {runtime_verified} | {crs_verified} | {response_body_verified} | `{verified_cases}` | {with_crs} | `{evidence}` |"
        )
    lines.extend(
        [
            "",
            "- HAProxy CRS verification is derived from live with-CRS YAML rows in the latest HAProxy summary.",
            "- Envoy, lighttpd, and Traefik remain not runtime-verified unless their own summary files report runtime PASS evidence.",
            "- RESPONSE_BODY remains not verified for these new connector smoke summaries.",
        ]
    )
    return lines


def md(value: object) -> str:
    text = str(value if value is not None else "-")
    text = text.replace("\n", "<br>")
    return text.replace("|", "\\|")


def read_yaml(path: Path) -> dict:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:
        warn(f"failed to parse YAML {path}: {exc}")
        return {}
    if not isinstance(raw, dict):
        warn(f"YAML root is not an object in {path}; treating as empty")
        return {}
    return raw


def infer_scope(path: Path) -> str:
    return infer_report_scope(path)


def display_path(path: Path) -> str:
    resolved = path.resolve()
    for root in (CONNECTOR_ROOT, FRAMEWORK_ROOT):
        try:
            return str(resolved.relative_to(root))
        except ValueError:
            continue
    return str(path)


def parse_runtime_verified(data: dict) -> str:
    rv = data.get("runtime_verified", data.get("verified"))
    if isinstance(rv, bool):
        return "true" if rv else "false"
    if isinstance(rv, str):
        low = rv.strip().lower()
        if low in {"true", "yes", "pass", "verified"}:
            return "true"
        if low in {"false", "no", "unverified", "pending"}:
            return "false"
    status = str(data.get("status", "unknown")).lower()
    if status in {"pass", "verified"}:
        return "true"
    if status in {"pending", "blocked", "unknown"}:
        return "false"
    return "unknown"


def extract_rule_metadata(rules: str) -> tuple[set[str], set[int], set[str], set[str]]:
    variables: set[str] = set()
    phases: set[int] = set()
    operators: set[str] = set()
    transformations: set[str] = set()
    for line in rules.splitlines():
        match = RULE_RE.search(line)
        if match:
            variables.add(match.group(1))
            operators.add(match.group(2))
        phases.update(int(p) for p in PHASE_RE.findall(line))
        transformations.update(TRANS_RE.findall(line))
    return variables, phases, operators, transformations


def metadata_mapping(data: dict) -> dict:
    metadata = data.get("metadata")
    return metadata if isinstance(metadata, dict) else {}


def metadata_variables(metadata: dict) -> set[str]:
    variables = metadata.get("variables")
    if not isinstance(variables, list):
        return set()
    return {str(item) for item in variables if str(item).strip()}


def metadata_phases(metadata: dict) -> set[int]:
    raw_phase = metadata.get("phase")
    if isinstance(raw_phase, int):
        return {raw_phase}
    if isinstance(raw_phase, str) and raw_phase.isdigit():
        return {int(raw_phase)}
    return set()


def normalized_report_token(value: object) -> str:
    return str(value).strip().lower().replace("_", "-")


def metadata_string_list(metadata: dict, key: str) -> list[str]:
    raw = metadata.get(key)
    if not isinstance(raw, list):
        return []
    return [str(item) for item in raw if str(item).strip()]


def metadata_classification(metadata: dict) -> str:
    value = str(metadata.get("classification") or "").strip()
    return value or "active"


def metadata_mapping_field(metadata: dict, key: str) -> dict:
    raw = metadata.get(key)
    return raw if isinstance(raw, dict) else {}


def extract_status_metadata(data: dict) -> tuple[str, str, str, str, dict]:
    status = str(data.get("status", "active") or "active").strip().lower()
    category = str(data.get("category", "unknown") or "unknown")
    notes = str(data.get("notes", data.get("note", "")) or "") or "-"
    metadata = metadata_mapping(data)
    source = str(data.get("source") or data.get("source_ref") or data.get("provenance") or metadata.get("source") or "unknown")
    caps = data.get("capabilities")
    if not isinstance(caps, dict):
        caps = {}
    return status, category, notes, source, caps


def extract_gap_tags(path: Path, status: str, category: str, notes: str, source: str) -> list[str]:
    tags: set[str] = set()
    for text in [path.name, status, category, notes, source]:
        tags.update(match.lower().replace("_", "-") for match in GAP_TAG_RE.findall(text))
    return sorted(tags)


def parse_case(path: Path) -> dict:
    data = read_yaml(path)
    rules = str(data.get("rules", "") or "")
    variables, phases, operators, transformations = extract_rule_metadata(rules)
    metadata = metadata_mapping(data)
    variables.update(metadata_variables(metadata))
    phases.update(metadata_phases(metadata))
    status, category, notes, source, _ = extract_status_metadata(data)
    classification = metadata_classification(metadata)
    classification_reason = str(metadata.get("classification_reason") or "").strip()
    report_labels = metadata_string_list(metadata, "report_labels")
    connector_observations = metadata_mapping_field(metadata, "connector_observations")
    non_promotion = metadata_mapping_field(metadata, "non_promotion")
    traceability = metadata_mapping_field(metadata, "traceability")
    tags = set(extract_gap_tags(path, status, category, notes, source))
    tags.update(normalized_report_token(label) for label in report_labels)
    if classification and normalized_report_token(classification) != "active":
        tags.add(normalized_report_token(classification))
    case_id = str(data.get("name", path.stem) or path.stem)
    case_for_detection = dict(data)
    case_for_detection.update(
        {
            "id": case_id,
            "path": display_path(path),
            "variables": sorted(variables),
            "category": category,
            "notes": notes,
            "metadata_classification": classification,
            "classification_reason": classification_reason,
            "report_labels": report_labels,
            "connector_observations": connector_observations,
            "non_promotion": non_promotion,
            "traceability": traceability,
            "tags": tags,
        }
    )

    response_body = is_response_body_related(case_for_detection, path)
    if not phases:
        warn(f"no phase metadata found in {path}")

    scope = infer_scope(path)
    connector_scope = metadata.get("connector_scope")
    if scope == "common" and isinstance(connector_scope, list):
        specific_scopes = [str(item) for item in connector_scope if str(item) in {"apache", "nginx"}]
        if len(specific_scopes) == 1:
            scope = specific_scopes[0]

    return {
        "id": case_id,
        "path": display_path(path),
        "scope": scope,
        "status": status,
        "former_xfail": bool(data.get("former_xfail") is True),
        "former_xfail_reason": str(data.get("former_xfail_reason", "") or ""),
        "promoted_from_xfail_date": str(data.get("promoted_from_xfail_date", "") or ""),
        "category": category,
        "runtime_verified": parse_runtime_verified(data),
        "variables": sorted(variables),
        "operators": sorted(operators),
        "transformations": sorted(transformations),
        "phases": sorted(phases),
        "response_body": response_body,
        "source": source,
        "notes": notes,
        "metadata_classification": classification,
        "classification_reason": classification_reason,
        "report_labels": report_labels,
        "connector_observations": connector_observations,
        "non_promotion": non_promotion,
        "traceability": traceability,
        "topic": str(metadata.get("topic") or ""),
        "tags": sorted(tags),
    }


def gather_cases() -> list[dict]:
    files = all_case_files(FRAMEWORK_ROOT)
    return [parse_case(p) for p in files]


def load_import_status() -> dict:
    try:
        return json.loads(IMPORT_STATUS.read_text(encoding="utf-8"))
    except Exception as exc:
        warn(f"failed to parse {IMPORT_STATUS}: {exc}")
        return {}


def load_runtime_snapshot() -> dict:
    if not RUNTIME_SNAPSHOT.exists():
        return {}
    try:
        raw = json.loads(RUNTIME_SNAPSHOT.read_text(encoding="utf-8"))
    except Exception as exc:
        warn(f"failed to parse {RUNTIME_SNAPSHOT}: {exc}")
        return {}
    if not isinstance(raw, dict):
        warn(f"{RUNTIME_SNAPSHOT} root is not an object; ignoring runtime snapshot")
        return {}
    return raw


def report_doc(name: str) -> str:
    try:
        return str((REPORT_ROOT / name).relative_to(OUTPUT_ROOT))
    except ValueError:
        return str(REPORT_ROOT / name)


def render_case_matrix(cases: list[dict]) -> str:
    rows = [
        "# Generated Case Matrix",
        "",
        "| case_id | path | scope | phase | variables | operators | transformations | status | classification | report labels | runtime_verified | RESPONSE_BODY non-verified | notes |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for case in cases:
        rows.append(
            f"| {case['id']} | `{case['path']}` | {case['scope']} | {','.join(map(str, case['phases'])) or '-'} | "
            f"{', '.join(case['variables']) or '-'} | {', '.join(case['operators']) or '-'} | "
            f"{', '.join(case['transformations']) or '-'} | {case['status']} | {case['metadata_classification']} | "
            f"{', '.join(case['report_labels']) or '-'} | {case['runtime_verified']} | "
            f"{'yes' if case['response_body'] else 'no'} | {case['notes']} |"
        )
    return "\n".join(rows)


def render_summary(cases: list[dict], by_scope: Counter, by_status: Counter, by_runtime: Counter, by_phase: Counter, by_var: Counter, response_body_count: int) -> str:
    by_source = source_counts(cases)
    lines = ["# Generated Coverage Summary", "", f"- Total cases: {len(cases)}", f"- RESPONSE_BODY cases: {response_body_count}", f"- Verified runtime cases: {by_runtime.get('true', 0)}", f"- Non-verified runtime cases: {len(cases) - by_runtime.get('true', 0)}", "", "## By scope"]
    lines.extend(f"- {scope}: {by_scope.get(scope, 0)}" for scope in ["common", "apache", "nginx", "unknown"])
    lines.extend(["", "## By source"])
    lines.extend(f"- {source}: {count}" for source, count in sorted(by_source.items()))
    lines.extend(render_mrts_source_summary_lines(cases))
    lines.extend(["", "## By status"])
    lines.extend(f"- {key}: {value}" for key, value in sorted(by_status.items()))
    lines.extend(["", "## By variable/collection"])
    lines.extend(f"- `{key}`: {value}" for key, value in by_var.most_common())
    lines.extend(["", "## By phase"])
    lines.extend(f"- phase {phase}: {by_phase.get(phase, 0)}" for phase in [1, 2, 3, 4])
    lines.extend(
        [
            "",
            "## Verification note",
            "- Generated summaries are reporting only and do not replace full runtime evidence from `make smoke-all`.",
            "- RESPONSE_BODY remains non-verified/non-promoted until stable full-smoke runtime evidence exists.",
            f"- {RESPONSE_BODY_EVIDENCE_NOTE}",
        ]
    )
    return "\n".join(lines)


def render_xfail(cases: list[dict], import_status: dict) -> str:
    current = [case for case in cases if case["status"] == "xfail"]
    former_cases = [case for case in cases if case.get("former_xfail")]
    lines = [
        "# Generated Former XFAIL Migration Summary",
        "",
        f"- Current XFAIL YAML cases: **{len(current)}**",
        f"- Former XFAIL YAML cases tracked: **{len(former_cases)}**",
        f"- Former XFAIL import manifest entries: **{len(import_status.get('former_xfail', [])) if isinstance(import_status.get('former_xfail', []), list) else 0}**",
        "",
    ]
    if current:
        lines.extend(
            [
                "## Current XFAIL Cases",
                "| case_id | path | YAML status | phase | variables | notes |",
                "|---|---|---|---|---|---|",
            ]
        )
        for case in current:
            lines.append(
                f"| {case['id']} | `{case['path']}` | {case['status']} | {','.join(map(str, case['phases'])) or '-'} | {', '.join(case['variables']) or '-'} | {case['notes']} |"
            )
    else:
        lines.append("No current XFAIL cases remain.")

    lines.extend(
        [
            "",
            "## Former XFAIL Cases",
            "| case_id | path | current YAML status | promoted_from_xfail_date | phase | variables | former reason |",
            "|---|---|---|---|---|---|---|",
        ]
    )
    if not former_cases:
        lines.append("| - | - | - | - | - | - | - |")
    for case in former_cases:
        lines.append(
            f"| {case['id']} | `{case['path']}` | {case['status']} | {case.get('promoted_from_xfail_date') or '-'} | "
            f"{','.join(map(str, case['phases'])) or '-'} | {', '.join(case['variables']) or '-'} | {case.get('former_xfail_reason') or '-'} |"
        )
    return "\n".join(lines)


def render_gap_summary(cases: list[dict], import_status: dict) -> str:
    rows = ["# Generated Connector Gap Summary", "", "| case_id | path | status | classification | tags | variables | source/provenance | notes |", "|---|---|---|---|---|---|---|---|"]
    for case in cases:
        if (
            case_has_classification(case, "connector-gap", "runtime-difference", "harness-incompatibility", "importer-mapping-issue")
            or case["status"] in {"connector-gap", "runtime-difference"}
        ):
            rows.append(
                f"| {case['id']} | `{case['path']}` | {case['status']} | "
                f"{', '.join(sorted(case_classifications(case))) or '-'} | {', '.join(case['tags']) or '-'} | "
                f"{', '.join(case['variables']) or '-'} | {case['source']} | {case['notes']} |"
            )
    for key in ["connector_specific", "runtime_blocked", "mapped_only", "blocked"]:
        for item in import_status.get(key, []):
            if isinstance(item, dict):
                rows.append(f"| {item.get('case') or item.get('source') or 'unknown'} | `config/testing/import-status.json` | {key} | - | - | {item.get('source', 'unknown')} | {item.get('reason', '')} |")
    return "\n".join(rows)


def render_phase_coverage(cases: list[dict]) -> str:
    rows = ["# Generated Phase Coverage", "", "| phase | case_count | top_variables | status_distribution |", "|---|---:|---|---|"]
    for phase in [1, 2, 3, 4]:
        phase_cases = [case for case in cases if phase in case["phases"]]
        var_count = Counter(v for case in phase_cases for v in case["variables"])
        stat_count = Counter(case["status"] for case in phase_cases)
        top_vars = ", ".join(f"{k}({v})" for k, v in var_count.most_common(5)) or "-"
        stats = ", ".join(f"{k}:{v}" for k, v in sorted(stat_count.items())) or "-"
        rows.append(f"| {phase} | {len(phase_cases)} | {top_vars} | {stats} |")
    return "\n".join(rows)


def root_summary_metrics(cases: list[dict], by_status: Counter, by_runtime: Counter) -> dict[str, int]:
    return {
        "total": len(cases),
        "verified": by_runtime.get("true", 0),
        "current_xfail": by_status.get("xfail", 0),
        "former_xfail": sum(1 for case in cases if case.get("former_xfail")),
        "pending_false": by_runtime.get("false", 0),
        "pending_unknown": by_runtime.get("unknown", 0),
        "connector_gap": sum(1 for case in cases if case_has_classification(case, "connector-gap") or case["status"] == "connector-gap"),
        "runtime_difference": sum(1 for case in cases if case_has_classification(case, "runtime-difference") or case["status"] == "runtime-difference"),
        "future_experimental": sum(
            1
            for case in cases
            if case_has_classification(case, "future", "experimental") or case["status"] in {"future", "experimental"}
        ),
        "response_body": sum(1 for case in cases if case["response_body"]),
    }


def normalized_collection_counts(cases: list[dict]) -> Counter:
    counts: Counter = Counter()
    for case in cases:
        for variable in case["variables"]:
            base = variable.split(":", 1)[0]
            if base in ROOT_COLLECTIONS:
                counts[base] += 1
    return counts


def case_text(case: dict) -> str:
    parts = [
        case["id"],
        case["path"],
        case["category"],
        case["source"],
        case["notes"],
        case.get("metadata_classification", ""),
        case.get("classification_reason", ""),
        " ".join(case.get("report_labels", [])),
        " ".join(case["tags"]),
        " ".join(case["variables"]),
    ]
    return " ".join(parts).lower()


def case_classifications(case: dict) -> set[str]:
    values = {normalized_report_token(case.get("metadata_classification", ""))}
    observations = case.get("connector_observations")
    if isinstance(observations, dict):
        for item in observations.values():
            if isinstance(item, dict):
                values.add(normalized_report_token(item.get("classification", "")))
    return {value for value in values if value}


def case_has_classification(case: dict, *values: str) -> bool:
    wanted = {normalized_report_token(value) for value in values}
    return bool(case_classifications(case).intersection(wanted) or set(case["tags"]).intersection(wanted))


def count_cases_matching(cases: list[dict], *needles: str) -> int:
    return sum(1 for case in cases if any(needle in case_text(case) for needle in needles))


def topic_counts(cases: list[dict]) -> dict[str, int]:
    explicit_topics = Counter(case["topic"] for case in cases if case.get("topic"))
    unclassified = [case for case in cases if not case.get("topic")]
    counts = {
        "Operators": explicit_topics.get("Operators", 0) + sum(1 for case in unclassified if case["operators"]),
        "Transformations": explicit_topics.get("Transformations", 0) + sum(1 for case in unclassified if case["transformations"]),
        "Multipart / FILES": explicit_topics.get("Multipart / FILES", 0) + count_cases_matching(unclassified, "multipart", "files", "multipart_filename"),
        "JSON": explicit_topics.get("JSON", 0) + count_cases_matching(unclassified, "json"),
        "XML": explicit_topics.get("XML", 0) + count_cases_matching(unclassified, "xml"),
        "Unicode / Encoding": explicit_topics.get("Unicode / Encoding", 0) + count_cases_matching(unclassified, "unicode", "encoding", "encoded", "urldecode", "url_decode"),
        "XSS-like compatibility probes": explicit_topics.get("XSS-like compatibility probes", 0) + count_cases_matching(unclassified, "xss_like", "xss-like"),
        "SQLi-like compatibility probes": explicit_topics.get("SQLi-like compatibility probes", 0) + count_cases_matching(unclassified, "sqli_like", "sqli-like"),
        "Audit-log probes": explicit_topics.get("Audit-log probes", 0) + count_cases_matching(unclassified, "audit_log", "audit-log", "auditlog"),
        "Response header probes": explicit_topics.get("Response header probes", 0) + count_cases_matching(unclassified, "response_headers", "response header", "phase3_response_headers"),
        "Response body experimental probes": explicit_topics.get("Response body experimental probes", 0) + sum(
            1
            for case in unclassified
            if case["response_body"] and ("experimental" in case["tags"] or "experimental" in case_text(case))
        ),
    }
    mrts_unclassified = explicit_topics.get("MRTS generated / unclassified", 0)
    if mrts_unclassified:
        counts["MRTS generated / unclassified"] = mrts_unclassified
    return counts


def source_counts(cases: list[dict]) -> Counter:
    return Counter(case["source"] for case in cases)


def mrts_cases(cases: list[dict]) -> list[dict]:
    return [case for case in cases if str(case.get("source", "")).lower() == "mrts"]


def mrts_source_summary(cases: list[dict]) -> dict[str, int]:
    rows = mrts_cases(cases)
    return {
        "total": len(rows),
        "active": sum(1 for case in rows if case_group(case) == "active"),
        "pending": sum(1 for case in rows if case_group(case) == "pending"),
        "unclassified": sum(1 for case in rows if case.get("topic") == "MRTS generated / unclassified"),
        "response_body_phase4": sum(1 for case in rows if case["response_body"] or 4 in case["phases"]),
        "runtime_executable": sum(
            1
            for case in rows
            if any(runtime_executable(case, connector) for connector in RUNTIME_CONNECTORS)
        ),
    }


def mrts_classification_counts(cases: list[dict]) -> Counter:
    rows = mrts_cases(cases)
    return Counter(normalized_report_token(case.get("metadata_classification", "active")) or "active" for case in rows)


def mrts_connector_classification_counts(cases: list[dict]) -> dict[str, Counter]:
    counts = {connector: Counter() for connector in RUNTIME_CONNECTORS}
    for case in mrts_cases(cases):
        observations = case.get("connector_observations")
        if not isinstance(observations, dict):
            continue
        for connector in RUNTIME_CONNECTORS:
            item = observations.get(connector)
            if isinstance(item, dict):
                classification = normalized_report_token(item.get("classification", ""))
                if classification:
                    counts[connector][classification] += 1
    return counts


def format_counter(counter: Counter) -> str:
    if not counter:
        return "-"
    return ", ".join(f"{key}({value})" for key, value in sorted(counter.items()))


def render_mrts_source_summary_lines(cases: list[dict]) -> list[str]:
    if not mrts_cases(cases):
        return []
    summary = mrts_source_summary(cases)
    classification_counts = mrts_classification_counts(cases)
    connector_counts = mrts_connector_classification_counts(cases)
    return [
        "",
        "## MRTS Source Summary",
        f"- Total MRTS imported cases: **{summary['total']}**",
        f"- Active MRTS cases: **{summary['active']}**",
        f"- Pending MRTS cases: **{summary['pending']}**",
        f"- Unclassified MRTS cases: **{summary['unclassified']}**",
        f"- Phase 4 / RESPONSE_BODY MRTS cases: **{summary['response_body_phase4']}**",
        f"- Runtime-executable MRTS cases: **{summary['runtime_executable']}**",
        f"- MRTS overlay classifications: **{format_counter(classification_counts)}**",
        f"- Apache observed classifications: **{format_counter(connector_counts['apache'])}**",
        f"- NGINX observed classifications: **{format_counter(connector_counts['nginx'])}**",
        f"- HAProxy observed classifications: **{format_counter(connector_counts['haproxy'])}**",
    ]


def render_status_table(
    title: str,
    rows: list[dict],
    columns: list[tuple[str, str]],
    heading_level: int = 2,
) -> list[str]:
    if not rows:
        return []
    heading = "#" * max(1, heading_level)
    out = ["", f"{heading} {title}", "| " + " | ".join(header for header, _ in columns) + " |", "|" + "|".join("---" for _ in columns) + "|"]
    for row in rows:
        out.append("| " + " | ".join(str(row.get(key, "-")) for _, key in columns) + " |")
    return out


def case_group(case: dict) -> str:
    return str(case.get("status") or "active").strip().lower()


def case_category(case: dict) -> str:
    parts = Path(case["path"]).parts
    try:
        index = parts.index("cases")
    except ValueError:
        return "unknown"
    category_parts: list[str] = []
    category_parts.extend(parts[index + 1 : -1])
    return "/".join(category_parts) or "unknown"


def runtime_summary_by_connector(snapshot: dict) -> dict[str, dict]:
    by_connector: dict[str, dict] = {}
    for item in snapshot.get("runtime_smokes", []):
        if not isinstance(item, dict):
            continue
        connector = str(item.get("connector", "")).strip()
        if connector in RUNTIME_CONNECTORS:
            by_connector[connector] = item
    return by_connector


def force_all_runtime_summary_by_connector(snapshot: dict) -> dict[str, dict]:
    by_connector: dict[str, dict] = {}
    for item in snapshot.get("force_all_runtime_smokes", []):
        if not isinstance(item, dict):
            continue
        connector = str(item.get("connector", "")).strip()
        if connector in RUNTIME_CONNECTORS:
            by_connector[connector] = item
    return by_connector


def runtime_summary_by_connector_for_mode(snapshot: dict, mode: str) -> dict[str, dict]:
    if mode == "force-all":
        return force_all_runtime_summary_by_connector(snapshot)
    return runtime_summary_by_connector(snapshot)


def connector_display_name(connector: str) -> str:
    if connector == "nginx":
        return "NGINX"
    if connector == "haproxy":
        return "HAProxy"
    return connector.title()


def smoke_counts(smoke: dict) -> dict:
    counts = smoke.get("counts") if isinstance(smoke.get("counts"), dict) else {}
    return counts if isinstance(counts, dict) else {}


def count_value(value: object) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def smoke_status_failed(smoke: dict) -> bool:
    status = status_label(smoke.get("status"))
    counts = smoke_counts(smoke)
    return status in {"FAIL", "BLOCKED"} or any(count_value(counts.get(key, 0)) for key in ("fail", "blocked"))


def smoke_case_rows(smoke: dict) -> list[dict]:
    cases = smoke.get("cases", [])
    return cases if isinstance(cases, list) else []


def smoke_per_case_results(smoke: dict) -> str:
    value = str(smoke.get("per_case_results", "") or "").strip().lower()
    if value:
        return value
    return "available" if smoke_case_rows(smoke) else "unavailable"


def smoke_unavailable_reason(smoke: dict, connector: str) -> str:
    reason = str(smoke.get("per_case_unavailable_reason", "") or "").strip()
    if reason:
        return reason
    blocker = smoke.get("blocker") if isinstance(smoke.get("blocker"), dict) else {}
    reason = str(blocker.get("reason", "") or "").strip()
    if reason:
        return reason
    if smoke_status_failed(smoke) and not smoke_case_rows(smoke):
        return str(smoke.get("details") or f"{connector_display_name(connector)} did not complete per-case runtime execution.")
    return ""


def smoke_evidence_note(smoke: dict) -> str:
    note = str(smoke.get("per_case_unavailable_evidence", "") or "").strip()
    if note:
        return note
    blocker = smoke.get("blocker") if isinstance(smoke.get("blocker"), dict) else {}
    return str(blocker.get("evidence_note", "") or "").strip()


def render_connector_runtime_availability(snapshot: dict) -> list[str]:
    smokes = runtime_summary_by_connector(snapshot)
    lines = [
        "",
        "## Connector Runtime Availability",
        "| Connector | Status | Build | Per-case results | Attempted cases | Summary evidence | Note |",
        "|---|---|---|---|---:|---|---|",
    ]
    for connector in RUNTIME_CONNECTORS:
        smoke = smokes.get(connector, {})
        note = smoke_unavailable_reason(smoke, connector) if smoke_per_case_results(smoke) != "available" else ""
        if not note:
            note = str(smoke.get("details", ""))
        lines.append(
            "| "
            + " | ".join(
                [
                    md(connector_display_name(connector)),
                    md(smoke.get("status", "unknown")),
                    md(smoke.get("build_status", "unknown")),
                    md(smoke_per_case_results(smoke)),
                    md(runtime_attempted_count(snapshot, connector)),
                    md(smoke.get("summary_path", "unknown")),
                    md(note or "-"),
                ]
            )
            + " |"
        )
    return lines


def runtime_results_by_connector(snapshot: dict) -> dict[str, dict[str, dict]]:
    results: dict[str, dict[str, dict]] = {connector: {} for connector in RUNTIME_CONNECTORS}
    for connector, smoke in runtime_summary_by_connector(snapshot).items():
        for item in smoke_case_rows(smoke):
            if not isinstance(item, dict):
                continue
            name = str(item.get("case") or item.get("name") or "").strip()
            if name:
                results.setdefault(connector, {})[name] = item
    return results


def connector_applies(case: dict, connector: str) -> bool:
    if case["scope"] == "common":
        return True
    return case["scope"] == connector


def is_force_all_snapshot(snapshot: dict) -> bool:
    return bool(snapshot.get("force_all_cases"))


def runtime_executable(case: dict, connector: str) -> bool:
    if not connector_applies(case, connector):
        return False
    if case.get("former_xfail") is True:
        return False
    return case_group(case) in ACTIVE_RUNTIME_STATUSES


def runtime_classification_token(value: object) -> str:
    return str(value).strip().lower().replace("-", "_")


def connector_observed_classification(case: dict, connector: str) -> str:
    observations = case.get("connector_observations")
    if not isinstance(observations, dict):
        return ""
    item = observations.get(connector)
    if not isinstance(item, dict):
        return ""
    return runtime_classification_token(item.get("classification", ""))


def connector_observed_reason(case: dict, connector: str) -> str:
    observations = case.get("connector_observations")
    if not isinstance(observations, dict):
        return ""
    item = observations.get(connector)
    if not isinstance(item, dict):
        return ""
    return str(item.get("classification_reason") or item.get("evidence_label") or "").strip()


def runtime_classification(case: dict, connector: str | None = None) -> str:
    if connector:
        observed_classification = connector_observed_classification(case, connector)
        if observed_classification:
            return observed_classification
    metadata_value = runtime_classification_token(case.get("metadata_classification", ""))
    if metadata_value and metadata_value != "active":
        return metadata_value
    tags = set(case["tags"])
    text = case_text(case)
    if "connector-gap" in tags or "connector_gap" in text:
        return "connector_gap"
    if "runtime-difference" in tags or "runtime_difference" in text or "runtime_diff" in text:
        return "runtime_difference"
    if "future" in tags or "experimental" in tags or "future" in text or "experimental" in text:
        return "future"
    if "pending" in tags or "pending" in text:
        return "pending"
    return "active"


def status_label(status: object) -> str:
    value = str(status or "").strip().lower()
    if value in {"pass", "fail", "blocked", "not_executable"}:
        return value.upper()
    if value == "xfail":
        return "FAIL"
    if value == "skipped":
        return NOT_EXECUTED
    if value in {"not_run", "not-run"}:
        return NOT_EXECUTED
    return NOT_EXECUTED


def normalized_matrix_status_value(row: dict) -> str:
    supplied = str(row.get("matrix_status", "") or "").strip()
    if supplied in {"PASS", "FAIL", "BLOCKED", "NOT_EXECUTABLE"}:
        return supplied
    if supplied.endswith("_PASS") or supplied.endswith("_RESPONSE_BODY_PASS_THROUGH"):
        return "PASS"
    if supplied.endswith("_FAIL"):
        return "FAIL"
    return status_label(row.get("status"))


def semantic_matrix_status(raw_status: str, classification: str, response_body_related: bool = False) -> str:
    return matrix_status_for_result(
        raw_status,
        classification,
        response_body_related=response_body_related,
    )


def response_body_pass_is_pass_through(observed: dict) -> bool:
    if str(observed.get("observed_transport_result", "http_status")).strip().lower() in {"connection_aborted", "aborted"}:
        return False
    expected = observed.get("expected_status", observed.get("expected"))
    actual = observed.get("actual_status", observed.get("actual"))
    try:
        return int(str(expected)) == 200 and int(str(actual)) == 200
    except (TypeError, ValueError):
        return False


def runtime_executable_for_snapshot(case: dict, connector: str, snapshot: dict) -> bool:
    if not connector_applies(case, connector):
        return False
    if is_force_all_snapshot(snapshot):
        return case_group(case) not in NON_EXECUTABLE_STATUSES
    return runtime_executable(case, connector)


def runtime_cell_not_applicable(case: dict, connector: str) -> dict[str, str]:
    return {
        "status": "NOT_EXECUTABLE",
        "reason": f"{case['scope']}-specific case is not applicable to {connector}",
        "evidence": "-",
        "promotion": "-",
    }


def runtime_cell_inventory_only(case: dict) -> dict[str, str]:
    return {
        "status": NOT_EXECUTED,
        "reason": f"YAML status `{case_group(case)}` is metadata inventory and is not part of default runtime smoke discovery",
        "evidence": "metadata only; no PASS promotion",
        "promotion": "not promoted",
    }


def runtime_cell_outside_snapshot(case: dict) -> dict[str, str]:
    return {
        "status": "NOT_EXECUTABLE",
        "reason": f"YAML status `{case_group(case)}` is outside active runtime smoke discovery",
        "evidence": "-",
        "promotion": "not promoted",
    }


def runtime_cell_from_observed(case: dict, observed: dict, connector: str) -> dict[str, str]:
    classification = str(observed.get("runtime_classification", runtime_classification(case, connector)))
    overlay_reason = connector_observed_reason(case, connector)
    observed_case = dict(case)
    observed_case.update(
        {
            "capabilities": observed.get("capabilities", case.get("capabilities", [])),
            "path": observed.get("path", case.get("path", "")),
        }
    )
    response_body_related = bool(observed.get("response_body_non_verified")) or is_response_body_related(
        observed_case,
        observed_case.get("path", ""),
    )
    raw_status = str(observed.get("status", ""))
    response_body_pass_through = response_body_related and raw_status.strip().lower() == "pass" and response_body_pass_is_pass_through(observed)
    computed_status = semantic_matrix_status(raw_status, classification, response_body_pass_through)
    supplied_status = str(observed.get("matrix_status") or "").strip()
    if supplied_status not in {"PASS", "FAIL", "BLOCKED", "NOT_EXECUTABLE"}:
        supplied_status = ""
    status = supplied_status or computed_status
    if response_body_related and raw_status.strip().lower() == "pass":
        status = computed_status
    if status in {NOT_EXECUTED, "NOT_EXECUTABLE"}:
        reason = str(observed.get("reason") or observed.get("details") or "skipped by runtime smoke")
    elif response_body_pass_through:
        reason = str(observed.get("reason") or f"{RESPONSE_BODY_RUNTIME_NOTE}; classification={classification}")
    elif response_body_related and raw_status.strip().lower() == "pass":
        reason = str(observed.get("reason") or f"RESPONSE_BODY disruptive evidence remains non-promoted; classification={classification}")
    else:
        reason = str(observed.get("reason") or f"runtime summary result; classification={classification}")
    if overlay_reason:
        reason = f"{reason}; overlay={overlay_reason}"
    expected = observed.get("expected_status", observed.get("expected", "unknown"))
    actual = observed.get("actual_status", observed.get("actual", "unknown"))
    evidence = str(observed.get("evidence") or f"expected={expected}; actual={actual}")
    promotion = (
        "RESPONSE_BODY non-verified; non-promotable"
        if response_body_related
        else ("promotion eligible" if classification == "active" and status == "PASS" else "not promoted")
    )
    return {"status": status, "reason": reason, "evidence": evidence, "promotion": promotion}


def runtime_cell_without_case_evidence(smoke: dict, connector: str, snapshot: dict) -> dict[str, str]:
    smoke_status = status_label(smoke.get("status"))
    if smoke_status in {"FAIL", "BLOCKED"} and not smoke.get("cases"):
        return {
            "status": smoke_status,
            "reason": smoke_unavailable_reason(smoke, connector)
            or f"{connector_display_name(connector)} smoke did not produce per-case results",
            "evidence": str(smoke.get("summary_path", "-")),
            "promotion": "not promoted",
        }
    return {
        "status": "NOT_EXECUTABLE" if is_force_all_snapshot(snapshot) else NOT_EXECUTED,
        "reason": f"no {connector} runtime evidence recorded for this executable YAML case",
        "evidence": str(smoke.get("summary_path", "no summary path recorded")),
        "promotion": "not promoted",
    }


def runtime_cell(case: dict, connector: str, snapshot: dict) -> dict[str, str]:
    if not connector_applies(case, connector):
        return runtime_cell_not_applicable(case, connector)
    results = runtime_results_by_connector(snapshot)
    observed = results.get(connector, {}).get(case["id"])
    if not is_force_all_snapshot(snapshot) and not runtime_executable(case, connector):
        return runtime_cell_inventory_only(case)
    if not runtime_executable_for_snapshot(case, connector, snapshot):
        return runtime_cell_outside_snapshot(case)
    if connector == "haproxy" and observed:
        return runtime_cell_from_observed(case, observed, connector)

    if observed:
        return runtime_cell_from_observed(case, observed, connector)

    smoke = runtime_summary_by_connector(snapshot).get(connector, {})
    return runtime_cell_without_case_evidence(smoke, connector, snapshot)


def runtime_rows(cases: list[dict], snapshot: dict) -> list[dict[str, str]]:
    rows = []
    for case in cases:
        cells = {connector: runtime_cell(case, connector, snapshot) for connector in RUNTIME_CONNECTORS}
        row = {
            "case_id": case["id"],
            "path": case["path"],
            "scope": case["scope"],
            "category": case_category(case),
            "metadata_class": runtime_classification(case),
            "yaml_status": case["status"],
            "runtime_executable": "yes" if any(runtime_executable(case, connector) for connector in RUNTIME_CONNECTORS) else "no",
            "force_all_executable": "yes"
            if any(runtime_executable_for_snapshot(case, connector, {"force_all_cases": True}) for connector in RUNTIME_CONNECTORS)
            else "no",
        }
        for connector, cell in cells.items():
            row[f"{connector}_status"] = cell["status"]
            row[f"{connector}_promotion"] = cell["promotion"]
            row[f"{connector}_reason"] = cell["reason"]
            row[f"{connector}_evidence"] = cell["evidence"]
        rows.append(row)
    return rows


def runtime_status_counts(rows: list[dict[str, str]], connector: str) -> Counter:
    key = f"{connector}_status"
    return Counter(row[key] for row in rows)


def ordered_runtime_statuses(*counters: Counter) -> list[str]:
    observed = set()
    for counter in counters:
        observed.update(counter.keys())
    ordered = [status for status in MATRIX_STATUS_ORDER if status in observed]
    ordered.extend(sorted(observed - set(MATRIX_STATUS_ORDER)))
    return ordered


def runtime_attempted_count(snapshot: dict, connector: str) -> int:
    smoke = runtime_summary_by_connector(snapshot).get(connector, {})
    return runtime_attempted_count_from_smoke(smoke)


def runtime_attempted_count_from_smoke(smoke: dict) -> int:
    if not isinstance(smoke, dict):
        return 0
    explicit = smoke.get("attempted")
    if explicit not in (None, "", "unknown"):
        return count_value(explicit)
    rows = smoke_case_rows(smoke)
    if rows:
        return len(rows)
    counts = smoke_counts(smoke)
    return sum(count_value(counts.get(status, 0)) for status in ("pass", "fail", "blocked", "not_executable"))


def force_all_runtime_attempted_count(snapshot: dict, connector: str) -> int:
    smoke = force_all_runtime_summary_by_connector(snapshot).get(connector, {})
    return runtime_attempted_count_from_smoke(smoke)


def render_runtime_status_count_table(
    apache_counts: Counter,
    nginx_counts: Counter,
    haproxy_counts: Counter | None = None,
    mapped_only_count: int = 0,
) -> list[str]:
    counters = [apache_counts, nginx_counts]
    if haproxy_counts is not None:
        counters.append(haproxy_counts)
    statuses = ordered_runtime_statuses(*counters)
    if mapped_only_count and "MAPPED_ONLY" not in statuses:
        statuses.append("MAPPED_ONLY")
    if haproxy_counts is None:
        lines = ["| Status | Apache | NGINX |", "|---|---:|---:|"]
    else:
        lines = ["| Status | Apache | NGINX | HAProxy |", "|---|---:|---:|---:|"]
    for status in statuses:
        if status == "MAPPED_ONLY":
            if haproxy_counts is None:
                lines.append(f"| {status} | {mapped_only_count} | {mapped_only_count} |")
            else:
                lines.append(f"| {status} | {mapped_only_count} | {mapped_only_count} | {mapped_only_count} |")
        elif haproxy_counts is None:
            lines.append(f"| {status} | {apache_counts.get(status, 0)} | {nginx_counts.get(status, 0)} |")
        else:
            lines.append(
                f"| {status} | {apache_counts.get(status, 0)} | {nginx_counts.get(status, 0)} | {haproxy_counts.get(status, 0)} |"
            )
    return lines


def render_runtime_matrix(cases: list[dict], import_status: dict, snapshot: dict) -> str:
    rows = runtime_rows(cases, snapshot)
    apache_counts = runtime_status_counts(rows, "apache")
    nginx_counts = runtime_status_counts(rows, "nginx")
    haproxy_counts = runtime_status_counts(rows, "haproxy")
    mapped_only = import_status.get("mapped_only", [])
    if not isinstance(mapped_only, list):
        mapped_only = []

    lines = [
        "# Generated Runtime Matrix",
        "",
        "This matrix joins repository YAML cases with the latest tracked local runtime snapshot.",
        "Former XFAIL cases are rendered from live runtime evidence like any other YAML case; RESPONSE_BODY remains non-verified/non-promoted.",
        "",
        "## Counts",
        f"- YAML cases: **{len(cases)}**",
        f"- Default runtime-executable YAML cases: **{sum(1 for row in rows if row['runtime_executable'] == 'yes')}**",
        f"- Force-all runtime-executable YAML cases: **{sum(1 for row in rows if row['force_all_executable'] == 'yes')}**",
        f"- Apache attempted YAML cases in default runtime snapshot: **{runtime_attempted_count(snapshot, 'apache')}**",
        f"- NGINX attempted YAML cases in default runtime snapshot: **{runtime_attempted_count(snapshot, 'nginx')}**",
        f"- HAProxy attempted YAML cases in default runtime snapshot: **{runtime_attempted_count(snapshot, 'haproxy')}**",
        f"- Apache attempted YAML cases in force-all runtime snapshot: **{force_all_runtime_attempted_count(snapshot, 'apache')}**",
        f"- NGINX attempted YAML cases in force-all runtime snapshot: **{force_all_runtime_attempted_count(snapshot, 'nginx')}**",
        f"- HAProxy attempted YAML cases in force-all runtime snapshot: **{force_all_runtime_attempted_count(snapshot, 'haproxy')}**",
        f"- mapped-only import inventory entries: **{len(mapped_only)}**",
        "- `NOT_EXECUTABLE` means the YAML case is not applicable to that connector or the runner cannot execute that YAML status for that connector.",
        f"- `{NOT_EXECUTED}` means no runtime case evidence is recorded in a non-force/default snapshot.",
        "- `MAPPED_ONLY` entries are import inventory items, not runnable YAML case files.",
        "- Bounded Phase 4 / strict-abort classifications remain non-promotable metadata even when the live runtime status is PASS.",
        "",
        "## Status Counts",
        *render_runtime_status_count_table(apache_counts, nginx_counts, haproxy_counts, len(mapped_only)),
        *render_connector_runtime_availability(snapshot),
        "",
        "## YAML Runtime Matrix",
        "| case_id | path | scope | category | metadata class | YAML status | default executable | force-all executable | Apache | Apache promotion | Apache reason | Apache evidence | NGINX | NGINX promotion | NGINX reason | NGINX evidence | HAProxy | HAProxy promotion | HAProxy reason | HAProxy evidence |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for row in rows:
        lines.append(
            "| "
            + " | ".join(
                md(row[key])
                for key in [
                    "case_id",
                    "path",
                    "scope",
                    "category",
                    "metadata_class",
                    "yaml_status",
                    "runtime_executable",
                    "force_all_executable",
                    "apache_status",
                    "apache_promotion",
                    "apache_reason",
                    "apache_evidence",
                    "nginx_status",
                    "nginx_promotion",
                    "nginx_reason",
                    "nginx_evidence",
                    "haproxy_status",
                    "haproxy_promotion",
                    "haproxy_reason",
                    "haproxy_evidence",
                ]
            )
            + " |"
        )

    lines.extend(
        [
            "",
            "## Mapped-only Import Inventory",
            "| source | reason | runtime status |",
            "|---|---|---|",
        ]
    )
    for item in mapped_only:
        if not isinstance(item, dict):
            continue
        lines.append(f"| {md(item.get('source', 'unknown'))} | {md(item.get('reason', ''))} | MAPPED_ONLY |")
    return "\n".join(lines)


def render_connector_runtime_results(cases: list[dict], snapshot: dict, connector: str) -> str:
    rows = runtime_rows(cases, snapshot)
    counts = runtime_status_counts(rows, connector)
    smoke = runtime_summary_by_connector(snapshot).get(connector, {})
    connector_name = connector_display_name(connector)
    raw_counts = smoke_counts(smoke)
    lines = [
        f"# Generated {connector_name} Runtime Results",
        "",
        f"- Command: `{smoke.get('command', 'unknown')}`",
        f"- Status: **{smoke.get('status', 'unknown')}**",
        f"- Exit code: `{smoke.get('exit_code', 'unknown')}`",
        f"- Build status: `{smoke.get('build_status', 'unknown')}`",
        f"- Per-case results: `{smoke_per_case_results(smoke)}`",
        f"- Summary evidence: `{smoke.get('summary_path', 'unknown')}`",
        f"- Attempted YAML cases in default runtime snapshot: **{runtime_attempted_count(snapshot, connector)}**",
        "- Runtime evidence is current local snapshot evidence only.",
        "- RESPONSE_BODY remains non-verified/non-promoted.",
        f"- {RESPONSE_BODY_EVIDENCE_NOTE}",
        "",
        "## Raw Smoke Summary",
        TABLE_STATUS_COUNT_HEADER,
        TABLE_STATUS_COUNT_SEPARATOR,
    ]
    for status in ["pass", "fail", "blocked", "not_executable", "skipped"]:
        lines.append(f"| {status.upper()} | {md(raw_counts.get(status, 'unknown'))} |")
    lines.extend(
        [
            "",
            "## Semantic Status Counts",
            TABLE_STATUS_COUNT_HEADER,
            TABLE_STATUS_COUNT_SEPARATOR,
        ]
    )
    for status in ordered_runtime_statuses(counts):
        lines.append(f"| {status} | {counts.get(status, 0)} |")
    if smoke_status_failed(smoke) and smoke_per_case_results(smoke) != "available":
        lines.extend(
            [
                "",
                f"{connector_name} did not emit per-case rows; semantic counts and result rows use connector-level blocker evidence for visibility.",
            ]
        )
    if connector == "haproxy":
        lines.extend(render_haproxy_runtime_details(snapshot, heading_level=2))
        lines.extend(render_haproxy_force_all_runtime_details(snapshot, heading_level=2))
    else:
        lines.extend(render_connector_runtime_fail_details(snapshot, connector, heading_level=2))
        lines.extend(
            render_connector_phase4_details(
                snapshot,
                connector,
                "runtime_smokes",
                f"{connector_name} Default Phase 4 / RESPONSE_BODY Evidence",
                heading_level=2,
            )
        )
        lines.extend(
            render_connector_phase4_details(
                snapshot,
                connector,
                "force_all_runtime_smokes",
                f"{connector_name} Force-All Phase 4 / RESPONSE_BODY Evidence",
                heading_level=2,
            )
        )
    lines.extend(
        [
            "",
            "## Results",
            "| case_id | path | YAML status | runtime status | promotion | reason | evidence |",
            "|---|---|---|---|---|---|---|",
        ]
    )
    for row in rows:
        lines.append(
            f"| {md(row['case_id'])} | {md(row['path'])} | {md(row['yaml_status'])} | "
            f"{md(row[f'{connector}_status'])} | {md(row[f'{connector}_promotion'])} | "
            f"{md(row[f'{connector}_reason'])} | {md(row[f'{connector}_evidence'])} |"
        )
    return "\n".join(lines)


def render_runtime_failure_table(rows: list[dict[str, object]]) -> list[str]:
    lines = [
        "| Case | Expected | Actual | Assessment | Evidence |",
        "|---|---|---|---|---|",
    ]
    for row in rows:
        lines.append(
            "| "
            + " | ".join(
                md(row.get(key, "-"))
                for key in ["case", "expected", "actual", "assessment", "evidence"]
            )
            + " |"
        )
    return lines


def runtime_failed_rows_for_connector(snapshot: dict, connector: str) -> list[dict[str, object]]:
    smoke = runtime_summary_by_connector(snapshot).get(connector, {})
    cases_by_name = {
        str(item.get("case") or item.get("name") or ""): item
        for item in smoke_case_rows(smoke)
        if isinstance(item, dict)
    }
    rows: list[dict[str, object]] = []
    failed_cases = smoke.get("failed_cases", [])
    if not isinstance(failed_cases, list):
        return rows
    for failed in failed_cases:
        if not isinstance(failed, dict):
            continue
        case_name = str(failed.get("case", "-"))
        case_row = cases_by_name.get(case_name, {})
        rows.append(
            {
                "case": case_name,
                "expected": failed.get("expected", "-"),
                "actual": failed.get("actual", "-"),
                "assessment": failed.get("assessment", "-"),
                "evidence": failed.get("evidence") or case_row.get("evidence") or smoke.get("summary_path", "-"),
            }
        )
    return rows


def render_connector_runtime_fail_details(snapshot: dict, connector: str, heading_level: int) -> list[str]:
    smoke = runtime_summary_by_connector(snapshot).get(connector, {})
    connector_name = connector_display_name(connector)
    lines = ["", f"{'#' * heading_level} {connector_name} FAIL Details"]
    failed_rows = runtime_failed_rows_for_connector(snapshot, connector)
    if failed_rows:
        lines.extend(render_runtime_failure_table(failed_rows))
        return lines

    if smoke_status_failed(smoke) and smoke_per_case_results(smoke) != "available":
        lines.append(f"{connector_name} did not complete per-case runtime execution.")
        reason = smoke_unavailable_reason(smoke, connector)
        if reason:
            lines.append(f"- Reason: {md(reason)}")
        lines.append(f"- Status: `{md(smoke.get('status', 'unknown'))}`")
        lines.append(f"- Build status: `{md(smoke.get('build_status', 'unknown'))}`")
        lines.append(f"- Summary evidence: `{md(smoke.get('summary_path', 'unknown'))}`")
        text_summary = smoke.get("text_summary_path")
        if text_summary:
            lines.append(f"- Text summary: `{md(text_summary)}`")
        evidence_note = smoke_evidence_note(smoke)
        if evidence_note:
            lines.append(f"- Evidence note: {md(evidence_note)}")
        return lines

    lines.append(f"No {connector_name} runtime FAIL details were reported.")
    return lines


def phase4_rows_for_smoke(smoke: dict) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for row in smoke_case_rows(smoke):
        if not isinstance(row, dict):
            continue
        capabilities = row.get("capabilities", [])
        capability_set = {str(item) for item in capabilities} if isinstance(capabilities, list) else set()
        if (
            row.get("phase") == 4
            or "phase4" in capability_set
            or "response-body" in capability_set
        ):
            rows.append(row)
    return rows


def render_connector_phase4_details(
    snapshot: dict,
    connector: str,
    snapshot_key: str,
    heading: str,
    heading_level: int,
) -> list[str]:
    smokes = (
        force_all_runtime_summary_by_connector(snapshot)
        if snapshot_key == "force_all_runtime_smokes"
        else runtime_summary_by_connector(snapshot)
    )
    smoke = smokes.get(connector, {})
    connector_name = connector_display_name(connector)
    lines = ["", f"{'#' * heading_level} {heading}"]
    if not smoke or smoke.get("status") == "NOT_AVAILABLE":
        lines.append(f"{connector_name} {heading.lower()} is `NOT_AVAILABLE`.")
        return lines
    rows = phase4_rows_for_smoke(smoke)
    if not rows:
        lines.append("No Phase 4 / RESPONSE_BODY rows are recorded in this summary.")
        return lines
    lines.extend(
        [
            "| Case | Status | Expected | Observed | Transport | Strict Abort | Body Seen | Truncated | Committed | Audit | Phase4 Log | Evidence |",
            "|---|---|---:|---:|---|---|---|---|---|---|---|---|",
        ]
    )
    for row in rows:
        lines.append(
            "| "
            + " | ".join(
                md(value)
                for value in [
                    row.get("case", row.get("name", "-")),
                    normalized_matrix_status_value(row),
                    row.get("expected_status", row.get("expected", "-")),
                    row.get("actual_status", row.get("observed", "-")),
                    row.get("observed_transport_result", "http_status"),
                    row.get("strict_abort", "-"),
                    row.get("response_body_seen", "-"),
                    row.get("response_body_truncated", "-"),
                    row.get("response_committed", "-"),
                    row.get("audit_log_path", "-"),
                    row.get("connector_phase4_log_path", "-"),
                    row.get("evidence_path") or row.get("evidence") or smoke.get("summary_path", "-"),
                ]
            )
            + " |"
        )
    return lines


def haproxy_smoke(snapshot: dict) -> dict:
    return runtime_summary_by_connector(snapshot).get("haproxy", {})


def haproxy_matrix_counts(smoke: dict) -> dict:
    counts = smoke.get("matrix_counts") if isinstance(smoke.get("matrix_counts"), dict) else {}
    if counts:
        return counts
    rows = smoke_case_rows(smoke)
    return dict(Counter(normalized_matrix_status_value(row) for row in rows if isinstance(row, dict)))


def haproxy_matrix_count(smoke: dict, status: str) -> int:
    return count_value(haproxy_matrix_counts(smoke).get(status, 0))


def haproxy_detail_variant(row: dict) -> str:
    variant = str(row.get("variant") or "-")
    if variant == "combined" and row.get("case") == "crs_sqli_anomaly_block" and row.get("crs_verified") is True:
        return "with-crs"
    return variant


def haproxy_detail_evidence(row: dict) -> str:
    return str(row.get("evidence_path") or row.get("decision_log_path") or row.get("source_evidence") or row.get("evidence") or "-")


def haproxy_rows_by_matrix_status(smoke: dict, status: str) -> list[dict]:
    return [
        row
        for row in smoke_case_rows(smoke)
        if isinstance(row, dict) and normalized_matrix_status_value(row) == status
    ]


def haproxy_live_rows_by_matrix_status(smoke: dict, status: str) -> list[dict]:
    return [
        row
        for row in haproxy_rows_by_matrix_status(smoke, status)
        if row.get("live_executed") is True
    ]


def haproxy_rows_by_raw_status(smoke: dict, status: str, *, live_only: bool = False) -> list[dict]:
    wanted = status.strip().lower()
    rows = [
        row
        for row in smoke_case_rows(smoke)
        if isinstance(row, dict) and str(row.get("status", "")).strip().lower() == wanted
    ]
    if live_only:
        rows = [row for row in rows if row.get("live_executed") is True]
    return rows


def render_haproxy_empty_detail(status: str, count: int, note: str) -> list[str]:
    return [
        "| Status | Count | Note |",
        "|---|---:|---|",
        f"| {status} | {count} | {md(note)} |",
    ]


def render_haproxy_pass_details(snapshot: dict, heading_level: int) -> list[str]:
    smoke = haproxy_smoke(snapshot)
    lines = ["", f"{'#' * heading_level} HAProxy PASS Details"]
    rows: list[dict[str, object]] = []
    for row in haproxy_rows_by_matrix_status(smoke, "PASS"):
        if row.get("live_executed") is not True:
            continue
        rows.append(
            {
                "case": row.get("case", "-"),
                "variant": haproxy_detail_variant(row),
                "expected": row.get("expected_status", "-"),
                "actual": row.get("actual_status", "-"),
                "evidence": haproxy_detail_evidence(row),
                "alias": False,
            }
        )
    if not rows:
        lines.extend(
            render_haproxy_empty_detail(
                "PASS",
                haproxy_matrix_count(smoke, "PASS"),
                "No live HAProxy runtime PASS rows were reported in the current matrix.",
            )
        )
        return lines
    lines.extend(["| Case | Variant | Expected | Actual | Evidence |", "|---|---|---:|---:|---|"])
    for row in rows:
        lines.append(
            "| "
            + " | ".join(md(row.get(key, "-")) for key in ["case", "variant", "expected", "actual", "evidence"])
            + " |"
        )
    if any(row.get("alias") for row in rows):
        lines.append("")
        lines.append("- `haproxy_phase1_header_block` is live no-CRS alias evidence and is not counted as a framework YAML PASS row.")
    return lines


def render_haproxy_status_details(snapshot: dict, status: str, heading_level: int) -> list[str]:
    smoke = haproxy_smoke(snapshot)
    lines = ["", f"{'#' * heading_level} HAProxy {status} Details"]
    if status == "FAIL":
        rows = haproxy_live_rows_by_matrix_status(smoke, status)
    else:
        rows = haproxy_rows_by_matrix_status(smoke, status)
    if not rows:
        notes = {
            "FAIL": "No live HAProxy runtime FAIL rows were reported in the current matrix.",
            "BLOCKED": "No HAProxy BLOCKED rows were reported in the current matrix.",
            "NOT_EXECUTABLE": "No HAProxy NOT_EXECUTABLE rows were reported in the current matrix.",
        }
        count = 0 if status == "FAIL" else haproxy_matrix_count(smoke, status)
        lines.extend(render_haproxy_empty_detail(status, count, notes.get(status, "No rows were reported.")))
        return lines
    if status == "FAIL":
        lines.extend(
            [
                "| Case | Variant | Expected | Actual | Assessment | Evidence |",
                "|---|---|---:|---:|---|---|",
            ]
        )
        for row in rows:
            lines.append(
                "| "
                + " | ".join(
                    md(value)
                    for value in [
                        row.get("case", "-"),
                        haproxy_detail_variant(row),
                        row.get("expected_status", "-"),
                        row.get("actual_status", "-"),
                        "live HAProxy runtime result mismatch",
                        haproxy_detail_evidence(row),
                    ]
                )
                + " |"
            )
        return lines
    lines.extend(["| Case | Variant | Reason | Evidence |", "|---|---|---|---|"])
    for row in rows:
        lines.append(
            "| "
            + " | ".join(
                md(value)
                for value in [
                    row.get("case", "-"),
                    haproxy_detail_variant(row),
                    row.get("reason", "-"),
                    haproxy_detail_evidence(row),
                ]
            )
            + " |"
        )
    return lines


def render_haproxy_mapped_only_details(snapshot: dict, heading_level: int) -> list[str]:
    smoke = haproxy_smoke(snapshot)
    lines = ["", f"{'#' * heading_level} HAProxy MAPPED_ONLY Details"]
    rows = smoke.get("mapped_only") if isinstance(smoke.get("mapped_only"), list) else []
    if not rows:
        lines.extend(
            render_haproxy_empty_detail(
                "MAPPED_ONLY",
                haproxy_matrix_count(smoke, "MAPPED_ONLY"),
                "No HAProxy mapped-only import inventory entries were reported in the current matrix.",
            )
        )
        return lines
    lines.extend(["| Case | Reason | Evidence |", "|---|---|---|"])
    for row in rows:
        if not isinstance(row, dict):
            continue
        lines.append(f"| {md(row.get('source', 'unknown'))} | {md(row.get('reason', ''))} | `config/testing/import-status.json` |")
    return lines


def render_haproxy_non_pass_summary(snapshot: dict, heading_level: int) -> list[str]:
    smoke = haproxy_smoke(snapshot)
    fail_count = len(haproxy_live_rows_by_matrix_status(smoke, "FAIL"))
    rows = [
        (
            "FAIL",
            fail_count,
            "Live-executed HAProxy runtime mismatches only; PASS/FAIL require live execution.",
        ),
        (
            "BLOCKED",
            haproxy_matrix_count(smoke, "BLOCKED"),
            "Relevant HAProxy rows blocked by current harness or prerequisites.",
        ),
        (
            "NOT_EXECUTABLE",
            haproxy_matrix_count(smoke, "NOT_EXECUTABLE"),
            "Rows outside the current HAProxy runtime surface.",
        ),
        (
            "MAPPED_ONLY",
            haproxy_matrix_count(smoke, "MAPPED_ONLY"),
            "Import inventory only; not runtime-executable YAML evidence.",
        ),
    ]
    lines = [
        "",
        f"{'#' * heading_level} HAProxy Non-PASS Summary",
        "| Status | Count | Note |",
        "|---|---:|---|",
    ]
    for status, count, note in rows:
        lines.append(f"| {status} | {count} | {md(note)} |")
    lines.extend(
        [
            "",
            f"- Detailed BLOCKED, NOT_EXECUTABLE, and MAPPED_ONLY rows are reported in `{report_doc('generated/haproxy-runtime-results.generated.md')}`.",
            "- BLOCKED, NOT_EXECUTABLE, and MAPPED_ONLY rows are not runtime FAIL rows.",
        ]
    )
    return lines


def render_haproxy_runtime_details(snapshot: dict, heading_level: int) -> list[str]:
    lines: list[str] = []
    lines.extend(render_haproxy_pass_details(snapshot, heading_level))
    lines.extend(render_haproxy_status_details(snapshot, "FAIL", heading_level))
    lines.extend(render_haproxy_status_details(snapshot, "BLOCKED", heading_level))
    lines.extend(render_haproxy_status_details(snapshot, "NOT_EXECUTABLE", heading_level))
    lines.extend(render_haproxy_mapped_only_details(snapshot, heading_level))
    return lines


def render_haproxy_compact_runtime_details(snapshot: dict, heading_level: int) -> list[str]:
    lines: list[str] = []
    lines.extend(render_haproxy_pass_details(snapshot, heading_level))
    lines.extend(render_haproxy_status_details(snapshot, "FAIL", heading_level))
    lines.extend(render_haproxy_non_pass_summary(snapshot, heading_level))
    return lines


def haproxy_force_all_smoke(snapshot: dict) -> dict:
    return force_all_runtime_summary_by_connector(snapshot).get("haproxy", {})


def render_haproxy_smoke_counts(smoke: dict, heading: str, heading_level: int) -> list[str]:
    counts = smoke_counts(smoke)
    attempted = runtime_attempted_count_from_smoke(smoke)
    lines = [
        "",
        f"{'#' * heading_level} {heading}",
        f"- Runtime mode: `{md(smoke.get('runtime_mode', 'unknown'))}`",
        f"- Command: `{md(smoke.get('command', 'unknown'))}`",
        f"- Status: **{md(smoke.get('status', 'unknown'))}**",
        f"- Exit code: `{md(smoke.get('exit_code', 'unknown'))}`",
        f"- Attempted YAML cases: **{attempted}**",
        f"- Total cases in summary: **{md(smoke.get('total_cases', len(smoke_case_rows(smoke))))}**",
        f"- Evidence root: `{md(smoke.get('evidence_root', smoke.get('summary_path', 'unknown')))}`",
        f"- JSONL evidence: `{md(smoke.get('jsonl_path', 'unknown'))}`",
        f"- Per-case result root: `{md(smoke.get('per_case_result_root', 'unknown'))}`",
        "",
        TABLE_STATUS_COUNT_HEADER,
        TABLE_STATUS_COUNT_SEPARATOR,
    ]
    for status in ["pass", "fail", "blocked", "not_executable", "skipped"]:
        lines.append(f"| {status.upper()} | {md(counts.get(status, 'unknown'))} |")
    if smoke.get("failed_due_to_live_mismatches"):
        lines.extend(["", "- Force-all exited nonzero because live-executed rows mismatched expected runtime outcomes."])
    return lines


def render_haproxy_smoke_status_details(smoke: dict, status: str, heading: str, heading_level: int) -> list[str]:
    lines = ["", f"{'#' * heading_level} {heading}"]
    raw_status = status.strip().lower()
    rows = haproxy_rows_by_raw_status(smoke, raw_status, live_only=status == "FAIL")
    if not rows:
        count = count_value(smoke_counts(smoke).get(raw_status, 0))
        lines.extend(render_haproxy_empty_detail(status, count, "No rows were reported."))
        return lines
    if status == "FAIL":
        lines.extend(["| Case | Expected | Observed | Reason | Evidence | Decision Log |", "|---|---:|---:|---|---|---|"])
        for row in rows:
            lines.append(
                "| "
                + " | ".join(
                    md(value)
                    for value in [
                        row.get("case", "-"),
                        row.get("expected_status", row.get("expected", "-")),
                        row.get("actual_status", row.get("observed", "-")),
                        row.get("reason", "live HAProxy runtime result mismatch"),
                        haproxy_detail_evidence(row),
                        row.get("decision_log_path", "-"),
                    ]
                )
                + " |"
            )
        return lines
    lines.extend(["| Case | Reason | Evidence | Decision Log |", "|---|---|---|---|"])
    for row in rows:
        lines.append(
            "| "
            + " | ".join(
                md(value)
                for value in [
                    row.get("case", "-"),
                    row.get("reason", "-"),
                    haproxy_detail_evidence(row),
                    row.get("decision_log_path", "-"),
                ]
            )
            + " |"
        )
    return lines


def render_haproxy_force_all_runtime_details(snapshot: dict, heading_level: int) -> list[str]:
    smoke = haproxy_force_all_smoke(snapshot)
    lines: list[str] = []
    if not smoke:
        return [
            "",
            f"{'#' * heading_level} HAProxy Force-All Runtime Details",
            "No HAProxy force-all runtime evidence is recorded.",
        ]
    lines.extend(render_haproxy_smoke_counts(smoke, "HAProxy Force-All Runtime Details", heading_level))
    lines.extend(render_haproxy_smoke_status_details(smoke, "FAIL", "HAProxy Force-All FAIL Rows", heading_level + 1))
    lines.extend(render_haproxy_smoke_status_details(smoke, "NOT_EXECUTABLE", "HAProxy Force-All NOT_EXECUTABLE Rows", heading_level + 1))
    lines.extend(render_haproxy_smoke_status_details(smoke, "BLOCKED", "HAProxy Force-All BLOCKED Rows", heading_level + 1))
    return lines


def snapshot_named_rows(snapshot: dict, key: str) -> list:
    rows = snapshot.get(key, [])
    return rows if isinstance(rows, list) else []


def runtime_smoke_rows_for_key(snapshot: dict, key: str) -> list[dict[str, object]]:
    rows = []
    for item in snapshot_named_rows(snapshot, key):
        if not isinstance(item, dict):
            continue
        counts = item.get("counts") if isinstance(item.get("counts"), dict) else {}
        rows.append(
            {
                "command": item.get("command", "-"),
                "connector": item.get("connector", "-"),
                "runtime_mode": item.get("runtime_mode", "default" if key == "runtime_smokes" else "force-all"),
                "status": item.get("status", "-"),
                "exit_code": item.get("exit_code", "-"),
                "pass": counts.get("pass", "unknown"),
                "fail": counts.get("fail", "unknown"),
                "blocked": counts.get("blocked", "unknown"),
                "not_executable": counts.get("not_executable", "unknown"),
                "attempted": runtime_attempted_count_from_smoke(item),
                "summary_path": item.get("summary_path", item.get("details", "-")),
            }
        )
    return rows


def runtime_smoke_rows(snapshot: dict) -> list[dict[str, object]]:
    return runtime_smoke_rows_for_key(snapshot, "runtime_smokes")


def force_all_runtime_smoke_rows(snapshot: dict) -> list[dict[str, object]]:
    return runtime_smoke_rows_for_key(snapshot, "force_all_runtime_smokes")


def render_force_all_runtime_status(snapshot: dict) -> list[str]:
    rows = force_all_runtime_smoke_rows(snapshot)
    if not rows:
        return [
            "| Connector | Status | Attempted | PASS | FAIL | BLOCKED | NOT_EXECUTABLE | Evidence |",
            "|---|---|---:|---:|---:|---:|---:|---|",
            "| Apache | NOT_AVAILABLE | 0 | unknown | unknown | unknown | unknown | not available |",
            "| NGINX | NOT_AVAILABLE | 0 | unknown | unknown | unknown | unknown | not available |",
            "| HAProxy | NOT_AVAILABLE | 0 | unknown | unknown | unknown | unknown | not available |",
        ]
    by_connector = {str(row.get("connector", "")): row for row in rows}
    lines = [
        "| Connector | Status | Attempted | PASS | FAIL | BLOCKED | NOT_EXECUTABLE | Evidence |",
        "|---|---|---:|---:|---:|---:|---:|---|",
    ]
    for connector in RUNTIME_CONNECTORS:
        row = by_connector.get(connector)
        if not row:
            lines.append(f"| {connector_display_name(connector)} | NOT_AVAILABLE | 0 | unknown | unknown | unknown | unknown | not available |")
            continue
        lines.append(
            "| "
            + " | ".join(
                md(value)
                for value in [
                    connector_display_name(connector),
                    row.get("status", "NOT_AVAILABLE"),
                    row.get("attempted", 0),
                    row.get("pass", "unknown"),
                    row.get("fail", "unknown"),
                    row.get("blocked", "unknown"),
                    row.get("not_executable", "unknown"),
                    row.get("summary_path", "not available"),
                ]
            )
            + " |"
        )
    return lines


def runtime_failed_rows(snapshot: dict) -> list[dict[str, object]]:
    rows = []
    for item in snapshot_named_rows(snapshot, "runtime_smokes"):
        if not isinstance(item, dict):
            continue
        connector = item.get("connector", item.get("command", "-"))
        for failed in item.get("failed_cases", []):
            if not isinstance(failed, dict):
                continue
            rows.append(
                {
                    "connector": connector,
                    "case": failed.get("case", "-"),
                    "expected": failed.get("expected", "-"),
                    "actual": failed.get("actual", "-"),
                    "assessment": failed.get("assessment", "-"),
                }
            )
    return rows


def append_snapshot_list(lines: list[str], title: str, values: object) -> None:
    if isinstance(values, list) and values:
        lines.extend(["", title])
        lines.extend(f"- {entry}" for entry in values)


def render_runtime_snapshot(snapshot: dict) -> list[str]:
    if not snapshot:
        return [
            "",
            "## Latest Local Runtime Validation Snapshot",
            f"- No local runtime snapshot is recorded in `{report_doc(RUNTIME_SNAPSHOT_FILENAME)}`.",
            "- Do not infer runtime PASS counts from generated coverage metadata.",
        ]

    lines = [
        "",
        "## Latest Local Runtime Validation Snapshot",
        f"- Snapshot: **{snapshot.get('snapshot_date', 'unknown')}** ({snapshot.get('captured_at', 'unknown')})",
        f"- Git: branch `{snapshot.get('branch', 'unknown')}`, commit `{snapshot.get('commit', 'unknown')}`",
        f"- BUILD_ROOT: `{snapshot.get('build_root', 'unknown')}`",
        "- This is a manual local runtime snapshot rendered from tracked snapshot data and local smoke summary files.",
    ]
    lines.extend(f"- {note}" for note in snapshot_named_rows(snapshot, "notes"))
    lines.extend(
        render_status_table(
            "Framework Check Status",
            snapshot_named_rows(snapshot, "framework_checks"),
            [("Command", "command"), ("Status", "status"), ("Details", "details")],
        )
    )
    lines.extend(
        render_status_table(
            "Readiness / Fetch Status",
            snapshot_named_rows(snapshot, "readiness_checks"),
            [("Command", "command"), ("Status", "status"), ("Details", "details")],
        )
    )
    lines.extend(
        render_status_table(
            "Default Runtime Smoke Status",
            runtime_smoke_rows(snapshot),
            [
                ("Connector", "connector"),
                ("Command", "command"),
                ("Status", "status"),
                ("Exit", "exit_code"),
                ("Attempted", "attempted"),
                ("PASS", "pass"),
                ("FAIL", "fail"),
                ("BLOCKED", "blocked"),
                ("NOT_EXECUTABLE", "not_executable"),
                ("Evidence", "summary_path"),
            ],
        )
    )
    lines.extend(
        render_status_table(
            "Force-All Runtime Smoke Status",
            force_all_runtime_smoke_rows(snapshot),
            [
                ("Connector", "connector"),
                ("Command", "command"),
                ("Status", "status"),
                ("Exit", "exit_code"),
                ("Attempted", "attempted"),
                ("PASS", "pass"),
                ("FAIL", "fail"),
                ("BLOCKED", "blocked"),
                ("NOT_EXECUTABLE", "not_executable"),
                ("Evidence", "summary_path"),
            ],
        )
    )
    lines.extend(render_connector_runtime_availability(snapshot))
    lines.extend(["", "## Runtime FAIL Details"])
    lines.extend(render_connector_runtime_fail_details(snapshot, "apache", heading_level=3))
    lines.extend(render_connector_runtime_fail_details(snapshot, "nginx", heading_level=3))
    append_snapshot_list(lines, "## Runtime Verified Status", snapshot.get("runtime_verified_status", []))
    append_snapshot_list(lines, "## Open Runtime Issues", snapshot.get("open_issues", []))
    return lines


def render_root_summary(
    cases: list[dict],
    import_status: dict,
    runtime_snapshot: dict,
    by_scope: Counter,
    by_status: Counter,
    by_runtime: Counter,
    by_phase: Counter,
) -> str:
    metrics = root_summary_metrics(cases, by_status, by_runtime)
    collection_counts = normalized_collection_counts(cases)
    mapped_only_count = len(import_status.get("mapped_only", []))
    runtime_blocked_count = len(import_status.get("runtime_blocked", []))
    topics = topic_counts(cases)
    rt_rows = runtime_rows(cases, runtime_snapshot)
    apache_runtime_counts = runtime_status_counts(rt_rows, "apache")
    nginx_runtime_counts = runtime_status_counts(rt_rows, "nginx")
    haproxy_runtime_counts = runtime_status_counts(rt_rows, "haproxy")
    runtime_smokes = runtime_summary_by_connector(runtime_snapshot)
    force_all_smokes = force_all_runtime_summary_by_connector(runtime_snapshot)
    apache_smoke_counts = runtime_smokes.get("apache", {}).get("counts", {})
    nginx_smoke_counts = runtime_smokes.get("nginx", {}).get("counts", {})
    haproxy_smoke_counts = runtime_smokes.get("haproxy", {}).get("counts", {})
    force_all_apache_smoke = force_all_smokes.get("apache", {})
    force_all_nginx_smoke = force_all_smokes.get("nginx", {})
    force_all_haproxy_smoke = force_all_smokes.get("haproxy", {})
    force_all_apache_counts = smoke_counts(force_all_apache_smoke)
    force_all_nginx_counts = smoke_counts(force_all_nginx_smoke)
    force_all_haproxy_counts = smoke_counts(force_all_haproxy_smoke)
    if not isinstance(apache_smoke_counts, dict):
        apache_smoke_counts = {}
    if not isinstance(nginx_smoke_counts, dict):
        nginx_smoke_counts = {}
    if not isinstance(haproxy_smoke_counts, dict):
        haproxy_smoke_counts = {}
    apache_attempted = runtime_attempted_count(runtime_snapshot, "apache")
    nginx_attempted = runtime_attempted_count(runtime_snapshot, "nginx")
    haproxy_attempted = runtime_attempted_count(runtime_snapshot, "haproxy")
    apache_force_all_attempted = force_all_runtime_attempted_count(runtime_snapshot, "apache")
    nginx_force_all_attempted = force_all_runtime_attempted_count(runtime_snapshot, "nginx")
    haproxy_force_all_attempted = force_all_runtime_attempted_count(runtime_snapshot, "haproxy")
    runtime_executable_count = sum(1 for row in rt_rows if row["runtime_executable"] == "yes")
    force_all_executable_count = sum(1 for row in rt_rows if row["force_all_executable"] == "yes")
    detail_docs = [
        "generated/case-matrix.generated.md",
        "generated/coverage-summary.generated.md",
        "generated/xfail-summary.generated.md",
        "generated/connector-gap-summary.generated.md",
        "generated/phase-coverage.generated.md",
        "generated/runtime-matrix.generated.md",
        "generated/apache-runtime-results.generated.md",
        "generated/nginx-runtime-results.generated.md",
        "generated/haproxy-runtime-results.generated.md",
        RUNTIME_SNAPSHOT_FILENAME,
    ]

    detail_docs = [
        OVERVIEW_FILENAME,
        "generated/case-matrix.generated.md",
        "generated/coverage-summary.generated.md",
        "generated/xfail-summary.generated.md",
        "generated/connector-gap-summary.generated.md",
        "generated/phase-coverage.generated.md",
        "generated/runtime-matrix.generated.md",
        "generated/apache-runtime-results.generated.md",
        "generated/nginx-runtime-results.generated.md",
        "generated/haproxy-runtime-results.generated.md",
        RUNTIME_SNAPSHOT_FILENAME,
    ]

    lines = [
        "# ModSecurity Connector Test Coverage Summary",
        "",
        "## Summary Status",
        f"- Total YAML cases: **{metrics['total']}**",
        f"- Verified/pass (`runtime_verified=true`): **{metrics['verified']}**",
        f"- Current XFAIL cases: **{metrics['current_xfail']}**",
        f"- Former XFAIL cases tracked: **{metrics['former_xfail']}**",
        f"- Pending runtime verification (`runtime_verified=false`): **{metrics['pending_false']}**",
        f"- Pending runtime verification (`runtime_verified=unknown`): **{metrics['pending_unknown']}**",
        f"- Connector-gap cases: **{metrics['connector_gap']}**",
        f"- Runtime-difference cases: **{metrics['runtime_difference']}**",
        f"- Future/experimental cases: **{metrics['future_experimental']}**",
        f"- RESPONSE_BODY cases: **{metrics['response_body']}**",
        f"- Default runtime-executable YAML cases: **{runtime_executable_count}**",
        f"- Force-all runtime-executable YAML cases: **{force_all_executable_count}**",
        f"- Apache attempted YAML cases in default runtime snapshot: **{apache_attempted}**",
        f"- NGINX attempted YAML cases in default runtime snapshot: **{nginx_attempted}**",
        f"- HAProxy attempted YAML cases in default runtime snapshot: **{haproxy_attempted}**",
        f"- Apache attempted YAML cases in force-all runtime snapshot: **{apache_force_all_attempted}**",
        f"- NGINX attempted YAML cases in force-all runtime snapshot: **{nginx_force_all_attempted}**",
        f"- HAProxy attempted YAML cases in force-all runtime snapshot: **{haproxy_force_all_attempted}**",
        f"- Apache force-all raw runtime PASS/FAIL/BLOCKED/NOT_EXECUTABLE: **{count_value(force_all_apache_counts.get('pass', 0))}** / **{count_value(force_all_apache_counts.get('fail', 0))}** / **{count_value(force_all_apache_counts.get('blocked', 0))}** / **{count_value(force_all_apache_counts.get('not_executable', 0))}**",
        f"- NGINX force-all raw runtime PASS/FAIL/BLOCKED/NOT_EXECUTABLE: **{count_value(force_all_nginx_counts.get('pass', 0))}** / **{count_value(force_all_nginx_counts.get('fail', 0))}** / **{count_value(force_all_nginx_counts.get('blocked', 0))}** / **{count_value(force_all_nginx_counts.get('not_executable', 0))}**",
        f"- HAProxy force-all raw runtime PASS/FAIL/BLOCKED/NOT_EXECUTABLE: **{count_value(force_all_haproxy_counts.get('pass', 0))}** / **{count_value(force_all_haproxy_counts.get('fail', 0))}** / **{count_value(force_all_haproxy_counts.get('blocked', 0))}** / **{count_value(force_all_haproxy_counts.get('not_executable', 0))}**",
        f"- Mapped-only import inventory entries: **{mapped_only_count}**",
        *render_mrts_source_summary_lines(cases),
        "",
        "## Important Reporting Semantics",
        "- PASS/FAIL are rendered only from live runtime evidence recorded in connector summaries and decision/result artifacts.",
        "- BLOCKED remains reserved for harness, environment, dependency, build, or runtime blockers.",
        "- NOT_EXECUTABLE means the case is structurally unmappable for that connector/run mode; it is not a blocker and not a pass.",
        "- Force-all evidence does not promote YAML feature support.",
        "- RESPONSE_BODY remains experimental/non-promoted, including bounded phase-4 and strict-abort evidence.",
        "",
        "## Framework Integration",
        f"- This framework-owned file is the source of truth for root coverage reporting: `{ROOT_SUMMARY_FILENAME}` in `ModSecurity-test-Framework`.",
        "- Connector repositories should link to this Framework summary instead of maintaining their own root coverage summary.",
        "- Shared YAML cases, runners, normalizers, generators, and detailed testing documentation are owned by `ModSecurity-test-Framework`.",
        "- The connector repository owns connector source, harnesses, adapter metadata, `config/testing/import-status.json`, and connector-specific generated evidence under `reports/testing/`.",
        "- `FRAMEWORK_ROOT` and `CONNECTOR_ROOT` are explicit integration paths; there is no absolute workspace fallback.",
        "",
        "## Case Inventory",
        f"- Common YAML cases: **{by_scope.get('common', 0)}**",
        f"- Apache-specific YAML cases: **{by_scope.get('apache', 0)}**",
        f"- NGINX-specific YAML cases: **{by_scope.get('nginx', 0)}**",
        f"- Current XFAIL cases: **{metrics['current_xfail']}**",
        f"- Former XFAIL cases tracked: **{metrics['former_xfail']}**",
        f"- Mapped-only import inventory entries: **{mapped_only_count}** (not counted as runnable YAML cases)",
        f"- Runtime-blocked import inventory entries: **{runtime_blocked_count}** (environment/harness blockers, not PASS promotions)",
        f"- Pending/future compatibility cases: **{metrics['future_experimental']}** future/experimental; **{metrics['pending_false'] + metrics['pending_unknown']}** not runtime-verified",
        "",
        "## Status Classes",
        TABLE_STATUS_COUNT_HEADER,
        TABLE_STATUS_COUNT_SEPARATOR,
    ]
    lines.extend(f"| {status} | {count} |" for status, count in sorted(by_status.items()))
    lines.extend(["", "## Scope", "| Scope | Count |", TABLE_STATUS_COUNT_SEPARATOR])
    lines.extend(f"| {scope} | {by_scope.get(scope, 0)} |" for scope in ["common", "apache", "nginx", "unknown"])
    lines.extend(["", "## Coverage By Variable / Collection", "| Variable / Collection | Count |", TABLE_STATUS_COUNT_SEPARATOR])
    lines.extend(f"| `{name}` | {collection_counts.get(name, 0)} |" for name in ROOT_COLLECTIONS)
    lines.extend(["", "## Coverage By Phase", "| Phase | Count |", TABLE_STATUS_COUNT_SEPARATOR])
    lines.extend(f"| Phase {phase} | {by_phase.get(phase, 0)} |" for phase in [1, 2, 3, 4])
    lines.extend(["", "## Coverage By Topic", "| Topic | Count |", TABLE_STATUS_COUNT_SEPARATOR])
    lines.extend(f"| {topic} | {count} |" for topic, count in topics.items())
    lines.extend(
        [
            "",
            "## Runtime Matrix Status",
            *render_runtime_status_count_table(apache_runtime_counts, nginx_runtime_counts, haproxy_runtime_counts, mapped_only_count),
            "",
            f"- Apache attempted YAML cases from default summary: **{apache_attempted}**",
            f"- NGINX attempted YAML cases from default summary: **{nginx_attempted}**",
            f"- HAProxy attempted YAML cases from default summary: **{haproxy_attempted}**",
            f"- Apache {NOT_EXECUTED} YAML rows: **{apache_runtime_counts.get(NOT_EXECUTED, 0)}**",
            f"- NGINX {NOT_EXECUTED} YAML rows: **{nginx_runtime_counts.get(NOT_EXECUTED, 0)}**",
            f"- HAProxy {NOT_EXECUTED} YAML rows: **{haproxy_runtime_counts.get(NOT_EXECUTED, 0)}**",
            f"- Apache NOT_EXECUTABLE YAML rows: **{apache_runtime_counts.get('NOT_EXECUTABLE', 0)}**",
            f"- NGINX NOT_EXECUTABLE YAML rows: **{nginx_runtime_counts.get('NOT_EXECUTABLE', 0)}**",
            f"- HAProxy NOT_EXECUTABLE YAML rows: **{haproxy_runtime_counts.get('NOT_EXECUTABLE', 0)}**",
            f"- Mapped-only import inventory entries: **{mapped_only_count}**",
            f"- Runtime matrix detail: `{report_doc('generated/runtime-matrix.generated.md')}`",
            f"- Apache per-case results: `{report_doc('generated/apache-runtime-results.generated.md')}`",
            f"- NGINX per-case results: `{report_doc('generated/nginx-runtime-results.generated.md')}`",
            f"- HAProxy per-case results: `{report_doc('generated/haproxy-runtime-results.generated.md')}`",
            "- PASS/BLOCKED/FAIL counts here come only from tracked runtime snapshot evidence.",
            "- RESPONSE_BODY remains non-verified even when a pass-through runtime case returns HTTP 200.",
            "",
            f"- HAProxy force-all attempted YAML cases: **{haproxy_force_all_attempted}**",
            f"- HAProxy force-all result JSONL: `{md(force_all_haproxy_smoke.get('jsonl_path', 'not available'))}`",
            f"- HAProxy force-all per-case evidence root: `{md(force_all_haproxy_smoke.get('per_case_result_root', 'not available'))}`",
            "- Force-all evidence is traceable runtime evidence but does not promote pending/future/gap feature support.",
        ]
    )
    lines.extend(
        render_status_table(
            "Framework Check Status",
            snapshot_named_rows(runtime_snapshot, "framework_checks"),
            [("Command", "command"), ("Status", "status"), ("Details", "details")],
        )
    )
    lines.extend(
        render_status_table(
            "Readiness / Fetch Status",
            snapshot_named_rows(runtime_snapshot, "readiness_checks"),
            [("Command", "command"), ("Status", "status"), ("Details", "details")],
        )
    )
    lines.extend(
        [
            "",
            "## Runtime Smoke Status",
            f"- Snapshot: **{runtime_snapshot.get('snapshot_date', 'unknown')}** ({runtime_snapshot.get('captured_at', 'unknown')})",
            f"- Git: branch `{runtime_snapshot.get('branch', 'unknown')}`, commit `{runtime_snapshot.get('commit', 'unknown')}`",
            f"- BUILD_ROOT: `{runtime_snapshot.get('build_root', 'unknown')}`",
            f"- Snapshot file: `{report_doc(RUNTIME_SNAPSHOT_FILENAME)}`",
        ]
    )
    lines.extend(
        render_status_table(
            "Default Runtime Smoke Status",
            runtime_smoke_rows(runtime_snapshot),
            [
                ("Connector", "connector"),
                ("Command", "command"),
                ("Status", "status"),
                ("Exit", "exit_code"),
                ("Attempted", "attempted"),
                ("PASS", "pass"),
                ("FAIL", "fail"),
                ("BLOCKED", "blocked"),
                ("NOT_EXECUTABLE", "not_executable"),
                ("Evidence", "summary_path"),
            ],
            heading_level=3,
        )
    )
    lines.extend(
        render_status_table(
            "Force-All Runtime Smoke Status",
            force_all_runtime_smoke_rows(runtime_snapshot),
            [
                ("Connector", "connector"),
                ("Command", "command"),
                ("Status", "status"),
                ("Exit", "exit_code"),
                ("Attempted", "attempted"),
                ("PASS", "pass"),
                ("FAIL", "fail"),
                ("BLOCKED", "blocked"),
                ("NOT_EXECUTABLE", "not_executable"),
                ("Evidence", "summary_path"),
            ],
            heading_level=3,
        )
    )
    lines.extend(render_connector_runtime_availability(runtime_snapshot))
    lines.extend(["", "## Runtime FAIL Details"])
    lines.extend(render_connector_runtime_fail_details(runtime_snapshot, "apache", heading_level=3))
    lines.extend(render_connector_runtime_fail_details(runtime_snapshot, "nginx", heading_level=3))
    lines.extend(render_connector_runtime_fail_details(runtime_snapshot, "haproxy", heading_level=3))
    append_snapshot_list(lines, "## Runtime Verified Status", runtime_snapshot.get("runtime_verified_status", []))
    append_snapshot_list(lines, "## Open Runtime Issues", runtime_snapshot.get("open_issues", []))
    lines.extend(
        [
            "",
            "## Open Areas / Gaps",
            "- Runtime verification pending: cases with `runtime_verified=false` or `runtime_verified=unknown` are not runtime PASS proof.",
            "- RESPONSE_BODY remains non-verified and non-promoted.",
            "- GitHub/Codex checks are intentionally lightweight and do not prove runtime compatibility.",
            "- Pending, future, connector-gap, and runtime-difference topics require local runtime evidence before any support claim.",
            "- Runtime-blocked import entries are environment or harness blockers and do not imply connector-gap/runtime-difference promotion.",
            "- `installed-readiness` is diagnostic detection, not runtime execution.",
            "- There is no separate artifact-reuse smoke path; runtime validation uses source-build execution.",
            "- `make smoke-all` is authoritative only when it is actually executed successfully.",
            "",
            "## Commands",
        ]
    )
    lines.extend(f"- `{command}`" for command in ROOT_COMMANDS)
    lines.extend(["", "## Detail Reports"])
    lines.extend(f"- `{report_doc(doc)}`" for doc in detail_docs)
    lines.extend(
        [
            "",
            "## Important Note",
            "Generated coverage is reporting only; it is not runtime evidence by itself.",
            "Full runtime validation is local and evidence-based.",
            "GitHub/Codex checks are intentionally lightweight.",
            "Pending, future, and gap topics need local runtime validation before promotion.",
            "`make smoke-all` is authoritative only if it was actually executed successfully.",
            "No PASS numbers are inferred from this file when `make smoke-all` was not run successfully.",
            "Phase 4 / RESPONSE_BODY remains non-promoted; bounded strict-abort evidence is reported as runtime evidence only.",
        ]
    )
    return "\n".join(lines)


def render_overview(
    cases: list[dict],
    import_status: dict,
    runtime_snapshot: dict,
    by_scope: Counter,
    by_status: Counter,
    by_runtime: Counter,
    by_phase: Counter,
    by_var: Counter,
    response_body_count: int,
) -> str:
    connector_gap_count = sum(1 for case in cases if case_has_classification(case, "connector-gap") or case["status"] == "connector-gap")
    runtime_diff_count = sum(1 for case in cases if case_has_classification(case, "runtime-difference") or case["status"] == "runtime-difference")
    future_exp_count = sum(1 for case in cases if case_has_classification(case, "future", "experimental") or case["status"] in {"future", "experimental"})
    rt_rows = runtime_rows(cases, runtime_snapshot)
    apache_runtime_counts = runtime_status_counts(rt_rows, "apache")
    nginx_runtime_counts = runtime_status_counts(rt_rows, "nginx")
    haproxy_runtime_counts = runtime_status_counts(rt_rows, "haproxy")
    force_all_smokes = force_all_runtime_summary_by_connector(runtime_snapshot)
    force_all_apache_counts = smoke_counts(force_all_smokes.get("apache", {}))
    force_all_nginx_counts = smoke_counts(force_all_smokes.get("nginx", {}))
    force_all_haproxy_counts = smoke_counts(force_all_smokes.get("haproxy", {}))
    mapped_only = import_status.get("mapped_only", [])
    mapped_only_count = len(mapped_only) if isinstance(mapped_only, list) else 0
    apache_attempted = runtime_attempted_count(runtime_snapshot, "apache")
    nginx_attempted = runtime_attempted_count(runtime_snapshot, "nginx")
    haproxy_attempted = runtime_attempted_count(runtime_snapshot, "haproxy")
    apache_force_all_attempted = force_all_runtime_attempted_count(runtime_snapshot, "apache")
    nginx_force_all_attempted = force_all_runtime_attempted_count(runtime_snapshot, "nginx")
    haproxy_force_all_attempted = force_all_runtime_attempted_count(runtime_snapshot, "haproxy")
    runtime_executable_count = sum(1 for row in rt_rows if row["runtime_executable"] == "yes")
    force_all_executable_count = sum(1 for row in rt_rows if row["force_all_executable"] == "yes")
    detail_docs = [
        "generated/case-matrix.generated.md",
        "generated/coverage-summary.generated.md",
        "generated/xfail-summary.generated.md",
        "generated/connector-gap-summary.generated.md",
        "generated/phase-coverage.generated.md",
        "generated/runtime-matrix.generated.md",
        "generated/apache-runtime-results.generated.md",
        "generated/nginx-runtime-results.generated.md",
        "generated/haproxy-runtime-results.generated.md",
        RUNTIME_SNAPSHOT_FILENAME,
    ]

    lines = [
        "# ModSecurity Connector Test Coverage Overview",
        "",
        "## Summary",
        f"- Total cases: **{len(cases)}**",
        f"- Verified/pass count (`runtime_verified=true`): **{by_runtime.get('true', 0)}**",
        f"- Current XFAIL count: **{by_status.get('xfail', 0)}**",
        f"- Former XFAIL cases tracked: **{sum(1 for case in cases if case.get('former_xfail'))}**",
        f"- Pending runtime verification count: **{by_runtime.get('false', 0)}**",
        f"- Connector-gap count: **{connector_gap_count}**",
        f"- Runtime-difference count: **{runtime_diff_count}**",
        f"- Future/experimental count: **{future_exp_count}**",
        f"- RESPONSE_BODY cases: **{response_body_count}** (still **not verified/promoted**)",
        f"- Mapped-only import inventory entries: **{mapped_only_count}**",
        *render_mrts_source_summary_lines(cases),
        "",
        "## Coverage By Variable / Collection",
        "| Variable | Count |",
        TABLE_STATUS_COUNT_SEPARATOR,
    ]
    lines.extend(f"| `{k}` | {v} |" for k, v in by_var.most_common(20))
    lines.extend(["", "## Coverage By Phase", "| Phase | Count |", TABLE_STATUS_COUNT_SEPARATOR])
    lines.extend(f"| {phase} | {by_phase.get(phase, 0)} |" for phase in [1, 2, 3, 4])
    lines.extend(["", "## Coverage By Status", TABLE_STATUS_COUNT_HEADER, TABLE_STATUS_COUNT_SEPARATOR])
    lines.extend(f"| {status} | {count} |" for status, count in sorted(by_status.items()))
    lines.extend(["", "## Coverage By Scope", "| Scope | Count |", TABLE_STATUS_COUNT_SEPARATOR])
    lines.extend(f"| {scope} | {by_scope.get(scope, 0)} |" for scope in ["common", "apache", "nginx", "unknown"])
    lines.extend(
        [
            "",
            "## Runtime Matrix Status",
            f"- Default runtime-executable YAML cases: **{runtime_executable_count}**",
            f"- Force-all runtime-executable YAML cases: **{force_all_executable_count}**",
            f"- Apache attempted YAML cases from default summary: **{apache_attempted}**",
            f"- NGINX attempted YAML cases from default summary: **{nginx_attempted}**",
            f"- HAProxy attempted YAML cases from default summary: **{haproxy_attempted}**",
            f"- Apache attempted YAML cases from force-all summary: **{apache_force_all_attempted}**",
            f"- NGINX attempted YAML cases from force-all summary: **{nginx_force_all_attempted}**",
            f"- HAProxy attempted YAML cases from force-all summary: **{haproxy_force_all_attempted}**",
            f"- Apache force-all raw runtime PASS/FAIL/BLOCKED/NOT_EXECUTABLE: **{count_value(force_all_apache_counts.get('pass', 0))}** / **{count_value(force_all_apache_counts.get('fail', 0))}** / **{count_value(force_all_apache_counts.get('blocked', 0))}** / **{count_value(force_all_apache_counts.get('not_executable', 0))}**",
            f"- NGINX force-all raw runtime PASS/FAIL/BLOCKED/NOT_EXECUTABLE: **{count_value(force_all_nginx_counts.get('pass', 0))}** / **{count_value(force_all_nginx_counts.get('fail', 0))}** / **{count_value(force_all_nginx_counts.get('blocked', 0))}** / **{count_value(force_all_nginx_counts.get('not_executable', 0))}**",
            f"- HAProxy force-all raw runtime PASS/FAIL/BLOCKED/NOT_EXECUTABLE: **{count_value(force_all_haproxy_counts.get('pass', 0))}** / **{count_value(force_all_haproxy_counts.get('fail', 0))}** / **{count_value(force_all_haproxy_counts.get('blocked', 0))}** / **{count_value(force_all_haproxy_counts.get('not_executable', 0))}**",
            *render_runtime_status_count_table(apache_runtime_counts, nginx_runtime_counts, haproxy_runtime_counts, mapped_only_count),
            f"- Details: `{report_doc('generated/runtime-matrix.generated.md')}`",
            f"- HAProxy per-case results: `{report_doc('generated/haproxy-runtime-results.generated.md')}`",
        ]
    )
    lines.extend(
        render_status_table(
            "Framework Check Status",
            snapshot_named_rows(runtime_snapshot, "framework_checks"),
            [("Command", "command"), ("Status", "status"), ("Details", "details")],
        )
    )
    lines.extend(
        render_status_table(
            "Readiness / Fetch Status",
            snapshot_named_rows(runtime_snapshot, "readiness_checks"),
            [("Command", "command"), ("Status", "status"), ("Details", "details")],
        )
    )
    lines.extend(
        [
            "",
            "## Runtime Smoke Status",
            f"- Snapshot: **{runtime_snapshot.get('snapshot_date', 'unknown')}** ({runtime_snapshot.get('captured_at', 'unknown')})",
            f"- Git: branch `{runtime_snapshot.get('branch', 'unknown')}`, commit `{runtime_snapshot.get('commit', 'unknown')}`",
            f"- BUILD_ROOT: `{runtime_snapshot.get('build_root', 'unknown')}`",
            f"- Snapshot file: `{report_doc(RUNTIME_SNAPSHOT_FILENAME)}`",
        ]
    )
    lines.extend(
        render_status_table(
            "Default Runtime Smoke Status",
            runtime_smoke_rows(runtime_snapshot),
            [
                ("Connector", "connector"),
                ("Command", "command"),
                ("Status", "status"),
                ("Exit", "exit_code"),
                ("Attempted", "attempted"),
                ("PASS", "pass"),
                ("FAIL", "fail"),
                ("BLOCKED", "blocked"),
                ("NOT_EXECUTABLE", "not_executable"),
                ("Evidence", "summary_path"),
            ],
            heading_level=3,
        )
    )
    lines.extend(
        render_status_table(
            "Force-All Runtime Smoke Status",
            force_all_runtime_smoke_rows(runtime_snapshot),
            [
                ("Connector", "connector"),
                ("Command", "command"),
                ("Status", "status"),
                ("Exit", "exit_code"),
                ("Attempted", "attempted"),
                ("PASS", "pass"),
                ("FAIL", "fail"),
                ("BLOCKED", "blocked"),
                ("NOT_EXECUTABLE", "not_executable"),
                ("Evidence", "summary_path"),
            ],
            heading_level=3,
        )
    )
    lines.extend(render_connector_runtime_availability(runtime_snapshot))
    lines.extend(["", "## Runtime FAIL Details"])
    lines.extend(render_connector_runtime_fail_details(runtime_snapshot, "apache", heading_level=3))
    lines.extend(render_connector_runtime_fail_details(runtime_snapshot, "nginx", heading_level=3))
    lines.extend(render_connector_runtime_fail_details(runtime_snapshot, "haproxy", heading_level=3))
    append_snapshot_list(lines, "## Runtime Verified Status", runtime_snapshot.get("runtime_verified_status", []))
    append_snapshot_list(lines, "## Open Runtime Issues", runtime_snapshot.get("open_issues", []))
    lines.extend(
        [
            "",
            "## Open Areas / Gaps",
            "- Runtime-verified means only cases explicitly classified as `runtime_verified=true`.",
            "- Cases with `runtime_verified=false` or `runtime_verified=unknown` are not runtime PASS proof.",
            f"- See `{report_doc('generated/connector-gap-summary.generated.md')}` for detailed connector-gap entries.",
            f"- Phase 3/4 cases are visible in `{report_doc('generated/phase-coverage.generated.md')}` and in the runtime matrix.",
            "- RESPONSE_BODY remains not verified and not promoted.",
            "- GitHub/Codex checks are intentionally lightweight.",
            "- Pending and gap topics need local runtime validation.",
            "- `make smoke-all` is authoritative only if it was actually executed successfully.",
            "",
            "## Commands",
        ]
    )
    lines.extend(f"- `{command}`" for command in ROOT_COMMANDS)
    lines.extend(["", "## Detail Reports"])
    lines.extend(f"- `{report_doc(doc)}`" for doc in detail_docs)
    lines.extend(
        [
            "",
            "## Important Note",
            "Generated coverage is reporting only; it is not runtime evidence by itself.",
            "Full runtime validation is local and evidence-based.",
            "GitHub/Codex checks are intentionally lightweight.",
            "Pending, future, and gap topics need local runtime validation before promotion.",
            "`make smoke-all` is authoritative only if it was actually executed successfully.",
            "No PASS numbers are inferred from this file when `make smoke-all` was not run successfully.",
            "Phase 4 / RESPONSE_BODY remains non-promoted; bounded strict-abort evidence is reported as runtime evidence only.",
        ]
    )
    return "\n".join(lines)

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--framework-root", default=str(FRAMEWORK_ROOT))
    parser.add_argument("--connector-root", default=None)
    parser.add_argument("--output-root", default=None)
    args = parser.parse_args(argv)
    configure_paths(args.framework_root, args.connector_root, args.output_root)
    report_layout = active_report_layout()

    cases = gather_cases()
    import_status = load_import_status()
    runtime_snapshot = load_runtime_snapshot()

    by_scope = Counter(case["scope"] for case in cases)
    by_status = Counter(case["status"] for case in cases)
    by_runtime = Counter(case["runtime_verified"] for case in cases)
    by_phase = Counter(phase for case in cases for phase in case["phases"])
    by_var = Counter(var for case in cases for var in case["variables"])
    response_body_count = sum(1 for case in cases if case["response_body"])

    report_layout.write_generated("case-matrix.generated.md", render_case_matrix(cases))
    report_layout.write_generated("coverage-summary.generated.md", render_summary(cases, by_scope, by_status, by_runtime, by_phase, by_var, response_body_count))
    report_layout.write_generated("xfail-summary.generated.md", render_xfail(cases, import_status))
    report_layout.write_generated("connector-gap-summary.generated.md", render_gap_summary(cases, import_status))
    report_layout.write_generated("phase-coverage.generated.md", render_phase_coverage(cases))
    report_layout.write_generated("runtime-matrix.generated.md", render_runtime_matrix(cases, import_status, runtime_snapshot))
    report_layout.write_generated("apache-runtime-results.generated.md", render_connector_runtime_results(cases, runtime_snapshot, "apache"))
    report_layout.write_generated("nginx-runtime-results.generated.md", render_connector_runtime_results(cases, runtime_snapshot, "nginx"))
    report_layout.write_generated("haproxy-runtime-results.generated.md", render_connector_runtime_results(cases, runtime_snapshot, "haproxy"))
    report_layout.write_overview(
        render_overview(cases, import_status, runtime_snapshot, by_scope, by_status, by_runtime, by_phase, by_var, response_body_count),
    )
    report_layout.write_root_summary(render_root_summary(cases, import_status, runtime_snapshot, by_scope, by_status, by_runtime, by_phase))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
