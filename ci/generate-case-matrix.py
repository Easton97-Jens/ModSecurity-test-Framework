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

from response_body_status import (
    RESPONSE_BODY_EVIDENCE_NOTE,
    RESPONSE_BODY_PASS_THROUGH_STATUS,
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
    "RESPONSE_BODY_PASS_THROUGH",
    "FAIL",
    "BLOCKED",
    "XFAIL_PASS",
    "XFAIL_RESPONSE_BODY_PASS_THROUGH",
    "XFAIL_FAIL",
    "PENDING_PASS",
    "PENDING_RESPONSE_BODY_PASS_THROUGH",
    "PENDING_FAIL",
    "FUTURE_PASS",
    "FUTURE_RESPONSE_BODY_PASS_THROUGH",
    "FUTURE_FAIL",
    "CONNECTOR_GAP_PASS",
    "CONNECTOR_GAP_RESPONSE_BODY_PASS_THROUGH",
    "CONNECTOR_GAP_FAIL",
    "RUNTIME_DIFFERENCE_PASS",
    "RUNTIME_DIFFERENCE_RESPONSE_BODY_PASS_THROUGH",
    "RUNTIME_DIFFERENCE_FAIL",
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

    aliases: dict[str, object] = {}
    no_aliases = no_crs_data.get("smoke_aliases") if isinstance(no_crs_data.get("smoke_aliases"), dict) else {}
    with_aliases = with_crs_data.get("smoke_aliases") if isinstance(with_crs_data.get("smoke_aliases"), dict) else {}
    if isinstance(no_aliases.get("no_crs"), dict):
        aliases["no_crs"] = no_aliases["no_crs"]
    if isinstance(with_aliases.get("with_crs"), dict):
        aliases["with_crs"] = with_aliases["with_crs"]

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
        "smoke_aliases": aliases,
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
        summary["status"] = "PARTIAL" if verified_cases else str(smoke.get("status", "BLOCKED"))
        summary["runtime_verified"] = bool(verified_cases)
        summary["runtime_status"] = str(smoke.get("runtime_status", "runtime-matrix-partial" if verified_cases else "not-verified"))
        summary["verified_cases"] = verified_cases
        summary["full_matrix_verified"] = False
        summary["matrix_full"] = False
        summary["counts"] = smoke.get("matrix_counts") if isinstance(smoke.get("matrix_counts"), dict) else smoke.get("counts", {})
        summary_path = Path(str(smoke.get("summary_path") or new_connector_default_evidence_path(connector)))
        results_dir = summary_path.parent
        summary["evidence_path"] = f"{results_dir / 'no-crs' / 'haproxy-summary.json'}; {results_dir / 'with-crs' / 'haproxy-summary.json'}"
    return summary


def load_new_connector_smoke_summaries(runtime_snapshot: dict | None = None) -> dict[str, dict]:
    runtime_snapshot = runtime_snapshot if isinstance(runtime_snapshot, dict) else {}
    build_root = Path(os.environ.get("BUILD_ROOT", "/src/ModSecurity-conector-build"))
    results_dir = build_root / "results"
    summaries: dict[str, dict] = {}
    for connector in NEW_CONNECTOR_SMOKE_CONNECTORS:
        path = results_dir / f"{connector}-summary.json"
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
            aliases = data.get("smoke_aliases")
            if isinstance(aliases, dict):
                parts = []
                for label, key in (("no-crs", "no_crs"), ("with-crs", "with_crs")):
                    alias = aliases.get(key)
                    if not isinstance(alias, dict):
                        continue
                    detail = f"{label} {alias.get('status', 'not-run')}"
                    if alias.get("block_probe_status") not in (None, "not-run"):
                        detail += f" block={alias.get('block_probe_status')}"
                    if alias.get("pass_probe_status") not in (None, "not-run"):
                        detail += f" pass={alias.get('pass_probe_status')}"
                    if alias.get("yaml_case"):
                        detail += f" yaml={alias.get('yaml_case')}"
                    parts.append(detail)
                with_crs = "; ".join(parts) if parts else "-"
            else:
                with_crs = "-"
        evidence = data.get("evidence_path", "-")
        lines.append(
            f"| {connector} | {status} | {runtime_status} | {runtime_verified} | {crs_verified} | {response_body_verified} | `{verified_cases}` | {with_crs} | `{evidence}` |"
        )
    lines.extend(
        [
            "",
            "- HAProxy CRS verification is scoped to `haproxy_crs_sqli_anomaly_block` only when HAProxy with-CRS evidence reports PASS and `crs_verified=true`.",
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
    s = str(path).replace("\\", "/")
    if "/tests/cases/connector-specific/apache/" in s:
        return "apache"
    if "/tests/cases/connector-specific/nginx/" in s:
        return "nginx"
    if "/tests/cases/" in s:
        return "common"
    return "unknown"


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
    if status in {"xfail", "pending", "blocked", "unknown"}:
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


def extract_status_metadata(data: dict) -> tuple[str, str, str, str, dict]:
    status = str(data.get("status", "active") or "active").strip().lower()
    category = str(data.get("category", "unknown") or "unknown")
    notes = str(data.get("notes", data.get("note", "")) or "") or "-"
    source = str(data.get("source") or data.get("source_ref") or data.get("provenance") or "unknown")
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
    status, category, notes, source, _ = extract_status_metadata(data)
    tags = extract_gap_tags(path, status, category, notes, source)
    case_id = str(data.get("name", path.stem) or path.stem)
    case_for_detection = dict(data)
    case_for_detection.update(
        {
            "id": case_id,
            "path": display_path(path),
            "variables": sorted(variables),
            "category": category,
            "notes": notes,
            "tags": tags,
        }
    )

    response_body = is_response_body_related(case_for_detection, path)
    if not phases:
        warn(f"no phase metadata found in {path}")

    return {
        "id": case_id,
        "path": display_path(path),
        "scope": infer_scope(path),
        "status": status,
        "category": category,
        "runtime_verified": parse_runtime_verified(data),
        "variables": sorted(variables),
        "operators": sorted(operators),
        "transformations": sorted(transformations),
        "phases": sorted(phases),
        "response_body": response_body,
        "source": source,
        "notes": notes,
        "tags": tags,
    }


def gather_cases() -> list[dict]:
    files = sorted((FRAMEWORK_ROOT / "tests" / "cases").rglob("*.yaml"))
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
        "| case_id | path | scope | phase | variables | operators | transformations | status | runtime_verified | RESPONSE_BODY non-verified | notes |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for case in cases:
        rows.append(
            f"| {case['id']} | `{case['path']}` | {case['scope']} | {','.join(map(str, case['phases'])) or '-'} | "
            f"{', '.join(case['variables']) or '-'} | {', '.join(case['operators']) or '-'} | "
            f"{', '.join(case['transformations']) or '-'} | {case['status']} | {case['runtime_verified']} | "
            f"{'yes' if case['response_body'] else 'no'} | {case['notes']} |"
        )
    return "\n".join(rows)


def render_summary(cases: list[dict], by_scope: Counter, by_status: Counter, by_runtime: Counter, by_phase: Counter, by_var: Counter, response_body_count: int) -> str:
    lines = ["# Generated Coverage Summary", "", f"- Total cases: {len(cases)}", f"- RESPONSE_BODY cases: {response_body_count}", f"- Verified runtime cases: {by_runtime.get('true', 0)}", f"- Non-verified runtime cases: {len(cases) - by_runtime.get('true', 0)}", "", "## By scope"]
    lines.extend(f"- {scope}: {by_scope.get(scope, 0)}" for scope in ["common", "apache", "nginx", "unknown"])
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


def render_xfail(cases: list[dict]) -> str:
    rows = ["# Generated XFAIL/Pending/Future Summary", "", "| case_id | path | status | phase | variables | notes |", "|---|---|---|---|---|---|"]
    marker_tags = {"future", "experimental", "pending"}
    for case in cases:
        if case["status"] in {"xfail", "pending", "future", "experimental"} or marker_tags.intersection(case["tags"]):
            rows.append(f"| {case['id']} | `{case['path']}` | {case['status']} | {','.join(map(str, case['phases'])) or '-'} | {', '.join(case['variables']) or '-'} | {case['notes']} |")
    return "\n".join(rows)


def render_gap_summary(cases: list[dict], import_status: dict) -> str:
    rows = ["# Generated Connector Gap Summary", "", "| case_id | path | status | tags | variables | source/provenance | notes |", "|---|---|---|---|---|---|---|"]
    for case in cases:
        tags = set(case["tags"])
        if {"connector-gap", "runtime-difference"}.intersection(tags) or case["status"] in {"connector-gap", "runtime-difference"}:
            rows.append(f"| {case['id']} | `{case['path']}` | {case['status']} | {', '.join(case['tags']) or '-'} | {', '.join(case['variables']) or '-'} | {case['source']} | {case['notes']} |")
    for key in ["connector_specific", "runtime_blocked", "mapped_only", "blocked", "xfail"]:
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
        "xfail": by_status.get("xfail", 0),
        "pending_false": by_runtime.get("false", 0),
        "pending_unknown": by_runtime.get("unknown", 0),
        "connector_gap": sum(1 for case in cases if "connector-gap" in case["tags"] or case["status"] == "connector-gap"),
        "runtime_difference": sum(1 for case in cases if "runtime-difference" in case["tags"] or case["status"] == "runtime-difference"),
        "future_experimental": sum(
            1
            for case in cases
            if "future" in case["tags"] or "experimental" in case["tags"] or case["status"] in {"future", "experimental"}
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
        " ".join(case["tags"]),
        " ".join(case["variables"]),
    ]
    return " ".join(parts).lower()


def count_cases_matching(cases: list[dict], *needles: str) -> int:
    return sum(1 for case in cases if any(needle in case_text(case) for needle in needles))


def topic_counts(cases: list[dict]) -> dict[str, int]:
    return {
        "Operators": sum(1 for case in cases if case["operators"]),
        "Transformations": sum(1 for case in cases if case["transformations"]),
        "Multipart / FILES": count_cases_matching(cases, "multipart", "files", "multipart_filename"),
        "JSON": count_cases_matching(cases, "json"),
        "XML": count_cases_matching(cases, "xml"),
        "Unicode / Encoding": count_cases_matching(cases, "unicode", "encoding", "encoded", "urldecode", "url_decode"),
        "XSS-like compatibility probes": count_cases_matching(cases, "xss_like", "xss-like"),
        "SQLi-like compatibility probes": count_cases_matching(cases, "sqli_like", "sqli-like"),
        "Audit-log probes": count_cases_matching(cases, "audit_log", "audit-log", "auditlog"),
        "Response header probes": count_cases_matching(cases, "response_headers", "response header", "phase3_response_headers"),
        "Response body experimental probes": sum(
            1
            for case in cases
            if case["response_body"] and ("experimental" in case["tags"] or "experimental" in case_text(case))
        ),
    }


def render_status_table(title: str, rows: list[dict], columns: list[tuple[str, str]]) -> list[str]:
    if not rows:
        return []
    out = ["", f"## {title}", "| " + " | ".join(header for header, _ in columns) + " |", "|" + "|".join("---" for _ in columns) + "|"]
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
    return case_group(case) in ACTIVE_RUNTIME_STATUSES


def is_xfail_case(case: dict) -> bool:
    return case["status"] == "xfail"


def runtime_classification(case: dict) -> str:
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
    if is_xfail_case(case):
        return "xfail"
    return "active"


def status_label(status: object) -> str:
    value = str(status or "").strip().lower()
    if value in {"pass", "fail", "blocked", "xfail"}:
        return value.upper()
    if value == "skipped":
        return NOT_EXECUTED
    if value in {"not_run", "not-run"}:
        return NOT_EXECUTED
    return NOT_EXECUTED


def semantic_matrix_status(raw_status: str, classification: str, response_body_related: bool = False) -> str:
    return matrix_status_for_result(
        raw_status,
        classification,
        response_body_related=response_body_related,
    )


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


def runtime_cell_from_observed(case: dict, observed: dict) -> dict[str, str]:
    classification = str(observed.get("runtime_classification", runtime_classification(case)))
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
    computed_status = semantic_matrix_status(raw_status, classification, response_body_related)
    status = str(observed.get("matrix_status") or computed_status)
    if response_body_related and raw_status.strip().lower() == "pass":
        status = computed_status
    if status in {NOT_EXECUTED, "NOT_EXECUTABLE"}:
        reason = str(observed.get("reason") or observed.get("details") or "skipped by runtime smoke")
    elif response_body_related and raw_status.strip().lower() == "pass":
        reason = str(observed.get("reason") or f"{RESPONSE_BODY_RUNTIME_NOTE}; classification={classification}")
    else:
        reason = str(observed.get("reason") or f"runtime summary result; classification={classification}")
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
    if connector == "haproxy" and observed:
        return runtime_cell_from_observed(case, observed)
    if not is_force_all_snapshot(snapshot) and not runtime_executable(case, connector):
        return runtime_cell_inventory_only(case)
    if not runtime_executable_for_snapshot(case, connector, snapshot):
        return runtime_cell_outside_snapshot(case)

    if observed:
        return runtime_cell_from_observed(case, observed)

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
            "group": case_group(case),
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
    return len(smoke_case_rows(smoke))


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
        "It does not promote xfail/pending cases, and RESPONSE_BODY remains non-verified/non-promoted.",
        "",
        "## Counts",
        f"- YAML cases: **{len(cases)}**",
        f"- Default runtime-executable YAML cases: **{sum(1 for row in rows if row['runtime_executable'] == 'yes')}**",
        f"- Force-all runtime-executable YAML cases: **{sum(1 for row in rows if row['force_all_executable'] == 'yes')}**",
        f"- Apache attempted YAML cases in latest snapshot: **{runtime_attempted_count(snapshot, 'apache')}**",
        f"- NGINX attempted YAML cases in latest snapshot: **{runtime_attempted_count(snapshot, 'nginx')}**",
        f"- HAProxy attempted YAML cases in latest snapshot: **{runtime_attempted_count(snapshot, 'haproxy')}**",
        f"- mapped-only import inventory entries: **{len(mapped_only)}**",
        "- `NOT_EXECUTABLE` means the YAML case is not applicable to that connector or the runner cannot execute that YAML status for that connector.",
        f"- `{NOT_EXECUTED}` means no runtime case evidence is recorded in a non-force/default snapshot.",
        "- `MAPPED_ONLY` entries are import inventory items, not runnable YAML case files.",
        f"- `{RESPONSE_BODY_PASS_THROUGH_STATUS}` and classified variants are pass-through evidence only and are non-promotable.",
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
                    "group",
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
        f"- Attempted YAML cases in latest snapshot: **{runtime_attempted_count(snapshot, connector)}**",
        "- Runtime evidence is current local snapshot evidence only; it is not xfail/pending promotion.",
        "- RESPONSE_BODY remains non-verified/non-promoted.",
        f"- {RESPONSE_BODY_EVIDENCE_NOTE}",
        "",
        "## Raw Smoke Summary",
        TABLE_STATUS_COUNT_HEADER,
        TABLE_STATUS_COUNT_SEPARATOR,
    ]
    for status in ["pass", "fail", "blocked", "skipped", "xfail"]:
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
    else:
        lines.extend(render_connector_runtime_fail_details(snapshot, connector, heading_level=2))
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


def haproxy_smoke(snapshot: dict) -> dict:
    return runtime_summary_by_connector(snapshot).get("haproxy", {})


def haproxy_matrix_counts(smoke: dict) -> dict:
    counts = smoke.get("matrix_counts") if isinstance(smoke.get("matrix_counts"), dict) else {}
    if counts:
        return counts
    rows = smoke_case_rows(smoke)
    return dict(Counter(str(row.get("matrix_status", "NOT_EXECUTABLE")) for row in rows if isinstance(row, dict)))


def haproxy_matrix_count(smoke: dict, status: str) -> int:
    return count_value(haproxy_matrix_counts(smoke).get(status, 0))


def haproxy_detail_variant(row: dict) -> str:
    variant = str(row.get("variant") or "-")
    if variant == "combined" and row.get("case") == "crs_sqli_anomaly_block" and row.get("crs_verified") is True:
        return "with-crs"
    return variant


def haproxy_detail_evidence(row: dict) -> str:
    return str(row.get("source_evidence") or row.get("evidence") or "-")


def haproxy_rows_by_matrix_status(smoke: dict, status: str) -> list[dict]:
    return [
        row
        for row in smoke_case_rows(smoke)
        if isinstance(row, dict) and str(row.get("matrix_status", "")).strip() == status
    ]


def haproxy_live_rows_by_matrix_status(smoke: dict, status: str) -> list[dict]:
    return [
        row
        for row in haproxy_rows_by_matrix_status(smoke, status)
        if row.get("live_executed") is True
    ]


def render_haproxy_empty_detail(status: str, count: int, note: str) -> list[str]:
    return [
        "| Status | Count | Note |",
        "|---|---:|---|",
        f"| {status} | {count} | {md(note)} |",
    ]


def render_haproxy_pass_details(snapshot: dict, heading_level: int) -> list[str]:
    smoke = haproxy_smoke(snapshot)
    summary_path = str(smoke.get("summary_path", "-"))
    lines = ["", f"{'#' * heading_level} HAProxy PASS Details"]
    rows: list[dict[str, object]] = []
    aliases = smoke.get("smoke_aliases") if isinstance(smoke.get("smoke_aliases"), dict) else {}
    no_crs_alias = aliases.get("no_crs") if isinstance(aliases.get("no_crs"), dict) else {}
    if no_crs_alias.get("verified") is True and str(no_crs_alias.get("status", "")).strip() == "PASS":
        rows.append(
            {
                "case": no_crs_alias.get("name", "haproxy_phase1_header_block"),
                "variant": "no-crs",
                "expected": no_crs_alias.get("expected_status", "-"),
                "actual": no_crs_alias.get("actual_status", no_crs_alias.get("block_probe_status", "-")),
                "evidence": f"{summary_path}; alias=no_crs; pass_actual={no_crs_alias.get('pass_actual_status', no_crs_alias.get('pass_probe_status', '-'))}",
                "alias": True,
            }
        )
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


def snapshot_named_rows(snapshot: dict, key: str) -> list:
    rows = snapshot.get(key, [])
    return rows if isinstance(rows, list) else []


def runtime_smoke_rows(snapshot: dict) -> list[dict[str, object]]:
    rows = []
    for item in snapshot_named_rows(snapshot, "runtime_smokes"):
        if not isinstance(item, dict):
            continue
        counts = item.get("counts") if isinstance(item.get("counts"), dict) else {}
        rows.append(
            {
                "command": item.get("command", "-"),
                "status": item.get("status", "-"),
                "exit_code": item.get("exit_code", "-"),
                "pass": counts.get("pass", "unknown"),
                "fail": counts.get("fail", "unknown"),
                "blocked": counts.get("blocked", "unknown"),
                "xfail": counts.get("xfail", "unknown"),
                "summary_path": item.get("summary_path", item.get("details", "-")),
            }
        )
    return rows


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
            "Runtime Smoke Status",
            runtime_smoke_rows(snapshot),
            [
                ("Command", "command"),
                ("Status", "status"),
                ("Exit", "exit_code"),
                ("PASS", "pass"),
                ("FAIL", "fail"),
                ("BLOCKED", "blocked"),
                ("XFAIL", "xfail"),
                ("Evidence", "summary_path"),
            ],
        )
    )
    lines.extend(render_connector_runtime_availability(snapshot))
    lines.extend(["", "## Runtime FAIL Details"])
    lines.extend(render_connector_runtime_fail_details(snapshot, "apache", heading_level=3))
    lines.extend(render_connector_runtime_fail_details(snapshot, "nginx", heading_level=3))
    lines.extend(["", "## HAProxy Runtime Matrix Details"])
    lines.extend(render_haproxy_compact_runtime_details(snapshot, heading_level=3))
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
    apache_smoke_counts = runtime_smokes.get("apache", {}).get("counts", {})
    nginx_smoke_counts = runtime_smokes.get("nginx", {}).get("counts", {})
    haproxy_smoke_counts = runtime_smokes.get("haproxy", {}).get("counts", {})
    if not isinstance(apache_smoke_counts, dict):
        apache_smoke_counts = {}
    if not isinstance(nginx_smoke_counts, dict):
        nginx_smoke_counts = {}
    if not isinstance(haproxy_smoke_counts, dict):
        haproxy_smoke_counts = {}
    apache_attempted = runtime_attempted_count(runtime_snapshot, "apache")
    nginx_attempted = runtime_attempted_count(runtime_snapshot, "nginx")
    haproxy_attempted = runtime_attempted_count(runtime_snapshot, "haproxy")
    runtime_executable_count = sum(1 for row in rt_rows if row["runtime_executable"] == "yes")
    force_all_executable_count = sum(1 for row in rt_rows if row["force_all_executable"] == "yes")

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
        f"- XFAIL cases: **{metrics['xfail']}**",
        f"- Pending runtime verification (`runtime_verified=false`): **{metrics['pending_false']}**",
        f"- Pending runtime verification (`runtime_verified=unknown`): **{metrics['pending_unknown']}**",
        f"- Connector-gap cases: **{metrics['connector_gap']}**",
        f"- Runtime-difference cases: **{metrics['runtime_difference']}**",
        f"- Future/experimental cases: **{metrics['future_experimental']}**",
        f"- RESPONSE_BODY cases: **{metrics['response_body']}**",
        f"- Default runtime-executable YAML cases: **{runtime_executable_count}**",
        f"- Force-all runtime-executable YAML cases: **{force_all_executable_count}**",
        f"- Apache attempted YAML cases in latest runtime snapshot: **{apache_attempted}**",
        f"- NGINX attempted YAML cases in latest runtime snapshot: **{nginx_attempted}**",
        f"- HAProxy attempted YAML cases in latest runtime snapshot: **{haproxy_attempted}**",
        f"- Mapped-only import inventory entries: **{mapped_only_count}**",
        "",
        "**RESPONSE_BODY is not verified or promoted.** This file is generated reporting, not runtime proof.",
        "",
        "## Framework Integration",
        f"- This framework-owned file is the source of truth for root coverage reporting: `{ROOT_SUMMARY_FILENAME}` in `ModSecurity-test-Framework`.",
        "- Connector repositories should link to this Framework summary instead of maintaining their own root coverage summary.",
        "- Shared YAML cases, runners, normalizers, generators, and detailed testing documentation are owned by `ModSecurity-test-Framework`.",
        "- The connector repository owns connector source, harnesses, adapter metadata, `config/testing/import-status.json`, and connector-specific generated evidence under `reports/testing/`.",
        "- `FRAMEWORK_ROOT` and `CONNECTOR_ROOT` are explicit integration paths; there is no absolute workspace fallback.",
        "",
        "## Case Types",
        f"- Common YAML cases: **{by_scope.get('common', 0)}**",
        f"- Apache-specific YAML cases: **{by_scope.get('apache', 0)}**",
        f"- NGINX-specific YAML cases: **{by_scope.get('nginx', 0)}**",
        f"- XFAIL cases: **{metrics['xfail']}**",
        f"- Mapped-only import inventory entries: **{mapped_only_count}** (not counted as runnable YAML cases)",
        f"- Runtime-blocked import inventory entries: **{runtime_blocked_count}** (environment/harness blockers, not PASS or XFAIL promotions)",
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
            f"- Apache attempted YAML cases from latest summary: **{apache_attempted}**",
            f"- NGINX attempted YAML cases from latest summary: **{nginx_attempted}**",
            f"- HAProxy attempted YAML cases from latest summary: **{haproxy_attempted}**",
            f"- Apache raw runtime XFAIL observations from latest summary: **{apache_smoke_counts.get('xfail', 0)}**",
            f"- NGINX raw runtime XFAIL observations from latest summary: **{nginx_smoke_counts.get('xfail', 0)}**",
            f"- HAProxy raw runtime XFAIL observations from latest summary: **{haproxy_smoke_counts.get('xfail', 0)}**",
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
            "- PASS/BLOCKED/FAIL counts here come only from tracked runtime snapshot evidence; XFAIL and pending cases are not promoted.",
            "- RESPONSE_BODY remains non-verified even when a pass-through runtime case returns HTTP 200.",
        ]
    )
    lines.extend(render_runtime_snapshot(runtime_snapshot))
    lines.extend(render_new_connector_smoke_evidence(runtime_snapshot))
    lines.extend(
        [
            "",
            "## Open Areas / Gaps",
            "- Runtime verification pending: cases with `runtime_verified=false` or `runtime_verified=unknown` are not runtime PASS proof.",
            "- RESPONSE_BODY remains non-verified and non-promoted.",
            "- GitHub/Codex checks are intentionally lightweight and do not prove runtime compatibility.",
            "- XFAIL, pending, future, connector-gap, and runtime-difference cases require local runtime evidence before any status change.",
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
            "XFAIL, pending, future, and gap cases need local runtime validation before promotion.",
            "`make smoke-all` is authoritative only if it was actually executed successfully.",
            "No PASS numbers are inferred from this file when `make smoke-all` was not run successfully.",
            "No RESPONSE_BODY promotion is made without stable full-smoke runtime evidence.",
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
    connector_gap_count = sum(1 for case in cases if "connector-gap" in case["tags"] or case["status"] == "connector-gap")
    runtime_diff_count = sum(1 for case in cases if "runtime-difference" in case["tags"] or case["status"] == "runtime-difference")
    future_exp_count = sum(1 for case in cases if "future" in case["tags"] or "experimental" in case["tags"] or case["status"] in {"future", "experimental"})
    rt_rows = runtime_rows(cases, runtime_snapshot)
    apache_runtime_counts = runtime_status_counts(rt_rows, "apache")
    nginx_runtime_counts = runtime_status_counts(rt_rows, "nginx")
    haproxy_runtime_counts = runtime_status_counts(rt_rows, "haproxy")
    mapped_only = import_status.get("mapped_only", [])
    mapped_only_count = len(mapped_only) if isinstance(mapped_only, list) else 0
    apache_attempted = runtime_attempted_count(runtime_snapshot, "apache")
    nginx_attempted = runtime_attempted_count(runtime_snapshot, "nginx")
    haproxy_attempted = runtime_attempted_count(runtime_snapshot, "haproxy")
    runtime_executable_count = sum(1 for row in rt_rows if row["runtime_executable"] == "yes")
    force_all_executable_count = sum(1 for row in rt_rows if row["force_all_executable"] == "yes")

    lines = [
        "# ModSecurity Connector Test Coverage Overview",
        "",
        "## Summary",
        f"- Total cases: **{len(cases)}**",
        f"- Verified/pass count (`runtime_verified=true`): **{by_runtime.get('true', 0)}**",
        f"- XFAIL count: **{by_status.get('xfail', 0)}**",
        f"- Pending runtime verification count: **{by_runtime.get('false', 0)}**",
        f"- Connector-gap count: **{connector_gap_count}**",
        f"- Runtime-difference count: **{runtime_diff_count}**",
        f"- Future/experimental count: **{future_exp_count}**",
        f"- RESPONSE_BODY cases: **{response_body_count}** (still **not verified/promoted**)",
        f"- Mapped-only import inventory entries: **{mapped_only_count}**",
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
            f"- Apache attempted YAML cases from latest summary: **{apache_attempted}**",
            f"- NGINX attempted YAML cases from latest summary: **{nginx_attempted}**",
            f"- HAProxy attempted YAML cases from latest summary: **{haproxy_attempted}**",
            *render_runtime_status_count_table(apache_runtime_counts, nginx_runtime_counts, haproxy_runtime_counts, mapped_only_count),
            f"- Details: `{report_doc('generated/runtime-matrix.generated.md')}`",
            f"- HAProxy per-case results: `{report_doc('generated/haproxy-runtime-results.generated.md')}`",
        ]
    )
    lines.extend(render_runtime_snapshot(runtime_snapshot))
    lines.extend(
        [
            "",
            "## Open Gaps",
            f"- See `{report_doc('generated/connector-gap-summary.generated.md')}` for detailed entries.",
            "",
            "## Verified Runtime Coverage",
            "- Runtime-verified means only cases explicitly classified as `runtime_verified=true`.",
            "",
            "## Pending Runtime Verification",
            "- Cases with `runtime_verified=false` or `runtime_verified=unknown` are not runtime PASS proof.",
            "",
            "## XFAIL / Known Gap Coverage",
            "- XFAIL, pending, future, and experimental cases are listed in the XFAIL summary.",
            "- XFAIL, pending, and gap cases need local runtime validation before promotion.",
            "",
            "## Connector Gap / Runtime Difference Coverage",
            "- Connector-gap and runtime-difference classes are reported separately.",
            "",
            "## Phase 3/4 Outbound Coverage",
            f"- Phase 3/4 cases are visible in `{report_doc('generated/phase-coverage.generated.md')}` and in the runtime matrix.",
            "",
            "## RESPONSE_BODY Status",
            "- RESPONSE_BODY remains not verified and not promoted.",
            "",
            "## Cloud / Quick / Full Smoke Meaning",
            "- Generated coverage is not runtime evidence by itself.",
            "- Full runtime validation is local and evidence-based.",
            "- GitHub/Codex checks are intentionally lightweight.",
            "- XFAIL, pending, and gap cases need local runtime validation.",
            "- `make smoke-all` is authoritative only if it was actually executed successfully.",
            "",
            "## Generated Artifacts",
            f"- `{report_doc('generated/case-matrix.generated.md')}`",
            f"- `{report_doc('generated/coverage-summary.generated.md')}`",
            f"- `{report_doc('generated/xfail-summary.generated.md')}`",
            f"- `{report_doc('generated/connector-gap-summary.generated.md')}`",
            f"- `{report_doc('generated/phase-coverage.generated.md')}`",
            "",
            "## Note",
            "- Generated summaries do not replace full-smoke runtime evidence.",
            "- No RESPONSE_BODY promotion is made without stable runtime evidence.",
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
    report_layout.write_generated("xfail-summary.generated.md", render_xfail(cases))
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
