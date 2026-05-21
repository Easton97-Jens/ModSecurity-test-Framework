#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
import argparse
from collections import Counter
from pathlib import Path

import yaml

FRAMEWORK_ROOT = Path(__file__).resolve().parents[1]
CONNECTOR_ROOT = Path.cwd()
OUTPUT_ROOT = CONNECTOR_ROOT
IMPORT_STATUS = CONNECTOR_ROOT / "tests/import-status.json"
RUNTIME_SNAPSHOT = OUTPUT_ROOT / "docs/testing/runtime-validation-snapshot.json"
OUT = OUTPUT_ROOT / "docs/testing/generated"

RULE_RE = re.compile(r'^\s*SecRule\s+([^\s]+)\s+"(@[^\s"]+)')
PHASE_RE = re.compile(r"phase:(\d)")
# \w keeps transformation tokens concise; current test corpus uses ASCII-style names.
TRANS_RE = re.compile(r"t:(\w+)")
GAP_TAG_RE = re.compile(r"(connector[_-]?gap|runtime[_-]?difference|future|experimental|pending|mapped[_-]?only)", re.I)
TABLE_SEPARATOR_2COL = "|---|---|"

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
    "make smoke-apache",
    "make smoke-nginx",
    "make smoke-all",
    "make generate-test-matrix",
    "make check-test-matrix",
]

MATRIX_STATUS_ORDER = [
    "PASS",
    "FAIL",
    "BLOCKED",
    "XFAIL_PASS",
    "XFAIL_FAIL",
    "PENDING_PASS",
    "PENDING_FAIL",
    "FUTURE_PASS",
    "FUTURE_FAIL",
    "CONNECTOR_GAP_PASS",
    "CONNECTOR_GAP_FAIL",
    "RUNTIME_DIFFERENCE_PASS",
    "RUNTIME_DIFFERENCE_FAIL",
    "NOT_EXECUTABLE",
    "MAPPED_ONLY",
    "NOT EXECUTED",
]

ROOT_DETAIL_DOCS = [
    "docs/testing/test-coverage-overview.md",
    "docs/testing/generated/case-matrix.generated.md",
    "docs/testing/generated/coverage-summary.generated.md",
    "docs/testing/generated/xfail-summary.generated.md",
    "docs/testing/generated/connector-gap-summary.generated.md",
    "docs/testing/generated/phase-coverage.generated.md",
    "docs/testing/generated/runtime-matrix.generated.md",
    "docs/testing/generated/apache-runtime-results.generated.md",
    "docs/testing/generated/nginx-runtime-results.generated.md",
    "docs/testing/runtime-validation-snapshot.json",
    "docs/testing/nginx-runtime-failure-classification.md",
    "docs/testing/response-body-blocking-investigation.md",
    "docs/testing/compatibility.md",
]


def warn(message: str) -> None:
    print(f"[matrix-generator] WARN: {message}", file=sys.stderr)


def configure_paths(framework_root: str | Path | None, connector_root: str | Path | None, output_root: str | Path | None) -> None:
    global FRAMEWORK_ROOT, CONNECTOR_ROOT, OUTPUT_ROOT, IMPORT_STATUS, RUNTIME_SNAPSHOT, OUT
    if framework_root is not None:
        FRAMEWORK_ROOT = Path(framework_root).resolve()
    if connector_root is not None:
        CONNECTOR_ROOT = Path(connector_root).resolve()
    else:
        CONNECTOR_ROOT = FRAMEWORK_ROOT
    OUTPUT_ROOT = Path(output_root).resolve() if output_root is not None else CONNECTOR_ROOT
    IMPORT_STATUS = CONNECTOR_ROOT / "tests/import-status.json"
    RUNTIME_SNAPSHOT = OUTPUT_ROOT / "docs/testing/runtime-validation-snapshot.json"
    OUT = OUTPUT_ROOT / "docs/testing/generated"


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
    if "/tests/common/" in s:
        return "common"
    if "/tests/apache/" in s:
        return "apache"
    if "/tests/nginx/" in s:
        return "nginx"
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
    status = str(data.get("status", "unknown") or "unknown").strip().lower()
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
    status, category, notes, source, caps = extract_status_metadata(data)
    tags = extract_gap_tags(path, status, category, notes, source)

    response_body = bool(caps.get("response_body", False)) or any("RESPONSE_BODY" in var for var in variables)
    if not phases:
        warn(f"no phase metadata found in {path}")

    return {
        "id": str(data.get("name", path.stem) or path.stem),
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
    files = []
    files.extend(sorted((FRAMEWORK_ROOT / "tests" / "common" / "cases").rglob("*.yaml")))
    for scope in ["apache", "nginx"]:
        files.extend(sorted((CONNECTOR_ROOT / "tests" / scope / "cases").rglob("*.yaml")))
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


def write(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("Generated file — do not edit manually.\n\n" + body.rstrip() + "\n", encoding="utf-8")


def render_case_matrix(cases: list[dict]) -> str:
    rows = ["# Generated Case Matrix", "", "| case_id | path | scope | phase | variables | operators | transformations | status | runtime_verified | notes |", "|---|---|---|---|---|---|---|---|---|---|"]
    for case in cases:
        rows.append(
            f"| {case['id']} | `{case['path']}` | {case['scope']} | {','.join(map(str, case['phases'])) or '-'} | "
            f"{', '.join(case['variables']) or '-'} | {', '.join(case['operators']) or '-'} | "
            f"{', '.join(case['transformations']) or '-'} | {case['status']} | {case['runtime_verified']} | {case['notes']} |"
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
    lines.extend(["", "## Verification note", "- Generated summaries are reporting only and do not replace full runtime evidence from `make smoke-all`.", "- RESPONSE_BODY remains non-verified/non-promoted until stable full-smoke runtime evidence exists."])
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
                rows.append(f"| {item.get('case') or item.get('source') or 'unknown'} | `tests/import-status.json` | {key} | - | - | {item.get('source', 'unknown')} | {item.get('reason', '')} |")
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
    parts = Path(case["path"]).parts
    try:
        index = parts.index("cases")
    except ValueError:
        return "unknown"
    if index + 1 < len(parts):
        return parts[index + 1]
    return "unknown"


def runtime_summary_by_connector(snapshot: dict) -> dict[str, dict]:
    by_connector: dict[str, dict] = {}
    for item in snapshot.get("runtime_smokes", []):
        if not isinstance(item, dict):
            continue
        connector = str(item.get("connector", "")).strip()
        if connector in {"apache", "nginx"}:
            by_connector[connector] = item
    return by_connector


def runtime_results_by_connector(snapshot: dict) -> dict[str, dict[str, dict]]:
    results: dict[str, dict[str, dict]] = {"apache": {}, "nginx": {}}
    for connector, smoke in runtime_summary_by_connector(snapshot).items():
        raw_cases = smoke.get("cases", [])
        if not isinstance(raw_cases, list):
            continue
        for item in raw_cases:
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
    return case_group(case) in {"minimal", "imported", "v2-imported", "v3-imported"}


def is_xfail_case(case: dict) -> bool:
    return case["status"] == "xfail" or case_group(case) == "xfail"


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
        return "NOT EXECUTED"
    if value in {"not_run", "not-run"}:
        return "NOT EXECUTED"
    return "NOT EXECUTED"


def semantic_matrix_status(raw_status: str, classification: str) -> str:
    status = raw_status.strip().lower()
    if status == "blocked":
        return "BLOCKED"
    if status == "skipped":
        return "NOT_EXECUTABLE"
    if status == "xfail":
        return "XFAIL_FAIL"
    if status not in {"pass", "fail"}:
        return status.upper() if status else "UNKNOWN"
    suffix = "PASS" if status == "pass" else "FAIL"
    if classification == "active":
        return suffix
    if classification == "connector_gap":
        return f"CONNECTOR_GAP_{suffix}"
    if classification == "runtime_difference":
        return f"RUNTIME_DIFFERENCE_{suffix}"
    if classification == "pending":
        return f"PENDING_{suffix}"
    if classification == "future":
        return f"FUTURE_{suffix}"
    return f"XFAIL_{suffix}"


def runtime_executable_for_snapshot(case: dict, connector: str, snapshot: dict) -> bool:
    if not connector_applies(case, connector):
        return False
    executable_groups = {"minimal", "imported", "v2-imported", "v3-imported"}
    if is_force_all_snapshot(snapshot):
        executable_groups.add("xfail")
    return case_group(case) in executable_groups


def runtime_cell(case: dict, connector: str, snapshot: dict) -> dict[str, str]:
    if not connector_applies(case, connector):
        return {
            "status": "NOT_EXECUTABLE",
            "reason": f"{case['scope']}-specific case is not applicable to {connector}",
            "evidence": "-",
        }
    if is_xfail_case(case) and not is_force_all_snapshot(snapshot):
        return {
            "status": "NOT EXECUTED",
            "reason": "YAML case is xfail/pending/future inventory and is not part of the default runtime smoke discovery",
            "evidence": "metadata only; no PASS promotion",
        }
    if not runtime_executable_for_snapshot(case, connector, snapshot):
        return {
            "status": "NOT_EXECUTABLE",
            "reason": f"case group `{case_group(case)}` is outside active runtime smoke discovery",
            "evidence": "-",
        }

    results = runtime_results_by_connector(snapshot)
    observed = results.get(connector, {}).get(case["id"])
    if observed:
        status = str(observed.get("matrix_status") or semantic_matrix_status(str(observed.get("status", "")), runtime_classification(case)))
        if status in {"NOT EXECUTED", "NOT_EXECUTABLE"}:
            reason = str(observed.get("reason") or observed.get("details") or "skipped by runtime smoke")
        else:
            classification = observed.get("runtime_classification", runtime_classification(case))
            reason = str(observed.get("reason") or f"runtime summary result; classification={classification}")
        expected = observed.get("expected_status", observed.get("expected", "unknown"))
        actual = observed.get("actual_status", observed.get("actual", "unknown"))
        evidence = str(observed.get("evidence") or f"expected={expected}; actual={actual}")
        return {"status": status, "reason": reason, "evidence": evidence}

    smoke = runtime_summary_by_connector(snapshot).get(connector, {})
    smoke_status = status_label(smoke.get("status"))
    if smoke_status in {"FAIL", "BLOCKED"} and not smoke.get("cases"):
        return {
            "status": smoke_status,
            "reason": str(smoke.get("details") or f"{connector} smoke did not produce per-case results"),
            "evidence": str(smoke.get("summary_path", "-")),
        }
    return {
        "status": "NOT_EXECUTABLE" if is_force_all_snapshot(snapshot) else "NOT EXECUTED",
        "reason": f"no {connector} runtime evidence recorded for this executable YAML case",
        "evidence": str(smoke.get("summary_path", "no summary path recorded")),
    }


def runtime_rows(cases: list[dict], snapshot: dict) -> list[dict[str, str]]:
    rows = []
    for case in cases:
        apache = runtime_cell(case, "apache", snapshot)
        nginx = runtime_cell(case, "nginx", snapshot)
        rows.append(
            {
                "case_id": case["id"],
                "path": case["path"],
                "scope": case["scope"],
                "group": case_group(case),
                "yaml_status": case["status"],
                "runtime_executable": "yes" if runtime_executable(case, "apache") or runtime_executable(case, "nginx") else "no",
                "force_all_executable": "yes"
                if runtime_executable_for_snapshot(case, "apache", {"force_all_cases": True})
                or runtime_executable_for_snapshot(case, "nginx", {"force_all_cases": True})
                else "no",
                "apache_status": apache["status"],
                "apache_reason": apache["reason"],
                "apache_evidence": apache["evidence"],
                "nginx_status": nginx["status"],
                "nginx_reason": nginx["reason"],
                "nginx_evidence": nginx["evidence"],
            }
        )
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
    cases = smoke.get("cases", [])
    return len(cases) if isinstance(cases, list) else 0


def render_runtime_status_count_table(
    apache_counts: Counter,
    nginx_counts: Counter,
    mapped_only_count: int = 0,
) -> list[str]:
    statuses = ordered_runtime_statuses(apache_counts, nginx_counts)
    if mapped_only_count and "MAPPED_ONLY" not in statuses:
        statuses.append("MAPPED_ONLY")
    lines = ["| Status | Apache | NGINX |", "|---|---:|---:|"]
    for status in statuses:
        if status == "MAPPED_ONLY":
            lines.append(f"| {status} | {mapped_only_count} | {mapped_only_count} |")
        else:
            lines.append(f"| {status} | {apache_counts.get(status, 0)} | {nginx_counts.get(status, 0)} |")
    return lines


def render_runtime_matrix(cases: list[dict], import_status: dict, snapshot: dict) -> str:
    rows = runtime_rows(cases, snapshot)
    apache_counts = runtime_status_counts(rows, "apache")
    nginx_counts = runtime_status_counts(rows, "nginx")
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
        f"- mapped-only import inventory entries: **{len(mapped_only)}**",
        "- `NOT_EXECUTABLE` means the YAML case is not applicable to that connector or the runner cannot execute that case group for that connector.",
        "- `NOT EXECUTED` means no runtime case evidence is recorded in a non-force/default snapshot.",
        "- `MAPPED_ONLY` entries are import inventory items, not runnable YAML case files.",
        "",
        "## Status Counts",
        *render_runtime_status_count_table(apache_counts, nginx_counts, len(mapped_only)),
        "",
        "## YAML Runtime Matrix",
        "| case_id | path | scope | group | YAML status | default executable | force-all executable | Apache | Apache reason | Apache evidence | NGINX | NGINX reason | NGINX evidence |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|",
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
                    "group",
                    "yaml_status",
                    "runtime_executable",
                    "force_all_executable",
                    "apache_status",
                    "apache_reason",
                    "apache_evidence",
                    "nginx_status",
                    "nginx_reason",
                    "nginx_evidence",
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
    connector_name = "NGINX" if connector == "nginx" else connector.title()
    lines = [
        f"# Generated {connector_name} Runtime Results",
        "",
        f"- Command: `{smoke.get('command', 'unknown')}`",
        f"- Status: **{smoke.get('status', 'unknown')}**",
        f"- Exit code: `{smoke.get('exit_code', 'unknown')}`",
        f"- Summary evidence: `{smoke.get('summary_path', 'unknown')}`",
        f"- Attempted YAML cases in latest snapshot: **{runtime_attempted_count(snapshot, connector)}**",
        "- Runtime evidence is current local snapshot evidence only; it is not xfail/pending promotion.",
        "- RESPONSE_BODY remains non-verified/non-promoted.",
        "",
        "## Counts",
        "| Status | Count |",
        "|---|---:|",
    ]
    for status in ordered_runtime_statuses(counts):
        lines.append(f"| {status} | {counts.get(status, 0)} |")
    lines.extend(
        [
            "",
            "## Results",
            "| case_id | path | YAML status | runtime status | reason | evidence |",
            "|---|---|---|---|---|---|",
        ]
    )
    for row in rows:
        lines.append(
            f"| {md(row['case_id'])} | {md(row['path'])} | {md(row['yaml_status'])} | "
            f"{md(row[f'{connector}_status'])} | {md(row[f'{connector}_reason'])} | {md(row[f'{connector}_evidence'])} |"
        )
    return "\n".join(lines)


def render_runtime_snapshot(snapshot: dict) -> list[str]:
    if not snapshot:
        return [
            "",
            "## Latest Local Runtime Validation Snapshot",
            "- No local runtime snapshot is recorded in `docs/testing/runtime-validation-snapshot.json`.",
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
    notes = snapshot.get("notes", [])
    if isinstance(notes, list) and notes:
        lines.extend(f"- {note}" for note in notes)

    framework_rows = snapshot.get("framework_checks", [])
    if isinstance(framework_rows, list):
        lines.extend(
            render_status_table(
                "Framework Check Status",
                framework_rows,
                [("Command", "command"), ("Status", "status"), ("Details", "details")],
            )
        )

    readiness_rows = snapshot.get("readiness_checks", [])
    if isinstance(readiness_rows, list):
        lines.extend(
            render_status_table(
                "Readiness / Fetch Status",
                readiness_rows,
                [("Command", "command"), ("Status", "status"), ("Details", "details")],
            )
        )

    smoke_rows = []
    for item in snapshot.get("runtime_smokes", []):
        if not isinstance(item, dict):
            continue
        counts = item.get("counts") if isinstance(item.get("counts"), dict) else {}
        smoke_rows.append(
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
    lines.extend(
        render_status_table(
            "Runtime Smoke Status",
            smoke_rows,
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

    failed_rows = []
    for item in snapshot.get("runtime_smokes", []):
        if not isinstance(item, dict):
            continue
        connector = item.get("connector", item.get("command", "-"))
        for failed in item.get("failed_cases", []):
            if not isinstance(failed, dict):
                continue
            failed_rows.append(
                {
                    "connector": connector,
                    "case": failed.get("case", "-"),
                    "expected": failed.get("expected", "-"),
                    "actual": failed.get("actual", "-"),
                    "assessment": failed.get("assessment", "-"),
                }
            )
    lines.extend(
        render_status_table(
            "Runtime FAIL Details",
            failed_rows,
            [
                ("Connector", "connector"),
                ("Case", "case"),
                ("Expected", "expected"),
                ("Actual", "actual"),
                ("Assessment", "assessment"),
            ],
        )
    )

    verification = snapshot.get("runtime_verified_status", [])
    if isinstance(verification, list) and verification:
        lines.extend(["", "## Runtime Verified Status"])
        lines.extend(f"- {entry}" for entry in verification)

    open_issues = snapshot.get("open_issues", [])
    if isinstance(open_issues, list) and open_issues:
        lines.extend(["", "## Offene Runtime-Probleme"])
        lines.extend(f"- {issue}" for issue in open_issues)

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
    runtime_smokes = runtime_summary_by_connector(runtime_snapshot)
    apache_smoke_counts = runtime_smokes.get("apache", {}).get("counts", {})
    nginx_smoke_counts = runtime_smokes.get("nginx", {}).get("counts", {})
    if not isinstance(apache_smoke_counts, dict):
        apache_smoke_counts = {}
    if not isinstance(nginx_smoke_counts, dict):
        nginx_smoke_counts = {}
    apache_attempted = runtime_attempted_count(runtime_snapshot, "apache")
    nginx_attempted = runtime_attempted_count(runtime_snapshot, "nginx")
    runtime_executable_count = sum(1 for row in rt_rows if row["runtime_executable"] == "yes")
    force_all_executable_count = sum(1 for row in rt_rows if row["force_all_executable"] == "yes")

    lines = [
        "# ModSecurity Connector Test Coverage Summary",
        "",
        "## Kurzstatus",
        f"- Gesamtzahl aller YAML Cases: **{metrics['total']}**",
        f"- verified/pass (`runtime_verified=true`): **{metrics['verified']}**",
        f"- xfail: **{metrics['xfail']}**",
        f"- pending-runtime-verification (`runtime_verified=false`): **{metrics['pending_false']}**",
        f"- pending-runtime-verification (`runtime_verified=unknown`): **{metrics['pending_unknown']}**",
        f"- connector-gap: **{metrics['connector_gap']}**",
        f"- runtime-difference: **{metrics['runtime_difference']}**",
        f"- future/experimental: **{metrics['future_experimental']}**",
        f"- RESPONSE_BODY Cases: **{metrics['response_body']}**",
        f"- default runtime-executable YAML Cases: **{runtime_executable_count}**",
        f"- force-all runtime-executable YAML Cases: **{force_all_executable_count}**",
        f"- Apache attempted YAML Cases in latest runtime snapshot: **{apache_attempted}**",
        f"- NGINX attempted YAML Cases in latest runtime snapshot: **{nginx_attempted}**",
        f"- mapped-only import inventory entries: **{mapped_only_count}**",
        "",
        "**RESPONSE_BODY ist nicht verified/promoted.** Diese Datei ist generiertes Reporting und keine Runtime-Evidenz.",
        "",
        "## Framework Integration",
        "- Framework root used for shared cases/tools: `FRAMEWORK_ROOT`.",
        "- Connector root used for adapter inventory/reports: `CONNECTOR_ROOT`.",
        "- Common YAML cases, runners, normalizers, and generators are owned by `ModSecurity-test-Framework`.",
        "- Connector-specific cases, adapter metadata, harnesses, import status, and generated reports are owned by this connector repository.",
        "- `FRAMEWORK_ROOT` is configurable; the sibling checkout is only a relative local convenience, not an absolute workspace fallback.",
        "",
        "## Testarten",
        f"- Common YAML Cases: **{by_scope.get('common', 0)}**",
        f"- Apache-specific Cases: **{by_scope.get('apache', 0)}**",
        f"- NGINX-specific Cases: **{by_scope.get('nginx', 0)}**",
        f"- xfail Cases: **{metrics['xfail']}**",
        f"- mapped-only import inventory entries: **{mapped_only_count}** (nicht als runnable YAML Cases gezählt)",
        f"- runtime-blocked import inventory entries: **{runtime_blocked_count}** (belegte Harness-/Umgebungsblocker, keine PASS- oder XFAIL-Promotion)",
        f"- pending/future compatibility Cases: **{metrics['future_experimental']}** future/experimental; "
        f"**{metrics['pending_false'] + metrics['pending_unknown']}** nicht runtime-verified",
        "",
        "## Statusklassen",
        "| Status | Count |",
        "|---|---:|",
    ]
    lines.extend(f"| {status} | {count} |" for status, count in sorted(by_status.items()))
    lines.extend(["", "## Scope", "| Scope | Count |", "|---|---:|"])
    lines.extend(f"| {scope} | {by_scope.get(scope, 0)} |" for scope in ["common", "apache", "nginx", "unknown"])
    lines.extend(["", "## Coverage nach Variablen/Collections", "| Variable / Collection | Count |", "|---|---:|"])
    lines.extend(f"| `{name}` | {collection_counts.get(name, 0)} |" for name in ROOT_COLLECTIONS)
    lines.extend(["", "## Coverage nach Phase", "| Phase | Count |", "|---|---:|"])
    lines.extend(f"| Phase {phase} | {by_phase.get(phase, 0)} |" for phase in [1, 2, 3, 4])
    lines.extend(["", "## Coverage nach Themen", "| Topic | Count |", "|---|---:|"])
    lines.extend(f"| {topic} | {count} |" for topic, count in topics.items())
    lines.extend(
        [
            "",
            "## Runtime Matrix Status",
            *render_runtime_status_count_table(apache_runtime_counts, nginx_runtime_counts, mapped_only_count),
            "",
            f"- Apache attempted YAML cases from latest summary: **{apache_attempted}**",
            f"- NGINX attempted YAML cases from latest summary: **{nginx_attempted}**",
            f"- Apache raw runtime XFAIL observations from latest summary: **{apache_smoke_counts.get('xfail', 0)}**",
            f"- NGINX raw runtime XFAIL observations from latest summary: **{nginx_smoke_counts.get('xfail', 0)}**",
            f"- Apache NOT EXECUTED YAML rows: **{apache_runtime_counts.get('NOT EXECUTED', 0)}**",
            f"- NGINX NOT EXECUTED YAML rows: **{nginx_runtime_counts.get('NOT EXECUTED', 0)}**",
            f"- Apache NOT_EXECUTABLE YAML rows: **{apache_runtime_counts.get('NOT_EXECUTABLE', 0)}**",
            f"- NGINX NOT_EXECUTABLE YAML rows: **{nginx_runtime_counts.get('NOT_EXECUTABLE', 0)}**",
            f"- mapped-only import inventory entries: **{mapped_only_count}**",
            "- Runtime Matrix Detail: `docs/testing/generated/runtime-matrix.generated.md`",
            "- Apache per-case results: `docs/testing/generated/apache-runtime-results.generated.md`",
            "- NGINX per-case results: `docs/testing/generated/nginx-runtime-results.generated.md`",
            "- PASS/BLOCKED/FAIL counts here come only from tracked runtime snapshot evidence; xfail/pending cases are not promoted.",
            "- RESPONSE_BODY remains non-verified even when a pass-through runtime case returns HTTP 200.",
        ]
    )
    lines.extend(render_runtime_snapshot(runtime_snapshot))
    lines.extend(
        [
            "",
            "## Offene Bereiche / Gaps",
            "- Runtime verification pending: Cases mit `runtime_verified=false` oder `runtime_verified=unknown` sind nicht als Runtime-PASS zu lesen.",
            "- RESPONSE_BODY non-verified: RESPONSE_BODY bleibt nicht promoted, auch wenn Reporting Cases erfasst.",
            "- GitHub/Codex checks sind absichtlich leichtgewichtig und liefern keine Runtime-Kompatibilitaetsbeweise.",
            "- XFAIL/Pending/Gaps brauchen lokale Runtime-Validierung vor einer Promotion.",
            "- Runtime-blocked Import-Einträge sind belegte Harness-/Umgebungsblocker und keine Connector-Gap- oder Runtime-Difference-Promotion.",
            "- `installed-readiness` ist Komponenten-Erkennung/Readiness, keine Runtime-Ausführung.",
            "- Es gibt keinen separaten Artefakt-Reuse-Smoke-Pfad; Runtime-Validierung erfolgt per frischem Source-Build.",
            "- `make smoke-all` bleibt die autoritative Quelle für echte Runtime-PASS-Zahlen.",
            "",
            "## Kommandos",
        ]
    )
    lines.extend(f"- `{command}`" for command in ROOT_COMMANDS)
    lines.extend(["", "## Detaildokumente"])
    lines.extend(f"- `{doc}`" for doc in ROOT_DETAIL_DOCS)
    lines.extend(
        [
            "",
            "## Wichtiger Hinweis",
            "Generated coverage != runtime evidence.",
            "Full runtime validation is local.",
            "GitHub/Codex checks are intentionally lightweight.",
            "XFAIL/pending/gap cases need local runtime validation.",
            "Die generierte Coverage-Dokumentation ist Reporting. Sie ersetzt keine Runtime-Evidenz.",
            "Full runtime validation ist lokal; GitHub/Codex checks sind absichtlich leichtgewichtig.",
            "XFAIL/Pending/Gaps brauchen lokale Runtime-Validierung vor einer Promotion.",
            "`make smoke-all` bleibt die autoritative Quelle für echte PASS-Zahlen.",
            "Keine PASS-Zahlen werden aus dieser Datei abgeleitet, wenn `make smoke-all` nicht vollständig lief.",
            "Keine RESPONSE_BODY-Promotion ohne stabile Full-Smoke-Runtime-Evidenz.",
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
    mapped_only = import_status.get("mapped_only", [])
    mapped_only_count = len(mapped_only) if isinstance(mapped_only, list) else 0
    apache_attempted = runtime_attempted_count(runtime_snapshot, "apache")
    nginx_attempted = runtime_attempted_count(runtime_snapshot, "nginx")
    runtime_executable_count = sum(1 for row in rt_rows if row["runtime_executable"] == "yes")
    force_all_executable_count = sum(1 for row in rt_rows if row["force_all_executable"] == "yes")

    lines = ["# ModSecurity Connector Test Coverage Overview", "", "## Kurzzusammenfassung", f"- Gesamtzahl Cases: **{len(cases)}**", f"- verified/pass count (runtime_verified=true): **{by_runtime.get('true', 0)}**", f"- xfail count: **{by_status.get('xfail', 0)}**", f"- pending-runtime-verification count: **{by_runtime.get('false', 0)}**", f"- connector-gap count: **{connector_gap_count}**", f"- runtime-difference count: **{runtime_diff_count}**", f"- future/experimental count: **{future_exp_count}**", f"- RESPONSE_BODY cases: **{response_body_count}** (weiterhin **nicht verified/promoted**)", f"- mapped-only import inventory entries: **{mapped_only_count}**", "", "## Coverage nach Variable/Collection", "| Variable | Count |", "|---|---:|"]
    lines.extend(f"| `{k}` | {v} |" for k, v in by_var.most_common(20))
    lines.extend(["", "## Coverage nach Phase", "| Phase | Count |", "|---|---:|"])
    lines.extend(f"| {phase} | {by_phase.get(phase, 0)} |" for phase in [1, 2, 3, 4])
    lines.extend(["", "## Coverage nach Status", "| Status | Count |", "|---|---:|"])
    lines.extend(f"| {status} | {count} |" for status, count in sorted(by_status.items()))
    lines.extend(["", "## Coverage nach Scope", "| Scope | Count |", "|---|---:|"])
    lines.extend(f"| {scope} | {by_scope.get(scope, 0)} |" for scope in ["common", "apache", "nginx", "unknown"])
    lines.extend(
        [
            "",
            "## Runtime Matrix Status",
            f"- Default runtime-executable YAML cases: **{runtime_executable_count}**",
            f"- Force-all runtime-executable YAML cases: **{force_all_executable_count}**",
            f"- Apache attempted YAML cases from latest summary: **{apache_attempted}**",
            f"- NGINX attempted YAML cases from latest summary: **{nginx_attempted}**",
            *render_runtime_status_count_table(apache_runtime_counts, nginx_runtime_counts, mapped_only_count),
            "- Details: `docs/testing/generated/runtime-matrix.generated.md`",
        ]
    )
    lines.extend(render_runtime_snapshot(runtime_snapshot))
    lines.extend(["", "## Top offene Gaps", "- Siehe `docs/testing/generated/connector-gap-summary.generated.md` für detaillierte Einträge.", "", "## Verified Runtime Coverage", "- Runtime-verified ist nur das, was als `runtime_verified=true` klassifiziert ist.", "", "## Pending Runtime Verification", "- Fälle mit `runtime_verified=false/unknown` sind nicht als Runtime-PASS zu lesen.", "", "## XFAIL / Known Gap Coverage", "- XFAIL/Pending/Future/Experimental Fälle sind in der XFAIL-Summary gelistet.", "- XFAIL/Pending/Gaps brauchen lokale Runtime-Validierung vor einer Promotion.", "", "## Connector Gap / Runtime Difference Coverage", "- Connector-Gap und Runtime-Difference sind explizit separat ausgewiesen.", "", "## Phase 3/4 Outbound Coverage", "- Phase 3/4 Fälle sind in `phase-coverage.generated.md` und der Matrix enthalten.", "", "## RESPONSE_BODY Status", "- RESPONSE_BODY bleibt nicht verified/promoted.", "", "## Cloud/Quick/Full Smoke Bedeutung", "- Generated coverage != runtime evidence.", "- Full runtime validation is local.", "- GitHub/Codex checks are intentionally lightweight.", "- XFAIL/pending/gap cases need local runtime validation.", "- GitHub/Codex checks sind absichtlich leichtgewichtig und liefern keine Runtime-Kompatibilitaetsbeweise.", "- Full runtime validation ist lokal.", "- `make smoke-all` bleibt autoritativ für Runtime-Evidenz.", "", "## Generated Artefakte", "- `docs/testing/generated/case-matrix.generated.md`", "- `docs/testing/generated/coverage-summary.generated.md`", "- `docs/testing/generated/xfail-summary.generated.md`", "- `docs/testing/generated/connector-gap-summary.generated.md`", "- `docs/testing/generated/phase-coverage.generated.md`", "", "## Hinweis", "- Generated summaries ersetzen keine Full-Smoke Runtime-Evidenz.", "- Keine RESPONSE_BODY-Promotion ohne stabile Vollbelege."])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--framework-root", default=str(FRAMEWORK_ROOT))
    parser.add_argument("--connector-root", default=None)
    parser.add_argument("--output-root", default=None)
    args = parser.parse_args(argv)
    configure_paths(args.framework_root, args.connector_root, args.output_root)

    cases = gather_cases()
    import_status = load_import_status()
    runtime_snapshot = load_runtime_snapshot()

    by_scope = Counter(case["scope"] for case in cases)
    by_status = Counter(case["status"] for case in cases)
    by_runtime = Counter(case["runtime_verified"] for case in cases)
    by_phase = Counter(phase for case in cases for phase in case["phases"])
    by_var = Counter(var for case in cases for var in case["variables"])
    response_body_count = sum(1 for case in cases if case["response_body"])

    write(OUT / "case-matrix.generated.md", render_case_matrix(cases))
    write(OUT / "coverage-summary.generated.md", render_summary(cases, by_scope, by_status, by_runtime, by_phase, by_var, response_body_count))
    write(OUT / "xfail-summary.generated.md", render_xfail(cases))
    write(OUT / "connector-gap-summary.generated.md", render_gap_summary(cases, import_status))
    write(OUT / "phase-coverage.generated.md", render_phase_coverage(cases))
    write(OUT / "runtime-matrix.generated.md", render_runtime_matrix(cases, import_status, runtime_snapshot))
    write(OUT / "apache-runtime-results.generated.md", render_connector_runtime_results(cases, runtime_snapshot, "apache"))
    write(OUT / "nginx-runtime-results.generated.md", render_connector_runtime_results(cases, runtime_snapshot, "nginx"))
    write(
        OUTPUT_ROOT / "docs/testing/test-coverage-overview.md",
        render_overview(cases, import_status, runtime_snapshot, by_scope, by_status, by_runtime, by_phase, by_var, response_body_count),
    )
    write(OUTPUT_ROOT / "TEST-COVERAGE-SUMMARY.md", render_root_summary(cases, import_status, runtime_snapshot, by_scope, by_status, by_runtime, by_phase))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
