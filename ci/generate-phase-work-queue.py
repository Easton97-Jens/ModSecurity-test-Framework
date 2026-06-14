#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


CONNECTORS = ("apache", "nginx", "haproxy")
PHASES = ("1", "2", "3", "4")
STATUS_ORDER = ("PASS", "FAIL", "BLOCKED", "NOT_EXECUTABLE", "UNKNOWN")
PRIORITY_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
REPORT_ONLY_CLASSIFICATION = "with_mrts_detection_only_non_disruptive"
REPORT_ONLY_PRIORITY = "report_only"
PHASE_ROW_RE = re.compile(r"^\|\s*([1-4])\s*\|\s*(\d+)\s*\|\s*(.*?)\s*\|\s*(.*?)\s*\|\s*$")
COUNT_TOKEN_RE = re.compile(r"([^,()]+)\((\d+)\)")

PHASE_DESCRIPTIONS = {
    "1": {
        "title": "Phase 1 Work Queue",
        "focus": "action/intervention, request headers, request URI, cookies, and early blocking",
        "directions": [
            "intervention_blocking",
            "request_header_mapping",
            "request_uri_mapping",
            "collection_mapping",
            "audit_log_evidence",
        ],
        "goal": "Stabilize Phase 1 first because it avoids body and multipart complexity.",
    },
    "2": {
        "title": "Phase 2 Work Queue",
        "focus": "ARGS, ARGS_NAMES, REQUEST_BODY, JSON, XML, Multipart/FILES, operators, and transformations",
        "directions": [
            "intervention_blocking",
            "request_body_processor",
            "json_processor",
            "xml_processor",
            "multipart_files",
            "operator_semantics",
            "transformation_semantics",
            "request_routing",
        ],
        "goal": "Treat Phase 2 as the largest coverage lever, but split body/XML/multipart work into separate clusters.",
    },
    "3": {
        "title": "Phase 3 Work Queue",
        "focus": "RESPONSE_HEADERS, Set-Cookie, response-header hooks, and audit-log phase 3 evidence",
        "directions": [
            "response_header_hook",
            "response_header_mapping",
            "audit_log_evidence",
            "intervention_blocking",
        ],
        "goal": "Separate response-header hook/mapping work from request-side intervention issues.",
    },
    "4": {
        "title": "Phase 4 Work Queue",
        "focus": "RESPONSE_BODY, bounded phase 4 execution, strict abort behavior, and phase 4 logs",
        "directions": ["response_body_non_promoted"],
        "goal": "Keep Phase 4 visible but non-promoted unless real runtime evidence and project policy allow promotion.",
    },
}

PHASE2_SUBGROUPS = (
    ("args", "Phase 2 / ARGS and ARGS_NAMES", {"args", "args_names", "request_body_urlencoded"}),
    ("json", "Phase 2 / JSON", {"request_body_json"}),
    ("xml", "Phase 2 / XML", {"request_body_xml"}),
    ("multipart", "Phase 2 / Multipart and FILES", {"multipart_files"}),
    ("operators", "Phase 2 / Operators", {"operators", "operator_semantics"}),
    ("transformations", "Phase 2 / Transformations", {"transformations", "transformation_semantics"}),
)

VARIABLE_LABELS = {
    "action_intervention": "INTERVENTION",
    "args": "ARGS",
    "args_names": "ARGS_NAMES",
    "audit_log": "AUDIT_LOG",
    "harness": "HARNESS",
    "multipart_files": "FILES",
    "operators": "OPERATORS",
    "request_body_json": "REQUEST_BODY/JSON",
    "request_body_urlencoded": "REQUEST_BODY",
    "request_body_xml": "XML",
    "request_cookies": "REQUEST_COOKIES",
    "request_cookies_names": "REQUEST_COOKIES_NAMES",
    "request_headers": "REQUEST_HEADERS",
    "request_headers_names": "REQUEST_HEADERS_NAMES",
    "request_routing": "REQUEST_ROUTING",
    "request_uri": "REQUEST_URI",
    "response_body": "RESPONSE_BODY",
    "response_headers": "RESPONSE_HEADERS",
    "rule_chain": "CHAIN",
    "secaction": "SECACTION",
    "transformations": "TRANSFORMATIONS",
}


def read_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    return data if isinstance(data, dict) else {}


def read_json_optional(path: Path | None) -> dict[str, Any]:
    if not path or not path.is_file():
        return {}
    return read_json(path)


def as_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    if value is None or value == "":
        return []
    return [str(value)]


def status_value(entry: dict[str, Any]) -> str:
    value = str(entry.get("runtime_status") or "UNKNOWN").upper().replace("-", "_")
    if value in {"NOT_EXECUTED", "NOT_EXECUTABLE", "NOT_EXECUTABLE"}:
        return "NOT_EXECUTABLE"
    if value in {"PASS", "FAIL", "BLOCKED"}:
        return value
    return "UNKNOWN"


def parse_count_list(value: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for match in COUNT_TOKEN_RE.finditer(value):
        counts[match.group(1).strip()] = int(match.group(2))
    return counts


def parse_status_distribution(value: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for part in value.split(","):
        if ":" not in part:
            continue
        key, raw_count = part.split(":", 1)
        key = key.strip()
        raw_count = raw_count.strip()
        if key and raw_count.isdigit():
            counts[key] = int(raw_count)
    return counts


def parse_phase_coverage(path: Path | None) -> dict[str, dict[str, Any]]:
    coverage = {
        phase: {"case_count": 0, "top_variables": {}, "status_distribution": {}}
        for phase in PHASES
    }
    if not path or not path.is_file():
        return coverage
    for line in path.read_text(encoding="utf-8").splitlines():
        match = PHASE_ROW_RE.match(line)
        if not match:
            continue
        phase, count, top_variables, status_distribution = match.groups()
        coverage[phase] = {
            "case_count": int(count),
            "top_variables": parse_count_list(top_variables),
            "status_distribution": parse_status_distribution(status_distribution),
        }
    return coverage


def is_phase4_or_response_body(entry: dict[str, Any]) -> bool:
    return str(entry.get("phase") or "") == "4" or "response_body" in as_list(entry.get("functional_area"))


def variable_or_collection(entry: dict[str, Any]) -> list[str]:
    labels: list[str] = []
    for area in as_list(entry.get("functional_area")):
        label = VARIABLE_LABELS.get(area, area.upper())
        if label not in labels:
            labels.append(label)
    if not labels and entry.get("category"):
        labels.append(str(entry["category"]).upper())
    return labels or ["UNKNOWN"]


def phase_work_direction(entry: dict[str, Any]) -> list[str]:
    phase = str(entry.get("phase") or "unknown")
    areas = set(as_list(entry.get("functional_area")))
    directions = set(as_list(entry.get("work_direction")))
    patterns = set(as_list(entry.get("failure_pattern")))
    classification = str(entry.get("classification") or "")

    if classification == REPORT_ONLY_CLASSIFICATION or "classification_only" in directions:
        return ["classification_only"]

    if is_phase4_or_response_body(entry):
        return ["response_body_non_promoted"]
    if phase == "1":
        if "expected_block_got_200" in patterns or "intervention_blocking" in directions:
            return ["intervention_blocking"]
        if {"request_headers", "request_headers_names"} & areas:
            return ["request_header_mapping"]
        if "request_uri" in areas or "request_routing" in directions:
            return ["request_uri_mapping"]
        if {"request_cookies", "request_cookies_names", "args", "args_names"} & areas:
            return ["collection_mapping"]
        if "audit_log" in areas:
            return ["audit_log_evidence"]
    if phase == "2":
        if "request_body_json" in areas:
            return ["json_processor"]
        if "request_body_xml" in areas:
            return ["xml_processor"]
        if "multipart_files" in areas:
            return ["multipart_files"]
        if "operators" in areas or "operator_semantics" in directions:
            return ["operator_semantics"]
        if "transformations" in areas or "transformation_semantics" in directions:
            return ["transformation_semantics"]
        if "request_routing" in directions:
            return ["request_routing"]
        if "expected_block_got_200" in patterns or "intervention_blocking" in directions:
            return ["intervention_blocking"]
        if "request_body_urlencoded" in areas:
            return ["request_body_processor"]
    if phase == "3":
        if "response_headers" in areas:
            return ["response_header_hook"]
        if "audit_log" in areas:
            return ["audit_log_evidence"]
        if "expected_block_got_200" in patterns or "intervention_blocking" in directions:
            return ["intervention_blocking"]
    return sorted(directions) or ["runtime_difference"]


def simple_blocking_cluster_key(entry: dict[str, Any]) -> tuple[str, str, str] | None:
    if str(entry.get("classification") or "") == REPORT_ONLY_CLASSIFICATION:
        return None
    if str(entry.get("phase")) not in {"1", "2"}:
        return None
    if status_value(entry) != "FAIL":
        return None
    if "expected_block_got_200" not in as_list(entry.get("failure_pattern")):
        return None
    areas = set(as_list(entry.get("functional_area")))
    if not ({"action_intervention", "secaction"} & areas):
        return None
    return (
        str(entry.get("case_id") or ""),
        str(entry.get("test_variant") or ""),
        str(entry.get("mrts_variant") or ""),
    )


def high_volume_patterns(entries: list[dict[str, Any]]) -> set[tuple[str, str]]:
    counts: Counter[tuple[str, str]] = Counter()
    for entry in entries:
        if status_value(entry) != "FAIL":
            continue
        if str(entry.get("classification") or "") == REPORT_ONLY_CLASSIFICATION:
            continue
        connector = str(entry.get("connector") or "")
        for pattern in as_list(entry.get("failure_pattern")):
            counts[(connector, pattern)] += 1
    return {key for key, count in counts.items() if count >= 10}


def choose_priority(entry: dict[str, Any], p0_clusters: set[tuple[str, str, str]], high_volume: set[tuple[str, str]]) -> str:
    status = status_value(entry)
    phase = str(entry.get("phase") or "unknown")
    areas = set(as_list(entry.get("functional_area")))
    patterns = set(as_list(entry.get("failure_pattern")))
    source_kind = str(entry.get("source_kind") or "")
    connector = str(entry.get("connector") or "")
    classification = str(entry.get("classification") or "")
    directions = set(as_list(entry.get("work_direction")))

    if classification == REPORT_ONLY_CLASSIFICATION or "classification_only" in directions:
        return REPORT_ONLY_PRIORITY
    if is_phase4_or_response_body(entry):
        return "P3"
    if source_kind in {"golden-only", "feature-demo-report-only"} or status == "NOT_EXECUTABLE":
        return "P3"
    key = simple_blocking_cluster_key(entry)
    if key and key in p0_clusters:
        return "P0"
    if source_kind == "runtime-job" and status == "BLOCKED":
        return "P1"
    if any((connector, pattern) in high_volume for pattern in patterns):
        return "P1"
    if connector == "nginx" and {"expected_200_got_404", "expected_200_got_405", "expected_block_got_404", "expected_block_got_405"} & patterns:
        return "P1"
    if connector == "haproxy" and any(pattern.endswith("_got_501") for pattern in patterns):
        return "P1"
    if "expected_block_got_200" in patterns:
        return "P1"
    if phase == "3" or {"request_body_json", "request_body_xml", "multipart_files", "operators", "transformations", "response_headers"} & areas:
        return "P2"
    return "P3"


def normalize_entries(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    raw_entries = [entry for entry in entries if isinstance(entry, dict)]
    clustered_connectors: defaultdict[tuple[str, str, str], set[str]] = defaultdict(set)
    for entry in raw_entries:
        key = simple_blocking_cluster_key(entry)
        if key:
            clustered_connectors[key].add(str(entry.get("connector") or ""))
    p0_clusters = {key for key, connectors in clustered_connectors.items() if len(connectors - {""}) >= 2}
    high_volume = high_volume_patterns(raw_entries)

    normalized: list[dict[str, Any]] = []
    for entry in raw_entries:
        phase = str(entry.get("phase") or "unknown")
        directions = phase_work_direction(entry)
        normalized.append(
            {
                "case_id": str(entry.get("case_id") or ""),
                "connector": str(entry.get("connector") or ""),
                "test_variant": str(entry.get("test_variant") or ""),
                "mrts_variant": str(entry.get("mrts_variant") or ""),
                "source_kind": str(entry.get("source_kind") or ""),
                "mrts_corpus": str(entry.get("mrts_corpus") or "none"),
                "phase": phase if phase in PHASES else "unknown",
                "variable_or_collection": variable_or_collection(entry),
                "category": str(entry.get("category") or "unknown"),
                "functional_area": as_list(entry.get("functional_area")),
                "failure_pattern": as_list(entry.get("failure_pattern")),
                "classification": str(entry.get("classification") or "unclassified"),
                "work_direction": directions,
                "priority": choose_priority(entry, p0_clusters, high_volume),
                "expected_status": entry.get("expected_status"),
                "actual_status": entry.get("actual_status"),
                "runtime_status": status_value(entry),
                "evidence": str(entry.get("evidence") or entry.get("summary_path") or ""),
                "reason": str(entry.get("reason") or ""),
            }
        )
    return normalized


def is_queue_entry(entry: dict[str, Any]) -> bool:
    return entry["runtime_status"] != "PASS" or entry["phase"] == "4" or "response_body_non_promoted" in entry["work_direction"]


def count_by(entries: list[dict[str, Any]], key: str) -> Counter[str]:
    counts: Counter[str] = Counter()
    for entry in entries:
        value = entry.get(key)
        if isinstance(value, list):
            for item in value:
                counts[str(item)] += 1
        else:
            counts[str(value)] += 1
    return counts


def sorted_queue(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        entries,
        key=lambda item: (
            PRIORITY_ORDER.get(item["priority"], 4),
            item["connector"],
            item["phase"],
            item["case_id"],
            item["test_variant"],
            item["mrts_variant"],
        ),
    )


def phase2_subgroups(entries: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for key, title, selectors in PHASE2_SUBGROUPS:
        rows = [
            entry
            for entry in entries
            if entry["phase"] == "2" and (selectors & set(entry["functional_area"]) or selectors & set(entry["work_direction"]))
        ]
        queue = sorted_queue([entry for entry in rows if is_queue_entry(entry)])
        groups[key] = {
            "title": title,
            "runtime_entries": len(rows),
            "queued_entries": len(queue),
            "runtime_status": dict(count_by(rows, "runtime_status")),
            "top_work_directions": dict(count_by(queue, "work_direction").most_common(8)),
            "top_failure_patterns": dict(count_by(queue, "failure_pattern").most_common(8)),
            "queue": queue,
        }
    return groups


def main_direction(entries: list[dict[str, Any]]) -> str:
    queued = [entry for entry in entries if is_queue_entry(entry)]
    return count_by(queued, "work_direction").most_common(1)[0][0] if queued else "-"


def connector_next_work(connector: str, entries: list[dict[str, Any]]) -> str:
    rows = [entry for entry in entries if entry["connector"] == connector]
    if connector == "apache" and any(entry["runtime_status"] == "BLOCKED" for entry in rows):
        return "Repair Apache build/harness first, then Phase 1/2 intervention_blocking."
    connector_patterns = count_by([entry for entry in rows if is_queue_entry(entry)], "failure_pattern")
    connector_directions = count_by([entry for entry in rows if is_queue_entry(entry)], "work_direction")
    if connector == "nginx" and (
        connector_patterns["expected_200_got_404"]
        or connector_patterns["expected_200_got_405"]
        or connector_patterns["expected_block_got_404"]
        or connector_patterns["expected_block_got_405"]
        or connector_directions["request_routing"]
    ):
        return "Fix request_routing / method-location handling, especially Phase 2 404/405, then intervention_blocking."
    if connector == "haproxy" and any(name.endswith("_got_501") for name in connector_patterns):
        return "Fix HAProxy 501 connector gaps around Body/XML/Multipart/SPOA, then 403->200 intervention_blocking."
    top = connector_directions.most_common(1)
    return f"Start with {top[0][0]}." if top else "No queued runtime work from current evidence."


def connector_top_three_work(connector: str, entries: list[dict[str, Any]]) -> list[str]:
    rows = [entry for entry in entries if entry["connector"] == connector]
    if connector == "apache" and any(entry["runtime_status"] == "BLOCKED" for entry in rows):
        return [
            "Repair Apache build/harness so runtime evidence is available.",
            "Rerun Apache Phase 1/2 intervention_blocking evidence.",
            "Verify Apache audit_log_evidence once smoke summaries contain cases.",
        ]
    if connector == "nginx":
        return [
            "Fix request_routing / method-location handling for 404/405 clusters.",
            "Stabilize Phase 2 ARGS / request body paths after routing is fixed.",
            "Then close intervention_blocking gaps where expected blocks return 200.",
        ]
    if connector == "haproxy":
        return [
            "Fix 501 connector gaps around Body/XML/Multipart/SPOA.",
            "Split XML, multipart, and FILES coverage into separate HAProxy repairs.",
            "Then close 403->200 intervention_blocking gaps.",
        ]
    queued = sorted_queue([entry for entry in rows if is_queue_entry(entry)])
    directions = [name for name, _ in count_by(queued, "work_direction").most_common(3)]
    while len(directions) < 3:
        directions.append("No additional queued runtime work from current evidence.")
    return directions


def build_payload(
    connector_work_queue: dict[str, Any],
    phase_coverage: dict[str, dict[str, Any]],
    full_runtime_matrix: dict[str, Any],
    framework_root: Path,
    connector_root: Path,
    inputs: dict[str, str],
) -> dict[str, Any]:
    entries = normalize_entries(connector_work_queue.get("entries", []))
    queue_entries = sorted_queue([entry for entry in entries if is_queue_entry(entry)])
    generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    phases: dict[str, Any] = {}
    for phase in PHASES:
        phase_entries = [entry for entry in entries if entry["phase"] == phase]
        phase_queue = sorted_queue([entry for entry in phase_entries if is_queue_entry(entry)])
        phases[phase] = {
            **PHASE_DESCRIPTIONS[phase],
            "coverage": phase_coverage[phase],
            "runtime_entries": len(phase_entries),
            "unique_runtime_cases": len({entry["case_id"] for entry in phase_entries}),
            "runtime_status": dict(count_by(phase_entries, "runtime_status")),
            "classification": dict(count_by(phase_queue, "classification").most_common(10)),
            "priority": dict(count_by(phase_queue, "priority")),
            "top_work_directions": dict(count_by(phase_queue, "work_direction").most_common(10)),
            "top_failure_patterns": dict(count_by(phase_queue, "failure_pattern").most_common(10)),
            "queue": phase_queue,
        }
    phases["2"]["subgroups"] = phase2_subgroups(entries)

    connectors: dict[str, Any] = {}
    for connector in CONNECTORS:
        connector_entries = [entry for entry in entries if entry["connector"] == connector]
        connector_queue = sorted_queue([entry for entry in connector_entries if is_queue_entry(entry)])
        phase_summary: dict[str, Any] = {}
        for phase in PHASES:
            rows = [entry for entry in connector_entries if entry["phase"] == phase]
            queued = [entry for entry in rows if is_queue_entry(entry)]
            phase_summary[phase] = {
                "runtime_status": dict(count_by(rows, "runtime_status")),
                "top_problems": dict(count_by(queued, "failure_pattern").most_common(5)),
                "top_work_directions": dict(count_by(queued, "work_direction").most_common(5)),
                "queued_entries": len(queued),
            }
        connectors[connector] = {
            "runtime_status": dict(count_by(connector_entries, "runtime_status")),
            "phase_summary": phase_summary,
            "top_work_directions": dict(count_by(connector_queue, "work_direction").most_common(10)),
            "top_failure_patterns": dict(count_by(connector_queue, "failure_pattern").most_common(10)),
            "next_work": connector_next_work(connector, entries),
            "top_3_next_work": connector_top_three_work(connector, entries),
        }

    recommended_work_order = [
        {"priority": 1, "phase": "1", "focus": "intervention/blocking"},
        {"priority": 2, "phase": "2", "focus": "ARGS / ARGS_NAMES"},
        {"priority": 3, "phase": "2", "focus": "JSON / request body"},
        {"priority": 4, "phase": "2", "focus": "XML / multipart / FILES"},
        {"priority": 5, "phase": "3", "focus": "response headers"},
        {"priority": 6, "phase": "4", "focus": "response body, non-promoted"},
    ]

    unknown_phase_entries = [entry for entry in entries if entry["phase"] == "unknown"]
    return {
        "generated_at": generated_at,
        "framework_root": str(framework_root),
        "connector_root": str(connector_root),
        "inputs": inputs,
        "summary": {
            "runtime_entries": len(entries),
            "queued_entries": len(queue_entries),
            "failures": sum(1 for entry in entries if entry["runtime_status"] == "FAIL"),
            "blocked": sum(1 for entry in entries if entry["runtime_status"] == "BLOCKED"),
            "not_executable": sum(1 for entry in entries if entry["runtime_status"] == "NOT_EXECUTABLE"),
            "unknown_phase_entries": len(unknown_phase_entries),
            "phase_case_totals": {phase: phase_coverage[phase]["case_count"] for phase in PHASES},
            "runtime_status_by_phase": {
                phase: dict(count_by([entry for entry in entries if entry["phase"] == phase], "runtime_status"))
                for phase in PHASES
            },
            "metadata_status_by_phase": {
                phase: phase_coverage[phase]["status_distribution"] for phase in PHASES
            },
            "main_work_direction_by_phase": {
                phase: main_direction([entry for entry in entries if entry["phase"] == phase])
                for phase in PHASES
            },
            "full_runtime_runs": len(full_runtime_matrix.get("runs", [])) if isinstance(full_runtime_matrix.get("runs"), list) else 0,
        },
        "phases": phases,
        "connectors": connectors,
        "recommended_work_order": recommended_work_order,
        "guardrails": {
            "runtime_status_source": "reports/testing/generated/connector-work-queue.generated.json",
            "classification_is_explanatory_only": True,
            "phase4_response_body_non_promoted": True,
            "missing_phase_metadata_policy": "reported as unknown; never forced into phases 1-4",
            "feature_demo_runtime_cases": connector_work_queue.get("guardrails", {}).get("feature_demo_runtime_cases"),
            "golden_runtime_cases": connector_work_queue.get("guardrails", {}).get("golden_runtime_cases"),
            "no_mrts_mrts_runtime_cases": connector_work_queue.get("guardrails", {}).get("no_mrts_mrts_runtime_cases"),
        },
    }


def markdown_table(headers: list[str], rows: list[list[Any]]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    if not rows:
        lines.append("| " + " | ".join("-" for _ in headers) + " |")
        return lines
    for row in rows:
        lines.append("| " + " | ".join(str(item).replace("\n", " ") if item is not None else "-" for item in row) + " |")
    return lines


def compact_counts(counts: dict[str, int], order: tuple[str, ...] | None = None) -> str:
    if not counts:
        return "-"
    items = []
    keys = list(order or ())
    keys.extend(sorted(key for key in counts if key not in keys))
    for key in keys:
        if counts.get(key):
            items.append(f"{key}:{counts[key]}")
    return ", ".join(items) or "-"


def compact_top(counts: dict[str, int], limit: int = 4) -> str:
    if not counts:
        return "-"
    return ", ".join(f"{key}({value})" for key, value in list(counts.items())[:limit])


def queue_rows(entries: list[dict[str, Any]], limit: int = 25) -> list[list[Any]]:
    rows: list[list[Any]] = []
    for entry in sorted_queue(entries)[:limit]:
        rows.append(
            [
                entry["priority"],
                entry["connector"],
                f"{entry['test_variant']}/{entry['mrts_variant']}",
                entry["case_id"],
                ", ".join(entry["variable_or_collection"]),
                entry["runtime_status"],
                entry["expected_status"],
                entry["actual_status"],
                ", ".join(entry["failure_pattern"]) or "-",
                ", ".join(entry["work_direction"]),
                entry["reason"] or "-",
                entry["evidence"] or "-",
            ]
        )
    return rows


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Phase-Oriented MRTS Work Queue",
        "",
        "Generated file - do not edit manually.",
        "",
        "## Executive Summary",
        f"- Generated at: `{payload['generated_at']}`",
        f"- Runtime evidence rows analyzed: **{payload['summary']['runtime_entries']}**",
        f"- Queued work rows: **{payload['summary']['queued_entries']}**",
        f"- Runtime FAIL/BLOCKED/NOT_EXECUTABLE: **{payload['summary']['failures']}** / **{payload['summary']['blocked']}** / **{payload['summary']['not_executable']}**",
        f"- Unknown-phase runtime rows: **{payload['summary']['unknown_phase_entries']}**",
        "- Recommended order: Phase 1 intervention/blocking, Phase 2 ARGS/ARGS_NAMES, Phase 2 JSON/body, Phase 2 XML/multipart/FILES, Phase 3 headers, Phase 4 response body non-promoted.",
        "",
    ]
    rows: list[list[Any]] = []
    for phase in PHASES:
        phase_data = payload["phases"][phase]
        coverage = phase_data["coverage"]
        rows.append(
            [
                phase,
                coverage["case_count"],
                phase_data["runtime_entries"],
                compact_counts(phase_data["runtime_status"], STATUS_ORDER),
                compact_counts(coverage["status_distribution"]),
                compact_top(phase_data["top_work_directions"], 1),
            ]
        )
    lines.extend(markdown_table(["phase", "coverage cases", "runtime rows", "PASS/FAIL/BLOCKED/NOT_EXECUTABLE", "active/imported/pending", "main work direction"], rows))

    for phase in PHASES:
        phase_data = payload["phases"][phase]
        lines.extend(
            [
                "",
                f"## {phase_data['title']}",
                f"- Focus: {phase_data['focus']}",
                f"- Directions: {', '.join(phase_data['directions'])}",
                f"- Goal: {phase_data['goal']}",
                f"- Top failure patterns: {compact_top(phase_data['top_failure_patterns'], 6)}",
                f"- Top work directions: {compact_top(phase_data['top_work_directions'], 6)}",
            ]
        )
        if phase == "4":
            lines.append("- Promotion policy: Phase 4 / RESPONSE_BODY remains visible but non-promoted; queued rows default to P3.")
        lines.extend(
            markdown_table(
                ["priority", "connector", "variant", "case", "variable/collection", "runtime", "expected", "actual", "failure", "work_direction", "reason", "evidence"],
                queue_rows(phase_data["queue"]),
            )
        )
        if phase == "2":
            lines.extend(["", "### Phase 2 Subgroups"])
            for subgroup in payload["phases"]["2"]["subgroups"].values():
                lines.extend(
                    [
                        "",
                        f"#### {subgroup['title']}",
                        f"- Runtime rows: **{subgroup['runtime_entries']}**",
                        f"- Queued rows: **{subgroup['queued_entries']}**",
                        f"- Runtime status: {compact_counts(subgroup['runtime_status'], STATUS_ORDER)}",
                        f"- Top work directions: {compact_top(subgroup['top_work_directions'], 5)}",
                    ]
                )
                lines.extend(
                    markdown_table(
                        ["priority", "connector", "variant", "case", "variable/collection", "runtime", "expected", "actual", "failure", "work_direction", "reason", "evidence"],
                        queue_rows(subgroup["queue"], 15),
                    )
                )

    lines.extend(["", "## Per Connector Phase Summary"])
    rows = []
    for connector, data in payload["connectors"].items():
        phase_summary = data["phase_summary"]
        rows.append(
            [
                connector,
                compact_top(phase_summary["1"]["top_work_directions"], 3),
                compact_top(phase_summary["2"]["top_work_directions"], 3),
                compact_top(phase_summary["3"]["top_work_directions"], 3),
                phase_summary["4"]["queued_entries"],
                data["next_work"],
            ]
        )
    lines.extend(markdown_table(["connector", "phase 1 top problems", "phase 2 top problems", "phase 3 top problems", "phase 4 non-promoted rows", "next sensible fix"], rows))

    lines.extend(["", "## Recommended Work Order"])
    for item in payload["recommended_work_order"]:
        lines.append(f"{item['priority']}. Phase {item['phase']} - {item['focus']}")

    lines.extend(
        [
            "",
            "## Connector-Specific Recommended Work",
        ]
    )
    for connector, data in payload["connectors"].items():
        lines.append(f"### {connector}")
        for index, item in enumerate(data["top_3_next_work"], start=1):
            lines.append(f"{index}. {item}")
    lines.extend(
        [
            "",
            "## Guardrails",
            "- Runtime PASS/FAIL/BLOCKED is sourced from `connector-work-queue.generated.json`.",
            "- Classification only explains results and never changes request data, rules, expected status, actual status, or runtime status.",
            "- RESPONSE_BODY / Phase 4 remains non-promoted.",
            "- Golden references and feature-demo report-only cases remain non-runtime inputs.",
            "- Missing phase metadata is reported as unknown and is not forced into phases 1-4.",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--framework-root", default=Path(__file__).resolve().parents[1])
    parser.add_argument("--connector-root", default=Path.cwd())
    parser.add_argument("--output-root", default=None)
    parser.add_argument("--connector-work-queue", default=None)
    parser.add_argument("--phase-coverage", default=None)
    parser.add_argument("--full-runtime-matrix", default=None)
    args = parser.parse_args()

    framework_root = Path(args.framework_root).resolve()
    connector_root = Path(args.connector_root).resolve()
    output_root = Path(args.output_root).resolve() if args.output_root else connector_root
    output_dir = output_root / "reports/testing/generated"
    connector_work_queue_path = Path(args.connector_work_queue).resolve() if args.connector_work_queue else output_dir / "connector-work-queue.generated.json"
    phase_coverage_path = Path(args.phase_coverage).resolve() if args.phase_coverage else output_dir / "phase-coverage.generated.md"
    full_runtime_matrix_path = Path(args.full_runtime_matrix).resolve() if args.full_runtime_matrix else output_dir / "full-runtime-matrix.generated.json"

    if not connector_work_queue_path.is_file():
        raise SystemExit(f"missing connector work queue JSON: {connector_work_queue_path}")

    connector_work_queue = read_json(connector_work_queue_path)
    phase_coverage = parse_phase_coverage(phase_coverage_path)
    full_runtime_matrix = read_json_optional(full_runtime_matrix_path)
    payload = build_payload(
        connector_work_queue,
        phase_coverage,
        full_runtime_matrix,
        framework_root,
        connector_root,
        {
            "connector_work_queue": str(connector_work_queue_path),
            "phase_coverage": str(phase_coverage_path),
            "full_runtime_matrix": str(full_runtime_matrix_path),
        },
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "phase-work-queue.generated.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (output_dir / "phase-work-queue.generated.md").write_text(render_markdown(payload), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
