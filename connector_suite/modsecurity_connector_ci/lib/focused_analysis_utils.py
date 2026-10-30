#!/usr/bin/env python3
from __future__ import annotations
from modsecurity_test_framework.connector_context import load_source

import argparse
import importlib.util
import sys
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

from modsecurity_connector_ci.lib.generated_report_utils import GENERATED_ROOT, build_metadata, generated_json_text, generated_markdown_text, report_path_from_root, report_relpath, utc_now
from modsecurity_connector_ci.lib.report_path_safety import read_json_file as read_json
from modsecurity_connector_ci.lib.report_path_safety import read_text_file as read_text
from modsecurity_connector_ci.lib.report_path_safety import add_report_roots, add_safe_roots, resolve_output_dir
from modsecurity_connector_ci.lib.report_path_safety import safe_existing_file
from modsecurity_connector_ci.lib.report_path_safety import write_json_file as write_json
from modsecurity_connector_ci.lib.report_path_safety import write_text_file


CONNECTOR_WORK_QUEUE_REPORT = "connector_work_queue"
FULL_RUNTIME_MATRIX_REPORT = "full_runtime_matrix"
PHASE_COVERAGE_REPORT = "phase_coverage"
PHASE_WORK_QUEUE_REPORT = "phase_work_queue"
ReportAnalysisBuilder = Callable[[Path, Path], dict[str, Any]]
ReportMarkdownRenderer = Callable[[dict[str, Any]], str]
ReportPostWrite = Callable[[Path, dict[str, Any]], None]


def as_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return [] if value in (None, "") else [str(value)]
    return [str(item) for item in value if str(item).strip()]


def find_framework_case_path(framework_root: Path, case_id: Any) -> Path | None:
    """Return a known framework case only when it passes the safe-file gate."""

    case_name = str(case_id or "").strip()
    if not case_name or "/" in case_name or "\\" in case_name:
        return None
    for root in (framework_root / "tests/cases", framework_root / "tests/upstream"):
        if not root.is_dir():
            continue
        for candidate in root.rglob(f"{case_name}.yaml"):
            path = safe_existing_file(candidate)
            if path is not None:
                return path
    return None


def upsert_marked_section(
    text: str,
    *,
    start: str,
    end: str,
    section: str,
    insert_before: str | None = None,
) -> str:
    """Replace a bounded report section or insert it before a known anchor."""

    marked = f"{start}\n{section}\n{end}"
    if start in text and end in text:
        prefix = text.split(start, 1)[0].rstrip()
        suffix = text.split(end, 1)[1].lstrip()
        return f"{prefix}\n\n{marked}\n\n{suffix}".rstrip() + "\n"
    if insert_before and insert_before in text:
        prefix, suffix = text.split(insert_before, 1)
        return f"{prefix.rstrip()}\n\n{marked}\n\n{insert_before}{suffix}".rstrip() + "\n"
    return text.rstrip() + "\n\n" + marked + "\n"


def refresh_connector_queue_totals(data: dict[str, Any]) -> None:
    entries = [entry for entry in data.get("entries", []) if isinstance(entry, dict)]
    non_pass = [entry for entry in entries if entry.get("runtime_status") != "PASS"]
    priority_counts = Counter(str(entry.get("priority") or "-") for entry in non_pass)
    totals = data.setdefault("totals", {})
    totals["entries"] = len(entries)
    totals["failures"] = sum(1 for entry in entries if entry.get("runtime_status") == "FAIL")
    totals["priority"] = dict(sorted(priority_counts.items()))


def import_script(path: Path, _module_name: str) -> Any:
    module = load_source(path)
    return module


def render_connector_work_queue_markdown(
    report_dir: Path,
    data: dict[str, Any],
    framework_root: Path,
) -> None:
    """Regenerate the fixed connector-work-queue Markdown report."""

    connector_root = report_dir.parents[2]
    module = import_script(
        framework_root / "ci/reporting/generate-connector-work-queue.py",
        "connector_work_queue_generator",
    )
    markdown = module.render_markdown(
        data.get("entries", []),
        Counter(data.get("source_counts", {})),
        Counter(data.get("runtime_source_counts", {})),
        str(data.get("generated_at") or utc_now()),
    )
    metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else build_metadata(
        generated_by="framework:ci/reporting/generate-connector-work-queue.py",
        make_target="generate-work-queue",
        connector_root=connector_root,
        framework_root=framework_root,
        inputs=[report_relpath(FULL_RUNTIME_MATRIX_REPORT, "json")],
        generated_at=str(data.get("generated_at") or utc_now()),
    )
    write_text_file(
        report_path_from_root(report_dir, CONNECTOR_WORK_QUEUE_REPORT, "md"),
        generated_markdown_text(markdown, metadata),
    )


def regenerate_phase_work_queue(
    report_dir: Path,
    framework_root: Path,
    connector_root: Path,
    phase_work_direction: Callable[[dict[str, Any], Callable[[dict[str, Any]], list[str]], Any], list[str]],
) -> None:
    """Regenerate the fixed phase-work reports with a caller-owned direction override."""

    module = import_script(
        framework_root / "ci/reporting/generate-phase-work-queue.py",
        "phase_work_queue_generator",
    )
    original_phase_work_direction = module.phase_work_direction

    def patched_phase_work_direction(entry: dict[str, Any]) -> list[str]:
        return phase_work_direction(entry, original_phase_work_direction, module)

    module.phase_work_direction = patched_phase_work_direction
    try:
        connector_work_queue_path = report_path_from_root(report_dir, CONNECTOR_WORK_QUEUE_REPORT, "json")
        phase_coverage_path = report_path_from_root(report_dir, PHASE_COVERAGE_REPORT, "md")
        full_runtime_matrix_path = report_path_from_root(report_dir, FULL_RUNTIME_MATRIX_REPORT, "json")
        connector_work_queue = module.read_json(connector_work_queue_path)
        phase_coverage = module.parse_phase_coverage(phase_coverage_path)
        full_runtime_matrix = module.read_json_optional(full_runtime_matrix_path)
        payload = module.build_payload(
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
        metadata = build_metadata(
            generated_by="framework:ci/reporting/generate-phase-work-queue.py",
            make_target="generate-phase-work-queue",
            connector_root=connector_root,
            framework_root=framework_root,
            inputs=[connector_work_queue_path, phase_coverage_path, full_runtime_matrix_path],
            generated_at=str(payload.get("generated_at") or utc_now()),
        )
        write_text_file(
            report_path_from_root(report_dir, PHASE_WORK_QUEUE_REPORT, "json"),
            generated_json_text(payload, metadata),
        )
        write_text_file(
            report_path_from_root(report_dir, PHASE_WORK_QUEUE_REPORT, "md"),
            generated_markdown_text(module.render_markdown(payload), metadata),
        )
    finally:
        module.phase_work_direction = original_phase_work_direction


def write_generated_report_pair(
    report_dir: Path,
    connector_root: Path,
    framework_root: Path,
    analysis: dict[str, Any],
    *,
    report_name: str,
    generated_by: str,
    make_target: str,
    markdown: str,
) -> Path:
    """Write one caller-owned generated report pair through the safe writer."""

    metadata = build_metadata(
        generated_by=generated_by,
        make_target=make_target,
        connector_root=connector_root,
        framework_root=framework_root,
        inputs=analysis["source_reports"].values(),
        generated_at=analysis["generated_at"],
    )
    json_path = report_path_from_root(report_dir, report_name, "json")
    md_path = report_path_from_root(report_dir, report_name, "md")
    write_text_file(json_path, generated_json_text(analysis, metadata))
    write_text_file(md_path, generated_markdown_text(markdown, metadata))
    return md_path


def run_report_generator(
    *,
    report_name: str,
    generated_by: str,
    make_target: str,
    build_analysis: ReportAnalysisBuilder,
    render_markdown: ReportMarkdownRenderer,
    post_write: ReportPostWrite | None = None,
) -> int:
    """Run one fixed report generator through the existing safe-root lifecycle."""

    parser = argparse.ArgumentParser()
    for option, default in (
        ("--connector-root", "."),
        ("--framework-root", None),
        ("--output-dir", None),
    ):
        parser.add_argument(option, default=default)
    args = parser.parse_args()

    connector_root = Path(args.connector_root).resolve()
    configured_framework_root = args.framework_root
    framework_root = Path(configured_framework_root).resolve() if configured_framework_root else connector_root / "modules/ModSecurity-test-Framework"
    report_dir = resolve_output_dir(connector_root, args.output_dir, GENERATED_ROOT)
    generated_root = connector_root / GENERATED_ROOT
    add_safe_roots(connector_root, framework_root, generated_root)
    add_report_roots(generated_root)
    report_dir.mkdir(parents=True, exist_ok=True)
    analysis = build_analysis(connector_root, framework_root)
    md_path = write_generated_report_pair(
        report_dir,
        connector_root,
        framework_root,
        analysis,
        report_name=report_name,
        generated_by=generated_by,
        make_target=make_target,
        markdown=render_markdown(analysis),
    )
    if post_write is not None:
        post_write(report_dir, analysis)
    print(md_path)
    return 0


def sanitize_path(value: Any, connector_root: Path, framework_root: Path) -> str:
    text = str(value or "")
    if not text:
        return "-"
    path = safe_existing_file(text)
    if path is None:
        leaf = text.replace("\\", "/").rstrip("/").split("/")[-1] or "-"
        return f"<runtime-artifact>/{leaf}"
    for root, prefix in ((connector_root, "connector"), (framework_root, "framework")):
        try:
            return f"{prefix}:{path.resolve().relative_to(root.resolve())}"
        except (OSError, ValueError):
            continue
    return f"<runtime-artifact>/{path.name}"


def _next_quote(quote: str | None, char: str) -> str | None:
    if char not in {"'", '"'}:
        return quote
    if quote is None:
        return char
    return None if quote == char else quote


def _append_action_part(parts: list[str], characters: list[str]) -> None:
    part = "".join(characters).strip()
    if part:
        parts.append(part)


def action_parts(action_text: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    quote: str | None = None
    for char in action_text:
        quote = _next_quote(quote, char)
        if char == "," and quote is None:
            _append_action_part(parts, current)
            current.clear()
        else:
            current.append(char)
    _append_action_part(parts, current)
    return parts


def action_value(actions: list[str], name: str) -> str:
    """Return the first case-insensitive named ModSecurity action value."""

    prefix = f"{name.lower()}:"
    for action in actions:
        text = action.strip()
        if text.lower().startswith(prefix):
            return text.split(":", 1)[1].strip()
    return "-"


def log_paths(evidence: dict[str, Any]) -> list[Path]:
    """Return safe report-log paths in the original evidence field order."""

    paths: list[Path] = []
    for key, value in evidence.items():
        if not value:
            continue
        if key.endswith("_log_path") or key == "decision_log":
            path = safe_existing_file(value)
            if path is not None:
                paths.append(path)
    return paths
