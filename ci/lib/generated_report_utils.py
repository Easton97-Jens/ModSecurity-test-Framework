#!/usr/bin/env python3
"""Framework-owned generated report helpers.

Connector repositories are untrusted inputs for report generation; keep helper
code in this repository so generators never import executable connector code.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

GENERATED_NOTICE = "Generated file - do not edit manually."
DATA_SOURCE_POLICY = "verified-inputs-only"

# Framework generators write committed Markdown into connector repositories.
# Paths from a runtime workspace must therefore be presentation-only aliases,
# never host-specific locations.  The connector report index documents these
# placeholders; raw paths remain available to the executing generator.
_LOCAL_PATH_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?P<path>/(?:var/tmp|tmp|root|home|Users)(?:/[^\s`<>()\[\]{}|,;]*)?)"
)
_HISTORICAL_RUN_ROOT_RE = re.compile(
    r"^/var/tmp/(?P<run>ModSecurity-conector-(?!verified(?:/|$))[^/]+)(?P<suffix>/.*)?$"
)


def portable_path_reference(value: str | Path) -> str:
    """Render local runtime paths as portable documentation references."""

    raw = str(value)
    for prefix, replacement in (
        ("/root/.local/state/ModSecurity-conector-build", "<local-state-root>"),
        ("/var/tmp/ModSecurity-conector-verified", "<verified-run-root>"),
        ("/tmp/ModSecurity-conector-verified", "<verified-run-root>"),
    ):
        if raw == prefix or raw.startswith(prefix + "/"):
            return replacement + raw[len(prefix) :]
    historical = _HISTORICAL_RUN_ROOT_RE.match(raw)
    if historical:
        return f"<historical-run-root:{historical.group('run')}>{historical.group('suffix') or ''}"
    if raw == "/var/tmp" or raw.startswith("/var/tmp/"):
        return "<temporary-work-root>" + raw[len("/var/tmp") :]
    if raw == "/tmp" or raw.startswith("/tmp/"):
        return "<temporary-work-root>" + raw[len("/tmp") :]
    if raw == "/root" or raw.startswith("/root/"):
        return "<local-home-root>" + raw[len("/root") :]
    if raw.startswith("/home/") or raw.startswith("/Users/"):
        parts = raw.split("/", 3)
        return "<local-home-root>" + ("/" + parts[3] if len(parts) == 4 else "")
    return raw


def portable_markdown_text(markdown: str) -> str:
    """Replace local filesystem tokens in generated Markdown display text."""

    def replace(match: re.Match[str]) -> str:
        token = match.group("path")
        trailing = ""
        while token and token[-1] in ".,;:!?":
            trailing = token[-1] + trailing
            token = token[:-1]
        return portable_path_reference(token) + trailing

    return _LOCAL_PATH_TOKEN_RE.sub(replace, markdown)

REPORT_OUTPUTS = {
    ("connector_work_queue", "json"): "connector_work_queue.generated.json",
    ("connector_work_queue", "md"): "connector_work_queue.generated.md",
    ("phase_work_queue", "json"): "phase_work_queue.generated.json",
    ("phase_work_queue", "md"): "phase_work_queue.generated.md",
    ("phase_coverage", "md"): "phase_coverage.generated.md",
    ("full_runtime_matrix", "json"): "full_runtime_matrix.generated.json",
    ("runtime_component_cache", "json"): "runtime_component_cache.generated.json",
    ("mrts_native_full", "json"): "mrts_native_full.generated.json",
    ("mrts_native_full", "md"): "mrts_native_full.generated.md",
    ("mrts_native_apache", "json"): "mrts_native_apache.generated.json",
    ("mrts_native_apache", "md"): "mrts_native_apache.generated.md",
    ("mrts_native_nginx", "json"): "mrts_native_nginx.generated.json",
    ("mrts_native_nginx", "md"): "mrts_native_nginx.generated.md",
    ("mrts_native_summary", "json"): "mrts_native_summary.generated.json",
    ("mrts_native_summary", "md"): "mrts_native_summary.generated.md",
}

REPORT_OUTPUT_DIR = Path("reports/testing/generated")
FULL_RUNTIME_MATRIX_INPUT = Path("reports/testing/generated/canonical/full-runtime-matrix.generated.json")
GENERATED_REPORT_CATEGORIES = {
    "apache-runtime-results.generated.md": "runtime",
    "case-matrix.generated.md": "coverage",
    "connector-gap-summary.generated.md": "coverage",
    "coverage-summary.generated.md": "coverage",
    "haproxy-runtime-results.generated.md": "runtime",
    "mrts-native-apache.generated.md": "mrts-native",
    "mrts-native-full.generated.md": "mrts-native",
    "mrts-native-nginx.generated.md": "mrts-native",
    "mrts-native-summary.generated.md": "mrts-native",
    "nginx-runtime-results.generated.md": "runtime",
    "phase-coverage.generated.md": "coverage",
    "runtime-matrix.generated.md": "runtime",
    "xfail-summary.generated.md": "coverage",
}



def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _as_posix(path: Path | str) -> str:
    return str(Path(path))


def git_sha(root: Path | str | None) -> str:
    if root is None:
        return "unknown"
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=10,
        )
    except Exception:
        return "unknown"
    return result.stdout.strip() or "unknown"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def relative_label(path: Path, connector_root: Path, framework_root: Path) -> str:
    resolved = path.resolve(strict=False)
    for root in (connector_root, framework_root):
        try:
            return resolved.relative_to(root.resolve(strict=False)).as_posix()
        except ValueError:
            continue
    return portable_path_reference(resolved.as_posix())


def read_json_object(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def current_verified_run_id(connector_root: Path) -> str:
    explicit = os.environ.get("VERIFIED_RUN_ID", "").strip()
    if explicit:
        return explicit
    snapshot = read_json_object(connector_root / "reports/testing/runtime-validation-snapshot.json")
    for key in ("verified_run_id", "run_id"):
        value = str(snapshot.get(key) or "").strip()
        if value:
            return value
    snapshot_date = str(snapshot.get("snapshot_date") or "").strip()
    commit = str(snapshot.get("commit") or "").strip()
    if snapshot_date and commit:
        return f"{snapshot_date}-{commit}"
    sha = git_sha(connector_root)
    return sha[:12] if sha != "unknown" else "unknown"


def input_records(inputs: Iterable[Path | str], connector_root: Path, framework_root: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for raw in inputs:
        path = Path(raw)
        if not path.is_absolute():
            path = connector_root / path
        label = relative_label(path, connector_root, framework_root)
        if not path.exists():
            records.append(
                {
                    "path": label,
                    "status": "missing",
                    "source_hash": "missing",
                    "verified_run_id": "unknown",
                    "notes": "input file is missing",
                }
            )
            continue
        if not path.is_file():
            records.append(
                {
                    "path": label,
                    "status": "unknown",
                    "source_hash": "unknown",
                    "verified_run_id": "unknown",
                    "notes": "input path is not a regular file",
                }
            )
            continue
        size = path.stat().st_size
        records.append(
            {
                "path": label,
                "status": "empty" if size == 0 else "present",
                "source_hash": sha256_file(path) if size else "empty",
                "verified_run_id": current_verified_run_id(connector_root),
                "notes": "input file available" if size else "input file is empty",
            }
        )
    return records


def input_status_summary(records: list[dict[str, Any]]) -> str:
    statuses = {str(record.get("status") or "unknown") for record in records}
    if not records:
        return "unknown"
    if statuses == {"present"}:
        return "complete"
    if "missing" in statuses:
        return "missing"
    if "unknown" in statuses:
        return "unknown"
    return "partial"


def build_metadata(*, generated_by: str, make_target: str, connector_root: Path | str, framework_root: Path | str, inputs: Iterable[Path | str], generated_at: str | None = None) -> dict[str, Any]:
    connector = Path(connector_root).resolve(strict=False)
    framework = Path(framework_root).resolve(strict=False)
    records = input_records(inputs, connector, framework)
    return {
        "generated_notice": GENERATED_NOTICE,
        "generated_at": generated_at or utc_now(),
        "verified_run_id": current_verified_run_id(connector),
        "data_source_policy": DATA_SOURCE_POLICY,
        "generated_by": generated_by,
        "make_target": make_target,
        "owner": "runtime",
        "severity": "informational",
        "connector_root": "<repository-root>",
        "framework_root": "<framework-root>",
        "connector_sha": git_sha(connector),
        "framework_sha": git_sha(framework),
        "input_status": input_status_summary(records),
        "inputs": records,
        "missing_inputs": [record["path"] for record in records if record["status"] == "missing"],
        "empty_inputs": [record["path"] for record in records if record["status"] == "empty"],
        "unknown_inputs": [record["path"] for record in records if record["status"] == "unknown"],
        "schema_version": 1,
    }



def trusted_root(value: Path | str, label: str) -> Path:
    reject_path_traversal(value, label)
    return Path(value).resolve()


def require_existing_file_under_approved_roots(candidate: Path | str, approved_roots: Iterable[Path | str], label: str) -> Path:
    reject_path_traversal(candidate, label)
    candidate_path = Path(candidate).resolve(strict=True)
    if not candidate_path.is_file():
        raise ValueError(f"{label} must be a regular file: {candidate_path}")
    for root in approved_roots:
        root_path = Path(root).resolve()
        try:
            candidate_path.relative_to(root_path)
            return candidate_path
        except ValueError:
            continue
    roots = ", ".join(str(Path(root).resolve()) for root in approved_roots)
    raise ValueError(f"{label} must stay under approved roots ({roots}): {candidate_path}")


def metadata_path_label(path: Path, approved_root: Path, root_label: str) -> str:
    resolved = path.resolve(strict=False)
    root = approved_root.resolve()
    try:
        relative = resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"metadata path must stay under {root}: {resolved}") from exc
    return f"{root_label}/{relative.as_posix()}"


def resolve_full_runtime_matrix_input(connector_root: Path, explicit_full_matrix: Path | None) -> Path:
    if explicit_full_matrix is not None:
        return require_existing_file_under_approved_roots(explicit_full_matrix, [connector_root], "full runtime matrix")
    return require_under(connector_root, FULL_RUNTIME_MATRIX_INPUT, "default full runtime matrix")


def generated_report_dir(output_root: Path) -> Path:
    return require_under(output_root, REPORT_OUTPUT_DIR, "generated report directory")


def connector_work_queue_output_path(output_dir: Path, suffix: str) -> Path:
    if suffix not in {"json", "md"}:
        raise ValueError(f"unsupported connector work queue output suffix: {suffix}")
    return report_path_from_root(output_dir, "connector_work_queue", suffix)

def report_path_from_root(root: Path | str, name: str, suffix: str) -> Path:
    filename = REPORT_OUTPUTS.get((name, suffix))
    if filename is None:
        raise ValueError(f"unsupported generated report output: {name}.{suffix}")
    return require_under(Path(root).resolve(), Path("canonical") / filename, f"generated report {name}.{suffix}")


def report_relpath_for_filename(filename: str | Path) -> str:
    name = Path(filename).name
    category = GENERATED_REPORT_CATEGORIES.get(name)
    if category is None:
        raise ValueError(f"unsupported generated report filename: {name}")
    return (REPORT_OUTPUT_DIR / category / name).as_posix()


def reject_path_traversal(value: Path | str, label: str) -> None:
    raw = str(value)
    path = Path(raw)
    if any(part in {"..", ""} for part in path.parts):
        raise ValueError(f"{label} contains unsafe traversal or empty path segment: {raw}")


def require_under(root: Path | str, candidate: Path | str, label: str) -> Path:
    reject_path_traversal(candidate, label)
    root_path = Path(root).resolve()
    candidate_path = Path(candidate)
    if not candidate_path.is_absolute():
        candidate_path = root_path / candidate_path
    resolved = candidate_path.resolve(strict=False)
    try:
        resolved.relative_to(root_path)
    except ValueError as exc:
        raise ValueError(f"{label} must stay under {root_path}: {resolved}") from exc
    parent = resolved.parent
    existing_parent = parent
    while not existing_parent.exists() and existing_parent != existing_parent.parent:
        existing_parent = existing_parent.parent
    try:
        existing_resolved = existing_parent.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"{label} parent must be resolvable: {parent}") from exc
    try:
        existing_resolved.relative_to(root_path)
    except ValueError:
        try:
            root_path.relative_to(existing_resolved)
        except ValueError as exc:
            raise ValueError(f"{label} parent must stay under {root_path}: {parent}") from exc
    if existing_parent.is_symlink() and existing_resolved != existing_parent.resolve(strict=False):
        raise ValueError(f"{label} parent resolves through an unsafe symlink: {existing_parent}")
    return resolved

def generated_json_text(payload: Any, metadata: dict[str, Any]) -> str:
    document = {"metadata": metadata, "data": payload}
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def generated_markdown_text(body: str, metadata: dict[str, Any]) -> str:
    text = body.strip()
    availability_marker = "\n## Data Availability / Missing Information"
    if availability_marker in text:
        text = text.split(availability_marker, 1)[0].rstrip()
    sources_marker = "\n## Data Sources"
    if sources_marker in text:
        text = text.split(sources_marker, 1)[0].rstrip()
    switch = language_switch(str(metadata.get("output_name") or ""))
    if switch is not None:
        text = insert_language_switch(text, switch[1], switch[0])
    text = portable_markdown_text(text)
    header = [
        f"> {GENERATED_NOTICE}",
        ">",
        f"> Generated at: `{metadata.get('generated_at', 'unknown')}`",
        f"> Verified run id: `{metadata.get('verified_run_id', 'unknown')}`",
        f"> Data source policy: `{metadata.get('data_source_policy', DATA_SOURCE_POLICY)}`",
        f"> Generator: `{metadata.get('generated_by', 'unknown')}`",
        f"> Make target: `{metadata.get('make_target', 'unknown')}`",
        f"> Owner: `{metadata.get('owner', 'unknown')}`",
        f"> Severity: `{metadata.get('severity', 'unknown')}`",
        f"> Connector SHA: `{metadata.get('connector_sha', 'unknown')}`",
        f"> Framework SHA: `{metadata.get('framework_sha', 'unknown')}`",
        f"> Input status: `{metadata.get('input_status', 'unknown')}`",
        "",
    ]
    return "\n".join(header) + "\n" + text + "\n\n" + data_sources_section(metadata) + "\n\n" + missing_information_section(metadata) + "\n"


def language_switch(output_name: str) -> tuple[str, str] | None:
    if not output_name.endswith(".md"):
        return None
    if output_name.endswith(".de.md"):
        english_name = output_name.removesuffix(".de.md") + ".md"
        return "**Sprache:**", f"**Sprache:** [English]({english_name}) | Deutsch"
    german_name = output_name.removesuffix(".md") + ".de.md"
    return "**Language:**", f"**Language:** English | [Deutsch]({german_name})"


def insert_language_switch(markdown: str, switch: str, prefix: str) -> str:
    lines = [line for line in markdown.splitlines() if not line.startswith(prefix)]
    try:
        heading_index = next(index for index, line in enumerate(lines) if line.startswith("# "))
    except StopIteration:
        return "\n".join([switch, "", *lines]).strip()
    before = lines[: heading_index + 1]
    after = lines[heading_index + 1 :]
    while after and not after[0].strip():
        after.pop(0)
    return "\n".join([*before, "", switch, "", *after]).strip()


def data_sources_section(metadata: dict[str, Any]) -> str:
    lines = [
        "## Data Sources",
        "",
        "| Value | Source | Source Hash | Verified Run ID | Status |",
        "|---|---|---|---|---|",
    ]
    records = metadata.get("inputs")
    if not isinstance(records, list) or not records:
        lines.append("| Declared inputs | `-` | `unknown` | `unknown` | unknown |")
    else:
        for record in records:
            source = portable_markdown_text(str(record.get("path", "-"))).replace("|", "\\|")
            source_hash = str(record.get("source_hash") or "unknown")
            run_id = str(record.get("verified_run_id") or metadata.get("verified_run_id") or "unknown")
            status = str(record.get("status") or "unknown")
            lines.append(f"| Declared input | `{source}` | `{source_hash}` | `{run_id}` | {status} |")
    return "\n".join(lines)


def missing_information_section(metadata: dict[str, Any]) -> str:
    lines = [
        "## Data Availability / Missing Information",
        "",
        "| Input | Status | Notes |",
        "|---|---|---|",
    ]
    records = metadata.get("inputs")
    if not isinstance(records, list) or not records:
        lines.append("| `-` | unknown | no input files were declared for this generated report |")
    else:
        for record in records:
            path = portable_markdown_text(str(record.get("path", "-"))).replace("|", "\\|")
            status = str(record.get("status") or "unknown")
            notes = portable_markdown_text(str(record.get("notes") or "-")).replace("|", "\\|")
            lines.append(f"| `{path}` | {status} | {notes} |")
    return "\n".join(lines)
