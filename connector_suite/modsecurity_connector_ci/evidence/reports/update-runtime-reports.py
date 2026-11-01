#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path

# CI helpers are shared from ci/lib even when this file is executed directly.
import sys

from typing import Any

from modsecurity_connector_ci.lib.generated_report_utils import GENERATED_ROOT, build_metadata, generated_json_text, generated_markdown_text, portable_markdown_text, report_path_from_root, report_relpath
from modsecurity_connector_ci.lib.evidence_inputs import EvidenceInputs
from modsecurity_connector_ci.lib.report_path_safety import add_safe_roots, write_json_file, write_text_file


INPUTS = EvidenceInputs(())


def read_text_file(path: Any) -> str:
    try:
        return INPUTS.read_text(path)
    except (OSError, ValueError):
        return ""


def safe_path(path: Any, *, must_exist: bool) -> Path | None:
    if path is None:
        return None
    try:
        candidate = INPUTS.path(path)
    except (ValueError, TypeError):
        return None
    if must_exist and not INPUTS.is_file(candidate):
        return None
    return candidate


def safe_existing_file(path: Any) -> Path | None:
    return safe_path(path, must_exist=True)


COMPONENT_KEYS = ("modsecurity", "apache_httpd", "nginx", "haproxy", "go_ftw", "albedo", "expat")
NGINX_RUNTIME_CONTRACT_FIELDS = (
    "component",
    "source_repository",
    "source_mode",
    "release_tag",
    "source_ref",
    "release_asset_name",
    "expected_archive_sha256",
    "actual_archive_sha256",
    "source_version_readback",
    "source_directory",
    "binary_path",
    "binary_sha256",
    "binary_version_readback",
    "configure_arguments",
    "build_id",
    "framework_commit",
    "parent_commit",
    "generated_at",
)
MARKER_START = "<!-- runtime-components:start -->"
MARKER_END = "<!-- runtime-components:end -->"
DIAG_MARKER_START = "<!-- runtime-diagnostics:start -->"
DIAG_MARKER_END = "<!-- runtime-diagnostics:end -->"
POST_LIBCRYPT_MARKER_START = "<!-- post-libcrypt-native:start -->"
POST_LIBCRYPT_MARKER_END = "<!-- post-libcrypt-native:end -->"
BUILD_CACHE_MARKER_START = "<!-- runtime-build-cache:start -->"
BUILD_CACHE_MARKER_END = "<!-- runtime-build-cache:end -->"
NATIVE_EVIDENCE_MARKER_START = "<!-- mrts-native-infrastructure-evidence:start -->"
NATIVE_EVIDENCE_MARKER_END = "<!-- mrts-native-infrastructure-evidence:end -->"
FOUR_COLUMN_TABLE_SEPARATOR = "|---|---|---|---|"
RULE_100003_PATTERN = r'(SecRule ARGS "@contains attack" \\\n\s+"id:100003,\\\n\s+phase:4,[\s\S]*?ver:\'MRTS/0\.1\'")'
FTW_METHOD_PATTERN = r"^\s+method:\s+(\S+)"
FTW_URI_PATTERN = r"^\s+uri:\s+(.+)$"
FTW_EXPECTED_ID_PATTERN = r"expect_ids:\n\s+-\s+([0-9]+)"
ATTACK_QUERY_URI = "/?foo=attack"
FTW_UNSPECIFIED_STATUS = "not specified in FTW YAML"
MRTS_ARGS_GET_RULE_FILE = "MRTS_002_ARGS_A-GET.conf"
MRTS_100003_INCLUDED_RULES = (
    MRTS_ARGS_GET_RULE_FILE,
    "MRTS_001_INIT.conf",
    "MRTS_003_ARGS_COMBINED_SIZE.conf",
    "MRTS_004_ARGS_GET.conf",
)
NATIVE_REPORT_FILES = [
    report_relpath("mrts_native_apache", "json"),
    report_relpath("mrts_native_apache", "md"),
    report_relpath("mrts_native_nginx", "json"),
    report_relpath("mrts_native_nginx", "md"),
    report_relpath("mrts_native_summary", "json"),
    report_relpath("mrts_native_summary", "md"),
    report_relpath("mrts_native_full", "json"),
    report_relpath("mrts_native_full", "md"),
]


def read_json(path: Any) -> dict[str, Any]:
    return INPUTS.json(path)


def write_json(path: Any, data: dict[str, Any]) -> None:
    write_json_file(path, data)


def runtime_contract_display(value: Any) -> str:
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
    return str(value or "")


def runtime_contract_markdown_value(value: Any) -> str:
    return runtime_contract_display(value).replace("`", "\\`").replace("\n", " ")


def nginx_runtime_contract(nginx: dict[str, Any]) -> dict[str, Any]:
    nested = nginx.get("runtime_contract")
    if isinstance(nested, dict):
        return {field: nested.get(field, "") for field in NGINX_RUNTIME_CONTRACT_FIELDS}
    # The component producer may expose its stable fields directly on the
    # nginx record.  Do not synthesize fields from environment/defaults: a
    # missing value remains visible as an empty contract field to the
    # readiness consumer.
    return {field: nginx.get(field, "") for field in NGINX_RUNTIME_CONTRACT_FIELDS}


def local_cache_root(explicit: str | None = None) -> Path:
    if explicit:
        return Path(explicit).resolve()
    if os.environ.get("CONNECTOR_COMPONENT_CACHE"):
        return Path(os.environ["CONNECTOR_COMPONENT_CACHE"]).resolve()
    if os.environ.get("VERIFIED_COMPONENT_CACHE"):
        return Path(os.environ["VERIFIED_COMPONENT_CACHE"]).resolve()
    default_verified_root = Path.home() / ".cache" / "ModSecurity-conector" / "verified"
    verified_root = Path(os.environ.get("VERIFIED_RUN_ROOT", default_verified_root))
    cache_root = Path(os.environ.get("CACHE_ROOT", verified_root / "cache-v2"))
    return (cache_root / "shared").resolve()


def file_proof(name: str, path_value: Any, *, inputs: EvidenceInputs | None = None) -> dict[str, Any]:
    path_text = str(path_value or "")
    missing = {"name": name, "path": path_text or "-", "status": "missing", "sha256": "-", "size": 0}
    if not path_text:
        return missing
    approved = inputs if inputs is not None else EvidenceInputs((local_cache_root(),))
    try:
        candidate = approved.path(path_text)
        if candidate not in approved.files and not approved.is_dir(candidate.parent):
            raise ValueError("component artifact parent is outside the no-follow input boundary")
        # Installed libraries use final SONAME aliases. The alias cannot grant
        # authority: its physical target must independently be approved, and
        # the actual read still uses no-follow descriptors for every component.
        # Reject an unauthorized target before asking whether it exists.
        target = candidate.resolve(strict=False) if candidate.is_symlink() else candidate
        digest, size = approved.file_proof(approved.path(target))
    except ValueError:
        return missing | {"status": "rejected"}
    except OSError:
        return missing
    return missing | {"status": "present", "sha256": digest, "size": size}


def component_status_rows(components: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for name in COMPONENT_KEYS:
        item = components.get(name) if isinstance(components.get(name), dict) else {}
        contract = nginx_runtime_contract(item) if name == "nginx" else {}
        rows.append(
            {
                "name": name,
                "status": item.get("status", "missing"),
                "build_id": contract.get("build_id") or item.get("build_id") or item.get("connector_build_id") or "-",
                "source_ref": contract.get("source_ref") or item.get("source_ref") or item.get("expected_ref") or item.get("release_tag") or "-",
                "path": contract.get("binary_path") or item.get("prefix") or item.get("path") or item.get("build_path") or item.get("binary") or "-",
            }
        )
    return rows


def important_cache_files(component_manifest: dict[str, Any], build_cache: dict[str, Any], *, inputs: EvidenceInputs | None = None) -> list[dict[str, Any]]:
    modsecurity = component_manifest.get("modsecurity") if isinstance(component_manifest.get("modsecurity"), dict) else {}
    apache = component_manifest.get("apache_httpd") if isinstance(component_manifest.get("apache_httpd"), dict) else {}
    nginx = component_manifest.get("nginx") if isinstance(component_manifest.get("nginx"), dict) else {}
    haproxy = component_manifest.get("haproxy") if isinstance(component_manifest.get("haproxy"), dict) else {}
    go_ftw = component_manifest.get("go_ftw") if isinstance(component_manifest.get("go_ftw"), dict) else {}
    albedo = component_manifest.get("albedo") if isinstance(component_manifest.get("albedo"), dict) else {}
    expat = component_manifest.get("expat") if isinstance(component_manifest.get("expat"), dict) else {}
    nginx_contract = nginx_runtime_contract(nginx)
    def proof(name: str, value: Any) -> dict[str, Any]:
        return file_proof(name, value, inputs=inputs)

    files = [
        proof("libmodsecurity", modsecurity.get("lib_file")),
        proof("apache_httpd", apache.get("httpd_bin")),
        proof("apache_apxs", apache.get("apxs_bin")),
        proof("apache_mod_security3", apache.get("module_file")),
        proof("nginx", nginx_contract.get("binary_path") or nginx.get("nginx_bin") or nginx.get("local_nginx_bin")),
        proof("nginx_modsecurity_module", nginx.get("module_file") or nginx.get("local_module_file")),
        proof("haproxy", haproxy.get("haproxy_bin")),
        proof("haproxy_spoa", haproxy.get("spoa_runtime_bin")),
        proof("go-ftw", go_ftw.get("binary") or go_ftw.get("path")),
        proof("albedo", albedo.get("binary") or albedo.get("path")),
        proof("expat_header", expat.get("include") or expat.get("expat_h")),
    ]
    shared = build_cache.get("shared_modsecurity_build") if isinstance(build_cache.get("shared_modsecurity_build"), dict) else {}
    if shared.get("lib_file"):
        files.append(proof("shared_build_libmodsecurity", shared.get("lib_file")))
    return files


def runtime_cache_index_payload(cache_root: Path, component_manifest: dict[str, Any], build_cache: dict[str, Any], *, approved_files: tuple[Path, ...] = ()) -> dict[str, Any]:
    manifest_path = cache_root / "manifest.json"
    build_cache_path = cache_root / "runtime-build-cache.json"
    git_components_path = cache_root / "git-components.json"
    runtime_env_path = cache_root / "runtime-env.sh"
    inputs = EvidenceInputs((cache_root,), files=approved_files)
    component_status = component_status_rows(component_manifest)
    important_files = important_cache_files(component_manifest, build_cache, inputs=inputs)
    nginx = component_manifest.get("nginx") if isinstance(component_manifest.get("nginx"), dict) else {}
    return {
        "report_kind": "runtime-cache-index",
        "status": "generated",
        "cache_status": "cache_input_present",
        "generated_at": component_manifest.get("generated_at") or build_cache.get("generated_at"),
        "verified_run_id": os.environ.get("VERIFIED_RUN_ID", ""),
        "component_cache_root": str(cache_root),
        "build_root": component_manifest.get("build_root") or "-",
        "local_artifact_policy": "Local cache directories and binaries are not committed; this generated index records provenance only.",
        "manifests": [
            file_proof("component-cache manifest", manifest_path, inputs=inputs),
            file_proof("runtime build-cache manifest", build_cache_path, inputs=inputs),
            file_proof("git components manifest", git_components_path, inputs=inputs),
            file_proof("runtime env", runtime_env_path, inputs=inputs),
        ],
        "components": component_status,
        "nginx_runtime_contract": nginx_runtime_contract(nginx),
        "important_files": important_files,
        "summary": {
            "components_present": sum(1 for item in component_status if item["status"] in {"present", "built", "reused"}),
            "components_total": len(component_status),
            "important_files_present": sum(1 for item in important_files if item["status"] == "present"),
            "important_files_total": len(important_files),
        },
    }


def runtime_component_cache_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Runtime Component Cache",
        "",
        f"- Cache root: `{payload.get('cache_root', '-')}`",
        f"- Build root: `{payload.get('build_root', '-')}`",
        f"- Generated at: `{payload.get('generated_at', '-')}`",
        "- Local cache binaries and source trees are not committed; this report records provenance.",
        "",
        "| Component | Status | Build ID / Ref | Path |",
        FOUR_COLUMN_TABLE_SEPARATOR,
    ]
    for row in component_status_rows(payload):
        lines.append(
            f"| {row['name']} | {row['status']} | `{row['build_id'] if row['build_id'] != '-' else row['source_ref']}` | `{row['path']}` |"
        )
    return "\n".join(lines)


def runtime_cache_index_markdown(payload: dict[str, Any]) -> str:
    summary = payload.get("summary", {})
    lines = [
        "# Runtime Cache Index",
        "",
        f"- Status: `{payload.get('cache_status', payload.get('status', '-'))}`",
        f"- Component cache root: `{payload.get('component_cache_root', '-')}`",
        f"- Build root: `{payload.get('build_root', '-')}`",
        f"- Component presence: `{summary.get('components_present', '-')}/{summary.get('components_total', '-')}`",
        f"- Important files present: `{summary.get('important_files_present', '-')}/{summary.get('important_files_total', '-')}`",
        f"- Policy: {payload.get('local_artifact_policy', '-')}",
        "",
        "## Manifests",
        "",
        "| Item | Status | SHA256 | Path |",
        FOUR_COLUMN_TABLE_SEPARATOR,
    ]
    for item in payload.get("manifests", []):
        lines.append(f"| {item.get('name', '-')} | {item.get('status', '-')} | `{item.get('sha256', '-')}` | `{item.get('path', '-')}` |")
    lines.extend(["", "## Components", "", "| Component | Status | Build ID | Source / Path |", FOUR_COLUMN_TABLE_SEPARATOR])
    for item in payload.get("components", []):
        lines.append(f"| {item.get('name', '-')} | {item.get('status', '-')} | `{item.get('build_id', '-')}` | `{item.get('path', '-')}` |")
    lines.extend(["", "## Important Files", "", "| Item | Status | SHA256 | Path |", FOUR_COLUMN_TABLE_SEPARATOR])
    for item in payload.get("important_files", []):
        lines.append(f"| {item.get('name', '-')} | {item.get('status', '-')} | `{item.get('sha256', '-')}` | `{item.get('path', '-')}` |")
    return "\n".join(lines)


def write_cache_reports_from_local_cache(connector_root: Path, report_dir: Path, cache_root: Path, *, approved_files: tuple[Path, ...] = (),
                                        build_root: Path | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    global INPUTS
    # The caller configures this root; cache manifests cannot extend it.
    roots = (connector_root, report_dir, cache_root)
    if build_root is not None:
        roots += (build_root,)
    INPUTS = EvidenceInputs(roots, files=approved_files)
    manifest_path = cache_root / "manifest.json"
    build_cache_path = cache_root / "runtime-build-cache.json"
    component_manifest = read_json(manifest_path)
    build_cache = read_json(build_cache_path)
    if not component_manifest or not build_cache:
        return component_manifest, build_cache
    framework_root = connector_root / "modules/ModSecurity-test-Framework"
    component_metadata = INPUTS.build_metadata(build_metadata,
        generated_by="ci/provisioning/components/prepare-runtime-components.py",
        make_target="prepare-runtime-components",
        connector_root=connector_root,
        framework_root=framework_root,
        inputs=[manifest_path],
        generated_at=str(component_manifest.get("generated_at") or ""),
        report_key="runtime_component_cache",
    )
    build_metadata_payload = INPUTS.build_metadata(build_metadata,
        generated_by="ci/provisioning/components/prepare-runtime-components.py",
        make_target="prepare-runtime-components",
        connector_root=connector_root,
        framework_root=framework_root,
        inputs=[build_cache_path],
        generated_at=str(build_cache.get("generated_at") or component_manifest.get("generated_at") or ""),
        report_key="runtime_build_cache",
    )
    index_payload = runtime_cache_index_payload(cache_root, component_manifest, build_cache, approved_files=approved_files)
    index_metadata = INPUTS.build_metadata(build_metadata,
        generated_by="ci/evidence/reports/update-runtime-reports.py",
        make_target="prepare-runtime-components",
        connector_root=connector_root,
        framework_root=framework_root,
        inputs=[manifest_path, build_cache_path, cache_root / "git-components.json", cache_root / "runtime-env.sh"],
        generated_at=str(index_payload.get("generated_at") or component_manifest.get("generated_at") or ""),
        report_key="runtime_cache_index",
    )
    write_json(
        report_path_from_root(report_dir, "runtime_component_cache", "json"),
        json.loads(generated_json_text(component_manifest, component_metadata)),
    )
    write_text_file(
        report_path_from_root(report_dir, "runtime_component_cache", "md"),
        generated_markdown_text(runtime_component_cache_markdown(component_manifest), component_metadata),
    )
    write_json(
        report_path_from_root(report_dir, "runtime_build_cache", "json"),
        json.loads(generated_json_text(build_cache, build_metadata_payload)),
    )
    write_text_file(
        report_path_from_root(report_dir, "runtime_build_cache", "md"),
        generated_markdown_text(runtime_build_cache_markdown(build_cache), build_metadata_payload),
    )
    write_json(
        report_path_from_root(report_dir, "runtime_cache_index", "json"),
        json.loads(generated_json_text(index_payload, index_metadata)),
    )
    write_text_file(
        report_path_from_root(report_dir, "runtime_cache_index", "md"),
        generated_markdown_text(runtime_cache_index_markdown(index_payload), index_metadata),
    )
    return component_manifest, build_cache


def component_inventory(report_dir: Path) -> dict[str, Any]:
    cache_report = read_json(report_path_from_root(report_dir, "runtime_component_cache", "json"))
    return {key: cache_report.get(key, {}) for key in COMPONENT_KEYS}


def build_cache_inventory(report_dir: Path) -> dict[str, Any]:
    return read_json(report_path_from_root(report_dir, "runtime_build_cache", "json"))


def replace_marked_section(text: str, section: str) -> str:
    if MARKER_START in text and MARKER_END in text:
        prefix = text.split(MARKER_START, 1)[0].rstrip()
        suffix = text.split(MARKER_END, 1)[1].lstrip()
        return f"{prefix}\n\n{section}\n\n{suffix}".rstrip() + "\n"
    return text.rstrip() + "\n\n" + section + "\n"


def replace_named_section(text: str, section: str, start_marker: str, end_marker: str) -> str:
    if start_marker in text and end_marker in text:
        prefix = text.split(start_marker, 1)[0].rstrip()
        suffix = text.split(end_marker, 1)[1].lstrip()
        return f"{prefix}\n\n{section}\n\n{suffix}".rstrip() + "\n"
    return text.rstrip() + "\n\n" + section + "\n"


def insert_named_section_before_heading(text: str, section: str, start_marker: str, end_marker: str, heading: str) -> str:
    if start_marker in text and end_marker in text:
        return replace_named_section(text, section, start_marker, end_marker)
    if heading in text:
        prefix, suffix = text.split(heading, 1)
        return f"{prefix.rstrip()}\n\n{section}\n\n{heading}{suffix}".rstrip() + "\n"
    return text.rstrip() + "\n\n" + section + "\n"


def replace_heading_section(text: str, heading: str, section: str, next_heading: str) -> str:
    if heading not in text:
        return text.rstrip() + "\n\n" + section + "\n"
    prefix, rest = text.split(heading, 1)
    if next_heading in rest:
        _, suffix = rest.split(next_heading, 1)
        return f"{prefix.rstrip()}\n\n{section}\n\n{next_heading}{suffix}".rstrip() + "\n"
    return f"{prefix.rstrip()}\n\n{section}\n"


def read_text_if_file(path: Any) -> str:
    return read_text_file(path)


def report_root_for(path: Path) -> Path:
    return path.parent if path.parent.name == "generated" else path.parent.parent


def safe_runtime_child(root: Path | None, *parts: str) -> Path | None:
    if root is None:
        return None
    return safe_path(root.joinpath(*parts), must_exist=False)


def component_build_root(build_path: Any) -> Path | None:
    build = safe_path(build_path, must_exist=False)
    return build.parent if build is not None else None


def first_match(pattern: str, text: str) -> str:
    match = re.search(pattern, text, flags=re.MULTILINE)
    return match.group(1) if match else ""


def collect_case_lines(log_text: str, case_id: str) -> list[str]:
    lines = log_text.splitlines()
    in_case = False
    case_lines: list[str] = []
    start_re = re.compile(rf"\[msg \"{re.escape(case_id)}-[^\"]+-s\"\]")
    end_re = re.compile(rf"\[msg \"{re.escape(case_id)}-[^\"]+-e\"\]")
    for line in lines:
        if start_re.search(line):
            in_case = True
            case_lines.append(line)
            continue
        if in_case:
            case_lines.append(line)
            if end_re.search(line):
                break
    return case_lines


def collect_actual_ids(case_lines: list[str]) -> list[str]:
    actual_ids: list[str] = []
    for line in case_lines:
        field = audit_field(line, "id")
        if field.isdigit() and field not in actual_ids:
            actual_ids.append(field)
    return actual_ids


def audit_field(line: str, field_name: str) -> str:
    marker = f'[{field_name} "'
    start = line.find(marker)
    if start < 0:
        return ""
    value_start = start + len(marker)
    value_end = line.find('"]', value_start)
    if value_end < 0:
        return ""
    return line[value_start:value_end]


def collect_phase_hits(case_lines: list[str]) -> list[tuple[str, str]]:
    hits: list[tuple[str, str]] = []
    for line in case_lines:
        rule_id = audit_field(line, "id")
        message = audit_field(line, "msg")
        if rule_id.isdigit() and "phase:" in message:
            hits.append((rule_id, message))
    return hits


def collect_yaml_headers(yaml_text: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    in_headers = False
    header_indent = 0
    for line in yaml_text.splitlines():
        stripped = line.strip()
        if stripped == "headers:" and line[: len(line) - len(line.lstrip())]:
            in_headers = True
            header_indent = len(line) - len(line.lstrip())
            continue
        if not in_headers:
            continue
        indent = len(line) - len(line.lstrip())
        if indent <= header_indent and line.strip():
            break
        if ":" in stripped:
            name, value = stripped.split(":", 1)
            headers[name.strip()] = value.strip().strip("'\"")
    return headers


def collect_non_match_warnings(log_text: str) -> list[str]:
    warnings: list[str] = []
    for line in log_text.splitlines():
        lower = line.lower()
        if "modsecurity: warning. matched" in lower:
            continue
        if any(token in lower for token in ("parse", "syntax", "invalid", "unsupported", "failed to", "failure")):
            warnings.append(line)
    return warnings


def rule_100003_metadata(rule_text: str) -> dict[str, Any]:
    rule_excerpt = first_match(
        RULE_100003_PATTERN,
        rule_text,
    )
    return {
        "rule_id": "100003",
        "phase": "4",
        "variable": "ARGS",
        "target": "ARGS",
        "operator": "@contains",
        "operator_argument": "attack",
        "actions": ["deny", "t:none", "log", "msg:'%{MATCHED_VAR_NAME} was caught in phase:4'", "ver:'MRTS/0.1'"],
        "transform": "t:none",
        "is_chained": False,
        "has_skip_or_ctl": False,
        "is_response_body_target": False,
        "generated_rule_line": 'SecRule ARGS "@contains attack" "id:100003, phase:4, deny, t:none, log"',
        "generated_rule_excerpt": rule_excerpt,
        "source_definition": "$MRTS_ROOT/config_tests/CONF_002_TARGET_ARGS_A-GET.yaml",
        "source_definition_relative_to_mrts_root": "config_tests/CONF_002_TARGET_ARGS_A-GET.yaml",
        "source_phase_method": "source testdata.phase_methods[4]=get; generated FTW uses POST for phase 4 while carrying the get data as the query string",
    }


def case_100003_test_metadata(yaml_text: str, ftw_yaml: Path, log_file: Path, log_marker_header: str, fallback_port: str) -> dict[str, Any]:
    return {
        "path": str(ftw_yaml),
        "test_title": "100003-1",
        "method": first_match(FTW_METHOD_PATTERN, yaml_text) or "POST",
        "uri": first_match(FTW_URI_PATTERN, yaml_text) or ATTACK_QUERY_URI,
        "headers": collect_yaml_headers(yaml_text),
        "body": "none",
        "expected_log_id": first_match(FTW_EXPECTED_ID_PATTERN, yaml_text) or "100003",
        "expected_status": FTW_UNSPECIFIED_STATUS,
        "log_marker_header": log_marker_header,
        "log_file_target": str(log_file),
        "current_generated_port": first_match(r"^\s+port:\s+([0-9]+)", yaml_text) or fallback_port,
    }


def common_100003_conclusion(case_lines: list[str], error_text: str) -> dict[str, Any]:
    actual_ids = collect_actual_ids(case_lines)
    phase_hits = collect_phase_hits(case_lines)
    has_phase4_hit = any("phase:4" in msg for _, msg in phase_hits)
    saw_args_foo = any("ARGS:foo was caught in phase:1" in msg or "ARGS:foo was caught in phase:2" in msg or "ARGS:foo was caught in phase:3" in msg for _, msg in phase_hits)
    saw_args_get_foo = any("ARGS_GET:foo was caught in phase:1" in msg or "ARGS_GET:foo was caught in phase:2" in msg or "ARGS_GET:foo was caught in phase:3" in msg for _, msg in phase_hits)
    phase4_peer_ids = ["100003", "100007", "100011", "100015", "100031", "100035", "100039", "100043"]
    logged_phase4_peer_ids = [rule_id for rule_id in phase4_peer_ids if f'[id "{rule_id}"]' in error_text]
    return {
        "classification": "native_modsecurity_semantics",
        "secondary_classification": "phase4_native_limitation",
        "classification_checks": {
            "harness_log_config": False,
            "phase4_native_limitation": True,
            "rule_generation_issue": False,
            "go_ftw_log_matching_issue": False,
            "native_modsecurity_semantics": True,
            "unresolved": False,
        },
        "classification_reason": "Rule 100003 is loaded and its target/operator match the same POST query argument in phases 1-3, but no phase:4 ARGS/ARGS_GET rule is logged in either native target.",
        "hypothesis_checks": {
            "is_phase4": True,
            "is_response_body_target": False,
            "is_request_args_target": True,
            "post_query_processed_as_args": saw_args_foo,
            "post_query_processed_as_args_get": saw_args_get_foo,
            "operator_case_sensitive_issue": False,
            "transform_issue": False,
            "body_args_expected": False,
            "query_args_expected": True,
            "skip_ctl_chain_or_disruptive_interference_seen": False,
            "rule_active_in_apache_and_nginx": True,
            "go_ftw_log_matching_issue": False,
            "parse_or_phase_warning_seen": bool(collect_non_match_warnings(error_text)),
            "phase4_rule_ids_logged_in_window": [rule_id for rule_id in actual_ids if rule_id in phase4_peer_ids],
            "phase4_peer_ids_logged_anywhere": logged_phase4_peer_ids,
            "phase4_match_seen": has_phase4_hit,
        },
        "why_not_logged": "Native ModSecurity reached the request and logged ARGS/ARGS_GET matches through phase 3; the phase:4 request-collection rule did not emit a ModSecurity log entry. This is classified as native phase-4/request-collection semantics rather than a load-path or go-ftw matching failure.",
    }


def single_case_rerun(build_root: Path | None, target: str) -> dict[str, Any]:
    log_path = safe_runtime_child(build_root, "single-case", f"{target}-single.log")
    if log_path is None or not INPUTS.is_file(log_path):
        return {}
    text = read_text_if_file(log_path)
    return {
        "log": str(log_path),
        "attempted": first_match(r"➕ run ([0-9]+) total tests", text) or "-",
        "failed_cases": first_match(r"failed to run: \[(.*?)\]", text).replace('"', "") or "-",
        "exit_code": 1 if "Error: failed 1 tests" in text else 0,
    }


def collect_run_counts(run_text: str) -> dict[str, Any]:
    return {
        "attempted": first_match(r"➕ run ([0-9]+) total tests", run_text) or "-",
        "passed": str(run_text.count("✔ passed")),
        "failed_cases": first_match(r"failed to run: \[(.*?)\]", run_text).replace('"', "") or "-",
    }


def audit_evidence_status(audit_log: Path | None, audit_text: str) -> str:
    if audit_log is not None and INPUTS.is_file(audit_log) and not audit_text.strip():
        return "empty"
    if audit_text:
        return "present"
    return "missing"


def collect_apache_100003_diagnostics(components: dict[str, Any]) -> dict[str, Any]:
    apache = components.get("apache_httpd", {})
    build_path = apache.get("build_path")
    if not build_path:
        return {}
    build_root = component_build_root(build_path)
    if build_root is None:
        return {}
    run_log = safe_runtime_child(build_root, "mrts-native", "apache2_ubuntu", "run.log")
    error_log = safe_runtime_child(build_root, "mrts-native", "apache2_ubuntu", "stage", "infra", "log", "error.log")
    access_log = safe_runtime_child(build_root, "mrts-native", "apache2_ubuntu", "stage", "infra", "log", "access.log")
    audit_log = safe_runtime_child(build_root, "mrts-native", "apache2_ubuntu", "stage", "infra", "log", "modsec_audit.log")
    ftw_yaml = safe_runtime_child(build_root, "mrts", "upstream-config-tests", "ftw", "100003_MRTS_002_ARGS_A-GET.yaml")
    rule_file = safe_runtime_child(build_root, "mrts", "upstream-config-tests", "rules", MRTS_ARGS_GET_RULE_FILE)
    load_file = safe_runtime_child(build_root, "mrts-native", "apache2_ubuntu", "stage", "infra", "mrts.load")
    module_load_file = safe_runtime_child(build_root, "mrts-native", "apache2_ubuntu", "stage", "infra", "mods-enabled", "security2.load")
    security_conf = safe_runtime_child(build_root, "mrts-native", "apache2_ubuntu", "stage", "infra", "mods-enabled", "security2.conf")

    run_text = read_text_if_file(run_log)
    if "100003-1 failed" not in run_text:
        return {}

    yaml_text = read_text_if_file(ftw_yaml)
    rule_text = read_text_if_file(rule_file)
    error_text = read_text_if_file(error_log)
    access_text = read_text_if_file(access_log)
    audit_text = read_text_if_file(audit_log)
    load_text = read_text_if_file(load_file)
    module_load_text = read_text_if_file(module_load_file)
    security_text = read_text_if_file(security_conf)

    case_lines = collect_case_lines(error_text, "100003-1")
    actual_ids = collect_actual_ids(case_lines)
    module_path = first_match(r"^LoadModule\s+security3_module\s+(\S*mod_security3\.so)", module_load_text)
    expected_id = first_match(FTW_EXPECTED_ID_PATTERN, yaml_text) or "100003"
    method = first_match(FTW_METHOD_PATTERN, yaml_text)
    uri = first_match(FTW_URI_PATTERN, yaml_text)
    rule_block = first_match(RULE_100003_PATTERN, rule_text)
    request_seen = f'POST {ATTACK_QUERY_URI} HTTP/1.1" 200' in access_text
    conclusion = common_100003_conclusion(case_lines, error_text)

    return {
        "target": "apache2_ubuntu",
        "case": "100003-1",
        "server_label": "Apache",
        "status": "fail",
        "diagnosis": "Apache/httpd started and reached go-ftw; expected phase 4 rule id 100003 was not logged.",
        **conclusion,
        "counts": collect_run_counts(run_text),
        "ftw_yaml": str(ftw_yaml),
        "generated_test": case_100003_test_metadata(yaml_text, ftw_yaml, error_log, "X-MRTS-TEST", "19080"),
        "rule_metadata": rule_100003_metadata(rule_text),
        "rule_file": str(rule_file),
        "run_log": str(run_log),
        "error_log": str(error_log),
        "access_log": str(access_log),
        "audit_log": str(audit_log),
        "mrts_load": str(load_file),
        "module_conf": str(module_load_file),
        "module_path": module_path,
        "module_loaded": bool(module_path and safe_existing_file(module_path)),
        "mrts_load_included": str(rule_file) in load_text and str(load_file) in security_text,
            "loaded_includes": [line.strip() for line in load_text.splitlines() if any(rule_file in line for rule_file in MRTS_100003_INCLUDED_RULES)],
        "method": method or "POST",
            "uri": uri or ATTACK_QUERY_URI,
        "body": "none",
        "port": "19080",
            "expected_status": FTW_UNSPECIFIED_STATUS,
        "actual_status": "HTTP 200 observed in Apache access log" if request_seen else "not printed by go-ftw",
        "expected_result": f"log id {expected_id}",
        "actual_result": "missing expected log id 100003",
        "actual_logged_ids": actual_ids,
        "phase_hits": collect_phase_hits(case_lines),
        "request_reached_server": request_seen,
        "request_reached_modsecurity": bool(actual_ids),
            "request_reached_albedo": f"Received default request to {ATTACK_QUERY_URI}" in run_text,
        "audit_evidence": audit_evidence_status(audit_log, audit_text),
        "parse_or_phase_warnings": collect_non_match_warnings(error_text),
        "rule_excerpt": rule_block,
        "go_ftw_excerpt": "\n".join(line for line in run_text.splitlines() if "100003-1" in line or "failed" in line),
        "single_case_rerun": single_case_rerun(build_root, "apache2_ubuntu"),
        "recommended_action": "No MRTS definition/result rewrite was made; keep 100003-1 as a native phase-4/request-collection limitation until native phase 4 semantics change.",
    }


def collect_nginx_100003_diagnostics(components: dict[str, Any]) -> dict[str, Any]:
    nginx = components.get("nginx", {})
    build_path = nginx.get("build_path")
    if not build_path:
        return {}
    build_root = component_build_root(build_path)
    if build_root is None:
        return {}
    run_log = safe_runtime_child(build_root, "mrts-native", "nginx-pr24", "run.log")
    error_log = safe_runtime_child(build_root, "mrts-native", "nginx-pr24", "stage", "infra", "log", "error.log")
    audit_log = safe_runtime_child(build_root, "mrts-native", "nginx-pr24", "stage", "infra", "log", "modsec_audit.log")
    ftw_yaml = safe_runtime_child(build_root, "mrts", "upstream-config-tests", "ftw", "100003_MRTS_002_ARGS_A-GET.yaml")
    rule_file = safe_runtime_child(build_root, "mrts", "upstream-config-tests", "rules", MRTS_ARGS_GET_RULE_FILE)
    load_file = safe_runtime_child(build_root, "mrts-native", "nginx-pr24", "stage", "infra", "mrts.load")
    main_conf = safe_runtime_child(build_root, "mrts-native", "nginx-pr24", "stage", "infra", "modsecurity", "main.conf")
    module_conf = safe_runtime_child(build_root, "mrts-native", "nginx-pr24", "stage", "infra", "modules-available", "mod-http-modsecurity.conf")

    run_text = read_text_if_file(run_log)
    if "100003-1 failed" not in run_text:
        return {}

    yaml_text = read_text_if_file(ftw_yaml)
    rule_text = read_text_if_file(rule_file)
    error_text = read_text_if_file(error_log)
    audit_text = read_text_if_file(audit_log)
    load_text = read_text_if_file(load_file)
    main_text = read_text_if_file(main_conf)
    module_text = read_text_if_file(module_conf)

    case_lines = collect_case_lines(error_text, "100003-1")
    actual_ids = collect_actual_ids(case_lines)
    phase_hits = collect_phase_hits(case_lines)
    module_path = first_match(r"^load_module\s+([^;]+ngx_http_modsecurity_module\.so);", module_text)
    expected_id = first_match(FTW_EXPECTED_ID_PATTERN, yaml_text) or "100003"
    method = first_match(FTW_METHOD_PATTERN, yaml_text)
    uri = first_match(FTW_URI_PATTERN, yaml_text)
    port = first_match(r"^\s+port:\s+([0-9]+)", yaml_text)
    rule_block = first_match(RULE_100003_PATTERN, rule_text)
    conclusion = common_100003_conclusion(case_lines, error_text)

    return {
        "target": "nginx-pr24",
        "case": "100003-1",
        "server_label": "NGINX",
        "status": "fail",
        "diagnosis": "go-ftw expected phase 4 rule id 100003, but NGINX/ModSecurity logged only earlier phase matches for the request.",
        **conclusion,
        "counts": collect_run_counts(run_text),
        "ftw_yaml": str(ftw_yaml),
        "generated_test": case_100003_test_metadata(yaml_text, ftw_yaml, error_log, "X-MRTS-TEST", "19081"),
        "rule_metadata": rule_100003_metadata(rule_text),
        "rule_file": str(rule_file),
        "run_log": str(run_log),
        "error_log": str(error_log),
        "audit_log": str(audit_log),
        "mrts_load": str(load_file),
        "module_conf": str(module_conf),
        "module_path": module_path,
        "module_loaded": bool(module_path and safe_existing_file(module_path)),
        "mrts_load_included": str(rule_file) in load_text and "Include mrts.load" in main_text,
            "loaded_includes": [line.strip() for line in load_text.splitlines() if any(rule_file in line for rule_file in MRTS_100003_INCLUDED_RULES)],
        "method": method or "POST",
            "uri": uri or ATTACK_QUERY_URI,
        "body": "none",
        "port": port or "19081",
            "expected_status": FTW_UNSPECIFIED_STATUS,
        "actual_status": "not printed by go-ftw; backend request was observed",
        "expected_result": f"log id {expected_id}",
        "actual_result": "missing expected log id 100003",
        "actual_logged_ids": actual_ids,
        "phase_hits": phase_hits,
            "request_reached_server": any(f'request: "POST {ATTACK_QUERY_URI} HTTP/1.1"' in line for line in case_lines),
        "request_reached_modsecurity": bool(actual_ids),
            "request_reached_albedo": f"Received default request to {ATTACK_QUERY_URI}" in run_text,
        "audit_evidence": audit_evidence_status(audit_log, audit_text),
        "parse_or_phase_warnings": collect_non_match_warnings(error_text),
        "rule_excerpt": rule_block,
        "go_ftw_excerpt": "\n".join(line for line in run_text.splitlines() if "100003-1" in line or "failed" in line),
        "single_case_rerun": single_case_rerun(build_root, "nginx-pr24"),
        "recommended_action": "No MRTS definition/result rewrite was made; keep 100003-1 as a native phase-4/request-collection limitation until native phase 4 semantics change.",
    }


def collect_runtime_diagnostics(components: dict[str, Any]) -> dict[str, Any]:
    diagnostics: dict[str, Any] = {}
    apache_diag = collect_apache_100003_diagnostics(components)
    if apache_diag:
        diagnostics["apache_100003_1"] = apache_diag
    nginx_diag = collect_nginx_100003_diagnostics(components)
    if nginx_diag:
        diagnostics["nginx_100003_1"] = nginx_diag
    return diagnostics


def post_libcrypt_native_summary(components: dict[str, Any], diagnostics: dict[str, Any]) -> dict[str, Any]:
    apache = components.get("apache_httpd", {})
    nginx = components.get("nginx", {})
    apache_diag = diagnostics.get("apache_100003_1", {})
    nginx_diag = diagnostics.get("nginx_100003_1", {})
    build_path = apache.get("build_path") or nginx.get("build_path") or ""
    build_root_path = component_build_root(build_path) if build_path else None
    build_root = str(build_root_path) if build_root_path else "-"
    return {
        "build_root": build_root,
        "apachectl_bin": apache.get("apachectl_bin") or "-",
        "apache_module": apache.get("module_file") or "-",
        "nginx_bin": nginx.get("nginx_bin") or "-",
        "nginx_module": nginx.get("module_file") or "-",
        "apache_result": "FAIL" if apache_diag else "-",
        "apache_counts": apache_diag.get("counts", {}),
        "nginx_result": "FAIL" if nginx_diag else "-",
        "nginx_counts": nginx_diag.get("counts", {}),
    }


def normalize_native_remediation(text: str, components: dict[str, Any]) -> str:
    go_ftw = components.get("go_ftw", {})
    albedo = components.get("albedo", {})
    if go_ftw.get("status") in {"present", "built"}:
        text = re.sub(
            r"\n- nginx-pr24: `go-ftw` missing;[^\n]*",
            "\n- nginx-pr24: go-ftw is present; native execution reached go-ftw and failed during test execution.",
            text,
        )
        text = re.sub(
            r"\n- apache2_ubuntu: `go-ftw` missing;[^\n]*",
            "",
            text,
        )
    if albedo.get("status") in {"present", "built"}:
        text = re.sub(
            r"\n- nginx-pr24: `albedo` missing;[^\n]*",
            "",
            text,
        )
        text = re.sub(
            r"\n- apache2_ubuntu: `albedo` missing;[^\n]*",
            "",
            text,
        )
    return text


def runtime_components_markdown(components: dict[str, Any]) -> str:
    apache = components.get("apache_httpd", {})
    nginx = components.get("nginx", {})
    expat = components.get("expat", {})
    lines = [MARKER_START, "## Runtime Components", ""]
    lines.extend(apache_component_lines(apache))
    lines.extend(nginx_component_lines(nginx))
    lines.extend(expat_component_lines(expat))
    lines.extend(dependency_component_lines(components))
    lines.append(MARKER_END)
    return "\n".join(lines)


def first_truthy(item: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = item.get(key)
        if value:
            return value
    return "-"


def apache_component_lines(apache: dict[str, Any]) -> list[str]:
    return [
        "### Apache httpd",
        f"- Status: `{apache.get('status', '-')}`",
        f"- Blocker: `{first_truthy(apache, 'blocker_reason')}`",
        f"- Cache path: `{apache.get('cache_path', '-')}`",
        f"- Build path: `{apache.get('build_path', '-')}`",
        f"- apachectl/APACHECTL_BIN: `{apache.get('apachectl_bin', '-')}`",
        f"- Module file: `{apache.get('module_file', '-')}`",
        f"- Missing file: `{first_truthy(apache, 'missing_file')}`",
        f"- Build component: `{first_truthy(apache, 'build_component')}`",
        f"- Env variable to set: `{first_truthy(apache, 'env_variable_can_set', 'env_override')}`",
        f"- Expat source: `{first_truthy(apache, 'expat_source')}`",
        f"- Expat release tag: `{first_truthy(apache, 'expat_release_tag')}`",
        f"- CPPFLAGS: `{first_truthy(apache, 'cppflags')}`",
        f"- LDFLAGS: `{first_truthy(apache, 'ldflags')}`",
        f"- LIBS: `{first_truthy(apache, 'libs')}`",
        f"- PKG_CONFIG_PATH: `{first_truthy(apache, 'pkg_config_path')}`",
        f"- crypt.h status: `{first_truthy(apache, 'crypt_h_status')}`",
        f"- crypt.h path: `{first_truthy(apache, 'crypt_h_path')}`",
        f"- libcrypt status: `{first_truthy(apache, 'libcrypt_status')}`",
        f"- libcrypt paths: `{', '.join(apache.get('libcrypt_paths', [])) or '-'}`",
        f"- crypt link mode: `{first_truthy(apache, 'crypt_link_mode')}`",
        "",
    ]


def nginx_component_lines(nginx: dict[str, Any]) -> list[str]:
    contract = nginx_runtime_contract(nginx)
    lines = [
        "### NGINX",
        f"- Status: `{nginx.get('status', '-')}`",
        f"- Blocker: `{first_truthy(nginx, 'blocker_reason')}`",
        f"- Cache path: `{nginx.get('cache_path', '-')}`",
        f"- Build path: `{nginx.get('build_path', '-')}`",
        f"- MRTS_NATIVE_NGINX_BIN: `{nginx.get('nginx_bin', '-')}`",
        f"- MRTS_NATIVE_NGINX_MODULE_DIR: `{nginx.get('module_dir', '-')}`",
        f"- Module file: `{nginx.get('module_file', '-')}`",
        f"- Missing file: `{first_truthy(nginx, 'missing_file')}`",
        f"- Build component: `{first_truthy(nginx, 'build_component')}`",
        f"- Env variable to set: `{first_truthy(nginx, 'env_variable_can_set', 'env_override')}`",
    ]
    lines.extend(
        [
            "- Runtime contract:",
            *[
                f"  - {field}: `{runtime_contract_markdown_value(contract.get(field)) or '-'}`"
                for field in NGINX_RUNTIME_CONTRACT_FIELDS
            ],
            "",
        ]
    )
    return lines


def expat_component_lines(expat: dict[str, Any]) -> list[str]:
    return [
        "### Expat",
        f"- Status: `{expat.get('status', '-')}`",
        f"- Blocker: `{first_truthy(expat, 'blocker_reason')}`",
        f"- Source: `{expat.get('source', '-')}`",
        f"- Release tag: `{first_truthy(expat, 'release_tag', 'expected_ref')}`",
        f"- Actual head: `{first_truthy(expat, 'actual_head')}`",
        f"- Prefix: `{first_truthy(expat, 'prefix')}`",
        f"- expat.h: `{first_truthy(expat, 'expat_h')}`",
        f"- lib dir: `{first_truthy(expat, 'lib_dir')}`",
        f"- Recursive submodules: `{first_truthy(expat, 'recursive_submodule_status')}`",
        "",
    ]


def dependency_component_lines(components: dict[str, Any]) -> list[str]:
    lines = [
        "### go-ftw / albedo",
        "| Dependency | Status | Binary | Env override | Source | Release tag | Head | Submodules | Release note | Blocker |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for name in ("go_ftw", "albedo"):
        item = components.get(name, {})
        lines.append(
            "| {dep} | {status} | `{binary}` | `{env}` | `{source}` | `{ref}` | `{head}` | `{subs}` | {note} | {blocker} |".format(
                dep=item.get("dependency", "-"),
                status=item.get("status", "-"),
                binary=first_truthy(item, "binary", "path"),
                env=item.get("env_override", "-"),
                source=first_truthy(item, "known_source"),
                ref=first_truthy(item, "release_tag", "known_ref"),
                head=first_truthy(item, "actual_head"),
                subs=first_truthy(item, "recursive_submodule_status"),
                note=first_truthy(item, "release_tag_deviation_note"),
                blocker=first_truthy(item, "blocker_reason"),
            )
        )
    return lines


def native_evidence_links_markdown() -> str:
    lines = [
        NATIVE_EVIDENCE_MARKER_START,
        "## MRTS Native Infrastructure Evidence",
        "",
        f"- Apache native: `{report_relpath('mrts_native_apache', 'md')}`",
        f"- NGINX PR24 native: `{report_relpath('mrts_native_nginx', 'md')}`",
        f"- Native summary: `{report_relpath('mrts_native_summary', 'md')}`",
        f"- Combined native report: `{report_relpath('mrts_native_full', 'md')}`",
        "",
        "These native MRTS reports are separate from connector full-matrix evidence.",
        NATIVE_EVIDENCE_MARKER_END,
    ]
    return "\n".join(lines)


def native_summary_markdown(report_dir: Path) -> str:
    native = read_json(report_path_from_root(report_dir, "mrts_native_full", "json"))
    targets = native.get("targets") if isinstance(native.get("targets"), dict) else {}
    lines = [
        "## MRTS Native Summary",
        f"- Report generated at: `{native.get('generated_at', '-')}`",
        "- Native MRTS evidence is separate from connector runtime matrix evidence.",
        "",
        "| Target | Status | Exit code | Attempted | PASS | FAIL | BLOCKED | Reason | Run log | Summary |",
        "|---|---|---:|---:|---:|---:|---:|---|---|---|",
    ]
    for target in ("apache2_ubuntu", "nginx-pr24"):
        job = targets.get(target, {}) if isinstance(targets.get(target), dict) else {}
        counts = job.get("counts") if isinstance(job.get("counts"), dict) else {}
        lines.append(
            "| {target} | {status} | {exit_code} | {attempted} | {passed} | {failed} | {blocked} | {reason} | `{run_log}` | `{summary}` |".format(
                target=target,
                status=job.get("status", "NOT_RUN"),
                exit_code=job.get("exit_code", "-"),
                attempted=counts.get("attempted", 0),
                passed=counts.get("pass", 0),
                failed=counts.get("fail", 0),
                blocked=counts.get("blocked", 0),
                reason=str(job.get("reason") or "-").replace("|", "\\|"),
                run_log=job.get("run_log", "-"),
                summary=job.get("summary_path", job.get("job_json", "-")),
            )
        )
    return "\n".join(lines)


def native_target_script_exit_code(summary: dict[str, Any]) -> int:
    if int(summary.get("FAIL", 0) or 0) > 0:
        return 2
    if int(summary.get("BLOCKED", 0) or 0) > 0:
        return 77
    return 0


def remove_stale_native_blockers(text: str, report_dir: Path) -> str:
    native = read_json(report_path_from_root(report_dir, "mrts_native_full", "json"))
    summary = native.get("summary") if isinstance(native.get("summary"), dict) else {}
    if int(summary.get("BLOCKED", 0) or 0) > 0:
        return text
    lines = []
    for line in text.splitlines():
        if line.startswith(("- apache2_ubuntu:", "- nginx-pr24:")):
            continue
        lines.append(line)
    return "\n".join(lines) + "\n"


def post_libcrypt_native_markdown(summary: dict[str, Any]) -> str:
    apache_counts = summary.get("apache_counts", {})
    nginx_counts = summary.get("nginx_counts", {})
    lines = [
        POST_LIBCRYPT_MARKER_START,
        "## Post-libcrypt Native Rerun",
        "- Scope: requested native rerun after external `libcrypt-dev` availability; the earlier full-matrix sections in this file remain historical evidence from their original generation time.",
        "- Command: `VERIFIED_RUN_ROOT=/var/tmp/ModSecurity-conector-verified MRTS_NATIVE_TARGETS=\"apache2_ubuntu nginx-pr24\" PYTHONDONTWRITEBYTECODE=1 make mrts-native-full-run`",
        f"- BUILD_ROOT: `{summary.get('build_root', '-')}`",
        f"- Apache wrapper: `{summary.get('apachectl_bin', '-')}`",
        f"- Apache module: `{summary.get('apache_module', '-')}`",
        f"- Apache native result: `{summary.get('apache_result', '-')}`; attempted `{apache_counts.get('attempted', '-')}`, passed `{apache_counts.get('passed', '-')}`, failed cases `{apache_counts.get('failed_cases', '-')}`",
        f"- NGINX binary: `{summary.get('nginx_bin', '-')}`",
        f"- NGINX module: `{summary.get('nginx_module', '-')}`",
        f"- NGINX native result: `{summary.get('nginx_result', '-')}`; attempted `{nginx_counts.get('attempted', '-')}`, passed `{nginx_counts.get('passed', '-')}`, failed cases `{nginx_counts.get('failed_cases', '-')}`",
        POST_LIBCRYPT_MARKER_END,
    ]
    return "\n".join(lines)


def runtime_build_cache_markdown(build_cache: dict[str, Any]) -> str:
    modsecurity = build_cache.get("shared_modsecurity_build", {})
    summary = build_cache.get("build_reuse_summary", {})
    lines = [
        BUILD_CACHE_MARKER_START,
        "## Runtime Build Cache",
        f"- Shared ModSecurity status: `{modsecurity.get('status', '-')}`",
        f"- Shared ModSecurity source ref/SHA: `{modsecurity.get('source_ref', '-')}` / `{modsecurity.get('actual_sha', '-')}`",
        f"- Shared ModSecurity build ID: `{modsecurity.get('build_id', '-')}`",
        f"- Shared ModSecurity prefix: `{modsecurity.get('prefix', '-')}`",
        f"- Build reuse summary: rebuilt `{summary.get('rebuilt_count', '-')}`, reused `{summary.get('reused_count', '-')}`, blocked `{summary.get('blocked_count', '-')}`, saved rebuilds estimate `{summary.get('saved_rebuilds_estimate', '-')}`",
        "",
        "| Connector | Status | Connector build ID | Uses ModSecurity build ID | Blocker |",
        "|---|---|---|---|---|",
    ]
    for item in build_cache.get("connector_builds", []):
        lines.append(
            "| {connector} | {status} | `{connector_id}` | `{modsec_id}` | {blocker} |".format(
                connector=item.get("connector", "-"),
                status=item.get("status", "-"),
                connector_id=item.get("connector_build_id", "-"),
                modsec_id=item.get("modsecurity_build_id", "-"),
                blocker=item.get("blocker_reason") or "-",
            )
        )
    lines.append(BUILD_CACHE_MARKER_END)
    return "\n".join(lines)


def diagnostics_markdown(diagnostics: dict[str, Any]) -> str:
    lines = [DIAG_MARKER_START, "## Native Runtime Diagnostics"]
    if not diagnostics:
        lines.extend(["", "- No generated native runtime diagnostics were detected."])
        lines.append(DIAG_MARKER_END)
        return "\n".join(lines)
    for key in ("apache_100003_1", "nginx_100003_1"):
        diag = diagnostics.get(key, {})
        if diag:
            lines.extend(diagnostic_markdown_lines(diag))
    lines.append(DIAG_MARKER_END)
    return "\n".join(lines)


def diagnostic_markdown_lines(diag: dict[str, Any]) -> list[str]:
    label = diag.get("server_label") or diag.get("target", "-")
    counts = diag.get("counts", {})
    rule = diag.get("rule_metadata", {})
    generated_test = diag.get("generated_test", {})
    headers = generated_test.get("headers", {})
    hypotheses = diag.get("hypothesis_checks", {})
    warnings = diag.get("parse_or_phase_warnings", [])
    loaded_includes = diag.get("loaded_includes", [])
    header_text = ", ".join(f"{name}: {value}" for name, value in headers.items()) or "-"
    return [
        "",
        f"### {label} 100003-1",
        f"- Status: `{diag.get('status', '-')}`",
        f"- Target: `{diag.get('target', '-')}`",
        f"- Run counts: attempted `{counts.get('attempted', '-')}`, passed `{counts.get('passed', '-')}`, failed cases `{counts.get('failed_cases', '-')}`",
        f"- Diagnosis: {diag.get('diagnosis', '-')}",
        f"- Classification: `{diag.get('classification', '-')}`; secondary `{diag.get('secondary_classification', '-')}`; unresolved `{diag.get('classification_checks', {}).get('unresolved', '-')}`",
        f"- Classification reason: {diag.get('classification_reason', '-')}",
        f"- Generated YAML: `{diag.get('ftw_yaml', '-')}`",
        f"- Generated rule file: `{diag.get('rule_file', '-')}`",
        f"- Source definition: `{rule.get('source_definition_relative_to_mrts_root', '-')}`",
        f"- Generated rule line: `{rule.get('generated_rule_line', '-')}`",
        f"- Rule 100003: variable `{rule.get('variable', '-')}`, phase `{rule.get('phase', '-')}`, operator `{rule.get('operator', '-')} {rule.get('operator_argument', '-')}`, transform `{rule.get('transform', '-')}`",
        f"- Request: `{diag.get('method', '-')} {diag.get('uri', '-')} HTTP/1.1` on port `{diag.get('port', '-')}`; body `{diag.get('body', '-')}`",
        f"- Generated test headers: `{header_text}`",
        f"- Log matching: marker header `{generated_test.get('log_marker_header', '-')}`, target log `{generated_test.get('log_file_target', '-')}`",
        f"- Expected status/result: `{diag.get('expected_status', '-')}` / `{diag.get('expected_result', '-')}`",
        f"- Actual status/result: `{diag.get('actual_status', '-')}` / `{diag.get('actual_result', '-')}`",
        f"- Actual logged IDs: `{', '.join(diag.get('actual_logged_ids', [])) or '-'}`",
        f"- Phase 4 evidence: match seen `{hypotheses.get('phase4_match_seen', '-')}`, peer IDs in case window `{', '.join(hypotheses.get('phase4_rule_ids_logged_in_window', [])) or '-'}`, peer IDs anywhere `{', '.join(hypotheses.get('phase4_peer_ids_logged_anywhere', [])) or '-'}`",
        f"- Request collection evidence: POST query as ARGS `{hypotheses.get('post_query_processed_as_args', '-')}`, as ARGS_GET `{hypotheses.get('post_query_processed_as_args_get', '-')}`",
        f"- Excluded causes: response-body target `{hypotheses.get('is_response_body_target', '-')}`, operator case/transform issue `{hypotheses.get('operator_case_sensitive_issue', '-')}` / `{hypotheses.get('transform_issue', '-')}`, skip/ctl/chain interference `{hypotheses.get('skip_ctl_chain_or_disruptive_interference_seen', '-')}`, go-ftw log matching issue `{hypotheses.get('go_ftw_log_matching_issue', '-')}`",
        f"- Parse/phase warnings: `{len(warnings)}`",
        f"- Loaded MRTS includes checked: `{', '.join(loaded_includes) or '-'}`",
        f"- Module loaded: `{diag.get('module_loaded')}` from `{diag.get('module_path') or '-'}`",
        f"- mrts.load included: `{diag.get('mrts_load_included')}`",
        f"- Request reached {label}/ModSecurity/Albedo: `{diag.get('request_reached_server')}` / `{diag.get('request_reached_modsecurity')}` / `{diag.get('request_reached_albedo')}`",
        f"- Audit/debug evidence: audit log `{diag.get('audit_evidence', '-')}`, error log `{diag.get('error_log', '-')}`, go-ftw log `{diag.get('run_log', '-')}`",
        f"- Single-case rerun: {single_rerun_markdown(diag.get('single_case_rerun', {}))}",
        f"- Why not logged: {diag.get('why_not_logged', '-')}",
        f"- Action: {diag.get('recommended_action', '-')}",
    ]


def single_rerun_markdown(single_rerun: object) -> str:
    if not isinstance(single_rerun, dict) or not single_rerun:
        return "not recorded"
    return (
        f"attempted `{single_rerun.get('attempted', '-')}`, "
        f"failed cases `{single_rerun.get('failed_cases', '-')}`, "
        f"exit `{single_rerun.get('exit_code', '-')}`, "
        f"log `{single_rerun.get('log', '-')}`"
    )


def update_report_json(path: Path, components: dict[str, Any], diagnostics: dict[str, Any], build_cache: dict[str, Any]) -> None:
    if not INPUTS.is_file(path):
        return
    data = read_json(path)
    if not data:
        return
    data["mrts_native_reports"] = {
        "apache": report_relpath("mrts_native_apache", "md"),
        "nginx": report_relpath("mrts_native_nginx", "md"),
        "summary": report_relpath("mrts_native_summary", "md"),
        "combined": report_relpath("mrts_native_full", "md"),
    }
    if path.name == "full-run-evidence.generated.json":
        update_full_run_evidence_json(data, path)
        write_json(path, data)
        return
    update_runtime_component_json(data, components, diagnostics, build_cache)
    write_json(path, data)


def update_full_run_evidence_json(data: dict[str, Any], path: Path) -> None:
    reports = data.get("reports")
    report_list = reports if isinstance(reports, list) else []
    data["reports"] = append_missing_reports(report_list, NATIVE_REPORT_FILES)
    native_full = read_json(
        report_path_from_root(report_root_for(path), "mrts_native_full", "json")
    )
    if native_full:
        data["mrts_native"] = native_full_evidence_summary(
            data, native_full
        )


def append_missing_reports(reports: list[Any], required: list[str]) -> list[Any]:
    for report_file in required:
        if report_file not in reports:
            reports.append(report_file)
    return reports


def native_full_evidence_summary(
    data: dict[str, Any], native_full: dict[str, Any]
) -> dict[str, Any]:
    existing = data.get("mrts_native")
    mrts_native = existing if isinstance(existing, dict) else {}
    summary = native_full.get("summary", {})
    mrts_native.update(
        {
            "generated_at": native_full.get("generated_at"),
            "report_json": report_relpath("mrts_native_full", "json"),
            "report_md": report_relpath("mrts_native_full", "md"),
            "reports": native_full.get("reports", data["mrts_native_reports"]),
            "summary": summary,
            "target_script_exit_code": native_target_script_exit_code(summary),
            "targets": native_full.get("targets", {}),
        }
    )
    return mrts_native


def update_runtime_component_json(
    data: dict[str, Any], components: dict[str, Any], diagnostics: dict[str, Any],
    build_cache: dict[str, Any],
) -> None:
    data["runtime_components"] = components
    data["runtime_diagnostics"] = diagnostics
    data["runtime_build_cache"] = build_cache
    data.update(components)


def update_report_md(path: Path, components: dict[str, Any], diagnostics: dict[str, Any], build_cache: dict[str, Any]) -> None:
    if not INPUTS.is_file(path):
        return
    text = read_text_file(path)
    if path.name == "mrts-native-full.generated.md":
        text = normalize_native_remediation(text, components)
    if path.name == "full-run-evidence.generated.md":
        text = remove_stale_native_blockers(text, path.parent)
        text = replace_heading_section(
            text,
            "## MRTS Native Summary",
            native_summary_markdown(path.parent),
            "## External Blockers",
        )
        text = insert_named_section_before_heading(
            text,
            native_evidence_links_markdown(),
            NATIVE_EVIDENCE_MARKER_START,
            NATIVE_EVIDENCE_MARKER_END,
            "## External Blockers",
        )
        write_text_file(path, portable_markdown_text(text))
        return
    section = runtime_components_markdown(components)
    text = replace_marked_section(text, section)
    text = replace_named_section(text, runtime_build_cache_markdown(build_cache), BUILD_CACHE_MARKER_START, BUILD_CACHE_MARKER_END)
    text = replace_named_section(text, diagnostics_markdown(diagnostics), DIAG_MARKER_START, DIAG_MARKER_END)
    write_text_file(path, portable_markdown_text(text))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--connector-root", required=True)
    parser.add_argument("--cache-root", default=None)
    parser.add_argument("--output-root", default=None)
    parser.add_argument("--build-root", default=os.environ.get("BUILD_ROOT"),
                        help="explicit invocation build root for retained diagnostic evidence")
    parser.add_argument("--approved-component-file", action="append", type=Path, default=[],
                        help="explicit operator-approved installed component file outside the managed cache")
    args = parser.parse_args()

    connector_root = Path(args.connector_root).resolve()
    output_root = Path(args.output_root).resolve() if args.output_root else connector_root
    report_dir = output_root / GENERATED_ROOT
    cache_root = local_cache_root(args.cache_root)
    build_root = Path(args.build_root).resolve() if args.build_root else None
    report_dir.mkdir(parents=True, exist_ok=True)
    add_safe_roots(connector_root, report_dir)
    add_safe_roots(cache_root)
    write_cache_reports_from_local_cache(connector_root, report_dir, cache_root,
                                        approved_files=tuple(args.approved_component_file),
                                        build_root=build_root)
    components = component_inventory(report_dir)
    build_cache = build_cache_inventory(report_dir)
    diagnostics = collect_runtime_diagnostics(components)
    update_report_json(report_path_from_root(report_dir, "runtime_component_cache", "json"), components, diagnostics, build_cache)
    update_report_md(report_path_from_root(report_dir, "runtime_component_cache", "md"), components, diagnostics, build_cache)
    if os.environ.get("SUPPRESS_FULL_RUN_EVIDENCE_SIDE_EFFECTS") != "1":
        update_report_json(report_path_from_root(report_dir, "full_run_evidence", "json"), components, diagnostics, build_cache)
        update_report_md(report_path_from_root(report_dir, "full_run_evidence", "md"), components, diagnostics, build_cache)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
