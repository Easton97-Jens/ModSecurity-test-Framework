#!/usr/bin/env python3
"""Reject old flat CI paths and non-portable developer paths in maintained files."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SKIPPED_PREFIXES = (
    ".git/",
    "__pycache__/",
    "tools/MRTS/",
    ".codex/",
)
LOCAL_AGENT_ROOT_NAMES = {
    "AGENTS.md",
    "AGENTS.override.md",
    "AGENTS.de.md",
}
OLD_CI_FILENAMES = {
    "adapter_metadata.py", "bootstrap-python.sh", "build-v3-under-src.sh", "check-adapter-helpers.sh",
    "check-adapter-metadata-drift.sh", "check-common-helpers.sh", "check-common-versions.py",
    "check-crs-version-pinning.sh", "check-doc-links.py", "check-mrts-importer.py",
    "check-open-runtime-provisioning-contract.sh", "check-protocol-evidence.py",
    "check-python-deps.py", "check-response-body-promotion.py", "check-security-data-flow-cases.py",
    "check-security-data-flow-normalizers.py", "check-transport-hardening-evidence.py",
    "check-v3-api-smoke-prereqs.sh", "check-workflow-yaml.py", "cloud-quick-check.sh", "common.sh",
    "connector-smoke-common.sh", "doctor.sh", "fetch-crs.sh", "fetch-smoke-sources.sh",
    "find-modsecurity-v3.sh", "generate-case-matrix.py", "generate-connector-work-queue.py",
    "generate-mrts-native-report.py", "generate-mrts.sh", "generate-phase-work-queue.py",
    "generated_report_utils.py", "import-mrts-cases.py", "materialize-connector-source.py",
    "materialize-connector-source.sh", "mrts-common.sh", "no_crs_baseline.py",
    "prepare-apache-build.sh", "prepare-crs.sh", "prepare-envoy-runtime.sh",
    "prepare-haproxy-runtime.sh", "prepare-lighttpd-runtime.sh", "prepare-nginx-build.sh",
    "prepare-traefik-runtime.sh", "probe-response-body-blocking.sh", "protocol_client.py",
    "quick-all.sh", "response_body_status.py", "run-apache-smoke.sh", "run-connector-smokes.sh",
    "run-connector-starter-checks.sh", "run-envoy-smoke.sh", "run-haproxy-runtime-matrix.sh",
    "run-haproxy-smoke.sh", "run-lighttpd-smoke.sh", "run-nginx-smoke.sh",
    "run-runtime-matrix.sh", "run-traefik-smoke.sh", "run-v3-api-smoke.sh",
    "runtime-component-common.sh", "runtime-components.manifest.json", "smoke-installed.sh",
    "summarize-results.py", "update-runtime-snapshot.py", "write-case-matrix.py",
    "write-haproxy-runtime-matrix.py", "write-mrts-load.sh",
}
LOCAL_PATH_RE = re.compile(r"/root" + r"/git/|[A-Za-z]:\\\\Users\\")
MARKDOWN_LOCAL_PATH_RE = re.compile(r"/root(?:/|$)|/var/tmp(?:/|$)")
TEXT_SUFFIXES = {".md", ".py", ".sh", ".yml", ".yaml", ".json", ".mk", ".txt"}


def relative(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def is_local_agent_configuration_path(path: Path) -> bool:
    value = relative(path)
    return value in LOCAL_AGENT_ROOT_NAMES


def should_scan(path: Path) -> bool:
    value = relative(path)
    if is_local_agent_configuration_path(path):
        return False
    if any(value.startswith(prefix) for prefix in SKIPPED_PREFIXES):
        return False
    return path.name == "Makefile" or path.suffix in TEXT_SUFFIXES


def is_skipped_directory(path: Path) -> bool:
    """Prune excluded trees before a recursive walk reaches their contents."""

    value = relative(path).rstrip("/") + "/"
    return any(value.startswith(prefix) for prefix in SKIPPED_PREFIXES)


def repository_files() -> list[Path]:
    """Return files while pruning excluded trees before enumerating their content."""

    files: list[Path] = []
    for directory, directory_names, file_names in os.walk(ROOT):
        directory_path = Path(directory)
        directory_names[:] = [
            name
            for name in directory_names
            if not is_skipped_directory(directory_path / name)
        ]
        files.extend(directory_path / name for name in file_names)
    return files


def scan_path_references(path: Path) -> tuple[bool, list[str]]:
    """Return content findings for one eligible path without stopping the scan."""

    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return False, []

    value = relative(path)
    errors: list[str] = []
    if LOCAL_PATH_RE.search(text):
        errors.append(f"{value}: contains a local developer path")
    if path.suffix == ".md" and MARKDOWN_LOCAL_PATH_RE.search(text):
        errors.append(f"{value}: contains a local developer path")
    for filename in OLD_CI_FILENAMES:
        old_path = f"ci/{filename}"
        if old_path in text:
            errors.append(f"{value}: obsolete flat CI path {old_path}")
    return True, errors


def main() -> int:
    errors: list[str] = []
    files_scanned = 0
    for path in repository_files():
        if not path.is_file() or not should_scan(path):
            continue
        scanned, path_errors = scan_path_references(path)
        if scanned:
            files_scanned += 1
        errors.extend(path_errors)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"repository path references ok: files_scanned={files_scanned} old_paths=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
