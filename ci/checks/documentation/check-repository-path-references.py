#!/usr/bin/env python3
"""Reject old flat CI paths and non-portable developer paths in maintained files."""

from __future__ import annotations

import hashlib
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


# Closed data/negative-fixture provenance from Connector commit
# ec18f9e92286379a2410e917f76e6a5502675804, before physical relocation.
# Original paths: ci/runtime/lifecycle/i12/objects/text/<same filename> and
# connectors/haproxy/harness/fixtures/i12-oracles-20261015.json. These are
# immutable data, never an exemption for executable source or an entire tree.
HISTORICAL_DATA_SHA256 = {
    "connector_suite/modsecurity_connector_ci/runtime/lifecycle/i12/objects/text/"
    "76d5319b726a8fdba12b01ccc946aac80e8442f72ad4e262ff314f3f1db838b8-private-runtime-v5.py.lines.json":
        "ffa031d78871fb37bdb205b38512601cb3576720b99ae802365b92e83e1092d2",
    "connector_suite/adapters/haproxy/harness/fixtures/i12-oracles-20261015.json":
        "642a72ba19398f3b18866169261e0d18ecf778acb95fafcfda77f242c9c77f69",
}
# Original tests/test_repository_path_references.py and
# tests/test_nginx_native_operation_collection.py at the same commit.
# SHA256 covers each complete UTF-8 source line including its newline. Only
# LOCAL_PATH matches on exactly one copy of that line are permitted. All other
# lines and every obsolete-flat-CI-path check remain active.
NEGATIVE_FIXTURE_LINE_SHA256 = {
    "connector_suite/modsecurity_connector_tests/test_repository_path_references.py":
        ("9b899b2ccc2c836af62ed8edc53278c10b783681468cdad4418939f4e19705f2", 1),
    "connector_suite/modsecurity_connector_tests/test_nginx_native_operation_collection.py":
        ("811dd25b945c6a0604ed3022cfdd2091708db8913d2494e81ddd36690efa8289", 1),
}


def local_path_policy(path: Path, raw: bytes, text: str) -> tuple[bool, list[str]]:
    """Recognize only reviewed immutable bytes and exact negative-input lines."""

    value = relative(path)
    errors: list[str] = []
    historical_digest = HISTORICAL_DATA_SHA256.get(value)
    if historical_digest is not None:
        if hashlib.sha256(raw).hexdigest() == historical_digest:
            return False, errors
        errors.append(f"{value}: immutable historical data SHA256 differs")

    lines = text.splitlines(keepends=True)
    admitted_lines: set[int] = set()
    fixture = NEGATIVE_FIXTURE_LINE_SHA256.get(value)
    if fixture is not None:
        expected_digest, expected_count = fixture
        matching = {
            index for index, line in enumerate(lines)
            if hashlib.sha256(line.encode("utf-8")).hexdigest() == expected_digest
        }
        if len(matching) == expected_count:
            admitted_lines = matching
        else:
            errors.append(f"{value}: reviewed negative-fixture line count differs")
    unexpected = any(
        LOCAL_PATH_RE.search(line) for index, line in enumerate(lines)
        if index not in admitted_lines
    )
    return unexpected, errors


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
        raw = path.read_bytes()
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        value = relative(path)
        if value in HISTORICAL_DATA_SHA256:
            return False, [f"{value}: immutable historical data SHA256 differs"]
        if value in NEGATIVE_FIXTURE_LINE_SHA256:
            return False, [f"{value}: reviewed negative-fixture line count differs"]
        return False, []

    value = relative(path)
    unexpected_local_path, errors = local_path_policy(path, raw, text)
    if unexpected_local_path:
        errors.append(f"{value}: contains a local developer path")
    if path.suffix == ".md" and MARKDOWN_LOCAL_PATH_RE.search(text):
        errors.append(f"{value}: contains a local developer path")
    for filename in OLD_CI_FILENAMES:
        old_path = f"ci/{filename}"
        if old_path in text:
            errors.append(f"{value}: obsolete flat CI path {old_path}")
    return True, errors


def fixture_policy_path_errors() -> list[str]:
    """Reject stale policy entries and aliases before admitting any fixture bytes."""

    errors: list[str] = []
    for value in (*HISTORICAL_DATA_SHA256, *NEGATIVE_FIXTURE_LINE_SHA256):
        path = ROOT / value
        if path.is_symlink() or not path.is_file():
            errors.append(f"{value}: reviewed fixture must remain a regular non-symlink file")
    return errors


def main() -> int:
    errors = fixture_policy_path_errors()
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
