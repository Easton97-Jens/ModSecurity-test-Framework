#!/usr/bin/env python3
"""Run an opt-in, read-only advisory Clang analysis baseline.

The runner intentionally treats diagnostics as triage input.  A completed
analysis therefore returns zero even when it reports findings.  It only writes
raw tool output and normalized JSON below an explicitly supplied child of the
marked ``CODEX_TEMP_ROOT``.
"""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import traceback
import uuid
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import unquote, urlparse


EXIT_OK = 0
EXIT_TECHNICAL_FAILURE = 1
EXIT_USAGE = 2
EXIT_BLOCKED = 77
SCHEMA_VERSION = "1.0"
TOOL_TIMEOUT_SECONDS = 300
MIB = 1024 * 1024
TEMP_WARNING_BYTES = 1536 * MIB
TEMP_STOP_BYTES = 2048 * MIB
MIN_FREE_BYTES = 5 * 1024 * 1024 * 1024

ALLOWED_CLASSIFICATIONS = (
    "confirmed_bug",
    "needs_validation",
    "possible_security_candidate",
    "false_positive",
    "third_party_header",
    "intentional_pattern",
    "out_of_scope",
)
SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".C"}
HEADER_SUFFIXES = {".h", ".hh", ".hpp", ".hxx", ".inc", ".inl"}
TIDY_DIAGNOSTIC = re.compile(
    r"^(?P<path>.+?):(?P<line>\d+):(?P<column>\d+): "
    r"(?P<severity>warning|error|note): (?P<message>.*?)(?: \[(?P<checks>[^\]]+)\])?$"
)


class BaselineError(RuntimeError):
    """An expected, user-facing baseline failure."""

    exit_code = EXIT_TECHNICAL_FAILURE


class UsageError(BaselineError):
    exit_code = EXIT_USAGE


class BlockedError(BaselineError):
    exit_code = EXIT_BLOCKED


@dataclass(frozen=True)
class Tool:
    label: str
    path: str
    version: str


@dataclass(frozen=True)
class CdbEntry:
    source: Path
    directory: Path
    arguments: tuple[str, ...]
    language: str
    system_include_dirs: tuple[Path, ...]


@dataclass(frozen=True)
class Invocation:
    repository_root: Path
    temp_root: Path
    compdb_path: Path
    output_root: Path
    entries: tuple[CdbEntry, ...]


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def repository_root() -> Path:
    root = connector_root()
    if not (root / ".git").exists():
        raise BaselineError(f"cannot locate repository root from {__file__}")
    return root


def path_from_argument(value: str, label: str, *, must_exist: bool) -> Path:
    if not value:
        raise UsageError(f"{label} is required")
    path = Path(value)
    if not path.is_absolute():
        raise UsageError(f"{label} must be absolute: {value}")
    try:
        return path.resolve(strict=must_exist)
    except OSError as error:
        if must_exist:
            raise BlockedError(f"{label} is unavailable: {value}: {error}") from error
        raise UsageError(f"cannot resolve {label}: {value}: {error}") from error


def require_temp_root() -> Path:
    configured = os.environ.get("CODEX_TEMP_ROOT", "")
    if not configured:
        raise BlockedError("CODEX_TEMP_ROOT is required")
    root = path_from_argument(configured, "CODEX_TEMP_ROOT", must_exist=True)
    marker = root / ".codex-temp-root"
    temp_dir = root / "tmp"
    if not root.is_dir() or not marker.is_file() or not temp_dir.is_dir():
        raise BlockedError(
            "CODEX_TEMP_ROOT must be a marked root with a tmp directory: "
            f"{root}"
        )
    if not os.access(root, os.W_OK) or not os.access(temp_dir, os.W_OK):
        raise BlockedError(f"CODEX_TEMP_ROOT is not writable: {root}")
    return root


def directory_usage_bytes(root: Path) -> int:
    total = 0
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        try:
            stat_result = current_path.lstat()
            total += getattr(stat_result, "st_blocks", 0) * 512 or stat_result.st_size
        except OSError:
            continue
        for name in files:
            path = current_path / name
            try:
                stat_result = path.lstat()
            except OSError:
                continue
            total += getattr(stat_result, "st_blocks", 0) * 512 or stat_result.st_size
        directories[:] = [
            name for name in directories if not (current_path / name).is_symlink()
        ]
    return total


def enforce_storage_gate(temp_root: Path) -> None:
    usage = directory_usage_bytes(temp_root)
    free = shutil.disk_usage(temp_root).free
    if usage >= TEMP_STOP_BYTES:
        raise BlockedError(
            f"CODEX_TEMP_ROOT is at or above the 2048 MiB stop limit: {usage} bytes"
        )
    if free < MIN_FREE_BYTES:
        raise BlockedError(
            f"filesystem free space is below 5 GiB: {free} bytes available"
        )
    if usage >= TEMP_WARNING_BYTES:
        raise BlockedError(
            "CODEX_TEMP_ROOT is at or above the 1536 MiB cleanup threshold; "
            "clean up owned temporary data before analysis"
        )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tracked_files(root: Path) -> set[Path]:
    completed = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", "replace").strip()
        raise BaselineError(f"cannot enumerate tracked repository files: {detail}")
    return {
        (root / name.decode("utf-8", "surrogateescape")).resolve(strict=False)
        for name in completed.stdout.split(b"\0")
        if name
    }


def arguments_from_entry(entry: dict[str, Any], source: Path) -> tuple[str, ...]:
    arguments = entry.get("arguments")
    if isinstance(arguments, list) and arguments and all(isinstance(item, str) for item in arguments):
        return tuple(arguments)
    command = entry.get("command")
    if isinstance(command, str) and command:
        try:
            parsed = shlex.split(command)
        except ValueError as error:
            raise UsageError(f"cannot parse compilation command for {source}: {error}") from error
        if parsed:
            return tuple(parsed)
    raise UsageError(
        f"compilation database entry for {source} has neither valid arguments nor command"
    )


def cdb_source(entry: dict[str, Any]) -> tuple[Path, Path]:
    directory = entry.get("directory")
    file_name = entry.get("file")
    if not isinstance(directory, str) or not directory:
        raise UsageError("compilation database entry has no non-empty directory")
    if not isinstance(file_name, str) or not file_name:
        raise UsageError("compilation database entry has no non-empty file")
    directory_path = Path(directory)
    if not directory_path.is_absolute():
        raise UsageError(f"compilation database entry directory is not absolute: {directory}")
    try:
        resolved_directory = directory_path.resolve(strict=True)
    except OSError as error:
        raise UsageError(f"compilation database directory is unavailable: {directory}: {error}") from error
    file_path = Path(file_name)
    if not file_path.is_absolute():
        file_path = resolved_directory / file_path
    try:
        return file_path.resolve(strict=True), resolved_directory
    except OSError as error:
        raise UsageError(f"compilation database source is unavailable: {file_path}: {error}") from error


def require_safe_cdb_output(entry: dict[str, Any], root: Path) -> None:
    output = entry.get("output")
    if not isinstance(output, str) or not output:
        raise UsageError("compilation database entry has no non-empty output path")
    path = Path(output)
    if not path.is_absolute():
        raise UsageError(f"compilation database output is not absolute: {output}")
    resolved = path.resolve(strict=False)
    if is_within(resolved, root):
        raise UsageError(f"compilation database output is inside the checkout: {resolved}")


def language_for_source(source: Path, arguments: tuple[str, ...]) -> str:
    if source.suffix == ".c":
        required = "-std=c17"
        language = "c17"
    elif source.suffix in SOURCE_SUFFIXES:
        required = "-std=c++17"
        language = "cxx17"
    else:
        raise UsageError(f"unsupported translation unit type: {source}")
    if required not in arguments:
        raise UsageError(f"translation unit is missing {required}: {source}")
    return language


def system_include_dirs(arguments: tuple[str, ...], directory: Path) -> tuple[Path, ...]:
    directories: list[Path] = []
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        value: str | None = None
        if argument == "-isystem":
            if index + 1 >= len(arguments):
                raise UsageError("-isystem has no path in compilation database")
            index += 1
            value = arguments[index]
        elif argument.startswith("-isystem") and argument != "-isystem":
            value = argument[len("-isystem") :]
        if value:
            candidate = Path(value)
            if not candidate.is_absolute():
                candidate = directory / candidate
            directories.append(candidate.resolve(strict=False))
        index += 1
    return tuple(directories)


def load_entries(compdb_path: Path, root: Path) -> tuple[CdbEntry, ...]:
    try:
        raw = json.loads(compdb_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise UsageError(f"invalid compilation database JSON at {compdb_path}: {error}") from error
    if not isinstance(raw, list) or not raw:
        raise UsageError("compilation database root must be a non-empty JSON array")
    tracked = tracked_files(root)
    entries: list[CdbEntry] = []
    seen_sources: set[Path] = set()
    for index, value in enumerate(raw):
        if not isinstance(value, dict):
            raise UsageError(f"compilation database entry {index} is not an object")
        source, directory = cdb_source(value)
        if not is_within(source, root) or source not in tracked or not source.is_file():
            raise UsageError(f"compilation database source is not a tracked checkout file: {source}")
        if not is_within(directory, root):
            raise UsageError(f"compilation database directory is outside the checkout: {directory}")
        if source in seen_sources:
            raise UsageError(f"compilation database has a duplicate translation unit: {source}")
        require_safe_cdb_output(value, root)
        arguments = arguments_from_entry(value, source)
        language = language_for_source(source, arguments)
        entries.append(
            CdbEntry(
                source=source,
                directory=directory,
                arguments=arguments,
                language=language,
                system_include_dirs=system_include_dirs(arguments, directory),
            )
        )
        seen_sources.add(source)
    return tuple(sorted(entries, key=lambda entry: entry.source.as_posix()))


def validate_invocation(arguments: argparse.Namespace) -> Invocation:
    root = repository_root()
    temp_root = require_temp_root()
    enforce_storage_gate(temp_root)
    compdb = path_from_argument(arguments.compdb_output, "COMPDB_OUTPUT", must_exist=True)
    if not compdb.is_file():
        raise BlockedError(f"COMPDB_OUTPUT is missing: {compdb}")
    if is_within(compdb, root):
        raise UsageError(f"COMPDB_OUTPUT must be outside the checkout: {compdb}")
    if not is_within(compdb, temp_root):
        raise UsageError(f"COMPDB_OUTPUT must be below CODEX_TEMP_ROOT: {compdb}")
    output = path_from_argument(arguments.analysis_output, "ANALYSIS_OUTPUT", must_exist=False)
    if is_within(output, root):
        raise UsageError(f"ANALYSIS_OUTPUT must be outside the checkout: {output}")
    if output == temp_root or not is_within(output, temp_root):
        raise UsageError(
            f"ANALYSIS_OUTPUT must be a child of CODEX_TEMP_ROOT: {output}"
        )
    entries = load_entries(compdb, root)
    # Reject write-capable compiler arguments before creating the caller's
    # output directory.  The compiler path is irrelevant for this validation.
    for entry in entries:
        sanitize_arguments(entry, "clang")
    return Invocation(root, temp_root, compdb, output, entries)


def discover_tool(value: str, label: str) -> str:
    if not value:
        raise BlockedError(f"{label} is unavailable: no executable was configured")
    resolved = shutil.which(value)
    if not resolved:
        raise BlockedError(f"{label} is unavailable: {value}")
    path = Path(resolved)
    if not path.is_file() or not os.access(path, os.X_OK):
        raise BlockedError(f"{label} is unavailable: {value}")
    # Keep the selected executable spelling.  Resolving ``clang++`` through
    # its symlink turns it into ``clang`` and loses the C++ driver mode.
    return str(path)


def tool_version(path: str, label: str) -> Tool:
    try:
        completed = subprocess.run(
            [path, "--version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=TOOL_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise BaselineError(f"cannot obtain {label} version: {error}") from error
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip().splitlines()
        rendered = detail[0] if detail else "no diagnostic output"
        raise BaselineError(f"{label} --version failed: {rendered}")
    lines = (completed.stdout or completed.stderr).strip().splitlines()
    return Tool(label=label, path=path, version=lines[0] if lines else "version unavailable")


def selected_tools(arguments: argparse.Namespace, mode: str) -> dict[str, Tool]:
    values: dict[str, str] = {}
    if mode in {"tidy", "combined"}:
        values["clang_tidy"] = discover_tool(arguments.clang_tidy, "clang-tidy")
    # clang-tidy consumes the staged database through clang/clang++, so it
    # needs both front ends even when the direct analyzer is not selected.
    if mode in {"tidy", "analyzer", "combined"}:
        values["clang"] = discover_tool(arguments.clang, "clang")
        values["clangxx"] = discover_tool(arguments.clangxx, "clang++")
    return {name: tool_version(path, name.replace("_", "-")) for name, path in values.items()}


def validate_check_expression(value: str, label: str) -> str:
    if not value or not re.fullmatch(r"[A-Za-z0-9_.*,-]+", value):
        raise UsageError(f"{label} contains unsupported characters: {value!r}")
    return value


def unsafe_cdb_argument(argument: str) -> bool:
    lower = argument.lower()
    return (
        argument == "-Xclang"
        or argument.startswith("-fplugin")
        or argument.startswith("-fpass-plugin")
        or argument.startswith("-fmodules")
        or argument.startswith("-fmodule-")
        or argument.startswith("-fprofile")
        or argument.startswith("-fcoverage")
        or argument.startswith("-fsave-optimization-record")
        or argument.startswith("-ftime-trace")
        or argument.startswith("-save-temps")
        or argument.startswith("-serialize-diagnostics")
        or argument.startswith("-gen-reproducer")
        or argument.startswith("-emit-")
        or lower in {"-load", "-plugin"}
        or argument.startswith("@")
    )


def source_argument(argument: str, entry: CdbEntry) -> bool:
    candidate = Path(argument)
    if not candidate.is_absolute():
        candidate = entry.directory / candidate
    try:
        return candidate.resolve(strict=False) == entry.source
    except OSError:
        return False


def sanitize_arguments(entry: CdbEntry, compiler: str) -> list[str]:
    """Retain safe compile context while eliminating all output-writing forms."""

    output_with_value = {"-o", "-MF", "-MT", "-MQ", "-MJ", "--output"}
    dependency_only = {"-M", "-MM", "-MD", "-MMD", "-MP", "-MG", "-c", "-S", "-E"}
    result: list[str] = [compiler]
    index = 1
    while index < len(entry.arguments):
        argument = entry.arguments[index]
        if unsafe_cdb_argument(argument):
            raise UsageError(
                f"unsafe compiler argument in compilation database for {entry.source}: {argument}"
            )
        if argument in output_with_value:
            if index + 1 >= len(entry.arguments):
                raise UsageError(f"{argument} has no value for {entry.source}")
            index += 2
            continue
        if argument in dependency_only or argument == "-Werror" or argument.startswith("-Werror="):
            index += 1
            continue
        if argument.startswith(("-o", "-MF", "-MT", "-MQ", "-MJ", "--output=")):
            index += 1
            continue
        if source_argument(argument, entry):
            index += 1
            continue
        result.append(argument)
        index += 1
    result.append(str(entry.source))
    return result


def relative_artifact(path: Path, output_root: Path) -> str:
    try:
        return path.relative_to(output_root).as_posix()
    except ValueError as error:
        raise BaselineError(f"raw artifact escaped ANALYSIS_OUTPUT: {path}") from error


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def worktree_snapshot(root: Path) -> bytes:
    completed = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ],
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", "replace").strip()
        raise BaselineError(f"cannot snapshot working tree: {detail}")
    return completed.stdout


def source_hashes(entries: Iterable[CdbEntry]) -> dict[str, str]:
    return {str(entry.source): sha256_file(entry.source) for entry in entries}


def tidy_config(checks: str, root: Path) -> str:
    return json.dumps(
        {
            "Checks": checks,
            "HeaderFilterRegex": f"^{re.escape(str(root))}/",
            "SystemHeaders": False,
            "UseColor": False,
            "WarningsAsErrors": "",
        },
        separators=(",", ":"),
    )


def run_command(
    command: list[str], directory: Path, stdout_path: Path, stderr_path: Path
) -> tuple[int | None, str | None]:
    try:
        completed = subprocess.run(
            command,
            cwd=directory,
            check=False,
            capture_output=True,
            text=True,
            timeout=TOOL_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        write_text(stdout_path, "")
        write_text(stderr_path, f"tool timed out after {TOOL_TIMEOUT_SECONDS} seconds\n")
        return None, f"timed out after {TOOL_TIMEOUT_SECONDS} seconds"
    except OSError as error:
        write_text(stdout_path, "")
        write_text(stderr_path, f"cannot execute tool: {error}\n")
        return None, f"cannot execute tool: {error}"
    write_text(stdout_path, completed.stdout)
    write_text(stderr_path, completed.stderr)
    if completed.returncode != 0:
        return completed.returncode, f"tool exited with {completed.returncode}"
    return completed.returncode, None


def canonical_location(value: str, root: Path) -> Path:
    if value.startswith("file://"):
        parsed = urlparse(value)
        value = unquote(parsed.path)
    path = Path(value)
    if not path.is_absolute():
        path = root / path
    return path.resolve(strict=False)


def checker_ids(value: str | None) -> list[str]:
    if not value:
        return []
    return sorted({item.strip() for item in value.split(",") if item.strip()})


def is_header(path: Path) -> bool:
    return path.suffix.lower() in HEADER_SUFFIXES


def header_origin(path: Path, system_paths: tuple[Path, ...]) -> str | None:
    if not is_header(path):
        return None
    if is_within(path, Path("/usr/include")) or is_within(path, Path("/usr/local/include")):
        return "system"
    # A project-specific include directory may have been passed as ``-isystem``
    # to suppress its compiler warnings, but it is still third-party code for
    # triage purposes rather than a system header owned by the platform.
    if any(is_within(path, parent) or path == parent for parent in system_paths):
        return "third_party"
    return "third_party"


def classification_for(
    path: Path, checks: list[str], root: Path, system_paths: tuple[Path, ...]
) -> tuple[str, str, str | None]:
    if is_header(path) and not is_within(path, root):
        origin = header_origin(path, system_paths)
        return "third_party_header", "external_header", origin
    if not is_within(path, root):
        return "out_of_scope", "external_non_header", None
    if any(check.startswith("cert-") or "security" in check for check in checks):
        return "possible_security_candidate", "security_or_cert_checker", "repository"
    return "needs_validation", "repository_tool_diagnostic", "repository"


def raw_finding(
    *,
    tool: str,
    source: Path,
    path: Path,
    line: int | None,
    column: int | None,
    severity: str,
    message: str,
    checks: list[str],
    root: Path,
    system_paths: tuple[Path, ...],
    artifact: str,
) -> dict[str, Any]:
    classification, basis, origin = classification_for(path, checks, root, system_paths)
    return {
        "tool": tool,
        "translation_unit": str(source.relative_to(root)),
        "location": {
            "path": str(path),
            "line": line,
            "column": column,
        },
        "severity": severity,
        "message": message,
        "checker_ids": checks,
        "classification": classification,
        "classification_basis": basis,
        "header_origin": origin,
        "raw_artifacts": [artifact],
    }


def parse_tidy_findings(
    text: str,
    entry: CdbEntry,
    root: Path,
    system_paths: tuple[Path, ...],
    artifact: str,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for line in text.splitlines():
        match = TIDY_DIAGNOSTIC.match(line)
        if not match or match.group("severity") == "note":
            continue
        location = canonical_location(match.group("path"), root)
        findings.append(
            raw_finding(
                tool="clang-tidy",
                source=entry.source,
                path=location,
                line=int(match.group("line")),
                column=int(match.group("column")),
                severity=match.group("severity"),
                message=match.group("message"),
                checks=checker_ids(match.group("checks")),
                root=root,
                system_paths=system_paths,
                artifact=artifact,
            )
        )
    return findings


def sarif_locations(result: dict[str, Any]) -> tuple[Path, int | None, int | None]:
    locations = result.get("locations")
    if not isinstance(locations, list) or not locations:
        raise BaselineError("static analyzer SARIF result has no location")
    location = locations[0]
    if not isinstance(location, dict):
        raise BaselineError("static analyzer SARIF location is invalid")
    physical = location.get("physicalLocation")
    if not isinstance(physical, dict):
        raise BaselineError("static analyzer SARIF physical location is invalid")
    artifact = physical.get("artifactLocation")
    if not isinstance(artifact, dict) or not isinstance(artifact.get("uri"), str):
        raise BaselineError("static analyzer SARIF artifact URI is invalid")
    region = physical.get("region")
    if not isinstance(region, dict):
        region = {}
    line = region.get("startLine")
    column = region.get("startColumn")
    return (
        canonical_location(artifact["uri"], repository_root()),
        line if isinstance(line, int) else None,
        column if isinstance(column, int) else None,
    )


def sarif_result_finding(
    result: object,
    path: Path,
    entry: CdbEntry,
    root: Path,
    system_paths: tuple[Path, ...],
    artifact: str,
) -> dict[str, Any]:
    if not isinstance(result, dict):
        raise BaselineError(f"static analyzer SARIF result is invalid: {path}")
    message_value = result.get("message")
    if not isinstance(message_value, dict) or not isinstance(message_value.get("text"), str):
        raise BaselineError(f"static analyzer SARIF message is invalid: {path}")
    rule_id = result.get("ruleId")
    checks = [rule_id] if isinstance(rule_id, str) and rule_id else []
    location, line, column = sarif_locations(result)
    return raw_finding(
        tool="clang-static-analyzer",
        source=entry.source,
        path=location,
        line=line,
        column=column,
        severity=result.get("level") if isinstance(result.get("level"), str) else "warning",
        message=message_value["text"],
        checks=checks,
        root=root,
        system_paths=system_paths,
        artifact=artifact,
    )


def sarif_run_findings(
    run: object,
    path: Path,
    entry: CdbEntry,
    root: Path,
    system_paths: tuple[Path, ...],
    artifact: str,
) -> list[dict[str, Any]]:
    if not isinstance(run, dict):
        raise BaselineError(f"static analyzer SARIF run is invalid: {path}")
    results = run.get("results", [])
    if not isinstance(results, list):
        raise BaselineError(f"static analyzer SARIF results are invalid: {path}")
    return [
        sarif_result_finding(result, path, entry, root, system_paths, artifact)
        for result in results
    ]


def parse_sarif_findings(
    path: Path,
    entry: CdbEntry,
    root: Path,
    system_paths: tuple[Path, ...],
    artifact: str,
) -> list[dict[str, Any]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise BaselineError(f"cannot parse static analyzer SARIF {path}: {error}") from error
    if not isinstance(payload, dict) or not isinstance(payload.get("runs"), list):
        raise BaselineError(f"static analyzer SARIF is not a valid SARIF object: {path}")
    return [
        finding
        for run in payload["runs"]
        for finding in sarif_run_findings(run, path, entry, root, system_paths, artifact)
    ]


def deduplicate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[Any, ...], dict[str, Any]] = {}
    for finding in findings:
        location = finding["location"]
        key = (
            finding["tool"],
            location["path"],
            location["line"],
            location["column"],
            finding["message"],
            tuple(finding["checker_ids"]),
        )
        current = grouped.get(key)
        if current is None:
            current = dict(finding)
            current["raw_artifacts"] = list(finding["raw_artifacts"])
            current["contributing_translation_units"] = [finding["translation_unit"]]
            current["occurrence_count"] = 1
            grouped[key] = current
            continue
        current["occurrence_count"] += 1
        current["raw_artifacts"] = sorted(
            set(current["raw_artifacts"]) | set(finding["raw_artifacts"])
        )
        current["contributing_translation_units"] = sorted(
            set(current["contributing_translation_units"]) | {finding["translation_unit"]}
        )
    normalized: list[dict[str, Any]] = []
    for key in sorted(grouped, key=lambda value: tuple(str(item) for item in value)):
        finding = grouped[key]
        identity = json.dumps(key, separators=(",", ":"), ensure_ascii=True)
        finding["id"] = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20]
        normalized.append(finding)
    return normalized


def prepare_tidy_database(
    entries: tuple[CdbEntry, ...], stage: Path, clang: str, clangxx: str
) -> Path:
    database: list[dict[str, Any]] = []
    for entry in entries:
        compiler = clang if entry.language == "c17" else clangxx
        arguments = sanitize_arguments(entry, compiler)
        arguments.insert(-1, "-fsyntax-only")
        database.append(
            {
                "directory": str(entry.directory),
                "file": str(entry.source),
                "arguments": arguments,
            }
        )
    path = stage / "compile_commands.json"
    path.write_text(json.dumps(database, indent=2) + "\n", encoding="utf-8")
    return path


def run_tidy(
    invocation: Invocation,
    tools: dict[str, Tool],
    checks: str,
    stage: Path,
    raw_root: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    config = tidy_config(checks, invocation.repository_root)
    tidy = tools["clang_tidy"]
    active_stdout = raw_root / "tidy" / "active-checks.stdout.log"
    active_stderr = raw_root / "tidy" / "active-checks.stderr.log"
    code, error = run_command(
        [tidy.path, "--list-checks", f"--config={config}"],
        invocation.repository_root,
        active_stdout,
        active_stderr,
    )
    failures: list[dict[str, Any]] = []
    if error:
        failures.append(
            {
                "stage": "active_checks",
                "tool": "clang-tidy",
                "returncode": code,
                "message": error,
                "raw_artifacts": [
                    relative_artifact(active_stdout, invocation.output_root),
                    relative_artifact(active_stderr, invocation.output_root),
                ],
            }
        )
    active_checks = [
        line.strip()
        for line in active_stdout.read_text(encoding="utf-8").splitlines()
        if line.startswith(("    ", "  "))
    ]
    findings: list[dict[str, Any]] = []
    system_paths = tuple(
        sorted(
            {path for entry in invocation.entries for path in entry.system_include_dirs},
            key=lambda path: path.as_posix(),
        )
    )
    completed = 0
    for index, entry in enumerate(invocation.entries, start=1):
        base = raw_root / "tidy" / f"{index:03d}-{entry.source.stem}"
        stdout_path = base.with_suffix(".stdout.log")
        stderr_path = base.with_suffix(".stderr.log")
        code, error = run_command(
            [
                tidy.path,
                str(entry.source),
                "-p",
                str(stage),
                f"--config={config}",
                "--quiet",
            ],
            entry.directory,
            stdout_path,
            stderr_path,
        )
        artifacts = [
            relative_artifact(stdout_path, invocation.output_root),
            relative_artifact(stderr_path, invocation.output_root),
        ]
        if error:
            failures.append(
                {
                    "stage": "analysis",
                    "tool": "clang-tidy",
                    "translation_unit": str(entry.source.relative_to(invocation.repository_root)),
                    "returncode": code,
                    "message": error,
                    "raw_artifacts": artifacts,
                }
            )
        else:
            completed += 1
        findings.extend(
            parse_tidy_findings(
                stdout_path.read_text(encoding="utf-8")
                + "\n"
                + stderr_path.read_text(encoding="utf-8"),
                entry,
                invocation.repository_root,
                system_paths,
                artifacts[1],
            )
        )
    return findings, failures, {
        "requested_checks": checks,
        "active_checks": sorted(set(active_checks)),
        "active_checks_artifacts": [
            relative_artifact(active_stdout, invocation.output_root),
            relative_artifact(active_stderr, invocation.output_root),
        ],
        "translation_units_attempted": len(invocation.entries),
        "translation_units_completed": completed,
    }


def run_analyzer(
    invocation: Invocation,
    tools: dict[str, Tool],
    checks: str,
    raw_root: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    system_paths = tuple(
        sorted(
            {path for entry in invocation.entries for path in entry.system_include_dirs},
            key=lambda path: path.as_posix(),
        )
    )
    completed = 0
    for index, entry in enumerate(invocation.entries, start=1):
        tool = tools["clang"] if entry.language == "c17" else tools["clangxx"]
        base = raw_root / "analyzer" / f"{index:03d}-{entry.source.stem}"
        stdout_path = base.with_suffix(".stdout.log")
        stderr_path = base.with_suffix(".stderr.log")
        sarif_path = base.with_suffix(".sarif")
        sarif_path.parent.mkdir(parents=True, exist_ok=True)
        command = [
            tool.path,
            "--analyze",
            "--analyzer-output",
            "sarif",
            "-o",
            str(sarif_path),
            "-fno-color-diagnostics",
            "-Wno-error",
            "-Xclang",
            f"-analyzer-checker={checks}",
            *sanitize_arguments(entry, tool.path)[1:],
        ]
        code, error = run_command(command, entry.directory, stdout_path, stderr_path)
        artifacts = [
            relative_artifact(stdout_path, invocation.output_root),
            relative_artifact(stderr_path, invocation.output_root),
            relative_artifact(sarif_path, invocation.output_root),
        ]
        if error:
            failures.append(
                {
                    "stage": "analysis",
                    "tool": "clang-static-analyzer",
                    "translation_unit": str(entry.source.relative_to(invocation.repository_root)),
                    "returncode": code,
                    "message": error,
                    "raw_artifacts": artifacts,
                }
            )
            continue
        if not sarif_path.is_file():
            failures.append(
                {
                    "stage": "analysis",
                    "tool": "clang-static-analyzer",
                    "translation_unit": str(entry.source.relative_to(invocation.repository_root)),
                    "returncode": code,
                    "message": "tool completed without its owned SARIF report",
                    "raw_artifacts": artifacts[:2],
                }
            )
            continue
        try:
            findings.extend(
                parse_sarif_findings(
                    sarif_path,
                    entry,
                    invocation.repository_root,
                    system_paths,
                    artifacts[2],
                )
            )
            completed += 1
        except BaselineError as error:
            failures.append(
                {
                    "stage": "normalize",
                    "tool": "clang-static-analyzer",
                    "translation_unit": str(entry.source.relative_to(invocation.repository_root)),
                    "returncode": code,
                    "message": str(error),
                    "raw_artifacts": artifacts,
                }
            )
    return findings, failures, {
        "requested_checks": checks,
        "route": "direct clang --analyze with owned SARIF output",
        "translation_units_attempted": len(invocation.entries),
        "translation_units_completed": completed,
    }


def summarize(
    *,
    mode: str,
    invocation: Invocation,
    tools: dict[str, Tool],
    compdb_hash: str,
    tidy_profile: dict[str, Any] | None,
    analyzer_profile: dict[str, Any] | None,
    raw_findings: list[dict[str, Any]],
    failures: list[dict[str, Any]],
    worktree_unchanged: bool,
    source_files_unchanged: bool,
    compdb_unchanged: bool,
) -> dict[str, Any]:
    findings = deduplicate_findings(raw_findings)
    counts = Counter(finding["classification"] for finding in findings)
    classifications = {name: counts.get(name, 0) for name in ALLOWED_CLASSIFICATIONS}
    complete = not failures and worktree_unchanged and source_files_unchanged and compdb_unchanged
    if not worktree_unchanged:
        failures.append(
            {
                "stage": "read_only_verification",
                "tool": "runner",
                "message": "repository working-tree status changed during analysis",
            }
        )
    if not source_files_unchanged:
        failures.append(
            {
                "stage": "read_only_verification",
                "tool": "runner",
                "message": "analyzed source content changed during analysis",
            }
        )
    if not compdb_unchanged:
        failures.append(
            {
                "stage": "read_only_verification",
                "tool": "runner",
                "message": "compilation database content changed during analysis",
            }
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": mode,
        "status": "complete" if complete else "technical_error",
        "analysis_complete": complete,
        "exit_code_semantics": {
            "0": "analysis completed; findings may be present",
            "2": "invalid or unsafe parameters",
            "77": "tool or prerequisite missing",
            "other_nonzero": "technical analysis failure",
        },
        "generated_at_utc": utc_now(),
        "compilation_database": {
            "path": str(invocation.compdb_path),
            "sha256": compdb_hash,
            "translation_unit_count": len(invocation.entries),
            "c17_translation_unit_count": sum(
                entry.language == "c17" for entry in invocation.entries
            ),
            "cxx17_translation_unit_count": sum(
                entry.language == "cxx17" for entry in invocation.entries
            ),
        },
        "tools": {
            name: {"path": tool.path, "version": tool.version}
            for name, tool in sorted(tools.items())
        },
        "profiles": {
            "clang_tidy": tidy_profile,
            "clang_static_analyzer": analyzer_profile,
        },
        "raw_occurrence_count": len(raw_findings),
        "unique_finding_count": len(findings),
        "allowed_classifications": list(ALLOWED_CLASSIFICATIONS),
        "classification_counts": classifications,
        "findings": findings,
        "technical_failures": failures,
        "read_only_verification": {
            "worktree_status_unchanged": worktree_unchanged,
            "analyzed_source_files_unchanged": source_files_unchanged,
            "compilation_database_unchanged": compdb_unchanged,
        },
    }


def summary_file(mode: str) -> str:
    return {
        "tidy": "clang-tidy-baseline.json",
        "analyzer": "clang-analyzer-baseline.json",
        "combined": "clang-analysis-baseline.json",
    }[mode]


def safe_cleanup(path: Path, output_root: Path, temp_root: Path) -> None:
    resolved = path.resolve(strict=False)
    if (
        not is_within(resolved, output_root)
        or not is_within(resolved, temp_root)
        or not resolved.name.startswith(".clang-analysis-stage-")
    ):
        raise BaselineError(f"refusing unsafe staging cleanup: {resolved}")
    if resolved.exists():
        shutil.rmtree(resolved)


def write_individual_summary(
    mode: str,
    base: dict[str, Any],
    output_root: Path,
) -> None:
    atomic_json(output_root / summary_file(mode), base)


def run_baseline(arguments: argparse.Namespace) -> int:
    mode = arguments.mode
    tidy_checks = validate_check_expression(arguments.tidy_checks, "CLANG_TIDY_CHECKS")
    analyzer_checks = validate_check_expression(
        arguments.analyzer_checks, "CLANG_ANALYZER_CHECKS"
    )
    invocation = validate_invocation(arguments)
    tools = selected_tools(arguments, mode)
    compdb_hash_before = sha256_file(invocation.compdb_path)
    invocation.output_root.mkdir(parents=True, exist_ok=True)
    run_id = uuid.uuid4().hex
    stage = invocation.output_root / f".clang-analysis-stage-{run_id}"
    raw_root = invocation.output_root / "raw" / run_id
    stage.mkdir(parents=True, exist_ok=False)
    raw_root.mkdir(parents=True, exist_ok=False)
    status_before = worktree_snapshot(invocation.repository_root)
    sources_before = source_hashes(invocation.entries)
    raw_findings: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    tidy_profile: dict[str, Any] | None = None
    analyzer_profile: dict[str, Any] | None = None
    try:
        if mode in {"tidy", "combined"}:
            prepare_tidy_database(
                invocation.entries,
                stage,
                tools["clang"].path,
                tools["clangxx"].path,
            )
            tidy_findings, tidy_failures, tidy_profile = run_tidy(
                invocation, tools, tidy_checks, stage, raw_root
            )
            raw_findings.extend(tidy_findings)
            failures.extend(tidy_failures)
        if mode in {"analyzer", "combined"}:
            analyzer_findings, analyzer_failures, analyzer_profile = run_analyzer(
                invocation, tools, analyzer_checks, raw_root
            )
            raw_findings.extend(analyzer_findings)
            failures.extend(analyzer_failures)
    except BaselineError as error:
        failures.append({"stage": "runner", "tool": "runner", "message": str(error)})
    except Exception as error:  # Preserve a normalized result for unexpected technical failures.
        failures.append(
            {
                "stage": "runner",
                "tool": "runner",
                "message": f"unexpected error: {error}",
            }
        )
    finally:
        try:
            safe_cleanup(stage, invocation.output_root, invocation.temp_root)
        except BaselineError as error:
            failures.append({"stage": "cleanup", "tool": "runner", "message": str(error)})
    try:
        compdb_hash_after = sha256_file(invocation.compdb_path)
        status_after = worktree_snapshot(invocation.repository_root)
        sources_after = source_hashes(invocation.entries)
    except BaselineError as error:
        failures.append({"stage": "read_only_verification", "tool": "runner", "message": str(error)})
        compdb_hash_after = ""
        status_after = b""
        sources_after = {}
    summary = summarize(
        mode=mode,
        invocation=invocation,
        tools=tools,
        compdb_hash=compdb_hash_before,
        tidy_profile=tidy_profile,
        analyzer_profile=analyzer_profile,
        raw_findings=raw_findings,
        failures=failures,
        worktree_unchanged=status_before == status_after,
        source_files_unchanged=sources_before == sources_after,
        compdb_unchanged=compdb_hash_before == compdb_hash_after,
    )
    write_individual_summary(mode, summary, invocation.output_root)
    print(
        f"{summary['status'].upper()}: {mode} baseline completed with "
        f"{summary['unique_finding_count']} normalized finding(s)"
    )
    for name, count in summary["classification_counts"].items():
        if count:
            print(f"CLASSIFICATION: {name}={count}")
    if summary["analysis_complete"]:
        return EXIT_OK
    for failure in summary["technical_failures"]:
        print(
            f"TECHNICAL: {failure.get('tool', 'runner')}: {failure.get('message', 'unknown failure')}",
            file=sys.stderr,
        )
    print("FAIL: analysis had technical failures; see normalized JSON", file=sys.stderr)
    return EXIT_TECHNICAL_FAILURE


def check_tools(arguments: argparse.Namespace) -> int:
    tools = selected_tools(arguments, "combined")
    for name in ("clang_tidy", "clang", "clangxx"):
        tool = tools[name]
        print(f"{tool.label}: {tool.path} ({tool.version})")
    print("PASS: clang-tidy and direct clang static-analysis tools are available")
    return EXIT_OK


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="run an opt-in, read-only advisory Clang analysis baseline"
    )
    parser.add_argument("--check-tools", action="store_true")
    parser.add_argument("--mode", choices=("tidy", "analyzer", "combined"))
    parser.add_argument("--compdb-output", default=os.environ.get("COMPDB_OUTPUT", ""))
    parser.add_argument("--analysis-output", default=os.environ.get("ANALYSIS_OUTPUT", ""))
    parser.add_argument("--clang-tidy", default=os.environ.get("CLANG_TIDY", "clang-tidy"))
    parser.add_argument("--clang", default=os.environ.get("CLANG", "clang"))
    parser.add_argument("--clangxx", default=os.environ.get("CLANGXX", "clang++"))
    parser.add_argument(
        "--tidy-checks", default=os.environ.get("CLANG_TIDY_CHECKS", "-*,bugprone-*,cert-*")
    )
    parser.add_argument(
        "--analyzer-checks",
        default=os.environ.get("CLANG_ANALYZER_CHECKS", "core,unix,security,cplusplus,deadcode"),
    )
    parsed = parser.parse_args()
    if parsed.check_tools:
        if parsed.mode:
            parser.error("--check-tools cannot be combined with --mode")
    elif not parsed.mode:
        parser.error("--mode is required unless --check-tools is used")
    return parsed


def main() -> int:
    try:
        arguments = parse_arguments()
        return check_tools(arguments) if arguments.check_tools else run_baseline(arguments)
    except BaselineError as error:
        prefix = "BLOCKED" if error.exit_code == EXIT_BLOCKED else "FAIL"
        print(f"{prefix}: {error}", file=sys.stderr)
        return error.exit_code
    except SystemExit:
        raise
    except Exception as error:
        print(f"FAIL: unexpected technical error: {error}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return EXIT_TECHNICAL_FAILURE


if __name__ == "__main__":
    raise SystemExit(main())
