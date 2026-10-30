#!/usr/bin/env python3
"""Produce a bounded, raw-payload-free aggregate from NGINX Memcheck logs.

The NGINX harness owns the diagnostic lifecycle.  This helper deliberately
does not interpret request/response data or print Valgrind excerpts: it only
aggregates terminal counters and whether the expected normal master/worker
evidence was retained beneath the already-validated harness evidence directory.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import stat
import sys
from pathlib import Path
from typing import Iterable, NamedTuple




from modsecurity_connector_ci.lib.runtime_path_utils import runtime_artifact_path, verified_runtime_artifact_root  # noqa: E402


MAX_LOG_BYTES = 4 * 1024 * 1024
MAX_METADATA_BYTES = 64 * 1024
LOG_NAME_RE = re.compile(r"valgrind\.(?P<pid>\d+)\.log\Z", re.ASCII)
ROLES_FILENAME = "nginx-memcheck-roles.txt"
LIFECYCLE_FILENAME = "nginx-memcheck-lifecycle.txt"
SUMMARY_JSON_FILENAME = "nginx-memcheck-summary.json"
SUMMARY_TEXT_FILENAME = "nginx-memcheck-summary.txt"
JSON_OUTPUT_LABEL = "JSON output"
TEXT_OUTPUT_LABEL = "text output"
ERROR_SUMMARY_RE = re.compile(r"ERROR SUMMARY:\s*(?P<count>[0-9,]+)\s+errors", re.IGNORECASE)
LEAK_RE = {
    "definitely_lost_bytes": re.compile(
        r"definitely lost:\s*(?P<count>[0-9,]+)\s+bytes", re.IGNORECASE
    ),
    "indirectly_lost_bytes": re.compile(
        r"indirectly lost:\s*(?P<count>[0-9,]+)\s+bytes", re.IGNORECASE
    ),
    "possibly_lost_bytes": re.compile(
        r"possibly lost:\s*(?P<count>[0-9,]+)\s+bytes", re.IGNORECASE
    ),
    "still_reachable_bytes": re.compile(
        r"still reachable:\s*(?P<count>[0-9,]+)\s+bytes", re.IGNORECASE
    ),
}


class UnsafeEvidenceError(ValueError):
    """An evidence input cannot safely contribute to a clean aggregate."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


class MetadataReadConfig(NamedTuple):
    """Describe the bounded metadata input and its payload-free failure reasons."""

    label: str
    reason_prefix: str
    missing_reason: str
    invalid_reason: str
    too_large_reason: str
    maximum_lines: int


ROLES_METADATA = MetadataReadConfig(
    label="roles file",
    reason_prefix="roles_file",
    missing_reason="roles_file_missing",
    invalid_reason="roles_file_invalid",
    too_large_reason="roles_file_too_large",
    maximum_lines=128,
)
LIFECYCLE_METADATA = MetadataReadConfig(
    label="lifecycle file",
    reason_prefix="lifecycle_file",
    missing_reason="lifecycle_file_missing",
    invalid_reason="lifecycle_file_invalid",
    too_large_reason="lifecycle_file_too_large",
    maximum_lines=64,
)


def parse_count(value: str) -> int:
    return int(value.replace(",", ""))


def absolute_path(path: Path) -> Path:
    """Normalize lexical paths without resolving an attacker-controlled symlink."""

    return Path(os.path.abspath(os.fspath(path)))


def same_file(first: os.stat_result, second: os.stat_result) -> bool:
    return first.st_dev == second.st_dev and first.st_ino == second.st_ino


def file_signature(file_stat: os.stat_result) -> tuple[int, int, int, int, int, int, int, int]:
    """Capture properties that must not change between validation and reading."""

    return (
        file_stat.st_dev,
        file_stat.st_ino,
        file_stat.st_mode,
        file_stat.st_uid,
        file_stat.st_nlink,
        file_stat.st_size,
        file_stat.st_mtime_ns,
        file_stat.st_ctime_ns,
    )


def validate_private_directory(path: Path, label: str) -> Path:
    """Validate a non-symlink directory before trusting evidence beneath it."""

    candidate = absolute_path(path)
    try:
        before = candidate.lstat()
    except FileNotFoundError as exc:
        raise ValueError(f"{label} is missing") from exc
    if stat.S_ISLNK(before.st_mode):
        raise ValueError(f"{label} must not be a symlink")
    if not stat.S_ISDIR(before.st_mode):
        raise ValueError(f"{label} is not a real directory")
    if before.st_uid != os.geteuid():
        raise ValueError(f"{label} is not owned by the effective uid")
    if before.st_mode & 0o022:
        raise ValueError(f"{label} is group or other writable")

    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(candidate, flags)
    except OSError as exc:
        raise ValueError(f"{label} cannot be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
    finally:
        os.close(descriptor)

    if not same_file(before, opened):
        raise ValueError(f"{label} changed while being opened")
    if not stat.S_ISDIR(opened.st_mode):
        raise ValueError(f"{label} is not a real directory")
    if opened.st_uid != os.geteuid():
        raise ValueError(f"{label} is not owned by the effective uid")
    if opened.st_mode & 0o022:
        raise ValueError(f"{label} is group or other writable")
    return candidate


def validate_evidence_root(verified_run_root: Path, log_dir: Path) -> Path:
    """Bind evidence to the verified run root before touching its directory."""

    verified_root = verified_runtime_artifact_root(verified_run_root)
    root = absolute_path(log_dir)
    if root == verified_root:
        raise ValueError("log directory must be a descendant of the verified runtime root")

    # Use the repository-native runtime artifact authority before lstat, list,
    # open, temporary-file creation, or replacement under the supplied
    # evidence directory. The boundary leaf is source-controlled, so this
    # check cannot turn an intentionally malformed metadata child into an
    # early CLI rejection; the existing aggregator still reports that input
    # as incomplete and payload-free.
    runtime_artifact_path(
        verified_root, root / ".memcheck-summarizer-boundary", "log directory boundary"
    )
    validate_private_directory(root.parent, "log directory parent")
    return validate_private_directory(root, "log directory")


def require_direct_child(log_dir: Path, path: Path, label: str) -> Path:
    """Reject outputs or metadata outside the harness-owned evidence root."""

    root = absolute_path(log_dir)
    candidate = absolute_path(path)
    if candidate.parent != root:
        raise ValueError(f"{label} must be a direct child of the log directory")
    return candidate


def evidence_artifact_paths(log_dir: Path) -> tuple[Path, Path, Path, Path]:
    """Return the only source-controlled metadata and output children."""

    root = absolute_path(log_dir)
    return (
        root / ROLES_FILENAME,
        root / LIFECYCLE_FILENAME,
        root / SUMMARY_JSON_FILENAME,
        root / SUMMARY_TEXT_FILENAME,
    )


def validate_private_regular_file(
    file_stat: os.stat_result, label: str, reason_prefix: str
) -> None:
    """Apply the ownership, link, and access invariant to one evidence file."""

    if stat.S_ISLNK(file_stat.st_mode):
        raise UnsafeEvidenceError(
            f"{reason_prefix}_symlink", f"{label} must not be a symlink"
        )
    if not stat.S_ISREG(file_stat.st_mode):
        raise UnsafeEvidenceError(
            f"{reason_prefix}_invalid", f"{label} is not a regular file"
        )
    if file_stat.st_nlink != 1:
        raise UnsafeEvidenceError(
            f"{reason_prefix}_hardlink", f"{label} must have exactly one link"
        )
    if file_stat.st_uid != os.geteuid():
        raise UnsafeEvidenceError(
            f"{reason_prefix}_owner_unsafe",
            f"{label} is not owned by the effective uid",
        )
    if file_stat.st_mode & 0o077:
        raise UnsafeEvidenceError(
            f"{reason_prefix}_permissions_unsafe",
            f"{label} is group or other accessible",
        )


def open_private_input(
    log_dir: Path,
    path: Path,
    label: str,
    reason_prefix: str,
    maximum_bytes: int,
    *,
    tail: bool,
) -> tuple[bytes, bool]:
    """Open one direct child without following a late symlink substitution."""

    candidate = require_direct_child(log_dir, path, label)
    try:
        before = candidate.lstat()
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise UnsafeEvidenceError(
            f"{reason_prefix}_unsafe", f"{label} cannot be inspected safely"
        ) from exc
    validate_private_regular_file(before, label, reason_prefix)

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(candidate, flags)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise UnsafeEvidenceError(
            f"{reason_prefix}_unsafe", f"{label} cannot be opened safely"
        ) from exc

    try:
        opened = os.fstat(descriptor)
        validate_private_regular_file(opened, label, reason_prefix)
        if file_signature(before) != file_signature(opened):
            raise UnsafeEvidenceError(
                f"{reason_prefix}_changed", f"{label} changed while being opened"
            )
        truncated = opened.st_size > maximum_bytes
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            if tail and truncated:
                handle.seek(-maximum_bytes, os.SEEK_END)
            data = handle.read(maximum_bytes)
        after = os.fstat(descriptor)
    except UnsafeEvidenceError:
        raise
    except OSError as exc:
        raise UnsafeEvidenceError(
            f"{reason_prefix}_unsafe", f"{label} could not be read safely"
        ) from exc
    finally:
        os.close(descriptor)

    if file_signature(opened) != file_signature(after):
        raise UnsafeEvidenceError(
            f"{reason_prefix}_changed", f"{label} changed while being read"
        )
    return data, truncated


def read_tail(log_dir: Path, path: Path) -> tuple[str, bool]:
    """Read a bounded tail that contains Valgrind's terminal summary."""

    data, truncated = open_private_input(
        log_dir,
        path,
        "Valgrind log",
        "valgrind_log",
        MAX_LOG_BYTES,
        tail=True,
    )
    return data.decode("utf-8", errors="replace"), truncated


def read_metadata(log_dir: Path, path: Path, label: str, reason_prefix: str) -> tuple[str, bool]:
    data, truncated = open_private_input(
        log_dir, path, label, reason_prefix, MAX_METADATA_BYTES, tail=False
    )
    return data.decode("utf-8", errors="replace"), truncated


def read_metadata_lines(
    log_dir: Path, path: Path | None, config: MetadataReadConfig
) -> tuple[list[str] | None, list[str]]:
    if path is None:
        return None, [config.missing_reason]
    try:
        raw_text, truncated = read_metadata(
            log_dir, path, config.label, config.reason_prefix
        )
    except FileNotFoundError:
        return None, [config.missing_reason]
    except UnsafeEvidenceError as exc:
        return None, [exc.reason]
    except (OSError, ValueError):
        return None, [config.invalid_reason]
    if truncated:
        return None, [config.too_large_reason]

    raw_lines = raw_text.splitlines()
    if len(raw_lines) > config.maximum_lines:
        return None, [config.too_large_reason]
    return raw_lines, []


def parse_role_lines(raw_lines: Iterable[str]) -> tuple[set[str], set[str], list[str]]:
    """Parse harness-controlled role lines after private bounded input validation."""

    masters: set[str] = set()
    workers: set[str] = set()
    reasons: list[str] = []
    for raw_line in raw_lines:
        if not raw_line:
            continue
        key, separator, value = raw_line.partition("=")
        if not separator or not value.isdecimal():
            reasons.append("roles_file_invalid")
            continue
        if key == "master_pid":
            masters.add(value)
        elif key == "worker_pid":
            workers.add(value)
        else:
            reasons.append("roles_file_invalid")
    if len(masters) != 1:
        reasons.append("master_snapshot_missing")
    if not workers:
        reasons.append("worker_snapshot_missing")
    return masters, workers, reasons


def parse_lifecycle_lines(raw_lines: Iterable[str]) -> tuple[dict[str, str], list[str]]:
    """Parse harness-controlled lifecycle lines after private bounded input validation."""

    values: dict[str, str] = {}
    reasons: list[str] = []
    for raw_line in raw_lines:
        key, separator, value = raw_line.partition("=")
        if not separator or key not in {"shutdown", "wait", "wrapper_exit_code", "containment"}:
            reasons.append("lifecycle_file_invalid")
            continue
        if key in values:
            reasons.append("lifecycle_file_invalid")
            continue
        values[key] = value
    if values.get("shutdown") not in {"graceful", "forced", "forced_term", "forced_kill"}:
        reasons.append("shutdown_status_missing")
    if values.get("wait") not in {"exited", "timed_out"}:
        reasons.append("wait_status_missing")
    if not values.get("wrapper_exit_code", "").isdecimal():
        reasons.append("wrapper_exit_status_missing")
    if values.get("containment") not in {"isolated", "unverified"}:
        reasons.append("containment_status_missing")
    return values, reasons


def parse_roles(log_dir: Path, path: Path | None) -> tuple[set[str], set[str], list[str]]:
    raw_lines, reasons = read_metadata_lines(log_dir, path, ROLES_METADATA)
    if raw_lines is None:
        return set(), set(), reasons
    masters, workers, parse_reasons = parse_role_lines(raw_lines)
    reasons.extend(parse_reasons)
    return masters, workers, reasons


def parse_lifecycle(log_dir: Path, path: Path | None) -> tuple[dict[str, str], list[str]]:
    raw_lines, reasons = read_metadata_lines(log_dir, path, LIFECYCLE_METADATA)
    if raw_lines is None:
        return {}, reasons
    values, parse_reasons = parse_lifecycle_lines(raw_lines)
    reasons.extend(parse_reasons)
    return values, reasons


def unique_reasons(reasons: Iterable[str]) -> list[str]:
    return sorted(set(reasons))


def status_for(*, errors_detected: bool, incomplete: bool) -> str:
    if errors_detected and incomplete:
        return "error_incomplete"
    if errors_detected:
        return "error"
    if incomplete:
        return "incomplete"
    return "clean"


def write_text(handle, summary: dict[str, object]) -> None:
    lines = [
        f"status={summary['status']}",
        f"complete={int(bool(summary['complete']))}",
        f"errors_detected={int(bool(summary['errors_detected']))}",
        f"logs_seen={summary['logs_seen']}",
        f"logs_with_final_summary={summary['logs_with_final_summary']}",
        f"error_count={summary['error_count']}",
        f"definitely_lost_bytes={summary['definitely_lost_bytes']}",
        f"indirectly_lost_bytes={summary['indirectly_lost_bytes']}",
        f"possibly_lost_bytes={summary['possibly_lost_bytes']}",
        f"still_reachable_bytes={summary['still_reachable_bytes']}",
        f"truncated_log_inputs={summary['truncated_log_inputs']}",
        f"private_log_inputs={summary['private_log_inputs']}",
        f"incomplete_reasons={','.join(summary['incomplete_reasons'])}",
    ]
    handle.write("\n".join(lines) + "\n")


def write_json(handle, summary: dict[str, object]) -> None:
    json.dump(summary, handle, indent=2, sort_keys=True)
    handle.write("\n")


def validate_output_target(log_dir: Path, path: Path, label: str) -> Path:
    """Existing output targets are evidence files too; absent targets are created safely."""

    candidate = require_direct_child(log_dir, path, label)
    try:
        file_stat = candidate.lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise ValueError(f"{label} cannot be inspected safely") from exc
    else:
        try:
            validate_private_regular_file(file_stat, label, "output")
        except UnsafeEvidenceError as exc:
            raise ValueError(f"{label} is unsafe: {exc}") from exc
    return candidate


def atomic_write(log_dir: Path, path: Path, label: str, writer, summary: dict[str, object]) -> None:
    """Create a private direct-child output without following an existing symlink."""

    output = validate_output_target(log_dir, path, label)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        log_dir_fd = os.open(log_dir, flags)
    except OSError as exc:
        raise ValueError(f"{label} directory cannot be opened safely") from exc

    descriptor = -1
    temporary_name: str | None = None
    try:
        for _ in range(64):
            candidate_name = f".{output.name}.{secrets.token_hex(16)}.tmp"
            try:
                descriptor = os.open(
                    candidate_name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                    dir_fd=log_dir_fd,
                )
            except FileExistsError:
                continue
            temporary_name = candidate_name
            break
        if descriptor == -1 or temporary_name is None:
            raise ValueError(f"{label} cannot create a private temporary output")
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            writer(handle, summary)
        os.replace(
            temporary_name,
            output.name,
            src_dir_fd=log_dir_fd,
            dst_dir_fd=log_dir_fd,
        )
        temporary_name = None
        validate_output_target(log_dir, output, label)
    finally:
        if descriptor != -1:
            os.close(descriptor)
        if temporary_name is not None:
            try:
                os.unlink(temporary_name, dir_fd=log_dir_fd)
            except FileNotFoundError:
                pass
        os.close(log_dir_fd)


def require_distinct_paths(paths: Iterable[tuple[str, Path]]) -> None:
    """Prevent an output path from replacing metadata or another requested output."""

    seen: dict[Path, str] = {}
    for label, path in paths:
        if path in seen:
            raise ValueError(f"{label} must not alias {seen[path]}")
        seen[path] = label


def collect_log_files(log_dir: Path) -> dict[str, Path]:
    """Collect only the harness-controlled Valgrind log filenames."""

    log_files: dict[str, Path] = {}
    try:
        candidates = tuple(log_dir.iterdir())
    except OSError as exc:
        raise ValueError("log directory cannot be listed safely") from exc
    for candidate in candidates:
        match = LOG_NAME_RE.fullmatch(candidate.name)
        if match is None:
            continue
        log_files[match.group("pid")] = candidate
    return log_files


def missing_log_reasons(
    log_files: dict[str, Path], masters: Iterable[str], workers: Iterable[str]
) -> list[str]:
    """Report role evidence that has no corresponding Valgrind log."""

    reasons: list[str] = []
    if not log_files:
        reasons.append("valgrind_logs_missing")
    for master_pid in masters:
        if master_pid not in log_files:
            reasons.append("master_log_missing")
    for worker_pid in workers:
        if worker_pid not in log_files:
            reasons.append("worker_log_missing")
    return reasons


def parse_log_counters(text: str) -> tuple[int, dict[str, int], int, list[str]]:
    """Extract bounded terminal counters without retaining log payloads."""

    error_matches = ERROR_SUMMARY_RE.findall(text)
    error_count = parse_count(error_matches[-1]) if error_matches else 0
    reasons = [] if error_matches else ["valgrind_final_summary_missing"]
    leak_counts = dict.fromkeys(LEAK_RE, 0)
    for name, pattern in LEAK_RE.items():
        leak_matches = pattern.findall(text)
        if leak_matches:
            leak_counts[name] = parse_count(leak_matches[-1])
    return error_count, leak_counts, int(bool(error_matches)), reasons


def unreadable_log_counters(reason: str) -> tuple[int, dict[str, int], int, int, int, list[str]]:
    """Represent one rejected input without letting it affect trusted counters."""

    return 0, dict.fromkeys(LEAK_RE, 0), 0, 0, 0, [reason]


def read_log_counters(
    log_dir: Path, log_path: Path
) -> tuple[int, dict[str, int], int, int, int, list[str]]:
    """Read one private log through the existing no-follow descriptor path."""

    try:
        text, truncated = read_tail(log_dir, log_path)
    except FileNotFoundError:
        return unreadable_log_counters("valgrind_log_missing")
    except UnsafeEvidenceError as exc:
        return unreadable_log_counters(exc.reason)
    except (OSError, ValueError):
        return unreadable_log_counters("valgrind_log_invalid")
    error_count, leak_counts, final_summary_count, reasons = parse_log_counters(text)
    return error_count, leak_counts, final_summary_count, int(truncated), 1, reasons


def aggregate_log_counters(
    log_dir: Path, log_files: Iterable[Path]
) -> tuple[int, dict[str, int], int, int, int, list[str]]:
    """Aggregate private input results while keeping each rejected reason."""

    error_count = 0
    leak_counts = dict.fromkeys(LEAK_RE, 0)
    final_summary_count = 0
    truncated_log_inputs = 0
    private_log_inputs = 0
    reasons: list[str] = []
    for log_path in log_files:
        (
            log_error_count,
            log_leak_counts,
            log_final_summary_count,
            log_truncated_inputs,
            log_private_inputs,
            log_reasons,
        ) = read_log_counters(log_dir, log_path)
        error_count += log_error_count
        final_summary_count += log_final_summary_count
        truncated_log_inputs += log_truncated_inputs
        private_log_inputs += log_private_inputs
        reasons.extend(log_reasons)
        for name, count in log_leak_counts.items():
            leak_counts[name] += count
    return (
        error_count,
        leak_counts,
        final_summary_count,
        truncated_log_inputs,
        private_log_inputs,
        reasons,
    )


def lifecycle_outcome(lifecycle: dict[str, str]) -> tuple[int, list[str]]:
    """Convert lifecycle metadata into summary errors and incomplete reasons."""

    reasons: list[str] = []
    if lifecycle.get("shutdown") != "graceful" or lifecycle.get("wait") == "timed_out":
        reasons.append("graceful_shutdown_incomplete")
    if lifecycle.get("containment") != "isolated":
        reasons.append("process_group_unverified")
    wrapper_exit_code = lifecycle.get("wrapper_exit_code")
    if wrapper_exit_code == "99":
        return 1, reasons
    if wrapper_exit_code and wrapper_exit_code != "0":
        reasons.append("wrapper_exit_nonzero")
    return 0, reasons


def summarize(log_dir: Path, roles_file: Path | None, lifecycle_file: Path | None) -> dict[str, object]:
    log_files = collect_log_files(log_dir)

    masters, workers, role_reasons = parse_roles(log_dir, roles_file)
    lifecycle, lifecycle_metadata_reasons = parse_lifecycle(log_dir, lifecycle_file)
    (
        error_count,
        leak_counts,
        final_summary_count,
        truncated_log_inputs,
        private_log_inputs,
        log_reasons,
    ) = aggregate_log_counters(log_dir, log_files.values())
    lifecycle_error_count, lifecycle_status_reasons = lifecycle_outcome(lifecycle)
    reasons = missing_log_reasons(log_files, masters, workers)
    reasons.extend(role_reasons)
    reasons.extend(lifecycle_metadata_reasons)
    reasons.extend(log_reasons)
    reasons.extend(lifecycle_status_reasons)
    error_count += lifecycle_error_count

    errors_detected = bool(
        error_count
        or leak_counts["definitely_lost_bytes"]
        or leak_counts["indirectly_lost_bytes"]
    )
    incomplete_reasons = unique_reasons(reasons)
    incomplete = bool(incomplete_reasons)
    return {
        "status": status_for(errors_detected=errors_detected, incomplete=incomplete),
        "complete": not incomplete,
        "errors_detected": errors_detected,
        "logs_seen": len(log_files),
        "logs_with_final_summary": final_summary_count,
        "error_count": error_count,
        "definitely_lost_bytes": leak_counts["definitely_lost_bytes"],
        "indirectly_lost_bytes": leak_counts["indirectly_lost_bytes"],
        "possibly_lost_bytes": leak_counts["possibly_lost_bytes"],
        "still_reachable_bytes": leak_counts["still_reachable_bytes"],
        "truncated_log_inputs": truncated_log_inputs,
        "private_log_inputs": private_log_inputs,
        "incomplete_reasons": incomplete_reasons,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verified-run-root", required=True, type=Path)
    parser.add_argument("--log-dir", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        log_dir = validate_evidence_root(args.verified_run_root, args.log_dir)
        roles_file, lifecycle_file, output, text_output = evidence_artifact_paths(log_dir)
        require_distinct_paths(
            (
                ("roles file", roles_file),
                ("lifecycle file", lifecycle_file),
                (JSON_OUTPUT_LABEL, output),
                (TEXT_OUTPUT_LABEL, text_output),
            )
        )
        validate_output_target(log_dir, output, JSON_OUTPUT_LABEL)
        validate_output_target(log_dir, text_output, TEXT_OUTPUT_LABEL)
        summary = summarize(log_dir, roles_file, lifecycle_file)
        atomic_write(log_dir, output, JSON_OUTPUT_LABEL, write_json, summary)
        atomic_write(log_dir, text_output, TEXT_OUTPUT_LABEL, write_text, summary)
    except (OSError, ValueError) as exc:
        print(f"nginx memcheck summary rejected input: {exc}", file=sys.stderr)
        return 2

    return 0 if summary["status"] == "clean" else 99


if __name__ == "__main__":
    raise SystemExit(main())
