#!/usr/bin/env python3
"""Print bounded, path-safe diagnostics for a failed exact-head NGINX build.

This program runs only after the provisioning step has already failed.  It
must therefore never turn a missing report into a successful provision, and it
must not trust environment values which PR-controlled build code can append to
``GITHUB_ENV``.  The workflow supplies the fixed runner-owned root explicitly;
all report and log locations below it are fixed constants.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any


PREFIX = "nginx exact-head diagnostics:"
LOG_LINE_PREFIX = f"{PREFIX} log: "
REPORT_RELATIVE_PATH = Path(
    "runtime-component-reports/reports/testing/generated/cache/"
    "runtime-component-cache.generated.json"
)
BUILD_LOG_RELATIVE_PATH = Path("build/logs/runtime-components/nginx-build.log")
MAX_REPORT_BYTES = 64 * 1024
MAX_LOG_TAIL_BYTES = 64 * 1024
MAX_LOG_LINES = 120
MAX_LOG_LINE_CHARS = 512
SAFE_METADATA_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$", re.ASCII)


class DiagnosticInputError(ValueError):
    """A fixed, payload-free reason why a diagnostic input was rejected."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _identity(details: os.stat_result) -> tuple[int, int, int, int, int, int, int, int]:
    """Return the file state that must stay stable across a bounded read."""

    return (
        details.st_dev,
        details.st_ino,
        details.st_mode,
        details.st_nlink,
        details.st_size,
        details.st_mtime_ns,
        details.st_ctime_ns,
        details.st_uid,
    )


def _absolute_nonroot_path(value: Path | str) -> Path:
    """Canonicalize syntax only; never resolve an attacker-provided link."""

    candidate = Path(value)
    if not candidate.is_absolute():
        raise DiagnosticInputError("run_root_not_absolute")
    normalized = Path(os.path.abspath(os.fspath(candidate)))
    if normalized == Path(normalized.anchor):
        raise DiagnosticInputError("run_root_is_root")
    return normalized


def _no_follow_flags() -> tuple[int, int]:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or directory is None:
        raise DiagnosticInputError("no_follow_unavailable")
    return no_follow, directory


def _require_directory(details: os.stat_result, reason: str) -> None:
    if stat.S_ISLNK(details.st_mode):
        raise DiagnosticInputError(f"{reason}_symlink")
    if not stat.S_ISDIR(details.st_mode):
        raise DiagnosticInputError(f"{reason}_not_directory")


def _require_regular(details: os.stat_result, reason: str, maximum_bytes: int | None) -> None:
    if stat.S_ISLNK(details.st_mode):
        raise DiagnosticInputError(f"{reason}_symlink")
    if not stat.S_ISREG(details.st_mode):
        raise DiagnosticInputError(f"{reason}_not_regular")
    if details.st_nlink != 1:
        raise DiagnosticInputError(f"{reason}_hardlink")
    if maximum_bytes is not None and details.st_size > maximum_bytes:
        raise DiagnosticInputError(f"{reason}_too_large")


def _open_run_root(run_root: Path) -> tuple[int, Path]:
    """Open the fixed root through no-follow descriptors from filesystem root."""

    root = _absolute_nonroot_path(run_root)
    no_follow, directory = _no_follow_flags()
    try:
        descriptor = os.open(root.anchor, os.O_RDONLY | directory | no_follow | os.O_CLOEXEC)
    except OSError as exc:
        raise DiagnosticInputError("run_root_unavailable") from exc
    try:
        for component in root.relative_to(root.anchor).parts:
            try:
                before = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError as exc:
                raise DiagnosticInputError("run_root_missing") from exc
            except OSError as exc:
                raise DiagnosticInputError("run_root_unavailable") from exc
            _require_directory(before, "run_root")
            try:
                next_fd = os.open(
                    component,
                    os.O_RDONLY | directory | no_follow | os.O_CLOEXEC,
                    dir_fd=descriptor,
                )
            except OSError as exc:
                raise DiagnosticInputError("run_root_unavailable") from exc
            try:
                opened = os.fstat(next_fd)
                _require_directory(opened, "run_root")
                if _identity(before) != _identity(opened):
                    raise DiagnosticInputError("run_root_changed")
            except Exception:
                os.close(next_fd)
                raise
            os.close(descriptor)
            descriptor = next_fd
    except Exception:
        os.close(descriptor)
        raise
    return descriptor, root


def _validate_relative_path(relative_path: Path, reason: str) -> None:
    if relative_path.is_absolute() or not relative_path.parts or ".." in relative_path.parts:
        raise DiagnosticInputError(f"{reason}_path_invalid")


def _stat_no_follow(directory_fd: int, component: str, reason: str) -> os.stat_result:
    try:
        return os.stat(component, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError as exc:
        raise DiagnosticInputError(f"{reason}_missing") from exc
    except OSError as exc:
        raise DiagnosticInputError(f"{reason}_unavailable") from exc


def _open_directory_component(
    directory_fd: int,
    component: str,
    reason: str,
    *,
    no_follow: int,
    directory: int,
) -> int:
    before = _stat_no_follow(directory_fd, component, reason)
    _require_directory(before, reason)
    try:
        next_fd = os.open(
            component,
            os.O_RDONLY | directory | no_follow | os.O_CLOEXEC,
            dir_fd=directory_fd,
        )
    except OSError as exc:
        raise DiagnosticInputError(f"{reason}_unavailable") from exc
    try:
        opened = os.fstat(next_fd)
        _require_directory(opened, reason)
        if _identity(before) != _identity(opened):
            raise DiagnosticInputError(f"{reason}_changed")
    except OSError as exc:
        os.close(next_fd)
        raise DiagnosticInputError(f"{reason}_unavailable") from exc
    except Exception:
        os.close(next_fd)
        raise
    return next_fd


def _open_relative_directory(run_root: Path, components: tuple[str, ...], reason: str) -> tuple[int, int]:
    no_follow, directory = _no_follow_flags()
    directory_fd, _ = _open_run_root(run_root)
    try:
        for component in components:
            next_fd = _open_directory_component(
                directory_fd,
                component,
                reason,
                no_follow=no_follow,
                directory=directory,
            )
            os.close(directory_fd)
            directory_fd = next_fd
    except Exception:
        os.close(directory_fd)
        raise
    return directory_fd, no_follow


def _open_regular_file(
    directory_fd: int,
    filename: str,
    reason: str,
    *,
    maximum_bytes: int | None,
    tail: bool,
    no_follow: int,
) -> tuple[int, os.stat_result]:
    before = _stat_no_follow(directory_fd, filename, reason)
    _require_regular(before, reason, None if tail else maximum_bytes)
    try:
        file_fd = os.open(
            filename,
            os.O_RDONLY | os.O_NONBLOCK | no_follow | os.O_CLOEXEC,
            dir_fd=directory_fd,
        )
    except OSError as exc:
        raise DiagnosticInputError(f"{reason}_unavailable") from exc
    try:
        opened = os.fstat(file_fd)
        _require_regular(opened, reason, None if tail else maximum_bytes)
        if _identity(before) != _identity(opened):
            raise DiagnosticInputError(f"{reason}_changed")
    except OSError as exc:
        os.close(file_fd)
        raise DiagnosticInputError(f"{reason}_unavailable") from exc
    except Exception:
        os.close(file_fd)
        raise
    return file_fd, opened


def _read_open_regular_file(
    file_fd: int,
    opened: os.stat_result,
    reason: str,
    *,
    maximum_bytes: int | None,
    tail: bool,
) -> tuple[bytes, bool]:
    try:
        truncated = maximum_bytes is not None and opened.st_size > maximum_bytes
        if tail and maximum_bytes is not None and truncated:
            os.lseek(file_fd, -maximum_bytes, os.SEEK_END)
        limit = maximum_bytes if tail and maximum_bytes is not None else (maximum_bytes or 0) + 1
        chunks: list[bytes] = []
        remaining = limit
        while remaining > 0:
            chunk = os.read(file_fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(file_fd)
    except OSError as exc:
        raise DiagnosticInputError(f"{reason}_unavailable") from exc
    _require_regular(after, reason, None if tail else maximum_bytes)
    if _identity(opened) != _identity(after):
        raise DiagnosticInputError(f"{reason}_changed")
    if maximum_bytes is not None and not tail and len(data) > maximum_bytes:
        raise DiagnosticInputError(f"{reason}_too_large")
    return data, truncated


def _read_fixed_regular_file(
    run_root: Path,
    relative_path: Path,
    reason: str,
    *,
    maximum_bytes: int | None,
    tail: bool,
) -> tuple[bytes, bool]:
    """Read one fixed descendant through no-follow directory descriptors."""

    _validate_relative_path(relative_path, reason)
    directory_fd, no_follow = _open_relative_directory(run_root, relative_path.parts[:-1], reason)
    file_fd = -1
    try:
        file_fd, opened = _open_regular_file(
            directory_fd,
            relative_path.parts[-1],
            reason,
            maximum_bytes=maximum_bytes,
            tail=tail,
            no_follow=no_follow,
        )
        return _read_open_regular_file(
            file_fd,
            opened,
            reason,
            maximum_bytes=maximum_bytes,
            tail=tail,
        )
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        os.close(directory_fd)


def _safe_metadata_token(value: object) -> str:
    if isinstance(value, str) and SAFE_METADATA_TOKEN.fullmatch(value):
        return value
    return "unavailable"


def _safe_exit_code(value: object) -> str:
    if isinstance(value, int) and not isinstance(value, bool) and -4096 <= value <= 4096:
        return str(value)
    return "unavailable"


def _safe_missing_file_count(value: object) -> str:
    if not isinstance(value, list):
        return "unavailable"
    return str(min(len(value), 9999)) if len(value) <= 9999 else ">=10000"


def _render_log_lines(data: bytes, *, truncated: bool) -> list[str]:
    """Make terminal-safe, line- and byte-bounded output from an untrusted log."""

    return [
        LOG_LINE_PREFIX + line
        for line in _render_safe_log_payload(
            data,
            truncated=truncated,
            output_prefix=LOG_LINE_PREFIX,
        )
    ]


def _render_safe_log_payload(
    data: bytes,
    *,
    truncated: bool,
    output_prefix: str,
) -> list[str]:
    """Return payloads that fit the caller's trusted complete-line prefix."""

    if len(output_prefix) > MAX_LOG_LINE_CHARS:
        raise ValueError("diagnostic output prefix exceeds line bound")

    text = data.decode("utf-8", errors="replace")
    lines = text.splitlines()
    if truncated and lines:
        lines = lines[1:]
    rendered: list[str] = []
    for line in lines[-MAX_LOG_LINES:]:
        safe = "".join(character if 32 <= ord(character) <= 126 else "?" for character in line)
        # A prefix prevents GitHub Actions workflow-command interpretation;
        # remove command delimiters as a second, representation-independent
        # guard for untrusted compiler output.
        safe = safe.replace("::", ": :")
        rendered.append(safe[: MAX_LOG_LINE_CHARS - len(output_prefix)])
    return rendered


def bounded_fixed_log_tail(
    root: Path | str,
    relative_path: Path,
    reason: str,
    *,
    output_prefix: str,
) -> tuple[list[str], bool]:
    """Read and sanitize a fixed descendant for another trusted coordinator.

    The caller must select both the root and relative path from its own
    validated state. ``output_prefix`` must be the trusted exact prefix the
    caller will prepend to each returned payload; it preserves the complete
    line bound. This helper never accepts a report-provided path and applies
    the same descriptor, identity, size, and terminal controls as the
    workflow-facing diagnostic.
    """

    normalized_root = _absolute_nonroot_path(root)
    data, truncated = _read_fixed_regular_file(
        normalized_root,
        relative_path,
        reason,
        maximum_bytes=MAX_LOG_TAIL_BYTES,
        tail=True,
    )
    return (
        _render_safe_log_payload(
            data,
            truncated=truncated,
            output_prefix=output_prefix,
        ),
        truncated,
    )


def _append_bounded_build_log_tail(lines: list[str], root: Path) -> list[str]:
    """Append only the fixed canonical NGINX log tail to diagnostic lines."""

    try:
        log_bytes, truncated = _read_fixed_regular_file(
            root,
            BUILD_LOG_RELATIVE_PATH,
            "build_log",
            maximum_bytes=MAX_LOG_TAIL_BYTES,
            tail=True,
        )
    except DiagnosticInputError as exc:
        lines.append(f"{PREFIX} build_log_unavailable={exc.reason}")
        return lines

    lines.extend(
        [
            f"{PREFIX} build_log={BUILD_LOG_RELATIVE_PATH.as_posix()}",
            f"{PREFIX} build_log_tail_truncated={'true' if truncated else 'false'}",
            f"{PREFIX} begin bounded nginx-build.log tail",
        ]
    )
    lines.extend(_render_log_lines(log_bytes, truncated=truncated))
    lines.append(f"{PREFIX} end bounded nginx-build.log tail")
    return lines


def diagnostic_lines(run_root: Path | str) -> list[str]:
    """Return payload-safe lines while preserving the already-failed primary step."""

    try:
        root = _absolute_nonroot_path(run_root)
        report_bytes, _ = _read_fixed_regular_file(
            root,
            REPORT_RELATIVE_PATH,
            "report",
            maximum_bytes=MAX_REPORT_BYTES,
            tail=False,
        )
        payload: Any = json.loads(report_bytes.decode("utf-8", errors="strict"))
    except (DiagnosticInputError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        reason = exc.reason if isinstance(exc, DiagnosticInputError) else "report_malformed"
        lines = [f"{PREFIX} unavailable={reason}"]
        # The complete generated report normally exceeds the metadata limit.
        # It must not select the log path, but the independently produced,
        # fixed descendant remains useful evidence for the failed build.
        if reason == "report_too_large":
            return _append_bounded_build_log_tail(lines, root)
        return lines

    nginx = payload.get("nginx") if isinstance(payload, dict) else None
    if not isinstance(nginx, dict):
        return [f"{PREFIX} unavailable=nginx_record_invalid"]

    lines = [
        f"{PREFIX} status={_safe_metadata_token(nginx.get('status'))}",
        f"{PREFIX} blocker_reason={_safe_metadata_token(nginx.get('blocker_reason'))}",
        f"{PREFIX} build_exit_code={_safe_exit_code(nginx.get('build_exit_code'))}",
        f"{PREFIX} missing_files_count={_safe_missing_file_count(nginx.get('missing_files'))}",
    ]
    expected_log = root / BUILD_LOG_RELATIVE_PATH
    if nginx.get("build_log") != str(expected_log):
        lines.append(f"{PREFIX} build_log=untrusted_path")
        return lines

    return _append_bounded_build_log_tail(lines, root)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-root", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        lines = diagnostic_lines(args.run_root)
    except Exception:
        # This is a post-failure aid only.  Do not let an unexpected hostile
        # artifact error obscure the original provisioning failure.
        lines = [f"{PREFIX} unavailable=internal_error"]
    for line in lines:
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
