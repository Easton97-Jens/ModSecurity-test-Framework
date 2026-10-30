#!/usr/bin/env python3
"""Ensure generated test-matrix Markdown keeps bilingual switches."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import os
from pathlib import Path
import secrets
import stat


GENERATED_TEST_MATRIX_REPORTS = (
    Path("reports/testing/generated/coverage/case-matrix.generated.md"),
    Path("reports/testing/generated/coverage/connector-gap-summary.generated.md"),
    Path("reports/testing/generated/coverage/coverage-summary.generated.md"),
    Path("reports/testing/generated/coverage/phase-coverage.generated.md"),
    Path("reports/testing/generated/coverage/xfail-summary.generated.md"),
    Path("reports/testing/generated/runtime/apache-runtime-results.generated.md"),
    Path("reports/testing/generated/runtime/haproxy-runtime-results.generated.md"),
    Path("reports/testing/generated/runtime/nginx-runtime-results.generated.md"),
    Path("reports/testing/generated/runtime/runtime-matrix.generated.md"),
    Path("reports/testing/test-coverage-overview.md"),
)
REPOSITORY_ROOT = connector_root()
_SAFE_DIRECTORY_OPEN_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
_SAFE_REPORT_OPEN_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK


def trusted_report_path(relative: Path) -> Path | None:
    """Return a regular report below this checkout, rejecting symlink escapes."""
    candidate = REPOSITORY_ROOT / relative
    if candidate.is_symlink() or not candidate.is_file():
        return None
    try:
        candidate.resolve(strict=True).relative_to(REPOSITORY_ROOT.resolve(strict=True))
    except (OSError, ValueError):
        return None
    return candidate


def _selected_report_parent(relative: Path) -> tuple[int, str]:
    """Open the selected report's parent without traversing a symlink."""
    if relative.is_absolute() or not relative.parts or any(part in {".", ".."} for part in relative.parts):
        raise ValueError(f"refusing non-relative selected report path: {relative}")
    directory_fd = os.open(REPOSITORY_ROOT, _SAFE_DIRECTORY_OPEN_FLAGS)
    try:
        for part in relative.parts[:-1]:
            child_fd = os.open(part, _SAFE_DIRECTORY_OPEN_FLAGS, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = child_fd
        return directory_fd, relative.parts[-1]
    except OSError:
        os.close(directory_fd)
        raise


def _read_selected_report(relative: Path) -> tuple[str, int] | None:
    """Read a regular selected report through verified directory descriptors."""
    if trusted_report_path(relative) is None:
        return None
    directory_fd, filename = _selected_report_parent(relative)
    try:
        report_fd = os.open(filename, _SAFE_REPORT_OPEN_FLAGS, dir_fd=directory_fd)
        report_stat = os.fstat(report_fd)
        if not stat.S_ISREG(report_stat.st_mode):
            os.close(report_fd)
            return None
        with os.fdopen(report_fd, "r", encoding="utf-8", errors="replace") as report:
            return report.read(), stat.S_IMODE(report_stat.st_mode)
    finally:
        os.close(directory_fd)


def _replace_selected_report(relative: Path, text: str, mode: int) -> None:
    """Atomically replace a selected report without following path symlinks."""
    directory_fd, filename = _selected_report_parent(relative)
    temporary_name = f".{filename}.language-switch-{secrets.token_hex(16)}.tmp"
    try:
        temporary_fd = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            mode,
            dir_fd=directory_fd,
        )
        published = False
        try:
            with os.fdopen(temporary_fd, "w", encoding="utf-8") as temporary:
                os.fchmod(temporary.fileno(), mode)
                temporary.write(text)
            os.replace(
                temporary_name,
                filename,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            published = True
        finally:
            if not published:
                try:
                    os.unlink(temporary_name, dir_fd=directory_fd)
                except FileNotFoundError:
                    pass
    finally:
        os.close(directory_fd)


def german_counterpart(path: Path) -> Path:
    return path.with_name(path.name.removesuffix(".md") + ".de.md")


def english_counterpart(path: Path) -> Path:
    return path.with_name(path.name.removesuffix(".de.md") + ".md")


def switched_report_text(text: str, switch: str, prefix: str) -> str:
    """Return report text with exactly one current language switch."""
    lines = [line for line in text.splitlines() if not line.startswith(prefix)]
    try:
        heading_index = next(index for index, line in enumerate(lines) if line.startswith("# "))
    except StopIteration:
        heading_index = -1

    if heading_index >= 0:
        before = lines[: heading_index + 1]
        after = lines[heading_index + 1 :]
        while after and not after[0].strip():
            after.pop(0)
        updated_lines = before + ["", switch, ""] + after
    else:
        updated_lines = [switch, ""] + lines

    return "\n".join(updated_lines).rstrip() + "\n"


def rewrite_selected_reports() -> int:
    """Rewrite only report paths declared by this checked-in generator."""
    changed = 0
    for english_relative in GENERATED_TEST_MATRIX_REPORTS:
        german_relative = german_counterpart(english_relative)
        english_switch = f"**Language:** English | [Deutsch]({german_relative.name})"
        english_snapshot = _read_selected_report(english_relative)
        if english_snapshot is not None:
            english_text, english_mode = english_snapshot
            english_updated = switched_report_text(english_text, english_switch, "**Language:**")
            if english_updated != english_text:
                _replace_selected_report(english_relative, english_updated, english_mode)
                changed += 1
        german_snapshot = _read_selected_report(german_relative)
        if german_snapshot is not None:
            source_path = english_counterpart(german_relative)
            german_switch = f"**Sprache:** [English]({source_path.name}) | Deutsch"
            german_text, german_mode = german_snapshot
            german_updated = switched_report_text(german_text, german_switch, "**Sprache:**")
            if german_updated != german_text:
                _replace_selected_report(german_relative, german_updated, german_mode)
                changed += 1
    return changed


def main() -> int:
    changed = rewrite_selected_reports()
    if changed:
        print(f"ensure-test-matrix-language-switches: updated {changed} file(s)")
    else:
        print("ensure-test-matrix-language-switches: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
