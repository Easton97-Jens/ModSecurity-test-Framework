#!/usr/bin/env python3
"""Check repository-owned Markdown relative links."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

REPO_ROOT = Path(os.environ.get("CONNECTOR_ROOT", Path(__file__).resolve().parents[3])).resolve()
LINK_RE = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
EXPLICIT_ANCHOR_RE = re.compile(r"<a\b[^>]*\bid=[\"']([^\"']+)[\"'][^>]*>", re.IGNORECASE)
SKIP_DIR_PARTS = {
    ".git",
    "__pycache__",
}
REMOTE_SCHEMES = {"http", "https", "mailto", "app"}


def is_skipped(path: Path) -> bool:
    relative = path.relative_to(REPO_ROOT).as_posix()
    return any(relative == part or relative.startswith(part + "/") for part in SKIP_DIR_PARTS)


def markdown_files() -> list[Path]:
    try:
        tracked = subprocess.check_output(
            ["git", "-C", str(REPO_ROOT), "ls-files", "--", "*.md"],
            text=True,
        ).splitlines()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RuntimeError(f"cannot list tracked Markdown files under {REPO_ROOT}: {exc}") from exc
    return sorted(
        path
        for relative in tracked
        if (path := REPO_ROOT / relative).is_file() and not is_skipped(path)
    )


def is_remote_target(target: str) -> bool:
    """Return whether a Markdown target is an external scheme we do not fetch."""

    return urlsplit(target).scheme.lower() in REMOTE_SCHEMES


def normalize_target(raw_target: str) -> tuple[str, str]:
    target = raw_target.strip()
    if not target or is_remote_target(target):
        return "", ""
    if target.startswith("#"):
        return "", target.removeprefix("#")
    if target.startswith("<") and target.endswith(">"):
        target = target[1:-1].strip()
    target, _, anchor = target.partition("#")
    target = target.split("?", 1)[0]
    return unquote(target), unquote(anchor)


def atx_heading_text(line: str) -> str | None:
    """Return a Markdown ATX heading's text using a bounded marker scan."""
    marker_length = 0
    while marker_length < 6 and marker_length < len(line) and line[marker_length] == "#":
        marker_length += 1
    if (
        marker_length == 0
        or marker_length == len(line)
        or not line[marker_length].isspace()
        or marker_length + 1 == len(line)
    ):
        return None

    text = line[marker_length + 1 :].rstrip()
    return text.rstrip("#").rstrip()


def heading_anchors(path: Path) -> set[str]:
    anchors: set[str] = set()
    duplicates: dict[str, int] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        anchors.update(unquote(anchor) for anchor in EXPLICIT_ANCHOR_RE.findall(line))
        text = atx_heading_text(line)
        if text is None:
            continue
        # Preserve underscores: variable headings such as `FRAMEWORK_ROOT`
        # intentionally use GitHub's `framework_root` anchor form.
        text = re.sub(r"[`*~]", "", text).lower()
        slug = re.sub(r"[^\w\- ]", "", text, flags=re.UNICODE)
        slug = re.sub(r"[\s\-]+", "-", slug).strip("-")
        index = duplicates.get(slug, 0)
        duplicates[slug] = index + 1
        anchors.add(slug if index == 0 else f"{slug}-{index}")
    return anchors


def link_errors(path: Path, target: str, anchor: str) -> list[str]:
    """Validate one local Markdown link target and optional anchor."""

    display_path = path.relative_to(REPO_ROOT)
    candidate = (path if not target else path.parent / target).resolve()
    try:
        candidate.relative_to(REPO_ROOT)
    except ValueError:
        return [f"{display_path}: link escapes repo: {target}"]
    if not candidate.exists():
        return [f"{display_path}: missing link target: {target}"]
    if anchor and candidate.is_file() and candidate.suffix == ".md":
        if anchor not in heading_anchors(candidate):
            return [f"{display_path}: missing link anchor: {target}#{anchor}"]
    return []


def check_file(path: Path) -> list[str]:
    errors: list[str] = []
    text = path.read_text(encoding="utf-8")
    for match in LINK_RE.finditer(text):
        target, anchor = normalize_target(match.group(1))
        if target or anchor:
            errors.extend(link_errors(path, target, anchor))
    return errors


def main() -> int:
    errors: list[str] = []
    for path in markdown_files():
        errors.extend(check_file(path))
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print("doc links ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
