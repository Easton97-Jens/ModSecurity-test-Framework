#!/usr/bin/env python3
"""Check repository-owned Markdown relative links."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote

REPO_ROOT = Path(os.environ.get("CONNECTOR_ROOT", Path(__file__).resolve().parents[3])).resolve()
LINK_RE = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
SKIP_DIR_PARTS = {
    ".git",
    "__pycache__",
}
REMOTE_PREFIXES = (
    "http://",
    "https://",
    "mailto:",
    "app://",
)


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


def normalize_target(raw_target: str) -> tuple[str, str]:
    target = raw_target.strip()
    if not target or target.startswith(REMOTE_PREFIXES):
        return "", ""
    if target.startswith("#"):
        return "", target.removeprefix("#")
    if target.startswith("<") and target.endswith(">"):
        target = target[1:-1].strip()
    target, _, anchor = target.partition("#")
    target = target.split("?", 1)[0]
    return unquote(target), unquote(anchor)


def heading_anchors(path: Path) -> set[str]:
    anchors: set[str] = set()
    duplicates: dict[str, int] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^#{1,6}\s+(.+?)\s*#*\s*$", line)
        if not match:
            continue
        # Preserve underscores: variable headings such as `FRAMEWORK_ROOT`
        # intentionally use GitHub's `framework_root` anchor form.
        text = re.sub(r"[`*~]", "", match.group(1)).lower()
        slug = re.sub(r"[^\w\- ]", "", text, flags=re.UNICODE)
        slug = re.sub(r"[\s\-]+", "-", slug).strip("-")
        index = duplicates.get(slug, 0)
        duplicates[slug] = index + 1
        anchors.add(slug if index == 0 else f"{slug}-{index}")
    return anchors


def check_file(path: Path) -> list[str]:
    errors: list[str] = []
    text = path.read_text(encoding="utf-8")
    for match in LINK_RE.finditer(text):
        target, anchor = normalize_target(match.group(1))
        if not target and not anchor:
            continue
        candidate = (path if not target else path.parent / target).resolve()
        try:
            candidate.relative_to(REPO_ROOT)
        except ValueError:
            errors.append(f"{path.relative_to(REPO_ROOT)}: link escapes repo: {target}")
            continue
        if not candidate.exists():
            errors.append(f"{path.relative_to(REPO_ROOT)}: missing link target: {target}")
            continue
        if anchor and candidate.is_file() and candidate.suffix == ".md":
            if anchor not in heading_anchors(candidate):
                errors.append(f"{path.relative_to(REPO_ROOT)}: missing link anchor: {target}#{anchor}")
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
