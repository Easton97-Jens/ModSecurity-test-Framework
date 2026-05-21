#!/usr/bin/env python3
"""Check repository-owned Markdown relative links."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from urllib.parse import unquote

REPO_ROOT = Path(os.environ.get("CONNECTOR_ROOT", Path(__file__).resolve().parents[1])).resolve()
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
    roots = [
        REPO_ROOT / "README.md",
        REPO_ROOT / "docs",
        REPO_ROOT / "connectors",
        REPO_ROOT / "common",
        REPO_ROOT / "licenses",
    ]
    files: list[Path] = []
    for root in roots:
        if root.is_file() and root.suffix == ".md":
            files.append(root)
        elif root.is_dir():
            files.extend(path for path in root.rglob("*.md") if not is_skipped(path))
    return sorted(files)


def normalize_target(raw_target: str) -> str:
    target = raw_target.strip()
    if not target or target.startswith("#") or target.startswith(REMOTE_PREFIXES):
        return ""
    if target.startswith("<") and target.endswith(">"):
        target = target[1:-1].strip()
    target = target.split("#", 1)[0]
    target = target.split("?", 1)[0]
    return unquote(target)


def check_file(path: Path) -> list[str]:
    errors: list[str] = []
    text = path.read_text(encoding="utf-8")
    for match in LINK_RE.finditer(text):
        target = normalize_target(match.group(1))
        if not target:
            continue
        candidate = (path.parent / target).resolve()
        try:
            candidate.relative_to(REPO_ROOT)
        except ValueError:
            errors.append(f"{path.relative_to(REPO_ROOT)}: link escapes repo: {target}")
            continue
        if not candidate.exists():
            errors.append(f"{path.relative_to(REPO_ROOT)}: missing link target: {target}")
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
