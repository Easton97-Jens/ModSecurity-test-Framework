"""Read canonical CI pin assignments without executing shell code.

This deliberately understands only the small, double-quoted assignment
language used for CI pins in ``ci/lib/common.sh``.  In particular it never
sources the file and never consults the process environment.
"""

from __future__ import annotations

from pathlib import Path
import re
import stat


_ASSIGNMENT = re.compile(r'^(CI_(?:ACTION|SECURITY_TOOL|OSV)_[A-Z0-9_]+)="([^"`$]*)"\s*$')
_DERIVED = re.compile(r'^(CI_(?:ACTION|SECURITY_TOOL|OSV)_[A-Z0-9_]+)="([^"`]*?)"\s*$')
_REFERENCE = re.compile(r"\$\{([A-Z][A-Z0-9_]*)(?:#([^{}]*))?\}")
_PIN_PREFIXES = ("CI_ACTION_", "CI_SECURITY_TOOL_", "CI_OSV_")


def _resolve_value(raw: str, values: dict[str, str], line_number: int) -> str:
    value = raw
    for _ in range(4):
        changed = False

        def replace(reference: re.Match[str]) -> str:
            nonlocal changed
            dependency, prefix = reference.groups()
            if dependency not in values:
                raise ValueError(
                    f"common.sh:{line_number}: unresolved canonical pin {dependency}"
                )
            resolved = values[dependency]
            if prefix and not resolved.startswith(prefix):
                raise ValueError(
                    f"common.sh:{line_number}: invalid canonical prefix removal"
                )
            changed = True
            return resolved[len(prefix) :] if prefix else resolved

        value = _REFERENCE.sub(replace, value)
        if not changed:
            break
    if "$" in value:
        raise ValueError(f"common.sh:{line_number}: unsafe canonical pin expression")
    return value


def _read_common(root: Path) -> list[str]:
    path = root / "ci" / "lib" / "common.sh"
    try:
        mode = path.lstat().st_mode
    except OSError as exc:
        raise ValueError(f"{path}: canonical common.sh is missing") from exc
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        raise ValueError(f"{path}: canonical common.sh must be a regular file")
    try:
        return path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"{path}: canonical common.sh cannot be decoded") from exc


def load_canonical_ci_pins(root: Path) -> dict[str, str]:
    """Return reviewed CI pin assignments from ``common.sh``.

    Resolution is intentionally limited to references to earlier assignments
    in the same file, including the reviewed ``${VAR#prefix}`` form.
    """

    values: dict[str, str] = {}
    locations: dict[str, int] = {}
    for line_number, line in enumerate(_read_common(root), start=1):
        match = _DERIVED.fullmatch(line)
        if match is None or not match.group(1).startswith(_PIN_PREFIXES):
            continue
        name, raw = match.groups()
        if name in locations:
            raise ValueError(f"common.sh:{line_number}: duplicate canonical pin {name}")
        values[name] = _resolve_value(raw, values, line_number)
        locations[name] = line_number
    if not values:
        raise ValueError("common.sh: no canonical CI pins found")
    return values


def canonical_action(values: dict[str, str], suffix: str) -> str:
    name = f"CI_ACTION_{suffix}_REPOSITORY"
    value = values.get(name)
    if not value:
        raise ValueError(f"common.sh: missing canonical pin {name}")
    return value
