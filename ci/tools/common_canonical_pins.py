"""Read canonical CI pin assignments without executing shell code.

This deliberately understands only the small, double-quoted assignment
language used for CI pins in ``ci/lib/common.sh``.  In particular it never
sources the file and never consults the process environment.
"""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path


_ASSIGNMENT = re.compile(r'^(CI_(?:ACTION|SECURITY_TOOL|OSV)_[A-Z0-9_]+)="([^"`$]*)"\s*$')
_DERIVED = re.compile(r'^(CI_(?:ACTION|SECURITY_TOOL|OSV)_[A-Z0-9_]+)="([^"`]*?)"\s*$')
_REFERENCE = re.compile(r"\$\{([A-Z][A-Z0-9_]*)(?:#([^{}]*))?\}")
_PIN_PREFIXES = ("CI_ACTION_", "CI_SECURITY_TOOL_", "CI_OSV_")


def _resolve_value(
    raw: str,
    values: dict[str, str],
    line_number: int,
    _depth: int = 0,
) -> str:
    value = raw
    def replace(reference: re.Match[str]) -> str:
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
        return resolved[len(prefix) :] if prefix else resolved

    value = _REFERENCE.sub(replace, value)
    if _depth < 3 and _REFERENCE.search(value):
        return _resolve_value(value, values, line_number, _depth + 1)
    if "$" in value:
        raise ValueError(f"common.sh:{line_number}: unsafe canonical pin expression")
    return value


def _trusted_common_path(root: Path) -> Path:
    """Return ``common.sh`` only when its complete path is non-symlinked.

    ``Path.read_text`` follows symlinked parents.  Checking only the leaf
    would therefore allow a checkout's ``ci`` or ``ci/lib`` directory to
    redirect canonical pin reads outside the Framework root.
    """

    root_path = Path(os.path.abspath(root))
    path = root_path / "ci" / "lib" / "common.sh"
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            mode = current.lstat().st_mode
        except OSError as exc:
            raise ValueError(
                f"{current}: canonical common.sh path is missing"
            ) from exc
        if stat.S_ISLNK(mode):
            raise ValueError(
                f"{current}: canonical common.sh path may not contain symlinks"
            )
        if current != path and not stat.S_ISDIR(mode):
            raise ValueError(
                f"{current}: canonical common.sh path parent is not a directory"
            )

    try:
        resolved_root = root_path.resolve(strict=True)
        resolved_path = path.resolve(strict=True)
        resolved_path.relative_to(resolved_root)
    except (OSError, ValueError) as exc:
        raise ValueError(f"{path}: canonical common.sh path escapes the Framework root") from exc
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError(f"{path}: canonical common.sh must be a regular file")
    return path


def _read_common(root: Path) -> list[str]:
    path = _trusted_common_path(root)
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


_GO_TOOL_ASSIGNMENT = re.compile(r'^CI_GO_TOOL_([A-Z0-9_]+)="([^"`$\\]*)"\s*$')
GO_TOOL_FIELDS = ("MODULE", "PACKAGE", "VERSION", "MODULE_SUM")
_GO_MODULE_PATH = re.compile(r"^[a-z0-9.-]+(?:/[A-Za-z0-9_.-]+)+$")
_GO_RELEASE = re.compile(r"^v\d+\.\d+\.\d+$")
_GO_MODULE_SUM = re.compile(r"^h1:[A-Za-z0-9+/]{43}=$")


def _go_tool_field(remainder: str, line_number: int) -> tuple[str, str]:
    for field in sorted(GO_TOOL_FIELDS, key=len, reverse=True):
        if remainder.endswith("_" + field) and len(remainder) > len(field) + 1:
            return remainder[: -(len(field) + 1)], field
    raise ValueError(f"common.sh:{line_number}: unsupported Go tool pin CI_GO_TOOL_{remainder}")


def _valid_go_tool(record: dict[str, str]) -> bool:
    module, package = record["MODULE"], record["PACKAGE"]
    return bool(
        _GO_MODULE_PATH.fullmatch(module)
        and (package == module or package.startswith(module + "/"))
        and _GO_RELEASE.fullmatch(record["VERSION"])
        and _GO_MODULE_SUM.fullmatch(record["MODULE_SUM"])
    )


def load_canonical_go_tools(root: Path) -> dict[str, dict[str, str]]:
    """Return the reviewed Go tool pins from ``common.sh`` keyed by tool name.

    Each ``CI_GO_TOOL_<NAME>_*`` group must define exactly the module, package,
    exact release version and ``h1:`` module sum; the executable is the last
    package path element. The file is parsed, never sourced.
    """
    groups: dict[str, dict[str, str]] = {}
    for line_number, line in enumerate(_read_common(root), start=1):
        if not line.startswith("CI_GO_TOOL_"):
            continue
        match = _GO_TOOL_ASSIGNMENT.fullmatch(line)
        if match is None:
            raise ValueError(f"common.sh:{line_number}: unsafe Go tool pin expression")
        name, field = _go_tool_field(match.group(1), line_number)
        record = groups.setdefault(name, {})
        if field in record:
            raise ValueError(f"common.sh:{line_number}: duplicate Go tool pin {name}_{field}")
        record[field] = match.group(2)
    tools: dict[str, dict[str, str]] = {}
    for name, record in sorted(groups.items()):
        if set(record) != set(GO_TOOL_FIELDS) or not _valid_go_tool(record):
            raise ValueError(f"common.sh: incomplete or invalid Go tool pin group {name}")
        executable = record["PACKAGE"].rsplit("/", 1)[-1]
        if executable.upper() != name:
            raise ValueError(f"common.sh: Go tool pin group {name} does not name its executable")
        tools[executable] = {"module": record["MODULE"], "package": record["PACKAGE"],
                             "version": record["VERSION"], "module_sum": record["MODULE_SUM"],
                             "executable": executable}
    return tools
