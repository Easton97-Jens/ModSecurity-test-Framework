#!/usr/bin/env python3
"""Synchronise workflow/tool provenance from ``ci/lib/common.sh``.

This command is deliberately offline.  ``common.sh`` is the only source of
the mutable CI pin values; the lock and workflow files are generated views.
``--check`` never writes and ``--write`` uses byte-idempotent atomic writes.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from typing import Any

import yaml


ACTION_SUFFIXES = (
    "CHECKOUT", "SETUP_PYTHON", "SETUP_NODE", "UPLOAD_ARTIFACT",
    "GITHUB_SCRIPT", "CREATE_GITHUB_APP_TOKEN", "CREATE_PULL_REQUEST",
    "CODEQL", "DEPENDENCY_REVIEW",
)
TOOL_SUFFIXES = (
    "SCORECARD", "OSV_SCANNER", "ACTIONLINT", "SHELLCHECK",
    "ZIZMOR", "GITLEAKS", "RUFF", "PYRIGHT",
)
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
LITERAL_VALUE = re.compile(r"^[A-Za-z0-9._/+:-]+$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SAFE_EXPANSION = re.compile(
    r"\$\{(?P<braced>CI_[A-Z0-9_]+)(?:#(?P<prefix>[A-Za-z0-9._+-]+))?\}|\$(?P<bare>CI_[A-Z0-9_]+)"
)
REMOTE_USE = re.compile(r"(?P<prefix>\buses:\s*)(?P<quote>[\"']?)(?P<ref>[^\s\"']+)(?P=quote)")
NODE_VERSION_LINE = re.compile(
    r"^(?P<prefix>\s*node-version:\s*)(?P<quote>[\"']?)(?P<value>[^\s#\"']+)(?P=quote)(?P<suffix>\s*(?:#.*)?)$"
)
OSV_LEGACY_FIELD_LINES = {
    "OSV_LEGACY_BASE_SHA": re.compile(
        r"^(?P<prefix>\s*OSV_LEGACY_BASE_SHA:\s*)(?P<value>[^\s#]+)(?P<suffix>\s*(?:#.*)?)$"
    ),
    "OSV_LEGACY_BASE_VERSION": re.compile(
        r"^(?P<prefix>\s*OSV_LEGACY_BASE_VERSION:\s*)(?P<value>[^\s#]+)(?P<suffix>\s*(?:#.*)?)$"
    ),
}
GENERATED_LOCK = "# GENERATED FILE: values are sourced from ci/lib/common.sh; do not edit pin fields manually.\n"
GENERATED_DOC = "<!-- GENERATED PIN TABLE: values are sourced from ci/lib/common.sh. -->"


class PinError(RuntimeError):
    pass


def root_path(value: str | None) -> Path:
    return Path(value).resolve() if value else Path(__file__).resolve().parents[2]


def _check_managed_component(current: Path, path: Path, require_file: bool) -> bool:
    try:
        current.lstat()
    except FileNotFoundError:
        if current != path:
            raise PinError(f"managed path has a missing parent: {current}")
        if require_file:
            raise PinError(f"managed file is missing: {path}")
        return False
    except OSError as exc:
        raise PinError(f"cannot inspect managed path {current}: {exc}") from exc
    if current.is_symlink():
        raise PinError(f"managed path may not be a symlink: {current}")
    if current != path and not current.is_dir():
        raise PinError(f"managed path parent is not a directory: {current}")
    return True


def validate_managed_path(root: Path, path: Path, *, require_file: bool = True) -> None:
    """Reject symlinked or escaped source/output paths before any I/O.

    The synchronizer writes generated views with ``os.replace``.  That is
    atomic for a regular destination, but it must not be allowed to replace a
    symlink or to traverse a symlinked parent supplied by a checkout.
    """

    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise PinError(f"managed path escapes repository root: {path}") from exc
    current = root
    for component in relative.parts:
        current /= component
        if not _check_managed_component(current, path, require_file):
            return
    if require_file and (not path.is_file() or not stat.S_ISREG(path.stat().st_mode)):
        raise PinError(f"managed file is not a regular file: {path}")


def canonical_names() -> list[str]:
    names = [
        "CI_CANONICAL_PYTHON_VERSION",
        "CI_CANONICAL_PYYAML_VERSION",
        "CI_CANONICAL_PYYAML_SHA256",
        "CI_CANONICAL_NODE_VERSION",
        "CI_OSV_LEGACY_BASE_SHA",
        "CI_OSV_LEGACY_BASE_VERSION",
    ]
    names += [
        f"CI_ACTION_{suffix}_{field}"
        for suffix in ACTION_SUFFIXES
        for field in ("REPOSITORY", "VERSION", "COMMIT")
    ]
    names += [
        f"CI_SECURITY_TOOL_{suffix}_{field}"
        for suffix in TOOL_SUFFIXES
        for field in ("REPOSITORY", "VERSION", "COMMIT", "ASSET_NAME", "SHA256")
    ]
    return names


def strip_shell_comment(line: str) -> str:
    """Remove a shell comment only when its ``#`` is outside quotes."""

    quote: str | None = None
    for index, character in enumerate(line):
        if character in {"'", '"'} and quote in (None, character):
            quote = None if quote == character else character
        elif character == "#" and quote is None:
            return line[:index]
    return line


def resolve_asset_expression(name: str, raw_value: str, values: dict[str, str]) -> str:
    """Resolve only a same-tool version expansion in a canonical asset name."""

    if "$" not in raw_value:
        return raw_value
    if not name.endswith("_ASSET_NAME"):
        raise PinError(f"{name} contains an unsupported shell expression")
    allowed_name = name.removesuffix("_ASSET_NAME") + "_VERSION"
    resolved: list[str] = []
    position = 0
    while position < len(raw_value):
        match = SAFE_EXPANSION.search(raw_value, position)
        if match is None:
            resolved.append(_asset_literal(name, raw_value[position:]))
            break
        resolved.append(_asset_literal(name, raw_value[position : match.start()]))
        resolved.append(_resolve_asset_match(name, allowed_name, match, values))
        position = match.end()
    result = "".join(resolved)
    if not result or not LITERAL_VALUE.fullmatch(result):
        raise PinError(f"{name} resolved to an unsafe asset name")
    return result


def _asset_literal(name: str, literal: str) -> str:
    if literal and not LITERAL_VALUE.fullmatch(literal):
        raise PinError(f"{name} contains an unsafe asset literal")
    return literal


def _resolve_asset_match(
    name: str, allowed_name: str, match: re.Match[str], values: dict[str, str]
) -> str:
    variable = match.group("braced") or match.group("bare")
    if variable != allowed_name or variable not in values:
        raise PinError(f"{name} expands an unapproved or forward variable")
    value = values[variable]
    prefix = match.group("prefix")
    if prefix is not None:
        if not value.startswith(prefix):
            raise PinError(f"{name} cannot remove nonmatching version prefix")
        value = value[len(prefix) :]
    if not value or not LITERAL_VALUE.fullmatch(value):
        raise PinError(f"{name} resolved to an unsafe asset fragment")
    return value


def source_common(root: Path) -> dict[str, str]:
    """Read only exact literal pin assignments; never execute ``common.sh``."""

    common = root / "ci/lib/common.sh"
    validate_managed_path(root, common)
    try:
        resolved_root = root.resolve(strict=True)
        resolved_common = common.resolve(strict=True)
    except OSError as exc:
        raise PinError(f"cannot resolve common source: {exc}") from exc
    if resolved_common.parent.parent.parent != resolved_root:
        raise PinError(f"common source is not a regular file: {common}")
    names = canonical_names()
    name_set = set(names)
    assignment = re.compile(r"^(?P<name>" + "|".join(re.escape(name) for name in names) + r")=(?P<quote>[\"'])(?P<value>[^\"']+)(?P=quote)$")
    values: dict[str, str] = {}
    try:
        content = common.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise PinError(f"common source is not UTF-8: {common}") from exc
    for line_number, line in enumerate(content.splitlines(), 1):
        assignment_value = _parse_canonical_assignment(
            line, line_number, common, name_set, assignment
        )
        if assignment_value is None:
            continue
        name, raw_value = assignment_value
        value = resolve_asset_expression(name, raw_value, values)
        _store_canonical_value(values, name, value, common, line_number)
    missing = [name for name in names if not values.get(name)]
    if missing:
        raise PinError("common.sh is missing canonical CI pins: " + ", ".join(missing))
    _validate_canonical_values(values)
    return values


def _parse_canonical_assignment(
    line: str,
    line_number: int,
    common: Path,
    names: set[str],
    assignment: re.Pattern[str],
) -> tuple[str, str] | None:
    candidate = strip_shell_comment(line).rstrip()
    if not candidate or "=" not in candidate:
        return None
    name = candidate.split("=", 1)[0]
    if name not in names:
        return None
    match = assignment.fullmatch(candidate)
    if match is None:
        raise PinError(
            f"{common}:{line_number}: canonical pin is not an exact quoted literal"
        )
    return name, match.group("value")


def _store_canonical_value(
    values: dict[str, str], name: str, value: str, common: Path, line_number: int
) -> None:
    if not LITERAL_VALUE.fullmatch(value):
        raise PinError(
            f"{common}:{line_number}: canonical pin contains unsafe literal characters"
        )
    if name in values:
        raise PinError(f"{common}:{line_number}: duplicate canonical pin assignment: {name}")
    values[name] = value


def _validate_canonical_values(values: dict[str, str]) -> None:
    for name, value in values.items():
        if name.endswith("_COMMIT") and not SHA40.fullmatch(value):
            raise PinError(f"{name} is not a lowercase full commit SHA")
        if name.endswith("_SHA") and not SHA40.fullmatch(value):
            raise PinError(f"{name} is not a lowercase full SHA")
        if name.endswith("_SHA256") and not SHA256.fullmatch(value):
            raise PinError(f"{name} is not a lowercase SHA-256")
        if name.endswith("_REPOSITORY") and not REPOSITORY.fullmatch(value):
            raise PinError(f"{name} is not an owner/repository identifier")


def atomic_write(path: Path, data: bytes) -> bool:
    if path.read_bytes() == data:
        return False
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return True


def action_suffix_for_reference(action: str, values: dict[str, str]) -> str | None:
    """Return the canonical descriptor for an Action or documented subaction."""

    matches = [
        suffix
        for suffix in ACTION_SUFFIXES
        if action == values.get(f"CI_ACTION_{suffix}_REPOSITORY")
        or action.startswith(values.get(f"CI_ACTION_{suffix}_REPOSITORY", "") + "/")
    ]
    if len(matches) > 1:
        raise PinError(f"ambiguous canonical Action repository: {action}")
    return matches[0] if matches else None


def replace_record_field(text: str, section: str, record: str, field: str, value: str) -> str:
    section_start = text.index(section + ":")
    marker = re.search(rf"(?m)^  {re.escape(record)}:\s*$", text[section_start:])
    if marker is None:
        raise PinError(f"lock record not found: {section}.{record}")
    start = section_start + marker.start()
    next_record = re.search(r"\n(?=\s{2}\S)", text[start + 3 :])
    end = start + 3 + next_record.start() if next_record else len(text)
    block = text[start:end]
    pattern = re.compile(rf"(?m)^(    {re.escape(field)}:)\s*.*$")
    if not pattern.search(block):
        raise PinError(f"lock field not found: {section}.{record}.{field}")
    return text[:start] + pattern.sub(rf"\1 {value}", block, count=1) + text[end:]


def lock_values(root: Path, values: dict[str, str]) -> bytes:
    path = root / "ci/tooling/security-tools.lock.yml"
    validate_managed_path(root, path)
    text = path.read_text(encoding="utf-8")
    if not text.startswith(GENERATED_LOCK):
        text = GENERATED_LOCK + text
    parsed: dict[str, Any] = yaml.safe_load(text) or {}
    actions = parsed.get("actions", {})
    tools = parsed.get("tools", {})
    action_records = {values[f"CI_ACTION_{suffix}_REPOSITORY"]: suffix for suffix in ACTION_SUFFIXES}
    tool_records = {values[f"CI_SECURITY_TOOL_{suffix}_REPOSITORY"].rsplit("/", 1)[-1]: suffix for suffix in TOOL_SUFFIXES}
    if set(actions) != set(action_records) or set(tools) != set(tool_records):
        raise PinError("security-tools.lock.yml records do not match canonical repositories")
    for action, suffix in action_records.items():
        version = values[f"CI_ACTION_{suffix}_VERSION"]
        commit = values[f"CI_ACTION_{suffix}_COMMIT"]
        text = replace_record_field(text, "actions", action, "name", action)
        text = replace_record_field(text, "actions", action, "version", version)
        text = replace_record_field(text, "actions", action, "immutable_commit", commit)
        text = replace_record_field(text, "actions", action, "upstream_release", f"https://github.com/{action}/releases/tag/{version}")
    for tool, suffix in tool_records.items():
        repository = values[f"CI_SECURITY_TOOL_{suffix}_REPOSITORY"]
        version = values[f"CI_SECURITY_TOOL_{suffix}_VERSION"]
        commit = values[f"CI_SECURITY_TOOL_{suffix}_COMMIT"]
        asset = values[f"CI_SECURITY_TOOL_{suffix}_ASSET_NAME"]
        digest = values[f"CI_SECURITY_TOOL_{suffix}_SHA256"]
        release = f"https://github.com/{repository}/releases/tag/{version}"
        asset_url = f"https://github.com/{repository}/releases/download/{version}/{asset}"
        for field, value in (("name", tool), ("version", version), ("immutable_commit", commit), ("upstream_release", release), ("asset", asset), ("asset_url", asset_url), ("sha256", digest)):
            text = replace_record_field(text, "tools", tool, field, value)
    return text.encode("utf-8")


def _rewrite_osv_line(
    path: Path, line: str, values: dict[str, str], seen: set[str]
) -> str | None:
    if path.name != "ci-security-osv.yml":
        return None
    bare_line = line.rstrip("\n")
    for field, field_pattern in OSV_LEGACY_FIELD_LINES.items():
        match = field_pattern.fullmatch(bare_line)
        if match is None:
            continue
        seen.add(field)
        newline = "\n" if line.endswith("\n") else ""
        return (
            match.group("prefix")
            + values["CI_" + field]
            + match.group("suffix")
            + newline
        )
    return None


def _rewrite_node_line(line: str, values: dict[str, str]) -> tuple[str | None, str | None]:
    if "node-version:" not in line.rstrip("\n"):
        return None, None
    match = NODE_VERSION_LINE.fullmatch(line.rstrip("\n"))
    if match is None:
        return line, "node-version must be a literal canonical value"
    quote = match.group("quote")
    newline = "\n" if line.endswith("\n") else ""
    return (
        match.group("prefix")
        + quote
        + values["CI_CANONICAL_NODE_VERSION"]
        + quote
        + match.group("suffix")
        + newline,
        None,
    )


def _rewrite_remote_action_line(
    line: str, values: dict[str, str]
) -> tuple[str, str | None]:
    match = REMOTE_USE.search(line)
    if match is None:
        return line, None
    ref = match.group("ref")
    action, at, _ = ref.rpartition("@")
    action_suffix = action_suffix_for_reference(action, values)
    if not at or action_suffix is None:
        if action.startswith(("./", "docker://", "Docker://")):
            return line, None
        return line, f"unknown or unsupported remote Action {ref}"
    expected_commit = values[f"CI_ACTION_{action_suffix}_COMMIT"]
    expected_version = values[f"CI_ACTION_{action_suffix}_VERSION"]
    prefix = line[: match.start("ref")]
    suffix_text = line[match.end("ref") :]
    suffix_text = re.sub(
        r"#\s*v?\d+(?:\.\d+){1,3}\s*$",
        "# " + expected_version,
        suffix_text.rstrip("\n"),
    )
    if "#" not in suffix_text:
        suffix_text = suffix_text.rstrip() + " # " + expected_version
    newline = "\n" if line.endswith("\n") else ""
    return prefix + action + "@" + expected_commit + suffix_text + newline, None


def _rewrite_workflow_line(
    path: Path,
    line: str,
    values: dict[str, str],
    osv_fields_seen: set[str],
) -> tuple[str, str | None]:
    osv_line = _rewrite_osv_line(path, line, values, osv_fields_seen)
    if osv_line is not None:
        return osv_line, None
    node_line, node_error = _rewrite_node_line(line, values)
    if node_line is not None:
        return node_line, node_error
    action_line, action_error = _rewrite_remote_action_line(line, values)
    if action_error is None:
        return action_line, None
    return action_line, action_error


def _validate_workflow_actions(
    root: Path, path: Path, text: str, values: dict[str, str]
) -> list[str]:
    errors: list[str] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        match = REMOTE_USE.search(line)
        if match is None:
            continue
        ref = match.group("ref")
        action, _, current = ref.rpartition("@")
        action_suffix = action_suffix_for_reference(action, values)
        if action_suffix and (
            not SHA40.fullmatch(current)
            or f"# {values[f'CI_ACTION_{action_suffix}_VERSION']}" not in line
        ):
            errors.append(f"{path.relative_to(root)}:{line_number}: Action pin/comment drift")
    return errors


def workflow_values(root: Path, values: dict[str, str]) -> tuple[list[str], list[tuple[Path, bytes]]]:
    errors: list[str] = []
    outputs: list[tuple[Path, bytes]] = []
    for path in sorted((root / ".github/workflows").glob("*.y*ml")):
        validate_managed_path(root, path)
        text = path.read_text(encoding="utf-8")
        changed_lines: list[str] = []
        osv_fields_seen: set[str] = set()
        for line_number, line in enumerate(text.splitlines(keepends=True), 1):
            changed_line, error = _rewrite_workflow_line(
                path, line, values, osv_fields_seen
            )
            changed_lines.append(changed_line)
            if error:
                errors.append(f"{path.relative_to(root)}:{line_number}: {error}")
        changed = "".join(changed_lines)
        if changed != text:
            outputs.append((path, changed.encode("utf-8")))
        errors.extend(_validate_workflow_actions(root, path, changed, values))
        if path.name == "ci-security-osv.yml":
            missing = set(OSV_LEGACY_FIELD_LINES) - osv_fields_seen
            errors.extend(
                f"{path.relative_to(root)}: missing generated {field} field"
                for field in sorted(missing)
            )
    return errors, outputs


def _documentation_line(line: str, values: dict[str, str]) -> str:
    for suffix in ACTION_SUFFIXES:
        action = values[f"CI_ACTION_{suffix}_REPOSITORY"]
        if not line.startswith(f"| `{action}`"):
            continue
        columns = line.rstrip("\n").split("|")
        if len(columns) < 6:
            continue
        columns[3] = " " + values[f"CI_ACTION_{suffix}_VERSION"] + " "
        columns[4] = " " + values[f"CI_ACTION_{suffix}_COMMIT"] + " "
        return "|".join(columns) + ("\n" if line.endswith("\n") else "")
    return line


def documentation_values(root: Path, values: dict[str, str]) -> list[tuple[Path, bytes]]:
    outputs: list[tuple[Path, bytes]] = []
    relatives = ("docs/github-actions-workflow-security.md", "docs/github-actions-workflow-security.de.md")
    for relative in relatives:
        path = root / relative
        validate_managed_path(root, path)
        text = path.read_text(encoding="utf-8")
        if GENERATED_DOC not in text:
            text = text.replace("\n\n", "\n\n" + GENERATED_DOC + "\n", 1)
        lines = [_documentation_line(line, values) for line in text.splitlines(keepends=True)]
        outputs.append((path, "".join(lines).encode("utf-8")))
    return outputs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    parser.add_argument("--root")
    args = parser.parse_args(argv)
    root = root_path(args.root)
    try:
        values = source_common(root)
        expected: list[tuple[Path, bytes]] = [(root / "ci/tooling/security-tools.lock.yml", lock_values(root, values))]
        errors, workflows = workflow_values(root, values)
        expected.extend(workflows)
        expected.extend(documentation_values(root, values))
        # Validate every destination before comparing or writing any output.
        # This also rejects symlinked generated views and symlinked parents.
        for path, _ in expected:
            validate_managed_path(root, path)
        mismatches: list[str] = errors[:]
        for path, data in expected:
            if path.read_bytes() != data:
                mismatches.append(f"{path.relative_to(root)}: generated output drift")
        if mismatches:
            if args.write:
                # Mutable/unknown references are never silently rewritten.
                if errors:
                    raise PinError("; ".join(errors))
                for path, data in expected:
                    atomic_write(path, data)
                print(f"canonical workflow pins: updated {len(expected)} files")
                return 0
            print("canonical workflow pins: FAIL", file=sys.stderr)
            print("\n".join(mismatches), file=sys.stderr)
            return 1
        print("canonical workflow pins: PASS")
        return 0
    except (OSError, PinError, yaml.YAMLError) as exc:
        print(f"canonical workflow pins: ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
