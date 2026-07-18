#!/usr/bin/env python3
"""Validate immutable commit-SHA pins for external workflow actions."""

from __future__ import annotations

import argparse
from pathlib import Path
import re


FULL_COMMIT_SHA = re.compile(r"[0-9a-fA-F]{40}$")
BLOCK_PREFIX = re.compile(r"^\s*(?:-\s*)?")
BLOCK_SCALAR_HEADER = re.compile(r"^.*:\s*[>|][0-9+-]*\s*$")
WORKFLOW_SUFFIXES = {".yaml", ".yml"}
YAML_DOUBLE_QUOTE_ESCAPES = {
    "0": "\0",
    "a": "\a",
    "b": "\b",
    "t": "\t",
    "n": "\n",
    "v": "\v",
    "f": "\f",
    "r": "\r",
    "e": "\x1b",
    " ": " ",
    '"': '"',
    "/": "/",
    "\\": "\\",
    "N": "\u0085",
    "_": "\u00a0",
    "L": "\u2028",
    "P": "\u2029",
}


def workflow_files(workflow_root: Path) -> list[Path]:
    """Return all workflow YAML files, including nested future locations."""

    return sorted(
        path
        for path in workflow_root.rglob("*")
        if path.is_file() and path.suffix.lower() in WORKFLOW_SUFFIXES
    )


def consume_double_quoted_scalar(value: str, start: int) -> tuple[str, int] | None:
    """Decode one YAML double-quoted scalar and return its closing index."""

    if start >= len(value) or value[start] != '"':
        return None

    characters: list[str] = []
    index = start + 1
    while index < len(value):
        character = value[index]
        if character == '"':
            return "".join(characters), index + 1
        if character != "\\":
            characters.append(character)
            index += 1
            continue
        if index + 1 >= len(value):
            return None

        escape = value[index + 1]
        if escape in YAML_DOUBLE_QUOTE_ESCAPES:
            characters.append(YAML_DOUBLE_QUOTE_ESCAPES[escape])
            index += 2
            continue
        hex_length = {"x": 2, "u": 4, "U": 8}.get(escape)
        if hex_length is None:
            return None
        hex_start = index + 2
        hex_end = hex_start + hex_length
        digits = value[hex_start:hex_end]
        if len(digits) != hex_length or not re.fullmatch(r"[0-9a-fA-F]+", digits):
            return None
        characters.append(chr(int(digits, 16)))
        index = hex_end
    return None


def consume_single_quoted_scalar(value: str, start: int) -> tuple[str, int] | None:
    """Decode one YAML single-quoted scalar and return its closing index."""

    if start >= len(value) or value[start] != "'":
        return None

    characters: list[str] = []
    index = start + 1
    while index < len(value):
        character = value[index]
        if character != "'":
            characters.append(character)
            index += 1
            continue
        if index + 1 < len(value) and value[index + 1] == "'":
            characters.append("'")
            index += 2
            continue
        return "".join(characters), index + 1
    return None


def skip_whitespace(value: str, start: int) -> int:
    """Return the first non-whitespace index at or after ``start``."""

    index = start
    while index < len(value) and value[index].isspace():
        index += 1
    return index


def consume_uses_key(value: str, start: int) -> int | None:
    """Return the end index when a YAML scalar decodes exactly to ``uses``."""

    if value.startswith("uses", start):
        return start + len("uses")
    scalar = (
        consume_double_quoted_scalar(value, start)
        if start < len(value) and value[start] == '"'
        else consume_single_quoted_scalar(value, start)
        if start < len(value) and value[start] == "'"
        else None
    )
    if scalar is not None and scalar[0] == "uses":
        return scalar[1]
    return None


def strip_inline_comment(value: str) -> str:
    """Remove a YAML-style inline comment while preserving quoted values."""

    quote: str | None = None
    escaped = False
    for index, character in enumerate(value):
        if quote == '"':
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
        elif quote == "'":
            if character == quote:
                quote = None
        elif character in {"'", '"'}:
            quote = character
        elif character == "#" and (index == 0 or value[index - 1].isspace()):
            return value[:index].rstrip()
    return value.strip()


def unquote_scalar(value: str) -> str:
    """Decode one complete quoted YAML scalar, or preserve an unquoted value."""

    scalar = (
        consume_double_quoted_scalar(value, 0)
        if value.startswith('"')
        else consume_single_quoted_scalar(value, 0)
        if value.startswith("'")
        else None
    )
    if scalar is not None and scalar[1] == len(value):
        return scalar[0]
    return value


def block_uses_value(line: str) -> str | None:
    """Return a block-mapping ``uses`` value, including an empty value."""

    index = BLOCK_PREFIX.match(line).end()
    key_end = consume_uses_key(line, index)
    if key_end is None:
        return None
    index = skip_whitespace(line, key_end)
    if index >= len(line) or line[index] != ":":
        return None
    return line[index + 1:].strip()


def is_explicit_yaml_mapping_key(line: str) -> bool:
    """Detect an unsupported YAML explicit mapping key before it spans lines."""

    index = BLOCK_PREFIX.match(line).end()
    return index < len(line) and line[index] == "?"


def leading_indentation(line: str) -> int:
    """Return the space indentation used to determine YAML block-scalar scope."""

    return len(line) - len(line.lstrip(" "))


def is_block_scalar_header(line: str) -> bool:
    """Return whether ``line`` begins a literal or folded YAML block scalar."""

    return bool(BLOCK_SCALAR_HEADER.fullmatch(line))


def starts_yaml_node_property_or_alias(value: str, start: int) -> bool:
    """Return whether a YAML node property or alias begins at ``start``."""

    index = skip_whitespace(value, start)
    return index < len(value) and value[index] in {"!", "&", "*"}


def has_yaml_node_property_or_alias_mapping_key(line: str) -> bool:
    """Reject block keys whose YAML decoding can obscure the ``uses`` spelling."""

    return starts_yaml_node_property_or_alias(line, BLOCK_PREFIX.match(line).end())


def unsupported_mapping_key_syntax(value: str, start: int) -> str | None:
    """Return an error for mapping-key syntax that this checker rejects safely."""

    index = skip_whitespace(value, start)
    if index >= len(value):
        return None
    if value[index] == "?":
        return "unsupported explicit uses key syntax"
    if value[index] in {"!", "&", "*"}:
        return "unsupported YAML node property or alias as mapping key"
    return None


def flow_mapping_unsupported_key_syntax(line: str) -> str | None:
    """Return unsupported explicit/node-property key syntax in flow mappings."""

    flow_depth = 0
    quote: str | None = None
    escaped = False
    index = 0
    while index < len(line):
        character = line[index]
        if quote == '"':
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            index += 1
            continue
        if quote == "'":
            if character == quote:
                quote = None
            index += 1
            continue
        if character in {"'", '"'}:
            quote = character
        elif line.startswith("${{", index):
            expression_end = line.find("}}", index + 3)
            if expression_end == -1:
                return None
            index = expression_end + 2
            continue
        elif character == "{":
            flow_depth += 1
            error = unsupported_mapping_key_syntax(line, index + 1)
            if error:
                return error
        elif character == "," and flow_depth:
            error = unsupported_mapping_key_syntax(line, index + 1)
            if error:
                return error
        elif character == "}":
            flow_depth = max(0, flow_depth - 1)
        index += 1
    return None


def unsupported_multiline_yaml_syntax(line: str) -> str | None:
    """Return an error for flow or quoted YAML syntax that spans physical lines."""

    flow_depth = 0
    quote: str | None = None
    escaped = False
    for character in line:
        if quote == '"':
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if quote == "'":
            if character == quote:
                quote = None
            continue
        if character in {"'", '"'}:
            quote = character
        elif character in "[{":
            flow_depth += 1
        elif character in "]}":
            if flow_depth == 0:
                return "unsupported unbalanced YAML flow delimiter"
            flow_depth -= 1
    if quote is not None:
        return "unsupported multiline quoted YAML scalar"
    if flow_depth:
        return "unsupported multiline YAML flow mapping"
    return None


def flow_uses_value(line: str, start: int) -> tuple[str, int] | None:
    """Return a flow-mapping ``uses`` value beginning at ``start``, if any."""

    index = skip_whitespace(line, start)
    key_end = consume_uses_key(line, index)
    if key_end is None:
        return None
    index = skip_whitespace(line, key_end)
    if index >= len(line) or line[index] != ":":
        return None
    index += 1
    while index < len(line) and line[index].isspace():
        index += 1

    value_start = index
    nested_flow = 0
    quote: str | None = None
    escaped = False
    while index < len(line):
        character = line[index]
        if quote == '"':
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
        elif quote == "'":
            if character == quote:
                quote = None
        elif character in {"'", '"'}:
            quote = character
        elif character in "[{":
            nested_flow += 1
        elif character in "]}":
            if nested_flow == 0:
                return line[value_start:index].strip(), index
            nested_flow -= 1
        elif character == "," and nested_flow == 0:
            return line[value_start:index].strip(), index
        index += 1
    return line[value_start:].strip(), index


def flow_mapping_uses_values(line: str) -> list[str]:
    """Extract ``uses`` values from YAML flow mappings without parsing strings."""

    values: list[str] = []
    flow_depth = 0
    quote: str | None = None
    escaped = False
    for index, character in enumerate(line):
        if quote == '"':
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if quote == "'":
            if character == quote:
                quote = None
            continue
        if character in {"'", '"'}:
            quote = character
            continue
        if character == "{":
            flow_depth += 1
            parsed = flow_uses_value(line, index + 1)
        elif character == "," and flow_depth:
            parsed = flow_uses_value(line, index + 1)
        else:
            parsed = None
        if parsed:
            value, _ = parsed
            values.append(value)
        if character == "}":
            flow_depth = max(0, flow_depth - 1)
    return values


def action_references(line: str) -> list[str]:
    """Extract block- and flow-mapping action references from one YAML line."""

    content = strip_inline_comment(line)
    if not content:
        return []
    references: list[str] = []
    block_value = block_uses_value(content)
    if block_value is not None:
        references.append(block_value)
    references.extend(flow_mapping_uses_values(content))
    return [unquote_scalar(reference) for reference in references]


def pin_error(reference: str) -> str | None:
    """Return why a parsed action reference violates the pinning invariant."""

    if not reference:
        return "missing action reference"
    if reference.startswith("./"):
        return None
    if reference.startswith(("!", "&", "*")):
        return "unsupported YAML node property or alias on action reference"
    if reference.lower().startswith("docker://"):
        return "Docker references cannot provide a full Git commit SHA"

    source, separator, revision = reference.rpartition("@")
    if (
        not separator
        or not source
        or "/" not in source
        or source.endswith("/")
        or not FULL_COMMIT_SHA.fullmatch(revision)
    ):
        return "external action references must end in a full 40-character Git commit SHA"
    return None


def validate_workflow_directory(workflow_root: Path) -> list[str]:
    """Return pinning violations for all supported workflow YAML files."""

    errors: list[str] = []
    for path in workflow_files(workflow_root):
        block_scalar_indent: int | None = None
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if block_scalar_indent is not None:
                if not line.strip() or leading_indentation(line) > block_scalar_indent:
                    continue
                block_scalar_indent = None
            if line.lstrip().startswith("#"):
                continue
            content = strip_inline_comment(line)
            if has_yaml_node_property_or_alias_mapping_key(content):
                errors.append(
                    f"{path}:{line_no}: unsupported YAML node property or alias as mapping key"
                )
                continue
            if is_explicit_yaml_mapping_key(content):
                errors.append(
                    f"{path}:{line_no}: unsupported explicit uses key syntax"
                )
                continue
            flow_key_error = flow_mapping_unsupported_key_syntax(content)
            if flow_key_error:
                errors.append(f"{path}:{line_no}: {flow_key_error}")
                continue
            syntax_error = unsupported_multiline_yaml_syntax(content)
            if syntax_error:
                errors.append(f"{path}:{line_no}: {syntax_error}")
                continue
            for reference in action_references(content):
                error = pin_error(reference)
                if error:
                    errors.append(f"{path}:{line_no}: {reference or '<empty>'}: {error}")
            if is_block_scalar_header(content):
                block_scalar_indent = leading_indentation(line)
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--workflow-root",
        type=Path,
        default=Path(".github/workflows"),
        help="directory containing workflow YAML files",
    )
    args = parser.parse_args()
    errors = validate_workflow_directory(args.workflow_root)
    if errors:
        print(
            "External actions must be pinned to a full 40-character Git commit SHA:"
        )
        print("\n".join(errors))
        return 1
    print("All external workflow actions are pinned to full Git commit SHAs.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
