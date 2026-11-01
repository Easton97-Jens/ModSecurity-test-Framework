"""Small C-source parsing helpers for static test contracts."""

from __future__ import annotations

import re


def matching_delimiter(source: str, opening: int, left: str, right: str) -> int:
    """Return the matching delimiter index or raise a precise test failure."""
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == left:
            depth += 1
        elif source[index] == right:
            depth -= 1
            if depth == 0:
                return index
    raise AssertionError(f"unterminated {left}{right} pair")


def function_definition(source: str, name: str) -> str:
    """Return a C function definition while ignoring calls and prototypes."""
    for match in re.finditer(rf"\b{re.escape(name)}\s*\(", source):
        opening = source.index("(", match.start())
        closing = matching_delimiter(source, opening, "(", ")")
        cursor = closing + 1
        while cursor < len(source) and source[cursor].isspace():
            cursor += 1
        if cursor >= len(source) or source[cursor] != "{":
            continue
        end = matching_delimiter(source, cursor, "{", "}")
        start = source.rfind("\n", 0, match.start()) + 1
        return source[start : end + 1]
    raise AssertionError(f"{name} definition was not found")
