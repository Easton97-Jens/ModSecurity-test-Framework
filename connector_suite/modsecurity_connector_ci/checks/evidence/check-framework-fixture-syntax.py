#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except Exception:  # pragma: no cover - surfaced as a lint failure.
    yaml = None


SEC_DIRECTIVE_RE = re.compile(r"^\s*(SecRule|SecAction)\s+")
EMPTY_OPERATOR_RE = re.compile(r"^@(streq|contains)\s*$", re.IGNORECASE)


def quoted_strings(line: str) -> list[str] | None:
    values: list[str] = []
    current: list[str] | None = None
    escaped = False
    for char in line:
        if current is None:
            if char == '"':
                current = []
            continue
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            current.append(char)
            escaped = True
            continue
        if char == '"':
            values.append("".join(current))
            current = None
            continue
        current.append(char)
    if current is not None:
        return None
    return values


def joined_rule_lines(rules: str) -> list[tuple[int, str]]:
    output: list[tuple[int, str]] = []
    pending = ""
    start_line = 0
    for line_number, line in enumerate(rules.splitlines(), start=1):
        stripped = line.rstrip()
        if pending:
            pending += " " + stripped.lstrip()
        else:
            pending = stripped
            start_line = line_number
        if stripped.endswith("\\"):
            pending = pending[:-1].rstrip()
            continue
        output.append((start_line, pending))
        pending = ""
        start_line = 0
    if pending:
        output.append((start_line, pending))
    return output


def lint_rule_line(path: Path, line_number: int, line: str) -> list[str]:
    if not SEC_DIRECTIVE_RE.search(line):
        return []
    values = quoted_strings(line)
    if values is None:
        return []
    directive = line.lstrip().split(None, 1)[0]
    if directive == "SecRule" and len(values) < 2:
        return [f"{path}:{line_number}: SecRule does not provide operator and action strings"]
    if directive == "SecAction" and len(values) < 1:
        return [f"{path}:{line_number}: SecAction does not provide an action string"]

    errors: list[str] = []
    if directive == "SecRule":
        operator = values[0].strip()
        if EMPTY_OPERATOR_RE.match(operator):
            errors.append(f"{path}:{line_number}: empty @{operator[1:].split()[0]} operator parameter")
        action_block = values[-1]
    else:
        action_block = values[0]

    if "msg:'former XFAIL invalid urlDecode" in action_block:
        errors.append(
            f"{path}:{line_number}: former-XFAIL note is embedded in msg:'...'; "
            "use a parser-safe message token or move the note to YAML metadata"
        )
    if "msg:" in action_block and "\n" in action_block:
        errors.append(f"{path}:{line_number}: msg action contains a newline")
    return errors


def lint_case(path: Path) -> list[str]:
    if yaml is None:
        return ["PyYAML is required for fixture syntax lint"]
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return [f"{path}: YAML parse failed: {exc}"]
    if not isinstance(data, dict):
        return []
    rules = data.get("rules")
    if not isinstance(rules, str) or not rules.strip():
        return []
    errors: list[str] = []
    for line_number, line in joined_rule_lines(rules):
        errors.extend(lint_rule_line(path, line_number, line))
    return errors


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Lint framework YAML rule fixtures for early syntax blockers.")
    parser.add_argument("--framework-root", default="modules/ModSecurity-test-Framework")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    framework_root = Path(args.framework_root).resolve()
    cases_root = framework_root / "tests/cases"
    if not cases_root.is_dir():
        print(f"check-framework-fixture-syntax: missing cases root: {cases_root}", file=sys.stderr)
        return 77

    errors: list[str] = []
    for path in sorted(cases_root.rglob("*.yaml")):
        errors.extend(lint_case(path))
    if errors:
        for error in errors:
            print(error)
        print(f"check-framework-fixture-syntax: FAIL ({len(errors)} issue(s))", file=sys.stderr)
        return 1
    print("check-framework-fixture-syntax: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
