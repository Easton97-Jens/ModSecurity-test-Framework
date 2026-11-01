#!/usr/bin/env python3
"""Extract narrowly scoped host-harness metadata from a shared YAML case.

The shared test framework owns case parsing and validation.  This helper uses
that parser, then projects only fixture values that a real HTTP response
backend or the Apache host template may consume.  It deliberately does not
copy expected outcomes into the runner.
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping
import importlib
import json
from pathlib import Path
import re
import sys
from typing import Any


HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
FORBIDDEN_FRAMING_HEADERS = frozenset({"connection", "content-length", "transfer-encoding"})
PHASE4_MODES = frozenset({"off", "safe", "strict"})


from modsecurity_connector_ci.runtime.common.response_fixture_omission import validate_omitted_headers


def load_case(case_path: Path, framework_root: Path) -> Mapping[str, Any]:
    runners = framework_root.resolve(strict=True) / "tests" / "runners"
    if not (runners / "runner_core.py").is_file():
        raise ValueError(f"framework runner_core.py is missing: {runners}")
    from modsecurity_test_framework.connector_context import load_source
    runner_core = load_source(runners / "runner_core.py")
    loaded = runner_core.load_case(case_path.resolve(strict=True))
    if not isinstance(loaded, Mapping):
        raise ValueError(f"case file must contain a mapping: {case_path}")
    return loaded


def normalize_status(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 100 <= value <= 599:
        raise ValueError("case response.status must be an integer between 100 and 599")
    return value


def normalize_header(name: object, value: object) -> tuple[str, str]:
    if not isinstance(name, str) or not HEADER_NAME_RE.fullmatch(name):
        raise ValueError(f"case response header has an invalid name: {name!r}")
    if name.lower() in FORBIDDEN_FRAMING_HEADERS:
        raise ValueError(f"case response header must not set framing header: {name}")
    if not isinstance(value, str) or "\r" in value or "\n" in value:
        raise ValueError(f"case response header has an invalid value: {name}")
    return name, value


def response_fixture(case: Mapping[str, Any]) -> dict[str, object]:
    response = case.get("response", {})
    if response is None:
        response = {}
    if not isinstance(response, Mapping):
        raise ValueError("case response must be a mapping")
    status = normalize_status(response.get("status", 200))
    raw_headers = response.get("headers", {})
    if raw_headers is None:
        raw_headers = {}
    if not isinstance(raw_headers, Mapping):
        raise ValueError("case response.headers must be a mapping")

    headers: list[list[str]] = []
    configured_names: set[str] = set()
    for name, raw_values in raw_headers.items():
        values = raw_values if isinstance(raw_values, list) else [raw_values]
        for value in values:
            header_name, header_value = normalize_header(name, value)
            headers.append([header_name, header_value])
            configured_names.add(header_name.lower())

    content_type = response.get("content_type")
    if content_type is not None and "content-type" not in configured_names:
        header_name, header_value = normalize_header("Content-Type", content_type)
        headers.append([header_name, header_value])

    fixture = {"status": status, "headers": headers}
    if "omit_headers" in response:
        validate_omitted_headers(response["omit_headers"], (name for name, _ in headers))
        fixture["omit_headers"] = response["omit_headers"]
    return fixture


def apache_phase4_mode(case: Mapping[str, Any], default: str) -> str:
    if default not in PHASE4_MODES:
        raise ValueError("Apache Phase-4 default must be off, safe, or strict")
    apache = case.get("apache", {})
    if apache is None:
        apache = {}
    if not isinstance(apache, Mapping):
        raise ValueError("case apache metadata must be a mapping")
    mode = apache.get("phase4_mode", default)
    if not isinstance(mode, str) or mode not in PHASE4_MODES:
        raise ValueError("case apache.phase4_mode must be off, safe, or strict")
    return mode


def write_response_fixture(args: argparse.Namespace) -> int:
    case = load_case(args.case, args.framework_root)
    output = args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(response_fixture(case), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


def print_apache_phase4_mode(args: argparse.Namespace) -> int:
    case = load_case(args.case, args.framework_root)
    print(apache_phase4_mode(case, args.default))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    fixture_parser = subparsers.add_parser(
        "response-header-fixture",
        help="write a validated upstream response status/header fixture",
    )
    fixture_parser.add_argument("--case", required=True, type=Path)
    fixture_parser.add_argument("--framework-root", required=True, type=Path)
    fixture_parser.add_argument("--output", required=True, type=Path)
    fixture_parser.set_defaults(func=write_response_fixture)

    apache_parser = subparsers.add_parser(
        "apache-phase4-mode",
        help="print the validated Apache Phase-4 mode for a case",
    )
    apache_parser.add_argument("--case", required=True, type=Path)
    apache_parser.add_argument("--framework-root", required=True, type=Path)
    apache_parser.add_argument("--default", default="off")
    apache_parser.set_defaults(func=print_apache_phase4_mode)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (ImportError, OSError, ValueError) as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
