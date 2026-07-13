#!/usr/bin/env python3
"""Print a compact connector smoke summary from connector-summary.json."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: summarize-results.py CONNECTOR_SUMMARY_JSON", file=sys.stderr)
        return 2

    path = Path(argv[1])
    if not path.exists():
        print(f"summary missing: {path}", file=sys.stderr)
        return 1

    data = json.loads(path.read_text(encoding="utf-8"))
    for connector in ("apache", "nginx"):
        summary = data.get(connector)
        if not isinstance(summary, dict):
            print(f"{connector}: missing")
            continue
        counts = summary.get("summary", {})
        variables = ", ".join(summary.get("verified_variables", []))
        print(f"{connector}: {counts}")
        print(f"  environment: {summary.get('environment', '')}")
        print(f"  audit_behavior: {summary.get('audit_behavior', '')}")
        print(f"  verified_variables: {variables}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
