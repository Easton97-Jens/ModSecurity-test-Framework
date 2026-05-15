#!/usr/bin/env python3
"""Write a minimal expected audit-log fixture for a YAML smoke case."""

from __future__ import annotations

import sys
from pathlib import Path


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: write-expected-audit-log.py CASE_FILE AUDIT_LOG", file=sys.stderr)
        return 2

    repo_root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(repo_root / "tests" / "runners"))

    from runner_core import expected_audit_log, load_case

    case = load_case(argv[1])
    audit = expected_audit_log(case)
    content = "\n".join(
        str(value)
        for key, value in audit.items()
        if key != "required" and value not in (None, "")
    )
    output = Path(argv[2])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(content + ("\n" if content else ""), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
