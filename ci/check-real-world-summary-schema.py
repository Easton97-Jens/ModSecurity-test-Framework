#!/usr/bin/env python3
"""Validate the static real-world connector summary shape used by CI."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: check-real-world-summary-schema.py SUMMARY_JSON", file=sys.stderr)
        return 2

    data = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    apache = data["apache"]
    assert apache["connector_path"] == "real-world"
    assert apache["validation_mode"] == "real-world-connector-path"
    assert apache["server"] == "apache"
    assert apache["environment"] in {"local", "github-actions"} or apache["environment"]
    assert apache["audit_behavior"] in {"stable", "unstable", "unexpected"}
    assert apache["verified_variables"] == []
    for key in ("server_binary", "module", "libmodsecurity", "summary", "cases"):
        assert key in apache
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
