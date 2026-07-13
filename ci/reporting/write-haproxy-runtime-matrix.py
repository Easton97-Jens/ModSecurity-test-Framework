#!/usr/bin/env python3
"""Deprecated HAProxy runtime matrix writer.

HAProxy runtime matrix evidence is now produced by live YAML execution through
``ci/runtime/run-haproxy-runtime-matrix.sh`` and consumed by
``ci/reporting/generate-case-matrix.py`` from ``haproxy-summary.json`` files. This legacy
entrypoint intentionally refuses to generate rows so it cannot reintroduce the
old diagnostic-only synthetic decision path.
"""

from __future__ import annotations

import sys


MESSAGE = (
    "write-haproxy-runtime-matrix.py is deprecated and no longer generates "
    "HAProxy runtime evidence. Run `make runtime-matrix-haproxy` to execute "
    "live YAML cases and `make generate-test-matrix` to render reports from "
    "haproxy-summary.json evidence."
)


def main() -> int:
    print(MESSAGE, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
