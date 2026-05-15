"""Skeleton audit log normalizer.

This module intentionally avoids connector-specific parsing. Patterns that are
not proven portable are left as TODOs in the README.
"""

from __future__ import annotations

import re


_PATTERNS = (
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[T ][0-9:.+-]+Z?\b"), "<timestamp>"),
    (re.compile(r"\bpid[=: ]\d+\b", re.IGNORECASE), "pid=<pid>"),
    (re.compile(r"\bthread[=: ]\d+\b", re.IGNORECASE), "thread=<thread>"),
    (re.compile(r"\b127\.0\.0\.1:\d+\b"), "127.0.0.1:<port>"),
    (re.compile(r"\btransaction(?:_id)?[=: ][A-Z0-9._:-]+\b", re.IGNORECASE), "transaction_id=<transaction-id>"),
)


def normalize(text: str) -> str:
    """Return audit log text with known volatile values replaced."""
    normalized = text
    for pattern, replacement in _PATTERNS:
        normalized = pattern.sub(replacement, normalized)
    return normalized


def main() -> None:
    import sys

    sys.stdout.write(normalize(sys.stdin.read()))


if __name__ == "__main__":
    main()
