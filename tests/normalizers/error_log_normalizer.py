"""Skeleton error log normalizer."""

from __future__ import annotations

import re


_PATTERNS = (
    (re.compile(r"\[[A-Z][a-z]{2} [A-Z][a-z]{2} [^\]]+\]"), "[<timestamp>]"),
    (re.compile(r"\bpid[=: ]\d+\b", re.IGNORECASE), "pid=<pid>"),
    (re.compile(r"\btid[=: ]\d+\b", re.IGNORECASE), "tid=<thread>"),
    (re.compile(r"\bthread[=: ]\d+\b", re.IGNORECASE), "thread=<thread>"),
    (re.compile(r"\b127\.0\.0\.1:\d+\b"), "127.0.0.1:<port>"),
    (re.compile(r"/root/conecter/[^\s:]+"), "<workspace-path>"),
)


def normalize(text: str) -> str:
    """Return error log text with known volatile values replaced."""
    normalized = text
    for pattern, replacement in _PATTERNS:
        normalized = pattern.sub(replacement, normalized)
    return normalized


def main() -> None:
    import sys

    sys.stdout.write(normalize(sys.stdin.read()))


if __name__ == "__main__":
    main()
