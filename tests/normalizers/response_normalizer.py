"""Skeleton HTTP response normalizer."""

from __future__ import annotations

import re


_PATTERNS = (
    (re.compile(r"^(Date|Last-Modified): .*$", re.MULTILINE | re.IGNORECASE), r"\1: <timestamp>"),
    (re.compile(r"^(Server): .*$", re.MULTILINE | re.IGNORECASE), r"\1: <server-banner>"),
    (re.compile(r"\b127\.0\.0\.1:\d+\b"), "127.0.0.1:<port>"),
    (re.compile(r"\btransaction(?:_id)?[=: ][A-Z0-9._:-]+\b", re.IGNORECASE), "transaction_id=<transaction-id>"),
)


def normalize(text: str) -> str:
    """Return response text with known volatile values replaced."""
    normalized = text
    for pattern, replacement in _PATTERNS:
        normalized = pattern.sub(replacement, normalized)
    return normalized


def main() -> None:
    import sys

    sys.stdout.write(normalize(sys.stdin.read()))


if __name__ == "__main__":
    main()
