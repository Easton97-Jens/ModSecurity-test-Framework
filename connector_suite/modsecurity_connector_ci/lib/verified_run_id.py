#!/usr/bin/env python3
"""Validate verified-run identities before they become path components."""

from __future__ import annotations

import re


VERIFIED_RUN_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


class VerifiedRunIdError(ValueError):
    """A verified-run identity cannot safely be used as one path segment."""


def validate_verified_run_id(value: str) -> str:
    """Return a bounded, non-traversing verified-run filename segment.

    The value originates in environment variables, CLI arguments, and the
    current-run marker.  It must be validated before any caller appends it to
    a build or matrix path.  The conservative double-dot rule matches the
    existing lifecycle resolver and avoids accepting traversal-looking IDs.
    """

    if not isinstance(value, str):
        raise VerifiedRunIdError("verified_run_id must be a string")
    if not value or value != value.strip() or "\x00" in value:
        raise VerifiedRunIdError("verified_run_id must be a non-empty trimmed string")
    if "/" in value or "\\" in value or value in {".", ".."}:
        raise VerifiedRunIdError("verified_run_id must be one safe filename segment")
    if not VERIFIED_RUN_ID_PATTERN.fullmatch(value) or ".." in value:
        raise VerifiedRunIdError(
            "verified_run_id must use 1-128 ASCII letters, digits, dots, underscores, "
            "or hyphens without traversal-looking components"
        )
    return value
