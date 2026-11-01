#!/usr/bin/env python3
"""Pure YAML case-document parsing shared by CI evidence reports."""

from __future__ import annotations

from typing import Any


def parse_case_document(
    raw: str,
    yaml_module: Any | None,
    *,
    parse_empty: bool = False,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], str, str]:
    """Return safe mapping fields and a split request path without file I/O.

    Callers retain their own safe-path/read controls and deliberately choose
    whether an empty document reaches their optional YAML parser.
    """

    parsed: dict[str, Any] = {}
    if yaml_module is not None and (raw or parse_empty):
        try:
            loaded = yaml_module.safe_load(raw)
            parsed = loaded if isinstance(loaded, dict) else {}
        except Exception:
            parsed = {}
    request = parsed.get("request") if isinstance(parsed.get("request"), dict) else {}
    expect = parsed.get("expect") if isinstance(parsed.get("expect"), dict) else {}
    source_metadata = parsed.get("metadata") if isinstance(parsed.get("metadata"), dict) else {}
    request_path = str(request.get("path") or "-")
    query = "-"
    if "?" in request_path:
        request_path, query = request_path.split("?", 1)
        request_path = request_path or "/"
    return parsed, request, expect, source_metadata, request_path, query
