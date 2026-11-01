#!/usr/bin/env python3
"""Copy a host log into canonical evidence without retaining request bodies.

The canonical full-lifecycle evidence root is intentionally useful after a
run, but it is not an audit-log archive.  In particular, a curl/debug trace
can otherwise reintroduce the test request or response body after the event
normalizer has carefully removed it.  This small filter preserves bounded
diagnostic lines and replaces known body sentinels and sensitive header
values.  It never treats a successful sanitization as runtime evidence.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re
import sys




from modsecurity_connector_ci.lib.runtime_path_utils import prepare_verified_runtime_artifact_root, runtime_artifact_path, write_runtime_artifact_text_atomic


BODY_SENTINELS = (
    "no-crs-request-body-marker",
    "no-crs-response-body-marker",
)
SENSITIVE_HEADER_NAMES = frozenset(
    ("authorization", "proxy-authorization", "cookie", "set-cookie")
)
INLINE_SENSITIVE_HEADER = re.compile(
    r"(?i)(authorization|proxy-authorization|cookie|set-cookie)\s*:\s*[^\s,;]+"
)
MAX_LINE_CHARS = 2048
SAFE_DIAGNOSTIC_LINE = re.compile(r"[\t\x20-\x7e]{0,2048}\Z")
SAFE_LOG_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")


def sensitive_header_prefix(line: str) -> str | None:
    """Return the safe header prefix when *line* carries a secret value.

    Header redaction is deliberately parsed rather than matched with a
    catch-all regular-expression tail.  That gives the same preservation of
    leading whitespace, field spelling, colon, and post-colon whitespace while
    bounding the work for an adversarially long diagnostic line.
    """

    leading = len(line) - len(line.lstrip())
    name, separator, remainder = line[leading:].partition(":")
    if not separator or name.strip().casefold() not in SENSITIVE_HEADER_NAMES:
        return None
    value_offset = len(remainder) - len(remainder.lstrip())
    return line[: leading + len(name) + 1 + value_offset]


def sanitize_line(line: str) -> tuple[str, bool]:
    """Return a bounded, payload-free diagnostic line and whether it changed."""
    lowered = line.casefold()
    if any(marker in lowered for marker in BODY_SENTINELS):
        return "[body payload line omitted]", True
    header_prefix = sensitive_header_prefix(line)
    if header_prefix is not None:
        return f"{header_prefix}[redacted]", True
    cleaned = INLINE_SENSITIVE_HEADER.sub(r"\1: [redacted]", line)
    changed = cleaned != line
    if len(cleaned) > MAX_LINE_CHARS:
        cleaned = cleaned[:MAX_LINE_CHARS] + " [line truncated]"
        changed = True
    if not SAFE_DIAGNOSTIC_LINE.fullmatch(cleaned):
        return "[diagnostic line omitted]", True
    return cleaned, changed


def validated_log_label(value: str) -> str:
    """Allow only the bounded label grammar used in canonical evidence."""

    if not SAFE_LOG_LABEL.fullmatch(value):
        raise ValueError(
            "log label must contain only ASCII letters, digits, dots, underscores, or dashes"
        )
    return value


def compatible_runtime_root(input_path: Path, output_path: Path) -> Path:
    """Preserve the single-directory CLI contract without widening path authority.

    Older focused callers provide a private input/output pair in the same
    directory rather than a separate root option. That directory is still
    passed through the descriptor-based runtime-root validator. Calls spanning
    directories must name their reviewed runtime root explicitly.
    """

    if input_path.parent != output_path.parent:
        raise ValueError(
            "--runtime-root is required when input and output use different directories"
        )
    return prepare_verified_runtime_artifact_root(input_path.parent)


def validated_log_paths(
    runtime_root_value: Path | None,
    input_value: Path,
    output_value: Path,
) -> tuple[Path, Path, Path]:
    """Return two no-follow artifact paths below one verified private root."""

    runtime_root = (
        prepare_verified_runtime_artifact_root(runtime_root_value)
        if runtime_root_value is not None
        else compatible_runtime_root(input_value, output_value)
    )
    return (
        runtime_root,
        runtime_artifact_path(runtime_root, input_value, "input log"),
        runtime_artifact_path(runtime_root, output_value, "output log"),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--runtime-root", type=Path)
    parser.add_argument("--label", default="host")
    args = parser.parse_args(argv)

    try:
        label = validated_log_label(args.label)
        runtime_root, input_path, output_path = validated_log_paths(
            args.runtime_root, args.input, args.output
        )
    except ValueError as exc:
        parser.error(str(exc))
    raw = input_path.read_bytes() if input_path.is_file() else b""
    text = raw.decode("utf-8", errors="replace")
    lines: list[str] = []
    redactions = 0
    for line in text.splitlines():
        safe, changed = sanitize_line(line)
        if changed:
            redactions += 1
        lines.append(safe)

    header = (
        f"canonical_log_label={label}\n"
        f"source_sha256={hashlib.sha256(raw).hexdigest()}\n"
        f"source_bytes={len(raw)}\n"
        f"redacted_lines={redactions}\n"
    )
    write_runtime_artifact_text_atomic(
        runtime_root,
        output_path,
        header + "\n".join(lines) + ("\n" if lines else ""),
        "canonical log",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
