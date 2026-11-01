#!/usr/bin/env python3
"""Extract bounded host counters for a synchronized first-byte evidence run.

The client/upstream barrier establishes ordering.  The selected host's Phase-4
event supplies the counters.  This helper joins those two observations without
copying a body, an intervention message, or an audit-log record into evidence.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any




from modsecurity_connector_ci.lib.runtime_path_utils import prepare_verified_runtime_artifact_root, runtime_artifact_path
from modsecurity_connector_ci.lib.first_byte_binding import create_binding, paused_append


def phase4_record(path: Path) -> dict[str, Any]:
    selected: dict[str, Any] | None = None
    for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{number}: invalid JSONL") from exc
        if not isinstance(record, dict):
            continue
        if str(record.get("rule_id") or "") != "1100301":
            continue
        phase = str(record.get("phase") or "").replace("-", "_").lower()
        if phase not in {"4", "response_body", "phase4"}:
            continue
        selected = record
    if selected is None:
        raise ValueError("host Phase-4 log does not contain rule 1100301")
    return selected


def nonnegative(record: dict[str, Any], name: str) -> int:
    value = record.get(name)
    if isinstance(value, bool):
        raise ValueError(f"{name} must be a non-negative integer")
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a non-negative integer") from exc
    if number < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return number


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase4-log", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--paused-file", type=Path)
    parser.add_argument("--release-file", type=Path)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--binding-output", type=Path)
    args = parser.parse_args(argv)

    runtime_root = prepare_verified_runtime_artifact_root()
    phase4_log = runtime_artifact_path(
        runtime_root, args.phase4_log, "Phase-4 log", must_exist=True
    )
    output = runtime_artifact_path(runtime_root, args.output, "output")
    paused = release = None
    if args.paused_file is not None:
        paused = runtime_artifact_path(runtime_root, args.paused_file, "paused record", must_exist=True)
        release = runtime_artifact_path(runtime_root, args.release_file, "release marker")
        if release.exists():
            raise ValueError("host metadata snapshot must precede upstream release")
        event, _, _ = paused_append(phase4_log)
    else:
        event = phase4_record(phase4_log)
    if event.get("response_committed") is not True:
        raise ValueError("host Phase-4 event does not confirm response_committed=true")
    seen = nonnegative(event, "body_bytes_seen")
    inspected = nonnegative(event, "body_bytes_inspected")
    if inspected > seen:
        raise ValueError("host body_bytes_inspected exceeds body_bytes_seen")
    # The client received a chunk while the reusable upstream still waited.
    # Combined with the host's current-chunk event counters, this is the
    # observed forward-first path; no payload is copied into this document.
    payload = {
        "response_committed": True,
        "body_bytes_seen": seen,
        "body_bytes_inspected": inspected,
        "no_full_response_buffering": True,
        "connector_owned_full_response_buffer": False,
    }
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.binding_output is not None:
        if paused is None or release is None or args.evidence is None:
            raise ValueError("first-byte binding requires paused, release and evidence paths")
        evidence = runtime_artifact_path(runtime_root, args.evidence, "first-byte evidence", must_exist=True)
        binding_output = runtime_artifact_path(runtime_root, args.binding_output, "first-byte binding")
        binding = create_binding(phase4_log, evidence, paused, release)
        binding_output.write_text(json.dumps(binding, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
