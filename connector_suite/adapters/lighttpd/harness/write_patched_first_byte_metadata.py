#!/usr/bin/env python3
"""Derive bounded Lighttpd host metadata for the synchronized P4 barrier.

The reusable upstream owns ordering.  This helper accepts only the actual
patched-native host action emitted after entity EOS and writes its numeric
counters without copying an HTTP body, rule message, or audit payload.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from adapters.lighttpd.harness.patched_event_validation import load_events, nonnegative, phase_is_four
from adapters.lighttpd.harness.safe_runtime_output import verified_runtime_output_root, write_text_atomic

NON_OBJECT_ERROR = "{path}:{line_number}: event must be an object"


def safe_host_action(events: list[dict[str, Any]]) -> dict[str, Any]:
    candidates = [
        event
        for event in events
        if event.get("connector") == "lighttpd"
        and event.get("integration_mode") == "patched-native-lighttpd"
        and str(event.get("rule_id") or "") == "1100301"
        and phase_is_four(event.get("phase"))
        and event.get("requested_action") == "deny"
        and event.get("actual_action") == "log_only"
        and event.get("late_intervention") is True
        and event.get("late_intervention_mode") == "safe"
        and event.get("headers_sent") is True
        and event.get("body_started") is True
        and event.get("response_committed") is True
        and event.get("connection_aborted") is False
        and event.get("transport_result") == "log_only"
        and event.get("visible_http_status") == 200
        and event.get("original_http_status") == 200
        and isinstance(event.get("transaction_id"), str)
        and bool(event["transaction_id"])
    ]
    if len(candidates) != 1:
        raise ValueError(
            "synchronized Lighttpd barrier requires exactly one safe P4 host-action event"
        )
    return candidates[0]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--runtime-output-root", required=True, type=Path)
    args = parser.parse_args(argv)

    event = safe_host_action(
        load_events(args.events, non_object_error=NON_OBJECT_ERROR)
    )
    seen = nonnegative(event.get("body_bytes_seen"), "body_bytes_seen")
    inspected = nonnegative(event.get("body_bytes_inspected"), "body_bytes_inspected")
    if inspected > seen:
        raise ValueError("body_bytes_inspected cannot exceed body_bytes_seen")
    output = {
        "response_committed": True,
        "body_bytes_seen": seen,
        "body_bytes_inspected": inspected,
        "no_full_response_buffering": True,
        "connector_owned_full_response_buffer": False,
    }
    write_text_atomic(
        verified_runtime_output_root(args.runtime_output_root),
        args.output,
        json.dumps(output, indent=2, sort_keys=True) + "\n",
        "first-byte metadata output",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
