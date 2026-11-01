"""Bind a paused NGINX first-byte snapshot to its original append event.

The receipt is metadata, not an invented Host event. Its log prefix remains
verifiable after later append/completion events are written.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
from modsecurity_connector_ci.lib.runtime_path_utils import runtime_artifact_path


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def event_digest(event: dict[str, Any]) -> str:
    return digest(json.dumps(event, sort_keys=True, separators=(",", ":")).encode())


def paused_append(log: Path) -> tuple[dict[str, Any], int, bytes]:
    prefix = log.read_bytes()
    event, index = paused_prefix(prefix)
    return event, index, prefix


def paused_prefix(prefix: bytes) -> tuple[dict[str, Any], int]:
    """Require a single transaction and the last pre-EOS native append."""
    events = [json.loads(line) for line in prefix.splitlines() if line.strip()]
    identities = {event.get("transaction_id") for event in events
                  if event.get("phase") in (4, "response_body", "phase4")}
    if len(identities) != 1 or None in identities or "" in identities:
        raise ValueError("first-byte snapshot requires one observed transaction")
    if any(event.get("event") in {"phase4_completion", "phase4_intervention"}
           or event.get("eos_seen") is True for event in events):
        raise ValueError("first-byte snapshot was taken after response completion")
    matches = [(index, event) for index, event in enumerate(events)
               if event.get("event") == "phase4_append"
               and event.get("phase") in (4, "response_body", "phase4")
               and event.get("response_committed") is True]
    if not matches:
        raise ValueError("first-byte snapshot requires a committed native append")
    index, event = matches[-1]
    return event, index


def create_binding(log: Path, evidence: Path, paused: Path, release: Path) -> dict[str, Any]:
    if release.exists() or not paused.is_file():
        raise ValueError("first-byte binding must precede upstream release")
    pause_state = json.loads(paused.read_bytes())
    if (pause_state.get("evidence_type") != "synchronized_upstream_paused"
            or pause_state.get("upstream_paused") is not True
            or pause_state.get("upstream_eos_sent") is not False
            or pause_state.get("body_payload_persisted") is not False):
        raise ValueError("first-byte binding requires original pre-EOS pause evidence")
    event, index, prefix = paused_append(log)
    snapshot = json.loads(evidence.read_bytes())
    for name in ("body_bytes_seen", "body_bytes_inspected", "response_committed"):
        if snapshot.get(name) != event.get(name):
            raise ValueError("first-byte snapshot does not match its native append")
    return {
        "schema_version": 1, "observation_point": "client_first_byte_upstream_paused",
        "phase4_log_path": str(log), "first_byte_evidence_path": str(evidence),
        "paused_path": str(paused), "release_path": str(release),
        "transaction_id": event["transaction_id"], "event_index": index,
        "event_sha256": event_digest(event), "log_prefix_size": len(prefix),
        "log_prefix_sha256": digest(prefix), "paused_sha256": digest(paused.read_bytes()),
        "evidence_sha256": digest(evidence.read_bytes()),
    }


def verify_binding(
    binding: dict[str, Any], log: Path, evidence: Path, authorized_root: Path,
) -> dict[str, Any]:
    if (binding.get("schema_version") != 1
            or binding.get("observation_point") != "client_first_byte_upstream_paused"
            or binding.get("phase4_log_path") != str(log)
            or binding.get("first_byte_evidence_path") != str(evidence)):
        raise ValueError("first-byte invocation binding mismatch")
    if digest(evidence.read_bytes()) != binding.get("evidence_sha256"):
        raise ValueError("first-byte snapshot bytes changed")
    paused = runtime_artifact_path(authorized_root, Path(str(binding.get("paused_path") or "")),
                                   "bound paused record", must_exist=True)
    release = runtime_artifact_path(authorized_root, Path(str(binding.get("release_path") or "")),
                                    "bound release marker", must_exist=True)
    if paused.parent != release.parent or digest(paused.read_bytes()) != binding.get("paused_sha256"):
        raise ValueError("first-byte paused invocation binding mismatch")
    binding_path = runtime_artifact_path(authorized_root, Path(str(evidence) + ".binding.json"),
                                        "first-byte binding", must_exist=True)
    if binding_path.stat().st_mtime_ns > release.stat().st_mtime_ns:
        raise ValueError("first-byte binding was written after upstream release")
    event = bound_append(binding, log)
    snapshot = json.loads(evidence.read_bytes())
    if any(snapshot.get(name) != event.get(name) for name in
           ("body_bytes_seen", "body_bytes_inspected", "response_committed")):
        raise ValueError("first-byte counter/event binding mismatch")
    return event


def bound_append(binding: dict[str, Any], log: Path) -> dict[str, Any]:
    """Verify the sealed prefix and exact original append in check order."""
    size = binding.get("log_prefix_size")
    index = binding.get("event_index")
    if (not isinstance(size, int) or isinstance(size, bool) or size < 1
            or not isinstance(index, int) or isinstance(index, bool) or index < 0):
        raise ValueError("invalid first-byte event position")
    prefix = log.read_bytes()[:size]
    if len(prefix) != size or digest(prefix) != binding.get("log_prefix_sha256"):
        raise ValueError("first-byte log prefix changed")
    event, observed_index = paused_prefix(prefix)
    if index != observed_index:
        raise ValueError("first-byte event position missing")
    if (event_digest(event) != binding.get("event_sha256")
            or event.get("transaction_id") != binding.get("transaction_id")
            or event.get("event") != "phase4_append"
            or event.get("response_committed") is not True
            or event.get("eos_seen") is True):
        raise ValueError("first-byte transaction/event binding mismatch")
    return event
