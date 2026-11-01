#!/usr/bin/env python3
"""Materialize an effective capability manifest for one selected host profile.

The checked-in connector manifests describe the default compatibility path in
several connectors.  A full-lifecycle run must instead record the host path it
actually selected.  This helper creates a run-local, capability-conservative
overlay; it never changes the checked-in manifest and never upgrades a
capability to ``verified``.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
from copy import deepcopy
from pathlib import Path
import sys
from typing import Any, Mapping, Sequence


from modsecurity_test_framework.connector_context import connector_root as _selected_connector_root
_REPOSITORY_ROOT = _selected_connector_root()


from modsecurity_connector_ci.lib.runtime_path_utils import prepare_verified_runtime_artifact_root, runtime_artifact_path, runtime_or_source_artifact_path


def _read_lighttpd_version() -> str:
    contract = _REPOSITORY_ROOT / "connectors/lighttpd/lighttpd-version.contract"
    try:
        lines = contract.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise RuntimeError(f"cannot read Lighttpd version contract: {contract}") from exc
    values = [line.partition("=")[2] for line in lines if line.startswith("LIGHTTPD_VERSION=")]
    if len(values) != 1 or re.fullmatch(r"\d+\.\d+\.\d+", values[0]) is None:
        raise RuntimeError("invalid Lighttpd version contract")
    return values[0]


def _read_haproxy_version() -> str:
    contract = _REPOSITORY_ROOT / "connectors/haproxy/htx-overlay/version-contract.json"
    try:
        payload = json.loads(contract.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"cannot read HAProxy version contract: {contract}") from exc
    version = payload.get("version") if isinstance(payload, dict) else None
    if (
        not isinstance(version, str)
        or re.fullmatch(r"\d+\.\d+\.\d+", version) is None
        or payload.get("schema_version") != 1
        or payload.get("component") != "haproxy-htx-overlay"
    ):
        raise RuntimeError("invalid HAProxy version contract")
    return version


LIGHTTPD_VERSION = _read_lighttpd_version()
HAPROXY_VERSION = _read_haproxy_version()


PROFILE_BY_CONNECTOR = {
    "apache": "native-httpd-module",
    "nginx": "native-nginx-http-module",
    "haproxy": "native-htx-filter",
    "envoy": "ext_proc",
    "traefik": "native-middleware",
    "lighttpd": "patched-native",
}


PROFILE_METADATA: dict[str, dict[str, str]] = {
    "apache": {
        "host_name": "Apache HTTP Server native module",
        "integration_mode": "native-httpd-module",
        "reason": "The selected full-lifecycle route is the native httpd module.",
    },
    "nginx": {
        "host_name": "NGINX native HTTP module",
        "integration_mode": "native-nginx-http-module",
        "reason": "The selected full-lifecycle route is the native NGINX HTTP module.",
    },
    "haproxy": {
        "host_name": f"HAProxy {HAPROXY_VERSION} native HTX filter",
        "integration_mode": "native-htx-filter",
        "reason": (
            f"The selected route is the patched HAProxy {HAPROXY_VERSION} HTX filter. "
            "It passes borrowed HTX body slices incrementally to a real "
            "libmodsecurity transaction and evaluates Phase 4 at HTX EOS; "
            "the response-body availability capability never authorizes a "
            "connector-owned full-response buffer."
        ),
    },
    "envoy": {
        "host_name": "Envoy ext_proc listener",
        "integration_mode": "ext_proc",
        "reason": (
            "The selected route is the streamed Envoy ext_proc listener with "
            "a Common/libmodsecurity bridge; strict post-commit reset remains "
            "unexecuted until a client-visible reset is proven."
        ),
    },
    "traefik": {
        "host_name": "Traefik native middleware",
        "integration_mode": "native-traefik-middleware",
        "reason": (
            "The selected route is the native Traefik middleware in the pinned "
            "host with a persistent local Common/libmodsecurity UDS service; "
            "strict post-commit reset remains unexecuted until proven."
        ),
    },
    "lighttpd": {
        "host_name": f"lighttpd {LIGHTTPD_VERSION} patched native host",
        "integration_mode": "patched-native-lighttpd",
        "reason": (
            f"The selected route is the patched lighttpd {LIGHTTPD_VERSION} core and matching "
            "module. Its Entity-Body hook receives decoded HTTP/1 response entity "
            "ranges before transfer framing and finalizes Phase 4 exactly once at "
            "entity EOS."
        ),
    },
}


# States below describe only source/transport availability.  They deliberately
# never assert a host proof or runtime promotion.  The canonical runner still
# requires a matching host event before it can turn any case into PASS.
IMPLEMENTED_NOT_ASSERTED: dict[str, tuple[str, ...]] = {
    "haproxy": (
        "connection_metadata",
        "transport_metadata",
        "request_headers",
        # P2 is recorded as host-buffered; this must not imply incremental
        # upstream request forwarding.
        "request_body_buffered",
        "response_headers",
        # The legacy catalog spelling means body availability for P4 rule
        # evaluation, never connector-owned complete response buffering.
        "response_body_buffered",
        "response_body_incremental_ingest",
        "phase1",
        "phase2",
        "phase3",
        "phase4",
        "phase4_rule_evaluation",
        "phase4_end_of_stream_evaluation",
        "deny",
        "log_only",
        "late_intervention",
        "late_intervention_log_only",
        "late_intervention_status_metadata",
        "no_full_response_buffering",
        "first_byte_before_response_end",
        "transaction_id",
        "event_jsonl",
    ),
    "envoy": (
        "transport_metadata",
        "request_headers",
        "request_body_buffered",
        "request_body_incremental_ingest",
        "response_headers",
        "response_body_buffered",
        "response_body_incremental_ingest",
        "phase1",
        "phase2",
        "phase3",
        "phase4",
        "phase4_rule_evaluation",
        "phase4_end_of_stream_evaluation",
        "deny",
        "redirect",
        "log_only",
        "late_intervention",
        "late_intervention_log_only",
        "late_intervention_status_metadata",
        "no_full_response_buffering",
        "first_byte_before_response_end",
        "transaction_id",
        "event_jsonl",
    ),
    "traefik": (
        "transport_metadata",
        "request_headers",
        "request_body_buffered",
        "request_body_incremental_ingest",
        "response_headers",
        "response_body_buffered",
        "response_body_incremental_ingest",
        "phase1",
        "phase2",
        "phase3",
        "phase4",
        "phase4_rule_evaluation",
        "phase4_end_of_stream_evaluation",
        "deny",
        "log_only",
        "late_intervention",
        "late_intervention_log_only",
        "late_intervention_status_metadata",
        "no_full_response_buffering",
        "first_byte_before_response_end",
        "transaction_id",
        "event_jsonl",
    ),
    "lighttpd": (
        "connection_metadata",
        "transport_metadata",
        "request_headers",
        "request_body_buffered",
        "request_body_incremental_ingest",
        "response_body_buffered",
        "response_body_incremental_ingest",
        "deny",
        "log_only",
        "late_intervention",
        "late_intervention_log_only",
        "late_intervention_status_metadata",
        "no_full_response_buffering",
        "first_byte_before_response_end",
        "response_headers",
        "phase1",
        "phase2",
        "phase3",
        "phase4",
        "phase4_rule_evaluation",
        "phase4_end_of_stream_evaluation",
        "transaction_id",
        "event_jsonl",
    ),
}


def load_manifest(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"cannot read capability manifest {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"capability manifest must be an object: {path}")
    connector = payload.get("connector")
    if connector not in PROFILE_BY_CONNECTOR:
        raise ValueError(f"unsupported connector in capability manifest: {connector!r}")
    if not isinstance(payload.get("capabilities"), dict):
        raise ValueError("capability manifest is missing capabilities")
    return payload


def set_capability(
    capabilities: dict[str, Any], name: str, state: str, reason: str
) -> None:
    current = capabilities.get(name)
    if not isinstance(current, Mapping):
        raise ValueError(f"capability manifest is missing {name}")
    replacement = dict(current)
    replacement["state"] = state
    replacement["reason"] = reason
    capabilities[name] = replacement


def effective_manifest(payload: Mapping[str, Any], profile: str) -> dict[str, Any]:
    connector = str(payload.get("connector") or "")
    expected_profile = PROFILE_BY_CONNECTOR.get(connector)
    if expected_profile is None:
        raise ValueError(f"unsupported connector: {connector!r}")
    if profile != expected_profile:
        raise ValueError(
            f"invalid full-lifecycle profile {profile!r} for {connector}; "
            f"expected {expected_profile!r}"
        )

    output = deepcopy(dict(payload))
    metadata = PROFILE_METADATA[connector]
    output["host_name"] = metadata["host_name"]
    output["integration_mode"] = metadata["integration_mode"]
    output["full_lifecycle_profile"] = profile
    output["full_lifecycle_profile_reason"] = metadata["reason"]
    constraints = list(output.get("host_model_constraints") or [])
    constraints.append(f"Selected full-lifecycle host profile: {profile}. {metadata['reason']}")
    output["host_model_constraints"] = constraints

    capabilities = output["capabilities"]
    if connector in IMPLEMENTED_NOT_ASSERTED:
        # Start conservatively: compatibility-path states cannot leak into a
        # selected native profile merely because the same connector owns both.
        for name in capabilities:
            set_capability(
                capabilities,
                name,
                "not_implemented",
                f"Not asserted for selected full-lifecycle profile {profile}; no canonical host evidence exists.",
            )
        for name in IMPLEMENTED_NOT_ASSERTED[connector]:
            set_capability(
                capabilities,
                name,
                "implemented_not_asserted",
                f"Implemented or observed on selected profile {profile}, but not promoted without a canonical host run.",
            )

    return output


def write_json_atomically(root: Path, path: Path, payload: Mapping[str, Any]) -> None:
    path = runtime_artifact_path(root, path, "effective capability manifest")
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.tmp-", dir=path.parent, text=True
    )
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--runtime-root", required=True, type=Path)
    parser.add_argument("--profile", required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        runtime_root = prepare_verified_runtime_artifact_root(args.runtime_root)
        input_path = runtime_or_source_artifact_path(
            runtime_root, args.input, "capability manifest", must_exist=True
        )
        output_path = runtime_artifact_path(
            runtime_root, args.output, "effective capability manifest"
        )
        output = effective_manifest(load_manifest(input_path), args.profile)
        write_json_atomically(runtime_root, output_path, output)
    except ValueError as exc:
        print(f"FAIL: {exc}", file=os.sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
