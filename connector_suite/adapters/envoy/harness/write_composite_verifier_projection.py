#!/usr/bin/env python3
"""Project one real Envoy matrix case into common-verifier metadata.

The projection copies an already stopped, raw observer JSONL byte-for-byte into
one private case directory and derives only verifier-schema booleans and HTTP
statuses from local client/upstream observations.  It deliberately does not
retain header values, request/response payloads, leases, process identities,
or observer decision identifiers outside the raw JSONL accepted by the common
verifier.
"""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import argparse
import json
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


REPOSITORY_ROOT = connector_root()
CI_LIB = REPOSITORY_ROOT / "ci" / "lib"



from modsecurity_connector_ci.lib.runtime_path_utils import PrivateRuntimeRoot, open_private_runtime_root
from connector_suite.adapters.composite_harness.verify_matrix_evidence import (
    EvidenceError,
    validate_raw_event_records,
    verify_manifest,
)


MAX_EVENT_LOG_BYTES = 256 * 1024
MAX_EVENT_LINE_BYTES = 16 * 1024
MAX_OBSERVATION_BYTES = 16 * 1024
EVENT_LOG_LABEL = "event log"
EVENT_LEAF = "verifier-events.jsonl"
CLIENT_LEAF = "verifier-client.observation.json"
UPSTREAM_LEAF = "verifier-upstream.observation.json"
MANIFEST_LEAF = "verifier-manifest.json"
SUMMARY_LEAF = "verifier-summary.json"
PROJECTION_ARTIFACT_LEAVES = frozenset({
    EVENT_LEAF,
    CLIENT_LEAF,
    UPSTREAM_LEAF,
    MANIFEST_LEAF,
    SUMMARY_LEAF,
})
CASE_PHASES: dict[str, tuple[str, ...]] = {
    "p1_allow": ("P1", "P2", "P3", "P4"),
    "p1_deny": ("P1",),
    "p2_allow": ("P1", "P2", "P3", "P4"),
    "p2_deny": ("P1", "P2"),
    "p2_oversize": ("P1", "P2"),
    "p3_deny": ("P1", "P2", "P3"),
    "p3_redirect": ("P1", "P2", "P3"),
    "p4_safe": ("P1", "P2", "P3", "P4"),
    "envoy_response_metadata_omitted": ("P1", "P2"),
}
REQUEST_TERMINAL_CASES = frozenset({"p1_deny", "p2_deny", "p2_oversize"})


class ProjectionError(ValueError):
    """The runner inputs cannot safely support a verifier projection."""


@dataclass(frozen=True)
class ProjectionResult:
    case: str
    status: str
    scope: str
    catalog_acceptance: bool
    manifest: Path
    summary: Path

    def as_dict(self) -> dict[str, object]:
        return {
            "case": self.case,
            "status": self.status,
            "scope": self.scope,
            "catalog_acceptance": self.catalog_acceptance,
            "lifecycle_verified": self.status == "LIFECYCLE_ONLY",
            "payloads_persisted": False,
        }


def _absolute(value: str | Path, label: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise ProjectionError(f"{label} must be absolute")
    # Normalize lexical traversal before any containment comparison.  The
    # descriptor-backed private-root helper separately rejects symlinks; this
    # prevents a textual path beneath a runtime root from normalizing outside
    # that root before the helper receives it.
    return Path(os.path.abspath(os.fspath(path)))


def _direct_child(root: Path, value: str | Path, label: str) -> Path:
    path = _absolute(value, label)
    if path.parent != root or path.name in {"", ".", ".."}:
        raise ProjectionError(f"{label} must be a direct child of its private root")
    if path.is_symlink():
        raise ProjectionError(f"{label} must not be a symlink")
    return path


def _no_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ProjectionError(f"duplicate JSON field: {key}")
        value[key] = item
    return value


def _object(text: str, label: str) -> dict[str, Any]:
    try:
        value = json.loads(text, object_pairs_hook=_no_duplicate_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProjectionError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ProjectionError(f"{label} must be an object")
    return value


def _private_event_identity(runtime_root: PrivateRuntimeRoot, name: str) -> tuple[int, int, int, int]:
    details = os.stat(name, dir_fd=runtime_root.descriptor, follow_symlinks=False)
    return details.st_dev, details.st_ino, details.st_size, details.st_nlink


def _bounded_private_event(
    runtime_root: PrivateRuntimeRoot, runtime_path: Path, event_log: Path,
) -> str:
    event_log = _direct_child(runtime_path, event_log, EVENT_LOG_LABEL)
    before = _private_event_identity(runtime_root, event_log.name)
    try:
        raw_text = runtime_root.read_text(
            event_log.name,
            label=EVENT_LOG_LABEL,
            maximum_bytes=MAX_EVENT_LOG_BYTES,
        )
    except ValueError as exc:
        raise ProjectionError("event log is not bounded private metadata") from exc
    if before != _private_event_identity(runtime_root, event_log.name):
        raise ProjectionError("event log changed while it was projected")
    return raw_text


def _projection_artifact_identity(details: os.stat_result, label: str) -> tuple[int, int]:
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_uid != os.geteuid()
        or stat.S_IMODE(details.st_mode) != 0o600
        or details.st_nlink != 1
    ):
        raise ProjectionError(f"{label} is not an owner-private regular file")
    return details.st_dev, details.st_ino


def _projection_staging_identity(details: os.stat_result, label: str) -> tuple[int, int]:
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_uid != os.geteuid()
        or stat.S_IMODE(details.st_mode) != 0o600
        or details.st_nlink != 0
    ):
        raise ProjectionError(f"{label} is not an owner-private anonymous staging file")
    return details.st_dev, details.st_ino


class _ProjectionOutputTransaction:
    """Publish projection leaves atomically without unsafe pathname cleanup.

    POSIX cannot make a later unlink conditional on a previously observed
    device/inode pair. A same-UID writer could otherwise replace a published
    leaf between validation and removal. Anonymous ``O_TMPFILE`` staging has
    no attacker-addressable name; once linked into the fixed output name, a
    failed projection deliberately retains the private artifact for the owner
    instead of risking deletion of a replacement.
    """

    def __init__(self, root: PrivateRuntimeRoot) -> None:
        self._root = root

    def rollback(self) -> None:
        # Do not unlink a pathname after publication. The directory is
        # descriptor-anchored and owner-private, but same-UID mutation is not
        # an atomic unlink-if-identity boundary. Retained leaves remain
        # bounded, fixed-name private artifacts for explicit owner cleanup.
        return None

    def create_text(self, name: str, value: str) -> None:
        if name not in PROJECTION_ARTIFACT_LEAVES:
            raise ProjectionError("projection artifact name is not permitted")
        anonymous_temporary = getattr(os, "O_TMPFILE", 0)
        if not anonymous_temporary:
            raise ProjectionError("projection output requires O_TMPFILE")
        descriptor = -1
        try:
            descriptor = os.open(
                ".",
                os.O_WRONLY | anonymous_temporary,
                0o600,
                dir_fd=self._root.descriptor,
            )
            os.fchmod(descriptor, 0o600)
            identity = _projection_staging_identity(
                os.fstat(descriptor), "projection staging artifact"
            )
            with os.fdopen(descriptor, "w", encoding="utf-8", closefd=False) as stream:
                stream.write(value)
                stream.flush()
                os.fsync(stream.fileno())
            os.link(
                f"/proc/self/fd/{descriptor}",
                name,
                dst_dir_fd=self._root.descriptor,
                follow_symlinks=True,
            )
            if _projection_artifact_identity(
                os.stat(name, dir_fd=self._root.descriptor, follow_symlinks=False),
                "projection artifact",
            ) != identity:
                raise ProjectionError("published projection artifact identity changed")
        except BaseException:
            self.rollback()
            raise
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def __enter__(self) -> "_ProjectionOutputTransaction":
        return self

    def __exit__(self, exception_type: object, *_: object) -> None:
        if exception_type is not None:
            self.rollback()


def _event_records(text: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for number, line in enumerate(text.splitlines(keepends=True), 1):
        if len(line.encode("utf-8")) > MAX_EVENT_LINE_BYTES:
            raise ProjectionError(f"event log line {number} exceeds verifier metadata limit")
        if not line.strip():
            raise ProjectionError(f"event log line {number} is blank")
        records.append(_object(line, f"event log line {number}"))
    if not records:
        raise ProjectionError("event log is empty")
    return records


def _bool(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise ProjectionError(f"{label} must be boolean")
    return value


def _status(value: object, label: str) -> int:
    if type(value) is not int or not 100 <= value <= 599:
        raise ProjectionError(f"{label} must be an HTTP status")
    return value


def _nonnegative(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        raise ProjectionError(f"{label} must be a non-negative integer")
    return value


def _probe_observation(case_path: Path, case_root: PrivateRuntimeRoot, probe: Path) -> tuple[int, int, bool]:
    probe = _direct_child(case_path, probe, "probe")
    # The descriptor-backed reader below is the actual path authority.  The
    # lexical direct-child check above prevents this adapter from consuming an
    # unrelated case artifact before that reader is entered.
    value = _object(
        case_root.read_text(probe.name, label="client probe", maximum_bytes=MAX_OBSERVATION_BYTES),
        "client probe",
    )
    required = {
        "schema_version",
        "evidence_type",
        "http_status",
        "response_bytes",
        "body_payload_persisted",
        "redirect_location_verified",
        "composite_lease_header_present",
    }
    if set(value) != required:
        raise ProjectionError("client probe has an unexpected metadata schema")
    if value["schema_version"] != 1 or value["evidence_type"] != "envoy_http_client_probe":
        raise ProjectionError("client probe has an unexpected identity")
    status = _status(value["http_status"], "client probe.http_status")
    response_bytes = _nonnegative(value["response_bytes"], "client probe.response_bytes")
    if _bool(value["body_payload_persisted"], "client probe.body_payload_persisted"):
        raise ProjectionError("client probe retained a response payload")
    redirect_location_verified = _bool(
        value["redirect_location_verified"],
        "client probe.redirect_location_verified",
    )
    if _bool(value["composite_lease_header_present"], "client probe.composite_lease_header_present"):
        raise ProjectionError("client observed a private composite lease header")
    return status, response_bytes, redirect_location_verified


def _optional_upstream_observation(
    case_path: Path, case_root: PrivateRuntimeRoot, upstream: Path, label: str,
) -> tuple[bool, bool] | None:
    upstream = _direct_child(case_path, upstream, label)
    try:
        upstream.lstat()
    except FileNotFoundError:
        return None
    value = _object(
        case_root.read_text(upstream.name, label=label, maximum_bytes=MAX_OBSERVATION_BYTES),
        label,
    )
    required = {
        "request_observed",
        "response_observed",
        "composite_lease_header_present",
    }
    if set(value) != required:
        raise ProjectionError(f"{label} has an unexpected metadata schema")
    request_observed = _bool(value["request_observed"], f"{label}.request_observed")
    response_observed = _bool(value["response_observed"], f"{label}.response_observed")
    if _bool(value["composite_lease_header_present"], f"{label}.composite_lease_header_present"):
        raise ProjectionError("private composite lease header reached upstream")
    return request_observed, response_observed


def _upstream_observation(
    case_path: Path, case_root: PrivateRuntimeRoot, request_observation: Path,
    response_observation: Path,
) -> tuple[bool, bool] | None:
    request = _optional_upstream_observation(
        case_path, case_root, request_observation, "upstream request observation"
    )
    response = _optional_upstream_observation(
        case_path, case_root, response_observation, "upstream response observation"
    )
    if request is None:
        if response is not None:
            raise ProjectionError("upstream response observation exists without request-start evidence")
        return None
    if request != (True, False):
        raise ProjectionError("upstream request observation must prove request start before response completion")
    if response is None:
        return True, False
    if response != (True, True):
        raise ProjectionError("upstream response observation must prove completed response")
    return response


def _request_deny_observed(events: list[dict[str, Any]]) -> bool:
    for event in events:
        if event.get("phase") != "request_host_action" or event.get("actual_host_action") != "deny":
            continue
        status = event.get("visible_status")
        if type(status) is int and 400 <= status <= 599:
            return True
    return False


def _upstream_projection(case: str, events: list[dict[str, Any]], observed: tuple[bool, bool] | None) -> dict[str, bool]:
    if observed is not None:
        request_observed, response_observed = observed
        if not request_observed or not response_observed:
            raise ProjectionError("upstream observation did not prove request and completed response")
        return {
            "lease_observed": False,
            "request_terminal": False,
            "response_observed": True,
        }
    if case in REQUEST_TERMINAL_CASES:
        if not _request_deny_observed(events):
            raise ProjectionError("request-side deny lacks bounded terminal host-action evidence")
        return {
            "lease_observed": False,
            "request_terminal": True,
            "response_observed": False,
        }
    raise ProjectionError("upstream observation is required for this verifier case")


def project_case(
    *,
    runtime_root: str | Path,
    case_root: str | Path,
    case: str,
    event_log: str | Path,
    probe: str | Path,
    upstream_request_observation: str | Path,
    upstream_response_observation: str | Path,
) -> ProjectionResult:
    if case not in CASE_PHASES:
        raise ProjectionError("case is not supported by the Envoy verifier projection")
    runtime_path = _absolute(runtime_root, "runtime root")
    case_path = _absolute(case_root, "case root")
    try:
        case_path.relative_to(runtime_path)
    except ValueError as exc:
        raise ProjectionError("case root escapes runtime root") from exc
    manifest_path = case_path / MANIFEST_LEAF
    event_copy = case_path / EVENT_LEAF
    summary_path = case_path / SUMMARY_LEAF
    with (
        open_private_runtime_root(runtime_path) as private_runtime,
        open_private_runtime_root(case_path) as private_case,
        _ProjectionOutputTransaction(private_case) as outputs,
    ):
            raw_text = _bounded_private_event(
                private_runtime,
                runtime_path,
                _absolute(event_log, "event log"),
            )
            events = _event_records(raw_text)
            try:
                validate_raw_event_records(events, connector="envoy", case=case)
            except EvidenceError as exc:
                raise ProjectionError("raw Envoy event log violates common verifier schema") from exc
            status, _response_bytes, redirect_location_verified = _probe_observation(
                case_path, private_case, _absolute(probe, "probe")
            )
            upstream = _upstream_observation(
                case_path,
                private_case,
                _absolute(upstream_request_observation, "upstream request observation"),
                _absolute(upstream_response_observation, "upstream response observation"),
            )
            upstream_projection = _upstream_projection(case, events, upstream)
            p4_committed = any(event.get("phase") == "P4" for event in events)
            client_projection: dict[str, object] = {
                "lease_observed": False,
                "visible_status": status,
                "redirect_location_verified": redirect_location_verified,
                "p4_outcome": "none",
                "p4_visible_status": status if p4_committed else None,
                "p4_response_committed": p4_committed,
            }
            manifest = {
                "schema": "msc-composite-evidence/v1",
                "connector": "envoy",
                "case": case,
                "case_artifact": {"id": f"envoy-{case}-lifecycle", "event_log": EVENT_LEAF},
                "expected_phases": list(CASE_PHASES[case]),
                "client_observation": CLIENT_LEAF,
                "upstream_observation": UPSTREAM_LEAF,
                "cleanup": {"count": 1, "status": "completed"},
            }
            outputs.create_text(EVENT_LEAF, raw_text)
            outputs.create_text(
                CLIENT_LEAF,
                json.dumps(client_projection, sort_keys=True) + "\n",
            )
            outputs.create_text(
                UPSTREAM_LEAF,
                json.dumps(upstream_projection, sort_keys=True) + "\n",
            )
            outputs.create_text(
                MANIFEST_LEAF,
                json.dumps(manifest, sort_keys=True) + "\n",
            )
            try:
                verification = verify_manifest(
                    manifest_path,
                    expected_event_log=event_copy,
                    runtime_root=case_path,
                )
            except EvidenceError as exc:
                raise ProjectionError("common verifier rejected projected Envoy evidence") from exc
            if not verification.lifecycle_verified or verification.catalog_acceptance:
                raise ProjectionError("common verifier did not return lifecycle-only non-catalog evidence")
            summary = {
                "schema_version": 1,
                "status": verification.status,
                "scope": verification.scope,
                "lifecycle_verified": verification.lifecycle_verified,
                "catalog_acceptance": verification.catalog_acceptance,
                "payloads_persisted": False,
            }
            outputs.create_text(
                SUMMARY_LEAF,
                json.dumps(summary, sort_keys=True) + "\n",
            )
    return ProjectionResult(
        case=case,
        status=verification.status,
        scope=verification.scope,
        catalog_acceptance=verification.catalog_acceptance,
        manifest=manifest_path,
        summary=summary_path,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-root", required=True, type=Path)
    parser.add_argument("--case-root", required=True, type=Path)
    parser.add_argument("--case", required=True, choices=sorted(CASE_PHASES))
    parser.add_argument("--event-log", required=True, type=Path)
    parser.add_argument("--probe", required=True, type=Path)
    parser.add_argument("--upstream-request-observation", required=True, type=Path)
    parser.add_argument("--upstream-response-observation", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = project_case(
            runtime_root=args.runtime_root,
            case_root=args.case_root,
            case=args.case,
            event_log=args.event_log,
            probe=args.probe,
            upstream_request_observation=args.upstream_request_observation,
            upstream_response_observation=args.upstream_response_observation,
        )
    except (OSError, ValueError) as exc:
        print(f"Envoy verifier projection failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result.as_dict(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
