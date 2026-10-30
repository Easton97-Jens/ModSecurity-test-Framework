#!/usr/bin/env python3
"""Exercise the Stock-lighttpd sidecar against an unchanged lighttpd host."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, framework_revision

from dataclasses import dataclass
from contextlib import contextmanager, ExitStack
import hashlib
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time


REPOSITORY_ROOT = connector_root()
_CI_LIB = REPOSITORY_ROOT / "ci" / "lib"

from modsecurity_connector_ci.lib.runtime_path_utils import open_private_runtime_root  # noqa: E402

_COMMIT_SHA = re.compile(r"^[0-9a-f]{40,64}$", re.ASCII)
_LIGHTTPD_VERSION = re.compile(r"\blighttpd/(\d+\.\d+\.\d+)\b", re.ASCII)
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_METADATA_KEY = re.compile(r"^[A-Za-z_]\w*$", re.ASCII)
_CASE_NAME = re.compile(r"^[a-z0-9_]+$", re.ASCII)
_MAX_CLIENT_RESPONSE_BYTES = 128 * 1024
_CLIENT_REQUEST_ARTIFACT = "request.http"
_MAX_EVENT_FILE_BYTES = 64 * 1024
_MAX_RECEIPT_BYTES = 16 * 1024
_BACKEND_ACCESS_LOG_WAIT_SECONDS = 6.0
_EVENT_INTEGRATION_MODE = "stock-lighttpd-sidecar"
_RECEIPT_INTEGRATION_MODE = "traffic-owning-sidecar"
_STOCK_STATICFILE_LINKAGE = "builtin"
_STOCK_STATICFILE_PLUGIN_INIT = "mod_staticfile_plugin_init"
_FNV_OFFSET = 14695981039346656037
_FNV_PRIME = 1099511628211
_FNV_MASK = (1 << 64) - 1
_EVENT_MAX_STRING_BYTES = 255
_EVENT_PHASE_VALUES = {
    "connection": 0,
    "uri": 1,
    "request_headers": 2,
    "request_body": 3,
    "response_headers": 4,
    "response_body": 5,
    "logging": 6,
    "unknown": -1,
}
_EVENT_STATUS_VALUES = {"ok": 0, "error": 1, "blocked": 2, "unsupported": 3}
_EVENT_ACTION_VALUES = {
    "allow", "deny", "redirect", "drop", "log_only", "abort_connection",
    "stream_reset", "error", "unsupported", "rate_limit", "unknown",
}
_EVENT_TRANSPORT_RESULTS = {
    "", "completed", "http_status", "log_only", "connection_aborted",
    "stream_reset", "client_cancelled", "client_disconnected", "upstream_reset",
    "upstream_disconnected", "timeout", "short_write", "write_would_block",
    "engine_error", "host_error", "not_observable",
}
_ENGINE_EVENT_EXPECTED_FIELDS = {
    "status": "blocked",
    "action": "deny",
    "requested_action": "deny",
    "actual_action": "",
}
_UNOBSERVED_ERROR_EVENTS = {
    "MSCONN_EVENT_ENGINE_TIMEOUT": "engine_timeout",
    "MSCONN_EVENT_ENGINE_UNAVAILABLE": "engine_unavailable",
    "MSCONN_EVENT_INVALID_ENGINE_RESPONSE": "invalid_engine_response",
    "MSCONN_EVENT_PROTOCOL_ERROR": "protocol_error",
    "MSCONN_EVENT_CONFIG_ERROR": "config_error",
    "MSCONN_EVENT_RULE_PARSE_ERROR": "rule_parse_error",
    "MSCONN_EVENT_INTERNAL_ERROR": "connector_error",
    "MSCONN_EVENT_CONNECTOR_ERROR": "connector_error",
    "MSCONN_EVENT_CLIENT_CANCEL": "client_cancel",
    "MSCONN_EVENT_UPSTREAM_DISCONNECT": "upstream_disconnect",
}
_EVENT_REQUIRED_STRING_KEYS = (
    "timestamp", "level", "message_id", "message", "event", "connector",
    "integration_mode", "transaction_id", "phase", "status", "action",
    "requested_action", "actual_action", "transport_result", "http_reason_phrase",
    "http_default_message", "rule_id", "reason", "method", "uri", "client_ip",
    "content_type",
)
_EVENT_OPTIONAL_STRING_KEYS = (
    "run_id", "transport_case_id", "requested_protocol", "downstream_protocol",
    "upstream_protocol", "negotiated_protocol", "transport", "alpn", "stream_id",
    "connection_id", "quic_version", "stream_reset_code", "reset_by", "reset_code",
    "timeout_stage", "write_result", "cleanup_reason", "body_limit_outcome",
    "late_intervention_mode",
)
_EVENT_REQUIRED_BOOL_KEYS = (
    "late_intervention", "response_started", "response_committed", "headers_sent",
    "body_started", "body_truncated", "connection_aborted", "client_disconnected",
    "upstream_disconnected", "cancelled", "eos_seen", "redacted", "truncated",
)
_EVENT_OPTIONAL_BOOL_KEYS = (
    "connection_reused", "quic_connection_id_present", "fallback_used", "stream_reset",
)
_EVENT_REQUIRED_INT_KEYS = (
    "http_status", "original_http_status", "visible_http_status", "body_bytes_seen",
    "body_bytes_inspected", "sequence", "previous_event_hash", "event_hash",
)
_EVENT_ALLOWED_KEYS = frozenset(
    _EVENT_REQUIRED_STRING_KEYS + _EVENT_OPTIONAL_STRING_KEYS +
    _EVENT_REQUIRED_BOOL_KEYS + _EVENT_OPTIONAL_BOOL_KEYS + _EVENT_REQUIRED_INT_KEYS
)
_EVENT_CONTRACT_PHASE_NAMES = {
    "P1": "request_headers",
    "P2": "request_body",
    "P3": "response_headers",
    "P4": "response_body",
}
_HEALTH_PATH = "/health.txt"
_ATTESTATION_LABEL = "Stock lighttpd artifact attestation"


def http_request(method: str, target: str, body: bytes = b"") -> bytes:
    return (
        f"{method} {target} HTTP/1.1\r\nHost: stock.test\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode("ascii")
        + body
    )


@dataclass(frozen=True)
class RealBackendCase:
    name: str
    request: bytes
    rules: tuple[str, ...]
    engine_request_limit: int
    engine_request_limit_action: str
    engine_response_limit: int
    engine_response_limit_action: str
    phase4_mode: str
    expected_status: int
    expected_body: bytes
    expected_phase_sequence: tuple[str, ...]
    expected_engine_decision: str
    expected_contract_action: str
    expected_error_class: str
    expected_response_committed: bool
    expected_engine_event: str | None
    expected_host_action_event: str | None
    expected_rule_id: str | None
    expected_actual_action: str | None
    expected_transport_result: str | None
    expected_backend_requests: int


REAL_BACKEND_CASES = (
    RealBackendCase(
        name="allow_full",
        request=http_request("GET", _HEALTH_PATH),
        rules=(),
        engine_request_limit=65536,
        engine_request_limit_action="Reject",
        engine_response_limit=65536,
        engine_response_limit_action="Reject",
        phase4_mode="strict",
        expected_status=200,
        expected_body=b"stock-backend-health",
        expected_phase_sequence=("P1", "P2", "P3", "P4"),
        expected_engine_decision="allow",
        expected_contract_action="allow",
        expected_error_class="none",
        expected_response_committed=True,
        expected_engine_event=None,
        expected_host_action_event=None,
        expected_rule_id=None,
        expected_actual_action="allow",
        expected_transport_result=None,
        expected_backend_requests=1,
    ),
    RealBackendCase(
        name="allow_empty",
        request=http_request("GET", "/empty.txt"),
        rules=(),
        engine_request_limit=65536,
        engine_request_limit_action="Reject",
        engine_response_limit=65536,
        engine_response_limit_action="Reject",
        phase4_mode="strict",
        expected_status=200,
        expected_body=b"",
        expected_phase_sequence=("P1", "P2", "P3", "P4"),
        expected_engine_decision="allow",
        expected_contract_action="allow",
        expected_error_class="none",
        expected_response_committed=True,
        expected_engine_event=None,
        expected_host_action_event=None,
        expected_rule_id=None,
        expected_actual_action="allow",
        expected_transport_result=None,
        expected_backend_requests=1,
    ),
    RealBackendCase(
        name="p1_deny",
        request=http_request("GET", "/p1-block"),
        rules=(
            'SecRule REQUEST_URI "@streq /p1-block" '
            '"id:9821001,phase:1,deny,status:451,log"',
        ),
        engine_request_limit=65536,
        engine_request_limit_action="Reject",
        engine_response_limit=65536,
        engine_response_limit_action="Reject",
        phase4_mode="strict",
        expected_status=451,
        expected_body=b"",
        expected_phase_sequence=("P1",),
        expected_engine_decision="block",
        expected_contract_action="deny",
        expected_error_class="none",
        expected_response_committed=False,
        expected_engine_event="MSCONN_EVENT_ENGINE_DECISION",
        expected_host_action_event="MSCONN_EVENT_REQUEST_BLOCKED",
        expected_rule_id="9821001",
        expected_actual_action="deny",
        expected_transport_result="http_status",
        expected_backend_requests=0,
    ),
    RealBackendCase(
        name="p2_deny",
        request=http_request("POST", _HEALTH_PATH, b"stock-p2-marker"),
        rules=(
            'SecRule REQUEST_BODY "@contains stock-p2-marker" '
            '"id:9821002,phase:2,deny,status:418,log"',
        ),
        engine_request_limit=65536,
        engine_request_limit_action="Reject",
        engine_response_limit=65536,
        engine_response_limit_action="Reject",
        phase4_mode="strict",
        expected_status=418,
        expected_body=b"",
        expected_phase_sequence=("P1", "P2"),
        expected_engine_decision="block",
        expected_contract_action="deny",
        expected_error_class="none",
        expected_response_committed=False,
        expected_engine_event="MSCONN_EVENT_ENGINE_DECISION",
        expected_host_action_event="MSCONN_EVENT_REQUEST_BLOCKED",
        expected_rule_id="9821002",
        expected_actual_action="deny",
        expected_transport_result="http_status",
        expected_backend_requests=0,
    ),
    RealBackendCase(
        name="p2_body_limit",
        request=http_request("POST", _HEALTH_PATH, b"12345"),
        rules=(),
        engine_request_limit=4,
        engine_request_limit_action="Reject",
        engine_response_limit=65536,
        engine_response_limit_action="Reject",
        phase4_mode="strict",
        expected_status=403,
        expected_body=b"",
        expected_phase_sequence=("P1", "P2"),
        expected_engine_decision="block",
        expected_contract_action="deny",
        expected_error_class="body_limit",
        expected_response_committed=False,
        expected_engine_event="MSCONN_EVENT_BODY_LIMIT",
        expected_host_action_event="MSCONN_EVENT_BODY_LIMIT",
        expected_rule_id=None,
        expected_actual_action="deny",
        expected_transport_result="http_status",
        expected_backend_requests=0,
    ),
    RealBackendCase(
        name="p3_deny",
        request=http_request("GET", "/p3.txt"),
        rules=(
            'SecRule RESPONSE_HEADERS:Content-Type "@contains text/plain" '
            '"id:9821003,phase:3,deny,status:422,log"',
        ),
        engine_request_limit=65536,
        engine_request_limit_action="Reject",
        engine_response_limit=65536,
        engine_response_limit_action="Reject",
        phase4_mode="strict",
        expected_status=422,
        expected_body=b"",
        expected_phase_sequence=("P1", "P2", "P3"),
        expected_engine_decision="block",
        expected_contract_action="deny",
        expected_error_class="none",
        expected_response_committed=False,
        expected_engine_event="MSCONN_EVENT_ENGINE_DECISION",
        expected_host_action_event="MSCONN_EVENT_RESPONSE_BLOCKED",
        expected_rule_id="9821003",
        expected_actual_action="deny",
        expected_transport_result="http_status",
        expected_backend_requests=1,
    ),
    RealBackendCase(
        name="p4_safe_rate_limit",
        request=http_request("GET", "/p4.txt"),
        rules=(
            'SecRule RESPONSE_BODY "@contains stock-p4-marker" '
            '"id:9821004,phase:4,deny,status:429,log"',
        ),
        engine_request_limit=65536,
        engine_request_limit_action="Reject",
        engine_response_limit=65536,
        engine_response_limit_action="Reject",
        phase4_mode="safe",
        expected_status=200,
        expected_body=b"stock-p4-marker",
        expected_phase_sequence=("P1", "P2", "P3", "P4"),
        expected_engine_decision="rate_limit",
        expected_contract_action="rate_limit",
        expected_error_class="none",
        expected_response_committed=True,
        expected_engine_event="MSCONN_EVENT_ENGINE_DECISION",
        expected_host_action_event="MSCONN_EVENT_PHASE4_LATE_INTERVENTION",
        expected_rule_id="9821004",
        expected_actual_action="log_only",
        expected_transport_result="log_only",
        expected_backend_requests=1,
    ),
)


def required(name: str) -> Path:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} is required")
    path = Path(value)
    if not path.is_absolute() or not path.exists():
        raise RuntimeError(f"{name} must name an existing absolute path")
    return path


def required_new_path(name: str) -> Path:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} is required")
    path = Path(value)
    if not path.is_absolute():
        raise RuntimeError(f"{name} must name an absolute path")
    return path


def verify_artifact_path_chain(path: Path, label: str) -> None:
    """Reject aliases and writable ancestry before trusting an evidence artifact.

    A sticky shared temporary directory is an operating-system namespace boundary,
    not an artifact directory: a non-writable, caller-owned child beneath it can
    still be safely addressed. Same-UID replacement after this check remains an
    explicit limitation of the operator-attestation trust boundary.
    """
    if not path.is_absolute():
        raise RuntimeError(f"{label} must name an absolute artifact path")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise RuntimeError(f"cannot resolve {label}") from error
    if resolved != path:
        raise RuntimeError(f"Stock lighttpd {label} path chain is not trusted")
    current = path
    while True:
        try:
            info = current.lstat()
        except OSError as error:
            raise RuntimeError(f"cannot inspect {label}") from error
        mode = stat.S_IMODE(info.st_mode)
        shared_sticky_directory = stat.S_ISDIR(info.st_mode) and \
            bool(info.st_mode & stat.S_ISVTX) and bool(mode & 0o022)
        if stat.S_ISLNK(info.st_mode) or (
                not shared_sticky_directory and (
                    info.st_uid not in {0, os.getuid()} or mode & 0o022)):
            raise RuntimeError(f"Stock lighttpd {label} path chain is not trusted")
        if current == current.parent:
            return
        current = current.parent


def private_directory(path: Path, label: str) -> None:
    verify_artifact_path_chain(path, label)
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise RuntimeError(f"{label} must be an owner-private directory")


def repository_revision() -> tuple[str, str]:
    completed = subprocess.run(
        ["git", "-C", str(REPOSITORY_ROOT), "rev-parse", "HEAD"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        timeout=5.0,
    )
    value = completed.stdout.strip()
    if completed.returncode != 0 or _COMMIT_SHA.fullmatch(value) is None:
        raise RuntimeError("cannot determine the exact Parent commit")
    dirty = subprocess.run(
        ["git", "-C", str(REPOSITORY_ROOT), "diff", "--quiet", "HEAD", "--"],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=5.0,
    )
    if dirty.returncode not in {0, 1}:
        raise RuntimeError("cannot determine the Parent source-tree state")
    return value, "dirty" if dirty.returncode else "clean"


def file_sha256(path: Path, label: str) -> str:
    verify_artifact_path_chain(path, label)
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise RuntimeError(f"{label} must be a regular non-symlink file")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(64 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def verify_artifact_digest(path: Path, label: str, expected_digest: str) -> None:
    if _SHA256_HEX.fullmatch(expected_digest) is None:
        raise RuntimeError(f"Stock lighttpd {label} has an invalid expected digest")
    if file_sha256(path, label) != expected_digest:
        raise RuntimeError(f"Stock lighttpd {label} changed after artifact admission")


def metadata_values(path: Path, label: str) -> dict[str, str]:
    try:
        info = path.lstat()
    except OSError as error:
        raise RuntimeError(f"cannot read {label}") from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or \
            info.st_size > 16 * 1024 or stat.S_IMODE(info.st_mode) & 0o022:
        raise RuntimeError(f"{label} must be a bounded non-writable regular file")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise RuntimeError(f"cannot read {label}") from error
    values: dict[str, str] = {}
    for line in lines:
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or _METADATA_KEY.fullmatch(key) is None or not value or key in values:
            raise RuntimeError(f"{label} is malformed")
        values[key] = value
    return values


def expected_stock_lighttpd_contract() -> dict[str, str]:
    values = metadata_values(
        REPOSITORY_ROOT / "connectors/lighttpd/lighttpd-version.contract",
        "Stock lighttpd version contract",
    )
    required_keys = (
        "LIGHTTPD_VERSION",
        "LIGHTTPD_SOURCE_URL",
        "LIGHTTPD_DOWNLOAD_URL",
        "LIGHTTPD_SHA256",
    )
    if any(key not in values for key in required_keys) or \
            re.fullmatch(r"\d+\.\d+\.\d+", values["LIGHTTPD_VERSION"]) is None or \
            _SHA256_HEX.fullmatch(values["LIGHTTPD_SHA256"]) is None:
        raise RuntimeError("Stock lighttpd version contract is invalid")
    return values


def verify_stock_host_provenance(binary: Path, module_dir: Path,
                                 binary_digest: str) -> dict[str, str]:
    contract = expected_stock_lighttpd_contract()
    build_root = binary.parent.parent
    if binary.parent.name != "bin" or module_dir != build_root / "lib":
        raise RuntimeError("Stock lighttpd inputs must use one staged build root")
    verify_artifact_path_chain(binary, "STOCK_LIGHTTPD_BIN")
    verify_artifact_path_chain(module_dir, "STOCK_LIGHTTPD_MODULE_DIR")
    binary_info = binary.lstat()
    module_info = module_dir.lstat()
    modules = {
        "stock_lighttpd_mod_accesslog_sha256": module_dir / "mod_accesslog.so",
    }
    if stat.S_ISLNK(binary_info.st_mode) or not stat.S_ISREG(binary_info.st_mode) or \
            stat.S_IMODE(binary_info.st_mode) & 0o022 or \
            stat.S_ISLNK(module_info.st_mode) or not stat.S_ISDIR(module_info.st_mode) or \
            stat.S_IMODE(module_info.st_mode) & 0o022:
        raise RuntimeError("Stock lighttpd module directory is not a verified staged module root")
    module_digests: dict[str, str] = {}
    for key, module in modules.items():
        try:
            module_info = module.lstat()
        except OSError as error:
            raise RuntimeError("Stock lighttpd loaded module is not a verified staged artifact") from error
        if stat.S_ISLNK(module_info.st_mode) or not stat.S_ISREG(module_info.st_mode) or \
                stat.S_IMODE(module_info.st_mode) & 0o022:
            raise RuntimeError("Stock lighttpd loaded module is not a verified staged artifact")
        module_digests[key] = file_sha256(module, "Stock lighttpd loaded module")
    binary_manifest_path = build_root / ".lighttpd-binary.provenance"
    verify_artifact_path_chain(binary_manifest_path, "Stock lighttpd binary provenance")
    binary_manifest = metadata_values(binary_manifest_path, "Stock lighttpd binary provenance")
    source_manifest = metadata_values(
        build_root / "src" / f"lighttpd-{contract['LIGHTTPD_VERSION']}" /
        ".lighttpd-source-provenance",
        "Stock lighttpd source provenance",
    )
    expected = {
        "lighttpd_version": contract["LIGHTTPD_VERSION"],
        "lighttpd_source_sha256": contract["LIGHTTPD_SHA256"],
        "lighttpd_binary_sha256": binary_digest,
    }
    if any(binary_manifest.get(key) != value for key, value in expected.items()) or \
            source_manifest.get("lighttpd_version") != contract["LIGHTTPD_VERSION"] or \
            source_manifest.get("lighttpd_source_url") != contract["LIGHTTPD_SOURCE_URL"] or \
            source_manifest.get("lighttpd_download_url") != contract["LIGHTTPD_DOWNLOAD_URL"] or \
            source_manifest.get("lighttpd_sha256") != contract["LIGHTTPD_SHA256"]:
        raise RuntimeError("Stock lighttpd provenance does not match the selected contract")
    return {
        **contract,
        "stock_lighttpd_binary_sha256": binary_digest,
        "stock_lighttpd_staticfile_linkage": _STOCK_STATICFILE_LINKAGE,
        **module_digests,
    }


def verify_stock_staticfile_linkage(binary: Path) -> None:
    verify_artifact_path_chain(binary, "STOCK_LIGHTTPD_BIN")
    try:
        completed = subprocess.run(
            ["nm", "-D", "--defined-only", str(binary)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5.0,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError("cannot inspect Stock lighttpd staticfile linkage") from error
    symbols = {line.split()[-1] for line in (completed.stdout or "").splitlines() if line.split()}
    if completed.returncode != 0 or _STOCK_STATICFILE_PLUGIN_INIT not in symbols:
        raise RuntimeError("Stock lighttpd staticfile linkage is not builtin")


def verify_stock_launch_artifacts(binary: Path, module_dir: Path,
                                  host: dict[str, str]) -> None:
    verify_artifact_path_chain(module_dir, "STOCK_LIGHTTPD_MODULE_DIR")
    verify_artifact_digest(
        binary, "STOCK_LIGHTTPD_BIN", host["stock_lighttpd_binary_sha256"]
    )
    verify_artifact_digest(
        module_dir / "mod_accesslog.so", "Stock lighttpd loaded module",
        host["stock_lighttpd_mod_accesslog_sha256"],
    )
    verify_stock_staticfile_linkage(binary)


def verify_product_sidecar_manifest(binary: Path, binary_digest: str,
                                    parent_commit: str, source_tree_state: str) -> dict[str, str]:
    manifest = binary.parent / "stock-sidecar-artifact.manifest"
    verify_artifact_path_chain(manifest, "Stock lighttpd Sidecar artifact manifest")
    values = metadata_values(manifest, "Stock lighttpd Sidecar artifact manifest")
    expected = {
        "schema_version": "2",
        "artifact_kind": "lighttpd_stock_sidecar",
        "connector_id": "lighttpd",
        "integration_mode": _EVENT_INTEGRATION_MODE,
        "parent_commit_sha": parent_commit,
        "parent_source_tree_state": source_tree_state,
        "c_standard": "c17",
        "sidecar_path": str(binary),
        "sidecar_binary_sha256": binary_digest,
    }
    required_keys = set(expected) | {
        "sidecar_source_inputs_sha256",
        "modsecurity_library_sha256",
    }
    if set(values) != required_keys or any(values.get(key) != value for key, value in expected.items()):
        raise RuntimeError("Stock lighttpd Sidecar artifact manifest is inconsistent")
    for key in ("sidecar_source_inputs_sha256", "modsecurity_library_sha256"):
        if _SHA256_HEX.fullmatch(values[key]) is None:
            raise RuntimeError("Stock lighttpd Sidecar artifact manifest has an invalid digest")
    return values


def verify_sidecar_build_manifest(binary: Path, binary_digest: str,
                                  parent_commit: str, source_tree_state: str,
                                  *, test_manifest: Path | None = None) -> dict[str, str]:
    """Bind separately owned product and Framework test artifacts before runtime."""
    product = verify_product_sidecar_manifest(binary, binary_digest, parent_commit, source_tree_state)
    manifest = test_manifest or required("STOCK_SIDECAR_TEST_MANIFEST")
    verify_artifact_path_chain(manifest, "Stock lighttpd Framework test artifact manifest")
    values = metadata_values(manifest, "Stock lighttpd Framework test artifact manifest")
    expected = {
        **product,
        "schema_version": "1",
        "artifact_kind": "lighttpd_stock_sidecar_test_artifacts",
        "framework_revision": framework_revision(),
        "product_manifest_sha256": file_sha256(binary.parent / "stock-sidecar-artifact.manifest",
                                               "Stock lighttpd Sidecar artifact manifest"),
        "runtime_begin_smoke_source_sha256": file_sha256(
            source_path("connectors/lighttpd/stock_sidecar/runtime_begin_smoke.c"),
            "Stock lighttpd runtime begin smoke source"),
    }
    if set(values) != set(expected) | {"runtime_begin_smoke_path", "runtime_begin_smoke_sha256"} or \
            any(values.get(key) != value for key, value in expected.items()):
        raise RuntimeError("Stock lighttpd Framework test artifact manifest is inconsistent")
    smoke = Path(values["runtime_begin_smoke_path"])
    if smoke != manifest.parent / "runtime-begin-smoke" or \
            _SHA256_HEX.fullmatch(values["runtime_begin_smoke_sha256"]) is None or \
            file_sha256(smoke, "Stock lighttpd runtime begin smoke") != values["runtime_begin_smoke_sha256"]:
        raise RuntimeError("Stock lighttpd Sidecar smoke artifact is inconsistent")
    return values


def verify_stock_artifact_attestation(path: Path, host: dict[str, str],
                                      sidecar: dict[str, str], parent_commit: str,
                                      source_tree_state: str, stock_binary: Path,
                                      sidecar_binary: Path, runtime_root: Path) -> str:
    verify_artifact_path_chain(path, _ATTESTATION_LABEL)
    try:
        resolved_attestation = path.resolve(strict=True)
        for artifact_root in (stock_binary.parent.parent, sidecar_binary.parent, runtime_root):
            try:
                resolved_attestation.relative_to(artifact_root.resolve(strict=True))
            except ValueError:
                continue
            raise RuntimeError("Stock lighttpd artifact attestation must stay outside artifact roots")
    except OSError as error:
        raise RuntimeError("cannot resolve Stock lighttpd artifact attestation") from error
    values = metadata_values(path, _ATTESTATION_LABEL)
    expected = {
        "schema_version": "1",
        "attestation_kind": "operator_expected_artifact_tuple",
        "connector_id": "lighttpd",
        "integration_mode": _EVENT_INTEGRATION_MODE,
        "parent_commit_sha": parent_commit,
        "parent_source_tree_state": source_tree_state,
        "lighttpd_version": host["LIGHTTPD_VERSION"],
        "lighttpd_source_sha256": host["LIGHTTPD_SHA256"],
        "stock_lighttpd_binary_sha256": host["stock_lighttpd_binary_sha256"],
        "stock_lighttpd_mod_accesslog_sha256": host["stock_lighttpd_mod_accesslog_sha256"],
        "stock_lighttpd_staticfile_linkage": host["stock_lighttpd_staticfile_linkage"],
        "sidecar_binary_sha256": sidecar["sidecar_binary_sha256"],
        "sidecar_source_inputs_sha256": sidecar["sidecar_source_inputs_sha256"],
        "sidecar_modsecurity_library_sha256": sidecar["modsecurity_library_sha256"],
        "sidecar_c_standard": sidecar["c_standard"],
    }
    if set(values) != set(expected) or any(values.get(key) != value for key, value in expected.items()):
        raise RuntimeError("Stock lighttpd artifact attestation does not match the selected artifacts")
    return file_sha256(path, "Stock lighttpd artifact attestation")


def host_version(binary: Path) -> str:
    verify_artifact_path_chain(binary, "STOCK_LIGHTTPD_BIN")
    completed = subprocess.run(
        [str(binary), "-v"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        timeout=5.0,
    )
    match = _LIGHTTPD_VERSION.search(completed.stdout)
    if completed.returncode != 0 or match is None:
        raise RuntimeError("Stock lighttpd did not report a valid version")
    return match.group(1)


def receipt_path(runtime_root: Path) -> Path:
    value = required_new_path("STOCK_SIDECAR_RECEIPT_PATH")
    try:
        value.relative_to(runtime_root)
    except ValueError as error:
        raise RuntimeError("STOCK_SIDECAR_RECEIPT_PATH must stay below STOCK_SIDECAR_RUNTIME_ROOT") from error
    if value.parent != runtime_root or value.suffix != ".json" or value.exists() or value.is_symlink():
        raise RuntimeError("STOCK_SIDECAR_RECEIPT_PATH must be a new JSON file directly below the runtime root")
    return value


def request_body(request: bytes) -> bytes:
    _head, separator, body = request.partition(b"\r\n\r\n")
    if not separator:
        raise RuntimeError("real Stock case request is malformed")
    return body


def expected_snapshot_request_bytes(case: RealBackendCase) -> int:
    # This catalog sets the native engine limit. The sidecar therefore accepts
    # the complete bounded request before libModSecurity returns BODY_LIMIT.
    return len(request_body(case.request))


def receipt_case_path(runtime_root: Path, initial: Path, case: RealBackendCase) -> Path:
    if case.name == "allow_full":
        return initial
    if _CASE_NAME.fullmatch(case.name) is None:
        raise RuntimeError("real Stock case name is invalid")
    value = runtime_root / f"{initial.stem}-{case.name}.runtime-snapshot.json"
    if value.exists() or value.is_symlink() or value.parent != runtime_root:
        raise RuntimeError("Stock lighttpd runtime snapshot path is not new and private")
    return value


def verified_case_path(runtime_root: Path, initial: Path, case: RealBackendCase) -> Path:
    if _CASE_NAME.fullmatch(case.name) is None:
        raise RuntimeError("real Stock case name is invalid")
    value = runtime_root / f"{initial.stem}-{case.name}.verified.json"
    if value.exists() or value.is_symlink() or value.parent != runtime_root:
        raise RuntimeError("Stock lighttpd verified receipt path is not new and private")
    return value


def bounded_nonnegative_integer(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise RuntimeError(f"Stock lighttpd receipt has an invalid {label}")
    return value


def _validate_receipt_identity(value: dict[str, object], binding: str,
                               case: RealBackendCase) -> None:
    expected_binding = hashlib.sha256(binding.encode("ascii")).hexdigest()
    if value.get("connector") != "lighttpd" or \
            value.get("connector_profile") != "lighttpd-stock-sidecar" or \
            value.get("integration_mode") != _RECEIPT_INTEGRATION_MODE:
        raise RuntimeError("Stock lighttpd receipt has an invalid identity")
    if value.get("phase_observation") != "runtime_snapshot_after_cleanup" or \
            value.get("cleanup_status") != "complete" or \
            value.get("cleanup_complete") is not True:
        raise RuntimeError("Stock lighttpd receipt does not prove completed cleanup")
    if value.get("receipt_binding_sha256") != expected_binding or \
            not isinstance(value.get("transaction_id_sha256"), str) or \
            _SHA256_HEX.fullmatch(value["transaction_id_sha256"]) is None:
        raise RuntimeError("Stock lighttpd receipt is not bound to this sidecar run")
    if value.get("transport_version") != "HTTP/1.1" or \
            value.get("payloads_persisted") is not False or \
            value.get("opaque_handles_persisted") is not False:
        raise RuntimeError("Stock lighttpd receipt has invalid transport or payload state")
    if "transaction_id" in value:
        raise RuntimeError("Stock lighttpd receipt persisted a raw transaction identifier")
    if value.get("observed_phase_sequence") != list(case.expected_phase_sequence):
        raise RuntimeError("Stock lighttpd receipt has an unexpected phase sequence")


def _validate_receipt_body_and_decision(value: dict[str, object], case: RealBackendCase) -> None:
    allowed_body_fields = {
        "request_body_bytes", "request_body_truncated", "response_body_bytes",
        "response_body_truncated", "response_body_finished",
    }
    if any("body" in key.lower() and key not in allowed_body_fields for key in value):
        raise RuntimeError("Stock lighttpd receipt contains an unexpected body field")
    if bounded_nonnegative_integer(value.get("request_body_bytes"), "request body count") != \
            expected_snapshot_request_bytes(case) or \
            bounded_nonnegative_integer(value.get("response_body_bytes"), "response body count") != \
            len(case.expected_body):
        raise RuntimeError("Stock lighttpd receipt body counters disagree with the observed case")
    if value.get("engine_decision") != case.expected_engine_decision or \
            value.get("response_committed") is not case.expected_response_committed:
        raise RuntimeError("Stock lighttpd receipt decision state disagrees with the observed case")


def _validate_receipt_schema(value: dict[str, object], case: RealBackendCase) -> None:
    if value.get("schema_version") == 1:
        if case.expected_engine_decision != "allow" or value.get("actual_host_action") != "allow" or \
                value.get("visible_http_status") != case.expected_status or \
                value.get("response_committed") is not True:
            raise RuntimeError("Stock lighttpd allow receipt is inconsistent")
        return
    if value.get("schema_version") != 2:
        raise RuntimeError("Stock lighttpd receipt has an unsupported schema")
    if value.get("receipt_kind") != "non_allow" or \
            value.get("contract_action") != case.expected_contract_action or \
            value.get("error_class") != case.expected_error_class or \
            value.get("mode") != case.phase4_mode or \
            value.get("last_completed_phase") != case.expected_phase_sequence[-1] or \
            "actual_host_action" in value or "rule_id" in value:
        raise RuntimeError("Stock lighttpd non-allow receipt is inconsistent")
    response_headers_processed = "P3" in case.expected_phase_sequence
    response_headers_sent = "P4" in case.expected_phase_sequence
    response_body_finished = "P4" in case.expected_phase_sequence
    if value.get("response_headers_processed") is not response_headers_processed or \
            value.get("response_headers_sent") is not response_headers_sent or \
            value.get("response_body_finished") is not response_body_finished:
        raise RuntimeError("Stock lighttpd receipt response progress is inconsistent")
    created_at = bounded_nonnegative_integer(value.get("created_at_ms"), "created timestamp")
    completed_at = bounded_nonnegative_integer(value.get("completed_at_ms"), "completed timestamp")
    cleanup_at = bounded_nonnegative_integer(value.get("cleanup_at_ms"), "cleanup timestamp")
    if not created_at <= completed_at <= cleanup_at:
        raise RuntimeError("Stock lighttpd receipt timestamps are not monotonic")


def read_sidecar_receipt(path: Path, binding: str, case: RealBackendCase) -> dict[str, object]:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
        raise RuntimeError("Stock lighttpd receipt must be an owner-private regular file")
    if info.st_uid != os.getuid() or info.st_size > _MAX_RECEIPT_BYTES:
        raise RuntimeError("Stock lighttpd receipt exceeds the metadata limit")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError("cannot read Stock lighttpd runtime receipt") from error
    if not isinstance(value, dict):
        raise RuntimeError("Stock lighttpd runtime receipt is not an object")
    _validate_receipt_identity(value, binding, case)
    _validate_receipt_body_and_decision(value, case)
    _validate_receipt_schema(value, case)
    return value


def wait_for_sidecar_receipt(path: Path, binding: str, case: RealBackendCase) -> dict[str, object]:
    deadline = time.monotonic() + 3.0
    last_error: RuntimeError | None = None
    while time.monotonic() < deadline:
        if path.exists() and not path.is_symlink():
            try:
                return read_sidecar_receipt(path, binding, case)
            except RuntimeError as error:
                last_error = error
        time.sleep(0.02)
    if last_error is not None:
        raise last_error
    raise RuntimeError("Stock lighttpd runtime snapshot was not published")


def backend_request_count(path: Path) -> int:
    if not path.exists():
        return 0
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or \
            info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022 or \
            info.st_size > _MAX_EVENT_FILE_BYTES:
        raise RuntimeError("Stock lighttpd backend access log is not a bounded private file")
    try:
        return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line)
    except OSError as error:
        raise RuntimeError("cannot read Stock lighttpd backend access log") from error


def wait_for_backend_requests(path: Path, expected: int) -> None:
    deadline = time.monotonic() + _BACKEND_ACCESS_LOG_WAIT_SECONDS
    while time.monotonic() < deadline:
        count = backend_request_count(path)
        if count == expected:
            return
        if count > expected:
            raise RuntimeError("Stock lighttpd backend received an unexpected request")
        time.sleep(0.02)
    raise RuntimeError("Stock lighttpd backend did not receive the expected request count")


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    record: dict[str, object] = {}
    for key, value in pairs:
        if key in record:
            raise json.JSONDecodeError(f"duplicate JSON event key: {key}", key, 0)
        record[key] = value
    return record


def _reject_json_constant(value: str) -> None:
    raise json.JSONDecodeError(f"invalid JSON constant: {value}", value, 0)


def _event_string(record: dict[str, object], key: str, *, optional: bool = False) -> str | None:
    value = record.get(key)
    if value is None and optional:
        return None
    if not isinstance(value, str):
        raise RuntimeError(f"Stock lighttpd event has an invalid {key}")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeError as error:
        raise RuntimeError(f"Stock lighttpd event has an invalid {key}") from error
    if "\0" in value:
        raise RuntimeError(f"Stock lighttpd event has an invalid {key}")
    if len(encoded) > _EVENT_MAX_STRING_BYTES:
        raise RuntimeError(f"Stock lighttpd event has an oversized {key}")
    return value


def _event_integer(record: dict[str, object], key: str, maximum: int) -> int:
    value = record.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > maximum:
        raise RuntimeError(f"Stock lighttpd event has an invalid {key}")
    return value


def _validate_event_keys(record: dict[str, object]) -> None:
    allowed_body_fields = {
        "body_bytes_seen",
        "body_bytes_inspected",
        "body_truncated",
        "body_limit_outcome",
        "body_started",
    }
    if any("body" in key.lower() and key not in allowed_body_fields for key in record):
        raise RuntimeError("Stock lighttpd event contains an unexpected body field")
    unknown = set(record).difference(_EVENT_ALLOWED_KEYS)
    if unknown:
        raise RuntimeError("Stock lighttpd event contains an unknown field")
    missing = (set(_EVENT_REQUIRED_STRING_KEYS) | set(_EVENT_REQUIRED_BOOL_KEYS) |
               set(_EVENT_REQUIRED_INT_KEYS)).difference(record)
    if missing:
        raise RuntimeError("Stock lighttpd event is missing a required field")


def _validate_event_string_fields(record: dict[str, object]) -> None:
    for key in _EVENT_REQUIRED_STRING_KEYS:
        _event_string(record, key)
    for key in _EVENT_OPTIONAL_STRING_KEYS:
        _event_string(record, key, optional=True)


def _validate_event_boolean_fields(record: dict[str, object]) -> None:
    for key in _EVENT_REQUIRED_BOOL_KEYS:
        if not isinstance(record[key], bool):
            raise RuntimeError(f"Stock lighttpd event has an invalid {key}")
    for key in _EVENT_OPTIONAL_BOOL_KEYS:
        if key in record and not isinstance(record[key], bool):
            raise RuntimeError(f"Stock lighttpd event has an invalid {key}")


def _validate_event_integer_fields(record: dict[str, object]) -> None:
    for key in ("http_status", "original_http_status", "visible_http_status"):
        _event_integer(record, key, 599)
    for key in ("body_bytes_seen", "body_bytes_inspected", "previous_event_hash", "event_hash"):
        _event_integer(record, key, _FNV_MASK)
    _event_integer(record, "sequence", _FNV_MASK)


def _validate_event_enums(record: dict[str, object]) -> None:
    allowed_values = (
        ("phase", _EVENT_PHASE_VALUES),
        ("status", _EVENT_STATUS_VALUES),
        ("action", _EVENT_ACTION_VALUES),
        ("requested_action", _EVENT_ACTION_VALUES),
        ("transport_result", _EVENT_TRANSPORT_RESULTS),
    )
    if any(record[key] not in values for key, values in allowed_values):
        raise RuntimeError("Stock lighttpd event has an invalid Common enum")
    if record["actual_action"] == "":
        engine = record["message_id"] == "MSCONN_EVENT_ENGINE_DECISION" and \
            record["event"] == "engine_decision" and record["status"] == "blocked" and \
            record["action"] == record["requested_action"] and \
            record["requested_action"] in {"deny", "redirect", "drop", "rate_limit",
                                           "abort_connection", "stream_reset"}
        policy = record["message_id"] == "MSCONN_EVENT_BODY_LIMIT" and \
            record["event"] == "body_limit" and \
            record["status"] == "blocked" and record["action"] == "deny" and \
            record["requested_action"] == "deny" and record["rule_id"] == ""
        error = _UNOBSERVED_ERROR_EVENTS.get(record["message_id"])
        technical = error is not None and record["event"] == error and \
            record["status"] == "error" and record["action"] == "error" and \
            record["requested_action"] == "error" and record["rule_id"] == ""
        if record["transport_result"] not in {"", "not_observable"} or \
                not (engine or technical or policy):
            raise RuntimeError("Stock lighttpd event has an invalid unobserved action")
    elif record["actual_action"] not in _EVENT_ACTION_VALUES:
        raise RuntimeError("Stock lighttpd event has an invalid Common enum")


def _validate_event_schema(record: dict[str, object]) -> None:
    _validate_event_keys(record)
    _validate_event_string_fields(record)
    _validate_event_boolean_fields(record)
    _validate_event_integer_fields(record)
    _validate_event_enums(record)


def _fnv_continue(value: int, data: bytes) -> int:
    for byte in data:
        value ^= byte
        value = (value * _FNV_PRIME) & _FNV_MASK
    return value


def _hash_event_string(value: int, text: str | None) -> int:
    return _fnv_continue(value, b"\0" if text is None else text.encode("utf-8") + b"\0")


def _safe_connection_id_for_event_hash(record: dict[str, object]) -> str | None:
    value = _event_string(record, "connection_id", optional=True)
    if value is None:
        return None
    quic = record.get("negotiated_protocol") == "h3" or \
        record.get("downstream_protocol") == "h3" or record.get("transport") == "quic_udp"
    if not quic:
        return value
    digest = value.removeprefix("sha256:")
    if not value.startswith("sha256:") or not 16 <= len(digest) <= 64 or \
            re.fullmatch(r"[0-9a-f]+", digest) is None:
        return None
    return value


def _bounded_transport_case_id_for_event_hash(record: dict[str, object]) -> str | None:
    value = _event_string(record, "transport_case_id", optional=True)
    if value is None or re.fullmatch(r"[A-Za-z0-9:._-]{1,128}", value) is None:
        return None
    return value


def event_integrity_hash(record: dict[str, object], previous_hash: int) -> int:
    """Mirror the Common FNV event projection for local, same-host evidence only."""
    value = _fnv_continue(_FNV_OFFSET, struct.pack("@Q", previous_hash))
    for key in (
        "timestamp", "level", "message_id", "message", "event", "connector",
        "integration_mode", "run_id",
    ):
        value = _hash_event_string(value, _event_string(record, key, optional=key == "run_id"))
    value = _hash_event_string(value, _bounded_transport_case_id_for_event_hash(record))
    value = _hash_event_string(value, _event_string(record, "transaction_id"))
    value = _fnv_continue(value, struct.pack("@i", _EVENT_PHASE_VALUES[str(record["phase"])]))
    value = _fnv_continue(value, struct.pack("@i", _EVENT_STATUS_VALUES[str(record["status"])]))
    for key in ("action", "requested_action", "actual_action", "rule_id", "reason"):
        value = _hash_event_string(value, _event_string(record, key))
    for key in ("http_status", "original_http_status", "visible_http_status"):
        value = _fnv_continue(value, struct.pack("@i", _event_integer(record, key, 599)))
    for key in ("transport_result", "http_reason_phrase", "http_default_message"):
        value = _hash_event_string(value, _event_string(record, key))
    for key in (
        "requested_protocol", "downstream_protocol", "upstream_protocol", "negotiated_protocol",
        "transport", "alpn", "stream_id",
    ):
        value = _hash_event_string(value, _event_string(record, key, optional=True))
    value = _hash_event_string(value, _safe_connection_id_for_event_hash(record))
    for key in ("quic_version", "stream_reset_code", "reset_by", "reset_code"):
        value = _hash_event_string(value, _event_string(record, key, optional=True))
    for key in ("connection_reused", "quic_connection_id_present", "fallback_used", "stream_reset"):
        value = _fnv_continue(value, struct.pack("@i", int(bool(record.get(key, False)))))
    for key in ("method", "uri", "client_ip", "content_type", "body_limit_outcome"):
        value = _hash_event_string(value, _event_string(record, key, optional=key == "body_limit_outcome"))
    for key in ("body_bytes_seen", "body_bytes_inspected"):
        value = _fnv_continue(value, struct.pack("@Q", _event_integer(record, key, _FNV_MASK)))
    value = _fnv_continue(value, struct.pack("@i", int(bool(record["late_intervention"]))))
    value = _hash_event_string(
        value, _event_string(record, "late_intervention_mode", optional=True)
    )
    for key in (
        "response_started", "response_committed", "headers_sent",
        "body_started", "body_truncated", "connection_aborted", "client_disconnected",
        "upstream_disconnected", "cancelled", "eos_seen", "redacted", "truncated",
    ):
        value = _fnv_continue(value, struct.pack("@i", int(bool(record[key]))))
    for key in ("timeout_stage", "write_result", "cleanup_reason"):
        value = _hash_event_string(value, _event_string(record, key, optional=True))
    return value


def verify_event_chain(records: list[dict[str, object]]) -> None:
    previous_hash = 0
    for expected_sequence, record in enumerate(records, start=1):
        if record["sequence"] != expected_sequence:
            raise RuntimeError("Stock lighttpd event sequence is not contiguous")
        if record["previous_event_hash"] != previous_hash:
            raise RuntimeError("Stock lighttpd event hash chain is discontinuous")
        event_hash = event_integrity_hash(record, previous_hash)
        if record["event_hash"] != event_hash:
            raise RuntimeError("Stock lighttpd event hash is invalid")
        previous_hash = event_hash


def event_records(path: Path) -> tuple[str, list[dict[str, object]]]:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or \
            info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022 or \
            info.st_size > _MAX_EVENT_FILE_BYTES:
        raise RuntimeError("Stock lighttpd event log is not a bounded private file")
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as error:
        raise RuntimeError("cannot read Stock lighttpd event log") from error
    records: list[dict[str, object]] = []
    for line in raw.splitlines():
        if not line or line != line.strip():
            raise RuntimeError("Stock lighttpd event log contains a non-canonical record")
        if len(line.encode("utf-8")) > _MAX_RECEIPT_BYTES:
            raise RuntimeError("Stock lighttpd event exceeds its configured bound")
        try:
            record = json.loads(line, object_pairs_hook=_reject_duplicate_json_keys,
                                parse_constant=_reject_json_constant)
        except json.JSONDecodeError as error:
            raise RuntimeError("Stock lighttpd event log is malformed") from error
        if not isinstance(record, dict):
            raise RuntimeError("Stock lighttpd event is not an object")
        _validate_event_schema(record)
        records.append(record)
    verify_event_chain(records)
    return raw, records


def _event_payload_free(raw: str, case: RealBackendCase) -> None:
    body = request_body(case.request)
    if body and body.decode("ascii") in raw:
        raise RuntimeError("Stock lighttpd event persisted request-body data")
    if case.expected_body and case.expected_body.decode("ascii") in raw:
        raise RuntimeError("Stock lighttpd event persisted response-body data")
    if "body_payload" in raw:
        raise RuntimeError("Stock lighttpd event persisted a body payload field")


def _event_matches_identity(record: dict[str, object], case: RealBackendCase) -> bool:
    return record.get("connector") == "lighttpd" and \
        record.get("integration_mode") == _EVENT_INTEGRATION_MODE and \
        record.get("phase") == _EVENT_CONTRACT_PHASE_NAMES[case.expected_phase_sequence[-1]] and \
        (case.expected_rule_id is None or record.get("rule_id") == case.expected_rule_id)


def _is_engine_event_candidate(record: dict[str, object], case: RealBackendCase) -> bool:
    event_name = "body_limit" if case.expected_engine_event == \
        "MSCONN_EVENT_BODY_LIMIT" else "engine_decision"
    return record.get("message_id") == case.expected_engine_event and \
        _event_matches_identity(record, case) and \
        all(record.get(key) == value for key, value in _ENGINE_EVENT_EXPECTED_FIELDS.items()) and \
        record.get("event") == event_name and \
        record.get("transport_result") in {"", "not_observable"} and \
        record.get("visible_http_status") == record.get("original_http_status") and \
        record.get("response_committed") is case.expected_response_committed and \
        record.get("late_intervention") is False


def _event_candidates(records: list[dict[str, object]], case: RealBackendCase) -> tuple[
        dict[str, object], dict[str, object]] | None:
    engine_candidates = [record for record in records if _is_engine_event_candidate(record, case)]
    host_action_candidates = [
        record for record in records
        if record.get("message_id") == case.expected_host_action_event and
        _event_matches_identity(record, case) and
        record.get("actual_action") == case.expected_actual_action and
        record.get("transport_result") == case.expected_transport_result and
        record.get("visible_http_status") == case.expected_status and
        record.get("response_committed") is case.expected_response_committed
    ]
    if len(engine_candidates) > 1:
        raise RuntimeError("Stock lighttpd emitted duplicate engine-decision events")
    if len(host_action_candidates) > 1:
        raise RuntimeError("Stock lighttpd emitted duplicate host-action events")
    if len(engine_candidates) != 1 or len(host_action_candidates) != 1:
        return None
    return engine_candidates[0], host_action_candidates[0]


def _validate_event_pair_correlation(records: list[dict[str, object]], engine_event: dict[str, object],
                                     event: dict[str, object], receipt: dict[str, object]) -> None:
    if len(records) != 2:
        raise RuntimeError("Stock lighttpd event log does not contain exactly one engine-host action pair")
    if engine_event["sequence"] >= event["sequence"]:
        raise RuntimeError("Stock lighttpd engine event must precede its host action")
    if event.get("transaction_id") != engine_event.get("transaction_id"):
        raise RuntimeError("Stock lighttpd engine and host-action events are not correlated")
    transaction_id = event.get("transaction_id")
    if not isinstance(transaction_id, str) or \
            hashlib.sha256(transaction_id.encode("utf-8")).hexdigest() != \
            receipt.get("transaction_id_sha256"):
        raise RuntimeError("Stock lighttpd host-action event is not correlated to its snapshot")


def _validate_event_action_metadata(engine_event: dict[str, object], event: dict[str, object],
                                    case: RealBackendCase) -> None:
    if case.expected_rule_id is None:
        if event.get("rule_id") != "" or engine_event.get("rule_id") != "":
            raise RuntimeError("Stock lighttpd body-limit event has an unexpected rule identifier")
    elif event.get("requested_action") != "deny":
        raise RuntimeError("Stock lighttpd rule event has an unexpected requested action")
    if case.expected_phase_sequence[-1] == "P4":
        if event.get("late_intervention") is not True or \
                event.get("late_intervention_mode") != case.phase4_mode:
            raise RuntimeError("Stock lighttpd P4 event is missing late-intervention metadata")
    elif event.get("late_intervention") is not False:
        raise RuntimeError("Stock lighttpd pre-commit event is incorrectly marked late")


def _project_host_action_event(event: dict[str, object], case: RealBackendCase) -> dict[str, object]:
    return {
        "actual_host_action": event["actual_action"],
        "transport_result": event["transport_result"],
        "original_http_status": event.get("original_http_status"),
        "rule_id": case.expected_rule_id,
    }


def _host_action_event_from_records(records: list[dict[str, object]], case: RealBackendCase,
                                    receipt: dict[str, object]) -> dict[str, object] | None:
    candidates = _event_candidates(records, case)
    if candidates is None:
        return None
    engine_event, event = candidates
    _validate_event_pair_correlation(records, engine_event, event, receipt)
    _validate_event_action_metadata(engine_event, event, case)
    return _project_host_action_event(event, case)


def _validate_no_event_case(path: Path, case: RealBackendCase) -> dict[str, object]:
    if path.exists() and not path.is_symlink():
        raw, records = event_records(path)
        _event_payload_free(raw, case)
        if records:
            raise RuntimeError("Stock lighttpd allow case emitted an unexpected event")
    return {}


def _wait_for_host_action_event(path: Path, case: RealBackendCase,
                                receipt: dict[str, object]) -> dict[str, object]:
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        if path.exists() and not path.is_symlink():
            raw, records = event_records(path)
            _event_payload_free(raw, case)
            result = _host_action_event_from_records(records, case, receipt)
            if result is not None:
                return result
        time.sleep(0.02)
    raise RuntimeError("Stock lighttpd host-action event was not observed")


def select_host_action_event(path: Path, case: RealBackendCase,
                             receipt: dict[str, object]) -> dict[str, object]:
    if case.expected_engine_event is None and case.expected_host_action_event is None:
        return _validate_no_event_case(path, case)
    if case.expected_engine_event is None or case.expected_host_action_event is None:
        raise RuntimeError("Stock lighttpd case has incomplete event expectations")
    return _wait_for_host_action_event(path, case, receipt)


def publish_verified_receipt(path: Path, value: dict[str, object]) -> None:
    encoded = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(encoded) > _MAX_RECEIPT_BYTES:
        raise RuntimeError("Stock lighttpd verified receipt exceeds its metadata bound")
    descriptor = -1
    created = False
    published = False
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        descriptor = os.open(path, flags, 0o600)
        created = True
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(encoded):
            written = os.write(descriptor, encoded[offset:])
            if written <= 0:
                raise OSError("short verified receipt write")
            offset += written
        os.fsync(descriptor)
        published = True
    except OSError as error:
        raise RuntimeError("cannot publish Stock lighttpd verified receipt") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if created and not published:
            try:
                path.unlink()
            except OSError:
                pass
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or \
            info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise RuntimeError("Stock lighttpd verified receipt is not owner-private")


def write_case_runtime_inputs(case_root: Path, case: RealBackendCase) -> tuple[Path, Path, Path]:
    rules_path = case_root / "rules.conf"
    events_path = case_root / "events.jsonl"
    config_path = case_root / "runtime.conf"
    rules_path.write_text(
        "\n".join((
            "SecRuleEngine On",
            "SecRequestBodyAccess On",
            f"SecRequestBodyLimit {case.engine_request_limit}",
            f"SecRequestBodyNoFilesLimit {case.engine_request_limit}",
            f"SecRequestBodyLimitAction {case.engine_request_limit_action}",
            "SecResponseBodyAccess On",
            "SecResponseBodyMimeType text/plain",
            f"SecResponseBodyLimit {case.engine_response_limit}",
            f"SecResponseBodyLimitAction {case.engine_response_limit_action}",
            *case.rules,
            "",
        )),
        encoding="utf-8",
    )
    rules_path.chmod(0o600)
    config_path.write_text(
        "\n".join((
            "enabled=on",
            f"rules_file={rules_path}",
            "transaction_id_header=x-request-id",
            "request_body_mode=streaming",
            "response_body_mode=streaming",
            f"phase4_mode={case.phase4_mode}",
            "default_block_status=403",
            "default_error_status=502",
            "max_header_count=64",
            "max_header_name_size=256",
            "max_header_value_size=8192",
            "max_total_header_bytes=65536",
            "max_event_json_bytes=16384",
            f"event_path={events_path}",
            "",
        )),
        encoding="utf-8",
    )
    config_path.chmod(0o600)
    return rules_path, events_path, config_path


def stop(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def write_observation(path: Path, value: dict[str, object]) -> None:
    # All callers use the newly created, service-owned private attempt directory.
    with path.open("x", encoding="utf-8") as output:
        path.chmod(0o600)
        json.dump(value, output, sort_keys=True)
        output.write("\n")


@contextmanager
def retained_attempt(runtime_root: Path):
    private_directory(runtime_root, "STOCK_SIDECAR_RUNTIME_ROOT")
    root = Path(tempfile.mkdtemp(prefix="stock-real-h1-", dir=runtime_root))
    root.chmod(0o700)
    started = time.time_ns()
    outcome = "completed"
    try:
        yield root
    except BaseException:
        outcome = "failed"
        raise
    finally:
        artifacts = []
        for path in sorted(root.rglob("*")):
            info = path.lstat()
            if stat.S_ISREG(info.st_mode):
                path.chmod(0o600)
                artifacts.append({"path": str(path.relative_to(root)),
                                  "sha256": file_sha256(path, "retained runtime artifact"),
                                  "bytes": info.st_size})
        write_observation(root / "attempt.json", {
            "started_unix_ns": started, "finished_unix_ns": time.time_ns(),
            "outcome": outcome, "artifacts": artifacts,
            "raw_artifacts_retained": True,
            "raw_http_fixture_payloads_retained": True,
        })


def stop_with_receipt(process: subprocess.Popen[bytes], port: int, path: Path) -> None:
    try:
        stop(process)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CleanupFailure("Stock lighttpd child could not be reaped") from error
    listener_connected = None
    listener_probe_error = None
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
            listener_connected = True
    except ConnectionRefusedError:
        listener_connected = False
    except OSError as error:
        listener_probe_error = type(error).__name__
    listener_closed = listener_connected is False
    write_observation(path, {"pid": process.pid, "wait_returncode": process.returncode,
                             "process_reaped": process.returncode is not None,
                             "listener_closed_observed": listener_closed,
                             "listener_connected_observed": listener_connected,
                             "listener_probe_error": listener_probe_error,
                             "observed_unix_ns": time.time_ns()})
    if not listener_closed or process.returncode is None:
        raise CleanupFailure("Stock lighttpd child cleanup could not be established")


def launch_logged(argv: list[str], root: Path, label: str,
                  *, env: dict[str, str] | None = None) -> subprocess.Popen[bytes]:
    process = None
    try:
        with (root / f"{label}-stdout.log").open("xb") as stdout, \
                (root / f"{label}-stderr.log").open("xb") as stderr:
            process = subprocess.Popen(argv, stdout=stdout, stderr=stderr, env=env)
        write_observation(root / f"{label}-launch.json", {
            "argv": argv, "cwd": str(Path.cwd()), "pid": process.pid,
            "uid": os.geteuid(), "gid": os.getegid(), "started_unix_ns": time.time_ns(),
        })
    except BaseException:
        if process is not None:
            try:
                stop(process)
            except (OSError, subprocess.TimeoutExpired) as error:
                raise CleanupFailure("Stock lighttpd launch failure child could not be reaped") from error
        raise
    return process


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def wait_ready(port: int, process: subprocess.Popen[bytes], label: str) -> None:
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"{label} exited before its listener became ready")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"{label} listener did not become ready")


def validate_client_descriptors(request_descriptor: int, response_descriptor: int) -> None:
    if request_descriptor < 3 or response_descriptor < 3 or request_descriptor == response_descriptor:
        raise RuntimeError("Stock lighttpd client requires distinct inherited artifact descriptors")
    identities = []
    for descriptor in (request_descriptor, response_descriptor):
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or \
                stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
            raise RuntimeError("Stock lighttpd client artifact descriptor is not owner-private")
        identities.append((info.st_dev, info.st_ino))
    if identities[0] == identities[1] or os.fstat(response_descriptor).st_size != 0:
        raise RuntimeError("Stock lighttpd client requires distinct fresh output")
    if fcntl.fcntl(request_descriptor, fcntl.F_GETFL) & os.O_ACCMODE == os.O_WRONLY or \
            fcntl.fcntl(response_descriptor, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY:
        raise RuntimeError("Stock lighttpd client artifact descriptor access is invalid")


def client_exchange(port: int, request_descriptor: int, response_descriptor: int) -> None:
    validate_client_descriptors(request_descriptor, response_descriptor)
    with os.fdopen(request_descriptor, "rb", closefd=False) as source:
        request = source.read()
    response = bytearray()
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5.0) as client:
            client.sendall(request)
            while True:
                chunk = client.recv(4096)
                if not chunk:
                    break
                if len(response) > _MAX_CLIENT_RESPONSE_BYTES - len(chunk):
                    raise RuntimeError("Stock lighttpd client response exceeds its bounded catalog limit")
                response.extend(chunk)
    finally:
        with os.fdopen(response_descriptor, "wb", closefd=False) as output:
            output.write(response)


@contextmanager
def client_artifacts(evidence_root: Path, request: bytes):
    with open_private_runtime_root(evidence_root) as root, ExitStack() as artifacts:
        streams = {}
        for name in (_CLIENT_REQUEST_ARTIFACT, "response.http", "stdout.log", "stderr.log"):
            descriptor = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                 0o600, dir_fd=root.descriptor)
            stream = artifacts.enter_context(os.fdopen(descriptor, "w+b"))
            os.fchmod(stream.fileno(), 0o600)
            if name == _CLIENT_REQUEST_ARTIFACT:
                stream.write(request)
                stream.flush()
                stream.seek(0)
            streams[name] = stream
        yield streams[_CLIENT_REQUEST_ARTIFACT], streams["response.http"], streams["stdout.log"], streams["stderr.log"]


def run_client(argv: list[str], descriptors: tuple[int, int], stdout, stderr) -> tuple[int, bool]:
    timed_out = False
    with subprocess.Popen(argv, stdout=stdout, stderr=stderr, pass_fds=descriptors) as process:
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            process.wait(timeout=5)
        return process.returncode, timed_out


def client_framing(raw: bytes, returncode: int):
    head, separator, body = raw.partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n", 1)[0].split()
    observed_status = int(status_line[1]) if separator and len(status_line) >= 2 and \
        status_line[1].isdigit() else None
    lengths = [line.partition(b":")[2].strip() for line in head.split(b"\r\n")[1:]
               if line.partition(b":")[0].lower() == b"content-length"]
    content_length = int(lengths[0]) if len(lengths) == 1 and lengths[0].isdigit() else None
    transfer_encoding = any(line.partition(b":")[0].lower() == b"transfer-encoding"
                            for line in head.split(b"\r\n")[1:])
    framing_complete = bool(separator) and not transfer_encoding and \
        (len(body) == content_length if lengths else returncode == 0)
    return head, separator, body, status_line, observed_status, content_length, transfer_encoding, framing_complete


def exchange(port: int, request: bytes, evidence_root: Path) -> tuple[int, bytes]:
    evidence_root.mkdir(mode=0o700)
    started = time.time_ns()
    with client_artifacts(evidence_root, request) as (source, response, stdout, stderr):
        descriptors = source.fileno(), response.fileno()
        argv = [sys.executable, str(Path(__file__).resolve()), "--client-exchange",
                str(port), *(str(descriptor) for descriptor in descriptors)]
        returncode, timed_out = run_client(argv, descriptors, stdout, stderr)
        response.seek(0)
        raw = response.read(_MAX_CLIENT_RESPONSE_BYTES + 1)
    head, separator, body, status_line, observed_status, content_length, transfer_encoding, framing_complete = \
        client_framing(raw, returncode)
    write_observation(evidence_root / "client.json", {
        "argv": argv, "cwd": str(Path.cwd()), "started_unix_ns": started,
        "finished_unix_ns": time.time_ns(), "wait_returncode": returncode,
        "signal": -returncode if returncode < 0 else None, "timed_out": timed_out,
        "http_status": observed_status, "response_bytes": len(raw),
        "body_bytes": len(body) if separator else None,
        "body_sha256": hashlib.sha256(body).hexdigest() if separator else None,
        "headers_sha256": hashlib.sha256(head).hexdigest() if separator else None,
        "content_length": content_length, "framing_complete": framing_complete,
    })
    if returncode != 0 or timed_out:
        raise RuntimeError("Stock lighttpd client exchange failed; retained its actual exit and bytes")
    if not separator:
        raise RuntimeError("sidecar returned no complete HTTP response")
    if len(status_line) < 2 or not status_line[1].isdigit():
        raise RuntimeError("sidecar returned an invalid HTTP status line")
    if transfer_encoding:
        raise RuntimeError("Stock lighttpd client framing requires an unsupported transfer decoder")
    if not framing_complete:
        raise CaseObservationError("Stock lighttpd client received incomplete or invalid response framing")
    return int(status_line[1]), body


class CleanupFailure(RuntimeError):
    """Prevent another case from starting while a previous child may survive."""


class CaseObservationError(RuntimeError):
    """An observed result disagrees with the fixed catalog contract."""


def follow_up_health(case: RealBackendCase, sidecar_port: int, case_root: Path,
                     backend_access_log: Path, baseline_backend_requests: int) -> str:
    if case.name != "p4_safe_rate_limit":
        return "not_run"
    status, body = exchange(sidecar_port, http_request("GET", _HEALTH_PATH),
                            case_root / "follow-up-client")
    if status != 200 or body != b"stock-backend-health":
        raise RuntimeError("Stock lighttpd did not remain healthy after P4 Safe")
    wait_for_backend_requests(
        backend_access_log, baseline_backend_requests + case.expected_backend_requests + 1
    )
    return "passed"


def run_case(*, runtime_root: Path, initial_receipt: Path, temporary_root: Path,
             sidecar_binary: Path, sidecar_binary_digest: str, backend_port: int,
             backend_access_log: Path,
             case: RealBackendCase, metadata: dict[str, object]) -> dict[str, object]:
    case_root = temporary_root / "cases" / case.name
    case_root.mkdir(parents=True)
    case_root.chmod(0o700)
    _rules_path, events_path, runtime_config = write_case_runtime_inputs(case_root, case)
    snapshot_path = receipt_case_path(runtime_root, initial_receipt, case)
    verified_path = verified_case_path(runtime_root, initial_receipt, case)
    receipt_binding = secrets.token_hex(32)
    sidecar_port = free_port()
    baseline_backend_requests = backend_request_count(backend_access_log)
    verify_artifact_digest(
        sidecar_binary, "MSCONNECTOR_STOCK_SIDECAR_BINARY", sidecar_binary_digest
    )
    sidecar = launch_logged(
        [str(sidecar_binary), "--config", str(runtime_config),
         "--listen", f"127.0.0.1:{sidecar_port}",
         "--upstream", f"127.0.0.1:{backend_port}", "--timeout-ms", "3000",
         "--spool-directory", str(case_root)],
        case_root, "sidecar",
        env={
            **os.environ,
            "STOCK_SIDECAR_RECEIPT_PATH": str(snapshot_path),
            "STOCK_SIDECAR_RECEIPT_BINDING": receipt_binding,
        },
    )
    try:
        wait_ready(sidecar_port, sidecar, "Stock lighttpd sidecar")
        status, body = exchange(sidecar_port, case.request, case_root / "client")
        if status != case.expected_status or body != case.expected_body:
            raise CaseObservationError("Stock lighttpd client result disagrees with its fixed catalog case")
        wait_for_backend_requests(
            backend_access_log, baseline_backend_requests + case.expected_backend_requests
        )
        observed_backend_requests = backend_request_count(backend_access_log) - baseline_backend_requests
        write_observation(case_root / "backend.json", {
            "baseline": baseline_backend_requests, "requests_observed": observed_backend_requests,
            "access_log": str(backend_access_log), "observed_unix_ns": time.time_ns(),
        })
        snapshot = wait_for_sidecar_receipt(snapshot_path, receipt_binding, case)
        event = select_host_action_event(events_path, case, snapshot)
        if case.expected_host_action_event is None:
            actual_action = snapshot.get("actual_host_action")
            transport_result = "completed"
            original_status = snapshot.get("original_http_status")
            rule_id: str | None = None
        else:
            actual_action = event["actual_host_action"]
            transport_result = event["transport_result"]
            original_status = event["original_http_status"]
            rule_id = event["rule_id"]
        if actual_action != case.expected_actual_action or \
                not isinstance(original_status, int) or isinstance(original_status, bool) or \
                not 0 <= original_status <= 599:
            raise RuntimeError("Stock lighttpd receipt projection is not internally consistent")
        health = follow_up_health(case, sidecar_port, case_root, backend_access_log,
                                  baseline_backend_requests)
        if sidecar.poll() is not None:
            raise RuntimeError("Stock lighttpd sidecar stopped during an active catalog case")
        verified = {
            "schema_version": 1,
            "receipt_kind": "verified_real_host_client_outcome",
            "connector": "lighttpd",
            "connector_profile": "lighttpd-stock-sidecar",
            "integration_mode": _RECEIPT_INTEGRATION_MODE,
            "transport_version": "HTTP/1.1",
            "test_case": case.name,
            "evidence_scope": ["real_host", "real_client"],
            "parent_commit_sha": metadata["parent_commit_sha"],
            "parent_source_tree_state": metadata["parent_source_tree_state"],
            "host_name": "lighttpd",
            "host_version": metadata["host_version"],
            "stock_lighttpd_source_sha256": metadata["stock_lighttpd_source_sha256"],
            "stock_lighttpd_sha256": metadata["stock_lighttpd_sha256"],
            "stock_lighttpd_mod_accesslog_sha256": metadata[
                "stock_lighttpd_mod_accesslog_sha256"
            ],
            "stock_lighttpd_staticfile_linkage": metadata[
                "stock_lighttpd_staticfile_linkage"
            ],
            "sidecar_binary_sha256": metadata["sidecar_binary_sha256"],
            "sidecar_source_inputs_sha256": metadata["sidecar_source_inputs_sha256"],
            "sidecar_modsecurity_library_sha256": metadata[
                "sidecar_modsecurity_library_sha256"
            ],
            "artifact_attestation_sha256": metadata["artifact_attestation_sha256"],
            "source_runtime_snapshot_sha256": file_sha256(snapshot_path, "Stock lighttpd runtime snapshot"),
            "source_runtime_snapshot_schema_version": snapshot["schema_version"],
            "transaction_id_sha256": snapshot["transaction_id_sha256"],
            "observed_phase_sequence": snapshot["observed_phase_sequence"],
            "p2_eos_count": int("P2" in case.expected_phase_sequence),
            "p4_eos_count": int("P4" in case.expected_phase_sequence),
            "request_body_bytes": snapshot["request_body_bytes"],
            "response_body_bytes": snapshot["response_body_bytes"],
            "engine_decision": snapshot["engine_decision"],
            "contract_action": snapshot.get("contract_action", "allow"),
            "actual_host_action": actual_action,
            "rule_id": rule_id,
            "original_http_status": original_status,
            "visible_http_status": status,
            "response_committed": snapshot["response_committed"],
            "transport_result": transport_result,
            "cleanup_status": snapshot["cleanup_status"],
            "cleanup_complete": snapshot["cleanup_complete"],
            "backend_requests_observed": observed_backend_requests,
            "process_healthy": True,
            "follow_up_health": health,
            "payloads_persisted": False,
            "opaque_handles_persisted": False,
        }
        outcome = {
            "case": case.name,
            "status": status,
            "phase_sequence": snapshot["observed_phase_sequence"],
            "actual_host_action": actual_action,
            "verified_receipt": verified_path,
        }
    finally:
        cleanup_error = None
        try:
            stop_with_receipt(sidecar, sidecar_port, case_root / "process-cleanup.json")
        except CleanupFailure as error:
            cleanup_error = error
        try:
            # Preserve independent backend evidence even if client/schema checks fail.
            observed = backend_request_count(backend_access_log) - baseline_backend_requests \
                if backend_access_log.exists() else None
            write_observation(case_root / "backend-final.json", {
                "baseline": baseline_backend_requests, "requests_observed": observed,
                "access_log": str(backend_access_log), "observed_unix_ns": time.time_ns(),
                "access_log_sha256": file_sha256(backend_access_log, "backend access log")
                if backend_access_log.exists() else None,
                "missing_evidence_reason": None if backend_access_log.exists() else "backend access log absent",
            })
        finally:
            if cleanup_error is not None:
                raise cleanup_error
    publish_verified_receipt(verified_path, verified)
    return outcome


def run_catalog(**inputs) -> list[dict[str, object]]:
    outcomes: list[dict[str, object]] = []
    for case in REAL_BACKEND_CASES:
        try:
            outcome = {**run_case(case=case, **inputs), "result": "PASS"}
        except CleanupFailure:
            raise
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
            outcome = {"case": case.name,
                       "result": "FAIL" if isinstance(error, CaseObservationError) else "BLOCKED",
                       "error": str(error), "error_class": type(error).__name__}
        case_root = inputs["temporary_root"] / "cases" / case.name
        case_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        write_observation(case_root / "outcome.json", {
            key: str(value) if isinstance(value, Path) else value
            for key, value in outcome.items()
        })
        outcomes.append(outcome)
    return outcomes


def main() -> int:
    stock_binary = required("STOCK_LIGHTTPD_BIN")
    module_dir = required("STOCK_LIGHTTPD_MODULE_DIR")
    sidecar_binary = required("MSCONNECTOR_STOCK_SIDECAR_BINARY")
    runtime_root = required("STOCK_SIDECAR_RUNTIME_ROOT")
    private_directory(runtime_root, "STOCK_SIDECAR_RUNTIME_ROOT")
    receipt = receipt_path(runtime_root)
    if not module_dir.is_dir():
        raise RuntimeError("STOCK_LIGHTTPD_MODULE_DIR must be a directory")
    stock_binary_digest = file_sha256(stock_binary, "STOCK_LIGHTTPD_BIN")
    host_contract = verify_stock_host_provenance(
        stock_binary, module_dir, stock_binary_digest
    )
    commit, source_tree_state = repository_revision()
    sidecar_binary_digest = file_sha256(sidecar_binary, "MSCONNECTOR_STOCK_SIDECAR_BINARY")
    sidecar_manifest = verify_sidecar_build_manifest(
        sidecar_binary, sidecar_binary_digest, commit, source_tree_state
    )
    artifact_attestation = required("STOCK_SIDECAR_ARTIFACT_ATTESTATION")
    artifact_attestation_digest = verify_stock_artifact_attestation(
        artifact_attestation, host_contract, sidecar_manifest, commit, source_tree_state,
        stock_binary, sidecar_binary, runtime_root,
    )
    verify_stock_staticfile_linkage(stock_binary)
    stock_version = host_version(stock_binary)
    if stock_version != host_contract["LIGHTTPD_VERSION"]:
        raise RuntimeError("Stock lighttpd version does not match its selected contract")
    with retained_attempt(runtime_root) as root:
        docroot = root / "htdocs"
        docroot.mkdir()
        (docroot / "health.txt").write_bytes(b"stock-backend-health")
        (docroot / "empty.txt").write_bytes(b"")
        (docroot / "p3.txt").write_bytes(b"stock-p3-marker")
        (docroot / "p4.txt").write_bytes(b"stock-p4-marker")
        backend_port = free_port()
        backend_config = root / "lighttpd.conf"
        backend_access_log = root / "backend-access.log"
        backend_config.write_text(
            "\n".join((
                'server.modules = ( "mod_accesslog", "mod_staticfile" )',
                f'server.document-root = "{docroot}"',
                'server.bind = "127.0.0.1"',
                f"server.port = {backend_port}",
                f'server.errorlog = "{root / "backend-error.log"}"',
                f'accesslog.filename = "{backend_access_log}"',
                f'server.pid-file = "{root / "backend.pid"}"',
                f'server.upload-dirs = ( "{root / "uploads"}" )',
                "",
            )),
            encoding="utf-8",
        )
        (root / "uploads").mkdir()
        verify_stock_launch_artifacts(stock_binary, module_dir, host_contract)
        verify_artifact_digest(
            artifact_attestation, _ATTESTATION_LABEL,
            artifact_attestation_digest,
        )
        backend = launch_logged(
            [str(stock_binary), "-D", "-m", str(module_dir), "-f", str(backend_config)],
            root, "backend",
        )
        try:
            wait_ready(backend_port, backend, "unchanged Stock lighttpd backend")
            metadata: dict[str, object] = {
                "parent_commit_sha": commit,
                "parent_source_tree_state": source_tree_state,
                "host_version": stock_version,
                "stock_lighttpd_source_sha256": host_contract["LIGHTTPD_SHA256"],
                "stock_lighttpd_sha256": stock_binary_digest,
                "stock_lighttpd_mod_accesslog_sha256": host_contract[
                    "stock_lighttpd_mod_accesslog_sha256"
                ],
                "stock_lighttpd_staticfile_linkage": host_contract[
                    "stock_lighttpd_staticfile_linkage"
                ],
                "sidecar_binary_sha256": sidecar_binary_digest,
                "sidecar_source_inputs_sha256": sidecar_manifest[
                    "sidecar_source_inputs_sha256"
                ],
                "sidecar_modsecurity_library_sha256": sidecar_manifest[
                    "modsecurity_library_sha256"
                ],
                "artifact_attestation_sha256": artifact_attestation_digest,
            }
            outcomes = run_catalog(
                runtime_root=runtime_root,
                initial_receipt=receipt,
                temporary_root=root,
                sidecar_binary=sidecar_binary,
                sidecar_binary_digest=sidecar_binary_digest,
                backend_port=backend_port,
                backend_access_log=backend_access_log,
                metadata=metadata,
            )
            write_observation(root / "catalog-summary.json", {
                "cases_attempted": len(outcomes),
                "counts": {result: sum(o["result"] == result for o in outcomes)
                           for result in ("PASS", "FAIL", "BLOCKED")},
                "evidence_scope": "bounded_real_backend_catalog",
            })
        finally:
            stop_with_receipt(backend, backend_port, root / "backend-cleanup.json")
    for outcome in outcomes:
        if outcome["result"] != "PASS":
            print(f"lighttpd_stock_sidecar_real_backend: {outcome['result']} "
                  f"case={outcome['case']} error={outcome['error']}", file=sys.stderr)
            continue
        print(
            "lighttpd_stock_sidecar_real_backend: PASS "
            f"case={outcome['case']} status={outcome['status']} "
            f"phases={','.join(outcome['phase_sequence'])} "
            f"actual_action={outcome['actual_host_action']} traffic_owner=sidecar "
            f"backend=unchanged-stock-lighttpd receipt={outcome['verified_receipt']}"
        )
    if any(outcome["result"] == "FAIL" for outcome in outcomes):
        return 1
    return 77 if any(outcome["result"] != "PASS" for outcome in outcomes) else 0


if __name__ == "__main__":
    try:
        if len(sys.argv) == 5 and sys.argv[1] == "--client-exchange":
            client_exchange(int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]))
            raise SystemExit(0)
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"lighttpd_stock_sidecar_real_backend: BLOCKED: {error}", file=sys.stderr)
        raise SystemExit(77)
