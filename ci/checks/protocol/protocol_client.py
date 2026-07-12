#!/usr/bin/env python3
"""Run a forced, payload-free HTTP protocol probe with curl.

The runtime harnesses use this helper for the *client -> connector* half of
the protocol matrix.  It deliberately does not try to infer evidence which
curl cannot expose (notably HTTP/2 and HTTP/3 stream identifiers).  Callers
can provide those bounded observations through a small JSON sidecar.

Every invocation writes the following files atomically to ``--artifact-dir``:

* ``client-version.txt``
* ``client-features.txt``
* ``client-command.txt``
* ``client-protocol-observation.json``

The response body is always sent to the platform null device.  The JSON
artifact contains only bounded outcome and provenance values; neither response
headers, response payload, raw curl stderr, nor raw QUIC connection IDs are
persisted.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field, replace
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
from typing import Any, Callable, Iterable, Mapping, Sequence
from urllib.parse import urlsplit, urlunsplit


CANONICAL_PROTOCOLS = frozenset({"http1", "h2", "h2c", "h3"})
CANONICAL_TRANSPORTS = frozenset({"tcp", "tls_tcp", "quic_udp"})
OBSERVATION_STATUSES = frozenset(
    {"PASS", "FAIL", "BLOCKED", "NOT_EXECUTED", "UNSUPPORTED_BY_HOST"}
)

_CURL_JSON_MIN_VERSION = (7, 70, 0)
_MAX_ARTIFACT_TEXT_BYTES = 64 * 1024
_MAX_SIDECAR_BYTES = 64 * 1024
_BOUNDED_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
_BOUNDED_TEXT = re.compile(r"^[^\x00-\x1f\x7f]{1,256}$")
_SHA256_TOKEN = re.compile(r"^sha256:[0-9a-f]{64}$")
_HTTP_FIELD_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_VERSION_RE = re.compile(r"\bcurl\s+(\d+)\.(\d+)(?:\.(\d+))?\b", re.IGNORECASE)
_OPTION_RE = re.compile(r"(?<![A-Za-z0-9_-])(--[A-Za-z0-9][A-Za-z0-9.-]*)")


class ProtocolClientError(ValueError):
    """Raised for invalid protocol-client input or unsafe sidecar content."""


@dataclass(frozen=True)
class CurlInspection:
    """Feature and option information obtained without making an HTTP request."""

    executable: str
    version_text: str
    version: tuple[int, int, int] | None
    features: frozenset[str]
    options: frozenset[str]
    version_returncode: int | None
    help_returncode: int | None
    error: str | None = None


@dataclass(frozen=True)
class Preflight:
    """Result of checking the curl build against one forced protocol profile."""

    status: str
    reason: str | None
    required_features: tuple[str, ...]
    required_options: tuple[str, ...]
    missing_features: tuple[str, ...]
    missing_options: tuple[str, ...]
    writeout_mode: str


@dataclass(frozen=True)
class ClientConfig:
    """Configuration accepted by :func:`run_protocol_client`."""

    url: str
    protocol: str = "http1"
    artifact_dir: Path = Path(".")
    curl: str = "curl"
    timeout: float = 30.0
    connect_timeout: float | None = None
    insecure: bool = False
    request: str = "GET"
    headers: tuple[str, ...] = ()
    data_file: Path | None = None
    cacert: Path | None = None
    resolve: tuple[str, ...] = ()
    connector: str | None = None
    integration_mode: str | None = None
    run_id: str | None = None
    transaction_id: str | None = None
    transport_case_id: str | None = None
    rule_id: str | None = None
    phase: str | None = None
    stream_id: int | None = None
    upstream_protocol: str | None = None
    quic_udp_observed: bool = False
    observation_sidecar: Path | None = None
    followup_url: str | None = None
    followup_protocol: str | None = None


@dataclass(frozen=True)
class ClientRunResult:
    """Payload-free output produced by :func:`run_protocol_client`."""

    observation: dict[str, Any]
    inspection: CurlInspection
    preflight: Preflight
    command: tuple[str, ...] = field(default_factory=tuple)


_PROTOCOL_REQUIREMENTS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "http1": ((), ("--http1.1",)),
    "h2": (("HTTP2",), ("--http2",)),
    "h2c": (("HTTP2",), ("--http2-prior-knowledge",)),
    # Intentionally do not use --http3: it can fall back to H2/H1.
    "h3": (("HTTP3",), ("--http3-only",)),
}

_COMMON_CURL_OPTIONS = (
    "--fail-with-body",
    "--max-time",
    "--output",
    "--request",
    "--show-error",
    "--silent",
    "--write-out",
)

_SIDECAR_KEYS = frozenset(
    {
        "stream_id",
        "connection_reused",
        "quic_udp_observed",
        "quic_connection_id_present",
        "quic_version",
        "alpn",
        "stream_reset",
        "stream_reset_code",
    }
)
_RAW_CONNECTION_ID_KEYS = frozenset(
    {
        "cid",
        "connection_id",
        "quic_cid",
        "quic_connection_id",
    }
)


def _run_process(
    command: Sequence[str], *, timeout: float | None = None
) -> subprocess.CompletedProcess[str]:
    """Run a command without a shell and keep output in memory only."""

    return subprocess.run(
        list(command),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )


def _truncate_text(value: str, limit: int = _MAX_ARTIFACT_TEXT_BYTES) -> str:
    encoded = value.encode("utf-8", errors="replace")
    if len(encoded) <= limit:
        return value
    clipped = encoded[:limit].decode("utf-8", errors="ignore")
    return clipped + "\n[truncated]\n"


def _parse_version(version_text: str) -> tuple[int, int, int] | None:
    match = _VERSION_RE.search(version_text)
    if not match:
        return None
    return (int(match.group(1)), int(match.group(2)), int(match.group(3) or 0))


def _parse_features(version_text: str) -> frozenset[str]:
    for line in version_text.splitlines():
        if line.lower().startswith("features:"):
            return frozenset(part.upper() for part in line.split(":", 1)[1].split())
    return frozenset()


def _parse_options(help_text: str) -> frozenset[str]:
    return frozenset(match.group(1).lower() for match in _OPTION_RE.finditer(help_text))


def inspect_curl(curl: str = "curl") -> CurlInspection:
    """Inspect curl's version, feature list, and documented long options.

    A missing executable is represented as a normal inspection result so a
    caller can still write all required artifacts and report ``BLOCKED``.
    """

    try:
        version_result = _run_process((curl, "--version"), timeout=10)
    except (FileNotFoundError, PermissionError, OSError):
        return CurlInspection(
            executable=curl,
            version_text="curl executable unavailable\n",
            version=None,
            features=frozenset(),
            options=frozenset(),
            version_returncode=None,
            help_returncode=None,
            error="curl_executable_unavailable",
        )
    except subprocess.TimeoutExpired:
        return CurlInspection(
            executable=curl,
            version_text="curl version probe timed out\n",
            version=None,
            features=frozenset(),
            options=frozenset(),
            version_returncode=None,
            help_returncode=None,
            error="curl_version_probe_timeout",
        )

    version_text = _truncate_text(version_result.stdout)
    if version_result.returncode != 0:
        return CurlInspection(
            executable=curl,
            version_text=version_text or "curl --version failed\n",
            version=_parse_version(version_text),
            features=_parse_features(version_text),
            options=frozenset(),
            version_returncode=version_result.returncode,
            help_returncode=None,
            error="curl_version_probe_failed",
        )

    try:
        help_result = _run_process((curl, "--help", "all"), timeout=10)
    except (FileNotFoundError, PermissionError, OSError):
        return CurlInspection(
            executable=curl,
            version_text=version_text,
            version=_parse_version(version_text),
            features=_parse_features(version_text),
            options=frozenset(),
            version_returncode=version_result.returncode,
            help_returncode=None,
            error="curl_help_probe_unavailable",
        )
    except subprocess.TimeoutExpired:
        return CurlInspection(
            executable=curl,
            version_text=version_text,
            version=_parse_version(version_text),
            features=_parse_features(version_text),
            options=frozenset(),
            version_returncode=version_result.returncode,
            help_returncode=None,
            error="curl_help_probe_timeout",
        )

    if help_result.returncode != 0:
        return CurlInspection(
            executable=curl,
            version_text=version_text,
            version=_parse_version(version_text),
            features=_parse_features(version_text),
            options=frozenset(),
            version_returncode=version_result.returncode,
            help_returncode=help_result.returncode,
            error="curl_help_probe_failed",
        )

    return CurlInspection(
        executable=curl,
        version_text=version_text,
        version=_parse_version(version_text),
        features=_parse_features(version_text),
        options=_parse_options(help_result.stdout),
        version_returncode=version_result.returncode,
        help_returncode=help_result.returncode,
    )


def _optional_curl_options(config: ClientConfig) -> tuple[str, ...]:
    required: list[str] = []
    if config.connect_timeout is not None:
        required.append("--connect-timeout")
    if config.insecure:
        required.append("--insecure")
    if config.data_file is not None:
        required.append("--data-binary")
    if config.cacert is not None:
        required.append("--cacert")
    if config.resolve:
        required.append("--resolve")
    if config.headers or config.transport_case_id is not None:
        required.append("--header")
    return tuple(required)


def preflight_curl(protocol: str, inspection: CurlInspection, config: ClientConfig | None = None) -> Preflight:
    """Check feature and option support before a protocol request is made."""

    normalized = normalize_protocol(protocol)
    feature_requirements, profile_options = _PROTOCOL_REQUIREMENTS[normalized]
    required_options = tuple(
        sorted(set(_COMMON_CURL_OPTIONS + profile_options + (_optional_curl_options(config) if config else ())))
    )
    required_features = tuple(sorted(feature_requirements))

    if inspection.error is not None:
        return Preflight(
            status="BLOCKED",
            reason=inspection.error,
            required_features=required_features,
            required_options=required_options,
            missing_features=required_features,
            missing_options=required_options,
            writeout_mode="none",
        )

    missing_features = tuple(
        feature for feature in required_features if feature.upper() not in inspection.features
    )
    missing_options = tuple(
        option for option in required_options if option.lower() not in inspection.options
    )
    if missing_features:
        # This is specifically what distinguishes a client without HTTP/3
        # support from an otherwise usable client talking to an unsupported
        # host.  Do not attempt the request in that case.
        reason = (
            "client_http3_unsupported"
            if normalized == "h3" and "HTTP3" in missing_features
            else "client_required_feature_unavailable"
        )
        status = "BLOCKED"
    elif missing_options:
        reason = "client_required_option_unavailable"
        status = "BLOCKED"
    else:
        reason = None
        status = "READY"

    writeout_mode = (
        "json"
        if inspection.version is not None and inspection.version >= _CURL_JSON_MIN_VERSION
        else "fields"
    )
    return Preflight(
        status=status,
        reason=reason,
        required_features=required_features,
        required_options=required_options,
        missing_features=missing_features,
        missing_options=missing_options,
        writeout_mode=writeout_mode,
    )


def normalize_protocol(value: str) -> str:
    protocol = str(value).strip().lower()
    if protocol not in CANONICAL_PROTOCOLS:
        raise ProtocolClientError("protocol must be one of http1, h2, h2c, h3")
    return protocol


def normalize_transport(value: str) -> str:
    transport = str(value).strip().lower()
    if transport not in CANONICAL_TRANSPORTS:
        raise ProtocolClientError("transport must be one of tcp, tls_tcp, quic_udp")
    return transport


def _validate_text_argument(value: str | None, name: str) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not _BOUNDED_TEXT.fullmatch(text):
        raise ProtocolClientError(f"{name} must be bounded printable text")
    return text


def _validate_config(config: ClientConfig) -> tuple[str, str]:
    protocol = normalize_protocol(config.protocol)
    if config.timeout <= 0:
        raise ProtocolClientError("timeout must be greater than zero")
    if config.connect_timeout is not None and config.connect_timeout <= 0:
        raise ProtocolClientError("connect_timeout must be greater than zero")
    if not config.request or any(character in config.request for character in "\r\n\x00"):
        raise ProtocolClientError("request must be a non-empty HTTP method")
    parsed = urlsplit(config.url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ProtocolClientError("url must be an absolute http or https URL")
    if any(character in config.url for character in "\r\n\x00"):
        raise ProtocolClientError("url contains a control character")
    if parsed.fragment:
        raise ProtocolClientError("url must not include a fragment")
    try:
        parsed.port
    except ValueError as exc:
        raise ProtocolClientError("url contains an invalid port") from exc
    if protocol == "h2" and parsed.scheme != "https":
        raise ProtocolClientError("h2 requires an https URL for TLS/ALPN evidence")
    if protocol == "h2c" and parsed.scheme != "http":
        raise ProtocolClientError("h2c requires an http URL")
    if protocol == "h3" and parsed.scheme != "https":
        raise ProtocolClientError("h3 requires an https URL")
    if config.stream_id is not None and (
        isinstance(config.stream_id, bool)
        or not isinstance(config.stream_id, int)
        or config.stream_id < 0
    ):
        raise ProtocolClientError("stream_id must be an integer greater than or equal to zero")
    if config.upstream_protocol is not None:
        normalize_protocol(config.upstream_protocol)
    for name in (
        "connector",
        "integration_mode",
        "run_id",
        "transaction_id",
        "rule_id",
        "phase",
    ):
        _validate_text_argument(getattr(config, name), name)
    if config.transport_case_id is not None and (
        not isinstance(config.transport_case_id, str)
        or not _BOUNDED_TOKEN.fullmatch(config.transport_case_id)
    ):
        raise ProtocolClientError("transport_case_id must be a bounded token")
    if protocol in {"h2", "h2c", "h3"} and not config.transport_case_id:
        raise ProtocolClientError("modern protocol probes require a transport_case_id")
    for header in config.headers:
        if (
            not isinstance(header, str)
            or not header
            or any(character in header for character in "\r\n\x00")
        ):
            raise ProtocolClientError("headers must be single-line strings")
        header_name, separator, _value = header.partition(":")
        header_name = header_name.strip()
        # Curl accepts both ``Header;`` (an explicitly empty header) and
        # ``@file`` forms.  Neither has a bounded, inspectable field name, so
        # allowing either would let a caller inject or suppress the helper's
        # causal header through curl-specific parsing.
        if not separator or not _HTTP_FIELD_NAME.fullmatch(header_name):
            raise ProtocolClientError("headers must use a valid name:value form")
        if header_name.lower() == "x-msconnector-transport-case":
            # The helper owns this causal header.  Accepting a caller-provided
            # duplicate would make first/last/combined-header behavior host
            # dependent and break request-to-event attribution.
            raise ProtocolClientError("transport correlation header is helper-owned")
    return protocol, parsed.scheme


def derive_followup_transport_case_id(primary: str | None) -> str | None:
    """Return a distinct bounded token for the independent health request.

    The token is deterministic only to make connector-side correlation easy;
    it is not an authorization value and is never used as a payload.  A
    secondary form avoids the (vanishingly unlikely) case where a caller chose
    the first derived value as its primary token.
    """

    if primary is None:
        return None
    if not isinstance(primary, str) or not _BOUNDED_TOKEN.fullmatch(primary):
        raise ProtocolClientError("transport_case_id must be a bounded token")
    digest = hashlib.sha256(
        ("msconnector-followup:" + primary).encode("ascii")
    ).hexdigest()[:32]
    candidate = "followup-" + digest
    if candidate == primary:
        candidate = "followup2-" + hashlib.sha256(
            ("msconnector-followup2:" + primary).encode("ascii")
        ).hexdigest()[:31]
    return candidate


def target_authority_sha256(url: str) -> str | None:
    """Return a non-reversible scheme/authority binding for a client probe.

    Paths, query strings, credentials, and response metadata are deliberately
    excluded.  The value lets a strict follow-up prove it targeted the same
    authority without retaining a raw URL in the canonical artifact.
    """

    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        return None
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    if scheme not in {"http", "https"} or not host:
        return None
    if port is None:
        port = 443 if scheme == "https" else 80
    authority = f"{scheme}://{host}:{port}"
    return "sha256:" + hashlib.sha256(authority.encode("utf-8")).hexdigest()


def _load_observation_sidecar(path: Path) -> dict[str, Any]:
    """Load only a narrow, non-payload sidecar vocabulary.

    In particular, raw connection IDs are rejected instead of being ignored:
    silently accepting one makes it too easy for a future caller to persist a
    QUIC CID by accident.
    """

    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ProtocolClientError("observation sidecar is unavailable") from exc
    if len(raw) > _MAX_SIDECAR_BYTES:
        raise ProtocolClientError("observation sidecar exceeds bounded size")
    try:
        loaded = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolClientError("observation sidecar is not valid JSON") from exc
    if not isinstance(loaded, dict):
        raise ProtocolClientError("observation sidecar must be a JSON object")
    keys = set(loaded)
    if keys & _RAW_CONNECTION_ID_KEYS:
        raise ProtocolClientError("raw connection identifiers are not accepted")
    unknown = keys - _SIDECAR_KEYS
    if unknown:
        raise ProtocolClientError("observation sidecar contains unsupported fields")

    result: dict[str, Any] = {}
    if "stream_id" in loaded:
        value = loaded["stream_id"]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ProtocolClientError("sidecar stream_id must be an integer >= 0")
        result["stream_id"] = value
    for key in (
        "connection_reused",
        "quic_udp_observed",
        "quic_connection_id_present",
        "stream_reset",
    ):
        if key in loaded:
            if not isinstance(loaded[key], bool):
                raise ProtocolClientError(f"sidecar {key} must be boolean")
            result[key] = loaded[key]
    if "quic_version" in loaded:
        value = loaded["quic_version"]
        if not isinstance(value, str) or not _BOUNDED_TOKEN.fullmatch(value):
            raise ProtocolClientError("sidecar quic_version must be a bounded token")
        result["quic_version"] = value
    if "alpn" in loaded:
        value = loaded["alpn"]
        if value not in {"h2", "h3"}:
            raise ProtocolClientError("sidecar alpn must be h2 or h3")
        result["alpn"] = value
    if "stream_reset_code" in loaded:
        value = loaded["stream_reset_code"]
        if isinstance(value, bool):
            raise ProtocolClientError("sidecar stream_reset_code must be numeric or bounded token")
        if isinstance(value, int):
            if value < 0:
                raise ProtocolClientError("sidecar stream_reset_code must be non-negative")
        elif not isinstance(value, str) or not _BOUNDED_TOKEN.fullmatch(value):
            raise ProtocolClientError("sidecar stream_reset_code must be numeric or bounded token")
        result["stream_reset_code"] = value
    return result


def _safe_url_for_command(url: str) -> str:
    """Keep a useful target in the command artifact without query credentials."""

    parsed = urlsplit(url)
    host = parsed.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    netloc = host
    if parsed.port is not None:
        netloc = f"{netloc}:{parsed.port}"
    safe_path = parsed.path or "/"
    query = "[redacted]" if parsed.query else ""
    return urlunsplit((parsed.scheme, netloc, safe_path, query, ""))


def _redacted_command(command: Iterable[str], *, url: str) -> str:
    """Render an audit command without request payloads or header values."""

    values = list(command)
    rendered: list[str] = []
    redact_next = False
    for index, value in enumerate(values):
        if redact_next:
            rendered.append("[redacted]")
            redact_next = False
            continue
        if value in {"--header", "--data-binary", "--cacert"}:
            rendered.append(value)
            redact_next = True
            continue
        if value == url:
            rendered.append(_safe_url_for_command(url))
            continue
        # Curl's data option may be written in the --option=value form by a
        # future caller.  Do not let that become a payload artifact.
        if value.startswith("--data") and "=" in value:
            rendered.append(value.split("=", 1)[0] + "=[redacted]")
            continue
        rendered.append(value)
    return shlex.join(rendered) + "\n"


def build_curl_command(config: ClientConfig, preflight: Preflight) -> tuple[str, ...]:
    """Build the locked-down curl command for a forced protocol profile."""

    protocol, _scheme = _validate_config(config)
    if preflight.status != "READY":
        raise ProtocolClientError("cannot build a command before a ready preflight")
    protocol_flag = {
        "http1": "--http1.1",
        "h2": "--http2",
        "h2c": "--http2-prior-knowledge",
        "h3": "--http3-only",
    }[protocol]
    writeout = "%{json}\n" if preflight.writeout_mode == "json" else (
        "PROTOCOL_CLIENT\t%{http_code}\t%{http_version}\t%{size_download}\t%{exitcode}\n"
    )
    command: list[str] = [
        config.curl,
        "--silent",
        "--show-error",
        "--fail-with-body",
        "--output",
        os.devnull,
        "--request",
        config.request,
        "--max-time",
        _format_timeout(config.timeout),
    ]
    if config.connect_timeout is not None:
        command.extend(("--connect-timeout", _format_timeout(config.connect_timeout)))
    if config.insecure:
        command.append("--insecure")
    if config.cacert is not None:
        command.extend(("--cacert", str(config.cacert)))
    for item in config.resolve:
        command.extend(("--resolve", item))
    for header in config.headers:
        command.extend(("--header", header))
    if config.transport_case_id is not None:
        command.extend((
            "--header",
            "X-MSConnector-Transport-Case: " + config.transport_case_id,
        ))
    if config.data_file is not None:
        command.extend(("--data-binary", f"@{config.data_file}"))
    command.extend((protocol_flag, "--write-out", writeout, config.url))
    # Guard the most important invariant close to command construction: no
    # code path can accidentally use curl's fallback-capable --http3 option.
    if protocol == "h3" and "--http3-only" not in command:
        raise ProtocolClientError("h3 command lost its required --http3-only flag")
    if "--http3" in command:
        raise ProtocolClientError("fallback-capable --http3 is forbidden")
    return tuple(command)


def _format_timeout(value: float) -> str:
    return format(float(value), ".6g")


def _parse_number(value: Any) -> float | int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return value if value >= 0 else None
    if isinstance(value, str):
        try:
            parsed = float(value)
        except ValueError:
            return None
        return parsed if parsed >= 0 else None
    return None


def _parse_writeout(stdout: str, mode: str) -> dict[str, Any]:
    """Extract only whitelisted fields from curl output; retain no raw JSON."""

    if mode == "json":
        try:
            payload = json.loads(stdout.strip())
        except json.JSONDecodeError:
            return {}
        if not isinstance(payload, Mapping):
            return {}
        status = payload.get("response_code", payload.get("http_code"))
        version = payload.get("http_version")
        size = payload.get("size_download")
        # %{json} varies by curl version.  Preserve this only when it is
        # actually emitted; do not synthesize a content length from headers.
        length = payload.get(
            "content_length_download",
            payload.get("content_length_download_t"),
        )
        return {
            "http_status": _coerce_status(status),
            "http_version": str(version) if version is not None else None,
            "downloaded_bytes": _parse_number(size),
            "content_length_download": _parse_number(length),
        }

    fields = stdout.strip().split("\t")
    if len(fields) != 5 or fields[0] != "PROTOCOL_CLIENT":
        return {}
    return {
        "http_status": _coerce_status(fields[1]),
        "http_version": fields[2] or None,
        "downloaded_bytes": _parse_number(fields[3]),
        "content_length_download": None,
    }


def _coerce_status(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        status = int(value)
    except (TypeError, ValueError):
        return None
    return status if 100 <= status <= 999 else None


def _negotiated_protocol(http_version: str | None, requested: str, scheme: str) -> str | None:
    if http_version is None:
        return None
    normalized = http_version.strip().lower()
    if normalized in {"1", "1.0", "1.1", "http/1.0", "http/1.1"}:
        return "http1"
    if normalized in {"2", "2.0", "http/2", "http/2.0"}:
        # Curl reports only the HTTP version.  The cleartext profile is known
        # from the forced prior-knowledge request and http scheme.
        return "h2c" if requested == "h2c" and scheme == "http" else "h2"
    if normalized in {"3", "3.0", "http/3", "http/3.0"}:
        return "h3"
    return None


def _classify_transport_error(
    returncode: int | None,
    stderr: str,
    requested_protocol: str,
    http_status: int | None,
) -> str:
    """Map curl outcome to a fixed vocabulary without retaining stderr."""

    if returncode == 0:
        return "none"
    if returncode == 22 and http_status is not None:
        return "http_response_error"
    # curl errors are stable enough for the common transport classes.  Keep
    # wording checks only as a supplemental signal and never export them.
    if returncode == 6:
        return "dns_failure"
    if returncode == 7:
        return "connection_failure"
    if returncode == 18:
        return "transfer_incomplete"
    if returncode == 28:
        return "timeout"
    if returncode in {35, 51, 58, 59, 60, 64, 66, 77, 80, 82, 83, 90, 91}:
        return "tls_failure"
    if returncode in {16, 92}:
        return "h2_failure"
    if returncode in {95, 96}:
        return "h3_failure"
    lower = stderr.lower()
    if "timed out" in lower or "timeout" in lower:
        return "timeout"
    if "certificate" in lower or "ssl" in lower or "tls" in lower:
        return "tls_failure"
    if "quic" in lower or "http/3" in lower or "http3" in lower:
        return "h3_failure" if requested_protocol == "h3" else "protocol_failure"
    if "http/2" in lower or "http2" in lower:
        return "h2_failure" if requested_protocol in {"h2", "h2c"} else "protocol_failure"
    return "client_or_network_failure"


def _expected_transport(protocol: str, scheme: str) -> str:
    if protocol == "h3":
        return "quic_udp"
    if protocol == "h2":
        return "tls_tcp"
    if protocol == "h2c":
        return "tcp"
    return "tls_tcp" if scheme == "https" else "tcp"


def _derive_transport(
    negotiated: str | None,
    requested: str,
    scheme: str,
    sidecar: Mapping[str, Any],
    quic_udp_observed: bool,
) -> str | None:
    if negotiated != requested:
        return None
    if negotiated == "h3":
        # H3's protocol name alone is not a QUIC/UDP traffic observation.
        return "quic_udp" if quic_udp_observed or sidecar.get("quic_udp_observed") is True else None
    return _expected_transport(negotiated, scheme)


def _provenance(config: ClientConfig, sidecar: Mapping[str, Any]) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    for name in (
        "connector",
        "integration_mode",
        "run_id",
        "transaction_id",
        "rule_id",
        "phase",
    ):
        value = _validate_text_argument(getattr(config, name), name)
        if value is not None:
            fields[name] = value
    if config.transport_case_id is not None:
        if not _BOUNDED_TOKEN.fullmatch(config.transport_case_id):
            raise ProtocolClientError("transport_case_id must be a bounded token")
        fields["transport_case_id"] = config.transport_case_id
    authority_hash = target_authority_sha256(config.url)
    if authority_hash is not None:
        fields["target_authority_sha256"] = authority_hash
    if config.upstream_protocol is not None:
        fields["upstream_protocol"] = normalize_protocol(config.upstream_protocol)
    stream_id = config.stream_id
    sidecar_stream_id = sidecar.get("stream_id")
    if stream_id is not None and sidecar_stream_id is not None and stream_id != sidecar_stream_id:
        raise ProtocolClientError("stream_id conflicts with observation sidecar")
    if stream_id is None:
        stream_id = sidecar_stream_id
    if stream_id is not None:
        fields["stream_id"] = stream_id
    for name in (
        "connection_reused",
        "quic_connection_id_present",
        "quic_version",
        "alpn",
        "stream_reset",
        "stream_reset_code",
    ):
        if name in sidecar:
            fields[name] = sidecar[name]
    return fields


def _evidence_gaps(observation: Mapping[str, Any]) -> tuple[list[str], list[str]]:
    """Return (missing, contradictory) strict protocol-evidence fields."""

    requested = observation.get("requested_protocol")
    negotiated = observation.get("negotiated_protocol")
    missing: list[str] = []
    contradictory: list[str] = []
    if negotiated != requested:
        contradictory.append("negotiated_protocol")
        return missing, contradictory
    expected_transport = observation.get("expected_transport")
    if expected_transport is None:
        # Persisted artifacts deliberately omit the URL and therefore cannot
        # distinguish HTTP/1.1 over cleartext from HTTPS here.  The other
        # forced profiles have one canonical transport each.
        expected_transport = {
            "h2": "tls_tcp",
            "h2c": "tcp",
            "h3": "quic_udp",
        }.get(requested)
    transport = observation.get("transport")
    if transport is None:
        missing.append("transport")
    elif expected_transport is not None and transport != expected_transport:
        contradictory.append("transport")
    if requested in {"h2", "h2c", "h3"}:
        stream_id = observation.get("stream_id")
        if stream_id is None:
            missing.append("stream_id")
        elif isinstance(stream_id, bool) or not isinstance(stream_id, int) or stream_id < 0:
            contradictory.append("stream_id")
    if requested == "h2":
        alpn = observation.get("alpn")
        if alpn is None:
            missing.append("alpn")
        elif alpn != "h2":
            contradictory.append("alpn")
    if requested == "h3":
        alpn = observation.get("alpn")
        if alpn is None:
            missing.append("alpn")
        elif alpn != "h3":
            contradictory.append("alpn")
        if observation.get("quic_udp_observed") is not True:
            missing.append("quic_udp_observed")
        if observation.get("quic_connection_id_present") is not True:
            missing.append("quic_connection_id_present")
    return missing, contradictory


def validate_protocol_observation(
    observation: Mapping[str, Any], *, require_pass_evidence: bool = False
) -> list[str]:
    """Validate canonical protocol/transport values and strict PASS evidence.

    This function is intentionally importable by connector runners and unit
    tests.  It reports errors instead of raising so a runner can turn an
    incomplete observation into a non-promoting result.
    """

    errors: list[str] = []
    requested = observation.get("requested_protocol")
    if requested not in CANONICAL_PROTOCOLS:
        errors.append("requested_protocol is not canonical")
    downstream = observation.get("downstream_protocol")
    if downstream not in CANONICAL_PROTOCOLS:
        errors.append("downstream_protocol is not canonical")
    upstream = observation.get("upstream_protocol")
    if upstream is not None and upstream not in CANONICAL_PROTOCOLS:
        errors.append("upstream_protocol is not canonical")
    negotiated = observation.get("negotiated_protocol")
    if negotiated is not None and negotiated not in CANONICAL_PROTOCOLS:
        errors.append("negotiated_protocol is not canonical")
    transport = observation.get("transport")
    if transport is not None and transport not in CANONICAL_TRANSPORTS:
        errors.append("transport is not canonical")
    if not isinstance(observation.get("fallback_used"), bool):
        errors.append("fallback_used must be boolean")
    if "stream_id" in observation:
        stream_id = observation["stream_id"]
        if isinstance(stream_id, bool) or not isinstance(stream_id, int) or stream_id < 0:
            errors.append("stream_id must be an integer >= 0")
    if "transport_case_id" in observation and (
        not isinstance(observation["transport_case_id"], str)
        or not _BOUNDED_TOKEN.fullmatch(observation["transport_case_id"])
    ):
        errors.append("transport_case_id must be a bounded token")
    if "target_authority_sha256" in observation and (
        not isinstance(observation["target_authority_sha256"], str)
        or not _SHA256_TOKEN.fullmatch(observation["target_authority_sha256"])
    ):
        errors.append("target_authority_sha256 must be a SHA-256 token")
    if "connection_reused" in observation and not isinstance(observation["connection_reused"], bool):
        errors.append("connection_reused must be boolean")
    if "quic_connection_id_present" in observation and not isinstance(
        observation["quic_connection_id_present"], bool
    ):
        errors.append("quic_connection_id_present must be boolean")
    if "quic_udp_observed" in observation and not isinstance(observation["quic_udp_observed"], bool):
        errors.append("quic_udp_observed must be boolean")
    if "quic_version" in observation and (
        not isinstance(observation["quic_version"], str)
        or not _BOUNDED_TOKEN.fullmatch(observation["quic_version"])
    ):
        errors.append("quic_version must be a bounded token")
    if "alpn" in observation and observation["alpn"] not in {"h2", "h3"}:
        errors.append("alpn must be h2 or h3")
    if "stream_reset" in observation and not isinstance(observation["stream_reset"], bool):
        errors.append("stream_reset must be boolean")
    if "stream_reset_code" in observation:
        code = observation["stream_reset_code"]
        if isinstance(code, bool) or (
            not isinstance(code, int)
            and (not isinstance(code, str) or not _BOUNDED_TOKEN.fullmatch(code))
        ):
            errors.append("stream_reset_code must be numeric or bounded token")
    if any(key in observation for key in _RAW_CONNECTION_ID_KEYS):
        errors.append("raw connection identifiers must not be persisted")
    if require_pass_evidence:
        if observation.get("fallback_used") is not False:
            errors.append("PASS cannot use fallback")
        missing, contradictory = _evidence_gaps(observation)
        errors.extend(f"missing {field}" for field in missing)
        errors.extend(f"contradictory {field}" for field in contradictory)
    return errors


def _initial_observation(
    protocol: str,
    scheme: str | None,
    config: ClientConfig,
    sidecar: Mapping[str, Any],
) -> dict[str, Any]:
    observation: dict[str, Any] = {
        "schema_version": 1,
        "status": "NOT_EXECUTED",
        "requested_protocol": protocol,
        "downstream_protocol": protocol,
        "negotiated_protocol": None,
        "transport": None,
        "fallback_used": False,
        "http_status": None,
        "downloaded_bytes": None,
        "content_length_download": None,
        "response_committed": False,
        "client_first_body_byte_visible": False,
        "response_complete": False,
        "curl_exit_code": None,
        "transport_error": "not_executed",
    }
    if scheme is not None:
        observation["expected_transport"] = _expected_transport(protocol, scheme)
    observation.update(_provenance(config, sidecar))
    if protocol == "h3":
        observation["quic_udp_observed"] = bool(
            config.quic_udp_observed or sidecar.get("quic_udp_observed") is True
        )
    return observation


def _apply_outcome(
    observation: dict[str, Any],
    outcome: Mapping[str, Any],
    *,
    returncode: int,
    stderr: str,
    requested: str,
    scheme: str,
    config: ClientConfig,
    sidecar: Mapping[str, Any],
) -> None:
    http_status = outcome.get("http_status")
    downloaded = outcome.get("downloaded_bytes")
    content_length = outcome.get("content_length_download")
    negotiated = _negotiated_protocol(outcome.get("http_version"), requested, scheme)
    observation.update(
        {
            "http_status": http_status,
            "downloaded_bytes": downloaded,
            "content_length_download": content_length,
            "response_committed": http_status is not None,
            "client_first_body_byte_visible": bool(
                isinstance(downloaded, (int, float)) and downloaded > 0
            ),
            "curl_exit_code": returncode,
            "transport_error": _classify_transport_error(
                returncode, stderr, requested, http_status
            ),
            "negotiated_protocol": negotiated,
            "fallback_used": negotiated is not None and negotiated != requested,
        }
    )
    observation["transport"] = _derive_transport(
        negotiated,
        requested,
        scheme,
        sidecar,
        config.quic_udp_observed,
    )
    response_complete = (
        http_status is not None
        and returncode in {0, 22}
        and isinstance(downloaded, (int, float))
        and isinstance(content_length, (int, float))
        and downloaded >= content_length
    )
    observation["response_complete"] = bool(response_complete)


def _finalize_status(observation: dict[str, Any], requested: str) -> None:
    """Set the final observation status with fallback as an unconditional fail."""

    negotiated = observation.get("negotiated_protocol")
    returncode = observation.get("curl_exit_code")
    if observation.get("fallback_used") is True:
        observation["status"] = "FAIL"
        observation["reason"] = "protocol_fallback_observed"
        return
    if negotiated != requested:
        error = observation.get("transport_error")
        if error in {"h2_failure", "h3_failure"}:
            observation["status"] = "UNSUPPORTED_BY_HOST"
            observation["reason"] = "requested_protocol_not_observed"
        else:
            observation["status"] = "FAIL"
            observation["reason"] = "requested_protocol_not_observed"
        return
    if returncode not in {0, 22}:
        observation["status"] = "FAIL"
        observation["reason"] = "curl_transfer_failed_after_protocol_observation"
        return
    missing, contradictory = _evidence_gaps(observation)
    if contradictory:
        observation["status"] = "FAIL"
        observation["reason"] = "contradictory_protocol_observation"
        observation["missing_evidence"] = sorted(contradictory)
        return
    if missing:
        observation["status"] = "NOT_EXECUTED"
        observation["reason"] = "incomplete_protocol_provenance"
        observation["missing_evidence"] = sorted(missing)
        return
    validation_errors = validate_protocol_observation(observation, require_pass_evidence=True)
    if validation_errors:
        observation["status"] = "FAIL"
        observation["reason"] = "invalid_protocol_observation"
        observation["validation_errors"] = sorted(validation_errors)
        return
    observation["status"] = "PASS"


def _features_report(inspection: CurlInspection, preflight: Preflight, protocol: str) -> str:
    lines = [
        f"curl_executable={inspection.executable}",
        "curl_version=" + (
            ".".join(str(part) for part in inspection.version)
            if inspection.version is not None
            else "unknown"
        ),
        "protocol=" + protocol,
        "features=" + ",".join(sorted(inspection.features)),
        "required_features=" + ",".join(preflight.required_features),
        "missing_features=" + ",".join(preflight.missing_features),
        "required_options=" + ",".join(preflight.required_options),
        "missing_options=" + ",".join(preflight.missing_options),
        "preflight_status=" + preflight.status,
        "preflight_reason=" + (preflight.reason or ""),
        "writeout_mode=" + preflight.writeout_mode,
    ]
    return "\n".join(lines) + "\n"


def atomic_write_text(path: Path, value: str) -> None:
    """Write one artifact atomically with restrictive temporary permissions."""

    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.parent.is_dir():
        raise ProtocolClientError("artifact parent is not a directory")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent), text=False
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(value.encode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        # Best-effort directory sync protects against a host crash after the
        # rename.  It is not available on every platform used by CI.
        try:
            directory_fd = os.open(path.parent, os.O_RDONLY)
        except OSError:
            directory_fd = None
        if directory_fd is not None:
            try:
                os.fsync(directory_fd)
            except OSError:
                pass
            finally:
                os.close(directory_fd)
    except Exception:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def atomic_write_json(path: Path, value: Mapping[str, Any]) -> None:
    atomic_write_text(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


def _write_artifacts(
    config: ClientConfig,
    inspection: CurlInspection,
    preflight: Preflight,
    command: Sequence[str],
    observation: Mapping[str, Any],
) -> None:
    directory = config.artifact_dir
    atomic_write_text(directory / "client-version.txt", _truncate_text(inspection.version_text))
    atomic_write_text(
        directory / "client-features.txt",
        _features_report(inspection, preflight, str(observation.get("requested_protocol", ""))),
    )
    command_text = _redacted_command(command, url=config.url) if command else "not executed\n"
    atomic_write_text(directory / "client-command.txt", command_text)
    atomic_write_json(directory / "client-protocol-observation.json", observation)


def _run_followup_observation(
    config: ClientConfig,
    inspection: CurlInspection,
) -> dict[str, Any] | None:
    """Perform one independent, payload-free health request when configured.

    A strict reset necessarily makes the primary client transfer fail.  The
    follow-up therefore has a deliberately narrow contract: it proves the
    host accepts a fresh forced-profile request with a healthy HTTP status.
    It does not reuse the primary request's stream ID or promote any rule
    outcome.  The URL, headers, body, command, and stderr remain unpersisted.
    """

    if config.followup_url is None:
        return None
    protocol = config.followup_protocol or config.protocol
    followup = replace(
        config,
        url=config.followup_url,
        protocol=protocol,
        request="GET",
        headers=(),
        data_file=None,
        transaction_id=None,
        transport_case_id=derive_followup_transport_case_id(config.transport_case_id),
        rule_id=None,
        phase=None,
        stream_id=None,
        observation_sidecar=None,
    )
    try:
        normalized_protocol, scheme = _validate_config(followup)
    except ProtocolClientError:
        return {
            "schema_version": 1,
            "status": "NOT_EXECUTED",
            "reason": "invalid_followup_configuration",
        }
    preflight = preflight_curl(normalized_protocol, inspection, followup)
    if preflight.status != "READY":
        return {
            "schema_version": 1,
            "status": "BLOCKED",
            "reason": preflight.reason or "followup_client_preflight_blocked",
            "requested_protocol": normalized_protocol,
        }
    try:
        command = build_curl_command(followup, preflight)
    except ProtocolClientError:
        return {
            "schema_version": 1,
            "status": "NOT_EXECUTED",
            "reason": "invalid_followup_configuration",
            "requested_protocol": normalized_protocol,
        }
    observation = _initial_observation(normalized_protocol, scheme, followup, {})
    try:
        execution = _run_process(command, timeout=followup.timeout + 10)
    except subprocess.TimeoutExpired:
        observation.update({"status": "FAIL", "reason": "followup_timeout", "transport_error": "timeout"})
    except (FileNotFoundError, PermissionError, OSError):
        observation.update({"status": "BLOCKED", "reason": "followup_client_unavailable", "transport_error": "client_unavailable"})
    else:
        outcome = _parse_writeout(execution.stdout, preflight.writeout_mode)
        _apply_outcome(
            observation,
            outcome,
            returncode=execution.returncode,
            stderr=execution.stderr,
            requested=normalized_protocol,
            scheme=scheme or "http",
            config=followup,
            sidecar={},
        )
        if observation.get("fallback_used") is True:
            observation.update({"status": "FAIL", "reason": "followup_protocol_fallback"})
        elif observation.get("negotiated_protocol") != normalized_protocol:
            observation.update({"status": "FAIL", "reason": "followup_protocol_not_observed"})
        elif (
            isinstance(observation.get("http_status"), int)
            and 200 <= int(observation["http_status"]) < 400
            and execution.returncode == 0
        ):
            observation.update({"status": "PASS", "reason": "healthy_independent_request"})
        else:
            observation.update({"status": "FAIL", "reason": "followup_unhealthy_response"})
    observation.pop("expected_transport", None)
    allowed = {
        "schema_version", "status", "reason", "requested_protocol", "downstream_protocol",
        "negotiated_protocol", "transport", "fallback_used", "http_status",
        "response_complete", "curl_exit_code", "transport_error", "connector",
        "integration_mode", "run_id", "transport_case_id", "target_authority_sha256",
    }
    return {key: value for key, value in observation.items() if key in allowed}


def _blocked_observation(
    config: ClientConfig,
    protocol: str,
    scheme: str | None,
    sidecar: Mapping[str, Any],
    *,
    status: str,
    reason: str,
) -> dict[str, Any]:
    observation = _initial_observation(protocol, scheme, config, sidecar)
    observation["status"] = status
    observation["reason"] = reason
    if status == "BLOCKED":
        observation["transport_error"] = "client_unavailable"
    return observation


def run_protocol_client(config: ClientConfig) -> ClientRunResult:
    """Preflight curl, execute a forced request, and atomically write evidence.

    Expected request-level HTTP errors (curl exit 22 from ``--fail-with-body``)
    can still prove negotiation because curl records a response protocol and
    status.  Protocol fallback, incomplete provenance, malformed observations,
    and partial transfers never become ``PASS``.
    """

    inspection = inspect_curl(config.curl)
    protocol = "http1"
    scheme: str | None = None
    config_error: str | None = None
    try:
        protocol, scheme = _validate_config(config)
    except ProtocolClientError:
        # Do not export user input or an exception message: these artifacts
        # are designed to remain safe for canonical evidence directories.
        config_error = "invalid_client_configuration"
        try:
            protocol = normalize_protocol(config.protocol)
        except ProtocolClientError:
            protocol = "http1"

    sidecar: dict[str, Any] = {}
    sidecar_error: str | None = None
    if config.observation_sidecar is not None:
        try:
            sidecar = _load_observation_sidecar(config.observation_sidecar)
        except ProtocolClientError:
            sidecar_error = "invalid_observation_sidecar"

    preflight = preflight_curl(protocol, inspection, config)
    command: tuple[str, ...] = ()
    if config_error is not None:
        observation = _blocked_observation(
            config,
            protocol,
            scheme,
            sidecar,
            status="NOT_EXECUTED",
            reason=config_error,
        )
        _write_artifacts(config, inspection, preflight, command, observation)
        return ClientRunResult(observation, inspection, preflight, command)
    if preflight.status != "READY":
        observation = _blocked_observation(
            config,
            protocol,
            scheme,
            sidecar,
            status="BLOCKED",
            reason=preflight.reason or "client_preflight_blocked",
        )
        _write_artifacts(config, inspection, preflight, command, observation)
        return ClientRunResult(observation, inspection, preflight, command)
    if sidecar_error is not None:
        observation = _blocked_observation(
            config,
            protocol,
            scheme,
            sidecar,
            status="NOT_EXECUTED",
            reason=sidecar_error,
        )
        _write_artifacts(config, inspection, preflight, command, observation)
        return ClientRunResult(observation, inspection, preflight, command)

    try:
        command = build_curl_command(config, preflight)
    except ProtocolClientError:
        observation = _blocked_observation(
            config,
            protocol,
            scheme,
            sidecar,
            status="NOT_EXECUTED",
            reason="invalid_client_configuration",
        )
        _write_artifacts(config, inspection, preflight, command, observation)
        return ClientRunResult(observation, inspection, preflight, command)

    observation = _initial_observation(protocol, scheme, config, sidecar)
    try:
        execution = _run_process(command, timeout=config.timeout + 10)
    except subprocess.TimeoutExpired:
        observation.update(
            {
                "status": "FAIL",
                "reason": "curl_execution_timeout",
                "curl_exit_code": None,
                "transport_error": "timeout",
            }
        )
    except (FileNotFoundError, PermissionError, OSError):
        observation.update(
            {
                "status": "BLOCKED",
                "reason": "curl_execution_unavailable",
                "transport_error": "client_unavailable",
            }
        )
    else:
        outcome = _parse_writeout(execution.stdout, preflight.writeout_mode)
        _apply_outcome(
            observation,
            outcome,
            returncode=execution.returncode,
            stderr=execution.stderr,
            requested=protocol,
            scheme=scheme or "http",
            config=config,
            sidecar=sidecar,
        )
        _finalize_status(observation, protocol)

    # These are local implementation keys useful while deciding PASS, but the
    # persisted observation should contain only the canonical actual fields.
    observation.pop("expected_transport", None)
    _write_artifacts(config, inspection, preflight, command, observation)
    followup = _run_followup_observation(config, inspection)
    if followup is not None:
        atomic_write_json(config.artifact_dir / "client-followup-observation.json", followup)
    return ClientRunResult(observation, inspection, preflight, command)


def _parse_headers(values: Sequence[str]) -> tuple[str, ...]:
    return tuple(values)


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a payload-free forced HTTP/1.1, H2, h2c, or H3 curl probe."
    )
    parser.add_argument("--url", required=True, help="Absolute http(s) target URL")
    parser.add_argument(
        "--protocol",
        choices=sorted(CANONICAL_PROTOCOLS),
        default="http1",
        help="Forced downstream protocol (default: http1)",
    )
    parser.add_argument("--artifact-dir", required=True, type=Path)
    parser.add_argument("--curl", default="curl", help="curl executable or absolute path")
    parser.add_argument("--timeout", type=float, default=30.0, help="curl max time in seconds")
    parser.add_argument("--connect-timeout", type=float)
    parser.add_argument("--insecure", action="store_true", help="Pass --insecure to curl")
    parser.add_argument("--request", default="GET", help="HTTP method")
    parser.add_argument("--header", action="append", default=[], help="Request header (not persisted)")
    parser.add_argument(
        "--data-file",
        type=Path,
        help="Request body file passed to curl; its path and contents are not persisted",
    )
    parser.add_argument("--cacert", type=Path, help="CA bundle passed to curl (not persisted)")
    parser.add_argument(
        "--resolve",
        action="append",
        default=[],
        help="curl --resolve value; may be specified more than once",
    )
    parser.add_argument("--connector")
    parser.add_argument("--integration-mode")
    parser.add_argument("--run-id")
    parser.add_argument("--transaction-id")
    parser.add_argument(
        "--transport-case-id",
        help=(
            "bounded per-request token sent as X-MSConnector-Transport-Case; "
            "the matching connector event must record it"
        ),
    )
    parser.add_argument("--rule-id")
    parser.add_argument("--phase")
    parser.add_argument("--stream-id", type=int)
    parser.add_argument("--upstream-protocol", choices=sorted(CANONICAL_PROTOCOLS))
    parser.add_argument(
        "--quic-udp-observed",
        action="store_true",
        help="Affirm a separate, real UDP/QUIC traffic observation for H3",
    )
    parser.add_argument(
        "--observation-sidecar",
        "--quic-udp-observation",
        dest="observation_sidecar",
        type=Path,
        help=(
            "Bounded JSON sidecar with stream/ALPN/QUIC observation fields; "
            "raw connection IDs are rejected"
        ),
    )
    parser.add_argument(
        "--followup-url",
        help="Independent payload-free health request required by strict reset evidence",
    )
    parser.add_argument(
        "--followup-protocol",
        choices=sorted(CANONICAL_PROTOCOLS),
        help="Forced protocol for --followup-url (defaults to --protocol)",
    )
    return parser.parse_args(argv)


def config_from_args(arguments: argparse.Namespace) -> ClientConfig:
    return ClientConfig(
        url=arguments.url,
        protocol=arguments.protocol,
        artifact_dir=arguments.artifact_dir,
        curl=arguments.curl,
        timeout=arguments.timeout,
        connect_timeout=arguments.connect_timeout,
        insecure=arguments.insecure,
        request=arguments.request,
        headers=_parse_headers(arguments.header),
        data_file=arguments.data_file,
        cacert=arguments.cacert,
        resolve=tuple(arguments.resolve),
        connector=arguments.connector,
        integration_mode=arguments.integration_mode,
        run_id=arguments.run_id,
        transaction_id=arguments.transaction_id,
        transport_case_id=arguments.transport_case_id,
        rule_id=arguments.rule_id,
        phase=arguments.phase,
        stream_id=arguments.stream_id,
        upstream_protocol=arguments.upstream_protocol,
        quic_udp_observed=arguments.quic_udp_observed,
        observation_sidecar=arguments.observation_sidecar,
        followup_url=arguments.followup_url,
        followup_protocol=arguments.followup_protocol,
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    result = run_protocol_client(config_from_args(args))
    # A nonzero exit makes protocol fallback and unavailable evidence visible
    # to plain shell callers.  Artifacts are written for every outcome.
    return 0 if result.observation.get("status") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
