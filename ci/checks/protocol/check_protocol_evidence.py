#!/usr/bin/env python3
"""Validate payload-free client evidence for forced H2/H3 protocol cases.

This checker is intentionally separate from ``no_crs_baseline.py``.  The
baseline normalizer binds a PASS to the matching connector event; this module
checks the client half of that same claim.  A build flag, a curl exit code, or
an internal reset is not sufficient evidence by itself.

For ordinary protocol evidence the managed client observation must be a
complete forced-profile PASS.  For ``--strict`` H2/H3 evidence it must instead
show an already committed, partial response followed by a client-observed
stream reset and a healthy independent follow-up observation.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import re
import shlex
import sys
from typing import Any, Mapping, Sequence


FRAMEWORK_ROOT = Path(__file__).resolve().parents[3]
PROTOCOL_CLIENT_PATH = FRAMEWORK_ROOT / "ci" / "checks" / "protocol" / "protocol_client.py"
SPEC = importlib.util.spec_from_file_location("msconnector_protocol_client", PROTOCOL_CLIENT_PATH)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - installation defect
    raise RuntimeError(f"cannot load protocol client helper: {PROTOCOL_CLIENT_PATH}")
protocol_client = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = protocol_client
SPEC.loader.exec_module(protocol_client)


CLIENT_VERSION_ARTIFACT = "client-version.txt"
CLIENT_FEATURES_ARTIFACT = "client-features.txt"
CLIENT_COMMAND_ARTIFACT = "client-command.txt"
PRIMARY_OBSERVATION_ARTIFACT = "client-protocol-observation.json"
REQUIRED_ARTIFACTS = (
    CLIENT_VERSION_ARTIFACT,
    CLIENT_FEATURES_ARTIFACT,
    CLIENT_COMMAND_ARTIFACT,
    PRIMARY_OBSERVATION_ARTIFACT,
)
FOLLOWUP_ARTIFACT = "client-followup-observation.json"
MAX_TEXT_BYTES = 64 * 1024
MAX_JSON_BYTES = 128 * 1024
ALLOWED_OBSERVATION_FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "reason",
        "missing_evidence",
        "validation_errors",
        "connector",
        "integration_mode",
        "run_id",
        "transaction_id",
        "transport_case_id",
        "target_authority_sha256",
        "rule_id",
        "phase",
        "requested_protocol",
        "downstream_protocol",
        "upstream_protocol",
        "negotiated_protocol",
        "transport",
        "expected_transport",
        "alpn",
        "stream_id",
        "connection_reused",
        "quic_udp_observed",
        "quic_connection_id_present",
        "quic_version",
        "fallback_used",
        "stream_reset",
        "stream_reset_code",
        "http_status",
        "downloaded_bytes",
        "content_length_download",
        "response_committed",
        "client_first_body_byte_visible",
        "response_complete",
        "curl_exit_code",
        "transport_error",
    }
)
FORBIDDEN_PAYLOAD_KEYS = frozenset(
    {
        "body",
        "request_body",
        "response_body",
        "response_headers",
        "headers",
        "stdout",
        "stderr",
        "url",
        "uri",
        "connection_id",
        "quic_connection_id",
        "quic_cid",
        "cid",
    }
)
FORBIDDEN_CAPTURE_OPTIONS = frozenset(
    {
        "--dump-header",
        "--include",
        "--remote-header-name",
        "--remote-name",
        "--trace",
        "--trace-ascii",
        "--trace-time",
        "--verbose",
        "-D",
        "-O",
        "-i",
        "-J",
        "-v",
    }
)
REDACTED_COMMAND_VALUE_OPTIONS = frozenset({"--header", "--data-binary", "--cacert"})
FORBIDDEN_TEXT_HEADERS = re.compile(
    r"(?im)^(?:authorization|proxy-authorization|cookie|set-cookie)\s*:"
)
RAW_CONNECTION_ID_TEXT = re.compile(
    r"(?i)\b(?:quic[_.-]?)?(?:connection[_.-]?id|cid)\b"
)
RAW_CONNECTION_ID_ARGUMENT = re.compile(
    r"(?i)^(?:--)?(?:quic[_.-]?)?(?:connection[_.-]?id|cid)(?:=|:|$)"
)
# ``--curl`` accepts an absolute executable path and Windows paths may contain
# spaces/backslashes.  The feature-report key allowlist plus the no-control
# bound keep that metadata safe without rejecting a generated cross-platform
# artifact.
SAFE_EXECUTABLE = re.compile(r"^[^\x00-\x1f\x7f]{1,512}$")
SAFE_VERSION = re.compile(r"^(?:unknown|\d+\.\d+\.\d+)$")
SAFE_FEATURE_LIST = re.compile(r"^(?:[A-Z0-9_+.-]+(?:,[A-Z0-9_+.-]+)*)?$")
SAFE_OPTION_LIST = re.compile(r"^(?:--[a-z0-9][a-z0-9.-]*(?:,--[a-z0-9][a-z0-9.-]*)*)?$")
SAFE_REASON = re.compile(r"^(?:|[a-z0-9][a-z0-9_:-]{0,127})$")
FEATURE_REPORT_FIELDS = frozenset(
    {
        "curl_executable",
        "curl_version",
        "protocol",
        "features",
        "required_features",
        "missing_features",
        "required_options",
        "missing_options",
        "preflight_status",
        "preflight_reason",
        "writeout_mode",
    }
)
ALLOWED_FOLLOWUP_FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "reason",
        "connector",
        "integration_mode",
        "run_id",
        "transport_case_id",
        "target_authority_sha256",
        "requested_protocol",
        "downstream_protocol",
        "negotiated_protocol",
        "transport",
        "fallback_used",
        "http_status",
        "response_complete",
        "curl_exit_code",
        "transport_error",
    }
)


def _read_text(path: Path, *, maximum: int) -> tuple[str | None, list[str]]:
    if path.is_symlink() or not path.is_file():
        return None, [f"missing or unsafe artifact: {path.name}"]
    try:
        raw = path.read_bytes()
    except OSError:
        return None, [f"unreadable artifact: {path.name}"]
    if len(raw) > maximum:
        return None, [f"artifact exceeds bounded size: {path.name}"]
    try:
        return raw.decode("utf-8"), []
    except UnicodeDecodeError:
        return None, [f"artifact is not UTF-8: {path.name}"]


def _read_json(path: Path) -> tuple[dict[str, Any] | None, list[str]]:
    text, errors = _read_text(path, maximum=MAX_JSON_BYTES)
    if text is None:
        return None, errors
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return None, [f"artifact is not JSON: {path.name}"]
    if not isinstance(value, dict):
        return None, [f"artifact must be a JSON object: {path.name}"]
    return value, []


def _payload_errors(value: object, *, path: str = "observation") -> list[str]:
    errors: list[str] = []
    if isinstance(value, Mapping):
        for key, nested in value.items():
            normalized = str(key).strip().lower().replace("-", "_")
            nested_path = f"{path}.{key}"
            if normalized in FORBIDDEN_PAYLOAD_KEYS:
                errors.append(f"{nested_path}: forbidden payload or connection-ID field")
            errors.extend(_payload_errors(nested, path=nested_path))
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            errors.extend(_payload_errors(nested, path=f"{path}[{index}]"))
    return errors


def _text_safety_errors(value: str, *, artifact: str) -> list[str]:
    """Reject text that cannot occur in a payload-free managed artifact.

    The managed client writes curl's version output verbatim and a small
    key/value feature report, so this deliberately avoids a brittle whitelist
    for every curl build string.  It does reject HTTP credential/header text
    and raw QUIC-CID labels, neither of which belongs in those artifacts.
    """

    errors: list[str] = []
    if any(ord(character) < 32 and character not in {"\n", "\r", "\t"} for character in value):
        errors.append(f"{artifact}: control characters are forbidden")
    if FORBIDDEN_TEXT_HEADERS.search(value):
        errors.append(f"{artifact}: sensitive HTTP header text is forbidden")
    if RAW_CONNECTION_ID_TEXT.search(value):
        errors.append(f"{artifact}: raw connection-ID text is forbidden")
    return errors


def _required_protocol_flag(protocol: str) -> str:
    return {
        "http1": "--http1.1",
        "h2": "--http2",
        "h2c": "--http2-prior-knowledge",
        "h3": "--http3-only",
    }[protocol]


def _required_protocol_feature(protocol: str) -> str | None:
    return {"h2": "HTTP2", "h2c": "HTTP2", "h3": "HTTP3"}.get(protocol)


def _validate_version_text(version_text: str) -> list[str]:
    errors = _text_safety_errors(version_text, artifact=CLIENT_VERSION_ARTIFACT)
    lines = version_text.splitlines()
    if not lines or not re.match(r"^curl\s+\d+\.\d+(?:\.\d+)?(?:\s|$)", lines[0], re.IGNORECASE):
        errors.append(f"{CLIENT_VERSION_ARTIFACT} does not contain a curl version banner")
    return errors


def _parse_feature_report(features_text: str) -> tuple[dict[str, str], list[str]]:
    values: dict[str, str] = {}
    errors: list[str] = []
    for line in features_text.splitlines():
        if "=" not in line:
            errors.append(f"{CLIENT_FEATURES_ARTIFACT} contains a non key/value line")
            continue
        key, value = line.split("=", 1)
        if key in values:
            errors.append(f"{CLIENT_FEATURES_ARTIFACT} repeats {key}")
            continue
        values[key] = value
    return values, errors


def _feature_schema_errors(values: Mapping[str, str]) -> tuple[list[str], bool]:
    errors: list[str] = []
    unknown = set(values) - FEATURE_REPORT_FIELDS
    if unknown:
        errors.append(
            f"{CLIENT_FEATURES_ARTIFACT} has unsupported fields: " + ", ".join(sorted(unknown))
        )
    missing = FEATURE_REPORT_FIELDS - set(values)
    if missing:
        errors.append(
            f"{CLIENT_FEATURES_ARTIFACT} is missing fields: " + ", ".join(sorted(missing))
        )
    return errors, bool(missing)


def _feature_value_errors(values: Mapping[str, str]) -> list[str]:
    errors: list[str] = []
    if not SAFE_EXECUTABLE.fullmatch(values["curl_executable"]):
        errors.append(
            f"{CLIENT_FEATURES_ARTIFACT} curl_executable is not a bounded executable path"
        )
    if not SAFE_VERSION.fullmatch(values["curl_version"]):
        errors.append(f"{CLIENT_FEATURES_ARTIFACT} curl_version is not bounded")
    for field in ("features", "required_features", "missing_features"):
        if not SAFE_FEATURE_LIST.fullmatch(values[field]):
            errors.append(f"{CLIENT_FEATURES_ARTIFACT} {field} is not a bounded feature list")
    for field in ("required_options", "missing_options"):
        if not SAFE_OPTION_LIST.fullmatch(values[field]):
            errors.append(f"{CLIENT_FEATURES_ARTIFACT} {field} is not a bounded option list")
    return errors


def _feature_protocol_errors(
    values: Mapping[str, str], *, protocol: str, require_correlation: bool,
) -> list[str]:
    errors: list[str] = []
    if values["protocol"] != protocol:
        errors.append(f"{CLIENT_FEATURES_ARTIFACT} protocol differs from the selected profile")
    if values["preflight_status"] != "READY":
        errors.append(f"{CLIENT_FEATURES_ARTIFACT} does not record a ready client preflight")
    if values["preflight_reason"]:
        errors.append(f"{CLIENT_FEATURES_ARTIFACT} READY preflight must not have a reason")
    if values["writeout_mode"] not in {"json", "fields"}:
        errors.append(f"{CLIENT_FEATURES_ARTIFACT} has an invalid ready writeout mode")
    required_feature = _required_protocol_feature(protocol)
    features = set(filter(None, values["features"].split(",")))
    required_features = set(filter(None, values["required_features"].split(",")))
    missing_features = set(filter(None, values["missing_features"].split(",")))
    if required_feature is not None:
        if required_feature not in features:
            errors.append(f"{CLIENT_FEATURES_ARTIFACT} lacks the selected protocol feature")
        if required_feature not in required_features:
            errors.append(
                f"{CLIENT_FEATURES_ARTIFACT} does not declare the selected protocol feature"
            )
        if required_feature in missing_features:
            errors.append(
                f"{CLIENT_FEATURES_ARTIFACT} reports the selected protocol feature as missing"
            )
    required_flag = _required_protocol_flag(protocol)
    required_options = set(filter(None, values["required_options"].split(",")))
    missing_options = set(filter(None, values["missing_options"].split(",")))
    if required_flag not in required_options:
        errors.append(f"{CLIENT_FEATURES_ARTIFACT} does not declare the forced protocol option")
    if required_flag in missing_options:
        errors.append(f"{CLIENT_FEATURES_ARTIFACT} reports the forced protocol option as missing")
    if require_correlation and "--header" not in required_options:
        errors.append(
            f"{CLIENT_FEATURES_ARTIFACT} does not declare the transport-correlation header option"
        )
    return errors


def _validate_features_text(
    features_text: str, *, protocol: str, require_correlation: bool = False,
) -> list[str]:
    """Validate the exact bounded report emitted by ``protocol_client.py``."""

    errors = _text_safety_errors(features_text, artifact=CLIENT_FEATURES_ARTIFACT)
    values, parse_errors = _parse_feature_report(features_text)
    errors.extend(parse_errors)
    schema_errors, has_missing_fields = _feature_schema_errors(values)
    errors.extend(schema_errors)
    if has_missing_fields:
        return errors
    errors.extend(_feature_value_errors(values))
    errors.extend(_feature_protocol_errors(
        values,
        protocol=protocol,
        require_correlation=require_correlation,
    ))
    return errors


def _match(expected: str | None, value: object, field: str, errors: list[str]) -> None:
    if expected is not None and str(value) != expected:
        errors.append(f"{field} does not match expected provenance")


def _parse_command_arguments(command: str) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    try:
        arguments = shlex.split(command)
    except ValueError:
        errors.append("client command is not shell-parseable")
        arguments = []
    if not arguments:
        errors.append("client command is empty")
    return arguments, errors


def _redacted_option_error(arguments: Sequence[str], index: int) -> str | None:
    argument = arguments[index]
    if argument in REDACTED_COMMAND_VALUE_OPTIONS:
        if index + 1 >= len(arguments) or arguments[index + 1] != "[redacted]":
            return f"client command leaks the value for {argument}"
        return None
    for option in REDACTED_COMMAND_VALUE_OPTIONS:
        prefix = option + "="
        if argument.startswith(prefix) and argument != prefix + "[redacted]":
            return f"client command leaks the value for {option}"
    return None


def _command_argument_safety_errors(arguments: Sequence[str]) -> list[str]:
    errors: list[str] = []
    for index, argument in enumerate(arguments):
        if RAW_CONNECTION_ID_ARGUMENT.match(argument):
            errors.append("client command contains a raw connection-ID argument")
        redaction_error = _redacted_option_error(arguments, index)
        if redaction_error is not None:
            errors.append(redaction_error)
    return errors


def _command_output_safety_errors(arguments: Sequence[str]) -> list[str]:
    """Require exactly one non-capturing curl output destination.

    Shell-word parsing is intentional here: textual substring checks cannot
    distinguish a safe ``--output /dev/null`` from a later overriding output
    option, nor do they recognize curl's ``--option=value`` forms.
    """

    errors: list[str] = []
    output_destinations: list[str] = []
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        option, separator, inline_value = argument.partition("=")
        if option in FORBIDDEN_CAPTURE_OPTIONS:
            errors.append(f"client command contains payload-capture option {option}")
        if option == "--output":
            if separator:
                output_destinations.append(inline_value)
            elif index + 1 < len(arguments):
                output_destinations.append(arguments[index + 1])
                index += 1
            else:
                errors.append("client command has an output option without a destination")
        elif argument == "-o":
            if index + 1 < len(arguments):
                output_destinations.append(arguments[index + 1])
                index += 1
            else:
                errors.append("client command has an output option without a destination")
        elif argument.startswith("-o") and len(argument) > 2:
            output_destinations.append(argument[2:])
        index += 1

    if output_destinations != ["/dev/null"]:
        errors.append("client command must use exactly one payload-free output destination")
    return errors


def _command_policy_errors(arguments: Sequence[str], *, protocol: str) -> list[str]:
    errors: list[str] = []
    if "--fail-with-body" not in arguments:
        errors.append("client command does not preserve a failed response observation")
    required_flag = _required_protocol_flag(protocol)
    if required_flag not in arguments:
        errors.append("client command does not force the selected protocol profile")
    errors.extend(_command_output_safety_errors(arguments))
    return errors


def _validate_command(command: str, *, protocol: str) -> list[str]:
    errors: list[str] = []
    if command == "not executed\n":
        return ["protocol evidence requires an executed managed-client command"]
    if FORBIDDEN_TEXT_HEADERS.search(command):
        errors.append("client command contains sensitive HTTP header text")
    arguments, parse_errors = _parse_command_arguments(command)
    errors.extend(parse_errors)
    # The managed renderer redacts every value which could contain a request
    # payload, credential, or CA path.  Enforce that invariant even if an
    # external directory is supplied to the finalizer.
    errors.extend(_command_argument_safety_errors(arguments))
    errors.extend(_command_policy_errors(arguments, protocol=protocol))
    return errors


def _followup_reason_errors(observation: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    for field in ("reason", "transport_error"):
        value = observation.get(field)
        if value is not None and (not isinstance(value, str) or not SAFE_REASON.fullmatch(value)):
            errors.append(f"independent follow-up has an unsafe {field}")
    return errors


def _followup_type_errors(observation: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    for field in ("response_complete", "fallback_used"):
        if field in observation and not isinstance(observation[field], bool):
            errors.append(f"independent follow-up has an invalid {field}")
    for field in ("http_status", "curl_exit_code"):
        value = observation.get(field)
        if value is not None and (isinstance(value, bool) or not isinstance(value, int)):
            errors.append(f"independent follow-up has an invalid {field}")
    return errors


def _followup_safety_errors(observation: Mapping[str, Any]) -> list[str]:
    """Validate the payload-free, bounded vocabulary of an optional follow-up."""

    errors: list[str] = []
    unknown = set(observation) - ALLOWED_FOLLOWUP_FIELDS
    if unknown:
        errors.append("follow-up has unsupported fields: " + ", ".join(sorted(unknown)))
    errors.extend(_payload_errors(observation, path="followup"))
    if observation.get("schema_version") != 1:
        errors.append("independent follow-up has an invalid schema_version")
    errors.extend(_followup_reason_errors(observation))
    errors.extend(_followup_type_errors(observation))
    return errors


def _followup_result_errors(observation: Mapping[str, Any], *, protocol: str) -> list[str]:
    errors: list[str] = []
    if observation.get("status") != "PASS":
        errors.append("independent follow-up did not pass")
    if observation.get("requested_protocol") != protocol:
        errors.append("independent follow-up requested protocol differs")
    if observation.get("negotiated_protocol") != protocol:
        errors.append("independent follow-up negotiated protocol differs")
    if observation.get("fallback_used") is not False:
        errors.append("independent follow-up used a fallback")
    status = observation.get("http_status")
    if isinstance(status, bool) or not isinstance(status, int) or not 200 <= status < 400:
        errors.append("independent follow-up has no healthy HTTP status")
    return errors


def _followup_correlation_errors(
    observation: Mapping[str, Any], *, primary_observation: Mapping[str, Any],
) -> list[str]:
    errors: list[str] = []
    primary_case_id = primary_observation.get("transport_case_id")
    if (
        not isinstance(primary_case_id, str)
        or not protocol_client._BOUNDED_TOKEN.fullmatch(primary_case_id)
    ):
        errors.append("strict evidence requires a bounded primary transport_case_id")
    else:
        expected_followup_case_id = protocol_client.derive_followup_transport_case_id(
            primary_case_id
        )
        if observation.get("transport_case_id") != expected_followup_case_id:
            errors.append("independent follow-up has no distinct bound transport_case_id")
        if observation.get("transport_case_id") == primary_case_id:
            errors.append("independent follow-up reuses the primary transport_case_id")
    authority_hash = primary_observation.get("target_authority_sha256")
    if (
        not isinstance(authority_hash, str)
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", authority_hash)
    ):
        errors.append("strict evidence requires a bounded primary target authority hash")
    elif observation.get("target_authority_sha256") != authority_hash:
        errors.append("independent follow-up target authority does not match primary observation")
    return errors


def _followup_provenance_errors(
    observation: Mapping[str, Any], *, primary_observation: Mapping[str, Any],
) -> list[str]:
    errors: list[str] = []
    for field in (
        "requested_protocol", "downstream_protocol", "negotiated_protocol",
        "transport", "fallback_used", "connector", "integration_mode", "run_id",
    ):
        if primary_observation.get(field) is not None and (
            observation.get(field) != primary_observation.get(field)
        ):
            errors.append(f"independent follow-up {field} does not match primary observation")
    return errors


def _validate_followup(
    observation: Mapping[str, Any], *, protocol: str, primary_observation: Mapping[str, Any],
) -> list[str]:
    errors = _followup_safety_errors(observation)
    errors.extend(protocol_client.validate_protocol_observation(
        observation, require_pass_evidence=False,
    ))
    errors.extend(_followup_result_errors(observation, protocol=protocol))
    errors.extend(_followup_correlation_errors(
        observation,
        primary_observation=primary_observation,
    ))
    # URLs and request payload remain absent.  Connector/run provenance, a
    # distinct follow-up token, and the non-reversible authority hash bind the
    # independent health request without pretending it is the primary stream.
    errors.extend(_followup_provenance_errors(
        observation,
        primary_observation=primary_observation,
    ))
    return errors


def _read_required_artifacts(
    artifact_dir: Path,
) -> tuple[dict[str, str], dict[str, Any] | None, list[str]]:
    text_artifacts: dict[str, str] = {}
    observation: dict[str, Any] | None = None
    errors: list[str] = []
    for name in REQUIRED_ARTIFACTS:
        path = artifact_dir / name
        if name == PRIMARY_OBSERVATION_ARTIFACT:
            observation, artifact_errors = _read_json(path)
        else:
            value, artifact_errors = _read_text(path, maximum=MAX_TEXT_BYTES)
            if isinstance(value, str):
                text_artifacts[name] = value
        errors.extend(artifact_errors)
    return text_artifacts, observation, errors


def _text_artifact_errors(
    text_artifacts: Mapping[str, str], *, protocol: str, require_correlation: bool,
) -> list[str]:
    errors: list[str] = []
    version_text = text_artifacts.get(CLIENT_VERSION_ARTIFACT)
    if version_text is not None:
        errors.extend(_validate_version_text(version_text))
    features_text = text_artifacts.get(CLIENT_FEATURES_ARTIFACT)
    if features_text is not None:
        errors.extend(_validate_features_text(
            features_text,
            protocol=protocol,
            require_correlation=require_correlation,
        ))
    command = text_artifacts.get(CLIENT_COMMAND_ARTIFACT)
    if command is not None:
        errors.extend(_validate_command(command, protocol=protocol))
    return errors


def _primary_observation_errors(
    observation: Mapping[str, Any],
    *,
    protocol: str,
    strict: bool,
    connector: str | None,
    integration_mode: str | None,
    run_id: str | None,
    transaction_id: str | None,
    rule_id: str | None,
    phase: str | None,
) -> list[str]:
    errors: list[str] = []
    unknown = set(observation) - ALLOWED_OBSERVATION_FIELDS
    if unknown:
        errors.append("observation has unsupported fields: " + ", ".join(sorted(unknown)))
    errors.extend(_payload_errors(observation))
    errors.extend(protocol_client.validate_protocol_observation(
        observation,
        require_pass_evidence=not strict,
    ))
    if observation.get("requested_protocol") != protocol:
        errors.append("requested_protocol differs from the selected profile")
    if observation.get("downstream_protocol") != protocol:
        errors.append("downstream_protocol differs from the selected profile")
    _match(connector, observation.get("connector"), "connector", errors)
    _match(integration_mode, observation.get("integration_mode"), "integration_mode", errors)
    _match(run_id, observation.get("run_id"), "run_id", errors)
    _match(transaction_id, observation.get("transaction_id"), "transaction_id", errors)
    _match(rule_id, observation.get("rule_id"), "rule_id", errors)
    _match(phase, observation.get("phase"), "phase", errors)
    return errors


def _expected_stream_errors(
    observation: Mapping[str, Any], *, expected_stream_id: int | None,
) -> list[str]:
    if expected_stream_id is None:
        return []
    if (
        isinstance(expected_stream_id, bool)
        or not isinstance(expected_stream_id, int)
        or expected_stream_id < 0
    ):
        return ["expected_stream_id must be a non-negative integer"]
    if observation.get("stream_id") != expected_stream_id:
        return ["stream_id does not match expected provenance"]
    return []


def _expected_upstream_errors(
    observation: Mapping[str, Any], *, expected_upstream_protocol: str | None,
) -> list[str]:
    if expected_upstream_protocol is None:
        return []
    if expected_upstream_protocol not in protocol_client.CANONICAL_PROTOCOLS:
        return ["expected_upstream_protocol is not canonical"]
    if observation.get("upstream_protocol") != expected_upstream_protocol:
        return ["upstream_protocol does not match expected provenance"]
    return []


def _expected_transport_case_errors(
    observation: Mapping[str, Any], *, expected_transport_case_id: str | None,
) -> list[str]:
    if expected_transport_case_id is None:
        return []
    if not protocol_client._BOUNDED_TOKEN.fullmatch(expected_transport_case_id):
        return ["expected_transport_case_id is not a bounded token"]
    if observation.get("transport_case_id") != expected_transport_case_id:
        return ["transport_case_id does not match expected provenance"]
    return []


def _expected_client_status_errors(
    observation: Mapping[str, Any], *, expected_client_status: int | None,
) -> list[str]:
    if expected_client_status is None:
        return []
    if (
        isinstance(expected_client_status, bool)
        or not isinstance(expected_client_status, int)
        or not 100 <= expected_client_status <= 999
    ):
        return ["expected_client_status must be an HTTP status integer"]
    observed_status = observation.get("http_status")
    if isinstance(observed_status, bool) or not isinstance(observed_status, int):
        return ["client observation has no response status matching the visible host status"]
    if observed_status != expected_client_status:
        return ["client status does not match the visible host status"]
    return []


def _expected_provenance_errors(
    observation: Mapping[str, Any],
    *,
    expected_client_status: int | None,
    expected_stream_id: int | None,
    expected_upstream_protocol: str | None,
    expected_transport_case_id: str | None,
) -> list[str]:
    errors = _expected_stream_errors(observation, expected_stream_id=expected_stream_id)
    errors.extend(_expected_upstream_errors(
        observation,
        expected_upstream_protocol=expected_upstream_protocol,
    ))
    errors.extend(_expected_transport_case_errors(
        observation,
        expected_transport_case_id=expected_transport_case_id,
    ))
    errors.extend(_expected_client_status_errors(
        observation,
        expected_client_status=expected_client_status,
    ))
    return errors


def _normal_evidence_errors(observation: Mapping[str, Any], followup_path: Path) -> list[str]:
    errors: list[str] = []
    if observation.get("status") != "PASS":
        errors.append("protocol client observation is not PASS")
    if followup_path.exists():
        followup, followup_errors = _read_json(followup_path)
        errors.extend(followup_errors)
        if followup is not None:
            errors.extend(_followup_safety_errors(followup))
    return errors


def _strict_primary_errors(observation: Mapping[str, Any], *, protocol: str) -> list[str]:
    errors: list[str] = []
    if observation.get("status") != "FAIL":
        errors.append("strict evidence requires a client-observed failed transfer")
    if observation.get("response_committed") is not True:
        errors.append("strict evidence requires response_committed=true")
    if observation.get("client_first_body_byte_visible") is not True:
        errors.append("strict evidence requires a client-visible first body byte")
    if observation.get("response_complete") is not False:
        errors.append("strict evidence requires an incomplete response")
    stream_id = observation.get("stream_id")
    if isinstance(stream_id, bool) or not isinstance(stream_id, int) or stream_id < 0:
        errors.append("strict evidence requires a non-negative stream_id")
    observed_status = observation.get("http_status")
    if isinstance(observed_status, bool) or not isinstance(observed_status, int):
        errors.append("strict evidence requires a client-observed response status")
    if observation.get("stream_reset") is not True:
        errors.append("strict evidence requires stream_reset=true")
    if observation.get("stream_reset_code") in (None, ""):
        errors.append("strict evidence requires a stream_reset_code")
    if observation.get("fallback_used") is not False:
        errors.append("strict evidence must not use a protocol fallback")
    if observation.get("negotiated_protocol") != protocol:
        errors.append("strict evidence negotiated protocol differs")
    expected_transport = {"h2": "tls_tcp", "h2c": "tcp", "h3": "quic_udp"}[protocol]
    if observation.get("transport") != expected_transport:
        errors.append("strict evidence transport differs from the selected profile")
    return errors


def _strict_transport_errors(observation: Mapping[str, Any], *, protocol: str) -> list[str]:
    errors: list[str] = []
    if protocol == "h2":
        if observation.get("alpn") != "h2":
            errors.append("strict HTTP/2 evidence requires alpn=h2")
    elif protocol == "h3":
        if observation.get("alpn") != "h3":
            errors.append("strict HTTP/3 evidence requires alpn=h3")
        if observation.get("quic_udp_observed") is not True:
            errors.append("strict HTTP/3 evidence requires QUIC/UDP observation")
        if observation.get("quic_connection_id_present") is not True:
            errors.append("strict HTTP/3 evidence requires QUIC CID presence only")
        if not isinstance(observation.get("quic_version"), str) or not observation["quic_version"]:
            errors.append("strict HTTP/3 evidence requires quic_version")
    return errors


def _strict_followup_errors(
    followup_path: Path, *, protocol: str, primary_observation: Mapping[str, Any],
) -> list[str]:
    followup, followup_errors = _read_json(followup_path)
    if followup is not None:
        followup_errors.extend(_validate_followup(
            followup,
            protocol=protocol,
            primary_observation=primary_observation,
        ))
    return followup_errors


def validate_protocol_artifacts(
    artifact_dir: Path,
    *,
    protocol: str,
    strict: bool = False,
    connector: str | None = None,
    integration_mode: str | None = None,
    run_id: str | None = None,
    transaction_id: str | None = None,
    rule_id: str | None = None,
    phase: str | None = None,
    expected_client_status: int | None = None,
    expected_stream_id: int | None = None,
    expected_upstream_protocol: str | None = None,
    expected_transport_case_id: str | None = None,
) -> list[str]:
    """Return evidence failures for one protocol client artifact directory."""

    errors: list[str] = []
    if protocol not in protocol_client.CANONICAL_PROTOCOLS:
        return ["protocol is not canonical"]
    if strict and protocol not in {"h2", "h2c", "h3"}:
        return ["strict protocol evidence is only valid for H2/H3"]
    if artifact_dir.is_symlink() or not artifact_dir.is_dir():
        return ["artifact directory is missing or unsafe"]
    text_artifacts, observation, artifact_errors = _read_required_artifacts(artifact_dir)
    errors.extend(artifact_errors)
    errors.extend(_text_artifact_errors(
        text_artifacts,
        protocol=protocol,
        require_correlation=expected_transport_case_id is not None,
    ))
    if observation is None:
        return sorted(dict.fromkeys(errors))
    errors.extend(_primary_observation_errors(
        observation,
        protocol=protocol,
        strict=strict,
        connector=connector,
        integration_mode=integration_mode,
        run_id=run_id,
        transaction_id=transaction_id,
        rule_id=rule_id,
        phase=phase,
    ))
    errors.extend(_expected_provenance_errors(
        observation,
        expected_client_status=expected_client_status,
        expected_stream_id=expected_stream_id,
        expected_upstream_protocol=expected_upstream_protocol,
        expected_transport_case_id=expected_transport_case_id,
    ))
    followup_path = artifact_dir / FOLLOWUP_ARTIFACT
    if not strict:
        errors.extend(_normal_evidence_errors(observation, followup_path))
        return sorted(dict.fromkeys(errors))

    # A strict post-commit reset is a successful evidence outcome even though
    # curl necessarily reports a failed/incomplete transfer.  It cannot be
    # a plain protocol PASS or an invented final HTTP denial.
    errors.extend(_strict_primary_errors(observation, protocol=protocol))
    errors.extend(_strict_transport_errors(observation, protocol=protocol))
    errors.extend(_strict_followup_errors(
        followup_path,
        protocol=protocol,
        primary_observation=observation,
    ))
    return sorted(dict.fromkeys(errors))


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate forced protocol client evidence")
    parser.add_argument("--artifact-dir", required=True, type=Path)
    parser.add_argument("--protocol", required=True, choices=sorted(protocol_client.CANONICAL_PROTOCOLS))
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--connector")
    parser.add_argument("--integration-mode")
    parser.add_argument("--run-id")
    parser.add_argument("--transaction-id")
    parser.add_argument("--rule-id")
    parser.add_argument("--phase")
    parser.add_argument("--expected-client-status", type=int)
    parser.add_argument("--expected-stream-id", type=int)
    parser.add_argument(
        "--expected-upstream-protocol",
        choices=sorted(protocol_client.CANONICAL_PROTOCOLS),
    )
    parser.add_argument("--expected-transport-case-id")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    errors = validate_protocol_artifacts(
        args.artifact_dir,
        protocol=args.protocol,
        strict=args.strict,
        connector=args.connector,
        integration_mode=args.integration_mode,
        run_id=args.run_id,
        transaction_id=args.transaction_id,
        rule_id=args.rule_id,
        phase=args.phase,
        expected_client_status=args.expected_client_status,
        expected_stream_id=args.expected_stream_id,
        expected_upstream_protocol=args.expected_upstream_protocol,
        expected_transport_case_id=args.expected_transport_case_id,
    )
    if errors:
        for error in errors:
            print(f"protocol-evidence: {error}", file=sys.stderr)
        return 1
    print(f"protocol-evidence: pass artifact_dir={args.artifact_dir}")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
