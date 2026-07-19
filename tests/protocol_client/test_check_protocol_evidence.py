from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "check_protocol_evidence", ROOT / "ci" / "checks" / "protocol" / "check_protocol_evidence.py"
)
assert SPEC is not None and SPEC.loader is not None
check_protocol_evidence = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = check_protocol_evidence
SPEC.loader.exec_module(check_protocol_evidence)

TEMPORARY_ROOT_PREFIX = "protocol-evidence-test-"
TEST_ARTIFACTS = frozenset(
    (*check_protocol_evidence.REQUIRED_ARTIFACTS, check_protocol_evidence.FOLLOWUP_ARTIFACT)
)


def temporary_artifact_directory() -> tempfile.TemporaryDirectory[str]:
    return tempfile.TemporaryDirectory(prefix=TEMPORARY_ROOT_PREFIX)


def task_owned_artifact_path(root: Path, artifact_name: str) -> Path:
    """Return a non-symlink artifact path below one direct temporary child."""

    temporary_parent = Path(tempfile.gettempdir()).resolve()
    resolved_root = root.resolve()
    if (
        root.is_symlink()
        or not root.is_dir()
        or not resolved_root.name.startswith(TEMPORARY_ROOT_PREFIX)
        or resolved_root.parent != temporary_parent
    ):
        raise ValueError("artifact root is not a direct task-owned TemporaryDirectory")
    if artifact_name not in TEST_ARTIFACTS:
        raise ValueError("artifact name is not a test-owned protocol artifact")
    unresolved_target = resolved_root / artifact_name
    if unresolved_target.is_symlink():
        raise ValueError("artifact target must not be a symlink")
    target = unresolved_target.resolve()
    if target.parent != resolved_root or target.name != artifact_name:
        raise ValueError("artifact target escapes its task-owned TemporaryDirectory")
    return target


def write_text_artifact(root: Path, artifact_name: str, value: str) -> None:
    task_owned_artifact_path(root, artifact_name).write_text(value, encoding="utf-8")


def read_json_artifact(root: Path, artifact_name: str) -> dict[str, object]:
    value = json.loads(task_owned_artifact_path(root, artifact_name).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def write_json_artifact(root: Path, artifact_name: str, value: dict[str, object]) -> None:
    write_text_artifact(root, artifact_name, json.dumps(value))


def write_bundle(root: Path, observation: dict[str, object], *, followup: bool = True) -> None:
    protocol = str(observation.get("requested_protocol", "h3"))
    required_feature = {"h2": "HTTP2", "h2c": "HTTP2", "h3": "HTTP3"}.get(protocol, "")
    protocol_flag = {
        "http1": "--http1.1",
        "h2": "--http2",
        "h2c": "--http2-prior-knowledge",
        "h3": "--http3-only",
    }[protocol]
    transport = {"h2": "tls_tcp", "h2c": "tcp", "h3": "quic_udp"}.get(protocol, "tls_tcp")
    primary_case_id = str(observation.setdefault("transport_case_id", "case-primary"))
    authority_hash = check_protocol_evidence.protocol_client.target_authority_sha256(
        "https://localhost/probe"
    )
    assert authority_hash is not None
    observation.setdefault("target_authority_sha256", authority_hash)
    write_text_artifact(
        root,
        check_protocol_evidence.CLIENT_VERSION_ARTIFACT,
        "curl 8.1.0 (test) libcurl/8.1.0\nFeatures: HTTP2 HTTP3\n",
    )
    write_text_artifact(
        root,
        check_protocol_evidence.CLIENT_FEATURES_ARTIFACT,
        "\n".join(
            (
                "curl_executable=curl",
                "curl_version=8.1.0",
                f"protocol={protocol}",
                "features=HTTP2,HTTP3",
                f"required_features={required_feature}",
                "missing_features=",
                "required_options=" + ",".join(
                    ("--fail-with-body", "--header", protocol_flag, "--max-time", "--output", "--request", "--show-error", "--silent", "--write-out")
                ),
                "missing_options=",
                "preflight_status=READY",
                "preflight_reason=",
                "writeout_mode=json",
                "",
            )
        ),
    )
    write_text_artifact(
        root,
        check_protocol_evidence.CLIENT_COMMAND_ARTIFACT,
        f"curl --silent --fail-with-body --output /dev/null --header [redacted] {protocol_flag} https://localhost/probe\n",
    )
    write_json_artifact(
        root,
        check_protocol_evidence.PRIMARY_OBSERVATION_ARTIFACT,
        observation,
    )
    if followup:
        write_json_artifact(
            root,
            check_protocol_evidence.FOLLOWUP_ARTIFACT,
            {
                "schema_version": 1,
                "status": "PASS",
                "reason": "healthy_independent_request",
                "transport_case_id": (
                    check_protocol_evidence.protocol_client
                    .derive_followup_transport_case_id(primary_case_id)
                ),
                "target_authority_sha256": authority_hash,
                "requested_protocol": protocol,
                "downstream_protocol": protocol,
                "negotiated_protocol": protocol,
                "transport": transport,
                "fallback_used": False,
                "http_status": 200,
                "response_complete": True,
                "curl_exit_code": 0,
                "transport_error": "none",
            },
        )


class ProtocolEvidenceTest(unittest.TestCase):
    def test_strict_h3_requires_client_visible_reset_and_followup(self) -> None:
        with temporary_artifact_directory() as temporary:
            root = Path(temporary)
            observation: dict[str, object] = {
                "schema_version": 1,
                "status": "FAIL",
                "requested_protocol": "h3",
                "downstream_protocol": "h3",
                "negotiated_protocol": "h3",
                "transport": "quic_udp",
                "alpn": "h3",
                "stream_id": 4,
                "fallback_used": False,
                "quic_udp_observed": True,
                "quic_connection_id_present": True,
                "quic_version": "v1",
                "stream_reset": True,
                "stream_reset_code": "H3_REQUEST_CANCELLED",
                "response_committed": True,
                "client_first_body_byte_visible": True,
                "response_complete": False,
                "http_status": 200,
                "curl_exit_code": 95,
                "transport_error": "h3_failure",
            }
            write_bundle(root, observation)
            self.assertEqual(
                [], check_protocol_evidence.validate_protocol_artifacts(
                    root, protocol="h3", strict=True
                )
            )

    def test_strict_evidence_rejects_missing_followup_and_raw_connection_id(self) -> None:
        with temporary_artifact_directory() as temporary:
            root = Path(temporary)
            observation: dict[str, object] = {
                "schema_version": 1,
                "status": "FAIL",
                "requested_protocol": "h3",
                "downstream_protocol": "h3",
                "negotiated_protocol": "h3",
                "transport": "quic_udp",
                "alpn": "h3",
                "stream_id": 4,
                "fallback_used": False,
                "quic_udp_observed": True,
                "quic_connection_id_present": True,
                "quic_version": "v1",
                "stream_reset": True,
                "stream_reset_code": "H3_REQUEST_CANCELLED",
                "response_committed": True,
                "client_first_body_byte_visible": True,
                "response_complete": False,
                "connection_id": "raw-cid",
            }
            write_bundle(root, observation, followup=False)
            errors = check_protocol_evidence.validate_protocol_artifacts(
                root, protocol="h3", strict=True
            )
            self.assertTrue(any("connection-ID" in error for error in errors))
            self.assertTrue(any("client-followup-observation.json" in error for error in errors))

    def test_strict_followup_requires_a_distinct_bound_correlation(self) -> None:
        with temporary_artifact_directory() as temporary:
            root = Path(temporary)
            observation: dict[str, object] = {
                "schema_version": 1,
                "status": "FAIL",
                "requested_protocol": "h3",
                "downstream_protocol": "h3",
                "negotiated_protocol": "h3",
                "transport": "quic_udp",
                "alpn": "h3",
                "stream_id": 4,
                "fallback_used": False,
                "quic_udp_observed": True,
                "quic_connection_id_present": True,
                "quic_version": "v1",
                "stream_reset": True,
                "stream_reset_code": "H3_REQUEST_CANCELLED",
                "response_committed": True,
                "client_first_body_byte_visible": True,
                "response_complete": False,
                "http_status": 200,
                "curl_exit_code": 95,
                "transport_error": "h3_failure",
            }
            write_bundle(root, observation)
            followup = read_json_artifact(root, check_protocol_evidence.FOLLOWUP_ARTIFACT)
            followup["transport_case_id"] = observation["transport_case_id"]
            write_json_artifact(root, check_protocol_evidence.FOLLOWUP_ARTIFACT, followup)
            errors = check_protocol_evidence.validate_protocol_artifacts(
                root, protocol="h3", strict=True,
            )
            self.assertTrue(any("distinct bound transport_case_id" in error for error in errors))

    def test_rejects_a_client_command_that_did_not_force_h3(self) -> None:
        with temporary_artifact_directory() as temporary:
            root = Path(temporary)
            observation: dict[str, object] = {
                "schema_version": 1,
                "status": "PASS",
                "requested_protocol": "h3",
                "downstream_protocol": "h3",
                "negotiated_protocol": "h3",
                "transport": "quic_udp",
                "alpn": "h3",
                "stream_id": 4,
                "fallback_used": False,
                "quic_udp_observed": True,
                "quic_connection_id_present": True,
                "quic_version": "v1",
            }
            write_bundle(root, observation, followup=False)
            write_text_artifact(
                root,
                check_protocol_evidence.CLIENT_COMMAND_ARTIFACT,
                "curl --silent --fail-with-body --output /dev/null https://localhost/probe\n",
            )
            errors = check_protocol_evidence.validate_protocol_artifacts(root, protocol="h3")
            self.assertTrue(any("does not force" in error for error in errors))

    def test_normal_evidence_requires_an_executed_command_and_matching_status(self) -> None:
        with temporary_artifact_directory() as temporary:
            root = Path(temporary)
            observation: dict[str, object] = {
                "schema_version": 1,
                "status": "PASS",
                "requested_protocol": "h3",
                "downstream_protocol": "h3",
                "negotiated_protocol": "h3",
                "transport": "quic_udp",
                "alpn": "h3",
                "stream_id": 4,
                "fallback_used": False,
                "quic_udp_observed": True,
                "quic_connection_id_present": True,
                "quic_version": "v1",
                "http_status": 403,
            }
            write_bundle(root, observation, followup=False)
            write_text_artifact(
                root,
                check_protocol_evidence.CLIENT_COMMAND_ARTIFACT,
                "not executed\n",
            )
            errors = check_protocol_evidence.validate_protocol_artifacts(
                root,
                protocol="h3",
                expected_client_status=200,
            )
            self.assertTrue(any("requires an executed" in error for error in errors))
            self.assertTrue(any("client status does not match" in error for error in errors))

    def test_rejects_raw_connection_id_in_a_command_artifact(self) -> None:
        with temporary_artifact_directory() as temporary:
            root = Path(temporary)
            observation: dict[str, object] = {
                "schema_version": 1,
                "status": "PASS",
                "requested_protocol": "h3",
                "downstream_protocol": "h3",
                "negotiated_protocol": "h3",
                "transport": "quic_udp",
                "alpn": "h3",
                "stream_id": 4,
                "fallback_used": False,
                "quic_udp_observed": True,
                "quic_connection_id_present": True,
                "quic_version": "v1",
            }
            write_bundle(root, observation, followup=False)
            write_text_artifact(
                root,
                check_protocol_evidence.CLIENT_COMMAND_ARTIFACT,
                "curl --silent --fail-with-body --output /dev/null --http3-only "
                "--quic-cid=deadbeef https://localhost/probe\n",
            )
            errors = check_protocol_evidence.validate_protocol_artifacts(root, protocol="h3")
            self.assertTrue(any("raw connection-ID argument" in error for error in errors))

    def test_binds_stream_and_upstream_provenance(self) -> None:
        with temporary_artifact_directory() as temporary:
            root = Path(temporary)
            observation: dict[str, object] = {
                "schema_version": 1,
                "status": "PASS",
                "requested_protocol": "h3",
                "downstream_protocol": "h3",
                "upstream_protocol": "http1",
                "transport_case_id": "case-h3-bound",
                "negotiated_protocol": "h3",
                "transport": "quic_udp",
                "alpn": "h3",
                "stream_id": 4,
                "fallback_used": False,
                "quic_udp_observed": True,
                "quic_connection_id_present": True,
                "quic_version": "v1",
                "http_status": 403,
            }
            write_bundle(root, observation, followup=False)
            self.assertEqual(
                [],
                check_protocol_evidence.validate_protocol_artifacts(
                    root,
                    protocol="h3",
                    expected_client_status=403,
                    expected_stream_id=4,
                    expected_upstream_protocol="http1",
                    expected_transport_case_id="case-h3-bound",
                ),
            )
            errors = check_protocol_evidence.validate_protocol_artifacts(
                root,
                protocol="h3",
                expected_stream_id=8,
                expected_upstream_protocol="h2",
                expected_transport_case_id="other-case",
            )
            self.assertTrue(any("stream_id does not match" in error for error in errors))
            self.assertTrue(any("upstream_protocol does not match" in error for error in errors))
            self.assertTrue(any("transport_case_id does not match" in error for error in errors))

    def test_followup_rejects_payload_fields_and_mismatched_provenance(self) -> None:
        with temporary_artifact_directory() as temporary:
            root = Path(temporary)
            observation: dict[str, object] = {
                "schema_version": 1,
                "status": "FAIL",
                "requested_protocol": "h3",
                "downstream_protocol": "h3",
                "negotiated_protocol": "h3",
                "transport": "quic_udp",
                "alpn": "h3",
                "stream_id": 4,
                "fallback_used": False,
                "quic_udp_observed": True,
                "quic_connection_id_present": True,
                "quic_version": "v1",
                "stream_reset": True,
                "stream_reset_code": "H3_REQUEST_CANCELLED",
                "response_committed": True,
                "client_first_body_byte_visible": True,
                "response_complete": False,
                "http_status": 200,
                "curl_exit_code": 95,
                "transport_error": "h3_failure",
            }
            write_bundle(root, observation)
            followup = read_json_artifact(root, check_protocol_evidence.FOLLOWUP_ARTIFACT)
            followup["transport"] = "tls_tcp"
            followup["response_body"] = "must-not-persist"
            write_json_artifact(root, check_protocol_evidence.FOLLOWUP_ARTIFACT, followup)
            errors = check_protocol_evidence.validate_protocol_artifacts(
                root, protocol="h3", strict=True,
            )
            self.assertTrue(any("follow-up has unsupported fields" in error for error in errors))
            self.assertTrue(any("forbidden payload" in error for error in errors))
            self.assertTrue(any("does not match primary observation" in error for error in errors))

    def test_optional_normal_followup_is_still_payload_checked(self) -> None:
        with temporary_artifact_directory() as temporary:
            root = Path(temporary)
            observation: dict[str, object] = {
                "schema_version": 1,
                "status": "PASS",
                "requested_protocol": "h3",
                "downstream_protocol": "h3",
                "negotiated_protocol": "h3",
                "transport": "quic_udp",
                "alpn": "h3",
                "stream_id": 4,
                "fallback_used": False,
                "quic_udp_observed": True,
                "quic_connection_id_present": True,
                "quic_version": "v1",
            }
            write_bundle(root, observation)
            followup = read_json_artifact(root, check_protocol_evidence.FOLLOWUP_ARTIFACT)
            followup["quic_cid"] = "raw-cid"
            write_json_artifact(root, check_protocol_evidence.FOLLOWUP_ARTIFACT, followup)
            errors = check_protocol_evidence.validate_protocol_artifacts(root, protocol="h3")
            self.assertTrue(any("follow-up has unsupported fields" in error for error in errors))
            self.assertTrue(any("connection-ID" in error for error in errors))

    def test_artifact_writer_rejects_a_non_child_temporary_root_before_writing(self) -> None:
        with temporary_artifact_directory() as temporary:
            root = Path(temporary)
            rejected_target = root.parent / check_protocol_evidence.FOLLOWUP_ARTIFACT

            with self.assertRaises(ValueError):
                write_json_artifact(root.parent, check_protocol_evidence.FOLLOWUP_ARTIFACT, {})

            self.assertFalse(rejected_target.exists())

    def test_artifact_writer_rejects_a_foreign_direct_temporary_child_before_writing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="foreign-protocol-evidence-") as temporary:
            root = Path(temporary)
            rejected_target = root / check_protocol_evidence.FOLLOWUP_ARTIFACT

            with self.assertRaises(ValueError):
                write_json_artifact(root, check_protocol_evidence.FOLLOWUP_ARTIFACT, {})

            self.assertFalse(rejected_target.exists())

    def test_oversized_version_artifact_is_rejected_before_validation(self) -> None:
        with temporary_artifact_directory() as temporary:
            root = Path(temporary)
            observation: dict[str, object] = {
                "schema_version": 1,
                "status": "PASS",
                "requested_protocol": "h3",
                "downstream_protocol": "h3",
                "negotiated_protocol": "h3",
                "transport": "quic_udp",
                "alpn": "h3",
                "stream_id": 4,
                "fallback_used": False,
                "quic_udp_observed": True,
                "quic_connection_id_present": True,
                "quic_version": "v1",
            }
            write_bundle(root, observation, followup=False)
            write_text_artifact(
                root,
                check_protocol_evidence.CLIENT_VERSION_ARTIFACT,
                "x" * (check_protocol_evidence.MAX_TEXT_BYTES + 1),
            )

            errors = check_protocol_evidence.validate_protocol_artifacts(root, protocol="h3")

            self.assertIn(
                f"artifact exceeds bounded size: {check_protocol_evidence.CLIENT_VERSION_ARTIFACT}",
                errors,
            )

    def test_feature_report_retains_duplicate_unknown_and_missing_field_errors(self) -> None:
        with temporary_artifact_directory() as temporary:
            root = Path(temporary)
            observation: dict[str, object] = {
                "schema_version": 1,
                "status": "PASS",
                "requested_protocol": "h3",
                "downstream_protocol": "h3",
                "negotiated_protocol": "h3",
                "transport": "quic_udp",
                "alpn": "h3",
                "stream_id": 4,
                "fallback_used": False,
                "quic_udp_observed": True,
                "quic_connection_id_present": True,
                "quic_version": "v1",
            }
            write_bundle(root, observation, followup=False)
            write_text_artifact(
                root,
                check_protocol_evidence.CLIENT_FEATURES_ARTIFACT,
                "curl_executable=curl\ncurl_executable=curl\nunknown_field=value\n",
            )

            errors = check_protocol_evidence.validate_protocol_artifacts(root, protocol="h3")

            self.assertTrue(any("repeats curl_executable" in error for error in errors))
            self.assertTrue(any("has unsupported fields" in error for error in errors))
            self.assertTrue(any("is missing fields" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
