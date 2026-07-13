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
    (root / "client-version.txt").write_text(
        "curl 8.1.0 (test) libcurl/8.1.0\nFeatures: HTTP2 HTTP3\n",
        encoding="utf-8",
    )
    (root / "client-features.txt").write_text(
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
        encoding="utf-8",
    )
    (root / "client-command.txt").write_text(
        f"curl --silent --fail-with-body --output /dev/null --header [redacted] {protocol_flag} https://localhost/probe\n",
        encoding="utf-8",
    )
    (root / "client-protocol-observation.json").write_text(
        json.dumps(observation), encoding="utf-8"
    )
    if followup:
        (root / "client-followup-observation.json").write_text(
            json.dumps(
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
                }
            ),
            encoding="utf-8",
        )


class ProtocolEvidenceTest(unittest.TestCase):
    def test_strict_h3_requires_client_visible_reset_and_followup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
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
        with tempfile.TemporaryDirectory() as temporary:
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
        with tempfile.TemporaryDirectory() as temporary:
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
            followup_path = root / "client-followup-observation.json"
            followup = json.loads(followup_path.read_text(encoding="utf-8"))
            followup["transport_case_id"] = observation["transport_case_id"]
            followup_path.write_text(json.dumps(followup), encoding="utf-8")
            errors = check_protocol_evidence.validate_protocol_artifacts(
                root, protocol="h3", strict=True,
            )
            self.assertTrue(any("distinct bound transport_case_id" in error for error in errors))

    def test_rejects_a_client_command_that_did_not_force_h3(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
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
            (root / "client-command.txt").write_text(
                "curl --silent --fail-with-body --output /dev/null https://localhost/probe\n",
                encoding="utf-8",
            )
            errors = check_protocol_evidence.validate_protocol_artifacts(root, protocol="h3")
            self.assertTrue(any("does not force" in error for error in errors))

    def test_normal_evidence_requires_an_executed_command_and_matching_status(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
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
            (root / "client-command.txt").write_text("not executed\n", encoding="utf-8")
            errors = check_protocol_evidence.validate_protocol_artifacts(
                root,
                protocol="h3",
                expected_client_status=200,
            )
            self.assertTrue(any("requires an executed" in error for error in errors))
            self.assertTrue(any("client status does not match" in error for error in errors))

    def test_rejects_raw_connection_id_in_a_command_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
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
            (root / "client-command.txt").write_text(
                "curl --silent --fail-with-body --output /dev/null --http3-only "
                "--quic-cid=deadbeef https://localhost/probe\n",
                encoding="utf-8",
            )
            errors = check_protocol_evidence.validate_protocol_artifacts(root, protocol="h3")
            self.assertTrue(any("raw connection-ID argument" in error for error in errors))

    def test_binds_stream_and_upstream_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
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
        with tempfile.TemporaryDirectory() as temporary:
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
            followup_path = root / "client-followup-observation.json"
            followup = json.loads(followup_path.read_text(encoding="utf-8"))
            followup["transport"] = "tls_tcp"
            followup["response_body"] = "must-not-persist"
            followup_path.write_text(json.dumps(followup), encoding="utf-8")
            errors = check_protocol_evidence.validate_protocol_artifacts(
                root, protocol="h3", strict=True,
            )
            self.assertTrue(any("follow-up has unsupported fields" in error for error in errors))
            self.assertTrue(any("forbidden payload" in error for error in errors))
            self.assertTrue(any("does not match primary observation" in error for error in errors))

    def test_optional_normal_followup_is_still_payload_checked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
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
            followup_path = root / "client-followup-observation.json"
            followup = json.loads(followup_path.read_text(encoding="utf-8"))
            followup["quic_cid"] = "raw-cid"
            followup_path.write_text(json.dumps(followup), encoding="utf-8")
            errors = check_protocol_evidence.validate_protocol_artifacts(root, protocol="h3")
            self.assertTrue(any("follow-up has unsupported fields" in error for error in errors))
            self.assertTrue(any("connection-ID" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
