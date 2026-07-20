from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("protocol_client", ROOT / "ci/checks/protocol/protocol_client.py")
assert SPEC is not None and SPEC.loader is not None
protocol_client = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = protocol_client
SPEC.loader.exec_module(protocol_client)


ALL_OPTIONS = frozenset(
    {
        "--http1.1",
        "--http2",
        "--http2-prior-knowledge",
        "--http3-only",
        "--fail-with-body",
        "--header",
        "--max-time",
        "--output",
        "--request",
        "--show-error",
        "--silent",
        "--write-out",
    }
)


def inspection(*features: str) -> object:
    return protocol_client.CurlInspection(
        executable="curl",
        version_text="curl 8.1.0\nFeatures: " + " ".join(features) + "\n",
        version=(8, 1, 0),
        features=frozenset(features),
        options=ALL_OPTIONS,
        version_returncode=0,
        help_returncode=0,
    )


class ProtocolClientTest(unittest.TestCase):
    def test_inspect_curl_treats_os_errors_as_an_unavailable_client(self) -> None:
        with mock.patch.object(protocol_client, "_run_process", side_effect=PermissionError):
            result = protocol_client.inspect_curl("unavailable-curl")

        self.assertEqual("unavailable-curl", result.executable)
        self.assertEqual("curl_executable_unavailable", result.error)
        self.assertIsNone(result.version_returncode)

    def test_h3_uses_http3_only_and_complete_provenance_can_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            sidecar = directory / "h3-observation.json"
            sidecar.write_text(
                json.dumps(
                    {
                        "stream_id": 4,
                        "quic_udp_observed": True,
                        "quic_connection_id_present": True,
                        "alpn": "h3",
                        "quic_version": "v1",
                    }
                ),
                encoding="utf-8",
            )
            completed = subprocess.CompletedProcess(
                args=["curl"],
                returncode=0,
                stdout=json.dumps(
                    {
                        "response_code": 200,
                        "http_version": "3",
                        "size_download": 0,
                        "content_length_download": 0,
                    }
                )
                + "\n",
                stderr="",
            )
            config = protocol_client.ClientConfig(
                url="https://localhost:8443/probe",
                protocol="h3",
                artifact_dir=directory,
                observation_sidecar=sidecar,
                transport_case_id="case-h3-negotiated",
            )
            with mock.patch.object(protocol_client, "inspect_curl", return_value=inspection("HTTP2", "HTTP3")), mock.patch.object(
                protocol_client, "_run_process", return_value=completed
            ):
                result = protocol_client.run_protocol_client(config)

            self.assertEqual("PASS", result.observation["status"])
            self.assertIn("--http3-only", result.command)
            self.assertNotIn("--http3", result.command)
            self.assertEqual("h3", result.observation["negotiated_protocol"])
            self.assertEqual("quic_udp", result.observation["transport"])
            self.assertFalse(result.observation["fallback_used"])
            self.assertEqual("case-h3-negotiated", result.observation["transport_case_id"])
            self.assertIn("X-MSConnector-Transport-Case: case-h3-negotiated", result.command)
            command_artifact = (directory / "client-command.txt").read_text(encoding="utf-8")
            feature_artifact = (directory / "client-features.txt").read_text(encoding="utf-8")
            self.assertIn("--header '[redacted]'", command_artifact)
            self.assertNotIn("case-h3-negotiated", command_artifact)
            self.assertIn("--header", feature_artifact)

    def test_missing_http3_feature_is_blocked_and_still_writes_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            config = protocol_client.ClientConfig(
                url="https://localhost:8443/probe",
                protocol="h3",
                artifact_dir=directory,
                transport_case_id="case-h3-preflight",
            )
            with mock.patch.object(protocol_client, "inspect_curl", return_value=inspection("HTTP2")), mock.patch.object(
                protocol_client, "_run_process"
            ) as execute:
                result = protocol_client.run_protocol_client(config)

            self.assertEqual("BLOCKED", result.observation["status"])
            self.assertEqual("client_http3_unsupported", result.observation["reason"])
            execute.assert_not_called()
            for name in (
                "client-version.txt",
                "client-features.txt",
                "client-command.txt",
                "client-protocol-observation.json",
            ):
                self.assertTrue((directory / name).is_file(), name)

    def test_command_and_observation_artifacts_do_not_persist_payload_or_stderr(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            body = directory / "request-body.txt"
            body.write_text("request-secret", encoding="utf-8")
            completed = subprocess.CompletedProcess(
                args=["curl"],
                returncode=0,
                stdout=json.dumps(
                    {
                        "response_code": 204,
                        "http_version": "1.1",
                        "size_download": 0,
                    }
                )
                + "\n",
                stderr="response-secret-must-not-be-persisted",
            )
            config = protocol_client.ClientConfig(
                url="https://localhost:8443/probe?token=secret-query",
                protocol="http1",
                artifact_dir=directory,
                headers=("Authorization: Bearer request-secret",),
                data_file=body,
            )
            option_set = ALL_OPTIONS | {"--data-binary", "--header"}
            h1_inspection = protocol_client.CurlInspection(
                executable="curl",
                version_text="curl 8.1.0\nFeatures: HTTP2\n",
                version=(8, 1, 0),
                features=frozenset({"HTTP2"}),
                options=option_set,
                version_returncode=0,
                help_returncode=0,
            )
            with mock.patch.object(protocol_client, "inspect_curl", return_value=h1_inspection), mock.patch.object(
                protocol_client, "_run_process", return_value=completed
            ):
                result = protocol_client.run_protocol_client(config)

            self.assertEqual("PASS", result.observation["status"])
            combined = "\n".join(
                (directory / name).read_text(encoding="utf-8")
                for name in (
                    "client-version.txt",
                    "client-features.txt",
                    "client-command.txt",
                    "client-protocol-observation.json",
                )
            )
            for forbidden in (
                "request-secret",
                "response-secret-must-not-be-persisted",
                "secret-query",
            ):
                self.assertNotIn(forbidden, combined)
            self.assertIn("[redacted]", (directory / "client-command.txt").read_text())

    def test_h2_fallback_is_a_failure_not_a_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            completed = subprocess.CompletedProcess(
                args=["curl"],
                returncode=0,
                stdout=json.dumps(
                    {
                        "response_code": 200,
                        "http_version": "1.1",
                        "size_download": 0,
                    }
                )
                + "\n",
                stderr="",
            )
            config = protocol_client.ClientConfig(
                url="https://localhost:8443/probe",
                protocol="h2",
                artifact_dir=directory,
                stream_id=1,
                transport_case_id="case-h2-fallback",
            )
            with mock.patch.object(protocol_client, "inspect_curl", return_value=inspection("HTTP2")), mock.patch.object(
                protocol_client, "_run_process", return_value=completed
            ):
                result = protocol_client.run_protocol_client(config)

            self.assertEqual("FAIL", result.observation["status"])
            self.assertTrue(result.observation["fallback_used"])
            self.assertEqual("protocol_fallback_observed", result.observation["reason"])

    def test_modern_probe_requires_a_transport_case_token(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            config = protocol_client.ClientConfig(
                url="https://localhost:8443/probe",
                protocol="h2",
                artifact_dir=directory,
                stream_id=1,
            )
            with mock.patch.object(
                protocol_client, "inspect_curl", return_value=inspection("HTTP2")
            ), mock.patch.object(protocol_client, "_run_process") as execute:
                result = protocol_client.run_protocol_client(config)

            self.assertEqual("NOT_EXECUTED", result.observation["status"])
            self.assertEqual("invalid_client_configuration", result.observation["reason"])
            execute.assert_not_called()

    def test_caller_cannot_override_or_indirect_the_transport_correlation_header(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for header in (
                "x-msconnector-transport-case: attacker-token",
                "X-MSConnector-Transport-Case;",
                "@attacker-controlled-headers.txt",
            ):
                with self.subTest(header=header):
                    config = protocol_client.ClientConfig(
                        url="https://localhost:8443/probe",
                        protocol="h2",
                        artifact_dir=directory,
                        stream_id=1,
                        transport_case_id="case-h2-owned-header",
                        headers=(header,),
                    )
                    with mock.patch.object(
                        protocol_client, "inspect_curl", return_value=inspection("HTTP2")
                    ), mock.patch.object(protocol_client, "_run_process") as execute:
                        result = protocol_client.run_protocol_client(config)

                    self.assertEqual("NOT_EXECUTED", result.observation["status"])
                    self.assertEqual("invalid_client_configuration", result.observation["reason"])
                    execute.assert_not_called()

    def test_pass_evidence_reports_h3_gaps_in_canonical_order(self) -> None:
        observation = {
            "requested_protocol": "h3",
            "downstream_protocol": "h3",
            "negotiated_protocol": "h3",
            "transport": None,
            "fallback_used": False,
        }

        self.assertEqual(
            [
                "missing transport",
                "missing stream_id",
                "missing alpn",
                "missing quic_udp_observed",
                "missing quic_connection_id_present",
            ],
            protocol_client.validate_protocol_observation(
                observation, require_pass_evidence=True
            ),
        )

    def test_optional_followup_writes_a_payload_free_health_observation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            completed = subprocess.CompletedProcess(
                args=["curl"],
                returncode=0,
                stdout=json.dumps(
                    {
                        "response_code": 200,
                        "http_version": "1.1",
                        "size_download": 4,
                        "content_length_download": 4,
                    }
                ) + "\n",
                stderr="",
            )
            config = protocol_client.ClientConfig(
                url="https://localhost:8443/primary?secret=one",
                protocol="http1",
                artifact_dir=directory,
                transport_case_id="case-followup-primary",
                followup_url="https://localhost:8443/health?secret=two",
            )
            with mock.patch.object(
                protocol_client, "inspect_curl", return_value=inspection("HTTP2")
            ), mock.patch.object(
                protocol_client, "_run_process", side_effect=[completed, completed]
            ):
                result = protocol_client.run_protocol_client(config)

            self.assertEqual("PASS", result.observation["status"])
            followup = json.loads(
                (directory / "client-followup-observation.json").read_text(encoding="utf-8")
            )
            self.assertEqual("PASS", followup["status"])
            self.assertEqual(200, followup["http_status"])
            self.assertEqual(
                protocol_client.derive_followup_transport_case_id("case-followup-primary"),
                followup["transport_case_id"],
            )
            self.assertNotEqual("case-followup-primary", followup["transport_case_id"])
            self.assertEqual(
                result.observation["target_authority_sha256"],
                followup["target_authority_sha256"],
            )
            self.assertNotIn("url", followup)
            self.assertNotIn("secret", json.dumps(followup))


if __name__ == "__main__":
    unittest.main()
