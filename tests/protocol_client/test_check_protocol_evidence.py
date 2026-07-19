from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import stat
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


def task_owned_artifact_directory_fd(root: Path) -> int:
    temporary_parent = Path(tempfile.gettempdir()).resolve()
    try:
        root_status = root.lstat()
        resolved_root = root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError("artifact root is not a direct task-owned TemporaryDirectory") from exc
    if (
        stat.S_ISLNK(root_status.st_mode)
        or not stat.S_ISDIR(root_status.st_mode)
        or not resolved_root.name.startswith(TEMPORARY_ROOT_PREFIX)
        or resolved_root.parent != temporary_parent
    ):
        raise ValueError("artifact root is not a direct task-owned TemporaryDirectory")
    try:
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    except AttributeError as exc:
        raise ValueError("artifact descriptor I/O requires no-follow support") from exc
    try:
        directory_fd = os.open(root, directory_flags)
    except OSError as exc:
        raise ValueError("artifact root cannot be opened safely") from exc
    try:
        directory_status = os.fstat(directory_fd)
    except OSError as exc:
        os.close(directory_fd)
        raise ValueError("artifact root cannot be opened safely") from exc
    if (
        not stat.S_ISDIR(directory_status.st_mode)
        or (directory_status.st_dev, directory_status.st_ino)
        != (root_status.st_dev, root_status.st_ino)
    ):
        os.close(directory_fd)
        raise ValueError("artifact root changed while opening it")
    return directory_fd


def open_task_owned_artifact(root: Path, artifact_name: str, *, writable: bool) -> int:
    if artifact_name not in TEST_ARTIFACTS:
        raise ValueError("artifact name is not a test-owned protocol artifact")
    directory_fd = task_owned_artifact_directory_fd(root)
    try:
        try:
            flags = (os.O_WRONLY if writable else os.O_RDONLY) | os.O_NOFOLLOW | os.O_NONBLOCK
        except AttributeError as exc:
            raise ValueError("artifact descriptor I/O requires no-follow support") from exc
        if writable:
            flags |= os.O_CREAT
        try:
            artifact_fd = os.open(artifact_name, flags, 0o600, dir_fd=directory_fd)
            try:
                if not stat.S_ISREG(os.fstat(artifact_fd).st_mode):
                    raise ValueError("artifact must be a regular file")
                if writable:
                    os.fchmod(artifact_fd, 0o600)
                    os.ftruncate(artifact_fd, 0)
                    os.lseek(artifact_fd, 0, os.SEEK_SET)
                return artifact_fd
            except Exception:
                os.close(artifact_fd)
                raise
        except OSError as exc:
            raise ValueError("artifact cannot be opened safely") from exc
    finally:
        os.close(directory_fd)


def write_text_artifact(root: Path, artifact_name: str, value: str) -> None:
    with os.fdopen(
        open_task_owned_artifact(root, artifact_name, writable=True),
        "w",
        encoding="utf-8",
    ) as artifact:
        artifact.write(value)


def read_json_artifact(root: Path, artifact_name: str) -> dict[str, object]:
    with os.fdopen(
        open_task_owned_artifact(root, artifact_name, writable=False),
        "r",
        encoding="utf-8",
    ) as artifact:
        value = json.load(artifact)
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

    def test_artifact_io_rejects_an_allowlisted_symlink_without_touching_its_target(self) -> None:
        with temporary_artifact_directory() as temporary:
            with tempfile.TemporaryDirectory(prefix="protocol-evidence-outside-") as outside_temporary:
                root = Path(temporary)
                outside = Path(outside_temporary) / "outside.json"
                outside.write_text('{"outside": true}', encoding="utf-8")
                artifact = root / check_protocol_evidence.FOLLOWUP_ARTIFACT
                artifact.symlink_to(outside)

                with self.assertRaises(ValueError):
                    write_json_artifact(root, check_protocol_evidence.FOLLOWUP_ARTIFACT, {})
                with self.assertRaises(ValueError):
                    read_json_artifact(root, check_protocol_evidence.FOLLOWUP_ARTIFACT)

                self.assertTrue(artifact.is_symlink())
                self.assertEqual('{"outside": true}', outside.read_text(encoding="utf-8"))

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
