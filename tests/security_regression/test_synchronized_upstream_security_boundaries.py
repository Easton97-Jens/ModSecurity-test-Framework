"""Security regressions for synchronized upstream network and file boundaries."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SYNCHRONIZED_UPSTREAM = ROOT / "tests" / "runners" / "synchronized_upstream.py"


def load_synchronized_upstream():
    spec = importlib.util.spec_from_file_location(
        "synchronized_upstream_security_regression", SYNCHRONIZED_UPSTREAM
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def valid_evidence() -> dict[str, object]:
    return {
        "schema_version": 1,
        "evidence_type": "synchronized_first_byte",
        "evidence_origin": "synthetic_harness",
        "promotion_eligible": False,
        "client_first_byte_received": True,
        "first_byte_before_response_end": True,
        "first_chunk_size": 7,
        "upstream_paused": True,
        "upstream_eos_sent_at_first_byte": False,
        "upstream_response_finished_at_first_byte": False,
        "response_committed": True,
        "body_bytes_seen": 7,
        "body_bytes_inspected": 7,
        "no_full_response_buffering": True,
        "connector_owned_full_response_buffer": False,
        "transport_protocol": "http1",
        "body_payload_persisted": False,
        "outcome": "PASS",
    }


def paused_record() -> dict[str, object]:
    return {
        "schema_version": 1,
        "evidence_type": "synchronized_upstream_paused",
        "first_chunk_size": 7,
        "upstream_paused": True,
        "upstream_eos_sent": False,
        "body_payload_persisted": False,
    }


def real_host_metadata() -> dict[str, object]:
    return {
        "response_committed": True,
        "body_bytes_seen": 7,
        "body_bytes_inspected": 7,
        "no_full_response_buffering": True,
        "connector_owned_full_response_buffer": False,
    }


class SynchronizedUpstreamSecurityBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.upstream_module = load_synchronized_upstream()

    def test_non_loopback_target_is_rejected_before_a_connection_is_opened(self) -> None:
        upstream = mock.Mock()
        with mock.patch.object(self.upstream_module.socket, "create_connection") as connect:
            with self.assertRaisesRegex(ValueError, "target_host"):
                self.upstream_module.run_client_barrier(
                    target_host="198.51.100.25",
                    target_port=443,
                    upstream=upstream,
                )
        connect.assert_not_called()

    def test_invalid_target_ports_are_rejected_before_a_connection_is_opened(self) -> None:
        for port in (False, 0, 65_536):
            with self.subTest(port=port):
                upstream = mock.Mock()
                with mock.patch.object(self.upstream_module.socket, "create_connection") as connect:
                    with self.assertRaisesRegex(ValueError, "target_port"):
                        self.upstream_module.run_client_barrier(
                            target_host="127.0.0.1",
                            target_port=port,
                            upstream=upstream,
                        )
                connect.assert_not_called()

    def test_listener_rejects_public_bind_addresses(self) -> None:
        with self.assertRaisesRegex(ValueError, "host"):
            self.upstream_module.SynchronizedStreamingUpstream(host="0.0.0.0")

    def test_control_paths_reject_outside_and_symlink_escapes_before_daemon_start(self) -> None:
        with tempfile.TemporaryDirectory(prefix="synchronized-upstream-root-") as root_name:
            with tempfile.TemporaryDirectory(prefix="synchronized-upstream-outside-") as outside_name:
                root = Path(root_name)
                outside = Path(outside_name)
                outside_output = outside / "evidence.json"
                evidence = valid_evidence()
                with self.assertRaisesRegex(ValueError, "evidence output path"):
                    self.upstream_module.write_evidence(
                        outside_output,
                        evidence,
                        control_root=root,
                    )
                self.assertFalse(outside_output.exists())

                escape = root / "escape"
                escape.symlink_to(outside, target_is_directory=True)
                with self.assertRaisesRegex(ValueError, "evidence output path"):
                    self.upstream_module.write_evidence(
                        escape / "evidence.json",
                        evidence,
                        control_root=root,
                    )

                with mock.patch.object(
                    self.upstream_module, "SynchronizedStreamingUpstream"
                ) as daemon:
                    with self.assertRaisesRegex(ValueError, "release_file"):
                        self.upstream_module.serve_with_control_files(
                            control_root=root,
                            ready_file=root / "ready.json",
                            release_file=outside / "release",
                        )
                daemon.assert_not_called()

    def test_merge_cli_accepts_only_control_root_files_and_preserves_local_flow(self) -> None:
        with tempfile.TemporaryDirectory(prefix="synchronized-upstream-cli-") as root_name:
            root = Path(root_name)
            paused = root / "paused.json"
            client_output = root / "client-output.bin"
            metadata = root / "metadata.json"
            output = root / "evidence.json"
            paused.write_text(json.dumps(paused_record()), encoding="utf-8")
            client_output.write_bytes(b"first-byte-only")
            metadata.write_text(json.dumps(real_host_metadata()), encoding="utf-8")

            result = self.upstream_module.main(
                [
                    "--control-root",
                    str(root),
                    "--merge-evidence",
                    "--paused-file",
                    str(paused),
                    "--client-first-byte-file",
                    str(client_output),
                    "--host-metadata-json",
                    str(metadata),
                    "--evidence-origin",
                    "real_host",
                    "--output",
                    str(output),
                ]
            )

            self.assertEqual(0, result)
            self.assertEqual(
                [],
                self.upstream_module.first_byte_evidence_errors(
                    json.loads(output.read_text(encoding="utf-8")),
                    require_real_host=True,
                    require_complete_proof=True,
                ),
            )

    def test_merge_cli_rejects_an_output_outside_its_control_root(self) -> None:
        with tempfile.TemporaryDirectory(prefix="synchronized-upstream-cli-") as root_name:
            with tempfile.TemporaryDirectory(prefix="synchronized-upstream-outside-") as outside_name:
                root = Path(root_name)
                paused = root / "paused.json"
                client_output = root / "client-output.bin"
                paused.write_text(json.dumps(paused_record()), encoding="utf-8")
                client_output.write_bytes(b"first-byte-only")
                outside_output = Path(outside_name) / "evidence.json"
                arguments = [
                    "--control-root",
                    str(root),
                    "--merge-evidence",
                    "--paused-file",
                    str(paused),
                    "--client-first-byte-file",
                    str(client_output),
                    "--output",
                    str(outside_output),
                ]

                with self.assertRaisesRegex(ValueError, "evidence output path"):
                    self.upstream_module.main(arguments)
                self.assertFalse(outside_output.exists())

    def test_loopback_upstream_remains_a_supported_local_test_target(self) -> None:
        with self.upstream_module.SynchronizedStreamingUpstream() as upstream:
            evidence = self.upstream_module.run_client_barrier(
                target_host=upstream.address.host,
                target_port=upstream.address.port,
                upstream=upstream,
                host_metadata=real_host_metadata(),
            )
        self.assertEqual(
            [],
            self.upstream_module.first_byte_evidence_errors(
                evidence, require_complete_proof=True
            ),
        )


if __name__ == "__main__":
    unittest.main()
