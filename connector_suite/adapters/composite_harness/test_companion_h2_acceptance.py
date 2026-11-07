"""Closed reader controls using a payload-free real native H2 metadata fixture."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from connector_suite.adapters.composite_harness import (
    companion_h2_acceptance as harness,
)


class CompanionReaderTests(unittest.TestCase):
    def test_post_cleanup_source_or_artifact_change_cannot_publish_pass(self):
        for failing_check in ("validate_sources", "admit_build"):
            with (
                self.subTest(check=failing_check),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                report = {
                    "status": "VALIDATED",
                    "cleanup": "PASS",
                    "uds_cleanup": "PASS",
                    "results": [{"status": "PASS"}],
                }
                with (
                    mock.patch.object(harness, "validate_sources"),
                    mock.patch.object(harness, "admit_build"),
                ):
                    with mock.patch.object(
                        harness,
                        failing_check,
                        side_effect=ValueError("changed after cleanup"),
                    ):
                        harness.finalize_report(None, root, report)
                saved = json.loads((root / "report.json").read_text())
                self.assertEqual(saved["status"], "FAIL")
                self.assertEqual(saved["results"], [])

    def test_cleanup_failure_discards_validated_results(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = {
                "status": "FAIL",
                "cleanup": "FAIL",
                "results": [{"status": "PASS"}],
            }
            with mock.patch.object(harness, "admit_build") as admission:
                harness.finalize_report(None, Path(temporary), report)
            admission.assert_not_called()
            self.assertEqual(report["results"], [])

    def setUp(self):
        self.proof = json.loads(
            (
                Path(__file__).with_name("fixtures") / "h2-allow-metadata.json"
            ).read_text()
        )

    def validate(self):
        return harness.validate_case(**self.proof)

    def test_actual_native_allow_metadata(self):
        self.assertEqual(self.validate()["status"], "PASS")

    def test_missing_traffic_fails(self):
        self.proof["wire"]["requests"] = []
        with self.assertRaises(ValueError):
            self.validate()

    def test_actual_native_binding_corruptions_fail(self):
        original = copy.deepcopy(self.proof)
        corruptions = (
            lambda proof: proof["access"].clear(),
            lambda proof: proof["records"].clear(),
            lambda proof: proof["upstream"].clear(),
            lambda proof: proof["wire"].update(alpn="http/1.1"),
            lambda proof: proof["wire"].update(tls_verified=False),
            lambda proof: proof["mapping"].update(target=proof["mapping"]["peer"]),
            lambda proof: proof["mapping"].update(
                target=proof["mapping"]["peer"], peer=proof["mapping"]["target"]
            ),
            lambda proof: proof["access"][0].update(
                stream_id=proof["access"][1]["stream_id"]
            ),
            lambda proof: proof["access"][0].update(connection_id=999),
            lambda proof: proof["access"][0].update(request_id="crossed"),
            lambda proof: proof["access"].append(copy.deepcopy(proof["access"][0])),
            lambda proof: proof["records"][0].update(request_path="native.ext_proc"),
            lambda proof: proof["records"][0].update(connector="traefik"),
            lambda proof: proof["records"].append(copy.deepcopy(proof["records"][0])),
            lambda proof: proof["wire"]["requests"][0].update(body_bytes=1),
            lambda proof: proof["wire"]["requests"][0].update(method="POST"),
            lambda proof: proof["wire"]["body_bytes"].update({"1": 0}),
            lambda proof: proof["wire"]["frames"].clear(),
            lambda proof: proof["upstream"].append(
                {"event": "fixture_error", "transaction_id": "writer"}
            ),
        )
        for mutation in corruptions:
            with self.subTest(control=corruptions.index(mutation)):
                self.proof = copy.deepcopy(original)
                mutation(self.proof)
                with self.assertRaises(ValueError):
                    self.validate()

    def test_failed_cleanup_is_rejected(self):
        terminal = next(
            row for row in self.proof["records"] if row["phase"] == "terminal"
        )
        terminal["cleanup_outcome"] = "failed"
        with self.assertRaises(ValueError):
            self.validate()

    def test_phase2_entity_and_common_rule_required(self):
        with self.assertRaises(ValueError):
            harness.validate_rule("phase2", [], [], {"target": "server-owned"})

    def test_held_case_requires_real_first_data_and_cleanup_barriers(self):
        with self.assertRaises(ValueError):
            harness.validate_terminal(
                "phase4_safe",
                self.proof["wire"],
                self.proof["records"],
                self.proof["mapping"],
            )

    def test_unattributed_cancel_cannot_substitute_ordinary_eos(self):
        with self.assertRaises(ValueError):
            harness.validate_terminal(
                "client_cancel",
                self.proof["wire"],
                self.proof["records"],
                self.proof["mapping"],
            )

    def test_real_strict_metadata_and_corruption_controls(self):
        self.proof = json.loads(
            (
                Path(__file__).with_name("fixtures") / "h2-strict-metadata.json"
            ).read_text()
        )
        self.assertEqual(self.validate()["status"], "PASS")
        original = copy.deepcopy(self.proof)
        corruptions = (
            lambda proof: proof["wire"]["terminal"]["3"].update(reset_code=8),
            lambda proof: proof["wire"]["body_bytes"].update({"3": 0}),
            lambda proof: proof["wire"].update(
                frames=[
                    row
                    for row in proof["wire"]["frames"]
                    if row.get("type") != "first_byte_before_eos"
                ]
            ),
            lambda proof: proof["wire"].update(
                frames=[row for row in proof["wire"]["frames"] if row.get("type") != 0]
            ),
            lambda proof: proof["records"].append(
                copy.deepcopy(
                    next(row for row in proof["records"] if row.get("phase") == "P4")
                )
            ),
            lambda proof: proof["common"][0].update(transaction_id="crossed"),
            lambda proof: proof["common"][0].update(integration_mode="ext_authz"),
        )
        for number, mutation in enumerate(corruptions):
            with self.subTest(control=number):
                self.proof = copy.deepcopy(original)
                mutation(self.proof)
                with self.assertRaises(ValueError):
                    self.validate()

    def test_real_cancel_requires_typed_transport_cleanup(self):
        self.proof = json.loads(
            (
                Path(__file__).with_name("fixtures") / "h2-cancel-metadata.json"
            ).read_text()
        )
        self.assertEqual(self.validate()["status"], "PASS")
        target = self.proof["mapping"]["target"]
        terminal = next(
            row
            for row in self.proof["records"]
            if row.get("phase") == "terminal" and row.get("decision_id") == target
        )
        terminal["reason"] = "response_end_of_stream"
        with self.assertRaises(ValueError):
            self.validate()

    def test_target_eos_absence_and_confounding_reset_are_rejected(self):
        for name in ("allow", "strict"):
            proof = json.loads(
                (
                    Path(__file__).with_name("fixtures") / f"h2-{name}-metadata.json"
                ).read_text()
            )
            self.proof = copy.deepcopy(proof)
            self.assertEqual(self.validate()["status"], "PASS")
            target = f"{proof['adapter']}-{proof['case']}-target"
            eos = next(
                row
                for row in proof["upstream"]
                if row.get("transaction_id") == target
                and row.get("event") == "upstream_eos"
            )
            controls = {
                "missing_eos": lambda value: value.update(
                    upstream=[row for row in value["upstream"] if row != eos]
                ),
                "unconfirmed_eos": lambda value: next(
                    row for row in value["upstream"] if row == eos
                ).update(eos_sent=False),
                "duplicate_eos": lambda value: value["upstream"].append(
                    copy.deepcopy(eos)
                ),
                "reset_instead_of_eos": lambda value: next(
                    row for row in value["upstream"] if row == eos
                ).update(event="upstream_abort", eos_sent=False),
                "reset_with_eos": lambda value: value["upstream"].append(
                    {
                        "event": "upstream_abort",
                        "transaction_id": target,
                        "eos_sent": False,
                    }
                ),
                "disconnect_with_eos": lambda value: value["upstream"].append(
                    {"event": "upstream_disconnected", "transaction_id": target}
                ),
            }
            for label, mutation in controls.items():
                with self.subTest(fixture=name, control=label):
                    self.proof = copy.deepcopy(proof)
                    mutation(self.proof)
                    with self.assertRaises(ValueError):
                        self.validate()

    def test_safe_target_requires_confirmed_eos_and_no_abort(self):
        target = f"{self.proof['adapter']}-allow-target"
        selected = [
            row for row in self.proof["upstream"] if row.get("transaction_id") == target
        ]
        harness.validate_target_eos("phase4_safe", selected)
        selected.append({"event": "upstream_abort", "eos_sent": False})
        with self.assertRaises(ValueError):
            harness.validate_target_eos("phase4_safe", selected)


if __name__ == "__main__":
    unittest.main()
