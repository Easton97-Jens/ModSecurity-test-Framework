from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = connector_root()
profiles = load_source(source_path('ci/runtime/lifecycle/resolve-full-lifecycle-profile.py', root=ROOT))


class FullLifecycleProfilesTest(unittest.TestCase):
    def capability_manifest(self, connector: str) -> dict[str, object]:
        return {
            "schema_version": 1,
            "connector": connector,
            "host_name": "compatibility-host",
            "integration_mode": "compatibility-mode",
            "host_model_constraints": [],
            "capabilities": {
                name: {"state": "verified", "reason": "compatibility fixture"}
                for name in (
                    "phase1",
                    "phase2",
                    "phase3",
                    "phase4",
                    "deny",
                    "request_headers",
                    "request_body_buffered",
                    "request_body_incremental_ingest",
                    "response_headers",
                    "response_body_buffered",
                    "response_body_incremental_ingest",
                    "no_full_response_buffering",
                    "first_byte_before_response_end",
                    "transaction_id",
                    "event_jsonl",
                    "transport_metadata",
                    "connection_metadata",
                    "phase4_rule_evaluation",
                    "phase4_end_of_stream_evaluation",
                    "redirect",
                    "log_only",
                    "late_intervention",
                    "late_intervention_log_only",
                    "late_intervention_status_metadata",
                )
            },
            "evidence_stages": {},
        }

    def test_every_connector_has_one_explicit_native_profile(self) -> None:
        self.assertEqual(
            set(profiles.PROFILE_BY_CONNECTOR),
            {"apache", "nginx", "haproxy", "envoy", "traefik", "lighttpd"},
        )
        for connector, profile in profiles.PROFILE_BY_CONNECTOR.items():
            payload = self.capability_manifest(connector)
            result = profiles.effective_manifest(payload, profile)
            self.assertEqual(profile, result["full_lifecycle_profile"])
            self.assertNotEqual(result["integration_mode"], "compatibility-mode")

    def test_patched_profile_metadata_reads_the_connector_version_contracts(self) -> None:
        self.assertIn(profiles.HAPROXY_VERSION, profiles.PROFILE_METADATA["haproxy"]["host_name"])
        self.assertIn(profiles.HAPROXY_VERSION, profiles.PROFILE_METADATA["haproxy"]["reason"])
        self.assertIn(profiles.LIGHTTPD_VERSION, profiles.PROFILE_METADATA["lighttpd"]["host_name"])
        self.assertIn(profiles.LIGHTTPD_VERSION, profiles.PROFILE_METADATA["lighttpd"]["reason"])

    def test_non_native_profiles_are_conservatively_downgraded(self) -> None:
        expected_phase4 = {
            "haproxy": "implemented_not_asserted",
            "envoy": "implemented_not_asserted",
            "traefik": "implemented_not_asserted",
            "lighttpd": "implemented_not_asserted",
        }
        for connector, phase4_state in expected_phase4.items():
            result = profiles.effective_manifest(
                self.capability_manifest(connector), profiles.PROFILE_BY_CONNECTOR[connector]
            )
            self.assertEqual(
                phase4_state,
                result["capabilities"]["phase4"]["state"],
            )
            self.assertNotEqual(result["capabilities"]["phase1"]["state"], "verified")

    def test_common_bridge_profiles_select_only_unpromoted_native_capabilities(self) -> None:
        for connector in ("envoy", "traefik"):
            result = profiles.effective_manifest(
                self.capability_manifest(connector), profiles.PROFILE_BY_CONNECTOR[connector]
            )
            for capability in (
                "request_headers", "request_body_incremental_ingest",
                "response_headers", "response_body_incremental_ingest",
                "phase1", "phase2", "phase3", "phase4",
                "late_intervention_log_only", "event_jsonl",
            ):
                self.assertEqual(
                    result["capabilities"][capability]["state"],
                    "implemented_not_asserted",
                    f"{connector}/{capability}",
                )
            self.assertNotEqual(
                result["capabilities"]["phase4"]["state"], "verified"
            )

    def test_patched_lighttpd_keeps_entity_body_lifecycle_selectable(self) -> None:
        result = profiles.effective_manifest(
            self.capability_manifest("lighttpd"), profiles.PROFILE_BY_CONNECTOR["lighttpd"]
        )
        for capability in (
            "deny", "response_body_buffered", "response_body_incremental_ingest",
            "phase4", "phase4_rule_evaluation", "phase4_end_of_stream_evaluation",
            "late_intervention_log_only", "first_byte_before_response_end",
        ):
            with self.subTest(capability=capability):
                self.assertEqual(result["capabilities"][capability]["state"], "implemented_not_asserted")

    def test_wrong_connector_profile_is_rejected_and_write_is_atomic(self) -> None:
        payload = self.capability_manifest("envoy")
        with self.assertRaisesRegex(ValueError, "invalid full-lifecycle profile"):
            profiles.effective_manifest(payload, "native-htx-filter")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "nested" / "effective.json"
            profiles.write_json_atomically(
                root,
                output,
                profiles.effective_manifest(payload, "ext_proc"),
            )
            loaded = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(loaded["full_lifecycle_profile"], "ext_proc")



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
