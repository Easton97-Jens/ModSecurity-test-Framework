from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "no_crs_baseline", ROOT / "ci/checks/catalog/no_crs_baseline.py"
)
assert SPEC is not None
assert SPEC.loader is not None
no_crs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(no_crs)


class ProtocolSelectionScopeTest(unittest.TestCase):
    @staticmethod
    def capable_manifest() -> dict[str, object]:
        return {
            "capabilities": {
                name: {"state": "verified", "reason": "synthetic selection-only capability"}
                for name in no_crs.CAPABILITIES
            }
        }

    def test_http1_plan_excludes_only_h2_h3_host_cases(self) -> None:
        catalog = no_crs.load_catalog()
        plan = no_crs.select_cases(
            "nginx", self.capable_manifest(), catalog,
            artifact_profile="full_lifecycle", downstream_protocol="http1",
        )
        by_id = {case["case_id"]: case for case in plan["cases"]}
        self.assertEqual(plan["downstream_protocol"], "http1")
        self.assertEqual(by_id["allow_without_marker"]["selection_status"], "SELECTED")
        for case in no_crs.catalog_cases(catalog):
            request = case.get("request") or {}
            if request.get("protocol_profile") in {"h2", "h2c", "h3"}:
                with self.subTest(protocol_only_case=case["case_id"]):
                    self.assertEqual(
                        by_id[case["case_id"]]["selection_status"], "NOT_APPLICABLE"
                    )
        for case_id in (
            "transport_http2_if_supported",
            "protocol_h2_negotiated", "protocol_h2_no_http1_fallback",
            "protocol_h3_negotiated", "protocol_h3_quic_transport",
            "protocol_h3_no_h2_fallback", "protocol_h3_alt_svc_advertised",
            "h2_phase1_deny", "h2_phase3_deny", "h2_phase4_safe",
            "h3_phase1_deny", "h3_phase3_deny", "h3_phase4_safe",
        ):
            with self.subTest(case_id=case_id):
                self.assertEqual(by_id[case_id]["selection_status"], "NOT_APPLICABLE")

    def test_nginx_full_lifecycle_requires_explicit_downstream_protocol(self) -> None:
        with self.assertRaises(no_crs.ContractError):
            no_crs.select_cases(
                "nginx", self.capable_manifest(), no_crs.load_catalog(),
                artifact_profile="full_lifecycle",
            )

    def test_capable_h2_and_h3_plans_retain_the_matching_claims(self) -> None:
        catalog = no_crs.load_catalog()
        manifest = self.capable_manifest()
        h2 = no_crs.select_cases(
            "nginx", manifest, catalog,
            artifact_profile="full_lifecycle", downstream_protocol="h2",
        )
        h3 = no_crs.select_cases(
            "nginx", manifest, catalog,
            artifact_profile="full_lifecycle", downstream_protocol="h3",
        )
        h2_cases = {case["case_id"]: case for case in h2["cases"]}
        h3_cases = {case["case_id"]: case for case in h3["cases"]}
        self.assertEqual(h2_cases["protocol_h2_negotiated"]["selection_status"], "SELECTED")
        self.assertEqual(h2_cases["transport_http2_if_supported"]["selection_status"], "SELECTED")
        self.assertEqual(h2_cases["protocol_h3_negotiated"]["selection_status"], "NOT_APPLICABLE")
        self.assertEqual(h3_cases["protocol_h3_negotiated"]["selection_status"], "SELECTED")
        self.assertEqual(h3_cases["protocol_h2_negotiated"]["selection_status"], "NOT_APPLICABLE")

    def test_init_rejects_a_plan_for_another_downstream_protocol(self) -> None:
        catalog = no_crs.load_catalog()
        manifest = self.capable_manifest()
        plan = no_crs.select_cases(
            "nginx", manifest, catalog,
            artifact_profile="full_lifecycle", downstream_protocol="h2",
        )
        with self.assertRaises(no_crs.ContractError):
            no_crs.validate_plan_against_capabilities(
                plan, "nginx", manifest, catalog, "no_crs_baseline",
                "full_lifecycle", downstream_protocol="http1",
            )


if __name__ == "__main__":
    unittest.main()
