"""Closed source dependencies; no runtime or artifact-build proof."""
import unittest

from tests.runners import nginx_native_operation_bundle as bundle


class NativeSourceDependencyTests(unittest.TestCase):
    def test_all_native_routes_seal_actual_mapping_and_caller_dependencies(self):
        required = {
            "framework:ci/checks/catalog/no_crs_baseline.py",
            "framework:tests/runners/nginx_native_operation_projection.py",
            "framework:tests/runners/nginx_native_operation_contract.py",
            "framework:tests/runners/nginx_native_operation_authority.py",
            "framework:tests/runners/nginx_http11_framing.py",
            "framework:tests/runners/nginx_lifecycle_sequence.py",
            "framework:tests/runners/nginx_phase4_contracts.py",
            "framework:tests/runners/msconnector_models.py",
            "framework:tests/cases/no-crs-baseline/catalog.json",
            "parent:ci/runtime/lifecycle/collect-no-crs-source.py",
            "parent:ci/runtime/lifecycle/nginx_native_collection.py",
            "parent:ci/runtime/lifecycle/nginx_native_authority.py",
            "parent:ci/runtime/lifecycle/run-no-crs-baseline.sh",
            "parent:ci/runtime/lifecycle/run-nginx-selected-host.sh",
            "parent:ci/runtime/lifecycle/run-connector-stage.sh",
        }
        required.update("framework:tests/schemas/no-crs-baseline/" + name + ".schema.json"
                        for name in ("case-catalog", "case-result", "result", "manifest", "inventory", "event"))
        self.assertEqual(len(bundle.CASE_IDS), 42)
        for case_id in bundle.CASE_IDS:
            with self.subTest(case_id=case_id):
                self.assertLessEqual(required, bundle.required_source_paths(case_id))
                self.assertLessEqual(len(bundle.required_source_paths(case_id)), 64)


if __name__ == "__main__":
    unittest.main()
