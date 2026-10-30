from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = connector_root()


import modsecurity_connector_ci.lib.generated_report_utils as generated_report_utils

connector_capabilities = load_source(source_path('ci/evidence/collectors/connector_capabilities.py', root=ROOT))


class ConnectorCapabilitiesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifests, errors = connector_capabilities.load_manifests()
        assert not errors, errors

    def _results(self, run_id: str) -> dict[str, dict[str, object]]:
        results: dict[str, dict[str, object]] = {}
        for connector in connector_capabilities.CONNECTORS:
            states = {
                name: self.manifests[connector]["capabilities"][name]["state"]
                for name in connector_capabilities.CAPABILITY_NAMES
            }
            results[connector] = {
                "result": {
                    "status": "PASS",
                    "source_failure": False,
                    "cases_failed": 0,
                    "cases_blocked": 0,
                    "capabilities_verified": ["request_headers"],
                    "capability_states": states,
                },
                "path": f"{connector}/{run_id}/result.json",
                "sha256": "a" * 64,
            }
        return results

    def _git(self, root: Path, *arguments: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(root), *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return result.stdout.strip()

    def _init_repository(self, root: Path) -> str:
        root.mkdir(parents=True)
        self._git(root, "init", "--quiet")
        self._git(root, "config", "user.email", "tests@example.invalid")
        self._git(root, "config", "user.name", "Connector tests")
        (root / "tracked.txt").write_text(f"{root.name}\n", encoding="utf-8")
        self._git(root, "add", "tracked.txt")
        self._git(root, "commit", "--quiet", "-m", "fixture")
        return self._git(root, "rev-parse", "HEAD")

    def _record_framework_gitlink(self, connector_root: Path, framework_sha: str) -> None:
        self._git(
            connector_root,
            "update-index",
            "--add",
            "--cacheinfo",
            f"160000,{framework_sha},modules/ModSecurity-test-Framework",
        )
        self._git(connector_root, "commit", "--quiet", "-m", "record framework gitlink")

    def _framework_checkout_with_recorded_gitlink(
        self,
        root: Path,
    ) -> tuple[Path, Path, str]:
        framework_source = root / "framework-source"
        framework_sha = self._init_repository(framework_source)
        connector_root = root / "connector"
        self._init_repository(connector_root)
        framework_root = connector_root / "modules" / "ModSecurity-test-Framework"
        self._git(
            connector_root,
            "clone",
            "--quiet",
            str(framework_source),
            str(framework_root),
        )
        self._record_framework_gitlink(connector_root, framework_sha)
        return connector_root, framework_root, framework_sha

    def _write_generated_framework_input(
        self,
        connector_root: Path,
        *,
        run_id: str,
        connector_sha: str,
        framework_sha: str,
    ) -> Path:
        report = (
            connector_root
            / "reports/testing/generated/canonical/connector-capabilities.generated.json"
        )
        report.parent.mkdir(parents=True)
        report.write_text(
            json.dumps(
                {
                    "status": "generated",
                    "metadata": {
                        "verified_run_id": run_id,
                        "connector_sha": connector_sha,
                        "framework_sha": framework_sha,
                        "framework_gitlink_sha": framework_sha,
                        "framework_checkout_status": "checked_out",
                        "framework_gitlink_status": "matches_checkout",
                    },
                }
            ),
            encoding="utf-8",
        )
        return report

    def test_metadata_uses_gitlink_when_framework_is_not_checked_out(self) -> None:
        with tempfile.TemporaryDirectory(prefix="framework-provenance-") as temporary:
            root = Path(temporary)
            framework_source = root / "framework-source"
            framework_sha = self._init_repository(framework_source)
            connector_root = root / "connector"
            connector_sha = self._init_repository(connector_root)
            framework_root = connector_root / "modules" / "ModSecurity-test-Framework"
            self._record_framework_gitlink(connector_root, framework_sha)
            framework_root.mkdir(parents=True)

            metadata = generated_report_utils.build_metadata(
                generated_by="tests/test_connector_capabilities.py",
                make_target="test-framework-provenance",
                connector_root=connector_root,
                framework_root=framework_root,
            )
            checked_out_framework = connector_root / "modules" / "checked-out-framework"
            checked_out_sha = self._init_repository(checked_out_framework)
            checked_out_metadata = generated_report_utils.build_metadata(
                generated_by="tests/test_connector_capabilities.py",
                make_target="test-framework-provenance",
                connector_root=connector_root,
                framework_root=checked_out_framework,
            )

        self.assertNotEqual(connector_sha, framework_sha)
        self.assertEqual(metadata["framework_sha"], "unknown")
        self.assertEqual(framework_sha, metadata["framework_gitlink_sha"])
        self.assertEqual(metadata["framework_checkout_status"], "not_checked_out")
        self.assertEqual(metadata["framework_gitlink_status"], "not_checked_out")
        self.assertEqual(metadata["framework_working_tree_dirty"], "unknown")
        self.assertEqual(checked_out_sha, checked_out_metadata["framework_sha"])
        self.assertEqual(checked_out_metadata["framework_gitlink_sha"], "unknown")
        self.assertEqual(checked_out_metadata["framework_checkout_status"], "checked_out")
        self.assertEqual(checked_out_metadata["framework_gitlink_status"], "not_a_gitlink")
        self.assertEqual(checked_out_metadata["framework_working_tree_dirty"], "clean")

    def test_framework_provenance_marks_a_matching_gitlink_checkout(self) -> None:
        with tempfile.TemporaryDirectory(prefix="framework-provenance-match-") as temporary:
            root = Path(temporary)
            connector_root, framework_root, framework_sha = (
                self._framework_checkout_with_recorded_gitlink(root)
            )

            provenance = generated_report_utils.framework_provenance(
                connector_root, framework_root
            )

        self.assertEqual(framework_sha, provenance["sha"])
        self.assertEqual(framework_sha, provenance["gitlink_sha"])
        self.assertEqual(provenance["checkout_status"], "checked_out")
        self.assertEqual(provenance["gitlink_status"], "matches_checkout")
        self.assertEqual(provenance["working_tree_dirty"], "clean")

    def test_framework_provenance_marks_a_checkout_that_differs_from_its_gitlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="framework-provenance-mismatch-") as temporary:
            root = Path(temporary)
            connector_root, framework_root, framework_sha = (
                self._framework_checkout_with_recorded_gitlink(root)
            )
            self._git(framework_root, "config", "user.email", "tests@example.invalid")
            self._git(framework_root, "config", "user.name", "Connector tests")
            (framework_root / "tracked.txt").write_text("mismatch\n", encoding="utf-8")
            self._git(framework_root, "add", "tracked.txt")
            self._git(framework_root, "commit", "--quiet", "-m", "advance checkout")
            checkout_sha = self._git(framework_root, "rev-parse", "HEAD")

            provenance = generated_report_utils.framework_provenance(
                connector_root, framework_root
            )

        self.assertNotEqual(framework_sha, checkout_sha)
        self.assertEqual(checkout_sha, provenance["sha"])
        self.assertEqual(framework_sha, provenance["gitlink_sha"])
        self.assertEqual(provenance["checkout_status"], "checked_out")
        self.assertEqual(provenance["gitlink_status"], "checkout_mismatch")
        self.assertEqual(provenance["working_tree_dirty"], "clean")

    def test_input_record_marks_a_missing_framework_checkout_stale(self) -> None:
        run_id = "framework-provenance-fixture"
        with tempfile.TemporaryDirectory(prefix="framework-input-unpopulated-") as temporary:
            root = Path(temporary)
            framework_source = root / "framework-source"
            framework_sha = self._init_repository(framework_source)
            connector_root = root / "connector"
            self._init_repository(connector_root)
            framework_root = connector_root / "modules" / "ModSecurity-test-Framework"
            self._record_framework_gitlink(connector_root, framework_sha)
            connector_sha = self._git(connector_root, "rev-parse", "HEAD")
            report = self._write_generated_framework_input(
                connector_root,
                run_id=run_id,
                connector_sha=connector_sha,
                framework_sha=framework_sha,
            )
            provenance = generated_report_utils.framework_provenance(
                connector_root, framework_root
            )

            with mock.patch.dict("os.environ", {"VERIFIED_RUN_ID": run_id}):
                record = generated_report_utils.input_record(
                    report, connector_root, framework_root
                )

        self.assertEqual(record["status"], "stale")
        self.assertEqual(provenance["sha"], "unknown")
        self.assertEqual(framework_sha, provenance["gitlink_sha"])
        self.assertEqual(provenance["checkout_status"], "not_checked_out")
        self.assertEqual(provenance["gitlink_status"], "not_checked_out")
        self.assertEqual(framework_sha, record["framework_sha"])
        self.assertEqual(framework_sha, record["framework_gitlink_sha"])
        self.assertEqual(record["framework_checkout_status"], "checked_out")
        self.assertEqual(record["framework_gitlink_status"], "matches_checkout")
        self.assertIn("framework checkout is not verified (not_checked_out)", record["notes"])

    def test_input_record_marks_a_framework_gitlink_mismatch_stale(self) -> None:
        run_id = "framework-provenance-fixture"
        with tempfile.TemporaryDirectory(prefix="framework-input-mismatch-") as temporary:
            root = Path(temporary)
            connector_root, framework_root, framework_sha = (
                self._framework_checkout_with_recorded_gitlink(root)
            )
            self._git(framework_root, "config", "user.email", "tests@example.invalid")
            self._git(framework_root, "config", "user.name", "Connector tests")
            (framework_root / "tracked.txt").write_text("mismatch\n", encoding="utf-8")
            self._git(framework_root, "add", "tracked.txt")
            self._git(framework_root, "commit", "--quiet", "-m", "advance checkout")
            connector_sha = self._git(connector_root, "rev-parse", "HEAD")
            report = self._write_generated_framework_input(
                connector_root,
                run_id=run_id,
                connector_sha=connector_sha,
                framework_sha=framework_sha,
            )

            with mock.patch.dict("os.environ", {"VERIFIED_RUN_ID": run_id}):
                record = generated_report_utils.input_record(
                    report, connector_root, framework_root
                )

        self.assertEqual(record["status"], "stale")
        self.assertIn(
            "framework checkout differs from its recorded gitlink", record["notes"]
        )

    def test_static_payload_remains_source_contract_only(self) -> None:
        payload = connector_capabilities.aggregate_payload(self.manifests)
        self.assertFalse(payload["runtime_promotion"])
        self.assertNotIn("runtime_evidence", payload)

    def test_envoy_and_traefik_host_model_state_invariants_are_fail_closed(self) -> None:
        shared_capabilities = (
            "response_headers,response_body_buffered,response_body_streaming,phase3,"
            "phase4,phase4_rule_evaluation,phase4_pre_commit_deny,"
            "late_intervention,late_intervention_log_only,late_intervention_abort,"
            "late_intervention_status_metadata"
        ).split(",")
        cases = (
            ("envoy", "configured_not_exercised", ("request_body_buffered", "phase2")),
            ("envoy", "unsupported_by_host_model", shared_capabilities),
            ("traefik", "configured_not_exercised", ("request_body_buffered", "phase2")),
            (
                "traefik",
                "unsupported_by_host_model",
                ("request_body_streaming", *shared_capabilities),
            ),
        )
        replacements = {
            "configured_not_exercised": "not_implemented",
            "not_implemented": "configured_not_exercised",
            "unsupported_by_host_model": "not_implemented",
        }

        for connector, expected, capabilities in cases:
            with self.subTest(connector=connector, expected=expected):
                self.assertEqual(
                    connector_capabilities.validate_manifest(
                        connector, self.manifests[connector]
                    ),
                    [],
                )
            for capability in capabilities:
                with self.subTest(connector=connector, capability=capability):
                    manifest = copy.deepcopy(self.manifests[connector])
                    actual = replacements[expected]
                    manifest["capabilities"][capability]["state"] = actual
                    errors = connector_capabilities.validate_manifest(connector, manifest)
                    self.assertIn(
                        (
                            f"{connector}: host-model invariant requires "
                            f"{capability}={expected}, got {actual}"
                        ),
                        errors,
                    )

    def test_companion_profiles_distinguish_direct_service_from_logical_connector(self) -> None:
        expected = {
            "envoy": (
                "http-ext-authz-service",
                "private-uds-ext-proc-response-observer",
            ),
            "traefik": (
                "http-forwardauth-service",
                "private-uds-response-observer-plugin",
            ),
        }
        for connector, (request_component, response_component) in expected.items():
            with self.subTest(connector=connector):
                contract = self.manifests[connector]["logical_transaction_contract"]
                host_path = contract["host_path"]
                self.assertEqual(host_path["request_component"], request_component)
                self.assertEqual(host_path["response_component"], response_component)
                self.assertEqual(
                    host_path["logical_connector"],
                    "request_component + response_component",
                )
                self.assertEqual(host_path["direct_service_phases"], ["P1", "P2"])
                self.assertEqual(
                    host_path["logical_connector_phases"], ["P1", "P2", "P3", "P4"]
                )
                self.assertEqual(
                    host_path["direct_service_response_phases"],
                    "not_exposed_by_protocol",
                )
                self.assertEqual(host_path["logical_connector_status"], contract["state"])
                self.assertEqual(contract["state"], "implemented_not_asserted")
                self.assertEqual(
                    self.manifests[connector]["capabilities"]["phase3"]["state"],
                    "unsupported_by_host_model",
                )
                self.assertEqual(
                    self.manifests[connector]["capabilities"]["phase4"]["state"],
                    "unsupported_by_host_model",
                )

    def test_host_model_state_requirements_are_deeply_immutable(self) -> None:
        requirements = connector_capabilities._HOST_MODEL_REQUIRED_STATES
        envoy_requirements = requirements["envoy"]
        with self.assertRaises(TypeError):
            requirements["envoy"] = {}  # type: ignore[index]
        with self.assertRaises(TypeError):
            envoy_requirements["phase2"] = "not_implemented"  # type: ignore[index]

    def test_traefik_requires_versioned_official_forwardauth_reference(self) -> None:
        expected_url = (
            "https://doc.traefik.io/traefik/v3.7/reference/"
            "routing-configuration/http/middlewares/forwardauth/"
        )
        manifest = copy.deepcopy(self.manifests["traefik"])
        reference_replaced = False
        for reference in manifest["external_references"]:
            if reference.get("url") == expected_url:
                reference["url"] = "https://doc.traefik.io/traefik/v3.7/reference/"
                reference_replaced = True

        self.assertTrue(reference_replaced)

        self.assertEqual(
            connector_capabilities.validate_manifest("traefik", manifest),
            ["traefik: missing versioned official ForwardAuth reference"],
        )

    def test_runtime_merge_is_report_only_and_promotes_checked_capabilities(self) -> None:
        run_id = "ci-123"
        source_snapshot = copy.deepcopy(self.manifests)
        results = self._results(run_id)
        results["nginx"]["result"]["status"] = "FAIL"  # type: ignore[index]

        merged, evidence = connector_capabilities.merge_runtime_results(
            self.manifests, results, run_id
        )

        self.assertEqual(
            self.manifests["apache"]["capabilities"]["request_headers"]["state"],
            "implemented_not_asserted",
        )
        self.assertEqual(source_snapshot, self.manifests)
        self.assertEqual(
            merged["apache"]["capabilities"]["request_headers"]["state"],
            "verified",
        )
        self.assertEqual(
            merged["apache"]["capabilities"]["request_headers"]["declared_state"],
            "implemented_not_asserted",
        )
        self.assertEqual(
            merged["apache"]["evidence_stages"]["no_crs_baseline"]["status"],
            "supported_and_verified",
        )
        self.assertEqual(
            merged["nginx"]["evidence_stages"]["no_crs_baseline"]["status"],
            "failed",
        )
        self.assertEqual(
            merged["nginx"]["capabilities"]["request_headers"]["state"],
            "implemented_not_asserted",
        )
        self.assertFalse(evidence["connectors"]["nginx"]["promotion_eligible"])
        self.assertEqual(
            evidence["connectors"]["apache"]["result"],
            "apache/ci-123/result.json",
        )

    def test_result_shape_rejects_a_negative_source_capability_promotion(self) -> None:
        manifest = self.manifests["traefik"]
        states = {
            name: manifest["capabilities"][name]["state"]
            for name in connector_capabilities.CAPABILITY_NAMES
        }
        result = {
            "connector": "traefik",
            "run_id": "ci-123",
            "evidence_stage": "no_crs_baseline",
            "ruleset": "no-crs-baseline",
            "status": "PASS",
            "source_failure": False,
            "cases_failed": 0,
            "cases_blocked": 0,
            "capabilities_verified": ["response_headers"],
            "capability_states": states,
        }

        errors = connector_capabilities._validated_result_shape_errors(
            "traefik", "ci-123", result, manifest
        )

        self.assertTrue(any("declares unsupported_by_host_model" in error for error in errors))

    def test_failed_or_tainted_results_never_promote_partial_cases(self) -> None:
        for update in (
            {"status": "FAIL"},
            {"status": "BLOCKED"},
            {"source_failure": True},
            {"cases_failed": 1},
            {"cases_blocked": 1},
        ):
            with self.subTest(update=update):
                results = self._results("ci-123")
                results["apache"]["result"].update(update)  # type: ignore[index]
                merged, evidence = connector_capabilities.merge_runtime_results(
                    self.manifests, results, "ci-123"
                )
                self.assertEqual(
                    merged["apache"]["capabilities"]["request_headers"]["state"],
                    "implemented_not_asserted",
                )
                self.assertFalse(evidence["connectors"]["apache"]["promotion_eligible"])

    def test_missing_evidence_is_all_or_nothing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="capability-evidence-") as temporary:
            results, errors = connector_capabilities.load_validated_runtime_results(
                self.manifests, Path(temporary), "ci-123"
            )
        self.assertEqual(results, {})
        self.assertEqual(len(connector_capabilities.CONNECTORS), len(errors))
        self.assertTrue(all("run directory is missing" in error for error in errors))

    def test_cli_renders_a_complete_validated_overlay_view(self) -> None:
        run_id = "ci-123"
        with tempfile.TemporaryDirectory(prefix="capability-evidence-") as temporary:
            root = Path(temporary)
            evidence_root = root / "evidence"
            results = self._results(run_id)
            for connector, record in results.items():
                result = record["result"]  # type: ignore[assignment]
                result.update({  # type: ignore[union-attr]
                    "connector": connector,
                    "run_id": run_id,
                    "evidence_stage": "no_crs_baseline",
                    "ruleset": "no-crs-baseline",
                })
                run_dir = evidence_root / connector / run_id
                run_dir.mkdir(parents=True)
                (run_dir / "result.json").write_text(
                    json.dumps(result), encoding="utf-8"
                )
            output = root / "report"
            with mock.patch.object(
                connector_capabilities, "_validate_evidence_run", return_value=[]
            ):
                rc = connector_capabilities.main(
                    [
                        "generate",
                        "--evidence-root",
                        str(evidence_root),
                        "--run-id",
                        run_id,
                        "--output-dir",
                        str(output),
                    ]
                )
            self.assertEqual(rc, 0)
            payload = json.loads(
                (output / "connector-capabilities.generated.json").read_text(
                    encoding="utf-8"
                )
            )
        self.assertTrue(payload["runtime_promotion"])
        self.assertEqual(payload["runtime_evidence"]["run_id"], run_id)
        self.assertEqual(payload["metadata"]["verified_run_id"], run_id)
        self.assertEqual(
            payload["connectors"]["apache"]["capabilities"]["request_headers"]["state"],
            "verified",
        )

    def test_framework_validator_is_required_for_each_runtime_result(self) -> None:
        run_dir = source_path('evidence/apache/ci-123', root=ROOT)
        manifest_path = source_path('connectors/apache/capabilities.json', root=ROOT)
        completed = subprocess.CompletedProcess([], 0, stdout="ok", stderr="")
        with tempfile.TemporaryDirectory() as temporary:
            validator = Path(temporary) / "no_crs_baseline.py"
            validator.write_text("# test validator\n", encoding="utf-8")
            with (
                mock.patch.object(
                    connector_capabilities,
                    "FRAMEWORK_NO_CRS_TOOL",
                    validator,
                ),
                mock.patch.object(
                    connector_capabilities.subprocess,
                    "run",
                    return_value=completed,
                ) as run,
            ):
                errors = connector_capabilities._validate_evidence_run(
                    "apache", run_dir, manifest_path
                )

        self.assertEqual(errors, [])
        command = run.call_args.args[0]
        self.assertIn("validate", command)
        self.assertIn("--check", command)
        self.assertEqual(command[command.index("--check") + 1], "all")
        self.assertIn("--connector-root", command)
        self.assertEqual(str(ROOT), command[command.index("--connector-root") + 1])

    def test_cli_requires_evidence_root_and_run_id_together(self) -> None:
        with tempfile.TemporaryDirectory(prefix="capability-output-") as temporary:
            rc = connector_capabilities.main(
                [
                    "generate",
                    "--evidence-root",
                    temporary,
                    "--output-dir",
                    temporary,
                ]
            )
        self.assertEqual(rc, 2)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
