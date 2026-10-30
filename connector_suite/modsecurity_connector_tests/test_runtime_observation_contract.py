"""Focused tests for the one canonical Parent runtime-observation contract."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest import mock


ROOT = connector_root()
CONTRACTS_ROOT = source_path('ci/runtime/contracts', root=ROOT)
CLI_PATH = source_path('ci/runtime/contracts/validate-runtime-observation.py', root=ROOT)
FIXTURE_ROOT = source_path('tests/fixtures/runtime-observation', root=ROOT)

import modsecurity_connector_ci.runtime.contracts.runtime_observation as contract  # noqa: E402
import modsecurity_connector_ci.runtime.contracts.runtime_observation_adapters as adapters  # noqa: E402

PARENT_COMMIT = "1" * 40
FRAMEWORK_COMMIT = "2" * 40
MRTS_COMMIT = "3" * 40


def assertion(
    case_id: str,
    expected_value: dict[str, object],
    observed_value: dict[str, object] | None = None,
    *,
    evidence_kind: str,
) -> dict[str, object]:
    return {
        "case_id": case_id,
        "expected": expected_value,
        "observed": expected_value if observed_value is None else observed_value,
        "required": True,
        "applicable": True,
        "executed": True,
        "live_executed": True,
        "result": "PASS",
        "reason": "structured live evidence matched",
        "evidence_kind": evidence_kind,
    }


def observation(
    connector: str = "envoy",
    profile: str = "with-crs-no-mrts",
    adapter_id: str | None = None,
    integration_mode: str | None = None,
) -> dict[str, object]:
    requirement = contract.PROFILE_REQUIREMENTS[profile]
    if adapter_id is None:
        adapter_id = contract.DEFAULT_ADAPTER_IDS.get(connector)
    if integration_mode is None:
        integration_mode = contract.CONNECTOR_INTEGRATION_MODES.get(connector)
    adapter = contract.adapter_for(connector, adapter_id, integration_mode)
    if adapter.fixture_producer:
        producer = adapter.fixture_producer
        evidence_kind = "canonical_fixture"
    elif adapter.protected_separate:
        producer = adapter.producer
        evidence_kind = "protected_runtime_evidence"
    else:
        producer = adapter.producer
        evidence_kind = "structured_connector_evidence"
    identity = {
        "connector": connector,
        "adapter_id": adapter_id,
        "integration_mode": integration_mode,
        "profile": profile,
        "crs": requirement["crs"],
        "mrts": requirement["mrts"],
        "run_id": "contract-run",
        "parent_commit": PARENT_COMMIT,
        "framework_commit": FRAMEWORK_COMMIT,
        "mrts_commit": MRTS_COMMIT,
        "producer": producer,
        "producer_version": "1.0.0",
    }
    manifest_digest = hashlib.sha256(f"fixture:{connector}:{profile}".encode()).hexdigest()
    evidence = {
        "name": "fixture_evidence",
        "path": "fixture-evidence.json",
        "sha256": hashlib.sha256(b"fixture").hexdigest(),
        "kind": evidence_kind,
    }
    return {
        "schema_version": contract.SCHEMA_VERSION,
        "identity": identity,
        "runtime": {
            "config_test": assertion("config", {"status": "PASS"}, evidence_kind=evidence_kind),
            "host_start": assertion("host-start", {"status": "PASS"}, evidence_kind=evidence_kind),
            "reachability": assertion("reachability", {"status": "PASS"}, evidence_kind=evidence_kind),
            "allow_case": assertion("allow", {"http_status": 200}, evidence_kind=evidence_kind),
            "block_case": assertion(
                "block",
                {"http_status": 403, "action": "deny", "rule_ids": [942270], "intervention_rule_ids": [942270]},
                evidence_kind=evidence_kind,
            ),
            "bypass_case": assertion("bypass", {"http_status": 403, "action": "deny"}, evidence_kind=evidence_kind),
            "runtime_status": "PASS",
        },
        "framework": {
            "selection_status": "SELECTED",
            "execution_status": "RUN",
            "validation_status": contract.CONTRACT_VALIDATED,
            "selected_count": 1,
            "executed_count": 1,
            "passed_count": 1,
            "failed_count": 0,
            "cancelled_count": 0,
            "unsupported_count": 0,
            "not_applicable_count": 0,
            "not_executed_count": 0,
            "failure_count": 0,
            "mismatch_count": 0,
            "cases": [{
                "framework_test_id": "runtime-contract-fixture",
                "scenario_category": None,
                "selected": True,
                "executed": True,
                "live_executed": True,
                "expectation": {"kind": "intervention", "http_status": 403, "action": "deny", "rule_ids": [942270]},
                "observation": {"http_status": 403, "action": "deny", "rule_ids": [942270]},
                "result": "PASS",
                "failure_count": 0,
                "mismatch_count": 0,
            }],
        },
        "isolation": {
            field: bool(requirement["requires_mrts"])
            for field in contract.ISOLATION_FIELDS
        },
        "cleanup": {
            **{field: 0 for field in contract.CLEANUP_COUNTERS},
            "cleanup_status": "PASS",
        },
        "provenance": {
            "evidence_kind": evidence_kind,
            "fixture_id": "runtime-contract-fixture",
            "manifest_digest": manifest_digest,
            "evidence_digest": contract.evidence_manifest_digest([evidence]),
            "source_contract": "canonical-fixture-v1",
            "validation_basis": "evidence-digest-v1",
            "contract_schema_version": 1,
            "producer_version": "1.0.0",
            "evidence": [evidence],
        },
    }


def expected_identity(value: dict[str, object]) -> dict[str, object]:
    identity = value["identity"]
    assert isinstance(identity, dict)
    return dict(identity)


def canonical_fixture(connector: str) -> dict[str, object]:
    return named_canonical_fixture(connector)


def named_canonical_fixture(name: str) -> dict[str, object]:
    return json.loads(
        (FIXTURE_ROOT / f"{name}-no-crs-no-mrts.json").read_text(encoding="utf-8")
    )


class RuntimeObservationContractTest(unittest.TestCase):
    def _run_private_observation_cli(
        self, path: Path, root: Path, connector: str
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(CLI_PATH),
                "--observation",
                str(path),
                "--evidence-root",
                str(root),
                "--connector",
                connector,
                "--adapter-id",
                str(contract.DEFAULT_ADAPTER_IDS[connector]),
                "--integration-mode",
                str(contract.CONNECTOR_INTEGRATION_MODES[connector]),
                "--profile",
                "with-crs-no-mrts",
                "--run-id",
                "contract-run",
                "--parent-sha",
                PARENT_COMMIT,
                "--framework-sha",
                FRAMEWORK_COMMIT,
                "--mrts-sha",
                MRTS_COMMIT,
                "--policy",
                "strict",
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    def assert_valid(self, value: dict[str, object]) -> None:
        provenance = value["provenance"]
        assert isinstance(provenance, dict)
        policy = "fixture" if provenance["evidence_kind"] == "canonical_fixture" else "strict"
        if policy == "fixture":
            result = contract.validate_runtime_observation(value, expected_identity(value), policy)
        else:
            with tempfile.TemporaryDirectory(prefix="runtime-contract-") as temporary:
                root = Path(temporary) / "evidence"
                root.mkdir(mode=0o700)
                os.chmod(root, 0o700)
                evidence = provenance["evidence"]
                assert isinstance(evidence, list)
                for record in evidence:
                    assert isinstance(record, dict)
                    path = root / str(record["path"])
                    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    os.chmod(path.parent, 0o700)
                    path.write_bytes(b"fixture")
                    os.chmod(path, 0o600)
                result = contract.validate_runtime_observation(
                    value,
                    expected_identity(value),
                    {"name": policy, "evidence_root": root},
                )
        self.assertTrue(result.valid, result.errors)
        self.assertEqual(result.status, "PASS")
        self.assertEqual(result["validation_status"], contract.CONTRACT_VALIDATED)

    def assert_invalid(
        self, value: dict[str, object], expected: dict[str, object] | None = None
    ) -> None:
        result = contract.validate_runtime_observation(
            value, expected if expected is not None else expected_identity(value), "strict"
        )
        self.assertFalse(result.valid)
        self.assertEqual(result.status, "VALIDATION_FAILED")
        self.assertTrue(result.errors)

    def test_valid_envoy_fixture(self) -> None:
        self.assert_valid(observation("envoy"))

    def test_valid_lighttpd_fixture(self) -> None:
        self.assert_valid(observation("lighttpd"))

    def test_valid_traefik_fixture(self) -> None:
        self.assert_valid(observation("traefik"))

    def test_adapter_id_is_mandatory_identity(self) -> None:
        value = observation()
        identity = value["identity"]
        assert isinstance(identity, dict)
        identity.pop("adapter_id")
        self.assert_invalid(value)

    def test_all_public_framework_expectation_kinds_accept_canonical_shapes(self) -> None:
        expectations = (
            {"kind": "http_status", "http_status": 403},
            {"kind": "intervention", "http_status": 403, "action": "deny", "rule_ids": [942270]},
            {"kind": "action", "action": "deny"},
            {"kind": "rule_match", "rule_ids": [942270]},
            {"kind": "event", "fields": ["rule_id", "transaction_id"], "event_type": "intervention"},
            {"kind": "request_headers", "names": ["content-type", "x-request-id"]},
            {"kind": "response_headers", "names": ["content-type", "x-request-id"]},
            {"kind": "request_body", "state": "observed"},
            {"kind": "response_body", "state": "buffered"},
            {"kind": "transport", "state": "http2"},
            {"kind": "lifecycle", "predicates": {"request_completed": True}},
            {"kind": "cleanup", "state": "completed"},
            {
                "kind": "compound",
                "conditions": [
                    {"kind": "http_status", "http_status": 403},
                    {"kind": "action", "action": "deny"},
                ],
            },
            {"kind": "not_applicable", "reason": "future_target"},
        )
        self.assertEqual({expectation["kind"] for expectation in expectations}, contract.EXPECTATION_KINDS)
        for expectation in expectations:
            with self.subTest(kind=expectation["kind"]):
                self.assertEqual(contract.normalize_framework_expectation(expectation), expectation)

    def test_canonical_apache_fixture_uses_common_validator(self) -> None:
        self.assert_valid(canonical_fixture("apache"))

    def test_canonical_haproxy_fixture_uses_common_validator(self) -> None:
        for fixture_name in ("haproxy-spoe-spop", "haproxy-native-htx"):
            with self.subTest(fixture_name=fixture_name):
                self.assert_valid(named_canonical_fixture(fixture_name))

    def test_apache_and_haproxy_have_no_lite_live_adapter(self) -> None:
        for connector, adapter_id, mode in (("apache", "apache-native-httpd-module", "native-httpd-module"), ("haproxy", "haproxy-spoe-spop-agent", "spoe-spop-agent"), ("haproxy", "haproxy-native-htx-filter", "native-htx-filter")):
            with self.subTest(connector=connector, adapter_id=adapter_id):
                self.assertFalse(contract.adapter_for(connector, adapter_id, mode).live_producer_supported)
                with self.assertRaises(contract.RuntimeObservationError):
                    contract.require_live_adapter(connector, adapter_id, mode)
        self.assertFalse(hasattr(contract, "validate_apache_lite"))
        self.assertFalse(hasattr(contract, "validate_haproxy_lite"))

    def test_apache_and_haproxy_live_claims_fail_closed_without_producers(self) -> None:
        for connector, adapter_id, mode in (("apache", "apache-native-httpd-module", "native-httpd-module"), ("haproxy", "haproxy-spoe-spop-agent", "spoe-spop-agent"), ("haproxy", "haproxy-native-htx-filter", "native-htx-filter")):
            with self.subTest(connector=connector, adapter_id=adapter_id):
                value = observation(connector, "with-crs-no-mrts", adapter_id, mode)
                identity = value["identity"]
                provenance = value["provenance"]
                assert isinstance(identity, dict)
                assert isinstance(provenance, dict)
                identity["producer"] = f"parent-runtime-observation-adapter-{connector}"
                provenance["evidence_kind"] = "structured_connector_evidence"
                evidence = provenance["evidence"]
                assert isinstance(evidence, list)
                evidence[0]["kind"] = "structured_connector_evidence"
                self._refresh_evidence_digest(value)
                self.assert_invalid(value)

    def test_fixture_policy_cannot_be_smuggled_into_strict_policy(self) -> None:
        value = canonical_fixture("apache")
        result = contract.validate_runtime_observation(
            value,
            expected_identity(value),
            {"name": "strict", "allow_fixture_evidence": True},
        )
        self.assertFalse(result.valid)
        self.assertEqual(result.status, "VALIDATION_FAILED")

    def test_missing_live_executed_prevents_framework_pass(self) -> None:
        value = observation()
        framework = value["framework"]
        assert isinstance(framework, dict)
        case = framework["cases"][0]
        assert isinstance(case, dict)
        case["live_executed"] = False
        self.assert_invalid(value)

    def test_wrong_http_status_prevents_pass(self) -> None:
        value = observation()
        runtime = value["runtime"]
        assert isinstance(runtime, dict)
        allow = runtime["allow_case"]
        assert isinstance(allow, dict)
        observed = allow["observed"]
        assert isinstance(observed, dict)
        observed["http_status"] = 403
        self.assert_invalid(value)

    def test_wrong_action_prevents_pass(self) -> None:
        value = observation()
        runtime = value["runtime"]
        assert isinstance(runtime, dict)
        block = runtime["block_case"]
        assert isinstance(block, dict)
        observed = block["observed"]
        assert isinstance(observed, dict)
        observed["action"] = "pass"
        self.assert_invalid(value)

    def test_wrong_rule_id_prevents_pass_when_expected(self) -> None:
        value = observation()
        framework = value["framework"]
        assert isinstance(framework, dict)
        observed = framework["cases"][0]["observation"]
        assert isinstance(observed, dict)
        observed["rule_ids"] = [942271]
        self.assert_invalid(value)

    def test_event_and_lifecycle_expectations_need_no_http_status(self) -> None:
        value = observation()
        runtime = value["runtime"]
        assert isinstance(runtime, dict)
        runtime["allow_case"] = assertion(
            "allow-event", {"event": "allow-observed"}, evidence_kind="structured_connector_evidence"
        )
        runtime["block_case"] = assertion(
            "block-lifecycle", {"predicates": {"request_completed": True}}, evidence_kind="structured_connector_evidence"
        )
        self.assert_valid(value)

    def test_cleanup_expectation_needs_no_http_status(self) -> None:
        value = observation()
        framework = value["framework"]
        assert isinstance(framework, dict)
        case = framework["cases"][0]
        assert isinstance(case, dict)
        case["expectation"] = {"kind": "cleanup", "state": "completed"}
        case["observation"] = {"cleanup": "completed"}
        self.assert_valid(value)

    def test_wrong_connector_is_rejected(self) -> None:
        value = observation()
        expected = expected_identity(value)
        expected["connector"] = "traefik"
        self.assert_invalid(value, expected)

    def test_unhashable_closed_literals_return_validation_failed(self) -> None:
        mutations = (
            ("identity.profile", []),
            ("runtime.runtime_status", {}),
            ("framework.selection_status", []),
            ("framework.case.result", {}),
            ("cleanup.cleanup_status", []),
            ("provenance.evidence_kind", {}),
        )
        for target, unsafe_value in mutations:
            with self.subTest(target=target):
                value = observation()
                if target == "identity.profile":
                    value["identity"]["profile"] = unsafe_value
                elif target == "runtime.runtime_status":
                    value["runtime"]["runtime_status"] = unsafe_value
                elif target == "framework.selection_status":
                    value["framework"]["selection_status"] = unsafe_value
                elif target == "framework.case.result":
                    value["framework"]["cases"][0]["result"] = unsafe_value
                elif target == "cleanup.cleanup_status":
                    value["cleanup"]["cleanup_status"] = unsafe_value
                else:
                    value["provenance"]["evidence_kind"] = unsafe_value
                self.assert_invalid(value)

    def test_excessively_nested_or_cyclic_metadata_returns_validation_failed(self) -> None:
        for label, metadata in (("nested", {}), ("cyclic", {})):
            with self.subTest(metadata=label):
                value = observation()
                if label == "nested":
                    current = metadata
                    for level in range(contract.MAX_METADATA_DEPTH + 1):
                        child: dict[str, object] = {}
                        current[f"level-{level}"] = child
                        current = child
                else:
                    metadata["self"] = metadata
                value["runtime"]["allow_case"]["observed"] = {
                    "status": "PASS",
                    "metadata": metadata,
                }
                self.assert_invalid(value)

    def test_haproxy_adapter_tuples_cannot_cross(self) -> None:
        for adapter_id, mode in (
            ("haproxy-spoe-spop-agent", "native-htx-filter"),
            ("haproxy-native-htx-filter", "spoe-spop-agent"),
        ):
            with self.subTest(adapter_id=adapter_id, mode=mode):
                with self.assertRaises(contract.RuntimeObservationError):
                    contract.adapter_for("haproxy", adapter_id, mode)
        value = observation("haproxy", "with-crs-no-mrts", "haproxy-spoe-spop-agent", "spoe-spop-agent")
        identity = value["identity"]
        assert isinstance(identity, dict)
        identity["integration_mode"] = "native-htx-filter"
        self.assert_invalid(value)

    def test_haproxy_fixture_evidence_cannot_cross_adapter_boundaries(self) -> None:
        for source_fixture, target_adapter, target_mode in (
            ("haproxy-spoe-spop", "haproxy-native-htx-filter", "native-htx-filter"),
            ("haproxy-native-htx", "haproxy-spoe-spop-agent", "spoe-spop-agent"),
        ):
            with self.subTest(source_fixture=source_fixture, target_adapter=target_adapter):
                value = named_canonical_fixture(source_fixture)
                identity = value["identity"]
                assert isinstance(identity, dict)
                identity["adapter_id"] = target_adapter
                identity["integration_mode"] = target_mode
                self.assert_invalid(value)

    def test_framework_public_union_rejects_public_rule_id_but_normalizes_legacy(self) -> None:
        self.assertEqual(
            contract.normalize_framework_expectation({"kind": "rule_id", "value": 942270}),
            {"kind": "rule_match", "rule_ids": [942270]},
        )
        value = observation()
        case = value["framework"]["cases"][0]
        assert isinstance(case, dict)
        case["expectation"] = {"kind": "rule_id", "value": 942270}
        case["observation"] = {"rule_ids": [942270]}
        self.assert_invalid(value)
        for expectation in ({"kind": "rule_match", "rule_id": 942270},):
            value = observation()
            case = value["framework"]["cases"][0]
            assert isinstance(case, dict)
            case["expectation"] = expectation
            case["observation"] = {"rule_ids": [942270]}
            self.assert_invalid(value)

    def test_framework_compound_is_bounded_and_closed(self) -> None:
        valid = {"kind": "compound", "conditions": [
            {"kind": "http_status", "http_status": 403},
            {"kind": "action", "action": "deny"},
        ]}
        self.assertEqual(contract.normalize_framework_expectation(valid), valid)
        invalid = (
            {"kind": "compound", "conditions": []},
            {"kind": "compound", "conditions": [valid["conditions"][0]] * 2},
            {"kind": "compound", "conditions": [{"kind": "unknown", "value": 1}, valid["conditions"][1]]},
            {"kind": "compound", "conditions": [{"kind": "http_status", "http_status": 403, "payload": "raw"}, valid["conditions"][1]]},
            {"kind": "compound", "conditions": [{"kind": "http_status", "http_status": 403, "path": "/tmp/x"}, valid["conditions"][1]]},
        )
        for expectation in invalid:
            with self.subTest(expectation=expectation):
                with self.assertRaises(contract.RuntimeObservationError):
                    contract.normalize_framework_expectation(expectation)

    def test_missing_explicit_structured_statuses_cannot_pass(self) -> None:
        value = observation()
        for field in ("config_test", "host_start", "reachability"):
            missing = observation()
            runtime = missing["runtime"]
            assert isinstance(runtime, dict)
            runtime.pop(field)
            self.assert_invalid(missing)
        value["runtime"]["config_test"]["observed"] = {"status": "PASS"}
        value["provenance"]["manifest_digest"] = "0" * 64
        self.assert_invalid(value)

    def test_runtime_pass_cannot_contradict_framework_case_or_aggregate(self) -> None:
        value = observation()
        case = value["framework"]["cases"][0]
        assert isinstance(case, dict)
        case["result"] = "FAIL"
        case["failure_count"] = 1
        self.assert_invalid(value)
        value = observation()
        value["framework"]["selected_count"] = 2
        self.assert_invalid(value)

    def test_framework_aggregate_equations_and_duplicate_ids_are_enforced(self) -> None:
        value = observation()
        framework = value["framework"]
        assert isinstance(framework, dict)
        case = framework["cases"][0]
        assert isinstance(case, dict)
        not_run = dict(case)
        not_run.update({
            "framework_test_id": "runtime-contract-no-crs",
            "selected": True,
            "executed": False,
            "live_executed": False,
            "result": "NOT_EXECUTED",
            "expectation": {"kind": "not_applicable", "reason": "future_target"},
            "observation": {"applicability": "future_target"},
        })
        framework["cases"] = [case, not_run]
        framework.update({
            "selected_count": 2, "executed_count": 1, "passed_count": 1,
            "failed_count": 0, "cancelled_count": 0, "unsupported_count": 0,
            "not_applicable_count": 0, "not_executed_count": 1,
        })
        self.assert_invalid(value)
        not_run["framework_test_id"] = case["framework_test_id"]
        self.assert_invalid(value)

    def test_selected_not_executed_case_prevents_runtime_aggregate_pass(self) -> None:
        value = observation()
        framework = value["framework"]
        assert isinstance(framework, dict)
        not_run = deepcopy(framework["cases"][0])
        assert isinstance(not_run, dict)
        not_run.update(
            {
                "framework_test_id": "runtime-contract-not-executed",
                "executed": False,
                "live_executed": False,
                "expectation": {"kind": "not_applicable", "reason": "future_target"},
                "observation": {"applicability": "future_target"},
                "result": "NOT_EXECUTED",
            }
        )
        framework["cases"] = [framework["cases"][0], not_run]
        framework.update(
            {
                "selected_count": 2,
                "executed_count": 1,
                "passed_count": 1,
                "failed_count": 0,
                "cancelled_count": 0,
                "unsupported_count": 0,
                "not_applicable_count": 0,
                "not_executed_count": 1,
                "failure_count": 0,
                "mismatch_count": 0,
            }
        )
        self.assert_invalid(value)

    def test_multiple_no_crs_cases_remain_representable_without_scenario_category(self) -> None:
        value = observation(profile="no-crs-no-mrts")
        framework = value["framework"]
        assert isinstance(framework, dict)
        first = framework["cases"][0]
        assert isinstance(first, dict)
        second = deepcopy(first)
        assert isinstance(second, dict)
        second["framework_test_id"] = "runtime-contract-no-crs-secondary"
        framework["cases"] = [first, second]
        framework.update(
            {
                "selected_count": 2,
                "executed_count": 2,
                "passed_count": 2,
                "failed_count": 0,
                "cancelled_count": 0,
                "unsupported_count": 0,
                "not_applicable_count": 0,
                "not_executed_count": 0,
                "failure_count": 0,
                "mismatch_count": 0,
            }
        )
        self.assertIsNone(first["scenario_category"])
        self.assertIsNone(second["scenario_category"])
        self.assert_valid(value)

    def test_wrong_profile_is_rejected(self) -> None:
        value = observation()
        expected = expected_identity(value)
        expected["profile"] = "no-crs-no-mrts"
        self.assert_invalid(value, expected)

    def test_wrong_run_id_is_rejected(self) -> None:
        value = observation()
        expected = expected_identity(value)
        expected["run_id"] = "other-run"
        self.assert_invalid(value, expected)

    def test_wrong_parent_commit_is_rejected(self) -> None:
        value = observation()
        expected = expected_identity(value)
        expected["parent_commit"] = "4" * 40
        self.assert_invalid(value, expected)

    def test_wrong_framework_commit_is_rejected(self) -> None:
        value = observation()
        expected = expected_identity(value)
        expected["framework_commit"] = "5" * 40
        self.assert_invalid(value, expected)

    def test_wrong_mrts_commit_is_rejected(self) -> None:
        value = observation("envoy", "with-crs-with-mrts")
        expected = expected_identity(value)
        expected["mrts_commit"] = "6" * 40
        self.assert_invalid(value, expected)

    def test_missing_mandatory_evidence_is_rejected(self) -> None:
        value = observation()
        runtime = value["runtime"]
        assert isinstance(runtime, dict)
        runtime.pop("reachability")
        self.assert_invalid(value)

    def test_explicit_not_applicable_bypass_is_accepted(self) -> None:
        value = observation()
        runtime = value["runtime"]
        assert isinstance(runtime, dict)
        runtime["bypass_case"] = {
            "case_id": "bypass-not-applicable",
            "expected": {"event": "bypass-not-applicable"},
            "observed": {"event": "bypass-not-applicable"},
            "required": False,
            "applicable": False,
            "executed": False,
            "live_executed": False,
            "result": contract.NOT_APPLICABLE,
            "reason": "central profile matrix makes bypass optional",
            "evidence_kind": "structured_connector_evidence",
        }
        self.assert_valid(value)

    def test_cleanup_residue_prevents_aggregate_pass(self) -> None:
        value = observation()
        cleanup = value["cleanup"]
        assert isinstance(cleanup, dict)
        cleanup["listeners_remaining"] = 1
        self.assert_invalid(value)

    def test_no_mrts_attestation_is_checked(self) -> None:
        value = observation()
        isolation = value["isolation"]
        assert isinstance(isolation, dict)
        isolation["mrts_runner_invoked"] = True
        self.assert_invalid(value)

    def test_no_mrts_profile_still_requires_mrts_revision_identity(self) -> None:
        value = observation()
        identity = value["identity"]
        assert isinstance(identity, dict)
        identity["mrts_commit"] = contract.NOT_APPLICABLE
        self.assert_invalid(value)

    def test_mrts_attestation_is_profile_dependent(self) -> None:
        self.assert_valid(observation("envoy", "with-crs-with-mrts"))
        value = observation("envoy", "with-crs-with-mrts")
        isolation = value["isolation"]
        assert isinstance(isolation, dict)
        isolation["mrts_artifact_used"] = False
        self.assert_invalid(value)

    def test_nginx_is_representable_as_protected_separate(self) -> None:
        self.assertTrue(contract.adapter_for("nginx").protected_separate)
        self.assertFalse(contract.adapter_for("nginx").live_producer_supported)
        value = observation("nginx", "no-crs-no-mrts")
        identity = value["identity"]
        assert isinstance(identity, dict)
        self.assertEqual(identity["producer"], "protected-nginx-root-broker")
        self.assert_valid(value)

    def test_duplicate_case_id_is_rejected(self) -> None:
        value = observation()
        runtime = value["runtime"]
        assert isinstance(runtime, dict)
        block = runtime["block_case"]
        assert isinstance(block, dict)
        block["case_id"] = "allow"
        self.assert_invalid(value)

    def test_provenance_digest_mismatch_is_rejected(self) -> None:
        value = observation()
        provenance = value["provenance"]
        assert isinstance(provenance, dict)
        provenance["evidence_digest"] = "0" * 64
        self.assert_invalid(value)

    def test_missing_bound_evidence_returns_validation_failed_without_a_path_leak(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-contract-") as temporary:
            root = Path(temporary) / "evidence"
            root.mkdir(mode=0o700)
            os.chmod(root, 0o700)
            value = observation()
            result = contract.validate_runtime_observation(
                value,
                expected_identity(value),
                {"name": "strict", "evidence_root": root},
            )
            self.assertEqual(result.status, "VALIDATION_FAILED")
            self.assertIn("referenced evidence is unavailable or unsafe", result.errors)
            self.assertNotIn(str(root), " ".join(result.errors))

    def test_strict_live_claim_requires_a_private_evidence_root(self) -> None:
        value = observation()
        result = contract.validate_runtime_observation(value, expected_identity(value), "strict")
        self.assertEqual(result.status, "VALIDATION_FAILED")
        self.assertIn("live runtime evidence requires a private evidence root", result.errors)

    def test_absolute_path_and_payload_fields_are_rejected(self) -> None:
        value = observation()
        provenance = value["provenance"]
        assert isinstance(provenance, dict)
        provenance["source_contract"] = "/runner/private"
        self.assert_invalid(value)
        value = observation()
        value["payload"] = "forbidden"
        self.assert_invalid(value)

    def test_assertion_evidence_kind_must_bind_to_provenance(self) -> None:
        value = observation()
        runtime = value["runtime"]
        assert isinstance(runtime, dict)
        allow = runtime["allow_case"]
        assert isinstance(allow, dict)
        allow["evidence_kind"] = "live_runtime_evidence"
        self.assert_invalid(value)

    @staticmethod
    def _write_private(root: Path, contents: bytes, mode: int = 0o600) -> Path:
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(root, 0o700)
        path = root / "runtime-observation.json"
        path.write_bytes(contents)
        os.chmod(path, mode)
        return path

    @staticmethod
    def _encoded(value: dict[str, object]) -> bytes:
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def _refresh_evidence_digest(value: dict[str, object]) -> None:
        provenance = value["provenance"]
        assert isinstance(provenance, dict)
        evidence = provenance["evidence"]
        assert isinstance(evidence, list)
        provenance["evidence_digest"] = contract.evidence_manifest_digest(evidence)

    def test_secure_reader_accepts_private_fixture(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-contract-") as temporary:
            root = Path(temporary) / "evidence"
            value = observation()
            path = self._write_private(root, self._encoded(value))
            fixture_evidence = root / "fixture-evidence.json"
            fixture_evidence.write_bytes(b"fixture")
            os.chmod(fixture_evidence, 0o600)
            self.assertEqual(contract.load_runtime_observation(path, evidence_root=root), value)

    def test_secure_reader_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-contract-") as temporary:
            root = Path(temporary) / "evidence"
            target = self._write_private(root, self._encoded(observation()))
            link = root / "observation-link.json"
            link.symlink_to(target.name)
            with self.assertRaises(contract.RuntimeObservationError):
                contract.load_runtime_observation(link, evidence_root=root)

    def test_secure_reader_rejects_hardlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-contract-") as temporary:
            root = Path(temporary) / "evidence"
            target = self._write_private(root, self._encoded(observation()))
            hardlink = root / "observation-hardlink.json"
            os.link(target, hardlink)
            with self.assertRaises(contract.RuntimeObservationError):
                contract.load_runtime_observation(hardlink, evidence_root=root)

    def test_secure_reader_rejects_unsafe_permissions(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-contract-") as temporary:
            root = Path(temporary) / "evidence"
            path = self._write_private(root, self._encoded(observation()), 0o644)
            with self.assertRaises(contract.RuntimeObservationError):
                contract.load_runtime_observation(path, evidence_root=root)

    def test_secure_reader_rejects_executable_file(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-contract-") as temporary:
            root = Path(temporary) / "evidence"
            path = self._write_private(root, self._encoded(observation()))
            os.chmod(path, 0o700)
            with self.assertRaises(contract.RuntimeObservationError):
                contract.load_runtime_observation(path, evidence_root=root)

    def test_secure_reader_rejects_group_writable_evidence_root(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-contract-") as temporary:
            root = Path(temporary) / "evidence"
            path = self._write_private(root, self._encoded(observation()))
            os.chmod(root, 0o770)
            with self.assertRaises(contract.RuntimeObservationError):
                contract.load_runtime_observation(path, evidence_root=root)

    def test_secure_reader_requires_exact_private_directory_modes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-contract-") as temporary:
            root = Path(temporary) / "evidence"
            path = self._write_private(root, self._encoded(observation()))
            os.chmod(root, 0o755)
            with self.assertRaises(contract.RuntimeObservationError):
                contract.load_runtime_observation(path, evidence_root=root)

            os.chmod(root, 0o700)
            nested = root / "normalized"
            nested.mkdir(mode=0o700)
            nested_path = nested / path.name
            path.rename(nested_path)
            os.chmod(nested, 0o750)
            with self.assertRaises(contract.RuntimeObservationError):
                contract.load_runtime_observation(nested_path, evidence_root=root)

    def test_secure_reader_rejects_wrong_owner(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-contract-") as temporary:
            root = Path(temporary) / "evidence"
            path = self._write_private(root, self._encoded(observation()))
            with mock.patch.object(contract.os, "geteuid", return_value=os.geteuid() + 1):
                with self.assertRaises(contract.RuntimeObservationError):
                    contract.load_runtime_observation(path, evidence_root=root)

    def test_secure_reader_rejects_malformed_json(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-contract-") as temporary:
            root = Path(temporary) / "evidence"
            path = self._write_private(root, b"{not-json")
            with self.assertRaises(contract.RuntimeObservationError):
                contract.load_runtime_observation(path, evidence_root=root)

    def test_secure_reader_rejects_duplicate_json_keys(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-contract-") as temporary:
            root = Path(temporary) / "evidence"
            path = self._write_private(root, b'{"schema_version":1,"schema_version":1}')
            with self.assertRaises(contract.RuntimeObservationError):
                contract.load_runtime_observation(path, evidence_root=root)

    def test_secure_reader_rejects_nonfinite_json_values(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-contract-") as temporary:
            root = Path(temporary) / "evidence"
            path = self._write_private(root, b'{"schema_version":NaN}')
            with self.assertRaises(contract.RuntimeObservationError):
                contract.load_runtime_observation(path, evidence_root=root)

    def test_secure_reader_rejects_oversized_file(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-contract-") as temporary:
            root = Path(temporary) / "evidence"
            path = self._write_private(root, b"x" * (contract.MAX_OBSERVATION_BYTES + 1))
            with self.assertRaises(contract.RuntimeObservationError):
                contract.load_runtime_observation(path, evidence_root=root)

    def test_canonical_writer_handles_a_short_write(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-contract-") as temporary:
            root = Path(temporary) / "evidence"
            root.mkdir(mode=0o700)
            payload = b'{"schema_version":1}'
            real_write = contract.os.write
            calls = 0

            def short_then_full(descriptor: int, data: bytes | memoryview) -> int:
                nonlocal calls
                calls += 1
                if calls == 1:
                    return real_write(descriptor, data[:1])
                return real_write(descriptor, data)

            with mock.patch.object(contract.os, "write", side_effect=short_then_full):
                path = contract.write_canonical_evidence_file(
                    "runtime-observation.json", payload, root
                )
            self.assertGreaterEqual(calls, 2)
            self.assertEqual(path.read_bytes(), payload)

    def test_file_snapshot_changes_when_file_timestamp_changes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-contract-") as temporary:
            root = Path(temporary) / "evidence"
            path = self._write_private(root, b"fixture")
            before = contract._file_snapshot(path.stat())
            current = path.stat()
            os.utime(path, ns=(current.st_atime_ns, current.st_mtime_ns + 1))
            self.assertNotEqual(before, contract._file_snapshot(path.stat()))

    def test_canonical_writer_is_private_and_refuses_overwrite(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-contract-") as temporary:
            root = Path(temporary) / "evidence"
            root.mkdir(mode=0o700)
            os.chmod(root, 0o700)
            normalized = root / "normalized"
            normalized.mkdir(mode=0o700)
            os.chmod(normalized, 0o700)
            path = contract.write_canonical_evidence_file(
                "runtime-observation.json", b'{"schema_version":1}', normalized
            )
            self.assertEqual(path.read_bytes(), b'{"schema_version":1}')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(contract.RuntimeObservationError):
                contract.write_canonical_evidence_file(
                    "runtime-observation.json", b'{"schema_version":1}', normalized
                )

    def test_structured_adapter_recomputes_private_evidence_digests(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-contract-") as temporary:
            root = Path(temporary) / "evidence"
            root.mkdir(mode=0o700)
            os.chmod(root, 0o700)
            records = []
            for name, contents in (
                ("host_configuration", b"host configuration"),
                ("allow_request", b"allow request"),
                ("block_audit", b"block audit"),
                ("cleanup", b"cleanup"),
            ):
                path = root / f"{name}.json"
                path.write_bytes(contents)
                os.chmod(path, 0o600)
                records.append({"name": name, "path": path.name})
            request = adapters.StructuredObservationInput(
                connector="envoy",
                adapter_id="envoy-ext-proc-service",
                integration_mode="ext_proc",
                run_id="adapter-run",
                parent_commit=PARENT_COMMIT,
                framework_commit=FRAMEWORK_COMMIT,
                mrts_commit=MRTS_COMMIT,
                config_test_status="PASS",
                host_start_status="PASS",
                reachability_status="PASS",
                allow_expected_status=200,
                allow_observed_status=200,
                block_expected_status=403,
                block_observed_status=403,
                bypass_expected_status=403,
                bypass_observed_status=403,
                expected_action="deny",
                observed_action="deny",
                expected_trigger_rule_ids=[942270],
                observed_trigger_rule_ids=[942270],
                expected_intervention_rule_ids=[942270],
                observed_intervention_rule_ids=[942270],
                framework_execution_status="RUN",
                framework_validation_status=contract.CONTRACT_VALIDATED,
                framework_cases=[{
                    "framework_test_id": "adapter-runtime-case",
                    "scenario_category": None,
                    "selected": True,
                    "executed": True,
                    "live_executed": True,
                    "expectation": {"kind": "intervention", "http_status": 403, "action": "deny", "rule_ids": [942270]},
                    "observation": {"http_status": 403, "action": "deny", "rule_ids": [942270]},
                    "result": "PASS",
                    "failure_count": 0,
                    "mismatch_count": 0,
                }],
                cleanup_status="PASS",
                cleanup={
                    "host_processes_remaining": 0,
                    "helper_processes_remaining": 0,
                    "listeners_remaining": 0,
                    "sockets_remaining": 0,
                    "pid_files_remaining": 0,
                    "temporary_paths_remaining": 0,
                },
                isolation={
                    "runner_invoked": False,
                    "case_inventory_loaded": False,
                    "process_started": False,
                    "socket_or_listener_created": False,
                    "artifact_used": False,
                },
                evidence=records,
                evidence_root=root,
                manifest_digest="a" * 64,
            )
            value = adapters.build_structured_observation(request)
            result = contract.validate_runtime_observation(
                value,
                expected_identity(value),
                {"name": "strict", "evidence_root": root},
            )
            self.assertTrue(result.valid, result.errors)
            records[0]["sha256"] = "0" * 64
            with self.assertRaises(adapters.ProducerEvidenceUnavailable):
                adapters.build_structured_observation(request)

    def test_cli_validates_private_observation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-contract-") as temporary:
            root = Path(temporary) / "evidence"
            value = observation()
            path = self._write_private(root, self._encoded(value))
            fixture_evidence = root / "fixture-evidence.json"
            fixture_evidence.write_bytes(b"fixture")
            os.chmod(fixture_evidence, 0o600)
            completed = self._run_private_observation_cli(path, root, "envoy")
            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(completed.stdout)
            self.assertEqual(result["status"], "PASS")
            self.assertEqual(result["validation_status"], contract.CONTRACT_VALIDATED)

    def test_cli_returns_two_for_validation_failure(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-contract-") as temporary:
            root = Path(temporary) / "evidence"
            value = observation()
            path = self._write_private(root, self._encoded(value))
            fixture_evidence = root / "fixture-evidence.json"
            fixture_evidence.write_bytes(b"fixture")
            os.chmod(fixture_evidence, 0o600)
            completed = self._run_private_observation_cli(path, root, "traefik")
            self.assertEqual(completed.returncode, 2, completed.stderr)
            self.assertEqual(json.loads(completed.stdout)["status"], "VALIDATION_FAILED")

    def test_cli_returns_validation_failed_for_unhashable_contract_input(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-contract-") as temporary:
            root = Path(temporary) / "evidence"
            value = observation()
            value["framework"]["selection_status"] = []
            path = self._write_private(root, self._encoded(value))
            fixture_evidence = root / "fixture-evidence.json"
            fixture_evidence.write_bytes(b"fixture")
            os.chmod(fixture_evidence, 0o600)
            completed = self._run_private_observation_cli(path, root, "envoy")
            self.assertEqual(completed.returncode, 2, completed.stderr)
            self.assertEqual(json.loads(completed.stdout)["status"], "VALIDATION_FAILED")

    def test_cli_requires_mrts_sha_for_every_profile(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(CLI_PATH),
                "--observation",
                "unused.json",
                "--connector",
                "envoy",
                "--profile",
                "with-crs-no-mrts",
                "--run-id",
                "contract-run",
                "--parent-sha",
                PARENT_COMMIT,
                "--framework-sha",
                FRAMEWORK_COMMIT,
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("--mrts-sha", completed.stderr)

    def test_partial_policy_never_promotes_missing_evidence(self) -> None:
        value = observation()
        runtime = value["runtime"]
        assert isinstance(runtime, dict)
        runtime.pop("block_case")
        result = contract.validate_runtime_observation(value, expected_identity(value), "partial")
        self.assertFalse(result.valid)
        self.assertIn(result.status, {"PARTIAL", "VALIDATION_FAILED"})



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
