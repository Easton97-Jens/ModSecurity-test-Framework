"""Offline contracts for the data-only protected NGINX broker caller helper."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock


ROOT = connector_root()
HELPER_PATH = source_path('ci/runtime/broker/protected_nginx_broker_caller.py', root=ROOT)
TARGET_SHA = "1" * 40
NO_CRS_RUN_ID = "protected-nginx-root-caller-101-1-no-crs"
WITH_CRS_RUN_ID = "protected-nginx-root-caller-101-1-with-crs"
ARTIFACT_DIGEST = "a" * 64
BINARY_DIGEST = "b" * 64
MODULE_DIGEST = "c" * 64
LIBRARY_DIGEST = "d" * 64
BUNDLE_MANIFEST_DIGEST = "e" * 64
BUNDLE_DIGEST = "f" * 64


def load_helper() -> object:
    return load_source(HELPER_PATH)

CALLER = load_helper()


class ApiResponse:
    def __init__(self, url: str, payload: dict[str, object], status: int = 200) -> None:
        self.url = url
        self.payload = payload
        self.status = status

    def __enter__(self) -> "ApiResponse":
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def geturl(self) -> str:
        return self.url

    def read(self, _: int) -> bytes:
        return json.dumps(self.payload).encode("utf-8")


class ProtectedNginxBrokerCallerTest(unittest.TestCase):
    def temporary_root(self) -> tempfile.TemporaryDirectory[str]:
        return tempfile.TemporaryDirectory(prefix="protected-nginx-broker-caller-")

    def api_response(self, target_sha: str = TARGET_SHA) -> ApiResponse:
        return ApiResponse(f"{CALLER.PROJECT_GIT_COMMIT_API}{target_sha}", {"sha": target_sha})

    def write_json(self, path: Path, payload: dict[str, object]) -> None:
        path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")

    def assert_evidence_rejected(self, root: Path) -> None:
        with mock.patch.dict(os.environ, {CALLER.RUNNER_TEMP_ENVIRONMENT: str(root)}):
            with self.assertRaises(CALLER.CallerContractError):
                CALLER.verify_evidence(TARGET_SHA, NO_CRS_RUN_ID, WITH_CRS_RUN_ID)

    def identity(self, variant: str, run_id: str) -> dict[str, object]:
        profile = CALLER.PROFILE_BY_VARIANT[variant]
        payload: dict[str, object] = {
            "schema_version": 2,
            "run_id": run_id,
            "matrix_variant": variant,
            "parent_head_sha": TARGET_SHA,
            "framework_sha": CALLER.PROTECTED_FRAMEWORK_SHA,
            "protected_broker_sha": CALLER.PROTECTED_BROKER_SHA,
            "nginx_binary_sha256": BINARY_DIGEST,
            "nginx_module_sha256": MODULE_DIGEST,
            "modsecurity_library_sha256": LIBRARY_DIGEST,
            "nginx_version": "1.31.4",
            "master_pid": 42,
            "master_uid": 0,
            "worker_pid": 43,
            "worker_uid": 1000,
            "worker_gid": 1000,
            "policy_profile": profile,
        }
        if profile == CALLER.OWASP_CRS_PROFILE:
            payload["crs_bundle_digest"] = BUNDLE_DIGEST
            payload["crs_commit"] = CALLER.CRS_COMMIT
        return payload

    def runtime(self, variant: str, run_id: str) -> dict[str, object]:
        profile = CALLER.PROFILE_BY_VARIANT[variant]
        payload: dict[str, object] = {
            "schema_version": 2,
            "run_id": run_id,
            "matrix_variant": variant,
            "parent_head_sha": TARGET_SHA,
            "framework_sha": CALLER.PROTECTED_FRAMEWORK_SHA,
            "protected_broker_sha": CALLER.PROTECTED_BROKER_SHA,
            "artifact_digest": ARTIFACT_DIGEST,
            "nginx_binary_sha256": BINARY_DIGEST,
            "nginx_module_sha256": MODULE_DIGEST,
            "modsecurity_library_sha256": LIBRARY_DIGEST,
            "nginx_version": "1.31.4",
            "root_broker_status": "PASS",
            "cleanup_state": CALLER.CLEANUP_STATE,
            "policy_profile": profile,
            "scope": (
                CALLER.WITH_CRS_SCOPE
                if profile == CALLER.OWASP_CRS_PROFILE
                else CALLER.NO_CRS_SCOPE
            ),
        }
        if profile == CALLER.OWASP_CRS_PROFILE:
            payload["crs"] = {
                "crs_repository": CALLER.CRS_REPOSITORY,
                "crs_release_tag": CALLER.CRS_RELEASE_TAG,
                "crs_commit": CALLER.CRS_COMMIT,
                "crs_bundle_manifest_sha256": BUNDLE_MANIFEST_DIGEST,
                "crs_bundle_digest": BUNDLE_DIGEST,
                "crs_file_count": 1,
                "expected_crs_evidence": {
                    "rule_id": CALLER.CRS_RULE_ID,
                    "request_path": CALLER.CRS_BLOCK_PATH,
                    "allow_path": CALLER.CRS_ALLOW_PATH,
                },
            }
        return payload

    def policy(self, variant: str, run_id: str, audit: bytes | None) -> dict[str, object]:
        profile = CALLER.PROFILE_BY_VARIANT[variant]
        payload: dict[str, object] = {
            "schema_version": 2,
            "run_id": run_id,
            "matrix_variant": variant,
            "policy_profile": profile,
            "allow": {"path": CALLER.CRS_ALLOW_PATH, "status": 200},
        }
        if profile == CALLER.NO_CRS_PROFILE:
            payload["block"] = {"path": "/blocked", "status": 403, "rule_id": "941001"}
            return payload
        assert audit is not None
        payload.update(
            {
                "block": {"path": CALLER.CRS_BLOCK_PATH, "status": 403},
                "transaction_id": "broker-transaction",
                "audit_log_sha256": hashlib.sha256(audit).hexdigest(),
                "crs_rule_id": CALLER.CRS_RULE_ID,
                "crs_bundle_digest": BUNDLE_DIGEST,
                "crs_commit": CALLER.CRS_COMMIT,
            }
        )
        return payload

    def cleanup(self, variant: str, run_id: str) -> dict[str, object]:
        return {
            "broker_sha": CALLER.PROTECTED_BROKER_SHA,
            "cleanup_status": "PASS",
            "matrix_variant": variant,
            "run_id": run_id,
        }

    def write_evidence_directory(self, root: Path, variant: str, run_id: str) -> Path:
        directory = root / variant
        directory.mkdir()
        audit = None
        if variant == CALLER.WITH_CRS_VARIANT:
            audit = (
                f"--broker-transaction-A--\n{run_id}\n{CALLER.CRS_BLOCK_PATH}\n"
                f"[id \"{CALLER.CRS_RULE_ID}\"]\n403\n--broker-transaction-Z--\n"
            ).encode("utf-8")
            (directory / CALLER.AUDIT_LOG_FILENAME).write_bytes(audit)
        self.write_json(directory / CALLER.IDENTITY_FILENAME, self.identity(variant, run_id))
        self.write_json(directory / CALLER.RUNTIME_FILENAME, self.runtime(variant, run_id))
        self.write_json(directory / CALLER.POLICY_FILENAME, self.policy(variant, run_id, audit))
        (directory / CALLER.ACCESS_LOG_FILENAME).write_text("GET / 200\n", encoding="utf-8")
        (directory / CALLER.ERROR_LOG_FILENAME).write_text("notice\n", encoding="utf-8")
        self.write_json(directory / CALLER.CLEANUP_FILENAME, self.cleanup(variant, run_id))
        return directory

    def runner_manifest_root(self, root: Path) -> Path:
        return root / f"{CALLER.CALLER_MANIFEST_ROOT_PREFIX}caller-101-1"

    def runner_evidence_root(self, root: Path) -> Path:
        return root / f"{CALLER.CALLER_EVIDENCE_ROOT_PREFIX}caller-101-1"

    def test_manifest_generation_uses_exact_schema_private_files_and_read_only_api(self) -> None:
        with self.temporary_root() as temporary:
            root = Path(temporary)
            output = self.runner_manifest_root(root)
            with (
                mock.patch.dict(os.environ, {CALLER.RUNNER_TEMP_ENVIRONMENT: str(root)}),
                mock.patch.object(CALLER, "urlopen", return_value=self.api_response()) as opener,
            ):
                CALLER.create_manifests(TARGET_SHA, NO_CRS_RUN_ID, WITH_CRS_RUN_ID)
            request = opener.call_args.args[0]
            self.assertEqual(request.full_url, f"{CALLER.PROJECT_GIT_COMMIT_API}{TARGET_SHA}")
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
            for variant, run_id, profile in (
                (CALLER.NO_CRS_VARIANT, NO_CRS_RUN_ID, CALLER.NO_CRS_PROFILE),
                (CALLER.WITH_CRS_VARIANT, WITH_CRS_RUN_ID, CALLER.OWASP_CRS_PROFILE),
            ):
                path = output / variant / CALLER.CALLER_MANIFEST_FILENAME
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                payload = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(set(payload), CALLER.CALLER_MANIFEST_FIELDS)
                self.assertEqual(payload["run_id"], run_id)
                self.assertEqual(payload["policy_profile"], profile)

    def test_manifest_contract_rejects_schema_profile_and_field_mutations(self) -> None:
        payload = CALLER.manifest_payload(TARGET_SHA, WITH_CRS_RUN_ID, CALLER.WITH_CRS_VARIANT)
        mutations = {
            "schema v1": {**payload, "schema_version": 1},
            "missing policy profile": {
                key: value for key, value in payload.items() if key != "policy_profile"
            },
            "profile mismatch": {**payload, "policy_profile": CALLER.NO_CRS_PROFILE},
            "extra field": {**payload, "unexpected": "field"},
            "missing field": {key: value for key, value in payload.items() if key != "framework_sha"},
        }
        for name, mutated in mutations.items():
            with self.subTest(name=name), self.assertRaises(CALLER.CallerContractError):
                CALLER.validate_manifest(mutated, TARGET_SHA, WITH_CRS_RUN_ID, CALLER.WITH_CRS_VARIANT)
        with self.assertRaises(CALLER.CallerContractError):
            CALLER.create_manifests("A" * 40, NO_CRS_RUN_ID, WITH_CRS_RUN_ID)

    def test_caller_cli_paths_are_derived_only_from_runner_temp_and_fixed_run_pair(self) -> None:
        with self.temporary_root() as temporary:
            root = Path(temporary)
            outside = root / "outside"
            bad_with_crs_run_id = "protected-nginx-root-foreign-with-crs"
            argument_parser = CALLER.parser()
            create_arguments = [
                "create-manifests",
                "--target-sha",
                TARGET_SHA,
                "--no-crs-run-id",
                NO_CRS_RUN_ID,
                "--with-crs-run-id",
                WITH_CRS_RUN_ID,
                "--output-root",
                str(outside),
            ]
            verify_arguments = [
                "verify-evidence",
                "--target-sha",
                TARGET_SHA,
                "--no-crs-run-id",
                NO_CRS_RUN_ID,
                "--with-crs-run-id",
                WITH_CRS_RUN_ID,
                "--no-crs-directory",
                str(outside),
            ]
            with mock.patch.dict(os.environ, {CALLER.RUNNER_TEMP_ENVIRONMENT: str(root)}):
                with mock.patch.object(CALLER, "urlopen") as opener:
                    with self.assertRaises(CALLER.CallerContractError):
                        CALLER.create_manifests(TARGET_SHA, NO_CRS_RUN_ID, bad_with_crs_run_id)
                opener.assert_not_called()
            self.assertFalse(outside.exists())
            with mock.patch.object(sys, "stderr"):
                with self.assertRaises(SystemExit):
                    argument_parser.parse_args(create_arguments)
                with self.assertRaises(SystemExit):
                    argument_parser.parse_args(verify_arguments)
            self.assertFalse(outside.exists())

    def test_constructed_child_path_rejects_escape_and_symlink_before_use(self) -> None:
        with self.temporary_root() as temporary:
            root = Path(temporary)
            trusted = root / "trusted"
            trusted.mkdir()
            outside = root / "outside"
            with self.assertRaises(CALLER.CallerContractError):
                CALLER.validated_direct_child_path(trusted, "../outside", "candidate")
            symlink = trusted / "linked"
            symlink.symlink_to(outside)
            with self.assertRaises(CALLER.CallerContractError):
                CALLER.validated_direct_child_path(trusted, symlink.name, "candidate")
            self.assertFalse(outside.exists())

    def test_file_sinks_reject_a_symlink_before_opening_it(self) -> None:
        with self.temporary_root() as temporary:
            root = Path(temporary)
            trusted = root / "trusted"
            trusted.mkdir()
            linked = trusted / "linked"
            linked.symlink_to(root / "outside")
            with mock.patch.object(CALLER.os, "open") as opener:
                with self.assertRaises(CALLER.CallerContractError):
                    CALLER.write_private_json(linked, {}, "candidate")
            opener.assert_not_called()
            with mock.patch.object(CALLER.os, "open") as opener:
                with self.assertRaises(CALLER.CallerContractError):
                    CALLER.read_regular_file(linked, "candidate", 1024)
            opener.assert_not_called()

    def test_runner_temp_must_be_absolute_and_non_symlink_before_manifest_api_access(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            with mock.patch.object(CALLER, "urlopen") as opener:
                with self.assertRaises(CALLER.CallerContractError):
                    CALLER.create_manifests(TARGET_SHA, NO_CRS_RUN_ID, WITH_CRS_RUN_ID)
            opener.assert_not_called()
        with mock.patch.dict(os.environ, {CALLER.RUNNER_TEMP_ENVIRONMENT: "relative"}):
            with mock.patch.object(CALLER, "urlopen") as opener:
                with self.assertRaises(CALLER.CallerContractError):
                    CALLER.create_manifests(TARGET_SHA, NO_CRS_RUN_ID, WITH_CRS_RUN_ID)
                opener.assert_not_called()

    def test_evidence_readback_rejects_an_unsafe_runner_root_or_mismatched_pair_before_reads(self) -> None:
        bad_with_crs_run_id = "protected-nginx-root-foreign-with-crs"
        cases: tuple[dict[str, str], ...] = (
            {},
            {CALLER.RUNNER_TEMP_ENVIRONMENT: "relative"},
        )
        for environment in cases:
            with self.subTest(environment=environment):
                with mock.patch.dict(os.environ, environment, clear=True):
                    with mock.patch.object(CALLER, "validate_evidence_directory") as validator:
                        with self.assertRaises(CALLER.CallerContractError):
                            CALLER.verify_evidence(TARGET_SHA, NO_CRS_RUN_ID, WITH_CRS_RUN_ID)
                    validator.assert_not_called()
        with self.temporary_root() as temporary:
            root = Path(temporary)
            trusted = root / "trusted"
            trusted.mkdir()
            symlink = root / "symlink"
            symlink.symlink_to(trusted, target_is_directory=True)
            for runner_temp, with_crs_run_id in (
                (str(symlink), WITH_CRS_RUN_ID),
                (str(trusted), bad_with_crs_run_id),
            ):
                with self.subTest(runner_temp=runner_temp, with_crs_run_id=with_crs_run_id):
                    with mock.patch.dict(
                        os.environ,
                        {CALLER.RUNNER_TEMP_ENVIRONMENT: runner_temp},
                        clear=True,
                    ):
                        with mock.patch.object(CALLER, "validate_evidence_directory") as validator:
                            with self.assertRaises(CALLER.CallerContractError):
                                CALLER.verify_evidence(
                                    TARGET_SHA,
                                    NO_CRS_RUN_ID,
                                    with_crs_run_id,
                                )
                        validator.assert_not_called()
            evidence_root = self.runner_evidence_root(trusted)
            evidence_root.symlink_to(root / "outside", target_is_directory=True)
            with mock.patch.dict(
                os.environ,
                {CALLER.RUNNER_TEMP_ENVIRONMENT: str(trusted)},
                clear=True,
            ):
                with mock.patch.object(CALLER, "validate_evidence_directory") as validator:
                    with self.assertRaises(CALLER.CallerContractError):
                        CALLER.verify_evidence(TARGET_SHA, NO_CRS_RUN_ID, WITH_CRS_RUN_ID)
                validator.assert_not_called()
        with self.temporary_root() as temporary:
            root = Path(temporary)
            trusted = root / "trusted"
            trusted.mkdir()
            symlink = root / "symlink"
            symlink.symlink_to(trusted, target_is_directory=True)
            with mock.patch.dict(os.environ, {CALLER.RUNNER_TEMP_ENVIRONMENT: str(symlink)}):
                with mock.patch.object(CALLER, "urlopen") as opener:
                    with self.assertRaises(CALLER.CallerContractError):
                        CALLER.create_manifests(TARGET_SHA, NO_CRS_RUN_ID, WITH_CRS_RUN_ID)
                opener.assert_not_called()

    def test_target_api_requires_the_exact_nonredirected_commit_identity(self) -> None:
        with mock.patch.object(
            CALLER,
            "urlopen",
            return_value=ApiResponse("https://example.invalid/redirect", {"sha": TARGET_SHA}),
        ):
            with self.assertRaises(CALLER.CallerContractError):
                CALLER.verify_target_commit(TARGET_SHA)
        with mock.patch.object(CALLER, "urlopen", return_value=self.api_response("2" * 40)):
            with self.assertRaises(CALLER.CallerContractError):
                CALLER.verify_target_commit(TARGET_SHA)
        with mock.patch.object(CALLER, "urlopen", side_effect=TimeoutError("timeout")):
            with self.assertRaises(CALLER.CallerContractError):
                CALLER.verify_target_commit(TARGET_SHA)

    def test_evidence_readback_rejects_unknown_cross_run_and_missing_audit_content(self) -> None:
        with self.temporary_root() as temporary:
            root = Path(temporary)
            evidence_root = self.runner_evidence_root(root)
            evidence_root.mkdir()
            no_crs = self.write_evidence_directory(
                evidence_root, CALLER.NO_CRS_VARIANT, NO_CRS_RUN_ID
            )
            with_crs = self.write_evidence_directory(
                evidence_root, CALLER.WITH_CRS_VARIANT, WITH_CRS_RUN_ID
            )
            with mock.patch.dict(os.environ, {CALLER.RUNNER_TEMP_ENVIRONMENT: str(root)}):
                CALLER.verify_evidence(TARGET_SHA, NO_CRS_RUN_ID, WITH_CRS_RUN_ID)

            runtime_path = no_crs / CALLER.RUNTIME_FILENAME
            runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
            runtime["unexpected"] = True
            self.write_json(runtime_path, runtime)
            self.assert_evidence_rejected(root)

        with self.temporary_root() as temporary:
            root = Path(temporary)
            evidence_root = self.runner_evidence_root(root)
            evidence_root.mkdir()
            no_crs = self.write_evidence_directory(
                evidence_root, CALLER.NO_CRS_VARIANT, NO_CRS_RUN_ID
            )
            with_crs = self.write_evidence_directory(
                evidence_root, CALLER.WITH_CRS_VARIANT, WITH_CRS_RUN_ID
            )
            (with_crs / CALLER.AUDIT_LOG_FILENAME).write_bytes(b"")
            self.assert_evidence_rejected(root)

        with self.temporary_root() as temporary:
            root = Path(temporary)
            evidence_root = self.runner_evidence_root(root)
            evidence_root.mkdir()
            no_crs = self.write_evidence_directory(
                evidence_root, CALLER.NO_CRS_VARIANT, NO_CRS_RUN_ID
            )
            with_crs = self.write_evidence_directory(
                evidence_root, CALLER.WITH_CRS_VARIANT, WITH_CRS_RUN_ID
            )
            identity_path = with_crs / CALLER.IDENTITY_FILENAME
            identity = json.loads(identity_path.read_text(encoding="utf-8"))
            identity["run_id"] = "foreign-run"
            self.write_json(identity_path, identity)
            with mock.patch.dict(os.environ, {CALLER.RUNNER_TEMP_ENVIRONMENT: str(root)}):
                with self.assertRaises(CALLER.CallerContractError):
                    CALLER.verify_evidence(TARGET_SHA, NO_CRS_RUN_ID, WITH_CRS_RUN_ID)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
