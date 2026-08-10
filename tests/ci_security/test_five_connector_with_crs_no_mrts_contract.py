from __future__ import annotations

import copy
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from typing import Callable
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
CATALOG_DIRECTORY = ROOT / "ci/checks/catalog"
MODULE_PATH = CATALOG_DIRECTORY / "five_connectors_with_crs_no_mrts.py"
WORKFLOW_PATH = ROOT / ".github/workflows/five-connectors-with-crs-no-mrts-contract.yml"
QUALITY_WORKFLOW_PATH = ROOT / ".github/workflows/ci-security-quality.yml"
PYRIGHT_CONFIG_PATH = ROOT / "pyrightconfig.json"
MAKEFILE_PATH = ROOT / "Makefile"
EVENT_SCHEMA_PATH = (
    ROOT / "tests/schemas/five-connectors-with-crs-no-mrts/normalized-event.schema.json"
)
MANIFEST_SCHEMA_PATH = (
    ROOT / "tests/schemas/five-connectors-with-crs-no-mrts/manifest.schema.json"
)
RECEIPT_SCHEMA_PATH = (
    ROOT / "tests/schemas/five-connectors-with-crs-no-mrts/receipt.schema.json"
)
RESULT_SCHEMA_PATH = (
    ROOT / "tests/schemas/five-connectors-with-crs-no-mrts/result.schema.json"
)
MAKE_RUNNER_PATH = ROOT / "ci/tools/run-five-connectors-with-crs-no-mrts.py"

if str(CATALOG_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(CATALOG_DIRECTORY))
SPEC = importlib.util.spec_from_file_location("five_connector_contract", MODULE_PATH)
assert SPEC is not None
assert SPEC.loader is not None
contract = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(contract)
RUNNER_SPEC = importlib.util.spec_from_file_location(
    "five_connector_make_runner", MAKE_RUNNER_PATH
)
assert RUNNER_SPEC is not None
assert RUNNER_SPEC.loader is not None
make_runner = importlib.util.module_from_spec(RUNNER_SPEC)
RUNNER_SPEC.loader.exec_module(make_runner)


class FiveConnectorWithCrsNoMrtsContractTest(unittest.TestCase):
    framework_commit = "a" * 40
    run_id = "five-crs-contract-run-1"

    def _run_git(self, *arguments: str) -> str:
        completed = subprocess.run(
            ["git", *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return completed.stdout.strip()

    def _write_text(self, path: Path, content: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def _write_json(self, path: Path, value: object) -> None:
        self._write_text(path, json.dumps(value, indent=2, sort_keys=True) + "\n")

    @staticmethod
    def _sha256(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    @staticmethod
    def _raw_record(fields: dict[str, object]) -> str:
        return (
            "\n".join(
                f"{name}={contract._record_value(value)}"
                for name, value in fields.items()
            )
            + "\n"
        )

    def _fixture_and_source(
        self, parent: Path
    ) -> tuple[dict[str, object], Path, str, str]:
        source_root = parent / "fresh-source"
        repository = source_root / "coreruleset"
        rule_path = repository / contract.CRS_RULE_FILE
        source = "\n".join(
            (
                'SecRule ARGS "@rx (?i)union.*?select.*?from" \\',
                '  "id:942270,phase:2,deny,',
                "  msg:'Looking for basic sql injection. Common attack string for mysql, oracle and others',",
                "  ver:'OWASP_CRS/4.28.0'\"",
                "",
            )
        )
        self._write_text(rule_path, source)
        self._run_git("init", "--quiet", str(repository))
        self._run_git(
            "-C", str(repository), "config", "user.email", "contract@example.test"
        )
        self._run_git("-C", str(repository), "config", "user.name", "Contract Test")
        self._run_git(
            "-C",
            str(repository),
            "add",
            "rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
        )
        self._run_git("-C", str(repository), "commit", "--quiet", "-m", "fixture")
        commit = self._run_git("-C", str(repository), "rev-parse", "HEAD")
        self._run_git("-C", str(repository), "tag", contract.CRS_RELEASE_TAG)
        self._run_git(
            "-C", str(repository), "remote", "add", "origin", contract.CRS_REPOSITORY
        )
        fixture = copy.deepcopy(contract.load_fixture())
        profile = fixture["with_crs_no_mrts"]
        assert isinstance(profile, dict)
        provenance = profile["provenance"]
        assert isinstance(provenance, dict)
        provenance["commit"] = commit
        provenance["rule_file_sha256"] = self._sha256(rule_path)
        schema_directory = parent / "contract-schemas"
        schema_directory.mkdir()
        self._schema_paths: dict[str, Path] = {}
        for name, production_path in {
            "event": contract.EVENT_SCHEMA_PATH,
            "manifest": contract.MANIFEST_SCHEMA_PATH,
            "receipt": contract.RECEIPT_SCHEMA_PATH,
            "result": contract.RESULT_SCHEMA_PATH,
        }.items():
            payload = json.loads(production_path.read_text(encoding="utf-8"))
            properties = payload["properties"]
            assert isinstance(properties, dict)
            if name in {"event", "manifest"}:
                properties["crs_rule_file_sha256"] = {"const": self._sha256(rule_path)}
            if name in {"event", "manifest", "receipt"}:
                properties["crs_commit"] = {"const": commit}
            path = schema_directory / production_path.name
            self._write_json(path, payload)
            self._schema_paths[name] = path
        return fixture, source_root, commit, self._sha256(rule_path)

    def _patch_contract(self, source_commit: str, source_sha256: str):
        return mock.patch.multiple(
            contract,
            CRS_COMMIT=source_commit,
            CRS_RULE_FILE_SHA256=source_sha256,
            EVENT_SCHEMA_PATH=self._schema_paths["event"],
            MANIFEST_SCHEMA_PATH=self._schema_paths["manifest"],
            RECEIPT_SCHEMA_PATH=self._schema_paths["receipt"],
            RESULT_SCHEMA_PATH=self._schema_paths["result"],
            verifier_framework_commit=mock.Mock(return_value=self.framework_commit),
        )

    def _artifact(self, root: Path, relative: Path, content: str) -> dict[str, str]:
        path = root / relative
        self._write_text(path, content)
        return {
            "evidence_path": relative.as_posix(),
            "evidence_sha256": self._sha256(path),
        }

    def _event(
        self, root: Path, connector: str, source_commit: str, source_sha256: str
    ) -> dict[str, object]:
        adapter = contract.ADAPTERS[connector]
        host_configuration = self._artifact(
            root,
            contract.host_configuration_relative_path(connector, self.run_id),
            self._raw_record(
                {
                    "schema_version": contract.SCHEMA_VERSION,
                    "record_type": "host_configuration",
                    "profile": contract.PROFILE,
                    "connector": connector,
                    "integration_mode": adapter["integration_mode"],
                    "run_id": self.run_id,
                    "config_test_status": "passed",
                    "host_start_status": "passed",
                }
            ),
        )
        allow_evidence = self._artifact(
            root,
            contract.allow_evidence_relative_path(connector, self.run_id),
            self._raw_record(
                {
                    "schema_version": contract.SCHEMA_VERSION,
                    "record_type": "allow_request",
                    "profile": contract.PROFILE,
                    "connector": connector,
                    "integration_mode": adapter["integration_mode"],
                    "fixture_id": f"{contract.FIXTURE_ID}:allow",
                    "run_id": self.run_id,
                    "request_id": f"{connector}-allow-request",
                    "transaction_id": f"{connector}-allow-transaction",
                    "method": "GET",
                    "path": contract.ALLOW_PATH,
                    "correlation_header": contract.CORRELATION_HEADER,
                    "correlation_value": self.run_id,
                    "payload_length": 0,
                    "status": 200,
                }
            ),
        )
        block_evidence = self._artifact(
            root,
            contract.block_evidence_relative_path(connector, self.run_id),
            self._raw_record(
                {
                    "schema_version": contract.SCHEMA_VERSION,
                    "record_type": "block_audit",
                    "profile": contract.PROFILE,
                    "connector": connector,
                    "integration_mode": adapter["integration_mode"],
                    "fixture_id": contract.FIXTURE_ID,
                    "run_id": self.run_id,
                    "request_id": f"{connector}-block-request",
                    "transaction_id": f"{connector}-block-transaction",
                    "method": "GET",
                    "path": contract.BLOCK_PATH,
                    "correlation_header": contract.CORRELATION_HEADER,
                    "correlation_value": self.run_id,
                    "payload_length": 0,
                    "expected_rule_id": contract.EXPECTED_RULE_ID,
                    "observed_rule_id": contract.EXPECTED_RULE_ID,
                    "expected_status": 403,
                    "observed_status": 403,
                    "intervention": "deny",
                    "evidence_type": adapter["evidence_types"][0],
                }
            ),
        )
        cleanup_evidence = self._artifact(
            root,
            contract.cleanup_evidence_relative_path(connector, self.run_id),
            self._raw_record(
                {
                    "schema_version": contract.SCHEMA_VERSION,
                    "record_type": "cleanup",
                    "profile": contract.PROFILE,
                    "connector": connector,
                    "run_id": self.run_id,
                    "status": "passed",
                    "host_processes_remaining": 0,
                    "helper_processes_remaining": 0,
                    "listeners_remaining": 0,
                    "sockets_remaining": 0,
                    "pid_files_remaining": 0,
                    "runtime_fixtures_remaining": 0,
                    "temporary_paths_remaining": 0,
                    "mrts_runner_invoked": False,
                    "mrts_case_inventory_loaded": False,
                    "mrts_process_started": False,
                    "mrts_socket_or_listener_created": False,
                    "mrts_artifact_used": False,
                }
            ),
        )
        allow = {
            "fixture_id": f"{contract.FIXTURE_ID}:allow",
            "run_id": self.run_id,
            "request_id": f"{connector}-allow-request",
            "transaction_id": f"{connector}-allow-transaction",
            "expected_status": 200,
            "observed_status": 200,
            "observed_rule_id": None,
            **allow_evidence,
        }
        cleanup = {
            "status": "passed",
            "host_processes_remaining": 0,
            "helper_processes_remaining": 0,
            "listeners_remaining": 0,
            "sockets_remaining": 0,
            "pid_files_remaining": 0,
            "runtime_fixtures_remaining": 0,
            "temporary_paths_remaining": 0,
            **cleanup_evidence,
        }
        event = {
            "schema_version": contract.SCHEMA_VERSION,
            "profile": contract.PROFILE,
            "connector": connector,
            "adapter_id": adapter["adapter_id"],
            "integration_mode": adapter["integration_mode"],
            "fixture_id": contract.FIXTURE_ID,
            "run_id": self.run_id,
            "framework_commit": self.framework_commit,
            "connector_commit": "b" * 40,
            "request_id": f"{connector}-block-request",
            "transaction_id": f"{connector}-block-transaction",
            "evidence_type": adapter["evidence_types"][0],
            "evidence_origin": "connector-host",
            "crs_repository": contract.CRS_REPOSITORY,
            "crs_release_tag": contract.CRS_RELEASE_TAG,
            "crs_commit": source_commit,
            "crs_rule_file": contract.CRS_RULE_FILE,
            "crs_rule_file_sha256": source_sha256,
            "crs_source_kind": "fresh",
            "crs_git_ref": contract.CRS_RELEASE_TAG,
            "expected_rule_id": contract.EXPECTED_RULE_ID,
            "observed_rule_id": contract.EXPECTED_RULE_ID,
            "expected_status": 403,
            "observed_status": 403,
            "intervention": "deny",
            "allow_case": allow,
            "host_configuration": {
                "config_test_status": "passed",
                "host_start_status": "passed",
                **host_configuration,
            },
            "block_evidence": block_evidence,
            "no_mrts": {field: False for field in contract.NO_MRTS_FIELDS},
            "cleanup": cleanup,
            "status": "PASS",
            "failure_count": 0,
            "mismatch_count": 0,
        }
        self.assertEqual(set(event), contract.EVENT_FIELDS)
        return event

    def _write_event(
        self, root: Path, connector: str, source_commit: str, source_sha256: str
    ) -> Path:
        event = self._event(root, connector, source_commit, source_sha256)
        path = root / contract.normalized_event_relative_path(connector, self.run_id)
        self._write_json(path, event)
        return path

    def _private_evidence_root(self, parent: Path) -> Path:
        root = parent / "evidence"
        root.mkdir(mode=0o700)
        os.chmod(root, 0o700)
        return root

    def _validate_all(
        self,
        root: Path,
        fixture: dict[str, object],
        source_root: Path,
        source_commit: str,
        source_sha256: str,
        connectors: tuple[str, ...] | None = None,
    ) -> dict[str, object]:
        selected = connectors or contract.CONNECTORS
        with self._patch_contract(source_commit, source_sha256):
            for connector in selected:
                contract.validate_connector_run(
                    root, connector, self.run_id, fixture, source_root
                )
            return dict(contract.aggregate(root, self.run_id, fixture, source_root))

    def _single_validation_error(
        self,
        mutate: Callable[[dict[str, object], Path], None],
        *,
        connector: str = "apache",
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="five-crs-negative-") as temporary:
            parent = Path(temporary)
            fixture, source_root, source_commit, source_sha256 = (
                self._fixture_and_source(parent)
            )
            root = self._private_evidence_root(parent)
            event_path = self._write_event(
                root, connector, source_commit, source_sha256
            )
            event = json.loads(event_path.read_text(encoding="utf-8"))
            mutate(event, root)
            self._write_json(event_path, event)
            with self._patch_contract(source_commit, source_sha256):
                with self.assertRaises(contract.ContractError):
                    contract.validate_connector_run(
                        root, connector, self.run_id, fixture, source_root
                    )

    def test_canonical_profile_fixture_and_schema_are_closed(self) -> None:
        fixture = contract.load_fixture()
        self.assertEqual(
            contract.profile_payload()["connectors"], list(contract.CONNECTORS)
        )
        self.assertNotIn("nginx", contract.CONNECTORS)
        self.assertEqual(
            fixture["with_crs_no_mrts"]["canonical_block"]["expected_rule_id"], 942270
        )
        self.assertEqual(
            contract.CRS_COMMIT, "55b09f5acfd16413e7b31041100711ceb7adc89c"
        )
        self.assertEqual(
            contract.CRS_RULE_FILE_SHA256,
            "db756f71e8270280c5ae74d09c11250fad8c118f6a905c6a6794d5643d27cd00",
        )
        for schema_path, expected_fields in (
            (EVENT_SCHEMA_PATH, contract.EVENT_FIELDS),
            (MANIFEST_SCHEMA_PATH, contract.MANIFEST_FIELDS),
            (RECEIPT_SCHEMA_PATH, contract.RECEIPT_FIELDS),
            (RESULT_SCHEMA_PATH, contract.RESULT_FIELDS),
        ):
            with self.subTest(schema=schema_path.name):
                schema = json.loads(schema_path.read_text(encoding="utf-8"))
                self.assertEqual(set(schema["required"]), expected_fields)
                self.assertEqual(set(schema["properties"]), expected_fields)
                self.assertFalse(schema["additionalProperties"])
                self.assertEqual(
                    schema["properties"]["schema_version"]["const"],
                    contract.SCHEMA_VERSION,
                )
                self.assertEqual(
                    schema["properties"]["connector"]["enum"], list(contract.CONNECTORS)
                )

        with mock.patch.dict(
            contract.ADAPTERS["apache"],
            {"framework_entrypoint": "ci/runtime/run-haproxy-smoke.sh"},
        ):
            with self.assertRaises(contract.ContractError):
                contract.validate_profile()

    def test_fixture_top_level_semantics_cannot_drift_from_canonical_block(
        self,
    ) -> None:
        for label, section_name, field, value in (
            ("path", "request", "path", "/?id=42"),
            ("status", "expect", "status", 200),
            ("intervention", "expect", "intervention", "pass"),
        ):
            with self.subTest(field=label):
                fixture = copy.deepcopy(contract.load_fixture())
                section = fixture[section_name]
                assert isinstance(section, dict)
                section[field] = value
                with self.assertRaises(contract.ContractError):
                    contract.validate_fixture(fixture)

    def test_each_selected_adapter_emits_only_a_non_promoting_contract_result(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="five-crs-valid-") as temporary:
            parent = Path(temporary)
            fixture, source_root, source_commit, source_sha256 = (
                self._fixture_and_source(parent)
            )
            root = self._private_evidence_root(parent)
            for connector in contract.CONNECTORS:
                self._write_event(root, connector, source_commit, source_sha256)
            aggregate = self._validate_all(
                root, fixture, source_root, source_commit, source_sha256
            )
            self.assertEqual(aggregate["status"], contract.CONTRACT_VALIDATED)
            self.assertEqual(aggregate["host_runtime_status"], "UNATTESTED")
            self.assertEqual(aggregate["connectors"], list(contract.CONNECTORS))
            for connector in contract.CONNECTORS:
                manifest = json.loads(
                    (
                        contract.result_directory(root, connector, self.run_id)
                        / "manifest.json"
                    ).read_text(encoding="utf-8")
                )
                self.assertEqual(
                    manifest["adapter_id"], contract.ADAPTERS[connector]["adapter_id"]
                )
                self.assertEqual(
                    manifest["integration_mode"],
                    contract.ADAPTERS[connector]["integration_mode"],
                )
                self.assertEqual(
                    manifest["framework_entrypoint"],
                    contract.ADAPTERS[connector]["framework_entrypoint"],
                )
                self.assertEqual(
                    manifest["framework_entrypoint_role"], "compatibility-only"
                )
                self.assertEqual(manifest["host_contract_owner"], "parent")
                self.assertEqual(
                    set(manifest["artifacts"]),
                    {
                        "host_configuration",
                        "allow_request",
                        "block_audit",
                        "cleanup",
                        "normalized_event",
                    },
                )

    def test_inventory_and_duplicate_outputs_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="five-crs-inventory-") as temporary:
            parent = Path(temporary)
            fixture, source_root, source_commit, source_sha256 = (
                self._fixture_and_source(parent)
            )
            root = self._private_evidence_root(parent)
            for connector in contract.CONNECTORS[:-1]:
                self._write_event(root, connector, source_commit, source_sha256)
            with self._patch_contract(source_commit, source_sha256):
                for connector in contract.CONNECTORS[:-1]:
                    contract.validate_connector_run(
                        root, connector, self.run_id, fixture, source_root
                    )
                with self.assertRaises(contract.ContractError):
                    contract.aggregate(root, self.run_id, fixture, source_root)
                with self.assertRaises(contract.ContractError):
                    contract.validate_connector_run(
                        root, "nginx", self.run_id, fixture, source_root
                    )
                with self.assertRaises(contract.ContractError):
                    contract.validate_connector_run(
                        root, "apache", self.run_id, fixture, source_root
                    )

    def test_aggregate_revalidates_host_inputs_instead_of_accepting_preseeded_bundles(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="five-crs-preseeded-") as temporary:
            parent = Path(temporary)
            fixture, source_root, source_commit, source_sha256 = (
                self._fixture_and_source(parent)
            )
            root = self._private_evidence_root(parent)
            for connector in contract.CONNECTORS:
                output = contract.result_directory(root, connector, self.run_id)
                self._write_json(
                    output / "result.json", {"status": contract.CONTRACT_VALIDATED}
                )
                self._write_json(output / "manifest.json", {})
                self._write_json(output / "receipt.json", {})
            with self._patch_contract(source_commit, source_sha256):
                with self.assertRaises(contract.ContractError):
                    contract.aggregate(root, self.run_id, fixture, source_root)

    def test_output_reservation_never_replaces_a_same_uid_run_directory(self) -> None:
        with tempfile.TemporaryDirectory(prefix="five-crs-output-race-") as temporary:
            parent = Path(temporary)
            fixture, source_root, source_commit, source_sha256 = (
                self._fixture_and_source(parent)
            )
            root = self._private_evidence_root(parent)
            self._write_event(root, "apache", source_commit, source_sha256)
            foreign_output = contract.result_directory(root, "apache", self.run_id)
            sentinel = foreign_output / "foreign-owner.txt"
            self._write_text(sentinel, "must remain intact\n")
            with self._patch_contract(source_commit, source_sha256):
                with self.assertRaises(contract.ContractError):
                    contract.validate_connector_run(
                        root, "apache", self.run_id, fixture, source_root
                    )
            self.assertEqual(
                sentinel.read_text(encoding="utf-8"), "must remain intact\n"
            )

        with tempfile.TemporaryDirectory(
            prefix="five-crs-aggregate-race-"
        ) as temporary:
            parent = Path(temporary)
            fixture, source_root, source_commit, source_sha256 = (
                self._fixture_and_source(parent)
            )
            root = self._private_evidence_root(parent)
            for connector in contract.CONNECTORS:
                self._write_event(root, connector, source_commit, source_sha256)
            with self._patch_contract(source_commit, source_sha256):
                for connector in contract.CONNECTORS:
                    contract.validate_connector_run(
                        root, connector, self.run_id, fixture, source_root
                    )
                aggregate_directory = root / "aggregate" / self.run_id
                sentinel = aggregate_directory / "foreign-owner.txt"
                self._write_text(sentinel, "must remain intact\n")
                with self.assertRaises(contract.ContractError):
                    contract.aggregate(root, self.run_id, fixture, source_root)
            self.assertEqual(
                sentinel.read_text(encoding="utf-8"), "must remain intact\n"
            )

    def test_evidence_snapshot_binds_the_parsed_bytes_and_digest_to_one_descriptor(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="five-crs-input-race-") as temporary:
            parent = Path(temporary)
            root = self._private_evidence_root(parent)
            path = root / "raw-evidence.log"
            replacement = parent / "replacement.log"
            original = "record=first-snapshot\n"
            replacement_content = "record=replaced-by-name-swap\n"
            self._write_text(path, original)
            self._write_text(replacement, replacement_content)
            original_read = contract.os.read
            replaced = False

            def read_then_replace(descriptor: int, size: int) -> bytes:
                nonlocal replaced
                chunk = original_read(descriptor, size)
                if chunk and not replaced:
                    os.replace(replacement, path)
                    replaced = True
                return chunk

            with mock.patch.object(contract.os, "read", side_effect=read_then_replace):
                with self.assertRaises(contract.ContractError) as raised:
                    contract._read_bounded_regular_text(path, "race test evidence")

            self.assertTrue(replaced)
            self.assertIn("changed while it was being read", str(raised.exception))
            self.assertEqual(path.read_text(encoding="utf-8"), replacement_content)

    def test_fixture_provenance_rejects_a_checkout_name_swap_during_rule_read(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="five-crs-source-race-") as temporary:
            parent = Path(temporary)
            fixture, source_root, source_commit, source_sha256 = (
                self._fixture_and_source(parent)
            )
            source = source_root / "coreruleset"
            replacement = parent / "replacement-coreruleset"
            original = parent / "original-coreruleset"
            shutil.copytree(source, replacement)
            original_reader = contract._read_bounded_regular_text
            replaced = False

            def swap_then_read(
                path: Path, label: str, *, max_bytes: int = contract.MAX_EVIDENCE_BYTES
            ) -> tuple[str, str]:
                nonlocal replaced
                if path == source / contract.CRS_RULE_FILE and not replaced:
                    os.replace(source, original)
                    os.replace(replacement, source)
                    replaced = True
                return original_reader(path, label, max_bytes=max_bytes)

            with self._patch_contract(source_commit, source_sha256):
                with mock.patch.object(
                    contract, "_read_bounded_regular_text", side_effect=swap_then_read
                ):
                    with self.assertRaises(contract.ContractError) as raised:
                        contract.verify_fixture_source(fixture, source_root)

            self.assertTrue(replaced)
            self.assertIn(
                "changed while the rule was being checked", str(raised.exception)
            )

    def test_closed_schema_rejects_extra_nested_evidence_fields(self) -> None:
        with tempfile.TemporaryDirectory(prefix="five-crs-schema-") as temporary:
            parent = Path(temporary)
            _, _, source_commit, source_sha256 = self._fixture_and_source(parent)
            root = self._private_evidence_root(parent)
            event = self._event(root, "apache", source_commit, source_sha256)
            allow = event["allow_case"]
            assert isinstance(allow, dict)
            allow["synthetic_field"] = "forbidden"
            with self._patch_contract(source_commit, source_sha256):
                with self.assertRaises(contract.ContractError):
                    contract._validate_event_schema(event)

    def test_rejects_non_pass_rule_status_correlation_and_adapter_drift(self) -> None:
        mutations = {
            "not_executable": lambda event, root: event.__setitem__(
                "status", "NOT_EXECUTABLE"
            ),
            "wrong_rule": lambda event, root: event.__setitem__(
                "observed_rule_id", 942100
            ),
            "wrong_status": lambda event, root: event.__setitem__(
                "observed_status", 200
            ),
            "failure_count": lambda event, root: event.__setitem__("failure_count", 1),
            "mismatch_count": lambda event, root: event.__setitem__(
                "mismatch_count", 1
            ),
            "foreign_run": lambda event, root: event.__setitem__(
                "run_id", "foreign-run"
            ),
            "foreign_request": lambda event, root: event.__setitem__(
                "request_id", "foreign-request"
            ),
            "foreign_transaction": lambda event, root: event.__setitem__(
                "transaction_id", "foreign-transaction"
            ),
            "foreign_framework_commit": lambda event, root: event.__setitem__(
                "framework_commit", "c" * 40
            ),
            "wrong_mode": lambda event, root: event.__setitem__(
                "integration_mode", "http-forwardauth-service"
            ),
            "synthetic": lambda event, root: event.__setitem__(
                "evidence_origin", "synthetic"
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                self._single_validation_error(mutate)
        for connector, compatibility_mode in {
            "haproxy": "spoe-spop-agent",
            "envoy": "ext_authz",
            "traefik": "forwardAuth",
            "lighttpd": "sidecar_proxy",
        }.items():
            with self.subTest(
                connector=connector, compatibility_mode=compatibility_mode
            ):
                self._single_validation_error(
                    lambda event, root, compatibility_mode=compatibility_mode: (
                        event.__setitem__("integration_mode", compatibility_mode)
                    ),
                    connector=connector,
                )

    def test_raw_evidence_records_reject_confusable_markers_and_bound_control_drift(
        self,
    ) -> None:
        def rewrite_raw(
            event: dict[str, object],
            root: Path,
            section: str,
            old: str,
            new: str,
        ) -> None:
            artifact = event[section]
            assert isinstance(artifact, dict)
            relative = artifact["evidence_path"]
            assert isinstance(relative, str)
            path = root / relative
            self._write_text(path, path.read_text(encoding="utf-8").replace(old, new))
            artifact["evidence_sha256"] = self._sha256(path)

        def fake_rule(event: dict[str, object], root: Path) -> None:
            rewrite_raw(
                event,
                root,
                "block_evidence",
                "observed_rule_id=942270",
                "fake_observed_rule_id=9422700",
            )

        def fake_status(event: dict[str, object], root: Path) -> None:
            rewrite_raw(
                event,
                root,
                "block_evidence",
                "observed_status=403",
                "not_observed_status=4030",
            )

        def raw_mrts(event: dict[str, object], root: Path) -> None:
            rewrite_raw(
                event,
                root,
                "cleanup",
                "mrts_runner_invoked=false",
                "mrts_runner_invoked=true",
            )

        def raw_cleanup(event: dict[str, object], root: Path) -> None:
            rewrite_raw(
                event,
                root,
                "cleanup",
                "listeners_remaining=0",
                "listeners_remaining=1",
            )

        for name, mutate in {
            "prefix_rule_marker": fake_rule,
            "prefix_status_marker": fake_status,
            "raw_mrts": raw_mrts,
            "raw_cleanup": raw_cleanup,
        }.items():
            with self.subTest(name=name):
                self._single_validation_error(mutate)

    def test_rejects_no_mrts_cleanup_and_host_configuration_violations(self) -> None:
        for field in contract.NO_MRTS_FIELDS:
            with self.subTest(no_mrts_field=field):
                self._single_validation_error(
                    lambda event, root, field=field: event["no_mrts"].__setitem__(
                        field, True
                    )
                )
        for field in (
            "host_processes_remaining",
            "helper_processes_remaining",
            "listeners_remaining",
            "sockets_remaining",
            "pid_files_remaining",
            "runtime_fixtures_remaining",
            "temporary_paths_remaining",
        ):
            with self.subTest(cleanup_field=field):
                self._single_validation_error(
                    lambda event, root, field=field: event["cleanup"].__setitem__(
                        field, 1
                    )
                )
        self._single_validation_error(
            lambda event, root: event["host_configuration"].__setitem__(
                "config_test_status", "failed"
            )
        )
        self._single_validation_error(
            lambda event, root: event["cleanup"].__setitem__("status", "failed")
        )

        def raw_mrts_marker(event: dict[str, object], root: Path) -> None:
            path = root / contract.cleanup_evidence_relative_path("apache", self.run_id)
            self._write_text(
                path,
                path.read_text(encoding="utf-8").replace(
                    "mrts_runner_invoked=false",
                    "mrts_runner_invoked=true",
                ),
            )
            event["cleanup"]["evidence_sha256"] = self._sha256(path)

        self._single_validation_error(raw_mrts_marker)

    def test_rejects_stale_empty_hashed_and_symlink_evidence(self) -> None:
        self._single_validation_error(
            lambda event, root: event["block_evidence"].__setitem__(
                "evidence_path", "raw/apache/old/block-audit.log"
            )
        )
        self._single_validation_error(
            lambda event, root: event["block_evidence"].__setitem__(
                "evidence_sha256", "0" * 64
            )
        )

        def empty_allow(event: dict[str, object], root: Path) -> None:
            path = root / contract.allow_evidence_relative_path("apache", self.run_id)
            self._write_text(path, "")
            event["allow_case"]["evidence_sha256"] = self._sha256(path)

        self._single_validation_error(empty_allow)
        if hasattr(os, "symlink"):

            def symlink_block(event: dict[str, object], root: Path) -> None:
                target = root.parent / "outside.log"
                self._write_text(target, "outside\n")
                path = root / contract.block_evidence_relative_path(
                    "apache", self.run_id
                )
                path.unlink()
                path.symlink_to(target)
                event["block_evidence"]["evidence_sha256"] = self._sha256(target)

            self._single_validation_error(symlink_block)

    def test_fixture_and_fresh_source_provenance_are_required(self) -> None:
        with tempfile.TemporaryDirectory(prefix="five-crs-provenance-") as temporary:
            parent = Path(temporary)
            fixture, source_root, source_commit, source_sha256 = (
                self._fixture_and_source(parent)
            )
            with mock.patch.multiple(
                contract, CRS_COMMIT=source_commit, CRS_RULE_FILE_SHA256=source_sha256
            ):
                self.assertTrue(
                    contract.verify_fixture_source(fixture, source_root).is_file()
                )
                repository = source_root / "coreruleset"
                self._run_git(
                    "-C", str(repository), "tag", "-d", contract.CRS_RELEASE_TAG
                )
                with self.assertRaises(contract.ContractError):
                    contract.verify_fixture_source(fixture, source_root)
                self._run_git(
                    "-C",
                    str(repository),
                    "commit",
                    "--allow-empty",
                    "--quiet",
                    "-m",
                    "moved-tag",
                )
                self._run_git("-C", str(repository), "tag", contract.CRS_RELEASE_TAG)
                self._run_git(
                    "-C",
                    str(repository),
                    "checkout",
                    "--quiet",
                    "--detach",
                    source_commit,
                )
                with self.assertRaises(contract.ContractError):
                    contract.verify_fixture_source(fixture, source_root)
                artificial = copy.deepcopy(fixture)
                artificial["rules"] = 'SecRule ARGS "@contains synthetic" "id:1,deny"'
                with self.assertRaises(contract.ContractError):
                    contract.validate_fixture(artificial)
                missing_rule_id = copy.deepcopy(fixture)
                del missing_rule_id["with_crs_no_mrts"]["canonical_block"][
                    "expected_rule_id"
                ]
                with self.assertRaises(contract.ContractError):
                    contract.validate_fixture(missing_rule_id)
                moving_ref = copy.deepcopy(fixture)
                moving_ref["with_crs_no_mrts"]["provenance"]["release_tag"] = "main"
                with self.assertRaises(contract.ContractError):
                    contract.validate_fixture(moving_ref)
                self._write_text(source_root / "cached-copy", "not a fresh topology\n")
                with self.assertRaises(contract.ContractError):
                    contract.verify_fixture_source(fixture, source_root)

    def test_private_root_and_exact_output_paths_are_required(self) -> None:
        with tempfile.TemporaryDirectory(prefix="five-crs-private-") as temporary:
            root = Path(temporary) / "evidence"
            root.mkdir(mode=0o750)
            os.chmod(root, 0o750)
            with self.assertRaises(contract.ContractError):
                contract._private_directory(root, "evidence_root")
            with self.assertRaises(contract.ContractError):
                contract._private_directory(contract.FRAMEWORK_ROOT, "evidence_root")

    def test_make_targets_keep_the_contract_outside_mrts_and_report_refresh(
        self,
    ) -> None:
        makefile = MAKEFILE_PATH.read_text(encoding="utf-8")
        fixture_target = makefile.split(
            "check-five-connectors-with-crs-no-mrts-fixture:\n", 1
        )[1].split(
            "\n\n",
            1,
        )[0]
        validate_target = makefile.split(
            "five-connectors-with-crs-no-mrts-validate:\n", 1
        )[1].split(
            "\n\n",
            1,
        )[0]
        aggregate_target = makefile.split(
            "five-connectors-with-crs-no-mrts-aggregate:\n", 1
        )[1].split(
            "\n\n",
            1,
        )[0]
        self.assertIn(
            "MODSECURITY_TEST_VARIANT=with-crs MODSECURITY_MRTS_VARIANT=no-mrts",
            fixture_target,
        )
        self.assertIn(
            "ci/tools/run-five-connectors-with-crs-no-mrts.py verify-fixture",
            fixture_target,
        )
        self.assertIn(
            "ci/tools/run-five-connectors-with-crs-no-mrts.py validate",
            validate_target,
        )
        self.assertIn(
            "ci/tools/run-five-connectors-with-crs-no-mrts.py aggregate",
            aggregate_target,
        )
        for target in (fixture_target, validate_target, aggregate_target):
            for forbidden in (
                "refresh-framework-reports",
                "mrts-import",
                "mrts-generate",
                "test-with-mrts",
                "MODSECURITY_MRTS_VARIANT=with-mrts",
            ):
                with self.subTest(target=target, forbidden=forbidden):
                    self.assertNotIn(forbidden, target)

    def test_make_targets_transport_profile_inputs_without_shell_reinterpretation(
        self,
    ) -> None:
        marker = "FIVE_CONNECTOR_MAKE_EVAL_CANARY"
        environment = os.environ.copy()
        environment.update(
            {
                "FIVE_CONNECTORS_WITH_CRS_NO_MRTS_EVIDENCE_ROOT": (
                    f"$(shell printf {marker} >&2)"
                ),
                "FIVE_CONNECTORS_WITH_CRS_NO_MRTS_RUN_ID": (
                    f"$(shell printf {marker} >&2)"
                ),
                "FIVE_CONNECTORS_WITH_CRS_NO_MRTS_CONNECTOR": (
                    f"$(shell printf {marker} >&2)"
                ),
                "SOURCE_ROOT": f"$(shell printf {marker} >&2)",
                "FIVE_CONNECTORS_WITH_CRS_NO_MRTS_TOOL": (
                    f"$(shell printf {marker} >&2)"
                ),
            }
        )
        for target, command in (
            ("five-connectors-with-crs-no-mrts-validate", "validate"),
            ("five-connectors-with-crs-no-mrts-aggregate", "aggregate"),
        ):
            with self.subTest(target=target):
                result = subprocess.run(
                    ["make", "-n", target],
                    cwd=ROOT,
                    env=environment,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn(marker, result.stderr)
                self.assertNotIn(marker, result.stdout)
                self.assertIn(
                    f"{MAKE_RUNNER_PATH.relative_to(ROOT)} {command}", result.stdout
                )

    def test_fixed_make_runner_accepts_only_closed_argument_vectors(self) -> None:
        environment = {
            "SOURCE_ROOT": "/private/source",
            "FIVE_CONNECTORS_WITH_CRS_NO_MRTS_EVIDENCE_ROOT": "/private/evidence",
            "FIVE_CONNECTORS_WITH_CRS_NO_MRTS_RUN_ID": "bounded-run",
            "FIVE_CONNECTORS_WITH_CRS_NO_MRTS_CONNECTOR": "apache",
        }
        with mock.patch.dict(os.environ, environment, clear=False):
            self.assertEqual(
                make_runner.argument_vector("verify-fixture"),
                ["verify-fixture", "--source-root", "/private/source"],
            )
            self.assertEqual(
                make_runner.argument_vector("validate"),
                [
                    "validate",
                    "--evidence-root",
                    "/private/evidence",
                    "--source-root",
                    "/private/source",
                    "--connector",
                    "apache",
                    "--run-id",
                    "bounded-run",
                ],
            )
            self.assertEqual(
                make_runner.argument_vector("aggregate"),
                [
                    "aggregate",
                    "--evidence-root",
                    "/private/evidence",
                    "--source-root",
                    "/private/source",
                    "--run-id",
                    "bounded-run",
                ],
            )
            with self.assertRaises(ValueError):
                make_runner.argument_vector("profile")

    def test_make_runner_imports_through_the_actual_target_environment(self) -> None:
        with tempfile.TemporaryDirectory(prefix="five-crs-make-runner-") as temporary:
            root = Path(temporary)
            environment = os.environ.copy()
            environment.update(
                {
                    "PYTHON": sys.executable,
                    "SOURCE_ROOT": str(root / "missing-source"),
                    "FIVE_CONNECTORS_WITH_CRS_NO_MRTS_EVIDENCE_ROOT": str(
                        root / "missing-evidence"
                    ),
                    "FIVE_CONNECTORS_WITH_CRS_NO_MRTS_RUN_ID": "bounded-run",
                    "FIVE_CONNECTORS_WITH_CRS_NO_MRTS_CONNECTOR": "apache",
                }
            )
            result = subprocess.run(
                ["make", "five-connectors-with-crs-no-mrts-validate"],
                cwd=ROOT,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("five-connectors-with-crs-no-mrts:", result.stderr)
            self.assertNotIn("ModuleNotFoundError", result.stderr)

    def test_make_runner_rejects_invalid_cli_and_missing_environment(self) -> None:
        for arguments in ([], ["validate", "unexpected"], ["unsupported"]):
            with (
                self.subTest(arguments=arguments),
                mock.patch.object(make_runner.contract, "main") as delegated,
            ):
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(make_runner.main(arguments), 2)
                delegated.assert_not_called()
        with (
            mock.patch.dict(os.environ, {}, clear=True),
            mock.patch.object(make_runner.contract, "main") as delegated,
        ):
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(make_runner.main(["verify-fixture"]), 2)
            delegated.assert_not_called()

    def test_make_runner_normalizes_make_escaped_dollar_without_a_shell(self) -> None:
        environment = {"SOURCE_ROOT": "/private/source$$literal"}
        with (
            mock.patch.dict(os.environ, environment, clear=True),
            mock.patch.object(
                make_runner.contract, "main", return_value=17
            ) as delegated,
        ):
            self.assertEqual(make_runner.main(["verify-fixture"]), 17)
        delegated.assert_called_once_with(
            ["verify-fixture", "--source-root", "/private/source$literal"]
        )

    def test_cli_rejects_a_caller_supplied_framework_commit(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                contract._parser().parse_args(
                    [
                        "validate",
                        "--evidence-root",
                        "/private/evidence",
                        "--source-root",
                        "/private/source",
                        "--connector",
                        "apache",
                        "--run-id",
                        self.run_id,
                        "--framework-commit",
                        "a" * 40,
                    ]
                )

    def test_ci_quality_gate_covers_the_contract_verifier(self) -> None:
        workflow = QUALITY_WORKFLOW_PATH.read_text(encoding="utf-8")
        verifier = "ci/checks/catalog/five_connectors_with_crs_no_mrts.py"
        runner = "ci/tools/run-five-connectors-with-crs-no-mrts.py"
        for path in (verifier, runner):
            with self.subTest(path=path):
                self.assertIn(f'- "{path}"', workflow)
        ruff_check = workflow.split('"$TOOLS_DIR/ruff" check ', 1)[1].split(
            '"$TOOLS_DIR/ruff" format --check ', 1
        )[0]
        ruff_format = workflow.split('"$TOOLS_DIR/ruff" format --check ', 1)[1]
        for path in (verifier, runner):
            with self.subTest(path=path):
                self.assertIn(path, ruff_check)
                self.assertIn(path, ruff_format)
        pyright = json.loads(PYRIGHT_CONFIG_PATH.read_text(encoding="utf-8"))
        for path in (verifier, runner):
            with self.subTest(path=path):
                self.assertIn(path, pyright["include"])


class FiveConnectorWorkflowSecurityContractTest(unittest.TestCase):
    def test_workflow_is_a_read_only_portable_contract_gate(self) -> None:
        text = WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertIn("pull_request:", text)
        self.assertIn("contents: read", text)
        self.assertIn("persist-credentials: false", text)
        self.assertIn("submodules: false", text)
        self.assertIn("github.event.pull_request.head.sha || github.sha", text)
        self.assertIn("test-five-connectors-with-crs-no-mrts-contract", text)
        self.assertIn("test-crs-provenance-contract", text)
        self.assertIn("Install hash-locked CI dependency", text)
        self.assertIn("--disable-pip-version-check", text)
        self.assertIn("--no-input", text)
        self.assertIn("--only-binary=:all:", text)
        self.assertIn("--require-hashes -r requirements-ci.lock", text)
        self.assertIn("python3 -m pip check", text)
        self.assertEqual(text.count('"requirements-ci.lock"'), 2)
        self.assertIn("ci/checks/catalog/five_connectors_with_crs_no_mrts.py", text)
        self.assertEqual(
            text.count("ci/tools/run-five-connectors-with-crs-no-mrts.py"), 2
        )
        self.assertIn("ci/provisioning/fetch-crs.sh", text)
        self.assertIn("ci/provisioning/crs-provenance.sh", text)
        self.assertIn("tests/cases/security/crs/crs_sqli_anomaly_block.yaml", text)
        for forbidden in (
            "pull_request_target",
            "secrets:",
            "github.token",
            "GITHUB_TOKEN",
            "contents: write",
            "id-token: write",
            "sudo",
            "continue-on-error",
            "workflow_call",
            "nginx",
            "test-with-crs",
            "run-connector-smokes.sh",
            "test-with-mrts",
            "tools/MRTS",
            "MODSECURITY_MRTS_VARIANT=with-mrts",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)
        self.assertIn("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", text)
        self.assertIn(
            "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97", text
        )
