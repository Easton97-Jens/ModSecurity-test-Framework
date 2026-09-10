"""Contract tests for the package-safe public Framework API."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from modsecurity_test_framework import contracts


ROOT = Path(__file__).resolve().parents[2]
CATALOG_RESOURCE = ROOT / "modsecurity_test_framework/data/framework-contract-catalog.json"
CATALOG_GENERATOR = ROOT / "ci/tools/generate-framework-contract-catalog.py"


class PublicContractApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._temporary_directory = tempfile.TemporaryDirectory(prefix="framework-contract-api-")
        cls.external_cwd = Path(cls._temporary_directory.name)
        cls.venv_directory = cls.external_cwd / "consumer-venv"
        cls.consumer_python = cls.venv_directory / "bin/python"
        cls.consumer_environment = os.environ.copy()
        cls.consumer_environment.pop("PYTHONPATH", None)
        cls.consumer_environment["PYTHONNOUSERSITE"] = "1"
        cls.consumer_environment["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
        cls.consumer_environment["PIP_NO_CACHE_DIR"] = "1"
        cls._run(
            [sys.executable, "-m", "venv", str(cls.venv_directory)],
            cwd=cls.external_cwd,
            environment=cls.consumer_environment,
        )
        cls._run(
            [
                str(cls.consumer_python),
                "-m",
                "pip",
                "install",
                "--no-build-isolation",
                "--no-deps",
                str(ROOT),
            ],
            cwd=cls.external_cwd,
            environment=cls.consumer_environment,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls._temporary_directory.cleanup()

    @classmethod
    def _run(
        cls,
        command: list[str],
        *,
        cwd: Path,
        environment: dict[str, str],
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            command,
            cwd=cwd,
            env=environment,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if result.returncode != 0:
            raise AssertionError(f"command failed with exit code {result.returncode}")
        return result

    def _external_json(self, *arguments: str) -> dict[str, object]:
        result = self._run(
            [str(self.consumer_python), "-m", "modsecurity_test_framework.contracts", *arguments],
            cwd=self.external_cwd,
            environment=self.consumer_environment,
        )
        self.assertEqual(result.stderr, "")
        return json.loads(result.stdout)

    def _catalog_data(self) -> dict[str, object]:
        return json.loads(CATALOG_RESOURCE.read_text(encoding="utf-8"))

    def _catalog_generator_module(self) -> object:
        specification = importlib.util.spec_from_file_location(
            "framework_contract_catalog_generator",
            CATALOG_GENERATOR,
        )
        self.assertIsNotNone(specification)
        self.assertIsNotNone(specification.loader)
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        return module

    def test_public_operations_import_from_repository_root(self) -> None:
        expected = {
            "load_test_catalog",
            "load_capability_manifest",
            "select_tests",
            "describe_test",
            "normalize_expectation",
            "validate_test_result",
            "load_profile_contract",
        }
        self.assertTrue(all(callable(getattr(contracts, name, None)) for name in expected))

    def test_external_consumer_import_requires_no_manual_sys_path(self) -> None:
        result = self._run(
            [
                str(self.consumer_python),
                "-c",
                (
                    "import json, pathlib, sys; "
                    "import modsecurity_test_framework.contracts as contracts; "
                    "print(json.dumps({'installed': str(pathlib.Path(contracts.__file__).resolve()).startswith(sys.prefix), "
                    "'has_api': callable(contracts.load_test_catalog)}))"
                ),
            ],
            cwd=self.external_cwd,
            environment=self.consumer_environment,
        )
        self.assertEqual(result.stderr, "")
        payload = json.loads(result.stdout)
        self.assertEqual(payload, {"has_api": True, "installed": True})

    def test_external_json_only_cli_supports_all_operations(self) -> None:
        inventory = self._external_json("inventory", "--catalog", "no-crs-baseline")
        self.assertEqual(inventory["schema_version"], 1)
        self.assertEqual(len(inventory["test_ids"]), 166)
        expected_commit = self._run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            environment=self.consumer_environment,
        ).stdout.strip()
        self.assertEqual(inventory["framework_commit"], expected_commit)

        capabilities = {
            "schema_version": 1,
            "connector": "apache",
            "capabilities": {
                "phase1": {"state": "verified"},
                "request_headers": {"state": "verified"},
            },
        }
        result = {"http_status": 200}
        (self.external_cwd / "capabilities.json").write_text(json.dumps(capabilities), encoding="utf-8")
        (self.external_cwd / "result.json").write_text(json.dumps(result), encoding="utf-8")

        selection = self._external_json("select", "--capabilities", "capabilities.json")
        self.assertIn("no-crs-baseline:allow_without_marker", selection["selected_test_ids"])
        description = self._external_json("describe", "--test-id", "no-crs-baseline:allow_without_marker")
        self.assertEqual(description["expectation_type"], "http_status")
        validation = self._external_json(
            "validate",
            "--test-id",
            "no-crs-baseline:allow_without_marker",
            "--result",
            "result.json",
        )
        self.assertTrue(validation["valid"])

    def test_full_no_crs_catalog_is_available(self) -> None:
        catalog = contracts.load_test_catalog(catalog="no-crs-baseline")
        self.assertEqual(len(catalog["test_ids"]), 166)
        self.assertEqual(len(set(catalog["test_ids"])), 166)
        self.assertIn("no-crs-baseline:deny_header_marker_403", catalog["test_ids"])

    def test_package_catalog_covers_all_declared_framework_sources(self) -> None:
        all_cases = contracts.load_test_catalog()
        yaml_cases = contracts.load_test_catalog(catalog="framework-yaml")
        self.assertEqual(len(all_cases["test_ids"]), 339)
        self.assertEqual(len(yaml_cases["test_ids"]), 182)
        for record in all_cases["tests"]:
            self.assertTrue(
                {
                    "framework_test_id",
                    "display_name",
                    "scenario_category",
                    "phase",
                    "area",
                    "profile",
                    "required_capabilities",
                    "expectation",
                    "applicability",
                }.issubset(record)
            )
            self.assertTrue(all(not source["path"].startswith("/") for source in record["sources"]))

    def test_existing_crs_profile_contract_is_available(self) -> None:
        profile = contracts.load_profile_contract()
        self.assertEqual(profile["profile"], "five-connectors-with-crs-no-mrts")
        self.assertEqual(profile["connectors"], ["apache", "envoy", "haproxy", "lighttpd", "traefik"])
        self.assertEqual(profile["expectation"], {
            "kind": "intervention",
            "http_status": 403,
            "action": "deny",
            "rule_ids": [942270],
        })

    def test_http_status_test_has_a_typed_expectation(self) -> None:
        description = contracts.describe_test("no-crs-baseline:allow_without_marker")
        self.assertEqual(description["test"]["expectation"], {"kind": "http_status", "http_status": 200})
        self.assertTrue(
            contracts.validate_test_result("no-crs-baseline:allow_without_marker", {"http_status": 200})["valid"]
        )

    def test_action_event_and_lifecycle_tests_remain_non_http(self) -> None:
        action = contracts.describe_test("no-crs-baseline:abort_if_supported")
        event = contracts.describe_test("no-crs-baseline:invalid_boolean")
        lifecycle = contracts.describe_test("no-crs-baseline:clean_shutdown")
        self.assertEqual(action["expectation_type"], "action")
        self.assertEqual(event["expectation_type"], "event")
        self.assertEqual(lifecycle["expectation_type"], "lifecycle")
        self.assertNotIn("http_status", action["test"]["expectation"])
        self.assertNotIn("http_status", event["test"]["expectation"])
        self.assertNotIn("http_status", lifecycle["test"]["expectation"])

    def test_invalid_status_types_and_status_on_action_are_rejected(self) -> None:
        invalid_values = ("403", True, 403.0, 99, 600)
        for value in invalid_values:
            with self.subTest(value=value):
                with self.assertRaises(contracts.ContractError):
                    contracts.normalize_expectation({"kind": "http_status", "http_status": value})
        with self.assertRaises(contracts.ContractError):
            contracts.normalize_expectation({"kind": "action", "action": "deny", "http_status": 403})

    def test_every_supported_tagged_expectation_kind_is_strictly_normalized(self) -> None:
        examples = {
            "http_status": {"kind": "http_status", "http_status": 403},
            "intervention": {"kind": "intervention", "http_status": 403, "action": "deny", "rule_ids": [942270]},
            "action": {"kind": "action", "action": "log_only"},
            "rule_match": {"kind": "rule_match", "rule_ids": [1100001]},
            "event": {"kind": "event", "fields": ["transaction_id"]},
            "request_headers": {"kind": "request_headers", "names": ["x_framework_run_id"]},
            "response_headers": {"kind": "response_headers", "names": ["content_type"]},
            "request_body": {"kind": "request_body", "state": "buffered"},
            "response_body": {"kind": "response_body", "state": "matched"},
            "transport": {"kind": "transport", "state": "stream_reset"},
            "lifecycle": {"kind": "lifecycle", "predicates": {"host_started": True, "request_completed": True}},
            "cleanup": {"kind": "cleanup", "state": "balanced"},
            "compound": {
                "kind": "compound",
                "conditions": [
                    {"kind": "http_status", "http_status": 403},
                    {"kind": "rule_match", "rule_ids": [942270]},
                ],
            },
            "not_applicable": {"kind": "not_applicable", "reason": "connector_gap"},
        }
        self.assertEqual(set(examples), contracts.EXPECTATION_KINDS)
        for kind, expectation in examples.items():
            with self.subTest(kind=kind):
                self.assertEqual(contracts.normalize_expectation(expectation)["kind"], kind)

    def test_unknown_expectation_kind_and_implicit_compound_are_rejected(self) -> None:
        with self.assertRaises(contracts.ContractError):
            contracts.normalize_expectation({"kind": "unknown", "value": "x"})
        with self.assertRaises(contracts.ContractError):
            contracts.normalize_expectation({"kind": []})
        with self.assertRaises(contracts.ContractError):
            contracts.normalize_expectation({"kind": "compound", "conditions": [{"kind": "http_status", "http_status": 200}]})

    def test_unhashable_result_enum_values_are_contract_errors(self) -> None:
        with self.assertRaises(contracts.ContractError):
            contracts.validate_test_result(
                "no-crs-baseline:allow_without_marker",
                {"request_body_state": []},
            )
        result_file = self.external_cwd / "unhashable-result.json"
        result_file.write_text('{"request_body_state":[]}', encoding="utf-8")
        result = subprocess.run(
            [
                str(self.consumer_python),
                "-m",
                "modsecurity_test_framework.contracts",
                "validate",
                "--test-id",
                "no-crs-baseline:allow_without_marker",
                "--result",
                result_file.name,
            ],
            cwd=self.external_cwd,
            env=self.consumer_environment,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(result.returncode, contracts.CONTRACT_ERROR_EXIT_CODE)
        self.assertEqual(result.stderr, "")
        self.assertEqual(json.loads(result.stdout)["error"]["code"], "invalid_result")

    def test_duplicate_or_conflicting_test_ids_are_rejected(self) -> None:
        duplicate = self._catalog_data()
        tests = duplicate["tests"]
        self.assertIsInstance(tests, list)
        tests.append(copy.deepcopy(tests[0]))
        with self.assertRaises(contracts.ContractError):
            contracts.load_test_catalog(catalog_data=duplicate)

        conflict = self._catalog_data()
        conflict_tests = conflict["tests"]
        self.assertIsInstance(conflict_tests, list)
        conflicting_record = copy.deepcopy(conflict_tests[0])
        conflicting_record["display_name"] = "Conflicting declared test"
        conflict_tests.append(conflicting_record)
        with self.assertRaises(contracts.ContractError):
            contracts.load_test_catalog(catalog_data=conflict)

    def test_framework_commit_is_bound_to_structured_answers(self) -> None:
        expected_commit = self._run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            environment=self.consumer_environment,
        ).stdout.strip()
        inventory = contracts.load_test_catalog(catalog="no-crs-baseline")
        selection = contracts.select_tests(
            {
                "schema_version": 1,
                "connector": "apache",
                "capabilities": {
                    "phase1": {"state": "verified"},
                    "request_headers": {"state": "verified"},
                },
            }
        )
        validation = contracts.validate_test_result("no-crs-baseline:allow_without_marker", {"http_status": 200})
        self.assertEqual(inventory["framework_commit"], expected_commit)
        self.assertEqual(selection["framework_commit"], expected_commit)
        self.assertEqual(validation["framework_commit"], expected_commit)

    def test_category_is_declared_not_inferred_from_rule_id(self) -> None:
        catalog_data = self._catalog_data()
        records = catalog_data["tests"]
        self.assertIsInstance(records, list)
        original = next(record for record in records if record["framework_test_id"] == "no-crs-baseline:deny_header_marker_403")
        original_category = original["scenario_category"]
        original["expectation"] = {
            "kind": "intervention",
            "http_status": 403,
            "action": "deny",
            "rule_ids": [9_999_999],
        }
        described = contracts.describe_test("no-crs-baseline:deny_header_marker_403", catalog_data=catalog_data)
        self.assertEqual(described["test"]["scenario_category"], original_category)
        self.assertEqual(described["test"]["scenario_category"], "basic")

    def test_duplicate_json_keys_and_unsafe_paths_fail_closed_without_path_output(self) -> None:
        duplicate_payload = (
            '{"schema_version":1,"schema_version":1,"connector":"apache",'
            '"capabilities":{"phase1":{"state":"verified"}}}'
        )
        (self.external_cwd / "duplicate.json").write_text(duplicate_payload, encoding="utf-8")
        result = subprocess.run(
            [
                str(self.consumer_python),
                "-m",
                "modsecurity_test_framework.contracts",
                "select",
                "--capabilities",
                "duplicate.json",
            ],
            cwd=self.external_cwd,
            env=self.consumer_environment,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(result.returncode, contracts.CONTRACT_ERROR_EXIT_CODE)
        self.assertEqual(result.stderr, "")
        self.assertEqual(json.loads(result.stdout)["error"]["code"], "duplicate_json_key")
        self.assertNotIn(str(self.external_cwd), result.stdout)

    def test_untrusted_file_paths_are_bounded_and_no_follow(self) -> None:
        valid = {
            "schema_version": 1,
            "connector": "apache",
            "capabilities": {"phase1": {"state": "verified"}},
        }
        target = self.external_cwd / "manifest-target.json"
        target.write_text(json.dumps(valid), encoding="utf-8")
        link = self.external_cwd / "manifest-link.json"
        if link.exists() or link.is_symlink():
            link.unlink()
        link.symlink_to(target.name)
        target_directory = self.external_cwd / "manifest-directory"
        target_directory.mkdir()
        (target_directory / "manifest.json").write_text(json.dumps(valid), encoding="utf-8")
        directory_link = self.external_cwd / "manifest-directory-link"
        directory_link.symlink_to(target_directory.name, target_is_directory=True)
        oversized = self.external_cwd / "oversized.json"
        oversized.write_bytes(b"{" + (b" " * (contracts.MAX_EXTERNAL_JSON_BYTES + 1)) + b"}")
        for filename, expected_code in (
            ("manifest-link.json", "unsafe_input_path"),
            ("manifest-directory-link/manifest.json", "unsafe_input_path"),
            ("oversized.json", "invalid_input_size"),
            ("../manifest-target.json", "invalid_input_path"),
            ("./manifest-target.json", "invalid_input_path"),
            ("nested/../manifest-target.json", "invalid_input_path"),
            ("manifest-target.json//", "invalid_input_path"),
            ("manifest-target\\target.json", "invalid_input_path"),
        ):
            with self.subTest(filename=filename):
                result = subprocess.run(
                    [
                        str(self.consumer_python),
                        "-m",
                        "modsecurity_test_framework.contracts",
                        "select",
                        "--capabilities",
                        filename,
                    ],
                    cwd=self.external_cwd,
                    env=self.consumer_environment,
                    check=False,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                self.assertEqual(result.returncode, contracts.CONTRACT_ERROR_EXIT_CODE)
                self.assertEqual(result.stderr, "")
                self.assertEqual(json.loads(result.stdout)["error"]["code"], expected_code)
                self.assertNotIn(str(self.external_cwd), result.stdout)

        fifo = self.external_cwd / "writerless.fifo"
        if hasattr(os, "mkfifo"):
            os.mkfifo(fifo)
            try:
                result = subprocess.run(
                    [
                        str(self.consumer_python),
                        "-m",
                        "modsecurity_test_framework.contracts",
                        "select",
                        "--capabilities",
                        fifo.name,
                    ],
                    cwd=self.external_cwd,
                    env=self.consumer_environment,
                    check=False,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=2,
                )
            finally:
                fifo.unlink()
            self.assertEqual(result.returncode, contracts.CONTRACT_ERROR_EXIT_CODE)
            self.assertEqual(result.stderr, "")
            self.assertEqual(json.loads(result.stdout)["error"]["code"], "invalid_input_size")

    def test_catalog_generator_refuses_a_symlinked_output_parent(self) -> None:
        generator = self._catalog_generator_module()
        safe_root = self.external_cwd / "generator-root"
        safe_root.mkdir()
        outside = self.external_cwd / "outside"
        outside.mkdir()
        (safe_root / "redirect").symlink_to(outside, target_is_directory=True)
        with mock.patch.object(generator, "ROOT", safe_root):
            with self.assertRaises(generator.GenerationError):
                generator._write_output(safe_root / "redirect/catalog.json", "{}\n")
        self.assertFalse((outside / "catalog.json").exists())

    def test_legacy_catalog_entrypoints_remain_compatible_from_external_cwd(self) -> None:
        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)
        environment["PYTHONNOUSERSITE"] = "1"
        no_crs = self._run(
            [sys.executable, str(ROOT / "ci/checks/catalog/no_crs_baseline.py"), "catalog-check"],
            cwd=self.external_cwd,
            environment=environment,
        )
        self.assertEqual(no_crs.returncode, 0)
        profile = self._run(
            [sys.executable, str(ROOT / "ci/checks/catalog/five_connectors_with_crs_no_mrts.py"), "profile"],
            cwd=self.external_cwd,
            environment=environment,
        )
        self.assertEqual(json.loads(profile.stdout)["profile"], "five-connectors-with-crs-no-mrts")

    def test_direct_legacy_module_load_no_longer_loses_its_sibling(self) -> None:
        script = ROOT / "ci/checks/catalog/five_connectors_with_crs_no_mrts.py"
        code = (
            "import importlib.util; "
            f"spec=importlib.util.spec_from_file_location('legacy_profile', {str(script)!r}); "
            "module=importlib.util.module_from_spec(spec); "
            "spec.loader.exec_module(module); "
            "print(module.PROFILE)"
        )
        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)
        environment["PYTHONNOUSERSITE"] = "1"
        result = self._run([sys.executable, "-c", code], cwd=self.external_cwd, environment=environment)
        self.assertEqual(result.stdout.strip(), "five-connectors-with-crs-no-mrts")


if __name__ == "__main__":
    unittest.main()
