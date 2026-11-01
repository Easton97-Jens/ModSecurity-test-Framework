from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import importlib.util
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock


ROOT = connector_root()


def load_report_module(relative_path: str, module_name: str):
    path = ROOT / relative_path
    module = load_source(path)
    return module


BODY_PROCESSOR = load_report_module(
    "ci/evidence/reports/generate-body-processor-analysis.py",
    "body_processor_analysis_presentation_test",
)
RULE_CHAIN = load_report_module(
    "ci/evidence/reports/generate-rule-chain-semantics-analysis.py",
    "rule_chain_semantics_presentation_test",
)
FULL_RUNTIME_MATRIX = load_report_module(
    "ci/evidence/reports/generate-full-runtime-matrix.py",
    "full_runtime_matrix_presentation_test",
)
RUNTIME_REPORTS = load_report_module(
    "ci/evidence/reports/update-runtime-reports.py",
    "runtime_reports_presentation_test",
)
RUNTIME_PRODUCER_READINESS = load_report_module(
    "ci/checks/evidence/check-runtime-producer-readiness.py",
    "runtime_producer_readiness_presentation_test",
)
SYSTEM_ENVIRONMENT_PROOF = load_report_module(
    "ci/evidence/reports/generate-system-environment-proof.py",
    "system_environment_proof_presentation_test",
)


class DefaultValues(dict[str, object]):
    def __missing__(self, key: str) -> object:
        return 0


def empty_subcluster(distribution_keys: tuple[str, ...]) -> DefaultValues:
    values = DefaultValues()
    values.update({key: {} for key in distribution_keys})
    return values


def empty_body_processor_report() -> dict[str, object]:
    urlencoded = empty_subcluster(
        (
            "connectors",
            "variants",
            "case_ids",
            "rule_ids",
            "targets",
            "operators",
            "body_lengths",
            "request_body_seen",
        )
    )
    xml_activation = empty_subcluster(
        (
            "connectors",
            "variants",
            "case_ids",
            "rule_ids",
            "targets",
            "operators",
            "content_types",
            "body_lengths",
            "body_hashes",
            "request_body_seen",
        )
    )
    multipart_activation = empty_subcluster(
        (
            "connectors",
            "variants",
            "case_ids",
            "rule_ids",
            "targets",
            "operators",
            "content_types",
            "boundaries",
            "boundary_status",
            "part_counts",
            "field_names",
            "filenames",
            "body_lengths",
            "body_hashes",
            "request_body_seen",
        )
    )
    return {
        "generated_at": "2026-07-27T00:00:00Z",
        "summary": DefaultValues(
            {
                "before_metadata_fix": DefaultValues(),
                "after_metadata_fix": DefaultValues(),
            }
        ),
        "selected_subcluster": DefaultValues(),
        "urlencoded_form_subcluster": urlencoded,
        "xml_activation_missing_subcluster": xml_activation,
        "multipart_activation_missing_subcluster": multipart_activation,
        "distribution": {
            "connectors": [],
            "variants": [],
            "body_kinds": [],
            "content_types": [],
            "targets": [],
            "failure_categories": [],
        },
        "groups": [],
        "next_fix_plan": DefaultValues(),
    }


def empty_rule_chain_report() -> dict[str, object]:
    summary_keys = (
        "rule_chain_failure_rows",
        "rule_chain_case_groups",
        "small_single_connector_failure_groups",
        "small_single_connector_failure_rows",
        "runtime_fixable_candidates",
        "report_only_items",
        "chain_parent_matched_rows",
        "chain_child_matched_rows",
        "full_chain_matched_rows",
        "chain_named_non_rule_chain_rows",
    )
    return {
        "generated_at": "2026-07-27T00:00:00Z",
        "summary": {key: 0 for key in summary_keys},
        "conclusion": {
            "selected_subcluster": "report-only",
            "root_cause": "none",
            "safe_change": "none",
        },
        "rule_chain_failures": [],
        "chain_named_non_rule_chain_failures": [],
        "small_single_connector_failures": [],
        "next_recommendation": {},
    }


class ReportPresentationLiteralsTest(unittest.TestCase):
    def test_body_processor_distribution_headers_remain_byte_exact(self) -> None:
        markdown = BODY_PROCESSOR.render_markdown(empty_body_processor_report())

        self.assertEqual(BODY_PROCESSOR.DISTRIBUTION_TABLE_HEADER, "| field | distribution |")
        self.assertEqual(BODY_PROCESSOR.DISTRIBUTION_TABLE_SEPARATOR, "| --- | --- |")
        self.assertEqual(markdown.count(BODY_PROCESSOR.DISTRIBUTION_TABLE_HEADER), 3)
        self.assertEqual(
            markdown.count(
                f"{BODY_PROCESSOR.DISTRIBUTION_TABLE_HEADER}\n"
                f"{BODY_PROCESSOR.DISTRIBUTION_TABLE_SEPARATOR}"
            ),
            3,
        )

    def test_rule_chain_empty_sections_remain_byte_exact(self) -> None:
        markdown = RULE_CHAIN.render_markdown(empty_rule_chain_report())

        self.assertEqual(RULE_CHAIN.NO_ROWS_MARKDOWN, "- None.")
        self.assertEqual(markdown.count(RULE_CHAIN.NO_ROWS_MARKDOWN), 3)

    def test_full_runtime_matrix_utc_offset_remains_parse_compatible(self) -> None:
        self.assertEqual(FULL_RUNTIME_MATRIX._UTC_OFFSET, "+00:00")
        self.assertEqual(
            FULL_RUNTIME_MATRIX.parse_time("2026-07-27T00:00:00Z"),
            datetime(2026, 7, 27, tzinfo=timezone.utc),
        )
        self.assertEqual(
            FULL_RUNTIME_MATRIX.duration_seconds(
                "2026-07-27T00:00:00Z",
                "2026-07-27T00:01:00Z",
            ),
            60,
        )

    def test_runtime_cache_four_column_tables_remain_byte_exact(self) -> None:
        cache_root = "/cache/components"
        build_root = "/build/runtime"
        component_build_id = "component-build-1"
        component_path = f"{cache_root}/modsecurity"
        component_markdown = RUNTIME_REPORTS.runtime_component_cache_markdown(
            {
                "cache_root": cache_root,
                "build_root": build_root,
                "generated_at": "2026-07-30T00:00:00Z",
                "modsecurity": {
                    "status": "built",
                    "build_id": component_build_id,
                    "prefix": component_path,
                },
            }
        )
        index_markdown = RUNTIME_REPORTS.runtime_cache_index_markdown(
            {
                "cache_status": "cache_input_present",
                "component_cache_root": cache_root,
                "build_root": build_root,
                "summary": {
                    "components_present": 1,
                    "components_total": 7,
                    "important_files_present": 1,
                    "important_files_total": 1,
                },
                "local_artifact_policy": "provenance only",
                "manifests": [
                    {
                        "name": "component-cache manifest",
                        "status": "present",
                        "sha256": "manifest-sha",
                        "path": f"{cache_root}/manifest.json",
                    }
                ],
                "components": [
                    {
                        "name": "modsecurity",
                        "status": "built",
                        "build_id": component_build_id,
                        "path": component_path,
                    }
                ],
                "important_files": [
                    {
                        "name": "libmodsecurity",
                        "status": "present",
                        "sha256": "library-sha",
                        "path": f"{cache_root}/libmodsecurity.so",
                    }
                ],
            }
        )

        separator = RUNTIME_REPORTS.FOUR_COLUMN_TABLE_SEPARATOR
        self.assertEqual(separator, "|---|---|---|---|")
        self.assertIn(
            "| Component | Status | Build ID / Ref | Path |\n"
            f"{separator}\n"
            f"| modsecurity | built | `{component_build_id}` | `{component_path}` |",
            component_markdown,
        )
        self.assertEqual(
            [line for line in component_markdown.splitlines() if line == separator],
            [separator],
        )
        self.assertIn(
            "| Item | Status | SHA256 | Path |\n"
            f"{separator}\n"
            f"| component-cache manifest | present | `manifest-sha` | `{cache_root}/manifest.json` |",
            index_markdown,
        )
        self.assertIn(
            "| Component | Status | Build ID | Source / Path |\n"
            f"{separator}\n"
            f"| modsecurity | built | `{component_build_id}` | `{component_path}` |",
            index_markdown,
        )
        self.assertIn(
            "| Item | Status | SHA256 | Path |\n"
            f"{separator}\n"
            f"| libmodsecurity | present | `library-sha` | `{cache_root}/libmodsecurity.so` |",
            index_markdown,
        )
        self.assertEqual(
            [line for line in index_markdown.splitlines() if line == separator],
            [separator, separator, separator],
        )

    def test_nginx_runtime_contract_requires_complete_provenance_and_managed_binary_identity(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nginx-runtime-contract-") as temporary:
            root = Path(temporary)
            cache_root = root / "cache"
            source_directory = root / "sources/nginx-1.31.6"
            source_directory.mkdir(parents=True)
            binary = cache_root / "builds/connectors/nginx/cache-key/nginx/sbin/nginx"
            binary.parent.mkdir(parents=True)
            binary.write_text("#!/bin/sh\nprintf 'nginx/1.31.6\\n'\n", encoding="utf-8")
            binary.chmod(0o755)
            module = cache_root / "builds/connectors/nginx/cache-key/nginx/modules/ngx_http_modsecurity_module.so"
            module.parent.mkdir(parents=True)
            module.write_text("test module\n", encoding="utf-8")
            binary_sha256 = RUNTIME_PRODUCER_READINESS.sha256_file(binary)
            fields = {
                "component": "nginx",
                "source_repository": "https://github.com/nginx/nginx",
                "source_mode": "github-release",
                "release_tag": "release-1.31.6",
                "source_ref": "release-1.31.6",
                "release_asset_name": "nginx-1.31.6.tar.gz",
                "expected_archive_sha256": "974ed5298a5e398e008704ed5db284e655fc270c596493dbccada452448fc9f1",
                "actual_archive_sha256": "974ed5298a5e398e008704ed5db284e655fc270c596493dbccada452448fc9f1",
                "source_version_readback": "nginx/1.31.6",
                "source_directory": str(source_directory),
                "binary_path": str(binary),
                "binary_sha256": binary_sha256,
                "binary_version_readback": "nginx/1.31.6",
                "configure_arguments": "--prefix=/managed/nginx --add-dynamic-module=/managed/module",
                "build_id": "nginx-cache-key",
                "framework_commit": "f" * 40,
                "parent_commit": "a" * 40,
                "generated_at": "2026-08-02T00:00:00Z",
            }
            contract_input = {
                "manifest_path": str(cache_root / "manifest.json"),
                "manifest_loaded": True,
                "record_path": "nginx.runtime_contract",
                "record_status": "built",
                "record": {
                    "status": "built",
                    "module_file": str(module),
                    "runtime_contract": fields,
                },
                "contract": fields,
            }
            mrts_native_root = root / "mrts-native"
            roots = {
                "cache": cache_root,
                "source": root / "sources",
                "mrts_native_root": mrts_native_root,
            }
            passed = RUNTIME_PRODUCER_READINESS.validate_nginx_runtime_contract(
                contract_input,
                roots,
            )

            self.assertEqual(passed["status"], "PASS")
            self.assertEqual(
                set(passed["fields"]),
                set(RUNTIME_PRODUCER_READINESS.NGINX_RUNTIME_CONTRACT_FIELDS),
            )
            self.assertTrue(all(value == "PASS" for value in passed["field_status"].values()))
            module_binding = RUNTIME_PRODUCER_READINESS.validate_nginx_runtime_module_binding(
                contract_input,
                module,
                roots,
            )
            self.assertEqual(module_binding["status"], "PASS")
            readiness = SYSTEM_ENVIRONMENT_PROOF.runtime_component_readiness(
                [],
                {"variables": {}},
                {"nginx_runtime_contract": passed},
            )
            nginx_readiness = next(item for item in readiness if item["component"] == "NGINX")
            self.assertEqual(nginx_readiness["status"], "present")

            rendered_contract = "\n".join(
                SYSTEM_ENVIRONMENT_PROOF.nginx_runtime_contract_markdown(
                    {"nginx_runtime_contract": passed}
                )
            )
            rendered_component = "\n".join(
                RUNTIME_REPORTS.nginx_component_lines(
                    {"status": "built", "runtime_contract": fields}
                )
            )
            for field in RUNTIME_PRODUCER_READINESS.NGINX_RUNTIME_CONTRACT_FIELDS:
                self.assertIn(field, rendered_contract)
                self.assertIn(field, rendered_component)
            self.assertIn(str(binary), rendered_contract)
            self.assertIn(binary_sha256, rendered_contract)

            missing_field_input = dict(contract_input)
            missing_field_input["contract"] = {**fields, "source_ref": ""}
            missing = RUNTIME_PRODUCER_READINESS.validate_nginx_runtime_contract(
                missing_field_input,
                roots,
            )
            self.assertEqual(missing["status"], "BLOCKED")
            self.assertEqual(missing["field_status"]["source_ref"], "BLOCKED")
            self.assertIn("missing required NGINX runtime contract fields: source_ref", missing["issues"])

            unmanaged_binary = root / "outside/nginx"
            unmanaged_binary.parent.mkdir(parents=True)
            unmanaged_binary.write_text("#!/bin/sh\n", encoding="utf-8")
            unmanaged_binary.chmod(0o755)
            unmanaged_input = dict(contract_input)
            unmanaged_input["contract"] = {
                **fields,
                "binary_path": str(unmanaged_binary),
                "binary_sha256": RUNTIME_PRODUCER_READINESS.sha256_file(unmanaged_binary),
            }
            unmanaged = RUNTIME_PRODUCER_READINESS.validate_nginx_runtime_contract(
                unmanaged_input,
                roots,
            )
            self.assertEqual(unmanaged["status"], "BLOCKED")
            self.assertEqual(unmanaged["field_status"]["binary_path"], "BLOCKED")
            self.assertTrue(
                any(
                    "binary_path must be a non-symlink executable below an approved non-MRTS runtime/cache root"
                    in issue
                    for issue in unmanaged["issues"]
                )
            )

            mrts_source = mrts_native_root / "sources/nginx-1.31.3"
            mrts_source.mkdir(parents=True)
            forged_mrts_source = dict(contract_input)
            forged_mrts_source["contract"] = {
                **fields,
                "source_directory": str(mrts_source),
            }
            source_under_mrts = RUNTIME_PRODUCER_READINESS.validate_nginx_runtime_contract(
                forged_mrts_source,
                roots,
            )
            self.assertEqual(source_under_mrts["status"], "BLOCKED")
            self.assertEqual(source_under_mrts["field_status"]["source_directory"], "BLOCKED")
            self.assertTrue(
                any(
                    "MRTS_NATIVE_ROOT is forbidden for NGINX runtime evidence" in issue
                    for issue in source_under_mrts["issues"]
                )
            )

            mrts_binary = mrts_native_root / "nginx/sbin/nginx"
            mrts_binary.parent.mkdir(parents=True)
            mrts_binary.write_text("#!/bin/sh\n", encoding="utf-8")
            mrts_binary.chmod(0o755)
            forged_mrts_binary = dict(contract_input)
            forged_mrts_binary["contract"] = {
                **fields,
                "binary_path": str(mrts_binary),
                "binary_sha256": RUNTIME_PRODUCER_READINESS.sha256_file(mrts_binary),
            }
            binary_under_mrts = RUNTIME_PRODUCER_READINESS.validate_nginx_runtime_contract(
                forged_mrts_binary,
                roots,
            )
            self.assertEqual(binary_under_mrts["status"], "BLOCKED")
            self.assertEqual(binary_under_mrts["field_status"]["binary_path"], "BLOCKED")
            self.assertTrue(
                any(
                    "MRTS_NATIVE_ROOT is forbidden for NGINX runtime evidence" in issue
                    for issue in binary_under_mrts["issues"]
                )
            )

            mrts_module = mrts_native_root / "nginx/modules/ngx_http_modsecurity_module.so"
            mrts_module.parent.mkdir(parents=True)
            mrts_module.write_text("unmanaged module\n", encoding="utf-8")
            module_under_mrts = RUNTIME_PRODUCER_READINESS.validate_nginx_runtime_module_binding(
                contract_input,
                mrts_module,
                roots,
            )
            self.assertEqual(module_under_mrts["status"], "BLOCKED")
            self.assertTrue(
                any(
                    "MRTS_NATIVE_ROOT is forbidden for NGINX runtime evidence" in issue
                    for issue in module_under_mrts["issues"]
                )
            )

            alternate_module = cache_root / "builds/connectors/nginx/cache-key/alternate/module.so"
            alternate_module.parent.mkdir(parents=True)
            alternate_module.write_text("alternate module\n", encoding="utf-8")
            mismatched_module = RUNTIME_PRODUCER_READINESS.validate_nginx_runtime_module_binding(
                contract_input,
                alternate_module,
                roots,
            )
            self.assertEqual(mismatched_module["status"], "BLOCKED")
            self.assertIn(
                "reported NGINX module does not match the managed component record",
                mismatched_module["issues"],
            )

            system_binary = Path("/usr/bin/env")
            self.assertTrue(system_binary.is_file())
            forged_system_binary = dict(contract_input)
            forged_system_binary["contract"] = {
                **fields,
                "binary_path": str(system_binary),
                "binary_sha256": RUNTIME_PRODUCER_READINESS.sha256_file(system_binary),
            }
            binary_under_system_root = RUNTIME_PRODUCER_READINESS.validate_nginx_runtime_contract(
                forged_system_binary,
                roots,
            )
            self.assertEqual(binary_under_system_root["status"], "BLOCKED")
            self.assertEqual(binary_under_system_root["field_status"]["binary_path"], "BLOCKED")
            self.assertTrue(
                any(
                    "system path is forbidden for NGINX runtime evidence" in issue
                    for issue in binary_under_system_root["issues"]
                )
            )

            for field, invalid, expected_issue in (
                ("framework_commit", "deadbeef", "framework_commit must be a full lowercase Git object ID"),
                ("parent_commit", "A" * 40, "parent_commit must be a full lowercase Git object ID"),
                ("generated_at", "2026-08-02T00:00:00+00:00", "generated_at must be a canonical UTC timestamp"),
            ):
                invalid_identity = dict(contract_input)
                invalid_identity["contract"] = {**fields, field: invalid}
                blocked_identity = RUNTIME_PRODUCER_READINESS.validate_nginx_runtime_contract(
                    invalid_identity,
                    roots,
                )
                self.assertEqual(blocked_identity["status"], "BLOCKED")
                self.assertEqual(blocked_identity["field_status"][field], "BLOCKED")
                self.assertIn(expected_issue, blocked_identity["issues"])

    def test_nginx_manifest_module_path_is_bound_without_resolving_raw_value(self) -> None:
        """A manifest path cannot drive filesystem resolution before binding."""

        with tempfile.TemporaryDirectory(prefix="nginx-module-binding-") as temporary:
            root = Path(temporary)
            cache_root = root / "cache"
            module = cache_root / "builds/nginx/modules/ngx_http_modsecurity_module.so"
            module.parent.mkdir(parents=True)
            module.write_text("managed module\n", encoding="utf-8")
            roots = {
                "cache": cache_root,
                "mrts_native_root": root / "mrts-native",
            }

            for raw_module_file in (
                "/etc/forged-nginx-module.so",
                "../../outside/forged-nginx-module.so",
                "../cache/builds/nginx/modules/ngx_http_modsecurity_module.so",
            ):
                with self.subTest(raw_module_file=raw_module_file):
                    contract_input = {"record": {"module_file": raw_module_file}}
                    with mock.patch.object(
                        RUNTIME_PRODUCER_READINESS,
                        "Path",
                        side_effect=AssertionError("raw manifest module_file must not be converted to a Path"),
                    ):
                        binding = RUNTIME_PRODUCER_READINESS.validate_nginx_runtime_module_binding(
                            contract_input,
                            module,
                            roots,
                        )

                    self.assertEqual(binding["status"], "BLOCKED")
                    self.assertEqual(binding["expected_module_path"], raw_module_file)
                    self.assertIn(
                        "reported NGINX module does not match the managed component record",
                        binding["issues"],
                    )

# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)
