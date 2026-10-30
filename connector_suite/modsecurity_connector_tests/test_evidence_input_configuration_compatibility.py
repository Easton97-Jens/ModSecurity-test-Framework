"""Explicit invocation evidence remains readable without trusting recorded paths."""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = connector_root()




def load(name, relative):
    module = load_source(ROOT / relative)
    return module


MISMATCH = load("configured_evidence_mismatch", "ci/evidence/reports/generate-verified-runtime-mismatch-analysis.py")
CACHE = load("configured_evidence_cache", "ci/evidence/reports/update-runtime-reports.py")
COMPONENTS = load("configured_evidence_components", "ci/provisioning/components/prepare-runtime-components.py")


class EvidenceInputConfigurationCompatibilityTests(unittest.TestCase):
    def setUp(self):
        from modsecurity_connector_ci.lib.active_test_inventory import validate_output_root
        storage = validate_output_root(ROOT, Path(os.environ["RUNNER_TEMP"]))
        temporary = tempfile.TemporaryDirectory(prefix="explicit-evidence-inputs-", dir=storage)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.enterContext(mock.patch.object(MISMATCH, "INPUTS", MISMATCH.INPUTS))
        self.enterContext(mock.patch.object(CACHE, "INPUTS", CACHE.INPUTS))
        self.enterContext(mock.patch("report_path_safety.SAFE_ROOTS", set()))

    def configure_external_commands(self, external_receipt=True, receipt_link=None):
        connector, build, verified, external = (self.root / name for name in
                                                ("connector", "build", "verified", "external"))
        for directory in (connector, build, verified, external):
            directory.mkdir(mode=0o700)
        commands = (external / "commands.json" if external_receipt else
                    build / "verified-runs/control/verified-commands.json")
        commands.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        payload = {"commands": [{"target": "control", "return_code": 0}]}
        commands.write_text(json.dumps(payload))
        if receipt_link == "final":
            alias = external / "commands-link.json"
            alias.symlink_to(commands)
            commands = alias
        elif receipt_link == "intermediate":
            alias = self.root / "external-link"
            alias.symlink_to(external, target_is_directory=True)
            commands = alias / "commands.json"
        arguments = argparse.Namespace(connector_root=str(connector), framework_root=None,
            build_root=str(build), output_dir=str(self.root / "reports"),
            verified_run_id="control", verified_commands_file=str(commands) if external_receipt else None)
        defaults = {"BUILD_ROOT": str(build), "VERIFIED_RUN_ROOT": str(verified)}
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(MISMATCH, "verified_runtime_paths", return_value=defaults):
            configuration = MISMATCH.analysis_configuration(arguments, argparse.ArgumentParser())
        return configuration, payload

    def test_explicit_external_commands_receipt_is_readable(self):
        configuration, payload = self.configure_external_commands()
        self.assertEqual(MISMATCH.load_commands_payload(configuration["commands_file"]), payload)
        self.assertEqual(MISMATCH.load_commands(configuration["commands_file"]), payload["commands"])

    def test_default_inside_root_commands_receipt_is_readable(self):
        configuration, payload = self.configure_external_commands(False)
        self.assertEqual(MISMATCH.load_commands_payload(configuration["commands_file"]), payload)
        self.assertEqual(MISMATCH.load_commands(configuration["commands_file"]), payload["commands"])

    def test_explicit_receipt_links_are_rejected_before_reading(self):
        base = self.root
        for variant in ("final", "intermediate"):
            with self.subTest(variant=variant):
                directory = base / variant
                directory.mkdir(mode=0o700)
                with mock.patch.object(self, "root", directory):
                    configuration, _ = self.configure_external_commands(receipt_link=variant)
                self.assertEqual(MISMATCH.load_commands_payload(configuration["commands_file"]), {})
                self.assertEqual(MISMATCH.load_commands(configuration["commands_file"]), [])

    def component_pipeline(self, manifest_chooses_outside):
        connector, cache, output, build, outside = (self.root / name for name in
                                                   ("connector", "cache", "output", "build", "outside"))
        for directory in (connector, cache, output, build, outside):
            directory.mkdir(mode=0o700)
        postprocess = connector / "ci/evidence/reports/update-runtime-reports.py"
        postprocess.parent.mkdir(parents=True)
        postprocess.write_text("# postprocess placeholder; production API invoked in-process\n")
        selected_build = outside if manifest_chooses_outside else build
        host_build = selected_build / "apache-build"
        host_build.mkdir(mode=0o700)
        log = selected_build / "mrts-native/apache2_ubuntu/run.log"
        log.parent.mkdir(parents=True)
        sentinel = "100003-1 failed: unapproved-manifest-sentinel" if manifest_chooses_outside else "100003-1 failed"
        log.write_text(sentinel + "\n")
        stamp = "2026-10-26T00:00:00Z"
        payload = {"generated_at": stamp, "build_root": str(outside),
                   "apache_httpd": {"build_path": str(host_build), "status": "ready"}}
        context = {"cache_root": cache, "connector_root": connector,
                   "framework_root": connector / "modules/ModSecurity-test-Framework",
                   "report_dir": output / CACHE.GENERATED_ROOT, "output_root": output,
                   "build_root": build, "env": {}}
        metadata = {"generated_at": stamp, "verified_run_id": "control"}
        commands = []
        def postprocess_in_process(command):
            commands.append(list(command))
            with mock.patch.object(sys, "argv", command[1:]):
                self.assertEqual(CACHE.main(), 0)
        with (mock.patch.dict(os.environ, {"SUPPRESS_FULL_RUN_EVIDENCE_SIDE_EFFECTS": "1"}, clear=True),
              mock.patch.object(COMPONENTS, "build_metadata", return_value=metadata),
              mock.patch.object(CACHE, "build_metadata", return_value=metadata),
              mock.patch.object(COMPONENTS, "markdown_report", return_value="# fixture"),
              mock.patch.object(COMPONENTS, "runtime_build_cache_markdown", return_value="# fixture"),
              mock.patch.object(COMPONENTS, "generated_markdown_text", return_value="# fixture"),
              mock.patch.object(COMPONENTS, "run", side_effect=postprocess_in_process)):
            COMPONENTS.write_runtime_component_reports(context, payload, {"generated_at": stamp}, [])
        report = CACHE.report_path_from_root(context["report_dir"], "runtime_component_cache", "json")
        return json.loads(report.read_text()), commands[0], build, log

    def test_producer_forwards_independent_build_root_and_retains_diagnostics(self):
        report, command, build, log = self.component_pipeline(False)
        diagnosis = report["runtime_diagnostics"]["apache_100003_1"]
        self.assertEqual(diagnosis["go_ftw_excerpt"], "100003-1 failed")
        self.assertEqual(diagnosis["run_log"], str(log))
        self.assertEqual(command[command.index("--build-root") + 1], str(build))

    def test_manifest_build_path_cannot_extend_the_configured_build_root(self):
        report, _, _, _ = self.component_pipeline(True)
        self.assertEqual(report["runtime_diagnostics"], {})
        self.assertNotIn("unapproved-manifest-sentinel", json.dumps(report))


if os.environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)
