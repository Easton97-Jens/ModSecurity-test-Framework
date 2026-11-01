"""Evidence contents never grant access to a different filesystem root."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = connector_root()


from modsecurity_connector_ci.lib.evidence_inputs import EvidenceInputs


def load(name: str, relative: str):
    module = load_source(ROOT / relative)
    return module


NGINX = load("nginx_evidence_security", "ci/evidence/reports/generate-nginx-mrts-http500-cluster-analysis.py")
CACHE = load("cache_evidence_security", "ci/evidence/reports/update-runtime-reports.py")
MISMATCH = load("mismatch_evidence_security", "ci/evidence/reports/generate-verified-runtime-mismatch-analysis.py")
COMPONENTS = load("component_evidence_security", "ci/provisioning/components/prepare-runtime-components.py")


class EvidenceInputSecurityTests(unittest.TestCase):
    def test_evidence_lookup_preserves_configured_source_and_build_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, build = root / "source", root / "build"
            source.mkdir()
            build.mkdir()
            (source / "rules.conf").write_text("control", encoding="utf-8")
            (build / "result.json").write_text("{}", encoding="utf-8")
            with mock.patch.object(MISMATCH, "INPUTS", EvidenceInputs((source, build))):
                self.assertEqual(MISMATCH.resolve_evidence_file("rules.conf", connector_root=source,
                                                               build_root=build), source / "rules.conf")
                self.assertEqual(MISMATCH.resolve_evidence_file("result.json", connector_root=source,
                                                               build_root=build), build / "result.json")
                self.assertEqual(MISMATCH.resolve_recorded_path("missing.json", connector_root=source,
                                                                build_root=build), build / "missing.json")

    def test_recorded_evidence_cannot_select_parent_or_sibling_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, build = root / "source", root / "build"
            source.mkdir()
            build.mkdir()
            outside = root / "build-other"
            outside.mkdir()
            secret = outside / "secret"
            secret.write_text("sentinel", encoding="utf-8")
            with mock.patch.object(MISMATCH, "INPUTS", EvidenceInputs((source, build))):
                for value in (str(secret), "../build-other/secret"):
                    with self.subTest(value=value):
                        with self.assertRaises(ValueError):
                            MISMATCH.resolve_evidence_file(value, connector_root=source, build_root=build)

    def test_jsonl_parser_keeps_valid_objects_and_ignores_malformed_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "events.jsonl"
            path.write_text('broken\n[]\n{"sequence":1}\nnull\n{"sequence":2}\n', encoding="utf-8")
            self.assertEqual(EvidenceInputs((root,)).jsonl(path), [{"sequence": 1}, {"sequence": 2}])

    def test_confined_metadata_preserves_failed_source_status(self) -> None:
        import modsecurity_connector_ci.lib.generated_report_utils as policy
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / policy.GENERATED_REPORTS["full_runtime_matrix"].filename("json")
            path.write_text(json.dumps({"metadata": {"verified_run_id": "control"}, "status": "failed"}), encoding="utf-8")
            metadata = EvidenceInputs((root,)).build_metadata(
                lambda **_: {"verified_run_id": "control"}, inputs=[path], connector_root=ROOT)
            self.assertEqual(metadata["inputs"][0]["status"], "failed")

    def test_confined_metadata_retains_markdown_receipt_identity(self) -> None:
        import modsecurity_connector_ci.lib.generated_report_utils as policy
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / policy.GENERATED_REPORTS["full_runtime_matrix"].filename("md")
            path.write_text('- Verified run id: `control`\n', encoding="utf-8")
            metadata = EvidenceInputs((root,)).build_metadata(
                lambda **_: {"verified_run_id": "control"}, inputs=[path], connector_root=ROOT)
            self.assertEqual(metadata["inputs"][0]["verified_run_id"], "control")
            self.assertEqual(metadata["inputs"][0]["status"], "present")

    def mismatch_cli(self, root: Path, *, linked: bool) -> tuple[dict, bytes]:
        connector = root / "connector"
        build = root / "build"
        output = root / "output"
        connector.mkdir()
        build.mkdir()
        data = b'{"record":"control"}\n'
        if linked:
            source = root / "outside"
            source.mkdir()
            (build / "full-matrix").symlink_to(source, target_is_directory=True)
        else:
            source = build / "full-matrix"
            source.mkdir()
        (source / "full-runtime-matrix-runs.jsonl").write_bytes(data)
        arguments = ["mismatch", "--connector-root", str(connector), "--build-root", str(build),
                     "--output-dir", str(output), "--verified-run-id", "security-control"]
        with (
            mock.patch.object(sys, "argv", arguments),
            mock.patch.dict(os.environ, {"VERIFIED_RUN_ROOT": str(root / "verified"),
                                        "VERIFIED_RUN_COMMANDS_FILE": ""}),
        ):
            self.assertEqual(MISMATCH.main(), 0)
        filename = MISMATCH.GENERATED_REPORTS["verified_runtime_mismatch_analysis"].filename("json")
        return json.loads((output / filename).read_text(encoding="utf-8")), data

    def test_mismatch_cli_metadata_rejects_an_intermediate_link(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            payload, data = self.mismatch_cli(Path(temporary), linked=True)
            self.assertNotIn(hashlib.sha256(data).hexdigest(), json.dumps(payload))
            manifest = next(item for item in payload["metadata"]["inputs"]
                            if item["path"].endswith("full-runtime-matrix-runs.jsonl"))
            self.assertEqual(manifest["status"], "blocked")

    def test_mismatch_cli_metadata_retains_regular_manifest_proof(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            payload, data = self.mismatch_cli(Path(temporary), linked=False)
            manifest = next(item for item in payload["metadata"]["inputs"]
                            if item["path"].endswith("full-runtime-matrix-runs.jsonl"))
            self.assertEqual(manifest["sha256"], hashlib.sha256(data).hexdigest())

    def test_nginx_report_does_not_publish_json_selected_outside_log(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build = root / "build"
            job = build / "full-matrix/with-crs/with-mrts/nginx"
            results = job / "results/force-all"
            results.mkdir(parents=True)
            (job / "job.json").write_text("{}", encoding="utf-8")
            outside = root / "outside.log"
            outside.write_text("outside-sentinel", encoding="utf-8")
            row = {"name": "mrts_100000_mrts_002_args_a_get_100000_1", "actual_status": 500,
                   "audit_log_path": str(outside)}
            (results / "nginx-results.jsonl").write_text(json.dumps(row) + "\n", encoding="utf-8")
            payload = NGINX.build_payload(ROOT, build, "security-control")
            self.assertNotIn("outside-sentinel", json.dumps(payload))

    def test_cache_report_does_not_hash_manifest_selected_outside_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache = root / "cache"
            cache.mkdir()
            outside = root / "outside.bin"
            outside.write_bytes(b"outside-sentinel")
            payload = CACHE.runtime_cache_index_payload(cache, {"nginx": {"nginx_bin": str(outside)}}, {})
            item = next(item for item in payload["important_files"] if item["name"] == "nginx")
            self.assertEqual(item["status"], "rejected")
            self.assertEqual(item["sha256"], "-")

    def test_read_and_hash_use_a_regular_file_in_an_explicit_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.json"
            source.write_bytes(b'{"control":true}')
            inputs = EvidenceInputs((root,))
            self.assertEqual(inputs.json(source), {"control": True})
            self.assertEqual(inputs.file_proof(source), (hashlib.sha256(source.read_bytes()).hexdigest(), 16))
            self.assertTrue(inputs.is_file(source))

    def test_rejects_sibling_prefix_traversal_and_final_or_intermediate_links(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / "run"
            root.mkdir()
            outside = parent / "run-other"
            outside.mkdir()
            victim = outside / "secret"
            victim.write_bytes(b"sentinel")
            (root / "link").symlink_to(victim)
            (root / "directory-link").symlink_to(outside, target_is_directory=True)
            inputs = EvidenceInputs((root,))
            for path in (victim, root / ".." / "run-other" / "secret", root / "link", root / "directory-link/secret"):
                with self.subTest(path=path):
                    with self.assertRaises((ValueError, OSError)):
                        inputs.read_bytes(path)
                    self.assertFalse(inputs.is_file(path))

    def test_replacement_before_final_open_cannot_follow_a_link(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.write_bytes(b"control")
            victim = root / "victim"
            victim.write_bytes(b"sentinel")
            inputs = EvidenceInputs((root,))
            real_open = os.open
            replaced = False

            def replace_on_open(path, flags, *args, **kwargs):
                nonlocal replaced
                if path == source.name and kwargs.get("dir_fd") is not None and not replaced:
                    replaced = True
                    source.unlink()
                    source.symlink_to(victim)
                return real_open(path, flags, *args, **kwargs)

            with mock.patch("evidence_inputs.os.open", side_effect=replace_on_open):
                with self.assertRaises(OSError):
                    inputs.read_bytes(source)
            self.assertTrue(replaced)

    def test_empty_or_filesystem_root_allowlists_cannot_grant_arbitrary_access(self) -> None:
        self.assertFalse(EvidenceInputs(()).is_file(source_path('Makefile', root=ROOT)))
        with self.assertRaisesRegex(ValueError, "entire filesystem"):
            EvidenceInputs((Path("/"),))

    def test_nested_rule_include_cannot_expand_configured_roots(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            runtime = parent / "runtime"
            source = parent / "framework"
            runtime.mkdir()
            source.mkdir()
            outside = parent / "outside-mrts.conf"
            outside.write_text(MISMATCH.DETECTION_ONLY_DIRECTIVE, encoding="utf-8")
            fixture = source / "fixture.conf"
            fixture.write_text(MISMATCH.DETECTION_ONLY_DIRECTIVE, encoding="utf-8")
            load = runtime / "mrts.load"
            load.write_text(f'Include "{outside}"\nInclude "{fixture}"\n', encoding="utf-8")
            smoke = runtime / "smoke.conf"
            smoke.write_text(f'Include "{load}"\n', encoding="utf-8")
            with mock.patch.object(MISMATCH, "INPUTS", EvidenceInputs((runtime, source))):
                paths = MISMATCH.detection_only_rule_paths_from_smoke_file(smoke)
                self.assertEqual(paths, [fixture])
                self.assertIsNone(MISMATCH.read_text_or_none(outside))

    def test_cache_proof_preserves_explicit_operator_approved_override(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            cache = parent / "cache"
            cache.mkdir()
            binary = parent / "installed-binary"
            binary.write_bytes(b"control")
            manifest = {"nginx": {"nginx_bin": str(binary)}, "build_root": "/"}
            denied = CACHE.runtime_cache_index_payload(cache, manifest, {})
            allowed = CACHE.runtime_cache_index_payload(cache, manifest, {}, approved_files=(binary,))
            denied_item = next(item for item in denied["important_files"] if item["name"] == "nginx")
            allowed_item = next(item for item in allowed["important_files"] if item["name"] == "nginx")
            self.assertEqual(denied_item["status"], "rejected")
            self.assertEqual(allowed_item["status"], "present")
            self.assertEqual(allowed_item["sha256"], hashlib.sha256(b"control").hexdigest())

    def test_cache_library_alias_keeps_only_an_independently_approved_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            cache = parent / "cache"
            library = cache / "prefix/lib/libmodsecurity.so.3.0.14"
            library.parent.mkdir(parents=True)
            library.write_bytes(b"library-control")
            alias = library.parent / "libmodsecurity.so"
            alias.symlink_to(library.name)
            manifest = {"modsecurity": {"lib_file": str(alias)}}
            payload = CACHE.runtime_cache_index_payload(cache, manifest, {})
            proof = next(item for item in payload["important_files"] if item["name"] == "libmodsecurity")
            self.assertEqual(proof["status"], "present")
            self.assertEqual(proof["sha256"], hashlib.sha256(b"library-control").hexdigest())
            outside = parent / "outside-library"
            outside.write_bytes(b"outside-sentinel")
            alias.unlink()
            alias.symlink_to(outside)
            payload = CACHE.runtime_cache_index_payload(cache, manifest, {})
            proof = next(item for item in payload["important_files"] if item["name"] == "libmodsecurity")
            self.assertEqual(proof["status"], "rejected")
            self.assertEqual(proof["sha256"], "-")

            outside.unlink()
            payload = CACHE.runtime_cache_index_payload(cache, manifest, {})
            absent_proof = next(item for item in payload["important_files"] if item["name"] == "libmodsecurity")
            self.assertEqual(absent_proof, proof)

    def test_full_nginx_generator_metadata_cannot_reopen_intermediate_symlink(self) -> None:
        self.enterContext(mock.patch("report_path_safety.SAFE_ROOTS", set()))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build = root / "build"
            job = build / "full-matrix/with-crs/with-mrts/nginx"
            outside = root / "outside"
            outside.mkdir()
            (outside / "job.json").write_text("{}", encoding="utf-8")
            (outside / "run.log").write_bytes(b"outside-metadata-sentinel")
            job.parent.mkdir(parents=True)
            job.symlink_to(outside, target_is_directory=True)
            output = root / "output"
            command = [str(NGINX.__file__), "--connector-root", str(ROOT), "--build-root", str(build),
                       "--output-dir", str(output), "--verified-run-id", "metadata-control"]
            with mock.patch.object(sys, "argv", command):
                self.assertEqual(NGINX.main(), 0)
            report = NGINX.report_path_from_root(output, "nginx_mrts_http500_cluster_analysis", "json")
            payload = json.loads(report.read_text(encoding="utf-8"))
            self.assertNotIn(hashlib.sha256(b"outside-metadata-sentinel").hexdigest(), json.dumps(payload))
            record = next(record for record in payload["metadata"]["inputs"] if record["path"].endswith("run.log"))
            self.assertEqual(record["status"], "blocked")

            job.unlink()
            job.mkdir()
            (job / "job.json").write_text("{}", encoding="utf-8")
            (job / "run.log").write_bytes(b"control")
            with mock.patch.object(sys, "argv", command):
                self.assertEqual(NGINX.main(), 0)
            payload = json.loads(report.read_text(encoding="utf-8"))
            record = next(record for record in payload["metadata"]["inputs"] if record["path"].endswith("run.log"))
            self.assertEqual(record["status"], "present")
            self.assertEqual(record["sha256"], hashlib.sha256(b"control").hexdigest())

    def test_confined_metadata_keeps_generated_report_staleness(self) -> None:
        import modsecurity_connector_ci.lib.generated_report_utils as policy
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / policy.GENERATED_REPORTS["verified_runtime_mismatch_analysis"].filename("json")
            path.write_text(json.dumps({"metadata": {"verified_run_id": "old-run"}}), encoding="utf-8")
            builder = mock.Mock(return_value={"verified_run_id": "current-run"})
            with mock.patch.object(policy, "_report_staleness_reasons", return_value=["verified_run_id differs"]):
                metadata = EvidenceInputs((root,)).build_metadata(
                    builder, connector_root=ROOT, inputs=(path,))
            self.assertEqual(builder.call_args.kwargs["inputs"], ())
            self.assertEqual(metadata["inputs"][0]["status"], "stale")
            self.assertEqual(metadata["input_status"], "stale")
            self.assertIn("verified_run_id differs", metadata["inputs"][0]["notes"])

    def test_component_postprocess_approves_configured_leaf_not_manifest_claim(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            connector = root / "connector"
            postprocess = connector / "ci/evidence/reports/update-runtime-reports.py"
            postprocess.parent.mkdir(parents=True)
            postprocess.write_text("# fixture", encoding="utf-8")
            cache = root / "cache"
            reports = root / CACHE.GENERATED_ROOT
            cache.mkdir()
            configured = root / "configured-httpd"
            configured.write_bytes(b"configured-control")
            attacker_claim = root / "manifest-selected-httpd"
            attacker_claim.write_bytes(b"untrusted-control")
            context = {"cache_root": cache, "connector_root": connector,
                       "framework_root": connector / "modules/ModSecurity-test-Framework",
                       "report_dir": reports, "output_root": root,
                       "env": {"APACHE_HTTPD": str(configured)}}
            payload = {"generated_at": "2026-10-25T00:00:00Z",
                       "apache_httpd": {"httpd_bin": str(configured)},
                       "nginx": {"nginx_bin": str(attacker_claim)}}
            with (mock.patch.object(COMPONENTS, "build_metadata", return_value={"generated_at": payload["generated_at"]}),
                  mock.patch.object(COMPONENTS, "markdown_report", return_value="# fixture"),
                  mock.patch.object(COMPONENTS, "runtime_build_cache_markdown", return_value="# fixture"),
                  mock.patch.object(COMPONENTS, "generated_markdown_text", return_value="# fixture"),
                  mock.patch.object(COMPONENTS, "run") as run):
                COMPONENTS.write_runtime_component_reports(context, payload, {"status": "control"}, [])
            command = run.call_args.args[0]
            approved = [command[index + 1] for index, item in enumerate(command) if item == "--approved-component-file"]
            self.assertEqual(approved, [str(configured)])
            self.assertNotIn(str(attacker_claim), approved)
            self.assertEqual(command[command.index("--cache-root") + 1], str(cache))
            # Execute the emitted postprocess contract with the real updater.
            command[1] = str(source_path('ci/evidence/reports/update-runtime-reports.py', root=ROOT))
            command[command.index("--connector-root") + 1] = str(ROOT)
            result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                                    env=dict(os.environ, SUPPRESS_FULL_RUN_EVIDENCE_SIDE_EFFECTS="1"))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            report = CACHE.report_path_from_root(reports, "runtime_cache_index", "json")
            files = {item["name"]: item for item in json.loads(report.read_text())["important_files"]}
            self.assertEqual(files["apache_httpd"]["status"], "present")
            self.assertEqual(files["nginx"]["status"], "rejected")


# Parent discovery remains inventory-bound; only an explicit selected Master
# assessment may opt into the complete module without importing helpers eagerly.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)


if __name__ == "__main__":
    unittest.main()
