"""Offline Hosted orchestration boundaries; no native builds, downloads or scans."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import ast
from copy import deepcopy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch


ROOT = connector_root()
CI = load_source(source_path('ci/checks/analysis/prepare-sonar-native-ci.py', root=ROOT))
REVISION = "a" * 40
TARGET = "traefik-engine-service"
CONTRACT = {"commit": "b" * 40, "source_url": "https://github.com/owasp-modsecurity/ModSecurity.git",
            "release_tag": "v3.0.17", "version": "3.0.17", "framework_sha": "c" * 40}


def scope_manifest() -> dict:
    paths = [source_path('common/src/runtime.c', root=ROOT), source_path('common/include/msconnector/runtime.h', root=ROOT)]
    return {"target": TARGET, "revision": REVISION, "import_eligible": True, "development_only": False,
            "translation_units": 1, "scanner_expected_parent_input_paths": [str(path) for path in paths],
            "scanner_scope": {"sonar.projectBaseDir": str(ROOT), "sonar.scm.revision": REVISION,
                              "sonar.sources": ",".join(str(path.relative_to(ROOT)) for path in paths),
                              "sonar.cfamily.compile-commands": "/external/validated/compile_commands.json",
                              "sonar.coverage.exclusions": "**"}}


def sdk_fixture(root: Path, member_name: str | None = None, outside_link: bool = False) -> tuple[Path, dict]:
    transfer = root / "transfer"
    transfer.mkdir()
    prefix = root / "sdk/cache-v2/shared/prefix/modsecurity/build-id"
    relative = prefix.relative_to(root)
    payload = b"real-sdk-fixture-bytes"
    with tarfile.open(transfer / "sdk.tar.gz", "w:gz") as archive:
        library = tarfile.TarInfo(member_name or str(relative / "lib/libmodsecurity.so.3"))
        library.size = len(payload)
        archive.addfile(library, io.BytesIO(payload))
        link = tarfile.TarInfo(str(relative / "lib/libmodsecurity.so"))
        link.type = tarfile.SYMTYPE
        link.linkname = "../../../../../escaped-sdk-link" if outside_link else "libmodsecurity.so.3"
        archive.addfile(link)
    metadata = {"schema": 1, "revision": REVISION, "source": CONTRACT,
                "prefix": str(prefix), "bundle_sha256": CI.digest(transfer / "sdk.tar.gz"),
                "library_sha256": hashlib.sha256(payload).hexdigest(),
                "provenance": {"actual_sha": CONTRACT["commit"], "build_id": prefix.name}}
    (transfer / "sdk-metadata.json").write_text(json.dumps(metadata))
    return transfer, metadata


class SonarNativeCiTests(unittest.TestCase):
    def test_analyze_exports_actual_producer_capture_directory(self):
        from modsecurity_connector_tests.test_sonar_native_security import NativeSecurityCaptureTest, VALIDATOR

        fixture = NativeSecurityCaptureTest(methodName="test_target_export_integrity")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.contract["target"] = TARGET
        root = fixture.root / "hosted"
        root.mkdir(mode=0o700)
        transfer, _ = sdk_fixture(root)
        producer = source_path('ci/checks/analysis/sonar-native-security', root=ROOT)
        tree = ast.parse((producer / "build-target.py").read_text())
        build = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "build")
        layout = next(node.value for node in build.body if isinstance(node, ast.Assign)
                      and any(isinstance(name, ast.Name) and name.id == "captures" for name in node.targets))
        self.assertIsInstance(layout, ast.BinOp)
        self.assertIsInstance(layout.op, ast.Div)
        self.assertIsInstance(layout.left, ast.Name)
        self.assertEqual(layout.left.id, "root")
        capture_child = ast.literal_eval(layout.right)
        commands = []

        def native_command(arguments, **kwargs):
            commands.append(Path(arguments[1]).name)
            if commands == ["build-target.py"]:
                output = Path(arguments[arguments.index("--output-root") + 1])
                output.mkdir(mode=0o700)
                fixture.captures.rename(output / capture_child)
                (output / "contract.json").write_text(json.dumps(fixture.contract))
            elif commands == ["build-target.py", "validate.py"]:
                capture_root = Path(arguments[arguments.index("--capture-root") + 1])
                contract = json.loads(Path(arguments[arguments.index("--contract") + 1]).read_text())
                output = Path(arguments[arguments.index("--output") + 1])
                VALIDATOR.export(capture_root, contract, fixture.checkout, output)
            else:
                self.fail("unexpected native subprocess dispatch")

        with patch.object(CI, "ROOT", fixture.checkout), \
                patch.object(CI, "NATIVE_STORAGE_ROOT", fixture.root), \
                patch.object(CI, "check_revision") as revision, \
                patch.object(CI, "framework_contract", return_value=CONTRACT), \
                patch.object(CI, "run", side_effect=native_command), \
                patch.object(CI, "ctu_limits", return_value=(2, 2048)), \
                patch.dict(os.environ, GITHUB_EVENT_NAME="push"):
            CI.analyze(root, transfer, REVISION, TARGET)
        self.assertEqual(commands, ["build-target.py", "validate.py"])
        self.assertEqual(revision.call_count, 2)
        rows = json.loads((root / "validated/compile_commands.json").read_text())
        self.assertEqual([row["file"] for row in rows], [str(fixture.source)])
        self.assertEqual(rows[0]["arguments"], fixture.compile["arguments"])
        settings = dict(line.split("=", 1) for line in (root / "native.properties").read_text().splitlines())
        self.assertEqual(settings["sonar.cfamily.compile-commands"], str(root / "validated/compile_commands.json"))
        self.assertEqual(set(settings["sonar.sources"].split(",")), {"product.c", "product.h"})

    def test_project_inventory_matches_real_native_producer_targets(self):
        tree = ast.parse((source_path('ci/checks/analysis/sonar-native-security/build-target.py', root=ROOT)).read_text())
        targets = next(node.value for node in tree.body if isinstance(node, ast.Assign)
                       and any(isinstance(name, ast.Name) and name.id == "TARGETS" for name in node.targets))
        self.assertEqual(set(CI.TARGETS), {ast.literal_eval(key) for key in targets.keys})
        self.assertEqual(CI.TARGETS[:2], ("traefik-engine-service", "haproxy-spoa-runtime"))
        self.assertEqual(len({CI.PROJECT_PREFIX + target.replace("-", "_") for target in CI.TARGETS}), 12)

    def test_settings_preserve_parent_headers_and_full_security_depth(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, GITHUB_EVENT_NAME="push"):
            output = Path(temporary)
            with patch.object(CI, "ctu_limits", return_value=(2, 2048)):
                CI.write_settings(scope_manifest(), output, TARGET, REVISION)
            values = dict(line.split("=", 1) for line in (output / "native.properties").read_text().splitlines())
            self.assertIn("common/include/msconnector/runtime.h", values["sonar.sources"])
            self.assertEqual(values["sonar.cfamily.taintAnalysis"], "true")
            self.assertEqual(values["sonar.cfamily.ctuAnalysis.branchSubstring"], "all branches")
            self.assertEqual(values["sonar.cfamily.analysisCache.mode"], "fs")
            self.assertEqual(values["sonar.qualitygate.wait"], "true")
            self.assertEqual(values["sonar.coverage.exclusions"], "**")
            self.assertNotIn("sonar.projectBaseDir", values)
            self.assertNotIn("sonar.exclusions", values)
            self.assertEqual(values["sonar.projectKey"], CI.PROJECT_PREFIX + "traefik_engine_service")

    def test_settings_reject_missing_parent_header(self):
        manifest = scope_manifest()
        manifest["scanner_scope"]["sonar.sources"] = "common/src/runtime.c"
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "exact eligible Parent target closure"):
                CI.write_settings(manifest, Path(temporary), TARGET, REVISION)

    def test_settings_reject_false_pr_identity(self):
        original = {"number": 123, "pull_request": {
            "head": {"sha": REVISION, "ref": "feature", "repo": {"full_name": "Easton97-Jens/ModSecurity-conector"}},
            "base": {"ref": "master", "repo": {"full_name": "Easton97-Jens/ModSecurity-conector"}}}}
        for kind in ("revision", "fork", "number"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                event = deepcopy(original)
                if kind == "revision":
                    event["pull_request"]["head"]["sha"] = "d" * 40
                elif kind == "fork":
                    event["pull_request"]["head"]["repo"]["full_name"] = "other/fork"
                else:
                    event["number"] = 0
                output = Path(temporary)
                path = output / "event.json"
                path.write_text(json.dumps(event))
                with patch.dict(os.environ, GITHUB_EVENT_NAME="pull_request", GITHUB_EVENT_PATH=str(path)), \
                        patch.object(CI, "ctu_limits", return_value=(2, 2048)):
                    manifest = scope_manifest()
                    with self.assertRaisesRegex(ValueError, "same-repository revision"):
                        CI.write_settings(manifest, output, TARGET, REVISION)

    def test_external_root_rejects_checkout(self):
        with self.assertRaisesRegex(ValueError, "private external project child"):
            CI.external_root(ROOT)

    def test_external_root_rejects_shared_ancestor_without_chmod(self):
        with tempfile.TemporaryDirectory() as temporary:
            storage = Path(temporary) / "approved"
            storage.mkdir()
            shared = storage / "shared"
            shared.mkdir()
            shared.chmod(0o777)
            with patch.object(CI, "NATIVE_STORAGE_ROOT", storage):
                with self.assertRaisesRegex(ValueError, "untrusted shared writes"):
                    CI.external_root(shared)
            self.assertEqual(shared.stat().st_mode & 0o777, 0o777)

    def test_sdk_transfer_preserves_real_relative_library_link(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            transfer, metadata = sdk_fixture(root)
            with patch.object(CI, "framework_contract", return_value=CONTRACT):
                prefix = CI.restore_sdk(root, transfer, REVISION)
            self.assertEqual(str(prefix), metadata["prefix"])
            self.assertTrue((prefix / "lib/libmodsecurity.so").is_symlink())
            self.assertEqual(CI.digest(prefix / "lib/libmodsecurity.so"), metadata["library_sha256"])

    def test_sdk_transfer_rejects_wrong_revision_source_or_digest(self):
        for field in ("revision", "source", "bundle_sha256"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                transfer, metadata = sdk_fixture(root)
                metadata[field] = {} if field == "source" else "0" * 40
                (transfer / "sdk-metadata.json").write_text(json.dumps(metadata))
                with patch.object(CI, "framework_contract", return_value=CONTRACT):
                    with self.assertRaises(ValueError):
                        CI.restore_sdk(root, transfer, REVISION)

    def test_sdk_transfer_rejects_archive_escape(self):
        for kind in ("absolute", "traversal", "symlink"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                member = "/escaped-sdk-file" if kind == "absolute" else "../escaped-sdk-file" if kind == "traversal" else None
                transfer, _ = sdk_fixture(root, member, outside_link=kind == "symlink")
                with patch.object(CI, "framework_contract", return_value=CONTRACT):
                    with self.assertRaisesRegex(ValueError, "escapes its fixed prefix subtree"):
                        CI.restore_sdk(root, transfer, REVISION)
                self.assertFalse((root.parent / "escaped-sdk-file").exists())

    def test_ctu_limits_reject_insufficient_resources(self):
        self.assertEqual(CI.ctu_limits(100, 32 * 1024**3, 16 * 1024**2, 8), (2, 4000))
        for units, disk, memory in ((0, 32 * 1024**3, 16 * 1024**2),
                                    (100, 0, 16 * 1024**2), (100, 32 * 1024**3, 0)):
            with self.subTest(units=units, disk=disk, memory=memory):
                with self.assertRaises(ValueError):
                    CI.ctu_limits(units, disk, memory, 8)


if os.environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)


if __name__ == "__main__":
    unittest.main()
