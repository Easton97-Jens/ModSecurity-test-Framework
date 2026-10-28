"""On-demand package CLI regressions using the pinned real MRTS generator."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]


class MrtsPackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mrts = Path(os.environ.get("MRTS_ROOT", str(ROOT / "tools/MRTS"))).resolve()
        if not (cls.mrts / "mrts/generate-rules.py").is_file():
            raise unittest.SkipTest("set MRTS_ROOT to the clean pinned MRTS checkout")
        cls.mrts_revision = cls.git(cls.mrts, "rev-parse", "HEAD")

    @staticmethod
    def git(root: Path, *args: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(root), "-c", "user.name=MRTS Package Test",
             "-c", "user.email=mrts-test@example.invalid", *args],
            check=True, text=True, capture_output=True,
        )
        return result.stdout.strip()

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="mrts-package-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.framework = self.root / "framework"
        self.connector = self.root / "connector"
        self.framework.mkdir()
        self.connector.mkdir()
        shutil.copy2(ROOT / "Makefile", self.framework / "Makefile")
        for name in ("ci", "tests/runners"):
            shutil.copytree(ROOT / name, self.framework / name, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        (self.framework / "tests/mrts").mkdir(parents=True)
        shutil.copy2(ROOT / "tests/mrts/classifications.yaml", self.framework / "tests/mrts/classifications.yaml")
        self.git(self.framework, "init", "-q")
        self.git(self.framework, "add", "Makefile", "ci", "tests")
        self.git(self.framework, "update-index", "--add", "--cacheinfo", f"160000,{self.mrts_revision},tools/MRTS")
        self.git(self.framework, "commit", "-qm", "Synthetic Framework package fixture")
        self.git(self.connector, "init", "-q")
        (self.connector / "README.md").write_text("Synthetic connector identity only.\n", encoding="utf-8")
        self.git(self.connector, "add", "README.md")
        self.git(self.connector, "commit", "-qm", "Synthetic connector identity")
        self.build = self.root / "build"
        self.package = self.build / "mrts/prepared"
        self.upstream = self.root / "upstream-definitions"
        self.demo = self.root / "demo-definitions"
        self.upstream.mkdir()
        self.demo.mkdir()
        self.copy_definitions(self.upstream)

    def copy_definitions(self, destination: Path) -> None:
        # The unchanged global template and a narrowed real ARGS definition
        # exercise generation/import without launching historical matrix cases.
        shutil.copy2(self.mrts / "config_tests/CONF_000_GLOBAL.yaml", destination)
        definition = yaml.safe_load((self.mrts / "config_tests/CONF_002_TARGET_ARGS_A-GET.yaml").read_text(encoding="utf-8"))
        definition["phase"] = [1]
        definition["colkey"] = [["arg1"]]
        definition["testdata"]["targets"] = [definition["testdata"]["targets"][1]]
        (destination / "CONF_002_TARGET_ARGS_A-GET.yaml").write_text(yaml.safe_dump(definition, sort_keys=False), encoding="utf-8")

    def cli(self, action: str, *, demo: int = 0, extra: tuple[str, ...] = ()) -> subprocess.CompletedProcess[str]:
        environment = dict(os.environ)
        for name in ("CI_ROOT", "REPO_ROOT", "SOURCE_ROOT", "BUILD_ROOT", "MRTS_BUILD_ROOT"):
            environment.pop(name, None)
        return subprocess.run(
            [sys.executable, str(self.framework / "ci/provisioning/mrts-package.py"), action,
             "--framework-root", str(self.framework), "--mrts-root", str(self.mrts),
             "--connector-root", str(self.connector), "--build-root", str(self.build),
             "--package-root", str(self.package), "--upstream-definitions", str(self.upstream),
             "--feature-demo-definitions", str(self.demo), "--include-feature-demo", str(demo), *extra],
            env=environment, text=True, capture_output=True, timeout=30, check=False,
        )

    def prepare(self) -> dict:
        result = self.cli("prepare")
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads((self.package / "manifest.json").read_text(encoding="utf-8"))

    def test_disabled_malformed_demo_does_not_block_base_package(self) -> None:
        (self.demo / "broken.yaml").write_text("global: [\n", encoding="utf-8")
        manifest = self.prepare()
        self.assertEqual(manifest["corpora"], ["upstream-config-tests"])
        self.assertEqual(manifest["corpus_status"]["feature-demo"], "disabled")
        self.assertFalse((self.package / "feature-demo").exists())
        self.assertTrue(manifest["case_ids"])
        self.assertEqual(self.cli("verify").returncode, 0)

    def test_enabled_malformed_demo_fails_without_publication(self) -> None:
        (self.demo / "broken.yaml").write_text("global: [\n", encoding="utf-8")
        result = self.cli("prepare", demo=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid YAML", result.stderr)
        self.assertFalse(self.package.exists())

    def test_enabled_rule_id_collision_remains_visible(self) -> None:
        self.copy_definitions(self.demo)
        result = self.cli("prepare", demo=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate rule IDs", result.stderr)
        self.assertFalse(self.package.exists())

    def test_failed_generator_cannot_reuse_old_outputs(self) -> None:
        stale = self.build / "mrts/upstream-config-tests/rules/stale.conf"
        stale.parent.mkdir(parents=True)
        stale.write_text('SecAction "id:42,phase:1,pass"\n', encoding="utf-8")
        definition_path = self.upstream / "CONF_002_TARGET_ARGS_A-GET.yaml"
        definition = yaml.safe_load(definition_path.read_text(encoding="utf-8"))
        definition["templates"] = ["missing generator template"]
        definition_path.write_text(yaml.safe_dump(definition), encoding="utf-8")
        result = self.cli("prepare")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.package.exists())
        self.assertEqual(stale.read_text(encoding="utf-8"), 'SecAction "id:42,phase:1,pass"\n')

    def test_artifact_hash_mismatch_is_rejected(self) -> None:
        self.prepare()
        artifact = next((self.package / "upstream-config-tests/rules").glob("*.conf"))
        artifact.write_text(artifact.read_text(encoding="utf-8") + "# tampered\n", encoding="utf-8")
        result = self.cli("verify")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("artifact hash mismatch", result.stderr)

    def test_selection_and_revision_mismatches_are_rejected(self) -> None:
        self.prepare()
        result = self.cli("verify", demo=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("identity mismatch", result.stderr)
        additional = self.upstream / "additional.yaml"
        additional.write_text("{}\n", encoding="utf-8")
        result = self.cli("verify")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("definition selection or hash mismatch", result.stderr)
        additional.unlink()
        (self.connector / "README.md").write_text("Changed identity.\n", encoding="utf-8")
        self.git(self.connector, "add", "README.md")
        self.git(self.connector, "commit", "-qm", "Change connector revision")
        result = self.cli("verify")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("identity mismatch", result.stderr)

    def test_private_port_materialization_preserves_shared_package(self) -> None:
        manifest = self.prepare()
        before = {p.relative_to(self.package): hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in self.package.rglob("*") if p.is_file()}
        private = self.build / "connector-run"
        result = self.cli("materialize", extra=("--output-root", str(private), "--port", "19321"))
        self.assertEqual(result.returncode, 0, result.stderr)
        after = {p.relative_to(self.package): hashlib.sha256(p.read_bytes()).hexdigest()
                 for p in self.package.rglob("*") if p.is_file()}
        self.assertEqual(before, after)
        self.assertEqual(self.cli("verify").returncode, 0)
        ports = []
        for ftw in (private / "upstream-config-tests/ftw").glob("*.yaml"):
            for test in yaml.safe_load(ftw.read_text(encoding="utf-8"))["tests"]:
                for stage in test["stages"]:
                    ports.append(stage.get("input", stage.get("stage", {}).get("input"))["port"])
        self.assertTrue(ports)
        self.assertEqual(set(ports), {19321})
        self.assertEqual(json.loads((private / "manifest.json").read_text())["case_ids"], manifest["case_ids"])
        self.assertIn(str(private), (private / "upstream-config-tests/mrts.load").read_text())
        prepared = subprocess.run(
            ["sh", "-eu", "-c", '. "$FRAMEWORK_ROOT/ci/lib/mrts-common.sh"; '
             'prepare_mrts_runtime_variant; printf "%s\\n" "$MRTS_RUNTIME_ROOT" "$MRTS_LOAD_FILE"'],
            env=dict(os.environ, FRAMEWORK_ROOT=str(self.framework), CONNECTOR_ROOT=str(self.connector),
                     MRTS_ROOT=str(self.mrts), BUILD_ROOT=str(self.build), MRTS_BUILD_ROOT=str(self.build / "mrts"),
                     MRTS_PACKAGE_ROOT=str(self.package), MRTS_RUNTIME_PORT="19322", PYTHON=sys.executable,
                     MRTS_UPSTREAM_DEFINITIONS=str(self.upstream), MRTS_FEATURE_DEMO_DEFINITIONS=str(self.demo),
                     MODSECURITY_MRTS_PREPARED="1", MODSECURITY_MRTS_VARIANT="with-mrts",
                     MODSECURITY_MRTS_INCLUDE_FEATURE_DEMO="0"),
            text=True, capture_output=True, timeout=30, check=False,
        )
        self.assertEqual(prepared.returncode, 0, prepared.stderr)
        runtime_root, runtime_load = prepared.stdout.splitlines()
        self.assertNotEqual(Path(runtime_root), self.package)
        self.assertEqual(Path(runtime_load), Path(runtime_root) / "upstream-config-tests/mrts.load")
        self.assertEqual(before, {p.relative_to(self.package): hashlib.sha256(p.read_bytes()).hexdigest()
                                  for p in self.package.rglob("*") if p.is_file()})

    def test_mid_import_failure_leaves_no_published_package(self) -> None:
        path = self.upstream / "CONF_002_TARGET_ARGS_A-GET.yaml"
        definition = yaml.safe_load(path.read_text(encoding="utf-8"))
        definition["testdata"]["targets"].append({
            "target": "arg1", "test": {"data": {"arg1": "attack"},
                "input": {"headers": [{"name": "bad name", "value": "invalid"}]}}
        })
        path.write_text(yaml.safe_dump(definition, sort_keys=False), encoding="utf-8")
        result = self.cli("prepare")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ASCII HTTP token", result.stderr)
        self.assertFalse(self.package.exists())
        self.assertEqual(list((self.build / "mrts").glob(".mrts-package-*")), [])

    def test_child_connectors_receive_independent_case_roots_and_preambles(self) -> None:
        self.prepare()
        child = '. "$FRAMEWORK_ROOT/ci/lib/mrts-common.sh"; prepare_mrts_runtime_variant; printf "%s|%s|%s\\n" "$MRTS_RUNTIME_ROOT" "$EXTRA_CASE_ROOTS" "$MODSECURITY_RULE_PREAMBLE_FILE"'
        # The orchestration shell prepares once, then starts two host shells.
        # Neither host may inherit that writable materialization or its load.
        script = child + '; sh -eu -c "$CHILD_SCRIPT"; sh -eu -c "$CHILD_SCRIPT"'
        result = subprocess.run(
            ["sh", "-eu", "-c", script],
            env=dict(os.environ, CHILD_SCRIPT=child, FRAMEWORK_ROOT=str(self.framework),
                CONNECTOR_ROOT=str(self.connector), MRTS_ROOT=str(self.mrts),
                BUILD_ROOT=str(self.build), MRTS_BUILD_ROOT=str(self.build / "mrts"),
                MRTS_PACKAGE_ROOT=str(self.package), PYTHON=sys.executable,
                MRTS_UPSTREAM_DEFINITIONS=str(self.upstream),
                MRTS_FEATURE_DEMO_DEFINITIONS=str(self.demo),
                MODSECURITY_MRTS_PREPARED="1", MODSECURITY_MRTS_VARIANT="with-mrts",
                MODSECURITY_MRTS_INCLUDE_FEATURE_DEMO="0"),
            text=True, capture_output=True, timeout=45, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = [line.split("|") for line in result.stdout.splitlines()]
        self.assertEqual(len(rows), 3)
        self.assertEqual(len({row[0] for row in rows}), 3)
        for runtime, roots, preamble in rows:
            self.assertEqual(roots, str(Path(runtime) / "upstream-config-tests/framework-cases"))
            self.assertEqual(preamble, str(Path(runtime) / "upstream-config-tests/mrts.load"))


if __name__ == "__main__":
    unittest.main()
