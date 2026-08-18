from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from ci.tools.crs_contract_pins import load_crs_pins, require_regular_file_within_root


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "ci/tools/sync-crs-contract-views.py"
COMMON = ROOT / "ci/lib/common.sh"
TARGETS = (
    "tests/schemas/five-connectors-with-crs-no-mrts/normalized-event.schema.json",
    "tests/schemas/five-connectors-with-crs-no-mrts/manifest.schema.json",
    "tests/schemas/five-connectors-with-crs-no-mrts/receipt.schema.json",
    "tests/cases/security/crs/crs_sqli_anomaly_block.yaml",
)
FULL_CRS_SCHEMA_TARGETS = TARGETS[:2]
RECEIPT_SCHEMA_TARGET = TARGETS[2]
FIXTURE_TARGET = TARGETS[3]


class SyncCrsContractViewsTests(unittest.TestCase):
    def _run(self, root: Path, mode: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(TOOL), mode, "--root", str(root)],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            env={"PATH": "/usr/bin:/bin", "PYTHONNOUSERSITE": "1"},
        )

    def _copy_fixture(self, root: Path) -> None:
        shutil.copy2(COMMON, root / "ci/lib/common.sh")
        for relative in TARGETS:
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination)

    def test_mutation_is_detected_and_write_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "ci/lib").mkdir(parents=True)
            self._copy_fixture(root)
            common = root / "ci/lib/common.sh"
            current_pins = load_crs_pins(common, root=root)
            current_tag = current_pins.release_tag
            major, minor, patch = current_tag[1:].split(".")
            mutated_tag = f"v{major}.{int(minor) + 1}.{patch}"
            mutated_commit = "0" * 40
            mutated_rule_sha256 = "f" * 64
            common.write_text(
                common.read_text(encoding="utf-8")
                .replace(
                    f'CRS_RELEASE_TAG="{current_tag}"',
                    f'CRS_RELEASE_TAG="{mutated_tag}"',
                )
                .replace(
                    f'CRS_APPROVED_COMMIT="{current_pins.commit}"',
                    f'CRS_APPROVED_COMMIT="{mutated_commit}"',
                )
                .replace(
                    f'CRS_RULE_FILE_SHA256="{current_pins.rule_file_sha256}"',
                    f'CRS_RULE_FILE_SHA256="{mutated_rule_sha256}"',
                ),
                encoding="utf-8",
            )
            self.assertEqual(self._run(root, "--check").returncode, 1)
            self.assertEqual(self._run(root, "--write").returncode, 0)
            self.assertEqual(self._run(root, "--check").returncode, 0)
            pins = load_crs_pins(common, root=root)
            for relative in FULL_CRS_SCHEMA_TARGETS:
                document = json.loads((root / relative).read_text(encoding="utf-8"))
                self.assertEqual(
                    document["properties"]["crs_release_tag"]["const"], pins.release_tag
                )
                self.assertEqual(
                    document["properties"]["crs_rule_file_sha256"]["const"],
                    pins.rule_file_sha256,
                )
            event = json.loads(
                (root / FULL_CRS_SCHEMA_TARGETS[0]).read_text(encoding="utf-8")
            )
            self.assertEqual(
                event["properties"]["crs_git_ref"]["const"], pins.release_tag
            )
            receipt = json.loads(
                (root / RECEIPT_SCHEMA_TARGET).read_text(encoding="utf-8")
            )
            self.assertEqual(receipt["properties"]["crs_commit"]["const"], pins.commit)
            self.assertIn(
                f"release_tag: {mutated_tag}",
                (root / FIXTURE_TARGET).read_text(encoding="utf-8"),
            )
            self.assertIn(
                f"rule_file_sha256: {mutated_rule_sha256}",
                (root / FIXTURE_TARGET).read_text(encoding="utf-8"),
            )

    def test_shell_expansion_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "ci/lib").mkdir(parents=True)
            self._copy_fixture(root)
            common = root / "ci/lib/common.sh"
            current_tag = load_crs_pins(common, root=root).release_tag
            common.write_text(
                common.read_text(encoding="utf-8").replace(
                    f'CRS_RELEASE_TAG="{current_tag}"',
                    'CRS_RELEASE_TAG="${CRS_RELEASE_TAG}"',
                ),
                encoding="utf-8",
            )
            result = self._run(root, "--check")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("semantic release tag", result.stderr)

    def test_rule_digest_is_required_and_strict(self) -> None:
        mutations = {
            "missing": ("", "missing CRS assignments"),
            "uppercase": (
                'CRS_RULE_FILE_SHA256="' + "F" * 64 + '"',
                "lowercase 64-character SHA-256",
            ),
            "short": (
                'CRS_RULE_FILE_SHA256="' + "a" * 63 + '"',
                "lowercase 64-character SHA-256",
            ),
            "duplicate": ("{line}\n{line}", "duplicate CRS assignment"),
        }
        for name, (replacement, expected) in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "ci/lib").mkdir(parents=True)
                self._copy_fixture(root)
                common = root / "ci/lib/common.sh"
                pins = load_crs_pins(common, root=root)
                line = f'CRS_RULE_FILE_SHA256="{pins.rule_file_sha256}"'
                rendered = replacement.format(line=line)
                common.write_text(
                    common.read_text(encoding="utf-8").replace(line, rendered),
                    encoding="utf-8",
                )
                result = self._run(root, "--check")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stderr)

    def test_non_ascii_release_tag_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "ci/lib").mkdir(parents=True)
            self._copy_fixture(root)
            common = root / "ci/lib/common.sh"
            current_tag = load_crs_pins(common, root=root).release_tag
            common.write_text(
                common.read_text(encoding="utf-8").replace(
                    f'CRS_RELEASE_TAG="{current_tag}"', 'CRS_RELEASE_TAG="v١.2.3"'
                ),
                encoding="utf-8",
            )
            result = self._run(root, "--check")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("semantic release tag", result.stderr)

    def test_repository_must_be_https_git_url(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "ci/lib").mkdir(parents=True)
            self._copy_fixture(root)
            common = root / "ci/lib/common.sh"
            pins = load_crs_pins(common, root=root)
            common.write_text(
                common.read_text(encoding="utf-8").replace(
                    f'CRS_APPROVED_REPO_URL="{pins.repository}"',
                    'CRS_APPROVED_REPO_URL="http://example.invalid/core.git"',
                ),
                encoding="utf-8",
            )
            result = self._run(root, "--check")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("HTTPS Git repository URL", result.stderr)

    def test_symlinked_common_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "ci/lib").mkdir(parents=True)
            self._copy_fixture(root)
            common = root / "ci/lib/common.sh"
            external = root / "external-common.sh"
            external.write_text(common.read_text(encoding="utf-8"), encoding="utf-8")
            common.unlink()
            os.symlink(external, common)
            result = self._run(root, "--check")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("symlinked framework path", result.stderr)

    def test_path_traversal_is_rejected_before_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "ci/lib").mkdir(parents=True)
            self._copy_fixture(root)
            outside = root.parent / "outside-common.sh"
            outside.write_text("untrusted\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "escapes framework root"):
                require_regular_file_within_root(root / ".." / outside.name, root)

    def test_symlinked_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "fixture"
            root.mkdir()
            (root / "ci/lib").mkdir(parents=True)
            self._copy_fixture(root)
            alias = Path(directory) / "root-alias"
            os.symlink(root, alias)
            result = self._run(alias, "--check")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "framework root must be a non-symlink directory", result.stderr
            )

    def test_symlinked_generated_parent_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "ci/lib").mkdir(parents=True)
            self._copy_fixture(root)
            shutil.rmtree(root / "tests")
            os.symlink(ROOT / "tests", root / "tests")
            result = self._run(root, "--check")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("symlinked framework path", result.stderr)


if __name__ == "__main__":
    unittest.main()
