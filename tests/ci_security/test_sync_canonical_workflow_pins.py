from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "ci/tools/sync-canonical-workflow-pins.py"
spec = importlib.util.spec_from_file_location("canonical_workflow_pins", TOOL)
assert spec and spec.loader
MODULE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(MODULE)


class CanonicalWorkflowPinsTest(unittest.TestCase):
    def write_canonical_common(
        self, root: Path, overrides: dict[str, str] | None = None
    ) -> Path:
        values: dict[str, str] = {}
        for name in MODULE.canonical_names():
            if name.endswith("_REPOSITORY"):
                values[name] = "example/repository"
            elif name.endswith("_COMMIT"):
                values[name] = "a" * 40
            elif name.endswith("_SHA256"):
                values[name] = "b" * 64
            elif name.endswith("_SHA"):
                values[name] = "a" * 40
            elif name.endswith("_ASSET_NAME"):
                values[name] = "asset.tar.gz"
            elif name == "CI_CANONICAL_NODE_VERSION":
                values[name] = "24.18.0"
            elif name == "CI_CANONICAL_PYTHON_VERSION":
                values[name] = "3.14.6"
            else:
                values[name] = "v1.2.3"
        values.update(overrides or {})
        common = root / "ci/lib/common.sh"
        common.parent.mkdir(parents=True)
        common.write_text(
            "\n".join(f'{name}="{value}"' for name, value in values.items()) + "\n",
            encoding="utf-8",
        )
        return common

    def test_record_field_replacement_is_scoped_to_record(self) -> None:
        text = "actions:\n  a:\n    version: old\n  b:\n    version: keep\n"
        result = MODULE.replace_record_field(text, "actions", "a", "version", "new")
        self.assertIn("  a:\n    version: new", result)
        self.assertIn("  b:\n    version: keep", result)

    def test_workflow_generation_updates_pin_and_comment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workflow_dir = root / ".github/workflows"
            workflow_dir.mkdir(parents=True)
            workflow = workflow_dir / "test.yml"
            workflow.write_text(
                "steps:\n  - uses: actions/checkout@" + "0" * 40 + " # v0.0.0\n",
                encoding="utf-8",
            )
            values = {
                "CI_ACTION_CHECKOUT_REPOSITORY": "actions/checkout",
                "CI_ACTION_CHECKOUT_COMMIT": "a" * 40,
                "CI_ACTION_CHECKOUT_VERSION": "v7.0.1",
            }
            errors, outputs = MODULE.workflow_values(root, values, False)
            self.assertEqual(errors, [])
            self.assertEqual(len(outputs), 1)
            self.assertIn(
                "actions/checkout@" + "a" * 40 + " # v7.0.1", outputs[0][1].decode()
            )

    def test_unknown_remote_action_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workflow_dir = root / ".github/workflows"
            workflow_dir.mkdir(parents=True)
            (workflow_dir / "unknown.yml").write_text(
                "steps:\n  - uses: example/action@main\n", encoding="utf-8"
            )
            errors, _ = MODULE.workflow_values(root, {}, False)
            self.assertTrue(any("unknown or unsupported" in error for error in errors))

    def test_codeql_subaction_uses_repository_pin(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workflow_dir = root / ".github/workflows"
            workflow_dir.mkdir(parents=True)
            (workflow_dir / "codeql.yml").write_text(
                "steps:\n  - uses: github/codeql-action/init@"
                + "0" * 40
                + " # v0.0.0\n",
                encoding="utf-8",
            )
            values = {
                "CI_ACTION_CODEQL_REPOSITORY": "github/codeql-action",
                "CI_ACTION_CODEQL_COMMIT": "b" * 40,
                "CI_ACTION_CODEQL_VERSION": "v4.37.6",
            }
            errors, outputs = MODULE.workflow_values(root, values, False)
            self.assertEqual(errors, [])
            self.assertIn(
                "github/codeql-action/init@" + "b" * 40 + " # v4.37.6",
                outputs[0][1].decode(),
            )

    def test_canonical_common_is_parsed_without_executing_injected_command(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "unexpected-command-marker"
            self.write_canonical_common(
                root,
                {"CI_CANONICAL_NODE_VERSION": f"$(touch {marker})"},
            )
            with self.assertRaises(MODULE.PinError):
                MODULE.source_common(root)
            self.assertFalse(marker.exists())

    def test_asset_name_allows_only_its_own_version_expansion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_canonical_common(
                root,
                {
                    "CI_SECURITY_TOOL_SCORECARD_VERSION": "v5.5.0",
                    "CI_SECURITY_TOOL_SCORECARD_ASSET_NAME": "scorecard_${CI_SECURITY_TOOL_SCORECARD_VERSION#v}_linux_amd64.tar.gz",
                },
            )
            values = MODULE.source_common(root)
            self.assertEqual(
                values["CI_SECURITY_TOOL_SCORECARD_ASSET_NAME"],
                "scorecard_5.5.0_linux_amd64.tar.gz",
            )

    def test_asset_name_rejects_an_unapproved_expansion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_canonical_common(
                root,
                {"CI_SECURITY_TOOL_SCORECARD_ASSET_NAME": "$CI_CANONICAL_NODE_VERSION"},
            )
            with self.assertRaises(MODULE.PinError):
                MODULE.source_common(root)

    def test_node_version_is_generated_from_the_canonical_literal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workflow_dir = root / ".github/workflows"
            workflow_dir.mkdir(parents=True)
            (workflow_dir / "node.yml").write_text(
                "steps:\n"
                "  - uses: actions/setup-node@" + "0" * 40 + " # v0.0.0\n"
                "    with:\n"
                '      node-version: "0.0.0"\n',
                encoding="utf-8",
            )
            values = {
                "CI_ACTION_SETUP_NODE_REPOSITORY": "actions/setup-node",
                "CI_ACTION_SETUP_NODE_COMMIT": "c" * 40,
                "CI_ACTION_SETUP_NODE_VERSION": "v7.0.0",
                "CI_CANONICAL_NODE_VERSION": "24.18.0",
            }
            errors, outputs = MODULE.workflow_values(root, values, False)
            self.assertEqual(errors, [])
            output = outputs[0][1].decode()
            self.assertIn("actions/setup-node@" + "c" * 40 + " # v7.0.0", output)
            self.assertIn('node-version: "24.18.0"', output)

    def test_osv_legacy_compatibility_tuple_is_generated_from_common(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workflow_dir = root / ".github/workflows"
            workflow_dir.mkdir(parents=True)
            (workflow_dir / "ci-security-osv.yml").write_text(
                "jobs:\n  pull-request-head:\n    steps:\n      - env:\n"
                "          OSV_LEGACY_BASE_SHA: " + "0" * 40 + "\n"
                "          OSV_LEGACY_BASE_VERSION: 0.0.0\n",
                encoding="utf-8",
            )
            values = {
                "CI_OSV_LEGACY_BASE_SHA": "a" * 40,
                "CI_OSV_LEGACY_BASE_VERSION": "3.13.14",
            }
            errors, outputs = MODULE.workflow_values(root, values, False)
            self.assertEqual(errors, [])
            output = outputs[0][1].decode()
            self.assertIn("OSV_LEGACY_BASE_SHA: " + "a" * 40, output)
            self.assertIn("OSV_LEGACY_BASE_VERSION: 3.13.14", output)

    def test_write_validates_unknown_action_before_writing_generated_drift(
        self,
    ) -> None:
        """An invalid workflow must not leave a partially regenerated checkout."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = [
                root / "ci/tooling/security-tools.lock.yml",
                root / ".github/workflows/unknown.yml",
                root / "docs/github-actions-workflow-security.md",
                root / "docs/github-actions-workflow-security.de.md",
            ]
            for path in paths:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"original\n")
            generated = [(paths[1], b"generated\n")]
            documentation = [(paths[2], b"generated\n"), (paths[3], b"generated\n")]
            with (
                mock.patch.object(MODULE, "source_common", return_value={}),
                mock.patch.object(MODULE, "lock_values", return_value=b"generated\n"),
                mock.patch.object(
                    MODULE,
                    "workflow_values",
                    return_value=(
                        ["unknown or unsupported remote Action example/action@main"],
                        generated,
                    ),
                ),
                mock.patch.object(
                    MODULE, "documentation_values", return_value=documentation
                ),
            ):
                result = MODULE.main(["--write", "--root", str(root)])
            self.assertEqual(result, 2)
            self.assertEqual(
                [path.read_bytes() for path in paths], [b"original\n"] * len(paths)
            )

    def test_write_rejects_symlinked_generated_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = root / "ci/tooling/security-tools.lock.yml"
            outside = root.parent / "workflow-pins-outside.yml"
            lock.parent.mkdir(parents=True)
            outside.write_bytes(b"outside\n")
            lock.symlink_to(outside)
            with self.assertRaises(MODULE.PinError):
                MODULE.validate_managed_path(root, lock)
            outside.unlink()


if __name__ == "__main__":
    unittest.main()
