from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
CLI_PATH = ROOT / "ci" / "tools" / "resolve-canonical-maintenance.py"
SPEC = importlib.util.spec_from_file_location(
    "resolve_canonical_maintenance_cli", CLI_PATH
)
assert SPEC is not None
assert SPEC.loader is not None
CLI = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CLI)


MANDATORY_SCOPES = {
    "go-ftw",
    "albedo",
    "python",
    "pyyaml",
    "node",
    "github-actions",
    "ci-security-tools",
}


class FakeOrchestrator:
    calls: list[tuple[Path, tuple[str, ...]]] = []
    applied: list[tuple[Path, str]] = []

    @staticmethod
    def build_plan(root: Path, *, components: tuple[str, ...], timeout: float) -> dict:
        FakeOrchestrator.calls.append((root, components))
        components_checked = [
            {
                "scope": scope,
                "component_name": scope,
                "current": "v1.0.0",
                "latest_compatible": "v1.0.0",
                "latest_upstream": "v1.0.0",
                "status": "current",
                "updates": [],
            }
            for scope in sorted(MANDATORY_SCOPES)
        ]
        components_checked.append(
            {
                "scope": "runtime",
                "component_name": "lighttpd",
                "current": "1.0.0",
                "latest_compatible": "1.1.0",
                "latest_upstream": "1.1.0",
                "status": "outdated",
                "updates": [
                    {"variable": "LIGHTTPD_VERSION", "old": "1.0.0", "new": "1.1.0"}
                ],
            }
        )
        return {
            "maintenance_outcome": "safe_updates_with_manual_review",
            "safe_updates": [
                {"variable": "LIGHTTPD_VERSION", "old": "1.0.0", "new": "1.1.0"}
            ],
            "manual_reviews": [
                {
                    "review_key": "go-ftw:major_version_transition:v3",
                    "reason": "review Go-FTW",
                }
            ],
            "checked_components": components_checked,
            "checked_global_components": sorted(MANDATORY_SCOPES),
            "checked_runtime_components": list(components) or ["lighttpd"],
            "plan_sha256": "a" * 64,
        }

    @staticmethod
    def render_plan_markdown(plan: dict) -> str:
        return (
            "\n".join(
                [
                    "# Canonical maintenance plan",
                    "",
                    "## Automatic updates",
                    "",
                    "- `LIGHTTPD_VERSION`",
                    "",
                    "## Manual reviews",
                    "",
                    "- `go-ftw:major_version_transition:v3`",
                ]
            )
            + "\n"
        )

    @staticmethod
    def apply_safe_updates(
        root: Path, plan: dict, *, expected_plan_sha256: str
    ) -> list[str]:
        FakeOrchestrator.applied.append((root, expected_plan_sha256))
        return ["ci/lib/common.sh"]


def _repo_root() -> Path:
    root = Path(tempfile.mkdtemp())
    (root / "ci" / "lib").mkdir(parents=True)
    (root / "ci" / "lib" / "common.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    return root


class ResolveCanonicalMaintenanceCliTests(unittest.TestCase):
    def setUp(self) -> None:
        FakeOrchestrator.calls.clear()
        FakeOrchestrator.applied.clear()

    def test_component_plan_retains_all_mandatory_global_scopes(self) -> None:
        root = _repo_root()
        plan_path = root / "plan.json"
        args = CLI.parse_args(
            ["--root", str(root), "--component", "lighttpd", "--plan", str(plan_path)]
        )
        with mock.patch.object(
            CLI, "_load_orchestrator", return_value=FakeOrchestrator
        ):
            self.assertEqual(CLI.run(args), 0)
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        self.assertEqual(set(plan["checked_global_components"]), MANDATORY_SCOPES)
        self.assertEqual(FakeOrchestrator.calls, [(root, ("lighttpd",))])

    def test_manual_review_does_not_hide_safe_runtime_update(self) -> None:
        root = _repo_root()
        output = root / "plan.md"
        args = CLI.parse_args(
            ["--root", str(root), "--component", "lighttpd", "--markdown", str(output)]
        )
        with mock.patch.object(
            CLI, "_load_orchestrator", return_value=FakeOrchestrator
        ):
            self.assertEqual(CLI.run(args), 0)
        rendered = output.read_text(encoding="utf-8")
        self.assertIn("LIGHTTPD_VERSION", rendered)
        self.assertIn("go-ftw:major_version_transition:v3", rendered)

    def test_reresolve_requires_the_caller_bound_plan_digest(self) -> None:
        root = _repo_root()
        plan_path = root / "plan.json"
        args = CLI.parse_args(
            [
                "--root",
                str(root),
                "--plan",
                str(plan_path),
                "--expected-plan-sha256",
                "b" * 64,
            ]
        )
        with mock.patch.object(
            CLI, "_load_orchestrator", return_value=FakeOrchestrator
        ):
            with self.assertRaisesRegex(CLI.CliError, "caller-bound SHA-256"):
                CLI.run(args)
        self.assertFalse(plan_path.exists())

    def test_apply_requires_digest_and_has_no_issue_mutation_surface(self) -> None:
        root = _repo_root()
        plan_path = root / "plan.json"
        plan_path.write_text("{}\n", encoding="utf-8")
        with self.assertRaises(SystemExit):
            CLI.parse_args(
                ["--root", str(root), "--plan", str(plan_path), "--apply-safe-updates"]
            )
        args = CLI.parse_args(
            [
                "--root",
                str(root),
                "--plan",
                str(plan_path),
                "--apply-safe-updates",
                "--expected-plan-sha256",
                "a" * 64,
            ]
        )
        with mock.patch.object(
            CLI, "_load_orchestrator", return_value=FakeOrchestrator
        ):
            self.assertEqual(CLI.run(args), 0)
        self.assertEqual(FakeOrchestrator.applied, [(root, "a" * 64)])
        self.assertFalse(hasattr(FakeOrchestrator, "create_issue"))

    def test_output_path_is_confined_and_atomic(self) -> None:
        root = _repo_root()
        with self.assertRaises(CLI.CliError):
            CLI._output_path("/tmp/outside-plan.json", root, label="--plan output")
        target = root / "atomic.json"
        CLI._atomic_write(target, b"{}\n")
        self.assertEqual(target.read_bytes(), b"{}\n")
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_nested_symlink_output_parent_is_rejected(self) -> None:
        root = _repo_root()
        outside = Path(tempfile.mkdtemp())
        (root / "generated").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(CLI.CliError, "symlink path component"):
            CLI._output_path("generated/nested/plan.json", root, label="--plan output")


if __name__ == "__main__":
    unittest.main()
