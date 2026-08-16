"""Focused no-network tests for the shared canonical maintenance resolver."""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "canonical_maintenance_test_target", ROOT / "ci/tools/canonical_maintenance.py"
)
assert SPEC is not None
assert SPEC.loader is not None
MAINTENANCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MAINTENANCE)


def entries(values: dict[str, str]) -> dict[str, SimpleNamespace]:
    return {name: SimpleNamespace(resolved=value) for name, value in values.items()}


class FakeChecker:
    class UpstreamError(RuntimeError):
        pass

    class UpstreamBlocked(RuntimeError):
        pass

    class UpstreamUnknown(RuntimeError):
        pass

    def __init__(self, commits: dict[str, str]) -> None:
        self.commits = commits

    def resolve_github_peeled_commit(
        self, _client: object, _repository: str, tag: str
    ) -> str:
        return self.commits[tag]


class FakeListClient:
    def __init__(self, releases: list[dict[str, object]]) -> None:
        self.releases = releases

    def get_json_list(self, _url: str) -> list[dict[str, object]]:
        return self.releases


class FakePyPiClient:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload

    def get_json(self, _url: str) -> dict[str, object]:
        return self.payload


class CanonicalMaintenanceTests(unittest.TestCase):
    def test_go_ftw_ignores_drafts_and_keeps_derived_aliases_out_of_updates(
        self,
    ) -> None:
        current_commit = "a" * 40
        patch_commit = "b" * 40
        major_commit = "c" * 40
        checker = FakeChecker(
            {"v2.2.0": current_commit, "v2.2.1": patch_commit, "v3.0.0": major_commit}
        )
        client = FakeListClient(
            [
                {"tag_name": "v2.2.1", "draft": False, "prerelease": False},
                {"tag_name": "v2.2.2", "draft": True, "prerelease": False},
                {"tag_name": "v2.3.0-rc.1", "draft": False, "prerelease": True},
                {"tag_name": "v3.0.0", "draft": False, "prerelease": False},
            ]
        )
        result, reviews = MAINTENANCE.resolve_git_release_component(
            checker,
            client,
            entries(
                {
                    "GO_FTW_SOURCE_URL": "https://github.com/coreruleset/go-ftw",
                    "GO_FTW_RELEASE_TAG": "v2.2.0",
                    "GO_FTW_GIT_REF": "v2.2.0",
                    "GO_FTW_PROMPT_EXPECTED_LATEST": "v2.2.0",
                    "GO_FTW_APPROVED_COMMIT": current_commit,
                }
            ),
            component_id="go-ftw",
            component_name="Go-FTW",
            source_variable="GO_FTW_SOURCE_URL",
            tag_variable="GO_FTW_RELEASE_TAG",
            ref_variable="GO_FTW_GIT_REF",
            commit_variable="GO_FTW_APPROVED_COMMIT",
            aliases=("GO_FTW_PROMPT_EXPECTED_LATEST",),
            automatic_policy="same_major",
        )
        self.assertEqual(result["status"], "outdated")
        self.assertEqual(
            result["updates"],
            [
                {"variable": "GO_FTW_RELEASE_TAG", "old": "v2.2.0", "new": "v2.2.1"},
                {
                    "variable": "GO_FTW_APPROVED_COMMIT",
                    "old": current_commit,
                    "new": patch_commit,
                },
            ],
        )
        self.assertEqual(
            reviews[0]["review_key"], "go-ftw:major_version_transition:3.0"
        )
        self.assertTrue(reviews[0]["automatic_update_also_available"])

    def test_albedo_zero_minor_transition_is_a_review_with_safe_patch(self) -> None:
        commits = {"v0.3.0": "a" * 40, "v0.3.1": "b" * 40, "v0.4.0": "c" * 40}
        result, reviews = MAINTENANCE.resolve_git_release_component(
            FakeChecker(commits),
            FakeListClient(
                [
                    {"tag_name": tag, "draft": False, "prerelease": False}
                    for tag in commits
                ]
            ),
            entries(
                {
                    "ALBEDO_SOURCE_URL": "https://github.com/coreruleset/albedo",
                    "ALBEDO_RELEASE_TAG": "v0.3.0",
                    "ALBEDO_GIT_REF": "v0.3.0",
                    "ALBEDO_PROMPT_EXPECTED_LATEST": "v0.3.0",
                    "ALBEDO_APPROVED_COMMIT": commits["v0.3.0"],
                }
            ),
            component_id="albedo",
            component_name="Albedo",
            source_variable="ALBEDO_SOURCE_URL",
            tag_variable="ALBEDO_RELEASE_TAG",
            ref_variable="ALBEDO_GIT_REF",
            commit_variable="ALBEDO_APPROVED_COMMIT",
            aliases=("ALBEDO_PROMPT_EXPECTED_LATEST",),
            automatic_policy="zero_same_minor",
        )
        self.assertEqual(result["updates"][0]["new"], "v0.3.1")
        self.assertEqual(reviews[0]["review_kind"], "minor_version_transition")
        self.assertEqual(reviews[0]["candidate_identity"]["tag"], "v0.4.0")

    def test_pyyaml_update_is_an_atomic_artifact_platform_digest_tuple(self) -> None:
        current_wheel = (
            "pyyaml-6.0.3-cp314-cp314-"
            "manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl"
        )
        candidate_wheel = current_wheel.replace("6.0.3", "6.0.4")
        payload: dict[str, object] = {
            "releases": {
                "6.0.3": [{"filename": current_wheel, "digests": {"sha256": "a" * 64}}],
                "6.0.4": [
                    {"filename": candidate_wheel, "digests": {"sha256": "b" * 64}}
                ],
            }
        }
        result, reviews = MAINTENANCE.resolve_pyyaml(
            entries(
                {
                    "CI_CANONICAL_PYTHON_VERSION": "3.14.6",
                    "CI_CANONICAL_PYYAML_VERSION": "6.0.3",
                    "CI_CANONICAL_PYYAML_ARTIFACT": current_wheel,
                    "CI_CANONICAL_PYYAML_PLATFORM": current_wheel.removesuffix(
                        ".whl"
                    ).rsplit("-", 1)[-1],
                    "CI_CANONICAL_PYYAML_SHA256": "a" * 64,
                }
            ),
            FakePyPiClient(payload),
        )
        self.assertEqual(result["status"], "outdated")
        self.assertEqual(
            {update["variable"] for update in result["updates"]},
            {
                "CI_CANONICAL_PYYAML_VERSION",
                "CI_CANONICAL_PYYAML_ARTIFACT",
                "CI_CANONICAL_PYYAML_PLATFORM",
                "CI_CANONICAL_PYYAML_SHA256",
            },
        )
        self.assertEqual(reviews, [])

    def test_dynamic_ci_group_coverage_rejects_an_incomplete_tool_tuple(self) -> None:
        def resolve_groups() -> object:
            return MAINTENANCE._groups(
                entries(
                    {
                        "CI_SECURITY_TOOL_EXAMPLE_REPOSITORY": "owner/example",
                        "CI_SECURITY_TOOL_EXAMPLE_VERSION": "v1.0.0",
                    }
                ),
                MAINTENANCE.TOOL_GROUP_RE,
                {"REPOSITORY", "VERSION", "COMMIT", "ASSET_NAME", "SHA256"},
                "CI_SECURITY_TOOL_",
            )

        with self.assertRaises(MAINTENANCE.MaintenanceError):
            resolve_groups()

    def test_derived_ci_tool_asset_is_rechecked_after_its_version_change(self) -> None:
        checker = MAINTENANCE.load_runtime_checker(ROOT)
        lines = [
            'CI_SECURITY_TOOL_SCORECARD_VERSION="v1.0.0"',
            'CI_SECURITY_TOOL_SCORECARD_ASSET_NAME="scorecard_${CI_SECURITY_TOOL_SCORECARD_VERSION#v}_linux_amd64.tar.gz"',
        ]
        parsed = checker.parse_common_lines(lines)
        candidate = MAINTENANCE._candidate_entries_after_updates(
            checker,
            lines,
            parsed,
            [
                {
                    "variable": "CI_SECURITY_TOOL_SCORECARD_VERSION",
                    "old": "v1.0.0",
                    "new": "v1.0.1",
                }
            ],
        )
        self.assertEqual(
            candidate["CI_SECURITY_TOOL_SCORECARD_ASSET_NAME"].resolved,
            "scorecard_1.0.1_linux_amd64.tar.gz",
        )

    def test_require_root_rejects_a_symlinked_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            real_root = parent / "real"
            common = real_root / "ci/lib/common.sh"
            common.parent.mkdir(parents=True)
            common.write_text(
                'CI_CANONICAL_PYTHON_VERSION="3.14.6"\n', encoding="utf-8"
            )
            symlink_root = parent / "linked"
            symlink_root.symlink_to(real_root, target_is_directory=True)
            with self.assertRaisesRegex(MAINTENANCE.MaintenanceError, "symlink"):
                MAINTENANCE.require_root(symlink_root)

    def test_apply_safe_updates_rolls_back_on_generated_view_failure(self) -> None:
        class ApplyChecker:
            class UpdateChange:
                def __init__(self, **kwargs: object) -> None:
                    self.__dict__.update(kwargs)

            @staticmethod
            def parse_common(
                _path: Path,
            ) -> tuple[list[str], dict[str, SimpleNamespace]]:
                return ["PIN=old"], {"PIN": SimpleNamespace(default="old", line=1)}

            @staticmethod
            def apply_updates(
                path: Path, _lines: list[str], _changes: list[object]
            ) -> None:
                path.write_bytes(b"PIN=new\n")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            common = root / "ci/lib/common.sh"
            for relative in MAINTENANCE.ALLOWED_AUTOMATIC_PATHS:
                (root / relative).parent.mkdir(parents=True, exist_ok=True)
            common.write_bytes(b"PIN=old\n")
            subprocess.run(["git", "init", "--quiet"], cwd=root, check=True)
            subprocess.run(["git", "add", "ci/lib/common.sh"], cwd=root, check=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=Canonical Test",
                    "-c",
                    "user.email=canonical-test@example.invalid",
                    "commit",
                    "--quiet",
                    "-m",
                    "initial",
                ],
                cwd=root,
                check=True,
            )
            plan = {
                "maintenance_outcome": "safe_updates",
                "safe_updates": [{"variable": "PIN", "old": "old", "new": "new"}],
                "source_common_sha256": hashlib.sha256(b"PIN=old\n").hexdigest(),
                "candidate_common_sha256": hashlib.sha256(b"PIN=new\n").hexdigest(),
            }
            plan["plan_sha256"] = hashlib.sha256(
                MAINTENANCE._canonical_json(plan)
            ).hexdigest()
            with (
                mock.patch.object(
                    MAINTENANCE, "load_runtime_checker", return_value=ApplyChecker
                ),
                mock.patch.object(
                    MAINTENANCE,
                    "generated_view_status",
                    return_value=[{"name": "generated", "status": "blocked"}],
                ),
            ):
                with self.assertRaisesRegex(
                    MAINTENANCE.MaintenanceError, "generated-view synchronization"
                ):
                    MAINTENANCE.apply_safe_updates(
                        root,
                        plan,
                        expected_plan_sha256=plan["plan_sha256"],
                    )
            self.assertEqual(common.read_bytes(), b"PIN=old\n")
            self.assertEqual(
                subprocess.run(
                    ["git", "status", "--porcelain=v1"],
                    cwd=root,
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout,
                "",
            )

    def test_ci_tool_provider_transition_is_classified_before_release_lookup(
        self,
    ) -> None:
        updater = SimpleNamespace(
            release_identity=lambda _record, _name: SimpleNamespace(
                slug="ossf/scorecard"
            )
        )
        identity, transition = MAINTENANCE._tool_provider_identity(
            updater,
            {
                "name": "scorecard",
                "repository": "ossf/scorecard",
                "version": "v5.5.0",
                "upstream_release": "https://github.com/ossf/scorecard/releases/tag/v5.5.0",
            },
            "scorecard",
            "attacker/scorecard",
        )
        self.assertEqual(identity.slug, "ossf/scorecard")
        self.assertTrue(transition)


if __name__ == "__main__":
    unittest.main()
