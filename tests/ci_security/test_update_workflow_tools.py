"""Regression tests for the constrained Framework workflow/tool updater."""

from __future__ import annotations

import base64
import contextlib
from copy import deepcopy
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Any
import unittest
from unittest.mock import Mock, call, patch
from urllib.request import Request


ROOT = Path(__file__).resolve().parents[2]
UPDATER_PATH = ROOT / "ci/tools/update-workflow-tools.py"


def load_updater():
    spec = importlib.util.spec_from_file_location("update_workflow_tools", UPDATER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {UPDATER_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


UPDATER = load_updater()


class WorkflowToolUpdaterTests(unittest.TestCase):
    def test_github_api_token_is_optional_and_scoped_to_fixed_api_origin(self) -> None:
        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *args: object) -> None:
                return None

            def geturl(self) -> str:
                return "https://api.github.com/repos/example/project/releases/latest"

            @staticmethod
            def read() -> bytes:
                return b'{"ok": true}'

        class Opener:
            def __init__(self) -> None:
                self.request: Request | None = None

            def open(self, request: Request, timeout: int) -> Response:
                del timeout
                self.request = request
                return Response()

        path = "/repos/example/project/releases/latest"
        for token in (None, "test-token"):
            with self.subTest(token_present=token is not None):
                opener = Opener()
                with patch.object(UPDATER, "GITHUB_API_OPENER", opener):
                    with patch.dict(
                        os.environ,
                        {} if token is None else {"GITHUB_TOKEN": token},
                        clear=True,
                    ):
                        self.assertEqual(UPDATER.github_payload(path), {"ok": True})
                assert opener.request is not None
                headers = opener.request.headers
                self.assertEqual(headers.get("X-github-api-version"), "2022-11-28")
                if token is None:
                    self.assertNotIn("Authorization", headers)
                else:
                    self.assertEqual(headers.get("Authorization"), f"Bearer {token}")

    def test_github_api_rejects_redirected_or_foreign_final_url(self) -> None:
        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *args: object) -> None:
                return None

            def geturl(self) -> str:
                return "https://evil.example/collect"

            def read(self) -> bytes:
                raise AssertionError("redirected response must not be read")

        class Opener:
            def open(self, request: object, timeout: int) -> Response:
                del request, timeout
                return Response()

        with (
            patch.object(UPDATER, "GITHUB_API_OPENER", Opener()),
            patch.dict(os.environ, {"GITHUB_TOKEN": "must-not-leak"}, clear=True),
        ):
            with self.assertRaisesRegex(UPDATER.UpdateError, "redirect|final URL"):
                UPDATER.github_payload("/repos/example/project/releases/latest")

    def test_github_api_rejects_control_characters_in_token_without_echoing_it(
        self,
    ) -> None:
        opener = Mock()
        unsafe_token = "test-token\r\nX-Injected: value"
        with (
            patch.object(UPDATER, "GITHUB_API_OPENER", opener),
            patch.dict(os.environ, {"GITHUB_TOKEN": unsafe_token}, clear=True),
        ):
            with self.assertRaises(UPDATER.UpdateError) as captured:
                UPDATER.github_payload("/repos/example/project/releases/latest")
        self.assertIn("prohibited control characters", str(captured.exception))
        self.assertNotIn(unsafe_token, str(captured.exception))
        opener.open.assert_not_called()

    def test_github_api_rejects_non_repository_paths_before_opening(self) -> None:
        opener = Mock()
        with patch.object(UPDATER, "GITHUB_API_OPENER", opener):
            for path in (
                "https://evil.example/repos/example/project",
                "/repository/example/project",
                "/repos/../evil/project",
                "/repos/example/project?unexpected=true",
                "/repos/example/project#fragment",
                "/repos/example/project;param",
            ):
                with self.subTest(path=path):
                    with self.assertRaisesRegex(
                        UPDATER.UpdateError, "repository-scoped"
                    ):
                        UPDATER.github_payload(path)
        opener.open.assert_not_called()

    def test_github_api_transport_never_follows_redirects(self) -> None:
        handler = UPDATER.NoRedirectHandler()
        request = UPDATER.Request("https://api.github.com/repos/example/project")
        self.assertIsNone(
            handler.redirect_request(
                request, None, 302, "Found", {}, "https://evil.example"
            )
        )

    def test_current_tool_pins_have_explicit_provider_identity(self) -> None:
        _path, lock, _digest = UPDATER.load_lock(ROOT)
        for name, record in lock["tools"].items():
            self.assertEqual(
                record["repository"], UPDATER.release_identity(record, name).slug
            )

    def test_provider_transition_is_rejected_before_resolution(self) -> None:
        _path, lock, _digest = UPDATER.load_lock(ROOT)
        record = deepcopy(lock["tools"]["scorecard"])
        record["repository"] = "attacker/scorecard"
        with self.assertRaisesRegex(UPDATER.UpdateError, "provider|repository"):
            UPDATER.validate_tool_lock_records({"tools": {"scorecard": record}})

    def copied_update_root(self, temporary_root: Path) -> Path:
        destination = temporary_root / "framework"
        for relative_text in UPDATER.PROPOSED_VALIDATION_INPUT_PATHS:
            relative = Path(relative_text)
            source = ROOT / relative
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        return destination

    @staticmethod
    def changed_action(
        lock: dict[str, Any], name: str, version: str, sha: str
    ) -> dict[str, str]:
        record = lock["actions"][name]
        upstream = UPDATER.release_identity(record, name)
        return {
            "version": version,
            "immutable_commit": sha,
            "upstream_release": UPDATER.release_url(upstream, version),
        }

    def candidate_for(
        self,
        root: Path,
        actions: dict[str, dict[str, str]] | None = None,
        *,
        tools: dict[str, dict[str, str]] | None = None,
    ) -> dict[str, object]:
        _path, _lock, digest = UPDATER.load_lock(root)
        return {
            "schema_version": UPDATER.CANDIDATE_SCHEMA_VERSION,
            "lock_sha256": digest,
            "actions": {} if actions is None else actions,
            "tools": {} if tools is None else tools,
        }

    def native_subset_blob_fixture(
        self, temporary_root: Path
    ) -> tuple[bytes, dict[str, Any], dict[str, Any], dict[tuple[str, str], bytes]]:
        base_lock_blob = (ROOT / "ci/tooling/security-tools.lock.yml").read_bytes()
        base_lock = UPDATER.yaml.safe_load(base_lock_blob)
        checkout = self.changed_action(
            base_lock, "actions/checkout", "v9.9.9", "a" * 40
        )
        candidate = self.candidate_for(ROOT, {"actions/checkout": checkout})
        expected_root = self.copied_update_root(temporary_root / "expected")
        UPDATER.apply_candidate(expected_root, candidate)
        head_lock = UPDATER.yaml.safe_load(
            (expected_root / "ci/tooling/security-tools.lock.yml").read_text(
                encoding="utf-8"
            )
        )
        blobs = {
            ("base", relative_text): (ROOT / relative_text).read_bytes()
            for relative_text in UPDATER.ALLOWED_UPDATE_PATHS
        }
        blobs.update(
            {
                ("head", relative_text): (expected_root / relative_text).read_bytes()
                for relative_text in UPDATER.ALLOWED_UPDATE_PATHS
            }
        )
        return base_lock_blob, base_lock, head_lock, blobs

    def test_resolver_uses_only_release_and_tag_identity(self) -> None:
        _path, lock, _digest = UPDATER.load_lock(ROOT)
        record = lock["actions"]["actions/checkout"]
        with (
            patch.object(
                UPDATER,
                "latest_release",
                return_value={
                    "tag_name": "v9.9.9",
                    "draft": False,
                    "prerelease": False,
                },
            ),
            patch.object(UPDATER, "release_tag_commit", return_value="a" * 40),
        ):
            candidate = UPDATER.action_candidate("actions/checkout", record)

        self.assertEqual(
            candidate,
            {
                "version": "v9.9.9",
                "immutable_commit": "a" * 40,
                "upstream_release": "https://github.com/actions/checkout/releases/tag/v9.9.9",
            },
        )

    def test_codeql_resolver_selects_only_the_latest_same_major_action_release(
        self,
    ) -> None:
        _path, lock, _digest = UPDATER.load_lock(ROOT)
        record = lock["actions"]["github/codeql-action"]
        releases = [
            {
                "tag_name": "codeql-bundle-v2.26.1",
                "draft": False,
                "prerelease": False,
            },
            {
                "tag_name": "v4.38.0",
                "draft": False,
                "prerelease": False,
                "target_commitish": "main",
            },
            {
                "tag_name": "v4.38.0.1",
                "draft": False,
                "prerelease": False,
            },
            {
                "tag_name": "v4.39.0-rc.1",
                "draft": False,
                "prerelease": True,
            },
            {
                "tag_name": "v5.0.0",
                "draft": False,
                "prerelease": False,
            },
        ]
        with (
            patch.object(UPDATER, "release_page", return_value=releases),
            patch.object(
                UPDATER,
                "latest_release",
                side_effect=AssertionError("CodeQL must not use releases/latest"),
            ),
            patch.object(
                UPDATER,
                "release_by_tag",
                return_value={
                    "tag_name": "v4.38.0",
                    "draft": False,
                    "prerelease": False,
                    "immutable": True,
                    "target_commitish": "main",
                },
            ),
            patch.object(UPDATER, "release_tag_commit", return_value="a" * 40),
        ):
            candidate = UPDATER.action_candidate("github/codeql-action", record)
            upstream = UPDATER.latest_stable_action_release(
                UPDATER.release_identity(record, "github/codeql-action")
            )

        self.assertEqual(
            candidate,
            {
                "version": "v4.38.0",
                "immutable_commit": "a" * 40,
                "upstream_release": "https://github.com/github/codeql-action/releases/tag/v4.38.0",
            },
        )
        self.assertEqual(upstream["tag_name"], "v5.0.0")

    def test_codeql_resolver_rejects_unrelated_bundle_or_major_releases(self) -> None:
        _path, lock, _digest = UPDATER.load_lock(ROOT)
        record = lock["actions"]["github/codeql-action"]
        releases = [
            {
                "tag_name": "codeql-bundle-v2.26.1",
                "draft": False,
                "prerelease": False,
            },
            {
                "tag_name": "v5.0.0",
                "draft": False,
                "prerelease": False,
            },
            {
                "tag_name": "v4.38",
                "draft": False,
                "prerelease": False,
            },
            {
                "tag_name": "v4.38.0.1",
                "draft": False,
                "prerelease": False,
            },
        ]
        with patch.object(UPDATER, "release_page", return_value=releases):
            with self.assertRaisesRegex(UPDATER.UpdateError, "reviewed major"):
                UPDATER.action_candidate("github/codeql-action", record)

    def test_codeql_release_resolution_is_runtime_bound(self) -> None:
        _path, lock, _digest = UPDATER.load_lock(ROOT)
        record = dict(lock["actions"]["github/codeql-action"])
        record["release_resolution"] = "latest-release"

        with self.assertRaisesRegex(UPDATER.UpdateError, "same-major-release"):
            UPDATER.action_release_resolution(record, "github/codeql-action")

    def test_codeql_resolver_requires_an_immutable_confirmed_action_release(
        self,
    ) -> None:
        _path, lock, _digest = UPDATER.load_lock(ROOT)
        record = lock["actions"]["github/codeql-action"]
        release = {
            "tag_name": "v4.38.0",
            "draft": False,
            "prerelease": False,
        }
        with (
            patch.object(UPDATER, "release_page", return_value=[release]),
            patch.object(
                UPDATER, "release_by_tag", return_value={**release, "immutable": False}
            ),
        ):
            with self.assertRaisesRegex(UPDATER.UpdateError, "must be immutable"):
                UPDATER.action_candidate("github/codeql-action", record)

    def test_codeql_resolver_rechecks_the_selected_release_object(self) -> None:
        _path, lock, _digest = UPDATER.load_lock(ROOT)
        record = lock["actions"]["github/codeql-action"]
        page_release = {
            "tag_name": "v4.38.0",
            "draft": False,
            "prerelease": False,
        }
        confirmations = {
            "draft": {
                "tag_name": "v4.38.0",
                "draft": True,
                "prerelease": False,
                "immutable": True,
            },
            "tag-mismatch": {
                "tag_name": "v4.38.1",
                "draft": False,
                "prerelease": False,
                "immutable": True,
            },
        }
        for name, confirmation in confirmations.items():
            with self.subTest(name=name):
                with (
                    patch.object(UPDATER, "release_page", return_value=[page_release]),
                    patch.object(UPDATER, "release_by_tag", return_value=confirmation),
                ):
                    with self.assertRaisesRegex(
                        UPDATER.UpdateError, "published non-prerelease|does not match"
                    ):
                        UPDATER.action_candidate("github/codeql-action", record)

    def test_codeql_annotated_tag_resolves_to_the_locked_commit(self) -> None:
        _path, lock, _digest = UPDATER.load_lock(ROOT)
        record = lock["actions"]["github/codeql-action"]
        identity = UPDATER.release_identity(record, "github/codeql-action")
        tag_object = "bb16b9baa2ec4010b29f5c606d57d01190139edd"
        expected_commit = record["immutable_commit"]
        with patch.object(
            UPDATER,
            "github_json",
            side_effect=[
                {"object": {"type": "tag", "sha": tag_object}},
                {"object": {"type": "commit", "sha": expected_commit}},
            ],
        ) as github_json:
            commit = UPDATER.release_tag_commit(identity, "v4.37.1")

        self.assertEqual(expected_commit, commit)
        self.assertEqual(
            github_json.call_args_list,
            [
                call("/repos/github/codeql-action/git/ref/tags/v4.37.1"),
                call(f"/repos/github/codeql-action/git/tags/{tag_object}"),
            ],
        )

    def test_codeql_candidate_rejects_a_major_upgrade(self) -> None:
        _path, lock, digest = UPDATER.load_lock(ROOT)
        candidate = self.candidate_for(
            ROOT,
            {
                "github/codeql-action": self.changed_action(
                    lock, "github/codeql-action", "v5.0.0", "a" * 40
                )
            },
        )
        with self.assertRaisesRegex(UPDATER.UpdateError, "reviewed major"):
            UPDATER.validate_candidate_shape(candidate, lock, digest)

    def test_resolver_rejects_preview_release_flags_and_tags(self) -> None:
        _path, lock, _digest = UPDATER.load_lock(ROOT)
        action = lock["actions"]["actions/checkout"]
        tool = lock["tools"]["actionlint"]
        releases = (
            {"tag_name": "v9.9.9", "draft": True, "prerelease": False},
            {"tag_name": "v9.9.9", "draft": False, "prerelease": True},
            {"tag_name": "v9.9.9-rc.1", "draft": False, "prerelease": False},
            {"tag_name": "v9.9.9-beta", "draft": False, "prerelease": False},
            {"tag_name": "v9.9.9-dev", "draft": False, "prerelease": False},
        )
        for release in releases:
            with self.subTest(release=release):
                with patch.object(UPDATER, "latest_release", return_value=release):
                    with self.assertRaisesRegex(UPDATER.UpdateError, "release|stable"):
                        UPDATER.action_candidate("actions/checkout", action)
                    with self.assertRaisesRegex(UPDATER.UpdateError, "release|stable"):
                        UPDATER.tool_candidate("actionlint", tool)

    def test_candidate_rejects_unapproved_fields_and_stale_lock_digest(self) -> None:
        _path, lock, digest = UPDATER.load_lock(ROOT)
        valid = self.changed_action(lock, "actions/checkout", "v9.9.9", "a" * 40)
        candidate = self.candidate_for(
            ROOT, {"actions/checkout": {**valid, "license": "untrusted"}}
        )
        with self.assertRaisesRegex(UPDATER.UpdateError, "unapproved field"):
            UPDATER.validate_candidate_shape(candidate, lock, digest)

        candidate["actions"] = {"actions/checkout": valid}
        candidate["lock_sha256"] = "0" * 64
        with self.assertRaisesRegex(UPDATER.UpdateError, "current trusted lock"):
            UPDATER.validate_candidate_shape(candidate, lock, digest)

    def test_candidate_identity_digest_and_required_update_gate_are_fail_closed(
        self,
    ) -> None:
        candidate = self.candidate_for(ROOT, {})
        digest = UPDATER.candidate_sha256(candidate)
        canonical_bytes = UPDATER.canonical_candidate_bytes(candidate)

        self.assertEqual(
            UPDATER.canonical_candidate(candidate).encode("utf-8"),
            canonical_bytes,
        )
        self.assertEqual(
            base64.b64decode(UPDATER.candidate_b64(candidate)), canonical_bytes
        )
        self.assertEqual(hashlib.sha256(canonical_bytes).hexdigest(), digest)
        self.assertEqual(digest, UPDATER.candidate_sha256(deepcopy(candidate)))
        UPDATER.require_candidate_sha256(candidate, digest)
        UPDATER.require_candidate_sha256(candidate, None)
        uppercase_digest = digest.upper()
        with self.assertRaisesRegex(UPDATER.UpdateError, "lowercase digest"):
            UPDATER.require_candidate_sha256(candidate, uppercase_digest)
        with self.assertRaisesRegex(
            UPDATER.UpdateError, "does not match the resolver result"
        ):
            UPDATER.require_candidate_sha256(candidate, "0" * 64)

        empty_changes = {"actions": {}, "tools": {}}
        UPDATER.require_candidate_updates(empty_changes, False)
        with self.assertRaisesRegex(UPDATER.UpdateError, "must contain"):
            UPDATER.require_candidate_updates(empty_changes, True)
        UPDATER.require_candidate_updates(
            {"actions": {"actions/checkout": {}}, "tools": {}}, True
        )

    def test_resolve_github_output_binds_payload_digest_and_update_state(self) -> None:
        candidate = self.candidate_for(ROOT, {})
        output = io.StringIO()
        args = UPDATER.argparse.Namespace(root=ROOT, github_output=True)

        with (
            patch.object(UPDATER, "resolve_candidate", return_value=candidate),
            contextlib.redirect_stdout(output),
        ):
            UPDATER.run_resolve_command(args)

        values = dict(
            line.split("=", 1) for line in output.getvalue().splitlines() if "=" in line
        )
        self.assertEqual(values["resolver_status"], "resolved")
        self.assertEqual(values["candidate_b64"], UPDATER.candidate_b64(candidate))
        self.assertEqual(
            values["candidate_sha256"], UPDATER.candidate_sha256(candidate)
        )
        self.assertEqual(values["has_updates"], "false")

    def test_apply_changes_only_lock_pins_and_paired_documentation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.copied_update_root(Path(temporary_directory))
            _path, lock, _digest = UPDATER.load_lock(root)
            checkout = self.changed_action(lock, "actions/checkout", "v9.9.9", "a" * 40)
            python = self.changed_action(
                lock, "actions/setup-python", "v9.9.8", "b" * 40
            )
            candidate = self.candidate_for(
                root,
                {
                    "actions/checkout": checkout,
                    "actions/setup-python": python,
                },
            )

            changed = UPDATER.apply_candidate(root, candidate)

            self.assertIn("ci/tooling/security-tools.lock.yml", changed)
            self.assertIn("docs/github-actions-workflow-security.md", changed)
            self.assertIn("docs/github-actions-workflow-security.de.md", changed)
            self.assertTrue(
                all(path in UPDATER.ALLOWED_UPDATE_PATHS for path in changed)
            )
            workflow_text = (
                root / ".github/workflows/check-action-versions.yml"
            ).read_text(encoding="utf-8")
            self.assertIn(f"actions/checkout@{'a' * 40} # v9.9.9", workflow_text)
            self.assertIn(f"actions/setup-python@{'b' * 40} # v9.9.8", workflow_text)
            documentation = (
                root / "docs/github-actions-workflow-security.md"
            ).read_text(encoding="utf-8")
            self.assertIn(f"`v9.9.9` | `{'a' * 40}`", documentation)
            self.assertIn(f"`v9.9.8` | `{'b' * 40}`", documentation)

    def test_apply_preserves_reviewed_codeql_subaction_suffixes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.copied_update_root(Path(temporary_directory))
            _path, lock, _digest = UPDATER.load_lock(root)
            codeql = self.changed_action(
                lock, "github/codeql-action", "v4.99.7", "c" * 40
            )
            candidate = self.candidate_for(root, {"github/codeql-action": codeql})

            UPDATER.apply_candidate(root, candidate)

            workflow = (root / ".github/workflows/ci-security-codeql.yml").read_text(
                encoding="utf-8"
            )
            self.assertIn(f"github/codeql-action/init@{'c' * 40} # v4.99.7", workflow)
            self.assertIn(
                f"github/codeql-action/analyze@{'c' * 40} # v4.99.7", workflow
            )

    def test_all_locked_action_references_are_in_the_publisher_allowlist(self) -> None:
        _path, lock, _digest = UPDATER.load_lock(ROOT)
        UPDATER.ensure_locked_action_workflow_coverage(ROOT, lock)

        workflow = (ROOT / ".github/workflows/check-common-versions.yml").read_text(
            encoding="utf-8"
        )
        publisher_paths = {
            line.strip()
            for line in workflow.split("          add-paths: |\n", 1)[1]
            .split("\n\n  result:", 1)[0]
            .splitlines()
            if line.strip()
        }
        self.assertTrue(
            set(UPDATER.ALLOWED_UPDATE_PATHS).issubset(publisher_paths),
            sorted(set(UPDATER.ALLOWED_UPDATE_PATHS).difference(publisher_paths)),
        )
        self.assertNotIn(".github/workflows/update-workflow-tools.yml", publisher_paths)

    def test_tool_candidate_requires_the_reviewed_asset_naming_rule(self) -> None:
        _path, lock, digest = UPDATER.load_lock(ROOT)
        baseline = lock["tools"]["actionlint"]
        identity = UPDATER.release_identity(baseline, "actionlint")
        candidate = self.candidate_for(
            ROOT,
            tools={
                "actionlint": {
                    "version": "v9.9.9",
                    "immutable_commit": "c" * 40,
                    "upstream_release": UPDATER.release_url(identity, "v9.9.9"),
                    "asset": "arbitrary-release-asset.tar.gz",
                    "asset_url": UPDATER.release_asset_url(
                        identity, "v9.9.9", "arbitrary-release-asset.tar.gz"
                    ),
                    "sha256": "d" * 64,
                }
            },
        )
        with self.assertRaisesRegex(UPDATER.UpdateError, "reviewed naming rule"):
            UPDATER.validate_candidate_shape(candidate, lock, digest)

    def test_changed_tool_assets_use_the_existing_checksum_safe_fetcher(self) -> None:
        calls: list[tuple[dict[str, str], Path]] = []

        class FakeFetcher:
            @staticmethod
            def fetch(record: dict[str, str], output_dir: Path) -> Path:
                calls.append((record, output_dir))
                return output_dir / "tool"

        changes = {
            "actions": {},
            "tools": {
                "fixture": {
                    "name": "fixture",
                    "version": "v1.0.0",
                    "immutable_commit": "a" * 40,
                    "upstream_release": "https://github.com/example/fixture/releases/tag/v1.0.0",
                    "asset": "fixture.tar.gz",
                    "asset_url": "https://github.com/example/fixture/releases/download/v1.0.0/fixture.tar.gz",
                    "sha256": "b" * 64,
                }
            },
        }
        with patch.object(UPDATER, "load_fetcher_module", return_value=FakeFetcher):
            UPDATER.verify_changed_tool_assets(changes, Path("/runner-temp/validated"))

        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0]["name"], "fixture")
        self.assertEqual(Path("/runner-temp/validated/fixture"), calls[0][1])

    def test_candidate_paths_reject_runner_temp_traversal_for_reads_and_writes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            runner_temp = temporary_root / "runner-temp"
            outside = temporary_root / "outside"
            runner_temp.mkdir()
            outside.mkdir()
            traversal = runner_temp / ".." / "outside" / "candidate.json"
            traversal.parent.mkdir(exist_ok=True)
            traversal.write_text("{}\n", encoding="utf-8")
            with patch.dict(os.environ, {"RUNNER_TEMP": str(runner_temp)}):
                with self.assertRaisesRegex(UPDATER.UpdateError, "strict child"):
                    UPDATER.runner_temp_path(traversal, for_write=True)
                with self.assertRaisesRegex(UPDATER.UpdateError, "strict child"):
                    UPDATER.runner_temp_path(traversal, for_write=False)
                redirected = runner_temp / "redirected"
                redirected.symlink_to(outside, target_is_directory=True)
                with self.assertRaisesRegex(UPDATER.UpdateError, "symlink"):
                    UPDATER.write_candidate(
                        redirected / "candidate.json", {"safe": True}
                    )

                candidate_path = runner_temp / "nested" / "candidate.json"
                candidate = {"safe": True}
                UPDATER.write_candidate(candidate_path, candidate)
                self.assertEqual(
                    candidate_path.read_bytes(),
                    UPDATER.canonical_candidate_bytes(candidate) + b"\n",
                )
                self.assertEqual(candidate, UPDATER.read_candidate(candidate_path))
                self.assertEqual(candidate_path.stat().st_mode & 0o777, 0o600)
                with self.assertRaisesRegex(UPDATER.UpdateError, "overwrite"):
                    UPDATER.write_candidate(candidate_path, candidate)

    def test_canonical_validation_snapshot_is_private_and_rejects_redirects(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            runner_temp = temporary_root / "runner-temp"
            outside = temporary_root / "outside"
            runner_temp.mkdir()
            outside.mkdir()
            redirected = runner_temp / "redirected"
            redirected.symlink_to(outside, target_is_directory=True)
            with patch.dict(os.environ, {"RUNNER_TEMP": str(runner_temp)}):
                with self.assertRaisesRegex(UPDATER.UpdateError, "symlink"):
                    UPDATER.snapshot_update_validation_inputs(ROOT, redirected)
                snapshot = UPDATER.snapshot_update_validation_inputs(
                    ROOT, runner_temp / "canonical-base"
                )
            self.assertEqual(snapshot, runner_temp / "canonical-base")
            self.assertEqual(snapshot.stat().st_mode & 0o777, 0o700)
            self.assertTrue((snapshot / "ci/tooling/security-tools.lock.yml").is_file())
            with patch.dict(os.environ, {"RUNNER_TEMP": str(runner_temp)}):
                with self.assertRaisesRegex(UPDATER.UpdateError, "overwrite"):
                    UPDATER.snapshot_update_validation_inputs(ROOT, snapshot)

    def test_canonical_generated_candidate_binds_the_preapply_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            runner_temp = temporary_root / "runner-temp"
            runner_temp.mkdir()
            head_root = self.copied_update_root(temporary_root / "head")
            _path, lock, _digest = UPDATER.load_lock(head_root)
            checkout = self.changed_action(lock, "actions/checkout", "v9.9.9", "a" * 40)
            candidate = self.candidate_for(head_root, {"actions/checkout": checkout})
            UPDATER.apply_candidate(head_root, candidate)
            expected_digest = UPDATER.candidate_sha256(candidate)

            with (
                patch.dict(os.environ, {"RUNNER_TEMP": str(runner_temp)}),
                patch.object(
                    UPDATER, "verify_existing_branch_lock_records"
                ) as provenance,
                patch.object(UPDATER, "verify_changed_tool_assets") as assets,
                patch.object(UPDATER, "run_proposed_tree_contract_checks") as contracts,
            ):
                base_root = UPDATER.snapshot_update_validation_inputs(
                    ROOT, runner_temp / "canonical-base"
                )
                derived = UPDATER.validate_canonical_generated_candidate(
                    head_root,
                    base_root,
                    expected_digest,
                    runner_temp / "canonical-assets",
                )

            self.assertEqual(derived, candidate)
            provenance.assert_called_once()
            assets.assert_called_once()
            contracts.assert_called_once()

    def test_canonical_generated_candidate_rejects_a_mismatched_cross_job_digest(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            runner_temp = temporary_root / "runner-temp"
            runner_temp.mkdir()
            head_root = self.copied_update_root(temporary_root / "head")
            with patch.dict(os.environ, {"RUNNER_TEMP": str(runner_temp)}):
                base_root = UPDATER.snapshot_update_validation_inputs(
                    ROOT, runner_temp / "canonical-base"
                )
                with self.assertRaisesRegex(UPDATER.UpdateError, "does not match"):
                    UPDATER.validate_canonical_generated_candidate(
                        head_root,
                        base_root,
                        "0" * 64,
                        runner_temp / "canonical-assets",
                    )

    def test_resolve_root_rejects_symlinks_and_traversal_before_resolving(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            actual = temporary_root / "actual"
            alias = temporary_root / "alias"
            actual.mkdir()
            alias.symlink_to(actual, target_is_directory=True)
            with self.assertRaisesRegex(UPDATER.UpdateError, "non-symlink"):
                UPDATER.resolve_root(alias)
            with self.assertRaisesRegex(UPDATER.UpdateError, "traversal"):
                UPDATER.resolve_root(actual / "..")

    def test_proposed_tree_validation_does_not_modify_the_source_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            root = self.copied_update_root(temporary_root)
            _path, lock, _digest = UPDATER.load_lock(root)
            checkout = self.changed_action(lock, "actions/checkout", "v9.9.9", "a" * 40)
            candidate = self.candidate_for(root, {"actions/checkout": checkout})
            source_lock = (root / "ci/tooling/security-tools.lock.yml").read_bytes()
            runner_temp = temporary_root / "runner-temp"
            runner_temp.mkdir()
            commands: list[tuple[list[str], Path]] = []

            def successful_check(
                arguments: list[str], **kwargs: object
            ) -> subprocess.CompletedProcess[str]:
                proposed_root = Path(str(kwargs["cwd"]))
                commands.append((arguments, proposed_root))
                self.assertTrue(proposed_root.is_relative_to(runner_temp))
                proposed_lock = (
                    proposed_root / "ci/tooling/security-tools.lock.yml"
                ).read_text(encoding="utf-8")
                self.assertIn(
                    "immutable_commit: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    proposed_lock,
                )
                self.assertEqual(
                    source_lock,
                    (root / "ci/tooling/security-tools.lock.yml").read_bytes(),
                )
                return subprocess.CompletedProcess(arguments, 0, "", "")

            with (
                patch.dict(os.environ, {"RUNNER_TEMP": str(runner_temp)}),
                patch.object(UPDATER.subprocess, "run", side_effect=successful_check),
            ):
                UPDATER.validate_proposed_tree(root, candidate)

            self.assertEqual(len(commands), 3)
            self.assertEqual(list(runner_temp.iterdir()), [])
            self.assertEqual(
                source_lock,
                (root / "ci/tooling/security-tools.lock.yml").read_bytes(),
            )

    def test_proposed_tree_validation_accepts_a_tool_only_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            root = self.copied_update_root(temporary_root)
            _path, lock, _digest = UPDATER.load_lock(root)
            baseline = lock["tools"]["actionlint"]
            identity = UPDATER.release_identity(baseline, "actionlint")
            version = "v9.9.9"
            asset = UPDATER.expected_asset_name(baseline, version, "actionlint")
            candidate = self.candidate_for(
                root,
                {},
                tools={
                    "actionlint": {
                        "version": version,
                        "immutable_commit": "a" * 40,
                        "upstream_release": UPDATER.release_url(identity, version),
                        "asset": asset,
                        "asset_url": UPDATER.release_asset_url(
                            identity, version, asset
                        ),
                        "sha256": "b" * 64,
                    }
                },
            )
            runner_temp = temporary_root / "runner-temp"
            runner_temp.mkdir()

            with patch.dict(os.environ, {"RUNNER_TEMP": str(runner_temp)}):
                UPDATER.validate_proposed_tree(root, candidate)

            self.assertEqual(list(runner_temp.iterdir()), [])

    def test_scope_verification_rejects_the_unallowlisted_source_of_a_rename(
        self,
    ) -> None:
        result = subprocess.CompletedProcess(
            ["git"],
            0,
            b"D\0unapproved-source.txt\0A\0.github/workflows/lint.yml\0",
            b"",
        )
        with patch.object(UPDATER.subprocess, "run", return_value=result) as run:
            with self.assertRaisesRegex(UPDATER.UpdateError, "unapproved-source.txt"):
                UPDATER.verify_git_scope(ROOT, staged=True)
        arguments = run.call_args.args[0]
        self.assertIn("--name-status", arguments)
        self.assertIn("-z", arguments)
        self.assertIn("--no-renames", arguments)

    def test_scope_verification_rejects_a_stale_reusable_branch(self) -> None:
        stale = subprocess.CompletedProcess(["git"], 1, b"", b"")
        with patch.object(UPDATER.subprocess, "run", return_value=stale) as run:
            with self.assertRaisesRegex(UPDATER.UpdateError, "stale"):
                UPDATER.verify_git_scope(
                    ROOT,
                    staged=False,
                    base="origin/main",
                    head="origin/automation/update-framework-workflow-tools",
                )
        arguments = run.call_args.args[0]
        self.assertIn("--end-of-options", arguments)
        self.assertFalse(run.call_args.kwargs["shell"])

        for unsafe_revision in (
            "--upload-pack=sh",
            "origin/../outside",
            "HEAD:README.md",
        ):
            with patch.object(UPDATER.subprocess, "run") as unsafe_run:
                with self.assertRaisesRegex(UPDATER.UpdateError, "safe Git revision"):
                    UPDATER.verify_git_scope(
                        ROOT,
                        staged=False,
                        base="origin/main",
                        head=unsafe_revision,
                    )
                with self.assertRaisesRegex(UPDATER.UpdateError, "safe Git revision"):
                    UPDATER.git_blob(ROOT, unsafe_revision, UPDATER.LOCK_RELATIVE_PATH)
                unsafe_run.assert_not_called()

    def test_existing_branch_cannot_change_a_tool_source_identity(self) -> None:
        _path, lock, _digest = UPDATER.load_lock(ROOT)
        base = deepcopy(lock)
        head = deepcopy(lock)
        tool = head["tools"]["actionlint"]
        tool.update(
            {
                "version": "v9.9.9",
                "immutable_commit": "c" * 40,
                "upstream_release": "https://github.com/attacker/actionlint/releases/tag/v9.9.9",
                "asset": "actionlint_9.9.9_linux_amd64.tar.gz",
                "asset_url": "https://github.com/attacker/actionlint/releases/download/v9.9.9/actionlint_9.9.9_linux_amd64.tar.gz",
                "sha256": "d" * 64,
            }
        )
        with self.assertRaisesRegex(UPDATER.UpdateError, "untrusted release URL"):
            UPDATER.verify_existing_branch_lock_records(base, head)

    def test_existing_branch_verifies_changed_tool_asset_against_base_identity(
        self,
    ) -> None:
        _path, lock, _digest = UPDATER.load_lock(ROOT)
        base = deepcopy(lock)
        head = deepcopy(lock)
        baseline = base["tools"]["actionlint"]
        identity = UPDATER.release_identity(baseline, "actionlint")
        asset = "actionlint_9.9.9_linux_amd64.tar.gz"
        asset_url = UPDATER.release_asset_url(identity, "v9.9.9", asset)
        head["tools"]["actionlint"].update(
            {
                "version": "v9.9.9",
                "immutable_commit": "c" * 40,
                "upstream_release": UPDATER.release_url(identity, "v9.9.9"),
                "asset": asset,
                "asset_url": asset_url,
                "sha256": "d" * 64,
            }
        )
        release = {
            "tag_name": "v9.9.9",
            "draft": False,
            "prerelease": False,
            "assets": [
                {
                    "name": asset,
                    "digest": f"sha256:{'d' * 64}",
                    "browser_download_url": asset_url,
                }
            ],
        }
        with (
            patch.object(UPDATER, "release_by_tag", return_value=release),
            patch.object(UPDATER, "release_tag_commit", return_value="c" * 40),
        ):
            UPDATER.verify_existing_branch_lock_records(base, head)

    def test_existing_branch_rejects_a_manually_modified_publisher_blob(self) -> None:
        lock_path = ROOT / "ci/tooling/security-tools.lock.yml"
        base_lock_blob = lock_path.read_bytes()
        base_lock = UPDATER.yaml.safe_load(base_lock_blob)
        base_lock_digest = UPDATER.hashlib.sha256(base_lock_blob).hexdigest()
        head_lock = deepcopy(base_lock)
        blobs = {
            (revision, relative_text): (ROOT / relative_text).read_bytes()
            for revision in ("base", "head")
            for relative_text in UPDATER.ALLOWED_UPDATE_PATHS
        }
        workflow_path = ".github/workflows/check-action-versions.yml"
        publisher_workflow = blobs[("head", workflow_path)].decode("utf-8")
        blobs[("head", workflow_path)] = publisher_workflow.replace(
            "name: Check GitHub Action versions",
            "name: Check GitHub Action versions # unreviewed branch mutation",
            1,
        ).encode("utf-8")

        def git_blob(_root: Path, revision: str, relative: Path) -> bytes:
            return blobs[(revision, relative.as_posix())]

        with tempfile.TemporaryDirectory() as temporary_directory:
            runner_temp = Path(temporary_directory) / "runner-temp"
            runner_temp.mkdir()
            with (
                patch.dict(os.environ, {"RUNNER_TEMP": str(runner_temp)}),
                patch.object(UPDATER, "git_blob", side_effect=git_blob),
            ):
                with self.assertRaisesRegex(
                    UPDATER.UpdateError,
                    "does not match constrained updater output",
                ):
                    UPDATER.verify_existing_branch_generated_blobs(
                        ROOT,
                        "base",
                        "head",
                        base_lock,
                        head_lock,
                        base_lock_digest,
                    )
            self.assertEqual(list(runner_temp.iterdir()), [])

    def test_existing_canonical_branch_rejects_a_manually_modified_native_blob(
        self,
    ) -> None:
        lock_path = ROOT / "ci/tooling/security-tools.lock.yml"
        base_lock_blob = lock_path.read_bytes()
        base_lock = UPDATER.yaml.safe_load(base_lock_blob)
        base_lock_digest = UPDATER.hashlib.sha256(base_lock_blob).hexdigest()
        head_lock = deepcopy(base_lock)
        blobs = {
            (revision, relative_text): (ROOT / relative_text).read_bytes()
            for revision in ("base", "head")
            for relative_text in UPDATER.ALLOWED_UPDATE_PATHS
        }
        for revision in ("base", "head"):
            blobs[(revision, "ci/lib/common.sh")] = (
                ROOT / "ci/lib/common.sh"
            ).read_bytes()
        workflow_path = ".github/workflows/check-action-versions.yml"
        publisher_workflow = blobs[("head", workflow_path)].decode("utf-8")
        blobs[("head", workflow_path)] = publisher_workflow.replace(
            "name: Check GitHub Action versions",
            "name: Check GitHub Action versions # unreviewed canonical mutation",
            1,
        ).encode("utf-8")

        def git_blob(
            _root: Path, revision: str, relative: Path, **_kwargs: Any
        ) -> bytes:
            return blobs[(revision, relative.as_posix())]

        with tempfile.TemporaryDirectory() as temporary_directory:
            runner_temp = Path(temporary_directory) / "runner-temp"
            runner_temp.mkdir()
            with (
                patch.dict(os.environ, {"RUNNER_TEMP": str(runner_temp)}),
                patch.object(UPDATER, "git_blob", side_effect=git_blob),
            ):
                with self.assertRaisesRegex(
                    UPDATER.UpdateError,
                    "existing canonical branch path does not match constrained",
                ):
                    UPDATER.verify_existing_canonical_generated_blobs(
                        ROOT,
                        "base",
                        "head",
                        base_lock,
                        head_lock,
                        base_lock_digest,
                    )
            self.assertEqual(list(runner_temp.iterdir()), [])

    def test_existing_canonical_branch_accepts_the_exact_native_subset(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            base_lock_blob, base_lock, head_lock, blobs = (
                self.native_subset_blob_fixture(temporary_root)
            )
            for revision in ("base", "head"):
                blobs[(revision, "ci/lib/common.sh")] = (
                    ROOT / "ci/lib/common.sh"
                ).read_bytes()

            def git_blob(
                _root: Path, revision: str, relative: Path, **_kwargs: Any
            ) -> bytes:
                return blobs[(revision, relative.as_posix())]

            runner_temp = temporary_root / "runner-temp"
            runner_temp.mkdir()
            with (
                patch.dict(os.environ, {"RUNNER_TEMP": str(runner_temp)}),
                patch.object(UPDATER, "git_blob", side_effect=git_blob),
            ):
                UPDATER.verify_existing_canonical_generated_blobs(
                    ROOT,
                    "base",
                    "head",
                    base_lock,
                    head_lock,
                    UPDATER.hashlib.sha256(base_lock_blob).hexdigest(),
                )
            self.assertEqual(list(runner_temp.iterdir()), [])

    def test_existing_branch_accepts_exact_trusted_base_derived_blobs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            base_lock_blob, base_lock, head_lock, blobs = (
                self.native_subset_blob_fixture(temporary_root)
            )

            def git_blob(_root: Path, revision: str, relative: Path) -> bytes:
                return blobs[(revision, relative.as_posix())]

            runner_temp = temporary_root / "runner-temp"
            runner_temp.mkdir()
            with (
                patch.dict(os.environ, {"RUNNER_TEMP": str(runner_temp)}),
                patch.object(UPDATER, "git_blob", side_effect=git_blob),
            ):
                UPDATER.verify_existing_branch_generated_blobs(
                    ROOT,
                    "base",
                    "head",
                    base_lock,
                    head_lock,
                    UPDATER.hashlib.sha256(base_lock_blob).hexdigest(),
                )
            self.assertEqual(list(runner_temp.iterdir()), [])

    def test_native_helper_is_orchestrated_only_by_canonical_maintenance(
        self,
    ) -> None:
        workflow = (ROOT / ".github/workflows/check-common-versions.yml").read_text(
            encoding="utf-8"
        )
        self.assertFalse(
            (ROOT / ".github/workflows/update-workflow-tools.yml").exists()
        )
        self.assertIn("canonical-maintenance:", workflow)
        self.assertIn("candidate:", workflow)
        self.assertIn("publish:", workflow)
        self.assertIn("result:", workflow)
        self.assertIn("actions/create-github-app-token@", workflow)
        self.assertIn("client-id: ${{ vars.WORKFLOW_UPDATER_APP_CLIENT_ID }}", workflow)
        self.assertIn(
            "private-key: ${{ secrets.WORKFLOW_UPDATER_APP_PRIVATE_KEY }}", workflow
        )
        self.assertIn("permission-contents: write", workflow)
        self.assertIn("permission-pull-requests: write", workflow)
        self.assertIn("permission-workflows: write", workflow)
        self.assertIn("${{ steps.publisher_app_token.outputs.token }}", workflow)
        publisher = workflow.split("\n  publish:\n", 1)[1].split("\n  result:\n", 1)[0]
        self.assertNotIn("${{ github.token }}", publisher)
        self.assertIn("Require publisher App configuration", workflow)
        self.assertIn("workflow_tool_candidate_sha256", workflow)
        self.assertIn("--expected-candidate-sha256", workflow)
        self.assertIn("--verify-tool-assets", workflow)
        self.assertIn("--validate-proposed-tree", workflow)
        self.assertIn("snapshot-validation-inputs", workflow)
        self.assertIn("validate-canonical-generated-candidate", workflow)
        self.assertIn(
            "Inspect matching Draft canonical maintenance pull request", workflow
        )
        self.assertIn("compareCommitsWithBasehead", workflow)
        self.assertIn("verify-existing-canonical-workflow-tool-subset", workflow)
        self.assertIn("draft: true", workflow)
        self.assertIn(
            "github.ref == format('refs/heads/{0}', github.event.repository.default_branch)",
            workflow,
        )
        self.assertIn("if: ${{ always() }}", workflow)
        self.assertNotIn("|| true", workflow)
        self.assertNotIn("--force", workflow)
        self.assertNotIn("pull_request_target", workflow)


if __name__ == "__main__":
    unittest.main()
