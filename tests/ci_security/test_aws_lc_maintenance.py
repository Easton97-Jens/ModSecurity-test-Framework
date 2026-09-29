"""Hermetic coverage for AWS-LC's automatic tag/peeled-commit maintenance."""

from __future__ import annotations

from copy import deepcopy
import dataclasses
from pathlib import Path
from typing import Any
import unittest

from ci.tools import canonical_maintenance as MAINTENANCE


ROOT = Path(__file__).resolve().parents[2]
CHECKER = MAINTENANCE.load_runtime_checker(ROOT)
COMPONENT = "AWS-LC"
REPOSITORY = "aws/aws-lc"
API = f"https://api.github.com/repos/{REPOSITORY}"
RELEASES_URL = f"{API}/releases?per_page=100"
CURRENT_TAG = "v5.5.0"
NEXT_TAG = "v5.10.0"
CURRENT_COMMIT = "a" * 40
NEXT_COMMIT = "b" * 40


def release(tag: str, **overrides: Any) -> dict[str, Any]:
    return {"tag_name": tag, "draft": False, "prerelease": False, **overrides}


def source(**overrides: str) -> list[str]:
    values = {
        "AWS_LC_REPOSITORY": f"https://github.com/{REPOSITORY}.git",
        "AWS_LC_TAG": CURRENT_TAG,
        "AWS_LC_COMMIT": CURRENT_COMMIT,
    }
    values.update(overrides)
    return [f'{name}="{value}"' for name, value in values.items()]


class ReleaseClient:
    def __init__(self, latest: str = NEXT_TAG, commit: str = NEXT_COMMIT) -> None:
        self.responses: dict[str, Any] = {
            RELEASES_URL: [release(CURRENT_TAG), release(latest)],
            f"{API}/git/ref/tags/{CURRENT_TAG}": {
                "object": {"type": "commit", "sha": CURRENT_COMMIT}
            },
            f"{API}/git/ref/tags/{latest}": {
                "object": {"type": "commit", "sha": commit}
            },
        }
        self.urls: list[str] = []

    def get_json(self, url: str) -> Any:
        self.urls.append(url)
        if url not in self.responses:
            raise AssertionError(f"unexpected upstream lookup: {url}")
        return deepcopy(self.responses[url])

    def get_json_list(self, url: str) -> list[dict[str, Any]]:
        return self.get_json(url)


class AwsLcMaintenanceTests(unittest.TestCase):
    def resolve(self, client: ReleaseClient, **overrides: str):
        entries = CHECKER.parse_common_lines(source(**overrides))
        result = CHECKER.check_all(entries, client, (COMPONENT,))[0]
        return entries, result

    def test_descriptor_enables_automatic_atomic_latest_stable_updates(self) -> None:
        definition = CHECKER.COMPONENT_DEFINITION_BY_NAME[COMPONENT]
        self.assertEqual("automatic", definition.update_policy)
        self.assertEqual(("AWS_LC_TAG", "AWS_LC_COMMIT"), definition.atomic_group)
        self.assertEqual(
            CHECKER.NO_HIDDEN_SERIES_RESTRICTION, definition.compatibility_policy
        )
        self.assertNotIn(COMPONENT, CHECKER.MANUAL_REVIEW_VARIABLES)

    def test_new_release_updates_tag_and_commit_and_settles_after_render(self) -> None:
        client = ReleaseClient()
        entries, result = self.resolve(client)
        self.assertEqual(CHECKER.STATUS_OUTDATED, result.status)
        updates, errors = CHECKER.maintenance_update_plan([result], entries)
        self.assertEqual([], errors)
        self.assertEqual(
            {"AWS_LC_TAG": NEXT_TAG, "AWS_LC_COMMIT": NEXT_COMMIT},
            {item.variable: item.new for item in updates},
        )
        rendered = CHECKER.render_updated_lines(source(), updates)
        candidate = CHECKER.parse_common_lines(rendered)
        settled = CHECKER.check_all(candidate, client, (COMPONENT,))[0]
        self.assertEqual(CHECKER.STATUS_CURRENT, settled.status)
        self.assertEqual([], settled.updates)
        self.assertEqual(NEXT_COMMIT, settled.details["peeled_commit"])

    def test_current_release_is_a_noop(self) -> None:
        _, result = self.resolve(ReleaseClient(CURRENT_TAG, CURRENT_COMMIT))
        self.assertEqual(CHECKER.STATUS_CURRENT, result.status)
        self.assertEqual([], result.updates)

    def test_numeric_selection_ignores_preview_fips_and_incomplete_metadata(
        self,
    ) -> None:
        client = ReleaseClient()
        client.responses[RELEASES_URL] = [
            release(NEXT_TAG),
            release("v5.9.0"),
            release("v99.0.0", draft=True),
            release("v98.0.0", prerelease=True),
            release("v97.0.0-rc.1"),
            release("AWS-LC-FIPS-99.0.0"),
            {"tag_name": "v96.0.0"},
        ]
        _, result = self.resolve(client)
        self.assertEqual(CHECKER.STATUS_OUTDATED, result.status)
        self.assertEqual(NEXT_TAG, result.latest)
        self.assertNotIn(f"{API}/git/ref/tags/v99.0.0", client.urls)

    def test_latest_stable_policy_does_not_freeze_the_major_line(self) -> None:
        _, result = self.resolve(ReleaseClient("v6.0.0"))
        self.assertEqual(CHECKER.STATUS_OUTDATED, result.status)
        self.assertEqual("v6.0.0", result.latest_compatible)
        self.assertEqual("v6.0.0", result.latest_upstream)

    def test_annotated_candidate_uses_the_peeled_commit_not_the_tag_object(
        self,
    ) -> None:
        client = ReleaseClient()
        annotated = "c" * 40
        client.responses[f"{API}/git/ref/tags/{NEXT_TAG}"] = {
            "object": {"type": "tag", "sha": annotated}
        }
        client.responses[f"{API}/git/tags/{annotated}"] = {
            "object": {"type": "commit", "sha": NEXT_COMMIT}
        }
        _, result = self.resolve(client)
        self.assertEqual(CHECKER.STATUS_OUTDATED, result.status)
        self.assertEqual(NEXT_COMMIT, result.details["latest_peeled_commit"])
        self.assertIn(f"{API}/git/tags/{annotated}", client.urls)
        self.assertNotIn(annotated, [item.new for item in result.updates])

    def test_invalid_current_tuple_fails_before_lookup(self) -> None:
        cases = (
            {"AWS_LC_REPOSITORY": "https://github.com/attacker/aws-lc.git"},
            {"AWS_LC_TAG": "main"},
            {"AWS_LC_TAG": "v5.6.0-rc.1"},
            {"AWS_LC_COMMIT": "1234567"},
        )
        for override in cases:
            with self.subTest(override=override):
                client = ReleaseClient()
                _, result = self.resolve(client, **override)
                self.assertIn(result.status, CHECKER.FATAL_STATUSES)
                self.assertEqual([], result.updates)
                self.assertEqual([], client.urls)

    def test_retargeted_current_tag_is_not_silently_repaired(self) -> None:
        client = ReleaseClient()
        client.responses[f"{API}/git/ref/tags/{CURRENT_TAG}"] = {
            "object": {"type": "commit", "sha": "d" * 40}
        }
        _, result = self.resolve(client)
        self.assertEqual(CHECKER.STATUS_UNKNOWN, result.status)
        self.assertEqual([], result.updates)
        self.assertNotIn(RELEASES_URL, client.urls)

    def test_stale_release_list_cannot_downgrade_the_pin(self) -> None:
        client = ReleaseClient("v5.4.0")
        client.responses[RELEASES_URL] = [release("v5.4.0")]
        _, result = self.resolve(client)
        self.assertEqual(CHECKER.STATUS_UNKNOWN, result.status)
        self.assertEqual([], result.updates)

    def test_missing_or_malformed_candidate_commit_blocks_the_whole_tuple(self) -> None:
        for target in (
            {},
            {"type": "tree", "sha": NEXT_COMMIT},
            {"type": "commit", "sha": "1234567"},
        ):
            with self.subTest(target=target):
                client = ReleaseClient()
                client.responses[f"{API}/git/ref/tags/{NEXT_TAG}"] = {"object": target}
                _, result = self.resolve(client)
                self.assertIn(result.status, CHECKER.FATAL_STATUSES)
                self.assertEqual([], result.updates)

    def test_empty_or_preview_only_release_list_is_not_a_success(self) -> None:
        for releases in ([], [release("v99.0.0", prerelease=True)]):
            with self.subTest(releases=releases):
                client = ReleaseClient()
                client.responses[RELEASES_URL] = releases
                _, result = self.resolve(client)
                self.assertIn(result.status, CHECKER.FATAL_STATUSES)
                self.assertEqual([], result.updates)

    def test_incomplete_atomic_update_is_rejected(self) -> None:
        entries, result = self.resolve(ReleaseClient())
        self.assertEqual(CHECKER.STATUS_OUTDATED, result.status)
        incomplete = dataclasses.replace(result, updates=result.updates[:1])
        updates, errors = CHECKER.maintenance_update_plan([incomplete], entries)
        self.assertEqual([], updates)
        self.assertEqual([COMPONENT], errors)

    def test_new_tag_for_same_commit_preserves_the_complete_expected_tuple(
        self,
    ) -> None:
        entries, result = self.resolve(ReleaseClient(commit=CURRENT_COMMIT))
        self.assertEqual(CHECKER.STATUS_OUTDATED, result.status)
        updates, errors = CHECKER.maintenance_update_plan([result], entries)
        self.assertEqual([], errors)
        self.assertEqual(["AWS_LC_TAG"], [item.variable for item in updates])
        self.assertEqual(
            {"AWS_LC_TAG": NEXT_TAG, "AWS_LC_COMMIT": CURRENT_COMMIT},
            result.details["atomic_expected_values"],
        )

    def test_unified_runtime_scope_carries_updates_without_manual_review(self) -> None:
        entries = CHECKER.parse_common_lines(source())
        results, reviews, selected = MAINTENANCE.resolve_runtime_components(
            CHECKER, entries, ReleaseClient(), ("aws-lc",)
        )
        self.assertEqual(["aws-lc"], selected)
        self.assertEqual([], reviews)
        updates = MAINTENANCE._unique_updates(results)
        self.assertEqual(
            {"AWS_LC_TAG": NEXT_TAG, "AWS_LC_COMMIT": NEXT_COMMIT},
            {item["variable"]: item["new"] for item in updates},
        )
        self.assertEqual(
            "safe_updates", MAINTENANCE._maintenance_outcome(results, updates, reviews)
        )


if __name__ == "__main__":
    unittest.main()
