import hashlib
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.ci_security.common_version_review_fixtures import make_component_results


ROOT = Path(__file__).parents[2]
SPEC = importlib.util.spec_from_file_location(
    "review_reconciler", ROOT / "ci/tools/reconcile-common-version-review-issues.py"
)
assert SPEC is not None
reconciler = importlib.util.module_from_spec(SPEC)
loader = SPEC.loader
assert loader is not None
loader.exec_module(reconciler)


class FakeClient:
    def __init__(self, issues=None):
        self.issues = list(issues or [])
        self.writes = []

    def list_issues(self, repository):
        return list(self.issues)

    def create_issue(self, repository, payload):
        self.writes.append(("create", repository, payload))
        return {"html_url": "https://github.example/issues/1", "number": 1}

    def update_issue(self, repository, number, payload):
        self.writes.append(("update", repository, number, payload))

    def comment(self, repository, number, body):
        self.writes.append(("comment", repository, number, body))


def make_review(candidate="1.5", state="active", **extra):
    review = {
        "review_key": f"lighttpd:series_transition:{candidate}",
        "component_id": "lighttpd",
        "component_name": "Lighttpd",
        "review_kind": "series_transition",
        "current_identity": {"series": "1.4", "version": "1.4.79"},
        "candidate_identity": {"series": candidate, "version": candidate + ".0"},
        "latest_compatible": "1.4.79",
        "latest_upstream": candidate + ".0",
        "canonical_variables": ["LIGHTTPD_SERIES"],
        "reason_code": "series_transition",
        "reason": "A new series needs compatibility review.",
        "evidence_urls": ["https://www.lighttpd.net/"],
        "automatic_update_also_available": False,
        "state": state,
    }
    review.update(extra)
    if state != "active":
        review["lifecycle_evidence"] = {
            "reason": "verified by the maintenance resolver",
            "maintenance_run": "run-1",
        }
    return review


def make_plan(reviews=None, **extra):
    component_results = make_component_results()
    checked = [item["component_id"] for item in component_results]
    plan = {
        "schema_version": "1",
        "maintenance_outcome": "manual_review_only",
        "global_inventory_complete": True,
        "scope": {"mode": "full", "checked_components": checked},
        "safe_updates": [],
        "manual_reviews": list(reviews if reviews is not None else [make_review()]),
        "checked_components": checked,
        "component_results": component_results,
        "generated_views": ["ci/provisioning/runtime-components.manifest.json"],
        "source_common_sha256": "a" * 64,
        "candidate_common_sha256": "b" * 64,
    }
    plan.update(extra)
    plan["plan_sha256"] = reconciler._plan_digest(plan)
    return plan


class ReconcilerTests(unittest.TestCase):
    def test_dry_run_never_writes(self):
        client = FakeClient()
        result = reconciler.reconcile(
            make_plan(), client, dry_run=True, repository="owner/repo"
        )
        self.assertEqual(result["actions"][0]["action"], "create")
        self.assertEqual(client.writes, [])

    def test_duplicate_managed_key_fails_closed(self):
        review = make_review()
        body = reconciler.issue_body(review)
        labels = [
            {"name": label}
            for label in (*reconciler.FIXED_LABELS, "component:lighttpd")
        ]
        issues = [
            {"number": 1, "body": body, "labels": labels},
            {"number": 2, "body": body, "labels": labels},
        ]
        plan = make_plan()
        client = FakeClient(issues)
        with self.assertRaises(reconciler.PlanError):
            reconciler.reconcile(plan, client, repository="owner/repo")

    def test_untrusted_duplicate_markers_are_quarantined_without_blocking(self):
        body = reconciler.issue_body(make_review())
        issues = [{"number": 1, "body": body}, {"number": 2, "body": body}]
        result = reconciler.reconcile(
            make_plan(), FakeClient(issues), repository="owner/repo"
        )
        self.assertEqual(result["actions"][0]["action"], "create")

    def test_marker_title_and_body_are_deterministic(self):
        review = make_review()
        self.assertEqual(
            reconciler.issue_title(review),
            "[Manual dependency review] Lighttpd: 1.4.79 -> 1.5.0",
        )
        body = reconciler.issue_body(review)
        self.assertIn(
            "<!-- common-version-review-key: lighttpd:series_transition:1.5 -->", body
        )
        self.assertEqual(body, reconciler.issue_body(review))

    def test_bounded_and_injection_like_inputs_rejected(self):
        review = make_review(reason="bad\n<!-- common-version-review-key: evil -->")
        plan = make_plan([review])
        with self.assertRaises(reconciler.PlanError):
            reconciler.validate_plan(plan)
        review = make_review(review_key="lighttpd:series_transition:1.5;curl evil")
        plan = make_plan([review])
        with self.assertRaises(reconciler.PlanError):
            reconciler.validate_plan(plan)

    def test_apply_is_rejected_outside_github_actions(self):
        plan = make_plan()
        with tempfile.TemporaryDirectory() as runner_temp:
            plan_path = Path(runner_temp) / reconciler.PLAN_FILENAME
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            with mock.patch.dict(os.environ, {"RUNNER_TEMP": runner_temp}, clear=True):
                code = reconciler.main(
                    [
                        "--plan",
                        str(plan_path),
                        "--repository",
                        "owner/repo",
                        "--apply",
                        "--token",
                        "secret",
                        "--trusted-default-branch",
                    ]
                )
        self.assertEqual(code, 2)

    def test_idempotence_update_and_close_lifecycle(self):
        review = make_review()
        existing = {
            "number": 7,
            "state": "open",
            "body": reconciler.issue_body(review),
            "title": reconciler.issue_title(review),
            "labels": [
                {"name": label}
                for label in (*reconciler.FIXED_LABELS, "component:lighttpd")
            ],
        }
        client = FakeClient([existing])
        self.assertEqual(
            reconciler.reconcile(make_plan(), client, repository="owner/repo")[
                "actions"
            ][0]["action"],
            "noop",
        )
        changed = make_plan([make_review("1.5")])
        changed["manual_reviews"][0]["reason"] = "Candidate evidence was refreshed."
        changed["plan_sha256"] = reconciler._plan_digest(changed)
        self.assertEqual(
            reconciler.reconcile(
                changed, client, dry_run=True, repository="owner/repo"
            )["actions"][0]["action"],
            "update",
        )
        completed = make_plan([make_review(state="completed")])
        self.assertEqual(
            reconciler.reconcile(
                completed, client, dry_run=True, repository="owner/repo"
            )["actions"][0]["action"],
            "close",
        )

    def test_component_scope_requires_global_result_scopes(self):
        plan = make_plan()
        plan["scope"] = {
            "mode": "component",
            "checked_components": plan["checked_components"],
        }
        plan["checked_components"] = list(plan["scope"]["checked_components"])
        plan["plan_sha256"] = reconciler._plan_digest(plan)
        self.assertEqual(reconciler.validate_plan(plan)["scope"]["mode"], "component")

        for missing_scope in ("github-actions", "ci-security-tools"):
            with self.subTest(missing_scope=missing_scope):
                incomplete = make_plan()
                incomplete["component_results"] = [
                    item
                    for item in incomplete["component_results"]
                    if item["scope"] != missing_scope
                ]
                incomplete["plan_sha256"] = reconciler._plan_digest(incomplete)
                with self.assertRaises(reconciler.PlanError):
                    reconciler.validate_plan(incomplete)

        unlisted_globals = make_plan()
        unlisted_globals["scope"] = {
            "mode": "component",
            "checked_components": ["lighttpd"],
        }
        unlisted_globals["checked_components"] = ["lighttpd"]
        unlisted_globals["plan_sha256"] = reconciler._plan_digest(unlisted_globals)
        with self.assertRaises(reconciler.PlanError):
            reconciler.validate_plan(unlisted_globals)

        swapped_scopes = make_plan()
        for item in swapped_scopes["component_results"]:
            if item["component_id"] == "go-ftw":
                item["scope"] = "albedo"
            elif item["component_id"] == "albedo":
                item["scope"] = "go-ftw"
        swapped_scopes["plan_sha256"] = reconciler._plan_digest(swapped_scopes)
        with self.assertRaises(reconciler.PlanError):
            reconciler.validate_plan(swapped_scopes)

        duplicate_result = make_plan()
        duplicate_result["component_results"].append(
            dict(duplicate_result["component_results"][0])
        )
        duplicate_result["plan_sha256"] = reconciler._plan_digest(duplicate_result)
        with self.assertRaises(reconciler.PlanError):
            reconciler.validate_plan(duplicate_result)

    def test_global_scope_fallback_records_are_valid(self):
        plan = make_plan()
        replacements = {
            "github-action-checkout": "github-actions",
            "ci-tool-shellcheck": "generated-views",
        }
        for item in plan["component_results"]:
            replacement = replacements.get(item["component_id"])
            if replacement is not None:
                item["component_id"] = replacement
                item["component_name"] = replacement
        checked = [
            replacements.get(component, component)
            for component in plan["checked_components"]
        ]
        plan["scope"]["checked_components"] = checked
        plan["checked_components"] = checked
        plan["plan_sha256"] = reconciler._plan_digest(plan)
        self.assertEqual(reconciler.validate_plan(plan)["checked_components"], checked)

    def test_non_slug_review_target_uses_full_sha256(self):
        target = "release candidate/2026"
        review = make_review(candidate=target)
        review["review_key"] = (
            "lighttpd:series_transition:" + hashlib.sha256(target.encode()).hexdigest()
        )
        review["candidate_identity"] = {"series": target, "version": "1.5.0"}
        plan = make_plan([review])
        self.assertEqual(
            reconciler.validate_plan(plan)["manual_reviews"][0]["review_key"],
            review["review_key"],
        )

    def test_optional_summary_data_is_bounded(self):
        plan = make_plan()
        plan["component_results"].append(
            {
                "component_id": "nginx",
                "component_name": "Nginx",
                "scope": "runtime-source",
                "status": "current",
                "message": "ok",
                "canonical_variables": ["NGINX_VERSION"],
                "details": {"policy": "same_major"},
            }
        )
        plan["generated_view_status"] = [
            {"name": "runtime-components", "status": "current", "message": "ok"}
        ]
        plan["plan_sha256"] = reconciler._plan_digest(plan)
        self.assertEqual(
            reconciler.validate_plan(plan)["component_results"][-1]["component_id"],
            "nginx",
        )
        plan["generated_views"] = ["../outside"]
        plan["plan_sha256"] = reconciler._plan_digest(plan)
        with self.assertRaises(reconciler.PlanError):
            reconciler.validate_plan(plan)

    def test_producer_empty_optional_summary_fields_validate_safely(self):
        plan = make_plan()
        results = {
            item["component_id"]: item
            for item in reconciler.validate_plan(plan)["component_results"]
        }
        self.assertEqual(results["ci-osv-compatibility"]["source"], "")
        self.assertEqual(
            {
                field: results["canonical-ci-coverage"][field]
                for field in (
                    "current",
                    "latest_compatible",
                    "latest_upstream",
                    "source",
                )
            },
            {
                "current": "",
                "latest_compatible": "",
                "latest_upstream": "",
                "source": "",
            },
        )
        for source in ("http://example.invalid/source", "https://example.invalid/\n"):
            with self.subTest(source=source):
                invalid = make_plan()
                next(
                    item
                    for item in invalid["component_results"]
                    if item["component_id"] == "ci-osv-compatibility"
                )["source"] = source
                invalid["plan_sha256"] = reconciler._plan_digest(invalid)
                with self.assertRaises(reconciler.PlanError):
                    reconciler.validate_plan(invalid)


if __name__ == "__main__":
    unittest.main()
