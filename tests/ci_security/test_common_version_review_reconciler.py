import hashlib
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).parents[2]
SPEC = importlib.util.spec_from_file_location("review_reconciler", ROOT / "ci/tools/reconcile-common-version-review-issues.py")
reconciler = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(reconciler)


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
        review["lifecycle_evidence"] = {"reason": "verified by the maintenance resolver", "maintenance_run": "run-1"}
    return review


def make_plan(reviews=None, **extra):
    checked = list(reconciler.MANDATORY_GLOBAL_COMPONENTS) + ["lighttpd"]
    plan = {
        "schema_version": "1",
        "maintenance_outcome": "manual_review_only",
        "scope": {"mode": "full", "checked_components": checked},
        "safe_updates": [],
        "manual_reviews": list(reviews if reviews is not None else [make_review()]),
        "checked_components": checked,
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
        result = reconciler.reconcile(make_plan(), client, dry_run=True, repository="owner/repo")
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
        with self.assertRaises(reconciler.PlanError):
            reconciler.reconcile(make_plan(), FakeClient(issues), repository="owner/repo")

    def test_untrusted_duplicate_markers_are_quarantined_without_blocking(self):
        body = reconciler.issue_body(make_review())
        issues = [{"number": 1, "body": body}, {"number": 2, "body": body}]
        result = reconciler.reconcile(make_plan(), FakeClient(issues), repository="owner/repo")
        self.assertEqual(result["actions"][0]["action"], "create")

    def test_marker_title_and_body_are_deterministic(self):
        review = make_review()
        self.assertEqual(reconciler.issue_title(review), "[Manual dependency review] Lighttpd: 1.4.79 -> 1.5.0")
        body = reconciler.issue_body(review)
        self.assertIn("<!-- common-version-review-key: lighttpd:series_transition:1.5 -->", body)
        self.assertEqual(body, reconciler.issue_body(review))

    def test_bounded_and_injection_like_inputs_rejected(self):
        review = make_review(reason="bad\n<!-- common-version-review-key: evil -->")
        with self.assertRaises(reconciler.PlanError):
            reconciler.validate_plan(make_plan([review]))
        review = make_review(review_key="lighttpd:series_transition:1.5;curl evil")
        with self.assertRaises(reconciler.PlanError):
            reconciler.validate_plan(make_plan([review]))

    def test_apply_is_rejected_outside_github_actions(self):
        plan = make_plan()
        with tempfile.NamedTemporaryFile("w", suffix=".json") as handle:
            json.dump(plan, handle)
            handle.flush()
            with mock.patch.dict(os.environ, {}, clear=True):
                code = reconciler.main(["--plan", handle.name, "--repository", "owner/repo", "--apply", "--token", "secret", "--trusted-default-branch"])
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
        self.assertEqual(reconciler.reconcile(make_plan(), client, repository="owner/repo")["actions"][0]["action"], "noop")
        changed = make_plan([make_review("1.5")])
        changed["manual_reviews"][0]["reason"] = "Candidate evidence was refreshed."
        changed["plan_sha256"] = reconciler._plan_digest(changed)
        self.assertEqual(reconciler.reconcile(changed, client, dry_run=True, repository="owner/repo")["actions"][0]["action"], "update")
        completed = make_plan([make_review(state="completed")])
        self.assertEqual(reconciler.reconcile(completed, client, dry_run=True, repository="owner/repo")["actions"][0]["action"], "close")

    def test_component_scope_includes_globals_and_selected_runtime(self):
        plan = make_plan()
        plan["scope"] = {"mode": "component", "checked_components": plan["checked_components"]}
        plan["checked_components"] = list(plan["scope"]["checked_components"])
        plan["plan_sha256"] = reconciler._plan_digest(plan)
        self.assertEqual(reconciler.validate_plan(plan)["scope"]["mode"], "component")

        incomplete = make_plan()
        incomplete["scope"] = {"mode": "component", "checked_components": ["lighttpd"]}
        incomplete["checked_components"] = ["lighttpd"]
        incomplete["plan_sha256"] = reconciler._plan_digest(incomplete)
        with self.assertRaises(reconciler.PlanError):
            reconciler.validate_plan(incomplete)

    def test_non_slug_review_target_uses_full_sha256(self):
        target = "release candidate/2026"
        review = make_review(candidate=target)
        review["review_key"] = "lighttpd:series_transition:" + hashlib.sha256(target.encode()).hexdigest()
        review["candidate_identity"] = {"series": target, "version": "1.5.0"}
        plan = make_plan([review])
        self.assertEqual(reconciler.validate_plan(plan)["manual_reviews"][0]["review_key"], review["review_key"])

    def test_optional_summary_data_is_bounded(self):
        plan = make_plan()
        plan["component_results"] = [{
            "component_id": "lighttpd", "component_name": "Lighttpd", "scope": "runtime-source",
            "status": "current", "message": "ok", "canonical_variables": ["LIGHTTPD_SERIES"],
            "details": {"policy": "same_major"},
        }]
        plan["generated_view_status"] = [{"name": "runtime-components", "status": "current", "message": "ok"}]
        plan["plan_sha256"] = reconciler._plan_digest(plan)
        self.assertEqual(len(reconciler.validate_plan(plan)["component_results"]), 1)
        plan["generated_views"] = ["../outside"]
        plan["plan_sha256"] = reconciler._plan_digest(plan)
        with self.assertRaises(reconciler.PlanError):
            reconciler.validate_plan(plan)


if __name__ == "__main__":
    unittest.main()
