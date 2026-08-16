import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[2]
SPEC = importlib.util.spec_from_file_location(
    "review_reconciler_lifecycle", ROOT / "ci/tools/reconcile-common-version-review-issues.py"
)
reconciler = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(reconciler)


class FakeClient:
    def __init__(self, issues):
        self.issues = list(issues)
        self.writes = []

    def list_issues(self, repository):
        return list(self.issues)

    def create_issue(self, repository, payload):
        self.writes.append(("create", payload))
        return {"html_url": "https://github.example/issues/1"}

    def update_issue(self, repository, number, payload):
        self.writes.append(("update", number, payload))

    def comment(self, repository, number, body):
        self.writes.append(("comment", number, body))


GLOBALS = list(reconciler.MANDATORY_GLOBAL_COMPONENTS)


def review(candidate="1.5", state="active"):
    item = {
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
    if state != "active":
        item["lifecycle_evidence"] = {"reason": "verified", "maintenance_run": "run-1"}
    return item


def plan(reviews, *, checked=None, outcome="manual_review_only", complete=True, statuses=None):
    checked = list(checked or GLOBALS + ["lighttpd"])
    statuses = statuses or {component: "current" for component in checked}
    value = {
        "schema_version": "1",
        "maintenance_outcome": outcome,
        "scope": {"mode": "full", "checked_components": checked},
        "safe_updates": [],
        "manual_reviews": list(reviews),
        "checked_components": checked,
        "component_results": [
            {
                "component_id": component,
                "component_name": component,
                "scope": "runtime-source" if component == "lighttpd" else "ci-security-tools",
                "status": statuses.get(component, "current"),
                "message": "checked",
                "canonical_variables": ["LIGHTTPD_SERIES"] if component == "lighttpd" else ["CI_CANONICAL_PYTHON_VERSION"],
            }
            for component in checked
        ],
        "generated_views": [],
        "generated_view_status": [],
        "global_inventory_complete": complete,
        "source_common_sha256": "a" * 64,
        "candidate_common_sha256": "b" * 64,
    }
    value["plan_sha256"] = reconciler._plan_digest(value)
    return value


def managed_issue(item, *, state="open", state_reason=None):
    issue = {
        "number": 7,
        "state": state,
        "body": reconciler.issue_body(item),
        "title": reconciler.issue_title(item),
        "labels": [
            {"name": label}
            for label in (*reconciler.FIXED_LABELS, f"component:{item['component_id']}")
        ],
    }
    if state_reason is not None:
        issue["state_reason"] = state_reason
    return issue


class ReviewLifecycleTests(unittest.TestCase):
    def test_full_empty_plan_closes_checked_issue_completed_without_dry_run_writes(self):
        old = review("1.5")
        client = FakeClient([managed_issue(old)])
        result = reconciler.reconcile(plan([]), client, dry_run=True, repository="owner/repo")
        self.assertEqual(result["actions"], [{"action": "close", "review_key": old["review_key"], "number": 7, "state_reason": "completed"}])
        self.assertEqual(client.writes, [])

    def test_component_scope_does_not_close_unscoped_runtime_issue(self):
        old = review("1.5")
        checked = GLOBALS + ["lighttpd"]
        client = FakeClient([managed_issue(old)])
        result = reconciler.reconcile(plan([], checked=checked), client, dry_run=True, repository="owner/repo")
        self.assertEqual(result["count"], 1)

        # A second issue for an unselected component is ignored, even though
        # the global inventory is complete for this component-scoped run.
        unscoped = dict(old, component_id="nginx", component_name="Nginx", review_key="nginx:series_transition:1.5")
        client = FakeClient([managed_issue(unscoped)])
        self.assertEqual(reconciler.reconcile(plan([], checked=checked), client, dry_run=True, repository="owner/repo")["actions"], [])

    def test_new_active_target_supersedes_old_target(self):
        old = review("1.5")
        current = review("1.6")
        client = FakeClient([managed_issue(old)])
        actions = reconciler.reconcile(plan([current]), client, dry_run=True, repository="owner/repo")["actions"]
        self.assertEqual(actions[0]["action"], "create")
        self.assertEqual(actions[1]["state_reason"], "not_planned")

    def test_fatal_or_incomplete_plan_never_closes_absent_reviews(self):
        old = review("1.5")
        client = FakeClient([managed_issue(old)])
        self.assertEqual(reconciler.reconcile(plan([], outcome="fatal", complete=False), client, dry_run=True, repository="owner/repo")["actions"], [])
        self.assertEqual(reconciler.reconcile(plan([], outcome="manual_review_only", complete=False), client, dry_run=True, repository="owner/repo")["actions"], [])

    def test_malformed_markers_are_not_evidence_for_closure(self):
        old = review("1.5")
        issue = managed_issue(old)
        issue["body"] = issue["body"].replace(
            f"common-version-component: {old['component_id']}", "common-version-component: nginx"
        )
        client = FakeClient([issue])
        self.assertEqual(reconciler.reconcile(plan([]), client, dry_run=True, repository="owner/repo")["actions"], [])

    def test_completed_issue_reopens_for_active_same_target(self):
        current = review("1.5")
        client = FakeClient([managed_issue(current, state="closed", state_reason="completed")])
        actions = reconciler.reconcile(plan([current]), client, dry_run=True, repository="owner/repo")["actions"]
        self.assertEqual(actions[0]["action"], "reopen")


if __name__ == "__main__":
    unittest.main()
