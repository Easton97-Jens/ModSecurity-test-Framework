"""Causal producer/consumer and runner-publication boundary regressions."""

import importlib.util
import json
from http.client import RemoteDisconnected
from pathlib import Path
import subprocess
import tempfile
import unittest
from copy import deepcopy
from unittest.mock import patch

import yaml
from tests.ci_security.test_canonical_maintenance import (
    MAINTENANCE,
    entries,
    FakeListClient,
)
from tests.ci_security.test_update_python_version import (
    UPDATER,
    FakeResponse,
    response_for,
    stable_record,
)
from tests.ci_security.test_ci_security_contract import CHECKER


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "runner_builds_regression", ROOT / "ci/tools/python_runner_builds.py"
)
assert SPEC is not None
assert SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


def manifest(version="3.14.7"):
    filename = f"python-{version}-linux-26.04-x64.tar.gz"
    return [
        {
            "version": version,
            "stable": True,
            "files": [
                {
                    "platform": "linux",
                    "platform_version": "26.04",
                    "arch": "x64",
                    "filename": filename,
                    "download_url": f"https://github.com/actions/python-versions/releases/download/{version}-123/{filename}",
                }
            ],
        }
    ]


class UpdaterReadinessTests(unittest.TestCase):
    def test_silent_generator_results_satisfy_unchanged_reconciler(self):
        consumer = MAINTENANCE._load_module(
            ROOT, "reconcile-common-version-review-issues.py", "readiness_reconciler"
        )
        for code in (0, 1):
            with (
                self.subTest(code=code),
                patch.object(
                    MAINTENANCE.subprocess,
                    "run",
                    return_value=subprocess.CompletedProcess(
                        [], code, stdout=" \n", stderr=""
                    ),
                ),
            ):
                statuses = MAINTENANCE.generated_view_status(ROOT)
            for index, row in enumerate(statuses):
                self.assertTrue(row["message"].strip())
                self.assertEqual(row["status"], "current" if code == 0 else "blocked")
                consumer._generated_view_status(row, index)

    def test_python_release_waits_for_exact_runner_build_without_writes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "ci/lib").mkdir(parents=True)
            pin = root / "ci/lib/common.sh"
            pin.write_text('CI_CANONICAL_PYTHON_VERSION="3.14.6"\n')
            original = pin.read_bytes()
            for builds, status in (
                ([], "blocked_metadata"),
                (manifest(), "update_available"),
            ):
                with (
                    self.subTest(status=status),
                    patch.object(
                        UPDATER.RUNNER_BUILDS, "fetch_manifest", return_value=builds
                    ),
                ):
                    result = UPDATER.resolve_update(
                        root,
                        opener=lambda req, timeout: response_for(
                            [stable_record(6), stable_record(7)]
                        ),
                    )
                self.assertEqual(result.status, status)
                self.assertEqual(pin.read_bytes(), original)

    def test_common_python_resolver_requires_same_runner_build(self):
        client = FakeListClient([stable_record(6), stable_record(7)])
        for builds, status in (([], "blocked"), (manifest(), "outdated")):
            with (
                self.subTest(status=status),
                patch.object(
                    MAINTENANCE.RUNNER_BUILDS, "fetch_manifest", return_value=builds
                ),
            ):
                result, _ = MAINTENANCE.resolve_python(
                    entries({"CI_CANONICAL_PYTHON_VERSION": "3.14.6"}), client
                )
            self.assertEqual(result["status"], status)
            self.assertEqual(len(result["updates"]), 1 if status == "outdated" else 0)

    def test_manifest_rejects_wrong_platform_arch_or_release_identity(self):
        for field, value in (
            ("arch", "arm64"),
            ("platform_version", "22.04"),
            ("download_url", "https://example.invalid/file"),
            ("filename", "python-3.14.8-linux-26.04-x64.tar.gz"),
        ):
            with self.subTest(field=field):
                payload = manifest()
                payload[0]["files"][0][field] = value
                with self.assertRaises(ValueError):
                    RUNNER.require_build(payload, "3.14.7")

    def test_manifest_fetch_rejects_redirect_and_oversized_payload(self):
        for response in (
            FakeResponse(b"[]", url="https://example.invalid/manifest"),
            FakeResponse(b"x" * (RUNNER.MAX_BYTES + 1), url=RUNNER.MANIFEST_URL),
        ):
            with self.subTest(url=response.geturl(), size=len(response.payload)):
                with self.assertRaises(ValueError):
                    RUNNER.fetch_manifest(opener=lambda req, **kwargs: response)
                self.assertTrue(response.closed)

    def test_manifest_transport_failure_is_a_blocked_metadata_input(self):
        with self.assertRaisesRegex(ValueError, "could not be fetched"):
            RUNNER.fetch_manifest(
                opener=lambda req, **kwargs: (_ for _ in ()).throw(
                    RemoteDisconnected("connection closed")
                )
            )

    def test_sonar_view_is_admitted_only_at_all_exact_publisher_paths(self):
        updater = MAINTENANCE.load_workflow_tool_updater(ROOT)
        path = ".github/workflows/sonarqube.yml"
        for allowed in (
            MAINTENANCE.ALLOWED_AUTOMATIC_PATHS,
            updater.ALLOWED_UPDATE_PATHS,
        ):
            self.assertIn(path, allowed)
            self.assertNotIn(".github/workflows/unreviewed.yml", allowed)
        workflow = yaml.safe_load(
            (ROOT / ".github/workflows/check-common-versions.yml").read_text()
        )
        steps = workflow["jobs"]["publish"]["steps"]
        inspect = next(
            step["with"]["script"]
            for step in steps
            if "const allowedPaths = new Set(["
            in step.get("with", {}).get("script", "")
        )
        self.assertIn(json.dumps(path), inspect)
        publish = next(step for step in steps if step.get("with", {}).get("add-paths"))
        self.assertIn(path, publish["with"]["add-paths"].splitlines())

    def test_python_runner_matches_manifest_target(self):
        document = yaml.safe_load(
            (ROOT / ".github/workflows/check-python-version.yml").read_text()
        )
        for name in ("resolve", "candidate-validate", "publish"):
            self.assertEqual(document["jobs"][name]["runs-on"], RUNNER.RUNNER)
        common = yaml.safe_load(
            (ROOT / ".github/workflows/check-common-versions.yml").read_text()
        )
        for job in common["jobs"].values():
            self.assertEqual(job["runs-on"], RUNNER.RUNNER)

    def test_common_workflow_rejects_manifest_runner_drift(self):
        path = ROOT / ".github/workflows/check-common-versions.yml"
        original = yaml.safe_load(path.read_text())
        for name in original["jobs"]:
            with self.subTest(job=name):
                document = deepcopy(original)
                document["jobs"][name]["runs-on"] = "ubuntu-latest"
                errors = CHECKER.common_version_maintenance_errors(path, document)
                self.assertTrue(
                    any("runner" in error and "manifest" in error for error in errors)
                )

    def test_all_active_workflow_jobs_pin_requested_ubuntu_release(self):
        import runpy

        integration = runpy.run_path(
            str(ROOT / "ci/checks/security/connector_action_pins.py")
        )
        for path in sorted((ROOT / ".github/workflows").glob("*.yml")):
            document = yaml.safe_load(path.read_text())
            for name, job in document["jobs"].items():
                with self.subTest(workflow=path.name, job=name):
                    if path.name in integration["WORKFLOWS"]:
                        self.assertEqual(
                            integration["validate_source"](
                                ROOT, str(path.relative_to(ROOT))
                            ),
                            [],
                        )
                    else:
                        self.assertEqual(job["runs-on"], "ubuntu-26.04")

    def test_previous_ubuntu_build_cannot_satisfy_new_target(self):
        previous = manifest()
        build = previous[0]["files"][0]
        build["platform_version"] = "24.04"
        build["filename"] = build["filename"].replace("26.04", "24.04")
        build["download_url"] = build["download_url"].replace("26.04", "24.04")
        with self.assertRaisesRegex(ValueError, "ubuntu-26.04/x64.*unavailable"):
            RUNNER.require_build(previous, "3.14.7")

    def test_actionlint_only_adds_the_exact_official_runner_label(self):
        config = yaml.safe_load((ROOT / ".github/actionlint.yaml").read_text())
        self.assertEqual(config, {"self-hosted-runner": {"labels": ["ubuntu-26.04"]}})
