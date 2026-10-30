"""Offline tests for the narrow CodeQL Go version-contract checker."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock


ROOT = connector_root()
CHECKER_PATH = source_path('ci/checks/common/check-go-version-contract.py', root=ROOT)


def load_checker():
    module = load_source(CHECKER_PATH)
    return module


checker = load_checker()


def go_job(
    name: str,
    *,
    setup_reference: str | None = None,
    selector: str = "file",
    extra_with_lines: tuple[str, ...] = (),
    cache_with_lines: tuple[str, ...] = (),
) -> str:
    reference = checker.SETUP_GO_REFERENCE if setup_reference is None else setup_reference
    version_line = (
        "          go-version: ${{ needs.trusted-go-version.outputs.version }}"
        if selector == "file"
        else "          go-version: '1.27.0'"
    )
    extra_lines = "".join(f"          {line}\n" for line in extra_with_lines)
    cache_lines = "".join(f"          {line}\n" for line in cache_with_lines)
    return f'''  {name}:
    needs: trusted-go-version
    runs-on: ubuntu-26.04
    steps:
      - uses: {reference}
        with:
{version_line}
{extra_lines}          check-latest: false
{cache_lines}'''


class GoVersionContractTests(unittest.TestCase):
    def root_with_workflow(self, root: Path, workflow: str, version: str = "1.27.0") -> Path:
        (root / ".github" / "workflows").mkdir(parents=True)
        (root / ".go-version").write_text(f"{version}\n", encoding="utf-8")
        (root / ".github" / "workflows" / "ci-security-codeql.yml").write_text(workflow, encoding="utf-8")
        return root

    def check_json(self, root: Path) -> tuple[int, dict[str, object]]:
        output = io.StringIO()
        with mock.patch.object(checker, "repository_root", return_value=root), contextlib.redirect_stdout(output):
            status = checker.main(["--json"])
        return status, json.loads(output.getvalue())

    def valid_workflow(self) -> str:
        trusted = '''  trusted-go-version:
    runs-on: ubuntu-26.04
    outputs:
      version: ${{ steps.version.outputs.version }}
    steps:
      - uses: actions/checkout@example
        with:
          ref: ${{ github.event.pull_request.base.sha || github.sha }}
      - id: setup-python
        uses: ''' + checker.SETUP_PYTHON_REFERENCE + '''
        with:
          python-version-file: .python-version
          check-latest: false
      - name: Verify Python interpreter contract
        env:
          EXPECTED_PYTHON: ${{ steps.setup-python.outputs.python-path }}
        run: python3 ci/checks/common/check-python-interpreter-contract.py --version-file .python-version --expected-python "$EXPECTED_PYTHON"
      - id: version
        run: |
          go_report="$(python3 scripts/update-go-version.py --check --json)"
          GO_REPORT="$go_report" python3 - <<'PY' >> "$GITHUB_OUTPUT"
          import json
          import os
          import re
          data = json.loads(os.environ["GO_REPORT"])
          latest = data.get("latest_version")
          current = data.get("current_version")
          def version_tuple(value):
              return (0, 0, 0)
          if version_tuple(latest) < version_tuple(current):
              raise SystemExit("trusted Go resolver returned a downgrade")
          print(f"version={latest}")
          PY
'''
        return "name: CodeQL\n\non:\n  workflow_dispatch:\n\njobs:\n" + trusted + go_job("envoy-go") + go_job("traefik-go")

    def checked_in_resolver_program(self) -> str:
        workflow = (source_path('.github/workflows/ci-security-codeql.yml', root=ROOT)).read_text(encoding="utf-8")
        prefix = 'GO_REPORT="$go_report" python3 - <<\'PY\' >> "$GITHUB_OUTPUT"\n'
        _, found, remainder = workflow.partition(prefix)
        self.assertTrue(found, "checked-in CodeQL workflow lacks the trusted resolver program")
        source, found, _ = remainder.partition("          PY\n")
        self.assertTrue(found, "checked-in CodeQL workflow lacks the trusted resolver terminator")
        return textwrap.dedent(source)

    def run_checked_in_resolver(self, report: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-c", self.checked_in_resolver_program()],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env={**os.environ, "GO_REPORT": report, "PYTHONDONTWRITEBYTECODE": "1"},
        )

    def test_valid_contract_accepts_strict_cross_series_selectors(self) -> None:
        for version in ("1.27.0", "2.0.0"):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as temporary:
                status, result = self.check_json(
                    self.root_with_workflow(Path(temporary), self.valid_workflow(), version)
                )
            self.assertEqual(status, 0)
            self.assertEqual(result["status"], "passed")
            self.assertEqual(result["version"], version)
            self.assertEqual(result["violations"], [])

    def test_checked_in_codeql_workflow_satisfies_contract(self) -> None:
        status, result = self.check_json(ROOT)
        self.assertEqual(status, 0)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["violations"], [])

    def cached_workflow(self, job_name: str) -> str:
        cache_lines = {
            "envoy-go": (
                "cache-dependency-path: |",
                "  connectors/envoy/ext_proc/go.mod",
                "  connectors/envoy/ext_proc/go.sum",
            ),
            "traefik-go": (
                "cache-dependency-path: connectors/traefik/native_middleware/go.mod",
            ),
        }
        return self.valid_workflow().replace(
            go_job(job_name), go_job(job_name, cache_with_lines=cache_lines[job_name])
        )

    def test_reviewed_job_specific_cache_paths_are_accepted(self) -> None:
        for job_name in ("envoy-go", "traefik-go"):
            with self.subTest(job=job_name), tempfile.TemporaryDirectory() as temporary:
                status, result = self.check_json(
                    self.root_with_workflow(Path(temporary), self.cached_workflow(job_name))
                )
                self.assertEqual(status, 0)
                self.assertEqual(result["violations"], [])

    def test_cached_setup_rejects_selector_and_cache_drift(self) -> None:
        version = "go-version: ${{ needs.trusted-go-version.outputs.version }}"
        variants = (
            ("wrong_envoy_path", "envoy-go", "connectors/envoy/ext_proc/go.sum", "arbitrary/go.sum"),
            ("wrong_traefik_path", "traefik-go", "connectors/traefik/native_middleware/go.mod", "connectors/envoy/ext_proc/go.mod"),
            ("duplicate_envoy_version", "envoy-go", version, version + "\n          go-version: '1.27.0'"),
            ("duplicate_traefik_version", "traefik-go", version, version + "\n          go-version: '1.27.0'"),
            ("literal_version", "envoy-go", version, "go-version: '1.27.0'"),
            ("version_file", "envoy-go", version, "go-version-file: .go-version"),
            ("quoted_key", "envoy-go", version, version.replace("go-version:", "'go-version':")),
            ("alternate_key", "envoy-go", version, version.replace("go-version:", "go-version :")),
            ("fallback", "envoy-go", version, version.replace("outputs.version", "outputs.version || '1.27.0'")),
            ("check_latest", "envoy-go", "          check-latest: false\n          cache-", "          check-latest: true\n          cache-"),
            ("unknown_cache_field", "envoy-go", "          cache-dependency-path:", "          cache: true\n          cache-dependency-path:"),
            ("duplicate_cache", "traefik-go", "          cache-dependency-path:", "          cache-dependency-path: arbitrary/go.mod\n          cache-dependency-path:"),
        )
        for label, job_name, before, after in variants:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                workflow = self.cached_workflow(job_name)
                prefix, header, job = workflow.partition(f"  {job_name}:\n")
                self.assertTrue(header)
                self.assertIn(before, job)
                workflow = prefix + header + job.replace(before, after, 1)
                status, result = self.check_json(
                    self.root_with_workflow(Path(temporary), workflow)
                )
                self.assertEqual(status, 2)
                self.assertTrue(any(
                    f"{job_name} must use only the trusted-base Go version output" == entry
                    for entry in result["violations"]
                ))

    def test_checked_in_resolver_accepts_only_coherent_freshness_reports(self) -> None:
        valid = json.dumps(
            {
                "current_version": "1.27.0",
                "latest_version": "1.27.1",
                "status": "update_available",
                "update_available": True,
            }
        )
        result = self.run_checked_in_resolver(valid)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "version=1.27.1\n")

        invalid_reports = {
            "invalid_json": "not-json",
            "non_string_version": json.dumps(
                {
                    "current_version": "1.27.0",
                    "latest_version": 12701,
                    "status": "update_available",
                    "update_available": True,
                }
            ),
            "downgrade": json.dumps(
                {
                    "current_version": "1.27.1",
                    "latest_version": "1.27.0",
                    "status": "update_available",
                    "update_available": True,
                }
            ),
            "inconsistent_update_flag": json.dumps(
                {
                    "current_version": "1.27.0",
                    "latest_version": "1.27.1",
                    "status": "current",
                    "update_available": False,
                }
            ),
            "inconsistent_status": json.dumps(
                {
                    "current_version": "1.27.0",
                    "latest_version": "1.27.1",
                    "status": "current",
                    "update_available": True,
                }
            ),
        }
        for label, report in invalid_reports.items():
            with self.subTest(label=label):
                result = self.run_checked_in_resolver(report)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")

    def test_literal_selector_and_unlisted_go_job_are_rejected(self) -> None:
        workflow = (
            "name: CodeQL\n\non:\n  workflow_dispatch:\n\njobs:\n"
            + go_job("envoy-go", selector="literal")
            + go_job("traefik-go")
            + go_job("other-go")
        )
        with tempfile.TemporaryDirectory() as temporary:
            status, result = self.check_json(self.root_with_workflow(Path(temporary), workflow))
        self.assertEqual(status, 2)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any("trusted Go version job" in entry for entry in result["violations"]))
        self.assertTrue(any("unlisted" in entry for entry in result["violations"]))

    def test_yaml_equivalent_literal_selector_variants_are_rejected(self) -> None:
        variants = {
            "space_before_colon": ("go-version : '1.27.0'",),
            "single_quoted_key": ("'go-version': '1.27.0'",),
            "double_quoted_key": ('"go-version": "1.27.0"',),
            "explicit_mapping_key": ("? go-version", ": '1.27.0'"),
        }
        for name, extra_with_lines in variants.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                workflow = (
                    "name: CodeQL\n\non:\n  workflow_dispatch:\n\njobs:\n"
                    + go_job("envoy-go", extra_with_lines=extra_with_lines)
                    + go_job("traefik-go")
                )
                status, result = self.check_json(
                    self.root_with_workflow(Path(temporary), workflow)
                )
            self.assertEqual(status, 2)
            self.assertEqual(result["status"], "failed")
            self.assertTrue(any("trusted Go version job" in entry for entry in result["violations"]))

    def test_committed_selector_only_is_rejected(self) -> None:
        workflow = self.valid_workflow().replace(
            'go_report="$(python3 scripts/update-go-version.py --check --json)"',
            'version="$(cat -- .go-version)"',
        )
        with tempfile.TemporaryDirectory() as temporary:
            status, result = self.check_json(self.root_with_workflow(Path(temporary), workflow))
        self.assertEqual(status, 2)
        self.assertTrue(
            any("must not use only the committed selector" in entry for entry in result["violations"])
        )

    def test_wrong_action_pin_and_invalid_version_file_fail_closed(self) -> None:
        wrong_reference = "actions/setup-go@main"
        workflow = (
            "name: CodeQL\n\non:\n  workflow_dispatch:\n\njobs:\n"
            + go_job("envoy-go", setup_reference=wrong_reference)
            + go_job("traefik-go")
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = self.root_with_workflow(Path(temporary), workflow)
            status, result = self.check_json(root)
            (root / ".go-version").write_text("1.027.0\n", encoding="utf-8")
            bad_status, bad_result = self.check_json(root)
        self.assertEqual(status, 2)
        self.assertTrue(any("actions/setup-go" in entry for entry in result["violations"]))
        self.assertEqual((2, "error"), (bad_status, bad_result["status"]))

    def test_setup_go_step_body_ends_at_the_next_step(self) -> None:
        job = go_job("envoy-go") + "      - name: unrelated\n        run: echo unrelated\n"
        steps = checker.setup_go_blocks(job)
        self.assertEqual(len(steps), 1)
        self.assertEqual(checker.SETUP_GO_REFERENCE, steps[0].reference)
        self.assertNotIn("unrelated", steps[0].body)

    def test_symlink_version_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outside = root / "outside"
            outside.write_text("1.27.0\n", encoding="utf-8")
            self.root_with_workflow(root, self.valid_workflow())
            (root / ".go-version").unlink()
            (root / ".go-version").symlink_to(outside)
            status, result = self.check_json(root)
        self.assertEqual((2, "error"), (status, result["status"]))



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
