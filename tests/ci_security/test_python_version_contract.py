from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[2]
CHECKER_PATH = ROOT / "ci/checks/security/check-python-version.py"
SETUP_SHA = "0" * 40


def load_checker():
    spec = importlib.util.spec_from_file_location(
        "python_version_contract", CHECKER_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {CHECKER_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CHECKER = load_checker()


def setup_step(version_file: str = ".python-version") -> str:
    return f"""\
      - name: Set up reviewed Python
        uses: actions/setup-python@{SETUP_SHA} # v6.3.0
        with:
          python-version-file: \"{version_file}\"
          check-latest: false
"""


def workflow(name: str, job: str) -> str:
    header = f"""\
name: {name}
on: workflow_dispatch
permissions:
  contents: read
concurrency:
  group: {name}
  cancel-in-progress: true
defaults:
  run:
    shell: bash
jobs:
"""
    return header + textwrap.indent(job.strip("\n"), "  ") + "\n"


class PythonVersionContractTest(unittest.TestCase):
    def make_root(self, directory: Path, version: str = "3.13.14\n") -> Path:
        root = directory / "framework"
        (root / ".github/workflows").mkdir(parents=True)
        (root / ".python-version").write_text(version, encoding="utf-8")
        (root / "Makefile").write_text("PYTHON ?= python3\n", encoding="utf-8")
        return root

    def write_workflow(self, root: Path, name: str, content: str) -> Path:
        path = root / ".github/workflows" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def test_current_framework_contract_passes(self) -> None:
        result = subprocess.run(
            [sys.executable, str(CHECKER_PATH), "--root", str(ROOT)],
            check=False,
            capture_output=True,
            encoding="utf-8",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_canonical_file_requires_one_exact_stable_value(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_root(Path(temporary_directory), "3.13.014\n")
            errors = CHECKER.canonical_version_errors(root)
            self.assertTrue(any("stable 3.13" in error for error in errors))
            (root / ".python-version").write_text("3.13.14\nextra\n", encoding="utf-8")
            errors = CHECKER.canonical_version_errors(root)
            self.assertTrue(any("exactly one" in error for error in errors))

    def test_recurses_yml_and_yaml_and_rejects_pre_setup_python_and_bare_pip(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_root(Path(temporary_directory))
            self.write_workflow(
                root,
                "nested/valid.yaml",
                workflow(
                    "valid",
                    """\
check:
  runs-on: ubuntu-latest
  timeout-minutes: 5
  steps:
"""
                    + setup_step()
                    + "      - run: python3 -m pip --version\n",
                ),
            )
            self.write_workflow(
                root,
                "unsafe.yml",
                workflow(
                    "unsafe",
                    """\
check:
  runs-on: ubuntu-latest
  timeout-minutes: 5
  steps:
      - run: python3 -c 'print(1)'\n      - run: pip install fixture\n""",
                ),
            )
            errors = CHECKER.validate(root)
            self.assertTrue(
                any(
                    "unsafe.yml" in error and "before reviewed" in error
                    for error in errors
                )
            )
            self.assertTrue(
                any("unsafe.yml" in error and "bare 'pip'" in error for error in errors)
            )
            self.assertFalse(
                any("nested/valid.yaml" in error for error in errors), "\n".join(errors)
            )

    def test_rejects_hardcoded_versions_matrix_and_external_reusable_workflows(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_root(Path(temporary_directory))
            self.write_workflow(
                root,
                "matrix.yml",
                workflow(
                    "matrix",
                    f"""\
check:
  runs-on: ubuntu-latest
  timeout-minutes: 5
  strategy:
    matrix:
      python: [\"3.13.14\"]
  steps:
      - uses: actions/setup-python@{SETUP_SHA} # v6.3.0
        with:
          python-version: \"3.13.14\"
          check-latest: false
""",
                ),
            )
            self.write_workflow(
                root,
                "reusable.yml",
                workflow(
                    "reusable",
                    """\
delegated:
  uses: example/unknown/.github/workflows/python.yml@v1
""",
                ),
            )
            errors = CHECKER.validate(root)
            self.assertTrue(any("hard-coded" in error for error in errors))
            self.assertTrue(
                any(
                    "must not select Python through a matrix" in error
                    for error in errors
                )
            )
            self.assertTrue(
                any("external reusable workflow" in error for error in errors)
            )

    def test_local_reusable_workflow_is_scanned_and_must_hold_the_contract(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_root(Path(temporary_directory))
            self.write_workflow(
                root,
                "reusable.yml",
                workflow(
                    "reusable caller",
                    """\
delegated:
  uses: ./.github/workflows/reusable-target.yaml
""",
                ),
            )
            self.write_workflow(
                root,
                "reusable-target.yaml",
                workflow(
                    "reusable target",
                    """\
check:
  runs-on: ubuntu-latest
  timeout-minutes: 5
  steps:
"""
                    + setup_step()
                    + "      - run: python3 -m pip --version\n",
                ),
            )
            self.assertEqual(CHECKER.validate(root), [])

    def test_candidate_runtime_exception_is_narrow_and_requires_canonical_setup_first(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_root(Path(temporary_directory))
            candidate_job = (
                """\
candidate-validate:
  runs-on: ubuntu-latest
  timeout-minutes: 5
  steps:
"""
                + setup_step()
                + setup_step(CHECKER.CANDIDATE_VERSION_FILE)
                + "      - run: python3 -VV\n"
            )
            candidate_path = self.write_workflow(
                root,
                CHECKER.CANDIDATE_WORKFLOW,
                workflow("candidate", candidate_job),
            )
            errors = CHECKER.workflow_errors(
                root, candidate_path, indirect_make_python=True
            )
            self.assertEqual(errors, [], "\n".join(errors))

            other_path = self.write_workflow(
                root,
                "ordinary.yml",
                workflow(
                    "ordinary", candidate_job.replace("candidate-validate", "ordinary")
                ),
            )
            errors = CHECKER.workflow_errors(
                root, other_path, indirect_make_python=True
            )
            self.assertTrue(any("python-version-file" in error for error in errors))

            nested_path = self.write_workflow(
                root,
                f"nested/{CHECKER.CANDIDATE_WORKFLOW}",
                workflow("nested candidate", candidate_job),
            )
            errors = CHECKER.workflow_errors(
                root, nested_path, indirect_make_python=True
            )
            self.assertTrue(any("python-version-file" in error for error in errors))

            reversed_job = candidate_job.replace(
                setup_step() + setup_step(CHECKER.CANDIDATE_VERSION_FILE),
                setup_step(CHECKER.CANDIDATE_VERSION_FILE) + setup_step(),
            )
            reversed_path = self.write_workflow(
                root,
                CHECKER.CANDIDATE_WORKFLOW,
                workflow("reversed", reversed_job),
            )
            errors = CHECKER.workflow_errors(
                root, reversed_path, indirect_make_python=True
            )
            self.assertTrue(any("must follow canonical" in error for error in errors))

    def test_osv_pull_request_head_bootstrap_is_narrow_and_counts_as_reviewed_setup(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_root(Path(temporary_directory))
            osv_job = (
                """\
pull-request-head:
  runs-on: ubuntu-latest
  timeout-minutes: 5
  steps:
"""
                + setup_step(CHECKER.OSV_PR_HEAD_VERSION_FILE)
                + "      - run: python3 -VV\n"
            )
            osv_path = self.write_workflow(
                root,
                CHECKER.OSV_WORKFLOW,
                workflow("OSV pull-request head", osv_job),
            )
            self.assertEqual(
                CHECKER.workflow_errors(root, osv_path, indirect_make_python=True),
                [],
            )

            ordinary_path = self.write_workflow(
                root,
                "ordinary.yml",
                workflow("ordinary", osv_job),
            )
            errors = CHECKER.workflow_errors(
                root, ordinary_path, indirect_make_python=True
            )
            self.assertTrue(any("python-version-file" in error for error in errors))

            duplicate_setup = osv_job.replace(
                setup_step(CHECKER.OSV_PR_HEAD_VERSION_FILE),
                setup_step(CHECKER.OSV_PR_HEAD_VERSION_FILE) + setup_step(),
            )
            duplicate_path = self.write_workflow(
                root,
                CHECKER.OSV_WORKFLOW,
                workflow("duplicate OSV setup", duplicate_setup),
            )
            errors = CHECKER.workflow_errors(
                root, duplicate_path, indirect_make_python=True
            )
            self.assertTrue(
                any("without another Python selection" in error for error in errors)
            )

    def test_indirect_make_python_requires_reviewed_setup_and_setup_pin_comment(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_root(Path(temporary_directory))
            unsafe_path = self.write_workflow(
                root,
                "make.yml",
                workflow(
                    "make",
                    """\
check:
  runs-on: ubuntu-latest
  timeout-minutes: 5
  steps:
      - run: make lint
""",
                ),
            )
            errors = CHECKER.workflow_errors(
                root, unsafe_path, indirect_make_python=True
            )
            self.assertTrue(any("before reviewed" in error for error in errors))

            pin_path = self.write_workflow(
                root,
                "pin.yml",
                workflow(
                    "pin",
                    """\
check:
  runs-on: ubuntu-latest
  timeout-minutes: 5
  steps:
      - uses: actions/setup-python@v6
        with:
          python-version-file: \".python-version\"
          check-latest: false
""",
                ),
            )
            errors = CHECKER.workflow_errors(root, pin_path, indirect_make_python=True)
            self.assertTrue(any("full lowercase SHA" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
