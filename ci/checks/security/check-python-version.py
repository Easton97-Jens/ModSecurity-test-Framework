#!/usr/bin/env python3
"""Validate the Framework's canonical CPython 3.13 workflow contract."""

from __future__ import annotations

import argparse
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from typing import Any

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover - exercised by the CLI only
    yaml = None


CANONICAL_VERSION_FILE = ".python-version"
CANONICAL_VERSION_VALUE = re.compile(r"^3\.13\.(0|[1-9][0-9]*)\n$")
WORKFLOW_SUFFIXES = {".yml", ".yaml"}
CANDIDATE_WORKFLOW = "check-python-version.yml"
CANDIDATE_WORKFLOW_PATH = Path(".github/workflows") / CANDIDATE_WORKFLOW
CANDIDATE_JOB = "candidate-validate"
CANDIDATE_VERSION_FILE = "${{ runner.temp }}/framework-python-3.13-candidate"
SETUP_PYTHON_REFERENCE = "actions/setup-python@"
SETUP_PYTHON_LINE = re.compile(
    r"^\s*(?:-\s*)?uses:\s*['\"]?actions/setup-python@"
    r"(?P<sha>[0-9a-f]{40})['\"]?\s+#\s*(?P<release>v[0-9]+(?:\.[0-9]+){1,3})\s*$"
)
PYTHON_VERSION_KEY = re.compile(r"^\s*python-version\s*:", re.MULTILINE)
HARDCODED_313 = re.compile(r"(?<![0-9A-Za-z_.-])3\.13\.(?:[0-9]+|x|\*)(?![0-9A-Za-z_.-])")
PYTHON_COMMAND = re.compile(
    r"(?<![0-9A-Za-z_.-])(?:python(?:3(?:\.[0-9]+)?)?|pytest|ruff|pyright|mypy|tox|nox)(?![0-9A-Za-z_.-])"
)
PIP_COMMAND = re.compile(r"(?<![0-9A-Za-z_.-])pip3?(?![0-9A-Za-z_.-])")
PYTHON_MODULE_PREFIX = re.compile(
    r"(?:^|[;&|]\s*|\s)python(?:3(?:\.[0-9]+)?)?\s+-m\s*$"
)
MAKE_COMMAND = re.compile(r"(?<![0-9A-Za-z_.-])make(?![0-9A-Za-z_.-])")


if yaml is not None:

    class UniqueKeySafeLoader(yaml.SafeLoader):
        """Safe YAML loader that fails closed on duplicate mapping keys."""


    def _construct_mapping(loader: Any, node: Any, deep: bool = False) -> dict[Any, Any]:
        mapping: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if key in mapping:
                raise yaml.YAMLError(f"duplicate key {key!r}")
            mapping[key] = loader.construct_object(value_node, deep=deep)
        return mapping


    UniqueKeySafeLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping
    )


def regular_file_errors(path: Path, description: str) -> list[str]:
    try:
        details = path.lstat()
    except OSError:
        return [f"{path}: {description} is missing"]
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode):
        return [f"{path}: {description} must be a regular non-symlink file"]
    return []


def canonical_version_errors(root: Path) -> list[str]:
    path = root / CANONICAL_VERSION_FILE
    errors = regular_file_errors(path, CANONICAL_VERSION_FILE)
    if errors:
        return errors
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return [f"{path}: {CANONICAL_VERSION_FILE} cannot be decoded as UTF-8"]
    if CANONICAL_VERSION_VALUE.fullmatch(content) is None:
        return [
            f"{path}: {CANONICAL_VERSION_FILE} must contain exactly one stable "
            "3.13.<numeric patch> newline-terminated value"
        ]
    return []


def workflow_paths(root: Path) -> tuple[list[Path], list[str]]:
    directory = root / ".github" / "workflows"
    try:
        resolved_directory = directory.resolve(strict=True)
    except OSError:
        return [], [f"{directory}: workflow directory is missing"]
    if not resolved_directory.is_dir() or directory.is_symlink():
        return [], [f"{directory}: workflow directory must be a real directory"]

    paths: list[Path] = []
    errors: list[str] = []
    for path in sorted(directory.rglob("*")):
        if path.suffix not in WORKFLOW_SUFFIXES:
            continue
        try:
            resolved = path.resolve(strict=True)
        except OSError:
            errors.append(f"{path}: workflow path cannot be resolved")
            continue
        if not resolved.is_relative_to(resolved_directory):
            errors.append(f"{path}: workflow path escapes .github/workflows")
            continue
        file_errors = regular_file_errors(path, "workflow")
        errors.extend(file_errors)
        if not file_errors:
            paths.append(path)
    if not paths and not errors:
        errors.append(f"{directory}: no .yml or .yaml workflow files found")
    return paths, errors


def load_yaml(path: Path) -> tuple[dict[str, Any] | None, list[str]]:
    if yaml is None:
        return None, [
            f"{path}: blocked: PyYAML is required; install the reviewed Framework dependencies"
        ]
    try:
        content = path.read_text(encoding="utf-8")
        parsed = yaml.load(content, Loader=UniqueKeySafeLoader)
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        return None, [f"{path}: invalid workflow YAML: {exc}"]
    if not isinstance(parsed, dict):
        return None, [f"{path}: workflow YAML must be a mapping"]
    return parsed, []


def setup_reference_errors(path: Path, text: str) -> list[str]:
    errors: list[str] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if SETUP_PYTHON_REFERENCE not in line:
            continue
        if SETUP_PYTHON_LINE.fullmatch(line) is None:
            errors.append(
                f"{path}:{line_number}: setup-python must use a full lowercase SHA "
                "and adjacent vX.Y.Z release comment"
            )
    return errors


def hardcoded_version_errors(path: Path, text: str) -> list[str]:
    errors: list[str] = []
    if PYTHON_VERSION_KEY.search(text):
        errors.append(
            f"{path}: python-version is forbidden; use {CANONICAL_VERSION_FILE} instead"
        )
    if HARDCODED_313.search(text):
        errors.append(
            f"{path}: hard-coded CPython 3.13 patch values are forbidden in workflows"
        )
    return errors


def normalized_uses(step: dict[str, Any]) -> str | None:
    value = step.get("uses")
    return value if isinstance(value, str) else None


def is_setup_python(step: dict[str, Any]) -> bool:
    reference = normalized_uses(step)
    return reference is not None and reference.startswith(SETUP_PYTHON_REFERENCE)


def setup_kind(
    root: Path, path: Path, job_name: str, step: dict[str, Any]
) -> tuple[str | None, list[str]]:
    errors: list[str] = []
    options = step.get("with")
    if not isinstance(options, dict):
        return None, [f"{path}: job {job_name!r} setup-python must have a with mapping"]
    if "python-version" in options:
        errors.append(
            f"{path}: job {job_name!r} setup-python must not select python-version directly"
        )
    if options.get("check-latest") is not False:
        errors.append(
            f"{path}: job {job_name!r} setup-python must set check-latest: false"
        )
    version_file = options.get("python-version-file")
    if version_file == CANONICAL_VERSION_FILE:
        return "canonical", errors
    if (
        path == root / CANDIDATE_WORKFLOW_PATH
        and job_name == CANDIDATE_JOB
        and version_file == CANDIDATE_VERSION_FILE
    ):
        return "candidate", errors
    errors.append(
        f"{path}: job {job_name!r} setup-python must use "
        f"python-version-file: {CANONICAL_VERSION_FILE!r}"
    )
    return None, errors


def bare_pip_errors(path: Path, job_name: str, step_number: int, run: str) -> list[str]:
    errors: list[str] = []
    for match in PIP_COMMAND.finditer(run):
        prefix = run[max(0, match.start() - 160) : match.start()]
        if PYTHON_MODULE_PREFIX.search(prefix) is None:
            errors.append(
                f"{path}: job {job_name!r} step {step_number} invokes bare "
                f"{match.group(0)!r}; use python -m pip"
            )
    return errors


def makefile_uses_python(root: Path) -> bool:
    path = root / "Makefile"
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return False
    return "$(PYTHON)" in content or "python3" in content or "python -m" in content


def run_uses_python(run: str, *, indirect_make_python: bool) -> bool:
    return (
        PYTHON_COMMAND.search(run) is not None
        or PIP_COMMAND.search(run) is not None
        or (indirect_make_python and MAKE_COMMAND.search(run) is not None)
    )


def matrix_errors(path: Path, job_name: str, job: dict[str, Any]) -> list[str]:
    strategy = job.get("strategy")
    if not isinstance(strategy, dict):
        return []
    matrix = strategy.get("matrix")
    if not isinstance(matrix, dict):
        return []
    errors: list[str] = []
    for key in matrix:
        if str(key).lower().replace("_", "-") in {"python", "python-version"}:
            errors.append(
                f"{path}: job {job_name!r} must not select Python through a matrix"
            )
    return errors


def local_reusable_errors(root: Path, path: Path, job_name: str, job: dict[str, Any]) -> list[str]:
    reusable = job.get("uses")
    if reusable is None:
        return []
    if not isinstance(reusable, str):
        return [f"{path}: job {job_name!r} reusable workflow reference must be a string"]
    if not reusable.startswith("./.github/workflows/"):
        return [
            f"{path}: job {job_name!r} external reusable workflow cannot establish "
            "the Framework Python contract"
        ]
    relative = reusable.removeprefix("./")
    candidate = root / PurePosixPath(relative)
    try:
        resolved_root = root.resolve(strict=True)
        resolved = candidate.resolve(strict=True)
    except OSError:
        return [f"{path}: job {job_name!r} reusable workflow target is missing"]
    if (
        not resolved.is_relative_to(resolved_root / ".github" / "workflows")
        or candidate.suffix not in WORKFLOW_SUFFIXES
        or candidate.is_symlink()
    ):
        return [f"{path}: job {job_name!r} reusable workflow target is unsafe"]
    return []


def job_errors(
    root: Path, path: Path, job_name: str, job: Any, *, indirect_make_python: bool
) -> list[str]:
    if not isinstance(job, dict):
        return [f"{path}: job {job_name!r} must be a mapping"]
    errors = matrix_errors(path, job_name, job)
    if "uses" in job:
        errors.extend(local_reusable_errors(root, path, job_name, job))
        if "steps" in job:
            errors.append(f"{path}: job {job_name!r} must not mix reusable uses and steps")
        return errors

    steps = job.get("steps")
    if not isinstance(steps, list):
        return [*errors, f"{path}: job {job_name!r} must define a steps list"]

    canonical_setup_seen = False
    candidate_setup_seen = False
    for step_number, raw_step in enumerate(steps, start=1):
        if not isinstance(raw_step, dict):
            errors.append(f"{path}: job {job_name!r} step {step_number} must be a mapping")
            continue
        if is_setup_python(raw_step):
            kind, setup_errors = setup_kind(root, path, job_name, raw_step)
            errors.extend(setup_errors)
            if kind == "canonical":
                if candidate_setup_seen:
                    errors.append(
                        f"{path}: job {job_name!r} cannot select canonical Python after candidate Python"
                    )
                canonical_setup_seen = True
            elif kind == "candidate":
                if not canonical_setup_seen:
                    errors.append(
                        f"{path}: job {job_name!r} candidate Python must follow canonical setup"
                    )
                candidate_setup_seen = True
        run = raw_step.get("run")
        if not isinstance(run, str):
            continue
        errors.extend(bare_pip_errors(path, job_name, step_number, run))
        if run_uses_python(run, indirect_make_python=indirect_make_python) and not canonical_setup_seen:
            errors.append(
                f"{path}: job {job_name!r} step {step_number} invokes Python before reviewed setup-python"
            )
    return errors


def workflow_errors(root: Path, path: Path, *, indirect_make_python: bool) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return [f"{path}: workflow cannot be decoded as UTF-8"]
    document, errors = load_yaml(path)
    errors.extend(setup_reference_errors(path, text))
    errors.extend(hardcoded_version_errors(path, text))
    if document is None:
        return errors
    jobs = document.get("jobs")
    if not isinstance(jobs, dict):
        return [*errors, f"{path}: workflow must define jobs as a mapping"]
    for raw_name, job in jobs.items():
        errors.extend(
            job_errors(
                root,
                path,
                str(raw_name),
                job,
                indirect_make_python=indirect_make_python,
            )
        )
    return errors


def resolve_root(root: Path) -> Path:
    try:
        resolved = root.resolve(strict=True)
    except OSError as exc:
        raise ValueError("--root must resolve to an existing directory") from exc
    if not resolved.is_dir():
        raise ValueError("--root must resolve to an existing directory")
    return resolved


def validate(root: Path) -> list[str]:
    errors = canonical_version_errors(root)
    paths, path_errors = workflow_paths(root)
    errors.extend(path_errors)
    indirect_make_python = makefile_uses_python(root)
    for path in paths:
        errors.extend(workflow_errors(root, path, indirect_make_python=indirect_make_python))
    return errors


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[3])
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        root = resolve_root(args.root)
    except ValueError as exc:
        print(f"Python version contract violations:\n- {exc}")
        return 2
    errors = validate(root)
    if errors:
        print("Python version contract violations:")
        print("\n".join(f"- {item}" for item in errors))
        return 1
    print("Python version contract passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
