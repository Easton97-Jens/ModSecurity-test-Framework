#!/usr/bin/env python3
"""Write a bounded GitHub summary of one real CRS/no-MRTS workflow cell.

The report deliberately consumes only fixed GitHub step outcomes.  It does not
parse same-UID writable raw runtime paths, and it never turns a missing runtime
record into a successful connector capability claim.
"""

from __future__ import annotations

import argparse
import os
import re
import stat
from collections.abc import Mapping, Sequence
from pathlib import Path


CONNECTORS = frozenset(("apache", "envoy", "haproxy", "lighttpd", "traefik"))
VALID_OUTCOMES = frozenset(("success", "failure", "skipped", "cancelled"))
STAGES = (
    ("checkout", "Checkout exact Parent head", "CHECKOUT_OUTCOME"),
    ("setup_python", "Locked Python toolchain", "SETUP_PYTHON_OUTCOME"),
    ("verify_python", "Python interpreter contract", "VERIFY_PYTHON_OUTCOME"),
    ("verify_revisions", "Parent/Framework/MRTS revisions", "VERIFY_REVISIONS_OUTCOME"),
    ("install_dependencies", "Hash-locked Framework dependency", "INSTALL_DEPENDENCIES_OUTCOME"),
    ("verify_cell", "Fixed runtime-cell policy", "VERIFY_CELL_OUTCOME"),
    ("initialize_roots", "Private runtime roots", "INITIALIZE_ROOTS_OUTCOME"),
    ("prepare_crs", "Workflow CRS source preparation", "PREPARE_CRS_OUTCOME"),
    ("runtime", "Real connector runtime target", "RUNTIME_OUTCOME"),
    ("upload_evidence", "Evidence publication", "UPLOAD_EVIDENCE_OUTCOME"),
)
SUMMARY_DIRECTORY_NAME = "_runner_file_commands"
SUMMARY_FILE_NAME = re.compile(r"^step_summary_[A-Za-z0-9_-]+$", re.ASCII)
UNSAFE_SUMMARY_PATH = "GitHub step summary path is unsafe"


def require_connector(value: str) -> str:
    if value not in CONNECTORS:
        raise ValueError("connector is outside the fixed CRS/no-MRTS runtime set")
    return value


def outcomes_from_environment(environment: Mapping[str, str]) -> dict[str, str]:
    outcomes: dict[str, str] = {}
    for key, _label, environment_name in STAGES:
        value = environment.get(environment_name, "")
        if value not in VALID_OUTCOMES:
            raise ValueError(f"{environment_name} is not a GitHub step outcome")
        outcomes[key] = value
    return outcomes


def rendered_outcome(connector: str, stage: str, outcome: str) -> str:
    del connector, stage
    return outcome


def outcome_counts(outcomes: Mapping[str, str]) -> dict[str, int]:
    counts = {
        "passed": 0,
        "failed": 0,
        "skipped": 0,
        "cancelled": 0,
        "security_skipped": 0,
    }
    for stage, _label, _environment_name in STAGES:
        outcome = outcomes[stage]
        if outcome == "success":
            counts["passed"] += 1
        elif outcome == "failure":
            counts["failed"] += 1
        elif outcome == "skipped":
            counts["skipped"] += 1
        else:
            counts["cancelled"] += 1
    return counts


def first_nonpassing_stage(connector: str, outcomes: Mapping[str, str]) -> str:
    for stage, label, _environment_name in STAGES:
        outcome = rendered_outcome(connector, stage, outcomes[stage])
        if outcome != "success":
            return label
    return "none"


def runtime_bundle_outcome(outcome: str) -> str:
    if outcome == "success":
        return "PASS — real target completed its fail-closed runtime assertions"
    if outcome == "failure":
        return "FAIL — runtime assertions did not complete"
    if outcome == "skipped":
        return "MISSING — runtime target did not run"
    return "CANCELLED — runtime target did not complete"


def render_summary(connector: str, outcomes: Mapping[str, str]) -> str:
    connector = require_connector(connector)
    if set(outcomes) != {stage for stage, _label, _environment_name in STAGES}:
        raise ValueError("summary outcomes do not match the fixed workflow stage set")
    if any(outcome not in VALID_OUTCOMES for outcome in outcomes.values()):
        raise ValueError("summary outcomes contain an invalid state")
    counts = outcome_counts(outcomes)
    rows = [
        f"### {connector} — CRS/no-MRTS runtime overview",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| Stages passed | `{counts['passed']}` |",
        f"| Stages failed | `{counts['failed']}` |",
        f"| Stages skipped | `{counts['skipped']}` |",
        f"| Stages cancelled | `{counts['cancelled']}` |",
        f"| Security-policy skips | `{counts['security_skipped']}` |",
        f"| First non-passing stage | `{first_nonpassing_stage(connector, outcomes)}` |",
        "",
        "| Stage | Actual outcome |",
        "| --- | --- |",
    ]
    rows.extend(
        f"| {label} | `{rendered_outcome(connector, stage, outcomes[stage])}` |"
        for stage, label, _environment_name in STAGES
    )
    rows.extend(
        (
            "",
            "| Real runtime assertion bundle | Outcome |",
            "| --- | --- |",
            "| Config/load, start, allow request, CRS block/rule, bypass, no-MRTS, cleanup | "
            f"`{runtime_bundle_outcome(outcomes['runtime'])}` |",
            "",
            "The table reports observed GitHub step outcomes only. A missing or failed runtime "
            "target is never promoted to a connector capability pass. Evidence publication is "
            "reported as its actual verified upload outcome for every connector.",
            "",
        )
    )
    return "\n".join(rows)


def _write_summary(descriptor: int, content: str) -> None:
    data = content.encode("utf-8")
    while data:
        written = os.write(descriptor, data)
        if written <= 0:
            raise OSError("cannot append GitHub step summary")
        data = data[written:]


def _safe_open_flags() -> tuple[int, int, int, int]:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    nonblock = getattr(os, "O_NONBLOCK", None)
    if (
        not isinstance(nofollow, int)
        or not isinstance(directory, int)
        or not isinstance(nonblock, int)
    ):
        raise ValueError("GitHub step summary safe-open capability is unavailable")
    return nofollow, directory, nonblock, getattr(os, "O_CLOEXEC", 0)


def _open_directory_without_symlinks(path: Path) -> int:
    if (
        not path.is_absolute()
        or path == Path("/")
        or os.path.normpath(os.fspath(path)) != os.fspath(path)
    ):
        raise ValueError(UNSAFE_SUMMARY_PATH)
    nofollow, directory, _nonblock, close_on_exec = _safe_open_flags()
    descriptor = -1
    try:
        descriptor = os.open(path.anchor, os.O_RDONLY | directory | close_on_exec)
        for component in path.parts[1:]:
            next_descriptor = os.open(
                component,
                os.O_RDONLY | directory | nofollow | close_on_exec,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        raise ValueError(UNSAFE_SUMMARY_PATH) from error
    return descriptor


def _require_trusted_directory(descriptor: int) -> None:
    details = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(details.st_mode)
        or details.st_uid != os.geteuid()
        or details.st_mode & 0o022
    ):
        raise ValueError("GitHub step summary directory is unsafe")


def _open_github_step_summary(environment: Mapping[str, str]) -> int:
    runner_temp_value = environment.get("RUNNER_TEMP", "")
    summary_value = environment.get("GITHUB_STEP_SUMMARY", "")
    runner_temp = Path(runner_temp_value)
    runner_descriptor = -1
    summary_parent_descriptor = -1
    summary_descriptor = -1
    try:
        if not summary_value:
            raise ValueError("GitHub step summary path is unavailable")
        nofollow, directory, nonblock, close_on_exec = _safe_open_flags()
        runner_descriptor = _open_directory_without_symlinks(runner_temp)
        _require_trusted_directory(runner_descriptor)
        summary_path = Path(summary_value)
        if (
            not summary_path.is_absolute()
            or os.path.normpath(summary_value) != summary_value
        ):
            raise ValueError(UNSAFE_SUMMARY_PATH)
        try:
            relative = summary_path.relative_to(runner_temp)
        except ValueError as error:
            raise ValueError(UNSAFE_SUMMARY_PATH) from error
        if (
            len(relative.parts) != 2
            or relative.parts[0] != SUMMARY_DIRECTORY_NAME
            or not SUMMARY_FILE_NAME.fullmatch(relative.parts[1])
        ):
            raise ValueError(UNSAFE_SUMMARY_PATH)
        summary_parent_descriptor = os.open(
            SUMMARY_DIRECTORY_NAME,
            os.O_RDONLY | directory | nofollow | close_on_exec,
            dir_fd=runner_descriptor,
        )
        _require_trusted_directory(summary_parent_descriptor)
        summary_descriptor = os.open(
            relative.parts[1],
            os.O_WRONLY | os.O_APPEND | nofollow | nonblock | close_on_exec,
            dir_fd=summary_parent_descriptor,
        )
        details = os.fstat(summary_descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != os.geteuid()
            or details.st_mode & 0o022
            or details.st_nlink != 1
        ):
            raise ValueError("GitHub step summary file is unsafe")
        result = summary_descriptor
        summary_descriptor = -1
        return result
    except OSError as error:
        raise ValueError(UNSAFE_SUMMARY_PATH) from error
    finally:
        if runner_descriptor >= 0:
            os.close(runner_descriptor)
        if summary_parent_descriptor >= 0:
            os.close(summary_parent_descriptor)
        if summary_descriptor >= 0:
            os.close(summary_descriptor)


def append_github_step_summary(environment: Mapping[str, str], content: str) -> None:
    descriptor = _open_github_step_summary(environment)
    try:
        _write_summary(descriptor, content)
    finally:
        os.close(descriptor)


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--connector", required=True)
    args = parser.parse_args(arguments)
    try:
        append_github_step_summary(
            os.environ,
            render_summary(args.connector, outcomes_from_environment(os.environ)),
        )
    except (OSError, ValueError) as error:
        print(f"FAIL: {error}", file=os.sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
