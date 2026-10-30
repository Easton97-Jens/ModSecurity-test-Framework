#!/usr/bin/env python3
"""Fail closed when a CI job is not running the requested Python interpreter."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
from typing import Sequence


CANONICAL_VERSION_FILENAME = ".python-version"
MAX_VERSION_FILE_BYTES = 64
EXACT_PYTHON_315 = re.compile(r"3\.15\.(?:0|[1-9]\d*)\Z", re.ASCII)


class ContractInputError(ValueError):
    """Raised when a canonical-version input is missing or malformed."""


def exact_version(value: str, source: str) -> str:
    """Return an exact supported version or raise a deterministic input error."""

    if not EXACT_PYTHON_315.fullmatch(value):
        raise ContractInputError(
            f"{source} must contain an exact Python 3.15.N version"
        )
    return value


def read_canonical_version_file() -> str:
    """Read the fixed repository-root version file without following links."""

    try:
        before = os.lstat(CANONICAL_VERSION_FILENAME)
    except OSError as exc:
        raise ContractInputError("cannot inspect canonical .python-version file") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ContractInputError("canonical .python-version file must be a regular non-symlink")
    if before.st_size > MAX_VERSION_FILE_BYTES:
        raise ContractInputError("canonical .python-version file exceeds the size limit")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(CANONICAL_VERSION_FILENAME, flags)
    except OSError as exc:
        raise ContractInputError("cannot open canonical .python-version file safely") from exc
    try:
        after = os.fstat(descriptor)
        if (
            not stat.S_ISREG(after.st_mode)
            or after.st_dev != before.st_dev
            or after.st_ino != before.st_ino
            or after.st_size > MAX_VERSION_FILE_BYTES
        ):
            raise ContractInputError("canonical .python-version file changed or is unsafe")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            content_bytes = handle.read(MAX_VERSION_FILE_BYTES + 1)
    except OSError as exc:
        raise ContractInputError("cannot read canonical .python-version file") from exc
    finally:
        os.close(descriptor)

    if len(content_bytes) > MAX_VERSION_FILE_BYTES:
        raise ContractInputError("canonical .python-version file exceeds the size limit")
    try:
        content = content_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContractInputError("canonical .python-version file is not UTF-8") from exc

    if content.endswith("\n"):
        content = content[:-1]
    if "\n" in content or "\r" in content:
        raise ContractInputError(
            "canonical .python-version file must contain one exact version and an optional final newline"
        )
    return exact_version(content, "canonical .python-version file")


def version_from_info(info: object) -> str:
    """Format the public version fields without relying on implementation details."""

    return f"{info.major}.{info.minor}.{info.micro}"


def same_interpreter(left: str | Path, right: str | Path) -> bool:
    """Use samefile where possible, with a safe canonical-path fallback."""

    try:
        return os.path.samefile(left, right)
    except (AttributeError, OSError):
        return os.path.normcase(os.path.realpath(left)) == os.path.normcase(
            os.path.realpath(right)
        )


def executable_path(argument: str, label: str, violations: list[str]) -> Path | None:
    """Validate a caller-supplied executable path without invoking a shell."""

    candidate = Path(argument)
    if not candidate.is_absolute():
        violations.append(f"{label} must be an absolute path: {argument!r}")
        return None
    if not candidate.is_file():
        violations.append(f"{label} is not a regular file: {candidate}")
        return None
    if not os.access(candidate, os.X_OK):
        violations.append(f"{label} is not executable: {candidate}")
        return None
    return candidate


def check_command_alias(
    command: str,
    reference: Path,
    violations: list[str],
) -> None:
    """Verify a PATH alias by identity only; never execute the alias itself."""

    resolved = shutil.which(command)
    if not resolved:
        violations.append(f"{command} does not resolve on PATH after setup-python")
        return

    resolved_path = Path(resolved)
    if not same_interpreter(resolved_path, reference):
        violations.append(f"{command} resolves to {resolved_path}, not {reference}")


def check_pip(violations: list[str]) -> None:
    """Require the selected interpreter's pip module without using a bare pip command."""

    try:
        completed = subprocess.run(
            [sys.executable, "-m", "pip", "--version"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        violations.append(f"{sys.executable} -m pip --version could not run: {exc}")
        return
    if completed.returncode != 0:
        violations.append(
            f"{sys.executable} -m pip --version exited with status {completed.returncode}"
        )


def evaluate_contract(expected_version: str, expected_python: str | None) -> list[str]:
    """Return every observed contract violation rather than stopping at the first."""

    violations: list[str] = []
    current = version_from_info(sys.version_info)
    if current != expected_version:
        violations.append(
            f"current sys.version is Python {current}, expected {expected_version}"
        )

    reference = executable_path(sys.executable, "sys.executable", violations)
    if reference is None:
        return violations

    for command in ("python", "python3"):
        check_command_alias(command, reference, violations)

    if expected_python is not None:
        action_python = executable_path(expected_python, "--expected-python", violations)
        if action_python is not None:
            if not same_interpreter(action_python, reference):
                violations.append(
                    f"--expected-python is {action_python}, not the current {reference}"
                )

    check_pip(violations)
    return violations


def parser() -> argparse.ArgumentParser:
    argument_parser = argparse.ArgumentParser(
        description="Verify the exact Python interpreter selected by actions/setup-python."
    )
    version_source = argument_parser.add_mutually_exclusive_group()
    version_source.add_argument(
        "--version-file",
        metavar="PATH",
        help="only the literal .python-version is accepted (the default)",
    )
    version_source.add_argument(
        "--expected-version",
        metavar="3.15.N",
        help="validated exact version for the one candidate-validation workflow",
    )
    argument_parser.add_argument(
        "--expected-python",
        metavar="ABSOLUTE_PATH",
        help="actions/setup-python's python-path output to compare with sys.executable",
    )
    argument_parser.add_argument("--json", action="store_true", help="emit a JSON result")
    return argument_parser


def report(status: str, expected_version: str | None, violations: list[str], as_json: bool) -> None:
    """Write either compact machine-readable data or clear actionable diagnostics."""

    if as_json:
        print(
            json.dumps(
                {
                    "status": status,
                    "expected_version": expected_version,
                    "sys_executable": sys.executable,
                    "violations": violations,
                },
                sort_keys=True,
            )
        )
        return

    if status == "valid":
        print(
            "python-interpreter-contract: valid "
            f"(Python {expected_version}; sys.executable={sys.executable})"
        )
        return
    for violation in violations:
        print(f"python-interpreter-contract: {violation}", file=sys.stderr)


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.expected_version is not None:
            expected_version = exact_version(args.expected_version, "--expected-version")
        else:
            if args.version_file not in (None, CANONICAL_VERSION_FILENAME):
                raise ContractInputError(
                    "--version-file must be the literal .python-version"
                )
            expected_version = read_canonical_version_file()
    except ContractInputError as exc:
        report("error", None, [str(exc)], args.json)
        return 2

    violations = evaluate_contract(expected_version, args.expected_python)
    if violations:
        report("violations", expected_version, violations, args.json)
        return 1
    report("valid", expected_version, [], args.json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
