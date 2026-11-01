#!/usr/bin/env python3
"""Classify one direct CI check and persist its status before Make sees it."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
from typing import Sequence


VALID_STATUSES = frozenset(
    {"passed", "failed", "blocked", "not_applicable", "not_executed"}
)
BLOCKED_EXIT_CODE = 77
CHECK_IDENTIFIER_RE = re.compile(r"^[a-z][a-z0-9_]*$")
APACHE_DEVELOPMENT_REASON = "apache_development_prerequisite"


@dataclass(frozen=True)
class StatusOutput:
    path: Path
    directory_descriptor: int


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run a direct check, write a machine-readable status record, and "
            "allow only explicitly approved blocked/not-applicable outcomes."
        )
    )
    parser.add_argument("--check", required=True, help="stable check identifier")
    parser.add_argument(
        "--allow-blocked-reason",
        action="append",
        default=[],
        metavar="REASON",
        help=(
            "return success only for an exact parent-issued blocked disposition "
            "with this reason"
        ),
    )
    parser.add_argument(
        "--blocked-if-missing-apache-development",
        action="store_true",
        help=(
            "do not run the child when this parent process cannot resolve an "
            "executable APXS with a usable httpd.h; record the structured "
            f"{APACHE_DEVELOPMENT_REASON} disposition instead"
        ),
    )
    parser.add_argument(
        "--allow-not-applicable",
        action="store_true",
        help="return success only for an explicit not_applicable disposition",
    )
    disposition = parser.add_mutually_exclusive_group()
    disposition.add_argument(
        "--not-applicable",
        metavar="REASON",
        help="record an explicit not_applicable disposition without running a command",
    )
    disposition.add_argument(
        "--not-executed",
        metavar="REASON",
        help="record a not_executed disposition without running a command",
    )
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="command to execute, introduced by --",
    )
    args = parser.parse_args(argv)
    if CHECK_IDENTIFIER_RE.fullmatch(args.check) is None:
        parser.error("--check must use lowercase letters, digits, and underscores")
    for reason in args.allow_blocked_reason:
        if CHECK_IDENTIFIER_RE.fullmatch(reason) is None:
            parser.error("--allow-blocked-reason must use lowercase letters, digits, and underscores")
    if args.blocked_if_missing_apache_development and (
        args.not_applicable is not None or args.not_executed is not None
    ):
        parser.error(
            "--blocked-if-missing-apache-development cannot be combined with an explicit disposition"
        )
    if args.not_applicable is None and args.not_executed is None:
        if args.command[:1] == ["--"]:
            args.command = args.command[1:]
        if not args.command:
            parser.error("a command is required unless an explicit disposition is used")
    elif args.command:
        parser.error("an explicit disposition cannot be combined with a command")
    return args


def prepare_status_output(check: str) -> StatusOutput:
    build_root_value = os.environ.get("BUILD_ROOT")
    if not build_root_value:
        raise ValueError("BUILD_ROOT must be set for status records")

    build_root = Path(build_root_value)
    if not build_root.is_absolute() or ".." in build_root.parts:
        raise ValueError("BUILD_ROOT must be an absolute canonical path")

    status_root = build_root / "check-status"
    repository_root = connector_root()
    resolved_status_root = status_root.resolve(strict=False)
    if resolved_status_root != status_root:
        raise ValueError(f"status root must not use symbolic links: {status_root}")
    try:
        resolved_status_root.relative_to(repository_root)
    except ValueError:
        pass
    else:
        raise ValueError(f"status root must stay outside the checkout: {status_root}")

    resolved_status_root.mkdir(parents=True, exist_ok=True)
    if (
        not resolved_status_root.is_dir()
        or resolved_status_root.is_symlink()
        or resolved_status_root.resolve() != resolved_status_root
    ):
        raise ValueError(f"status root must be a non-symlink directory: {status_root}")

    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise ValueError("safe status-file output requires O_NOFOLLOW support")
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | no_follow
    try:
        directory_descriptor = os.open(resolved_status_root, directory_flags)
    except OSError as error:
        raise ValueError(f"could not safely open status root: {status_root}") from error
    return StatusOutput(
        path=resolved_status_root / f"{check.replace('_', '-')}.json",
        directory_descriptor=directory_descriptor,
    )


def write_status(status_output: StatusOutput, record: dict[str, object]) -> None:
    path = status_output.path
    directory_descriptor = status_output.directory_descriptor
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise ValueError("safe status-file output requires O_NOFOLLOW support")

    temporary_name: str | None = None
    try:
        try:
            target_mode = os.stat(
                path.name, dir_fd=directory_descriptor, follow_symlinks=False
            ).st_mode
        except FileNotFoundError:
            target_mode = None
        if target_mode is not None and stat.S_ISLNK(target_mode):
            raise ValueError(f"status file must not be a symlink: {path}")

        for _ in range(100):
            temporary_name = f".{path.name}.{secrets.token_hex(16)}.tmp"
            try:
                file_descriptor = os.open(
                    temporary_name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | no_follow,
                    0o600,
                    dir_fd=directory_descriptor,
                )
            except FileExistsError:
                continue
            break
        else:
            raise ValueError(f"could not allocate a status temporary file: {path}")

        with os.fdopen(file_descriptor, "w", encoding="utf-8") as handle:
            json.dump(record, handle, indent=2, sort_keys=True)
            handle.write("\n")
        try:
            target_mode = os.stat(
                path.name, dir_fd=directory_descriptor, follow_symlinks=False
            ).st_mode
        except FileNotFoundError:
            target_mode = None
        if target_mode is not None and stat.S_ISLNK(target_mode):
            raise ValueError(f"status file must not be a symlink: {path}")
        os.replace(
            temporary_name,
            path.name,
            src_dir_fd=directory_descriptor,
            dst_dir_fd=directory_descriptor,
        )
    finally:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name, dir_fd=directory_descriptor)
            except FileNotFoundError:
                pass


def run_command(command: Sequence[str]) -> int:
    try:
        completed = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError:
        return 127
    sys.stdout.write(completed.stdout)
    sys.stderr.write(completed.stderr)
    return completed.returncode


def apache_development_candidates() -> tuple[str, ...]:
    """Return the parent-controlled APXS candidate order for the lint preflight."""
    candidates: tuple[str, ...] = ("apxs", "apxs2")
    for variable in ("APXS_BIN", "APXS"):
        value = os.environ.get(variable)
        if value:
            candidates = (value,)
            break
    else:
        configured_candidates = os.environ.get("CI_APXS_BIN_CANDIDATES")
        if configured_candidates:
            try:
                candidates = tuple(shlex.split(configured_candidates))
            except ValueError:
                candidates = ()
    return candidates


def resolve_executable(candidate: str) -> Path | None:
    """Resolve one APXS candidate without treating child output as input."""
    expanded = os.path.expanduser(os.path.expandvars(candidate))
    if "/" in expanded:
        path = Path(expanded)
        if not path.is_absolute():
            path = Path.cwd() / path
    else:
        resolved = shutil.which(expanded)
        if resolved is None:
            return None
        path = Path(resolved)
    if not path.is_file() or not os.access(path, os.X_OK):
        return None
    return path


def apache_development_available() -> bool:
    """Check the Apache development prerequisite before the child starts.

    The runner owns this classification.  It accepts only an executable APXS
    candidate that resolves an absolute include directory containing ``httpd.h``.
    Diagnostic output from the later child command is never part of this
    decision.
    """
    for candidate in apache_development_candidates():
        apxs = resolve_executable(candidate)
        if apxs is None:
            continue
        try:
            completed = subprocess.run(
                [str(apxs), "-q", "INCLUDEDIR"],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        include_directory = Path(completed.stdout.strip())
        if (
            completed.returncode == 0
            and include_directory.is_absolute()
            and include_directory.is_dir()
            and (include_directory / "httpd.h").is_file()
        ):
            return True
    return False


def status_for_exit_code(exit_code: int) -> str:
    if exit_code == 0:
        return "passed"
    if exit_code == BLOCKED_EXIT_CODE:
        return "blocked"
    return "failed"


def workflow_exit_code(
    status: str,
    command_exit_code: int | None,
    allow_blocked: bool,
    allow_not_applicable: bool,
) -> int:
    if status == "passed":
        return 0
    if status == "blocked":
        return 0 if allow_blocked else BLOCKED_EXIT_CODE
    if status == "not_applicable":
        return 0 if allow_not_applicable else 1
    if status == "not_executed":
        return 1
    if command_exit_code is not None and command_exit_code > 0:
        return command_exit_code
    return 1


def main(argv: Sequence[str]) -> int:
    args = parse_args(argv)
    try:
        status_output = prepare_status_output(args.check)
    except ValueError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2

    try:
        command_exit_code: int | None
        reason: str | None = None
        status_source: str
        if args.not_applicable is not None:
            status = "not_applicable"
            command_exit_code = None
            reason = args.not_applicable
            status_source = "parent_explicit"
        elif args.not_executed is not None:
            status = "not_executed"
            command_exit_code = None
            reason = args.not_executed
            status_source = "parent_explicit"
        elif (
            args.blocked_if_missing_apache_development
            and not apache_development_available()
        ):
            status = "blocked"
            command_exit_code = None
            reason = APACHE_DEVELOPMENT_REASON
            status_source = "parent_preflight"
        else:
            command_exit_code = run_command(args.command)
            status = status_for_exit_code(command_exit_code)
            status_source = "child_exit_code"
            if status == "blocked":
                reason = "unclassified direct blocked exit code 77"

        if status not in VALID_STATUSES:
            raise AssertionError(f"unsupported status: {status}")
        exit_code = workflow_exit_code(
            status,
            command_exit_code,
            status == "blocked"
            and status_source == "parent_preflight"
            and reason in args.allow_blocked_reason,
            args.allow_not_applicable,
        )
        record: dict[str, object] = {
            "schema_version": 2,
            "check": args.check,
            "status": status,
            "status_source": status_source,
            "command_exit_code": command_exit_code,
            "workflow_exit_code": exit_code,
            "allowed_by_contract": exit_code == 0
            and status in {"blocked", "not_applicable"},
        }
        if reason is not None:
            record["reason"] = reason
        try:
            write_status(status_output, record)
        except ValueError as error:
            print(f"ERROR: {error}", file=sys.stderr)
            return 2
        print(f"CHECK_STATUS {json.dumps(record, sort_keys=True)}")
        return exit_code
    finally:
        os.close(status_output.directory_descriptor)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
