#!/usr/bin/env python3
"""Invoke the No-CRS finalizer with an argv vector, never shell text."""

from __future__ import annotations

import os
import shlex
import subprocess
import sys


def optional_environment_value(name: str, default: str = "") -> str:
    """Return one Make-transported value with its literal dollars restored."""
    return os.environ.get(name, default).replace("$$", "$")


def required_environment_value(name: str) -> str:
    """Return one required exported value after literal-dollar restoration."""
    value = optional_environment_value(name)
    if value is None or value == "":
        raise ValueError(f"{name} is required")
    return value


def parse_extra_arguments(value: str) -> list[str]:
    """Parse documented extra options as data, rejecting malformed quoting."""
    try:
        return shlex.split(value, posix=True)
    except ValueError as error:
        raise ValueError(f"invalid NO_CRS_FINALIZE_ARGS: {error}") from error


def build_finalizer_command() -> list[str]:
    """Build the child command from explicitly exported Make variables."""
    # Keep the target's existing connector requirement at this non-shell
    # boundary. The finalizer receives the resulting run and capability paths.
    required_environment_value("CONNECTOR")
    finalizer = required_environment_value("NO_CRS_TOOL")
    command = [
        sys.executable,
        finalizer,
        "finalize",
        "--run-dir",
        required_environment_value("NO_CRS_RUN_DIR"),
        "--connector-root",
        required_environment_value("CONNECTOR_ROOT"),
        "--capabilities",
        required_environment_value("CAPABILITIES_FILE"),
        "--stage-rc",
        required_environment_value("NO_CRS_STAGE_RC"),
        "--stage-reason",
        optional_environment_value("NO_CRS_STAGE_REASON"),
    ]
    protocol_client_artifact_dir = optional_environment_value(
        "NO_CRS_PROTOCOL_CLIENT_ARTIFACT_DIR"
    )
    if protocol_client_artifact_dir:
        command.extend(
            ["--protocol-client-artifact-dir", protocol_client_artifact_dir]
        )
    command.extend(parse_extra_arguments(optional_environment_value("NO_CRS_FINALIZE_ARGS")))
    return command


def main() -> int:
    """Run the finalizer and preserve its status for the Make recipe."""
    try:
        command = build_finalizer_command()
    except ValueError as error:
        print(f"no-crs finalizer configuration error: {error}", file=sys.stderr)
        return 2

    try:
        return subprocess.run(command, check=False, shell=False).returncode
    except OSError as error:
        print(f"could not start no-crs finalizer: {error}", file=sys.stderr)
        return 127


if __name__ == "__main__":
    raise SystemExit(main())
