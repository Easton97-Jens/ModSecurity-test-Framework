#!/usr/bin/env python3
"""Bind the checked-out Parent gitlink and private migrated-test environment."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


def canonical_root(value: str) -> Path:
    root = Path(value)
    if not root.is_absolute() or ".." in root.parts or str(root) != value:
        raise ValueError("context roots must be canonical absolute paths")
    if any(character in value for character in "\r\n\0"):
        raise ValueError("context paths must be single-line values")
    return root


def git(root: Path, *arguments: str) -> str:
    environment = {
        "PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0", "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_GRAFT_FILE": "/dev/null", "GIT_NO_LAZY_FETCH": "1",
        "GIT_ALLOW_PROTOCOL": "",
    }
    return subprocess.check_output(
        ["/usr/bin/git", "-c", "core.hooksPath=/nonexistent", "-c", "core.fsmonitor=false",
         "-C", str(root), *arguments], env=environment, stdin=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, timeout=15, text=True,
    ).strip()


def private_output(runner_temp: str) -> Path:
    root = canonical_root(runner_temp)
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in root.parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        name = "ModSecurity-conector-tests"
        try:
            os.mkdir(name, 0o700, dir_fd=descriptor)
        except FileExistsError:
            pass
        child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=descriptor)
        try:
            metadata = os.fstat(child)
            if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o022:
                raise ValueError("test output must be owned by the runner and privately writable")
        finally:
            os.close(child)
    finally:
        os.close(descriptor)
    return root / name


def context(root: Path, revision: str, expected_framework: str) -> dict[str, str]:
    for value in (revision, expected_framework):
        if not re.fullmatch(r"[a-f0-9]{40}", value):
            raise ValueError("context revisions must be exact SHA-1 values")
    if git(root, "rev-parse", "--show-toplevel", "HEAD").splitlines() != [str(root), revision]:
        raise ValueError("Parent checkout differs from its explicit revision")
    framework = root / "modules/ModSecurity-test-Framework"
    gitlink = git(root, "rev-parse", f"{revision}:modules/ModSecurity-test-Framework")
    if gitlink != expected_framework:
        raise ValueError("Framework revision differs from the Parent gitlink")
    if git(framework, "rev-parse", "--show-toplevel", "HEAD").splitlines() != [str(framework), gitlink]:
        raise ValueError("Framework checkout differs from the Parent gitlink")
    if not (framework / "modsecurity_test_framework/connector.py").is_file():
        raise ValueError("Framework connector entrypoint is missing")
    output = private_output(os.environ["RUNNER_TEMP"])
    return {
        "CONNECTOR_ROOT": str(root), "CONNECTOR_REVISION": revision,
        "TEST_ROOT": str(framework), "FRAMEWORK_ROOT": str(framework),
        "FRAMEWORK_REVISION": gitlink, "CONNECTOR_TEST_PROFILE": "h1",
        "CONNECTOR_TEST_OUTPUT_ROOT": str(output),
        "PYTHONPATH": f"{framework}:{framework}/connector_suite",
        "PYTHONSAFEPATH": "1", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--connector-root", required=True)
    parser.add_argument("--connector-revision", required=True)
    parser.add_argument("--framework-revision", required=True)
    arguments = parser.parse_args()
    try:
        values = context(canonical_root(arguments.connector_root), arguments.connector_revision,
                         arguments.framework_revision)
        destination = canonical_root(os.environ["GITHUB_ENV"])
        with destination.open("a", encoding="utf-8") as output:
            output.writelines(f"{key}={value}\n" for key, value in values.items())
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        print(f"connector context: {error}", file=sys.stderr)
        return 77
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
