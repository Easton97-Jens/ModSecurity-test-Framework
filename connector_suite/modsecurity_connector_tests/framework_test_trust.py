"""Non-executing trust checks for Framework-executing Parent tests."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess


FRAMEWORK_SUBMODULE_PATH = "modules/ModSecurity-test-Framework"
COMMON_RELATIVE_PATH = Path("ci/lib/common.sh")
TRUSTED_GIT_PATHS = (
    Path("/usr/bin/git"),
    Path("/bin/git"),
    Path("/usr/local/bin/git"),
)


def _trusted_git_executable() -> str | None:
    """Resolve Git without allowing an inherited PATH entry to redirect it."""

    for candidate in TRUSTED_GIT_PATHS:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def _run_git(root: Path, *arguments: str) -> tuple[str | None, str | None]:
    executable = _trusted_git_executable()
    if executable is None:
        return None, "trusted Git executable not found"
    environment = {
        key: value for key, value in os.environ.items() if not key.startswith("GIT_")
    }
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    result = subprocess.run(
        [
            executable,
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-C",
            str(root),
            *arguments,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        env=environment,
    )
    if result.returncode != 0:
        return None, result.stderr.strip() or result.stdout.strip() or "git command failed"
    return result.stdout, None


def _expected_gitlink(parent_root: Path) -> tuple[str | None, str | None]:
    output, error = _run_git(parent_root, "ls-tree", "HEAD", "--", FRAMEWORK_SUBMODULE_PATH)
    if error is not None:
        return None, f"cannot resolve Parent Framework gitlink: {error}"
    fields = (output or "").strip().split()
    if len(fields) != 4 or fields[0] != "160000" or fields[1] != "commit":
        return None, "Parent HEAD does not contain the expected Framework gitlink"
    return fields[2], None


def trusted_framework_root(
    parent_root: Path,
    framework_root: Path,
) -> tuple[Path | None, str | None]:
    """Return a clean exact-gitlink Framework root without executing its code."""

    if framework_root.is_symlink() or not framework_root.is_dir():
        return None, "Framework test root must be a regular directory"
    expected, error = _expected_gitlink(parent_root)
    if error is not None:
        return None, error
    actual_output, error = _run_git(framework_root, "rev-parse", "--verify", "HEAD")
    if error is not None:
        return None, f"cannot resolve Framework test root HEAD: {error}"
    actual = (actual_output or "").strip()
    if actual != expected:
        return None, f"Framework test root HEAD {actual} does not match Parent gitlink {expected}"
    status, error = _run_git(
        framework_root,
        "status",
        "--porcelain",
        "--untracked-files=all",
        "--ignore-submodules=none",
    )
    if error is not None:
        return None, f"cannot inspect Framework test root status: {error}"
    common = framework_root / COMMON_RELATIVE_PATH
    if (status or "").strip() or common.is_symlink() or not common.is_file():
        return None, "Framework test root must be clean and contain a regular common.sh"
    return framework_root, None
