"""Bind real adoption checkers to an isolated, committed mutation fixture."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess


def fixture_environment(repository: Path) -> dict[str, str]:
    """Snapshot copied sources without inheriting another Git checkout's state."""
    repository = repository.resolve(strict=True)
    if (repository / ".git").exists():
        raise AssertionError("checker fixture must not already contain Git metadata")
    environment = {
        key: value for key, value in os.environ.items() if not key.startswith("GIT_")
    }
    environment.update({
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "PYTHONDONTWRITEBYTECODE": "1",
    })
    executable = next(
        (str(path) for path in (Path("/usr/bin/git"), Path("/bin/git"))
         if path.is_file() and os.access(path, os.X_OK)),
        None,
    )
    if executable is None:
        raise AssertionError("trusted Git executable not found")

    def git(*arguments: str) -> str:
        result = subprocess.run(
            [executable, "-c", "core.hooksPath=" + os.devnull,
             "-c", "core.fsmonitor=false", "-c", "commit.gpgsign=false",
             "-c", "user.name=Checker Fixture",
             "-c", "user.email=checker-fixture@example.invalid",
             "-c", "protocol.allow=never", "-C", str(repository), *arguments],
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        return result.stdout.strip()

    git("init", "--quiet", "--template=", "--initial-branch=checker-fixture")
    git("add", "--all", "--", ".")
    git("commit", "--quiet", "--no-gpg-sign", "-m", "Snapshot checker fixture")
    environment["CONNECTOR_ROOT"] = str(repository)
    environment["CONNECTOR_REVISION"] = git("rev-parse", "--verify", "HEAD")
    return environment
