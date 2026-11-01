"""Run local Make lint with the existing PATH actionlint and safe normalization."""

from __future__ import annotations

import argparse
import shutil
import subprocess

from modsecurity_connector_ci.tools.lint_workflows import actionlint_source, workflow_paths


def lint() -> int:
    """Preserve local tool selection, original sources and failure outcomes."""

    executable = shutil.which("actionlint")
    if executable is None:
        raise ValueError("installed actionlint is unavailable")
    status = 0
    for workflow in workflow_paths():
        source = actionlint_source(workflow.read_text(encoding="utf-8"))
        result = subprocess.run(
            [executable, "-stdin-filename", str(workflow), "-"],
            input=source,
            text=True,
            check=False,
            timeout=120,
        )
        if result.returncode:
            status = result.returncode if result.returncode > 0 else 1
    return status


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    try:
        return lint()
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        parser.exit(1, f"local workflow lint failed: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
