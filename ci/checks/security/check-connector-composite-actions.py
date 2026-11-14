#!/usr/bin/env python3
"""Keep actionlint/ShellCheck coverage over the actual migrated CI action source."""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from modsecurity_test_framework.sonar_diagnostics_contract import ACTION_PATH, validate_frozen_metadata

from modsecurity_connector_ci.lib.active_test_inventory import validate_output_root
from modsecurity_test_framework.workflow_sources import (
    composite_validation_workflow,
    read_composite_action_source,
)

ACTION_METADATA_FILENAME = "action.yml"


def resolve_shellcheck_executable(value: str) -> str:
    """Resolve one literal executable before actionlint can parse a command line."""
    selected = shutil.which(value)
    if selected is None:
        raise ValueError("--shellcheck must select one existing executable")
    resolved = Path(selected).resolve(strict=True)
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise ValueError("--shellcheck must select one regular executable")
    return str(resolved)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--framework-root", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--actionlint", required=True)
    parser.add_argument("--shellcheck", required=True)
    args = parser.parse_args()
    shellcheck = resolve_shellcheck_executable(args.shellcheck)
    selected_framework = args.framework_root.absolute()
    if any(parent.is_symlink() for parent in (selected_framework, *selected_framework.parents)):
        raise ValueError("Framework source root may not have symlink ancestors")
    framework = selected_framework.resolve(strict=True)
    output = Path(tempfile.mkdtemp(prefix="composite-actionlint-",
                                  dir=validate_output_root(framework, args.output_root)))
    action_root = framework / ".github/actions"
    if any(source.is_symlink() for source in (action_root, action_root.parent, *action_root.rglob("*"))):
        raise ValueError("action source inventory must not contain symlinks")
    sources = sorted([*action_root.rglob(ACTION_METADATA_FILENAME), *action_root.rglob("action.yaml")])
    if not sources:
        raise ValueError("Framework composite action source is empty")
    workflows = []
    reviewed_nodes = 0
    role = framework / ACTION_PATH
    if role.is_dir() and not (role / ACTION_METADATA_FILENAME).is_file():
        raise ValueError("reviewed private action metadata is missing or renamed")
    if (framework / "ci/lib/common.sh").is_file() and not (role / ACTION_METADATA_FILENAME).is_file():
        raise ValueError("reviewed private action is missing from declared inventory")
    for number, source in enumerate(sources):
        relative = source.relative_to(framework).as_posix()
        if relative.startswith(ACTION_PATH + "/"):
            validate_frozen_metadata(framework, relative, read_composite_action_source)
            reviewed_nodes += 1
            continue
        destination = output / f"action-{number}.yml"
        text = read_composite_action_source(framework, relative)
        destination.write_text(composite_validation_workflow(text, framework_root=framework), encoding="utf-8")
        workflows.append(str(destination))
    configuration = framework / ".github/actionlint.yaml"
    if not configuration.is_file():
        raise ValueError("checked-in Framework actionlint configuration is required")
    if resolve_shellcheck_executable(shellcheck) != shellcheck:
        raise ValueError("selected ShellCheck executable changed during validation")
    result = subprocess.run([args.actionlint, "-config-file", str(configuration),
                             "-shellcheck=" + shellcheck, *workflows],
                            cwd=framework, check=False, timeout=120)
    print(f"composite_source_count={len(workflows)} reviewed_node_count={reviewed_nodes} syntax_artifacts={output}")
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
