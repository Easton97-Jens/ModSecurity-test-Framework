#!/usr/bin/env python3
"""Parse GitHub workflow YAML files."""

from __future__ import annotations

import pathlib
import sys

try:
    import yaml  # type: ignore[import-not-found]
except ModuleNotFoundError as exc:
    raise SystemExit(
        "blocked: missing dependency PyYAML; install with: "
        "python3 -m pip install -r requirements-dev.txt"
    ) from exc


MAX_WORKFLOW_YAML_BYTES = 1_000_000
MAX_WORKFLOW_YAML_DEPTH = 100
MAX_WORKFLOW_YAML_NODES = 10_000
MAX_WORKFLOW_YAML_ALIASES = 100


class WorkflowYamlInputError(ValueError):
    """A controlled rejection of an untrusted workflow YAML input."""


class BoundedSafeLoader(yaml.SafeLoader):
    """SafeLoader with resource limits for PR-controlled workflow files."""

    def __init__(self, stream: object) -> None:
        super().__init__(stream)
        self._workflow_depth = 0
        self._workflow_nodes = 0
        self._workflow_aliases = 0

    def compose_node(self, parent: object, index: object) -> object:
        if self.check_event(yaml.events.AliasEvent):
            self._workflow_aliases += 1
            if self._workflow_aliases > MAX_WORKFLOW_YAML_ALIASES:
                raise WorkflowYamlInputError(
                    f"workflow exceeds {MAX_WORKFLOW_YAML_ALIASES} alias limit"
                )
            return super().compose_node(parent, index)

        self._workflow_depth += 1
        try:
            if self._workflow_depth > MAX_WORKFLOW_YAML_DEPTH:
                raise WorkflowYamlInputError(
                    f"workflow exceeds {MAX_WORKFLOW_YAML_DEPTH} nesting depth limit"
                )
            self._workflow_nodes += 1
            if self._workflow_nodes > MAX_WORKFLOW_YAML_NODES:
                raise WorkflowYamlInputError(
                    f"workflow exceeds {MAX_WORKFLOW_YAML_NODES} node limit"
                )
            return super().compose_node(parent, index)
        finally:
            self._workflow_depth -= 1


def read_bounded_workflow(path: pathlib.Path) -> str:
    try:
        with path.open("rb") as workflow_file:
            raw_workflow = workflow_file.read(MAX_WORKFLOW_YAML_BYTES + 1)
    except OSError as exc:
        raise WorkflowYamlInputError(f"cannot read workflow: {exc}") from exc
    if len(raw_workflow) > MAX_WORKFLOW_YAML_BYTES:
        raise WorkflowYamlInputError(
            f"workflow exceeds {MAX_WORKFLOW_YAML_BYTES} byte limit"
        )
    try:
        return raw_workflow.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise WorkflowYamlInputError("workflow is not valid UTF-8") from exc


def load_workflow(path: pathlib.Path) -> None:
    try:
        yaml.load(read_bounded_workflow(path), Loader=BoundedSafeLoader)
    except WorkflowYamlInputError:
        raise
    except RecursionError as exc:
        raise WorkflowYamlInputError("workflow YAML nesting is too deep") from exc
    except yaml.YAMLError as exc:
        raise WorkflowYamlInputError("invalid YAML") from exc


def main() -> int:
    workflow_root = pathlib.Path(".github/workflows")
    workflow_paths = sorted(
        [*workflow_root.glob("*.yml"), *workflow_root.glob("*.yaml")]
    )
    status = 0
    for path in workflow_paths:
        try:
            load_workflow(path)
        except WorkflowYamlInputError as exc:
            print(f"error {path}: {exc}", file=sys.stderr)
            status = 1
        else:
            print("ok", path)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
