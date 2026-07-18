#!/usr/bin/env python3
"""Enforce the Framework's GitHub Actions security contract.

The immutable-pin check intentionally uses only the Python standard library so
the dedicated pull-request workflow can run it before development dependencies
are installed. Permission and pull-request trust-boundary checks parse YAML
with PyYAML and run as part of the Framework lint contract.
"""

from __future__ import annotations

import argparse
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
import re
import sys
from typing import Any

try:
    import yaml  # type: ignore[import-not-found]
except ModuleNotFoundError:
    yaml = None  # type: ignore[assignment]


USES_KEY_RE = re.compile(r"^\s*(?:-\s*)?(?:uses|['\"]uses['\"])\s*:\s*")
USES_LINE_RE = re.compile(
    r"^\s*(?:-\s*)?(?:uses|['\"]uses['\"])\s*:\s*"
    r"(?P<reference>(?:'[^']*'|\"[^\"]*\"|[^\s#]+))"
    r"(?P<comment>\s+#.*)?\s*$"
)
BLOCK_SCALAR_START_RE = re.compile(
    r"^(?P<indent>\s*)(?:-\s*)?[^#:\n][^:\n]*:\s*[>|][+-]?(?:\s*#.*)?$"
)
FLOW_COLLECTION_RE = re.compile(r"(?:^|[:\-,\[]\s*)[\[{]")
EXPLICIT_MAPPING_KEY_RE = re.compile(r"^\s*(?:-\s*)?\?")
ADVANCED_YAML_NODE_RE = re.compile(r"^\s*(?:-\s*)?(?:!|&|\*|<<\s*:)")
ADVANCED_YAML_MAPPING_VALUE_RE = re.compile(
    r"^\s*(?:-\s*)?[^#:\n][^:\n]*:\s*(?:!|&|\*)"
)
YAML_DOCUMENT_MARKER_RE = re.compile(r"^\s*(?:---|\.\.\.)(?:\s|$)")
DOUBLE_QUOTED_MAPPING_KEY_RE = re.compile(
    r'^\s*(?:-\s*)?"(?P<key>(?:[^"\\]|\\.)*)"\s*:'
)
REMOTE_ACTION_RE = re.compile(
    r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*@[0-9a-f]{40}$"
)
RELEASE_COMMENT_RE = re.compile(
    r"^\s+#\s*v[0-9]+(?:\.[0-9]+){0,2}(?:[-+][A-Za-z0-9._-]+)?\s*$"
)
WRITE_PERMISSION_VALUES = {"write", "admin", "write-all"}
SECRET_REFERENCE_RE = re.compile(r"\bsecrets\s*(?:\.|\[)", re.IGNORECASE)
GITHUB_TOKEN_REFERENCE_RE = re.compile(
    r"\bgithub\s*(?:\.\s*token|\[\s*['\"]token['\"]\s*\])",
    re.IGNORECASE,
)


if yaml is not None:

    class UniqueKeySafeLoader(yaml.SafeLoader):
        """Safe YAML loader that rejects duplicate and merge keys."""


    def construct_unique_mapping(
        loader: Any, node: Any, deep: bool = False
    ) -> dict[Any, Any]:
        mapping: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if key == "<<":
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    "YAML merge keys are prohibited in workflows",
                    key_node.start_mark,
                )
            if key in mapping:
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    f"found duplicate key {key!r}",
                    key_node.start_mark,
                )
            mapping[key] = loader.construct_object(value_node, deep=deep)
        return mapping


    UniqueKeySafeLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_unique_mapping
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate immutable pins and trust boundaries in GitHub Actions workflows."
    )
    parser.add_argument(
        "--workflow-root",
        type=Path,
        default=Path(".github/workflows"),
        help="workflow file or directory containing .yml and .yaml workflow files",
    )
    parser.add_argument(
        "--check",
        choices=("all", "pins", "permissions"),
        default="all",
        help="contract section to validate (default: all)",
    )
    return parser.parse_args()


def workflow_paths(workflow_root: Path) -> list[Path]:
    if workflow_root.is_file():
        return [workflow_root] if workflow_root.suffix in {".yml", ".yaml"} else []
    return sorted([*workflow_root.glob("*.yml"), *workflow_root.glob("*.yaml")])


def normalized_reference(reference: str) -> str:
    return reference.strip().strip("'\"")


def source_uses(path: Path) -> tuple[list[tuple[int, str, str | None]], list[str]]:
    action_uses: list[tuple[int, str, str | None]] = []
    errors: list[str] = []
    block_scalar_indent: int | None = None
    for line_number, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        indentation = len(line) - len(line.lstrip())
        if block_scalar_indent is not None:
            if line.strip() and indentation <= block_scalar_indent:
                block_scalar_indent = None
            else:
                continue
        block_scalar_match = BLOCK_SCALAR_START_RE.match(line)
        if YAML_DOCUMENT_MARKER_RE.match(line):
            errors.append(
                f"{path}:{line_number}: YAML document markers are prohibited in "
                "workflows; use one simple block-mapping document for reviewable "
                "action pins"
            )
            continue
        if EXPLICIT_MAPPING_KEY_RE.match(line):
            errors.append(
                f"{path}:{line_number}: YAML explicit mapping keys are prohibited "
                "in workflows; use simple block mappings for reviewable action pins"
            )
            continue
        if (
            ADVANCED_YAML_NODE_RE.match(line)
            or ADVANCED_YAML_MAPPING_VALUE_RE.match(line)
        ):
            errors.append(
                f"{path}:{line_number}: YAML tags, anchors, aliases, and merge keys "
                "are prohibited in workflows; use simple block mappings for "
                "reviewable action pins"
            )
            continue
        double_quoted_key_match = DOUBLE_QUOTED_MAPPING_KEY_RE.match(line)
        if (
            double_quoted_key_match is not None
            and "\\" in double_quoted_key_match.group("key")
        ):
            errors.append(
                f"{path}:{line_number}: escaped double-quoted mapping keys are "
                "prohibited in workflows; use simple block mappings for reviewable "
                "action pins"
            )
            continue
        if USES_KEY_RE.match(line):
            if block_scalar_match is not None:
                errors.append(
                    f"{path}:{line_number}: uses entries must not use YAML block "
                    "scalars; use a single action reference"
                )
                block_scalar_indent = len(block_scalar_match.group("indent"))
                continue
            match = USES_LINE_RE.match(line)
            if match is None:
                errors.append(
                    f"{path}:{line_number}: uses entries must be a single action reference"
                )
                continue
            action_uses.append(
                (
                    line_number,
                    normalized_reference(match.group("reference")),
                    match.group("comment"),
                )
            )
            continue
        if block_scalar_match is not None:
            block_scalar_indent = len(block_scalar_match.group("indent"))
            continue
        if FLOW_COLLECTION_RE.search(line) is not None:
            errors.append(
                f"{path}:{line_number}: flow-style YAML collections are prohibited in "
                "workflows; use block mappings for reviewable action pins"
            )
            continue
    return action_uses, errors


def validate_pins(path: Path) -> list[str]:
    errors: list[str] = []
    action_uses, source_errors = source_uses(path)
    errors.extend(source_errors)
    for line_number, reference, comment in action_uses:
        if reference.startswith("./"):
            continue
        if not REMOTE_ACTION_RE.fullmatch(reference):
            errors.append(
                f"{path}:{line_number}: remote uses reference must use an immutable full "
                f"SHA: {reference}"
            )
            continue
        if comment is None or not RELEASE_COMMENT_RE.fullmatch(comment):
            errors.append(
                f"{path}:{line_number}: immutable remote action pins need a validated "
                "release comment such as '# v7.0.0'"
            )
    return errors


def as_mapping(value: Any) -> Mapping[str, Any] | None:
    return value if isinstance(value, Mapping) else None


def as_sequence(value: Any) -> Sequence[Any]:
    return value if isinstance(value, Sequence) and not isinstance(value, str) else ()


def workflow_events(document: Mapping[str, Any]) -> set[str]:
    raw_events = document.get("on", document.get(True))
    if isinstance(raw_events, str):
        return {raw_events}
    if isinstance(raw_events, Mapping):
        return {str(event) for event in raw_events}
    return {str(event) for event in as_sequence(raw_events)}


def permission_allows_write(value: Any) -> bool:
    permissions = as_mapping(value)
    if permissions is not None:
        return any(
            isinstance(permission, str)
            and permission.lower() in WRITE_PERMISSION_VALUES
            for permission in permissions.values()
        )
    return isinstance(value, str) and value.lower() in WRITE_PERMISSION_VALUES


def enabled_submodules(value: Any) -> bool:
    if value is False or value is None:
        return False
    return not (
        isinstance(value, str)
        and value.strip().lower() in {"", "0", "false", "no", "off"}
    )


def contains_secret_reference(value: Any) -> bool:
    if isinstance(value, str):
        return SECRET_REFERENCE_RE.search(value) is not None
    mapping = as_mapping(value)
    if mapping is not None:
        return any(contains_secret_reference(item) for item in mapping.values())
    return any(contains_secret_reference(item) for item in as_sequence(value))


def contains_github_token_reference(value: Any) -> bool:
    if isinstance(value, str):
        return GITHUB_TOKEN_REFERENCE_RE.search(value) is not None
    mapping = as_mapping(value)
    if mapping is not None:
        return any(contains_github_token_reference(item) for item in mapping.values())
    return any(contains_github_token_reference(item) for item in as_sequence(value))


def load_workflow(path: Path) -> tuple[Mapping[str, Any] | None, list[str]]:
    if yaml is None:
        return None, [
            "blocked: missing dependency PyYAML; install with: "
            "python3 -m pip install -r requirements-dev.txt"
        ]
    text = path.read_text(encoding="utf-8")
    try:
        for event in yaml.parse(text):
            if isinstance(event, yaml.events.AliasEvent):
                return None, [f"{path}: YAML aliases are prohibited in workflows"]
            if getattr(event, "anchor", None) is not None:
                return None, [f"{path}: YAML anchors are prohibited in workflows"]
        document = yaml.load(text, Loader=UniqueKeySafeLoader)
    except yaml.YAMLError as exc:
        return None, [f"{path}: invalid YAML: {exc}"]
    mapping = as_mapping(document)
    if mapping is None:
        return None, [f"{path}: workflow document must be a mapping"]
    return mapping, []


def checkout_steps(job: Mapping[str, Any]) -> Iterator[tuple[int, Mapping[str, Any]]]:
    for index, step in enumerate(as_sequence(job.get("steps")), 1):
        mapping = as_mapping(step)
        if mapping is None:
            continue
        uses = mapping.get("uses")
        if not isinstance(uses, str):
            continue
        action_name = normalized_reference(uses).split("@", 1)[0]
        if action_name == "actions/checkout":
            yield index, mapping


def validate_permissions(path: Path, document: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    top_permissions = as_mapping(document.get("permissions"))
    if dict(top_permissions or {}) != {"contents": "read"}:
        errors.append(
            f"{path}: top-level permissions must be exactly '{{contents: read}}'"
        )

    events = workflow_events(document)
    is_pull_request_workflow = "pull_request" in events
    if "pull_request_target" in events:
        errors.append(f"{path}: pull_request_target is prohibited")
    if is_pull_request_workflow and contains_secret_reference(document):
        errors.append(
            f"{path}: pull_request workflows must not expose secrets to untrusted code"
        )
    workflow_env = as_mapping(document.get("env"))
    if workflow_env is not None and "GITHUB_TOKEN" in workflow_env:
        errors.append(
            f"{path}: workflow must not define a workflow-level GITHUB_TOKEN; "
            "scope it to the one step that needs it"
        )
    if workflow_env is not None and contains_github_token_reference(workflow_env):
        errors.append(
            f"{path}: workflow-level env must not expose github.token under any "
            "variable name; scope it to the one step that needs it"
        )

    jobs = as_mapping(document.get("jobs"))
    if jobs is None:
        return [*errors, f"{path}: workflow must define jobs"]
    for job_name, raw_job in jobs.items():
        job = as_mapping(raw_job)
        if job is None:
            errors.append(f"{path}: job '{job_name}' must be a mapping")
            continue
        if permission_allows_write(job.get("permissions")) and is_pull_request_workflow:
            errors.append(
                f"{path}: job '{job_name}' grants a write permission in a pull_request "
                "workflow"
            )
        job_env = as_mapping(job.get("env"))
        if job_env is not None and "GITHUB_TOKEN" in job_env:
            errors.append(
                f"{path}: job '{job_name}' must not define a job-level GITHUB_TOKEN; "
                "scope it to the one step that needs it"
            )
        if job_env is not None and contains_github_token_reference(job_env):
            errors.append(
                f"{path}: job '{job_name}' env must not expose github.token under "
                "any variable name; scope it to the one step that needs it"
            )
        if is_pull_request_workflow and "secrets" in job:
            errors.append(
                f"{path}: job '{job_name}' must not forward reusable-workflow "
                "secrets in a pull_request workflow"
            )
        for step_index, checkout in checkout_steps(job):
            checkout_with = as_mapping(checkout.get("with"))
            if checkout_with is None or checkout_with.get("persist-credentials") is not False:
                errors.append(
                    f"{path}: job '{job_name}' checkout step {step_index} must set "
                    "persist-credentials: false"
                )
            if is_pull_request_workflow and checkout_with is not None and enabled_submodules(
                checkout_with.get("submodules")
            ):
                errors.append(
                    f"{path}: job '{job_name}' checkout step {step_index} enables "
                    "submodules in a pull_request workflow"
                )
    return errors


def main() -> int:
    args = parse_args()
    paths = workflow_paths(args.workflow_root)
    if not paths:
        print(f"{args.workflow_root}: no .yml or .yaml workflow files found", file=sys.stderr)
        return 1

    include_pins = args.check in {"all", "pins"}
    include_permissions = args.check in {"all", "permissions"}
    errors: list[str] = []
    for path in paths:
        if include_pins:
            errors.extend(validate_pins(path))
        if include_permissions:
            document, load_errors = load_workflow(path)
            errors.extend(load_errors)
            if document is not None:
                errors.extend(validate_permissions(path, document))

    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    for path in paths:
        print(f"ok {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
