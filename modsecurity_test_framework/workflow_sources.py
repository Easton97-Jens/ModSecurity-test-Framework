"""Inspect the actual steps behind immutable Framework CI entrypoints.

This is offline source inspection, not workflow execution or runtime evidence.
Only the closed connector-ci actions, same-commit context action and protected
reusable workflow mappings may be expanded. Unsupported caller bindings fail
instead of fabricating a view.
"""
from __future__ import annotations

import json
import os
from pathlib import Path, PurePosixPath
import re
import stat

import yaml
from yaml.nodes import MappingNode, ScalarNode, SequenceNode
from yaml.tokens import AliasToken, AnchorToken, TagToken


OWNER = "Easton97-Jens/ModSecurity-test-Framework/"
ACTION = re.compile(
    re.escape(OWNER) + r"(?P<path>\.github/actions/(?:connector-ci/[a-z0-9-]+/[a-z0-9-]+|connector-context))"
    r"@(?P<revision>[a-f0-9]{40})\Z"
)
PROTECTED_REUSABLE_WORKFLOWS = {
    "run-trusted-lighttpd-namespace-dispatch.yml": (
        "connector-trusted-lighttpd-namespace.yml", ("target", "on_demand"),
        {"contents": "read", "statuses": "write"},
    ),
    "run-protected-nginx-exact-head.yml": (
        "connector-protected-nginx-exact-head.yml", ("pr_number", "expected_head_sha"),
        {"contents": "read"},
    ),
    "run-protected-nginx-root-broker.yml": (
        "connector-protected-nginx-root-broker-caller.yml", ("parent_head_sha",),
        {"contents": "read"},
    ),
}
PROTECTED_REUSABLE = re.compile(re.escape(OWNER) +
    r"\.github/workflows/(?P<workflow>[a-z0-9-]+\.yml)@(?P<revision>[a-f0-9]{40})\Z")
HISTORICAL_ROOT_BROKER = (
    "Easton97-Jens/ModSecurity-conector/.github/workflows/nginx-root-broker.yml@"
    "8ae707d72f1a8acb25d239e55e28a73cbc7522b1"
)

SHA = re.compile(r"[a-f0-9]{40}\Z")
MAX_SOURCE_BYTES = 1024 * 1024


class WorkflowSourceError(ValueError):
    """The actual immutable caller/callee source cannot be composed safely."""


def _read(root: Path, relative: str) -> str:
    path = PurePosixPath(relative)
    if path.is_absolute() or any(part in ("", ".", "..") for part in relative.split("/")):
        raise WorkflowSourceError("workflow source path must stay beneath its explicit owner")
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for name in path.parts[:-1]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        source = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
        with os.fdopen(source, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_SOURCE_BYTES:
                raise WorkflowSourceError("workflow source must be a bounded regular file")
            data = stream.read(MAX_SOURCE_BYTES + 1)
        if len(data) > MAX_SOURCE_BYTES:
            raise WorkflowSourceError("workflow source exceeds its size limit")
        return data.decode("utf-8")
    except (OSError, UnicodeError) as error:
        raise WorkflowSourceError("workflow source must use regular non-symlink UTF-8 files") from error
    finally:
        os.close(descriptor)


def _document(text: str) -> MappingNode:
    if len(text.encode()) > MAX_SOURCE_BYTES:
        raise WorkflowSourceError("workflow source exceeds its size limit")
    try:
        if any(isinstance(token, (AliasToken, AnchorToken, TagToken)) for token in yaml.scan(text)):
            raise WorkflowSourceError("workflow source indirection is forbidden")
        node = yaml.compose(text, Loader=yaml.BaseLoader)
    except (yaml.YAMLError, RecursionError) as error:
        raise WorkflowSourceError("workflow source must be unambiguous YAML") from error
    if not isinstance(node, MappingNode):
        raise WorkflowSourceError("workflow source must be a mapping")
    _unique_mappings(node)
    return node


def _unique_mappings(node) -> None:
    if isinstance(node, MappingNode):
        names = [key.value for key, _ in node.value if isinstance(key, ScalarNode)]
        if len(names) != len(node.value) or len(set(names)) != len(names):
            raise WorkflowSourceError("workflow source has duplicate or complex keys")
        for _, value in node.value:
            _unique_mappings(value)
    elif isinstance(node, SequenceNode):
        for value in node.value:
            _unique_mappings(value)


def _field(node: MappingNode, name: str):
    if not isinstance(node, MappingNode):
        raise WorkflowSourceError("workflow field must use a mapping")
    return next((value for key, value in node.value if key.value == name), None)


def _scalar(node, name: str) -> str | None:
    value = _field(node, name)
    if value is None:
        return None
    if not isinstance(value, ScalarNode):
        raise WorkflowSourceError("workflow field must be a scalar: " + name)
    return value.value


def _scalars(node) -> dict[str, str]:
    if not isinstance(node, MappingNode):
        raise WorkflowSourceError("action inputs require an explicit mapping")
    if any(not isinstance(value, ScalarNode) for _, value in node.value):
        raise WorkflowSourceError("action input values must be scalars")
    return {key.value: value.value for key, value in node.value}


def _compact(value: str) -> str:
    return re.sub(r"\s+", "", value)


def _restore(text: str, inputs: dict[str, str], revision: str) -> str:
    for name, context in (("caller-matrix", "matrix"), ("caller-inputs", "inputs"), ("caller-needs", "needs")):
        if name in inputs:
            if _compact(inputs[name]) != "${{toJSON(" + context + ")}}":
                raise WorkflowSourceError("unsupported caller JSON context binding: " + name)
            text = text.replace("fromJSON(inputs." + name + ").", context + ".")
    if "checkout-outcome" in inputs:
        if _compact(inputs["checkout-outcome"]) != "${{steps.checkout.outcome}}":
            raise WorkflowSourceError("checkout outcome must bind the actual Parent checkout")
        text = text.replace("inputs.checkout-outcome", "steps.checkout.outcome")
    return re.sub(r"\$\{\{\s*inputs\.framework-revision\s*\}\}", revision, text)


def _shift(text: str, amount: int) -> str:
    return "".join((" " * amount + line if amount >= 0 else line[-amount:]) if line.strip() else line
                   for line in text.splitlines(keepends=True))


def _action_steps(relative: str, framework: Path, revision: str, inputs: dict[str, str], depth: int = 0):
    if depth > 2:
        raise WorkflowSourceError("workflow action expansion exceeded its closed depth")
    if inputs.get("framework-revision") != revision:
        raise WorkflowSourceError("caller action input does not match its immutable Framework pin")
    text = _read(framework, relative + "/action.yml")
    document = _document(text)
    declared = _field(document, "inputs")
    allowed = {"framework-revision", "caller-matrix", "caller-inputs", "caller-needs", "checkout-outcome"}
    if not isinstance(declared, MappingNode) or set(inputs) != {key.value for key, _ in declared.value} or not set(inputs) <= allowed:
        raise WorkflowSourceError("caller inputs differ from the closed Framework action interface")
    runs = _field(document, "runs")
    if _scalar(runs, "using") != "composite":
        raise WorkflowSourceError("Framework test entrypoint must be a composite action")
    steps = _field(runs, "steps")
    if not isinstance(steps, SequenceNode):
        raise WorkflowSourceError("Framework composite steps are missing")
    lines, parts = text.splitlines(keepends=True), []
    for step in steps.value:
        block = _restore("".join(lines[step.start_mark.line:step.end_mark.line]), inputs, revision)
        uses = _scalar(step, "uses")
        if uses and uses.startswith("$/"):
            if uses != "$/.github/actions/connector-context":
                raise WorkflowSourceError("unknown same-commit Framework helper action")
            nested = {key: _restore(value, inputs, revision)
                      for key, value in _scalars(_field(step, "with")).items()}
            children, _ = _action_steps(".github/actions/connector-context", framework, revision, nested, depth + 1)
            parts.extend(children)
        else:
            parts.append((block, step.start_mark.column))
    outputs = {}
    output_node = _field(document, "outputs")
    if output_node is not None:
        if not isinstance(output_node, MappingNode):
            raise WorkflowSourceError("composite outputs must be an explicit mapping")
        for key, value in output_node.value:
            expression = _scalar(value, "value") or ""
            if re.fullmatch(r"\$\{\{\s*steps\.[a-zA-Z0-9_-]+\.outputs\.[a-zA-Z0-9_-]+\s*\}\}", expression) is None:
                raise WorkflowSourceError("composite output must bind an actual internal step output")
            outputs[key.value] = expression
    return parts, outputs


def read_protected_workflow_source(framework_root: Path, workflow_name: str) -> str:
    """Read one closed Framework-owned protected implementation without links."""
    if workflow_name not in {row[0] for row in PROTECTED_REUSABLE_WORKFLOWS.values()}:
        raise WorkflowSourceError("unknown protected Framework workflow source")
    return _read(framework_root, ".github/workflows/" + workflow_name)


def _root_block(text: str, document: MappingNode, name: str) -> str:
    entries = list(document.value)
    for index, (key, _) in enumerate(entries):
        if key.value == name:
            end = entries[index + 1][0].start_mark.line if index + 1 < len(entries) else len(text.splitlines())
            return "".join(text.splitlines(keepends=True)[key.start_mark.line:end])
    return ""


def _protected_reusable_source(text: str, document: MappingNode, jobs: MappingNode,
                               framework: Path, revision: str, workflow_name: str | None) -> str | None:
    calls = [job for _, job in jobs.value if (_scalar(job, "uses") or "").startswith(OWNER)]
    selected = PROTECTED_REUSABLE_WORKFLOWS.get(workflow_name)
    if not calls:
        if selected is not None and any(_scalar(job, "uses") is not None for _, job in jobs.value):
            raise WorkflowSourceError("protected caller must select its exact Framework callee")
        return None
    if selected is None or len(jobs.value) != 1 or jobs.value[0][0].value != "framework":
        raise WorkflowSourceError("protected reusable caller is outside the closed workflow/job mapping")
    callee_name, input_names, permissions = selected
    job = calls[0]
    if {key.value for key, _ in document.value} != {"name", "on", "permissions", "jobs"}:
        raise WorkflowSourceError("protected caller has unsupported top-level overrides")
    if {key.value for key, _ in job.value} != {"permissions", "uses", "with"}:
        raise WorkflowSourceError("protected caller has unsupported job overrides")
    if _scalars(_field(document, "permissions")) != {} or _scalars(_field(job, "permissions")) != permissions:
        raise WorkflowSourceError("protected caller permissions differ from the exact reviewed grant")
    match = PROTECTED_REUSABLE.fullmatch(_scalar(job, "uses") or "")
    if match is None or match["workflow"] != callee_name or match["revision"] != revision:
        raise WorkflowSourceError("protected callee or immutable pin differs from the selected source")
    bindings = _scalars(_field(job, "with"))
    if set(bindings) != set(input_names) or any(_compact(bindings[name]) != "${{inputs." + name + "}}" for name in input_names):
        raise WorkflowSourceError("protected reusable inputs must be exact same-name passthroughs")
    callee = read_protected_workflow_source(framework, callee_name)
    child = _document(callee)
    if {key.value for key, _ in child.value} != {"name", "on", "permissions", "concurrency", "jobs"}:
        raise WorkflowSourceError("protected callee has unsupported top-level fields")
    if _scalars(_field(child, "permissions")) != {}:
        raise WorkflowSourceError("protected callee must retain deny-default top-level permissions")
    caller_on, child_on = _field(document, "on"), _field(child, "on")
    if (not isinstance(caller_on, MappingNode) or [key.value for key, _ in caller_on.value] != ["workflow_dispatch"] or
            not isinstance(child_on, MappingNode) or [key.value for key, _ in child_on.value] != ["workflow_call"]):
        raise WorkflowSourceError("protected caller/callee triggers differ from the dispatch/call contract")
    caller_value = yaml.load(text, Loader=yaml.BaseLoader)
    child_value = yaml.load(callee, Loader=yaml.BaseLoader)
    if (caller_value["on"]["workflow_dispatch"] != child_value["on"]["workflow_call"] or
            set(child_value["on"]["workflow_call"]) != {"inputs"} or
            set(child_value["on"]["workflow_call"]["inputs"]) != set(input_names)):
        raise WorkflowSourceError("protected caller and callee input declarations must match exactly")
    child_jobs = _field(child, "jobs")
    if not isinstance(child_jobs, MappingNode) or not child_jobs.value:
        raise WorkflowSourceError("protected callee requires actual nonempty jobs")
    for _, child_job in child_jobs.value:
        if _field(child_job, "env") is not None or _field(child_job, "continue-on-error") is not None:
            raise WorkflowSourceError("protected callee has unsupported environment/failure overrides")
        granted = _scalars(_field(child_job, "permissions"))
        if any(name not in permissions or level not in {"read", "write"} or
               (level == "write" and permissions[name] != "write") for name, level in granted.items()):
            raise WorkflowSourceError("protected callee exceeds the exact caller permission grant")
        nested = _scalar(child_job, "uses")
        if nested is not None and nested != HISTORICAL_ROOT_BROKER:
            raise WorkflowSourceError("protected callee has an unreviewed nested reusable workflow")
    # This view retains real inner IDs for source checks. It does not rename
    # GitHub's actual nested check contexts or authorize workflow execution.
    header = "".join(text.splitlines(keepends=True)[:next(key.start_mark.line for key, _ in document.value if key.value == "jobs")])
    return header + _root_block(callee, child, "concurrency") + _root_block(callee, child, "jobs")


def expand_workflow_source(text: str, *, framework_root: Path, framework_revision: str,
                           workflow_name: str | None = None) -> str:
    """Compose only supported exact-pin action calls, preserving their true semantics."""
    if SHA.fullmatch(framework_revision) is None:
        raise WorkflowSourceError("a complete immutable Framework revision is required")
    document = _document(text)
    jobs = _field(document, "jobs")
    if not isinstance(jobs, MappingNode):
        raise WorkflowSourceError("workflow jobs are missing")
    protected = _protected_reusable_source(text, document, jobs, framework_root, framework_revision, workflow_name)
    if protected is not None:
        text = protected
        document = _document(text)
        jobs = _field(document, "jobs")
    lines, edits = text.splitlines(keepends=True), []
    for jobkey, job in jobs.value:
        steps = _field(job, "steps")
        if not isinstance(steps, SequenceNode):
            continue
        for step in steps.value:
            uses = _scalar(step, "uses") or ""
            if not uses.startswith(OWNER):
                continue
            match = ACTION.fullmatch(uses)
            if match is None or match["revision"] != framework_revision:
                raise WorkflowSourceError("Framework action path or immutable pin does not match the selected source")
            relative = match["path"]
            if relative.startswith(".github/actions/connector-ci/"):
                parts = relative.split("/")
                if parts[-1] != jobkey.value or (workflow_name and parts[-2] != Path(workflow_name).stem):
                    raise WorkflowSourceError("Framework action does not bind its caller workflow and job")
                condition = _compact(_scalar(step, "if") or "")
                # The exact-head adapter owns checkout and is the first step.
                # No earlier failure can suppress its terminal inner steps.
                first_step = step is steps.value[0]
                if condition not in ("always()", "${{always()}}") and not (first_step and not condition):
                    raise WorkflowSourceError("composite wrapper must preserve terminal cleanup and failure steps")
            if _scalar(step, "continue-on-error") not in (None, "false") or _field(step, "env") is not None:
                raise WorkflowSourceError("unsupported composite wrapper failure or environment override")
            bindings = _scalars(_field(step, "with"))
            parts, outputs = _action_steps(relative, framework_root, framework_revision, bindings)
            replacement = "".join(_shift(block, step.start_mark.column - indentation) for block, indentation in parts)
            edits.append((step.start_mark.line, step.end_mark.line, replacement))
            identifier = _scalar(step, "id")
            job_outputs = _field(job, "outputs")
            if identifier and job_outputs is not None:
                block = "".join(lines[job_outputs.start_mark.line:job_outputs.end_mark.line])
                for key, expression in outputs.items():
                    block = block.replace("${{ steps." + identifier + ".outputs." + key + " }}", expression)
                edits.append((job_outputs.start_mark.line, job_outputs.end_mark.line, block))
    for first, last, replacement in sorted(edits, reverse=True):
        lines[first:last] = replacement.splitlines(keepends=True)
    return "".join(lines)


def read_connector_workflow(path: str | Path) -> str:
    """Read Parent workflow plus its explicitly pinned Framework test actions offline."""
    path = Path(path)
    text = _read(path.parent, path.name)
    if OWNER not in text:
        return text
    from .connector_context import connector_root, test_root, framework_revision

    framework, connector = test_root(), connector_root()
    revision = os.environ.get("FRAMEWORK_REVISION")
    if not revision:
        lock = json.loads(_read(connector, "ci/tooling/project-versions.lock.json"))
        revision = lock.get("framework_sha")
    if not isinstance(revision, str):
        raise WorkflowSourceError("explicit Framework source revision is missing")
    if revision != framework_revision():
        raise WorkflowSourceError("selected Framework revision does not match its actual checkout")
    return expand_workflow_source(text, framework_root=framework, framework_revision=revision,
                                  workflow_name=path.name)


def composite_validation_workflow(text: str, *, framework_root: Path | None = None) -> str:
    """Expose actual composite steps to actionlint/ShellCheck without executing them.

    GitHub's workflow linter does not traverse remote composite source. A
    temporary workflow supplies typed string inputs for static context checks;
    every original command, condition, action reference and output is retained.
    This validates syntax and source contracts, never a remote pin or a run.
    """
    document = _document(text)
    runs = _field(document, "runs")
    if _scalar(runs, "using") != "composite":
        raise WorkflowSourceError("action metadata must declare composite execution")
    steps = _field(runs, "steps")
    if not isinstance(steps, SequenceNode) or not steps.value:
        raise WorkflowSourceError("composite action requires nonempty steps")
    keys = {"id", "if", "name", "shell", "run", "uses", "with", "env", "working-directory", "continue-on-error"}
    for step in steps.value:
        if not isinstance(step, MappingNode) or not {key.value for key, _ in step.value} <= keys:
            raise WorkflowSourceError("unsupported composite step field")
        if (_field(step, "run") is None) == (_field(step, "uses") is None):
            raise WorkflowSourceError("composite step requires exactly one run or uses")
        if _field(step, "run") is not None and not _scalar(step, "shell"):
            raise WorkflowSourceError("composite run step requires an explicit shell")
    value = yaml.safe_load(text)
    actual_steps = []
    for step in value["runs"]["steps"]:
        uses = step.get("uses", "")
        if isinstance(uses, str) and uses.startswith("$/"):
            if (uses != "$/.github/actions/connector-context" or framework_root is None
                    or step.get("with") != {"framework-revision": "${{ inputs.framework-revision }}"}
                    or any(key in step for key in ("if", "env", "continue-on-error"))):
                raise WorkflowSourceError("unsupported self-repository helper binding during syntax inspection")
            child = read_composite_action_source(framework_root, ".github/actions/connector-context/action.yml")
            inspected = yaml.safe_load(composite_validation_workflow(child, framework_root=framework_root))
            actual_steps.extend(inspected["jobs"]["composite-source"]["steps"])
        else:
            actual_steps.append(step)
    inputs = {name: {"description": "Static input context only", "type": "string", "default": "{}"}
              for name in value.get("inputs", {})}
    job = {"runs-on": "ubuntu-26.04", "steps": actual_steps}
    if value.get("outputs"):
        job["outputs"] = {name: output["value"] for name, output in value["outputs"].items()}
    workflow = {"name": "Composite source syntax inspection", "on": {"workflow_dispatch": {"inputs": inputs}},
                "permissions": {}, "jobs": {"composite-source": job}}
    return yaml.safe_dump(workflow, sort_keys=False, width=120)


def read_composite_action_source(framework_root: Path, relative: str) -> str:
    """Read bounded owned action metadata without following source links."""
    if not relative.startswith(".github/actions/") or not relative.endswith("/action.yml"):
        raise WorkflowSourceError("composite source must name Framework action metadata")
    return _read(framework_root, relative)
