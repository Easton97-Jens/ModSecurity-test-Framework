#!/usr/bin/env python3
"""Validate parsed CI-security evidence contracts for Framework workflows."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import shlex
from typing import Any, Iterable

import yaml


CODEQL_PR_WORKFLOW = "ci-security-codeql-pr.yml"
CODEQL_TRUSTED_WORKFLOW = "ci-security-codeql.yml"
OSV_WORKFLOW = "ci-security-osv.yml"
QUALITY_WORKFLOW = "ci-security-quality.yml"
SCORECARD_WORKFLOW = "ci-security-scorecard.yml"
GITLEAKS_WORKFLOW = "ci-security-secrets.yml"
WORKFLOW_LINT_WORKFLOW = "ci-security-workflow-lint.yml"
CODEQL_LANGUAGES = ["actions", "python", "c-cpp"]
SCORECARD_COMMANDS = (
    '"$TOOLS_DIR/scorecard" --local . --format json --output "$SCORECARD_RESULTS"',
    'python3 ci/checks/security/check-json-result.py --input "$SCORECARD_RESULTS" --max-bytes 1048576',
)
CHECKOUT = "actions/checkout@"
UPLOAD_ARTIFACT = "actions/upload-artifact@"
PR_HEAD = "${{ github.event.pull_request.head.sha }}"
DEFAULT_OR_PR_HEAD = "${{ github.event.pull_request.head.sha || github.sha }}"
GITHUB_SHA = "${{ github.sha }}"
PULL_REQUEST_CONDITION = "github.event_name == 'pull_request'"
DEFAULT_BRANCH_CONDITION = (
    "github.event_name != 'pull_request' && github.ref == "
    "format('refs/heads/{0}', github.event.repository.default_branch)"
)
SCANNER_ARTIFACT_FREE_WORKFLOWS = frozenset(
    {
        CODEQL_PR_WORKFLOW,
        CODEQL_TRUSTED_WORKFLOW,
        QUALITY_WORKFLOW,
        GITLEAKS_WORKFLOW,
        WORKFLOW_LINT_WORKFLOW,
    }
)
WORKFLOW_NAMES = (
    CODEQL_PR_WORKFLOW,
    CODEQL_TRUSTED_WORKFLOW,
    OSV_WORKFLOW,
    QUALITY_WORKFLOW,
    SCORECARD_WORKFLOW,
    GITLEAKS_WORKFLOW,
    WORKFLOW_LINT_WORKFLOW,
)


def load_yaml(path: Path) -> dict[str, Any]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError(f"cannot parse {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{path}: workflow must be a mapping")
    return data


def required_job(
    path: Path, data: dict[str, Any], name: str
) -> tuple[dict[str, Any] | None, list[str]]:
    jobs = data.get("jobs")
    job = jobs.get(name) if isinstance(jobs, dict) else None
    if isinstance(job, dict):
        return job, []
    return None, [f"{path}: required job {name!r} is absent"]


def job_steps(
    path: Path, name: str, job: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[str]]:
    steps = job.get("steps")
    if isinstance(steps, list) and all(isinstance(step, dict) for step in steps):
        return steps, []
    return [], [f"{path}: job {name!r} must declare mapping steps"]


def require_condition(
    path: Path, job_name: str, job: dict[str, Any], expected: str
) -> list[str]:
    if job.get("if") == expected:
        return []
    return [f"{path}: job {job_name!r} must set if to {expected!r}"]


def checkout_steps(steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        step
        for step in steps
        if isinstance(step.get("uses"), str) and step["uses"].startswith(CHECKOUT)
    ]


def require_checkout(
    path: Path,
    job_name: str,
    steps: list[dict[str, Any]],
    expected_ref: str,
    expected_depth: int,
) -> list[str]:
    checkouts = checkout_steps(steps)
    if len(checkouts) != 1:
        return [f"{path}: job {job_name!r} must contain exactly one checkout step"]
    settings = checkouts[0].get("with")
    if not isinstance(settings, dict):
        return [f"{path}: job {job_name!r} checkout must declare a with mapping"]
    errors: list[str] = []
    if settings.get("ref") != expected_ref:
        errors.append(
            f"{path}: job {job_name!r} checkout must use ref {expected_ref!r}"
        )
    if settings.get("fetch-depth") != expected_depth:
        errors.append(
            f"{path}: job {job_name!r} checkout must set fetch-depth: {expected_depth}"
        )
    if settings.get("persist-credentials") is not False:
        errors.append(
            f"{path}: job {job_name!r} checkout must disable persisted credentials"
        )
    if settings.get("submodules") is not False:
        errors.append(f"{path}: job {job_name!r} checkout must disable submodules")
    return errors


def step_by_field(
    path: Path,
    job_name: str,
    steps: list[dict[str, Any]],
    field: str,
    expected: str,
) -> tuple[dict[str, Any] | None, list[str]]:
    matches = [step for step in steps if step.get(field) == expected]
    if len(matches) != 1:
        return None, [
            f"{path}: job {job_name!r} must contain exactly one step with "
            f"{field} {expected!r}"
        ]
    return matches[0], []


def require_run_step(
    path: Path,
    job_name: str,
    steps: list[dict[str, Any]],
    field: str,
    expected: str,
) -> tuple[str | None, list[str]]:
    step, errors = step_by_field(path, job_name, steps, field, expected)
    if step is None:
        return None, errors
    run = step.get("run")
    if isinstance(run, str):
        return run, []
    return None, [f"{path}: job {job_name!r} step {expected!r} must run a script"]


def strip_shell_comment_line(line: str) -> str:
    """Return one shell line without an unquoted comment."""
    quote: str | None = None
    escaped = False
    retained: list[str] = []
    for index, character in enumerate(line):
        if escaped:
            retained.append(character)
            escaped = False
            continue
        if character == "\\" and quote != "'":
            retained.append(character)
            escaped = True
            continue
        if character in {"'", '"'}:
            if quote is None:
                quote = character
            elif quote == character:
                quote = None
            retained.append(character)
            continue
        if (
            character == "#"
            and quote is None
            and (index == 0 or line[index - 1].isspace())
        ):
            break
        retained.append(character)
    return "".join(retained).rstrip()


def strip_shell_comments(script: str) -> str:
    """Drop unquoted shell comments so comments cannot satisfy command checks."""
    return "\n".join(strip_shell_comment_line(line) for line in script.splitlines())


def normalized_shell_lines(script: str) -> list[str]:
    """Join continuations after removing comments to get executable command lines."""
    lines: list[str] = []
    current = ""
    for line in strip_shell_comments(script).splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        current = f"{current} {stripped}".strip() if current else stripped
        if current.endswith("\\"):
            current = current[:-1].rstrip()
            continue
        lines.append(current)
        current = ""
    if current:
        lines.append(current)
    return lines


SHELL_IDENTIFIER = r"[A-Za-z_]\w*"
FUNCTION_DECLARATION = re.compile(
    rf"(?:function\s+(?P<function_name>{SHELL_IDENTIFIER})(?:\s*\(\))?|"
    rf"(?P<posix_name>{SHELL_IDENTIFIER})\s*\(\))",
    re.ASCII,
)
FUNCTION_CALL = re.compile(rf"(?P<name>{SHELL_IDENTIFIER})\b", re.ASCII)
ASSIGNMENT_WORD = re.compile(
    rf"{SHELL_IDENTIFIER}\+?=(?:'[^']*'|\"[^\"]*\"|[^\s]*)\s*",
    re.ASCII,
)
IF_BRANCH = re.compile(r"if\b")
LOOP_BRANCH = re.compile(r"(?:for|while|until|select)\b")
CASE_BRANCH = re.compile(r"case\b")
ShellFunctionBlock = tuple[str, int, int, str | None]


def without_leading_shell_assignments(line: str) -> str:
    """Return the command position after zero or more shell assignment words."""
    remainder = line.lstrip()
    while True:
        assignment = ASSIGNMENT_WORD.match(remainder)
        if assignment is None:
            return remainder
        remainder = remainder[assignment.end() :]


def shell_function_call_name(line: str) -> str | None:
    """Return a direct function call name, excluding non-call shell words."""
    remainder = without_leading_shell_assignments(line)
    call = FUNCTION_CALL.match(remainder)
    if call is None:
        return None
    # ``name[...]`` cannot be a direct function invocation in Bash.  Treat it
    # as non-call syntax even if a future array-assignment form falls outside
    # the deliberately narrow assignment-word parser above.
    if remainder[call.end() :].startswith("["):
        return None
    return call.group("name")


def shell_function_definition(lines: list[str], index: int) -> re.Match[str] | None:
    """Return a supported function declaration only when its brace is present."""
    line = lines[index]
    candidate = line[:-1].rstrip() if line.endswith("{") else line
    definition = FUNCTION_DECLARATION.fullmatch(candidate)
    if definition is None:
        return None
    if line.endswith("{") or (index + 1 < len(lines) and lines[index + 1] == "{"):
        return definition
    return None


def shell_function_blocks(
    lines: list[str],
) -> list[ShellFunctionBlock]:
    """Return balanced Bash function blocks and their lexical parents."""
    blocks: list[ShellFunctionBlock] = []
    stack: list[tuple[str, int, str | None]] = []
    for index, line in enumerate(lines):
        definition = shell_function_definition(lines, index)
        if definition is not None:
            name = definition.group("function_name") or definition.group("posix_name")
            if name is None:
                continue
            parent = stack[-1][0] if stack else None
            stack.append((name, index, parent))
            continue
        if line == "}" and stack:
            name, start, parent = stack.pop()
            blocks.append((name, start, index, parent))
    return blocks


def control_flow_line_indexes(lines: list[str]) -> set[int]:
    """Return lines nested in shell control flow rather than direct execution."""
    control_lines: set[int] = set()
    endings: list[str] = []
    for index, line in enumerate(lines):
        if endings:
            control_lines.add(index)
        if IF_BRANCH.match(line):
            endings.append("fi")
            continue
        if LOOP_BRANCH.match(line):
            endings.append("done")
            continue
        if CASE_BRANCH.match(line):
            endings.append("esac")
            continue
        if endings and line == endings[-1]:
            endings.pop()
    return control_lines


def direct_context_lines(
    lines: list[str],
    start: int,
    end: int,
    children: Iterable[ShellFunctionBlock],
    control_lines: set[int],
) -> list[str]:
    """Return direct lines in one context, excluding controls and child functions."""
    child_indexes = {
        index
        for _name, child_start, child_end, _parent in children
        for index in range(child_start, child_end + 1)
    }
    direct_lines: list[str] = []
    terminated = False
    for index, line in enumerate(lines[start:end], start):
        if terminated or index in child_indexes or index in control_lines:
            continue
        direct_lines.append(line)
        if is_terminal_shell_command(line):
            terminated = True
    return direct_lines


def is_exit_command(line: str) -> bool:
    """Return whether a direct exit prevents later lines from running."""
    return line == "exit" or (
        line.startswith("exit")
        and len(line) > len("exit")
        and line[len("exit")].isspace()
        and bool(line[len("exit") :].strip())
    )


def shell_redirection_consumes_target(word: str) -> bool:
    """Return whether a redirection token consumes the next shell word."""
    prefix_length = 0
    while prefix_length < len(word) and word[prefix_length].isdigit():
        prefix_length += 1
    return word[prefix_length:] in {">", ">>", "<", "<<", ">&", "<&"}


def is_shell_redirection(word: str) -> bool:
    """Recognize a shell redirection token without applying a regex to scripts."""
    prefix_length = 0
    while prefix_length < len(word) and word[prefix_length].isdigit():
        prefix_length += 1
    return word[prefix_length:].startswith((">", "<"))


def exec_arguments_include_command(arguments: list[str]) -> bool:
    """Return whether parsed exec arguments include an executable command."""
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if is_shell_redirection(argument):
            index += 2 if shell_redirection_consumes_target(argument) else 1
            continue
        if argument == "-a":
            index += 2
            continue
        if argument.startswith("-") and argument != "-":
            index += 1
            continue
        return True
    return False


def exec_replaces_shell(line: str) -> bool:
    """Return whether a direct exec statement prevents later shell commands."""
    command = without_leading_shell_assignments(line)
    if not (
        command == "exec"
        or (
            command.startswith("exec")
            and len(command) > len("exec")
            and command[len("exec")].isspace()
        )
    ):
        return False
    try:
        words = shlex.split(command, comments=False, posix=True)
    except ValueError:
        return True
    if not words or words[0] != "exec":
        return True
    return exec_arguments_include_command(words[1:])


def is_terminal_shell_command(line: str) -> bool:
    """Return whether a direct shell statement prevents later execution."""
    return is_exit_command(line) or exec_replaces_shell(line)


def unique_function_definitions(
    blocks: Iterable[ShellFunctionBlock], control_lines: set[int]
) -> dict[str, tuple[int, int, str | None]]:
    """Return non-control-flow function definitions with duplicate names removed."""
    definitions: dict[str, tuple[int, int, str | None]] = {}
    duplicate_names: set[str] = set()
    for name, start, end, parent in blocks:
        if start in control_lines:
            continue
        if name in definitions:
            duplicate_names.add(name)
            continue
        definitions[name] = (start, end, parent)
    for name in duplicate_names:
        definitions.pop(name, None)
    return definitions


def context_direct_lines(
    lines: list[str],
    blocks: list[ShellFunctionBlock],
    definitions: dict[str, tuple[int, int, str | None]],
    control_lines: set[int],
    context: str | None,
) -> list[str]:
    """Return direct executable lines for the root or one reachable function."""
    if context is None:
        root_children = [block for block in blocks if block[3] is None]
        return direct_context_lines(lines, 0, len(lines), root_children, control_lines)
    start, end, _parent = definitions[context]
    children = [block for block in blocks if block[3] == context]
    return direct_context_lines(lines, start + 1, end, children, control_lines)


def called_function_contexts(
    lines: Iterable[str],
    definitions: dict[str, tuple[int, int, str | None]],
    context: str | None,
) -> list[str]:
    """Return direct function calls that are visible from one lexical context."""
    contexts: list[str] = []
    for line in lines:
        name = shell_function_call_name(line)
        if name is None:
            continue
        definition = definitions.get(name)
        if definition is None:
            continue
        _start, _end, parent = definition
        if parent is None or parent == context:
            contexts.append(name)
    return contexts


def reachable_shell_lines(script: str) -> list[str]:
    """Return root commands plus commands in functions called from that root.

    This is a deliberately narrow structural check for the Framework workflow
    scripts. It rejects commands hidden in shell control flow or in a function
    that is never called, while retaining commands in direct, reachable OSV
    helper functions.
    """
    lines = normalized_shell_lines(script)
    blocks = shell_function_blocks(lines)
    control_lines = control_flow_line_indexes(lines)
    definitions = unique_function_definitions(blocks, control_lines)
    contexts: list[str | None] = [None]
    visited: set[str | None] = set()
    reachable: list[str] = []
    while contexts:
        context = contexts.pop()
        if context in visited:
            continue
        visited.add(context)
        context_lines = context_direct_lines(
            lines, blocks, definitions, control_lines, context
        )
        reachable.extend(context_lines)
        contexts.extend(called_function_contexts(context_lines, definitions, context))
    return reachable


def require_commands(
    path: Path,
    job_name: str,
    step_name: str,
    script: str,
    commands: Iterable[str],
) -> list[str]:
    lines = reachable_shell_lines(script)
    errors: list[str] = []
    for command in commands:
        if not any(
            re.fullmatch(rf"\s*{re.escape(command)}\s*", line) for line in lines
        ):
            errors.append(
                f"{path}: job {job_name!r} step {step_name!r} must execute {command!r}"
            )
    return errors


def artifact_steps(steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        step
        for step in steps
        if isinstance(step.get("uses"), str)
        and step["uses"].startswith(UPLOAD_ARTIFACT)
    ]


def require_artifact(
    path: Path,
    job_name: str,
    steps: list[dict[str, Any]],
    expected_if: str | None,
    expected_paths: list[str],
) -> list[str]:
    artifacts = artifact_steps(steps)
    if len(artifacts) != 1:
        return [f"{path}: job {job_name!r} must contain exactly one artifact step"]
    artifact = artifacts[0]
    errors: list[str] = []
    if expected_if is not None and artifact.get("if") != expected_if:
        errors.append(
            f"{path}: job {job_name!r} artifact gate must equal {expected_if!r}"
        )
    settings = artifact.get("with")
    if not isinstance(settings, dict):
        return [
            *errors,
            f"{path}: job {job_name!r} artifact must declare a with mapping",
        ]
    if settings.get("retention-days") != 1:
        errors.append(f"{path}: job {job_name!r} artifact must set retention-days: 1")
    if settings.get("if-no-files-found") != "error":
        errors.append(
            f"{path}: job {job_name!r} artifact must set if-no-files-found: error"
        )
    path_value = settings.get("path")
    actual_paths = (
        [line.strip() for line in path_value.splitlines() if line.strip()]
        if isinstance(path_value, str)
        else []
    )
    if actual_paths != expected_paths:
        errors.append(
            f"{path}: job {job_name!r} artifact paths must equal {expected_paths!r}"
        )
    return errors


def has_write_permission(data: dict[str, Any], permission: str) -> bool:
    scopes: list[Any] = [data.get("permissions")]
    jobs = data.get("jobs")
    if isinstance(jobs, dict):
        scopes.extend(
            job.get("permissions") for job in jobs.values() if isinstance(job, dict)
        )
    return any(
        isinstance(permissions, dict) and permissions.get(permission) == "write"
        for permissions in scopes
    )


def workflow_events(data: dict[Any, Any]) -> set[str]:
    raw_events = data.get("on", data.get(True))
    if isinstance(raw_events, str):
        return {raw_events}
    if isinstance(raw_events, dict):
        return {str(event) for event in raw_events}
    if isinstance(raw_events, list):
        return {str(event) for event in raw_events}
    return set()


def osv_run_errors(
    path: Path,
    job_name: str,
    step_name: str,
    run: str,
    commands: Iterable[str],
    prohibited_label: str,
) -> list[str]:
    errors: list[str] = []
    errors.extend(require_commands(path, job_name, step_name, run, commands))
    actual = "\n".join(normalized_shell_lines(run))
    for prohibited in ("--allow-no-lockfiles", "--recursive"):
        if prohibited in actual:
            errors.append(f"{path}: {prohibited_label} must not contain {prohibited!r}")
    return errors


def osv_pull_request_errors(path: Path, data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    pull_request, job_errors = required_job(path, data, "pull-request-head")
    errors.extend(job_errors)
    if pull_request is None:
        return errors
    errors.extend(
        require_condition(
            path, "pull-request-head", pull_request, PULL_REQUEST_CONDITION
        )
    )
    steps, step_errors = job_steps(path, "pull-request-head", pull_request)
    errors.extend(step_errors)
    if step_errors:
        return errors
    errors.extend(require_checkout(path, "pull-request-head", steps, PR_HEAD, 0))
    run, run_errors = require_run_step(
        path, "pull-request-head", steps, "id", "compare_osv"
    )
    errors.extend(run_errors)
    if run is not None:
        errors.extend(
            osv_run_errors(
                path,
                "pull-request-head",
                "compare_osv",
                run,
                (
                    'test "$(git rev-parse HEAD)" = "$HEAD_SHA"',
                    'git cat-file -e "$BASE_SHA^{commit}"',
                    'git cat-file -e "$HEAD_SHA^{commit}"',
                    'git cat-file -e "$HEAD_SHA:requirements-ci.lock"',
                    "write_osv_input requirements-dev.txt requirements-dev.txt false",
                    "write_osv_input requirements-ci.lock requirements-ci.txt true",
                    'local -a lockfiles=(--lockfile "$input_directory/requirements-dev.txt")',
                    'lockfiles+=(--lockfile "$input_directory/requirements-ci.txt")',
                    '"$TOOLS_DIR/osv-scanner" scan source --format json --output-file "$result_file" "${lockfiles[@]}"',
                    'python3 ci/checks/security/check-json-result.py --input "$RESULTS_DIR/base.json" --max-bytes 1048576 --osv-report',
                    'python3 ci/checks/security/check-json-result.py --input "$RESULTS_DIR/head.json" --max-bytes 1048576 --osv-report',
                    'python3 ci/checks/security/compare-osv-results.py --base "$RESULTS_DIR/base.json" --head "$RESULTS_DIR/head.json" --base-revision "$BASE_SHA" --head-revision "$HEAD_SHA" --output "$RESULTS_DIR/comparison.json"',
                    'echo "evidence_valid=true" >> "$GITHUB_OUTPUT"',
                ),
                "OSV comparison",
            )
        )
    errors.extend(
        require_artifact(
            path,
            "pull-request-head",
            steps,
            "always() && steps.compare_osv.outputs.evidence_valid == 'true'",
            [
                "${{ runner.temp }}/framework-ci-security-results/osv/base.json",
                "${{ runner.temp }}/framework-ci-security-results/osv/head.json",
                "${{ runner.temp }}/framework-ci-security-results/osv/comparison.json",
            ],
        )
    )
    return errors


def osv_scheduled_errors(path: Path, data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    scheduled, job_errors = required_job(path, data, "scheduled-advisory")
    errors.extend(job_errors)
    if scheduled is None:
        return errors
    errors.extend(
        require_condition(
            path, "scheduled-advisory", scheduled, DEFAULT_BRANCH_CONDITION
        )
    )
    steps, step_errors = job_steps(path, "scheduled-advisory", scheduled)
    errors.extend(step_errors)
    if step_errors:
        return errors
    errors.extend(require_checkout(path, "scheduled-advisory", steps, GITHUB_SHA, 1))
    run, run_errors = require_run_step(
        path, "scheduled-advisory", steps, "id", "scan_current_osv"
    )
    errors.extend(run_errors)
    if run is not None:
        errors.extend(
            osv_run_errors(
                path,
                "scheduled-advisory",
                "scan_current_osv",
                run,
                (
                    'test "$(git rev-parse HEAD)" = "$REVISION"',
                    'git cat-file -e "$REVISION^{commit}"',
                    'git cat-file -e "$REVISION:requirements-ci.lock"',
                    "write_osv_input requirements-dev.txt requirements-dev.txt",
                    "write_osv_input requirements-ci.lock requirements-ci.txt",
                    'lockfiles=(--lockfile "$input_directory/requirements-dev.txt")',
                    'lockfiles+=(--lockfile "$input_directory/requirements-ci.txt")',
                    '"$TOOLS_DIR/osv-scanner" scan source --format json --output-file "$RESULTS_DIR/current.json" "${lockfiles[@]}"',
                    'python3 ci/checks/security/check-json-result.py --input "$RESULTS_DIR/current.json" --max-bytes 1048576 --osv-report',
                    'echo "evidence_valid=true" >> "$GITHUB_OUTPUT"',
                ),
                "OSV scheduled scan",
            )
        )
    errors.extend(
        require_artifact(
            path,
            "scheduled-advisory",
            steps,
            "always() && steps.scan_current_osv.outputs.evidence_valid == 'true'",
            ["${{ runner.temp }}/framework-ci-security-results/osv/current.json"],
        )
    )
    return errors


def osv_errors(path: Path, data: dict[str, Any]) -> list[str]:
    errors = [*osv_pull_request_errors(path, data), *osv_scheduled_errors(path, data)]
    if has_write_permission(data, "security-events"):
        errors.append(f"{path}: OSV must not grant security-events: write")
    return errors


def scorecard_pull_request_errors(path: Path, data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    pull_request, job_errors = required_job(path, data, "pull-request-head")
    errors.extend(job_errors)
    if pull_request is None:
        return errors
    errors.extend(
        require_condition(
            path, "pull-request-head", pull_request, PULL_REQUEST_CONDITION
        )
    )
    steps, step_errors = job_steps(path, "pull-request-head", pull_request)
    errors.extend(step_errors)
    if step_errors:
        return errors
    errors.extend(require_checkout(path, "pull-request-head", steps, PR_HEAD, 1))
    run, run_errors = require_run_step(
        path,
        "pull-request-head",
        steps,
        "name",
        "Run Scorecard against the exact pull-request checkout",
    )
    errors.extend(run_errors)
    if run is not None:
        errors.extend(
            require_commands(
                path,
                "pull-request-head",
                "Scorecard pull-request scan",
                run,
                SCORECARD_COMMANDS,
            )
        )
    if artifact_steps(steps):
        errors.append(f"{path}: pull-request Scorecard evidence must be artifact-free")
    return errors


def scorecard_current_revision_errors(path: Path, data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    current, job_errors = required_job(path, data, "current-revision-advisory")
    errors.extend(job_errors)
    if current is None:
        return errors
    errors.extend(
        require_condition(
            path, "current-revision-advisory", current, DEFAULT_BRANCH_CONDITION
        )
    )
    steps, step_errors = job_steps(path, "current-revision-advisory", current)
    errors.extend(step_errors)
    if step_errors:
        return errors
    errors.extend(
        require_checkout(path, "current-revision-advisory", steps, GITHUB_SHA, 1)
    )
    if "continue-on-error" in current or any(
        "continue-on-error" in step for step in steps
    ):
        errors.append(f"{path}: Scorecard current-revision scan must fail closed")
    run, run_errors = require_run_step(
        path,
        "current-revision-advisory",
        steps,
        "name",
        "Run Scorecard against the current Framework checkout (advisory)",
    )
    errors.extend(run_errors)
    if run is not None:
        errors.extend(
            require_commands(
                path,
                "current-revision-advisory",
                "Scorecard current-revision scan",
                run,
                SCORECARD_COMMANDS,
            )
        )
    errors.extend(
        require_artifact(
            path,
            "current-revision-advisory",
            steps,
            None,
            ["${{ runner.temp }}/scorecard-results.json"],
        )
    )
    return errors


def scorecard_errors(path: Path, data: dict[str, Any]) -> list[str]:
    errors = [
        *scorecard_pull_request_errors(path, data),
        *scorecard_current_revision_errors(path, data),
    ]
    if has_write_permission(data, "security-events"):
        errors.append(f"{path}: Scorecard must not grant security-events: write")
    return errors


def codeql_permissions_errors(
    path: Path,
    data: dict[str, Any],
    analyze: dict[str, Any],
    requires_security_events_write: bool,
) -> list[str]:
    errors: list[str] = []
    permissions = analyze.get("permissions")
    if not isinstance(permissions, dict) or permissions.get("contents") != "read":
        errors.append(f"{path}: CodeQL must retain contents: read")
    if requires_security_events_write:
        if (
            not isinstance(permissions, dict)
            or permissions.get("security-events") != "write"
        ):
            errors.append(
                f"{path}: trusted CodeQL upload must retain scoped security-events: write"
            )
    elif has_write_permission(data, "security-events"):
        errors.append(
            f"{path}: pull-request CodeQL must not grant security-events: write"
        )
    return errors


def codeql_strategy_errors(path: Path, analyze: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    strategy = analyze.get("strategy")
    matrix = strategy.get("matrix") if isinstance(strategy, dict) else None
    if not isinstance(matrix, dict) or matrix.get("language") != CODEQL_LANGUAGES:
        errors.append(f"{path}: CodeQL must scan actions, python, and c-cpp")
    return errors


def codeql_init_errors(
    path: Path, job_name: str, steps: list[dict[str, Any]]
) -> list[str]:
    errors: list[str] = []
    init, init_errors = step_by_field(
        path,
        job_name,
        steps,
        "name",
        "Initialize CodeQL for actual Framework languages",
    )
    errors.extend(init_errors)
    if init is None:
        return errors
    settings = init.get("with")
    if not isinstance(settings, dict):
        return [*errors, f"{path}: CodeQL init must declare a with mapping"]
    if settings.get("languages") != "${{ matrix.language }}":
        errors.append(f"{path}: CodeQL init must use the language matrix")
    if settings.get("build-mode") != "none":
        errors.append(f"{path}: CodeQL init must use build-mode: none")
    if settings.get("tools") != "linked":
        errors.append(f"{path}: CodeQL init must select tools: linked")
    config = settings.get("config")
    try:
        config_data = yaml.safe_load(config) if isinstance(config, str) else None
    except yaml.YAMLError:
        config_data = None
    ignored = config_data.get("paths-ignore") if isinstance(config_data, dict) else None
    if not isinstance(ignored, list) or "tools/MRTS/**" not in ignored:
        errors.append(f"{path}: CodeQL must exclude tools/MRTS/**")
    return errors


def codeql_analyze_step_errors(
    path: Path,
    job_name: str,
    steps: list[dict[str, Any]],
    analyze_step_name: str,
    expected_upload: str,
) -> list[str]:
    errors: list[str] = []
    analyze_step, analyze_errors = step_by_field(
        path, job_name, steps, "name", analyze_step_name
    )
    errors.extend(analyze_errors)
    if analyze_step is None:
        return errors
    settings = analyze_step.get("with")
    if not isinstance(settings, dict):
        return [*errors, f"{path}: CodeQL analyze step must declare a with mapping"]
    if settings.get("upload") != expected_upload:
        return [
            *errors,
            f"{path}: CodeQL analyze step must set upload: {expected_upload}",
        ]
    if expected_upload == "never" and settings.get("upload-database") is not False:
        errors.append(f"{path}: pull-request CodeQL must set upload-database: false")
    return errors


def codeql_analysis_errors(
    path: Path,
    data: dict[str, Any],
    *,
    job_name: str,
    expected_ref: str,
    expected_condition: str | None,
    analyze_step_name: str,
    expected_upload: str,
    requires_security_events_write: bool,
) -> list[str]:
    errors: list[str] = []
    analyze, job_errors = required_job(path, data, job_name)
    errors.extend(job_errors)
    if analyze is None:
        return errors
    if expected_condition is not None:
        errors.extend(require_condition(path, job_name, analyze, expected_condition))
    errors.extend(
        codeql_permissions_errors(path, data, analyze, requires_security_events_write)
    )
    errors.extend(codeql_strategy_errors(path, analyze))
    steps, step_errors = job_steps(path, job_name, analyze)
    errors.extend(step_errors)
    if step_errors:
        return errors
    errors.extend(require_checkout(path, job_name, steps, expected_ref, 1))
    errors.extend(codeql_init_errors(path, job_name, steps))
    errors.extend(
        codeql_analyze_step_errors(
            path, job_name, steps, analyze_step_name, expected_upload
        )
    )
    return errors


def codeql_pull_request_errors(path: Path, data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    events = workflow_events(data)
    if events != {"pull_request"}:
        errors.append(
            f"{path}: pull-request CodeQL must be triggered only by pull_request"
        )
    errors.extend(
        codeql_analysis_errors(
            path,
            data,
            job_name="analyze-pull-request",
            expected_ref=PR_HEAD,
            expected_condition=PULL_REQUEST_CONDITION,
            analyze_step_name="Analyze bounded pull-request source without upload",
            expected_upload="never",
            requires_security_events_write=False,
        )
    )
    return errors


def codeql_trusted_errors(path: Path, data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    events = workflow_events(data)
    if "pull_request" in events:
        errors.append(f"{path}: trusted CodeQL upload must not run on pull_request")
    required_events = {"push", "schedule", "workflow_dispatch"}
    if not required_events.issubset(events):
        errors.append(
            f"{path}: trusted CodeQL upload must retain push, schedule, and workflow_dispatch triggers"
        )
    errors.extend(
        codeql_analysis_errors(
            path,
            data,
            job_name="analyze-trusted",
            expected_ref=GITHUB_SHA,
            expected_condition=None,
            analyze_step_name="Analyze bounded Framework source",
            expected_upload="always",
            requires_security_events_write=True,
        )
    )
    return errors


def gitleaks_pull_request_errors(
    path: Path, data: dict[str, Any]
) -> tuple[list[str], bool]:
    errors: list[str] = []
    pull_request, job_errors = required_job(path, data, "pull-request-range")
    errors.extend(job_errors)
    if pull_request is None:
        return errors, False
    errors.extend(
        require_condition(
            path,
            "pull-request-range",
            pull_request,
            PULL_REQUEST_CONDITION,
        )
    )
    steps, step_errors = job_steps(path, "pull-request-range", pull_request)
    errors.extend(step_errors)
    if step_errors:
        return errors, True
    errors.extend(require_checkout(path, "pull-request-range", steps, PR_HEAD, 0))
    run, run_errors = require_run_step(
        path,
        "pull-request-range",
        steps,
        "name",
        "Scan exact pull-request commit range with redaction",
    )
    errors.extend(run_errors)
    if run is not None:
        errors.extend(
            require_commands(
                path,
                "pull-request-range",
                "Gitleaks pull-request range scan",
                run,
                (
                    'test "$(git rev-parse HEAD)" = "$HEAD_SHA"',
                    'git cat-file -e "$BASE_SHA^{commit}"',
                    'git cat-file -e "$HEAD_SHA^{commit}"',
                    'merge_base="$(git merge-base "$BASE_SHA" "$HEAD_SHA")"',
                    '"$TOOLS_DIR/gitleaks" git --redact=100 --log-opts="$merge_base..$HEAD_SHA" .',
                ),
            )
        )
    if artifact_steps(steps):
        errors.append(f"{path}: pull-request Gitleaks evidence must be artifact-free")
    return errors, True


def gitleaks_advisory_errors(path: Path, data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    advisory, advisory_errors = required_job(path, data, "advisory-full-history")
    errors.extend(advisory_errors)
    if advisory is None:
        return errors
    errors.extend(
        require_condition(
            path,
            "advisory-full-history",
            advisory,
            "github.event_name != 'pull_request'",
        )
    )
    advisory_steps, advisory_step_errors = job_steps(
        path, "advisory-full-history", advisory
    )
    errors.extend(advisory_step_errors)
    if advisory_step_errors:
        return errors
    errors.extend(
        require_checkout(path, "advisory-full-history", advisory_steps, GITHUB_SHA, 0)
    )
    advisory_step, advisory_run_errors = step_by_field(
        path,
        "advisory-full-history",
        advisory_steps,
        "name",
        "Scan full history with redaction (advisory)",
    )
    errors.extend(advisory_run_errors)
    if advisory_step is not None:
        if advisory_step.get("continue-on-error") is not True:
            errors.append(f"{path}: full-history Gitleaks must remain advisory")
        advisory_run = advisory_step.get("run")
        if isinstance(advisory_run, str):
            errors.extend(
                require_commands(
                    path,
                    "advisory-full-history",
                    "Gitleaks full-history scan",
                    advisory_run,
                    ("\"$TOOLS_DIR/gitleaks\" git --redact=100 --log-opts='--all' .",),
                )
            )
        else:
            errors.append(f"{path}: full-history Gitleaks step must run a script")
    if artifact_steps(advisory_steps):
        errors.append(f"{path}: full-history Gitleaks evidence must be artifact-free")
    return errors


def gitleaks_errors(path: Path, data: dict[str, Any]) -> list[str]:
    errors, pull_request_exists = gitleaks_pull_request_errors(path, data)
    if not pull_request_exists:
        return errors
    errors.extend(gitleaks_advisory_errors(path, data))
    if has_write_permission(data, "security-events"):
        errors.append(f"{path}: Gitleaks must not grant security-events: write")
    return errors


def boundary_step_errors(path: Path, job_name: str, step: dict[str, Any]) -> list[str]:
    """Return forbidden evidence-boundary uses from one workflow step."""
    errors: list[str] = []
    uses = step.get("uses")
    if isinstance(uses, str) and uses.startswith("actions/cache@"):
        errors.append(
            f"{path}: job {job_name!r} must not restore or save a persistent cache"
        )
    if isinstance(uses, str) and uses.startswith("github/codeql-action/upload-sarif@"):
        errors.append(f"{path}: job {job_name!r} must not upload raw SARIF directly")
    if (
        path.name in SCANNER_ARTIFACT_FREE_WORKFLOWS
        and isinstance(uses, str)
        and uses.startswith(UPLOAD_ARTIFACT)
    ):
        errors.append(f"{path}: job {job_name!r} must not upload scanner artifacts")
    run = step.get("run")
    if isinstance(run, str) and "--sarif" in "\n".join(normalized_shell_lines(run)):
        errors.append(
            f"{path}: job {job_name!r} must not emit raw SARIF from a shell step"
        )
    return errors


def boundary_errors(path: Path, data: dict[str, Any]) -> list[str]:
    """Reject persistent cache, raw SARIF, and unapproved artifact boundaries."""
    errors: list[str] = []
    jobs = data.get("jobs")
    if not isinstance(jobs, dict):
        return errors
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps")
        if not isinstance(steps, list):
            continue
        for step in steps:
            if isinstance(step, dict):
                errors.extend(boundary_step_errors(path, job_name, step))
    return errors


def exact_pr_checkout_errors(path: Path, data: dict[str, Any]) -> list[str]:
    """Require CI-security jobs to inspect PR heads rather than synthetic merge refs."""
    errors: list[str] = []
    jobs = data.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        return [f"{path}: CI-security workflow must define jobs"]
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            errors.append(f"{path}: job {job_name!r} must be a mapping")
            continue
        steps, step_errors = job_steps(path, str(job_name), job)
        errors.extend(step_errors)
        if not step_errors:
            errors.extend(
                require_checkout(path, str(job_name), steps, DEFAULT_OR_PR_HEAD, 1)
            )
    if has_write_permission(data, "security-events"):
        errors.append(
            f"{path}: CI-security workflow must not grant security-events: write"
        )
    return errors


def workflow_errors(path: Path, data: dict[str, Any]) -> list[str]:
    if path.name == OSV_WORKFLOW:
        return [*osv_errors(path, data), *boundary_errors(path, data)]
    if path.name == SCORECARD_WORKFLOW:
        return [*scorecard_errors(path, data), *boundary_errors(path, data)]
    if path.name == CODEQL_PR_WORKFLOW:
        return [*codeql_pull_request_errors(path, data), *boundary_errors(path, data)]
    if path.name == CODEQL_TRUSTED_WORKFLOW:
        return [*codeql_trusted_errors(path, data), *boundary_errors(path, data)]
    if path.name == GITLEAKS_WORKFLOW:
        return [*gitleaks_errors(path, data), *boundary_errors(path, data)]
    if path.name in {QUALITY_WORKFLOW, WORKFLOW_LINT_WORKFLOW}:
        return [
            *exact_pr_checkout_errors(path, data),
            *boundary_errors(path, data),
        ]
    return []


def validate(root: Path) -> list[str]:
    errors: list[str] = []
    workflows = root / ".github" / "workflows"
    for name in WORKFLOW_NAMES:
        path = workflows / name
        if not path.is_file():
            errors.append(f"{path}: required workflow is absent")
            continue
        try:
            data = load_yaml(path)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        errors.extend(workflow_errors(path, data))
    return errors


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[3]
    )
    return parser.parse_args()


def main() -> int:
    root = parse_args().root.resolve()
    errors = validate(root)
    if errors:
        print("CI security evidence contract violations:")
        print("\n".join(f"- {error}" for error in errors))
        return 1
    print("CI security evidence contract passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
