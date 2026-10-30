#!/usr/bin/env python3
"""Statically enforce the Parent's Python workflow-selection contract.

The narrow job parser inspects Parent envelopes and the actual steps behind
their immutable Framework test actions. The bounded source composer rejects
unsupported pin/path/input bindings before this parser examines Python setup.
Workflow content is never executed.
"""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_source

import argparse
import hashlib
from dataclasses import dataclass
import json
from pathlib import Path
import re
import stat
import sys
import textwrap
from typing import Iterable, Mapping, Sequence



from modsecurity_test_framework.product_sources.ci.lib.workflow_action_pins import read_action_reference
from modsecurity_test_framework.workflow_sources import read_connector_workflow, read_protected_workflow_source, WorkflowSourceError


CANONICAL_VERSION_FILE = ".python-version"
SETUP_PYTHON_REFERENCE = read_action_reference(connector_root(), "actions/setup-python")
SETUP_PYTHON_ACTION, SETUP_PYTHON_RELEASE_COMMENT = SETUP_PYTHON_REFERENCE.split(" ", 1)
VERIFIER_NAME = "Verify Python interpreter contract"
CANDIDATE_VERIFIER_NAME = "Verify Python candidate interpreter contract"
VERIFIER_PATH = "modules/ModSecurity-test-Framework/connector_suite/modsecurity_connector_ci/checks/common/check-python-interpreter-contract.py"
SETUP_PYTHON_OUTPUT = "${{ steps.setup-python.outputs.python-path }}"
CANDIDATE_VERSION_OUTPUT = "${{ needs.resolve-python-patch.outputs.latest_version }}"
NORMAL_VERIFIER_COMMAND = (
    f'python3 -P {VERIFIER_PATH} --version-file .python-version '
    '--expected-python "$EXPECTED_PYTHON"'
)
CANDIDATE_VERIFIER_COMMAND = (
    f'python3 -P {VERIFIER_PATH} --expected-version "$EXPECTED_VERSION" '
    '--expected-python "$EXPECTED_PYTHON"'
)
# Only the trusted-base Go resolver spans pre/post-migration repository layouts.
# Exact lines, fixed paths, both interpreter checks and the failure branch are
# part of this exception; normalization removes only indentation/comments.
TRUSTED_BASE_VERIFIER_COMMAND = """set -eu
migrated=modules/ModSecurity-test-Framework/connector_suite/modsecurity_connector_ci/checks/common/check-python-interpreter-contract.py
legacy=ci/checks/common/check-python-interpreter-contract.py
if [ -f "$migrated" ] && [ ! -L "$migrated" ]; then
  python3 -P "$migrated" --version-file .python-version --expected-python "$EXPECTED_PYTHON"
elif [ -f "$legacy" ] && [ ! -L "$legacy" ]; then
  python3 -I "$legacy" --version-file .python-version --expected-python "$EXPECTED_PYTHON"
else
  echo 'Trusted base has no supported Python interpreter contract' >&2
  exit 1
fi"""
TRUSTED_BASE_GITLINK_COMMAND = """set -euo pipefail
revision=$(git rev-parse HEAD:modules/ModSecurity-test-Framework)
printf '%s\\n' "$revision" | grep -Eq '^[a-f0-9]{40}$'
printf 'revision=%s\\n' "$revision" >> "$GITHUB_OUTPUT"
"""
TRUSTED_BASE_CONTEXT_GUARD = (
    "${{ hashFiles('" + VERIFIER_PATH + "') != '' }}"
)
TRUSTED_BASE_CHECKOUT_REFERENCE = read_action_reference(connector_root(), "actions/checkout")
TRUSTED_BASE_CONTEXT_NAME = "Bind migrated trusted-base Framework context when available"
TRUSTED_BASE_CONTEXT_COMMAND = r"""set -euo pipefail
connector_root="${GITHUB_WORKSPACE:?}"
connector_revision=$(git -C "$connector_root" rev-parse HEAD)
python3 -I "$connector_root/ci/run-trusted-framework.py" \
  --tool connector-context \
  --connector-root "$connector_root" \
  --connector-revision "$connector_revision" -- \
  --connector-root "$connector_root" \
  --connector-revision "$connector_revision" \
  --framework-revision "$EXPECTED_FRAMEWORK_REVISION"
"""

UPDATE_PYTHON_VERSION_WORKFLOW = "update-python-version.yml"
UPDATE_GO_VERSION_WORKFLOW = "update-go-version.yml"
UPDATE_WORKFLOW_TOOLS_WORKFLOW = "update-workflow-tools.yml"
CI_SECURITY_WORKFLOW_LINT_WORKFLOW = "ci-security-workflow-lint.yml"
CI_SECURITY_CODEQL_WORKFLOW = "ci-security-codeql.yml"
PROTECTED_NGINX_BROKER_CALLER_WORKFLOW = "run-protected-nginx-root-broker.yml"
PROTECTED_NGINX_BROKER_REUSABLE_WORKFLOW = (
    "Easton97-Jens/ModSecurity-conector/.github/workflows/nginx-root-broker.yml@"
    "8ae707d72f1a8acb25d239e55e28a73cbc7522b1"
)
REUSABLE_FIVE_CONNECTORS_PROFILE_WORKFLOW = "reusable-five-connectors-profile.yml"
JOB_LEVEL_REUSABLE_WORKFLOW_INVOCATION = "job-level reusable workflow invocation"


@dataclass(frozen=True, order=True)
class JobIdentity:
    """A stable workflow filename/job-ID pair used by the inventory contract."""

    workflow: str
    job: str

    def display(self) -> str:
        return f"{self.workflow}:{self.job}"


TRUSTED_BASE_MIGRATION_JOB = JobIdentity("ci-security-codeql.yml", "trusted-go-version")

# These are the explicit Parent-native Python jobs, including the resolver and
# publisher in update-python-version.yml and all three Go updater
# jobs. The Go updater is Python-bearing because its bounded official-metadata
# parser and workflow-contract tests use the canonical interpreter. The one
# Python candidate job below is deliberately separate because it validates a
# prospective patch before the canonical .python-version file is changed.
EXPECTED_NORMAL_PYTHON_JOBS = frozenset(
    {
        JobIdentity(REUSABLE_FIVE_CONNECTORS_PROFILE_WORKFLOW, "aggregate"),
        JobIdentity(REUSABLE_FIVE_CONNECTORS_PROFILE_WORKFLOW, "no-crs"),
        JobIdentity(REUSABLE_FIVE_CONNECTORS_PROFILE_WORKFLOW, "resolve-profile"),
        JobIdentity("ci-security-secrets.yml", "advisory-full-history"),
        JobIdentity("ci-security-secrets.yml", "pull-request-range"),
        JobIdentity(CI_SECURITY_WORKFLOW_LINT_WORKFLOW, "actionlint"),
        JobIdentity(CI_SECURITY_WORKFLOW_LINT_WORKFLOW, "apr-util-provenance"),
        JobIdentity(CI_SECURITY_WORKFLOW_LINT_WORKFLOW, "zizmor"),
        JobIdentity("ci-findings-regressions.yml", "nginx-b09-regression"),
        JobIdentity(CI_SECURITY_CODEQL_WORKFLOW, "trusted-go-version"),
        JobIdentity(CI_SECURITY_CODEQL_WORKFLOW, "traefik-go"),
        JobIdentity(CI_SECURITY_CODEQL_WORKFLOW, "bounded-c-cpp"),
        JobIdentity("validate-go-candidate.yml", "go-candidate"),
        JobIdentity("test-connectors-with-crs-no-mrts.yml", "connector-mode"),
        JobIdentity("test-connectors-with-crs-no-mrts.yml", "aggregate-with-crs-no-mrts"),
        JobIdentity("test-nginx-exact-head.yml", "nginx-exact-head"),
        JobIdentity("lint.yml", "scaffold-lint"),
        JobIdentity("nginx-root-broker.yml", "trusted-root-smoke"),
        JobIdentity("open-connectors-smoke.yml", "open-connectors-smoke"),
        JobIdentity("protocol-contract.yml", "nginx-profile-and-client-preflight"),
        JobIdentity("protocol-contract.yml", "protocol-contract"),
        JobIdentity("quick-framework-check.yml", "quick-check"),
        JobIdentity("sonarqube.yml", "analysis"),
        JobIdentity(PROTECTED_NGINX_BROKER_CALLER_WORKFLOW, "prepare-manifests"),
        JobIdentity(PROTECTED_NGINX_BROKER_CALLER_WORKFLOW, "verify-evidence"),
        JobIdentity("test-apache.yml", "apache-autotools-bootstrap"),
        JobIdentity("test-apache.yml", "apache-structure"),
        JobIdentity("test-common.yml", "common-structure"),
        JobIdentity("test-envoy.yml", "envoy-contract"),
        JobIdentity("test-full-smoke-sequential.yml", "manual-heavy-runtime-validation"),
        JobIdentity("test-haproxy.yml", "haproxy-structure"),
        JobIdentity("test-lighttpd.yml", "lighttpd-contract"),
        JobIdentity("test-nginx.yml", "nginx-structure"),
        JobIdentity("test-traefik.yml", "traefik-contract"),
        JobIdentity(UPDATE_PYTHON_VERSION_WORKFLOW, "publish-python-update"),
        JobIdentity(UPDATE_PYTHON_VERSION_WORKFLOW, "resolve-python-patch"),
        JobIdentity(UPDATE_GO_VERSION_WORKFLOW, "create-go-update-pr"),
        JobIdentity(UPDATE_GO_VERSION_WORKFLOW, "resolve-go-release"),
        JobIdentity(UPDATE_GO_VERSION_WORKFLOW, "validate-go-release"),
        JobIdentity("update-submodules.yml", "create-submodule-update-pr"),
        JobIdentity("update-submodules.yml", "validate-submodule-update"),
        JobIdentity(UPDATE_WORKFLOW_TOOLS_WORKFLOW, "publisher"),
        JobIdentity(UPDATE_WORKFLOW_TOOLS_WORKFLOW, "resolver"),
        JobIdentity(UPDATE_WORKFLOW_TOOLS_WORKFLOW, "validator"),
        JobIdentity("verified-report-governance.yml", "report-governance"),
    }
)

# A job-level reusable call may select Python code outside the caller source.
# It cannot satisfy the ordinary setup-python-step shape, so this is an exact
# inventory of the only approved immutable protected broker calls instead of a
# broad exception for reusable workflows.
EXPECTED_IMMUTABLE_REUSABLE_PYTHON_JOBS: Mapping[JobIdentity, str] = {
    JobIdentity(PROTECTED_NGINX_BROKER_CALLER_WORKFLOW, "run-no-crs-broker"):
        PROTECTED_NGINX_BROKER_REUSABLE_WORKFLOW,
    JobIdentity(PROTECTED_NGINX_BROKER_CALLER_WORKFLOW, "run-with-crs-broker"):
        PROTECTED_NGINX_BROKER_REUSABLE_WORKFLOW,
}

# Local reusable callers do not themselves execute Python, but their calls are
# conservatively classified as Python-bearing. Keep approved caller identities in
# a separate closed mapping so its callee jobs retain the normal strict setup
# and verifier contract above.
EXPECTED_LOCAL_REUSABLE_PYTHON_CALLERS: Mapping[JobIdentity, str] = {
    JobIdentity("all-connectors-no-crs.yml", "no-crs"): (
        "./.github/workflows/reusable-five-connectors-profile.yml"
    ),
}

# This protected bootstrap deliberately uses a root-owned system interpreter
# only inside its cleared, unprivileged namespace. Its complete dedicated
# source trust contract is required instead of normal setup-python execution.
TRUSTED_SYSTEM_PYTHON_JOB = JobIdentity(
    "run-trusted-lighttpd-namespace-dispatch.yml", "trusted-lighttpd-namespace"
)
TRUSTED_SYSTEM_WORKFLOW_SHA256 = "37e9223b670faa76d3a2c501d7bec87c037879e2370e498f6110a8678a9ce94c"
EXPECTED_SYSTEM_PYTHON_JOBS = frozenset({TRUSTED_SYSTEM_PYTHON_JOB})


# This is intentionally an exact pair, not a filename/job-name pattern.  It
# does not permit ambient Python: the candidate version and setup-python path
# are both checked by the stricter verifier shape below.
CANDIDATE_VALIDATION_JOB = JobIdentity(
    UPDATE_PYTHON_VERSION_WORKFLOW, "validate-python-patch"
)

# The list is intentionally explicit.  Broadly classifying every Make target
# as Python-bearing would both create false positives and conceal an inventory
# decision.  Each target here invokes Parent/Framework Python in the current
# workflow contract.
KNOWN_PYTHON_MAKE_TARGETS = frozenset(
    {
        "capabilities-all-connectors-evidence",
        "check-envoy-common-adoption",
        "check-ci-security-contract",
        "check-lighttpd-common-adoption",
        "check-remaining-connectors-build-wiring",
        "check-remaining-connectors-claim-policy",
        "check-remaining-connectors-common-adoption",
        "check-remaining-connectors-host-integration",
        "check-remaining-connectors-start-wiring",
        "check-test-matrix",
        "check-traefik-common-adoption",
        "codex-check",
        "generate-test-matrix",
        "install-dev-deps",
        "lint",
        "quick-check",
        "readiness-remaining-connectors",
        "report-governance",
        "setup-dev",
        "test-no-crs",
        "test-protocol-client",
        "test-with-crs",
    }
)

# Executable basenames are recognized structurally below rather than with a
# regular expression.  The scanner deliberately does not search arbitrary
# shell text: `echo python3`, comments, and here-document bodies are not
# interpreter executions.  Versioned and absolute/venv forms remain covered
# through `is_python_or_pip_command()`.
MAX_SHELL_SOURCE_LENGTH = 131_072
MAX_SHELL_NESTING = 32
SHELL_CONTROL_WORDS = frozenset(
    {
        "!",
        "{",
        "}",
        "do",
        "done",
        "elif",
        "else",
        "esac",
        "fi",
        "for",
        "function",
        "if",
        "in",
        "then",
        "time",
        "until",
        "while",
    }
)
SHELL_COMMAND_OPTION_ONLY = frozenset({"-v", "-V"})
SHELL_OPTIONS_WITH_VALUE = frozenset(
    {
        "-C",
        "-g",
        "-h",
        "-p",
        "-r",
        "-t",
        "-u",
        "--chdir",
        "--group",
        "--host",
        "--prompt",
        "--role",
        "--user",
    }
)
PYTHON_MATRIX_KEY = re.compile(
    r"^\s*(?:-\s*)?python(?:[-_]?versions?)?\s*:", re.IGNORECASE
)
PYTHON_MATRIX_REFERENCE = re.compile(
    r"\bmatrix\.python(?:[-_]?versions?)?\b", re.IGNORECASE
)
VERIFIER_COMMAND_LINE = re.compile(
    rf"(?m)^\s*python3\s+-P\s+{re.escape(VERIFIER_PATH)}\b[^\n]*$"
)


class ContractInputError(ValueError):
    """Raised for invalid command input or an unusable canonical version file."""


@dataclass
class Step:
    index: int
    start_line: int
    indent: int
    lines: list[tuple[int, str]]

    def scalar(self, key: str) -> str | None:
        for _, _, entry in direct_step_entries(self.lines, self.indent):
            if entry[0] == key:
                return clean_scalar(entry[1])
        return None

    def raw_scalar(self, key: str) -> str | None:
        """Return the unnormalized scalar text for a direct step mapping key.

        The setup-python provenance comment is part of this contract, so it
        must be checked before `clean_scalar()` removes a YAML comment.
        """

        for _, _, entry in direct_step_entries(self.lines, self.indent):
            if entry[0] == key:
                return entry[1].strip()
        return None

    def nested_mapping(self, key: str) -> dict[str, str]:
        for position, parent_indent, entry in direct_step_entries(
            self.lines, self.indent
        ):
            if entry[0] == key:
                return direct_child_mapping(self.lines[position + 1 :], parent_indent)
        return {}

    def run(self) -> str:
        for position, parent_indent, entry in direct_step_entries(
            self.lines, self.indent
        ):
            if entry[0] == "run":
                return step_run_value(
                    entry[1], self.lines[position + 1 :], parent_indent
                )
        return ""


@dataclass
class Job:
    identity: JobIdentity
    indent: int
    lines: list[tuple[int, str]]

    def scalar(self, key: str) -> str | None:
        """Return a direct job-level scalar without descending into steps."""

        for _, line in self.lines[1:]:
            indent = indentation(line)
            if indent != self.indent + 2:
                continue
            entry = mapping_entry(line[indent:])
            if entry is not None and entry[0] == key:
                return clean_scalar(entry[1])
        return None

    def steps(self) -> list[Step]:
        steps_line = steps_mapping_index(self.lines, self.indent)
        if steps_line is None:
            return []
        return build_steps(self.lines[steps_line + 1 :], self.indent)


def indentation(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def step_mapping_tail(
    line: str, position: int, step_indent: int, line_indent: int
) -> str | None:
    """Return a direct step-mapping tail in the supported YAML subset."""

    tail = line[line_indent:]
    if position == 0 and line_indent == step_indent and tail.startswith("- "):
        return tail[2:]
    if line_indent == step_indent + 2:
        return tail
    return None


def direct_step_entries(
    lines: Sequence[tuple[int, str]], step_indent: int
) -> Iterable[tuple[int, int, tuple[str, str]]]:
    """Yield direct mapping entries from one workflow step."""

    for position, (_, line) in enumerate(lines):
        line_indent = indentation(line)
        tail = step_mapping_tail(line, position, step_indent, line_indent)
        if tail is None:
            continue
        entry = mapping_entry(tail)
        if entry is not None:
            yield position, line_indent, entry


def direct_child_mapping(
    lines: Sequence[tuple[int, str]], parent_indent: int
) -> dict[str, str]:
    """Collect direct scalar children until the parent mapping ends."""

    result: dict[str, str] = {}
    for _, child_line in lines:
        child_indent = indentation(child_line)
        if child_line.strip() and child_indent <= parent_indent:
            break
        if child_indent != parent_indent + 2:
            continue
        child_entry = mapping_entry(child_line[child_indent:])
        if child_entry is not None:
            result[child_entry[0]] = clean_scalar(child_entry[1])
    return result


def step_run_value(
    value: str, following_lines: Sequence[tuple[int, str]], parent_indent: int
) -> str:
    """Return a supported inline or block ``run`` value."""

    scalar = clean_scalar(value)
    if not scalar.startswith(("|", ">")):
        return scalar
    return textwrap.dedent("\n".join(block_lines(following_lines, parent_indent))).strip()


def block_lines(
    lines: Sequence[tuple[int, str]], parent_indent: int
) -> list[str]:
    """Return a YAML block body without crossing its parent indentation."""

    result: list[str] = []
    for _, line in lines:
        if line.strip() and indentation(line) <= parent_indent:
            break
        result.append(line)
    return result


def steps_mapping_index(lines: Sequence[tuple[int, str]], job_indent: int) -> int | None:
    """Locate the direct ``steps:`` mapping in a parsed job."""

    for position, (_, line) in enumerate(lines):
        if indentation(line) == job_indent + 2 and line.strip() == "steps:":
            return position
    return None


def append_step(
    result: list[Step],
    lines: list[tuple[int, str]] | None,
    start_line: int,
    step_indent: int,
) -> None:
    """Append one accumulated workflow step when one is available."""

    if lines is not None:
        result.append(Step(len(result), start_line, step_indent, lines))


def build_steps(lines: Sequence[tuple[int, str]], job_indent: int) -> list[Step]:
    """Split the bounded YAML ``steps:`` body into individual steps."""

    step_indent = job_indent + 4
    result: list[Step] = []
    current: list[tuple[int, str]] | None = None
    current_start = 0
    for line_number, line in lines:
        line_indent = indentation(line)
        if line.strip() and line_indent <= job_indent + 2:
            break
        if line_indent == step_indent and line[line_indent:].startswith("- "):
            append_step(result, current, current_start, step_indent)
            current = [(line_number, line)]
            current_start = line_number
            continue
        if current is not None:
            current.append((line_number, line))
    append_step(result, current, current_start, step_indent)
    return result


def is_mapping_key(value: str) -> bool:
    """Return whether *value* is in the deliberately narrow YAML key subset."""

    return bool(value) and all(
        character.isascii() and (character.isalnum() or character in "_-")
        for character in value
    )


def mapping_entry(value: str) -> tuple[str, str] | None:
    """Parse the small ``key: value`` YAML shape used by this checker.

    This deliberately avoids a general YAML parser and regular-expression
    backtracking.  It accepts exactly the former contract's ASCII key subset,
    keeps colons in the value, and leaves scalar normalization to
    :func:`clean_scalar`.
    """

    separator = value.find(":")
    if separator <= 0:
        return None
    key = value[:separator]
    if not is_mapping_key(key):
        return None
    return key, value[separator + 1 :].lstrip()


def job_header(value: str) -> str | None:
    """Return a narrow job key when *value* is a YAML job header."""

    entry = mapping_entry(value)
    if entry is None:
        return None
    key, remainder = entry
    if not remainder or remainder.startswith("#"):
        return key
    return None


def clean_scalar(value: str) -> str:
    """Normalize the scalar forms used by the checked-in workflow contract."""

    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    if " #" in value:
        value = value.split(" #", 1)[0].rstrip()
    return value


def repository_root() -> Path:
    return connector_root()


def is_ascii_decimal(value: str) -> bool:
    """Return whether *value* contains one or more ASCII decimal digits."""

    return bool(value) and all("0" <= character <= "9" for character in value)


def is_exact_python_315_version(value: str) -> bool:
    """Return whether *value* is the accepted ``3.15.N`` version shape."""

    prefix = "3.15."
    if not value.startswith(prefix):
        return False
    patch = value.removeprefix(prefix)
    return patch == "0" or (
        bool(patch) and patch[0] != "0" and is_ascii_decimal(patch)
    )


def parse_exact_version(value: str, source: str) -> str:
    if not is_exact_python_315_version(value):
        raise ContractInputError(
            f"{source} must be an exact Python 3.15.N version; got {value!r}"
        )
    return value


def canonical_version_file(root: Path) -> Path:
    """Return the one regular, non-symlink canonical version file.

    The public CLI intentionally does not accept a user-selected root or
    version-file path.  This helper is kept separate so in-process tests can
    supply an isolated repository root without widening the command boundary.
    """

    candidate = root / CANONICAL_VERSION_FILE
    try:
        metadata = candidate.lstat()
    except OSError as exc:
        raise ContractInputError(
            f"cannot inspect canonical version file {candidate}: {exc}"
        ) from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise ContractInputError(f"canonical version file must not be a symlink: {candidate}")
    if not stat.S_ISREG(metadata.st_mode):
        raise ContractInputError(f"canonical version file must be a regular file: {candidate}")
    return candidate


def read_canonical_version(path: Path) -> str:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ContractInputError(f"cannot inspect canonical version file {path}: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise ContractInputError(f"canonical version file must not be a symlink: {path}")
    if not stat.S_ISREG(metadata.st_mode):
        raise ContractInputError(f"canonical version file must be a regular file: {path}")
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ContractInputError(f"cannot read canonical version file {path}: {exc}") from exc
    if content.endswith("\n"):
        content = content[:-1]
    if "\n" in content or "\r" in content:
        raise ContractInputError(
            f"canonical version file {path} must contain one exact version and an optional final newline"
        )
    return parse_exact_version(content, f"canonical version file {path}")


def version_tuple(value: str) -> tuple[int, int, int]:
    major, minor, patch = (int(part) for part in value.split("."))
    return major, minor, patch


def workflow_files(root: Path) -> tuple[list[Path], list[str]]:
    workflows = root / ".github" / "workflows"
    if not workflows.is_dir():
        raise ContractInputError(f"workflow directory is missing: {workflows}")

    paths = sorted({*workflows.glob("*.yml"), *workflows.glob("*.yaml")})
    result: list[Path] = []
    violations: list[str] = []
    for path in paths:
        if path.is_symlink():
            violations.append(f"workflow must not be a symlink: {path.relative_to(root)}")
        elif path.is_file():
            result.append(path)
    return result, violations


def read_workflow_lines(path: Path) -> tuple[list[str] | None, list[str]]:
    """Inspect actual pinned callee steps while retaining the Parent job contract."""

    try:
        return read_connector_workflow(path).splitlines(), []
    except WorkflowSourceError as exc:
        return None, [f"cannot compose immutable workflow {path.name}: {exc}"]
    except UnicodeDecodeError as exc:
        return None, [f"cannot decode workflow {path.name}: {exc}"]
    except OSError as exc:
        return None, [f"cannot read workflow {path.name}: {exc}"]


def jobs_mapping_index(lines: Sequence[str]) -> int | None:
    """Locate the top-level ``jobs:`` mapping when it exists."""

    for index, line in enumerate(lines):
        if indentation(line) == 0 and line.strip() == "jobs:":
            return index
    return None


def starts_top_level_section(line: str) -> bool:
    """Return whether a nonblank line ends the current ``jobs:`` section."""

    return bool(line.strip()) and indentation(line) == 0


def job_block_transition(
    line: str, current_indent: int | None
) -> tuple[int | None, str | None]:
    """Return the selected job indentation and any new job header."""

    line_indent = indentation(line)
    header = job_header(line[line_indent:])
    if header is None:
        return current_indent, None
    if current_indent is None:
        return line_indent, header
    if line_indent == current_indent:
        return current_indent, header
    return current_indent, None


def workflow_job_blocks(
    path: Path, lines: Sequence[str], jobs_start: int
) -> Iterable[tuple[JobIdentity, int, list[tuple[int, str]]]]:
    """Yield the narrow, indentation-delimited jobs below ``jobs:``."""

    job_indent: int | None = None
    current_identity: JobIdentity | None = None
    current_lines: list[tuple[int, str]] = []
    for line_number, line in enumerate(lines[jobs_start + 1 :], start=jobs_start + 2):
        if starts_top_level_section(line):
            break
        job_indent, header = job_block_transition(line, job_indent)
        if header is not None:
            if current_identity is not None:
                assert job_indent is not None
                yield current_identity, job_indent, current_lines
            current_identity = JobIdentity(path.name, header)
            current_lines = [(line_number, line)]
            continue
        if current_identity is not None:
            current_lines.append((line_number, line))
    if current_identity is not None:
        assert job_indent is not None
        yield current_identity, job_indent, current_lines


def add_job_block(
    result: dict[JobIdentity, Job],
    violations: list[str],
    identity: JobIdentity,
    job_indent: int,
    lines: list[tuple[int, str]],
) -> None:
    """Record one workflow job or retain the existing duplicate diagnostic."""

    if identity in result:
        violations.append(f"duplicate workflow job: {identity.display()}")
        return
    result[identity] = Job(identity, job_indent, list(lines))


def parse_jobs(path: Path) -> tuple[dict[JobIdentity, Job], list[str]]:
    lines, read_errors = read_workflow_lines(path)
    if lines is None:
        return {}, read_errors

    jobs_start = jobs_mapping_index(lines)
    if jobs_start is None:
        return {}, []

    result: dict[JobIdentity, Job] = {}
    violations: list[str] = []
    for identity, job_indent, job_lines in workflow_job_blocks(path, lines, jobs_start):
        add_job_block(result, violations, identity, job_indent, job_lines)
    return result, violations


def run_without_verifier_command(
    run: str, identity: JobIdentity | None = None, *, verifier_name: str | None = None
) -> str:
    if (identity == TRUSTED_BASE_MIGRATION_JOB and verifier_name == VERIFIER_NAME and
            exact_script(run, TRUSTED_BASE_VERIFIER_COMMAND)):
        return ""
    return VERIFIER_COMMAND_LINE.sub("", run)


def is_shell_name(value: str) -> bool:
    """Return whether *value* is a POSIX-style variable name."""

    if not value or not (value[0].isalpha() or value[0] == "_"):
        return False
    return all(character.isalnum() or character == "_" for character in value[1:])


def is_shell_assignment(word: "ShellWord") -> bool:
    separator = word.value.find("=")
    return (
        not word.redirection_target
        and separator > 0
        and is_shell_name(word.value[:separator])
    )


@dataclass(frozen=True)
class ShellWord:
    """One bounded, source-only shell word.

    ``dynamic`` means that the word contains a shell expansion.  A static
    basename can still be safely classified (for example
    ``$RUNNER_TEMP/tool/actionlint``); an expansion in the executable basename
    is rejected rather than silently treated as non-Python.
    """

    value: str
    dynamic: bool = False
    redirection_target: bool = False


@dataclass(frozen=True)
class ShellCommand:
    command: ShellWord
    arguments: tuple[ShellWord, ...]


@dataclass(frozen=True)
class ShellAnalysis:
    commands: tuple[ShellCommand, ...]
    errors: tuple[str, ...]


@dataclass
class ShellScanState:
    """Mutable state for one bounded linear shell scan."""

    cursor: int
    words: list[ShellWord]
    redirection_target: bool = False


@dataclass
class ShellWordReadState:
    """Mutable state while consuming one source-only shell word."""

    characters: list[str]
    dynamic: bool = False
    quote: str | None = None
    stopped: bool = False


def command_basename(command: str) -> str:
    return command.rsplit("/", 1)[-1]


def static_command_basename(word: ShellWord) -> str | None:
    """Return a statically known executable basename, if one is available."""

    basename = command_basename(word.value)
    if word.dynamic and "$" in basename:
        return None
    return basename


def is_dotted_ascii_decimal(value: str) -> bool:
    """Return whether *value* is one or more dotted ASCII decimal components."""

    return all(is_ascii_decimal(component) for component in value.split("."))


def is_versioned_command_name(command: str, prefix: str) -> bool:
    """Recognize an unversioned or dotted-ASCII-version executable name."""

    if not command.startswith(prefix):
        return False
    suffix = command.removeprefix(prefix)
    return not suffix or is_dotted_ascii_decimal(suffix)


def is_python_or_pip_command(command: str) -> bool:
    basename = command_basename(command)
    return any(
        is_versioned_command_name(basename, prefix) for prefix in ("python", "pip")
    )


def is_bare_pip_command(command: str) -> bool:
    return is_versioned_command_name(command_basename(command), "pip")


def read_heredoc_delimiter(
    line: str, start: int
) -> tuple[str | None, bool, int, str | None]:
    """Read a narrow, static here-document delimiter after ``<<``.

    Dynamic and malformed delimiters are not safe to skip: their bodies could
    contain a hidden command.  They are therefore reported as scanner errors.
    """

    cursor = start + 2
    if cursor < len(line) and line[cursor] == "<":
        # ``<<<`` is a here-string, not a here-document.
        return None, False, cursor + 1, None
    strip_tabs = cursor < len(line) and line[cursor] == "-"
    if strip_tabs:
        cursor += 1
    while cursor < len(line) and line[cursor] in " \t":
        cursor += 1
    if cursor >= len(line):
        return None, strip_tabs, cursor, "here-document has no delimiter"

    quote = line[cursor]
    if quote in {"'", '"'}:
        closing = line.find(quote, cursor + 1)
        if closing < 0:
            return None, strip_tabs, len(line), "unterminated here-document delimiter"
        delimiter = line[cursor + 1 : closing]
        cursor = closing + 1
    else:
        delimiter_start = cursor
        while cursor < len(line) and line[cursor] not in " \t;|&<>":
            cursor += 1
        delimiter = line[delimiter_start:cursor]

    if not is_shell_name(delimiter):
        return (
            None,
            strip_tabs,
            cursor,
            "here-document delimiter must be a static shell identifier",
        )
    return delimiter, strip_tabs, cursor, None


def advance_heredoc_quote(
    line: str, cursor: int, quote: str
) -> tuple[int, str | None]:
    """Advance one quoted character while looking only for heredoc openings."""

    character = line[cursor]
    if character == "\\" and quote == '"':
        return cursor + 2, quote
    if character == quote:
        return cursor + 1, None
    return cursor + 1, quote


def shell_comment_starts(line: str, cursor: int) -> bool:
    """Return whether ``#`` begins a supported shell comment."""

    if line[cursor] != "#":
        return False
    return cursor == 0 or line[cursor - 1].isspace() or line[cursor - 1] in ";|&"


def heredoc_starts_at(line: str, cursor: int) -> bool:
    """Return whether the cursor starts a possible here-document operator."""

    return line[cursor] == "<" and cursor + 1 < len(line) and line[cursor + 1] == "<"


def record_heredoc_opening(
    openings: list[tuple[str, bool]],
    errors: list[str],
    delimiter: str | None,
    strip_tabs: bool,
    error: str | None,
) -> None:
    """Retain a valid delimiter or its fail-closed scanner error."""

    if error is not None:
        errors.append(error)
    elif delimiter is not None:
        openings.append((delimiter, strip_tabs))


def heredoc_openings(line: str) -> tuple[list[tuple[str, bool]], list[str]]:
    """Find static here-document openings outside comments and shell quotes."""

    openings: list[tuple[str, bool]] = []
    errors: list[str] = []
    cursor = 0
    quote: str | None = None
    while cursor < len(line):
        character = line[cursor]
        if quote is not None:
            cursor, quote = advance_heredoc_quote(line, cursor, quote)
            continue
        if character in {"'", '"'}:
            quote = character
            cursor += 1
            continue
        if character == "\\":
            cursor += 2
            continue
        if shell_comment_starts(line, cursor):
            break
        if heredoc_starts_at(line, cursor):
            delimiter, strip_tabs, cursor, error = read_heredoc_delimiter(line, cursor)
            record_heredoc_opening(openings, errors, delimiter, strip_tabs, error)
            continue
        cursor += 1
    return openings, errors


def shell_source_without_heredoc_bodies(run: str) -> tuple[str, tuple[str, ...]]:
    """Keep command lines while excluding only statically delimited bodies."""

    result: list[str] = []
    pending_delimiters: list[tuple[str, bool]] = []
    errors: list[str] = []
    for line in run.splitlines():
        if pending_delimiters:
            delimiter, strip_tabs = pending_delimiters[0]
            candidate = line.lstrip("\t") if strip_tabs else line
            if candidate.strip() == delimiter:
                pending_delimiters.pop(0)
            continue
        result.append(line)
        openings, line_errors = heredoc_openings(line)
        pending_delimiters.extend(openings)
        errors.extend(line_errors)
    if pending_delimiters:
        errors.append("unterminated here-document body")
    return "\n".join(result), tuple(errors)


class ShellScanner:
    """A bounded linear scanner for the contract's intentionally small shell subset."""

    def __init__(self, source: str, depth: int = 0) -> None:
        self.source = source
        self.depth = depth
        self.commands: list[ShellCommand] = []
        self.errors: list[str] = []

    def scan(self) -> ShellAnalysis:
        limit_error = self._scanner_limit_error()
        if limit_error is not None:
            return ShellAnalysis((), (limit_error,))

        state = ShellScanState(0, [])
        while state.cursor < len(self.source):
            self._scan_next(state)
        self._finish_scan(state)
        return ShellAnalysis(tuple(self.commands), tuple(self.errors))

    def _scanner_limit_error(self) -> str | None:
        if len(self.source) > MAX_SHELL_SOURCE_LENGTH:
            return f"shell source exceeds {MAX_SHELL_SOURCE_LENGTH} byte scanner limit"
        if self.depth > MAX_SHELL_NESTING:
            return f"shell nesting exceeds {MAX_SHELL_NESTING} levels"
        return None

    def _scan_next(self, state: ShellScanState) -> None:
        character = self.source[state.cursor]
        if character in " \t\r":
            state.cursor += 1
            return
        if shell_comment_starts(self.source, state.cursor):
            state.cursor = self._comment_end(state.cursor)
            return
        if character == "\n" or character in ";|&":
            self._consume_command_boundary(state, character)
            return
        redirection_start = self._redirection_start(state.cursor)
        if redirection_start is not None:
            state.cursor, state.redirection_target = self._consume_redirection(
                redirection_start
            )
            return
        if character in "()":
            self._consume_parenthesis(state, character)
            return
        self._consume_word(state)

    def _comment_end(self, cursor: int) -> int:
        end = self.source.find("\n", cursor)
        return len(self.source) if end < 0 else end

    def _consume_command_boundary(self, state: ShellScanState, character: str) -> None:
        if state.redirection_target:
            self.errors.append("redirection has no target")
            state.redirection_target = False
        self._finish_segment(state.words)
        state.words = []
        state.cursor = self._after_command_boundary(state.cursor, character)

    def _after_command_boundary(self, cursor: int, character: str) -> int:
        next_cursor = cursor + 1
        if (
            character in "|&"
            and next_cursor < len(self.source)
            and self.source[next_cursor] == character
        ):
            return next_cursor + 1
        return next_cursor

    def _consume_parenthesis(self, state: ShellScanState, character: str) -> None:
        if character == "(" and self._is_function_declaration(state):
            state.words = []
            state.cursor += 2
            return
        if character == "(":
            if state.redirection_target:
                state.redirection_target = False
            self._finish_segment(state.words)
            state.words = []
            state.cursor += 1
            return
        self._finish_segment(state.words)
        state.words = []
        state.cursor += 1

    def _is_function_declaration(self, state: ShellScanState) -> bool:
        cursor = state.cursor
        return (
            cursor + 1 < len(self.source)
            and self.source[cursor + 1] == ")"
            and len(state.words) == 1
            and not state.words[0].dynamic
        )

    def _consume_word(self, state: ShellScanState) -> None:
        word, state.cursor = self._read_word(state.cursor)
        if state.redirection_target:
            word = ShellWord(word.value, word.dynamic, redirection_target=True)
            state.redirection_target = False
        state.words.append(word)

    def _finish_scan(self, state: ShellScanState) -> None:
        if state.redirection_target:
            self.errors.append("redirection has no target")
        self._finish_segment(state.words)

    def _redirection_start(self, cursor: int) -> int | None:
        character = self.source[cursor]
        if character in "<>":
            return cursor
        if not character.isdigit():
            return None
        end = cursor
        while end < len(self.source) and self.source[end].isdigit():
            end += 1
        return end if end < len(self.source) and self.source[end] in "<>" else None

    def _consume_redirection(self, cursor: int) -> tuple[int, bool]:
        operator = self.source[cursor]
        cursor += 1
        if cursor < len(self.source) and self.source[cursor] == operator:
            cursor += 1
        if operator == "<" and cursor < len(self.source) and self.source[cursor] == "-":
            cursor += 1
        if cursor < len(self.source) and self.source[cursor] == "&":
            cursor += 1
            while cursor < len(self.source) and (
                self.source[cursor].isdigit() or self.source[cursor] == "-"
            ):
                cursor += 1
            return cursor, False
        return cursor, True

    def _read_word(self, cursor: int) -> tuple[ShellWord, int]:
        state = ShellWordReadState([])
        while cursor < len(self.source) and not state.stopped:
            if self._word_boundary(cursor, state.quote):
                break
            cursor = self._consume_word_character(cursor, state)
        if state.quote is not None and not state.stopped:
            self.errors.append("unterminated shell quote")
        return ShellWord("".join(state.characters), state.dynamic), cursor

    def _word_boundary(self, cursor: int, quote: str | None) -> bool:
        return quote is None and self.source[cursor] in " \t\r\n;|&<>()"

    def _consume_word_character(
        self, cursor: int, state: ShellWordReadState
    ) -> int:
        if state.quote is None:
            return self._consume_unquoted_word_character(cursor, state)
        return self._consume_quoted_word_character(cursor, state)

    def _consume_quoted_word_character(
        self, cursor: int, state: ShellWordReadState
    ) -> int:
        quote = state.quote
        assert quote is not None
        character = self.source[cursor]
        if character == quote:
            state.quote = None
            return cursor + 1
        if character == "\\" and quote == '"':
            return self._consume_quoted_escape(cursor, state)
        if character == "$" and quote == '"':
            return self._consume_word_expansion(cursor, state)
        if character == "`" and quote == '"':
            self.errors.append("backtick command substitution is unsupported")
        state.characters.append(character)
        return cursor + 1

    def _consume_quoted_escape(
        self, cursor: int, state: ShellWordReadState
    ) -> int:
        if cursor + 1 >= len(self.source):
            self.errors.append("dangling shell escape")
            state.stopped = True
            return len(self.source)
        state.characters.append(self.source[cursor + 1])
        return cursor + 2

    def _consume_unquoted_word_character(
        self, cursor: int, state: ShellWordReadState
    ) -> int:
        character = self.source[cursor]
        if character in {"'", '"'}:
            state.quote = character
            return cursor + 1
        if character == "\\":
            return self._consume_unquoted_escape(cursor, state)
        if character == "$":
            return self._consume_word_expansion(cursor, state)
        if character == "`":
            self.errors.append("backtick command substitution is unsupported")
        state.characters.append(character)
        return cursor + 1

    def _consume_unquoted_escape(
        self, cursor: int, state: ShellWordReadState
    ) -> int:
        if cursor + 1 >= len(self.source):
            self.errors.append("dangling shell escape")
            state.stopped = True
            return len(self.source)
        if self.source[cursor + 1] != "\n":
            state.characters.append(self.source[cursor + 1])
        return cursor + 2

    def _consume_word_expansion(
        self, cursor: int, state: ShellWordReadState
    ) -> int:
        cursor, expansion_dynamic = self._read_expansion(cursor, state.characters)
        state.dynamic = state.dynamic or expansion_dynamic
        return cursor

    def _read_expansion(self, cursor: int, characters: list[str]) -> tuple[int, bool]:
        if cursor + 1 >= len(self.source):
            characters.append("$")
            return cursor + 1, True
        marker = self.source[cursor + 1]
        if marker == "(":
            return self._read_parenthesized_expansion(cursor, characters)
        if marker == "{":
            return self._read_braced_expansion(cursor, characters)
        if marker.isalpha() or marker == "_":
            return self._read_named_expansion(cursor, characters)
        characters.append(self.source[cursor : cursor + 2])
        return cursor + 2, True

    def _read_parenthesized_expansion(
        self, cursor: int, characters: list[str]
    ) -> tuple[int, bool]:
        content, end = self._command_substitution(cursor)
        if content is None:
            self.errors.append("unterminated command substitution")
            return len(self.source), True
        self._inspect_parenthesized_expansion(content)
        characters.append("$()")
        return end, True

    def _inspect_parenthesized_expansion(self, content: str) -> None:
        if content.startswith("("):
            self._validate_arithmetic_expansion(content)
            return
        nested = ShellScanner(content, self.depth + 1).scan()
        self.commands.extend(nested.commands)
        self.errors.extend(nested.errors)

    def _validate_arithmetic_expansion(self, content: str) -> None:
        """Reject executable substitutions hidden inside arithmetic expansion."""

        if "$(" in content[1:]:
            self.errors.append(
                "arithmetic expansion with command substitution is unsupported"
            )
        if "`" in content:
            self.errors.append(
                "arithmetic expansion with backtick substitution is unsupported"
            )

    def _read_braced_expansion(
        self, cursor: int, characters: list[str]
    ) -> tuple[int, bool]:
        end = self._braced_expansion_end(cursor)
        if end is None:
            self.errors.append("unterminated braced shell expansion")
            return len(self.source), True
        characters.append("${}")
        return end, True

    def _read_named_expansion(
        self, cursor: int, characters: list[str]
    ) -> tuple[int, bool]:
        end = self._named_expansion_end(cursor)
        characters.append(self.source[cursor:end])
        return end, True

    def _named_expansion_end(self, cursor: int) -> int:
        end = cursor + 2
        while end < len(self.source) and (
            self.source[end].isalnum() or self.source[end] == "_"
        ):
            end += 1
        return end

    def _command_substitution(self, start: int) -> tuple[str | None, int]:
        cursor = start + 2
        content_start = cursor
        depth = 1
        quote: str | None = None
        while cursor < len(self.source):
            cursor, depth, quote = self._advance_command_substitution(
                cursor, depth, quote
            )
            if depth == 0:
                return self.source[content_start : cursor - 1], cursor
        return None, len(self.source)

    def _advance_command_substitution(
        self, cursor: int, depth: int, quote: str | None
    ) -> tuple[int, int, str | None]:
        if quote is not None:
            return self._advance_substitution_quote(cursor, depth, quote)
        character = self.source[cursor]
        if character in {"'", '"'}:
            return cursor + 1, depth, character
        if character == "\\":
            return cursor + 2, depth, None
        if character == "(":
            return cursor + 1, depth + 1, None
        if character == ")":
            return cursor + 1, depth - 1, None
        return cursor + 1, depth, None

    def _advance_substitution_quote(
        self, cursor: int, depth: int, quote: str
    ) -> tuple[int, int, str | None]:
        character = self.source[cursor]
        if character == "\\" and quote == '"':
            return cursor + 2, depth, quote
        if character == quote:
            return cursor + 1, depth, None
        return cursor + 1, depth, quote

    def _braced_expansion_end(self, start: int) -> int | None:
        cursor = start + 2
        depth = 1
        while cursor < len(self.source):
            character = self.source[cursor]
            if character == "\\":
                cursor += 2
                continue
            if character == "{":
                depth += 1
            elif character == "}":
                depth -= 1
                if depth == 0:
                    return cursor + 1
            cursor += 1
        return None

    def _finish_segment(self, words: list[ShellWord]) -> None:
        command, error = self._command_from_words(words)
        if error is not None:
            self.errors.append(error)
            return
        if command is None:
            return
        self.commands.append(command)
        self._scan_shell_script_argument(command)

    def _command_from_words(
        self, words: list[ShellWord]
    ) -> tuple[ShellCommand | None, str | None]:
        usable = [word for word in words if not word.redirection_target]
        cursor = self._first_non_assignment_word(usable)
        while cursor < len(usable):
            cursor, command, error, finished = self._command_head_transition(
                usable, cursor
            )
            if error is not None:
                return None, error
            if command is not None:
                return command, None
            if finished:
                return None, None
        return None, None

    def _first_non_assignment_word(self, words: Sequence[ShellWord]) -> int:
        cursor = 0
        while cursor < len(words) and is_shell_assignment(words[cursor]):
            cursor += 1
        return cursor

    def _command_head_transition(
        self, words: list[ShellWord], cursor: int
    ) -> tuple[int, ShellCommand | None, str | None, bool]:
        word = words[cursor]
        value = word.value if not word.dynamic else None
        if value in {"case", "for", "function"}:
            return cursor, None, None, True
        if value in SHELL_CONTROL_WORDS:
            return cursor + 1, None, None, False
        if value == "command":
            return self._command_wrapper_transition(words, cursor)
        if value == "env":
            next_cursor, error = self._skip_env_options(words, cursor + 1)
            return next_cursor, None, error, False
        if value == "sudo":
            next_cursor, error = self._skip_wrapper_options(words, cursor + 1)
            return next_cursor, None, error, False
        basename = static_command_basename(word)
        if basename is None:
            return cursor, None, "dynamic shell command head is unsupported", True
        return cursor, ShellCommand(word, tuple(words[cursor + 1 :])), None, True

    def _command_wrapper_transition(
        self, words: list[ShellWord], cursor: int
    ) -> tuple[int, ShellCommand | None, str | None, bool]:
        option_cursor = cursor + 1
        if (
            option_cursor < len(words)
            and words[option_cursor].value in SHELL_COMMAND_OPTION_ONLY
        ):
            return option_cursor, None, None, True
        next_cursor, error = self._skip_wrapper_options(words, option_cursor)
        return next_cursor, None, error, False

    def _skip_wrapper_options(
        self, words: list[ShellWord], cursor: int
    ) -> tuple[int, str | None]:
        while cursor < len(words):
            word = words[cursor]
            if word.dynamic:
                return cursor, "dynamic shell wrapper option is unsupported"
            if word.value == "--":
                return cursor + 1, None
            if not word.value.startswith("-") or word.value == "-":
                return cursor, None
            cursor += 1
            if word.value in SHELL_OPTIONS_WITH_VALUE:
                if cursor >= len(words):
                    return cursor, "shell wrapper option has no value"
                cursor += 1
        return cursor, None

    def _skip_env_options(
        self, words: list[ShellWord], cursor: int
    ) -> tuple[int, str | None]:
        while cursor < len(words):
            cursor, finished, error = self._env_option_transition(words, cursor)
            if error is not None:
                return cursor, error
            if finished:
                return cursor, None
        return cursor, None

    def _env_option_transition(
        self, words: list[ShellWord], cursor: int
    ) -> tuple[int, bool, str | None]:
        word = words[cursor]
        if word.value == "--" and not word.dynamic:
            return cursor + 1, True, None
        if is_shell_assignment(word):
            return cursor + 1, False, None
        if word.dynamic:
            return cursor, True, "dynamic env command head is unsupported"
        if not word.value.startswith("-") or word.value == "-":
            return cursor, True, None
        next_cursor = cursor + 1
        if word.value not in {"-C", "-u", "--chdir", "--unset"}:
            return next_cursor, False, None
        if next_cursor >= len(words):
            return next_cursor, True, "env option has no value"
        return next_cursor + 1, False, None

    def _scan_shell_script_argument(self, command: ShellCommand) -> None:
        basename = static_command_basename(command.command)
        if basename not in {"bash", "dash", "ksh", "sh", "zsh"}:
            return
        for index, argument in enumerate(command.arguments):
            if argument.value != "-c" or argument.dynamic:
                continue
            if index + 1 >= len(command.arguments):
                self.errors.append("shell -c has no script argument")
                return
            script = command.arguments[index + 1]
            if script.dynamic:
                self.errors.append("dynamic shell -c script is unsupported")
                return
            nested = ShellScanner(script.value, self.depth + 1).scan()
            self.commands.extend(nested.commands)
            self.errors.extend(nested.errors)
            return


def analyze_shell_source(run: str) -> ShellAnalysis:
    source, heredoc_errors = shell_source_without_heredoc_bodies(run)
    scanned = ShellScanner(source).scan()
    return ShellAnalysis(scanned.commands, heredoc_errors + scanned.errors)


def direct_python_or_pip_command(run: str) -> str | None:
    for shell_command in analyze_shell_source(run).commands:
        command = static_command_basename(shell_command.command)
        if command is not None and is_python_or_pip_command(command):
            return command
    return None


def bare_pip_command(run: str) -> str | None:
    for shell_command in analyze_shell_source(run).commands:
        command = static_command_basename(shell_command.command)
        if command is not None and is_bare_pip_command(command):
            return command
    return None


def python_make_target(run: str) -> str | None:
    for shell_command in analyze_shell_source(run).commands:
        command = static_command_basename(shell_command.command)
        if command != "make":
            continue
        for argument in shell_command.arguments:
            if not argument.dynamic and argument.value in KNOWN_PYTHON_MAKE_TARGETS:
                return argument.value
    return None


def shell_syntax_error(run: str) -> str | None:
    analysis = analyze_shell_source(run)
    return analysis.errors[0] if analysis.errors else None


def actual_python_use(step: Step, identity: JobIdentity | None = None) -> str | None:
    run = step.run()
    without_verifier = run_without_verifier_command(run, identity, verifier_name=step.scalar("name"))
    if direct_python_or_pip_command(without_verifier) is not None:
        return "direct python/pip command"
    target = python_make_target(without_verifier)
    if target is not None:
        return f"Make target {target}"
    return None


def first_python_use(steps: Iterable[Step], identity: JobIdentity | None = None) -> tuple[Step, str] | None:
    for step in steps:
        use = actual_python_use(step, identity)
        if use is not None:
            return step, use
    return None


def first_shell_syntax_error(steps: Iterable[Step], identity: JobIdentity | None = None) -> tuple[Step, str] | None:
    """Return a fail-closed shell-recognition error, if a step has one."""

    for step in steps:
        error = shell_syntax_error(run_without_verifier_command(step.run(), identity, verifier_name=step.scalar("name")))
        if error is not None:
            return step, error
    return None


def has_python_matrix_selector(job: Job) -> bool:
    """Identify Python-bearing matrix axes and matrix-derived selectors."""

    if any(PYTHON_MATRIX_REFERENCE.search(line) for _, line in job.lines):
        return True
    if any("matrix" in line.lower() for line in selector_lines(job)):
        return True

    for position, (_, line) in enumerate(job.lines):
        matrix_indent = indentation(line)
        if line[matrix_indent:].strip() != "matrix:":
            continue
        for _, child_line in job.lines[position + 1 :]:
            child_indent = indentation(child_line)
            if child_line.strip() and child_indent <= matrix_indent:
                break
            if PYTHON_MATRIX_KEY.match(child_line):
                return True
    return False


def python_job_reason(job: Job) -> str | None:
    """Classify every workflow form that can select or invoke Python.

    Reusable workflow calls cannot be proved non-Python from the caller source,
    and a Python matrix can choose a runtime without an inline command.  Both
    are deliberately inventoried rather than silently bypassing this check.
    """

    direct = first_python_use(job.steps(), job.identity)
    if direct is not None:
        return direct[1]
    syntax_error = first_shell_syntax_error(job.steps(), job.identity)
    if syntax_error is not None:
        return f"unsupported/malformed shell syntax: {syntax_error[1]}"
    if job.scalar("uses") is not None:
        return JOB_LEVEL_REUSABLE_WORKFLOW_INVOCATION
    if has_python_matrix_selector(job):
        return "Python-related matrix selector"
    return None


def script_lines(run: str) -> list[str]:
    return [line.strip() for line in run.splitlines()
            if line.strip() and not line.lstrip().startswith("#")]


def exact_script(run: str, expected: str) -> bool:
    return script_lines(run) == script_lines(expected)


def exact_command(run: str, expected: str) -> bool:
    return script_lines(run) == [expected]


def pinned_setup_step(steps: Sequence[Step]) -> tuple[Step | None, list[str]]:
    setup_like = [
        step
        for step in steps
        if (uses := step.scalar("uses")) is not None
        and uses.startswith("actions/setup-python@")
    ]
    matching = [
        step for step in setup_like if step.raw_scalar("uses") == SETUP_PYTHON_REFERENCE
    ]
    errors: list[str] = []
    if len(matching) != 1:
        if setup_like:
            errors.append(
                "actions/setup-python must use exactly "
                f"{SETUP_PYTHON_REFERENCE}; found {len(matching)} exact reference(s)"
            )
        else:
            errors.append(
                "must contain exactly one "
                f"{SETUP_PYTHON_ACTION} setup step; found {len(matching)}"
            )
        return None, errors
    setup = matching[0]
    if setup.scalar("id") != "setup-python":
        errors.append("pinned actions/setup-python step must have id: setup-python")
    return setup, errors


def selector_lines(job: Job) -> list[str]:
    lines: list[str] = []
    for _, line in job.lines:
        if re.match(r"^\s*python-version\s*:", line):
            lines.append(line.strip())
    return lines


def verifier_step(steps: Sequence[Step], name: str = VERIFIER_NAME) -> Step | None:
    named = [step for step in steps if step.scalar("name") == name]
    return named[0] if len(named) == 1 else None


def validate_order(
    identity: JobIdentity,
    steps: Sequence[Step],
    setup: Step | None,
    verifier: Step | None,
    verifier_name: str = VERIFIER_NAME,
    *, trusted_base_bootstrap: Step | None = None,
) -> list[str]:
    errors: list[str] = []
    first_use = first_python_use(
        [step for step in steps if step is not trusted_base_bootstrap], identity
    )
    if setup is None:
        if first_use is not None:
            errors.append(
                f"{identity.display()} uses Python via {first_use[1]} before pinned setup-python"
            )
        return errors
    if verifier is None:
        errors.append(f"{identity.display()} lacks exactly one {verifier_name!r} step")
    elif verifier.index <= setup.index:
        errors.append(f"{identity.display()} verifier must run after setup-python")
    if first_use is not None:
        use_step, use_kind = first_use
        if use_step.index <= setup.index:
            errors.append(
                f"{identity.display()} first Python use ({use_kind}) must be after setup-python"
            )
        if verifier is None or verifier.index >= use_step.index:
            errors.append(
                f"{identity.display()} verifier must run before first Python use ({use_kind})"
            )
    return errors


def validate_no_bare_pip(identity: JobIdentity, steps: Iterable[Step]) -> list[str]:
    """Reject PATH-dependent pip aliases even when setup has already run."""

    errors: list[str] = []
    for step in steps:
        command = bare_pip_command(run_without_verifier_command(step.run(), identity, verifier_name=step.scalar("name")))
        if command is not None:
            errors.append(
                f"{identity.display()} must not invoke bare pip command {command!r}; "
                "use python -m pip through the verified interpreter"
            )
    return errors


def validate_shell_syntax(identity: JobIdentity, steps: Iterable[Step]) -> list[str]:
    """Reject unsupported shell forms instead of silently missing Python use."""

    errors: list[str] = []
    for step in steps:
        error = shell_syntax_error(run_without_verifier_command(step.run(), identity, verifier_name=step.scalar("name")))
        if error is not None:
            errors.append(
                f"{identity.display()} step at workflow line {step.start_line} "
                f"contains unsupported/malformed shell syntax: {error}"
            )
    return errors


def normal_setup_violations(job: Job, setup: Step) -> list[str]:
    """Return normal-job setup selector violations in their contract order."""

    errors: list[str] = []
    with_values = setup.nested_mapping("with")
    if with_values.get("python-version-file") != ".python-version":
        errors.append("setup-python must use python-version-file: '.python-version'")
    if with_values.get("check-latest") != "false":
        errors.append("setup-python must use check-latest: false")
    if "python-version" in with_values:
        errors.append("normal Python jobs must not use python-version selectors")
    if any("3.15" in line or "matrix" in line for line in selector_lines(job)):
        errors.append("normal Python jobs must not use a literal or matrix Python selector")
    if has_python_matrix_selector(job):
        errors.append(
            "normal Python jobs must not declare or reference Python-related matrix selectors"
        )
    return errors


def normal_verifier_violations(verifier: Step, identity: JobIdentity | None = None) -> list[str]:
    """Return normal-job verifier-shape violations in contract order."""

    errors: list[str] = []
    if verifier.nested_mapping("env").get("EXPECTED_PYTHON") != SETUP_PYTHON_OUTPUT:
        errors.append(
            "verifier EXPECTED_PYTHON must be exactly "
            "${{ steps.setup-python.outputs.python-path }}"
        )
    if not (exact_command(verifier.run(), NORMAL_VERIFIER_COMMAND) or
            (identity == TRUSTED_BASE_MIGRATION_JOB and
             exact_script(verifier.run(), TRUSTED_BASE_VERIFIER_COMMAND))):
        errors.append(
            "verifier must invoke the interpreter checker with .python-version and "
            '"$EXPECTED_PYTHON"'
        )
    return errors


def trusted_base_migration_violations(job: Job, steps: Sequence[Step], verifier: Step) -> list[str]:
    """Bind the one exact dual-layout body to its fixed trusted-base bootstrap."""
    if job.identity != TRUSTED_BASE_MIGRATION_JOB:
        return ["dual-layout verifier is restricted to the trusted-base Go resolver"]
    errors: list[str] = []
    checkouts = [step for step in steps if (step.scalar("uses") or "").startswith("actions/checkout@")]
    if len(checkouts) != 1:
        errors.append("trusted-base migration requires exactly one reviewed checkout")
    else:
        checkout = checkouts[0]
        if (checkout.scalar("uses") != TRUSTED_BASE_CHECKOUT_REFERENCE.split(" ", 1)[0] or
                checkout.nested_mapping("with") != {
                    "submodules": "true",
                    "ref": "${{ github.event.pull_request.base.sha || github.sha }}",
                    "persist-credentials": "false",
                }):
            errors.append("trusted-base migration checkout must retain the exact base ref, submodule and credential contract")
    gitlinks = [step for step in steps if step.scalar("id") == "framework-gitlink"]
    contexts = [step for step in steps if step.scalar("name") == TRUSTED_BASE_CONTEXT_NAME]
    setups = [step for step in steps if step.scalar("id") == "setup-python"]
    if len(gitlinks) != 1 or not exact_script(gitlinks[0].run(), TRUSTED_BASE_GITLINK_COMMAND):
        errors.append("trusted-base migration requires the exact committed Framework gitlink reader")
    if len(contexts) != 1:
        errors.append("trusted-base migration requires the exact guarded authenticated Framework context")
    else:
        context = contexts[0]
        keys = [entry[0] for _, _, entry in direct_step_entries(context.lines, context.indent)]
        if (len(keys) != 5 or set(keys) != {"name", "if", "shell", "env", "run"}
                or context.scalar("if") != TRUSTED_BASE_CONTEXT_GUARD
                or context.scalar("shell") != "bash"
                or context.nested_mapping("env") != {
                    "EXPECTED_FRAMEWORK_REVISION": "${{ steps.framework-gitlink.outputs.revision }}"
                }
                or not exact_script(context.run(), TRUSTED_BASE_CONTEXT_COMMAND)):
            errors.append("trusted-base migration requires the exact guarded authenticated Framework context")
    if len(setups) != 1:
        errors.append("trusted-base migration requires the unique canonical setup-python step")
    if len(checkouts) == len(gitlinks) == len(contexts) == len(setups) == 1:
        if not (checkouts[0].index < gitlinks[0].index < contexts[0].index < setups[0].index < verifier.index):
            errors.append("trusted-base migration bootstrap must precede its verifier in reviewed order")
    return errors


def finalize_job_validation(
    identity: JobIdentity, steps: Sequence[Step], errors: list[str]
) -> list[str]:
    """Prefix structural errors before adding source-level shell violations."""

    prefixed = [f"{identity.display()}: {error}" for error in errors]
    return (
        prefixed
        + validate_no_bare_pip(identity, steps)
        + validate_shell_syntax(identity, steps)
    )


def validate_normal_job(job: Job) -> list[str]:
    steps = job.steps()
    setup, errors = pinned_setup_step(steps)
    if setup is not None:
        errors.extend(normal_setup_violations(job, setup))

    verifier = verifier_step(steps)
    trusted_base_bootstrap = None
    if verifier is not None:
        errors.extend(normal_verifier_violations(verifier, job.identity))
        if exact_script(verifier.run(), TRUSTED_BASE_VERIFIER_COMMAND):
            migration_errors = trusted_base_migration_violations(job, steps, verifier)
            errors.extend(migration_errors)
            if not migration_errors:
                trusted_base_bootstrap = next(
                    step for step in steps if step.scalar("name") == TRUSTED_BASE_CONTEXT_NAME
                )
    errors.extend(validate_order(job.identity, steps, setup, verifier,
                                 trusted_base_bootstrap=trusted_base_bootstrap))
    return finalize_job_validation(job.identity, steps, errors)


def candidate_setup_violations(job: Job, setup: Step) -> list[str]:
    """Return candidate-job setup selector violations in contract order."""

    errors: list[str] = []
    with_values = setup.nested_mapping("with")
    if with_values.get("python-version") != CANDIDATE_VERSION_OUTPUT:
        errors.append(
            "candidate setup-python must use exactly "
            "python-version: ${{ needs.resolve-python-patch.outputs.latest_version }}"
        )
    if "python-version-file" in with_values:
        errors.append("candidate setup-python must not use python-version-file")
    if with_values.get("check-latest") != "false":
        errors.append("candidate setup-python must use check-latest: false")
    if any("3.15" in line or "matrix" in line for line in selector_lines(job)):
        errors.append("candidate job must not use literal or matrix Python selectors")
    if has_python_matrix_selector(job):
        errors.append(
            "candidate job must not declare or reference Python-related matrix selectors"
        )
    return errors


def candidate_verifier_violations(verifier: Step) -> list[str]:
    """Return candidate verifier-shape violations in contract order."""

    errors: list[str] = []
    env = verifier.nested_mapping("env")
    if env.get("EXPECTED_VERSION") != CANDIDATE_VERSION_OUTPUT:
        errors.append(
            "candidate verifier EXPECTED_VERSION must be exactly "
            "${{ needs.resolve-python-patch.outputs.latest_version }}"
        )
    if env.get("EXPECTED_PYTHON") != SETUP_PYTHON_OUTPUT:
        errors.append(
            "candidate verifier EXPECTED_PYTHON must be exactly "
            "${{ steps.setup-python.outputs.python-path }}"
        )
    if not exact_command(verifier.run(), CANDIDATE_VERIFIER_COMMAND):
        errors.append(
            "candidate verifier must invoke the checker with "
            '"$EXPECTED_VERSION" and "$EXPECTED_PYTHON"'
        )
    return errors


def validate_candidate_job(job: Job) -> list[str]:
    """Validate the one explicit candidate-patch exception without widening it."""

    steps = job.steps()
    setup, errors = pinned_setup_step(steps)
    if setup is not None:
        errors.extend(candidate_setup_violations(job, setup))

    verifier = verifier_step(steps, CANDIDATE_VERIFIER_NAME)
    if verifier is not None:
        errors.extend(candidate_verifier_violations(verifier))
    errors.extend(
        validate_order(
            job.identity,
            steps,
            setup,
            verifier,
            CANDIDATE_VERIFIER_NAME,
        )
    )
    return finalize_job_validation(job.identity, steps, errors)


def downgrade_violations(
    canonical_version: str, previous_version: str | None, allow_downgrade: bool
) -> list[str]:
    """Return the explicit-authorization error for a version downgrade."""

    if previous_version is None:
        return []
    previous = parse_exact_version(previous_version, "--previous-version")
    if version_tuple(canonical_version) >= version_tuple(previous) or allow_downgrade:
        return []
    return [
        f"canonical Python version {canonical_version} is a downgrade from {previous}; "
        "pass --allow-downgrade only with explicit authorization"
    ]


def collect_workflow_jobs(root: Path) -> tuple[dict[JobIdentity, Job], list[str]]:
    """Collect workflow jobs and retain source-file diagnostics in path order."""

    paths, violations = workflow_files(root)
    jobs: dict[JobIdentity, Job] = {}
    for path in paths:
        parsed, parse_violations = parse_jobs(path)
        jobs.update(parsed)
        violations.extend(parse_violations)
    return jobs, violations


def missing_inventory_violations(
    jobs: dict[JobIdentity, Job],
    expected: frozenset[JobIdentity],
    expected_candidate_job: JobIdentity | None,
    expected_immutable_reusable_jobs: Mapping[JobIdentity, str],
) -> list[str]:
    """Return required inventory entries that are absent from the workflows."""

    violations = [
        f"expected normal Python job is absent: {identity.display()}"
        for identity in sorted(expected)
        if identity not in jobs
    ]
    if expected_candidate_job is not None and expected_candidate_job not in jobs:
        violations.append(
            f"expected candidate-validation job is absent: {expected_candidate_job.display()}"
        )
    violations.extend(
        f"expected immutable reusable Python job is absent: {identity.display()}"
        for identity in sorted(expected_immutable_reusable_jobs)
        if identity not in jobs
    )
    return violations


def detected_python_jobs(jobs: dict[JobIdentity, Job]) -> set[JobIdentity]:
    """Return the inventory of every job that can select or execute Python."""

    return {
        identity for identity, job in jobs.items() if python_job_reason(job) is not None
    }


def expected_normal_job_violations(
    jobs: dict[JobIdentity, Job],
    expected: frozenset[JobIdentity],
    detected: set[JobIdentity],
) -> list[str]:
    """Validate each expected normal job in stable inventory order."""

    violations: list[str] = []
    for identity in sorted(expected):
        job = jobs.get(identity)
        if job is None:
            continue
        if identity not in detected:
            violations.append(
                f"expected normal Python job has no detected Python use, known Make use, "
                f"reusable invocation, or Python-related matrix selector: "
                f"{identity.display()}"
            )
        violations.extend(validate_normal_job(job))
    return violations


def candidate_job_violations(
    jobs: dict[JobIdentity, Job],
    candidate_identity: JobIdentity | None,
    detected: set[JobIdentity],
) -> list[str]:
    """Validate the one candidate exception when it is configured and present."""

    if candidate_identity is None:
        return []
    candidate = jobs.get(candidate_identity)
    if candidate is None:
        return []
    violations: list[str] = []
    if candidate_identity not in detected:
        violations.append(
            "candidate-validation job has no detected Python use, known Make use, "
            "reusable invocation, or Python-related matrix selector: "
            f"{candidate_identity.display()}"
        )
    violations.extend(validate_candidate_job(candidate))
    return violations


def immutable_reusable_job_violations(
    jobs: dict[JobIdentity, Job],
    expected: Mapping[JobIdentity, str],
    detected: set[JobIdentity],
) -> list[str]:
    """Validate the closed inventory of immutable protected reusable calls."""

    violations: list[str] = []
    for identity, reference in sorted(expected.items()):
        job = jobs.get(identity)
        if job is None:
            continue
        if identity not in detected:
            violations.append(
                f"expected immutable reusable Python job has no reusable invocation: "
                f"{identity.display()}"
            )
            continue
        if python_job_reason(job) != JOB_LEVEL_REUSABLE_WORKFLOW_INVOCATION:
            violations.append(
                f"immutable reusable Python job has an unexpected execution shape: "
                f"{identity.display()}"
            )
        if job.scalar("uses") != reference:
            violations.append(
                f"immutable reusable Python job must use exactly {reference}: "
                f"{identity.display()}"
            )
    return violations


def local_reusable_caller_violations(
    jobs: dict[JobIdentity, Job],
    expected: Mapping[JobIdentity, str],
    detected: set[JobIdentity],
) -> list[str]:
    """Validate the closed inventory of approved local reusable callers."""

    violations: list[str] = []
    for identity, reference in sorted(expected.items()):
        job = jobs.get(identity)
        if job is None:
            continue
        if identity not in detected:
            violations.append(
                f"expected local reusable Python caller has no reusable invocation: "
                f"{identity.display()}"
            )
            continue
        if python_job_reason(job) != JOB_LEVEL_REUSABLE_WORKFLOW_INVOCATION:
            violations.append(
                f"local reusable Python caller has an unexpected execution shape: "
                f"{identity.display()}"
            )
        if job.scalar("uses") not in {reference, "$/" + reference.removeprefix("./")}:
            violations.append(
                f"local reusable Python caller must use exactly {reference}: "
                f"{identity.display()}"
            )
    return violations


def trusted_namespace_source_errors(root: Path, identity: JobIdentity) -> list[str]:
    """Bind the system interpreter exception to its reviewed source and trust checks."""
    contract_path = source_path("tests/test_trusted_lighttpd_namespace_dispatch_workflow.py")
    if contract_path.is_symlink() or not contract_path.is_file():
        raise ContractInputError("trusted namespace source contract must be a regular file")
    contract = load_source(contract_path)
    # This function only inspects source text; importing does not run tests.
    # Compose the caller first so its pin, permissions and passthroughs cannot
    # bypass the actual protected implementation's dedicated source contract.
    read_connector_workflow(root / ".github/workflows" / identity.workflow)
    source = read_protected_workflow_source(
        test_root(), "connector-trusted-lighttpd-namespace.yml"
    ).encode("utf-8")
    errors: list[str] = []
    if hashlib.sha256(source).hexdigest() != TRUSTED_SYSTEM_WORKFLOW_SHA256:
        errors.append("trusted system Python workflow differs from the reviewed profile")
    errors.extend(contract.trusted_dispatch_errors(source.decode("utf-8")))
    return [f"{identity.display()}: {error}" for error in errors]


def system_python_job_violations(
    root: Path, jobs: dict[JobIdentity, Job], expected: frozenset[JobIdentity]
) -> list[str]:
    """Reuse the complete dedicated source contract for the fixed bootstrap."""
    errors: list[str] = []
    for identity in sorted(expected):
        if identity != TRUSTED_SYSTEM_PYTHON_JOB or identity not in jobs:
            errors.append(f"required trusted system Python job is absent or unapproved: {identity.display()}")
            continue
        errors.extend(trusted_namespace_source_errors(root, identity))
    return errors


def unlisted_python_job_violations(
    jobs: dict[JobIdentity, Job],
    expected: frozenset[JobIdentity],
    expected_candidate_job: JobIdentity | None,
    expected_immutable_reusable_jobs: Mapping[JobIdentity, str],
    expected_local_reusable_callers: Mapping[JobIdentity, str],
    detected: set[JobIdentity],
    expected_system_python_jobs: frozenset[JobIdentity],
) -> list[str]:
    """Reject detected Python jobs absent from the explicit inventory."""

    violations: list[str] = []
    for identity in sorted(detected):
        if (
            identity in expected
            or identity == expected_candidate_job
            or identity in expected_immutable_reusable_jobs
            or identity in expected_local_reusable_callers
            or identity in expected_system_python_jobs
        ):
            continue
        violations.append(
            f"unlisted Python-related workflow job: {identity.display()} "
            f"({python_job_reason(jobs[identity])})"
        )
        violations.extend(validate_normal_job(jobs[identity]))
    return violations


def evaluate_workflow_contract(
    root: Path,
    version_file: Path,
    previous_version: str | None = None,
    allow_downgrade: bool = False,
    expected_normal_jobs: Iterable[JobIdentity] = EXPECTED_NORMAL_PYTHON_JOBS,
    expected_candidate_job: JobIdentity | None = CANDIDATE_VALIDATION_JOB,
    expected_immutable_reusable_jobs: Mapping[JobIdentity, str] | None = None,
    expected_local_reusable_callers: Mapping[JobIdentity, str] | None = None,
    expected_system_python_jobs: Iterable[JobIdentity] | None = None,
) -> tuple[str, list[str], set[JobIdentity]]:
    """Evaluate source-only workflow policy and return version, violations, inventory."""

    canonical_version = read_canonical_version(version_file)
    violations = downgrade_violations(
        canonical_version, previous_version, allow_downgrade
    )
    jobs, workflow_violations = collect_workflow_jobs(root)
    violations.extend(workflow_violations)

    expected = frozenset(expected_normal_jobs)
    expected_system = frozenset(EXPECTED_SYSTEM_PYTHON_JOBS if expected_system_python_jobs is None else expected_system_python_jobs)
    expected_reusable = dict(
        EXPECTED_IMMUTABLE_REUSABLE_PYTHON_JOBS
        if expected_immutable_reusable_jobs is None
        else expected_immutable_reusable_jobs
    )
    expected_local_callers = dict(
        EXPECTED_LOCAL_REUSABLE_PYTHON_CALLERS
        if expected_local_reusable_callers is None
        else expected_local_reusable_callers
    )
    violations.extend(
        missing_inventory_violations(jobs, expected, expected_candidate_job, expected_reusable)
    )
    detected = detected_python_jobs(jobs)
    violations.extend(system_python_job_violations(root, jobs, expected_system))
    violations.extend(expected_normal_job_violations(jobs, expected, detected))
    violations.extend(candidate_job_violations(jobs, expected_candidate_job, detected))
    violations.extend(immutable_reusable_job_violations(jobs, expected_reusable, detected))
    violations.extend(
        local_reusable_caller_violations(jobs, expected_local_callers, detected)
    )
    violations.extend(
        unlisted_python_job_violations(
            jobs,
            expected,
            expected_candidate_job,
            expected_reusable,
            expected_local_callers,
            detected,
            expected_system,
        )
    )

    return canonical_version, violations, detected


def parser() -> argparse.ArgumentParser:
    argument_parser = argparse.ArgumentParser(
        description="Validate Parent GitHub Actions Python setup and interpreter checks."
    )
    argument_parser.add_argument(
        "--version-file",
        metavar="PATH",
        default=CANONICAL_VERSION_FILE,
        help="must be the literal canonical path .python-version",
    )
    argument_parser.add_argument(
        "--previous-version",
        metavar="3.15.N",
        help="previous canonical version; reject a downgrade unless explicitly allowed",
    )
    argument_parser.add_argument(
        "--allow-downgrade",
        action="store_true",
        help="acknowledge an intentional canonical-version downgrade",
    )
    argument_parser.add_argument("--json", action="store_true", help="emit JSON")
    return argument_parser


def report(
    status: str,
    canonical_version: str | None,
    violations: list[str],
    detected: set[JobIdentity],
    as_json: bool,
) -> None:
    if as_json:
        print(
            json.dumps(
                {
                    "canonical_version": canonical_version,
                    "detected_python_jobs": [item.display() for item in sorted(detected)],
                    "status": status,
                    "violations": violations,
                },
                sort_keys=True,
            )
        )
        return
    if status == "valid":
        print(
            "python-version-contract: valid "
            f"(Python {canonical_version}; {len(detected)} Python-executing workflow jobs)"
        )
        return
    for violation in violations:
        print(f"python-version-contract: {violation}", file=sys.stderr)


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        # Validate the only remaining path-shaped argument before resolving or
        # reading any filesystem path.  The public command has no caller-
        # controlled repository boundary.
        if args.version_file != CANONICAL_VERSION_FILE:
            raise ContractInputError(
                "--version-file must be exactly the literal '.python-version'"
            )
        root = repository_root()
        if not root.is_dir():
            raise ContractInputError(f"repository root is not a directory: {root}")
        version_file = canonical_version_file(root)
        canonical_version, violations, detected = evaluate_workflow_contract(
            root,
            version_file,
            previous_version=args.previous_version,
            allow_downgrade=args.allow_downgrade,
        )
    except ContractInputError as exc:
        report("error", None, [str(exc)], set(), args.json)
        return 2

    if violations:
        report("violations", canonical_version, violations, detected, args.json)
        return 1
    report("valid", canonical_version, [], detected, args.json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
