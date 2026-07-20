#!/usr/bin/env python3
"""Validate Framework-owned GitHub Actions security contracts."""

from __future__ import annotations

import argparse
from pathlib import Path, PurePosixPath
import re
from typing import Any, Iterable
from urllib.parse import urlparse

import yaml


SHA = re.compile(r"^[0-9a-f]{40}$")
UNSAFE_TRIGGER = re.compile(r"\bpull_request_target\b", re.ASCII)
UNTRUSTED_INTERPOLATION = re.compile(r"github\.event\.pull_request\.(?:title|body)\b")
ID_TOKEN_WRITE = re.compile(r"\bid-token\s*:\s*['\"]?write['\"]?", re.IGNORECASE)
ARCHIVE_TYPE_TAR_GZ = "tar.gz"
ARCHIVE_TYPE_RAW = "raw"
LAYOUT_EXECUTABLE = "executable"
LAYOUT_TREE = "tree"
CHECK_JSON_RESULT = "check-json-result.py"
UPLOAD_ARTIFACT = "actions/upload-artifact@"
RETENTION_DAYS_ONE = "retention-days: 1"
IF_NO_FILES_FOUND_ERROR = "if-no-files-found: error"
SECURITY_EVENTS_WRITE = "security-events: write"
SECURITY_TOOL_DOWNLOADER = "ci/tools/fetch-security-tool.py"
HASH_LOCKED_CI_REQUIREMENTS = "--require-hashes -r requirements-ci.lock"
ACTION_FIELDS = {
    "name",
    "version",
    "immutable_commit",
    "upstream_release",
    "license",
    "purpose",
    "platform",
    "update_procedure",
}
TOOL_FIELDS = ACTION_FIELDS | {
    "asset",
    "asset_url",
    "sha256",
    "archive_type",
    "layout",
}
EXECUTABLE_TOOL_FIELDS = TOOL_FIELDS | {"executable"}
TAR_EXECUTABLE_TOOL_FIELDS = EXECUTABLE_TOOL_FIELDS | {"archive_member"}
TREE_TOOL_FIELDS = TOOL_FIELDS | {"archive_root", "entrypoint"}
ALLOWED_ARCHIVE_TYPES = {ARCHIVE_TYPE_TAR_GZ, ARCHIVE_TYPE_RAW}
ALLOWED_PERMISSION_LEVELS = {"read", "write", "none"}
WRITE_PERMISSION_ALLOWLIST = {
    "check-common-versions.yml": {"contents", "pull-requests"},
    "check-python-version.yml": {"contents", "pull-requests"},
    "cleanup-artifacts.yml": {"actions"},
    "ci-security-codeql.yml": {"security-events"},
}
TOKEN_REFERENCE_ALLOWLIST = {
    "check-common-versions.yml",
    "check-python-version.yml",
    "ci-security-dependency-review.yml",
}
TOKEN_REFERENCE = re.compile(
    r"(?:github(?:\s*\.\s*token|\s*\[\s*['\"]token['\"]\s*\])|"
    r"secrets(?:\s*\.\s*GITHUB_TOKEN|\s*\[\s*['\"]GITHUB_TOKEN['\"]\s*\])|"
    r"\$\{?GITHUB_TOKEN\}?)"
)
GITHUB_EXPRESSION = re.compile(r"\$\{\{(?P<expression>.*?)\}\}", re.DOTALL)
SECRET_CONTEXT_REFERENCE = re.compile(r"\bsecrets\b", re.IGNORECASE)
GITHUB_TOKEN_REFERENCE = re.compile(
    r"\bgithub\s*(?:\.\s*token\b|\[)", re.IGNORECASE
)
BARE_GITHUB_CONTEXT_REFERENCE = re.compile(
    r"\bgithub\b(?!\s*(?:\.|\[))", re.IGNORECASE
)
SHELL_GITHUB_TOKEN_REFERENCE = re.compile(r"\$\{?GITHUB_TOKEN\}?", re.IGNORECASE)
CANONICAL_PYTHON_VERSION_FILE = ".python-version"
PYTHON_VERSION_CANDIDATE_FILE = "${{ runner.temp }}/framework-python-3.13-candidate"
PYTHON_VERSION_PR_BODY_FILE = "${{ runner.temp }}/framework-python-version-pr-body.md"
PYTHON_VERSION_PR_BODY_RUN_PATH = "$RUNNER_TEMP/framework-python-version-pr-body.md"
PYTHON_VERSION_MAINTENANCE_WORKFLOW = "check-python-version.yml"
PYTHON_VERSION_DECLARATION = re.compile(
    r"^\s*python-version:\s*['\"]?([^\s'\"#]+)['\"]?\s*(?:#.*)?$",
    re.MULTILINE,
)
PYTHON_VERSION_FILE_DECLARATION = re.compile(
    r"^\s*python-version-file:\s*(?:\"([^\"]+)\"|'([^']+)'|([^#\n]+?))\s*(?:#.*)?$",
    re.MULTILINE,
)
CHECK_LATEST_FALSE = re.compile(r"^\s*check-latest:\s*false\s*(?:#.*)?$", re.MULTILINE)

OSV_JOB_REQUIREMENTS: dict[str, tuple[str, ...]] = {
    "pull-request-head": (
        "github.event.pull_request.base.sha",
        "github.event.pull_request.head.sha",
        "github.event.pull_request.number",
        "fetch-depth: 1",
        'test "$(git rev-parse HEAD)" = "$BASE_SHA"',
        'git cat-file -e "$BASE_SHA^{commit}"',
        "git -c protocol.file.allow=never fetch --depth=1 --no-tags origin",
        '"+refs/pull/$PR_NUMBER/head:refs/remotes/origin/pr-$PR_NUMBER"',
        'test "$resolved_head" = "$HEAD_SHA"',
        'git cat-file -e "$HEAD_SHA^{commit}"',
        'git cat-file -e "$HEAD_SHA:requirements-ci.lock"',
        "write_osv_input requirements-dev.txt requirements-dev.txt false",
        "write_osv_input requirements-ci.lock requirements-ci.txt true",
        "--format json",
        '--lockfile "$input_directory/requirements-dev.txt"',
        '--lockfile "$input_directory/requirements-ci.txt"',
        "compare-osv-results.py",
        CHECK_JSON_RESULT,
        "id: compare_osv",
        'echo "evidence_valid=true" >> "$GITHUB_OUTPUT"',
        UPLOAD_ARTIFACT,
        RETENTION_DAYS_ONE,
        IF_NO_FILES_FOUND_ERROR,
        "steps.compare_osv.outputs.evidence_valid == 'true'",
        "framework-ci-security-results/osv/base.json",
        "framework-ci-security-results/osv/head.json",
        "framework-ci-security-results/osv/comparison.json",
    ),
    "scheduled-advisory": (
        "ref: ${{ github.sha }}",
        "--format json",
        CHECK_JSON_RESULT,
        "id: scan_current_osv",
        'echo "evidence_valid=true" >> "$GITHUB_OUTPUT"',
        UPLOAD_ARTIFACT,
        RETENTION_DAYS_ONE,
        IF_NO_FILES_FOUND_ERROR,
        "steps.scan_current_osv.outputs.evidence_valid == 'true'",
        "framework-ci-security-results/osv/current.json",
    ),
}
OSV_PROHIBITED_SNIPPETS = (
    "--allow-no-lockfiles",
    "--recursive",
    SECURITY_EVENTS_WRITE,
)
SCORECARD_JOB_REQUIREMENTS: dict[str, tuple[str, ...]] = {
    "pull-request-head": (
        "github.event.pull_request.head.sha",
        CHECK_JSON_RESULT,
        "scorecard-results.json",
    ),
    "current-revision-advisory": (
        "github.event.repository.default_branch",
        "ref: ${{ github.sha }}",
        CHECK_JSON_RESULT,
        UPLOAD_ARTIFACT,
        "path: ${{ runner.temp }}/scorecard-results.json",
        RETENTION_DAYS_ONE,
        IF_NO_FILES_FOUND_ERROR,
    ),
}


def load_yaml(path: Path) -> Any:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError(f"cannot parse YAML: {exc}") from exc


def pull_request_target_errors(path: Path, text: str) -> list[str]:
    if not UNSAFE_TRIGGER.search(text):
        return []

    errors = [f"{path}: pull_request_target is forbidden"]
    if UNTRUSTED_INTERPOLATION.search(text):
        errors.append(
            f"{path}: pull_request_target must not interpolate PR title or body"
        )
    return errors


def id_token_permission_errors(path: Path, text: str) -> list[str]:
    if ID_TOKEN_WRITE.search(text):
        return [f"{path}: id-token: write is not allowed by this Framework CI contract"]
    return []


def github_token_reference_errors(path: Path, text: str) -> list[str]:
    if TOKEN_REFERENCE.search(text) and path.name not in TOKEN_REFERENCE_ALLOWLIST:
        return [f"{path}: GitHub token reference is not allow-listed for this workflow"]
    return []


def trust_boundary_errors(path: Path, text: str) -> list[str]:
    return [
        *pull_request_target_errors(path, text),
        *id_token_permission_errors(path, text),
        *github_token_reference_errors(path, text),
    ]


def is_safe_archive_path(value: str) -> bool:
    path = PurePosixPath(value)
    return (
        bool(value)
        and not path.is_absolute()
        and all(part not in {"", ".", ".."} for part in path.parts)
    )


def is_safe_path_component(value: str) -> bool:
    path = PurePosixPath(value)
    return is_safe_archive_path(value) and len(path.parts) == 1


def required_record_fields(group: str, record: dict[str, Any]) -> set[str]:
    if group != "tool":
        return ACTION_FIELDS

    layout = record.get("layout")
    archive_type = record.get("archive_type")
    if layout == LAYOUT_EXECUTABLE and archive_type == ARCHIVE_TYPE_TAR_GZ:
        return TAR_EXECUTABLE_TOOL_FIELDS
    if layout == LAYOUT_EXECUTABLE:
        return EXECUTABLE_TOOL_FIELDS
    if layout == LAYOUT_TREE:
        return TREE_TOOL_FIELDS
    return TOOL_FIELDS


def common_record_errors(
    path: Path, group: str, name: str, record: dict[str, Any]
) -> list[str]:
    errors: list[str] = []
    if record.get("name") != name:
        errors.append(f"{path}: {group} {name!r} has a mismatched name")
    if not SHA.fullmatch(str(record.get("immutable_commit", ""))):
        errors.append(f"{path}: {group} {name!r} has no immutable commit SHA")
    release_url = str(record.get("upstream_release", ""))
    if not release_url.startswith("https://github.com/"):
        errors.append(f"{path}: {group} {name!r} has no GitHub upstream release")
    for field in ("version", "license", "purpose", "platform", "update_procedure"):
        if not isinstance(record.get(field), str) or not record[field].strip():
            errors.append(f"{path}: {group} {name!r} has an empty {field}")
    return errors


def tool_asset_errors(path: Path, name: str, record: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not is_safe_path_component(name):
        errors.append(f"{path}: tool {name!r} is not a safe output path component")
    if not re.fullmatch(r"[0-9a-f]{64}", str(record.get("sha256", ""))):
        errors.append(f"{path}: tool {name!r} has no SHA-256 asset digest")

    archive_type = record.get("archive_type")
    layout = record.get("layout")
    if archive_type not in ALLOWED_ARCHIVE_TYPES:
        errors.append(f"{path}: tool {name!r} has an unsupported archive type")
    if layout not in {LAYOUT_EXECUTABLE, LAYOUT_TREE}:
        errors.append(f"{path}: tool {name!r} has an unsupported archive layout")
    if archive_type == ARCHIVE_TYPE_RAW and layout != LAYOUT_EXECUTABLE:
        errors.append(f"{path}: tool {name!r} raw assets must use executable layout")

    asset = str(record.get("asset", ""))
    if not is_safe_path_component(asset):
        errors.append(f"{path}: tool {name!r} has an unsafe release asset name")
    asset_url = str(record.get("asset_url", ""))
    parsed = urlparse(asset_url)
    if (
        parsed.scheme != "https"
        or parsed.netloc != "github.com"
        or parsed.query
        or parsed.fragment
        or "/releases/download/" not in parsed.path
        or not parsed.path.endswith(f"/{asset}")
    ):
        errors.append(f"{path}: tool {name!r} has no direct GitHub release asset URL")
    return errors


def executable_tool_errors(path: Path, name: str, record: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    archive_type = record.get("archive_type")
    if archive_type == ARCHIVE_TYPE_TAR_GZ and not is_safe_archive_path(
        str(record.get("archive_member", ""))
    ):
        errors.append(f"{path}: tool {name!r} has an unsafe executable archive member")
    if archive_type == ARCHIVE_TYPE_RAW and "archive_member" in record:
        errors.append(
            f"{path}: tool {name!r} raw assets must not declare an archive member"
        )
    if not is_safe_path_component(str(record.get("executable", ""))):
        errors.append(f"{path}: tool {name!r} has an unsafe executable output name")
    return errors


def tree_tool_errors(path: Path, name: str, record: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if record.get("archive_type") != ARCHIVE_TYPE_TAR_GZ:
        errors.append(f"{path}: tool {name!r} tree layout requires a tar.gz asset")
    if not is_safe_path_component(str(record.get("archive_root", ""))):
        errors.append(f"{path}: tool {name!r} has an unsafe tree archive root")
    if not is_safe_archive_path(str(record.get("entrypoint", ""))):
        errors.append(f"{path}: tool {name!r} has an unsafe tree entrypoint")
    return errors


def tool_record_errors(path: Path, name: str, record: dict[str, Any]) -> list[str]:
    errors = tool_asset_errors(path, name, record)
    layout = record.get("layout")
    if layout == LAYOUT_EXECUTABLE:
        errors.extend(executable_tool_errors(path, name, record))
    if layout == LAYOUT_TREE:
        errors.extend(tree_tool_errors(path, name, record))
    return errors


def record_errors(path: Path, group: str, name: str, record: Any) -> list[str]:
    if not isinstance(record, dict):
        return [f"{path}: {group} {name!r} must be a mapping"]

    missing = sorted(required_record_fields(group, record).difference(record))
    if missing:
        return [f"{path}: {group} {name!r} lacks {', '.join(missing)}"]

    errors = common_record_errors(path, group, name, record)
    if group == "tool":
        errors.extend(tool_record_errors(path, name, record))
    return errors


def valid_lock_records(
    path: Path, group: str, records: Any
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    if not isinstance(records, dict):
        return {}, [f"{path}: {group}s must be a mapping"]

    valid_records: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    for raw_name, record in records.items():
        name = str(raw_name)
        record_validation_errors = record_errors(path, group, name, record)
        errors.extend(record_validation_errors)
        if not record_validation_errors and isinstance(record, dict):
            valid_records[name] = record
    return valid_records, errors


def load_lock(
    path: Path,
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], list[str]]:
    loaded = load_yaml(path)
    if not isinstance(loaded, dict):
        return {}, {}, [f"{path}: lock must be a mapping"]

    action_lock, action_errors = valid_lock_records(
        path, "action", loaded.get("actions")
    )
    tool_lock, tool_errors = valid_lock_records(path, "tool", loaded.get("tools"))
    errors = [*action_errors, *tool_errors]
    return action_lock, tool_lock, errors


def workflow_paths(root: Path) -> list[Path]:
    workflow_dir = root / ".github" / "workflows"
    if not workflow_dir.is_dir():
        return []
    return sorted(
        path
        for path in workflow_dir.iterdir()
        if path.is_file() and path.suffix in {".yml", ".yaml"}
    )


def uses_reference_and_comment(line: str) -> tuple[str, str] | None:
    """Return a workflow uses reference and its trailing version comment."""

    content = line.lstrip()
    if content.startswith("- "):
        content = content[2:].lstrip()
    if not content.startswith("uses:"):
        return None

    reference, separator, comment = (
        content.removeprefix("uses:").strip().partition(" #")
    )
    reference = reference.strip()
    if reference.startswith(("'", '"')):
        quote = reference[:1]
        if len(reference) < 2 or not reference.endswith(quote):
            return "", comment.strip()
        reference = reference[1:-1]
    return reference, comment.strip() if separator else ""


def locked_action_details(reference: str) -> tuple[str, str] | None:
    source, separator, pin = reference.partition("@")
    source_parts = source.split("/")
    if (
        not separator
        or not SHA.fullmatch(pin)
        or reference.startswith("docker://")
        or len(source_parts) < 2
        or not source_parts[0]
        or not source_parts[1]
    ):
        return None
    return "/".join(source_parts[:2]), pin


def action_pin_errors(
    path: Path,
    line_number: int,
    reference: str,
    comment: str,
    actions: dict[str, dict[str, Any]],
) -> list[str]:
    details = locked_action_details(reference)
    if details is None:
        return [
            f"{path}:{line_number}: {reference} must be a locked GitHub Action "
            "with a full immutable commit SHA"
        ]

    action, pin = details
    record = actions.get(action)
    if record is None:
        return [f"{path}:{line_number}: {action} is absent from the action lock"]

    errors: list[str] = []
    if pin != record["immutable_commit"]:
        errors.append(
            f"{path}:{line_number}: {action} SHA differs from the reviewed lock"
        )
    if comment != record["version"]:
        errors.append(
            f"{path}:{line_number}: {action} must have exact version comment "
            f"{record['version']!r}"
        )
    return errors


def line_pin_errors(
    path: Path,
    line_number: int,
    line: str,
    actions: dict[str, dict[str, Any]],
) -> list[str]:
    parsed = uses_reference_and_comment(line)
    if parsed is None:
        return []

    reference, comment = parsed
    if reference.startswith("./"):
        return []
    return action_pin_errors(path, line_number, reference, comment, actions)


def pin_errors(path: Path, text: str, actions: dict[str, dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        errors.extend(line_pin_errors(path, line_number, line, actions))
    return errors


def run_shell_default(data: dict[str, Any]) -> bool:
    defaults = data.get("defaults")
    return (
        isinstance(defaults, dict)
        and isinstance(defaults.get("run"), dict)
        and defaults["run"].get("shell") == "bash"
    )


def permission_definitions(data: dict[str, Any]) -> Iterable[tuple[str, Any]]:
    if "permissions" in data:
        yield "top-level", data["permissions"]
    jobs = data.get("jobs")
    if isinstance(jobs, dict):
        for job_name, job in jobs.items():
            if isinstance(job, dict) and "permissions" in job:
                yield f"job {job_name!r}", job["permissions"]


def permission_entry_errors(
    path: Path,
    scope: str,
    permission: Any,
    level: Any,
    allowed_writes: set[str],
) -> list[str]:
    if level not in ALLOWED_PERMISSION_LEVELS:
        return [
            f"{path}: {scope} {permission}: {level!r} is not an explicit permission level"
        ]
    if level != "write":
        return []
    if scope == "top-level":
        return [
            f"{path}: top-level write permissions are forbidden; scope them to a job"
        ]
    if permission not in allowed_writes:
        return [f"{path}: {permission}: write is not allow-listed for this workflow"]
    return []


def permission_scope_errors(
    path: Path,
    scope: str,
    permissions: Any,
    allowed_writes: set[str],
) -> list[str]:
    if not isinstance(permissions, dict):
        return [f"{path}: {scope} permissions must be a mapping"]

    errors: list[str] = []
    for permission, level in permissions.items():
        errors.extend(
            permission_entry_errors(path, scope, permission, level, allowed_writes)
        )
    return errors


def permission_errors(path: Path, data: dict[str, Any]) -> list[str]:
    allowed_writes = WRITE_PERMISSION_ALLOWLIST.get(path.name, set())
    errors: list[str] = []
    for scope, permissions in permission_definitions(data):
        errors.extend(permission_scope_errors(path, scope, permissions, allowed_writes))
    return errors


def concurrency_errors(path: Path, data: dict[str, Any]) -> list[str]:
    concurrency = data.get("concurrency")
    if not isinstance(concurrency, dict):
        return [f"{path}: workflow must declare a concurrency mapping"]
    errors: list[str] = []
    if (
        not isinstance(concurrency.get("group"), str)
        or not concurrency["group"].strip()
    ):
        errors.append(f"{path}: concurrency must declare a non-empty group")
    if type(concurrency.get("cancel-in-progress")) is not bool:
        errors.append(
            f"{path}: concurrency must declare cancel-in-progress as a boolean"
        )
    return errors


def setup_python_errors(path: Path, text: str) -> list[str]:
    if "actions/setup-python@" not in text:
        return []

    errors: list[str] = []
    setup_count = text.count("actions/setup-python@")
    if PYTHON_VERSION_DECLARATION.search(text):
        errors.append(
            f"{path}: setup-python must select {CANONICAL_PYTHON_VERSION_FILE} "
            "through python-version-file, never python-version"
        )
    version_files = [
        next(value for value in match if value is not None).strip()
        for match in PYTHON_VERSION_FILE_DECLARATION.findall(text)
    ]
    allowed_files = {CANONICAL_PYTHON_VERSION_FILE}
    if path.name == PYTHON_VERSION_MAINTENANCE_WORKFLOW:
        allowed_files.add(PYTHON_VERSION_CANDIDATE_FILE)
    if len(version_files) != setup_count or any(
        version_file not in allowed_files for version_file in version_files
    ):
        errors.append(
            f"{path}: every setup-python use must select the canonical "
            f"{CANONICAL_PYTHON_VERSION_FILE} file"
        )
    if len(CHECK_LATEST_FALSE.findall(text)) < setup_count:
        errors.append(f"{path}: setup-python must set check-latest: false")
    return errors


def security_tool_downloader_errors(path: Path, text: str) -> list[str]:
    if SECURITY_TOOL_DOWNLOADER not in text:
        return []

    errors: list[str] = []
    if "actions/setup-python@" not in text:
        errors.append(
            f"{path}: the security-tool downloader requires reviewed setup-python"
        )
    normalized = " ".join(text.split())
    if (
        "python3 -m pip install" not in normalized
        or HASH_LOCKED_CI_REQUIREMENTS not in normalized
    ):
        errors.append(
            f"{path}: the security-tool downloader requires hash-locked "
            "requirements-ci.lock installation"
        )
    return errors


def python_provisioning_errors(path: Path, text: str) -> list[str]:
    return [
        *setup_python_errors(path, text),
        *security_tool_downloader_errors(path, text),
    ]


def workflow_events(data: dict[str, Any]) -> dict[str, Any] | None:
    raw_events = data.get("on", data.get(True))
    return raw_events if isinstance(raw_events, dict) else None


def as_job_steps(path: Path, job_name: str, job: Any) -> tuple[list[dict[str, Any]], list[str]]:
    if not isinstance(job, dict):
        return [], [f"{path}: Python maintenance job {job_name!r} must be a mapping"]
    steps = job.get("steps")
    if not isinstance(steps, list):
        return [], [f"{path}: Python maintenance job {job_name!r} must define steps"]
    mappings = [step for step in steps if isinstance(step, dict)]
    if len(mappings) != len(steps):
        return [], [f"{path}: Python maintenance job {job_name!r} has a malformed step"]
    return mappings, []


def job_run_text(steps: Iterable[dict[str, Any]]) -> str:
    return "\n".join(str(step.get("run", "")) for step in steps)


def contains_sensitive_reference(value: str) -> bool:
    """Reject secret contexts and GitHub-context forms that can expose its token."""

    if SHELL_GITHUB_TOKEN_REFERENCE.search(value):
        return True
    for match in GITHUB_EXPRESSION.finditer(value):
        expression = match.group("expression")
        if (
            SECRET_CONTEXT_REFERENCE.search(expression)
            or GITHUB_TOKEN_REFERENCE.search(expression)
            or BARE_GITHUB_CONTEXT_REFERENCE.search(expression)
        ):
            return True
    return False


def sensitive_reference_paths(
    value: Any, path: tuple[str, ...] = ()
) -> list[tuple[str, ...]]:
    """Return parsed locations containing an explicit token or secret reference."""

    if isinstance(value, str):
        return [path] if contains_sensitive_reference(value) else []
    if isinstance(value, dict):
        paths: list[tuple[str, ...]] = []
        for key, item in value.items():
            paths.extend(sensitive_reference_paths(item, (*path, str(key))))
        return paths
    if isinstance(value, list):
        paths = []
        for index, item in enumerate(value):
            paths.extend(sensitive_reference_paths(item, (*path, str(index))))
        return paths
    return []


def normalized_needs(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return set(value)
    return set()


def read_only_job_errors(path: Path, job_name: str, job: Any) -> list[str]:
    if not isinstance(job, dict):
        return []
    permissions = job.get("permissions")
    if permissions is not None and permissions != {"contents": "read"}:
        return [
            f"{path}: Python maintenance job {job_name!r} must remain contents: read only"
        ]
    return []


def create_pull_request_steps(
    steps: Iterable[dict[str, Any]],
) -> list[tuple[int, dict[str, Any]]]:
    matches: list[tuple[int, dict[str, Any]]] = []
    for index, step in enumerate(steps):
        reference = step.get("uses")
        if isinstance(reference, str) and reference.startswith(
            "peter-evans/create-pull-request@"
        ):
            matches.append((index, step))
    return matches


def python_version_maintenance_errors(path: Path, data: dict[str, Any]) -> list[str]:
    if path.name != PYTHON_VERSION_MAINTENANCE_WORKFLOW:
        return []

    errors: list[str] = []
    events = workflow_events(data)
    if not isinstance(events, dict) or set(events) != {"workflow_dispatch", "schedule"}:
        errors.append(
            f"{path}: Python maintenance must be scheduled/manual only with no other trigger"
        )
    elif not isinstance(events.get("schedule"), list) or not events["schedule"]:
        errors.append(f"{path}: Python maintenance must declare a schedule")

    jobs = data.get("jobs")
    required_jobs = {"resolve", "candidate-validate", "publish"}
    if not isinstance(jobs, dict) or set(jobs) != required_jobs:
        return [
            *errors,
            f"{path}: Python maintenance must define exactly resolve, candidate-validate, and publish jobs",
        ]
    resolve = jobs["resolve"]
    candidate = jobs["candidate-validate"]
    publish = jobs["publish"]
    errors.extend(read_only_job_errors(path, "resolve", resolve))
    errors.extend(read_only_job_errors(path, "candidate-validate", candidate))
    if not isinstance(publish, dict) or publish.get("permissions") != {
        "contents": "write",
        "pull-requests": "write",
    }:
        errors.append(
            f"{path}: Python maintenance publish job must have only contents/pull-requests write"
        )
    if isinstance(candidate, dict) and normalized_needs(candidate.get("needs")) != {"resolve"}:
        errors.append(f"{path}: Python maintenance candidate job must need resolve only")
    if isinstance(publish, dict) and normalized_needs(publish.get("needs")) != {
        "resolve",
        "candidate-validate",
    }:
        errors.append(f"{path}: Python maintenance publish job must need both prior jobs")

    resolve_steps, resolve_step_errors = as_job_steps(path, "resolve", resolve)
    candidate_steps, candidate_step_errors = as_job_steps(path, "candidate-validate", candidate)
    publish_steps, publish_step_errors = as_job_steps(path, "publish", publish)
    errors.extend(resolve_step_errors)
    errors.extend(candidate_step_errors)
    errors.extend(publish_step_errors)
    resolve_run = job_run_text(resolve_steps)
    candidate_run = job_run_text(candidate_steps)
    publish_run = job_run_text(publish_steps)
    if "update-python-version.py --check --write-github-output" not in resolve_run:
        errors.append(f"{path}: resolve must use the no-write updater check with GitHub outputs")
    for job_name, job in (("resolve", resolve), ("candidate-validate", candidate)):
        if sensitive_reference_paths(job):
            errors.append(
                f"{path}: Python maintenance read-only job {job_name!r} must not "
                "declare a GitHub token or secret"
            )
    candidate_file_lines = [
        line.strip().rstrip("\\").strip()
        for line in candidate_run.splitlines()
        if "--write-candidate-file" in line
    ]
    if (
        "update-python-version.py --check" not in candidate_run
        or "--update" in candidate_run
        or "--expected-candidate \"$CANDIDATE\"" not in candidate_run
        or candidate_file_lines != ["--write-candidate-file"]
    ):
        errors.append(
            f"{path}: candidate validation must independently validate and materialize only "
            "the fixed controlled RUNNER_TEMP candidate file without a caller path"
        )
    if (
        "update-python-version.py --check --expected-candidate \"$CANDIDATE\""
        not in publish_run
        or "update-python-version.py --update --expected-candidate \"$CANDIDATE\""
        not in publish_run
    ):
        errors.append(
            f"{path}: publisher must independently re-resolve and update with the expected candidate"
        )
    if (
        "git diff --name-only" not in publish_run
        or 'test "$changed_paths" = ".python-version"' not in publish_run
    ):
        errors.append(f"{path}: publisher must assert the exact .python-version-only diff")
    if any(token in publish_run for token in ("gh pr merge", "--auto", "auto-merge")):
        errors.append(
            f"{path}: publisher must not merge or enable auto-merge for its Draft pull request"
        )

    candidate_if = candidate.get("if") if isinstance(candidate, dict) else None
    if not isinstance(candidate_if, str) or "needs.resolve.outputs.update_available == 'true'" not in candidate_if:
        errors.append(f"{path}: candidate job must be gated on an available resolver update")
    publish_if = publish.get("if") if isinstance(publish, dict) else None
    publisher_conditions = (
        "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'",
        "needs.resolve.outputs.update_available == 'true'",
        "needs.candidate-validate.outputs.candidate_validated == 'true'",
        "github.repository == 'Easton97-Jens/ModSecurity-test-Framework'",
        "github.ref == 'refs/heads/master'",
    )
    if not isinstance(publish_if, str) or any(
        condition not in publish_if for condition in publisher_conditions
    ):
        errors.append(
            f"{path}: publisher must be gated on trusted repository/default-ref and validated candidate"
        )

    pull_request_steps = create_pull_request_steps(publish_steps)
    allowed_sensitive_path: tuple[str, ...] | None = None
    if len(pull_request_steps) != 1:
        errors.append(
            f"{path}: publisher must use exactly one reviewed create-pull-request action"
        )
    else:
        pull_request_index, pull_request = pull_request_steps[0]
        options = pull_request.get("with")
        if not isinstance(options, dict):
            errors.append(f"{path}: create-pull-request must have a with mapping")
        else:
            if options.get("token") != "${{ github.token }}":
                errors.append(f"{path}: create-pull-request must use its explicit github.token input")
            else:
                allowed_sensitive_path = (
                    "steps",
                    str(pull_request_index),
                    "with",
                    "token",
                )
            if options.get("branch") != "automation/update-framework-python-313":
                errors.append(f"{path}: publisher branch must be fixed and reviewable")
            if options.get("draft") is not True:
                errors.append(f"{path}: publisher must create or update a Draft pull request")
            if str(options.get("add-paths", "")).strip() != CANONICAL_PYTHON_VERSION_FILE:
                errors.append(f"{path}: publisher add-paths must be limited to .python-version")
            if options.get("body-path") != PYTHON_VERSION_PR_BODY_FILE:
                errors.append(
                    f"{path}: create-pull-request body-path must be the controlled RUNNER_TEMP file"
                )
    unexpected_sensitive_paths = [
        location
        for location in sensitive_reference_paths(publish)
        if location != allowed_sensitive_path
    ]
    if unexpected_sensitive_paths:
        errors.append(
            f"{path}: publisher may only declare github.token in the reviewed "
            "create-pull-request with.token input"
        )
    if f'> "{PYTHON_VERSION_PR_BODY_RUN_PATH}"' not in publish_run:
        errors.append(
            f"{path}: publisher must write its Draft pull request body under RUNNER_TEMP"
        )
    return errors


def is_job_header(line: str) -> bool:
    stripped = line.rstrip()
    return (
        line.startswith("  ")
        and not line.startswith("   ")
        and not stripped.lstrip().startswith("#")
        and stripped.endswith(":")
    )


def job_text(text: str, name: str) -> str | None:
    selected: list[str] = []
    collecting = False
    for line in text.splitlines(keepends=True):
        if is_job_header(line):
            if collecting:
                return "".join(selected)
            collecting = line.strip() == f"{name}:"
        if collecting:
            selected.append(line)
    return "".join(selected) if selected else None


def require_workflow_text(
    path: Path, section_name: str, section: str | None, snippets: Iterable[str]
) -> list[str]:
    if section is None:
        return [f"{path}: required job {section_name!r} is absent"]
    return [
        f"{path}: job {section_name!r} must contain {snippet!r}"
        for snippet in snippets
        if snippet not in section
    ]


def job_requirement_errors(
    path: Path, text: str, requirements: dict[str, tuple[str, ...]]
) -> list[str]:
    errors: list[str] = []
    for job_name, snippets in requirements.items():
        errors.extend(
            require_workflow_text(path, job_name, job_text(text, job_name), snippets)
        )
    return errors


def forbidden_workflow_snippet_errors(
    path: Path, text: str, workflow_name: str, snippets: Iterable[str]
) -> list[str]:
    return [
        f"{path}: {workflow_name} workflow must not contain {snippet!r}"
        for snippet in snippets
        if snippet in text
    ]


def osv_scanner_evidence_errors(path: Path, text: str) -> list[str]:
    return [
        *job_requirement_errors(path, text, OSV_JOB_REQUIREMENTS),
        *forbidden_workflow_snippet_errors(path, text, "OSV", OSV_PROHIBITED_SNIPPETS),
    ]


def scorecard_pull_request_artifact_errors(path: Path, text: str) -> list[str]:
    pull_request = job_text(text, "pull-request-head")
    if pull_request is not None and UPLOAD_ARTIFACT in pull_request:
        return [f"{path}: pull-request Scorecard evidence must remain artifact-free"]
    return []


def scorecard_current_revision_errors(path: Path, text: str) -> list[str]:
    current_revision = job_text(text, "current-revision-advisory")
    if current_revision is not None and "continue-on-error" in current_revision:
        return [
            f"{path}: current-revision Scorecard evidence must fail on scanner errors"
        ]
    return []


def scorecard_evidence_errors(path: Path, text: str) -> list[str]:
    return [
        *job_requirement_errors(path, text, SCORECARD_JOB_REQUIREMENTS),
        *scorecard_pull_request_artifact_errors(path, text),
        *scorecard_current_revision_errors(path, text),
        *forbidden_workflow_snippet_errors(
            path, text, "Scorecard", (SECURITY_EVENTS_WRITE,)
        ),
    ]


def scanner_evidence_errors(path: Path, text: str) -> list[str]:
    if path.name == "ci-security-osv.yml":
        return osv_scanner_evidence_errors(path, text)
    if path.name == "ci-security-scorecard.yml":
        return scorecard_evidence_errors(path, text)
    return []


def top_level_permission_errors(path: Path, data: dict[str, Any]) -> list[str]:
    if "permissions" not in data:
        return [f"{path}: workflow must declare explicit top-level permissions"]
    return []


def codeql_tool_bundle_errors(path: Path, text: str) -> list[str]:
    if (
        path.name in {"ci-security-codeql.yml", "ci-security-codeql-pr.yml"}
        and "tools: linked" not in text
    ):
        return [f"{path}: CodeQL init must select the linked tool bundle"]
    return []


def run_shell_default_errors(path: Path, text: str, data: dict[str, Any]) -> list[str]:
    if "run:" in text and not run_shell_default(data):
        return [f"{path}: shell-running workflow must set defaults.run.shell to bash"]
    return []


def workflow_token_environment_errors(path: Path, data: dict[str, Any]) -> list[str]:
    environment = data.get("env")
    if isinstance(environment, dict) and "GITHUB_TOKEN" in environment:
        return [f"{path}: GITHUB_TOKEN must not be exposed at workflow scope"]
    return []


def workflow_metadata_errors(path: Path, text: str, data: dict[str, Any]) -> list[str]:
    return [
        *top_level_permission_errors(path, data),
        *concurrency_errors(path, data),
        *python_provisioning_errors(path, text),
        *python_version_maintenance_errors(path, data),
        *scanner_evidence_errors(path, text),
        *codeql_tool_bundle_errors(path, text),
        *run_shell_default_errors(path, text, data),
        *permission_errors(path, data),
        *workflow_token_environment_errors(path, data),
    ]


def checkout_safety_errors(path: Path, step: dict[str, Any]) -> list[str]:
    checkout = step.get("with")
    if not isinstance(checkout, dict):
        return [f"{path}: checkout step must declare safe checkout settings"]

    errors: list[str] = []
    if checkout.get("persist-credentials") is not False:
        errors.append(f"{path}: checkout must set persist-credentials: false")
    if checkout.get("submodules") is not False:
        errors.append(f"{path}: checkout must set submodules: false")
    return errors


def job_contract_errors(path: Path, job_name: str, job: Any) -> list[str]:
    if not isinstance(job, dict):
        return [f"{path}: job {job_name!r} must be a mapping"]

    errors: list[str] = []
    timeout = job.get("timeout-minutes")
    if type(timeout) is not int or timeout <= 0:
        errors.append(
            f"{path}: job {job_name!r} must set a positive integer timeout-minutes"
        )
    if isinstance(job.get("env"), dict) and "GITHUB_TOKEN" in job["env"]:
        errors.append(f"{path}: job {job_name!r} must not expose GITHUB_TOKEN")

    steps = job.get("steps", [])
    if not isinstance(steps, list):
        return errors
    for step in steps:
        if not isinstance(step, dict):
            continue
        reference = str(step.get("uses", ""))
        if reference.startswith("actions/checkout@"):
            errors.extend(checkout_safety_errors(path, step))
    return errors


def jobs_contract_errors(path: Path, data: dict[str, Any]) -> list[str]:
    jobs = data.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        return [f"{path}: workflow must define jobs"]

    errors: list[str] = []
    for job_name, job in jobs.items():
        errors.extend(job_contract_errors(path, str(job_name), job))
    return errors


def workflow_contract_errors(path: Path, text: str, data: Any) -> list[str]:
    errors = trust_boundary_errors(path, text)
    if not isinstance(data, dict):
        return [*errors, f"{path}: workflow must be a mapping"]
    errors.extend(workflow_metadata_errors(path, text, data))
    errors.extend(jobs_contract_errors(path, data))
    return errors


def validate(root: Path, lock_path: Path) -> list[str]:
    actions, _tools, errors = load_lock(lock_path)
    for path in workflow_paths(root):
        text = path.read_text(encoding="utf-8")
        try:
            data = load_yaml(path)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        errors.extend(pin_errors(path, text, actions))
        errors.extend(workflow_contract_errors(path, text, data))
    return errors


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[3]
    )
    parser.add_argument(
        "--lock",
        type=Path,
        default=Path("ci/tooling/security-tools.lock.yml"),
        help="Lock path that must resolve inside --root.",
    )
    return parser.parse_args()


def resolve_root_path(root: Path) -> Path:
    try:
        resolved = root.resolve(strict=True)
    except OSError as exc:
        raise ValueError(
            f"{root}: --root must resolve to an existing directory"
        ) from exc
    if not resolved.is_dir():
        raise ValueError(f"{root}: --root must resolve to an existing directory")
    return resolved


def resolve_lock_path(root: Path, lock: Path) -> Path:
    candidate = lock if lock.is_absolute() else root / lock
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"{lock}: --lock must resolve inside --root") from exc
    if not resolved.is_relative_to(root):
        raise ValueError(f"{lock}: --lock must resolve inside --root")
    if not resolved.is_file():
        raise ValueError(f"{lock}: --lock must resolve to a regular file")
    return resolved


def main() -> int:
    args = parse_args()
    try:
        root = resolve_root_path(args.root)
        lock_path = resolve_lock_path(root, args.lock)
    except ValueError as exc:
        print("CI security contract violations:")
        print(f"- {exc}")
        return 1
    errors = validate(root, lock_path)
    if errors:
        print("CI security contract violations:")
        print("\n".join(f"- {error}" for error in errors))
        return 1
    print("CI security contract passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
