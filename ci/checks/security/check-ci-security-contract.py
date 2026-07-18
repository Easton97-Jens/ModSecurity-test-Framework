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
USES = re.compile(
    r"^\s*(?:-\s+)?uses:\s*(?:(?P<quote>['\"])(?P<quoted_reference>[^'\"\r\n]+)(?P=quote)|(?P<reference>[^\s#]+))(?:\s+#\s*(?P<comment>[^#\r\n]+?))?\s*$"
)
UNSAFE_TRIGGER = re.compile(
    r"(?<![A-Za-z0-9_])['\"]?pull_request_target['\"]?(?![A-Za-z0-9_])"
)
UNTRUSTED_INTERPOLATION = re.compile(r"github\.event\.pull_request\.(title|body)")
ID_TOKEN_WRITE = re.compile(r"\bid-token\s*:\s*['\"]?write['\"]?", re.IGNORECASE)
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
ALLOWED_ARCHIVE_TYPES = {"tar.gz", "raw"}
ALLOWED_PERMISSION_LEVELS = {"read", "write", "none"}
WRITE_PERMISSION_ALLOWLIST = {
    "check-common-versions.yml": {"contents", "pull-requests"},
    "cleanup-artifacts.yml": {"actions"},
    "ci-security-codeql.yml": {"security-events"},
}
TOKEN_REFERENCE_ALLOWLIST = {
    "check-common-versions.yml",
    "ci-security-dependency-review.yml",
}
TOKEN_REFERENCE = re.compile(
    r"(?:github\.token|secrets\.GITHUB_TOKEN|\$\{?GITHUB_TOKEN\}?)"
)
REVIEWED_PYTHON_VERSION = "3.12.13"
PYTHON_VERSION_DECLARATION = re.compile(
    r"^\s*python-version:\s*['\"]?([^\s'\"#]+)['\"]?\s*(?:#.*)?$",
    re.MULTILINE,
)
CHECK_LATEST_FALSE = re.compile(r"^\s*check-latest:\s*false\s*(?:#.*)?$", re.MULTILINE)
JOB_SECTION = re.compile(
    r"^  (?P<name>[A-Za-z0-9_-]+):\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
    re.DOTALL | re.MULTILINE,
)


def load_yaml(path: Path) -> Any:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError(f"cannot parse YAML: {exc}") from exc


def trust_boundary_errors(path: Path, text: str) -> list[str]:
    errors: list[str] = []
    if UNSAFE_TRIGGER.search(text):
        errors.append(f"{path}: pull_request_target is forbidden")
    if UNSAFE_TRIGGER.search(text) and UNTRUSTED_INTERPOLATION.search(text):
        errors.append(
            f"{path}: pull_request_target must not interpolate PR title or body"
        )
    if ID_TOKEN_WRITE.search(text):
        errors.append(
            f"{path}: id-token: write is not allowed by this Framework CI contract"
        )
    if TOKEN_REFERENCE.search(text) and path.name not in TOKEN_REFERENCE_ALLOWLIST:
        errors.append(
            f"{path}: GitHub token reference is not allow-listed for this workflow"
        )
    return errors


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


def record_errors(path: Path, group: str, name: str, record: Any) -> list[str]:
    if not isinstance(record, dict):
        return [f"{path}: {group} {name!r} must be a mapping"]

    fields = ACTION_FIELDS
    if group == "tool":
        layout = record.get("layout")
        archive_type = record.get("archive_type")
        fields = (
            TAR_EXECUTABLE_TOOL_FIELDS
            if layout == "executable" and archive_type == "tar.gz"
            else EXECUTABLE_TOOL_FIELDS
            if layout == "executable"
            else TREE_TOOL_FIELDS
            if layout == "tree"
            else TOOL_FIELDS
        )
    missing = sorted(fields.difference(record))
    if missing:
        return [f"{path}: {group} {name!r} lacks {', '.join(missing)}"]

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
    if group != "tool":
        return errors

    if not is_safe_path_component(name):
        errors.append(f"{path}: tool {name!r} is not a safe output path component")
    if not re.fullmatch(r"[0-9a-f]{64}", str(record.get("sha256", ""))):
        errors.append(f"{path}: tool {name!r} has no SHA-256 asset digest")
    archive_type = record.get("archive_type")
    layout = record.get("layout")
    if archive_type not in ALLOWED_ARCHIVE_TYPES:
        errors.append(f"{path}: tool {name!r} has an unsupported archive type")
    if layout not in {"executable", "tree"}:
        errors.append(f"{path}: tool {name!r} has an unsupported archive layout")
    if archive_type == "raw" and layout != "executable":
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
    if layout == "executable":
        if archive_type == "tar.gz" and not is_safe_archive_path(
            str(record.get("archive_member", ""))
        ):
            errors.append(
                f"{path}: tool {name!r} has an unsafe executable archive member"
            )
        if archive_type == "raw" and "archive_member" in record:
            errors.append(
                f"{path}: tool {name!r} raw assets must not declare an archive member"
            )
        if not is_safe_path_component(str(record.get("executable", ""))):
            errors.append(f"{path}: tool {name!r} has an unsafe executable output name")
    if layout == "tree":
        if archive_type != "tar.gz":
            errors.append(f"{path}: tool {name!r} tree layout requires a tar.gz asset")
        if not is_safe_path_component(str(record.get("archive_root", ""))):
            errors.append(f"{path}: tool {name!r} has an unsafe tree archive root")
        if not is_safe_archive_path(str(record.get("entrypoint", ""))):
            errors.append(f"{path}: tool {name!r} has an unsafe tree entrypoint")
    return errors


def load_lock(
    path: Path,
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], list[str]]:
    errors: list[str] = []
    loaded = load_yaml(path)
    if not isinstance(loaded, dict):
        return {}, {}, [f"{path}: lock must be a mapping"]
    action_lock = loaded.get("actions")
    tool_lock = loaded.get("tools")
    if not isinstance(action_lock, dict):
        errors.append(f"{path}: actions must be a mapping")
        action_lock = {}
    if not isinstance(tool_lock, dict):
        errors.append(f"{path}: tools must be a mapping")
        tool_lock = {}
    for group, records in (("action", action_lock), ("tool", tool_lock)):
        for name, record in records.items():
            errors.extend(record_errors(path, group, str(name), record))
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


def pin_errors(path: Path, text: str, actions: dict[str, dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        match = USES.match(line)
        if not match:
            continue
        reference = match.group("quoted_reference") or match.group("reference")
        if reference.startswith("./"):
            continue
        source, separator, pin = reference.partition("@")
        parts = source.split("/")
        if (
            not separator
            or not SHA.fullmatch(pin)
            or reference.startswith("docker://")
            or len(parts) < 2
            or not parts[0]
            or not parts[1]
        ):
            errors.append(
                f"{path}:{line_number}: {reference} must be a locked GitHub Action with a full immutable commit SHA"
            )
            continue
        action = "/".join(parts[:2])
        record = actions.get(action)
        if record is None:
            errors.append(
                f"{path}:{line_number}: {action} is absent from the action lock"
            )
            continue
        if pin != record["immutable_commit"]:
            errors.append(
                f"{path}:{line_number}: {action} SHA differs from the reviewed lock"
            )
        comment = (match.group("comment") or "").strip()
        if comment != record["version"]:
            errors.append(
                f"{path}:{line_number}: {action} must have exact version comment {record['version']!r}"
            )
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


def permission_errors(path: Path, data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    allowed_writes = WRITE_PERMISSION_ALLOWLIST.get(path.name, set())
    for scope, permissions in permission_definitions(data):
        if not isinstance(permissions, dict):
            errors.append(f"{path}: {scope} permissions must be a mapping")
            continue
        for permission, level in permissions.items():
            if level not in ALLOWED_PERMISSION_LEVELS:
                errors.append(
                    f"{path}: {scope} {permission}: {level!r} is not an explicit permission level"
                )
                continue
            if level == "write":
                if scope == "top-level":
                    errors.append(
                        f"{path}: top-level write permissions are forbidden; scope them to a job"
                    )
                elif permission not in allowed_writes:
                    errors.append(
                        f"{path}: {permission}: write is not allow-listed for this workflow"
                    )
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


def python_provisioning_errors(path: Path, text: str) -> list[str]:
    errors: list[str] = []
    uses_setup_python = "actions/setup-python@" in text
    if uses_setup_python:
        versions = PYTHON_VERSION_DECLARATION.findall(text)
        if not versions or any(
            version != REVIEWED_PYTHON_VERSION for version in versions
        ):
            errors.append(
                f"{path}: setup-python must use exact reviewed CPython "
                f"{REVIEWED_PYTHON_VERSION}"
            )
        if not CHECK_LATEST_FALSE.search(text):
            errors.append(f"{path}: setup-python must set check-latest: false")

    if "ci/tools/fetch-security-tool.py" not in text:
        return errors

    normalized = " ".join(text.split())
    if not uses_setup_python:
        errors.append(
            f"{path}: the security-tool downloader requires reviewed setup-python"
        )
    if "python3 -m pip install" not in normalized or (
        "--require-hashes -r requirements-ci.lock" not in normalized
    ):
        errors.append(
            f"{path}: the security-tool downloader requires hash-locked "
            "requirements-ci.lock installation"
        )
    return errors


def job_text(text: str, name: str) -> str | None:
    for match in JOB_SECTION.finditer(text):
        if match.group("name") == name:
            return match.group(0)
    return None


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


def scanner_evidence_errors(path: Path, text: str) -> list[str]:
    errors: list[str] = []
    if path.name == "ci-security-osv.yml":
        pull_request = job_text(text, "pull-request-head")
        errors.extend(
            require_workflow_text(
                path,
                "pull-request-head",
                pull_request,
                (
                    "github.event.pull_request.base.sha",
                    "github.event.pull_request.head.sha",
                    "fetch-depth: 0",
                    'test "$(git rev-parse HEAD)" = "$HEAD_SHA"',
                    'git cat-file -e "$BASE_SHA^{commit}"',
                    "write_osv_input requirements-dev.txt requirements-dev.txt",
                    "write_osv_input requirements-ci.lock requirements-ci.txt",
                    "--format json",
                    '--lockfile "$input_directory/requirements-dev.txt"',
                    '--lockfile "$input_directory/requirements-ci.txt"',
                    "compare-osv-results.py",
                    "check-json-result.py",
                    "id: compare_osv",
                    'echo "evidence_valid=true" >> "$GITHUB_OUTPUT"',
                    "actions/upload-artifact@",
                    "retention-days: 1",
                    "if-no-files-found: error",
                    "steps.compare_osv.outputs.evidence_valid == 'true'",
                    "framework-ci-security-results/osv/base.json",
                    "framework-ci-security-results/osv/head.json",
                    "framework-ci-security-results/osv/comparison.json",
                ),
            )
        )
        scheduled = job_text(text, "scheduled-advisory")
        errors.extend(
            require_workflow_text(
                path,
                "scheduled-advisory",
                scheduled,
                (
                    "ref: ${{ github.sha }}",
                    "--format json",
                    "check-json-result.py",
                    "id: scan_current_osv",
                    'echo "evidence_valid=true" >> "$GITHUB_OUTPUT"',
                    "actions/upload-artifact@",
                    "retention-days: 1",
                    "if-no-files-found: error",
                    "steps.scan_current_osv.outputs.evidence_valid == 'true'",
                    "framework-ci-security-results/osv/current.json",
                ),
            )
        )
        for prohibited in (
            "--allow-no-lockfiles",
            "--recursive",
            "security-events: write",
        ):
            if prohibited in text:
                errors.append(f"{path}: OSV workflow must not contain {prohibited!r}")
    if path.name == "ci-security-scorecard.yml":
        pull_request = job_text(text, "pull-request-head")
        errors.extend(
            require_workflow_text(
                path,
                "pull-request-head",
                pull_request,
                (
                    "github.event.pull_request.head.sha",
                    "check-json-result.py",
                    "scorecard-results.json",
                ),
            )
        )
        if pull_request is not None and "actions/upload-artifact@" in pull_request:
            errors.append(
                f"{path}: pull-request Scorecard evidence must remain artifact-free"
            )
        current_revision = job_text(text, "current-revision-advisory")
        errors.extend(
            require_workflow_text(
                path,
                "current-revision-advisory",
                current_revision,
                (
                    "github.event.repository.default_branch",
                    "ref: ${{ github.sha }}",
                    "check-json-result.py",
                    "actions/upload-artifact@",
                    "path: ${{ runner.temp }}/scorecard-results.json",
                    "retention-days: 1",
                    "if-no-files-found: error",
                ),
            )
        )
        if current_revision is not None and "continue-on-error" in current_revision:
            errors.append(
                f"{path}: current-revision Scorecard evidence must fail on scanner errors"
            )
        for prohibited in ("security-events: write", "actions/upload-artifact@"):
            if prohibited == "actions/upload-artifact@":
                continue
            if prohibited in text:
                errors.append(
                    f"{path}: Scorecard workflow must not contain {prohibited!r}"
                )
    return errors


def workflow_contract_errors(path: Path, text: str, data: Any) -> list[str]:
    errors = trust_boundary_errors(path, text)
    if not isinstance(data, dict):
        return [*errors, f"{path}: workflow must be a mapping"]
    if "permissions" not in data:
        errors.append(f"{path}: workflow must declare explicit top-level permissions")
    errors.extend(concurrency_errors(path, data))
    errors.extend(python_provisioning_errors(path, text))
    errors.extend(scanner_evidence_errors(path, text))
    if path.name == "ci-security-codeql.yml" and "tools: linked" not in text:
        errors.append(f"{path}: CodeQL init must select the linked tool bundle")
    if "run:" in text and not run_shell_default(data):
        errors.append(
            f"{path}: shell-running workflow must set defaults.run.shell to bash"
        )
    errors.extend(permission_errors(path, data))
    if isinstance(data.get("env"), dict) and "GITHUB_TOKEN" in data["env"]:
        errors.append(f"{path}: GITHUB_TOKEN must not be exposed at workflow scope")
    jobs = data.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        errors.append(f"{path}: workflow must define jobs")
        return errors
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            errors.append(f"{path}: job {job_name!r} must be a mapping")
            continue
        timeout = job.get("timeout-minutes")
        if type(timeout) is not int or timeout <= 0:
            errors.append(
                f"{path}: job {job_name!r} must set a positive integer timeout-minutes"
            )
        if isinstance(job.get("env"), dict) and "GITHUB_TOKEN" in job["env"]:
            errors.append(f"{path}: job {job_name!r} must not expose GITHUB_TOKEN")
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            continue
        for step in steps:
            if not isinstance(step, dict):
                continue
            reference = str(step.get("uses", ""))
            if reference.startswith("actions/checkout@"):
                checkout = step.get("with")
                if not isinstance(checkout, dict):
                    errors.append(
                        f"{path}: checkout step must declare safe checkout settings"
                    )
                    continue
                if checkout.get("persist-credentials") is not False:
                    errors.append(
                        f"{path}: checkout must set persist-credentials: false"
                    )
                if checkout.get("submodules") is not False:
                    errors.append(f"{path}: checkout must set submodules: false")
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
        help="Path relative to --root unless already absolute.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.root.resolve()
    lock_path = args.lock if args.lock.is_absolute() else root / args.lock
    errors = validate(root, lock_path)
    if errors:
        print("CI security contract violations:")
        print("\n".join(f"- {error}" for error in errors))
        return 1
    print("CI security contract passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
