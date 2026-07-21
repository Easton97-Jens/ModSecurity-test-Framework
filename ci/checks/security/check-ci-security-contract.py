#!/usr/bin/env python3
"""Validate Framework-owned GitHub Actions security contracts."""

from __future__ import annotations

import argparse
import hashlib
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
WORKFLOW_TOOL_UPDATER = "update-workflow-tools.yml"
GITHUB_TOKEN_EXPRESSION = "${{ github.token }}"
UPDATER_PUBLISH_TOKEN_ENV = "PUBLISH_TOKEN"
STEP_CHECKOUT_TRUSTED_DEFAULT_REVISION = "Checkout trusted default revision"
STEP_SETUP_REVIEWED_PYTHON = "Set up reviewed Python"
STEP_INSTALL_HASH_LOCKED_CI_DEPENDENCY = "Install hash-locked CI dependency"
STEP_FETCH_CHECKSUM_VERIFIED_SHELLCHECK = "Fetch checksum-verified ShellCheck"
STEP_VALIDATE_EPHEMERAL_COMMON_SH_CANDIDATE = (
    "Validate an ephemeral common.sh candidate"
)
STEP_SYNTAX_AND_SHELLCHECK = "Syntax and ShellCheck"
STEP_INSPECT_DRAFT_MAINTENANCE_PULL_REQUEST = (
    "Inspect matching Draft maintenance pull request"
)
STEP_PREPARE_CONSTRAINED_MAINTENANCE_BRANCH = (
    "Prepare the constrained maintenance branch"
)
STEP_REVALIDATE_REUSABLE_DRAFT_BRANCH = (
    "Revalidate the reusable Draft branch before modifying it"
)
STEP_RERESOLVE_CURRENT_CANDIDATES = "Re-resolve and narrowly apply current candidates"
STEP_COMMIT_AND_PUSH_APPROVED_UPDATER_PATHS = (
    "Commit and push only approved updater paths"
)
STEP_CREATE_DRAFT_PULL_REQUEST = "Create the matching Draft pull request"
STEP_KEYS_ACTION = frozenset({"name", "uses", "with"})
STEP_KEYS_RUN = frozenset({"name", "run"})
STEP_KEYS_ENV_RUN = frozenset({"env", "name", "run"})
STEP_KEYS_SCRIPT = frozenset({"id", "name", "uses", "with"})
STEP_KEYS_ENV_ID_RUN = frozenset({"env", "id", "name", "run"})
STEP_KEYS_CONDITIONAL_SCRIPT = frozenset({"if", "name", "uses", "with"})
COMMON_RECORD_FIELDS = {
    "name",
    "version",
    "immutable_commit",
    "upstream_release",
    "license",
    "purpose",
    "platform",
    "update_procedure",
}
ACTION_RELEASE_RESOLUTION_LATEST = "latest-release"
ACTION_RELEASE_RESOLUTION_SAME_MAJOR = "same-major-release"
ACTION_RELEASE_RESOLUTIONS = {
    ACTION_RELEASE_RESOLUTION_LATEST,
    ACTION_RELEASE_RESOLUTION_SAME_MAJOR,
}
REVIEWED_ACTION_RELEASE_RESOLUTIONS = {
    "github/codeql-action": ACTION_RELEASE_RESOLUTION_SAME_MAJOR,
}
CODEQL_ACTION_SERIES_TAG = re.compile(r"^v\d+\.\d+\.\d+$", re.ASCII)
ACTION_FIELDS = COMMON_RECORD_FIELDS | {"release_resolution"}
TOOL_FIELDS = COMMON_RECORD_FIELDS | {
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
    "cleanup-artifacts.yml": {"actions"},
    "ci-security-codeql.yml": {"security-events"},
    WORKFLOW_TOOL_UPDATER: {"contents", "pull-requests"},
}
TOKEN_REFERENCE_ALLOWLIST = {
    "ci-security-dependency-review.yml",
    WORKFLOW_TOOL_UPDATER,
}
TOKEN_REFERENCE = re.compile(
    r"(?:github\.token|secrets\.GITHUB_TOKEN|\$\{?GITHUB_TOKEN\}?)"
)
GITHUB_COMPONENT = r"[A-Za-z0-9_.-]+"
GITHUB_RELEASE_URL = re.compile(
    rf"^https://github\.com/(?P<owner>{GITHUB_COMPONENT})/"
    rf"(?P<repository>{GITHUB_COMPONENT})/releases/tag/(?P<tag>[^/?#]+)$"
)
GITHUB_RELEASE_ASSET_URL = re.compile(
    rf"^https://github\.com/(?P<owner>{GITHUB_COMPONENT})/"
    rf"(?P<repository>{GITHUB_COMPONENT})/releases/download/"
    rf"(?P<tag>[^/?#]+)/(?P<asset>{GITHUB_COMPONENT})$"
)
REVIEWED_PYTHON_VERSION = "3.13.14"
UPDATER_READ_ONLY_PERMISSIONS = {"contents": "read"}
UPDATER_PUBLISHER_PERMISSIONS = {
    "contents": "write",
    "pull-requests": "write",
}
UPDATER_JOB_NAMES = frozenset({"resolver", "validator", "publisher"})
UPDATER_DEFAULT_REF_CONDITION = (
    "github.ref == format('refs/heads/{0}', github.event.repository.default_branch)"
)
UPDATER_HAS_UPDATES_CONDITION = "needs.resolver.outputs.has_updates == 'true'"
UPDATER_TRIGGERS = {
    "workflow_dispatch": None,
    "schedule": [{"cron": "17 5 * * 1"}],
}
COMMON_VERSION_READ_ONLY_PERMISSIONS = {"contents": "read"}
COMMON_VERSION_JOB_NAME = "check-common-versions"
COMMON_VERSION_JOB_KEYS = frozenset(
    {"runs-on", "timeout-minutes", "permissions", "steps"}
)
COMMON_VERSION_STEP_PROFILE = (
    (STEP_CHECKOUT_TRUSTED_DEFAULT_REVISION, STEP_KEYS_ACTION),
    (STEP_SETUP_REVIEWED_PYTHON, STEP_KEYS_ACTION),
    (STEP_INSTALL_HASH_LOCKED_CI_DEPENDENCY, STEP_KEYS_RUN),
    (STEP_FETCH_CHECKSUM_VERIFIED_SHELLCHECK, STEP_KEYS_ENV_RUN),
    (STEP_VALIDATE_EPHEMERAL_COMMON_SH_CANDIDATE, STEP_KEYS_RUN),
    (STEP_SYNTAX_AND_SHELLCHECK, STEP_KEYS_ENV_RUN),
)
COMMON_VERSION_ACTIONS = {
    STEP_CHECKOUT_TRUSTED_DEFAULT_REVISION: "actions/checkout",
    STEP_SETUP_REVIEWED_PYTHON: "actions/setup-python",
}
COMMON_VERSION_WITH_VALUES = {
    STEP_CHECKOUT_TRUSTED_DEFAULT_REVISION: {
        "ref": "${{ github.event.repository.default_branch }}",
        "fetch-depth": 1,
        "persist-credentials": False,
        "submodules": False,
    },
    STEP_SETUP_REVIEWED_PYTHON: {
        "python-version": REVIEWED_PYTHON_VERSION,
        "check-latest": False,
    },
}
COMMON_VERSION_ENV_VALUES = {
    STEP_FETCH_CHECKSUM_VERIFIED_SHELLCHECK: {
        "TOOLS_DIR": "${{ runner.temp }}/framework-ci-security-tools",
    },
    STEP_SYNTAX_AND_SHELLCHECK: {
        "TOOLS_DIR": "${{ runner.temp }}/framework-ci-security-tools",
    },
}
COMMON_VERSION_RUN_SHA256 = {
    STEP_INSTALL_HASH_LOCKED_CI_DEPENDENCY: "bd13dd746985e7fc0aeb48e4966da62abc3775685f8c16117911fe3c3ba5399e",
    STEP_FETCH_CHECKSUM_VERIFIED_SHELLCHECK: "f4e26f8af7f41a9e425a9416c78f0ff7ca2b4e8faa0837acd94c91b26a4ecb7d",
    STEP_VALIDATE_EPHEMERAL_COMMON_SH_CANDIDATE: "07bd03533098e4545fc5ad541321b508a694832dad4a2c97c35737f12053fe2d",
    STEP_SYNTAX_AND_SHELLCHECK: "48e6e6a734c93fd322d37696b3667027b5a2be31aa2192b386ff47a6b35f739e",
}
COMMON_VERSION_FORBIDDEN_DELIVERY_SNIPPETS = (
    "peter-evans/create-pull-request@",
    "actions/github-script@",
    "github.token",
    "GITHUB_TOKEN",
    "PUBLISH_TOKEN",
    "git push",
    "git switch",
    "git branch",
    "git checkout -b",
    "gh pr",
    "pulls.create",
    "pulls.update",
    "pulls.merge",
    "delete-branch:",
    "force",
    "refs/heads/",
)
# The publisher is the updater's only write-capable trust boundary.  Its run and
# github-script bodies are intentionally static: updating an Action pin does not
# change them.  Hashing the YAML-parsed bodies, together with the exact step
# profile below, fails closed on aliases, shell prefixes, comments, or extra
# publisher behavior instead of attempting to recognize every unsafe spelling.
UPDATER_PUBLISHER_JOB_KEYS = frozenset(
    {"needs", "if", "runs-on", "timeout-minutes", "permissions", "steps"}
)
UPDATER_PUBLISHER_STEP_PROFILE = (
    (STEP_CHECKOUT_TRUSTED_DEFAULT_REVISION, STEP_KEYS_ACTION),
    (STEP_SETUP_REVIEWED_PYTHON, STEP_KEYS_ACTION),
    (STEP_INSTALL_HASH_LOCKED_CI_DEPENDENCY, STEP_KEYS_RUN),
    (
        STEP_INSPECT_DRAFT_MAINTENANCE_PULL_REQUEST,
        STEP_KEYS_SCRIPT,
    ),
    (
        STEP_PREPARE_CONSTRAINED_MAINTENANCE_BRANCH,
        STEP_KEYS_ENV_RUN,
    ),
    (STEP_REVALIDATE_REUSABLE_DRAFT_BRANCH, STEP_KEYS_RUN),
    (STEP_RERESOLVE_CURRENT_CANDIDATES, STEP_KEYS_RUN),
    (STEP_COMMIT_AND_PUSH_APPROVED_UPDATER_PATHS, STEP_KEYS_ENV_ID_RUN),
    (
        STEP_CREATE_DRAFT_PULL_REQUEST,
        STEP_KEYS_CONDITIONAL_SCRIPT,
    ),
)
UPDATER_PUBLISHER_ACTIONS = {
    STEP_CHECKOUT_TRUSTED_DEFAULT_REVISION: "actions/checkout",
    STEP_SETUP_REVIEWED_PYTHON: "actions/setup-python",
    STEP_INSPECT_DRAFT_MAINTENANCE_PULL_REQUEST: "actions/github-script",
    STEP_CREATE_DRAFT_PULL_REQUEST: "actions/github-script",
}
UPDATER_PUBLISHER_WITH_VALUES = {
    STEP_CHECKOUT_TRUSTED_DEFAULT_REVISION: {
        "ref": "${{ github.event.repository.default_branch }}",
        "fetch-depth": 1,
        "persist-credentials": False,
        "submodules": False,
    },
    STEP_SETUP_REVIEWED_PYTHON: {
        "python-version": REVIEWED_PYTHON_VERSION,
        "check-latest": False,
    },
}
UPDATER_PUBLISHER_WITH_KEYS = {
    **{
        name: frozenset(values)
        for name, values in UPDATER_PUBLISHER_WITH_VALUES.items()
    },
    STEP_INSPECT_DRAFT_MAINTENANCE_PULL_REQUEST: frozenset({"github-token", "script"}),
    STEP_CREATE_DRAFT_PULL_REQUEST: frozenset({"github-token", "script"}),
}
UPDATER_PUBLISHER_ENV_VALUES = {
    STEP_PREPARE_CONSTRAINED_MAINTENANCE_BRANCH: {
        "MAINTENANCE_PR_EXISTS": "${{ steps.maintenance_pr.outputs.existing }}",
        UPDATER_PUBLISH_TOKEN_ENV: GITHUB_TOKEN_EXPRESSION,
    },
    STEP_COMMIT_AND_PUSH_APPROVED_UPDATER_PATHS: {
        UPDATER_PUBLISH_TOKEN_ENV: GITHUB_TOKEN_EXPRESSION,
    },
}
UPDATER_PUBLISHER_FIELD_VALUES = {
    STEP_INSPECT_DRAFT_MAINTENANCE_PULL_REQUEST: {"id": "maintenance_pr"},
    STEP_COMMIT_AND_PUSH_APPROVED_UPDATER_PATHS: {"id": "commit"},
    STEP_CREATE_DRAFT_PULL_REQUEST: {
        "if": "steps.commit.outputs.changed == 'true' && "
        "steps.maintenance_pr.outputs.existing == 'false'",
    },
}
UPDATER_PUBLISHER_RUN_SHA256 = {
    STEP_INSTALL_HASH_LOCKED_CI_DEPENDENCY: "bd13dd746985e7fc0aeb48e4966da62abc3775685f8c16117911fe3c3ba5399e",
    STEP_PREPARE_CONSTRAINED_MAINTENANCE_BRANCH: "f04648061e1365c9a9b74c74746bdef6afb4481e1959d57fdf008606d650a9c6",
    STEP_REVALIDATE_REUSABLE_DRAFT_BRANCH: "4c68dd3aed3315ae942409eb52d6a44175a1c668cde2e9413a475e4422524c93",
    STEP_RERESOLVE_CURRENT_CANDIDATES: "bd0d48ff34d281197af63c9e72be64a719ecd48689c2edf6fbf7fbd4a5f6a278",
    STEP_COMMIT_AND_PUSH_APPROVED_UPDATER_PATHS: "7287c78623047abc8f73b435103bad91c1dcf1bf4b149ba58bedaea28826e174",
}
UPDATER_PUBLISHER_SCRIPT_SHA256 = {
    STEP_INSPECT_DRAFT_MAINTENANCE_PULL_REQUEST: "3d51794a9c57865efd999657eb78214383cf3c81f7575498eebb1ef9dcbf4699",
    STEP_CREATE_DRAFT_PULL_REQUEST: "83d13cd70cdb643a924d7a79abc1d52bb58f9e2979d5b1e925c7595446fe806c",
}
UPDATER_SENSITIVE_KEY = re.compile(r"(?:secret|token)", re.IGNORECASE)
UPDATER_SENSITIVE_VALUE = re.compile(
    r"(?:\$\{\{[^}]*\b(?:secrets|token)\b[^}]*\}\}|"
    r"\bgithub\s*\.\s*token\b|\bsecrets\s*(?:\.|\[)|"
    r"\b(?:GITHUB_TOKEN|PUBLISH_TOKEN)\b|"
    r"\$(?:\{)?[A-Za-z_]*TOKEN[A-Za-z_]*\}?)",
    re.IGNORECASE,
)
PYTHON_VERSION_DECLARATION = re.compile(
    r"^\s*python-version:\s*['\"]?([^\s'\"#]+)['\"]?\s*(?:#.*)?$",
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
    if group == "action":
        resolution = record.get("release_resolution")
        expected_resolution = REVIEWED_ACTION_RELEASE_RESOLUTIONS.get(
            name, ACTION_RELEASE_RESOLUTION_LATEST
        )
        if (
            not isinstance(resolution, str)
            or resolution not in ACTION_RELEASE_RESOLUTIONS
        ):
            errors.append(
                f"{path}: action {name!r} has an unsupported release resolution"
            )
        elif resolution != expected_resolution:
            errors.append(
                f"{path}: action {name!r} must use release resolution "
                f"{expected_resolution!r}"
            )
        if (
            resolution == ACTION_RELEASE_RESOLUTION_SAME_MAJOR
            and not CODEQL_ACTION_SERIES_TAG.fullmatch(str(record.get("version", "")))
        ):
            errors.append(
                f"{path}: action {name!r} same-major release resolution requires "
                "a v<major>.<minor>.<patch> version"
            )
    return errors


def release_provenance_errors(
    path: Path, group: str, name: str, record: dict[str, Any]
) -> list[str]:
    """Bind every static lock record to one exact official release tuple."""

    errors: list[str] = []
    version = record.get("version")
    release = record.get("upstream_release")
    release_match = (
        GITHUB_RELEASE_URL.fullmatch(release) if isinstance(release, str) else None
    )
    if release_match is None:
        return [f"{path}: {group} {name!r} has no exact GitHub release URL"]
    release_identity = (
        release_match.group("owner"),
        release_match.group("repository"),
        release_match.group("tag"),
    )
    if not isinstance(version, str) or release_identity[2] != version:
        errors.append(
            f"{path}: {group} {name!r} release URL tag must match record.version"
        )
    if group == "action" and "/".join(release_identity[:2]) != name:
        errors.append(
            f"{path}: action {name!r} upstream release owner/repository must match its name"
        )
    if group != "tool":
        return errors

    asset_url = record.get("asset_url")
    asset_match = (
        GITHUB_RELEASE_ASSET_URL.fullmatch(asset_url)
        if isinstance(asset_url, str)
        else None
    )
    if asset_match is None:
        return [
            *errors,
            f"{path}: tool {name!r} has no exact GitHub release asset URL",
        ]
    asset_identity = (
        asset_match.group("owner"),
        asset_match.group("repository"),
        asset_match.group("tag"),
    )
    if asset_identity != release_identity:
        errors.append(
            f"{path}: tool {name!r} asset URL owner/repository/tag must match "
            "upstream_release and record.version"
        )
    if asset_match.group("asset") != record.get("asset"):
        errors.append(
            f"{path}: tool {name!r} asset URL must end in its exact locked asset"
        )
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

    errors = [
        *common_record_errors(path, group, name, record),
        *release_provenance_errors(path, group, name, record),
    ]
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
    versions = PYTHON_VERSION_DECLARATION.findall(text)
    if not versions or any(version != REVIEWED_PYTHON_VERSION for version in versions):
        errors.append(
            f"{path}: setup-python must use exact reviewed CPython "
            f"{REVIEWED_PYTHON_VERSION}"
        )
    if not CHECK_LATEST_FALSE.search(text):
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


def updater_sensitive_references(value: Any, location: str = "job") -> list[str]:
    """Find token-bearing values/keys after YAML parsing, never by comments."""

    if isinstance(value, dict):
        references: list[str] = []
        for raw_key, child in value.items():
            key = str(raw_key)
            child_location = f"{location}.{key}"
            if UPDATER_SENSITIVE_KEY.search(key):
                references.append(child_location)
            references.extend(updater_sensitive_references(child, child_location))
        return references
    if isinstance(value, list):
        return [
            reference
            for index, child in enumerate(value)
            for reference in updater_sensitive_references(child, f"{location}[{index}]")
        ]
    if isinstance(value, str) and UPDATER_SENSITIVE_VALUE.search(value):
        return [location]
    return []


def updater_read_only_job_errors(path: Path, data: dict[str, Any]) -> list[str]:
    """Enforce least privilege for named non-publishing updater jobs."""

    jobs = data.get("jobs")
    if not isinstance(jobs, dict):
        return [f"{path}: updater must define resolver and validator jobs"]

    errors: list[str] = []
    for name in ("resolver", "validator"):
        job = jobs.get(name)
        if not isinstance(job, dict):
            errors.append(f"{path}: updater {name} job must be a mapping")
            continue
        if job.get("permissions") != UPDATER_READ_ONLY_PERMISSIONS:
            errors.append(
                f"{path}: updater {name} must declare exactly "
                "{contents: read} permissions"
            )
        references = updater_sensitive_references(job, f"jobs.{name}")
        if references:
            errors.append(
                f"{path}: updater {name} must not contain secrets or token "
                f"expressions ({', '.join(sorted(set(references)))})"
            )
    return errors


def updater_job_topology_errors(path: Path, data: dict[str, Any]) -> list[str]:
    """Keep all token-bearing or write-capable updater work in publisher only."""

    jobs = data.get("jobs")
    if not isinstance(jobs, dict):
        return [
            f"{path}: updater must define exactly resolver, validator, and publisher jobs"
        ]
    errors: list[str] = []
    if set(jobs) != UPDATER_JOB_NAMES:
        errors.append(
            f"{path}: updater must define exactly resolver, validator, and publisher jobs"
        )
    if data.get("permissions") != UPDATER_READ_ONLY_PERMISSIONS:
        errors.append(
            f"{path}: updater top-level permissions must be exactly {UPDATER_READ_ONLY_PERMISSIONS}"
        )
    top_level_references = updater_sensitive_references(data.get("env", {}), "env")
    if top_level_references:
        errors.append(
            f"{path}: updater must not contain secrets or token expressions outside "
            f"publisher ({', '.join(sorted(set(top_level_references)))})"
        )
    publisher = jobs.get("publisher")
    if not isinstance(publisher, dict):
        errors.append(f"{path}: updater publisher job must be a mapping")
    elif publisher.get("permissions") != UPDATER_PUBLISHER_PERMISSIONS:
        errors.append(
            f"{path}: updater publisher must declare exactly "
            "{contents: write, pull-requests: write} permissions"
        )
    return errors


def job_needs(job: dict[str, Any]) -> set[str] | None:
    value = job.get("needs")
    if isinstance(value, str):
        return {value}
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return set(value)
    return None


def updater_ordering_errors(path: Path, data: dict[str, Any]) -> list[str]:
    """Require the parsed resolver → validator → publisher trust ordering."""

    jobs = data.get("jobs")
    if not isinstance(jobs, dict):
        return [
            f"{path}: updater must define ordered resolver/validator/publisher jobs"
        ]
    validator = jobs.get("validator")
    publisher = jobs.get("publisher")
    errors: list[str] = []
    if not isinstance(validator, dict):
        errors.append(f"{path}: updater validator job must be a mapping")
    elif job_needs(validator) != {"resolver"}:
        errors.append(f"{path}: updater validator must need exactly resolver")
    if not isinstance(publisher, dict):
        errors.append(f"{path}: updater publisher job must be a mapping")
        return errors
    if job_needs(publisher) != {"resolver", "validator"}:
        errors.append(f"{path}: updater publisher must need resolver and validator")
    expected_if = f"{UPDATER_DEFAULT_REF_CONDITION} && {UPDATER_HAS_UPDATES_CONDITION}"
    actual_if = publisher.get("if")
    if not isinstance(actual_if, str) or " ".join(actual_if.split()) != expected_if:
        errors.append(
            f"{path}: updater publisher must be gated to the default branch and "
            "resolver has_updates output"
        )
    return errors


def updater_trigger_errors(path: Path, data: dict[str, Any]) -> list[str]:
    """Allow the write-capable updater to start only by schedule or dispatch."""

    yaml_data: dict[Any, Any] = data
    has_string_on = "on" in yaml_data
    has_yaml_boolean_on = True in yaml_data
    if has_string_on and has_yaml_boolean_on:
        return [f"{path}: updater trigger declaration is ambiguous"]
    triggers = yaml_data.get("on") if has_string_on else yaml_data.get(True)
    if triggers != UPDATER_TRIGGERS:
        return [
            f"{path}: updater triggers must be exactly the reviewed schedule and workflow_dispatch"
        ]
    return []


def publisher_body_digest(value: str) -> str:
    """Return the fixed digest for a YAML-parsed publisher program body."""

    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def publisher_job_setting_errors(path: Path, publisher: dict[str, Any]) -> list[str]:
    """Validate the reviewed publisher job fields before checking its steps."""

    errors: list[str] = []
    if set(publisher) != UPDATER_PUBLISHER_JOB_KEYS:
        errors.append(
            f"{path}: updater publisher job must match its reviewed key profile"
        )
    if publisher.get("runs-on") != "ubuntu-latest":
        errors.append(f"{path}: updater publisher must use the reviewed runner")
    if publisher.get("timeout-minutes") != 25:
        errors.append(f"{path}: updater publisher must use the reviewed timeout")
    return errors


def publisher_step_key_errors(
    path: Path, step: dict[str, Any], name: str, expected_keys: frozenset[str]
) -> list[str]:
    if set(step) == expected_keys:
        return []
    return [f"{path}: publisher step {name!r} must match its reviewed key profile"]


def publisher_step_action_errors(
    path: Path, step: dict[str, Any], name: str
) -> list[str]:
    expected_action = UPDATER_PUBLISHER_ACTIONS.get(name)
    if expected_action is None:
        return []
    uses = step.get("uses")
    action_name = uses.split("@", 1)[0] if isinstance(uses, str) else None
    if action_name == expected_action:
        return []
    return [f"{path}: publisher step {name!r} must use {expected_action}"]


def publisher_script_body_errors(
    path: Path, name: str, with_values: dict[Any, Any]
) -> list[str]:
    if name not in UPDATER_PUBLISHER_SCRIPT_SHA256:
        return []

    errors: list[str] = []
    if with_values.get("github-token") != GITHUB_TOKEN_EXPRESSION:
        errors.append(
            f"{path}: publisher step {name!r} must use the scoped github token"
        )
    script = with_values.get("script")
    if not isinstance(script, str) or (
        publisher_body_digest(script) != UPDATER_PUBLISHER_SCRIPT_SHA256[name]
    ):
        errors.append(
            f"{path}: publisher github-script body {name!r} must match the reviewed SHA-256"
        )
    return errors


def publisher_step_with_errors(
    path: Path, step: dict[str, Any], name: str
) -> list[str]:
    expected_with_keys = UPDATER_PUBLISHER_WITH_KEYS.get(name)
    if expected_with_keys is None:
        return []

    errors: list[str] = []
    with_values = step.get("with")
    if not isinstance(with_values, dict) or set(with_values) != expected_with_keys:
        errors.append(
            f"{path}: publisher step {name!r} must match its reviewed with profile"
        )
        with_values = {}
    expected_with_values = UPDATER_PUBLISHER_WITH_VALUES.get(name)
    if expected_with_values is not None and with_values != expected_with_values:
        errors.append(f"{path}: publisher step {name!r} must use reviewed with values")
    errors.extend(publisher_script_body_errors(path, name, with_values))
    return errors


def publisher_step_environment_errors(
    path: Path, step: dict[str, Any], name: str
) -> list[str]:
    expected_environment = UPDATER_PUBLISHER_ENV_VALUES.get(name)
    if expected_environment is None or step.get("env") == expected_environment:
        return []
    return [f"{path}: publisher step {name!r} must use the reviewed environment"]


def publisher_step_field_errors(
    path: Path, step: dict[str, Any], name: str
) -> list[str]:
    return [
        f"{path}: publisher step {name!r} must use the reviewed {field}"
        for field, expected_value in UPDATER_PUBLISHER_FIELD_VALUES.get(
            name, {}
        ).items()
        if step.get(field) != expected_value
    ]


def publisher_step_run_errors(path: Path, step: dict[str, Any], name: str) -> list[str]:
    expected_run_digest = UPDATER_PUBLISHER_RUN_SHA256.get(name)
    if expected_run_digest is None:
        return []
    run = step.get("run")
    if isinstance(run, str) and publisher_body_digest(run) == expected_run_digest:
        return []
    return [f"{path}: publisher run body {name!r} must match the reviewed SHA-256"]


def publisher_step_profile_errors(
    path: Path, step: dict[str, Any], name: str, expected_keys: frozenset[str]
) -> list[str]:
    """Return all exact-profile errors for one already identified publisher step."""

    return [
        *publisher_step_key_errors(path, step, name, expected_keys),
        *publisher_step_action_errors(path, step, name),
        *publisher_step_with_errors(path, step, name),
        *publisher_step_environment_errors(path, step, name),
        *publisher_step_field_errors(path, step, name),
        *publisher_step_run_errors(path, step, name),
    ]


def updater_publisher_profile_errors(path: Path, data: dict[str, Any]) -> list[str]:
    """Fail closed if the write-capable publisher differs from its reviewed profile."""

    jobs = data.get("jobs")
    if not isinstance(jobs, dict):
        return [f"{path}: updater publisher profile requires jobs to be a mapping"]
    publisher = jobs.get("publisher")
    if not isinstance(publisher, dict):
        return [f"{path}: updater publisher profile requires a publisher job mapping"]

    errors = publisher_job_setting_errors(path, publisher)

    steps = publisher.get("steps")
    if not isinstance(steps, list):
        return [*errors, f"{path}: updater publisher steps must be a list"]
    expected_names = [name for name, _keys in UPDATER_PUBLISHER_STEP_PROFILE]
    actual_names = [
        step.get("name") if isinstance(step, dict) else None for step in steps
    ]
    if actual_names != expected_names:
        return [
            *errors,
            f"{path}: updater publisher steps must match the reviewed order and count",
        ]

    for step, (name, expected_keys) in zip(steps, UPDATER_PUBLISHER_STEP_PROFILE):
        assert isinstance(step, dict)
        errors.extend(publisher_step_profile_errors(path, step, name, expected_keys))
    return errors


def workflow_tool_updater_errors(
    path: Path, text: str, data: dict[str, Any]
) -> list[str]:
    """Enforce resolver/validator/publisher separation for the CI updater."""

    if path.name != WORKFLOW_TOOL_UPDATER:
        return []

    errors: list[str] = []
    errors.extend(updater_read_only_job_errors(path, data))
    errors.extend(updater_job_topology_errors(path, data))
    errors.extend(updater_ordering_errors(path, data))
    errors.extend(updater_trigger_errors(path, data))
    errors.extend(updater_publisher_profile_errors(path, data))
    resolver = job_text(text, "resolver")
    validator = job_text(text, "validator")
    errors.extend(
        require_workflow_text(
            path,
            "resolver",
            resolver,
            (
                "contents: read",
                "resolve --root . --github-output",
                "persist-credentials: false",
                "submodules: false",
            ),
        )
    )
    errors.extend(
        require_workflow_text(
            path,
            "validator",
            validator,
            (
                "contents: read",
                "--candidate-b64",
                "--verify-tool-assets",
                "persist-credentials: false",
                "submodules: false",
            ),
        )
    )
    return errors


def common_version_job_profile_errors(path: Path, job: dict[str, Any]) -> list[str]:
    """Validate the reviewed common-version job fields before checking its steps."""

    errors: list[str] = []
    if set(job) != COMMON_VERSION_JOB_KEYS:
        errors.append(
            f"{path}: common-version checker job must match its reviewed key profile"
        )
    if job.get("runs-on") != "ubuntu-latest" or job.get("timeout-minutes") != 30:
        errors.append(
            f"{path}: common-version checker job must use its reviewed runner and timeout"
        )
    if job.get("permissions") != COMMON_VERSION_READ_ONLY_PERMISSIONS:
        errors.append(
            f"{path}: common-version checker job must declare exactly {COMMON_VERSION_READ_ONLY_PERMISSIONS}"
        )
    return errors


def common_version_action_profile_errors(
    path: Path, step: dict[str, Any], name: str
) -> list[str]:
    expected_action = COMMON_VERSION_ACTIONS.get(name)
    if expected_action is None:
        return []

    errors: list[str] = []
    uses = step.get("uses")
    action_name = uses.split("@", 1)[0] if isinstance(uses, str) else None
    if action_name != expected_action:
        errors.append(
            f"{path}: common-version step {name!r} must use {expected_action}"
        )
    if step.get("with") != COMMON_VERSION_WITH_VALUES[name]:
        errors.append(
            f"{path}: common-version step {name!r} must use reviewed checkout/runtime values"
        )
    return errors


def common_version_step_profile_errors(
    path: Path, step: dict[str, Any], name: str, expected_keys: frozenset[str]
) -> list[str]:
    """Return all exact-profile errors for one already identified read-only step."""

    errors: list[str] = []
    if set(step) != expected_keys:
        errors.append(
            f"{path}: common-version step {name!r} must match its reviewed key profile"
        )
    errors.extend(common_version_action_profile_errors(path, step, name))
    expected_environment = COMMON_VERSION_ENV_VALUES.get(name)
    if expected_environment is not None and step.get("env") != expected_environment:
        errors.append(
            f"{path}: common-version step {name!r} must use the reviewed environment"
        )
    expected_run_digest = COMMON_VERSION_RUN_SHA256.get(name)
    if expected_run_digest is not None:
        run = step.get("run")
        if (
            not isinstance(run, str)
            or publisher_body_digest(run) != expected_run_digest
        ):
            errors.append(
                f"{path}: common-version run body {name!r} must match the reviewed SHA-256"
            )
    return errors


def common_version_step_errors(
    path: Path, job: dict[str, Any]
) -> tuple[list[str], bool]:
    """Validate the ordered steps and report whether delivery checks may continue."""

    steps = job.get("steps")
    if not isinstance(steps, list):
        return [f"{path}: common-version checker steps must be a list"], False
    expected_names = [name for name, _keys in COMMON_VERSION_STEP_PROFILE]
    actual_names = [
        step.get("name") if isinstance(step, dict) else None for step in steps
    ]
    if actual_names != expected_names:
        return [
            f"{path}: common-version checker steps must match the reviewed order and count"
        ], False

    errors: list[str] = []
    for step, (name, expected_keys) in zip(steps, COMMON_VERSION_STEP_PROFILE):
        assert isinstance(step, dict)
        errors.extend(
            common_version_step_profile_errors(path, step, name, expected_keys)
        )
    return errors, True


def common_version_job_errors(
    path: Path, data: dict[str, Any]
) -> tuple[list[str], dict[str, Any] | None]:
    """Return reviewed-job errors and the mapping needed for step validation."""

    errors: list[str] = []
    if data.get("permissions") != COMMON_VERSION_READ_ONLY_PERMISSIONS:
        errors.append(
            f"{path}: common-version workflow must declare exactly "
            "{contents: read} top-level permissions"
        )
    jobs = data.get("jobs")
    if not isinstance(jobs, dict) or set(jobs) != {COMMON_VERSION_JOB_NAME}:
        return [
            *errors,
            f"{path}: common-version workflow must define exactly its read-only checker job",
        ], None
    job = jobs[COMMON_VERSION_JOB_NAME]
    if not isinstance(job, dict):
        return [*errors, f"{path}: common-version checker job must be a mapping"], None
    errors.extend(common_version_job_profile_errors(path, job))
    return errors, job


def common_version_read_only_errors(
    path: Path, text: str, data: dict[str, Any]
) -> list[str]:
    """Keep the common-version checker read-only and free of delivery behavior."""

    if path.name != "check-common-versions.yml":
        return []

    errors, job = common_version_job_errors(path, data)
    if job is None:
        return errors

    step_errors, can_check_delivery = common_version_step_errors(path, job)
    errors.extend(step_errors)
    if not can_check_delivery:
        return errors
    errors.extend(
        forbidden_workflow_snippet_errors(
            path,
            text,
            "common-version read-only",
            COMMON_VERSION_FORBIDDEN_DELIVERY_SNIPPETS,
        )
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
        *scanner_evidence_errors(path, text),
        *codeql_tool_bundle_errors(path, text),
        *run_shell_default_errors(path, text, data),
        *permission_errors(path, data),
        *workflow_token_environment_errors(path, data),
        *workflow_tool_updater_errors(path, text, data),
        *common_version_read_only_errors(path, text, data),
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
