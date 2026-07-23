#!/usr/bin/env python3
"""Resolve, validate, and narrowly apply Framework CI Action/tool updates.

The updater deliberately separates three capabilities used by the GitHub
Actions workflow:

* ``resolve`` performs public, read-only GitHub API lookups and writes a
  candidate only below ``RUNNER_TEMP`` (or exposes a base64 GitHub output).
* ``validate`` rechecks the candidate against the checked-in lock and, for
  changed downloaded tools, verifies the release asset digest without
  executing the downloaded file.
* ``apply`` changes only the reviewed lock, the enumerated workflow pins, and
  the paired workflow-security guides.  The publisher calls it only after the
  read-only jobs succeeded.

It is intentionally not a general GitHub API client, package installer, or
repository editor.  URLs, record names, output paths, changed fields, and
publisher-visible paths are all constrained by the existing lock and explicit
allowlists.
"""

from __future__ import annotations

import argparse
import base64
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen

import yaml


class UpdateError(RuntimeError):
    """Raised when an update candidate violates the CI provenance contract."""


LOCK_RELATIVE_PATH = Path("ci/tooling/security-tools.lock.yml")
CANDIDATE_SCHEMA_VERSION = 1
GITHUB_API_ORIGIN = "https://api.github.com"
GITHUB_WEB_ORIGIN = "https://github.com"
GITHUB_USER_AGENT = "framework-workflow-tool-updater/1"
RUNNER_TEMP_STRICT_CHILD_ERROR = "candidate path must be a strict child of RUNNER_TEMP"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
STABLE_RELEASE_TAG = r"v?[0-9]+(?:\.[0-9]+){1,3}"
RELEASE_TAG = re.compile(rf"^{STABLE_RELEASE_TAG}$")
ACTION_SERIES_TAG = re.compile(
    r"^v(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)$", re.ASCII
)
UPSTREAM_RELEASE = re.compile(
    r"^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/releases/tag/"
    rf"({STABLE_RELEASE_TAG})$"
)
GIT_REVISION = re.compile(r"^[A-Za-z0-9_./-]+$")

# These are deliberately individual files, not broad directory prefixes.  A
# new workflow must be reviewed and added here before this publisher can touch
# it.  The paired guides describe the lock and the updater; only the Action
# table rows are mechanically refreshed.
ALLOWED_UPDATE_PATHS = frozenset(
    {
        "ci/tooling/security-tools.lock.yml",
        ".github/workflows/check-action-versions.yml",
        ".github/workflows/check-common-versions.yml",
        ".github/workflows/check-python-version.yml",
        ".github/workflows/cleanup-artifacts.yml",
        ".github/workflows/ci-security-codeql-pr.yml",
        ".github/workflows/ci-security-codeql.yml",
        ".github/workflows/ci-security-dependency-review.yml",
        ".github/workflows/ci-security-osv.yml",
        ".github/workflows/ci-security-quality.yml",
        ".github/workflows/ci-security-scorecard.yml",
        ".github/workflows/ci-security-secrets.yml",
        ".github/workflows/ci-security-workflow-lint.yml",
        ".github/workflows/lint.yml",
        ".github/workflows/test-common.yml",
        ".github/workflows/update-workflow-tools.yml",
        "docs/github-actions-workflow-security.md",
        "docs/github-actions-workflow-security.de.md",
    }
)
WORKFLOW_UPDATE_PATHS = tuple(
    path
    for path in sorted(ALLOWED_UPDATE_PATHS)
    if path.startswith(".github/workflows/")
)
DOCUMENTATION_UPDATE_PATHS = tuple(
    path for path in sorted(ALLOWED_UPDATE_PATHS) if path.startswith("docs/")
)
ACTION_MUTABLE_FIELDS = ("version", "immutable_commit", "upstream_release")
TOOL_MUTABLE_FIELDS = (
    "version",
    "immutable_commit",
    "upstream_release",
    "asset",
    "asset_url",
    "sha256",
)
ACTION_RELEASE_RESOLUTION_LATEST = "latest-release"
ACTION_RELEASE_RESOLUTION_SAME_MAJOR = "same-major-release"
REVIEWED_ACTION_RELEASE_RESOLUTIONS = {
    "github/codeql-action": ACTION_RELEASE_RESOLUTION_SAME_MAJOR,
}


@dataclass(frozen=True)
class RepositoryIdentity:
    """One official GitHub release source derived from a trusted lock record."""

    owner: str
    repository: str
    current_tag: str

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.repository}"


def framework_root() -> Path:
    return Path(__file__).resolve().parents[2]


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def is_safe_component(value: str) -> bool:
    path = PurePosixPath(value)
    return (
        bool(value)
        and not path.is_absolute()
        and len(path.parts) == 1
        and path.parts[0] not in {".", ".."}
    )


def is_safe_posix_path(value: str) -> bool:
    path = PurePosixPath(value)
    return (
        bool(value)
        and not path.is_absolute()
        and all(part not in {"", ".", ".."} for part in path.parts)
    )


def resolve_regular_file(root: Path, relative: Path) -> Path:
    """Resolve an existing regular non-symlink file contained by ``root``."""

    if (
        relative.is_absolute()
        or not relative.parts
        or any(part == ".." for part in relative.parts)
    ):
        raise UpdateError(f"unsafe relative path: {relative}")
    current = root
    for part in relative.parts:
        current = current / part
        try:
            mode = current.lstat().st_mode
        except OSError as exc:
            raise UpdateError(f"required path is missing: {relative}") from exc
        if stat.S_ISLNK(mode):
            raise UpdateError(f"required path must not traverse a symlink: {relative}")
    if not stat.S_ISREG(mode):
        raise UpdateError(f"required path is not a regular file: {relative}")
    return current


def resolve_root(root: Path) -> Path:
    if any(part == ".." for part in root.parts):
        raise UpdateError(f"root path must not contain traversal components: {root}")
    # Check before resolving: Path.resolve() erases the evidence that the
    # caller supplied a symlink, which would otherwise defeat this boundary.
    if root.is_symlink():
        raise UpdateError(f"root must be a non-symlink directory: {root}")
    try:
        resolved = root.resolve(strict=True)
    except OSError as exc:
        raise UpdateError(f"root must be an existing directory: {root}") from exc
    if not resolved.is_dir():
        raise UpdateError(f"root must be a non-symlink directory: {root}")
    return resolved


def load_lock(root: Path) -> tuple[Path, dict[str, Any], str]:
    lock_path = resolve_regular_file(root, LOCK_RELATIVE_PATH)
    try:
        data = yaml.safe_load(lock_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise UpdateError(f"cannot parse the security tool lock: {exc}") from exc
    if not isinstance(data, dict):
        raise UpdateError("security tool lock must be a mapping")
    if not isinstance(data.get("actions"), dict) or not isinstance(
        data.get("tools"), dict
    ):
        raise UpdateError("security tool lock must contain action and tool mappings")
    return lock_path, data, sha256_file(lock_path)


def workflow_source_paths(root: Path) -> list[Path]:
    """Return every regular Framework workflow without following symlinks."""

    workflow_root = root / ".github" / "workflows"
    for directory in (root / ".github", workflow_root):
        try:
            mode = directory.lstat().st_mode
        except OSError as exc:
            raise UpdateError("Framework workflow directory is missing") from exc
        if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
            raise UpdateError(
                "Framework workflow directory must be a non-symlink directory"
            )
    paths: list[Path] = []
    for candidate in sorted(workflow_root.rglob("*")):
        relative = candidate.relative_to(root)
        try:
            mode = candidate.lstat().st_mode
        except OSError as exc:
            raise UpdateError(f"cannot inspect workflow path: {relative}") from exc
        if stat.S_ISLNK(mode):
            raise UpdateError(f"workflow path must not be a symlink: {relative}")
        if stat.S_ISREG(mode) and candidate.suffix in {".yml", ".yaml"}:
            paths.append(resolve_regular_file(root, relative))
    return paths


def ensure_locked_action_workflow_coverage(root: Path, lock: dict[str, Any]) -> None:
    """Fail if a lock-managed Action appears outside publisher-approved paths."""

    workflow_paths = workflow_source_paths(root)
    missing: dict[str, list[str]] = {}
    actions = lock.get("actions")
    if not isinstance(actions, dict):
        raise UpdateError("lock actions records are missing")
    for name in sorted(actions):
        if not isinstance(name, str):
            raise UpdateError("lock action name is invalid")
        reference = re.compile(
            rf"{re.escape(name)}(?:/[A-Za-z0-9_.-]+)*@[0-9a-f]{{40}}"
        )
        referenced = {
            str(path.relative_to(root))
            for path in workflow_paths
            if reference.search(path.read_text(encoding="utf-8"))
        }
        unapproved = sorted(referenced.difference(WORKFLOW_UPDATE_PATHS))
        if unapproved:
            missing[name] = unapproved
    if missing:
        details = "; ".join(
            f"{name}: {', '.join(paths)}" for name, paths in sorted(missing.items())
        )
        raise UpdateError(
            "lock-managed Action references escape the publisher allowlist: " + details
        )


def lock_record(lock: dict[str, Any], group: str, name: str) -> dict[str, Any]:
    records = lock.get(group)
    if not isinstance(records, dict):
        raise UpdateError(f"lock {group} records are missing")
    record = records.get(name)
    if not isinstance(record, dict):
        raise UpdateError(f"{group} {name!r} is not an allow-listed lock record")
    return record


def release_identity(
    record: dict[str, Any], name: str, *, require_name_match: bool = False
) -> RepositoryIdentity:
    version = record.get("version")
    release = record.get("upstream_release")
    if not isinstance(version, str) or not RELEASE_TAG.fullmatch(version):
        raise UpdateError(f"{name!r} has an unsafe current release version")
    if not isinstance(release, str):
        raise UpdateError(f"{name!r} has no upstream release URL")
    match = UPSTREAM_RELEASE.fullmatch(release)
    if match is None:
        raise UpdateError(f"{name!r} must use an exact official GitHub release URL")
    owner, repository, current_tag = match.groups()
    if current_tag != version:
        raise UpdateError(f"{name!r} release URL tag does not match its version")
    identity = RepositoryIdentity(owner, repository, current_tag)
    if require_name_match and identity.slug != name:
        raise UpdateError(
            f"{name!r} release owner/repository does not match its action name"
        )
    return identity


def action_release_resolution(record: dict[str, Any], name: str) -> str:
    """Return the lock-reviewed Action release selection mode, fail closed."""

    expected = REVIEWED_ACTION_RELEASE_RESOLUTIONS.get(
        name, ACTION_RELEASE_RESOLUTION_LATEST
    )
    resolution = record.get("release_resolution")
    if resolution != expected:
        raise UpdateError(
            f"action {name!r} must use reviewed release resolution {expected!r}"
        )
    if resolution == ACTION_RELEASE_RESOLUTION_SAME_MAJOR:
        version = record.get("version")
        if not isinstance(version, str) or not ACTION_SERIES_TAG.fullmatch(version):
            raise UpdateError(
                f"action {name!r} same-major release resolution requires a "
                "v<major>.<minor>.<patch> lock tag"
            )
    return expected


def validate_tool_baseline_provenance(
    record: dict[str, Any], identity: RepositoryIdentity, tool: str
) -> None:
    """Require a tool lock's download tuple to match its trusted release tuple."""

    asset = record.get("asset")
    if not isinstance(asset, str) or not is_safe_component(asset):
        raise UpdateError(f"tool {tool!r} has an unsafe current asset record")
    expected_url = (
        f"{GITHUB_WEB_ORIGIN}/{identity.slug}/releases/download/"
        f"{identity.current_tag}/{asset}"
    )
    if record.get("asset_url") != expected_url:
        raise UpdateError(
            f"tool {tool!r} asset URL does not match its release owner/repository/tag"
        )


def require_sha40(value: Any, description: str) -> str:
    if not isinstance(value, str) or not SHA40.fullmatch(value):
        raise UpdateError(f"{description} must be a lowercase 40-character commit SHA")
    return value


def require_sha256(value: Any, description: str) -> str:
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        raise UpdateError(f"{description} must be a lowercase SHA-256 digest")
    return value


def github_payload(path: str) -> Any:
    """Read one fixed official GitHub API response without a token."""

    if not path.startswith("/repos/"):
        raise UpdateError("only repository-scoped GitHub API paths are allowed")
    request = Request(
        f"{GITHUB_API_ORIGIN}{path}",
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": GITHUB_USER_AGENT,
        },
    )
    try:
        with urlopen(request, timeout=30) as response:
            final = urlparse(response.geturl())
            if final.scheme != "https" or final.netloc != "api.github.com":
                raise UpdateError("GitHub API redirect escaped the official HTTPS API")
            payload = json.loads(response.read().decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UpdateError(f"official GitHub API request failed: {exc}") from exc
    return payload


def github_json(path: str) -> dict[str, Any]:
    """Read one fixed-shape object response from GitHub's public API."""

    payload = github_payload(path)
    if not isinstance(payload, dict):
        raise UpdateError("official GitHub API response must be an object")
    return payload


def github_json_list(path: str) -> list[dict[str, Any]]:
    """Read one bounded list response and reject malformed release entries."""

    payload = github_payload(path)
    if not isinstance(payload, list) or not all(
        isinstance(item, dict) for item in payload
    ):
        raise UpdateError("official GitHub API response must be a list of objects")
    return payload


def latest_release(identity: RepositoryIdentity) -> dict[str, Any]:
    return github_json(f"/repos/{identity.owner}/{identity.repository}/releases/latest")


def release_by_tag(identity: RepositoryIdentity, tag: str) -> dict[str, Any]:
    return github_json(
        f"/repos/{identity.owner}/{identity.repository}/releases/tags/"
        f"{quote(tag, safe='')}"
    )


def release_page(identity: RepositoryIdentity) -> list[dict[str, Any]]:
    """Read the bounded newest release page for an explicitly selected Action."""

    return github_json_list(
        f"/repos/{identity.owner}/{identity.repository}/releases?per_page=100"
    )


def stable_release_tag(release: dict[str, Any], description: str) -> str:
    """Return a stable official release tag, rejecting all preview states."""

    if release.get("draft") is not False or release.get("prerelease") is not False:
        raise UpdateError(f"{description} must be a published non-prerelease release")
    tag = release.get("tag_name")
    if not isinstance(tag, str) or not RELEASE_TAG.fullmatch(tag):
        raise UpdateError(f"{description} has no supported stable tag")
    return tag


def stable_release_tag_or_none(release: dict[str, Any]) -> str | None:
    """Return a published stable tag when a list entry is selectable."""

    if release.get("draft") is not False or release.get("prerelease") is not False:
        return None
    tag = release.get("tag_name")
    return tag if isinstance(tag, str) and RELEASE_TAG.fullmatch(tag) else None


def stable_tag_key(tag: str) -> tuple[int, int, int, int]:
    """Normalize a reviewed numeric Action tag for an exact-major comparison."""

    if not RELEASE_TAG.fullmatch(tag):
        raise UpdateError(f"unsupported stable release tag {tag!r}")
    parts = [int(part) for part in tag.removeprefix("v").split(".")]
    parts.extend([0] * (4 - len(parts)))
    return parts[0], parts[1], parts[2], parts[3]


def same_major_action_tag(current_tag: str, candidate_tag: str) -> bool:
    """Accept only a stable tag in the current lock's exact Action major line."""

    current = ACTION_SERIES_TAG.fullmatch(current_tag)
    candidate = ACTION_SERIES_TAG.fullmatch(candidate_tag)
    return (
        current is not None
        and candidate is not None
        and (current.group("major") == candidate.group("major"))
    )


def latest_same_major_action_release(
    identity: RepositoryIdentity, current_tag: str
) -> dict[str, Any]:
    """Select the highest published Action release in the lock-reviewed major."""

    current_key = stable_tag_key(current_tag)
    candidates: list[tuple[tuple[int, int, int, int], dict[str, Any]]] = []
    for release in release_page(identity):
        tag = stable_release_tag_or_none(release)
        if tag is None or not same_major_action_tag(current_tag, tag):
            continue
        candidates.append((stable_tag_key(tag), release))
    if not candidates:
        raise UpdateError(
            f"action {identity.slug!r} has no published stable release in "
            f"the reviewed major for {current_tag!r}"
        )
    candidate_key, candidate = max(candidates, key=lambda item: item[0])
    if candidate_key < current_key:
        raise UpdateError(
            f"action {identity.slug!r} release page is stale for {current_tag!r}"
        )
    return candidate


def selected_action_release(
    identity: RepositoryIdentity, name: str, record: dict[str, Any]
) -> dict[str, Any]:
    """Resolve only the lock-selected official Action release stream."""

    resolution = action_release_resolution(record, name)
    if resolution == ACTION_RELEASE_RESOLUTION_LATEST:
        return latest_release(identity)
    if resolution == ACTION_RELEASE_RESOLUTION_SAME_MAJOR:
        release = latest_same_major_action_release(identity, identity.current_tag)
        tag = stable_release_tag(release, f"action {name!r} selected page release")
        confirmed = release_by_tag(identity, tag)
        confirmed_tag = stable_release_tag(
            confirmed, f"action {name!r} selected release"
        )
        if confirmed_tag != tag:
            raise UpdateError(
                f"action {name!r} release tag does not match its release page"
            )
        return confirmed
    raise UpdateError(f"action {name!r} has an unsupported release resolution")


def validate_action_release_tag(
    identity: RepositoryIdentity, name: str, record: dict[str, Any], tag: str
) -> None:
    """Keep constrained Action records in their lock-reviewed release stream."""

    if action_release_resolution(
        record, name
    ) == ACTION_RELEASE_RESOLUTION_SAME_MAJOR and not same_major_action_tag(
        identity.current_tag, tag
    ):
        raise UpdateError(
            f"action {name!r} selected release does not match the reviewed major"
        )


def selected_action_release_tag(
    identity: RepositoryIdentity,
    name: str,
    record: dict[str, Any],
    release: dict[str, Any],
    description: str,
) -> str:
    """Validate the Action release object selected from its reviewed stream."""

    tag = stable_release_tag(release, description)
    resolution = action_release_resolution(record, name)
    validate_action_release_tag(identity, name, record, tag)
    if (
        resolution == ACTION_RELEASE_RESOLUTION_SAME_MAJOR
        and release.get("immutable") is not True
    ):
        raise UpdateError(f"action {name!r} selected release must be immutable")
    return tag


def release_tag_commit(identity: RepositoryIdentity, tag: str) -> str:
    """Resolve an official release tag through the GitHub Git API, fail closed."""

    if not RELEASE_TAG.fullmatch(tag):
        raise UpdateError(
            f"{identity.slug} latest release tag is not a supported stable version"
        )
    reference = github_json(
        f"/repos/{identity.owner}/{identity.repository}/git/ref/tags/{quote(tag, safe='')}"
    )
    obj = reference.get("object")
    if not isinstance(obj, dict):
        raise UpdateError(f"{identity.slug} tag reference has no Git object")
    kind = obj.get("type")
    sha = require_sha40(obj.get("sha"), f"{identity.slug} tag object")
    # Annotated tags point at a tag object.  Refuse nested/other object types
    # instead of guessing a commit identity.
    if kind == "commit":
        return sha
    if kind != "tag":
        raise UpdateError(
            f"{identity.slug} tag must resolve to a commit or annotated tag"
        )
    tag_object = github_json(
        f"/repos/{identity.owner}/{identity.repository}/git/tags/{sha}"
    ).get("object")
    if not isinstance(tag_object, dict) or tag_object.get("type") != "commit":
        raise UpdateError(
            f"{identity.slug} annotated tag must resolve directly to a commit"
        )
    return require_sha40(tag_object.get("sha"), f"{identity.slug} annotated tag commit")


def expected_asset_name(record: dict[str, Any], new_version: str, tool: str) -> str:
    old_version = record.get("version")
    asset = record.get("asset")
    if (
        not isinstance(old_version, str)
        or not isinstance(asset, str)
        or not is_safe_component(asset)
    ):
        raise UpdateError(f"tool {tool!r} has an unsafe current asset record")
    old_token = old_version.removeprefix("v")
    new_token = new_version.removeprefix("v")
    if old_token and old_token in asset:
        if asset.count(old_token) != 1:
            raise UpdateError(
                f"tool {tool!r} asset contains its version more than once"
            )
        return asset.replace(old_token, new_token)
    return asset


def selected_release_asset(
    identity: RepositoryIdentity,
    release: dict[str, Any],
    record: dict[str, Any],
    tool: str,
) -> tuple[str, str, str]:
    tag = stable_release_tag(release, f"tool {tool!r} release")
    asset_name = expected_asset_name(record, tag, tool)
    assets = release.get("assets")
    if not isinstance(assets, list):
        raise UpdateError(f"tool {tool!r} release has no asset list")
    candidates = [
        asset
        for asset in assets
        if isinstance(asset, dict) and asset.get("name") == asset_name
    ]
    if len(candidates) != 1:
        raise UpdateError(
            f"tool {tool!r} release must contain exactly one expected asset {asset_name!r}"
        )
    asset = candidates[0]
    digest = asset.get("digest")
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        raise UpdateError(f"tool {tool!r} official release asset has no SHA-256 digest")
    sha256 = require_sha256(
        digest.removeprefix("sha256:"), f"tool {tool!r} release asset"
    )
    asset_url = (
        f"{GITHUB_WEB_ORIGIN}/{identity.slug}/releases/download/{tag}/{asset_name}"
    )
    if asset.get("browser_download_url") != asset_url:
        raise UpdateError(
            f"tool {tool!r} release asset URL does not match the official release tuple"
        )
    return tag, asset_name, sha256


def action_candidate(name: str, record: dict[str, Any]) -> dict[str, str] | None:
    identity = release_identity(record, name, require_name_match=True)
    release = selected_action_release(identity, name, record)
    tag = selected_action_release_tag(
        identity, name, record, release, f"action {name!r} selected release"
    )
    commit = release_tag_commit(identity, tag)
    if tag == record["version"] and commit == record["immutable_commit"]:
        return None
    return {
        "version": tag,
        "immutable_commit": commit,
        "upstream_release": f"{GITHUB_WEB_ORIGIN}/{identity.slug}/releases/tag/{tag}",
    }


def tool_candidate(name: str, record: dict[str, Any]) -> dict[str, str] | None:
    identity = release_identity(record, name)
    validate_tool_baseline_provenance(record, identity, name)
    release = latest_release(identity)
    tag, asset, asset_digest = selected_release_asset(identity, release, record, name)
    commit = release_tag_commit(identity, tag)
    candidate = {
        "version": tag,
        "immutable_commit": commit,
        "upstream_release": f"{GITHUB_WEB_ORIGIN}/{identity.slug}/releases/tag/{tag}",
        "asset": asset,
        "asset_url": f"{GITHUB_WEB_ORIGIN}/{identity.slug}/releases/download/{tag}/{asset}",
        "sha256": asset_digest,
    }
    if all(candidate[field] == record[field] for field in TOOL_MUTABLE_FIELDS):
        return None
    return candidate


def resolve_candidate(root: Path) -> dict[str, Any]:
    """Resolve a public-read-only candidate from the trusted current lock."""

    _lock_path, lock, lock_digest = load_lock(root)
    ensure_locked_action_workflow_coverage(root, lock)
    actions: dict[str, dict[str, str]] = {}
    tools: dict[str, dict[str, str]] = {}
    for name, record in sorted(lock["actions"].items()):
        if not isinstance(name, str) or not isinstance(record, dict):
            raise UpdateError("action lock contains an invalid record")
        resolved = action_candidate(name, record)
        if resolved is not None:
            actions[name] = resolved
    for name, record in sorted(lock["tools"].items()):
        if not isinstance(name, str) or not isinstance(record, dict):
            raise UpdateError("tool lock contains an invalid record")
        resolved = tool_candidate(name, record)
        if resolved is not None:
            tools[name] = resolved
    return {
        "schema_version": CANDIDATE_SCHEMA_VERSION,
        "lock_sha256": lock_digest,
        "actions": actions,
        "tools": tools,
    }


def canonical_candidate(candidate: dict[str, Any]) -> str:
    return json.dumps(candidate, sort_keys=True, separators=(",", ":"))


def candidate_b64(candidate: dict[str, Any]) -> str:
    return base64.b64encode(canonical_candidate(candidate).encode("utf-8")).decode(
        "ascii"
    )


def decode_candidate(value: str) -> dict[str, Any]:
    try:
        decoded = base64.b64decode(value, validate=True).decode("utf-8")
        candidate = json.loads(decoded)
    except ValueError as exc:
        raise UpdateError("candidate base64 payload is malformed") from exc
    if not isinstance(candidate, dict):
        raise UpdateError("candidate payload must be a JSON object")
    return candidate


def runner_temp_root() -> Path:
    """Return the owned physical runner temp root without accepting a symlink."""

    runner_value = os.environ.get("RUNNER_TEMP")
    if not runner_value:
        raise UpdateError("RUNNER_TEMP is required for candidate files")
    runner_temp = Path(runner_value)
    if not runner_temp.is_absolute():
        raise UpdateError("RUNNER_TEMP and candidate paths must be absolute")
    if any(part == ".." for part in runner_temp.parts):
        raise UpdateError("RUNNER_TEMP must not contain traversal components")
    if runner_temp.is_symlink() or not runner_temp.is_dir():
        raise UpdateError("RUNNER_TEMP must be an existing non-symlink directory")
    runner_root = runner_temp.resolve(strict=True)
    if runner_root.stat().st_uid != os.geteuid():
        raise UpdateError("RUNNER_TEMP must be owned by the current runner user")
    return runner_root


def runner_temp_relative_path(path: Path, runner_root: Path) -> Path:
    """Return one lexical, strict child path before any filesystem access."""

    if not path.is_absolute():
        raise UpdateError("RUNNER_TEMP and candidate paths must be absolute")
    try:
        relative = path.relative_to(runner_root)
    except ValueError as exc:
        raise UpdateError(RUNNER_TEMP_STRICT_CHILD_ERROR) from exc
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise UpdateError(RUNNER_TEMP_STRICT_CHILD_ERROR)
    return relative


def reject_runner_temp_symlinks(runner_root: Path, relative: Path) -> None:
    """Reject every existing lexical component that could redirect candidate I/O."""

    current = runner_root
    for component in relative.parts:
        current = current / component
        if current.is_symlink():
            raise UpdateError("candidate path must not traverse a symlink")


def resolved_runner_temp_child(path: Path, runner_root: Path, *, strict: bool) -> Path:
    """Canonicalize a candidate path and prove it remains a strict temp child."""

    try:
        resolved = path.resolve(strict=strict)
    except OSError as exc:
        raise UpdateError("candidate path cannot be resolved") from exc
    try:
        relative = resolved.relative_to(runner_root)
    except ValueError as exc:
        raise UpdateError(RUNNER_TEMP_STRICT_CHILD_ERROR) from exc
    if not relative.parts:
        raise UpdateError(RUNNER_TEMP_STRICT_CHILD_ERROR)
    return resolved


def candidate_write_path(path: Path, runner_root: Path, relative: Path) -> Path:
    """Create a candidate-only parent without permitting an existing target."""

    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    reject_runner_temp_symlinks(runner_root, relative)
    if path.exists() or path.is_symlink():
        raise UpdateError("refusing to overwrite an existing candidate file")
    return resolved_runner_temp_child(path, runner_root, strict=False)


def candidate_read_path(path: Path, runner_root: Path) -> Path:
    """Require an existing candidate to remain a regular non-symlink file."""

    if path.is_symlink() or not path.is_file():
        raise UpdateError("candidate must be a regular non-symlink file")
    return resolved_runner_temp_child(path, runner_root, strict=True)


def runner_temp_path(path: Path, *, for_write: bool) -> Path:
    """Require a regular path beneath a runner-owned, non-symlink temp root."""

    runner_root = runner_temp_root()
    relative = runner_temp_relative_path(path, runner_root)
    reject_runner_temp_symlinks(runner_root, relative)
    if for_write:
        return candidate_write_path(path, runner_root, relative)
    return candidate_read_path(path, runner_root)


def write_candidate(path: Path, candidate: dict[str, Any]) -> None:
    destination = runner_temp_path(path, for_write=True)
    # Resolve immediately at the filesystem sink as a defense in depth layer
    # for CLI-provided paths; runner_temp_path already checked containment.
    destination = destination.resolve(strict=False)
    with destination.open("x", encoding="utf-8") as output:
        os.fchmod(output.fileno(), 0o600)
        output.write(canonical_candidate(candidate) + "\n")


def read_candidate(path: Path) -> dict[str, Any]:
    source = runner_temp_path(path, for_write=False)
    # The direct canonicalization keeps the checked path at the I/O boundary.
    source = source.resolve(strict=True)
    try:
        with source.open(encoding="utf-8") as input_file:
            loaded = json.load(input_file)
    except (OSError, json.JSONDecodeError) as exc:
        raise UpdateError("candidate JSON is malformed") from exc
    if not isinstance(loaded, dict):
        raise UpdateError("candidate JSON must be an object")
    return loaded


def validated_candidate_record(
    group: str, fields: tuple[str, ...], lock: dict[str, Any], name: Any, changes: Any
) -> tuple[str, dict[str, Any]]:
    """Validate one candidate entry and reconstruct its resulting lock record."""

    if not isinstance(name, str) or not isinstance(changes, dict):
        raise UpdateError(f"candidate {group} entry is malformed")
    baseline = lock_record(lock, group, name)
    if set(changes) != set(fields):
        raise UpdateError(f"candidate {group} {name!r} changes an unapproved field")
    if not all(isinstance(changes[field], str) and changes[field] for field in fields):
        raise UpdateError(f"candidate {group} {name!r} has an empty field")
    if changes["version"] == baseline.get("version"):
        raise UpdateError(
            f"candidate {group} {name!r} must not include a no-op version"
        )
    validate_changed_record(group, name, baseline, changes)
    resulting = deepcopy(baseline)
    resulting.update(changes)
    return name, resulting


def validated_candidate_group(
    candidate: dict[str, Any], lock: dict[str, Any], group: str, fields: tuple[str, ...]
) -> dict[str, dict[str, Any]]:
    """Validate every changed record for one lock group."""

    proposed = candidate.get(group)
    if not isinstance(proposed, dict):
        raise UpdateError(f"candidate {group} must be a mapping")
    changed_records: dict[str, dict[str, Any]] = {}
    for name, changes in proposed.items():
        record_name, resulting = validated_candidate_record(
            group, fields, lock, name, changes
        )
        changed_records[record_name] = resulting
    return changed_records


def validate_candidate_shape(
    candidate: dict[str, Any], lock: dict[str, Any], lock_digest: str
) -> dict[str, dict[str, dict[str, Any]]]:
    """Validate candidate fields and reconstruct the exact resulting records."""

    if candidate.get("schema_version") != CANDIDATE_SCHEMA_VERSION:
        raise UpdateError("candidate schema version is not supported")
    if candidate.get("lock_sha256") != lock_digest:
        raise UpdateError("candidate does not describe the current trusted lock")
    return {
        "actions": validated_candidate_group(
            candidate, lock, "actions", ACTION_MUTABLE_FIELDS
        ),
        "tools": validated_candidate_group(
            candidate, lock, "tools", TOOL_MUTABLE_FIELDS
        ),
    }


def validate_changed_record(
    group: str, name: str, baseline: dict[str, Any], changes: dict[str, str]
) -> None:
    identity = release_identity(baseline, name, require_name_match=group == "actions")
    if group == "tools":
        validate_tool_baseline_provenance(baseline, identity, name)
    version = changes["version"]
    if not RELEASE_TAG.fullmatch(version):
        raise UpdateError(
            f"candidate {group} {name!r} version is not a supported stable tag"
        )
    require_sha40(changes["immutable_commit"], f"candidate {group} {name!r} commit")
    expected_release = f"{GITHUB_WEB_ORIGIN}/{identity.slug}/releases/tag/{version}"
    if changes["upstream_release"] != expected_release:
        raise UpdateError(f"candidate {group} {name!r} has an untrusted release URL")
    if group == "actions":
        validate_action_release_tag(identity, name, baseline, version)
        return
    asset = changes["asset"]
    if not is_safe_component(asset):
        raise UpdateError(f"candidate tool {name!r} has an unsafe asset name")
    expected_asset = expected_asset_name(baseline, version, name)
    if asset != expected_asset:
        raise UpdateError(
            f"candidate tool {name!r} asset does not match its reviewed naming rule"
        )
    expected_url = (
        f"{GITHUB_WEB_ORIGIN}/{identity.slug}/releases/download/{version}/{asset}"
    )
    if changes["asset_url"] != expected_url:
        raise UpdateError(f"candidate tool {name!r} has an untrusted asset URL")
    require_sha256(changes["sha256"], f"candidate tool {name!r} asset")


def load_fetcher_module() -> Any:
    module_path = Path(__file__).with_name("fetch-security-tool.py")
    spec = importlib.util.spec_from_file_location(
        "framework_security_tool_fetcher", module_path
    )
    if spec is None or spec.loader is None:
        raise UpdateError("cannot load the checksum-verified tool downloader")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify_changed_tool_assets(
    changes: dict[str, dict[str, dict[str, str]]], output_dir: Path
) -> None:
    """Fetch only changed tools through the existing checksum-safe downloader."""

    changed_tools = changes["tools"]
    if not changed_tools:
        return
    fetcher = load_fetcher_module()
    # The downloader independently enforces that this is a safe RUNNER_TEMP
    # child, verifies the SHA-256 before extraction, and never executes assets.
    for name, record in sorted(changed_tools.items()):
        fetcher.fetch(record, output_dir / name)


def proposed_validation_root() -> Path:
    """Create one private, bounded temporary root for candidate-only writes."""

    runner_root = runner_temp_root()
    proposed = Path(
        tempfile.mkdtemp(prefix="framework-workflow-tool-proposed-", dir=runner_root)
    )
    mode = proposed.lstat().st_mode
    if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
        raise UpdateError("proposed validation root must be a non-symlink directory")
    if proposed.parent != runner_root or proposed.stat().st_uid != os.geteuid():
        raise UpdateError("proposed validation root must be runner-owned")
    proposed.chmod(0o700)
    return proposed


def copy_update_inputs(source_root: Path, destination_root: Path) -> None:
    """Copy only the explicit update surface into a fresh private temp root."""

    for relative_text in sorted(ALLOWED_UPDATE_PATHS):
        relative = Path(relative_text)
        source = resolve_regular_file(source_root, relative)
        destination = destination_root / relative
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if destination.exists() or destination.is_symlink():
            raise UpdateError(f"proposed validation path already exists: {relative}")
        with source.open("rb") as input_file, destination.open("xb") as output_file:
            shutil.copyfileobj(input_file, output_file)
        destination.chmod(0o600)


def run_proposed_tree_contract_checks(proposed_root: Path) -> None:
    """Run fixed trusted checkers against the candidate-only proposed tree."""

    source_root = framework_root()
    checks = (
        (
            Path("ci/checks/security/check-github-actions-workflows.py"),
            ("--workflow-root", ".github/workflows", "--check", "all"),
            "workflow metadata",
        ),
        (
            Path("ci/checks/security/check-workflow-action-pins.py"),
            ("--workflow-root", ".github/workflows"),
            "workflow Action pins",
        ),
        (
            Path("ci/checks/security/check-ci-security-contract.py"),
            ("--root", "."),
            "CI security contract",
        ),
    )
    for relative, arguments, description in checks:
        checker = resolve_regular_file(source_root, relative)
        result = subprocess.run(
            [sys.executable, str(checker), *arguments],
            cwd=proposed_root,
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            output = f"{result.stdout}{result.stderr}".strip()
            raise UpdateError(
                f"proposed workflow-tool candidate fails {description}: {output}"
            )


def validate_proposed_tree(root: Path, candidate: dict[str, Any]) -> None:
    """Apply a candidate only in RUNNER_TEMP, then validate its resulting tree."""

    source_root = resolve_root(root)
    proposed_root = proposed_validation_root()
    try:
        copy_update_inputs(source_root, proposed_root)
        apply_candidate(proposed_root, candidate)
        run_proposed_tree_contract_checks(proposed_root)
    finally:
        shutil.rmtree(proposed_root, ignore_errors=True)


def replace_lock_field(section: str, field: str, old: str, new: str, name: str) -> str:
    expected = f"    {field}: {old}\n"
    replacement = f"    {field}: {new}\n"
    count = section.count(expected)
    if count != 1:
        raise UpdateError(
            f"lock record {name!r} does not contain exactly one expected {field}"
        )
    return section.replace(expected, replacement)


def lock_record_section(text: str, group: str, name: str) -> tuple[int, int, str]:
    group_header = f"{group}:\n"
    group_start = text.find(group_header)
    if group_start < 0:
        raise UpdateError(f"lock has no {group} section")
    header = f"  {name}:\n"
    start = text.find(header, group_start + len(group_header))
    if start < 0:
        raise UpdateError(f"lock has no record for {name!r}")
    # Fields are indented by four spaces.  The record ends only at the next
    # two-space mapping key or a following top-level mapping key, never at a
    # field line that merely starts with the same first two spaces.
    boundaries = [
        match.start()
        for match in re.finditer(
            r"(?m)^ {2}\S.*:$|^\S.*:$", text[start + len(header) :]
        )
    ]
    end = start + len(header) + min(boundaries) if boundaries else len(text)
    section = text[start:end]
    if not section.startswith(header):
        raise UpdateError(f"lock record {name!r} has an unsafe layout")
    return start, end, section


def write_verified_text(path: Path, text: str) -> None:
    """Rewrite an existing reviewed regular file through its canonical path."""

    if path.is_symlink() or not path.is_file():
        raise UpdateError("updated path must be a regular non-symlink file")
    destination = path.resolve(strict=True)
    with destination.open("w", encoding="utf-8") as output:
        output.write(text)


def apply_lock_changes(
    lock_path: Path, lock: dict[str, Any], candidate: dict[str, Any]
) -> None:
    text = lock_path.read_text(encoding="utf-8")
    for group, fields in (
        ("actions", ACTION_MUTABLE_FIELDS),
        ("tools", TOOL_MUTABLE_FIELDS),
    ):
        for name, changes in sorted(candidate[group].items()):
            baseline = lock_record(lock, group, name)
            start, end, section = lock_record_section(text, group, name)
            for field in fields:
                section = replace_lock_field(
                    section, field, str(baseline[field]), changes[field], name
                )
            text = f"{text[:start]}{section}{text[end:]}"
    write_verified_text(lock_path, text)


def update_workflow_references(
    root: Path, lock: dict[str, Any], candidate: dict[str, Any]
) -> None:
    for name, changes in sorted(candidate["actions"].items()):
        baseline = lock_record(lock, "actions", name)
        # Most records are used directly (``owner/action@sha``).  CodeQL is a
        # reviewed exception with explicit subactions such as ``/init`` and
        # ``/analyze``; retain only a simple safe suffix when replacing its
        # immutable pin rather than broadening the source/action allowlist.
        reference = re.compile(
            rf"{re.escape(name)}(?P<suffix>(?:/[A-Za-z0-9_.-]+)*)@"
            rf"{re.escape(str(baseline['immutable_commit']))}"
            rf" # {re.escape(str(baseline['version']))}"
        )
        replacements = 0
        for relative_text in WORKFLOW_UPDATE_PATHS:
            relative = Path(relative_text)
            path = resolve_regular_file(root, relative)
            text = path.read_text(encoding="utf-8")
            count = len(reference.findall(text))
            if count:
                write_verified_text(
                    path,
                    reference.sub(
                        lambda match: (
                            f"{name}{match.group('suffix')}@{changes['immutable_commit']}"
                            f" # {changes['version']}"
                        ),
                        text,
                    ),
                )
                replacements += count
        if replacements == 0:
            raise UpdateError(
                f"action {name!r} has no reviewed workflow reference to update"
            )


def update_documentation_references(
    root: Path, lock: dict[str, Any], candidate: dict[str, Any]
) -> None:
    for name, changes in sorted(candidate["actions"].items()):
        baseline = lock_record(lock, "actions", name)
        old_cells = f"`{baseline['version']}` | `{baseline['immutable_commit']}`"
        new_cells = f"`{changes['version']}` | `{changes['immutable_commit']}`"
        for relative_text in DOCUMENTATION_UPDATE_PATHS:
            path = resolve_regular_file(root, Path(relative_text))
            text = path.read_text(encoding="utf-8")
            if old_cells in text:
                write_verified_text(path, text.replace(old_cells, new_cells))


def apply_candidate(root: Path, candidate: dict[str, Any]) -> list[str]:
    root = resolve_root(root)
    lock_path, lock, lock_digest = load_lock(root)
    ensure_locked_action_workflow_coverage(root, lock)
    validate_candidate_shape(candidate, lock, lock_digest)
    before = {
        path: resolve_regular_file(root, Path(path)).read_bytes()
        for path in ALLOWED_UPDATE_PATHS
    }
    apply_lock_changes(lock_path, lock, candidate)
    update_workflow_references(root, lock, candidate)
    update_documentation_references(root, lock, candidate)
    changed = [
        path
        for path, contents in before.items()
        if resolve_regular_file(root, Path(path)).read_bytes() != contents
    ]
    unexpected = sorted(set(changed).difference(ALLOWED_UPDATE_PATHS))
    if unexpected:
        raise UpdateError(
            f"updater changed an unallowlisted path: {', '.join(unexpected)}"
        )
    return sorted(changed)


def safe_git_revision(value: str, description: str) -> str:
    if (
        not GIT_REVISION.fullmatch(value)
        or value.startswith("-")
        or ".." in value
        or value.endswith("/")
    ):
        raise UpdateError(f"{description} is not a safe Git revision")
    return value


def git_output_text(value: bytes | str) -> str:
    return (
        value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value
    )


def name_status_paths(output: bytes) -> list[str]:
    """Parse `git diff --name-status -z` and retain every changed pathname."""

    entries = output.split(b"\0")
    if not entries or entries[-1] != b"":
        raise UpdateError("publisher diff name-status output is malformed")
    entries.pop()
    if len(entries) % 2:
        raise UpdateError("publisher diff name-status output has an incomplete path")
    paths: list[str] = []
    for status, path in zip(entries[::2], entries[1::2], strict=True):
        status_text = status.decode("ascii", errors="replace")
        if not re.fullmatch(r"[ACDMRTUXB?]+", status_text):
            raise UpdateError("publisher diff name-status output has an invalid status")
        paths.append(os.fsdecode(path))
    return paths


def verify_git_scope(
    root: Path, staged: bool, base: str | None = None, head: str | None = None
) -> list[str]:
    if bool(base) != bool(head):
        raise UpdateError("scope comparison requires both --base and --head")
    if staged and base:
        raise UpdateError("--staged cannot be combined with --base/--head")
    arguments = ["git", "-C", str(root), "diff", "--name-status", "-z", "--no-renames"]
    if base and head:
        base = safe_git_revision(base, "scope base")
        head = safe_git_revision(head, "scope head")
        ancestry = subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "merge-base",
                "--is-ancestor",
                "--end-of-options",
                base,
                head,
            ],
            check=False,
            capture_output=True,
            shell=False,
        )
        if ancestry.returncode == 1:
            raise UpdateError(
                "publisher branch is stale: the current default branch is not its ancestor"
            )
        if ancestry.returncode != 0:
            raise UpdateError(
                "cannot verify publisher branch ancestry: "
                f"{git_output_text(ancestry.stderr).strip()}"
            )
        # Compare the current default tip directly to the reusable branch tip.
        # Triple-dot would hide paths introduced only on the newer default tip.
        arguments.extend(("--end-of-options", base, head))
    elif staged:
        arguments.append("--cached")
    result = subprocess.run(arguments, check=False, capture_output=True, shell=False)
    if result.returncode != 0:
        raise UpdateError(
            "cannot inspect publisher diff scope: "
            f"{git_output_text(result.stderr).strip()}"
        )
    changed = sorted(set(name_status_paths(result.stdout)))
    unexpected = sorted(set(changed).difference(ALLOWED_UPDATE_PATHS))
    if unexpected:
        raise UpdateError(
            f"publisher diff includes unallowlisted paths: {', '.join(unexpected)}"
        )
    return changed


def git_blob(root: Path, revision: str, relative: Path) -> bytes:
    """Read one allow-listed regular source blob without checking out its ref."""

    revision = safe_git_revision(revision, "Git blob revision")
    relative_text = relative.as_posix()
    if relative_text not in ALLOWED_UPDATE_PATHS:
        raise UpdateError(f"Git blob path is not allow-listed: {relative_text}")
    result = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "show",
            "--no-textconv",
            "--format=",
            "--end-of-options",
            f"{revision}:{relative_text}",
        ],
        check=False,
        capture_output=True,
        shell=False,
    )
    if result.returncode != 0:
        raise UpdateError(
            f"cannot read {relative_text} from {revision}: "
            f"{git_output_text(result.stderr).strip()}"
        )
    return result.stdout


def git_lock_blob_data(root: Path, revision: str) -> tuple[bytes, dict[str, Any]]:
    """Read and parse one trusted lock blob from a Git revision without checkout."""

    blob = git_blob(root, revision, LOCK_RELATIVE_PATH)
    try:
        data = yaml.safe_load(blob.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise UpdateError(
            f"security tool lock at {revision} is malformed: {exc}"
        ) from exc
    if (
        not isinstance(data, dict)
        or not isinstance(data.get("actions"), dict)
        or not isinstance(data.get("tools"), dict)
    ):
        raise UpdateError(
            f"security tool lock at {revision} must contain action and tool mappings"
        )
    return blob, data


def changed_lock_record_fields(
    group: str, name: str, base_record: dict[str, Any], head_record: dict[str, Any]
) -> dict[str, str] | None:
    """Allow only a complete mutable release tuple to differ from the base lock."""

    mutable_fields = (
        ACTION_MUTABLE_FIELDS if group == "actions" else TOOL_MUTABLE_FIELDS
    )
    if set(base_record) != set(head_record):
        raise UpdateError(
            f"existing branch {group} {name!r} adds or removes lock fields"
        )
    for field in base_record:
        if field not in mutable_fields and head_record[field] != base_record[field]:
            raise UpdateError(
                f"existing branch {group} {name!r} changes immutable field {field!r}"
            )
    changes = {field: head_record.get(field) for field in mutable_fields}
    if any(not isinstance(value, str) or not value for value in changes.values()):
        raise UpdateError(
            f"existing branch {group} {name!r} has an invalid mutable release field"
        )
    if all(changes[field] == base_record.get(field) for field in mutable_fields):
        return None
    return {field: str(value) for field, value in changes.items()}


def verify_changed_existing_branch_record(
    group: str, name: str, baseline: dict[str, Any], changes: dict[str, str]
) -> None:
    """Resolve a reused branch's changed tuple from the *base* lock identity."""

    validate_changed_record(group, name, baseline, changes)
    identity = release_identity(baseline, name, require_name_match=group == "actions")
    release = release_by_tag(identity, changes["version"])
    if group == "actions":
        tag = selected_action_release_tag(
            identity,
            name,
            baseline,
            release,
            f"existing branch action {name!r} release",
        )
    else:
        tag = stable_release_tag(release, f"existing branch tool {name!r} release")
    if tag != changes["version"]:
        raise UpdateError(
            f"existing branch {group} {name!r} release tag does not match its lock"
        )
    commit = release_tag_commit(identity, tag)
    if commit != changes["immutable_commit"]:
        raise UpdateError(
            f"existing branch {group} {name!r} commit does not match its tag"
        )
    if group == "actions":
        return
    _tag, asset, digest = selected_release_asset(identity, release, baseline, name)
    if asset != changes["asset"] or digest != changes["sha256"]:
        raise UpdateError(
            f"existing branch tool {name!r} asset or digest does not match its base identity"
        )


def verify_existing_branch_lock_metadata(
    base_lock: dict[str, Any], head_lock: dict[str, Any]
) -> None:
    """Keep lock-wide metadata immutable on a reusable maintenance branch."""

    if set(base_lock) != set(head_lock):
        raise UpdateError(
            "existing branch security tool lock adds or removes top-level fields"
        )
    for field in base_lock:
        if field not in {"actions", "tools"} and head_lock[field] != base_lock[field]:
            raise UpdateError(f"existing branch changes immutable lock field {field!r}")


def existing_branch_group_records(lock: dict[str, Any], group: str) -> dict[str, Any]:
    """Return one required lock-record mapping from a reusable branch."""

    records = lock.get(group)
    if not isinstance(records, dict):
        raise UpdateError(f"existing branch {group} lock records are missing")
    return records


def verify_existing_branch_group_record(
    group: str, name: Any, baseline: Any, head_record: Any
) -> None:
    """Verify the sole permissible mutable release tuple for one lock entry."""

    if (
        not isinstance(name, str)
        or not isinstance(baseline, dict)
        or not isinstance(head_record, dict)
    ):
        raise UpdateError(f"existing branch {group} lock record is malformed")
    changes = changed_lock_record_fields(group, name, baseline, head_record)
    if changes is not None:
        verify_changed_existing_branch_record(group, name, baseline, changes)


def verify_existing_branch_group_records(
    group: str, base_records: dict[str, Any], head_records: dict[str, Any]
) -> None:
    """Verify every lock entry in one immutable record group."""

    if set(base_records) != set(head_records):
        raise UpdateError(f"existing branch {group} lock records add or remove entries")
    for name in sorted(base_records):
        verify_existing_branch_group_record(
            group, name, base_records[name], head_records[name]
        )


def verify_existing_branch_lock_records(
    base_lock: dict[str, Any], head_lock: dict[str, Any]
) -> None:
    """Reject a reusable branch unless its lock is a base-identity verified update."""

    verify_existing_branch_lock_metadata(base_lock, head_lock)
    for group in ("actions", "tools"):
        verify_existing_branch_group_records(
            group,
            existing_branch_group_records(base_lock, group),
            existing_branch_group_records(head_lock, group),
        )


def existing_branch_candidate(
    base_lock: dict[str, Any], head_lock: dict[str, Any], base_lock_digest: str
) -> dict[str, Any]:
    """Derive the sole updater candidate that can produce a reusable branch."""

    candidate: dict[str, dict[str, dict[str, str]]] = {"actions": {}, "tools": {}}
    for group in ("actions", "tools"):
        base_records = base_lock[group]
        head_records = head_lock[group]
        if not isinstance(base_records, dict) or not isinstance(head_records, dict):
            raise UpdateError(f"existing branch {group} lock records are missing")
        for name in sorted(base_records):
            baseline = base_records[name]
            head_record = head_records.get(name)
            if (
                not isinstance(name, str)
                or not isinstance(baseline, dict)
                or not isinstance(head_record, dict)
            ):
                raise UpdateError(f"existing branch {group} lock record is malformed")
            changes = changed_lock_record_fields(group, name, baseline, head_record)
            if changes is not None:
                candidate[group][name] = changes
    return {
        "schema_version": CANDIDATE_SCHEMA_VERSION,
        "lock_sha256": base_lock_digest,
        "actions": candidate["actions"],
        "tools": candidate["tools"],
    }


def copy_git_update_inputs(root: Path, revision: str, destination_root: Path) -> None:
    """Materialize only trusted base blobs into a fresh bounded temp root."""

    for relative_text in sorted(ALLOWED_UPDATE_PATHS):
        relative = Path(relative_text)
        destination = destination_root / relative
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if destination.exists() or destination.is_symlink():
            raise UpdateError(
                f"existing branch validation path already exists: {relative}"
            )
        destination.write_bytes(git_blob(root, revision, relative))
        destination.chmod(0o600)


def verify_existing_branch_generated_blobs(
    root: Path,
    base: str,
    head: str,
    base_lock: dict[str, Any],
    head_lock: dict[str, Any],
    base_lock_digest: str,
) -> None:
    """Require every reusable-branch file to equal trusted updater output exactly."""

    candidate = existing_branch_candidate(base_lock, head_lock, base_lock_digest)
    expected_root = proposed_validation_root()
    try:
        copy_git_update_inputs(root, base, expected_root)
        apply_candidate(expected_root, candidate)
        for relative_text in sorted(ALLOWED_UPDATE_PATHS):
            relative = Path(relative_text)
            expected = resolve_regular_file(expected_root, relative).read_bytes()
            actual = git_blob(root, head, relative)
            if actual != expected:
                raise UpdateError(
                    "existing branch path does not match constrained updater output: "
                    f"{relative_text}"
                )
    finally:
        shutil.rmtree(expected_root, ignore_errors=True)


def verify_existing_branch(root: Path, base: str, head: str) -> None:
    """Verify a reusable Draft branch before trusting or switching to it."""

    root = resolve_root(root)
    verify_git_scope(root, staged=False, base=base, head=head)
    base_lock_blob, base_lock = git_lock_blob_data(root, base)
    _head_lock_blob, head_lock = git_lock_blob_data(root, head)
    verify_existing_branch_lock_records(base_lock, head_lock)
    verify_existing_branch_generated_blobs(
        root,
        base,
        head,
        base_lock,
        head_lock,
        hashlib.sha256(base_lock_blob).hexdigest(),
    )


def candidate_from_arguments(args: argparse.Namespace) -> dict[str, Any]:
    if getattr(args, "candidate_b64", None):
        return decode_candidate(args.candidate_b64)
    return read_candidate(args.candidate)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="mode", required=True)

    resolve = subparsers.add_parser(
        "resolve", help="resolve a public read-only candidate"
    )
    resolve.add_argument("--root", type=Path, default=framework_root())
    output = resolve.add_mutually_exclusive_group(required=True)
    output.add_argument("--output", type=Path)
    output.add_argument("--github-output", action="store_true")

    validate = subparsers.add_parser(
        "validate", help="validate a candidate without source writes"
    )
    validate.add_argument("--root", type=Path, default=framework_root())
    candidate = validate.add_mutually_exclusive_group(required=True)
    candidate.add_argument("--candidate", type=Path)
    candidate.add_argument("--candidate-b64")
    validate.add_argument("--verify-tool-assets", action="store_true")
    validate.add_argument("--output-dir", type=Path)
    validate.add_argument(
        "--validate-proposed-tree",
        action="store_true",
        help="apply only in a bounded RUNNER_TEMP copy and validate the result",
    )

    apply = subparsers.add_parser(
        "apply", help="apply the narrow allow-listed candidate"
    )
    apply.add_argument("--root", type=Path, default=framework_root())
    candidate = apply.add_mutually_exclusive_group(required=True)
    candidate.add_argument("--candidate", type=Path)
    candidate.add_argument("--candidate-b64")

    scope = subparsers.add_parser(
        "verify-scope", help="fail if a publisher diff escapes the allowlist"
    )
    scope.add_argument("--root", type=Path, default=framework_root())
    scope.add_argument("--staged", action="store_true")
    scope.add_argument("--base")
    scope.add_argument("--head")

    existing = subparsers.add_parser(
        "verify-existing-branch",
        help="verify a reusable branch against the trusted base lock before switching",
    )
    existing.add_argument("--root", type=Path, default=framework_root())
    existing.add_argument("--base", required=True)
    existing.add_argument("--head", required=True)
    return parser.parse_args()


def run_resolve_command(args: argparse.Namespace) -> None:
    candidate = resolve_candidate(resolve_root(args.root))
    if args.github_output:
        print(f"candidate_b64={candidate_b64(candidate)}")
        print(
            f"has_updates={'true' if candidate['actions'] or candidate['tools'] else 'false'}"
        )
        return
    write_candidate(args.output, candidate)
    print(args.output)


def run_validate_command(args: argparse.Namespace) -> int:
    root = resolve_root(args.root)
    _lock_path, lock, lock_digest = load_lock(root)
    ensure_locked_action_workflow_coverage(root, lock)
    candidate = candidate_from_arguments(args)
    changes = validate_candidate_shape(candidate, lock, lock_digest)
    if args.verify_tool_assets:
        if args.output_dir is None:
            raise UpdateError("--verify-tool-assets requires --output-dir")
        verify_changed_tool_assets(changes, args.output_dir)
    if args.validate_proposed_tree:
        validate_proposed_tree(root, candidate)
    print("workflow-tool candidate passed validation")
    return 0


def run_apply_command(args: argparse.Namespace) -> int:
    changed = apply_candidate(args.root, candidate_from_arguments(args))
    print("\n".join(changed))
    return 0


def run_verify_existing_branch_command(args: argparse.Namespace) -> int:
    verify_existing_branch(args.root, args.base, args.head)
    print("existing maintenance branch passed base-identity verification")
    return 0


def run_verify_scope_command(args: argparse.Namespace) -> int:
    root = resolve_root(args.root)
    changed = verify_git_scope(root, args.staged, args.base, args.head)
    print("\n".join(changed))
    return 0


def run_command(args: argparse.Namespace) -> int:
    if args.mode == "resolve":
        run_resolve_command(args)
        return 0
    handlers = {
        "validate": run_validate_command,
        "apply": run_apply_command,
        "verify-existing-branch": run_verify_existing_branch_command,
        "verify-scope": run_verify_scope_command,
    }
    handler = handlers.get(args.mode)
    if handler is None:
        raise UpdateError(f"unsupported updater mode: {args.mode!r}")
    return handler(args)


def main() -> int:
    try:
        return run_command(parse_args())
    except UpdateError as exc:
        print(f"workflow-tool updater error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
