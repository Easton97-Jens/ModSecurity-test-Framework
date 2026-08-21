"""Deterministic, fail-closed common-version maintenance planning.

This module is deliberately the *orchestration* layer.  It reuses the
component-specific release checks and the workflow-tool resolver, but makes
the non-optional global scopes visible in every productive run.  It never
sources ``common.sh`` and it never performs a GitHub write.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from typing import Any, Iterable, Protocol
from urllib.parse import urlparse


SCHEMA_VERSION = "1"
MAX_TEXT = 240
MAX_URLS = 8
REVIEW_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,159}$", re.ASCII)
COMPONENT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,79}$", re.ASCII)
VERSION_RE = re.compile(r"^v?\d+(?:\.\d+){1,3}$", re.ASCII)
SHA40_RE = re.compile(r"^[0-9a-f]{40}$", re.ASCII)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
ACTION_GROUP_RE = re.compile(
    r"^CI_ACTION_(?P<suffix>[A-Z0-9_]+)_(?P<field>REPOSITORY|VERSION|COMMIT)$",
    re.ASCII,
)
SIMPLE_REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", re.ASCII)
CANONICAL_VARIABLE_RE = re.compile(r"[A-Z][A-Z0-9_]{0,127}", re.ASCII)
NODE_COMPONENT_NAME = "Node.js"
CANONICAL_CI_COVERAGE_NAME = "Canonical CI pin coverage"
TOOL_GROUP_RE = re.compile(
    r"^CI_SECURITY_TOOL_(?P<suffix>[A-Z0-9_]+)_"
    r"(?P<field>REPOSITORY|VERSION|COMMIT|ASSET_NAME|SHA256)$",
    re.ASCII,
)
REVIEW_KINDS = frozenset(
    {
        "series_transition",
        "major_version_transition",
        "minor_version_transition",
        "release_commit_provenance",
        "provider_transition",
        "artifact_layout_transition",
        "platform_transition",
        "manual_digest_verification",
        "runtime_compatibility_review",
        "ci_runtime_transition",
    }
)
PYTHON_RELEASES_URL = "https://www.python.org/api/v2/downloads/release/"
PYPI_PYYAML_URL = "https://pypi.org/pypi/PyYAML/json"
NODE_INDEX_URL = "https://nodejs.org/dist/index.json"
PYTHON_VERSION_PATH = ".python-version"
CI_REQUIREMENTS_PATH = "requirements-ci.lock"
RUNTIME_MANIFEST_PATH = "ci/provisioning/runtime-components.manifest.json"
RUNTIME_LOCK_PATH = "ci/provisioning/runtime-component-lock.json"
SECURITY_TOOLS_LOCK_PATH = "ci/tooling/security-tools.lock.yml"
COMMON_SH_PATH = "ci/lib/common.sh"

MANDATORY_GLOBAL_SCOPES = (
    "go-ftw",
    "albedo",
    "python",
    "pyyaml",
    "node",
    "github-actions",
    "ci-security-tools",
)
GENERATED_VIEW_PATHS = (
    PYTHON_VERSION_PATH,
    CI_REQUIREMENTS_PATH,
    RUNTIME_MANIFEST_PATH,
    RUNTIME_LOCK_PATH,
    SECURITY_TOOLS_LOCK_PATH,
    "docs/reference/variables.md",
    "docs/reference/variables.de.md",
)
ALLOWED_AUTOMATIC_PATHS = frozenset(
    {
        COMMON_SH_PATH,
        PYTHON_VERSION_PATH,
        CI_REQUIREMENTS_PATH,
        SECURITY_TOOLS_LOCK_PATH,
        RUNTIME_MANIFEST_PATH,
        RUNTIME_LOCK_PATH,
        "docs/reference/variables.md",
        "docs/reference/variables.de.md",
        "docs/github-actions-workflow-security.md",
        "docs/github-actions-workflow-security.de.md",
        "tests/schemas/five-connectors-with-crs-no-mrts/normalized-event.schema.json",
        "tests/schemas/five-connectors-with-crs-no-mrts/manifest.schema.json",
        "tests/schemas/five-connectors-with-crs-no-mrts/receipt.schema.json",
        "tests/cases/security/crs/crs_sqli_anomaly_block.yaml",
    }
    | {
        f".github/workflows/{name}"
        for name in (
            "check-action-versions.yml",
            "check-common-versions.yml",
            "check-python-version.yml",
            "ci-security-codeql-pr.yml",
            "ci-security-codeql.yml",
            "ci-security-dependency-review.yml",
            "ci-security-osv.yml",
            "ci-security-quality.yml",
            "ci-security-scorecard.yml",
            "ci-security-secrets.yml",
            "ci-security-workflow-lint.yml",
            "cleanup-artifacts.yml",
            "five-connectors-with-crs-no-mrts-contract.yml",
            "lint.yml",
            "test-common.yml",
            "update-submodules.yml",
        )
    }
)


class MaintenanceError(RuntimeError):
    """A deterministic planning or candidate-application failure."""


class JsonClient(Protocol):
    def get_json(self, url: str) -> dict[str, Any]: ...

    def get_json_list(self, url: str) -> list[dict[str, Any]]: ...


def _load_module(root: Path, filename: str, module_name: str) -> Any:
    path = _managed_path(root, Path("ci") / "tools" / filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise MaintenanceError(f"cannot load checked-in maintenance helper {filename}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def load_runtime_checker(root: Path) -> Any:
    return _load_module(root, "check-common-versions.py", "framework_common_versions")


def load_workflow_tool_updater(root: Path) -> Any:
    return _load_module(root, "update-workflow-tools.py", "framework_workflow_tools")


def _require_real_directory_chain(path: Path, *, label: str) -> Path:
    """Return an absolute directory only when every ancestor is real."""

    candidate = Path(os.path.abspath(path))
    current = Path(candidate.anchor)
    _validate_directory_part(
        current, label=f"{label} root", missing_message="unavailable"
    )
    for part in candidate.parts[1:]:
        current /= part
        _validate_directory_part(
            current,
            label=label,
            missing_message=f"unavailable: {candidate}",
        )
    return candidate


def _validate_directory_part(path: Path, *, label: str, missing_message: str) -> None:
    try:
        details = path.lstat()
    except OSError as exc:
        raise MaintenanceError(f"{label} {missing_message}") from exc
    if stat.S_ISLNK(details.st_mode):
        raise MaintenanceError(f"{label} must not contain a symlink")
    if not stat.S_ISDIR(details.st_mode):
        raise MaintenanceError(f"{label} must be a real directory")


def _inspect_managed_part(
    current: Path, relative: Path, *, final: bool, allow_missing: bool
) -> bool:
    try:
        details = current.lstat()
    except FileNotFoundError:
        if final and allow_missing:
            return True
        raise MaintenanceError(f"managed maintenance path is unavailable: {relative}")
    except OSError as exc:
        raise MaintenanceError(
            f"cannot inspect managed maintenance path: {relative}"
        ) from exc
    if stat.S_ISLNK(details.st_mode):
        raise MaintenanceError(
            f"managed maintenance path must not traverse a symlink: {relative}"
        )
    if not final and not stat.S_ISDIR(details.st_mode):
        raise MaintenanceError(
            f"managed maintenance path has a non-directory ancestor: {relative}"
        )
    return False


def _managed_path(root: Path, relative: Path, *, allow_missing: bool = False) -> Path:
    """Confine an approved relative path below a real, non-symlinked root."""
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise MaintenanceError(
            "managed maintenance path must be a simple relative path"
        )
    current = root
    for index, part in enumerate(relative.parts):
        current /= part
        if _inspect_managed_part(
            current,
            relative,
            final=index == len(relative.parts) - 1,
            allow_missing=allow_missing,
        ):
            return current
    return current


def require_root(root: Path) -> Path:
    root = _require_real_directory_chain(root, label="maintenance root")
    common = _managed_path(root, Path("ci") / "lib" / "common.sh")
    try:
        common_details = common.lstat()
    except OSError as exc:
        raise MaintenanceError("canonical common.sh is unavailable") from exc
    if stat.S_ISLNK(common_details.st_mode) or not stat.S_ISREG(common_details.st_mode):
        raise MaintenanceError("canonical common.sh must be a regular non-symlink file")
    return root


def bounded(value: Any, fallback: str = "") -> str:
    if not isinstance(value, str):
        value = fallback
    return value.replace("\r", " ").replace("\n", " ")[:MAX_TEXT]


def safe_component_id(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    if not normalized or not COMPONENT_ID_RE.fullmatch(normalized):
        raise MaintenanceError(f"unsafe component identifier: {value!r}")
    return normalized


def version_tuple(value: str) -> tuple[int, ...]:
    if VERSION_RE.fullmatch(value) is None:
        raise MaintenanceError(f"unsupported stable version identity: {value!r}")
    return tuple(int(part) for part in value.removeprefix("v").split("."))


def compare_versions(left: str, right: str) -> int:
    left_parts = version_tuple(left)
    right_parts = version_tuple(right)
    width = max(len(left_parts), len(right_parts))
    left_parts += (0,) * (width - len(left_parts))
    right_parts += (0,) * (width - len(right_parts))
    return (left_parts > right_parts) - (left_parts < right_parts)


def same_policy_line(current: str, candidate: str, policy: str) -> bool:
    current_parts = version_tuple(current)
    candidate_parts = version_tuple(candidate)
    if policy == "patch_only":
        return current_parts[:2] == candidate_parts[:2]
    if policy == "same_minor":
        return current_parts[:2] == candidate_parts[:2]
    if policy == "same_major":
        return current_parts[:1] == candidate_parts[:1]
    if policy == "zero_same_minor":
        return (
            current_parts[:1] == (0,)
            and candidate_parts[:1] == (0,)
            and current_parts[:2] == candidate_parts[:2]
        ) or (current_parts[:1] != (0,) and current_parts[:1] == candidate_parts[:1])
    raise MaintenanceError(f"unsupported automatic update policy: {policy}")


def exact_https_github_repo(url: str) -> str:
    parsed = urlparse(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or parsed.port not in {None, 443}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise MaintenanceError(
            "component source must be an exact https://github.com owner/repository URL"
        )
    repository = parsed.path.strip("/").removesuffix(".git")
    if SIMPLE_REPOSITORY_RE.fullmatch(repository) is None:
        raise MaintenanceError("component source has an unsafe GitHub repository path")
    return repository


def _entry_value(entries: dict[str, Any], name: str) -> str:
    item = entries.get(name)
    if item is None:
        raise MaintenanceError(f"missing canonical variable {name}")
    value = getattr(item, "resolved", None)
    if not isinstance(value, str) or not value:
        raise MaintenanceError(f"canonical variable {name} is empty")
    return value


def _check_result(
    *,
    component_id: str,
    component_name: str,
    scope: str,
    status: str,
    message: str,
    variables: Iterable[str],
    current: str = "",
    latest_compatible: str = "",
    latest_upstream: str = "",
    source: str = "",
    updates: Iterable[dict[str, str]] = (),
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if component_id not in MANDATORY_GLOBAL_SCOPES and not COMPONENT_ID_RE.fullmatch(
        component_id
    ):
        raise MaintenanceError(f"unsafe component id {component_id!r}")
    canonical_variables = list(variables)
    if not canonical_variables or not all(
        isinstance(name, str) and re.fullmatch(r"[A-Z][A-Z0-9_]*", name)
        for name in canonical_variables
    ):
        raise MaintenanceError("component record has unsafe canonical variables")
    safe_updates: list[dict[str, str]] = []
    for update in updates:
        variable = update.get("variable")
        old = update.get("old")
        new = update.get("new")
        if (
            not isinstance(variable, str)
            or variable not in canonical_variables
            or not isinstance(old, str)
            or not isinstance(new, str)
            or not old
            or not new
            or len(old) > MAX_TEXT
            or len(new) > MAX_TEXT
        ):
            raise MaintenanceError("component contains an unsafe automatic update")
        safe_updates.append({"variable": variable, "old": old, "new": new})
    return {
        "component_id": component_id,
        "component_name": bounded(component_name),
        "scope": scope,
        "status": status,
        "message": bounded(message),
        "canonical_variables": canonical_variables,
        "current": bounded(current),
        "latest_compatible": bounded(latest_compatible),
        "latest_upstream": bounded(latest_upstream),
        "source": bounded(source),
        "updates": safe_updates,
        "details": details or {},
    }


def _review(
    *,
    component_id: str,
    component_name: str,
    review_kind: str,
    current_identity: dict[str, str],
    candidate_identity: dict[str, str],
    latest_compatible: str,
    latest_upstream: str,
    variables: Iterable[str],
    reason_code: str,
    reason: str,
    evidence_urls: Iterable[str],
    generated_views: Iterable[str],
    automatic_update_also_available: bool,
) -> dict[str, Any]:
    if not COMPONENT_ID_RE.fullmatch(component_id):
        raise MaintenanceError("review component id is unsafe")
    if review_kind not in REVIEW_KINDS:
        raise MaintenanceError(f"unsupported review kind: {review_kind}")
    target = (
        candidate_identity.get("series")
        or candidate_identity.get("version")
        or candidate_identity.get("tag")
    )
    if not isinstance(target, str) or not target:
        raise MaintenanceError("review candidate has no deterministic target identity")
    normalized_target = target.lower()
    if REVIEW_KEY_RE.fullmatch(normalized_target):
        target_slug = normalized_target
    else:
        target_slug = hashlib.sha256(target.encode("utf-8")).hexdigest()
    review_key = f"{component_id}:{review_kind}:{target_slug}"
    if REVIEW_KEY_RE.fullmatch(review_key) is None:
        raise MaintenanceError("review key is unsafe")
    safe_urls, variable_list, view_list = _review_lists(
        evidence_urls, variables, generated_views
    )
    return {
        "review_key": review_key,
        "component_id": component_id,
        "component_name": bounded(component_name),
        "review_kind": review_kind,
        "current_identity": dict(current_identity),
        "candidate_identity": dict(candidate_identity),
        "latest_compatible": bounded(latest_compatible),
        "latest_upstream": bounded(latest_upstream),
        "canonical_variables": variable_list,
        "reason_code": reason_code,
        "reason": bounded(reason),
        "evidence_urls": safe_urls,
        "generated_views": view_list,
        "automatic_update_also_available": bool(automatic_update_also_available),
    }


def _review_lists(
    evidence_urls: Iterable[str],
    variables: Iterable[str],
    generated_views: Iterable[str],
) -> tuple[list[str], list[str], list[str]]:
    safe_urls = []
    for url in evidence_urls:
        parsed = urlparse(url)
        if (
            not isinstance(url, str)
            or parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise MaintenanceError("review evidence URL is unsafe")
        safe_urls.append(url)
    if not safe_urls or len(safe_urls) > MAX_URLS:
        raise MaintenanceError("review needs a bounded official evidence URL set")
    variable_list = list(variables)
    if (
        not variable_list
        or len(set(variable_list)) != len(variable_list)
        or not all(
            isinstance(value, str) and CANONICAL_VARIABLE_RE.fullmatch(value)
            for value in variable_list
        )
    ):
        raise MaintenanceError(
            "review variables are not a unique canonical variable set"
        )
    view_list = list(generated_views)
    if not all(
        isinstance(value, str)
        and value
        and len(value) <= 160
        and not value.startswith(("/", "\\\\"))
        and ".." not in value
        and "\\" not in value
        for value in view_list
    ):
        raise MaintenanceError("review generated views are unsafe")
    return safe_urls, variable_list, view_list


def _latest_versions(records: Iterable[str]) -> list[str]:
    versions = sorted(
        {value for value in records if VERSION_RE.fullmatch(value)}, key=version_tuple
    )
    if not versions:
        raise MaintenanceError("official metadata contains no stable numeric releases")
    return versions


def _github_stable_releases(
    checker: Any, client: JsonClient, repository: str
) -> list[dict[str, Any]]:
    releases = client.get_json_list(
        f"https://api.github.com/repos/{repository}/releases?per_page=100"
    )
    selected: list[dict[str, Any]] = []
    for release in releases:
        if release.get("draft") is not False or release.get("prerelease") is not False:
            continue
        tag = release.get("tag_name")
        if not isinstance(tag, str) or VERSION_RE.fullmatch(tag) is None:
            continue
        selected.append(release)
    if not selected:
        raise checker.UpstreamUnknown(
            "official GitHub release page has no stable numeric release"
        )
    return selected


def _github_release_for_tag(
    releases: Iterable[dict[str, Any]], tag: str
) -> dict[str, Any]:
    matches = [release for release in releases if release.get("tag_name") == tag]
    if len(matches) != 1:
        raise MaintenanceError(
            "official GitHub release listing is missing or duplicates its selected tag"
        )
    return matches[0]


def _git_release_state(
    checker: Any,
    client: JsonClient,
    entries: dict[str, Any],
    *,
    source_variable: str,
    tag_variable: str,
    ref_variable: str,
    commit_variable: str,
    aliases: Iterable[str],
) -> tuple[str, str, str]:
    repository = exact_https_github_repo(_entry_value(entries, source_variable))
    current_tag = _entry_value(entries, tag_variable)
    current_ref = _entry_value(entries, ref_variable)
    current_commit = _entry_value(entries, commit_variable)
    if VERSION_RE.fullmatch(current_tag) is None or current_ref != current_tag:
        raise MaintenanceError(
            "release tag and Git ref must be one stable canonical identity"
        )
    if SHA40_RE.fullmatch(current_commit) is None:
        raise MaintenanceError(
            "approved release commit must be a lowercase full commit SHA"
        )
    for alias in aliases:
        if _entry_value(entries, alias) != current_tag:
            raise MaintenanceError(
                f"derived compatibility alias {alias} is not bound to the release tag"
            )
    if (
        checker.resolve_github_peeled_commit(client, repository, current_tag)
        != current_commit
    ):
        raise MaintenanceError(
            "configured approved commit does not match the canonical release tag"
        )
    return repository, current_tag, current_commit


def _git_release_versions(
    checker: Any,
    client: JsonClient,
    repository: str,
    current_tag: str,
    automatic_policy: str,
) -> tuple[str, str]:
    releases = _github_stable_releases(checker, client, repository)
    tags = _latest_versions(str(release["tag_name"]) for release in releases)
    latest_upstream = tags[-1]
    compatible = [
        tag for tag in tags if same_policy_line(current_tag, tag, automatic_policy)
    ]
    if not compatible:
        raise MaintenanceError("official release page lacks a compatible stable line")
    latest_compatible = compatible[-1]
    if compare_versions(current_tag, latest_upstream) > 0:
        raise MaintenanceError(
            "configured release tag is newer than the official release listing"
        )
    return latest_upstream, latest_compatible


def _git_release_updates(
    checker: Any,
    client: JsonClient,
    repository: str,
    current_tag: str,
    current_commit: str,
    latest_compatible: str,
    *,
    tag_variable: str,
    commit_variable: str,
) -> list[dict[str, str]]:
    if compare_versions(current_tag, latest_compatible) >= 0:
        return []
    candidate_commit = checker.resolve_github_peeled_commit(
        client, repository, latest_compatible
    )
    return [
        {"variable": tag_variable, "old": current_tag, "new": latest_compatible},
        {"variable": commit_variable, "old": current_commit, "new": candidate_commit},
    ]


def _git_release_reviews(
    checker: Any,
    client: JsonClient,
    repository: str,
    current_tag: str,
    current_commit: str,
    latest_upstream: str,
    latest_compatible: str,
    *,
    component_id: str,
    component_name: str,
    variables: Iterable[str],
    automatic_updates: list[dict[str, str]],
) -> list[dict[str, Any]]:
    if latest_upstream == latest_compatible:
        return []
    candidate_commit = checker.resolve_github_peeled_commit(
        client, repository, latest_upstream
    )
    current_series = ".".join(current_tag.removeprefix("v").split(".")[:2])
    candidate_series = ".".join(latest_upstream.removeprefix("v").split(".")[:2])
    return [
        _review(
            component_id=component_id,
            component_name=component_name,
            review_kind=(
                "minor_version_transition"
                if current_tag.removeprefix("v").startswith("0.")
                else "major_version_transition"
            ),
            current_identity={
                "tag": current_tag,
                "commit": current_commit,
                "series": current_series,
            },
            candidate_identity={
                "tag": latest_upstream,
                "commit": candidate_commit,
                "series": candidate_series,
            },
            latest_compatible=latest_compatible,
            latest_upstream=latest_upstream,
            variables=variables,
            reason_code="compatibility_line_transition",
            reason="The latest stable upstream release is outside the declared automatic compatibility line.",
            evidence_urls=[f"https://github.com/{repository}/releases/latest"],
            generated_views=GENERATED_VIEW_PATHS,
            automatic_update_also_available=bool(automatic_updates),
        )
    ]


def resolve_git_release_component(
    checker: Any,
    client: JsonClient,
    entries: dict[str, Any],
    *,
    component_id: str,
    component_name: str,
    source_variable: str,
    tag_variable: str,
    ref_variable: str,
    commit_variable: str,
    aliases: Iterable[str],
    automatic_policy: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    variables = [source_variable, tag_variable, ref_variable, commit_variable, *aliases]
    try:
        repository, current_tag, current_commit = _git_release_state(
            checker,
            client,
            entries,
            source_variable=source_variable,
            tag_variable=tag_variable,
            ref_variable=ref_variable,
            commit_variable=commit_variable,
            aliases=aliases,
        )
        latest_upstream, latest_compatible = _git_release_versions(
            checker, client, repository, current_tag, automatic_policy
        )
        source = f"https://github.com/{repository}/releases/latest"
        safe_updates = _git_release_updates(
            checker,
            client,
            repository,
            current_tag,
            current_commit,
            latest_compatible,
            tag_variable=tag_variable,
            commit_variable=commit_variable,
        )
        reviews = _git_release_reviews(
            checker,
            client,
            repository,
            current_tag,
            current_commit,
            latest_upstream,
            latest_compatible,
            component_id=component_id,
            component_name=component_name,
            variables=variables,
            automatic_updates=safe_updates,
        )
        status = "outdated" if safe_updates else "current"
        return (
            _check_result(
                component_id=component_id,
                component_name=component_name,
                scope=component_id,
                status=status,
                message=(
                    "A fully verified compatible release update is available."
                    if safe_updates
                    else "Canonical release tag and immutable commit are current."
                ),
                variables=variables,
                current=current_tag,
                latest_compatible=latest_compatible,
                latest_upstream=latest_upstream,
                source=source,
                updates=safe_updates,
                details={"update_policy": automatic_policy, "repository": repository},
            ),
            reviews,
        )
    except (
        MaintenanceError,
        checker.UpstreamError,
        checker.UpstreamBlocked,
        checker.UpstreamUnknown,
    ) as exc:
        return (
            _check_result(
                component_id=component_id,
                component_name=component_name,
                scope=component_id,
                status="blocked",
                message=str(exc),
                variables=variables,
            ),
            [],
        )


def _python_versions(payload: Iterable[dict[str, Any]]) -> list[str]:
    versions: list[str] = []
    for record in payload:
        name = record.get("name")
        if not isinstance(name, str):
            raise MaintenanceError("Python metadata release name is invalid")
        match = re.fullmatch(r"Python (\d+\.\d+\.\d+)", name)
        if match is None:
            continue
        if (
            record.get("is_published") is not True
            or record.get("pre_release") is not False
        ):
            continue
        versions.append(match.group(1))
    return _latest_versions(versions)


def resolve_python(
    entries: dict[str, Any], client: JsonClient
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    variables = ("CI_CANONICAL_PYTHON_VERSION",)
    try:
        current = _entry_value(entries, variables[0])
        if VERSION_RE.fullmatch(current) is None:
            raise MaintenanceError("canonical Python version is malformed")
        versions = _python_versions(client.get_json_list(PYTHON_RELEASES_URL))
        latest_upstream = versions[-1]
        compatible = [
            version
            for version in versions
            if same_policy_line(current, version, "patch_only")
        ]
        if not compatible:
            raise MaintenanceError("Python metadata has no compatible patch release")
        latest_compatible = compatible[-1]
        if compare_versions(current, latest_upstream) > 0:
            raise MaintenanceError(
                "canonical Python version is newer than official metadata"
            )
        updates = []
        if compare_versions(current, latest_compatible) < 0:
            updates.append(
                {"variable": variables[0], "old": current, "new": latest_compatible}
            )
        reviews: list[dict[str, Any]] = []
        if latest_upstream != latest_compatible:
            reviews.append(
                _review(
                    component_id="python",
                    component_name="CPython",
                    review_kind="minor_version_transition",
                    current_identity={
                        "version": current,
                        "series": ".".join(current.split(".")[:2]),
                    },
                    candidate_identity={
                        "version": latest_upstream,
                        "series": ".".join(latest_upstream.split(".")[:2]),
                    },
                    latest_compatible=latest_compatible,
                    latest_upstream=latest_upstream,
                    variables=variables,
                    reason_code="python_runtime_line_transition",
                    reason="A newer stable CPython minor or major line requires CI compatibility review.",
                    evidence_urls=[PYTHON_RELEASES_URL],
                    generated_views=(PYTHON_VERSION_PATH, CI_REQUIREMENTS_PATH),
                    automatic_update_also_available=bool(updates),
                )
            )
        return (
            _check_result(
                component_id="python",
                component_name="CPython",
                scope="python",
                status="outdated" if updates else "current",
                message="A compatible CPython patch update is available."
                if updates
                else "Canonical CPython release is current.",
                variables=variables,
                current=current,
                latest_compatible=latest_compatible,
                latest_upstream=latest_upstream,
                source=PYTHON_RELEASES_URL,
                updates=updates,
                details={"update_policy": "patch_only"},
            ),
            reviews,
        )
    except Exception as exc:
        return _check_result(
            component_id="python",
            component_name="CPython",
            scope="python",
            status="blocked",
            message=str(exc),
            variables=variables,
        ), []


def _pyyaml_release_records(
    payload: dict[str, Any], version: str
) -> list[dict[str, Any]]:
    releases = payload.get("releases")
    if not isinstance(releases, dict):
        raise MaintenanceError("PyPI PyYAML metadata has no releases map")
    records = releases.get(version)
    if not isinstance(records, list) or not all(
        isinstance(item, dict) for item in records
    ):
        raise MaintenanceError("PyPI PyYAML release files are missing or malformed")
    return records


def _pyyaml_wheel(
    records: Iterable[dict[str, Any]], version: str, python_version: str
) -> tuple[str, str, str]:
    abi = "cp" + "".join(python_version.split(".")[:2])
    prefix = f"pyyaml-{version}-{abi}-{abi}-"
    matches = [
        record
        for record in records
        if isinstance(record.get("filename"), str)
        and str(record["filename"]).startswith(prefix)
        and "manylinux" in str(record["filename"])
        and "x86_64" in str(record["filename"])
    ]
    if len(matches) != 1:
        raise MaintenanceError(
            "PyYAML metadata must contain exactly one canonical CPython Linux wheel"
        )
    filename = str(matches[0]["filename"])
    digests = matches[0].get("digests")
    digest = digests.get("sha256") if isinstance(digests, dict) else None
    if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
        raise MaintenanceError("PyYAML canonical wheel has no SHA-256 digest")
    platform = filename.removesuffix(".whl").rsplit("-", 1)[-1]
    if not platform or platform == filename:
        raise MaintenanceError("PyYAML canonical wheel has no platform tag")
    return filename, digest, platform


def resolve_pyyaml(
    entries: dict[str, Any], client: JsonClient
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    variables = [
        "CI_CANONICAL_PYYAML_VERSION",
        "CI_CANONICAL_PYYAML_ARTIFACT",
        "CI_CANONICAL_PYYAML_PLATFORM",
        "CI_CANONICAL_PYYAML_SHA256",
    ]
    try:
        current = _entry_value(entries, "CI_CANONICAL_PYYAML_VERSION")
        current_artifact = _entry_value(entries, "CI_CANONICAL_PYYAML_ARTIFACT")
        current_platform = _entry_value(entries, "CI_CANONICAL_PYYAML_PLATFORM")
        current_digest = _entry_value(entries, "CI_CANONICAL_PYYAML_SHA256")
        python_version = _entry_value(entries, "CI_CANONICAL_PYTHON_VERSION")
        if (
            VERSION_RE.fullmatch(current) is None
            or SHA256_RE.fullmatch(current_digest) is None
        ):
            raise MaintenanceError("canonical PyYAML version or digest is malformed")
        payload = client.get_json(PYPI_PYYAML_URL)
        releases = payload.get("releases")
        if not isinstance(releases, dict):
            raise MaintenanceError("PyPI PyYAML metadata has no releases map")
        versions = _latest_versions(str(version) for version in releases)
        latest_upstream = versions[-1]
        compatible = [
            version
            for version in versions
            if same_policy_line(current, version, "same_major")
        ]
        if not compatible:
            raise MaintenanceError("PyPI has no compatible PyYAML major line")
        latest_compatible = compatible[-1]
        current_wheel, official_current_digest, official_current_platform = (
            _pyyaml_wheel(
                _pyyaml_release_records(payload, current), current, python_version
            )
        )
        if current_digest != official_current_digest:
            raise MaintenanceError(
                "configured PyYAML digest differs from the official canonical wheel"
            )
        if (
            current_artifact != current_wheel
            or current_platform != official_current_platform
        ):
            raise MaintenanceError(
                "configured PyYAML wheel is not bound to the selected Python ABI/platform"
            )
        updates: list[dict[str, str]] = []
        if compare_versions(current, latest_compatible) < 0:
            candidate_wheel, candidate_digest, candidate_platform = _pyyaml_wheel(
                _pyyaml_release_records(payload, latest_compatible),
                latest_compatible,
                python_version,
            )
            updates.extend(
                (
                    {
                        "variable": "CI_CANONICAL_PYYAML_VERSION",
                        "old": current,
                        "new": latest_compatible,
                    },
                    {
                        "variable": "CI_CANONICAL_PYYAML_ARTIFACT",
                        "old": current_artifact,
                        "new": candidate_wheel,
                    },
                    {
                        "variable": "CI_CANONICAL_PYYAML_PLATFORM",
                        "old": current_platform,
                        "new": candidate_platform,
                    },
                    {
                        "variable": "CI_CANONICAL_PYYAML_SHA256",
                        "old": current_digest,
                        "new": candidate_digest,
                    },
                )
            )
        reviews: list[dict[str, Any]] = []
        if latest_upstream != latest_compatible:
            reviews.append(
                _review(
                    component_id="pyyaml",
                    component_name="PyYAML",
                    review_kind="major_version_transition",
                    current_identity={
                        "version": current,
                        "asset": current_wheel,
                        "platform": official_current_platform,
                    },
                    candidate_identity={"version": latest_upstream},
                    latest_compatible=latest_compatible,
                    latest_upstream=latest_upstream,
                    variables=variables,
                    reason_code="python_dependency_major_transition",
                    reason="A newer PyYAML major line requires interpreter and wheel compatibility review.",
                    evidence_urls=[PYPI_PYYAML_URL],
                    generated_views=(CI_REQUIREMENTS_PATH,),
                    automatic_update_also_available=bool(updates),
                )
            )
        return (
            _check_result(
                component_id="pyyaml",
                component_name="PyYAML",
                scope="pyyaml",
                status="outdated" if updates else "current",
                message="A compatible PyYAML wheel/digest update is available."
                if updates
                else "Canonical PyYAML wheel and digest are current.",
                variables=variables,
                current=current,
                latest_compatible=latest_compatible,
                latest_upstream=latest_upstream,
                source=PYPI_PYYAML_URL,
                updates=updates,
                details={"update_policy": "same_major", "wheel": current_wheel},
            ),
            reviews,
        )
    except Exception as exc:
        return _check_result(
            component_id="pyyaml",
            component_name="PyYAML",
            scope="pyyaml",
            status="blocked",
            message=str(exc),
            variables=variables,
        ), []


def resolve_node(
    entries: dict[str, Any], client: JsonClient
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    variables = ("CI_CANONICAL_NODE_VERSION",)
    try:
        current = _entry_value(entries, variables[0])
        if VERSION_RE.fullmatch(current) is None:
            raise MaintenanceError("canonical Node.js version is malformed")
        records = client.get_json_list(NODE_INDEX_URL)
        versions = _latest_versions(
            str(record.get("version", "")).removeprefix("v")
            for record in records
            if isinstance(record.get("version"), str)
            and "-" not in str(record["version"])
        )
        latest_upstream = versions[-1]
        latest_compatible = latest_upstream
        updates = []
        if compare_versions(current, latest_compatible) < 0:
            updates.append(
                {"variable": variables[0], "old": current, "new": latest_compatible}
            )
        return (
            _check_result(
                component_id="node",
                component_name=NODE_COMPONENT_NAME,
                scope="node",
                status="outdated" if updates else "current",
                message="A newer stable Node.js release is available."
                if updates
                else "Canonical Node.js release is current.",
                variables=variables,
                current=current,
                latest_compatible=latest_compatible,
                latest_upstream=latest_upstream,
                source=NODE_INDEX_URL,
                updates=updates,
                details={"update_policy": "latest_stable"},
            ),
            [],
        )
    except Exception as exc:
        return _check_result(
            component_id="node",
            component_name=NODE_COMPONENT_NAME,
            scope="node",
            status="blocked",
            message=str(exc),
            variables=variables,
        ), []


def _groups(
    entries: dict[str, Any],
    pattern: re.Pattern[str],
    required: set[str],
    family_prefix: str,
) -> dict[str, dict[str, str]]:
    groups: dict[str, dict[str, str]] = {}
    for name in entries:
        if not name.startswith(family_prefix):
            continue
        match = pattern.fullmatch(name)
        if match is None:
            raise MaintenanceError(
                f"canonical CI variable {name} is not a supported complete tuple field"
            )
        groups.setdefault(match.group("suffix"), {})[match.group("field")] = name
    if not groups:
        raise MaintenanceError("canonical CI group family is missing")
    for suffix, fields in groups.items():
        if set(fields) != required:
            raise MaintenanceError(
                f"canonical CI group {suffix} is incomplete: expected {sorted(required)}, found {sorted(fields)}"
            )
    return groups


def _tool_compatible_release(
    updater: Any, identity: Any, current: str
) -> dict[str, Any]:
    candidates: list[tuple[tuple[int, ...], dict[str, Any]]] = []
    for release in updater.release_page(identity):
        tag = updater.stable_release_tag_or_none(release)
        if tag is None:
            continue
        policy = "zero_same_minor" if version_tuple(current)[0] == 0 else "same_major"
        if same_policy_line(current, tag, policy):
            candidates.append((version_tuple(tag), release))
    if not candidates:
        raise MaintenanceError(
            "official CI-tool release page has no compatible release"
        )
    tag, release = max(candidates, key=lambda item: item[0])
    confirmed = updater.release_by_tag(identity, str(release["tag_name"]))
    if version_tuple(str(confirmed.get("tag_name", ""))) != tag:
        raise MaintenanceError(
            "official CI-tool release page and tag endpoint disagree"
        )
    return confirmed


def _workflow_lock_record(
    lock: dict[str, Any], family: str, name: str
) -> dict[str, Any]:
    records = lock.get(family)
    record = records.get(name) if isinstance(records, dict) else None
    if not isinstance(record, dict):
        raise MaintenanceError(
            f"canonical {family} group {name!r} is absent from the security-tool lock"
        )
    return record


def _tool_provider_identity(
    updater: Any, record: dict[str, Any], name: str, canonical_repository: str
) -> tuple[Any, bool]:
    """Bind a tool record's immutable provider to canonical source identity."""

    if SIMPLE_REPOSITORY_RE.fullmatch(canonical_repository) is None:
        raise MaintenanceError("canonical CI-tool repository is malformed")
    locked_repository = record.get("repository")
    if (
        not isinstance(locked_repository, str)
        or SIMPLE_REPOSITORY_RE.fullmatch(locked_repository) is None
    ):
        raise MaintenanceError(
            "canonical CI-tool lock has no immutable repository identity"
        )
    identity = updater.release_identity(record, name)
    if getattr(identity, "slug", None) != locked_repository:
        raise MaintenanceError(
            "canonical CI-tool lock repository disagrees with its release identity"
        )
    return identity, locked_repository != canonical_repository


def _candidate_entries_after_updates(
    checker: Any,
    common_lines: list[str],
    entries: dict[str, Any],
    updates: list[dict[str, str]],
) -> dict[str, Any]:
    """Render a prospective tuple through the canonical non-executing parser."""

    changes = []
    for update in updates:
        item = entries.get(update["variable"])
        if item is None or item.default != update["old"]:
            raise MaintenanceError(
                "prospective CI tuple is not bound to canonical common.sh"
            )
        changes.append(
            checker.UpdateChange(
                variable=update["variable"],
                line=item.line,
                old=item.default,
                new=update["new"],
            )
        )
    return checker.parse_common_lines(
        checker.render_updated_lines(common_lines, changes)
    )


def _resolve_action_pin(
    entries: dict[str, Any],
    updater: Any,
    lock: dict[str, Any],
    suffix: str,
    fields: dict[str, str],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    variables = [fields[field] for field in ("REPOSITORY", "VERSION", "COMMIT")]
    component_id = f"github-action-{safe_component_id(suffix)}"
    repository = _entry_value(entries, fields["REPOSITORY"])
    current = _entry_value(entries, fields["VERSION"])
    current_commit = _entry_value(entries, fields["COMMIT"])
    try:
        record = _workflow_lock_record(lock, "actions", repository)
        if (
            record.get("version") != current
            or record.get("immutable_commit") != current_commit
            or record.get("name") != repository
        ):
            raise MaintenanceError(
                "canonical Action tuple differs from the generated reviewed lock"
            )
        identity = updater.release_identity(record, repository, require_name_match=True)
        if updater.release_tag_commit(identity, current) != current_commit:
            raise MaintenanceError(
                "canonical Action commit differs from its official release tag"
            )
        resolution = updater.action_release_resolution(record, repository)
        if resolution == updater.ACTION_RELEASE_RESOLUTION_SAME_MAJOR:
            latest_release = updater.latest_stable_action_release(identity)
            latest_source = updater.release_page_url(identity)
            latest_evidence_url = f"https://github.com/{repository}/releases"
        elif resolution == updater.ACTION_RELEASE_RESOLUTION_LATEST:
            latest_release = updater.latest_release(identity)
            latest_source = f"https://github.com/{repository}/releases/latest"
            latest_evidence_url = latest_source
        else:
            raise MaintenanceError(
                "canonical Action has an unsupported release resolution"
            )
        latest_upstream = updater.stable_release_tag(
            latest_release, "latest Action release"
        )
        latest_compatible = updater.stable_release_tag(
            updater.latest_same_major_action_release(identity, current),
            "compatible Action release",
        )
        if compare_versions(current, latest_upstream) > 0:
            raise MaintenanceError(
                "canonical Action version is newer than official latest release"
            )
        updates: list[dict[str, str]] = []
        if compare_versions(current, latest_compatible) < 0:
            updates = [
                {
                    "variable": fields["VERSION"],
                    "old": current,
                    "new": latest_compatible,
                },
                {
                    "variable": fields["COMMIT"],
                    "old": current_commit,
                    "new": updater.release_tag_commit(identity, latest_compatible),
                },
            ]
        reviews = []
        if latest_upstream != latest_compatible:
            reviews.append(
                _review(
                    component_id=component_id,
                    component_name=repository,
                    review_kind="major_version_transition",
                    current_identity={
                        "version": current,
                        "commit": current_commit,
                        "series": current.removeprefix("v").split(".")[0],
                    },
                    candidate_identity={
                        "version": latest_upstream,
                        "series": latest_upstream.removeprefix("v").split(".")[0],
                    },
                    latest_compatible=latest_compatible,
                    latest_upstream=latest_upstream,
                    variables=variables,
                    reason_code="github_action_major_transition",
                    reason="A newer GitHub Action major requires manual compatibility and immutable-commit review.",
                    evidence_urls=[latest_evidence_url],
                    generated_views=(SECURITY_TOOLS_LOCK_PATH,),
                    automatic_update_also_available=bool(updates),
                )
            )
        result = _check_result(
            component_id=component_id,
            component_name=repository,
            scope="github-actions",
            status="outdated" if updates else "current",
            message="A compatible immutable Action update is available."
            if updates
            else "Canonical Action tuple is current.",
            variables=variables,
            current=current,
            latest_compatible=latest_compatible,
            latest_upstream=latest_upstream,
            source=latest_source,
            updates=updates,
            details={"update_policy": "same_major"},
        )
        return result, reviews
    except Exception as exc:
        return _check_result(
            component_id=component_id,
            component_name=repository,
            scope="github-actions",
            status="blocked",
            message=str(exc),
            variables=variables,
            current=current,
        ), []


def _tool_provider_review(
    component_id: str,
    repository: str,
    current: str,
    record: dict[str, Any],
    variables: list[str],
) -> dict[str, Any]:
    return _review(
        component_id=component_id,
        component_name=repository,
        review_kind="provider_transition",
        current_identity={
            "repository": str(record["repository"]),
            "version": str(record.get("version", "")),
        },
        candidate_identity={"repository": repository, "version": current},
        latest_compatible=current,
        latest_upstream=current,
        variables=variables,
        reason_code="ci_tool_provider_transition",
        reason="The canonical CI-tool repository differs from the lock-reviewed provider and cannot be updated automatically.",
        evidence_urls=(str(record.get("upstream_release", "https://github.com")),),
        generated_views=(SECURITY_TOOLS_LOCK_PATH,),
        automatic_update_also_available=False,
    )


def _tool_candidate_updates(
    checker: Any,
    common_lines: list[str],
    entries: dict[str, Any],
    fields: dict[str, str],
    current: str,
    current_commit: str,
    current_asset: str,
    current_digest: str,
    latest_compatible: str,
    candidate_asset: str,
    candidate_digest: str,
    candidate_commit: str,
) -> tuple[list[dict[str, str]], bool]:
    if compare_versions(current, latest_compatible) >= 0:
        return [], True
    proposed = [
        {"variable": fields["VERSION"], "old": current, "new": latest_compatible},
        {"variable": fields["COMMIT"], "old": current_commit, "new": candidate_commit},
        {"variable": fields["SHA256"], "old": current_digest, "new": candidate_digest},
    ]
    if entries[fields["ASSET_NAME"]].default == current_asset:
        proposed.insert(
            2,
            {
                "variable": fields["ASSET_NAME"],
                "old": current_asset,
                "new": candidate_asset,
            },
        )
    candidate_entries = _candidate_entries_after_updates(
        checker, common_lines, entries, proposed
    )
    matches = all(
        _entry_value(candidate_entries, fields[name]) == expected
        for name, expected in (
            ("VERSION", latest_compatible),
            ("COMMIT", candidate_commit),
            ("ASSET_NAME", candidate_asset),
            ("SHA256", candidate_digest),
        )
    )
    return (proposed if matches else [], matches)


def _tool_pin_release_data(
    updater: Any,
    identity: Any,
    record: dict[str, Any],
    current: str,
    current_commit: str,
    current_asset: str,
    current_digest: str,
) -> tuple[str, str, str, str, str]:
    updater.validate_tool_baseline_provenance(record, identity, record["name"])
    if updater.release_tag_commit(identity, current) != current_commit:
        raise MaintenanceError(
            "canonical CI-tool commit differs from its official release tag"
        )
    current_release = updater.release_by_tag(identity, current)
    current_tag, official_asset, official_digest = updater.selected_release_asset(
        identity, current_release, record, record["name"]
    )
    if (
        current_tag != current
        or official_asset != current_asset
        or official_digest != current_digest
    ):
        raise MaintenanceError(
            "canonical CI-tool asset/digest differs from its official release tuple"
        )
    latest_upstream = updater.stable_release_tag(
        updater.latest_release(identity), "latest CI-tool release"
    )
    compatible_release = _tool_compatible_release(updater, identity, current)
    latest_compatible, candidate_asset, candidate_digest = (
        updater.selected_release_asset(
            identity, compatible_release, record, record["name"]
        )
    )
    if compare_versions(current, latest_upstream) > 0:
        raise MaintenanceError(
            "canonical CI-tool version is newer than official latest release"
        )
    if compare_versions(current, latest_compatible) < 0:
        candidate_commit = updater.release_tag_commit(identity, latest_compatible)
    else:
        candidate_commit = current_commit
    return (
        latest_upstream,
        latest_compatible,
        candidate_asset,
        candidate_digest,
        candidate_commit,
    )


def _tool_pin_transition_reviews(
    component_id: str,
    repository: str,
    current: str,
    current_asset: str,
    latest_compatible: str,
    latest_upstream: str,
    variables: list[str],
    updates: list[dict[str, str]],
) -> list[dict[str, Any]]:
    if latest_upstream == latest_compatible:
        return []
    if version_tuple(current)[0] == 0:
        series_parts = 2
        review_kind = "minor_version_transition"
    else:
        series_parts = 1
        review_kind = "major_version_transition"
    return [
        _review(
            component_id=component_id,
            component_name=repository,
            review_kind=review_kind,
            current_identity={
                "version": current,
                "asset": current_asset,
                "series": ".".join(current.removeprefix("v").split(".")[:series_parts]),
            },
            candidate_identity={"version": latest_upstream},
            latest_compatible=latest_compatible,
            latest_upstream=latest_upstream,
            variables=variables,
            reason_code="ci_tool_compatibility_transition",
            reason="The latest CI-tool release is outside the reviewed automatic compatibility line.",
            evidence_urls=[f"https://github.com/{repository}/releases/latest"],
            generated_views=(SECURITY_TOOLS_LOCK_PATH,),
            automatic_update_also_available=bool(updates),
        )
    ]


def _tool_pin_status(
    updates: list[dict[str, str]],
    reviews: list[dict[str, Any]],
    current: str,
    latest_compatible: str,
) -> tuple[str, str]:
    if updates:
        return "outdated", "A compatible verified CI-tool update is available."
    if reviews and compare_versions(current, latest_compatible) < 0:
        return (
            "review_required",
            "The canonical asset expression does not produce the official candidate artifact; manual artifact-layout review is required.",
        )
    return "current", "Canonical CI-tool tuple is current."


class _ToolPinContext:
    def __init__(
        self,
        component_id: str,
        variables: list[str],
        repository: str,
        current: str,
        current_commit: str,
        current_asset: str,
        current_digest: str,
    ) -> None:
        self.component_id = component_id
        self.variables = variables
        self.repository = repository
        self.current = current
        self.current_commit = current_commit
        self.current_asset = current_asset
        self.current_digest = current_digest


def _resolve_tool_pin(
    entries: dict[str, Any],
    updater: Any,
    lock: dict[str, Any],
    suffix: str,
    fields: dict[str, str],
    *,
    checker: Any,
    common_lines: list[str],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    variables = [
        fields[field]
        for field in ("REPOSITORY", "VERSION", "COMMIT", "ASSET_NAME", "SHA256")
    ]
    component_id = f"ci-tool-{safe_component_id(suffix)}"
    repository = _entry_value(entries, fields["REPOSITORY"])
    current = _entry_value(entries, fields["VERSION"])
    current_commit = _entry_value(entries, fields["COMMIT"])
    current_asset = _entry_value(entries, fields["ASSET_NAME"])
    current_digest = _entry_value(entries, fields["SHA256"])
    try:
        return _resolve_tool_pin_checked(
            entries,
            updater,
            lock,
            suffix,
            fields,
            checker=checker,
            common_lines=common_lines,
            context=_ToolPinContext(
                component_id=component_id,
                variables=variables,
                repository=repository,
                current=current,
                current_commit=current_commit,
                current_asset=current_asset,
                current_digest=current_digest,
            ),
        )
    except Exception as exc:
        return _check_result(
            component_id=component_id,
            component_name=repository,
            scope="ci-security-tools",
            status="blocked",
            message=str(exc),
            variables=variables,
            current=current,
        ), []


def _resolve_tool_pin_checked(
    entries: dict[str, Any],
    updater: Any,
    lock: dict[str, Any],
    suffix: str,
    fields: dict[str, str],
    *,
    checker: Any,
    common_lines: list[str],
    context: _ToolPinContext,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    component_id = context.component_id
    variables = context.variables
    repository = context.repository
    current = context.current
    current_commit = context.current_commit
    current_asset = context.current_asset
    current_digest = context.current_digest
    lock_name = safe_component_id(suffix)
    record = _workflow_lock_record(lock, "tools", lock_name)
    if record.get("name") != lock_name:
        raise MaintenanceError(
            "canonical CI tool group has no matching stable lock name"
        )
    identity, provider_transition = _tool_provider_identity(
        updater, record, str(record["name"]), repository
    )
    if provider_transition:
        review = _tool_provider_review(
            component_id, repository, current, record, variables
        )
        result = _check_result(
            component_id=component_id,
            component_name=repository,
            scope="ci-security-tools",
            status="review_required",
            message="Canonical CI-tool provider transition requires manual review before any release lookup or update.",
            variables=variables,
            current=current,
            latest_compatible=current,
            latest_upstream=current,
            source=str(record.get("upstream_release", "")),
            details={
                "provider_transition": True,
                "locked_repository": record["repository"],
            },
        )
        return result, [review]
    if (
        record.get("version") != current
        or record.get("immutable_commit") != current_commit
        or record.get("asset") != current_asset
        or record.get("sha256") != current_digest
    ):
        raise MaintenanceError(
            "canonical CI-tool tuple differs from the generated reviewed lock"
        )
    (
        latest_upstream,
        latest_compatible,
        candidate_asset,
        candidate_digest,
        candidate_commit,
    ) = _tool_pin_release_data(
        updater,
        identity,
        record,
        current,
        current_commit,
        current_asset,
        current_digest,
    )
    updates, matches = _tool_candidate_updates(
        checker,
        common_lines,
        entries,
        fields,
        current,
        current_commit,
        current_asset,
        current_digest,
        latest_compatible,
        candidate_asset,
        candidate_digest,
        candidate_commit,
    )
    reviews: list[dict[str, Any]] = []
    if compare_versions(current, latest_compatible) < 0 and not matches:
        reviews.append(
            _review(
                component_id=component_id,
                component_name=repository,
                review_kind="artifact_layout_transition",
                current_identity={"version": current, "asset": current_asset},
                candidate_identity={
                    "version": latest_compatible,
                    "asset": candidate_asset,
                },
                latest_compatible=latest_compatible,
                latest_upstream=latest_upstream,
                variables=variables,
                reason_code="ci_tool_asset_expression_mismatch",
                reason="The existing canonical asset expression cannot be proven to select the official compatible artifact.",
                evidence_urls=[
                    f"https://github.com/{repository}/releases/tag/{latest_compatible}"
                ],
                generated_views=(SECURITY_TOOLS_LOCK_PATH,),
                automatic_update_also_available=False,
            )
        )
    reviews.extend(
        _tool_pin_transition_reviews(
            component_id,
            repository,
            current,
            current_asset,
            latest_compatible,
            latest_upstream,
            variables,
            updates,
        )
    )
    status, message = _tool_pin_status(updates, reviews, current, latest_compatible)
    result = _check_result(
        component_id=component_id,
        component_name=repository,
        scope="ci-security-tools",
        status=status,
        message=message,
        variables=variables,
        current=current,
        latest_compatible=latest_compatible,
        latest_upstream=latest_upstream,
        source=f"https://github.com/{repository}/releases/latest",
        updates=updates,
        details={
            "update_policy": "zero_same_minor"
            if version_tuple(current)[0] == 0
            else "same_major"
        },
    )
    return result, reviews


def _resolve_tool_pin_legacy(
    entries: dict[str, Any],
    updater: Any,
    lock: dict[str, Any],
    suffix: str,
    fields: dict[str, str],
    *,
    checker: Any,
    common_lines: list[str],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Retained only as an implementation marker during migration."""
    del entries, updater, lock, suffix, fields, checker, common_lines
    raise AssertionError("legacy resolver is not callable")


"""LEGACY_RESOLVER_BODY_REMOVED

    try:
        lock_name = safe_component_id(suffix)
        record = _workflow_lock_record(lock, "tools", lock_name)
        if record.get("name") != lock_name:
            raise MaintenanceError(
                "canonical CI tool group has no matching stable lock name"
            )
        identity, provider_transition = _tool_provider_identity(
            updater, record, str(record["name"]), repository
        )
        if provider_transition:
            review = _tool_provider_review(
                component_id, repository, current, record, variables
            )
            result = _check_result(
                component_id=component_id,
                component_name=repository,
                scope="ci-security-tools",
                status="review_required",
                message="Canonical CI-tool provider transition requires manual review before any release lookup or update.",
                variables=variables,
                current=current,
                latest_compatible=current,
                latest_upstream=current,
                source=str(record.get("upstream_release", "")),
                details={
                    "provider_transition": True,
                    "locked_repository": record["repository"],
                },
            )
            return result, [review]
        if (
            record.get("version") != current
            or record.get("immutable_commit") != current_commit
            or record.get("asset") != current_asset
            or record.get("sha256") != current_digest
        ):
            raise MaintenanceError(
                "canonical CI-tool tuple differs from the generated reviewed lock"
            )
        updater.validate_tool_baseline_provenance(record, identity, record["name"])
        if updater.release_tag_commit(identity, current) != current_commit:
            raise MaintenanceError(
                "canonical CI-tool commit differs from its official release tag"
            )
        current_release = updater.release_by_tag(identity, current)
        current_tag, official_asset, official_digest = updater.selected_release_asset(
            identity, current_release, record, record["name"]
        )
        if (
            current_tag != current
            or official_asset != current_asset
            or official_digest != current_digest
        ):
            raise MaintenanceError(
                "canonical CI-tool asset/digest differs from its official release tuple"
            )
        latest_upstream = updater.stable_release_tag(
            updater.latest_release(identity), "latest CI-tool release"
        )
        compatible_release = _tool_compatible_release(updater, identity, current)
        latest_compatible, candidate_asset, candidate_digest = (
            updater.selected_release_asset(
                identity, compatible_release, record, record["name"]
            )
        )
        if compare_versions(current, latest_upstream) > 0:
            raise MaintenanceError(
                "canonical CI-tool version is newer than official latest release"
            )
        candidate_commit = (
            updater.release_tag_commit(identity, latest_compatible)
            if compare_versions(current, latest_compatible) < 0
            else current_commit
        )
        updates, matches = _tool_candidate_updates(
            checker,
            common_lines,
            entries,
            fields,
            current,
            current_commit,
            current_asset,
            current_digest,
            latest_compatible,
            candidate_asset,
            candidate_digest,
            candidate_commit,
        )
        reviews: list[dict[str, Any]] = []
        if compare_versions(current, latest_compatible) < 0 and not matches:
            reviews.append(
                _review(
                    component_id=component_id,
                    component_name=repository,
                    review_kind="artifact_layout_transition",
                    current_identity={"version": current, "asset": current_asset},
                    candidate_identity={
                        "version": latest_compatible,
                        "asset": candidate_asset,
                    },
                    latest_compatible=latest_compatible,
                    latest_upstream=latest_upstream,
                    variables=variables,
                    reason_code="ci_tool_asset_expression_mismatch",
                    reason="The existing canonical asset expression cannot be proven to select the official compatible artifact.",
                    evidence_urls=[
                        f"https://github.com/{repository}/releases/tag/{latest_compatible}"
                    ],
                    generated_views=(SECURITY_TOOLS_LOCK_PATH,),
                    automatic_update_also_available=False,
                )
            )
        if latest_upstream != latest_compatible:
            series_parts = 2 if version_tuple(current)[0] == 0 else 1
            reviews.append(
                _review(
                    component_id=component_id,
                    component_name=repository,
                    review_kind="minor_version_transition"
                    if version_tuple(current)[0] == 0
                    else "major_version_transition",
                    current_identity={
                        "version": current,
                        "asset": current_asset,
                        "series": ".".join(
                            current.removeprefix("v").split(".")[:series_parts]
                        ),
                    },
                    candidate_identity={"version": latest_upstream},
                    latest_compatible=latest_compatible,
                    latest_upstream=latest_upstream,
                    variables=variables,
                    reason_code="ci_tool_compatibility_transition",
                    reason="The latest CI-tool release is outside the reviewed automatic compatibility line.",
                    evidence_urls=[f"https://github.com/{repository}/releases/latest"],
                    generated_views=(SECURITY_TOOLS_LOCK_PATH,),
                    automatic_update_also_available=bool(updates),
                )
            )
        status = (
            "outdated"
            if updates
            else (
                "review_required"
                if reviews and compare_versions(current, latest_compatible) < 0
                else "current"
            )
        )
        message = (
            "A compatible verified CI-tool update is available."
            if updates
            else (
                "The canonical asset expression does not produce the official candidate artifact; manual artifact-layout review is required."
                if status == "review_required"
                else "Canonical CI-tool tuple is current."
            )
        )
        result = _check_result(
            component_id=component_id,
            component_name=repository,
            scope="ci-security-tools",
            status=status,
            message=message,
            variables=variables,
            current=current,
            latest_compatible=latest_compatible,
            latest_upstream=latest_upstream,
            source=f"https://github.com/{repository}/releases/latest",
            updates=updates,
            details={
                "update_policy": "zero_same_minor"
                if version_tuple(current)[0] == 0
                else "same_major"
            },
        )
        return result, reviews
    except Exception as exc:
        return _check_result(
            component_id=component_id,
            component_name=repository,
            scope="ci-security-tools",
            status="blocked",
            message=str(exc),
            variables=variables,
            current=current,
        ), []
"""


def resolve_workflow_pins(
    root: Path,
    entries: dict[str, Any],
    updater: Any,
    *,
    checker: Any,
    common_lines: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Resolve dynamically discovered Actions and CI tools through their lock helper."""
    try:
        _path, lock, _digest = updater.load_lock(root)
        updater.require_canonical_action_lock(root, lock)
        actions = _groups(
            entries, ACTION_GROUP_RE, {"REPOSITORY", "VERSION", "COMMIT"}, "CI_ACTION_"
        )
        tools = _groups(
            entries,
            TOOL_GROUP_RE,
            {"REPOSITORY", "VERSION", "COMMIT", "ASSET_NAME", "SHA256"},
            "CI_SECURITY_TOOL_",
        )
    except Exception as exc:
        return [
            _check_result(
                component_id="github-actions",
                component_name="Canonical GitHub Actions",
                scope="github-actions",
                status="blocked",
                message=str(exc),
                variables=("CI_ACTION_CHECKOUT_REPOSITORY",),
            )
        ], []
    results: list[dict[str, Any]] = []
    reviews: list[dict[str, Any]] = []
    for suffix, fields in sorted(actions.items()):
        result, component_reviews = _resolve_action_pin(
            entries, updater, lock, suffix, fields
        )
        results.append(result)
        reviews.extend(component_reviews)
    for suffix, fields in sorted(tools.items()):
        result, component_reviews = _resolve_tool_pin(
            entries,
            updater,
            lock,
            suffix,
            fields,
            checker=checker,
            common_lines=common_lines,
        )
        results.append(result)
        reviews.extend(component_reviews)
    return results, reviews


def resolve_osv_compatibility(entries: dict[str, Any]) -> dict[str, Any]:
    variables = ("CI_OSV_LEGACY_BASE_SHA", "CI_OSV_LEGACY_BASE_VERSION")
    try:
        sha = _entry_value(entries, variables[0])
        version = _entry_value(entries, variables[1])
        if SHA40_RE.fullmatch(sha) is None or VERSION_RE.fullmatch(version) is None:
            raise MaintenanceError("OSV compatibility baseline is malformed")
        return _check_result(
            component_id="ci-osv-compatibility",
            component_name="OSV compatibility baseline",
            scope="ci-security-tools",
            status="current",
            message="Explicit historical OSV compatibility baseline is structurally valid.",
            variables=variables,
            current=version,
            latest_compatible=version,
            latest_upstream=version,
            details={"update_policy": "manual_only", "historical_exception": True},
        )
    except MaintenanceError as exc:
        return _check_result(
            component_id="ci-osv-compatibility",
            component_name="OSV compatibility baseline",
            scope="ci-security-tools",
            status="blocked",
            message=str(exc),
            variables=variables,
        )


def resolve_canonical_ci_coverage(entries: dict[str, Any]) -> dict[str, Any]:
    """Reject a new manual CI canonical pin until it has an active resolver."""

    supported = {
        "CI_CANONICAL_PYTHON_VERSION",
        "CI_CANONICAL_PYYAML_VERSION",
        "CI_CANONICAL_PYYAML_ARTIFACT",
        "CI_CANONICAL_PYYAML_PLATFORM",
        "CI_CANONICAL_PYYAML_SHA256",
        "CI_CANONICAL_NODE_VERSION",
    }
    discovered = sorted(name for name in entries if name.startswith("CI_CANONICAL_"))
    unknown = sorted(set(discovered).difference(supported))
    variables = discovered or ["CI_CANONICAL_PYTHON_VERSION"]
    if unknown:
        return _check_result(
            component_id="canonical-ci-coverage",
            component_name=CANONICAL_CI_COVERAGE_NAME,
            scope="ci-security-tools",
            status="blocked",
            message=(
                "Canonical CI pins have no active maintenance descriptor: "
                + ", ".join(unknown)
            ),
            variables=variables,
        )
    missing = sorted(supported.difference(discovered))
    if missing:
        return _check_result(
            component_id="canonical-ci-coverage",
            component_name=CANONICAL_CI_COVERAGE_NAME,
            scope="ci-security-tools",
            status="blocked",
            message="Required canonical CI pins are missing: " + ", ".join(missing),
            variables=variables,
        )
    return _check_result(
        component_id="canonical-ci-coverage",
        component_name=CANONICAL_CI_COVERAGE_NAME,
        scope="ci-security-tools",
        status="current",
        message="Every CI_CANONICAL_* pin is covered by an active maintenance resolver.",
        variables=variables,
    )


def _runtime_review(definition: Any, result: Any) -> dict[str, Any] | None:
    candidate = result.latest_upstream or result.latest
    if result.status != "review_required" or not candidate:
        return None
    return _review(
        component_id=safe_component_id(definition.name),
        component_name=definition.name,
        review_kind="release_commit_provenance",
        current_identity={"version": result.current},
        candidate_identity={"version": candidate},
        latest_compatible=result.latest_compatible or candidate,
        latest_upstream=candidate,
        variables=definition.variables,
        reason_code="reviewed_runtime_provenance",
        reason=result.message,
        evidence_urls=[result.source] if result.source else ["https://github.com"],
        generated_views=GENERATED_VIEW_PATHS,
        automatic_update_also_available=False,
    )


def _resolve_runtime_component(
    checker: Any,
    entries: dict[str, Any],
    client: Any,
    definition: Any,
    component_id: str,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    try:
        raw = checker.resolve_component_definition(definition, entries, client)
        result = checker.decorate_component_result(definition, raw, entries)
        updates = [
            {"variable": update.variable, "old": update.old, "new": update.new}
            for update in result.updates
        ]
        record = _check_result(
            component_id=component_id,
            component_name=definition.name,
            scope="runtime-source",
            status=result.status,
            message=result.message,
            variables=definition.variables,
            current=result.current,
            latest_compatible=result.latest_compatible or result.latest,
            latest_upstream=result.latest_upstream or result.latest,
            source=result.source,
            updates=updates,
            details={
                "resolver": definition.resolver,
                "update_policy": definition.update_policy,
            },
        )
        return record, _runtime_review(definition, result)
    except (
        checker.UpstreamError,
        checker.UpstreamBlocked,
        checker.UpstreamUnknown,
        MaintenanceError,
    ) as exc:
        return _check_result(
            component_id=component_id,
            component_name=definition.name,
            scope="runtime-source",
            status="blocked",
            message=str(exc),
            variables=definition.variables,
        ), None


def resolve_runtime_components(
    checker: Any,
    entries: dict[str, Any],
    client: Any,
    selected_runtime: tuple[str, ...],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    global_definition_ids = {"go-ftw", "albedo", "canonical-ci-pins"}
    runtime_definitions = [
        definition
        for definition in checker.COMPONENT_DEFINITIONS
        if definition.update_policy != "not_applicable"
        and safe_component_id(definition.name) not in global_definition_ids
    ]
    runtime_by_id = {
        safe_component_id(definition.name): definition
        for definition in runtime_definitions
    }
    if len(runtime_by_id) != len(runtime_definitions):
        raise MaintenanceError("runtime/source descriptor ids are not unique")
    selected = tuple(safe_component_id(value) for value in selected_runtime) or tuple(
        runtime_by_id
    )
    if len(set(selected)) != len(selected):
        raise MaintenanceError(
            "--component contains a duplicate runtime/source component"
        )
    unknown = sorted(set(selected).difference(runtime_by_id))
    if unknown:
        raise MaintenanceError(
            "--component may select only runtime/source components: "
            + ", ".join(unknown)
        )
    results: list[dict[str, Any]] = []
    reviews: list[dict[str, Any]] = []
    for component_id in selected:
        result, review = _resolve_runtime_component(
            checker, entries, client, runtime_by_id[component_id], component_id
        )
        results.append(result)
        if review is not None:
            reviews.append(review)
    return results, reviews, list(selected)


def generated_view_status(root: Path, *, write: bool = False) -> list[dict[str, str]]:
    mode = "--write" if write else "--check"
    commands = (
        (
            "canonical-python-pins",
            [
                sys.executable,
                str(root / "ci/tools/sync-canonical-python-pins.py"),
                mode,
                "--root",
                str(root),
            ],
        ),
        (
            "canonical-workflow-pins",
            [
                sys.executable,
                str(root / "ci/tools/sync-canonical-workflow-pins.py"),
                mode,
                "--root",
                str(root),
            ],
        ),
        (
            "runtime-components",
            [
                sys.executable,
                str(root / "ci/tools/sync-runtime-components.py"),
                mode,
                "--common-sh",
                str(root / COMMON_SH_PATH),
                "--manifest",
                str(root / RUNTIME_MANIFEST_PATH),
                "--lock",
                str(root / RUNTIME_LOCK_PATH),
            ],
        ),
        (
            "crs-contract-views",
            [
                sys.executable,
                str(root / "ci/tools/sync-crs-contract-views.py"),
                mode,
                "--root",
                str(root),
            ],
        ),
    )
    statuses = []
    for name, command in commands:
        result = subprocess.run(
            command, cwd=root, check=False, capture_output=True, text=True
        )
        statuses.append(
            {
                "name": name,
                "status": "current" if result.returncode == 0 else "blocked",
                "message": bounded(result.stdout + result.stderr, "generator failed"),
            }
        )
    return statuses


def _unique_updates(results: Iterable[dict[str, Any]]) -> list[dict[str, str]]:
    updates: dict[str, dict[str, str]] = {}
    for result in results:
        if result["status"] != "outdated":
            continue
        for update in result["updates"]:
            existing = updates.get(update["variable"])
            if existing is not None and existing != update:
                raise MaintenanceError(
                    "two components propose conflicting canonical updates"
                )
            updates[update["variable"]] = update
    return [updates[name] for name in sorted(updates)]


def _candidate_common_sha256(
    checker: Any, lines: list[str], updates: list[dict[str, str]]
) -> str:
    change_type = checker.UpdateChange
    changes = []
    entries = checker.parse_common_lines(lines)
    for update in updates:
        item = entries.get(update["variable"])
        if item is None or item.default != update["old"]:
            raise MaintenanceError(
                "automatic update is not bound to canonical common.sh"
            )
        changes.append(
            change_type(
                variable=update["variable"],
                line=item.line,
                old=item.default,
                new=update["new"],
            )
        )
    rendered = checker.render_updated_lines(lines, changes)
    return hashlib.sha256(("\n".join(rendered) + "\n").encode("utf-8")).hexdigest()


def _maintenance_outcome(
    results: list[dict[str, Any]],
    updates: list[dict[str, str]],
    reviews: list[dict[str, Any]],
) -> str:
    fatal = any(
        result["status"] in {"unknown", "blocked", "error"} for result in results
    )
    if fatal:
        return "fatal"
    if updates and reviews:
        return "safe_updates_with_manual_review"
    if updates:
        return "safe_updates"
    return "manual_review_only" if reviews else "no_updates"


def _global_inventory_complete(results: list[dict[str, Any]]) -> bool:
    scopes = {
        result["scope"]
        for result in results
        if result["scope"] in MANDATORY_GLOBAL_SCOPES
    }
    return set(MANDATORY_GLOBAL_SCOPES).issubset(scopes) and not any(
        result["scope"] in MANDATORY_GLOBAL_SCOPES
        and result["status"] in {"unknown", "blocked", "error"}
        for result in results
    )


def _canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _git_output(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise MaintenanceError("could not inspect the maintenance candidate Git state")
    return result.stdout


def _require_clean_worktree(root: Path) -> None:
    if _git_output(root, "status", "--porcelain=v1", "--untracked-files=all").strip():
        raise MaintenanceError(
            "safe maintenance application requires a clean candidate worktree"
        )


def _snapshot_allowed_views(root: Path) -> dict[str, tuple[bytes, int]]:
    snapshots: dict[str, tuple[bytes, int]] = {}
    for relative in ALLOWED_AUTOMATIC_PATHS:
        path = _managed_path(root, Path(relative), allow_missing=True)
        try:
            details = path.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise MaintenanceError(
                f"cannot snapshot generated view {relative}"
            ) from exc
        if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode):
            raise MaintenanceError(
                f"generated view {relative} must be a regular non-symlink file"
            )
        snapshots[relative] = (path.read_bytes(), details.st_mode & 0o777)
    return snapshots


def _atomic_restore(path: Path, data: bytes, mode: int) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if descriptor != -1:
            os.close(descriptor)
        if temporary.exists():
            temporary.unlink()


def _rollback_allowed_views(
    root: Path, snapshots: dict[str, tuple[bytes, int]]
) -> None:
    changed = set(_git_output(root, "diff", "--name-only").splitlines())
    unexpected = changed.difference(ALLOWED_AUTOMATIC_PATHS)
    if unexpected:
        raise MaintenanceError(
            "automatic maintenance transaction touched an unsafe path: "
            + ", ".join(sorted(unexpected))
        )
    for relative in changed:
        snapshot = snapshots.get(relative)
        if snapshot is None:
            raise MaintenanceError(
                f"automatic maintenance transaction created an unsnapshotted view: {relative}"
            )
        _atomic_restore(root / relative, snapshot[0], snapshot[1])


def build_plan(
    root: Path,
    *,
    components: tuple[str, ...] = (),
    timeout: float = 20.0,
    checker: Any | None = None,
    client: Any | None = None,
    workflow_updater: Any | None = None,
    check_generated_views: bool = True,
) -> dict[str, Any]:
    """Build the shared global-plus-runtime maintenance plan without writes."""

    root = require_root(root)
    checker = checker or load_runtime_checker(root)
    lines, entries = checker.parse_common(root / COMMON_SH_PATH)
    client = client or checker.HttpClient(timeout=timeout)
    workflow_updater = workflow_updater or load_workflow_tool_updater(root)
    results: list[dict[str, Any]] = []
    reviews: list[dict[str, Any]] = []
    for args in (
        {
            "component_id": "go-ftw",
            "component_name": "Go-FTW",
            "source_variable": "GO_FTW_SOURCE_URL",
            "tag_variable": "GO_FTW_RELEASE_TAG",
            "ref_variable": "GO_FTW_GIT_REF",
            "commit_variable": "GO_FTW_APPROVED_COMMIT",
            "aliases": ("GO_FTW_PROMPT_EXPECTED_LATEST",),
            "automatic_policy": "same_major",
        },
        {
            "component_id": "albedo",
            "component_name": "Albedo",
            "source_variable": "ALBEDO_SOURCE_URL",
            "tag_variable": "ALBEDO_RELEASE_TAG",
            "ref_variable": "ALBEDO_GIT_REF",
            "commit_variable": "ALBEDO_APPROVED_COMMIT",
            "aliases": ("ALBEDO_PROMPT_EXPECTED_LATEST",),
            "automatic_policy": "zero_same_minor",
        },
    ):
        result, component_reviews = resolve_git_release_component(
            checker, client, entries, **args
        )
        results.append(result)
        reviews.extend(component_reviews)
    for resolver in (resolve_python, resolve_pyyaml, resolve_node):
        result, component_reviews = resolver(entries, client)
        results.append(result)
        reviews.extend(component_reviews)
    workflow_results, workflow_reviews = resolve_workflow_pins(
        root,
        entries,
        workflow_updater,
        checker=checker,
        common_lines=lines,
    )
    results.extend(workflow_results)
    reviews.extend(workflow_reviews)
    results.append(resolve_osv_compatibility(entries))
    results.append(resolve_canonical_ci_coverage(entries))
    runtime_results, runtime_reviews, _ = resolve_runtime_components(
        checker, entries, client, components
    )
    results.extend(runtime_results)
    reviews.extend(runtime_reviews)
    views = generated_view_status(root) if check_generated_views else []
    if any(view["status"] != "current" for view in views):
        results.append(
            _check_result(
                component_id="generated-views",
                component_name="Generated maintenance views",
                scope="ci-security-tools",
                status="blocked",
                message="One or more generated canonical views drifted from common.sh.",
                variables=("CI_CANONICAL_PYTHON_VERSION",),
            )
        )
    automatic_updates = _unique_updates(results)
    manual = sorted(reviews, key=lambda item: item["review_key"])
    outcome = _maintenance_outcome(results, automatic_updates, manual)
    checked_components = [result["component_id"] for result in results]
    if len(set(checked_components)) != len(checked_components):
        raise MaintenanceError("maintenance plan has duplicate component ids")
    generated_views = sorted(ALLOWED_AUTOMATIC_PATHS.difference({COMMON_SH_PATH}))
    global_inventory_complete = _global_inventory_complete(results)
    source_bytes = (root / COMMON_SH_PATH).read_bytes()
    plan: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "maintenance_outcome": outcome,
        "scope": {
            "mode": "component" if components else "full",
            "checked_components": checked_components,
        },
        "safe_updates": automatic_updates,
        "manual_reviews": manual,
        "checked_components": checked_components,
        "component_results": results,
        "generated_views": generated_views,
        "generated_view_status": views,
        "global_inventory_complete": global_inventory_complete,
        "source_common_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "candidate_common_sha256": _candidate_common_sha256(
            checker, lines, automatic_updates
        ),
    }
    plan["plan_sha256"] = hashlib.sha256(_canonical_json(plan)).hexdigest()
    return plan


def validate_plan_digest(plan: dict[str, Any], expected: str | None = None) -> str:
    observed = plan.get("plan_sha256")
    copied = dict(plan)
    copied.pop("plan_sha256", None)
    calculated = hashlib.sha256(_canonical_json(copied)).hexdigest()
    if not isinstance(observed, str) or observed != calculated:
        raise MaintenanceError("maintenance plan SHA-256 is invalid")
    if expected is not None and expected != observed:
        raise MaintenanceError(
            "maintenance plan SHA-256 does not match the caller-bound plan"
        )
    return observed


def render_plan_markdown(plan: dict[str, Any]) -> str:
    validate_plan_digest(plan)
    lines = [
        "# Canonical maintenance plan",
        "",
        f"- Outcome: `{plan['maintenance_outcome']}`",
        f"- Scope: `{plan['scope']['mode']}`",
        f"- Plan SHA-256: `{plan['plan_sha256']}`",
        "",
        "## Checked components",
        "",
        "| Scope | Component | Current | Compatible | Upstream | Status |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for result in plan.get("component_results", []):
        lines.append(
            "| {scope} | {name} | `{current}` | `{compatible}` | `{upstream}` | `{status}` |".format(
                scope=bounded(result["scope"]),
                name=bounded(result["component_name"]),
                current=bounded(result["current"]),
                compatible=bounded(result["latest_compatible"]),
                upstream=bounded(result["latest_upstream"]),
                status=bounded(result["status"]),
            )
        )
    lines.extend(["", "## Automatic updates", ""])
    if plan["safe_updates"]:
        for update in plan["safe_updates"]:
            lines.append(
                f"- `{update['variable']}`: `{update['old']}` → `{update['new']}`"
            )
    else:
        lines.append("- None")
    lines.extend(["", "## Manual reviews", ""])
    if plan["manual_reviews"]:
        for review in plan["manual_reviews"]:
            lines.append(f"- `{review['review_key']}` — {review['reason']}")
    else:
        lines.append("- None")
    lines.extend(["", "## Generated views", ""])
    for status in plan.get("generated_view_status", []):
        lines.append(f"- `{status['name']}`: `{status['status']}`")
    return "\n".join(lines) + "\n"


def apply_safe_updates(
    root: Path, plan: dict[str, Any], *, expected_plan_sha256: str
) -> list[str]:
    """Apply only a caller-bound safe plan and regenerate exactly allowlisted views."""

    root = require_root(root)
    validate_plan_digest(plan, expected_plan_sha256)
    if plan.get("maintenance_outcome") not in {
        "safe_updates",
        "safe_updates_with_manual_review",
    }:
        raise MaintenanceError("only a safe-update maintenance plan may be applied")
    _require_clean_worktree(root)
    snapshots = _snapshot_allowed_views(root)
    try:
        checker = load_runtime_checker(root)
        common = root / COMMON_SH_PATH
        if hashlib.sha256(common.read_bytes()).hexdigest() != plan.get(
            "source_common_sha256"
        ):
            raise MaintenanceError(
                "canonical source digest no longer matches the bound maintenance plan"
            )
        lines, entries = checker.parse_common(common)
        changes = []
        for update in plan["safe_updates"]:
            item = entries.get(update["variable"])
            if item is None or item.default != update["old"]:
                raise MaintenanceError(
                    "canonical source no longer matches the bound maintenance plan"
                )
            changes.append(
                checker.UpdateChange(
                    variable=update["variable"],
                    line=item.line,
                    old=item.default,
                    new=update["new"],
                )
            )
        checker.apply_updates(common, lines, changes)
        if hashlib.sha256(common.read_bytes()).hexdigest() != plan.get(
            "candidate_common_sha256"
        ):
            raise MaintenanceError(
                "updated canonical source does not match the bound maintenance candidate"
            )
        statuses = generated_view_status(root, write=True)
        if any(item["status"] != "current" for item in statuses):
            raise MaintenanceError(
                "generated-view synchronization failed after common.sh update"
            )
        statuses = generated_view_status(root, write=False)
        if any(item["status"] != "current" for item in statuses):
            raise MaintenanceError(
                "generated views did not settle after synchronization"
            )
        changed = sorted(
            path
            for path in _git_output(root, "diff", "--name-only").splitlines()
            if path
        )
        unknown = [path for path in changed if path not in ALLOWED_AUTOMATIC_PATHS]
        if unknown:
            raise MaintenanceError(
                "automatic maintenance candidate escapes its path policy: "
                + ", ".join(unknown)
            )
        return changed
    except Exception as original_error:
        try:
            _rollback_allowed_views(root, snapshots)
        except Exception as rollback_error:
            raise MaintenanceError(
                "automatic maintenance transaction failed and rollback could not complete: "
                + str(rollback_error)
            ) from original_error
        raise
