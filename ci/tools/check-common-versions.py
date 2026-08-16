#!/usr/bin/env python3
"""Check and safely update upstream version pins from ci/lib/common.sh."""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from http.client import HTTPException
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast
from urllib.error import HTTPError
from urllib.parse import ParseResult, quote, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

DEFAULT_BUILD_ROOT = Path("/src/ModSecurity-conector-build")
SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_COMMON_SH = SCRIPT_DIR.parent / "lib" / "common.sh"
NO_SAFE_UPDATER_MESSAGE = "No safe updater implemented for this source yet."
SHA256_SUFFIX = ".sha256"
ARCHIVE_BZ2_EXTENSION = ".tar.bz2"
APACHE_DOWNLOAD_HOST = "downloads.apache.org"
HAPROXY_WEB_HOST = "www.haproxy.org"
HAPROXY_WEB_HOST_RE = re.escape(HAPROXY_WEB_HOST)
MODSECURITY_V3_COMPONENT = "ModSecurity v3"
GITHUB_WEB_HOST = "github.com"
GITHUB_API_HOST = "api.github.com"
GITHUB_API_ORIGIN = f"https://{GITHUB_API_HOST}"
JSON_MIME_TYPE = "application/json"
TAR_GZ_EXTENSION = ".tar.gz"
CANONICAL_CI_PINS_LABEL = "Canonical CI pins"
VERSION_PAIR_RE = re.compile(r"\d+\.\d+", re.ASCII)
GITHUB_WEB_ORIGIN = f"https://{GITHUB_WEB_HOST}"
ENVOY_COMPONENT = "Envoy"
TRAEFIK_COMPONENT = "Traefik"
GITHUB_RELEASES_SOURCE_COMPONENTS = frozenset({ENVOY_COMPONENT, TRAEFIK_COMPONENT})
NGINX_COMPONENT = "NGINX"
NGINX_GITHUB_REPOSITORY_VARIABLE = "NGINX_GITHUB_REPO"
NGINX_SOURCE_GIT_REF_VARIABLE = "NGINX_SOURCE_GIT_REF"
NGINX_RELEASE_TAG_VARIABLE = "NGINX_RELEASE_TAG"
AUTOMATIC_UPDATE_POLICY = "automatic"
GITHUB_RELEASE_MANIFEST_RESOLVER = "github_release_manifest"
GITHUB_RELEASE_HOSTS = (GITHUB_WEB_HOST, GITHUB_API_HOST)
GITHUB_STABLE_RELEASE_POLICY = (
    "GitHub non-draft, non-prerelease stable v<version> release"
)
VERSION_TAG_PATTERN = r"^v\d+(?:\.\d+)+$"
APACHE_APR_SOURCE_PATH_PREFIX = "/apr/"
NO_HIDDEN_SERIES_RESTRICTION = "latest stable release; no hidden series restriction"
APACHE_LISTING_RESOLVER = "apache_listing"
APACHE_STABLE_RELEASE_POLICY = "official Apache numeric release listing"
SAME_MAJOR_MINOR_COMPATIBILITY_POLICY = (
    "same major/minor series documented in this descriptor"
)
OFFICIAL_ASSET_SHA256_FILE_STRATEGY = "official_asset_sha256_file"
SHA256_CAPTURE_RE = r"([a-f0-9]{64})"

# The inventory deliberately limits itself to provenance inputs rather than
# incidental runtime paths such as ``*_SOURCE_ROOT``.  A new matching variable
# has to be registered below or explicitly classified as not applicable.
RELEVANT_PROVENANCE_VARIABLE_RE = re.compile(
    r"(?:_VERSION|_RELEASE_TAG|_GIT_REF|_APPROVED_COMMIT|_SOURCE_URL|"
    r"_DOWNLOAD_URL|_RELEASE_ASSET_NAME|_SHA256|_SOURCE_SHA256|"
    r"_SHA256_URL|_CHECKSUM(?:_[A-Z0-9_]+)?|_REPO_URL|_GITHUB_REPO|"
    r"_GIT_URL|_RELEASE_INDEX_URL|_LATEST_URL|_PROMPT_EXPECTED_LATEST|"
    r"_ARCHIVE_NAME|_ASSET_NAME|_ARTIFACT|_ARTIFACT_PLATFORM|_PLATFORM|_SOURCE_MODE|"
    r"_SERIES|_RELEASE_ROOT_URL|_SERIES_BASE_URL|"
    r"_REPOSITORY|_COMMIT|_SHA"
    r")$"
)
TRACKED_NAME_RE = RELEVANT_PROVENANCE_VARIABLE_RE
PARAM_EXPANSION_RE = re.compile(r"\$\{((?!\d)\w+):?[-=]([^{}]*)\}", re.ASCII)
BRACED_VAR_RE = re.compile(r"\$\{((?!\d)\w+)\}", re.ASCII)
PLAIN_VAR_RE = re.compile(r"\$((?!\d)\w+)", re.ASCII)
PARAM_REMOVE_PREFIX_RE = re.compile(r"\$\{([A-Z][A-Z0-9_]*)#([^{}]*)\}")
SHA256_RE = re.compile(r"\b([A-Fa-f0-9]{64})\b")
SHA256_VALUE_RE = re.compile(r"^[a-f0-9]{64}$")
GIT_COMMIT_SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SAFE_REF_RE = re.compile(r"^(?!.*\.\.)(?!/)(?!.*//)[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
SAFE_VERSION_RE = re.compile(r"^\d+(?:\.\d+)+$")
RELEASE_TAG_RE = re.compile(r"^v\d+\.\d+\.\d+$")
MODSECURITY_V3_RELEASE_TAG_RE = re.compile(r"^v3\.\d+\.\d+$")
SAFE_HTTPS_HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$")
SAFE_HTTPS_PATH_RE = re.compile(r"^/[A-Za-z0-9._~/-]*$")
URL_PATH_DYNAMIC_VALUE_RE = re.compile(
    r"\$(?:\{[A-Za-z_](?a:\w)*\}|[A-Za-z_](?a:\w)*)|\d+\.\d+(?:\.\d+)*"
)
NGINX_RELEASE_ASSET_RE = re.compile(
    rf"^nginx-([A-Za-z0-9][A-Za-z0-9._-]*){re.escape(TAR_GZ_EXTENSION)}$"
)
SAFE_ASSET_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
GITHUB_RELEASE_URL_RE = re.compile(
    r"^https://github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/releases/download/"
    r"([^/]+)/([^/?#]+)$"
)

# These are checked-in generated projections of common.sh.  Keep this list
# exact: a broad directory exemption would allow an active consumer to hide a
# second source of truth.  Historical reports, audit exports, and tests are
# not scanned at all and therefore need no exemption here.
GENERATED_CANONICAL_VIEW_PATHS = frozenset(
    {
        ".python-version",
        "requirements-ci.lock",
        "ci/provisioning/runtime-components.manifest.json",
        "ci/provisioning/runtime-component-lock.json",
        "ci/tooling/security-tools.lock.yml",
        "docs/reference/variables.md",
        "docs/reference/variables.de.md",
        *{
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
                "update-workflow-tools.yml",
            )
        },
    }
)
# These exact files validate provenance metadata; they do not acquire or
# execute the pinned component.  They remain visible in code review but are
# not active consumers for this check.
NON_CONSUMER_METADATA_PATHS = frozenset(
    {
        "ci/checks/catalog/five_connectors_with_crs_no_mrts.py",
        "ci/checks/security/check-github-actions-workflows.py",
    }
)
ACTIVE_CONSUMER_ROOTS = ("ci", "src", ".github")
ACTIVE_CONSUMER_SUFFIXES = frozenset(
    {".c", ".cc", ".cpp", ".h", ".hpp", ".json", ".mk", ".py", ".sh", ".yml", ".yaml"}
)
CANONICAL_PIN_VARIABLE_RE = re.compile(
    r"(?:_VERSION|_RELEASE_TAG|_GIT_REF|_COMMIT|_SHA256|_SOURCE_SHA256|"
    r"_SOURCE_URL|_DOWNLOAD_URL|_REPO_URL|_GITHUB_REPO|_GIT_URL|"
    r"_ARCHIVE_NAME|_ASSET_NAME|_ARTIFACT_PLATFORM|_PLATFORM|_SOURCE_MODE|"
    r"_SERIES|_RELEASE_ROOT_URL|_SERIES_BASE_URL|"
    r"_REPOSITORY)$"
)
GENERIC_CANONICAL_PIN_VALUES = frozenset({"", "master", "main", "github-release"})
OPTIONAL_EMPTY_VARIABLES = {
    "APACHE_BIN",
    "APACHECTL_BIN",
    "APXS_BIN",
    "MODSECURITY_APACHE_REPO_URL",
    "MODSECURITY_APACHE_GIT_URL",
    "MODSECURITY_NGINX_REPO_URL",
    "MODSECURITY_NGINX_GIT_URL",
    "MODSECURITY_PKG_CONFIG",
    "MODSECURITY_LIB_DIR",
    "MODSECURITY_INCLUDE_DIR",
    "MODSECURITY_RULE_PREAMBLE_FILE",
    "NGINX_BIN",
    "PCRE2_SHA256",
    "PCRE2_SHA256_URL",
}
APPROVED_LITERAL_VARIABLES = {
    "APR_UTIL_PINNED_VERSION",
    "APR_UTIL_PINNED_SOURCE_URL",
    "APR_UTIL_PINNED_SHA256",
    "APR_UTIL_PINNED_SHA256_URL",
    "CRS_APPROVED_REPO_URL",
    "CRS_APPROVED_COMMIT",
    "CRS_RELEASE_TAG",
    "MODSECURITY_V3_APPROVED_REPO_URL",
    "MODSECURITY_V3_APPROVED_COMMIT",
    "MODSECURITY_V3_RELEASE_TAG",
    # APR-util deliberately rejects environment overrides, so its authoritative
    # version/digest are literals and its URLs are safe, parser-visible
    # derivations.  Keeping the former PINNED names accepted preserves a clear
    # error for legacy fixtures without reintroducing dual source-of-truth data.
    "APR_UTIL_VERSION",
    "APR_UTIL_SOURCE_URL",
    "APR_UTIL_SHA256",
    "APR_UTIL_SHA256_URL",
    # Traefik likewise has one fail-closed reviewed archive tuple.  Its
    # version/digest are literals; URLs and archive identity are parser-visible
    # derivations so an automated candidate update cannot create a second
    # handwritten pin source.
    "TRAEFIK_VERSION",
    "TRAEFIK_SOURCE_URL",
    "TRAEFIK_INSTALL_DOCS_URL",
    "TRAEFIK_ARTIFACT_PLATFORM",
    "TRAEFIK_ARCHIVE_NAME",
    "TRAEFIK_DOWNLOAD_URL",
    "TRAEFIK_SHA256",
    "TRAEFIK_SHA256_URL",
}

STATUS_CURRENT = "current"
STATUS_OUTDATED = "outdated"
STATUS_UNKNOWN = "unknown"
STATUS_NOT_APPLICABLE = "not_applicable"
STATUS_BLOCKED = "blocked"
STATUS_ERROR = "error"
STATUS_REVIEW_REQUIRED = "review_required"

MAINTENANCE_OUTCOME_NO_UPDATES = "no_updates"
MAINTENANCE_OUTCOME_MANUAL_REVIEW_ONLY = "manual_review_only"
MAINTENANCE_OUTCOME_SAFE_UPDATES = "safe_updates"
MAINTENANCE_OUTCOME_SAFE_UPDATES_WITH_MANUAL_REVIEW = "safe_updates_with_manual_review"
MAINTENANCE_OUTCOME_FATAL = "fatal"
MAINTENANCE_OUTCOMES = frozenset(
    {
        MAINTENANCE_OUTCOME_NO_UPDATES,
        MAINTENANCE_OUTCOME_MANUAL_REVIEW_ONLY,
        MAINTENANCE_OUTCOME_SAFE_UPDATES,
        MAINTENANCE_OUTCOME_SAFE_UPDATES_WITH_MANUAL_REVIEW,
        MAINTENANCE_OUTCOME_FATAL,
    }
)
FATAL_STATUSES = frozenset({STATUS_UNKNOWN, STATUS_BLOCKED, STATUS_ERROR})
CRS_COMPONENT = "OWASP Core Rule Set"
# Resolver descriptors use a neutral marker.  The reviewed repository identity
# is read from the canonical common.sh URL at resolution time; keeping the
# marker here prevents a second handwritten upstream identity.
CANONICAL_REPOSITORY_MARKER = "canonical/repository"
CRS_APPROVED_REPOSITORY = CANONICAL_REPOSITORY_MARKER
MODSECURITY_V3_APPROVED_REPOSITORY = CANONICAL_REPOSITORY_MARKER
# Digest of the fixed upstream repository identity.  Keep the readable URL in
# common.sh as the canonical authority; this immutable trust anchor prevents a
# candidate from redirecting the ModSecurity v3 provenance lookup without
# reintroducing a copied active URL pin in this consumer.
MODSECURITY_V3_APPROVED_REPOSITORY_SHA256 = (
    "3aa7b655ad2eec501e97cbc4a76fa820dd20cb4c95696ca41d0b1280ab8fa0fd"
)
CI_CANONICAL_PIN_VARIABLES = (
    "CI_CANONICAL_PYTHON_VERSION",
    "CI_CANONICAL_PYYAML_VERSION",
    "CI_CANONICAL_PYYAML_SHA256",
    "CI_CANONICAL_PYYAML_WHEEL",
    "CI_CANONICAL_PYYAML_PLATFORM",
    "CI_CANONICAL_NODE_VERSION",
    "CI_OSV_LEGACY_BASE_SHA",
    "CI_OSV_LEGACY_BASE_VERSION",
    *tuple(
        f"CI_ACTION_{suffix}_{field}"
        for suffix in (
            "CHECKOUT",
            "SETUP_PYTHON",
            "SETUP_NODE",
            "UPLOAD_ARTIFACT",
            "GITHUB_SCRIPT",
            "CREATE_GITHUB_APP_TOKEN",
            "CREATE_PULL_REQUEST",
            "CODEQL",
            "DEPENDENCY_REVIEW",
        )
        for field in ("REPOSITORY", "VERSION", "COMMIT")
    ),
    *tuple(
        f"CI_SECURITY_TOOL_{suffix}_{field}"
        for suffix in (
            "SCORECARD",
            "OSV_SCANNER",
            "ACTIONLINT",
            "SHELLCHECK",
            "ZIZMOR",
            "GITLEAKS",
            "RUFF",
            "PYRIGHT",
        )
        for field in ("REPOSITORY", "VERSION", "COMMIT", "ASSET_NAME", "SHA256")
    ),
)
# The legacy tuple above is retained for compatibility with older imports, but
# its generated projections are intentionally replaced by the artifact name
# used by the live common.sh contract.  Action and security-tool groups are
# extended from parsed prefixes below rather than relying on this snapshot.
CI_CANONICAL_PIN_VARIABLES = tuple(
    name for name in CI_CANONICAL_PIN_VARIABLES if name != "CI_CANONICAL_PYYAML_WHEEL"
)
CI_CANONICAL_REQUIRED_FIELDS = {
    "PYTHON": frozenset({"VERSION"}),
    "PYYAML": frozenset({"VERSION", "SHA256", "ARTIFACT", "PLATFORM"}),
    "NODE": frozenset({"VERSION"}),
}
CI_ACTION_REQUIRED_FIELDS = frozenset({"REPOSITORY", "VERSION", "COMMIT"})
CI_SECURITY_TOOL_REQUIRED_FIELDS = frozenset(
    {"REPOSITORY", "VERSION", "COMMIT", "ASSET_NAME", "SHA256"}
)


def canonical_ci_group_inventory(
    entries: dict[str, "VariableEntry"] | None = None,
) -> tuple[tuple[str, ...], list[str]]:
    """Discover CI pin groups from parsed names and validate their shape."""

    if entries is None:
        return (), []
    names = {name for name in entries if name.startswith("CI_")}
    groups: dict[tuple[str, str], set[str]] = {}
    errors: list[str] = []
    for name in sorted(names):
        group_info = _canonical_group_prefix(name)
        if group_info is None:
            continue
        prefix, suffix = group_info
        tail = name[len(prefix) :]
        fields = set(CI_ACTION_REQUIRED_FIELDS)
        fields.update(CI_SECURITY_TOOL_REQUIRED_FIELDS)
        fields.update(
            field
            for group_fields in CI_CANONICAL_REQUIRED_FIELDS.values()
            for field in group_fields
        )
        field = next(
            (
                candidate
                for candidate in sorted(fields, key=len, reverse=True)
                if tail.endswith("_" + candidate)
            ),
            None,
        )
        if field is None:
            errors.append(f"unsupported {suffix} variable {name}")
            continue
        group = tail[: -(len(field) + 1)]
        if not group:
            errors.append(f"unsupported {suffix} variable {name}")
            continue
        groups.setdefault((suffix, group), set()).add(field)

    expected = {
        ("canonical", group): set(fields)
        for group, fields in CI_CANONICAL_REQUIRED_FIELDS.items()
    }
    for key, fields in sorted(groups.items()):
        required = _canonical_required_fields(key, expected)
        if required is None:
            errors.append(f"unsupported canonical CI group {key[1]}")
            continue
        unsupported = sorted(fields - required)
        missing = sorted(required - fields)
        if unsupported:
            errors.append(
                f"unsupported fields in {key[0]} group {key[1]}: "
                + ", ".join(unsupported)
            )
        if missing:
            errors.append(
                f"incomplete {key[0]} group {key[1]}; missing: " + ", ".join(missing)
            )

    expected_names = set(CI_CANONICAL_PIN_VARIABLES)
    expected_names.update(name for name in entries if name.startswith("CI_ACTION_"))
    expected_names.update(
        name for name in entries if name.startswith("CI_SECURITY_TOOL_")
    )
    return tuple(sorted(expected_names)), errors


def _canonical_group_prefix(name: str) -> tuple[str, str] | None:
    for prefix, label in (
        ("CI_ACTION_", "action"),
        ("CI_SECURITY_TOOL_", "security tool"),
        ("CI_CANONICAL_", "canonical"),
    ):
        if name.startswith(prefix):
            return prefix, label
    return None


def _canonical_required_fields(
    key: tuple[str, str], expected: dict[tuple[str, str], set[str]]
) -> set[str] | None:
    if key[0] == "action":
        return set(CI_ACTION_REQUIRED_FIELDS)
    if key[0] == "security tool":
        return set(CI_SECURITY_TOOL_REQUIRED_FIELDS)
    return expected.get(key)


MANUAL_REVIEW_VARIABLES = {
    CRS_COMPONENT: (
        "CRS_APPROVED_REPO_URL",
        "CRS_RELEASE_TAG",
        "CRS_APPROVED_COMMIT",
        "CRS_REPO_URL",
        "CRS_GIT_REF",
    ),
    MODSECURITY_V3_COMPONENT: (
        "MODSECURITY_V3_APPROVED_REPO_URL",
        "MODSECURITY_V3_RELEASE_TAG",
        "MODSECURITY_V3_APPROVED_COMMIT",
        "MODSECURITY_REPO_URL",
        "MODSECURITY_GIT_REF",
        "MODSECURITY_V3_GIT_URL",
        "MODSECURITY_V3_GIT_REF",
    ),
}


@dataclasses.dataclass(frozen=True)
class ComponentDefinition:
    """One auditable external-component provenance contract.

    Resolver adapters are intentionally small; all component identity,
    expected variables, trusted upstream, stable-selection rule, compatibility
    policy, checksum strategy, and atomic update group live in this table.
    """

    name: str
    resolver: str
    variables: tuple[str, ...]
    atomic_group: tuple[str, ...]
    update_policy: str
    stable_policy: str
    compatibility_policy: str
    authorized_hosts: tuple[str, ...] = ()
    github_repository: str | None = None
    version_variable: str | None = None
    release_tag_variable: str | None = None
    source_url_variable: str | None = None
    download_url_variable: str | None = None
    asset_variable: str | None = None
    sha256_variable: str | None = None
    sha256_url_variable: str | None = None
    git_commit_variable: str | None = None
    asset_template: str | None = None
    asset_platform_variable: str | None = None
    checksum_asset_template: str | None = None
    checksum_strategy: str = ""
    tag_prefix: str = ""
    tag_pattern: str = ""
    filename_prefix: str = ""
    archive_extension: str = ""
    source_path_prefix: str = ""
    alias_bindings: tuple[tuple[str, str], ...] = ()
    not_applicable_reason: str = ""


# This registry is the source of truth for the common.sh provenance inventory.
# ``not_applicable`` records are intentional: they document metadata consumed
# only as local hints or repo-local connector defaults, so a future consumer
# cannot silently turn them into an updater input.
COMPONENT_DEFINITIONS: tuple[ComponentDefinition, ...] = (
    ComponentDefinition(
        name=ENVOY_COMPONENT,
        resolver=GITHUB_RELEASE_MANIFEST_RESOLVER,
        variables=(
            "ENVOY_VERSION",
            "ENVOY_SOURCE_URL",
            "ENVOY_ARTIFACT_PLATFORM",
            "ENVOY_ASSET_NAME",
            "ENVOY_DOWNLOAD_URL",
            "ENVOY_SHA256",
            "ENVOY_SHA256_URL",
        ),
        atomic_group=(
            "ENVOY_VERSION",
            "ENVOY_SOURCE_URL",
            "ENVOY_DOWNLOAD_URL",
            "ENVOY_SHA256",
            "ENVOY_SHA256_URL",
        ),
        update_policy=AUTOMATIC_UPDATE_POLICY,
        stable_policy=GITHUB_STABLE_RELEASE_POLICY,
        compatibility_policy=NO_HIDDEN_SERIES_RESTRICTION,
        authorized_hosts=GITHUB_RELEASE_HOSTS,
        github_repository="envoyproxy/envoy",
        version_variable="ENVOY_VERSION",
        source_url_variable="ENVOY_SOURCE_URL",
        download_url_variable="ENVOY_DOWNLOAD_URL",
        sha256_variable="ENVOY_SHA256",
        sha256_url_variable="ENVOY_SHA256_URL",
        asset_template="envoy-{version}-{platform}",
        asset_platform_variable="ENVOY_ARTIFACT_PLATFORM",
        checksum_asset_template="checksums.txt.asc",
        checksum_strategy="github_release_asset_digest_or_official_manifest",
        tag_prefix="v",
        tag_pattern=VERSION_TAG_PATTERN,
    ),
    ComponentDefinition(
        name=TRAEFIK_COMPONENT,
        resolver=GITHUB_RELEASE_MANIFEST_RESOLVER,
        variables=(
            "TRAEFIK_VERSION",
            "TRAEFIK_SOURCE_URL",
            "TRAEFIK_ARTIFACT_PLATFORM",
            "TRAEFIK_ARCHIVE_NAME",
            "TRAEFIK_DOWNLOAD_URL",
            "TRAEFIK_SHA256",
            "TRAEFIK_SHA256_URL",
        ),
        atomic_group=(
            "TRAEFIK_VERSION",
            "TRAEFIK_SOURCE_URL",
            "TRAEFIK_DOWNLOAD_URL",
            "TRAEFIK_SHA256",
            "TRAEFIK_SHA256_URL",
        ),
        update_policy=AUTOMATIC_UPDATE_POLICY,
        stable_policy=GITHUB_STABLE_RELEASE_POLICY,
        compatibility_policy=NO_HIDDEN_SERIES_RESTRICTION,
        authorized_hosts=GITHUB_RELEASE_HOSTS,
        github_repository="traefik/traefik",
        version_variable="TRAEFIK_VERSION",
        source_url_variable="TRAEFIK_SOURCE_URL",
        download_url_variable="TRAEFIK_DOWNLOAD_URL",
        sha256_variable="TRAEFIK_SHA256",
        sha256_url_variable="TRAEFIK_SHA256_URL",
        asset_template=f"traefik_v{{version}}_{{platform}}{TAR_GZ_EXTENSION}",
        asset_platform_variable="TRAEFIK_ARTIFACT_PLATFORM",
        checksum_asset_template="traefik_v{version}_checksums.txt",
        checksum_strategy="github_release_asset_digest_or_official_manifest",
        tag_prefix="v",
        tag_pattern=VERSION_TAG_PATTERN,
    ),
    ComponentDefinition(
        name="lighttpd",
        resolver="lighttpd_latest",
        variables=(
            "LIGHTTPD_SERIES",
            "LIGHTTPD_RELEASE_ROOT_URL",
            "LIGHTTPD_SERIES_BASE_URL",
            "LIGHTTPD_VERSION",
            "LIGHTTPD_SOURCE_URL",
            "LIGHTTPD_ARCHIVE_NAME",
            "LIGHTTPD_RELEASE_INDEX_URL",
            "LIGHTTPD_LATEST_URL",
            "LIGHTTPD_DOWNLOAD_URL",
            "LIGHTTPD_SHA256",
            "LIGHTTPD_SHA256_URL",
        ),
        atomic_group=(
            "LIGHTTPD_SERIES",
            "LIGHTTPD_RELEASE_ROOT_URL",
            "LIGHTTPD_SERIES_BASE_URL",
            "LIGHTTPD_VERSION",
            "LIGHTTPD_SOURCE_URL",
            "LIGHTTPD_RELEASE_INDEX_URL",
            "LIGHTTPD_LATEST_URL",
            "LIGHTTPD_DOWNLOAD_URL",
            "LIGHTTPD_SHA256",
            "LIGHTTPD_SHA256_URL",
        ),
        update_policy=AUTOMATIC_UPDATE_POLICY,
        stable_policy="official releases-1.4.x latest.txt stable numeric release",
        compatibility_policy="the explicitly configured releases-1.4.x line",
        authorized_hosts=("download.lighttpd.net",),
        version_variable="LIGHTTPD_VERSION",
        source_url_variable="LIGHTTPD_SOURCE_URL",
        download_url_variable="LIGHTTPD_DOWNLOAD_URL",
        sha256_variable="LIGHTTPD_SHA256",
        sha256_url_variable="LIGHTTPD_SHA256_URL",
        asset_template="lighttpd-{version}.tar.xz",
        checksum_strategy="official_sha256sum_manifest",
        filename_prefix="lighttpd",
        archive_extension=".tar.xz",
    ),
    ComponentDefinition(
        name=CRS_COMPONENT,
        resolver="github_tag_commit",
        variables=(
            "CRS_APPROVED_REPO_URL",
            "CRS_RELEASE_TAG",
            "CRS_APPROVED_COMMIT",
            "CRS_REPO_URL",
            "CRS_GIT_REF",
        ),
        atomic_group=("CRS_RELEASE_TAG", "CRS_APPROVED_COMMIT"),
        update_policy="manual_review",
        stable_policy=GITHUB_STABLE_RELEASE_POLICY,
        compatibility_policy="latest stable release requires immutable peeled-commit review",
        authorized_hosts=GITHUB_RELEASE_HOSTS,
        github_repository=CRS_APPROVED_REPOSITORY,
        release_tag_variable="CRS_RELEASE_TAG",
        git_commit_variable="CRS_APPROVED_COMMIT",
        checksum_strategy="peeled_git_tag_commit",
        tag_pattern=VERSION_TAG_PATTERN,
        alias_bindings=(
            ("CRS_REPO_URL", "CRS_APPROVED_REPO_URL"),
            ("CRS_GIT_REF", "CRS_RELEASE_TAG"),
        ),
    ),
    ComponentDefinition(
        name=MODSECURITY_V3_COMPONENT,
        resolver="github_tag_commit",
        variables=(
            "MODSECURITY_V3_APPROVED_REPO_URL",
            "MODSECURITY_V3_RELEASE_TAG",
            "MODSECURITY_V3_APPROVED_COMMIT",
            "MODSECURITY_REPO_URL",
            "MODSECURITY_GIT_REF",
            "MODSECURITY_V3_GIT_URL",
            "MODSECURITY_V3_GIT_REF",
        ),
        atomic_group=(
            "MODSECURITY_V3_RELEASE_TAG",
            "MODSECURITY_V3_APPROVED_COMMIT",
        ),
        update_policy="manual_review",
        stable_policy="GitHub non-draft, non-prerelease stable v3.<version> release",
        compatibility_policy="latest stable v3 release requires immutable peeled-commit review",
        authorized_hosts=GITHUB_RELEASE_HOSTS,
        github_repository=MODSECURITY_V3_APPROVED_REPOSITORY,
        release_tag_variable="MODSECURITY_V3_RELEASE_TAG",
        git_commit_variable="MODSECURITY_V3_APPROVED_COMMIT",
        checksum_strategy="peeled_git_tag_commit",
        tag_pattern=r"^v3\.\d+\.\d+$",
        alias_bindings=(
            ("MODSECURITY_REPO_URL", "MODSECURITY_V3_APPROVED_REPO_URL"),
            ("MODSECURITY_GIT_REF", "MODSECURITY_V3_RELEASE_TAG"),
            ("MODSECURITY_V3_GIT_URL", "MODSECURITY_V3_APPROVED_REPO_URL"),
            ("MODSECURITY_V3_GIT_REF", "MODSECURITY_V3_RELEASE_TAG"),
        ),
    ),
    ComponentDefinition(
        name="ModSecurity Apache connector",
        resolver="not_applicable",
        variables=(
            "MODSECURITY_APACHE_REPO_URL",
            "MODSECURITY_APACHE_GIT_URL",
            "MODSECURITY_APACHE_GIT_REF",
        ),
        atomic_group=(),
        update_policy="not_applicable",
        stable_policy="none",
        compatibility_policy="repo-local connector source",
        not_applicable_reason="connector source is repo-local unless explicitly configured",
    ),
    ComponentDefinition(
        name="ModSecurity NGINX connector",
        resolver="not_applicable",
        variables=(
            "MODSECURITY_NGINX_REPO_URL",
            "MODSECURITY_NGINX_GIT_URL",
            "MODSECURITY_NGINX_GIT_REF",
        ),
        atomic_group=(),
        update_policy="not_applicable",
        stable_policy="none",
        compatibility_policy="repo-local connector source",
        not_applicable_reason="connector source is repo-local unless explicitly configured",
    ),
    ComponentDefinition(
        name="Apache httpd",
        resolver=APACHE_LISTING_RESOLVER,
        variables=(
            "HTTPD_VERSION",
            "HTTPD_ARCHIVE_NAME",
            "HTTPD_SOURCE_URL",
            "HTTPD_SHA256",
            "HTTPD_SHA256_URL",
        ),
        atomic_group=(
            "HTTPD_VERSION",
            "HTTPD_SOURCE_URL",
            "HTTPD_SHA256",
            "HTTPD_SHA256_URL",
        ),
        update_policy=AUTOMATIC_UPDATE_POLICY,
        stable_policy=APACHE_STABLE_RELEASE_POLICY,
        compatibility_policy=SAME_MAJOR_MINOR_COMPATIBILITY_POLICY,
        authorized_hosts=(APACHE_DOWNLOAD_HOST,),
        version_variable="HTTPD_VERSION",
        source_url_variable="HTTPD_SOURCE_URL",
        sha256_variable="HTTPD_SHA256",
        sha256_url_variable="HTTPD_SHA256_URL",
        checksum_strategy=OFFICIAL_ASSET_SHA256_FILE_STRATEGY,
        filename_prefix="httpd",
        archive_extension=ARCHIVE_BZ2_EXTENSION,
        source_path_prefix="/httpd/",
    ),
    ComponentDefinition(
        name="APR",
        resolver=APACHE_LISTING_RESOLVER,
        variables=(
            "APR_VERSION",
            "APR_ARCHIVE_NAME",
            "APR_SOURCE_URL",
            "APR_SHA256",
            "APR_SHA256_URL",
        ),
        atomic_group=("APR_VERSION", "APR_SOURCE_URL", "APR_SHA256", "APR_SHA256_URL"),
        update_policy=AUTOMATIC_UPDATE_POLICY,
        stable_policy=APACHE_STABLE_RELEASE_POLICY,
        compatibility_policy=SAME_MAJOR_MINOR_COMPATIBILITY_POLICY,
        authorized_hosts=(APACHE_DOWNLOAD_HOST,),
        version_variable="APR_VERSION",
        source_url_variable="APR_SOURCE_URL",
        sha256_variable="APR_SHA256",
        sha256_url_variable="APR_SHA256_URL",
        checksum_strategy=OFFICIAL_ASSET_SHA256_FILE_STRATEGY,
        filename_prefix="apr",
        archive_extension=ARCHIVE_BZ2_EXTENSION,
        source_path_prefix=APACHE_APR_SOURCE_PATH_PREFIX,
    ),
    ComponentDefinition(
        name="APR-util",
        resolver=APACHE_LISTING_RESOLVER,
        variables=(
            "APR_UTIL_VERSION",
            "APR_UTIL_ARCHIVE_NAME",
            "APR_UTIL_SOURCE_URL",
            "APR_UTIL_SHA256",
            "APR_UTIL_SHA256_URL",
        ),
        atomic_group=(
            "APR_UTIL_VERSION",
            "APR_UTIL_SOURCE_URL",
            "APR_UTIL_SHA256",
            "APR_UTIL_SHA256_URL",
        ),
        update_policy=AUTOMATIC_UPDATE_POLICY,
        stable_policy=APACHE_STABLE_RELEASE_POLICY,
        compatibility_policy=SAME_MAJOR_MINOR_COMPATIBILITY_POLICY,
        authorized_hosts=(APACHE_DOWNLOAD_HOST,),
        version_variable="APR_UTIL_VERSION",
        source_url_variable="APR_UTIL_SOURCE_URL",
        sha256_variable="APR_UTIL_SHA256",
        sha256_url_variable="APR_UTIL_SHA256_URL",
        checksum_strategy=OFFICIAL_ASSET_SHA256_FILE_STRATEGY,
        filename_prefix="apr-util",
        archive_extension=ARCHIVE_BZ2_EXTENSION,
        source_path_prefix=APACHE_APR_SOURCE_PATH_PREFIX,
    ),
    ComponentDefinition(
        name="PCRE2",
        resolver="github_release_digest",
        variables=(
            "PCRE2_VERSION",
            "PCRE2_ARCHIVE_NAME",
            "PCRE2_SOURCE_URL",
            "PCRE2_SHA256",
            "PCRE2_SHA256_URL",
        ),
        atomic_group=(
            "PCRE2_VERSION",
            "PCRE2_SOURCE_URL",
            "PCRE2_SHA256",
            "PCRE2_SHA256_URL",
        ),
        update_policy=AUTOMATIC_UPDATE_POLICY,
        stable_policy="GitHub non-draft, non-prerelease pcre2-<version> release",
        compatibility_policy=NO_HIDDEN_SERIES_RESTRICTION,
        authorized_hosts=GITHUB_RELEASE_HOSTS,
        github_repository="PCRE2Project/pcre2",
        version_variable="PCRE2_VERSION",
        source_url_variable="PCRE2_SOURCE_URL",
        sha256_variable="PCRE2_SHA256",
        sha256_url_variable="PCRE2_SHA256_URL",
        asset_template="pcre2-{version}.tar.bz2",
        checksum_strategy="github_release_asset_digest",
        tag_prefix="pcre2-",
        tag_pattern=r"^pcre2-\d+(?:\.\d+)+$",
    ),
    ComponentDefinition(
        name=NGINX_COMPONENT,
        resolver="github_release_digest",
        variables=(
            "NGINX_SOURCE_REPO_URL",
            "NGINX_SOURCE_MODE",
            "NGINX_GITHUB_REPO",
            "NGINX_RELEASE_TAG",
            "NGINX_SOURCE_GIT_REF",
            "NGINX_RELEASE_ASSET_NAME",
            "NGINX_DOWNLOAD_URL",
            "NGINX_SHA256",
        ),
        atomic_group=(
            "NGINX_RELEASE_TAG",
            "NGINX_SOURCE_GIT_REF",
            "NGINX_RELEASE_ASSET_NAME",
            "NGINX_SHA256",
        ),
        update_policy=AUTOMATIC_UPDATE_POLICY,
        stable_policy="GitHub non-draft, non-prerelease release-<version> release",
        compatibility_policy=NO_HIDDEN_SERIES_RESTRICTION,
        authorized_hosts=GITHUB_RELEASE_HOSTS,
        github_repository=CANONICAL_REPOSITORY_MARKER,
        release_tag_variable="NGINX_RELEASE_TAG",
        source_url_variable="NGINX_SOURCE_REPO_URL",
        asset_variable="NGINX_RELEASE_ASSET_NAME",
        sha256_variable="NGINX_SHA256",
        asset_template=f"nginx-{{version}}{TAR_GZ_EXTENSION}",
        checksum_strategy="github_release_asset_digest",
        tag_prefix="release-",
        tag_pattern=r"^release-\d+(?:\.\d+)+$",
    ),
    ComponentDefinition(
        name="OpenSSL for NGINX QUIC/TLS",
        resolver="github_release_digest",
        variables=(
            "NGINX_QUIC_TLS_VERSION",
            "NGINX_QUIC_TLS_ARCHIVE_NAME",
            "NGINX_QUIC_TLS_SOURCE_URL",
            "NGINX_QUIC_TLS_SOURCE_SHA256",
        ),
        atomic_group=(
            "NGINX_QUIC_TLS_VERSION",
            "NGINX_QUIC_TLS_SOURCE_URL",
            "NGINX_QUIC_TLS_SOURCE_SHA256",
        ),
        update_policy=AUTOMATIC_UPDATE_POLICY,
        stable_policy="GitHub non-draft, non-prerelease openssl-<version> release",
        compatibility_policy=NO_HIDDEN_SERIES_RESTRICTION,
        authorized_hosts=GITHUB_RELEASE_HOSTS,
        github_repository="openssl/openssl",
        version_variable="NGINX_QUIC_TLS_VERSION",
        source_url_variable="NGINX_QUIC_TLS_SOURCE_URL",
        sha256_variable="NGINX_QUIC_TLS_SOURCE_SHA256",
        asset_template=f"openssl-{{version}}{TAR_GZ_EXTENSION}",
        checksum_strategy="github_release_asset_digest",
        tag_prefix="openssl-",
        tag_pattern=r"^openssl-\d+(?:\.\d+)+$",
    ),
    ComponentDefinition(
        name="HAProxy",
        resolver="haproxy_series",
        variables=(
            "HAPROXY_SERIES",
            "HAPROXY_RELEASE_ROOT_URL",
            "HAPROXY_SERIES_BASE_URL",
            "HAPROXY_VERSION",
            "HAPROXY_ARCHIVE_NAME",
            "HAPROXY_SOURCE_URL",
            "HAPROXY_SHA256_URL",
            "HAPROXY_SHA256",
        ),
        atomic_group=(
            "HAPROXY_SERIES",
            "HAPROXY_RELEASE_ROOT_URL",
            "HAPROXY_SERIES_BASE_URL",
            "HAPROXY_VERSION",
            "HAPROXY_SOURCE_URL",
            "HAPROXY_SHA256_URL",
            "HAPROXY_SHA256",
        ),
        update_policy=AUTOMATIC_UPDATE_POLICY,
        stable_policy="official HAProxy numeric series release directory",
        compatibility_policy=SAME_MAJOR_MINOR_COMPATIBILITY_POLICY,
        authorized_hosts=(HAPROXY_WEB_HOST,),
        version_variable="HAPROXY_VERSION",
        source_url_variable="HAPROXY_SOURCE_URL",
        sha256_variable="HAPROXY_SHA256",
        sha256_url_variable="HAPROXY_SHA256_URL",
        checksum_strategy=OFFICIAL_ASSET_SHA256_FILE_STRATEGY,
        filename_prefix="haproxy",
        archive_extension=TAR_GZ_EXTENSION,
    ),
    ComponentDefinition(
        name="HAProxy HTX",
        resolver="haproxy_htx_series",
        variables=(
            "HAPROXY_RELEASE_ROOT_URL",
            "HAPROXY_HTX_SERIES",
            "HAPROXY_HTX_SERIES_BASE_URL",
            "HAPROXY_HTX_VERSION",
            "HAPROXY_HTX_ARCHIVE_NAME",
            "HAPROXY_HTX_SOURCE_URL",
            "HAPROXY_HTX_SHA256",
        ),
        atomic_group=(
            "HAPROXY_HTX_SERIES",
            "HAPROXY_HTX_SERIES_BASE_URL",
            "HAPROXY_HTX_VERSION",
            "HAPROXY_HTX_ARCHIVE_NAME",
            "HAPROXY_HTX_SOURCE_URL",
            "HAPROXY_HTX_SHA256",
        ),
        update_policy=AUTOMATIC_UPDATE_POLICY,
        stable_policy="official HAProxy numeric series release directory",
        compatibility_policy=SAME_MAJOR_MINOR_COMPATIBILITY_POLICY,
        authorized_hosts=(HAPROXY_WEB_HOST,),
        version_variable="HAPROXY_HTX_VERSION",
        source_url_variable="HAPROXY_HTX_SOURCE_URL",
        sha256_variable="HAPROXY_HTX_SHA256",
        checksum_strategy=OFFICIAL_ASSET_SHA256_FILE_STRATEGY,
        filename_prefix="haproxy",
        archive_extension=TAR_GZ_EXTENSION,
    ),
    ComponentDefinition(
        name="go-ftw",
        resolver="unified_orchestrator",
        variables=(
            "GO_FTW_SOURCE_URL",
            "GO_FTW_PROMPT_EXPECTED_LATEST",
            "GO_FTW_GIT_REF",
            "GO_FTW_RELEASE_TAG",
            "GO_FTW_APPROVED_COMMIT",
        ),
        atomic_group=(),
        update_policy="manual_review",
        stable_policy="stable tag is documented, but no Framework fetch consumer exists",
        compatibility_policy="local executable probe only",
        not_applicable_reason="resolved by the unified canonical maintenance orchestrator",
    ),
    ComponentDefinition(
        name="Albedo",
        resolver="unified_orchestrator",
        variables=(
            "ALBEDO_SOURCE_URL",
            "ALBEDO_PROMPT_EXPECTED_LATEST",
            "ALBEDO_GIT_REF",
            "ALBEDO_RELEASE_TAG",
            "ALBEDO_APPROVED_COMMIT",
        ),
        atomic_group=(),
        update_policy="manual_review",
        stable_policy="stable tag is documented, but no Framework fetch consumer exists",
        compatibility_policy="local executable probe only",
        not_applicable_reason="resolved by the unified canonical maintenance orchestrator",
    ),
    ComponentDefinition(
        name="Expat",
        resolver="not_applicable",
        variables=(
            "EXPAT_SOURCE_URL",
            "EXPAT_GIT_REF",
            "EXPAT_GIT_URL",
            "EXPAT_PROMPT_EXPECTED_LATEST",
        ),
        atomic_group=(),
        update_policy="not_applicable",
        stable_policy="not fetched by this Framework",
        compatibility_policy="legacy metadata is unused by an acquisition path",
        not_applicable_reason="Expat metadata has no Framework source-acquisition consumer and is intentionally not an updater input",
    ),
    ComponentDefinition(
        name=CANONICAL_CI_PINS_LABEL,
        resolver="unified_orchestrator",
        variables=CI_CANONICAL_PIN_VARIABLES,
        atomic_group=(),
        update_policy="manual_review",
        stable_policy="exact reviewed action/tool/interpreter release and digest",
        compatibility_policy="generated workflow, lock, and documentation views",
        not_applicable_reason="resolved by the unified canonical maintenance orchestrator and generated-view checks",
    ),
    ComponentDefinition(
        name="Default branch",
        resolver="not_applicable",
        variables=("DEFAULT_BRANCH",),
        atomic_group=(),
        update_policy="not_applicable",
        stable_policy="none",
        compatibility_policy="local policy default",
        not_applicable_reason="DEFAULT_BRANCH is a local policy default, not an upstream release source",
    ),
)

COMPONENT_DEFINITION_BY_NAME = {item.name: item for item in COMPONENT_DEFINITIONS}


def canonical_component_selection(requested: list[str] | None) -> tuple[str, ...]:
    """Validate exact CLI component names and preserve registry order."""

    if not requested:
        return ()
    requested_names = set(requested)
    unknown = sorted(requested_names.difference(COMPONENT_DEFINITION_BY_NAME))
    if unknown:
        raise UpstreamError(
            "unknown component selector(s): "
            + ", ".join(repr(name) for name in unknown)
        )
    return tuple(
        definition.name
        for definition in COMPONENT_DEFINITIONS
        if definition.name in requested_names
    )


def component_definition_for_variable(variable: str) -> ComponentDefinition | None:
    """Return the sole declared component owner for a provenance variable."""

    if variable.startswith(("CI_CANONICAL_", "CI_ACTION_", "CI_SECURITY_TOOL_")):
        return COMPONENT_DEFINITION_BY_NAME[CANONICAL_CI_PINS_LABEL]
    if variable == "HAPROXY_RELEASE_ROOT_URL":
        return COMPONENT_DEFINITION_BY_NAME["HAProxy"]

    owners = [item for item in COMPONENT_DEFINITIONS if variable in item.variables]
    if len(owners) > 1:
        raise UpstreamError(
            f"provenance variable {variable} has multiple component owners: "
            + ", ".join(item.name for item in owners)
        )
    return owners[0] if owners else None


class UpstreamBlocked(RuntimeError):
    """The upstream source could not be checked right now."""


class UpstreamUnknown(RuntimeError):
    """The upstream structure is not safe enough for an automated decision."""


class UpstreamError(RuntimeError):
    """The upstream source returned contradictory or invalid data."""


@dataclasses.dataclass
class VariableEntry:
    name: str
    line: int
    raw: str
    default: str
    resolved: str
    tracked: bool
    style: str


@dataclasses.dataclass
class UpdateChange:
    variable: str
    line: int
    old: str
    new: str


@dataclasses.dataclass
class ComponentResult:
    component: str
    status: str
    message: str
    variables: list[str]
    current: str = ""
    latest: str = ""
    latest_upstream: str = ""
    latest_compatible: str = ""
    source: str = ""
    asset_name: str = ""
    official_sha256: str = ""
    sha256_source: str = ""
    update_policy: str = ""
    atomic_group: tuple[str, ...] = ()
    updates: list[UpdateChange] = dataclasses.field(default_factory=list)
    details: dict[str, Any] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass(frozen=True)
class MaintenanceDisposition:
    """Classify a checked candidate without relaxing fatal source states."""

    outcome: str
    safe_updates_available: bool
    manual_review_required: bool
    manual_review_components: tuple[str, ...]
    fatal_components: tuple[str, ...]
    automatic_updates: tuple[UpdateChange, ...]
    automatic_update_variables: tuple[str, ...]


def validate_entries(entries: dict[str, VariableEntry]) -> list[str]:
    """Return tracked variables that resolve to empty without being documented as optional."""
    missing: list[str] = []
    for item in sorted(entries.values(), key=lambda current: current.line):
        if (
            item.tracked
            and not item.resolved
            and item.name not in OPTIONAL_EMPTY_VARIABLES
        ):
            missing.append(item.name)
    return missing


def build_root() -> Path:
    return Path(os.path.abspath(os.environ.get("BUILD_ROOT", str(DEFAULT_BUILD_ROOT))))


def require_no_symlink_ancestors(path: Path, label: str) -> Path:
    """Reject symlinked path components before any read, mkdir, or replace."""

    absolute = Path(os.path.abspath(path))
    current = absolute
    while True:
        try:
            details = current.lstat()
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise UpstreamError(f"cannot inspect {label}: {current}") from exc
        else:
            if stat.S_ISLNK(details.st_mode):
                raise UpstreamError(
                    f"{label} contains a symlink path component: {current}"
                )
            if current != absolute and not stat.S_ISDIR(details.st_mode):
                raise UpstreamError(
                    f"{label} contains a non-directory ancestor: {current}"
                )
        if current == Path(current.anchor):
            break
        current = current.parent
    return absolute


def is_under(path: Path, root: Path) -> bool:
    try:
        Path(os.path.abspath(path)).relative_to(Path(os.path.abspath(root)))
    except ValueError:
        return False
    return True


def require_safe_build_write_target(path: Path) -> Path:
    target = require_no_symlink_ancestors(path, "BUILD_ROOT output")
    root = build_root()
    require_no_symlink_ancestors(root, "BUILD_ROOT")
    if is_under(target, root):
        return target
    raise UpstreamError(f"refusing to write outside BUILD_ROOT ({root}): {target}")


def require_safe_common_sh_update_target(path: Path) -> Path:
    target = require_no_symlink_ancestors(path, "common.sh update target")
    canonical_common_sh = require_no_symlink_ancestors(
        DEFAULT_COMMON_SH, "canonical common.sh"
    )
    if target == canonical_common_sh:
        return target
    if target.name == canonical_common_sh.name:
        return require_safe_build_write_target(target)
    raise UpstreamError(
        "refusing to update a file other than the canonical common.sh or a "
        f"BUILD_ROOT test fixture: {target}"
    )


def require_safe_common_sh_source(path: Path) -> Path:
    """Allow CLI reads only from the canonical tree or an explicit build fixture."""

    source = require_no_symlink_ancestors(path, "common.sh source")
    canonical_common_sh = require_no_symlink_ancestors(
        DEFAULT_COMMON_SH, "canonical common.sh"
    )
    if source == canonical_common_sh:
        return source
    root = require_no_symlink_ancestors(build_root(), "BUILD_ROOT")
    if source.name == canonical_common_sh.name and is_under(source, root):
        return source
    raise UpstreamError(
        "refusing to read a file other than the canonical common.sh or a "
        f"BUILD_ROOT test fixture: {source}"
    )


def resolve_value(raw_value: str, resolved: dict[str, str]) -> str:
    value = raw_value
    for _ in range(30):
        before = value

        def replace_param(match: re.Match[str]) -> str:
            name = match.group(1)
            fallback = match.group(2)
            current = resolved.get(name, "")
            return current if current else fallback

        value = PARAM_EXPANSION_RE.sub(replace_param, value)
        if value == before:
            break
    value = PARAM_REMOVE_PREFIX_RE.sub(
        lambda match: (
            resolved.get(match.group(1), "").removeprefix(match.group(2))
            if resolved.get(match.group(1), "").startswith(match.group(2))
            else resolved.get(match.group(1), "")
        ),
        value,
    )
    value = BRACED_VAR_RE.sub(lambda match: resolved.get(match.group(1), ""), value)
    value = PLAIN_VAR_RE.sub(lambda match: resolved.get(match.group(1), ""), value)
    return value


def parse_common_assignment(line: str) -> tuple[str, str, str] | None:
    assign_re = re.compile(r'^([A-Z][A-Z0-9_]*)="\$\{\1:-(.*)\}"\s*$')
    unset_assign_re = re.compile(r'^([A-Z][A-Z0-9_]*)="\$\{\1-(.*)\}"\s*$')
    colon_re = re.compile(r'^:\s+"\$\{([A-Z][A-Z0-9_]*):=(.*)\}"\s*$')
    # A selected small set of reviewed literals may contain a simple variable
    # reference (for example APR-util's URL derived from its one version).  The
    # parser only substitutes already-parsed variables; it never evaluates shell
    # syntax, command substitution, or environment values.
    literal_re = re.compile(r'^([A-Z][A-Z0-9_]*)="([^"`]*)"\s*$')

    for style, pattern in (
        ("colon-default", colon_re),
        ("assignment-default", assign_re),
        ("assignment-unset-default", unset_assign_re),
    ):
        match = pattern.match(line)
        if match:
            return style, match.group(1), match.group(2)

    match = literal_re.match(line)
    if not match:
        return None
    name = match.group(1)
    # Canonical pins are intentionally literal assignments.  Accept only
    # names covered by the provenance inventory (or the small legacy allowlist)
    # so arbitrary shell configuration is still ignored and never evaluated.
    if (
        name not in APPROVED_LITERAL_VARIABLES
        and not RELEVANT_PROVENANCE_VARIABLE_RE.search(name)
    ):
        return None
    return "literal-assignment", name, match.group(2)


def parse_common_lines(lines: list[str]) -> dict[str, VariableEntry]:
    """Parse already-rendered common.sh lines without touching a write target."""

    entries: dict[str, VariableEntry] = {}
    resolved: dict[str, str] = {}

    for line_no, line in enumerate(lines, start=1):
        assignment = parse_common_assignment(line)
        if assignment is None:
            continue
        style, name, default = assignment
        value = resolve_value(default, resolved)
        resolved[name] = value
        # A runtime path may interpolate a version (for example
        # ``ENVOY_SOURCE_ROOT``).  That does not make the path itself an
        # upstream-provenance input, so classify only the assignment name.
        tracked = bool(TRACKED_NAME_RE.search(name))
        entries[name] = VariableEntry(
            name=name,
            line=line_no,
            raw=line,
            default=default,
            resolved=value,
            tracked=tracked,
            style=style,
        )
    return entries


def parse_common(common_sh: Path) -> tuple[list[str], dict[str, VariableEntry]]:
    common_sh = require_no_symlink_ancestors(common_sh, "common.sh source")
    lines = common_sh.read_text(encoding="utf-8").splitlines()
    return lines, parse_common_lines(lines)


def provenance_assignment_occurrences(
    lines: list[str],
) -> dict[str, list[int]]:
    """Return provenance assignment locations without executing common.sh.

    This deliberately reuses the restricted assignment parser.  Function
    bodies and shell control flow are treated as plain text; only reviewed
    assignment forms are considered.  The locations make duplicate pin
    definitions observable instead of silently letting the last dictionary
    value win.
    """

    occurrences: dict[str, list[int]] = {}
    for line_no, line in enumerate(lines, start=1):
        assignment = parse_common_assignment(line)
        if assignment is None:
            continue
        _, name, _ = assignment
        if RELEVANT_PROVENANCE_VARIABLE_RE.search(name) or name == "DEFAULT_BRANCH":
            occurrences.setdefault(name, []).append(line_no)
    return occurrences


def duplicate_provenance_variables(lines: list[str]) -> dict[str, list[int]]:
    """Return relevant names assigned more than once, with source lines."""

    return {
        name: locations
        for name, locations in provenance_assignment_occurrences(lines).items()
        if len(locations) > 1
    }


def _canonical_registry_errors() -> list[str]:
    errors: list[str] = []
    owners: dict[str, list[str]] = {}
    for definition in COMPONENT_DEFINITIONS:
        for name in definition.variables:
            owners.setdefault(name, []).append(definition.name)
    duplicate_owners = {
        name: names
        for name, names in owners.items()
        if len(names) > 1 and name != "HAPROXY_RELEASE_ROOT_URL"
    }
    for name, names in sorted(duplicate_owners.items()):
        errors.append(f"duplicate registry ownership for {name}: {', '.join(names)}")
    return errors


def _canonical_assignment_errors(
    lines: list[str], entries: dict[str, VariableEntry]
) -> list[str]:
    errors: list[str] = []
    expected = {
        name for definition in COMPONENT_DEFINITIONS for name in definition.variables
    }
    dynamic_ci_names, ci_group_errors = canonical_ci_group_inventory(entries)
    expected.update(dynamic_ci_names)
    errors.extend(ci_group_errors)

    missing = sorted(name for name in expected if name not in entries)
    if missing:
        errors.append("missing canonical assignments: " + ", ".join(missing))

    duplicates = duplicate_provenance_variables(lines)
    for name, locations in sorted(duplicates.items()):
        errors.append(
            f"duplicate canonical assignment for {name} at lines "
            + ", ".join(str(item) for item in locations)
        )

    unassigned = unassigned_provenance_variables(entries)
    if unassigned:
        errors.append("unassigned canonical assignments: " + ", ".join(unassigned))
    return errors


def _canonical_value_errors(entries: dict[str, VariableEntry]) -> list[str]:
    errors: list[str] = []
    missing_values = validate_entries(entries)
    if missing_values:
        errors.append("empty canonical assignments: " + ", ".join(missing_values))

    literal_required = {
        name
        for definition in COMPONENT_DEFINITIONS
        if definition.update_policy != "not_applicable"
        or definition.name == CANONICAL_CI_PINS_LABEL
        for name in definition.variables
    }
    environment_defaults = sorted(
        item.name
        for item in entries.values()
        if item.name in literal_required
        and item.style in {"assignment-default", "assignment-unset-default"}
    )
    if environment_defaults:
        errors.append(
            "canonical pins must not use environment-default assignments: "
            + ", ".join(environment_defaults)
        )

    osv_sha = entries.get("CI_OSV_LEGACY_BASE_SHA")
    if osv_sha and not GIT_COMMIT_SHA1_RE.fullmatch(osv_sha.resolved):
        errors.append(
            "CI_OSV_LEGACY_BASE_SHA must be a lowercase 40-character commit SHA"
        )
    osv_version = entries.get("CI_OSV_LEGACY_BASE_VERSION")
    if osv_version and not SAFE_VERSION_RE.fullmatch(osv_version.resolved):
        errors.append("CI_OSV_LEGACY_BASE_VERSION must be a numeric dotted version")

    unresolved = sorted(
        item.name for item in entries.values() if item.tracked and "$" in item.resolved
    )
    if unresolved:
        errors.append("unresolved canonical derivations: " + ", ".join(unresolved))
    return errors


def canonical_contract_errors(
    lines: list[str], entries: dict[str, VariableEntry]
) -> list[str]:
    """Validate the complete local canonical pin contract, offline.

    The updater intentionally permits component-specific fixtures containing
    only a subset of variables.  This stricter contract is reserved for the
    canonical checkout/lint path and therefore checks every registered
    provenance variable, ownership, duplicate assignment, and resolution.
    """

    errors = _canonical_registry_errors()
    errors.extend(_canonical_assignment_errors(lines, entries))
    errors.extend(_canonical_value_errors(entries))
    return errors


def _canonical_pin_values(common_sh: Path) -> dict[str, str]:
    common_sh = require_no_symlink_ancestors(common_sh, "canonical common.sh source")
    pin_values = {
        item.name: item.resolved
        for item in parse_common_lines(
            common_sh.read_text(encoding="utf-8").splitlines()
        ).values()
        if item.tracked
        and CANONICAL_PIN_VARIABLE_RE.search(item.name)
        and item.resolved not in GENERIC_CANONICAL_PIN_VALUES
    }
    # GitHub repository fields are sometimes consumed in owner/repository
    # form while common.sh stores the approved HTTPS URL.  Check both exact
    # representations without treating arbitrary URL path fragments as pins.
    for name, value in list(pin_values.items()):
        parsed = urlparse(value)
        if parsed.hostname == GITHUB_WEB_HOST:
            repository = parsed.path.strip("/").removesuffix(".git")
            if repository.count("/") == 1:
                pin_values[f"{name} (repository)"] = repository
    return pin_values


def _pin_value_names(pin_values: dict[str, str]) -> dict[str, list[str]]:
    value_names: dict[str, list[str]] = {}
    for name, value in pin_values.items():
        value_names.setdefault(value, []).append(name)
    return value_names


def _is_active_consumer_file(path: Path) -> bool:
    return path.is_file() and (
        path.suffix in ACTIVE_CONSUMER_SUFFIXES
        or path.name.startswith("Dockerfile")
        or not path.suffix
    )


def _active_consumer_files(root: Path) -> list[Path]:
    paths: list[Path] = []
    for relative_root in ACTIVE_CONSUMER_ROOTS:
        scan_root = root / relative_root
        if scan_root.is_dir():
            paths.extend(
                path
                for path in sorted(scan_root.rglob("*"))
                if _is_active_consumer_file(path)
            )
    return paths


def _consumer_pin_findings(
    path: Path,
    root: Path,
    common_sh: Path,
    value_pattern: re.Pattern[str],
    value_names: dict[str, list[str]],
) -> list[str]:
    relative = path.relative_to(root).as_posix()
    common_path = common_sh.resolve()
    common_relative = (
        common_path.relative_to(root).as_posix()
        if common_path.is_relative_to(root)
        else None
    )
    if common_relative and relative == common_relative:
        return []
    if (
        relative in GENERATED_CANONICAL_VIEW_PATHS
        or relative in NON_CONSUMER_METADATA_PATHS
    ):
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError, UnicodeError:
        return []
    findings: list[str] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for match in value_pattern.finditer(line):
            value = match.group(0)
            findings.extend(
                f"{relative}:{line_no}: {name}={value}" for name in value_names[value]
            )
    return findings


def active_consumer_pin_literals(
    common_sh: Path, repository_root: Path | None = None
) -> list[str]:
    """Find copied current pins in active consumers without executing code."""

    root = (repository_root or DEFAULT_COMMON_SH.parents[2]).resolve()
    value_names = _pin_value_names(_canonical_pin_values(common_sh))
    value_pattern = re.compile(
        "|".join(
            rf"(?<![A-Za-z0-9_.-]){re.escape(value)}(?![A-Za-z0-9_.-])"
            for value in sorted(value_names, key=len, reverse=True)
        )
    )
    findings = [
        finding
        for path in _active_consumer_files(root)
        for finding in _consumer_pin_findings(
            path, root, common_sh, value_pattern, value_names
        )
    ]
    return sorted(set(findings))


def entry(entries: dict[str, VariableEntry], name: str) -> VariableEntry | None:
    return entries.get(name)


def value(entries: dict[str, VariableEntry], name: str) -> str:
    current = entry(entries, name)
    return current.resolved if current else ""


def trusted_https_path_prefix(path: str) -> str:
    dynamic_value = URL_PATH_DYNAMIC_VALUE_RE.search(path)
    if dynamic_value is not None:
        return path[: dynamic_value.start()]
    return path.rsplit("/", 1)[0] + "/"


def _https_url_parts(
    variable: str, raw_url: str, error_prefix: str
) -> tuple[ParseResult, str | None, int | None]:
    parsed = urlparse(raw_url)
    try:
        return parsed, parsed.hostname, parsed.port
    except ValueError as exc:
        raise UpstreamError(f"{error_prefix} for {variable}: {raw_url!r}") from exc


def _safe_https_parts(
    parsed: ParseResult, hostname: str | None, port: int | None
) -> bool:
    return not (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not hostname
        or not SAFE_HTTPS_HOST_RE.fullmatch(hostname)
        or ".." in hostname
        or (port is not None and not 1 <= port <= 65535)
        or not SAFE_HTTPS_PATH_RE.fullmatch(parsed.path or "/")
        or ".." in parsed.path
        or "//" in parsed.path
    )


def _trusted_https_parts_match(
    parsed: ParseResult,
    hostname: str | None,
    port: int | None,
    trusted: ParseResult,
    trusted_hostname: str | None,
    trusted_port: int | None,
) -> bool:
    return not (
        trusted.scheme != "https"
        or not trusted.netloc
        or trusted.username is not None
        or trusted.password is not None
        or not trusted_hostname
        or not SAFE_HTTPS_HOST_RE.fullmatch(trusted_hostname)
        or ".." in trusted_hostname
        or (trusted_port is not None and not 1 <= trusted_port <= 65535)
        or ".." in trusted.path
        or "//" in trusted.path
        or hostname != trusted_hostname
        or port != trusted_port
        or not parsed.path.startswith(trusted_https_path_prefix(trusted.path or "/"))
    )


def require_safe_https_update_url(
    variable: str,
    new_default: str,
    trusted_default: str | None = None,
) -> None:
    parsed, hostname, port = _https_url_parts(
        variable, new_default, "refusing invalid HTTPS URL"
    )
    if not _safe_https_parts(parsed, hostname, port):
        raise UpstreamError(
            f"refusing invalid HTTPS URL for {variable}: {new_default!r}"
        )
    if trusted_default is None:
        return
    trusted, trusted_hostname, trusted_port = _https_url_parts(
        variable,
        trusted_default,
        "refusing URL update without a trusted HTTPS authority",
    )
    if not _trusted_https_parts_match(
        parsed, hostname, port, trusted, trusted_hostname, trusted_port
    ):
        raise UpstreamError(
            f"refusing HTTPS authority change for {variable}: {new_default!r}"
        )


def require_shell_safe_default(
    variable: str,
    new_default: str,
    trusted_default: str | None = None,
) -> None:
    if not isinstance(new_default, str) or not new_default:
        raise UpstreamError(f"refusing empty or non-text shell default for {variable}")
    if _has_unsafe_shell_character(new_default):
        raise UpstreamError(
            f"refusing unsafe shell default for {variable}: {new_default!r}"
        )
    if _is_version_variable(variable):
        if not _valid_version(new_default, trusted_default):
            raise UpstreamError(
                f"refusing invalid version for {variable}: {new_default!r}"
            )
        return
    if variable == "SHA256" or variable.endswith("_SHA256"):
        if not SHA256_VALUE_RE.fullmatch(new_default):
            raise UpstreamError(
                f"refusing invalid SHA-256 value for {variable}: {new_default!r}"
            )
        return
    if variable == "URL" or variable.endswith("_URL"):
        require_safe_https_update_url(variable, new_default, trusted_default)
        return
    if ".." in new_default or new_default.startswith("/") or "//" in new_default:
        raise UpstreamError(
            f"refusing traversal-like shell default for {variable}: {new_default!r}"
        )


def _has_unsafe_shell_character(value: str) -> bool:
    return any(ch in value for ch in " \t\n$`\"';{}()#&|<>\\")


def _is_version_variable(variable: str) -> bool:
    return variable == "VERSION" or variable.endswith("_VERSION")


def _valid_version(value: str, trusted_default: str | None) -> bool:
    tagged = isinstance(trusted_default, str) and trusted_default.startswith("v")
    return bool(
        SAFE_VERSION_RE.fullmatch(value)
        or (tagged and re.fullmatch(r"v\d+(?:\.\d+)+", value))
    )


def plan_update(
    entries: dict[str, VariableEntry], variable: str, new_default: str
) -> UpdateChange | None:
    current = entry(entries, variable)
    require_shell_safe_default(
        variable,
        new_default,
        current.default if current is not None else None,
    )
    if current is None:
        return None
    if current.default == new_default:
        return None
    return UpdateChange(
        variable=variable, line=current.line, old=current.default, new=new_default
    )


def is_template_value(raw_default: str, variable: str) -> bool:
    return (
        f"${variable}" in raw_default
        or f"${{{variable}}}" in raw_default
        or f"${{{variable}#" in raw_default
    )


def default_transitively_depends_on(
    entries: dict[str, VariableEntry],
    variable: str,
    dependency: str,
    seen: set[str] | None = None,
) -> bool:
    """Return whether a canonical assignment will track another assignment."""

    if variable == dependency:
        return True
    if seen is None:
        seen = set()
    if variable in seen:
        return False
    seen.add(variable)
    current = entries.get(variable)
    if current is None:
        return False
    references = set(BRACED_VAR_RE.findall(current.default))
    references.update(PLAIN_VAR_RE.findall(current.default))
    references.update(PARAM_EXPANSION_RE.findall(current.default))
    references.update(PARAM_REMOVE_PREFIX_RE.findall(current.default))
    names = {
        reference[0] if isinstance(reference, tuple) else reference
        for reference in references
    }
    return any(
        default_transitively_depends_on(entries, name, dependency, seen)
        for name in names
    )


def replace_default_line(line: str, variable: str, new_default: str) -> str:
    escaped = re.escape(variable)
    colon_re = re.compile(rf'^(:\s*"\$\{{{escaped}:=)(.*)(\}}"\s*)$')
    assign_re = re.compile(rf'^({escaped}\s*=\s*"\$\{{{escaped}:=)(.*)(\}}"\s*)$')
    default_re = re.compile(rf'^({escaped}\s*=\s*"\$\{{{escaped}:-)(.*)(\}}"\s*)$')
    unset_default_re = re.compile(rf'^({escaped}\s*=\s*"\$\{{{escaped}-)(.*)(\}}"\s*)$')
    literal_re = re.compile(rf'^({escaped}\s*=\s*")(.*)("\s*)$')
    for pattern in (colon_re, assign_re, default_re, unset_default_re, literal_re):
        match = pattern.match(line)
        if match:
            return f"{match.group(1)}{new_default}{match.group(3)}"
    raise UpstreamError(f"cannot safely update line for {variable}: {line}")


def render_updated_lines(lines: list[str], updates: list[UpdateChange]) -> list[str]:
    """Validate and render an update plan without mutating its target."""

    seen: set[str] = set()
    replacements: list[tuple[int, str]] = []
    for update in updates:
        if update.variable in seen:
            raise UpstreamError(f"duplicate update for {update.variable}")
        seen.add(update.variable)
        if update.line < 1:
            raise UpstreamError(
                f"invalid update line for {update.variable}: {update.line}"
            )
        index = update.line - 1
        try:
            current_line = lines[index]
        except IndexError as exc:
            raise UpstreamError(
                f"invalid update line for {update.variable}: {update.line}"
            ) from exc
        assignment = parse_common_assignment(current_line)
        if (
            assignment is None
            or assignment[1] != update.variable
            or assignment[2] != update.old
        ):
            raise UpstreamError(
                f"update no longer matches {update.variable} at line {update.line}"
            )
        require_shell_safe_default(update.variable, update.new, assignment[2])
        replacements.append(
            (index, replace_default_line(current_line, update.variable, update.new))
        )
    updated_lines = list(lines)
    for index, replacement in replacements:
        updated_lines[index] = replacement
    return updated_lines


def apply_updates(
    common_sh: Path, lines: list[str], updates: list[UpdateChange]
) -> None:
    if not updates:
        return
    target = require_safe_common_sh_update_target(common_sh)
    updated_lines = render_updated_lines(lines, updates)
    payload = ("\n".join(updated_lines) + "\n").encode("utf-8")
    original_mode = target.stat().st_mode & 0o777
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.",
        suffix=".tmp",
        dir=target.parent,
    )
    temporary = Path(temporary_name)
    try:
        try:
            os.fchmod(descriptor, original_mode)
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = -1
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, target)
        finally:
            if descriptor != -1:
                os.close(descriptor)
        # Persist the replacement directory entry where the platform exposes a
        # directory file descriptor.  The replacement itself is already
        # atomic; filesystems that do not allow directory fsync retain that
        # property without turning a completed write into a false no-write.
        try:
            directory_descriptor = os.open(target.parent, os.O_RDONLY)
        except OSError:
            directory_descriptor = -1
        if directory_descriptor != -1:
            try:
                try:
                    os.fsync(directory_descriptor)
                except OSError:
                    pass
            finally:
                os.close(directory_descriptor)
    finally:
        if temporary.exists():
            temporary.unlink()


def consume_decimal_digits(text: str, start: int) -> int:
    end = start
    while end < len(text) and text[end].isdecimal():
        end += 1
    return end


def dotted_version_text(text: str) -> str:
    start = 0
    while start < len(text):
        if not text[start].isdecimal():
            start += 1
            continue
        end = consume_decimal_digits(text, start)
        dotted_end = end
        while dotted_end < len(text) and text[dotted_end] == ".":
            next_start = dotted_end + 1
            next_end = consume_decimal_digits(text, next_start)
            if next_end == next_start:
                break
            dotted_end = next_end
        if dotted_end != end:
            return text[start:dotted_end]
        start = end
    raise UpstreamUnknown(f"no dotted numeric version in {text!r}")


def version_tuple(text: str) -> tuple[int, ...]:
    version = dotted_version_text(text)
    return tuple(int(part) for part in version.split("."))


def compare_versions(left: str, right: str) -> int:
    left_tuple = version_tuple(left)
    right_tuple = version_tuple(right)
    width = max(len(left_tuple), len(right_tuple))
    left_tuple = left_tuple + (0,) * (width - len(left_tuple))
    right_tuple = right_tuple + (0,) * (width - len(right_tuple))
    if left_tuple < right_tuple:
        return -1
    if left_tuple > right_tuple:
        return 1
    return 0


def same_series(left: str, right: str) -> bool:
    left_tuple = version_tuple(left)
    right_tuple = version_tuple(right)
    return (
        len(left_tuple) >= 2
        and len(right_tuple) >= 2
        and left_tuple[:2] == right_tuple[:2]
    )


def is_stable_version(value_text: str) -> bool:
    """Accept only a plain numeric release identity, never prerelease text."""

    return SAFE_VERSION_RE.fullmatch(value_text) is not None


def latest_versions_from_listing(
    html: str,
    filename_prefix: str,
    extension: str,
    current_version: str,
    restrict_to_current_series: bool,
) -> tuple[str, str]:
    """Return latest upstream and the explicitly compatible candidate."""

    pattern = re.compile(
        rf"{re.escape(filename_prefix)}-(\d+(?:\.\d+)+){re.escape(extension)}"
    )
    upstream_versions = sorted(
        {
            match.group(1)
            for match in pattern.finditer(html)
            if is_stable_version(match.group(1))
        },
        key=version_tuple,
    )
    if not upstream_versions:
        raise UpstreamUnknown(
            f"No safe updater implemented for this source yet: no matching {filename_prefix} "
            "stable versions found in official listing."
        )
    compatible_versions = (
        [
            candidate
            for candidate in upstream_versions
            if same_series(candidate, current_version)
        ]
        if restrict_to_current_series
        else upstream_versions
    )
    if not compatible_versions:
        raise UpstreamUnknown(
            f"no latest compatible {filename_prefix} version is available under the documented policy"
        )
    return upstream_versions[-1], compatible_versions[-1]


def markdown_escape(value_text: str) -> str:
    return value_text.replace("|", "\\|").replace("\n", "<br>")


class NoRedirectHandler(HTTPRedirectHandler):
    """Refuse redirects before urllib can follow them or copy request headers."""

    def redirect_request(  # type: ignore[override]
        self,
        request: Request,
        fp: Any,
        code: int,
        message: str,
        headers: Any,
        newurl: str,
    ) -> None:
        del request, fp, code, message, headers, newurl
        return None


def json_accept_header(url: str) -> str:
    """Use GitHub's media type only for GitHub's API endpoints."""

    return (
        "application/vnd.github+json"
        if urlparse(url).hostname == GITHUB_API_HOST
        else JSON_MIME_TYPE
    )


class HttpClient:
    def __init__(self, timeout: float) -> None:
        self.timeout = timeout
        self._opener = build_opener(NoRedirectHandler())

    def _headers(self, url: str, accept: str | None = None) -> dict[str, str]:
        headers = {
            "User-Agent": "ModSecurity-test-Framework common.sh version checker",
        }
        if accept:
            headers["Accept"] = accept
        parsed = urlparse(url)
        token = os.environ.get("GITHUB_TOKEN")
        if token and parsed.netloc == GITHUB_API_HOST:
            headers["Authorization"] = f"Bearer {token}"
            headers["X-GitHub-Api-Version"] = "2022-11-28"
        return headers

    def _get_text(
        self,
        url: str,
        accept: str | None = None,
        *,
        allowed_content_types: frozenset[str] | None = None,
    ) -> str:
        request = Request(url, headers=self._headers(url, accept))
        try:
            with self._opener.open(request, timeout=self.timeout) as response:  # nosec B310
                final_url = response.geturl()
                if final_url != url:
                    raise UpstreamUnknown(
                        f"{url}: redirect or final URL change is not permitted"
                    )
                content_type = response.headers.get_content_type().lower()
                if (
                    allowed_content_types is not None
                    and content_type not in allowed_content_types
                ):
                    raise UpstreamUnknown(
                        f"{url}: unexpected content type {content_type!r}"
                    )
                raw = response.read()
                charset = response.headers.get_content_charset() or "utf-8"
                try:
                    return raw.decode(charset, errors="replace")
                except (LookupError, UnicodeError) as exc:
                    raise UpstreamUnknown(
                        f"{url}: response declares an unsupported character encoding"
                    ) from exc
        except HTTPError as exc:
            if exc.code in {403, 429}:
                remaining = exc.headers.get("x-ratelimit-remaining")
                reset = exc.headers.get("x-ratelimit-reset")
                detail = f"HTTP {exc.code}"
                if remaining == "0" and reset:
                    detail += f"; GitHub rate limit reset={reset}"
                raise UpstreamBlocked(f"{url}: {detail}") from exc
            if exc.code == 404:
                raise UpstreamUnknown(f"{url}: HTTP 404") from exc
            raise UpstreamError(f"{url}: HTTP {exc.code}") from exc
        # urllib can surface a peer disconnect directly as an HTTPException
        # (for example ``RemoteDisconnected``) or OSError. Keep every
        # transport failure inside the fail-closed
        # resolver model so the caller still emits its diagnostic summary.
        except (HTTPException, OSError) as exc:
            raise UpstreamBlocked(f"{url}: {exc}") from exc

    def get_text(self, url: str, accept: str | None = None) -> str:
        return self._get_text(url, accept)

    def get_checksum_text(self, url: str) -> str:
        """Read only a non-HTML official checksum/manifest response."""

        return self._get_text(
            url,
            allowed_content_types=frozenset(
                {
                    "text/plain",
                    "application/octet-stream",
                    "application/pgp-signature",
                    "application/x-pgp-signature",
                }
            ),
        )

    def get_json(self, url: str) -> dict[str, Any]:
        text = self._get_text(
            url,
            accept=json_accept_header(url),
            allowed_content_types=frozenset({JSON_MIME_TYPE}),
        )
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise UpstreamError(f"{url}: invalid JSON") from exc
        if not isinstance(data, dict):
            raise UpstreamError(f"{url}: JSON response is not an object")
        return data

    def get_json_list(self, url: str) -> list[Any]:
        """Read an official JSON array without weakening transport checks."""

        text = self._get_text(
            url,
            accept=json_accept_header(url),
            allowed_content_types=frozenset({JSON_MIME_TYPE}),
        )
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise UpstreamError(f"{url}: invalid JSON") from exc
        if not isinstance(data, list):
            raise UpstreamError(f"{url}: JSON response is not an array")
        return data


def parse_sha256(text: str, expected_filename: str) -> str:
    if "<html" in text.lower() or "<!doctype html" in text.lower():
        raise UpstreamUnknown("official checksum response appears to be HTML")
    matches: list[str] = []
    matching_but_invalid = False
    gnu_line = re.compile(
        r"^\s*" + SHA256_CAPTURE_RE + r"[ \t]+\*?([^\s]+)\s*$",
        re.IGNORECASE,
    )
    bsd_line = re.compile(
        r"^\s*SHA256 \(([^)]+)\) = " + SHA256_CAPTURE_RE + r"\s*$",
        re.IGNORECASE,
    )
    for line in text.splitlines():
        gnu_match = gnu_line.fullmatch(line)
        bsd_match = bsd_line.fullmatch(line)
        if gnu_match and gnu_match.group(2) == expected_filename:
            matches.append(gnu_match.group(1).lower())
            continue
        if bsd_match and bsd_match.group(1) == expected_filename:
            matches.append(bsd_match.group(2).lower())
            continue
        if expected_filename in line:
            matching_but_invalid = True
    if matching_but_invalid:
        raise UpstreamUnknown(
            f"official checksum entry for {expected_filename} is malformed or uses an unsupported algorithm"
        )
    if not matches:
        raise UpstreamBlocked(f"official checksum did not name {expected_filename}")
    if len(matches) != 1:
        raise UpstreamBlocked(f"official checksum for {expected_filename} is ambiguous")
    return matches[0]


def fetch_sha256(client: HttpClient, checksum_url: str, expected_filename: str) -> str:
    get_checksum_text = getattr(client, "get_checksum_text", None)
    text = (
        get_checksum_text(checksum_url)
        if callable(get_checksum_text)
        else client.get_text(checksum_url)
    )
    return parse_sha256(text, expected_filename)


def latest_from_listing(
    html: str,
    filename_prefix: str,
    extension: str,
    current_version: str,
    restrict_to_current_series: bool,
) -> str:
    _, latest_compatible = latest_versions_from_listing(
        html,
        filename_prefix,
        extension,
        current_version,
        restrict_to_current_series,
    )
    return latest_compatible


def missing_variables_result(
    component: str,
    entries: dict[str, VariableEntry],
    variables: list[str],
) -> ComponentResult | None:
    missing = [name for name in variables if name not in entries]
    if not missing:
        return None
    return ComponentResult(
        component=component,
        status=STATUS_UNKNOWN,
        message=f"missing variables: {', '.join(missing)}",
        variables=variables,
    )


def is_expected_tarball_url(
    current_url: str,
    allowed_host: str,
    filename: str,
    source_path_prefix: str | None = None,
) -> bool:
    parsed = urlparse(current_url)
    return (
        parsed.scheme == "https"
        and parsed.hostname == allowed_host
        and parsed.port is None
        and parsed.username is None
        and parsed.password is None
        and not parsed.query
        and not parsed.fragment
        and parsed.path.endswith("/" + filename)
        and (source_path_prefix is None or parsed.path.startswith(source_path_prefix))
    )


def append_planned_update(
    updates: list[UpdateChange],
    entries: dict[str, VariableEntry],
    variable: str,
    new_default: str,
) -> None:
    update = plan_update(entries, variable, new_default)
    if update is not None:
        updates.append(update)


def collect_tarball_updates(
    entries: dict[str, VariableEntry],
    *,
    version_var: str,
    source_url_var: str,
    sha_var: str,
    sha_url_var: str,
    current_sha: str,
    latest_version: str,
    latest_url: str,
    latest_sha_url: str,
    latest_sha: str,
) -> list[UpdateChange]:
    updates: list[UpdateChange] = []
    append_planned_update(updates, entries, version_var, latest_version)
    if not default_transitively_depends_on(entries, source_url_var, version_var):
        append_planned_update(updates, entries, source_url_var, latest_url)
    if not default_transitively_depends_on(entries, sha_url_var, source_url_var):
        append_planned_update(updates, entries, sha_url_var, latest_sha_url)
    del current_sha
    # A literal digest is the integrity identity of this group.  Do not permit
    # the historical "new version, old digest" partial-plan failure mode.
    append_planned_update(updates, entries, sha_var, latest_sha)
    return updates


def official_tarball_check(
    component: str,
    entries: dict[str, VariableEntry],
    client: HttpClient,
    *,
    version_var: str,
    source_url_var: str,
    sha_var: str,
    sha_url_var: str,
    filename_prefix: str,
    extension: str,
    allowed_host: str,
    restrict_to_current_series: bool,
    source_path_prefix: str | None = None,
) -> ComponentResult:
    variables = [version_var, source_url_var, sha_var, sha_url_var]
    missing_result = missing_variables_result(component, entries, variables)
    if missing_result is not None:
        return missing_result

    current_version = value(entries, version_var)
    current_url = value(entries, source_url_var)
    current_sha = value(entries, sha_var)
    current_sha_url = value(entries, sha_url_var)
    filename = f"{filename_prefix}-{current_version}{extension}"
    if not is_expected_tarball_url(
        current_url,
        allowed_host,
        filename,
        source_path_prefix,
    ):
        return ComponentResult(
            component=component,
            status=STATUS_UNKNOWN,
            message=NO_SAFE_UPDATER_MESSAGE,
            variables=variables,
            current=current_version,
            source=current_url,
            details={"reason": "source URL is not the expected official tarball URL"},
        )

    expected_current_sha_url = current_url + SHA256_SUFFIX
    if current_sha_url != expected_current_sha_url:
        return ComponentResult(
            component=component,
            status=STATUS_UNKNOWN,
            message="Configured checksum URL is not bound to the configured official source asset.",
            variables=variables,
            current=current_version,
            source=current_url,
            details={
                "expected_sha256_url": expected_current_sha_url,
                "configured_sha256_url": current_sha_url,
            },
        )

    if SHA256_VALUE_RE.fullmatch(current_sha.lower()) is None:
        return ComponentResult(
            component=component,
            status=STATUS_UNKNOWN,
            message=f"{sha_var} must be a non-empty 64-character SHA-256 value.",
            variables=variables,
            current=current_version,
            source=current_url,
            details={"reason": "configured SHA-256 is missing or malformed"},
        )

    listing_url = current_url.rsplit("/", 1)[0] + "/"
    latest_upstream, latest_version = latest_versions_from_listing(
        client.get_text(listing_url),
        filename_prefix,
        extension,
        current_version,
        restrict_to_current_series,
    )
    latest_filename = f"{filename_prefix}-{latest_version}{extension}"
    latest_url = listing_url + latest_filename
    latest_sha_url = latest_url + SHA256_SUFFIX
    latest_sha = fetch_sha256(client, latest_sha_url, latest_filename)
    comparison = compare_versions(current_version, latest_version)

    if comparison > 0:
        return ComponentResult(
            component=component,
            status=STATUS_UNKNOWN,
            message="Configured version is newer than the official listing; refusing to guess.",
            variables=variables,
            current=current_version,
            latest=latest_version,
            latest_upstream=latest_upstream,
            latest_compatible=latest_version,
            source=listing_url,
        )

    if comparison < 0:
        updates = collect_tarball_updates(
            entries,
            version_var=version_var,
            source_url_var=source_url_var,
            sha_var=sha_var,
            sha_url_var=sha_url_var,
            current_sha=current_sha,
            latest_version=latest_version,
            latest_url=latest_url,
            latest_sha_url=latest_sha_url,
            latest_sha=latest_sha,
        )
        return ComponentResult(
            component=component,
            status=STATUS_OUTDATED,
            message="A newer official tarball is available.",
            variables=variables,
            current=current_version,
            latest=latest_version,
            latest_upstream=latest_upstream,
            latest_compatible=latest_version,
            source=listing_url,
            asset_name=latest_filename,
            official_sha256=latest_sha,
            sha256_source="official_asset_sha256_file",
            updates=updates,
            details={
                "latest_source_url": latest_url,
                "latest_sha256_url": latest_sha_url,
                "latest_sha256": latest_sha,
                "latest_upstream": latest_upstream,
                "latest_compatible": latest_version,
                "compatibility_review_required": latest_upstream != latest_version,
            },
        )

    official_current_sha = fetch_sha256(
        client,
        expected_current_sha_url,
        filename,
    )
    if current_sha and current_sha.lower() != official_current_sha:
        updates: list[UpdateChange] = []
        append_planned_update(updates, entries, sha_var, official_current_sha)
        return ComponentResult(
            component=component,
            status=STATUS_OUTDATED,
            message="Configured checksum differs from the official checksum.",
            variables=variables,
            current=current_version,
            latest=latest_version,
            latest_upstream=latest_upstream,
            latest_compatible=latest_version,
            source=listing_url,
            asset_name=filename,
            official_sha256=official_current_sha,
            sha256_source="official_asset_sha256_file",
            updates=updates,
            details={
                "official_sha256": official_current_sha,
                "configured_sha256": current_sha,
            },
        )

    return ComponentResult(
        component=component,
        status=STATUS_CURRENT,
        message="Version and official checksum source are current.",
        variables=variables,
        current=current_version,
        latest=latest_version,
        latest_upstream=latest_upstream,
        latest_compatible=latest_version,
        source=listing_url,
        asset_name=filename,
        official_sha256=official_current_sha,
        sha256_source="official_asset_sha256_file",
        details={
            "sha256_mode": "literal" if current_sha else "sha256_url",
            "official_sha256": official_current_sha,
            "latest_upstream": latest_upstream,
            "latest_compatible": latest_version,
            "compatibility_review_required": latest_upstream != latest_version,
        },
    )


def check_apr_util_release_provenance(
    entries: dict[str, VariableEntry], client: HttpClient
) -> ComponentResult:
    """Resolve one APR-util version/digest group from official Apache files."""

    return official_tarball_check(
        "APR-util",
        entries,
        client,
        version_var="APR_UTIL_VERSION",
        source_url_var="APR_UTIL_SOURCE_URL",
        sha_var="APR_UTIL_SHA256",
        sha_url_var="APR_UTIL_SHA256_URL",
        filename_prefix="apr-util",
        extension=ARCHIVE_BZ2_EXTENSION,
        allowed_host=APACHE_DOWNLOAD_HOST,
        restrict_to_current_series=True,
        source_path_prefix=APACHE_APR_SOURCE_PATH_PREFIX,
    )


def haproxy_source_series(current_url: str, current_version: str) -> str | None:
    match = re.fullmatch(
        rf"https://{HAPROXY_WEB_HOST_RE}/download/(\d+\.\d+)/src/haproxy-(\d+\.\d+\.\d+){re.escape(TAR_GZ_EXTENSION)}",
        current_url,
    )
    if match is None or match.group(2) != current_version:
        return None
    return match.group(1)


def _is_official_haproxy_root(root: str) -> bool:
    try:
        parsed = urlparse(root)
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and parsed.hostname == HAPROXY_WEB_HOST
        and parsed.username is None
        and parsed.password is None
        and port is None
        and parsed.path == "/download"
        and not parsed.query
        and not parsed.fragment
    )


def _check_haproxy_listing(
    entries: dict[str, VariableEntry],
    client: HttpClient,
    variables: list[str],
    current_version: str,
    current_sha_url: str,
    configured_sha: str,
    series_base: str,
) -> ComponentResult:
    listing_url = f"{series_base}/"
    latest_upstream, latest_version = latest_versions_from_listing(
        client.get_text(listing_url),
        "haproxy",
        TAR_GZ_EXTENSION,
        current_version,
        restrict_to_current_series=True,
    )
    latest_filename = f"haproxy-{latest_version}{TAR_GZ_EXTENSION}"
    latest_url = f"{listing_url}{latest_filename}"
    latest_sha_url = latest_url + SHA256_SUFFIX
    latest_sha = fetch_sha256(client, latest_sha_url, latest_filename)
    comparison = compare_versions(current_version, latest_version)
    if comparison > 0:
        return ComponentResult(
            component="HAProxy",
            status=STATUS_UNKNOWN,
            message="Configured version is newer than the official HAProxy series listing; refusing to guess.",
            variables=variables,
            current=current_version,
            latest=latest_version,
            latest_upstream=latest_upstream,
            latest_compatible=latest_version,
            source=listing_url,
        )
    if comparison < 0:
        updates = collect_tarball_updates(
            entries,
            version_var="HAPROXY_VERSION",
            source_url_var="HAPROXY_SOURCE_URL",
            sha_var="HAPROXY_SHA256",
            sha_url_var="HAPROXY_SHA256_URL",
            current_sha=configured_sha,
            latest_version=latest_version,
            latest_url=latest_url,
            latest_sha_url=latest_sha_url,
            latest_sha=latest_sha,
        )
        return ComponentResult(
            component="HAProxy",
            status=STATUS_OUTDATED,
            message="A newer official HAProxy tarball and checksum are available.",
            variables=variables,
            current=current_version,
            latest=latest_version,
            latest_upstream=latest_upstream,
            latest_compatible=latest_version,
            source=listing_url,
            asset_name=latest_filename,
            official_sha256=latest_sha,
            sha256_source="official_asset_sha256_file",
            updates=updates,
            details={
                "latest_source_url": latest_url,
                "latest_sha256_url": latest_sha_url,
                "latest_sha256": latest_sha,
                "latest_upstream": latest_upstream,
                "latest_compatible": latest_version,
                "compatibility_review_required": latest_upstream != latest_version,
            },
        )
    official_current_sha = fetch_sha256(
        client, current_sha_url, f"haproxy-{current_version}{TAR_GZ_EXTENSION}"
    )
    if configured_sha != official_current_sha:
        updates: list[UpdateChange] = []
        append_planned_update(updates, entries, "HAPROXY_SHA256", official_current_sha)
        return ComponentResult(
            component="HAProxy",
            status=STATUS_OUTDATED,
            message="Configured HAProxy checksum differs from the official checksum.",
            variables=variables,
            current=current_version,
            latest=latest_version,
            latest_upstream=latest_upstream,
            latest_compatible=latest_version,
            source=listing_url,
            asset_name=f"haproxy-{current_version}{TAR_GZ_EXTENSION}",
            official_sha256=official_current_sha,
            sha256_source="official_asset_sha256_file",
            updates=updates,
            details={
                "official_sha256": official_current_sha,
                "configured_sha256": configured_sha,
            },
        )
    return ComponentResult(
        component="HAProxy",
        status=STATUS_CURRENT,
        message="Version and official checksum are current for the configured HAProxy series.",
        variables=variables,
        current=current_version,
        latest=latest_version,
        latest_upstream=latest_upstream,
        latest_compatible=latest_version,
        source=listing_url,
        asset_name=f"haproxy-{current_version}{TAR_GZ_EXTENSION}",
        official_sha256=official_current_sha,
        sha256_source="official_asset_sha256_file",
        details={
            "official_sha256": official_current_sha,
            "latest_upstream": latest_upstream,
            "latest_compatible": latest_version,
            "compatibility_review_required": latest_upstream != latest_version,
        },
    )


def check_haproxy(
    entries: dict[str, VariableEntry], client: HttpClient
) -> ComponentResult:
    variables = list(COMPONENT_DEFINITION_BY_NAME["HAProxy"].variables)
    missing_result = missing_variables_result("HAProxy", entries, variables)
    if missing_result is not None:
        return missing_result
    current_version = value(entries, "HAPROXY_VERSION")
    current_url = value(entries, "HAPROXY_SOURCE_URL")
    configured_sha = value(entries, "HAPROXY_SHA256").lower()
    current_sha_url = value(entries, "HAPROXY_SHA256_URL")
    series = value(entries, "HAPROXY_SERIES")
    release_root = value(entries, "HAPROXY_RELEASE_ROOT_URL")
    series_base = value(entries, "HAPROXY_SERIES_BASE_URL")
    htx_series = value(entries, "HAPROXY_HTX_SERIES")
    htx_series_base = value(entries, "HAPROXY_HTX_SERIES_BASE_URL")
    htx_version = value(entries, "HAPROXY_HTX_VERSION")
    htx_archive = value(entries, "HAPROXY_HTX_ARCHIVE_NAME")
    htx_url = value(entries, "HAPROXY_HTX_SOURCE_URL")
    if (
        VERSION_PAIR_RE.fullmatch(series) is None
        or VERSION_PAIR_RE.fullmatch(htx_series) is None
    ):
        return ComponentResult(
            component="HAProxy",
            status=STATUS_BLOCKED,
            message="HAProxy series pins must be numeric major.minor values.",
            variables=variables,
            current=current_version,
        )
    if not _is_official_haproxy_root(release_root):
        return ComponentResult(
            component="HAProxy",
            status=STATUS_UNKNOWN,
            message="HAPROXY_RELEASE_ROOT_URL is not the authorized official root.",
            variables=variables,
            current=current_version,
            source=release_root,
        )
    expected_base = f"{release_root}/{series}/src"
    expected_htx_base = f"{release_root}/{htx_series}/src"
    if series_base != expected_base or htx_series_base != expected_htx_base:
        return ComponentResult(
            component="HAProxy",
            status=STATUS_UNKNOWN,
            message="HAProxy series base URLs are not derived from their explicit series pins.",
            variables=variables,
            current=current_version,
            details={
                "expected_series_base_url": expected_base,
                "expected_htx_series_base_url": expected_htx_base,
            },
        )
    expected_htx_archive = f"haproxy-{htx_version}{TAR_GZ_EXTENSION}"
    if (
        htx_archive != expected_htx_archive
        or htx_url != f"{htx_series_base}/{htx_archive}"
    ):
        return ComponentResult(
            component="HAProxy",
            status=STATUS_UNKNOWN,
            message="HAProxy HTX source tuple is not bound to its independent series and asset.",
            variables=variables,
            current=current_version,
            source=htx_url,
        )
    if version_tuple(current_version)[:2] != version_tuple(series) or version_tuple(
        htx_version
    )[:2] != version_tuple(htx_series):
        return ComponentResult(
            component="HAProxy",
            status=STATUS_UNKNOWN,
            message="HAProxy version pins are outside their explicitly configured series.",
            variables=variables,
            current=current_version,
        )
    if haproxy_source_series(current_url, current_version) != series:
        return ComponentResult(
            component="HAProxy",
            status=STATUS_UNKNOWN,
            message=NO_SAFE_UPDATER_MESSAGE,
            variables=variables,
            current=current_version,
            source=current_url,
            details={
                "reason": "source URL is not the expected official HAProxy tarball URL"
            },
        )
    if not configured_sha:
        return ComponentResult(
            component="HAProxy",
            status=STATUS_BLOCKED,
            message="HAPROXY_SHA256 is required for safe HAProxy updates.",
            variables=variables,
            current=current_version,
            source=current_url,
        )
    if SHA256_VALUE_RE.fullmatch(configured_sha) is None:
        return ComponentResult(
            component="HAProxy",
            status=STATUS_BLOCKED,
            message="HAPROXY_SHA256 must be a 64-character SHA-256 value.",
            variables=variables,
            current=current_version,
            source=current_url,
        )
    configured_htx_sha = value(entries, "HAPROXY_HTX_SHA256").lower()
    if SHA256_VALUE_RE.fullmatch(configured_htx_sha) is None:
        return ComponentResult(
            component="HAProxy",
            status=STATUS_BLOCKED,
            message="HAPROXY_HTX_SHA256 must be a 64-character SHA-256 value.",
            variables=variables,
            current=current_version,
            source=htx_url,
        )
    expected_current_sha_url = current_url + SHA256_SUFFIX
    if current_sha_url != expected_current_sha_url:
        return ComponentResult(
            component="HAProxy",
            status=STATUS_UNKNOWN,
            message="Configured HAProxy checksum URL is not bound to the configured official source asset.",
            variables=variables,
            current=current_version,
            source=current_url,
            details={
                "expected_sha256_url": expected_current_sha_url,
                "configured_sha256_url": current_sha_url,
            },
        )

    return _check_haproxy_listing(
        entries,
        client,
        variables,
        current_version,
        current_sha_url,
        configured_sha,
        series_base,
    )


def check_haproxy_htx(
    entries: dict[str, VariableEntry], client: HttpClient
) -> ComponentResult:
    """Verify the HTX tarball as an independently owned canonical tuple."""

    definition = COMPONENT_DEFINITION_BY_NAME["HAProxy HTX"]
    missing = required_component_variables(definition, entries)
    if missing is not None:
        return missing
    root = value(entries, "HAPROXY_RELEASE_ROOT_URL")
    series = value(entries, "HAPROXY_HTX_SERIES")
    base = value(entries, "HAPROXY_HTX_SERIES_BASE_URL")
    version = value(entries, "HAPROXY_HTX_VERSION")
    archive = value(entries, "HAPROXY_HTX_ARCHIVE_NAME")
    source = value(entries, "HAPROXY_HTX_SOURCE_URL")
    configured_sha = value(entries, "HAPROXY_HTX_SHA256").lower()
    if VERSION_PAIR_RE.fullmatch(series) is None:
        return ComponentResult(
            component=definition.name,
            status=STATUS_BLOCKED,
            message="HAProxy HTX series pin must be numeric major.minor.",
            variables=list(definition.variables),
            current=version,
        )
    if not _is_official_haproxy_root(root) or base != f"{root}/{series}/src":
        return ComponentResult(
            component=definition.name,
            status=STATUS_UNKNOWN,
            message="HAProxy HTX URLs are not derived from the official root and series.",
            variables=list(definition.variables),
            current=version,
            source=source,
        )
    expected_archive = f"haproxy-{version}{TAR_GZ_EXTENSION}"
    expected_source = f"{base}/{expected_archive}"
    if archive != expected_archive or source != expected_source:
        return ComponentResult(
            component=definition.name,
            status=STATUS_UNKNOWN,
            message="HAProxy HTX source tuple is not bound to its independent series and asset.",
            variables=list(definition.variables),
            current=version,
            source=source,
        )
    if (
        version_tuple(version)[:2] != version_tuple(series)
        or SHA256_VALUE_RE.fullmatch(configured_sha) is None
    ):
        return ComponentResult(
            component=definition.name,
            status=STATUS_BLOCKED,
            message="HAProxy HTX version or checksum is invalid.",
            variables=list(definition.variables),
            current=version,
            source=source,
        )
    listing_url = f"{base}/"
    latest_upstream, latest_version = latest_versions_from_listing(
        client.get_text(listing_url),
        "haproxy",
        TAR_GZ_EXTENSION,
        version,
        restrict_to_current_series=True,
    )
    latest_asset = f"haproxy-{latest_version}{TAR_GZ_EXTENSION}"
    latest_url = f"{base}/{latest_asset}"
    latest_sha_url = latest_url + SHA256_SUFFIX
    latest_sha = fetch_sha256(client, latest_sha_url, latest_asset)
    comparison = compare_versions(version, latest_version)
    if comparison > 0:
        raise UpstreamUnknown(
            "configured HAProxy HTX version is newer than the official series listing"
        )
    if comparison < 0:
        updates = collect_tarball_updates(
            entries,
            version_var="HAPROXY_HTX_VERSION",
            source_url_var="HAPROXY_HTX_SOURCE_URL",
            sha_var="HAPROXY_HTX_SHA256",
            sha_url_var="HAPROXY_HTX_SOURCE_URL",
            current_sha=configured_sha,
            latest_version=latest_version,
            latest_url=latest_url,
            latest_sha_url=latest_sha_url,
            latest_sha=latest_sha,
        )
        return ComponentResult(
            component=definition.name,
            status=STATUS_OUTDATED,
            message="A newer official HAProxy HTX tarball and checksum are available.",
            variables=list(definition.variables),
            current=version,
            latest=latest_version,
            latest_upstream=latest_upstream,
            latest_compatible=latest_version,
            source=listing_url,
            asset_name=latest_asset,
            official_sha256=latest_sha,
            sha256_source="official_asset_sha256_file",
            updates=updates,
        )
    official_sha = fetch_sha256(
        client, value(entries, "HAPROXY_HTX_SOURCE_URL") + SHA256_SUFFIX, archive
    )
    if configured_sha != official_sha:
        update = plan_update(entries, "HAPROXY_HTX_SHA256", official_sha)
        return ComponentResult(
            component=definition.name,
            status=STATUS_OUTDATED,
            message="Configured HAProxy HTX checksum differs from the official checksum.",
            variables=list(definition.variables),
            current=version,
            latest=latest_version,
            official_sha256=official_sha,
            updates=[update] if update else [],
        )
    return ComponentResult(
        component=definition.name,
        status=STATUS_CURRENT,
        message="HAProxy HTX release and official checksum are current.",
        variables=list(definition.variables),
        current=version,
        latest=latest_version,
    )


def github_repo_path(repo_url: str) -> str | None:
    parsed = urlparse(repo_url.strip())
    if (
        parsed.scheme != "https"
        or parsed.netloc != GITHUB_WEB_HOST
        or parsed.query
        or parsed.fragment
    ):
        return None
    repo = parsed.path.removeprefix("/").removesuffix(".git").strip("/")
    parts = repo.split("/")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        return None
    return f"{parts[0]}/{parts[1]}"


def canonicalize_github_repository(
    definition: ComponentDefinition, entries: dict[str, VariableEntry]
) -> ComponentDefinition:
    """Bind neutral descriptors to the repository URL parsed from common.sh."""

    if definition.github_repository != CANONICAL_REPOSITORY_MARKER:
        return definition
    source_variable = definition.source_url_variable
    source_url = value(entries, source_variable) if source_variable else ""
    if not source_url:
        for candidate in definition.variables:
            if candidate.endswith(("_REPO_URL", "_GIT_URL")):
                source_url = value(entries, candidate)
                if source_url:
                    break
    repository = github_repo_path(source_url)
    if repository is None:
        raise UpstreamUnknown(
            f"{definition.name} canonical repository URL is not an official GitHub URL"
        )
    updated_definition = dataclasses.replace(definition, github_repository=repository)
    return cast(ComponentDefinition, updated_definition)


def latest_github_release(client: HttpClient, repo_path: str) -> dict[str, Any]:
    return client.get_json(f"{GITHUB_API_ORIGIN}/repos/{repo_path}/releases/latest")


def github_release_by_tag(
    client: HttpClient, repo_path: str, tag: str
) -> dict[str, Any]:
    return client.get_json(f"{GITHUB_API_ORIGIN}/repos/{repo_path}/releases/tags/{tag}")


def release_tag_name(release: dict[str, Any], repo_path: str) -> str:
    tag = release.get("tag_name")
    if not isinstance(tag, str) or not tag.strip():
        raise UpstreamUnknown(
            f"GitHub latest release for {repo_path} did not include tag_name"
        )
    tag = tag.strip()
    if not SAFE_REF_RE.fullmatch(tag):
        raise UpstreamError(
            f"GitHub release tag for {repo_path} is not shell-safe: {tag!r}"
        )
    return tag


def check_github_release_ref(
    component: str,
    entries: dict[str, VariableEntry],
    client: HttpClient,
    *,
    repo_var: str,
    ref_var: str,
) -> ComponentResult:
    variables = [repo_var, ref_var]
    repo_url = value(entries, repo_var)
    current_ref = value(entries, ref_var)
    if not repo_url or not current_ref:
        return ComponentResult(
            component=component,
            status=STATUS_UNKNOWN,
            message=NO_SAFE_UPDATER_MESSAGE,
            variables=variables,
            current=current_ref,
            source=repo_url,
            details={"reason": "repository URL or ref is empty"},
        )
    if (
        not SAFE_REF_RE.fullmatch(current_ref)
        or current_ref in {"latest", "master", "main"}
        or "/" in current_ref
    ):
        return ComponentResult(
            component=component,
            status=STATUS_UNKNOWN,
            message=NO_SAFE_UPDATER_MESSAGE,
            variables=variables,
            current=current_ref,
            source=repo_url,
            details={
                "reason": "ref is branch-like or dynamic, not a concrete release tag"
            },
        )
    repo_path = github_repo_path(repo_url)
    if not repo_path:
        return ComponentResult(
            component=component,
            status=STATUS_UNKNOWN,
            message=NO_SAFE_UPDATER_MESSAGE,
            variables=variables,
            current=current_ref,
            source=repo_url,
            details={
                "reason": "repository URL is not an official github.com owner/repo URL"
            },
        )
    latest_ref = require_stable_github_release(
        latest_github_release(client, repo_path), repo_path, ""
    )
    comparison = compare_versions(current_ref, latest_ref)
    if comparison > 0:
        return ComponentResult(
            component=component,
            status=STATUS_UNKNOWN,
            message="Configured ref is newer than the latest GitHub release; refusing to guess.",
            variables=variables,
            current=current_ref,
            latest=latest_ref,
            source=f"https://github.com/{repo_path}",
        )
    if comparison < 0:
        updates: list[UpdateChange] = []
        update = plan_update(entries, ref_var, latest_ref)
        if update:
            updates.append(update)
        return ComponentResult(
            component=component,
            status=STATUS_OUTDATED,
            message="A newer official GitHub release tag is available.",
            variables=variables,
            current=current_ref,
            latest=latest_ref,
            source=f"https://github.com/{repo_path}/releases/latest",
            updates=updates,
        )
    return ComponentResult(
        component=component,
        status=STATUS_CURRENT,
        message="Release tag is current.",
        variables=variables,
        current=current_ref,
        latest=latest_ref,
        source=f"https://github.com/{repo_path}/releases/latest",
    )


def manual_release_provenance_precondition(
    component: str,
    entries: dict[str, VariableEntry],
    *,
    expected_repository: str,
    release_tag_var: str,
    approved_commit_var: str,
    expected_tag: re.Pattern[str],
    aliases: dict[str, str],
    variables: list[str],
) -> ComponentResult | None:
    """Validate the fixed tuple before deferring an atomic manual decision."""

    repository_var = next(name for name in variables if name.endswith("_REPO_URL"))
    repository_url = value(entries, repository_var)
    current_tag = value(entries, release_tag_var)
    if github_repo_path(repository_url) != expected_repository:
        return ComponentResult(
            component=component,
            status=STATUS_UNKNOWN,
            message="Reviewed release provenance must use its fixed official repository.",
            variables=variables,
            current=current_tag,
            source=repository_url,
            details={
                "reason": "approved repository does not match the reviewed identity"
            },
        )
    if expected_tag.fullmatch(current_tag) is None:
        return ComponentResult(
            component=component,
            status=STATUS_UNKNOWN,
            message="Reviewed release provenance must use its expected immutable release-tag form.",
            variables=variables,
            current=current_tag,
            source=repository_url,
            details={
                "reason": "release tag is not in the reviewed component-specific form"
            },
        )
    approved_commit = value(entries, approved_commit_var)
    if GIT_COMMIT_SHA1_RE.fullmatch(approved_commit) is None:
        return ComponentResult(
            component=component,
            status=STATUS_BLOCKED,
            message=f"{approved_commit_var} must be a reviewed 40-hex immutable commit.",
            variables=variables,
            current=current_tag,
            source=repository_url,
            details={
                "reason": f"{approved_commit_var} is required before release provenance can be checked"
            },
        )
    for alias, expected_value in aliases.items():
        if value(entries, alias) != expected_value:
            return ComponentResult(
                component=component,
                status=STATUS_UNKNOWN,
                message="Runtime release metadata must remain bound to the reviewed provenance tuple.",
                variables=variables,
                current=current_tag,
                source=repository_url,
                details={
                    "reason": f"{alias} does not match its reviewed provenance value"
                },
            )
    return None


def resolve_github_peeled_commit(client: HttpClient, repo_path: str, tag: str) -> str:
    """Resolve lightweight or annotated tags to one immutable commit SHA."""

    if not SAFE_REF_RE.fullmatch(tag):
        raise UpstreamUnknown(f"unsafe release tag cannot be resolved: {tag!r}")
    payload = client.get_json(
        f"{GITHUB_API_ORIGIN}/repos/{repo_path}/git/ref/tags/{quote(tag, safe='')}"
    )
    for _ in range(4):
        target = payload.get("object")
        if not isinstance(target, dict):
            raise UpstreamUnknown("GitHub tag response did not include an object")
        object_type = target.get("type")
        object_sha = target.get("sha")
        if (
            not isinstance(object_sha, str)
            or GIT_COMMIT_SHA1_RE.fullmatch(object_sha) is None
        ):
            raise UpstreamUnknown(
                "GitHub tag response did not include a 40-hex object SHA"
            )
        if object_type == "commit":
            return object_sha
        if object_type != "tag":
            raise UpstreamUnknown(
                "GitHub tag object is neither a commit nor an annotated tag"
            )
        payload = client.get_json(
            f"{GITHUB_API_ORIGIN}/repos/{repo_path}/git/tags/{object_sha}"
        )
    raise UpstreamUnknown(
        "GitHub annotated tag chain exceeded the safe resolution limit"
    )


def check_manual_git_provenance(
    definition: ComponentDefinition,
    entries: dict[str, VariableEntry],
    client: HttpClient,
) -> ComponentResult:
    """Report manual tag/peeled-commit transitions without weakening pins."""

    release_tag_var = cast(str, definition.release_tag_variable)
    commit_var = cast(str, definition.git_commit_variable)
    expected_tag = re.compile(definition.tag_pattern)
    aliases = {
        alias: value(entries, expected_variable)
        for alias, expected_variable in definition.alias_bindings
    }
    precondition = manual_release_provenance_precondition(
        definition.name,
        entries,
        expected_repository=cast(str, definition.github_repository),
        release_tag_var=release_tag_var,
        approved_commit_var=commit_var,
        expected_tag=expected_tag,
        aliases=aliases,
        variables=list(definition.variables),
    )
    if precondition is not None:
        return precondition
    current_tag = value(entries, release_tag_var)
    current_commit = value(entries, commit_var)
    resolved_current_commit = resolve_github_peeled_commit(
        client, cast(str, definition.github_repository), current_tag
    )
    if resolved_current_commit != current_commit:
        return ComponentResult(
            component=definition.name,
            status=STATUS_UNKNOWN,
            message="Configured immutable commit does not equal the configured release tag's peeled commit.",
            variables=list(definition.variables),
            current=current_tag,
            source=f"https://github.com/{definition.github_repository}",
            details={
                "configured_commit": current_commit,
                "resolved_peeled_commit": resolved_current_commit,
            },
        )
    latest_release = latest_github_release(
        client, cast(str, definition.github_repository)
    )
    latest_tag = require_stable_github_release(
        latest_release, cast(str, definition.github_repository), definition.tag_pattern
    )
    latest_commit = resolve_github_peeled_commit(
        client, cast(str, definition.github_repository), latest_tag
    )
    comparison = compare_versions(current_tag, latest_tag)
    if comparison > 0:
        return ComponentResult(
            component=definition.name,
            status=STATUS_UNKNOWN,
            message="Configured release tag is newer than the latest stable official release; refusing to guess.",
            variables=list(definition.variables),
            current=current_tag,
            latest=latest_tag,
            latest_upstream=latest_tag,
            latest_compatible=latest_tag,
            source=f"https://github.com/{definition.github_repository}/releases/latest",
        )
    if comparison < 0:
        manual_variables = MANUAL_REVIEW_VARIABLES[definition.name]
        return ComponentResult(
            component=definition.name,
            status=STATUS_REVIEW_REQUIRED,
            message=(
                f"A newer {definition.name} release is available, but its release tag and "
                "immutable peeled commit require a reviewed provenance change."
            ),
            variables=list(definition.variables),
            current=current_tag,
            latest=latest_tag,
            latest_upstream=latest_tag,
            latest_compatible=latest_tag,
            source=f"https://github.com/{definition.github_repository}/releases/latest",
            official_sha256=latest_commit,
            sha256_source="peeled_git_tag_commit",
            details={
                "reason": (
                    f"update {release_tag_var} and {commit_var} together after "
                    "peeled-commit provenance review"
                ),
                "manual_variables": list(manual_variables),
                "current_peeled_commit": resolved_current_commit,
                "latest_peeled_commit": latest_commit,
            },
        )
    return ComponentResult(
        component=definition.name,
        status=STATUS_CURRENT,
        message="Configured release tag and immutable peeled commit are current.",
        variables=list(definition.variables),
        current=current_tag,
        latest=latest_tag,
        latest_upstream=latest_tag,
        latest_compatible=latest_tag,
        source=f"https://github.com/{definition.github_repository}/releases/latest",
        official_sha256=resolved_current_commit,
        sha256_source="peeled_git_tag_commit",
        details={"peeled_commit": resolved_current_commit},
    )


def review_required_release_result(
    result: ComponentResult,
    *,
    expected_tag: re.Pattern[str],
    manual_variables: tuple[str, ...],
    message: str,
    reason: str,
) -> ComponentResult:
    """Convert only a validated newer tag into an explicit manual review state."""

    if result.status != STATUS_OUTDATED:
        return result
    if expected_tag.fullmatch(result.latest) is None:
        return cast(
            ComponentResult,
            dataclasses.replace(
                result,
                status=STATUS_UNKNOWN,
                updates=[],
                message="Latest upstream release tag is outside the reviewed component-specific form.",
                details={
                    "reason": "latest release tag is outside the reviewed update contract"
                },
            ),
        )
    return cast(
        ComponentResult,
        dataclasses.replace(
            result,
            status=STATUS_REVIEW_REQUIRED,
            updates=[],
            message=message,
            details={"reason": reason, "manual_variables": list(manual_variables)},
        ),
    )


def check_crs_release_provenance(
    entries: dict[str, VariableEntry], client: HttpClient
) -> ComponentResult:
    """Classify a valid CRS tag/commit transition as explicitly manual only."""
    # Keep the reviewed repository identity derived from the canonical URL in
    # common.sh.  The descriptor deliberately carries only a neutral marker;
    # resolving it here also protects direct callers of this helper (rather
    # than only the generic component dispatcher) from a second repository
    # literal or an unbound alias.
    definition = canonicalize_github_repository(
        COMPONENT_DEFINITION_BY_NAME[CRS_COMPONENT], entries
    )
    return check_manual_git_provenance(definition, entries, client)


def check_modsecurity_v3_release_provenance(
    entries: dict[str, VariableEntry], client: HttpClient
) -> ComponentResult:
    """Classify a valid ModSecurity-v3 tag/commit transition as manual only."""
    base_definition = COMPONENT_DEFINITION_BY_NAME[MODSECURITY_V3_COMPONENT]
    try:
        definition = canonicalize_github_repository(base_definition, entries)
    except UpstreamUnknown as exc:
        return ComponentResult(
            component=base_definition.name,
            status=STATUS_UNKNOWN,
            message=str(exc),
            variables=list(base_definition.variables),
        )
    repository = cast(str, definition.github_repository)
    if (
        hashlib.sha256(repository.encode("ascii")).hexdigest()
        != MODSECURITY_V3_APPROVED_REPOSITORY_SHA256
    ):
        return ComponentResult(
            component=base_definition.name,
            status=STATUS_UNKNOWN,
            message="ModSecurity v3 canonical repository identity is not approved.",
            variables=list(base_definition.variables),
            source=value(entries, "MODSECURITY_V3_APPROVED_REPO_URL"),
        )
    return check_manual_git_provenance(definition, entries, client)


def release_asset_metadata(release: dict[str, Any], asset_name: str) -> dict[str, Any]:
    assets = release.get("assets")
    if not isinstance(assets, list):
        raise UpstreamUnknown("GitHub release response did not include an assets list")
    matches: list[dict[str, Any]] = []
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        if asset.get("name") == asset_name:
            matches.append(asset)
    if not matches:
        raise UpstreamUnknown(f"GitHub release did not include asset {asset_name}")
    if len(matches) != 1:
        raise UpstreamUnknown(f"GitHub release asset {asset_name} is ambiguous")
    return matches[0]


def find_release_asset(release: dict[str, Any], asset_name: str) -> str:
    asset = release_asset_metadata(release, asset_name)
    url = asset.get("browser_download_url")
    if not isinstance(url, str) or not url:
        raise UpstreamUnknown(
            f"GitHub release asset {asset_name} has no browser download URL"
        )
    return url


def release_asset_sha256(release: dict[str, Any], asset_name: str) -> str:
    asset = release_asset_metadata(release, asset_name)
    digest = asset.get("digest")
    if not isinstance(digest, str):
        raise UpstreamUnknown(
            f"GitHub release asset {asset_name} has no published digest"
        )
    match = re.fullmatch(r"sha256:([A-Fa-f0-9]{64})", digest.strip())
    if not match:
        raise UpstreamUnknown(
            f"GitHub release asset {asset_name} has no usable SHA-256 digest"
        )
    return match.group(1).lower()


def expected_github_asset_url(repo_path: str, tag: str, asset_name: str) -> str:
    if not SAFE_REF_RE.fullmatch(tag) or not SAFE_ASSET_NAME_RE.fullmatch(asset_name):
        raise UpstreamError("GitHub release tag or asset name is not shell-safe")
    return (
        f"{GITHUB_WEB_ORIGIN}/{repo_path}/releases/download/"
        f"{quote(tag, safe='')}/{quote(asset_name, safe='')}"
    )


def verified_release_asset_url(
    release: dict[str, Any], repo_path: str, tag: str, asset_name: str
) -> str:
    actual_url = find_release_asset(release, asset_name)
    expected_url = expected_github_asset_url(repo_path, tag, asset_name)
    if actual_url != expected_url:
        raise UpstreamUnknown(
            f"GitHub release asset {asset_name} URL does not bind the expected "
            "repository, tag, and asset"
        )
    return actual_url


def require_stable_github_release(
    release: dict[str, Any],
    repo_path: str,
    tag_pattern: str,
) -> str:
    """Reject draft/prerelease metadata even when GitHub's endpoint filters it."""

    if release.get("draft") is True or release.get("prerelease") is True:
        raise UpstreamUnknown(
            f"GitHub latest release for {repo_path} is draft or prerelease"
        )
    tag = release_tag_name(release, repo_path)
    if tag_pattern and re.fullmatch(tag_pattern, tag) is None:
        raise UpstreamUnknown(
            f"GitHub release tag {tag!r} is outside the component stable-release policy"
        )
    return tag


def release_version_from_tag(definition: ComponentDefinition, tag: str) -> str:
    if definition.tag_pattern and re.fullmatch(definition.tag_pattern, tag) is None:
        raise UpstreamUnknown(
            f"{definition.name} release tag {tag!r} is outside its declared stable policy"
        )
    if definition.tag_prefix and not tag.startswith(definition.tag_prefix):
        raise UpstreamUnknown(
            f"{definition.name} release tag does not use its declared prefix: {tag!r}"
        )
    version = tag.removeprefix(definition.tag_prefix)
    if not is_stable_version(version):
        raise UpstreamUnknown(
            f"{definition.name} release tag does not contain a stable numeric version: {tag!r}"
        )
    return version


def release_tag_from_component(
    definition: ComponentDefinition, entries: dict[str, VariableEntry]
) -> str:
    if definition.release_tag_variable:
        tag = value(entries, definition.release_tag_variable)
    elif definition.version_variable:
        version = value(entries, definition.version_variable)
        if not is_stable_version(version):
            raise UpstreamUnknown(
                f"{definition.version_variable} must be a stable numeric version"
            )
        tag = f"{definition.tag_prefix}{version}"
    else:
        raise UpstreamError(f"{definition.name} has no release identity variable")
    if not SAFE_REF_RE.fullmatch(tag) or tag in {"latest", "main", "master"}:
        raise UpstreamUnknown(
            f"{definition.name} release identity is branch-like or unsafe: {tag!r}"
        )
    if definition.tag_pattern and re.fullmatch(definition.tag_pattern, tag) is None:
        raise UpstreamUnknown(
            f"{definition.name} release identity does not match its stable tag policy: {tag!r}"
        )
    return tag


def release_asset_name(
    definition: ComponentDefinition,
    version: str,
    entries: dict[str, VariableEntry] | None = None,
) -> str:
    if not definition.asset_template:
        raise UpstreamError(f"{definition.name} has no release asset template")
    platform = (
        value(entries, definition.asset_platform_variable)
        if entries is not None and definition.asset_platform_variable
        else ""
    )
    if definition.asset_platform_variable and not platform:
        raise UpstreamUnknown(
            f"{definition.name} canonical artifact platform is missing"
        )
    asset_name = definition.asset_template.format(version=version, platform=platform)
    if not SAFE_ASSET_NAME_RE.fullmatch(asset_name):
        raise UpstreamError(
            f"{definition.name} asset template rendered an unsafe filename: {asset_name!r}"
        )
    return asset_name


def release_checksum_asset_name(definition: ComponentDefinition, version: str) -> str:
    if not definition.checksum_asset_template:
        raise UpstreamError(f"{definition.name} has no checksum asset template")
    asset_name = definition.checksum_asset_template.format(version=version)
    if not SAFE_ASSET_NAME_RE.fullmatch(asset_name):
        raise UpstreamError(
            f"{definition.name} checksum template rendered an unsafe filename: {asset_name!r}"
        )
    return asset_name


def github_release_checksum(
    definition: ComponentDefinition,
    release: dict[str, Any],
    client: HttpClient,
    *,
    repo_path: str,
    tag: str,
    version: str,
    asset_name: str,
) -> tuple[str, str, str]:
    """Return one official digest, its source label, and its source URL."""

    if definition.checksum_strategy == "github_release_asset_digest":
        verified_release_asset_url(release, repo_path, tag, asset_name)
        return (
            release_asset_sha256(release, asset_name),
            "github_release_asset_digest",
            f"{GITHUB_API_ORIGIN}/repos/{repo_path}/releases/tags/{tag}",
        )

    if (
        definition.checksum_strategy
        == "github_release_asset_digest_or_official_manifest"
    ):
        verified_release_asset_url(release, repo_path, tag, asset_name)
        try:
            return (
                release_asset_sha256(release, asset_name),
                "github_release_asset_digest",
                f"{GITHUB_API_ORIGIN}/repos/{repo_path}/releases/tags/{tag}",
            )
        except UpstreamUnknown:
            # Some releases publish an exact official manifest instead of a
            # per-asset GitHub digest.  It remains a trusted fallback after
            # its release-asset URL has been bound below.
            pass

    checksum_asset = release_checksum_asset_name(definition, version)
    checksum_url = verified_release_asset_url(release, repo_path, tag, checksum_asset)
    return (
        fetch_sha256(client, checksum_url, asset_name),
        "official_release_checksum_manifest",
        checksum_url,
    )


def required_component_variables(
    definition: ComponentDefinition,
    entries: dict[str, VariableEntry],
) -> ComponentResult | None:
    return missing_variables_result(
        definition.name, entries, list(definition.variables)
    )


def configured_release_url_error(
    definition: ComponentDefinition,
    *,
    message: str,
    tag: str,
    source: str = "",
    asset_name: str = "",
    details: dict[str, str] | None = None,
) -> ComponentResult:
    """Return the shared fail-closed result for a mismatched release alias."""

    return ComponentResult(
        component=definition.name,
        status=STATUS_UNKNOWN,
        message=message,
        variables=list(definition.variables),
        current=tag,
        source=source,
        asset_name=asset_name,
        details=details or {},
    )


def expected_configured_source_url(
    definition: ComponentDefinition,
    repo_path: str,
    expected_asset_url: str,
) -> str:
    """Return the declared source alias for a release component."""

    repository_url = f"{GITHUB_WEB_ORIGIN}/{repo_path}"
    if definition.name in GITHUB_RELEASES_SOURCE_COMPONENTS:
        return f"{repository_url}/releases"
    if definition.name == NGINX_COMPONENT:
        return repository_url
    return expected_asset_url


def configured_nginx_release_aliases_are_bound(
    definition: ComponentDefinition,
    entries: dict[str, VariableEntry],
    *,
    repo_path: str,
    tag: str,
) -> ComponentResult | None:
    """Check the extra NGINX aliases tied to its repository and release tag."""

    if value(entries, NGINX_GITHUB_REPOSITORY_VARIABLE) != (
        f"{GITHUB_WEB_ORIGIN}/{repo_path}"
    ):
        return configured_release_url_error(
            definition,
            message="NGINX_GITHUB_REPO must match NGINX_SOURCE_REPO_URL.",
            tag=tag,
        )
    if value(entries, NGINX_SOURCE_GIT_REF_VARIABLE) != tag:
        return configured_release_url_error(
            definition,
            message="NGINX_SOURCE_GIT_REF must equal NGINX_RELEASE_TAG.",
            tag=tag,
        )
    return None


def configured_release_checksum_url_is_bound(
    definition: ComponentDefinition,
    entries: dict[str, VariableEntry],
    *,
    repo_path: str,
    tag: str,
    version: str,
) -> ComponentResult | None:
    """Check a configured checksum URL against its declared release asset."""

    if not definition.sha256_url_variable or not definition.checksum_asset_template:
        return None
    checksum_asset = release_checksum_asset_name(definition, version)
    expected_checksum_url = expected_github_asset_url(repo_path, tag, checksum_asset)
    if value(entries, definition.sha256_url_variable) != expected_checksum_url:
        return configured_release_url_error(
            definition,
            message="Configured checksum URL is not bound to the declared official release asset.",
            tag=tag,
            details={"expected_sha256_url": expected_checksum_url},
        )
    return None


def configured_github_release_urls_are_bound(
    definition: ComponentDefinition,
    entries: dict[str, VariableEntry],
    *,
    repo_path: str,
    tag: str,
    version: str,
    asset_name: str,
) -> ComponentResult | None:
    """Validate all configured URL/asset aliases before any upstream lookup."""

    expected_asset_url = expected_github_asset_url(repo_path, tag, asset_name)
    if definition.source_url_variable:
        configured_source = value(entries, definition.source_url_variable)
        expected_source = expected_configured_source_url(
            definition, repo_path, expected_asset_url
        )
        if configured_source != expected_source:
            return configured_release_url_error(
                definition,
                message="Configured source URL is not bound to the declared official release identity.",
                tag=tag,
                source=configured_source,
                details={"expected_source_url": expected_source},
            )
    if definition.download_url_variable:
        configured_download = value(entries, definition.download_url_variable)
        if configured_download != expected_asset_url:
            return configured_release_url_error(
                definition,
                message="Configured download URL is not bound to the declared official release asset.",
                tag=tag,
                source=configured_download,
                details={"expected_download_url": expected_asset_url},
            )
    if definition.asset_variable:
        configured_asset = value(entries, definition.asset_variable)
        if configured_asset != asset_name:
            return configured_release_url_error(
                definition,
                message="Configured release asset is not derived from the declared release tag.",
                tag=tag,
                asset_name=configured_asset,
                details={"expected_asset_name": asset_name},
            )
    if definition.name == NGINX_COMPONENT:
        nginx_alias_error = configured_nginx_release_aliases_are_bound(
            definition, entries, repo_path=repo_path, tag=tag
        )
        if nginx_alias_error is not None:
            return nginx_alias_error
    checksum_url_error = configured_release_checksum_url_is_bound(
        definition,
        entries,
        repo_path=repo_path,
        tag=tag,
        version=version,
    )
    if checksum_url_error is not None:
        return checksum_url_error
    return None


def add_release_identity_updates(
    desired: dict[str, str],
    definition: ComponentDefinition,
    *,
    latest_tag: str,
    latest_version: str,
    latest_sha256: str,
) -> None:
    """Add the direct version, tag, and digest members of a release group."""

    if definition.version_variable:
        desired[definition.version_variable] = latest_version
    if definition.release_tag_variable:
        desired[definition.release_tag_variable] = latest_tag
    if definition.sha256_variable:
        desired[definition.sha256_variable] = latest_sha256


def add_non_template_release_update(
    desired: dict[str, str],
    entries: dict[str, VariableEntry],
    variable: str | None,
    identity_variable: str,
    replacement: str,
) -> None:
    """Retain reviewed templates; update only an equivalent literal alias."""

    if variable and not is_template_value(entries[variable].default, identity_variable):
        desired[variable] = replacement


def add_github_release_url_updates(
    desired: dict[str, str],
    definition: ComponentDefinition,
    entries: dict[str, VariableEntry],
    *,
    latest_tag: str,
    latest_version: str,
    latest_asset_name: str,
) -> None:
    """Add literal GitHub asset aliases without expanding safe shell templates."""

    repository = cast(str, definition.github_repository)
    identity_variable = definition.version_variable or ""
    asset_url = expected_github_asset_url(repository, latest_tag, latest_asset_name)
    if definition.name not in GITHUB_RELEASES_SOURCE_COMPONENTS | {NGINX_COMPONENT}:
        add_non_template_release_update(
            desired,
            entries,
            definition.source_url_variable,
            identity_variable,
            asset_url,
        )
    add_non_template_release_update(
        desired,
        entries,
        definition.download_url_variable,
        identity_variable,
        asset_url,
    )
    if definition.checksum_asset_template:
        checksum_url = expected_github_asset_url(
            repository,
            latest_tag,
            release_checksum_asset_name(definition, latest_version),
        )
        add_non_template_release_update(
            desired,
            entries,
            definition.sha256_url_variable,
            identity_variable,
            checksum_url,
        )


def collect_github_release_updates(
    definition: ComponentDefinition,
    entries: dict[str, VariableEntry],
    *,
    latest_tag: str,
    latest_version: str,
    latest_asset_name: str,
    latest_sha256: str,
) -> tuple[list[UpdateChange], dict[str, str]]:
    """Build only the changed members of one otherwise fully checked group."""

    desired: dict[str, str] = {}
    add_release_identity_updates(
        desired,
        definition,
        latest_tag=latest_tag,
        latest_version=latest_version,
        latest_sha256=latest_sha256,
    )
    if definition.name == NGINX_COMPONENT:
        add_non_template_release_update(
            desired,
            entries,
            NGINX_SOURCE_GIT_REF_VARIABLE,
            NGINX_RELEASE_TAG_VARIABLE,
            latest_tag,
        )
    if definition.asset_variable:
        identity_variable = (
            definition.release_tag_variable or definition.version_variable or ""
        )
        add_non_template_release_update(
            desired,
            entries,
            definition.asset_variable,
            identity_variable,
            latest_asset_name,
        )

    # Preserve safe, version/tag-derived shell templates rather than rendering
    # them into duplicate literal URLs.  A non-template legacy URL is updated
    # alongside its identity/digest only after the exact official endpoint was
    # derived above.
    add_github_release_url_updates(
        desired,
        definition,
        entries,
        latest_tag=latest_tag,
        latest_version=latest_version,
        latest_asset_name=latest_asset_name,
    )

    updates: list[UpdateChange] = []
    for variable, desired_value in desired.items():
        append_planned_update(updates, entries, variable, desired_value)
    return updates, desired


def check_github_release_component(
    definition: ComponentDefinition,
    entries: dict[str, VariableEntry],
    client: HttpClient,
) -> ComponentResult:
    """Resolve a complete GitHub release asset/digest tuple from one descriptor."""

    missing = required_component_variables(definition, entries)
    if missing is not None:
        return missing
    repo_path = cast(str, definition.github_repository)
    if definition.name == "NGINX":
        configured_repo = github_repo_path(value(entries, "NGINX_SOURCE_REPO_URL"))
        if configured_repo != repo_path:
            return ComponentResult(
                component=definition.name,
                status=STATUS_UNKNOWN,
                message="NGINX source is not the declared official GitHub repository.",
                variables=list(definition.variables),
                source=value(entries, "NGINX_SOURCE_REPO_URL"),
            )

    current_tag = release_tag_from_component(definition, entries)
    current_version = release_version_from_tag(definition, current_tag)
    current_asset = release_asset_name(definition, current_version, entries)
    bound = configured_github_release_urls_are_bound(
        definition,
        entries,
        repo_path=repo_path,
        tag=current_tag,
        version=current_version,
        asset_name=current_asset,
    )
    if bound is not None:
        return bound
    configured_sha = value(entries, cast(str, definition.sha256_variable)).lower()
    if SHA256_VALUE_RE.fullmatch(configured_sha) is None:
        return ComponentResult(
            component=definition.name,
            status=STATUS_BLOCKED,
            message=f"{definition.sha256_variable} must be a non-empty 64-character SHA-256 value.",
            variables=list(definition.variables),
            current=current_tag,
        )

    latest_release = latest_github_release(client, repo_path)
    latest_tag = require_stable_github_release(
        latest_release, repo_path, definition.tag_pattern
    )
    latest_version = release_version_from_tag(definition, latest_tag)
    latest_asset = release_asset_name(definition, latest_version, entries)
    latest_sha, sha_source, sha_source_url = github_release_checksum(
        definition,
        latest_release,
        client,
        repo_path=repo_path,
        tag=latest_tag,
        version=latest_version,
        asset_name=latest_asset,
    )
    comparison = compare_versions(current_version, latest_version)
    if comparison > 0:
        return ComponentResult(
            component=definition.name,
            status=STATUS_UNKNOWN,
            message="Configured release is newer than the latest stable official release; refusing to guess.",
            variables=list(definition.variables),
            current=current_tag,
            latest=latest_tag,
            latest_upstream=latest_tag,
            latest_compatible=latest_tag,
            source=f"https://github.com/{repo_path}/releases/latest",
        )

    if comparison < 0:
        updates, desired = collect_github_release_updates(
            definition,
            entries,
            latest_tag=latest_tag,
            latest_version=latest_version,
            latest_asset_name=latest_asset,
            latest_sha256=latest_sha,
        )
        return ComponentResult(
            component=definition.name,
            status=STATUS_OUTDATED,
            message="A newer stable official GitHub release with a trusted digest is available.",
            variables=list(definition.variables),
            current=current_tag,
            latest=latest_tag,
            latest_upstream=latest_tag,
            latest_compatible=latest_tag,
            source=f"https://github.com/{repo_path}/releases/latest",
            asset_name=latest_asset,
            official_sha256=latest_sha,
            sha256_source=sha_source,
            updates=updates,
            details={
                "official_asset_url": expected_github_asset_url(
                    repo_path, latest_tag, latest_asset
                ),
                "official_asset_sha256": latest_sha,
                "sha256_source": sha_source,
                "sha256_source_url": sha_source_url,
                "atomic_expected_values": desired,
            },
        )

    if configured_sha != latest_sha:
        updates, desired = collect_github_release_updates(
            definition,
            entries,
            latest_tag=current_tag,
            latest_version=current_version,
            latest_asset_name=current_asset,
            latest_sha256=latest_sha,
        )
        return ComponentResult(
            component=definition.name,
            status=STATUS_OUTDATED,
            message="Configured digest differs from the trusted official release digest.",
            variables=list(definition.variables),
            current=current_tag,
            latest=latest_tag,
            latest_upstream=latest_tag,
            latest_compatible=latest_tag,
            source=f"https://github.com/{repo_path}/releases/tags/{current_tag}",
            asset_name=current_asset,
            official_sha256=latest_sha,
            sha256_source=sha_source,
            updates=updates,
            details={
                "official_asset_url": expected_github_asset_url(
                    repo_path, current_tag, current_asset
                ),
                "official_asset_sha256": latest_sha,
                "sha256_source": sha_source,
                "sha256_source_url": sha_source_url,
                "atomic_expected_values": desired,
            },
        )

    return ComponentResult(
        component=definition.name,
        status=STATUS_CURRENT,
        message="Configured release asset and trusted official digest are current.",
        variables=list(definition.variables),
        current=current_tag,
        latest=latest_tag,
        latest_upstream=latest_tag,
        latest_compatible=latest_tag,
        source=f"https://github.com/{repo_path}/releases/latest",
        asset_name=current_asset,
        official_sha256=latest_sha,
        sha256_source=sha_source,
        details={
            "official_asset_url": expected_github_asset_url(
                repo_path, current_tag, current_asset
            ),
            "official_asset_sha256": latest_sha,
            "sha256_source": sha_source,
            "sha256_source_url": sha_source_url,
        },
    )


def nginx_release_asset_name(release_tag: str) -> str:
    version = release_tag.removeprefix("release-")
    asset_name = f"nginx-{version}{TAR_GZ_EXTENSION}"
    if ".." in asset_name or not NGINX_RELEASE_ASSET_RE.fullmatch(asset_name):
        raise UpstreamError(
            f"NGINX release tag cannot form a safe release asset name: {release_tag!r}"
        )
    return asset_name


def check_nginx_release_provenance(
    entries: dict[str, VariableEntry], client: HttpClient
) -> ComponentResult:
    """Resolve NGINX's latest stable tag/ref/asset/digest tuple atomically."""

    definition = canonicalize_github_repository(
        COMPONENT_DEFINITION_BY_NAME["NGINX"], entries
    )
    return check_github_release_component(definition, entries, client)


def check_pcre2(
    entries: dict[str, VariableEntry], client: HttpClient
) -> ComponentResult:
    """Resolve PCRE2 version and GitHub-published asset digest as one group."""

    return check_github_release_component(
        COMPONENT_DEFINITION_BY_NAME["PCRE2"], entries, client
    )


def latest_lighttpd_version(text: str) -> str:
    candidates = sorted(
        {
            match.group(1)
            for match in re.finditer(
                r"\b(?:lighttpd-)?(\d+(?:\.\d+)+)(?:\.tar\.xz)?\b", text
            )
            if is_stable_version(match.group(1))
        },
        key=version_tuple,
    )
    if len(candidates) != 1:
        raise UpstreamUnknown("official lighttpd latest.txt is missing or ambiguous")
    return candidates[0]


def _check_lighttpd_release(
    entries: dict[str, VariableEntry],
    client: HttpClient,
    definition: ComponentDefinition,
    version: str,
    base: str,
    expected: dict[str, str],
    configured_sha: str,
) -> ComponentResult:
    latest_url = expected["LIGHTTPD_LATEST_URL"]
    latest_version = latest_lighttpd_version(client.get_text(latest_url))
    variables = list(definition.variables)
    if not same_series(version, latest_version):
        return ComponentResult(
            component=definition.name,
            status=STATUS_CURRENT,
            message="A newer lighttpd release is outside the explicitly configured release series and requires compatibility review.",
            variables=variables,
            current=version,
            latest=version,
            latest_upstream=latest_version,
            latest_compatible=version,
            source=latest_url,
            details={"compatibility_review_required": True},
        )
    latest_asset = f"lighttpd-{latest_version}.tar.xz"
    latest_sha_url = base + f"/lighttpd-{latest_version}.sha256sum"
    latest_sha = fetch_sha256(client, latest_sha_url, latest_asset)
    comparison = compare_versions(version, latest_version)
    if comparison > 0:
        return ComponentResult(
            component=definition.name,
            status=STATUS_UNKNOWN,
            message="Configured lighttpd version is newer than official latest.txt; refusing to guess.",
            variables=variables,
            current=version,
            latest=latest_version,
            latest_upstream=latest_version,
            latest_compatible=latest_version,
            source=latest_url,
        )
    if comparison < 0:
        updates: list[UpdateChange] = []
        append_planned_update(updates, entries, "LIGHTTPD_VERSION", latest_version)
        append_planned_update(updates, entries, "LIGHTTPD_SHA256", latest_sha)
        return ComponentResult(
            component=definition.name,
            status=STATUS_OUTDATED,
            message="A newer official lighttpd release and checksum are available.",
            variables=variables,
            current=version,
            latest=latest_version,
            latest_upstream=latest_version,
            latest_compatible=latest_version,
            source=latest_url,
            asset_name=latest_asset,
            official_sha256=latest_sha,
            sha256_source="official_sha256sum_manifest",
            updates=updates,
            details={
                "latest_download_url": base + "/" + latest_asset,
                "latest_sha256_url": latest_sha_url,
                "official_sha256": latest_sha,
                "atomic_expected_values": {
                    "LIGHTTPD_VERSION": latest_version,
                    "LIGHTTPD_SHA256": latest_sha,
                },
            },
        )
    if configured_sha != latest_sha:
        update = plan_update(entries, "LIGHTTPD_SHA256", latest_sha)
        return ComponentResult(
            component=definition.name,
            status=STATUS_OUTDATED,
            message="Configured lighttpd digest differs from its official checksum manifest.",
            variables=variables,
            current=version,
            latest=latest_version,
            latest_upstream=latest_version,
            latest_compatible=latest_version,
            source=latest_url,
            asset_name=f"lighttpd-{version}.tar.xz",
            official_sha256=latest_sha,
            sha256_source="official_sha256sum_manifest",
            updates=[update] if update else [],
            details={
                "official_sha256": latest_sha,
                "atomic_expected_values": {"LIGHTTPD_SHA256": latest_sha},
            },
        )
    return ComponentResult(
        component=definition.name,
        status=STATUS_CURRENT,
        message="Configured lighttpd release and official checksum are current.",
        variables=variables,
        current=version,
        latest=latest_version,
        latest_upstream=latest_version,
        latest_compatible=latest_version,
        source=latest_url,
        asset_name=f"lighttpd-{version}.tar.xz",
        official_sha256=latest_sha,
        sha256_source="official_sha256sum_manifest",
        details={"official_sha256": latest_sha},
    )


def check_lighttpd(
    entries: dict[str, VariableEntry], client: HttpClient
) -> ComponentResult:
    definition = COMPONENT_DEFINITION_BY_NAME["lighttpd"]
    missing = required_component_variables(definition, entries)
    if missing is not None:
        return missing
    version = value(entries, "LIGHTTPD_VERSION")
    if not is_stable_version(version):
        return ComponentResult(
            component=definition.name,
            status=STATUS_UNKNOWN,
            message="LIGHTTPD_VERSION must be a stable numeric release version.",
            variables=list(definition.variables),
            current=version,
        )
    series = value(entries, "LIGHTTPD_SERIES")
    release_root = value(entries, "LIGHTTPD_RELEASE_ROOT_URL")
    series_base = value(entries, "LIGHTTPD_SERIES_BASE_URL")
    if VERSION_PAIR_RE.fullmatch(series) is None:
        return ComponentResult(
            component=definition.name,
            status=STATUS_BLOCKED,
            message="LIGHTTPD_SERIES must be a numeric major.minor series.",
            variables=list(definition.variables),
            current=version,
        )
    parsed_root = urlparse(release_root)
    if (
        parsed_root.scheme != "https"
        or parsed_root.hostname != definition.authorized_hosts[0]
        or parsed_root.path != "/lighttpd"
        or parsed_root.query
        or parsed_root.fragment
    ):
        return ComponentResult(
            component=definition.name,
            status=STATUS_UNKNOWN,
            message="LIGHTTPD_RELEASE_ROOT_URL is not the authorized official root.",
            variables=list(definition.variables),
            current=version,
            source=release_root,
        )
    expected_series_base = f"{release_root}/releases-{series}.x"
    if (
        series_base != expected_series_base
        or "/../" in series_base
        or "//" in urlparse(series_base).path
    ):
        return ComponentResult(
            component=definition.name,
            status=STATUS_UNKNOWN,
            message="LIGHTTPD_SERIES_BASE_URL is malformed or contains a duplicate slash.",
            variables=list(definition.variables),
            current=version,
            source=series_base,
            details={"expected_series_base_url": expected_series_base},
        )
    if version_tuple(version)[:2] != version_tuple(series):
        return ComponentResult(
            component=definition.name,
            status=STATUS_UNKNOWN,
            message="LIGHTTPD_VERSION is outside the explicitly configured LIGHTTPD_SERIES.",
            variables=list(definition.variables),
            current=version,
            source=series_base,
        )
    base = series_base
    asset = f"lighttpd-{version}.tar.xz"
    expected = {
        "LIGHTTPD_SOURCE_URL": base + "/",
        "LIGHTTPD_RELEASE_INDEX_URL": base + "/",
        "LIGHTTPD_LATEST_URL": base + "/latest.txt",
        "LIGHTTPD_DOWNLOAD_URL": base + "/" + asset,
        "LIGHTTPD_SHA256_URL": base + f"/lighttpd-{version}.sha256sum",
    }
    mismatches = {
        variable: expected_value
        for variable, expected_value in expected.items()
        if value(entries, variable) != expected_value
    }
    if mismatches:
        return ComponentResult(
            component=definition.name,
            status=STATUS_UNKNOWN,
            message="Configured lighttpd URLs are not bound to the declared release series and asset.",
            variables=list(definition.variables),
            current=version,
            source=value(entries, "LIGHTTPD_SOURCE_URL"),
            details={"expected_urls": mismatches},
        )
    configured_sha = value(entries, "LIGHTTPD_SHA256").lower()
    if SHA256_VALUE_RE.fullmatch(configured_sha) is None:
        return ComponentResult(
            component=definition.name,
            status=STATUS_BLOCKED,
            message="LIGHTTPD_SHA256 must be a non-empty 64-character SHA-256 value.",
            variables=list(definition.variables),
            current=version,
        )

    return _check_lighttpd_release(
        entries, client, definition, version, base, expected, configured_sha
    )


def unknown_component(
    component: str,
    entries: dict[str, VariableEntry],
    variables: list[str],
    reason: str,
) -> ComponentResult:
    return ComponentResult(
        component=component,
        status=STATUS_UNKNOWN,
        message=NO_SAFE_UPDATER_MESSAGE,
        variables=variables,
        current=", ".join(
            f"{name}={value(entries, name)}" for name in variables if name in entries
        ),
        details={"reason": reason},
    )


def not_applicable_component(
    component: str,
    entries: dict[str, VariableEntry],
    variables: list[str],
    reason: str,
) -> ComponentResult:
    """Describe a tracked local-policy entry that has no updater contract."""

    return ComponentResult(
        component=component,
        status=STATUS_NOT_APPLICABLE,
        message=reason,
        variables=variables,
        current=", ".join(
            f"{name}={value(entries, name)}" for name in variables if name in entries
        ),
        details={"reason": reason},
    )


def decorate_component_result(
    definition: ComponentDefinition,
    result: ComponentResult,
    entries: dict[str, VariableEntry],
) -> ComponentResult:
    """Attach descriptor evidence and atomic-group state to every report row."""

    details = dict(result.details)
    details.setdefault("resolver", definition.resolver)
    details.setdefault("authorized_hosts", list(definition.authorized_hosts))
    details.setdefault("github_repository", definition.github_repository or "")
    details.setdefault("checksum_strategy", definition.checksum_strategy)
    details.setdefault("stable_policy", definition.stable_policy)
    details.setdefault("compatibility_policy", definition.compatibility_policy)
    details.setdefault("atomic_group", list(definition.atomic_group))
    if result.status == STATUS_OUTDATED and definition.update_policy == "automatic":
        expected_values = dict(details.get("atomic_expected_values", {}))
        planned_values = {update.variable: update.new for update in result.updates}
        for variable in definition.atomic_group:
            current = entry(entries, variable)
            if current is None:
                continue
            expected_values[variable] = planned_values.get(variable, current.default)
        details["atomic_expected_values"] = expected_values
        details["atomic_changed_variables"] = [
            update.variable for update in result.updates
        ]
    return cast(
        ComponentResult,
        dataclasses.replace(
            result,
            component=definition.name,
            variables=list(definition.variables),
            latest_upstream=result.latest_upstream or result.latest,
            latest_compatible=result.latest_compatible or result.latest,
            update_policy=definition.update_policy,
            atomic_group=definition.atomic_group,
            details=details,
        ),
    )


def unified_orchestrator_component(
    definition: ComponentDefinition,
    entries: dict[str, VariableEntry],
) -> ComponentResult:
    """Keep global sources visible while delegating resolution to the shared plan."""

    missing = [name for name in definition.variables if name not in entries]
    if missing:
        return ComponentResult(
            component=definition.name,
            status=STATUS_BLOCKED,
            message=(
                "Unified canonical maintenance ownership is incomplete; missing: "
                + ", ".join(missing)
            ),
            variables=list(definition.variables),
            details={"owner": "ci/tools/canonical_maintenance.py"},
        )
    return ComponentResult(
        component=definition.name,
        status=STATUS_REVIEW_REQUIRED,
        message=(
            "This global source is resolved by the unified canonical maintenance "
            "orchestrator; run resolve-canonical-maintenance.py."
        ),
        variables=list(definition.variables),
        details={"owner": "ci/tools/canonical_maintenance.py"},
    )


def resolve_component_definition(
    definition: ComponentDefinition,
    entries: dict[str, VariableEntry],
    client: HttpClient,
) -> ComponentResult:
    if definition.resolver in {
        "github_release_manifest",
        "github_release_digest",
        "github_tag_commit",
    }:
        definition = canonicalize_github_repository(definition, entries)
    if definition.resolver == "not_applicable":
        return not_applicable_component(
            definition.name,
            entries,
            list(definition.variables),
            definition.not_applicable_reason,
        )
    if definition.resolver == "unified_orchestrator":
        return unified_orchestrator_component(definition, entries)
    if definition.resolver == "apache_listing":
        return official_tarball_check(
            definition.name,
            entries,
            client,
            version_var=cast(str, definition.version_variable),
            source_url_var=cast(str, definition.source_url_variable),
            sha_var=cast(str, definition.sha256_variable),
            sha_url_var=cast(str, definition.sha256_url_variable),
            filename_prefix=definition.filename_prefix,
            extension=definition.archive_extension,
            allowed_host=definition.authorized_hosts[0],
            restrict_to_current_series=True,
            source_path_prefix=definition.source_path_prefix or None,
        )
    if definition.resolver in {"github_release_manifest", "github_release_digest"}:
        return check_github_release_component(definition, entries, client)
    if definition.resolver == "github_tag_commit":
        return check_manual_git_provenance(definition, entries, client)
    if definition.resolver == "lighttpd_latest":
        return check_lighttpd(entries, client)
    if definition.resolver == "haproxy_series":
        return check_haproxy(entries, client)
    if definition.resolver == "haproxy_htx_series":
        return check_haproxy_htx(entries, client)
    raise UpstreamError(
        f"unknown resolver strategy for {definition.name}: {definition.resolver}"
    )


def check_all(
    entries: dict[str, VariableEntry],
    client: HttpClient,
    component_names: tuple[str, ...] | None = None,
) -> list[ComponentResult]:
    """Check registry-selected component descriptors in deterministic order."""

    selected = set(component_names or ())
    # The unified orchestrator resolves Go-FTW, Albedo, and CI pins before it
    # delegates runtime/source descriptors here.  A selector for this low-level
    # checker therefore remains scoped to those runtime/source descriptors.
    definitions = [
        definition
        for definition in COMPONENT_DEFINITIONS
        if not selected or definition.name in selected
    ]
    checks: list[ComponentResult] = []
    for definition in definitions:
        try:
            result = resolve_component_definition(definition, entries, client)
            checks.append(decorate_component_result(definition, result, entries))
        except UpstreamUnknown as exc:
            checks.append(
                decorate_component_result(
                    definition,
                    ComponentResult(
                        component=definition.name,
                        status=STATUS_UNKNOWN,
                        message=str(exc),
                        variables=list(definition.variables),
                    ),
                    entries,
                )
            )
        except UpstreamBlocked as exc:
            checks.append(
                decorate_component_result(
                    definition,
                    ComponentResult(
                        component=definition.name,
                        status=STATUS_BLOCKED,
                        message=str(exc),
                        variables=list(definition.variables),
                    ),
                    entries,
                )
            )
        except UpstreamError as exc:
            checks.append(
                decorate_component_result(
                    definition,
                    ComponentResult(
                        component=definition.name,
                        status=STATUS_ERROR,
                        message=str(exc),
                        variables=list(definition.variables),
                    ),
                    entries,
                )
            )
    return checks


def relevant_inventory_entries(
    entries: dict[str, VariableEntry],
) -> list[VariableEntry]:
    return [
        item
        for item in sorted(entries.values(), key=lambda current: current.line)
        if item.tracked or item.name == "DEFAULT_BRANCH"
    ]


def unassigned_provenance_variables(entries: dict[str, VariableEntry]) -> list[str]:
    return [
        item.name
        for item in relevant_inventory_entries(entries)
        if component_definition_for_variable(item.name) is None
    ]


def inventory(entries: dict[str, VariableEntry]) -> list[dict[str, Any]]:
    rows = []
    for item in relevant_inventory_entries(entries):
        definition = component_definition_for_variable(item.name)
        rows.append(
            {
                "name": item.name,
                "line": item.line,
                "default": item.default,
                "resolved": item.resolved,
                "style": item.style,
                "component": definition.name if definition else "",
                "classification": (
                    definition.update_policy if definition else "unassigned"
                ),
                "resolver": definition.resolver if definition else "",
                "atomic_group": list(definition.atomic_group) if definition else [],
                "reason": definition.not_applicable_reason if definition else "",
            }
        )
    return rows


def flatten_updates(results: list[ComponentResult]) -> list[UpdateChange]:
    updates: list[UpdateChange] = []
    for result in results:
        updates.extend(result.updates)
    ordered: dict[str, UpdateChange] = {}
    for update in updates:
        previous = ordered.get(update.variable)
        if previous and previous.new != update.new:
            raise UpstreamError(
                f"conflicting updates for {update.variable}: {previous.new!r} vs {update.new!r}"
            )
        ordered[update.variable] = update
    return sorted(ordered.values(), key=lambda update: update.line)


def append_unique(values: list[str], value: str) -> None:
    if value not in values:
        values.append(value)


def reviewed_manual_variables(result: ComponentResult) -> tuple[str, ...] | None:
    """Return the only manual pin set that may be deferred by maintenance mode."""

    expected = MANUAL_REVIEW_VARIABLES.get(result.component)
    declared = result.details.get("manual_variables")
    if (
        expected is None
        or result.updates
        or not isinstance(declared, list)
        or declared != list(expected)
    ):
        return None
    return expected


def manual_review_pin_values(
    results: list[ComponentResult], entries: dict[str, VariableEntry]
) -> dict[str, str]:
    """Capture exact reviewed-pin source lines for a later byte-for-byte check."""

    values: dict[str, str] = {}
    for result in results:
        if result.status != STATUS_REVIEW_REQUIRED:
            continue
        variables = reviewed_manual_variables(result)
        if variables is None:
            raise UpstreamError(
                f"manual review metadata is invalid for {result.component}"
            )
        for variable in variables:
            current = entry(entries, variable)
            if current is None:
                raise UpstreamError(
                    f"manual review pin {variable} is missing for {result.component}"
                )
            previous = values.get(variable)
            if previous is not None and previous != current.raw:
                raise UpstreamError(
                    f"manual review pin {variable} has conflicting source lines"
                )
            values[variable] = current.raw
    return values


def manual_review_pin_digest(
    results: list[ComponentResult], entries: dict[str, VariableEntry]
) -> str:
    """Hash a canonical, non-secret proof of the exact manual pin source lines."""

    pins = manual_review_pin_values(results, entries)
    if not pins:
        return ""
    payload = "".join(f"{name}\0{pins[name]}\n" for name in sorted(pins))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def require_manual_review_pins_unchanged(
    before: dict[str, str], after: dict[str, VariableEntry]
) -> None:
    """Reject a candidate if an automatic plan touched a manual source line."""

    for variable, raw_line in before.items():
        updated = entry(after, variable)
        if updated is None or updated.raw != raw_line:
            raise UpstreamError(
                f"automatic candidate changed manual review pin {variable}"
            )


def manual_review_variable_names(results: list[ComponentResult]) -> set[str]:
    """Return the declared manual variables from already-recognized review rows."""

    names: set[str] = set()
    for result in results:
        if result.status != STATUS_REVIEW_REQUIRED:
            continue
        reviewed = reviewed_manual_variables(result)
        if reviewed is not None:
            names.update(reviewed)
    return names


def update_matches_automatic_plan(
    update: UpdateChange,
    result: ComponentResult,
    entries: dict[str, VariableEntry],
    manual_variables: set[str],
) -> bool:
    """Accept only an exact automatic update that cannot touch a manual pin."""

    current = entry(entries, update.variable)
    try:
        require_shell_safe_default(
            update.variable,
            update.old,
            current.default if current is not None else None,
        )
        require_shell_safe_default(
            update.variable,
            update.new,
            current.default if current is not None else None,
        )
    except UpstreamError:
        return False
    return bool(
        current is not None
        and update.variable in result.variables
        and update.line == current.line
        and update.old == current.default
        and update.variable not in manual_variables
    )


def automatic_updates_are_valid(
    result: ComponentResult,
    entries: dict[str, VariableEntry],
    manual_variables: set[str],
    seen_variables: dict[str, str],
    invalid_components: list[str],
) -> bool:
    """Validate each planned update and retain duplicate ownership failures."""

    valid = True
    for update in result.updates:
        if not update_matches_automatic_plan(update, result, entries, manual_variables):
            append_unique(invalid_components, result.component)
            valid = False
            continue
        previous_component = seen_variables.get(update.variable)
        if previous_component is not None:
            append_unique(invalid_components, result.component)
            append_unique(invalid_components, previous_component)
            valid = False
            continue
        seen_variables[update.variable] = result.component
    return valid


def automatic_atomic_group_matches_plan(
    result: ComponentResult,
    entries: dict[str, VariableEntry],
) -> bool:
    """Require an automatic result to update every changed atomic member."""

    if not result.atomic_group:
        return True
    expected_values = result.details.get("atomic_expected_values")
    if not isinstance(expected_values, dict):
        return False
    expected_changes: dict[str, str] = {}
    for variable in result.atomic_group:
        current = entry(entries, variable)
        expected = expected_values.get(variable)
        if (
            current is None
            or not isinstance(expected, str)
            or variable not in result.variables
        ):
            return False
        if current.default != expected:
            expected_changes[variable] = expected
    actual_changes = {update.variable: update.new for update in result.updates}
    return expected_changes == actual_changes


def automatic_plan_errors(
    automatic_results: list[ComponentResult],
    entries: dict[str, VariableEntry],
    manual_variables: set[str],
) -> list[str]:
    """Return every component whose automatic update set is incomplete or unsafe."""

    invalid_components: list[str] = []
    seen_variables: dict[str, str] = {}
    for result in automatic_results:
        if not result.updates:
            append_unique(invalid_components, result.component)
            continue
        updates_valid = automatic_updates_are_valid(
            result,
            entries,
            manual_variables,
            seen_variables,
            invalid_components,
        )
        if not updates_valid or not automatic_atomic_group_matches_plan(
            result, entries
        ):
            append_unique(invalid_components, result.component)
    return invalid_components


def maintenance_update_plan(
    results: list[ComponentResult], entries: dict[str, VariableEntry]
) -> tuple[list[UpdateChange], list[str]]:
    """Return only complete automatic plans, or their affected fatal components."""

    automatic_results = [
        result for result in results if result.status == STATUS_OUTDATED
    ]
    plan_errors = automatic_plan_errors(
        automatic_results,
        entries,
        manual_review_variable_names(results),
    )
    if plan_errors:
        return [], plan_errors
    try:
        updates = flatten_updates(automatic_results)
    except UpstreamError:
        return [], [result.component for result in automatic_results]
    expected_count = sum(len(result.updates) for result in automatic_results)
    if len(updates) != expected_count:
        return [], [result.component for result in automatic_results]
    return updates, []


def reviewed_component_groups(
    results: list[ComponentResult],
) -> tuple[list[str], list[str]]:
    """Separate fail-closed statuses from explicitly recognized manual review."""

    fatal_components: list[str] = []
    manual_components: list[str] = []
    for result in results:
        if result.status in FATAL_STATUSES:
            append_unique(fatal_components, result.component)
        elif result.status == STATUS_REVIEW_REQUIRED:
            destination = (
                manual_components
                if reviewed_manual_variables(result) is not None
                else fatal_components
            )
            append_unique(destination, result.component)
    return fatal_components, manual_components


def append_review_components_as_fatal(
    fatal_components: list[str], results: list[ComponentResult]
) -> None:
    """Preserve failure when a reviewed pin snapshot cannot be proven exact."""

    for result in results:
        if result.status == STATUS_REVIEW_REQUIRED:
            append_unique(fatal_components, result.component)


def manual_review_pins_are_valid(
    results: list[ComponentResult], entries: dict[str, VariableEntry]
) -> bool:
    try:
        manual_review_pin_values(results, entries)
    except UpstreamError:
        return False
    return True


def append_unique_values(destination: list[str], values: list[str]) -> None:
    for value in values:
        append_unique(destination, value)


def build_maintenance_disposition(
    fatal_components: list[str],
    manual_components: list[str],
    automatic_updates: list[UpdateChange],
) -> MaintenanceDisposition:
    """Construct the sole terminal disposition after every safety check ran."""

    if fatal_components:
        return MaintenanceDisposition(
            outcome=MAINTENANCE_OUTCOME_FATAL,
            safe_updates_available=False,
            manual_review_required=bool(manual_components),
            manual_review_components=tuple(manual_components),
            fatal_components=tuple(fatal_components),
            automatic_updates=(),
            automatic_update_variables=(),
        )

    safe_updates_available = bool(automatic_updates)
    if safe_updates_available:
        outcome = (
            MAINTENANCE_OUTCOME_SAFE_UPDATES_WITH_MANUAL_REVIEW
            if manual_components
            else MAINTENANCE_OUTCOME_SAFE_UPDATES
        )
    else:
        outcome = (
            MAINTENANCE_OUTCOME_MANUAL_REVIEW_ONLY
            if manual_components
            else MAINTENANCE_OUTCOME_NO_UPDATES
        )
    return MaintenanceDisposition(
        outcome=outcome,
        safe_updates_available=safe_updates_available,
        manual_review_required=bool(manual_components),
        manual_review_components=tuple(manual_components),
        fatal_components=(),
        automatic_updates=tuple(automatic_updates),
        automatic_update_variables=tuple(
            update.variable for update in automatic_updates
        ),
    )


def maintenance_disposition(
    results: list[ComponentResult],
    entries: dict[str, VariableEntry],
    *,
    defer_reviewed_provenance: bool,
) -> MaintenanceDisposition:
    """Classify maintenance work without converting unsafe states into success."""

    fatal_components, manual_components = reviewed_component_groups(results)
    if not manual_review_pins_are_valid(results, entries):
        append_review_components_as_fatal(fatal_components, results)
    if manual_components and not defer_reviewed_provenance:
        append_unique_values(fatal_components, manual_components)
    automatic_updates, plan_errors = maintenance_update_plan(results, entries)
    append_unique_values(fatal_components, plan_errors)
    return build_maintenance_disposition(
        fatal_components,
        manual_components,
        automatic_updates,
    )


def result_to_dict(result: ComponentResult) -> dict[str, Any]:
    data = dataclasses.asdict(result)
    data["updates"] = [dataclasses.asdict(update) for update in result.updates]
    return data


def make_summary(
    common_sh: Path,
    entries: dict[str, VariableEntry],
    results: list[ComponentResult],
    updates_applied: list[UpdateChange],
    disposition: MaintenanceDisposition,
    selected_components: tuple[str, ...] = (),
) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for result in results:
        counts[result.status] = counts.get(result.status, 0) + 1
    missing_required = validate_entries(entries)
    manual_review_pins_sha256 = (
        manual_review_pin_digest(results, entries)
        if disposition.manual_review_required
        else ""
    )
    return {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "common_sh": str(common_sh),
        "selected_components": list(selected_components),
        "maintenance_outcome": disposition.outcome,
        "safe_updates_available": disposition.safe_updates_available,
        "manual_review_required": disposition.manual_review_required,
        "manual_review_components": list(disposition.manual_review_components),
        "manual_review_pins_preserved": disposition.manual_review_required,
        "manual_review_pins_sha256": manual_review_pins_sha256,
        "automatic_update_variables": list(disposition.automatic_update_variables),
        "fatal_components": list(disposition.fatal_components),
        "status_counts": counts,
        "components": [result_to_dict(result) for result in results],
        "inventory": inventory(entries),
        "missing_required": missing_required,
        "updates_applied": [dataclasses.asdict(update) for update in updates_applied],
    }


def markdown_component_action(result: dict[str, Any]) -> str:
    """Describe a component action without changing its terminal status."""

    if result.get("updates"):
        return ", ".join(update["variable"] for update in result["updates"])
    if result["status"] in {STATUS_UNKNOWN, STATUS_REVIEW_REQUIRED}:
        return result.get("details", {}).get("reason") or "manual review"
    if result["status"] == STATUS_BLOCKED:
        return "retry when upstream is reachable"
    return "none"


def append_markdown_component_rows(
    lines: list[str], components: list[dict[str, Any]]
) -> None:
    for result in components:
        lines.append(
            "| {component} | {current} | {latest} | `{status}` | {action} |".format(
                component=markdown_escape(result["component"]),
                current=markdown_escape(result.get("current") or ""),
                latest=markdown_escape(result.get("latest") or ""),
                status=markdown_escape(result["status"]),
                action=markdown_escape(markdown_component_action(result)),
            )
        )


def append_markdown_component_section(
    lines: list[str], heading: str, components: list[str]
) -> None:
    if not components:
        return
    lines.extend(["", heading, ""])
    for component in components:
        lines.append(f"- `{markdown_escape(component)}`")


def append_markdown_applied_updates(
    lines: list[str], updates: list[dict[str, Any]]
) -> None:
    if not updates:
        return
    lines.extend(["", "## Applied Updates", ""])
    lines.append("| Variable | Line | Before | After |")
    lines.append("| --- | ---: | --- | --- |")
    for update in updates:
        lines.append(
            "| {variable} | {line} | `{old}` | `{new}` |".format(
                variable=markdown_escape(update["variable"]),
                line=update["line"],
                old=markdown_escape(update["old"]),
                new=markdown_escape(update["new"]),
            )
        )


def append_markdown_inventory(
    lines: list[str], inventory_rows: list[dict[str, Any]]
) -> None:
    lines.extend(["", "## Inventory", ""])
    lines.append("| Variable | Line | Resolved value |")
    lines.append("| --- | ---: | --- |")
    for item in inventory_rows:
        lines.append(
            "| {name} | {line} | `{resolved}` |".format(
                name=markdown_escape(item["name"]),
                line=item["line"],
                resolved=markdown_escape(item["resolved"]),
            )
        )


def markdown_summary(summary: dict[str, Any]) -> str:
    lines = [
        "# common.sh version check",
        "",
        f"- Generated: `{summary['generated_at']}`",
        f"- File: `{summary['common_sh']}`",
        "- Components: `all`"
        if not summary.get("selected_components")
        else "- Components: "
        + ", ".join(
            f"`{markdown_escape(component)}`"
            for component in summary["selected_components"]
        ),
        f"- Maintenance outcome: `{summary['maintenance_outcome']}`",
        "",
        "## Components",
        "",
        "| Komponente | aktuelle Version | neueste Version | Status | Aktion |",
        "| --- | --- | --- | --- | --- |",
    ]
    append_markdown_component_rows(lines, summary["components"])
    if summary["missing_required"]:
        lines.extend(["", "## Missing required values", ""])
        lines.extend(f"- `{name}`" for name in summary["missing_required"])
    append_markdown_component_section(
        lines,
        "## Manual provenance review required",
        summary["manual_review_components"],
    )
    append_markdown_component_section(
        lines,
        "## Fatal components",
        summary["fatal_components"],
    )
    append_markdown_applied_updates(lines, summary["updates_applied"])
    append_markdown_inventory(lines, summary["inventory"])
    lines.append("")
    return "\n".join(lines)


def plain_summary(summary: dict[str, Any]) -> str:
    lines = [
        f"common.sh version check: {summary['common_sh']}",
        f"maintenance outcome: {summary['maintenance_outcome']}",
    ]
    for result in summary["components"]:
        line = f"{result['status']}: {result['component']}"
        if result.get("current"):
            line += f" current={result['current']}"
        if result.get("latest"):
            line += f" latest={result['latest']}"
        line += f" - {result['message']}"
        lines.append(line)
    updates = summary["updates_applied"]
    if updates:
        lines.append("applied updates:")
        for update in updates:
            lines.append(
                f"  {update['variable']} line {update['line']}: {update['old']} -> {update['new']}"
            )
    return "\n".join(lines) + "\n"


def exit_code(
    results: list[ComponentResult],
    entries: dict[str, VariableEntry] | None = None,
    *,
    defer_reviewed_provenance: bool = False,
) -> int:
    """Keep the legacy default strict while exposing an explicit maintenance mode."""

    if entries is None:
        statuses = {result.status for result in results}
        if statuses.intersection(FATAL_STATUSES) or (
            STATUS_REVIEW_REQUIRED in statuses and not defer_reviewed_provenance
        ):
            return 2
        if STATUS_OUTDATED in statuses:
            return 1
        return 0

    disposition = maintenance_disposition(
        results,
        entries,
        defer_reviewed_provenance=defer_reviewed_provenance,
    )
    if disposition.outcome == MAINTENANCE_OUTCOME_FATAL:
        return 2
    return 1 if disposition.safe_updates_available else 0


def write_summary_files(summary: dict[str, Any], markdown: str) -> None:
    root = build_root()
    output_dir = root / "results" / "common-version-check"
    require_safe_build_write_target(output_dir)
    require_no_symlink_ancestors(output_dir, "summary output directory")
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output_dir / "summary.md").write_text(markdown, encoding="utf-8")


def common_path_from_args(path_text: str | None) -> Path:
    if path_text:
        return require_safe_common_sh_source(Path(path_text))
    return require_safe_common_sh_source(DEFAULT_COMMON_SH)


def parse_arguments(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--check", action="store_true", help="check common.sh without modifying it"
    )
    mode.add_argument(
        "--update", action="store_true", help="apply safe updates to common.sh"
    )
    mode.add_argument(
        "--validate-canonical",
        action="store_true",
        help="validate the complete canonical pin contract locally without network access",
    )
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--json", action="store_true", help="print JSON summary")
    output.add_argument(
        "--markdown", action="store_true", help="print Markdown summary"
    )
    parser.add_argument(
        "--write-files",
        action="store_true",
        help="write summary files under BUILD_ROOT",
    )
    parser.add_argument(
        "--defer-reviewed-provenance",
        action="store_true",
        help=(
            "allow only explicitly classified manual provenance reviews to defer "
            "while applying independent safe updates"
        ),
    )
    parser.add_argument(
        "--component",
        action="append",
        help="check exactly this canonical component name (may be repeated)",
    )
    parser.add_argument(
        "--list-components",
        action="store_true",
        help="print canonical component names and exit",
    )
    parser.add_argument("--common-sh", help=argparse.SUPPRESS)
    parser.add_argument(
        "--timeout", type=float, default=20.0, help="network timeout in seconds"
    )
    return parser.parse_args(argv)


def append_missing_required_result(
    results: list[ComponentResult], entries: dict[str, VariableEntry]
) -> None:
    missing_required = validate_entries(entries)
    if not missing_required:
        return
    results.append(
        ComponentResult(
            component="common.sh required values",
            status=STATUS_ERROR,
            message="Required tracked variables resolved to empty: "
            + ", ".join(missing_required),
            variables=missing_required,
            details={
                "action": "define a value or add the variable to OPTIONAL_EMPTY_VARIABLES"
            },
        )
    )


def append_unassigned_inventory_result(
    results: list[ComponentResult], entries: dict[str, VariableEntry]
) -> None:
    """Fail closed if common.sh gains a provenance input outside the registry."""

    unassigned = unassigned_provenance_variables(entries)
    if not unassigned:
        return
    results.append(
        ComponentResult(
            component="common.sh provenance inventory",
            status=STATUS_ERROR,
            message="Relevant provenance variables lack a resolver or not_applicable classification: "
            + ", ".join(unassigned),
            variables=unassigned,
            details={"unassigned_variables": unassigned},
        )
    )


def prepare_update_candidate(
    common_sh: Path,
    lines: list[str],
    updates: list[UpdateChange],
    manual_pins: dict[str, str],
) -> tuple[Path, list[str], dict[str, VariableEntry]]:
    """Render and validate every local invariant before the first file write."""

    target = require_safe_common_sh_update_target(common_sh)
    candidate_lines = render_updated_lines(lines, updates)
    candidate_entries = parse_common_lines(candidate_lines)
    if validate_entries(candidate_entries):
        raise UpstreamError(
            "candidate common.sh leaves required tracked variables empty"
        )
    require_manual_review_pins_unchanged(manual_pins, candidate_entries)
    return target, candidate_lines, candidate_entries


def revalidate_update_candidate(
    candidate_entries: dict[str, VariableEntry],
    manual_pins: dict[str, str],
    manual_components: tuple[str, ...],
    *,
    defer_reviewed_provenance: bool,
    revalidate: Callable[[dict[str, VariableEntry]], list[ComponentResult]] | None,
) -> None:
    """Require a fresh candidate view to settle before a mutation is allowed."""

    if revalidate is None:
        return
    candidate_results = revalidate(candidate_entries)
    append_missing_required_result(candidate_results, candidate_entries)
    candidate_disposition = maintenance_disposition(
        candidate_results,
        candidate_entries,
        defer_reviewed_provenance=defer_reviewed_provenance,
    )
    if candidate_disposition.outcome not in {
        MAINTENANCE_OUTCOME_NO_UPDATES,
        MAINTENANCE_OUTCOME_MANUAL_REVIEW_ONLY,
    }:
        raise UpstreamError(
            "candidate revalidation did not settle to no updates or manual review only"
        )
    if candidate_disposition.manual_review_components != manual_components:
        raise UpstreamError("candidate revalidation changed manual review components")
    require_manual_review_pins_unchanged(manual_pins, candidate_entries)


def reversed_updates(updates: list[UpdateChange]) -> list[UpdateChange]:
    """Return an exact inverse plan suitable for the existing safe write path."""

    return [
        UpdateChange(
            variable=update.variable,
            line=update.line,
            old=update.new,
            new=update.old,
        )
        for update in updates
    ]


def rollback_update_candidate(
    target: Path, candidate_lines: list[str], updates: list[UpdateChange]
) -> None:
    """Rollback through the same BUILD_ROOT-checked update primitive as writes."""

    apply_updates(target, candidate_lines, reversed_updates(updates))


def verify_written_candidate(
    common_sh: Path,
    candidate_lines: list[str],
    candidate_entries: dict[str, VariableEntry],
    manual_pins: dict[str, str],
) -> tuple[list[str], dict[str, VariableEntry]]:
    """Reject any post-write mismatch before reporting the update as successful."""

    updated_lines, updated_entries = parse_common(common_sh)
    if updated_lines != candidate_lines or updated_entries != candidate_entries:
        raise UpstreamError("written common.sh does not match its validated candidate")
    require_manual_review_pins_unchanged(manual_pins, updated_entries)
    return updated_lines, updated_entries


def apply_requested_updates(
    update_requested: bool,
    rc: int,
    common_sh: Path,
    lines: list[str],
    entries: dict[str, VariableEntry],
    results: list[ComponentResult],
    *,
    defer_reviewed_provenance: bool = False,
    revalidate: Callable[[dict[str, VariableEntry]], list[ComponentResult]]
    | None = None,
) -> tuple[int, list[UpdateChange], list[str], dict[str, VariableEntry]] | None:
    if not update_requested:
        return rc, [], lines, entries
    disposition = maintenance_disposition(
        results,
        entries,
        defer_reviewed_provenance=defer_reviewed_provenance,
    )
    if disposition.outcome == MAINTENANCE_OUTCOME_FATAL:
        print(
            "blocked: refusing to update while one or more upstream checks failed",
            file=sys.stderr,
        )
        return 2, [], lines, entries
    if not disposition.safe_updates_available:
        return rc, [], lines, entries

    updates = list(disposition.automatic_updates)
    manual_pins = manual_review_pin_values(results, entries)
    try:
        target, candidate_lines, candidate_entries = prepare_update_candidate(
            common_sh,
            lines,
            updates,
            manual_pins,
        )
        revalidate_update_candidate(
            candidate_entries,
            manual_pins,
            disposition.manual_review_components,
            defer_reviewed_provenance=defer_reviewed_provenance,
            revalidate=revalidate,
        )
        apply_updates(common_sh, lines, updates)
    except (OSError, UpstreamError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return None

    try:
        updated_lines, updated_entries = verify_written_candidate(
            common_sh,
            candidate_lines,
            candidate_entries,
            manual_pins,
        )
    except (OSError, UpstreamError) as exc:
        try:
            rollback_update_candidate(target, candidate_lines, updates)
        except (OSError, UpstreamError) as rollback_exc:
            print(f"error: {exc}; rollback failed: {rollback_exc}", file=sys.stderr)
            return None
        print(f"error: {exc}", file=sys.stderr)
        return None
    print("applied updates:", file=sys.stderr)
    for update in updates:
        print(
            f" - {update.variable} line {update.line}: {update.old} -> {update.new}",
            file=sys.stderr,
        )
    return 0, updates, updated_lines, updated_entries


def emit_summary(
    summary: dict[str, Any],
    markdown: str,
    json_requested: bool,
    markdown_requested: bool,
) -> None:
    if json_requested:
        print(json.dumps(summary, indent=2, sort_keys=True))
    elif markdown_requested:
        print(markdown)
    else:
        print(plain_summary(summary), end="")


def _validate_canonical(args: argparse.Namespace, common_sh: Path) -> int:
    try:
        lines, entries = parse_common(common_sh)
        errors = canonical_contract_errors(lines, entries)
        errors.extend(
            "active consumer contains copied canonical pin: " + item
            for item in active_consumer_pin_literals(common_sh)
        )
    except (OSError, UnicodeError) as exc:
        print(f"error: cannot read canonical common.sh: {exc}", file=sys.stderr)
        return 2
    if errors:
        if args.json:
            print(json.dumps({"status": STATUS_ERROR, "errors": errors}, indent=2))
        else:
            for error in errors:
                print(f"error: {error}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps({"status": STATUS_CURRENT, "errors": []}, indent=2))
    else:
        print("canonical common.sh pins: PASS")
    return 0


def _revalidate_candidate(
    candidate_entries: dict[str, VariableEntry],
    selected_components: tuple[str, ...],
    timeout: float,
) -> list[ComponentResult]:
    candidate_results = check_all(
        candidate_entries,
        HttpClient(timeout=timeout),
        selected_components,
    )
    append_missing_required_result(candidate_results, candidate_entries)
    append_unassigned_inventory_result(candidate_results, candidate_entries)
    return candidate_results


def _run_version_checks(
    args: argparse.Namespace,
    common_sh: Path,
    selected_components: tuple[str, ...],
) -> int:
    lines, entries = parse_common(common_sh)
    client = HttpClient(timeout=args.timeout)
    results = check_all(entries, client, selected_components)
    append_missing_required_result(results, entries)
    append_unassigned_inventory_result(results, entries)
    disposition = maintenance_disposition(
        results,
        entries,
        defer_reviewed_provenance=args.defer_reviewed_provenance,
    )
    rc = exit_code(
        results,
        entries,
        defer_reviewed_provenance=args.defer_reviewed_provenance,
    )

    update_result = apply_requested_updates(
        args.update,
        rc,
        common_sh,
        lines,
        entries,
        results,
        defer_reviewed_provenance=args.defer_reviewed_provenance,
        revalidate=lambda candidate_entries: _revalidate_candidate(
            candidate_entries, selected_components, args.timeout
        ),
    )
    if update_result is None:
        return 2
    rc, updates_applied, lines, entries = update_result

    summary = make_summary(
        common_sh,
        entries,
        results,
        updates_applied,
        disposition,
        selected_components,
    )
    markdown = markdown_summary(summary)
    if args.write_files:
        try:
            write_summary_files(summary, markdown)
        except UpstreamError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    emit_summary(summary, markdown, args.json, args.markdown)
    return rc


def main(argv: list[str] | None = None) -> int:
    args = parse_arguments(argv)

    if args.list_components:
        for definition in COMPONENT_DEFINITIONS:
            print(definition.name)
        return 0

    try:
        selected_components = canonical_component_selection(args.component)
    except UpstreamError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        common_sh = common_path_from_args(args.common_sh)
    except UpstreamError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.validate_canonical:
        return _validate_canonical(args, common_sh)
    return _run_version_checks(args, common_sh, selected_components)


if __name__ == "__main__":
    raise SystemExit(main())
