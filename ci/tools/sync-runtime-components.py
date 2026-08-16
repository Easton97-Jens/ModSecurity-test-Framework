#!/usr/bin/env python3
"""Synchronize reviewed runtime metadata without executing ``common.sh``.

``ci/lib/common.sh`` is PR-controlled shell.  This tool deliberately treats it
as data: it accepts only a small assignment grammar for the explicitly listed
runtime pin variables, expands only earlier allowlisted variables, and never
invokes a shell or subprocess.  It therefore remains safe to run in CI before
trusting a proposed common.sh change.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
COMMON = ROOT / "ci/lib/common.sh"
MANIFEST = ROOT / "ci/provisioning/runtime-components.manifest.json"
LOCK = ROOT / "ci/provisioning/runtime-component-lock.json"

SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$", re.ASCII)
VERSION_RE = re.compile(r"^\d+(?:\.\d+){2}$", re.ASCII)
ASSIGNMENT_RE = re.compile(
    r"^(?P<name>[A-Z][A-Z0-9_]*)=\"(?P<value>[^\"\r\n]*)\"$", re.ASCII
)
EXPANSION_RE = re.compile(
    r"\$(?:([A-Z][A-Z0-9_]*)|\{([A-Z][A-Z0-9_]*)(?:#([^{}$\\`;&|<>()]*))?\})",
    re.ASCII,
)
SAFE_LITERAL_RE = re.compile(r"[A-Za-z0-9./:_?=+@%\-]*", re.ASCII)
# Immutable digest of the official HAProxy download root.  The URL itself is
# intentionally kept only in common.sh; this trust anchor prevents a proposed
# common.sh from redirecting generated metadata to an attacker-controlled host
# without creating a second active URL pin in this parser.
HAPROXY_RELEASE_ROOT_SHA256 = (
    "61e9698ab286c0fd358feab0ee9717bf15e3c3365ed1637ee361fce737f07562"
)

# This table contains only stable variable names and profile metadata.  Pin
# values are parsed solely from common.sh and are never duplicated here.
PIN_VARIABLES = frozenset(
    {
        "ENVOY_VERSION",
        "ENVOY_SOURCE_URL",
        "ENVOY_INSTALL_DOCS_URL",
        "ENVOY_ARTIFACT_PLATFORM",
        "ENVOY_ASSET_NAME",
        "ENVOY_DOWNLOAD_URL",
        "ENVOY_SHA256",
        "ENVOY_SHA256_URL",
        "TRAEFIK_VERSION",
        "TRAEFIK_SOURCE_URL",
        "TRAEFIK_INSTALL_DOCS_URL",
        "TRAEFIK_ARTIFACT_PLATFORM",
        "TRAEFIK_ARCHIVE_NAME",
        "TRAEFIK_DOWNLOAD_URL",
        "TRAEFIK_SHA256",
        "TRAEFIK_SHA256_URL",
        "LIGHTTPD_SERIES",
        "LIGHTTPD_RELEASE_ROOT_URL",
        "LIGHTTPD_SERIES_BASE_URL",
        "LIGHTTPD_VERSION",
        "LIGHTTPD_SOURCE_URL",
        "LIGHTTPD_RELEASE_INDEX_URL",
        "LIGHTTPD_LATEST_URL",
        "LIGHTTPD_ARCHIVE_NAME",
        "LIGHTTPD_DOWNLOAD_URL",
        "LIGHTTPD_SHA256",
        "LIGHTTPD_SHA256_URL",
        "NGINX_SOURCE_REPO_URL",
        "NGINX_RELEASE_TAG",
        "NGINX_RELEASE_ASSET_NAME",
        "NGINX_SHA256",
        "HAPROXY_SERIES",
        "HAPROXY_RELEASE_ROOT_URL",
        "HAPROXY_SERIES_BASE_URL",
        "HAPROXY_VERSION",
        "HAPROXY_ARCHIVE_NAME",
        "HAPROXY_SOURCE_URL",
        "HAPROXY_SHA256",
        "HAPROXY_HTX_SERIES",
        "HAPROXY_HTX_SERIES_BASE_URL",
        "HAPROXY_HTX_VERSION",
        "HAPROXY_HTX_ARCHIVE_NAME",
        "HAPROXY_HTX_SOURCE_URL",
        "HAPROXY_HTX_SHA256",
    }
)
LOCK_DESCRIPTORS: tuple[dict[str, str], ...] = (
    {
        "id": "nginx-h1",
        "component": "nginx",
        "profile": "http/1.1",
        "version": "NGINX_RELEASE_TAG",
        "asset": "NGINX_RELEASE_ASSET_NAME",
        "url": "NGINX_DOWNLOAD_URL",
        "sha": "NGINX_SHA256",
        "source": "NGINX_SOURCE_REPO_URL",
        "version_prefix": "release-",
        "provenance": "github-release:{NGINX_RELEASE_TAG}",
    },
    {
        "id": "haproxy-htx",
        "component": "haproxy",
        "profile": "htx",
        "series": "HAPROXY_HTX_SERIES",
        "version": "HAPROXY_HTX_VERSION",
        "asset": "HAPROXY_HTX_ARCHIVE_NAME",
        "url": "HAPROXY_HTX_SOURCE_URL",
        "sha": "HAPROXY_HTX_SHA256",
        # HTX is an independently pinned tuple; never substitute generic HAProxy.
        "source": "HAPROXY_HTX_SOURCE_URL",
        "version_prefix": "",
        "provenance": "haproxy-release:{HAPROXY_HTX_VERSION}",
    },
    {
        "id": "haproxy-spoe-spop",
        "component": "haproxy",
        "profile": "spoe/spop",
        "series": "HAPROXY_SERIES",
        "version": "HAPROXY_VERSION",
        "asset": "HAPROXY_ARCHIVE_NAME",
        "url": "HAPROXY_SOURCE_URL",
        "sha": "HAPROXY_SHA256",
        "source": "HAPROXY_SOURCE_URL",
        "version_prefix": "",
        "provenance": "haproxy-release:{HAPROXY_VERSION}",
    },
    {
        "id": "envoy-ext-authz",
        "component": "envoy",
        "profile": "ext_authz",
        "version": "ENVOY_VERSION",
        "asset": "ENVOY_ASSET_NAME",
        "url": "ENVOY_DOWNLOAD_URL",
        "sha": "ENVOY_SHA256",
        "source": "ENVOY_SOURCE_URL",
        "platform": "ENVOY_ARTIFACT_PLATFORM",
        "version_prefix": "",
        "provenance": "github-release:v{ENVOY_VERSION}",
        "manifest": "true",
    },
    {
        "id": "envoy-ext-proc",
        "component": "envoy",
        "profile": "ext_proc",
        "version": "ENVOY_VERSION",
        "asset": "ENVOY_ASSET_NAME",
        "url": "ENVOY_DOWNLOAD_URL",
        "sha": "ENVOY_SHA256",
        "source": "ENVOY_SOURCE_URL",
        "platform": "ENVOY_ARTIFACT_PLATFORM",
        "version_prefix": "",
        "provenance": "github-release:v{ENVOY_VERSION}",
    },
    {
        "id": "traefik-forwardauth",
        "component": "traefik",
        "profile": "forwardauth",
        "version": "TRAEFIK_VERSION",
        "asset": "TRAEFIK_ARCHIVE_NAME",
        "url": "TRAEFIK_DOWNLOAD_URL",
        "sha": "TRAEFIK_SHA256",
        "source": "TRAEFIK_SOURCE_URL",
        "platform": "TRAEFIK_ARTIFACT_PLATFORM",
        "version_prefix": "",
        "provenance": "github-release:v{TRAEFIK_VERSION}",
    },
    {
        "id": "traefik-native",
        "component": "traefik",
        "profile": "native",
        "version": "TRAEFIK_VERSION",
        "asset": "TRAEFIK_ARCHIVE_NAME",
        "url": "TRAEFIK_DOWNLOAD_URL",
        "sha": "TRAEFIK_SHA256",
        "source": "TRAEFIK_SOURCE_URL",
        "platform": "TRAEFIK_ARTIFACT_PLATFORM",
        "version_prefix": "",
        "provenance": "github-release:v{TRAEFIK_VERSION}",
        "manifest": "true",
    },
    {
        "id": "lighttpd-sidecar",
        "component": "lighttpd",
        "profile": "sidecar_proxy",
        "series": "LIGHTTPD_SERIES",
        "version": "LIGHTTPD_VERSION",
        "asset": "LIGHTTPD_ARCHIVE_NAME",
        "url": "LIGHTTPD_DOWNLOAD_URL",
        "sha": "LIGHTTPD_SHA256",
        "source": "LIGHTTPD_SOURCE_URL",
        "version_prefix": "",
        "provenance": "lighttpd-release:{LIGHTTPD_VERSION}",
        "manifest": "true",
    },
)
MANIFEST_COMPONENTS = tuple(
    descriptor["component"]
    for descriptor in LOCK_DESCRIPTORS
    if descriptor.get("manifest") == "true"
)
if not MANIFEST_COMPONENTS or len(MANIFEST_COMPONENTS) != len(set(MANIFEST_COMPONENTS)):
    raise RuntimeError(
        "runtime descriptor manifest membership must be unique and non-empty"
    )
# Compatibility API for the runtime lock checker.  The checker consumes the
# descriptor schema, not a second pin table.
DESCRIPTORS = {
    descriptor["id"]: {**descriptor, "prefix": descriptor["version_prefix"]}
    for descriptor in LOCK_DESCRIPTORS
}


class SyncError(ValueError):
    """The static source or a generated artifact violates its contract."""


# Historical tests import these names from the compatibility wrapper.
ManifestSyncError = SyncError


def _framework_root_for_common(path: Path, test_root: Path | None = None) -> Path:
    resolved = _reject_symlink_path(path, "common", require_file=True)
    approved_test_root = (
        _reject_symlink_path(test_root, "explicit test root")
        if test_root is not None
        else None
    )
    if (
        resolved.name == "common.sh"
        and resolved.parent.name == "lib"
        and resolved.parent.parent.name == "ci"
    ):
        candidate = resolved.parents[2]
        if approved_test_root is not None:
            try:
                candidate.relative_to(approved_test_root)
            except ValueError as exc:
                raise SyncError("common must be below the explicit test root") from exc
            return approved_test_root
        try:
            candidate.relative_to(ROOT)
        except ValueError as exc:
            raise SyncError(
                "common must be below the approved Framework checkout"
            ) from exc
        return ROOT
    if test_root is None:
        raise SyncError(
            "non-canonical common path requires an explicit test root; "
            "production inputs must be below the approved Framework checkout"
        )
    assert approved_test_root is not None
    try:
        resolved.relative_to(approved_test_root)
    except ValueError as exc:
        raise SyncError("common must be below the explicit test root") from exc
    # Parser-only test fixtures may use a differently named temporary source;
    # unlike sourcing, accepting that file cannot execute its contents.
    return approved_test_root


def _reject_symlink_path(path: Path, label: str, *, require_file: bool = False) -> Path:
    """Return an absolute path only when every existing component is trusted."""

    absolute = Path(os.path.abspath(path))
    current = absolute
    while True:
        _inspect_path_component(current, absolute, label)
        if current == Path(current.anchor):
            break
        current = current.parent
    if require_file and (not absolute.is_file() or absolute.is_symlink()):
        raise SyncError(f"{label} must be a regular file")
    return absolute


def _inspect_path_component(current: Path, absolute: Path, label: str) -> None:
    try:
        current.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise SyncError(f"cannot inspect {label}: {current}") from exc
    if current.is_symlink():
        raise SyncError(f"{label} contains a symlink path component: {current}")
    if current != absolute and not current.is_dir():
        raise SyncError(f"{label} contains a non-directory ancestor: {current}")


def require_regular(path: Path, root: Path, label: str) -> Path:
    try:
        resolved = _reject_symlink_path(path, label, require_file=True)
        trusted_root = _reject_symlink_path(root, "Framework source root")
        resolved.relative_to(trusted_root)
        canonical = resolved.resolve(strict=True)
        canonical.relative_to(trusted_root.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise SyncError(f"{label} must be below the Framework source root") from exc
    if canonical != resolved or not canonical.is_file() or canonical.is_symlink():
        raise SyncError(
            f"{label} must be a regular file below the Framework source root"
        )
    return canonical


def _expand_expression(
    expression: str, raw: dict[str, str], stack: tuple[str, ...]
) -> str:
    """Evaluate only $NAME, ${NAME}, and ${NAME#literal-prefix}."""
    pieces: list[str] = []
    position = 0
    for match in EXPANSION_RE.finditer(expression):
        literal = expression[position : match.start()]
        if not SAFE_LITERAL_RE.fullmatch(literal):
            raise SyncError("canonical assignment uses disallowed shell syntax")
        pieces.append(literal)
        name = match.group(1) or match.group(2)
        assert name is not None
        if name not in PIN_VARIABLES or name not in raw:
            raise SyncError(
                f"canonical assignment references unavailable allowlisted variable {name}"
            )
        if name in stack:
            raise SyncError(
                f"canonical assignment has a variable expansion cycle at {name}"
            )
        value = _expand_expression(raw[name], raw, (*stack, name))
        prefix = match.group(3)
        if prefix is not None:
            if not value.startswith(prefix):
                raise SyncError(
                    f"canonical assignment cannot remove prefix {prefix!r} from {name}"
                )
            value = value[len(prefix) :]
        pieces.append(value)
        position = match.end()
    trailing = expression[position:]
    if not SAFE_LITERAL_RE.fullmatch(trailing):
        raise SyncError("canonical assignment uses disallowed shell syntax")
    pieces.append(trailing)
    return "".join(pieces)


def _collect_assignments(source: Path) -> dict[str, str]:
    raw: dict[str, str] = {}
    for line_number, line in enumerate(
        _read_trusted_text(source, "common").splitlines(), 1
    ):
        match = ASSIGNMENT_RE.fullmatch(line)
        if match is None:
            continue
        name, expression = match.group("name"), match.group("value")
        if name not in PIN_VARIABLES:
            continue
        _validate_expression_syntax(expression, source, line_number, name)
        if name in raw:
            if name == "TRAEFIK_VERSION":
                raise SyncError(
                    f"{source}: expected exactly one manually maintained TRAEFIK_VERSION literal, found 2"
                )
            raise SyncError(
                f"{source}:{line_number}: duplicate canonical assignment for {name}"
            )
        raw[name] = expression
    missing = sorted(PIN_VARIABLES - set(raw))
    if missing:
        raise SyncError(
            f"{source}: missing canonical assignments: {', '.join(missing)}"
        )
    return raw


def _validate_expression_syntax(
    expression: str, source: Path, line_number: int, name: str
) -> None:
    position = 0
    for match in EXPANSION_RE.finditer(expression):
        if not SAFE_LITERAL_RE.fullmatch(expression[position : match.start()]):
            raise SyncError(
                f"{source}:{line_number}: malformed canonical assignment for {name}"
            )
        position = match.end()
    if not SAFE_LITERAL_RE.fullmatch(expression[position:]):
        raise SyncError(
            f"{source}:{line_number}: malformed canonical assignment for {name}"
        )


def _validate_pin_values(values: dict[str, str]) -> None:
    _validate_pin_formats(values)
    _validate_release_bindings(values)


def _validate_pin_formats(values: dict[str, str]) -> None:
    for name, value in values.items():
        if name.endswith("SHA256") and not SHA256_RE.fullmatch(value):
            raise SyncError(f"{name} is not a 64-character SHA-256 digest")
        if name.endswith("VERSION") and not VERSION_RE.fullmatch(value):
            raise SyncError(f"{name} must be an exact dotted release")


def _validate_release_bindings(values: dict[str, str]) -> None:
    _validate_nginx_binding(values)
    _validate_lighttpd_binding(values)
    _validate_haproxy_bindings(values)


def _validate_nginx_binding(values: dict[str, str]) -> None:
    nginx_tag = values["NGINX_RELEASE_TAG"]
    if not nginx_tag.startswith("release-") or not VERSION_RE.fullmatch(nginx_tag[8:]):
        raise SyncError("NGINX_RELEASE_TAG must use release-X.Y.Z")


def _validate_lighttpd_binding(values: dict[str, str]) -> None:
    _validate_series_binding(
        values["LIGHTTPD_SERIES"], values["LIGHTTPD_VERSION"], "LIGHTTPD"
    )
    if values["LIGHTTPD_SERIES_BASE_URL"] != (
        f"{values['LIGHTTPD_RELEASE_ROOT_URL']}/releases-{values['LIGHTTPD_SERIES']}.x"
    ):
        raise SyncError(
            "LIGHTTPD_SERIES_BASE_URL is not derived from its release root and series"
        )
    if values["LIGHTTPD_SOURCE_URL"] != f"{values['LIGHTTPD_SERIES_BASE_URL']}/":
        raise SyncError(
            "LIGHTTPD_SOURCE_URL must be the series base URL with one trailing slash"
        )
    if (
        values["LIGHTTPD_LATEST_URL"]
        != f"{values['LIGHTTPD_SERIES_BASE_URL']}/latest.txt"
    ):
        raise SyncError("LIGHTTPD_LATEST_URL must be derived from the series base URL")
    if "//" in values["LIGHTTPD_LATEST_URL"].removeprefix("https://"):
        raise SyncError("LIGHTTPD_LATEST_URL contains a double slash")


def _validate_haproxy_bindings(values: dict[str, str]) -> None:
    root_digest = hashlib.sha256(
        values["HAPROXY_RELEASE_ROOT_URL"].encode("ascii")
    ).hexdigest()
    if root_digest != HAPROXY_RELEASE_ROOT_SHA256:
        raise SyncError("HAPROXY_RELEASE_ROOT_URL must be the authorized official root")
    _validate_series_binding(
        values["HAPROXY_SERIES"], values["HAPROXY_VERSION"], "HAPROXY"
    )
    _validate_series_binding(
        values["HAPROXY_HTX_SERIES"], values["HAPROXY_HTX_VERSION"], "HAPROXY_HTX"
    )
    if values["HAPROXY_SERIES_BASE_URL"] != (
        f"{values['HAPROXY_RELEASE_ROOT_URL']}/{values['HAPROXY_SERIES']}/src"
    ):
        raise SyncError(
            "HAPROXY_SERIES_BASE_URL is not derived from its release root and series"
        )
    if values["HAPROXY_HTX_SERIES_BASE_URL"] != (
        f"{values['HAPROXY_RELEASE_ROOT_URL']}/{values['HAPROXY_HTX_SERIES']}/src"
    ):
        raise SyncError(
            "HAPROXY_HTX_SERIES_BASE_URL is not derived from its release root and series"
        )
    if values["HAPROXY_SOURCE_URL"] != (
        f"{values['HAPROXY_SERIES_BASE_URL']}/{values['HAPROXY_ARCHIVE_NAME']}"
    ):
        raise SyncError("HAPROXY_SOURCE_URL is not derived from its series base URL")
    if values["HAPROXY_HTX_SOURCE_URL"] != (
        f"{values['HAPROXY_HTX_SERIES_BASE_URL']}/{values['HAPROXY_HTX_ARCHIVE_NAME']}"
    ):
        raise SyncError(
            "HAPROXY_HTX_SOURCE_URL is not derived from its series base URL"
        )


def _validate_series_binding(series: str, version: str, label: str) -> None:
    if not re.fullmatch(r"\d+\.\d+", series):
        raise SyncError(f"{label} series must be an exact numeric major.minor value")
    if not VERSION_RE.fullmatch(version) or not version.startswith(f"{series}."):
        raise SyncError(
            f"{label} version {version!r} does not match declared series {series!r}"
        )


def _expand_pin_values(raw: dict[str, str]) -> dict[str, str]:
    values = {
        name: _expand_expression(raw[name], raw, (name,)) for name in PIN_VARIABLES
    }
    # NGINX has a release repository, tag, and asset; the download URL is
    # deterministic metadata derived from those canonical fields.
    values["NGINX_DOWNLOAD_URL"] = (
        f"{values['NGINX_SOURCE_REPO_URL'].rstrip('/')}/releases/download/"
        f"{values['NGINX_RELEASE_TAG']}/{values['NGINX_RELEASE_ASSET_NAME']}"
    )
    return values


def common_values(path: Path, test_root: Path | None = None) -> dict[str, str]:
    """Read the canonical runtime pins with a non-executing allowlist parser."""
    root = _framework_root_for_common(path, test_root)
    source = require_regular(path, root, "common")
    values = _expand_pin_values(_collect_assignments(source))
    _validate_pin_values(values)
    return values


def load_canonical_tuple(path: Path) -> dict[str, str]:
    values = common_values(path)
    names = (
        "TRAEFIK_VERSION",
        "TRAEFIK_SOURCE_URL",
        "TRAEFIK_INSTALL_DOCS_URL",
        "TRAEFIK_ARTIFACT_PLATFORM",
        "TRAEFIK_ARCHIVE_NAME",
        "TRAEFIK_DOWNLOAD_URL",
        "TRAEFIK_SHA256",
        "TRAEFIK_SHA256_URL",
    )
    return {name: values[name] for name in names}


def validate_canonical_tuple(values: dict[str, str]) -> None:
    version = values.get("TRAEFIK_VERSION", "")
    if not VERSION_RE.fullmatch(version):
        raise ManifestSyncError(
            "canonical Traefik version must be an exact dotted release"
        )
    if not SHA256_RE.fullmatch(values.get("TRAEFIK_SHA256", "")):
        raise ManifestSyncError(
            "canonical Traefik SHA256 must be exactly 64 hexadecimal characters"
        )
    platform = values.get("TRAEFIK_ARTIFACT_PLATFORM", "")
    platform_identity(platform)
    expected_asset = f"traefik_v{version}_{platform}.tar.gz"
    if values.get("TRAEFIK_ARCHIVE_NAME") != expected_asset:
        raise ManifestSyncError(
            "canonical Traefik archive name does not bind the version and platform"
        )
    source = values.get("TRAEFIK_SOURCE_URL", "")
    if (
        values.get("TRAEFIK_DOWNLOAD_URL")
        != f"{source}/download/v{version}/{expected_asset}"
    ):
        raise ManifestSyncError(
            "canonical Traefik download URL does not bind the selected archive"
        )
    if (
        values.get("TRAEFIK_SHA256_URL")
        != f"{source}/download/v{version}/traefik_v{version}_checksums.txt"
    ):
        raise ManifestSyncError(
            "canonical Traefik checksum URL does not bind the selected release"
        )


def source_root_url(value: str) -> str:
    """Release pages use a stable repository URL in the lock provenance."""
    return value.removesuffix("/releases")


def platform_identity(raw_platform: str) -> tuple[str, str]:
    """Normalize a canonical artifact-platform spelling to OS/architecture.

    The raw spelling remains the pin in common.sh.  This conversion only
    bridges common upstream conventions (underscore or dash separators) to
    the lock and manifest schema's OS/architecture fields.
    """
    normalized = raw_platform.lower().replace("-", "_")
    if "_" not in normalized:
        raise SyncError(
            f"canonical platform {raw_platform!r} lacks an OS/architecture separator"
        )
    operating_system, architecture = normalized.split("_", 1)
    if (
        not operating_system
        or not architecture
        or not re.fullmatch(r"[a-z0-9_]+", normalized, re.ASCII)
    ):
        raise SyncError(f"canonical platform {raw_platform!r} is invalid")
    # x86-64 is an upstream spelling; the lock schema uses its OCI name.
    architecture_key = architecture.replace("_", "")
    architecture = (
        "amd64" if architecture_key == "x8664" else architecture.replace("_", "-")
    )
    return operating_system, architecture


def runtime_profile_platform(values: dict[str, str]) -> tuple[str, str]:
    """Require every pinned binary artifact to select the same runtime target."""
    identities = {
        platform_identity(values[descriptor["platform"]])
        for descriptor in LOCK_DESCRIPTORS
        if descriptor.get("platform")
    }
    if len(identities) != 1:
        rendered = ", ".join(
            f"{os_name}/{architecture}" for os_name, architecture in sorted(identities)
        )
        raise SyncError(f"canonical runtime artifact platforms disagree: {rendered}")
    return next(iter(identities))


def normalized_asset(descriptor: dict[str, str], values: dict[str, str]) -> str:
    """Return the reviewed release asset named by a lock descriptor."""
    return values[descriptor["asset"]]


def render_lock(values: dict[str, str]) -> dict[str, Any]:
    operating_system, architecture = runtime_profile_platform(values)
    profiles: list[dict[str, str]] = []
    for descriptor in LOCK_DESCRIPTORS:
        version = values[descriptor["version"]]
        prefix = descriptor["version_prefix"]
        if prefix:
            if not version.startswith(prefix):
                raise SyncError(
                    f"{descriptor['id']} version does not use required prefix {prefix!r}"
                )
            version = version[len(prefix) :]
        source = values[descriptor["source"]]
        if descriptor["component"] in {"envoy", "traefik"}:
            source = source_root_url(source)
        provenance = descriptor["provenance"].format(**values)
        profiles.append(
            {
                "id": descriptor["id"],
                "component": descriptor["component"],
                "profile": descriptor["profile"],
                "version": version,
                "series": values[descriptor["series"]]
                if descriptor.get("series")
                else "",
                "os": operating_system,
                "arch": architecture,
                "asset_name": values[descriptor["asset"]],
                "download_url": values[descriptor["url"]],
                "sha256": values[descriptor["sha"]].lower(),
                "source_url": source,
                "source_provenance": provenance,
            }
        )
    return {
        "schema_version": 1,
        "platform": f"{operating_system}-{architecture}",
        "profiles": profiles,
    }


def expected_manifest_fields(component: str, values: dict[str, str]) -> dict[str, str]:
    if component == "envoy":
        operating_system, architecture = platform_identity(
            values["ENVOY_ARTIFACT_PLATFORM"]
        )
        return {
            "artifact_type": "direct_binary",
            "artifact_platform": f"{operating_system}/{architecture}",
            "archive_name": values["ENVOY_ASSET_NAME"],
            "pin_source": "ci/lib/common.sh:ENVOY_VERSION",
            "version_env": "ENVOY_VERSION",
            "version": values["ENVOY_VERSION"],
            "source_url_env": "ENVOY_SOURCE_URL",
            "source_url": values["ENVOY_SOURCE_URL"],
            "install_docs_env": "ENVOY_INSTALL_DOCS_URL",
            "install_docs": values["ENVOY_INSTALL_DOCS_URL"],
            "download_url_env": "ENVOY_DOWNLOAD_URL",
            "download_url": values["ENVOY_DOWNLOAD_URL"],
            "sha256_env": "ENVOY_SHA256",
            "sha256": values["ENVOY_SHA256"].lower(),
            "sha256_url_env": "ENVOY_SHA256_URL",
            "sha256_url": values["ENVOY_SHA256_URL"],
        }
    if component == "traefik":
        validate_canonical_tuple(load_canonical_tuple_from_values(values))
        operating_system, architecture = platform_identity(
            values["TRAEFIK_ARTIFACT_PLATFORM"]
        )
        return {
            "artifact_type": "tarball_with_binary",
            "artifact_digest_type": "sha256_release_archive",
            "artifact_platform": f"{operating_system}/{architecture}",
            "archive_name": values["TRAEFIK_ARCHIVE_NAME"],
            "pin_source": "ci/lib/common.sh:ci_traefik_set_canonical_tuple",
            "version_env": "TRAEFIK_VERSION",
            "version": values["TRAEFIK_VERSION"],
            "source_url_env": "TRAEFIK_SOURCE_URL",
            "source_url": values["TRAEFIK_SOURCE_URL"],
            "install_docs_env": "TRAEFIK_INSTALL_DOCS_URL",
            "install_docs": values["TRAEFIK_INSTALL_DOCS_URL"],
            "download_url_env": "TRAEFIK_DOWNLOAD_URL",
            "download_url": values["TRAEFIK_DOWNLOAD_URL"],
            "sha256_env": "TRAEFIK_SHA256",
            "sha256": values["TRAEFIK_SHA256"].lower(),
            "sha256_url_env": "TRAEFIK_SHA256_URL",
            "sha256_url": values["TRAEFIK_SHA256_URL"],
        }
    if component == "lighttpd":
        version = values["LIGHTTPD_VERSION"]
        return {
            "artifact_type": "source_tarball",
            "artifact_digest_type": "sha256_source_archive",
            "archive_name": values["LIGHTTPD_ARCHIVE_NAME"],
            "pin_source": "ci/lib/common.sh:LIGHTTPD_VERSION",
            "series_env": "LIGHTTPD_SERIES",
            "series": values["LIGHTTPD_SERIES"],
            "release_root_url_env": "LIGHTTPD_RELEASE_ROOT_URL",
            "release_root_url": values["LIGHTTPD_RELEASE_ROOT_URL"],
            "series_base_url_env": "LIGHTTPD_SERIES_BASE_URL",
            "series_base_url": values["LIGHTTPD_SERIES_BASE_URL"],
            "version_env": "LIGHTTPD_VERSION",
            "version": version,
            "source_url_env": "LIGHTTPD_SOURCE_URL",
            "source_url": values["LIGHTTPD_SOURCE_URL"],
            "release_index_url_env": "LIGHTTPD_RELEASE_INDEX_URL",
            "release_index_url": values["LIGHTTPD_RELEASE_INDEX_URL"],
            "latest_url_env": "LIGHTTPD_LATEST_URL",
            "latest_url": values["LIGHTTPD_LATEST_URL"],
            "download_url_env": "LIGHTTPD_DOWNLOAD_URL",
            "download_url": values["LIGHTTPD_DOWNLOAD_URL"],
            "sha256_env": "LIGHTTPD_SHA256",
            "sha256": values["LIGHTTPD_SHA256"].lower(),
            "sha256_url_env": "LIGHTTPD_SHA256_URL",
            "sha256_url": values["LIGHTTPD_SHA256_URL"],
            "source_stage_dir": f"$BUILD_ROOT/lighttpd-connector/src/lighttpd-{version}",
        }
    raise SyncError(f"unsupported runtime manifest component {component}")


def load_canonical_tuple_from_values(values: dict[str, str]) -> dict[str, str]:
    return {
        name: values[name]
        for name in (
            "TRAEFIK_VERSION",
            "TRAEFIK_SOURCE_URL",
            "TRAEFIK_INSTALL_DOCS_URL",
            "TRAEFIK_ARTIFACT_PLATFORM",
            "TRAEFIK_ARCHIVE_NAME",
            "TRAEFIK_DOWNLOAD_URL",
            "TRAEFIK_SHA256",
            "TRAEFIK_SHA256_URL",
        )
    }


def render_manifest(
    current: dict[str, Any], values: dict[str, str], component: str | None
) -> dict[str, Any]:
    if current.get("schema_version") != 1 or not isinstance(
        current.get("components"), list
    ):
        raise SyncError("manifest must use schema_version 1 with a components array")
    entries = current["components"]
    names: list[str] = []
    by_name: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
            raise SyncError("manifest component entries must be named objects")
        name = entry["name"]
        if name in by_name:
            raise SyncError(f"manifest contains duplicate component {name}")
        names.append(name)
        by_name[name] = entry
    required = {component} if component else set(MANIFEST_COMPONENTS)
    if component is None and set(names) != set(MANIFEST_COMPONENTS):
        raise SyncError(
            f"manifest component coverage mismatch: expected {sorted(MANIFEST_COMPONENTS)}, found {sorted(names)}"
        )
    if component is not None and component not in by_name:
        raise SyncError(f"manifest is missing {component}")
    rendered = json.loads(json.dumps(current))
    rendered_by_name = {entry["name"]: entry for entry in rendered["components"]}
    for name in required:
        rendered_by_name[name].update(expected_manifest_fields(name, values))
    return rendered


def render_json(document: Any) -> str:
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def _read_json(path: Path, label: str) -> Any:
    try:
        document = json.loads(_read_trusted_text(path, label))
    except json.JSONDecodeError as exc:
        raise SyncError(f"invalid {label} JSON: {exc}") from exc
    return document


def _read_trusted_text(path: Path, label: str) -> str:
    """Read a previously validated file without reopening through a symlink."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SyncError(f"cannot open trusted {label}: {path}") from exc
    try:
        with os.fdopen(descriptor, "r", encoding="utf-8", newline="") as stream:
            descriptor = -1
            return stream.read()
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def atomic_write(path: Path, content: str) -> None:
    parent = _reject_symlink_path(path.parent, "atomic output parent")
    if path.exists() or path.is_symlink():
        _reject_symlink_path(path, "atomic output")
    directory_flags = (
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        directory = os.open(parent, directory_flags)
    except OSError as exc:
        raise SyncError(f"cannot open atomic output parent: {parent}") from exc
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=parent, text=True
    )
    temporary_name = Path(temporary).name
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
        os.rename(
            temporary_name,
            path.name,
            src_dir_fd=directory,
            dst_dir_fd=directory,
        )
    except BaseException:
        try:
            os.unlink(temporary_name, dir_fd=directory)
        except FileNotFoundError:
            pass
        raise
    finally:
        os.close(directory)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    parser.add_argument("--common-sh", type=Path, default=COMMON)
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--lock", type=Path, default=LOCK)
    parser.add_argument(
        "--test-root",
        type=Path,
        help="explicit root for parser-only synthetic fixtures; not used by production workflows",
    )
    parser.add_argument("--component", choices=MANIFEST_COMPONENTS)
    return parser.parse_args(argv)


def _render_documents(
    args: argparse.Namespace, values: dict[str, str], common_root: Path
) -> tuple[Path, dict[str, Any], bool, Path | None, dict[str, Any] | None, bool]:
    manifest_root = (
        common_root.parent if args.component and common_root != ROOT else common_root
    )
    manifest_path = require_regular(args.manifest, manifest_root, "manifest")
    current_manifest = _read_json(manifest_path, "manifest")
    expected_manifest = render_manifest(current_manifest, values, args.component)
    manifest_drift = render_json(current_manifest) != render_json(expected_manifest)
    if args.component is not None:
        return manifest_path, expected_manifest, manifest_drift, None, None, False
    lock_path = require_regular(args.lock, common_root, "lock")
    current_lock = _read_json(lock_path, "lock")
    expected_lock = render_lock(values)
    lock_drift = render_json(current_lock) != render_json(expected_lock)
    return (
        manifest_path,
        expected_manifest,
        manifest_drift,
        lock_path,
        expected_lock,
        lock_drift,
    )


def _report_drift(manifest_drift: bool, lock_drift: bool) -> int:
    if not manifest_drift and not lock_drift:
        return 0
    print(
        "runtime component synchronization drift: "
        f"lock={'drift' if lock_drift else 'ok'} "
        f"manifest={'drift' if manifest_drift else 'ok'} "
        "expected=generated found=checked-in",
        file=sys.stderr,
    )
    return 1


def run(args: argparse.Namespace) -> int:
    common_root = _framework_root_for_common(args.common_sh, args.test_root)
    require_regular(args.common_sh, common_root, "common")
    values = common_values(args.common_sh, args.test_root)
    (
        manifest_path,
        expected_manifest,
        manifest_drift,
        lock_path,
        expected_lock,
        lock_drift,
    ) = _render_documents(args, values, common_root)
    if args.check:
        drift_status = _report_drift(manifest_drift, lock_drift)
        if drift_status:
            return drift_status
        print(
            "traefik runtime manifest: PASS"
            if args.component == "traefik"
            else "runtime components: PASS"
        )
        return 0
    if manifest_drift:
        atomic_write(manifest_path, render_json(expected_manifest))
    if lock_drift and lock_path is not None and expected_lock is not None:
        atomic_write(lock_path, render_json(expected_lock))
    print(
        f"traefik runtime manifest: wrote {manifest_path}"
        if args.component == "traefik"
        else "runtime components: wrote"
    )
    return 0


def main(argv: list[str]) -> int:
    return run(parse_args(argv))


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, ValueError) as exc:
        print(f"sync-runtime-components: ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2)
