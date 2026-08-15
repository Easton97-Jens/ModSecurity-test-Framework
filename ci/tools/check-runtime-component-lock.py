#!/usr/bin/env python3
"""Verify the single runtime-component version/asset/digest contract."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ASSIGNMENT = re.compile(r"^(?P<name>[A-Z][A-Z0-9_]*)=\"(?P<value>[^\"]*)\"$")
DEFAULTS = {
    "nginx": ("NGINX_RELEASE_TAG", "NGINX_SHA256"),
    "haproxy": ("HAPROXY_VERSION", "HAPROXY_SHA256"),
    "envoy": ("ENVOY_VERSION", "ENVOY_SHA256"),
    "traefik": ("TRAEFIK_VERSION", "TRAEFIK_SHA256"),
}
HTX_DEFAULTS = ("HAPROXY_HTX_VERSION", "HAPROXY_HTX_SHA256")
EXPECTED_ASSET_TEMPLATE = {
    "nginx": "nginx-{version}.tar.gz",
    "haproxy": "haproxy-{version}.tar.gz",
    "envoy": "envoy-{version}-linux-x86_64",
    "traefik": "traefik_v{version}_linux_amd64.tar.gz",
}


def framework_source_root(common: Path) -> Path:
    """Return this checker's canonical Framework root for reviewed files."""
    source_root = Path(__file__).resolve().parents[2]
    try:
        common_resolved = common.resolve(strict=True)
        relative = common_resolved.relative_to(source_root)
    except OSError as exc:
        raise ValueError(f"common file cannot be resolved: {exc}") from exc
    except ValueError as exc:
        raise ValueError("common must be below this checker's Framework source root") from exc
    if relative != Path("ci/lib/common.sh"):
        raise ValueError("common must be Framework ci/lib/common.sh")
    if not source_root.is_dir() or common.is_symlink():
        raise ValueError("common must be a regular file in the Framework source root")
    return source_root


def read_framework_text(path: Path, source_root: Path, label: str) -> str:
    """Read only a regular, non-symlinked file below the Framework root."""
    try:
        resolved = path.resolve(strict=True)
        relative = resolved.relative_to(source_root)
    except (OSError, ValueError) as exc:
        raise ValueError(f"{label} must be below the Framework source root") from exc
    if not relative.parts or not resolved.is_file() or path.is_symlink():
        raise ValueError(f"{label} must be a regular file below the Framework source root")
    candidate = path.absolute()
    while candidate != source_root:
        if candidate.is_symlink():
            raise ValueError(f"{label} contains a symlinked path component")
        candidate = candidate.parent
    try:
        with resolved.open(encoding="utf-8") as handle:
            return handle.read()
    except OSError as exc:
        raise ValueError(f"{label} cannot be read: {exc}") from exc


def environment_values(raw_values: list[str]) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in raw_values:
        if "=" not in raw:
            raise ValueError("environment value must use NAME=VALUE")
        name, value = raw.split("=", 1)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", name):
            raise ValueError("environment value name is invalid")
        if name in values:
            raise ValueError(f"environment value {name} is duplicated")
        values[name] = value
    return values


def require_environment_profile(
    components: list[dict[str, object]], profile_id: str, raw_values: list[str]
) -> None:
    profile = next((item for item in components if item.get("id") == profile_id), None)
    if profile is None:
        raise ValueError(f"environment profile {profile_id} is not locked")
    values = environment_values(raw_values)
    version = str(profile["version"])
    asset = str(profile["asset_name"])
    digest = str(profile["sha256"])
    download_url = str(profile["download_url"])
    expected: dict[str, str]
    if profile_id == "nginx-h1":
        expected = {
            "NGINX_RELEASE_TAG": f"release-{version}",
            "NGINX_RELEASE_ASSET_NAME": asset,
            "NGINX_SHA256": digest,
        }
    elif profile_id == "haproxy-htx":
        expected = {
            "HAPROXY_HTX_VERSION": version,
            "HAPROXY_HTX_SOURCE_URL": download_url,
            "HAPROXY_HTX_SHA256": digest,
        }
    elif profile_id == "haproxy-spoe-spop":
        expected = {
            "HAPROXY_VERSION": version,
            "HAPROXY_SOURCE_URL": download_url,
            "HAPROXY_SHA256": digest,
        }
    elif profile_id.startswith("envoy-"):
        expected = {
            "ENVOY_VERSION": version,
            "ENVOY_DOWNLOAD_URL": download_url,
            "ENVOY_SHA256": digest,
        }
    elif profile_id.startswith("traefik-"):
        expected = {
            "TRAEFIK_VERSION": version,
            "TRAEFIK_DOWNLOAD_URL": download_url,
            "TRAEFIK_SHA256": digest,
        }
    else:
        raise ValueError(f"environment profile {profile_id} is unsupported")
    if set(values) != set(expected):
        raise ValueError(f"environment profile {profile_id} fields mismatch")
    for name, expected_value in expected.items():
        actual = values[name]
        if name.endswith("SHA256"):
            actual = actual.lower()
            expected_value = expected_value.lower()
        if actual != expected_value:
            raise ValueError(f"environment profile {profile_id} {name} drift")


def defaults(path: Path, source_root: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in read_framework_text(path, source_root, "common").splitlines():
        match = ASSIGNMENT.match(raw.strip())
        if not match:
            continue
        value = match.group("value")
        if value.startswith("${") and value.endswith("}"):
            inner = value[2:-1]
            if ":-" in inner:
                value = inner.split(":-", 1)[1]
            elif "-" in inner:
                value = inner.split("-", 1)[1]
            else:
                value = ""
        if "${" not in value:
            values[match.group("name")] = value
    return values


def expected_version(name: str, values: dict[str, str]) -> str:
    value = values[DEFAULTS[name][0]]
    if name == "nginx":
        if not value.startswith("release-"):
            raise ValueError("NGINX_RELEASE_TAG must use release-X.Y.Z")
        return value.removeprefix("release-")
    return value


def expected_tuple(item: dict[str, str], values: dict[str, str]) -> tuple[str, str]:
    if item["id"] == "haproxy-htx":
        return values[HTX_DEFAULTS[0]], values[HTX_DEFAULTS[1]].lower()
    name = item["component"]
    return expected_version(name, values), values[DEFAULTS[name][1]].lower()


def require_profile_shape(item: dict[str, object], version: str, digest: str) -> None:
    identifier = str(item.get("id", "unknown"))
    component = str(item.get("component", ""))
    if component not in EXPECTED_ASSET_TEMPLATE:
        raise ValueError(f"{identifier} has an unsupported component")
    actual_digest = str(item.get("sha256", "")).lower()
    if re.fullmatch(r"[0-9a-f]{64}", actual_digest) is None:
        raise ValueError(f"{identifier} SHA-256 is missing or invalid")
    if actual_digest != digest:
        raise ValueError(f"{identifier} SHA-256 drift")
    if item.get("os") != "linux" or item.get("arch") != "amd64":
        raise ValueError(f"{identifier} has an unsupported platform")
    expected_asset = EXPECTED_ASSET_TEMPLATE[component].format(version=version)
    if item.get("asset_name") != expected_asset:
        raise ValueError(f"{identifier} asset does not match locked version and architecture")
    download_url = str(item.get("download_url", ""))
    if not download_url.startswith("https://") or not download_url.endswith(f"/{expected_asset}"):
        raise ValueError(f"{identifier} download URL does not bind the locked asset")
    if not item.get("source_url") or not item.get("source_provenance"):
        raise ValueError(f"{identifier} lacks source provenance")


def require_manifest_matches_lock(
    manifest: dict[str, object], components: list[dict[str, object]]
) -> None:
    entries = {entry["name"]: entry for entry in manifest["components"]}
    for name in ("envoy", "traefik"):
        entry = entries.get(name)
        if entry is None:
            raise ValueError(f"manifest is missing {name}")
        profile = next(item for item in components if item["component"] == name)
        if entry.get("version") != profile["version"]:
            raise ValueError(f"manifest {name} version drift")
        if entry.get("sha256", "").lower() != profile["sha256"].lower():
            raise ValueError(f"manifest {name} SHA-256 drift")
        if entry.get("download_url") != profile["download_url"]:
            raise ValueError(f"manifest {name} asset/download drift")


def validate_lock(
    lock: dict[str, object], values: dict[str, str]
) -> list[dict[str, object]]:
    if lock.get("schema_version") != 1:
        raise ValueError("lock schema_version must be 1")
    if lock.get("platform") != "linux-amd64":
        raise ValueError("lock platform must be linux-amd64")
    components = lock.get("profiles")
    if not isinstance(components, list):
        raise ValueError("lock profiles must be a list")
    expected_ids = {
        "nginx-h1", "haproxy-htx", "haproxy-spoe-spop",
        "envoy-ext-authz", "envoy-ext-proc", "traefik-forwardauth",
        "traefik-native",
    }
    ids = [item.get("id") for item in components if isinstance(item, dict)]
    if set(ids) != expected_ids or len(ids) != len(expected_ids):
        raise ValueError(f"lock profiles mismatch: {sorted(str(item) for item in ids)}")
    for item in components:
        if not isinstance(item, dict):
            raise ValueError("lock profile must be an object")
        version, digest = expected_tuple(item, values)
        if item["version"] != version:
            raise ValueError(f"{item['id']} version drift: lock={item['version']} common={version}")
        if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise ValueError(f"{item['id']} canonical SHA-256 is invalid")
        require_profile_shape(item, version, digest)
    return components


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--common", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--environment-profile")
    parser.add_argument("--environment-value", action="append", default=[])
    args = parser.parse_args()
    try:
        source_root = framework_source_root(args.common)
        lock = json.loads(read_framework_text(args.lock, source_root, "lock"))
        values = defaults(args.common, source_root)
        components = validate_lock(lock, values)
        if args.manifest:
            manifest = json.loads(read_framework_text(args.manifest, source_root, "manifest"))
            require_manifest_matches_lock(manifest, components)
        if args.environment_profile:
            require_environment_profile(
                components, args.environment_profile, args.environment_value
            )
        print("runtime-component-lock: PASS")
    except (OSError, KeyError, TypeError, ValueError) as exc:
        print(f"runtime-component-lock: BLOCKED: {exc}", file=sys.stderr)
        return 77
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
