#!/usr/bin/env python3
"""Verify the single runtime-component version/asset/digest contract."""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path


def synchronizer(source_root: Path):
    """Load the generic runtime descriptor API from this Framework checkout."""
    path = source_root / "ci/tools/sync-runtime-components.py"
    if path.is_symlink() or not path.is_file():
        raise ValueError("generic runtime synchronizer is missing or not a regular file")
    spec = importlib.util.spec_from_file_location("runtime_component_sync", path)
    if spec is None or spec.loader is None:
        raise ValueError("generic runtime synchronizer cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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
    components: list[dict[str, object]], profile_id: str, raw_values: list[str], canonical: dict[str, str], descriptors
) -> None:
    profile = next((item for item in components if item.get("id") == profile_id), None)
    if profile is None:
        raise ValueError(f"environment profile {profile_id} is not locked")
    descriptor = descriptors.get(profile_id)
    if descriptor is None:
        raise ValueError(f"environment profile {profile_id} is not described by the generic synchronizer")
    supplied = environment_values(raw_values)
    expected_names = {
        str(descriptor[key])
        for key in ("version", "url", "sha", "asset")
        if descriptor.get(key)
    }
    if len(supplied) != 3 or not set(supplied).issubset(expected_names):
        raise ValueError(f"environment profile {profile_id} fields mismatch")
    expected_values = {
        str(descriptor["version"]): str(canonical[str(descriptor["version"])]),
        str(descriptor["url"]): str(profile["download_url"]),
        str(descriptor["sha"]): str(profile["sha256"]).lower(),
    }
    if descriptor.get("asset"):
        expected_values[str(descriptor["asset"])] = str(profile["asset_name"])
    for name, actual in supplied.items():
        expected_value = expected_values[name]
        if name.endswith("SHA256"):
            actual = actual.lower()
            expected_value = expected_value.lower()
        if actual != expected_value:
            raise ValueError(f"environment profile {profile_id} {name} drift")


def expected_tuple(item: dict[str, str], values: dict[str, str], descriptors) -> tuple[str, str]:
    descriptor = descriptors[item["id"]]
    version = values[str(descriptor["version"])].removeprefix(str(descriptor.get("prefix", "")))
    return version, values[str(descriptor["sha"])].lower()


def _require_profile_identity(item: dict[str, object], digest: str, descriptor, values, sync) -> None:
    identifier = str(item.get("id", "unknown"))
    expected_component = str(descriptor["component"])
    if item.get("component") != expected_component:
        raise ValueError(f"{identifier} component does not match its descriptor")
    actual_digest = str(item.get("sha256", "")).lower()
    if re.fullmatch(r"[0-9a-f]{64}", actual_digest) is None:
        raise ValueError(f"{identifier} SHA-256 is missing or invalid")
    if actual_digest != digest:
        raise ValueError(f"{identifier} SHA-256 drift")
    expected_os, expected_arch = sync.runtime_profile_platform(values)
    if item.get("os") != expected_os or item.get("arch") != expected_arch:
        raise ValueError(f"{identifier} has an unsupported platform")


def _require_profile_artifact(item: dict[str, object], descriptor, values, sync) -> None:
    identifier = str(item.get("id", "unknown"))
    expected_asset = sync.normalized_asset(descriptor, values)
    if item.get("asset_name") != expected_asset:
        raise ValueError(f"{identifier} asset does not match locked version and architecture")
    download_url = str(item.get("download_url", ""))
    expected_download_url = str(values[str(descriptor["url"])])
    if download_url != expected_download_url:
        raise ValueError(f"{identifier} download URL drift")
    if not download_url.startswith("https://") or not download_url.endswith(f"/{expected_asset}"):
        raise ValueError(f"{identifier} download URL does not bind the locked asset")


def _require_profile_provenance(item: dict[str, object], descriptor, values, sync) -> None:
    identifier = str(item.get("id", "unknown"))
    expected_source = sync.source_root_url(str(values[str(descriptor["source"])]))
    if item.get("source_url") != expected_source:
        raise ValueError(f"{identifier} source URL does not match its descriptor")
    if not item.get("source_url") or not item.get("source_provenance"):
        raise ValueError(f"{identifier} lacks source provenance")


def require_profile_shape(item: dict[str, object], digest: str, descriptor, values, sync) -> None:
    _require_profile_identity(item, digest, descriptor, values, sync)
    _require_profile_artifact(item, descriptor, values, sync)
    _require_profile_provenance(item, descriptor, values, sync)


def require_manifest_matches_lock(
    manifest: dict[str, object], components: list[dict[str, object]], descriptors
) -> None:
    expected_manifest_components = {
        str(descriptor["component"])
        for descriptor in descriptors.values()
        if descriptor.get("manifest") == "true"
    }
    if not expected_manifest_components:
        raise ValueError("generic synchronizer declares no manifest components")
    entries: dict[str, dict[str, object]] = {}
    for entry in manifest["components"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
            raise ValueError("manifest component must be an object with a name")
        name = str(entry["name"])
        if name in entries:
            raise ValueError(f"manifest contains duplicate component {name}")
        if name not in expected_manifest_components:
            raise ValueError(f"manifest contains unknown component {name}")
        entries[name] = entry
    missing = expected_manifest_components - set(entries)
    if missing:
        raise ValueError("manifest is missing " + ", ".join(sorted(missing)))
    unexpected = set(entries) - expected_manifest_components
    if unexpected:
        raise ValueError("manifest contains unknown component " + ", ".join(sorted(unexpected)))
    for name in expected_manifest_components:
        entry = entries[name]
        profile = next(item for item in components if item["component"] == name)
        if entry.get("version") != profile["version"]:
            raise ValueError(f"manifest {name} version drift")
        if entry.get("sha256", "").lower() != profile["sha256"].lower():
            raise ValueError(f"manifest {name} SHA-256 drift")
        if entry.get("download_url") != profile["download_url"]:
            raise ValueError(f"manifest {name} asset/download drift")


def _validate_lock_header(lock: dict[str, object], values: dict[str, str], sync) -> None:
    if lock.get("schema_version") != 1:
        raise ValueError("lock schema_version must be 1")
    expected_os, expected_arch = sync.runtime_profile_platform(values)
    if lock.get("platform") != f"{expected_os}-{expected_arch}":
        raise ValueError(f"lock platform must be {expected_os}-{expected_arch}")


def _lock_profiles(lock: dict[str, object]) -> list[dict[str, object]]:
    components = lock.get("profiles")
    if not isinstance(components, list):
        raise ValueError("lock profiles must be a list")
    if not all(isinstance(item, dict) for item in components):
        raise ValueError("lock profile must be an object")
    return components


def _validate_profile_inventory(
    components: list[dict[str, object]], descriptors
) -> None:
    expected_ids = set(descriptors)
    ids = [item.get("id") for item in components]
    if set(ids) != expected_ids or len(ids) != len(expected_ids):
        raise ValueError(f"lock profiles mismatch: {sorted(str(item) for item in ids)}")


def _validate_profile(
    item: dict[str, object], values: dict[str, str], descriptors, sync
) -> None:
    identifier = item.get("id")
    if identifier not in descriptors:
        raise ValueError(f"unknown lock profile {identifier}")
    version, digest = expected_tuple(item, values, descriptors)
    if item["version"] != version:
        raise ValueError(f"{item['id']} version drift: lock={item['version']} common={version}")
    if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise ValueError(f"{item['id']} canonical SHA-256 is invalid")
    require_profile_shape(item, digest, descriptors[identifier], values, sync)


def validate_lock(
    lock: dict[str, object], values: dict[str, str], descriptors, sync
) -> list[dict[str, object]]:
    _validate_lock_header(lock, values, sync)
    components = _lock_profiles(lock)
    _validate_profile_inventory(components, descriptors)
    for item in components:
        _validate_profile(item, values, descriptors, sync)
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
        sync = synchronizer(source_root)
        values = sync.common_values(args.common)
        descriptors = sync.DESCRIPTORS
        components = validate_lock(lock, values, descriptors, sync)
        if args.manifest:
            manifest = json.loads(read_framework_text(args.manifest, source_root, "manifest"))
            require_manifest_matches_lock(manifest, components, descriptors)
        if args.environment_profile:
            require_environment_profile(
                components, args.environment_profile, args.environment_value, values, descriptors
            )
        print("runtime-component-lock: PASS")
    except (OSError, KeyError, TypeError, ValueError) as exc:
        print(f"runtime-component-lock: BLOCKED: {exc}", file=sys.stderr)
        return 77
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
