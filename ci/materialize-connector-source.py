#!/usr/bin/env python3
"""Materialize connector build sources under BUILD_ROOT.

The materialized source tree is generated from repo-owned adapter files plus,
for connectors that still need it, a controlled upstream import. It is a build
artifact and must never be written inside the repository checkout or the
read-only reference repositories.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import shutil
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from adapter_metadata import load_metadata


REPO_ROOT = Path(os.environ.get("CONNECTOR_ROOT", Path(__file__).resolve().parents[1])).resolve()
SCRIPT_RELATIVE = "ci/materialize-connector-source.py"
EXCLUDED_DIRS = {
    ".deps",
    ".git",
    ".github",
    ".libs",
    "__pycache__",
    "autom4te.cache",
    "objs",
}
EXCLUDED_NAMES = {
    ".travis.yml",
}
EXCLUDED_PATTERNS = (
    "*.la",
    "*.lo",
    "*.log",
    "*.o",
    "*.so",
)
GENERATED_MANIFESTS = ("MATERIALIZED_SOURCE.md", "materialized-source.json")


@dataclass(frozen=True)
class ManifestEntry:
    path: str
    source: str
    origin_path: str
    license: str
    commit: str
    version: str
    reason: str
    source_url: str = ""
    base_path: str = ""
    patches: list[dict[str, str]] = field(default_factory=list)


def relative_or_absolute(path: Path) -> str:
    resolved = path.resolve(strict=False)
    try:
        return resolved.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return str(resolved)


def validate_source_dir(path: Path, label: str) -> Path:
    resolved = path.resolve(strict=True)
    if not resolved.is_dir():
        raise SystemExit(f"{label} is not a directory: {resolved}")
    return resolved


def validate_destination(path: Path) -> Path:
    if not path.is_absolute():
        raise SystemExit(f"dest-dir must be absolute: {path}")
    resolved = path.resolve(strict=False)
    try:
        resolved.relative_to(REPO_ROOT)
    except ValueError:
        pass
    else:
        raise SystemExit(f"dest-dir must not be inside the checkout: {resolved}")
    if resolved.exists() and any(resolved.iterdir()):
        raise SystemExit(f"dest-dir must be empty or absent: {resolved}")
    return resolved


def should_skip(relative_path: Path) -> bool:
    if any(part in EXCLUDED_DIRS for part in relative_path.parts):
        return True
    name = relative_path.name
    if name in EXCLUDED_NAMES:
        return True
    return any(fnmatch.fnmatch(name, pattern) for pattern in EXCLUDED_PATTERNS)


def iter_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative_path = path.relative_to(root)
        if should_skip(relative_path):
            continue
        files.append(relative_path)
    return sorted(files, key=lambda item: item.as_posix())


def copy_tree_files(
    source_root: Path,
    destination_root: Path,
    destination_prefix: Path,
    source_kind: str,
    metadata_license: str,
    metadata_commit: str,
    metadata_version: str,
    reason: str,
) -> dict[str, ManifestEntry]:
    entries: dict[str, ManifestEntry] = {}
    for relative_path in iter_files(source_root):
        destination_relative = destination_prefix / relative_path
        destination = destination_root / destination_relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_root / relative_path, destination)
        key = destination_relative.as_posix()
        entries[key] = ManifestEntry(
            path=key,
            source=source_kind,
            origin_path=relative_or_absolute(source_root / relative_path),
            license=metadata_license,
            commit=metadata_commit,
            version=metadata_version,
            reason=reason,
        )
    return entries


def load_source_map(adapter_root: Path) -> dict[str, Any]:
    source_map_path = adapter_root / "SOURCE_MAP.json"
    if not source_map_path.exists():
        return {}
    with source_map_path.open(encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise SystemExit(f"invalid SOURCE_MAP.json: {source_map_path}")
    files = payload.get("files", {})
    patches = payload.get("patches", {})
    if not isinstance(files, dict) or not isinstance(patches, dict):
        raise SystemExit(f"invalid SOURCE_MAP.json file/patch maps: {source_map_path}")
    return payload


def adapter_destination_relative(connector: str, relative_path: Path) -> Path:
    if connector == "apache":
        if relative_path.parts[:2] == ("tests", "t"):
            return Path(*relative_path.parts[1:])
        return relative_path
    if connector == "nginx":
        return relative_path
    raise ValueError(f"unsupported connector: {connector}")


def source_map_entry(
    source_map: dict[str, Any],
    destination_relative: Path,
) -> dict[str, Any]:
    files = source_map.get("files", {})
    if not isinstance(files, dict):
        return {}
    value = files.get(destination_relative.as_posix(), {})
    return value if isinstance(value, dict) else {}


def source_map_patches(
    source_map: dict[str, Any],
    file_entry: dict[str, Any],
) -> list[dict[str, str]]:
    patch_names = file_entry.get("patches", [])
    patch_map = source_map.get("patches", {})
    if not isinstance(patch_names, list) or not isinstance(patch_map, dict):
        return []
    patches: list[dict[str, str]] = []
    for name in patch_names:
        if not isinstance(name, str):
            continue
        patch = patch_map.get(name, {})
        if not isinstance(patch, dict):
            continue
        patches.append(
            {
                "name": name,
                "url": str(patch.get("url", "")),
                "commit": str(patch.get("commit", "")),
                "reason": str(patch.get("reason", "")),
            }
        )
    return patches


def copy_adapter_files(
    connector: str,
    adapter_root: Path,
    destination_root: Path,
    metadata_license: str,
    metadata_commit: str,
    metadata_version: str,
) -> dict[str, ManifestEntry]:
    entries: dict[str, ManifestEntry] = {}
    source_map = load_source_map(adapter_root)
    source_map_files = source_map.get("files", {})
    if source_map and not isinstance(source_map_files, dict):
        raise SystemExit(f"invalid SOURCE_MAP.json files map under {adapter_root}")
    base = source_map.get("base", {})
    source_url = str(base.get("url", "")) if isinstance(base, dict) else ""
    for relative_path in iter_files(adapter_root):
        destination_relative = adapter_destination_relative(connector, relative_path)
        if source_map and destination_relative.as_posix() not in source_map_files:
            continue
        destination = destination_root / destination_relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(adapter_root / relative_path, destination)
        file_entry = source_map_entry(source_map, destination_relative)
        key = destination_relative.as_posix()
        entries[key] = ManifestEntry(
            path=key,
            source="adapter-owned",
            origin_path=relative_or_absolute(adapter_root / relative_path),
            license=str(file_entry.get("license", metadata_license)),
            commit=str(file_entry.get("commit", metadata_commit)),
            version=str(file_entry.get("version", metadata_version)),
            reason=str(
                file_entry.get(
                    "reason",
                    "Repo-owned adapter source overlaid into the generated build tree.",
                )
            ),
            source_url=source_url,
            base_path=str(file_entry.get("base_path", "")),
            patches=source_map_patches(source_map, file_entry),
        )
    return entries


def manifest_payload(
    connector: str,
    destination: Path,
    entries: dict[str, ManifestEntry],
) -> dict[str, object]:
    metadata = load_metadata(connector)
    return {
        "connector": connector,
        "source_url": metadata.source_url,
        "source_commit": metadata.source_commit,
        "source_version": metadata.source_version,
        "license": metadata.license,
        "destination": str(destination),
        "entries": [asdict(entries[name]) for name in sorted(entries)],
    }


def write_markdown_manifest(destination: Path, payload: dict[str, object]) -> None:
    rows = [
        "# Materialized Connector Source",
        "",
        f"Connector: `{payload['connector']}`",
        f"Destination: `{payload['destination']}`",
        f"Upstream: {payload['source_url']}",
        f"Commit: `{payload['source_commit']}`",
        f"Version: `{payload['source_version']}`",
        f"License: {payload['license']}",
        "",
        "| File | Source | Origin | Patch provenance | Reason |",
        "| --- | --- | --- | --- | --- |",
    ]
    for entry in payload["entries"]:
        assert isinstance(entry, dict)
        patches = entry.get("patches") or []
        if isinstance(patches, list) and patches:
            patch_text = ", ".join(
                f"{patch.get('name', 'patch')}@{patch.get('commit', '')[:12]}"
                for patch in patches
                if isinstance(patch, dict)
            )
        else:
            patch_text = "-"
        rows.append(
            "| `{path}` | {source} | `{origin_path}` | {patch_provenance} | {reason} |".format(
                patch_provenance=patch_text,
                **entry,
            )
        )
    rows.append("")
    (destination / "MATERIALIZED_SOURCE.md").write_text("\n".join(rows), encoding="utf-8")


def materialize(connector: str, upstream_dir: Path | None, adapter_dir: Path, dest_dir: Path) -> None:
    upstream = validate_source_dir(upstream_dir, "upstream-dir") if upstream_dir is not None else None
    adapter = validate_source_dir(adapter_dir, "adapter-dir")
    destination = validate_destination(dest_dir)
    metadata = load_metadata(connector)

    destination.mkdir(parents=True, exist_ok=True)
    entries: dict[str, ManifestEntry] = {}
    if upstream is not None:
        entries = copy_tree_files(
            upstream,
            destination,
            Path("."),
            "upstream-derived",
            metadata.license,
            metadata.source_commit,
            metadata.source_version,
            "Remaining imported connector source required by the current build.",
        )
    entries.update(
        copy_adapter_files(
            connector,
            adapter,
            destination,
            metadata.license,
            metadata.source_commit,
            metadata.source_version,
        )
    )

    for manifest_name in GENERATED_MANIFESTS:
        entries[manifest_name] = ManifestEntry(
            path=manifest_name,
            source="generated-overlay",
            origin_path=SCRIPT_RELATIVE,
            license=metadata.license,
            commit=metadata.source_commit,
            version=metadata.source_version,
            reason="Generated materialized-source manifest.",
        )

    payload = manifest_payload(connector, destination, entries)
    write_markdown_manifest(destination, payload)
    (destination / "materialized-source.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"materialized {connector} connector source at {destination}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--connector", required=True, choices=("apache", "nginx"))
    parser.add_argument("--upstream-dir", type=Path)
    parser.add_argument("--adapter-dir", required=True, type=Path)
    parser.add_argument("--dest-dir", required=True, type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    materialize(args.connector, args.upstream_dir, args.adapter_dir, args.dest_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
