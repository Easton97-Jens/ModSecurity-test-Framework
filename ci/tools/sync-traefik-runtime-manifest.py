#!/usr/bin/env python3
"""Synchronize the checked-in Traefik manifest slice from common.sh.

``ci/lib/common.sh`` owns the reviewed Traefik release-archive tuple.  This
tool deliberately updates only the Traefik object in the broader runtime
inventory so unrelated component metadata stays outside this remediation.
``--check`` is suitable for CI and reports every expected/found divergence;
``--write`` is deterministic and is the only supported way to refresh this
generated slice after an approved tuple update.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_COMMON_SH = ROOT / "ci" / "lib" / "common.sh"
DEFAULT_MANIFEST = ROOT / "ci" / "provisioning" / "runtime-components.manifest.json"
CANONICAL_FIELDS = (
    "TRAEFIK_VERSION",
    "TRAEFIK_SOURCE_URL",
    "TRAEFIK_INSTALL_DOCS_URL",
    "TRAEFIK_ARTIFACT_PLATFORM",
    "TRAEFIK_ARCHIVE_NAME",
    "TRAEFIK_DOWNLOAD_URL",
    "TRAEFIK_SHA256",
    "TRAEFIK_SHA256_URL",
)
LITERAL_CANONICAL_FIELDS = (
    "TRAEFIK_VERSION",
    "TRAEFIK_SOURCE_URL",
    "TRAEFIK_INSTALL_DOCS_URL",
    "TRAEFIK_ARTIFACT_PLATFORM",
    "TRAEFIK_SHA256",
)
VERSION_RE = re.compile(r"^\d+(?:\.\d+){2}$", re.ASCII)
SHA256_RE = re.compile(r"^[0-9A-Fa-f]{64}$")
LITERAL_ASSIGNMENT_RE = {
    name: re.compile(rf"^{re.escape(name)}=\"([^\"$`]*)\"\s*$", re.MULTILINE)
    for name in LITERAL_CANONICAL_FIELDS
}
PLATFORM_LABELS = {"linux_amd64": "linux/amd64"}
PIN_SOURCE = "ci/lib/common.sh:ci_traefik_set_canonical_tuple"


class ManifestSyncError(RuntimeError):
    """A source, tuple, or manifest contract is invalid."""


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="fail when the generated slice drifts")
    mode.add_argument("--write", action="store_true", help="write the generated Traefik slice")
    parser.add_argument("--common-sh", type=Path, default=DEFAULT_COMMON_SH)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    return parser.parse_args(argv)


def require_file(path: Path, label: str) -> Path:
    resolved = path.resolve()
    if not resolved.is_file():
        raise ManifestSyncError(f"missing {label}: {resolved}")
    return resolved


def controlled_common_environment(common_sh: Path) -> dict[str, str]:
    """Return a small environment that cannot supply an alternate tuple."""

    framework_root = common_sh.parents[2]
    verified_root = framework_root / ".traefik-manifest-read-only"
    return {
        "PATH": os.environ.get("PATH", os.defpath),
        "LC_ALL": "C",
        "FRAMEWORK_ROOT": str(framework_root),
        "CONNECTOR_ROOT": str(framework_root),
        "VERIFIED_RUN_ROOT": str(verified_root),
        "BUILD_ROOT": str(verified_root / "build"),
    }


def load_canonical_tuple(common_sh: Path) -> dict[str, str]:
    """Load the trusted passive common.sh tuple through its own fail-closed guard."""

    source = require_file(common_sh, "common.sh")
    source_text = source.read_text(encoding="utf-8")
    literals: dict[str, str] = {}
    for name, pattern in LITERAL_ASSIGNMENT_RE.items():
        matches = pattern.findall(source_text)
        if len(matches) != 1:
            raise ManifestSyncError(
                f"{source}: expected exactly one manually maintained {name} literal, found {len(matches)}"
            )
        literals[name] = matches[0]

    shell_script = """set -a
. \"$1\"
ci_require_traefik_pinned_provenance
printf '%s\\0' \\
  \"$TRAEFIK_VERSION\" \\
  \"$TRAEFIK_SOURCE_URL\" \\
  \"$TRAEFIK_INSTALL_DOCS_URL\" \\
  \"$TRAEFIK_ARTIFACT_PLATFORM\" \\
  \"$TRAEFIK_ARCHIVE_NAME\" \\
  \"$TRAEFIK_DOWNLOAD_URL\" \\
  \"$TRAEFIK_SHA256\" \\
  \"$TRAEFIK_SHA256_URL\"
"""
    completed = subprocess.run(
        ["sh", "-eu", "-c", shell_script, "sync-traefik-runtime-manifest", str(source)],
        cwd=source.parents[2],
        env=controlled_common_environment(source),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        detail = (completed.stdout + completed.stderr).decode("utf-8", errors="replace").strip()
        raise ManifestSyncError(
            f"cannot load canonical Traefik tuple from {source} (exit {completed.returncode}): {detail}"
        )

    parts = completed.stdout.split(b"\0")
    if parts and parts[-1] == b"":
        parts.pop()
    if len(parts) != len(CANONICAL_FIELDS):
        raise ManifestSyncError(
            f"canonical Traefik tuple from {source} returned {len(parts)} fields; expected {len(CANONICAL_FIELDS)}"
        )
    try:
        values = [part.decode("utf-8") for part in parts]
    except UnicodeDecodeError as exc:
        raise ManifestSyncError(f"canonical Traefik tuple from {source} is not UTF-8") from exc
    tuple_values = dict(zip(CANONICAL_FIELDS, values, strict=True))

    for name, literal in literals.items():
        if tuple_values[name] != literal:
            raise ManifestSyncError(
                f"canonical Traefik {name} expected {literal!r} from its literal, found {tuple_values[name]!r}"
            )
    validate_canonical_tuple(tuple_values)
    return tuple_values


def validate_canonical_tuple(values: dict[str, str]) -> None:
    version = values["TRAEFIK_VERSION"]
    source_url = values["TRAEFIK_SOURCE_URL"]
    platform = values["TRAEFIK_ARTIFACT_PLATFORM"]
    archive_name = values["TRAEFIK_ARCHIVE_NAME"]
    download_url = values["TRAEFIK_DOWNLOAD_URL"]
    checksum_url = values["TRAEFIK_SHA256_URL"]
    sha256 = values["TRAEFIK_SHA256"]
    if not VERSION_RE.fullmatch(version):
        raise ManifestSyncError(
            f"canonical Traefik version must be an exact dotted release, found {version!r}"
        )
    if not SHA256_RE.fullmatch(sha256):
        raise ManifestSyncError(
            f"canonical Traefik SHA256 must be exactly 64 hexadecimal characters, found {sha256!r}"
        )
    if platform not in PLATFORM_LABELS:
        raise ManifestSyncError(
            f"canonical Traefik artifact platform must be one of {sorted(PLATFORM_LABELS)}, found {platform!r}"
        )
    expected_archive = f"traefik_v{version}_{platform}.tar.gz"
    expected_download = f"{source_url}/download/v{version}/{expected_archive}"
    expected_checksum = f"{source_url}/download/v{version}/traefik_v{version}_checksums.txt"
    if archive_name != expected_archive:
        raise ManifestSyncError(
            f"canonical Traefik archive name expected {expected_archive!r}, found {archive_name!r}"
        )
    if download_url != expected_download:
        raise ManifestSyncError(
            f"canonical Traefik download URL expected {expected_download!r}, found {download_url!r}"
        )
    if checksum_url != expected_checksum:
        raise ManifestSyncError(
            f"canonical Traefik checksum URL expected {expected_checksum!r}, found {checksum_url!r}"
        )


def expected_manifest_fields(values: dict[str, str]) -> dict[str, str]:
    return {
        "artifact_type": "tarball_with_binary",
        "artifact_digest_type": "sha256_release_archive",
        "artifact_platform": PLATFORM_LABELS[values["TRAEFIK_ARTIFACT_PLATFORM"]],
        "archive_name": values["TRAEFIK_ARCHIVE_NAME"],
        "pin_source": PIN_SOURCE,
        "version_env": "TRAEFIK_VERSION",
        "version": values["TRAEFIK_VERSION"],
        "source_url_env": "TRAEFIK_SOURCE_URL",
        "source_url": values["TRAEFIK_SOURCE_URL"],
        "install_docs_env": "TRAEFIK_INSTALL_DOCS_URL",
        "install_docs": values["TRAEFIK_INSTALL_DOCS_URL"],
        "download_url_env": "TRAEFIK_DOWNLOAD_URL",
        "download_url": values["TRAEFIK_DOWNLOAD_URL"],
        "sha256_env": "TRAEFIK_SHA256",
        "sha256": values["TRAEFIK_SHA256"],
        "sha256_url_env": "TRAEFIK_SHA256_URL",
        "sha256_url": values["TRAEFIK_SHA256_URL"],
    }


def load_manifest(path: Path) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    manifest_path = require_file(path, "runtime components manifest")
    try:
        document = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ManifestSyncError(f"invalid JSON in {manifest_path}: {exc}") from exc
    components = document.get("components") if isinstance(document, dict) else None
    if not isinstance(components, list):
        raise ManifestSyncError(f"{manifest_path}: components must be a JSON array")
    matches = [component for component in components if isinstance(component, dict) and component.get("name") == "traefik"]
    if len(matches) != 1:
        raise ManifestSyncError(
            f"{manifest_path}: expected exactly one Traefik component, found {len(matches)}"
        )
    return manifest_path, document, matches[0]


def manifest_divergences(component: dict[str, Any], expected: dict[str, str]) -> list[str]:
    divergences: list[str] = []
    for field, expected_value in expected.items():
        found = component.get(field, "<missing>")
        if found != expected_value:
            divergences.append(
                f"{field}: expected {expected_value!r}, found {found!r}"
            )
    return divergences


def render_manifest(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def atomic_write(path: Path, content: str) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent, text=True
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def run(argv: list[str]) -> int:
    args = parse_args(argv)
    values = load_canonical_tuple(args.common_sh)
    expected = expected_manifest_fields(values)
    manifest_path, document, component = load_manifest(args.manifest)
    divergences = manifest_divergences(component, expected)
    if args.check:
        if divergences:
            print(
                "runtime-components manifest divergence for Traefik:\n  - "
                + "\n  - ".join(divergences),
                file=sys.stderr,
            )
            return 1
        print("traefik runtime manifest: PASS")
        return 0

    component.update(expected)
    rendered = render_manifest(document)
    current = manifest_path.read_text(encoding="utf-8")
    if current != rendered:
        atomic_write(manifest_path, rendered)
    print(f"traefik runtime manifest: wrote {manifest_path}")
    return 0


def main() -> int:
    try:
        return run(sys.argv[1:])
    except ManifestSyncError as exc:
        print(f"sync-traefik-runtime-manifest: ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
