#!/usr/bin/env python3
"""Fetch one checksum-locked CI security tool into a runner-owned directory."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path, PurePosixPath
import shutil
import tarfile
import tempfile
from typing import Any
from urllib.parse import urlparse
from urllib.request import Request, urlopen

import yaml


class ToolError(RuntimeError):
    """Raised when a tool record or its downloaded archive is unsafe."""


TOOL_FIELDS = {
    "name",
    "version",
    "immutable_commit",
    "upstream_release",
    "asset",
    "asset_url",
    "sha256",
    "archive_type",
    "layout",
    "license",
    "purpose",
    "platform",
    "update_procedure",
}
SUPPORTED_ARCHIVE_TYPES = {"tar.gz", "raw"}


def is_safe_archive_member(name: str) -> bool:
    path = PurePosixPath(name)
    return (
        bool(name)
        and not path.is_absolute()
        and all(part not in {"", ".", ".."} for part in path.parts)
    )


def is_safe_path_component(name: str) -> bool:
    path = PurePosixPath(name)
    return is_safe_archive_member(name) and len(path.parts) == 1


def read_tool_record(lock_path: Path, tool: str) -> dict[str, Any]:
    try:
        loaded = yaml.safe_load(lock_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ToolError(f"cannot read YAML lock {lock_path}: {exc}") from exc
    if not isinstance(loaded, dict) or not isinstance(loaded.get("tools"), dict):
        raise ToolError("security tool lock must contain a tools mapping")
    record = loaded["tools"].get(tool)
    if not isinstance(record, dict):
        raise ToolError(f"tool {tool!r} is not an allow-listed record")
    if not is_safe_path_component(tool):
        raise ToolError(f"tool {tool!r} is not a safe output path component")
    missing = sorted(TOOL_FIELDS.difference(record))
    if missing:
        raise ToolError(
            f"tool {tool!r} lacks required lock fields: {', '.join(missing)}"
        )
    if record.get("name") != tool:
        raise ToolError(f"tool {tool!r} has a mismatched name field")
    if not is_safe_path_component(str(record.get("asset", ""))):
        raise ToolError(f"tool {tool!r} has an unsafe release asset name")
    if not isinstance(record.get("sha256"), str) or len(record["sha256"]) != 64:
        raise ToolError(f"tool {tool!r} has no valid SHA-256 digest")
    if any(character not in "0123456789abcdef" for character in record["sha256"]):
        raise ToolError(f"tool {tool!r} has a non-lowercase SHA-256 digest")
    archive_type = record.get("archive_type")
    layout = record.get("layout")
    if archive_type not in SUPPORTED_ARCHIVE_TYPES:
        raise ToolError(f"tool {tool!r} has unsupported archive type")
    if layout not in {"executable", "tree"}:
        raise ToolError(f"tool {tool!r} has unsupported archive layout")
    if archive_type == "raw" and layout != "executable":
        raise ToolError(f"tool {tool!r} raw assets must use executable layout")
    parsed = urlparse(str(record["asset_url"]))
    if (
        parsed.scheme != "https"
        or parsed.netloc != "github.com"
        or parsed.query
        or parsed.fragment
    ):
        raise ToolError(
            f"tool {tool!r} must use a direct HTTPS GitHub release asset URL"
        )
    if "/releases/download/" not in parsed.path or not parsed.path.endswith(
        f"/{record['asset']}"
    ):
        raise ToolError(
            f"tool {tool!r} asset URL does not match its locked release asset"
        )
    if (
        layout == "executable"
        and archive_type == "tar.gz"
        and not is_safe_archive_member(str(record.get("archive_member", "")))
    ):
        raise ToolError(f"tool {tool!r} has an unsafe executable archive member")
    if layout == "executable" and archive_type == "raw" and "archive_member" in record:
        raise ToolError(f"tool {tool!r} raw assets must not declare an archive member")
    if layout == "executable" and not is_safe_path_component(
        str(record.get("executable", ""))
    ):
        raise ToolError(f"tool {tool!r} has an unsafe executable output name")
    if layout == "tree" and archive_type != "tar.gz":
        raise ToolError(f"tool {tool!r} tree layout requires a tar.gz asset")
    if layout == "tree":
        if not is_safe_path_component(str(record.get("archive_root", ""))):
            raise ToolError(f"tool {tool!r} has an unsafe tree archive root")
        if not is_safe_archive_member(str(record.get("entrypoint", ""))):
            raise ToolError(f"tool {tool!r} has an unsafe tree entrypoint")
    return record


def checked_download(record: dict[str, Any], staging_dir: Path) -> Path:
    archive = staging_dir / str(record["asset"])
    request = Request(
        str(record["asset_url"]), headers={"User-Agent": "framework-ci-security/1"}
    )
    digest = hashlib.sha256()
    try:
        with urlopen(request, timeout=30) as response, archive.open("wb") as output:
            final_url = urlparse(response.geturl())
            if final_url.scheme != "https":
                raise ToolError("release asset redirect did not remain on HTTPS")
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                output.write(chunk)
    except OSError as exc:
        raise ToolError(f"could not download {record['name']}: {exc}") from exc
    actual = digest.hexdigest()
    if actual != record["sha256"]:
        raise ToolError(
            f"SHA-256 mismatch for {record['name']}: expected {record['sha256']}, got {actual}"
        )
    return archive


def checked_members(archive: tarfile.TarFile) -> list[tarfile.TarInfo]:
    members = archive.getmembers()
    for member in members:
        if not is_safe_archive_member(member.name):
            raise ToolError(f"archive contains unsafe path {member.name!r}")
        if member.issym() or member.islnk() or member.isdev():
            raise ToolError(
                f"archive contains unsupported link or device {member.name!r}"
            )
        if not (member.isdir() or member.isfile()):
            raise ToolError(f"archive contains unsupported member {member.name!r}")
    return members


def extract_executable(
    record: dict[str, Any], archive_path: Path, output_dir: Path
) -> Path:
    target = output_dir / str(record["executable"])
    if target.exists() or target.is_symlink():
        raise ToolError(f"refusing to overwrite existing tool target {target}")
    with tarfile.open(archive_path, mode="r:gz") as archive:
        members = checked_members(archive)
        matching = [
            member
            for member in members
            if member.name == record["archive_member"] and member.isfile()
        ]
        if len(matching) != 1:
            raise ToolError(
                f"expected exactly one executable member for {record['name']}"
            )
        source = archive.extractfile(matching[0])
        if source is None:
            raise ToolError(f"could not read executable member for {record['name']}")
        stage = output_dir / f".{record['name']}.tmp"
        try:
            with source, stage.open("xb") as destination:
                shutil.copyfileobj(source, destination)
            stage.chmod(0o755)
            os.replace(stage, target)
        finally:
            stage.unlink(missing_ok=True)
    return target


def install_raw_executable(
    record: dict[str, Any], downloaded_path: Path, output_dir: Path
) -> Path:
    target = output_dir / str(record["executable"])
    if target.exists() or target.is_symlink():
        raise ToolError(f"refusing to overwrite existing tool target {target}")
    stage = output_dir / f".{record['name']}.tmp"
    try:
        with downloaded_path.open("rb") as source, stage.open("xb") as destination:
            shutil.copyfileobj(source, destination)
        stage.chmod(0o755)
        os.replace(stage, target)
    finally:
        stage.unlink(missing_ok=True)
    return target


def extract_tree(record: dict[str, Any], archive_path: Path, output_dir: Path) -> Path:
    root = str(record["archive_root"])
    target = output_dir / str(record["name"])
    if target.exists() or target.is_symlink():
        raise ToolError(f"refusing to overwrite existing tool target {target}")
    staging = Path(tempfile.mkdtemp(prefix=f".{record['name']}-", dir=output_dir))
    try:
        with tarfile.open(archive_path, mode="r:gz") as archive:
            members = checked_members(archive)
            for member in members:
                if member.name != root and not member.name.startswith(f"{root}/"):
                    raise ToolError(
                        f"archive member outside locked root: {member.name!r}"
                    )
                relative = PurePosixPath(member.name).relative_to(root)
                destination = staging.joinpath(*relative.parts)
                if member.isdir():
                    destination.mkdir(parents=True, exist_ok=True)
                    continue
                destination.parent.mkdir(parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    raise ToolError(f"could not read archive member {member.name!r}")
                with source, destination.open("xb") as output:
                    shutil.copyfileobj(source, output)
                destination.chmod(member.mode & 0o777)
        entrypoint = staging.joinpath(*PurePosixPath(str(record["entrypoint"])).parts)
        if not entrypoint.is_file():
            raise ToolError(
                f"locked entrypoint is absent from {record['name']} archive"
            )
        os.replace(staging, target)
        return target / str(record["entrypoint"])
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def runner_owned_output_dir(output_dir: Path) -> Path:
    runner_temp_value = os.environ.get("RUNNER_TEMP")
    if not runner_temp_value:
        raise ToolError("RUNNER_TEMP must name an existing runner-owned directory")
    runner_temp = Path(runner_temp_value)
    if not output_dir.is_absolute() or not runner_temp.is_absolute():
        raise ToolError("output directory and RUNNER_TEMP must be absolute paths")
    if runner_temp.is_symlink() or not runner_temp.is_dir():
        raise ToolError("RUNNER_TEMP must be an existing non-symlink directory")
    try:
        runner_root = runner_temp.resolve(strict=True)
        relative_output = output_dir.relative_to(runner_root)
        resolved_output = output_dir.resolve(strict=False)
    except (OSError, ValueError) as exc:
        raise ToolError(
            "output directory must be a strict child of the runner-owned RUNNER_TEMP"
        ) from exc
    if not relative_output.parts or resolved_output == runner_root:
        raise ToolError(
            "output directory must be a strict child of the runner-owned RUNNER_TEMP"
        )
    current = runner_root
    for component in relative_output.parts:
        current = current / component
        if current.is_symlink():
            raise ToolError("output directory must not traverse a symlink")
    if runner_root not in resolved_output.parents:
        raise ToolError(
            "output directory must be a strict child of the runner-owned RUNNER_TEMP"
        )
    if runner_root.stat().st_uid != os.geteuid():
        raise ToolError("RUNNER_TEMP is not owned by the current runner user")
    return resolved_output


def fetch(record: dict[str, Any], output_dir: Path) -> Path:
    output_dir = runner_owned_output_dir(output_dir)
    output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    output_dir = runner_owned_output_dir(output_dir)
    if output_dir.is_symlink() or not output_dir.is_dir():
        raise ToolError(f"output directory is not a safe directory: {output_dir}")
    staging = Path(
        tempfile.mkdtemp(prefix=f".{record['name']}-download-", dir=output_dir)
    )
    try:
        archive = checked_download(record, staging)
        if record["archive_type"] == "raw":
            return install_raw_executable(record, archive, output_dir)
        if record["layout"] == "executable":
            return extract_executable(record, archive, output_dir)
        return extract_tree(record, archive, output_dir)
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--tool", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.lock.is_file() or args.lock.is_symlink():
        raise ToolError(f"lock must be a regular non-symlink file: {args.lock}")
    record = read_tool_record(args.lock, args.tool)
    path = fetch(record, args.output_dir)
    print(path)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ToolError as exc:
        print(f"security-tool error: {exc}", file=os.sys.stderr)
        raise SystemExit(2) from exc
