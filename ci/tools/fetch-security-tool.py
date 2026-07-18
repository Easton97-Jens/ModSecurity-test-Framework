#!/usr/bin/env python3
"""Fetch one checksum-locked CI security tool into a runner-owned directory."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import sys
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
ARCHIVE_TYPE_TAR_GZ = "tar.gz"
ARCHIVE_TYPE_RAW = "raw"
SUPPORTED_ARCHIVE_TYPES = {ARCHIVE_TYPE_TAR_GZ, ARCHIVE_TYPE_RAW}
ABSOLUTE_PATHS_ERROR = "output directory and RUNNER_TEMP must be absolute paths"
RUNNER_TEMP_DIRECTORY_ERROR = "RUNNER_TEMP must be an existing non-symlink directory"
STRICT_CHILD_ERROR = (
    "output directory must be a strict child of the runner-owned RUNNER_TEMP"
)
SYMLINK_OUTPUT_ERROR = "output directory must not traverse a symlink"
LOCK_ROOT_ERROR = "lock must be contained within the Framework root"
LOCK_TRAVERSAL_ERROR = "lock path must not contain traversal components"
LOCK_SYMLINK_ERROR = "lock path must not traverse a symlink"
LOCK_FILE_ERROR = "lock must be a regular non-symlink file"


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


def framework_root() -> Path:
    return Path(__file__).resolve().parents[2]


def confined_lock_path(lock_path: Path) -> Path:
    """Return a regular lock file beneath the Framework root without symlinks."""
    root = framework_root()
    candidate = lock_path if lock_path.is_absolute() else root / lock_path
    try:
        relative_lock = candidate.relative_to(root)
    except ValueError as exc:
        raise ToolError(LOCK_ROOT_ERROR) from exc
    if not relative_lock.parts:
        raise ToolError(LOCK_FILE_ERROR)
    if any(component == ".." for component in relative_lock.parts):
        raise ToolError(LOCK_TRAVERSAL_ERROR)

    current = root
    for component in relative_lock.parts:
        current = current / component
        try:
            mode = current.lstat().st_mode
        except OSError as exc:
            raise ToolError(f"{LOCK_FILE_ERROR}: {lock_path}") from exc
        if stat.S_ISLNK(mode):
            raise ToolError(LOCK_SYMLINK_ERROR)
    if not stat.S_ISREG(mode):
        raise ToolError(f"{LOCK_FILE_ERROR}: {lock_path}")
    return current


def _lock_tools(lock_path: Path) -> dict[str, Any]:
    try:
        loaded = yaml.safe_load(lock_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ToolError(f"cannot read YAML lock {lock_path}: {exc}") from exc
    if not isinstance(loaded, dict) or not isinstance(loaded.get("tools"), dict):
        raise ToolError("security tool lock must contain a tools mapping")
    return loaded["tools"]


def _tool_record(tools: dict[str, Any], tool: str) -> dict[str, Any]:
    record = tools.get(tool)
    if not isinstance(record, dict):
        raise ToolError(f"tool {tool!r} is not an allow-listed record")
    if not is_safe_path_component(tool):
        raise ToolError(f"tool {tool!r} is not a safe output path component")
    return record


def _validate_tool_identity(record: dict[str, Any], tool: str) -> None:
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


def _validate_release_asset_url(record: dict[str, Any], tool: str) -> None:
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


def _validate_executable_layout(
    record: dict[str, Any], tool: str, archive_type: str
) -> None:
    if archive_type == ARCHIVE_TYPE_TAR_GZ and not is_safe_archive_member(
        str(record.get("archive_member", ""))
    ):
        raise ToolError(f"tool {tool!r} has an unsafe executable archive member")
    if archive_type == ARCHIVE_TYPE_RAW and "archive_member" in record:
        raise ToolError(f"tool {tool!r} raw assets must not declare an archive member")
    if not is_safe_path_component(str(record.get("executable", ""))):
        raise ToolError(f"tool {tool!r} has an unsafe executable output name")


def _validate_tree_layout(record: dict[str, Any], tool: str, archive_type: str) -> None:
    if archive_type != ARCHIVE_TYPE_TAR_GZ:
        raise ToolError(f"tool {tool!r} tree layout requires a tar.gz asset")
    if not is_safe_path_component(str(record.get("archive_root", ""))):
        raise ToolError(f"tool {tool!r} has an unsafe tree archive root")
    if not is_safe_archive_member(str(record.get("entrypoint", ""))):
        raise ToolError(f"tool {tool!r} has an unsafe tree entrypoint")


def _validate_archive_layout(record: dict[str, Any], tool: str) -> None:
    archive_type = record.get("archive_type")
    layout = record.get("layout")
    if archive_type not in SUPPORTED_ARCHIVE_TYPES:
        raise ToolError(f"tool {tool!r} has unsupported archive type")
    if layout not in {"executable", "tree"}:
        raise ToolError(f"tool {tool!r} has unsupported archive layout")
    if archive_type == ARCHIVE_TYPE_RAW and layout != "executable":
        raise ToolError(f"tool {tool!r} raw assets must use executable layout")

    if layout == "executable":
        _validate_executable_layout(record, tool, archive_type)
    else:
        _validate_tree_layout(record, tool, archive_type)


def read_tool_record(lock_path: Path, tool: str) -> dict[str, Any]:
    """Read and validate an allow-listed tool record from a trusted lock file."""
    trusted_lock_path = confined_lock_path(lock_path)
    record = _tool_record(_lock_tools(trusted_lock_path), tool)
    _validate_tool_identity(record, tool)
    _validate_release_asset_url(record, tool)
    _validate_archive_layout(record, tool)
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


def require_absolute_output_paths(output_dir: Path, runner_temp: Path) -> None:
    if output_dir.is_absolute() and runner_temp.is_absolute():
        return
    raise ToolError(ABSOLUTE_PATHS_ERROR)


def resolve_runner_temp_root(runner_temp: Path) -> Path:
    if runner_temp.is_symlink() or not runner_temp.is_dir():
        raise ToolError(RUNNER_TEMP_DIRECTORY_ERROR)
    try:
        runner_root = runner_temp.resolve(strict=True)
    except OSError as exc:
        raise ToolError(STRICT_CHILD_ERROR) from exc
    return runner_root


def require_current_runner_owner(runner_root: Path) -> None:
    if runner_root.stat().st_uid != os.geteuid():
        raise ToolError("RUNNER_TEMP is not owned by the current runner user")


def resolve_strict_child(output_dir: Path, runner_root: Path) -> tuple[Path, Path]:
    try:
        relative_output = output_dir.relative_to(runner_root)
        resolved_output = output_dir.resolve(strict=False)
    except (OSError, ValueError) as exc:
        raise ToolError(STRICT_CHILD_ERROR) from exc
    if not relative_output.parts or resolved_output == runner_root:
        raise ToolError(STRICT_CHILD_ERROR)
    return relative_output, resolved_output


def reject_symlink_path_components(runner_root: Path, relative_output: Path) -> None:
    current = runner_root
    for component in relative_output.parts:
        current = current / component
        if current.is_symlink():
            raise ToolError(SYMLINK_OUTPUT_ERROR)


def require_resolved_strict_child(runner_root: Path, resolved_output: Path) -> None:
    if runner_root not in resolved_output.parents:
        raise ToolError(STRICT_CHILD_ERROR)


def runner_owned_output_dir(output_dir: Path) -> Path:
    runner_temp_value = os.environ.get("RUNNER_TEMP")
    if not runner_temp_value:
        raise ToolError("RUNNER_TEMP must name an existing runner-owned directory")
    runner_temp = Path(runner_temp_value)
    require_absolute_output_paths(output_dir, runner_temp)
    runner_root = resolve_runner_temp_root(runner_temp)
    relative_output, resolved_output = resolve_strict_child(output_dir, runner_root)
    reject_symlink_path_components(runner_root, relative_output)
    require_resolved_strict_child(runner_root, resolved_output)
    require_current_runner_owner(runner_root)
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
    lock_path = confined_lock_path(args.lock)
    record = read_tool_record(lock_path, args.tool)
    path = fetch(record, args.output_dir)
    print(path)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ToolError as exc:
        print(f"security-tool error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
