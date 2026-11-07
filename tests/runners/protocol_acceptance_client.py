"""Build the real libcurl multi acceptance client outside the source checkout."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shlex
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from connector_suite.modsecurity_connector_ci.lib import runtime_path_utils as runtime_paths


def digest_file(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def build_client(prefix: Path, build_root: Path) -> Path:
    """Compile against an explicitly selected, already installed curl prefix."""
    prefix = Path(prefix).resolve(strict=True)
    source = Path(__file__).with_suffix(".c").resolve(strict=True)
    build_root = Path(os.path.abspath(build_root))
    if (source.parents[2] == build_root or source.parents[2] in build_root.parents
            or not runtime_paths.is_safe_runtime_root(build_root)):
        raise ValueError(f"unsafe client build root: {build_root}")
    config = prefix / "bin" / "curl-config"
    if not config.is_file():
        raise ValueError(f"curl-config missing from prefix: {prefix}")
    def flags(option: str) -> list[str]:
        return shlex.split(subprocess.check_output([str(config), option], text=True))
    compiler = shlex.split(os.environ.get("CC", "cc"))
    options = ["-std=c17", "-O2", "-Wall", "-Wextra", "-Werror", "-pedantic"]
    # curl-config's static-libs selects libcurl.a but its QUIC dependencies can
    # remain shared libraries. Pin their actual location for runtime loading.
    command = compiler + options + flags("--cflags") + [str(source)] + flags("--static-libs")
    command += ["-Wl,--disable-new-dtags", f"-Wl,-rpath,{prefix / 'lib'}"]
    inputs = {"command": command, "source_sha256": digest_file(source),
              "curl_version": subprocess.check_output([str(config), "--version"], text=True).strip(),
              "libcurl_sha256": digest_file(prefix / "lib" / "libcurl.a"),
              "shared_libraries": {str(p): digest_file(p) for p in sorted((prefix / "lib").glob("*.so.*"))}}
    identity = hashlib.sha256(json.dumps(inputs, sort_keys=True).encode()).hexdigest()
    destination = build_root / identity
    runtime_paths.ensure_safe_runtime_directory(destination)
    executable = destination / "protocol-acceptance-client"
    manifest = destination / "build-manifest.json"
    if executable.is_symlink() or manifest.is_symlink():
        raise ValueError("client build artifacts must not be symlinks")
    if executable.exists() and manifest.exists():
        cached = json.loads(runtime_paths.read_runtime_artifact_text(
            build_root, manifest, "client build manifest"))
        runtime_paths.runtime_artifact_path(build_root, executable, "client executable", must_exist=True)
        if cached.get("inputs") == inputs and cached.get("executable_sha256") == digest_file(executable):
            return executable
        raise ValueError("client build cache integrity mismatch")
    parent_descriptor = runtime_paths.open_runtime_artifact_parent(executable)
    temporary_name = f"client.{secrets.token_hex(16)}.tmp"
    try:
        descriptor = os.open(temporary_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o700, dir_fd=parent_descriptor)
        os.close(descriptor)
        pinned_temporary = Path(f"/proc/{os.getpid()}/fd/{parent_descriptor}/{temporary_name}")
        environment = os.environ.copy()
        environment["TMPDIR"] = str(pinned_temporary.parent)
        subprocess.run(command + ["-o", str(pinned_temporary)], check=True, env=environment)
        binary_digest = digest_file(pinned_temporary)
        os.replace(temporary_name, executable.name,
                   src_dir_fd=parent_descriptor, dst_dir_fd=parent_descriptor)
        runtime_paths.write_runtime_artifact_text_atomic(
            build_root, manifest,
            json.dumps({"inputs": inputs, "executable_sha256": binary_digest}, indent=2) + "\n",
            "client build manifest")
    finally:
        try:
            os.unlink(temporary_name, dir_fd=parent_descriptor)
        except FileNotFoundError:
            pass
        os.close(parent_descriptor)
    return executable


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--curl-prefix", required=True, type=Path)
    parser.add_argument("--build-root", required=True, type=Path)
    args = parser.parse_args()
    try:
        print(build_client(args.curl_prefix, args.build_root))
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f"client build failed: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
