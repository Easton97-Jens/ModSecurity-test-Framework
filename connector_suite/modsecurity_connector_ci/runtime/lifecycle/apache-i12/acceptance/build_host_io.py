#!/usr/bin/env python3
"""Build the Apache-only opt-in physical I/O observer with explicit SDK headers."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess

HERE = Path(__file__).resolve().parent
TRANSACTION_HEADER = "modsecurity/transaction.h"

def build(output: Path, include: Path, multipart_object: Path | None = None) -> dict:
    output = output.resolve()
    if not (include / TRANSACTION_HEADER).is_file():
        raise ValueError("explicit selected SDK transaction header required")
    output.mkdir(parents=True, exist_ok=True)
    apr = shlex.split(subprocess.run(["rtk", "proxy", "apr-1-config", "--includes", "--cppflags", "--cflags"],
        capture_output=True, text=True, check=True, timeout=10).stdout)
    links = shlex.split(subprocess.run(["rtk", "proxy", "apr-1-config", "--link-ld", "--libs"],
        capture_output=True, text=True, check=True, timeout=10).stdout)
    source = HERE / "host_io.c"
    target = output / "apache-host-io.so"
    extra_objects: list[str] = []
    extra_links: list[str] = []
    multipart_sha256 = None
    if multipart_object is not None:
        multipart_object = multipart_object.resolve()
        if not multipart_object.is_file():
            raise ValueError("explicit multipart observer object required")
        extra_objects.append(str(multipart_object))
        extra_links.append("-lstdc++")
        multipart_sha256 = hashlib.sha256(multipart_object.read_bytes()).hexdigest()
    command = ["rtk", "proxy", *shlex.split(os.environ.get("CC", "cc")), "-std=c17", "-Wall", "-Wextra", "-Werror",
        "-fPIC", "-fno-lto", "-shared", "-I", str(include.resolve()), *apr, str(source), *extra_objects,
        "-o", str(target), *links, "-ldl", "-pthread", *extra_links]
    result = subprocess.run(command, capture_output=True, text=True, timeout=90)
    receipt = {"command": command, "exit": result.returncode, "stdout": result.stdout, "stderr": result.stderr,
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "selected_sdk_header": str((include / TRANSACTION_HEADER).resolve()),
        "selected_sdk_header_sha256": hashlib.sha256((include / TRANSACTION_HEADER).read_bytes()).hexdigest(),
        "multipart_object": str(multipart_object) if multipart_object is not None else None,
        "multipart_object_sha256": multipart_sha256,
        "binary_sha256": hashlib.sha256(target.read_bytes()).hexdigest() if result.returncode == 0 else None,
        "test_only": True, "runtime_qualified": False}
    (output / "host-io-build.json").write_text(json.dumps(receipt, indent=2) + "\n")
    if result.returncode:
        raise RuntimeError(result.stderr)
    return receipt

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sdk-include", type=Path, required=True)
    parser.add_argument("--multipart-object", type=Path)
    args = parser.parse_args()
    print(json.dumps(build(args.output, args.sdk_include, args.multipart_object), sort_keys=True))

if __name__ == "__main__":
    main()
