#!/usr/bin/env python3
"""Build the Apache-only public SDK multipart observer and retain exact identity."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess

HERE = Path(__file__).resolve().parent


def build(output: Path, include: Path) -> dict:
    """Compile an object and loadable observer using the selected public headers."""
    include = include.resolve()
    header = include / "modsecurity/transaction.h"
    if not header.is_file():
        raise ValueError("explicit selected SDK transaction header required")
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    source = HERE / "multipart_observer.cpp"
    obj = output / "apache-multipart-observer.o"
    library = output / "apache-multipart-observer.so"
    headers = [] if include == Path("/usr/include") else ["-isystem", str(include)]
    command = ["rtk", "proxy", *shlex.split(os.environ.get("CXX", "c++")), "-std=c++17",
               "-Wall", "-Wextra", "-Werror", "-fPIC", "-fno-lto", *headers,
               "-c", str(source), "-o", str(obj)]
    compilation = subprocess.run(command, capture_output=True, text=True, timeout=90)
    link_command = ["rtk", "proxy", *shlex.split(os.environ.get("CXX", "c++")), "-shared",
                    str(obj), "-pthread", "-o", str(library)]
    linked = subprocess.run(link_command, capture_output=True, text=True, timeout=90) if compilation.returncode == 0 else None
    receipt = {"compile_command": command, "compile_exit": compilation.returncode,
               "compile_stderr": compilation.stderr, "link_command": link_command,
               "link_exit": linked.returncode if linked else None,
               "link_stderr": linked.stderr if linked else None,
               "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
               "sdk_header_sha256": hashlib.sha256(header.read_bytes()).hexdigest(),
               "object_sha256": hashlib.sha256(obj.read_bytes()).hexdigest() if compilation.returncode == 0 else None,
               "binary_sha256": hashlib.sha256(library.read_bytes()).hexdigest() if linked and linked.returncode == 0 else None,
               "test_only": True, "host_qualified": False}
    (output / "multipart-observer-build.json").write_text(json.dumps(receipt, indent=2) + "\n")
    if compilation.returncode or not linked or linked.returncode:
        raise RuntimeError(compilation.stderr + (linked.stderr if linked else ""))
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--sdk-include", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(build(args.output, args.sdk_include), sort_keys=True))


if __name__ == "__main__":
    main()
