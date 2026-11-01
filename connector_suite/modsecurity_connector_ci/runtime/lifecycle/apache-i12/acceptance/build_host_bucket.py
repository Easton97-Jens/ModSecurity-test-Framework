#!/usr/bin/env python3
"""Compile the isolated test-only APR bucket observer extension object."""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]

def query(*args):
    return subprocess.run(["rtk", "proxy", *args], capture_output=True, text=True,
                          check=True, timeout=10).stdout.strip()

def build(output: Path, include: Path) -> dict:
    if not (include / "modsecurity/transaction.h").is_file():
        raise ValueError("explicit selected SDK headers required")
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    source = HERE / "host_bucket.c"
    target = output / "apache-host-bucket.o"
    command = ["rtk", "proxy", *shlex.split(os.environ.get("CC", "cc")), "-std=c17",
               "-Wall", "-Wextra", "-Werror", "-fPIC", "-fno-lto", "-I", str(include.resolve()),
               "-I", str(source_path('connectors/apache/src', root=ROOT)), "-I", str(source_path('common/include', root=ROOT)),
               "-I", query("apxs", "-q", "INCLUDEDIR"),
               *shlex.split(query("apr-1-config", "--includes", "--cppflags", "--cflags")),
               "-c", str(source), "-o", str(target)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=60)
    receipt = {"command": command, "exit": result.returncode, "stdout": result.stdout,
               "stderr": result.stderr, "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
               "object_sha256": hashlib.sha256(target.read_bytes()).hexdigest() if not result.returncode else None,
               "link_flag": "-Wl,--wrap=apache_lifecycle_observe", "test_only": True,
               "runtime_qualified": False, "shared_observer_edits": False,
               "integration": ["Link this object alongside the unchanged Apache host observer and native lifecycle observer",
                   "Add exactly one GNU wrap symbol apache_lifecycle_observe; keep -Bsymbolic-functions and every existing wrapper",
                   "Set I12_APACHE_BUCKET_ROOT/RUN/CASE before host startup; canonical root0700 and host-bucket.enable0600 containing I12_APACHE_HOST_BUCKET_V1 newline",
                   "Capture stderr schema apache-host-bucket-v1; at most4096 snapshots plus one explicit overflow record, each less than2048 bytes",
                   "Snapshot stage is existing observer entry; verify the actual source hook precedes apr_bucket_read before claiming pre-read FILE provenance",
                   "allocation_scope_call null means actual accessor returned0; never derive association from run/case/URI",
                   "No bucket read, payload capture, productive return substitution, or private native offset access"]}
    (output / "host-bucket-build.json").write_text(json.dumps(receipt, indent=2) + "\n")
    if result.returncode:
        raise RuntimeError(result.stderr)
    return receipt

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sdk-include", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.output, args.sdk_include), sort_keys=True))

if __name__ == "__main__":
    main()
