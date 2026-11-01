"""Validate an explicit prepared pair without changing its producer identity."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


SOURCE_ROOT = connector_root()
PROBE_TIMEOUT_SECONDS = 10


def canonical_source_root(value: Path | str) -> Path:
    raw = os.fspath(value)
    path = Path(raw)
    if not path.is_absolute() or str(path) != raw or path.resolve(strict=True) != path:
        raise ValueError("source root must be canonical, absolute, and not a symlink")
    if not path.is_dir() or path != SOURCE_ROOT:
        raise ValueError("source root must be the validator's own checkout")
    return SOURCE_ROOT


def canonical_file(value: str, *, executable: bool = False) -> Path:
    path = Path(value)
    if not path.is_absolute() or str(path) != value or path.resolve(strict=True) != path:
        raise ValueError("prepared input must be canonical, absolute, and not a symlink")
    if not path.is_file() or (executable and not os.access(path, os.X_OK)):
        raise ValueError("prepared input must be a regular executable" if executable else "prepared input must be regular")
    return path


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def production_paths(root: Path) -> set[str]:
    paths = {str(p.relative_to(root)) for directory in ("common/src", "common/include", "common/runtime", "connectors/haproxy/src")
             for p in (root / directory).rglob("*") if p.is_file() and p.suffix in (".c", ".h")}
    paths.update({"connectors/profile_registry.c", "connectors/profile_registry.h",
                  "connectors/haproxy/htx-overlay/haproxy_modsecurity_htx_filter.c"})
    return paths


def validate(root: Path | str, haproxy: str, spoa: str, provenance: str,
             equivalence: str, library: str, version: str) -> dict:
    root = canonical_source_root(root)
    binaries = {"haproxy_htx": canonical_file(haproxy, executable=True),
                "haproxy_spop": canonical_file(spoa, executable=True)}
    manifest = json.loads(canonical_file(provenance).read_text())
    for name, path in binaries.items():
        if digest(path) != manifest["artifacts"][name]["sha256"]:
            raise ValueError("prepared artifact hash differs from build provenance: " + name)
    if digest(canonical_file(library)) != manifest["library"]["sha256"]:
        raise ValueError("prepared library differs from build provenance")
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=SOURCE_ROOT,
                              check=True, capture_output=True, text=True,
                              timeout=PROBE_TIMEOUT_SECONDS).stdout.strip()
    build_revision = manifest["source_sha"]
    if not equivalence:
        raise ValueError("prepared artifacts require a production-source equivalence receipt")
    proof = json.loads(canonical_file(equivalence).read_text())
    if proof["artifact_build_sha"] != build_revision or proof["runtime_parent_sha"] != revision or proof["production_runtime_inputs_equal"] is not True:
        raise ValueError("prepared producer/runtime revision binding differs")
    required = production_paths(root)
    if not required <= proof["file_objects"].keys():
        raise ValueError("prepared source proof omits production inputs")
    for relative in sorted(required):
        data = canonical_file(str(root / relative)).read_bytes()
        # Git's object identity, not a cryptographic authentication mechanism.
        blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data, usedforsecurity=False).hexdigest()
        record = proof["file_objects"][relative]
        if record["type"] != "blob" or blob != record["git_object"]:
            raise ValueError("prepared artifact production input differs: " + relative)
    result = subprocess.run([str(binaries["haproxy_htx"]), "-v"], check=True,
                            capture_output=True, text=True, timeout=PROBE_TIMEOUT_SECONDS)
    if "HAProxy version " + version not in result.stdout + result.stderr:
        raise ValueError("prepared HAProxy version differs from contract")
    return {"artifact_build_sha": build_revision, "runtime_parent_sha": revision,
            "artifact_sha256": {name: digest(path) for name, path in binaries.items()},
            "source_proof_sha256": digest(Path(equivalence)),
            "build_provenance_sha256": digest(Path(provenance)),
            "verified_production_inputs": len(required)}


if __name__ == "__main__":
    try:
        print(json.dumps(validate(sys.argv[1], *sys.argv[2:]), sort_keys=True))
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print("prepared-artifact validation failed: " + str(error), file=sys.stderr)
        raise SystemExit(1)
