#!/usr/bin/env python3
"""Export explicit component inputs as an incomplete CycloneDX 1.6 SBOM.

Offline, stdlib-only exporter. It does not resolve packages, infer linkage,
scan containers, fetch dependencies or execute supplied build descriptions.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

MAX_JSON = 16 * 1024 * 1024
LIMITS = ("Explicit inputs only; native transitive linkage, OS/container packages, "
          "runtime qualification and vulnerability assessment are not established. "
          "Go modules are a selected module list, not an observed binary dependency graph. "
          "Python distributions describe the selected environment, not product linkage. "
          "Build descriptions are supplied assertions, not verified build observations.")


def encoded(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def regular_bytes(path: Path, *, limit: int | None = MAX_JSON) -> bytes:
    """Read explicit local regular files without following symlink components."""
    path = path.absolute()
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("input contains a symlink")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("input must be a single-link regular file")
        if limit is not None and info.st_size > limit:
            raise ValueError("JSON input exceeds 16 MiB")
        data = handle.read() if limit is None else handle.read(limit + 1)
        if limit is not None and len(data) > limit:
            raise ValueError("JSON input exceeds 16 MiB")
    return data


def artifact_digest(path: Path) -> tuple[str, int]:
    path = path.absolute()
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("artifact contains a symlink")
    value = hashlib.sha256()
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as handle:
        before = os.fstat(handle.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError("artifact must be a single-link regular file")
        while block := handle.read(1024 * 1024):
            value.update(block)
        after = os.fstat(handle.fileno())
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError("artifact changed during export")
    return value.hexdigest(), before.st_size


def text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 4096:
        raise ValueError(f"{label} must be a nonempty string of at most 4096 characters")
    if any(ord(char) < 32 for char in value):
        raise ValueError(f"{label} contains a control character")
    return value


def properties(values: dict[str, str]) -> list[dict[str, str]]:
    return [{"name": f"modsecurity:{key}", "value": value}
            for key, value in sorted(values.items())]


def repository(root: Path, expected: str, allow_dirty: bool) -> dict[str, str]:
    if re.fullmatch(r"[0-9a-f]{40}", expected) is None:
        raise ValueError("repository revision must be an exact lowercase SHA-1")
    root = root.resolve(strict=True)
    def git(*args: str) -> str:
        return subprocess.check_output(["git", "-C", str(root), *args], text=True,
                                       stderr=subprocess.DEVNULL).strip()
    if Path(git("rev-parse", "--show-toplevel")).resolve() != root:
        raise ValueError("repository root must be its Git toplevel")
    if git("rev-parse", "HEAD") != expected:
        raise ValueError("repository revision does not match HEAD")
    status = git("status", "--porcelain=v1", "--untracked-files=all")
    if status and not allow_dirty:
        raise ValueError("repository has uncommitted changes; final-pair export requires clean sources")
    return {"revision": expected, "source-state": "dirty-development" if status else "clean",
            "root": str(root)}


def component(kind: str, name: str, version: str, origin: str,
              extra: dict[str, str] | None = None) -> dict:
    name, version = text(name, "name"), text(version, "version")
    attrs = {"origin": origin, **(extra or {})}
    identity = encoded([kind, name, version, attrs])
    return {"type": kind, "name": name, "version": version,
            "bom-ref": "component:" + digest(identity), "properties": properties(attrs)}


def source_components(document: object) -> list[dict]:
    if not isinstance(document, dict):
        raise ValueError("source input must be an object")
    rows = document.get("profiles", document.get("components"))
    if not isinstance(rows, list) or not rows:
        raise ValueError("source input requires nonempty profiles or components")
    result = []
    for row in rows:
        name = row.get("component", row.get("name"))
        profile = text(row.get("id", row.get("profile", "source")), "source profile")
        is_git = "commit" in row
        identity = text(row.get("commit" if is_git else "sha256"), "source identity")
        if re.fullmatch(r"[0-9a-f]{40}" if is_git else r"[0-9a-f]{64}", identity) is None:
            raise ValueError("source identity must be an exact lowercase commit or SHA-256")
        url = text(row.get("repository_url" if is_git else "download_url"), "source URL")
        if not url.startswith("https://") or "@" in url or "?" in url or "#" in url:
            raise ValueError("source download URL must be credential-free HTTPS without query or fragment")
        item = component("library", name, row.get("version"), "locked-source-or-release",
                         {"profile": profile,
                          "source-commit" if is_git else "expected-release-sha256": identity})
        # Lock hashes describe downloaded assets, not the source component itself.
        reference = {"type": "vcs" if is_git else "distribution", "url": url}
        if not is_git:
            reference["hashes"] = [{"alg": "SHA-256", "content": identity}]
        item["externalReferences"] = [reference]
        result.append(item)
    return result


def go_components(data: bytes) -> list[dict]:
    """Accept the JSON object stream emitted by go list -m -json all."""
    decoder, offset, result = json.JSONDecoder(), 0, []
    raw = data.decode("utf-8")
    while offset < len(raw):
        if raw[offset].isspace():
            offset += 1
            continue
        row, offset = decoder.raw_decode(raw, offset)
        if not isinstance(row, dict) or row.get("Error"):
            raise ValueError("Go export contains a malformed or unresolved module")
        if row.get("Replace"):
            raise ValueError("Go replacements need separate reviewed source/artifact input")
        version = row.get("Version")
        if row.get("Main"):
            # Source main identity is bound by repository revisions, not a release version.
            version = version or "unreleased"
        item = component("library", row.get("Path"), version, "go-selected-module-list",
                         {"main-module": str(bool(row.get("Main"))).lower(),
                          "indirect": str(bool(row.get("Indirect"))).lower()})
        result.append(item)
    if not result:
        raise ValueError("Go export is empty")
    return result


def python_components(document: object) -> list[dict]:
    if not isinstance(document, list) or not document:
        raise ValueError("Python export requires a nonempty pip list --format=json array")
    return [component("library", row.get("name"), row.get("version"),
                      "python-selected-environment") for row in document]


def artifact_components(document: object, base: Path) -> list[dict]:
    if not isinstance(document, list) or not document:
        raise ValueError("artifact input requires a nonempty array")
    result = []
    for row in document:
        artifact = Path(text(row.get("path"), "artifact path"))
        artifact = artifact if artifact.is_absolute() else base / artifact
        sha256, size = artifact_digest(artifact)
        build = row.get("build")
        if not isinstance(build, dict) or not build:
            raise ValueError("artifact requires a nonempty supplied build description")
        item = component("file", row.get("name"), row.get("version"), "observed-artifact-bytes",
                         {"profile": text(row.get("profile"), "artifact profile"),
                          "supplied-build-description": encoded(build).decode().strip(),
                          "size": str(size)})
        item["hashes"] = [{"alg": "SHA-256", "content": sha256}]
        result.append(item)
    return result


def export(args: argparse.Namespace) -> dict:
    roots = {"parent": args.parent_root, "framework": args.framework_root}
    revisions = {"parent": args.parent_revision, "framework": args.framework_revision}
    before = {name: repository(root, revisions[name], args.allow_dirty)
              for name, root in roots.items()}
    components, provenance = [], []
    selected = set()
    for kind in ("source", "go", "python", "artifacts"):
        for path in getattr(args, kind):
            identity = (kind, path.absolute())
            if identity in selected:
                raise ValueError("duplicate input; select each input once")
            selected.add(identity)
            raw = regular_bytes(path)
            provenance.append({"kind": kind, "path": str(path.absolute()), "sha256": digest(raw)})
            if kind == "go":
                components.extend(go_components(raw))
            else:
                document = json.loads(raw)
                producer = {"source": source_components, "python": python_components}
                components.extend(artifact_components(document, path.absolute().parent)
                                  if kind == "artifacts" else producer[kind](document))
    if not components:
        raise ValueError("at least one nonempty component input is required")
    # Different selected modules/environments can share exactly the same component.
    # Retain every input's provenance while emitting that identical record once.
    components = list({item["bom-ref"]: item for item in components}.values())
    after = {name: repository(root, revisions[name], args.allow_dirty)
             for name, root in roots.items()}
    if before != after:
        raise ValueError("repository revision or clean state changed during export")
    return {"$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
            "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {"properties": properties({
                "scope": "explicit-input-partial-inventory", "limitations": LIMITS,
                "repositories": encoded(before).decode().strip(),
                "inputs": encoded(sorted(provenance, key=lambda p: (p["kind"], p["path"]))).decode().strip(),
                "exporter-sha256": digest(regular_bytes(Path(__file__))),
            })},
            "components": sorted(components, key=lambda item: item["bom-ref"]),
            "compositions": [{"aggregate": "incomplete"}]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("parent", "framework"):
        parser.add_argument(f"--{name}-root", type=Path, required=True)
        parser.add_argument(f"--{name}-revision", required=True)
    for kind in ("source", "go", "python", "artifacts"):
        parser.add_argument(f"--{kind}", type=Path, action="append", default=[])
    parser.add_argument("--allow-dirty", action="store_true", help="development only; labelled dirty")
    parser.add_argument("--output", type=Path, required=True, help="new external output file")
    args = parser.parse_args()
    try:
        output = args.output.absolute()
        resolved = output.resolve()
        if any(resolved.is_relative_to(root.resolve()) for root in (args.parent_root, args.framework_root)):
            raise ValueError("output must be outside both source repositories")
        if any(part.is_symlink() for part in (output, *output.parents)):
            raise ValueError("output contains a symlink")
        bom = export(args)
        # No overwrite or partial output after invalid input.
        with output.open("xb") as handle:
            handle.write(encoded(bom))
        print(f"partial component SBOM: {len(bom['components'])} components; incomplete scope")
        return 0
    except ValueError as exc:
        # Only our fixed contract diagnostics, never JSON/Unicode decoder values.
        reason = str(exc) if type(exc) is ValueError else "malformed JSON or text input"
        print(f"component SBOM: BLOCKED: {reason}", file=sys.stderr)
        return 77
    except (OSError, TypeError, AttributeError, KeyError, subprocess.SubprocessError):
        # Do not echo arbitrary input values, supplied metadata or Git stderr.
        print("component SBOM: BLOCKED (invalid input, revision, source state or output; see input contract)",
              file=sys.stderr)
        return 77


if __name__ == "__main__":
    raise SystemExit(main())
