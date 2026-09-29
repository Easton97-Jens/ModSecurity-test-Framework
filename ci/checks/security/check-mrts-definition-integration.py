#!/usr/bin/env python3
"""Exercise the real pinned MRTS generator through the Framework entrypoint.

Compare legitimate corpora with direct generation, then prove that rejected
global settings and output-path escapes do not write outside selected roots.
No source, gitlink, rule policy, or production service is modified.
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
import tempfile

ROOT = Path(__file__).resolve().parents[3]
MRTS = ROOT / "tools" / "MRTS"
GENERATOR = MRTS / "mrts" / "generate-rules.py"
ENTRYPOINT = ROOT / "ci" / "provisioning" / "generate-mrts.sh"
CORPORA = {
    "upstream-config-tests": MRTS / "config_tests",
    "feature-demo": MRTS / "feature_demo" / "config_tests",
}
SHA = re.compile(r"[0-9a-f]{40}")


class IntegrationFailure(RuntimeError):
    """The observed real component did not meet the bounded test contract."""


def git_text(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True, capture_output=True, text=True, timeout=30,
    )
    return result.stdout.strip()


def source_identity(expected: str) -> tuple[str, str]:
    if SHA.fullmatch(expected) is None:
        raise IntegrationFailure("expected Framework head is not an exact SHA")
    head = git_text(ROOT, "rev-parse", "--verify", "HEAD")
    if head != expected:
        raise IntegrationFailure("Framework checkout does not match the requested head")
    entry = git_text(ROOT, "ls-tree", "HEAD", "--", "tools/MRTS").split()
    if len(entry) != 4 or entry[:2] != ["160000", "commit"]:
        raise IntegrationFailure("MRTS is not the recorded gitlink")
    pinned = entry[2]
    if git_text(MRTS, "rev-parse", "--verify", "HEAD") != pinned:
        raise IntegrationFailure("MRTS checkout differs from the Framework gitlink")
    if git_text(ROOT, "status", "--porcelain", "--untracked-files=no"):
        raise IntegrationFailure("Framework tracked sources must be clean")
    if git_text(MRTS, "status", "--porcelain", "--untracked-files=all"):
        raise IntegrationFailure("MRTS input must be clean, including untracked files")
    if not GENERATOR.is_file() or not ENTRYPOINT.is_file():
        raise IntegrationFailure("the real generator or Framework entrypoint is absent")
    return head, pinned


def run_root() -> Path:
    value = os.environ.get("RUNNER_TEMP", "")
    parent = Path(value)
    if not value or not parent.is_absolute() or ".." in parent.parts:
        raise IntegrationFailure("RUNNER_TEMP must be an existing absolute directory")
    current = Path(parent.anchor)
    for part in parent.parts[1:]:
        current /= part
        metadata = current.lstat()
        if not stat.S_ISDIR(metadata.st_mode):
            raise IntegrationFailure("RUNNER_TEMP must not traverse a symlink")
    if parent.stat().st_uid != os.geteuid():
        raise IntegrationFailure("RUNNER_TEMP must belong to the executing user")
    return Path(tempfile.mkdtemp(prefix="framework-mrts-real-", dir=parent))


def files_snapshot(directory: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for path in sorted(directory.rglob("*")):
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise IntegrationFailure("unexpected non-regular output or input")
        result[path.relative_to(directory).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def input_definitions(directory: Path) -> list[Path]:
    definitions = sorted(directory.rglob("*.yaml"), key=str)
    if not definitions or any(not path.is_file() or path.is_symlink() for path in definitions):
        raise IntegrationFailure("required real corpus is missing or unsafe")
    return definitions


def case_environment(base: Path, corpus: str, definitions: Path) -> dict[str, str]:
    env = os.environ.copy()
    env.update({
        "FRAMEWORK_ROOT": str(ROOT), "CONNECTOR_ROOT": str(ROOT),
        "CI_ROOT": str(ROOT / "ci"), "MRTS_ROOT": str(MRTS),
        "VERIFIED_RUN_ROOT": str(base), "VERIFIED_BUILD_ROOT": str(base / "build"),
        "BUILD_ROOT": str(base / "build"), "MRTS_BUILD_ROOT": str(base / "build" / "mrts"),
        "MRTS_CORPUS": corpus, "MRTS_DEFINITIONS": str(definitions),
        "MRTS_RULES_OUT": str(base / "build" / "mrts" / corpus / "rules"),
        "MRTS_FTW_OUT": str(base / "build" / "mrts" / corpus / "ftw"),
        "PYTHON": sys.executable, "PYTHONDONTWRITEBYTECODE": "1",
    })
    return env


def execute(arguments: list[str], env: dict[str, str], log: Path) -> int:
    with log.open("xb") as output:
        os.fchmod(output.fileno(), 0o600)
        completed = subprocess.run(
            arguments, cwd=MRTS, env=env, stdout=output,
            stderr=subprocess.STDOUT, check=False, timeout=240,
        )
    return completed.returncode


def compare_corpus(work: Path, corpus: str, definitions: Path) -> dict:
    paths = input_definitions(definitions)
    source_before = files_snapshot(definitions)
    case = work / corpus
    case.mkdir(mode=0o700)
    direct = case / "direct"
    for directory in (direct / "rules", direct / "ftw"):
        directory.mkdir(mode=0o700, parents=True)
    env = case_environment(case / "guarded", corpus, definitions)
    baseline = execute(
        [sys.executable, "--", str(GENERATOR), "-r", *map(str, paths),
         "-e", str(direct / "rules"), "-t", str(direct / "ftw")],
        env, case / "direct.log",
    )
    if baseline != 0:
        raise IntegrationFailure(f"{corpus}: direct pinned generator failed ({baseline})")
    status = execute(["/bin/sh", str(ENTRYPOINT)], env, case / "guarded.log")
    if status != 0:
        raise IntegrationFailure(f"{corpus}: guarded entrypoint failed ({status})")
    counts = {}
    for name, setting in (("rules", "MRTS_RULES_OUT"), ("ftw", "MRTS_FTW_OUT")):
        reference = files_snapshot(direct / name)
        observed = files_snapshot(Path(env[setting]))
        if not reference or observed != reference:
            raise IntegrationFailure(f"{corpus}: {name} inventory/content differs")
        counts[name] = len(reference)
    if files_snapshot(definitions) != source_before:
        raise IntegrationFailure(f"{corpus}: input definitions were modified")
    if list(Path(env["MRTS_BUILD_ROOT"]).glob("mrts-validated-*")):
        raise IntegrationFailure(f"{corpus}: temporary input snapshots were not removed")
    return {"corpus": corpus, "definitions": len(paths), **counts, "byte_equal": True}


def reject_global(work: Path, key: str) -> dict:
    case = work / ("reject-" + key)
    definitions = case / "definitions"
    definitions.mkdir(mode=0o700, parents=True)
    outside = case / "outside"
    outside.mkdir(mode=0o700)
    sentinel = outside / "probe.conf"
    sentinel.write_text("unchanged\n", encoding="utf-8")
    # Controlled test-only paths, not a payload against another system.
    document = {"global": {key: str(outside)}, "rulefile": "probe.conf", "objects": []}
    (definitions / "probe.yaml").write_text(json.dumps(document), encoding="utf-8")
    env = case_environment(case / "run", "negative", definitions)
    status = execute(["/bin/sh", str(ENTRYPOINT)], env, case / "guarded.log")
    diagnostic = (case / "guarded.log").read_text(encoding="utf-8")
    if status != 77 or "BLOCKED: definition 1: unsupported global setting" not in diagnostic:
        raise IntegrationFailure(f"global.{key}: expected intake rejection was not observed")
    if sentinel.read_text(encoding="utf-8") != "unchanged\n":
        raise IntegrationFailure(f"global.{key}: sentinel preservation failed")
    for setting in ("MRTS_RULES_OUT", "MRTS_FTW_OUT"):
        if files_snapshot(Path(env[setting])):
            raise IntegrationFailure(f"global.{key}: rejected input produced output")
    return {"global_key": key, "status": status, "outside_unchanged": True}


def reject_output_escape(work: Path, kind: str) -> dict:
    case = work / ("escape-" + kind)
    definitions = case / "definitions"
    definitions.mkdir(mode=0o700, parents=True)
    env = case_environment(case / "run", "negative", definitions)
    output = Path(env["MRTS_RULES_OUT"])
    output.mkdir(mode=0o700, parents=True)
    outside = case / "outside"
    outside.mkdir(mode=0o700)
    sentinel = outside / "probe.conf"
    sentinel.write_text("unchanged\n", encoding="utf-8")
    names = {
        "absolute": str(sentinel),
        "traversal": os.path.relpath(sentinel, output),
        "symlink": "escape/probe.conf",
    }
    if kind == "symlink":
        (output / "escape").symlink_to(outside, target_is_directory=True)
    document = {"rulefile": names[kind], "objects": []}
    (definitions / "probe.yaml").write_text(json.dumps(document), encoding="utf-8")
    status = execute(["/bin/sh", str(ENTRYPOINT)], env, case / "guarded.log")
    diagnostic = (case / "guarded.log").read_text(encoding="utf-8")
    if status != 1 or "rulefile must stay within" not in diagnostic:
        raise IntegrationFailure(f"{kind}: expected real generator path rejection, got {status}")
    if sentinel.read_text(encoding="utf-8") != "unchanged\n":
        raise IntegrationFailure(f"{kind}: output escaped the selected directory")
    return {"escape": kind, "nonzero_child_status": status, "outside_unchanged": True}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-head", required=True)
    args = parser.parse_args()
    work: Path | None = None
    try:
        head, pinned = source_identity(args.expected_head)
        work = run_root()
        corpora = [compare_corpus(work, name, path) for name, path in CORPORA.items()]
        rejected = [reject_global(work, key) for key in ("expdir", "testdir", "content")]
        escapes = [reject_output_escape(work, kind) for kind in ("absolute", "traversal", "symlink")]
        source_identity(head)
        receipt = {
            "status": "passed", "framework_head": head, "mrts_gitlink": pinned,
            "corpora": corpora, "rejected_globals": rejected, "output_escape_controls": escapes,
            "scope": "Framework entrypoint and pinned generator compatibility, not a complete B03 fix",
        }
        (work / "result.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(receipt, sort_keys=True))
        return 0
    except (IntegrationFailure, OSError, subprocess.SubprocessError) as error:
        print(f"MRTS real integration failed: {error}", file=sys.stderr)
        if work is not None:
            print(f"Retained private diagnostics: {work}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
