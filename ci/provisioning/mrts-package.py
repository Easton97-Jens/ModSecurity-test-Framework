#!/usr/bin/env python3
"""Prepare, verify and privately materialize a Framework-owned MRTS package."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

import yaml

CORPORA = ("upstream-config-tests", "feature-demo")
SOURCE_FILES = (
    "ci/lib/common.sh",
    "ci/lib/path.sh",
    "ci/lib/path-bootstrap.sh",
    "ci/lib/mrts-common.sh",
    "ci/provisioning/mrts-package.py",
    "ci/provisioning/generate-mrts.sh",
    "ci/provisioning/mrts_definition_guard.py",
    "ci/provisioning/import-mrts-cases.py",
    "ci/provisioning/write-mrts-load.sh",
    "tests/runners/runner_core.py",
    "tests/mrts/classifications.yaml",
)


class PackageError(ValueError):
    """A package does not satisfy the preparation contract."""


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(root: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(root), *args], text=True, stderr=subprocess.DEVNULL
    ).strip()


def revision(root: Path) -> str:
    # Reject a directory inside another repository masquerading as its own root.
    if Path(git(root, "rev-parse", "--show-toplevel")).resolve() != root:
        raise PackageError("source root is not a repository root")
    return git(root, "rev-parse", "HEAD")


def identities(args: argparse.Namespace) -> dict:
    result = {name: revision(getattr(args, name + "_root")) for name in (
        "framework", "mrts", "connector"
    )}
    entry = git(args.framework_root, "ls-tree", "HEAD", "tools/MRTS").split()
    if len(entry) < 3 or entry[0] != "160000" or entry[2] != result["mrts"]:
        raise PackageError("MRTS checkout does not match the Framework gitlink")
    if git(args.mrts_root, "status", "--porcelain", "--untracked-files=normal"):
        raise PackageError("MRTS checkout must be clean")
    result["framework_sources"] = {
        name: digest(args.framework_root / name) for name in SOURCE_FILES
    }
    result["python"] = {
        "version": list(sys.version_info[:3]), "pyyaml": yaml.__version__
    }
    return result


def contained(path: Path, root: Path) -> bool:
    return path != root and path.is_relative_to(root)


def checked_output(path: Path, args: argparse.Namespace, *, package: bool) -> Path:
    if not path.is_absolute() or ".." in path.parts:
        raise PackageError("output paths must be absolute without traversal")
    resolved = path.resolve()
    allowed = args.build_root / "mrts" if package else args.build_root
    if not contained(resolved, allowed):
        raise PackageError("output is outside the authorized build root")
    for source in (args.framework_root, args.mrts_root, args.connector_root):
        if resolved == source or resolved.is_relative_to(source):
            raise PackageError("output must be outside source checkouts")
    if any(char in str(resolved) for char in ('"', "\n", "\r")):
        raise PackageError("output path contains unsupported load-file characters")
    # Never follow existing symlinks at a publication boundary.
    if any(parent.is_symlink() for parent in (path, *path.parents)):
        raise PackageError("output path must not contain symlinks")
    return resolved


def artifact_hashes(root: Path) -> dict[str, str]:
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or (not path.is_file() and not path.is_dir()):
            raise PackageError("package contains an unsafe filesystem object")
        if path.is_file() and path != root / "manifest.json":
            result[path.relative_to(root).as_posix()] = digest(path)
    return result


def runner(args: argparse.Namespace):
    sys.path.insert(0, str(args.framework_root / "tests/runners"))
    import runner_core
    return runner_core


def case_ids(root: Path, corpora: list[str], args: argparse.Namespace) -> list[str]:
    core = runner(args)
    ids = []
    for corpus in corpora:
        paths = sorted((root / corpus / "framework-cases").glob("*.yaml"))
        if not paths:
            raise PackageError("selected corpus has no imported cases")
        for path in paths:
            case = core.load_case(path)
            ids.append(case["name"])
    if len(ids) != len(set(ids)):
        raise PackageError("duplicate imported case IDs")
    return ids


def run_step(argv: list[str], environment: dict[str, str]) -> None:
    # Keep stdout machine-readable: only the final root is printed there.
    subprocess.run(argv, env=environment, check=True, stdout=sys.stderr)


def relocate(value, old: Path, new: Path):
    if isinstance(value, str):
        return value.replace(str(old) + "/", str(new) + "/")
    if isinstance(value, list):
        return [relocate(item, old, new) for item in value]
    if isinstance(value, dict):
        return {key: relocate(item, old, new) for key, item in value.items()}
    return value


def rewrite_paths(root: Path, old: Path, new: Path) -> None:
    for path in root.rglob("*.yaml"):
        # Only imported provenance contains preparation paths. Definitions and
        # executable request values are never globally rewritten.
        if path.parent.name != "framework-cases":
            continue
        case = yaml.safe_load(path.read_text(encoding="utf-8"))
        for key in ("metadata", "origin"):
            if key in case:
                case[key] = relocate(case[key], old, new)
        path.write_text(yaml.safe_dump(case, sort_keys=False, allow_unicode=True), encoding="utf-8")
    for path in root.rglob("mrts.load"):
        path.write_text(path.read_text(encoding="utf-8").replace(
            str(old) + "/", str(new) + "/"
        ), encoding="utf-8")


def check_collisions(root: Path, corpora: list[str]) -> None:
    by_corpus = []
    for corpus in corpora:
        ids = set()
        for path in (root / corpus / "rules").glob("*.conf"):
            ids.update(re.findall(r"\bid\s*:\s*['\"]?(\d+)", path.read_text(encoding="utf-8")))
        if not ids:
            raise PackageError("selected corpus has no generated rule IDs")
        by_corpus.append(ids)
    if len(by_corpus) == 2 and by_corpus[0] & by_corpus[1]:
        raise PackageError("feature-demo has duplicate rule IDs with upstream-config-tests")


def definition_selection(args: argparse.Namespace, corpora: list[str]) -> dict:
    selection = {}
    for corpus in corpora:
        directory = args.upstream_definitions if corpus == CORPORA[0] else args.feature_demo_definitions
        directory = directory.resolve(strict=True)
        paths = sorted(directory.glob("*.yaml"))
        if not paths or any(not path.is_file() or path.is_symlink() for path in paths):
            raise PackageError("selected definitions must be nonempty regular YAML files")
        selection[corpus] = {str(path): digest(path) for path in paths}
    return selection


def prepare(args: argparse.Namespace) -> Path:
    target = checked_output(args.package_root, args, package=True)
    if target.exists():
        raise PackageError("package destination already exists; use verify for reuse")
    source = identities(args)
    corpora = list(CORPORA if args.include_feature_demo == 1 else CORPORA[:1])
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".mrts-package-", dir=target.parent) as temporary:
        stage = Path(temporary) / "package"
        stage.mkdir(mode=0o700)
        definitions = definition_selection(args, corpora)
        environment = dict(os.environ, PYTHON=sys.executable,
            PYTHONDONTWRITEBYTECODE="1", PYTHONNOUSERSITE="1",
            FRAMEWORK_ROOT=str(args.framework_root), CONNECTOR_ROOT=str(args.connector_root),
            BUILD_ROOT=str(args.build_root), MRTS_BUILD_ROOT=str(target.parent),
            MRTS_ROOT=str(args.mrts_root))
        for corpus in corpora:
            original = args.upstream_definitions if corpus == CORPORA[0] else args.feature_demo_definitions
            original = original.resolve(strict=True)
            snapshots = stage / "definitions" / corpus
            snapshots.mkdir(parents=True)
            originals = sorted(original.glob("*.yaml"))
            if not originals:
                raise PackageError("selected corpus has no definitions")
            for path in originals:
                if not path.is_file() or path.is_symlink():
                    raise PackageError("definitions must be regular files")
                data = path.read_bytes()
                (snapshots / path.name).write_bytes(data)
                if hashlib.sha256(data).hexdigest() != definitions[corpus][str(path)]:
                    raise PackageError("definitions changed before snapshotting")
            corpus_root = stage / corpus
            rules, ftw, cases = (corpus_root / name for name in ("rules", "ftw", "framework-cases"))
            selected_environment = dict(environment, MRTS_CORPUS=corpus,
                MRTS_DEFINITIONS=str(snapshots), MRTS_RULES_OUT=str(rules), MRTS_FTW_OUT=str(ftw))
            run_step(["sh", str(args.framework_root / "ci/provisioning/generate-mrts.sh")], selected_environment)
            run_step([sys.executable, str(args.framework_root / "ci/provisioning/import-mrts-cases.py"),
                "--framework-root", str(args.framework_root), "--mrts-corpus", corpus,
                "--source-definition-dir", str(snapshots), "--mrts-ftw-dir", str(ftw),
                "--upstream-ftw-dir", str(args.mrts_root / (
                    "generated/tests/regression/tests" if corpus == CORPORA[0] else "feature_demo/generated/tests")),
                "--mrts-rules-dir", str(rules), "--output-dir", str(cases)], selected_environment)
            run_step(["sh", str(args.framework_root / "ci/provisioning/write-mrts-load.sh")],
                dict(selected_environment, MRTS_LOAD_FILE=str(corpus_root / "mrts.load")))
        check_collisions(stage, corpora)
        ids = case_ids(stage, corpora, args)
        rewrite_paths(stage, stage, target)
        manifest = {
            "schema_version": 1, "package_root": str(target), "status": "validated", "import_status": "passed",
            "validation_status": "passed", "sources": source, "corpora": corpora,
            "corpus_status": {name: "validated" if name in corpora else "disabled" for name in CORPORA},
            "definitions": definitions, "case_ids": ids, "artifacts": artifact_hashes(stage),
        }
        (stage / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        # Refuse races and stale preparation after any source/revision change.
        if identities(args) != source:
            raise PackageError("sources changed during preparation")
        if definition_selection(args, corpora) != definitions:
            raise PackageError("definitions changed during preparation")
        if target.exists():
            raise PackageError("package destination appeared during preparation")
        stage.rename(target)
    return target


def verify(args: argparse.Namespace) -> dict:
    root = checked_output(args.package_root, args, package=True)
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    corpora = list(CORPORA if args.include_feature_demo == 1 else CORPORA[:1])
    if (manifest.get("schema_version") != 1 or manifest.get("package_root") != str(root)
            or manifest.get("status") != "validated"
            or manifest.get("import_status") != "passed" or manifest.get("validation_status") != "passed"
            or manifest.get("corpora") != corpora or manifest.get("sources") != identities(args)):
        raise PackageError("package selection or source identity mismatch")
    if manifest.get("artifacts") != artifact_hashes(root):
        raise PackageError("package artifact hash mismatch")
    if manifest.get("definitions") != definition_selection(args, corpora):
        raise PackageError("package definition selection or hash mismatch")
    if manifest.get("case_ids") != case_ids(root, corpora, args):
        raise PackageError("package case ID mismatch")
    check_collisions(root, corpora)
    return manifest


def materialize(args: argparse.Namespace) -> Path:
    manifest = verify(args)
    target = checked_output(args.output_root, args, package=False)
    source = args.package_root.resolve()
    if target.exists() or target.is_relative_to(source) or source.is_relative_to(target):
        raise PackageError("materialization requires a fresh independent destination")
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".mrts-run-", dir=target.parent) as temporary:
        stage = Path(temporary) / "package"
        shutil.copytree(source, stage)
        # Detect source mutation across copy before touching the private files.
        if artifact_hashes(stage) != manifest["artifacts"]:
            raise PackageError("package changed during materialization")
        rewrite_paths(stage, source, target)
        for corpus in manifest["corpora"]:
            for path in (stage / corpus / "ftw").glob("*.yaml"):
                document = yaml.safe_load(path.read_text(encoding="utf-8"))
                for test in document.get("tests", []):
                    for step in test.get("stages", []):
                        request = step.get("input", step.get("stage", {}).get("input"))
                        if isinstance(request, dict):
                            request["port"] = args.port
                path.write_text(yaml.safe_dump(document, sort_keys=False, allow_unicode=True), encoding="utf-8")
        case_ids(stage, manifest["corpora"], args)
        (stage / "materialization.json").write_text(json.dumps({
            "source_manifest_sha256": digest(source / "manifest.json"), "port": args.port,
            "status": "materialized", "artifacts": artifact_hashes(stage),
        }, indent=2) + "\n", encoding="utf-8")
        if target.exists():
            raise PackageError("materialization destination appeared during preparation")
        stage.rename(target)
    return target


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "verify", "materialize"))
    for name in ("framework", "mrts", "connector", "build", "package"):
        parser.add_argument("--" + name + "-root", type=Path, required=True)
    parser.add_argument("--include-feature-demo", type=int, choices=(0, 1), default=0)
    parser.add_argument("--upstream-definitions", type=Path)
    parser.add_argument("--feature-demo-definitions", type=Path)
    parser.add_argument("--output-root", type=Path)
    parser.add_argument("--port", type=int)
    args = parser.parse_args()
    try:
        for name in ("framework", "mrts", "connector"):
            setattr(args, name + "_root", getattr(args, name + "_root").resolve(strict=True))
        if not args.build_root.is_absolute() or args.build_root.resolve() in (Path("/"), Path("/tmp"), Path("/var/tmp")):
            raise PackageError("build root must be a dedicated absolute external directory")
        args.build_root = args.build_root.resolve()
        if args.build_root.parts[1:2] in (("root",), ("usr",), ("etc",), ("var",)) and not args.build_root.is_relative_to(Path("/var/tmp")):
            raise PackageError("build root is not an external runtime directory")
        args.upstream_definitions = args.upstream_definitions or args.mrts_root / "config_tests"
        args.feature_demo_definitions = args.feature_demo_definitions or args.mrts_root / "feature_demo/config_tests"
        if args.action == "prepare":
            result = prepare(args)
        elif args.action == "verify":
            verify(args)
            result = args.package_root
        else:
            if args.output_root is None or args.port is None or not 1 <= args.port <= 65535:
                raise PackageError("materialize requires an output root and a valid port")
            result = materialize(args)
        print(result)
        return 0
    except (PackageError, OSError, ValueError, KeyError, TypeError, yaml.YAMLError, subprocess.SubprocessError) as error:
        print(f"BLOCKED: MRTS package {args.action}: {error}", file=sys.stderr)
        return 77


if __name__ == "__main__":
    raise SystemExit(main())
