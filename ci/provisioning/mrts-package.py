#!/usr/bin/env python3
"""Prepare, verify and privately materialize a Framework-owned MRTS package."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import stat
import subprocess
import sys
import tempfile

import yaml

FRAMEWORK_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(FRAMEWORK_ROOT / "ci/lib"))
from mrts_path_safety import approved_runtime_root
from runtime_path_safety import (
    absolute_path_without_traversal,
    has_symlink_component,
    private_runtime_root,
)

MANIFEST_FILE = "manifest.json"
YAML_FILES = "*.yaml"
LOAD_FILE = "mrts.load"
GENERATE_SCRIPT = "generate-mrts.sh"
LOAD_SCRIPT = "write-mrts-load.sh"

CORPORA = ("upstream-config-tests", "feature-demo")
SOURCE_FILES = (
    "ci/lib/mrts_path_safety.py",
    "ci/lib/runtime_path_safety.py",
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
    "tests/runners/adapter_interface.py",
    "tests/runners/case_roots.py",
    "tests/runners/msconnector_models.py",
    "ci/lib/generated_report_utils.py",
    "tests/mrts/classifications.yaml",
)
PUBLIC_NAMESPACE = "modsecurity_test_framework"
MAX_PUBLIC_SOURCE_FILES = 1024
MAX_PUBLIC_SOURCE_NODES = 4096
MAX_PUBLIC_SOURCE_BYTES = 1024 * 1024
MAX_PUBLIC_SOURCE_TOTAL_BYTES = 16 * 1024 * 1024
MAX_PUBLIC_SOURCE_DEPTH = 32


class PackageError(ValueError):
    """A package does not satisfy the preparation contract."""


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def checked_source_directory(value: Path) -> Path:
    path = absolute_path_without_traversal(value, "source directory")
    if has_symlink_component(path) or not path.is_dir():
        raise PackageError("source directory must exist without symlink components")
    if any(ord(char) < 32 or ord(char) == 127 for char in str(path)):
        raise PackageError("source directory contains control characters")
    return path.resolve(strict=True)


def trusted_executable(name: str) -> str:
    # System search directories, never a caller-controlled PATH entry.
    value = sys.executable if name == "python" else shutil.which(name, path=os.defpath)
    if not value:
        raise PackageError("required executable is unavailable")
    path = Path(value).resolve(strict=True)
    mode = path.stat()
    if (
        not stat.S_ISREG(mode.st_mode)
        or not os.access(path, os.X_OK)
        or mode.st_uid not in (0, os.geteuid())
        or mode.st_mode & 0o022
    ):
        raise PackageError("required executable is not trusted")
    # Keep the venv launcher spelling: resolving it for execution would switch
    # Python's prefix and discard the Framework's declared dependencies.
    return str(Path(value).absolute()) if name == "python" else str(path)


def git(root: Path, operation: str) -> str:
    commands = {
        "root": ("rev-parse", "--show-toplevel"),
        "revision": ("rev-parse", "--verify", "HEAD^{commit}"),
        "mrts-pin": ("ls-tree", "HEAD", "--", "tools/MRTS"),
        "status": ("status", "--porcelain", "--untracked-files=normal"),
    }
    if operation not in commands:
        raise PackageError("unsupported Git inspection")
    directory = checked_source_directory(root)
    environment = {
        name: value for name, value in os.environ.items() if not name.startswith("GIT_")
    }
    return subprocess.check_output(
        [
            trusted_executable("git"),
            "--no-optional-locks",
            "-c",
            "core.fsmonitor=false",
            *commands[operation],
        ],
        cwd=directory,
        env=environment,
        text=True,
        stderr=subprocess.DEVNULL,
    ).strip()


def revision(root: Path) -> str:
    # Reject a directory inside another repository masquerading as its own root.
    if Path(git(root, "root")).resolve() != root:
        raise PackageError("source root is not a repository root")
    value = git(root, "revision")
    if not re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", value):
        raise PackageError("invalid source revision")
    return value


def _public_source_body(descriptor: int, name: str) -> bytes:
    child = os.open(
        name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor
    )
    with os.fdopen(child, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_PUBLIC_SOURCE_BYTES:
            raise PackageError("public Framework source size exceeds bound")
        body = stream.read(MAX_PUBLIC_SOURCE_BYTES + 1)
        after = os.fstat(stream.fileno())
    identity = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if (
        any(getattr(before, key) != getattr(after, key) for key in identity)
        or len(body) != before.st_size
        or len(body) > MAX_PUBLIC_SOURCE_BYTES
    ):
        raise PackageError("public Framework source changed during inspection")
    return body


class _PublicSourceTree:
    def __init__(self) -> None:
        self.sources: dict[str, str] = {}
        self.nodes = 0
        self.total_bytes = 0

    def visit(self, descriptor: int, relative: str, depth: int) -> None:
        if depth > MAX_PUBLIC_SOURCE_DEPTH:
            raise PackageError("public Framework source depth exceeds bound")
        with os.scandir(descriptor) as entries:
            for entry in entries:
                self.nodes += 1
                if self.nodes > MAX_PUBLIC_SOURCE_NODES:
                    raise PackageError("public Framework source nodes exceed bound")
                self.entry(descriptor, relative, depth, entry)

    def entry(
        self, descriptor: int, relative: str, depth: int, entry: os.DirEntry
    ) -> None:
        mode = entry.stat(follow_symlinks=False).st_mode
        path = relative + "/" + entry.name
        if stat.S_ISLNK(mode):
            raise PackageError("public Framework sources must not contain symlinks")
        if stat.S_ISDIR(mode):
            child = os.open(
                entry.name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            try:
                self.visit(child, path, depth + 1)
            finally:
                os.close(child)
        elif entry.name.endswith(".py"):
            if not stat.S_ISREG(mode) or len(self.sources) >= MAX_PUBLIC_SOURCE_FILES:
                raise PackageError(
                    "public Framework sources must be bounded regular files"
                )
            body = _public_source_body(descriptor, entry.name)
            self.total_bytes += len(body)
            if self.total_bytes > MAX_PUBLIC_SOURCE_TOTAL_BYTES:
                raise PackageError("public Framework source total size exceeds bound")
            self.sources[path] = hashlib.sha256(body).hexdigest()


def public_source_hashes(root: Path) -> dict[str, str]:
    """Bind the fixed public Framework namespace without following symlinks."""
    tree = _PublicSourceTree()
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        namespace = os.open(
            PUBLIC_NAMESPACE,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=descriptor,
        )
        try:
            tree.visit(namespace, PUBLIC_NAMESPACE, 0)
        finally:
            os.close(namespace)
    finally:
        os.close(descriptor)
    if not tree.sources:
        raise PackageError("public Framework source namespace must be nonempty")
    return dict(sorted(tree.sources.items()))


def identities(args: argparse.Namespace) -> dict:
    result = {
        name: revision(getattr(args, name + "_root"))
        for name in ("framework", "mrts", "connector")
    }
    entry = git(args.framework_root, "mrts-pin").split()
    if len(entry) < 3 or entry[0] != "160000" or entry[2] != result["mrts"]:
        raise PackageError("MRTS checkout does not match the Framework gitlink")
    if git(args.mrts_root, "status"):
        raise PackageError("MRTS checkout must be clean")
    result["framework_sources"] = {
        name: digest(args.framework_root / name) for name in SOURCE_FILES
    }
    result["framework_sources"].update(public_source_hashes(FRAMEWORK_ROOT))
    result["python"] = {
        "version": list(sys.version_info[:3]),
        "pyyaml": yaml.__version__,
    }
    return result


def contained(path: Path, root: Path) -> bool:
    return path != root and path.is_relative_to(root)


def checked_output(path: Path, args: argparse.Namespace, *, package: bool) -> Path:
    if not path.is_absolute() or ".." in path.parts:
        raise PackageError("output paths must be absolute without traversal")
    resolved = private_runtime_root(path, "output path")
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
    return {
        path.relative_to(root).as_posix(): digest(path)
        for path in package_files(root)
        if path.name != MANIFEST_FILE or path.parent != root
    }


def runner(args: argparse.Namespace):
    sys.path.insert(0, str(args.framework_root / "tests/runners"))
    import runner_core

    return runner_core


def case_ids(root: Path, corpora: list[str], args: argparse.Namespace) -> list[str]:
    core = runner(args)
    ids = []
    for corpus in corpora:
        paths = sorted((root / corpus / "framework-cases").glob(YAML_FILES))
        if not paths:
            raise PackageError("selected corpus has no imported cases")
        for path in paths:
            case = core.load_case(path)
            ids.append(case["name"])
    if len(ids) != len(set(ids)):
        raise PackageError("duplicate imported case IDs")
    return ids


def framework_script(name: str) -> Path:
    if name not in {GENERATE_SCRIPT, "import-mrts-cases.py", LOAD_SCRIPT}:
        raise PackageError("unsupported Framework entrypoint")
    path = FRAMEWORK_ROOT / "ci/provisioning" / name
    if has_symlink_component(path) or not path.is_file():
        raise PackageError("Framework entrypoint must be a regular checkout file")
    return path


def run_shell_step(name: str, environment: dict[str, str]) -> None:
    if name not in {GENERATE_SCRIPT, LOAD_SCRIPT}:
        raise PackageError("unsupported shell preparation step")
    subprocess.run(
        [trusted_executable("sh"), "--", str(framework_script(name))],
        env=environment,
        check=True,
        stdout=sys.stderr,
    )


def run_import(
    args: argparse.Namespace,
    corpus: str,
    snapshots: Path,
    corpus_root: Path,
    environment: dict[str, str],
) -> None:
    if corpus not in CORPORA:
        raise PackageError("unsupported import corpus")
    for path in (snapshots, corpus_root):
        private_runtime_root(path, "import operand")
        if not contained(path, args.build_root):
            raise PackageError("import operand is outside the build root")
    upstream = args.mrts_root / (
        "generated/tests/regression/tests"
        if corpus == CORPORA[0]
        else "feature_demo/generated/tests"
    )
    # Fixed executable, script and option layout. Every variable operand is an
    # absolute validated path; -- terminates interpreter option processing.
    subprocess.run(
        [
            trusted_executable("python"),
            "--",
            str(framework_script("import-mrts-cases.py")),
            "--framework-root",
            str(FRAMEWORK_ROOT),
            "--mrts-corpus",
            corpus,
            "--source-definition-dir",
            str(snapshots),
            "--mrts-ftw-dir",
            str(corpus_root / "ftw"),
            "--upstream-ftw-dir",
            str(upstream),
            "--mrts-rules-dir",
            str(corpus_root / "rules"),
            "--output-dir",
            str(corpus_root / "framework-cases"),
        ],
        env=environment,
        check=True,
        stdout=sys.stderr,
    )


def checked_artifact(path: Path, root: Path) -> Path:
    # Content is data, never a filesystem destination. Validate discovered
    # entries as well as the root before opening anything for read or write.
    if (
        not contained(path, root)
        or has_symlink_component(path)
        or not path.resolve(strict=True).is_relative_to(root.resolve(strict=True))
        or not stat.S_ISREG(path.lstat().st_mode)
    ):
        raise PackageError("package artifact must be a contained regular file")
    return path


def package_files(root: Path) -> list[Path]:
    private_runtime_root(root, "package root")
    paths = sorted(root.rglob("*"))
    if any(
        path.is_symlink() or not (path.is_dir() or path.is_file()) for path in paths
    ):
        raise PackageError("package contains an unsafe filesystem object")
    return [checked_artifact(path, root) for path in paths if path.is_file()]


def relocate(value, old: Path, new: Path):
    if isinstance(value, str):
        return value.replace(str(old) + "/", str(new) + "/")
    if isinstance(value, list):
        return [relocate(item, old, new) for item in value]
    if isinstance(value, dict):
        return {key: relocate(item, old, new) for key, item in value.items()}
    return value


def rewrite_paths(root: Path, old: Path, new: Path) -> None:
    for path in package_files(root):
        if path.suffix == ".yaml" and path.parent.name == "framework-cases":
            rewrite_case_provenance(path, old, new)
        elif path.name == LOAD_FILE:
            with path.open("r", encoding="utf-8") as stream:
                content = stream.read().replace(str(old) + "/", str(new) + "/")
            with path.open("w", encoding="utf-8") as stream:
                stream.write(content)


def rewrite_case_provenance(path: Path, old: Path, new: Path) -> None:
    with path.open("r", encoding="utf-8") as stream:
        case = yaml.safe_load(stream)
    if not isinstance(case, dict):
        raise PackageError("imported case must be a mapping")
    for key in ("metadata", "origin"):
        if key in case:
            case[key] = relocate(case[key], old, new)
    with path.open("w", encoding="utf-8") as stream:
        yaml.safe_dump(case, stream, sort_keys=False, allow_unicode=True)


def check_collisions(root: Path, corpora: list[str]) -> None:
    by_corpus = []
    for corpus in corpora:
        ids = set()
        for path in (root / corpus / "rules").glob("*.conf"):
            ids.update(
                re.findall(r"\bid\s*:\s*['\"]?(\d+)", path.read_text(encoding="utf-8"))
            )
        if not ids:
            raise PackageError("selected corpus has no generated rule IDs")
        by_corpus.append(ids)
    if len(by_corpus) == 2 and by_corpus[0] & by_corpus[1]:
        raise PackageError(
            "feature-demo has duplicate rule IDs with upstream-config-tests"
        )


def definition_selection(args: argparse.Namespace, corpora: list[str]) -> dict:
    guard = runpy.run_path(
        str(FRAMEWORK_ROOT / "ci/provisioning/mrts_definition_guard.py")
    )
    selection = {}
    for corpus in corpora:
        directory = (
            args.upstream_definitions
            if corpus == CORPORA[0]
            else args.feature_demo_definitions
        )
        directory = checked_source_directory(directory)
        paths = guard["select_definition_files"](directory)
        if not paths or any(not path.is_file() or path.is_symlink() for path in paths):
            raise PackageError(
                "selected definitions must be nonempty regular YAML files"
            )
        selection[corpus] = {str(path): digest(path) for path in paths}
    return selection


def selected_corpora(args: argparse.Namespace) -> list[str]:
    return list(CORPORA if args.include_feature_demo == 1 else CORPORA[:1])


def snapshot_definitions(stage: Path, corpus: str, entries: dict[str, str]) -> Path:
    snapshots = stage / "definitions" / corpus
    snapshots.mkdir(parents=True)
    for name, expected in entries.items():
        original = Path(name)
        path = checked_artifact(original, checked_source_directory(original.parent))
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise PackageError("definitions changed before snapshotting")
        (snapshots / path.name).write_bytes(data)
    return snapshots


def prepare_corpus(
    args: argparse.Namespace,
    stage: Path,
    target: Path,
    corpus: str,
    entries: dict[str, str],
) -> None:
    snapshots = snapshot_definitions(stage, corpus, entries)
    corpus_root = stage / corpus
    environment = dict(
        os.environ,
        PATH=os.defpath,
        PYTHON=sys.executable,
        PYTHONDONTWRITEBYTECODE="1",
        PYTHONNOUSERSITE="1",
        FRAMEWORK_ROOT=str(FRAMEWORK_ROOT),
        CONNECTOR_ROOT=str(args.connector_root),
        BUILD_ROOT=str(args.build_root),
        MRTS_BUILD_ROOT=str(target.parent),
        MRTS_ROOT=str(args.mrts_root),
        MRTS_CORPUS=corpus,
        MRTS_DEFINITIONS=str(snapshots),
        MRTS_RULES_OUT=str(corpus_root / "rules"),
        MRTS_FTW_OUT=str(corpus_root / "ftw"),
    )
    run_shell_step(GENERATE_SCRIPT, environment)
    run_import(args, corpus, snapshots, corpus_root, environment)
    run_shell_step(
        LOAD_SCRIPT, dict(environment, MRTS_LOAD_FILE=str(corpus_root / LOAD_FILE))
    )


def publish(stage: Path, target: Path) -> None:
    private_runtime_root(target, "publication target")
    if target.exists():
        raise PackageError("destination appeared during preparation")
    stage.rename(target)


def prepare(args: argparse.Namespace) -> Path:
    target = checked_output(args.package_root, args, package=True)
    if target.exists():
        raise PackageError("package destination already exists; use verify for reuse")
    source = identities(args)
    corpora = selected_corpora(args)
    definitions = definition_selection(args, corpora)
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=".mrts-package-", dir=target.parent
    ) as temporary:
        stage = Path(temporary) / "package"
        stage.mkdir(mode=0o700)
        for corpus in corpora:
            prepare_corpus(args, stage, target, corpus, definitions[corpus])
        check_collisions(stage, corpora)
        ids = case_ids(stage, corpora, args)
        rewrite_paths(stage, stage, target)
        manifest = {
            "schema_version": 1,
            "package_root": str(target),
            "status": "validated",
            "import_status": "passed",
            "validation_status": "passed",
            "sources": source,
            "corpora": corpora,
            "corpus_status": {
                name: "validated" if name in corpora else "disabled" for name in CORPORA
            },
            "definitions": definitions,
            "case_ids": ids,
            "artifacts": artifact_hashes(stage),
        }
        (stage / MANIFEST_FILE).write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )
        if identities(args) != source:
            raise PackageError("sources changed during preparation")
        if definition_selection(args, corpora) != definitions:
            raise PackageError("definitions changed during preparation")
        publish(stage, target)
    return target


def verify(args: argparse.Namespace) -> dict:
    root = checked_output(args.package_root, args, package=True)
    manifest_path = checked_artifact(root / MANIFEST_FILE, root)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    corpora = selected_corpora(args)
    if (
        manifest.get("schema_version") != 1
        or manifest.get("package_root") != str(root)
        or manifest.get("status") != "validated"
        or manifest.get("import_status") != "passed"
        or manifest.get("validation_status") != "passed"
        or manifest.get("corpora") != corpora
        or manifest.get("sources") != identities(args)
    ):
        raise PackageError("package selection or source identity mismatch")
    if manifest.get("artifacts") != artifact_hashes(root):
        raise PackageError("package artifact hash mismatch")
    if manifest.get("definitions") != definition_selection(args, corpora):
        raise PackageError("package definition selection or hash mismatch")
    if manifest.get("case_ids") != case_ids(root, corpora, args):
        raise PackageError("package case ID mismatch")
    check_collisions(root, corpora)
    return manifest


def ftw_request(step: object) -> dict | None:
    if not isinstance(step, dict) or not isinstance(step.get("stage", {}), dict):
        raise PackageError("FTW stage must be a mapping")
    request = step.get("input", step.get("stage", {}).get("input"))
    if request is not None and not isinstance(request, dict):
        raise PackageError("FTW request must be a mapping")
    return request


def ftw_requests(document: object):
    if not isinstance(document, dict) or not isinstance(document.get("tests"), list):
        raise PackageError("FTW document requires a test list")
    for test in document["tests"]:
        if not isinstance(test, dict) or not isinstance(test.get("stages"), list):
            raise PackageError("FTW test requires a stage list")
        for step in test["stages"]:
            request = ftw_request(step)
            if request is not None:
                yield request


def update_ftw_ports(stage: Path, corpora: list[str], port: int) -> None:
    for corpus in corpora:
        for candidate in (stage / corpus / "ftw").glob(YAML_FILES):
            path = checked_artifact(candidate, stage)
            with path.open("r", encoding="utf-8") as stream:
                document = yaml.safe_load(stream)
            for request in ftw_requests(document):
                request["port"] = port
            with path.open("w", encoding="utf-8") as stream:
                yaml.safe_dump(document, stream, sort_keys=False, allow_unicode=True)


def materialize(args: argparse.Namespace) -> Path:
    manifest = verify(args)
    target = checked_output(args.output_root, args, package=False)
    source = args.package_root.resolve()
    if (
        target.exists()
        or target.is_relative_to(source)
        or source.is_relative_to(target)
    ):
        raise PackageError("materialization requires a fresh independent destination")
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=".mrts-run-", dir=target.parent
    ) as temporary:
        stage = Path(temporary) / "package"
        shutil.copytree(source, stage, symlinks=True)
        if artifact_hashes(stage) != manifest["artifacts"]:
            raise PackageError("package changed during materialization")
        rewrite_paths(stage, source, target)
        corpora = selected_corpora(args)
        update_ftw_ports(stage, corpora, args.port)
        case_ids(stage, corpora, args)
        (stage / "materialization.json").write_text(
            json.dumps(
                {
                    "source_manifest_sha256": digest(
                        checked_artifact(source / MANIFEST_FILE, source)
                    ),
                    "port": args.port,
                    "status": "materialized",
                    "artifacts": artifact_hashes(stage),
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        publish(stage, target)
    return target


def validate_roots(args: argparse.Namespace) -> None:
    for name in ("framework", "mrts", "connector"):
        setattr(
            args,
            name + "_root",
            checked_source_directory(getattr(args, name + "_root")),
        )
    if args.framework_root != FRAMEWORK_ROOT:
        raise PackageError("Framework root must match the executing checkout")
    args.build_root = approved_runtime_root(args.build_root, "build root")
    for source in (args.framework_root, args.mrts_root, args.connector_root):
        if (
            args.build_root == source
            or args.build_root.is_relative_to(source)
            or source.is_relative_to(args.build_root)
        ):
            raise PackageError("build root must be separate from source checkouts")


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
        validate_roots(args)
        args.upstream_definitions = (
            args.upstream_definitions or args.mrts_root / "config_tests"
        )
        args.feature_demo_definitions = (
            args.feature_demo_definitions
            or args.mrts_root / "feature_demo/config_tests"
        )
        if args.action == "prepare":
            result = prepare(args)
        elif args.action == "verify":
            verify(args)
            result = args.package_root
        else:
            if (
                args.output_root is None
                or args.port is None
                or not 1 <= args.port <= 65535
            ):
                raise PackageError(
                    "materialize requires an output root and a valid port"
                )
            result = materialize(args)
        print(result)
        return 0
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        yaml.YAMLError,
        subprocess.SubprocessError,
    ) as error:
        print(f"BLOCKED: MRTS package {args.action}: {error}", file=sys.stderr)
        return 77


if __name__ == "__main__":
    raise SystemExit(main())
