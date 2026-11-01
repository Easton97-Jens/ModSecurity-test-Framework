"""Producer-owned pre-execution source mapping with real include-context proof."""

import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import stat
import uuid


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def verify_trusted_directory(path):
    """Require canonical root/euid ancestry without shared write access.

    Root-owned sticky temporary ancestors are permitted; the task leaf itself
    is created privately by the caller. No existing permissions are changed.
    """
    path = Path(path)
    if not path.is_absolute() or path.resolve(strict=True) != path or not path.is_dir():
        raise ValueError("external directory must be canonical and already exist")
    for directory in (path, *path.parents):
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, os.geteuid()}:
            raise ValueError("external directory ancestor is not root/current-user owned")
        if info.st_mode & 0o022 and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX):
            raise ValueError("external directory ancestor permits untrusted shared writes")


def absolute(value, cwd):
    return (cwd / value).resolve() if not Path(value).is_absolute() else Path(value).resolve()


def verify_manifest(manifest):
    checkout = Path(manifest["checkout"])
    copied_root = Path(manifest["copy_root"])
    producer = Path(manifest["producer"]["path"])
    if (manifest["schema"] != 1 or not checkout.is_absolute() or not copied_root.is_absolute()
            or copied_root.is_relative_to(checkout) or checkout.is_relative_to(copied_root)
            or not producer.is_relative_to(checkout)
            or digest(producer) != manifest["producer"]["sha256"]):
        raise ValueError("copied-source mapping producer identity is invalid")
    verify_manifest_files(manifest, checkout, copied_root)
    verify_manifest_include_directories(manifest, checkout)


def verify_manifest_files(manifest, checkout, copied_root):
    for copied, identity in manifest["files"].items():
        source, original = Path(copied), Path(identity["original"])
        if (source.resolve(strict=True) != source or original.resolve(strict=True) != original
                or not source.is_relative_to(copied_root) or not original.is_relative_to(checkout)
                or digest(source) != identity["sha256"] or digest(original) != identity["sha256"]):
            raise ValueError("copied source/header identity mismatch")
    for name, expected in manifest["context_files"].items():
        if not Path(name).is_absolute() or digest(name) != expected:
            raise ValueError("copied-source native archive/configure context changed")


def verify_manifest_include_directories(manifest, checkout):
    for field in ("original_include_directories", "original_quote_directories"):
        for name in manifest.get(field, []):
            path = Path(name)
            if path.resolve(strict=True) != path or not path.is_dir() or not path.is_relative_to(checkout):
                raise ValueError("source mapping include directory is not an original checkout directory")


def mapped_arguments(arguments, index, original, copied, manifest):
    mapped = list(arguments)
    mapped[index] = str(original)
    prefix = []
    for field, flag in (("original_include_directories", "-I"), ("original_quote_directories", "-iquote")):
        for directory in manifest.get(field, []):
            prefix += [flag, directory]
    return [*prefix, *mapped, "-iquote", str(copied.parent)]


def verify_dependency_context(copied_dependencies, original_dependencies, manifest):
    verify_manifest(manifest)
    mapped = [manifest["files"].get(str(path), {"original": str(path)})["original"]
              for path in copied_dependencies]
    if mapped != [str(path) for path in original_dependencies]:
        raise ValueError("copied/original ordered include context differs")
    for copied, original in zip(copied_dependencies, original_dependencies):
        if digest(copied) != digest(original):
            raise ValueError("copied/original dependency content differs")


def dependency_paths(path, cwd):
    _, separator, values = path.read_text().replace("\\\n", " ").partition(":")
    if not separator:
        raise ValueError("source-map compiler dependency pass has no target")
    return [absolute(value, cwd) for value in shlex.split(values)]


def dependency_arguments(arguments, destination):
    result = []
    index = 0
    paired = {"-o", "-MF", "-MT", "-MQ"}
    discarded = {"-c", "-MD", "-MMD", "-MP", "-M", "-MM", "-MG"}
    while index < len(arguments):
        argument = arguments[index]
        if argument in paired:
            index += 2
            continue
        if argument in discarded or any(argument.startswith(flag) and argument != flag for flag in paired):
            index += 1
            continue
        result.append(argument)
        index += 1
    return [*result, "-M", "-MF", str(destination), "-MT", "sonar_mapping_context"]


def prepare(compiler, arguments, cwd, capture_root, manifest_path):
    manifest = json.loads(manifest_path.read_text())
    candidates = [(index, absolute(argument, cwd)) for index, argument in enumerate(arguments)
                  if not argument.startswith("-") and Path(argument).suffix in {".c", ".cc", ".cpp", ".cxx", ".C"}
                  and str(absolute(argument, cwd)) in manifest["files"]]
    if not candidates:
        return arguments, None
    if len(candidates) != 1 or "-c" not in arguments:
        raise ValueError("copied-source producer must compile one mapped translation unit at a time")
    verify_manifest(manifest)
    index, copied = candidates[0]
    original = Path(manifest["files"][str(copied)]["original"])
    mapped = mapped_arguments(arguments, index, original, copied, manifest)
    directory = capture_root / "source-map-preflight" / uuid.uuid4().hex
    directory.mkdir(parents=True, mode=0o700)
    commands, dependencies = [], []
    for name, selected in (("copied", arguments), ("original", mapped)):
        destination = directory / (name + ".d")
        command = [compiler, *dependency_arguments(selected, destination)]
        with (directory / (name + ".log")).open("x") as log:
            subprocess.run(command, cwd=cwd, stdout=log, stderr=subprocess.STDOUT, check=True)
        commands.append(command)
        dependencies.append(dependency_paths(destination, cwd))
    verify_dependency_context(dependencies[0], dependencies[1], manifest)
    path_macro_sources = [str(path) for path in dependencies[1]
                          if Path(path).is_relative_to(Path(manifest["checkout"]))
                          and re.search(rb"\b__(?:FILE|BASE_FILE|TIMESTAMP)__\b", Path(path).read_bytes())]
    receipt = {"manifest": str(manifest_path), "manifest_sha256": digest(manifest_path),
               "copied_source": str(copied), "original_source": str(original),
               "source_sha256": digest(original), "original_producer_arguments": [compiler, *arguments],
               "dependency_commands": commands,
               "copied_dependencies": {str(path): digest(path) for path in dependencies[0]},
               "original_dependencies": {str(path): digest(path) for path in dependencies[1]},
               "ordered_copied_dependencies": [str(path) for path in dependencies[0]],
               "ordered_original_dependencies": [str(path) for path in dependencies[1]],
               "path_macro_sources": path_macro_sources,
               "limitation": "Actual original-operand compile; source/debug/diagnostic path strings may differ; no general binary parity claim."}
    (directory / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return mapped, receipt
