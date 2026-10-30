#!/usr/bin/env python3
"""Build only the reviewed pure-Python PyYAML source exception, then install it.

All archives are verified before backend execution. Build tools remain in a
fresh external virtual environment; the selected target receives only PyYAML.
"""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import argparse
from email.parser import BytesParser
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import NamedTuple
from urllib.parse import urlsplit
from urllib.request import urlopen
import venv
import zipfile

ROOT = connector_root()
FRAMEWORK_LOCK = Path("modules/ModSecurity-test-Framework/requirements-ci.lock")
PIP_INSTALL = ["install", "--no-index", "--no-deps", "--only-binary=:all:",
               "--require-hashes", "--no-input", "--disable-pip-version-check"]


class Artifact(NamedTuple):
    name: str
    url: str
    sha256: str

    @property
    def filename(self) -> str:
        return Path(urlsplit(self.url).path).name


def locked_artifacts(path: Path) -> list[Artifact]:
    text = path.read_text(encoding="ascii").replace("\\\n", "")
    result = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"(PyYAML|pip|setuptools|Cython) @ "
                             r"(https://files\.pythonhosted\.org/packages/[\w/.-]+)"
                             r"\s+--hash=sha256:([a-f0-9]{64})", line)
        if match is None:
            raise ValueError("CI artifact lock must contain exact official URLs and SHA-256")
        result.append(Artifact(*match.groups()))
    return result


def framework_contract(path: Path, version: str) -> None:
    if path != FRAMEWORK_LOCK:
        raise ValueError("only the existing Framework CI lock may be validated")
    selected = source_path(path, root=ROOT)
    observed = selected.lstat()
    if not stat.S_ISREG(observed.st_mode) or observed.st_size > 16384:
        raise ValueError("Framework CI lock must be a bounded regular file")
    descriptor = os.open(selected, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "r", encoding="ascii") as source:
        actual = os.fstat(source.fileno())
        if (actual.st_dev, actual.st_ino) != (observed.st_dev, observed.st_ino):
            raise ValueError("Framework CI lock changed during validation")
        text = source.read(16385).replace("\\\n", "")
    lines = [line.strip() for line in text.splitlines()
             if line.strip() and not line.lstrip().startswith("#")]
    expression = r"PyYAML==" + re.escape(version) + r"(?:\s+--hash=sha256:[a-f0-9]{64})+"
    if len(lines) != 1 or re.fullmatch(expression, lines[0]) is None:
        raise ValueError("Framework CI lock differs from the single reviewed PyYAML version")


def trusted_directory_component(path: Path, selected: bool) -> None:
    observed = path.lstat()
    if not stat.S_ISDIR(observed.st_mode) or observed.st_uid not in (0, os.geteuid()):
        raise ValueError("CI dependency build ancestry must contain trusted non-symlink directories")
    writable = observed.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    protected_public_ancestor = (not selected and observed.st_uid == 0 and
                                 observed.st_mode & stat.S_ISVTX)
    if writable and not protected_public_ancestor:
        raise ValueError("CI dependency build ancestry must not be adversary-writable")
    if selected and observed.st_uid != os.geteuid():
        raise ValueError("CI dependency build root must belong to the selected user")


def external_directory(path: Path) -> Path:
    if not path.is_absolute() or ".." in path.parts or path == Path(path.anchor):
        raise ValueError("CI dependency build root must be an existing external directory")
    for component in [*reversed(path.parents), path]:
        trusted_directory_component(component, component == path)
    resolved = path.resolve(strict=True)
    if resolved == ROOT or ROOT in resolved.parents:
        raise ValueError("CI dependency build root must be an existing external directory")
    return resolved


def selected_version(ci_toolcache: bool, expected_version: str | None) -> str:
    canonical = (source_path('.python-version', root=ROOT)).read_text(encoding="ascii").strip()
    if expected_version is None:
        return canonical
    if not ci_toolcache or re.fullmatch(r"\d+\.\d+\.\d+", expected_version) is None:
        raise ValueError("an exact Python patch candidate requires the explicit CI toolcache mode")
    baseline = tuple(map(int, canonical.split(".")))
    candidate = tuple(map(int, expected_version.split(".")))
    if candidate[:2] != baseline[:2] or candidate < baseline:
        raise ValueError("Python candidate must stay in the canonical minor without a downgrade")
    return expected_version


def validate_toolcache() -> None:
    runner = os.environ.get("RUNNER_TEMP")
    location = os.environ.get("pythonLocation")
    if os.environ.get("GITHUB_ACTIONS") != "true" or not runner or not location:
        raise ValueError("toolcache installation requires the selected GitHub Actions environment")
    external_directory(Path(runner))
    selected = Path(location).resolve(strict=True)
    executable = Path(sys.executable).resolve(strict=True)
    if (not Path(location).is_absolute() or not selected.is_dir() or
            Path(sys.prefix).resolve(strict=True) != selected or
            Path(sys.base_prefix).resolve(strict=True) != selected or
            not executable.is_relative_to(selected / "bin") or not executable.is_file() or
            not os.access(executable, os.X_OK)):
        raise ValueError("CI toolcache identity differs from the selected setup-python interpreter")


def validate_target(ci_toolcache: bool, build_root: Path,
                    expected_version: str | None = None) -> Path:
    expected = selected_version(ci_toolcache, expected_version)
    actual = ".".join(map(str, sys.version_info[:3]))
    if actual != expected:
        raise ValueError("selected interpreter does not match the selected exact Python version")
    if ci_toolcache:
        validate_toolcache()
    elif sys.prefix == sys.base_prefix:
        raise ValueError("local CI dependencies require an explicitly selected virtual environment")
    return external_directory(build_root)


def download_verified(artifact: Artifact, destination: Path) -> None:
    with urlopen(artifact.url, timeout=60) as response:
        if response.geturl() != artifact.url:
            raise ValueError("CI artifact redirected outside its locked URL")
        data = response.read(16 * 1024 * 1024 + 1)
    if len(data) > 16 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != artifact.sha256:
        raise ValueError("CI artifact SHA-256 mismatch or oversized download")
    with destination.open("xb") as output:
        output.write(data)


def extract_source(archive: Path, destination: Path, directory: str) -> Path:
    with tarfile.open(archive, "r:gz") as source:
        members = source.getmembers()
        if len(members) > 4096 or sum(item.size for item in members) > 64 * 1024 * 1024:
            raise ValueError("PyYAML source archive exceeds its bounded build scope")
        for member in members:
            parts = Path(member.name).parts
            if (not parts or parts[0] != directory or ".." in parts or
                    not (member.isfile() or member.isdir())):
                raise ValueError("PyYAML source archive contains an unsafe member")
        source.extractall(destination, members=members, filter="data")
    return destination / directory


def pure_wheel(path: Path, version: str) -> None:
    if path.name != f"pyyaml-{version}-py3-none-any.whl":
        raise ValueError("PyYAML build did not produce the expected pure-Python wheel")
    with zipfile.ZipFile(path) as wheel:
        names = wheel.namelist()
        if (len(names) != len(set(names)) or
                any(Path(name).is_absolute() or ".." in Path(name).parts or "\\" in name
                    for name in names)):
            raise ValueError("PyYAML wheel contains ambiguous or unsafe paths")
        if any(name.endswith((".so", ".pyd", ".dll", ".dylib")) for name in names):
            raise ValueError("PyYAML pure-Python wheel contains a native extension")
        tags = BytesParser().parsebytes(wheel.read(f"pyyaml-{version}.dist-info/WHEEL"))
        if tags.get_all("Root-Is-Purelib") != ["true"] or tags.get_all("Tag") != ["py3-none-any"]:
            raise ValueError("PyYAML wheel metadata is not exclusively pure Python")
        metadata = BytesParser().parsebytes(wheel.read(f"pyyaml-{version}.dist-info/METADATA"))
        if (metadata["Name"] != "PyYAML" or metadata["Version"] != version or
                metadata.get_all("Requires-Dist")):
            raise ValueError("PyYAML wheel identity or dependency contract changed")


def child_environment(work: Path, ci_toolcache: bool = False) -> dict[str, str]:
    retained = ("PATH", "SYSTEMROOT", "LD_LIBRARY_PATH")
    environment = {key: os.environ[key] for key in retained if key in os.environ}
    environment.update(PYTHONNOUSERSITE="1", PYTHONDONTWRITEBYTECODE="1",
                       PIP_CONFIG_FILE=os.devnull, PIP_NO_INDEX="1",
                       PIP_DISABLE_PIP_VERSION_CHECK="1",
                       PIP_REQUIRE_VIRTUALENV="false" if ci_toolcache else "true",
                       PIP_CACHE_DIR=str(work / "cache"), TMPDIR=str(work),
                       PYYAML_FORCE_LIBYAML="0", SOURCE_DATE_EPOCH="315532800",
                       PYTHONHASHSEED="0")
    return environment


def run_stage(name: str, arguments: list[str], work: Path,
              environment: dict[str, str], cwd: Path | None = None) -> None:
    log = work / (name + ".log")
    with log.open("w", encoding="utf-8") as output:
        result = subprocess.run(arguments, cwd=cwd, env=environment, stdout=output,
                                stderr=subprocess.STDOUT, timeout=300, check=False)
    if result.returncode:
        raise RuntimeError(f"CI dependency stage {name} failed; log: {log}")


def local_lock(path: Path, artifacts: list[Artifact], work: Path) -> None:
    lines = [f"{work / item.filename} --hash=sha256:{item.sha256}" for item in artifacts]
    path.write_text("\n".join(lines) + "\n", encoding="ascii")


def reviewed_pins(framework_lock: Path | None) -> tuple[Artifact, list[Artifact], str]:
    source_pins = locked_artifacts(source_path('requirements-ci.lock', root=ROOT))
    tools = locked_artifacts(source_path('requirements-ci-build.lock', root=ROOT))
    if ([item.name for item in source_pins] != ["PyYAML"] or
            sorted(item.name for item in tools) != ["Cython", "pip", "setuptools"] or
            not all(item.filename.endswith("-py3-none-any.whl") for item in tools)):
        raise ValueError("CI build accepts only the reviewed source and universal build tools")
    source_pin = source_pins[0]
    version = source_pin.filename.removeprefix("pyyaml-").removesuffix(".tar.gz")
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("CI build requires the exact PyYAML source release")
    if framework_lock is not None:
        framework_contract(framework_lock, version)
    return source_pin, tools, version


def prepare_builder(work: Path, tools: list[Artifact], environment: dict[str, str]) -> Path:
    builder = work / "builder"
    venv.EnvBuilder(with_pip=False).create(builder)
    builder_python = builder / "bin/python"
    build_lock = work / "build-tools.lock"
    local_lock(build_lock, tools, work)
    run_stage("install-build-tools", [sys.executable, "-m", "pip", "--python",
              str(builder_python), *PIP_INSTALL, "-r", str(build_lock)], work, environment)
    return builder_python


def build_pure_wheel(work: Path, source_pin: Artifact, version: str,
                     builder_python: Path, environment: dict[str, str]) -> Path:
    source = extract_source(work / source_pin.filename, work, "pyyaml-" + version)
    output = work / "wheel"
    output.mkdir()
    backend = ("import sys; sys.path.insert(0, 'packaging'); import _pyyaml_pep517; "
               "_pyyaml_pep517.build_wheel(sys.argv[1], "
               "config_settings={'--global-option': ['--no-user-cfg']})")
    run_stage("build-pyyaml", [str(builder_python), "-c", backend, str(output)],
              work, environment, cwd=source)
    wheels = list(output.glob("*.whl"))
    if len(wheels) != 1:
        raise ValueError("PyYAML build must produce exactly one wheel")
    pure_wheel(wheels[0], version)
    return wheels[0]


def install_verified_wheel(work: Path, builder_python: Path, wheel: Path,
                           ci_toolcache: bool) -> str:
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    install_lock = work / "install.lock"
    install_lock.write_text(f"{wheel} --hash=sha256:{digest}\n", encoding="ascii")
    run_stage("install-pyyaml", [str(builder_python), "-m", "pip", "--python",
              sys.executable, *PIP_INSTALL, "-r", str(install_lock)], work,
              child_environment(work, ci_toolcache))
    return digest


def install(build_root: Path, ci_toolcache: bool, framework_lock: Path | None,
            expected_version: str | None = None) -> Path:
    build_root = validate_target(ci_toolcache, build_root, expected_version)
    source_pin, tools, version = reviewed_pins(framework_lock)
    work = Path(tempfile.mkdtemp(prefix="ci-dependency-build-", dir=build_root))
    for artifact in [source_pin, *tools]:
        download_verified(artifact, work / artifact.filename)
    environment = child_environment(work)
    builder_python = prepare_builder(work, tools, environment)
    wheel = build_pure_wheel(work, source_pin, version, builder_python, environment)
    digest = install_verified_wheel(work, builder_python, wheel, ci_toolcache)
    receipt = work / "receipt.json"
    receipt.write_text(json.dumps({"python": sys.version.split()[0],
        "target": sys.executable, "source_sha256": source_pin.sha256,
        "build_tools": {item.name: item.sha256 for item in tools},
        "input_sha256": {name: hashlib.sha256(source_path(name, root=ROOT).read_bytes()).hexdigest()
                         for name in (".python-version", "requirements-ci.lock",
                                      "requirements-ci-build.lock", "ci/tools/install-ci-dependencies.py")},
        "wheel_sha256": digest, "wheel": str(wheel),
        "libyaml_extension": False}, indent=2) + "\n", encoding="utf-8")
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ci-toolcache", action="store_true")
    parser.add_argument("--build-root", type=Path,
                        default=os.environ.get("RUNNER_TEMP"))
    parser.add_argument("--framework-lock", type=Path)
    parser.add_argument("--expected-version", help="explicit same-minor CI patch candidate")
    args = parser.parse_args()
    if args.build_root is None:
        parser.error("--build-root or RUNNER_TEMP must select an external build directory")
    try:
        receipt = install(args.build_root, args.ci_toolcache, args.framework_lock,
                          args.expected_version)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        parser.exit(1, f"CI dependency install failed: {error}\n")
    print(f"CI dependency install passed; receipt: {receipt}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
