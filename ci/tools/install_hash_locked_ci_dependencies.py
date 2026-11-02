#!/usr/bin/env python3
"""Install the reviewed wheel, or build verified PyYAML source in a disposable venv.

Only input downloads use the network. The source backend receives no inherited
credentials, build tools stay outside the target environment, and all pip build
and installation steps disable dependency resolution and index access.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
from urllib import request
from urllib.parse import urlsplit
import zipfile

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "installer_canonical_pins", ROOT / "ci/tools/sync-canonical-python-pins.py"
)
assert SPEC is not None and SPEC.loader is not None
PINS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PINS)
MAX_ARTIFACT_BYTES = 32 * 1024 * 1024
BUILD_LOCK = ROOT / "ci/pyyaml-build-tools.lock.json"


class InstallError(ValueError):
    """A provenance or build contract failed before target installation."""


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise InstallError("artifact redirects are forbidden")


def artifact_name(url: str) -> str:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.netloc != "files.pythonhosted.org"
        or parsed.query
        or parsed.fragment
        or not re.fullmatch(r"/packages/[a-f0-9/]+/[A-Za-z0-9_.-]+", parsed.path)
    ):
        raise InstallError("artifact URL must identify an official PyPI file")
    return parsed.path.rsplit("/", 1)[-1]


def download_verified(url: str, digest: str, directory: Path) -> Path:
    name = artifact_name(url)
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise InstallError("artifact digest is malformed")
    opener = request.build_opener(NoRedirect())
    with opener.open(url, timeout=30) as response:
        if response.status != 200 or response.geturl() != url:
            raise InstallError("artifact response identity changed")
        data = response.read(MAX_ARTIFACT_BYTES + 1)
    if len(data) > MAX_ARTIFACT_BYTES:
        raise InstallError("artifact exceeds size limit")
    if hashlib.sha256(data).hexdigest() != digest:
        raise InstallError("artifact SHA-256 mismatch")
    destination = directory / name
    destination.write_bytes(data)
    return destination


def clean_environment(work: Path) -> dict[str, str]:
    """Allowlist build state; never pass tokens, proxy credentials or pip config."""
    environment = {
        "PATH": os.defpath,
        "HOME": str(work),
        "TMPDIR": str(work),
        "PYTHONNOUSERSITE": "1",
        "PYTHONSAFEPATH": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PIP_CONFIG_FILE": os.devnull,
        "PIP_NO_INDEX": "1",
        "PIP_NO_CACHE_DIR": "1",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_INPUT": "1",
        "PYYAML_FORCE_LIBYAML": "0",
        "SOURCE_DATE_EPOCH": "0",
    }
    return environment


def require_runtime_environment() -> None:
    """Admit a venv or the setup-python runtime selected by GitHub Actions.

    This prevents accidental local system/user installation. Actions environment
    values describe its existing runtime contract, not a hostile-env boundary.
    Only build tools are unconditionally isolated in a disposable venv.
    """
    if sys.prefix != sys.base_prefix:
        return
    location = os.environ.get("pythonLocation")
    if os.environ.get("GITHUB_ACTIONS") == "true" and location:
        prefix = Path(sys.prefix).resolve(strict=True)
        selected = Path(location).resolve(strict=True)
        executable = Path(sys.executable).resolve(strict=True)
        if selected == prefix and executable.is_relative_to(prefix):
            return
    raise InstallError(
        "runtime must be a venv or the verified Actions setup-python prefix"
    )


def run(command: list[str], work: Path, environment: dict[str, str]) -> None:
    subprocess.run(command, cwd=work, env=environment, check=True)


def extract_source(archive: Path, destination: Path) -> Path:
    """Extract bounded regular files/directories, rejecting links and traversal."""
    with tarfile.open(archive, "r:gz") as stream:
        members = stream.getmembers()
        if len(members) > 10_000 or sum(m.size for m in members) > 64 * 1024 * 1024:
            raise InstallError("source archive exceeds extraction limits")
        for member in members:
            path = Path(member.name)
            if (
                path.is_absolute()
                or ".." in path.parts
                or not path.parts
                or path.parts[0] != archive.name.removesuffix(".tar.gz")
                or not (member.isfile() or member.isdir())
            ):
                raise InstallError("source archive contains an unsafe member")
        stream.extractall(destination, members=members, filter="data")
    return destination / archive.name.removesuffix(".tar.gz")


def validated_build_lock(values: dict[str, str]) -> tuple[str, list[dict[str, str]]]:
    document = json.loads(PINS.read_utf8(BUILD_LOCK, ROOT, "build-tool lock"))
    if (
        set(document) != {"schema_version", "source_url", "wheels"}
        or document["schema_version"] != 1
    ):
        raise InstallError("unsupported build-tool lock")
    source_url = document["source_url"]
    if artifact_name(source_url) != values["CI_CANONICAL_PYYAML_ARTIFACT"]:
        raise InstallError("source URL does not match the canonical artifact")
    wheels = document["wheels"]
    if not isinstance(wheels, list) or len(wheels) != 4:
        raise InstallError("build-tool lock must contain the four reviewed tools")
    names = set()
    for wheel in wheels:
        if not isinstance(wheel, dict) or set(wheel) != {"url", "sha256"}:
            raise InstallError("malformed build-tool wheel")
        name = artifact_name(wheel["url"])
        match = re.fullmatch(
            r"(setuptools|wheel|cython|packaging)-\d+\.\d+(?:\.\d+)?-py3-none-any\.whl",
            name,
            flags=re.ASCII,
        )
        if (
            match is None
            or match[1] in names
            or not re.fullmatch(r"[0-9a-f]{64}", wheel["sha256"])
        ):
            raise InstallError(
                "build tools must be unique exact pure-Python wheels with hashes"
            )
        names.add(match[1])
    return source_url, wheels


def source_install(values: dict[str, str], work: Path) -> None:
    source_url, wheels = validated_build_lock(values)
    inputs = work / "inputs"
    inputs.mkdir()
    source = download_verified(source_url, values["CI_CANONICAL_PYYAML_SHA256"], inputs)
    tool_paths = [
        download_verified(row["url"], row["sha256"], inputs) for row in wheels
    ]
    environment = clean_environment(work)
    builder = work / "builder"
    # venv uses the reviewed interpreter's bundled ensurepip, not an index.
    run([sys.executable, "-I", "-m", "venv", str(builder)], work, environment)
    python = str(builder / "bin/python")
    tool_lock = work / "build-tools.lock"
    tool_lock.write_text(
        "".join(
            f"{path.as_uri()} --hash=sha256:{row['sha256']}\n"
            for path, row in zip(tool_paths, wheels, strict=True)
        )
    )
    run(
        [
            python,
            "-I",
            "-m",
            "pip",
            "install",
            "--no-index",
            "--no-deps",
            "--only-binary=:all:",
            "--require-hashes",
            "-r",
            str(tool_lock),
        ],
        work,
        environment,
    )
    run([python, "-I", "-m", "pip", "check"], work, environment)
    source_root = extract_source(source, work)
    output = work / "wheels"
    output.mkdir()
    # Invoke the official PEP 517 backend directly; no implicit isolation or downloads.
    code = (
        "import sys; sys.path.insert(0, 'packaging'); "
        "import _pyyaml_pep517; _pyyaml_pep517.build_wheel(sys.argv[1])"
    )
    run([python, "-I", "-c", code, str(output)], source_root, environment)
    built = list(output.iterdir())
    expected = f"pyyaml-{values['CI_CANONICAL_PYYAML_VERSION']}-py3-none-any.whl"
    if len(built) != 1 or built[0].name != expected or not built[0].is_file():
        raise InstallError("backend did not produce the expected pure Python wheel")
    with zipfile.ZipFile(built[0]) as archive:
        if any(name.endswith((".so", ".pyd", ".dll")) for name in archive.namelist()):
            raise InstallError("pure Python wheel contains a native library")
    digest = hashlib.sha256(built[0].read_bytes()).hexdigest()
    runtime_lock = work / "built-runtime.lock"
    runtime_lock.write_text(f"{built[0].as_uri()} --hash=sha256:{digest}\n")
    print(
        f"verified source {source.name}; built {expected}; SHA-256 {digest}", flush=True
    )
    run(
        [
            sys.executable,
            "-I",
            "-m",
            "pip",
            "install",
            "--no-index",
            "--no-deps",
            "--require-hashes",
            "-r",
            str(runtime_lock),
        ],
        work,
        environment,
    )
    run([sys.executable, "-I", "-m", "pip", "check"], work, environment)


def trusted_source_directory_component(path: Path, selected: bool) -> None:
    """Reject ancestry that another user can replace or redirect."""
    details = path.lstat()
    if not stat.S_ISDIR(details.st_mode) or details.st_uid not in (0, os.getuid()):
        raise InstallError(
            "source build ancestry must contain trusted non-symlink directories"
        )
    writable = details.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    protected_shared_ancestor = (
        not selected and details.st_uid == 0 and details.st_mode & stat.S_ISVTX
    )
    if selected and (details.st_uid != os.getuid() or writable):
        raise InstallError(
            "source build temporary root must be user-owned without shared write access"
        )
    if writable and not protected_shared_ancestor:
        raise InstallError("source build ancestry must not be adversary-writable")


def require_source_temporary_root() -> Path:
    """Require an external, user-owned build base without shared write access."""
    temporary_root = os.environ.get("RUNNER_TEMP")
    if not temporary_root or not Path(temporary_root).is_absolute():
        raise InstallError("source builds require an explicit external RUNNER_TEMP")
    candidate = Path(temporary_root)
    if ".." in candidate.parts or candidate == Path(candidate.anchor):
        raise InstallError(
            "source build temporary root must be an existing external directory"
        )
    PINS.reject_symlink_components(candidate, "source build temporary root")
    for component in (*reversed(candidate.parents), candidate):
        trusted_source_directory_component(component, component == candidate)
    selected = candidate.resolve(strict=True)
    if selected == ROOT or ROOT in selected.parents:
        raise InstallError("source build temporary root must be outside the checkout")
    return selected


def main() -> int:
    if len(sys.argv) != 1:
        raise InstallError("no arguments are accepted")
    values = PINS.canonical_values(ROOT / "ci/lib/common.sh", ROOT)
    for path, expected in PINS.expected_views(ROOT, values).items():
        if PINS.read_bytes(path, ROOT, "generated pin view") != expected:
            raise InstallError("generated Python pins are out of sync")
    require_runtime_environment()
    if values["CI_CANONICAL_PYYAML_ARTIFACT"].endswith(".whl"):
        subprocess.run(
            [
                sys.executable,
                "-I",
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--no-input",
                "--only-binary=:all:",
                "--require-hashes",
                "-r",
                str(ROOT / "requirements-ci.lock"),
            ],
            check=True,
        )
        subprocess.run([sys.executable, "-I", "-m", "pip", "check"], check=True)
    else:
        if not re.fullmatch(
            r"3\.15\.(0|[1-9]\d*)",
            values["CI_CANONICAL_PYTHON_VERSION"],
            flags=re.ASCII,
        ) or sys.version_info[:2] != (3, 15):
            raise InstallError("source builds are reviewed only for CPython 3.15")
        selected = require_source_temporary_root()
        with tempfile.TemporaryDirectory(
            prefix="pyyaml-build-", dir=selected
        ) as temporary:
            source_install(values, Path(temporary))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        OSError,
        ValueError,
        subprocess.CalledProcessError,
        tarfile.TarError,
        zipfile.BadZipFile,
    ) as exc:
        print(f"CI dependency installation: {exc}", file=sys.stderr)
        raise SystemExit(2)
