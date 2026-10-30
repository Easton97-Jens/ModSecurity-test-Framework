"""Verify a committed Connector/Framework combination using private local clones.

The default Framework revision is the authenticated gitlink in the selected
Connector commit. An explicit development override is always reported separately.
No submodule is fetched and no MRTS feature or host service is executed.
"""

from __future__ import annotations

import argparse
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile


_MRTS_GITLINK_PATH = 'tools/MRTS'
_CASE_ID_SUFFIX = '.case'
_GIT_STATUS_PORCELAIN_ARG = '--porcelain=v1'
_GIT_STATUS_UNTRACKED_ARG = '--untracked-files=all'
_GIT_STATUS_SUBMODULE_ARG = '--ignore-submodules=none'


GITLINK = "modules/ModSecurity-test-Framework"
EXECUTION = "common.header-valid-length"
MAX_OBJECT = 32 * 1024 * 1024


class IntegrationError(ValueError):
    """The selected committed combination cannot satisfy its integration contract."""


def exact_revision(value: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{40}", value) is None:
        raise IntegrationError(
            "an exact lowercase 40-character commit revision is required"
        )
    return value


def physical_directory(value: Path, *, private: bool = False) -> Path:
    value = Path(value)
    if not value.is_absolute() or ".." in value.parts:
        raise IntegrationError("an explicit physical absolute directory is required")
    for component in (value, *value.parents):
        info = component.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise IntegrationError("directory paths must not contain symlinks")
        if info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX:
            raise IntegrationError(
                "directory ancestors must not permit shared replacement"
            )
    info = value.stat()
    if private and (info.st_uid != os.geteuid() or info.st_mode & 0o077):
        raise IntegrationError(
            "output root must be current-user-owned and private (0700)"
        )
    return value


def git_environment() -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("GIT_") and key not in {"LD_PRELOAD", "LD_LIBRARY_PATH"}
    }
    environment.update(
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_TERMINAL_PROMPT="0",
        GIT_NO_REPLACE_OBJECTS="1",
        GIT_ALLOW_PROTOCOL="file",
        GIT_ATTR_NOSYSTEM="1",
    )
    return environment


def git(root: Path, *arguments: str, data: bytes | None = None) -> bytes:
    command = [
        "git",
        "--no-replace-objects",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "protocol.file.allow=always",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "uploadpack.packObjectsHook=",
        "-C",
        str(root),
        *arguments,
    ]
    try:
        result = subprocess.run(
            command,
            input=data,
            env=git_environment(),
            capture_output=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise IntegrationError(f"local Git operation failed: {error}") from error
    if result.returncode:
        raise IntegrationError(
            f"local Git {' '.join(arguments[:2])} failed: "
            + result.stderr.decode(errors="replace")[:2000]
        )
    return result.stdout


def _object_git_environment() -> dict[str, str]:
    # No inherited Git configuration, loader injection, filters or transport.
    # HOME is deliberately not changed or repurposed.
    return {
        "PATH": "/usr/bin:/bin", "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0",
        "GIT_NO_REPLACE_OBJECTS": "1", "GIT_GRAFT_FILE": os.devnull,
        "GIT_NO_LAZY_FETCH": "1", "GIT_ALLOW_PROTOCOL": "",
        "GIT_ATTR_NOSYSTEM": "1", "GIT_DEFAULT_HASH": "sha1",
    }


@lru_cache(maxsize=1)
def _require_collision_detecting_git() -> None:
    """Require the fixed native Git's collision-detecting SHA-1 implementation."""
    try:
        result = subprocess.run(
            ["/usr/bin/git", "version", "--build-options"],
            cwd="/", env=_object_git_environment(), capture_output=True,
            timeout=15, check=True,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise IntegrationError("native Git SHA1_DC implementation cannot be verified") from error
    if b"SHA-1: SHA1_DC" not in result.stdout.splitlines():
        raise IntegrationError("native Git object authentication requires SHA1_DC")


def git_object_identity(
    kind: str, payload: bytes, *, repository: Path | None = None
) -> str:
    """Authenticate Git protocol bytes with native collision detection, without writes."""
    if kind not in ("commit", "tree", "blob") or not isinstance(payload, bytes):
        raise IntegrationError("native object authentication requires a fixed Git type and bytes")
    _require_collision_detecting_git()
    command = ["/usr/bin/git"]
    if kind == "tree":
        # Git validates tree entries against its repository object format.
        # Commit/blob authentication remains independent of repository config.
        if repository is None:
            raise IntegrationError("native tree authentication requires an explicit repository")
        command += [
            "--no-replace-objects", "-c", "core.hooksPath=/dev/null",
            "-c", "core.fsmonitor=false", "-C", str(repository),
        ]
    command += ["hash-object", "--no-filters", "-t", kind, "--stdin"]
    try:
        result = subprocess.run(
            command,
            input=payload, cwd="/", env=_object_git_environment(),
            capture_output=True, timeout=15, check=True,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise IntegrationError("Git object bytes do not authenticate: native Git rejected the input") from error
    if re.fullmatch(rb"[0-9a-f]{40}\n", result.stdout) is None:
        raise IntegrationError("native Git returned an incompatible object identity")
    return result.stdout[:-1].decode("ascii")


def raw_object(root: Path, identity: str, expected_type: str) -> bytes:
    exact_revision(identity)
    size = git(root, "cat-file", "-s", identity).strip()
    if not size.isdigit() or int(size) > MAX_OBJECT:
        raise IntegrationError("Git object exceeds the bounded integration input size")
    raw = git(root, "cat-file", "--batch", data=(identity + "\n").encode())
    header, separator, body = raw.partition(b"\n")
    fields = header.split()
    if (
        not separator
        or len(fields) != 3
        or fields[0].decode() != identity
        or fields[1].decode() != expected_type
        or not fields[2].isdigit()
    ):
        raise IntegrationError("Git object type or identity is incompatible")
    length = int(fields[2])
    if length > MAX_OBJECT or len(body) != length + 1 or body[-1:] != b"\n":
        raise IntegrationError("Git object framing is invalid")
    payload = body[:-1]
    actual = git_object_identity(expected_type, payload, repository=root)
    if actual != identity:
        raise IntegrationError(
            "Git object bytes do not authenticate to their recorded identity"
        )
    return payload


def tree_entries(payload: bytes) -> list[tuple[str, str, str]]:
    entries, position, names = [], 0, set()
    while position < len(payload):
        end = payload.find(b"\0", position)
        if end < 0 or end + 21 > len(payload):
            raise IntegrationError("Git tree is truncated")
        mode, separator, raw_name = payload[position:end].partition(b" ")
        name = os.fsdecode(raw_name)
        if (
            not separator
            or name in {"", ".", "..", ".git"}
            or "/" in name
            or name in names
            or mode not in {b"40000", b"100644", b"100755", b"120000", b"160000"}
        ):
            raise IntegrationError("Git tree has an unsafe or duplicate entry")
        names.add(name)
        entries.append((mode.decode(), name, payload[end + 1 : end + 21].hex()))
        position = end + 21
    return entries


def authenticated_tree(root: Path, revision: str) -> dict[str, tuple[str, str]]:
    commit = raw_object(root, exact_revision(revision), "commit")
    line = commit.split(b"\n", 1)[0]
    if not re.fullmatch(rb"tree [0-9a-f]{40}", line):
        raise IntegrationError("selected commit has no authenticated root tree")
    files: dict[str, tuple[str, str]] = {}
    pending = [("", line[5:].decode())]
    seen = set()
    trees = 0
    while pending:
        prefix, identity = pending.pop()
        trees += 1
        if trees + len(files) + len(pending) > 100000 or prefix.count("/") > 128:
            raise IntegrationError("Git tree exceeds the bounded integration inventory")
        for mode, name, child in tree_entries(raw_object(root, identity, "tree")):
            path = prefix + name
            if mode == "40000":
                pending.append((path + "/", child))
            else:
                files[path] = (mode, child)
                if mode != "160000" and child not in seen:
                    raw_object(root, child, "blob")
                    seen.add(child)
    return files


def recorded_framework(files: dict[str, tuple[str, str]]) -> str:
    mode, identity = files.get(GITLINK, ("", ""))
    if mode != "160000":
        raise IntegrationError("Connector commit has no Framework gitlink")
    return exact_revision(identity)


def validate_version_lock(
    value: dict, recorded: str, framework_files: dict[str, tuple[str, str]]
) -> dict[str, str]:
    links = {
        name: identity
        for name, (mode, identity) in framework_files.items()
        if mode == "160000"
    }
    if set(links) != {_MRTS_GITLINK_PATH}:
        raise IntegrationError(
            "Framework gitlinks must contain exactly the approved tools/MRTS dependency"
        )
    if not isinstance(value, dict) or value.get("framework_sha") != recorded:
        raise IntegrationError(
            "Parent version-lock framework_sha does not match its recorded Framework gitlink"
        )
    if value.get("mrts_sha") != links[_MRTS_GITLINK_PATH]:
        raise IntegrationError(
            "Parent version-lock mrts_sha does not match the selected Framework MRTS gitlink"
        )
    return {"framework_sha": recorded, "mrts_sha": exact_revision(links[_MRTS_GITLINK_PATH])}


def read_contained(root: Path, relative: str, maximum: int = 16 * 1024 * 1024) -> bytes:
    """Pin every directory and read one bounded single-link regular file without following links."""
    item = Path(relative)
    if (
        item.is_absolute()
        or not item.parts
        or any(part in {"", ".", ".."} for part in relative.split("/"))
    ):
        raise IntegrationError(
            "integration artifact requires a bounded relative filename"
        )
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        if not root.is_absolute() or ".." in root.parts:
            raise IntegrationError("integration artifact root must be absolute")
        for part in (*root.parts[1:], *item.parts[:-1]):
            child = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = child
        source = os.open(
            item.name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            dir_fd=descriptor,
        )
        with os.fdopen(source, "rb") as stream:
            before = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_size > maximum
            ):
                raise IntegrationError(
                    "integration artifact must be a bounded single-link regular file"
                )
            raw = stream.read(maximum + 1)
            after = os.fstat(stream.fileno())

            def identity(info):
                return (
                    info.st_dev,
                    info.st_ino,
                    info.st_size,
                    info.st_mtime_ns,
                    info.st_ctime_ns,
                )

            if len(raw) > maximum or identity(before) != identity(after):
                raise IntegrationError(
                    "integration artifact changed or exceeded its size bound"
                )
            return raw
    except OSError as error:
        raise IntegrationError(
            "integration artifact must have physical directories and a regular file"
        ) from error
    finally:
        os.close(descriptor)


def probe_contract(
    parent: Path, framework: Path, revision: str, selected: str, profile: str
) -> dict:
    inventory_bytes = read_contained(
        framework, "connector_suite/config/testing/active-cases.json"
    )
    mapping_bytes = read_contained(framework, "connector_suite/source-map.json")
    inventory, mapping = json.loads(inventory_bytes), json.loads(mapping_bytes)
    probes = [row for row in inventory["executions"] if row["id"] == EXECUTION]
    if (
        len(probes) != 1
        or probes[0]["selector"]
        != {
            "kind": "native",
            "script": "ci/checks/common/run-active-header-case.sh",
            "args": ["valid-length"],
        }
        or [case["id"] for case in probes[0]["cases"]] != [EXECUTION + _CASE_ID_SUFFIX]
    ):
        raise IntegrationError(
            "the committed default inventory does not admit the exact Common probe"
        )
    product = {
        name: hashlib.sha256(
            read_contained(parent, mapping["connector_paths"].get(name, name))
        ).hexdigest()
        for name in inventory["connector_source_paths"]
    }
    return {
        "schema_version": 1,
        "connector_root": str(parent),
        "test_root": str(framework),
        "active_case_count": 100,
        "hard_limit": 100,
        "connector_revision": revision,
        "framework_revision": selected,
        "profile": profile,
        "inventory_sha256": hashlib.sha256(inventory_bytes).hexdigest(),
        "source_map_sha256": hashlib.sha256(mapping_bytes).hexdigest(),
        "selected_execution_ids": [EXECUTION],
        "selected_case_ids": [EXECUTION + _CASE_ID_SUFFIX],
        "selected_core_case_ids": [EXECUTION + _CASE_ID_SUFFIX],
        "selected_offline_exception_case_ids": [],
        "connector_source_bindings": product,
        "connector_source_bindings_sha256": hashlib.sha256(
            json.dumps(product, sort_keys=True).encode()
        ).hexdigest(),
        "connector_worktree_dirty": False,
    }


def validated_probe_results(output: Path, expected: dict) -> list[dict]:
    # Do not glob through directories: every discovered candidate is validated,
    # and read_contained pins all of its components with O_NOFOLLOW.
    candidates = []
    with os.scandir(output) as entries:
        for number, entry in enumerate(entries):
            if number > 1000:
                raise IntegrationError("integration output contains too many entries")
            if entry.name.startswith("active-tests-"):
                if (
                    not entry.is_dir(follow_symlinks=False)
                    or re.fullmatch(r"active-tests-[A-Za-z0-9_.-]+", entry.name) is None
                ):
                    raise IntegrationError("engine summary directory must be physical")
                candidates.append(entry.name)
    if len(candidates) != 1:
        raise IntegrationError(
            "integration requires exactly one engine execution summary"
        )
    relative = candidates[0] + "/summary.json"
    summary = json.loads(read_contained(output, relative))
    if not isinstance(summary, dict) or any(
        summary.get(key) != value for key, value in expected.items()
    ):
        raise IntegrationError(
            "engine summary belongs to another root, revision, source binding or selection"
        )
    if summary.get("output_directory") != str(output / candidates[0]):
        raise IntegrationError("engine summary belongs to another output directory")
    observed = summary.get("results")
    if (
        not isinstance(observed, list)
        or len(observed) != 1
        or not isinstance(observed[0], dict)
        or observed[0].get("execution_id") != EXECUTION
        or observed[0].get("status") != "passed"
        or observed[0].get("case_ids") != [EXECUTION + _CASE_ID_SUFFIX]
    ):
        raise IntegrationError(
            "actual Parent Make did not retain the exact successful standard execution"
        )
    if observed[0].get("log") != EXECUTION + ".log":
        raise IntegrationError("engine summary does not retain its exact execution log")
    read_contained(output, candidates[0] + "/" + observed[0]["log"])
    return observed


def clean_checkout(root: Path, revision: str) -> None:
    if Path(os.fsdecode(git(root, "rev-parse", "--show-toplevel")).strip()) != root:
        raise IntegrationError(
            "checkout Git root does not match its selected directory"
        )
    if git(root, "rev-parse", "HEAD").decode().strip() != revision:
        raise IntegrationError("checkout HEAD does not match the selected commit")
    if git(
        root,
        "status",
        _GIT_STATUS_PORCELAIN_ARG,
        _GIT_STATUS_UNTRACKED_ARG,
        _GIT_STATUS_SUBMODULE_ARG,
    ):
        raise IntegrationError("integration checkout is dirty")


def clone(source: Path, destination: Path, revision: str) -> dict[str, tuple[str, str]]:
    # File-only transport copies Git objects; never copy source worktree contents,
    # source hooks, alternates, replacement refs or untracked migration files.
    git(
        source,
        "clone",
        "--no-local",
        "--no-hardlinks",
        "--no-checkout",
        "--",
        str(source),
        str(destination),
    )
    files = authenticated_tree(destination, revision)
    git(destination, "checkout", "--detach", revision, "--")
    clean_checkout(destination, revision)
    return files


def isolated_environment(
    parent: Path,
    framework: Path,
    revision: str,
    output: Path,
    python: Path,
    profile: str,
) -> dict[str, str]:
    environment = {
        "PATH": os.defpath,
        "LANG": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }
    environment.update(
        CONNECTOR_ROOT=str(parent),
        CONNECTOR_REVISION=revision,
        FRAMEWORK_ROOT=str(framework),
        TEST_ROOT=str(framework),
        FRAMEWORK_REVISION=git(framework, "rev-parse", "HEAD").decode().strip(),
        CONNECTOR_TEST_PROFILE=profile,
        CONNECTOR_TEST_OUTPUT_ROOT=str(output),
        PYTHON=str(python),
        PYTHONPATH=os.pathsep.join(
            (str(framework), str(framework / "connector_suite"))
        ),
        PYTHONSAFEPATH="1",
        PYTHONNOUSERSITE="1",
        PYTHONDONTWRITEBYTECODE="1",
        TMPDIR=str(output),
        TMP_ROOT=str(output),
        BUILD_ROOT=str(output / "build"),
        XDG_CACHE_HOME=str(output / "cache"),
        PIP_CACHE_DIR=str(output / "cache/pip"),
        PYTHONPYCACHEPREFIX=str(output / "cache/pycache"),
        RUNNER_TEMP=str(output),
    )
    compiler = shutil.which("cc", path=os.defpath)
    if compiler is None:
        raise IntegrationError(
            "installed cc is required for the real Common integration execution"
        )
    environment["CC"] = compiler
    return environment


def process_records() -> dict[int, tuple[int, int]]:
    records = {}
    for directory in Path("/proc").iterdir():
        if not directory.name.isdecimal():
            continue
        try:
            parts = (directory / "stat").read_text().rsplit(")", 1)[1].split()
            records[int(directory.name)] = (int(parts[1]), int(parts[19]))
        except OSError, ValueError, IndexError:
            continue
    return records


def terminate_owned_tree(
    process: subprocess.Popen, identity: tuple[int, int] | None
) -> None:
    """Freeze verified descendants before killing; session changes do not detach ownership."""
    selected = {process.pid: identity}
    for _ in range(16):
        records = process_records()
        # An ancestry edge is admitted only while the already-owned parent still
        # has its original start identity. A reused PID never admits descendants.
        found = {
            pid: observed
            for pid, observed in records.items()
            if pid not in selected
            and observed[0] in selected
            and selected[observed[0]] is not None
            and records.get(observed[0]) == selected[observed[0]]
        }
        selected.update(found)
        for pid, expected in selected.items():
            if expected is not None and process_records().get(pid) == expected:
                try:
                    os.kill(pid, signal.SIGSTOP)
                except ProcessLookupError:
                    pass
        if not found:
            break
    for pid, expected in reversed(tuple(selected.items())):
        if expected is not None and process_records().get(pid) == expected:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    process.wait(timeout=10)


def run_logged(
    command: list[str],
    root: Path,
    environment: dict[str, str],
    output: Path,
    label: str,
    *,
    timeout_seconds: float = 180,
) -> None:
    if not 0 < timeout_seconds <= 180:
        raise IntegrationError(
            "process timeout must be positive and bounded by 180 seconds"
        )
    with (
        (output / (label + ".stdout.log")).open("xb") as stdout,
        (output / (label + ".stderr.log")).open("xb") as stderr,
    ):
        try:
            process = subprocess.Popen(
                command,
                cwd=root,
                env=environment,
                stdout=stdout,
                stderr=stderr,
                start_new_session=True,
            )
            identity = process_records().get(process.pid)
            try:
                code = process.wait(timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                terminate_owned_tree(process, identity)
                raise
        except (OSError, subprocess.SubprocessError) as error:
            raise IntegrationError(f"{label} process failed: {error}") from error
    if code:
        raise IntegrationError(
            f"{label} failed with exit {code}; inspect {output / (label + '.stderr.log')}"
        )


COMPATIBILITY_PROGRAM = r"""
import inspect,json,runpy,sys
from pathlib import Path
f=Path(sys.argv[1])
package=runpy.run_path(str(f/'ci/provisioning/mrts-package.py'),run_name='integration_package')
results=runpy.run_path(str(f/'ci/lib/mrts_results.py'),run_name='integration_results')
for name in ('prepare','verify','materialize'):
    function=package.get(name)
    if not callable(function): raise ValueError('missing MRTS package interface: '+name)
    inspect.signature(function).bind(None)
for name in ('observed_results','write_job'):
    if not callable(results.get(name)): raise ValueError('missing MRTS result interface: '+name)
value=results['observed_results'](['990000-1'],{'run':1,'success':['990000-1']})
if not value['complete'] or value['passed']!=1: raise ValueError('incompatible MRTS result interface')
print(json.dumps({'package_interfaces':['prepare','verify','materialize'],'results_interfaces':['observed_results','write_job'],'observed_result':value},sort_keys=True))
"""


def verify_combination(
    *,
    connector_source: Path,
    framework_source: Path,
    connector_revision: str,
    output_root: Path,
    python: Path,
    profile: str,
    development_framework_revision: str | None = None,
) -> Path:
    parent_source = physical_directory(connector_source)
    framework_source = physical_directory(framework_source)
    output_root = physical_directory(output_root, private=True)
    if any(
        output_root.is_relative_to(root) for root in (parent_source, framework_source)
    ):
        raise IntegrationError(
            "integration output must be external to both source checkouts"
        )
    python = Path(python)
    if (
        not python.is_absolute()
        or not python.is_file()
        or not os.access(python, os.X_OK)
    ):
        raise IntegrationError("an explicit existing Python executable is required")
    if not profile or re.fullmatch(r"[a-zA-Z0-9_.-]+", profile) is None:
        raise IntegrationError("an explicit bounded connector profile is required")
    revision = exact_revision(connector_revision)
    run = Path(tempfile.mkdtemp(prefix="clean-combination-", dir=output_root))
    report = {
        "schema_version": 1,
        "status": "failed",
        "connector_revision": revision,
        "mode": "development"
        if development_framework_revision is not None
        else "recorded-pin",
        "standard_combination": development_framework_revision is None,
        "run_root": str(run),
    }
    try:
        source_files = authenticated_tree(parent_source, revision)
        pin = recorded_framework(source_files)
        selected = (
            exact_revision(development_framework_revision)
            if development_framework_revision is not None
            else pin
        )
        report.update(
            recorded_framework_revision=pin, selected_framework_revision=selected
        )
        authenticated_tree(framework_source, selected)
        parent, framework = run / "connector", run / "connector" / GITLINK
        parent_files = clone(parent_source, parent, revision)
        if recorded_framework(parent_files) != pin:
            raise IntegrationError(
                "cloned Connector does not retain its authenticated Framework pin"
            )
        framework.parent.mkdir(parents=True, exist_ok=True)
        # A Git checkout creates an empty directory for an uninitialized gitlink.
        if framework.exists():
            framework.rmdir()
        framework_files = clone(framework_source, framework, selected)
        lock_mode, lock_identity = parent_files.get(
            "ci/tooling/project-versions.lock.json", ("", "")
        )
        if lock_mode != "100644":
            raise IntegrationError(
                "Parent commit must retain a regular reviewed version-lock file"
            )
        lock_bytes = raw_object(parent, lock_identity, "blob")
        if len(lock_bytes) > 16384:
            raise IntegrationError("Parent version-lock file exceeds its size bound")
        report["version_lock"] = validate_version_lock(
            json.loads(lock_bytes), pin, framework_files
        )
        # Development mode intentionally differs from Parent's recorded gitlink;
        # never misreport that difference as a clean standard combination.
        parent_status = git(
            parent,
            "status",
            _GIT_STATUS_PORCELAIN_ARG,
            _GIT_STATUS_UNTRACKED_ARG,
            _GIT_STATUS_SUBMODULE_ARG,
        ).decode()
        if selected == pin:
            clean_checkout(parent, revision)
        elif parent_status != " M " + GITLINK + "\n":
            raise IntegrationError(
                "development checkout has changes beyond its explicit Framework revision"
            )
        clean_checkout(framework, selected)
        report.update(
            connector_root=str(parent),
            framework_root=str(framework),
            clean_before={"connector": not parent_status, "framework": True},
            connector_status_before=parent_status,
        )
        required = (
            "ci/provisioning/mrts-package.py",
            "ci/lib/mrts_results.py",
            "modsecurity_test_framework/connector.py",
            "connector_suite/connector.mk",
        )
        for name in required:
            if name not in framework_files:
                raise IntegrationError(
                    "selected Framework is incompatible: missing " + name
                )
        artifacts = run / "results"
        artifacts.mkdir(mode=0o700)
        expected = probe_contract(parent, framework, revision, selected, profile)
        report["admitted_probe"] = expected
        environment = isolated_environment(
            parent, framework, revision, artifacts, python, profile
        )
        run_logged(
            [str(python), "-P", "-c", COMPATIBILITY_PROGRAM, str(framework)],
            parent,
            environment,
            artifacts,
            "interfaces",
        )
        command = [
            "make",
            "--no-print-directory",
            "-C",
            str(parent),
            "test-framework-integration-probe",
            "PYTHON=" + str(python),
        ]
        report["command"] = command
        run_logged(command, parent, environment, artifacts, "parent-make")
        observed = validated_probe_results(artifacts, expected)
        final_parent = git(
            parent,
            "status",
            _GIT_STATUS_PORCELAIN_ARG,
            _GIT_STATUS_UNTRACKED_ARG,
            _GIT_STATUS_SUBMODULE_ARG,
        ).decode()
        if final_parent != parent_status:
            raise IntegrationError("Parent checkout changed during integration")
        clean_checkout(framework, selected)
        report.update(
            status="passed",
            execution_results=observed,
            connector_status_after=final_parent,
            clean_after={"connector": not final_parent, "framework": True},
        )
    except (IntegrationError, OSError, ValueError, subprocess.SubprocessError) as error:
        report["error"] = str(error)
        raise IntegrationError(
            f"{error}; receipt: {run / 'integration.json'}"
        ) from error
    finally:
        (run / "integration.json").write_text(json.dumps(report, indent=2) + "\n")
    return run / "integration.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "connector-source",
        "framework-source",
        "connector-revision",
        "output-root",
        "python",
        "profile",
    ):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--development-framework-revision")
    args = parser.parse_args(argv)
    try:
        receipt = verify_combination(
            connector_source=Path(args.connector_source),
            framework_source=Path(args.framework_source),
            connector_revision=args.connector_revision,
            output_root=Path(args.output_root),
            python=Path(args.python),
            profile=args.profile,
            development_framework_revision=args.development_framework_revision,
        )
    except IntegrationError as error:
        print("CONNECTOR_INTEGRATION_REJECTED: " + str(error), file=sys.stderr)
        return 2
    print(receipt)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
