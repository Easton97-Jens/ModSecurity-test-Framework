#!/usr/bin/env python3
"""Run a sealed Lighttpd runtime from the protected-master side.

The namespace dispatcher may materialize pull-request source, but a
pull-request artifact must never decide whether a runtime passed.  This module
therefore accepts only a sealed, root-owned artifact set and starts the exact
Lighttpd binary itself.  It observes that child process, its mapped connector
module, its loopback listener, and three fixed HTTP probes before it writes the
only terminal receipt.

It is deliberately useful only from the protected runtime protocol.  The
current fixture dispatcher does not yet create a sealed artifact set or invoke
this program.  Until a later protected-master integration supplies canonical
independent runtime no-CRS provenance, this program blocks before it can start
Lighttpd or claim a runtime result.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import errno
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import subprocess
import sys
import time
from typing import Any, Mapping, Sequence


SCHEMA_VERSION = 1
EXIT_BLOCKED = 77
MAX_ARTIFACT_BYTES = 128 * 1024 * 1024
MAX_CONFIG_BYTES = 512 * 1024
MAX_RESPONSE_BYTES = 64 * 1024
MAX_RESPONSE_HEADERS = 64
MAX_RESPONSE_HEADER_BYTES = 8 * 1024
START_TIMEOUT_SECONDS = 20.0
STOP_TIMEOUT_SECONDS = 10.0
RECEIPT_NAME = "trusted-lighttpd-runtime-receipt.json"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
HOST_TRANSACTION_ID_RE = re.compile(r"^lighttpd-[1-9]\d*-[1-9]\d*$")
SOCKET_LINK_RE = re.compile(r"^socket:\[(?P<inode>[1-9]\d*)\]$")
FORBIDDEN_CRS_CONFIGURATION_TOKENS = (
    "owasp",
    "coreruleset",
    "crs-setup.conf",
    "/crs/",
    "\\\\crs\\\\",
)
FORBIDDEN_CONFIG_PATH_KEYS = frozenset({"event_path", "rules_file"})
SEALED_ARTIFACT_ROOT = "sealed artifact root"
SEALED_ARTIFACT_DIRECTORY = "sealed artifact directory"
SEALED_LIBRARY_DIRECTORY = "sealed library directory"
SUPERVISOR_RECEIPT_ROOT = "supervisor receipt root"
HOST = "127.0.0.1"
TRANSACTION_HEADER = "x-msconnector-host-transaction-id"


class SupervisorError(RuntimeError):
    """Raised when the protected runtime contract cannot be proven."""


@dataclass(frozen=True)
class ArtifactSpec:
    """One sealed file which the supervisor may use or observe."""

    path: Path
    sha256: str
    label: str


@dataclass(frozen=True)
class ProbeCase:
    """One fixed, master-controlled HTTP request and expected observation."""

    case_id: str
    headers: tuple[tuple[str, str], ...]
    expected_status: int


@dataclass(frozen=True)
class RuntimePlan:
    """The closed set of values used to start one protected runtime."""

    target_sha: str
    run_id: str
    sealed_root: Path
    receipt_root: Path
    binary: ArtifactSpec
    module: ArtifactSpec
    config: ArtifactSpec
    sealed_artifacts: tuple[ArtifactSpec, ...]
    library_directories: tuple[Path, ...]
    port: int
    runtime_uid: int
    runtime_gid: int


@dataclass(frozen=True)
class ProcessObservation:
    """Facts independently read from the process and kernel interfaces."""

    pid: int
    start_ticks: int
    executable_sha256: str
    module_sha256: str
    listener_inode: int
    listener_address: str
    listener_port: int


@dataclass(frozen=True)
class ProbeObservation:
    """A bounded response observation for a master-owned probe."""

    case_id: str
    status: int
    transaction_id: str


def fail(message: str) -> None:
    """Raise one uniform fail-closed exception."""

    raise SupervisorError(message)


def required_sha256(value: object, label: str) -> str:
    """Return one canonical SHA-256 literal or reject it."""

    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        fail(f"{label} must be a lowercase SHA-256")
    return value


def required_target_sha(value: object) -> str:
    """Return the API-bound pull-request head SHA."""

    if not isinstance(value, str) or SHA_RE.fullmatch(value) is None:
        fail("target SHA must be a lowercase full Git SHA")
    return value


def required_run_id(value: object) -> str:
    """Return a bounded opaque run identifier."""

    if not isinstance(value, str) or RUN_ID_RE.fullmatch(value) is None:
        fail("run ID must be a bounded opaque token")
    return value


def normalized_absolute(path: Path | str, label: str) -> Path:
    """Normalize an absolute path without resolving a possible symbolic link."""

    raw = os.fspath(path)
    if not raw or "\x00" in raw or not os.path.isabs(raw):
        fail(f"{label} must be an absolute path")
    candidate = Path(raw)
    if any(part in {"", ".", ".."} for part in candidate.parts):
        fail(f"{label} must not contain traversal")
    return Path(os.path.normpath(raw))


def require_within(path: Path, root: Path, label: str) -> Path:
    """Require a lexical descendant without resolving untrusted path components."""

    candidate = normalized_absolute(path, label)
    trusted_root = normalized_absolute(root, SEALED_ARTIFACT_ROOT)
    try:
        relative = candidate.relative_to(trusted_root)
    except ValueError:
        fail(f"{label} must be below the sealed artifact root")
    if relative == Path("."):
        fail(f"{label} must not be the sealed artifact root")
    return candidate


def require_no_symlink_components(path: Path, label: str) -> None:
    """Reject a symbolic-link substitution in any existing path component."""

    candidate = normalized_absolute(path, label)
    cursor = Path(candidate.anchor)
    for part in candidate.parts[1:]:
        cursor /= part
        try:
            details = os.lstat(cursor)
        except OSError as error:
            fail(f"cannot inspect {label}: {error}")
        if stat.S_ISLNK(details.st_mode):
            fail(f"{label} must not use symbolic links")


def private_directory(path: Path, label: str, *, owner: int, mode: int) -> Path:
    """Require an exact root-owned/private directory before writing a receipt."""

    candidate = normalized_absolute(path, label)
    require_no_symlink_components(candidate, label)
    try:
        details = os.lstat(candidate)
    except OSError as error:
        fail(f"cannot inspect {label}: {error}")
    if (
        not stat.S_ISDIR(details.st_mode)
        or details.st_uid != owner
        or stat.S_IMODE(details.st_mode) != mode
    ):
        fail(f"{label} must be an owner-private directory")
    return candidate


def sealed_directory(path: Path, label: str, *, owner: int) -> Path:
    """Require a root-owned read-only-to-others artifact directory."""

    candidate = normalized_absolute(path, label)
    require_no_symlink_components(candidate, label)
    try:
        details = os.lstat(candidate)
    except OSError as error:
        fail(f"cannot inspect {label}: {error}")
    mode = stat.S_IMODE(details.st_mode)
    if (
        not stat.S_ISDIR(details.st_mode)
        or details.st_uid != owner
        or mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        fail(f"{label} must be an owner-controlled directory")
    return candidate


def _open_regular(path: Path, label: str) -> tuple[int, os.stat_result]:
    """Open one regular non-link file while retaining its inode identity."""

    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        fail(f"cannot open {label}: {error}")
    details = os.fstat(descriptor)
    if not stat.S_ISREG(details.st_mode):
        os.close(descriptor)
        fail(f"{label} must be a regular file")
    return descriptor, details


def _stable_regular_file(
    path: Path,
    label: str,
    *,
    maximum_bytes: int,
    retain_contents: bool,
) -> tuple[str, os.stat_result, bytes | None]:
    """Read and hash a stable non-link file through one retained descriptor."""

    descriptor, before = _open_regular(path, label)
    contents = bytearray() if retain_contents else None
    try:
        if before.st_size <= 0 or before.st_size > maximum_bytes:
            fail(f"{label} has an invalid size")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            if contents is not None:
                contents.extend(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ):
        fail(f"{label} changed while it was hashed")
    return digest.hexdigest(), before, bytes(contents) if contents is not None else None


def sha256_regular_file(path: Path, label: str, *, maximum_bytes: int) -> tuple[str, os.stat_result]:
    """Hash one stable regular file through a no-follow descriptor."""

    digest, details, _ = _stable_regular_file(
        path,
        label,
        maximum_bytes=maximum_bytes,
        retain_contents=False,
    )
    return digest, details


def reject_privileged_file_capabilities(path: Path, label: str) -> None:
    """Reject file capabilities that could regain privilege after the UID drop."""

    unsupported = {errno.ENODATA, errno.ENOTSUP, errno.EOPNOTSUPP}
    try:
        capabilities = os.getxattr(path, "security.capability", follow_symlinks=False)
    except OSError as error:
        if error.errno in unsupported:
            return
        fail(f"cannot inspect {label} file capabilities: {error}")
    if capabilities:
        fail(f"{label} must not carry Linux file capabilities")


def validated_sealed_artifact(
    spec: ArtifactSpec,
    sealed_root: Path,
    *,
    owner: int,
    maximum_bytes: int,
    retain_contents: bool,
) -> tuple[os.stat_result, bytes | None]:
    """Validate one sealed artifact and optionally return its exact read bytes."""

    path = require_within(spec.path, sealed_root, spec.label)
    require_no_symlink_components(path, spec.label)
    reject_privileged_file_capabilities(path, spec.label)
    digest, details, contents = _stable_regular_file(
        path,
        spec.label,
        maximum_bytes=maximum_bytes,
        retain_contents=retain_contents,
    )
    mode = stat.S_IMODE(details.st_mode)
    if (
        details.st_uid != owner
        or mode & (stat.S_IWGRP | stat.S_IWOTH)
        or details.st_mode & (stat.S_ISUID | stat.S_ISGID)
        or details.st_nlink != 1
    ):
        fail(f"{spec.label} is not a sealed owner-controlled file")
    if digest != required_sha256(spec.sha256, f"{spec.label} SHA-256"):
        fail(f"{spec.label} digest does not match its sealed identity")
    return details, contents


def validate_artifact(spec: ArtifactSpec, sealed_root: Path, *, owner: int) -> os.stat_result:
    """Validate one fixed sealed artifact and return its stable metadata."""

    details, _ = validated_sealed_artifact(
        spec,
        sealed_root,
        owner=owner,
        maximum_bytes=MAX_ARTIFACT_BYTES,
        retain_contents=False,
    )
    return details


def _sealed_tree_entries(directory: Path) -> list[os.DirEntry[str]]:
    """Return one sealed directory's entries or stop before a partial tree scan."""

    try:
        return list(os.scandir(directory))
    except OSError as error:
        fail(f"cannot enumerate sealed artifact directory: {error}")


def _sealed_tree_entry_is_directory(entry: os.DirEntry[str]) -> bool:
    """Reject non-regular/non-directory entries and return the directory case."""

    try:
        details = entry.stat(follow_symlinks=False)
    except OSError as error:
        fail(f"cannot inspect sealed artifact entry: {error}")
    if stat.S_ISLNK(details.st_mode):
        fail("sealed artifact tree must not contain symbolic links")
    if stat.S_ISDIR(details.st_mode):
        return True
    if not stat.S_ISREG(details.st_mode):
        fail("sealed artifact tree must contain only directories and regular files")
    return False


def _walk_sealed_artifact_tree(root: Path, manifest_paths: frozenset[Path], *, owner: int) -> None:
    """Reject every unmanifested, writable, linked, or special sealed-tree entry."""

    pending = [root]
    observed_files: set[Path] = set()
    while pending:
        directory = pending.pop()
        sealed_directory(directory, SEALED_ARTIFACT_DIRECTORY, owner=owner)
        for entry in _sealed_tree_entries(directory):
            path = Path(entry.path)
            if _sealed_tree_entry_is_directory(entry):
                pending.append(path)
                continue
            if path not in manifest_paths:
                fail("sealed artifact tree contains a file outside its digest manifest")
            observed_files.add(path)
    if observed_files != manifest_paths:
        fail("sealed artifact digest manifest does not match its tree")


def validate_sealed_artifact_manifest(
    plan: RuntimePlan,
    sealed_root: Path,
    *,
    owner: int,
) -> dict[Path, os.stat_result]:
    """Validate the complete immutable file set exposed to the child loader."""

    if not plan.sealed_artifacts:
        fail("supervisor requires a complete sealed artifact digest manifest")
    metadata: dict[Path, os.stat_result] = {}
    digests: dict[Path, str] = {}
    for spec in plan.sealed_artifacts:
        path = require_within(spec.path, sealed_root, "sealed manifest artifact")
        if path in metadata:
            fail("sealed artifact digest manifest has duplicate paths")
        metadata[path] = validate_artifact(
            ArtifactSpec(path, spec.sha256, spec.label),
            sealed_root,
            owner=owner,
        )
        digests[path] = spec.sha256
    for primary in (plan.binary, plan.module, plan.config):
        primary_path = require_within(primary.path, sealed_root, primary.label)
        if digests.get(primary_path) != primary.sha256:
            fail(f"{primary.label} must be present in the sealed artifact digest manifest")
    _walk_sealed_artifact_tree(sealed_root, frozenset(metadata), owner=owner)
    return metadata


def bounded_sealed_text(
    spec: ArtifactSpec,
    sealed_root: Path,
    *,
    owner: int,
    maximum_bytes: int,
) -> str:
    """Read one sealed UTF-8 artifact through the descriptor used for its digest."""

    _, contents = validated_sealed_artifact(
        spec,
        sealed_root,
        owner=owner,
        maximum_bytes=maximum_bytes,
        retain_contents=True,
    )
    if contents is None:
        fail(f"cannot read {spec.label} through its sealed descriptor")
    try:
        return contents.decode("utf-8")
    except UnicodeError as error:
        fail(f"cannot read {spec.label}: {error}")


def bounded_config_text(spec: ArtifactSpec, sealed_root: Path, *, owner: int) -> str:
    """Read the sealed generated configuration with its dedicated small bound."""

    return bounded_sealed_text(
        spec,
        sealed_root,
        owner=owner,
        maximum_bytes=MAX_CONFIG_BYTES,
    )


def configuration_assignment_key(line: str) -> str | None:
    """Return a narrow ASCII configuration assignment key, if the line has one."""

    key, separator, _ = line.partition("=")
    key = key.strip()
    if not separator or not key or not key.isascii() or not key[0].isalpha():
        return None
    if not all(character.isalnum() or character in "_.-" for character in key):
        return None
    return key.lower()


def validate_no_crs_configuration(
    config: str,
    environment: Mapping[str, str],
) -> None:
    """Reject CRS selection and any uncontracted rule or runtime-data source."""

    ruleset = environment.get("MODSECURITY_RULESET", "").strip().lower()
    if ruleset not in {"", "no-crs"}:
        fail("MODSECURITY_RULESET must not select CRS")
    if environment.get("MSCONNECTOR_CRS_RUNTIME", "0") != "0":
        fail("MSCONNECTOR_CRS_RUNTIME must be 0")
    folded = config.lower()
    if any(token in folded for token in FORBIDDEN_CRS_CONFIGURATION_TOKENS):
        fail("sealed configuration contains an OWASP CRS reference")
    for raw_line in config.splitlines():
        line = raw_line.split("#", maxsplit=1)[0].strip()
        if not line:
            continue
        if re.match(r"^include(?:_shell)?\b", line, flags=re.IGNORECASE):
            fail("sealed configuration must not include external files or shell output")
        key = configuration_assignment_key(line)
        if key is None:
            continue
        if key in FORBIDDEN_CONFIG_PATH_KEYS:
            fail(
                f"sealed configuration must not use {key} before a canonical protected "
                "rule/data provenance contract exists"
            )


def validate_runtime_plan(plan: RuntimePlan) -> None:
    """Validate every master-controlled input before a subprocess is started."""

    owner = os.geteuid()
    required_target_sha(plan.target_sha)
    required_run_id(plan.run_id)
    sealed_root = sealed_directory(plan.sealed_root, SEALED_ARTIFACT_ROOT, owner=owner)
    receipt_root = private_directory(plan.receipt_root, SUPERVISOR_RECEIPT_ROOT, owner=owner, mode=0o700)
    try:
        receipt_root.relative_to(sealed_root)
        fail("supervisor receipt root must not overlap sealed artifacts")
    except ValueError:
        try:
            sealed_root.relative_to(receipt_root)
            fail("supervisor receipt root must not overlap sealed artifacts")
        except ValueError:
            pass
    if not 1024 <= plan.port <= 65535:
        fail("supervisor port must be an unprivileged TCP port")
    if plan.runtime_uid <= 0 or plan.runtime_gid <= 0:
        fail("runtime identity must be a non-root UID and GID")
    if not plan.library_directories:
        fail("supervisor requires at least one sealed library directory")
    artifact_metadata = validate_sealed_artifact_manifest(plan, sealed_root, owner=owner)
    binary_path = require_within(plan.binary.path, sealed_root, plan.binary.label)
    binary_details = artifact_metadata[binary_path]
    if not binary_details.st_mode & stat.S_IXUSR:
        fail("Lighttpd binary must be owner-executable")
    artifact_paths = {plan.binary.path, plan.module.path, plan.config.path}
    if len(artifact_paths) != 3:
        fail("sealed binary, module, and configuration must be distinct files")
    configuration = bounded_config_text(plan.config, sealed_root, owner=owner)
    validate_no_crs_configuration(
        configuration,
        {"MSCONNECTOR_CRS_RUNTIME": "0", "MODSECURITY_RULESET": "no-crs"},
    )
    library_directories: set[Path] = set()
    for directory in plan.library_directories:
        candidate = require_within(directory, sealed_root, SEALED_LIBRARY_DIRECTORY)
        if candidate in library_directories:
            fail("sealed library directories must not repeat")
        sealed_directory(candidate, SEALED_LIBRARY_DIRECTORY, owner=owner)
        if not any(path != candidate and candidate in path.parents for path in artifact_metadata):
            fail("sealed library directory must contain a digest-manifest artifact")
        library_directories.add(candidate)


def require_independent_runtime_no_crs_provenance(plan: RuntimePlan) -> None:
    """Block execution until protected master can bind the actual rule provenance.

    A sealed binary and static configuration alone cannot prove that the live
    connector did not activate an embedded or default CRS source.  Keeping the
    prerequisite unavailable is safer than emitting a false no-CRS PASS.
    """

    del plan
    fail("independent runtime no-CRS provenance is not implemented")


def fixed_probe_cases(run_id: str) -> tuple[ProbeCase, ...]:
    """Return the closed control, detection, and alternate-negative probe set."""

    token = required_run_id(run_id)
    return (
        ProbeCase(
            case_id="control",
            headers=(("X-Modsec-Transaction-Id", f"{token}-control"),),
            expected_status=200,
        ),
        ProbeCase(
            case_id="detection",
            headers=(
                ("X-Modsec-Smoke", "block"),
                ("X-Modsec-Transaction-Id", f"{token}-detection"),
            ),
            expected_status=403,
        ),
        ProbeCase(
            case_id="alternate-negative",
            headers=(
                ("X-Modsec-Smoke", "alternative-status"),
                ("X-Modsec-Transaction-Id", f"{token}-alternate"),
            ),
            expected_status=429,
        ),
    )


def process_start_ticks(pid: int) -> int:
    """Read the Linux process start token without trusting a PID alone."""

    if pid <= 1:
        fail("supervisor process PID is invalid")
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    except OSError as error:
        fail(f"cannot inspect supervisor process: {error}")
    closing = raw.rfind(")")
    fields = raw[closing + 2 :].split() if closing > 0 else []
    if len(fields) <= 19 or not fields[19].isdigit() or int(fields[19]) <= 0:
        fail("supervisor process start token is invalid")
    return int(fields[19])


def verified_artifact_identity(artifact: ArtifactSpec, sealed_root: Path) -> tuple[Path, os.stat_result]:
    """Return an exact stable artifact identity for a later process observation."""

    expected = require_within(artifact.path, sealed_root, artifact.label)
    expected_digest, expected_details = sha256_regular_file(
        expected, artifact.label, maximum_bytes=MAX_ARTIFACT_BYTES
    )
    if expected_digest != required_sha256(artifact.sha256, f"{artifact.label} SHA-256"):
        fail(f"{artifact.label} changed before process observation")
    return expected, expected_details


def process_uses_artifact(pid: int, artifact: ArtifactSpec, sealed_root: Path) -> None:
    """Tie a live `/proc` executable inode to its sealed artifact."""

    _, expected_details = verified_artifact_identity(artifact, sealed_root)
    try:
        observed = os.stat(f"/proc/{pid}/exe")
        executable_link = os.readlink(f"/proc/{pid}/exe")
    except OSError as error:
        fail(f"cannot inspect supervisor process executable: {error}")
    if executable_link.endswith(" (deleted)") or (
        observed.st_dev,
        observed.st_ino,
    ) != (expected_details.st_dev, expected_details.st_ino):
        fail("supervisor process executable does not match the sealed Lighttpd binary")


def module_is_mapped(pid: int, artifact: ArtifactSpec, sealed_root: Path) -> None:
    """Require the exact sealed connector module to be mapped by Lighttpd."""

    expected, expected_details = verified_artifact_identity(artifact, sealed_root)
    try:
        rows = Path(f"/proc/{pid}/maps").read_text(encoding="utf-8").splitlines()
    except OSError as error:
        fail(f"cannot inspect supervisor process mappings: {error}")
    for row in rows:
        fields = row.split(maxsplit=5)
        if len(fields) != 6 or not fields[4].isdigit():
            continue
        mapped_path = fields[5]
        if mapped_path.endswith(" (deleted)"):
            continue
        if int(fields[4]) == expected_details.st_ino and mapped_path == str(expected):
            return
    fail("supervisor process did not map the sealed connector module")


def loopback_listener_inodes(port: int) -> list[int]:
    """Read all exact loopback TCP listener inodes for one fixed port."""

    try:
        rows = Path("/proc/net/tcp").read_text(encoding="ascii").splitlines()[1:]
    except OSError as error:
        fail(f"cannot inspect TCP listeners: {error}")
    target = f"0100007F:{port:04X}"
    matches: list[int] = []
    for row in rows:
        fields = row.split()
        if len(fields) < 10 or fields[1] != target or fields[3] != "0A":
            continue
        if fields[9].isdigit() and int(fields[9]) > 0:
            matches.append(int(fields[9]))
    return matches


def listener_inode(port: int) -> int:
    """Return only one loopback TCP listener inode; wildcard listeners do not count."""

    matches = loopback_listener_inodes(port)
    if len(matches) != 1:
        fail("supervisor did not observe exactly one loopback Lighttpd listener")
    return matches[0]


def process_socket_inodes(pid: int) -> set[int]:
    """Read only the kernel socket descriptors held by the supervisor child."""

    directory = Path(f"/proc/{pid}/fd")
    try:
        entries = list(directory.iterdir())
    except OSError as error:
        fail(f"cannot inspect supervisor process descriptors: {error}")
    result: set[int] = set()
    for entry in entries:
        try:
            target = os.readlink(entry)
        except OSError:
            continue
        match = SOCKET_LINK_RE.fullmatch(target)
        if match is not None:
            result.add(int(match.group("inode")))
    return result


def observe_process(plan: RuntimePlan, process: subprocess.Popen[bytes], start_ticks: int) -> ProcessObservation:
    """Collect independent binary, module, and listener facts for the child."""

    if process.poll() is not None or process_start_ticks(process.pid) != start_ticks:
        fail("supervisor process exited or changed before observation")
    process_uses_artifact(process.pid, plan.binary, plan.sealed_root)
    module_is_mapped(process.pid, plan.module, plan.sealed_root)
    inode = listener_inode(plan.port)
    if inode not in process_socket_inodes(process.pid):
        fail("supervisor listener is not owned by the Lighttpd process")
    return ProcessObservation(
        pid=process.pid,
        start_ticks=start_ticks,
        executable_sha256=plan.binary.sha256,
        module_sha256=plan.module.sha256,
        listener_inode=inode,
        listener_address=HOST,
        listener_port=plan.port,
    )


def wait_for_observation(plan: RuntimePlan, process: subprocess.Popen[bytes], start_ticks: int) -> ProcessObservation:
    """Wait a bounded interval for the independently owned listener."""

    deadline = time.monotonic() + START_TIMEOUT_SECONDS
    last_error = "Lighttpd listener did not become ready"
    while time.monotonic() < deadline:
        try:
            return observe_process(plan, process, start_ticks)
        except SupervisorError as error:
            last_error = str(error)
            if process.poll() is not None:
                break
            time.sleep(0.1)
    fail(last_error)


def _response_transaction_id(response: http.client.HTTPResponse, request_token: str) -> str:
    """Require one fresh host-generated transaction ID in the response."""

    values = [value.strip() for name, value in response.getheaders() if name.lower() == TRANSACTION_HEADER]
    if len(values) != 1 or HOST_TRANSACTION_ID_RE.fullmatch(values[0]) is None:
        fail("fixed probe has no valid host-generated transaction ID")
    if values[0] == request_token:
        fail("fixed probe reflected the untrusted transaction ID")
    return values[0]


def run_fixed_probe(port: int, case: ProbeCase) -> ProbeObservation:
    """Send a fixed request from the supervisor, never from target evidence."""

    request_token = dict(case.headers).get("X-Modsec-Transaction-Id", "")
    connection = http.client.HTTPConnection(HOST, port, timeout=5)
    try:
        connection.putrequest("OPTIONS", "*", skip_host=True, skip_accept_encoding=True)
        connection.putheader("Host", "lighttpd-runtime.test")
        for name, value in case.headers:
            connection.putheader(name, value)
        connection.endheaders()
        response = connection.getresponse()
        headers = response.getheaders()
        header_bytes = sum(len(name) + len(value) for name, value in headers)
        if len(headers) > MAX_RESPONSE_HEADERS or header_bytes > MAX_RESPONSE_HEADER_BYTES:
            fail("fixed probe response headers exceed their bound")
        payload = response.read(MAX_RESPONSE_BYTES + 1)
        if len(payload) > MAX_RESPONSE_BYTES:
            fail("fixed probe response body exceeds its bound")
        if response.status != case.expected_status:
            fail(f"fixed probe {case.case_id} returned {response.status}, expected {case.expected_status}")
        transaction_id = _response_transaction_id(response, request_token)
    except (OSError, http.client.HTTPException) as error:
        fail(f"fixed probe {case.case_id} failed: {error}")
    finally:
        connection.close()
    return ProbeObservation(case_id=case.case_id, status=case.expected_status, transaction_id=transaction_id)


def run_fixed_probes(plan: RuntimePlan) -> tuple[ProbeObservation, ...]:
    """Execute the closed control/detection/alternate-negative case set."""

    observations = tuple(run_fixed_probe(plan.port, case) for case in fixed_probe_cases(plan.run_id))
    identifiers = {item.transaction_id for item in observations}
    if len(identifiers) != len(observations):
        fail("fixed probes reused a host transaction ID")
    return observations


def require_private_pid_namespace_init() -> None:
    """Require the supervisor to be PID 1 so namespace teardown kills all children."""

    if os.getpid() != 1:
        fail("trusted runtime supervisor must execute as PID 1 in its private PID namespace")


def private_pid_namespace_is_clean() -> bool:
    """Confirm that no escaped child process remains in the private PID namespace."""

    try:
        process_ids = {int(entry.name) for entry in Path("/proc").iterdir() if entry.name.isdigit()}
    except OSError:
        return False
    return os.getpid() == 1 and process_ids == {1}


def child_environment(plan: RuntimePlan) -> dict[str, str]:
    """Construct a closed environment for the Lighttpd child."""

    library_path = os.pathsep.join(str(directory) for directory in plan.library_directories)
    return {
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "MSCONNECTOR_CRS_RUNTIME": "0",
        "MODSECURITY_RULESET": "no-crs",
        "NO_CRS_RUN_ID": plan.run_id,
        "PATH": "/usr/bin:/bin",
        "LD_LIBRARY_PATH": library_path,
    }


def start_lighttpd(plan: RuntimePlan) -> subprocess.Popen[bytes]:
    """Start only the sealed binary with its fixed Lighttpd argument vector."""

    require_private_pid_namespace_init()
    command = [
        str(plan.binary.path),
        "-D",
        "-m",
        str(plan.module.path.parent),
        "-f",
        str(plan.config.path),
    ]
    kwargs: dict[str, Any] = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "cwd": str(plan.sealed_root),
        "env": child_environment(plan),
        "start_new_session": True,
    }
    if os.geteuid() == 0:
        kwargs.update({"user": plan.runtime_uid, "group": plan.runtime_gid, "extra_groups": ()})
    elif os.geteuid() != plan.runtime_uid or os.getegid() != plan.runtime_gid:
        fail("unprivileged supervisor cannot select a different runtime identity")
    try:
        return subprocess.Popen(command, **kwargs)
    except OSError as error:
        fail(f"cannot start sealed Lighttpd process: {error}")


def terminate_lighttpd(process: subprocess.Popen[bytes], start_ticks: int | None) -> bool:
    """Stop the fresh child group, retaining a PID token whenever observation reached it."""

    if process.poll() is not None:
        return True
    try:
        # A still-live Popen child has not been reaped, so its PID cannot have
        # been reused if an early /proc start-token read failed.
        if start_ticks is not None and process_start_ticks(process.pid) != start_ticks:
            fail("supervisor refuses to signal a reused Lighttpd PID")
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=STOP_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        try:
            if start_ticks is not None and process_start_ticks(process.pid) != start_ticks:
                fail("supervisor refuses to kill a reused Lighttpd PID")
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=STOP_TIMEOUT_SECONDS)
        except (OSError, subprocess.SubprocessError, SupervisorError):
            return False
    except (OSError, subprocess.SubprocessError, SupervisorError):
        return False
    return process.poll() is not None


def listener_released(port: int) -> bool:
    """Return whether no loopback listener remains on the supervisor port."""

    try:
        return not loopback_listener_inodes(port)
    except SupervisorError:
        return False


def _write_all(descriptor: int, data: bytes) -> None:
    """Write a complete receipt through the already-validated directory FD."""

    offset = 0
    while offset < len(data):
        count = os.write(descriptor, data[offset:])
        if count <= 0:
            fail("cannot write a complete supervisor receipt")
        offset += count


def write_receipt(receipt_root: Path, payload: Mapping[str, object]) -> Path:
    """Atomically publish the one root-owned receipt without replacement."""

    root = private_directory(receipt_root, SUPERVISOR_RECEIPT_ROOT, owner=os.geteuid(), mode=0o700)
    data = (json.dumps(dict(payload), sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(data) > MAX_CONFIG_BYTES:
        fail("supervisor receipt exceeds its bound")
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    temporary = f".{RECEIPT_NAME}.tmp-{os.getpid()}"
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=root_fd,
        )
        try:
            _write_all(descriptor, data)
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o600)
        finally:
            os.close(descriptor)
        try:
            os.link(temporary, RECEIPT_NAME, src_dir_fd=root_fd, dst_dir_fd=root_fd, follow_symlinks=False)
        except FileExistsError:
            fail("supervisor receipt already exists")
        os.fsync(root_fd)
    finally:
        try:
            os.unlink(temporary, dir_fd=root_fd)
        except FileNotFoundError:
            pass
        os.close(root_fd)
    return root / RECEIPT_NAME


def receipt_payload(
    plan: RuntimePlan,
    *,
    outcome: str,
    blocker: str | None,
    process: ProcessObservation | None,
    probes: Sequence[ProbeObservation],
    cleanup_passed: bool,
    static_no_crs_configuration_checked: bool,
) -> dict[str, object]:
    """Construct a receipt from supervisor observations only."""

    return {
        "schema_version": SCHEMA_VERSION,
        "producer": "trusted-lighttpd-runtime-supervisor",
        "target_sha": plan.target_sha,
        "run_id": plan.run_id,
        "profile": "no-crs",
        "mrts": {"executed": False, "status": "NOT_INVOKED"},
        "runtime_status": outcome,
        "blocker": blocker,
        "artifacts": {
            "lighttpd_binary_sha256": plan.binary.sha256,
            "connector_module_sha256": plan.module.sha256,
            "config_sha256": plan.config.sha256,
        },
        "process": asdict(process) if process is not None else None,
        "probes": [asdict(item) for item in probes],
        "no_crs": {
            "msconnector_crs_runtime": "0",
            "modsecurity_ruleset": "no-crs",
            "static_configuration_checked": static_no_crs_configuration_checked,
            "runtime_provenance_status": "NOT_VERIFIED",
        },
        "cleanup_passed": cleanup_passed,
    }


def supervise(plan: RuntimePlan) -> dict[str, object]:
    """Start, independently observe, probe, stop, and receipt one runtime."""

    private_directory(plan.receipt_root, SUPERVISOR_RECEIPT_ROOT, owner=os.geteuid(), mode=0o700)
    process: subprocess.Popen[bytes] | None = None
    start_ticks: int | None = None
    observation: ProcessObservation | None = None
    probes: tuple[ProbeObservation, ...] = ()
    blocker: str | None = None
    cleanup_passed = False
    static_no_crs_configuration_checked = False
    try:
        validate_runtime_plan(plan)
        static_no_crs_configuration_checked = True
        require_independent_runtime_no_crs_provenance(plan)
        process = start_lighttpd(plan)
        start_ticks = process_start_ticks(process.pid)
        observation = wait_for_observation(plan, process, start_ticks)
        probes = run_fixed_probes(plan)
        final_observation = observe_process(plan, process, start_ticks)
        if final_observation != observation:
            fail("supervisor process identity changed while fixed probes ran")
    except SupervisorError as error:
        blocker = str(error)
    finally:
        if process is not None:
            cleanup_passed = (
                terminate_lighttpd(process, start_ticks)
                and listener_released(plan.port)
                and private_pid_namespace_is_clean()
            )
        elif process is None:
            cleanup_passed = private_pid_namespace_is_clean()
    if not cleanup_passed:
        blocker = blocker or "supervisor cleanup did not release the Lighttpd listener"
    outcome = "PASS" if blocker is None and cleanup_passed else "BLOCKED"
    receipt = receipt_payload(
        plan,
        outcome=outcome,
        blocker=blocker,
        process=observation,
        probes=probes,
        cleanup_passed=cleanup_passed,
        static_no_crs_configuration_checked=static_no_crs_configuration_checked,
    )
    write_receipt(plan.receipt_root, receipt)
    if outcome != "PASS":
        fail(blocker or "supervisor did not produce a complete runtime observation")
    return receipt


def parsed_plan(arguments: argparse.Namespace) -> RuntimePlan:
    """Turn trusted workflow arguments into a fully validated plan object."""

    return RuntimePlan(
        target_sha=required_target_sha(arguments.target_sha),
        run_id=required_run_id(arguments.run_id),
        sealed_root=normalized_absolute(arguments.sealed_root, SEALED_ARTIFACT_ROOT),
        receipt_root=normalized_absolute(arguments.receipt_root, SUPERVISOR_RECEIPT_ROOT),
        binary=ArtifactSpec(
            normalized_absolute(arguments.binary, "Lighttpd binary"),
            required_sha256(arguments.binary_sha256, "Lighttpd binary SHA-256"),
            "Lighttpd binary",
        ),
        module=ArtifactSpec(
            normalized_absolute(arguments.module, "Lighttpd connector module"),
            required_sha256(arguments.module_sha256, "Lighttpd connector module SHA-256"),
            "Lighttpd connector module",
        ),
        config=ArtifactSpec(
            normalized_absolute(arguments.config, "Lighttpd configuration"),
            required_sha256(arguments.config_sha256, "Lighttpd configuration SHA-256"),
            "Lighttpd configuration",
        ),
        sealed_artifacts=tuple(
            ArtifactSpec(
                normalized_absolute(path, f"sealed artifact {index}"),
                required_sha256(digest, f"sealed artifact {index} SHA-256"),
                f"sealed artifact {index}",
            )
            for index, (path, digest) in enumerate(arguments.sealed_artifact, start=1)
        ),
        library_directories=tuple(
            normalized_absolute(value, SEALED_LIBRARY_DIRECTORY) for value in arguments.library_dir
        ),
        port=arguments.port,
        runtime_uid=arguments.runtime_uid,
        runtime_gid=arguments.runtime_gid,
    )


def parser() -> argparse.ArgumentParser:
    """Create the fixed protected-runtime command line."""

    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--target-sha", required=True)
    result.add_argument("--run-id", required=True)
    result.add_argument("--sealed-root", required=True, type=Path)
    result.add_argument("--receipt-root", required=True, type=Path)
    result.add_argument("--binary", required=True, type=Path)
    result.add_argument("--binary-sha256", required=True)
    result.add_argument("--module", required=True, type=Path)
    result.add_argument("--module-sha256", required=True)
    result.add_argument("--config", required=True, type=Path)
    result.add_argument("--config-sha256", required=True)
    result.add_argument(
        "--sealed-artifact",
        required=True,
        action="append",
        nargs=2,
        metavar=("PATH", "SHA256"),
    )
    result.add_argument("--library-dir", required=True, action="append", type=Path)
    result.add_argument("--port", required=True, type=int)
    result.add_argument("--runtime-uid", required=True, type=int)
    result.add_argument("--runtime-gid", required=True, type=int)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    """Run one fail-closed supervisor session from a trusted workflow."""

    arguments = parser().parse_args(argv)
    try:
        receipt = supervise(parsed_plan(arguments))
    except SupervisorError as error:
        print(f"BLOCKED: trusted Lighttpd runtime supervisor: {error}", file=sys.stderr)
        return EXIT_BLOCKED
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
