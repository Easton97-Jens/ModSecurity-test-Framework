#!/usr/bin/env python3
"""Run the complete ordinary NGINX catalog through the existing Functional-A path.

This candidate-owned functional gate is not a protected broker or adversarial
attestation. Preparation and summarization remain unprivileged; root receives
only a fixed entry point and bounded, independently checked inputs.
"""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import grp
import re
import signal
import stat
import subprocess
import sys
import time

ROOT = connector_root()
FRAMEWORK = source_path('modules/ModSecurity-test-Framework', root=ROOT)
CASE_CLI = FRAMEWORK / "tests/runners/case_cli.py"
HARNESS = source_path('connectors/nginx/harness/run_nginx_smoke.sh', root=ROOT)
COUNTS = {"no-crs": 60, "with-crs": 61}
MAX_RECORD_BYTES = 131072
MAX_SOURCE_BYTES = 32 * 1024 * 1024
SYSTEM_PYTHON = "/usr/bin/python3"
BOUNDED_DIRECTORY_LABEL = "bounded directory"
SAFE_ENV = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1"}


class CaseRunError(ValueError):
    """A bounded functional input or its live result could not be verified."""


def load_module(name: str, path: Path):
    module = load_source(path)
    return module


LAUNCHER = load_module("bounded_nginx_functional_launcher", source_path('connectors/nginx/harness/run_github_hosted_functional_a.py', root=ROOT))
PINS = load_module("bounded_nginx_revision_pins", source_path('ci/lib/framework_revision_pins.py', root=ROOT))
GROUPS = load_module("bounded_nginx_process_groups", source_path('ci/runtime/lifecycle/with-private-sockets.py', root=ROOT))


def run_fixed(command: list[str], *, env: dict[str, str], timeout: float = 30) -> bytes:
    result = subprocess.run(command, env=env, capture_output=True, timeout=timeout, check=False)
    if result.returncode != 0:
        raise CaseRunError("fixed native helper failed")
    if len(result.stdout) > 2 * 1024 * 1024:
        raise CaseRunError("fixed native helper exceeded its output bound")
    return result.stdout


def git_value(root: Path, *args: str) -> bytes:
    return run_fixed(["/usr/bin/git", "--no-replace-objects", "-c", f"safe.directory={root}",
                      "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
                      "-c", "core.attributesFile=/dev/null", "-C", str(root), *args], env=SAFE_ENV)


def regular_bytes(path: Path, *, limit: int = MAX_RECORD_BYTES) -> bytes:
    LAUNCHER._require_no_symlink_components(path, "bounded input")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size > limit:
            raise CaseRunError("bounded input must be a regular, singly linked bounded file")
        body = stream.read(limit + 1)
        if len(body) > limit:
            raise CaseRunError("bounded input exceeds its size limit")
        return body


def contained_directory(path: Path, parent: Path, *, owner: int | None = None, mode: int | None = None) -> Path:
    path = LAUNCHER._absolute_path(str(path), BOUNDED_DIRECTORY_LABEL)
    LAUNCHER._require_under(path, parent, BOUNDED_DIRECTORY_LABEL)
    LAUNCHER._require_directory(path, BOUNDED_DIRECTORY_LABEL)
    metadata = path.lstat()
    if owner is not None and metadata.st_uid != owner:
        raise CaseRunError("bounded directory has an unexpected owner")
    if mode is not None and stat.S_IMODE(metadata.st_mode) != mode:
        raise CaseRunError("bounded directory has an unexpected mode")
    return path


def native_environment(variant: str) -> dict[str, str]:
    if variant not in COUNTS:
        raise CaseRunError("unknown NGINX variant")
    return dict(SAFE_ENV, MODSECURITY_TEST_VARIANT=variant, FORCE_ALL_CASES="", NO_CRS_BASELINE="",
                CONNECTOR_ROOT=str(ROOT), FRAMEWORK_ROOT=str(FRAMEWORK))


def discover_cases(variant: str) -> list[Path]:
    body = run_fixed([SYSTEM_PYTHON, str(CASE_CLI), "list-cases", "--repo-root", str(ROOT),
                      "--framework-root", str(FRAMEWORK), "--connector-root", str(ROOT),
                      "--connector", "nginx", "--scope", "all"], env=native_environment(variant))
    paths = [Path(line) for line in body.decode("utf-8").splitlines()]
    if len(paths) != COUNTS[variant] or len(set(paths)) != len(paths):
        raise CaseRunError("native ordinary catalog has an unexpected case count or duplicate")
    for path in paths:
        if not path.is_absolute() or path.suffix != ".yaml":
            raise CaseRunError("native catalog contains an invalid case path")
        LAUNCHER._require_under(path, FRAMEWORK / "tests/cases", "native case")
        regular_bytes(path)
    return paths


def catalog_digest(cases: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in cases:
        digest.update(str(path.relative_to(FRAMEWORK)).encode() + b"\0")
        digest.update(hashlib.sha256(regular_bytes(path)).digest())
    return digest.hexdigest()


def verify_committed_inputs(expected_sha: str) -> None:
    # This privately loaded reader uses the same exact scoped Git adapter;
    # neither global Git configuration nor a wildcard safe.directory is used.
    PINS._git = git_value
    try:
        PINS.verify_framework_revision_pins(ROOT, expected_sha)
    except PINS.FrameworkRevisionPinsError as error:
        raise CaseRunError("committed Parent/Framework/MRTS identity does not agree") from error
    for repository, prefixes in (
        (ROOT, ("connectors/nginx/", "ci/runtime/common/", "ci/runtime/lifecycle/run-bounded-nginx-cases.py",
                "ci/runtime/lifecycle/with-private-sockets.py", "ci/lib/framework_revision_pins.py",
                "ci/lib/runtime_path_utils.py", "config/testing/")),
        (FRAMEWORK, ("ci/lib/", "tests/runners/", "tests/rules/", "tests/cases/", "tests/schema")),
    ):
        verify_source_blobs(repository, prefixes)


def source_tree(root: Path) -> list[tuple[str, str, Path]]:
    records = git_value(root, "ls-tree", "-r", "-z", "HEAD").split(b"\0")
    output = []
    for raw in records:
        if not raw:
            continue
        header, relative = raw.split(b"\t", 1)
        mode, kind, object_id = header.decode("ascii").split()
        path = Path(relative.decode("utf-8"))
        if path.is_absolute() or ".." in path.parts:
            raise CaseRunError("Git source tree contains an escaping path")
        if kind == "blob":
            output.append((mode, object_id, path))
    if len(output) > 8192:
        raise CaseRunError("Git source tree exceeds its file bound")
    return output


def verify_source_blobs(root: Path, prefixes: tuple[str, ...]) -> None:
    for mode, object_id, relative in source_tree(root):
        if not any(str(relative).startswith(prefix) for prefix in prefixes):
            continue
        if mode not in {"100644", "100755"}:
            raise CaseRunError("functional executable source is not a regular Git blob")
        body = regular_bytes(root / relative, limit=2 * 1024 * 1024)
        if body != git_value(root, "cat-file", "blob", object_id):
            raise CaseRunError("functional executable source differs from its exact committed blob")


def runtime_digest(env: dict[str, str]) -> str:
    digest = hashlib.sha256()
    paths = (Path(env["NGINX_BINARY"]), Path(env["NGINX_MODULE"]),
             Path(env["NGINX_FUNCTIONAL_A_RUNTIME_LIBRARY"]),
             FRAMEWORK / "tests/rules/no-crs-baseline.conf")
    for path in paths:
        digest.update(str(path).encode() + b"\0")
        digest.update(hashlib.sha256(regular_bytes(path, limit=256 * 1024 * 1024)).digest())
    return digest.hexdigest()


def crs_authority() -> dict[str, str]:
    common = regular_bytes(FRAMEWORK / "ci/lib/common.sh", limit=2 * 1024 * 1024).decode()
    expected = {}
    for key in ("CRS_APPROVED_REPO_URL", "CRS_APPROVED_COMMIT", "CRS_RELEASE_TAG"):
        match = re.search(r"^" + key + r"=\"([^\"\r\n]+)\"$", common, re.MULTILINE)
        if match is None:
            raise CaseRunError("exact Framework CRS authority is unavailable")
        expected[key] = match.group(1)
    return expected


def validate_crs_repository(crs: Path) -> None:
    expected = crs_authority()
    if git_value(crs, "rev-parse", "--show-toplevel").decode().strip() != str(crs):
        raise CaseRunError("CRS source is not its own fixed repository")
    checks = (("config", "--get", "remote.origin.url"), ("rev-parse", "HEAD"),
              ("rev-parse", expected["CRS_RELEASE_TAG"] + "^{commit}"))
    required = (expected["CRS_APPROVED_REPO_URL"], expected["CRS_APPROVED_COMMIT"], expected["CRS_APPROVED_COMMIT"])
    if any(git_value(crs, *command).decode().strip() != value for command, value in zip(checks, required)):
        raise CaseRunError("prepared CRS source identity disagrees with exact Framework authority")


def expected_crs_preamble(runtime: Path, crs: Path) -> bytes:
    lines = ["# Generated by ci/provisioning/prepare-crs.sh. Do not edit.", f"Include \"{runtime}/crs-setup.conf\""]
    plugins = crs / "plugins"
    if plugins.exists():
        lines.extend([f"Include \"{plugins}/*-config.conf\"", f"Include \"{plugins}/*-before.conf\""])
    lines.append(f"Include \"{crs}/rules/*.conf\"")
    if plugins.exists():
        lines.append(f"Include \"{plugins}/*-after.conf\"")
    return ("\n".join(lines) + "\n").encode()


def validate_include_tree(directory: Path, paths: set[Path]) -> None:
    if not directory.exists():
        return
    LAUNCHER._require_directory(directory, "CRS include directory")
    for index, candidate in enumerate(directory.rglob("*")):
        if index >= 8192:
            raise CaseRunError("prepared CRS include tree exceeds its entry bound")
        metadata = candidate.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode) or candidate not in paths:
            raise CaseRunError("prepared CRS include tree contains an untracked or non-regular entry")


def include_tree_digest(crs: Path) -> bytes:
    tree = source_tree(crs)
    paths = {crs / relative for _, _, relative in tree}
    if not paths or len(paths) > 4096:
        raise CaseRunError("prepared CRS source exceeds its file count bound")
    for directory in (crs / "rules", crs / "plugins"):
        validate_include_tree(directory, paths)
    digest = hashlib.sha256()
    total = 0
    for mode, object_id, relative in tree:
        if mode not in {"100644", "100755"}:
            raise CaseRunError("prepared CRS source contains a non-regular committed file")
        path = crs / relative
        LAUNCHER._require_under(path, crs, "CRS source file")
        body = regular_bytes(path, limit=MAX_SOURCE_BYTES)
        if body != git_value(crs, "cat-file", "blob", object_id):
            raise CaseRunError("prepared CRS source differs from its exact committed blob")
        total += len(body)
        if total > MAX_SOURCE_BYTES:
            raise CaseRunError("prepared CRS source exceeds its total size bound")
        digest.update(str(relative).encode() + b"\0" + hashlib.sha256(body).digest())
    return digest.digest()


def crs_digest(env: dict[str, str]) -> str:
    input_root = Path(env["BOUNDED_INPUT_ROOT"])
    build = contained_directory(Path(env["BOUNDED_BUILD_ROOT"]), input_root)
    source = contained_directory(Path(env["BOUNDED_SOURCE_ROOT"]), input_root)
    runtime = contained_directory(build / "crs", build)
    crs = contained_directory(source / "coreruleset", source)
    validate_crs_repository(crs)
    preamble = regular_bytes(runtime / "modsecurity-crs-preamble.conf")
    if preamble != expected_crs_preamble(runtime, crs):
        raise CaseRunError("prepared CRS preamble differs from the fixed native include contract")
    setup = regular_bytes(runtime / "crs-setup.conf", limit=MAX_SOURCE_BYTES)
    if setup != regular_bytes(crs / "crs-setup.conf.example", limit=MAX_SOURCE_BYTES):
        raise CaseRunError("prepared CRS setup differs from the exact source template")
    return hashlib.sha256(preamble + setup + include_tree_digest(crs)).hexdigest()


def root_assignments(command: list[str]) -> dict[str, str]:
    return dict((key, value) for key, value in (item.split("=", 1) for item in command[4:-2]))


def build_root_command(env: dict[str, str], variant: str, cases: list[Path]) -> list[str]:
    if variant == "no-crs":
        canonical_variant = "no-crs"
    elif variant == "with-crs":
        canonical_variant = "with-crs"
    else:
        raise CaseRunError("unknown NGINX root variant")
    command = LAUNCHER.build_root_command(env)
    values = root_assignments(command)
    input_root = Path(env["VERIFIED_RUN_ROOT"])
    build = contained_directory(Path(env["BUILD_ROOT"]), input_root)
    source = contained_directory(Path(env["SOURCE_ROOT"]), input_root)
    user = pwd.getpwnam(values["NGINX_WORKER_USER"])
    group = grp.getgrnam(values["NGINX_WORKER_GROUP"])
    if user.pw_uid == 0 or group.gr_gid == 0:
        raise CaseRunError("functional workers must have distinct non-root identities")
    values.update(BOUNDED_INPUT_ROOT=str(input_root), BOUNDED_BUILD_ROOT=str(build),
                  BOUNDED_SOURCE_ROOT=str(source), MODSECURITY_TEST_VARIANT=canonical_variant,
                  NO_CRS_BASELINE="", BOUNDED_CATALOG_SHA256=catalog_digest(cases))
    values["BOUNDED_RUNTIME_SHA256"] = runtime_digest(values)
    values["BOUNDED_CRS_SHA256"] = crs_digest(values) if canonical_variant == "with-crs" else ""
    if canonical_variant == "with-crs":
        values["MODSECURITY_RULE_PREAMBLE_FILE"] = str(build / "crs/modsecurity-crs-preamble.conf")
    return ["/usr/bin/sudo", "-n", "/usr/bin/env", "-i", *[f"{key}={value}" for key, value in values.items()],
            SYSTEM_PYTHON, "-I", str(Path(__file__).resolve()), "--root-runtime", "--variant", canonical_variant]


def fresh_directory(path: Path, *, owner: int, group: int, mode: int) -> None:
    LAUNCHER._require_directory(path.parent, "fresh directory parent")
    path.mkdir(mode=0o700)
    os.chown(path, owner, group)
    os.chmod(path, mode)
    if (path.lstat().st_uid, path.lstat().st_gid, stat.S_IMODE(path.lstat().st_mode)) != (owner, group, mode):
        raise CaseRunError("fresh directory did not retain its required identity")


def write_fresh(path: Path, body: bytes, *, owner: int, group: int) -> None:
    LAUNCHER._require_directory(path.parent, "fresh record parent")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        os.fchown(stream.fileno(), owner, group)
        stream.write(body)
        stream.flush()
        os.fsync(stream.fileno())


def case_environment(env: dict[str, str], case: Path, case_root: Path, index: int) -> dict[str, str]:
    allowed = {
        "PATH", "HOME", "LC_ALL", "PYTHONDONTWRITEBYTECODE", "CONNECTOR_ROOT", "FRAMEWORK_ROOT",
        "NGINX_PREFIX", "NGINX_BUILD_DIR", "NGINX_BINARY", "NGINX_MODULE", "MODSECURITY_LIB_DIR",
        "NGINX_FUNCTIONAL_A_RUNTIME_LIBRARY", "MODSECURITY_RULE_PREAMBLE_FILE", "MODSECURITY_TEST_VARIANT",
        "NGINX_WORKER_USER", "NGINX_WORKER_GROUP", "NGINX_PROTOCOL_PROFILE", "PYTHON", "CURL",
        "NGINX_LIFECYCLE_ENABLED",
    }
    values = {key: value for key, value in env.items() if key in allowed}
    for key, value in SAFE_ENV.items():
        values[key] = value
    values["PYTHON"] = SYSTEM_PYTHON
    values["CURL"] = "/usr/bin/curl"
    values.update(VERIFIED_RUN_ROOT=str(case_root.parent), VERIFIED_BUILD_ROOT=str(case_root), BUILD_ROOT=str(case_root),
                  LOG_ROOT=str(case_root / "harness/logs"), LOG_DIR=str(case_root / "harness/logs"), RESULTS_DIR=str(case_root / "results"),
                  NGINX_HARNESS_PARENT=str(case_root / "harness-parent"), NGINX_HARNESS_WORK_ROOT=str(case_root / "harness"),
                  RUNTIME_BASE=str(case_root / "runtime-base"), RUNTIME_ROOT=str(case_root / "runtime"),
                  TEST_CASE=str(case), RUN_ONE_CASE="1", FORCE_ALL_CASES="", NO_CRS_BASELINE="", CASE_SCOPE="all",
                  NGINX_HOSTED_FUNCTIONAL_A="1", NGINX_PHASE4_LOG_TARGET_MODE="regular", NGINX_PHASE4_LOG_SCOPE="location",
                  NGINX_PHASE4_LOG_LIFECYCLE_PROBE="0", NGINX_FUNCTIONAL_A_QUERY_CANARY="0", NGINX_USE_ERROR_LOG="on",
                  PORT=str(18081 + index), PORT_RETRY_LIMIT="1")
    return values


def _unique_record_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CaseRunError("native record contains duplicate JSON keys")
        result[key] = value
    return result


def _validate_record_identity(record: dict, case: Path, variant: str) -> None:
    if record.get("path") != str(case):
        raise CaseRunError("native case record names another catalog path")
    if record.get("executed_connector") != "nginx" or record.get("variant") != variant:
        raise CaseRunError("native case identity or variant disagrees")
    if not isinstance(record.get("name"), str) or not record["name"] or not isinstance(record.get("scope"), str):
        raise CaseRunError("native case record lacks its catalog identity")


def _validate_record_observation(record: dict) -> None:
    status = record.get("status")
    if status in {"pass", "fail"} and record.get("live_executed") is not True:
        raise CaseRunError("native case record has no live execution metadata")
    if status != "pass":
        return
    if record.get("operation_status") != "ok" or type(record.get("actual_status")) is not int:
        raise CaseRunError("passing native case has no actual HTTP observation")
    if record.get("observed_transport_result") == "http_status" and record.get("actual_status") != record.get("expected_status"):
        raise CaseRunError("passing native case has an HTTP status mismatch")


def decode_record(body: bytes, case: Path, variant: str, returncode: int) -> dict:
    try:
        record = json.loads(body, object_pairs_hook=_unique_record_keys)
    except ValueError as error:
        raise CaseRunError("live case has no valid normalized record") from error
    expected_status = {0: "pass", 77: "blocked", 78: "not_executable"}.get(returncode, "fail")
    if not isinstance(record, dict) or record.get("status") != expected_status:
        raise CaseRunError("native case status does not match the live harness exit")
    _validate_record_identity(record, case, variant)
    _validate_record_observation(record)
    return record


def run_case(case: Path, case_root: Path, env: dict[str, str], deadline: float) -> int:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise CaseRunError("complete NGINX catalog exceeded its time bound")
    log = case_root / "harness-output.log"
    descriptor = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        process = subprocess.Popen(["/bin/sh", str(HARNESS)], env=env, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        old_handlers = {}
        def interrupt(signum, _frame):
            os.killpg(process.pid, signum)
            raise CaseRunError("bounded NGINX case was interrupted")
        try:
            for signum in (signal.SIGINT, signal.SIGTERM):
                old_handlers[signum] = signal.signal(signum, interrupt)
            try:
                return process.wait(timeout=min(120, remaining))
            except subprocess.TimeoutExpired as error:
                raise CaseRunError("bounded NGINX case timed out") from error
        finally:
            try:
                remaining = GROUPS.stop_group(process.pid)
                process.wait(timeout=10)
                if GROUPS.live_group_members(process.pid):
                    raise CaseRunError("bounded NGINX case left an unverified live process group")
                if remaining and process.returncode == 0:
                    raise CaseRunError("successful native harness left live processes requiring termination")
            finally:
                for signum, handler in old_handlers.items():
                    signal.signal(signum, handler)


def project_case_failure(case_root: Path, receipt: Path, case: Path, variant: str,
                         index: int, returncode: int | None, expected_sha: str,
                         owner: int, group: int) -> Path:
    """Retain bounded diagnostic data, never a substitute normalized result."""
    contained_directory(case_root, case_root.parent, owner=0, mode=0o711)
    log = case_root / "harness-output.log"
    LAUNCHER._require_no_symlink_components(log, "native failure log")
    descriptor = os.open(log, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)) != (0, 0, 0o600)
                or before.st_size > MAX_RECORD_BYTES):
            raise CaseRunError("native failure log is not a private bounded root-owned regular file")
        body = stream.read(MAX_RECORD_BYTES + 1)
        after = os.fstat(stream.fileno())
        stable_fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
                         "st_size", "st_mtime_ns", "st_ctime_ns")
        if len(body) > MAX_RECORD_BYTES or any(getattr(before, key) != getattr(after, key) for key in stable_fields):
            raise CaseRunError("native failure log changed during bounded projection")
    # JSON escaping prevents terminal/workflow control sequences from being
    # interpreted. Keep both ends of longer logs within the projection bound.
    excerpt = body if len(body) <= 16384 else body[:8192] + b"\n[bounded excerpt]\n" + body[-8192:]
    diagnostic = {
        "schema_version": 1, "kind": "native-harness-failure-diagnostic",
        "parent_sha": expected_sha, "catalog_case": str(case.relative_to(FRAMEWORK)),
        "variant": variant, "case_index": index, "harness_exit": returncode,
        "harness_log_sha256": hashlib.sha256(body).hexdigest(),
        "harness_log_bytes": len(body), "excerpt_truncated": len(body) > 16384,
        "harness_output": excerpt.decode("utf-8", errors="replace"),
    }
    payload = (json.dumps(diagnostic, sort_keys=True, ensure_ascii=True) + "\n").encode("ascii")
    if len(payload) > MAX_RECORD_BYTES:
        raise CaseRunError("native failure projection exceeds its size limit")
    target = receipt / f"case-{index:03d}-failure.json"
    write_fresh(target, payload, owner=owner, group=group)
    return target


def execute_case_record(case: Path, case_root: Path, env: dict[str, str], deadline: float,
                        receipt: Path, variant: str, index: int, expected_sha: str,
                        owner: int, group: int) -> tuple[int, dict]:
    code = None
    try:
        code = run_case(case, case_root, env, deadline)
        record = decode_record(regular_bytes(case_root / "harness/logs/result.json"), case, variant, code)
    except (OSError, ValueError, subprocess.SubprocessError, RuntimeError) as error:
        try:
            target = project_case_failure(case_root, receipt, case, variant, index,
                                          code, expected_sha, owner, group)
        except (OSError, ValueError) as projection_error:
            raise CaseRunError(f"case-{index:03d} native harness exit={code}; private diagnostic rejected: {type(projection_error).__name__}") from error
        raise CaseRunError(f"case-{index:03d} native harness exit={code}; private diagnostic: {target}") from error
    return code, record



def _validate_fresh_receipt(env: dict[str, str]) -> tuple[Path, int, int]:
    receipt = Path(env["NGINX_FUNCTIONAL_A_EVIDENCE_ROOT"])
    owner = int(env["NGINX_FUNCTIONAL_A_EVIDENCE_OWNER_UID"])
    group = int(env["NGINX_FUNCTIONAL_A_EVIDENCE_OWNER_GID"])
    if owner <= 0 or group <= 0 or owner > 2147483647 or group > 2147483647:
        raise CaseRunError("functional receipt must belong to a non-root runner")
    contained_directory(receipt, Path(env["BOUNDED_INPUT_ROOT"]), owner=owner, mode=0o700)
    if receipt.lstat().st_gid != group:
        raise CaseRunError("functional receipt has an unexpected group")
    if any(receipt.iterdir()):
        raise CaseRunError("functional receipt directory is not fresh")
    return receipt, owner, group


def _verify_artifact_identities(
    env: dict[str, str], cases: list[Path], variant: str,
    artifact_error: str, crs_error: str,
) -> None:
    if catalog_digest(cases) != env["BOUNDED_CATALOG_SHA256"] or runtime_digest(env) != env["BOUNDED_RUNTIME_SHA256"]:
        raise CaseRunError(artifact_error)
    if variant == "with-crs" and crs_digest(env) != env["BOUNDED_CRS_SHA256"]:
        raise CaseRunError(crs_error)

def root_runtime(env: dict[str, str], variant: str) -> int:
    if os.geteuid() != 0:
        raise CaseRunError("fixed functional root entry requires root")
    if env.get("MODSECURITY_TEST_VARIANT") != variant:
        raise CaseRunError("root entry variant does not match its bounded input")
    verify_committed_inputs(env["EXPECTED_PARENT_SHA"])
    cases = discover_cases(variant)
    _verify_artifact_identities(env, cases, variant,
                                "root entry catalog or runtime identity changed",
                                "root entry CRS identity changed")
    parent = Path(env["NGINX_FUNCTIONAL_A_PARENT_ROOT"])
    contained_directory(parent, parent.parent, owner=0, mode=0o711)
    runtime = parent / ("nginx-bounded-cases-" + variant)
    fresh_directory(runtime, owner=0, group=0, mode=0o711)
    receipt, owner, group = _validate_fresh_receipt(env)
    deadline = time.monotonic() + 1500
    names = set()
    failed = False
    for index, case in enumerate(cases):
        case_root = runtime / f"case-{index:03d}"
        fresh_directory(case_root, owner=0, group=0, mode=0o711)
        values = case_environment(env, case, case_root, index)
        code, record = execute_case_record(case, case_root, values, deadline, receipt,
                                          variant, index, env["EXPECTED_PARENT_SHA"], owner, group)
        identity = (record["scope"], record["name"])
        if identity in names:
            raise CaseRunError("live catalog produced duplicate native identities")
        names.add(identity)
        record["catalog_case"] = str(case.relative_to(FRAMEWORK))
        record["runtime_evidence_path"] = str(case_root / "harness/logs/result.json")
        record["evidence_path"] = str(receipt / f"case-{index:03d}.json")
        write_fresh(receipt / f"case-{index:03d}.json", (json.dumps(record, sort_keys=True) + "\n").encode(), owner=owner, group=group)
        failed |= code != 0
    _verify_artifact_identities(env, cases, variant,
                                "functional artifact identity changed during execution",
                                "prepared CRS identity changed during execution")
    verify_committed_inputs(env["EXPECTED_PARENT_SHA"])
    return int(failed)


def complete_records(receipt: Path, cases: list[Path], variant: str) -> list[dict]:
    expected = {f"case-{index:03d}.json" for index in range(len(cases))}
    if {item.name for item in receipt.iterdir()} != expected:
        raise CaseRunError("receipt does not contain exactly the complete native catalog")
    records = []
    for index, case in enumerate(cases):
        target = receipt / f"case-{index:03d}.json"
        metadata = target.lstat()
        if metadata.st_uid != os.geteuid() or metadata.st_gid != os.getegid() or stat.S_IMODE(metadata.st_mode) != 0o600:
            raise CaseRunError("receipt record changed its runner identity or private mode")
        record = decode_record(regular_bytes(target), case, variant, 0)
        if record.get("catalog_case") != str(case.relative_to(FRAMEWORK)):
            raise CaseRunError("receipt case does not match the independently selected catalog")
        records.append(record)
    return records



def command_label(variant: str) -> str:
    if variant == "no-crs":
        return "make test-smoke-sequential-no-crs"
    if variant == "with-crs":
        return "make test-smoke-sequential-with-crs"
    raise CaseRunError("unknown bounded command label")

def summarize(env: dict[str, str], cases: list[Path], variant: str) -> None:
    results = contained_directory(Path(env["RESULTS_DIR"]), Path(env["VERIFIED_RUN_ROOT"]), owner=os.geteuid())
    receipt = Path(env["NGINX_FUNCTIONAL_A_EVIDENCE_ROOT"])
    records = complete_records(receipt, cases, variant)
    targets = [results / name for name in ("nginx-results.jsonl", "nginx-summary.json", "nginx-summary.txt", "nginx.rc")]
    if any(path.exists() or path.is_symlink() for path in targets):
        raise CaseRunError("native NGINX result target is already occupied")
    write_fresh(targets[0], b"".join((json.dumps(record, sort_keys=True) + "\n").encode() for record in records), owner=os.geteuid(), group=os.getegid())
    command = [SYSTEM_PYTHON, str(CASE_CLI), "summarize-results", "--connector", "nginx", "--input-jsonl", str(targets[0]),
               "--summary-json", str(targets[1]), "--summary-text", str(targets[2]), "--connector-path", "real-world",
               "--validation-mode", "real-world-connector-path", "--server", "nginx", "--runtime-mode", "default",
               "--command", command_label(variant), "--exit-status", "0", "--per-case-result-root", str(receipt),
               "--server-binary", str(Path(env["NGINX_PREFIX"]) / "sbin/nginx"),
               "--module", str(Path(env["NGINX_PREFIX"]) / "modules/ngx_http_modsecurity_module.so"),
               "--libmodsecurity", str(Path(env["MODSECURITY_LIB_DIR"]) / "libmodsecurity.so.3")]
    origin = json.loads(run_fixed(
        [SYSTEM_PYTHON, str(FRAMEWORK / "ci/lib/adapter_metadata.py"), "json", "nginx"],
        env=native_environment(variant),
    ))
    for option, key in (("source", "source_kind"), ("source-repo", "component"),
                        ("source-url", "source_url"), ("source-commit", "source_commit"),
                        ("source-version", "source_version"), ("license", "license")):
        command.extend(["--origin-" + option, origin[key]])
    command.extend(["--origin-imported-path", str(ROOT / origin["imported_path"])])
    run_fixed(command, env=native_environment(variant))
    run_fixed([SYSTEM_PYTHON, str(CASE_CLI), "validate-real-world-summary",
               "--summary-json", str(targets[1]), "--connector", "nginx", "--server", "nginx"],
              env=native_environment(variant))
    summary = json.loads(regular_bytes(targets[1], limit=2 * 1024 * 1024))
    section = summary.get("nginx", {})
    counts = section.get("summary", {})
    if section.get("attempted") != len(cases) or section.get("total_cases") != len(cases) or counts.get("pass") != len(cases):
        raise CaseRunError("native NGINX summary is incomplete")
    if any(counts.get(key, 0) != 0 for key in ("fail", "blocked", "not_executable", "skipped")):
        raise CaseRunError("native NGINX summary contains unsuccessful cases")
    write_fresh(targets[3], b"0\n", owner=os.geteuid(), group=os.getegid())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--variant", required=True, choices=tuple(COUNTS))
    parser.add_argument("--root-runtime", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    env = dict(os.environ)
    os.umask(0o077)
    try:
        if args.root_runtime:
            return root_runtime(env, args.variant)
        if os.geteuid() == 0:
            raise CaseRunError("preparation and normalization must run as the non-root workflow runner")
        verify_committed_inputs(env["EXPECTED_PARENT_SHA"])
        cases = discover_cases(args.variant)
        command = build_root_command(env, args.variant, cases)
        result = subprocess.run(command, env={"PATH": "/usr/bin:/bin"}, timeout=1560, check=False)
        if result.returncode != 0:
            raise CaseRunError("complete root functional case execution did not pass")
        summarize(env, cases, args.variant)
    except (OSError, KeyError, ValueError, subprocess.SubprocessError, RuntimeError) as error:
        print(f"bounded NGINX cases blocked: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
