#!/usr/bin/env python3
"""Run one closed, configuration-only NGINX rejection contract.

This does not start a daemon, bind a listener, send HTTP, or create native
transaction events. Unit tests use controlled executables, not runtime proof.
"""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import sys
import time


CAPTURE_LIMIT = 65536
TIMEOUT_SECONDS = 10
ARTIFACT_LIMIT = 64 * 1024 * 1024
MISSING_RULES_FILE_NAME = "missing-rules.conf"


def rejection_contract(case_id: str, directive: str, value: str, *diagnostics: str) -> dict:
    """Construct the closed config-only rejection input, never observed evidence."""
    return {
        "operation": "configtest", "directive": directive, "value": value,
        "expected_exit_code": 1, "expected_outcome": "config_rejected",
        "error_class": case_id, "diagnostic_fragments": list(diagnostics),
    }


CONFIGTEST_CONTRACTS = {
    "invalid_status": rejection_contract(
        "invalid_status", "modsecurity_rules",
        'SecRule REQUEST_URI "@unconditionalMatch" "id:1100901,phase:1,deny,status:not-a-number"',
        '"modsecurity_rules" directive Rules error', "Expecting an action, got:  status:not-a-number"),
    "phase4_invalid_scope_file": rejection_contract(
        "phase4_invalid_scope_file", "modsecurity_phase4_content_types_file",
        "invalid-content-type-scope.txt", 'unknown directive "modsecurity_phase4_content_types_file"'),
    "phase4_wildcard_scope_rejected": rejection_contract(
        "phase4_wildcard_scope_rejected", "modsecurity_phase4_content_types_file",
        "wildcard-content-type-scope.txt", 'unknown directive "modsecurity_phase4_content_types_file"'),
    "missing_rules_file": rejection_contract(
        "missing_rules_file", "modsecurity_rules_file", MISSING_RULES_FILE_NAME,
        '"modsecurity_rules_file" directive', MISSING_RULES_FILE_NAME, "Failed to open the file"),
    "invalid_rule_syntax": rejection_contract(
        "invalid_rule_syntax", "modsecurity_rules", "SecRule REQUEST_URI",
        '"modsecurity_rules" directive', "syntax error"),
    "unknown_config_key": rejection_contract(
        "unknown_config_key", "modsecurity_unknown_config_key", "on",
        'unknown directive "modsecurity_unknown_config_key"'),
    "unsafe_event_path": rejection_contract(
        "unsafe_event_path", "modsecurity_phase4_log", "unsafe-event-directory",
        'modsecurity_phase4_log "', 'unsafe-event-directory" is not a secure private event file'),
    "invalid_boolean": rejection_contract(
        "invalid_boolean", "modsecurity", "maybe", '"modsecurity" directive', "invalid boolean value"),
    "invalid_size": rejection_contract(
        "removed_directive", "modsecurity_phase4_body_limit", "1048576",
        'unknown directive "modsecurity_phase4_body_limit"'),
}
CONFIGTEST_PATH_FIXTURES = {
    "missing_rules_file": (MISSING_RULES_FILE_NAME, "absent"),
    "unsafe_event_path": ("unsafe-event-directory", "directory"),
    "phase4_invalid_scope_file": ("invalid-content-type-scope.txt", "regular"),
    "phase4_wildcard_scope_rejected": ("wildcard-content-type-scope.txt", "regular"),
}
CONFIGTEST_REGULAR_FIXTURE_BYTES = {
    "phase4_invalid_scope_file": b"not a valid media type\n",
    "phase4_wildcard_scope_rejected": b"text/*\n",
}
PARENT_ROOT = connector_root()


from modsecurity_connector_ci.lib.runtime_path_utils import ensure_safe_runtime_directory, fixed_runtime_temp_parent

AUTHORIZED_STORAGE_ROOT = fixed_runtime_temp_parent() / "codex" / "ModSecurity-conector"


def absolute_path(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or not re.fullmatch(r"/[A-Za-z0-9_./-]+", value):
        raise ValueError("paths must be absolute and configuration-safe")
    if any(part in (".", "..") for part in value.split("/")):
        raise ValueError("paths must not contain traversal components")
    for candidate in (path, *path.parents):
        if candidate.is_symlink():
            raise ValueError("symlink paths are not authorized")
    return path


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_checkout(path: Path) -> bool:
    """A protected placeholder .git directory alone is not a checkout."""
    marker = path / ".git"
    return marker.is_file() or (marker / "HEAD").is_file()


def snapshot_artifact(path: Path, destination: Path, *, executable: bool) -> str:
    """Retain and hash bounded regular-file bytes via non-following descriptors."""
    result = hashlib.sha256()
    source_fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(source_fd, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > ARTIFACT_LIMIT:
            raise ValueError("artifact must be a regular file no larger than 64 MiB")
        destination_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o700 if executable else 0o600)
        with os.fdopen(destination_fd, "wb") as retained:
            total = 0
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                total += len(chunk)
                if total > ARTIFACT_LIMIT:
                    raise ValueError("artifact grew beyond the 64 MiB limit")
                result.update(chunk)
                retained.write(chunk)
    return result.hexdigest()


def empty_invocation_receipt() -> dict:
    """Unknown child facts stay null until an actual Popen succeeds."""
    return {"schema_version": 1, "invoked": False, "argv": None, "cwd": None,
            "pid": None, "returncode": None, "exit_code": None, "signal": None,
            "capture_failure": None, "stdout_sha256": None, "stderr_sha256": None}


def started_invocation_receipt(process: subprocess.Popen, cwd: str) -> dict:
    return dict(empty_invocation_receipt(), invoked=True, argv=list(process.args),
                cwd=cwd, pid=process.pid)


def completed_invocation_receipt(receipt: dict, returncode: int,
                                 stdout: bytes, stderr: bytes, failure: str | None) -> None:
    receipt.update(returncode=returncode, exit_code=returncode if returncode >= 0 else None,
                   signal=-returncode if returncode < 0 else None, capture_failure=failure,
                   stdout_sha256=digest(stdout), stderr_sha256=digest(stderr))


def capture_available(selector, captured, timeout):
    for key, _ in selector.select(timeout):
        chunk = os.read(key.fileobj.fileno(), 8192)
        if not chunk:
            selector.unregister(key.fileobj)
            continue
        capacity = CAPTURE_LIMIT - sum(map(len, captured.values()))
        captured[key.data].extend(chunk[:capacity])
        if len(chunk) > capacity:
            return "configtest_capture_limit"
    return None


def invoke(argv: list[str], environment: dict[str, str], *,
           invocation_receipt: dict | None = None) -> tuple[int, bytes, bytes, str | None]:
    """Capture both streams with a hard combined byte limit and deadline."""
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    failure = None
    receipt = {} if invocation_receipt is None else invocation_receipt
    receipt.update(empty_invocation_receipt())
    cwd = os.getcwd()
    with subprocess.Popen(argv, env=environment, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
        receipt.update(started_invocation_receipt(process, cwd))
        deadline = time.monotonic() + TIMEOUT_SECONDS
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    failure = "configtest_timeout"
                    break
                failure = capture_available(selector, captured, min(remaining, 0.2))
                if failure:
                    break
        if failure:
            process.kill()
        try:
            exit_code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            process.kill()
            exit_code = process.wait()
            failure = "configtest_timeout"
    stdout, stderr = bytes(captured["stdout"]), bytes(captured["stderr"])
    completed_invocation_receipt(receipt, exit_code, stdout, stderr, failure)
    return exit_code, stdout, stderr, failure


def argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case-id", required=True, choices=CONFIGTEST_CONTRACTS)
    for name in ("nginx-binary", "module", "output-root", "run-id", "parent-sha",
                 "framework-sha", "mrts-sha"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--library-dir")
    return parser


def validate_output_root(output: Path) -> None:
    storage_root = AUTHORIZED_STORAGE_ROOT
    if storage_root not in output.parents:
        raise ValueError("output must be under the authorized external task storage")
    if (output == PARENT_ROOT or PARENT_ROOT in output.parents
            or any(is_checkout(ancestor) for ancestor in output.parents
                   if ancestor != storage_root and storage_root in ancestor.parents)):
        raise ValueError("output must be outside the checkout")
    if output.exists() or not output.parent.is_dir():
        raise ValueError("output must be a fresh child of an existing external parent")
    ensure_safe_runtime_directory(output.parent)


def validate_inputs(args) -> tuple[Path, Path, Path]:
    binary, module, output = map(absolute_path, (args.nginx_binary, args.module, args.output_root))
    if not binary.is_file() or not os.access(binary, os.X_OK) or not module.is_file():
        raise ValueError("an executable binary and regular module are required")
    validate_output_root(output)
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", args.run_id):
        raise ValueError("run identity must be bounded and path-safe")
    for sha in (args.parent_sha, args.framework_sha, args.mrts_sha):
        if not re.fullmatch(r"[0-9a-f]{40}", sha):
            raise ValueError("exact source identities must be 40-character lowercase SHAs")
    return binary, module, output


def configtest_environment(library_dir: str | None) -> dict[str, str]:
    environment = {"PATH": os.defpath, "LANG": "C", "LC_ALL": "C"}
    if library_dir:
        library = absolute_path(library_dir)
        if not library.is_dir():
            raise ValueError("library directory must exist")
        environment["LD_LIBRARY_PATH"] = str(library)
    return environment


def retain_configtest_inputs(binary: Path, module: Path, output: Path, contract: dict) -> tuple:
    retained_binary = output / "nginx-binary"
    retained_module = output / "nginx-module.so"
    binary_sha = snapshot_artifact(binary, retained_binary, executable=True)
    module_sha = snapshot_artifact(module, retained_module, executable=False)
    value = contract["value"]
    fixture = CONFIGTEST_PATH_FIXTURES.get(contract["error_class"])
    if fixture is not None:
        leaf, state = fixture
        if state == "directory":
            (output / leaf).mkdir(mode=0o700)
        elif state == "regular":
            descriptor = os.open(output / leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(CONFIGTEST_REGULAR_FIXTURE_BYTES[contract["error_class"]])
        if not configtest_fixture_intact(contract["error_class"], output):
            raise ValueError("controlled path fixture does not match its closed initial state")
        value = f'"{output}/{leaf}"'
    elif contract["directive"] == "modsecurity_rules":
        value = json.dumps(value)
    configuration = (
        f'load_module "{retained_module}";\n'
        f'pid "{output}/nginx.pid";\n'
        f'error_log "{output}/nginx-error.log";\n'
        "events {}\nhttp {\n"
        f"  {contract['directive']} {value};\n"
        "}\n"
    ).encode("utf-8")
    config_path = output / "nginx.conf"
    config_path.write_bytes(configuration)
    return binary_sha, module_sha, configuration, config_path


def configtest_fixture_intact(case_id: str, output: Path) -> bool:
    """Check the fixed private leaf without following substituted symlinks."""
    fixture = CONFIGTEST_PATH_FIXTURES.get(case_id)
    if fixture is None:
        return True
    leaf, state = fixture
    directory = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    descriptor = None
    try:
        if state == "absent":
            try:
                os.stat(leaf, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                return True
            return False
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        if state == "directory":
            flags |= os.O_DIRECTORY
        descriptor = os.open(leaf, flags,
                             dir_fd=directory)
        info = os.fstat(descriptor)
        if state == "regular":
            return (stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                    and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
                    and info.st_size <= 512
                    and os.read(descriptor, 513) == CONFIGTEST_REGULAR_FIXTURE_BYTES[case_id])
        return (stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
                and stat.S_IMODE(info.st_mode) == 0o700 and not os.listdir(descriptor))
    except OSError:
        return False
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory)


def configtest_result(args, contract: dict, output: Path, artifacts: tuple, capture: tuple,
                      invocation_receipt: dict | None = None) -> tuple:
    binary_sha, module_sha, configuration, _ = artifacts
    exit_code, stdout, stderr, failure = capture
    text = stderr.decode("utf-8", errors="replace")
    fragments = contract["diagnostic_fragments"]
    matched = [fragment for fragment in fragments if fragment in text]
    expected_exit = contract["expected_exit_code"]
    fixture = CONFIGTEST_PATH_FIXTURES.get(args.case_id)
    if not configtest_fixture_intact(args.case_id, output):
        failure = failure or "configtest_fixture_changed"
    named_fixture = fixture is None or str(output / fixture[0]) in text
    if fixture is not None and fixture[1] == "regular":
        # Removed directives are rejected before their argument file is read.
        # Bind the genuine diagnostic to the exact retained config and line.
        named_fixture = f" in {output}/nginx.conf:6" in text
    passed = not failure and exit_code == expected_exit and matched == fragments and named_fixture
    receipt = {
        "schema_version": 1, "case_id": args.case_id, "connector": "nginx",
        "operation": "configtest", "run_id": args.run_id,
        "integration_mode": "native-nginx-http-module", "parent_sha": args.parent_sha,
        "framework_sha": args.framework_sha, "mrts_sha": args.mrts_sha,
        "binary_sha256": binary_sha, "module_sha256": module_sha,
        "config_path_identity": "sha256:" + digest(configuration),
        "directive": contract["directive"], "value": contract["value"],
        "expected_outcome": contract["expected_outcome"],
        "expected_exit_code": expected_exit, "observed_exit_code": exit_code,
        "observed_outcome": contract["expected_outcome"] if exit_code == expected_exit and not failure else "unexpected_outcome",
        "error_class": contract["error_class"] if passed else failure or "unexpected_config_error",
        "diagnostic_fragments": matched, "stdout_sha256": digest(stdout),
        "stderr_sha256": digest(stderr), "process_started": False, "listener_created": False,
        "native_parser_invocation": invocation_receipt,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    if fixture is not None:
        receipt.update(fixture_leaf=fixture[0], fixture_state=fixture[1])
        if fixture[1] == "regular" and configtest_fixture_intact(args.case_id, output):
            receipt["fixture_sha256"] = digest((output / fixture[0]).read_bytes())
    result = {"cases": [{"case_id": args.case_id, "status": "PASS" if passed else "FAIL",
                         "live_executed": failure != "configtest_exec_error",
                         "actual_status": exit_code, "observed_result": receipt["observed_outcome"],
                         "run_id": args.run_id, "integration_mode": receipt["integration_mode"],
                         "artifacts": {"configtest_dir": str(output)},
                         "configtest_receipt": receipt}]}
    return result, passed


def main() -> int:
    parser = argument_parser()
    args = parser.parse_args()
    contract = CONFIGTEST_CONTRACTS[args.case_id]
    try:
        binary, module, output = validate_inputs(args)
        environment = configtest_environment(args.library_dir)
        output.mkdir(mode=0o700)
        artifacts = retain_configtest_inputs(binary, module, output, contract)
        invocation_receipt = empty_invocation_receipt()
        try:
            exit_code, stdout, stderr, failure = invoke(
                [str(output / "nginx-binary"), "-e", "stderr", "-t", "-c", str(artifacts[3]), "-p", str(output) + "/"], environment,
                invocation_receipt=invocation_receipt,
            )
        except OSError:
            exit_code, stdout, stderr, failure = -1, b"", b"", "configtest_exec_error"
            invocation_receipt["capture_failure"] = failure
        (output / "stdout.log").write_bytes(stdout)
        (output / "stderr.log").write_bytes(stderr)
        result, passed = configtest_result(args, contract, output, artifacts,
                                          (exit_code, stdout, stderr, failure), invocation_receipt)
        (output / "source-result.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        (output / "source-result.jsonl").write_text(
            json.dumps(result["cases"][0], sort_keys=True) + "\n", encoding="utf-8",
        )
        return 0 if passed else 1
    except (ValueError, OSError) as error:
        parser.exit(2, "configtest input/output rejected: " + str(error) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
