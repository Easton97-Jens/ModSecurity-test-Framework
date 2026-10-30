#!/usr/bin/env python3
"""Build and exercise the native NGINX P4 response-buffer fixture.

The runner deliberately rebuilds NGINX, the connector module, and the
specified exact checkout.  It never reuses a previously built connector module
as evidence.  Its retained JSON report contains only lengths, hashes, flags,
and process results; raw loopback responses and NGINX logs stay in the private
task log directory.
"""

from __future__ import annotations

import argparse
import grp
import hashlib
import json
import os
import pwd
import re
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import time
from pathlib import Path
from typing import Any

from modsecurity_test_framework.connector_context import load_tool
from modsecurity_connector_ci.lib.runtime_path_utils import (
    canonical_project_roots, ensure_safe_runtime_directory, is_safe_runtime_root,
)


verify_trusted_directory = load_tool(
    "ci/checks/analysis/sonar-native-security/source_mapping.py"
).verify_trusted_directory


_NGINX_ERROR_LOG_NAME = 'error.log'


FIXTURE_PAYLOAD = b"P4-FIXTURE-BODY!"
FIXTURE_PAYLOAD_BYTES = len(FIXTURE_PAYLOAD)
FIXTURE_FILE_PAYLOAD = FIXTURE_PAYLOAD + b"X"
FIXTURE_SHORT_FILE_PAYLOAD = FIXTURE_PAYLOAD[:-1]
FIXTURE_MIXED_FILE_PAYLOAD = b"FILE-BACKING-XXXX"
FIXTURE_MIXED_FORWARDED_PAYLOAD = FIXTURE_MIXED_FILE_PAYLOAD[: len(FIXTURE_PAYLOAD)]
EXPECTED_NGINX_ROOT = "nginx-1.31.6"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
MAX_RESPONSE_BYTES = 256 * 1024
MAX_LOG_BYTES = 2 * 1024 * 1024


class FixtureFailure(RuntimeError):
    """A deterministic fixture precondition or observation failed."""


def fail(message: str) -> None:
    raise FixtureFailure(message)


def create_output_directory(path: Path, label: str) -> None:
    if (path.resolve() != path or not is_safe_runtime_root(path)
            or any(path.is_relative_to(source) or source.is_relative_to(path)
                   for source in canonical_project_roots())):
        fail(f"{label} must be a canonical external runtime path")
    ancestor = path
    while not ancestor.exists():
        ancestor = ancestor.parent
    try:
        verify_trusted_directory(ancestor)
        created = not path.exists()
        ensure_safe_runtime_directory(path)
        if created:
            path.chmod(0o700)
    except ValueError as exc:
        raise FixtureFailure(f"{label} has unsafe ancestry: {exc}") from exc


def require_absolute_directory(path: Path, label: str, *, create: bool = False) -> Path:
    if not path.is_absolute() or path == Path("/"):
        fail(f"{label} must be an absolute non-root path")
    if create:
        create_output_directory(path, label)
    try:
        details = path.lstat()
    except FileNotFoundError as exc:
        raise FixtureFailure(f"{label} is missing") from exc
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode):
        fail(f"{label} is not a real directory")
    if details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) & 0o022:
        fail(f"{label} has an unsafe owner or mode")
    resolved = path.resolve(strict=True)
    if resolved != path:
        fail(f"{label} resolves through a symlink")
    return path


def require_regular_file(path: Path, label: str) -> Path:
    try:
        details = path.lstat()
    except FileNotFoundError as exc:
        raise FixtureFailure(f"{label} is missing") from exc
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode):
        fail(f"{label} is not a regular non-symlink file")
    if details.st_nlink != 1:
        fail(f"{label} must not be hard-linked")
    if details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) & 0o022:
        fail(f"{label} has an unsafe owner or mode")
    return path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def classify_configtest_failure(output: str) -> str:
    """Return a bounded category without publishing private NGINX output."""
    normalized = output.lower()
    if "bind() to" in normalized and "address already in use" in normalized:
        return "listener_address_in_use"
    if "chown(" in normalized and "client_body_temp" in normalized:
        return "client_body_temp_ownership"
    if "permission denied" in normalized:
        return "permission_denied"
    if "unknown directive" in normalized:
        return "unknown_directive"
    return "unclassified"


def configtest_failure_summary(output: str) -> str:
    encoded = output.encode("utf-8", errors="replace")
    return (
        "configtest_output_sha256="
        + hashlib.sha256(encoded).hexdigest()
        + " configtest_failure_class="
        + classify_configtest_failure(output)
    )


def run(
    arguments: list[str], *, cwd: Path, environment: dict[str, str], log: Path
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        arguments,
        cwd=cwd,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    log.write_text(result.stdout, encoding="utf-8", errors="replace")
    if result.returncode != 0:
        summary = ""
        if "-t" in arguments:
            summary = "; " + configtest_failure_summary(result.stdout)
        fail(f"command failed ({result.returncode}): {' '.join(arguments)}; see {log}{summary}")
    return result


def safe_extract(archive: Path, destination: Path) -> Path:
    with tarfile.open(archive, mode="r:gz") as tar:
        members = tar.getmembers()
        if len(members) > 10000:
            fail("NGINX archive has too many members")
        for member in members:
            member_path = Path(member.name)
            if (
                member_path.is_absolute()
                or ".." in member_path.parts
                or member.issym()
                or member.islnk()
                or member.isdev()
            ):
                fail("NGINX archive contains an unsafe member")
        tar.extractall(destination, members=members)
    source = destination / EXPECTED_NGINX_ROOT
    if not source.is_dir() or source.is_symlink():
        fail("NGINX archive did not produce the expected source root")
    return source


def git_output(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments], cwd=root, text=True, capture_output=True, check=False
    )
    if result.returncode != 0:
        fail(f"git {' '.join(arguments)} failed")
    return result.stdout.strip()


def assert_exact_checkout(root: Path, expected_head: str) -> str:
    if not COMMIT.fullmatch(expected_head):
        fail("expected head must be a complete lowercase commit SHA")
    actual = git_output(root, "rev-parse", "HEAD^{commit}")
    if actual != expected_head:
        fail(f"checkout head mismatch: expected {expected_head}, observed {actual}")
    if git_output(root, "status", "--porcelain=v1"):
        fail("fixture requires a clean exact checkout")
    return actual


def choose_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def write_private(path: Path, content: bytes) -> None:
    if path.exists() or path.is_symlink():
        fail(f"refusing to replace fixture path: {path}")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        remaining = memoryview(content)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                fail(f"short write to fixture path: {path}")
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_config(
    path: Path,
    *,
    prefix: Path,
    port: int,
    body_file: Path,
    short_body_file: Path,
    mixed_body_file: Path,
    phase4_log: Path,
    response_body_limit: int,
    response_body_limit_action: str,
) -> None:
    if response_body_limit <= 0 or response_body_limit_action not in {"Reject", "ProcessPartial"}:
        fail("fixture requires explicit positive response limit and Reject/ProcessPartial action")
    try:
        nginx_user = pwd.getpwuid(os.geteuid()).pw_name
        nginx_group = grp.getgrgid(os.getegid()).gr_name
    except KeyError as exc:
        raise FixtureFailure("fixture runner cannot resolve its current NGINX identity") from exc
    if not re.fullmatch(r"[A-Za-z0-9_-]+", nginx_user) or not re.fullmatch(
        r"[A-Za-z0-9_-]+", nginx_group
    ):
        fail("fixture runner has an unsafe NGINX user or group name")

    def location(mode: str) -> str:
        return "\n".join(
            (
                f"    location = /{mode} {{",
                f"      body_buffer_fixture {mode};",
                f"      body_buffer_fixture_file {body_file};",
                f"      body_buffer_fixture_short_file {short_body_file};",
                f"      body_buffer_fixture_mixed_file {mixed_body_file};",
                "    }",
            )
        )

    modes = (
        "memory-within",
        "memory-over-limit",
        "file-within",
        "file-over-limit",
        "mixed-within",
        "mixed-over-limit",
        "invalid-metadata",
        "missing-source",
        "read-error",
        "short-read",
        "allocation-failure",
    )
    rules = prefix / "rules.conf"
    write_private(
        rules,
        b"SecRuleEngine On\n"
        b"SecRequestBodyAccess Off\n"
        b"SecResponseBodyAccess On\n"
        + f"SecResponseBodyLimit {response_body_limit}\nSecResponseBodyLimitAction {response_body_limit_action}\n".encode("ascii")
        +
        b"SecRule RESPONSE_BODY \"@contains P4-FIXTURE-BODY!\" \"id:1250001,phase:4,deny,status:403,log\"\n",
    )
    config = "\n".join(
        (
            f"user {nginx_user} {nginx_group};",
            "worker_processes 1;",
            f"error_log {prefix / 'logs' / _NGINX_ERROR_LOG_NAME} notice;",
            f"pid {prefix / 'logs' / 'nginx.pid'};",
            "events { worker_connections 32; }",
            "http {",
            "  access_log off;",
            "  default_type text/plain;",
            "  sendfile on;",
            "  server {",
            f"    listen 127.0.0.1:{port};",
            "    modsecurity on;",
            f"    modsecurity_rules_file {rules};",
            "    modsecurity_phase4_mode safe;",
            f"    modsecurity_phase4_log {phase4_log};",
            *(location(mode) for mode in modes),
            "  }",
            "}",
            "",
        )
    )
    write_private(path, config.encode("utf-8"))


def wait_for_listener(port: int, process: subprocess.Popen[str], log: Path) -> None:
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        if process.poll() is not None:
            fail(f"NGINX exited before listen readiness; see {log}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    fail("NGINX did not become ready")


def raw_request(port: int, path: str) -> bytes:
    request = (
        f"GET {path} HTTP/1.1\r\nHost: fixture.local\r\nConnection: close\r\n\r\n"
    ).encode("ascii")
    chunks: list[bytes] = []
    received = 0
    with socket.create_connection(("127.0.0.1", port), timeout=3.0) as client:
        client.settimeout(3.0)
        client.sendall(request)
        while True:
            try:
                chunk = client.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
            received += len(chunk)
            if received > MAX_RESPONSE_BYTES:
                fail("fixture response exceeded bound")
    return b"".join(chunks)


def response_body(response: bytes) -> bytes:
    marker = b"\r\n\r\n"
    if marker not in response:
        return b""
    return response.split(marker, 1)[1]


def read_bounded(path: Path, limit: int = MAX_LOG_BYTES) -> str:
    require_regular_file(path, "fixture output")
    if path.stat().st_size > limit:
        fail(f"fixture output exceeds {limit} bytes")
    return path.read_text(encoding="utf-8", errors="replace")


def require_fixture_log(
    error_log: str,
    mode: str,
    *,
    memory: bool,
    in_file: bool,
    representation: str,
    injection: str,
) -> None:
    expected = (
        "body-buffer-fixture connector-boundary "
        f"mode={mode} memory={int(memory)} in_file={int(in_file)}"
    )
    pattern = re.compile(
        re.escape(expected)
        + r"[^\n]*representation="
        + re.escape(representation)
        + r" injection="
        + re.escape(injection)
        + r"(?:,|\n|$)"
    )
    if pattern.search(error_log) is None:
        fail(f"connector-boundary buffer-state log missing: {expected}")


def require_healthy_worker(process: subprocess.Popen[str], error_log: str, mode: str) -> None:
    if process.poll() is not None:
        fail(f"NGINX master exited while serving {mode}")
    if re.search(r"worker process [0-9]+ exited on signal", error_log) is not None:
        fail(f"NGINX worker crashed while serving {mode}")


def require_static_fixture_filter_order(module_registration: Path) -> str:
    """Verify that the test-only fault filter directly surrounds the connector."""
    registration = read_bounded(module_registration)
    try:
        modules = registration.split("ngx_module_t *ngx_modules[] = {", 1)[1].split(
            "    NULL", 1
        )[0]
    except IndexError as exc:
        raise FixtureFailure("NGINX static module registration has an unexpected form") from exc
    ordered = (
        "ngx_http_modsecurity_module",
        "ngx_http_body_buffer_fixture_module",
        "ngx_http_postpone_filter_module",
    )
    positions = [modules.find(f"&{name}") for name in ordered]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        fail("static fixture filter does not follow connector before postpone filter")
    return sha256_file(module_registration)


def parse_events(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        fail("phase4 event log was not produced for legitimate controls")
    rows: list[dict[str, Any]] = []
    for line in read_bounded(path).splitlines():
        value = json.loads(line)
        if not isinstance(value, dict):
            fail("phase4 event log contains a non-object record")
        rows.append(value)
    return rows


def validate_positive_events(events: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    expected_bytes = {
        "/memory-within": FIXTURE_PAYLOAD_BYTES,
        "/memory-over-limit": FIXTURE_PAYLOAD_BYTES + 1,
        "/file-within": FIXTURE_PAYLOAD_BYTES,
        "/file-over-limit": FIXTURE_PAYLOAD_BYTES + 1,
        "/mixed-within": FIXTURE_PAYLOAD_BYTES,
        "/mixed-over-limit": FIXTURE_PAYLOAD_BYTES + 1,
    }
    observed: dict[str, list[dict[str, Any]]] = {
        path: [] for path in expected_bytes
    }
    for row in events:
        uri = row.get("uri")
        if uri not in observed:
            continue
        # Append/completion/cleanup telemetry shares the request URI but does
        # not claim the rule intervention being measured. Retain those rows
        # in the original event log; they cannot satisfy this accounting.
        if row.get("event") != "phase4_intervention":
            continue
        if (
            row.get("phase") != "response_body"
            or type(row.get("body_bytes_seen")) is not int
            or type(row.get("body_bytes_inspected")) is not int
            or type(row.get("body_truncated")) is not bool
            or type(row.get("truncated")) is not bool
            or type(row.get("eos_seen")) is not bool
            or
            row.get("rule_id") != "1250001"
            or
            row.get("body_bytes_seen") != expected_bytes[str(uri)]
            or row.get("body_bytes_inspected") != expected_bytes[str(uri)]
            or row.get("body_truncated") is not False
            or row.get("truncated") is not False
            or row.get("eos_seen") is not True
        ):
            fail(f"positive phase4 event accounting is invalid for {uri}")
        observed[str(uri)].append(
            {
                "body_bytes_seen": row["body_bytes_seen"],
                "body_bytes_inspected": row["body_bytes_inspected"],
                "body_truncated": row["body_truncated"],
                "truncated": row["truncated"],
                "eos_seen": row["eos_seen"],
                "rule_id": row["rule_id"],
            }
        )
    missing = [path for path, values in observed.items() if len(values) != 1]
    if missing:
        fail("positive phase4 event accounting is not exactly once for: " + ", ".join(sorted(missing)))
    return {path: values[0] for path, values in observed.items()}


def run_server_cases(
    *,
    nginx: Path,
    config: Path,
    prefix: Path,
    port: int,
    environment: dict[str, str],
    cases: tuple[tuple[str, bool, bool, bool, str, str, bytes, str], ...],
) -> list[dict[str, Any]]:
    log_path = prefix / "logs" / "nginx.stdout.log"
    with log_path.open("w", encoding="utf-8") as output:
        process = subprocess.Popen(
            [str(nginx), "-p", str(prefix), "-c", str(config), "-g", "daemon off;"],
            cwd=prefix,
            env=environment,
            text=True,
            stdout=output,
            stderr=subprocess.STDOUT,
        )
    try:
        wait_for_listener(port, process, log_path)
        observations: list[dict[str, Any]] = []
        for (
            mode,
            expect_success,
            memory,
            in_file,
            representation,
            injection,
            expected_body,
            forwarding_representation,
        ) in cases:
            response = raw_request(port, f"/{mode}")
            body = response_body(response)
            time.sleep(0.05)
            error_log = read_bounded(prefix / "logs" / _NGINX_ERROR_LOG_NAME)
            require_fixture_log(
                error_log,
                mode,
                memory=memory,
                in_file=in_file,
                representation=representation,
                injection=injection,
            )
            require_healthy_worker(process, error_log, mode)
            if expect_success:
                if body != expected_body:
                    fail(
                        f"{mode} did not forward the expected legitimate body "
                        f"(observed {len(body)} bytes: {body.hex()})"
                    )
            else:
                if body != b"":
                    fail(f"{mode} emitted {len(body)} body bytes after a required rejection")
            observations.append(
                {
                    "mode": mode,
                    "expected": "forwarded" if expect_success else "rejected_before_forwarding",
                    "buffer": {"memory": memory, "in_file": in_file},
                    "connector_boundary_representation": representation,
                    "connector_boundary_injection": injection,
                    "forwarding_representation": forwarding_representation,
                    "expected_forwarded_body_sha256": hashlib.sha256(expected_body).hexdigest(),
                    "response_bytes": len(response),
                    "response_body_bytes": len(body),
                    "rejected_before_forwarding": not expect_success and body == b"",
                }
            )
        return observations
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10.0)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5.0)


def prepare_prefix(root: Path, name: str) -> Path:
    prefix = root / name
    if prefix.exists() or prefix.is_symlink():
        fail(f"fixture prefix already exists: {prefix}")
    (prefix / "logs").mkdir(parents=True, mode=0o700)
    return prefix


def module_target(library: Path) -> Path:
    target = library.resolve(strict=True)
    details = target.lstat()
    if not stat.S_ISREG(details.st_mode) or stat.S_ISLNK(details.st_mode):
        fail("resolved ModSecurity library is not a regular file")
    return target


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--connector-root", required=True, type=Path)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--nginx-archive", required=True, type=Path)
    parser.add_argument("--nginx-sha256", required=True)
    parser.add_argument("--modsecurity-include", required=True, type=Path)
    parser.add_argument("--modsecurity-lib", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--response-body-limit", required=True, type=int)
    parser.add_argument("--response-body-limit-action", required=True, choices=("Reject", "ProcessPartial"))
    arguments = parser.parse_args(argv)

    connector_root = require_absolute_directory(arguments.connector_root, "connector root")
    output_root = require_absolute_directory(arguments.output_root, "output root", create=True)
    archive = require_regular_file(arguments.nginx_archive, "NGINX archive")
    if not SHA256.fullmatch(arguments.nginx_sha256):
        fail("NGINX SHA-256 must be lowercase hexadecimal")
    archive_digest = sha256_file(archive)
    if archive_digest != arguments.nginx_sha256:
        fail("NGINX archive SHA-256 mismatch")
    include_dir = require_absolute_directory(arguments.modsecurity_include, "ModSecurity include")
    lib_dir = require_absolute_directory(arguments.modsecurity_lib, "ModSecurity library directory")
    require_regular_file(include_dir / "modsecurity" / "modsecurity.h", "ModSecurity header")
    library = lib_dir / "libmodsecurity.so"
    if not library.exists():
        fail("ModSecurity linker library is missing")
    library_target = module_target(library)
    head = assert_exact_checkout(connector_root, arguments.expected_head)

    task_root = output_root / f"native-nginx-body-buffer-fixture-{head[:12]}"
    if task_root.exists() or task_root.is_symlink():
        fail(f"task output already exists: {task_root}")
    task_root.mkdir(mode=0o700)
    source_root = task_root / "source"
    build_root = task_root / "build"
    runtime_root = task_root / "runtime"
    logs_root = task_root / "logs"
    evidence_root = task_root / "evidence"
    for directory in (source_root, build_root, runtime_root, logs_root, evidence_root):
        directory.mkdir(mode=0o700)

    nginx_source = safe_extract(archive, source_root)
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(task_root),
        "LC_ALL": "C",
        "LANG": "C",
        "MODSECURITY_INC": str(include_dir),
        "MODSECURITY_LIB": str(lib_dir),
        "MSCONNECTOR_COMMON_INC": str(connector_root / "common" / "include"),
        "MSCONNECTOR_COMMON_SRC": str(connector_root / "common" / "src"),
        "MSCONNECTOR_PROFILE_REGISTRY_ROOT": str(connector_root),
    }
    configure = [
        "./configure",
        f"--prefix={build_root / 'prefix'}",
        "--with-compat",
        "--with-ld-opt=-Wl,--wrap=ngx_pnalloc",
        f"--add-module={connector_root / 'connectors' / 'nginx'}",
        f"--add-module={connector_root / 'tests' / 'nginx_body_buffer_fixture'}",
    ]
    run(configure, cwd=nginx_source, environment=environment, log=logs_root / "configure.log")
    jobs = str(min(2, max(1, os.cpu_count() or 1)))
    run(["make", f"-j{jobs}"], cwd=nginx_source, environment=environment, log=logs_root / "make.log")

    nginx = nginx_source / "objs" / "nginx"
    module_registration = nginx_source / "objs" / "ngx_modules.c"
    connector_body_filter_object = (
        nginx_source / "objs" / "addon" / "src" / "ngx_http_modsecurity_body_filter.o"
    )
    for path, label in (
        (nginx, "NGINX test binary"),
        (module_registration, "NGINX static module registration"),
        (connector_body_filter_object, "static connector body-filter object"),
    ):
        require_regular_file(path, label)
    module_registration_digest = require_static_fixture_filter_order(module_registration)

    body_file = runtime_root / "fixture-body.bin"
    short_body_file = runtime_root / "fixture-short-body.bin"
    mixed_body_file = runtime_root / "fixture-mixed-body.bin"
    phase4_log = runtime_root / "phase4.jsonl"
    write_private(body_file, FIXTURE_FILE_PAYLOAD)
    write_private(short_body_file, FIXTURE_SHORT_FILE_PAYLOAD)
    write_private(mixed_body_file, FIXTURE_MIXED_FILE_PAYLOAD)
    write_private(phase4_log, b"")
    normal_prefix = prepare_prefix(runtime_root, "normal")
    normal_config = normal_prefix / "nginx.conf"
    normal_port = choose_port()
    write_config(
        normal_config,
        prefix=normal_prefix,
        port=normal_port,
        body_file=body_file,
        short_body_file=short_body_file,
        mixed_body_file=mixed_body_file,
        phase4_log=phase4_log,
        response_body_limit=arguments.response_body_limit,
        response_body_limit_action=arguments.response_body_limit_action,
    )
    normal_environment = {**environment, "LD_LIBRARY_PATH": str(lib_dir)}
    run(
        [str(nginx), "-p", str(normal_prefix), "-c", str(normal_config), "-t"],
        cwd=normal_prefix,
        environment=normal_environment,
        log=logs_root / "nginx-configtest.log",
    )
    normal_cases = (
        ("memory-within", True, True, False, "preserved", "none", FIXTURE_PAYLOAD, "memory"),
        ("memory-over-limit", True, True, False, "preserved", "none", FIXTURE_FILE_PAYLOAD, "memory"),
        ("file-within", True, False, True, "file-only", "none", FIXTURE_PAYLOAD, "file"),
        ("file-over-limit", True, False, True, "file-only", "none", FIXTURE_FILE_PAYLOAD, "file"),
        (
            "mixed-within",
            True,
            True,
            True,
            "preserved",
            "none",
            FIXTURE_MIXED_FORWARDED_PAYLOAD,
            "file",
        ),
        ("mixed-over-limit", True, True, True, "preserved", "none", FIXTURE_MIXED_FILE_PAYLOAD, "file"),
        (
            "invalid-metadata",
            False,
            False,
            True,
            "file-only",
            "invalid-metadata",
            b"",
            "none",
        ),
        (
            "missing-source",
            False,
            False,
            True,
            "file-only",
            "missing-source",
            b"",
            "none",
        ),
        ("read-error", False, False, True, "file-only", "read-error", b"", "none"),
        ("short-read", False, False, True, "file-only", "short-read", b"", "none"),
    )
    observations = run_server_cases(
        nginx=nginx,
        config=normal_config,
        prefix=normal_prefix,
        port=normal_port,
        environment=normal_environment,
        cases=normal_cases,
    )
    events = parse_events(phase4_log)
    event_accounting = validate_positive_events(events)

    allocation_prefix = prepare_prefix(runtime_root, "allocation")
    allocation_config = allocation_prefix / "nginx.conf"
    allocation_port = choose_port()
    write_config(
        allocation_config,
        prefix=allocation_prefix,
        port=allocation_port,
        body_file=body_file,
        short_body_file=short_body_file,
        mixed_body_file=mixed_body_file,
        phase4_log=phase4_log,
        response_body_limit=arguments.response_body_limit,
        response_body_limit_action=arguments.response_body_limit_action,
    )
    allocation_environment = normal_environment
    run(
        [str(nginx), "-p", str(allocation_prefix), "-c", str(allocation_config), "-t"],
        cwd=allocation_prefix,
        environment=allocation_environment,
        log=logs_root / "nginx-allocation-configtest.log",
    )
    observations.extend(
        run_server_cases(
            nginx=nginx,
            config=allocation_config,
            prefix=allocation_prefix,
            port=allocation_port,
            environment=allocation_environment,
            cases=(
                (
                    "allocation-failure",
                    False,
                    False,
                    True,
                    "file-only",
                    "allocation-failure",
                    b"",
                    "none",
                ),
            ),
        )
    )
    allocation_error = read_bounded(allocation_prefix / "logs" / _NGINX_ERROR_LOG_NAME)
    if "cannot allocate file-backed response body scratch" not in allocation_error:
        fail("allocation-failure case did not reach the connector scratch allocation")
    if len(re.findall(
        r"body-buffer-fixture allocation-wrapper-hits=1(?:\D|$)", allocation_error
    )) != 1:
        fail("allocation-failure case did not record exactly one fixture wrapper hit")
    normal_error = read_bounded(normal_prefix / "logs" / _NGINX_ERROR_LOG_NAME)
    for expected_error, label in (
        ("invalid file-backed response body metadata", "invalid-metadata"),
        ("missing file-backed response body source", "missing-source"),
        ("file-backed response body read is short or failed", "read/short-read"),
    ):
        if expected_error not in normal_error:
            fail(f"{label} case did not reach its connector error branch")

    evidence: dict[str, Any] = {
        "schema_version": 1,
        "record_type": "nginx_native_body_buffer_fixture",
        "head": head,
        "nginx": {
            "version": "1.31.4",
            "archive_sha256": archive_digest,
            "binary_sha256": sha256_file(nginx),
            "connector_linkage": "static_test_binary",
            "module_registration_sha256": module_registration_digest,
            "allocation_filter_order": "connector_then_fixture_then_postpone",
            "connector_body_filter_object_sha256": sha256_file(connector_body_filter_object),
            "connector_body_filter_source_sha256": sha256_file(
                connector_root / "connectors" / "nginx" / "src" / "ngx_http_modsecurity_body_filter.c"
            ),
            "fixture_source_sha256": sha256_file(
                connector_root
                / "tests"
                / "nginx_body_buffer_fixture"
                / "ngx_http_body_buffer_fixture_module.c"
            ),
        },
        "modsecurity": {
            "library_target": library_target.name,
            "library_sha256": sha256_file(library_target),
            "response_body_limit": arguments.response_body_limit,
            "response_body_limit_action": arguments.response_body_limit_action,
        },
        "fixture": {
            "payload_bytes": FIXTURE_PAYLOAD_BYTES,
            "payload_sha256": hashlib.sha256(FIXTURE_PAYLOAD).hexdigest(),
            "file_payload_sha256": hashlib.sha256(FIXTURE_FILE_PAYLOAD).hexdigest(),
            "short_file_payload_sha256": hashlib.sha256(FIXTURE_SHORT_FILE_PAYLOAD).hexdigest(),
            "mixed_file_payload_sha256": hashlib.sha256(FIXTURE_MIXED_FILE_PAYLOAD).hexdigest(),
            "allocation_failure": "test_only_static_ngx_pnalloc_wrap_32768_byte_scratch",
            "allocation_wrapper_hits": 1,
            "overflow": "not_representable_on_this_64_bit_off_t_size_t_runtime",
        },
        "cases": observations,
        "positive_phase4_event_accounting": event_accounting,
        "phase4_event_log_sha256": sha256_file(phase4_log),
        "phase4_event_count": len(events),
        "exit_code": 0,
    }
    evidence_path = evidence_root / "result.json"
    write_private(
        evidence_path,
        (json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"),
    )
    print(f"native_nginx_body_buffer_fixture: PASS head={head} evidence={evidence_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except FixtureFailure as error:
        print(f"native_nginx_body_buffer_fixture: FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
