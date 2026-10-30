#!/usr/bin/env python3
"""Build and exercise the native NGINX P3 response-header fault fixture.

The runner rebuilds a static test NGINX from an exact clean checkout.  Two
test-only filter modules surround the real connector: a linker wrapper returns
success, zero, or a negative value from ``msc_process_response_headers`` and a
downstream observer proves whether the real connector forwarded headers.
Retained evidence contains only bounded state bits, lengths, and hashes.
"""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import argparse
import grp
import hashlib
import importlib.util
import json
import os
import pwd
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


ROOT = connector_root()
SHARED_RUNNER = source_path('tests/run_nginx_body_buffer_fixture.py', root=ROOT)
PAYLOAD = b"P3-HEADER-FIXTURE\n"
MAX_LOG_BYTES = 2 * 1024 * 1024


def load_shared_runner():
    module = load_source(SHARED_RUNNER)
    return module


SHARED = load_shared_runner()
FixtureFailure = SHARED.FixtureFailure


def fail(message: str) -> None:
    raise FixtureFailure(message)


def write_config(path: Path, *, prefix: Path, port: int) -> None:
    try:
        nginx_user = pwd.getpwuid(os.geteuid()).pw_name
        nginx_group = grp.getgrgid(os.getegid()).gr_name
    except KeyError as exc:
        raise FixtureFailure("fixture runner cannot resolve its current NGINX identity") from exc
    if not re.fullmatch(r"[A-Za-z0-9_-]+", nginx_user) or not re.fullmatch(
        r"[A-Za-z0-9_-]+", nginx_group
    ):
        fail("fixture runner has an unsafe NGINX user or group name")

    rules = prefix / "rules.conf"
    SHARED.write_private(
        rules,
        b"SecRuleEngine On\n"
        b"SecRequestBodyAccess Off\n"
        b"SecResponseBodyAccess Off\n",
    )

    def location(mode: str) -> str:
        return "\n".join(
            (
                f"    location = /{mode} {{",
                f"      p3_header_fixture {mode};",
                "    }",
            )
        )

    config = "\n".join(
        (
            f"user {nginx_user} {nginx_group};",
            "worker_processes 1;",
            f"error_log {prefix / 'logs' / 'error.log'} notice;",
            f"pid {prefix / 'logs' / 'nginx.pid'};",
            "events { worker_connections 32; }",
            "http {",
            "  access_log off;",
            "  default_type text/plain;",
            f"  client_body_temp_path {prefix / 'temp'} 1 2;",
            "  server {",
            f"    listen 127.0.0.1:{port};",
            "    modsecurity on;",
            f"    modsecurity_rules_file {rules};",
            *(location(mode) for mode in ("success", "zero", "negative", "zero-reinvoke")),
            "  }",
            "}",
            "",
        )
    )
    SHARED.write_private(path, config.encode("utf-8"))


def require_static_fixture_filter_order(module_registration: Path) -> str:
    registration = SHARED.read_bounded(module_registration)
    try:
        modules = registration.split("ngx_module_t *ngx_modules[] = {", 1)[1].split(
            "    NULL", 1
        )[0]
    except IndexError as exc:
        raise FixtureFailure("NGINX static module registration has an unexpected form") from exc
    ordered = (
        "ngx_http_p3_header_observer_fixture_module",
        "ngx_http_modsecurity_module",
        "ngx_http_p3_header_injector_fixture_module",
        "ngx_http_postpone_filter_module",
    )
    positions = [modules.find(f"&{name}") for name in ordered]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        fail("static P3 fixture ordering is not observer-connector-injector-postpone")
    return SHARED.sha256_file(module_registration)


def outcome_pattern(mode: str, *, failed: bool, reinvoked: bool) -> re.Pattern[str]:
    retry = "-1" if reinvoked else "-5"
    return re.compile(
        r"p3-header-fixture outcome mode="
        + re.escape(mode)
        + r" wrapper-hits=1 first-result="
        + (r"-1" if failed else r"0")
        + r" retry-result="
        + retry
        + r" terminal="
        + ("1" if failed else "0")
        + r" invalid-engine="
        + ("1" if failed else "0")
        + r" headers-seen="
        + ("0" if failed else "1")
        + r"(?:,|\n|$)"
    )


def cleanup_pattern(mode: str) -> re.Pattern[str]:
    return re.compile(
        r"p3-header-fixture cleanup mode="
        + re.escape(mode)
        + r" invalid-engine=1 headers-seen=0 cleanup-complete=1 transaction-null=1"
        + r"(?:,|\s|$)"
    )


def wait_for_case_log(
    *, prefix: Path, mode: str, failed: bool, reinvoked: bool
) -> str:
    deadline = time.monotonic() + 3.0
    expected_outcome = outcome_pattern(mode, failed=failed, reinvoked=reinvoked)
    expected_cleanup = cleanup_pattern(mode) if failed else None
    error_path = prefix / "logs" / "error.log"
    while time.monotonic() < deadline:
        error_log = SHARED.read_bounded(error_path, MAX_LOG_BYTES)
        if expected_outcome.search(error_log) and (
            expected_cleanup is None or expected_cleanup.search(error_log)
        ):
            return error_log
        time.sleep(0.05)
    fail(f"bounded P3 fixture state log missing for {mode}")


def check_response(*, mode: str, response: bytes, failed: bool) -> None:
    lowered = response.lower()
    downstream = b"x-p3-header-fixture-downstream: reached"
    if failed:
        if downstream in lowered:
            fail(f"{mode} reached the downstream header filter")
        if PAYLOAD in response:
            fail(f"{mode} emitted the fixture response body after native P3 failure")
        if b" 200 " in response.split(b"\r\n", 1)[0]:
            fail(f"{mode} returned a normal success response after native P3 failure")
        return
    if not response.startswith(b"HTTP/1.1 200"):
        fail(f"{mode} did not return the legitimate 200 control response")
    if downstream not in lowered:
        fail(f"{mode} did not reach the downstream header filter")
    if SHARED.response_body(response) != PAYLOAD:
        fail(f"{mode} did not emit the expected legitimate fixture body")


def run_cases(
    *, nginx: Path, config: Path, prefix: Path, port: int, environment: dict[str, str]
) -> tuple[list[dict[str, Any]], str]:
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
    cases = (
        ("success", False, False),
        ("zero", True, False),
        ("negative", True, False),
        ("zero-reinvoke", True, True),
        ("success", False, False),
    )
    observations: list[dict[str, Any]] = []
    try:
        SHARED.wait_for_listener(port, process, log_path)
        for ordinal, (mode, failed, reinvoked) in enumerate(cases, start=1):
            response = SHARED.raw_request(port, f"/{mode}")
            error_log = wait_for_case_log(
                prefix=prefix, mode=mode, failed=failed, reinvoked=reinvoked
            )
            SHARED.require_healthy_worker(process, error_log, f"{mode}-{ordinal}")
            check_response(mode=mode, response=response, failed=failed)
            observations.append(
                {
                    "ordinal": ordinal,
                    "mode": mode,
                    "native_result": "success" if not failed else ("negative" if mode == "negative" else "zero"),
                    "reinvoked": reinvoked,
                    "expected_downstream": not failed,
                    "expected_terminal_invalid_engine": failed,
                    "expected_cleanup_complete": failed,
                    "response_bytes": len(response),
                    "response_body_bytes": len(SHARED.response_body(response)),
                    "response_sha256": hashlib.sha256(response).hexdigest(),
                }
            )
        final_log = SHARED.read_bounded(prefix / "logs" / "error.log", MAX_LOG_BYTES)
        if len(re.findall(r"p3-header-observer downstream=1(?:,|\n|$)", final_log)) != 2:
            fail("downstream observer count does not match the two legitimate controls")
        for mode in ("zero", "negative", "zero-reinvoke"):
            if cleanup_pattern(mode).search(final_log) is None:
                fail(f"cleanup observation missing for {mode}")
        return observations, final_log
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10.0)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5.0)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--connector-root", required=True, type=Path)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--nginx-archive", required=True, type=Path)
    parser.add_argument("--nginx-sha256", required=True)
    parser.add_argument("--modsecurity-include", required=True, type=Path)
    parser.add_argument("--modsecurity-lib", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    arguments = parser.parse_args(argv)

    if os.geteuid() == 0:
        fail(
            "native NGINX P3 fixture must run as an unprivileged user; "
            "root-run services are not accepted as validation"
        )

    connector_root = SHARED.require_absolute_directory(
        arguments.connector_root, "connector root"
    )
    output_root = SHARED.require_absolute_directory(
        arguments.output_root, "output root", create=True
    )
    archive = SHARED.require_regular_file(arguments.nginx_archive, "NGINX archive")
    if not SHARED.SHA256.fullmatch(arguments.nginx_sha256):
        fail("NGINX SHA-256 must be lowercase hexadecimal")
    archive_digest = SHARED.sha256_file(archive)
    if archive_digest != arguments.nginx_sha256:
        fail("NGINX archive SHA-256 mismatch")
    include_dir = SHARED.require_absolute_directory(
        arguments.modsecurity_include, "ModSecurity include"
    )
    lib_dir = SHARED.require_absolute_directory(
        arguments.modsecurity_lib, "ModSecurity library directory"
    )
    SHARED.require_regular_file(
        include_dir / "modsecurity" / "modsecurity.h", "ModSecurity header"
    )
    library = lib_dir / "libmodsecurity.so"
    if not library.exists():
        fail("ModSecurity linker library is missing")
    library_target = SHARED.module_target(library)
    head = SHARED.assert_exact_checkout(connector_root, arguments.expected_head)

    task_root = output_root / f"native-nginx-p3-header-fixture-{head[:12]}"
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

    nginx_source = SHARED.safe_extract(archive, source_root)
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
        "--with-ld-opt=-Wl,--wrap=msc_process_response_headers",
        f"--add-module={connector_root / 'tests' / 'nginx_p3_header_observer_fixture'}",
        f"--add-module={connector_root / 'connectors' / 'nginx'}",
        f"--add-module={connector_root / 'tests' / 'nginx_p3_header_injector_fixture'}",
    ]
    SHARED.run(
        configure, cwd=nginx_source, environment=environment, log=logs_root / "configure.log"
    )
    jobs = str(min(2, max(1, os.cpu_count() or 1)))
    SHARED.run(
        ["make", f"-j{jobs}"], cwd=nginx_source, environment=environment,
        log=logs_root / "make.log"
    )

    nginx = nginx_source / "objs" / "nginx"
    module_registration = nginx_source / "objs" / "ngx_modules.c"
    for path, label in (
        (nginx, "NGINX test binary"),
        (module_registration, "NGINX static module registration"),
    ):
        SHARED.require_regular_file(path, label)
    module_registration_digest = require_static_fixture_filter_order(module_registration)

    prefix = SHARED.prepare_prefix(runtime_root, "p3-header")
    (prefix / "temp").mkdir(mode=0o700)
    config = prefix / "nginx.conf"
    port = SHARED.choose_port()
    write_config(config, prefix=prefix, port=port)
    runtime_environment = {**environment, "LD_LIBRARY_PATH": str(lib_dir)}
    SHARED.run(
        [str(nginx), "-p", str(prefix), "-c", str(config), "-t"],
        cwd=prefix,
        environment=runtime_environment,
        log=logs_root / "nginx-configtest.log",
    )
    observations, error_log = run_cases(
        nginx=nginx,
        config=config,
        prefix=prefix,
        port=port,
        environment=runtime_environment,
    )

    evidence: dict[str, Any] = {
        "schema_version": 1,
        "record_type": "nginx_native_p3_header_fixture",
        "head": head,
        "nginx": {
            "version": "1.31.4",
            "archive_sha256": archive_digest,
            "binary_sha256": SHARED.sha256_file(nginx),
            "connector_linkage": "static_test_binary",
            "module_registration_sha256": module_registration_digest,
            "header_filter_order": "observer_then_connector_then_injector",
        },
        "modsecurity": {
            "library_target": library_target.name,
            "library_sha256": SHARED.sha256_file(library_target),
        },
        "fixture": {
            "wrapper": "test_only_static_msc_process_response_headers",
            "downstream_observer": "test_only_static_header_filter",
            "reinvocation": "zero_result_reinvokes_real_connector_filter",
            "payload_sha256": hashlib.sha256(PAYLOAD).hexdigest(),
            "injector_source_sha256": SHARED.sha256_file(
                connector_root
                / "tests"
                / "nginx_p3_header_injector_fixture"
                / "ngx_http_p3_header_injector_fixture_module.c"
            ),
            "observer_source_sha256": SHARED.sha256_file(
                connector_root
                / "tests"
                / "nginx_p3_header_observer_fixture"
                / "ngx_http_p3_header_observer_fixture_module.c"
            ),
        },
        "cases": observations,
        "error_log_sha256": hashlib.sha256(error_log.encode("utf-8")).hexdigest(),
        "exit_code": 0,
    }
    evidence_path = evidence_root / "result.json"
    SHARED.write_private(
        evidence_path,
        (json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"),
    )
    print(f"native_nginx_p3_header_fixture: PASS head={head} evidence={evidence_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except FixtureFailure as error:
        print(f"native_nginx_p3_header_fixture: FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
