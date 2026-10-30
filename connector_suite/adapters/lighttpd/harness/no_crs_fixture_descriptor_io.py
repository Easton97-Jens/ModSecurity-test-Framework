#!/usr/bin/env python3
"""Descriptor-bound lifecycle I/O for the private No-CRS entity fixture.

The shell harness owns the helper process and its PID.  This helper owns the
fixture directory descriptor and never uses the mutable fixture pathname for
artifact reads, writes, curl header capture, diagnostics, or cleanup.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time

import connector_suite.adapters.lighttpd.harness.lighttpd_http1_entity_fixture_upstream as entity_fixture
from connector_suite.adapters.lighttpd.harness.namespace_fixture_directory import NamespaceFixtureDirectory, create_namespace_fixture_directory, open_namespace_fixture_directory


FIXTURE_PREFIX = ".entity-fixtures-"
LEGACY_FIXTURE_NAMES = ("entity-fixtures",)
FIXTURE_ARTIFACTS = (
    "upstream-ready.json",
    "result.json",
    "upstream.stdout",
    "upstream.stderr",
    "content-length.headers",
    "chunked.headers",
)
READY_FILE = "upstream-ready.json"
RESULT_FILE = "result.json"
UPSTREAM_STDOUT = "upstream.stdout"
UPSTREAM_STDERR = "upstream.stderr"
MAX_READY_BYTES = 16 * 1024
MAX_HEADER_BYTES = 64 * 1024
MAX_DIAGNOSTIC_BYTES = 64 * 1024
MAX_TIMEOUT_SECONDS = 30.0
MAX_CURL_OUTPUT_BYTES = MAX_HEADER_BYTES + 3
HTTP_STATUS_LINE = re.compile(rb"HTTP/1\.1 200 [ -~]+")
CONTENT_LENGTH_VALUE = re.compile(rb"\d+")
STATUS_CODE_VALUE = re.compile(rb"\d{3}")

_CURL_CASES = {
    "content-length": (
        "content-length.headers",
        "/p4/fixture/content-length",
        "lighttpd-p4-content-length",
    ),
    "chunked": (
        "chunked.headers",
        "/p4/fixture/chunked",
        "lighttpd-p4-chunked",
    ),
}


def bounded_timeout(value: str) -> float:
    try:
        timeout = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("timeout must be numeric") from error
    if not 0 < timeout <= MAX_TIMEOUT_SECONDS:
        raise argparse.ArgumentTypeError(
            f"timeout must be in the range (0, {MAX_TIMEOUT_SECONDS:g}]"
        )
    return timeout


def valid_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("port must be an integer") from error
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def valid_pid(value: str) -> int:
    try:
        pid = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("pid must be an integer") from error
    if pid <= 0:
        raise argparse.ArgumentTypeError("pid must be positive")
    return pid


def open_fixture_directory(args: argparse.Namespace) -> NamespaceFixtureDirectory:
    return open_namespace_fixture_directory(
        args.runtime_output_root,
        name=args.fixture_name,
        identity=args.fixture_identity,
    )


def create_fixture_directory(args: argparse.Namespace) -> int:
    with create_namespace_fixture_directory(
        args.runtime_output_root,
        prefix=FIXTURE_PREFIX,
        rejected_names=LEGACY_FIXTURE_NAMES,
    ) as directory:
        if directory.name is None:
            raise ValueError("new fixture directory has no direct name")
        print(f"{directory.name}\t{directory.identity}")
    return 0


def verify_fixture_directory(args: argparse.Namespace) -> int:
    directory = open_fixture_directory(args)
    directory.close()
    print("verified")
    return 0


def _redirect_fixture_logs(directory: NamespaceFixtureDirectory) -> None:
    stdout_descriptor = directory.create_empty_file(UPSTREAM_STDOUT, "fixture stdout")
    stderr_descriptor = directory.create_empty_file(UPSTREAM_STDERR, "fixture stderr")
    try:
        os.dup2(stdout_descriptor, sys.stdout.fileno())
        os.dup2(stderr_descriptor, sys.stderr.fileno())
    finally:
        os.close(stdout_descriptor)
        os.close(stderr_descriptor)


def serve_fixture(args: argparse.Namespace) -> int:
    with open_fixture_directory(args) as directory:
        _redirect_fixture_logs(directory)
        entity_fixture.serve_bound(
            directory=directory,
            ready_name=READY_FILE,
            result_name=RESULT_FILE,
            host="127.0.0.1",
            port=0,
            timeout=args.timeout,
            inter_part_delay=0.35,
        )
    return 0


def _ready_port(directory: NamespaceFixtureDirectory) -> int:
    raw = directory.read_text(READY_FILE, "fixture ready record", maximum_bytes=MAX_READY_BYTES)
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("fixture ready record is not an object")
    if value.get("schema_version") != 1:
        raise ValueError("fixture ready record schema is invalid")
    if value.get("evidence_type") != "lighttpd_http1_entity_fixture_ready":
        raise ValueError("fixture ready record type is invalid")
    if value.get("upstream_host") != "127.0.0.1":
        raise ValueError("fixture ready record host is invalid")
    port = value.get("upstream_port")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ValueError("fixture ready record port is invalid")
    if value.get("body_payload_persisted") is not False:
        raise ValueError("fixture ready record must be payload-free")
    return port


def wait_for_ready(args: argparse.Namespace) -> int:
    deadline = time.monotonic() + args.timeout
    while True:
        try:
            with open_fixture_directory(args) as directory:
                print(_ready_port(directory))
            return 0
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        if time.monotonic() >= deadline:
            raise ValueError("fixture did not publish a descriptor-bound ready record")
        try:
            os.kill(args.fixture_pid, 0)
        except ProcessLookupError as error:
            raise ValueError("fixture exited before publishing its ready record") from error
        except PermissionError as error:
            raise ValueError("fixture PID cannot be inspected") from error
        time.sleep(0.1)


def _curl_binary() -> str:
    candidate = shutil.which("curl")
    if candidate is None:
        raise ValueError("curl is required for the descriptor-bound fixture probe")
    path = Path(candidate)
    details = path.stat()
    if not stat.S_ISREG(details.st_mode) or not os.access(path, os.X_OK):
        raise ValueError("resolved curl binary is not an executable regular file")
    return str(path)


def _parse_response_headers(value: bytes, case: str) -> list[tuple[bytes, bytes]]:
    if len(value) > MAX_HEADER_BYTES:
        raise ValueError(f"{case} response headers exceed the bounded size")
    if value.count(b"\r\n\r\n") != 1 or not value.endswith(b"\r\n\r\n"):
        raise ValueError(f"{case} response must contain exactly one complete HTTP header block")
    lines = value[:-4].split(b"\r\n")
    if not lines or HTTP_STATUS_LINE.fullmatch(lines[0]) is None:
        raise ValueError(f"{case} response has an unexpected HTTP status line")
    parsed: list[tuple[bytes, bytes]] = []
    for line in lines[1:]:
        name, separator, header_value = line.partition(b":")
        if not separator or not name or any(byte < 0x20 or byte > 0x7E for byte in line):
            raise ValueError(f"{case} response contains an invalid header row")
        parsed.append((name.strip().lower(), header_value.strip()))
    return parsed


def _validate_case_headers(case: str, value: bytes) -> None:
    headers = _parse_response_headers(value, case)
    content_length = [header for name, header in headers if name == b"content-length"]
    transfer_encoding = [header for name, header in headers if name == b"transfer-encoding"]
    if case == "content-length":
        if len(content_length) != 1 or CONTENT_LENGTH_VALUE.fullmatch(content_length[0]) is None:
            raise ValueError("Content-Length fixture response lost its Content-Length boundary")
        if any(value.lower() == b"chunked" for value in transfer_encoding):
            raise ValueError("Content-Length fixture response was relabelled as chunked")
        return
    if case == "chunked":
        if len(transfer_encoding) != 1 or transfer_encoding[0].lower() != b"chunked":
            raise ValueError("chunked fixture response lost its chunked boundary")
        return
    raise ValueError("unrecognized descriptor-bound fixture curl case")


def _stop_owned_curl(process: subprocess.Popen[bytes]) -> None:
    """Bound termination to the curl process started by this helper."""

    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def _bounded_curl_output(command: list[str], case: str) -> bytes:
    """Capture headers plus the fixed status suffix without unbounded memory."""

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if process.stdout is None:
        _stop_owned_curl(process)
        raise ValueError(f"{case} fixture curl did not create a stdout pipe")
    chunks: list[bytes] = []
    total = 0
    try:
        while True:
            chunk = os.read(
                process.stdout.fileno(),
                min(8192, MAX_CURL_OUTPUT_BYTES + 1 - total),
            )
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_CURL_OUTPUT_BYTES:
                _stop_owned_curl(process)
                raise ValueError(f"{case} fixture curl output exceeds the bounded limit")
            chunks.append(chunk)
        try:
            status = process.wait(timeout=MAX_TIMEOUT_SECONDS + 5)
        except subprocess.TimeoutExpired as error:
            _stop_owned_curl(process)
            raise ValueError(f"{case} fixture curl timed out") from error
        if status != 0:
            raise ValueError(f"{case} fixture curl failed with status {status}")
        return b"".join(chunks)
    finally:
        process.stdout.close()
        _stop_owned_curl(process)


def curl_fixture_case(args: argparse.Namespace) -> int:
    header_name, request_path, transaction_id = _CURL_CASES[args.case]
    with open_fixture_directory(args) as directory:
        response = _bounded_curl_output(
            [
                _curl_binary(),
                "--http1.1",
                "--silent",
                "--show-error",
                "--no-buffer",
                "--connect-timeout",
                "5",
                "--max-time",
                "30",
                "--dump-header",
                "-",
                "--output",
                "/dev/null",
                "--write-out",
                "%{http_code}",
                "--header",
                f"X-Modsec-Transaction-Id: {transaction_id}",
                f"http://127.0.0.1:{args.port}{request_path}",
            ],
            args.case,
        )
        if len(response) < 3 or STATUS_CODE_VALUE.fullmatch(response[-3:]) is None:
            raise ValueError(f"{args.case} fixture curl did not emit one HTTP status")
        status = response[-3:]
        headers = response[:-3]
        directory.write_bytes_fresh(header_name, headers, f"{args.case} response headers")
        persisted = directory.read_bytes(
            header_name,
            f"{args.case} response headers",
            maximum_bytes=MAX_HEADER_BYTES,
        )
        if persisted != headers:
            raise ValueError(f"{args.case} response header artifact changed after capture")
        _validate_case_headers(args.case, persisted)
        print(status.decode("ascii"))
    return 0


def print_fixture_diagnostics(args: argparse.Namespace) -> int:
    with open_fixture_directory(args) as directory:
        value = directory.read_bytes(
            UPSTREAM_STDERR,
            "fixture stderr",
            maximum_bytes=MAX_DIAGNOSTIC_BYTES,
        )
    sys.stdout.buffer.write(value)
    return 0


def cleanup_fixture_directory(args: argparse.Namespace) -> int:
    with open_fixture_directory(args) as directory:
        directory.verify_allowed_leaves(FIXTURE_ARTIFACTS)
    # The direct child and every verified leaf intentionally remain until the
    # private tmpfs is released by the Mount/PID namespace supervisor. There
    # is no path-based unlink or stat(name)-then-rmdir(name) fallback.
    print("leaves-retained-for-namespace-lifecycle")
    return 0


def add_fixture_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--runtime-output-root", required=True, type=Path)
    parser.add_argument("--fixture-name", required=True)
    parser.add_argument("--fixture-identity", required=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    create = commands.add_parser("create")
    create.add_argument("--runtime-output-root", required=True, type=Path)
    create.set_defaults(handler=create_fixture_directory)

    verify = commands.add_parser("verify")
    add_fixture_arguments(verify)
    verify.set_defaults(handler=verify_fixture_directory)

    serve = commands.add_parser("serve")
    add_fixture_arguments(serve)
    serve.add_argument("--timeout", type=bounded_timeout, default=MAX_TIMEOUT_SECONDS)
    serve.set_defaults(handler=serve_fixture)

    ready = commands.add_parser("wait-ready")
    add_fixture_arguments(ready)
    ready.add_argument("--fixture-pid", required=True, type=valid_pid)
    ready.add_argument("--timeout", type=bounded_timeout, default=MAX_TIMEOUT_SECONDS)
    ready.set_defaults(handler=wait_for_ready)

    curl = commands.add_parser("curl-case")
    add_fixture_arguments(curl)
    curl.add_argument("--case", choices=tuple(_CURL_CASES), required=True)
    curl.add_argument("--port", type=valid_port, required=True)
    curl.set_defaults(handler=curl_fixture_case)

    diagnostics = commands.add_parser("diagnostics")
    add_fixture_arguments(diagnostics)
    diagnostics.set_defaults(handler=print_fixture_diagnostics)

    cleanup = commands.add_parser("cleanup")
    add_fixture_arguments(cleanup)
    cleanup.set_defaults(handler=cleanup_fixture_directory)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except (
        entity_fixture.FixtureError,
        OSError,
        ValueError,
        subprocess.TimeoutExpired,
    ) as error:
        print(f"no_crs_fixture_descriptor_io: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
