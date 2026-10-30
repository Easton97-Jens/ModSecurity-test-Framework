#!/usr/bin/env python3
"""Bounded Stock-lighttpd lifecycle probes.

The probe intentionally records transport/process outcomes only.  Stock
lighttpd has no patched stream callback, so these cases never promote an
abort/termination into a connector event claim.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import socket
import stat
import time


MAX_PARALLEL = 8
MAX_RECEIPT_BYTES = 65536
TRUSTED_RUNTIME_ROOT: Path | None = None


class ProbeFailure(RuntimeError):
    pass


class ProbeBlocked(RuntimeError):
    pass


def _loopback_port(value: int) -> int:
    if type(value) is not int or not 1024 <= value <= 65535:
        raise ProbeFailure("network port must be an unprivileged TCP port")
    return value


def _safe_write(path: Path, payload: dict[str, object]) -> None:
    runtime_root = TRUSTED_RUNTIME_ROOT
    if runtime_root is None:
        raise ProbeFailure("trusted runtime root is required")
    runtime_root = Path(os.path.abspath(runtime_root))
    if not path.is_absolute() or path.name in ("", ".", ".."):
        raise ProbeFailure("receipt path must be absolute and have a filename")
    if runtime_root != runtime_root.resolve(strict=True) or path != Path(os.path.abspath(path)):
        raise ProbeFailure("runtime root and receipt path must be normalized and have no symlink")
    try:
        details = runtime_root.stat()
    except OSError as exc:
        raise ProbeFailure("trusted runtime root cannot be inspected") from exc
    if not stat.S_ISDIR(details.st_mode) or details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) != 0o700 or path.parent != runtime_root or path.is_symlink():
        raise ProbeFailure("receipt must be a direct child of the trusted runtime root")
    data = (json.dumps(payload, sort_keys=True) + "\n").encode()
    if len(data) > MAX_RECEIPT_BYTES:
        raise ProbeFailure("receipt exceeds bounded size")
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    if not getattr(os, "O_DIRECTORY", 0) or not no_follow:
        raise ProbeFailure("private receipt writes require directory and no-follow support")
    try:
        parent_fd = os.open(path.parent, directory_flags)
    except OSError as exc:
        raise ProbeFailure("receipt parent could not be opened as a private runtime root") from exc
    try:
        current = os.fstat(parent_fd)
        if not stat.S_ISDIR(current.st_mode) or current.st_uid != os.geteuid() or stat.S_IMODE(current.st_mode) != 0o700:
            raise ProbeFailure("receipt parent changed or is not a private runtime root")
        try:
            fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | no_follow, 0o600, dir_fd=parent_fd)
        except OSError as exc:
            raise ProbeFailure("receipt must be a fresh non-symlink file") from exc
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
    finally:
        os.close(parent_fd)


def _request(port: int, block: bool = False) -> int:
    port = _loopback_port(port)
    extra = b"X-Modsec-Smoke: block\r\n" if block else b""
    with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
        sock.settimeout(3)
        sock.sendall(b"OPTIONS * HTTP/1.1\r\nHost: stock-lifecycle\r\nConnection: close\r\n" + extra + b"\r\n")
        line = sock.recv(4096).split(b"\r\n", 1)[0].split()
    if len(line) < 2 or line[0] != b"HTTP/1.1":
        raise ProbeFailure("invalid HTTP/1.1 response")
    return int(line[1])


def client_abort(port: int, upstream_port: int, receipt: Path, timeout: float, backend_read_timeout: float) -> None:
    port = _loopback_port(port)
    upstream_port = _loopback_port(upstream_port)
    if not 1 <= backend_read_timeout <= 30 or backend_read_timeout >= timeout:
        raise ProbeFailure("backend read timeout must be below the overall probe timeout")
    started = time.monotonic()
    deadline = time.monotonic() + timeout
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", upstream_port))
        listener.listen(1)
        with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
            client.settimeout(3)
            client.sendall(b"GET /p4/close/ HTTP/1.1\r\nHost: stock-abort\r\nConnection: close\r\n\r\n")
            listener.settimeout(max(0.1, deadline - time.monotonic()))
            try:
                upstream, _ = listener.accept()
            except socket.timeout as exc:
                raise ProbeFailure("V6 upstream accept timed out; Stock did not reach an active backend transaction") from exc
            with upstream:
                client.shutdown(socket.SHUT_RDWR)
                observed = ""
                upstream.settimeout(max(0.1, deadline - time.monotonic()))
                try:
                    while time.monotonic() < deadline:
                        if not upstream.recv(4096):
                            observed = "eof"
                            break
                except socket.timeout as exc:
                    _safe_write(receipt, {"evidence_type": "stock_client_abort", "active_request_started": True, "client_closed": True, "upstream_observed_client_close": False, "status": "blocked", "blocked_reason": "Stock backend remained open after active client close within bounded timeout", "host_timeout_fallback": True, "timeout_seconds": timeout, "backend_read_timeout_seconds": backend_read_timeout, "elapsed_seconds": round(time.monotonic() - started, 3), "event_promotion": "not_claimed"})
                    raise ProbeBlocked("V6 backend close observation timed out after active upstream accept") from exc
                except OSError as exc:
                    if getattr(exc, "errno", None) in (104, 108, 32):
                        observed = "reset-or-close"
                    else:
                        raise
                if not observed:
                    raise ProbeFailure("upstream did not observe bounded client-close propagation")
    elapsed = round(time.monotonic() - started, 3)
    if elapsed >= backend_read_timeout:
        _safe_write(receipt, {"evidence_type": "stock_client_abort", "active_request_started": True, "client_closed": True, "upstream_observed_client_close": False, "upstream_close_outcome": "host-timeout-followed-close", "status": "blocked", "blocked_reason": "client close completed only after configured backend read timeout", "host_timeout_fallback": True, "client_direct_propagation": "not_observed", "timeout_seconds": timeout, "backend_read_timeout_seconds": backend_read_timeout, "elapsed_seconds": elapsed, "event_promotion": "not_claimed"})
        raise ProbeBlocked("V6 close completed only after configured backend read timeout")
    _safe_write(receipt, {"evidence_type": "stock_client_abort", "active_request_started": True, "client_closed": True, "upstream_observed_client_close": True, "upstream_close_outcome": observed, "status": "pass", "host_timeout_fallback": False, "timeout_seconds": timeout, "backend_read_timeout_seconds": backend_read_timeout, "elapsed_seconds": elapsed, "event_promotion": "not_claimed"})


def parallel(port: int, receipt: Path) -> None:
    port = _loopback_port(port)
    with ThreadPoolExecutor(max_workers=MAX_PARALLEL) as pool:
        statuses = list(pool.map(lambda _: _request(port), range(MAX_PARALLEL)))
    if statuses != [200] * MAX_PARALLEL:
        raise ProbeFailure("parallel control requests did not all return 200")
    _safe_write(receipt, {"evidence_type": "stock_parallel_http1", "requests": MAX_PARALLEL, "statuses": statuses, "bounded": True})


def hold(port: int, upstream_port: int, ready: Path, release: Path, receipt: Path, timeout: float) -> None:
    port = _loopback_port(port)
    upstream_port = _loopback_port(upstream_port)
    deadline = time.monotonic() + timeout
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", upstream_port))
        listener.listen(1)
        with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
            client.settimeout(3)
            client.sendall(b"GET /p4/close/ HTTP/1.1\r\nHost: stock-termination\r\nConnection: close\r\n\r\n")
            listener.settimeout(max(0.1, deadline - time.monotonic()))
            upstream, _ = listener.accept()
            _safe_write(ready, {"evidence_type": "stock_host_termination", "upstream_listener": True, "active_request_started": True})
            with upstream:
                while not release.exists() and time.monotonic() < deadline:
                    time.sleep(0.02)
            if not release.exists():
                raise ProbeFailure("release marker deadline expired")
            observed = ""
            client.settimeout(max(0.1, deadline - time.monotonic()))
            try:
                while time.monotonic() < deadline:
                    if not client.recv(4096):
                        observed = "eof"
                        break
            except OSError as exc:
                if getattr(exc, "errno", None) in (104, 108, 32):
                    observed = "reset-or-close"
                else:
                    raise
            if not observed:
                raise ProbeFailure("client did not observe bounded host-close propagation")
    _safe_write(receipt, {"evidence_type": "stock_host_termination", "active_request_started": True, "host_event": "not_claimed", "upstream_closed": True, "client_observed_host_close": True, "client_close_outcome": observed})


def release(path: Path) -> None:
    _safe_write(path, {"release": True})


def main() -> int:
    global TRUSTED_RUNTIME_ROOT
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("client-abort", "parallel", "hold", "release"))
    parser.add_argument("--frontend-port", type=int)
    parser.add_argument("--upstream-port", type=int)
    parser.add_argument("--ready", type=Path)
    parser.add_argument("--release", dest="release_path", type=Path)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--backend-read-timeout", type=float, default=2.0)
    parser.add_argument("--runtime-root", type=Path, required=True)
    args = parser.parse_args()
    try:
        TRUSTED_RUNTIME_ROOT = Path(args.runtime_root)
        if args.mode == "release":
            release(args.release_path)
        elif args.mode == "client-abort":
            client_abort(args.frontend_port, args.upstream_port, args.receipt, args.timeout, args.backend_read_timeout)
        elif args.mode == "parallel":
            parallel(args.frontend_port, args.receipt)
        else:
            hold(args.frontend_port, args.upstream_port, args.ready, args.release_path, args.receipt, args.timeout)
    except ProbeBlocked as exc:
        print(f"lighttpd_stock_lifecycle_probe: BLOCKED {exc}")
        return 77
    except (OSError, ProbeFailure, ValueError) as exc:
        print(f"lighttpd_stock_lifecycle_probe: FAIL {exc}")
        return 1
    print(f"lighttpd_stock_lifecycle_probe: PASS mode={args.mode}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
