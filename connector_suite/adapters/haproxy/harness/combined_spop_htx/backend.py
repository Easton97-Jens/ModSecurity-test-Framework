#!/usr/bin/env python3
"""Bounded loopback-only backend fixture for the combined HAProxy harness."""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPSServer
from pathlib import Path
import sys
import threading


RESPONSE_BODY = b"combined-response-body\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--ready-file", required=True, type=Path)
    parser.add_argument("--log-file", required=True, type=Path)
    parser.add_argument("--root-dir", required=True, type=Path)
    parser.add_argument("--cert-file", required=True, type=Path)
    parser.add_argument("--key-file", required=True, type=Path)
    args = parser.parse_args()
    if args.bind != "127.0.0.1" or not 1024 <= args.port <= 65535:
        parser.error("the fixture accepts only a non-privileged loopback port")
    if not args.root_dir.is_absolute() or not args.root_dir.is_dir():
        parser.error("root directory must be an existing absolute directory")
    if args.root_dir.stat().st_mode & 0o077:
        parser.error("root directory must be private to the task owner")
    root = args.root_dir.resolve()
    for path in (args.ready_file, args.log_file, args.cert_file, args.key_file):
        if not path.is_absolute():
            parser.error("fixture paths must be absolute")
        try:
            path.resolve(strict=False).relative_to(root)
        except ValueError as exc:
            raise SystemExit("fixture path escapes the private task root") from exc
        if path.is_symlink():
            parser.error("fixture paths must not be symbolic links")
    return args


def main() -> int:
    args = parse_args()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _handle(self) -> None:
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length:
                self.rfile.read(content_length)

            path = self.path.split("?", 1)[0]
            if path == "/slow":
                delay_seconds = 2
            else:
                delay_seconds = 0
            with args.log_file.open("a", encoding="utf-8") as log:
                # Deliberately record only a fixed route classification and no
                # request/response body or client header payload.
                json.dump({"route": path, "slow": bool(delay_seconds)}, log)
                log.write("\n")

            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(RESPONSE_BODY)))
            self.send_header(
                "X-Combined-Decision", "p3-deny" if path == "/p3-deny" else "allow"
            )
            self.end_headers()
            if delay_seconds:
                # An interruptible wait keeps the fixture responsive to
                # shutdown/cancellation while preserving the deterministic
                # delayed-response contract used by the harness.
                threading.Event().wait(delay_seconds)
            try:
                self.wfile.write(RESPONSE_BODY)
            except (BrokenPipeError, ConnectionResetError):
                # The harness's explicit cancel test intentionally reaches
                # this point after the loopback client has disconnected.
                pass

        def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
            self._handle()

        def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
            self._handle()

        def log_message(self, _format: str, *_args: object) -> None:
            return

    if not args.ready_file.parent.is_dir() or not args.log_file.parent.is_dir():
        parser_error = "the harness must create task-owned ready/log directories first"
        raise SystemExit(parser_error)
    server = ThreadingHTTPSServer(
        (args.bind, args.port), Handler, certfile=args.cert_file, keyfile=args.key_file
    )
    args.ready_file.write_text("ready\n", encoding="ascii")
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
