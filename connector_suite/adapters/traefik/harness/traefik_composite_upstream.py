#!/usr/bin/env python3
"""Serve bounded, catalog-backed upstream responses for one Traefik case.

Only the selected vector's response metadata is used.  The response body is
written to the socket, but is never printed, persisted, or included in an
observation record.  This helper intentionally has no shutdown endpoint and
is expected to be owned by the shell runner's process-group cleanup.
"""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import argparse
import http.server
import json
from pathlib import Path
import ssl
import sys
import threading
import time
from typing import Any, NoReturn

_CI_LIB = connector_root() / "ci" / "lib"


from modsecurity_connector_ci.lib.runtime_path_utils import open_private_runtime_root

MAX_CATALOG = 256 * 1024
MAX_RESPONSE = 64 * 1024
MAX_OBSERVATION = 16 * 1024
LEASE_HEADER = "x-msconnector-composite-lease"
P2_TO_P3_TIMEOUT_SECONDS = 6.0
P2_TO_P3_TIMEOUT_CASE = "p2_to_p3_timeout"


def fail(message: str) -> NoReturn:
    raise RuntimeError(message)


def response_header_delay_seconds(observation_root: Path) -> float:
    """Select a bounded delay only from the operator-owned runtime-root."""
    root_name = observation_root.name
    if root_name == P2_TO_P3_TIMEOUT_CASE or root_name.endswith(
        f"-{P2_TO_P3_TIMEOUT_CASE}"
    ):
        return P2_TO_P3_TIMEOUT_SECONDS
    return 0.0


def load_catalog(runtime: Any, leaf: str) -> dict[str, Any]:
    catalog = json.loads(runtime.read_text(leaf, "case input", maximum_bytes=MAX_CATALOG))
    if not isinstance(catalog, dict) or not isinstance(catalog.get("vectors"), list):
        fail("case input is not a catalog with vectors")
    return catalog


def vectors_by_path(catalog: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for vector in catalog["vectors"]:
        if not isinstance(vector, dict):
            continue
        request = vector.get("request")
        if not isinstance(request, dict) or not isinstance(request.get("path"), str):
            continue
        path = request["path"]
        if path in result:
            fail("catalog contains duplicate request paths")
        result[path] = vector
    return result


class ControlledHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *_args: object) -> None:
        # The default server logger would retain request paths and headers.
        return

    def do_GET(self) -> None:  # noqa: N802 - stdlib callback name
        self._serve()

    def do_POST(self) -> None:  # noqa: N802 - stdlib callback name
        self._serve()

    def _serve(self) -> None:
        self.server.observation.record(self.headers)  # type: ignore[attr-defined]
        vector = self.server.vectors.get(self.path)  # type: ignore[attr-defined]
        if vector is None:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            return
        upstream = vector.get("upstream")
        if not isinstance(upstream, dict):
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            return
        status = upstream.get("status", 200)
        headers = upstream.get("headers", {})
        body_text = upstream.get("body", "")
        if not isinstance(status, int) or not 100 <= status <= 599:
            fail("catalog upstream status is invalid")
        if not isinstance(headers, dict) or not isinstance(body_text, str):
            fail("catalog upstream metadata is invalid")
        body = body_text.encode("utf-8")
        if len(body) > MAX_RESPONSE:
            fail("catalog upstream response exceeds the bounded response size")
        delay = response_header_delay_seconds(self.server.observation_root)  # type: ignore[attr-defined]
        if delay:
            # The request is already recorded; only response headers are delayed.
            time.sleep(delay)
        self.send_response(status)
        for name, value in headers.items():
            if not isinstance(name, str) or not isinstance(value, str):
                fail("catalog upstream header is invalid")
            if name.lower() in {"content-length", "connection", "transfer-encoding"}:
                continue
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


class ControlledServer(http.server.ThreadingHTTPSServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(
        self,
        address: tuple[str, int],
        vectors: dict[str, dict[str, Any]],
        observation: "ObservationWriter",
        observation_root: Path,
        certfile: str,
        keyfile: str,
    ) -> None:
        super().__init__(address, ControlledHandler, certfile=certfile, keyfile=keyfile)
        self.vectors = vectors
        self.observation = observation
        self.observation_root = observation_root
        self.socket.context.minimum_version = ssl.TLSVersion.TLSv1_2


class ObservationWriter:
    """Write only bounded metadata about requests received by this child."""

    def __init__(self, runtime: Any, leaf: str) -> None:
        self.runtime = runtime
        self.leaf = leaf
        self.lock = threading.Lock()
        self.requests_seen = 0
        self.lease_header_observed = False
        self._persist()

    def record(self, headers: Any) -> None:
        with self.lock:
            self.requests_seen += 1
            self.lease_header_observed = self.lease_header_observed or any(
                name.lower() == LEASE_HEADER for name in headers.keys()
            )

            self._persist()

    def _persist(self) -> None:
        value = {
            "schema": "traefik-composite-upstream-observation/v1",
            "requests_seen": self.requests_seen,
            "lease_header_observed": self.lease_header_observed,
        }
        encoded = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        if len(encoded) > MAX_OBSERVATION:
            fail("observation exceeds the bounded metadata size")
        try:
            self.runtime.replace_text(self.leaf, encoded.decode("utf-8"), "upstream observation")
        except (OSError, ValueError) as exc:
            fail(f"observation write failed: {exc}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen", required=True)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--case-input", required=True, type=Path)
    parser.add_argument("--observation", required=True, type=Path)
    parser.add_argument("--observation-root", required=True, type=Path)
    parser.add_argument("--cert", required=True, type=Path)
    parser.add_argument("--key", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.root != args.observation_root:
            fail("upstream root and observation root must be identical")
        if not args.case_input.is_absolute() or args.case_input.parent != args.root:
            fail("case input must be an absolute direct child of the runtime root")
        if not args.observation.is_absolute() or args.observation.parent != args.root:
            fail("observation must be an absolute direct child of the runtime root")
        if not args.cert.is_absolute() or args.cert.parent != args.root:
            fail("certificate must be an absolute direct child of the runtime root")
        if not args.key.is_absolute() or args.key.parent != args.root:
            fail("private key must be an absolute direct child of the runtime root")
        host, separator, port_text = args.listen.rpartition(":")
        if not separator or host != "127.0.0.1":
            fail("listen must be the numeric loopback host and port")
        port = int(port_text)
        if not 1 <= port <= 65535:
            fail("listen port is outside the valid range")
        runtime = open_private_runtime_root(args.root)
        with runtime:
            observation = ObservationWriter(runtime, args.observation.name)
            server = ControlledServer(
                (host, port),
                vectors_by_path(load_catalog(runtime, args.case_input.name)),
                observation,
                args.root,
                str(args.cert),
                str(args.key),
            )
            try:
                server.timeout = 0.2
                while True:
                    server.handle_request()
            finally:
                server.server_close()
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"traefik_composite_upstream: FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
