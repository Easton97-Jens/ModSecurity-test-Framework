"""Own bounded upstream: release the marker only after client sees headers."""
from __future__ import annotations

import socketserver
import threading

PREFIX = b"owned-prefix\n" * 400
SUFFIX = b"no-crs-response-body-marker\n" + b"owned-suffix\n" * 400
TRANSPORT_BODY = b"transport fixture body"


class _Handler(socketserver.StreamRequestHandler):
    def read_request_head(self):
        first = self.rfile.readline(4096)
        if not first or len(first) == 4096:
            return None
        while True:
            line = self.rfile.readline(4096)
            if not line or len(line) == 4096:
                return None
            if line == b"\r\n":
                return first

    def handle(self):
        first = self.read_request_head()
        if first is None:
            return
        path = first.split(b" ", 2)[1]
        late = path.endswith(b"/0")
        prefix = PREFIX * 40 if self.server.backpressure else PREFIX
        body = prefix + SUFFIX if late else b"owned-followup\n"
        framing = b"Transfer-Encoding: chunked" if late else b"Content-Length: " + str(len(body)).encode()
        header = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n" + framing + b"\r\nConnection: close\r\n\r\n"
        prefix_wire = format(len(prefix), "x").encode() + b"\r\n" + prefix + b"\r\n"
        if late:
            self.server.prefix_sent.set()
        try:
            self.wfile.write(header + (prefix_wire if late else body))
            self.wfile.flush()
        except OSError:
            if late:
                self.server.prefix_sent.clear()
            self.server.upstream_write_failed = True
            return
        if late:
            try:
                self.send_marker()
            except OSError:
                self.server.upstream_write_failed = True

    def send_marker(self):
        if not self.server.client_headers_seen.wait(timeout=5):
            self.server.barrier_timeout = True
            return
        self.wfile.write(format(len(SUFFIX), "x").encode() + b"\r\n" + SUFFIX + b"\r\n0\r\n\r\n")
        self.wfile.flush()
        self.server.marker_sent.set()


class SynchronizedUpstream:
    def __init__(self, *, backpressure=False):
        self.server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _Handler)
        self.server.daemon_threads = True
        self.server.prefix_sent = threading.Event()
        self.server.client_headers_seen = threading.Event()
        self.server.marker_sent = threading.Event()
        self.server.barrier_timeout = False
        self.server.upstream_write_failed = False
        self.server.backpressure = backpressure
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def port(self):
        return self.server.server_address[1]

    def start(self):
        self.thread.start()

    def headers_seen(self, index):
        if index == 0:
            if not self.server.prefix_sent.is_set():
                raise ValueError("client headers preceded the upstream prefix")
            self.server.client_headers_seen.set()

    def observation(self):
        return {"prefix_sent": self.server.prefix_sent.is_set(),
                "client_headers_seen": self.server.client_headers_seen.is_set(),
                "marker_sent": self.server.marker_sent.is_set(),
                "barrier_timeout": self.server.barrier_timeout,
                "upstream_write_failed": self.server.upstream_write_failed}

    def stop(self):
        self.server.client_headers_seen.set()
        if self.thread.is_alive():
            self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


class _FramingHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(3)
        lines = []
        for _ in range(64):
            line = self.rfile.readline(4096)
            if not line or len(line) == 4096:
                return
            lines.append(line)
            if sum(map(len, lines)) > 8192:
                return
            if line == b"\r\n":
                break
        else:
            return
        first = lines[0].split(b" ")
        if len(first) != 3 or first[1] != self.server.expected_path.encode("ascii"):
            return
        self.server.framing_request = b"".join(lines)
        self.server.framing_requests += 1
        wire = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n"
                b"Connection: close\r\n\r\n9\r\ntransport\r\nd\r\n fixture body\r\n0\r\n\r\n")
        try:
            self.wfile.write(wire)
            self.wfile.flush()
            self.server.framing_response = wire
        except OSError:
            self.server.upstream_write_failed = True


class FramingUpstream(SynchronizedUpstream):
    """Actual chunked origin; its wire evidence is separate from downstream."""
    def __init__(self, path):
        super().__init__()
        self.server.RequestHandlerClass = _FramingHandler
        self.server.expected_path = path
        self.server.framing_request = b""
        self.server.framing_response = b""
        self.server.framing_requests = 0

    def observation(self):
        return {"request_hex": self.server.framing_request.hex(),
                "response_hex": self.server.framing_response.hex(),
                "request_count": self.server.framing_requests,
                "write_complete": bool(self.server.framing_response),
                "upstream_write_failed": self.server.upstream_write_failed}
