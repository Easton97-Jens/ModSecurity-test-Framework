"""Independent bounded HTTP/2 wire probe for real connector host tests.

Requests use literal, non-Huffman HPACK. Only protocol metadata and byte counts
are retained; native host access records independently establish HTTP status.
"""
from __future__ import annotations
import ctypes
import ctypes.util
import json
from pathlib import Path
import socket
import ssl
import struct
import time


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def write_json(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
    path.chmod(0o600)


def frame(kind: int, flags: int, stream: int, payload: bytes = b"") -> bytes:
    require(len(payload) < 1 << 24 and 0 <= stream < 1 << 31, "invalid frame")
    return len(payload).to_bytes(3, "big") + bytes((kind, flags)) + struct.pack("!I", stream) + payload


def hpack_string(value: str) -> bytes:
    value_bytes = value.encode("ascii")
    length = len(value_bytes)
    prefix = bytearray((min(length, 127),))
    if length >= 127:
        length -= 127
        while length >= 128:
            prefix.append((length & 127) | 128)
            length >>= 7
        prefix.append(length)
    return bytes(prefix) + value_bytes


def request_headers(port: int, path: str, transaction: str, method: str, body: bytes, phase1: bool,
                    extra_headers: tuple = (), transaction_header: str = "x-acceptance-id") -> bytes:
    require(method in ("GET", "POST"), "explicit GET/POST required")
    require(path.startswith("/"), "origin-form request path required")
    pairs = [(":method", method), (":scheme", "https"), (":authority", f"127.0.0.1:{port}"),
             (":path", path), (transaction_header, transaction)]
    if body:
        pairs.extend((("content-length", str(len(body))), ("content-type", "text/plain")))
    if phase1:
        pairs.append(("x-modsec-smoke", "block"))
    for name, value in extra_headers:
        require(bool(name) and not name.startswith(":") and name == name.lower(), "invalid additional header name")
        pairs.append((name, value))
    for name, value in pairs:
        require(all(32 <= ord(c) < 127 for c in name + value), "header control/non-ASCII rejected")
    return b"".join(b"\x00" + hpack_string(name) + hpack_string(value) for name, value in pairs)


class HeaderValue(ctypes.Structure):
    # Public nghttp2_nv ABI from nghttp2/nghttp2.h, not a private codec layout.
    _fields_ = [("name", ctypes.c_void_p), ("value", ctypes.c_void_p),
                ("namelen", ctypes.c_size_t), ("valuelen", ctypes.c_size_t), ("flags", ctypes.c_uint8)]


class StatusDecoder:
    """Use installed native HPACK, retaining only response :status integers."""

    def __init__(self):
        library = ctypes.util.find_library("nghttp2")
        require(bool(library), "installed libnghttp2 is required for independent response status decoding")
        self.library = ctypes.CDLL(library)
        self.library.nghttp2_hd_inflate_new.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
        self.library.nghttp2_hd_inflate_new.restype = ctypes.c_int
        self.library.nghttp2_hd_inflate_hd2.argtypes = [ctypes.c_void_p, ctypes.POINTER(HeaderValue),
            ctypes.POINTER(ctypes.c_int), ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
        self.library.nghttp2_hd_inflate_hd2.restype = ctypes.c_ssize_t
        self.library.nghttp2_hd_inflate_end_headers.argtypes = [ctypes.c_void_p]
        self.library.nghttp2_hd_inflate_end_headers.restype = ctypes.c_int
        self.library.nghttp2_hd_inflate_del.argtypes = [ctypes.c_void_p]
        self.library.nghttp2_hd_inflate_del.restype = None
        self.inflater = ctypes.c_void_p()
        require(self.library.nghttp2_hd_inflate_new(ctypes.byref(self.inflater)) == 0, "HPACK inflater allocation failed")

    def decode(self, block: bytes) -> list[int]:
        require(len(block) <= 65536, "HPACK block bound exceeded")
        buffer = ctypes.create_string_buffer(block)
        offset, total = 0, 0
        statuses = []
        for _ in range(256):
            value, flags = HeaderValue(), ctypes.c_int()
            consumed = self.library.nghttp2_hd_inflate_hd2(self.inflater, ctypes.byref(value), ctypes.byref(flags),
                        ctypes.c_void_p(ctypes.addressof(buffer) + offset), len(block) - offset, 1)
            require(0 <= consumed <= len(block) - offset, "invalid HPACK response")
            offset += consumed
            if flags.value & 2:
                require(value.namelen <= 1024 and value.valuelen <= 16384, "HPACK field bound exceeded")
                total += value.namelen + value.valuelen
                require(total <= 65536, "expanded HPACK block bound exceeded")
                if ctypes.string_at(value.name, value.namelen) == b":status":
                    text = ctypes.string_at(value.value, value.valuelen)
                    require(len(text) == 3 and text.isdigit() and 100 <= int(text) <= 599, "invalid :status")
                    statuses.append(int(text))
            if flags.value & 1:
                require(offset == len(block), "trailing HPACK input")
                require(self.library.nghttp2_hd_inflate_end_headers(self.inflater) == 0, "HPACK boundary failed")
                require(len(statuses) <= 1, "ambiguous response :status")
                return statuses
            require(consumed > 0 or flags.value & 2, "HPACK decoder made no progress")
        raise ValueError("HPACK field count bound exceeded")

    def close(self) -> None:
        if self.inflater:
            self.library.nghttp2_hd_inflate_del(self.inflater)
            self.inflater = ctypes.c_void_p()


class WireClient:
    """One verified TLS 1.3 physical connection with explicit H2 frames."""

    def __init__(self, port: int, ca: Path, output: Path, transaction_header: str = "x-acceptance-id"):
        context = ssl.create_default_context(cafile=str(ca))
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.set_alpn_protocols(["h2"])
        self.socket = context.wrap_socket(socket.create_connection(("127.0.0.1", port), 5), server_hostname="127.0.0.1")
        if self.socket.selected_alpn_protocol() != "h2":
            self.socket.close()
            raise ValueError("server did not negotiate h2")
        self.socket.settimeout(0.2)
        self.port = port
        self.transaction_header = transaction_header
        self.buffer = bytearray()
        self.records: list[dict] = []
        self.sent: list[dict] = []
        self.status: dict[int, int] = {}
        self.header_block = bytearray()
        self.header_stream = 0
        self.decoder = StatusDecoder()
        self.bytes: dict[int, int] = {}
        self.terminal: dict[int, dict] = {}
        self.output = output
        self.socket.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, 0))

    def request(self, stream: int, path: str, transaction: str, body: bytes = b"", phase1: bool = False,
                headers: tuple = (), method: str | None = None) -> None:
        require(stream > 0 and stream % 2 == 1 and all(record["stream_id"] != stream for record in self.sent),
                "fresh client-initiated stream required")
        require(len(body) <= 1024, "bounded request entity required")
        self.socket.sendall(frame(1, 4 | (0 if body else 1), stream,
                                  request_headers(self.port, path, transaction, method or ("POST" if body else "GET"),
                                                  body, phase1, headers, self.transaction_header)))
        if body:
            self.socket.sendall(frame(0, 1, stream, body))
        self.sent.append({"stream_id": stream, "path": path, "transaction_id": transaction,
                          "method": method or ("POST" if body else "GET"), "body_bytes": len(body),
                          "monotonic_ns": time.monotonic_ns()})

    def _headers(self, kind, flags, stream, payload):
        if kind == 1:
            require(stream != 0 and not self.header_stream, "invalid HEADERS stream")
            padding = payload[0] + 1 if flags & 8 else 0
            start = (1 if flags & 8 else 0) + (5 if flags & 32 else 0)
            require(start + (padding - 1 if padding else 0) <= len(payload), "invalid HEADERS padding/priority")
            end = len(payload) - (padding - 1 if padding else 0)
            self.header_block.extend(payload[start:end])
            self.header_stream = stream
        else:
            require(self.header_stream == stream, "unexpected CONTINUATION")
            self.header_block.extend(payload)
        require(len(self.header_block) <= 65536, "HEADERS block bound exceeded")
        if flags & 4:
            self._finish_headers(stream)

    def _finish_headers(self, stream):
        statuses = self.decoder.decode(bytes(self.header_block))
        if stream not in self.status:
            require(len(statuses) == 1, "missing initial response :status")
            if statuses[0] >= 200:
                self.status[stream] = statuses[0]
        else:
            require(not statuses, "duplicate final response :status")
        self.header_block.clear()
        self.header_stream = 0

    def _data(self, flags, stream, size, payload):
        padding = payload[0] + 1 if flags & 8 else 0
        require(padding <= len(payload), "invalid DATA padding")
        self.bytes[stream] = self.bytes.get(stream, 0) + size - padding
        if size:
            self.socket.sendall(frame(8, 0, 0, struct.pack("!I", size)))
        if stream not in self.terminal and size and not flags & 1:
            self.socket.sendall(frame(8, 0, stream, struct.pack("!I", size)))

    def _observe_frame(self, kind, flags, stream, payload):
        size = len(payload)
        observation = {"monotonic_ns": time.monotonic_ns(), "type": kind, "flags": flags,
                       "stream_id": stream, "size": size}
        require(len(self.records) < 8192, "wire observation bound exceeded")
        self.records.append(observation)
        require(not self.header_stream or kind == 9 and stream == self.header_stream, "interleaved CONTINUATION block")
        if kind in (1, 9):
            self._headers(kind, flags, stream, payload)
        if kind == 4 and not flags & 1:
            self.socket.sendall(frame(4, 1, 0))
        if kind == 6 and not flags & 1:
            self.socket.sendall(frame(6, 1, 0, payload))
        require(kind != 7, "unexpected GOAWAY closes shared connection")
        if kind == 0:
            self._data(flags, stream, size, payload)
        if kind == 3:
            require(size == 4, "invalid RST_STREAM")
            observation["reset_code"] = int.from_bytes(payload, "big")
            self.terminal[stream] = observation
        elif kind in (0, 1) and flags & 1:
            self.terminal[stream] = observation

    def poll(self) -> None:
        try:
            chunk = self.socket.recv(65536)
        except socket.timeout:
            return
        require(bool(chunk), "physical connection closed before follow-up")
        self.buffer.extend(chunk)
        while len(self.buffer) >= 9:
            size = int.from_bytes(self.buffer[:3], "big")
            require(size <= 65536, "unexpectedly large peer frame")
            if len(self.buffer) < size + 9:
                break
            kind, flags = self.buffer[3:5]
            stream = int.from_bytes(self.buffer[5:9], "big") & 0x7fffffff
            payload = bytes(self.buffer[9:9 + size])
            del self.buffer[:9 + size]
            self._observe_frame(kind, flags, stream, payload)

    def wait(self, predicate, timeout: float = 8) -> None:
        deadline = time.monotonic() + timeout
        while not predicate():
            require(time.monotonic() < deadline, "H2 barrier/terminal deadline exceeded")
            self.poll()

    def close(self) -> None:
        tls_version = self.socket.version()
        self.socket.close()
        self.decoder.close()
        write_json(self.output, {"alpn": "h2", "tls_verified": True, "frames": self.records,
                                 "body_bytes": self.bytes, "terminal": self.terminal,
                                 "requests": self.sent, "tls_version": tls_version, "status": self.status})
