"""Bounded, strict parsing of actual HTTP/1.1 fixture response wire bytes."""
from __future__ import annotations

import hashlib
import re

BODY = b"transport fixture body"


def capture_bytes(value, limit):
    if not isinstance(value, str) or not 1 <= len(value) <= limit * 2 or re.fullmatch(r"(?:[0-9a-f]{2})+", value) is None:
        raise ValueError("exact bounded hexadecimal wire capture is required")
    return bytes.fromhex(value)


def response_headers(raw):
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= 32768:
        raise ValueError("bounded raw response bytes are required")
    split = raw.find(b"\r\n\r\n")
    if not 0 < split <= 8192:
        raise ValueError("bounded complete raw response headers are required")
    lines = raw[:split].split(b"\r\n")
    if len(lines) > 64 or re.fullmatch(rb"HTTP/1\.1 200 [\x20-\x7e]+", lines[0]) is None:
        raise ValueError("actual successful HTTP/1.1 status line is required")
    headers = {}
    for line in lines[1:]:
        name, value = parse_header(line)
        if name in headers and name in (b"content-length", b"transfer-encoding"):
            raise ValueError("duplicate framing header is ambiguous")
        headers[name] = value
    return headers, raw[split + 4:]


def parse_header(line):
    name, colon, value = line.partition(b":")
    if not colon or re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) is None:
        raise ValueError("raw header syntax is invalid")
    if any(byte < 32 and byte != 9 or byte > 126 for byte in value):
        raise ValueError("raw header value is invalid")
    return name.lower(), value.strip(b" \t")


def decode_chunks(raw):
    body = bytearray()
    offset = 0
    for _ in range(32):
        end = raw.find(b"\r\n", offset)
        if end < 0 or re.fullmatch(rb"[0-9A-Fa-f]{1,6}", raw[offset:end]) is None:
            raise ValueError("bounded complete raw chunk size is required")
        size = int(raw[offset:end], 16)
        offset = end + 2
        if size == 0:
            if raw[offset:] != b"\r\n":
                raise ValueError("actual terminal chunk must finish the response exactly")
            return bytes(body)
        if size > 32768 or len(body) + size > 32768 or raw[offset + size:offset + size + 2] != b"\r\n":
            raise ValueError("bounded complete raw chunk data is required")
        body.extend(raw[offset:offset + size])
        offset += size + 2
    raise ValueError("raw response exceeds the bounded chunk count")


def parse_http11_response(raw):
    headers, encoded = response_headers(raw)
    length, transfer = headers.get(b"content-length"), headers.get(b"transfer-encoding")
    if length is not None and transfer is not None:
        raise ValueError("Content-Length and Transfer-Encoding cannot prove one unambiguous framing")
    if transfer is not None:
        if transfer.lower() != b"chunked":
            raise ValueError("only actual chunked transfer coding is supported")
        body, framing, declared = decode_chunks(encoded), "chunked", None
    elif length is not None and re.fullmatch(rb"[0-9]{1,5}", length) is not None:
        declared = int(length)
        if declared != len(encoded):
            raise ValueError("actual body bytes must match the exact Content-Length")
        body, framing = encoded, "content_length"
    else:
        raise ValueError("actual Content-Length or chunked framing is required")
    return {"observed_status": 200, "http_version": 11, "framing": framing,
            "declared_length": declared, "bytes_received": len(body),
            "body_sha256": hashlib.sha256(body).hexdigest(), "body": body}
