"""Closed malformed H1 inputs and strict actual host-rejection observations.

Input specifications are not evidence. A native NGINX rejection requires the
retained complete wire response, exact access entry and source-defined error.
No Engine transaction or event is created for a pre-connector rejection.
"""
from __future__ import annotations

import re

FAULT_HEADERS = {
    "invalid_content_length": b"Content-Length: not-a-number\r\n",
    "conflicting_content_length": b"Content-Length: 1\r\nContent-Length: 2\r\n",
    "duplicate_transfer_encoding": b"Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n",
    "content_length_overflow": b"Content-Length: 18446744073709551616\r\n",
}
RECORD_IDS = frozenset(FAULT_HEADERS)
DIAGNOSTICS = {
    "invalid_content_length": 'client sent invalid "Content-Length" header',
    "content_length_overflow": 'client sent invalid "Content-Length" header',
    "conflicting_content_length": 'client sent duplicate header line: "Content-Length: 2", previous value: "Content-Length: 1"',
    "duplicate_transfer_encoding": 'client sent duplicate header line: "Transfer-Encoding: chunked", previous value: "Transfer-Encoding: chunked"',
}


def request_path(case_id: str, run_id: str) -> str:
    if not isinstance(case_id, str) or case_id not in RECORD_IDS:
        raise ValueError("unknown closed raw H1 case")
    if not isinstance(run_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", run_id):
        raise ValueError("raw H1 run identity must be bounded and path-safe")
    return f"/no-crs/raw/{case_id}/{run_id}"


def request_bytes(case_id: str, run_id: str, *, control: bool = False) -> bytes:
    path = request_path(case_id, run_id)
    headers = b"Content-Length: 1\r\n" if control else FAULT_HEADERS[case_id]
    body = b"0\r\n\r\n" if case_id == "duplicate_transfer_encoding" and not control else b"x"
    return (f"POST {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n".encode()
            + headers + b"\r\n" + body)


def response_status(response: bytes) -> int:
    if not isinstance(response, bytes) or len(response) > 65536:
        raise ValueError("response must be bounded actual bytes")
    header, delimiter, body = response.partition(b"\r\n\r\n")
    status = re.fullmatch(rb"HTTP/1\.1 ([1-5][0-9]{2}) [^\r\n]*", header.split(b"\r\n", 1)[0])
    if not delimiter or status is None:
        raise ValueError("complete H1 response headers are required")
    lengths = []
    for line in header.split(b"\r\n")[1:]:
        name, colon, value = line.partition(b":")
        if not colon:
            raise ValueError("invalid response header")
        if name.lower() == b"transfer-encoding":
            raise ValueError("host rejection contract requires explicit Content-Length")
        if name.lower() == b"content-length":
            if not re.fullmatch(rb"[0-9]{1,5}", value.strip()):
                raise ValueError("invalid response Content-Length")
            lengths.append(int(value.strip()))
    if len(lengths) != 1 or len(body) != lengths[0]:
        raise ValueError("one exact fully received response length is required")
    return int(status.group(1))


def validate_host_rejection(case_id: str, run_id: str, response: bytes,
                            access: dict, error_log: bytes) -> list[str]:
    path = request_path(case_id, run_id)
    errors = []
    try:
        if response_status(response) != 400:
            errors.append("host did not reject the wire request with HTTP400")
    except ValueError as exc:
        errors.append(str(exc))
    if not isinstance(access, dict) or any(access.get(key) != wanted or type(access.get(key)) is not type(wanted)
                                          for key, wanted in {"method": "POST", "uri": path, "status": 400}.items()):
        errors.append("native access entry does not bind the exact actual request/status")
    if not isinstance(error_log, bytes) or len(error_log) > 65536 or DIAGNOSTICS[case_id].encode() not in error_log:
        errors.append("exact native H1 parser rejection diagnostic is missing")
    return errors
