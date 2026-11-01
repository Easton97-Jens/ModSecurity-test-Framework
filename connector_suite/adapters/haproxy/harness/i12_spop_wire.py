"""Independent bounded SPOP decoder used by the HAProxy I12 wire observer.

This module records representation; it never upgrades an ACK or HTTP status to
native lifecycle evidence. Binary values retain their bytes as hex.
"""
from __future__ import annotations

import ipaddress
import struct

MAX_FRAME = 65536


class InvalidFrame(ValueError):
    """A complete supported SPOP representation could not be decoded."""


class Reader:
    def __init__(self, data: bytes):
        self.data, self.pos = data, 0

    def take(self, size: int) -> bytes:
        if size < 0 or size > len(self.data) - self.pos:
            raise InvalidFrame("truncated value")
        value = self.data[self.pos:self.pos + size]
        self.pos += size
        return value

    def uint(self) -> int:
        value = self.take(1)[0]
        if value < 240:
            return value
        shift = 4
        for _ in range(9):
            byte = self.take(1)[0]
            value += byte << shift
            if value > (1 << 64) - 1:
                raise InvalidFrame("integer overflow")
            if byte < 128:
                return value
            shift += 7
        raise InvalidFrame("unterminated integer")

    def blob(self) -> bytes:
        return self.take(self.uint())

    def typed(self) -> dict:
        tag = self.take(1)[0]
        kind = tag & 15
        if kind == 0:
            value = None
        elif kind == 1:
            value = bool(tag & 16)
        elif kind in (2, 3, 4, 5):
            value = self.uint()
        elif kind in (6, 7):
            value = str(ipaddress.ip_address(self.take(4 if kind == 6 else 16)))
        elif kind in (8, 9):
            raw = self.blob()
            value = raw.decode("utf-8") if kind == 8 else raw.hex()
        else:
            raise InvalidFrame("unknown data type")
        return {"tag": tag, "value": value}


def decode_messages(reader):
    messages = []
    while reader.pos < len(reader.data):
        name = reader.blob().decode("utf-8")
        count = reader.take(1)[0]
        arguments = []
        for _ in range(count):
            key = reader.blob().decode("utf-8")
            arguments.append({"name": key, **reader.typed()})
        messages.append({"name": name, "arguments": arguments})
    return messages


def decode_key_values(reader):
    pairs = []
    while reader.pos < len(reader.data):
        pairs.append({"name": reader.blob().decode("utf-8"), **reader.typed()})
    return pairs


def decode_frame(raw: bytes) -> dict:
    if len(raw) < 4:
        raise InvalidFrame("missing length")
    size = struct.unpack("!I", raw[:4])[0]
    if size > MAX_FRAME or size != len(raw) - 4:
        raise InvalidFrame("invalid frame length")
    reader = Reader(raw[4:])
    kind = reader.take(1)[0]
    flags = struct.unpack("!I", reader.take(4))[0]
    result = {"kind": kind, "flags": flags, "stream": reader.uint(),
              "frame": reader.uint()}
    if kind in (1, 2, 101, 102):
        start = reader.pos
        result["key_values"] = decode_key_values(reader)
        result["payload_hex"] = reader.data[start:].hex()
    elif kind == 3:
        result["messages"] = decode_messages(reader)
    elif kind == 103:
        actions = []
        while reader.pos < len(reader.data):
            if reader.take(2) != b"\x01\x03":
                raise InvalidFrame("unsupported ACK action")
            scope = reader.take(1)[0]
            actions.append({"scope": scope, "name": reader.blob().decode("utf-8"),
                            **reader.typed()})
        result["actions"] = actions
    else:
        result["payload_hex"] = reader.take(len(reader.data) - reader.pos).hex()
    return result
