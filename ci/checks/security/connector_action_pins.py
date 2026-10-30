"""Closed migration authority for preserved connector integration sources.

The snapshot is Framework-owned. It never reads a Connector checkout. Native
Framework maintenance cannot repin these sources under its different lock.
Whole-source digests retain the reviewed jobs, credentials, runner labels,
conditions and shell boundaries instead of exempting them from inspection.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import stat

LOCK = "ci/tooling/connector-actions.lock.json"
AUTHORITY = {"repository": "Easton97-Jens/ModSecurity-conector",
             "revision": "ec18f9e92286379a2410e917f76e6a5502675804",
             "path": "ci/tooling/security-tools.lock.yml",
             "sha256": "ad2b62a5d698ba7211a02df8b0239b7d0be7b105e2154fef738d96242aeb7f64"}
ACTION_RECORDS_SHA256 = "3830ab9e7242edf449b834f83b08b0e862e601d7ac7ec6586bf4ea1490b9b240"
SOURCES_SHA256 = "e7f02f4ba4fdb94fc9a60688796594097480836f7906bf02fbf8ab59a5ea3e30"
WORKFLOWS = frozenset({"connector-nginx-root-broker-historical.yml",
    "connector-protected-nginx-exact-head.yml", "connector-protected-nginx-root-broker-caller.yml",
    "connector-trusted-lighttpd-namespace.yml"})
HISTORICAL_WORKFLOW = "Easton97-Jens/ModSecurity-conector/.github/workflows/nginx-root-broker.yml@8ae707d72f1a8acb25d239e55e28a73cbc7522b1"

def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def _read(root: Path, relative: str) -> bytes:
    if relative.startswith("/") or any(part in ("", ".", "..") for part in relative.split("/")):
        raise ValueError("integration source path escapes its fixed owner")
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parts = relative.split("/")
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        child = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
        with os.fdopen(child, "rb") as stream:
            identity = os.fstat(stream.fileno())
            if not stat.S_ISREG(identity.st_mode) or identity.st_size > 1024 * 1024:
                raise ValueError("integration source is not bounded regular data")
            body = stream.read(1024 * 1024 + 1)
        if len(body) > 1024 * 1024:
            raise ValueError("integration source exceeds bound")
        return body
    finally:
        os.close(descriptor)

def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate integration authority key")
        value[key] = item
    return value

def load_lock(root: Path):
    value = json.loads(_read(root, LOCK), object_pairs_hook=_unique)
    if (set(value) != {"schema_version", "authority", "actions", "sources"}
            or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or value["authority"] != AUTHORITY
            or _digest(value["actions"]) != ACTION_RECORDS_SHA256
            or _digest(value["sources"]) != SOURCES_SHA256):
        raise ValueError("integration authority differs from the reviewed immutable migration snapshot")
    return value

def validate_source(root: Path, relative: str, text: str | None = None):
    """Fail closed for unknown paths, changed trust boundaries or action pins."""
    try:
        lock = load_lock(root)
        if relative not in lock["sources"]:
            raise ValueError("source is outside the closed integration registry")
        body = _read(root, relative)
        if text is not None and body != text.encode():
            raise ValueError("integration source changed during inspection")
        if hashlib.sha256(body).hexdigest() != lock["sources"][relative]:
            raise ValueError("integration source differs from its reviewed migration contract")
        # These exact source bytes are authenticated above. Their reviewed uses
        # entries are literal block scalars, so bootstrap validation needs no YAML
        # package before CI installs its development dependencies.
        for item in re.findall(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)", body.decode(), re.MULTILINE):
            if item == HISTORICAL_WORKFLOW or item == "$/.github/actions/connector-context":
                continue
            match = re.fullmatch(r"([^@]+)@([a-f0-9]{40})", item)
            if match is None:
                raise ValueError("unknown integration source reference")
            record = lock["actions"].get(match[1])
            if record is None or record["sha"] != match[2]:
                raise ValueError("integration action does not match its immutable authority")
        return []
    except (OSError, ValueError, TypeError) as error:
        return [f"{relative}: connector integration contract: {error}"]
