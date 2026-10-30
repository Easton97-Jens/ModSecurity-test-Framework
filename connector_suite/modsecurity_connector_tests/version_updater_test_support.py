"""Shared offline fixtures and spec-loader support for version updater tests."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import json
from functools import partial
from pathlib import Path
from typing import Callable


SCRIPTS_DIRECTORY = connector_root() / "scripts"


def load_updater(module_name: str, script: Path) -> object:
    """Load the product updater through its collision-checked public namespace."""
    return load_source(script)


class FakeResponse:
    """Small response double with explicit metadata headers and a trusted URL."""

    def __init__(
        self,
        body: bytes,
        *,
        canonical_url: str,
        content_type: str | None = "application/json; charset=utf-8",
        content_length: int | None = None,
        url: str | None = None,
        status: int = 200,
    ) -> None:
        self.body = body
        self.status = status
        self.url = canonical_url if url is None else url
        self.headers: dict[str, str] = {}
        if content_type is not None:
            self.headers["Content-Type"] = content_type
        self.headers["Content-Length"] = str(len(body) if content_length is None else content_length)
        self.closed = False

    def read(self, size: int = -1) -> bytes:
        return self.body if size < 0 else self.body[:size]

    def geturl(self) -> str:
        return self.url

    def getcode(self) -> int:
        return self.status

    def close(self) -> None:
        self.closed = True


class FakeOpener:
    """Record requests while returning one controlled response or controlled error."""

    def __init__(self, response: FakeResponse | None = None, error: Exception | None = None) -> None:
        self.response = response
        self.error = error
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        if self.error is not None:
            raise self.error
        if self.response is None:
            raise AssertionError("FakeOpener needs a response or an error")
        return self.response


def response_factory(canonical_url: str) -> Callable[..., FakeResponse]:
    """Bind one adapter's canonical endpoint into the shared response fixture."""

    return partial(FakeResponse, canonical_url=canonical_url)


def uses_shared_core(module: object) -> bool:
    """Require one stable package core for both parser and runtime identities."""
    owner = getattr(getattr(module, "_decode_metadata", None), "__module__", None)
    runtime = getattr(getattr(module, "_RUNTIME", None).__class__, "__module__", None)
    return owner == runtime and owner in {
        "scripts.version_updater_common",
        "modsecurity_test_framework.product_sources.scripts.version_updater_common",
    }


def write_project_pins(root: Path, **versions: str) -> Path:
    """Provision a complete central lock for isolated toolchain fixtures."""
    pins = {"schema_version": 1, "framework_sha": "6" * 40, "mrts_sha": "8" * 40,
            "python_version": "3.15.7", "go_version": "1.27.1"}
    pins.update(versions)
    target = root / "ci/tooling/project-versions.lock.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(pins, indent=2) + "\n", encoding="utf-8")
    return target
