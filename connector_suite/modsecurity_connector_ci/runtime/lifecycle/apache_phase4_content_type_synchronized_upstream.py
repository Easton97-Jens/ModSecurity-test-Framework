#!/usr/bin/env python3
"""Parent-owned content-type variant of the Framework streaming barrier.

The Framework helper deliberately fixes its upstream content type to
``text/plain``.  This thin test-only wrapper reuses its synchronization model
but emits one explicitly supplied MIME type so the Apache connector can prove
that its Phase-4 gate is not narrower than libModSecurity's MIME policy.
"""

from __future__ import annotations
from modsecurity_test_framework.connector_context import load_source

import argparse
from importlib.util import module_from_spec, spec_from_file_location
import json
import os
from pathlib import Path
import sys
import time
from types import ModuleType


def load_framework_helper() -> ModuleType:
    framework_root = os.environ.get("FRAMEWORK_ROOT")
    if not framework_root:
        raise RuntimeError("FRAMEWORK_ROOT is required")
    helper = Path(framework_root) / "tests/runners/synchronized_upstream.py"
    module = load_source(helper)
    return module


FRAMEWORK_HELPER = load_framework_helper()


class ContentTypedSynchronizedStreamingUpstream(
    FRAMEWORK_HELPER.SynchronizedStreamingUpstream
):
    """Reuse Framework synchronization while changing only the test header."""

    def __init__(self, *, content_type: str, **kwargs: object) -> None:
        if not content_type or "\r" in content_type or "\n" in content_type:
            raise ValueError("content type must be a non-empty HTTP header value")
        self._content_type = content_type.encode("ascii")
        super().__init__(**kwargs)

    def _serve_once(self) -> None:
        try:
            listener = self._listener
            if listener is None:
                raise RuntimeError("synchronized upstream listener is unavailable")
            connection, _peer = listener.accept()
            self._connection = connection
            connection.settimeout(self._timeout)
            self._recv_request_headers(connection)
            connection.sendall(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: " + self._content_type + b"\r\n"
                b"Transfer-Encoding: chunked\r\n"
                b"Connection: close\r\n\r\n"
            )
            connection.sendall(self._chunk(self._first_chunk))
            self._first_chunk_sent.set()
            self._paused.set()
            if not self._release.wait(self._timeout):
                raise FRAMEWORK_HELPER.StreamingProbeError(
                    "test harness did not release the upstream barrier"
                )
            connection.sendall(self._chunk(self._later_chunk))
            connection.sendall(b"0\r\n\r\n")
            self._eos_sent.set()
        except Exception as exc:  # surface server failures in the parent loop
            self._error = exc
        finally:
            if self._connection is not None:
                try:
                    self._connection.close()
                except OSError:
                    pass
            if self._listener is not None:
                try:
                    self._listener.close()
                except OSError:
                    pass
            self._closed.set()


def write_control_json(
    path: Path, payload: dict[str, object], *, control_root: Path
) -> None:
    control_path = resolve_control_path(
        str(path), control_root, "control file", required=True
    )
    if control_path is None:
        raise RuntimeError("required control path validation returned no path")
    control_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = control_path.with_name(f".{control_path.name}.tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(control_path)


def resolve_control_root(value: str) -> Path:
    root = Path(value).resolve()
    if not root.is_dir():
        raise ValueError(f"control root must be an existing directory: {root}")
    return root


def resolve_control_path(
    value: str | None, control_root: Path, label: str, *, required: bool
) -> Path | None:
    if not value:
        if required:
            raise ValueError(f"{label} is required")
        return None
    path = Path(value).resolve()
    try:
        relative = path.relative_to(control_root)
    except ValueError as exc:
        raise ValueError(
            f"{label} must resolve beneath control root: {control_root}"
        ) from exc
    if not relative.parts:
        raise ValueError(f"{label} must name a file beneath control root")
    return path


def resolve_control_paths(
    args: argparse.Namespace,
) -> tuple[Path, Path, Path, Path | None, Path | None]:
    control_root = resolve_control_root(args.control_root)
    ready = resolve_control_path(
        args.ready_file, control_root, "ready file", required=True
    )
    release = resolve_control_path(
        args.release_file, control_root, "release file", required=True
    )
    paused = resolve_control_path(
        args.paused_file, control_root, "paused file", required=False
    )
    evidence = resolve_control_path(
        args.server_evidence_file, control_root, "server evidence file", required=False
    )
    paths = [
        path for path in (ready, release, paused, evidence) if path is not None
    ]
    if len(paths) != len(set(paths)):
        raise ValueError("control file paths must be distinct")
    return control_root, ready, release, paused, evidence


def publish_paused_control(
    path: Path | None,
    upstream: ContentTypedSynchronizedStreamingUpstream,
    *,
    control_root: Path,
) -> None:
    if path is None:
        return
    write_control_json(
        path,
        {
            "schema_version": 1,
            "evidence_type": "synchronized_upstream_paused",
            "first_chunk_size": upstream.first_chunk_size,
            "upstream_paused": True,
            "upstream_eos_sent": False,
            "body_payload_persisted": False,
        },
        control_root=control_root,
    )


def serve_with_control_files(args: argparse.Namespace) -> None:
    control_root, ready, release, paused, evidence = resolve_control_paths(args)
    stale = [
        path
        for path in (ready, release, paused)
        if path is not None and path.exists()
    ]
    if stale:
        raise ValueError(
            "control-file daemon requires fresh paths: "
            + ", ".join(str(path) for path in stale)
        )

    timeout = float(args.timeout)
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    paused_published = False
    deadline = time.monotonic() + timeout
    with ContentTypedSynchronizedStreamingUpstream(
        content_type=args.content_type, host=args.listen_host,
        port=args.listen_port, timeout=timeout
    ) as upstream:
        address = upstream.address
        write_control_json(
            ready,
            {
                "schema_version": 1,
                "evidence_type": "synchronized_upstream_ready",
                "upstream_host": address.host,
                "upstream_port": address.port,
                "body_payload_persisted": False,
            },
            control_root=control_root,
        )
        while not upstream.eos_sent:
            upstream._raise_if_failed()
            if upstream.paused and not paused_published:
                publish_paused_control(
                    paused, upstream, control_root=control_root
                )
                paused_published = True
            if release.exists():
                upstream.release()
            if time.monotonic() >= deadline:
                raise FRAMEWORK_HELPER.StreamingProbeError(
                    "timed out waiting for release-file"
                )
            time.sleep(0.01)
        upstream._raise_if_failed()
        if evidence is not None:
            write_control_json(
                evidence,
                {
                    "schema_version": 1,
                    "evidence_type": "synchronized_upstream_server",
                    "first_chunk_size": upstream.first_chunk_size,
                    "upstream_paused": paused_published,
                    "upstream_eos_sent": True,
                    "body_payload_persisted": False,
                },
                control_root=control_root,
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=0)
    parser.add_argument("--control-root")
    parser.add_argument("--ready-file")
    parser.add_argument("--paused-file")
    parser.add_argument("--release-file")
    parser.add_argument("--server-evidence-file")
    parser.add_argument("--content-type", default=os.environ.get(
        "APACHE_PHASE4_SYNC_CONTENT_TYPE", "application/vnd.apache-phase4+json"
    ))
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args(argv)
    if not args.serve:
        parser.error("--serve is required")
    if not args.control_root or not args.ready_file or not args.release_file:
        parser.error(
            "--serve requires --control-root, --ready-file, and --release-file"
        )
    serve_with_control_files(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
