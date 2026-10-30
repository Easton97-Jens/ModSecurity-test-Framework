"""Bounded physical file client/backend; invoked only by an admitted controller."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat

if __package__:
    from .http_stream import request_client, response_backend, save_new
    from .source import validate_manifest
else:
    from connector_suite.adapters.traefik.harness.i12_file.http_stream import request_client, response_backend, save_new
    from connector_suite.adapters.traefik.harness.i12_file.source import validate_manifest


def private(path):
    """Require the exact nonsymlink directory supplied in a sealed admission."""
    if not path.is_absolute() or path != path.resolve(strict=True):
        raise ValueError("literal absolute nonsymlink private directory required")
    value = path.stat()
    if not stat.S_ISDIR(value.st_mode) or value.st_uid != os.getuid() or stat.S_IMODE(value.st_mode) != 0o700:
        raise ValueError("reader-owned mode0700 private directory required")
    return path


def load_manifest(path):
    if path.stat().st_size > 16384:
        raise ValueError("bounded fixture manifest required")
    manifest = json.loads(path.read_text())
    if (manifest.get("schema") != "traefik-physical-file-fixtures-v1" or
            manifest.get("native_file_api") is not False or len(manifest.get("files", [])) != 4):
        raise ValueError("exact physical transport fixture contract required")
    names = [validate_manifest(spec)[0] for spec in manifest["files"]]
    if len(set(names)) != 4:
        raise ValueError("unique fixture files required")
    return manifest


def stage(fixture_root, private_root, manifest):
    """Fresh regular-file copies for the future reader process, never payload decoding.

    Stage bytes are verified here, and verified again by the actual reader later.
    Staging alone does not establish source-file transport or engine inspection.
    """
    private(private_root)
    receipts = []
    for spec in manifest["files"]:
        name, size, _, expected_hash = validate_manifest(spec)
        source = fixture_root / name
        source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        digest = hashlib.sha256()
        count = 0
        try:
            value = os.fstat(source_fd)
            if not stat.S_ISREG(value.st_mode) or value.st_size != size:
                raise ValueError("exact regular source fixture required")
            output_fd = os.open(private_root / name,
                                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(output_fd, "wb") as output:
                while count < size:
                    part = os.read(source_fd, min(8192, size - count))
                    if not part:
                        raise ValueError("source fixture short read")
                    count += len(part)
                    digest.update(part)
                    output.write(part)
                if os.read(source_fd, 1):
                    raise ValueError("source fixture grew")
                output.flush()
                os.fsync(output.fileno())
            after = os.fstat(source_fd)
            if ((after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) !=
                    (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)):
                raise ValueError("source fixture changed during staging")
            if digest.hexdigest() != expected_hash:
                raise ValueError("staged physical source hash mismatch")
            receipts.append({"relative_path": name, "bytes": count, "sha256": digest.hexdigest(),
                             "staging_only": True, "transport_proven": False})
        finally:
            os.close(source_fd)
    return receipts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("stage", "client", "backend"))
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--private-root", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--fixture-root", type=Path)
    parser.add_argument("--fixture")
    parser.add_argument("--port", type=int)
    parser.add_argument("--key")
    parser.add_argument("--transaction-id")
    parser.add_argument("--uri", default="/no-crs/request-body")
    args = parser.parse_args()
    private_root, evidence_root = private(args.private_root), private(args.evidence_root)
    manifest = load_manifest(args.manifest)
    if args.mode == "stage":
        if (args.fixture_root is None or args.fixture is not None or args.port is not None or
                args.key is not None or args.transaction_id is not None):
            raise ValueError("staging requires only admitted fixture root")
        receipts = stage(args.fixture_root, private_root, manifest)
        save_new(evidence_root, "file-staging.json", {"schema": "traefik-file-staging-v1", "files": receipts})
        return 0
    if args.fixture_root is not None or args.fixture is None or args.port is None or args.key is None:
        raise ValueError("HTTP process requires exact fixture, port and key")
    selected = [spec for spec in manifest["files"] if spec["relative_path"] == args.fixture]
    if len(selected) != 1:
        raise ValueError("fixture must be a single admitted manifest file")
    function = request_client if args.mode == "client" else response_backend
    kwargs = {"transaction_id": args.transaction_id}
    if args.mode == "client":
        kwargs["uri"] = args.uri
    result = function(args.port, args.key, private_root, selected[0], evidence_root, **kwargs)
    return int("error" in result)


if __name__ == "__main__":
    raise SystemExit(main())
