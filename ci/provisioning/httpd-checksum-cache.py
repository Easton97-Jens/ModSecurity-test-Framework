#!/usr/bin/env python3
"""Admit genuine private cached HTTPD checksum metadata against reviewed pins."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat


def approved_contract():
    source = (Path(__file__).resolve().parents[1] / "lib/common.sh").read_text()
    values = {}
    for key in ("HTTPD_VERSION", "HTTPD_SHA256"):
        matches = re.findall(r'^' + key + r'="([A-Za-z0-9.-]+)"$', source, re.MULTILINE)
        if len(matches) != 1:
            raise ValueError("ambiguous reviewed HTTPD contract")
        values[key] = matches[0]
    url = "https://downloads.apache.org/httpd/httpd-" + values["HTTPD_VERSION"] + ".tar.bz2"
    return url, values["HTTPD_SHA256"]


def private_file(path, limit):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("cache path must be absolute without traversal")
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in path.parts[1:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    finally:
        os.close(directory)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) & 0o077 or not 0 < info.st_size <= limit):
            raise ValueError("cached source/metadata must be a bounded private owned regular single-link file")
        return descriptor, info
    except BaseException:
        os.close(descriptor)
        raise


def file_identity(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def require_provider_identity(archive, checksum, source_url, checksum_url, expected_sha, approved_url, approved_sha):
    filename = approved_url.rsplit("/", 1)[1]
    if (source_url != approved_url or checksum_url != approved_url + ".sha256" or expected_sha != approved_sha
            or archive.name != filename or checksum.name != "httpd.sha256" or archive.parent != checksum.parent):
        raise ValueError("cached HTTPD provider/filename/current-pin identity mismatch")


def checked_metadata(descriptor, expected_sha, filename):
    metadata = os.read(descriptor, 4097)
    fields = metadata.decode("ascii").split()
    if len(fields) != 2 or fields[0] != expected_sha or fields[1] not in (filename, "*" + filename):
        raise ValueError("cached checksum does not match the reviewed HTTPD pin and filename")
    return metadata


def hash_archive(descriptor, info):
    digest = hashlib.sha256()
    remaining = info.st_size
    while remaining:
        chunk = os.read(descriptor, min(remaining, 1024 * 1024))
        if not chunk:
            raise ValueError("cached archive changed while reading")
        digest.update(chunk)
        remaining -= len(chunk)
    if file_identity(os.fstat(descriptor)) != file_identity(info):
        raise ValueError("cached archive changed while hashing")
    return digest.hexdigest()


def verify_cache(archive, checksum, source_url, checksum_url, expected_sha):
    approved_url, approved_sha = approved_contract()
    archive, checksum = Path(archive), Path(checksum)
    require_provider_identity(archive, checksum, source_url, checksum_url, expected_sha, approved_url, approved_sha)
    metadata_descriptor, metadata_info = private_file(checksum, 4096)
    archive_descriptor, archive_info = None, None
    try:
        metadata = checked_metadata(metadata_descriptor, approved_sha, archive.name)
        archive_descriptor, archive_info = private_file(archive, 512 * 1024 * 1024)
        archive_sha = hash_archive(archive_descriptor, archive_info)
        if (archive_sha != approved_sha
                or file_identity(os.fstat(metadata_descriptor)) != file_identity(metadata_info)):
            raise ValueError("cached HTTPD archive/metadata integrity mismatch")
        return {"schema_version": 1, "provenance": "cached_verified_metadata", "source_url": approved_url,
                "checksum_url": checksum_url, "archive_sha256": archive_sha,
                "checksum_sha256": hashlib.sha256(metadata).hexdigest(), "archive": str(archive), "checksum": str(checksum)}
    finally:
        os.close(metadata_descriptor)
        if archive_descriptor is not None:
            os.close(archive_descriptor)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("archive", "checksum", "source-url", "checksum-url", "expected-sha"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    try:
        result = verify_cache(args.archive, args.checksum, args.source_url, args.checksum_url, args.expected_sha)
    except (OSError, ValueError):
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
