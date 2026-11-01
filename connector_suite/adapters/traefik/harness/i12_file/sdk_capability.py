"""Inspect the exact SDK C declarations and exports without executing a file API."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while part := stream.read(65536):
            digest.update(part)
    return digest.hexdigest()


def admitted_file(path, label):
    if not isinstance(path, Path) or not path.is_absolute() or path.is_symlink():
        raise ValueError("absolute non-symlink " + label + " path required")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise ValueError("existing " + label + " path required") from error
    if resolved != path or not resolved.is_file():
        raise ValueError("canonical regular " + label + " file required")
    return resolved


def inspect(header, library):
    header = admitted_file(header, "SDK header")
    library = admitted_file(library, "SDK library")
    if header.stat().st_size > 1024 * 1024:
        raise ValueError("bounded SDK header required")
    text = header.read_text()
    result = subprocess.run(["/usr/bin/nm", "-D", "--defined-only", "--", str(library)],
                            capture_output=True, check=True, timeout=15)
    if len(result.stdout) > 8 * 1024 * 1024:
        raise ValueError("bounded SDK symbol inventory exceeded")
    symbols = result.stdout.decode().splitlines()
    exported = {line.split()[-1] for line in symbols if line.split()}
    declarations = sorted(set(re.findall(r"\b(msc_\w+)\s*\(", text, flags=re.ASCII)))
    def response_file(name):
        return name.startswith("msc_") and "response" in name and "file" in name
    return {"schema": "traefik-sdk-file-symbols-v1", "header": str(header.resolve()),
            "header_sha256": sha(header), "library": str(library.resolve()), "library_sha256": sha(library),
            "request_file_declared": "msc_request_body_from_file" in declarations,
            "request_file_exported": "msc_request_body_from_file" in exported,
            "response_file_C_declarations": [name for name in declarations if response_file(name)],
            "response_file_C_exports": sorted(name for name in exported if response_file(name)),
            "native_file_api_executed": False, "host_route_executed": False,
            "scope": "exact supplied SDK header and shared library C API; no invented response-file API"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--header", type=Path, required=True)
    parser.add_argument("--library", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(inspect(args.header, args.library), indent=2))


if __name__ == "__main__":
    main()
