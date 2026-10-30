#!/usr/bin/env python3
"""Prepare only approved NGINX configure headers for native source analysis."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile

from modsecurity_test_framework.connector_context import (
    connector_root, load_tool, source_path, test_root, validate_checkout,
)


def prepare(output: Path, archives: Path | None) -> dict[str, object]:
    product, framework = connector_root(), test_root()
    if not output.is_absolute() or ".." in output.parts:
        raise ValueError("output must be an explicit absolute external path")
    selected = output.resolve()
    if any(selected.is_relative_to(root) or root.is_relative_to(selected)
           for root in (product, framework)):
        raise ValueError("output must be outside both selected source roots")
    if archives is not None:
        if (not archives.is_absolute() or ".." in archives.parts
                or archives.is_symlink() or not archives.is_dir()):
            raise ValueError("archive cache must be an explicit existing regular directory")
        archives = archives.resolve(strict=True)
    native = load_tool("ci/checks/analysis/prepare-sonar-native-context.py")
    item = native.contracts()["nginx"]
    # The existing admission rejects existing paths and symlinked ancestors.
    output = native.fresh_root(str(output))
    sources, downloads, logs = (output / name for name in ("sources", "downloads", "logs"))
    for directory in (sources, downloads, logs):
        directory.mkdir(mode=0o700)
    archive = native.verified_archive(item, downloads, archives)
    source = native.unpack(archive, sources, item["directory"])
    module = source_path("connectors/nginx", root=product)
    command = native.run(
        ["sh", "./configure", "--with-compat", "--add-dynamic-module=" + str(module)],
        source, logs / "nginx-configure.log",
    )
    generated = native.required_files([
        source / "objs/ngx_auto_config.h", source / "objs/ngx_auto_headers.h",
        source / "objs/Makefile",
    ])
    includes = native.nginx_includes(source)
    native.include_value(includes)
    validate_checkout()
    receipt = {
        "schema_version": 1, "connector_root": str(product),
        "connector_revision": os.environ["CONNECTOR_REVISION"],
        "framework_root": str(framework), "source": str(source),
        "connector_module": str(module), "archive": str(archive),
        "archive_url": item["url"], "archive_sha256": item["sha256"],
        "version": item["version"], "configure": command,
        "includes": [str(path) for path in includes], "generated_files": generated,
        "scope": "configure headers only; no native build or runtime execution",
    }
    (output / "manifest.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--connector-root", required=True)
    parser.add_argument("--connector-revision", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--archives", type=Path)
    args = parser.parse_args()
    os.environ["CONNECTOR_ROOT"] = args.connector_root
    os.environ["CONNECTOR_REVISION"] = args.connector_revision
    try:
        receipt = prepare(args.output, args.archives)
    except (ValueError, OSError, subprocess.SubprocessError, tarfile.TarError) as error:
        print(f"Sonar NGINX configuration failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
