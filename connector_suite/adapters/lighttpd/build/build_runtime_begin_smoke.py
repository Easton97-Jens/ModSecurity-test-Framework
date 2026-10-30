#!/usr/bin/env python3
"""Build the selected Framework-owned runtime-begin smoke, never a product artifact."""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from modsecurity_test_framework.connector_context import ConnectorContext, framework_revision, source_path
from modsecurity_connector_ci.lib.active_test_inventory import validate_output_root
from connector_suite.adapters.lighttpd.harness.run_stock_sidecar_real_backend import (
    file_sha256, repository_revision, verify_product_sidecar_manifest,
)


_MODSECURITY_SHARED_LIBRARY_NAME = 'libmodsecurity.so'


def product_source_digest(root: Path) -> str:
    """Match the product builder's ordered, NUL-framed source receipt."""
    paths = [root / relative for relative in (
        "connectors/lighttpd/stock_sidecar/stock_sidecar.c",
        "connectors/lighttpd/stock_sidecar/stock_sidecar.h",
        "common/runtime/msconnector_runtime.c", "common/runtime/msconnector_runtime.h",
        "connectors/profile_registry.c", "connectors/profile_registry.h",
        "common/src/header_validation_internal.h",
    )]
    paths += sorted((root / "common/src").glob("*.c"))
    paths += sorted((root / "common/include/msconnector").glob("*.h"))
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.relative_to(root).as_posix().encode() + b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).hexdigest().encode() + b"\n")
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sidecar-binary", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    args = parser.parse_args()
    if os.environ.get("ON_DEMAND_TESTS") != "1":
        parser.error("this specialist build requires explicit ON_DEMAND_TESTS=1")
    os.environ["CONNECTOR_TEST_OUTPUT_ROOT"] = str(args.output_root)
    context = ConnectorContext.from_environment()
    output = Path(tempfile.mkdtemp(prefix="lighttpd-stock-tests-",
                                dir=validate_output_root(context.connector, context.output)))
    compiler = shutil.which(os.environ.get("CC", "cc"))
    if compiler is None:
        raise ValueError("the selected C compiler is unavailable")
    include = Path(os.environ["MODSECURITY_INCLUDE_DIR"])
    libraries = Path(os.environ["MODSECURITY_LIB_DIR"])
    if (not include.is_absolute() or not (include / "modsecurity/modsecurity.h").is_file()
            or not libraries.is_absolute() or not (libraries / _MODSECURITY_SHARED_LIBRARY_NAME).is_file()):
        raise ValueError("explicit absolute libmodsecurity SDK paths are required")
    binary = args.sidecar_binary
    commit, state = repository_revision()
    product = verify_product_sidecar_manifest(binary, file_sha256(binary, "Stock lighttpd Sidecar"), commit, state)
    source = source_path("connectors/lighttpd/stock_sidecar/runtime_begin_smoke.c")
    source_digest = file_sha256(source, "Runtime begin smoke source")
    product_manifest_digest = file_sha256(binary.parent / "stock-sidecar-artifact.manifest", "Sidecar manifest")
    if (product_source_digest(context.connector) != product["sidecar_source_inputs_sha256"] or
            file_sha256((libraries / _MODSECURITY_SHARED_LIBRARY_NAME).resolve(strict=True), "ModSecurity library") != product["modsecurity_library_sha256"]):
        raise ValueError("smoke compile inputs differ from the product artifact provenance")
    smoke = output / "runtime-begin-smoke"
    command = [compiler, "-std=c17", "-Wall", "-Wextra", "-Werror", "-pthread",
               "-I" + str(context.connector), "-I" + str(context.connector / "common/include"),
               "-I" + str(context.connector / "common/runtime"),
               "-I" + str(context.connector / "connectors/lighttpd/stock_sidecar"), "-I" + str(include),
               str(source), str(context.connector / "common/runtime/msconnector_runtime.c"),
               str(context.connector / "connectors/profile_registry.c"),
               *(str(path) for path in sorted((context.connector / "common/src").glob("*.c"))),
               "-L" + str(libraries), "-Wl,-rpath," + str(libraries), "-lmodsecurity", "-lcrypto", "-lyajl",
               "-o", str(smoke)]
    completed = subprocess.run(command, capture_output=True, text=True, check=False, timeout=180)
    if completed.returncode:
        raise RuntimeError("runtime-begin smoke compile/link failed:\n" + completed.stderr)
    if (product_source_digest(context.connector) != product["sidecar_source_inputs_sha256"] or
            file_sha256(source, "Runtime begin smoke source") != source_digest or
            file_sha256(binary.parent / "stock-sidecar-artifact.manifest", "Sidecar manifest") != product_manifest_digest or
            file_sha256((libraries / _MODSECURITY_SHARED_LIBRARY_NAME).resolve(strict=True), "ModSecurity library") != product["modsecurity_library_sha256"]):
        raise ValueError("smoke or product source provenance changed during compilation")
    values = {
        **product, "schema_version": "1", "artifact_kind": "lighttpd_stock_sidecar_test_artifacts",
        "framework_revision": framework_revision(),
        "product_manifest_sha256": product_manifest_digest,
        "runtime_begin_smoke_source_sha256": source_digest,
        "runtime_begin_smoke_path": str(smoke),
        "runtime_begin_smoke_sha256": file_sha256(smoke, "Runtime begin smoke"),
    }
    if any("\n" in value or "\r" in value for value in values.values()):
        raise ValueError("test artifact metadata must use single-line values")
    manifest = output / "stock-sidecar-test-artifact.manifest"
    manifest.write_text("".join(f"{key}={value}\n" for key, value in sorted(values.items())))
    manifest.chmod(0o444)
    print(manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
