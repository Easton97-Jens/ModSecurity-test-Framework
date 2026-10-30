#!/usr/bin/env python3
"""Compile native Framework sources and record successful real compiler commands."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import runpy
import tempfile
from pathlib import Path
import shlex
import shutil
import subprocess
import stat
import sys


DATABASE_FILENAME = "compile_commands.json"
EVIDENCE_FILENAME = "compilation-evidence.json"


def record_compile(fragment: Path, compiler: str, arguments: list[str]) -> None:
    """Write evidence only after the actual unmodified compiler argv succeeds."""
    if fragment.is_symlink():
        raise ValueError("refusing symlinked compiler evidence")
    fragment.unlink(missing_ok=True)
    subprocess.run([compiler, *arguments], check=True)
    if arguments.count("-c") != 1:
        raise ValueError("expected one compile-only source argument")
    source = arguments[arguments.index("-c") + 1]
    record = {
        "directory": str(Path.cwd()),
        "file": source,
        "arguments": [compiler, *arguments],
    }
    fragment.write_text(json.dumps(record) + "\n", encoding="utf-8")


def sdk_layout(sdk: Path) -> tuple[Path, Path]:
    """Accept installed prefixes or the existing approved native build layout."""
    layouts = (
        (sdk / "include", sdk / "lib"),
        (sdk / "include", sdk / "lib/x86_64-linux-gnu"),
        (sdk / "headers", sdk / "src/.libs"),
    )
    for headers, library_dir in layouts:
        if (headers / "modsecurity/modsecurity.h").is_file() and (
            library_dir / "libmodsecurity.so"
        ).is_file():
            return headers, library_dir
    raise ValueError(
        "ModSecurity SDK requires installed include/lib or native headers/src/.libs"
    )


def validate_output_leaves(output: Path) -> None:
    for filename in (
        DATABASE_FILENAME,
        EVIDENCE_FILENAME,
        "compiler-command.json",
        "capture-compiler",
        "v3_api_smoke.o",
    ):
        if (output / filename).is_symlink():
            raise ValueError("refusing symlinked analysis output file")


def prepare_output_files(output: Path) -> None:
    """Initialize only a previously admitted, external private output root."""
    validate_output_leaves(output)
    output.mkdir(parents=True, exist_ok=True)
    output.chmod(0o700)
    for stale in (DATABASE_FILENAME, EVIDENCE_FILENAME):
        (output / stale).unlink(missing_ok=True)


def sdk_stage_links(output: Path, headers: Path, library_dir: Path) -> tuple:
    """Validate the complete staging layout without creating or replacing paths."""
    stage = output / "sdk"
    if stage.is_symlink() or (stage / "src").is_symlink():
        raise ValueError("refusing symlinked SDK staging directory")
    links = ((stage / "headers", headers), (stage / "src/.libs", library_dir))
    for destination, source in links:
        if destination.is_symlink() and destination.resolve() == source.resolve():
            continue
        if destination.exists() or destination.is_symlink():
            raise ValueError(f"refusing to replace existing SDK path: {destination}")
    return links


def stage_sdk(output: Path, headers: Path, library_dir: Path) -> Path:
    """Reuse the unchanged native Makefile layout after all root admission."""
    links = sdk_stage_links(output, headers, library_dir)
    stage = output / "sdk"
    (stage / "src").mkdir(parents=True, exist_ok=True)
    for destination, source in links:
        if not destination.is_symlink():
            destination.symlink_to(source, target_is_directory=True)
    return stage


def git(root: Path, *arguments: str) -> str:
    return subprocess.check_output(
        ["git", "--no-replace-objects", "-C", str(root), *arguments],
        text=True,
        timeout=60,
    ).strip()


def admitted_directory(path: Path, label: str) -> Path:
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError(f"{label} must be an absolute directory")
    for component in (path, *path.parents):
        if component.is_symlink():
            raise ValueError(f"{label} has a symlinked component")
    if not path.is_dir():
        raise ValueError(f"missing {label}: {path}")
    return path.resolve()


def file_hash(path: Path) -> str:
    if any(component.is_symlink() for component in (path, *path.parents)):
        raise ValueError(f"native input has a symlinked component: {path}")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or not 0 < before.st_size <= 8 * 1024 * 1024
        ):
            raise ValueError(
                f"native input must be a bounded nonempty regular file: {path}"
            )
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(8 * 1024 * 1024 + 1)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ValueError("native input changed while hashing")
        if len(data) != before.st_size:
            raise ValueError("native input exceeded stable read bounds")
        return hashlib.sha256(data).hexdigest()
    finally:
        os.close(descriptor)


def header_files(root: Path):
    for directory, subdirs, files in os.walk(root, followlinks=False):
        if any((Path(directory) / name).is_symlink() for name in subdirs):
            raise ValueError("host/SDK include directory contains a symlink")
        for name in files:
            path = Path(directory) / name
            if path.suffix in {".h", ".hpp", ".inc"}:
                yield path


def snapshot_headers(roots: list[Path]) -> dict[str, str]:
    result = {}
    total = 0
    for path in (path for root in roots for path in header_files(root)):
        if str(path) in result:
            continue
        result[str(path)] = file_hash(path)
        total += path.stat().st_size
        if len(result) > 8192 or total > 128 * 1024 * 1024:
            raise ValueError("host/SDK header snapshot exceeds input bounds")
    return result


def product_identity(root: Path, expected: str) -> str:
    if not re.fullmatch(r"[a-f0-9]{40}", expected):
        raise ValueError("Product revision must be an exact commit")
    if git(root, "rev-parse", "--show-toplevel") != str(root):
        raise ValueError("Product root must be its own Git checkout")
    actual = git(root, "rev-parse", "HEAD")
    if actual != expected or git(
        root, "status", "--porcelain", "--untracked-files=all"
    ):
        raise ValueError("Product source must be clean at the explicit revision")
    for required in (
        "common/include/msconnector/transaction_contract.h",
        "connectors/profile_registry.h",
    ):
        file_hash(root / required)
    return actual


def native_inventory(root: Path) -> set[Path]:
    tracked = git(root, "ls-files", "-z").split("\0")
    return {
        root / name
        for name in tracked
        if Path(name).suffix.lower() in {".c", ".cc", ".cpp", ".cxx", ".m", ".mm"}
    }


def snapshot_tree(root: Path) -> dict[str, str]:
    paths = git(root, "ls-files", "-z").split("\0")
    selected = [
        root / name
        for name in paths
        if name
        and (
            Path(name).suffix.lower()
            in {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".inc"}
            or name
            in {
                "src/v3-api-smoke/Makefile",
                "ci/checks/analysis/native-cfamily-recipes.py",
                "ci/checks/analysis/prepare-sonar-cfamily.py",
                "connector_suite/modsecurity_connector_tests/c_source_contract.py",
            }
        )
    ]
    # New reviewed helpers are included before their first commit as well.
    for name in ("ci/checks/analysis/native-cfamily-recipes.py",):
        if (root / name).is_file() and root / name not in selected:
            selected.append(root / name)
    if len(selected) > 8192:
        raise ValueError("native source snapshot exceeds file bound")
    return {str(path): file_hash(path) for path in sorted(selected)}


def nginx_include_path(
    source: Path, token: str, product: Path, sdk_headers: Path | None = None
) -> Path | None:
    if not token.startswith("-I") or not token[2:]:
        raise ValueError("only include directories are admitted from NGINX ALL_INCS")
    raw = source / token[2:]
    if any(component.is_symlink() for component in (raw, *raw.parents)):
        raise ValueError("NGINX include has a symlinked component")
    directory = admitted_directory(raw.resolve(), "NGINX include root")
    if directory in {product, product / "common/include"}:
        return None  # Already explicit Product roots, not host context.
    if sdk_headers is not None and directory == sdk_headers:
        return None  # Already the explicitly admitted and snapshotted SDK headers.
    if not directory.is_relative_to(source):
        raise ValueError("NGINX include escapes explicit source root")
    return directory


def nginx_include_directories(
    source: Path, product: Path, tokens: list[str], sdk_headers: Path | None = None
) -> list[Path]:
    result = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "-I":
            index += 1
            if index == len(tokens):
                raise ValueError("invalid configured NGINX include list")
            token = "-I" + tokens[index]
        directory = nginx_include_path(source, token, product, sdk_headers)
        if directory is not None and directory not in result:
            result.append(directory)
        index += 1
    return result


def nginx_includes(
    source: Path, build: Path, product: Path, sdk_headers: Path | None = None
) -> tuple[list[Path], dict[str, str]]:
    if not build.is_relative_to(source):
        raise ValueError(
            "configured NGINX build must be inside its explicit source root"
        )
    if sdk_headers is not None:
        sdk_headers = admitted_directory(sdk_headers, "SDK include root")
    identities = {
        str(build / name): file_hash(build / name)
        for name in ("ngx_auto_config.h", "ngx_auto_headers.h", "Makefile")
    }
    text = (build / "Makefile").read_text().replace("\\\n", " ")
    declarations = [
        line.partition("=")[2]
        for line in text.splitlines()
        if line.partition("=")[0].strip() == "ALL_INCS"
    ]
    if len(declarations) != 1:
        raise ValueError("configured NGINX must declare one ALL_INCS")
    result = nginx_include_directories(
        source, product, shlex.split(declarations[0]), sdk_headers
    )
    for header, relative in (
        ("ngx_config.h", "src/core"),
        ("ngx_core.h", "src/core"),
        ("ngx_http.h", "src/http"),
    ):
        identities[str(source / relative / header)] = file_hash(
            source / relative / header
        )
    if build not in result:
        raise ValueError("configured NGINX include list omits generated headers")
    return result, identities


def compile_arguments(
    source: Path, obj: Path, includes: list[Path], sdk_headers: Path
) -> list[str]:
    standard = "c++17" if source.suffix in {".cc", ".cpp", ".cxx"} else "c17"
    arguments = [
        f"-std={standard}",
        "-D_POSIX_C_SOURCE=200809L",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pthread",
        "-fPIC",
        "-fno-lto",
        "-ffunction-sections",
        "-fdata-sections",
    ]
    if source.name == "apache_header_semantics_probe.c":
        # apr-1-config --cppflags in its existing native test recipe.
        arguments.extend(["-DLINUX", "-D_REENTRANT", "-D_GNU_SOURCE"])
    for directory in includes:
        # Existing native C++ observer recipes classify external SDK headers as
        # system headers, preserving -Wall/-Wextra/-Werror on maintained code.
        kind = "-isystem" if standard == "c++17" and directory == sdk_headers else "-I"
        arguments.extend([kind, str(directory)])
    return [*arguments, "-c", str(source), "-o", str(obj)]


def validated_records(root: Path, units: set[Path], records: list[dict]) -> None:
    captured = [(Path(item["directory"]) / item["file"]).resolve() for item in records]
    if len(captured) != len(set(captured)) or units != set(captured):
        raise ValueError(
            "native source inventory does not match actual compilation; update native build capture"
        )
    objects = []
    for record in records:
        arguments = record["arguments"]
        if arguments.count("-c") != 1 or arguments.count("-o") != 1:
            raise ValueError(
                "native capture requires one real compile-only source and object"
            )
        if (
            Path(record["directory"]) / arguments[arguments.index("-c") + 1]
        ).resolve() != (Path(record["directory"]) / record["file"]).resolve():
            raise ValueError("native record source differs from real compiler input")
        obj = Path(arguments[arguments.index("-o") + 1])
        if obj.is_symlink() or not obj.is_file() or not obj.stat().st_size:
            raise ValueError("native compilation did not produce an object")
        objects.append(obj.resolve())
    if len(objects) != len(set(objects)):
        raise ValueError("native objects must be unique per source")


def admit_output(capture: argparse.Namespace) -> None:
    if not capture.output.is_absolute() or ".." in capture.output.parts:
        raise ValueError("analysis output must be an absolute path without traversal")
    if any(
        component.is_symlink()
        for component in (capture.output, *capture.output.parents)
    ):
        raise ValueError("refusing symlinked analysis output")
    capture.root, capture.output, capture.sdk = (
        capture.root.resolve(),
        capture.output.absolute(),
        capture.sdk.resolve(),
    )
    if (
        capture.output == capture.root
        or capture.root in capture.output.parents
        or capture.output in capture.root.parents
    ):
        raise ValueError("analysis output must be outside the checkout")
    capture.compiler = shutil.which(capture.compiler_name)
    if capture.compiler is None:
        raise ValueError("a real native C compiler is required")
    capture.headers, capture.library_dir = sdk_layout(capture.sdk)
    validate_output_leaves(capture.output)
    sdk_stage_links(capture.output, capture.headers, capture.library_dir)


def admit_product_and_hosts(capture: argparse.Namespace) -> None:
    if capture.connector_root is None or capture.connector_revision is None:
        raise ValueError(
            "explicit Product root and revision are required for full native capture"
        )
    capture.product = admitted_directory(capture.connector_root, "Product root")
    if (
        capture.root == capture.product
        or capture.root.is_relative_to(capture.product)
        or capture.product.is_relative_to(capture.root)
    ):
        raise ValueError("Framework and Product source roots must be separate")
    product_identity(capture.product, capture.connector_revision)
    if any(
        value is None
        for value in (
            capture.apache_include,
            capture.apr_include,
            capture.nginx_source,
            capture.nginx_build,
        )
    ):
        raise ValueError("explicit Apache, APR and configured NGINX roots are required")
    capture.apache = admitted_directory(capture.apache_include, "Apache include root")
    capture.apr = admitted_directory(capture.apr_include, "APR include root")
    capture.nginx = admitted_directory(capture.nginx_source, "NGINX source root")
    capture.configured = admitted_directory(capture.nginx_build, "NGINX build root")
    capture.host_includes, capture.host_hashes = nginx_includes(
        capture.nginx, capture.configured, capture.product, capture.headers
    )
    capture.host_hashes.update(
        {
            str(capture.apache / "httpd.h"): file_hash(capture.apache / "httpd.h"),
            str(capture.apr / "apr.h"): file_hash(capture.apr / "apr.h"),
        }
    )
    for input_root in (
        capture.product,
        capture.sdk,
        capture.nginx,
        capture.apache,
        capture.apr,
    ):
        if (
            capture.output == input_root
            or capture.output.is_relative_to(input_root)
            or input_root.is_relative_to(capture.output)
        ):
            raise ValueError("analysis output must be outside all source and SDK roots")
    capture.cxx = shutil.which(capture.cxx_compiler)
    if capture.cxx is None:
        raise ValueError("a real native C++ compiler is required")


def snapshot_capture_inputs(capture: argparse.Namespace) -> None:
    capture.recipes = runpy.run_path(
        str(capture.root / "ci/checks/analysis/native-cfamily-recipes.py")
    )
    capture.units = native_inventory(capture.root)
    if capture.units != {
        capture.root / name for name in capture.recipes["NATIVE_UNITS"]
    }:
        raise ValueError(
            "native source inventory differs from the closed reviewed recipes"
        )
    capture.header_roots = [
        capture.headers,
        capture.apache,
        capture.apr,
        *capture.host_includes,
    ]
    capture.host_hashes.update(snapshot_headers(capture.header_roots))
    capture.initial = {**snapshot_tree(capture.root), **snapshot_tree(capture.product)}
    capture.framework_revision = git(capture.root, "rev-parse", "HEAD")


def materialize_capture(capture: argparse.Namespace, run: Path) -> dict[str, str]:
    capture.projection = run / "includes"
    capture.projection.mkdir(mode=0o700)
    (capture.projection / "tests").symlink_to(
        capture.root / "connector_suite/modsecurity_connector_tests",
        target_is_directory=True,
    )
    for name, relative in (
        ("PRODUCT_BINDING", "connectors/haproxy/src/haproxy_modsecurity_binding.c"),
        ("PRODUCT_RUNTIME", "connectors/haproxy/src/haproxy_spop_diagnostic_runtime.c"),
    ):
        file_hash(capture.product / relative)
        if name == "PRODUCT_RUNTIME":
            (capture.projection / name).write_text(
                '#include "'
                + str(capture.product / relative)
                + '"\n'
                + capture.recipes["spop_fixture_helper"]()
                + "\n"
            )
        else:
            (capture.projection / name).symlink_to(capture.product / relative)
    runtime_hash = file_hash(capture.projection / "PRODUCT_RUNTIME")
    generated = capture.recipes["materialize_host_includes"](
        (
            capture.product
            / "connectors/haproxy/htx-overlay/haproxy_modsecurity_htx_filter.c"
        ).read_text(),
        capture.projection,
    )
    generated["PRODUCT_RUNTIME"] = runtime_hash
    parts = capture.recipes["lighttpd_parts"](
        native=(
            capture.product / "connectors/lighttpd/module/mod_msconnector.c"
        ).read_text(),
        sidecar=(
            capture.product / "connectors/lighttpd/stock_sidecar/stock_sidecar.c"
        ).read_text(),
    )
    generated.update(
        capture.recipes["write_lighttpd_includes"](parts, capture.projection)
    )
    capture.prelude = capture.projection / "native-haproxy-binding-driver.inc"
    capture.prelude.write_text(
        '#include "'
        + str(capture.product / "connectors/haproxy/src/haproxy_modsecurity_binding.c")
        + '"\n'
        '#include "'
        + str(
            capture.root
            / "connector_native_tests/connectors/haproxy/src/haproxy_modsecurity_binding.inc"
        )
        + '"\n'
    )
    generated[capture.prelude.name] = file_hash(capture.prelude)
    capture.suite = capture.root / "connector_suite"
    capture.includes = [
        capture.projection,
        capture.root / "connector_native_tests",
        capture.suite / "common/include",
        capture.suite,
        capture.product,
        capture.product / "common/include",
        capture.product / "common/runtime",
        capture.headers,
        capture.apache,
        capture.apr,
        *capture.host_includes,
    ]
    capture.includes += [
        capture.product / "connectors" / connector / "src"
        for connector in ("apache", "nginx", "haproxy", "envoy", "traefik", "lighttpd")
    ]
    capture.includes += [capture.product / "connectors/lighttpd/stock_sidecar"]
    capture.environment = {"PATH": os.defpath, "LC_ALL": "C", "TMPDIR": str(run)}
    return generated


def compile_unit(
    capture: argparse.Namespace, run: Path, source: Path
) -> tuple[dict, dict]:
    smoke = capture.root / "src/v3-api-smoke/v3_api_smoke.c"
    key = hashlib.sha256(str(source.relative_to(capture.root)).encode()).hexdigest()[
        :24
    ]
    obj = run / (key + ".o")
    fragment = run / (key + ".json")
    log = run / (key + ".log")
    with log.open("x") as stream:
        if source == smoke:
            wrapper = run / "capture-compiler"
            invocation = [
                sys.executable,
                str(Path(__file__).resolve()),
                "--record-compile",
                str(fragment),
                capture.compiler,
            ]
            wrapper.write_text("#!/bin/sh\nexec " + shlex.join(invocation) + ' "$@"\n')
            wrapper.chmod(0o700)
            # Unchanged native smoke recipe and C99 warning contract.
            obj = run / "v3_api_smoke.o"
            subprocess.run(
                [
                    "make",
                    "--always-make",
                    "-C",
                    str(smoke.parent),
                    str(obj),
                    f"MODSECURITY_V3_DIR={capture.stage}",
                    f"BUILD_ROOT={run}",
                    f"BUILD_DIR={run}",
                    f"CC={wrapper}",
                ],
                env=capture.environment,
                stdout=stream,
                stderr=subprocess.STDOUT,
                check=True,
                timeout=120,
            )
        else:
            selected = (
                capture.cxx
                if source.suffix in {".cc", ".cpp", ".cxx"}
                else capture.compiler
            )
            arguments = compile_arguments(
                source, obj, capture.includes, capture.headers
            )
            if (
                source
                == capture.suite
                / "adapters/haproxy/src/haproxy_modsecurity_binding_self_test.c"
            ):
                arguments[:0] = ["-include", str(capture.prelude)]
            command = [
                sys.executable,
                str(Path(__file__).resolve()),
                "--record-compile",
                str(fragment),
                selected,
                *arguments,
            ]
            subprocess.run(
                command,
                cwd=capture.root,
                env=capture.environment,
                stdout=stream,
                stderr=subprocess.STDOUT,
                check=True,
                timeout=120,
            )
    record = json.loads(fragment.read_text())
    receipt = {
        "source": str(source.relative_to(capture.root)),
        "source_sha256": capture.initial[str(source)],
        "object": str(obj),
        "object_sha256": file_hash(obj),
        "record": str(fragment),
        "record_sha256": file_hash(fragment),
        "log": str(log),
    }
    return record, receipt


def verify_capture(capture: argparse.Namespace, records: list[dict]) -> None:
    validated_records(capture.root, capture.units, records)
    if (
        native_inventory(capture.root) != capture.units
        or git(capture.root, "rev-parse", "HEAD") != capture.framework_revision
    ):
        raise ValueError(
            "Framework native inventory or revision changed during compilation"
        )
    product_identity(capture.product, capture.connector_revision)
    if capture.initial != {
        **snapshot_tree(capture.root),
        **snapshot_tree(capture.product),
    }:
        raise ValueError("native source changed during compilation")
    if {
        **snapshot_headers(capture.header_roots),
        **{
            str(capture.configured / "Makefile"): file_hash(
                capture.configured / "Makefile"
            )
        },
    } != capture.host_hashes:
        raise ValueError("configured host headers changed during compilation")


def publish_capture(
    capture: argparse.Namespace,
    run: Path,
    records: list[dict],
    source_receipts: list[dict],
    generated: dict[str, str],
) -> Path:
    evidence = {
        "framework_root": str(capture.root),
        "framework_revision": capture.framework_revision,
        "connector_root": str(capture.product),
        "connector_revision": capture.connector_revision,
        "compiler": capture.compiler,
        "cxx_compiler": capture.cxx,
        "sdk": str(capture.sdk),
        "apache_include": str(capture.apache),
        "apr_include": str(capture.apr),
        "nginx_source": str(capture.nginx),
        "nginx_build": str(capture.configured),
        "host_inputs": capture.host_hashes,
        "source_inputs": capture.initial,
        "generated_includes": generated,
        "compiled_units": len(capture.units),
        "units": source_receipts,
    }
    database = capture.output / DATABASE_FILENAME
    pending = run / DATABASE_FILENAME
    pending.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    pending_evidence = run / EVIDENCE_FILENAME
    pending_evidence.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    pending_evidence.replace(capture.output / EVIDENCE_FILENAME)
    pending.replace(database)
    print(f"Validated {len(capture.units)} compiled native units: {database}")
    return database


def prepare(root: Path, output: Path, sdk: Path, compiler_name: str, **inputs) -> Path:
    capture = argparse.Namespace(
        root=root,
        output=output,
        sdk=sdk,
        compiler_name=compiler_name,
        connector_root=None,
        connector_revision=None,
        apache_include=None,
        apr_include=None,
        nginx_source=None,
        nginx_build=None,
        cxx_compiler="g++",
    )
    unknown = set(inputs) - set(vars(capture))
    if unknown:
        raise ValueError("unknown native capture inputs")
    vars(capture).update(inputs)
    admit_output(capture)
    admit_product_and_hosts(capture)
    snapshot_capture_inputs(capture)
    prepare_output_files(capture.output)
    capture.output = admitted_directory(capture.output, "analysis output")
    capture.stage = stage_sdk(capture.output, capture.headers, capture.library_dir)
    run = Path(tempfile.mkdtemp(prefix="capture-", dir=capture.output))
    generated = materialize_capture(capture, run)
    records, receipts = [], []
    for source in sorted(capture.units):
        record, receipt = compile_unit(capture, run, source)
        records.append(record)
        receipts.append(receipt)
        print(
            f"Compiled {len(records)}/{len(capture.units)}: {source.relative_to(capture.root)}",
            flush=True,
        )
    verify_capture(capture, records)
    return publish_capture(capture, run, records, receipts, generated)


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "--record-compile":
        record_compile(Path(sys.argv[2]), sys.argv[3], sys.argv[4:])
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sdk", type=Path, required=True)
    parser.add_argument("--compiler", default="gcc")
    parser.add_argument("--cxx-compiler", default="g++")
    parser.add_argument("--connector-root", type=Path, required=True)
    parser.add_argument("--connector-revision", required=True)
    parser.add_argument("--apache-include", type=Path, required=True)
    parser.add_argument("--apr-include", type=Path, required=True)
    parser.add_argument("--nginx-source", type=Path, required=True)
    parser.add_argument("--nginx-build", type=Path, required=True)
    args = parser.parse_args()
    prepare(
        Path(__file__).resolve().parents[3],
        args.output,
        args.sdk,
        args.compiler,
        connector_root=args.connector_root,
        connector_revision=args.connector_revision,
        apache_include=args.apache_include,
        apr_include=args.apr_include,
        nginx_source=args.nginx_source,
        nginx_build=args.nginx_build,
        cxx_compiler=args.cxx_compiler,
    )


if __name__ == "__main__":
    main()
