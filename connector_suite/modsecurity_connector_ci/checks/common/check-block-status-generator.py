#!/usr/bin/env python3
"""Smoke checks for ci/tools/generate-block-status-config.py."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import filecmp
import subprocess
import sys
import tempfile
from pathlib import Path


REPO_ROOT = connector_root()
GENERATOR = source_path('ci/tools/generate-block-status-config.py', root=REPO_ROOT)
HEADER = "msconnector_block_statuses.generated.h"
SOURCE = "msconnector_block_statuses.generated.c"
HAPROXY_CFG = "haproxy-block-status-rules.generated.cfg"


FULL_STATUS_LIST = "400,401,403,404,405,406,408,409,410,413,415,418,422,425,429,451,500,501,502,503,504"
FULL_STATUSES = tuple(int(value) for value in FULL_STATUS_LIST.split(","))
DEFAULT_WEB_SERVER_STATUSES = "403,501"

RUNS = (
    ("nginx", DEFAULT_WEB_SERVER_STATUSES),
    ("apache", DEFAULT_WEB_SERVER_STATUSES),
    ("haproxy", "401,403,406,429,501,503"),
    ("envoy", "403"),
    ("traefik", "403"),
    ("lighttpd", "403"),
)


def run_generator(
    connector: str,
    statuses: str,
    out_dir: Path,
    working_dir: Path,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(GENERATOR),
            "--connector",
            connector,
            "--statuses",
            statuses,
            "--out-dir",
            str(out_dir),
        ],
        check=False,
        cwd=working_dir,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def require_success(result: subprocess.CompletedProcess[str]) -> None:
    require(result.returncode == 0, f"expected success, got {result.returncode}: {result.stderr}")


def require_failure(result: subprocess.CompletedProcess[str], expected: str) -> None:
    require(result.returncode != 0, "expected generator to fail")
    require(expected in result.stderr, f"expected {expected!r} in stderr: {result.stderr!r}")


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def check_successful_runs(tmp: Path) -> None:
    for connector, statuses in RUNS:
        out_dir = tmp / connector
        require_success(run_generator(connector, statuses, Path(connector), tmp))
        header = out_dir / HEADER
        source = out_dir / SOURCE
        haproxy_cfg = out_dir / HAPROXY_CFG
        require(header.is_file(), f"missing header for {connector}")
        require(source.is_file(), f"missing source for {connector}")
        require(haproxy_cfg.is_file() == (connector == "haproxy"), f"unexpected HAProxy cfg state for {connector}")

        header_text = read(header)
        requested = {int(value) for value in statuses.split(",")}
        has_501 = "#define MSCONNECTOR_ENABLE_BLOCK_STATUS_501 1" in header_text
        require(has_501 == (501 in requested), f"501 enablement mismatch for {connector}")
        if 501 not in requested:
            require("#define MSCONNECTOR_ENABLE_BLOCK_STATUS_501 0" in header_text, f"501 disabled macro missing for {connector}")
        require("#define MSCONNECTOR_ENABLE_BLOCK_STATUS_400 0" in header_text, f"disabled 400 macro missing for {connector}")

        source_text = read(source)
        require("#include \"msconnector_block_statuses.generated.h\"" in source_text, f"missing generated include for {connector}")
        require("msconnector_generated_block_status_is_enabled" in source_text, f"missing accessor for {connector}")

    haproxy_text = read(tmp / "haproxy" / HAPROXY_CFG)
    require("http-request deny status 501 if { var(txn.modsec.status) -m int 501 }" in haproxy_text, "missing HAProxy request 501 mapping")
    require("http-response deny status 501 if { var(txn.modsec.status) -m int 501 }" in haproxy_text, "missing HAProxy response 501 mapping")


def check_full_status_list(tmp: Path) -> None:
    out_dir = tmp / "full-haproxy"
    require_success(run_generator("haproxy", FULL_STATUS_LIST, out_dir.relative_to(tmp), tmp))
    header_text = read(out_dir / HEADER)
    source_text = read(out_dir / SOURCE)
    haproxy_text = read(out_dir / HAPROXY_CFG)

    for status in FULL_STATUSES:
        require(
            f"#define MSCONNECTOR_ENABLE_BLOCK_STATUS_{status} 1" in header_text,
            f"full list did not enable {status}",
        )
        require(
            f"http-request deny status {status} if {{ var(txn.modsec.status) -m int {status} }}" in haproxy_text,
            f"full HAProxy config missing request mapping for {status}",
        )
        require(
            f"http-response deny status {status} if {{ var(txn.modsec.status) -m int {status} }}" in haproxy_text,
            f"full HAProxy config missing response mapping for {status}",
        )

    require("#define MSCONNECTOR_ENABLE_BLOCK_STATUS_200" not in header_text, "unexpected 200 generated macro")
    require("deny status 200" not in haproxy_text, "disabled 200 appeared in HAProxy config")
    require("501" in source_text, "501 should appear in generated source only when explicitly requested")


def check_failures(tmp: Path) -> None:
    require_failure(run_generator("nginx", "403,403", Path("duplicate"), tmp), "duplicate status")
    require_failure(run_generator("nginx", "99", Path("invalid-low"), tmp), "outside the valid HTTP range")
    require_failure(run_generator("nginx", "200", Path("unsupported"), tmp), "global block-status contract")
    require_failure(run_generator("not-a-connector", "403", Path("unknown"), tmp), "unsupported connector")
    require_failure(run_generator("nginx", "", Path("empty"), tmp), "must not be empty")
    require_failure(run_generator("nginx", "abc", Path("non-integer"), tmp), "must be an integer")


def check_output_containment(tmp: Path) -> None:
    nested = Path("nested") / "nginx"
    require_success(run_generator("nginx", DEFAULT_WEB_SERVER_STATUSES, nested, tmp))
    require((tmp / nested / HEADER).is_file(), "nested in-root output was not generated")

    traversal_target = tmp.parent / "block-status-generator-traversal-escape"
    require_failure(
        run_generator("nginx", DEFAULT_WEB_SERVER_STATUSES, Path("..") / traversal_target.name, tmp),
        "must stay beneath the current working directory",
    )
    require(not traversal_target.exists(), "traversal path escaped the working directory")

    absolute_target = tmp.parent / "block-status-generator-absolute-escape"
    require_failure(
        run_generator("nginx", DEFAULT_WEB_SERVER_STATUSES, absolute_target, tmp),
        "must be a relative path beneath the current working directory",
    )
    require(not absolute_target.exists(), "absolute path escaped the working directory")

    symlink_target = tmp.parent / "block-status-generator-symlink-escape"
    symlink = tmp / "outside-link"
    symlink.symlink_to(symlink_target, target_is_directory=True)
    require_failure(
        run_generator("nginx", DEFAULT_WEB_SERVER_STATUSES, Path(symlink.name) / "generated", tmp),
        "must stay beneath the current working directory",
    )
    require(not (symlink_target / "generated").exists(), "symlink path escaped the working directory")

    output_dir = tmp / "final-file-symlink"
    output_dir.mkdir()
    final_file_target = tmp.parent / "block-status-generator-final-file-escape"
    final_file_link = output_dir / HEADER
    final_file_link.symlink_to(final_file_target)
    require_success(
        run_generator("nginx", DEFAULT_WEB_SERVER_STATUSES, Path(output_dir.name), tmp)
    )
    require(not final_file_target.exists(), "final generated file escaped the working directory")
    require(final_file_link.is_file(), "final generated header was not created")
    require(not final_file_link.is_symlink(), "final generated header remained a symlink")


def check_deterministic(tmp: Path) -> None:
    first = tmp / "deterministic-a"
    second = tmp / "deterministic-b"
    require_success(run_generator("nginx", "501,403", first.relative_to(tmp), tmp))
    require_success(run_generator("nginx", DEFAULT_WEB_SERVER_STATUSES, second.relative_to(tmp), tmp))
    for filename in (HEADER, SOURCE):
        require(filecmp.cmp(first / filename, second / filename, shallow=False), f"non-deterministic {filename}")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="msconnector-block-status-generator-") as raw_tmp:
        tmp = Path(raw_tmp)
        check_successful_runs(tmp)
        check_full_status_list(tmp)
        check_failures(tmp)
        check_output_containment(tmp)
        check_deterministic(tmp)
    print("block_status_generator: pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
