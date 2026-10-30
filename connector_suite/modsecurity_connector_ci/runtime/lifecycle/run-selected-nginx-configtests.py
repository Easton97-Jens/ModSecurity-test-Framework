#!/usr/bin/env python3
"""Dispatch only explicitly selected, supported NGINX configuration contracts."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


ROOT = connector_root()
DRIVER = Path(__file__).with_name("run-nginx-configtest.py")
STARTUP_DRIVER = Path(__file__).with_name("run-nginx-valid-rules.py")


def startup_contract() -> dict:
    module = load_source(STARTUP_DRIVER)
    return module.VALID_RULES_CONTRACT


def source_identity(root: Path, *arguments: str) -> str:
    result = subprocess.run(["git", "-C", str(root), *arguments], check=True,
                            capture_output=True, text=True, timeout=10).stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", result):
        raise ValueError("source identity must be an exact Git SHA")
    return result


def selected_invocations(driver, framework: Path) -> list[str]:
    selected = os.environ.get("NO_CRS_SELECTED_CASE_IDS", "").split()
    if len(selected) != len(set(selected)) or any(
            not re.fullmatch(r"[a-z][a-z0-9_]{0,127}", value) for value in selected):
        raise ValueError("selected case identities must be unique and path-safe")
    catalog_path = framework / "tests/cases/no-crs-baseline/catalog.json"
    driver.absolute_path(str(catalog_path))
    records = json.loads(catalog_path.read_text(encoding="utf-8"))["cases"]
    invocations = supported_invocations(driver, records, selected)
    if len(invocations) != len(set(invocations)):
        raise ValueError("duplicate catalog configuration invocations")
    return invocations


def supported_invocations(driver, records: list, selected: list[str]) -> list[str]:
    invocations = []
    for case in records:
        if case["case_id"] not in selected:
            continue
        contract = case.get("config_invocations", {}).get("nginx")
        if contract is None:
            continue  # Never promote other selected cases or infer a runner.
        expected = (startup_contract() if case["case_id"] == "valid_rules_file"
                    else driver.CONFIGTEST_CONTRACTS.get(case["case_id"]))
        if (expected is None or contract != expected
                or type(contract["expected_exit_code"]) is not int):
            raise ValueError("selected configuration invocation has no supported host driver")
        invocations.append(case["case_id"])
    return invocations


def dispatch_paths(driver) -> tuple[Path, Path]:
    build = driver.absolute_path(os.environ["BUILD_ROOT"])
    results = driver.absolute_path(os.environ["RESULTS_DIR"])
    storage = driver.AUTHORIZED_STORAGE_ROOT
    if storage not in build.parents or any(driver.is_checkout(path) for path in (build, *build.parents)):
        raise ValueError("build output must be external authorized task storage")
    results.relative_to(build)
    if any(driver.is_checkout(path) for path in (results, *results.parents)):
        raise ValueError("results must be outside all source checkouts")
    if not build.is_dir():
        raise ValueError("build output root must already exist")
    driver.ensure_safe_runtime_directory(build)
    return build, results


def prepare_output_parent(driver, build: Path, results: Path, invocations: list[str]) -> Path:
    output_parent = driver.absolute_path(str(build / "configtests"))
    output_parent.mkdir(mode=0o700, exist_ok=True)
    driver.ensure_safe_runtime_directory(output_parent)
    driver.ensure_safe_runtime_directory(results.parent)
    results.mkdir(mode=0o700, exist_ok=True)
    driver.ensure_safe_runtime_directory(results)
    if any((output_parent / case_id).exists() or (output_parent / case_id).is_symlink()
           for case_id in invocations):
        raise ValueError("configuration output must be a fresh child")
    return output_parent


def validate_result_input(stream, invocations: list[str]) -> None:
    metadata = os.fstat(stream.fileno())
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 4 * 1024 * 1024:
        raise ValueError("existing result input must be a bounded regular file")
    if (metadata.st_uid != os.geteuid() or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) & 0o022):
        raise ValueError("result input must be owned, single-link, and nonwritable by other users")
    stream.seek(0)
    previous = [json.loads(line) for line in stream if line.strip()]
    if any(row.get("case_id") in invocations for row in previous):
        raise ValueError("configuration invocation result already exists")


def invoke_configtest(driver, case_id: str, prefix: Path, output: Path, run_id: str, identities: tuple) -> tuple:
    parent_sha, framework_sha, mrts_sha = identities
    entrypoint = STARTUP_DRIVER if case_id == "valid_rules_file" else DRIVER
    arguments = [sys.executable, str(entrypoint), "--case-id", case_id,
                 "--nginx-binary", str(prefix / "sbin/nginx"),
                 "--module", str(prefix / "modules/ngx_http_modsecurity_module.so"),
                 "--output-root", str(output), "--run-id", run_id,
                 "--parent-sha", parent_sha, "--framework-sha", framework_sha,
                 "--mrts-sha", mrts_sha]
    if os.environ.get("MODSECURITY_LIB_DIR"):
        arguments += ["--library-dir", os.environ["MODSECURITY_LIB_DIR"]]
    if case_id == "valid_rules_file":
        framework = driver.absolute_path(os.environ["FRAMEWORK_ROOT"])
        projection = driver.absolute_path(os.environ["NGINX_DOCROOT_PROJECTION_PARENT"])
        arguments += ["--rules-file", str(framework / "tests/rules/no-crs-baseline.conf"),
                      "--projection-parent", str(projection), "--framework-root", str(framework)]
    completed = subprocess.run(arguments, check=False, timeout=60 if case_id == "valid_rules_file" else 30)
    print(f"nginx host invocation case={case_id} driver_exit_code={completed.returncode}", file=sys.stderr)
    source = driver.absolute_path(str(output / "source-result.jsonl"))
    if not source.is_file():
        raise ValueError("configuration invocation produced no source result")
    if source.stat().st_size > 65536:
        raise ValueError("configuration source result exceeds the receipt limit")
    rows = [json.loads(line) for line in source.read_text(encoding="utf-8").splitlines()]
    if len(rows) != 1 or rows[0].get("case_id") != case_id:
        raise ValueError("configuration invocation result identity mismatch")
    return rows[0], completed.returncode != 0


def append_configtests(driver, invocations: list[str], prefix: Path, output_parent: Path,
                      run_id: str, identities: tuple, result_path: Path) -> int:
    flags = os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW
    with os.fdopen(os.open(result_path, flags, 0o600), "a+", encoding="utf-8") as stream:
        validate_result_input(stream, invocations)
        failed = False
        for case_id in invocations:
            row, invocation_failed = invoke_configtest(driver, case_id, prefix,
                                                       output_parent / case_id, run_id, identities)
            stream.write(json.dumps(row, sort_keys=True) + "\n")
            stream.flush()
            failed = failed or invocation_failed
        return 1 if failed else 0


def main() -> int:
    driver = load_source(DRIVER)
    try:
        framework = driver.absolute_path(os.environ["FRAMEWORK_ROOT"])
        invocations = selected_invocations(driver, framework)
        if not invocations:
            return 0
        build, results = dispatch_paths(driver)
        prefix = driver.absolute_path(os.environ["NGINX_PREFIX"])
        identities = (source_identity(ROOT, "rev-parse", "HEAD"),
                      source_identity(framework, "rev-parse", "HEAD"),
                      source_identity(framework, "rev-parse", "HEAD:tools/MRTS"))
        run_id = os.environ["NO_CRS_RUN_ID"]
        output_parent = prepare_output_parent(driver, build, results, invocations)
        result_path = driver.absolute_path(str(results / "nginx-results.jsonl"))
        return append_configtests(driver, invocations, prefix, output_parent, run_id, identities, result_path)
    except (KeyError, ValueError, OSError, subprocess.SubprocessError) as error:
        print("selected NGINX configtests rejected: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
