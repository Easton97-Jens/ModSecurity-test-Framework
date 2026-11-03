#!/usr/bin/env python3
"""Dispatch selected supported modern cases without borrowing H1 evidence."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from modsecurity_test_framework.connector_context import connector_root
from tests.runners import nginx_protocol as protocol

HERE = Path(__file__).resolve().parent


def selected_operations(environment, framework):
    """Validate closed selection identities before resolving or launching hosts."""
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", environment["NO_CRS_RUN_ID"]):
        raise ValueError("bounded path-safe protocol run identity required")
    selected = environment.get("NO_CRS_SELECTED_CASE_IDS", "").split()
    if len(selected) != len(set(selected)) or any(not re.fullmatch(r"[a-z][a-z0-9_]{0,127}", case) for case in selected):
        raise ValueError("selected protocol case IDs must be unique bounded tokens")
    catalog = json.loads((framework / "tests/cases/no-crs-baseline/catalog.json").read_bytes())
    if len({case["case_id"] for case in catalog["cases"]}) != len(catalog["cases"]):
        raise ValueError("duplicate protocol catalog identity")
    return [case["case_id"] for case in catalog["cases"]
            if case["case_id"] in selected and protocol.invocation(case) is not None]


def source_identities(framework):
    parent = connector_root()
    return {"parent_sha": subprocess.check_output(["git", "-C", str(parent), "rev-parse", "HEAD"], text=True).strip(),
            "framework_sha": subprocess.check_output(["git", "-C", str(framework), "rev-parse", "HEAD"], text=True).strip(),
            "mrts_sha": subprocess.check_output(["git", "-C", str(framework), "rev-parse", "HEAD:tools/MRTS"], text=True).strip()}


def execute_case(case, environment, framework, identities, output, prefix):
    """Launch one supported contract and return its original source result."""
    protocol_name = protocol.CASES[case][0]
    if protocol_name != environment["NGINX_DOWNSTREAM_PROTOCOL"]:
        raise ValueError("selected protocol operation differs from requested downstream")
    args = [sys.executable, str(HERE / "run-nginx-protocol-cases.py"), "--case-id", case,
                "--nginx-binary", str(prefix / "sbin/nginx"),
                "--module", str(prefix / "modules/ngx_http_modsecurity_module.so"),
                "--output-root", str(output / case), "--run-id", environment["NO_CRS_RUN_ID"],
                "--framework-root", str(framework), "--curl", environment.get("CURL_BIN", "curl")]
    for key, value in identities.items():
        args += ["--" + key.replace("_", "-"), value]
    if environment.get("MODSECURITY_LIB_DIR"):
        args += ["--library-dir", environment["MODSECURITY_LIB_DIR"]]
    completed = subprocess.run(args, check=False, timeout=120)
    source = output / case / "source-result.json"
    if source.is_file():
        row = json.loads(source.read_bytes())
    else:
        row = {"case_id": case, "run_id": environment["NO_CRS_RUN_ID"], "connector": "nginx",
               "integration_mode": protocol.MODE, "status": "BLOCKED" if completed.returncode == 77 else "FAIL",
               "live_executed": False, "reason": "native protocol prerequisites or launch failed"}
    return row, completed.returncode


def run(environment):
    os.umask(0o077)
    framework = Path(environment["FRAMEWORK_ROOT"])
    supported = selected_operations(environment, framework)
    identities = source_identities(framework)
    build, results = Path(environment["BUILD_ROOT"]), Path(environment["RESULTS_DIR"])
    from modsecurity_connector_ci.lib.runtime_path_utils import ensure_safe_runtime_directory
    ensure_safe_runtime_directory(build)
    ensure_safe_runtime_directory(results)
    output = build / ("native-protocol-" + environment["NO_CRS_RUN_ID"])
    output.mkdir(mode=0o700)
    prefix = Path(environment["NGINX_PREFIX"])
    rows, exit_code = [], 0
    for case in supported:
        row, code = execute_case(case, environment, framework, identities, output, prefix)
        rows.append(row)
        if code:
            exit_code = 77 if code == 77 and exit_code in (0, 77) else 1
    with (results / "nginx-results.jsonl").open("x") as stream:
        for row in rows:
            stream.write(json.dumps(row, sort_keys=True) + "\n")
    return exit_code


if __name__ == "__main__":
    try:
        raise SystemExit(run(os.environ))
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as exc:
        print("native protocol selection rejected: " + str(exc), file=sys.stderr)
        raise SystemExit(2)
