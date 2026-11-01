#!/usr/bin/env python3
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path

# CI helpers are shared from ci/lib even when this file is executed directly.


from modsecurity_connector_ci.lib.runtime_path_utils import DEFAULT_RUN_BASENAME, fixed_runtime_temp_parent, is_allowed_runtime_path, is_system_write_path, verified_runtime_paths


CONNECTOR_ROOT = connector_root()
FRAMEWORK_ROOT = source_path('modules/ModSecurity-test-Framework', root=CONNECTOR_ROOT)
# The checked default comes from the shared path-policy helper.  It retains the
# exact policy location while avoiding a second, unchecked temporary-root
# construction in this control script.
VERIFIED_ROOT = fixed_runtime_temp_parent() / DEFAULT_RUN_BASENAME
RUNTIME_POLICY_CONTROL_ROOT = VERIFIED_ROOT / "runtime-policy-control"
RUNTIME_PATH_OVERRIDES = (
    "VERIFIED_RUN_ROOT",
    "VERIFIED_STATE_ROOT",
    "VERIFIED_BUILD_ROOT",
    "VERIFIED_SOURCE_ROOT",
    "VERIFIED_TMP_ROOT",
    "VERIFIED_LOG_ROOT",
    "CACHE_ROOT",
    "VERIFIED_COMPONENT_CACHE",
    "CONNECTOR_COMPONENT_CACHE",
    "SOURCE_ROOT",
    "BUILD_ROOT",
    "TMP_ROOT",
    "LOG_ROOT",
    "NGINX_HARNESS_PARENT",
    "RUNTIME_RUN_ROOT",
    "RUNTIME_LOG_ROOT",
    "MATRIX_ROOT",
    "MRTS_BUILD_ROOT",
    "MRTS_NATIVE_ROOT",
)
VAR_LIB_SELFTEST_PATH = "/var/lib/foo"
VAR_LOG_SELFTEST_PATH = "/var/log/foo"
ETC_SELFTEST_PATH = "/etc/foo"
USR_LOCAL_SELFTEST_PATH = "/usr/local/foo"
PYTHON_BLOCKED_RUNTIME_PATHS = (
    "/var",
    VAR_LIB_SELFTEST_PATH,
    VAR_LOG_SELFTEST_PATH,
    "/var/cache/foo",
    ETC_SELFTEST_PATH,
    USR_LOCAL_SELFTEST_PATH,
    "/root/.local/state/foo",
)
SHELL_SYSTEM_PATH_SELFTEST_PATHS = PYTHON_BLOCKED_RUNTIME_PATHS[:-1]
HAPROXY_BLOCKED_SOURCE_ROOTS = (
    VAR_LIB_SELFTEST_PATH,
    VAR_LOG_SELFTEST_PATH,
    USR_LOCAL_SELFTEST_PATH,
    ETC_SELFTEST_PATH,
)


def fail(message: str) -> None:
    print(f"check-runtime-path-policy: FAIL: {message}")
    raise SystemExit(1)


def policy_environment() -> dict[str, str]:
    """Return a deterministic environment for default-path policy self-tests.

    This checker deliberately verifies *defaults*.  A caller may legitimately
    invoke it beneath a custom Cache-v2 run root, so inherited path overrides
    must not leak into the self-test and make its fixed expected defaults look
    incorrect.
    """
    env = dict(os.environ)
    for name in RUNTIME_PATH_OVERRIDES:
        env.pop(name, None)
    env.update(
        {
            "CONNECTOR_ROOT": str(CONNECTOR_ROOT),
            "FRAMEWORK_ROOT": str(FRAMEWORK_ROOT),
            "REPO_ROOT": str(CONNECTOR_ROOT),
            "VERIFIED_RUN_ROOT": str(VERIFIED_ROOT),
            "RUNNER_TEMP": str(VERIFIED_ROOT),
            "TMPDIR": str(VERIFIED_ROOT),
        }
    )
    return env


def check_python_policy() -> None:
    env = policy_environment()
    writable_allowed = (
        VERIFIED_ROOT,
        VERIFIED_ROOT / "cache-v2",
        VERIFIED_ROOT / "cache-v2" / "shared",
    )
    read_only_sources = (
        Path("/src"),
        Path("/src/ModSecurity-conector-build"),
        CONNECTOR_ROOT,
        source_path('build', root=CONNECTOR_ROOT),
    )
    blocked = tuple(Path(path) for path in PYTHON_BLOCKED_RUNTIME_PATHS)
    for path in writable_allowed:
        if is_system_write_path(path, env):
            fail(f"python marked allowed runtime path as system write path: {path}")
        if not is_allowed_runtime_path(path, env):
            fail(f"python rejected allowed runtime path: {path}")
    for path in read_only_sources:
        if not is_system_write_path(path, env):
            fail(f"python accepted read-only source path as writable: {path}")
        if not is_allowed_runtime_path(path, env):
            fail(f"python rejected read-only source path: {path}")
    for path in blocked:
        if not is_system_write_path(path):
            fail(f"python did not block system/runtime path: {path}")
    paths = verified_runtime_paths(env)
    if paths["CACHE_ROOT"] != str(VERIFIED_ROOT / "cache-v2"):
        fail(f"unexpected default cache root: {paths['CACHE_ROOT']}")
    if paths["VERIFIED_COMPONENT_CACHE"] != str(VERIFIED_ROOT / "cache-v2" / "shared"):
        fail(f"unexpected default shared cache: {paths['VERIFIED_COMPONENT_CACHE']}")


def shell_result(script: str) -> subprocess.CompletedProcess[str]:
    env = policy_environment()
    result = subprocess.run(
        ["bash", "-lc", script],
        cwd=str(CONNECTOR_ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.stdout:
        sys.stdout.write(result.stdout)
    if result.stderr:
        sys.stderr.write(result.stderr)
    return result


def shell_status(script: str) -> int:
    return shell_result(script).returncode


def check_shell_policy() -> None:
    common = "set -eu; . \"$FRAMEWORK_ROOT/ci/lib/common.sh\"; "
    expected_system = SHELL_SYSTEM_PATH_SELFTEST_PATHS
    expected_not_system = (
        str(VERIFIED_ROOT),
        str(VERIFIED_ROOT / "cache-v2"),
        str(VERIFIED_ROOT / "cache-v2" / "shared"),
        str(RUNTIME_POLICY_CONTROL_ROOT),
        "/src",
        "/src/ModSecurity-conector-build",
        str(CONNECTOR_ROOT),
        str(source_path('build', root=CONNECTOR_ROOT)),
    )
    for path in expected_system:
        rc = shell_status(common + f"ci_path_is_system_path {sh_quote(path)}")
        if rc != 0:
            fail(f"shell did not classify system path as blocked: {path}")
    for path in expected_not_system:
        rc = shell_status(common + f"ci_path_is_system_path {sh_quote(path)}")
        if rc == 0:
            fail(f"shell classified allowed runtime path as system path: {path}")

    rc = shell_status(common + f"assert_safe_runtime_path {sh_quote(str(VERIFIED_ROOT / 'cache-v2' / 'shared'))} test_path")
    if rc != 0:
        fail(f"shell rejected allowed safe runtime path: {VERIFIED_ROOT / 'cache-v2' / 'shared'}")
    # Source roots are legitimate non-system/read-only inputs, not mutable
    # runtime destinations.  A Framework candidate may therefore reject them
    # through assert_safe_runtime_path while still accepting the verified cache
    # root above.
    rc = shell_status(common + "assert_safe_runtime_path /root/.local/state/foo test_path")
    if rc == 0:
        fail("shell accepted old /root runtime path")

    haproxy_allowed = haproxy_policy_selftest(str(VERIFIED_ROOT / "cache-v2" / "shared" / "sources"))
    rc = shell_status(haproxy_allowed)
    if rc != 0:
        fail(f"HAProxy smoke policy rejected verified component-cache SOURCE_ROOT: {VERIFIED_ROOT / 'cache-v2' / 'shared' / 'sources'}")

    for blocked_path in HAPROXY_BLOCKED_SOURCE_ROOTS:
        rc = shell_status(haproxy_policy_selftest(blocked_path))
        if rc == 0:
            fail(f"HAProxy smoke policy accepted blocked SOURCE_ROOT: {blocked_path}")


def sh_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def haproxy_policy_selftest(source_root: str, verified_root: Path = VERIFIED_ROOT) -> str:
    build_root = verified_root / "build" / "haproxy-policy-selftest"
    log_root = build_root / "logs"
    return " ".join(
        [
            "set -eu;",
            f"VERIFIED_RUN_ROOT={sh_quote(str(verified_root))}",
            f"CONNECTOR_COMPONENT_CACHE={sh_quote(str(verified_root / 'cache-v2' / 'shared'))}",
            f"SOURCE_ROOT={sh_quote(source_root)}",
            f"BUILD_ROOT={sh_quote(str(build_root))}",
            f"RESULTS_DIR={sh_quote(str(build_root / 'results'))}",
            f"TMP_ROOT={sh_quote(str(build_root / 'tmp'))}",
            f"LOG_ROOT={sh_quote(str(log_root))}",
            f"LOG_DIR={sh_quote(str(log_root / 'haproxy-runtime'))}",
            f"RUNTIME_BASE={sh_quote(str(build_root / 'haproxy-runtime-cases'))}",
            "HAPROXY_SMOKE_POLICY_SELFTEST=1",
            sh_quote(str(source_path("connectors/haproxy/harness/run_haproxy_smoke.sh", root=CONNECTOR_ROOT))),
        ]
    )


ACTIVE_POLICY_CASES = ("python-allowed", "python-blocked", "shell-allowed", "shell-blocked")


def selected_shell_case(name: str) -> None:
    from modsecurity_connector_ci.lib.active_test_inventory import validate_output_root

    parent = os.environ.get("RUNNER_TEMP") or os.environ.get("TMP_ROOT")
    if not parent:
        fail("selected shell policy requires an explicit existing external output root")
    output_root = validate_output_root(CONNECTOR_ROOT, Path(parent))
    for relative in ("ci/lib/common.sh", "tests/runners/case_cli.py"):
        if not (FRAMEWORK_ROOT / relative).is_file():
            fail("selected shell policy requires the pinned Framework checkout")
    with tempfile.TemporaryDirectory(prefix="runtime-policy-", dir=output_root) as temporary:
        verified = Path(temporary)
        source = (str(verified / "cache-v2" / "shared" / "sources")
                  if name == "shell-allowed" else VAR_LIB_SELFTEST_PATH)
        observed = shell_result(haproxy_policy_selftest(source, verified))
        expected_status = 0 if name == "shell-allowed" else 77
        expected_output = ("haproxy_smoke: path-policy-selftest PASS" if name == "shell-allowed" else
                           "haproxy_smoke: blocked SOURCE_ROOT must not use a system path: " + source)
        if (observed.returncode != expected_status or observed.stdout.strip() != expected_output
                or observed.stderr):
            fail("HAProxy/Framework shell policy did not produce its exact selected boundary result")


def selected_policy_case(name: str) -> None:
    """Execute one independently inventoried path/input through its real owner."""
    env = policy_environment()
    allowed = VERIFIED_ROOT / "cache-v2" / "shared"
    if name == "python-allowed":
        if is_system_write_path(allowed, env) or not is_allowed_runtime_path(allowed, env):
            fail("Python rejected the legitimate verified component-cache path")
    elif name == "python-blocked":
        blocked = Path("/root/.local/state/foo")
        if not is_system_write_path(blocked, env) or is_allowed_runtime_path(blocked, env):
            fail("Python accepted the blocked legacy home runtime path")
    elif name in {"shell-allowed", "shell-blocked"}:
        selected_shell_case(name)
    else:
        fail("unknown selected policy case")


def admit_selected_policy_case(name: str) -> None:
    from modsecurity_connector_ci.lib.active_test_inventory import InventoryError, load_inventory

    inventory = load_inventory(CONNECTOR_ROOT)
    matches = [item for item in inventory.executions if item["selector"] == {
        "kind": "native", "script": "ci/checks/security/run-active-runtime-path-policy.sh", "args": [name]
    }]
    if len(matches) != 1 or len(matches[0]["cases"]) != 1:
        raise InventoryError("runtime-path case is absent or not singly expanded in the active inventory")


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate the selected runtime-path policy boundary.")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--case", choices=ACTIVE_POLICY_CASES)
    mode.add_argument("--on-demand-full", action="store_true")
    args = parser.parse_args()
    if args.on_demand_full:
        if os.environ.get("ON_DEMAND_TESTS") != "1":
            parser.error("the archived full policy catalog requires explicit ON_DEMAND_TESTS=1")
        check_python_policy()
        check_shell_policy()
        print("check-runtime-path-policy: full on-demand catalog PASS")
    elif args.case is None:
        os.execv(sys.executable, [sys.executable, "-P", str(source_path("ci/tools/run-active-tests.py")), "--group", "runtime-path-policy"])
    else:
        try:
            admit_selected_policy_case(args.case)
            selected_policy_case(args.case)
        except (OSError, ValueError) as error:
            fail(str(error))
        print(f"check-runtime-path-policy: {args.case} PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
