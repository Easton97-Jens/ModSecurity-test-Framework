#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
FRAMEWORK_ROOT="${FRAMEWORK_ROOT:-$(CDPATH= cd "$SCRIPT_DIR/.." && pwd)}"
CONNECTOR_ROOT="${CONNECTOR_ROOT:-$(pwd)}"
REPO_ROOT="$CONNECTOR_ROOT"
. "$SCRIPT_DIR/common.sh"

RESULTS_DIR="${RESULTS_DIR:-$BUILD_ROOT/results}"
APACHE_BUILD_ROOT="${APACHE_BUILD_ROOT:-$BUILD_ROOT/apache-build}"
HTTPD_PREFIX="${HTTPD_PREFIX:-$BUILD_ROOT/apache-runtime/httpd}"
APACHE_MODULE="${APACHE_MODULE:-$APACHE_BUILD_ROOT/output/apache/mod_security3.so}"
MODSECURITY_LIB_DIR="${MODSECURITY_LIB_DIR:-$APACHE_BUILD_ROOT/output/modsecurity/lib}"
DEFAULT_APACHE_SOURCE_DIR="$CONNECTOR_ROOT/connectors/apache"
MODSECURITY_APACHE_SOURCE_DIR="${MODSECURITY_APACHE_SOURCE_DIR:-$DEFAULT_APACHE_SOURCE_DIR}"
APACHE_ORIGIN_SOURCE="${APACHE_ORIGIN_SOURCE:-}"
APACHE_ORIGIN_SOURCE_REPO="${APACHE_ORIGIN_SOURCE_REPO:-}"
APACHE_ORIGIN_SOURCE_URL="${APACHE_ORIGIN_SOURCE_URL:-}"
APACHE_ORIGIN_SOURCE_COMMIT="${APACHE_ORIGIN_SOURCE_COMMIT:-}"
APACHE_ORIGIN_SOURCE_VERSION="${APACHE_ORIGIN_SOURCE_VERSION:-}"
APACHE_ORIGIN_LICENSE="${APACHE_ORIGIN_LICENSE:-}"
APACHE_ORIGIN_IMPORTED_PATH="${APACHE_ORIGIN_IMPORTED_PATH:-}"
REFRESH="${REFRESH:-0}"
SMOKE_CASES="${SMOKE_CASES:-}"
CASE_SCOPE="${CASE_SCOPE:-all}"
BUILD_HTTPD_FROM_SOURCE="${BUILD_HTTPD_FROM_SOURCE:-1}"
BUILD_PCRE2_FROM_SOURCE="${BUILD_PCRE2_FROM_SOURCE:-1}"
APACHE_BUILD_LOG_DIR="${APACHE_BUILD_LOG_DIR:-$BUILD_ROOT/logs/apache}"
APACHE_RUNTIME_LOG_DIR="${APACHE_RUNTIME_LOG_DIR:-$BUILD_ROOT/logs/apache-runtime}"
PYTHON_BIN="${PYTHON_BIN:-$(ci_python)}"
MODSECURITY_V3_SOURCE_DIR="${MODSECURITY_V3_SOURCE_DIR:-}"
SMOKE_PREPARE_TIMEOUT_SECONDS="${SMOKE_PREPARE_TIMEOUT_SECONDS:-3600}"
AUTO_REFRESH_STALE_BUILD="${AUTO_REFRESH_STALE_BUILD:-1}"
SMOKE_LOCK_TIMEOUT_SECONDS="${SMOKE_LOCK_TIMEOUT_SECONDS:-900}"
SMOKE_DISABLE_LOCK="${SMOKE_DISABLE_LOCK:-0}"
SMOKE_LOCK_MODE="${SMOKE_LOCK_MODE:-wait}"

prepare_crs_variant() {
    if [ "$MODSECURITY_TEST_VARIANT" != "with-crs" ]; then
        MODSECURITY_RULE_PREAMBLE_FILE=""
        export MODSECURITY_RULE_PREAMBLE_FILE
        return 0
    fi
    if [ -z "$MODSECURITY_RULE_PREAMBLE_FILE" ]; then
        sh "$FRAMEWORK_ROOT/ci/prepare-crs.sh"
        MODSECURITY_RULE_PREAMBLE_FILE="$CRS_RUNTIME_DIR/modsecurity-crs-preamble.conf"
    fi
    export MODSECURITY_RULE_PREAMBLE_FILE
}

load_apache_adapter_metadata() {
    eval "$(CONNECTOR_ROOT="$CONNECTOR_ROOT" "$PYTHON_BIN" "$FRAMEWORK_ROOT/ci/adapter_metadata.py" shell apache --prefix APACHE_ADAPTER)"
}

configure_apache_origin() {
    load_apache_adapter_metadata
    if [ "$MODSECURITY_APACHE_SOURCE_DIR" = "$DEFAULT_APACHE_SOURCE_DIR" ]; then
        APACHE_ORIGIN_SOURCE="${APACHE_ORIGIN_SOURCE:-$APACHE_ADAPTER_SOURCE}"
        APACHE_ORIGIN_SOURCE_REPO="${APACHE_ORIGIN_SOURCE_REPO:-$APACHE_ADAPTER_SOURCE_REPO}"
        APACHE_ORIGIN_SOURCE_URL="${APACHE_ORIGIN_SOURCE_URL:-$APACHE_ADAPTER_SOURCE_URL}"
        APACHE_ORIGIN_SOURCE_COMMIT="${APACHE_ORIGIN_SOURCE_COMMIT:-$APACHE_ADAPTER_SOURCE_COMMIT}"
        APACHE_ORIGIN_SOURCE_VERSION="${APACHE_ORIGIN_SOURCE_VERSION:-$APACHE_ADAPTER_SOURCE_VERSION}"
        APACHE_ORIGIN_LICENSE="${APACHE_ORIGIN_LICENSE:-$APACHE_ADAPTER_LICENSE}"
        APACHE_ORIGIN_IMPORTED_PATH="${APACHE_ORIGIN_IMPORTED_PATH:-$APACHE_ADAPTER_IMPORTED_PATH}"
        return
    fi
    APACHE_ORIGIN_SOURCE="${APACHE_ORIGIN_SOURCE:-external}"
    APACHE_ORIGIN_SOURCE_REPO="${APACHE_ORIGIN_SOURCE_REPO:-$APACHE_ADAPTER_SOURCE_REPO}"
    APACHE_ORIGIN_SOURCE_URL="${APACHE_ORIGIN_SOURCE_URL:-$APACHE_ADAPTER_SOURCE_URL}"
    APACHE_ORIGIN_SOURCE_COMMIT="${APACHE_ORIGIN_SOURCE_COMMIT:-$(ci_git_value "$MODSECURITY_APACHE_SOURCE_DIR" rev-parse HEAD)}"
    APACHE_ORIGIN_SOURCE_VERSION="${APACHE_ORIGIN_SOURCE_VERSION:-$(ci_git_value "$MODSECURITY_APACHE_SOURCE_DIR" describe --tags --always --dirty)}"
    APACHE_ORIGIN_LICENSE="${APACHE_ORIGIN_LICENSE:-$APACHE_ADAPTER_LICENSE}"
    APACHE_ORIGIN_IMPORTED_PATH="${APACHE_ORIGIN_IMPORTED_PATH:-$MODSECURITY_APACHE_SOURCE_DIR}"
}

write_connector_result() {
    status=$1
    message=$2
    mkdir -p "$RESULTS_DIR"
    "$PYTHON_BIN" "$FRAMEWORK_ROOT/tests/runners/case_cli.py" summarize-empty \
        --connector apache \
        --status "$status" \
        --message "$message" \
        --summary-json "$RESULTS_DIR/apache-summary.json" \
        --summary-text "$RESULTS_DIR/apache-summary.txt" \
        --connector-path real-world \
        --validation-mode real-world-connector-path \
        --server apache \
        --server-binary "$HTTPD_PREFIX/bin/httpd" \
        --module "$APACHE_MODULE" \
        --libmodsecurity "$MODSECURITY_LIB_DIR/libmodsecurity.so" \
        --origin-source "$APACHE_ORIGIN_SOURCE" \
        --origin-source-repo "$APACHE_ORIGIN_SOURCE_REPO" \
        --origin-source-url "$APACHE_ORIGIN_SOURCE_URL" \
        --origin-source-commit "$APACHE_ORIGIN_SOURCE_COMMIT" \
        --origin-source-version "$APACHE_ORIGIN_SOURCE_VERSION" \
        --origin-license "$APACHE_ORIGIN_LICENSE" \
        --origin-imported-path "$APACHE_ORIGIN_IMPORTED_PATH"
    cp "$RESULTS_DIR/apache-summary.txt" "$RESULTS_DIR/connector-summary.txt"
}

acquire_build_root_lock() {
    if [ "$SMOKE_DISABLE_LOCK" = "1" ]; then
        echo "run_apache_smoke: lock disabled (SMOKE_DISABLE_LOCK=1)"
        return 0
    fi
    lock_dir="$BUILD_ROOT/.smoke.lock"
    echo "run_apache_smoke: lock-acquire begin path=$lock_dir mode=$SMOKE_LOCK_MODE timeout=${SMOKE_LOCK_TIMEOUT_SECONDS}s"
    if command -v flock >/dev/null 2>&1; then
        mkdir -p "$BUILD_ROOT"
        lock_file="$lock_dir.file"
        : > "$lock_file"
        exec 9>"$lock_file"
        if [ "$SMOKE_LOCK_MODE" = "fail" ]; then
            flock -n 9 || { echo "run_apache_smoke: lock-busy path=$lock_file"; return 73; }
        else
            flock -w "$SMOKE_LOCK_TIMEOUT_SECONDS" 9 || { echo "run_apache_smoke: lock-timeout path=$lock_file"; return 73; }
        fi
        echo "run_apache_smoke: lock-acquire success path=$lock_file method=flock"
        return 0
    fi
    start=$(date +%s)
    while :; do
        if mkdir "$lock_dir" 2>/dev/null; then
            echo "$$" > "$lock_dir/pid"
            echo "run_apache_smoke: lock-acquire success path=$lock_dir method=mkdir"
            return 0
        fi
        [ "$SMOKE_LOCK_MODE" = "fail" ] && { echo "run_apache_smoke: lock-busy path=$lock_dir"; return 73; }
        now=$(date +%s); elapsed=$((now - start))
        [ "$elapsed" -ge "$SMOKE_LOCK_TIMEOUT_SECONDS" ] && { echo "run_apache_smoke: lock-timeout path=$lock_dir"; return 73; }
        echo "run_apache_smoke: lock-wait path=$lock_dir elapsed=${elapsed}s"
        sleep 2
    done
}

release_build_root_lock() {
    [ "$SMOKE_DISABLE_LOCK" = "1" ] && return 0
    lock_dir="$BUILD_ROOT/.smoke.lock"
    if command -v flock >/dev/null 2>&1; then
        if [ -n "${lock_file:-}" ]; then
            echo "run_apache_smoke: lock-release path=$lock_file method=flock"
            flock -u 9 || true
            exec 9>&-
        fi
        return 0
    fi
    if [ -d "$lock_dir" ]; then
        rm -rf "$lock_dir"
        echo "run_apache_smoke: lock-release path=$lock_dir method=mkdir"
    fi
}

prepare_crs_variant
echo "run_apache_smoke: MODSECURITY_TEST_VARIANT=$MODSECURITY_TEST_VARIANT"
if [ -n "$MODSECURITY_RULE_PREAMBLE_FILE" ]; then
    echo "run_apache_smoke: MODSECURITY_RULE_PREAMBLE_FILE=$MODSECURITY_RULE_PREAMBLE_FILE"
fi

configure_apache_origin
if ! acquire_build_root_lock; then
    write_connector_result blocked "build root lock unavailable: $BUILD_ROOT"
    exit 73
fi
trap 'release_build_root_lock' EXIT INT TERM

print_blocked_prereq() {
    missing_path=$1
    env_name=$2
    echo "blocked: missing runtime prerequisite for ${env_name}: ${missing_path}"
    echo "blocked: set MODSECURITY_SOURCE_DIR or MODSECURITY_V3_SOURCE_DIR to a valid ModSecurity v3 source tree"
    echo "blocked: or run make fetch-deps with the intended BUILD_ROOT/SOURCE_ROOT"
    echo "blocked: smoke result is BLOCKED, not FAIL"
}

resolve_modsecurity_v3_source_dir() {
    if [ -n "$MODSECURITY_V3_SOURCE_DIR" ] && [ -d "$MODSECURITY_V3_SOURCE_DIR" ]; then
        return
    fi
    if detected=$(FRAMEWORK_ROOT="$FRAMEWORK_ROOT" CONNECTOR_ROOT="$CONNECTOR_ROOT" sh "$FRAMEWORK_ROOT/ci/find-modsecurity-v3.sh"); then
        MODSECURITY_V3_SOURCE_DIR="$detected"
        echo "info: auto-detected MODSECURITY_V3_SOURCE_DIR=$MODSECURITY_V3_SOURCE_DIR"
        return
    fi
}

preflight_runtime_prereqs() {
    resolve_modsecurity_v3_source_dir
    if [ ! -d "$MODSECURITY_V3_SOURCE_DIR" ]; then
    print_blocked_prereq "${MODSECURITY_V3_SOURCE_DIR:-<unset>}" MODSECURITY_V3_SOURCE_DIR
        write_connector_result blocked "missing MODSECURITY_V3_SOURCE_DIR: $MODSECURITY_V3_SOURCE_DIR (set env var and retry)"
        exit 77
    fi
}

preflight_runtime_prereqs

apache_adapter_build_current() {
    manifest="$APACHE_BUILD_ROOT/connector-src/materialized-source.json"
    [ -f "$manifest" ] || return 1
    "$PYTHON_BIN" - "$manifest" <<'PY'
import json
import sys

required_adapter_owned = {
    "autogen.sh",
    "configure.ac",
    "Makefile.am",
    "build/apxs-wrapper.in",
    "build/ax_prog_apache.m4",
    "build/find_apxs.m4",
    "build/find_libmodsec.m4",
    "src/mod_security3.c",
    "src/mod_security3.h",
    "src/msc_config.c",
    "src/msc_config.h",
    "src/msc_filters.c",
    "src/msc_filters.h",
    "src/msc_utils.c",
    "src/msc_utils.h",
}
required_framework_reference = {
    "t/conf/extra.conf.in",
    "tests/run-regression-tests.pl.in",
    "tests/regression/server_root/conf/httpd.conf.in",
    "tests/regression/misc/40-secRemoteRules.t.in",
    "tests/regression/misc/50-ipmatchfromfile-external.t.in",
    "tests/regression/misc/60-pmfromfile-external.t.in",
}
removed_from_source_tree = {
    "AUTHORS",
    "CHANGES",
    "LICENSE",
    "README.md",
    "SOURCE_MAP.json",
    "metadata.c",
    "metadata.h",
    "src/SOURCE_MAP.json",
    "src/metadata.c",
    "src/metadata.h",
}

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    manifest = json.load(handle)

entries = manifest.get("entries")
if not isinstance(entries, list):
    raise SystemExit(1)

sources_by_path = {
    entry.get("path"): entry.get("source")
    for entry in entries
    if isinstance(entry, dict)
}
if any(source == "upstream-derived" for source in sources_by_path.values()):
    raise SystemExit(1)
if any(path in sources_by_path for path in removed_from_source_tree):
    raise SystemExit(1)
for path in required_adapter_owned:
    if sources_by_path.get(path) != "adapter-owned":
        raise SystemExit(1)
for path in required_framework_reference:
    if sources_by_path.get(path) != "framework-upstream-reference":
        raise SystemExit(1)
PY
}

needs_build=0
prepare_refresh="$REFRESH"
if [ "$REFRESH" = "1" ]; then
    needs_build=1
elif [ ! -x "$HTTPD_PREFIX/bin/httpd" ] || [ ! -x "$HTTPD_PREFIX/bin/apxs" ]; then
    needs_build=1
elif [ ! -f "$APACHE_MODULE" ] || [ ! -f "$MODSECURITY_LIB_DIR/libmodsecurity.so" ]; then
    needs_build=1
elif [ "$MODSECURITY_APACHE_SOURCE_DIR" = "$DEFAULT_APACHE_SOURCE_DIR" ] && ! apache_adapter_build_current; then
    echo "run_apache_smoke: existing Apache build predates adapter-owned materialized source; refreshing build artifacts"
    needs_build=1
    prepare_refresh=1
fi

if [ "$needs_build" -eq 1 ]; then
    if [ "$prepare_refresh" != "1" ] && [ "$AUTO_REFRESH_STALE_BUILD" = "1" ] && [ -e "$APACHE_BUILD_ROOT" ]; then
        echo "run_apache_smoke: stale/incomplete build tree detected, forcing REFRESH=1 for prepare"
        prepare_refresh=1
    fi
    echo "run_apache_smoke: phase-begin prepare"
    started=$(date +%s)
    echo "run_apache_smoke: preparing Apache PoC build"
    set +e
    if command -v timeout >/dev/null 2>&1; then
        timeout "$SMOKE_PREPARE_TIMEOUT_SECONDS" env REFRESH="$prepare_refresh" \
        MODSECURITY_APACHE_SOURCE_DIR="$MODSECURITY_APACHE_SOURCE_DIR" \
        LOG_DIR="$APACHE_BUILD_LOG_DIR" \
        BUILD_HTTPD_FROM_SOURCE="$BUILD_HTTPD_FROM_SOURCE" \
        BUILD_PCRE2_FROM_SOURCE="$BUILD_PCRE2_FROM_SOURCE" \
        FRAMEWORK_ROOT="$FRAMEWORK_ROOT" CONNECTOR_ROOT="$CONNECTOR_ROOT" sh "$FRAMEWORK_ROOT/ci/prepare-apache-build.sh"
    else
        REFRESH="$prepare_refresh" \
            MODSECURITY_APACHE_SOURCE_DIR="$MODSECURITY_APACHE_SOURCE_DIR" \
            LOG_DIR="$APACHE_BUILD_LOG_DIR" \
            BUILD_HTTPD_FROM_SOURCE="$BUILD_HTTPD_FROM_SOURCE" \
            BUILD_PCRE2_FROM_SOURCE="$BUILD_PCRE2_FROM_SOURCE" \
            FRAMEWORK_ROOT="$FRAMEWORK_ROOT" CONNECTOR_ROOT="$CONNECTOR_ROOT" sh "$FRAMEWORK_ROOT/ci/prepare-apache-build.sh"
    fi
    rc=$?
    set -e
    ended=$(date +%s)
    elapsed=$((ended - started))
    echo "run_apache_smoke: phase-end prepare duration=${elapsed}s rc=$rc"
    if [ "$rc" -eq 77 ]; then
        write_connector_result blocked "prepare-apache-build blocked; see $APACHE_BUILD_LOG_DIR"
        exit 77
    fi
    if [ "$rc" -ne 0 ]; then
        write_connector_result fail "prepare-apache-build failed; see $APACHE_BUILD_LOG_DIR"
        exit "$rc"
    fi
fi

LOG_DIR="$APACHE_RUNTIME_LOG_DIR" \
    RESULTS_DIR="$RESULTS_DIR" \
    BUILD_ROOT="$BUILD_ROOT" \
    APACHE_BUILD_ROOT="$APACHE_BUILD_ROOT" \
    HTTPD_PREFIX="$HTTPD_PREFIX" \
    APACHE_MODULE="$APACHE_MODULE" \
    MODSECURITY_LIB_DIR="$MODSECURITY_LIB_DIR" \
    CONNECTOR_ORIGIN_SOURCE="$APACHE_ORIGIN_SOURCE" \
    CONNECTOR_ORIGIN_SOURCE_REPO="$APACHE_ORIGIN_SOURCE_REPO" \
    CONNECTOR_ORIGIN_SOURCE_URL="$APACHE_ORIGIN_SOURCE_URL" \
    CONNECTOR_ORIGIN_SOURCE_COMMIT="$APACHE_ORIGIN_SOURCE_COMMIT" \
    CONNECTOR_ORIGIN_SOURCE_VERSION="$APACHE_ORIGIN_SOURCE_VERSION" \
    CONNECTOR_ORIGIN_LICENSE="$APACHE_ORIGIN_LICENSE" \
    CONNECTOR_ORIGIN_IMPORTED_PATH="$APACHE_ORIGIN_IMPORTED_PATH" \
    MODSECURITY_TEST_VARIANT="$MODSECURITY_TEST_VARIANT" \
    MODSECURITY_RULE_PREAMBLE_FILE="$MODSECURITY_RULE_PREAMBLE_FILE" \
    SMOKE_CASES="$SMOKE_CASES" \
    CASE_SCOPE="$CASE_SCOPE" \
    FRAMEWORK_ROOT="$FRAMEWORK_ROOT" CONNECTOR_ROOT="$CONNECTOR_ROOT" sh "$CONNECTOR_ROOT/connectors/apache/harness/run_apache_smoke.sh"
