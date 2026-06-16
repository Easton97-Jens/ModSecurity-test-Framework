#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
FRAMEWORK_ROOT="${FRAMEWORK_ROOT:-$(CDPATH= cd "$SCRIPT_DIR/.." && pwd)}"
CONNECTOR_ROOT="${CONNECTOR_ROOT:-$(pwd)}"
REPO_ROOT="$CONNECTOR_ROOT"
. "$SCRIPT_DIR/common.sh"
. "$SCRIPT_DIR/mrts-common.sh"

RESULTS_DIR="${RESULTS_DIR:-$BUILD_ROOT/results}"
NGINX_BUILD_DIR="${NGINX_BUILD_DIR:-$BUILD_ROOT/nginx-build}"
NGINX_PREFIX="${NGINX_PREFIX:-$BUILD_ROOT/nginx-runtime/nginx}"
NGINX_BINARY="${NGINX_BINARY:-$NGINX_PREFIX/sbin/nginx}"
NGINX_MODULE="${NGINX_MODULE:-$NGINX_PREFIX/modules/ngx_http_modsecurity_module.so}"
MODSECURITY_LIB_DIR="${MODSECURITY_LIB_DIR:-$NGINX_BUILD_DIR/output/modsecurity/lib}"
DEFAULT_NGINX_SOURCE_DIR="$CONNECTOR_ROOT/connectors/nginx"
MODSECURITY_NGINX_SOURCE_DIR="${MODSECURITY_NGINX_SOURCE_DIR:-$DEFAULT_NGINX_SOURCE_DIR}"
NGINX_ORIGIN_SOURCE="${NGINX_ORIGIN_SOURCE:-}"
NGINX_ORIGIN_SOURCE_REPO="${NGINX_ORIGIN_SOURCE_REPO:-}"
NGINX_ORIGIN_SOURCE_URL="${NGINX_ORIGIN_SOURCE_URL:-}"
NGINX_ORIGIN_SOURCE_COMMIT="${NGINX_ORIGIN_SOURCE_COMMIT:-}"
NGINX_ORIGIN_SOURCE_VERSION="${NGINX_ORIGIN_SOURCE_VERSION:-}"
NGINX_ORIGIN_LICENSE="${NGINX_ORIGIN_LICENSE:-}"
NGINX_ORIGIN_IMPORTED_PATH="${NGINX_ORIGIN_IMPORTED_PATH:-}"
REFRESH="${REFRESH:-0}"
SMOKE_CASES="${SMOKE_CASES:-}"
CASE_SCOPE="${CASE_SCOPE:-all}"
BUILD_NGINX_FROM_SOURCE="${BUILD_NGINX_FROM_SOURCE:-1}"
NGINX_BUILD_LOG_DIR="${NGINX_BUILD_LOG_DIR:-$BUILD_ROOT/logs/nginx}"
PYTHON_BIN="${PYTHON_BIN:-$(ci_python)}"
MODSECURITY_V3_SOURCE_DIR="${MODSECURITY_V3_SOURCE_DIR:-}"
SMOKE_PREPARE_TIMEOUT_SECONDS="${SMOKE_PREPARE_TIMEOUT_SECONDS:-3600}"
AUTO_REFRESH_STALE_BUILD="${AUTO_REFRESH_STALE_BUILD:-1}"
SMOKE_LOCK_TIMEOUT_SECONDS="${SMOKE_LOCK_TIMEOUT_SECONDS:-900}"
SMOKE_DISABLE_LOCK="${SMOKE_DISABLE_LOCK:-0}"
SMOKE_LOCK_MODE="${SMOKE_LOCK_MODE:-wait}"
CURRENT_UID=$(id -u 2>/dev/null || printf 'unknown')
if [ -z "${NGINX_HARNESS_WORK_ROOT:-}" ]; then
    NGINX_HARNESS_PARENT="${NGINX_HARNESS_PARENT:-$VERIFIED_RUN_ROOT/nginx-harness}"
    NGINX_HARNESS_WORK_ROOT="$NGINX_HARNESS_PARENT/ModSecurity-conector-nginx-runtime-$CURRENT_UID"
fi
NGINX_RUNTIME_BASE="${NGINX_RUNTIME_BASE:-${RUNTIME_BASE:-$NGINX_HARNESS_WORK_ROOT/runtime}}"
NGINX_RUNTIME_LOG_DIR="${NGINX_RUNTIME_LOG_DIR:-$NGINX_HARNESS_WORK_ROOT/logs}"

validate_runtime_paths() {
    assert_safe_runtime_path "$BUILD_ROOT" BUILD_ROOT || exit 77
    assert_safe_runtime_path "$RESULTS_DIR" RESULTS_DIR || exit 77
    assert_safe_runtime_path "$NGINX_BUILD_DIR" NGINX_BUILD_DIR || exit 77
    assert_safe_runtime_path "$NGINX_PREFIX" NGINX_PREFIX || exit 77
    assert_safe_runtime_path "$NGINX_HARNESS_PARENT" NGINX_HARNESS_PARENT || exit 77
    assert_safe_runtime_path "$NGINX_HARNESS_WORK_ROOT" NGINX_HARNESS_WORK_ROOT || exit 77
    assert_safe_runtime_path "$NGINX_RUNTIME_BASE" NGINX_RUNTIME_BASE || exit 77
    assert_safe_runtime_path "$NGINX_RUNTIME_LOG_DIR" NGINX_RUNTIME_LOG_DIR || exit 77
    assert_safe_runtime_path "$NGINX_BUILD_LOG_DIR" NGINX_BUILD_LOG_DIR || exit 77
    assert_safe_runtime_path "$CRS_RUNTIME_DIR" CRS_RUNTIME_DIR || exit 77
    assert_safe_runtime_path "${MRTS_BUILD_ROOT:-$BUILD_ROOT/mrts}" MRTS_BUILD_ROOT || exit 77
}

prepare_crs_variant() {
    existing_preamble="${MODSECURITY_RULE_PREAMBLE_FILE:-}"
    if [ "$MODSECURITY_TEST_VARIANT" != "with-crs" ]; then
        MODSECURITY_RULE_PREAMBLE_FILE="$existing_preamble"
        export MODSECURITY_RULE_PREAMBLE_FILE
        return 0
    fi
    sh "$FRAMEWORK_ROOT/ci/prepare-crs.sh"
    crs_preamble="$CRS_RUNTIME_DIR/modsecurity-crs-preamble.conf"
    MODSECURITY_RULE_PREAMBLE_FILE=$(combine_rule_preambles "$crs_preamble" "$existing_preamble" "nginx-with-crs-${MODSECURITY_MRTS_VARIANT:-no-mrts}")
    export MODSECURITY_RULE_PREAMBLE_FILE
}

load_nginx_adapter_metadata() {
    eval "$(CONNECTOR_ROOT="$CONNECTOR_ROOT" "$PYTHON_BIN" "$FRAMEWORK_ROOT/ci/adapter_metadata.py" shell nginx --prefix NGINX_ADAPTER)"
}

configure_nginx_origin() {
    load_nginx_adapter_metadata
    if [ "$MODSECURITY_NGINX_SOURCE_DIR" = "$DEFAULT_NGINX_SOURCE_DIR" ]; then
        NGINX_ORIGIN_SOURCE="${NGINX_ORIGIN_SOURCE:-$NGINX_ADAPTER_SOURCE}"
        NGINX_ORIGIN_SOURCE_REPO="${NGINX_ORIGIN_SOURCE_REPO:-$NGINX_ADAPTER_SOURCE_REPO}"
        NGINX_ORIGIN_SOURCE_URL="${NGINX_ORIGIN_SOURCE_URL:-$NGINX_ADAPTER_SOURCE_URL}"
        NGINX_ORIGIN_SOURCE_COMMIT="${NGINX_ORIGIN_SOURCE_COMMIT:-$NGINX_ADAPTER_SOURCE_COMMIT}"
        NGINX_ORIGIN_SOURCE_VERSION="${NGINX_ORIGIN_SOURCE_VERSION:-$NGINX_ADAPTER_SOURCE_VERSION}"
        NGINX_ORIGIN_LICENSE="${NGINX_ORIGIN_LICENSE:-$NGINX_ADAPTER_LICENSE}"
        NGINX_ORIGIN_IMPORTED_PATH="${NGINX_ORIGIN_IMPORTED_PATH:-$NGINX_ADAPTER_IMPORTED_PATH}"
        return
    fi
    NGINX_ORIGIN_SOURCE="${NGINX_ORIGIN_SOURCE:-external}"
    NGINX_ORIGIN_SOURCE_REPO="${NGINX_ORIGIN_SOURCE_REPO:-$NGINX_ADAPTER_SOURCE_REPO}"
    NGINX_ORIGIN_SOURCE_URL="${NGINX_ORIGIN_SOURCE_URL:-$NGINX_ADAPTER_SOURCE_URL}"
    NGINX_ORIGIN_SOURCE_COMMIT="${NGINX_ORIGIN_SOURCE_COMMIT:-$(ci_git_value "$MODSECURITY_NGINX_SOURCE_DIR" rev-parse HEAD)}"
    NGINX_ORIGIN_SOURCE_VERSION="${NGINX_ORIGIN_SOURCE_VERSION:-$(ci_git_value "$MODSECURITY_NGINX_SOURCE_DIR" describe --tags --always --dirty)}"
    NGINX_ORIGIN_LICENSE="${NGINX_ORIGIN_LICENSE:-$NGINX_ADAPTER_LICENSE}"
    NGINX_ORIGIN_IMPORTED_PATH="${NGINX_ORIGIN_IMPORTED_PATH:-$MODSECURITY_NGINX_SOURCE_DIR}"
}

write_connector_result() {
    status=$1
    message=$2
    assert_safe_runtime_path "$RESULTS_DIR" RESULTS_DIR || exit 77
    mkdir -p "$RESULTS_DIR"
    "$PYTHON_BIN" "$FRAMEWORK_ROOT/tests/runners/case_cli.py" summarize-empty \
        --connector nginx \
        --status "$status" \
        --message "$message" \
        --summary-json "$RESULTS_DIR/nginx-summary.json" \
        --summary-text "$RESULTS_DIR/nginx-summary.txt" \
        --connector-path real-world \
        --validation-mode real-world-connector-path \
        --server nginx \
        --server-binary "$NGINX_BINARY" \
        --module "$NGINX_MODULE" \
        --libmodsecurity "$MODSECURITY_LIB_DIR/libmodsecurity.so" \
        --origin-source "$NGINX_ORIGIN_SOURCE" \
        --origin-source-repo "$NGINX_ORIGIN_SOURCE_REPO" \
        --origin-source-url "$NGINX_ORIGIN_SOURCE_URL" \
        --origin-source-commit "$NGINX_ORIGIN_SOURCE_COMMIT" \
        --origin-source-version "$NGINX_ORIGIN_SOURCE_VERSION" \
        --origin-license "$NGINX_ORIGIN_LICENSE" \
        --origin-imported-path "$NGINX_ORIGIN_IMPORTED_PATH"
    cp "$RESULTS_DIR/nginx-summary.txt" "$RESULTS_DIR/connector-summary.txt"
}

acquire_build_root_lock() {
    if [ "$SMOKE_DISABLE_LOCK" = "1" ]; then
        echo "run_nginx_smoke: lock disabled (SMOKE_DISABLE_LOCK=1)"
        return 0
    fi
    lock_dir="$BUILD_ROOT/.smoke.lock"
    echo "run_nginx_smoke: lock-acquire begin path=$lock_dir mode=$SMOKE_LOCK_MODE timeout=${SMOKE_LOCK_TIMEOUT_SECONDS}s"
    if command -v flock >/dev/null 2>&1; then
        assert_safe_runtime_path "$BUILD_ROOT" BUILD_ROOT || return 77
        assert_not_system_path_for_write "$lock_dir.file" "smoke lock file" || return 77
        mkdir -p "$BUILD_ROOT"
        lock_file="$lock_dir.file"
        : > "$lock_file"
        exec 9>"$lock_file"
        if [ "$SMOKE_LOCK_MODE" = "fail" ]; then
            flock -n 9 || { echo "run_nginx_smoke: lock-busy path=$lock_file"; return 73; }
        else
            flock -w "$SMOKE_LOCK_TIMEOUT_SECONDS" 9 || { echo "run_nginx_smoke: lock-timeout path=$lock_file"; return 73; }
        fi
        echo "run_nginx_smoke: lock-acquire success path=$lock_file method=flock"
        return 0
    fi
    start=$(date +%s)
    while :; do
        if mkdir "$lock_dir" 2>/dev/null; then
            echo "$$" > "$lock_dir/pid"
            echo "run_nginx_smoke: lock-acquire success path=$lock_dir method=mkdir"
            return 0
        fi
        [ "$SMOKE_LOCK_MODE" = "fail" ] && { echo "run_nginx_smoke: lock-busy path=$lock_dir"; return 73; }
        now=$(date +%s); elapsed=$((now - start))
        [ "$elapsed" -ge "$SMOKE_LOCK_TIMEOUT_SECONDS" ] && { echo "run_nginx_smoke: lock-timeout path=$lock_dir"; return 73; }
        echo "run_nginx_smoke: lock-wait path=$lock_dir elapsed=${elapsed}s"
        sleep 2
    done
}

release_build_root_lock() {
    [ "$SMOKE_DISABLE_LOCK" = "1" ] && return 0
    lock_dir="$BUILD_ROOT/.smoke.lock"
    if command -v flock >/dev/null 2>&1; then
        if [ -n "${lock_file:-}" ]; then
            echo "run_nginx_smoke: lock-release path=$lock_file method=flock"
            flock -u 9 || true
            exec 9>&-
        fi
        return 0
    fi
    if [ -d "$lock_dir" ]; then
        safe_remove_runtime_path "$lock_dir" "$BUILD_ROOT" "NGINX smoke lock directory" || return 77
        echo "run_nginx_smoke: lock-release path=$lock_dir method=mkdir"
    fi
}

validate_runtime_paths
prepare_mrts_runtime_variant
prepare_crs_variant
echo "run_nginx_smoke: MODSECURITY_TEST_VARIANT=$MODSECURITY_TEST_VARIANT"
echo "run_nginx_smoke: MODSECURITY_MRTS_VARIANT=$MODSECURITY_MRTS_VARIANT"
if [ -n "$MODSECURITY_RULE_PREAMBLE_FILE" ]; then
    echo "run_nginx_smoke: MODSECURITY_RULE_PREAMBLE_FILE=$MODSECURITY_RULE_PREAMBLE_FILE"
fi

configure_nginx_origin
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

nginx_adapter_build_current() {
    manifest="$NGINX_BUILD_DIR/connector-src/materialized-source.json"
    [ -f "$manifest" ] || return 1
    "$PYTHON_BIN" - "$manifest" <<'PY'
import json
import sys

required_adapter_owned = {
    "config",
    "src/ddebug.h",
    "src/ngx_http_modsecurity_access.c",
    "src/ngx_http_modsecurity_body_filter.c",
    "src/ngx_http_modsecurity_common.h",
    "src/ngx_http_modsecurity_header_filter.c",
    "src/ngx_http_modsecurity_log.c",
    "src/ngx_http_modsecurity_module.c",
}
removed_from_build_source = {
    "SOURCE_MAP.json",
    "metadata.c",
    "metadata.h",
    "README.md",
    "src/config",
    "src/SOURCE_MAP.json",
    "src/metadata.c",
    "src/metadata.h",
    "src/README.md",
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
if any(path in sources_by_path for path in removed_from_build_source):
    raise SystemExit(1)
for path in required_adapter_owned:
    if sources_by_path.get(path) != "adapter-owned":
        raise SystemExit(1)
PY
}

needs_build=0
prepare_refresh="$REFRESH"
if [ "$REFRESH" = "1" ]; then
    needs_build=1
elif [ ! -x "$NGINX_BINARY" ] || [ ! -f "$NGINX_MODULE" ]; then
    needs_build=1
elif [ ! -f "$MODSECURITY_LIB_DIR/libmodsecurity.so" ]; then
    needs_build=1
elif [ "$MODSECURITY_NGINX_SOURCE_DIR" = "$DEFAULT_NGINX_SOURCE_DIR" ] && ! nginx_adapter_build_current; then
    echo "run_nginx_smoke: existing NGINX build predates adapter-owned materialized source; refreshing build artifacts"
    needs_build=1
    prepare_refresh=1
fi

if [ "$needs_build" -eq 1 ]; then
    if [ "$prepare_refresh" != "1" ] && [ "$AUTO_REFRESH_STALE_BUILD" = "1" ] && [ -e "$NGINX_BUILD_DIR" ]; then
        echo "run_nginx_smoke: stale/incomplete build tree detected, forcing REFRESH=1 for prepare"
        prepare_refresh=1
    fi
    echo "run_nginx_smoke: phase-begin prepare"
    started=$(date +%s)
    echo "run_nginx_smoke: preparing NGINX PoC build"
    set +e
    if command -v timeout >/dev/null 2>&1; then
        timeout "$SMOKE_PREPARE_TIMEOUT_SECONDS" env REFRESH="$prepare_refresh" \
        MODSECURITY_NGINX_SOURCE_DIR="$MODSECURITY_NGINX_SOURCE_DIR" \
        LOG_DIR="$NGINX_BUILD_LOG_DIR" \
        BUILD_NGINX_FROM_SOURCE="$BUILD_NGINX_FROM_SOURCE" \
        FRAMEWORK_ROOT="$FRAMEWORK_ROOT" CONNECTOR_ROOT="$CONNECTOR_ROOT" sh "$FRAMEWORK_ROOT/ci/prepare-nginx-build.sh"
    else
        REFRESH="$prepare_refresh" \
            MODSECURITY_NGINX_SOURCE_DIR="$MODSECURITY_NGINX_SOURCE_DIR" \
            LOG_DIR="$NGINX_BUILD_LOG_DIR" \
            BUILD_NGINX_FROM_SOURCE="$BUILD_NGINX_FROM_SOURCE" \
            FRAMEWORK_ROOT="$FRAMEWORK_ROOT" CONNECTOR_ROOT="$CONNECTOR_ROOT" sh "$FRAMEWORK_ROOT/ci/prepare-nginx-build.sh"
    fi
    rc=$?
    set -e
    ended=$(date +%s)
    elapsed=$((ended - started))
    echo "run_nginx_smoke: phase-end prepare duration=${elapsed}s rc=$rc"
    if [ "$rc" -eq 77 ]; then
        write_connector_result blocked "prepare-nginx-build blocked; see $NGINX_BUILD_LOG_DIR"
        exit 77
    fi
    if [ "$rc" -ne 0 ]; then
        write_connector_result fail "prepare-nginx-build failed; see $NGINX_BUILD_LOG_DIR"
        exit "$rc"
    fi
fi

LOG_DIR="$NGINX_RUNTIME_LOG_DIR" \
    RESULTS_DIR="$RESULTS_DIR" \
    BUILD_ROOT="$BUILD_ROOT" \
    NGINX_BUILD_DIR="$NGINX_BUILD_DIR" \
    NGINX_PREFIX="$NGINX_PREFIX" \
    NGINX_BINARY="$NGINX_BINARY" \
    NGINX_MODULE="$NGINX_MODULE" \
    MODSECURITY_LIB_DIR="$MODSECURITY_LIB_DIR" \
    NGINX_HARNESS_PARENT="$NGINX_HARNESS_PARENT" \
    NGINX_HARNESS_WORK_ROOT="$NGINX_HARNESS_WORK_ROOT" \
    RUNTIME_BASE="$NGINX_RUNTIME_BASE" \
    CONNECTOR_ORIGIN_SOURCE="$NGINX_ORIGIN_SOURCE" \
    CONNECTOR_ORIGIN_SOURCE_REPO="$NGINX_ORIGIN_SOURCE_REPO" \
    CONNECTOR_ORIGIN_SOURCE_URL="$NGINX_ORIGIN_SOURCE_URL" \
    CONNECTOR_ORIGIN_SOURCE_COMMIT="$NGINX_ORIGIN_SOURCE_COMMIT" \
    CONNECTOR_ORIGIN_SOURCE_VERSION="$NGINX_ORIGIN_SOURCE_VERSION" \
    CONNECTOR_ORIGIN_LICENSE="$NGINX_ORIGIN_LICENSE" \
    CONNECTOR_ORIGIN_IMPORTED_PATH="$NGINX_ORIGIN_IMPORTED_PATH" \
    MODSECURITY_TEST_VARIANT="$MODSECURITY_TEST_VARIANT" \
    MODSECURITY_RULE_PREAMBLE_FILE="$MODSECURITY_RULE_PREAMBLE_FILE" \
    SMOKE_CASES="$SMOKE_CASES" \
    CASE_SCOPE="$CASE_SCOPE" \
    FRAMEWORK_ROOT="$FRAMEWORK_ROOT" CONNECTOR_ROOT="$CONNECTOR_ROOT" sh "$CONNECTOR_ROOT/connectors/nginx/harness/run_nginx_smoke.sh"
