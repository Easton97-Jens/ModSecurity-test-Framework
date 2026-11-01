#!/bin/sh
: "${TEST_ROOT:?TEST_ROOT is required explicitly}"
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
REPO_ROOT=${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}
FRAMEWORK_ROOT=${TEST_ROOT:?TEST_ROOT is required explicitly}
PYTHONPATH="$TEST_ROOT:$TEST_ROOT/connector_suite"
PYTHONSAFEPATH=1
PYTHONNOUSERSITE=1
export PYTHONPATH PYTHONSAFEPATH PYTHONNOUSERSITE
[ -d "$FRAMEWORK_ROOT" ] || { echo "nginx_smoke: blocked FRAMEWORK_ROOT is missing; run git submodule update --init --recursive or set FRAMEWORK_ROOT=/path/to/ModSecurity-test-Framework"; exit 77; }
CONNECTOR_ROOT="${CONNECTOR_ROOT:-$REPO_ROOT}"
. "$FRAMEWORK_ROOT/ci/lib/common.sh"
VERIFIED_RUN_ROOT="${VERIFIED_RUN_ROOT:-${RUNNER_TEMP:-${TMPDIR:-/var/tmp}}/ModSecurity-conector-verified}"
VERIFIED_BUILD_ROOT="${VERIFIED_BUILD_ROOT:-$VERIFIED_RUN_ROOT/build}"
BUILD_ROOT="${BUILD_ROOT:-$VERIFIED_BUILD_ROOT}"
NGINX_HARNESS_PARENT="${NGINX_HARNESS_PARENT:-$BUILD_ROOT/nginx-harness}"
NGINX_DOCROOT_PROJECTION="${NGINX_DOCROOT_PROJECTION:-0}"
# The default direct harness keeps using its private materialized docroot.
# Canonical lifecycle callers opt in explicitly and must supply a trusted,
# pre-existing external parent and exact fresh child. Projection mode itself
# fails closed unless both are supplied, so it never creates a fallback
# location during a lifecycle run. The harness validates those structural
# constraints; it does not load or enforce a lifecycle manifest for them.
NGINX_DOCROOT_PROJECTION_PARENT="${NGINX_DOCROOT_PROJECTION_PARENT:-}"
NGINX_DOCROOT_PROJECTION_ROOT="${NGINX_DOCROOT_PROJECTION_ROOT:-}"
NGINX_DOCROOT_PROJECTION_HELPER="$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/common/prepare-nginx-docroot-projection.py"
NGINX_DOCROOT_PROJECTION_PATH=""
CURRENT_UID=$(id -u 2>/dev/null || printf 'unknown')
# Case materialization constrains all generated paths to BUILD_ROOT.  The
# authority validator must not silently reroute the default parent to a
# sibling temporary directory; it either proves the configured path safe or
# blocks before creating it.
NGINX_HARNESS_WORK_ROOT="${NGINX_HARNESS_WORK_ROOT:-}"
NGINX_PATHS_VALIDATED=0
# Preserve the direct H1 harness defaults while making non-H1 profile paths
# distinct for callers that invoke this script without the framework wrapper.
if [ -n "${NGINX_BUILD_DIR+x}" ]; then NGINX_BUILD_DIR_WAS_SET=1; else NGINX_BUILD_DIR_WAS_SET=0; fi
if [ -n "${NGINX_PREFIX+x}" ]; then NGINX_PREFIX_WAS_SET=1; else NGINX_PREFIX_WAS_SET=0; fi
case "$NGINX_PROTOCOL_PROFILE" in
    h1) NGINX_PROFILE_PATH_SUFFIX="" ;;
    h1-h2|h1-h2-h3-quic) NGINX_PROFILE_PATH_SUFFIX="-$NGINX_PROTOCOL_PROFILE" ;;
    *) NGINX_PROFILE_PATH_SUFFIX="-$NGINX_PROTOCOL_PROFILE" ;;
esac
if [ "$NGINX_BUILD_DIR_WAS_SET" = "1" ]; then
    NGINX_BUILD_DIR="$NGINX_BUILD_DIR"
else
    NGINX_BUILD_DIR="$BUILD_ROOT/nginx-build$NGINX_PROFILE_PATH_SUFFIX"
fi
if [ "$NGINX_PREFIX_WAS_SET" = "1" ]; then
    NGINX_PREFIX="$NGINX_PREFIX"
else
    NGINX_PREFIX="$BUILD_ROOT/nginx-runtime/nginx$NGINX_PROFILE_PATH_SUFFIX"
fi
NGINX_BINARY="${NGINX_BINARY:-$NGINX_PREFIX/sbin/nginx}"
NGINX_MODULE="${NGINX_MODULE:-$NGINX_PREFIX/modules/ngx_http_modsecurity_module.so}"
MODSECURITY_LIB_DIR="${MODSECURITY_LIB_DIR:-$NGINX_BUILD_DIR/output/modsecurity/lib}"
NGINX_FUNCTIONAL_A_RUNTIME_LIBRARY="${NGINX_FUNCTIONAL_A_RUNTIME_LIBRARY:-}"
MODSECURITY_RUNTIME_LIBRARY="$MODSECURITY_LIB_DIR/libmodsecurity.so"
LOG_DIR="${LOG_DIR:-}"
RESULTS_DIR="${RESULTS_DIR:-$BUILD_ROOT/results}"
if [ -n "${FORCE_ALL_CASES:-}" ] && [ "$RESULTS_DIR" = "$BUILD_ROOT/results" ]; then
    RESULTS_DIR="$BUILD_ROOT/results/force-all"
fi
RUNTIME_BASE="${RUNTIME_BASE:-}"
RUNTIME_ROOT="${RUNTIME_ROOT:-}"
CURL_BIN="${CURL:-}"
PYTHON_BIN="${PYTHON:-python3}"
: "${CONNECTOR_REVISION:?CONNECTOR_REVISION is required explicitly}"
RESULT_RUN_ID=${NO_CRS_RUN_ID:-${SMOKE_RUN_ID:-${VERIFIED_RUN_ID:-}}}
: "${RESULT_RUN_ID:?an explicit NO_CRS_RUN_ID, SMOKE_RUN_ID or VERIFIED_RUN_ID is required}"
SMOKE_RUN_ID=$RESULT_RUN_ID
export SMOKE_RUN_ID

NGINX_PATH_AUTHORITY_VALIDATOR="$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/common/validate-nginx-harness-paths.py"
PYTHONDONTWRITEBYTECODE="${PYTHONDONTWRITEBYTECODE:-1}"
export PYTHONDONTWRITEBYTECODE
BASE_PORT="${PORT:-18081}"
PORT="$BASE_PORT"
PORT_SEARCH_LIMIT="${PORT_SEARCH_LIMIT:-100}"
PORT_RETRY_LIMIT="${PORT_RETRY_LIMIT:-1}"
TEMPLATE="$SCRIPT_DIR/nginx_smoke.conf"
TEST_CASE="${TEST_CASE:-}"
SMOKE_CASES="${SMOKE_CASES:-}"
NO_CRS_SELECTED_CASE_IDS="${NO_CRS_SELECTED_CASE_IDS:-}"
CASE_SCOPE="${CASE_SCOPE:-all}"
CASE_CLI="$FRAMEWORK_ROOT/tests/runners/case_cli.py"
RUN_ONE_CASE="${RUN_ONE_CASE:-0}"
NGINX_HOSTED_FUNCTIONAL_A="${NGINX_HOSTED_FUNCTIONAL_A:-0}"
NGINX_CASE_ENV_READER="$TEST_ROOT/connector_suite/adapters/nginx/harness/read_case_env.py"
NGINX_PHASE4_LOG_TARGET_MODE="${NGINX_PHASE4_LOG_TARGET_MODE:-regular}"
NGINX_PHASE4_LOG_SCOPE="${NGINX_PHASE4_LOG_SCOPE:-location}"
NGINX_PHASE4_LOG_LIFECYCLE_PROBE="${NGINX_PHASE4_LOG_LIFECYCLE_PROBE:-0}"
NGINX_FUNCTIONAL_A_QUERY_CANARY="${NGINX_FUNCTIONAL_A_QUERY_CANARY:-0}"
MSCONNECTOR_SMOKE_STAGE="${MSCONNECTOR_SMOKE_STAGE:-minimal_runtime_smoke}"
MSCONNECTOR_SMOKE_STAGE_BOUNDED_SOAK=bounded_soak
NGINX_TR_DELETE_WHITESPACE='[:space:]'
STATUS_FILE=""
CONNECTOR_ORIGIN_SOURCE="${CONNECTOR_ORIGIN_SOURCE:-}"
CONNECTOR_ORIGIN_SOURCE_REPO="${CONNECTOR_ORIGIN_SOURCE_REPO:-}"
CONNECTOR_ORIGIN_SOURCE_URL="${CONNECTOR_ORIGIN_SOURCE_URL:-}"
CONNECTOR_ORIGIN_SOURCE_COMMIT="${CONNECTOR_ORIGIN_SOURCE_COMMIT:-}"
CONNECTOR_ORIGIN_SOURCE_VERSION="${CONNECTOR_ORIGIN_SOURCE_VERSION:-}"
CONNECTOR_ORIGIN_LICENSE="${CONNECTOR_ORIGIN_LICENSE:-}"
CONNECTOR_ORIGIN_IMPORTED_PATH="${CONNECTOR_ORIGIN_IMPORTED_PATH:-}"
MODSECURITY_TEST_VARIANT="${MODSECURITY_TEST_VARIANT:-}"
MODSECURITY_RULE_PREAMBLE_FILE="${MODSECURITY_RULE_PREAMBLE_FILE:-}"
NGINX_WORKER_USER="${NGINX_WORKER_USER:-nobody}"
NGINX_WORKER_GROUP="${NGINX_WORKER_GROUP:-}"
PERMISSIONS_LOG="${PERMISSIONS_LOG:-}"
MSCONNECTOR_FULL_LIFECYCLE_SYNC="${MSCONNECTOR_FULL_LIFECYCLE_SYNC:-0}"
# Preserve only this explicit Parent route policy across portable case.env.
NGINX_TRUSTED_SYNCHRONIZED_PHASE4_MODE="${NGINX_SYNCHRONIZED_PHASE4_MODE:-}"
readonly NGINX_TRUSTED_SYNCHRONIZED_PHASE4_MODE
FULL_LIFECYCLE_EVIDENCE_OUTPUT="${FULL_LIFECYCLE_EVIDENCE_OUTPUT:-}"
SYNCHRONIZED_UPSTREAM_CONTROL_ROOT="${SYNCHRONIZED_UPSTREAM_CONTROL_ROOT:-}"
SYNCHRONIZED_UPSTREAM="$FRAMEWORK_ROOT/tests/runners/synchronized_upstream.py"
NGINX_DOWNSTREAM_PROTOCOL="${NGINX_DOWNSTREAM_PROTOCOL:-http1}"
NGINX_UPSTREAM_PROTOCOL="${NGINX_UPSTREAM_PROTOCOL:-http1}"
NO_CRS_PROTOCOL_CLIENT_ARTIFACT_DIR="${NO_CRS_PROTOCOL_CLIENT_ARTIFACT_DIR:-}"
# This is deliberately a small, selected catalog subset rather than an
# unbounded traffic generator.  Each case needs its own materialized rule and
# host configuration, but its workers reuse one already-started NGINX process.
NGINX_SOAK_CASES="${NGINX_SOAK_CASES:-allow_without_marker phase2_body_limits phase2_args_block phase1_header_block request_body_urlencoded_block phase3_redirect_before_commit nginx_phase4_deny_after_commit_log_only nginx_phase4_deny_after_commit_abort}"
NGINX_SOAK_MAX_CASES=8
NGINX_SOAK_DURATION_SECONDS="${NGINX_SOAK_DURATION_SECONDS:-30}"
NGINX_SOAK_CONCURRENCY="${NGINX_SOAK_CONCURRENCY:-4}"
NGINX_SOAK_WORKER_PIDS=""
# Memcheck is intentionally a separate, opt-in bounded-soak diagnostic.  The
# normal harness neither probes Valgrind nor changes its startup path.
NGINX_MEMCHECK="${NGINX_MEMCHECK:-0}"
VALGRIND_BIN="${VALGRIND_BIN:-valgrind}"
SETSID_BIN="${SETSID_BIN:-setsid}"
# This source-controlled, exact upstream NGINX worker-exit suppression is not
# configurable by the caller.  Memcheck also binds it to the canonical
# NGINX-1.31.2 binary and SHA-256-verified retained source archive.  A changed
# stack does not match and remains a failing Memcheck result; no connector or
# invalid-access diagnostics are suppressed.
NGINX_MEMCHECK_SUPPRESSIONS="$SCRIPT_DIR/valgrind-nginx-core-1.31.2.supp"
NGINX_MEMCHECK_EXPECTED_VERSION=1.31.2
NGINX_MEMCHECK_NGINX_BINARY="$NGINX_PREFIX/sbin/nginx"
NGINX_MEMCHECK_NGINX_ARCHIVE="$NGINX_BUILD_DIR/verified-archives/nginx-1.31.2.tar.gz"
NGINX_MEMCHECK_NGINX_ARCHIVE_SHA256=af2a957c41da636ddc4f883e4523c6d140b4784dbce42000c364ae5092aa473c
NGINX_MEMCHECK_WAIT_SECONDS=30
NGINX_MEMCHECK_SUMMARIZER="$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/common/summarize-nginx-memcheck.py"
NGINX_MEMCHECK_STARTED=0
NGINX_MEMCHECK_FINALIZED=0
NGINX_MEMCHECK_SHUTDOWN=not_started
NGINX_MEMCHECK_WAIT_STATUS=not_started
NGINX_MEMCHECK_WRAPPER_EXIT_CODE=
NGINX_MEMCHECK_PROCESS_GROUP=""
NGINX_MEMCHECK_CONTAINMENT=unverified
# Normal smoke runs must prove the real master/worker lifecycle.  This is
# deliberately independent from the opt-in Memcheck diagnostic: a diagnostic
# wrapper is not evidence that the production process model was exercised.
NGINX_LIFECYCLE_TIMEOUT_SECONDS="${NGINX_LIFECYCLE_TIMEOUT_SECONDS:-30}"
NGINX_LIFECYCLE_ENABLED="${NGINX_LIFECYCLE_ENABLED:-1}"
NGINX_LIFECYCLE_ROLE_FILE=""
NGINX_LIFECYCLE_FILE=""
NGINX_LIFECYCLE_SHUTDOWN=not_started
NGINX_LIFECYCLE_EXIT_STATUS=not_observed
NGINX_LIFECYCLE_RELOAD=not_attempted
NGINX_LIFECYCLE_INITIAL_WORKER=""
NGINX_LIFECYCLE_RELOADED_WORKER=""

case "$NGINX_HOSTED_FUNCTIONAL_A" in
    0|1) ;;
    *)
        echo "nginx_smoke: blocked NGINX_HOSTED_FUNCTIONAL_A must be 0 or 1"
        exit 77
        ;;
esac

case "$NGINX_PHASE4_LOG_TARGET_MODE" in
    regular|existing_regular_0644|unsafe_symlink|unsafe_fifo|unsafe_directory|unsafe_writable_parent|unsafe_wrong_owner) ;;
    *)
        echo "nginx_smoke: blocked unsupported NGINX_PHASE4_LOG_TARGET_MODE"
        exit 77
        ;;
esac
case "$NGINX_PHASE4_LOG_SCOPE" in
    location|location_if_missing|server|server_with_location_override) ;;
    *)
        echo "nginx_smoke: blocked unsupported NGINX_PHASE4_LOG_SCOPE"
        exit 77
        ;;
esac
case "$NGINX_PHASE4_LOG_LIFECYCLE_PROBE:$NGINX_FUNCTIONAL_A_QUERY_CANARY" in
    0:0|0:1|1:0|1:1) ;;
    *)
        echo "nginx_smoke: blocked functional-A phase4 probe flags must be 0 or 1"
        exit 77
        ;;
esac

load_connector_adapter_metadata() {
    eval "$(CONNECTOR_ROOT="$REPO_ROOT" "$PYTHON_BIN" "$FRAMEWORK_ROOT/ci/lib/adapter_metadata.py" shell nginx --prefix CONNECTOR_ADAPTER)"
    CONNECTOR_ORIGIN_SOURCE="${CONNECTOR_ORIGIN_SOURCE:-$CONNECTOR_ADAPTER_SOURCE}"
    CONNECTOR_ORIGIN_SOURCE_REPO="${CONNECTOR_ORIGIN_SOURCE_REPO:-$CONNECTOR_ADAPTER_SOURCE_REPO}"
    CONNECTOR_ORIGIN_SOURCE_URL="${CONNECTOR_ORIGIN_SOURCE_URL:-$CONNECTOR_ADAPTER_SOURCE_URL}"
    CONNECTOR_ORIGIN_SOURCE_COMMIT="${CONNECTOR_ORIGIN_SOURCE_COMMIT:-$CONNECTOR_ADAPTER_SOURCE_COMMIT}"
    CONNECTOR_ORIGIN_SOURCE_VERSION="${CONNECTOR_ORIGIN_SOURCE_VERSION:-$CONNECTOR_ADAPTER_SOURCE_VERSION}"
    CONNECTOR_ORIGIN_LICENSE="${CONNECTOR_ORIGIN_LICENSE:-$CONNECTOR_ADAPTER_LICENSE}"
    CONNECTOR_ORIGIN_IMPORTED_PATH="${CONNECTOR_ORIGIN_IMPORTED_PATH:-$CONNECTOR_ADAPTER_IMPORTED_PATH}"
}

if [ "$NGINX_HOSTED_FUNCTIONAL_A" = "1" ]; then
    # Functional A intentionally does not evaluate the Framework metadata
    # shell fragment while this selected native harness runs as root.  The
    # mode is bounded to one case, so aggregate origin-summary metadata is
    # neither needed nor silently replaced.
    [ "$RUN_ONE_CASE" = "1" ] || {
        echo "nginx_smoke: blocked hosted functional A requires RUN_ONE_CASE=1"
        exit 77
    }
    case "$NGINX_FUNCTIONAL_A_RUNTIME_LIBRARY" in
        "$MODSECURITY_LIB_DIR/libmodsecurity.so.3")
            MODSECURITY_RUNTIME_LIBRARY="$NGINX_FUNCTIONAL_A_RUNTIME_LIBRARY"
            ;;
        *)
            echo "nginx_smoke: blocked hosted functional A requires the validated libmodsecurity.so.3 artifact" >&2
            exit 77
            ;;
    esac
else
    load_connector_adapter_metadata
fi

read_functional_case_value() {
    case_key=$1
    (
        exec 3< "$RUNTIME_ROOT" || exit 2
        exec "$PYTHON_BIN" "$NGINX_CASE_ENV_READER" --key "$case_key"
    )
}

assert_functional_case_path_match() {
    case_key=$1
    expected_path=$2
    actual_path=$(read_functional_case_value "$case_key") || \
        blocked "generated case environment failed the hosted functional-A data parser"
    [ "$actual_path" = "$expected_path" ] || \
        blocked "generated case environment changed the trusted $case_key path"
}

load_functional_case_environment() {
    [ -f "$NGINX_CASE_ENV_READER" ] || \
        blocked "missing hosted functional-A case environment reader: $NGINX_CASE_ENV_READER"
    if ! CASE_NAME=$(read_functional_case_value CASE_NAME) || \
       ! REQUEST_METHOD=$(read_functional_case_value REQUEST_METHOD) || \
       ! REQUEST_PATH=$(read_functional_case_value REQUEST_PATH) || \
       ! REQUEST_HAS_BODY=$(read_functional_case_value REQUEST_HAS_BODY) || \
       ! EXPECT_STATUS=$(read_functional_case_value EXPECT_STATUS) || \
       ! EXPECT_INTERVENTION=$(read_functional_case_value EXPECT_INTERVENTION) || \
       ! EXPECT_RULE_ID=$(read_functional_case_value EXPECT_RULE_ID) || \
       ! EXPECT_RESPONSE_CONTAINS=$(read_functional_case_value EXPECT_RESPONSE_CONTAINS) || \
       ! EXPECT_TRANSPORT=$(read_functional_case_value EXPECT_TRANSPORT) || \
       ! EXPECT_AUDIT_LOG_REQUIRED=$(read_functional_case_value EXPECT_AUDIT_LOG_REQUIRED) || \
       ! NGINX_PHASE4_MODE=$(read_functional_case_value NGINX_PHASE4_MODE); then
        blocked "generated case environment failed the hosted functional-A data parser"
    fi
    assert_functional_case_path_match REQUEST_HEADERS_FILE "$REQUEST_HEADERS_FILE"
    assert_functional_case_path_match REQUEST_BODY_FILE "$REQUEST_BODY_FILE"
    assert_functional_case_path_match AUDIT_LOG_FILE "$AUDIT_LOG_FILE"
    assert_functional_case_path_match AUDIT_LOG_DIR "$AUDIT_LOG_DIR"
    export CASE_NAME REQUEST_METHOD REQUEST_PATH REQUEST_HAS_BODY \
        REQUEST_HEADERS_FILE REQUEST_BODY_FILE AUDIT_LOG_FILE AUDIT_LOG_DIR \
        EXPECT_STATUS EXPECT_INTERVENTION EXPECT_RULE_ID EXPECT_RESPONSE_CONTAINS \
        EXPECT_TRANSPORT EXPECT_AUDIT_LOG_REQUIRED NGINX_PHASE4_MODE
}

write_harness_status() {
    status_kind=$1
    shift
    [ "$NGINX_PATHS_VALIDATED" = "1" ] || return 0
    [ -n "${STATUS_FILE:-}" ] || return 0
    printf '%s: %s\n' "$status_kind" "$*" >> "$STATUS_FILE"
}

blocked() {
    echo "nginx_smoke: blocked $*"
    write_harness_status blocked "$*"
    exit 77
}

fail() {
    echo "nginx_smoke: fail $*"
    write_harness_status fail "$*"
    exit 1
}

not_executable() {
    echo "nginx_smoke: not_executable $*"
    write_harness_status not_executable "$*"
    exit 78
}

configtest_case_not_executable() {
    grep -E "Rules error|modsecurity-smoke\\.conf|modsecurity_rules_file|modsecurity_rules" \
        "$LOG_DIR/configtest.log" >/dev/null 2>&1
}

ensure_dir_755() {
    for path in "$@"; do
        install -d -m 755 "$path"
    done
}

ensure_private_dir() {
    for path in "$@"; do
        install -d -m 700 "$path"
        if [ "$CURRENT_UID" = "0" ]; then
            chown root:root "$path"
        fi
        chmod 700 "$path"
    done
}

nginx_worker_group() {
    if [ -n "${NGINX_WORKER_RESOLVED_GROUP:-}" ]; then
        printf '%s\n' "$NGINX_WORKER_RESOLVED_GROUP"
        return 0
    fi
    if [ -n "$NGINX_WORKER_GROUP" ]; then
        printf '%s\n' "$NGINX_WORKER_GROUP"
        return 0
    fi
    id -gn "$NGINX_WORKER_USER" 2>/dev/null || printf '%s\n' "$NGINX_WORKER_USER"
}

write_permission_diagnostics() {
    [ "$NGINX_PATHS_VALIDATED" = "1" ] || return 0
    log_file=$PERMISSIONS_LOG
    {
        echo "nginx_harness_permissions:"
        echo "  effective_user=$(id -un 2>/dev/null || printf unknown)"
        echo "  effective_uid=$CURRENT_UID"
        echo "  nginx_worker_user_hint=$NGINX_WORKER_USER"
        echo "  nginx_worker_group_hint=$(nginx_worker_group)"
        echo "  build_root=$BUILD_ROOT"
        echo "  nginx_harness_work_root=$NGINX_HARNESS_WORK_ROOT"
        echo "  runtime_base=$RUNTIME_BASE"
        echo "  runtime_root=$RUNTIME_ROOT"
        echo "  log_dir=$LOG_DIR"
        echo "  nginx_worker_state_root=${NGINX_WORKER_STATE_ROOT:-}"
        echo "  nginx_server_log_root=${NGINX_SERVER_LOG_ROOT:-}"
        echo "  nginx_memcheck_evidence_dir=${NGINX_MEMCHECK_EVIDENCE_DIR:-}"
        echo "  docroot=${DOCROOT:-}"
        echo
        for path in \
            "$NGINX_HARNESS_WORK_ROOT" \
            "$RUNTIME_BASE" \
            "$RUNTIME_ROOT" \
            "$LOG_DIR" \
            "${NGINX_WORKER_STATE_ROOT:-}" \
            "${NGINX_SERVER_LOG_ROOT:-}" \
            "${NGINX_SERVER_LOG_ROOT:-}/error.log" \
            "${NGINX_SERVER_LOG_ROOT:-}/access.log" \
            "${NGINX_SERVER_LOG_ROOT:-}/audit" \
            "${NGINX_SERVER_LOG_ROOT:-}/phase4.log" \
            "${NGINX_MEMCHECK_EVIDENCE_DIR:-}" \
            "${DOCROOT:-}" \
            "${DOCROOT:-}/index.html" \
            "${DOCROOT:-}/__modsec_smoke_ready" \
            "${NGINX_PHASE4_LOG_FILE:-}" \
            "${CONFIG_FILE:-}" \
            "${RULES_FILE:-}"
        do
            [ -n "$path" ] || continue
            echo "-- $path"
            if [ -e "$path" ]; then
                stat -c '%A %U %G %n' "$path" 2>/dev/null || ls -ld "$path" 2>/dev/null || true
                if command -v namei >/dev/null 2>&1; then
                    namei -l "$path" 2>/dev/null || true
                fi
            else
                echo "missing"
            fi
            echo
        done
    } > "$log_file"
}

prepare_nginx_worker_paths() {
    worker_group=$(nginx_worker_group)
    if [ "$CURRENT_UID" = "0" ]; then
        resolve_nginx_worker_identity
        worker_group=$NGINX_WORKER_RESOLVED_GROUP
        # A previous handoff is immutable from the restricted root master:
        # without DAC_OVERRIDE/FOWNER it cannot traverse or chmod worker 0700
        # directories. Verify the complete tree as the worker instead.
        if [ "$(stat -c '%u' "$NGINX_WORKER_STATE_ROOT" 2>/dev/null || true)" = "$NGINX_WORKER_RESOLVED_UID" ]; then
            nginx_worker_runuser -u "$NGINX_WORKER_RESOLVED_USER" -g "$worker_group" -- \
                /bin/sh -eu -c '
                    expected=$1
                    shift
                    for path do
                        [ ! -L "$path" ] && [ -d "$path" ] &&
                            [ "$(stat -c "%u:%g:%a" "$path")" = "$expected" ] || exit 1
                    done
                ' nginx-worker-paths "$NGINX_WORKER_RESOLVED_UID:$NGINX_WORKER_RESOLVED_GID:700" \
                "$NGINX_WORKER_STATE_ROOT" \
                "$NGINX_WORKER_STATE_ROOT/client_body_temp" \
                "$NGINX_WORKER_STATE_ROOT/proxy_temp" \
                "$NGINX_WORKER_STATE_ROOT/fastcgi_temp" \
                "$NGINX_WORKER_STATE_ROOT/uwsgi_temp" \
                "$NGINX_WORKER_STATE_ROOT/scgi_temp" \
                "$NGINX_SERVER_LOG_ROOT" "$NGINX_SERVER_LOG_ROOT/audit" || \
                blocked "existing NGINX worker paths failed ownership/mode validation"
            return 0
        fi
    fi
    for path in \
        "$NGINX_WORKER_STATE_ROOT" \
        "$NGINX_WORKER_STATE_ROOT/client_body_temp" \
        "$NGINX_WORKER_STATE_ROOT/proxy_temp" \
        "$NGINX_WORKER_STATE_ROOT/fastcgi_temp" \
        "$NGINX_WORKER_STATE_ROOT/uwsgi_temp" \
        "$NGINX_WORKER_STATE_ROOT/scgi_temp" \
        "$NGINX_SERVER_LOG_ROOT" \
        "$NGINX_SERVER_LOG_ROOT/audit"
    do
        [ ! -L "$path" ] || blocked "NGINX worker path must not be a symlink: $path"
        if [ -e "$path" ]; then
            [ -d "$path" ] || blocked "NGINX worker path must be a directory: $path"
            [ "$(stat -c '%u' "$path")" = "$CURRENT_UID" ] || \
                blocked "NGINX worker path must be owned by the launcher before handoff: $path"
        fi
        install -d -m 700 "$path"
        chmod 700 "$path"
    done
    # Finish all creation and mode changes before losing ownership. Children
    # precede their private parents so restricted root retains traversal.
    if [ "$CURRENT_UID" = "0" ]; then
        for path in \
            "$NGINX_WORKER_STATE_ROOT/client_body_temp" \
            "$NGINX_WORKER_STATE_ROOT/proxy_temp" \
            "$NGINX_WORKER_STATE_ROOT/fastcgi_temp" \
            "$NGINX_WORKER_STATE_ROOT/uwsgi_temp" \
            "$NGINX_WORKER_STATE_ROOT/scgi_temp" \
            "$NGINX_SERVER_LOG_ROOT/audit" \
            "$NGINX_WORKER_STATE_ROOT" "$NGINX_SERVER_LOG_ROOT"
        do
            chown "$NGINX_WORKER_RESOLVED_USER:$worker_group" "$path"
        done
    fi
}

resolve_nginx_worker_identity() {
    NGINX_WORKER_RESOLVED_USER=$(id -un "$NGINX_WORKER_USER" 2>/dev/null) || \
        blocked "NGINX_WORKER_USER is not a local account: $NGINX_WORKER_USER"
    NGINX_WORKER_RESOLVED_UID=$(id -u "$NGINX_WORKER_USER" 2>/dev/null) || \
        blocked "cannot resolve NGINX_WORKER_USER uid: $NGINX_WORKER_USER"
    if [ "$CURRENT_UID" = "0" ] && [ "$NGINX_WORKER_RESOLVED_UID" = "$CURRENT_UID" ]; then
        blocked "NGINX_WORKER_USER must be distinct from the root harness identity"
    fi
    if [ -n "$NGINX_WORKER_GROUP" ]; then
        command -v getent >/dev/null 2>&1 || \
            blocked "NGINX_WORKER_GROUP requires getent for safe group resolution"
        nginx_worker_group_record=$(getent group "$NGINX_WORKER_GROUP") || \
            blocked "NGINX_WORKER_GROUP is not a local group: $NGINX_WORKER_GROUP"
        NGINX_WORKER_RESOLVED_GROUP=${nginx_worker_group_record%%:*}
        nginx_worker_group_fields=${nginx_worker_group_record#*:}
        nginx_worker_group_fields=${nginx_worker_group_fields#*:}
        NGINX_WORKER_RESOLVED_GID=${nginx_worker_group_fields%%:*}
    else
        NGINX_WORKER_RESOLVED_GROUP=$(id -gn "$NGINX_WORKER_USER" 2>/dev/null) || \
            blocked "cannot resolve NGINX_WORKER_USER group: $NGINX_WORKER_USER"
        NGINX_WORKER_RESOLVED_GID=$(id -g "$NGINX_WORKER_USER" 2>/dev/null) || \
            blocked "cannot resolve NGINX_WORKER_USER gid: $NGINX_WORKER_USER"
    fi
    [ -n "$NGINX_WORKER_RESOLVED_GROUP" ] || \
        blocked "NGINX worker group resolved to an empty value"
    case "$NGINX_WORKER_RESOLVED_GID" in
        *[!0-9]*|"") blocked "NGINX worker group resolved to an invalid gid" ;;
        *) ;;
    esac
}

lock_private_runtime_paths() {
    ensure_private_dir "$LOG_DIR" "$RUNTIME_ROOT/conf" "$NGINX_MEMCHECK_EVIDENCE_DIR"
    if [ "$NGINX_DOCROOT_PROJECTION" = "1" ]; then
        ensure_private_dir "$RUNTIME_ROOT" "$PRIVATE_DOCROOT"
    else
        if [ "$CURRENT_UID" = "0" ]; then
            chown root:root "$RUNTIME_ROOT" "$PRIVATE_DOCROOT"
        fi
        chmod 711 "$RUNTIME_ROOT"
        chmod -R u+rwX,go+rX "$PRIVATE_DOCROOT"
    fi
    write_permission_diagnostics
}

append_worker_preflight_record() {
    check_name=$1
    check_status=$2
    check_path=$3
    check_notes=$4
    preflight_file=$NGINX_WORKER_PREFLIGHT_FILE
    "$PYTHON_BIN" - "$preflight_file" "$check_name" "$check_status" "$check_path" "$check_notes" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
record = {
    "check": sys.argv[2],
    "status": sys.argv[3],
    "path": sys.argv[4],
    "notes": sys.argv[5],
}
with path.open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(record, sort_keys=True) + "\n")
PY
}

nginx_worker_runuser_is_available() {
    [ -x /usr/sbin/runuser ] || [ -x /usr/bin/runuser ]
}

nginx_worker_runuser() {
    if [ -x /usr/sbin/runuser ]; then
        /usr/sbin/runuser "$@"
    elif [ -x /usr/bin/runuser ]; then
        /usr/bin/runuser "$@"
    else
        return 127
    fi
}

nginx_worker_can_access() {
    access_mode=$1
    access_path=$2
    if nginx_worker_runuser_is_available && [ "$CURRENT_UID" = "0" ] && id "$NGINX_WORKER_USER" >/dev/null 2>&1; then
        nginx_worker_runuser -u "$NGINX_WORKER_USER" -g "$NGINX_WORKER_RESOLVED_GROUP" -- \
            test "$access_mode" "$access_path"
        return $?
    fi
    test "$access_mode" "$access_path"
}

nginx_worker_identity_is_verifiable() {
    [ "$CURRENT_UID" = "0" ] || return 1
    nginx_worker_runuser_is_available || return 1
    nginx_worker_uid=$(id -u "$NGINX_WORKER_USER" 2>/dev/null) || return 1
    [ "$nginx_worker_uid" != "$CURRENT_UID" ]
}

validate_nginx_worker_isolation() {
    [ "$CURRENT_UID" = "0" ] || \
        blocked "NGINX harness requires root to establish a distinct verified worker identity"
    resolve_nginx_worker_identity
    nginx_worker_identity_is_verifiable || \
        blocked "NGINX harness requires runuser and a distinct verifiable NGINX worker identity"
}

nginx_worker_access_notes() {
    if nginx_worker_identity_is_verifiable; then
        printf 'checked with runuser -u %s -g %s' \
            "$NGINX_WORKER_USER" "$NGINX_WORKER_RESOLVED_GROUP"
    else
        printf 'runuser worker check unavailable; used current process stat/test fallback'
    fi
}

validate_nginx_docroot_projection_mode() {
    case "$NGINX_DOCROOT_PROJECTION" in
        0|1) ;;
        *) fail "NGINX_DOCROOT_PROJECTION must be 0 or 1" ;;
    esac
    if [ "$NGINX_DOCROOT_PROJECTION" = "0" ] && \
       [ -n "$NGINX_DOCROOT_PROJECTION_ROOT$NGINX_DOCROOT_PROJECTION_PARENT" ]; then
        blocked "NGINX docroot projection parent/root requires NGINX_DOCROOT_PROJECTION=1"
    fi
    if [ "$NGINX_DOCROOT_PROJECTION" = "1" ] && \
       { [ -z "$NGINX_DOCROOT_PROJECTION_PARENT" ] || [ -z "$NGINX_DOCROOT_PROJECTION_ROOT" ]; }; then
        blocked "NGINX docroot projection requires an explicit safe parent and fresh root"
    fi
}

project_nginx_worker_docroot() {
    [ "$NGINX_DOCROOT_PROJECTION" = "1" ] || return 0
    [ -f "$NGINX_DOCROOT_PROJECTION_HELPER" ] || \
        blocked "missing NGINX docroot projection helper: $NGINX_DOCROOT_PROJECTION_HELPER"

    # Framework case_cli writes all mutable case material into PRIVATE_DOCROOT
    # below BUILD_ROOT.  The helper emits a fresh, non-overlapping projection
    # containing only the two static files NGINX workers need to read.
    set -- "$PYTHON_BIN" "$NGINX_DOCROOT_PROJECTION_HELPER" \
        --source-docroot "$PRIVATE_DOCROOT" \
        --private-root "$BUILD_ROOT" \
        --worker-gid "$NGINX_WORKER_RESOLVED_GID" \
        --avoid-root "$BUILD_ROOT" \
        --avoid-root "$VERIFIED_BUILD_ROOT" \
        --avoid-root "$VERIFIED_RUN_ROOT" \
        --avoid-root "$NGINX_HARNESS_PARENT" \
        --avoid-root "$NGINX_HARNESS_WORK_ROOT" \
        --avoid-root "$RUNTIME_BASE" \
        --avoid-root "$RUNTIME_ROOT" \
        --avoid-root "$LOG_DIR" \
        --avoid-root "$RESULTS_DIR"
    if [ -n "${CACHE_ROOT:-}" ]; then
        set -- "$@" --avoid-root "$CACHE_ROOT"
    fi
    if [ -n "${VERIFIED_EVIDENCE_ROOT:-}" ]; then
        set -- "$@" --avoid-root "$VERIFIED_EVIDENCE_ROOT"
    fi
    if [ -n "${EVIDENCE_ROOT:-}" ]; then
        set -- "$@" --avoid-root "$EVIDENCE_ROOT"
    fi
    if [ -n "${CONNECTOR_RUN_ROOT:-}" ]; then
        set -- "$@" --avoid-root "$CONNECTOR_RUN_ROOT"
    fi
    if [ -n "${CONNECTOR_LOG_ROOT:-}" ]; then
        set -- "$@" --avoid-root "$CONNECTOR_LOG_ROOT"
    fi
    if [ -n "$NGINX_DOCROOT_PROJECTION_PARENT" ]; then
        set -- "$@" --projection-parent "$NGINX_DOCROOT_PROJECTION_PARENT"
    fi
    if [ -n "$NGINX_DOCROOT_PROJECTION_ROOT" ]; then
        set -- "$@" --projection-root "$NGINX_DOCROOT_PROJECTION_ROOT"
    fi
    if ! "$@" > "$LOG_DIR/docroot-projection.path" \
        2> "$LOG_DIR/docroot-projection.log"; then
        blocked "unable to prepare a worker-visible NGINX docroot projection; see $LOG_DIR/docroot-projection.log"
    fi
    projection_path_line_count=$(wc -l < "$LOG_DIR/docroot-projection.path" | tr -d "$NGINX_TR_DELETE_WHITESPACE")
    case "$projection_path_line_count" in
        1) ;;
        *) blocked "NGINX docroot projection helper emitted an invalid path result" ;;
    esac
    NGINX_DOCROOT_PROJECTION_PATH=$(sed -n '1p' "$LOG_DIR/docroot-projection.path")
    case "$NGINX_DOCROOT_PROJECTION_PATH" in
        /*) ;;
        *) blocked "NGINX docroot projection helper returned a non-absolute path" ;;
    esac
    NGINX_DOCROOT_PROJECTION_ROOT=$NGINX_DOCROOT_PROJECTION_PATH
    NGINX_DOCROOT_PROJECTION_PARENT=$(dirname "$NGINX_DOCROOT_PROJECTION_PATH")
    DOCROOT=$NGINX_DOCROOT_PROJECTION_PATH
}

preflight_nginx_worker_docroot() {
    preflight_file="${NGINX_WORKER_PREFLIGHT_FILE:-$LOG_DIR/nginx-worker-preflight.jsonl}"
    : > "$preflight_file"
    preflight_failed=0
    index_file="$DOCROOT/index.html"
    ready_file="$DOCROOT/__modsec_smoke_ready"

    case "$NGINX_HARNESS_PARENT" in
        /root|/root/*)
            append_worker_preflight_record "Path under /root" "FAIL" "$NGINX_HARNESS_PARENT" "NGINX_HARNESS_PARENT must not be under /root"
            preflight_failed=1
            ;;
        *)
            append_worker_preflight_record "Path under /root" "PASS" "$NGINX_HARNESS_PARENT" "NGINX_HARNESS_PARENT is outside /root"
            ;;
    esac
    case "$NGINX_HARNESS_WORK_ROOT" in
        /root|/root/*)
            append_worker_preflight_record "Work root under /root" "FAIL" "$NGINX_HARNESS_WORK_ROOT" "NGINX_HARNESS_WORK_ROOT must not be under /root"
            preflight_failed=1
            ;;
        *)
            append_worker_preflight_record "Work root under /root" "PASS" "$NGINX_HARNESS_WORK_ROOT" "NGINX_HARNESS_WORK_ROOT is outside /root"
            ;;
    esac

    if [ -f "$index_file" ]; then
        append_worker_preflight_record "DOCROOT/index.html exists" "PASS" "$index_file" "materialized before NGINX start"
    else
        append_worker_preflight_record "DOCROOT/index.html exists" "FAIL" "$index_file" "materialized docroot index is missing"
        preflight_failed=1
    fi
    if [ "$NGINX_DOCROOT_PROJECTION" = "1" ]; then
        if [ -f "$ready_file" ]; then
            append_worker_preflight_record "DOCROOT/__modsec_smoke_ready exists" "PASS" "$ready_file" "copied from private materialization"
        else
            append_worker_preflight_record "DOCROOT/__modsec_smoke_ready exists" "FAIL" "$ready_file" "worker-visible projection is incomplete"
            preflight_failed=1
        fi
    fi

    if command -v namei >/dev/null 2>&1; then
        namei -l "$index_file" > "$LOG_DIR/namei-docroot-index.log" 2>&1 || true
    else
        printf '%s\n' "namei unavailable" > "$LOG_DIR/namei-docroot-index.log"
    fi

    access_notes=$(nginx_worker_access_notes)
    if [ "$NGINX_DOCROOT_PROJECTION" = "1" ] && ! nginx_worker_identity_is_verifiable; then
        append_worker_preflight_record "NGINX worker identity" "FAIL" "$NGINX_WORKER_USER" "projection mode requires an actual worker-identity check"
        preflight_failed=1
    fi
    if [ "$NGINX_DOCROOT_PROJECTION" = "1" ] && \
       nginx_worker_can_access -x "$NGINX_DOCROOT_PROJECTION_PARENT"; then
        append_worker_preflight_record "Projection parent traversable" "PASS" "$NGINX_DOCROOT_PROJECTION_PARENT" "$access_notes"
    elif [ "$NGINX_DOCROOT_PROJECTION" = "1" ]; then
        append_worker_preflight_record "Projection parent traversable" "FAIL" "$NGINX_DOCROOT_PROJECTION_PARENT" "$access_notes"
        preflight_failed=1
    elif nginx_worker_can_access -x "$NGINX_HARNESS_PARENT"; then
        append_worker_preflight_record "Harness parent traversable" "PASS" "$NGINX_HARNESS_PARENT" "$access_notes"
    else
        append_worker_preflight_record "Harness parent traversable" "FAIL" "$NGINX_HARNESS_PARENT" "$access_notes"
        preflight_failed=1
    fi
    if nginx_worker_can_access -x "$DOCROOT"; then
        append_worker_preflight_record "NGINX worker can traverse docroot" "PASS" "$DOCROOT" "$access_notes"
    else
        append_worker_preflight_record "NGINX worker can traverse docroot" "FAIL" "$DOCROOT" "$access_notes"
        preflight_failed=1
    fi
    if nginx_worker_can_access -r "$index_file"; then
        append_worker_preflight_record "htdocs/index.html readable by worker" "PASS" "$index_file" "$access_notes"
    else
        append_worker_preflight_record "htdocs/index.html readable by worker" "FAIL" "$index_file" "$access_notes"
        preflight_failed=1
    fi
    if [ "$NGINX_DOCROOT_PROJECTION" = "1" ] && \
       nginx_worker_can_access -r "$ready_file"; then
        append_worker_preflight_record "htdocs/__modsec_smoke_ready readable by worker" "PASS" "$ready_file" "$access_notes"
    elif [ "$NGINX_DOCROOT_PROJECTION" = "1" ]; then
        append_worker_preflight_record "htdocs/__modsec_smoke_ready readable by worker" "FAIL" "$ready_file" "$access_notes"
        preflight_failed=1
    fi
    if nginx_worker_can_access -w "$NGINX_WORKER_STATE_ROOT"; then
        append_worker_preflight_record "NGINX worker state writable" "PASS" "$NGINX_WORKER_STATE_ROOT" "$access_notes"
    else
        append_worker_preflight_record "NGINX worker state writable" "FAIL" "$NGINX_WORKER_STATE_ROOT" "$access_notes"
        preflight_failed=1
    fi
    if nginx_worker_can_access -w "$NGINX_SERVER_LOG_ROOT"; then
        append_worker_preflight_record "NGINX server log root writable" "PASS" "$NGINX_SERVER_LOG_ROOT" "$access_notes"
    else
        append_worker_preflight_record "NGINX server log root writable" "FAIL" "$NGINX_SERVER_LOG_ROOT" "$access_notes"
        preflight_failed=1
    fi
    if [ "$NGINX_DOCROOT_PROJECTION" = "1" ] && \
       nginx_worker_can_access -x "$RUNTIME_ROOT"; then
        append_worker_preflight_record "Private runtime root hidden from worker" "FAIL" "$RUNTIME_ROOT" "worker may traverse private materialization"
        preflight_failed=1
    elif [ "$NGINX_DOCROOT_PROJECTION" = "1" ]; then
        append_worker_preflight_record "Private runtime root hidden from worker" "PASS" "$RUNTIME_ROOT" "$access_notes"
    fi
    if [ "$NGINX_DOCROOT_PROJECTION" = "1" ] && \
       nginx_worker_can_access -r "$RULES_FILE"; then
        append_worker_preflight_record "Rules remain private" "FAIL" "$RULES_FILE" "worker may read materialized rules"
        preflight_failed=1
    elif [ "$NGINX_DOCROOT_PROJECTION" = "1" ]; then
        append_worker_preflight_record "Rules remain private" "PASS" "$RULES_FILE" "$access_notes"
    fi
    if nginx_worker_can_access -x "$LOG_DIR"; then
        append_worker_preflight_record "Private harness logs hidden from worker" "FAIL" "$LOG_DIR" "worker may traverse private harness logs"
        preflight_failed=1
    else
        append_worker_preflight_record "Private harness logs hidden from worker" "PASS" "$LOG_DIR" "$access_notes"
    fi
    if nginx_worker_can_access -x "$NGINX_MEMCHECK_EVIDENCE_DIR"; then
        append_worker_preflight_record "Memcheck evidence hidden from worker" "FAIL" "$NGINX_MEMCHECK_EVIDENCE_DIR" "worker may traverse private Memcheck evidence"
        preflight_failed=1
    else
        append_worker_preflight_record "Memcheck evidence hidden from worker" "PASS" "$NGINX_MEMCHECK_EVIDENCE_DIR" "$access_notes"
    fi
    if [ "$NGINX_DOCROOT_PROJECTION" = "1" ]; then
        append_worker_preflight_record "Private harness root not required" "PASS" "$NGINX_HARNESS_PARENT" "worker only receives the independent static projection"
    fi
    append_worker_preflight_record "try_files fallback guarded" "$([ "$preflight_failed" -eq 0 ] && printf PASS || printf FAIL)" "$index_file" "docroot readability is checked before try_files /index.html can loop"

    if [ "$preflight_failed" -ne 0 ]; then
        write_permission_diagnostics
        echo "BLOCKED: nginx worker cannot access harness docroot"
        blocked "nginx worker cannot access harness docroot"
    fi
}

nginx_docroot_permission_denied() {
    [ -f "$NGINX_SERVER_LOG_ROOT/error.log" ] || return 1
    grep -E "htdocs/index\\.html.*Permission denied|htdocs/index\\.html.*forbidden \\(13: Permission denied\\)" "$NGINX_SERVER_LOG_ROOT/error.log" >/dev/null 2>&1
}

require_absolute_generated_path() {
    path=$1
    label=$2
    case "$path" in
        /*) ;;
        *) blocked "$label must be absolute: $path" ;;
    esac
    case "$path" in
        "$REPO_ROOT"|"$REPO_ROOT"/*|"$FRAMEWORK_ROOT"|"$FRAMEWORK_ROOT"/*)
            blocked "$label is inside a read-only or source checkout: $path"
            ;;
        *) ;;
    esac
}

canonical_generated_path() {
    generated_path=$1
    "$PYTHON_BIN" -c 'import os, sys; print(os.path.realpath(os.path.abspath(sys.argv[1])))' "$generated_path"
}

generated_paths_overlap() {
    generated_first_path=$1
    generated_second_path=$2
    first=$(canonical_generated_path "$generated_first_path") || \
        blocked "cannot canonicalize generated path: $generated_first_path"
    second=$(canonical_generated_path "$generated_second_path") || \
        blocked "cannot canonicalize generated path: $generated_second_path"
    case "$first" in
        "$second"|"$second"/*) return 0 ;;
        *) ;;
    esac
    case "$second" in
        "$first"|"$first"/*) return 0 ;;
        *) ;;
    esac
    return 1
}

require_private_worker_path_separation() {
    for private_path in "$RUNTIME_ROOT" "$LOG_DIR" "$NGINX_MEMCHECK_EVIDENCE_DIR"; do
        for worker_path in "$NGINX_WORKER_STATE_ROOT" "$NGINX_SERVER_LOG_ROOT"; do
            if generated_paths_overlap "$private_path" "$worker_path"; then
                blocked "private and NGINX worker paths must not overlap: $private_path / $worker_path"
            fi
        done
    done
    if generated_paths_overlap "$NGINX_WORKER_STATE_ROOT" "$NGINX_SERVER_LOG_ROOT"; then
        blocked "NGINX worker state and server-log paths must not overlap"
    fi
}

validate_nginx_harness_bootstrap_paths() {
    [ -f "$NGINX_PATH_AUTHORITY_VALIDATOR" ] || \
        blocked "missing NGINX harness path authority validator: $NGINX_PATH_AUTHORITY_VALIDATOR"
    if ! "$PYTHON_BIN" "$NGINX_PATH_AUTHORITY_VALIDATOR" --quiet \
        --verified-run-root "$VERIFIED_RUN_ROOT" \
        --directory BUILD_ROOT "$BUILD_ROOT" \
        --directory NGINX_HARNESS_PARENT "$NGINX_HARNESS_PARENT"; then
        blocked "NGINX harness bootstrap paths are outside verified runtime storage"
    fi
}

validate_nginx_harness_outer_paths() {
    [ -f "$NGINX_PATH_AUTHORITY_VALIDATOR" ] || \
        blocked "missing NGINX harness path authority validator: $NGINX_PATH_AUTHORITY_VALIDATOR"
    if ! "$PYTHON_BIN" "$NGINX_PATH_AUTHORITY_VALIDATOR" --quiet \
        --verified-run-root "$VERIFIED_RUN_ROOT" \
        --directory BUILD_ROOT "$BUILD_ROOT" \
        --directory NGINX_HARNESS_PARENT "$NGINX_HARNESS_PARENT" \
        --directory NGINX_HARNESS_WORK_ROOT "$NGINX_HARNESS_WORK_ROOT" \
        --directory RUNTIME_BASE "$RUNTIME_BASE" \
        --directory LOG_DIR "$LOG_DIR" \
        --directory RESULTS_DIR "$RESULTS_DIR"; then
        blocked "NGINX harness output paths are outside verified runtime storage"
    fi
    STATUS_FILE="$LOG_DIR/status.txt"
    NGINX_PATHS_VALIDATED=1
}

initialize_nginx_harness_paths() {
    validate_nginx_harness_bootstrap_paths
    if [ -z "$NGINX_HARNESS_WORK_ROOT" ]; then
        NGINX_HARNESS_WORK_ROOT=$(mktemp -d "$NGINX_HARNESS_PARENT/ModSecurity-conector-nginx-runtime-$CURRENT_UID-XXXXXX") || \
            blocked "could not create NGINX harness work root below the authorized parent"
    fi
    if [ -z "$LOG_DIR" ]; then
        LOG_DIR="$NGINX_HARNESS_WORK_ROOT/logs"
    fi
    if [ -z "$RUNTIME_BASE" ]; then
        RUNTIME_BASE="$NGINX_HARNESS_WORK_ROOT/runtime"
    fi
    validate_nginx_harness_outer_paths
}

validate_nginx_generated_path_authority() {
    [ -f "$NGINX_PATH_AUTHORITY_VALIDATOR" ] || \
        blocked "missing NGINX harness path authority validator: $NGINX_PATH_AUTHORITY_VALIDATOR"

    set -- "$PYTHON_BIN" "$NGINX_PATH_AUTHORITY_VALIDATOR" --quiet \
        --verified-run-root "$VERIFIED_RUN_ROOT" \
        --directory BUILD_ROOT "$BUILD_ROOT" \
        --directory NGINX_HARNESS_PARENT "$NGINX_HARNESS_PARENT" \
        --directory NGINX_HARNESS_WORK_ROOT "$NGINX_HARNESS_WORK_ROOT" \
        --directory RUNTIME_BASE "$RUNTIME_BASE" \
        --directory RUNTIME_ROOT "$RUNTIME_ROOT" \
        --directory LOG_DIR "$LOG_DIR" \
        --directory RESULTS_DIR "$RESULTS_DIR" \
        --directory NGINX_WORKER_STATE_ROOT "$NGINX_WORKER_STATE_ROOT" \
        --directory NGINX_SERVER_LOG_ROOT "$NGINX_SERVER_LOG_ROOT" \
        --directory NGINX_MEMCHECK_EVIDENCE_DIR "$NGINX_MEMCHECK_EVIDENCE_DIR" \
        --path RUNTIME_PID_FILE "$RUNTIME_PID_FILE" \
        --direct-child STATUS_FILE "$STATUS_FILE" "$LOG_DIR" \
        --direct-child PERMISSIONS_LOG "$PERMISSIONS_LOG" "$LOG_DIR" \
        --direct-child NGINX_WORKER_PREFLIGHT_FILE "$NGINX_WORKER_PREFLIGHT_FILE" "$LOG_DIR"

    if [ -n "$NO_CRS_PROTOCOL_CLIENT_ARTIFACT_DIR" ]; then
        set -- "$@" \
            --directory NO_CRS_PROTOCOL_CLIENT_ARTIFACT_DIR "$NO_CRS_PROTOCOL_CLIENT_ARTIFACT_DIR"
    fi
    if [ -n "$FULL_LIFECYCLE_EVIDENCE_OUTPUT" ]; then
        set -- "$@" \
            --path FULL_LIFECYCLE_EVIDENCE_OUTPUT "$FULL_LIFECYCLE_EVIDENCE_OUTPUT"
    fi
    if [ "$MSCONNECTOR_FULL_LIFECYCLE_SYNC" = "1" ]; then
        [ -n "$SYNCHRONIZED_UPSTREAM_CONTROL_ROOT" ] || \
            blocked "full-lifecycle synchronized upstream requires SYNCHRONIZED_UPSTREAM_CONTROL_ROOT"
        # The Framework helper enforces containment below this root.  Bind the
        # root itself to the harness-verified storage boundary before any
        # helper control or evidence file is opened.
        set -- "$@" \
            --directory SYNCHRONIZED_UPSTREAM_CONTROL_ROOT "$SYNCHRONIZED_UPSTREAM_CONTROL_ROOT"
    fi
    if ! "$@"; then
        blocked "NGINX generated paths are outside verified runtime storage"
    fi

    if [ "$CURRENT_UID" = "0" ]; then
        chown root:root "$NGINX_HARNESS_PARENT"
        chmod 711 "$NGINX_HARNESS_PARENT"
    fi
    NGINX_PATHS_VALIDATED=1
}

validate_nginx_external_projection_authority() {
    [ "$NGINX_DOCROOT_PROJECTION" = "1" ] || return 0
    [ -f "$NGINX_PATH_AUTHORITY_VALIDATOR" ] || \
        blocked "missing NGINX harness path authority validator: $NGINX_PATH_AUTHORITY_VALIDATOR"
    if ! "$PYTHON_BIN" "$NGINX_PATH_AUTHORITY_VALIDATOR" --quiet \
        --verified-run-root "$VERIFIED_RUN_ROOT" \
        --existing-private-directory NGINX_DOCROOT_PROJECTION_PARENT "$NGINX_DOCROOT_PROJECTION_PARENT" \
        --existing-direct-child NGINX_DOCROOT_PROJECTION_ROOT "$NGINX_DOCROOT_PROJECTION_ROOT" "$NGINX_DOCROOT_PROJECTION_PARENT"; then
        blocked "NGINX worker-visible docroot projection is outside authorized runtime storage"
    fi
}

validate_nginx_request_output_path() {
    output_label=$1
    output_path=$2
    case "$output_path" in
        /dev/null)
            return 0
            ;;
        *) ;;
    esac
    if ! "$PYTHON_BIN" "$NGINX_PATH_AUTHORITY_VALIDATOR" --quiet \
        --verified-run-root "$VERIFIED_RUN_ROOT" \
        --path "$output_label" "$output_path"; then
        blocked "$output_label is outside verified runtime storage"
    fi
}

resolve_case_path() {
    item=$1
    "$PYTHON_BIN" "$CASE_CLI" list-cases \
        --repo-root "$REPO_ROOT" \
        --framework-root "$FRAMEWORK_ROOT" \
        --connector-root "$REPO_ROOT" \
        --connector nginx \
        --scope "$CASE_SCOPE" \
        --test-case "$item"
}

list_case_files() {
    if [ -n "$TEST_CASE" ]; then
        "$PYTHON_BIN" "$CASE_CLI" list-cases \
            --repo-root "$REPO_ROOT" \
            --framework-root "$FRAMEWORK_ROOT" \
            --connector-root "$REPO_ROOT" \
            --connector nginx \
            --scope "$CASE_SCOPE" \
            --test-case "$TEST_CASE"
        return
    fi
    if [ -n "$SMOKE_CASES" ]; then
        "$PYTHON_BIN" "$CASE_CLI" list-cases \
            --repo-root "$REPO_ROOT" \
            --framework-root "$FRAMEWORK_ROOT" \
            --connector-root "$REPO_ROOT" \
            --connector nginx \
            --scope "$CASE_SCOPE" \
            --smoke-cases "$SMOKE_CASES"
        return
    fi
    "$PYTHON_BIN" "$CASE_CLI" list-cases \
        --repo-root "$REPO_ROOT" \
        --framework-root "$FRAMEWORK_ROOT" \
        --connector-root "$REPO_ROOT" \
        --connector nginx \
        --scope "$CASE_SCOPE"
}

append_smoke_case() {
    fixture=$1
    case " $SMOKE_CASES " in
        *" $fixture "*|*" $fixture.yaml "*) return 0 ;;
    esac
    SMOKE_CASES="${SMOKE_CASES}${SMOKE_CASES:+ }$fixture"
}

append_selected_phase4_fixtures() {
    # The canonical catalog remains connector-neutral.  NGINX maps only its
    # real, post-header safe/strict host paths to dedicated fixtures, whose
    # YAML names are the canonical case IDs.  Never synthesize a pre-commit
    # result from this body-filter path.
    case "${NO_CRS_BASELINE:-}" in
        1|true|TRUE|yes|YES|on|ON) ;;
        *) return 0 ;;
    esac
    [ "$RUN_ONE_CASE" != "1" ] || return 0
    [ -n "$NO_CRS_SELECTED_CASE_IDS" ] || return 0

    set -f
    for case_id in $NO_CRS_SELECTED_CASE_IDS; do
        case "$case_id" in
            phase4_deny_after_commit_log_only)
                append_smoke_case nginx_phase4_deny_after_commit_log_only
                ;;
            phase4_deny_after_commit_abort)
                append_smoke_case nginx_phase4_deny_after_commit_abort
                ;;
            *[!A-Za-z0-9_]*|"")
                set +f
                blocked "unsafe canonical case id: $case_id"
                ;;
            *)
                # Other canonical IDs either have a catalog-owned runner
                # fixture or are derived from the real safe/strict events.
                ;;
        esac
    done
    set +f
}

write_case_result() {
    case_path=$1
    case_status=$2
    actual_status=${3:-}
    output=$4
    observed_transport=${5:-http_status}
    reason=${6:-}
    output_dir=$(dirname "$output")
    set -- "$PYTHON_BIN" "$CASE_CLI" case-info \
        --case "$case_path" --connector nginx \
        --status "$case_status" --observed-transport-result "$observed_transport" \
        --reason "$reason" --response-body-file "$output_dir/response-body.txt" \
        --audit-log-file "${AUDIT_LOG_FILE:-$output_dir/audit.log}" \
        --access-log-file "$output_dir/access.log" --error-log-file "$output_dir/error.log" \
        --phase4-log-file "$output_dir/phase4.log" \
        --capture-request-log "$output_dir/phase4.log" \
        --capture-request-window "$output_dir/request-window.json" \
        --run-id "$RESULT_RUN_ID" --source-revision "$CONNECTOR_REVISION" \
        --output-root "$output_dir" --output "$output"
    if [ -n "$actual_status" ]; then
        set -- "$@" --actual-status "$actual_status"
    fi
    "$@"
}

require_bounded_positive_decimal() {
    bounded_value=$1
    bounded_label=$2
    bounded_maximum=$3
    case "$bounded_value" in
        ""|0|0*|*[!0-9]*)
            fail "$bounded_label must be a positive decimal value"
            ;;
        *) ;;
    esac
    if [ "${#bounded_value}" -gt 3 ] || [ "$bounded_value" -gt "$bounded_maximum" ]; then
        fail "$bounded_label must be a positive decimal value no greater than $bounded_maximum"
    fi
}

soak_category_for_case() {
    soak_case=$1
    case "$soak_case" in
        allow_without_marker) printf '%s\n' benign_get ;;
        phase2_body_limits) printf '%s\n' benign_post ;;
        phase2_args_block) printf '%s\n' uri_args_attack ;;
        phase1_header_block) printf '%s\n' header_attack ;;
        request_body_urlencoded_block) printf '%s\n' body_attack ;;
        phase3_redirect_before_commit) printf '%s\n' response_header_redirect ;;
        nginx_phase4_deny_after_commit_log_only) printf '%s\n' phase4_safe ;;
        nginx_phase4_deny_after_commit_abort) printf '%s\n' phase4_strict ;;
        *) printf '%s\n' custom_case ;;
    esac
}

soak_case_selection_status() {
    selected_soak_case=$1
    case " $NGINX_SOAK_CASES " in
        *" $selected_soak_case "*) printf '%s\n' selected ;;
        *) printf '%s\n' not_applicable ;;
    esac
}

write_bounded_soak_category_selection() {
    NGINX_SOAK_CATEGORY_SUMMARY_FILE="$LOG_DIR/nginx-bounded-soak-categories.txt"
    : > "$NGINX_SOAK_CATEGORY_SUMMARY_FILE"
    printf 'stage=%s\n' "$MSCONNECTOR_SMOKE_STAGE_BOUNDED_SOAK" >> "$NGINX_SOAK_CATEGORY_SUMMARY_FILE"
    for soak_case in \
        allow_without_marker \
        phase2_body_limits \
        phase2_args_block \
        phase1_header_block \
        request_body_urlencoded_block \
        phase3_redirect_before_commit \
        nginx_phase4_deny_after_commit_log_only \
        nginx_phase4_deny_after_commit_abort
    do
        printf 'category=%s case=%s selection=%s\n' \
            "$(soak_category_for_case "$soak_case")" \
            "$soak_case" \
            "$(soak_case_selection_status "$soak_case")" >> "$NGINX_SOAK_CATEGORY_SUMMARY_FILE"
    done
    # This stage is intentionally H1-only.  It does not turn a repeated H1
    # request into HTTP/2 or HTTP/3 evidence.
    printf '%s\n' 'category=modern_transport status=not_applicable reason=h1_only_bounded_soak' \
        >> "$NGINX_SOAK_CATEGORY_SUMMARY_FILE"
}

write_bounded_soak_category_result() {
    soak_case=$1
    soak_result=$2
    case "$soak_result" in
        not_executable) soak_result=not_applicable ;;
        *) ;;
    esac
    printf 'category=%s case=%s result=%s\n' \
        "$(soak_category_for_case "$soak_case")" \
        "$soak_case" \
        "$soak_result" >> "$NGINX_SOAK_CATEGORY_SUMMARY_FILE"
}

prepare_bounded_soak_selection() {
    [ "$MSCONNECTOR_SMOKE_STAGE" = "$MSCONNECTOR_SMOKE_STAGE_BOUNDED_SOAK" ] || return 0
    case "$NGINX_SOAK_CASES" in
        *[!A-Za-z0-9_.\ -]*|'')
            fail "NGINX_SOAK_CASES must contain only space-separated canonical case ids"
            ;;
        *) ;;
    esac
    soak_case_count=0
    soak_seen_case_ids=" "
    for soak_case in $NGINX_SOAK_CASES; do
        soak_case_count=$((soak_case_count + 1))
        if [ "$soak_case_count" -gt "$NGINX_SOAK_MAX_CASES" ]; then
            fail "NGINX_SOAK_CASES permits at most $NGINX_SOAK_MAX_CASES canonical case ids"
        fi
        case "$soak_case" in
            allow_without_marker|phase2_body_limits|phase2_args_block|phase1_header_block|request_body_urlencoded_block|phase3_redirect_before_commit|nginx_phase4_deny_after_commit_log_only|nginx_phase4_deny_after_commit_abort)
                ;;
            *)
                fail "NGINX_SOAK_CASES may select only the bounded canonical case set"
                ;;
        esac
        case "$soak_seen_case_ids" in
            *" $soak_case "*)
                fail "NGINX_SOAK_CASES must not repeat canonical case ids"
                ;;
            *)
                soak_seen_case_ids="${soak_seen_case_ids}${soak_case} "
                ;;
        esac
    done
    [ "$soak_case_count" -gt 0 ] || \
        fail "NGINX_SOAK_CASES must select at least one canonical case id"
    if [ "$NGINX_MEMCHECK" = "1" ]; then
        case "$NGINX_SOAK_CASES" in
            *' '*|'')
                fail "NGINX_MEMCHECK=1 requires exactly one canonical NGINX_SOAK_CASES id"
                ;;
            *) ;;
        esac
    fi
    if [ "$RUN_ONE_CASE" != "1" ]; then
        TEST_CASE=
        SMOKE_CASES=$NGINX_SOAK_CASES
        # The bounded default deliberately includes canonical no-CRS fixtures
        # and selected non-default lifecycle fixtures.  The existing case CLI
        # still resolves every item in the connector's scoped catalog.
        FORCE_ALL_CASES=1
        NO_CRS_BASELINE=1
        export FORCE_ALL_CASES NO_CRS_BASELINE
    fi
    if [ -z "$MODSECURITY_RULE_PREAMBLE_FILE" ] && [ "$MODSECURITY_TEST_VARIANT" != "with-crs" ]; then
        MODSECURITY_RULE_PREAMBLE_FILE="$FRAMEWORK_ROOT/tests/rules/no-crs-baseline.conf"
        [ -f "$MODSECURITY_RULE_PREAMBLE_FILE" ] || \
            blocked "missing canonical no-CRS rules preamble: $MODSECURITY_RULE_PREAMBLE_FILE"
    fi
}

run_all_cases() {
    # Validate the caller's exact namespace seed before deriving fresh sibling
    # children. Only the projection helper creates each selected child.
    validate_nginx_docroot_projection_mode
    validate_nginx_external_projection_authority
    require_absolute_generated_path "$BUILD_ROOT" "BUILD_ROOT"
    require_absolute_generated_path "$LOG_DIR" "LOG_DIR"
    require_absolute_generated_path "$RESULTS_DIR" "RESULTS_DIR"
    require_absolute_generated_path "$RUNTIME_BASE" "RUNTIME_BASE"

    mkdir -p "$LOG_DIR" "$RESULTS_DIR"
    summary_file="$RESULTS_DIR/nginx-summary.txt"
    json_file="$RESULTS_DIR/nginx-summary.json"
    results_jsonl="$RESULTS_DIR/nginx-results.jsonl"
    connector_summary="$RESULTS_DIR/connector-summary.txt"
    : > "$summary_file"
    : > "$results_jsonl"

    if [ "$MSCONNECTOR_SMOKE_STAGE" = "$MSCONNECTOR_SMOKE_STAGE_BOUNDED_SOAK" ]; then
        write_bounded_soak_category_selection
    fi

    append_selected_phase4_fixtures
    cases=$(list_case_files) || exit 1
    if [ -z "$cases" ]; then
        echo "nginx_smoke: fail no shared smoke cases found" >&2
        exit 1
    fi

    any_fail=0
    any_blocked=0
    any_not_executable=0
    index=0
    for case_path in $cases; do
        case_name=$(basename "$case_path" .yaml)
        case_log_dir="$LOG_DIR/$case_name"
        case_runtime="$RUNTIME_BASE/$case_name"
        case_port=$((BASE_PORT + index))
        case_projection_root=$NGINX_DOCROOT_PROJECTION_ROOT
        if [ "$NGINX_DOCROOT_PROJECTION" = "1" ]; then
            case_projection_root=$("$PYTHON_BIN" -c 'import pathlib, re, sys, uuid; seed = pathlib.Path(sys.argv[1]); re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", seed.name) or sys.exit("unsafe projection root name"); print(seed.with_name("nginx-case-" + uuid.uuid4().hex))' "$NGINX_DOCROOT_PROJECTION_ROOT") || exit 1
        fi
        echo "nginx_smoke: running case=$case_name port=$case_port"
        set +e
        RUN_ONE_CASE=1 \
            TEST_CASE="$case_path" \
            LOG_DIR="$case_log_dir" \
            RUNTIME_ROOT="$case_runtime" \
            NGINX_DOCROOT_PROJECTION_ROOT="$case_projection_root" \
            PORT="$case_port" \
            sh "$0"
        rc=$?
        set -e
        case_status=pass
        case_status_upper=PASS
        if [ "$rc" -eq 77 ]; then
            case_status=blocked
            case_status_upper=BLOCKED
            any_blocked=1
        elif [ "$rc" -eq 78 ]; then
            case_status=not_executable
            case_status_upper=NOT_EXECUTABLE
            any_not_executable=1
        elif [ "$rc" -ne 0 ]; then
            case_status=fail
            case_status_upper=FAIL
            any_fail=1
        fi
        if [ "$MSCONNECTOR_SMOKE_STAGE" = "$MSCONNECTOR_SMOKE_STAGE_BOUNDED_SOAK" ]; then
            write_bounded_soak_category_result "$case_name" "$case_status"
        fi
        actual_status=""
        if [ -f "$case_log_dir/observed-status.txt" ]; then
            actual_status=$(cat "$case_log_dir/observed-status.txt")
        fi
        observed_transport=http_status
        if [ -f "$case_log_dir/observed-transport-result.txt" ]; then
            observed_transport=$(cat "$case_log_dir/observed-transport-result.txt")
        fi
        reason=""
        if [ -f "$case_log_dir/status.txt" ]; then
            reason=$(tail -n 1 "$case_log_dir/status.txt")
        fi
        write_case_result "$case_path" "$case_status" "$actual_status" "$case_log_dir/result.json" "$observed_transport" "$reason" || exit 1
        [ -s "$case_log_dir/result.json" ] || { echo "nginx_smoke: missing required result for $case_name" >&2; exit 1; }
        cat "$case_log_dir/result.json" >> "$results_jsonl"
        echo "$case_status_upper $case_name" | tee -a "$summary_file"
        index=$((index + 1))
    done

    set --
    for case_path in $cases; do
        set -- "$@" --expected-case "$(basename "$case_path" .yaml)"
    done
    "$PYTHON_BIN" "$CASE_CLI" summarize-results "$@" \
        --connector nginx \
        --input-jsonl "$results_jsonl" \
        --summary-json "$json_file" \
        --summary-text "$summary_file" \
        --import-status-file "$TEST_ROOT/connector_suite/config/testing/import-status.json" \
        --connector-path real-world \
        --validation-mode real-world-connector-path \
        --server nginx \
        --server-binary "$NGINX_BINARY" \
        --module "$NGINX_MODULE" \
        --libmodsecurity "$MODSECURITY_RUNTIME_LIBRARY" \
        --origin-source "$CONNECTOR_ORIGIN_SOURCE" \
        --origin-source-repo "$CONNECTOR_ORIGIN_SOURCE_REPO" \
        --origin-source-url "$CONNECTOR_ORIGIN_SOURCE_URL" \
        --origin-source-commit "$CONNECTOR_ORIGIN_SOURCE_COMMIT" \
        --origin-source-version "$CONNECTOR_ORIGIN_SOURCE_VERSION" \
        --origin-license "$CONNECTOR_ORIGIN_LICENSE" \
        --origin-imported-path "$CONNECTOR_ORIGIN_IMPORTED_PATH" \
        --runtime-mode "$([ -n "${FORCE_ALL_CASES:-}" ] && printf force-all || printf default)" \
        --command "$([ -n "${FORCE_ALL_CASES:-}" ] && printf 'FORCE_ALL_CASES=1 make smoke-nginx' || printf 'make smoke-nginx')" \
        --exit-status "$([ "$any_fail" -ne 0 ] && printf 1 || { [ "$any_blocked" -ne 0 ] && printf 77 || printf 0; })" \
        --per-case-result-root "$LOG_DIR"
    cp "$summary_file" "$connector_summary"

    if [ "$any_fail" -ne 0 ]; then
        exit 1
    fi
    if [ "$any_blocked" -ne 0 ]; then
        exit 77
    fi
    exit 0
}

find_curl() {
    if [ -n "$CURL_BIN" ]; then
        printf '%s\n' "$CURL_BIN"
        return 0
    fi
    command -v curl 2>/dev/null || true
}

find_valgrind() {
    case "$VALGRIND_BIN" in
        "") return 1 ;;
        */*)
            [ -x "$VALGRIND_BIN" ] || return 1
            printf '%s\n' "$VALGRIND_BIN"
            ;;
        *) command -v "$VALGRIND_BIN" 2>/dev/null || true ;;
    esac
}

find_setsid() {
    case "$SETSID_BIN" in
        "") return 1 ;;
        */*)
            [ -x "$SETSID_BIN" ] || return 1
            printf '%s\n' "$SETSID_BIN"
            ;;
        *) command -v "$SETSID_BIN" 2>/dev/null || true ;;
    esac
}

validate_nginx_memcheck_binary_identity() {
    [ "$NGINX_BINARY" = "$NGINX_MEMCHECK_NGINX_BINARY" ] || \
        fail "NGINX_MEMCHECK=1 requires NGINX_BINARY=$NGINX_MEMCHECK_NGINX_BINARY"
    [ -x "$NGINX_MEMCHECK_NGINX_BINARY" ] || \
        blocked "missing executable canonical NGINX Memcheck binary: $NGINX_MEMCHECK_NGINX_BINARY"
    [ -f "$NGINX_MEMCHECK_NGINX_ARCHIVE" ] || \
        blocked "missing retained NGINX $NGINX_MEMCHECK_EXPECTED_VERSION archive: $NGINX_MEMCHECK_NGINX_ARCHIVE"

    NGINX_MEMCHECK_VERSION_OUTPUT=$("$NGINX_BINARY" -v 2>&1) || \
        fail "cannot determine canonical NGINX Memcheck binary version: $NGINX_BINARY"
    [ "$NGINX_MEMCHECK_VERSION_OUTPUT" = "nginx version: nginx/$NGINX_MEMCHECK_EXPECTED_VERSION" ] || \
        fail "NGINX_MEMCHECK=1 requires nginx/$NGINX_MEMCHECK_EXPECTED_VERSION; got: $NGINX_MEMCHECK_VERSION_OUTPUT"

    command -v sha256sum >/dev/null 2>&1 || \
        blocked "missing sha256sum required to verify retained NGINX Memcheck archive"
    NGINX_MEMCHECK_NGINX_ARCHIVE_CHECKSUM=$(sha256sum "$NGINX_MEMCHECK_NGINX_ARCHIVE") || \
        fail "cannot calculate retained NGINX Memcheck archive SHA-256: $NGINX_MEMCHECK_NGINX_ARCHIVE"
    NGINX_MEMCHECK_NGINX_ARCHIVE_ACTUAL_SHA256=${NGINX_MEMCHECK_NGINX_ARCHIVE_CHECKSUM%% *}
    [ "$NGINX_MEMCHECK_NGINX_ARCHIVE_ACTUAL_SHA256" = "$NGINX_MEMCHECK_NGINX_ARCHIVE_SHA256" ] || \
        fail "retained NGINX Memcheck archive SHA-256 does not match the source-controlled NGINX 1.31.2 digest"
}

validate_nginx_memcheck_mode() {
    case "$NGINX_MEMCHECK" in
        0) return 0 ;;
        1) ;;
        *) fail "NGINX_MEMCHECK must be exactly 0 or 1" ;;
    esac
    [ "$MSCONNECTOR_SMOKE_STAGE" = "$MSCONNECTOR_SMOKE_STAGE_BOUNDED_SOAK" ] || \
        fail "NGINX_MEMCHECK=1 requires MSCONNECTOR_SMOKE_STAGE=bounded_soak"
    [ "$NGINX_PROTOCOL_PROFILE" = "h1" ] || \
        fail "NGINX_MEMCHECK=1 requires NGINX_PROTOCOL_PROFILE=h1"
    [ "$NGINX_DOWNSTREAM_PROTOCOL" = "http1" ] || \
        fail "NGINX_MEMCHECK=1 requires NGINX_DOWNSTREAM_PROTOCOL=http1"
    [ "$NGINX_UPSTREAM_PROTOCOL" = "http1" ] || \
        fail "NGINX_MEMCHECK=1 requires NGINX_UPSTREAM_PROTOCOL=http1"
    nginx_worker_identity_is_verifiable || \
        blocked "NGINX_MEMCHECK=1 requires a distinct verifiable NGINX worker identity"
    validate_nginx_memcheck_binary_identity
    VALGRIND_BIN=$(find_valgrind || true)
    [ -n "$VALGRIND_BIN" ] || \
        blocked "missing executable Valgrind; set VALGRIND_BIN=/path/to/valgrind"
    [ -x "$VALGRIND_BIN" ] || \
        blocked "Valgrind is not executable: $VALGRIND_BIN"
    SETSID_BIN=$(find_setsid || true)
    [ -n "$SETSID_BIN" ] || \
        blocked "missing executable setsid required for contained NGINX Memcheck"
    [ -x "$SETSID_BIN" ] || \
        blocked "setsid is not executable: $SETSID_BIN"
    [ -f "$NGINX_MEMCHECK_SUPPRESSIONS" ] || \
        fail "missing source-controlled NGINX Memcheck suppression file: $NGINX_MEMCHECK_SUPPRESSIONS"
    [ -f "$NGINX_MEMCHECK_SUMMARIZER" ] || \
        fail "missing NGINX Memcheck summarizer: $NGINX_MEMCHECK_SUMMARIZER"
}

validate_nginx_lifecycle_mode() {
    case "$NGINX_LIFECYCLE_ENABLED" in
        0|1) ;;
        *) fail "NGINX_LIFECYCLE_ENABLED must be exactly 0 or 1" ;;
    esac
    case "$NGINX_LIFECYCLE_TIMEOUT_SECONDS" in
        ''|0|*[!0-9]*) fail "NGINX_LIFECYCLE_TIMEOUT_SECONDS must be a positive decimal value" ;;
        *) ;;
    esac
    if [ "$NGINX_LIFECYCLE_ENABLED" = "0" ] && [ "$MSCONNECTOR_SMOKE_STAGE" != "config_load" ]; then
        fail "normal NGINX smoke requires lifecycle enabled"
    fi
    if [ "$NGINX_LIFECYCLE_ENABLED" = "1" ] && [ "$NGINX_MEMCHECK" = "1" ]; then
        # The Valgrind path has its own isolated wrapper/process-group proof;
        # it is never promoted as normal master/worker evidence.
        write_harness_status info "normal master/worker lifecycle proof disabled for opt-in Memcheck mode"
    fi
}

validate_nginx_protocol_request() {
    nginx_protocol_profile_valid "$NGINX_PROTOCOL_PROFILE" || \
        blocked "unsupported NGINX_PROTOCOL_PROFILE=$NGINX_PROTOCOL_PROFILE; expected h1, h1-h2, or h1-h2-h3-quic"
    case "$NGINX_DOWNSTREAM_PROTOCOL" in
        http1|h2|h3) ;;
        *) blocked "unsupported NGINX_DOWNSTREAM_PROTOCOL=$NGINX_DOWNSTREAM_PROTOCOL; expected http1, h2, or h3" ;;
    esac
    case "$NGINX_UPSTREAM_PROTOCOL" in
        http1) ;;
        h2|h2c|h3)
            blocked "NGINX upstream protocol $NGINX_UPSTREAM_PROTOCOL is not implemented by this bounded harness; downstream and upstream protocol evidence remain separate"
            ;;
        *) blocked "unsupported NGINX_UPSTREAM_PROTOCOL=$NGINX_UPSTREAM_PROTOCOL" ;;
    esac
    if [ "$NGINX_DOWNSTREAM_PROTOCOL" = "h2" ] && ! nginx_protocol_profile_has_http2 "$NGINX_PROTOCOL_PROFILE"; then
        blocked "requested h2 downstream requires NGINX_PROTOCOL_PROFILE=h1-h2 or h1-h2-h3-quic"
    fi
    if [ "$NGINX_DOWNSTREAM_PROTOCOL" = "h3" ] && ! nginx_protocol_profile_has_http3 "$NGINX_PROTOCOL_PROFILE"; then
        blocked "requested h3 downstream requires NGINX_PROTOCOL_PROFILE=h1-h2-h3-quic"
    fi
}

nginx_downstream_transport() {
    case "$NGINX_DOWNSTREAM_PROTOCOL" in
        http1) printf '%s\n' tcp ;;
        h2) printf '%s\n' tls_tcp ;;
        h3) printf '%s\n' quic_udp ;;
        *) blocked "unsupported NGINX_DOWNSTREAM_PROTOCOL=$NGINX_DOWNSTREAM_PROTOCOL" ;;
    esac
}

verify_nginx_protocol_build() {
    version_log="$LOG_DIR/nginx-version.log"
    case "$NGINX_PROTOCOL_PROFILE" in
        h1)
            return 0
            ;;
        h1-h2)
            required_flags='--with-http_ssl_module --with-http_v2_module'
            ;;
        h1-h2-h3-quic)
            required_flags='--with-http_ssl_module --with-http_v2_module --with-http_v3_module'
            ;;
        *) blocked "unsupported NGINX_PROTOCOL_PROFILE=$NGINX_PROTOCOL_PROFILE" ;;
    esac
    for required_flag in $required_flags; do
        grep -F -- "$required_flag" "$version_log" >/dev/null 2>&1 || \
            blocked "NGINX -V lacks required $NGINX_PROTOCOL_PROFILE build flag $required_flag; see $version_log"
    done
    if nginx_protocol_profile_has_http3 "$NGINX_PROTOCOL_PROFILE" && \
        ! grep -F -- '--with-openssl=' "$version_log" >/dev/null 2>&1; then
        blocked "NGINX -V lacks a pinned --with-openssl source binding for the requested H3 profile; see $version_log"
    fi
}

record_nginx_protocol_applicability() {
    version_log="$LOG_DIR/nginx-version.log"
    applicability_file="$LOG_DIR/nginx-protocol-applicability.json"
    legacy_http2_file="$LOG_DIR/nginx-http2-applicability.json"

    if ! "$NGINX_BINARY" -V > "$version_log" 2>&1; then
        blocked "NGINX host probe failed: $NGINX_BINARY -V; see $version_log"
    fi

    "$PYTHON_BIN" - "$version_log" "$applicability_file" "$legacy_http2_file" "$NGINX_BINARY" \
        "$NGINX_PROTOCOL_PROFILE" "$NGINX_DOWNSTREAM_PROTOCOL" "$NGINX_UPSTREAM_PROTOCOL" "$(nginx_downstream_transport)" "$PORT" <<'PY'
import json
import sys
from pathlib import Path

version_log = Path(sys.argv[1])
output = Path(sys.argv[2])
legacy_output = Path(sys.argv[3])
binary, profile, downstream, upstream, transport, port_text = sys.argv[4:]
port = int(port_text)
configure_output = version_log.read_text(encoding="utf-8", errors="replace")
flags = {
    "http_ssl": "--with-http_ssl_module" in configure_output,
    "http2": "--with-http_v2_module" in configure_output,
    "http3": "--with-http_v3_module" in configure_output,
    "pinned_tls_source": "--with-openssl=" in configure_output,
}

def applicability(protocol: str, flag: bool, selected: bool) -> dict[str, object]:
    if not flag:
        return {
            "status": "NOT_APPLICABLE",
            "reason": f"nginx -V lacks the {protocol} module required by this host build",
        }
    if not selected:
        return {
            "status": "NOT_EXECUTED",
            "reason": f"{protocol} is build-capable, but this invocation selected {downstream} downstream traffic",
        }
    return {
        "status": "NOT_EXECUTED",
        "reason": f"{protocol} listener/client path was selected, but no negotiated client observation has been recorded yet",
    }

payload = {
    "evidence_origin": "real_host_build",
    "nginx_binary": binary,
    "nginx_v_log": str(version_log),
    "protocol_profile": profile,
    "downstream_protocol": downstream,
    "upstream_protocol": upstream,
    "transport": transport,
    "integration_mode": "nginx_module",
    "http_ssl_configure_flag": flags["http_ssl"],
    "http2_configure_flag": flags["http2"],
    "http3_configure_flag": flags["http3"],
    "pinned_tls_source_configure_arg": flags["pinned_tls_source"],
    "http2": applicability("HTTP/2", flags["http2"], downstream == "h2"),
    "http3": applicability("HTTP/3", flags["http3"], downstream == "h3"),
    # TCP and UDP use the same numeric port for the H3 profile, but remain
    # separate listener facts.  Neither fact is negotiated-runtime evidence.
    "tcp_listener": {
        "configured": downstream in {"h2", "h3"},
        "transport": "tls_tcp" if downstream in {"h2", "h3"} else "tcp",
        "port": port,
    },
    "udp_listener": {
        "configured": downstream == "h3" and flags["http3"],
        "transport": "quic_udp",
        "port": port,
    },
    "http3_0rtt": {
        "status": "NOT_EXECUTED",
        "reason": "0-RTT is outside the first H3 milestone and has no replay/body transaction contract.",
    },
    "runtime_evidence_recorded": False,
    "reason": "Build flags and a rendered listener are not negotiated protocol or connector lifecycle evidence.",
}
output.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")

# Preserve the prior single-protocol artifact for consumers that have not yet
# adopted the bounded H2/H3 applicability document.
legacy = {
    "evidence_origin": payload["evidence_origin"],
    "nginx_binary": binary,
    "nginx_v_log": str(version_log),
    "http2_configure_flag": flags["http2"],
    "status": payload["http2"]["status"],
    "reason": payload["http2"]["reason"],
}
legacy_output.write_text(json.dumps(legacy, sort_keys=True) + "\n", encoding="utf-8")
PY
}

escape_sed() {
    raw_value=$1
    printf '%s' "$raw_value" | sed 's/[&|]/\\&/g'
}

generate_protocol_tls_material() {
    [ "$NGINX_DOWNSTREAM_PROTOCOL" != "http1" ] || return 0
    command -v openssl >/dev/null 2>&1 || \
        blocked "missing openssl required to create an ephemeral local TLS certificate for $NGINX_DOWNSTREAM_PROTOCOL"
    umask 077
    if ! openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
        -subj '/CN=ModSecurity local test CA' \
        -keyout "$NGINX_TLS_CA_KEY" \
        -out "$NGINX_TLS_CA_CERT" > "$LOG_DIR/tls-certificate-generation.log" 2>&1 || \
        ! openssl req -new -newkey rsa:2048 -nodes \
        -subj '/CN=localhost' \
        -keyout "$NGINX_TLS_SERVER_KEY" \
        -out "$NGINX_TLS_SERVER_CSR" >> "$LOG_DIR/tls-certificate-generation.log" 2>&1 || \
        ! printf '%s\n' \
            'basicConstraints=CA:FALSE' \
            'keyUsage=digitalSignature,keyEncipherment' \
            'extendedKeyUsage=serverAuth' \
            'subjectAltName=DNS:localhost,IP:127.0.0.1' \
            > "$NGINX_TLS_SERVER_EXT" || \
        ! openssl x509 -req -days 1 -sha256 \
            -in "$NGINX_TLS_SERVER_CSR" \
            -CA "$NGINX_TLS_CA_CERT" -CAkey "$NGINX_TLS_CA_KEY" -CAcreateserial \
            -out "$NGINX_TLS_SERVER_CERT" -extfile "$NGINX_TLS_SERVER_EXT" \
            >> "$LOG_DIR/tls-certificate-generation.log" 2>&1; then
        blocked "could not create ephemeral local CA and short-lived leaf certificate; see $LOG_DIR/tls-certificate-generation.log"
    fi
    chmod 600 "$NGINX_TLS_CA_KEY" "$NGINX_TLS_SERVER_KEY"
    chmod 644 "$NGINX_TLS_CA_CERT" "$NGINX_TLS_SERVER_CERT"
}

write_nginx_protocol_directives() {
    : > "$NGINX_PROTOCOL_LISTEN_DIRECTIVES_FILE"
    : > "$NGINX_PROTOCOL_SERVER_DIRECTIVES_FILE"
    case "$NGINX_DOWNSTREAM_PROTOCOL" in
        http1)
            printf 'listen 127.0.0.1:%s;\n' "$PORT" > "$NGINX_PROTOCOL_LISTEN_DIRECTIVES_FILE"
            ;;
        h2)
            generate_protocol_tls_material
            printf 'listen 127.0.0.1:%s ssl;\n' "$PORT" > "$NGINX_PROTOCOL_LISTEN_DIRECTIVES_FILE"
            {
                printf 'ssl_certificate "%s";\n' "$NGINX_TLS_SERVER_CERT"
                printf 'ssl_certificate_key "%s";\n' "$NGINX_TLS_SERVER_KEY"
                echo 'ssl_protocols TLSv1.2 TLSv1.3;'
                echo 'http2 on;'
            } > "$NGINX_PROTOCOL_SERVER_DIRECTIVES_FILE"
            ;;
        h3)
            generate_protocol_tls_material
            {
                printf 'listen 127.0.0.1:%s ssl;\n' "$PORT"
                printf 'listen 127.0.0.1:%s quic reuseport;\n' "$PORT"
            } > "$NGINX_PROTOCOL_LISTEN_DIRECTIVES_FILE"
            {
                printf 'ssl_certificate "%s";\n' "$NGINX_TLS_SERVER_CERT"
                printf 'ssl_certificate_key "%s";\n' "$NGINX_TLS_SERVER_KEY"
                echo 'ssl_protocols TLSv1.2 TLSv1.3;'
                echo 'http2 on;'
                echo 'http3 on;'
                printf 'add_header Alt-Svc '\''h3=":%s"; ma=60'\'' always;\n' "$PORT"
            } > "$NGINX_PROTOCOL_SERVER_DIRECTIVES_FILE"
            ;;
        *) blocked "unsupported NGINX_DOWNSTREAM_PROTOCOL=$NGINX_DOWNSTREAM_PROTOCOL" ;;
    esac
}

create_fresh_phase4_regular_file() {
    phase4_target=$1
    if ! (set -C; : > "$phase4_target"); then
        fail "phase4 test target must be a fresh regular file: $phase4_target"
    fi
}

prepare_phase4_log_target() {
    NGINX_PHASE4_LOG_FILE="$LOG_DIR/phase4.log"
    NGINX_PHASE4_LOG_SERVER_FILE="$LOG_DIR/phase4-server.log"
    case "$NGINX_PHASE4_LOG_TARGET_MODE" in
        regular)
            ;;
        existing_regular_0644)
            create_fresh_phase4_regular_file "$NGINX_PHASE4_LOG_FILE"
            chmod 644 "$NGINX_PHASE4_LOG_FILE"
            ;;
        unsafe_symlink)
            phase4_symlink_target="$LOG_DIR/phase4-symlink-target.log"
            create_fresh_phase4_regular_file "$phase4_symlink_target"
            chmod 600 "$phase4_symlink_target"
            ln -s "$phase4_symlink_target" "$NGINX_PHASE4_LOG_FILE" || \
                fail "could not create phase4 symlink rejection target"
            ;;
        unsafe_fifo)
            mkfifo "$NGINX_PHASE4_LOG_FILE" || \
                fail "could not create phase4 FIFO rejection target"
            ;;
        unsafe_directory)
            mkdir "$NGINX_PHASE4_LOG_FILE" || \
                fail "could not create phase4 directory rejection target"
            ;;
        unsafe_writable_parent)
            phase4_writable_parent="$LOG_DIR/phase4-writable-parent"
            mkdir "$phase4_writable_parent" || \
                fail "could not create writable-parent rejection directory"
            chmod 770 "$phase4_writable_parent"
            NGINX_PHASE4_LOG_FILE="$phase4_writable_parent/phase4.log"
            ;;
        unsafe_wrong_owner)
            [ "$CURRENT_UID" = "0" ] || \
                blocked "unsafe_wrong_owner phase4 fixture requires root"
            create_fresh_phase4_regular_file "$NGINX_PHASE4_LOG_FILE"
            chmod 600 "$NGINX_PHASE4_LOG_FILE"
            chown "$NGINX_WORKER_USER" "$NGINX_PHASE4_LOG_FILE" || \
                fail "could not create wrong-owner phase4 rejection target"
            ;;
        *)
            blocked "unsupported NGINX_PHASE4_LOG_TARGET_MODE=$NGINX_PHASE4_LOG_TARGET_MODE"
            ;;
    esac
}

phase4_reload_overlap_sync_enabled() {
    [ "$NGINX_HOSTED_FUNCTIONAL_A" = "1" ] && \
        [ "$NGINX_PHASE4_LOG_LIFECYCLE_PROBE" = "1" ]
}

apply_synchronized_phase4_policy() {
    case "$MSCONNECTOR_FULL_LIFECYCLE_SYNC:$NGINX_TRUSTED_SYNCHRONIZED_PHASE4_MODE" in
        1:safe)
            NGINX_PHASE4_MODE=$NGINX_TRUSTED_SYNCHRONIZED_PHASE4_MODE
            ;;
        0:)
            # Ordinary smoke cases retain their generated mode and default Off.
            ;;
        1:*)
            blocked "synchronized First-Byte proof requires NGINX_SYNCHRONIZED_PHASE4_MODE=safe"
            ;;
        *)
            blocked "NGINX_SYNCHRONIZED_PHASE4_MODE is only valid for synchronized First-Byte proof"
            ;;
    esac
}

render_config() {
    NGINX_PHASE4_MODE_DIRECTIVE=""
    NGINX_PHASE4_LOG_SERVER_DIRECTIVE=""
    NGINX_PHASE4_LOG_LOCATION_DIRECTIVE=""
    NGINX_USE_ERROR_LOG_DIRECTIVE="modsecurity_use_error_log on;"
    case "${NGINX_USE_ERROR_LOG:-on}" in
        on) NGINX_USE_ERROR_LOG_DIRECTIVE="modsecurity_use_error_log on;" ;;
        off) NGINX_USE_ERROR_LOG_DIRECTIVE="modsecurity_use_error_log off;" ;;
        *) fail "unsupported NGINX_USE_ERROR_LOG=${NGINX_USE_ERROR_LOG}" ;;
    esac
    NGINX_WORKER_USER_DIRECTIVE=""
    if [ "$CURRENT_UID" = "0" ]; then
        resolve_nginx_worker_identity
        NGINX_WORKER_USER_DIRECTIVE="user $NGINX_WORKER_RESOLVED_USER $NGINX_WORKER_RESOLVED_GROUP;"
    fi
    # Each smoke fixture starts an independent NGINX process.  Scope the
    # native complex-value transaction ID to that fixture so distinct real
    # P4 transactions cannot reuse the host's fresh connection counter.
    NGINX_TRANSACTION_ID_DIRECTIVE="modsecurity_transaction_id nginx-${case_name}-\$connection-\$connection_requests;"
    case "${NGINX_PHASE4_MODE:-}" in
        "") ;;
        off|safe|strict)
            NGINX_PHASE4_MODE_DIRECTIVE="modsecurity_phase4_mode $NGINX_PHASE4_MODE;"
            ;;
        *)
            fail "unsupported generated NGINX_PHASE4_MODE=$NGINX_PHASE4_MODE"
            ;;
    esac
    case "$NGINX_PHASE4_LOG_SCOPE" in
        location)
            # Connector-specific Framework cases own their one location
            # directive through the generated include below.
            ;;
        location_if_missing)
            # Generic no-CRS cases need the same case-local native sink that
            # connector-specific fixtures already provide in their include.
            [ -r "$NGINX_LOCATION_DIRECTIVES_FILE" ] || \
                fail "missing generated NGINX location directives"
            if ! grep -Eq '^[[:space:]]*modsecurity_phase4_log[[:space:]]' \
                "$NGINX_LOCATION_DIRECTIVES_FILE"; then
                NGINX_PHASE4_LOG_LOCATION_DIRECTIVE="modsecurity_phase4_log \"$NGINX_PHASE4_LOG_FILE\";"
            fi
            ;;
        server)
            NGINX_PHASE4_LOG_SERVER_DIRECTIVE="modsecurity_phase4_log \"$NGINX_PHASE4_LOG_SERVER_FILE\";"
            ;;
        server_with_location_override)
            NGINX_PHASE4_LOG_SERVER_DIRECTIVE="modsecurity_phase4_log \"$NGINX_PHASE4_LOG_SERVER_FILE\";"
            NGINX_PHASE4_LOG_LOCATION_DIRECTIVE="modsecurity_phase4_log \"$NGINX_PHASE4_LOG_FILE\";"
            ;;
        *)
            blocked "unsupported NGINX_PHASE4_LOG_SCOPE=$NGINX_PHASE4_LOG_SCOPE"
            ;;
    esac
    sed \
        -e "s|@@RUNTIME_ROOT@@|$(escape_sed "$RUNTIME_ROOT")|g" \
        -e "s|@@NGINX_WORKER_STATE_ROOT@@|$(escape_sed "$NGINX_WORKER_STATE_ROOT")|g" \
        -e "s|@@NGINX_SERVER_LOG_ROOT@@|$(escape_sed "$NGINX_SERVER_LOG_ROOT")|g" \
        -e "s|@@LOG_DIR@@|$(escape_sed "$LOG_DIR")|g" \
        -e "s|@@PORT@@|$(escape_sed "$PORT")|g" \
        -e "s|@@NGINX_MODULE@@|$(escape_sed "$NGINX_MODULE")|g" \
        -e "s|@@NGINX_USE_ERROR_LOG_DIRECTIVE@@|$(escape_sed "$NGINX_USE_ERROR_LOG_DIRECTIVE")|g" \
        -e "s|@@DOCROOT@@|$(escape_sed "$DOCROOT")|g" \
        -e "s|@@RULES_FILE@@|$(escape_sed "$RULES_FILE")|g" \
        -e "s|@@NGINX_PHASE4_LOG@@|$(escape_sed "$NGINX_PHASE4_LOG_FILE")|g" \
        -e "s|@@NGINX_PHASE4_LOG_SERVER_DIRECTIVE@@|$(escape_sed "$NGINX_PHASE4_LOG_SERVER_DIRECTIVE")|g" \
        -e "s|@@NGINX_PHASE4_LOG_LOCATION_DIRECTIVE@@|$(escape_sed "$NGINX_PHASE4_LOG_LOCATION_DIRECTIVE")|g" \
        -e "s|@@NGINX_PHASE4_RELOAD_OVERLAP_DIRECTIVES@@|$(escape_sed "$NGINX_PHASE4_RELOAD_OVERLAP_DIRECTIVES_FILE")|g" \
        -e "s|@@NGINX_WORKER_USER_DIRECTIVE@@|$(escape_sed "$NGINX_WORKER_USER_DIRECTIVE")|g" \
        -e "s|@@NGINX_TRANSACTION_ID_DIRECTIVE@@|$(escape_sed "$NGINX_TRANSACTION_ID_DIRECTIVE")|g" \
        -e "s|@@NGINX_PHASE4_MODE_DIRECTIVE@@|$(escape_sed "$NGINX_PHASE4_MODE_DIRECTIVE")|g" \
        -e "s|@@NGINX_PROTOCOL_LISTEN_DIRECTIVES@@|$(escape_sed "$NGINX_PROTOCOL_LISTEN_DIRECTIVES_FILE")|g" \
        -e "s|@@NGINX_PROTOCOL_SERVER_DIRECTIVES@@|$(escape_sed "$NGINX_PROTOCOL_SERVER_DIRECTIVES_FILE")|g" \
        -e "s|@@NGINX_LOCATION_DIRECTIVES@@|$(escape_sed "$NGINX_LOCATION_DIRECTIVES_FILE")|g" \
        -e "s|@@NGINX_LOCATION_HANDLER_DIRECTIVES@@|$(escape_sed "$NGINX_LOCATION_HANDLER_DIRECTIVES_FILE")|g" \
        "$TEMPLATE" > "$CONFIG_FILE"
}

record_nginx_memcheck_process_group() {
    nginx_memcheck_master_pid=$1
    NGINX_MEMCHECK_PROCESS_GROUP=""
    NGINX_MEMCHECK_CONTAINMENT=unverified
    nginx_memcheck_group=$(ps -o pgid= -p "$nginx_memcheck_master_pid" 2>/dev/null | tr -d "$NGINX_TR_DELETE_WHITESPACE" || true)
    nginx_memcheck_session=$(ps -o sid= -p "$nginx_memcheck_master_pid" 2>/dev/null | tr -d "$NGINX_TR_DELETE_WHITESPACE" || true)
    nginx_memcheck_harness_group=$(ps -o pgid= -p "$$" 2>/dev/null | tr -d "$NGINX_TR_DELETE_WHITESPACE" || true)
    case "$nginx_memcheck_group" in ""|*[!0-9]*) return 0 ;; *) ;; esac
    case "$nginx_memcheck_session" in ""|*[!0-9]*) return 0 ;; *) ;; esac
    case "$nginx_memcheck_harness_group" in ""|*[!0-9]*) return 0 ;; *) ;; esac
    [ "$nginx_memcheck_group" = "$nginx_memcheck_session" ] || return 0
    [ "$nginx_memcheck_group" != "$nginx_memcheck_harness_group" ] || return 0
    NGINX_MEMCHECK_PROCESS_GROUP=$nginx_memcheck_group
    NGINX_MEMCHECK_CONTAINMENT=isolated
}

nginx_memcheck_process_group_alive() {
    [ "$NGINX_MEMCHECK_CONTAINMENT" = "isolated" ] || return 1
    [ -n "$NGINX_MEMCHECK_PROCESS_GROUP" ] || return 1
    kill -0 "-$NGINX_MEMCHECK_PROCESS_GROUP" >/dev/null 2>&1
}

record_nginx_memcheck_roles() {
    [ "$NGINX_MEMCHECK" = "1" ] || return 0
    ( umask 077; : > "$NGINX_MEMCHECK_ROLE_FILE" )
    chmod 600 "$NGINX_MEMCHECK_ROLE_FILE"
    nginx_memcheck_master_pid=$(tr -d "$NGINX_TR_DELETE_WHITESPACE" < "$RUNTIME_PID_FILE" 2>/dev/null || true)
    case "$nginx_memcheck_master_pid" in
        ""|*[!0-9]*) return 0 ;;
        *)
            printf 'master_pid=%s\n' "$nginx_memcheck_master_pid" >> "$NGINX_MEMCHECK_ROLE_FILE"
            # The launch wrapper records its isolated session before readiness
            # so a failed readiness probe can still clean up the exact group.
            # Refresh only when that early snapshot was unavailable.
            if [ "$NGINX_MEMCHECK_CONTAINMENT" != "isolated" ]; then
                record_nginx_memcheck_process_group "$nginx_memcheck_master_pid"
            fi
            ;;
    esac

    nginx_memcheck_role_attempt=0
    while [ "$nginx_memcheck_role_attempt" -lt 10 ]; do
        nginx_memcheck_worker_pids=$(ps -o pid= --ppid "$nginx_memcheck_master_pid" 2>/dev/null || true)
        nginx_memcheck_worker_count=0
        for nginx_memcheck_worker_pid in $nginx_memcheck_worker_pids; do
            case "$nginx_memcheck_worker_pid" in
                ""|*[!0-9]*) continue ;;
                *)
                    printf 'worker_pid=%s\n' "$nginx_memcheck_worker_pid" >> "$NGINX_MEMCHECK_ROLE_FILE"
                    nginx_memcheck_worker_count=$((nginx_memcheck_worker_count + 1))
                    ;;
            esac
        done
        [ "$nginx_memcheck_worker_count" -gt 0 ] && return 0
        nginx_memcheck_role_attempt=$((nginx_memcheck_role_attempt + 1))
        sleep 1
    done
}

signal_nginx_memcheck_processes() {
    nginx_memcheck_signal=$1
    if [ "$NGINX_MEMCHECK_CONTAINMENT" = "isolated" ] && \
       [ -n "$NGINX_MEMCHECK_PROCESS_GROUP" ] && \
       kill "-$nginx_memcheck_signal" "-$NGINX_MEMCHECK_PROCESS_GROUP" >/dev/null 2>&1; then
        return 0
    fi
    kill "-$nginx_memcheck_signal" "$NGINX_PID" >/dev/null 2>&1
}

wait_for_nginx_memcheck_exit() {
    nginx_memcheck_wait_limit=$1
    nginx_memcheck_deadline=$(( $(date +%s) + nginx_memcheck_wait_limit ))
    while :; do
        nginx_memcheck_wrapper_alive=0
        nginx_memcheck_group_alive=0
        if kill -0 "$NGINX_PID" >/dev/null 2>&1; then
            nginx_memcheck_wrapper_alive=1
        fi
        if nginx_memcheck_process_group_alive; then
            nginx_memcheck_group_alive=1
        fi
        [ "$nginx_memcheck_wrapper_alive" -eq 0 ] && \
            [ "$nginx_memcheck_group_alive" -eq 0 ] && break
        nginx_memcheck_now=$(date +%s)
        [ "$nginx_memcheck_now" -lt "$nginx_memcheck_deadline" ] || return 1
        sleep 1
    done
    set +e
    wait "$NGINX_PID"
    NGINX_MEMCHECK_WRAPPER_EXIT_CODE=$?
    set -e
    return 0
}

stop_nginx_memcheck() {
    [ "$NGINX_MEMCHECK" = "1" ] || return 0
    [ -n "${NGINX_PID:-}" ] || return 0

    if ! kill -0 "$NGINX_PID" >/dev/null 2>&1 && ! nginx_memcheck_process_group_alive; then
        NGINX_MEMCHECK_SHUTDOWN=forced
        NGINX_MEMCHECK_WAIT_STATUS=exited
        set +e
        wait "$NGINX_PID"
        NGINX_MEMCHECK_WRAPPER_EXIT_CODE=$?
        set -e
        NGINX_PID=""
        return 0
    fi

    NGINX_MEMCHECK_SHUTDOWN=graceful
    if ! (
        umask 077
        exec "$NGINX_BINARY" -p "$RUNTIME_ROOT" -c "$CONFIG_FILE" -s quit \
            > "$LOG_DIR/nginx-memcheck-quit.log" 2>&1
    ); then
        NGINX_MEMCHECK_SHUTDOWN=forced
    fi
    if wait_for_nginx_memcheck_exit "$NGINX_MEMCHECK_WAIT_SECONDS"; then
        NGINX_MEMCHECK_WAIT_STATUS=exited
        NGINX_PID=""
        return 0
    fi

    # The normal NGINX quit path has already been given its full bounded
    # window.  Signal the isolated task-owned process group so a failed master
    # cannot leave a worker, listener, or diagnostic process behind.
    NGINX_MEMCHECK_SHUTDOWN=forced_term
    signal_nginx_memcheck_processes TERM || true
    if wait_for_nginx_memcheck_exit 5; then
        NGINX_MEMCHECK_WAIT_STATUS=exited
        NGINX_PID=""
        return 0
    fi
    NGINX_MEMCHECK_SHUTDOWN=forced_kill
    signal_nginx_memcheck_processes KILL || true
    if wait_for_nginx_memcheck_exit 5; then
        NGINX_MEMCHECK_WAIT_STATUS=exited
        NGINX_PID=""
        return 0
    fi
    NGINX_MEMCHECK_WAIT_STATUS=timed_out
    NGINX_MEMCHECK_WRAPPER_EXIT_CODE=unknown
    return 1
}

write_nginx_memcheck_lifecycle() {
    [ "$NGINX_MEMCHECK" = "1" ] || return 0
    [ -n "${NGINX_MEMCHECK_LIFECYCLE_FILE:-}" ] || return 0
    (
        umask 077
        {
            printf 'shutdown=%s\n' "$NGINX_MEMCHECK_SHUTDOWN"
            printf 'wait=%s\n' "$NGINX_MEMCHECK_WAIT_STATUS"
            printf 'wrapper_exit_code=%s\n' "$NGINX_MEMCHECK_WRAPPER_EXIT_CODE"
            printf 'containment=%s\n' "$NGINX_MEMCHECK_CONTAINMENT"
        } > "$NGINX_MEMCHECK_LIFECYCLE_FILE"
    )
    chmod 600 "$NGINX_MEMCHECK_LIFECYCLE_FILE"
}

finalize_nginx_memcheck() {
    [ "$NGINX_MEMCHECK" = "1" ] || return 0
    [ "$NGINX_MEMCHECK_STARTED" = "1" ] || return 0
    [ "$NGINX_MEMCHECK_FINALIZED" = "0" ] || return 0

    NGINX_MEMCHECK_FINALIZED=1
    stop_nginx_memcheck || true
    write_nginx_memcheck_lifecycle
    set +e
    "$PYTHON_BIN" "$NGINX_MEMCHECK_SUMMARIZER" \
        --verified-run-root "$VERIFIED_RUN_ROOT" \
        --log-dir "$NGINX_MEMCHECK_EVIDENCE_DIR"
    nginx_memcheck_summary_rc=$?
    set -e
    printf 'memcheck_summary_exit_code=%s\n' "$nginx_memcheck_summary_rc" >> "$STATUS_FILE"
    [ "$nginx_memcheck_summary_rc" -eq 0 ]
}

write_nginx_lifecycle_event() {
    [ "$NGINX_LIFECYCLE_ENABLED" = "1" ] || return 0
    [ -n "${NGINX_LIFECYCLE_FILE:-}" ] || return 0
    printf '%s\n' "$*" >> "$NGINX_LIFECYCLE_FILE"
}

nginx_process_child_snapshot() {
    nginx_snapshot_parent_pid=$1
    # Keep lifecycle decisions restricted to live, direct children of the
    # identity-verified NGINX master.  In particular, a bare PID list cannot
    # distinguish a stale zombie from the worker that is still serving the
    # paused reload-overlap request.
    ps -o pid=,ppid=,stat= --ppid "$nginx_snapshot_parent_pid" 2>/dev/null | \
        awk -v expected_parent="$nginx_snapshot_parent_pid" '
            $1 ~ /^[0-9]+$/ && $2 == expected_parent && $3 !~ /^Z/ {
                print $1, $2, $3
            }
        ' || true
}

nginx_process_children() {
    nginx_children_parent_pid=$1
    nginx_process_child_snapshot "$nginx_children_parent_pid" | awk '{ print $1 }' || true
}

nginx_process_record() {
    nginx_role=$1
    nginx_pid=$2
    nginx_parent_pid=$(ps -o ppid= -p "$nginx_pid" 2>/dev/null | tr -d "$NGINX_TR_DELETE_WHITESPACE" || true)
    nginx_uid=$(ps -o uid= -p "$nginx_pid" 2>/dev/null | tr -d "$NGINX_TR_DELETE_WHITESPACE" || true)
    nginx_gid=$(ps -o gid= -p "$nginx_pid" 2>/dev/null | tr -d "$NGINX_TR_DELETE_WHITESPACE" || true)
    nginx_command=$(ps -o comm= -p "$nginx_pid" 2>/dev/null | tr -d '\n' || true)
    case "$nginx_pid:$nginx_parent_pid:$nginx_uid:$nginx_gid" in
        ''|*[!0-9:]*)
            fail "NGINX $nginx_role process metadata is unavailable for pid=$nginx_pid"
            ;;
        *) : ;;
    esac
    printf 'role=%s pid=%s ppid=%s uid=%s gid=%s command=%s\n' \
        "$nginx_role" "$nginx_pid" "$nginx_parent_pid" "$nginx_uid" "$nginx_gid" "$nginx_command" \
        >> "$NGINX_LIFECYCLE_ROLE_FILE"
}

record_nginx_master_worker_roles() {
    [ "$NGINX_LIFECYCLE_ENABLED" = "1" ] || return 0
    master_pid=$(tr -d "$NGINX_TR_DELETE_WHITESPACE" < "$RUNTIME_PID_FILE" 2>/dev/null || true)
    case "$master_pid" in
        ''|*[!0-9]*) fail "NGINX master pid file does not contain a numeric pid" ;;
        *) : ;;
    esac
    kill -0 "$master_pid" >/dev/null 2>&1 || fail "NGINX master pid=$master_pid is not alive"
    [ "$master_pid" = "$NGINX_PID" ] || \
        fail "NGINX pid file master=$master_pid differs from harness process=$NGINX_PID"
    nginx_process_record master "$master_pid"

    worker_pids=$(nginx_process_children "$master_pid")
    worker_count=$(printf '%s\n' "$worker_pids" | awk 'NF { count += 1 } END { print count + 0 }')
    [ "$worker_count" -eq 1 ] || fail "NGINX master pid=$master_pid has $worker_count direct worker children; expected exactly one"
    worker_pid=$(printf '%s\n' "$worker_pids" | awk 'NR == 1 { print $1 }')
    case "$worker_pid" in
        ''|*[!0-9]*) fail "NGINX master pid=$master_pid has no observable worker child" ;;
        *) : ;;
    esac
    worker_uid=$(ps -o uid= -p "$worker_pid" 2>/dev/null | tr -d "$NGINX_TR_DELETE_WHITESPACE" || true)
    worker_gid=$(ps -o gid= -p "$worker_pid" 2>/dev/null | tr -d "$NGINX_TR_DELETE_WHITESPACE" || true)
    [ "$worker_uid" = "$NGINX_WORKER_RESOLVED_UID" ] || \
        fail "NGINX worker pid=$worker_pid uid=$worker_uid does not match configured uid=$NGINX_WORKER_RESOLVED_UID"
    [ "$worker_uid" != "0" ] || fail "NGINX worker pid=$worker_pid is running as root"
    [ "$worker_gid" = "$NGINX_WORKER_RESOLVED_GID" ] || \
        fail "NGINX worker pid=$worker_pid gid=$worker_gid does not match configured gid=$NGINX_WORKER_RESOLVED_GID"
    nginx_process_record worker "$worker_pid"
    printf '%s\n' "$worker_pid"
}

wait_for_nginx_worker_replacement() {
    old_worker_pid=$1
    attempt=0
    while [ "$attempt" -lt "$NGINX_LIFECYCLE_TIMEOUT_SECONDS" ]; do
        new_worker_pids=$(nginx_process_children "$NGINX_PID")
        new_worker_count=$(printf '%s\n' "$new_worker_pids" | awk 'NF { count += 1 } END { print count + 0 }')
        [ "$new_worker_count" -eq 1 ] || {
            attempt=$((attempt + 1))
            sleep 1
            continue
        }
        new_worker_pid=$(printf '%s\n' "$new_worker_pids" | awk 'NR == 1 { print $1 }')
        case "$new_worker_pid" in
            ''|*[!0-9]*) ;;
            *)
                if [ "$new_worker_pid" != "$old_worker_pid" ] && kill -0 "$new_worker_pid" >/dev/null 2>&1; then
                    printf '%s\n' "$new_worker_pid"
                    return 0
                fi
                ;;
        esac
        attempt=$((attempt + 1))
        sleep 1
    done
    return 1
}

reload_nginx_master_worker() {
    [ "$NGINX_LIFECYCLE_ENABLED" = "1" ] || return 0
    [ "$NGINX_MEMCHECK" = "0" ] || return 0
    NGINX_LIFECYCLE_INITIAL_WORKER=$(record_nginx_master_worker_roles)
    write_nginx_lifecycle_event "phase=before_reload master_pid=$NGINX_PID worker_pid=$NGINX_LIFECYCLE_INITIAL_WORKER"
    if ! "$NGINX_BINARY" -p "$RUNTIME_ROOT" -c "$CONFIG_FILE" -s reload > "$LOG_DIR/nginx-reload.log" 2>&1; then
        fail "NGINX graceful reload command failed; see $LOG_DIR/nginx-reload.log"
    fi
    NGINX_LIFECYCLE_RELOADED_WORKER=$(wait_for_nginx_worker_replacement "$NGINX_LIFECYCLE_INITIAL_WORKER") || \
        fail "NGINX reload did not replace the worker within ${NGINX_LIFECYCLE_TIMEOUT_SECONDS}s"
    NGINX_LIFECYCLE_RELOAD=passed
    record_nginx_master_worker_roles >/dev/null
    write_nginx_lifecycle_event "phase=after_reload master_pid=$NGINX_PID old_worker_pid=$NGINX_LIFECYCLE_INITIAL_WORKER new_worker_pid=$NGINX_LIFECYCLE_RELOADED_WORKER result=passed"
}

wait_for_nginx_exit() {
    wait_limit=$1
    wait_deadline=$(( $(date +%s) + wait_limit ))
    while kill -0 "$NGINX_PID" >/dev/null 2>&1; do
        [ "$(date +%s)" -lt "$wait_deadline" ] || return 1
        sleep 1
    done
    set +e
    wait "$NGINX_PID"
    NGINX_LIFECYCLE_EXIT_STATUS=$?
    set -e
    return 0
}

shutdown_nginx_gracefully() {
    [ "$NGINX_LIFECYCLE_ENABLED" = "1" ] || return 0
    [ "$NGINX_MEMCHECK" = "0" ] || return 0
    [ -n "${NGINX_PID:-}" ] || return 0
    if ! kill -0 "$NGINX_PID" >/dev/null 2>&1; then
        set +e
        wait "$NGINX_PID"
        NGINX_LIFECYCLE_EXIT_STATUS=$?
        set -e
        NGINX_LIFECYCLE_SHUTDOWN=already_exited
        return 0
    fi
    NGINX_LIFECYCLE_SHUTDOWN=graceful_quit
    if ! "$NGINX_BINARY" -p "$RUNTIME_ROOT" -c "$CONFIG_FILE" -s quit > "$LOG_DIR/nginx-quit.log" 2>&1; then
        NGINX_LIFECYCLE_SHUTDOWN=quit_command_failed
    fi
    if ! wait_for_nginx_exit "$NGINX_LIFECYCLE_TIMEOUT_SECONDS"; then
        NGINX_LIFECYCLE_SHUTDOWN=forced_term
        kill -TERM "$NGINX_PID" >/dev/null 2>&1 || true
        wait_for_nginx_exit 5 || {
            NGINX_LIFECYCLE_SHUTDOWN=forced_kill
            kill -KILL "$NGINX_PID" >/dev/null 2>&1 || true
            wait_for_nginx_exit 5 || NGINX_LIFECYCLE_EXIT_STATUS=timeout
        }
    fi
    write_nginx_lifecycle_event "phase=shutdown mode=$NGINX_LIFECYCLE_SHUTDOWN exit_status=$NGINX_LIFECYCLE_EXIT_STATUS"
    [ "$NGINX_LIFECYCLE_EXIT_STATUS" = "0" ] || return 1
}

record_nginx_cleanup_state() {
    [ "$NGINX_LIFECYCLE_ENABLED" = "1" ] || return 0
    nginx_cleanup_check_status=0
    if [ -n "${NGINX_PID:-}" ] && kill -0 "$NGINX_PID" >/dev/null 2>&1; then
        nginx_cleanup_check_status=1
        write_nginx_lifecycle_event "phase=cleanup master_pid=$NGINX_PID result=still_alive"
    else
        write_nginx_lifecycle_event "phase=cleanup master_pid=${NGINX_PID:-none} result=exited"
    fi
    for nginx_tracked_worker_pid in "$NGINX_LIFECYCLE_INITIAL_WORKER" "$NGINX_LIFECYCLE_RELOADED_WORKER"; do
        [ -n "$nginx_tracked_worker_pid" ] || continue
        if kill -0 "$nginx_tracked_worker_pid" >/dev/null 2>&1; then
            nginx_cleanup_check_status=1
            write_nginx_lifecycle_event "phase=cleanup worker_pid=$nginx_tracked_worker_pid result=still_alive"
        else
            write_nginx_lifecycle_event "phase=cleanup worker_pid=$nginx_tracked_worker_pid result=exited"
        fi
    done
    if [ -n "${NGINX_PID:-}" ]; then
        if [ "$NGINX_LIFECYCLE_EXIT_STATUS" = "0" ]; then
            write_nginx_lifecycle_event "phase=cleanup exit_status=0 result=passed"
        else
            nginx_cleanup_check_status=1
            write_nginx_lifecycle_event "phase=cleanup exit_status=$NGINX_LIFECYCLE_EXIT_STATUS result=failed"
        fi
    fi
    remaining_children=$(nginx_process_children "${NGINX_PID:-0}")
    if [ -n "$remaining_children" ]; then
        nginx_cleanup_check_status=1
        write_nginx_lifecycle_event "phase=cleanup children=remained result=failed pids=$remaining_children"
    else
        write_nginx_lifecycle_event "phase=cleanup children=none result=passed"
    fi
    if cleanup_port_is_free "$PORT"; then
        write_nginx_lifecycle_event "phase=cleanup port=$PORT result=freed"
    else
        nginx_cleanup_check_status=1
        write_nginx_lifecycle_event "phase=cleanup port=$PORT result=still_bound"
    fi
    if [ -e "$RUNTIME_PID_FILE" ]; then
        write_nginx_lifecycle_event "phase=cleanup pid_file=$RUNTIME_PID_FILE result=present_before_cleanup"
    else
        write_nginx_lifecycle_event "phase=cleanup pid_file=$RUNTIME_PID_FILE result=absent"
    fi
    uds_paths=$(find "$RUNTIME_ROOT" -type s -print 2>/dev/null || true)
    if [ -n "$uds_paths" ]; then
        nginx_cleanup_check_status=1
        write_nginx_lifecycle_event "phase=cleanup uds=present result=failed paths=$uds_paths"
    else
        write_nginx_lifecycle_event "phase=cleanup uds=none result=passed"
    fi
    if [ "$NGINX_HOSTED_FUNCTIONAL_A" = "1" ] && \
       [ "$NGINX_PHASE4_LOG_LIFECYCLE_PROBE" = "1" ] && \
       [ -n "${NGINX_PID:-}" ]; then
        if [ -d "/proc/$NGINX_PID/fd" ]; then
            nginx_cleanup_check_status=1
            write_nginx_lifecycle_event "phase=phase4_fd_shutdown result=master_fd_table_present"
        else
            write_nginx_lifecycle_event "phase=phase4_fd_shutdown result=closed_after_master_exit"
        fi
    fi
    return "$nginx_cleanup_check_status"
}

start_nginx_process() {
    if [ "$NGINX_MEMCHECK" = "1" ]; then
        (
            # Valgrind uses private log files itself; the inherited restrictive
            # mask additionally preserves that guarantee for every traced
            # master/worker process beneath the task-owned log root.
            umask 077
            exec "$SETSID_BIN" "$VALGRIND_BIN" \
                --tool=memcheck \
                --trace-children=yes \
                --vgdb=no \
                --leak-check=full \
                --show-leak-kinds=definite,indirect,possible \
                --errors-for-leak-kinds=definite,indirect \
                --error-exitcode=99 \
                --num-callers=24 \
                --suppressions="$NGINX_MEMCHECK_SUPPRESSIONS" \
                --log-file="$NGINX_MEMCHECK_EVIDENCE_DIR/valgrind.%p.log" \
                "$NGINX_BINARY" -p "$RUNTIME_ROOT" -c "$CONFIG_FILE" \
                > "$LOG_DIR/nginx-stdout.log" 2>&1
        ) &
        NGINX_MEMCHECK_STARTED=1
        NGINX_MEMCHECK_FINALIZED=0
        NGINX_MEMCHECK_PROCESS_GROUP=""
        NGINX_MEMCHECK_CONTAINMENT=unverified
    else
        "$NGINX_BINARY" -p "$RUNTIME_ROOT" -c "$CONFIG_FILE" > "$LOG_DIR/nginx-stdout.log" 2>&1 &
    fi
    NGINX_PID=$!
    if [ "$NGINX_MEMCHECK" = "1" ]; then
        # Capture the dedicated setsid group immediately, rather than waiting
        # for HTTP readiness and the NGINX pid-file.  This is the narrow
        # containment boundary for a startup failure or a failed readiness
        # probe; later role capture supplies the evidence identities.
        record_nginx_memcheck_process_group "$NGINX_PID"
    fi
}

cleanup() {
    nginx_cleanup_return=0
    if [ -n "${PHASE4_RELOAD_OVERLAP_CLIENT_PID:-}" ]; then
        if /bin/kill -0 "$PHASE4_RELOAD_OVERLAP_CLIENT_PID" >/dev/null 2>&1; then
            /bin/kill -TERM "$PHASE4_RELOAD_OVERLAP_CLIENT_PID" >/dev/null 2>&1 || true
        fi
        wait "$PHASE4_RELOAD_OVERLAP_CLIENT_PID" >/dev/null 2>&1 || true
        PHASE4_RELOAD_OVERLAP_CLIENT_PID=""
    fi
    if [ -n "${NGINX_SOAK_WORKER_PIDS:-}" ]; then
        for soak_worker_pid in $NGINX_SOAK_WORKER_PIDS; do
            if kill -0 "$soak_worker_pid" >/dev/null 2>&1; then
                kill "$soak_worker_pid" >/dev/null 2>&1 || true
            fi
            wait "$soak_worker_pid" >/dev/null 2>&1 || true
        done
    fi
    if [ -n "${SYNCHRONIZED_UPSTREAM_PID:-}" ] && kill -0 "$SYNCHRONIZED_UPSTREAM_PID" >/dev/null 2>&1; then
        [ -n "${SYNCHRONIZED_RELEASE_FILE:-}" ] && : > "$SYNCHRONIZED_RELEASE_FILE"
        kill "$SYNCHRONIZED_UPSTREAM_PID" >/dev/null 2>&1 || true
        wait "$SYNCHRONIZED_UPSTREAM_PID" >/dev/null 2>&1 || true
    fi
    if [ "$NGINX_MEMCHECK" = "1" ]; then
        finalize_nginx_memcheck || true
    elif [ -n "${NGINX_PID:-}" ] && kill -0 "$NGINX_PID" >/dev/null 2>&1; then
        if [ "$NGINX_LIFECYCLE_ENABLED" = "1" ]; then
            if ! shutdown_nginx_gracefully; then
                nginx_cleanup_return=1
                write_nginx_lifecycle_event "phase=cleanup result=failed reason=shutdown"
            fi
        else
            kill "$NGINX_PID" >/dev/null 2>&1 || true
            wait "$NGINX_PID" >/dev/null 2>&1 || true
        fi
    elif [ -n "${NGINX_PID:-}" ] && [ "$NGINX_LIFECYCLE_ENABLED" = "1" ]; then
        set +e
        wait "$NGINX_PID"
        NGINX_LIFECYCLE_EXIT_STATUS=$?
        set -e
    fi
    if [ -n "${RESPONSE_HEADER_BACKEND_PID:-}" ] && kill -0 "$RESPONSE_HEADER_BACKEND_PID" >/dev/null 2>&1; then
        kill "$RESPONSE_HEADER_BACKEND_PID" >/dev/null 2>&1 || true
        wait "$RESPONSE_HEADER_BACKEND_PID" >/dev/null 2>&1 || true
    fi
    if [ -n "${RUNTIME_PID_FILE:-}" ]; then
        if ! record_nginx_cleanup_state; then
            nginx_cleanup_return=1
            write_nginx_lifecycle_event "phase=cleanup result=failed reason=pre_cleanup_artifact_check"
        fi
        rm -f "$RUNTIME_PID_FILE"
        if [ ! -e "$RUNTIME_PID_FILE" ]; then
            write_nginx_lifecycle_event "phase=cleanup pid_file=$RUNTIME_PID_FILE result=absent_after_cleanup"
        else
            write_nginx_lifecycle_event "phase=cleanup pid_file=$RUNTIME_PID_FILE result=present_after_cleanup"
        fi
    fi
    # These private keys belong only to the ephemeral local listener.  No key
    # or certificate chain may survive cleanup into a reusable runtime or an
    # evidence directory.
    rm -f \
        "${NGINX_TLS_CA_KEY:-}" "${NGINX_TLS_CA_CERT:-}" \
        "${NGINX_TLS_SERVER_KEY:-}" "${NGINX_TLS_SERVER_CERT:-}" \
        "${NGINX_TLS_SERVER_CSR:-}" "${NGINX_TLS_SERVER_EXT:-}" \
        "${NGINX_TLS_CA_CERT:-}.srl"
    for nginx_cleanup_path in \
        "${NGINX_TLS_CA_KEY:-}" "${NGINX_TLS_CA_CERT:-}" \
        "${NGINX_TLS_SERVER_KEY:-}" "${NGINX_TLS_SERVER_CERT:-}" \
        "${NGINX_TLS_SERVER_CSR:-}" "${NGINX_TLS_SERVER_EXT:-}" \
        "${NGINX_TLS_CA_CERT:-}.srl"; do
        [ -n "$nginx_cleanup_path" ] || continue
        if [ -e "$nginx_cleanup_path" ]; then
            nginx_cleanup_return=1
            write_nginx_lifecycle_event "phase=cleanup temporary_file=$nginx_cleanup_path result=present_after_cleanup"
        fi
    done
    return "$nginx_cleanup_return"
}

cleanup_port_is_free() {
    port_to_probe=$1
    if nginx_port_probe_output=$("$PYTHON_BIN" - "$port_to_probe" "$NGINX_DOWNSTREAM_PROTOCOL" <<'PY'
import json
import os
import socket
import sys

port = int(sys.argv[1])
protocol = sys.argv[2]
diagnostic = {
    "address": "127.0.0.1",
    "family": "AF_INET",
    "netns": None,
    "port": port,
    "tcp_bind": "skipped",
    "tcp_bind_errno": None,
    "tcp_listeners": 0,
    "tcp_reuseaddr": True,
    "tcp_time_wait": 0,
    "udp_bind": "not_applicable",
    "udp_bind_errno": None,
}


def finish(result, status):
    diagnostic["result"] = result
    print(json.dumps(diagnostic, sort_keys=True, separators=(",", ":")))
    return status


try:
    if not 1 <= port <= 65535 or protocol not in ("http1", "h2", "h3"):
        raise ValueError("invalid probe arguments")
    diagnostic["netns"] = os.readlink("/proc/self/ns/net")
    with open("/proc/net/tcp", encoding="ascii") as table:
        table_header = next(table).split()
        if "local_address" not in table_header or "st" not in table_header:
            raise ValueError("invalid TCP table header")
        for line in table:
            fields = line.split()
            if len(fields) < 4:
                raise ValueError("incomplete TCP table row")
            address, hex_port = fields[1].split(":")
            if len(address) != 8 or len(hex_port) != 4:
                raise ValueError("invalid TCP local address")
            int(address, 16)
            local_port = int(hex_port, 16)
            state = fields[3]
            if len(state) != 2 or int(state, 16) not in range(1, 13):
                raise ValueError("unknown TCP state")
            if local_port == port and address in ("0100007F", "00000000"):
                if state == "0A":
                    diagnostic["tcp_listeners"] += 1
                elif state == "06":
                    diagnostic["tcp_time_wait"] += 1
except (OSError, ValueError, IndexError, StopIteration) as error:
    diagnostic["inspection_error"] = type(error).__name__
    diagnostic["inspection_errno"] = getattr(error, "errno", None)
    raise SystemExit(finish("inspection_failed", 1))

if diagnostic["tcp_listeners"]:
    raise SystemExit(finish("listener_present", 1))

try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp:
        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp.bind(("127.0.0.1", port))
except OSError as error:
    diagnostic["tcp_bind"] = "failed"
    diagnostic["tcp_bind_errno"] = error.errno
    raise SystemExit(finish("tcp_bind_failed", 1))
diagnostic["tcp_bind"] = "ok"

if protocol == "h3":
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.bind(("127.0.0.1", port))
    except OSError as error:
        diagnostic["udp_bind"] = "failed"
        diagnostic["udp_bind_errno"] = error.errno
        raise SystemExit(finish("udp_bind_failed", 1))
    diagnostic["udp_bind"] = "ok"

raise SystemExit(finish("freed", 0))
PY
    ); then
        nginx_port_probe_status=0
    else
        nginx_port_probe_status=$?
    fi
    if [ -z "$nginx_port_probe_output" ]; then
        nginx_port_probe_output='{"result":"probe_execution_failed"}'
        nginx_port_probe_status=1
    fi
    printf 'nginx_port_cleanup_probe %s\n' "$nginx_port_probe_output" >&2
    if [ -n "${NGINX_LIFECYCLE_FILE:-}" ]; then
        write_nginx_lifecycle_event "phase=cleanup port_probe=$nginx_port_probe_output"
    fi
    return "$nginx_port_probe_status"
}

port_is_free() {
    port_to_probe=$1
    "$PYTHON_BIN" - "$port_to_probe" "$NGINX_DOWNSTREAM_PROTOCOL" <<'PY'
import socket
import sys

port = int(sys.argv[1])
protocol = sys.argv[2]
kinds = [socket.SOCK_STREAM]
if protocol == "h3":
    kinds.append(socket.SOCK_DGRAM)
for kind in kinds:
    sock = socket.socket(socket.AF_INET, kind)
    try:
        sock.bind(("127.0.0.1", port))
    except OSError:
        raise SystemExit(1)
    finally:
        sock.close()
PY
}

port_accepts_tcp() {
    port_to_probe=$1
    "$PYTHON_BIN" - "$port_to_probe" <<'PY'
import socket
import sys

port = int(sys.argv[1])
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(0.2)
try:
    sock.connect(("127.0.0.1", port))
except OSError:
    raise SystemExit(1)
finally:
    sock.close()
PY
}

wait_tcp_port() {
    port_to_probe=$1
    i=0
    while [ "$i" -lt 30 ]; do
        if port_accepts_tcp "$port_to_probe"; then
            return 0
        fi
        i=$((i + 1))
        sleep 1
    done
    return 1
}

select_free_port() {
    start_port=$1
    search_limit=$2
    offset=0
    while [ "$offset" -lt "$search_limit" ]; do
        candidate=$((start_port + offset))
        if port_is_free "$candidate"; then
            printf '%s\n' "$candidate"
            return 0
        fi
        offset=$((offset + 1))
    done
    return 1
}

start_synchronized_upstream() {
    if [ "$MSCONNECTOR_FULL_LIFECYCLE_SYNC" = "1" ]; then
        if phase4_reload_overlap_sync_enabled; then
            blocked "full-lifecycle and phase4 reload-overlap synchronization cannot share one upstream"
        fi
        SYNCHRONIZED_DIR="$RUNTIME_ROOT/first-byte"
        SYNCHRONIZED_CONTROL_ROOT="$SYNCHRONIZED_UPSTREAM_CONTROL_ROOT"
        [ -n "$SYNCHRONIZED_CONTROL_ROOT" ] || \
            blocked "full-lifecycle synchronized upstream requires SYNCHRONIZED_UPSTREAM_CONTROL_ROOT"
    elif phase4_reload_overlap_sync_enabled; then
        # This fixture has no promotion artifact.  Its control endpoints stay
        # inside the freshly created task runtime and only establish an
        # in-flight request while the NGINX worker reloads.
        SYNCHRONIZED_DIR="$RUNTIME_ROOT/phase4-reload-overlap"
        SYNCHRONIZED_CONTROL_ROOT="$RUNTIME_ROOT"
    else
        return 0
    fi
    [ -f "$SYNCHRONIZED_UPSTREAM" ] || blocked "missing synchronized upstream helper: $SYNCHRONIZED_UPSTREAM"
    SYNCHRONIZED_READY_FILE="$SYNCHRONIZED_DIR/upstream-ready.json"
    SYNCHRONIZED_PAUSED_FILE="$SYNCHRONIZED_DIR/upstream-paused.json"
    SYNCHRONIZED_RELEASE_FILE="$SYNCHRONIZED_DIR/upstream-release"
    SYNCHRONIZED_SERVER_EVIDENCE_FILE="$SYNCHRONIZED_DIR/upstream-server.json"
    [ ! -e "$SYNCHRONIZED_DIR" ] && [ ! -L "$SYNCHRONIZED_DIR" ] || \
        fail "synchronized upstream control directory is unexpectedly occupied: $SYNCHRONIZED_DIR"
    mkdir -p "$SYNCHRONIZED_DIR" || \
        fail "could not create synchronized upstream control directory: $SYNCHRONIZED_DIR"
    "$PYTHON_BIN" "$SYNCHRONIZED_UPSTREAM" --serve \
        --control-root "$SYNCHRONIZED_CONTROL_ROOT" \
        --ready-file "$SYNCHRONIZED_READY_FILE" \
        --paused-file "$SYNCHRONIZED_PAUSED_FILE" \
        --release-file "$SYNCHRONIZED_RELEASE_FILE" \
        --server-evidence-file "$SYNCHRONIZED_SERVER_EVIDENCE_FILE" \
        --timeout 30 >"$LOG_DIR/synchronized-upstream.stdout.log" \
        2>"$LOG_DIR/synchronized-upstream.stderr.log" &
    SYNCHRONIZED_UPSTREAM_PID=$!
    i=0
    while [ "$i" -lt 30 ]; do
        if [ -f "$SYNCHRONIZED_READY_FILE" ]; then
            break
        fi
        if ! kill -0 "$SYNCHRONIZED_UPSTREAM_PID" >/dev/null 2>&1; then
            blocked "synchronized upstream exited before publishing its address"
        fi
        i=$((i + 1))
        sleep 1
    done
    [ -f "$SYNCHRONIZED_READY_FILE" ] || blocked "synchronized upstream did not publish its address"
    SYNCHRONIZED_UPSTREAM_PORT=$("$PYTHON_BIN" - "$SYNCHRONIZED_READY_FILE" <<'PY'
import json
import sys
payload = json.load(open(sys.argv[1], encoding="utf-8"))
port = payload.get("upstream_port")
if not isinstance(port, int) or port < 1 or port > 65535:
    raise SystemExit(1)
print(port)
PY
    ) || blocked "synchronized upstream ready record has no valid port"
}

send_synchronized_first_byte_request() {
    [ "$MSCONNECTOR_FULL_LIFECYCLE_SYNC" = "1" ] || return 1
    [ -n "$FULL_LIFECYCLE_EVIDENCE_OUTPUT" ] || fail "FULL_LIFECYCLE_EVIDENCE_OUTPUT is required for synchronized lifecycle mode"
    request_url_path=$(quote_request_path "$REQUEST_PATH")
    : > "$RESPONSE_BODY"
    "$CURL_BIN" -sS --no-buffer -X GET -o "$RESPONSE_BODY" -w "%{http_code}" \
        "http://127.0.0.1:$PORT$request_url_path" >"$LOG_DIR/first-byte-status.txt" \
        2>"$LOG_DIR/first-byte-client.err" &
    FIRST_BYTE_CLIENT_PID=$!
    observed_first_byte=0
    i=0
    while [ "$i" -lt 300 ]; do
        if [ -f "$SYNCHRONIZED_PAUSED_FILE" ] && [ -s "$RESPONSE_BODY" ]; then
            observed_first_byte=1
            break
        fi
        if ! kill -0 "$FIRST_BYTE_CLIENT_PID" >/dev/null 2>&1; then
            break
        fi
        i=$((i + 1))
        sleep 0.1
    done
    [ "$observed_first_byte" -eq 1 ] || fail "client did not receive a first response byte while upstream was paused"
    [ -s "$NGINX_PHASE4_LOG_FILE" ] || fail "Phase-4 append log is missing at first byte"
    FIRST_BYTE_HOST_METADATA="$SYNCHRONIZED_DIR/host-metadata.json"
    "$PYTHON_BIN" "$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/lifecycle/write-first-byte-host-metadata.py" \
        --phase4-log "$NGINX_PHASE4_LOG_FILE" --output "$FIRST_BYTE_HOST_METADATA" \
        --paused-file "$SYNCHRONIZED_PAUSED_FILE" --release-file "$SYNCHRONIZED_RELEASE_FILE" || \
        fail "could not derive bounded host metadata from the Phase-4 event"
    "$PYTHON_BIN" "$SYNCHRONIZED_UPSTREAM" --merge-evidence \
        --control-root "$SYNCHRONIZED_CONTROL_ROOT" \
        --paused-file "$SYNCHRONIZED_PAUSED_FILE" \
        --client-first-byte-file "$RESPONSE_BODY" \
        --host-metadata-json "$FIRST_BYTE_HOST_METADATA" \
        --evidence-origin real_host \
        --output "$FULL_LIFECYCLE_EVIDENCE_OUTPUT" || \
        fail "could not write synchronized first-byte evidence"
    "$PYTHON_BIN" "$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/lifecycle/write-first-byte-host-metadata.py" \
        --phase4-log "$NGINX_PHASE4_LOG_FILE" --output "$FIRST_BYTE_HOST_METADATA" \
        --paused-file "$SYNCHRONIZED_PAUSED_FILE" --release-file "$SYNCHRONIZED_RELEASE_FILE" \
        --evidence "$FULL_LIFECYCLE_EVIDENCE_OUTPUT" \
        --binding-output "$FULL_LIFECYCLE_EVIDENCE_OUTPUT.binding.json" || \
        fail "could not bind first-byte snapshot to the paused native append"
    : > "$SYNCHRONIZED_RELEASE_FILE"
    set +e
    wait "$FIRST_BYTE_CLIENT_PID"
    client_rc=$?
    set -e
    [ "$client_rc" -eq 0 ] || fail "synchronized client failed after upstream release rc=$client_rc"
    http_status=$(cat "$LOG_DIR/first-byte-status.txt" 2>/dev/null || true)
    [ "$http_status" = "200" ] || fail "synchronized safe response status was not 200: $http_status"
    printf '%s\n' "$http_status" > "$LOG_DIR/observed-status.txt"
    printf '%s\n' "http_status" > "$LOG_DIR/observed-transport-result.txt"
    return 0
}

stop_stale_runtime_pid() {
    pid_file=$1
    [ -f "$pid_file" ] || return 0
    case "$pid_file" in
        "$BUILD_ROOT"/*|"$RUNTIME_BASE"/*|"$NGINX_HARNESS_WORK_ROOT"/*) ;;
        *) blocked "runtime pid file is outside allowed generated runtime roots: $pid_file" ;;
    esac
    stale_pid=$(cat "$pid_file" 2>/dev/null || true)
    case "$stale_pid" in
        ""|*[!0-9]*)
            rm -f "$pid_file"
            return 0
            ;;
        *) ;;
    esac
    if ! kill -0 "$stale_pid" >/dev/null 2>&1; then
        rm -f "$pid_file"
        return 0
    fi
    stale_cmd=$(tr '\0' ' ' < "/proc/$stale_pid/cmdline" 2>/dev/null || true)
    case "$stale_cmd" in
        *"$RUNTIME_ROOT"*) ;;
        *)
            blocked "runtime pid file points to non-smoke process pid=$stale_pid command=$stale_cmd"
            ;;
    esac
    echo "nginx_smoke: stopping stale runtime process pid=$stale_pid"
    kill "$stale_pid" >/dev/null 2>&1 || true
    wait_count=0
    while kill -0 "$stale_pid" >/dev/null 2>&1 && [ "$wait_count" -lt 10 ]; do
        wait_count=$((wait_count + 1))
        sleep 1
    done
    if kill -0 "$stale_pid" >/dev/null 2>&1; then
        blocked "stale runtime process did not stop pid=$stale_pid"
    fi
    rm -f "$pid_file"
}

bind_conflict_seen() {
    grep -E "Address already in use|could not bind|bind\\(\\)" \
        "$LOG_DIR/nginx-stdout.log" \
        "$LOG_DIR/error.log" >/dev/null 2>&1
}

run_nginx_protocol_client_if_requested() {
    artifact_dir=$NO_CRS_PROTOCOL_CLIENT_ARTIFACT_DIR
    [ -n "$artifact_dir" ] || return 0
    observation=$artifact_dir/client-protocol-observation.json
    if [ -f "$observation" ] && [ ! -L "$observation" ]; then
        return 0
    fi
    case "$NGINX_DOWNSTREAM_PROTOCOL" in
        h2|h3) protocol=$NGINX_DOWNSTREAM_PROTOCOL ;;
        *) return 0 ;;
    esac
    protocol_probe_token="nginx-${protocol}-live-probe"
    umask 077
    mkdir -p "$artifact_dir"
    # This is a real forced client->native-connector probe while NGINX is
    # alive. Its bounded probe token identifies only this non-promoting request;
    # no native event or catalog case is allowed to borrow it. The probe also
    # intentionally supplies no synthetic stream ID or ALPN sidecar: curl
    # cannot establish the per-stream causal facts required for promotion.
    set +e
    "$PYTHON_BIN" "$FRAMEWORK_ROOT/ci/checks/protocol/protocol_client.py" \
        --url "https://127.0.0.1:$PORT/no-crs/allow" \
        --protocol "$protocol" \
        --artifact-dir "$artifact_dir" \
        --curl "$CURL_BIN" \
        --cacert "$NGINX_TLS_CA_CERT" \
        --header "X-Modsec-Smoke: allow" \
        --transport-case-id "$protocol_probe_token" \
        --connector nginx \
        --integration-mode native-nginx-http-module \
        --run-id "${NO_CRS_RUN_ID:-local}" >/dev/null 2>&1
    client_rc=$?
    set -e
    [ -s "$observation" ] || fail "protocol client did not publish a payload-free observation"
    client_status=$("$PYTHON_BIN" - "$observation" "$protocol" "$protocol_probe_token" <<'PY'
import json
import sys

try:
    value = json.load(open(sys.argv[1], encoding="utf-8"))
except (OSError, ValueError):
    raise SystemExit(1)
protocol = sys.argv[2]
probe_token = sys.argv[3]
if not isinstance(value, dict):
    raise SystemExit(1)
status = value.get("status")
if value.get("transport_case_id") != probe_token:
    raise SystemExit(1)
if status == "BLOCKED":
    if value.get("reason") not in {
        "client_http3_unsupported",
        "client_required_feature_unavailable",
        "client_required_option_unavailable",
        "curl_executable_unavailable",
        "curl_version_probe_timeout",
        "curl_version_probe_failed",
        "curl_help_probe_unavailable",
        "curl_help_probe_timeout",
        "curl_help_probe_failed",
    } or value.get("curl_exit_code") is not None:
        raise SystemExit(1)
elif status == "NOT_EXECUTED":
    if (
        value.get("reason") != "incomplete_protocol_provenance"
        or value.get("requested_protocol") != protocol
        or value.get("negotiated_protocol") != protocol
        or value.get("fallback_used") is not False
        or value.get("http_status") != 200
        or value.get("curl_exit_code") != 0
        or value.get("response_committed") is not True
    ):
        raise SystemExit(1)
    if protocol == "h2" and value.get("transport") != "tls_tcp":
        raise SystemExit(1)
    # This diagnostic probe must remain explicitly non-promoting.  A native
    # stream/ALPN sidecar belongs to a case-correlated transport test, not to
    # this standalone liveness request.
    if "stream_id" in value or "alpn" in value:
        raise SystemExit(1)
else:
    # A fallback, transfer failure, or accidental complete PASS is not a
    # harmless diagnostic. It would contradict this exact non-promoting probe.
    raise SystemExit(1)
print(status)
PY
    ) || fail "protocol client wrote an invalid observation"
    printf 'protocol-client status=%s exit=%s (non-promoting without stream/case correlation)\n' \
        "$client_status" "$client_rc" >> "$STATUS_FILE"
}

start_server() {
    attempt=0
    while :; do
        selected_port=$(select_free_port "$PORT" "$PORT_SEARCH_LIMIT") || \
            blocked "no free localhost port found from $PORT within $PORT_SEARCH_LIMIT attempts"
        if [ "$selected_port" != "$PORT" ]; then
            echo "nginx_smoke: selected free port=$selected_port after requested port=$PORT was unavailable"
            echo "info: selected port $selected_port after requested port $PORT was unavailable" >> "$STATUS_FILE"
        fi
        PORT="$selected_port"
        write_nginx_protocol_directives
        render_config

        if ! "$NGINX_BINARY" -t -p "$RUNTIME_ROOT" -c "$CONFIG_FILE" > "$LOG_DIR/configtest.log" 2>&1; then
            if configtest_case_not_executable; then
                not_executable "NGINX rejected generated ModSecurity rules; see $LOG_DIR/configtest.log"
            fi
            fail "NGINX configtest failed; see $LOG_DIR/configtest.log"
        fi

        if [ "$MSCONNECTOR_SMOKE_STAGE" = "config_load" ]; then
            return 0
        fi

        start_nginx_process

        if [ "$MSCONNECTOR_SMOKE_STAGE" = "start_smoke" ]; then
            sleep 1
            if kill -0 "$NGINX_PID" >/dev/null 2>&1; then
                return 0
            fi
            fail "NGINX exited during request-free start smoke; see $LOG_DIR/nginx-stdout.log and $LOG_DIR/error.log"
        fi

        if [ "$NGINX_DOWNSTREAM_PROTOCOL" != "http1" ]; then
            # The profile listener is real and was config-tested/started, but
            # this baseline case runner has no protocol-specific case catalog
            # or transaction/stream correlation yet.  Never send its legacy
            # HTTP/1 curl request to a TLS/QUIC listener and never count that
            # as H2/H3 evidence.
            sleep 1
            if kill -0 "$NGINX_PID" >/dev/null 2>&1; then
                # This is a TCP readiness check only.  The forced client
                # probe below remains the sole HTTP/2 or HTTP/3 observation.
                wait_tcp_port "$PORT" || fail "NGINX protocol listener did not become TCP-ready; see $LOG_DIR/nginx-stdout.log and $LOG_DIR/error.log"
                run_nginx_protocol_client_if_requested
                not_executable "forced $NGINX_DOWNSTREAM_PROTOCOL client case is not wired in this bounded NGINX harness; protocol applicability remains NOT_EXECUTED"
            fi
            fail "NGINX exited before protocol-specific client dispatch; see $LOG_DIR/nginx-stdout.log and $LOG_DIR/error.log"
        fi

        ready=0
        i=0
        while [ "$i" -lt 30 ]; do
            if ! kill -0 "$NGINX_PID" >/dev/null 2>&1; then
                if [ "$attempt" -lt "$PORT_RETRY_LIMIT" ] && bind_conflict_seen; then
                    cleanup
                    attempt=$((attempt + 1))
                    PORT=$((PORT + 1))
                    echo "nginx_smoke: retrying after bind conflict attempt=$attempt"
                    echo "info: retrying after bind conflict attempt=$attempt" >> "$STATUS_FILE"
                    continue 2
                fi
                fail "NGINX exited before request; see $LOG_DIR/nginx-stdout.log and $LOG_DIR/error.log"
            fi
            if "$CURL_BIN" -sS -o /dev/null "http://127.0.0.1:$PORT/__modsec_smoke_ready" >/dev/null 2>"$LOG_DIR/curl-ready.err"; then
                ready=1
                break
            fi
            i=$((i + 1))
            sleep 1
        done

        if [ "$ready" -eq 1 ]; then
            record_nginx_memcheck_roles
            reload_nginx_master_worker
            return 0
        fi
        fail "NGINX did not become ready on 127.0.0.1:$PORT"
    done
}

send_case_request() {
    [ "${NGINX_DOWNSTREAM_PROTOCOL:-http1}" = http1 ] || \
        blocked "legacy case request requires NGINX_DOWNSTREAM_PROTOCOL=http1"
    response_output="${SEND_CASE_RESPONSE_BODY:-$RESPONSE_BODY}"
    curl_error_output="${SEND_CASE_CURL_ERROR_LOG:-$LOG_DIR/curl-attack.err}"
    validate_nginx_request_output_path SEND_CASE_RESPONSE_BODY "$response_output"
    validate_nginx_request_output_path SEND_CASE_CURL_ERROR_LOG "$curl_error_output"
    set -- "$CURL_BIN" -q --http1.1 -sS -X "$REQUEST_METHOD" -o "$response_output" -w "%{http_code}"
    if [ -n "${SEND_CASE_MAX_TIME_SECONDS:-}" ]; then
        set -- "$@" --max-time "$SEND_CASE_MAX_TIME_SECONDS"
    fi
    if [ -n "${REQUEST_HEADERS_FILE:-}" ] && [ -s "$REQUEST_HEADERS_FILE" ]; then
        while IFS= read -r header_line || [ -n "$header_line" ]; do
            [ -n "$header_line" ] || continue
            case "$header_line" in
                *:*)
                    header_value=${header_line#*:}
                    case "$header_value" in
                        ''|' ') header_line="${header_line%%:*};" ;;
                        *) : ;;
                    esac
                    ;;
                *) : ;;
            esac
            set -- "$@" -H "$header_line"
        done < "$REQUEST_HEADERS_FILE"
    fi
    if [ "${REQUEST_HAS_BODY:-0}" = "1" ]; then
        set -- "$@" --data-binary "@$REQUEST_BODY_FILE"
    fi
    request_url_path=$(quote_request_path "$REQUEST_PATH")
    set -- "$@" "http://127.0.0.1:$PORT$request_url_path"
    "$PYTHON_BIN" "$CASE_CLI" request-window --phase begin \
        --case "$TEST_CASE" --event-log "$LOG_DIR/phase4.log" \
        --receipt "$LOG_DIR/request-window.json" --output-root "$LOG_DIR" \
        --run-id "$RESULT_RUN_ID" --source-revision "$CONNECTOR_REVISION" || return 1
    request_status=0
    "$@" 2>"$curl_error_output" || request_status=$?
    "$PYTHON_BIN" "$CASE_CLI" request-window --phase end \
        --case "$TEST_CASE" --event-log "$LOG_DIR/phase4.log" \
        --receipt "$LOG_DIR/request-window.json" --output-root "$LOG_DIR" \
        --run-id "$RESULT_RUN_ID" --source-revision "$CONNECTOR_REVISION" || return 1
    return "$request_status"
}

phase4_file_size() {
    phase4_size_path=$1
    [ -f "$phase4_size_path" ] && [ ! -L "$phase4_size_path" ] || return 1
    /usr/bin/wc -c < "$phase4_size_path" | /usr/bin/tr -d '[:space:]'
}

phase4_fd_count_for_target() {
    phase4_fd_target=$1
    phase4_fd_count=0
    for phase4_fd_pid in "$NGINX_PID" $(nginx_process_children "$NGINX_PID"); do
        case "$phase4_fd_pid" in
            ''|*[!0-9]*) continue ;;
            *) ;;
        esac
        [ -d "/proc/$phase4_fd_pid/fd" ] || continue
        for phase4_fd_entry in "/proc/$phase4_fd_pid/fd/"*; do
            [ -L "$phase4_fd_entry" ] || continue
            phase4_fd_link=$(/usr/bin/readlink -- "$phase4_fd_entry" 2>/dev/null || true)
            [ "$phase4_fd_link" = "$phase4_fd_target" ] || continue
            phase4_fd_count=$((phase4_fd_count + 1))
            write_nginx_lifecycle_event "phase=phase4_fd pid=$phase4_fd_pid fd=${phase4_fd_entry##*/} target=$phase4_fd_target"
        done
    done
    printf '%s\n' "$phase4_fd_count"
}

assert_phase4_fd_holders() {
    phase4_expected_target=$1
    phase4_minimum_holders=$2
    phase4_fd_label=$3
    phase4_observed_holders=$(phase4_fd_count_for_target "$phase4_expected_target") || \
        fail "phase4 FD scan failed for $phase4_fd_label"
    [ "$phase4_observed_holders" -ge "$phase4_minimum_holders" ] || \
        fail "phase4 $phase4_fd_label has $phase4_observed_holders descriptor holders, expected at least $phase4_minimum_holders"
    write_nginx_lifecycle_event "phase=phase4_fd_check label=$phase4_fd_label holders=$phase4_observed_holders result=passed"
}

assert_phase4_fd_absent() {
    phase4_absent_target=$1
    phase4_absent_label=$2
    phase4_remaining_holders=$(phase4_fd_count_for_target "$phase4_absent_target") || \
        fail "phase4 FD absence scan failed for $phase4_absent_label"
    [ "$phase4_remaining_holders" -eq 0 ] || \
        fail "phase4 $phase4_absent_label still has $phase4_remaining_holders descriptor holders"
    write_nginx_lifecycle_event "phase=phase4_fd_check label=$phase4_absent_label holders=0 result=passed"
}

start_phase4_reload_overlap_client() {
    phase4_reload_overlap_sync_enabled || \
        fail "phase4 reload overlap requires the hosted synchronized upstream"
    [ -n "${SYNCHRONIZED_PAUSED_FILE:-}" ] || \
        fail "phase4 reload overlap has no paused-upstream control path"
    phase4_overlap_output="$LOG_DIR/phase4-reload-overlap.response"
    phase4_overlap_status_file="$LOG_DIR/phase4-reload-overlap.status"
    phase4_overlap_error="$LOG_DIR/phase4-reload-overlap.err"
    for phase4_overlap_path in \
        "$phase4_overlap_output" "$phase4_overlap_status_file" "$phase4_overlap_error"; do
        [ ! -e "$phase4_overlap_path" ] && [ ! -L "$phase4_overlap_path" ] || \
            fail "phase4 reload-overlap client path is unexpectedly occupied: $phase4_overlap_path"
    done
    "$CURL_BIN" -sS --no-buffer --max-time 30 -X GET \
        -o "$phase4_overlap_output" -w "%{http_code}" \
        "http://127.0.0.1:$PORT/__modsec_slow_stream" \
        > "$phase4_overlap_status_file" 2> "$phase4_overlap_error" &
    PHASE4_RELOAD_OVERLAP_CLIENT_PID=$!
    phase4_overlap_attempt=0
    while [ "$phase4_overlap_attempt" -lt 100 ]; do
        if [ -f "$SYNCHRONIZED_PAUSED_FILE" ] && \
           [ ! -L "$SYNCHRONIZED_PAUSED_FILE" ] && \
           [ -s "$phase4_overlap_output" ]; then
            return 0
        fi
        /bin/kill -0 "$PHASE4_RELOAD_OVERLAP_CLIENT_PID" >/dev/null 2>&1 || \
            fail "phase4 reload-overlap client ended before the paused first-byte barrier"
        phase4_overlap_attempt=$((phase4_overlap_attempt + 1))
        /bin/sleep 0.1
    done
    fail "phase4 reload-overlap client did not reach the paused first-byte barrier"
}

validate_phase4_reload_overlap_server_record() {
    "$PYTHON_BIN" - "$SYNCHRONIZED_SERVER_EVIDENCE_FILE" <<'PY'
import json
from pathlib import Path
import sys

path = Path(sys.argv[1])
if path.is_symlink() or not path.is_file():
    raise SystemExit("synchronized overlap server record is missing or unsafe")
payload = json.loads(path.read_text(encoding="utf-8"))
expected = {
    "schema_version",
    "evidence_type",
    "first_chunk_size",
    "upstream_paused",
    "upstream_eos_sent",
    "body_payload_persisted",
}
if not isinstance(payload, dict) or set(payload) != expected:
    raise SystemExit("synchronized overlap server record has an unexpected shape")
if payload["schema_version"] != 1:
    raise SystemExit("synchronized overlap server record has an invalid schema")
if payload["evidence_type"] != "synchronized_upstream_server":
    raise SystemExit("synchronized overlap server record has an invalid type")
if type(payload["first_chunk_size"]) is not int or payload["first_chunk_size"] < 1:
    raise SystemExit("synchronized overlap server record has an invalid first chunk size")
if payload["upstream_paused"] is not True or payload["upstream_eos_sent"] is not True:
    raise SystemExit("synchronized overlap server record lacks the paused-to-EOS transition")
if payload["body_payload_persisted"] is not False:
    raise SystemExit("synchronized overlap server record persisted a body payload")
PY
}

stop_phase4_reload_overlap_client() {
    [ -n "${PHASE4_RELOAD_OVERLAP_CLIENT_PID:-}" ] || return 0
    [ -n "${SYNCHRONIZED_RELEASE_FILE:-}" ] || \
        fail "phase4 reload overlap has no upstream release control path"
    [ ! -e "$SYNCHRONIZED_RELEASE_FILE" ] && [ ! -L "$SYNCHRONIZED_RELEASE_FILE" ] || \
        fail "phase4 reload-overlap release control is unexpectedly occupied"
    : > "$SYNCHRONIZED_RELEASE_FILE" || \
        fail "phase4 reload-overlap upstream release could not be recorded"
    set +e
    wait "$PHASE4_RELOAD_OVERLAP_CLIENT_PID"
    phase4_overlap_client_wait_status=$?
    wait "$SYNCHRONIZED_UPSTREAM_PID"
    phase4_overlap_upstream_wait_status=$?
    set -e
    PHASE4_RELOAD_OVERLAP_CLIENT_PID=""
    SYNCHRONIZED_UPSTREAM_PID=""
    [ "$phase4_overlap_client_wait_status" -eq 0 ] || \
        fail "phase4 reload-overlap client failed after release: $phase4_overlap_client_wait_status"
    [ "$phase4_overlap_upstream_wait_status" -eq 0 ] || \
        fail "phase4 reload-overlap upstream failed after release: $phase4_overlap_upstream_wait_status"
    validate_phase4_reload_overlap_server_record || \
        fail "phase4 reload-overlap server evidence was invalid"
    phase4_overlap_status=$(cat "$phase4_overlap_status_file" 2>/dev/null || true)
    [ "$phase4_overlap_status" = "200" ] || \
        fail "phase4 reload-overlap response status was not 200: $phase4_overlap_status"
    [ -s "$phase4_overlap_output" ] || \
        fail "phase4 reload-overlap response did not retain the bounded first-byte observation"
}

observe_phase4_reload_overlap() {
    phase4_old_worker=$1
    phase4_overlap_attempt=0
    while [ "$phase4_overlap_attempt" -lt 10 ]; do
        phase4_overlap_snapshot=$(nginx_process_child_snapshot "$NGINX_PID")
        phase4_overlap_count=$(printf '%s\n' "$phase4_overlap_snapshot" | /usr/bin/awk 'NF { count += 1 } END { print count + 0 }')
        phase4_old_worker_present=$(printf '%s\n' "$phase4_overlap_snapshot" | /usr/bin/awk \
            -v expected_old_worker="$phase4_old_worker" -v expected_parent="$NGINX_PID" '
                $1 == expected_old_worker && $2 == expected_parent && $3 !~ /^Z/ { present = 1 }
                END { print present ? 1 : 0 }
            ')
        phase4_replacement_present=$(printf '%s\n' "$phase4_overlap_snapshot" | /usr/bin/awk \
            -v expected_old_worker="$phase4_old_worker" -v expected_parent="$NGINX_PID" '
                $1 != expected_old_worker && $2 == expected_parent && $3 !~ /^Z/ { present = 1 }
                END { print present ? 1 : 0 }
            ')
        phase4_overlap_last_snapshot=$(printf '%s\n' "$phase4_overlap_snapshot" | /usr/bin/awk '
            NF == 3 {
                if (count < 8) {
                    printf "%s%s:%s:%s", separator, $1, $2, $3
                    separator = ","
                }
                count += 1
            }
            END {
                if (count == 0) {
                    printf "none"
                } else if (count > 8) {
                    printf ",more=%d", count - 8
                }
            }
        ')
        if [ "$phase4_old_worker_present" = "1" ] && [ "$phase4_replacement_present" = "1" ]; then
            write_nginx_lifecycle_event "phase=phase4_reload_overlap old_worker=$phase4_old_worker worker_count=$phase4_overlap_count result=observed"
            return 0
        fi
        phase4_overlap_attempt=$((phase4_overlap_attempt + 1))
        /bin/sleep 1
    done
    write_nginx_lifecycle_event "phase=phase4_reload_overlap old_worker=$phase4_old_worker worker_count=$phase4_overlap_count old_worker_present=$phase4_old_worker_present replacement_present=$phase4_replacement_present last_snapshot=$phase4_overlap_last_snapshot result=not_observed"
    fail "phase4 reload never showed old and replacement workers concurrently"
}

send_expected_phase4_lifecycle_request() {
    phase4_request_label=$1
    phase4_response="$LOG_DIR/phase4-lifecycle-$phase4_request_label.response"
    phase4_error="$LOG_DIR/phase4-lifecycle-$phase4_request_label.err"
    set +e
    phase4_status=$(SEND_CASE_RESPONSE_BODY="$phase4_response" \
        SEND_CASE_CURL_ERROR_LOG="$phase4_error" send_case_request)
    phase4_rc=$?
    set -e
    [ "$phase4_rc" -eq 0 ] || \
        fail "phase4 lifecycle $phase4_request_label request failed rc=$phase4_rc"
    [ "$phase4_status" = "$EXPECT_STATUS" ] || \
        fail "phase4 lifecycle $phase4_request_label expected HTTP $EXPECT_STATUS, observed $phase4_status"
}

exercise_phase4_log_lifecycle() {
    [ "$NGINX_HOSTED_FUNCTIONAL_A" = "1" ] || \
        fail "phase4 lifecycle probe is restricted to hosted functional A"
    [ "$CURRENT_UID" = "0" ] || \
        blocked "phase4 lifecycle probe requires a root NGINX master"
    [ "$NGINX_PHASE4_LOG_TARGET_MODE" = "regular" ] || \
        fail "phase4 lifecycle probe requires a regular secure event target"
    [ "$NGINX_PHASE4_LOG_SCOPE" = "location" ] || \
        fail "phase4 lifecycle probe requires the fixture-owned location directive"
    [ -f "$NGINX_PHASE4_LOG_FILE" ] && [ ! -L "$NGINX_PHASE4_LOG_FILE" ] || \
        fail "phase4 lifecycle initial event file is missing or unsafe"
    [ "$(/usr/bin/stat -c '%a' "$NGINX_PHASE4_LOG_FILE")" = "600" ] || \
        fail "phase4 lifecycle initial event file does not have mode 0600"
    assert_phase4_fd_holders "$NGINX_PHASE4_LOG_FILE" 2 initial_secure_descriptor

    phase4_old_file="$LOG_DIR/phase4-before-usr1.log"
    phase4_canary_file="$LOG_DIR/phase4-usr1-canary.log"
    [ ! -e "$phase4_old_file" ] && [ ! -L "$phase4_old_file" ] || \
        fail "phase4 lifecycle old-target evidence path is unexpectedly occupied"
    [ ! -e "$phase4_canary_file" ] && [ ! -L "$phase4_canary_file" ] || \
        fail "phase4 lifecycle canary evidence path is unexpectedly occupied"
    /bin/mv "$NGINX_PHASE4_LOG_FILE" "$phase4_old_file"
    if ! (set -C; : > "$phase4_canary_file"); then
        fail "phase4 lifecycle could not create fresh canary file"
    fi
    /bin/chmod 600 "$phase4_canary_file"
    /bin/ln -s "$phase4_canary_file" "$NGINX_PHASE4_LOG_FILE" || \
        fail "phase4 lifecycle could not install the controlled symlink substitution"
    phase4_old_before_usr1=$(phase4_file_size "$phase4_old_file") || \
        fail "phase4 lifecycle cannot measure the pre-USR1 event file"

    # The module deliberately does not register its descriptor with
    # cycle->open_files.  This ordinary NGINX reopen signal must therefore
    # retain the validated FD rather than following the substituted pathname.
    /bin/kill -USR1 "$NGINX_PID" || fail "phase4 lifecycle USR1 signal failed"
    /bin/sleep 1
    send_expected_phase4_lifecycle_request after_usr1
    phase4_old_after_usr1=$(phase4_file_size "$phase4_old_file") || \
        fail "phase4 lifecycle cannot measure the post-USR1 event file"
    [ "$phase4_old_after_usr1" -gt "$phase4_old_before_usr1" ] || \
        fail "phase4 lifecycle USR1 did not retain the secure inherited descriptor"
    [ ! -s "$phase4_canary_file" ] || \
        fail "phase4 lifecycle USR1 followed the substituted unsafe pathname"
    assert_phase4_fd_holders "$phase4_old_file" 2 usr1_retained_descriptor
    write_nginx_lifecycle_event "phase=phase4_usr1 result=retained_secure_fd old_file=$phase4_old_file"

    # A reload parses a new cycle.  While the configured target is a symlink,
    # Common must fail closed and the still-active old cycle must continue to
    # service the case through its inherited descriptor.
    if "$NGINX_BINARY" -t -p "$RUNTIME_ROOT" -c "$CONFIG_FILE" \
        > "$LOG_DIR/nginx-reload-unsafe-phase4-configtest.log" 2>&1; then
        fail "phase4 lifecycle unsafe target unexpectedly passed config validation"
    fi
    # A separate `nginx -s reload` process parses the now intentionally
    # rejected configuration before it can signal the active master.  Verify
    # that master immediately before addressing it directly so this test
    # observes NGINX's actual reload and rollback behavior.
    record_nginx_master_worker_roles >/dev/null
    /bin/kill -HUP "$NGINX_PID" || \
        fail "phase4 lifecycle unsafe reload signal could not reach the active master"
    /bin/sleep 1
    /bin/kill -0 "$NGINX_PID" >/dev/null 2>&1 || \
        fail "phase4 lifecycle unsafe reload damaged the active master"
    phase4_old_before_failed_reload_request=$(phase4_file_size "$phase4_old_file") || \
        fail "phase4 lifecycle cannot measure old event file after failed reload"
    send_expected_phase4_lifecycle_request after_failed_reload
    phase4_old_after_failed_reload_request=$(phase4_file_size "$phase4_old_file") || \
        fail "phase4 lifecycle cannot measure retained event file after failed reload"
    [ "$phase4_old_after_failed_reload_request" -gt "$phase4_old_before_failed_reload_request" ] || \
        fail "phase4 lifecycle failed reload did not preserve the active descriptor"
    [ ! -s "$phase4_canary_file" ] || \
        fail "phase4 lifecycle failed reload wrote to the unsafe substituted pathname"
    assert_phase4_fd_holders "$phase4_old_file" 2 failed_reload_retained_descriptor
    write_nginx_lifecycle_event "phase=phase4_reload_unsafe result=failed_old_cycle_preserved"

    /bin/rm -f "$NGINX_PHASE4_LOG_FILE"
    phase4_old_worker=$(record_nginx_master_worker_roles)
    start_phase4_reload_overlap_client
    if ! "$NGINX_BINARY" -p "$RUNTIME_ROOT" -c "$CONFIG_FILE" -s reload \
        > "$LOG_DIR/nginx-reload-secure-phase4.log" 2>&1; then
        stop_phase4_reload_overlap_client
        fail "phase4 lifecycle secure reload command failed"
    fi
    observe_phase4_reload_overlap "$phase4_old_worker"
    stop_phase4_reload_overlap_client
    NGINX_LIFECYCLE_RELOADED_WORKER=$(wait_for_nginx_worker_replacement "$phase4_old_worker") || \
        fail "phase4 lifecycle secure reload did not drain the old worker"
    /bin/kill -0 "$phase4_old_worker" >/dev/null 2>&1 && \
        fail "phase4 lifecycle old worker remained after the controlled drain"
    NGINX_LIFECYCLE_RELOAD=passed
    record_nginx_master_worker_roles >/dev/null
    write_nginx_lifecycle_event "phase=after_reload master_pid=$NGINX_PID old_worker_pid=$phase4_old_worker new_worker_pid=$NGINX_LIFECYCLE_RELOADED_WORKER result=passed"
    [ -f "$NGINX_PHASE4_LOG_FILE" ] && [ ! -L "$NGINX_PHASE4_LOG_FILE" ] || \
        fail "phase4 lifecycle secure reload did not create a replacement event file"
    [ "$(/usr/bin/stat -c '%a' "$NGINX_PHASE4_LOG_FILE")" = "600" ] || \
        fail "phase4 lifecycle replacement event file does not have mode 0600"
    phase4_new_before_reload_request=$(phase4_file_size "$NGINX_PHASE4_LOG_FILE") || \
        fail "phase4 lifecycle cannot measure replacement event file"
    send_expected_phase4_lifecycle_request after_secure_reload
    phase4_new_after_reload_request=$(phase4_file_size "$NGINX_PHASE4_LOG_FILE") || \
        fail "phase4 lifecycle cannot measure replacement event file after reload"
    [ "$phase4_new_after_reload_request" -gt "$phase4_new_before_reload_request" ] || \
        fail "phase4 lifecycle secure reload did not activate the replacement descriptor"
    assert_phase4_fd_holders "$NGINX_PHASE4_LOG_FILE" 2 secure_reload_new_descriptor
    assert_phase4_fd_absent "$phase4_old_file" old_cycle_descriptor_after_drain
    write_nginx_lifecycle_event "phase=phase4_reload_secure result=new_validated_fd"
}

soak_request_matches_case() {
    soak_http_status=$1
    soak_curl_rc=$2
    soak_transport=http_status
    if [ "$soak_curl_rc" -ne 0 ]; then
        soak_transport=connection_aborted
    fi
    [ "$soak_transport" = "$EXPECT_TRANSPORT" ] || return 1
    [ "$soak_http_status" = "$EXPECT_STATUS" ] || return 1
    return 0
}

run_bounded_soak_worker() {
    soak_worker_index=$1
    soak_deadline=$2
    soak_worker_summary="$NGINX_SOAK_WORKER_DIR/$soak_worker_index.summary"
    soak_worker_requests=0
    soak_worker_failures=0

    while :; do
        soak_now=$(date +%s)
        if [ "$soak_worker_requests" -gt 0 ] && [ "$soak_now" -ge "$soak_deadline" ]; then
            break
        fi
        set +e
        soak_http_status=$(SEND_CASE_RESPONSE_BODY=/dev/null \
            SEND_CASE_CURL_ERROR_LOG=/dev/null \
            SEND_CASE_MAX_TIME_SECONDS=10 \
            send_case_request)
        soak_curl_rc=$?
        set -e
        soak_worker_requests=$((soak_worker_requests + 1))
        if ! soak_request_matches_case "$soak_http_status" "$soak_curl_rc"; then
            soak_worker_failures=$((soak_worker_failures + 1))
            break
        fi
    done

    printf 'requests=%s failures=%s\n' "$soak_worker_requests" "$soak_worker_failures" > "$soak_worker_summary"
    [ "$soak_worker_failures" -eq 0 ]
}

collect_bounded_soak_worker_summaries() {
    NGINX_SOAK_REQUESTS_COMPLETED=0
    NGINX_SOAK_REQUEST_FAILURES=0
    NGINX_SOAK_WORKER_SUMMARY_FAILURES=0
    soak_worker_index=1
    while [ "$soak_worker_index" -le "$NGINX_SOAK_CONCURRENCY" ]; do
        soak_worker_summary="$NGINX_SOAK_WORKER_DIR/$soak_worker_index.summary"
        if [ ! -f "$soak_worker_summary" ] || [ -L "$soak_worker_summary" ]; then
            NGINX_SOAK_WORKER_SUMMARY_FAILURES=$((NGINX_SOAK_WORKER_SUMMARY_FAILURES + 1))
            soak_worker_index=$((soak_worker_index + 1))
            continue
        fi
        soak_requests_field=
        soak_failures_field=
        soak_extra_field=
        IFS=' ' read -r soak_requests_field soak_failures_field soak_extra_field < "$soak_worker_summary" || true
        case "$soak_requests_field:$soak_failures_field:$soak_extra_field" in
            requests=[0-9]*:failures=[0-9]*:)
                soak_worker_requests=${soak_requests_field#requests=}
                soak_worker_failures=${soak_failures_field#failures=}
                case "$soak_worker_requests:$soak_worker_failures" in
                    *[!0-9:]*|:*)
                        NGINX_SOAK_WORKER_SUMMARY_FAILURES=$((NGINX_SOAK_WORKER_SUMMARY_FAILURES + 1))
                        ;;
                    *)
                        NGINX_SOAK_REQUESTS_COMPLETED=$((NGINX_SOAK_REQUESTS_COMPLETED + soak_worker_requests))
                        NGINX_SOAK_REQUEST_FAILURES=$((NGINX_SOAK_REQUEST_FAILURES + soak_worker_failures))
                        ;;
                esac
                ;;
            *)
                NGINX_SOAK_WORKER_SUMMARY_FAILURES=$((NGINX_SOAK_WORKER_SUMMARY_FAILURES + 1))
                ;;
        esac
        rm -f "$soak_worker_summary"
        soak_worker_index=$((soak_worker_index + 1))
    done
    rmdir "$NGINX_SOAK_WORKER_DIR" >/dev/null 2>&1 || true
}

write_bounded_soak_summary() {
    soak_summary_status=$1
    soak_server_alive=$2
    {
        printf 'stage=%s\n' "$MSCONNECTOR_SMOKE_STAGE_BOUNDED_SOAK"
        printf 'case=%s\n' "$case_name"
        printf 'duration_seconds=%s\n' "$NGINX_SOAK_DURATION_SECONDS"
        printf 'concurrency=%s\n' "$NGINX_SOAK_CONCURRENCY"
        printf 'requests_completed=%s\n' "$NGINX_SOAK_REQUESTS_COMPLETED"
        printf 'request_failures=%s\n' "$NGINX_SOAK_REQUEST_FAILURES"
        printf 'worker_summary_failures=%s\n' "$NGINX_SOAK_WORKER_SUMMARY_FAILURES"
        printf 'server_alive=%s\n' "$soak_server_alive"
        printf 'status=%s\n' "$soak_summary_status"
    } > "$NGINX_SOAK_SUMMARY_FILE"
}

run_bounded_soak() {
    require_bounded_positive_decimal "$NGINX_SOAK_DURATION_SECONDS" \
        NGINX_SOAK_DURATION_SECONDS 300
    require_bounded_positive_decimal "$NGINX_SOAK_CONCURRENCY" \
        NGINX_SOAK_CONCURRENCY 16
    NGINX_SOAK_SUMMARY_FILE="$LOG_DIR/nginx-bounded-soak-summary.txt"
    NGINX_SOAK_WORKER_DIR="$RUNTIME_ROOT/bounded-soak-workers"
    require_absolute_generated_path "$NGINX_SOAK_WORKER_DIR" "NGINX_SOAK_WORKER_DIR"
    mkdir -p "$NGINX_SOAK_WORKER_DIR"
    NGINX_SOAK_DEADLINE=$(( $(date +%s) + NGINX_SOAK_DURATION_SECONDS ))
    NGINX_SOAK_WORKER_PIDS=""

    soak_worker_index=1
    while [ "$soak_worker_index" -le "$NGINX_SOAK_CONCURRENCY" ]; do
        run_bounded_soak_worker "$soak_worker_index" "$NGINX_SOAK_DEADLINE" &
        NGINX_SOAK_WORKER_PIDS="${NGINX_SOAK_WORKER_PIDS}${NGINX_SOAK_WORKER_PIDS:+ }$!"
        soak_worker_index=$((soak_worker_index + 1))
    done

    NGINX_SOAK_WORKER_FAILURES=0
    for soak_worker_pid in $NGINX_SOAK_WORKER_PIDS; do
        set +e
        wait "$soak_worker_pid"
        soak_worker_rc=$?
        set -e
        if [ "$soak_worker_rc" -ne 0 ]; then
            NGINX_SOAK_WORKER_FAILURES=$((NGINX_SOAK_WORKER_FAILURES + 1))
        fi
    done
    NGINX_SOAK_WORKER_PIDS=""
    collect_bounded_soak_worker_summaries

    soak_server_alive=0
    if [ -n "${NGINX_PID:-}" ] && kill -0 "$NGINX_PID" >/dev/null 2>&1; then
        soak_server_alive=1
    fi
    if [ "$NGINX_SOAK_WORKER_FAILURES" -ne 0 ] || \
       [ "$NGINX_SOAK_REQUEST_FAILURES" -ne 0 ] || \
       [ "$NGINX_SOAK_WORKER_SUMMARY_FAILURES" -ne 0 ]; then
        write_bounded_soak_summary fail "$soak_server_alive"
        fail "bounded soak worker failures detected"
    fi
    if [ "$soak_server_alive" -ne 1 ]; then
        write_bounded_soak_summary fail "$soak_server_alive"
        fail "NGINX did not remain alive after bounded soak"
    fi
    write_bounded_soak_summary pass "$soak_server_alive"
}

quote_request_path() {
    request_path=$1
    "$PYTHON_BIN" - "$request_path" <<'PY'
import sys
from urllib.parse import quote

print(quote(sys.argv[1], safe="/:?&=%+$,;@[]!'()*"))
PY
}

response_header_backend_needed() {
    [ "$MSCONNECTOR_FULL_LIFECYCLE_SYNC" = "1" ] && return 0
    grep -Eqi '(^|[^[:alnum:]_])RESPONSE_HEADERS([[:space:]:]|$)' "$RULES_FILE"
}

start_response_header_backend() {
    if [ "$MSCONNECTOR_FULL_LIFECYCLE_SYNC" = "1" ]; then
        start_synchronized_upstream
        RESPONSE_HEADER_BACKEND_PORT="$SYNCHRONIZED_UPSTREAM_PORT"
        return 0
    fi
    if phase4_reload_overlap_sync_enabled; then
        start_synchronized_upstream
        PHASE4_RELOAD_OVERLAP_UPSTREAM_PORT="$SYNCHRONIZED_UPSTREAM_PORT"
    fi
    response_header_backend_needed || return 0
    RESPONSE_HEADER_BACKEND_PORT=$(select_free_port $((PORT + 1000)) "$PORT_SEARCH_LIMIT") || \
        blocked "no free response-header backend port found"
    "$PYTHON_BIN" "$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/common/response-header-test-backend.py" \
        --port "$RESPONSE_HEADER_BACKEND_PORT" \
        --body-file "$DOCROOT/index.html" \
        --safe-root "$RUNTIME_ROOT" \
        --safe-root "$DOCROOT" \
        --fixture-file "$RESPONSE_HEADER_FIXTURE_FILE" \
        >"$LOG_DIR/response-header-backend.stdout.log" \
        2>"$LOG_DIR/response-header-backend.stderr.log" &
    RESPONSE_HEADER_BACKEND_PID=$!
    wait_tcp_port "$RESPONSE_HEADER_BACKEND_PORT" || blocked "response-header backend failed to start"
}

write_phase4_reload_overlap_directives() {
    output=$1
    [ ! -e "$output" ] && [ ! -L "$output" ] || \
        fail "phase4 reload-overlap directives output is unexpectedly occupied: $output"
    if phase4_reload_overlap_sync_enabled; then
        [ -n "${PHASE4_RELOAD_OVERLAP_UPSTREAM_PORT:-}" ] || \
            fail "phase4 reload-overlap upstream did not publish a port"
        {
            echo "# Dedicated paused loopback upstream for the reload-overlap assertion."
            echo "proxy_pass http://127.0.0.1:$PHASE4_RELOAD_OVERLAP_UPSTREAM_PORT;"
            echo "proxy_buffering off;"
            echo "proxy_set_header Host \$host;"
        } > "$output"
        return 0
    fi
    {
        echo "limit_rate 1024;"
        printf 'root "%s";\n' "$DOCROOT"
        echo "try_files /__modsec_slow_stream =404;"
    } > "$output"
}

write_location_handler_directives() {
    output=$1
    : > "$output"
    if response_header_backend_needed; then
        {
            echo "# Generated proxy route for response-header smoke cases."
            echo "proxy_pass http://127.0.0.1:$RESPONSE_HEADER_BACKEND_PORT;"
            # The synchronized first-byte proof observes a client-visible
            # chunk while the upstream is paused.  NGINX's default proxy
            # buffering can defer that chunk until EOS, which would test its
            # buffer policy rather than the connector's forwarding path.
            if [ "$MSCONNECTOR_FULL_LIFECYCLE_SYNC" = "1" ]; then
                echo "proxy_buffering off;"
            fi
            echo "proxy_set_header Host \$host;"
        } > "$output"
        return 0
    fi
    {
        echo "error_page 405 =200 /index.html;"
        echo "try_files \$uri \$uri/ /index.html;"
    } > "$output"
}

require_crs_preamble_if_needed() {
    if [ "$MODSECURITY_TEST_VARIANT" = "with-crs" ] && [ -z "$MODSECURITY_RULE_PREAMBLE_FILE" ]; then
        blocked "MODSECURITY_RULE_PREAMBLE_FILE is required for MODSECURITY_TEST_VARIANT=with-crs; run make test-with-crs or make prepare-crs"
    fi
}

initialize_nginx_harness_paths
prepare_bounded_soak_selection
require_crs_preamble_if_needed

if [ "$RUN_ONE_CASE" != "1" ]; then
    run_all_cases
fi

if [ -z "$TEST_CASE" ]; then
    TEST_CASE="phase2_args_block"
fi
TEST_CASE=$(resolve_case_path "$TEST_CASE") || exit 1
case_name=$(basename "$TEST_CASE" .yaml)
if [ -z "$RUNTIME_ROOT" ]; then
    RUNTIME_ROOT="$RUNTIME_BASE/$case_name"
fi
NGINX_WORKER_STATE_ROOT="$NGINX_HARNESS_WORK_ROOT/worker-state/$case_name"
NGINX_SERVER_LOG_ROOT="$NGINX_HARNESS_WORK_ROOT/server-logs/$case_name"
NGINX_MEMCHECK_EVIDENCE_DIR="$LOG_DIR/memcheck-evidence/$case_name"
STATUS_FILE="$LOG_DIR/status.txt"
PERMISSIONS_LOG="${PERMISSIONS_LOG:-$LOG_DIR/permissions.log}"
NGINX_WORKER_PREFLIGHT_FILE="${NGINX_WORKER_PREFLIGHT_FILE:-$LOG_DIR/nginx-worker-preflight.jsonl}"
RUNTIME_PID_FILE="$RUNTIME_ROOT/nginx.pid"
NGINX_LIFECYCLE_ROLE_FILE="$LOG_DIR/nginx-process-roles.txt"
NGINX_LIFECYCLE_FILE="$LOG_DIR/nginx-lifecycle.txt"

validate_nginx_protocol_request
validate_nginx_docroot_projection_mode
require_absolute_generated_path "$BUILD_ROOT" "BUILD_ROOT"
require_absolute_generated_path "$NGINX_BUILD_DIR" "NGINX_BUILD_DIR"
require_absolute_generated_path "$NGINX_PREFIX" "NGINX_PREFIX"
require_absolute_generated_path "$RUNTIME_ROOT" "RUNTIME_ROOT"
require_absolute_generated_path "$LOG_DIR" "LOG_DIR"
require_absolute_generated_path "$NGINX_WORKER_STATE_ROOT" "NGINX_WORKER_STATE_ROOT"
require_absolute_generated_path "$NGINX_SERVER_LOG_ROOT" "NGINX_SERVER_LOG_ROOT"
require_absolute_generated_path "$NGINX_MEMCHECK_EVIDENCE_DIR" "NGINX_MEMCHECK_EVIDENCE_DIR"
if [ "$NGINX_DOCROOT_PROJECTION" = "1" ]; then
    require_absolute_generated_path "$NGINX_DOCROOT_PROJECTION_PARENT" "NGINX_DOCROOT_PROJECTION_PARENT"
    require_absolute_generated_path "$NGINX_DOCROOT_PROJECTION_ROOT" "NGINX_DOCROOT_PROJECTION_ROOT"
fi
validate_nginx_generated_path_authority
validate_nginx_external_projection_authority
require_private_worker_path_separation
validate_nginx_worker_isolation

echo "nginx_smoke: BUILD_ROOT=$BUILD_ROOT"
echo "nginx_smoke: NGINX_BUILD_DIR=$NGINX_BUILD_DIR"
echo "nginx_smoke: NGINX_PREFIX=$NGINX_PREFIX"
echo "nginx_smoke: NGINX_BINARY=$NGINX_BINARY"
echo "nginx_smoke: NGINX_MODULE=$NGINX_MODULE"
echo "nginx_smoke: NGINX_HARNESS_WORK_ROOT=$NGINX_HARNESS_WORK_ROOT"
echo "nginx_smoke: RUNTIME_ROOT=$RUNTIME_ROOT"
echo "nginx_smoke: LOG_DIR=$LOG_DIR"
echo "nginx_smoke: NGINX_WORKER_STATE_ROOT=$NGINX_WORKER_STATE_ROOT"
echo "nginx_smoke: NGINX_SERVER_LOG_ROOT=$NGINX_SERVER_LOG_ROOT"
echo "nginx_smoke: NGINX_MEMCHECK_EVIDENCE_DIR=$NGINX_MEMCHECK_EVIDENCE_DIR"
echo "nginx_smoke: TEST_CASE=$TEST_CASE"
echo "nginx_smoke: CASE_SCOPE=$CASE_SCOPE"
echo "nginx_smoke: MODSECURITY_TEST_VARIANT=$MODSECURITY_TEST_VARIANT"
echo "nginx_smoke: MSCONNECTOR_SMOKE_STAGE=$MSCONNECTOR_SMOKE_STAGE"
echo "nginx_smoke: NGINX_PROTOCOL_PROFILE=$NGINX_PROTOCOL_PROFILE"
echo "nginx_smoke: downstream_protocol=$NGINX_DOWNSTREAM_PROTOCOL"
echo "nginx_smoke: upstream_protocol=$NGINX_UPSTREAM_PROTOCOL"
echo "nginx_smoke: transport=$(nginx_downstream_transport)"
if [ -n "$MODSECURITY_RULE_PREAMBLE_FILE" ]; then
    echo "nginx_smoke: MODSECURITY_RULE_PREAMBLE_FILE=$MODSECURITY_RULE_PREAMBLE_FILE"
fi

ensure_dir_755 "$NGINX_HARNESS_WORK_ROOT" "$RUNTIME_BASE" \
    "$NGINX_HARNESS_WORK_ROOT/worker-state" \
    "$NGINX_HARNESS_WORK_ROOT/server-logs" \
    "$NGINX_HARNESS_WORK_ROOT/memcheck-evidence"
if [ "$CURRENT_UID" = "0" ]; then
    chown root:root "$NGINX_HARNESS_WORK_ROOT" \
        "$NGINX_HARNESS_WORK_ROOT/worker-state" \
        "$NGINX_HARNESS_WORK_ROOT/server-logs" \
        "$NGINX_HARNESS_WORK_ROOT/memcheck-evidence"
fi
chmod 711 "$NGINX_HARNESS_WORK_ROOT" \
    "$NGINX_HARNESS_WORK_ROOT/worker-state" \
    "$NGINX_HARNESS_WORK_ROOT/server-logs" \
    "$NGINX_HARNESS_WORK_ROOT/memcheck-evidence"
ensure_private_dir "$LOG_DIR" "$RUNTIME_ROOT" "$RUNTIME_ROOT/conf" \
    "$RUNTIME_ROOT/htdocs" "$NGINX_MEMCHECK_EVIDENCE_DIR" \
    "$NGINX_SERVER_LOG_ROOT" "$NGINX_SERVER_LOG_ROOT/audit"
# Keep audit targets root-private until CASE_CLI materialize succeeds below.
: > "$STATUS_FILE"
stop_stale_runtime_pid "$RUNTIME_PID_FILE"
rm -f "$LOG_DIR/configtest.log" \
	    "$LOG_DIR/nginx-version.log" \
	    "$LOG_DIR/nginx-http2-applicability.json" \
	    "$LOG_DIR/nginx-protocol-applicability.json" \
    "$LOG_DIR/curl-attack.err" \
    "$LOG_DIR/curl-ready.err" \
	    "$LOG_DIR/nginx.log" \
	    "$LOG_DIR/nginx-stdout.log" \
	    "$LOG_DIR/phase4.log" \
	    "$LOG_DIR/phase4-server.log" \
	    "$LOG_DIR/response-body.txt" \
	    "$LOG_DIR/nginx-bounded-soak-summary.txt" \
	    "$LOG_DIR/nginx-bounded-soak-categories.txt" \
	    "$LOG_DIR/nginx-memcheck-quit.log" \
	    "$NGINX_SERVER_LOG_ROOT/error.log" \
	    "$NGINX_SERVER_LOG_ROOT/access.log" \
	    "$NGINX_SERVER_LOG_ROOT/audit.log" \
	    "$NGINX_MEMCHECK_EVIDENCE_DIR/nginx-memcheck-lifecycle.txt" \
	    "$NGINX_MEMCHECK_EVIDENCE_DIR/nginx-memcheck-roles.txt" \
	    "$NGINX_MEMCHECK_EVIDENCE_DIR/nginx-memcheck-summary.json" \
	    "$NGINX_MEMCHECK_EVIDENCE_DIR/nginx-memcheck-summary.txt" \
	    "$RUNTIME_ROOT/nginx.pid"
if [ "$NGINX_LIFECYCLE_ENABLED" = "1" ]; then
    : > "$NGINX_LIFECYCLE_ROLE_FILE"
    : > "$NGINX_LIFECYCLE_FILE"
    chmod 600 "$NGINX_LIFECYCLE_ROLE_FILE" "$NGINX_LIFECYCLE_FILE"
fi
rm -f "$NGINX_MEMCHECK_EVIDENCE_DIR"/valgrind.*.log
rm -f "$NGINX_SERVER_LOG_ROOT"/audit/*

case "$MSCONNECTOR_SMOKE_STAGE" in
    config_load|start_smoke|minimal_runtime_smoke) ;;
    "$MSCONNECTOR_SMOKE_STAGE_BOUNDED_SOAK") ;;
    *) fail "unsupported MSCONNECTOR_SMOKE_STAGE=$MSCONNECTOR_SMOKE_STAGE" ;;
esac
validate_nginx_memcheck_mode
validate_nginx_lifecycle_mode

if [ "$MSCONNECTOR_SMOKE_STAGE" = "minimal_runtime_smoke" ] || \
   [ "$MSCONNECTOR_SMOKE_STAGE" = "$MSCONNECTOR_SMOKE_STAGE_BOUNDED_SOAK" ]; then
    CURL_BIN=$(find_curl)
else
    CURL_BIN=
fi

[ -x "$NGINX_BINARY" ] || blocked "missing executable NGINX binary: $NGINX_BINARY"
[ -f "$NGINX_MODULE" ] || blocked "missing NGINX ModSecurity dynamic module: $NGINX_MODULE"
record_nginx_protocol_applicability
verify_nginx_protocol_build
if [ "$MSCONNECTOR_SMOKE_STAGE" = "minimal_runtime_smoke" ] || \
   [ "$MSCONNECTOR_SMOKE_STAGE" = "$MSCONNECTOR_SMOKE_STAGE_BOUNDED_SOAK" ]; then
    [ -n "$CURL_BIN" ] || blocked "missing curl; set CURL=/path/to/curl"
    [ -x "$CURL_BIN" ] || blocked "curl is not executable: $CURL_BIN"
fi
[ -f "$MODSECURITY_RUNTIME_LIBRARY" ] || \
    blocked "missing staged libmodsecurity runtime library: $MODSECURITY_RUNTIME_LIBRARY"
if [ "$NGINX_HOSTED_FUNCTIONAL_A" = "1" ] && [ -L "$MODSECURITY_RUNTIME_LIBRARY" ]; then
    blocked "hosted functional-A runtime library must not be a symlink: $MODSECURITY_RUNTIME_LIBRARY"
fi

CONFIG_FILE="$RUNTIME_ROOT/conf/nginx.conf"
RULES_FILE="$RUNTIME_ROOT/conf/modsecurity-smoke.conf"
PRIVATE_DOCROOT="$RUNTIME_ROOT/htdocs"
DOCROOT="$PRIVATE_DOCROOT"
RESPONSE_BODY="$LOG_DIR/response-body.txt"
CASE_ENV_FILE="$RUNTIME_ROOT/conf/case.env"
REQUEST_HEADERS_FILE="$RUNTIME_ROOT/conf/request-headers.txt"
REQUEST_BODY_FILE="$RUNTIME_ROOT/conf/request-body.bin"
AUDIT_LOG_FILE="$NGINX_SERVER_LOG_ROOT/audit.log"
AUDIT_LOG_DIR="$NGINX_SERVER_LOG_ROOT/audit"
NGINX_LOCATION_DIRECTIVES_FILE="$RUNTIME_ROOT/conf/nginx-location-directives.conf"
NGINX_LOCATION_HANDLER_DIRECTIVES_FILE="$RUNTIME_ROOT/conf/nginx-location-handler-directives.conf"
NGINX_PHASE4_RELOAD_OVERLAP_DIRECTIVES_FILE="$RUNTIME_ROOT/conf/nginx-phase4-reload-overlap-directives.conf"
NGINX_PHASE4_LOG_FILE="$LOG_DIR/phase4.log"
NGINX_PHASE4_LOG_SERVER_FILE="$LOG_DIR/phase4-server.log"
RESPONSE_HEADER_FIXTURE_FILE="$RUNTIME_ROOT/conf/response-header-fixture.json"
NGINX_PROTOCOL_LISTEN_DIRECTIVES_FILE="$RUNTIME_ROOT/conf/nginx-protocol-listen.conf"
NGINX_PROTOCOL_SERVER_DIRECTIVES_FILE="$RUNTIME_ROOT/conf/nginx-protocol-server.conf"
NGINX_TLS_SERVER_CERT="$RUNTIME_ROOT/conf/nginx-test-server.crt"
NGINX_TLS_SERVER_KEY="$RUNTIME_ROOT/conf/nginx-test-server.key"
NGINX_TLS_CA_CERT="$RUNTIME_ROOT/conf/nginx-test-ca.crt"
NGINX_TLS_CA_KEY="$RUNTIME_ROOT/conf/nginx-test-ca.key"
NGINX_TLS_SERVER_CSR="$RUNTIME_ROOT/conf/nginx-test-server.csr"
NGINX_TLS_SERVER_EXT="$RUNTIME_ROOT/conf/nginx-test-server.ext"
NGINX_MEMCHECK_ROLE_FILE="$NGINX_MEMCHECK_EVIDENCE_DIR/nginx-memcheck-roles.txt"
NGINX_MEMCHECK_LIFECYCLE_FILE="$NGINX_MEMCHECK_EVIDENCE_DIR/nginx-memcheck-lifecycle.txt"
NGINX_MEMCHECK_SUMMARY_JSON="$NGINX_MEMCHECK_EVIDENCE_DIR/nginx-memcheck-summary.json"
NGINX_MEMCHECK_SUMMARY_TEXT="$NGINX_MEMCHECK_EVIDENCE_DIR/nginx-memcheck-summary.txt"

prepare_phase4_log_target

if ! "$PYTHON_BIN" "$CASE_CLI" materialize \
    --case "$TEST_CASE" \
    --rules-file "$RULES_FILE" \
    --env-file "$CASE_ENV_FILE" \
    --headers-file "$REQUEST_HEADERS_FILE" \
    --body-file "$REQUEST_BODY_FILE" \
	    --docroot "$PRIVATE_DOCROOT" \
	    --audit-log-file "$AUDIT_LOG_FILE" \
	    --audit-log-dir "$AUDIT_LOG_DIR" \
	    --rules-preamble-file "$MODSECURITY_RULE_PREAMBLE_FILE" \
	    --nginx-location-directives-file "$NGINX_LOCATION_DIRECTIVES_FILE" \
	    --nginx-runtime-config-dir "$RUNTIME_ROOT/conf" \
	    --nginx-phase4-log-file "$NGINX_PHASE4_LOG_FILE" > "$LOG_DIR/case-materialize.log" 2>&1; then
    not_executable "failed to materialize shared case; see $LOG_DIR/case-materialize.log"
fi
lock_private_runtime_paths
prepare_nginx_worker_paths
project_nginx_worker_docroot
if [ "$NGINX_DOCROOT_PROJECTION" = "1" ]; then
    echo "nginx_smoke: NGINX_DOCROOT_PROJECTION_ROOT=$NGINX_DOCROOT_PROJECTION_ROOT"
    echo "nginx_smoke: NGINX_DOCROOT_PROJECTION_PARENT=$NGINX_DOCROOT_PROJECTION_PARENT"
fi
if [ "$NGINX_HOSTED_FUNCTIONAL_A" = "1" ]; then
    load_functional_case_environment
else
    . "$CASE_ENV_FILE"
fi
apply_synchronized_phase4_policy
if [ "$NGINX_HOSTED_FUNCTIONAL_A" = "1" ] && \
   [ "$NGINX_FUNCTIONAL_A_QUERY_CANARY" = "1" ]; then
    case "$REQUEST_PATH" in
        *\?*) blocked "functional-A query canary requires a query-free case path" ;;
        *) REQUEST_PATH="${REQUEST_PATH}?nginx-functional-a-canary=must-redact" ;;
    esac
    export REQUEST_PATH
fi
if ! "$PYTHON_BIN" "$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/common/harness-case-metadata.py" response-header-fixture \
    --case "$TEST_CASE" \
    --framework-root "$FRAMEWORK_ROOT" \
    --output "$RESPONSE_HEADER_FIXTURE_FILE" > "$LOG_DIR/response-header-fixture.log" 2>&1; then
    not_executable "failed to materialize response-header backend fixture; see $LOG_DIR/response-header-fixture.log"
fi
start_response_header_backend
write_location_handler_directives "$NGINX_LOCATION_HANDLER_DIRECTIVES_FILE"
write_phase4_reload_overlap_directives "$NGINX_PHASE4_RELOAD_OVERLAP_DIRECTIVES_FILE"
lock_private_runtime_paths
prepare_nginx_worker_paths
preflight_nginx_worker_docroot

LD_LIBRARY_PATH="$MODSECURITY_LIB_DIR:$NGINX_PREFIX/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export LD_LIBRARY_PATH

cleanup_on_signal() {
    signal_name=$1
    signal_status=$2
    # exit below would otherwise run cleanup_on_exit as well, duplicating
    # process and artifact cleanup for one signal.
    trap - "$signal_name" EXIT
    cleanup || true
    exit "$signal_status"
}

cleanup_on_exit() {
    nginx_exit_status=$?
    trap - EXIT
    if ! cleanup && [ "$nginx_exit_status" -eq 0 ]; then
        exit 1
    fi
    exit "$nginx_exit_status"
}

trap cleanup_on_exit EXIT
trap 'cleanup_on_signal INT 130' INT
trap 'cleanup_on_signal TERM 143' TERM
start_server

if [ "$MSCONNECTOR_SMOKE_STAGE" = "config_load" ]; then
    echo "nginx_smoke: pass config_load (no process started, no request sent)"
    exit 0
fi
if [ "$MSCONNECTOR_SMOKE_STAGE" = "start_smoke" ]; then
    echo "nginx_smoke: pass start_smoke (request-free host liveness verified)"
    exit 0
fi

if [ "$MSCONNECTOR_SMOKE_STAGE" = "$MSCONNECTOR_SMOKE_STAGE_BOUNDED_SOAK" ]; then
    run_bounded_soak
    if ! finalize_nginx_memcheck; then
        fail "NGINX Memcheck reported an error or incomplete diagnostic; see $NGINX_MEMCHECK_SUMMARY_TEXT"
    fi
    echo "nginx_smoke: pass $MSCONNECTOR_SMOKE_STAGE_BOUNDED_SOAK case=$CASE_NAME"
    exit 0
fi

if [ "$MSCONNECTOR_FULL_LIFECYCLE_SYNC" = "1" ]; then
    send_synchronized_first_byte_request
    echo "nginx_smoke: pass synchronized-first-byte"
    exit 0
fi

set +e
http_status=$(send_case_request)
curl_rc=$?
set -e
observed_transport_result=http_status
if [ "$curl_rc" -ne 0 ]; then
    observed_transport_result=connection_aborted
fi
printf '%s\n' "$http_status" > "$LOG_DIR/observed-status.txt"
printf '%s\n' "$observed_transport_result" > "$LOG_DIR/observed-transport-result.txt"

if "$PYTHON_BIN" "$CASE_CLI" assert-status \
    --case "$TEST_CASE" \
	    --actual-status "$http_status" \
	    --observed-transport-result "$observed_transport_result" \
	    --response-body-file "$RESPONSE_BODY" \
	    --audit-log-file "$AUDIT_LOG_FILE" \
	    --phase4-log-file "$NGINX_PHASE4_LOG_FILE" \
	    --status-file "$STATUS_FILE" > "$LOG_DIR/case-assert.log" 2>&1; then
    if [ "$NGINX_PHASE4_LOG_LIFECYCLE_PROBE" = "1" ]; then
        exercise_phase4_log_lifecycle
    fi
    write_case_result "$TEST_CASE" pass "$http_status" "$LOG_DIR/result.json" "$observed_transport_result" || exit 1
    echo "nginx_smoke: pass case=$CASE_NAME status=$http_status"
    exit 0
fi

reason=$(cat "$LOG_DIR/case-assert.log" 2>/dev/null || true)
if [ "$curl_rc" -ne 0 ]; then
    reason="curl attack request failed rc=$curl_rc; $reason"
fi
write_case_result "$TEST_CASE" fail "$http_status" "$LOG_DIR/result.json" "$observed_transport_result" "$reason" || exit 1
if [ "$http_status" = "403" ] && nginx_docroot_permission_denied; then
    write_case_result "$TEST_CASE" blocked "$http_status" "$LOG_DIR/result.json" "$observed_transport_result" "NGINX could not read generated docroot" || exit 1
    write_permission_diagnostics
    blocked "NGINX could not read generated docroot; see $LOG_DIR/error.log and $LOG_DIR/permissions.log"
fi
echo "nginx_smoke: fail case=$CASE_NAME observed=$http_status expected=$EXPECT_STATUS"
exit 1
