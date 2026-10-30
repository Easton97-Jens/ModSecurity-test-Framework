#!/bin/sh
: "${TEST_ROOT:?TEST_ROOT is required explicitly}"
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CONNECTOR_ROOT="${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}"
FRAMEWORK_ROOT="${TEST_ROOT:?TEST_ROOT is required explicitly}"
VERIFIED_RUN_ROOT="${VERIFIED_RUN_ROOT:-${RUNNER_TEMP:-${TMPDIR:-/var/tmp}}/ModSecurity-conector-verified}"
VERIFIED_BUILD_ROOT="${VERIFIED_BUILD_ROOT:-$VERIFIED_RUN_ROOT/build}"
VERIFIED_SOURCE_ROOT="${VERIFIED_SOURCE_ROOT:-$VERIFIED_RUN_ROOT/src}"
VERIFIED_TMP_ROOT="${VERIFIED_TMP_ROOT:-$VERIFIED_RUN_ROOT/tmp}"
VERIFIED_LOG_ROOT="${VERIFIED_LOG_ROOT:-$VERIFIED_RUN_ROOT/logs}"
SOURCE_ROOT="${SOURCE_ROOT:-$VERIFIED_SOURCE_ROOT}"
SHARED_BUILD_ROOT="${BUILD_ROOT:-$VERIFIED_BUILD_ROOT}"
BUILD_ROOT="$SHARED_BUILD_ROOT"
TMP_ROOT="${TMP_ROOT:-$VERIFIED_TMP_ROOT}"
LOG_ROOT="${LOG_ROOT:-$VERIFIED_LOG_ROOT}"
VERIFIED_COMPONENT_CACHE="${VERIFIED_COMPONENT_CACHE:-$VERIFIED_RUN_ROOT/cache-v2/shared}"
CONNECTOR_COMPONENT_CACHE="${CONNECTOR_COMPONENT_CACHE:-$VERIFIED_COMPONENT_CACHE}"
CONNECTOR_BUILD_OWNER_ROOT="$CONNECTOR_COMPONENT_CACHE/builds/connectors"
MATRIX_ROOT="${MATRIX_ROOT:-$SHARED_BUILD_ROOT/full-matrix}"
MRTS_BUILD_ROOT="${MRTS_BUILD_ROOT:-$SHARED_BUILD_ROOT/mrts}"
PYTHON="${PYTHON:-python3}"
PYTHONDONTWRITEBYTECODE="${PYTHONDONTWRITEBYTECODE:-1}"
FORCE_ALL_CASES="${FORCE_ALL_CASES:-1}"
FULL_MATRIX_VARIANTS="${FULL_MATRIX_VARIANTS:-no-crs/no-mrts no-crs/with-mrts with-crs/no-mrts with-crs/with-mrts}"
FULL_MATRIX_CONNECTORS="${FULL_MATRIX_CONNECTORS:-apache nginx haproxy}"
FULL_MATRIX_REPORT_DIR="${FULL_MATRIX_REPORT_DIR:-$CONNECTOR_ROOT/reports/testing/generated}"
FULL_MATRIX_MANIFEST="${FULL_MATRIX_MANIFEST:-$MATRIX_ROOT/full-runtime-matrix-runs.jsonl}"
FULL_MATRIX_PORT_SPAN="${FULL_MATRIX_PORT_SPAN:-1000}"
FULL_MATRIX_PREPARE_SHARED_BUILDS="${FULL_MATRIX_PREPARE_SHARED_BUILDS:-1}"
FULL_MATRIX_PREPARE_CASE="${FULL_MATRIX_PREPARE_CASE:-action_allow_phase1_pass}"
FULL_MATRIX_TRUNCATE_MANIFEST="${FULL_MATRIX_TRUNCATE_MANIFEST:-1}"
FULL_MATRIX_SKIP_REPORTS="${FULL_MATRIX_SKIP_REPORTS:-0}"
FULL_MATRIX_PORT_PLANNER="$SCRIPT_DIR/plan_full_matrix_ports.py"
HAPROXY_SPOA_PORT_OFFSET="${HAPROXY_SPOA_PORT_OFFSET:-12000}"
HAPROXY_BACKEND_PORT_OFFSET="${HAPROXY_BACKEND_PORT_OFFSET:-24000}"
matrix_completion_wait_timeout="${VERIFIED_RUN_FULL_MATRIX_JOB_TIMEOUT_SECONDS:-3600}"
print_effective_parallelism=0

case "$#" in
    0) ;;
    1)
        if [ "$1" = "--print-effective-parallelism" ]; then
            print_effective_parallelism=1
        else
            echo "ERROR: unsupported full-matrix argument: $1" >&2
            exit 2
        fi
        ;;
    *)
        echo "ERROR: expected no arguments or --print-effective-parallelism" >&2
        exit 2
        ;;
esac

is_positive_decimal() {
    case "${1:-}" in
        ''|*[!0-9]*) return 1 ;;
        *[1-9]*) return 0 ;;
        *) return 1 ;;
    esac
}

normalize_positive_decimal() {
    normalized_decimal=$1
    while [ "${normalized_decimal#0}" != "$normalized_decimal" ]; do
        normalized_decimal=${normalized_decimal#0}
    done
    printf '%s\n' "$normalized_decimal"
}

detect_online_cpu_count() {
    detected_cpu_count=""
    if command -v nproc >/dev/null 2>&1; then
        detected_cpu_count=$(nproc 2>/dev/null || true)
    fi
    if ! is_positive_decimal "$detected_cpu_count" && command -v getconf >/dev/null 2>&1; then
        detected_cpu_count=$(getconf _NPROCESSORS_ONLN 2>/dev/null || true)
    fi
    if is_positive_decimal "$detected_cpu_count"; then
        normalize_positive_decimal "$detected_cpu_count"
        return 0
    fi
    printf '%s\n' 1
    return 0
}

parallelism_source=explicit
if [ "${FULL_MATRIX_MAX_PARALLEL_JOBS+x}" != x ]; then
    FULL_MATRIX_MAX_PARALLEL_JOBS=$(detect_online_cpu_count)
    parallelism_source=auto-detected
fi
if ! is_positive_decimal "$FULL_MATRIX_MAX_PARALLEL_JOBS"; then
    echo "ERROR: FULL_MATRIX_MAX_PARALLEL_JOBS must be a positive decimal integer: $FULL_MATRIX_MAX_PARALLEL_JOBS" >&2
    exit 2
fi
FULL_MATRIX_MAX_PARALLEL_JOBS=$(normalize_positive_decimal "$FULL_MATRIX_MAX_PARALLEL_JOBS")
if ! is_positive_decimal "$matrix_completion_wait_timeout"; then
    echo "ERROR: VERIFIED_RUN_FULL_MATRIX_JOB_TIMEOUT_SECONDS must be a positive decimal integer: $matrix_completion_wait_timeout" >&2
    exit 2
fi
matrix_completion_wait_timeout=$(normalize_positive_decimal "$matrix_completion_wait_timeout")

if [ "$print_effective_parallelism" -eq 1 ]; then
    echo "full-matrix-parallel: effective parallel job cap=$FULL_MATRIX_MAX_PARALLEL_JOBS source=$parallelism_source"
    exit 0
fi

export CONNECTOR_ROOT FRAMEWORK_ROOT SOURCE_ROOT BUILD_ROOT TMP_ROOT LOG_ROOT CONNECTOR_COMPONENT_CACHE PYTHONDONTWRITEBYTECODE FORCE_ALL_CASES MRTS_BUILD_ROOT

"$PYTHON" "$SCRIPT_DIR/prepare-verified-runtime-paths.py" --build-root "$SHARED_BUILD_ROOT" || exit 77

REPO_ROOT="$CONNECTOR_ROOT"
. "$FRAMEWORK_ROOT/ci/lib/common.sh"

validate_runner_paths() {
    assert_safe_runtime_path "$SHARED_BUILD_ROOT" SHARED_BUILD_ROOT || exit 77
    assert_safe_runtime_path "$TMP_ROOT" TMP_ROOT || exit 77
    assert_safe_runtime_path "$LOG_ROOT" LOG_ROOT || exit 77
    assert_safe_runtime_path "$CONNECTOR_COMPONENT_CACHE" CONNECTOR_COMPONENT_CACHE || exit 77
    assert_safe_runtime_path "$CONNECTOR_BUILD_OWNER_ROOT" CONNECTOR_BUILD_OWNER_ROOT || exit 77
    assert_safe_runtime_path "$MATRIX_ROOT" MATRIX_ROOT || exit 77
    assert_safe_runtime_path "$MRTS_BUILD_ROOT" MRTS_BUILD_ROOT || exit 77
    assert_safe_runtime_path "$NGINX_HARNESS_PARENT" NGINX_HARNESS_PARENT || exit 77
    assert_not_system_path_for_write "$FULL_MATRIX_REPORT_DIR" FULL_MATRIX_REPORT_DIR || exit 77
    assert_not_system_path_for_write "$FULL_MATRIX_MANIFEST" FULL_MATRIX_MANIFEST || exit 77
}

connector_build_root_for() {
    connector=$1

    case "$connector" in
        apache) printf '%s\n' "${APACHE_BUILD_ROOT:-$SHARED_BUILD_ROOT/apache-build}" ;;
        nginx) printf '%s\n' "${NGINX_BUILD_DIR:-$SHARED_BUILD_ROOT/nginx-build}" ;;
        *) echo "ERROR: no cache-backed build root for connector: $connector" >&2; return 2 ;;
    esac
    return 0
}

validate_connector_build_root() {
    connector=$1
    connector_build_root=$2

    assert_runtime_path_under_root \
        "$connector_build_root" \
        "$CONNECTOR_BUILD_OWNER_ROOT" \
        "$connector matrix build root"
}

run_cache_backed_connector() {
    connector=$1
    port=$2
    connector_build_root=$(connector_build_root_for "$connector") || return $?

    validate_connector_build_root "$connector" "$connector_build_root" >> "$run_log" 2>&1 || return 77

    case "$connector" in
        apache)
            smoke_target=smoke-apache
            set -- \
                "APACHE_TEST_PORT=$port" \
                "APACHE_BUILD_ROOT=$connector_build_root" \
                "APACHE_BUILD_OWNER_ROOT=$CONNECTOR_BUILD_OWNER_ROOT" \
                "HTTPD_PREFIX=${HTTPD_PREFIX:-}" \
                "APACHE_MODULE=${APACHE_MODULE:-}" \
                "MODSECURITY_LIB_DIR=${APACHE_MRTS_MODSECURITY_LIB_DIR:-${MODSECURITY_LIB_DIR:-}}" \
                "APACHE_BUILD_LOG_DIR=$job_log_root/apache-build" \
                "APACHE_RUNTIME_LOG_DIR=$job_log_root/apache-runtime"
            ;;
        nginx)
            nginx_harness_parent="${NGINX_HARNESS_PARENT:-$TMP_ROOT/nginx-harness}"
            nginx_harness_root="$nginx_harness_parent/ModSecurity-conector-full-matrix"
            nginx_harness_root="$nginx_harness_root/$test_variant-$mrts_variant-nginx-$port"
            nginx_module="${MRTS_NATIVE_NGINX_MODULE_FILE:-${MRTS_NATIVE_NGINX_MODULE_DIR:-}/ngx_http_modsecurity_module.so}"
            smoke_target=smoke-nginx
            set -- \
                "NGINX_TEST_PORT=$port" \
                "NGINX_BUILD_DIR=$connector_build_root" \
                "NGINX_BUILD_OWNER_ROOT=$CONNECTOR_BUILD_OWNER_ROOT" \
                "NGINX_PREFIX=${NGINX_PREFIX:-}" \
                "NGINX_BINARY=${MRTS_NATIVE_NGINX_BIN:-}" \
                "NGINX_MODULE=$nginx_module" \
                "MODSECURITY_LIB_DIR=${MRTS_NATIVE_NGINX_MODSECURITY_LIB_DIR:-${MODSECURITY_LIB_DIR:-}}" \
                "NGINX_HARNESS_PARENT=$nginx_harness_parent" \
                "NGINX_HARNESS_WORK_ROOT=$nginx_harness_root" \
                "NGINX_RUNTIME_BASE=$nginx_harness_root/runtime" \
                "NGINX_RUNTIME_LOG_DIR=$nginx_harness_root/logs"
            ;;
        *)
            echo "ERROR: unsupported cache-backed connector: $connector" >> "$run_log"
            return 2
            ;;
    esac

    env $common_env "$@" make -C "$CONNECTOR_ROOT" "$smoke_target" >> "$run_log" 2>&1
}

active_jobs=""
matrix_lock_held=0
matrix_completion_fifo=""
matrix_completion_fd_open=0
matrix_completion_watchdog_pid=""
matrix_completion_wait_generation=0
port_check_blocked=0

terminate_jobs() {
    for active_job in $active_jobs; do
        pid=${active_job#*:}
        kill "$pid" >/dev/null 2>&1 || true
    done
    return 0
}

stop_matrix_completion_watchdog() {
    if [ -n "$matrix_completion_watchdog_pid" ]; then
        kill "$matrix_completion_watchdog_pid" >/dev/null 2>&1 || true
        wait "$matrix_completion_watchdog_pid" >/dev/null 2>&1 || true
        matrix_completion_watchdog_pid=""
    fi
    return 0
}

start_matrix_completion_watchdog() {
    stop_matrix_completion_watchdog
    matrix_completion_wait_generation=$((matrix_completion_wait_generation + 1))
    watchdog_generation=$matrix_completion_wait_generation
    (
        # The watchdog reports through FD 8 only.  It must not prolong the
        # scheduler's FD-9 lock if the scheduler parent is killed.
        exec 9>&- || true
        watchdog_sleep_pid=""
        stop_watchdog_sleep() {
            if [ -n "$watchdog_sleep_pid" ]; then
                kill "$watchdog_sleep_pid" >/dev/null 2>&1 || true
            fi
            exit 0
        }
        trap stop_watchdog_sleep INT TERM HUP
        sleep "$matrix_completion_wait_timeout" &
        watchdog_sleep_pid=$!
        if wait "$watchdog_sleep_pid"; then
            printf 'timeout:%s\n' "$watchdog_generation" >&8
        fi
    ) &
    matrix_completion_watchdog_pid=$!
    return 0
}

release_matrix_completion_queue() {
    stop_matrix_completion_watchdog
    if [ "$matrix_completion_fd_open" = "1" ]; then
        exec 8>&- || true
        matrix_completion_fd_open=0
    fi
    if [ -n "$matrix_completion_fifo" ] && [ -p "$matrix_completion_fifo" ]; then
        safe_rm_rf "$matrix_completion_fifo" "$MATRIX_ROOT" "full-matrix completion FIFO" || true
    fi
    matrix_completion_fifo=""
    return 0
}

release_matrix_lock() {
    if [ "$matrix_lock_held" = "1" ]; then
        exec 9>&- || true
        matrix_lock_held=0
    fi
    return 0
}

cleanup_matrix_run() {
    terminate_jobs
    release_matrix_completion_queue
    release_matrix_lock
}

safe_rm_rf() {
    target=$1
    parent=$2
    label=$3

    safe_remove_runtime_path "$target" "$parent" "$label"
    return $?
}

acquire_matrix_lock() {
    candidate="$MATRIX_ROOT/.full-matrix-run.lock"
    assert_safe_runtime_path "$candidate" "full-matrix run lock" || return 77
    if [ -L "$candidate" ]; then
        echo "ERROR: full-matrix run lock must not be a symbolic link: $candidate" >&2
        return 77
    fi
    if ! command -v flock >/dev/null 2>&1; then
        echo "ERROR: full-matrix scheduler requires flock" >&2
        return 77
    fi
    previous_umask=$(umask)
    umask 077
    if exec 9>>"$candidate"; then
        umask "$previous_umask"
    else
        umask "$previous_umask"
        echo "ERROR: cannot open full-matrix run lock: $candidate" >&2
        return 77
    fi
    if ! flock -n 9; then
        exec 9>&- || true
        echo "ERROR: another full-matrix run owns $candidate" >&2
        return 77
    fi
    matrix_lock_held=1
    return 0
}

prepare_matrix_completion_queue() {
    candidate="$MATRIX_ROOT/.full-matrix-completions.fifo"
    assert_safe_runtime_path "$candidate" "full-matrix completion FIFO" || return 77
    if [ -L "$candidate" ]; then
        echo "ERROR: full-matrix completion FIFO must not be a symbolic link: $candidate" >&2
        return 77
    fi
    if [ -e "$candidate" ]; then
        if [ ! -p "$candidate" ]; then
            echo "ERROR: unexpected full-matrix completion queue type: $candidate" >&2
            return 77
        fi
        safe_rm_rf "$candidate" "$MATRIX_ROOT" "stale full-matrix completion FIFO" || return 77
    fi
    previous_umask=$(umask)
    umask 077
    if mkfifo "$candidate"; then
        umask "$previous_umask"
    else
        umask "$previous_umask"
        echo "ERROR: cannot create full-matrix completion FIFO: $candidate" >&2
        return 77
    fi
    if exec 8<>"$candidate"; then
        matrix_completion_fifo="$candidate"
        matrix_completion_fd_open=1
        return 0
    fi
    echo "ERROR: cannot open full-matrix completion FIFO: $candidate" >&2
    safe_rm_rf "$candidate" "$MATRIX_ROOT" "full-matrix completion FIFO" || true
    return 77
}

trap cleanup_matrix_run 0
trap 'exit 77' INT TERM

validate_matrix_connectors() {
    seen_connectors=""
    for connector in $FULL_MATRIX_CONNECTORS; do
        case "$connector" in
            apache|nginx|haproxy) ;;
            *) echo "ERROR: unsupported FULL_MATRIX_CONNECTORS item: $connector" >&2; return 2 ;;
        esac
        case " $seen_connectors " in
            *" $connector "*)
                echo "ERROR: duplicate FULL_MATRIX_CONNECTORS item: $connector" >&2
                return 2
                ;;
        esac
        seen_connectors="$seen_connectors $connector"
    done
    return 0
}

validate_matrix_variants() {
    seen_variants=""
    for variant in $FULL_MATRIX_VARIANTS; do
        case "$variant" in
            no-crs/no-mrts|no-crs/with-mrts|with-crs/no-mrts|with-crs/with-mrts) ;;
            *) echo "ERROR: unsupported FULL_MATRIX_VARIANTS item: $variant" >&2; return 2 ;;
        esac
        case " $seen_variants " in
            *" $variant "*)
                echo "ERROR: duplicate FULL_MATRIX_VARIANTS item: $variant" >&2
                return 2
                ;;
        esac
        seen_variants="$seen_variants $variant"
    done
    return 0
}

summary_path_for() {
    results_dir=$1
    connector=$2

    printf '%s/%s-summary.json\n' "$results_dir" "$connector"
    return 0
}

shared_connector_ready() {
    connector=$1

    case "$connector" in
        apache)
            [ -x "${APACHE_HTTPD:-}" ] &&
                [ -f "${APACHE_MODULE:-}" ] &&
                [ -f "${APACHE_MRTS_MODSECURITY_LIB_DIR:-}/libmodsecurity.so" ]
            ;;
        nginx)
            [ -x "${MRTS_NATIVE_NGINX_BIN:-}" ] &&
                [ -f "${MRTS_NATIVE_NGINX_MODULE_DIR:-}/ngx_http_modsecurity_module.so" ] &&
                [ -f "${MRTS_NATIVE_NGINX_MODSECURITY_LIB_DIR:-${MODSECURITY_LIB_DIR:-}}/libmodsecurity.so" ]
            ;;
        haproxy)
            [ -x "${HAPROXY_BIN:-}" ] &&
                [ -x "${SPOA_RUNTIME_BIN:-}" ] &&
                [ -f "${MODSECURITY_BINDING_DIR:-}/paths.env" ]
            ;;
        *) return 1 ;;
    esac
}

prepare_shared_connector() {
    connector=$1
    if shared_connector_ready "$connector"; then
        return 0
    fi
    echo "full-matrix-parallel: prepared $connector build artifacts missing; runtime job will block without building"
    return 0
}

write_job_build_manifest() {
    manifest_path=$1
    connector=$2
    "$PYTHON" - "$manifest_path" "$connector" <<'PY'
import json
import os
import sys
from pathlib import Path

path = Path(sys.argv[1])
connector = sys.argv[2]
connector_id_env = {
    "apache": "APACHE_CONNECTOR_BUILD_ID",
    "nginx": "NGINX_CONNECTOR_BUILD_ID",
    "haproxy": "HAPROXY_CONNECTOR_BUILD_ID",
}.get(connector, "")
payload = {
    "connector": connector,
    "modsecurity_build_id": os.environ.get("MODSECURITY_BUILD_ID", ""),
    "modsecurity_prefix": os.environ.get("MODSECURITY_PREFIX", ""),
    "connector_build_id": os.environ.get(connector_id_env, ""),
    "runtime_build_cache_manifest": os.environ.get("RUNTIME_BUILD_CACHE_MANIFEST", ""),
    "prepared_only": os.environ.get("RUNTIME_COMPONENTS_PREPARED_ONLY", ""),
}
path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

prepare_shared_builds() {
    for connector in $FULL_MATRIX_CONNECTORS; do
        prepare_shared_connector "$connector"
    done
    return 0
}

matrix_case_count() {
    connector=$1
    case_cli="$FRAMEWORK_ROOT/tests/runners/case_cli.py"
    case_scope="${CASE_SCOPE:-all}"
    if [ ! -f "$case_cli" ]; then
        echo "ERROR: missing matrix case selector: $case_cli" >&2
        return 2
    fi
    if [ -n "${TEST_CASE:-}" ]; then
        if ! selected_cases=$("$PYTHON" "$case_cli" list-cases \
            --repo-root "$CONNECTOR_ROOT" \
            --framework-root "$FRAMEWORK_ROOT" \
            --connector-root "$CONNECTOR_ROOT" \
            --connector "$connector" \
            --scope "$case_scope" \
            --test-case "$TEST_CASE"); then
            echo "ERROR: cannot select $connector matrix cases" >&2
            return 2
        fi
    elif [ -n "${SMOKE_CASES:-}" ]; then
        if ! selected_cases=$("$PYTHON" "$case_cli" list-cases \
            --repo-root "$CONNECTOR_ROOT" \
            --framework-root "$FRAMEWORK_ROOT" \
            --connector-root "$CONNECTOR_ROOT" \
            --connector "$connector" \
            --scope "$case_scope" \
            --smoke-cases "$SMOKE_CASES"); then
            echo "ERROR: cannot select $connector matrix cases" >&2
            return 2
        fi
    elif ! selected_cases=$("$PYTHON" "$case_cli" list-cases \
        --repo-root "$CONNECTOR_ROOT" \
        --framework-root "$FRAMEWORK_ROOT" \
        --connector-root "$CONNECTOR_ROOT" \
        --connector "$connector" \
        --scope "$case_scope"); then
        echo "ERROR: cannot select $connector matrix cases" >&2
        return 2
    fi
    case_count=$(printf '%s\n' "$selected_cases" | awk 'NF { count += 1 } END { print count + 0 }')
    if ! is_positive_decimal "$case_count"; then
        echo "ERROR: no selected $connector matrix cases" >&2
        return 2
    fi
    normalize_positive_decimal "$case_count"
    return 0
}

write_matrix_port_plan() {
    matrix_port_plan=$1
    case "${NO_CRS_BASELINE:-}" in
        1|true|TRUE|yes|YES|on|ON)
            if [ -n "${NO_CRS_SELECTED_CASE_IDS:-}" ]; then
                echo "ERROR: full-matrix global parallelism requires the canonical case selector" >&2
                return 2
            fi
            ;;
        *)
            # Other baseline values do not enable the optional selector guard.
            :
            ;;
    esac
    set -- "$PYTHON" "$FULL_MATRIX_PORT_PLANNER" \
        --port-span "$FULL_MATRIX_PORT_SPAN" \
        --haproxy-spoa-offset "$HAPROXY_SPOA_PORT_OFFSET" \
        --haproxy-backend-offset "$HAPROXY_BACKEND_PORT_OFFSET"
    for connector in $FULL_MATRIX_CONNECTORS; do
        case_count=$(matrix_case_count "$connector") || return $?
        set -- "$@" --case-count "$connector=$case_count"
    done
    for variant in $FULL_MATRIX_VARIANTS; do
        for connector in $FULL_MATRIX_CONNECTORS; do
            set -- "$@" --job "$variant:$connector"
        done
    done
    "$@" > "$matrix_port_plan"
}

all_matrix_connectors_ready() {
    for connector in $FULL_MATRIX_CONNECTORS; do
        if ! shared_connector_ready "$connector"; then
            return 1
        fi
    done
    return 0
}

prepare_batch() {
    test_variant=$1
    mrts_variant=$2
    batch_root="$MATRIX_ROOT/$test_variant/$mrts_variant/_batch"
    assert_safe_runtime_path "$batch_root" "matrix batch root" || return 77
    mkdir -p "$batch_root"
    if [ "$mrts_variant" = "with-mrts" ]; then
        echo "full-matrix-parallel: preparing MRTS for $test_variant/$mrts_variant"
        env \
            FRAMEWORK_ROOT="$FRAMEWORK_ROOT" \
            CONNECTOR_ROOT="$CONNECTOR_ROOT" \
            SOURCE_ROOT="$SOURCE_ROOT" \
            BUILD_ROOT="$SHARED_BUILD_ROOT" \
            MRTS_BUILD_ROOT="$MRTS_BUILD_ROOT" \
            TMP_ROOT="$SHARED_BUILD_ROOT/tmp" \
            LOG_ROOT="$SHARED_BUILD_ROOT/logs" \
            MODSECURITY_TEST_VARIANT="$test_variant" \
            MODSECURITY_MRTS_VARIANT="$mrts_variant" \
            MODSECURITY_MRTS_PREPARED=0 \
            PYTHONDONTWRITEBYTECODE="$PYTHONDONTWRITEBYTECODE" \
            sh -eu -c '. "$FRAMEWORK_ROOT/ci/lib/common.sh"; . "$FRAMEWORK_ROOT/ci/lib/mrts-common.sh"; prepare_mrts_runtime_variant' \
            > "$batch_root/mrts-prepare.log" 2>&1 || \
            echo "full-matrix-parallel: MRTS prepare failed for $test_variant/$mrts_variant; jobs will block using prepared-mode checks"
    fi
    if [ "$test_variant" = "with-crs" ]; then
        echo "full-matrix-parallel: fetching CRS source for $test_variant/$mrts_variant"
        env \
            FRAMEWORK_ROOT="$FRAMEWORK_ROOT" \
            CONNECTOR_ROOT="$CONNECTOR_ROOT" \
            SOURCE_ROOT="$SOURCE_ROOT" \
            BUILD_ROOT="$SHARED_BUILD_ROOT" \
            MRTS_BUILD_ROOT="$MRTS_BUILD_ROOT" \
            TMP_ROOT="$SHARED_BUILD_ROOT/tmp" \
            LOG_ROOT="$SHARED_BUILD_ROOT/logs" \
            PYTHONDONTWRITEBYTECODE="$PYTHONDONTWRITEBYTECODE" \
            sh "$FRAMEWORK_ROOT/ci/provisioning/fetch-crs.sh" > "$batch_root/crs-fetch.log" 2>&1 || \
            echo "full-matrix-parallel: CRS fetch failed for $test_variant/$mrts_variant; jobs may block"
    fi
    return 0
}

run_job() {
    test_variant=$1
    mrts_variant=$2
    connector=$3
    port=$4

    job_root="$MATRIX_ROOT/$test_variant/$mrts_variant/$connector"
    job_build_root="$job_root"
    job_tmp_root="$job_root/tmp"
    job_log_root="$job_root/logs"
    results_dir="$job_root/results"
    run_log="$job_root/run.log"
    exit_code_file="$job_root/exit.code"
    summary_path_file="$job_root/summary.path"
    job_json="$job_root/job.json"
    build_manifest="$job_root/build-manifest.json"
    summary_path=$(summary_path_for "$results_dir" "$connector")

    assert_safe_runtime_path "$job_root" "matrix job root" || return 77
    assert_safe_runtime_path "$job_tmp_root" "matrix job tmp root" || return 77
    assert_safe_runtime_path "$job_log_root" "matrix job log root" || return 77
    assert_safe_runtime_path "$results_dir" "matrix job results root" || return 77
    assert_not_system_path_for_write "$run_log" "matrix run log" || return 77
    assert_not_system_path_for_write "$job_json" "matrix job json" || return 77
    assert_not_system_path_for_write "$build_manifest" "matrix build manifest" || return 77
    safe_rm_rf "$job_root" "$MATRIX_ROOT" "matrix job root"
    mkdir -p "$job_build_root" "$job_tmp_root" "$job_log_root" "$results_dir"
    : > "$run_log"
    printf '%s\n' "$summary_path" > "$summary_path_file"

    started_epoch=$(date +%s)
    started_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    prepared_flag=0
    job_refresh=0
    if [ "$mrts_variant" = "with-mrts" ]; then
        prepared_flag=1
    fi
    if ! shared_connector_ready "$connector"; then
        job_refresh=1
    fi

    echo "full-matrix-parallel: job start connector=$connector variant=$test_variant/$mrts_variant port=$port" >> "$run_log"
    RUNTIME_COMPONENTS_PREPARED_ONLY=1
    export RUNTIME_COMPONENTS_PREPARED_ONLY
    write_job_build_manifest "$build_manifest" "$connector"

    common_env="FRAMEWORK_ROOT=$FRAMEWORK_ROOT CONNECTOR_ROOT=$CONNECTOR_ROOT SOURCE_ROOT=$SOURCE_ROOT BUILD_ROOT=$job_build_root MRTS_BUILD_ROOT=$MRTS_BUILD_ROOT TMP_ROOT=$job_tmp_root LOG_ROOT=$job_log_root RESULTS_DIR=$results_dir CONNECTOR_COMPONENT_CACHE=$CONNECTOR_COMPONENT_CACHE MODSECURITY_TEST_VARIANT=$test_variant MODSECURITY_MRTS_VARIANT=$mrts_variant MODSECURITY_MRTS_PREPARED=$prepared_flag FORCE_ALL_CASES=$FORCE_ALL_CASES PYTHONDONTWRITEBYTECODE=$PYTHONDONTWRITEBYTECODE PORT=$port PORT_SEARCH_LIMIT=$FULL_MATRIX_PORT_SPAN PORT_RETRY_LIMIT=1 REFRESH=$job_refresh AUTO_REFRESH_STALE_BUILD=0 CRS_RUNTIME_DIR=$job_build_root/crs MRTS_LOAD_FILE=$MRTS_BUILD_ROOT/upstream-config-tests/mrts.load SKIP_RUNTIME_COMPONENT_PREPARE=1 RUNTIME_COMPONENTS_PREPARED_ONLY=1"

    set +e
    case "$connector" in
        apache|nginx)
            run_cache_backed_connector "$connector" "$port"
            rc=$?
            ;;
        haproxy)
            env $common_env \
                TMP_ROOT="$job_tmp_root" \
                LOG_ROOT="$job_log_root" \
                RESULTS_DIR="$results_dir" \
                HAPROXY_TEST_PORT="$port" \
                TEST_BACKEND_PORT=$((port + 500)) \
                HAPROXY_SPOA_PORT_OFFSET="$HAPROXY_SPOA_PORT_OFFSET" \
                HAPROXY_BACKEND_PORT_OFFSET="$HAPROXY_BACKEND_PORT_OFFSET" \
                HAPROXY_RUNTIME_BUILD_DIR="${HAPROXY_RUNTIME_BUILD_DIR:-$SHARED_BUILD_ROOT/haproxy-runtime-build}" \
                HAPROXY_RUNTIME_DIR="${HAPROXY_RUNTIME_DIR:-$SHARED_BUILD_ROOT/haproxy-runtime/haproxy}" \
                HAPROXY_BIN="${HAPROXY_BIN:-}" \
                SPOA_RUNTIME_BIN="${SPOA_RUNTIME_BIN:-}" \
                MODSECURITY_BINDING_DIR="${MODSECURITY_BINDING_DIR:-}" \
                LOG_DIR="$job_log_root/haproxy-runtime" \
                RUNTIME_BASE="$job_build_root/haproxy-runtime-cases" \
                make -C "$CONNECTOR_ROOT" smoke-haproxy >> "$run_log" 2>&1
            rc=$?
            ;;
        *)
            rc=2
            echo "unsupported connector: $connector" >> "$run_log"
            ;;
    esac
    set -eu
    ended_epoch=$(date +%s)
    ended_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    duration=$((ended_epoch - started_epoch))
    actual_summary_path=$summary_path
    if [ ! -f "$actual_summary_path" ] && [ -f "$results_dir/force-all/$connector-summary.json" ]; then
        actual_summary_path="$results_dir/force-all/$connector-summary.json"
    fi
    results_jsonl="$results_dir/force-all/$connector-results.jsonl"
    printf '%s\n' "$actual_summary_path" > "$summary_path_file"
    printf '%s\n' "$rc" > "$exit_code_file"
    echo "full-matrix-parallel: job end connector=$connector variant=$test_variant/$mrts_variant rc=$rc duration=$duration" >> "$run_log"

    RUN_CONNECTOR="$connector" \
    RUN_TEST_VARIANT="$test_variant" \
    RUN_MRTS_VARIANT="$mrts_variant" \
    RUN_RC="$rc" \
    RUN_STARTED_AT="$started_at" \
    RUN_ENDED_AT="$ended_at" \
    RUN_DURATION="$duration" \
    RUN_RESULTS_DIR="$results_dir" \
    RUN_SUMMARY_PATH="$actual_summary_path" \
    RUN_RESULTS_JSONL="$results_jsonl" \
    RUN_LOG_PATH="$run_log" \
    RUN_JOB_JSON="$job_json" \
    RUN_BUILD_MANIFEST="$build_manifest" \
    RUN_VERIFIED_RUN_ID="${VERIFIED_RUN_ID:-}" \
    "$PYTHON" - <<'PY' > "$job_json"
import hashlib
import json
import os
from pathlib import Path

def sha256(path):
    p = Path(path)
    if not p.is_file():
        return "missing"
    h = hashlib.sha256()
    with p.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

connector = os.environ["RUN_CONNECTOR"]
test_variant = os.environ["RUN_TEST_VARIANT"]
mrts_variant = os.environ["RUN_MRTS_VARIANT"]
rc = int(os.environ["RUN_RC"])

print(json.dumps({
    "connector": connector,
    "job_id": f"{connector}:{test_variant}:{mrts_variant}",
    "verified_run_id": os.environ.get("RUN_VERIFIED_RUN_ID", ""),
    "test_variant": test_variant,
    "mrts_variant": mrts_variant,
    "return_code": rc,
    "status": "completed" if rc == 0 else "completed_with_mismatches",
    "started_at": os.environ["RUN_STARTED_AT"],
    "ended_at": os.environ["RUN_ENDED_AT"],
    "duration_seconds": int(os.environ["RUN_DURATION"]),
    "results_dir": os.environ["RUN_RESULTS_DIR"],
    "summary_path": os.environ["RUN_SUMMARY_PATH"],
    "log_path": os.environ["RUN_LOG_PATH"],
    "hashes": {
        "log": sha256(os.environ["RUN_LOG_PATH"]),
        "summary": sha256(os.environ["RUN_SUMMARY_PATH"]),
        "build_manifest": sha256(os.environ["RUN_BUILD_MANIFEST"]),
        "results_jsonl": sha256(os.environ["RUN_RESULTS_JSONL"]),
    },
    "inputs": {
        "build_manifest": os.environ["RUN_BUILD_MANIFEST"],
    },
    "outputs": {
        "job_json": os.environ["RUN_JOB_JSON"],
        "log": os.environ["RUN_LOG_PATH"],
        "summary": os.environ["RUN_SUMMARY_PATH"],
        "results_dir": os.environ["RUN_RESULTS_DIR"],
        "results_jsonl": os.environ["RUN_RESULTS_JSONL"],
    },
}, sort_keys=True))
PY
    return "$rc"
}

append_job_json() {
    job_json=$1
    if [ -f "$job_json" ]; then
        cat "$job_json" >> "$FULL_MATRIX_MANIFEST"
        printf '\n' >> "$FULL_MATRIX_MANIFEST"
    fi
    return 0
}

collect_batch_ports() {
    ports_file=$1
    shift
    : > "$ports_file"
    for log_path in "$@"; do
        if [ -f "$log_path" ]; then
            sed -n 's/.*port=\([0-9][0-9]*\).*/\1/p' "$log_path" >> "$ports_file" || true
        fi
    done
    sort -u "$ports_file" -o "$ports_file"
    return 0
}

check_ports_free() {
    ports_file=$1
    [ -s "$ports_file" ] || return 0
    "$PYTHON" - "$ports_file" <<'PY'
import socket
import sys
from pathlib import Path

busy = []
for raw in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    if not raw.strip():
        continue
    port = int(raw.strip())
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("127.0.0.1", port))
    except OSError:
        busy.append(port)
    finally:
        sock.close()
if busy:
    print("busy ports after batch: " + " ".join(map(str, busy)), file=sys.stderr)
    sys.exit(1)
PY
    return 0
}

wait_active_jobs() {
    waited_rc=0
    for active_job in $active_jobs; do
        pid=${active_job#*:}
        if ! wait "$pid"; then
            waited_rc=1
        fi
    done
    active_jobs=""
    return "$waited_rc"
}

run_job_and_report_completion() {
    completion_token=$1
    shift

    if run_job "$@"; then
        job_rc=0
    else
        job_rc=$?
    fi
    if ! printf 'complete:%s\n' "$completion_token" >&8; then
        echo "ERROR: cannot report full-matrix job completion token=$completion_token" >&2
        return 77
    fi
    return "$job_rc"
}

wait_one_parallel_job() {
    start_matrix_completion_watchdog
    while :; do
        if ! IFS= read -r completion_event <&8; then
            stop_matrix_completion_watchdog
            echo "ERROR: cannot read full-matrix job completion" >&2
            return 2
        fi
        case "$completion_event" in
            complete:*)
                completed_token=${completion_event#complete:}
                stop_matrix_completion_watchdog
                break
                ;;
            timeout:*)
                timeout_generation=${completion_event#timeout:}
                if ! is_positive_decimal "$timeout_generation"; then
                    stop_matrix_completion_watchdog
                    echo "ERROR: invalid full-matrix completion timeout event: $completion_event" >&2
                    return 2
                fi
                if [ "$timeout_generation" = "$matrix_completion_wait_generation" ]; then
                    wait "$matrix_completion_watchdog_pid" >/dev/null 2>&1 || true
                    matrix_completion_watchdog_pid=""
                    echo "ERROR: full-matrix job completion timed out after $matrix_completion_wait_timeout seconds" >&2
                    return 2
                fi
                ;;
            *)
                stop_matrix_completion_watchdog
                echo "ERROR: invalid full-matrix completion event: $completion_event" >&2
                return 2
                ;;
        esac
    done
    if ! is_positive_decimal "$completed_token"; then
        echo "ERROR: invalid full-matrix completion token: $completed_token" >&2
        return 2
    fi

    completed_pid=""
    remaining_jobs=""
    completion_matches=0
    for active_job in $active_jobs; do
        active_token=${active_job%%:*}
        active_pid=${active_job#*:}
        if [ "$active_token" = "$completed_token" ]; then
            completed_pid=$active_pid
            completion_matches=$((completion_matches + 1))
        else
            remaining_jobs="$remaining_jobs $active_job"
        fi
    done
    if [ "$completion_matches" -ne 1 ] || [ -z "$completed_pid" ]; then
        echo "ERROR: unexpected full-matrix completion token: $completed_token" >&2
        return 2
    fi
    active_jobs=$remaining_jobs
    if ! wait "$completed_pid"; then
        return 1
    fi
    return 0
}

run_planned_jobs() {
    matrix_port_plan=$1
    execution_mode=$2
    active_count=0
    job_sequence=0
    planned_rc=0
    planned_job_jsons=""
    planned_logs=""
    tab=$(printf '\t')

    if [ "$execution_mode" = "parallel" ]; then
        prepare_matrix_completion_queue || return 77
    fi

    while IFS="$tab" read -r test_variant connector port; do
        [ -n "$test_variant" ] || continue
        case "$test_variant/$connector" in
            no-crs/no-mrts/apache|no-crs/no-mrts/nginx|no-crs/no-mrts/haproxy|\
            no-crs/with-mrts/apache|no-crs/with-mrts/nginx|no-crs/with-mrts/haproxy|\
            with-crs/no-mrts/apache|with-crs/no-mrts/nginx|with-crs/no-mrts/haproxy|\
            with-crs/with-mrts/apache|with-crs/with-mrts/nginx|with-crs/with-mrts/haproxy) ;;
            *)
                echo "ERROR: invalid full-matrix port-plan entry: $test_variant/$connector" >&2
                return 2
                ;;
        esac
        if ! is_positive_decimal "$port" || [ "$port" -gt 65000 ]; then
            echo "ERROR: invalid full-matrix port-plan port: $port" >&2
            return 2
        fi
        mrts_variant=${test_variant#*/}
        test_variant=${test_variant%/*}
        job_root="$MATRIX_ROOT/$test_variant/$mrts_variant/$connector"
        job_sequence=$((job_sequence + 1))
        if [ "$execution_mode" = "parallel" ]; then
            run_job_and_report_completion "$job_sequence" "$test_variant" "$mrts_variant" "$connector" "$port" &
        else
            run_job "$test_variant" "$mrts_variant" "$connector" "$port" &
        fi
        pid=$!
        active_jobs="$active_jobs $job_sequence:$pid"
        planned_job_jsons="$planned_job_jsons $job_root/job.json"
        planned_logs="$planned_logs $job_root/run.log"
        active_count=$((active_count + 1))
        echo "full-matrix-parallel: spawned pid=$pid connector=$connector variant=$test_variant/$mrts_variant port=$port"

        if [ "$execution_mode" != "parallel" ]; then
            if ! wait_active_jobs; then
                planned_rc=1
            fi
            active_count=0
            continue
        fi

        if [ "$active_count" -lt "$FULL_MATRIX_MAX_PARALLEL_JOBS" ]; then
            continue
        fi
        if wait_one_parallel_job; then
            wait_rc=0
        else
            wait_rc=$?
        fi
        if [ "$wait_rc" -gt 1 ]; then
            terminate_jobs
            wait_active_jobs || true
            return 77
        fi
        if [ "$wait_rc" -ne 0 ]; then
            planned_rc=1
        fi
        active_count=$((active_count - 1))
    done < "$matrix_port_plan"

    while [ "$execution_mode" = "parallel" ] && [ "$active_count" -gt 0 ]; do
        if wait_one_parallel_job; then
            wait_rc=0
        else
            wait_rc=$?
        fi
        if [ "$wait_rc" -gt 1 ]; then
            terminate_jobs
            wait_active_jobs || true
            return 77
        fi
        if [ "$wait_rc" -ne 0 ]; then
            planned_rc=1
        fi
        active_count=$((active_count - 1))
    done
    release_matrix_completion_queue

    for job_json in $planned_job_jsons; do
        append_job_json "$job_json"
    done

    ports_file="$MATRIX_ROOT/used-ports.txt"
    collect_batch_ports "$ports_file" $planned_logs
    if ! check_ports_free "$ports_file" > "$MATRIX_ROOT/port-check.log" 2>&1; then
        port_check_blocked=1
        echo "full-matrix-parallel: port cleanup check failed; see $MATRIX_ROOT/port-check.log"
    fi
    return "$planned_rc"
}

validate_matrix_connectors || exit $?
validate_matrix_variants || exit $?
validate_runner_paths
mkdir -p "$MATRIX_ROOT" "$FULL_MATRIX_REPORT_DIR"
acquire_matrix_lock || exit $?
if [ "$FULL_MATRIX_TRUNCATE_MANIFEST" = "1" ]; then
    : > "$FULL_MATRIX_MANIFEST"
else
    mkdir -p "$(dirname "$FULL_MATRIX_MANIFEST")"
    touch "$FULL_MATRIX_MANIFEST"
fi

prepare_shared_builds
matrix_port_plan="$MATRIX_ROOT/full-matrix-port-plan.tsv"
write_matrix_port_plan "$matrix_port_plan" || exit $?

for variant in $FULL_MATRIX_VARIANTS; do
    test_variant=${variant%/*}
    mrts_variant=${variant#*/}
    echo "full-matrix-parallel: preparing $test_variant/$mrts_variant"
    prepare_batch "$test_variant" "$mrts_variant"
done

matrix_rc=0
if all_matrix_connectors_ready; then
    echo "full-matrix-parallel: scheduling up to $FULL_MATRIX_MAX_PARALLEL_JOBS isolated runtime jobs (source=$parallelism_source)"
    if run_planned_jobs "$matrix_port_plan" parallel; then
        :
    else
        run_planned_jobs_rc=$?
        if [ "$run_planned_jobs_rc" -eq 77 ]; then
            exit 77
        fi
        matrix_rc=2
    fi
else
    echo "full-matrix-parallel: cache artifacts are not all ready; keeping planned runtime jobs serial"
    if run_planned_jobs "$matrix_port_plan" serial; then
        :
    else
        run_planned_jobs_rc=$?
        if [ "$run_planned_jobs_rc" -eq 77 ]; then
            exit 77
        fi
        matrix_rc=2
    fi
fi

if [ "$FULL_MATRIX_SKIP_REPORTS" = "1" ]; then
    echo "full-matrix-parallel: skip downstream report generation (FULL_MATRIX_SKIP_REPORTS=1)"
    echo "full-matrix-parallel: manifest=$FULL_MATRIX_MANIFEST"
    exit "$matrix_rc"
fi

set +e
"$PYTHON" "$TEST_ROOT/connector_suite/modsecurity_connector_ci/evidence/reports/generate-full-runtime-matrix.py" \
    --connector-root "$CONNECTOR_ROOT" \
    --framework-root "$FRAMEWORK_ROOT" \
    --build-root "$MATRIX_ROOT" \
    --log-root "$MATRIX_ROOT" \
    --manifest "$FULL_MATRIX_MANIFEST" \
    --output-dir "$FULL_MATRIX_REPORT_DIR"
report_rc=$?

"$PYTHON" "$FRAMEWORK_ROOT/ci/reporting/generate-connector-work-queue.py" \
    --connector-root "$CONNECTOR_ROOT" \
    --framework-root "$FRAMEWORK_ROOT" \
    --output-root "$CONNECTOR_ROOT" \
    --full-runtime-matrix "$FULL_MATRIX_REPORT_DIR/canonical/full-runtime-matrix.generated.json"
work_queue_rc=$?

"$PYTHON" "$FRAMEWORK_ROOT/ci/reporting/generate-phase-work-queue.py" \
    --connector-root "$CONNECTOR_ROOT" \
    --framework-root "$FRAMEWORK_ROOT" \
    --output-root "$CONNECTOR_ROOT" \
    --connector-work-queue "$FULL_MATRIX_REPORT_DIR/work-queues/connector-work-queue.generated.json" \
    --phase-coverage "$FULL_MATRIX_REPORT_DIR/coverage/phase-coverage.generated.md" \
    --full-runtime-matrix "$FULL_MATRIX_REPORT_DIR/canonical/full-runtime-matrix.generated.json"
phase_work_queue_rc=$?

"$PYTHON" "$TEST_ROOT/connector_suite/modsecurity_connector_ci/evidence/reports/generate-nolog-audit-evidence-analysis.py" \
    --connector-root "$CONNECTOR_ROOT" \
    --framework-root "$FRAMEWORK_ROOT" \
    --output-dir "$FULL_MATRIX_REPORT_DIR"
nolog_audit_evidence_rc=$?

"$PYTHON" "$TEST_ROOT/connector_suite/modsecurity_connector_ci/evidence/reports/generate-response-header-hook-analysis.py" \
    --connector-root "$CONNECTOR_ROOT" \
    --framework-root "$FRAMEWORK_ROOT" \
    --output-dir "$FULL_MATRIX_REPORT_DIR"
response_header_hook_rc=$?

"$PYTHON" "$TEST_ROOT/connector_suite/modsecurity_connector_ci/evidence/reports/generate-remaining-failure-analysis.py" \
    --connector-root "$CONNECTOR_ROOT" \
    --output-dir "$FULL_MATRIX_REPORT_DIR"
remaining_failure_analysis_rc=$?
set -eu

echo "full-matrix-parallel: manifest=$FULL_MATRIX_MANIFEST"
echo "full-matrix-parallel: report=$FULL_MATRIX_REPORT_DIR/canonical/full-runtime-matrix.generated.md"
echo "full-matrix-parallel: work_queue=$FULL_MATRIX_REPORT_DIR/work-queues/connector-work-queue.generated.md"
echo "full-matrix-parallel: phase_work_queue=$FULL_MATRIX_REPORT_DIR/work-queues/phase-work-queue.generated.md"
echo "full-matrix-parallel: response_header_hook=$FULL_MATRIX_REPORT_DIR/focused-analysis/response-header-hook-analysis.generated.md"
echo "full-matrix-parallel: remaining_failure_analysis=$FULL_MATRIX_REPORT_DIR/canonical/remaining-failure-analysis.generated.md"

if [ "$report_rc" -ne 0 ] || [ "$work_queue_rc" -ne 0 ] || [ "$phase_work_queue_rc" -ne 0 ] || [ "$nolog_audit_evidence_rc" -ne 0 ] || [ "$response_header_hook_rc" -ne 0 ] || [ "$remaining_failure_analysis_rc" -ne 0 ]; then
    exit 2
fi

"$PYTHON" - "$FULL_MATRIX_REPORT_DIR/canonical/full-runtime-matrix.generated.json" "$port_check_blocked" <<'PY'
import json
import sys
from pathlib import Path

data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
port_blocked = int(sys.argv[2])
has_fail = False
has_blocked = bool(port_blocked)
for run in data.get("runs", []):
    if run.get("fail", 0) or run.get("outcome") == "FAIL":
        has_fail = True
    if run.get("blocked", 0) or run.get("missing_summary"):
        has_blocked = True
if has_fail:
    sys.exit(2)
if has_blocked:
    sys.exit(77)
sys.exit(0)
PY
