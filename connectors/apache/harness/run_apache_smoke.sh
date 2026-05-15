#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd "$SCRIPT_DIR/../../.." && pwd)
BUILD_ROOT="${BUILD_ROOT:-/src/ModSecurity-test-Framework-build}"
APACHE_BUILD_ROOT="${APACHE_BUILD_ROOT:-$BUILD_ROOT/apache-build}"
LOG_DIR="${LOG_DIR:-$BUILD_ROOT/logs/apache-runtime}"
RESULTS_DIR="${RESULTS_DIR:-$BUILD_ROOT/results}"
RUNTIME_BASE="${RUNTIME_BASE:-$BUILD_ROOT/apache-runtime}"
RUNTIME_ROOT="${RUNTIME_ROOT:-}"
HTTPD_PREFIX="${HTTPD_PREFIX:-$BUILD_ROOT/apache-runtime/httpd}"
MODSECURITY_V3_DIR="${MODSECURITY_V3_DIR:-$APACHE_BUILD_ROOT/ModSecurity_V3}"
MODSECURITY_LIB_DIR="${MODSECURITY_LIB_DIR:-$APACHE_BUILD_ROOT/output/modsecurity/lib}"
PCRE2_PREFIX="${PCRE2_PREFIX:-$APACHE_BUILD_ROOT/output/pcre2}"
APACHE_MODULE="${APACHE_MODULE:-$APACHE_BUILD_ROOT/output/apache/mod_security3.so}"
APACHE_HTTPD_BIN="${APACHE_HTTPD:-${APACHE:-$HTTPD_PREFIX/bin/httpd}}"
APXS_BIN="${APXS:-$HTTPD_PREFIX/bin/apxs}"
CURL_BIN="${CURL:-}"
PYTHON_BIN="${PYTHON:-python3}"
PYTHONDONTWRITEBYTECODE="${PYTHONDONTWRITEBYTECODE:-1}"
export PYTHONDONTWRITEBYTECODE
BASE_PORT="${PORT:-18080}"
PORT="$BASE_PORT"
TEMPLATE="$SCRIPT_DIR/apache_smoke.conf"
TEST_CASE="${TEST_CASE:-}"
SMOKE_CASES="${SMOKE_CASES:-}"
CASE_SCOPE="${CASE_SCOPE:-all}"
CASE_CLI="$REPO_ROOT/tests/runners/case_cli.py"
RUN_ONE_CASE="${RUN_ONE_CASE:-0}"
STATUS_FILE="$LOG_DIR/status.txt"
IFMODULE_END="</IfModule>"

blocked() {
    echo "apache_smoke: blocked $*"
    mkdir -p "$LOG_DIR"
    echo "blocked: $*" >> "$STATUS_FILE"
    exit 77
}

fail() {
    echo "apache_smoke: fail $*"
    mkdir -p "$LOG_DIR"
    echo "fail: $*" >> "$STATUS_FILE"
    exit 1
}

require_absolute_generated_path() {
    path=$1
    label=$2
    case "$path" in
        /*) ;;
        *) blocked "$label must be absolute: $path" ;;
    esac
    case "$path" in
        "$REPO_ROOT"|"$REPO_ROOT"/*|/root/conecter/*)
            blocked "$label is inside a read-only or source checkout: $path"
            ;;
        *) ;;
    esac
}

resolve_case_path() {
    item=$1
    "$PYTHON_BIN" "$CASE_CLI" list-cases \
        --repo-root "$REPO_ROOT" \
        --connector apache \
        --scope "$CASE_SCOPE" \
        --test-case "$item"
}

list_case_files() {
    args="--repo-root $REPO_ROOT --connector apache --scope $CASE_SCOPE"
    if [ -n "$TEST_CASE" ]; then
        "$PYTHON_BIN" "$CASE_CLI" list-cases \
            --repo-root "$REPO_ROOT" \
            --connector apache \
            --scope "$CASE_SCOPE" \
            --test-case "$TEST_CASE"
        return
    fi
    if [ -n "$SMOKE_CASES" ]; then
        "$PYTHON_BIN" "$CASE_CLI" list-cases \
            --repo-root "$REPO_ROOT" \
            --connector apache \
            --scope "$CASE_SCOPE" \
            --smoke-cases "$SMOKE_CASES"
        return
    fi
    # shellcheck disable=SC2086
    "$PYTHON_BIN" "$CASE_CLI" list-cases $args
}

write_case_result() {
    case_path=$1
    case_status=$2
    actual_status=${3:-}
    output=$4
    if [ -n "$actual_status" ]; then
        "$PYTHON_BIN" "$CASE_CLI" case-info \
            --case "$case_path" \
            --connector apache \
            --status "$case_status" \
            --actual-status "$actual_status" \
            --output "$output"
    else
        "$PYTHON_BIN" "$CASE_CLI" case-info \
            --case "$case_path" \
            --connector apache \
            --status "$case_status" \
            --output "$output"
    fi
}

run_all_cases() {
    require_absolute_generated_path "$BUILD_ROOT" "BUILD_ROOT"
    require_absolute_generated_path "$LOG_DIR" "LOG_DIR"
    require_absolute_generated_path "$RESULTS_DIR" "RESULTS_DIR"
    require_absolute_generated_path "$RUNTIME_BASE" "RUNTIME_BASE"

    mkdir -p "$LOG_DIR" "$RESULTS_DIR"
    summary_file="$RESULTS_DIR/apache-summary.txt"
    json_file="$RESULTS_DIR/apache-summary.json"
    results_jsonl="$RESULTS_DIR/apache-results.jsonl"
    connector_summary="$RESULTS_DIR/connector-summary.txt"
    : > "$summary_file"
    : > "$results_jsonl"

    cases=$(list_case_files) || exit 1
    if [ -z "$cases" ]; then
        echo "apache_smoke: fail no shared smoke cases found" >&2
        exit 1
    fi

    any_fail=0
    any_blocked=0
    index=0
    for case_path in $cases; do
        case_name=$(basename "$case_path" .yaml)
        case_log_dir="$LOG_DIR/$case_name"
        case_runtime="$RUNTIME_BASE/$case_name"
        case_port=$((BASE_PORT + index))
        echo "apache_smoke: running case=$case_name port=$case_port"
        set +e
        RUN_ONE_CASE=1 \
            TEST_CASE="$case_path" \
            LOG_DIR="$case_log_dir" \
            RUNTIME_ROOT="$case_runtime" \
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
        elif [ "$rc" -ne 0 ]; then
            case_status=fail
            case_status_upper=FAIL
            any_fail=1
        fi
        actual_status=""
        if [ -f "$case_log_dir/observed-status.txt" ]; then
            actual_status=$(cat "$case_log_dir/observed-status.txt")
        fi
        write_case_result "$case_path" "$case_status" "$actual_status" "$case_log_dir/result.json" || true
        if [ -f "$case_log_dir/result.json" ]; then
            cat "$case_log_dir/result.json" >> "$results_jsonl"
        fi
        echo "$case_status_upper $case_name" | tee -a "$summary_file"
        index=$((index + 1))
    done

    "$PYTHON_BIN" "$CASE_CLI" summarize-results \
        --connector apache \
        --input-jsonl "$results_jsonl" \
        --summary-json "$json_file" \
        --summary-text "$summary_file" \
        --import-status-file "$REPO_ROOT/tests/import-status.json" \
        --connector-path real-world \
        --validation-mode real-world-connector-path \
        --server apache \
        --server-binary "$APACHE_HTTPD_BIN" \
        --module "$APACHE_MODULE" \
        --libmodsecurity "$MODSECURITY_LIB_DIR/libmodsecurity.so"
    cp "$summary_file" "$connector_summary"

    if [ "$any_fail" -ne 0 ]; then
        exit 1
    fi
    if [ "$any_blocked" -ne 0 ]; then
        exit 77
    fi
    exit 0
}

find_apache() {
    if [ -n "$APACHE_HTTPD_BIN" ]; then
        printf '%s\n' "$APACHE_HTTPD_BIN"
    fi
}

find_apxs() {
    if [ -n "$APXS_BIN" ]; then
        printf '%s\n' "$APXS_BIN"
    fi
}

find_curl() {
    if [ -n "$CURL_BIN" ]; then
        printf '%s\n' "$CURL_BIN"
        return 0
    fi
    command -v curl 2>/dev/null || true
}

apache_modules_dir() {
    if [ -n "$APXS_BIN" ] && [ -x "$APXS_BIN" ]; then
        dir=$("$APXS_BIN" -q LIBEXECDIR 2>/dev/null || true)
        if [ -n "$dir" ]; then
            printf '%s\n' "$dir"
            return 0
        fi
        libdir=$("$APXS_BIN" -q LIBDIR 2>/dev/null || true)
        if [ -n "$libdir" ]; then
            printf '%s/modules\n' "$libdir"
            return 0
        fi
    fi
    return 1
}

append_load_if_exists() {
    module_name=$1
    file_name=$2
    modules_dir=$3
    output=$4
    module_path="$modules_dir/$file_name"
    if [ -f "$module_path" ]; then
            {
                echo "<IfModule !$module_name>"
                echo "LoadModule $module_name \"$module_path\""
                echo "$IFMODULE_END"
            } >> "$output"
    fi
}

append_mpm_if_needed() {
    modules_dir=$1
    output=$2
    for candidate in \
        "mpm_event_module mod_mpm_event.so" \
        "mpm_worker_module mod_mpm_worker.so" \
        "mpm_prefork_module mod_mpm_prefork.so"
    do
        module_name=${candidate% *}
        file_name=${candidate#* }
        module_path="$modules_dir/$file_name"
        if [ -f "$module_path" ]; then
            {
                echo "<IfModule !mpm_event_module>"
                echo "<IfModule !mpm_worker_module>"
                echo "<IfModule !mpm_prefork_module>"
                echo "LoadModule $module_name \"$module_path\""
                echo "$IFMODULE_END"
                echo "$IFMODULE_END"
                echo "$IFMODULE_END"
            } >> "$output"
            return 0
        fi
    done
    return 0
}

escape_sed() {
    raw_value=$1
    printf '%s' "$raw_value" | sed 's/[&|]/\\&/g'
}

render_config() {
    sed \
        -e "s|@@RUNTIME_ROOT@@|$(escape_sed "$RUNTIME_ROOT")|g" \
        -e "s|@@PORT@@|$(escape_sed "$PORT")|g" \
        -e "s|@@MODULES_FILE@@|$(escape_sed "$MODULES_FILE")|g" \
        -e "s|@@APACHE_MODULE@@|$(escape_sed "$APACHE_MODULE")|g" \
        -e "s|@@DOCROOT@@|$(escape_sed "$DOCROOT")|g" \
        -e "s|@@RULES_FILE@@|$(escape_sed "$RULES_FILE")|g" \
        "$TEMPLATE" > "$CONFIG_FILE"
}

cleanup() {
    if [ -n "${HTTPD_PID:-}" ] && kill -0 "$HTTPD_PID" >/dev/null 2>&1; then
        kill "$HTTPD_PID" >/dev/null 2>&1 || true
        wait "$HTTPD_PID" >/dev/null 2>&1 || true
    fi
}

send_case_request() {
    set -- "$CURL_BIN" -sS -X "$REQUEST_METHOD" -o "$RESPONSE_BODY" -w "%{http_code}"
    if [ -n "${REQUEST_HEADERS_FILE:-}" ] && [ -s "$REQUEST_HEADERS_FILE" ]; then
        while IFS= read -r header_line || [ -n "$header_line" ]; do
            [ -n "$header_line" ] || continue
            set -- "$@" -H "$header_line"
        done < "$REQUEST_HEADERS_FILE"
    fi
    if [ "${REQUEST_HAS_BODY:-0}" = "1" ]; then
        set -- "$@" --data-binary "@$REQUEST_BODY_FILE"
    fi
    set -- "$@" "http://127.0.0.1:$PORT$REQUEST_PATH"
    "$@" 2>"$LOG_DIR/curl-attack.err"
}

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
STATUS_FILE="$LOG_DIR/status.txt"

echo "apache_smoke: BUILD_ROOT=$BUILD_ROOT"
echo "apache_smoke: APACHE_BUILD_ROOT=$APACHE_BUILD_ROOT"
echo "apache_smoke: HTTPD_PREFIX=$HTTPD_PREFIX"
echo "apache_smoke: RUNTIME_ROOT=$RUNTIME_ROOT"
echo "apache_smoke: LOG_DIR=$LOG_DIR"
echo "apache_smoke: APACHE_MODULE=$APACHE_MODULE"
echo "apache_smoke: TEST_CASE=$TEST_CASE"
echo "apache_smoke: CASE_SCOPE=$CASE_SCOPE"

require_absolute_generated_path "$BUILD_ROOT" "BUILD_ROOT"
require_absolute_generated_path "$APACHE_BUILD_ROOT" "APACHE_BUILD_ROOT"
require_absolute_generated_path "$HTTPD_PREFIX" "HTTPD_PREFIX"
require_absolute_generated_path "$RUNTIME_ROOT" "RUNTIME_ROOT"
require_absolute_generated_path "$LOG_DIR" "LOG_DIR"

mkdir -p "$LOG_DIR" "$LOG_DIR/audit" "$RUNTIME_ROOT/conf" "$RUNTIME_ROOT/logs" "$RUNTIME_ROOT/htdocs" "$RUNTIME_ROOT/run"
rm -f "$RUNTIME_ROOT/logs/"* \
    "$LOG_DIR/configtest.log" \
    "$LOG_DIR/curl-attack.err" \
    "$LOG_DIR/curl-ready.err" \
    "$LOG_DIR/httpd.log" \
    "$LOG_DIR/response-body.txt" \
    "$LOG_DIR/audit.log"
rm -f "$LOG_DIR/audit/"*
: > "$STATUS_FILE"

APACHE_HTTPD_BIN=$(find_apache)
APXS_BIN=$(find_apxs)
CURL_BIN=$(find_curl)

[ -n "$APACHE_HTTPD_BIN" ] || blocked "missing Apache httpd executable; set APACHE_HTTPD=/path/to/apache2-or-httpd"
[ -x "$APACHE_HTTPD_BIN" ] || blocked "Apache executable is not executable: $APACHE_HTTPD_BIN"
[ -n "$CURL_BIN" ] || blocked "missing curl; set CURL=/path/to/curl"
[ -x "$CURL_BIN" ] || blocked "curl is not executable: $CURL_BIN"
[ -f "$APACHE_MODULE" ] || blocked "missing Apache connector module: $APACHE_MODULE"

if [ ! -f "$MODSECURITY_LIB_DIR/libmodsecurity.so" ]; then
    if [ -f "$MODSECURITY_V3_DIR/src/.libs/libmodsecurity.so" ]; then
        MODSECURITY_LIB_DIR="$MODSECURITY_V3_DIR/src/.libs"
    else
        blocked "missing libmodsecurity.so in staged or build-copy library directories"
    fi
fi

MODULES_FILE="$RUNTIME_ROOT/conf/modules.load"
CONFIG_FILE="$RUNTIME_ROOT/conf/httpd.conf"
RULES_FILE="$RUNTIME_ROOT/conf/modsecurity-smoke.conf"
MIME_TYPES_FILE="$RUNTIME_ROOT/conf/mime.types"
DOCROOT="$RUNTIME_ROOT/htdocs"
RESPONSE_BODY="$LOG_DIR/response-body.txt"
CASE_ENV_FILE="$RUNTIME_ROOT/conf/case.env"
REQUEST_HEADERS_FILE="$RUNTIME_ROOT/conf/request-headers.txt"
REQUEST_BODY_FILE="$RUNTIME_ROOT/conf/request-body.bin"
AUDIT_LOG_FILE="$LOG_DIR/audit.log"
AUDIT_LOG_DIR="$LOG_DIR/audit"

if [ -f "$HTTPD_PREFIX/conf/mime.types" ]; then
    cp -a "$HTTPD_PREFIX/conf/mime.types" "$MIME_TYPES_FILE"
else
    : > "$MIME_TYPES_FILE"
fi
if ! "$PYTHON_BIN" "$CASE_CLI" materialize \
    --case "$TEST_CASE" \
    --rules-file "$RULES_FILE" \
    --env-file "$CASE_ENV_FILE" \
    --headers-file "$REQUEST_HEADERS_FILE" \
    --body-file "$REQUEST_BODY_FILE" \
    --docroot "$DOCROOT" \
    --audit-log-file "$AUDIT_LOG_FILE" \
    --audit-log-dir "$AUDIT_LOG_DIR" > "$LOG_DIR/case-materialize.log" 2>&1; then
    blocked "failed to materialize shared case; see $LOG_DIR/case-materialize.log"
fi
. "$CASE_ENV_FILE"

: > "$MODULES_FILE"
if modules_dir=$(apache_modules_dir); then
    append_mpm_if_needed "$modules_dir" "$MODULES_FILE"
    append_load_if_exists "authz_core_module" "mod_authz_core.so" "$modules_dir" "$MODULES_FILE"
    append_load_if_exists "authz_host_module" "mod_authz_host.so" "$modules_dir" "$MODULES_FILE"
    append_load_if_exists "unixd_module" "mod_unixd.so" "$modules_dir" "$MODULES_FILE"
    append_load_if_exists "dir_module" "mod_dir.so" "$modules_dir" "$MODULES_FILE"
    append_load_if_exists "mime_module" "mod_mime.so" "$modules_dir" "$MODULES_FILE"
fi

render_config

LD_LIBRARY_PATH="$MODSECURITY_LIB_DIR:$HTTPD_PREFIX/lib:$PCRE2_PREFIX/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export LD_LIBRARY_PATH

if ! "$APACHE_HTTPD_BIN" -t -f "$CONFIG_FILE" > "$LOG_DIR/configtest.log" 2>&1; then
    fail "Apache configtest failed; see $LOG_DIR/configtest.log"
fi

trap cleanup EXIT INT TERM
"$APACHE_HTTPD_BIN" -X -f "$CONFIG_FILE" > "$LOG_DIR/httpd.log" 2>&1 &
HTTPD_PID=$!

ready=0
i=0
while [ "$i" -lt 30 ]; do
    if ! kill -0 "$HTTPD_PID" >/dev/null 2>&1; then
        fail "Apache exited before request; see $LOG_DIR/httpd.log"
    fi
    if "$CURL_BIN" -sS -o /dev/null "http://127.0.0.1:$PORT/__modsec_smoke_ready" >/dev/null 2>"$LOG_DIR/curl-ready.err"; then
        ready=1
        break
    fi
    i=$((i + 1))
    sleep 1
done

[ "$ready" -eq 1 ] || fail "Apache did not become ready on 127.0.0.1:$PORT"

set +e
http_status=$(send_case_request)
curl_rc=$?
set -e
printf '%s\n' "$http_status" > "$LOG_DIR/observed-status.txt"

if [ "$curl_rc" -ne 0 ]; then
    write_case_result "$TEST_CASE" fail "$http_status" "$LOG_DIR/result.json" || true
    fail "curl attack request failed rc=$curl_rc; see $LOG_DIR/curl-attack.err"
fi

if "$PYTHON_BIN" "$CASE_CLI" assert-status \
    --case "$TEST_CASE" \
    --actual-status "$http_status" \
    --response-body-file "$RESPONSE_BODY" \
    --audit-log-file "$AUDIT_LOG_FILE" \
    --status-file "$STATUS_FILE" > "$LOG_DIR/case-assert.log" 2>&1; then
    write_case_result "$TEST_CASE" pass "$http_status" "$LOG_DIR/result.json" || true
    echo "apache_smoke: pass case=$CASE_NAME status=$http_status"
    exit 0
fi

write_case_result "$TEST_CASE" fail "$http_status" "$LOG_DIR/result.json" || true
echo "apache_smoke: fail case=$CASE_NAME observed=$http_status expected=$EXPECT_STATUS"
exit 1
