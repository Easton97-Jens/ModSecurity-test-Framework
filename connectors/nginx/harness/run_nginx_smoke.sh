#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd "$SCRIPT_DIR/../../.." && pwd)
BUILD_ROOT="${BUILD_ROOT:-/src/ModSecurity-test-Framework-build}"
NGINX_BUILD_DIR="${NGINX_BUILD_DIR:-$BUILD_ROOT/nginx-build}"
NGINX_PREFIX="${NGINX_PREFIX:-$BUILD_ROOT/nginx-runtime/nginx}"
NGINX_BINARY="${NGINX_BINARY:-$NGINX_PREFIX/sbin/nginx}"
NGINX_MODULE="${NGINX_MODULE:-$NGINX_PREFIX/modules/ngx_http_modsecurity_module.so}"
MODSECURITY_LIB_DIR="${MODSECURITY_LIB_DIR:-$NGINX_BUILD_DIR/output/modsecurity/lib}"
LOG_DIR="${LOG_DIR:-$BUILD_ROOT/logs/nginx-runtime}"
RESULTS_DIR="${RESULTS_DIR:-$BUILD_ROOT/results}"
RUNTIME_BASE="${RUNTIME_BASE:-$BUILD_ROOT/nginx-runtime}"
RUNTIME_ROOT="${RUNTIME_ROOT:-}"
CURL_BIN="${CURL:-}"
PYTHON_BIN="${PYTHON:-python3}"
PYTHONDONTWRITEBYTECODE="${PYTHONDONTWRITEBYTECODE:-1}"
export PYTHONDONTWRITEBYTECODE
BASE_PORT="${PORT:-18081}"
PORT="$BASE_PORT"
TEMPLATE="$SCRIPT_DIR/nginx_smoke.conf"
TEST_CASE="${TEST_CASE:-}"
SMOKE_CASES="${SMOKE_CASES:-}"
CASE_SCOPE="${CASE_SCOPE:-all}"
CASE_CLI="$REPO_ROOT/tests/runners/case_cli.py"
RUN_ONE_CASE="${RUN_ONE_CASE:-0}"
STATUS_FILE="$LOG_DIR/status.txt"

blocked() {
    echo "nginx_smoke: blocked $*"
    mkdir -p "$LOG_DIR"
    echo "blocked: $*" >> "$STATUS_FILE"
    exit 77
}

fail() {
    echo "nginx_smoke: fail $*"
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
        --connector nginx \
        --scope "$CASE_SCOPE" \
        --test-case "$item"
}

list_case_files() {
    if [ -n "$TEST_CASE" ]; then
        "$PYTHON_BIN" "$CASE_CLI" list-cases \
            --repo-root "$REPO_ROOT" \
            --connector nginx \
            --scope "$CASE_SCOPE" \
            --test-case "$TEST_CASE"
        return
    fi
    if [ -n "$SMOKE_CASES" ]; then
        "$PYTHON_BIN" "$CASE_CLI" list-cases \
            --repo-root "$REPO_ROOT" \
            --connector nginx \
            --scope "$CASE_SCOPE" \
            --smoke-cases "$SMOKE_CASES"
        return
    fi
    "$PYTHON_BIN" "$CASE_CLI" list-cases \
        --repo-root "$REPO_ROOT" \
        --connector nginx \
        --scope "$CASE_SCOPE"
}

write_case_result() {
    case_path=$1
    case_status=$2
    actual_status=${3:-}
    output=$4
    if [ -n "$actual_status" ]; then
        "$PYTHON_BIN" "$CASE_CLI" case-info \
            --case "$case_path" \
            --connector nginx \
            --status "$case_status" \
            --actual-status "$actual_status" \
            --output "$output"
    else
        "$PYTHON_BIN" "$CASE_CLI" case-info \
            --case "$case_path" \
            --connector nginx \
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
    summary_file="$RESULTS_DIR/nginx-summary.txt"
    json_file="$RESULTS_DIR/nginx-summary.json"
    results_jsonl="$RESULTS_DIR/nginx-results.jsonl"
    connector_summary="$RESULTS_DIR/connector-summary.txt"
    : > "$summary_file"
    : > "$results_jsonl"

    cases=$(list_case_files) || exit 1
    if [ -z "$cases" ]; then
        echo "nginx_smoke: fail no shared smoke cases found" >&2
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
        echo "nginx_smoke: running case=$case_name port=$case_port"
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
        --connector nginx \
        --input-jsonl "$results_jsonl" \
        --summary-json "$json_file" \
        --summary-text "$summary_file" \
        --import-status-file "$REPO_ROOT/tests/import-status.json" \
        --connector-path real-world \
        --validation-mode real-world-connector-path \
        --server nginx \
        --server-binary "$NGINX_BINARY" \
        --module "$NGINX_MODULE" \
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

find_curl() {
    if [ -n "$CURL_BIN" ]; then
        printf '%s\n' "$CURL_BIN"
        return 0
    fi
    command -v curl 2>/dev/null || true
}

escape_sed() {
    raw_value=$1
    printf '%s' "$raw_value" | sed 's/[&|]/\\&/g'
}

render_config() {
    sed \
        -e "s|@@RUNTIME_ROOT@@|$(escape_sed "$RUNTIME_ROOT")|g" \
        -e "s|@@LOG_DIR@@|$(escape_sed "$LOG_DIR")|g" \
        -e "s|@@PORT@@|$(escape_sed "$PORT")|g" \
        -e "s|@@NGINX_MODULE@@|$(escape_sed "$NGINX_MODULE")|g" \
        -e "s|@@DOCROOT@@|$(escape_sed "$DOCROOT")|g" \
        -e "s|@@RULES_FILE@@|$(escape_sed "$RULES_FILE")|g" \
        "$TEMPLATE" > "$CONFIG_FILE"
}

cleanup() {
    if [ -n "${NGINX_PID:-}" ] && kill -0 "$NGINX_PID" >/dev/null 2>&1; then
        kill "$NGINX_PID" >/dev/null 2>&1 || true
        wait "$NGINX_PID" >/dev/null 2>&1 || true
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

echo "nginx_smoke: BUILD_ROOT=$BUILD_ROOT"
echo "nginx_smoke: NGINX_BUILD_DIR=$NGINX_BUILD_DIR"
echo "nginx_smoke: NGINX_PREFIX=$NGINX_PREFIX"
echo "nginx_smoke: NGINX_BINARY=$NGINX_BINARY"
echo "nginx_smoke: NGINX_MODULE=$NGINX_MODULE"
echo "nginx_smoke: RUNTIME_ROOT=$RUNTIME_ROOT"
echo "nginx_smoke: LOG_DIR=$LOG_DIR"
echo "nginx_smoke: TEST_CASE=$TEST_CASE"
echo "nginx_smoke: CASE_SCOPE=$CASE_SCOPE"

require_absolute_generated_path "$BUILD_ROOT" "BUILD_ROOT"
require_absolute_generated_path "$NGINX_BUILD_DIR" "NGINX_BUILD_DIR"
require_absolute_generated_path "$NGINX_PREFIX" "NGINX_PREFIX"
require_absolute_generated_path "$RUNTIME_ROOT" "RUNTIME_ROOT"
require_absolute_generated_path "$LOG_DIR" "LOG_DIR"

mkdir -p "$LOG_DIR" "$LOG_DIR/audit" "$RUNTIME_ROOT/conf" "$RUNTIME_ROOT/htdocs" \
    "$RUNTIME_ROOT/client_body_temp" "$RUNTIME_ROOT/proxy_temp" \
    "$RUNTIME_ROOT/fastcgi_temp" "$RUNTIME_ROOT/uwsgi_temp" \
    "$RUNTIME_ROOT/scgi_temp"
rm -f "$LOG_DIR/configtest.log" \
    "$LOG_DIR/curl-attack.err" \
    "$LOG_DIR/curl-ready.err" \
    "$LOG_DIR/nginx.log" \
    "$LOG_DIR/nginx-stdout.log" \
    "$LOG_DIR/response-body.txt" \
    "$LOG_DIR/audit.log" \
    "$RUNTIME_ROOT/nginx.pid"
rm -f "$LOG_DIR/audit/"*
: > "$STATUS_FILE"

CURL_BIN=$(find_curl)

[ -x "$NGINX_BINARY" ] || blocked "missing executable NGINX binary: $NGINX_BINARY"
[ -f "$NGINX_MODULE" ] || blocked "missing NGINX ModSecurity dynamic module: $NGINX_MODULE"
[ -n "$CURL_BIN" ] || blocked "missing curl; set CURL=/path/to/curl"
[ -x "$CURL_BIN" ] || blocked "curl is not executable: $CURL_BIN"
[ -f "$MODSECURITY_LIB_DIR/libmodsecurity.so" ] || blocked "missing staged libmodsecurity.so: $MODSECURITY_LIB_DIR/libmodsecurity.so"

CONFIG_FILE="$RUNTIME_ROOT/conf/nginx.conf"
RULES_FILE="$RUNTIME_ROOT/conf/modsecurity-smoke.conf"
DOCROOT="$RUNTIME_ROOT/htdocs"
RESPONSE_BODY="$LOG_DIR/response-body.txt"
CASE_ENV_FILE="$RUNTIME_ROOT/conf/case.env"
REQUEST_HEADERS_FILE="$RUNTIME_ROOT/conf/request-headers.txt"
REQUEST_BODY_FILE="$RUNTIME_ROOT/conf/request-body.bin"
AUDIT_LOG_FILE="$LOG_DIR/audit.log"
AUDIT_LOG_DIR="$LOG_DIR/audit"

chmod go+rx "$BUILD_ROOT" "$RUNTIME_BASE" "$RUNTIME_ROOT" "$DOCROOT" 2>/dev/null || true
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
chmod go+r "$DOCROOT/index.html" "$DOCROOT/__modsec_smoke_ready" 2>/dev/null || true
. "$CASE_ENV_FILE"

render_config

LD_LIBRARY_PATH="$MODSECURITY_LIB_DIR:$NGINX_PREFIX/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export LD_LIBRARY_PATH

if ! "$NGINX_BINARY" -t -p "$RUNTIME_ROOT" -c "$CONFIG_FILE" > "$LOG_DIR/configtest.log" 2>&1; then
    fail "NGINX configtest failed; see $LOG_DIR/configtest.log"
fi

trap cleanup EXIT INT TERM
"$NGINX_BINARY" -p "$RUNTIME_ROOT" -c "$CONFIG_FILE" > "$LOG_DIR/nginx-stdout.log" 2>&1 &
NGINX_PID=$!

ready=0
i=0
while [ "$i" -lt 30 ]; do
    if ! kill -0 "$NGINX_PID" >/dev/null 2>&1; then
        fail "NGINX exited before request; see $LOG_DIR/nginx-stdout.log and $LOG_DIR/error.log"
    fi
    if "$CURL_BIN" -sS -o /dev/null "http://127.0.0.1:$PORT/__modsec_smoke_ready" >/dev/null 2>"$LOG_DIR/curl-ready.err"; then
        ready=1
        break
    fi
    i=$((i + 1))
    sleep 1
done

[ "$ready" -eq 1 ] || fail "NGINX did not become ready on 127.0.0.1:$PORT"

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
    echo "nginx_smoke: pass case=$CASE_NAME status=$http_status"
    exit 0
fi

write_case_result "$TEST_CASE" fail "$http_status" "$LOG_DIR/result.json" || true
echo "nginx_smoke: fail case=$CASE_NAME observed=$http_status expected=$EXPECT_STATUS"
exit 1
