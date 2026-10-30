#!/bin/sh
: "${TEST_ROOT:?TEST_ROOT is required explicitly}"
set -eu

SCRIPT_DIR=$(CDPATH='' cd "$(dirname "$0")" && pwd)
REPO_ROOT=${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}
BUILD_ROOT=${BUILD_ROOT:-${XDG_STATE_HOME:-${HOME:-/tmp}/.local/state}/ModSecurity-conector-build}
MODULE_PATH=${LIGHTTPD_CONNECTOR_MODULE:-${LIGHTTPD_MODULE_DIR:-$BUILD_ROOT/lighttpd-connector/modules}/mod_msconnector.so}
SMOKE_PORT=${LIGHTTPD_SMOKE_PORT:-18084}
EXPECTED_RULE_ID=${MSCONNECTOR_EXPECTED_RULE_ID:-1000001}

blocked() {
    reason=$1
    printf 'lighttpd_runtime_smoke: BLOCKED: %s\n' "$reason"
    exit 77
}

[ -n "${LIGHTTPD_BIN:-}" ] || blocked "LIGHTTPD_BIN is required"
if [ -x "$LIGHTTPD_BIN" ]; then
    LIGHTTPD_COMMAND=$LIGHTTPD_BIN
else
    LIGHTTPD_COMMAND=$(command -v "$LIGHTTPD_BIN" 2>/dev/null || true)
    [ -n "$LIGHTTPD_COMMAND" ] || blocked "lighttpd binary is not executable: $LIGHTTPD_BIN"
fi
command -v curl >/dev/null 2>&1 || blocked "curl is required for the runtime request path"
[ -f "$MODULE_PATH" ] || blocked "connector module is missing: $MODULE_PATH"

if [ "${MSCONNECTOR_NO_CRS_BASELINE:-0}" = "1" ]; then
    NO_CRS_SELECTION_CONSUMER=$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/lifecycle/consume-no-crs-selected-cases.sh
    [ -x "$NO_CRS_SELECTION_CONSUMER" ] || blocked "No-CRS selected-case consumer is missing: $NO_CRS_SELECTION_CONSUMER"
    "$NO_CRS_SELECTION_CONSUMER" lighttpd
fi

SMOKE_PREPARER=${LIGHTTPD_SMOKE_PREPARER:-$SCRIPT_DIR/prepare_native_smoke.sh}
[ -f "$SMOKE_PREPARER" ] || blocked "smoke preparer is missing: $SMOKE_PREPARER"
LIGHTTPD_CONFIG=$(BUILD_ROOT="$BUILD_ROOT" \
    LIGHTTPD_SMOKE_PORT="$SMOKE_PORT" \
    LIGHTTPD_SMOKE_DIR="${LIGHTTPD_SMOKE_DIR:-}" \
    sh "$SMOKE_PREPARER")
MODULE_DIR=$(dirname "$MODULE_PATH")
SMOKE_DIR=$(dirname "$LIGHTTPD_CONFIG")
EVENT_PATH=$SMOKE_DIR/events.jsonl
ERROR_LOG=$SMOKE_DIR/lighttpd-error.log
SERVER_STDOUT=$SMOKE_DIR/runtime-smoke.stdout
SERVER_STDERR=$SMOKE_DIR/runtime-smoke.stderr
SERVER_PID=

cleanup() {
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill -TERM "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT HUP INT TERM

if ! "$LIGHTTPD_COMMAND" -m "$MODULE_DIR" -tt -f "$LIGHTTPD_CONFIG" \
    >"$SMOKE_DIR/runtime-config-check.stdout" 2>"$SMOKE_DIR/runtime-config-check.stderr"; then
    sed -n '1,200p' "$SMOKE_DIR/runtime-config-check.stderr" >&2
    printf 'lighttpd_runtime_smoke: FAIL config-load\n' >&2
    exit 1
fi

# The error log belongs to this disposable smoke directory.  Reset it after
# the config check so a diagnostic from an earlier run cannot masquerade as a
# Phase-4 failure in this run.
[ ! -L "$ERROR_LOG" ] || {
    printf 'lighttpd_runtime_smoke: FAIL error log must not be a symlink\n' >&2
    exit 1
}
: > "$ERROR_LOG"

"$LIGHTTPD_COMMAND" -D -m "$MODULE_DIR" -f "$LIGHTTPD_CONFIG" \
    >"$SERVER_STDOUT" 2>"$SERVER_STDERR" &
SERVER_PID=$!
sleep 1
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    wait "$SERVER_PID" 2>/dev/null || true
    sed -n '1,200p' "$SERVER_STDERR" >&2
    printf 'lighttpd_runtime_smoke: FAIL process did not remain alive\n' >&2
    exit 1
fi

BASE_URL=http://127.0.0.1:$SMOKE_PORT/
BASELINE_STATUS=$(curl --silent --show-error --output /dev/null \
    --write-out '%{http_code}' --request OPTIONS --request-target '*' "$BASE_URL")
BLOCK_STATUS=$(curl --silent --show-error --output /dev/null \
    --write-out '%{http_code}' --request OPTIONS --request-target '*' \
    --header 'X-Modsec-Smoke: block' "$BASE_URL")

[ "$BASELINE_STATUS" = 200 ] || {
    printf 'lighttpd_runtime_smoke: FAIL baseline_status=%s expected=200\n' "$BASELINE_STATUS" >&2
    exit 1
}
[ "$BLOCK_STATUS" = 403 ] || {
    printf 'lighttpd_runtime_smoke: FAIL block_status=%s expected=403\n' "$BLOCK_STATUS" >&2
    exit 1
}
[ -s "$EVENT_PATH" ] || {
    printf 'lighttpd_runtime_smoke: FAIL decision event was not written\n' >&2
    exit 1
}
grep -F '"connector":"lighttpd"' "$EVENT_PATH" >/dev/null || {
    printf 'lighttpd_runtime_smoke: FAIL event connector metadata is missing\n' >&2
    exit 1
}
grep -F "\"rule_id\":\"$EXPECTED_RULE_ID\"" "$EVENT_PATH" >/dev/null || {
    printf 'lighttpd_runtime_smoke: FAIL event rule metadata is missing\n' >&2
    exit 1
}
if grep -E 'request_body|response_body|body_payload' "$EVENT_PATH" >/dev/null; then
    printf 'lighttpd_runtime_smoke: FAIL event unexpectedly contains a body field\n' >&2
    exit 1
fi

kill -TERM "$SERVER_PID"
status=0
wait "$SERVER_PID" 2>/dev/null || status=$?
if [ "$status" -ne 0 ] && [ "$status" -ne 143 ]; then
    sed -n '1,200p' "$SERVER_STDERR" >&2
    printf 'lighttpd_runtime_smoke: FAIL shutdown status=%s\n' "$status" >&2
    exit 1
fi
if grep -Fq 'msconnector response-body finalization failed' "$ERROR_LOG"; then
    printf 'lighttpd_runtime_smoke: FAIL response-body finalization ran although response_body_mode=none\n' >&2
    exit 1
fi
SERVER_PID=
trap - EXIT HUP INT TERM

printf 'lighttpd_runtime_smoke: PASS baseline=%s blocked=%s module=%s event=%s\n' \
    "$BASELINE_STATUS" "$BLOCK_STATUS" "$MODULE_PATH" "$EVENT_PATH"
