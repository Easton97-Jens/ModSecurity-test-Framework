#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd "$(dirname "$0")" && pwd)
BUILD_ROOT=${BUILD_ROOT:-${XDG_STATE_HOME:-${HOME:-/tmp}/.local/state}/ModSecurity-conector-build}
MODULE_PATH=${LIGHTTPD_CONNECTOR_MODULE:-${LIGHTTPD_MODULE_DIR:-$BUILD_ROOT/lighttpd-connector/modules}/mod_msconnector.so}

blocked() {
    reason=$1
    printf 'lighttpd_start_smoke: BLOCKED: %s\n' "$reason"
    exit 77
}

[ -n "${LIGHTTPD_BIN:-}" ] || blocked "LIGHTTPD_BIN is required"
if [ -x "$LIGHTTPD_BIN" ]; then
    LIGHTTPD_COMMAND=$LIGHTTPD_BIN
else
    LIGHTTPD_COMMAND=$(command -v "$LIGHTTPD_BIN" 2>/dev/null || true)
    [ -n "$LIGHTTPD_COMMAND" ] || blocked "lighttpd binary is not executable: $LIGHTTPD_BIN"
fi
[ -f "$MODULE_PATH" ] || blocked "connector module is missing: $MODULE_PATH"

SMOKE_PREPARER=${LIGHTTPD_SMOKE_PREPARER:-$SCRIPT_DIR/prepare_native_smoke.sh}
[ -f "$SMOKE_PREPARER" ] || blocked "smoke preparer is missing: $SMOKE_PREPARER"
LIGHTTPD_CONFIG=$(BUILD_ROOT="$BUILD_ROOT" \
    LIGHTTPD_SMOKE_DIR="${LIGHTTPD_SMOKE_DIR:-}" \
    sh "$SMOKE_PREPARER")
MODULE_DIR=$(dirname "$MODULE_PATH")
SMOKE_DIR=$(dirname "$LIGHTTPD_CONFIG")
SERVER_STDOUT=$SMOKE_DIR/start-smoke.stdout
SERVER_STDERR=$SMOKE_DIR/start-smoke.stderr
SERVER_PID=

cleanup() {
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill -TERM "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT HUP INT TERM

if ! "$LIGHTTPD_COMMAND" -m "$MODULE_DIR" -tt -f "$LIGHTTPD_CONFIG" \
    >"$SMOKE_DIR/start-config-check.stdout" 2>"$SMOKE_DIR/start-config-check.stderr"; then
    sed -n '1,200p' "$SMOKE_DIR/start-config-check.stderr" >&2
    printf 'lighttpd_start_smoke: FAIL config-load\n' >&2
    exit 1
fi

"$LIGHTTPD_COMMAND" -D -m "$MODULE_DIR" -f "$LIGHTTPD_CONFIG" \
    >"$SERVER_STDOUT" 2>"$SERVER_STDERR" &
SERVER_PID=$!
sleep 1

if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    wait "$SERVER_PID" 2>/dev/null || true
    sed -n '1,200p' "$SERVER_STDERR" >&2
    printf 'lighttpd_start_smoke: FAIL process did not remain alive\n' >&2
    exit 1
fi

# This start smoke deliberately sends no network requests.
kill -TERM "$SERVER_PID"
status=0
wait "$SERVER_PID" || status=$?
if [ "$status" -ne 0 ] && [ "$status" -ne 143 ]; then
    sed -n '1,200p' "$SERVER_STDERR" >&2
    printf 'lighttpd_start_smoke: FAIL shutdown status=%s\n' "$status" >&2
    exit 1
fi
SERVER_PID=
trap - EXIT HUP INT TERM

printf 'lighttpd_start_smoke: PASS binary=%s module=%s requests=0\n' \
    "$LIGHTTPD_COMMAND" "$MODULE_PATH"
