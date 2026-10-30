#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd "$(dirname "$0")" && pwd)
BUILD_ROOT=${BUILD_ROOT:-${XDG_STATE_HOME:-${HOME:-/tmp}/.local/state}/ModSecurity-conector-build}
MODULE_PATH=${LIGHTTPD_CONNECTOR_MODULE:-${LIGHTTPD_MODULE_DIR:-$BUILD_ROOT/lighttpd-connector/modules}/mod_msconnector.so}

blocked() {
    reason=$1
    printf 'lighttpd_config_check: BLOCKED: %s\n' "$reason"
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
CHECK_STDOUT=$SMOKE_DIR/config-check.stdout
CHECK_STDERR=$SMOKE_DIR/config-check.stderr

if "$LIGHTTPD_COMMAND" -m "$MODULE_DIR" -tt -f "$LIGHTTPD_CONFIG" \
    >"$CHECK_STDOUT" 2>"$CHECK_STDERR"; then
    printf 'lighttpd_config_check: PASS binary=%s module=%s config=%s\n' \
        "$LIGHTTPD_COMMAND" "$MODULE_PATH" "$LIGHTTPD_CONFIG"
    exit 0
fi

sed -n '1,200p' "$CHECK_STDERR" >&2
printf 'lighttpd_config_check: FAIL binary=%s module=%s config=%s\n' \
    "$LIGHTTPD_COMMAND" "$MODULE_PATH" "$LIGHTTPD_CONFIG" >&2
exit 1
