#!/bin/sh
set -eu

BUILD_ROOT=${BUILD_ROOT:-${XDG_STATE_HOME:-${HOME:-/tmp}/.local/state}/ModSecurity-conector-build}
OUT_DIR=$BUILD_ROOT/lighttpd-bridge-starter
BRIDGE_BIN=$OUT_DIR/lighttpd-bridge-starter

case "$BUILD_ROOT" in
    /*) ;;
    *) echo "lighttpd_bridge_self_test: BLOCKED: BUILD_ROOT must be absolute: $BUILD_ROOT"; exit 77 ;;
esac

if [ ! -x "$BRIDGE_BIN" ]; then
    echo "lighttpd_bridge_self_test: BLOCKED: bridge binary is missing: $BRIDGE_BIN"
    exit 77
fi

"$BRIDGE_BIN" --self-test > "$OUT_DIR/self-test.txt"
printf 'lighttpd_bridge_self_test: PASS output=%s\n' "$OUT_DIR/self-test.txt"
cat "$OUT_DIR/self-test.txt"
