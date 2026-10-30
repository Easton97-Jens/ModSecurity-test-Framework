#!/bin/sh
set -eu

BUILD_ROOT=${BUILD_ROOT:-${XDG_STATE_HOME:-${HOME:-/tmp}/.local/state}/ModSecurity-conector-build}
OUT_DIR=$BUILD_ROOT/lighttpd-build-starter
STARTER_BIN=$OUT_DIR/lighttpd-build-starter

case "$BUILD_ROOT" in
    /*) ;;
    *) echo "lighttpd_build_starter_self_test: BLOCKED: BUILD_ROOT must be absolute: $BUILD_ROOT"; exit 77 ;;
esac

if [ ! -x "$STARTER_BIN" ]; then
    echo "lighttpd_build_starter_self_test: BLOCKED: starter binary is missing: $STARTER_BIN"
    exit 77
fi

"$STARTER_BIN" > "$OUT_DIR/result.txt"
printf 'lighttpd_build_starter_self_test: PASS output=%s\n' "$OUT_DIR/result.txt"
cat "$OUT_DIR/result.txt"
