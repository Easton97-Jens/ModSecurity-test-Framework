#!/bin/sh
# Resolve test infrastructure only from the explicitly selected Framework.
: "${TEST_ROOT:?TEST_ROOT is required explicitly}"
: "${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}"
: "${CONNECTOR_REVISION:?CONNECTOR_REVISION is required explicitly}"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
. "$TEST_ROOT/ci/lib/path-bootstrap.sh"
set -eu

SCRIPT_DIR=$(
    CDPATH=
    cd "$(dirname "$0")"
    pwd
)
REPO_ROOT=${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}
VERIFIED_RUN_ROOT="${VERIFIED_RUN_ROOT:-${RUNNER_TEMP:-${TMPDIR:-/var/tmp}}/ModSecurity-conector-verified}"
VERIFIED_BUILD_ROOT="${VERIFIED_BUILD_ROOT:-$VERIFIED_RUN_ROOT/build}"
BUILD_ROOT="${BUILD_ROOT:-$VERIFIED_BUILD_ROOT}"
OUT_DIR="$BUILD_ROOT/common-http-header-fuzz"
FUZZ_BIN="$OUT_DIR/common_http_headers_fuzz"

case "$BUILD_ROOT" in
    /*) ;;
    *) echo "common_http_headers_fuzz: BUILD_ROOT must be absolute: $BUILD_ROOT"; exit 77 ;;
esac

BUILD_ROOT_RESOLVED=$(
    CDPATH=
    if cd "$BUILD_ROOT" 2>/dev/null; then
        pwd 2>/dev/null
    else
        printf '%s' "$BUILD_ROOT"
    fi
)

case "$BUILD_ROOT_RESOLVED" in
    "$REPO_ROOT"|"$REPO_ROOT"/*)
        echo "common_http_headers_fuzz: BUILD_ROOT must not be inside the checkout: $BUILD_ROOT"
        exit 77
        ;;
    *) ;;
esac

CLANG_BIN=$(command -v clang 2>/dev/null || true)
if [ -z "$CLANG_BIN" ]; then
    echo "common_http_headers_fuzz: missing clang with libFuzzer support"
    exit 77
fi

mkdir -p "$OUT_DIR"
"$CLANG_BIN" \
    -std=c17 -Wall -Wextra -Werror -g -O1 -fno-omit-frame-pointer \
    -fsanitize=fuzzer,address,undefined \
    -I"$REPO_ROOT/common/include" \
    "$TEST_ROOT/connector_suite/fuzz/common_http_headers_fuzz.c" \
    "$REPO_ROOT/common/src/headers.c" \
    "$REPO_ROOT/common/src/log_sanitize.c" \
    -o "$FUZZ_BIN"

(
    cd "$OUT_DIR"
    "$FUZZ_BIN" \
        -max_total_time=15 \
        -timeout=5 \
        -rss_limit_mb=256 \
        -workers=1 \
        -artifact_prefix="$OUT_DIR/"
)
