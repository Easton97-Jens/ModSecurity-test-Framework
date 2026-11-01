#!/bin/sh
# Resolve test infrastructure only from the explicitly selected Framework.
: "${TEST_ROOT:?TEST_ROOT is required explicitly}"
: "${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}"
: "${CONNECTOR_REVISION:?CONNECTOR_REVISION is required explicitly}"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
. "$TEST_ROOT/ci/lib/path-bootstrap.sh"
: "${TEST_ROOT:?TEST_ROOT is required explicitly}"
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
REPO_ROOT=${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}
VERIFIED_RUN_ROOT="${VERIFIED_RUN_ROOT:-${RUNNER_TEMP:-${TMPDIR:-/var/tmp}}/ModSecurity-conector-verified}"
VERIFIED_BUILD_ROOT="${VERIFIED_BUILD_ROOT:-$VERIFIED_RUN_ROOT/build}"
BUILD_ROOT="${BUILD_ROOT:-$VERIFIED_BUILD_ROOT}"
CC_BIN="${CC:-cc}"
MSCONNECTOR_C_STD="${MSCONNECTOR_C_STD:-c17}"
MSCONNECTOR_CFLAGS="${MSCONNECTOR_CFLAGS:--std=$MSCONNECTOR_C_STD -Wall -Wextra -Werror}"
OUT_DIR="$BUILD_ROOT/http-authorization-service-timeout-smoke"
TEST_SOURCE="$TEST_ROOT/connector_suite/modsecurity_connector_ci/checks/common/http_authorization_service_timeout_smoke.c"
TEST_BINARY="$OUT_DIR/http_authorization_service_timeout_smoke"
COMPANION_SOURCE="$TEST_ROOT/connector_suite/modsecurity_connector_tests/http_authorization_service_response_companion_lifecycle_smoke.c"
COMPANION_BINARY="$OUT_DIR/http_authorization_service_response_companion_lifecycle_smoke"
TRUSTED_SOURCE="$TEST_ROOT/connector_suite/modsecurity_connector_tests/http_authorization_service_trusted_binding_smoke.c"
TRUSTED_BINARY="$OUT_DIR/http_authorization_service_trusted_binding_smoke"

case "$BUILD_ROOT" in
    /*) ;;
    *) echo "http_authorization_service_timeout_smoke: BUILD_ROOT must be absolute" >&2; exit 77 ;;
esac
case "$(CDPATH= cd "$BUILD_ROOT" 2>/dev/null && pwd 2>/dev/null || printf '%s' "$BUILD_ROOT")" in
    "$REPO_ROOT"|"$REPO_ROOT"/*)
        echo "http_authorization_service_timeout_smoke: BUILD_ROOT must not be inside the checkout" >&2
        exit 77
        ;;
    *) ;;
esac
if [ -L "$OUT_DIR" ]; then
    echo "http_authorization_service_timeout_smoke: output directory must not be a symlink" >&2
    exit 77
fi
command -v "$CC_BIN" >/dev/null 2>&1 || {
    echo "http_authorization_service_timeout_smoke: missing C compiler: $CC_BIN" >&2
    exit 77
}

mkdir -p "$OUT_DIR"
"$CC_BIN" $MSCONNECTOR_CFLAGS -pthread \
    -I "$REPO_ROOT" \
    -I "$REPO_ROOT/common/include" \
    -I "$REPO_ROOT/common/runtime" \
    "$TEST_SOURCE" \
    "$REPO_ROOT/common/runtime/http_authorization_service.c" \
    "$REPO_ROOT"/common/src/*.c \
    -o "$TEST_BINARY"
"$TEST_BINARY"

"$CC_BIN" $MSCONNECTOR_CFLAGS -pthread \
    -I "$REPO_ROOT" \
    -I "$REPO_ROOT/common/include" \
    -I "$REPO_ROOT/common/runtime" \
    "$COMPANION_SOURCE" \
    "$REPO_ROOT"/common/src/*.c \
    -o "$COMPANION_BINARY"
"$COMPANION_BINARY"

"$CC_BIN" $MSCONNECTOR_CFLAGS -pthread \
    -I "$REPO_ROOT" \
    -I "$REPO_ROOT/common/include" \
    -I "$REPO_ROOT/common/runtime" \
    "$TRUSTED_SOURCE" \
    "$REPO_ROOT/common/runtime/http_authorization_service.c" \
    "$REPO_ROOT"/common/src/*.c \
    -o "$TRUSTED_BINARY"
"$TRUSTED_BINARY"

for fixture in detached_worker peer_close; do
    "$CC_BIN" $MSCONNECTOR_CFLAGS -pthread \
        -I "$REPO_ROOT" \
        -I "$REPO_ROOT/common/include" \
        -I "$REPO_ROOT/common/runtime" \
        "$TEST_ROOT/connector_suite/modsecurity_connector_tests/http_authorization_service_${fixture}_smoke.c" \
        "$REPO_ROOT/common/runtime/http_authorization_service.c" \
        "$REPO_ROOT"/common/src/*.c \
        -o "$OUT_DIR/http_authorization_service_${fixture}_smoke"
    "$OUT_DIR/http_authorization_service_${fixture}_smoke"
done

printf 'http_authorization_service_timeout_smoke: pass output=%s\n' "$OUT_DIR"
