#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
. "$SCRIPT_DIR/../lib/path-bootstrap.sh"
REPO_ROOT="${REPO_ROOT:-$FRAMEWORK_ROOT}"
. "$CI_ROOT/lib/common.sh"

SMOKE_DIR="$REPO_ROOT/src/v3-api-smoke"

MODSECURITY_V3_SOURCE_DIR="${MODSECURITY_V3_SOURCE_DIR:-$MODSECURITY_SOURCE_DIR}"
MODSECURITY_V3_DIR="${MODSECURITY_V3_DIR:-$BUILD_ROOT/ModSecurity_V3_build}"
LOG_DIR="${LOG_DIR:-$BUILD_ROOT/logs}"
BUILD_DIR="${BUILD_DIR:-$BUILD_ROOT/v3-api-smoke}"
CC="${CC:-cc}"
CXX="${CXX:-c++}"

validate_compiler() {
    compiler_name=$1
    compiler_value=$2
    case "$compiler_value" in
        ''|*[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_./+-]*)
            echo "v3_api_smoke: blocked $compiler_name contains shell metacharacters: $compiler_value" >&2
            return 77
            ;;
        *)
            :
            ;;
    esac
    command -v "$compiler_value" >/dev/null 2>&1 || {
        echo "v3_api_smoke: blocked $compiler_name is not an executable command: $compiler_value" >&2
        return 77
    }
}

# GNU Make expands variable values before its recipe-level validation runs.
# These values are path-only inputs, so reject Make syntax and every other
# unsupported path character before passing them as Make variables.
validate_make_safe_path() {
    path_name=$1
    path_value=$2
    case "$path_value" in
        ''|*[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_./+-]*)
            echo "v3_api_smoke: blocked $path_name contains Make syntax or unsupported path characters: $path_value" >&2
            return 77
            ;;
        *)
            :
            ;;
    esac
    return 0
}

validate_compiler CC "$CC" || exit 77
validate_compiler CXX "$CXX" || exit 77
validate_make_safe_path MODSECURITY_V3_SOURCE_DIR "$MODSECURITY_V3_SOURCE_DIR" || exit 77
validate_make_safe_path MODSECURITY_V3_DIR "$MODSECURITY_V3_DIR" || exit 77
validate_make_safe_path BUILD_ROOT "$BUILD_ROOT" || exit 77
validate_make_safe_path BUILD_DIR "$BUILD_DIR" || exit 77
validate_make_safe_path LOG_DIR "$LOG_DIR" || exit 77

export MODSECURITY_V3_SOURCE_DIR MODSECURITY_V3_DIR BUILD_ROOT LOG_DIR
export BUILD_DIR CC CXX

case "$BUILD_ROOT" in
    /*) ;;
    *)
        echo "v3_api_smoke: blocked BUILD_ROOT must be absolute and outside the checkout: $BUILD_ROOT"
        exit 77
        ;;
esac

case "$BUILD_DIR" in
    /*) ;;
    *)
        echo "v3_api_smoke: blocked BUILD_DIR must be absolute and outside the checkout: $BUILD_DIR"
        exit 77
        ;;
esac

case "$BUILD_ROOT" in
    "$REPO_ROOT"|"$REPO_ROOT"/*)
        echo "v3_api_smoke: blocked BUILD_ROOT is not an allowed artifact location: $BUILD_ROOT"
        exit 77
        ;;
    *) ;;
esac

case "$BUILD_DIR" in
    "$REPO_ROOT"|"$REPO_ROOT"/*)
        echo "v3_api_smoke: blocked BUILD_DIR is not an allowed artifact location: $BUILD_DIR"
        exit 77
        ;;
    *) ;;
esac

set +e
sh "$SCRIPT_DIR/check-v3-api-smoke-prereqs.sh"
rc=$?
set -e
if [ "$rc" -ne 0 ]; then
    exit "$rc"
fi

make -C "$SMOKE_DIR" run \
    MODSECURITY_V3_DIR="$MODSECURITY_V3_DIR" \
    BUILD_ROOT="$BUILD_ROOT" \
    BUILD_DIR="$BUILD_DIR" \
    CC="$CC" \
    CXX="$CXX"
