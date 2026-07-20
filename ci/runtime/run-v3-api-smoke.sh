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
