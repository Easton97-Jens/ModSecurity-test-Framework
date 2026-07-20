#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
. "$SCRIPT_DIR/../lib/path-bootstrap.sh"
REPO_ROOT="${REPO_ROOT:-$FRAMEWORK_ROOT}"
. "$CI_ROOT/lib/common.sh"

MODSECURITY_V3_SOURCE_DIR="${MODSECURITY_V3_SOURCE_DIR:-$MODSECURITY_SOURCE_DIR}"
MODSECURITY_V3_DIR="${MODSECURITY_V3_DIR:-$BUILD_ROOT/ModSecurity_V3_build}"
LOG_DIR="${LOG_DIR:-$BUILD_ROOT/logs}"
HEADER_FILE="$MODSECURITY_V3_DIR/headers/modsecurity/modsecurity.h"
LIB_FILE="$MODSECURITY_V3_DIR/src/.libs/libmodsecurity.so"
status=0

echo "v3_api_smoke: MODSECURITY_V3_SOURCE_DIR=$MODSECURITY_V3_SOURCE_DIR"
echo "v3_api_smoke: MODSECURITY_V3_DIR=$MODSECURITY_V3_DIR"
echo "v3_api_smoke: BUILD_ROOT=$BUILD_ROOT"
echo "v3_api_smoke: LOG_DIR=$LOG_DIR"

if git -C "$MODSECURITY_V3_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    branch=$(git -C "$MODSECURITY_V3_DIR" rev-parse --abbrev-ref HEAD)
    version=$(git -C "$MODSECURITY_V3_DIR" describe --tags --always --dirty)
    echo "v3_api_smoke: v3 branch=$branch"
    echo "v3_api_smoke: v3 version=$version"
else
    echo "v3_api_smoke: blocked not a git checkout: $MODSECURITY_V3_DIR"
    status=77
fi

if [ -f "$HEADER_FILE" ]; then
    echo "v3_api_smoke: header present: $HEADER_FILE"
else
    echo "v3_api_smoke: blocked missing header: $HEADER_FILE"
    status=77
fi

if [ -f "$LIB_FILE" ]; then
    echo "v3_api_smoke: library present: $LIB_FILE"
else
    echo "v3_api_smoke: blocked missing library: $LIB_FILE"
    echo "v3_api_smoke: not building ModSecurity_V3 from this script"
    status=77
fi

exit "$status"
