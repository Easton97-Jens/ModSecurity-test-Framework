#!/bin/sh
# Resolve test infrastructure only from the explicitly selected Framework.
: "${TEST_ROOT:?TEST_ROOT is required explicitly}"
: "${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}"
: "${CONNECTOR_REVISION:?CONNECTOR_REVISION is required explicitly}"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
. "$TEST_ROOT/ci/lib/path-bootstrap.sh"
: "${TEST_ROOT:?TEST_ROOT is required explicitly}"
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}
ROOT=$(CDPATH= cd -- "$ROOT" && pwd -P)
CXX_BIN=${CXX:-c++}

block() {
    echo "BLOCKED: $*" >&2
    exit 77
}

require_absolute_directory() {
    value=$1
    label=$2
    [ -n "$value" ] || block "$label is required"
    case "$value" in
        /*) ;;
        *) block "$label must be absolute: $value" ;;
    esac
    [ -d "$value" ] || block "$label is not a directory: $value"
    resolved=$(CDPATH= cd -- "$value" && pwd -P) || block "cannot resolve $label: $value"
    printf '%s\n' "$resolved"
}

[ -n "${CPP_BUILD_ROOT:-}" ] || {
    echo "FAIL: CPP_BUILD_ROOT is required" >&2
    exit 2
}
case "$CPP_BUILD_ROOT" in
    /*) ;;
    *) echo "FAIL: CPP_BUILD_ROOT must be absolute: $CPP_BUILD_ROOT" >&2; exit 2 ;;
esac
command -v realpath >/dev/null 2>&1 || block "missing realpath utility"
CPP_BUILD_ROOT=$(realpath -m -- "$CPP_BUILD_ROOT") || {
    echo "FAIL: cannot canonicalize CPP_BUILD_ROOT: $CPP_BUILD_ROOT" >&2
    exit 2
}
case "$CPP_BUILD_ROOT" in
    "$ROOT"|"$ROOT"/*)
        echo "FAIL: CPP_BUILD_ROOT must be outside the checkout: $CPP_BUILD_ROOT" >&2
        exit 2
        ;;
    *) : ;;
esac
mkdir -p "$CPP_BUILD_ROOT" || block "cannot create CPP_BUILD_ROOT: $CPP_BUILD_ROOT"
CPP_BUILD_ROOT=$(CDPATH= cd -- "$CPP_BUILD_ROOT" && pwd -P) || block "cannot resolve CPP_BUILD_ROOT"

command -v "$CXX_BIN" >/dev/null 2>&1 || block "missing C++ compiler: $CXX_BIN"
CXX_PATH=$(command -v "$CXX_BIN")
MODSECURITY_INCLUDE_DIR=$(require_absolute_directory "${MODSECURITY_INCLUDE_DIR:-}" MODSECURITY_INCLUDE_DIR)
MODSECURITY_LIB_DIR=$(require_absolute_directory "${MODSECURITY_LIB_DIR:-}" MODSECURITY_LIB_DIR)

for header in modsecurity/modsecurity.h modsecurity/rules_set.h modsecurity/transaction.h; do
    [ -f "$MODSECURITY_INCLUDE_DIR/$header" ] || block "missing libmodsecurity header: $MODSECURITY_INCLUDE_DIR/$header"
done

if [ -n "${MODSECURITY_LIB_FILE:-}" ]; then
    case "$MODSECURITY_LIB_FILE" in
        /*) ;;
        *) block "MODSECURITY_LIB_FILE must be absolute: $MODSECURITY_LIB_FILE" ;;
    esac
    [ -f "$MODSECURITY_LIB_FILE" ] || block "MODSECURITY_LIB_FILE is not a file: $MODSECURITY_LIB_FILE"
    MODSECURITY_LIB_FILE=$(CDPATH= cd -- "$(dirname -- "$MODSECURITY_LIB_FILE")" && pwd -P)/$(basename -- "$MODSECURITY_LIB_FILE")
    LINK_INPUT=$MODSECURITY_LIB_FILE
else
    if [ -f "$MODSECURITY_LIB_DIR/libmodsecurity.so" ] || [ -f "$MODSECURITY_LIB_DIR/libmodsecurity.a" ]; then
        LINK_INPUT=-lmodsecurity
    else
        block "missing libmodsecurity.so or libmodsecurity.a under MODSECURITY_LIB_DIR: $MODSECURITY_LIB_DIR"
    fi
fi

SOURCE=$TEST_ROOT/connector_suite/common/scripts/modsecurity_targeted_eval.cc
[ -f "$SOURCE" ] || {
    echo "FAIL: missing tracked evaluator source: $SOURCE" >&2
    exit 1
}
OUTPUT=$CPP_BUILD_ROOT/modsecurity_targeted_eval
umask 077
TEMP_OUTPUT=$(mktemp "$CPP_BUILD_ROOT/.modsecurity_targeted_eval.XXXXXX") || \
    block "cannot create evaluator temporary output"
INCLUDE_OVERLAY=
trap 'rm -f "$TEMP_OUTPUT"; if [ -n "$INCLUDE_OVERLAY" ]; then rm -rf -- "$INCLUDE_OVERLAY"; fi' EXIT HUP INT TERM
INCLUDE_OVERLAY=$(mktemp -d "$CPP_BUILD_ROOT/.modsecurity_includes.XXXXXX") || \
    block "cannot create evaluator private include directory"
# Supply only the selected SDK's namespace. Passing a default include root
# (notably /usr/include) with -isystem reorders the C++ standard-header search
# and can break libstdc++'s include_next <stdlib.h>. The private overlay keeps
# the SDK selection and system-header warning treatment without moving any
# default root or substituting another installed ModSecurity SDK.
ln -s "$MODSECURITY_INCLUDE_DIR/modsecurity" "$INCLUDE_OVERLAY/modsecurity" || \
    block "cannot bind selected ModSecurity headers"

"$CXX_PATH" -std=c++17 -Wall -Wextra -Werror \
    -isystem "$INCLUDE_OVERLAY" \
    "$SOURCE" \
    -L "$MODSECURITY_LIB_DIR" \
    "-Wl,-rpath,$MODSECURITY_LIB_DIR" \
    "$LINK_INPUT" \
    -o "$TEMP_OUTPUT"
mv -f "$TEMP_OUTPUT" "$OUTPUT"
rm -rf -- "$INCLUDE_OVERLAY"
trap - EXIT HUP INT TERM

printf 'PASS: targeted C++17 evaluator compiled at %s (not executed)\n' "$OUTPUT"
