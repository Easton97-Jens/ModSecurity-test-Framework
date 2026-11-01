#!/bin/sh
# Resolve test infrastructure only from the explicitly selected Framework.
: "${TEST_ROOT:?TEST_ROOT is required explicitly}"
: "${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}"
: "${CONNECTOR_REVISION:?CONNECTOR_REVISION is required explicitly}"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
. "$TEST_ROOT/ci/lib/path-bootstrap.sh"
set -u

missing=0

check_tool() {
    label=$1
    tool=$2
    path=$(command -v "$tool" 2>/dev/null || true)
    if [ -z "$path" ]; then
        echo "BLOCKED: $label is unavailable: $tool" >&2
        missing=1
        return
    fi

    version=$("$path" --version 2>&1 | sed -n '1p' || true)
    if [ -n "$version" ]; then
        printf '%s: %s (%s)\n' "$label" "$path" "$version"
    else
        printf '%s: %s (version unavailable)\n' "$label" "$path"
    fi
}

check_tool CC "${CC:-cc}"
check_tool CXX "${CXX:-c++}"
check_tool clangd clangd
check_tool Bear bear

if [ "$missing" -ne 0 ]; then
    exit 77
fi

echo "PASS: local C/C++ analysis tools are available"
