#!/bin/sh
# Resolve test infrastructure only from the explicitly selected Framework.
: "${TEST_ROOT:?TEST_ROOT is required explicitly}"
: "${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}"
: "${CONNECTOR_REVISION:?CONNECTOR_REVISION is required explicitly}"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
. "$TEST_ROOT/ci/lib/path-bootstrap.sh"
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PYTHON_BIN=${PYTHON:-python3}

command -v "$PYTHON_BIN" >/dev/null 2>&1 || {
    echo "BLOCKED: Python interpreter is unavailable: $PYTHON_BIN" >&2
    exit 77
}

exec "$PYTHON_BIN" -P "$SCRIPT_DIR/clang_analysis_baseline.py" \
    --check-tools \
    --clang-tidy "${CLANG_TIDY:-clang-tidy}" \
    --clang "${CLANG:-clang}" \
    --clangxx "${CLANGXX:-clang++}"
