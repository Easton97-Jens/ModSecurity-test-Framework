#!/bin/sh
# Resolve test infrastructure only from the explicitly selected Framework.
: "${TEST_ROOT:?TEST_ROOT is required explicitly}"
: "${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}"
: "${CONNECTOR_REVISION:?CONNECTOR_REVISION is required explicitly}"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
. "$TEST_ROOT/ci/lib/path-bootstrap.sh"
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}
ROOT=$(CDPATH= cd -- "$ROOT" && pwd -P)
PYTHON_BIN=${PYTHON:-python3}
CC_BIN=${CC:-cc}
MAKE_BIN=${MAKE:-make}

block() {
    echo "BLOCKED: $*" >&2
    exit 77
}

require_external_output() {
    requested=$1
    case "$requested" in
        /*) ;;
        *) echo "FAIL: COMPDB_OUTPUT must be absolute: $requested" >&2; exit 2 ;;
    esac
    command -v realpath >/dev/null 2>&1 || block "missing realpath utility"
    requested=$(realpath -m -- "$requested") || {
        echo "FAIL: cannot canonicalize COMPDB_OUTPUT: $requested" >&2
        exit 2
    }
    case "$requested" in
        "$ROOT"|"$ROOT"/*)
            echo "FAIL: COMPDB_OUTPUT must be outside the checkout: $requested" >&2
            exit 2
            ;;
        *) : ;;
    esac
    parent=$(dirname -- "$requested")
    name=$(basename -- "$requested")
    mkdir -p "$parent" || block "cannot create COMPDB_OUTPUT parent: $parent"
    parent=$(CDPATH= cd -- "$parent" && pwd -P) || block "cannot resolve COMPDB_OUTPUT parent: $parent"
    output=$parent/$name
    case "$output" in
        "$ROOT"|"$ROOT"/*)
            echo "FAIL: COMPDB_OUTPUT must be outside the checkout: $output" >&2
            exit 2
            ;;
        *) : ;;
    esac
    printf '%s\n' "$output"
}

[ -n "${COMPDB_OUTPUT:-}" ] || {
    echo "FAIL: COMPDB_OUTPUT is required" >&2
    exit 2
}
OUTPUT=$(require_external_output "$COMPDB_OUTPUT")

command -v "$PYTHON_BIN" >/dev/null 2>&1 || block "missing Python interpreter: $PYTHON_BIN"
command -v "$CC_BIN" >/dev/null 2>&1 || block "missing C compiler: $CC_BIN"
command -v "$MAKE_BIN" >/dev/null 2>&1 || block "missing make program: $MAKE_BIN"
command -v bear >/dev/null 2>&1 || block "missing Bear compiler interception tool"

CAPTURE_DIR=$(mktemp -d "$(dirname -- "$OUTPUT")/.compile-db-nginx-c17.XXXXXX") || \
    block "cannot create external Bear capture directory"
trap 'rm -rf "$CAPTURE_DIR"' EXIT HUP INT TERM

bear --output "$CAPTURE_DIR/compile_commands.raw.json" -- \
    "$MAKE_BIN" --no-print-directory check-nginx-c17 \
    CC="$CC_BIN" BUILD_ROOT="$CAPTURE_DIR/build" || {
    rc=$?
    exit "$rc"
}

[ -s "$CAPTURE_DIR/compile_commands.raw.json" ] || {
    echo "FAIL: Bear did not produce a compilation database" >&2
    exit 1
}

"$PYTHON_BIN" -P "$SCRIPT_DIR/compile_database.py" \
    --repo-root "$ROOT" \
    --input "$CAPTURE_DIR/compile_commands.raw.json" \
    --capture-root "$CAPTURE_DIR" \
    --output "$OUTPUT" \
    --merge-existing \
    --require nginx
