#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
. "$SCRIPT_DIR/../lib/path-bootstrap.sh"
REPO_ROOT="${REPO_ROOT:-$FRAMEWORK_ROOT}"
. "$CI_ROOT/lib/common.sh"

MODSECURITY_V3_SOURCE_DIR="${MODSECURITY_V3_SOURCE_DIR:-$MODSECURITY_SOURCE_DIR}"
MODSECURITY_V3_DIR="${MODSECURITY_V3_DIR:-$BUILD_ROOT/ModSecurity_V3_build}"
LOG_DIR="${LOG_DIR:-$BUILD_ROOT/logs}"
REFRESH="${REFRESH:-0}"

log_file=""

run_logged() {
    label=$1
    shift
    log_file="$LOG_DIR/$label.log"
    echo "v3_build: running $*"
    echo "v3_build: log $log_file"
    if "$@" >"$log_file" 2>&1; then
        return 0
    fi
    rc=$?
    echo "v3_build: blocked command failed: $*"
    echo "v3_build: see log: $log_file"
    exit 77
}

echo "v3_build: MODSECURITY_V3_SOURCE_DIR=$MODSECURITY_V3_SOURCE_DIR"
echo "v3_build: MODSECURITY_V3_DIR=$MODSECURITY_V3_DIR"
echo "v3_build: BUILD_ROOT=$BUILD_ROOT"
echo "v3_build: LOG_DIR=$LOG_DIR"

for generated_path in "$MODSECURITY_V3_DIR" "$BUILD_ROOT" "$LOG_DIR"; do
    case "$generated_path" in
        /*) ;;
        *)
            echo "v3_build: blocked generated path must be absolute: $generated_path"
            exit 77
            ;;
    esac
    assert_safe_runtime_path "$generated_path" "$generated_path" || exit 77
done

if [ ! -d "$MODSECURITY_V3_SOURCE_DIR" ]; then
    echo "v3_build: blocked missing source directory: $MODSECURITY_V3_SOURCE_DIR"
    exit 77
fi
ci_require_approved_modsecurity_v3_checkout "$MODSECURITY_V3_SOURCE_DIR" || exit 77

source_real=$(ci_canonical_existing "$MODSECURITY_V3_SOURCE_DIR")

if [ -e "$MODSECURITY_V3_DIR" ]; then
    dest_real=$(ci_canonical_existing "$MODSECURITY_V3_DIR")
    if [ "$dest_real" = "$source_real" ]; then
        echo "v3_build: blocked destination equals source checkout"
        exit 77
    fi
    if [ "$REFRESH" != "1" ]; then
        echo "v3_build: blocked destination exists: $MODSECURITY_V3_DIR"
        echo "v3_build: set REFRESH=1 to replace the destination copy"
        exit 77
    fi
    safe_remove_runtime_path "$MODSECURITY_V3_DIR" "$BUILD_ROOT" "v3 build REFRESH destination" || exit 77
fi

dest_parent=$(dirname "$MODSECURITY_V3_DIR")

mkdir -p "$dest_parent" "$LOG_DIR"
run_logged copy-source cp -a "$MODSECURITY_V3_SOURCE_DIR" "$MODSECURITY_V3_DIR"

if [ ! -d "$MODSECURITY_V3_DIR" ]; then
    echo "v3_build: blocked copy did not create destination: $MODSECURITY_V3_DIR"
    exit 77
fi

(
    cd "$MODSECURITY_V3_DIR"
    run_logged build-sh ./build.sh
    run_logged configure ./configure
    run_logged make make
)

if [ -f "$MODSECURITY_V3_DIR/src/.libs/libmodsecurity.so" ]; then
    echo "v3_build: built library: $MODSECURITY_V3_DIR/src/.libs/libmodsecurity.so"
else
    echo "v3_build: blocked build completed without expected library: $MODSECURITY_V3_DIR/src/.libs/libmodsecurity.so"
    exit 77
fi
