#!/bin/sh
set -u

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
FRAMEWORK_ROOT="${FRAMEWORK_ROOT:-$(CDPATH= cd "$SCRIPT_DIR/.." && pwd)}"
CONNECTOR_ROOT="${CONNECTOR_ROOT:-$(pwd)}"
BUILD_ROOT="${BUILD_ROOT:-/src/ModSecurity-conector-build}"
RESULTS_ROOT="${RESULTS_ROOT:-$BUILD_ROOT/results}"
TMP_ROOT="${TMP_ROOT:-$BUILD_ROOT/tmp/haproxy-runtime-matrix}"
LOG_ROOT="${LOG_ROOT:-$BUILD_ROOT/logs}"
PYTHON_BIN="${PYTHON:-python3}"
MATRIX_VARIANT="${HAPROXY_MATRIX_VARIANT:-all}"
FORCE_ALL_CASES="${FORCE_ALL_CASES:-0}"
export FORCE_ALL_CASES
COMMON_SH="$FRAMEWORK_ROOT/ci/common.sh"
if [ -f "$COMMON_SH" ]; then
    . "$COMMON_SH"
fi

prepare_crs_if_needed() {
    MODSECURITY_RULE_PREAMBLE_FILE="${MODSECURITY_RULE_PREAMBLE_FILE:-$BUILD_ROOT/crs/modsecurity-crs-preamble.conf}"
    export MODSECURITY_RULE_PREAMBLE_FILE
    if [ -f "$MODSECURITY_RULE_PREAMBLE_FILE" ]; then
        return 0
    fi
    if [ ! -f "$FRAMEWORK_ROOT/ci/prepare-crs.sh" ]; then
        echo "haproxy-runtime-matrix: prepare-crs helper missing" >&2
        return 77
    fi
    SOURCE_ROOT="${SOURCE_ROOT:-/src}" \
        BUILD_ROOT="$BUILD_ROOT" \
        TMP_ROOT="${TMP_ROOT:-$BUILD_ROOT/tmp}" \
        LOG_ROOT="$LOG_ROOT" \
        CONNECTOR_ROOT="$CONNECTOR_ROOT" \
        FRAMEWORK_ROOT="$FRAMEWORK_ROOT" \
        sh "$FRAMEWORK_ROOT/ci/prepare-crs.sh"
}

copy_variant_to_root() {
    variant_dir=$1
    if [ -f "$variant_dir/haproxy-summary.json" ]; then
        cp "$variant_dir/haproxy-summary.json" "$RESULTS_ROOT/haproxy-summary.json"
    fi
    if [ -f "$variant_dir/haproxy-results.jsonl" ]; then
        cp "$variant_dir/haproxy-results.jsonl" "$RESULTS_ROOT/haproxy-results.jsonl"
    fi
    if [ -f "$variant_dir/haproxy-summary.txt" ]; then
        cp "$variant_dir/haproxy-summary.txt" "$RESULTS_ROOT/haproxy-summary.txt"
    fi
}

run_variant() {
    variant=$1
    out_dir=$2
    mkdir -p "$out_dir"
    if [ "$variant" = "with-crs" ]; then
        prepare_crs_if_needed || return $?
    fi
    echo "haproxy-runtime-matrix: running make smoke-haproxy variant=$variant results=$out_dir"
    set +e
    FRAMEWORK_ROOT="$FRAMEWORK_ROOT" \
        CONNECTOR_ROOT="$CONNECTOR_ROOT" \
        BUILD_ROOT="$BUILD_ROOT" \
        RESULTS_DIR="$out_dir" \
        MODSECURITY_TEST_VARIANT="$variant" \
        MODSECURITY_RULE_PREAMBLE_FILE="${MODSECURITY_RULE_PREAMBLE_FILE:-}" \
        make -C "$CONNECTOR_ROOT" smoke-haproxy
    rc=$?
    set -e
    echo "haproxy-runtime-matrix: smoke-haproxy variant=$variant exit=$rc"
    return "$rc"
}

update_snapshot() {
    snapshot_force_args=
    haproxy_command="make runtime-matrix-haproxy"
    if [ "$FORCE_ALL_CASES" = "1" ]; then
        snapshot_force_args="--force-all"
        haproxy_command="FORCE_ALL_CASES=1 make runtime-matrix-haproxy"
    fi
    "$PYTHON_BIN" "$FRAMEWORK_ROOT/ci/update-runtime-snapshot.py" \
        --framework-root "$FRAMEWORK_ROOT" \
        --connector-root "$CONNECTOR_ROOT" \
        --output-root "$CONNECTOR_ROOT" \
        --build-root "$BUILD_ROOT" \
        --haproxy-exit-code "$matrix_rc" \
        --haproxy-command "$haproxy_command" \
        $snapshot_force_args
}

mkdir -p "$RESULTS_ROOT" "$TMP_ROOT"

matrix_rc=0
if [ "$FORCE_ALL_CASES" = "1" ]; then
    run_variant no-crs "$RESULTS_ROOT/force-all" || matrix_rc=$?
    update_snapshot || {
        rc=$?
        if [ "$matrix_rc" -eq 0 ]; then
            matrix_rc=$rc
        fi
    }
    exit "$matrix_rc"
fi

case "$MATRIX_VARIANT" in
    no-crs)
        run_variant no-crs "$RESULTS_ROOT/no-crs" || matrix_rc=$?
        copy_variant_to_root "$RESULTS_ROOT/no-crs"
        ;;
    with-crs)
        run_variant with-crs "$RESULTS_ROOT/with-crs" || matrix_rc=$?
        copy_variant_to_root "$RESULTS_ROOT/with-crs"
        ;;
    all)
        run_variant no-crs "$RESULTS_ROOT/no-crs" || matrix_rc=$?
        run_variant with-crs "$RESULTS_ROOT/with-crs" || {
            rc=$?
            if [ "$matrix_rc" -eq 0 ]; then
                matrix_rc=$rc
            fi
        }
        copy_variant_to_root "$RESULTS_ROOT/with-crs"
        update_snapshot || matrix_rc=$?
        ;;
    *)
        echo "haproxy-runtime-matrix: unsupported HAPROXY_MATRIX_VARIANT=$MATRIX_VARIANT" >&2
        exit 2
        ;;
esac

exit "$matrix_rc"
