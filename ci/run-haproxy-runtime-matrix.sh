#!/bin/sh
set -u

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
FRAMEWORK_ROOT="${FRAMEWORK_ROOT:-$(CDPATH= cd "$SCRIPT_DIR/.." && pwd)}"
CONNECTOR_ROOT="${CONNECTOR_ROOT:-$(pwd)}"
BUILD_ROOT="${BUILD_ROOT:-/src/ModSecurity-conector-build}"
RESULTS_ROOT="${RESULTS_ROOT:-$BUILD_ROOT/results}"
TMP_ROOT="${TMP_ROOT:-$BUILD_ROOT/tmp/haproxy-runtime-matrix}"
PYTHON_BIN="${PYTHON:-python3}"
MATRIX_VARIANT="${HAPROXY_MATRIX_VARIANT:-all}"

run_smoke_and_preserve_summary() {
    mkdir -p "$TMP_ROOT"
    pre_matrix_summary="$TMP_ROOT/pre-root-haproxy-summary.json"
    pre_matrix_results="$TMP_ROOT/pre-root-haproxy-results.jsonl"
    pre_matrix_text="$TMP_ROOT/pre-root-haproxy-summary.txt"
    rm -f "$pre_matrix_summary" "$pre_matrix_results" "$pre_matrix_text"
    if [ -f "$RESULTS_ROOT/haproxy-summary.json" ] && grep -q '"validation_mode": "haproxy-runtime-matrix"' "$RESULTS_ROOT/haproxy-summary.json"; then
        cp "$RESULTS_ROOT/haproxy-summary.json" "$pre_matrix_summary"
        if [ -f "$RESULTS_ROOT/haproxy-results.jsonl" ]; then
            cp "$RESULTS_ROOT/haproxy-results.jsonl" "$pre_matrix_results"
        fi
        if [ -f "$RESULTS_ROOT/haproxy-summary.txt" ]; then
            cp "$RESULTS_ROOT/haproxy-summary.txt" "$pre_matrix_text"
        fi
    fi
    echo "haproxy-runtime-matrix: running make smoke-haproxy"
    set +e
    FRAMEWORK_ROOT="$FRAMEWORK_ROOT" CONNECTOR_ROOT="$CONNECTOR_ROOT" BUILD_ROOT="$BUILD_ROOT" \
        make -C "$CONNECTOR_ROOT" smoke-haproxy
    smoke_rc=$?
    set -e
    echo "haproxy-runtime-matrix: smoke-haproxy exit=$smoke_rc"
    smoke_summary="$RESULTS_ROOT/haproxy-smoke-summary.json"
    smoke_results="$RESULTS_ROOT/haproxy-smoke-results.jsonl"
    if [ -f "$RESULTS_ROOT/haproxy-summary.json" ]; then
        cp "$RESULTS_ROOT/haproxy-summary.json" "$smoke_summary"
    else
        : > "$smoke_summary"
    fi
    if [ -f "$RESULTS_ROOT/haproxy-results.jsonl" ]; then
        cp "$RESULTS_ROOT/haproxy-results.jsonl" "$smoke_results"
    else
        : > "$smoke_results"
    fi
}

restore_previous_root_matrix() {
    if [ -f "$pre_matrix_summary" ]; then
        cp "$pre_matrix_summary" "$RESULTS_ROOT/haproxy-summary.json"
        if [ -f "$pre_matrix_results" ]; then
            cp "$pre_matrix_results" "$RESULTS_ROOT/haproxy-results.jsonl"
        fi
        if [ -f "$pre_matrix_text" ]; then
            cp "$pre_matrix_text" "$RESULTS_ROOT/haproxy-summary.txt"
        fi
    fi
}

write_matrix_variant() {
    variant=$1
    out_dir=$2
    "$PYTHON_BIN" "$FRAMEWORK_ROOT/ci/write-haproxy-runtime-matrix.py" \
        --framework-root "$FRAMEWORK_ROOT" \
        --connector-root "$CONNECTOR_ROOT" \
        --build-root "$BUILD_ROOT" \
        --results-dir "$out_dir" \
        --variant "$variant" \
        --smoke-summary "$smoke_summary"
}

update_snapshot() {
    "$PYTHON_BIN" "$FRAMEWORK_ROOT/ci/update-runtime-snapshot.py" \
        --framework-root "$FRAMEWORK_ROOT" \
        --connector-root "$CONNECTOR_ROOT" \
        --output-root "$CONNECTOR_ROOT" \
        --build-root "$BUILD_ROOT" \
        --haproxy-exit-code "$matrix_rc" \
        --haproxy-command "make runtime-matrix-haproxy"
}

mkdir -p "$RESULTS_ROOT"
run_smoke_and_preserve_summary

matrix_rc=0
case "$MATRIX_VARIANT" in
    no-crs)
        write_matrix_variant no-crs "$RESULTS_ROOT/no-crs" || matrix_rc=$?
        restore_previous_root_matrix
        ;;
    with-crs)
        write_matrix_variant with-crs "$RESULTS_ROOT/with-crs" || matrix_rc=$?
        restore_previous_root_matrix
        ;;
    all)
        write_matrix_variant no-crs "$RESULTS_ROOT/no-crs" || matrix_rc=$?
        write_matrix_variant with-crs "$RESULTS_ROOT/with-crs" || matrix_rc=$?
        write_matrix_variant combined "$RESULTS_ROOT" || matrix_rc=$?
        update_snapshot || matrix_rc=$?
        ;;
    *)
        echo "haproxy-runtime-matrix: unsupported HAPROXY_MATRIX_VARIANT=$MATRIX_VARIANT" >&2
        exit 2
        ;;
esac

if [ "$smoke_rc" -ne 0 ] && [ "$matrix_rc" -eq 0 ]; then
    exit "$smoke_rc"
fi
exit "$matrix_rc"
