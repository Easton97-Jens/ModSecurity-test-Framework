#!/bin/sh
: "${TEST_ROOT:?TEST_ROOT is required explicitly}"
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CONNECTOR_ROOT="${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}"
FRAMEWORK_ROOT="${TEST_ROOT:?TEST_ROOT is required explicitly}"
VERIFIED_RUN_ROOT="${VERIFIED_RUN_ROOT:-${RUNNER_TEMP:-${TMPDIR:-/var/tmp}}/ModSecurity-conector-verified}"
VERIFIED_BUILD_ROOT="${VERIFIED_BUILD_ROOT:-$VERIFIED_RUN_ROOT/build}"
VERIFIED_SOURCE_ROOT="${VERIFIED_SOURCE_ROOT:-$VERIFIED_RUN_ROOT/src}"
VERIFIED_TMP_ROOT="${VERIFIED_TMP_ROOT:-$VERIFIED_RUN_ROOT/tmp}"
VERIFIED_LOG_ROOT="${VERIFIED_LOG_ROOT:-$VERIFIED_RUN_ROOT/logs}"
SOURCE_ROOT="${SOURCE_ROOT:-$VERIFIED_SOURCE_ROOT}"
BUILD_ROOT="${BUILD_ROOT:-$VERIFIED_BUILD_ROOT}"
MRTS_BUILD_ROOT="${MRTS_BUILD_ROOT:-$BUILD_ROOT/mrts}"
TMP_ROOT="${TMP_ROOT:-$VERIFIED_TMP_ROOT}"
LOG_ROOT="${LOG_ROOT:-$VERIFIED_LOG_ROOT}"
PYTHON="${PYTHON:-python3}"
PYTHONDONTWRITEBYTECODE="${PYTHONDONTWRITEBYTECODE:-1}"
FORCE_ALL_CASES="${FORCE_ALL_CASES:-1}"

export CONNECTOR_ROOT FRAMEWORK_ROOT SOURCE_ROOT BUILD_ROOT MRTS_BUILD_ROOT TMP_ROOT LOG_ROOT
export PYTHONDONTWRITEBYTECODE FORCE_ALL_CASES
"$PYTHON" "$SCRIPT_DIR/prepare-verified-runtime-paths.py" --build-root "$BUILD_ROOT" || exit 77

COMMON_SH="$FRAMEWORK_ROOT/ci/lib/common.sh"
if [ -f "$COMMON_SH" ]; then
    REPO_ROOT="$CONNECTOR_ROOT"
    . "$COMMON_SH"
fi

FULL_MATRIX_RESULTS_ROOT="${FULL_MATRIX_RESULTS_ROOT:-$BUILD_ROOT/results/full-matrix}"
FULL_MATRIX_LOG_ROOT="${FULL_MATRIX_LOG_ROOT:-$LOG_ROOT/full-matrix}"
FULL_MATRIX_REPORT_DIR="${FULL_MATRIX_REPORT_DIR:-$CONNECTOR_ROOT/reports/testing/generated}"
FULL_MATRIX_MANIFEST="${FULL_MATRIX_MANIFEST:-$FULL_MATRIX_RESULTS_ROOT/full-runtime-matrix-runs.jsonl}"

assert_safe_runtime_path "$BUILD_ROOT" BUILD_ROOT || exit 77
assert_safe_runtime_path "$TMP_ROOT" TMP_ROOT || exit 77
assert_safe_runtime_path "$LOG_ROOT" LOG_ROOT || exit 77
assert_safe_runtime_path "$MRTS_BUILD_ROOT" MRTS_BUILD_ROOT || exit 77
assert_safe_runtime_path "$FULL_MATRIX_RESULTS_ROOT" FULL_MATRIX_RESULTS_ROOT || exit 77
assert_safe_runtime_path "$FULL_MATRIX_LOG_ROOT" FULL_MATRIX_LOG_ROOT || exit 77
assert_not_system_path_for_write "$FULL_MATRIX_REPORT_DIR" FULL_MATRIX_REPORT_DIR || exit 77
assert_not_system_path_for_write "$FULL_MATRIX_MANIFEST" FULL_MATRIX_MANIFEST || exit 77
mkdir -p "$FULL_MATRIX_RESULTS_ROOT" "$FULL_MATRIX_LOG_ROOT" "$FULL_MATRIX_REPORT_DIR"
: > "$FULL_MATRIX_MANIFEST"

safe_rm_rf() {
    target=$1
    parent=$2
    label=$3

    safe_remove_runtime_path "$target" "$parent" "$label"
    return $?
}

prepare_haproxy_crs_preamble() {
    connector=$1
    test_variant=$2

    if [ "$connector" != "haproxy" ] || [ "$test_variant" != "with-crs" ]; then
        return 0
    fi
    sh "$FRAMEWORK_ROOT/ci/provisioning/fetch-crs.sh"
    sh "$FRAMEWORK_ROOT/ci/provisioning/prepare-crs.sh"
    MODSECURITY_RULE_PREAMBLE_FILE="$CRS_RUNTIME_DIR/modsecurity-crs-preamble.conf"
    export MODSECURITY_RULE_PREAMBLE_FILE
    return 0
}

run_one() {
    test_variant=$1
    mrts_variant=$2
    connector=$3

    results_dir="$FULL_MATRIX_RESULTS_ROOT/$test_variant/$mrts_variant/$connector"
    log_dir="$FULL_MATRIX_LOG_ROOT/$test_variant/$mrts_variant"
    log_path="$log_dir/$connector.log"
    summary_path="$results_dir/$connector-summary.json"

    assert_safe_runtime_path "$log_dir" "full matrix log dir" || exit 77
    assert_safe_runtime_path "$results_dir" "full matrix results dir" || exit 77
    assert_not_system_path_for_write "$log_path" "full matrix log path" || exit 77
    mkdir -p "$log_dir"
    safe_rm_rf "$results_dir" "$FULL_MATRIX_RESULTS_ROOT" "full matrix results directory"
    mkdir -p "$results_dir"
    : > "$log_path"

    echo "full-matrix: running connector=$connector test_variant=$test_variant mrts_variant=$mrts_variant results=$results_dir"
    started_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    MODSECURITY_RULE_PREAMBLE_FILE=
    if prepare_haproxy_crs_preamble "$connector" "$test_variant" >> "$log_path" 2>&1; then
        set +e
        env \
            FRAMEWORK_ROOT="$FRAMEWORK_ROOT" \
            SOURCE_ROOT="$SOURCE_ROOT" \
            BUILD_ROOT="$BUILD_ROOT" \
            MRTS_BUILD_ROOT="$MRTS_BUILD_ROOT" \
            TMP_ROOT="$TMP_ROOT" \
            LOG_ROOT="$LOG_ROOT" \
            RESULTS_DIR="$results_dir" \
            MODSECURITY_TEST_VARIANT="$test_variant" \
            MODSECURITY_MRTS_VARIANT="$mrts_variant" \
            MODSECURITY_RULE_PREAMBLE_FILE="$MODSECURITY_RULE_PREAMBLE_FILE" \
            FORCE_ALL_CASES="$FORCE_ALL_CASES" \
            SKIP_RUNTIME_COMPONENT_PREPARE=1 \
            PYTHONDONTWRITEBYTECODE="$PYTHONDONTWRITEBYTECODE" \
            make -C "$CONNECTOR_ROOT" "smoke-$connector" >> "$log_path" 2>&1
        rc=$?
        set -eu
    else
        rc=$?
        echo "full-matrix: blocked preparing connector=$connector test_variant=$test_variant rc=$rc" >> "$log_path"
    fi
    ended_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    echo "full-matrix: finished connector=$connector test_variant=$test_variant mrts_variant=$mrts_variant rc=$rc log=$log_path"

    RUN_CONNECTOR="$connector" \
    RUN_TEST_VARIANT="$test_variant" \
    RUN_MRTS_VARIANT="$mrts_variant" \
    RUN_RC="$rc" \
    RUN_STARTED_AT="$started_at" \
    RUN_ENDED_AT="$ended_at" \
    RUN_RESULTS_DIR="$results_dir" \
    RUN_SUMMARY_PATH="$summary_path" \
    RUN_LOG_PATH="$log_path" \
    "$PYTHON" - <<'PY' >> "$FULL_MATRIX_MANIFEST"
import json
import os

print(json.dumps({
    "connector": os.environ["RUN_CONNECTOR"],
    "test_variant": os.environ["RUN_TEST_VARIANT"],
    "mrts_variant": os.environ["RUN_MRTS_VARIANT"],
    "return_code": int(os.environ["RUN_RC"]),
    "started_at": os.environ["RUN_STARTED_AT"],
    "ended_at": os.environ["RUN_ENDED_AT"],
    "results_dir": os.environ["RUN_RESULTS_DIR"],
    "summary_path": os.environ["RUN_SUMMARY_PATH"],
    "log_path": os.environ["RUN_LOG_PATH"],
}, sort_keys=True))
PY
    return 0
}

for test_variant in no-crs with-crs; do
    for mrts_variant in no-mrts with-mrts; do
        for connector in apache nginx haproxy; do
            run_one "$test_variant" "$mrts_variant" "$connector"
        done
    done
done

set +e
"$PYTHON" "$TEST_ROOT/connector_suite/modsecurity_connector_ci/evidence/reports/generate-full-runtime-matrix.py" \
    --connector-root "$CONNECTOR_ROOT" \
    --framework-root "$FRAMEWORK_ROOT" \
    --build-root "$BUILD_ROOT" \
    --log-root "$LOG_ROOT" \
    --manifest "$FULL_MATRIX_MANIFEST" \
    --output-dir "$FULL_MATRIX_REPORT_DIR"
report_rc=$?
set -eu

echo "full-matrix: manifest=$FULL_MATRIX_MANIFEST"
echo "full-matrix: report=$FULL_MATRIX_REPORT_DIR/canonical/full-runtime-matrix.generated.md"
exit "$report_rc"
