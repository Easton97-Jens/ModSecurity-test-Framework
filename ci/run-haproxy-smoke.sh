#!/bin/sh
set -eu

SOURCE_ROOT="${SOURCE_ROOT:-/src}"
BUILD_ROOT="${BUILD_ROOT:-/src/ModSecurity-conector-build}"
if [ "${FORCE_ALL_CASES:-0}" = "1" ] && [ -z "${RESULTS_DIR+x}" ]; then
    RESULTS_DIR="$BUILD_ROOT/results/force-all"
else
    RESULTS_DIR="${RESULTS_DIR:-$BUILD_ROOT/results}"
fi
TMP_ROOT="${TMP_ROOT:-$BUILD_ROOT/tmp}"
LOG_ROOT="${LOG_ROOT:-$BUILD_ROOT/logs}"
SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
. "$SCRIPT_DIR/connector-smoke-common.sh"
. "$SCRIPT_DIR/mrts-common.sh"

prepare_crs_variant() {
    existing_preamble="${MODSECURITY_RULE_PREAMBLE_FILE:-}"
    if [ "$MODSECURITY_TEST_VARIANT" != "with-crs" ]; then
        MODSECURITY_RULE_PREAMBLE_FILE="$existing_preamble"
        export MODSECURITY_RULE_PREAMBLE_FILE
        return 0
    fi
    sh "$FRAMEWORK_ROOT/ci/prepare-crs.sh"
    crs_preamble="$CRS_RUNTIME_DIR/modsecurity-crs-preamble.conf"
    MODSECURITY_RULE_PREAMBLE_FILE=$(combine_rule_preambles "$crs_preamble" "$existing_preamble" "haproxy-with-crs-${MODSECURITY_MRTS_VARIANT:-no-mrts}")
    export MODSECURITY_RULE_PREAMBLE_FILE
}

prepare_mrts_runtime_variant
prepare_crs_variant

connector_smoke_run haproxy "$CONNECTOR_ROOT/connectors/haproxy/harness/run_haproxy_smoke.sh"
