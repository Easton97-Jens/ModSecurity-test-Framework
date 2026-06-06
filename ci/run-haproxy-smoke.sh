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

connector_smoke_run haproxy "$CONNECTOR_ROOT/connectors/haproxy/harness/run_haproxy_smoke.sh"
