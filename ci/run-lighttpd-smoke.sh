#!/bin/sh
set -eu

SOURCE_ROOT="${SOURCE_ROOT:-/src}"
BUILD_ROOT="${BUILD_ROOT:-/src/ModSecurity-conector-build}"
RESULTS_DIR="${RESULTS_DIR:-$BUILD_ROOT/results}"
TMP_ROOT="${TMP_ROOT:-$BUILD_ROOT/tmp}"
LOG_ROOT="${LOG_ROOT:-$BUILD_ROOT/logs}"
SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
. "$SCRIPT_DIR/connector-smoke-common.sh"

connector_smoke_run lighttpd "$CONNECTOR_ROOT/connectors/lighttpd/harness/run_lighttpd_smoke.sh"
