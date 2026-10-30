#!/bin/sh
: "${TEST_ROOT:?TEST_ROOT is required explicitly}"
set -eu

SCRIPT_DIR=$(CDPATH='' cd "$(dirname "$0")" && pwd)
CONNECTOR_ROOT="${CONNECTOR_ROOT:-$(CDPATH='' cd "$SCRIPT_DIR/../../.." && pwd)}"
FRAMEWORK_ROOT="${FRAMEWORK_ROOT:-$CONNECTOR_ROOT/modules/ModSecurity-test-Framework}"
HARNESS_PATH="$SCRIPT_DIR/$(basename "$0")"

# shellcheck source=/dev/null
. "$FRAMEWORK_ROOT/ci/lib/common.sh"

export CONNECTOR_ROOT FRAMEWORK_ROOT HARNESS_PATH

sh "$TEST_ROOT/connector_suite/common/scripts/run_blocked_runtime_smoke.sh" \
    lighttpd \
    "$LIGHTTPD_INTEGRATION_MODE" \
    LIGHTTPD_BIN \
    lighttpd \
    "lighttpd runtime dependency not available in local common.sh-managed paths" \
    "lighttpd sidecar_proxy runtime smoke is not available" \
    "lighttpd sidecar_proxy integration" \
    "Legacy sidecar_proxy smoke; native-module build, start, and Phase-1 runtime evidence use the connector-local native targets." \
    1
