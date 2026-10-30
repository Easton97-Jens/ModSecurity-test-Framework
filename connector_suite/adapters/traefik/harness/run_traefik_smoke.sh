#!/bin/sh
: "${TEST_ROOT:?TEST_ROOT is required explicitly}"
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
CONNECTOR_ROOT="${CONNECTOR_ROOT:-$(CDPATH= cd "$SCRIPT_DIR/../../.." && pwd)}"
FRAMEWORK_ROOT="${FRAMEWORK_ROOT:-$CONNECTOR_ROOT/modules/ModSecurity-test-Framework}"
HARNESS_PATH="$SCRIPT_DIR/$(basename "$0")"

. "$FRAMEWORK_ROOT/ci/lib/common.sh"

export CONNECTOR_ROOT FRAMEWORK_ROOT HARNESS_PATH

sh "$TEST_ROOT/connector_suite/common/scripts/run_blocked_runtime_smoke.sh" \
    traefik \
    "$TRAEFIK_INTEGRATION_MODE" \
    TRAEFIK_BIN \
    traefik \
    "traefik runtime dependency not available in local common.sh-managed paths" \
    "Traefik forwardAuth runtime smoke is blocked until forwardAuth service wiring and a libmodsecurity-backed decision service are available." \
    "forwardAuth runtime configuration and libmodsecurity-backed decision service" \
    "Phase 1 targets forwardAuth; a Go plugin is explicitly out of scope."
