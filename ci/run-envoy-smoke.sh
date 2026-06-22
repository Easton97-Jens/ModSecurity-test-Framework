#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
. "$SCRIPT_DIR/connector-smoke-common.sh"

connector_smoke_run envoy "$CONNECTOR_ROOT/connectors/envoy/harness/run_envoy_smoke.sh"
