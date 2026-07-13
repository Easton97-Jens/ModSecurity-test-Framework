#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
CI_ROOT="${CI_ROOT:-$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)}"
. "$CI_ROOT/lib/path-bootstrap.sh"
. "$CI_ROOT/lib/connector-smoke-common.sh"

connector_smoke_run envoy "$CONNECTOR_ROOT/connectors/envoy/harness/run_envoy_smoke.sh"
