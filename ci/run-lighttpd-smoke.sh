#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
. "$SCRIPT_DIR/connector-smoke-common.sh"

connector_smoke_run lighttpd "$CONNECTOR_ROOT/connectors/lighttpd/harness/run_lighttpd_smoke.sh"
