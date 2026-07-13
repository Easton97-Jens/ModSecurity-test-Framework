#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
CI_ROOT="${CI_ROOT:-$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)}"
. "$CI_ROOT/lib/path-bootstrap.sh"
. "$CI_ROOT/lib/connector-smoke-common.sh"

connector_smoke_run lighttpd "$CONNECTOR_ROOT/connectors/lighttpd/harness/run_lighttpd_smoke.sh"
