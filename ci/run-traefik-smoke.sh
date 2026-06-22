#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
. "$SCRIPT_DIR/connector-smoke-common.sh"

connector_smoke_run traefik "$CONNECTOR_ROOT/connectors/traefik/harness/run_traefik_smoke.sh"
