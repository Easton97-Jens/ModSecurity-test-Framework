#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
. "$SCRIPT_DIR/../lib/path-bootstrap.sh"
. "$CI_ROOT/lib/connector-smoke-common.sh"

connector_smoke_run traefik "$TEST_ROOT/connector_suite/adapters/traefik/harness/run_traefik_smoke.sh"
