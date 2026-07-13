#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
CI_ROOT="${CI_ROOT:-$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)}"
. "$CI_ROOT/lib/path-bootstrap.sh"
CONNECTOR_ROOT="${CONNECTOR_ROOT:-$(pwd)}"
REPO_ROOT="$CONNECTOR_ROOT"
. "$CI_ROOT/lib/common.sh"

PYTHON_BIN="${PYTHON_BIN:-$(ci_python)}"

exec env CONNECTOR_ROOT="$CONNECTOR_ROOT" "$PYTHON_BIN" "$FRAMEWORK_ROOT/ci/provisioning/materialize-connector-source.py" "$@"
