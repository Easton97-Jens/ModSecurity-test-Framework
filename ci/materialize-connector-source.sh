#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
FRAMEWORK_ROOT="${FRAMEWORK_ROOT:-$(CDPATH= cd "$SCRIPT_DIR/.." && pwd)}"
CONNECTOR_ROOT="${CONNECTOR_ROOT:-$(pwd)}"
REPO_ROOT="$CONNECTOR_ROOT"
. "$SCRIPT_DIR/common.sh"

PYTHON_BIN="${PYTHON_BIN:-$(ci_python)}"

exec env CONNECTOR_ROOT="$CONNECTOR_ROOT" "$PYTHON_BIN" "$FRAMEWORK_ROOT/ci/materialize-connector-source.py" "$@"
