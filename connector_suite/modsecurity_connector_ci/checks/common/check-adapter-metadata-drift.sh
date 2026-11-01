#!/bin/sh
# Resolve test infrastructure only from the explicitly selected Framework.
: "${TEST_ROOT:?TEST_ROOT is required explicitly}"
: "${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}"
: "${CONNECTOR_REVISION:?CONNECTOR_REVISION is required explicitly}"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
. "$TEST_ROOT/ci/lib/path-bootstrap.sh"
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
REPO_ROOT=${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}
FRAMEWORK_ROOT=$TEST_ROOT
[ -d "$FRAMEWORK_ROOT" ] || { echo "adapter_metadata_drift: missing FRAMEWORK_ROOT; run git submodule update --init --recursive or set FRAMEWORK_ROOT=/path/to/ModSecurity-test-Framework"; exit 77; }

PYTHON_BIN="${PYTHON_BIN:-${PYTHON:-python3}}"

FRAMEWORK_ROOT="$TEST_ROOT" CONNECTOR_ROOT="$REPO_ROOT" "$PYTHON_BIN" -P "$FRAMEWORK_ROOT/ci/lib/adapter_metadata.py" check-drift
