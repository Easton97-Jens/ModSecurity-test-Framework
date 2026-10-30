#!/bin/sh
# Resolve test infrastructure only from the explicitly selected Framework.
: "${TEST_ROOT:?TEST_ROOT is required explicitly}"
: "${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}"
: "${CONNECTOR_REVISION:?CONNECTOR_REVISION is required explicitly}"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
. "$TEST_ROOT/ci/lib/path-bootstrap.sh"
# One named policy boundary/input per admitted behavioral case.
set -eu
SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
case "${1:-}" in python-allowed|python-blocked|shell-allowed|shell-blocked) ;; *) echo "FAIL: unknown active runtime-path case" >&2; exit 2 ;; esac
exec "${PYTHON:-python3}" -P "$SCRIPT_DIR/check-runtime-path-policy.py" --case "$1"
