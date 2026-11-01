#!/bin/sh
# Closed configuration/native invocations supplement the existing HTTP cases.
set -eu

SCRIPT_DIR=$(CDPATH='' cd "$(dirname "$0")" && pwd)
: "${FRAMEWORK_ROOT:?FRAMEWORK_ROOT is required}"
host_rc=0
sh "$FRAMEWORK_ROOT/ci/runtime/run-nginx-smoke.sh" || host_rc=$?
config_rc=0
"${PYTHON:-python3}" "$SCRIPT_DIR/run-selected-nginx-configtests.py" || config_rc=$?
native_rc=0
"${PYTHON:-python3}" "$SCRIPT_DIR/run-selected-nginx-native-operations.py" || native_rc=$?
if [ "$host_rc" -ne 0 ]; then
    exit "$host_rc"
fi
if [ "$config_rc" -ne 0 ]; then
    exit "$config_rc"
fi
exit "$native_rc"
