#!/bin/sh
# Resolve test infrastructure only from the explicitly selected Framework.
: "${TEST_ROOT:?TEST_ROOT is required explicitly}"
: "${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}"
: "${CONNECTOR_REVISION:?CONNECTOR_REVISION is required explicitly}"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
. "$TEST_ROOT/ci/lib/path-bootstrap.sh"
: "${TEST_ROOT:?TEST_ROOT is required explicitly}"
# Run exactly one admitted HTTP request deadline through the actual service.
set -eu
[ "$#" -eq 1 ] || { echo 'active authorization timeout requires one case' >&2; exit 2; }
case "$1" in
    incomplete-headers|incomplete-body) ;;
    *) echo 'unknown active authorization timeout case' >&2; exit 2 ;;
esac
ROOT=${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}
OUTPUT_ROOT=${RUNNER_TEMP:-${TMP_ROOT:-}}
: "${OUTPUT_ROOT:?an explicit external RUNNER_TEMP or TMP_ROOT is required}"
"${PYTHON:-python3}" -P - "$ROOT" "$OUTPUT_ROOT" <<'ADMITROOT'
from pathlib import Path
import sys
from modsecurity_connector_ci.lib.active_test_inventory import validate_output_root
validate_output_root(Path(sys.argv[1]), Path(sys.argv[2]))
ADMITROOT
umask 077
case_root=$(mktemp -d "$OUTPUT_ROOT/active-authorization-timeout.XXXXXXXX")
trap 'rm -rf -- "$case_root"' EXIT HUP INT TERM
"${CC:-cc}" -std=c17 -Wall -Wextra -Werror -pthread \
    -I "$ROOT" -I "$ROOT/common/include" -I "$ROOT/common/runtime" \
    "$TEST_ROOT/connector_suite/modsecurity_connector_ci/checks/common/http_authorization_service_timeout_smoke.c" \
    "$ROOT/common/runtime/http_authorization_service.c" \
    "$ROOT"/common/src/*.c -o "$case_root/authorization-timeout"
"$case_root/authorization-timeout" --active-case "$1"
