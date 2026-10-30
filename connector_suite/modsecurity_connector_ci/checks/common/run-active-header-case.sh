#!/bin/sh
# Resolve test infrastructure only from the explicitly selected Framework.
: "${TEST_ROOT:?TEST_ROOT is required explicitly}"
: "${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}"
: "${CONNECTOR_REVISION:?CONNECTOR_REVISION is required explicitly}"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
. "$TEST_ROOT/ci/lib/path-bootstrap.sh"
: "${TEST_ROOT:?TEST_ROOT is required explicitly}"
set -eu
case "${1:-}" in
    valid-length|duplicate-length|overflow-length) ;;
    *) echo 'active header case: unknown case' >&2; exit 2 ;;
esac
root=${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}
output_root=${RUNNER_TEMP:-${TMP_ROOT:-${BUILD_ROOT:-}}}
: "${output_root:?active header case requires an existing external RUNNER_TEMP, TMP_ROOT or BUILD_ROOT}"
"${PYTHON:-python3}" -P - "$root" "$output_root" <<'ADMITROOT'
from pathlib import Path
import sys
from modsecurity_connector_ci.lib.active_test_inventory import validate_output_root
validate_output_root(Path(sys.argv[1]), Path(sys.argv[2]))
ADMITROOT
umask 077
directory=$(mktemp -d "$output_root/active-header.XXXXXXXX")
trap 'rm -rf -- "$directory"' EXIT HUP INT TERM
"${CC:-cc}" -std=c17 -Wall -Wextra -Werror -I"$root/common/include" \
    "$TEST_ROOT/connector_suite/modsecurity_connector_tests/active_header_case.c" "$root/common/src/headers.c" -o "$directory/header-case"
"$directory/header-case" "$1"
