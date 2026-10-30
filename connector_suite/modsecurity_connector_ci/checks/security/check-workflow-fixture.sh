#!/bin/sh
# Resolve test infrastructure only from the explicitly selected Framework.
: "${TEST_ROOT:?TEST_ROOT is required explicitly}"
: "${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}"
: "${CONNECTOR_REVISION:?CONNECTOR_REVISION is required explicitly}"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
. "$TEST_ROOT/ci/lib/path-bootstrap.sh"
# Four separately inventoried scanner contract scenarios; never discover fixtures.
set -eu
SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
REPO_ROOT=${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}
fixture=${1:?an inventoried fixture identifier is required}
case "$fixture" in
    insecure) path=ci/fixtures/zizmor/insecure.yml; expected=reject ;;
    safe) path=ci/fixtures/zizmor/safe.yml; expected=accept ;;
    permission-unsafe) path=ci/fixtures/workflow-permission-contract/unsafe.yml; expected=reject ;;
    permission-safe) path=ci/fixtures/workflow-permission-contract/safe.yml; expected=accept ;;
    *) echo "FAIL: unknown workflow fixture" >&2; exit 2 ;;
esac
: "${RUNNER_TEMP:?RUNNER_TEMP must select the existing checksum-verified scanner}"
scanner="$RUNNER_TEMP/security-tools/zizmor"
[ -f "$scanner" ] && [ ! -L "$scanner" ] && [ -x "$scanner" ] || {
    echo "FAIL: checksum-verified zizmor executable is unavailable" >&2
    exit 2
}
scanner_status=0
"$scanner" --offline --strict-collection "$TEST_ROOT/connector_suite/modsecurity_connector_ci/${path#ci/}" || scanner_status=$?
case "$scanner_status" in
    0) observed=accept ;;
    11|12|13|14) observed=reject ;;
    *) echo "FAIL: scanner failed before a valid fixture verdict (exit $scanner_status)" >&2; exit "$scanner_status" ;;
esac
[ "$observed" = "$expected" ] || {
    echo "FAIL: scanner fixture result did not match its requirement" >&2
    exit 1
}
printf 'workflow fixture %s: %s
' "$fixture" "$observed"
