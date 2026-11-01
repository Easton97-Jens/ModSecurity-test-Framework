#!/bin/sh
: "${TEST_ROOT:?TEST_ROOT is required explicitly}"
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CONNECTOR_ROOT="${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}"
FRAMEWORK_ROOT="${TEST_ROOT:?TEST_ROOT is required explicitly}"
: "${CONNECTOR_REVISION:?CONNECTOR_REVISION is required explicitly}"
: "${CONNECTOR_TEST_PROFILE:?CONNECTOR_TEST_PROFILE is required explicitly}"
PYTHONPATH="$TEST_ROOT:$TEST_ROOT/connector_suite"
PYTHONSAFEPATH=1
PYTHONNOUSERSITE=1
export TEST_ROOT PYTHONPATH PYTHONSAFEPATH PYTHONNOUSERSITE
VERIFIED_RUN_ROOT="${VERIFIED_RUN_ROOT:-${RUNNER_TEMP:-${TMPDIR:-/var/tmp}}/ModSecurity-conector-verified}"
VERIFIED_BUILD_ROOT="${VERIFIED_BUILD_ROOT:-$VERIFIED_RUN_ROOT/build}"
CACHE_ROOT="${CACHE_ROOT:-$VERIFIED_RUN_ROOT/cache-v2}"
VERIFIED_COMPONENT_CACHE="${VERIFIED_COMPONENT_CACHE:-$CACHE_ROOT/shared}"
BUILD_ROOT="${BUILD_ROOT:-$VERIFIED_BUILD_ROOT}"
RUNTIME_REPORT_OUTPUT_ROOT="${RUNTIME_REPORT_OUTPUT_ROOT:-$BUILD_ROOT/runtime-component-reports}"
RUNTIME_COMPONENT_TARGET="${RUNTIME_COMPONENT_TARGET:-all}"

if [ -z "${CONNECTOR_COMPONENT_CACHE:-}" ]; then
    CONNECTOR_COMPONENT_CACHE="$VERIFIED_COMPONENT_CACHE"
fi
resolved_component_cache=$CONNECTOR_COMPONENT_CACHE
requested_component_target=$RUNTIME_COMPONENT_TARGET

[ -f "$FRAMEWORK_ROOT/ci/lib/common.sh" ] || {
    echo "BLOCKED: framework common.sh is missing: $FRAMEWORK_ROOT/ci/lib/common.sh" >&2
    exit 77
}
REPO_ROOT=$CONNECTOR_ROOT
# Confirm any inherited tuple against Framework provenance before this wrapper
# reserves a snapshot or resolves cache state.  Framework remains the source.
/bin/sh "$CONNECTOR_ROOT/ci/tools/print-framework-apr-util-env.sh" "$FRAMEWORK_ROOT" "$CONNECTOR_ROOT" >/dev/null
# shellcheck disable=SC1090
. "$FRAMEWORK_ROOT/ci/lib/common.sh"
ci_require_apr_util_pinned_provenance || exit 77
assert_safe_runtime_path "$RUNTIME_REPORT_OUTPUT_ROOT" RUNTIME_REPORT_OUTPUT_ROOT || exit 77
assert_not_system_path_for_write "$RUNTIME_REPORT_OUTPUT_ROOT" RUNTIME_REPORT_OUTPUT_ROOT || exit 77

if [ -z "${RUNTIME_COMPONENT_ENV_SNAPSHOT:-}" ]; then
    RUNTIME_COMPONENT_ENV_SNAPSHOT=$(sh "$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/lifecycle/reserve-runtime-env-snapshot.sh" "$RUNTIME_REPORT_OUTPUT_ROOT") || exit $?
    snapshot_reserved_here=1
else
    snapshot_reserved_here=0
fi
runtime_env=$RUNTIME_COMPONENT_ENV_SNAPSHOT

export CONNECTOR_ROOT FRAMEWORK_ROOT BUILD_ROOT CACHE_ROOT VERIFIED_COMPONENT_CACHE CONNECTOR_COMPONENT_CACHE
export RUNTIME_REPORT_OUTPUT_ROOT RUNTIME_COMPONENT_TARGET RUNTIME_COMPONENT_ENV_SNAPSHOT

# A caller which deliberately skips preparation may still use a snapshot it
# inherited from its parent invocation.  If it has none, re-run the cheap
# cache resolver to materialize a target-bound local snapshot rather than
# falling back to the mutable shared runtime-env.sh file.
if [ "${SKIP_RUNTIME_COMPONENT_PREPARE:-0}" != "1" ] || [ ! -s "$runtime_env" ]; then
    set +e
    sh "$TEST_ROOT/connector_suite/modsecurity_connector_ci/provisioning/components/prepare-runtime-components.sh"
    prepare_rc=$?
    set -e
    if [ "$prepare_rc" -ne 0 ]; then
        if [ "$snapshot_reserved_here" -eq 1 ]; then
            rm -f "$runtime_env"
        fi
        exit "$prepare_rc"
    fi
fi
SKIP_RUNTIME_COMPONENT_PREPARE=1
export SKIP_RUNTIME_COMPONENT_PREPARE

case "$runtime_env" in
    "$RUNTIME_REPORT_OUTPUT_ROOT"/*) ;;
    *)
        echo "FAIL: runtime environment snapshot must remain under RUNTIME_REPORT_OUTPUT_ROOT: $runtime_env" >&2
        exit 1
        ;;
esac
[ -s "$runtime_env" ] || {
    echo "FAIL: runtime component preparation did not publish an invocation-local environment snapshot: $runtime_env" >&2
    exit 1
}
[ ! -L "$runtime_env" ] || {
    echo "FAIL: runtime environment snapshot must not be a symlink: $runtime_env" >&2
    exit 1
}
# shellcheck disable=SC1090
. "$runtime_env"
case "$requested_component_target:${RUNTIME_COMPONENT_ENV_SNAPSHOT_TARGET:-}" in
    all:all|shared:shared|shared:all|apache:apache|nginx:nginx|haproxy:haproxy) ;;
    *)
        echo "FAIL: runtime environment snapshot target mismatch: requested=$requested_component_target snapshot=${RUNTIME_COMPONENT_ENV_SNAPSHOT_TARGET:-unset}" >&2
        exit 1
        ;;
esac
if [ "${RUNTIME_COMPONENT_ENV_SNAPSHOT_CACHE:-}" != "$resolved_component_cache" ]; then
    echo "FAIL: runtime environment snapshot cache mismatch: expected=$resolved_component_cache snapshot=${RUNTIME_COMPONENT_ENV_SNAPSHOT_CACHE:-unset}" >&2
    exit 1
fi
# A generated environment may be older than the selected cache-v2 root.  It
# may supply toolchain paths, but never gets to redirect this invocation back
# to an unmarked legacy component cache.
CONNECTOR_COMPONENT_CACHE=$resolved_component_cache
VERIFIED_COMPONENT_CACHE=$resolved_component_cache
RUNTIME_COMPONENT_ENV_SNAPSHOT=$runtime_env
RUNTIME_COMPONENT_TARGET=$requested_component_target
export CACHE_ROOT VERIFIED_COMPONENT_CACHE CONNECTOR_COMPONENT_CACHE
export RUNTIME_COMPONENT_ENV_SNAPSHOT RUNTIME_COMPONENT_TARGET

exec "$@"
