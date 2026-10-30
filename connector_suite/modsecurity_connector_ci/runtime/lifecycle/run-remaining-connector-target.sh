#!/bin/sh
: "${TEST_ROOT:?TEST_ROOT is required explicitly}"
set -eu

connector=${1:?connector is required}
target=${2:?target is required}

case "$connector:$target" in
    *:start-smoke|*:start-smoke-*|lighttpd:check-lighttpd-config)
        [ "${ON_DEMAND_TESTS:-0}" = 1 ] || {
            echo "FAIL: standalone lifecycle diagnostic is archived; explicit ON_DEMAND_TESTS=1 is required" >&2
            exit 2
        }
        ;;
    envoy:*|traefik:*|lighttpd:*)
        # Component-native Makefiles validate other non-diagnostic targets.
        :
        ;;
    *)
        echo "FAIL: unsupported remaining connector: $connector" >&2
        exit 2
        ;;
esac

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
CONNECTOR_ROOT=${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}
FRAMEWORK_ROOT=${TEST_ROOT:?TEST_ROOT is required explicitly}
VERIFIED_RUN_ROOT=${VERIFIED_RUN_ROOT:-${RUNNER_TEMP:-${TMPDIR:-/var/tmp}}/ModSecurity-conector-verified}
BUILD_ROOT=${BUILD_ROOT:-$VERIFIED_RUN_ROOT/build}
CACHE_ROOT=${CACHE_ROOT:-$VERIFIED_RUN_ROOT/cache-v2}
CONNECTOR_COMPONENT_CACHE=${CONNECTOR_COMPONENT_CACHE:-${VERIFIED_COMPONENT_CACHE:-$CACHE_ROOT/shared}}
TMP_ROOT=${TMP_ROOT:-$BUILD_ROOT/tmp}
RUNTIME_REPORT_OUTPUT_ROOT=${RUNTIME_REPORT_OUTPUT_ROOT:-$BUILD_ROOT/runtime-component-reports}
RUNTIME_COMPONENT_TARGET=${RUNTIME_COMPONENT_TARGET:-shared}
resolved_component_cache=$CONNECTOR_COMPONENT_CACHE
requested_component_target=$RUNTIME_COMPONENT_TARGET

export CONNECTOR_ROOT FRAMEWORK_ROOT VERIFIED_RUN_ROOT BUILD_ROOT CACHE_ROOT CONNECTOR_COMPONENT_CACHE TMP_ROOT
export RUNTIME_REPORT_OUTPUT_ROOT RUNTIME_COMPONENT_TARGET

case "${PYTHON:-python3}" in
    /*) ;;
    */*) PYTHON="$CONNECTOR_ROOT/${PYTHON}" ;;
    *) PYTHON=${PYTHON:-python3} ;;
esac
export PYTHON

[ -f "$FRAMEWORK_ROOT/ci/lib/common.sh" ] || {
    echo "FAIL: framework common.sh is missing" >&2
    exit 1
}

# shellcheck disable=SC1090
. "$FRAMEWORK_ROOT/ci/lib/common.sh"
assert_safe_runtime_path "$RUNTIME_REPORT_OUTPUT_ROOT" RUNTIME_REPORT_OUTPUT_ROOT || exit 77
assert_not_system_path_for_write "$RUNTIME_REPORT_OUTPUT_ROOT" RUNTIME_REPORT_OUTPUT_ROOT || exit 77

if [ -z "${RUNTIME_COMPONENT_ENV_SNAPSHOT:-}" ]; then
    RUNTIME_COMPONENT_ENV_SNAPSHOT=$(sh "$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/lifecycle/reserve-runtime-env-snapshot.sh" "$RUNTIME_REPORT_OUTPUT_ROOT") || exit $?
    snapshot_reserved_here=1
else
    snapshot_reserved_here=0
fi
runtime_env=$RUNTIME_COMPONENT_ENV_SNAPSHOT
case "$runtime_env" in
    "$RUNTIME_REPORT_OUTPUT_ROOT"/*) ;;
    *)
        echo "FAIL: runtime environment snapshot must remain under RUNTIME_REPORT_OUTPUT_ROOT: $runtime_env" >&2
        exit 1
        ;;
esac
export RUNTIME_COMPONENT_ENV_SNAPSHOT

ensure_runtime_env_snapshot() {
    if [ -s "$runtime_env" ]; then
        return 0
    fi
    # A SKIP_RUNTIME_COMPONENT_PREPARE caller may reuse an inherited snapshot,
    # but it may not fall back to the mutable shared runtime-env.sh.  Materialize
    # a target-bound local snapshot when none was supplied.
    set +e
    sh "$TEST_ROOT/connector_suite/modsecurity_connector_ci/provisioning/components/prepare-runtime-components.sh"
    prepare_rc=$?
    set -e
    if [ "$prepare_rc" -ne 0 ]; then
        if [ "$snapshot_reserved_here" -eq 1 ]; then
            rm -f "$runtime_env"
        fi
        return "$prepare_rc"
    fi
    [ -s "$runtime_env" ] || {
        echo "FAIL: runtime component preparation did not publish an invocation-local environment snapshot: $runtime_env" >&2
        return 1
    }
}

load_runtime_env() {
    [ -s "$runtime_env" ] || {
        echo "FAIL: runtime environment snapshot is missing: $runtime_env" >&2
        return 1
    }
    [ ! -L "$runtime_env" ] || {
        echo "FAIL: runtime environment snapshot must not be a symlink: $runtime_env" >&2
        return 1
    }
    # shellcheck disable=SC1090
    . "$runtime_env"
    case "$requested_component_target:${RUNTIME_COMPONENT_ENV_SNAPSHOT_TARGET:-}" in
        shared:shared|shared:all|all:all|apache:apache|nginx:nginx|haproxy:haproxy) ;;
        *)
            echo "FAIL: runtime environment snapshot target mismatch: requested=$requested_component_target snapshot=${RUNTIME_COMPONENT_ENV_SNAPSHOT_TARGET:-unset}" >&2
            return 1
            ;;
    esac
    if [ "${RUNTIME_COMPONENT_ENV_SNAPSHOT_CACHE:-}" != "$resolved_component_cache" ]; then
        echo "FAIL: runtime environment snapshot cache mismatch: expected=$resolved_component_cache snapshot=${RUNTIME_COMPONENT_ENV_SNAPSHOT_CACHE:-unset}" >&2
        return 1
    fi
    # A generated environment may carry useful toolchain paths, but it never
    # gets to redirect this invocation away from its Cache-v2 shared root.
    CONNECTOR_COMPONENT_CACHE=$resolved_component_cache
    VERIFIED_COMPONENT_CACHE=$resolved_component_cache
    RUNTIME_COMPONENT_ENV_SNAPSHOT=$runtime_env
    RUNTIME_COMPONENT_TARGET=$requested_component_target
    export CACHE_ROOT VERIFIED_COMPONENT_CACHE CONNECTOR_COMPONENT_CACHE
    export RUNTIME_COMPONENT_ENV_SNAPSHOT RUNTIME_COMPONENT_TARGET
}

run_make_target() {
    mkdir -p "$TMP_ROOT"
    make_log=$(mktemp "$TMP_ROOT/remaining-connector-make.XXXXXX")
    set +e
    make "$@" >"$make_log" 2>&1
    make_rc=$?
    set -e
    cat "$make_log"
    if [ "$make_rc" -eq 2 ] \
        && grep -Eq '(^|:)[[:space:]]*\*\*\*.*Error 77' "$make_log" \
        && grep -q 'BLOCKED:' "$make_log" \
        && ! grep -q '^FAIL:' "$make_log"; then
        rm -f "$make_log"
        return 77
    fi
    rm -f "$make_log"
    return "$make_rc"
}

require_modsecurity_build_environment() {
    ensure_runtime_env_snapshot || return $?
    load_runtime_env
    if [ -f "${MODSECURITY_INCLUDE_DIR:-}/modsecurity/modsecurity.h" ] \
        && [ -d "${MODSECURITY_LIB_DIR:-}" ]; then
        return 0
    fi
    if [ "${SKIP_RUNTIME_COMPONENT_PREPARE:-0}" = "1" ]; then
        echo "FAIL: libmodsecurity build environment is missing and preparation is disabled" >&2
        return 1
    fi
    PYTHON=${PYTHON:-python3} FRAMEWORK_ROOT="$FRAMEWORK_ROOT" CONNECTOR_ROOT="$CONNECTOR_ROOT" \
        sh "$TEST_ROOT/connector_suite/modsecurity_connector_ci/provisioning/components/prepare-runtime-components.sh"
    ensure_runtime_env_snapshot || return $?
    load_runtime_env
    if [ ! -f "${MODSECURITY_INCLUDE_DIR:-}/modsecurity/modsecurity.h" ] \
        || [ ! -d "${MODSECURITY_LIB_DIR:-}" ]; then
        echo "FAIL: runtime preparation did not provide libmodsecurity headers and libraries" >&2
        return 1
    fi
}

require_host=0
case "$target" in
    start-smoke-*|runtime-smoke-*|no-crs-baseline-*) require_host=1 ;;
    *) ;;
esac

require_modsecurity_build_environment

case "$connector" in
    envoy)
        envoy_build_paths >/dev/null
        if [ "$require_host" = "1" ]; then
            ENVOY_BIN=$(require_or_provision_envoy)
            export ENVOY_BIN
        fi
        ext_proc_runtime_root=${PARENT_HOST_RUNTIME_ROOT:-${ENVOY_EXT_PROC_RUNTIME_ROOT:-${ENVOY_RESULT_ROOT:-${RUNTIME_ROOT:-$BUILD_ROOT/envoy-ext-proc/runtime-smoke}}}}
        ext_proc_event_log=${ENVOY_EXT_PROC_EVENT_LOG_PATH:-$ext_proc_runtime_root/events.jsonl}
        run_make_target -C "$CONNECTOR_ROOT/connectors/envoy" "$target" \
            BUILD_ROOT="$BUILD_ROOT" ENVOY_BIN="$ENVOY_BIN" \
            EXT_PROC_RUNTIME_ROOT="$ext_proc_runtime_root" \
            EXT_PROC_RUNTIME_EVENT_LOG_PATH="$ext_proc_event_log" \
            MODSECURITY_INCLUDE_DIR="$MODSECURITY_INCLUDE_DIR" \
            MODSECURITY_LIB_DIR="$MODSECURITY_LIB_DIR" \
            MODSECURITY_PREFIX="${MODSECURITY_PREFIX:-}"
        ;;
    traefik)
        traefik_build_paths >/dev/null
        if [ "$require_host" = "1" ]; then
            TRAEFIK_BIN=$(require_or_provision_traefik)
            export TRAEFIK_BIN
        fi
        traefik_native_runtime_root=${PARENT_HOST_RUNTIME_ROOT:-${TRAEFIK_NATIVE_RUNTIME_ROOT:-${TRAEFIK_RESULT_ROOT:-${RUNTIME_ROOT:-$BUILD_ROOT/traefik-native-middleware/runtime-smoke}}}}
        TRAEFIK_NATIVE_RUNTIME_ROOT=$traefik_native_runtime_root
        MODSECURITY_PREFIX=${MODSECURITY_PREFIX:-}
        export TRAEFIK_BIN TRAEFIK_NATIVE_RUNTIME_ROOT
        export MODSECURITY_INCLUDE_DIR MODSECURITY_LIB_DIR MODSECURITY_PREFIX
        run_make_target -C "$CONNECTOR_ROOT/connectors/traefik" "$target"
        ;;
    lighttpd)
        lighttpd_build_paths >/dev/null
        LIGHTTPD_BIN=$(require_or_provision_lighttpd)
        export LIGHTTPD_BIN LIGHTTPD_SOURCE_DIR LIGHTTPD_BUILD_ROOT
        export LIGHTTPD_INCLUDE_DIR LIGHTTPD_CONNECTOR_BUILD_ROOT LIGHTTPD_MODULE_DIR
        lighttpd_patched_root=${LIGHTTPD_PATCHED_ROOT:-$BUILD_ROOT/lighttpd-core-patched}
        lighttpd_patched_smoke_dir=${PARENT_HOST_RUNTIME_ROOT:-${LIGHTTPD_PATCHED_SMOKE_DIR:-${RUNTIME_ROOT:-$BUILD_ROOT/lighttpd-patched-smoke}}}
        run_make_target -C "$CONNECTOR_ROOT/connectors/lighttpd" "$target" \
            BUILD_ROOT="$BUILD_ROOT" LIGHTTPD_BIN="$LIGHTTPD_BIN" \
            LIGHTTPD_SOURCE_DIR="$LIGHTTPD_SOURCE_DIR" \
            LIGHTTPD_BUILD_ROOT="$LIGHTTPD_BUILD_ROOT" \
            LIGHTTPD_INCLUDE_DIR="$LIGHTTPD_INCLUDE_DIR" \
            LIGHTTPD_CONNECTOR_BUILD_ROOT="$LIGHTTPD_CONNECTOR_BUILD_ROOT" \
            LIGHTTPD_MODULE_DIR="$LIGHTTPD_MODULE_DIR" \
            LIGHTTPD_PATCHED_ROOT="$lighttpd_patched_root" \
            LIGHTTPD_PATCHED_SMOKE_DIR="$lighttpd_patched_smoke_dir" \
            MODSECURITY_INCLUDE_DIR="$MODSECURITY_INCLUDE_DIR" \
            MODSECURITY_LIB_DIR="$MODSECURITY_LIB_DIR" \
            MODSECURITY_PREFIX="${MODSECURITY_PREFIX:-}"
        ;;
    *)
        echo "usage: $0 envoy|traefik|lighttpd target" >&2
        exit 2
        ;;
esac
