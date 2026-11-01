#!/bin/sh
: "${TEST_ROOT:?TEST_ROOT is required explicitly}"
set -eu

connector=${1:?connector is required}
stage=${2:?stage is required}

SCRIPT_DIR=$(CDPATH='' cd "$(dirname "$0")" && pwd)
CONNECTOR_ROOT=${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}
FRAMEWORK_ROOT=${TEST_ROOT:?TEST_ROOT is required explicitly}
VERIFIED_RUN_ROOT=${VERIFIED_RUN_ROOT:-${RUNNER_TEMP:-${TMPDIR:-/var/tmp}}/ModSecurity-conector-verified}
BUILD_ROOT=${BUILD_ROOT:-$VERIFIED_RUN_ROOT/build}
CACHE_ROOT=${CACHE_ROOT:-$VERIFIED_RUN_ROOT/cache-v2}
VERIFIED_COMPONENT_CACHE=${VERIFIED_COMPONENT_CACHE:-$CACHE_ROOT/shared}
CONNECTOR_COMPONENT_CACHE=${CONNECTOR_COMPONENT_CACHE:-$VERIFIED_COMPONENT_CACHE}
TMP_ROOT=${TMP_ROOT:-$BUILD_ROOT/tmp}
LOG_ROOT=${LOG_ROOT:-$BUILD_ROOT/logs}
RESULTS_DIR=${RESULTS_DIR:-$BUILD_ROOT/stages/$connector/$stage/results}
RUNTIME_REPORT_OUTPUT_ROOT=${RUNTIME_REPORT_OUTPUT_ROOT:-$BUILD_ROOT/runtime-component-reports}
PYTHON=${PYTHON:-python3}
NO_CRS_ARTIFACT_PROFILE=${NO_CRS_ARTIFACT_PROFILE:-generic}
FIVE_CONNECTOR_PROFILE=${FIVE_CONNECTOR_PROFILE:-}
FULL_LIFECYCLE_HOST_PROFILE=${FULL_LIFECYCLE_HOST_PROFILE:-}
FULL_LIFECYCLE_EXECUTED_TARGET=${FULL_LIFECYCLE_EXECUTED_TARGET:-}
NO_CRS_SELECTED_CASES_MISSING_MESSAGE='FAIL: capability-selected No-CRS runner cases are missing'
readonly NO_CRS_SELECTED_CASES_MISSING_MESSAGE

case "$connector" in
    apache|nginx|haproxy|envoy|traefik|lighttpd) ;;
    *) echo "usage: $0 apache|nginx|haproxy|envoy|traefik|lighttpd build|config_load|start_smoke|minimal_runtime_smoke|no_crs_baseline" >&2; exit 2 ;;
esac
case "$stage" in
    build|config_load|start_smoke|minimal_runtime_smoke|no_crs_baseline) ;;
    *) echo "usage: $0 apache|nginx|haproxy|envoy|traefik|lighttpd build|config_load|start_smoke|minimal_runtime_smoke|no_crs_baseline" >&2; exit 2 ;;
esac

# The minimal runtime stage retains its real configuration/start/shutdown.
# Separate request-free invocations are archived and do not earn active PASS.
case "$connector:$stage" in
    apache:config_load|nginx:config_load|haproxy:config_load|lighttpd:config_load|*:start_smoke)
        [ "${ON_DEMAND_TESTS:-0}" = 1 ] || {
            echo "FAIL: standalone lifecycle diagnostic is archived; explicit ON_DEMAND_TESTS=1 is required" >&2
            exit 2
        }
        ;;
    *:build|*:minimal_runtime_smoke|*:no_crs_baseline|envoy:config_load|traefik:config_load)
        # Both values were validated above; these stages are not archived.
        :
        ;;
    *)
        echo "FAIL: unsupported connector lifecycle stage: $connector:$stage" >&2
        exit 2
        ;;
esac

# Keep sockets short while artifacts retain their revision-bound identities.
case "$connector:$stage:$NO_CRS_ARTIFACT_PROFILE" in
    envoy:start_smoke:*|envoy:minimal_runtime_smoke:*|envoy:no_crs_baseline:generic|traefik:start_smoke:*|traefik:minimal_runtime_smoke:*|traefik:no_crs_baseline:generic)
        if [ -z "${MSCONNECTOR_PRIVATE_SOCKET_ROOT:-}" ]; then
            exec "$PYTHON" "$SCRIPT_DIR/with-private-sockets.py" \
                --socket-parent "${RUNNER_TEMP:-${TMPDIR:-}}" \
                --connector "$connector" --stage "$stage"
        fi
        ;;
    *) : ;;
esac

# A profile-selected stage has no fallback route.  The shared generic runner
# still serves the existing master connector targets when no profile is set,
# while the reusable five-connector workflow gets one closed source of truth
# before any host-specific dispatch can start.
if [ -n "$FIVE_CONNECTOR_PROFILE" ]; then
    FIVE_CONNECTOR_PROFILE_RESOLVER=$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/lifecycle/five-connector-no-crs-profile.py
    [ -f "$FIVE_CONNECTOR_PROFILE_RESOLVER" ] || {
        echo "FAIL: five-connector profile resolver is missing: $FIVE_CONNECTOR_PROFILE_RESOLVER" >&2
        exit 1
    }
    "$PYTHON" "$FIVE_CONNECTOR_PROFILE_RESOLVER" \
        --profile "$FIVE_CONNECTOR_PROFILE" \
        --verify-connector \
        --connector "$connector"
fi

expected_full_lifecycle_profile() {
    requested_connector=$1
    case "$requested_connector" in
        apache) printf '%s\n' native-httpd-module ;;
        nginx) printf '%s\n' native-nginx-http-module ;;
        haproxy) printf '%s\n' native-htx-filter ;;
        envoy) printf '%s\n' ext_proc ;;
        traefik) printf '%s\n' native-middleware ;;
        lighttpd) printf '%s\n' patched-native ;;
        *) return 1 ;;
    esac
}

expected_full_lifecycle_target() {
    requested_connector=$1
    case "$requested_connector" in
        apache) printf '%s\n' full-lifecycle-apache ;;
        nginx) printf '%s\n' full-lifecycle-nginx ;;
        haproxy) printf '%s\n' full-lifecycle-haproxy-htx ;;
        envoy) printf '%s\n' full-lifecycle-envoy-ext-proc ;;
        traefik) printf '%s\n' full-lifecycle-traefik-native ;;
        lighttpd) printf '%s\n' full-lifecycle-lighttpd-patched ;;
        *) return 1 ;;
    esac
}

# Full-lifecycle evidence may never fall through to a request-only or stock
# compatibility runner. Every connector below dispatches a profile-specific
# native host route; any case without matching raw host evidence remains
# non-promoted instead of borrowing compatibility evidence.
if [ "$stage" = no_crs_baseline ] && [ "$NO_CRS_ARTIFACT_PROFILE" = full_lifecycle ]; then
    expected_profile=$(expected_full_lifecycle_profile "$connector")
    expected_target=$(expected_full_lifecycle_target "$connector")
    if [ "$FULL_LIFECYCLE_HOST_PROFILE" != "$expected_profile" ] || \
       [ "$FULL_LIFECYCLE_EXECUTED_TARGET" != "$expected_target" ]; then
        echo "FAIL: full-lifecycle stage profile/target mismatch for $connector" >&2
        exit 1
    fi
fi

[ -f "$FRAMEWORK_ROOT/ci/lib/common.sh" ] || {
    echo "BLOCKED: framework common.sh is missing: $FRAMEWORK_ROOT/ci/lib/common.sh" >&2
    exit 77
}

case "$BUILD_ROOT" in
    /*) ;;
    *) echo "BLOCKED: BUILD_ROOT must be absolute: $BUILD_ROOT" >&2; exit 77 ;;
esac
case "$BUILD_ROOT" in
    "$CONNECTOR_ROOT"|"$CONNECTOR_ROOT"/*)
        echo "BLOCKED: BUILD_ROOT must be outside the checkout: $BUILD_ROOT" >&2
        exit 77
        ;;
    *) ;;
esac

export CONNECTOR_ROOT FRAMEWORK_ROOT VERIFIED_RUN_ROOT BUILD_ROOT CACHE_ROOT VERIFIED_COMPONENT_CACHE CONNECTOR_COMPONENT_CACHE TMP_ROOT LOG_ROOT RESULTS_DIR
export RUNTIME_REPORT_OUTPUT_ROOT RUNTIME_ROOT RUNTIME_BASE PYTHON RUNTIME_COMPONENT_ENV_SNAPSHOT
case "$connector" in
    apache|nginx|haproxy) RUNTIME_COMPONENT_TARGET=$connector ;;
    envoy|traefik|lighttpd) RUNTIME_COMPONENT_TARGET=shared ;;
    *)
        echo "FAIL: unsupported connector runtime-component target: $connector" >&2
        exit 2
        ;;
esac
export RUNTIME_COMPONENT_TARGET

run_framework_host() {
    framework_script=$1
    smoke_stage=$2
    shift 2
    host_script=$FRAMEWORK_ROOT/ci/runtime/$framework_script
    if [ "$connector:$stage" = nginx:no_crs_baseline ]; then
        host_script=$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-nginx-selected-host.sh
        # Reassert an explicit caller prefix after component provisioning. If
        # absent, retain the real prefix exported by the component snapshot.
        if [ "${NGINX_PREFIX+x}" = x ]; then
            set -- "NGINX_PREFIX=$NGINX_PREFIX" "$@"
        fi
    fi
    exec "$TEST_ROOT/connector_suite/modsecurity_connector_ci/provisioning/cache/with-runtime-components.sh" env \
        CONNECTOR_ROOT="$CONNECTOR_ROOT" \
        FRAMEWORK_ROOT="$FRAMEWORK_ROOT" \
        VERIFIED_RUN_ROOT="$VERIFIED_RUN_ROOT" \
        VERIFIED_COMPONENT_CACHE="$VERIFIED_COMPONENT_CACHE" \
        CACHE_ROOT="$CACHE_ROOT" \
        CONNECTOR_COMPONENT_CACHE="$CONNECTOR_COMPONENT_CACHE" \
        BUILD_ROOT="$BUILD_ROOT" \
        TMP_ROOT="$TMP_ROOT" \
        LOG_ROOT="$LOG_ROOT" \
        RESULTS_DIR="$RESULTS_DIR" \
        RUNTIME_REPORT_OUTPUT_ROOT="$RUNTIME_REPORT_OUTPUT_ROOT" \
        RUNTIME_COMPONENT_TARGET="$RUNTIME_COMPONENT_TARGET" \
        RUNTIME_COMPONENT_ENV_SNAPSHOT="${RUNTIME_COMPONENT_ENV_SNAPSHOT:-}" \
        NO_CRS_BASELINE=1 \
        NO_CRS_SELECTED_CASE_IDS="${NO_CRS_SELECTED_CASE_IDS:-}" \
        NO_CRS_SELECTED_CASES="${NO_CRS_SELECTED_CASES:-}" \
        NO_CRS_RUN_ID="${NO_CRS_RUN_ID:-}" \
        NGINX_DOCROOT_PROJECTION_PARENT="${NGINX_DOCROOT_PROJECTION_PARENT:-}" \
        FIVE_CONNECTOR_PARENT_COMMIT="${FIVE_CONNECTOR_PARENT_COMMIT:-}" \
        FIVE_CONNECTOR_FRAMEWORK_COMMIT="${FIVE_CONNECTOR_FRAMEWORK_COMMIT:-}" \
        NGX_NATIVE_INPUT_FAULT_LIBRARY="${NGX_NATIVE_INPUT_FAULT_LIBRARY:-}" \
        NGX_NATIVE_BEGIN_FAULT_LIBRARY="${NGX_NATIVE_BEGIN_FAULT_LIBRARY:-}" \
        NGX_NATIVE_WRITE_FAULT_LIBRARY="${NGX_NATIVE_WRITE_FAULT_LIBRARY:-}" \
        NGX_NATIVE_FINISH_FAULT_LIBRARY="${NGX_NATIVE_FINISH_FAULT_LIBRARY:-}" \
        NGX_NATIVE_ENGINE_BUDGET_FAULT_LIBRARY="${NGX_NATIVE_ENGINE_BUDGET_FAULT_LIBRARY:-}" \
        MODSECURITY_TEST_VARIANT=no-crs \
        MODSECURITY_MRTS_VARIANT=no-mrts \
        MODSECURITY_RULE_PREAMBLE_FILE="${NO_CRS_RULES_FILE:-}" \
        MSCONNECTOR_SMOKE_STAGE="$smoke_stage" \
        "$@" sh "$host_script"
}

run_remaining_connector() {
    target=$1
    exec env \
        CONNECTOR_ROOT="$CONNECTOR_ROOT" \
        FRAMEWORK_ROOT="$FRAMEWORK_ROOT" \
        VERIFIED_RUN_ROOT="$VERIFIED_RUN_ROOT" \
        VERIFIED_COMPONENT_CACHE="$VERIFIED_COMPONENT_CACHE" \
        CACHE_ROOT="$CACHE_ROOT" \
        CONNECTOR_COMPONENT_CACHE="$CONNECTOR_COMPONENT_CACHE" \
        BUILD_ROOT="$BUILD_ROOT" \
        TMP_ROOT="$TMP_ROOT" \
        LOG_ROOT="$LOG_ROOT" \
        RESULTS_DIR="$RESULTS_DIR" \
        RUNTIME_ROOT="${RUNTIME_ROOT:-$BUILD_ROOT/runtime}" \
        RUNTIME_BASE="${RUNTIME_BASE:-$BUILD_ROOT/runtime}" \
        RUNTIME_REPORT_OUTPUT_ROOT="$RUNTIME_REPORT_OUTPUT_ROOT" \
        RUNTIME_COMPONENT_TARGET="$RUNTIME_COMPONENT_TARGET" \
        RUNTIME_COMPONENT_ENV_SNAPSHOT="${RUNTIME_COMPONENT_ENV_SNAPSHOT:-}" \
        TRAEFIK_ENGINE_SOCKET_PARENT="${TRAEFIK_ENGINE_SOCKET_PARENT:-}" \
        sh "$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-remaining-connector-target.sh" "$connector" "$target"
}

run_full_lifecycle_haproxy_htx() {
    # The overlay build is connector-local while its pinned source and
    # libmodsecurity prerequisites remain in Cache-v2 shared components.
    # Its raw native HTX records are collected only from this selected host.
    case "$PYTHON" in
        /*) python_bin=$PYTHON ;;
        */*) python_bin=$CONNECTOR_ROOT/$PYTHON ;;
        *) python_bin=$PYTHON ;;
    esac
    # shellcheck disable=SC2016 # The explicitly invoked inner shell expands this script.
    exec "$TEST_ROOT/connector_suite/modsecurity_connector_ci/provisioning/cache/with-runtime-components.sh" env PYTHON="$python_bin" sh -eu -c '
        : "${HAPROXY_SOURCE_DIR:?HAProxy source was not provisioned}"
        : "${MODSECURITY_INCLUDE_DIR:?libmodsecurity headers were not provisioned}"
        : "${MODSECURITY_LIB_DIR:?libmodsecurity library was not provisioned}"
        make -C "$CONNECTOR_ROOT/connectors/haproxy" runtime-smoke-haproxy-htx \
            BUILD_ROOT="$BUILD_ROOT" REPO_ROOT="$CONNECTOR_ROOT" \
            HAPROXY_HTX_SOURCE_DIR="$HAPROXY_SOURCE_DIR" \
            HAPROXY_HTX_RUNTIME_ROOT="$RUNTIME_ROOT" \
            HAPROXY_HTX_BUILD_DIR="$RUNTIME_ROOT/overlay-build" \
            HAPROXY_HTX_BIN="$RUNTIME_ROOT/overlay-build/worktree/haproxy" \
            HAPROXY_HTX_EVENT_LOG_PATH="$RUNTIME_ROOT/events.jsonl" \
            PYTHON="$PYTHON"
    '
}

case "$connector:$stage" in
    apache:build)
        run_framework_host run-apache-smoke.sh build
        ;;
    nginx:build)
        run_framework_host run-nginx-smoke.sh build
        ;;
    haproxy:build)
        # shellcheck disable=SC2016 # The explicitly invoked inner shell expands this script.
        exec "$TEST_ROOT/connector_suite/modsecurity_connector_ci/provisioning/cache/with-runtime-components.sh" sh -eu -c '
            sh "$FRAMEWORK_ROOT/ci/provisioning/prepare-haproxy-runtime.sh"
            make -C "$CONNECTOR_ROOT/connectors/haproxy" build-modsecurity-binding build-spoa-runtime \
                BUILD_ROOT="$BUILD_ROOT" REPO_ROOT="$CONNECTOR_ROOT"
        '
        ;;
    apache:config_load|nginx:config_load|haproxy:config_load)
        run_framework_host "run-$connector-smoke.sh" config_load \
            RUN_ONE_CASE=1 TEST_CASE=allow_without_marker
        ;;
    apache:start_smoke|nginx:start_smoke|haproxy:start_smoke)
        run_framework_host "run-$connector-smoke.sh" start_smoke \
            RUN_ONE_CASE=1 TEST_CASE=allow_without_marker
        ;;
    apache:minimal_runtime_smoke|nginx:minimal_runtime_smoke|haproxy:minimal_runtime_smoke)
        run_framework_host "run-$connector-smoke.sh" minimal_runtime_smoke \
            RUN_ONE_CASE=0 SMOKE_CASES="allow_without_marker deny_header_marker_403"
        ;;
    haproxy:no_crs_baseline)
        if [ "$NO_CRS_ARTIFACT_PROFILE" = full_lifecycle ]; then
            # This helper execs the HTX observer.  Do not continue into the
            # SPOE/SPOP compatibility runner after a native full profile.
            run_full_lifecycle_haproxy_htx
        else
            [ -n "${NO_CRS_SELECTED_CASES:-}" ] || {
                echo "$NO_CRS_SELECTED_CASES_MISSING_MESSAGE" >&2
                exit 1
            }
            run_framework_host "run-$connector-smoke.sh" minimal_runtime_smoke \
                RUN_ONE_CASE=0 SMOKE_CASES="$NO_CRS_SELECTED_CASES"
        fi
        ;;
    nginx:no_crs_baseline)
        [ -n "${NO_CRS_SELECTED_CASES:-}" ] || {
            echo "$NO_CRS_SELECTED_CASES_MISSING_MESSAGE" >&2
            exit 1
        }
        run_framework_host "run-nginx-smoke.sh" minimal_runtime_smoke \
            RUN_ONE_CASE=0 SMOKE_CASES="$NO_CRS_SELECTED_CASES" \
            NGINX_PHASE4_LOG_SCOPE=location_if_missing
        ;;
    apache:no_crs_baseline)
        [ -n "${NO_CRS_SELECTED_CASES:-}" ] || {
            echo "$NO_CRS_SELECTED_CASES_MISSING_MESSAGE" >&2
            exit 1
        }
        run_framework_host "run-$connector-smoke.sh" minimal_runtime_smoke \
            RUN_ONE_CASE=0 SMOKE_CASES="$NO_CRS_SELECTED_CASES"
        ;;
    envoy:build)
        run_remaining_connector build-envoy-connector
        ;;
    traefik:build)
        run_remaining_connector build-traefik-connector
        ;;
    lighttpd:build)
        run_remaining_connector build-lighttpd-connector
        ;;
    envoy:config_load)
        run_remaining_connector check-envoy-config
        ;;
    traefik:config_load)
        run_remaining_connector check-traefik-config
        ;;
    lighttpd:config_load)
        run_remaining_connector check-lighttpd-config
        ;;
    envoy:start_smoke)
        run_remaining_connector start-smoke-envoy
        ;;
    traefik:start_smoke)
        run_remaining_connector start-smoke-traefik
        ;;
    lighttpd:start_smoke)
        run_remaining_connector start-smoke-lighttpd
        ;;
    envoy:minimal_runtime_smoke)
        run_remaining_connector runtime-smoke-envoy
        ;;
    traefik:minimal_runtime_smoke)
        run_remaining_connector runtime-smoke-traefik
        ;;
    lighttpd:minimal_runtime_smoke)
        run_remaining_connector runtime-smoke-lighttpd
        ;;
    envoy:no_crs_baseline)
        if [ "$NO_CRS_ARTIFACT_PROFILE" = full_lifecycle ]; then
            # run_remaining_connector execs: ext_proc must not fall through
            # into the ext_authz compatibility target.
            run_remaining_connector runtime-smoke-envoy-ext-proc
        else
            [ -n "${NO_CRS_SELECTED_CASES:-}" ] || {
                echo "$NO_CRS_SELECTED_CASES_MISSING_MESSAGE" >&2
                exit 1
            }
            run_remaining_connector no-crs-baseline-envoy
        fi
        ;;
    traefik:no_crs_baseline)
        if [ "$NO_CRS_ARTIFACT_PROFILE" = full_lifecycle ]; then
            # run_remaining_connector execs: this native local-plugin host
            # must not inherit forwardAuth compatibility evidence.
            run_remaining_connector runtime-smoke-traefik-native
        else
            [ -n "${NO_CRS_SELECTED_CASES:-}" ] || {
                echo "$NO_CRS_SELECTED_CASES_MISSING_MESSAGE" >&2
                exit 1
            }
            run_remaining_connector no-crs-baseline-traefik
        fi
        ;;
    lighttpd:no_crs_baseline)
        if [ "$NO_CRS_ARTIFACT_PROFILE" = full_lifecycle ]; then
            # run_remaining_connector execs: a patched native host may not
            # be replaced by the stock compatibility smoke.
            run_remaining_connector runtime-smoke-lighttpd-patched
        else
            [ -n "${NO_CRS_SELECTED_CASES:-}" ] || {
                echo "$NO_CRS_SELECTED_CASES_MISSING_MESSAGE" >&2
                exit 1
            }
            # These targets consume the plan before delegating to their narrow
            # real-host probes. They are deliberately distinct from the legacy
            # minimal-runtime targets: selected cases stay explicit in canonical
            # evidence instead of being implied by a 200/403 smoke.
            run_remaining_connector no-crs-baseline-lighttpd
        fi
        ;;
    *)
        echo "FAIL: unsupported connector stage dispatch: $connector:$stage" >&2
        exit 2
        ;;
esac
