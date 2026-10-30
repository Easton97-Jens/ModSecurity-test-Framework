#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd "$(dirname "$0")" && pwd)
BUILD_ROOT=${BUILD_ROOT:-${XDG_STATE_HOME:-${HOME:-/tmp}/.local/state}/ModSecurity-conector-build}
PATCHED_ROOT=${LIGHTTPD_PATCHED_ROOT:-$BUILD_ROOT/lighttpd-core-patched}
CORE_BIN=$PATCHED_ROOT/stage/bin/lighttpd
MODULE_PATH=$PATCHED_ROOT/stage/modules/mod_msconnector.so
HOST_MANIFEST=$PATCHED_ROOT/patched-host-build-info.txt
SMOKE_DIR=${LIGHTTPD_PATCHED_SMOKE_DIR:-$PATCHED_ROOT/smoke}
NO_CRS_NAMESPACE_RUNNER=$SCRIPT_DIR/run_no_crs_fixture_trusted_namespace.py

# The canonical full-lifecycle route is intentionally separate from the
# compatibility Phase-1 smoke below.  It runs P1/P2/P3 through the real
# patched host and emits selected-case metadata; P4 remains unavailable
# because the current output callback exposes HTTP/1 wire bytes.
if [ "${NO_CRS_ARTIFACT_PROFILE:-}" = full_lifecycle ]; then
    case "${MSCONNECTOR_CRS_RUNTIME:-0}" in
        0)
            [ -f "$NO_CRS_NAMESPACE_RUNNER" ] || {
                printf 'lighttpd_patched_lifecycle_smoke: BLOCKED: No-CRS namespace launcher is missing\n' >&2
                exit 77
            }
            exec /usr/bin/python3 "$NO_CRS_NAMESPACE_RUNNER" \
                --timeout-seconds "${LIGHTTPD_NO_CRS_NAMESPACE_TIMEOUT_SECONDS:-300}" \
                -- /bin/sh "$SCRIPT_DIR/run_patched_full_lifecycle.sh"
            ;;
        1)
            exec sh "$SCRIPT_DIR/run_patched_full_lifecycle.sh"
            ;;
        *)
            printf 'lighttpd_patched_lifecycle_smoke: BLOCKED: MSCONNECTOR_CRS_RUNTIME must be 0 or 1\n' >&2
            exit 77
            ;;
    esac
fi

blocked() {
    reason=$1
    printf 'lighttpd_patched_lifecycle_smoke: BLOCKED: %s\n' "$reason" >&2
    exit 77
}

manifest_value() {
    key=$1
    sed -n "s/^$key=//p" "$HOST_MANIFEST" | sed -n '1p'
}

# This standalone patched-host target is not the generic No-CRS runner and
# must not inherit a selected-case consumer or turn its Phase-1 smoke into
# canonical lifecycle evidence.
unset MSCONNECTOR_NO_CRS_BASELINE

BUILD_ROOT="$BUILD_ROOT" \
LIGHTTPD_PATCHED_ROOT="$PATCHED_ROOT" \
LIGHTTPD_PATCHED_SMOKE_DIR="$SMOKE_DIR" \
sh "$SCRIPT_DIR/check_patched_lifecycle_host.sh"

MODSECURITY_LIB_DIR=$(manifest_value modsecurity_lib_dir)
[ -n "$MODSECURITY_LIB_DIR" ] || blocked "patched host manifest has no libmodsecurity directory"
LD_LIBRARY_PATH="$MODSECURITY_LIB_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export LD_LIBRARY_PATH
BUILD_ROOT="$BUILD_ROOT" \
LIGHTTPD_PATCHED_ROOT="$PATCHED_ROOT" \
LIGHTTPD_PATCHED_SMOKE_DIR="$SMOKE_DIR" \
LIGHTTPD_BIN="$CORE_BIN" \
LIGHTTPD_CONNECTOR_MODULE="$MODULE_PATH" \
LIGHTTPD_MODULE_DIR=$(dirname "$MODULE_PATH") \
LIGHTTPD_SMOKE_DIR="$SMOKE_DIR" \
LIGHTTPD_SMOKE_PREPARER="$SCRIPT_DIR/prepare_patched_lifecycle_smoke.sh" \
sh "$SCRIPT_DIR/runtime_lighttpd_smoke.sh"

printf 'lighttpd_patched_lifecycle_smoke: PASS patched_core_and_module=loaded phase1_runtime=pass response_body_mode=none phase4=not-executed\n'
