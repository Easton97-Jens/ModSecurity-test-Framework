#!/bin/sh
set -eu

[ "$#" -eq 1 ] || { echo "FAIL: one legacy connector is required" >&2; exit 2; }
case "$1" in
    envoy|traefik|lighttpd) connector=$1 ;;
    *) echo "FAIL: unsupported legacy connector" >&2; exit 2 ;;
esac

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
CONNECTOR_ROOT=${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}
FRAMEWORK_ROOT=${TEST_ROOT:?TEST_ROOT is required explicitly}
export CONNECTOR_ROOT FRAMEWORK_ROOT
# Select the central prepared paths, never an inherited executable override.
unset ENVOY_BIN TRAEFIK_BIN LIGHTTPD_BIN
unset ENVOY_BIN_WAS_SET TRAEFIK_BIN_WAS_SET LIGHTTPD_BIN_WAS_SET
# shellcheck source=modules/ModSecurity-test-Framework/ci/lib/common.sh
. "$FRAMEWORK_ROOT/ci/lib/common.sh"

case "$connector" in
    envoy)
        envoy_build_paths >/dev/null
        expected_binary=$ENVOY_COMPONENT_ROOT/bin/envoy
        ENVOY_BIN=$(require_or_provision_envoy)
        selected_binary=$ENVOY_BIN
        SERVICE_BIN=$BUILD_ROOT/envoy-connector/msconnector_envoy_ext_authz
        RESPONSE_OBSERVER_BIN=$BUILD_ROOT/envoy-connector/msconnector_envoy_response_observer
        export ENVOY_BIN SERVICE_BIN RESPONSE_OBSERVER_BIN
        ;;
    traefik)
        traefik_build_paths >/dev/null
        expected_binary=$TRAEFIK_BUILD_ROOT/bin/traefik
        TRAEFIK_BIN=$(require_or_provision_traefik)
        selected_binary=$TRAEFIK_BIN
        export TRAEFIK_BIN
        ;;
    lighttpd)
        lighttpd_build_paths >/dev/null
        expected_binary=$LIGHTTPD_CONNECTOR_BUILD_ROOT/bin/lighttpd
        LIGHTTPD_BIN=$(require_or_provision_lighttpd)
        selected_binary=$LIGHTTPD_BIN
        export LIGHTTPD_BIN
        ;;
    *) echo "FAIL: unsupported legacy connector" >&2; exit 2 ;;
esac

set -- "$selected_binary" "$expected_binary"
if [ "$connector" = envoy ]; then
    set -- "$@" "$SERVICE_BIN" "$BUILD_ROOT/envoy-connector/msconnector_envoy_ext_authz" \
        "$RESPONSE_OBSERVER_BIN" "$BUILD_ROOT/envoy-connector/msconnector_envoy_response_observer"
fi
"${PYTHON:-python3}" - "$@" <<'PY'
import os
from pathlib import Path
import stat
import sys

def require_prepared_executable(candidate, expected):
    if not candidate.is_absolute() or candidate != expected or candidate.resolve(strict=True) != candidate:
        raise SystemExit("FAIL: legacy binary must use its exact symlink-free prepared path")
    details = candidate.lstat()
    if (not stat.S_ISREG(details.st_mode) or details.st_uid != os.geteuid()
            or details.st_nlink != 1 or details.st_mode & 0o022 or not os.access(candidate, os.X_OK)):
        raise SystemExit("FAIL: legacy binary must be an owned, singly linked protected executable")


for index in range(1, len(sys.argv), 2):
    require_prepared_executable(Path(sys.argv[index]), Path(sys.argv[index + 1]))
PY

case "$connector" in
    envoy) exec sh "$FRAMEWORK_ROOT/ci/runtime/run-envoy-smoke.sh" ;;
    traefik) exec sh "$FRAMEWORK_ROOT/ci/runtime/run-traefik-smoke.sh" ;;
    lighttpd) exec sh "$FRAMEWORK_ROOT/ci/runtime/run-lighttpd-smoke.sh" ;;
    *) echo "FAIL: unsupported legacy connector" >&2; exit 2 ;;
esac
