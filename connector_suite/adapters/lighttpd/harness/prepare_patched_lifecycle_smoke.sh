#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd "$(dirname "$0")" && pwd)
LIGHTTPD_VERSION=$(sh "$SCRIPT_DIR/../build/read_version.sh")
BUILD_ROOT=${BUILD_ROOT:-${XDG_STATE_HOME:-${HOME:-/tmp}/.local/state}/ModSecurity-conector-build}
PATCHED_ROOT=${LIGHTTPD_PATCHED_ROOT:-$BUILD_ROOT/lighttpd-core-patched}
PATCHED_SOURCE_DIR=${LIGHTTPD_PATCHED_SOURCE_DIR:-$PATCHED_ROOT/lighttpd-$LIGHTTPD_VERSION}
SMOKE_DIR=${LIGHTTPD_PATCHED_SMOKE_DIR:-${LIGHTTPD_SMOKE_DIR:-$PATCHED_ROOT/smoke}}

blocked() {
    reason=$1
    printf 'lighttpd_patched_lifecycle_config: BLOCKED: %s\n' "$reason" >&2
    exit 77
}

case "$PATCHED_ROOT" in
    /*) ;;
    *) blocked "LIGHTTPD_PATCHED_ROOT must be absolute: $PATCHED_ROOT" ;;
esac
case "$SMOKE_DIR" in
    /*) ;;
    *) blocked "LIGHTTPD_PATCHED_SMOKE_DIR must be absolute: $SMOKE_DIR" ;;
esac
[ -f "$PATCHED_SOURCE_DIR/src/plugin.h" ] || blocked "patched source is missing: $PATCHED_SOURCE_DIR"
grep -Fq LIGHTTPD_MSCONNECTOR_STREAM_HOOK_ABI_VERSION "$PATCHED_SOURCE_DIR/src/plugin.h" || \
    blocked "patched source does not expose the required hook ABI"

# The pinned patch exposes HTTP/1.x entity bytes before transfer framing.  This
# preparer remains deliberately narrow: only identity content is eligible and
# caller-side evidence, not configuration, decides whether P4 is promoted.
case "${LIGHTTPD_PATCHED_REQUEST_BODY_MODE:-none}" in
    none|streaming) ;;
    *) blocked "LIGHTTPD_PATCHED_REQUEST_BODY_MODE must be none or streaming" ;;
esac
case "${LIGHTTPD_PATCHED_RESPONSE_BODY_MODE:-none}" in
    none|streaming) ;;
    *) blocked "LIGHTTPD_PATCHED_RESPONSE_BODY_MODE must be none or streaming" ;;
esac
case "${LIGHTTPD_PATCHED_ENTITY_ENCODING:-identity}" in
    identity) ;;
    *) blocked "patched lifecycle smoke supports only identity entity-body input; gzip/br require a separately evidenced filter order" ;;
esac

LIGHTTPD_SMOKE_DIR="$SMOKE_DIR" \
LIGHTTPD_REQUEST_BODY_MODE="${LIGHTTPD_PATCHED_REQUEST_BODY_MODE:-none}" \
LIGHTTPD_RESPONSE_BODY_MODE="${LIGHTTPD_PATCHED_RESPONSE_BODY_MODE:-none}" \
LIGHTTPD_ENTITY_BODY_HOOK=1 \
LIGHTTPD_RESPONSE_HEADER_MARKER="${LIGHTTPD_PATCHED_RESPONSE_HEADER_MARKER:-}" \
exec sh "$SCRIPT_DIR/prepare_native_smoke.sh"
