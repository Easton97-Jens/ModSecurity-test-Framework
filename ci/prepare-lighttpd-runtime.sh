#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
FRAMEWORK_ROOT="${FRAMEWORK_ROOT:-$(CDPATH= cd "$SCRIPT_DIR/.." && pwd)}"
if [ -n "${CONNECTOR_ROOT:-}" ]; then
    CONNECTOR_ROOT=$(CDPATH= cd "$CONNECTOR_ROOT" && pwd)
elif [ -d "$FRAMEWORK_ROOT/../../connectors" ]; then
    CONNECTOR_ROOT=$(CDPATH= cd "$FRAMEWORK_ROOT/../.." && pwd)
else
    CONNECTOR_ROOT=$(pwd)
fi

. "$SCRIPT_DIR/common.sh"
. "$SCRIPT_DIR/runtime-component-common.sh"

ci_validate_https_runtime_url_config || exit 77

sha_status=$(runtime_component_sha_status "$LIGHTTPD_SHA256")
LIGHTTPD_SOURCE_STAGE_DIR="${LIGHTTPD_SOURCE_STAGE_DIR:-$LIGHTTPD_COMPONENT_ROOT/src/lighttpd-$LIGHTTPD_VERSION}"
blocked_extra="Lighttpd download is a source tarball, not a runtime binary.
Source staged: $([ -d "$LIGHTTPD_SOURCE_STAGE_DIR" ] && printf true || printf false)
Runtime binary available: false
Stage or build a prepared lighttpd binary at:
  $LIGHTTPD_COMPONENT_ROOT/bin/lighttpd
or set LIGHTTPD_BIN to an executable local/common.sh-managed path."

assert_safe_runtime_path "$LIGHTTPD_COMPONENT_ROOT" LIGHTTPD_COMPONENT_ROOT || exit 77
assert_safe_runtime_path "$LIGHTTPD_RUNTIME_ROOT" LIGHTTPD_RUNTIME_ROOT || exit 77
assert_safe_runtime_path "$LIGHTTPD_CONFIG_ROOT" LIGHTTPD_CONFIG_ROOT || exit 77
assert_safe_runtime_path "$LIGHTTPD_LOG_ROOT" LIGHTTPD_LOG_ROOT || exit 77
assert_safe_runtime_path "$LIGHTTPD_RESULT_ROOT" LIGHTTPD_RESULT_ROOT || exit 77
ci_require_absolute_path "$LIGHTTPD_BIN" LIGHTTPD_BIN || exit 77
if ci_path_is_system_path "$LIGHTTPD_BIN"; then
    ci_blocked "LIGHTTPD_BIN must not point at a global system path: $LIGHTTPD_BIN"
    exit 77
fi

if [ -f "$LIGHTTPD_BIN" ] && [ -x "$LIGHTTPD_BIN" ]; then
    printf 'lighttpd runtime binary: %s\n' "$LIGHTTPD_BIN"
    printf 'lighttpd_version=%s\n' "$LIGHTTPD_VERSION"
    printf 'lighttpd_source_url=%s\n' "$LIGHTTPD_SOURCE_URL"
    printf 'lighttpd_download_url=%s\n' "$LIGHTTPD_DOWNLOAD_URL"
    printf 'lighttpd_sha256_status=%s\n' "$sha_status"
    printf 'lighttpd_source_staged=%s\n' "$([ -d "$LIGHTTPD_SOURCE_STAGE_DIR" ] && printf true || printf false)"
    exit 0
fi

if ! require_runtime_download_opt_in; then
    write_prepare_blocked_message \
        lighttpd \
        "$LIGHTTPD_VERSION" \
        "$LIGHTTPD_SOURCE_URL" \
        "" \
        "$LIGHTTPD_LATEST_URL" \
        "$LIGHTTPD_DOWNLOAD_URL" \
        "$sha_status" \
        "$LIGHTTPD_SHA256_URL" \
        "$LIGHTTPD_BIN" \
        "$blocked_extra"
    exit 77
fi

require_pinned_runtime_source lighttpd "$LIGHTTPD_VERSION" "$LIGHTTPD_SOURCE_URL" "$LIGHTTPD_DOWNLOAD_URL" "$LIGHTTPD_SHA256" || exit 77

archive="$LIGHTTPD_COMPONENT_ROOT/downloads/lighttpd-$LIGHTTPD_VERSION.tar.xz"
source_parent="$LIGHTTPD_COMPONENT_ROOT/src"
download_runtime_artifact lighttpd "$LIGHTTPD_DOWNLOAD_URL" "$archive" >/dev/null || exit 77
verify_runtime_artifact_sha256 lighttpd "$LIGHTTPD_SHA256" "$archive" || exit 77
source_dir=$(extract_runtime_source_tar lighttpd "$archive" "$source_parent" "lighttpd-$LIGHTTPD_VERSION") || exit 77

{
    printf 'lighttpd source staged: %s\n' "$source_dir"
    printf 'lighttpd_version=%s\n' "$LIGHTTPD_VERSION"
    printf 'lighttpd_download_url=%s\n' "$LIGHTTPD_DOWNLOAD_URL"
    printf 'lighttpd_sha256_status=%s\n' "$sha_status"
    printf 'lighttpd_runtime_binary_available=false\n'
    printf 'BLOCKED: lighttpd source is staged, but no local lighttpd runtime binary was built.\n'
    printf 'Lighttpd runtime smoke remains BLOCKED until build and integration mode are implemented.\n'
} >&2
exit 77
