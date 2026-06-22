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

ci_validate_https_runtime_url_config || exit 77

sha_status=pinned
if [ -z "$LIGHTTPD_SHA256" ] || [ "$LIGHTTPD_SHA256" = "TODO_PIN_SHA256" ]; then
    sha_status=missing
fi

assert_safe_runtime_path "$LIGHTTPD_COMPONENT_ROOT" LIGHTTPD_COMPONENT_ROOT || exit 77
assert_safe_runtime_path "$LIGHTTPD_RUNTIME_ROOT" LIGHTTPD_RUNTIME_ROOT || exit 77
assert_safe_runtime_path "$LIGHTTPD_CONFIG_ROOT" LIGHTTPD_CONFIG_ROOT || exit 77
assert_safe_runtime_path "$LIGHTTPD_LOG_ROOT" LIGHTTPD_LOG_ROOT || exit 77
assert_safe_runtime_path "$LIGHTTPD_RESULT_ROOT" LIGHTTPD_RESULT_ROOT || exit 77
assert_not_system_path_for_write "$LIGHTTPD_COMPONENT_ROOT/bin" LIGHTTPD_COMPONENT_BIN_DIR || exit 77
ci_require_absolute_path "$LIGHTTPD_BIN" LIGHTTPD_BIN || exit 77
if ci_path_is_system_path "$LIGHTTPD_BIN"; then
    ci_blocked "LIGHTTPD_BIN must not point at a global system path: $LIGHTTPD_BIN"
    exit 77
fi

if [ -f "$LIGHTTPD_BIN" ] && [ -x "$LIGHTTPD_BIN" ]; then
    printf 'lighttpd runtime binary: %s\n' "$LIGHTTPD_BIN"
    printf 'lighttpd_version=%s\n' "$LIGHTTPD_VERSION"
    printf 'lighttpd_source_page=%s\n' "$LIGHTTPD_SOURCE_PAGE"
    printf 'lighttpd_download_url=%s\n' "$LIGHTTPD_DOWNLOAD_URL"
    printf 'lighttpd_sha256_status=%s\n' "$sha_status"
    exit 0
fi

mkdir -p "$LIGHTTPD_COMPONENT_ROOT/bin"

cat >&2 <<EOF
BLOCKED: lighttpd runtime dependency is not staged locally.
Version: $LIGHTTPD_VERSION
Source page: $LIGHTTPD_SOURCE_PAGE
Latest marker: $LIGHTTPD_LATEST_MARKER_URL
Download URL: $LIGHTTPD_DOWNLOAD_URL
SHA256 status: $sha_status
SHA256 URL: $LIGHTTPD_SHA256_URL
Expected local binary: $LIGHTTPD_BIN
Stage a prepared lighttpd binary at:
  $LIGHTTPD_COMPONENT_ROOT/bin/lighttpd
or set LIGHTTPD_BIN to an executable local/common.sh-managed path.
No global installation or download was attempted. Download execution is
disabled unless a future helper uses ALLOW_RUNTIME_DOWNLOADS=1 with the pinned
version and SHA256 above.
EOF
exit 77
