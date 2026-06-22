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
if [ -z "$ENVOY_SHA256" ] || [ "$ENVOY_SHA256" = "TODO_PIN_SHA256" ]; then
    sha_status=missing
fi

assert_safe_runtime_path "$ENVOY_COMPONENT_ROOT" ENVOY_COMPONENT_ROOT || exit 77
assert_safe_runtime_path "$ENVOY_RUNTIME_ROOT" ENVOY_RUNTIME_ROOT || exit 77
assert_safe_runtime_path "$ENVOY_CONFIG_ROOT" ENVOY_CONFIG_ROOT || exit 77
assert_safe_runtime_path "$ENVOY_LOG_ROOT" ENVOY_LOG_ROOT || exit 77
assert_safe_runtime_path "$ENVOY_RESULT_ROOT" ENVOY_RESULT_ROOT || exit 77
assert_not_system_path_for_write "$ENVOY_COMPONENT_ROOT/bin" ENVOY_COMPONENT_BIN_DIR || exit 77
ci_require_absolute_path "$ENVOY_BIN" ENVOY_BIN || exit 77
if ci_path_is_system_path "$ENVOY_BIN"; then
    ci_blocked "ENVOY_BIN must not point at a global system path: $ENVOY_BIN"
    exit 77
fi

if [ -f "$ENVOY_BIN" ] && [ -x "$ENVOY_BIN" ]; then
    printf 'envoy runtime binary: %s\n' "$ENVOY_BIN"
    printf 'envoy_version=%s\n' "$ENVOY_VERSION"
    printf 'envoy_source_page=%s\n' "$ENVOY_SOURCE_PAGE"
    printf 'envoy_download_url=%s\n' "$ENVOY_DOWNLOAD_URL"
    printf 'envoy_sha256_status=%s\n' "$sha_status"
    exit 0
fi

mkdir -p "$ENVOY_COMPONENT_ROOT/bin"

cat >&2 <<EOF
BLOCKED: envoy runtime dependency is not staged locally.
Version: $ENVOY_VERSION
Source page: $ENVOY_SOURCE_PAGE
Install docs: $ENVOY_INSTALL_DOCS_URL
Download URL: $ENVOY_DOWNLOAD_URL
SHA256 status: $sha_status
SHA256 URL: $ENVOY_SHA256_URL
Expected local binary: $ENVOY_BIN
Stage a prepared Envoy binary at:
  $ENVOY_COMPONENT_ROOT/bin/envoy
or set ENVOY_BIN to an executable local/common.sh-managed path.
No global installation or download was attempted. Download execution is
disabled unless a future helper uses ALLOW_RUNTIME_DOWNLOADS=1 with the pinned
version and SHA256 above.
EOF
exit 77
