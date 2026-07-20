#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
. "$SCRIPT_DIR/../lib/path-bootstrap.sh"
if [ -n "${CONNECTOR_ROOT:-}" ]; then
    CONNECTOR_ROOT=$(CDPATH= cd "$CONNECTOR_ROOT" && pwd)
elif [ -d "$FRAMEWORK_ROOT/../../connectors" ]; then
    CONNECTOR_ROOT=$(CDPATH= cd "$FRAMEWORK_ROOT/../.." && pwd)
else
    CONNECTOR_ROOT=$(pwd)
fi

. "$CI_ROOT/lib/common.sh"
. "$CI_ROOT/lib/runtime-component-common.sh"

ci_validate_https_runtime_url_config || exit 77

sha_status=$(runtime_component_sha_status "$ENVOY_SHA256")
blocked_extra="Stage a prepared Envoy binary at:
  $ENVOY_COMPONENT_ROOT/bin/envoy
or set ENVOY_BIN to an executable local/common.sh-managed path."

assert_safe_runtime_path "$ENVOY_COMPONENT_ROOT" ENVOY_COMPONENT_ROOT || exit 77
assert_safe_runtime_path "$ENVOY_RUNTIME_ROOT" ENVOY_RUNTIME_ROOT || exit 77
assert_safe_runtime_path "$ENVOY_CONFIG_ROOT" ENVOY_CONFIG_ROOT || exit 77
assert_safe_runtime_path "$ENVOY_LOG_ROOT" ENVOY_LOG_ROOT || exit 77
assert_safe_runtime_path "$ENVOY_RESULT_ROOT" ENVOY_RESULT_ROOT || exit 77
ci_require_absolute_path "$ENVOY_BIN" ENVOY_BIN || exit 77
if ci_path_is_system_path "$ENVOY_BIN"; then
    ci_blocked "ENVOY_BIN must not point at a global system path: $ENVOY_BIN"
    exit 77
fi

if [ -f "$ENVOY_BIN" ] && [ -x "$ENVOY_BIN" ]; then
    printf 'envoy runtime binary: %s\n' "$ENVOY_BIN"
    printf 'envoy_version=%s\n' "$ENVOY_VERSION"
    printf 'envoy_source_url=%s\n' "$ENVOY_SOURCE_URL"
    printf 'envoy_download_url=%s\n' "$ENVOY_DOWNLOAD_URL"
    printf 'envoy_sha256_status=%s\n' "$sha_status"
    exit 0
fi

if ! require_runtime_download_opt_in; then
    write_prepare_blocked_message \
        envoy \
        "$ENVOY_VERSION" \
        "$ENVOY_SOURCE_URL" \
        "$ENVOY_INSTALL_DOCS_URL" \
        "" \
        "$ENVOY_DOWNLOAD_URL" \
        "$sha_status" \
        "$ENVOY_SHA256_URL" \
        "$ENVOY_BIN" \
        "$blocked_extra"
    exit 77
fi

require_pinned_runtime_source envoy "$ENVOY_VERSION" "$ENVOY_SOURCE_URL" "$ENVOY_DOWNLOAD_URL" "$ENVOY_SHA256" || exit 77

artifact="$ENVOY_COMPONENT_ROOT/downloads/envoy-$ENVOY_VERSION-linux-x86_64"
download_runtime_artifact envoy "$ENVOY_DOWNLOAD_URL" "$artifact" >/dev/null || exit 77
verify_runtime_artifact_sha256 envoy "$ENVOY_SHA256" "$artifact" || exit 77
stage_executable_binary envoy "$artifact" "$ENVOY_BIN" >/dev/null || exit 77

printf 'envoy runtime binary staged: %s\n' "$ENVOY_BIN"
printf 'envoy_version=%s\n' "$ENVOY_VERSION"
printf 'envoy_download_url=%s\n' "$ENVOY_DOWNLOAD_URL"
printf 'envoy_sha256_status=%s\n' "$sha_status"
