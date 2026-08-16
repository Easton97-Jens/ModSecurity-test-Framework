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

case "$ENVOY_INTEGRATION_MODE" in
    ext_authz) envoy_lock_profile=envoy-ext-authz ;;
    ext_proc) envoy_lock_profile=envoy-ext-proc ;;
    *)
        ci_blocked "unsupported ENVOY_INTEGRATION_MODE for the reviewed component lock"
        exit 77
        ;;
esac
runtime_component_require_locked_profile \
    "$envoy_lock_profile" \
    "ENVOY_VERSION=$ENVOY_VERSION" \
    "ENVOY_DOWNLOAD_URL=$ENVOY_DOWNLOAD_URL" \
    "ENVOY_SHA256=$ENVOY_SHA256" || {
    ci_blocked "Envoy runtime configuration does not match the reviewed component lock"
    exit 77
}

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

expected_envoy_bin="$ENVOY_COMPONENT_ROOT/bin/envoy"
if [ "${ENVOY_BIN_WAS_SET:-0}" = "1" ] && [ "$ENVOY_BIN" != "$expected_envoy_bin" ]; then
    ci_blocked "explicit ENVOY_BIN must use the reviewed staged path: $expected_envoy_bin"
    exit 77
fi

verify_existing_envoy_binary() {
    [ -f "$ENVOY_BIN" ] && [ -x "$ENVOY_BIN" ] || return 1
    actual_sha=$(ci_trusted_sha256_file "$ENVOY_BIN") || return 77
    if [ "$actual_sha" != "$ENVOY_SHA256" ]; then
        ci_blocked "existing Envoy binary sha256 does not match the reviewed artifact"
        return 77
    fi
    return 0
}

if [ -f "$ENVOY_BIN" ] && [ -x "$ENVOY_BIN" ]; then
    verify_existing_envoy_binary || exit 77
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

artifact="$ENVOY_COMPONENT_ROOT/downloads/$ENVOY_ASSET_NAME"
download_runtime_artifact envoy "$ENVOY_DOWNLOAD_URL" "$artifact" >/dev/null || exit 77
verify_runtime_artifact_sha256 envoy "$ENVOY_SHA256" "$artifact" || exit 77
stage_executable_binary envoy "$artifact" "$ENVOY_BIN" >/dev/null || exit 77

printf 'envoy runtime binary staged: %s\n' "$ENVOY_BIN"
printf 'envoy_version=%s\n' "$ENVOY_VERSION"
printf 'envoy_download_url=%s\n' "$ENVOY_DOWNLOAD_URL"
printf 'envoy_sha256_status=%s\n' "$sha_status"
