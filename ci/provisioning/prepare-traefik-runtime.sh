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
ci_require_traefik_pinned_provenance || exit 77

case "$TRAEFIK_INTEGRATION_MODE" in
    forwardAuth|forwardauth) traefik_lock_profile=traefik-forwardauth ;;
    native|native-middleware) traefik_lock_profile=traefik-native ;;
    *)
        ci_blocked "unsupported TRAEFIK_INTEGRATION_MODE for the reviewed component lock"
        exit 77
        ;;
esac
runtime_component_require_locked_profile \
    "$traefik_lock_profile" \
    "TRAEFIK_VERSION=$TRAEFIK_VERSION" \
    "TRAEFIK_DOWNLOAD_URL=$TRAEFIK_DOWNLOAD_URL" \
    "TRAEFIK_SHA256=$TRAEFIK_SHA256" || {
    ci_blocked "Traefik runtime configuration does not match the reviewed component lock"
    exit 77
}

sha_status=$(runtime_component_sha_status "$TRAEFIK_SHA256")
blocked_extra="Stage the reviewed Traefik Linux amd64 release archive at:
  $TRAEFIK_ARCHIVE
It must be named $TRAEFIK_ARCHIVE_NAME and match the canonical SHA256 before
the local binary can be staged."

assert_safe_runtime_path "$TRAEFIK_COMPONENT_ROOT" TRAEFIK_COMPONENT_ROOT || exit 77
assert_safe_runtime_path "$TRAEFIK_RUNTIME_ROOT" TRAEFIK_RUNTIME_ROOT || exit 77
assert_safe_runtime_path "$TRAEFIK_CONFIG_ROOT" TRAEFIK_CONFIG_ROOT || exit 77
assert_safe_runtime_path "$TRAEFIK_LOG_ROOT" TRAEFIK_LOG_ROOT || exit 77
assert_safe_runtime_path "$TRAEFIK_RESULT_ROOT" TRAEFIK_RESULT_ROOT || exit 77
assert_safe_runtime_path "$TRAEFIK_ARCHIVE" TRAEFIK_ARCHIVE || exit 77
runtime_component_require_under_root "$TRAEFIK_BUILD_ROOT" "$BUILD_ROOT" TRAEFIK_BUILD_ROOT || exit 77
runtime_component_require_under_root "$TRAEFIK_BIN" "$TRAEFIK_BUILD_ROOT" TRAEFIK_BIN || exit 77
ci_require_absolute_path "$TRAEFIK_BIN" TRAEFIK_BIN || exit 77
if ci_path_is_system_path "$TRAEFIK_BIN"; then
    ci_blocked "TRAEFIK_BIN must not point at a global system path: $TRAEFIK_BIN"
    exit 77
fi
runtime_component_require_under_cache "$TRAEFIK_ARCHIVE" TRAEFIK_ARCHIVE || exit 77
require_pinned_runtime_source traefik "$TRAEFIK_VERSION" "$TRAEFIK_SOURCE_URL" "$TRAEFIK_DOWNLOAD_URL" "$TRAEFIK_SHA256" || exit 77

archive=$TRAEFIK_ARCHIVE
verified_archive="$TRAEFIK_BUILD_ROOT/verified-archives/$TRAEFIK_ARCHIVE_NAME"
extract_root="$TRAEFIK_BUILD_ROOT/extract/traefik-$TRAEFIK_VERSION"
if [ ! -f "$archive" ]; then
    if ! require_runtime_download_opt_in; then
        write_prepare_blocked_message \
            traefik \
            "$TRAEFIK_VERSION" \
            "$TRAEFIK_SOURCE_URL" \
            "$TRAEFIK_INSTALL_DOCS_URL" \
            "" \
            "$TRAEFIK_DOWNLOAD_URL" \
            "$sha_status" \
            "$TRAEFIK_SHA256_URL" \
            "$TRAEFIK_BIN" \
            "$blocked_extra"
        exit 77
    fi
    download_runtime_artifact traefik "$TRAEFIK_DOWNLOAD_URL" "$archive" >/dev/null || exit 77
fi
verify_runtime_artifact_sha256 traefik "$TRAEFIK_SHA256" "$archive" || exit 77
verified_archive=$(runtime_component_stage_verified_archive \
    traefik "$TRAEFIK_SHA256" "$archive" "$verified_archive" \
    "$TRAEFIK_BUILD_ROOT") || exit 77
extracted_binary=$(extract_single_binary_from_tar traefik "$verified_archive" traefik "$extract_root" "$TRAEFIK_BUILD_ROOT") || exit 77
stage_executable_binary traefik "$extracted_binary" "$TRAEFIK_BIN" "$TRAEFIK_BUILD_ROOT" >/dev/null || exit 77

printf 'traefik runtime binary staged: %s\n' "$TRAEFIK_BIN"
printf 'traefik_version=%s\n' "$TRAEFIK_VERSION"
printf 'traefik_download_url=%s\n' "$TRAEFIK_DOWNLOAD_URL"
printf 'traefik_sha256_status=%s\n' "$sha_status"
