#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
CI_ROOT="${CI_ROOT:-$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)}"
. "$CI_ROOT/lib/path-bootstrap.sh"
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

sha_status=$(runtime_component_sha_status "$TRAEFIK_SHA256")
blocked_extra="Stage a prepared Traefik binary at:
  $TRAEFIK_COMPONENT_ROOT/bin/traefik
or set TRAEFIK_BIN to an executable local/common.sh-managed path."

assert_safe_runtime_path "$TRAEFIK_COMPONENT_ROOT" TRAEFIK_COMPONENT_ROOT || exit 77
assert_safe_runtime_path "$TRAEFIK_RUNTIME_ROOT" TRAEFIK_RUNTIME_ROOT || exit 77
assert_safe_runtime_path "$TRAEFIK_CONFIG_ROOT" TRAEFIK_CONFIG_ROOT || exit 77
assert_safe_runtime_path "$TRAEFIK_LOG_ROOT" TRAEFIK_LOG_ROOT || exit 77
assert_safe_runtime_path "$TRAEFIK_RESULT_ROOT" TRAEFIK_RESULT_ROOT || exit 77
ci_require_absolute_path "$TRAEFIK_BIN" TRAEFIK_BIN || exit 77
if ci_path_is_system_path "$TRAEFIK_BIN"; then
    ci_blocked "TRAEFIK_BIN must not point at a global system path: $TRAEFIK_BIN"
    exit 77
fi

if [ -f "$TRAEFIK_BIN" ] && [ -x "$TRAEFIK_BIN" ]; then
    printf 'traefik runtime binary: %s\n' "$TRAEFIK_BIN"
    printf 'traefik_version=%s\n' "$TRAEFIK_VERSION"
    printf 'traefik_source_url=%s\n' "$TRAEFIK_SOURCE_URL"
    printf 'traefik_download_url=%s\n' "$TRAEFIK_DOWNLOAD_URL"
    printf 'traefik_sha256_status=%s\n' "$sha_status"
    exit 0
fi

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

require_pinned_runtime_source traefik "$TRAEFIK_VERSION" "$TRAEFIK_SOURCE_URL" "$TRAEFIK_DOWNLOAD_URL" "$TRAEFIK_SHA256" || exit 77

archive="$TRAEFIK_COMPONENT_ROOT/downloads/traefik_v${TRAEFIK_VERSION}_linux_amd64.tar.gz"
extract_root="$TRAEFIK_COMPONENT_ROOT/extract/traefik-$TRAEFIK_VERSION"
download_runtime_artifact traefik "$TRAEFIK_DOWNLOAD_URL" "$archive" >/dev/null || exit 77
verify_runtime_artifact_sha256 traefik "$TRAEFIK_SHA256" "$archive" || exit 77
extracted_binary=$(extract_single_binary_from_tar traefik "$archive" traefik "$extract_root") || exit 77
stage_executable_binary traefik "$extracted_binary" "$TRAEFIK_BIN" >/dev/null || exit 77

printf 'traefik runtime binary staged: %s\n' "$TRAEFIK_BIN"
printf 'traefik_version=%s\n' "$TRAEFIK_VERSION"
printf 'traefik_download_url=%s\n' "$TRAEFIK_DOWNLOAD_URL"
printf 'traefik_sha256_status=%s\n' "$sha_status"
