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
if [ -z "$TRAEFIK_SHA256" ] || [ "$TRAEFIK_SHA256" = "TODO_PIN_SHA256" ]; then
    sha_status=missing
fi

assert_safe_runtime_path "$TRAEFIK_COMPONENT_ROOT" TRAEFIK_COMPONENT_ROOT || exit 77
assert_safe_runtime_path "$TRAEFIK_RUNTIME_ROOT" TRAEFIK_RUNTIME_ROOT || exit 77
assert_safe_runtime_path "$TRAEFIK_CONFIG_ROOT" TRAEFIK_CONFIG_ROOT || exit 77
assert_safe_runtime_path "$TRAEFIK_LOG_ROOT" TRAEFIK_LOG_ROOT || exit 77
assert_safe_runtime_path "$TRAEFIK_RESULT_ROOT" TRAEFIK_RESULT_ROOT || exit 77
assert_not_system_path_for_write "$TRAEFIK_COMPONENT_ROOT/bin" TRAEFIK_COMPONENT_BIN_DIR || exit 77
ci_require_absolute_path "$TRAEFIK_BIN" TRAEFIK_BIN || exit 77
if ci_path_is_system_path "$TRAEFIK_BIN"; then
    ci_blocked "TRAEFIK_BIN must not point at a global system path: $TRAEFIK_BIN"
    exit 77
fi

if [ -f "$TRAEFIK_BIN" ] && [ -x "$TRAEFIK_BIN" ]; then
    printf 'traefik runtime binary: %s\n' "$TRAEFIK_BIN"
    printf 'traefik_version=%s\n' "$TRAEFIK_VERSION"
    printf 'traefik_source_page=%s\n' "$TRAEFIK_SOURCE_PAGE"
    printf 'traefik_download_url=%s\n' "$TRAEFIK_DOWNLOAD_URL"
    printf 'traefik_sha256_status=%s\n' "$sha_status"
    exit 0
fi

mkdir -p "$TRAEFIK_COMPONENT_ROOT/bin"

cat >&2 <<EOF
BLOCKED: traefik runtime dependency is not staged locally.
Version: $TRAEFIK_VERSION
Source page: $TRAEFIK_SOURCE_PAGE
Install docs: $TRAEFIK_INSTALL_DOCS_URL
Download URL: $TRAEFIK_DOWNLOAD_URL
SHA256 status: $sha_status
SHA256 URL: $TRAEFIK_SHA256_URL
Expected local binary: $TRAEFIK_BIN
Stage a prepared Traefik binary at:
  $TRAEFIK_COMPONENT_ROOT/bin/traefik
or set TRAEFIK_BIN to an executable local/common.sh-managed path.
No global installation or download was attempted. Download execution is
disabled unless a future helper uses ALLOW_RUNTIME_DOWNLOADS=1 with the pinned
version and SHA256 above.
EOF
exit 77
