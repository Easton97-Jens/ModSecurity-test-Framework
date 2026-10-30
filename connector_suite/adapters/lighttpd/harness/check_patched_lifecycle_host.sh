#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd "$(dirname "$0")" && pwd)
LIGHTTPD_VERSION=$(sh "$SCRIPT_DIR/../build/read_version.sh")
BUILD_ROOT=${BUILD_ROOT:-${XDG_STATE_HOME:-${HOME:-/tmp}/.local/state}/ModSecurity-conector-build}
PATCHED_ROOT=${LIGHTTPD_PATCHED_ROOT:-$BUILD_ROOT/lighttpd-core-patched}
CORE_BIN=$PATCHED_ROOT/stage/bin/lighttpd
MODULE_PATH=$PATCHED_ROOT/stage/modules/mod_msconnector.so
PROXY_MODULE_PATH=$PATCHED_ROOT/stage/modules/mod_proxy.so
HOST_MANIFEST=$PATCHED_ROOT/patched-host-build-info.txt
SMOKE_DIR=${LIGHTTPD_PATCHED_SMOKE_DIR:-$PATCHED_ROOT/smoke}
NM_BIN=${NM:-nm}

blocked() {
    reason=$1
    printf 'lighttpd_patched_host_check: BLOCKED: %s\n' "$reason" >&2
    exit 77
}

manifest_value() {
    key=$1
    sed -n "s/^$key=//p" "$HOST_MANIFEST" | sed -n '1p'
}

sha256_file() {
    input_path=$1
    sha256sum "$input_path" | awk '{print $1}'
}

[ -f "$HOST_MANIFEST" ] || blocked "patched host manifest is missing; run build-lighttpd-patched-host first"
[ -x "$CORE_BIN" ] || blocked "patched lighttpd binary is missing: $CORE_BIN"
[ -f "$MODULE_PATH" ] || blocked "patched module is missing: $MODULE_PATH"
[ -f "$PROXY_MODULE_PATH" ] || blocked "patched proxy module is missing: $PROXY_MODULE_PATH"
[ "$(manifest_value lighttpd_version)" = "$LIGHTTPD_VERSION" ] || blocked "patched host manifest has an unexpected version"
[ "$(manifest_value core_binary)" = "$CORE_BIN" ] || blocked "manifest core binary does not match staged patched binary"
[ "$(manifest_value module)" = "$MODULE_PATH" ] || blocked "manifest module does not match staged patched module"
[ "$(manifest_value proxy_module)" = "$PROXY_MODULE_PATH" ] || blocked "manifest proxy module does not match staged proxy module"
[ "$(manifest_value phase4_runtime_evidence)" = not_executed ] || blocked "patched host manifest has an unsafe Phase-4 claim"
command -v "$NM_BIN" >/dev/null 2>&1 || blocked "missing nm command: $NM_BIN"
command -v sha256sum >/dev/null 2>&1 || blocked "missing sha256sum command"
[ "$(manifest_value core_binary_sha256)" = "$(sha256_file "$CORE_BIN")" ] || \
    blocked "staged core binary does not match its host manifest"
[ "$(manifest_value module_sha256)" = "$(sha256_file "$MODULE_PATH")" ] || \
    blocked "staged module does not match its host manifest"
[ "$(manifest_value proxy_module_sha256)" = "$(sha256_file "$PROXY_MODULE_PATH")" ] || \
    blocked "staged proxy module does not match its host manifest"

"$CORE_BIN" -v 2>&1 | grep -Fq "lighttpd/$LIGHTTPD_VERSION" || blocked "staged binary does not report lighttpd/$LIGHTTPD_VERSION"
for symbol in plugins_call_handle_request_body plugins_call_handle_response_body; do
    "$NM_BIN" -D "$CORE_BIN" | grep -Eq "[[:space:]][Tt][[:space:]]$symbol$" || \
        blocked "patched binary does not export required hook symbol: $symbol"
done
"$NM_BIN" -D "$PROXY_MODULE_PATH" | grep -Eq '[[:space:]][Tt][[:space:]]mod_proxy_plugin_init$' || \
    blocked "staged proxy module does not export mod_proxy_plugin_init"

MODSECURITY_LIB_DIR=$(manifest_value modsecurity_lib_dir)
[ -n "$MODSECURITY_LIB_DIR" ] || blocked "patched host manifest has no libmodsecurity directory"
[ -f "$MODSECURITY_LIB_DIR/libmodsecurity.so" ] || blocked "manifest libmodsecurity directory is unusable: $MODSECURITY_LIB_DIR"

LD_LIBRARY_PATH="$MODSECURITY_LIB_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export LD_LIBRARY_PATH
BUILD_ROOT="$BUILD_ROOT" \
LIGHTTPD_PATCHED_ROOT="$PATCHED_ROOT" \
LIGHTTPD_PATCHED_SMOKE_DIR="$SMOKE_DIR" \
LIGHTTPD_BIN="$CORE_BIN" \
LIGHTTPD_CONNECTOR_MODULE="$MODULE_PATH" \
LIGHTTPD_MODULE_DIR=$(dirname "$MODULE_PATH") \
LIGHTTPD_SMOKE_DIR="$SMOKE_DIR" \
LIGHTTPD_SMOKE_PREPARER="$SCRIPT_DIR/prepare_patched_lifecycle_smoke.sh" \
sh "$SCRIPT_DIR/check_lighttpd_config.sh"

printf 'lighttpd_patched_host_check: PASS binary=%s module=%s config_root=%s phase4=not-executed\n' \
    "$CORE_BIN" "$MODULE_PATH" "$SMOKE_DIR"
