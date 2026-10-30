#!/bin/sh
: "${TEST_ROOT:?TEST_ROOT is required explicitly}"
set -eu

SCRIPT_DIR=$(CDPATH='' cd "$(dirname "$0")" && pwd)
CONNECTOR_DIR=$(CDPATH='' cd "$SCRIPT_DIR/.." && pwd)
REPO_ROOT=$(CDPATH='' cd "$CONNECTOR_DIR/../.." && pwd)
BUILD_ROOT=${BUILD_ROOT:-${XDG_STATE_HOME:-${HOME:-/tmp}/.local/state}/ModSecurity-conector-build}
SMOKE_DIR=${LIGHTTPD_SMOKE_DIR:-$BUILD_ROOT/lighttpd-connector/smoke}
SMOKE_PORT=${LIGHTTPD_SMOKE_PORT:-18084}
RULES_FILE=${MSCONNECTOR_RULES_FILE:-$TEST_ROOT/connector_suite/common/rules/modsecurity_targeted_smoke.conf}
REQUEST_BODY_MODE=${LIGHTTPD_REQUEST_BODY_MODE:-none}
RESPONSE_BODY_MODE=${LIGHTTPD_RESPONSE_BODY_MODE:-none}
RESPONSE_HEADER_MARKER=${LIGHTTPD_RESPONSE_HEADER_MARKER:-}
EXPOSE_HOST_TRANSACTION_ID=${LIGHTTPD_EXPOSE_HOST_TRANSACTION_ID:-0}
PROXY_BARRIER_PORT=${LIGHTTPD_PROXY_BARRIER_PORT:-}
PROXY_FIXTURE_PORT=${LIGHTTPD_PROXY_FIXTURE_PORT:-}
RUNTIME_CONFIG=$SMOKE_DIR/msconnector-runtime.conf
LIGHTTPD_CONFIG=$SMOKE_DIR/lighttpd.conf
EVENT_PATH=$SMOKE_DIR/events.jsonl

blocked() {
    reason=$1
    printf 'lighttpd_native_smoke_config: BLOCKED: %s\n' "$reason" >&2
    exit 77
}

case "$BUILD_ROOT" in
    /*) ;;
    *) blocked "BUILD_ROOT must be absolute: $BUILD_ROOT" ;;
esac
case "$SMOKE_DIR" in
    /*) ;;
    *) blocked "LIGHTTPD_SMOKE_DIR must be absolute: $SMOKE_DIR" ;;
esac
case "$SMOKE_PORT" in
    ''|*[!0-9]*) blocked "LIGHTTPD_SMOKE_PORT must be numeric" ;;
    *) ;;
esac
if [ "$SMOKE_PORT" -lt 1024 ] || [ "$SMOKE_PORT" -gt 65535 ]; then
    blocked "LIGHTTPD_SMOKE_PORT must be between 1024 and 65535"
fi
[ -f "$RULES_FILE" ] || blocked "smoke rules file is missing: $RULES_FILE"
case "$REQUEST_BODY_MODE" in
    none|streaming) ;;
    *) blocked "LIGHTTPD_REQUEST_BODY_MODE must be none or streaming" ;;
esac
case "$RESPONSE_BODY_MODE" in
    none) ;;
    streaming)
        [ "${LIGHTTPD_ENTITY_BODY_HOOK:-0}" = 1 ] || blocked \
            "LIGHTTPD_RESPONSE_BODY_MODE=streaming requires the patched Lighttpd entity-body hook"
        ;;
    *) blocked "LIGHTTPD_RESPONSE_BODY_MODE must be none or streaming" ;;
esac
case "$RESPONSE_HEADER_MARKER" in
    ''|block|redirect) ;;
    *) blocked "LIGHTTPD_RESPONSE_HEADER_MARKER must be empty, block, or redirect" ;;
esac
case "$EXPOSE_HOST_TRANSACTION_ID" in
    0|1) ;;
    *) blocked "LIGHTTPD_EXPOSE_HOST_TRANSACTION_ID must be 0 or 1" ;;
esac
for proxy_port in "$PROXY_BARRIER_PORT" "$PROXY_FIXTURE_PORT"; do
    case "$proxy_port" in
        '') ;;
        *[!0-9]*) blocked "Lighttpd proxy ports must be numeric" ;;
        *)
            if [ "$proxy_port" -lt 1 ] || [ "$proxy_port" -gt 65535 ]; then
                blocked "Lighttpd proxy ports must be between 1 and 65535"
            fi
            ;;
    esac
done
if [ -n "$PROXY_BARRIER_PORT" ] || [ -n "$PROXY_FIXTURE_PORT" ]; then
    [ -n "$PROXY_BARRIER_PORT" ] && [ -n "$PROXY_FIXTURE_PORT" ] || blocked \
        "both LIGHTTPD_PROXY_BARRIER_PORT and LIGHTTPD_PROXY_FIXTURE_PORT are required"
    [ "$RESPONSE_BODY_MODE" = streaming ] || blocked \
        "the Lighttpd HTTP/1.1 proxy routes require response_body_mode=streaming"
fi

mkdir -p "$SMOKE_DIR/document-root" "$SMOKE_DIR/upload"
: > "$EVENT_PATH"
printf '%s\n' 'lighttpd native connector smoke' > "$SMOKE_DIR/document-root/index.html"
printf '%s\n' 'lighttpd phase-3 response header probe' > "$SMOKE_DIR/document-root/phase3-block"
printf '%s\n' 'lighttpd phase-3 redirect header probe' > "$SMOKE_DIR/document-root/phase3-redirect"

{
    printf 'enabled=on\n'
    printf 'rules_file=%s\n' "$RULES_FILE"
    # The patched module supplies its own unique host transaction ID first;
    # retain the canonical fallback header for hosts that do not provide one.
    printf 'transaction_id_header=x-modsec-transaction-id\n'
    printf 'request_body_mode=%s\n' "$REQUEST_BODY_MODE"
    printf 'response_body_mode=%s\n' "$RESPONSE_BODY_MODE"
    printf 'default_block_status=403\n'
    printf 'default_error_status=500\n'
    printf 'max_header_count=256\n'
    printf 'max_header_name_size=256\n'
    printf 'max_header_value_size=8192\n'
    printf 'max_total_header_bytes=65536\n'
    printf 'max_event_json_bytes=16384\n'
    printf 'event_path=%s\n' "$EVENT_PATH"
} > "$RUNTIME_CONFIG"

escape_lighttpd_string() {
    input_value=$1
    printf '%s' "$input_value" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

DOCUMENT_ROOT_ESCAPED=$(escape_lighttpd_string "$SMOKE_DIR/document-root")
ERROR_LOG_ESCAPED=$(escape_lighttpd_string "$SMOKE_DIR/lighttpd-error.log")
PID_FILE_ESCAPED=$(escape_lighttpd_string "$SMOKE_DIR/lighttpd.pid")
UPLOAD_DIR_ESCAPED=$(escape_lighttpd_string "$SMOKE_DIR/upload")
RUNTIME_CONFIG_ESCAPED=$(escape_lighttpd_string "$RUNTIME_CONFIG")

{
    printf 'server.compat-module-load = "disable"\n'
    if [ -n "$PROXY_BARRIER_PORT" ]; then
        # Only the patched HTTP/1.x entity-body path is exercised.  mod_h2 is
        # deliberately absent; no H2/H3 listener or protocol claim is added.
        if [ -n "$RESPONSE_HEADER_MARKER" ]; then
            printf 'server.modules = ( "mod_setenv", "mod_proxy", "mod_msconnector" )\n'
        else
            printf 'server.modules = ( "mod_proxy", "mod_msconnector" )\n'
        fi
        # Flush proxied HTTP/1.1 entity chunks while the upstream barrier is
        # still paused.  This is a delivery setting, not a response buffer.
        printf 'server.stream-response-body = 1\n'
    elif [ -n "$RESPONSE_HEADER_MARKER" ]; then
        # Response-start hooks run in module order.  The header producer must
        # run before mod_msconnector maps the real response headers.
        printf 'server.modules = ( "mod_setenv", "mod_msconnector" )\n'
    else
        printf 'server.modules = ( "mod_msconnector" )\n'
    fi
    printf 'server.document-root = "%s"\n' "$DOCUMENT_ROOT_ESCAPED"
    printf 'server.bind = "127.0.0.1"\n'
    printf 'server.port = %s\n' "$SMOKE_PORT"
    printf 'server.errorlog = "%s"\n' "$ERROR_LOG_ESCAPED"
    printf 'server.pid-file = "%s"\n' "$PID_FILE_ESCAPED"
    printf 'server.upload-dirs = ( "%s" )\n' "$UPLOAD_DIR_ESCAPED"
    printf 'msconnector.enabled = "enable"\n'
    printf 'msconnector.config-file = "%s"\n' "$RUNTIME_CONFIG_ESCAPED"
    if [ "$REQUEST_BODY_MODE" = streaming ]; then
        # Patched P2 is a preventive gate: the module must not enable
        # lighttpd's request-stream forwarding flag while body EOS is pending.
        printf 'msconnector.request-body-gate = "pre-upstream"\n'
    fi
    if [ "$EXPOSE_HOST_TRANSACTION_ID" = 1 ]; then
        # This is harness-only evidence plumbing.  The module emits the
        # server-generated host transaction ID; it never reflects a request
        # header or changes Common Runtime transaction-ID selection.
        printf 'msconnector.expose-host-transaction-id = "enable"\n'
    fi
    if [ -n "$PROXY_BARRIER_PORT" ]; then
        printf 'proxy.server = (\n'
        printf '  "/p4/barrier/" => ( ( "host" => "127.0.0.1", "port" => %s ) ),\n' "$PROXY_BARRIER_PORT"
        printf '  "/p4/fixture/" => ( ( "host" => "127.0.0.1", "port" => %s ) )\n' "$PROXY_FIXTURE_PORT"
        printf ')\n'
    fi
    if [ -n "$RESPONSE_HEADER_MARKER" ]; then
        printf '%s\n' "\$HTTP[\"url\"] == \"/phase3-${RESPONSE_HEADER_MARKER}\" {"
        if [ "$EXPOSE_HOST_TRANSACTION_ID" = 1 ]; then
            # The response module must replace this controlled upstream value
            # with its own host-generated identifier.  This regression probe
            # is only present in the private opt-in evidence harness.
            printf '  setenv.add-response-header = ( "X-Modsec-Upstream" => "%s", "X-Msconnector-Host-Transaction-Id" => "untrusted-upstream-value" )\n' "$RESPONSE_HEADER_MARKER"
        else
            printf '  setenv.add-response-header = ( "X-Modsec-Upstream" => "%s" )\n' "$RESPONSE_HEADER_MARKER"
        fi
        printf '}\n'
    fi
} > "$LIGHTTPD_CONFIG"

printf '%s\n' "$LIGHTTPD_CONFIG"
