#!/bin/sh
: "${TEST_ROOT:?TEST_ROOT is required explicitly}"
set -eu

REPO_ROOT=${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}
SCRIPT_DIR="${TEST_ROOT:?TEST_ROOT is required explicitly}/connector_suite/adapters/envoy/harness"
CONNECTOR_DIR="$REPO_ROOT/connectors/envoy"
BUILD_ROOT=${BUILD_ROOT:-${XDG_STATE_HOME:-${HOME:-/tmp}/.local/state}/ModSecurity-conector-build}
SERVICE_BIN=${SERVICE_BIN:-$BUILD_ROOT/envoy-connector/msconnector_envoy_ext_authz}
RESPONSE_OBSERVER_BIN=${RESPONSE_OBSERVER_BIN:-$BUILD_ROOT/envoy-connector/msconnector_envoy_response_observer}
CONFIG_FILE=${CONFIG_FILE:-$CONNECTOR_DIR/config/envoy-ext-authz.conf}
RULES_FILE=${RULES_FILE:-$TEST_ROOT/connector_suite/common/rules/modsecurity_targeted_smoke.conf}
EVENT_LOG_PATH=${EVENT_LOG_PATH:-$BUILD_ROOT/envoy-connector/start-smoke/events.jsonl}
PYTHON_BIN=${PYTHON:-python3}
HELPER="$SCRIPT_DIR/envoy_smoke_helper.py"
TLS_RENDERER="$CONNECTOR_DIR/config/lib/tls_yaml_render.sh"
YAML_TEMPLATE="${TEST_ROOT:?TEST_ROOT is required explicitly}/connector_suite/adapters/envoy/config/envoy-ext-authz-smoke.yaml.in"
START_ROOT=${START_ROOT:-$BUILD_ROOT/envoy-connector/start-smoke}
ENVOY_CONFIG="$START_ROOT/envoy.yaml"
ENVOY_STDOUT="$START_ROOT/envoy.stdout.log"
ENVOY_STDERR="$START_ROOT/envoy.stderr.log"
SERVICE_STDOUT="$START_ROOT/service.stdout.log"
SERVICE_STDERR="$START_ROOT/service.stderr.log"
SUMMARY="$START_ROOT/start-summary.txt"
SED_LOG_RANGE='1,160p'
TLS_CERTIFICATE="$START_ROOT/envoy-loopback.crt"
TLS_PRIVATE_KEY="$START_ROOT/envoy-loopback.key"
PRIVATE_SOCKET_DIR=${MSCONNECTOR_PRIVATE_SOCKET_ROOT:-$START_ROOT/mrc}
RESPONSE_OBSERVER_SOCKET="$PRIVATE_SOCKET_DIR/envoy-response-observer.sock"
COMPANION_SOCKET="$PRIVATE_SOCKET_DIR/envoy-ext-authz-companion.sock"
OBSERVER_STDOUT="$START_ROOT/response-observer.stdout.log"
OBSERVER_STDERR="$START_ROOT/response-observer.stderr.log"
envoy_pid=
service_pid=
observer_pid=

missing_dependency() {
    reason=$1
    echo "envoy_start_smoke: BLOCKED - $reason" >&2
    exit 77
}

cleanup() {
    for pid in "$envoy_pid" "$service_pid" "$observer_pid"; do
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    for pid in "$envoy_pid" "$service_pid" "$observer_pid"; do
        if [ -n "$pid" ]; then
            set +e
            wait "$pid" 2>/dev/null
            set -e
        fi
    done
    rm -f "$TLS_CERTIFICATE" "$TLS_PRIVATE_KEY"
}

[ -n "${ENVOY_BIN:-}" ] || missing_dependency "ENVOY_BIN is required"
[ -x "$ENVOY_BIN" ] || missing_dependency "ENVOY_BIN is not executable: $ENVOY_BIN"
[ -x "$SERVICE_BIN" ] || missing_dependency "connector service is not executable: $SERVICE_BIN"
[ -x "$RESPONSE_OBSERVER_BIN" ] || missing_dependency "required response observer is not executable: $RESPONSE_OBSERVER_BIN"
[ -f "$HELPER" ] || missing_dependency "smoke helper is missing: $HELPER"
[ -f "$TLS_RENDERER" ] || missing_dependency "TLS YAML renderer is missing: $TLS_RENDERER"
[ -f "$YAML_TEMPLATE" ] || missing_dependency "Envoy config template is missing: $YAML_TEMPLATE"
command -v "$PYTHON_BIN" >/dev/null 2>&1 || missing_dependency "Python interpreter is missing: $PYTHON_BIN"
. "$TLS_RENDERER"

case "$START_ROOT" in
    /*) ;;
    *) echo "envoy_start_smoke: FAIL - START_ROOT must be absolute" >&2; exit 1 ;;
esac
case "$START_ROOT" in
    "$REPO_ROOT"|"$REPO_ROOT"/*)
        echo "envoy_start_smoke: FAIL - START_ROOT must not be inside the checkout" >&2
        exit 1
        ;;
    *) ;;
esac
if ! "$PYTHON_BIN" "$HELPER" prepare-runtime-root --runtime-root "$START_ROOT"; then
    echo "envoy_start_smoke: FAIL - START_ROOT is unsafe for private runtime artifacts" >&2
    exit 1
fi
trap cleanup EXIT HUP INT TERM
rm -f "$SUMMARY" "$TLS_CERTIFICATE" "$TLS_PRIVATE_KEY"
set -- prepare-runtime-root --runtime-root "$PRIVATE_SOCKET_DIR"
if [ -n "${MSCONNECTOR_PRIVATE_SOCKET_ROOT:-}" ]; then
    set -- "$@" --require-private-mode
fi
if ! "$PYTHON_BIN" "$HELPER" "$@"; then
    echo "envoy_start_smoke: FAIL - private socket root is unsafe" >&2
    exit 1
fi
if [ -L "$PRIVATE_SOCKET_DIR" ]; then
    echo "envoy_start_smoke: FAIL - private response-observer directory must not be a symlink" >&2
    exit 1
fi
if [ ! -d "$PRIVATE_SOCKET_DIR" ]; then
    (umask 077 && mkdir "$PRIVATE_SOCKET_DIR") || {
        echo "envoy_start_smoke: FAIL - could not create private response-observer directory" >&2
        exit 1
    }
fi
chmod 700 "$PRIVATE_SOCKET_DIR" || {
    echo "envoy_start_smoke: FAIL - private response-observer directory must be owner-only" >&2
    exit 1
}
if [ "${#RESPONSE_OBSERVER_SOCKET}" -ge 108 ] || [ "${#COMPANION_SOCKET}" -ge 108 ]; then
    echo "envoy_start_smoke: FAIL - private response-observer socket path is too long" >&2
    exit 1
fi

set -- $("$PYTHON_BIN" "$HELPER" free-ports --count 4)
listen_port=${ENVOY_SMOKE_PORT:-$1}
upstream_port=${ENVOY_UPSTREAM_PORT:-$2}
authz_port=${ENVOY_AUTHZ_PORT:-$3}
admin_port=${ENVOY_ADMIN_PORT:-$4}
base_id=$(((listen_port + admin_port) % 100000))

command -v openssl >/dev/null 2>&1 || missing_dependency "openssl is required for the private loopback TLS certificate"
if ! create_private_loopback_tls "$TLS_CERTIFICATE" "$TLS_PRIVATE_KEY"; then
    echo "envoy_start_smoke: FAIL - could not create the private loopback TLS certificate" >&2
    exit 1
fi

set +e
TLS_CERTIFICATE_ESCAPED=$(render_yaml_path_for_sed_replacement "$TLS_CERTIFICATE")
TLS_CERTIFICATE_RENDER_STATUS=$?
set -e
if [ "$TLS_CERTIFICATE_RENDER_STATUS" -ne 0 ]; then
    echo "envoy_start_smoke: FAIL - TLS certificate path contains an unsupported control character" >&2
    exit 1
fi
set +e
TLS_PRIVATE_KEY_ESCAPED=$(render_yaml_path_for_sed_replacement "$TLS_PRIVATE_KEY")
TLS_PRIVATE_KEY_RENDER_STATUS=$?
set -e
if [ "$TLS_PRIVATE_KEY_RENDER_STATUS" -ne 0 ]; then
    echo "envoy_start_smoke: FAIL - TLS private key path contains an unsupported control character" >&2
    exit 1
fi

sed \
    -e "s|@LISTEN_PORT@|$listen_port|g" \
    -e "s|@UPSTREAM_PORT@|$upstream_port|g" \
    -e "s|@AUTHZ_PORT@|$authz_port|g" \
    -e "s|@ADMIN_PORT@|$admin_port|g" \
    -e "s|@RESPONSE_OBSERVER_SOCKET@|$RESPONSE_OBSERVER_SOCKET|g" \
    -e "s|@TLS_CERTIFICATE@|$TLS_CERTIFICATE_ESCAPED|g" \
    -e "s|@TLS_PRIVATE_KEY@|$TLS_PRIVATE_KEY_ESCAPED|g" \
    "$YAML_TEMPLATE" > "$ENVOY_CONFIG"

SERVICE_BIN="$SERVICE_BIN" BUILD_ROOT="$BUILD_ROOT" CONFIG_FILE="$CONFIG_FILE" \
    RULES_FILE="$RULES_FILE" EVENT_LOG_PATH="$EVENT_LOG_PATH" \
    sh "$CONNECTOR_DIR/config/check_envoy_config.sh"

if ! "$ENVOY_BIN" --mode validate -c "$ENVOY_CONFIG" \
    --base-id "$base_id" --disable-hot-restart >"$START_ROOT/envoy-validate.stdout.log" \
    2>"$START_ROOT/envoy-validate.stderr.log"; then
    echo "envoy_start_smoke: FAIL - Envoy rejected generated config" >&2
    sed -n "$SED_LOG_RANGE" "$START_ROOT/envoy-validate.stderr.log" >&2 || true
    exit 1
fi

"$RESPONSE_OBSERVER_BIN" --listen "$RESPONSE_OBSERVER_SOCKET" \
    --socket "$COMPANION_SOCKET" >"$OBSERVER_STDOUT" 2>"$OBSERVER_STDERR" &
observer_pid=$!
attempt=0
while [ "$attempt" -lt 20 ] && [ ! -S "$RESPONSE_OBSERVER_SOCKET" ]; do
    attempt=$((attempt + 1))
    if ! kill -0 "$observer_pid" 2>/dev/null; then
        echo "envoy_start_smoke: FAIL - response observer exited before socket readiness" >&2
        sed -n "$SED_LOG_RANGE" "$OBSERVER_STDERR" >&2 || true
        exit 1
    fi
    sleep 0.1
done
if [ ! -S "$RESPONSE_OBSERVER_SOCKET" ]; then
    echo "envoy_start_smoke: FAIL - response observer private socket was not created" >&2
    exit 1
fi

SERVICE_BIN="$SERVICE_BIN" BUILD_ROOT="$BUILD_ROOT" CONFIG_FILE="$CONFIG_FILE" \
    RULES_FILE="$RULES_FILE" EVENT_LOG_PATH="$EVENT_LOG_PATH" \
    MSCONNECTOR_ENVOY_EXT_AUTHZ_COMPANION_SOCKET="$COMPANION_SOCKET" \
    LISTEN_ADDRESS=127.0.0.1 LISTEN_PORT="$authz_port" \
    sh "$SCRIPT_DIR/serve_envoy_connector.sh" >"$SERVICE_STDOUT" 2>"$SERVICE_STDERR" &
service_pid=$!

"$ENVOY_BIN" -c "$ENVOY_CONFIG" --base-id "$base_id" --disable-hot-restart \
    --log-level error >"$ENVOY_STDOUT" 2>"$ENVOY_STDERR" &
envoy_pid=$!

sleep 1
if ! kill -0 "$service_pid" 2>/dev/null; then
    echo "envoy_start_smoke: FAIL - connector service exited before liveness check" >&2
    sed -n "$SED_LOG_RANGE" "$SERVICE_STDERR" >&2 || true
    exit 1
fi
if ! kill -0 "$observer_pid" 2>/dev/null; then
    echo "envoy_start_smoke: FAIL - response observer exited before liveness check" >&2
    sed -n "$SED_LOG_RANGE" "$OBSERVER_STDERR" >&2 || true
    exit 1
fi
if ! kill -0 "$envoy_pid" 2>/dev/null; then
    echo "envoy_start_smoke: FAIL - Envoy exited before liveness check" >&2
    sed -n "$SED_LOG_RANGE" "$ENVOY_STDERR" >&2 || true
    exit 1
fi

{
    printf 'connector_config_check=pass\n'
    printf 'envoy_config_validate=pass\n'
    printf 'service_process_started=yes\n'
    printf 'service_pid=%s\n' "$service_pid"
    printf 'response_observer_process_started=yes\n'
    printf 'response_observer_pid=%s\n' "$observer_pid"
    printf 'response_observer_socket=%s\n' "$RESPONSE_OBSERVER_SOCKET"
    printf 'envoy_process_started=yes\n'
    printf 'envoy_pid=%s\n' "$envoy_pid"
    printf 'envoy_listen=127.0.0.1:%s\n' "$listen_port"
    printf 'authz_listen=127.0.0.1:%s\n' "$authz_port"
    printf 'downstream_transport=tls_loopback\n'
    printf 'requests_sent=no\n'
} > "$SUMMARY"

cleanup
envoy_pid=
service_pid=
observer_pid=
trap - EXIT HUP INT TERM
printf 'service_process_stopped=yes\n' >> "$SUMMARY"
printf 'envoy_process_stopped=yes\n' >> "$SUMMARY"
printf 'response_observer_process_stopped=yes\n' >> "$SUMMARY"
printf 'envoy_start_smoke: pass summary=%s\n' "$SUMMARY"
