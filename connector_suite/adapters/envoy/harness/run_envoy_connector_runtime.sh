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
EXPECTED_RULE_ID=${MSCONNECTOR_EXPECTED_RULE_ID:-1000001}
RESPONSE_PHASE_SMOKE=${MSCONNECTOR_RESPONSE_PHASE_SMOKE:-0}
P3_RULE_ID=${MSCONNECTOR_P3_RULE_ID:-1000003}
P4_RULE_ID=${MSCONNECTOR_P4_RULE_ID:-1000004}
P3_TRANSACTION_ID=envoy-p3-block-1
P4_TRANSACTION_ID=envoy-p4-safe-1
RUNTIME_ROOT=${RUNTIME_ROOT:-${RUNNER_TEMP:-${TMPDIR:-/var/tmp}}/ModSecurity-conector-envoy-runtime-smoke}
EVENT_LOG_PATH=${EVENT_LOG_PATH:-$RUNTIME_ROOT/events.jsonl}
PYTHON_BIN=${PYTHON:-python3}
HELPER="$SCRIPT_DIR/envoy_smoke_helper.py"
TLS_RENDERER="$CONNECTOR_DIR/config/lib/tls_yaml_render.sh"
YAML_TEMPLATE="${TEST_ROOT:?TEST_ROOT is required explicitly}/connector_suite/adapters/envoy/config/envoy-ext-authz-smoke.yaml.in"
NO_CRS_SELECTION_CONSUMER="$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/lifecycle/consume-no-crs-selected-cases.sh"
ENVOY_CONFIG="$RUNTIME_ROOT/envoy.yaml"
SUMMARY="$RUNTIME_ROOT/runtime-summary.txt"
ALLOW_PROBE="$RUNTIME_ROOT/allow-client.json"
DENY_PROBE="$RUNTIME_ROOT/deny-client.json"
SED_LOG_RANGE='1,160p'
ENVOY_STDOUT="$RUNTIME_ROOT/envoy.stdout.log"
ENVOY_STDERR="$RUNTIME_ROOT/envoy.stderr.log"
SERVICE_STDOUT="$RUNTIME_ROOT/service.stdout.log"
SERVICE_STDERR="$RUNTIME_ROOT/service.stderr.log"
UPSTREAM_STDOUT="$RUNTIME_ROOT/upstream.stdout.log"
UPSTREAM_STDERR="$RUNTIME_ROOT/upstream.stderr.log"
TLS_CERTIFICATE="$RUNTIME_ROOT/envoy-loopback.crt"
TLS_PRIVATE_KEY="$RUNTIME_ROOT/envoy-loopback.key"
PRIVATE_SOCKET_DIR=${MSCONNECTOR_PRIVATE_SOCKET_ROOT:-$RUNTIME_ROOT/mrc}
RESPONSE_OBSERVER_SOCKET="$PRIVATE_SOCKET_DIR/envoy-response-observer.sock"
COMPANION_SOCKET="$PRIVATE_SOCKET_DIR/envoy-ext-authz-companion.sock"
OBSERVER_STDOUT="$RUNTIME_ROOT/response-observer.stdout.log"
OBSERVER_STDERR="$RUNTIME_ROOT/response-observer.stderr.log"
envoy_pid=
service_pid=
upstream_pid=
observer_pid=

missing_dependency() {
    reason=$1
    echo "envoy_runtime_smoke: BLOCKED - $reason" >&2
    exit 77
}

cleanup() {
    for pid in "$envoy_pid" "$service_pid" "$upstream_pid" "$observer_pid"; do
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    for pid in "$envoy_pid" "$service_pid" "$upstream_pid" "$observer_pid"; do
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
[ -f "$RULES_FILE" ] || missing_dependency "rules file is missing: $RULES_FILE"
[ -f "$YAML_TEMPLATE" ] || missing_dependency "Envoy config template is missing: $YAML_TEMPLATE"
[ -f "$HELPER" ] || missing_dependency "smoke helper is missing: $HELPER"
[ -f "$TLS_RENDERER" ] || missing_dependency "TLS YAML renderer is missing: $TLS_RENDERER"
command -v "$PYTHON_BIN" >/dev/null 2>&1 || missing_dependency "Python interpreter is missing: $PYTHON_BIN"
case "$RESPONSE_PHASE_SMOKE" in
    0|1) ;;
    *) echo "envoy_runtime_smoke: FAIL - MSCONNECTOR_RESPONSE_PHASE_SMOKE must be 0 or 1" >&2; exit 1 ;;
esac
. "$TLS_RENDERER"

if [ "${MSCONNECTOR_NO_CRS_BASELINE:-0}" = "1" ]; then
    [ -x "$NO_CRS_SELECTION_CONSUMER" ] || missing_dependency "No-CRS selected-case consumer is missing: $NO_CRS_SELECTION_CONSUMER"
    "$NO_CRS_SELECTION_CONSUMER" envoy
fi

case "$RUNTIME_ROOT" in
    /*) ;;
    *) echo "envoy_runtime_smoke: FAIL - RUNTIME_ROOT must be absolute" >&2; exit 1 ;;
esac
case "$RUNTIME_ROOT" in
    "$REPO_ROOT"|"$REPO_ROOT"/*)
        echo "envoy_runtime_smoke: FAIL - RUNTIME_ROOT must not be inside the checkout" >&2
        exit 1
        ;;
    *) ;;
esac
if ! "$PYTHON_BIN" "$HELPER" prepare-runtime-root --runtime-root "$RUNTIME_ROOT"; then
    echo "envoy_runtime_smoke: FAIL - RUNTIME_ROOT is unsafe for private runtime artifacts" >&2
    exit 1
fi
trap cleanup EXIT HUP INT TERM
case "$EVENT_LOG_PATH" in
    "$RUNTIME_ROOT"/*) ;;
    *)
        echo "envoy_runtime_smoke: FAIL - EVENT_LOG_PATH must be under RUNTIME_ROOT" >&2
        exit 1
        ;;
esac
rm -f "$EVENT_LOG_PATH" "$SUMMARY" "$TLS_CERTIFICATE" "$TLS_PRIVATE_KEY"
set -- prepare-runtime-root --runtime-root "$PRIVATE_SOCKET_DIR"
if [ -n "${MSCONNECTOR_PRIVATE_SOCKET_ROOT:-}" ]; then
    set -- "$@" --require-private-mode
fi
if ! "$PYTHON_BIN" "$HELPER" "$@"; then
    echo "envoy_runtime_smoke: FAIL - private socket root is unsafe" >&2
    exit 1
fi
if [ -L "$PRIVATE_SOCKET_DIR" ]; then
    echo "envoy_runtime_smoke: FAIL - private response-observer directory must not be a symlink" >&2
    exit 1
fi
if [ ! -d "$PRIVATE_SOCKET_DIR" ]; then
    (umask 077 && mkdir "$PRIVATE_SOCKET_DIR") || {
        echo "envoy_runtime_smoke: FAIL - could not create private response-observer directory" >&2
        exit 1
    }
fi
chmod 700 "$PRIVATE_SOCKET_DIR" || {
    echo "envoy_runtime_smoke: FAIL - private response-observer directory must be owner-only" >&2
    exit 1
}
if [ "${#RESPONSE_OBSERVER_SOCKET}" -ge 108 ] || [ "${#COMPANION_SOCKET}" -ge 108 ]; then
    echo "envoy_runtime_smoke: FAIL - private response-observer socket path is too long" >&2
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
    echo "envoy_runtime_smoke: FAIL - could not create the private loopback TLS certificate" >&2
    exit 1
fi

set +e
TLS_CERTIFICATE_ESCAPED=$(render_yaml_path_for_sed_replacement "$TLS_CERTIFICATE")
TLS_CERTIFICATE_RENDER_STATUS=$?
set -e
if [ "$TLS_CERTIFICATE_RENDER_STATUS" -ne 0 ]; then
    echo "envoy_runtime_smoke: FAIL - TLS certificate path contains an unsupported control character" >&2
    exit 1
fi
set +e
TLS_PRIVATE_KEY_ESCAPED=$(render_yaml_path_for_sed_replacement "$TLS_PRIVATE_KEY")
TLS_PRIVATE_KEY_RENDER_STATUS=$?
set -e
if [ "$TLS_PRIVATE_KEY_RENDER_STATUS" -ne 0 ]; then
    echo "envoy_runtime_smoke: FAIL - TLS private key path contains an unsupported control character" >&2
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
    --base-id "$base_id" --disable-hot-restart >"$RUNTIME_ROOT/envoy-validate.stdout.log" \
    2>"$RUNTIME_ROOT/envoy-validate.stderr.log"; then
    echo "envoy_runtime_smoke: FAIL - Envoy rejected generated config" >&2
    sed -n "$SED_LOG_RANGE" "$RUNTIME_ROOT/envoy-validate.stderr.log" >&2 || true
    exit 1
fi

"$RESPONSE_OBSERVER_BIN" --listen "$RESPONSE_OBSERVER_SOCKET" \
    --socket "$COMPANION_SOCKET" >"$OBSERVER_STDOUT" 2>"$OBSERVER_STDERR" &
observer_pid=$!
attempt=0
while [ "$attempt" -lt 20 ] && [ ! -S "$RESPONSE_OBSERVER_SOCKET" ]; do
    attempt=$((attempt + 1))
    if ! kill -0 "$observer_pid" 2>/dev/null; then
        echo "envoy_runtime_smoke: FAIL - response observer exited before socket readiness" >&2
        sed -n "$SED_LOG_RANGE" "$OBSERVER_STDERR" >&2 || true
        exit 1
    fi
    sleep 0.1
done
if [ ! -S "$RESPONSE_OBSERVER_SOCKET" ]; then
    echo "envoy_runtime_smoke: FAIL - response observer private socket was not created" >&2
    exit 1
fi

"$PYTHON_BIN" "$HELPER" serve-upstream --port "$upstream_port" \
    --runtime-root "$RUNTIME_ROOT" \
    --tls-certificate "$TLS_CERTIFICATE" \
    --tls-private-key "$TLS_PRIVATE_KEY" \
    >"$UPSTREAM_STDOUT" 2>"$UPSTREAM_STDERR" &
upstream_pid=$!

SERVICE_BIN="$SERVICE_BIN" BUILD_ROOT="$BUILD_ROOT" CONFIG_FILE="$CONFIG_FILE" \
    RULES_FILE="$RULES_FILE" EVENT_LOG_PATH="$EVENT_LOG_PATH" \
    MSCONNECTOR_ENVOY_EXT_AUTHZ_COMPANION_SOCKET="$COMPANION_SOCKET" \
    LISTEN_ADDRESS=127.0.0.1 LISTEN_PORT="$authz_port" \
    sh "$SCRIPT_DIR/serve_envoy_connector.sh" >"$SERVICE_STDOUT" 2>"$SERVICE_STDERR" &
service_pid=$!

"$ENVOY_BIN" -c "$ENVOY_CONFIG" --base-id "$base_id" --disable-hot-restart \
    --log-level error >"$ENVOY_STDOUT" 2>"$ENVOY_STDERR" &
envoy_pid=$!

allowed_status=
attempt=0
while [ "$attempt" -lt 30 ]; do
    attempt=$((attempt + 1))
    for process_pair in "envoy:$envoy_pid" "service:$service_pid" "upstream:$upstream_pid" "response-observer:$observer_pid"; do
        process_name=${process_pair%%:*}
        process_id=${process_pair##*:}
        if ! kill -0 "$process_id" 2>/dev/null; then
            echo "envoy_runtime_smoke: FAIL - $process_name process exited early" >&2
            sed -n "$SED_LOG_RANGE" "$ENVOY_STDERR" >&2 || true
            sed -n "$SED_LOG_RANGE" "$SERVICE_STDERR" >&2 || true
            exit 1
        fi
    done
    set +e
    allowed_status=$("$PYTHON_BIN" "$HELPER" probe \
        --runtime-root "$RUNTIME_ROOT" --tls-certificate "$TLS_CERTIFICATE" \
        --url "https://127.0.0.1:$listen_port/allowed" \
        --evidence-path "$ALLOW_PROBE" \
        --header "X-Request-Id: envoy-allow-1" \
        --forbid-response-header x-msconnector-terminal-authz 2>/dev/null)
    probe_rc=$?
    set -e
    if [ "$probe_rc" -eq 0 ] && [ "$allowed_status" = "200" ]; then
        break
    fi
    sleep 1
done

if [ "$allowed_status" != "200" ]; then
    echo "envoy_runtime_smoke: FAIL - allowed request returned ${allowed_status:-no status}, expected 200" >&2
    exit 1
fi

if ! blocked_status=$("$PYTHON_BIN" "$HELPER" probe \
    --runtime-root "$RUNTIME_ROOT" --tls-certificate "$TLS_CERTIFICATE" \
    --url "https://127.0.0.1:$listen_port/blocked" \
    --evidence-path "$DENY_PROBE" \
    --header "X-Request-Id: envoy-block-1" \
    --header "X-Modsec-Smoke: block" \
    --forbid-response-header x-msconnector-terminal-authz); then
    echo "envoy_runtime_smoke: FAIL - blocked request could not be completed" >&2
    exit 1
fi
if [ "$blocked_status" != "403" ]; then
    echo "envoy_runtime_smoke: FAIL - blocked request returned $blocked_status, expected 403" >&2
    exit 1
fi
if [ "$RESPONSE_PHASE_SMOKE" = "1" ]; then
    if ! p3_status=$("$PYTHON_BIN" "$HELPER" probe \
        --runtime-root "$RUNTIME_ROOT" --tls-certificate "$TLS_CERTIFICATE" \
        --url "https://127.0.0.1:$listen_port/phase3-block" \
        --header "X-Request-Id: $P3_TRANSACTION_ID" \
        --forbid-response-header x-msconnector-terminal-authz); then
        echo "envoy_runtime_smoke: FAIL - P3 response probe could not be completed" >&2
        exit 1
    fi
    if [ "$p3_status" != "403" ]; then
        echo "envoy_runtime_smoke: FAIL - P3 response probe returned $p3_status, expected 403" >&2
        exit 1
    fi
    if ! p4_status=$("$PYTHON_BIN" "$HELPER" probe \
        --runtime-root "$RUNTIME_ROOT" --tls-certificate "$TLS_CERTIFICATE" \
        --url "https://127.0.0.1:$listen_port/phase4-marker" \
        --header "X-Request-Id: $P4_TRANSACTION_ID" \
        --forbid-response-header x-msconnector-terminal-authz); then
        echo "envoy_runtime_smoke: FAIL - P4 response probe could not be completed" >&2
        exit 1
    fi
    if [ "$p4_status" != "200" ]; then
        echo "envoy_runtime_smoke: FAIL - P4 Safe response probe returned $p4_status, expected 200" >&2
        exit 1
    fi
fi
if [ ! -s "$EVENT_LOG_PATH" ]; then
    echo "envoy_runtime_smoke: FAIL - metadata event log was not produced: $EVENT_LOG_PATH" >&2
    exit 1
fi
if ! grep -q "\"rule_id\":\"$EXPECTED_RULE_ID\"" "$EVENT_LOG_PATH" ||
    ! grep -q '"transaction_id":"envoy-block-1"' "$EVENT_LOG_PATH"; then
    echo "envoy_runtime_smoke: FAIL - event log lacks rule/transaction evidence" >&2
    exit 1
fi
if [ "$RESPONSE_PHASE_SMOKE" = "1" ] && ! "$PYTHON_BIN" "$HELPER" verify-response-phase-events \
        --runtime-root "$RUNTIME_ROOT" --event-log "$EVENT_LOG_PATH" \
        --p3-rule-id "$P3_RULE_ID" --p3-transaction-id "$P3_TRANSACTION_ID" \
        --p4-rule-id "$P4_RULE_ID" --p4-transaction-id "$P4_TRANSACTION_ID"; then
    echo "envoy_runtime_smoke: FAIL - metadata event log lacks validated P3/P4 evidence" >&2
    exit 1
fi
for process_pair in "envoy:$envoy_pid" "service:$service_pid" "upstream:$upstream_pid" "response-observer:$observer_pid"; do
    process_name=${process_pair%%:*}
    process_id=${process_pair##*:}
    if ! kill -0 "$process_id" 2>/dev/null; then
        echo "envoy_runtime_smoke: FAIL - $process_name was not stable after requests" >&2
        exit 1
    fi
done

{
    printf 'status=PASS\n'
    printf 'integration_mode=ext_authz\n'
    printf 'allowed_request_status=%s\n' "$allowed_status"
    printf 'blocked_request_status=%s\n' "$blocked_status"
    printf 'rule_id=%s\n' "$EXPECTED_RULE_ID"
    printf 'event_log=%s\n' "$EVENT_LOG_PATH"
    printf 'envoy_config=%s\n' "$ENVOY_CONFIG"
    printf 'response_observer_socket=%s\n' "$RESPONSE_OBSERVER_SOCKET"
    printf 'response_observer_started=yes\n'
    printf 'terminal_authz_marker_stripped=yes\n'
    printf 'response_phase_smoke=%s\n' "$RESPONSE_PHASE_SMOKE"
    if [ "$RESPONSE_PHASE_SMOKE" = "1" ]; then
        printf 'p3_response_status=%s\n' "$p3_status"
    printf 'p4_safe_response_status=%s\n' "$p4_status"
    fi
    printf 'downstream_transport=tls_loopback\n'
    # The companion validates P3/P4 metadata events, but ext_authz itself
    # cannot truthfully claim host-owned response-body enforcement.
    printf 'response_body_verified=false\n'
    if [ "$RESPONSE_PHASE_SMOKE" = "1" ]; then
        printf 'response_phase_events_verified=true\n'
    else
        printf 'response_phase_events_verified=false\n'
    fi
    printf 'production_ready=false\n'
} > "$SUMMARY"

cleanup
envoy_pid=
service_pid=
upstream_pid=
observer_pid=
trap - EXIT HUP INT TERM
printf 'processes_stopped=yes\n' >> "$SUMMARY"
printf 'envoy_runtime_smoke: pass summary=%s\n' "$SUMMARY"
