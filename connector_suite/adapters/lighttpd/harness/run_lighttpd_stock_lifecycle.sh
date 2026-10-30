#!/bin/sh
set -euC

# Bounded Stock-only lifecycle run.  The host/module pair is checked before
# startup and the Linux guard owns process-session containment and cleanup.
# This profile exercises Stock transport lifecycles plus the Stock header ABI;
# it never promotes transport closes into patched stream events.
SCRIPT_DIR=$(CDPATH='' cd "$(dirname "$0")" && pwd)
LINUX_GUARD=$SCRIPT_DIR/lighttpd_backend_close_linux_guard.py
BACKEND_PROBE=$SCRIPT_DIR/lighttpd_backend_close_probe.py
LIFECYCLE_PROBE=$SCRIPT_DIR/lighttpd_stock_lifecycle_probe.py
BUILD_ROOT=${BUILD_ROOT:-${XDG_STATE_HOME:-${HOME:-/tmp}/.local/state}/ModSecurity-conector-build}
RUNTIME_ROOT=${RUNTIME_ROOT:-$BUILD_ROOT/lighttpd-stock-lifecycle}
HOST_BINARY=${LIGHTTPD_BIN:-}
MODULE_PATH=${LIGHTTPD_CONNECTOR_MODULE:-}
RULES_FILE=${LIGHTTPD_STOCK_LIFECYCLE_RULES_FILE:-}
FRONTEND_PORT=${LIGHTTPD_STOCK_LIFECYCLE_FRONTEND_PORT:-}
UPSTREAM_PORT=${LIGHTTPD_STOCK_LIFECYCLE_UPSTREAM_PORT:-}
TIMEOUT=${LIGHTTPD_STOCK_LIFECYCLE_TIMEOUT:-5}
CLEANUP_TIMEOUT=${LIGHTTPD_STOCK_LIFECYCLE_CLEANUP_TIMEOUT:-5}
BACKEND_READ_TIMEOUT=${LIGHTTPD_STOCK_LIFECYCLE_BACKEND_READ_TIMEOUT:-2}
MODULE_DIR=
CONFIG_PID=
CONFIG_START_TIME=
CONFIG_SESSION=
SERVER_PID=
SERVER_START_TIME=
SERVER_SESSION=
SERVER_START_ATTEMPTED=0
CLEANUP_ACTIVE=0
CLEANUP_STATUS=1

blocked() {
    blocked_message=$1
    printf 'lighttpd_stock_lifecycle: BLOCKED: %s\n' "$blocked_message" >&2
    exit 77
}
fail() {
    failure_message=$1
    printf 'lighttpd_stock_lifecycle: FAIL: %s\n' "$failure_message" >&2
    exit 1
}

[ -f "$LINUX_GUARD" ] || blocked "Linux cleanup guard is missing"
[ -f "$BACKEND_PROBE" ] || blocked "backend-close probe is missing"
[ -f "$LIFECYCLE_PROBE" ] || blocked "Stock lifecycle probe is missing"
[ -n "$HOST_BINARY" ] || blocked "LIGHTTPD_BIN is required"
[ -n "$MODULE_PATH" ] || blocked "LIGHTTPD_CONNECTOR_MODULE is required"
[ -n "$RULES_FILE" ] || blocked "LIGHTTPD_STOCK_LIFECYCLE_RULES_FILE is required"
[ -f "$HOST_BINARY" ] && [ -x "$HOST_BINARY" ] || blocked "host must be an executable regular file"
[ -f "$MODULE_PATH" ] || blocked "connector module must be a regular file"
[ -f "$RULES_FILE" ] || blocked "rules file must be a regular file"
python3 "$LINUX_GUARD" check-pidfd >/dev/null || blocked "usable Linux pidfd capability is required"

case "$RUNTIME_ROOT" in /*) : ;; *) blocked "RUNTIME_ROOT must be absolute" ;; esac
case "$FRONTEND_PORT" in ''|*[!0-9]*) blocked "fresh frontend port is required and must be numeric" ;; *) : ;; esac
case "$UPSTREAM_PORT" in ''|*[!0-9]*) blocked "fresh upstream port is required and must be numeric" ;; *) : ;; esac
case "$TIMEOUT:$CLEANUP_TIMEOUT" in *[!0-9:]*) blocked "timeouts must be numeric" ;; *) : ;; esac
[ "$TIMEOUT" -ge 1 ] && [ "$TIMEOUT" -le 30 ] || blocked "timeout must be between 1 and 30 seconds"
[ "$CLEANUP_TIMEOUT" -ge 1 ] && [ "$CLEANUP_TIMEOUT" -le 30 ] || blocked "cleanup timeout must be between 1 and 30 seconds"
case "$BACKEND_READ_TIMEOUT" in ''|*[!0-9]*) blocked "backend read timeout must be numeric" ;; *) : ;; esac
[ "$BACKEND_READ_TIMEOUT" -ge 1 ] && [ "$BACKEND_READ_TIMEOUT" -le 30 ] || blocked "backend read timeout must be between 1 and 30 seconds"
[ "$BACKEND_READ_TIMEOUT" -lt "$TIMEOUT" ] || blocked "backend read timeout must be below the overall probe timeout"

HOST_BINARY=$(readlink -f -- "$HOST_BINARY")
MODULE_PATH=$(readlink -f -- "$MODULE_PATH")
RULES_FILE=$(readlink -f -- "$RULES_FILE")
[ -f "$HOST_BINARY" ] && [ -x "$HOST_BINARY" ] || blocked "resolved host is not executable"
[ "$(basename "$MODULE_PATH")" = mod_msconnector.so ] || blocked "module basename must be mod_msconnector.so"
[ -f "$MODULE_PATH" ] && [ -f "$RULES_FILE" ] || blocked "resolved module or rules file is missing"
MODULE_DIR=$(CDPATH='' cd "$(dirname "$MODULE_PATH")" && pwd -P)
[ -f "$MODULE_DIR/mod_proxy.so" ] || blocked "Stock proxy module is missing beside resolved connector module"

RUNTIME_PARENT=$(CDPATH='' cd "$(dirname "$RUNTIME_ROOT")" 2>/dev/null && pwd -P) || blocked "runtime parent unavailable"
RUNTIME_ROOT=$RUNTIME_PARENT/$(basename "$RUNTIME_ROOT")
[ ! -e "$RUNTIME_ROOT" ] && [ ! -L "$RUNTIME_ROOT" ] || blocked "RUNTIME_ROOT must be fresh and non-symlink"
umask 077
mkdir "$RUNTIME_ROOT" || blocked "could not create private runtime root"
[ "$(stat -c '%a' "$RUNTIME_ROOT")" = 700 ] || chmod 700 "$RUNTIME_ROOT"
export MSCONNECTOR_TRUSTED_RUNTIME_ROOT="$RUNTIME_ROOT"

python3 - "$FRONTEND_PORT" "$UPSTREAM_PORT" <<'PY'
import socket
import sys
for raw in sys.argv[1:]:
    port = int(raw)
    if not 1024 <= port <= 65535:
        raise SystemExit("port outside the unprivileged range")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", port))
PY

python3 "$LINUX_GUARD" write-config --root "$RUNTIME_ROOT" --rules-file "$RULES_FILE" \
    --frontend-port "$FRONTEND_PORT" --upstream-port "$UPSTREAM_PORT" \
    --backend-read-timeout "$BACKEND_READ_TIMEOUT" >/dev/null || \
    fail "could not write Stock runtime configuration"
# The guard's shared backend-close config selects streaming to serve the
# patched profile.  Stock must reject that ABI mode, so make the generated
# task-local runtime config explicitly Stock-compatible before validation.
sed -i 's/^response_body_mode=streaming$/response_body_mode=none/' \
    "$RUNTIME_ROOT/msconnector-runtime.conf"
grep -Fqx 'response_body_mode=none' "$RUNTIME_ROOT/msconnector-runtime.conf" || \
    fail "Stock runtime config did not disable response bodies"

HOST_SHA256=$(sha256sum "$HOST_BINARY" | awk '{print $1}')
MODULE_SHA256=$(sha256sum "$MODULE_PATH" | awk '{print $1}')
RULES_SHA256=$(sha256sum "$RULES_FILE" | awk '{print $1}')
PROVENANCE=$RUNTIME_ROOT/stock-provenance.txt
RECEIPT=$RUNTIME_ROOT/raw-receipt.json
CONFIG_SESSION_RECORD=$RUNTIME_ROOT/config-session.json
SERVER_SESSION_RECORD=$RUNTIME_ROOT/server-session.json
CONFIG_CLEANUP_RECEIPT=$RUNTIME_ROOT/config-cleanup.json
SERVER_CLEANUP_RECEIPT=$RUNTIME_ROOT/server-cleanup.json
V6_RECEIPT=$RUNTIME_ROOT/v6-client-abort.json
V6_TIMEOUT_RECEIPT=$RUNTIME_ROOT/v6-host-timeout.json
V6_CONTROL_RECEIPT=$RUNTIME_ROOT/v6-follow-up.json
V9_RECEIPT=$RUNTIME_ROOT/v9-parallel.json
V10_READY=$RUNTIME_ROOT/v10-ready.json
V10_RELEASE=$RUNTIME_ROOT/v10-release.json
V10_RECEIPT=$RUNTIME_ROOT/v10-host-termination.json
V10_PROBE_SESSION_RECORD=$RUNTIME_ROOT/v10-probe-session.json
V10_PROBE_CLEANUP_RECEIPT=$RUNTIME_ROOT/v10-probe-cleanup.json
V10_PROBE_SESSION=
V10_PROBE_START_TIME=
PYTHON_BINARY=$(readlink -f -- "$(command -v python3)")

{
    printf 'profile=stock-native-lighttpd\n'
    printf 'host_binary=%s\n' "$HOST_BINARY"
    printf 'host_sha256=%s\n' "$HOST_SHA256"
    printf 'connector_module=%s\n' "$MODULE_PATH"
    printf 'connector_module_sha256=%s\n' "$MODULE_SHA256"
    printf 'rules_file=%s\n' "$RULES_FILE"
    printf 'rules_sha256=%s\n' "$RULES_SHA256"
    printf 'integration_mode=native-lighttpd-plugin\n'
    printf 'backend_close_vectors=V7,V11-incomplete-response\n'
    printf 'follow_up=allow-200,block-403,allow-200\n'
    printf 'cleanup=pidfd-session,process,port,uds\n'
    printf 'backend_read_timeout=%s\n' "$BACKEND_READ_TIMEOUT"
    printf 'lifecycle_vectors=V6-client-abort,V9-bounded-parallel,V10-verified-host-termination\n'
    printf 'not_executed=V12,V13,V14,V15\n'
} > "$PROVENANCE"

proc_start_time() {
    proc_pid=$1
    proc_stat=$(cat "/proc/$proc_pid/stat" 2>/dev/null) || return 1
    proc_stat=${proc_stat#*)}
    printf '%s\n' "$proc_stat" | awk '{print $20}'
}

pid_alive() {
    pid=${1:-}
    [ -n "$pid" ] && [ -e "/proc/$pid/stat" ] && [ "$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null)" != Z ]
}

cleanup_process() {
    cleanup_record=$1
    cleanup_receipt=$2
    cleanup_status=0
    if [ -f "$cleanup_record" ]; then
        python3 "$LINUX_GUARD" cleanup-session --session-record "$cleanup_record" \
            --leader-exe "$HOST_BINARY" --timeout-seconds "$CLEANUP_TIMEOUT" \
            --output "$cleanup_receipt" --reject-unexpected-members >/dev/null || cleanup_status=1
    fi
    return "$cleanup_status"
}

cleanup_unregistered_process() {
    unregistered_pid=$1
    unregistered_start_time=$2
    unregistered_exe=$3
    [ -n "$unregistered_pid" ] && [ -n "$unregistered_start_time" ] || return 1
    unregistered_status=0
    python3 "$LINUX_GUARD" terminate-unregistered \
        --pid "$unregistered_pid" --start-time "$unregistered_start_time" --exe "$unregistered_exe" \
        --timeout-seconds "$CLEANUP_TIMEOUT" >/dev/null || unregistered_status=$?
    # EXITED means the identity-verified leader was already gone; the caller
    # still verifies session, port, and artifact absence below.
    [ "$unregistered_status" -eq 0 ] || [ "$unregistered_status" -eq 75 ]
}

cleanup() {
    [ "$CLEANUP_ACTIVE" -eq 0 ] || return "$CLEANUP_STATUS"
    CLEANUP_ACTIVE=1
    cleanup_status=0
    if [ -n "$V10_PROBE_SESSION" ]; then
        if [ -f "$V10_PROBE_SESSION_RECORD" ]; then
            cleanup_process "$V10_PROBE_SESSION_RECORD" "$V10_PROBE_CLEANUP_RECEIPT" || cleanup_status=1
        else
            cleanup_unregistered_process "$V10_PROBE_PID" "$V10_PROBE_START_TIME" "$PYTHON_BINARY" || cleanup_status=1
        fi
    fi
    if [ -n "$CONFIG_SESSION" ]; then
        if [ -f "$CONFIG_SESSION_RECORD" ]; then
            cleanup_process "$CONFIG_SESSION_RECORD" "$CONFIG_CLEANUP_RECEIPT" || cleanup_status=1
        else
            cleanup_unregistered_process "$CONFIG_PID" "$CONFIG_START_TIME" "$PYTHON_BINARY" || cleanup_status=1
        fi
    fi
    if [ "$SERVER_START_ATTEMPTED" -eq 1 ]; then
        if [ -f "$SERVER_SESSION_RECORD" ]; then
            cleanup_process "$SERVER_SESSION_RECORD" "$SERVER_CLEANUP_RECEIPT" || cleanup_status=1
        else
            # A signal can arrive after exec-session has created the unique
            # leader but before registration is published.  Contain that
            # bounded race through its recorded start-time/executable and
            # pidfd; never fall back to a numeric PID signal.
            cleanup_unregistered_process "$SERVER_PID" "$SERVER_START_TIME" "$PYTHON_BINARY" || cleanup_status=1
        fi
    fi
    if [ -n "$SERVER_SESSION" ]; then
        python3 "$LINUX_GUARD" assert-session-absent --session "$SERVER_SESSION" \
            --wait-seconds "$CLEANUP_TIMEOUT" >/dev/null || cleanup_status=1
    fi
    CLEANUP_STATUS=$cleanup_status
    return "$CLEANUP_STATUS"
}

cleanup_on_signal() {
    signal_name=$1
    cleanup_status=0
    cleanup || cleanup_status=$?
    trap - EXIT HUP INT TERM
    [ "$cleanup_status" -eq 0 ] || {
        printf 'lighttpd_stock_lifecycle: FAIL: cleanup failed on %s\n' "$signal_name" >&2
        exit "$cleanup_status"
    }
    exit 128
}

trap cleanup EXIT
trap 'cleanup_on_signal HUP' HUP
trap 'cleanup_on_signal INT' INT
trap 'cleanup_on_signal TERM' TERM

MSCONNECTOR_LIGHTTPD_SESSION_PROFILE=lighttpd-config-check \
MSCONNECTOR_LIGHTTPD_SESSION_EXECUTABLE="$HOST_BINARY" \
MSCONNECTOR_LIGHTTPD_SESSION_MODULE_DIR="$MODULE_DIR" \
MSCONNECTOR_LIGHTTPD_SESSION_CONFIG="$RUNTIME_ROOT/lighttpd.conf" \
MSCONNECTOR_LIGHTTPD_SESSION_PARENT_PID="$$" \
python3 "$LINUX_GUARD" exec-session --file-limit-blocks 128 \
    --session-record "$CONFIG_SESSION_RECORD" \
    >"$RUNTIME_ROOT/config-check.stdout" 2>"$RUNTIME_ROOT/config-check.stderr" &
CONFIG_PID=$!
CONFIG_SESSION=$CONFIG_PID
CONFIG_START_TIME=$(proc_start_time "$CONFIG_PID" 2>/dev/null || true)
wait "$CONFIG_PID" || CONFIG_STATUS=$?
[ "${CONFIG_STATUS:-0}" -eq 0 ] || fail "Stock config check failed"
python3 "$LINUX_GUARD" assert-session-absent --session "$CONFIG_SESSION" \
    --wait-seconds "$CLEANUP_TIMEOUT" >/dev/null || fail "config-check session remained"
CONFIG_PID=

SERVER_START_ATTEMPTED=1
MSCONNECTOR_LIGHTTPD_SESSION_PROFILE=lighttpd-server \
MSCONNECTOR_LIGHTTPD_SESSION_EXECUTABLE="$HOST_BINARY" \
MSCONNECTOR_LIGHTTPD_SESSION_MODULE_DIR="$MODULE_DIR" \
MSCONNECTOR_LIGHTTPD_SESSION_CONFIG="$RUNTIME_ROOT/lighttpd.conf" \
MSCONNECTOR_LIGHTTPD_SESSION_PARENT_PID="$$" \
python3 "$LINUX_GUARD" exec-session --file-limit-blocks 128 \
    --session-record "$SERVER_SESSION_RECORD" \
    >"$RUNTIME_ROOT/host.stdout" 2>"$RUNTIME_ROOT/host.stderr" &
SERVER_PID=$!
SERVER_SESSION=$SERVER_PID
SERVER_START_TIME=$(proc_start_time "$SERVER_PID" 2>/dev/null || true)
[ -n "$SERVER_START_TIME" ] || fail "could not record Stock host start time"

end=$(( $(date +%s) + CLEANUP_TIMEOUT ))
while [ "$(date +%s)" -lt "$end" ]; do
    if pid_alive "$SERVER_PID" && \
        python3 "$LINUX_GUARD" assert-listener --pid "$SERVER_PID" \
            --start-time "$SERVER_START_TIME" --exe "$HOST_BINARY" \
            --host 127.0.0.1 --port "$FRONTEND_PORT" >/dev/null 2>&1; then
        break
    fi
    sleep 0.05
done
python3 "$LINUX_GUARD" assert-listener --pid "$SERVER_PID" --start-time "$SERVER_START_TIME" \
    --exe "$HOST_BINARY" --host 127.0.0.1 --port "$FRONTEND_PORT" >/dev/null || \
    fail "Stock host did not reach an owned listener"

# Stock cannot emit the patched stream callback.  Retain transport/process
# evidence only: V6 closes a client, V9 completes a bounded parallel batch,
# and V10 terminates only the identity-verified host with an active request.
V6_RESULT=direct-close
v6_status=0
python3 "$LIFECYCLE_PROBE" client-abort --frontend-port "$FRONTEND_PORT" \
    --upstream-port "$UPSTREAM_PORT" --timeout "$TIMEOUT" \
    --backend-read-timeout "$BACKEND_READ_TIMEOUT" --runtime-root "$RUNTIME_ROOT" \
    --receipt "$V6_RECEIPT" || v6_status=$?
if [ "$v6_status" -eq 77 ]; then
    V6_RESULT=bounded-timeout-fallback
elif [ "$v6_status" -ne 0 ]; then
    fail "Stock active client-abort probe failed"
fi
printf 'v6_result=%s\n' "$V6_RESULT" >> "$PROVENANCE"

if [ "$V6_RESULT" = bounded-timeout-fallback ]; then
    backend_timeout_log_evidence=0
    end=$(( $(date +%s) + TIMEOUT ))
    while [ "$(date +%s)" -lt "$end" ]; do
        python3 "$LINUX_GUARD" assert-file-marker \
            --path "$RUNTIME_ROOT/lighttpd-error.log" \
            --marker "read timeout on socket:" --max-bytes 65536 \
            >/dev/null 2>&1 && backend_timeout_log_evidence=1 && break
        sleep 0.05
    done
    [ "$backend_timeout_log_evidence" -eq 1 ] || fail "Stock V6 fallback lacked bounded host read-timeout log evidence"
    python3 "$LINUX_GUARD" write-json --output "$V6_TIMEOUT_RECEIPT" \
        --field "evidence_type=stock_v6_host_timeout_fallback" \
        --field "host_event=proxy_backend_read_timeout" \
        --field "configured_backend_read_timeout_seconds=$BACKEND_READ_TIMEOUT" \
        --field "source_log=lighttpd-error.log" \
        --field "source_log_marker=read timeout on socket" \
        --field "client_direct_propagation=not_observed" \
        --field "connector_event=not_claimed" >/dev/null || \
        fail "Stock V6 timeout fallback receipt could not be written"
    printf 'v6_backend_timeout_log=read timeout on socket\n' >> "$PROVENANCE"
fi

# The V6 fallback must recover before the raw V7/V11 truncation transaction.
# This is deliberately a separate legitimate control through the same host.
python3 - "$FRONTEND_PORT" <<'PY'
import socket
import sys
with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=3) as sock:
    sock.sendall(b"OPTIONS * HTTP/1.1\r\nHost: stock-v6-control\r\nConnection: close\r\n\r\n")
    line = sock.recv(4096).split(b"\r\n", 1)[0]
if not line.startswith(b"HTTP/1.1 200"):
    raise SystemExit("V6 immediate control failed: %r" % line)
PY
python3 "$LINUX_GUARD" write-json --output "$V6_CONTROL_RECEIPT" \
    --field "evidence_type=stock_v6_follow_up_control" \
    --field "http_status=200" \
    --field "request=OPTIONS-star" \
    --field "same_host=true" \
    --field "v6_resolution=$V6_RESULT" \
    --field "connector_event=not_claimed" >/dev/null || \
    fail "Stock V6 follow-up receipt could not be written"

# Run the active client-close before the Stock V7/V11 truncation exchange.
# The latter intentionally closes an upstream response early and may leave a
# Stock proxy transaction in its terminal cleanup path until the host loop
# advances; V6 must not depend on that prior state.
python3 "$BACKEND_PROBE" --frontend-port "$FRONTEND_PORT" --upstream-port "$UPSTREAM_PORT" \
    --path /p4/close/ --timeout "$TIMEOUT" --runtime-root "$RUNTIME_ROOT" \
    --receipt "$RECEIPT" || \
    fail "Stock backend-close probe failed"

python3 "$LIFECYCLE_PROBE" parallel --frontend-port "$FRONTEND_PORT" \
    --runtime-root "$RUNTIME_ROOT" --receipt "$V9_RECEIPT" || fail "Stock bounded parallel probe failed"

MSCONNECTOR_LIGHTTPD_SESSION_PROFILE=stock-lifecycle-hold \
MSCONNECTOR_LIGHTTPD_SESSION_EXECUTABLE="$PYTHON_BINARY" \
MSCONNECTOR_LIGHTTPD_SESSION_FRONTEND_PORT="$FRONTEND_PORT" \
MSCONNECTOR_LIGHTTPD_SESSION_UPSTREAM_PORT="$UPSTREAM_PORT" \
MSCONNECTOR_LIGHTTPD_SESSION_READY="$V10_READY" \
MSCONNECTOR_LIGHTTPD_SESSION_RELEASE="$V10_RELEASE" \
MSCONNECTOR_LIGHTTPD_SESSION_RUNTIME_ROOT="$RUNTIME_ROOT" \
MSCONNECTOR_LIGHTTPD_SESSION_RECEIPT="$V10_RECEIPT" \
MSCONNECTOR_LIGHTTPD_SESSION_TIMEOUT="$TIMEOUT" \
MSCONNECTOR_LIGHTTPD_SESSION_PARENT_PID="$$" \
python3 "$LINUX_GUARD" exec-session --file-limit-blocks 128 \
    --session-record "$V10_PROBE_SESSION_RECORD" >"$RUNTIME_ROOT/v10-probe.stdout" 2>"$RUNTIME_ROOT/v10-probe.stderr" &
V10_PROBE_PID=$!
V10_PROBE_SESSION=$V10_PROBE_PID
V10_PROBE_START_TIME=$(proc_start_time "$V10_PROBE_PID" 2>/dev/null || true)
end=$(( $(date +%s) + CLEANUP_TIMEOUT ))
while [ ! -f "$V10_READY" ] && [ "$(date +%s)" -lt "$end" ]; do
    pid_alive "$V10_PROBE_PID" || fail "Stock V10 probe exited before readiness"
    sleep 0.05
done
[ -f "$V10_READY" ] || fail "Stock V10 probe did not become ready"
python3 "$LINUX_GUARD" signal-session --pid "$SERVER_PID" --start-time "$SERVER_START_TIME" \
    --exe "$HOST_BINARY" --signal TERM >/dev/null || fail "Stock host identity-checked termination failed"
wait "$SERVER_PID" 2>/dev/null || true
python3 "$LINUX_GUARD" assert-session-absent --session "$SERVER_SESSION" \
    --wait-seconds "$CLEANUP_TIMEOUT" >/dev/null || fail "terminated Stock host session remained"
# Preserve an identity-bound cleanup receipt for the deliberately terminated
# first host before registering its replacement.  The V10 signal and absence
# assertion establish that it is already gone; cleanup-session records that
# terminal state instead of silently replacing the only host cleanup receipt.
cleanup_process "$SERVER_SESSION_RECORD" "$SERVER_CLEANUP_RECEIPT" || \
    fail "terminated Stock host cleanup receipt failed"
[ -s "$SERVER_CLEANUP_RECEIPT" ] || fail "terminated Stock host cleanup receipt is missing"
python3 "$LIFECYCLE_PROBE" release --runtime-root "$RUNTIME_ROOT" --release "$V10_RELEASE" || fail "Stock V10 release marker failed"
end=$(( $(date +%s) + CLEANUP_TIMEOUT ))
while [ ! -s "$V10_RECEIPT" ] && [ "$(date +%s)" -lt "$end" ]; do
    pid_alive "$V10_PROBE_PID" || fail "Stock V10 probe exited before client-close evidence"
    sleep 0.05
done
[ -s "$V10_RECEIPT" ] || fail "Stock V10 client-close evidence did not arrive"
python3 "$LINUX_GUARD" cleanup-session --session-record "$V10_PROBE_SESSION_RECORD" \
    --leader-exe "$PYTHON_BINARY" --timeout-seconds "$CLEANUP_TIMEOUT" \
    --output "$V10_PROBE_CLEANUP_RECEIPT" --reject-unexpected-members >/dev/null || \
    fail "Stock V10 probe cleanup failed"
V10_PROBE_SESSION=
python3 "$LINUX_GUARD" assert-session-absent --session "$V10_PROBE_PID" \
    --wait-seconds "$CLEANUP_TIMEOUT" >/dev/null || fail "Stock V10 probe session remained"
[ -s "$V10_RECEIPT" ] || fail "Stock V10 receipt is missing"

# Register the replacement host in a fresh record so EXIT cleanup remains
# idempotent after the deliberately terminated first host.
SERVER_PID=
SERVER_SESSION=
SERVER_START_TIME=
SERVER_SESSION_RECORD=$RUNTIME_ROOT/server-session-restart.json
SERVER_CLEANUP_RECEIPT=$RUNTIME_ROOT/server-cleanup-restart.json
MSCONNECTOR_LIGHTTPD_SESSION_PROFILE=lighttpd-server \
MSCONNECTOR_LIGHTTPD_SESSION_EXECUTABLE="$HOST_BINARY" \
MSCONNECTOR_LIGHTTPD_SESSION_MODULE_DIR="$MODULE_DIR" \
MSCONNECTOR_LIGHTTPD_SESSION_CONFIG="$RUNTIME_ROOT/lighttpd.conf" \
MSCONNECTOR_LIGHTTPD_SESSION_PARENT_PID="$$" \
python3 "$LINUX_GUARD" exec-session --file-limit-blocks 128 \
    --session-record "$SERVER_SESSION_RECORD" \
    >"$RUNTIME_ROOT/host-restart.stdout" 2>"$RUNTIME_ROOT/host-restart.stderr" &
SERVER_PID=$!
SERVER_SESSION=$SERVER_PID
SERVER_START_TIME=$(proc_start_time "$SERVER_PID" 2>/dev/null || true)
[ -n "$SERVER_START_TIME" ] || fail "could not record restarted Stock host start time"
end=$(( $(date +%s) + CLEANUP_TIMEOUT ))
while [ "$(date +%s)" -lt "$end" ]; do
    if pid_alive "$SERVER_PID" && python3 "$LINUX_GUARD" assert-listener \
        --pid "$SERVER_PID" --start-time "$SERVER_START_TIME" --exe "$HOST_BINARY" \
        --host 127.0.0.1 --port "$FRONTEND_PORT" >/dev/null 2>&1; then
        break
    fi
    sleep 0.05
done
python3 "$LINUX_GUARD" assert-listener --pid "$SERVER_PID" --start-time "$SERVER_START_TIME" \
    --exe "$HOST_BINARY" --host 127.0.0.1 --port "$FRONTEND_PORT" >/dev/null || \
    fail "restarted Stock host did not reach an owned listener"

control_status() {
    expected=$1
    block=$2
    python3 - "$FRONTEND_PORT" "$expected" "$block" <<'PY'
import socket
import sys
port, expected, block = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3] == "1"
extra = "X-Modsec-Smoke: block\r\n" if block else ""
with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
    sock.sendall(("OPTIONS * HTTP/1.1\r\nHost: stock-follow-up\r\nConnection: close\r\n" + extra + "\r\n").encode())
    line = sock.recv(4096).split(b"\r\n", 1)[0]
if not line.startswith(("HTTP/1.1 %d" % expected).encode()):
    raise SystemExit("unexpected follow-up response: %r" % line)
PY
}

control_status 200 0
control_status 403 1
control_status 200 0

cleanup
SERVER_PID=
SERVER_SESSION=
trap - EXIT HUP INT TERM
python3 "$LINUX_GUARD" assert-no-uds --root "$RUNTIME_ROOT" || fail "Stock runtime root retains a UDS"
python3 "$LINUX_GUARD" assert-listener-absent --host 127.0.0.1 --port "$FRONTEND_PORT" || \
    fail "Stock frontend listener remains after cleanup"
python3 "$LINUX_GUARD" assert-listener-absent --host 127.0.0.1 --port "$UPSTREAM_PORT" || \
    fail "Stock upstream listener remains after cleanup"
[ -s "$RECEIPT" ] || fail "backend-close receipt is missing"
[ -s "$V6_RECEIPT" ] || fail "V6 receipt is missing"
[ -s "$V6_CONTROL_RECEIPT" ] || fail "V6 follow-up receipt is missing"
if [ "$V6_RESULT" = bounded-timeout-fallback ]; then
    [ -s "$V6_TIMEOUT_RECEIPT" ] || fail "V6 host-timeout receipt is missing"
fi
[ -s "$V9_RECEIPT" ] || fail "V9 receipt is missing"
[ -s "$V10_RECEIPT" ] || fail "V10 receipt is missing"
[ -s "$SERVER_CLEANUP_RECEIPT" ] || fail "server cleanup receipt is missing"

printf 'lighttpd_stock_lifecycle: PASS profile=stock-native-lighttpd backend_close=pass lifecycle=V6-%s,V9,V10 follow_up=200,403,200 cleanup=verified provenance=%s receipt=%s not_executed=V12,V13,V14,V15\n' \
    "$V6_RESULT" \
    "$PROVENANCE" "$RECEIPT"
