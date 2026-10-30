#!/bin/sh
set -euC

SCRIPT_DIR=$(CDPATH='' cd "$(dirname "$0")" && pwd)
LINUX_GUARD=$SCRIPT_DIR/lighttpd_backend_close_linux_guard.py
BUILD_ROOT=${BUILD_ROOT:-${XDG_STATE_HOME:-${HOME:-/tmp}/.local/state}/ModSecurity-conector-build}
RUNTIME_ROOT=${RUNTIME_ROOT:-$BUILD_ROOT/lighttpd-backend-close}
HOST_BINARY=${LIGHTTPD_BIN:-}
MODULE_PATH=${LIGHTTPD_CONNECTOR_MODULE:-}
RULES_FILE=${LIGHTTPD_BACKEND_CLOSE_RULES_FILE:-}
MODE=${LIGHTTPD_BACKEND_CLOSE_MODE:-}
FRONTEND_PORT=${LIGHTTPD_BACKEND_CLOSE_FRONTEND_PORT:-}
UPSTREAM_PORT=${LIGHTTPD_BACKEND_CLOSE_UPSTREAM_PORT:-}
EXPECTED_MODE=${LIGHTTPD_EXPECTED_INTEGRATION_MODE:-}
PATH_TO_PROBE=${LIGHTTPD_BACKEND_CLOSE_PATH:-/p4/close/}
TIMEOUT=${LIGHTTPD_BACKEND_CLOSE_TIMEOUT:-5}
CLEANUP_TIMEOUT=${LIGHTTPD_BACKEND_CLOSE_CLEANUP_TIMEOUT:-5}
LOG_FILE_BLOCKS=${LIGHTTPD_BACKEND_CLOSE_LOG_FILE_BLOCKS:-128}
LOG_FILE_BYTES=$(( LOG_FILE_BLOCKS * 512 ))
PIDFD_TARGET_EXIT_STATUS=75
AWK_FIRST_FIELD='{print $1}'

blocked() {
    blocked_message=$1
    printf 'lighttpd_backend_close: BLOCKED: %s\n' "$blocked_message"
    exit 77
}
fail() {
    failure_message=$1
    printf 'lighttpd_backend_close: FAIL: %s\n' "$failure_message" >&2
    exit 1
}

[ -n "$HOST_BINARY" ] || blocked "LIGHTTPD_BIN is required"
[ -n "$MODULE_PATH" ] || blocked "LIGHTTPD_CONNECTOR_MODULE is required"
[ -n "$RULES_FILE" ] || blocked "LIGHTTPD_BACKEND_CLOSE_RULES_FILE is required"
case "$MODE" in stock|patched) ;; *) blocked "LIGHTTPD_BACKEND_CLOSE_MODE must be stock or patched" ;; esac
case "$EXPECTED_MODE" in native-lighttpd-plugin|patched-native-lighttpd) ;; *) blocked "LIGHTTPD_EXPECTED_INTEGRATION_MODE is required" ;; esac
case "$CLEANUP_TIMEOUT" in ''|*[!0-9]*) blocked "LIGHTTPD_BACKEND_CLOSE_CLEANUP_TIMEOUT must be numeric" ;; *) : ;; esac
[ "$CLEANUP_TIMEOUT" -ge 1 ] && [ "$CLEANUP_TIMEOUT" -le 30 ] || blocked "cleanup timeout must be between 1 and 30 seconds"
case "$LOG_FILE_BLOCKS" in ''|*[!0-9]*) blocked "LIGHTTPD_BACKEND_CLOSE_LOG_FILE_BLOCKS must be numeric" ;; *) : ;; esac
[ "$LOG_FILE_BLOCKS" -ge 1 ] && [ "$LOG_FILE_BLOCKS" -le 2048 ] || blocked "log file limit must be between 1 and 2048 blocks"
[ -f "$LINUX_GUARD" ] || blocked "Linux pidfd guard is missing: $LINUX_GUARD"
python3 "$LINUX_GUARD" check-pidfd >/dev/null || blocked "usable Linux pidfd capability is required for safe process cleanup"
[ -f "$HOST_BINARY" ] && [ -x "$HOST_BINARY" ] || blocked "host binary must be an executable regular file: $HOST_BINARY"
[ -f "$MODULE_PATH" ] || blocked "module is missing: $MODULE_PATH"
[ -f "$RULES_FILE" ] || blocked "rules file is missing: $RULES_FILE"
case "$MODE:$EXPECTED_MODE" in
    patched:patched-native-lighttpd) ;;
    stock:native-lighttpd-plugin)
        blocked "Stock response-body backend-close coverage requires the patched streaming-hook host; use run_lighttpd_stock_lifecycle.sh"
        ;;
    *) blocked "mode and expected integration provenance disagree" ;;
esac

case "$RUNTIME_ROOT" in /*) : ;; *) blocked "RUNTIME_ROOT must be absolute" ;; esac
RUNTIME_PARENT=$(CDPATH='' cd "$(dirname "$RUNTIME_ROOT")" && pwd -P)
RUNTIME_ROOT=$RUNTIME_PARENT/$(basename "$RUNTIME_ROOT")
[ ! -e "$RUNTIME_ROOT" ] && [ ! -L "$RUNTIME_ROOT" ] || blocked "runtime root must be fresh and non-symlink"
umask 077
mkdir "$RUNTIME_ROOT" || blocked "could not create fresh private runtime root"
[ "$(stat -c '%a' "$RUNTIME_ROOT")" = 700 ] || chmod 700 "$RUNTIME_ROOT"
export MSCONNECTOR_TRUSTED_RUNTIME_ROOT="$RUNTIME_ROOT"
for item in "$HOST_BINARY" "$MODULE_PATH" "$RULES_FILE"; do
    [ -e "$item" ] || blocked "provenance path disappeared: $item"
done
HOST_BINARY=$(readlink -f -- "$HOST_BINARY")
MODULE_PATH=$(readlink -f -- "$MODULE_PATH")
RULES_FILE=$(readlink -f -- "$RULES_FILE")
MODULE_DIR=$(CDPATH='' cd "$(dirname "$MODULE_PATH")" && pwd -P) || \
    blocked "resolved module directory is unavailable"
[ -f "$HOST_BINARY" ] && [ -x "$HOST_BINARY" ] || blocked "resolved host binary must be an executable regular file: $HOST_BINARY"
[ "$(basename "$MODULE_PATH")" = mod_msconnector.so ] || blocked "module basename must be mod_msconnector.so"
[ -f "$MODULE_PATH" ] && [ -f "$RULES_FILE" ] || blocked "resolved module/rules is not a regular file"
MODULE_SHA256=$(sha256sum "$MODULE_PATH" | awk "$AWK_FIRST_FIELD")
HOST_SHA256=$(sha256sum "$HOST_BINARY" | awk "$AWK_FIRST_FIELD")
RULES_SHA256=$(sha256sum "$RULES_FILE" | awk "$AWK_FIRST_FIELD")

case "$FRONTEND_PORT:$UPSTREAM_PORT" in *[!0-9:]*|:|*:) blocked "frontend and upstream ports are required numeric values" ;; *) : ;; esac
python3 - "$FRONTEND_PORT" "$UPSTREAM_PORT" <<'PY'
import socket, sys
for raw in sys.argv[1:]:
    port = int(raw)
    if not 1024 <= port <= 65535:
        raise SystemExit("port outside unprivileged range")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", port))
PY

python3 "$LINUX_GUARD" write-config --root "$RUNTIME_ROOT" --rules-file "$RULES_FILE" \
    --frontend-port "$FRONTEND_PORT" --upstream-port "$UPSTREAM_PORT" >/dev/null || \
    fail "could not write task-owned lighttpd runtime configuration"
LIGHTTPD_CONFIG=$RUNTIME_ROOT/lighttpd.conf
RUNTIME_CONFIG=$RUNTIME_ROOT/msconnector-runtime.conf
ERROR_LOG=$RUNTIME_ROOT/lighttpd-error.log
RECEIPT=$RUNTIME_ROOT/raw-receipt.json
PROVENANCE=$RUNTIME_ROOT/provenance.json
PROVENANCE_CONFIGCHECK_BEFORE=$RUNTIME_ROOT/provenance-before-configcheck.json
PROVENANCE_CONFIGCHECK_AFTER=$RUNTIME_ROOT/provenance-after-configcheck.json
PROVENANCE_START=$RUNTIME_ROOT/provenance-after-start.json
SESSION_START=$RUNTIME_ROOT/session-after-start.json
SESSION_PRE_CLEANUP=$RUNTIME_ROOT/session-before-cleanup.json
CONFIG_SESSION_SNAPSHOT=$RUNTIME_ROOT/session-configcheck.json
CONFIG_SESSION_RECORD=$RUNTIME_ROOT/session-configcheck-registration.json
SERVER_SESSION_RECORD=$RUNTIME_ROOT/session-host-registration.json
CONFIG_CLEANUP_RECEIPT=$RUNTIME_ROOT/session-configcheck-cleanup.json
SERVER_CLEANUP_RECEIPT=$RUNTIME_ROOT/session-host-cleanup.json
CONFIG_SHA256=$(sha256sum "$LIGHTTPD_CONFIG" | awk "$AWK_FIRST_FIELD")
RUNTIME_CONFIG_SHA256=$(sha256sum "$RUNTIME_CONFIG" | awk "$AWK_FIRST_FIELD")

write_provenance() {
    output=$1
    phase=$2
    python3 "$LINUX_GUARD" write-json --output "$output" \
        --field "phase=$phase" --field "mode=$MODE" --field "host_binary=$HOST_BINARY" \
        --field "host_sha256=$HOST_SHA256" --field "module=$MODULE_PATH" \
        --field "module_sha256=$MODULE_SHA256" --field "rules_file=$RULES_FILE" \
        --field "rules_sha256=$RULES_SHA256" --field "lighttpd_config=$LIGHTTPD_CONFIG" \
        --field "lighttpd_config_sha256=$CONFIG_SHA256" --field "runtime_config=$RUNTIME_CONFIG" \
        --field "runtime_config_sha256=$RUNTIME_CONFIG_SHA256" \
        --field "output_rlimit_bytes=$LOG_FILE_BYTES" \
        --field "atomic_staging=not_used; fail_closed_on_hash_change" \
        --field "task_config=generated_in_runtime_root" \
        --field "session_cleanup=pidfd_registered_sid_pgid_term_kill; unexpected_members_fail_closed_after_containment" >/dev/null || \
        fail "could not write safe JSON provenance"
}
assert_static_provenance() {
    provenance_phase=$1
    [ "$(sha256sum "$HOST_BINARY" | awk "$AWK_FIRST_FIELD")" = "$HOST_SHA256" ] || fail "host binary changed $provenance_phase"
    [ "$(sha256sum "$MODULE_PATH" | awk "$AWK_FIRST_FIELD")" = "$MODULE_SHA256" ] || fail "module changed $provenance_phase"
    [ "$(sha256sum "$RULES_FILE" | awk "$AWK_FIRST_FIELD")" = "$RULES_SHA256" ] || fail "rules changed $provenance_phase"
    [ "$(sha256sum "$LIGHTTPD_CONFIG" | awk "$AWK_FIRST_FIELD")" = "$CONFIG_SHA256" ] || fail "task-owned config changed $provenance_phase"
    [ "$(sha256sum "$RUNTIME_CONFIG" | awk "$AWK_FIRST_FIELD")" = "$RUNTIME_CONFIG_SHA256" ] || fail "task-owned runtime config changed $provenance_phase"
}
write_provenance "$PROVENANCE" initial
write_provenance "$PROVENANCE_CONFIGCHECK_BEFORE" before-configcheck

SERVER_PID=
CONFIG_PID=
SERVER_START_TIME=
CONFIG_START_TIME=
SERVER_SESSION=
CONFIG_SESSION=
CLEANUP_ACTIVE=0
CLEANUP_STATUS=1
proc_start_time() {
    proc_pid=$1
    proc_stat=$(cat "/proc/$proc_pid/stat" 2>/dev/null) || return 1
    proc_stat=${proc_stat#*) }
    printf '%s\n' "$proc_stat" | awk '{print $20}'
}
proc_state() {
    proc_pid=$1
    proc_stat=$(cat "/proc/$proc_pid/stat" 2>/dev/null) || return 1
    proc_stat=${proc_stat#*) }
    printf '%s\n' "$proc_stat" | awk "$AWK_FIRST_FIELD"
}
pid_alive() {
    pid=${1:-}
    [ -n "$pid" ] && [ -e "/proc/$pid/stat" ] && [ "$(proc_state "$pid")" != Z ]
}
process_owned() {
    process_pid=$1
    process_start=$2
    pid_alive "$process_pid" || return 1
    current_exe=$(readlink -f -- "/proc/$process_pid/exe" 2>/dev/null || true)
    current_start=$(proc_start_time "$process_pid" 2>/dev/null || true)
    [ "$current_exe" = "$HOST_BINARY" ] && [ "$current_start" = "$process_start" ]
}
assert_host_identity() {
    session_output=${1:-}
    process_owned "$SERVER_PID" "$SERVER_START_TIME" || fail "host identity changed"
    python3 "$LINUX_GUARD" assert-listener --pid "$SERVER_PID" --start-time "$SERVER_START_TIME" \
        --exe "$HOST_BINARY" --host 127.0.0.1 --port "$FRONTEND_PORT" >/dev/null || \
        fail "frontend listener is not provably owned by the task host"
    if [ -n "$session_output" ]; then
        python3 "$LINUX_GUARD" assert-session --pid "$SERVER_PID" --start-time "$SERVER_START_TIME" \
            --exe "$HOST_BINARY" --output "$session_output" >/dev/null || fail "task host session inventory changed"
    else
        python3 "$LINUX_GUARD" assert-session --pid "$SERVER_PID" --start-time "$SERVER_START_TIME" \
            --exe "$HOST_BINARY" >/dev/null || fail "task host session inventory changed"
    fi
}
wait_for_exit() {
    wait_pid=$1
    end=$(( $(date +%s) + CLEANUP_TIMEOUT ))
    while pid_alive "$wait_pid" && [ "$(date +%s)" -lt "$end" ]; do
        sleep 0.1
    done
}
wait_for_process_identity() {
    identity_pid=$1
    identity_start=$2
    identity_mismatch=0
    end=$(( $(date +%s) + CLEANUP_TIMEOUT ))
    while pid_alive "$identity_pid" && [ "$(date +%s)" -lt "$end" ]; do
        process_owned "$identity_pid" "$identity_start" && return 0
        # Do not let a previously observed live identity mismatch become a
        # tolerated exit merely because that PID disappears on the next poll.
        pid_alive "$identity_pid" || return "$PIDFD_TARGET_EXIT_STATUS"
        identity_mismatch=1
        sleep 0.05
    done
    # A disappeared or zombie config-check is a normal terminal transition;
    # a still-live process that did not retain the registered identity is not.
    [ "$identity_mismatch" -eq 0 ] || return 1
    pid_alive "$identity_pid" || return "$PIDFD_TARGET_EXIT_STATUS"
    return 1
}
snapshot_configcheck_session() {
    pid_alive "$CONFIG_PID" || return 0
    identity_status=0
    wait_for_process_identity "$CONFIG_PID" "$CONFIG_START_TIME" || identity_status=$?
    if [ "$identity_status" -ne 0 ]; then
        if [ "$identity_status" -eq "$PIDFD_TARGET_EXIT_STATUS" ] && ! pid_alive "$CONFIG_PID"; then
            return 0
        fi
        fail "config-check process did not retain the expected host identity"
    fi
    session_status=0
    python3 "$LINUX_GUARD" assert-session --pid "$CONFIG_PID" --start-time "$CONFIG_START_TIME" \
        --exe "$HOST_BINARY" --output "$CONFIG_SESSION_SNAPSHOT" >/dev/null || session_status=$?
    if [ "$session_status" -eq 0 ]; then
        return 0
    fi
    # Status 75 is emitted only after the guard failed to acquire a pidfd and
    # immediately proved the target was gone or a zombie.  Recheck liveness to
    # reject PID reuse; all other guard errors remain fail-closed.
    if [ "$session_status" -eq "$PIDFD_TARGET_EXIT_STATUS" ] && ! pid_alive "$CONFIG_PID"; then
        return 0
    fi
    fail "config-check session inventory changed or pidfd target remained live"
}
wait_for_host_listener() {
    end=$(( $(date +%s) + CLEANUP_TIMEOUT ))
    while pid_alive "$SERVER_PID" && [ "$(date +%s)" -lt "$end" ]; do
        if process_owned "$SERVER_PID" "$SERVER_START_TIME" && \
            python3 "$LINUX_GUARD" assert-listener --pid "$SERVER_PID" --start-time "$SERVER_START_TIME" \
                --exe "$HOST_BINARY" --host 127.0.0.1 --port "$FRONTEND_PORT" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.05
    done
    fail "task host did not reach a provably owned frontend listener before the bounded deadline"
}
cleanup_process() {
    cleanup_pid=$1
    cleanup_session=$2
    cleanup_record=$3
    cleanup_receipt=$4
    cleanup_status=0
    if [ -L "$cleanup_record" ]; then
        printf 'lighttpd_backend_close: FAIL: refusing a symlinked task session registration\n' >&2
        cleanup_status=1
    elif [ -f "$cleanup_record" ]; then
        if ! python3 "$LINUX_GUARD" cleanup-session --session-record "$cleanup_record" \
            --leader-exe "$HOST_BINARY" --timeout-seconds "$CLEANUP_TIMEOUT" \
            --output "$cleanup_receipt" --reject-unexpected-members >/dev/null; then
            printf 'lighttpd_backend_close: FAIL: task session pidfd containment failed\n' >&2
            cleanup_status=1
        fi
    elif pid_alive "$cleanup_pid"; then
        printf 'lighttpd_backend_close: FAIL: refusing to cleanup a process without registered task SID/PGID\n' >&2
        cleanup_status=1
    fi
    if [ -n "$cleanup_pid" ]; then
        if pid_alive "$cleanup_pid"; then
            printf 'lighttpd_backend_close: FAIL: task host remains active after bounded session containment\n' >&2
            cleanup_status=1
        else
            wait "$cleanup_pid" 2>/dev/null || true
        fi
    fi
    if [ -n "$cleanup_session" ] && ! python3 "$LINUX_GUARD" assert-session-absent \
        --session "$cleanup_session" --wait-seconds "$CLEANUP_TIMEOUT" >/dev/null; then
        printf 'lighttpd_backend_close: FAIL: task session still contains processes after cleanup\n' >&2
        cleanup_status=1
    fi
    return "$cleanup_status"
}
cleanup() {
    [ "$CLEANUP_ACTIVE" -eq 0 ] || return "$CLEANUP_STATUS"
    CLEANUP_ACTIVE=1
    # A re-entrant signal must fail closed while the first cleanup is in
    # progress; replace this only with that first cleanup's actual result.
    CLEANUP_STATUS=1
    cleanup_status=0
    cleanup_process "$CONFIG_PID" "$CONFIG_SESSION" "$CONFIG_SESSION_RECORD" "$CONFIG_CLEANUP_RECEIPT" || cleanup_status=1
    cleanup_process "$SERVER_PID" "$SERVER_SESSION" "$SERVER_SESSION_RECORD" "$SERVER_CLEANUP_RECEIPT" || cleanup_status=1
    CLEANUP_STATUS=$cleanup_status
    return "$CLEANUP_STATUS"
}
cleanup_on_signal() {
    signal_name=$1
    cleanup_status=0
    cleanup || cleanup_status=$?
    trap - EXIT HUP INT TERM
    if [ "$cleanup_status" -ne 0 ]; then
        printf 'lighttpd_backend_close: FAIL: cleanup failed while handling signal %s (status=%s)\n' \
            "$signal_name" "$cleanup_status" >&2
        exit "$cleanup_status"
    fi
    exit 128
}
trap cleanup EXIT
trap 'cleanup_on_signal HUP' HUP
trap 'cleanup_on_signal INT' INT
trap 'cleanup_on_signal TERM' TERM

assert_static_provenance "before config check"
MSCONNECTOR_LIGHTTPD_SESSION_PROFILE=lighttpd-config-check \
MSCONNECTOR_LIGHTTPD_SESSION_EXECUTABLE="$HOST_BINARY" \
MSCONNECTOR_LIGHTTPD_SESSION_MODULE_DIR="$MODULE_DIR" \
MSCONNECTOR_LIGHTTPD_SESSION_CONFIG="$LIGHTTPD_CONFIG" \
python3 "$LINUX_GUARD" exec-session --file-limit-blocks "$LOG_FILE_BLOCKS" \
    --session-record "$CONFIG_SESSION_RECORD" \
    >"$RUNTIME_ROOT/config-check.stdout" 2>"$RUNTIME_ROOT/config-check.stderr" &
CONFIG_PID=$!
CONFIG_START_TIME=$(proc_start_time "$CONFIG_PID" 2>/dev/null || true)
CONFIG_SESSION=$CONFIG_PID
[ -n "$CONFIG_START_TIME" ] || fail "could not record config-check process start time"
snapshot_configcheck_session
wait_for_exit "$CONFIG_PID"
if pid_alive "$CONFIG_PID"; then
    fail "lighttpd config check exceeded its bounded deadline"
fi
wait "$CONFIG_PID" 2>/dev/null || config_status=$?
CONFIG_PID=
[ "${config_status:-0}" -eq 0 ] || fail "lighttpd config check failed"
python3 "$LINUX_GUARD" assert-session-absent --session "$CONFIG_SESSION" \
    --wait-seconds "$CLEANUP_TIMEOUT" >/dev/null || fail "config-check session did not exit"
assert_static_provenance "after config check"
write_provenance "$PROVENANCE_CONFIGCHECK_AFTER" after-configcheck

assert_static_provenance "before host startup"
MSCONNECTOR_LIGHTTPD_SESSION_PROFILE=lighttpd-server \
MSCONNECTOR_LIGHTTPD_SESSION_EXECUTABLE="$HOST_BINARY" \
MSCONNECTOR_LIGHTTPD_SESSION_MODULE_DIR="$MODULE_DIR" \
MSCONNECTOR_LIGHTTPD_SESSION_CONFIG="$LIGHTTPD_CONFIG" \
python3 "$LINUX_GUARD" exec-session --file-limit-blocks "$LOG_FILE_BLOCKS" \
    --session-record "$SERVER_SESSION_RECORD" \
    >"$RUNTIME_ROOT/host.stdout" 2>"$RUNTIME_ROOT/host.stderr" &
SERVER_PID=$!
SERVER_START_TIME=$(proc_start_time "$SERVER_PID" 2>/dev/null || true)
SERVER_SESSION=$SERVER_PID
[ -n "$SERVER_START_TIME" ] || fail "could not record host process start time"
wait_for_host_listener
assert_host_identity "$SESSION_START"
assert_static_provenance "after host startup"
write_provenance "$PROVENANCE_START" after-host-start

python3 "$SCRIPT_DIR/lighttpd_backend_close_probe.py" \
    --frontend-port "$FRONTEND_PORT" --upstream-port "$UPSTREAM_PORT" \
    --path "$PATH_TO_PROBE" --timeout "$TIMEOUT" --runtime-root "$RUNTIME_ROOT" \
    --receipt "$RECEIPT" || fail "raw-socket truncation proof failed"
[ -s "$RECEIPT" ] || fail "raw-socket receipt missing before host stop"
assert_host_identity
python3 "$LINUX_GUARD" assert-abort-event --receipt "$RECEIPT" --error-log "$ERROR_LOG" \
    --max-bytes "$LOG_FILE_BYTES" --wait-seconds "$TIMEOUT" >/dev/null || \
    fail "matching upstream_eof abort event is missing"

control_status() {
    expected=$1
    block=$2
    assert_host_identity
    python3 - "$FRONTEND_PORT" "$expected" "$block" <<'PY'
import socket, sys
port, expected, block = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3] == "1"
extra = "X-Modsec-Smoke: block\r\n" if block else ""
with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
    sock.sendall(("OPTIONS * HTTP/1.1\r\nHost: control\r\nConnection: close\r\n" + extra + "\r\n").encode())
    data = sock.recv(4096)
line = data.split(b"\r\n", 1)[0]
if not line.startswith(("HTTP/1.1 %d" % expected).encode()):
    raise SystemExit("unexpected control response: %r" % line)
PY
}
control_status 200 0
control_status 403 1
control_status 200 0
assert_host_identity "$SESSION_PRE_CLEANUP"

cleanup
SERVER_PID=
trap - EXIT HUP INT TERM
python3 "$LINUX_GUARD" assert-no-uds --root "$RUNTIME_ROOT" >/dev/null || fail "task runtime root retains a UDS"
python3 "$LINUX_GUARD" assert-listener-absent --host 127.0.0.1 --port "$FRONTEND_PORT" >/dev/null || \
    fail "frontend listener remains after cleanup"
python3 "$LINUX_GUARD" assert-listener-absent --host 127.0.0.1 --port "$UPSTREAM_PORT" >/dev/null || \
    fail "upstream listener remains after cleanup"
printf 'lighttpd_backend_close: PASS mode=%s receipt=%s provenance=%s\n' "$MODE" "$RECEIPT" "$PROVENANCE"
