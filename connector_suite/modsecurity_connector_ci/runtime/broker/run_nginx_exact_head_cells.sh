#!/bin/sh
# Trusted-base exact-head NGINX cell driver.
#
# The root launcher creates every NGINX configuration, ModSecurity rule and
# include boundary before this script is reached. This Base-owned helper only
# starts the descriptor-admitted native artifacts and writes transient data
# below the launcher-provided runtime/log directories. It never sources,
# imports or executes candidate shell/Python orchestration.
set -eu

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
LC_ALL=C
export LC_ALL
umask 077

die() {
    printf '%s\n' 'NGINX exact-head cell refused' >&2
    exit 1
}

is_abs_clean() {
    path=$1
    case "$path" in
        /*) : ;;
        *) return 1 ;;
    esac
    case "$path" in
        *"/../"*|*"/./"*|*/..|*/.) return 1 ;;
    esac
}

[ "$#" -eq 3 ] || die
CANDIDATE_ROOT=$1
CANDIDATE_MANIFEST=$2
SCRATCH_ROOT=$3
is_abs_clean "$CANDIDATE_ROOT" || die
is_abs_clean "$CANDIDATE_MANIFEST" || die
is_abs_clean "$SCRATCH_ROOT" || die
[ -d "$CANDIDATE_ROOT" ] || die
[ -f "$CANDIDATE_MANIFEST" ] || die
[ -d "$SCRATCH_ROOT/on" ] || die
[ -d "$SCRATCH_ROOT/off" ] || die
[ -z "$(/usr/bin/find "$SCRATCH_ROOT" -mindepth 1 -maxdepth 1 ! -name on ! -name off -print -quit)" ] || die

# The launcher supplies these values only after descriptor admission. The
# loader path is constructed by the Base launcher inside env -i and is not
# inherited from the candidate job.
case "${NGINX_BINARY:-}" in "$CANDIDATE_ROOT/nginx") : ;; *) die ;; esac
case "${NGINX_MODULE:-}" in "$CANDIDATE_ROOT/ngx_http_modsecurity_module.so") : ;; *) die ;; esac
case "${MODSECURITY_LIB_DIR:-}" in "$CANDIDATE_ROOT") : ;; *) die ;; esac
case "${LD_LIBRARY_PATH:-}" in "$CANDIDATE_ROOT") : ;; *) die ;; esac
[ -z "${LD_PRELOAD:-}" ] || die
[ -z "${PYTHONPATH:-}" ] || die
[ "${NGINX_EXACT_HEAD_IN_ROOT_LAUNCHER:-}" = 1 ] || die
case "${NGINX_EXACT_HEAD_TRUSTED_BASE_ROOT:-}" in /*) : ;; *) die ;; esac
[ "${NGINX_EXACT_HEAD_SCRATCH_ROOT:-}" = "$SCRATCH_ROOT" ] || die
NGINX_WORKER_USER=${NGINX_WORKER_USER:-}
NGINX_WORKER_GROUP=${NGINX_WORKER_GROUP:-}
case "$NGINX_WORKER_USER" in mscnxw_[0-9a-f]*) : ;; *) die ;; esac
case "$NGINX_WORKER_GROUP" in mscnxg_[0-9a-f]*) : ;; *) die ;; esac

[ -x "$NGINX_BINARY" ] || die
[ -r "$NGINX_MODULE" ] || die
[ -r "$MODSECURITY_LIB_DIR/libmodsecurity.so.3" ] || die

write_mode() {
    mode=$1
    case "$mode" in on|off) : ;; *) die ;; esac
    cell="$SCRATCH_ROOT/$mode"
    config_root="$cell/config"
    control="$cell/control"
    runtime="$cell/runtime"
    logs="$cell/logs"
    config="$config_root/nginx.conf"
    rules="$config_root/modsecurity.conf"
    docroot="$config_root/docroot"
    pid_path="$runtime/nginx.pid"
    ready_path="$runtime/ready.json"
    release_path="$control/release"
    completion_path="$control/request-complete.json"
    [ -d "$config_root" ] && [ -d "$control" ] && [ -d "$runtime" ] && [ -d "$logs" ] && [ -d "$docroot" ] || die
    [ -f "$config" ] && [ -f "$rules" ] && [ -f "$docroot/index.html" ] || die
    [ ! -w "$config_root" ] && [ ! -w "$control" ] && [ ! -w "$config" ] && [ ! -w "$rules" ] || die
    [ ! -e "$ready_path" ] && [ ! -e "$release_path" ] && [ ! -e "$completion_path" ] || die

    # Validation and execution use only the fixed config path and the
    # descriptor-admitted binary. No candidate-selected include or command is
    # reachable here.
    "$NGINX_BINARY" -p "$cell" -c "$config" -t > "$runtime/configtest.txt" 2>&1 || die
    "$NGINX_BINARY" -p "$cell" -c "$config" > "$runtime/master.stdout" 2>"$runtime/master.stderr" &
    master_pid=$!
    ready=0
    attempt=0
    while [ "$attempt" -lt 40 ]; do
        if ! kill -0 "$master_pid" 2>/dev/null; then break; fi
        if [ -f "$pid_path" ]; then ready=1; break; fi
        attempt=$((attempt + 1))
        /usr/bin/sleep 1
    done
    [ "$ready" -eq 1 ] || { kill "$master_pid" 2>/dev/null; wait "$master_pid"; die; }
    worker_pid=''
    if worker_pid=$(/usr/bin/ps -eo pid=,ppid= | /usr/bin/awk -v parent="$master_pid" '$2 == parent {print $1; exit}' 2>/dev/null); then :; else die; fi
    case "$worker_pid" in
        ''|*[!0-9]*) kill "$master_pid"; wait "$master_pid"; die ;;
        *) : ;;
    esac
    worker_uid=''
    worker_gid=''
    master_uid=''
    master_gid=''
    if worker_uid=$(/usr/bin/stat -c '%u' "/proc/$worker_pid" 2>/dev/null); then :; else die; fi
    if worker_gid=$(/usr/bin/stat -c '%g' "/proc/$worker_pid" 2>/dev/null); then :; else die; fi
    if master_uid=$(/usr/bin/stat -c '%u' "/proc/$master_pid" 2>/dev/null); then :; else die; fi
    if master_gid=$(/usr/bin/stat -c '%g' "/proc/$master_pid" 2>/dev/null); then :; else die; fi
    [ -n "$worker_uid" ] && [ -n "$worker_gid" ] || die
    [ "$worker_uid" != "$master_uid" ] || die
    [ "$worker_gid" != "$master_gid" ] || die
    printf '{"schema_version":1,"mode":"%s","binary_path":"%s","config_path":"%s","pid_path":"%s","master_pid":%s,"worker_pid":%s,"master_uid":%s,"master_gid":%s,"worker_uid":%s,"worker_gid":%s}\n' \
        "$mode" "$NGINX_BINARY" "$config" "$pid_path" "$master_pid" "$worker_pid" "$master_uid" \
        "$master_gid" "$worker_uid" "$worker_gid" > "$ready_path"
    chmod 400 "$ready_path"

    released=0
    release_attempt=0
    while [ "$release_attempt" -lt 40 ]; do
        if [ -f "$release_path" ]; then
            # This marker sits in the Base-created, host-root-owned control
            # directory. Host-root ownership is intentionally not evaluated
            # inside the user namespace, where an unmapped host UID appears
            # as overflow; the candidate cannot create or replace entries in
            # this directory.
            released=1
            [ "$released" -eq 1 ] && break
        fi
        release_attempt=$((release_attempt + 1))
        /usr/bin/sleep 1
    done
    [ "$released" -eq 1 ] || die

    # The root launcher issues the HTTP request through a fixed host-side
    # client in this network namespace. This helper waits for that root-owned
    # completion record in the separate candidate-non-writable control
    # directory rather than writing a candidate-writable status file.
    completed=0
    completion_attempt=0
    while [ "$completion_attempt" -lt 40 ]; do
        if [ -f "$completion_path" ]; then completed=1; break; fi
        if ! kill -0 "$master_pid" 2>/dev/null; then break; fi
        completion_attempt=$((completion_attempt + 1))
        /usr/bin/sleep 1
    done
    [ "$completed" -eq 1 ] || { kill "$master_pid"; wait "$master_pid"; die; }
    kill -TERM "$master_pid"
    shutdown_status=0
    if wait "$master_pid"; then :; else shutdown_status=$?; fi
    [ "$shutdown_status" -eq 0 ] || die

    # This is a local fail-closed guard. The root launcher separately parses
    # the raw fixed log paths after namespace shutdown and publishes new,
    # terminal-safe evidence for the collector.
    actual_tx=''
    if actual_tx=$(/usr/bin/sed -n 's/.*"transaction_id":"\([^"]*\)".*/\1/p' "$logs/events.jsonl" | /usr/bin/head -n 1); then :; else die; fi
    case "$actual_tx" in nginx-exact-head-[0-9]*-[0-9]*-[0-9]*) : ;; *) die ;; esac
    callback=0
    if /usr/bin/grep -F "modsecurity_transaction_id=$actual_tx" "$logs/error.log" >/dev/null 2>&1; then callback=1; else callback=0; fi
    { [ "$mode" = on ] && [ "$callback" -eq 1 ]; } || { [ "$mode" = off ] && [ "$callback" -eq 0 ]; } || die
    jsonl=0
    if [ -s "$logs/events.jsonl" ] && /usr/bin/grep -F '"transaction_id":"'"$actual_tx"'"' "$logs/events.jsonl" >/dev/null 2>&1; then jsonl=1; else jsonl=0; fi
    [ "$jsonl" -eq 1 ] || die
}

write_mode on
write_mode off
exit 0
