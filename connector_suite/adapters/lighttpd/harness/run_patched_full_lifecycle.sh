#!/bin/sh
set -eu

# Exercise the Framework-version-synchronized patched Lighttpd native module through its HTTP/1.1
# entity-body hook.  The P4 path is deliberately limited to identity entities
# proxied by mod_proxy; no H2/H3, compression, file, or zero-copy route is
# represented here.

SCRIPT_DIR=$(CDPATH='' cd "$(dirname "$0")" && pwd)
REPO_ROOT=${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}
FRAMEWORK_ROOT=${FRAMEWORK_ROOT:-$REPO_ROOT/modules/ModSecurity-test-Framework}
BUILD_ROOT=${BUILD_ROOT:-${XDG_STATE_HOME:-${HOME:-/tmp}/.local/state}/ModSecurity-conector-build}
PATCHED_ROOT=${LIGHTTPD_PATCHED_ROOT:-$BUILD_ROOT/lighttpd-core-patched}
CORE_BIN=$PATCHED_ROOT/stage/bin/lighttpd
MODULE_PATH=$PATCHED_ROOT/stage/modules/mod_msconnector.so
PROXY_MODULE_PATH=$PATCHED_ROOT/stage/modules/mod_proxy.so
HOST_MANIFEST=$PATCHED_ROOT/patched-host-build-info.txt
SMOKE_DIR=${LIGHTTPD_PATCHED_SMOKE_DIR:-$PATCHED_ROOT/smoke}
SMOKE_PORT=${LIGHTTPD_SMOKE_PORT:-18084}
RULES_FILE=${MSCONNECTOR_RULES_FILE:-${RULES_FILE:-$FRAMEWORK_ROOT/tests/rules/no-crs-baseline.conf}}
PYTHON_BIN=${PYTHON:-python3}
: "${NO_CRS_RUN_ID:?NO_CRS_RUN_ID is required}"
MSCONNECTOR_CRS_RUNTIME=${MSCONNECTOR_CRS_RUNTIME:-0}
LIGHTTPD_EXPOSE_HOST_TRANSACTION_ID=${LIGHTTPD_EXPOSE_HOST_TRANSACTION_ID:-$MSCONNECTOR_CRS_RUNTIME}
SYNCHRONIZED_UPSTREAM=$FRAMEWORK_ROOT/tests/runners/synchronized_upstream.py
NO_CRS_FIXTURE_IO=$SCRIPT_DIR/no_crs_fixture_descriptor_io.py
FIXTURE_RUNTIME_ROOT=${LIGHTTPD_NO_CRS_FIXTURE_ROOT:-}
FIRST_BYTE_METADATA=$SCRIPT_DIR/write_patched_first_byte_metadata.py
RESULT_WRITER=$SCRIPT_DIR/write_patched_lifecycle_results.py
RESULTS_PATH=$SMOKE_DIR/results.jsonl
SUMMARY_PATH=$SMOKE_DIR/runtime-summary.txt
EVENT_PATH=$SMOKE_DIR/events.jsonl
ERROR_LOG=$SMOKE_DIR/lighttpd-error.log
SERVER_STDOUT=$SMOKE_DIR/runtime-smoke.stdout
SERVER_STDERR=$SMOKE_DIR/runtime-smoke.stderr
FIRST_BYTE_EVIDENCE=${FULL_LIFECYCLE_EVIDENCE_OUTPUT:-$SMOKE_DIR/first-byte-evidence.json}
FIRST_BYTE_DIR=$SMOKE_DIR/first-byte
FIXTURE_BASENAME=
FIXTURE_IDENTITY=
FIXTURE_DIR_OWNED=0
P4_CONTENT_LENGTH_EVENTS=$SMOKE_DIR/phase4-content-length-events.jsonl
P4_CHUNKED_EVENTS=$SMOKE_DIR/phase4-chunked-events.jsonl
P4_BARRIER_EVENTS=$SMOKE_DIR/phase4-barrier-events.jsonl
P4_PROJECTED_EVENTS=$SMOKE_DIR/phase4-barrier-eos-events.jsonl
P4_SUMMARY_JSON=$SMOKE_DIR/phase4-safe-summary.json
CRS_EVIDENCE_DIR=$SMOKE_DIR/crs-request-evidence
HOST_TRANSACTION_EVIDENCE_DIR=$SMOKE_DIR/host-transaction-evidence
CRS_RESPONSE_TRANSACTION_HEADER=X-Msconnector-Host-Transaction-Id
SERVER_PID=
SERVER_PID_TOKEN=
FIXTURE_PID=
FIXTURE_PID_TOKEN=
BARRIER_PID=
BARRIER_PID_TOKEN=
FIRST_BYTE_CLIENT_PID=
FIRST_BYTE_CLIENT_PID_TOKEN=
CRS_UPSTREAM_PID=
CRS_UPSTREAM_PID_TOKEN=
CRS_UPSTREAM_PORT=
CRS_UPSTREAM_READY=
BARRIER_RELEASE_FILE=
HTTP_STATUS_FORMAT='%{http_code}'
DIAGNOSTIC_LINES='1,200p'
CHILD_STOP_ATTEMPTS=50
CHILD_STOP_DELAY=0.1

blocked() {
    reason=$1
    printf 'lighttpd_patched_full_lifecycle: BLOCKED: %s\n' "$reason" >&2
    exit 77
}

case "$MSCONNECTOR_CRS_RUNTIME" in
    0|1) ;;
    *) blocked "MSCONNECTOR_CRS_RUNTIME must be 0 or 1" ;;
esac
case "$LIGHTTPD_EXPOSE_HOST_TRANSACTION_ID" in
    0|1) ;;
    *) blocked "LIGHTTPD_EXPOSE_HOST_TRANSACTION_ID must be 0 or 1" ;;
esac
if [ "$MSCONNECTOR_CRS_RUNTIME" = 0 ]; then
    [ "${LIGHTTPD_NO_CRS_FIXTURE_NAMESPACE_ACTIVE:-}" = 1 ] || \
        blocked "No-CRS entity fixture requires the private Mount/PID namespace launcher"
    case "$FIXTURE_RUNTIME_ROOT" in
        /tmp/msconnector-lighttpd-no-crs-fixture) ;;
        *) blocked "No-CRS entity fixture root is not the fixed private namespace mount" ;;
    esac
else
    [ -z "$FIXTURE_RUNTIME_ROOT" ] || \
        blocked "CRS runtime must not receive a No-CRS fixture namespace root"
fi

fail() {
    reason=$1
    printf 'lighttpd_patched_full_lifecycle: FAIL %s\n' "$reason" >&2
    exit 1
}

verify_runtime_output_paths() {
    "$PYTHON_BIN" - "$SCRIPT_DIR" "$SMOKE_DIR" "$FIRST_BYTE_EVIDENCE" \
        "$MSCONNECTOR_CRS_RUNTIME" "$CRS_EVIDENCE_DIR" \
        "$LIGHTTPD_EXPOSE_HOST_TRANSACTION_ID" "$HOST_TRANSACTION_EVIDENCE_DIR" <<'PY'
from pathlib import Path
import sys

sys.path.insert(0, sys.argv[1])
from safe_runtime_output import safe_output_path, verified_runtime_output_root

root = verified_runtime_output_root(Path(sys.argv[2]))
safe_output_path(root, Path(sys.argv[3]), "first-byte evidence output")
if sys.argv[4] == "1":
    evidence_dir = Path(sys.argv[5])
    for name in (
        "allow.trace",
        "allow.response.headers",
        "block.trace",
        "block.response.headers",
        "bypass.trace",
        "bypass.response.headers",
    ):
        safe_output_path(root, evidence_dir / name, f"CRS request evidence {name}")
if sys.argv[6] == "1":
    evidence_dir = Path(sys.argv[7])
    for name in (
        "p1-allow.response.headers",
        "p1-deny.response.headers",
        "p2-deny.response.headers",
        "p3-deny.response.headers",
    ):
        safe_output_path(root, evidence_dir / name, f"host transaction response evidence {name}")
PY
}

manifest_value() {
    key=$1
    sed -n "s/^$key=//p" "$HOST_MANIFEST" | sed -n '1p'
}

owned_child_start_token() {
    child_pid=$1
    case "$child_pid" in
        ''|*[!0-9]*) return 1 ;;
        *) ;;
    esac
    [ -r "/proc/$child_pid/stat" ] || return 1
    child_token=$(awk '{ print $22 }' "/proc/$child_pid/stat") || return 1
    case "$child_token" in
        ''|*[!0-9]*) return 1 ;;
        *) ;;
    esac
    printf '%s\n' "$child_token"
}

owned_child_is_current() {
    child_pid=$1
    expected_token=$2
    current_token=$(owned_child_start_token "$child_pid") || return 1
    [ "$current_token" = "$expected_token" ]
}

owned_child_is_zombie() {
    child_pid=$1
    [ -r "/proc/$child_pid/stat" ] || return 1
    child_state=$(awk '{ print $3 }' "/proc/$child_pid/stat") || return 1
    [ "$child_state" = Z ]
}

wait_for_owned_child_stop() {
    child_pid=$1
    child_token=$2
    child_label=$3
    child_attempt=0
    while [ "$child_attempt" -lt "$CHILD_STOP_ATTEMPTS" ]; do
        if ! kill -0 "$child_pid" 2>/dev/null; then
            return 0
        fi
        if ! owned_child_is_current "$child_pid" "$child_token"; then
            printf 'lighttpd_patched_full_lifecycle: refusing to signal a changed %s PID %s\n' \
                "$child_label" "$child_pid" >&2
            return 1
        fi
        if owned_child_is_zombie "$child_pid"; then
            return 0
        fi
        child_attempt=$((child_attempt + 1))
        sleep "$CHILD_STOP_DELAY"
    done
    return 1
}

stop_child() {
    child_pid=$1
    child_token=$2
    child_label=$3
    [ -n "$child_pid" ] || return 0
    case "$child_token" in
        ''|*[!0-9]*)
            printf 'lighttpd_patched_full_lifecycle: missing owned-process identity for %s PID %s\n' \
                "$child_label" "$child_pid" >&2
            return 1
            ;;
        *) ;;
    esac
    if kill -0 "$child_pid" 2>/dev/null; then
        if ! owned_child_is_current "$child_pid" "$child_token"; then
            printf 'lighttpd_patched_full_lifecycle: refusing to signal a changed %s PID %s\n' \
                "$child_label" "$child_pid" >&2
            return 1
        fi
        if ! kill -TERM "$child_pid" 2>/dev/null && \
            kill -0 "$child_pid" 2>/dev/null && ! owned_child_is_zombie "$child_pid"; then
            printf 'lighttpd_patched_full_lifecycle: owned %s PID %s did not accept SIGTERM\n' \
                "$child_label" "$child_pid" >&2
            return 1
        fi
    fi
    if ! wait_for_owned_child_stop "$child_pid" "$child_token" "$child_label" && \
        kill -0 "$child_pid" 2>/dev/null; then
        if ! owned_child_is_current "$child_pid" "$child_token"; then
            printf 'lighttpd_patched_full_lifecycle: refusing to signal a changed %s PID %s\n' \
                "$child_label" "$child_pid" >&2
            return 1
        fi
        if ! kill -KILL "$child_pid" 2>/dev/null && \
            kill -0 "$child_pid" 2>/dev/null && ! owned_child_is_zombie "$child_pid"; then
            printf 'lighttpd_patched_full_lifecycle: owned %s PID %s did not accept SIGKILL\n' \
                "$child_label" "$child_pid" >&2
            return 1
        fi
        if ! wait_for_owned_child_stop "$child_pid" "$child_token" "$child_label"; then
            printf 'lighttpd_patched_full_lifecycle: owned %s PID %s did not stop within the bounded timeout\n' \
                "$child_label" "$child_pid" >&2
            return 1
        fi
    fi
    child_status=0
    if wait "$child_pid" 2>/dev/null; then
        child_status=0
    else
        child_status=$?
    fi
    case "$child_status" in
        0|137|143) return 0 ;;
        *)
            printf 'lighttpd_patched_full_lifecycle: owned %s PID %s exited with status %s\n' \
                "$child_label" "$child_pid" "$child_status" >&2
            return 1
            ;;
    esac
}

release_barrier() {
    [ -n "$BARRIER_RELEASE_FILE" ] || return 0
    if ! : > "$BARRIER_RELEASE_FILE" 2>/dev/null; then
        printf 'lighttpd_patched_full_lifecycle: could not release owned synchronized upstream barrier\n' >&2
        return 1
    fi
}

fixture_no_crs_io() {
    "$PYTHON_BIN" "$NO_CRS_FIXTURE_IO" "$@"
}

prepare_no_crs_fixture_directory() {
    fixture_no_crs_io create --runtime-output-root "$FIXTURE_RUNTIME_ROOT"
}

verify_no_crs_fixture_directory() {
    fixture_no_crs_io verify \
        --runtime-output-root "$FIXTURE_RUNTIME_ROOT" \
        --fixture-name "$FIXTURE_BASENAME" \
        --fixture-identity "$FIXTURE_IDENTITY"
}

cleanup() {
    cleanup_server_pid=$SERVER_PID
    cleanup_server_token=$SERVER_PID_TOKEN
    cleanup_upstream_pid=$CRS_UPSTREAM_PID
    cleanup_upstream_token=$CRS_UPSTREAM_PID_TOKEN
    cleanup_failed=0
    if ! release_barrier; then
        cleanup_failed=1
    fi
    if stop_child "$SERVER_PID" "$SERVER_PID_TOKEN" "Lighttpd"; then
        SERVER_PID=
        SERVER_PID_TOKEN=
    else
        cleanup_failed=1
    fi
    if stop_child "$FIXTURE_PID" "$FIXTURE_PID_TOKEN" "HTTP/1.1 fixture upstream"; then
        FIXTURE_PID=
        FIXTURE_PID_TOKEN=
    else
        cleanup_failed=1
    fi
    if stop_child "$BARRIER_PID" "$BARRIER_PID_TOKEN" "synchronized upstream"; then
        BARRIER_PID=
        BARRIER_PID_TOKEN=
    else
        cleanup_failed=1
    fi
    if stop_child "$FIRST_BYTE_CLIENT_PID" "$FIRST_BYTE_CLIENT_PID_TOKEN" "synchronized HTTP/1.1 client"; then
        FIRST_BYTE_CLIENT_PID=
        FIRST_BYTE_CLIENT_PID_TOKEN=
    else
        cleanup_failed=1
    fi
    if stop_child "$CRS_UPSTREAM_PID" "$CRS_UPSTREAM_PID_TOKEN" "CRS control upstream"; then
        CRS_UPSTREAM_PID=
        CRS_UPSTREAM_PID_TOKEN=
    else
        cleanup_failed=1
    fi
    if [ "$FIXTURE_DIR_OWNED" = 1 ]; then
        # The fixture is mounted only in the private Mount/PID namespace.
        # Do not use a check-then-rmdir cleanup path here: namespace teardown
        # releases the tmpfs after every normal, error, timeout, and signal
        # path, including a controller crash via the supervisor PDeathSIG.
        FIXTURE_DIR_OWNED=0
        FIXTURE_BASENAME=
        FIXTURE_IDENTITY=
    fi
    if [ "$MSCONNECTOR_CRS_RUNTIME" = 1 ] && \
        { [ -n "$cleanup_server_pid" ] || [ -n "$cleanup_upstream_pid" ] || \
            [ -n "$CRS_UPSTREAM_READY" ]; } && \
        ! verify_crs_cleanup \
            "$cleanup_server_pid" "$cleanup_server_token" \
            "$cleanup_upstream_pid" "$cleanup_upstream_token"; then
        cleanup_failed=1
    fi
    if [ "$cleanup_failed" -ne 0 ]; then
        printf 'lighttpd_patched_full_lifecycle: owned process cleanup did not complete cleanly\n' >&2
    fi
    return "$cleanup_failed"
}

on_signal() {
    signal_status=$1
    if ! cleanup; then
        printf 'lighttpd_patched_full_lifecycle: cleanup failed while handling signal\n' >&2
    fi
    trap - EXIT HUP INT TERM
    exit "$signal_status"
}

verify_released_listener() {
    listener_port=$1
    listener_label=$2
    case "$listener_port" in
        ''|*[!0-9]*)
            printf 'lighttpd_patched_full_lifecycle: invalid %s port: %s\n' \
                "$listener_label" "$listener_port" >&2
            return 1
            ;;
        *) ;;
    esac
    if [ "$listener_port" -lt 1 ] || [ "$listener_port" -gt 65535 ]; then
        printf 'lighttpd_patched_full_lifecycle: invalid %s port: %s\n' \
            "$listener_label" "$listener_port" >&2
        return 1
    fi
    if ! command -v ss >/dev/null 2>&1; then
        printf 'lighttpd_patched_full_lifecycle: ss is required to verify %s listener cleanup\n' \
            "$listener_label" >&2
        return 1
    fi
    if listener_rows=$(ss -H -ltn "sport = :$listener_port" 2>/dev/null); then
        :
    else
        printf 'lighttpd_patched_full_lifecycle: could not inspect %s listener cleanup\n' \
            "$listener_label" >&2
        return 1
    fi
    if [ -n "$listener_rows" ]; then
        printf 'lighttpd_patched_full_lifecycle: %s listener remains on port %s\n' \
            "$listener_label" "$listener_port" >&2
        return 1
    fi
}

verify_crs_cleanup() {
    crs_server_pid=$1
    crs_server_token=$2
    crs_upstream_pid=$3
    crs_upstream_token=$4
    crs_upstream_port=$CRS_UPSTREAM_PORT
    if [ -n "$crs_server_pid" ] && owned_child_is_current "$crs_server_pid" "$crs_server_token"; then
        printf 'lighttpd_patched_full_lifecycle: Lighttpd PID %s remains after CRS cleanup\n' \
            "$crs_server_pid" >&2
        return 1
    fi
    if [ -n "$crs_upstream_pid" ] && owned_child_is_current "$crs_upstream_pid" "$crs_upstream_token"; then
        printf 'lighttpd_patched_full_lifecycle: CRS upstream PID %s remains after cleanup\n' \
            "$crs_upstream_pid" >&2
        return 1
    fi
    if [ -e "$SMOKE_DIR/lighttpd.pid" ]; then
        printf 'lighttpd_patched_full_lifecycle: CRS cleanup left a Lighttpd pid file\n' >&2
        return 1
    fi
    if [ -z "$crs_upstream_port" ] && [ -n "$CRS_UPSTREAM_READY" ] && [ -e "$CRS_UPSTREAM_READY" ]; then
        crs_upstream_port=$(ready_port "$CRS_UPSTREAM_READY") || {
            printf 'lighttpd_patched_full_lifecycle: CRS upstream control file has no valid port during cleanup\n' >&2
            return 1
        }
    fi
    if [ -n "$CRS_UPSTREAM_READY" ] && [ -e "$CRS_UPSTREAM_READY" ] && \
        ! rm -f "$CRS_UPSTREAM_READY"; then
        printf 'lighttpd_patched_full_lifecycle: could not remove CRS upstream control file\n' >&2
        return 1
    fi
    if [ -n "$CRS_UPSTREAM_READY" ] && [ -e "$CRS_UPSTREAM_READY" ]; then
        printf 'lighttpd_patched_full_lifecycle: CRS upstream control file remains after cleanup\n' >&2
        return 1
    fi
    if ! verify_released_listener "$SMOKE_PORT" "Lighttpd"; then
        return 1
    fi
    if [ -n "$crs_upstream_port" ] && \
        ! verify_released_listener "$crs_upstream_port" "CRS control upstream"; then
        return 1
    fi
}

trap cleanup EXIT
trap 'on_signal 129' HUP
trap 'on_signal 130' INT
trap 'on_signal 143' TERM

wait_for_file() {
    path=$1
    label=$2
    child_pid=$3
    attempt=0
    while [ "$attempt" -lt 30 ]; do
        [ -f "$path" ] && return 0
        if ! kill -0 "$child_pid" 2>/dev/null; then
            blocked "$label exited before publishing its control record"
        fi
        attempt=$((attempt + 1))
        sleep 1
    done
    blocked "$label did not publish its control record"
}

ready_port() {
    metadata_path=$1
    "$PYTHON_BIN" - "$metadata_path" <<'PY'
import json
import sys

value = json.load(open(sys.argv[1], encoding="utf-8"))
port = value.get("upstream_port")
if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
    raise SystemExit(1)
print(port)
PY
}

event_cursor() {
    if [ -f "$EVENT_PATH" ]; then
        awk 'END { print NR + 0 }' "$EVENT_PATH"
    else
        printf '0\n'
    fi
}

snapshot_events() {
    first_line=$1
    destination=$2
    last_line=$(event_cursor)
    : > "$destination"
    if [ "$last_line" -gt "$first_line" ]; then
        sed -n "$((first_line + 1)),$last_line p" "$EVENT_PATH" > "$destination"
    fi
}

prepare_private_response_evidence() {
    evidence_dir=$1
    shift
    [ "$#" -gt 0 ] || fail "private response evidence has no artifact names"
    # Curl writes these files directly, so provision their private parent
    # before the requests and reject symlink/non-regular leftovers rather
    # than accepting a path controlled outside this run root.
    umask 077
    "$PYTHON_BIN" - "$SCRIPT_DIR" "$SMOKE_DIR" "$evidence_dir" "$@" <<'PY'
import os
import stat
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1])
from safe_runtime_output import safe_output_path, verified_runtime_output_root

root = verified_runtime_output_root(Path(sys.argv[2]))
evidence_dir = Path(sys.argv[3])
names = sys.argv[4:]
if not names or len(set(names)) != len(names):
    raise SystemExit("private response evidence needs unique artifact names")
for name in names:
    if Path(name).name != name:
        raise SystemExit(f"private response evidence name is not a file name: {name}")
    destination = safe_output_path(root, evidence_dir / name,
                                   f"private response evidence {name}")
    if destination.exists():
        mode = destination.lstat().st_mode
        if destination.is_symlink() or not stat.S_ISREG(mode):
            raise SystemExit(f"private response evidence is not a regular file: {destination}")
        destination.unlink()

# Curl owns the leaf artifacts, but the harness owns this parent.  Open the
# already-validated directory without following links before tightening it,
# so untrusted local users cannot inspect or replace a request trace between
# curl's write and the subsequent correlation check.
directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
if not getattr(os, "O_DIRECTORY", 0) or not getattr(os, "O_NOFOLLOW", 0):
    raise SystemExit("private response evidence requires O_DIRECTORY and O_NOFOLLOW")
descriptor = os.open(evidence_dir, directory_flags)
try:
    details = os.fstat(descriptor)
    if not stat.S_ISDIR(details.st_mode) or details.st_uid != os.geteuid():
        raise SystemExit("private response evidence directory is not an owned directory")
    os.fchmod(descriptor, 0o700)
finally:
    os.close(descriptor)
PY
}

prepare_crs_request_evidence() {
    prepare_private_response_evidence "$CRS_EVIDENCE_DIR" \
        allow.trace allow.response.headers \
        block.trace block.response.headers \
        bypass.trace bypass.response.headers
}

prepare_host_transaction_evidence() {
    prepare_private_response_evidence "$HOST_TRANSACTION_EVIDENCE_DIR" \
        p1-allow.response.headers p1-deny.response.headers \
        p2-deny.response.headers p3-deny.response.headers
}

case "$SMOKE_DIR" in
    /*) ;;
    *) blocked "LIGHTTPD_PATCHED_SMOKE_DIR must be absolute" ;;
esac
case "$RULES_FILE" in
    /*) ;;
    *) blocked "MSCONNECTOR_RULES_FILE must be absolute" ;;
esac
case "$FIRST_BYTE_EVIDENCE" in
    /*) ;;
    *) blocked "FULL_LIFECYCLE_EVIDENCE_OUTPUT must be absolute" ;;
esac
[ -f "$RULES_FILE" ] || blocked "canonical rules file is missing: $RULES_FILE"
[ -x "$CORE_BIN" ] || blocked "patched lighttpd binary is missing: $CORE_BIN"
[ -f "$MODULE_PATH" ] || blocked "patched module is missing: $MODULE_PATH"
[ -f "$PROXY_MODULE_PATH" ] || blocked "patched mod_proxy module is missing: $PROXY_MODULE_PATH"
[ -f "$HOST_MANIFEST" ] || blocked "patched host manifest is missing: $HOST_MANIFEST"
[ -f "$SYNCHRONIZED_UPSTREAM" ] || blocked "synchronized upstream helper is missing: $SYNCHRONIZED_UPSTREAM"
[ -f "$NO_CRS_FIXTURE_IO" ] || blocked "descriptor-bound HTTP/1.1 fixture helper is missing"
[ -f "$FIRST_BYTE_METADATA" ] || blocked "Lighttpd first-byte metadata helper is missing"
[ -f "$RESULT_WRITER" ] || blocked "Lighttpd result writer is missing"
command -v curl >/dev/null 2>&1 || blocked "curl is required"
command -v "$PYTHON_BIN" >/dev/null 2>&1 || blocked "python3 is required"
verify_runtime_output_paths || blocked "Lighttpd runtime output paths are unsafe"

MODSECURITY_LIB_DIR=$(manifest_value modsecurity_lib_dir)
[ -n "$MODSECURITY_LIB_DIR" ] || blocked "patched host manifest has no libmodsecurity directory"
[ -f "$MODSECURITY_LIB_DIR/libmodsecurity.so" ] || blocked "libmodsecurity is missing"

mkdir -p "$SMOKE_DIR" "$FIRST_BYTE_DIR"
if [ "$MSCONNECTOR_CRS_RUNTIME" = 0 ]; then
    fixture_directory_record=$(prepare_no_crs_fixture_directory) || \
        blocked "could not create a private No-CRS entity fixture directory"
    fixture_tab=$(printf '\t')
    IFS=$fixture_tab read -r fixture_name fixture_identity fixture_extra <<EOF
$fixture_directory_record
EOF
    case "$fixture_name" in
        .entity-fixtures-?*) ;;
        *) blocked "No-CRS fixture helper returned an invalid directory name" ;;
    esac
    case "$fixture_name" in
        *[!A-Za-z0-9._-]*) blocked "No-CRS fixture helper returned an unsafe directory name" ;;
        *) ;;
    esac
    case "$fixture_identity" in
        *:*) ;;
        *) blocked "No-CRS fixture helper returned an invalid directory identity" ;;
    esac
    fixture_device=${fixture_identity%%:*}
    fixture_inode=${fixture_identity#*:}
    case "$fixture_device" in
        ''|*[!0-9]*) blocked "No-CRS fixture helper returned an invalid device identity" ;;
        *) ;;
    esac
    case "$fixture_inode" in
        ''|*[!0-9]*) blocked "No-CRS fixture helper returned an invalid inode identity" ;;
        *) ;;
    esac
    [ -z "$fixture_extra" ] || \
        blocked "No-CRS fixture helper returned an ambiguous identity record"
    FIXTURE_BASENAME=$fixture_name
    FIXTURE_IDENTITY=$fixture_identity
    # Cleanup may act on this directory only after both the random direct
    # child name and its kernel identity token were validated above.
    FIXTURE_DIR_OWNED=1
    verify_no_crs_fixture_directory || \
        blocked "No-CRS fixture directory changed immediately after creation"
fi
for generated in \
    "$FIRST_BYTE_DIR/upstream-ready.json" \
    "$FIRST_BYTE_DIR/upstream-paused.json" \
    "$FIRST_BYTE_DIR/upstream-release" \
    "$FIRST_BYTE_DIR/upstream-server.json" \
    "$FIRST_BYTE_DIR/client-body.bin" \
    "$FIRST_BYTE_DIR/host-metadata.json"; do
    rm -f "$generated"
done

CRS_UPSTREAM_READY=$SMOKE_DIR/crs-upstream-ready.json
rm -f "$CRS_UPSTREAM_READY"
if [ "$MSCONNECTOR_CRS_RUNTIME" = 0 ]; then
fixture_no_crs_io serve \
    --runtime-output-root "$FIXTURE_RUNTIME_ROOT" \
    --fixture-name "$FIXTURE_BASENAME" \
    --fixture-identity "$FIXTURE_IDENTITY" \
    --timeout 30 &
FIXTURE_PID=$!
FIXTURE_PID_TOKEN=$(owned_child_start_token "$FIXTURE_PID") || \
    blocked "HTTP/1.1 fixture did not start as a verifiable owned process"
FIXTURE_PORT=$(fixture_no_crs_io wait-ready \
    --runtime-output-root "$FIXTURE_RUNTIME_ROOT" \
    --fixture-name "$FIXTURE_BASENAME" \
    --fixture-identity "$FIXTURE_IDENTITY" \
    --fixture-pid "$FIXTURE_PID" \
    --timeout 30) || \
    blocked "HTTP/1.1 entity fixture ready record has no valid port"

BARRIER_RELEASE_FILE=$FIRST_BYTE_DIR/upstream-release
"$PYTHON_BIN" "$SYNCHRONIZED_UPSTREAM" --serve \
    --control-root "$SMOKE_DIR" \
    --ready-file "$FIRST_BYTE_DIR/upstream-ready.json" \
    --paused-file "$FIRST_BYTE_DIR/upstream-paused.json" \
    --release-file "$BARRIER_RELEASE_FILE" \
    --server-evidence-file "$FIRST_BYTE_DIR/upstream-server.json" \
    --timeout 30 >"$FIRST_BYTE_DIR/upstream.stdout" \
    2>"$FIRST_BYTE_DIR/upstream.stderr" &
BARRIER_PID=$!
BARRIER_PID_TOKEN=$(owned_child_start_token "$BARRIER_PID") || \
    blocked "synchronized upstream did not start as a verifiable owned process"
wait_for_file "$FIRST_BYTE_DIR/upstream-ready.json" "synchronized upstream" "$BARRIER_PID"
BARRIER_PORT=$(ready_port "$FIRST_BYTE_DIR/upstream-ready.json") || \
    blocked "synchronized upstream ready record has no valid port"

else
    (
        exec "$PYTHON_BIN" - "$CRS_UPSTREAM_READY" <<'PY'
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import os
import sys
import tempfile

ready_path = Path(sys.argv[1])

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler API
        body = b"OK"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        return

server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
payload = json.dumps({"schema_version": 1, "upstream_host": "127.0.0.1", "upstream_port": server.server_address[1]}) + "\n"
fd, temporary = tempfile.mkstemp(prefix="crs-upstream-ready.", dir=ready_path.parent)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, ready_path)
finally:
    try:
        os.unlink(temporary)
    except FileNotFoundError:
        pass
server.serve_forever()
PY
    ) >"$SMOKE_DIR/crs-upstream.stdout" 2>"$SMOKE_DIR/crs-upstream.stderr" &
    CRS_UPSTREAM_PID=$!
    CRS_UPSTREAM_PID_TOKEN=$(owned_child_start_token "$CRS_UPSTREAM_PID") || \
        blocked "CRS control upstream did not start as a verifiable owned process"
    wait_for_file "$CRS_UPSTREAM_READY" "CRS control upstream" "$CRS_UPSTREAM_PID"
    CRS_UPSTREAM_PORT=$(ready_port "$CRS_UPSTREAM_READY") || \
        blocked "CRS control upstream ready record has no valid port"
    # The CRS branch does not run the unused full-lifecycle P4 helpers.  The
    # generated P4 routes remain syntactically valid but are not selected.
    BARRIER_PORT=$CRS_UPSTREAM_PORT
    FIXTURE_PORT=$CRS_UPSTREAM_PORT
fi

LIGHTTPD_CONFIG=$( \
    LIGHTTPD_PATCHED_ROOT="$PATCHED_ROOT" \
    LIGHTTPD_PATCHED_SMOKE_DIR="$SMOKE_DIR" \
    LIGHTTPD_SMOKE_PORT="$SMOKE_PORT" \
    LIGHTTPD_PATCHED_REQUEST_BODY_MODE=streaming \
    LIGHTTPD_PATCHED_RESPONSE_BODY_MODE=streaming \
    LIGHTTPD_PATCHED_RESPONSE_HEADER_MARKER=block \
    LIGHTTPD_EXPOSE_HOST_TRANSACTION_ID="$LIGHTTPD_EXPOSE_HOST_TRANSACTION_ID" \
    LIGHTTPD_PROXY_BARRIER_PORT="$BARRIER_PORT" \
    LIGHTTPD_PROXY_FIXTURE_PORT="$FIXTURE_PORT" \
    MSCONNECTOR_RULES_FILE="$RULES_FILE" \
    sh "$SCRIPT_DIR/prepare_patched_lifecycle_smoke.sh"
)

if [ "$MSCONNECTOR_CRS_RUNTIME" = 1 ]; then
    # The focused CRS route uses the canonical root URI.  The existing
    # lifecycle config only maps /p4 routes, so add a private run-local root
    # proxy atomically before validating and starting Lighttpd.
    "$PYTHON_BIN" - "$LIGHTTPD_CONFIG" "$SMOKE_DIR" "$CRS_UPSTREAM_PORT" <<'PY'
from pathlib import Path
import os
import sys
import tempfile

config_path, smoke_dir, barrier_port = map(Path, sys.argv[1:])
if config_path.is_symlink() or not config_path.is_file():
    raise SystemExit("CRS config must be a regular non-symlink file")
if config_path.parent != Path(smoke_dir):
    raise SystemExit("CRS config must be directly below the private smoke root")
port = barrier_port.name
if not port.isdigit() or not 1 <= int(port) <= 65535:
    raise SystemExit("invalid synchronized upstream port")
text = config_path.read_text(encoding="utf-8")
needle = "proxy.server = (\n"
route = f'  "/" => ( ( "host" => "127.0.0.1", "port" => {port} ) ),\n'
if needle not in text:
    raise SystemExit("generated Lighttpd config has no proxy.server declaration")
if '  "/" =>' in text:
    raise SystemExit("generated Lighttpd config unexpectedly already has a root proxy")
fd, temporary = tempfile.mkstemp(prefix="lighttpd-crs-config.", dir=config_path.parent)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(text.replace(needle, needle + route, 1))
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, config_path)
finally:
    try:
        os.unlink(temporary)
    except FileNotFoundError:
        pass
PY
fi

LD_LIBRARY_PATH="$MODSECURITY_LIB_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export LD_LIBRARY_PATH
MODULE_DIR=$(dirname "$MODULE_PATH")
if ! "$CORE_BIN" -m "$MODULE_DIR" -tt -f "$LIGHTTPD_CONFIG" \
    >"$SMOKE_DIR/runtime-config-check.stdout" \
    2>"$SMOKE_DIR/runtime-config-check.stderr"; then
    sed -n "$DIAGNOSTIC_LINES" "$SMOKE_DIR/runtime-config-check.stderr" >&2
    fail "config-load"
fi

: > "$ERROR_LOG"
"$CORE_BIN" -D -m "$MODULE_DIR" -f "$LIGHTTPD_CONFIG" \
    >"$SERVER_STDOUT" 2>"$SERVER_STDERR" &
SERVER_PID=$!
SERVER_PID_TOKEN=$(owned_child_start_token "$SERVER_PID") || \
    blocked "Lighttpd did not start as a verifiable owned process"
server_ready=0
CRS_HOST=crs-runtime.test
for attempt in 1 2 3 4 5 6 7 8 9 10; do
    if "$PYTHON_BIN" - "$SMOKE_PORT" <<'PY'
import socket
import sys

port = int(sys.argv[1])
with socket.create_connection(("127.0.0.1", port), timeout=1):
    pass
PY
    then
        server_ready=1
        break
    fi
    sleep 1
done
[ "$server_ready" -eq 1 ] || {
    sed -n "$DIAGNOSTIC_LINES" "$SERVER_STDERR" >&2
    fail "process did not become ready"
}
kill -0 "$SERVER_PID" 2>/dev/null || {
    sed -n "$DIAGNOSTIC_LINES" "$SERVER_STDERR" >&2
    fail "process did not remain alive"
}

base_url=http://127.0.0.1:$SMOKE_PORT/

run_crs_runtime() {
    # This branch deliberately stops after the focused CRS host path.  The
    # existing lifecycle below remains the No-CRS/full-streaming contract and
    # is not reused with different expected values.
    crs_allow_uri='/?id=42'
    crs_block_uri='/?id=1%20UNION%20SELECT%20password%20FROM%20users'
    crs_bypass_uri='/?id=1%20uNiOn%20SeLeCt%20password%20FrOm%20users'
    crs_allow_request_id="${NO_CRS_RUN_ID}-allow"
    crs_block_request_id="${NO_CRS_RUN_ID}-block"
    crs_bypass_request_id="${NO_CRS_RUN_ID}-bypass"
    crs_status_format=$HTTP_STATUS_FORMAT
    crs_base_url=${base_url%/}
    crs_allow_trace=$CRS_EVIDENCE_DIR/allow.trace
    crs_allow_headers=$CRS_EVIDENCE_DIR/allow.response.headers
    crs_block_trace=$CRS_EVIDENCE_DIR/block.trace
    crs_block_headers=$CRS_EVIDENCE_DIR/block.response.headers
    crs_bypass_trace=$CRS_EVIDENCE_DIR/bypass.trace
    crs_bypass_headers=$CRS_EVIDENCE_DIR/bypass.response.headers

    prepare_crs_request_evidence

    crs_allow_status=$(curl --http1.1 --no-keepalive --silent --show-error --path-as-is \
        --connect-timeout 5 --max-time 30 --trace-ascii "$crs_allow_trace" \
        --dump-header "$crs_allow_headers" --output /dev/null \
        --write-out "$crs_status_format" --request GET \
        --header "Host: $CRS_HOST" \
        --header "X-Framework-Run-ID: $NO_CRS_RUN_ID" \
        --header "X-Framework-Request-ID: $crs_allow_request_id" \
        "$crs_base_url$crs_allow_uri")
    crs_block_status=$(curl --http1.1 --no-keepalive --silent --show-error --path-as-is \
        --connect-timeout 5 --max-time 30 --trace-ascii "$crs_block_trace" \
        --dump-header "$crs_block_headers" --output /dev/null \
        --write-out "$crs_status_format" --request GET \
        --header "Host: $CRS_HOST" \
        --header "X-Framework-Run-ID: $NO_CRS_RUN_ID" \
        --header "X-Framework-Request-ID: $crs_block_request_id" \
        "$crs_base_url$crs_block_uri")
    crs_bypass_status=$(curl --http1.1 --no-keepalive --silent --show-error --path-as-is \
        --connect-timeout 5 --max-time 30 --trace-ascii "$crs_bypass_trace" \
        --dump-header "$crs_bypass_headers" --output /dev/null \
        --write-out "$crs_status_format" --request GET \
        --header "Host: $CRS_HOST" \
        --header "X-Framework-Run-ID: $NO_CRS_RUN_ID" \
        --header "X-Framework-Request-ID: $crs_bypass_request_id" \
        "$crs_base_url$crs_bypass_uri")

    [ "$crs_allow_status" = 200 ] || fail "crs_allow_status=$crs_allow_status expected=200"
    [ "$crs_block_status" = 403 ] || fail "crs_block_status=$crs_block_status expected=403"
    [ "$crs_bypass_status" = 403 ] || fail "crs_bypass_status=$crs_bypass_status expected=403"
    [ -s "$EVENT_PATH" ] || fail "CRS requests emitted no Common event"

    # Only observed fields from the real Common JSONL events are promoted.  In
    # particular, the rule id and transaction ids below are never copied from
    # the expected fixture; they must be present on the event for the exact
    # URI that curl sent through Lighttpd.
    "$PYTHON_BIN" - "$SCRIPT_DIR" "$SMOKE_DIR" "$EVENT_PATH" "$SERVER_STDERR" \
        "$CRS_RESPONSE_TRANSACTION_HEADER" "$crs_allow_uri" "$crs_block_uri" \
        "$crs_bypass_uri" "$NO_CRS_RUN_ID" "$crs_allow_request_id" \
        "$crs_block_request_id" "$crs_bypass_request_id" "$crs_allow_trace" \
        "$crs_allow_headers" "$crs_block_trace" "$crs_block_headers" \
        "$crs_bypass_trace" "$crs_bypass_headers" <<'PY' \
        >"$SUMMARY_PATH"
import json
import re
import stat
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1])
from safe_runtime_output import read_runtime_input_text, safe_input_path, verified_runtime_output_root

(
    script_dir,
    smoke_dir,
    event_path,
    raw_log_path,
    response_transaction_header,
    allow_uri,
    block_uri,
    bypass_uri,
    run_id,
    allow_request_id,
    block_request_id,
    bypass_request_id,
    allow_trace_path,
    allow_headers_path,
    block_trace_path,
    block_headers_path,
    bypass_trace_path,
    bypass_headers_path,
) = sys.argv[1:]
root = verified_runtime_output_root(Path(smoke_dir))
MAX_CRS_WIRE_EVIDENCE_BYTES = 65536

def read_artifact(path_value, label):
    path = safe_input_path(root, Path(path_value), label)
    return read_runtime_input_text(root, path, label)

def read_private_wire_artifact(path_value, label):
    path = safe_input_path(root, Path(path_value), label)
    details = path.lstat()
    if not stat.S_ISREG(details.st_mode) or stat.S_IMODE(details.st_mode) & 0o077:
        raise SystemExit(f"{label} must be a private regular runtime artifact")
    if details.st_size <= 0 or details.st_size > MAX_CRS_WIRE_EVIDENCE_BYTES:
        raise SystemExit(f"{label} exceeds the private wire-evidence size limit")
    return read_runtime_input_text(root, path, label)

events = []
for line_number, line in enumerate(read_artifact(event_path, "Common event JSONL").splitlines(), 1):
    if not line.strip():
        continue
    try:
        value = json.loads(line)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid Common event JSON at line {line_number}: {exc}")
    if isinstance(value, dict):
        events.append(value)
raw_log = read_artifact(raw_log_path, "raw ModSecurity log")

CURL_TRACE_SEND_HEADER = re.compile(r"^=> Send header, ([0-9]+) bytes \(0x[0-9a-fA-F]+\)$")
CURL_TRACE_DATA_ROW = re.compile(r"^([0-9a-fA-F]+): ?(.*)$")
CURL_TRACE_RECEIVE_HEADER = re.compile(r"^<= Recv header, [0-9]+ bytes \(0x[0-9a-fA-F]+\)$")
# curl 8.18 emits informational records as ``== Info: ...`` in the trace
# stream.  Accept only the documented printable record form; a bare ``*``
# line is a data/diagnostic row here and must not be allowed to bypass the
# contiguous request-byte validation below.
CURL_TRACE_INFO_LINE = re.compile(r"^== Info: [ -~]{1,256}$")
CURL_RESPONSE_STATUS = re.compile(r"^HTTP/1\.1 ([0-9]{3})(?: [ -~]*)?$")

def classify_unexpected_trace_record(line):
    if not line:
        return "blank trace record"
    if line.startswith("== Info:"):
        return "malformed info record"
    if any(ord(char) < 0x20 or ord(char) > 0x7E for char in line):
        return "nonprintable/control trace record"
    if line.startswith("* "):
        return "unsupported star trace record family"
    return "unsupported trace record family"

def parse_curl_request_lines(trace, case):
    trace_lines = trace.splitlines()
    send_headers = []
    for index, line in enumerate(trace_lines):
        match = CURL_TRACE_SEND_HEADER.fullmatch(line)
        if match is not None:
            send_headers.append((index, match))
    if len(send_headers) != 1:
        raise SystemExit(f"{case} curl trace needs exactly one outgoing header block")
    explicit_completions = sum(
        line in {"* Request completely sent off", "== Info: Request completely sent off"}
        for line in trace_lines
    )
    if explicit_completions > 1:
        raise SystemExit(f"{case} curl trace needs exactly one request exchange")
    start_index, declaration = send_headers[0]
    declared_length = int(declaration.group(1))
    rows = []
    completed = False
    for line in trace_lines[start_index + 1:]:
        if line in {"* Request completely sent off", "== Info: Request completely sent off"}:
            completed = True
            break
        # Curl's documented trace callback labels the first received HTTP
        # header as ``<= Recv header``. Older runners can transition directly
        # to that marker without an explicit request-complete info record.
        # It is a structural boundary only: the independent raw-header parser
        # below still validates the observed HTTP status and response fields.
        if CURL_TRACE_RECEIVE_HEADER.fullmatch(line):
            completed = True
            break
        # curl 8.18 may emit informational trace records with the ``== Info:``
        # prefix while the outgoing header is being flushed.  They carry no
        # request bytes; all byte rows remain subject to the contiguous offset
        # and declared-length checks below.
        if CURL_TRACE_INFO_LINE.fullmatch(line):
            continue
        row = CURL_TRACE_DATA_ROW.fullmatch(line)
        if row is None:
            reason = classify_unexpected_trace_record(line)
            raise SystemExit(
                f"{case} curl trace has an unexpected outgoing-header row ({reason})"
            )
        offset = int(row.group(1), 16)
        fragment = row.group(2)
        if not fragment.isascii() or any(not 0x20 <= ord(char) <= 0x7e for char in fragment):
            raise SystemExit(f"{case} curl trace has a non-ASCII outgoing-header fragment")
        rows.append((offset, fragment))
    if not completed or not rows:
        raise SystemExit(f"{case} curl trace has no completed outgoing-header block")

    logical_lines = []
    current_line = ""
    expected_offset = 0
    for index, (offset, fragment) in enumerate(rows):
        if offset != expected_offset:
            raise SystemExit(f"{case} curl trace has a non-contiguous outgoing-header offset")
        next_offset = rows[index + 1][0] if index + 1 < len(rows) else declared_length
        span = next_offset - offset
        visible_length = len(fragment)
        if span == visible_length:
            current_line += fragment
        elif span == visible_length + 2:
            current_line += fragment
            logical_lines.append(current_line)
            current_line = ""
        else:
            raise SystemExit(f"{case} curl trace has an invalid outgoing-header byte span")
        expected_offset = next_offset
    if expected_offset != declared_length or current_line or not logical_lines or logical_lines[-1] != "":
        raise SystemExit(f"{case} curl trace has an unterminated outgoing-header block")
    return logical_lines

def require_single_request_header(lines, case, name, value):
    matches = []
    for line in lines[1:-1]:
        header_name, separator, header_value = line.partition(":")
        if separator and header_name.lower() == name.lower():
            matches.append(header_value.strip())
    if matches != [value]:
        raise SystemExit(f"{case} curl trace has an invalid {name} request header")

def parse_single_response_headers(headers, case, expected_status):
    lines = headers.splitlines()
    if len(lines) < 2 or lines[-1] != "":
        raise SystemExit(f"{case} raw response headers lack one complete response block")
    status = CURL_RESPONSE_STATUS.fullmatch(lines[0])
    if status is None or status.group(1) != expected_status:
        raise SystemExit(f"{case} raw response headers have an unexpected HTTP status")
    parsed = []
    for line in lines[1:-1]:
        name, separator, value = line.partition(":")
        if (
            not separator
            or not name
            or not line.isascii()
            or any(not 0x20 <= ord(char) <= 0x7e for char in line)
        ):
            raise SystemExit(f"{case} raw response headers have an invalid header row")
        parsed.append((name.strip(), value.strip()))
    return parsed

def host_transaction_id(case, uri, request_id, expected_status, trace_path, headers_path):
    trace = read_private_wire_artifact(trace_path, f"{case} curl trace")
    headers = read_private_wire_artifact(headers_path, f"{case} raw response headers")
    request_lines = parse_curl_request_lines(trace, case)
    if request_lines[0] != f"GET {uri} HTTP/1.1":
        raise SystemExit(f"{case} curl trace has an unexpected request line")
    require_single_request_header(request_lines, case, "Host", "crs-runtime.test")
    require_single_request_header(request_lines, case, "X-Framework-Run-ID", run_id)
    require_single_request_header(request_lines, case, "X-Framework-Request-ID", request_id)
    if any(
        line.partition(":")[0].lower()
        in {"x-modsec-transaction-id", "x-msconnector-host-transaction-id"}
        for line in request_lines[1:-1]
    ):
        raise SystemExit(f"{case} curl trace supplied a client transaction id")
    values = [
        value
        for name, value in parse_single_response_headers(headers, case, expected_status)
        if name.lower() == response_transaction_header.lower()
    ]
    if len(values) != 1:
        raise SystemExit(
            f"{case} raw response headers need exactly one {response_transaction_header}; found {len(values)}"
        )
    transaction_id = values[0]
    if not re.fullmatch(r"lighttpd-[1-9][0-9]*-[1-9][0-9]*", transaction_id):
        raise SystemExit(f"{case} response host transaction id has an unsafe format")
    if transaction_id == request_id:
        raise SystemExit(f"{case} response transaction id reused its client request label")
    return transaction_id

allow_response_transaction_id = host_transaction_id(
    "allow", allow_uri, allow_request_id, "200", allow_trace_path, allow_headers_path
)
block_response_transaction_id = host_transaction_id(
    "block", block_uri, block_request_id, "403", block_trace_path, block_headers_path
)
bypass_response_transaction_id = host_transaction_id(
    "bypass", bypass_uri, bypass_request_id, "403", bypass_trace_path, bypass_headers_path
)
if len({allow_response_transaction_id, block_response_transaction_id,
        bypass_response_transaction_id}) != 3:
    raise SystemExit("CRS requests reused a server-generated host transaction id")

if any(
    event.get("uri") == allow_uri and event.get("actual_action") == "deny"
    for event in events
):
    raise SystemExit("legitimate CRS control request unexpectedly emitted a blocking event")

def require_exactly_one_raw_crs_record(raw_log, transaction_id, request_id):
    correlated_raw_lines = [
        line
        for line in raw_log.splitlines()
        if '[id "942270"]' in line and f'[unique_id "{transaction_id}"]' in line
    ]
    if len(correlated_raw_lines) != 1:
        raise SystemExit(
            f"{request_id} raw ModSecurity log needs exactly one same-line "
            f"CRS rule-942270 record for {transaction_id}; found {len(correlated_raw_lines)}"
        )
    return correlated_raw_lines[0]

def serialized_event_uri(uri):
    path, separator, query = uri.partition("?")
    return f"{path}?<redacted>" if separator and query else uri

def observed(uri, request_id, response_transaction_id):
    expected_event_uri = serialized_event_uri(uri)
    matches = [
        event for event in events
        if event.get("connector") == "lighttpd"
        and event.get("integration_mode") == "patched-native-lighttpd"
        and event.get("method") == "GET"
        and event.get("uri") == expected_event_uri
        and event.get("redacted") is (expected_event_uri != uri)
        and event.get("rule_id") == "949110"
        and event.get("http_status") == 403
        and event.get("visible_http_status") == 403
        and event.get("transport_result") == "http_status"
        and event.get("actual_action") == "deny"
        and isinstance(event.get("transaction_id"), str)
        and bool(event["transaction_id"])
        and event.get("transaction_id") == response_transaction_id
    ]
    if len(matches) != 1:
        raise SystemExit(
            f"expected exactly one observed Lighttpd intervention rule-949110 event for {expected_event_uri!r}; found {len(matches)}"
        )
    event = matches[0]
    if expected_event_uri != uri and any(
        secret in event["uri"].lower() for secret in ("password", "union", "select")
    ):
        raise SystemExit(f"{request_id} serialized Common URI leaked query content")
    transaction_id = event["transaction_id"]
    if transaction_id != response_transaction_id:
        raise SystemExit(
            f"{request_id} Common transaction id does not match the server-generated response header"
        )
    require_exactly_one_raw_crs_record(raw_log, transaction_id, request_id)
    print(f"{request_id}_transaction_id={transaction_id}")
    print(f"{request_id}_observed_intervention_rule_id={event['rule_id']}")
    print(f"{request_id}_observed_crs_trigger_rule_id=942270")
    print(f"{request_id}_observed_http_status={event['visible_http_status']}")
    print(f"{request_id}_observed_uri={event['uri']}")
    return transaction_id, event["rule_id"]

block_transaction_id, block_intervention_rule_id = observed(
    block_uri, "block", block_response_transaction_id
)
bypass_transaction_id, bypass_intervention_rule_id = observed(
    bypass_uri, "bypass", bypass_response_transaction_id
)
if block_transaction_id == bypass_transaction_id:
    raise SystemExit("CRS block and bypass-class requests reused a transaction id")
print("connector=lighttpd")
print("integration_mode=patched-native-lighttpd")
print(f"run_id={run_id}")
print("crs_runtime=true")
print("requests_sent=true")
print("crs_repository=OWASP CRS")
print("crs_rule_id=942270")
print(f"intervention_rule_id={block_intervention_rule_id}")
print("raw_crs_trigger_rule_id=942270")
print("allow_request_method=GET")
print("allow_request_uri=/?id=42")
print(f"allow_request_id={allow_request_id}")
print(f"allow_transaction_id={allow_response_transaction_id}")
print(f"allow_response_transaction_id={allow_response_transaction_id}")
print("allow_request_status=200")
print("block_request_method=GET")
print(f"block_request_uri={block_uri}")
print(f"block_request_id={block_request_id}")
print(f"block_response_transaction_id={block_response_transaction_id}")
print("block_request_status=403")
print("block_observed_action=deny")
print("block_trigger_rule_id=942270")
print(f"block_intervention_rule_id={block_intervention_rule_id}")
print("bypass_class=case-variation")
print(f"bypass_request_uri={bypass_uri}")
print(f"bypass_request_id={bypass_request_id}")
print(f"bypass_response_transaction_id={bypass_response_transaction_id}")
print("bypass_request_status=403")
print("bypass_observed_action=deny")
print("bypass_trigger_rule_id=942270")
print(f"bypass_intervention_rule_id={bypass_intervention_rule_id}")
print(f"response_transaction_header_name={response_transaction_header}")
print("response_transaction_header_origin=server_generated_lighttpd_host")
print(f"allow_request_trace={allow_trace_path}")
print(f"allow_response_headers={allow_headers_path}")
print(f"block_request_trace={block_trace_path}")
print(f"block_response_headers={block_headers_path}")
print(f"bypass_request_trace={bypass_trace_path}")
print(f"bypass_response_headers={bypass_headers_path}")
print("evidence_origin=real_host_event_and_wire_response")
print(f"events={event_path}")
print(f"raw_crs_evidence={raw_log_path}")
print("raw_crs_correlation=verified_by_response_header_and_transaction_id")
print("config_test_status=PASS")
print("host_start_status=PASS")
print("reachability_status=PASS")
PY

    if ! cleanup; then
        fail "CRS cleanup did not stop every owned process"
    fi
    printf 'cleanup_status=PASS\n' >> "$SUMMARY_PATH"
    printf 'status=PASS\n' >> "$SUMMARY_PATH"
    trap - EXIT HUP INT TERM
    printf 'lighttpd_patched_full_lifecycle: PASS CRS allow=%s block=%s bypass=%s events=%s\n' \
        "$crs_allow_status" "$crs_block_status" "$crs_bypass_status" "$EVENT_PATH"
}

if [ "$MSCONNECTOR_CRS_RUNTIME" = 1 ]; then
    run_crs_runtime
    exit 0
fi

host_transaction_header_path() {
    host_transaction_case=$1
    case "$host_transaction_case" in
        p1-allow|p1-deny|p2-deny|p3-deny)
            printf '%s/%s.response.headers\n' "$HOST_TRANSACTION_EVIDENCE_DIR" "$host_transaction_case"
            ;;
        *)
            fail "unrecognized host transaction response evidence case: $host_transaction_case"
            ;;
    esac
}

curl_lifecycle_status() {
    host_transaction_case=$1
    shift
    if [ "$LIGHTTPD_EXPOSE_HOST_TRANSACTION_ID" = 1 ]; then
        curl --silent --show-error --output /dev/null --write-out "$HTTP_STATUS_FORMAT" \
            --dump-header "$(host_transaction_header_path "$host_transaction_case")" "$@"
    else
        curl --silent --show-error --output /dev/null --write-out "$HTTP_STATUS_FORMAT" "$@"
    fi
}

verify_host_transaction_response_headers() {
    "$PYTHON_BIN" - "$SCRIPT_DIR" "$SMOKE_DIR" "$HOST_TRANSACTION_EVIDENCE_DIR" \
        "$CRS_RESPONSE_TRANSACTION_HEADER" <<'PY'
import os
import re
import stat
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1])
from safe_runtime_output import read_runtime_input_text, safe_input_path, verified_runtime_output_root

_, _script_dir, smoke_dir, evidence_dir, header_name = sys.argv
root = verified_runtime_output_root(Path(smoke_dir))
directory = Path(evidence_dir)
details = directory.lstat()
if (
    not stat.S_ISDIR(details.st_mode)
    or details.st_uid != os.geteuid()
    or stat.S_IMODE(details.st_mode) != 0o700
):
    raise SystemExit("host transaction evidence directory must be private mode 0700")

cases = {
    "p1-allow": "lighttpd-p1-allow",
    "p1-deny": "lighttpd-p1-deny",
    "p2-deny": "lighttpd-p2-deny",
    "p3-deny": "lighttpd-p3-deny",
}
observed = []
for case, client_label in cases.items():
    artifact = safe_input_path(
        root, directory / f"{case}.response.headers", f"{case} raw response headers"
    )
    mode = artifact.lstat().st_mode
    if not stat.S_ISREG(mode) or stat.S_IMODE(mode) & 0o077:
        raise SystemExit(f"{case} raw response headers must be a private regular artifact")
    raw_headers = read_runtime_input_text(root, artifact, f"{case} raw response headers")
    values = []
    for line in raw_headers.splitlines():
        name, separator, value = line.partition(":")
        if separator and name.strip().lower() == header_name.lower():
            values.append(value.strip())
    if len(values) != 1:
        raise SystemExit(f"{case} needs exactly one {header_name}; found {len(values)}")
    host_transaction_id = values[0]
    if host_transaction_id in {
        client_label, "untrusted-client-value", "untrusted-upstream-value"
    }:
        raise SystemExit(f"{case} reflected an untrusted transaction identifier")
    if not re.fullmatch(r"lighttpd-[1-9][0-9]*-[1-9][0-9]*", host_transaction_id):
        raise SystemExit(f"{case} has an unsafe host transaction identifier")
    observed.append(host_transaction_id)
if len(set(observed)) != len(observed):
    raise SystemExit("host transaction response evidence reused a transaction id")
PY
}

if [ "$LIGHTTPD_EXPOSE_HOST_TRANSACTION_ID" = 1 ]; then
    prepare_host_transaction_evidence
    # A client value using the response-header name must not be reflected or
    # selected as the host transaction identity.  Keep this negative probe
    # inside the explicit evidence mode so the ordinary No-CRS requests do
    # not gain an unrelated request header.
    allow_status=$(curl_lifecycle_status p1-allow --request OPTIONS --request-target '*' \
        --header 'X-Modsec-Transaction-Id: lighttpd-p1-allow' \
        --header 'X-Msconnector-Host-Transaction-Id: untrusted-client-value' "$base_url")
else
    allow_status=$(curl_lifecycle_status p1-allow --request OPTIONS --request-target '*' \
        --header 'X-Modsec-Transaction-Id: lighttpd-p1-allow' "$base_url")
fi
deny_status=$(curl_lifecycle_status p1-deny --request OPTIONS --request-target '*' \
    --header 'X-Modsec-Smoke: block' \
    --header 'X-Modsec-Transaction-Id: lighttpd-p1-deny' "$base_url")
alternative_status=$(curl --silent --show-error --output /dev/null --write-out "$HTTP_STATUS_FORMAT" \
    --request OPTIONS --request-target '*' \
    --header 'X-Modsec-Smoke: alternative-status' \
    --header 'X-Modsec-Transaction-Id: lighttpd-p1-alternative' "$base_url")
request_body_status=$(curl_lifecycle_status p2-deny --request OPTIONS --request-target '*' \
    --data-binary 'no-crs-request-body-marker' \
    --header 'Content-Type: text/plain' \
    --header 'X-Modsec-Transaction-Id: lighttpd-p2-deny' "$base_url")
response_header_status=$(curl_lifecycle_status p3-deny --request OPTIONS \
    --header 'X-Modsec-Transaction-Id: lighttpd-p3-deny' \
    "http://127.0.0.1:$SMOKE_PORT/phase3-block")

[ "$allow_status" = 200 ] || fail "allow_status=$allow_status expected=200"
[ "$deny_status" = 403 ] || fail "deny_status=$deny_status expected=403"
[ "$alternative_status" = 429 ] || fail "alternative_status=$alternative_status expected=429"
[ "$request_body_status" = 403 ] || fail "request_body_status=$request_body_status expected=403"
[ "$response_header_status" = 403 ] || fail "response_header_status=$response_header_status expected=403"
if [ "$LIGHTTPD_EXPOSE_HOST_TRANSACTION_ID" = 1 ]; then
    verify_host_transaction_response_headers
fi

content_length_cursor=$(event_cursor)
content_length_status=$(fixture_no_crs_io curl-case \
    --runtime-output-root "$FIXTURE_RUNTIME_ROOT" \
    --fixture-name "$FIXTURE_BASENAME" \
    --fixture-identity "$FIXTURE_IDENTITY" \
    --case content-length \
    --port "$SMOKE_PORT") || \
    fail "descriptor-bound Content-Length fixture request failed"
snapshot_events "$content_length_cursor" "$P4_CONTENT_LENGTH_EVENTS"
[ "$content_length_status" = 200 ] || fail "Content-Length entity status=$content_length_status expected=200"

chunked_cursor=$(event_cursor)
chunked_status=$(fixture_no_crs_io curl-case \
    --runtime-output-root "$FIXTURE_RUNTIME_ROOT" \
    --fixture-name "$FIXTURE_BASENAME" \
    --fixture-identity "$FIXTURE_IDENTITY" \
    --case chunked \
    --port "$SMOKE_PORT") || \
    fail "descriptor-bound chunked fixture request failed"
snapshot_events "$chunked_cursor" "$P4_CHUNKED_EVENTS"
[ "$chunked_status" = 200 ] || fail "chunked entity status=$chunked_status expected=200"

if ! wait "$FIXTURE_PID"; then
    if ! fixture_no_crs_io diagnostics \
        --runtime-output-root "$FIXTURE_RUNTIME_ROOT" \
        --fixture-name "$FIXTURE_BASENAME" \
        --fixture-identity "$FIXTURE_IDENTITY" >&2; then
        printf 'lighttpd_patched_full_lifecycle: could not read descriptor-bound fixture diagnostics\n' >&2
    fi
    fail "HTTP/1.1 entity fixture failed"
fi
FIXTURE_PID=

barrier_cursor=$(event_cursor)
: > "$FIRST_BYTE_DIR/client-body.bin"
curl --http1.1 --silent --show-error --no-buffer --connect-timeout 5 --max-time 30 \
    --output "$FIRST_BYTE_DIR/client-body.bin" \
    --write-out "$HTTP_STATUS_FORMAT" \
    --header 'X-Modsec-Transaction-Id: lighttpd-p4-barrier' \
    "http://127.0.0.1:$SMOKE_PORT/p4/barrier/first-byte" \
    >"$FIRST_BYTE_DIR/client-status.txt" 2>"$FIRST_BYTE_DIR/client.stderr" &
FIRST_BYTE_CLIENT_PID=$!
FIRST_BYTE_CLIENT_PID_TOKEN=$(owned_child_start_token "$FIRST_BYTE_CLIENT_PID") || \
    fail "synchronized HTTP/1.1 client did not start as a verifiable owned process"
first_byte_observed=0
attempt=0
while [ "$attempt" -lt 300 ]; do
    if [ -f "$FIRST_BYTE_DIR/upstream-paused.json" ] && \
       [ -s "$FIRST_BYTE_DIR/client-body.bin" ]; then
        first_byte_observed=1
        break
    fi
    if ! kill -0 "$FIRST_BYTE_CLIENT_PID" 2>/dev/null; then
        break
    fi
    attempt=$((attempt + 1))
    sleep 0.1
done
: > "$BARRIER_RELEASE_FILE"
if ! wait "$FIRST_BYTE_CLIENT_PID"; then
    sed -n '1,120p' "$FIRST_BYTE_DIR/client.stderr" >&2
    fail "synchronized HTTP/1.1 client failed after upstream release"
fi
FIRST_BYTE_CLIENT_PID=
FIRST_BYTE_CLIENT_PID_TOKEN=
[ "$first_byte_observed" -eq 1 ] || fail "client did not receive a first body byte while upstream was paused"
phase4_safe_status=$(cat "$FIRST_BYTE_DIR/client-status.txt" 2>/dev/null || true)
[ "$phase4_safe_status" = 200 ] || fail "synchronized safe response status=$phase4_safe_status expected=200"
snapshot_events "$barrier_cursor" "$P4_BARRIER_EVENTS"
[ -s "$P4_BARRIER_EVENTS" ] || fail "synchronized barrier produced no P4 host event"

"$PYTHON_BIN" "$FIRST_BYTE_METADATA" \
    --events "$P4_BARRIER_EVENTS" --output "$FIRST_BYTE_DIR/host-metadata.json" \
    --runtime-output-root "$SMOKE_DIR" || \
    fail "could not derive bounded Lighttpd P4 metadata"
"$PYTHON_BIN" "$SYNCHRONIZED_UPSTREAM" --merge-evidence \
    --control-root "$SMOKE_DIR" \
    --paused-file "$FIRST_BYTE_DIR/upstream-paused.json" \
    --client-first-byte-file "$FIRST_BYTE_DIR/client-body.bin" \
    --host-metadata-json "$FIRST_BYTE_DIR/host-metadata.json" \
    --evidence-origin real_host \
    --output "$FIRST_BYTE_EVIDENCE" || \
    fail "could not write payload-free synchronized first-byte evidence"
rm -f "$FIRST_BYTE_DIR/client-body.bin"
if ! wait "$BARRIER_PID"; then
    sed -n "$DIAGNOSTIC_LINES" "$FIRST_BYTE_DIR/upstream.stderr" >&2
    fail "synchronized upstream failed"
fi
BARRIER_PID=
BARRIER_RELEASE_FILE=

[ -s "$EVENT_PATH" ] || fail "no Common event was emitted"
"$PYTHON_BIN" "$RESULT_WRITER" \
    --events "$EVENT_PATH" \
    --run-id "$NO_CRS_RUN_ID" \
    --output "$RESULTS_PATH" \
    --selected-case-ids "${NO_CRS_SELECTED_CASE_IDS:-}" \
    --allow-status "$allow_status" \
    --deny-status "$deny_status" \
    --alternative-status "$alternative_status" \
    --request-body-status "$request_body_status" \
    --response-header-status "$response_header_status" \
    --phase4-safe-events "$P4_BARRIER_EVENTS" \
    --phase4-projected-events-output "$P4_PROJECTED_EVENTS" \
    --phase4-safe-status "$phase4_safe_status" \
    --phase4-first-byte-evidence "$FIRST_BYTE_EVIDENCE" \
    --content-length-events "$P4_CONTENT_LENGTH_EVENTS" \
    --chunked-events "$P4_CHUNKED_EVENTS" \
    --entity-fixture-directory-name "$FIXTURE_BASENAME" \
    --entity-fixture-directory-identity "$FIXTURE_IDENTITY" \
    --entity-fixture-runtime-output-root "$FIXTURE_RUNTIME_ROOT" \
    --phase4-summary-output "$P4_SUMMARY_JSON" \
    --runtime-output-root "$SMOKE_DIR"
if grep -Fq '"status": "FAIL"' "$RESULTS_PATH"; then
    fail "a host-confirmed case result did not match"
fi
if grep -Eq 'msconnector (request-body|response-body) finalization failed|host-action event was not recorded' "$ERROR_LOG"; then
    sed -n "$DIAGNOSTIC_LINES" "$ERROR_LOG" >&2
    fail "runtime lifecycle error"
fi

{
    printf 'status=PASS\n'
    printf 'requests_sent=true\n'
    printf 'runtime_verified=true\n'
    printf 'rule_evaluation=libmodsecurity_host_runtime\n'
    printf 'allowed_request_status=%s\n' "$allow_status"
    printf 'blocked_request_status=%s\n' "$deny_status"
    printf 'alternative_status=%s\n' "$alternative_status"
    printf 'request_body_status=%s\n' "$request_body_status"
    printf 'response_header_status=%s\n' "$response_header_status"
    "$PYTHON_BIN" - "$P4_SUMMARY_JSON" <<'PY'
import json
import sys

value = json.load(open(sys.argv[1], encoding="utf-8"))
for key in (
    "phase4_safe_status",
    "p4_safe_log_only_status",
    "phase4_end_of_stream_evaluation_status",
    "phase4_first_byte_before_response_end_status",
    "phase4_no_full_response_buffering_status",
    "phase4_rule_id",
    "phase4_requested_action",
    "phase4_actual_action",
    "phase4_late_intervention",
    "phase4_late_intervention_mode",
    "phase4_headers_sent",
    "phase4_body_started",
    "phase4_response_committed",
    "phase4_connection_aborted",
    "phase4_transport_result",
    "phase4_entity_eos_finalized_once",
    "phase4_host_action_events",
    "http1_content_length_entity_bytes",
    "http1_chunked_entity_bytes",
):
    item = value[key]
    if isinstance(item, bool):
        item = str(item).lower()
    print(f"{key}={item}")
PY
    printf 'first_byte_evidence=%s\n' "$FIRST_BYTE_EVIDENCE"
    printf 'phase4_barrier_events=%s\n' "$P4_PROJECTED_EVENTS"
    printf 'content_length_events=%s\n' "$P4_CONTENT_LENGTH_EVENTS"
    printf 'chunked_events=%s\n' "$P4_CHUNKED_EVENTS"
    printf 'events=%s\n' "$EVENT_PATH"
    printf 'results=%s\n' "$RESULTS_PATH"
} > "$SUMMARY_PATH"

if ! cleanup; then
    fail "cleanup did not stop every owned process"
fi
trap - EXIT HUP INT TERM
printf 'cleanup_status=PASS\n' >> "$SUMMARY_PATH"

printf 'lighttpd_patched_full_lifecycle: PASS allow=%s deny=%s alternative=%s p2=%s p3=%s p4-safe=%s results=%s\n' \
    "$allow_status" "$deny_status" "$alternative_status" "$request_body_status" \
    "$response_header_status" "$phase4_safe_status" "$RESULTS_PATH"
