#!/bin/sh
# Local-only combined HAProxy SPOE/SPOP -> native-HTX MRC1 v2 contract proof.
#
# This harness deliberately has no default build, runtime, socket, or port
# paths.  A caller must provide a fresh child of a task-owned external root
# and every host dependency explicitly.  It only starts loopback services and
# only terminates the process groups and socket that it created itself.
set -eu

umask 077

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
CONNECTOR_DIR=$(CDPATH='' cd -- "$SCRIPT_DIR/../.." && pwd)
REPO_ROOT=$(CDPATH='' cd -- "$CONNECTOR_DIR/../.." && pwd)
BACKEND_FIXTURE="$SCRIPT_DIR/backend.py"
P3_RULES="$SCRIPT_DIR/rules-p3-deny.conf"
P4_RULES="$SCRIPT_DIR/rules-p4-safe.conf"
MRC1_HEADER="$REPO_ROOT/common/runtime/response_companion_transport.h"
MRC1_CLIENT="$REPO_ROOT/common/runtime/response_companion_client.c"
HTX_FILTER="$REPO_ROOT/connectors/haproxy/htx-overlay/haproxy_modsecurity_htx_filter.c"
VERSION_CONTRACT="$REPO_ROOT/connectors/haproxy/htx-overlay/version-contract.json"
VERSION_PARSER="$REPO_ROOT/connectors/haproxy/htx-overlay/version_contract.py"

SERVICE_TIMEOUT_SECONDS=180
BUILD_TIMEOUT_SECONDS=300
WAIT_ATTEMPTS=20

run_root_created=0
backend_pid=
spoa_pid=
haproxy_pid=
socket_owned=0
run_result=FAIL

die() {
    printf '%s\n' "combined_spop_htx: FAIL - $*" >&2
    exit 1
}

blocked() {
    printf '%s\n' "combined_spop_htx: BLOCKED - $*" >&2
    exit 77
}

require_value() {
    value=$1
    name=$2
    [ -n "$value" ] || blocked "$name must be explicitly set"
}

require_absolute_path() {
    value=$1
    name=$2
    case "$value" in
        /*) ;;
        *) die "$name must be an absolute path" ;;
    esac
}

require_safe_path_text() {
    value=$1
    name=$2
    case "$value" in
        *[!A-Za-z0-9_./:-]*|'') die "$name contains unsupported path characters" ;;
        *) ;;
    esac
}

canonical_existing_directory() {
    value=$1
    name=$2
    [ -d "$value" ] || blocked "$name is not an existing directory: $value"
    (CDPATH='' cd -- "$value" && pwd -P)
}

require_regular_file() {
    value=$1
    name=$2
    [ -f "$value" ] || blocked "$name is not a regular file: $value"
}

require_port() {
    value=$1
    name=$2
    case "$value" in
        *[!0-9]*|'') die "$name must be a decimal port" ;;
        *) ;;
    esac
    [ "$value" -ge 1024 ] && [ "$value" -le 65535 ] || die "$name must be in 1024..65535"
}

assert_mrc1_v2() {
    require_regular_file "$MRC1_HEADER" "MRC1 transport header"
    require_regular_file "$MRC1_CLIENT" "MRC1 client source"
    require_regular_file "$HTX_FILTER" "native HTX filter source"
    if ! grep -Fqx '#define MSCONNECTOR_RESPONSE_COMPANION_TRANSPORT_PROTOCOL_VERSION 2U' "$MRC1_HEADER"; then
        die "current source does not select MRC1 protocol version 2"
    fi
    if ! grep -Fq 'There is deliberately no v1' "$MRC1_HEADER"; then
        die "current source does not declare the no-v1-fallback invariant"
    fi
    if ! grep -Fq 'msconnector_response_companion_client_cancel_with_cause' "$MRC1_CLIENT" ||
            ! grep -Fq 'msconnector_response_companion_client_cancel_with_cause' "$HTX_FILTER"; then
        die "current source does not wire typed MRC1 v2 cancellation end-to-end"
    fi
}

stop_process_group() {
    process_name=$1
    process_pid=$2
    status_path=$3

    [ -n "$process_pid" ] || return 0
    if kill -0 "$process_pid" 2>/dev/null; then
        /bin/kill -TERM -- "-$process_pid" 2>/dev/null || /bin/kill -TERM "$process_pid" 2>/dev/null || true
    fi
    set +e
    wait "$process_pid" 2>/dev/null
    wait_status=$?
    set -e
    printf 'owner=combined_spop_htx\nstate=stopped\nexit_status=%s\n' "$wait_status" >"$status_path"
    printf '%s\n' "combined_spop_htx: stopped $process_name pid=$process_pid" >&2
}

cleanup() {
    stop_process_group haproxy "$haproxy_pid" "$PROCESS_ROOT/haproxy.status" || true
    haproxy_pid=
    stop_process_group spoa "$spoa_pid" "$PROCESS_ROOT/spoa.status" || true
    spoa_pid=
    stop_process_group backend "$backend_pid" "$PROCESS_ROOT/backend.status" || true
    backend_pid=
    if [ "$socket_owned" -eq 1 ] && [ -S "$SOCKET_PATH" ]; then
        rm -f -- "$SOCKET_PATH"
    fi
    if [ "$run_root_created" -eq 1 ]; then
        printf 'owner=combined_spop_htx\nstate=complete\nresult=%s\n' "$run_result" >"$RUN_ROOT/status.txt"
    fi
}

wait_for_ready() {
    readiness_kind=$1
    readiness_target=$2
    readiness_failure=$3
    attempt=0
    while [ "$attempt" -lt "$WAIT_ATTEMPTS" ]; do
        if [ "$readiness_kind" = socket ] && [ -S "$SOCKET_PATH" ]; then
            socket_owned=1
            return 0
        fi
        if [ "$readiness_kind" = port ] && "$PYTHON_BIN" - "$readiness_target" <<'PY'
import socket
import sys

try:
    with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=0.2):
        pass
except OSError:
    raise SystemExit(1)
PY
        then
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 1
    done
    die "$readiness_failure"
}

wait_for_socket() {
    wait_for_ready socket "-" "SPOP did not create its private MRC1 socket"
}

wait_for_port() {
    port=$1
    label=$2
    wait_for_ready port "$port" "$label did not listen on 127.0.0.1:$port"
}

write_process_record() {
    name=$1
    purpose=$2
    command_text=$3
    printf 'owner=combined_spop_htx\npurpose=%s\nworking_directory=%s\nhard_timeout_seconds=%s\ncommand=%s\n' \
        "$purpose" "$RUN_ROOT" "$SERVICE_TIMEOUT_SECONDS" "$command_text" >"$PROCESS_ROOT/$name.command.txt"
}

start_backend() {
    if ! command -v openssl >/dev/null 2>&1; then
        blocked "openssl is unavailable for the private backend TLS fixture"
    fi
    if ! openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 \
            -subj '/CN=127.0.0.1' -addext 'subjectAltName=IP:127.0.0.1' \
            -keyout "$PRIVATE_ROOT/backend.key" -out "$PRIVATE_ROOT/backend.crt" \
            >"$LOG_ROOT/backend-tls.stdout.log" 2>"$LOG_ROOT/backend-tls.stderr.log"; then
        die "private backend TLS certificate generation failed"
    fi
    chmod 600 "$PRIVATE_ROOT/backend.key" "$PRIVATE_ROOT/backend.crt"
    write_process_record backend 'bounded loopback TLS response fixture' "$PYTHON_BIN $BACKEND_FIXTURE --bind 127.0.0.1 --port $BACKEND_PORT"
    setsid "$TIMEOUT_BIN" --foreground "$SERVICE_TIMEOUT_SECONDS" \
        "$PYTHON_BIN" "$BACKEND_FIXTURE" --bind 127.0.0.1 --port "$BACKEND_PORT" \
        --root-dir "$RUN_ROOT" --ready-file "$RUN_ROOT/backend.ready" \
        --log-file "$EVIDENCE_ROOT/backend.jsonl" --cert-file "$PRIVATE_ROOT/backend.crt" \
        --key-file "$PRIVATE_ROOT/backend.key" \
        >"$LOG_ROOT/backend.stdout.log" 2>"$LOG_ROOT/backend.stderr.log" &
    backend_pid=$!
    printf '%s\n' "$backend_pid" >"$PROCESS_ROOT/backend.pid"
    printf 'owner=combined_spop_htx\nstate=started\npid=%s\n' "$backend_pid" >"$PROCESS_ROOT/backend.status"
    wait_for_port "$BACKEND_PORT" backend
    [ -f "$RUN_ROOT/backend.ready" ] || die "backend did not create its task-owned ready marker"
}

write_spoe_config() {
    cat >"$CONFIG_ROOT/spoe.cfg" <<EOF
[modsecurity]
spoe-agent modsecurity-agent
    groups request-check
    option var-prefix modsec
    register-var-names blocked action status redirect_url rule_id phase error response_handle
    max-frame-size 65532
    option continue-on-error
    timeout hello 1s
    timeout idle 3s
    timeout processing 2s
    use-backend be_spoa

spoe-group request-check
    messages check-request

spoe-message check-request
    args request_id=unique-id client_ip=src client_port=src_port server_ip=dst server_port=dst_port method=method path=path uri=url host=req.hdr(host) headers_bin=req.hdrs_bin headers=req.hdrs body=req.body body_len=req.body_size http_version=req.ver
EOF
}

write_agent_config() {
    case_name=$1
    rules_file=$2
    body_timeout_ms=$3
    case_root="$RUN_ROOT/cases/$case_name"
    cat >"$case_root/spoa-agent.conf" <<EOF
listen=127.0.0.1:$SPOA_PORT
log-file=$case_root/spoa.log
decision-log=$case_root/decision.jsonl
audit-log=$case_root/audit.jsonl
rules-file=$rules_file
mode=block
fail-mode=closed
runtime-mode=production
response-companion=native-htx
response-phases=true
response-companion-socket=$SOCKET_PATH
response-companion-uid=$SERVICE_UID
response-companion-gid=$SERVICE_GID
response-body-timeout=$body_timeout_ms
spoe-timeout=2000
max-transactions=64
EOF
}

write_haproxy_config() {
    case_name=$1
    send_spoe=$2
    case_root="$RUN_ROOT/cases/$case_name"
    if [ "$send_spoe" = yes ]; then
        spoe_request_line='    http-request send-spoe-group modsecurity request-check'
    else
        spoe_request_line='    # Deliberately omitted: missing MRC1 correlation must fail closed at P3.'
    fi
    cat >"$case_root/haproxy.cfg" <<EOF
global
    log stdout format raw local0
    tune.bufsize 65536
    pidfile $case_root/haproxy.pid

defaults
    mode http
    timeout connect 1s
    timeout client 5s
    timeout server 5s

frontend fe_combined
    bind 127.0.0.1:$HAPROXY_PORT
    unique-id-format %[uuid()]
    option http-buffer-request
    filter spoe engine modsecurity config $CONFIG_ROOT/spoe.cfg
    filter modsecurity-htx response-companion-socket $SOCKET_PATH response-companion-timeout-ms 2000 response-companion-uid $SERVICE_UID response-companion-gid $SERVICE_GID phase4-mode safe
$spoe_request_line
    http-request deny status 403 if { var(txn.modsec.blocked) -m bool }
    default_backend be_app

backend be_app
    mode http
    server app 127.0.0.1:$BACKEND_PORT ssl verify none

backend be_spoa
    mode spop
    timeout connect 1s
    timeout server 3s
    server agent 127.0.0.1:$SPOA_PORT
EOF
}

start_spoa() {
    case_name=$1
    case_root="$RUN_ROOT/cases/$case_name"
    [ ! -e "$SOCKET_PATH" ] || die "refusing pre-existing MRC1 socket path"
    write_process_record spoa "current-source SPOP agent for $case_name" "$SPOA_BIN --config $case_root/spoa-agent.conf"
    setsid "$TIMEOUT_BIN" --foreground "$SERVICE_TIMEOUT_SECONDS" \
        "$SPOA_BIN" --config "$case_root/spoa-agent.conf" \
        >"$case_root/spoa.stdout.log" 2>"$case_root/spoa.stderr.log" &
    spoa_pid=$!
    printf '%s\n' "$spoa_pid" >"$PROCESS_ROOT/spoa.pid"
    printf 'owner=combined_spop_htx\nstate=started\npid=%s\ncase=%s\n' "$spoa_pid" "$case_name" >"$PROCESS_ROOT/spoa.status"
    wait_for_port "$SPOA_PORT" spoa
    wait_for_socket
}

start_haproxy() {
    case_name=$1
    case_root="$RUN_ROOT/cases/$case_name"
    if ! "$HAPROXY_BIN" -c -f "$case_root/haproxy.cfg" >"$case_root/haproxy.config.stdout.log" \
            2>"$case_root/haproxy.config.stderr.log"; then
        sed -n '1,160p' "$case_root/haproxy.config.stderr.log" >&2 || true
        die "current overlay HAProxy rejected $case_name config"
    fi
    write_process_record haproxy "current-source overlay HAProxy for $case_name" "$HAPROXY_BIN -db -f $case_root/haproxy.cfg"
    setsid "$TIMEOUT_BIN" --foreground "$SERVICE_TIMEOUT_SECONDS" \
        "$HAPROXY_BIN" -db -f "$case_root/haproxy.cfg" \
        >"$case_root/haproxy.stdout.log" 2>"$case_root/haproxy.stderr.log" &
    haproxy_pid=$!
    printf '%s\n' "$haproxy_pid" >"$PROCESS_ROOT/haproxy.pid"
    printf 'owner=combined_spop_htx\nstate=started\npid=%s\ncase=%s\n' "$haproxy_pid" "$case_name" >"$PROCESS_ROOT/haproxy.status"
    wait_for_port "$HAPROXY_PORT" haproxy
}

stop_case_services() {
    stop_process_group haproxy "$haproxy_pid" "$PROCESS_ROOT/haproxy.status"
    haproxy_pid=
    stop_process_group spoa "$spoa_pid" "$PROCESS_ROOT/spoa.status"
    spoa_pid=
    if [ -e "$SOCKET_PATH" ]; then
        die "SPOP did not remove the MRC1 socket it owned"
    fi
    socket_owned=0
}

assert_status() {
    value=$1
    expected=$2
    case_name=$3
    [ "$value" = "$expected" ] || die "$case_name expected HTTP $expected, observed $value"
}

curl_post() {
    case_name=$1
    path=$2
    case_root="$RUN_ROOT/cases/$case_name"
    if ! status=$("$TIMEOUT_BIN" 10 "$CURL_BIN" --http1.1 --max-time 5 -sS \
            -X POST -H 'Content-Type: application/x-www-form-urlencoded' --data 'p2=bounded' \
            -D "$case_root/client.headers" -o "$case_root/client.body" \
            -w '%{http_code}' "http://127.0.0.1:$HAPROXY_PORT$path"); then
        die "$case_name curl request failed"
    fi
    printf '%s' "$status"
}

assert_p2_evidence() {
    decision_log=$1
    "$PYTHON_BIN" - "$decision_log" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as source:
    records = [json.loads(line) for line in source if line.strip()]
if not any(
    record.get("phase") == 2
    and record.get("modsecurity_processed") is True
    and record.get("request_headers_seen") is True
    and record.get("request_body_seen") is True
    for record in records
):
    raise SystemExit("missing P1/P2 SPOP decision evidence")
PY
}

assert_no_unexpected_technical_events() {
    case_root=$1
    for physical_log in "$case_root/haproxy.stderr.log" "$case_root/decision.jsonl"; do
        [ -f "$physical_log" ] || die "normal case physical log missing: $physical_log"
        if grep -Eq '"event"[[:space:]]*:[[:space:]]*"(connector_error|protocol_error)"' "$physical_log"; then
            die "normal case contains an unexpected physical connector/protocol error: $physical_log"
        fi
    done
}

run_case() {
    case_name=$1
    rules_file=$2
    body_timeout_ms=$3
    endpoint=$4
    expected_status=$5
    send_spoe=$6
    mkdir "$RUN_ROOT/cases/$case_name"
    write_agent_config "$case_name" "$rules_file" "$body_timeout_ms"
    write_haproxy_config "$case_name" "$send_spoe"
    start_spoa "$case_name"
    start_haproxy "$case_name"
    observed_status=$(curl_post "$case_name" "$endpoint")
    assert_status "$observed_status" "$expected_status" "$case_name"
    if [ "$send_spoe" = yes ]; then
        assert_p2_evidence "$RUN_ROOT/cases/$case_name/decision.jsonl"
        assert_no_unexpected_technical_events "$RUN_ROOT/cases/$case_name"
    fi
}

run_connection_reuse_case() {
    case_name=connection-reuse
    case_root="$RUN_ROOT/cases/$case_name"
    mkdir "$case_root"
    write_agent_config "$case_name" "$P4_RULES" 2000
    write_haproxy_config "$case_name" yes
    start_spoa "$case_name"
    start_haproxy "$case_name"
    if ! "$TIMEOUT_BIN" 10 "$PYTHON_BIN" - "$HAPROXY_PORT" "$case_root/connection-reuse.json" <<'PY'
import json
import socket
import sys

port = int(sys.argv[1])
evidence_path = sys.argv[2]
request_body = b"p2=bounded"


def read_response(connection: socket.socket) -> tuple[int, bytes]:
    received = bytearray()
    while b"\r\n\r\n" not in received:
        chunk = connection.recv(4096)
        if not chunk:
            raise RuntimeError("connection closed before response headers")
        received.extend(chunk)
    header_bytes, body = bytes(received).split(b"\r\n\r\n", 1)
    header_lines = header_bytes.decode("iso-8859-1").split("\r\n")
    status = int(header_lines[0].split()[1])
    content_length = next(
        int(line.split(":", 1)[1].strip())
        for line in header_lines[1:]
        if line.lower().startswith("content-length:")
    )
    while len(body) < content_length:
        chunk = connection.recv(4096)
        if not chunk:
            raise RuntimeError("connection closed before the declared response body")
        body += chunk
    return status, body[:content_length]


with socket.create_connection(("127.0.0.1", port), timeout=5) as connection:
    connection.settimeout(5)
    statuses: list[int] = []
    for sequence in (1, 2):
        request = (
            f"POST /p4-safe?reuse={sequence} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(request_body)}\r\n"
            "Connection: keep-alive\r\n\r\n"
        ).encode("ascii") + request_body
        connection.sendall(request)
        status, _body = read_response(connection)
        if status != 200:
            raise RuntimeError(f"expected HTTP 200 on reuse request {sequence}, got {status}")
        statuses.append(status)

with open(evidence_path, "w", encoding="ascii") as output:
    json.dump(
        {"same_tcp_connection": True, "request_count": 2, "statuses": statuses},
        output,
        sort_keys=True,
    )
    output.write("\n")
PY
    then
        die "HTTP/1.1 connection-reuse proof failed"
    fi
    assert_p2_evidence "$case_root/decision.jsonl"
    assert_no_unexpected_technical_events "$case_root"
    if ! grep -Fq 'host_action=log_only' "$case_root/haproxy.stderr.log"; then
        die "connection-reuse case did not record the P4 safe/log-only host action"
    fi
}

run_cancel_case() {
    case_name=client-cancel
    case_root="$RUN_ROOT/cases/$case_name"
    mkdir "$case_root"
    write_agent_config "$case_name" "$P4_RULES" 5000
    write_haproxy_config "$case_name" yes
    start_spoa "$case_name"
    start_haproxy "$case_name"
    set +e
    "$TIMEOUT_BIN" 5 "$CURL_BIN" --http1.1 --max-time 1 -sS \
        -X POST -H 'Content-Type: application/x-www-form-urlencoded' --data 'p2=bounded' \
        -D "$case_root/client.headers" -o "$case_root/client.body" \
        "http://127.0.0.1:$HAPROXY_PORT/slow" >"$case_root/client.stdout.log" 2>"$case_root/client.stderr.log"
    cancel_status=$?
    set -e
    [ "$cancel_status" -eq 28 ] || die "client cancel expected curl status 28, observed $cancel_status"
    assert_p2_evidence "$case_root/decision.jsonl"
}

run_ttl_case() {
    case_name=ttl-expiry
    case_root="$RUN_ROOT/cases/$case_name"
    mkdir "$case_root"
    write_agent_config "$case_name" "$P4_RULES" 100
    write_haproxy_config "$case_name" yes
    start_spoa "$case_name"
    start_haproxy "$case_name"
    set +e
    status=$("$TIMEOUT_BIN" 10 "$CURL_BIN" --http1.1 --max-time 5 -sS \
        -X POST -H 'Content-Type: application/x-www-form-urlencoded' --data 'p2=bounded' \
        -D "$case_root/client.headers" -o "$case_root/client.body" \
        -w '%{http_code}' "http://127.0.0.1:$HAPROXY_PORT/slow")
    ttl_curl_status=$?
    set -e
    # A response body that arrives after the MRC1 ownership TTL is deliberately
    # truncated post-commit. curl's partial-transfer status (18) is the
    # expected local proof that no stale body was silently forwarded.
    [ "$ttl_curl_status" -eq 18 ] || die "TTL expiry expected curl status 18, observed $ttl_curl_status"
    assert_status "$status" 200 "$case_name"
    [ -f "$case_root/client.headers" ] || die "TTL expiry did not return response headers before truncation"
    assert_p2_evidence "$case_root/decision.jsonl"
    if ! grep -Fq 'fail-closed postcommit response-companion body' "$case_root/haproxy.stderr.log"; then
        die "TTL expiry did not reach the postcommit fail-closed response-companion path"
    fi
}

RUNTIME_ROOT=${COMBINED_SPOP_HTX_RUNTIME_ROOT:-}
ALLOWED_ROOT=${COMBINED_SPOP_HTX_ALLOWED_ROOT:-}
HAPROXY_SOURCE_DIR=${COMBINED_SPOP_HTX_HAPROXY_SOURCE_DIR:-}
MODSECURITY_INCLUDE_DIR=${COMBINED_SPOP_HTX_MODSECURITY_INCLUDE_DIR:-}
MODSECURITY_LIB_DIR=${COMBINED_SPOP_HTX_MODSECURITY_LIB_DIR:-}
MODSECURITY_LIBRARY=${COMBINED_SPOP_HTX_MODSECURITY_LIBRARY:-}
HAPROXY_PORT=${COMBINED_SPOP_HTX_HAPROXY_PORT:-}
SPOA_PORT=${COMBINED_SPOP_HTX_SPOA_PORT:-}
BACKEND_PORT=${COMBINED_SPOP_HTX_BACKEND_PORT:-}
PYTHON_BIN=${COMBINED_SPOP_HTX_PYTHON:-python3}
CURL_BIN=${COMBINED_SPOP_HTX_CURL:-curl}
TIMEOUT_BIN=${COMBINED_SPOP_HTX_TIMEOUT:-timeout}
PREPARED_HAPROXY_BIN=${COMBINED_SPOP_HTX_PREPARED_HAPROXY_BIN:-}
PREPARED_SPOA_BIN=${COMBINED_SPOP_HTX_PREPARED_SPOA_BIN:-}
PREPARED_PROVENANCE=${COMBINED_SPOP_HTX_PREPARED_PROVENANCE:-}
PREPARED_SOURCE_EQUIVALENCE=${COMBINED_SPOP_HTX_PREPARED_SOURCE_EQUIVALENCE:-}
prepared_mode=0
if [ -n "$PREPARED_HAPROXY_BIN$PREPARED_SPOA_BIN$PREPARED_PROVENANCE$PREPARED_SOURCE_EQUIVALENCE" ]; then
    require_value "$PREPARED_HAPROXY_BIN" COMBINED_SPOP_HTX_PREPARED_HAPROXY_BIN
    require_value "$PREPARED_SPOA_BIN" COMBINED_SPOP_HTX_PREPARED_SPOA_BIN
    require_value "$PREPARED_PROVENANCE" COMBINED_SPOP_HTX_PREPARED_PROVENANCE
    require_value "$PREPARED_SOURCE_EQUIVALENCE" COMBINED_SPOP_HTX_PREPARED_SOURCE_EQUIVALENCE
    prepared_mode=1
fi

require_value "$RUNTIME_ROOT" COMBINED_SPOP_HTX_RUNTIME_ROOT
require_value "$ALLOWED_ROOT" COMBINED_SPOP_HTX_ALLOWED_ROOT
require_value "$HAPROXY_SOURCE_DIR" COMBINED_SPOP_HTX_HAPROXY_SOURCE_DIR
require_value "$MODSECURITY_INCLUDE_DIR" COMBINED_SPOP_HTX_MODSECURITY_INCLUDE_DIR
require_value "$MODSECURITY_LIB_DIR" COMBINED_SPOP_HTX_MODSECURITY_LIB_DIR
require_value "$MODSECURITY_LIBRARY" COMBINED_SPOP_HTX_MODSECURITY_LIBRARY
require_value "$HAPROXY_PORT" COMBINED_SPOP_HTX_HAPROXY_PORT
require_value "$SPOA_PORT" COMBINED_SPOP_HTX_SPOA_PORT
require_value "$BACKEND_PORT" COMBINED_SPOP_HTX_BACKEND_PORT

require_absolute_path "$RUNTIME_ROOT" COMBINED_SPOP_HTX_RUNTIME_ROOT
require_absolute_path "$ALLOWED_ROOT" COMBINED_SPOP_HTX_ALLOWED_ROOT
require_absolute_path "$HAPROXY_SOURCE_DIR" COMBINED_SPOP_HTX_HAPROXY_SOURCE_DIR
require_absolute_path "$MODSECURITY_INCLUDE_DIR" COMBINED_SPOP_HTX_MODSECURITY_INCLUDE_DIR
require_absolute_path "$MODSECURITY_LIB_DIR" COMBINED_SPOP_HTX_MODSECURITY_LIB_DIR
require_absolute_path "$MODSECURITY_LIBRARY" COMBINED_SPOP_HTX_MODSECURITY_LIBRARY
require_safe_path_text "$RUNTIME_ROOT" COMBINED_SPOP_HTX_RUNTIME_ROOT
require_safe_path_text "$ALLOWED_ROOT" COMBINED_SPOP_HTX_ALLOWED_ROOT
require_safe_path_text "$HAPROXY_SOURCE_DIR" COMBINED_SPOP_HTX_HAPROXY_SOURCE_DIR
require_safe_path_text "$MODSECURITY_INCLUDE_DIR" COMBINED_SPOP_HTX_MODSECURITY_INCLUDE_DIR
require_safe_path_text "$MODSECURITY_LIB_DIR" COMBINED_SPOP_HTX_MODSECURITY_LIB_DIR
require_safe_path_text "$MODSECURITY_LIBRARY" COMBINED_SPOP_HTX_MODSECURITY_LIBRARY
require_port "$HAPROXY_PORT" COMBINED_SPOP_HTX_HAPROXY_PORT
require_port "$SPOA_PORT" COMBINED_SPOP_HTX_SPOA_PORT
require_port "$BACKEND_PORT" COMBINED_SPOP_HTX_BACKEND_PORT
[ "$HAPROXY_PORT" != "$SPOA_PORT" ] && [ "$HAPROXY_PORT" != "$BACKEND_PORT" ] && [ "$SPOA_PORT" != "$BACKEND_PORT" ] || die "selected ports must be distinct"

ALLOWED_ROOT=$(canonical_existing_directory "$ALLOWED_ROOT" COMBINED_SPOP_HTX_ALLOWED_ROOT)
case "$ALLOWED_ROOT" in
    /|"$REPO_ROOT"|"$REPO_ROOT"/*) die "COMBINED_SPOP_HTX_ALLOWED_ROOT must be task-owned external storage" ;;
    *) ;;
esac
runtime_parent=$(dirname -- "$RUNTIME_ROOT")
runtime_leaf=$(basename -- "$RUNTIME_ROOT")
[ "$runtime_leaf" != . ] && [ "$runtime_leaf" != .. ] || die "runtime root leaf is unsafe"
runtime_parent=$(canonical_existing_directory "$runtime_parent" 'runtime root parent')
[ "$runtime_parent" = "$ALLOWED_ROOT" ] || die "runtime root must be a fresh direct child of COMBINED_SPOP_HTX_ALLOWED_ROOT"
RUN_ROOT="$runtime_parent/$runtime_leaf"
[ ! -e "$RUN_ROOT" ] || die "runtime root must not already exist: $RUN_ROOT"

HAPROXY_SOURCE_DIR=$(canonical_existing_directory "$HAPROXY_SOURCE_DIR" COMBINED_SPOP_HTX_HAPROXY_SOURCE_DIR)
MODSECURITY_INCLUDE_DIR=$(canonical_existing_directory "$MODSECURITY_INCLUDE_DIR" COMBINED_SPOP_HTX_MODSECURITY_INCLUDE_DIR)
MODSECURITY_LIB_DIR=$(canonical_existing_directory "$MODSECURITY_LIB_DIR" COMBINED_SPOP_HTX_MODSECURITY_LIB_DIR)
require_regular_file "$MODSECURITY_LIBRARY" COMBINED_SPOP_HTX_MODSECURITY_LIBRARY
require_regular_file "$BACKEND_FIXTURE" backend-fixture
require_regular_file "$P3_RULES" p3-rules
require_regular_file "$P4_RULES" p4-rules
require_regular_file "$VERSION_CONTRACT" HAProxy-version-contract
require_regular_file "$VERSION_PARSER" HAProxy-version-parser
command -v "$PYTHON_BIN" >/dev/null 2>&1 || blocked "Python interpreter is unavailable: $PYTHON_BIN"
command -v "$CURL_BIN" >/dev/null 2>&1 || blocked "curl is unavailable: $CURL_BIN"
command -v "$TIMEOUT_BIN" >/dev/null 2>&1 || blocked "timeout is unavailable: $TIMEOUT_BIN"
command -v setsid >/dev/null 2>&1 || blocked "setsid is unavailable"
command -v make >/dev/null 2>&1 || blocked "make is unavailable"

EXPECTED_HAPROXY_VERSION=$("$PYTHON_BIN" "$VERSION_PARSER" --contract "$VERSION_CONTRACT" --field version)
require_regular_file "$HAPROXY_SOURCE_DIR/VERSION" HAProxy-VERSION
actual_haproxy_version=$(tr -d '[:space:]' <"$HAPROXY_SOURCE_DIR/VERSION")
[ "$actual_haproxy_version" = "$EXPECTED_HAPROXY_VERSION" ] || die "expected HAProxy $EXPECTED_HAPROXY_VERSION, found $actual_haproxy_version"
assert_mrc1_v2

mkdir "$RUN_ROOT"
run_root_created=1
chmod 700 "$RUN_ROOT"
CONFIG_ROOT="$RUN_ROOT/config"
LOG_ROOT="$RUN_ROOT/logs"
EVIDENCE_ROOT="$RUN_ROOT/evidence"
PROCESS_ROOT="$RUN_ROOT/processes"
PRIVATE_ROOT="$RUN_ROOT/private"
mkdir "$CONFIG_ROOT" "$LOG_ROOT" "$EVIDENCE_ROOT" "$PROCESS_ROOT" "$PRIVATE_ROOT" "$RUN_ROOT/cases"
chmod 700 "$PRIVATE_ROOT"
SOCKET_PATH="$PRIVATE_ROOT/mrc1-v2.sock"
[ "${#SOCKET_PATH}" -lt 100 ] || die "private MRC1 socket path is too long"
SERVICE_UID=$(id -u)
SERVICE_GID=$(id -g)
printf 'owner=combined_spop_htx\nprotocol=MRC1-v2\nsource_root=%s\n' "$REPO_ROOT" >"$RUN_ROOT/ownership.txt"
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

if [ "$prepared_mode" -eq 1 ]; then
    if ! "$PYTHON_BIN" "$SCRIPT_DIR/prepared_artifacts.py" "$REPO_ROOT" \
            "$PREPARED_HAPROXY_BIN" "$PREPARED_SPOA_BIN" "$PREPARED_PROVENANCE" \
            "$PREPARED_SOURCE_EQUIVALENCE" "$MODSECURITY_LIBRARY" "$EXPECTED_HAPROXY_VERSION" \
            >"$EVIDENCE_ROOT/prepared-artifacts.json"; then
        die "explicit prepared artifacts failed source/provenance validation"
    fi
    HAPROXY_BIN=$PREPARED_HAPROXY_BIN
    SPOA_BIN=$PREPARED_SPOA_BIN
else
printf '%s\n' "combined_spop_htx: building current task-worktree SPOP runtime" >&2
if ! "$TIMEOUT_BIN" "$BUILD_TIMEOUT_SECONDS" make -C "$CONNECTOR_DIR" \
        REPO_ROOT="$REPO_ROOT" BUILD_ROOT="$RUN_ROOT/build" \
        HAPROXY_MODSECURITY_BINDING_DIR="$RUN_ROOT/build/haproxy-modsecurity-binding" \
        MODSECURITY_INCLUDE_DIR="$MODSECURITY_INCLUDE_DIR" MODSECURITY_LIB_DIR="$MODSECURITY_LIB_DIR" \
        MODSECURITY_LIBRARY="$MODSECURITY_LIBRARY" CFLAGS= HAPROXY_MODSECURITY_BINDING_CPPFLAGS= \
        build-modsecurity-binding build-spoa-runtime >"$LOG_ROOT/build-spoa.stdout.log" 2>"$LOG_ROOT/build-spoa.stderr.log"; then
    die "current-source SPOP build failed; see $LOG_ROOT/build-spoa.stderr.log"
fi
SPOA_BIN="$RUN_ROOT/build/haproxy-spoa-runtime/haproxy-modsecurity-spoa"
[ -x "$SPOA_BIN" ] || die "current-source SPOP build did not create $SPOA_BIN"

printf '%s\n' "combined_spop_htx: building current task-worktree HTX overlay" >&2
if ! "$TIMEOUT_BIN" "$BUILD_TIMEOUT_SECONDS" make -C "$CONNECTOR_DIR" \
        REPO_ROOT="$REPO_ROOT" BUILD_ROOT="$RUN_ROOT/build" \
        HAPROXY_MODSECURITY_BINDING_DIR="$RUN_ROOT/build/haproxy-modsecurity-binding" \
        HAPROXY_HTX_SOURCE_DIR="$HAPROXY_SOURCE_DIR" HAPROXY_HTX_BUILD_DIR="$RUN_ROOT/overlay" \
        MODSECURITY_INCLUDE_DIR="$MODSECURITY_INCLUDE_DIR" MODSECURITY_LIB_DIR="$MODSECURITY_LIB_DIR" \
        MODSECURITY_LIBRARY="$MODSECURITY_LIBRARY" CFLAGS= HAPROXY_MODSECURITY_BINDING_CPPFLAGS= \
        build-htx-overlay >"$LOG_ROOT/build-overlay.stdout.log" 2>"$LOG_ROOT/build-overlay.stderr.log"; then
    die "current-source HTX overlay build failed; see $LOG_ROOT/build-overlay.stderr.log"
fi
HAPROXY_BIN="$RUN_ROOT/overlay/worktree/haproxy"
[ -x "$HAPROXY_BIN" ] || die "current-source HTX build did not create $HAPROXY_BIN"
fi
if ! "$HAPROXY_BIN" -v >"$EVIDENCE_ROOT/haproxy-version.txt" 2>&1; then
    die "current-source HAProxy binary is not runnable"
fi
if ! grep -Fq "HAProxy version $EXPECTED_HAPROXY_VERSION" "$EVIDENCE_ROOT/haproxy-version.txt"; then
    die "current overlay binary is not HAProxy $EXPECTED_HAPROXY_VERSION"
fi

write_spoe_config
start_backend

run_case p3-deny "$P3_RULES" 2000 /p3-deny 403 yes
stop_case_services

run_case p4-safe "$P4_RULES" 2000 /p4-safe 200 yes
if ! grep -Fq 'host_action=log_only' "$RUN_ROOT/cases/p4-safe/haproxy.stderr.log"; then
    die "P4 safe case did not record the Safe/log-only host action"
fi
stop_case_services

run_cancel_case
stop_case_services

run_ttl_case
stop_case_services

run_case missing-correlation "$P4_RULES" 2000 /p4-safe 503 no
if ! grep -Fq 'fail-closed response-companion claim' "$RUN_ROOT/cases/missing-correlation/haproxy.stderr.log"; then
    die "missing-correlation case did not use the P3 fail-closed claim path"
fi
stop_case_services

run_connection_reuse_case
stop_case_services

# Recheck after service reap so a terminal event arriving after the client
# completed cannot escape the normal-case evidence gate.
for normal_case in p3-deny p4-safe connection-reuse; do
    assert_no_unexpected_technical_events "$RUN_ROOT/cases/$normal_case"
done

printf 'owner=combined_spop_htx\nresult=PASS\nchecks=p1-p2-ack-handle,p3-deny,p4-safe-eos,client-cancel,ttl-expiry,missing-correlation,connection-reuse\n' >"$EVIDENCE_ROOT/summary.txt"
run_result=PASS
printf '%s\n' "combined_spop_htx: PASS - evidence retained under $EVIDENCE_ROOT" >&2
