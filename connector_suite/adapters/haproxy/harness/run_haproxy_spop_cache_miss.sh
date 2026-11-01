#!/bin/sh
: "${TEST_ROOT:?TEST_ROOT is required explicitly}"
set -eu

# Direct, production-mode SPOP transaction-cache regression.  This is
# intentionally independent of HAProxy and the Framework: it exercises the
# agent's wire contract and keeps every generated file in one task-owned root.
SCRIPT_DIR=$(CDPATH='' cd "$(dirname "$0")" && pwd)
REPO_ROOT=${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}
BUILD_ROOT=${BUILD_ROOT:-/var/tmp/codex/ModSecurity-conector/spop-cache-miss-build}
SPOA_BIN=${SPOA_BIN:-$BUILD_ROOT/haproxy-spoa-runtime/haproxy-modsecurity-spoa}
RUNTIME_ROOT=${RUNTIME_ROOT:-$BUILD_ROOT/response-phase-guard-regression}
PYTHON_BIN=${PYTHON_BIN:-python3}
RULES_FILE=${RULES_FILE:-$TEST_ROOT/connector_suite/common/rules/modsecurity_targeted_smoke.conf}

case "$BUILD_ROOT" in
  /*) ;;
  *) echo "blocked: BUILD_ROOT must be absolute: $BUILD_ROOT" >&2; exit 77 ;;
esac
case "$RUNTIME_ROOT" in
  /*) ;;
  *) echo "blocked: RUNTIME_ROOT must be absolute: $RUNTIME_ROOT" >&2; exit 77 ;;
esac
case "$BUILD_ROOT" in
  /|/root|/root/*) echo "blocked: BUILD_ROOT is not task-owned: $BUILD_ROOT" >&2; exit 77 ;;
  *) : ;;
esac
case "$RUNTIME_ROOT" in
  /|/root|/root/*|/tmp|/tmp/*) echo "blocked: RUNTIME_ROOT is not task-owned: $RUNTIME_ROOT" >&2; exit 77 ;;
  *) : ;;
esac
[ -x "$SPOA_BIN" ] || {
  echo "blocked: SPOA_BIN is missing or not executable: $SPOA_BIN" >&2
  echo "build with: BUILD_ROOT=$BUILD_ROOT MODSECURITY_INCLUDE_DIR=/usr/include MODSECURITY_LIB_DIR=/usr/lib/x86_64-linux-gnu make -C connectors/haproxy build-spoa-runtime" >&2
  exit 77
}
[ -f "$RULES_FILE" ] || { echo "blocked: RULES_FILE is missing: $RULES_FILE" >&2; exit 77; }

mkdir -p "$RUNTIME_ROOT"
exec "$PYTHON_BIN" - "$SPOA_BIN" "$RULES_FILE" "$RUNTIME_ROOT" <<'PY'
import json
import os
import select
import socket
import struct
import subprocess
import sys
import time

SPOA_BIN, RULES_FILE, ROOT = sys.argv[1:]
PORT = 0

def varint(value):
    if value < 240:
        return bytes((value,))
    out = bytearray(((value & 0xff) | 240,))
    value = (value - 240) >> 4
    while value >= 128:
        out.append((value & 0xff) | 128)
        value = (value - 128) >> 7
    out.append(value)
    return bytes(out)

def string(value):
    raw = value.encode()
    return varint(len(raw)) + raw

def typed_string(value):
    return b"\x08" + string(value)

def typed_ipv4(value):
    return b"\x06" + socket.inet_aton(value)

def typed_uint(value):
    return b"\x03" + varint(value)

def hello():
    return (string("supported-versions") + typed_string("2.0,1.2") +
            string("max-frame-size") + typed_uint(65536) +
            string("capabilities") + typed_string("") +
            string("healthcheck") + b"\x10")

def notify(message, request_id, test_header=""):
    args = [("request_id", typed_string(request_id)),
            ("method", typed_string("GET")),
            ("path", typed_string("/cache-miss")),
            ("uri", typed_string("/cache-miss")),
            ("host", typed_string("localhost")),
            # Production admission requires both endpoint identities.  Keep
            # these in every control request so cache-hit/miss assertions
            # exercise the engine path instead of the missing-metadata guard.
            ("client_ip", typed_ipv4("127.0.0.1")),
            ("server_ip", typed_ipv4("127.0.0.1")),
            ("client_port", typed_uint(41000)),
            ("server_port", typed_uint(8080))]
    headers = "Host: localhost\r\n"
    if test_header:
        headers += "X-Modsec-Smoke: block\r\n"
    args.append(("headers", typed_string(headers)))
    payload = string(message) + bytes((len(args),))
    return payload + b"".join(string(k) + v for k, v in args)

def frame(kind, stream, frame_id, payload):
    body = bytes((kind,)) + struct.pack("!I", 1) + varint(stream) + varint(frame_id) + payload
    return struct.pack("!I", len(body)) + body

def read_exact(sock, count, deadline):
    data = bytearray()
    while len(data) < count:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("SPOP response deadline exceeded")
        ready, _, _ = select.select([sock], [], [], remaining)
        if not ready:
            raise TimeoutError("SPOP response deadline exceeded")
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise ConnectionError("SPOP peer closed")
        data.extend(chunk)
    return bytes(data)

def read_varint(data, pos):
    value = data[pos]
    pos += 1
    if value < 240:
        return value, pos
    shift = 4
    while True:
        byte = data[pos]
        pos += 1
        value += byte << shift
        if byte < 128:
            return value, pos
        shift += 7

def read_string(data, pos):
    length, pos = read_varint(data, pos)
    return data[pos:pos + length].decode(errors="replace"), pos + length

def read_typed(data, pos):
    kind = data[pos] & 0x0f
    raw_kind = data[pos]
    pos += 1
    if kind == 1:
        return bool(raw_kind & 0x10), pos
    if kind == 3:
        return read_varint(data, pos)
    if kind in (8, 9):
        return read_string(data, pos)
    return None, pos

def ack_fields(payload):
    fields = {}
    pos = 0
    while pos < len(payload):
        action = payload[pos]
        pos += 1
        if action != 1:
            raise AssertionError(f"unsupported ACK action {action}")
        count = payload[pos]
        pos += 1
        if count != 3:
            raise AssertionError(f"unexpected ACK action arity {count}")
        pos += 1  # transaction scope
        key, pos = read_string(payload, pos)
        fields[key], pos = read_typed(payload, pos)
    return fields

def recv_frame(sock, timeout=5):
    deadline = time.monotonic() + timeout
    length = struct.unpack("!I", read_exact(sock, 4, deadline))[0]
    body = read_exact(sock, length, deadline)
    kind = body[0]
    pos = 5
    stream, pos = read_varint(body, pos)
    frame_id, pos = read_varint(body, pos)
    return kind, stream, frame_id, body[pos:]

def expect(sock, payload, stream, frame_id):
    sock.sendall(frame(3, stream, frame_id, payload))
    kind, got_stream, got_id, response = recv_frame(sock)
    if kind != 103 or got_stream != stream or got_id != frame_id:
        raise AssertionError(f"unexpected SPOP reply kind={kind} stream={got_stream} frame={got_id}")
    return ack_fields(response)

def record(label, fields):
    result = {"label": label, "fields": fields}
    print(json.dumps(result, sort_keys=True))
    return result

sock = None
agent = None
results = []
try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        PORT = probe.getsockname()[1]
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = env.get("ASAN_OPTIONS", "detect_leaks=1:abort_on_error=1")
    agent = subprocess.Popen([
        SPOA_BIN, "--listen", f"127.0.0.1:{PORT}", "--rules-file", RULES_FILE,
        "--max-transactions", "1", "--worker-count", "2",
        "--spoe-timeout", "1000", "--fail-mode", "closed", "--mode", "block",
        "--log-file", os.path.join(ROOT, "agent.log"),
        "--decision-log", os.path.join(ROOT, "decisions.jsonl")],
        cwd=os.path.dirname(SPOA_BIN), env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    deadline = time.monotonic() + 5
    while True:
        if agent.poll() is not None:
            raise RuntimeError("SPOA agent exited before accepting connections")
        try:
            sock = socket.create_connection(("127.0.0.1", PORT), timeout=0.2)
            break
        except OSError:
            if time.monotonic() >= deadline:
                raise TimeoutError("SPOA agent did not accept a loopback connection")
    sock.settimeout(5)
    sock.sendall(frame(1, 0, 0, hello()))
    kind, _, _, _ = recv_frame(sock)
    if kind != 101:
        raise AssertionError(f"agent HELLO missing, got kind={kind}")

    results.append(record("request-A-allow", expect(sock, notify("check-request", "A"), 1, 1)))
    results.append(record("request-B-follow-up", expect(sock, notify("check-request", "B"), 2, 1)))
    rejected = record("response-disabled-phase", expect(sock, notify("check-response", "A"), 1, 2))
    if (rejected["fields"].get("status") != 503 or
            rejected["fields"].get("blocked") is not True or
            rejected["fields"].get("error") != "response_phase_disabled_closed"):
        raise AssertionError(f"disabled response phase was not rejected fail-closed: {rejected}")
    blocked = record("request-block", expect(sock, notify("check-request", "BLOCK", "block"), 3, 1))
    if blocked["fields"].get("status") != 403 or blocked["fields"].get("blocked") is not True:
        raise AssertionError(f"legitimate block control failed: {blocked}")
    allowed = record("request-C-fresh-allow", expect(sock, notify("check-request", "C"), 4, 1))
    if allowed["fields"].get("status") != 200 or allowed["fields"].get("blocked") is not False:
        raise AssertionError(f"fresh allow control failed: {allowed}")
    print("spop-response-phase-guard-regression: PASS")
finally:
    if sock is not None:
        try:
            sock.close()
        except OSError:
            pass
    if agent is not None:
        agent.terminate()
        try:
            agent.wait(timeout=3)
        except subprocess.TimeoutExpired:
            agent.kill()
            agent.wait(timeout=3)
    if agent is not None and agent.stderr is not None:
        stderr = agent.stderr.read()
        if agent.returncode not in (0, -15):
            sys.stderr.write(stderr)
            raise SystemExit(f"SPOA agent exited with status {agent.returncode}")
PY
