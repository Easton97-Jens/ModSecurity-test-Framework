#!/bin/sh
set -eu
: "${TEST_ROOT:?TEST_ROOT is required explicitly}"

REPO_ROOT=${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}
BUILD_ROOT="${BUILD_ROOT:-${TMPDIR:-/var/tmp}/ModSecurity-conector-verified/build}"
OUT_DIR="${TRAEFIK_ENGINE_SERVICE_BUILD_DIR:-$BUILD_ROOT/traefik-engine-service}"
ENGINE_BIN="${TRAEFIK_ENGINE_SERVICE_BIN:-$OUT_DIR/traefik-engine-service}"
PYTHON_BIN="${PYTHON:-python3}"
SOCKET_PARENT="${TRAEFIK_ENGINE_SOCKET_TEST_PARENT:-}"
SOCKET_DIR=""
SOCKET_PATH=""
CONFIG_PATH="$REPO_ROOT/connectors/traefik/config/traefik-engine-service.conf"
SERVICE_PID=""

case "$ENGINE_BIN" in
    /*) ;;
    *) echo "FAIL: TRAEFIK_ENGINE_SERVICE_BIN must be absolute" >&2; exit 1 ;;
esac

if [ ! -x "$ENGINE_BIN" ]; then
    echo "FAIL: build-engine-service must produce an executable before runtime test" >&2
    exit 1
fi
if [ ! -f "$CONFIG_PATH" ]; then
    echo "FAIL: engine-service example configuration is missing" >&2
    exit 1
fi
command -v "$PYTHON_BIN" >/dev/null 2>&1 || {
    echo "BLOCKED: missing Python interpreter for local Unix-socket protocol test" >&2
    exit 77
}
case "$SOCKET_PARENT" in
    "") echo "BLOCKED: TRAEFIK_ENGINE_SOCKET_TEST_PARENT must name an existing private 0700 directory" >&2; exit 77 ;;
    /*) ;;
    *) echo "BLOCKED: TRAEFIK_ENGINE_SOCKET_TEST_PARENT must be absolute" >&2; exit 77 ;;
esac
if [ ! -d "$SOCKET_PARENT" ] || [ -L "$SOCKET_PARENT" ]; then
    echo "BLOCKED: engine-service socket parent must be a real directory" >&2
    exit 77
fi
if [ "$(stat -c '%u' "$SOCKET_PARENT")" != "$(id -u)" ] ||
   [ "$(stat -c '%a' "$SOCKET_PARENT")" != 700 ]; then
    echo "BLOCKED: TRAEFIK_ENGINE_SOCKET_TEST_PARENT must name an existing private 0700 directory" >&2
    exit 77
fi
SOCKET_PARENT_CANONICAL=$("$PYTHON_BIN" -c '
import os
import stat
import sys

candidate = sys.argv[1]
if any(ord(character) < 0x20 or ord(character) == 0x7F for character in candidate):
    raise SystemExit(1)
canonical = os.path.realpath(candidate)
if canonical != candidate:
    raise SystemExit(1)
child = candidate
while child != os.path.dirname(child):
    child_stat = os.lstat(child)
    ancestor = os.path.dirname(child)
    ancestor_stat = os.lstat(ancestor)
    parent_mode = stat.S_IMODE(ancestor_stat.st_mode)
    if not stat.S_ISDIR(ancestor_stat.st_mode):
        raise SystemExit(1)
    if parent_mode & (stat.S_IWGRP | stat.S_IWOTH):
        if not (parent_mode & stat.S_ISVTX and child_stat.st_uid == os.geteuid()):
            raise SystemExit(1)
    child = ancestor
print(canonical)
' "$SOCKET_PARENT") || {
    echo "BLOCKED: TRAEFIK_ENGINE_SOCKET_TEST_PARENT must be canonical, symlink-free, and protected from cross-user ancestor replacement" >&2
    exit 77
}
[ "$SOCKET_PARENT_CANONICAL" = "$SOCKET_PARENT" ] || {
    echo "BLOCKED: TRAEFIK_ENGINE_SOCKET_TEST_PARENT must be canonical, symlink-free, and protected from cross-user ancestor replacement" >&2
    exit 77
}

cleanup() {
    if [ -n "$SERVICE_PID" ]; then
        kill "$SERVICE_PID" 2>/dev/null || true
        wait "$SERVICE_PID" 2>/dev/null || true
    fi
    if [ -n "$SOCKET_DIR" ] && [ ! -L "$SOCKET_DIR" ]; then
        rm -f "$SOCKET_DIR/config.conf"
        rmdir "$SOCKET_DIR" 2>/dev/null || true
    fi
}
trap cleanup EXIT HUP INT TERM

# The durable test build root can be far beyond Unix-domain pathname limits.
# Keep this transient transport socket in a short, private directory instead;
# it is neither a runtime artifact nor an evidence destination.
SOCKET_DIR=$(mktemp -d "$SOCKET_PARENT"/msconnector-traefik-engine-test.XXXXXX) || {
    echo "BLOCKED: unable to create private engine-service socket directory" >&2
    exit 77
}
case "$SOCKET_DIR" in
    "$SOCKET_PARENT"/msconnector-traefik-engine-test.*) ;;
    *)
        echo "BLOCKED: unexpected private engine-service socket directory: $SOCKET_DIR" >&2
        exit 77
        ;;
esac
[ ! -L "$SOCKET_DIR" ] || {
    echo "BLOCKED: private engine-service socket directory is a symlink" >&2
    exit 77
}
CONFIG_TEMPLATE="$CONFIG_PATH"
CONFIG_PATH="$SOCKET_DIR/config.conf"
while IFS= read -r config_line || [ -n "$config_line" ]; do
    case "$config_line" in
        rules_file=*) printf 'rules_file=%s\n' "$TEST_ROOT/connector_suite/common/rules/modsecurity_targeted_smoke.conf" ;;
        *) printf '%s\n' "$config_line" ;;
    esac
done < "$CONFIG_TEMPLATE" > "$CONFIG_PATH"
SOCKET_PATH="$SOCKET_DIR/engine.sock"
case "$SOCKET_PATH" in
    /*) ;;
    *) echo "FAIL: protocol socket path must be absolute" >&2; exit 1 ;;
esac
[ "${#SOCKET_PATH}" -le 100 ] || {
    echo "BLOCKED: private engine-service socket path is too long" >&2
    exit 77
}

(
    cd "$REPO_ROOT"
    "$ENGINE_BIN" --check-config --config "$CONFIG_PATH"
)
(
    cd "$REPO_ROOT"
    "$ENGINE_BIN" --serve --config "$CONFIG_PATH" --socket "$SOCKET_PATH" \
        --max-connections 5
) &
SERVICE_PID=$!

SOCKET_PATH="$SOCKET_PATH" "$PYTHON_BIN" -c '
import os
import socket
import stat
import struct
import time

path = os.environ["SOCKET_PATH"]
for _ in range(250):
    if os.path.exists(path):
        break
    time.sleep(0.02)
else:
    raise SystemExit("engine service socket did not appear")

socket_stat = os.stat(path)
assert stat.S_ISSOCK(socket_stat.st_mode)
assert socket_stat.st_uid == os.geteuid()
parent_stat = os.stat(os.path.dirname(path))
assert parent_stat.st_uid == os.geteuid()
assert stat.S_IMODE(parent_stat.st_mode) == 0o700

def text(value):
    raw = value.encode("ascii")
    return len(raw).to_bytes(2, "big") + raw

def exact(connection, count):
    data = b""
    while len(data) < count:
        fragment = connection.recv(count - len(data))
        if not fragment:
            raise AssertionError("unexpected engine-service EOF")
        data += fragment
    return data

def invoke(connection, opcode, payload, expected_result):
    frame = b"MSE1" + bytes((1, opcode, 0, 0))
    connection.sendall(frame + len(payload).to_bytes(4, "big") + payload)
    header = exact(connection, 12)
    assert header[:4] == b"MSE1" and header[4] == 1 and header[5] == 128
    result = exact(connection, int.from_bytes(header[8:12], "big"))
    assert result[0] == opcode and result[1] == expected_result, result[:2]
    return result

def assert_terminal(connection):
    # Once a technical RESULT was sent, no later command may reach the
    # transaction. EOF and peer reset are equivalent terminal dispositions.
    connection.settimeout(3)
    commands = ((10, b"\x00\x00\x00\x00"), (3, b""), (8, b""))
    frames = b""
    for opcode, payload in commands:
        frame = b"MSE1" + bytes((1, opcode, 0, 0))
        frames += frame + len(payload).to_bytes(4, "big") + payload
    try:
        connection.sendall(frames)
    except (BrokenPipeError, ConnectionResetError):
        pass
    try:
        received = connection.recv(12)
    except ConnectionResetError:
        received = b""
    assert received == b"", ("terminal peer accepted another command", received)

def begin_payload(uri, request_id, headers):
    wire_headers = len(headers).to_bytes(2, "big")
    for name, value in headers:
        wire_headers += text(name) + text(value)
    return (
        text("GET") + text(uri) + text("HTTP/1.1") + text("example.test") +
        text("127.0.0.1") + (12345).to_bytes(2, "big") +
        text("127.0.0.1") + (80).to_bytes(2, "big") + text(request_id) +
        wire_headers
    )

with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
    connection.connect(path)
    invoke(connection, 1, begin_payload("/engine-oversized", "engine-runtime-oversized", [
        ("host", "example.test")
    ]), 0)
    # A single oversized frame is a technical terminal error, independently
    # of native body policy. OUTCOME cannot revive its rejected transaction.
    invoke(connection, 2, b"x" * 32769, 2)
    assert_terminal(connection)

with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
    connection.connect(path)
    invoke(connection, 1, begin_payload("/engine-invalid-outcome", "engine-runtime-invalid-outcome", [
        ("host", "example.test")
    ]), 0)
    # No disruptive action is pending: this OUTCOME is independently invalid.
    invoke(connection, 10, b"\x00\x00\x00\x00", 2)
    assert_terminal(connection)

# All legitimate P2/EOS/P3/P4/finish/destroy controls use a fresh transaction.
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
    connection.connect(path)
    invoke(connection, 1, begin_payload("/engine-safe", "engine-runtime-safe", [
        ("host", "example.test")
    ]), 0)
    invoke(connection, 3, b"", 0)
    response = (200).to_bytes(2, "big") + text("HTTP/1.1") + (0).to_bytes(2, "big")
    invoke(connection, 4, response, 0)
    invoke(connection, 7, b"\x00\x00", 0)
    invoke(connection, 6, b"", 0)
    invoke(connection, 8, b"", 0)
    invoke(connection, 9, b"", 0)

# A peer reset while the service is writing must be isolated to that peer.
# The listener remains alive for the following legitimate connection; this
# also exercises the per-send MSG_NOSIGNAL path without globally ignoring
# SIGPIPE.
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
    connection.connect(path)
    payload = begin_payload("/engine-reset", "engine-runtime-reset", [
        ("host", "example.test")
    ])
    frame = b"MSE1" + bytes((1, 1, 0, 0))
    connection.sendall(frame + len(payload).to_bytes(4, "big") + payload)
    connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                          struct.pack("ii", 1, 0))

# The following persistent-service connection proves that the Common runtime
# evaluates the configured targeted request-header rule. It is still not a
# Traefik host action: OUTCOME is only the service in-memory coordination
# hook and writes no evidence.
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
    connection.connect(path)
    denied = invoke(connection, 1, begin_payload("/engine-block", "engine-runtime-block", [
        ("host", "example.test"), ("x-modsec-smoke", "block")
    ]), 0)
    assert denied[2] == 2 and denied[3] == 2 and denied[4:6] == (403).to_bytes(2, "big")
    invoke(connection, 10, bytes((2, 1)) + (403).to_bytes(2, "big"), 0)
    invoke(connection, 8, b"", 0)
    invoke(connection, 9, b"", 0)

print("traefik_engine_service_protocol_runtime_test=pass")
'

wait "$SERVICE_PID"
SERVICE_PID=""
if [ -e "$SOCKET_PATH" ]; then
    echo "FAIL: engine service did not remove its Unix socket" >&2
    exit 1
fi

# A peer that never reads must not hold a worker indefinitely.  Run this in a
# separate service instance so the bounded first-pass connection count above
# remains deterministic.  The client receive buffers are deliberately small;
# each peer sends valid frames but never reads the RESULT frames, forcing the
# service send path to reach its monotonic 30-second deadline.  All 64 worker
# slots are exercised so the follow-up proves that at least one timed-out
# worker was released before the next request was admitted.
(
    cd "$REPO_ROOT"
    "$ENGINE_BIN" --serve --config "$CONFIG_PATH" --socket "$SOCKET_PATH"
) &
SERVICE_PID=$!
SOCKET_PATH="$SOCKET_PATH" "$PYTHON_BIN" -c '
import os
import select
import socket
import time

path = os.environ["SOCKET_PATH"]
for _ in range(250):
    if os.path.exists(path):
        break
    time.sleep(0.02)
else:
    raise SystemExit("engine service socket did not appear for send-deadline test")

def text(value):
    raw = value.encode("ascii")
    return len(raw).to_bytes(2, "big") + raw

def begin_payload(request_id):
    return (
        text("GET") + text("/engine-send-deadline") + text("HTTP/1.1") +
        text("example.test") + text("127.0.0.1") + (12345).to_bytes(2, "big") +
        text("127.0.0.1") + (80).to_bytes(2, "big") + text(request_id) +
        (1).to_bytes(2, "big") + text("host") + text("example.test")
    )

def frame(opcode, payload=b""):
    return (b"MSE1" + bytes((1, opcode, 0, 0)) +
            len(payload).to_bytes(4, "big") + payload)

def exact(connection, count):
    data = b""
    while len(data) < count:
        fragment = connection.recv(count - len(data))
        if not fragment:
            raise AssertionError("follow-up connection closed before RESULT")
        data += fragment
    return data

def followup():
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        connection.settimeout(3.0)
        connection.connect(path)
        connection.sendall(frame(1, begin_payload("send-deadline-followup")))
        header = exact(connection, 12)
        assert header[:4] == b"MSE1" and header[5] == 128
        result = exact(connection, int.from_bytes(header[8:12], "big"))
        assert result[0] == 1 and result[1] == 0, result[:2]
    finally:
        connection.close()

def assert_followup_not_admitted_yet():
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        connection.settimeout(1.0)
        connection.connect(path)
        try:
            connection.sendall(frame(1, begin_payload("send-deadline-probe")))
        except (BrokenPipeError, ConnectionResetError):
            # The saturated listener can reject the peer before its first
            # write, as well as while the following recv is pending.
            return
        try:
            data = connection.recv(12)
        except socket.timeout:
            return
        except ConnectionResetError:
            return
        if data:
            raise AssertionError("follow-up was admitted before worker deadline")
    finally:
        connection.close()

peers = []
try:
    # Linux enforces a small minimum receive buffer, but this is still enough
    # to make the bounded RESULT stream fill after a handful of frames.
    for index in range(64):
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
        connection.connect(path)
        connection.sendall(frame(1, begin_payload("send-deadline-%03d" % index)))
        # Empty request chunks are valid and produce fixed-size RESULT frames.
        # They are sent in one batch; the peer deliberately never calls recv().
        connection.sendall(frame(2) * 128)
        peers.append(connection)
    time.sleep(1.0)
    assert_followup_not_admitted_yet()
    started = time.monotonic()
    # The production deadline is 30 seconds.  Add a small scheduling margin,
    # while keeping the wait below the repository 60-second command limit.
    deadline = started + 31.0
    while time.monotonic() < deadline:
        time.sleep(min(0.25, deadline - time.monotonic()))
    followup_started = time.monotonic()
    followup_error = None
    for _ in range(24):
        try:
            followup()
            followup_error = None
            break
        except (AssertionError, OSError, socket.timeout) as error:
            followup_error = error
            time.sleep(0.25)
    if followup_error is not None:
        raise AssertionError("follow-up was not served after send deadline: %s" % followup_error)
    elapsed = time.monotonic() - started
    print("traefik_engine_service_nonreading_peer_deadline_test=pass peers=64 elapsed_seconds=%.1f followup_latency_seconds=%.1f" %
          (elapsed, time.monotonic() - followup_started))
finally:
    for connection in peers:
        connection.close()
'
kill -TERM "$SERVICE_PID"
wait "$SERVICE_PID" || true
SERVICE_PID=""
if [ -e "$SOCKET_PATH" ]; then
    echo "FAIL: send-deadline service did not remove its Unix socket" >&2
    exit 1
fi

# A pathname replacement after a successful bind belongs to neither the
# service nor this cleanup trap. The service must preserve it and report an
# incomplete cleanup instead of unlinking it on shutdown.
(
    cd "$REPO_ROOT"
    "$ENGINE_BIN" --serve --config "$CONFIG_PATH" --socket "$SOCKET_PATH"
) &
SERVICE_PID=$!
SOCKET_PATH="$SOCKET_PATH" "$PYTHON_BIN" -c '
import os
import socket
import time

path = os.environ["SOCKET_PATH"]
def stat_is_socket(path):
    import stat
    return stat.S_ISSOCK(os.lstat(path).st_mode)

for _ in range(250):
    if os.path.exists(path) and stat_is_socket(path):
        break
    time.sleep(0.02)
else:
    raise SystemExit("engine service socket did not appear for ownership regression")
'

rm -- "$SOCKET_PATH"
printf '%s\n' 'replacement-sentinel' > "$SOCKET_PATH"
kill -TERM "$SERVICE_PID"
if wait "$SERVICE_PID"; then
    echo "FAIL: engine service did not report replaced-socket cleanup refusal" >&2
    exit 1
fi
SERVICE_PID=""
if [ ! -f "$SOCKET_PATH" ] || [ -L "$SOCKET_PATH" ] ||
    [ "$(cat "$SOCKET_PATH")" != 'replacement-sentinel' ]; then
    echo "FAIL: engine service removed or changed the replacement sentinel" >&2
    exit 1
fi
rm -- "$SOCKET_PATH"

rm -f "$CONFIG_PATH"
rmdir "$SOCKET_DIR"
SOCKET_DIR=""
printf 'traefik_engine_service_protocol_negative_test=pass\n'
