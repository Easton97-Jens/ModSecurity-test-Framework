"""Test-only UDS relay: real engine execution, explicit physical reply faults."""
import json
import argparse
import os
from pathlib import Path
import re
import signal
import socket
import struct
import stat
import sys
import threading
import time

LOG = Path('/task/proxy.jsonl')
LOCK = threading.Lock()
SOCKET_ROOT = Path('/task/sockets')


def record(value):
    with LOCK, LOG.open('a') as output:
        output.write(json.dumps(value) + '\n')


def exact(connection, count):
    result = bytearray()
    while len(result) < count:
        part = connection.recv(count - len(result))
        if not part:
            raise EOFError()
        result.extend(part)
    return bytes(result)


def frame(connection):
    head = exact(connection, 12)
    count = struct.unpack('!I', head[8:12])[0]
    if count > 131072:
        raise ValueError('bounded proxy frame exceeded')
    return head, exact(connection, count)


def reply_fault(label, opcode, body_chunks, head, payload):
    if label == 'fault-mse1' and opcode == 1:
        return b'BAD1' + head[4:], payload, 'corrupt-MSE1-magic-after-real-engine-begin'
    faults = {
        ('fault-result', 3): 'technical-result-after-real-request-EOS',
        ('fault-ack', 10): 'technical-result-on-acknowledge-applied',
    }
    fault = faults.get((label, opcode))
    if label == 'fault-postcommit' and opcode == 5 and body_chunks >= 2:
        fault = 'technical-result-on-response-chunk-after-host-headers'
    if fault:
        payload = payload[:1] + b'\x05' + payload[2:]
    return head, payload, fault


def request_label(payload, previous):
    match = re.search(rb'/i12-eos-([a-z0-9-]+)', payload)
    return match[1].decode() if match else previous


def relay(client, engine_path):
    label = 'unknown'
    connection_id = time.monotonic_ns()
    body_chunks = 0
    try:
        with client, socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as engine:
            engine.settimeout(15)
            client.settimeout(15)
            engine.connect(engine_path)
            while True:
                head, payload = frame(client)
                opcode = head[5]
                body_chunks += int(opcode == 5)
                if opcode == 1:
                    label = request_label(payload, label)
                engine.sendall(head + payload)
                reply_head, reply_payload = frame(engine)
                reply_head, reply_payload, fault = reply_fault(label, opcode, body_chunks, reply_head, reply_payload)
                record({'connection': connection_id, 'label': label, 'opcode': opcode,
                        'request_payload_bytes': len(payload), 'reply_payload_bytes': len(reply_payload),
                        'fault': fault, 'monotonic_ns': time.monotonic_ns()})
                client.sendall(reply_head + reply_payload)
    except (EOFError, OSError, ValueError) as error:
        record({'connection': connection_id, 'label': label, 'end': type(error).__name__,
                'monotonic_ns': time.monotonic_ns()})


def validate_socket_directory(path, *, strict=False):
    try:
        metadata = path.stat()
    except OSError as error:
        raise ValueError('physical socket directory required') from error
    if metadata.st_uid != os.getuid() or metadata.st_mode & 0o022:
        raise ValueError('socket directory must be private and task-owned')
    if not stat.S_ISDIR(metadata.st_mode) or (strict and stat.S_IMODE(metadata.st_mode) != 0o700):
        raise ValueError('private physical socket directory required')


def validate_engine_socket(candidate):
    child = candidate.parent
    if (candidate.name != 'engine.sock' or child.parent != SOCKET_ROOT or
            re.fullmatch(r'msconnector-traefik-uds-[A-Za-z0-9_-]{1,32}', child.name) is None):
        raise ValueError('actual engine socket required')
    validate_socket_directory(child, strict=True)
    metadata = candidate.lstat()
    if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise ValueError('task-owned engine socket required')


def validate_socket(path, *, listener):
    candidate = Path(path)
    if not candidate.is_absolute() or '..' in candidate.parts or len(os.fsencode(candidate)) > 100:
        raise ValueError('private bounded task socket required')
    if listener and candidate != SOCKET_ROOT / 'proxy.sock':
        raise ValueError('private task socket required')
    if any(part.is_symlink() for part in (candidate, *candidate.parents)):
        raise ValueError('symlink socket path prohibited')
    validate_socket_directory(SOCKET_ROOT)
    if listener:
        if candidate != SOCKET_ROOT / 'proxy.sock' or candidate.exists():
            raise ValueError('fresh proxy socket required')
    else:
        validate_engine_socket(candidate)
    return str(candidate)


def remove_owned_socket(owned):
    path = Path('/task/sockets/proxy.sock')
    try:
        current = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISSOCK(current.st_mode) and (current.st_dev, current.st_ino) == (owned.st_dev, owned.st_ino):
        path.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('listener', choices=('/task/sockets/proxy.sock',))
    parser.add_argument('engine', type=lambda value: validate_socket(value, listener=False))
    args = parser.parse_args()
    path = validate_socket(args.listener, listener=True)
    engine_path = validate_socket(args.engine, listener=False)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(path)
    owned = Path(path).lstat()
    listener.listen(16)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    try:
        while True:
            client, _ = listener.accept()
            threading.Thread(target=relay, args=(client, engine_path), daemon=True).start()
    finally:
        listener.close()
        remove_owned_socket(owned)


if __name__ == '__main__':
    main()
