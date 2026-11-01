"""Actual MSE1 relay with independently named, selected-operation faults."""
from modsecurity_test_framework.connector_context import load_source
import hashlib
import argparse
import importlib.util
import json
from pathlib import Path
import signal
import socket
import sys
import threading
import time

transport = load_source(Path(__file__).with_name('fault_proxy.py'))
MANIFEST = '/mnt/fixtures/acceptance-manifest.json'


def wait_client_prefix(key, row):
    marker = Path('/task/barriers') / key
    deadline = time.monotonic() + 5
    while not marker.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    row['actual_client_prefix_marker'] = marker.exists()
    if not marker.exists():
        raise TimeoutError('no client prefix before postcommit fault')


def corrupt_metadata(case, payload):
    uri = case['fixture']['request']['uri'].encode()
    if payload.count(uri) != 1:
        raise ValueError('exact metadata URI not present once')
    return payload.replace(uri, b'\x00' + uri[1:], 1)


def alter_reply(state, row, head, reply):
    kind, opcode, chunks, positive_control, injected = state
    if injected:
        return head, reply, injected
    target = ((kind == 'commit-ack-applied' and opcode == 10) or
              (kind in ('incomplete-framing', 'no-second-response') and opcode == 5 and chunks == 2))
    if target and not positive_control:
        if opcode == 5:
            wait_client_prefix(row['key'], row)
        row['fault'] = 'MSE1-result-TECHNICAL-5'
        return head, reply[:1] + b'\x05' + reply[2:], True
    if kind == 'mse1-error' and opcode == 1:
        row['fault'] = 'MSE1-reply-magic-BAD!'
        return b'BAD!' + head[4:], reply, True
    timeout_opcode = 5 if kind == 'engine_timeout_after_commit' else 1
    timeout_kind = kind in ('timeout', 'engine_timeout_before_commit', 'engine_timeout_after_commit')
    if timeout_kind and opcode == timeout_opcode and (opcode != 5 or chunks >= 2):
        time.sleep(5.5)
        row['fault'] = 'physical-reply-delay-5500ms-exceeds-real5000ms-client-deadline'
        return head, reply, True
    return head, reply, False


def relay(client, engine_path, case):
    chunks = 0
    injected = False
    fault = case['fixture'].get('fault') or {}
    kind = fault.get('kind')
    key = case['key']
    connection_id = time.monotonic_ns()
    positive_control = False
    try:
        with client, socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as engine:
            engine.settimeout(15)
            client.settimeout(15)
            engine.connect(engine_path)
            while True:
                head, payload = transport.frame(client)
                opcode = head[5]
                if opcode == 1:
                    positive_control = case['positive_control_id'].encode() in payload
                chunks += int(opcode == 5)
                row = {'key': key, 'connection': connection_id, 'opcode': opcode,
                       'request_bytes': len(payload), 'request_sha256': hashlib.sha256(head + payload).hexdigest(),
                       'started_ns': time.monotonic_ns(), 'fault': None}
                if kind == 'invalid-metadata' and opcode == 1 and not injected:
                    payload = corrupt_metadata(case, payload)
                    injected = True
                    row['fault'] = 'outgoing-BEGIN-URI-embedded-NUL'
                engine.sendall(head + payload)
                reply_head, reply = transport.frame(engine)
                reply_head, reply, injected = alter_reply((kind, opcode, chunks,
                    positive_control, injected), row, reply_head, reply)
                row.update(reply_bytes=len(reply), reply_sha256=hashlib.sha256(reply_head + reply).hexdigest(),
                           completed_ns=time.monotonic_ns())
                transport.record(row)
                client.sendall(reply_head + reply)
    except (EOFError, OSError, ValueError) as error:
        transport.record({'key': key, 'connection': connection_id, 'end': type(error).__name__,
                          'injected': injected, 'monotonic_ns': time.monotonic_ns()})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('listener', choices=('/task/sockets/proxy.sock',))
    parser.add_argument('engine')
    parser.add_argument('manifest', choices=(MANIFEST,))
    parser.add_argument('key')
    args = parser.parse_args()
    listener_path = transport.validate_socket(args.listener, listener=True)
    engine_path = transport.validate_socket(args.engine, listener=False)
    if Path(MANIFEST).resolve(strict=True) != Path(MANIFEST):
        raise ValueError('physical sealed manifest required')
    manifest = json.loads(Path(MANIFEST).read_text())
    case = next(c for c in manifest['cases'] if c['key'] == args.key)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(listener_path)
    owned = Path(listener_path).lstat()
    listener.listen(16)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    try:
        while True:
            client, _ = listener.accept()
            threading.Thread(target=relay, args=(client, engine_path, case), daemon=True).start()
    finally:
        listener.close()
        transport.remove_owned_socket(owned)


if __name__ == '__main__':
    main()
