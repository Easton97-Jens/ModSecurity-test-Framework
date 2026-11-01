"""Bounded raw actual-host client. Client EOF is deliberately native_eos=null."""
import argparse
import hashlib
import copy
import json
import os
from pathlib import Path
import signal
import socket
import struct
import time

MAX_BYTES = 16 * 1024 * 1024
MANIFEST = '/mnt/fixtures/acceptance-manifest.json'


def request_bytes(case, neighbor=False):
    fixture = case['fixture']['request']
    key = ('neighbor-' if neighbor else '') + case['key']
    body = b'' if neighbor else bytes.fromhex(fixture['body_hex'])
    uri = '/i12/neighbor/' + key if neighbor else fixture['uri']
    method = 'GET' if neighbor else fixture['method']
    headers = [] if neighbor else list(fixture['headers'])
    headers += [('Host', 'example.test'), ('X-I12-Acceptance-Key', key), ('Connection', 'close')]
    if neighbor or not fixture.get('omit_transaction_id'):
        headers.append(('X-Request-Id', case['neighbor_id'] if neighbor else case['transaction_id']))
    chunks = [] if neighbor else fixture['chunk_lengths']
    template = fixture.get('raw_template') if not neighbor else None
    request_framing_headers(headers, template, chunks, body)
    head = (method + ' ' + uri + ' HTTP/1.1\r\n' + ''.join(n + ': ' + v + '\r\n' for n, v in headers) + '\r\n').encode('latin1')
    parts = chunked_request_parts(chunks, body)
    return key, head, parts, body


def await_kernel_backpressure(path, nonce, local, peer, timeout=8):
    """Bounded metadata wait; missing real EAGAIN releases as unqualified."""
    started = time.monotonic_ns()
    result = {'started_ns': started, 'observed_eagain': None, 'release_reason': 'bounded_timeout'}
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.is_file():
            raw = path.read_bytes()
            if len(raw) > 16 * 1024 * 1024:
                result['release_reason'] = 'bounded_metadata_exceeded'
                break
            row = metadata_eagain(raw, nonce, local, peer, started)
            if row is not None:
                result.update(observed_eagain=row, release_reason='actual_target_tuple_eagain')
                result['completed_ns'] = time.monotonic_ns()
                return result
        time.sleep(0.02)
    result['completed_ns'] = time.monotonic_ns()
    return result


def metadata_eagain(raw, nonce, local, peer, started):
    for line in raw.splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue  # An actively written last line can be incomplete.
        if isinstance(row, dict) and target_eagain(row, nonce, local, peer, started):
            return row
    return None


def run(port, case, neighbor=False):
    key, head, parts, body = request_bytes(case, neighbor)
    root = Path('/task/client')
    root.mkdir(mode=0o700, exist_ok=True)
    wire = bytearray()
    received = bytearray()
    receipt = {'key': key, 'id': case['id'], 'neighbor': neighbor, 'pid': os.getpid(),
               'started_ns': time.monotonic_ns(), 'tcp_eof': False, 'native_eos': None,
               'request_body_bytes': len(body), 'request_body_sha256': hashlib.sha256(body).hexdigest()}
    fault = case['fixture'].get('fault') or {}
    kind = fault.get('kind') if not neighbor else None
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=15) as connection:
            connection.settimeout(15)
            backpressure = case['fixture']['request'].get('kernel_backpressure') and not neighbor
            if backpressure:
                receipt['receive_buffer_policy'] = 'unmodified OS default'
                receipt['actual_so_rcvbuf'] = connection.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
            receipt.update(local=list(connection.getsockname()), peer=list(connection.getpeername()))
            (root / (key + '.connection.json')).write_text(json.dumps(receipt | {
                'connected_ns': time.monotonic_ns(), 'response_complete': False}, indent=2) + '\n')
            connection.sendall(head)
            wire.extend(head)
            for part in parts:
                connection.sendall(part)
                wire.extend(part)
                time.sleep(0.06)
            if kind == 'missing-eos':
                connection.shutdown(socket.SHUT_WR)
                receipt['request_http_chunk_terminator_deliberately_omitted'] = True
            elif parts:
                connection.sendall(b'0\r\n\r\n')
                wire.extend(b'0\r\n\r\n')
            elif body:
                connection.sendall(body)
                wire.extend(body)
            receive_response(connection, case, key, root, (receipt, wire, received, kind, backpressure, neighbor))
    except (OSError, ValueError) as error:
        receipt['error'] = {'type': type(error).__name__, 'message': str(error)[:256]}
    receipt['completed_ns'] = time.monotonic_ns()
    save(root, key, wire, received, receipt)


def response_entity(head, encoded):
    headers = {}
    for line in head.split(b'\r\n')[1:]:
        name, separator, value = line.partition(b':')
        if separator:
            headers.setdefault(name.strip().lower(), []).append(value.strip())
    if headers.get(b'transfer-encoding') == [b'chunked']:
        return chunked_entity(encoded)
    if b'content-length' in headers:
        try:
            expected = int(headers[b'content-length'][0])
        except ValueError:
            return encoded, {'framing': 'content-length', 'complete': False, 'invalid_size': True}
        return encoded, {'framing': 'content-length', 'declared': expected,
                         'complete': expected >= 0 and len(encoded) == expected}
    return encoded, {'framing': 'close-delimited', 'complete': None}


def save(root, key, wire, received, receipt):
    raw = bytes(received)
    if b'\r\n\r\n' in raw:
        head, body = raw.split(b'\r\n\r\n', 1)
        receipt['response_headers_latin1'] = head.decode('latin1')
        try:
            receipt['status'] = int(head.split(b'\r\n', 1)[0].split()[1])
        except (ValueError, IndexError):
            receipt['status'] = None
        entity, framing = response_entity(head, body)
        receipt.update(body_bytes=len(body), body_sha256=hashlib.sha256(body).hexdigest(),
            entity_bytes=len(entity), entity_sha256=hashlib.sha256(entity).hexdigest(), http_framing=framing)
        (root / (key + '.response-entity.raw')).write_bytes(entity)
    receipt['status_line_count'] = sum(line.startswith(b'HTTP/1.') for line in raw.split(b'\r\n'))
    receipt['wire_bytes'] = len(raw)
    receipt['wire_sha256'] = hashlib.sha256(raw).hexdigest()
    receipt['measurement_only'] = True
    (root / (key + '.request.raw')).write_bytes(wire)
    (root / (key + '.response.raw')).write_bytes(received)
    (root / (key + '.receipt.json')).write_text(json.dumps(receipt, indent=2) + '\n')


def chunked_request_parts(chunks, body):
    parts = []
    position = 0
    for length in chunks:
        part = body[position:position + length]
        if len(part) != length or length <= 0:
            raise ValueError('request fixture chunk mismatch')
        position += length
        parts.append(f'{length:x}\r\n'.encode() + part + b'\r\n')
    if chunks and position != len(body):
        raise ValueError('request fixture not exhausted')
    return parts


def request_framing_headers(headers, template, chunks, body):
    extra = {'invalid_content_length': [('Content-Length', 'not-a-number')],
             'conflicting_content_length': [('Content-Length', '1'), ('Content-Length', '2')],
             'duplicate_transfer_encoding': [('Transfer-Encoding', 'chunked'), ('Transfer-Encoding', 'chunked')],
             'content_length_overflow': [('Content-Length', '18446744073709551616')]}
    if template:
        headers += extra[template]
    elif chunks:
        headers.append(('Transfer-Encoding', 'chunked'))
    else:
        headers.append(('Content-Length', str(len(body))))


def target_eagain(row, nonce, local, peer, started):
    return (row.get('schema') == 'traefik-own-child-syscall-v1' and row.get('nonce') == nonce and
                    row.get('local_address') == peer[0] and row.get('local_port') == peer[1] and
                    row.get('peer_address') == local[0] and row.get('peer_port') == local[1] and
                    row.get('fd_identity_unchanged') is True and row.get('kernel_result') == -11 and row.get('errno') == 11 and
                    started <= row.get('exit_monotonic_ns', 0) <= time.monotonic_ns())

def chunked_entity(encoded):
    body, remainder = bytearray(), encoded
    while True:
        line, separator, rest = remainder.partition(b'\r\n')
        if not separator:
            return bytes(body), {'framing': 'chunked', 'complete': False}
        try:
            size = int(line.split(b';', 1)[0], 16)
        except ValueError:
            return bytes(body), {'framing': 'chunked', 'complete': False, 'invalid_size': True}
        if size < 0 or size > MAX_BYTES:
            return bytes(body), {'framing': 'chunked', 'complete': False, 'invalid_size': True}
        if size == 0:
            return bytes(body), {'framing': 'chunked', 'complete': rest == b'\r\n'}
        body.extend(rest[:size])
        if len(rest) < size + 2 or rest[size:size + 2] != b'\r\n':
            return bytes(body), {'framing': 'chunked', 'complete': False}
        remainder = rest[size + 2:]


def receive_response(connection, case, key, root, state):
    receipt, received, backpressure = state[0], state[2], state[4]
    while True:
        # Read a bounded prefix bytewise until exactly8192 entity bytes;
        # client reads are outside the host-only syscall observer.
        block = connection.recv(receive_size(backpressure, receipt))
        if not block:
            receipt['tcp_eof'] = True
            break
        received.extend(block)
        receipt.setdefault('first_recv_ns', time.monotonic_ns())
        if len(received) > MAX_BYTES:
            raise ValueError('bounded client response exceeded')
        if received_block(connection, case, key, root, state):
            break


def receive_size(backpressure, receipt):
    return 1 if backpressure and 'kernel_backpressure_wait' not in receipt else 8192


def response_prefix(received, backpressure):
    separator = received.find(b'\r\n\r\n')
    body_received = len(received) - separator - 4 if separator >= 0 else 0
    if backpressure and separator >= 0 and body_received >= 8192:
        body_received = len(response_entity(bytes(received[:separator]), bytes(received[separator + 4:]))[0])
    return separator, body_received


def received_block(connection, case, key, root, state):
    receipt, wire, received, kind, backpressure, neighbor = state
    separator, body_received = response_prefix(received, backpressure)
    active_prefix = kind in ('cancel', 'abort-reset-observation', 'client-exit-signal',
        'incomplete-framing', 'no-second-response', 'engine_timeout_after_commit')
    minimum_prefix = 8192 if active_prefix or backpressure else 1
    if separator >= 0 and body_received >= minimum_prefix:
        if observe_prefix(connection, key, root, (receipt, wire, received, kind, body_received)):
            return True
    if backpressure and 'kernel_backpressure_wait' not in receipt and separator >= 0:
        pause_backpressure(case, key, root, receipt, received, separator)
    if case['fixture']['request'].get('slow_reader') and not neighbor:
        time.sleep(0.005)
    return False


def observe_prefix(connection, key, root, state):
    receipt, wire, received, kind, body_received = state
    marker = Path('/task/barriers') / key
    if not marker.exists():
        marker.write_text(json.dumps({'key': key, 'actual_received_bytes': len(received),
            'actual_received_entity_bytes': body_received,
            'monotonic_ns': time.monotonic_ns(), 'prefix_sha256': hashlib.sha256(received).hexdigest()}))
    if kind in ('cancel', 'abort-reset-observation'):
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        receipt['client_rst_ns'] = time.monotonic_ns()
        return True
    if kind == 'client-exit-signal':
        receipt['requested_signal'] = signal.SIGTERM
        # Parent waits the child and records the actual negative
        # subprocess return. Persist physical prefix first.
        receipt['completed_ns'] = time.monotonic_ns()
        save(root, key, wire, received, receipt)
        os.kill(os.getpid(), signal.SIGTERM)

    return False

def pause_backpressure(case, key, root, receipt, received, separator):
    entity, _ = response_entity(bytes(received[:separator]), bytes(received[separator + 4:]))
    if len(entity) >= 8192:
        receipt['paused_after_entity_bytes'] = len(entity)
        (root / (key + '.response-prefix.raw')).write_bytes(received)
        (root / (key + '.prefix.json')).write_text(json.dumps(receipt | {
            'prefix_ns': time.monotonic_ns(), 'prefix_entity_bytes': len(entity),
            'prefix_entity_sha256': hashlib.sha256(entity).hexdigest(),
            'prefix_wire_sha256': hashlib.sha256(received).hexdigest(), 'response_complete': False}, indent=2) + '\n')
        receipt['kernel_backpressure_wait'] = await_kernel_backpressure(
            Path('/task/cases') / case['key'] / 'host-syscalls.jsonl', case['key'], receipt['local'], receipt['peer'])
        (root / (key + '.pause-result.json')).write_text(json.dumps(receipt['kernel_backpressure_wait'], indent=2) + '\n')


def select_client_case(case, mode):
    if mode in ('neighbor-before', 'neighbor-after'):
        case = copy.deepcopy(case)
        case['key'] = ('main-before-' if mode == 'neighbor-before' else 'main-after-') + case['key']
        case['neighbor_id'] = case['main_before_id' if mode == 'neighbor-before' else 'main_after_id']
    if mode.startswith('readiness-'):
        index = int(mode.removeprefix('readiness-'))
        if not 0 <= index < len(case.get('readiness_ids', [])):
            raise ValueError('readiness attempt outside admitted literal IDs')
        case = copy.deepcopy(case)
        case['key'] = mode + '-' + case['key']
        case['neighbor_id'] = case['readiness_ids'][index]
    if mode == 'sink-recovery':
        case = copy.deepcopy(case)
        case['key'] = 'control-' + case['key']
        case['transaction_id'] = case['positive_control_id']
        case['fixture']['request']['uri'] = case['fixture']['sink_recovery_control']['uri']
        case['fixture']['fault'] = None
    if mode == 'ack-control':
        case = copy.deepcopy(case)
        case['key'] = 'control-' + case['key']
        case['transaction_id'] = case['positive_control_id']
        case['fixture']['fault'] = None
    case = sequence_case(case, mode)
    return main_control_case(case, mode)

def sequence_case(case, mode):
    if mode.startswith('sequence-'):
        index = int(mode.removeprefix('sequence-'))
        if case['fixture']['sequence'] != ['allow_without_marker', 'deny_header_marker_403', 'allow_without_marker']:
            raise ValueError('unsupported original request sequence')
        case = copy.deepcopy(case)
        case['key'] = mode + '-' + case['key']
        case['transaction_id'] = case['sequence_ids'][index]
        case['fixture']['fault'] = None
        case['fixture']['request'] = {'method': 'GET', 'uri': '/no-crs/allow',
            'headers': [['X-Modsec-Smoke', 'deny']] if index == 1 else [],
            'body_hex': '', 'chunk_lengths': []}
    return case

def main_control_case(case, mode):
    if mode in ('main-before', 'main-after'):
        case = copy.deepcopy(case)
        case['fixture']['request']['uri'] = '/i12/reuse/' + mode + '/' + case['key']
        case['key'] = mode + '-' + case['key']
        case['transaction_id'] = case['main_before_id' if mode == 'main-before' else 'main_after_id']
        case['fixture']['fault'] = None
        case['fixture']['request']['raw_template'] = None
        case['fixture']['request']['omit_transaction_id'] = False
        case['fixture']['request']['kernel_backpressure'] = False
        case['fixture']['request']['slow_reader'] = False
    return case

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('port', type=int)
    parser.add_argument('manifest', choices=(MANIFEST,))
    parser.add_argument('key')
    parser.add_argument('mode', nargs='?', default='target')
    args = parser.parse_args()
    if not 1 <= args.port <= 65535 or Path(MANIFEST).resolve(strict=True) != Path(MANIFEST):
        raise ValueError('bounded loopback port and physical sealed manifest required')
    manifest = json.loads(Path(MANIFEST).read_text())
    case = next(c for c in manifest['cases'] + manifest.get('supplementary_executions', []) if c['key'] == args.key)
    mode = args.mode
    case = select_client_case(case, mode)
    # Wait the actual client PID ourselves. The RTK process exit is a different
    # observation and cannot substitute for a signalled child's wait status.
    child = os.fork()
    if child == 0:
        run(args.port, case, mode.startswith(('neighbor', 'readiness-')))
        os._exit(0)
    waited_pid, status = os.waitpid(child, 0)
    returncode = os.waitstatus_to_exitcode(status)
    key = ('neighbor-' if mode.startswith(('neighbor', 'readiness-')) else '') + case['key']
    waited = {'client_pid': child, 'waited_pid': waited_pid, 'raw_wait_status': status,
        'returncode': returncode, 'signal': -returncode if returncode < 0 else None,
        'wait_completed_ns': time.monotonic_ns()}
    (Path('/task/client') / (key + '.wait.json')).write_text(json.dumps(waited, indent=2) + '\n')
