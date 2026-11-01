#!/usr/bin/env python3
"""Summarize handed-back Envoy physical captures without assigning oracle PASS.

Hashes, measured counts and closed metadata are emitted. Payloads, opaque
leases and arbitrary log/error text remain exclusively in the original files.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import modsecurity_connector_ci.runtime.lifecycle.i12.envoy.source_inventory as source_inventory
import modsecurity_connector_ci.runtime.lifecycle.i12.envoy.evidence_io as evidence_io
import modsecurity_connector_ci.runtime.lifecycle.i12.envoy.transport as maintained_transport
import modsecurity_connector_ci.runtime.lifecycle.i12.envoy.grpc_stream_observations as maintained_capture
from modsecurity_connector_ci.runtime.lifecycle.i12.envoy.transport import paths

HERE = Path(__file__).resolve().parent
STORAGE = evidence_io.STORAGE
MAX_PARSE_BYTES = 32 * 1024 * 1024
BINDING_CACHE = {}
CLIENT_PREFIX = 'client/'
COMMAND_SUFFIX = '.command.json'


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def error_kind(error):
    return type(error).__name__ if error is not None else None


def counter(values):
    return dict(sorted(Counter(str(value) for value in values).items()))


def binding_summary(binding):
    source, ledger = Path(binding['source']), Path(binding['ledger'])
    key = (str(source), str(ledger), binding['ledger_sha256'])
    if key in BINDING_CACHE:
        return BINDING_CACHE[key]
    ledger_matches = digest(ledger) == binding['ledger_sha256']
    files = json.loads(ledger.read_text())['files']
    mismatches = []
    for relative, expected in files.items():
        target = source / relative
        if (Path(relative).is_absolute() or '..' in Path(relative).parts
                or not target.is_file() or target.resolve() != target or digest(target) != expected):
            mismatches.append(relative)
    result = {'ledger_hash_verified': ledger_matches, 'file_count': len(files),
              'all_file_hashes_verified': not mismatches, 'mismatched_paths': mismatches}
    BINDING_CACHE[key] = result
    return result


class Artifacts:
    """Read only stable physical regular files and seal every consumed byte."""
    def __init__(self, root):
        self.root, self.files, self.issues = root, {}, []
        for directory, directories, names in os.walk(root, followlinks=False):
            for name in tuple(directories):
                path = Path(directory) / name
                if path.is_symlink():
                    directories.remove(name)
                    self.issues.append({'path': str(path.relative_to(root)), 'kind': 'symlink_directory'})
            for name in names:
                path = Path(directory) / name
                relative = str(path.relative_to(root))
                before = path.lstat()
                if not stat.S_ISREG(before.st_mode):
                    self.issues.append({'path': relative, 'kind': 'nonregular_file'})
                    continue
                sha = digest(path)
                after = path.stat()
                if (before.st_ino, before.st_size, before.st_mtime_ns) != (
                        after.st_ino, after.st_size, after.st_mtime_ns):
                    self.issues.append({'path': relative, 'kind': 'changed_during_hash'})
                    continue
                self.files[relative] = {'bytes': after.st_size, 'sha256': sha}

    def raw(self, relative):
        metadata = self.files.get(relative)
        if metadata is None:
            return None
        if metadata['bytes'] > MAX_PARSE_BYTES:
            self.issues.append({'path': relative, 'kind': 'parse_size_bound'})
            return None
        value = (self.root / relative).read_bytes()
        if hashlib.sha256(value).hexdigest() != metadata['sha256']:
            self.issues.append({'path': relative, 'kind': 'changed_after_hash'})
            return None
        return value

    def json(self, relative):
        raw = self.raw(relative)
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except ValueError as error:
            self.issues.append({'path': relative, 'kind': error_kind(error)})
            return None

    def rows(self, relative):
        raw = self.raw(relative)
        if raw is None:
            return None
        try:
            rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
            if any(not isinstance(row, dict) for row in rows):
                raise ValueError('nonobject observation')
            return rows
        except ValueError as error:
            self.issues.append({'path': relative, 'kind': error_kind(error)})
            return None

    def compare(self, relative, expected):
        actual = self.files.get(relative)
        match = actual is not None and actual['sha256'] == expected
        if not match:
            self.issues.append({'path': relative, 'kind': 'receipt_hash_mismatch'})
        return match


def chunked_entity(wire):
    """Return entity bytes only for complete bounded chunk framing."""
    body, remainder = bytearray(), wire
    try:
        for _ in range(4096):
            token, remainder = remainder.split(b'\r\n', 1)
            if not re.fullmatch(rb'[0-9a-fA-F]+', token):
                return None
            size = int(token, 16)
            if size == 0:
                return body if remainder == b'\r\n' else None
            if size > 65536 - len(body) or len(remainder) < size + 2 or remainder[size:size+2] != b'\r\n':
                return None
            body.extend(remainder[:size])
            remainder = remainder[size+2:]
    except ValueError:
        return None
    return None


def raw_response_summary(raw):
    result = {'framing_complete': None, 'entity_bytes': None, 'wire_body_bytes': None}
    if raw is None or b'\r\n\r\n' not in raw:
        return result
    head, wire = raw.split(b'\r\n\r\n', 1)
    result['wire_body_bytes'] = len(wire)
    fields = [line.split(b':', 1) for line in head.split(b'\r\n')[1:] if b':' in line]
    lengths = [value.strip() for name, value in fields if name.lower() == b'content-length']
    transfer = [value.strip().lower() for name, value in fields if name.lower() == b'transfer-encoding']
    if transfer:
        result['framing_complete'] = False
        if transfer != [b'chunked'] or lengths:
            return result
        body = chunked_entity(wire)
        if body is not None:
            result.update(framing_complete=True, entity_bytes=len(body),
                          entity_sha256=hashlib.sha256(body).hexdigest())
    elif len(lengths) == 1 and lengths[0].isdigit():
        complete = int(lengths[0]) == len(wire)
        result['framing_complete'] = complete
        if complete:
            result.update(entity_bytes=len(wire), entity_sha256=hashlib.sha256(wire).hexdigest())
    return result


def content_type(raw):
    if raw is None:
        return None
    header = raw.split(b'\r\n\r\n', 1)[0]
    values = [line.split(b':', 1)[1].strip().decode('ascii', errors='replace')
              for line in header.split(b'\r\n')[1:] if line.lower().startswith(b'content-type:')]
    allowed = {'text/plain', 'text/plain; charset=utf-8', 'application/octet-stream'}
    return values[0] if len(values) == 1 and values[0] in allowed else 'unknown_or_unclassified'


def client_barrier(artifacts, label):
    raw = artifacts.json(CLIENT_PREFIX + label + '.first-entity.json')
    if not isinstance(raw, dict):
        return None
    return {key: raw[key] for key in ('monotonic_ns', 'wall_ns') if type(raw.get(key)) is int}


def client_body_matches(artifacts, label, receipt, body, request):
    request_body = request.split(b'\r\n\r\n', 1)[1] if request and b'\r\n\r\n' in request else None
    request_match = (request_body is not None and len(request_body) == receipt.get('request_bytes')
                     and hashlib.sha256(request_body).hexdigest() == receipt.get('request_sha256'))
    response_match = (body is not None and body['bytes'] == receipt.get('bytes')
                      and artifacts.compare(CLIENT_PREFIX + label + '.body.raw', receipt.get('sha256')))
    if not request_match:
        artifacts.issues.append({'path': CLIENT_PREFIX + label + '.request.raw', 'kind': 'request_body_receipt_mismatch'})
    return request_match, response_match


def client_summary(artifacts, label):
    receipt = artifacts.json(CLIENT_PREFIX + label + '.receipt.json')
    if not isinstance(receipt, dict):
        return {'observed': False, 'http_status': None, 'unknown': ['client_receipt']}
    body = artifacts.files.get(CLIENT_PREFIX + label + '.body.raw')
    request = artifacts.raw(CLIENT_PREFIX + label + '.request.raw')
    request_match, response_match = client_body_matches(artifacts, label, receipt, body, request)
    response = artifacts.raw(CLIENT_PREFIX + label + '.response.raw')
    status_match = re.match(rb'HTTP/\d(?:\.\d)? (\d{3})[ \r]', response or b'')
    raw_status = int(status_match[1]) if status_match else None
    sent = receipt.get('actual_send_calls')
    barrier = client_barrier(artifacts, label)
    return {'observed': True, 'http_status': receipt.get('status'), 'raw_http_status': raw_status,
            'status_agrees_with_raw': raw_status is not None and raw_status == receipt.get('status'),
            'request_body_bytes': receipt.get('request_bytes'), 'request_body_hash_verified': request_match,
            'request_bytes_scope': 'prepared_raw_request_not_proof_of_delivery',
            'request_content_type': content_type(request), 'response_content_type': content_type(response),
            'response_body_bytes': receipt.get('bytes'), 'response_wire_body_bytes': receipt.get('wire_body_bytes'),
            'independent_raw_response': raw_response_summary(response),
            'response_body_hash_verified': response_match,
            'actual_request_send_calls': len(sent) if isinstance(sent, list) else None,
            'actual_request_send_bytes': sum(row['bytes'] for row in sent) if isinstance(sent, list) else None,
            'response_chunk_sizes': receipt.get('chunk_sizes'),
            'tls_stream_eof_observed': receipt.get('tls_stream_eof_observed'),
            'tcp_eof_observed': receipt.get('tcp_eof_observed'),
            'tcp_reset_observed': receipt.get('tcp_reset_observed'),
            'tcp_close_error': ({key: receipt['tcp_close_error'].get(key) for key in ('type', 'errno')}
                                if isinstance(receipt.get('tcp_close_error'), dict) else None),
            'deliberate_cancel': receipt.get('deliberate_cancel'),
            'deliberate_cancel_after_entity_byte': receipt.get('deliberate_cancel_after_entity_byte'),
            'first_entity_barrier': barrier,
            'first_entity_barrier_matches_client': bool(barrier and barrier == receipt.get('first_entity_clock')),
            'started_monotonic_ns': receipt.get('started_ns'),
            'completed_monotonic_ns': receipt.get('completed_ns'),
            'process_exit': receipt.get('proposed_process_exit'),
            'error_type': (receipt.get('error') or {}).get('type')}


def backend_raw_requests(artifacts, shape, rows):
    raw_requests = []
    for name in sorted(artifacts.files):
        match = re.fullmatch(r'backend/(\d+)\.request-line\.raw', name)
        if match is None:
            continue
        sequence = int(match[1])
        line = (artifacts.raw(name) or b'').split()
        path = line[1].decode('ascii', errors='replace') if len(line) >= 2 else None
        role = next((label for label in ('target', 'neighbor')
                     if shape.get(label) and path == '/' + shape[label]), 'unmapped')
        raw_requests.append({'sequence': sequence, 'role': role,
            'parsed_headers_retained': f'backend/{sequence}.parsed-headers.json' in artifacts.files,
            'framing_error_retained': f'backend/{sequence}.framing-error.json' in artifacts.files,
            'completed_receipt_retained': any(row.get('sequence') == sequence for row in rows or []),
            'captured_request_body_bytes': (artifacts.files.get(f'backend/{sequence}.request-body.raw') or {}).get('bytes')})
    return raw_requests


def backend_completed_requests(artifacts, shape, rows):
    requests = []
    for row in rows or []:
        sequence = row.get('sequence')
        role = next((label for label in ('target', 'neighbor')
                     if shape.get(label) and row.get('path') == '/' + shape[label]), 'unmapped')
        hashes = {}
        for direction in ('request', 'response'):
            name = f'backend/{sequence}.{direction}-body.raw'
            hashes[direction] = artifacts.compare(name, row.get(direction + '_sha256'))
            metadata = artifacts.files.get(name)
            if metadata and metadata['bytes'] != row.get(direction + '_bytes'):
                artifacts.issues.append({'path': name, 'kind': 'receipt_size_mismatch'})
                hashes[direction] = False
        sends = row.get('actual_response_send_calls')
        requests.append({'role': role, 'sequence': sequence,
            'request_body_bytes': row.get('request_bytes'), 'request_wire_bytes': row.get('request_wire_bytes'),
            'response_body_bytes': row.get('response_bytes'), 'response_status': row.get('response_status'),
            'request_body_hash_verified': hashes['request'], 'response_body_hash_verified': hashes['response'],
            'request_eos_framing_observed': (row.get('request_framing') or {}).get('end_of_framing'),
            'response_eos_written': row.get('response_eos_written'),
            'response_written_monotonic_ns': row.get('response_written_ns'),
            'actual_response_send_calls': len(sends) if isinstance(sends, list) else None,
            'actual_response_send_bytes': sum(value['bytes'] for value in sends) if isinstance(sends, list) else None})
    return requests


def backend_sequences(artifacts, raw_requests, rows):
    sequences = {row['sequence'] for row in raw_requests}
    sequences.update(row.get('sequence') for row in rows or [] if isinstance(row.get('sequence'), int))
    sequences.update(int(match[1]) for name in artifacts.files
                     if (match := re.fullmatch(r'backend/(\d+)\.(?:request-body\.raw|parsed-headers\.json)', name)))
    return sequences


def backend_summary(artifacts, shape, line_capture_supported=None):
    rows = artifacts.rows('backend/receipts.jsonl')
    raw_requests = backend_raw_requests(artifacts, shape, rows)
    requests = backend_completed_requests(artifacts, shape, rows)
    capture_directory = (artifacts.root / 'backend').is_dir()
    sequences = backend_sequences(artifacts, raw_requests, rows)
    completed_count = 0 if capture_directory else None
    if rows is not None:
        completed_count = len(rows)
    return {'request_count': len(sequences) if capture_directory else None,
            'retained_request_sequences': sorted(sequences),
            'request_count_is_lower_bound': line_capture_supported is not True,
            'early_request_line_capture_supported': line_capture_supported,
            'raw_request_line_count': len(raw_requests),
            'backend_capture_directory_present': capture_directory,
            'raw_request_role_counts': counter(row['role'] for row in raw_requests),
            'raw_request_lines': raw_requests,
            'completed_receipt_count': completed_count,
            'completed_receipt_file_present': rows is not None,
            'completed_receipt_role_counts': counter(row['role'] for row in requests), 'requests': requests,
            'unknown': ['completed_backend_receipts'] if rows is None else []}


def native_finish_spans(actual, returned):
    spans = []
    for start in actual:
        if start.get('edge') != 'enter' or start.get('function') not in (
                'runtime_finish_request_body', 'runtime_finish_response_body', 'companion_finish_response_body'):
            continue
        ends = [row for row in returned if row.get('call') == start.get('call')]
        if len(ends) == 1:
            end = ends[0]
            spans.append({'function': start['function'], 'call': start['call'],
                'result': end.get('result'), 'native_body_returns_inside_span': counter(
                    row.get('function') for row in returned if row.get('function') in (
                        'native_process_request_body', 'native_process_response_body') and
                    start['sequence'] < row['sequence'] < end['sequence'])})
    return spans


def completed_transitions(returned, actual):
    return sum(
                row.get('contract_state', {}).get('status') == 3 and before.get('contract_state', {}).get('status') != 3
                for row in returned if isinstance(row.get('contract_state'), dict)
                and row.get('function') in ('common_complete_phase', 'common_finish')
                for before in actual if before.get('edge') == 'enter' and before.get('call') == row.get('call')
                and isinstance(before.get('contract_state'), dict))


def contract_state_samples(returned):
    return [{'function': row['function'], 'call': row.get('call'),
            'sequence': row.get('sequence'), 'monotonic_ns': row.get('monotonic_ns'),
            'result': row.get('result'), 'state': {key: value for key, value in (row.get('contract_state') or {}).items()
                if key in ('status', 'response_committed', 'active_phase', 'last_completed_phase', 'completed_phase_mask',
                           'cleanup_started', 'cleanup_complete', 'completed_at_ms', 'cleanup_at_ms') and type(value) is int}}
            for row in returned if row.get('function') in ('common_set_response_committed', 'common_finish', 'common_cleanup')]


def return_result_counts(returned):
    return {name: counter(row.get('result') for row in returned if row.get('function') == name)
                                 for name in sorted({row.get('function') for row in returned})}


def native_scope_summary(rows, host, pid, scope):
    scoped = [row for row in rows if (row.get('pid'), row.get('allocation_scope_call')) == (pid, scope)]
    calls = {row.get('call') for row in scoped if row.get('edge') == 'enter'}
    actual = [row for row in rows if row.get('pid') == pid and
              (row.get('allocation_scope_call') == scope or row.get('call') in calls)]
    returned = [row for row in actual if row.get('edge') == 'return']
    typed = [row for row in host if (row.get('pid'), row.get('allocation_scope_call')) == (pid, scope)]
    spans = native_finish_spans(actual, returned)
    return {'pid': pid, 'allocation_scope_call': scope,
        'observed_return_counts': counter(row.get('function') for row in returned),
        'return_result_counts': return_result_counts(returned),
        'explicit_runtime_eos_handoff_counts': counter(row.get('runtime_eos_handoff') for row in returned
                                                     if row.get('runtime_eos_handoff') is not None),
        'explicit_host_eos_counts': counter(row.get('host_eos') for row in actual if row.get('host_eos') is not None),
        'typed_host_operation_counts': counter(row.get('operation') for row in typed),
        'typed_body_callbacks': [{'operation': row.get('operation'), 'response_direction': row.get('response_direction'),
            'eos_argument': row.get('body_end_of_stream_argument'), 'body_bytes': row.get('body_size'),
            'declared_bytes': row.get('declared_size'), 'result': row.get('actual_result'),
            'claim_succeeded': row.get('companion_claim_succeeded')} for row in typed],
        'native_finish_spans': spans,
        'contract_state_samples': contract_state_samples(returned),
        'completed_transition_count': completed_transitions(returned, actual),
        'native_mime_selection': None, 'native_charset_selection': None}


def native_summary(rows, host):
    if rows is None:
        return {'row_count': None, 'scopes': [], 'unknown': ['native_observer']}
    host = host or []
    keys = {(row.get('pid'), row.get('allocation_scope_call')) for row in rows
            if row.get('allocation_join_verified') is True and row.get('allocation_scope_call') is not None}
    scopes = [native_scope_summary(rows, host, pid, scope) for pid, scope in sorted(keys)]
    states = [{name: row.get(name) for name in ('pid', 'edge', 'invalid', 'pending_calls', 'live_mappings')}
              for row in rows if row.get('function') == 'observer']
    return {'row_count': len(rows), 'verified_allocation_scope_count': len(scopes), 'scopes': scopes,
            'observer_states': states, 'host_row_count': len(host)}


def event_summary(rows):
    if rows is None:
        return {'row_count': None, 'unknown': ['physical_event_file']}
    # Closed structural fields only. Arbitrary messages/headers/opaque IDs stay raw.
    fields = ('phase', 'action', 'event_type', 'event', 'type', 'kind', 'outcome', 'close_reason', 'status',
              'response_code', 'request_body_bytes', 'request_body_chunks', 'response_body_bytes',
              'response_body_chunks', 'request_header_count', 'response_header_count', 'bytes_received',
              'bytes_sent', 'downstream_wire_bytes_received', 'downstream_wire_bytes_sent')
    allowed = {'allow', 'block', 'deny', 'error', 'abort', 'log_only', 'continue', 'request', 'response',
               'request_headers', 'request_body', 'response_headers', 'response_body', 'logging',
               'response_allow', 'request_allow', 'request_deny', 'response_deny', 'close', 'finish', 'cleanup',
               'peer_eof', 'protocol_error', 'completed', 'canceled', 'context_canceled', 'engine_open_error',
               'shutdown', 'timeout', 'send_error', 'transaction_closed', 'transaction_complete'}
    def closed(value):
        return value if value is None or isinstance(value, (int, bool)) or isinstance(value, str) and value in allowed else 'unclassified_value'
    errors = [row for row in rows if row.get('status') == 'error' and row.get('action') == 'error']
    first = errors[0] if errors else None
    metadata = ('http_status', 'original_http_status', 'visible_http_status', 'response_committed',
                'response_started', 'body_started', 'headers_sent', 'eos_seen', 'body_bytes_seen',
                'body_bytes_inspected', 'sequence')
    return {'row_count': len(rows), 'field_counts': {name: counter(closed(row[name]) for row in rows if name in row)
             for name in fields if any(name in row for row in rows)},
            'first_physical_technical_error': None if first is None else {
                **{name: closed(first.get(name)) for name in ('event', 'phase', 'status', 'action', 'reason')},
                **{name: first[name] for name in metadata if isinstance(first.get(name), (int, bool))}}}


def text_log_summary(artifacts, relative):
    raw = artifacts.raw(relative)
    if raw is None:
        return {'bytes': None, 'line_count': None, 'unknown': ['physical_log']}
    text = raw.decode('utf-8', errors='replace')
    return {'bytes': len(raw), 'line_count': len(raw.splitlines()),
        'logged_numeric_rule_id_counts': counter(re.findall(r'\[id "(\d+)"\]', text)),
        'literal_starting_phase_marker_count': text.count('Starting phase'),
        'literal_executing_operator_marker_count': text.count('Executing operator'),
        'sdk_request_append_sizes_and_limits': [
            {'append_bytes': int(size), 'configured_limit': int(limit)}
            for size, limit in re.findall(r'Appending request body: (\d+) bytes\. Limit set to: (\d+)\.0+\b', text)],
        'sdk_response_cumulative_sizes_and_limits': [
            {'cumulative_bytes': int(size), 'configured_limit': int(limit)}
            for size, limit in re.findall(r'Appending response body: (\d+) bytes\. Limit set to: (\d+)\.0+\b', text)],
        'sdk_limit_action_marker_counts': {action: text.count(marker) for action, marker in (
            ('request_reject', 'Request body limit is marked to reject the request'),
            ('request_process_partial', 'Request body limit is marked to process partial'),
            ('response_reject', 'Response body limit is marked to reject the request'),
            ('response_process_partial', 'Response body limit is marked to process partial'))},
        'sdk_response_utf8_content_type_target_count': text.count(
            'Target value: "text/plain; charset=utf-8" (Variable: RESPONSE_HEADERS:content-type)'),
        'sdk_octet_stream_append_excluded_count': text.count(
            'Not appending response body. Response Content-Type is application/octet-stream. It is not marked to be inspected.'),
        'scope': 'physical_log_aggregate_not_per_transaction_join'}


def versions_summary(artifacts):
    result = {}
    for label in ('host-version', 'go-version', 'sdk-who'):
        receipt = artifacts.json(label + COMMAND_SUFFIX)
        raw = artifacts.raw(label + '.stdout')
        text = raw.decode('ascii', errors='replace').strip() if raw is not None else None
        # Identities are closed printable version strings, never arbitrary logs.
        printable = text if text and len(text) <= 512 and re.fullmatch(r'[A-Za-z0-9 .:/_+()\-]+', text) else None
        result[label] = {'command_exit_code': receipt.get('exit_code') if isinstance(receipt, dict) else None,
                         'identity': printable}
        if isinstance(receipt, dict):
            for channel in ('stdout', 'stderr'):
                artifacts.compare(label + '.' + channel, receipt.get(channel + '_sha256'))
    return result


def parser_modules(helpers):
    hashes = maintained_transport.historical_helper_hashes(helpers)
    capture = maintained_capture if helpers is not None else None
    return maintained_transport, capture, hashes


def transport_summary(artifacts, shape, transport, capture):
    raw = artifacts.raw('envoy.stderr')
    result = {}
    for label in ('target', 'neighbor'):
        observation = {'verified': False}
        unary = None
        if raw is not None and capture is not None and isinstance(shape.get(label), str):
            text = raw.decode('utf-8', errors='replace')
            path = '/' + shape[label]
            observation = capture.observe(text, path)
            unary = transport.authorization_observation(text, path, capture.authorization_host_logs)
        classified = transport.terminal(observation, unary)
        result[label] = {name: classified[name] for name in ('process', 'authorization')}
        result[label]['received_http2_payload_callback_count'] = (
            len(observation['actual_received_payload_callbacks'])
            if 'actual_received_payload_callbacks' in observation else None)
    return result


def add_controller_summary(controller, result):
    result['controller'] = {name: controller.get(name) for name in (
        'exitcode', 'controller_exitcode', 'timeout', 'supervisor_reaped', 'resource_violation', 'namespace_pin_verified')}
    result['controller']['error_count'] = len(controller.get('errors', []))
    result['controller']['surviving_namespace_pid_count'] = (
        len(controller['surviving_namespace_pids']) if 'surviving_namespace_pids' in controller else None)
    result['controller']['outside_mount_leak_count'] = (
        len(controller['outside_mount_leaks']) if 'outside_mount_leaks' in controller else None)
    result['controller']['executed_input_hashes_unchanged'] = (
        bool(controller.get('executed_input_hashes_before')) and
        controller['executed_input_hashes_before'] == controller.get('executed_input_hashes_after'))


def add_driver_summary(artifacts, result):
    driver = artifacts.json('result.json')
    result['observation_state'] = 'driver_result_observed' if isinstance(driver, dict) else 'driver_result_missing'
    result['driver'] = driver_summary(driver)
    if isinstance(driver, dict):
        for relative, expected in driver.get('actual_runtime_copies_hashes', {}).items():
            artifacts.compare(relative, expected)


def driver_summary(driver):
    if not isinstance(driver, dict):
        return None
    return {
        'failure_type': (driver.get('failure') or {}).get('type'),
        'remaining_owned_process_count': len(driver['remaining_owned_processes']) if 'remaining_owned_processes' in driver else None,
        'processes': {name: {key: value.get(key) for key in ('waited_exit_code', 'forced_kill', 'signal_sent')}
                      for name, value in driver.get('processes', {}).items()}}


def verify_fixture_configuration(artifacts, fixture, build):
    for path, expected in build.get('fixture_configuration', {}).items():
        if path.startswith('/task/'):
            artifacts.compare(path.removeprefix('/task/'), expected)
        elif path.startswith('/mnt/fixtures/'):
            actual = fixture / path.removeprefix('/mnt/fixtures/')
            if not actual.is_file() or digest(actual) != expected:
                artifacts.issues.append({'path': 'fixture/' + actual.name, 'kind': 'receipt_hash_mismatch'})


def verify_build_artifacts(artifacts, fixture, shape):
    build = artifacts.json('build-manifest.json')
    if isinstance(build, dict):
        for name, field in (('envoy', 'host_sha256'),
                            ('msconnector_envoy_ext_proc' if shape.get('leg') == 'envoy-ext-proc' else 'msconnector_composite', 'engine_sha256')):
            artifacts.compare('cache/' + name, build.get(field))
        verify_fixture_configuration(artifacts, fixture, build)
    return build


def loaded_image(name, process, build):
    record_image = {'pid': process.get('pid'), 'executable_sha256': process.get('executable_sha256'),
        'identity': process.get('identity'), 'fd_count': process.get('fd_count'),
        'native_libraries': [{'sha256': value.get('sha256')} for value in process.get('native_libraries', [])]}
    if isinstance(build, dict) and name in ('engine', 'envoy'):
        record_image['matches_build_manifest'] = process.get('executable_sha256') == build.get(
            'engine_sha256' if name == 'engine' else 'host_sha256')
        if name == 'engine':
            sdk_hash = build.get('actual_external_build_provenance', {}).get('sdk_library', {}).get('sha256')
            record_image['sdk_matches_native_build'] = (
                len(record_image['native_libraries']) == 1 and sdk_hash is not None and
                record_image['native_libraries'][0]['sha256'] == sdk_hash)
    return record_image


def loaded_images(artifacts, build):
    snapshots = {}
    for label in ('before-request', 'after-target', 'after-neighbor'):
        snapshot = artifacts.json(label + '.json')
        if not isinstance(snapshot, dict):
            snapshots[label] = None
            continue
        snapshots[label] = {}
        for name, process in snapshot.get('processes', {}).items():
            snapshots[label][name] = loaded_image(name, process, build)
    return snapshots


def source_row_valid(row, source_contract, source_ledger):
    relative = row.get('path')
    baseline = source_contract.get('source_inputs', {}).get(relative)
    actual = row.get('actual_source_sha256')
    overlay = source_contract.get('approved_test_overlays', {}).get(relative) or {}
    return (baseline is not None and row.get('baseline_a9_sha256') == baseline
        and source_ledger.get(relative) == actual and
        (baseline == actual or overlay.get('baseline_a9_sha256') == baseline
         and overlay.get('instrumented_sha256') == actual))


def add_source_equality(artifacts, fixture, bindings, result):
    source_proof = artifacts.json('scoped-product-source-equality.json')
    source_contract = json.loads((fixture / 'scoped-product-source-a9.json').read_text())
    source_ledger = json.loads(Path(bindings['/mnt/src']['ledger']).read_text())['files']
    native_proof = json.loads((fixture / 'actual-build-provenance-v1.json').read_text())
    complete_source_bound = source_ledger == source_inventory.expected_inventory(native_proof)
    independently_valid = []
    for row in source_proof if isinstance(source_proof, list) else []:
        independently_valid.append(source_row_valid(row, source_contract, source_ledger))
    result['source_equality'] = {'row_count': len(source_proof) if isinstance(source_proof, list) else None,
        'all_rows_verified': all(row.get('verified') is True for row in source_proof) if isinstance(source_proof, list) and source_proof else None,
        'independent_sealed_baseline_overlay_contract_verified': all(independently_valid) if independently_valid else None,
        'source_contract_parent_sha': source_contract.get('parent_sha')}
    result['source_equality']['complete_archived_build_inventory_verified'] = complete_source_bound
    return complete_source_bound


def add_clients(artifacts, result):
    result['clients'] = {label: client_summary(artifacts, label) for label in ('target', 'neighbor')}
    target, neighbor = (result['clients'][label] for label in ('target', 'neighbor'))
    intervals = [value.get(field) for value in (target, neighbor)
                 for field in ('started_monotonic_ns', 'completed_monotonic_ns')]
    result['client_time_overlap_observed'] = (
        max(intervals[0], intervals[2]) < min(intervals[1], intervals[3])
        if all(isinstance(value, int) for value in intervals)
        and intervals[0] <= intervals[1] and intervals[2] <= intervals[3] else None)


def add_command_exits(artifacts, result):
    result['command_exit_codes'] = {}
    for relative in artifacts.files:
        if '/' not in relative and relative.endswith(COMMAND_SUFFIX):
            command = artifacts.json(relative)
            if isinstance(command, dict):
                label = relative.removesuffix(COMMAND_SUFFIX)
                result['command_exit_codes'][label] = command.get('exit_code')
                for channel in ('stdout', 'stderr'):
                    artifacts.compare(label + '.' + channel, command.get(channel + '_sha256'))


def fixture_identity_mismatch(shape, case, parent_sha):
    return (shape.get('case_id') != 'I12-ENVOY-HOST::' + case['label'] or shape.get('leg') != case['route']
            or parent_sha is None or shape.get('parent_sha') != parent_sha
            or shape.get('original_case_ids', []) != case.get('original_case_ids', [])
            or shape.get('oracle_review_sha256') != case.get('oracle_review_sha256'))


def admission_context(case, controller, result, parent_sha):
    spec_path = Path(case['spec'])
    if STORAGE is None or not spec_path.is_absolute() or spec_path.resolve(strict=True) != spec_path or STORAGE not in spec_path.parents:
        raise ValueError('nonphysical admission specification')
    spec = json.loads(spec_path.read_text())
    bindings = {binding.get('target'): binding for binding in spec.get('bindings', [])}
    result['admission_spec_hash_verified'] = digest(spec_path) == controller.get('spec_sha256')
    if not result['admission_spec_hash_verified'] or set(bindings) != {'/mnt/src', '/mnt/artifacts', '/mnt/fixtures'}:
        result.update({'declared_route': result['route'], 'route': None,
                         'observation_state': 'admission_scope_mismatch', 'unknown': ['scoped_host_execution']})
        return None
    result['sealed_inputs'] = {name: binding_summary(binding) for name, binding in bindings.items()}
    if any(not item.get('ledger_hash_verified') or not item.get('all_file_hashes_verified')
           for item in result['sealed_inputs'].values()):
        result.update({'declared_route': result['route'], 'route': None,
                         'observation_state': 'sealed_input_mismatch', 'unknown': ['scoped_host_execution']})
        return None
    fixture = Path(bindings['/mnt/fixtures']['source'])
    shape = json.loads((fixture / 'shape.json').read_text())
    result['fixture_shape_sha256'] = digest(fixture / 'shape.json')
    if fixture_identity_mismatch(shape, case, parent_sha):
        result.update({'declared_route': result['route'], 'route': None,
                         'observation_state': 'fixture_identity_mismatch', 'unknown': ['scoped_host_execution']})
        return None
    result['original_oracle_case_ids'] = shape.get('original_case_ids', [])
    result['oracle_review_sha256'] = shape.get('oracle_review_sha256')
    return fixture, bindings, shape


def review_run(record, transport, capture, parent_sha=None):
    case = record['case']
    result = {'scenario': case['label'], 'route': case['route'], 'runner_exit_code': record.get('exit_code'),
        'expected_http_status': case.get('expected_http_status'),
        'host_lifecycle_qualified': False, 'original_oracle_case_ids': [],
        'qualification': 'physical_observation_only_no_original_id_oracle_verdict'}
    packet = record.get('controller_result')
    if not packet or not packet.get('attempt'):
        return result | {'observation_state': 'controller_admission_failed_or_unknown', 'unknown': ['attempt', 'host_execution']}
    attempt = Path(packet['attempt'])
    if STORAGE is None or not attempt.is_absolute() or attempt.resolve() != attempt or STORAGE not in attempt.parents:
        raise ValueError('attempt is not a physical external project path')
    result['attempt'] = str(attempt)
    controller_path = attempt / 'controller-result.json'
    if not controller_path.is_file():
        return result | {'observation_state': 'controller_not_completed', 'unknown': ['cleanup_handoff', 'host_execution']}
    controller = json.loads(controller_path.read_text())
    add_controller_summary(controller, result)
    result['controller_result_sha256'] = digest(controller_path)
    data = attempt / 'data'
    handoff = attempt / 'retained-original-ownership.json'
    if (not handoff.is_file() or not data.is_dir() or data.resolve() != data
            or data.stat().st_uid != os.getuid()):
        return result | {'observation_state': 'no_safe_completed_data_handoff', 'unknown': ['physical_host_artifacts']}
    result['handoff_receipt_sha256'] = digest(handoff)
    artifacts = Artifacts(data)
    context = admission_context(case, controller, result, parent_sha)
    if context is None:
        return result
    fixture, bindings, shape = context
    add_driver_summary(artifacts, result)
    build = verify_build_artifacts(artifacts, fixture, shape)
    result['loaded_images'] = loaded_images(artifacts, build)
    complete_source_bound = add_source_equality(artifacts, fixture, bindings, result)
    if not complete_source_bound:
        return result | {'declared_route': result['route'], 'route': None,
                         'observation_state': 'complete_build_source_mismatch', 'unknown': ['scoped_host_execution']}
    result['build'] = None if not isinstance(build, dict) else {name: build.get(name) for name in (
        'source_git_baseline', 'product_contract', 'source_scope_count', 'host_sha256', 'engine_sha256')}
    add_clients(artifacts, result)
    backend_source = (fixture / 'backend.py').read_bytes()
    result['backend'] = backend_summary(artifacts, shape, b'.request-line.raw' in backend_source)
    result['native'] = native_summary(artifacts.rows('runtime/native-lifecycle.jsonl'), artifacts.rows('runtime/host-lifecycle.jsonl'))
    result['events'] = {name: event_summary(artifacts.rows('runtime/' + name + '.jsonl'))
                        for name in ('common-events', 'adapter-events', 'envoy-access')}
    result['native_logs'] = {name: text_log_summary(artifacts, 'runtime/' + name + '.log')
                              for name in ('native-debug', 'native-audit')}
    result['versions'] = versions_summary(artifacts)
    add_command_exits(artifacts, result)
    result['grpc_transport'] = transport_summary(artifacts, shape, transport, capture)
    result['physical_files'] = artifacts.files
    result['artifact_integrity_issues'] = artifacts.issues
    result['unknown'] = ['original_exact_id_oracle_review', 'native_mime_selection', 'native_charset_selection',
                         'strict_p4_capability_qualification']
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runs', type=Path, required=True)
    parser.add_argument('--helpers', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    runs_bytes = evidence_io.read_bytes(args.runs)
    runs = json.loads(runs_bytes)
    for record in runs['runs']:
        paths.leaf_name(record['case']['label'])
    paths.output_path(args.output)
    snapshot_path = args.output.with_suffix('.runs-input.json')
    if args.output.exists() or snapshot_path.exists():
        parser.error('fresh output and input-snapshot paths required')
    paths.create_bytes(snapshot_path, runs_bytes)
    transport, capture, helpers = parser_modules(args.helpers)
    results = [review_run(record, transport, capture, runs['parent_sha']) for record in runs['runs']]
    log_checks = []
    for record in runs['runs']:
        base = args.runs.parent / (args.runs.stem + '-' + record['case']['label'])
        for channel in ('stdout', 'stderr'):
            path = base.with_suffix('.' + channel)
            log_checks.append({'scenario': record['case']['label'], 'channel': channel,
                'hash_verified': path.is_file() and digest(path) == record.get(channel + '_sha256')})
    output = {'schema': 'i12.envoy.physical-review.v1', 'parent_sha': runs.get('parent_sha'),
        'runs_sha256': hashlib.sha256(runs_bytes).hexdigest(), 'runs_snapshot': str(snapshot_path),
        'helper_sha256': helpers,
        'current_parser_sha256': maintained_transport.current_parser_hashes(),
        'transport_wrapper_sha256': digest(HERE / 'transport.py'),
        'host_lifecycle_qualified': False, 'oracle_progress_assigned': False,
        'route_scenario_counts': counter(result['route'] for result in results),
        'runner_log_checks': log_checks, 'scenarios': results}
    with paths.new_text(args.output) as target:
        json.dump(output, target, indent=2)
        target.write('\n')
    print(json.dumps({'output': str(args.output), 'scenario_count': len(results),
                      'host_lifecycle_qualified': False}))


if __name__ == '__main__':
    main()
