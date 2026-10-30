"""Adapt complete native producer receipts to the existing candidate packet API.

This adapter never reviews an oracle or assigns a qualifier verdict. Missing
sources, malformed physical records and absent measurements remain explicit.
"""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import argparse
from collections import Counter
from functools import partial
import hashlib
import importlib.util
import io
import json
import re
import sys
from pathlib import Path

ROOT = connector_root()
FAULTS_NAME = 'faults.jsonl'
WAIT_SUFFIX = '.wait.json'


def file_http():
    """Load the producer's bounded physical HTTP parsers without starting a host."""
    name = '_traefik_i12_packet_file'
    directory = source_path('connectors/traefik/harness/i12_file', root=ROOT)
    if name not in sys.modules:
        package = load_source(directory / '__init__.py')
    return importlib.import_module(name + '.http_stream')


def file_request(raw):
    """Replay the producer parser against retained bytes, without a live socket."""
    class RetainedConnection:
        stream = io.BytesIO(raw)

        def makefile(self, *args, **kwargs):
            return self.stream

        def gettimeout(self):
            return None

        def setblocking(self, value):
            # Retained bytes have no live socket blocking state to change.
            pass

        def settimeout(self, value):
            # Replay reads are deterministic and do not perform socket I/O.
            pass

        def recv(self, *args):
            return self.stream.read(1)

    return file_http().read_request(RetainedConnection())


def contracts():
    path = source_path('connectors/traefik/harness/i12_ledger.py', root=ROOT)
    module = load_source(path)
    return module.contracts()


def read(path):
    return json.loads(path.read_text()) if path.is_file() else None


def reference(path, role):
    if not path.is_file():
        return None
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    return {'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest(),
            'bytes': len(raw), 'role': role}


def records(path):
    if not path.is_file():
        return None, [{'path': str(path), 'reason': 'missing physical source'}]
    try:
        raw = path.read_bytes()
    except OSError as error:
        return None, [{'path': str(path), 'reader_error': type(error).__name__, 'errno': error.errno,
                       'reason': 'Physical source could not be read; absence is not zero.'}]
    rows, errors = [], []
    for index, line in enumerate(raw.splitlines()):
        try:
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError('physical JSONL row is not an object')
            rows.append(value)
        except ValueError as error:
            errors.append({'path': str(path), 'line': index, 'reason': str(error),
                           'raw_sha256': hashlib.sha256(line).hexdigest()})
    return rows, errors


def generated_join_window(case, measurement, before, client, raw_request):
    if (case.get('key') != '004-b044cc412aca' or
            not case.get('id', '').endswith('::transaction_id_generated_or_fallback') or
            not case.get('fixture', {}).get('request', {}).get('omit_transaction_id')):
        return None
    admitted = (measurement or {}).get('generated_id_child_environment', {})
    if admitted != {'name': 'I12_NATIVE_GENERATED_CASE', 'present': True,
                    'value': '004-b044cc412aca', 'dedicated_host': True}:
        return None
    if not raw_request or b'x-request-id:' in raw_request.split(b'\r\n\r\n', 1)[0].lower():
        return None
    pid = (before or {}).get('processes', {}).get('engine', {}).get('pid')
    start, end = (client or {}).get('started_ns'), (client or {}).get('completed_ns')
    if not all(isinstance(v, int) and v > 0 for v in (pid, start, end)) or end < start:
        return None
    return pid, start, end


def body_selection_debug(rules_path, debug_path, proof, direction, response):
    rules = rules_path.read_text()
    ids = set(re.findall(r'\bid:(\d+)', rules))
    debug = [line for line in debug_path.read_text().splitlines() if line.startswith('[' + proof['transaction_id'] + ']')]
    body_variable = direction.upper() + '_BODY'
    executed = [line for line in debug if 'Executing operator' in line and 'against ' + body_variable in line
                and any('(Rule: ' + identifier + ')' in line for identifier in ids)]
    exclusion = [line for line in debug if response and 'not marked to be inspected' in line]
    return executed, exclusion


def validate_file_identity(row, supplement, key, tx, mode):
    if not row or row.get('schema') != 'traefik-file-http-' + mode + '-v1':
        raise ValueError('Missing exact physical file reader receipt')
    if (row.get('key'), row.get('transaction_id'), row.get('native_file_api'), row.get('native_eos')) != (key, tx, False, None):
        raise ValueError('File reader identity or API/EOS boundary differs')
    source, spec = row['file_source'], supplement['file_spec']
    pid = row['pid']
    if type(pid) is not int or pid <= 0 or row['process']['pid'] != pid or source['pid'] != pid:
        raise ValueError('File source and reader process identity differ')
    if (source.get('schema') != 'traefik-physical-file-source-v1' or
            (source.get('native_file_api'), source.get('native_eos'), source.get('complete')) != (False, None, True)):
        raise ValueError('Incomplete physical source; never a native File API receipt')
    if (source['relative_path'], source['expected_size'], source['bytes'], source['expected_sha256'], source['sha256']) != (
            spec['relative_path'], spec['size'], spec['size'], spec['sha256'], spec['sha256']):
        raise ValueError('Physical file source differs from sealed fixture')
    if type(spec['read_size']) is not int or source.get('requested_read_size') != spec['read_size']:
        raise ValueError('Physical file requested read size differs from sealed fixture')
    return source, spec, pid


def validate_file_content(source, spec, root, mode, result):
    content_path = root / 'file-source' / spec['relative_path']
    content = content_path.read_bytes()
    if len(content) != spec['size'] or hashlib.sha256(content).hexdigest() != spec['sha256']:
        raise ValueError('Retained physical source bytes differ')
    result['file_source'] = reference(content_path, mode + '_process')
    if (source['pre_stat'] != source['post_stat'] or source['pre_stat'].get('regular_file') is not True or
            source['pre_stat'].get('size') != spec['size'] or source['close']['result'] != 0 or
            source['root_close']['result'] != 0 or source['eof_read_result'] != 0):
        raise ValueError('Physical source mutation, EOF or close failure')
    return content


def validate_file_clock(row, source):
    start, end = row['started_ns'], row['completed_ns']
    if not (type(start) is int and type(end) is int and 0 < start <= end and
            start <= source['started_ns'] <= source['completed_ns'] <= end and
            source['close']['completed_ns'] <= source['root_close']['completed_ns'] <=
            source['completed_ns'] <= row['http_terminator_send_started_ns'] <=
            row['http_terminator_sendall_returned_ns'] <= end):
        raise ValueError('Physical file/HTTP clock window differs')
    return start, end


def validate_file_chunks(row, source, spec, content, start, end):
    offset = 0
    if len(source['reads']) != len(row['http_chunks']):
        raise ValueError('Physical file reads and HTTP chunks differ')
    for read_row, chunk in zip(source['reads'], row['http_chunks']):
        size = read_row['result']
        requested = min(spec['read_size'], spec['size'] - offset)
        wire = f'{size:x}\r\n'.encode() + content[offset:offset + size] + b'\r\n' if type(size) is int else b''
        if (type(size) is not int or size <= 0 or read_row['offset'] != offset or
                read_row.get('requested') != requested or size != requested or
                chunk['source_offset'] != offset or chunk['entity_bytes'] != size or
                read_row['sha256'] != chunk['entity_sha256'] or
                hashlib.sha256(content[offset:offset + size]).hexdigest() != read_row['sha256'] or
                chunk.get('wire_bytes') != len(wire) or
                chunk.get('wire_sha256') != hashlib.sha256(wire).hexdigest() or
                chunk.get('remote_delivery_proven') is not False or
                not start <= read_row['started_ns'] <= read_row['completed_ns'] <=
                chunk['started_ns'] <= chunk['sendall_returned_ns'] <= read_row['consumer_returned_ns'] <= end):
            raise ValueError('Physical file read/chunk join differs')
        offset += size
    if offset != spec['size']:
        raise ValueError('Physical file read coverage differs')
    if (row.get('http_terminator_wire_bytes') != 5 or
            row.get('http_terminator_wire_sha256') != hashlib.sha256(b'0\r\n\r\n').hexdigest()):
        raise ValueError('Physical HTTP terminator differs')


def validate_file_client(row, measurement, evidence, result):
    key, tx = row['key'], row['transaction_id']
    start, end = row['started_ns'], row['completed_ns']
    waited = (measurement or {}).get('client', {})
    if (row['process']['ppid'] != waited.get('wrapper_pid') or
            not waited['started_ns'] <= start <= end <= waited['completed_ns']):
        raise ValueError('Physical client differs from waited child window')
    for suffix, count, sha in (('request-head.raw', 'request_head_wire_bytes', 'request_head_wire_sha256'),
            ('response.raw', 'client_response_wire_bytes', 'client_response_wire_sha256'),
            ('response-entity.raw', 'client_response_entity_bytes', 'client_response_entity_sha256')):
        raw = (evidence / (key + '.' + suffix)).read_bytes()
        if len(raw) != row[count] or hashlib.sha256(raw).hexdigest() != row[sha]:
            raise ValueError('Physical client raw bytes differ')
        result['raw_sources'].append(reference(evidence / (key + '.' + suffix), 'client_process'))
    head = result['request_path'].read_bytes().lower()
    if (b'\r\nx-request-id: ' + tx.lower().encode() + b'\r\n' not in head or
            b'\r\nx-i12-acceptance-key: ' + key.lower().encode() + b'\r\n' not in head):
        raise ValueError('Physical client HTTP correlation differs')
    response_head = result['response_path'].read_bytes().split(b'\r\n\r\n', 1)[0]
    if (response_head.decode('latin1') != row['response_headers_latin1'] or
            int(response_head.split(b'\r\n', 1)[0].split()[1]) != row['actual_status']):
        raise ValueError('Physical client response headers/status differ')
    entity, framing = file_http().response_entity(result['response_path'].read_bytes())
    if (entity != result['entity_path'].read_bytes() or row.get('response_http_complete') is not True or
            framing != row.get('response_http_framing')):
        raise ValueError('Physical client decoded response entity/framing differs')
    result.update(client=row | {'status': row['actual_status'],
        'entity_bytes': row['client_response_entity_bytes'], 'entity_sha256': row['client_response_entity_sha256']},
        waited=waited | {'returncode': waited.get('exit_code')})


def validate_file_backend(row, measurement, before, evidence, result):
    key, tx, pid = row['key'], row['transaction_id'], row['pid']
    listening_path = evidence / (key + '.backend-listening.json')
    accept_path = evidence / (key + '.backend-accept.json')
    listening, accept = read(listening_path), read(accept_path)
    physical = (measurement or {}).get('physical_file', {})
    snapshot = (before or {}).get('processes', {}).get('file-backend', {})
    if (not listening or not accept or listening != physical.get('listening') or
            pid != listening['pid'] or pid != snapshot.get('pid') or
            row['process']['ppid'] != snapshot.get('proxy_pid') or
            row.get('independent_backend_accept_count') != 1 or
            any(accept.get(field) != row.get(field) for field in
                ('key', 'transaction_id', 'pid', 'local', 'peer', 'accepted_ns')) or
            row['local'] != ['127.0.0.1', listening['port']] or
            row['observed_correlation'].get('x-request-id') != tx or
            row['observed_correlation'].get('x-i12-acceptance-key') != key or
            row.get('request_http_framing_valid') is not True):
        raise ValueError('Physical backend accept/PID/request correlation differs')
    for suffix, count, sha in (('backend-request.raw', 'request_wire_bytes', 'request_wire_sha256'),
            ('backend-response-head.raw', 'response_head_wire_bytes', 'response_head_wire_sha256')):
        raw = (evidence / (key + '.' + suffix)).read_bytes()
        if len(raw) != row[count] or hashlib.sha256(raw).hexdigest() != row[sha]:
            raise ValueError('Physical backend raw bytes differ')
        result['raw_sources'].append(reference(evidence / (key + '.' + suffix), 'backend_process'))
    head = (evidence / (key + '.backend-request.raw')).read_bytes().split(b'\r\n\r\n', 1)[0].lower() + b'\r\n'
    if (b'\r\nx-request-id: ' + tx.lower().encode() + b'\r\n' not in head or
            b'\r\nx-i12-acceptance-key: ' + key.lower().encode() + b'\r\n' not in head):
        raise ValueError('Physical backend raw HTTP correlation differs')
    wire, entity, headers = file_request((evidence / (key + '.backend-request.raw')).read_bytes())
    if (len(wire) != row['request_wire_bytes'] or len(entity) != row['request_body_bytes'] or
            hashlib.sha256(entity).hexdigest() != row['request_body_sha256'] or
            headers.get(b'x-request-id') != tx.encode() or
            headers.get(b'x-i12-acceptance-key') != key.encode()):
        raise ValueError('Physical backend decoded request entity/correlation differs')
    result.update(backend=row, backend_accept=reference(accept_path, 'backend_process'),
        backend_listening=reference(listening_path, 'backend_process'))


def retained_body_matches(row, direction, pid, proof):
    allowed_methods = ('append_' + direction + '_body', 'process_' + direction + '_body', 'transaction_cleanup_before_free')
    if (row.get('operation'), row.get('accessor'), row.get('pid')) != (
            'native_retained_body', 'msc_get_' + direction + '_body_length', pid) or row.get('injected') is not False:
        return False
    if (pid, row.get('allocation_scope_call')) not in proof['scopes'] or row.get('native_method') not in allowed_methods:
        return False
    if type(row.get('retained_body_bytes')) is not int or row['retained_body_bytes'] < 0 or type(row.get('monotonic_ns')) is not int:
        return False
    client = proof['client']
    in_window = client['started_ns'] <= row['monotonic_ns'] <= client['completed_ns']
    return (in_window or row['native_method'] == 'transaction_cleanup_before_free') and paired_accessor_call(row, proof['associated'])


def generated_join(case, measurement, before, client, native, raw_request):
    """Resolve only the admitted original blank-ID experiment by physical scope."""
    window = generated_join_window(case, measurement, before, client, raw_request)
    if window is None:
        return None
    pid, start, end = window
    allocations = generated_allocations(native, pid, start, end)
    if len(allocations) != 1:
        return None
    allocation = allocations[0]
    scope, identity = allocation.get('allocation_scope_call'), allocation.get('transaction_id')
    if not scope or not identity or allocation.get('transaction_id_origin') != 'sdk_public_m_id':
        return None
    joined = [r for r in native or [] if r.get('pid') == pid and r.get('allocation_scope_call') == scope
              and r.get('allocation_join_verified')]
    if not joined or any(r.get('invalid') is not False for r in joined):
        return None
    return {'pid': pid, 'allocation_scope_call': scope, 'transaction_id': identity,
            'client_transaction_id': None, 'binding': 'exact admitted case/PID/client window/single actual SDK allocation'}


def physical_content_types(path):
    if not path.is_file():
        return None
    head, separator, _ = path.read_bytes().partition(b'\r\n\r\n')
    if not separator or len(head) > 65536:
        return None
    return [line.partition(b':')[2].strip().decode('latin1') for line in head.split(b'\r\n')[1:]
            if line.partition(b':')[0].lower() == b'content-type']


def paired_accessor_call(row, native_rows):
    function = 'native_cleanup' if row['native_method'] == 'transaction_cleanup_before_free' else 'native_' + row['native_method']
    related = [r for r in native_rows if r.get('pid') == row['pid'] and r.get('function') == function and r.get('invalid') is False]
    entered = {r.get('call') for r in related if r.get('edge') == 'enter' and r.get('monotonic_ns', 0) <= row['monotonic_ns']}
    returned = {r.get('call') for r in related if r.get('edge') == 'return' and row['monotonic_ns'] <= r.get('monotonic_ns', 0)}
    return bool((entered & returned) - {None})


def retained_body_records(root, direction, pid, proof):
    rows, malformed = records(root / FAULTS_NAME)
    if malformed:
        return []
    return [row for row in rows or [] if retained_body_matches(row, direction, pid, proof)]


def complete_pid_observer(rows, pid):
    rows = [r for r in rows if r.get('pid') == pid]
    if not rows or [r.get('sequence') for r in rows] != list(range(1, len(rows) + 1)):
        return False
    admitted = rows[0].get('function') == 'observer' and rows[0].get('edge') in ('admitted', 'fork')
    final = rows[-1].get('function') == 'observer' and rows[-1].get('edge') in ('final', 'snapshot')
    return admitted and final and rows[-1].get('live_mappings') == 0 and all(r.get('invalid') is False for r in rows)


def body_selection_pid(client, before):
    start, end = client.get('started_ns'), client.get('completed_ns')
    pid = before.get('processes', {}).get('engine', {}).get('pid')
    if not all(type(v) is int and v > 0 for v in (start, end, pid)) or end < start:
        return None
    return pid


def response_headers_match(response, rows, client):
    return not response or any(row.get('function') == 'native_process_response_headers' and
            row.get('edge') == 'return' and row.get('argument_response_status') == client.get('status') for row in rows)


def body_selection_interpretation(executed, exclusion):
    interpretation = 'final_retention_and_native_call_trace_observed'
    if executed:
        interpretation = 'sdk_rule_operator_execution_observed'
    elif exclusion:
        interpretation = 'sdk_mime_exclusion_debug_observed'
    return interpretation


def body_selection_candidate(case, root, proof):
    """Return joined physical facts; Root alone interprets MIME/charset policy."""
    client, before = proof['client'] or {}, proof['before'] or {}
    pid = body_selection_pid(client, before)
    if pid is None:
        return None
    response = 'response' in case['id'].rsplit('::', 1)[-1] or 'phase4' in case['id']
    direction = 'response' if response else 'request'
    raw_path = proof['response_path'] if response else proof['request_path']
    headers = physical_content_types(raw_path)
    if headers is None:
        return None
    rows = proof['associated']
    if not response_headers_match(response, rows, client):
        return None  # A locally generated error response is not the upstream header sample.
    retained = retained_body_records(root, direction, pid, proof)
    rules_path, debug_path = root / 'rules.conf', root / 'debug.log'
    if not retained or not rules_path.is_file() or not debug_path.is_file():
        return None
    executed, exclusion = body_selection_debug(rules_path, debug_path, proof, direction, response)
    continuous = complete_pid_observer(proof['all_native'], pid)
    final = [r for r in retained if r['native_method'] == 'transaction_cleanup_before_free']
    if not executed and not exclusion and not (continuous and final):
        return None
    interpretation = body_selection_interpretation(executed, exclusion)
    return body_selection_result({'direction': direction,
            'headers': headers,
            'response': response,
            'raw_path': raw_path,
            'retained': retained,
            'executed': executed,
            'exclusion': exclusion,
            'rules_path': rules_path,
            'rows': rows,
            'pid': pid,
            'continuous': continuous,
            'interpretation': interpretation})


MEASUREMENT_FILE = 'measurement.json'


def physical_file_candidate(case, root, measurement, before):
    """Bind file-origin byte transport without claiming SDK File API or EOS."""
    supplement = case.get('fixture', {}).get('file_supplement')
    if not supplement:
        return None
    key, tx = case['key'], case['transaction_id']
    evidence = root / 'file-evidence'
    mode = 'client' if supplement['physical_reader'] == 'client' else 'backend'
    path = evidence / (key + '.' + mode + '.json')
    result = {'binding_valid': False, 'native_file_api': False, 'native_eos': None,
        'inspection_proven': False, 'backend_exclusion_proven': False,
        'reader': read(path), 'reader_source': reference(path, mode + '_process'),
        'client_path': path, 'request_path': evidence / (key + '.request-head.raw'),
        'response_path': evidence / (key + '.response.raw'),
        'entity_path': evidence / (key + '.response-entity.raw'),
        'wait_path': root / MEASUREMENT_FILE, 'backend_path': path, 'backend': None,
        'raw_sources': []}
    try:
        row = result['reader']
        source, spec, _ = validate_file_identity(row, supplement, key, tx, mode)
        content = validate_file_content(source, spec, root, mode, result)
        start, end = validate_file_clock(row, source)
        validate_file_chunks(row, source, spec, content, start, end)
        if mode == 'client':
            validate_file_client(row, measurement, evidence, result)
        else:
            validate_file_backend(row, measurement, before, evidence, result)
        result['binding_valid'] = True
    except (KeyError, IndexError, TypeError, ValueError, OSError) as error:
        result['binding_error'] = str(error)
    return result


def observe_client(observed, evidence):
    if evidence['client'] is not None:
        observed('client_exit',
            evidence['waited'].get('returncode') if evidence['waited'] else None,
            reference(evidence['wait_path'],
                'client_process'))
        observed('client_signal', evidence['waited'], reference(evidence['wait_path'], 'client_process'))
        observed('client_headers', evidence['client'].get('response_headers_latin1'), evidence['client_ref'], evidence['raw_ref'])
        observed('client_bytes',
            evidence['client'].get('entity_bytes'),
            evidence['client_ref'],
            reference(evidence['entity_path'],
                'client_process'))
        observed('client_sha256', evidence['client'].get('entity_sha256'), evidence['client_ref'])
        observed('transport_framing', {'client': evidence['client'], 'waited': evidence['waited']}, evidence['client_ref'], evidence['raw_ref'])
        observed('transport_reset_scope',
            {'actual_client': evidence['client'],
                'host_errors': [row for row in evidence['host'] if row.get('fields',
                        {}).get('error')]},
            evidence['client_ref'],
            evidence['host_ref'])


def observe_backend(observed, evidence):
    if evidence['backend_rows'] is not None and (evidence['physical_file'] is None or (evidence['physical_file']['binding_valid'] and evidence['case']['fixture']['file_supplement']['physical_reader'] == 'client')):
        observed('backend_request_count', len(evidence['arrivals']), evidence['backend_ref'])
        observed('backend_payload_identity',
            {'arrivals': evidence['arrivals'],
                'client': evidence['client'],
                'records': [row for row in evidence['backend_rows'] if row.get('key') == evidence['key']]},
            evidence['backend_ref'],
            evidence['client_ref'])
        observed('client_backend_correlation',
            {'key': evidence['key'],
                'transaction_id': evidence['tx'],
                'arrivals': evidence['arrivals'],
                'client': evidence['client']},
            evidence['backend_ref'],
            evidence['client_ref'])
    if evidence['physical_file'] and evidence['physical_file']['binding_valid'] and evidence['physical_file'].get('backend'):
        physical_backend = evidence['physical_file']['backend']
        file_backend_ref = reference(evidence['physical_file']['backend_path'], 'backend_process')
        observed('backend_request_count', physical_backend['independent_backend_accept_count'], file_backend_ref)
        observed('backend_payload_identity',
            {'physical_file_backend': physical_backend,
                'client': evidence['client'],
                'backend_exclusion_proven': False},
            file_backend_ref,
            evidence['client_ref'])
        observed('client_backend_correlation',
            {'key': evidence['key'],
                'transaction_id': evidence['tx'],
                'physical_file_backend': physical_backend,
                'client': evidence['client']},
            file_backend_ref,
            evidence['client_ref'])


def observe_sink(observed, evidence):
    if evidence['sink'] is not None:
        observed('native_events',
            {'physical_common_events': evidence['events'],
                'malformed_physical_rows': [row for row in evidence['errors'] if row['path'] == str(evidence['events_path'])]},
            evidence['sink_ref'],
            evidence['audit_ref'])
        observed('physical_event_order', evidence['events'], evidence['sink_ref'])
        observed('terminal_event_count', len(evidence['events']), evidence['sink_ref'])


def observe_native(observed, evidence):
    if evidence['direct']:
        observed('native_api_returns', evidence['returns'], evidence['native_ref'])
        observed('native_transaction_id',
            [row for row in evidence['direct'] if row.get('transaction_id_origin') == 'sdk_public_m_id'],
            evidence['native_ref'])
        observed('common_transaction_id', [row for row in evidence['direct'] if row.get('canonical_transaction_id')], evidence['native_ref'])
        observed('observed_handle_association',
            {'verified_pid_scopes': sorted(evidence['scopes']),
                'direct': evidence['direct']},
            evidence['native_ref'])
        observed('native_phases',
            {name: evidence['counts'][name] for name in ('native_process_request_headers',
                    'native_process_request_body',
                    'native_process_response_headers',
                    'native_process_response_body',
                    'native_process_logging')},
            evidence['native_ref'],
            evidence['debug_ref'])
        observed('native_body_chunks',
            [row for row in evidence['returns'] if row['function'] in ('native_append_request_body',
                    'native_append_response_body')],
            evidence['native_ref'])
        observed('native_intervention_or_first_cause',
            {'native_interventions': [row for row in evidence['returns'] if row['function'] == 'native_intervention'],
                'fault_rows': records(evidence['root'] / FAULTS_NAME)[0],
                'injected_adapter_return_is_sdk_return': False},
            evidence['native_ref'],
            reference(evidence['root'] / FAULTS_NAME,
                'native_api'))
        observed('finish_calls',
            {'actual_runtime_finish': evidence['counts']['runtime_finish'],
                'actual_common_finish': evidence['counts']['common_finish'],
                'actual_native_logging': evidence['counts']['native_process_logging']},
            evidence['native_ref'])
        observed('finish_transitions',
            [row for row in evidence['associated'] if row['function'] in ('common_complete_phase',
                    'common_finish')],
            evidence['native_ref'])
        observed('native_free_calls', evidence['counts']['native_cleanup'], evidence['native_ref'])


def observe_native_eos(observed, evidence):
    if evidence['direct'] and evidence['host']:
        observed('native_eos',
            {'runtime_handoffs': [row for row in evidence['returns'] if row['function'] in ('runtime_finish_request_body',
                        'runtime_finish_response_body')],
                'native_finalizations': [row for row in evidence['returns'] if row['function'] in ('native_process_request_body',
                        'native_process_response_body')],
                'tcp_eof_is_native_eos': False},
            evidence['native_ref'],
            evidence['host_ref'])


def observe_host(observed, evidence):
    if evidence['host']:
        observed('capability',
            {'selected_route': 'traefik-native-uds',
                'actual_host_rows': evidence['host']},
            evidence['host_ref'],
            reference(source_path('connectors/traefik/native_middleware/middleware.go', root=ROOT),
                'source_contract'))
        observed('host_eos',
            [row for row in evidence['host'] if row.get('fields',
                    {}).get('end_argument') or row.get('fields',
                    {}).get('opcode') in (3,
                    6)],
            evidence['host_ref'])
        observed('commit_order',
            {'host': evidence['host'],
                'client': evidence['client'],
                'actual_native_committed_updates': [row for row in evidence['associated'] if row['function'] == 'common_set_response_committed']},
            evidence['host_ref'],
            evidence['client_ref'])
        observed('host_action',
            {'writer_rows': [row for row in evidence['host'] if row['operation'].startswith('writer_')],
                'actual_status': evidence['client'].get('status') if evidence['client'] else None},
            evidence['host_ref'],
            evidence['client_ref'])


def observe_cleanup(observed, evidence):
    if evidence['measurement'] is not None and evidence['controller'] is not None:
        observed('cleanup_receipts',
            {'case': evidence['measurement'],
                'controller': evidence['controller'],
                'final_native': [row for row in evidence['native'] or [] if row.get('function') == 'observer' and row.get('edge') == 'final']},
            evidence['case_ref'],
            evidence['result_ref'],
            evidence['isolation_ref'])
        observed('descriptor_cleanup',
            {'before': read(evidence['before_path']),
                'after_case': read(evidence['after_path']),
                'postcase_stop': evidence['measurement'].get('processes')},
            reference(evidence['after_path'],
                'cleanup_observer'),
            evidence['case_ref'])
        observed('process_listener_cleanup',
            {'case': evidence['measurement'],
                'survivors': evidence['controller'].get('surviving_namespace_pids'),
                'outside_mount_leaks': evidence['controller'].get('outside_mount_leaks')},
            evidence['case_ref'],
            evidence['result_ref'],
            evidence['isolation_ref'])


def native_association(native, tx, fallback):
    direct = [row for row in native or [] if row.get('transaction_id') == tx and
              (not fallback or row.get('pid') == fallback['pid'])]
    scopes = {(row.get('pid'), row.get('allocation_scope_call')) for row in direct
              if row.get('allocation_join_verified')}
    associated = [row for row in native or [] if
        (not fallback or row.get('pid') == fallback['pid']) and
        (row.get('transaction_id') == tx or (row.get('allocation_join_verified') and
         (row.get('pid'), row.get('allocation_scope_call')) in scopes))]
    returns = [row for row in associated if row.get('edge') == 'return']
    counts = Counter(row['function'] for row in returns)
    return direct, scopes, associated, returns, counts


def body_selection_result(selection):
    return {'schema': 'traefik-native-body-selection-candidate-v1',
        'direction': selection['direction'],
        'actual_content_type_headers': selection['headers'],
        'header_source_layer': 'client_response' if selection['response'] else 'client_request',
        'header_source': reference(selection['raw_path'],
            'client_process'),
        'actual_retained_body_records': selection['retained'],
        'sdk_rule_operator_debug': selection['executed'],
        'sdk_mime_exclusion_debug': selection['exclusion'],
        'effective_rule_source': reference(selection['rules_path'],
            'effective_configuration'),
        'actual_native_body_calls': [r for r in selection['rows'] if r.get('pid') == selection['pid'] and r.get('edge') == 'return' and (r.get('function') in ('native_append_' + selection['direction'] + '_body',
                    'native_process_' + selection['direction'] + '_body'))],
        'actual_native_interventions': [r for r in selection['rows'] if r.get('function') == 'native_intervention' and r.get('edge') == 'return'],
        'complete_pid_observer_window': selection['continuous'],
        'retained_is_inspected': False,
        'selection_interpretation': selection['interpretation'],
        'root_approval': 'pending',
        'inspection_byte_count_claimed': False}


def generated_allocations(native, pid, start, end):
    allocations = [r for r in native or [] if r.get('pid') == pid and
        start <= r.get('monotonic_ns', 0) <= end and r.get('function') in ('native_new', 'native_new_with_id') and
        r.get('edge') == 'return' and r.get('result') == 1 and r.get('invalid') is False]
    return allocations


def record_observation(observations, required_roles, name, value, *proofs):
    refs = [item for item in proofs if item is not None]
    if any(item['role'] not in required_roles[name] for item in refs):
        raise ValueError('Physical evidence role outside central observation contract: ' + name)
    if value is not None and required_roles[name] <= {item['role'] for item in refs}:
        observations[name] = {'applicable': True, 'value': value, 'evidence': refs}



def client_sources(data, root, key, case, measurement, before, errors):
    client_path = data / 'client' / (key + '.receipt.json')
    client = read(client_path)
    request_path = data / 'client' / (key + '.request.raw')
    response_path = data / 'client' / (key + '.response.raw')
    entity_path = data / 'client' / (key + '.response-entity.raw')
    wait_path = data / 'client' / (key + WAIT_SUFFIX)
    physical_file = physical_file_candidate(case, root, measurement, before)
    if physical_file and not physical_file['binding_valid']:
        errors.append({'path': str(root / 'file-evidence'),
                       'reason': physical_file.get('binding_error', 'Physical file binding incomplete')})
    if physical_file and case['fixture']['file_supplement']['physical_reader'] == 'client':
        client = physical_file.get('client') if physical_file['binding_valid'] else None
        client_path, request_path, response_path, entity_path, wait_path = (
            physical_file[name] for name in ('client_path', 'request_path', 'response_path', 'entity_path', 'wait_path'))
    return client, client_path, request_path, response_path, entity_path, wait_path, physical_file


def host_association(root, before, tx, fallback, errors):
    host_path = root / 'host-lifecycle.jsonl'
    host_rows, invalid = records(host_path)
    errors.extend(invalid)
    # Host records expose their own monotonic epoch, not Linux CLOCK_MONOTONIC.
    # Exact dedicated PID + admitted blank-only target binds these records;
    # the native allocation join above uses the actual client clock window.
    host_pid = (before or {}).get('processes', {}).get('traefik', {}).get('pid')
    host = [row for row in host_rows or [] if row.get('transaction_id') == tx or
        (fallback and host_pid is not None and row.get('pid') == host_pid and row.get('transaction_id') == '')]
    host_ref = reference(host_path, 'host_callback')
    return host, host_ref


def packet_result(case, root, identities, observations, errors, physical_file):
    output = {'run_scoped_case_id': case['id'],
        'leg_id': 'traefik-native-uds',
        'reviewed_by': 'pending_root',
        'execution_observed': identities['measurement'] is not None,
        'fixture_sha256': case.get('fixture_sha256'),
        'execution_kind': None if case['classification'] == 'config' else 'host_http',
        'run_id': identities['native'][0].get('run') if identities['native'] else None,
        'parent_sha': identities['binding'].get('checkout_base') if identities['binding'] else None,
        'framework_sha': '99a7985c1be92a2297b1b59208f64df6768f2cbf',
        'framework_scope': 'read-only original catalog; not executed',
        'mrts_sha': '8a6bb546c4c81d8ffc7be801dceac60c6925685f',
        'mrts_scope': 'read-only original catalog identity; not executed',
        'effective_config_sha256': reference(root / 'engine.conf',
            'effective_configuration'),
        'generated_id_physical_join': identities['fallback'],
        'observations': observations,
        'oracle_evaluated': False,
        'oracle_sha256': None,
        'outcome': None,
        'full_lifecycle_qualified': False,
        'physical_source_errors': errors,
        'contract_blockers': case.get('contract_blockers',
            []),
        'scope': 'Candidate only; Root must select own config/preallocation/runtime contract, approve independent oracle and evaluate.'}
    if physical_file is not None:
        output['physical_file_supplement'] = {name: value for name, value in physical_file.items() if not isinstance(value, Path)}
    config = output['effective_config_sha256']
    output['effective_config_sha256'] = config['sha256'] if config else None
    return output


def packet(attempt, case):
    data = attempt / 'data'
    key, tx = case['key'], case['transaction_id']
    root = data / 'cases' / key
    measurement = read(root / MEASUREMENT_FILE)
    if measurement is not None and (measurement.get('id') != case['id'] or
            measurement.get('fixture_sha256') != case.get('fixture_sha256')):
        raise ValueError('Actual original-ID/fixture hash differs from the supplied case binding')
    required_roles = contracts().ROLES
    observations = {name: {'applicable': True, 'value': None, 'evidence': [],
        'reason': 'No matching complete physical measurement was found.'}
        for name in required_roles}
    errors = []

    observed = partial(record_observation, observations, required_roles)

    native_path = data / 'runtime/logs/native-lifecycle.jsonl'
    native, invalid = records(native_path)
    errors.extend(invalid)
    native_ref = reference(native_path, 'native_api')
    before_path, after_path = data / (key + '-before.json'), data / (key + '-after.json')
    client, client_path, request_path, response_path, entity_path, wait_path, physical_file = client_sources(
        data, root, key, case, measurement, read(before_path), errors)
    fallback = generated_join(case, measurement, read(before_path), client, native,
                              request_path.read_bytes() if request_path.is_file() else None)
    if fallback:
        tx = fallback['transaction_id']
    direct, scopes, associated, returns, counts = native_association(native, tx, fallback)
    host, host_ref = host_association(root, read(before_path), tx, fallback, errors)
    client_ref = reference(client_path, 'client_process')
    raw_ref = reference(response_path, 'client_process')
    waited = physical_file.get('waited') if physical_file and physical_file.get('client') else read(wait_path)
    backend_path = data / 'backend/receipts.jsonl'
    backend_rows, invalid = records(backend_path)
    errors.extend(invalid)
    arrivals = [row for row in backend_rows or [] if row.get('key') == key and
                row.get('operation') == 'headers-arrived']
    backend_ref = reference(backend_path, 'backend_process')
    events_path = root / 'events.jsonl'
    sink, invalid = records(events_path)
    errors.extend(invalid)
    events = [row for row in sink or [] if row.get('transaction_id') == tx]
    sink_ref = reference(events_path, 'physical_event_sink')
    controller = read(attempt / 'controller-result.json')
    isolation_ref = reference(attempt / 'controller-result.json', 'isolation_receipt')
    result_ref = reference(data / 'acceptance-result.json', 'cleanup_observer')
    case_ref = reference(root / MEASUREMENT_FILE, 'cleanup_observer')
    debug_ref = reference(root / 'debug.log', 'native_debug')
    audit_ref = reference(root / 'audit.log', 'physical_event_sink')
    binding = read(data / 'current-product-binding.json')
    build = read(data / 'acceptance-build.json')
    observed('product_host_identity', {'before': read(before_path), 'after': read(after_path),
        'controller': controller}, reference(before_path, 'loaded_image'), isolation_ref)
    if measurement is not None:
        observed('source_config_binding', {'build': build, 'product_binding': binding,
            'configuration': measurement.get('configuration')},
            reference(data / 'acceptance-build.json', 'source_manifest'),
            reference(data / 'current-product-binding.json', 'source_manifest'),
            reference(root / 'engine.conf', 'effective_configuration'))
    observe_client(observed,
        {'client': client,
            'client_ref': client_ref,
            'entity_path': entity_path,
            'host': host,
            'host_ref': host_ref,
            'raw_ref': raw_ref,
            'wait_path': wait_path,
            'waited': waited})
    observe_backend(observed,
        {'arrivals': arrivals,
            'backend_ref': backend_ref,
            'backend_rows': backend_rows,
            'case': case,
            'client': client,
            'client_ref': client_ref,
            'key': key,
            'physical_file': physical_file,
            'tx': tx})
    observe_sink(observed,
        {'audit_ref': audit_ref,
            'errors': errors,
            'events': events,
            'events_path': events_path,
            'sink': sink,
            'sink_ref': sink_ref})
    observe_native(observed,
        {'associated': associated,
            'counts': counts,
            'direct': direct,
            'native_ref': native_ref,
            'returns': returns,
            'root': root,
            'scopes': scopes,
            'debug_ref': debug_ref})
    observe_native_eos(observed, {'direct': direct, 'host': host, 'host_ref': host_ref, 'native_ref': native_ref, 'returns': returns})
    observe_host(observed, {'associated': associated, 'client': client, 'client_ref': client_ref, 'host': host, 'host_ref': host_ref})
    observe_cleanup(observed,
        {'after_path': after_path,
            'before_path': before_path,
            'case_ref': case_ref,
            'controller': controller,
            'isolation_ref': isolation_ref,
            'measurement': measurement,
            'native': native,
            'result_ref': result_ref})
    neighbor_path = data / 'client' / ('neighbor-' + key + '.receipt.json')
    observed('neighbor_health', {'client': read(neighbor_path), 'backend': [row for row in backend_rows or []
        if row.get('key') == 'neighbor-' + key]}, reference(neighbor_path, 'client_process'), backend_ref)
    selection = body_selection_candidate(case, root, {'client': client, 'before': read(before_path),
        'request_path': request_path, 'response_path': response_path,
        'associated': associated, 'all_native': native or [], 'scopes': scopes, 'transaction_id': tx})
    if selection is not None:
        observed('mime_gate', selection, reference(root / FAULTS_NAME, 'native_api'), native_ref, debug_ref, sink_ref)
    return packet_result(case, root, {'measurement': measurement, 'native': native,
        'binding': binding, 'fallback': fallback}, observations, errors, physical_file)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('attempt', type=Path)
    parser.add_argument('manifest', type=Path)
    parser.add_argument('key')
    args = parser.parse_args()
    selected = next(case for case in read(args.manifest)['cases'] + read(args.manifest).get('supplementary_executions',
            []) if case['key'] == args.key)
    print(json.dumps(packet(args.attempt, selected), indent=2))
