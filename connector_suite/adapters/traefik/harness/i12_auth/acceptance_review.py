"""Reconcile original-ID auth raw outputs without inferring missing evidence."""
from modsecurity_test_framework.connector_context import load_source
import argparse
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path

# Load the maintained Parent filesystem boundary from this checkout.
import sys as _i12_sys

import modsecurity_connector_ci.lib.i12_path_safety as i12_paths


CASE_RECEIPT = 'case.json'


def read(path):
    return json.loads(path.read_text()) if path.is_file() else None


def jsonl(path):
    if not path.is_file():
        return {'rows':None,'parsed_rows':None,'decode_errors':None}
    raw=path.read_bytes();parsed=[];errors=[];offset=0
    for index,line in enumerate(raw.splitlines(keepends=True)):
        if line.strip():
            try:
                row=json.loads(line)
                if not isinstance(row,dict):raise ValueError('JSONL record is not an object')
                parsed.append(row)
            except ValueError as error:
                errors.append({'zero_based_line':index,'byte_offset':offset,'line_bytes':len(line),
                    'line_sha256':hashlib.sha256(line).hexdigest(),'exception':type(error).__name__,
                    'message':str(error)[:1000]})
        offset+=len(line)
    return {'rows':None if errors else parsed,'parsed_rows':parsed,'decode_errors':errors,
        'raw_sha256':hashlib.sha256(raw).hexdigest(),'raw_bytes':len(raw)}


def rows(path):
    return jsonl(path)['rows']


def reference(path):
    return {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
            'bytes': path.stat().st_size}


def require(condition, message):
    if not condition:
        raise ValueError(message)
def receipt(path):
    require(path.is_file() and not path.is_symlink(), 'missing physical receipt: ' + str(path))
    value = read(path)
    require(isinstance(value, dict), 'physical receipt object required')
    return value
def same_wire(path, value, size, digest):
    require(path.is_file() and not path.is_symlink(), 'missing physical wire: ' + str(path))
    require(path.stat().st_size == value.get(size) and reference(path)['sha256'] == value.get(digest),
            'physical wire digest differs: ' + str(path))
def correlated_headers(path, key):
    head = path.read_bytes().partition(b'\r\n\r\n')[0].split(b'\r\n')[1:]
    pairs = [line.split(b':', 1) for line in head if b':' in line]
    for name in (b'x-request-id', b'x-i12-acceptance-key', b'x-i12-probe'):
        require([value.strip() for header, value in pairs if header.lower() == name] == [key.encode()],
                'foreign physical HTTP correlation')


def validate_prepared_file_case(root, prepared, spec, binding, result):
    controls_path = Path(__file__).with_name('acceptance_controls.py')
    controls = load_source(controls_path)
    controls.file_binding(spec)
    fixtures = prepared / 'fixtures'
    admitted = receipt(fixtures / 'acceptance-manifest.json')['cases']
    expanded = [row for case in admitted for row in [case, *controls.controls(case)]]
    matches = [row for row in expanded if row['probe_id'] == spec['probe_id']]
    require(matches == [spec] and root.name == spec['probe_id'], 'physical file case differs from Prepared original/control')
    manifest_path = fixtures / 'i12_file/manifest.json'
    manifest = receipt(manifest_path)
    require(reference(manifest_path)['sha256'] == binding['manifest_sha256'] and
            {row['relative_path']: row for row in manifest['files']} == binding['files'],
            'physical file manifest differs from Prepared binding')
    require(reference(fixtures / 'i12_file/acceptance.py')['sha256'] == binding['rules_source_sha256'],
            'physical file source contract differs from Prepared binding')
    result['prepared_binding'] = {'case': reference(root / CASE_RECEIPT),
        'manifest': reference(manifest_path), 'source_contract': reference(fixtures / 'i12_file/acceptance.py')}


def validate_physical_source(source, physical, binding, expected):
    if source is not None:
        require(isinstance(source, dict), 'physical source object required')
        require(source.get('pid') == physical['pid'] and source.get('uid') == 65534 and source.get('native_file_api') is False and
                source.get('relative_path') == binding['fixture'] and
                source.get('expected_size') == expected['size'] and source.get('expected_sha256') == expected['sha256'],
                'foreign physical source receipt')
        if source.get('complete') is True:
            require(source.get('bytes') == expected['size'] and source.get('sha256') == expected['sha256'] and
                    source.get('close', {}).get('result') == 0 and source.get('root_close', {}).get('result') == 0,
                    'complete physical source digest/close differs')


def physical_client_window(direction, response_path, client, evidence, key, command, spec):
    binding = spec['fixture']['physical_file_supplement']
    if direction == 'request':
        same_wire(response_path, client, 'client_response_wire_bytes', 'client_response_wire_sha256')
        same_wire(evidence / (key + '.request-head.raw'), client, 'request_head_wire_bytes', 'request_head_wire_sha256')
        correlated_headers(evidence / (key + '.request-head.raw'), key)
        peer = client.get('peer')
        require(isinstance(peer, list) and len(peer) == 2 and peer[0] == '127.0.0.1' and
                type(peer[1]) is int and 1 <= peer[1] <= 65535, 'physical file host endpoint differs')
        virtual_root = '/task/cases/' + key
        expected_argv = ['rtk', 'proxy', '/usr/local/bin/python3', '-P', '/mnt/fixtures/i12_file/run.py', 'client',
            '--manifest', '/mnt/fixtures/i12_file/manifest.json', '--private-root', virtual_root + '/file-source',
            '--evidence-root', virtual_root + '/file-evidence', '--fixture', binding['fixture'],
            '--port', str(client['peer'][1]), '--key', key, '--transaction-id', key, '--uri', spec['fixture']['request']['uri']]
        require(command.get('argv') == expected_argv, 'physical file client argv differs from sealed invocation')
        start = client.get('started_ns'); end = client.get('completed_ns')
    else:
        require(client.get('probe') == key and all(row.get('wire_probe') == key for row in client.get('requests', [])) and
                len(client.get('requests', [])) == 1, 'foreign physical response client')
        same_wire(response_path, client['requests'][0], 'raw_bytes', 'raw_sha256')
        start = client.get('monotonic_ns'); end = client.get('completed_ns')
    return (start, end)


def validate_source_closes(source):
    for name in ('close', 'root_close'):
        event = source.get(name)
        if event is not None:
            for field in ('started_ns', 'completed_ns'):
                if field in event:
                    ordered(source['started_ns'], event[field], source['completed_ns'])
            if 'started_ns' in event and 'completed_ns' in event:
                ordered(event['started_ns'], event['completed_ns'])


def allocation_scope(allocation, identities, native, host, common):
    scope = allocation.get('allocation_scope_call')
    identity = allocation.get('transaction_id')
    ambiguous=identity is None or identities[identity]!=1
    entered = {row['call'] for row in native
               if row.get('allocation_scope_call') == scope and row.get('edge') == 'enter'}
    calls = [row for row in native
             if row.get('allocation_scope_call') == scope or row.get('call') in entered]
    if scope is None:
        calls = [allocation]
    scope_record = {'native_id': identity, 'allocation_scope_call': scope, 'native_allocation': allocation,
        'native_call_returns': dict(Counter(row['function'] for row in calls if row.get('edge') == 'return')),
        'native_calls': calls,
        'native_id_reused_or_unknown_in_case':ambiguous,
        'host_observations': None if host is None or ambiguous else [row for row in host if row.get('transaction_id') == identity],
        'common_events': None if common is None or ambiguous else [row for row in common if row.get('transaction_id') == identity]}
    return scope_record


def validate_source_events(source, physical, end):
    ordered(physical['backend_headers_sendall_returned_ns'], source.get('started_ns'), source.get('completed_ns'), end)
    # Stat mtime_ns/ctime_ns use the filesystem epoch clock. Only
    # the producer's explicit monotonic event fields belong here.
    for name in ('open_started_ns', 'opened_ns', 'eof_read_started_ns', 'eof_read_completed_ns'):
        if name in source:
            ordered(source['started_ns'], source[name], source['completed_ns'])
    validate_source_closes(source)
    for event in source.get('reads', []):
        ordered(source['started_ns'], event.get('started_ns'), event.get('completed_ns'), source['completed_ns'])
        if 'consumer_returned_ns' in event:
            ordered(event['completed_ns'], event['consumer_returned_ns'], source['completed_ns'])
    for event in physical.get('http_chunks', []):
        ordered(source['started_ns'], event.get('started_ns'), event.get('sendall_returned_ns'), source['completed_ns'])


def validate_backend_source_timing(source, physical, end):
    if source is not None:
        validate_source_events(source, physical, end)
    if 'http_terminator_send_started_ns' in physical:
        ordered(source.get('completed_ns') if source else None, physical['http_terminator_send_started_ns'],
                physical.get('http_terminator_sendall_returned_ns'), end)


def ordered(*times):
    require(all(type(value) is int for value in times) and list(times) == sorted(times),
            'physical backend event lies outside client window or event order')


def review_physical_backend(root, spec, physical, result):
    direction = spec['fixture']['physical_file_supplement']['direction']
    key = spec['probe_id']
    evidence = root / 'file-evidence'
    start = result['client_window']['started_ns']
    end = result['client_window']['completed_ns']
    source = physical.get('file_source')
    if direction == 'response':
        accept_path = evidence / (key + '.backend-accept.json'); accept = receipt(accept_path)
        listen_path = evidence / (key + '.backend-listening.json'); listen = receipt(listen_path)
        request_path = evidence / (key + '.backend-request.raw')
        same_wire(request_path, physical, 'request_wire_bytes', 'request_wire_sha256')
        correlated_headers(request_path, key)
        for name in (b'x-request-id', b'x-i12-acceptance-key', b'x-i12-probe'):
            require(physical.get('observed_correlation', {}).get(name.decode()) == key, 'foreign physical backend correlation')
        require(accept.get('pid') == physical['pid'] and accept.get('key') == key and accept.get('transaction_id') == key and
                accept.get('independent_backend_accept_count') == physical.get('independent_backend_accept_count') == 1 and
                accept.get('peer') == physical.get('peer') and listen.get('pid') == physical['pid'] and
                physical.get('local') == ['127.0.0.1', listen.get('port')], 'foreign physical backend accept/listen identity')
        producer_path = root / 'result.json'; producer = receipt(producer_path)
        snapshot_path = root / 'before-target.json'; snapshot = receipt(snapshot_path)
        launch_path = root / 'physical-file-backend.launch.json'; launch = receipt(launch_path)
        readiness = producer.get('physical_file_backend_readiness', {})
        process = snapshot.get('processes', {}).get('physical-file-backend', {})
        require(readiness.get('pid') == process.get('pid') == physical['pid'] and
                readiness.get('wrapper_pid') == process.get('proxy_pid') == launch.get('proxy_pid') and
                readiness.get('port') == listen.get('port') and
                readiness.get('receipt') == '/task/cases/' + key + '/file-evidence/' + key + '.backend-listening.json' and
                readiness.get('sha256') == reference(listen_path)['sha256'] and
                readiness.get('tcp_readiness_probe_performed') is False,
                'physical backend differs from independent driver readiness/process snapshot')
        ordered(launch.get('monotonic_ns'), snapshot.get('monotonic_ns'), start)
        ordered(physical.get('started_ns'), listen.get('monotonic_ns'), snapshot.get('monotonic_ns'), start,
                accept.get('accepted_ns'), physical.get('accepted_ns'), physical.get('request_http_eos_ns'),
                physical.get('backend_headers_send_started_ns'), physical.get('backend_headers_sendall_returned_ns'), end)
        require(accept.get('accepted_ns') == physical.get('accepted_ns'), 'physical accept timestamp differs')
        validate_backend_source_timing(source, physical, end)
        result.update(backend=physical, backend_accept=accept, backend_listen=listen,
                      backend_driver_binding={'readiness': readiness, 'snapshot': snapshot, 'launch': launch,
                          'references': [reference(path) for path in (producer_path, snapshot_path, launch_path)]})
        result['paths'].update(backend=result['paths']['reader'], backend_accept=str(accept_path), backend_listen=str(listen_path),
                               backend_request=str(request_path), backend_driver=str(producer_path),
                               backend_snapshot=str(snapshot_path), backend_launch=str(launch_path))


def physical_file_review(root, prepared):
    """Join exact physical-file receipts to admitted bytes, without qualification."""
    spec = read(root / CASE_RECEIPT)
    binding = spec.get('fixture', {}).get('physical_file_supplement') if spec else None
    if binding is None:
        return None
    result = {'binding_valid': False, 'errors': [], 'qualification': None,
              'native_file_api_executed': False, 'paths': {}}
    try:
        require(prepared is not None, 'Prepared binding required for physical file receipts')
        validate_prepared_file_case(root, prepared, spec, binding, result)
        if spec['classification'] == 'config':
            result.update(binding_valid=True, configuration_only=True)
            return result
        key = spec['probe_id']; direction = binding['direction']; evidence = root / 'file-evidence'
        file_path = evidence / (key + ('.client.json' if direction == 'request' else '.backend.json'))
        physical = receipt(file_path)
        require(physical.get('schema') == 'traefik-file-http-' + ('client' if direction == 'request' else 'backend') + '-v1' and
                physical.get('key') == key and physical.get('transaction_id') == key and
                physical.get('native_file_api') is False and type(physical.get('pid')) is int and physical['pid'] > 0 and
                physical.get('process', {}).get('pid') == physical['pid'] and
                physical.get('process', {}).get('uid') == 65534, 'foreign physical reader identity')
        expected = binding['files'][binding['fixture']]
        source = physical.get('file_source')
        validate_physical_source(source, physical, binding, expected)
        client_path = file_path if direction == 'request' else root / 'client-target.json'
        client = receipt(client_path)
        response_path = evidence / (key + '.response.raw') if direction == 'request' else root / 'target-0.response.raw'
        command_path = root / ('physical-file-client.command.json' if direction == 'request' else 'client-target.command.json')
        command = receipt(command_path)
        require(type(command.get('started_ns')) is int and type(command.get('completed_ns')) is int and
                command['started_ns'] <= command['completed_ns'], 'missing physical client command window')
        (start, end) = physical_client_window(direction, response_path, client, evidence, key, command, spec)
        require(type(start) is int and type(end) is int and command['started_ns'] <= start <= end <= command['completed_ns'],
                'physical client lies outside waited command window')
        require(response_path.is_file() and not response_path.is_symlink(), 'missing physical client response wire')
        result['paths'] = {'reader': str(file_path), 'client': str(client_path), 'response': str(response_path),
                           'client_command': str(command_path)}
        result.update(client=client, command=command, reader=physical, client_window={'started_ns': start, 'completed_ns': end},
                      source_complete=bool(source and source.get('complete') is True), backend=None)
        review_physical_backend(root, spec, physical, result)
        result['binding_valid'] = True
    except (ValueError, KeyError, TypeError, OSError) as error:
        result['errors'].append(str(error))
    return result


def native_scopes(native, host, common):
    scopes = []
    if native is not None:
        identities=Counter(row.get('transaction_id') for row in native
            if row.get('function') in ('native_new','native_new_with_id') and row.get('edge')=='return' and row.get('result')==1)
        for allocation in native:
            if allocation.get('function') not in ('native_new', 'native_new_with_id') or allocation.get('edge') != 'return':
                continue
            if allocation.get('result') != 1:
                continue
            scopes.append(allocation_scope(allocation, identities, native, host, common))
    return scopes


def review_case(root, prepared=None):
    spec = read(root / CASE_RECEIPT)
    if spec is None:
        return {'path': str(root), 'producer_error': 'missing original fixture binding', 'qualification': None}
    native = rows(root / 'runtime/logs/native-lifecycle.jsonl')
    host = rows(root / 'runtime/logs/host-lifecycle.jsonl')
    common = rows(root / 'runtime/logs/events.jsonl')
    owner_path = Path(__file__).with_name('review.py')
    owner = load_source(owner_path)
    clients = {path.name: owner.framing(path.read_bytes())
               for path in sorted(root.glob('*.response.raw'))}
    physical = physical_file_review(root, prepared)
    if physical and physical['binding_valid'] and not physical.get('configuration_only'):
        path = Path(physical['paths']['response'])
        clients[str(path.relative_to(root))] = owner.framing(path.read_bytes())
    scopes = native_scopes(native, host, common)
    return {'original_id': spec['id'], 'probe_id': spec['probe_id'],
            'control_name': spec.get('control_name'), 'fixture': spec,
            'producer': read(root / 'result.json'), 'clients': clients,
            'physical_file_supplement': physical,
            'authorization': rows(root / 'authorization.jsonl'),
            'backend': rows(root / 'backend.jsonl'), 'native_scopes': scopes,
            'host_probe_observations': host,
            'host_probe_identity_is_not_assumed_native_identity': True,
            'observer_final': None if native is None else [row for row in native if row.get('edge') == 'final'],
            'fault_operations': rows(root / 'faults.jsonl'),
            'companion_transport': rows(root / 'companion-peer.jsonl'),
            'jsonl_decoding': {name:jsonl(root/name) for name in (
                'runtime/logs/native-lifecycle.jsonl','runtime/logs/host-lifecycle.jsonl',
                'runtime/logs/events.jsonl','faults.jsonl','authorization.jsonl','backend.jsonl','companion-peer.jsonl')},
            'raw_references': [reference(path) for path in sorted(root.rglob('*')) if path.is_file()],
            'qualification': None}


def review(attempt, output, prepared=None):
    binding = None
    if prepared is not None:
        owner = load_source(Path(__file__).with_name('acceptance_binding.py'))
        binding = owner.validate_attempt_binding(attempt, prepared)
    data = attempt / 'data'
    selected = [review_case(root, prepared) for root in sorted((data / 'cases').iterdir()) if root.is_dir()]
    result = {'schema': 'traefik-auth-acceptance-physical-review-v1',
        'attempt': str(attempt), 'controller': read(attempt / 'controller-result.json'),
        'prepared_attempt_binding': binding,
        'build': read(data / 'acceptance-build.json'),
        'execution_summary': read(data / 'acceptance-execution-summary.json'),
        'physical_case_directories': len(selected), 'cases': selected,
        'qualification': None}
    with i12_paths.new_text(output) as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--attempt', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--prepared', type=Path)
    args = parser.parse_args()
    value = review(args.attempt, args.output, args.prepared)
    print(json.dumps({'case_directories': value['physical_case_directories'], 'qualification': None}))
