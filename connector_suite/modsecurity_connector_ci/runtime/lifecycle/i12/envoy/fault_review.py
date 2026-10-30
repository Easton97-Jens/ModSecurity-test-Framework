#!/usr/bin/env python3
"""Add independently scoped fault facts to one physical review; never assign PASS."""
import argparse
from collections import Counter, deque
import hashlib
import json
from pathlib import Path
import re

import modsecurity_connector_ci.runtime.lifecycle.i12.envoy.evidence_io as E


FAULT_CONTRACT = 'fault-contract.json'
SHAPE = 'shape.json'

HASH = re.compile(r'[\da-f]{64}', re.ASCII)
TAGGED = re.compile(r'\[Tags: "ConnectionId":"(\d+)","StreamId":"(\d+)"\]', re.ASCII)
THREAD = re.compile(r'^\[[^]]+\] \[(\d+)\]', re.ASCII)


def selected_stream(rows, identity):
    ids = {row['stream_id'] for row in rows if row.get('request_id') == identity}
    if len(ids) != 1:
        raise ValueError('exactly one proxy stream per selected client required')
    stream_id = ids.pop()
    selected = [row for row in rows if row.get('stream_id') == stream_id]
    if (not selected or [row.get('sequence') for row in selected] != list(range(1, len(selected) + 1))
            or any(row.get('request_id') not in ('', identity) for row in selected)):
        raise ValueError('proxy stream sequence or client correlation changed')
    return selected


def terminal(rows, name):
    values = [row for row in rows if row.get('event') == name]
    if len(values) != 1:
        raise ValueError('one actual proxy terminal observation required: ' + name)
    return {key: values[0].get(key) for key in (
        'sequence', 'grpc_api_code', 'wire_grpc_status', 'recv_eof', 'return_source',
        'close_send_error_nil', 'trailers', 'error_sha256')}


def message_fingerprint(row):
    digest = row.get('message_sha256')
    size = row.get('message_bytes')
    if not isinstance(digest, str) or HASH.fullmatch(digest) is None or type(size) is not int or size < 0:
        raise ValueError('bounded proxy message identity required')
    body_size = row.get('body_bytes')
    body_digest = row.get('body_sha256')
    if body_size is not None and (type(body_size) is not int or body_size < 0
                                  or not isinstance(body_digest, str) or HASH.fullmatch(body_digest) is None):
        raise ValueError('bounded proxy body identity required')
    return tuple(row.get(key) for key in (
        'message_sha256', 'message_bytes', 'message_type', 'body_bytes', 'body_sha256', 'eos'))


def ordered_flow(rows, incoming, outgoing, dropped=None):
    """Match each message to its later forwarding decision without losing ordering."""
    pending = deque()
    for row in rows:
        if row.get('event') != 'message':
            continue
        direction = row.get('direction')
        if direction == incoming:
            pending.append(message_fingerprint(row))
        elif direction == outgoing or (dropped is not None and direction == dropped):
            if not pending or pending.popleft() != message_fingerprint(row):
                return False
    return not pending


def stream_summary(rows):
    messages = [row for row in rows if row.get('event') == 'message']
    allowed_directions = {'downstream_receive', 'upstream_send', 'upstream_receive',
                          'downstream_send', 'dropped_before_upstream_send'}
    if any(row.get('direction') not in allowed_directions for row in messages):
        raise ValueError('unknown proxy message direction')
    directions = Counter(row['direction'] for row in messages)
    dropped = [row for row in messages if row['direction'] == 'dropped_before_upstream_send']
    request_ordered = ordered_flow(rows, 'downstream_receive', 'upstream_send',
                                   'dropped_before_upstream_send')
    response_ordered = ordered_flow(rows, 'upstream_receive', 'downstream_send')
    return {'stream_id': rows[0]['stream_id'], 'message_direction_counts': dict(directions),
        'actual_upstream_attempt_count': sum(row.get('event') == 'upstream_attempt_begin' for row in rows),
        'dropped_messages': [{key: row.get(key) for key in (
            'sequence', 'message_type', 'message_sha256', 'body_bytes', 'body_sha256', 'eos')} for row in dropped],
        'request_messages_forwarded_unchanged_in_order': request_ordered,
        'response_messages_forwarded_unchanged_in_order': response_ordered,
        'upstream_attempt_terminal': terminal(rows, 'upstream_attempt_end'),
        'upstream_receive_terminal': terminal(rows, 'upstream_recv_end'),
        'proxy_downstream_return': terminal(rows, 'downstream_return'),
        'remote_wire_status_observed': False}


def proxy_projection(rows, shape):
    target_rows = selected_stream(rows, shape['target'])
    neighbor_rows = selected_stream(rows, shape['neighbor'])
    if target_rows[0]['stream_id'] == neighbor_rows[0]['stream_id']:
        raise ValueError('target and neighbor proxy streams must be independent')
    target, neighbor = stream_summary(target_rows), stream_summary(neighbor_rows)
    half_close = terminal(target_rows, 'upstream_close_send_return')
    target['actual_upstream_close_send'] = half_close
    drops = target['dropped_messages']
    dropped_receive = [row for row in target_rows if row.get('direction') == 'downstream_receive'
                       and drops and row.get('message_sha256') == drops[0]['message_sha256']]
    ordered_terminal = bool(len(dropped_receive) == 1 and drops
        and dropped_receive[0]['sequence'] < drops[0]['sequence'] < half_close['sequence']
        < target['upstream_attempt_terminal']['sequence'] < target['upstream_receive_terminal']['sequence']
        < target['proxy_downstream_return']['sequence'])
    target_error = target['upstream_receive_terminal']['error_sha256']
    checks = {
        'one_empty_response_eos_dropped': len(drops) == 1 and drops[0]['body_bytes'] == 0
            and drops[0]['eos'] is True
            and drops[0]['message_type'] == '*ext_procv3.ProcessingRequest_ResponseBody',
        'drop_and_terminals_are_ordered': ordered_terminal,
        'actual_successful_close_send': half_close['close_send_error_nil'] is True
            and half_close['grpc_api_code'] is None,
        'upstream_api_unavailable': target['upstream_attempt_terminal']['grpc_api_code'] == 14
            and target['upstream_receive_terminal']['grpc_api_code'] == 14
            and target['upstream_receive_terminal']['recv_eof'] is False,
        'proxy_return_preserves_actual_upstream_error': target['proxy_downstream_return']['grpc_api_code'] == 14
            and target['proxy_downstream_return']['return_source'] == 'upstream_receive'
            and isinstance(target_error, str) and HASH.fullmatch(target_error) is not None
            and target['upstream_attempt_terminal']['error_sha256'] == target_error
            and target['proxy_downstream_return']['error_sha256'] == target_error,
        'neighbor_unchanged_and_actual_api_success': neighbor['dropped_messages'] == []
            and neighbor['upstream_attempt_terminal']['grpc_api_code'] == 0
            and neighbor['upstream_receive_terminal']['grpc_api_code'] == 0
            and neighbor['upstream_receive_terminal']['recv_eof'] is True
            and neighbor['proxy_downstream_return']['grpc_api_code'] == 0,
        'single_actual_upstream_attempt_each': target['actual_upstream_attempt_count'] == 1
            and neighbor['actual_upstream_attempt_count'] == 1,
        'all_forwarded_messages_unchanged_in_order':
            target['request_messages_forwarded_unchanged_in_order']
            and target['response_messages_forwarded_unchanged_in_order']
            and neighbor['request_messages_forwarded_unchanged_in_order']
            and neighbor['response_messages_forwarded_unchanged_in_order'],
        'wire_status_not_invented': all(row.get('wire_grpc_status') is None for row in rows),
    }
    if not all(checks.values()):
        failed = sorted(name for name, passed in checks.items() if not passed)
        raise ValueError('fault proxy evidence contract changed: ' + ','.join(failed))
    return {'target': target, 'neighbor': neighbor, 'source_contract_checks': checks,
        'engine_api_status_is_not_envoy_receipt': True,
        'host_lifecycle_qualified': False, 'new_lifecycle_pass': 0}


def request_headers(lines, index):
    headers = []
    for candidate in lines[index + 1:index + 34]:
        if not candidate:
            break
        headers.append(candidate)
    return headers


def tagged_requests(lines, identity):
    requests = []
    for index, line in enumerate(lines):
        tags = TAGGED.search(line)
        if tags is None or 'request headers complete (end_stream=false):' not in line:
            continue
        headers = request_headers(lines, index)
        if f"':path', '/{identity}'" in headers and f"'x-request-id', '{identity}'" in headers:
            worker = THREAD.match(line)
            if worker is None:
                raise ValueError('tagged Envoy request requires a worker identity')
            requests.append((index, tags.group(1), tags.group(2), worker.group(1)))
    return requests


def adjacent_status_chains(lines, error_line):
    chains = []
    for status_line in range(max(0, error_line - 12), error_line):
        match = re.fullmatch(r"'grpc-status', '(\d+)'", lines[status_line], re.ASCII)
        if match is None:
            continue
        markers = [i for i in range(max(0, status_line - 6), status_line)
                   if 'async http request response trailers:' in lines[i]]
        remote = [(i, int(found.group(1))) for i in range(status_line + 1, error_line)
                  if (found := re.search(r'gRPC stream closed remotely with status (\d+):', lines[i], re.ASCII))]
        if len(markers) == 1 and len(remote) == 1:
            chains.append((markers[0], status_line, int(match.group(1)), remote[0]))
    return chains


def tagged_error_and_reset(lines, tag):
    errors = [(index, int(match.group(1))) for index, line in enumerate(lines)
              if tag in line and (match := re.search(r'Received gRPC error on stream: (\d+),', line, re.ASCII))]
    resets = [(index, int(match.group(1))) for index, line in enumerate(lines)
              if tag in line and 'Prior headers have already been sent' in line
              and (match := re.search(r'ext_proc_error_gRPC_error_(\d+)', line, re.ASCII))]
    if len(errors) != 1 or len(resets) != 1 or errors[0][1] != 14 or resets[0][1] != 14:
        raise ValueError('one tagged Envoy status-14 callback and postcommit reset required')
    return errors, resets


def validate_status_chain(lines, request_line, worker_id, errors, resets, chain):
    marker_line, trailer_line, trailer_status, (remote_line, remote_status) = chain
    error_line, reset_line = errors[0][0], resets[0][0]
    worker_lines = (request_line, marker_line, remote_line, error_line, reset_line)
    same_worker = all((match := THREAD.match(lines[index])) is not None
                      and match.group(1) == worker_id for index in worker_lines)
    if not (request_line < marker_line and marker_line + 1 == trailer_line
            and remote_line == trailer_line + 3 and lines[trailer_line + 1].startswith("'grpc-message', '")
            and lines[trailer_line + 2] == '' and remote_line + 1 == error_line < reset_line
            and same_worker
            and trailer_status == remote_status == errors[0][1] == resets[0][1]):
        raise ValueError('Envoy status correlation or event order changed')


def envoy_status_projection(raw, identity):
    """Bind an Envoy status to the selected HTTP stream, not to an untagged trailer alone."""
    lines = raw.decode('utf-8', errors='replace').splitlines()
    requests = tagged_requests(lines, identity)
    if len(requests) != 1:
        raise ValueError('one tagged Envoy request stream must match the selected client')
    request_line, connection_id, stream_id, worker_id = requests[0]
    tag = f'[Tags: "ConnectionId":"{connection_id}","StreamId":"{stream_id}"]'
    errors, resets = tagged_error_and_reset(lines, tag)
    error_line, reset_line = errors[0][0], resets[0][0]
    chains = adjacent_status_chains(lines, error_line)
    if len(chains) != 1:
        raise ValueError('one adjacent Envoy trailer and remote-close chain required')
    marker_line, trailer_line, trailer_status, (remote_line, _) = chains[0]
    validate_status_chain(lines, request_line, worker_id, errors, resets, chains[0])
    return {'request_id': identity, 'connection_id': int(connection_id), 'stream_id': int(stream_id),
        'worker_id': int(worker_id),
        'grpc_status': trailer_status, 'trailer_status_observed': True,
        'remote_close_status_observed': True, 'tagged_error_callback_observed': True,
        'postcommit_reset_observed': True, 'successful_grpc_completion': False,
        'physical_line_numbers': {'request_headers': request_line + 1, 'trailers': marker_line + 1,
            'grpc_status': trailer_line + 1, 'remote_close': remote_line + 1,
            'tagged_error': error_line + 1, 'postcommit_reset': reset_line + 1}}


def chunked_response_parts(raw):
    head, remainder = raw.split(b'\r\n\r\n', 1)
    status = re.match(rb'HTTP/1\.1 (\d{3}) ', head)
    fields = [line.split(b':', 1) for line in head.split(b'\r\n')[1:] if b':' in line]
    lengths = [value.strip() for name, value in fields if name.lower() == b'content-length']
    transfer = [value.strip().lower() for name, value in fields if name.lower() == b'transfer-encoding']
    if status is None or transfer != [b'chunked'] or lengths:
        return None
    return int(status[1]), remainder


def prefix_result(status, complete, body, sizes, wire_bytes):
    return {'http_status': status, 'framing_complete': complete,
        'terminal_zero_chunk_observed': complete, 'entity_prefix_bytes': len(body),
        'entity_prefix_sha256': hashlib.sha256(body).hexdigest(),
        'complete_chunk_sizes': sizes, 'wire_body_bytes': wire_bytes}


def complete_chunk(remainder, body_bytes):
    if b'\r\n' not in remainder:
        return None
    token, content = remainder.split(b'\r\n', 1)
    if re.fullmatch(rb'[\da-fA-F]+', token) is None:
        return None
    size = int(token, 16)
    if size == 0:
        return (size, content) if content == b'\r\n' else None
    if size > 65536 - body_bytes or len(content) < size + 2 or content[size:size + 2] != b'\r\n':
        return None
    return size, content


def chunked_prefix(raw):
    """Decode only complete bounded chunks, retaining an absent terminal chunk as incomplete."""
    if not isinstance(raw, bytes) or len(raw) > 65536 or b'\r\n\r\n' not in raw:
        return None
    parts = chunked_response_parts(raw)
    if parts is None:
        return None
    status, remainder = parts
    wire_bytes = len(remainder)
    body, sizes = bytearray(), []
    for _ in range(4096):
        if remainder == b'':
            return prefix_result(status, False, body, sizes, wire_bytes)
        chunk = complete_chunk(remainder, len(body))
        if chunk is None:
            return None
        size, content = chunk
        if size == 0:
            return prefix_result(status, True, body, sizes, wire_bytes)
        body.extend(content[:size])
        sizes.append(size)
        remainder = content[size + 2:]
    return None


def fault_client_projection(raw, expected):
    result = chunked_prefix(raw)
    if (result is None or result['http_status'] != 200 or result['framing_complete'] is not False
            or result['terminal_zero_chunk_observed'] is not False
            or result['entity_prefix_bytes'] != len(expected)
            or result['entity_prefix_sha256'] != hashlib.sha256(expected).hexdigest()
            or result['complete_chunk_sizes'] != [64, 32]):
        raise ValueError('selected client response is not the bounded incomplete 96-byte prefix')
    return result


def verified_artifact(scenario, relative):
    path = Path(scenario['attempt']) / 'data' / relative
    reference = E.reference(path)
    physical = scenario['physical_files'].get(relative)
    if not isinstance(physical, dict) or any(reference[key] != physical.get(key) for key in ('sha256', 'bytes')):
        raise ValueError('fault artifact differs from physical review: ' + relative)
    return path, reference


def sealed_fixture_files(binding, names):
    source, ledger_path = Path(binding['source']), Path(binding['ledger'])
    ledger_raw = E.read_bytes(ledger_path)
    ledger_digest = hashlib.sha256(ledger_raw).hexdigest()
    if ledger_digest != binding.get('ledger_sha256'):
        raise ValueError('sealed fixture ledger hash changed')
    ledger = json.loads(ledger_raw)
    files = ledger.get('files')
    if not isinstance(files, dict):
        raise ValueError('sealed fixture ledger file map required')
    references, payloads = {}, {}
    for name in names:
        if '/' in name or name not in files or not isinstance(files[name], str):
            raise ValueError('selected file absent from sealed fixture ledger: ' + name)
        path = source / name
        raw = E.read_bytes(path)
        digest = hashlib.sha256(raw).hexdigest()
        if digest != files[name]:
            raise ValueError('selected file differs from sealed fixture ledger: ' + name)
        references[name] = {'path': str(path), 'sha256': digest, 'bytes': len(raw)}
        payloads[name] = raw
    ledger_reference = {'path': str(ledger_path), 'sha256': ledger_digest, 'bytes': len(ledger_raw)}
    return ledger_reference, references, payloads, len(files)


def validate_client_failure(scenario):
    target_client = scenario.get('clients', {}).get('target', {})
    if (target_client.get('raw_http_status') != 200
            or target_client.get('independent_raw_response', {}).get('framing_complete') is not False
            or target_client.get('independent_raw_response', {}).get('entity_bytes') is not None
            or target_client.get('process_exit') != 1
            or scenario.get('command_exit_codes', {}).get('selected-target-client') != 1):
        raise ValueError('base review must retain the selected client framing failure')


def validated_proxy_binary(scenario, fixture_references, fixture_payloads):
    proof = json.loads(fixture_payloads['fault-proxy-build.json'])
    if proof.get('schema') != 'i12.envoy.fault-proxy-build.v1':
        raise ValueError('sealed proxy build receipt required')
    expected_binary = proof.get('binary', {})
    sealed_binary = fixture_references['fault-proxy']
    if any(sealed_binary.get(key) != expected_binary.get(key) for key in ('sha256', 'bytes')):
        raise ValueError('sealed proxy binary differs from its build receipt')
    loaded = all(scenario.get('loaded_images', {}).get(name, {}).get('fault-proxy', {}).get(
        'executable_sha256') == sealed_binary['sha256']
        for name in ('before-request', 'after-target', 'after-neighbor'))
    if not loaded:
        raise ValueError('loaded proxy image differs from sealed build')
    return sealed_binary


def validated_fixture_response(scenario, fixture_references, fixture_file_count, shape, contract):
    sealed = scenario.get('sealed_inputs', {}).get('/mnt/fixtures', {})
    if (scenario.get('fixture_shape_sha256') != fixture_references[SHAPE]['sha256']
            or sealed.get('ledger_hash_verified') is not True
            or sealed.get('all_file_hashes_verified') is not True
            or sealed.get('file_count') != fixture_file_count
            or sealed.get('mismatched_paths') != []):
        raise ValueError('base review fixture integrity differs from current sealed ledger')
    if (scenario['route'] != 'envoy-ext-proc' or shape.get('test_fault') != 'drop-response-eos'
            or contract.get('host_lifecycle_qualified') is not False
            or contract.get('envoy_received_terminal_status') is not None
            or contract.get('engine_terminal_expected', {}).get('grpc_status') != 14):
        raise ValueError('selected Response-EOS fault identity and source contract required')
    expected_hex = shape.get('response_hex')
    if not isinstance(expected_hex, str) or re.fullmatch(r'[\da-f]+', expected_hex, re.ASCII) is None:
        raise ValueError('sealed expected response payload identity required')
    expected = bytes.fromhex(expected_hex)
    if len(expected) != shape.get('response_bytes'):
        raise ValueError('sealed expected response length changed')
    return expected


def enrich(document):
    if document.get('host_lifecycle_qualified') is not False or len(document.get('scenarios', [])) != 1:
        raise ValueError('one unqualified physical fault review required')
    scenario = document['scenarios'][0]
    proxy_path, proxy_reference = verified_artifact(scenario, 'runtime/proxy-events.jsonl')
    envoy_path, envoy_reference = verified_artifact(scenario, 'envoy.stderr')
    response_path, response_reference = verified_artifact(scenario, 'client/target.response.raw')
    rows = [json.loads(line) for line in E.read_bytes(proxy_path, max_bytes=32 * 1024 * 1024).splitlines()]
    attempt = Path(scenario['attempt'])
    if scenario.get('scenario') != 'ext-proc-drop-response-eos':
        raise ValueError('selected fault scenario label required')
    spec_path = attempt.parents[1] / 'host-fixtures' / (scenario['scenario'] + '-admission.json')
    spec = E.read_json(spec_path)
    spec_reference = E.reference(spec_path)
    controller_path = attempt / 'controller-result.json'
    controller = E.read_json(controller_path)
    before = controller.get('executed_input_hashes_before', {})
    after = controller.get('executed_input_hashes_after', {})
    if (controller.get('spec_sha256') != spec_reference['sha256']
            or before.get(str(spec_path)) != spec_reference['sha256']
            or after.get(str(spec_path)) != spec_reference['sha256']):
        raise ValueError('executed admission differs from sealed fault fixture binding')
    fixtures = [item for item in spec['bindings'] if item['target'] == '/mnt/fixtures']
    if len(fixtures) != 1:
        raise ValueError('one sealed fault fixture binding required')
    fixture_ledger, fixture_references, fixture_payloads, fixture_file_count = sealed_fixture_files(
        fixtures[0], (SHAPE, FAULT_CONTRACT, 'fault-proxy-build.json', 'fault-proxy'))
    shape = json.loads(fixture_payloads[SHAPE])
    contract = json.loads(fixture_payloads[FAULT_CONTRACT])
    expected = validated_fixture_response(scenario, fixture_references, fixture_file_count, shape, contract)
    projection = proxy_projection(rows, shape)
    projection['physical_proxy_trace'] = proxy_reference
    projection['executed_admission'] = spec_reference
    projection['physical_controller_result'] = E.reference(controller_path)
    projection['sealed_fixture_ledger'] = fixture_ledger
    projection['envoy_received_status'] = envoy_status_projection(
        E.read_bytes(envoy_path, max_bytes=32 * 1024 * 1024), shape['target'])
    projection['physical_envoy_trace'] = envoy_reference
    projection['target_client_incomplete_response'] = fault_client_projection(
        E.read_bytes(response_path, max_bytes=65536), expected)
    projection['target_client_incomplete_response']['physical_raw_response'] = response_reference
    validate_client_failure(scenario)
    projection['source_contract'] = fixture_references[FAULT_CONTRACT]
    sealed_binary = validated_proxy_binary(scenario, fixture_references, fixture_payloads)
    projection['loaded_proxy_matches_sealed_build'] = True
    projection['sealed_proxy_binary'] = sealed_binary
    scenario['fault_proxy'] = projection
    return document


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--review', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    value = enrich(E.read_json(args.review))
    import modsecurity_connector_ci.runtime.lifecycle.i12.envoy.qualify_originals as qualify_originals
    qualify_originals.write(args.output, value)
    print(json.dumps({'output': str(args.output), 'new_lifecycle_pass': 0}))


if __name__ == '__main__':
    main()
