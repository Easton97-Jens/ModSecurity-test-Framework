"""Build a complete *candidate* observation packet; Root owns verdict/oracle."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

from connector_suite.adapters.traefik.harness.i12.native.review import records

EVENTS_FILE = 'events.jsonl'


def read(path):
    return json.loads(path.read_text())


def reference(path, role):
    raw = path.read_bytes()
    return {'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw), 'role': role}


def packet(attempt, label, case_id):
    data = attempt / 'data'
    tx = 'tf-' + label
    logs = data / 'runtime/logs'
    native = records(logs / 'native-lifecycle.jsonl')
    direct = [row for row in native if row.get('transaction_id') == tx]
    scopes = {row['allocation_scope_call'] for row in direct if row.get('allocation_join_verified')}
    events = [row for row in native if row.get('transaction_id') == tx or
              (row.get('allocation_join_verified') and row.get('allocation_scope_call') in scopes)]
    host = [row for row in records(logs / 'host-lifecycle.jsonl') if row.get('transaction_id') == tx]
    returns = [row for row in events if row['edge'] == 'return']
    counts = Counter(row['function'] for row in returns)
    client_path = data / f'client/{label}.receipt.json'
    client = read(client_path)
    command = data / f'client-{label}.command.json'
    backend_path = data / 'backend/receipts.jsonl'
    backend = [row for row in records(backend_path) if row['request_id'] == tx]
    before = read(data / 'before-target.json')
    after = read(data / f'after-{label}.json')
    neighbor = read(data / 'after-neighbor.json')
    controller = read(attempt / 'controller-result.json')
    admission_paths = [Path(path) for path, digest in controller['executed_input_hashes_before'].items()
                       if digest == controller['spec_sha256']]
    if len(admission_paths) != 1:
        raise ValueError('exact controller spec binding unavailable')
    admission = read(admission_paths[0])
    source = Path(next(binding['source'] for binding in admission['bindings'] if binding['target'] == '/mnt/src'))
    driver = read(data / 'result.json')
    build = read(data / 'build-manifest.json')
    n = reference(logs / 'native-lifecycle.jsonl', 'native_api')
    h = reference(logs / 'host-lifecycle.jsonl', 'host_callback')
    c = reference(client_path, 'client_process')
    b = reference(backend_path, 'backend_process')
    isolate = reference(attempt / 'controller-result.json', 'isolation_receipt')
    cleanup = reference(data / 'result.json', 'cleanup_observer')
    debug = reference(logs / 'native-debug.log', 'native_debug')
    audit = reference(logs / 'native-audit.log', 'physical_event_sink')
    sink = reference(logs / EVENTS_FILE, 'physical_event_sink')
    config = data / 'runtime/effective-config/traefik-native-engine.conf'
    raw_response = (data / f'client/{label}.response.raw').read_bytes()
    headers = raw_response.split(b'\r\n\r\n', 1)[0].decode('latin1').split('\r\n')
    observations = {}

    def observed(name, value, *refs):
        observations[name] = {'applicable': True, 'value': value, 'evidence': list(refs)}

    observed('product_host_identity', {'loaded_images': before, 'after': after,
             'actual_host_version_output': (data / 'host-version.stdout').read_text(),
             'sdk_who': (data / 'sdk-who.stdout').read_text()}, reference(data / 'before-target.json', 'loaded_image'), isolate)
    observed('source_config_binding', {'build': build, 'current_product_binding': read(data / 'current-product-binding.json'),
             'actual_admission': admission,
             'host_observer_scope_binding': read(source / 'i12-host-scope-binding.json') if (source / 'i12-host-scope-binding.json').exists() else None,
             'controller_spec_sha256': controller['spec_sha256']}, reference(data / 'build-manifest.json', 'source_manifest'),
             reference(data / 'current-product-binding.json', 'source_manifest'), reference(config, 'effective_configuration'))
    observed('capability', {'observed_host_rows': host, 'selected_route': 'traefik-native-uds'}, h,
             reference(source / 'connectors/traefik/native_middleware/middleware.go', 'source_contract'))
    observed('client_exit', read(command)['exit_code'], reference(command, 'client_process'))
    observed('client_signal', {'waited_exit_code': read(command)['exit_code'], 'normal_exit': read(command)['exit_code'] == 0}, reference(command, 'client_process'))
    observed('client_headers', headers, c, reference(data / f'client/{label}.response.raw', 'client_process'))
    observed('client_bytes', client.get('body_bytes'), c)
    observed('client_sha256', client.get('body_sha256'), c)
    observed('backend_request_count', len(backend), b)
    observed('backend_payload_identity', {'actual_backend': backend, 'client': client}, b, c)
    observed('client_backend_correlation', {'transaction_id': tx, 'actual_backend': backend, 'client': client}, b, c)
    observed('native_events', {'physical_common_events': [row for row in records(logs / EVENTS_FILE) if row.get('transaction_id') == tx],
             'audit_transaction_lines': [line for line in (logs / 'native-audit.log').read_text().splitlines() if tx in line]}, audit, sink)
    observed('native_api_returns', returns, n)
    observed('native_transaction_id', [row for row in direct if row.get('transaction_id_origin') == 'sdk_public_m_id'], n)
    observed('common_transaction_id', [row for row in direct if row.get('canonical_transaction_id')], n)
    observed('observed_handle_association', {'verified_allocation_scopes': sorted(scopes), 'direct_native_rows': direct}, n)
    observed('native_phases', {name: counts[name] for name in ('native_process_request_headers', 'native_process_request_body',
             'native_process_response_headers', 'native_process_response_body', 'native_process_logging')}, n, debug)
    observed('native_body_chunks', [row for row in returns if row['function'] in ('native_append_request_body', 'native_append_response_body')], n)
    observed('native_intervention_or_first_cause', {'returns': [row for row in returns if row['function'] == 'native_intervention'],
             'output_semantics': 'A false SDK intervention return does not initialize status/disruptive output; original null outputs retained.'}, n)
    observed('host_eos', [row for row in host if row.get('fields', {}).get('end_argument') or row.get('fields', {}).get('opcode') in (3, 6)], h)
    observed('native_eos', {'runtime_handoffs': [row for row in returns if row['function'] in ('runtime_finish_request_body', 'runtime_finish_response_body')],
             'native_finalizations': [row for row in returns if row['function'] in ('native_process_request_body', 'native_process_response_body')],
             'transport_eof_is_native_eos': False}, n, h)
    observed('commit_order', {'actual_host_writes': [row for row in host if row['operation'].startswith('writer_')],
             'actual_native_committed_updates': [row for row in events if row['function'] == 'common_set_response_committed'],
             'client_clocks': client}, h, c)
    observed('mime_gate', {'original_native_mime_selection': None, 'physical_debug_transaction_lines':
             [line for line in (logs / 'native-debug.log').read_text().splitlines() if tx in line]}, debug, audit)
    observed('finish_calls', {'actual_runtime_finish': counts['runtime_finish'], 'actual_common_finish': counts['common_finish'],
             'actual_native_logging': counts['native_process_logging'], 'common_idempotent_calls_not_new_transitions': True}, n)
    observed('finish_transitions', [row for row in events if row['function'] in ('common_complete_phase', 'common_finish')], n)
    observed('native_free_calls', counts['native_cleanup'], n)
    observed('cleanup_receipts', {'driver': driver, 'final_native': [row for row in native if row['function'] == 'observer' and row['edge'] == 'final']}, cleanup, isolate)
    observed('descriptor_cleanup', {'before': before, 'after_case': after, 'after_neighbor': neighbor}, reference(data / 'after-neighbor.json', 'cleanup_observer'))
    observed('process_listener_cleanup', {'driver': driver, 'survivors': controller['surviving_namespace_pids'],
             'outside_mount_leaks': controller['outside_mount_leaks']}, cleanup, isolate)
    observed('neighbor_health', {'client': read(data / 'client/neighbor.receipt.json'),
             'backend': [row for row in records(backend_path) if row['request_id'] == 'tf-neighbor']},
             reference(data / 'client/neighbor.receipt.json', 'client_process'), b)
    observed('transport_framing', {'headers': headers, 'client': client}, c)
    observed('transport_reset_scope', {'actual_client': client, 'actual_host_errors': [row for row in host if row.get('fields', {}).get('error')]}, c, h)
    observed('host_action', {'writer_rows': [row for row in host if row['operation'].startswith('writer_')], 'actual_status': client.get('status')}, h, c)
    observed('physical_event_order', [row for row in records(logs / EVENTS_FILE) if row.get('transaction_id') == tx], sink, audit)
    observed('terminal_event_count', sum(row.get('transaction_id') == tx for row in records(logs / EVENTS_FILE)), sink)
    # Null observations remain explicitly incomplete rather than fabricated.
    for field, value in observations.items():
        if value['value'] is None:
            value['reason'] = 'The selected physical client did not complete this measurement.'
    if not host:
        for field in ('capability', 'host_eos', 'commit_order', 'host_action'):
            observations[field] = {'applicable': True, 'value': None,
                                   'reason': 'No actual host observer callbacks admitted this transaction ID; source-bound observer retake required.'}
    return {'run_scoped_case_id': 'I12::traefik-native-uds::' + case_id, 'leg_id': 'traefik-native-uds',
            'reviewed_by': 'pending_root', 'execution_observed': True, 'execution_kind': 'host_http',
            'run_id': native[0]['run'], 'parent_sha': build['delivery_base'], 'framework_sha': '99a7985c1be92a2297b1b59208f64df6768f2cbf',
            'framework_scope': 'read-only catalog; not executed', 'mrts_sha': '8a6bb546c4c81d8ffc7be801dceac60c6925685f', 'mrts_scope': 'read-only; not executed',
            'effective_config_sha256': hashlib.sha256(config.read_bytes()).hexdigest(),
            'observations': observations, 'oracle_evaluated': False, 'oracle_sha256': None,
            'outcome': None, 'full_lifecycle_qualified': False,
            'scope': 'Fresh original measurements. Case mapping and independently sourced oracle require Root review.'}


if __name__ == '__main__':
    print(json.dumps(packet(Path(sys.argv[1]), sys.argv[2], sys.argv[3]), indent=2))
