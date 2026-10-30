"""Prepare the existing 35 observations from physical files, pending Root review.

This module makes no verdict, oracle correction, absence approval or lifecycle
qualification. Missing measurements remain null. Allocation scopes are selected
by the actual target client's measured monotonic window, never by a guessed ID.
"""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import argparse
from collections import Counter
import importlib.util
import json
import hashlib
from pathlib import Path

# Load the maintained Parent filesystem boundary from this checkout.
import sys as _i12_sys

import modsecurity_connector_ci.lib.i12_path_safety as i12_paths


TARGET_CLIENT = 'client-target.json'
RESULT_RECEIPT = 'result.json'
BEFORE_TARGET = 'before-target.json'
AFTER_NEIGHBOR = 'after-neighbor.json'
NEIGHBOR_CLIENT = 'client-neighbor.json'
PARSER_COMMAND = 'check-config.command.json'
PARSER_STDOUT = 'check-config.stdout'
PARSER_STDERR = 'check-config.stderr'
ENGINE_POINTER = '/processes/engine'

def load(path, _name):
    value = load_source(path)
    return value


REVIEW = load(Path(__file__).with_name('acceptance_review.py'), 'auth_acceptance_physical_review')
LEDGER = load(connector_root() /
    'ci/evidence/reports/generate-pr382-i12-lifecycle-ledger.py', 'auth_acceptance_central_ledger')
FIELD_NAMES = (
    'product_host_identity', 'source_config_binding', 'capability', 'client_exit',
    'client_signal', 'client_headers', 'client_bytes', 'client_sha256',
    'backend_request_count', 'backend_payload_identity', 'client_backend_correlation',
    'native_events', 'native_api_returns', 'native_transaction_id', 'common_transaction_id',
    'observed_handle_association', 'native_phases', 'native_body_chunks',
    'native_intervention_or_first_cause', 'host_eos', 'native_eos', 'commit_order',
    'mime_gate', 'finish_calls', 'finish_transitions', 'native_free_calls',
    'cleanup_receipts', 'descriptor_cleanup', 'process_listener_cleanup', 'neighbor_health',
    'transport_framing', 'transport_reset_scope', 'host_action', 'physical_event_order',
    'terminal_event_count',
)
PROVENANCE_FIELDS = ('run_id','integration_mode','transaction_id','rule_id','phase','event','message_id',
    'requested_action','actual_action','transport_result','transport_case_id','connection_id',
    'connection_reused','eos_seen','cleanup_reason')


def provenance_events(events):
    return {'actual_events': events, 'provenance_fields': list(PROVENANCE_FIELDS),
        'missing_fields_by_event': [[key for key in PROVENANCE_FIELDS if key not in row] for row in events],
        'missing_fields_are_not_synthesized': True}


def reference(path, role):
    return dict(REVIEW.reference(path), role=role) if path.is_file() else None


def observation(value, *proofs):
    evidence = [proof for proof in proofs if proof is not None]
    if value is None or not evidence:
        return {'value': None, 'applicable': True, 'evidence': evidence,
                'reason': 'The retained physical files do not establish this observation.'}
    return {'value': value, 'applicable': True, 'evidence': evidence}


def scoped_observation(field, value, *proofs):
    evidence = [proof for proof in proofs if proof is not None and proof.get('role') in LEDGER.ROLES[field]]
    result = observation(value, *evidence)
    missing = LEDGER.REQUIRED_ROLES.get(field, set()) - {proof['role'] for proof in evidence}
    if missing:
        result.update(value=None, reason='Missing independent physical producer roles: ' + ', '.join(sorted(missing)))
    return result


def target_scopes(measured, client):
    if client is None:
        return []
    start = client.get('started_ns') if client.get('schema') == 'traefik-file-http-client-v1' else client.get('monotonic_ns')
    end = client.get('completed_ns')
    if not isinstance(start, int) or not isinstance(end, int):
        return []
    return [scope for scope in measured['native_scopes']
            if start <= scope['native_allocation']['monotonic_ns'] <= end]


validate_attempt_binding = load(Path(__file__).with_name("acceptance_binding.py"),
    "auth_acceptance_binding").validate_attempt_binding


def client_observations(put, command, command_path, framing, wire):
    for field, key in (('client_exit', 'exit_code'), ('client_signal', 'signal')):
        if command is not None:
            value = command.get(key)
            # A waited, normal process exit proves signal zero, not an unknown signal.
            if field == 'client_signal' and value is None and isinstance(command.get('exit_code'),int) and command['exit_code'] >= 0:
                value = 0
            put(field, value, reference(command_path, 'client_process'))
    if framing is not None:
        for field, key in (('client_headers', 'headers'), ('client_bytes', 'entity_bytes'), ('client_sha256', 'entity_sha256')):
            put(field, framing.get(key), wire)
        put('transport_framing', framing, wire)


def backend_observations(put, values, measured, context):
    physical = context['physical']
    file_execution = context['file_execution']
    probes = context['probes']
    client = context['client']
    framing = context['framing']
    cp = context['cp']
    bp = context['bp']
    backend = measured['backend']
    if file_execution and physical.get('backend') is not None:
        physical_backend = physical['backend']
        file_bp = reference(Path(physical['paths']['backend']), 'backend_process')
        request_bp = reference(Path(physical['paths']['backend_request']), 'backend_process')
        put('backend_request_count', physical_backend['independent_backend_accept_count'], file_bp, request_bp)
        put('backend_payload_identity', {'physical_file_backend': physical_backend,
            'actual_client': client, 'actual_target_response_framing': framing}, file_bp, request_bp, cp)
        put('client_backend_correlation', {'probe': measured['probe_id'], 'actual_client': client,
            'physical_file_backend': physical_backend, 'physical_backend_accept': physical['backend_accept'],
            'physical_backend_listen': physical['backend_listen'],
            'physical_backend_driver_binding': physical['backend_driver_binding'],
            'legacy_backend_rows_are_not_relabelled': True}, file_bp, request_bp, cp)
    elif backend is not None:
        target = [row for row in backend if row.get('probe') in probes]
        parsed = [row for row in target if row.get('event') == 'parsed_headers' and row.get('parse_success') is True]
        put('backend_request_count', len(parsed), bp)
        put('backend_payload_identity', {'actual_backend_rows': target, 'actual_client': client,
            'all_actual_target_response_framing':{name:result for name,result in measured['clients'].items() if name.startswith('target-')}}, bp, cp)
        put('client_backend_correlation', {'probe': measured['probe_id'], 'actual_backend_rows': target}, bp, cp)
        if values['client_backend_correlation']['value'] is not None:
            values['client_backend_correlation']['value'].update(
            actual_client_socket_receipts=client,
            actual_backend_private_header_receipts=[row.get('private_headers') for row in parsed],
            same_connection_is_not_inferred_from_connection_reused_false=True)


def native_observations(put, values, measured, context):
    native_present = context['native_present']
    scopes = context['scopes']
    calls = context['calls']
    counts = context['counts']
    returns = context['returns']
    events = context['events']
    nr = context['nr']
    debug = context['debug']
    hr = context['hr']
    sink = context['sink']
    root = context['root']
    if native_present:
        scope_keys={(scope['native_allocation'].get('pid'),scope['allocation_scope_call']) for scope in scopes}
        retained=None if measured['fault_operations'] is None else [row for row in measured['fault_operations']
            if row.get('operation')=='native_retained_body' and (row.get('pid'),row.get('allocation_scope_call')) in scope_keys]
        put('native_events', events, sink)
        if values['native_events']['value'] is not None:
            values['native_events']['value'] = provenance_events(events)
        put('native_api_returns', {'returns': returns, 'counts': dict(counts),
            'actual_retained_body_accessors':retained,'retained_length_is_not_inspection_length':True}, nr,
            reference(root/'faults.jsonl','native_api'))
        put('native_transaction_id', [scope['native_allocation'] for scope in scopes], nr)
        put('common_transaction_id', [row for row in calls if row.get('function') == 'common_init'], nr)
        put('observed_handle_association', {'allocations': [scope['native_allocation'] for scope in scopes],
            'actual_typed_calls': [row for row in calls if 'companion' in row.get('function', '')]}, nr)
        put('native_phases', [row for row in calls if row.get('function', '').startswith('native_process_')], nr, debug)
        put('native_body_chunks', [row for row in calls if 'append_' in row.get('function', '')], nr)
        put('native_intervention_or_first_cause', {'calls': [row for row in calls if row.get('function') == 'native_intervention'],
            'events': events, 'fault_operations': measured['fault_operations']}, nr)
        put('native_eos', {'actual_request_eos_calls': counts.get('native_process_request_body', 0),
            'actual_response_eos_calls': counts.get('native_process_response_body', 0), 'tcp_eof_is_not_native_eos': True}, nr, hr)
        put('finish_calls', {'native_logging': counts.get('native_process_logging', 0),
            'common_finish': counts.get('common_finish', 0), 'runtime_finish_is_separate': True}, nr)
        put('finish_transitions', [row for row in calls if row.get('contract_state') is not None], nr)
        put('native_free_calls', counts.get('native_cleanup', 0), nr)
        put('terminal_event_count', {'common_events': len(events) if events is not None else None,
            'native_logging': counts.get('native_process_logging', 0), 'native_cleanup': counts.get('native_cleanup', 0)}, sink)


def client_execution(root, measured, physical):
    file_execution = bool(physical and not physical.get('configuration_only'))
    client_path = Path(physical['paths']['client']) if file_execution else root / TARGET_CLIENT
    response_path = Path(physical['paths']['response']) if file_execution else root / 'target-0.response.raw'
    command_path = Path(physical['paths']['client_command']) if file_execution else root / 'client-target.command.json'
    client = physical['client'] if file_execution else REVIEW.read(client_path)
    probes={row.get('wire_probe') for row in client.get('requests',[]) if row.get('wire_probe')} if client else set()
    if not probes:probes={measured['probe_id']}
    return (file_execution, client_path, response_path, command_path, client, probes)


def target_native_execution(measured, client, logs, probes):
    scopes = target_scopes(measured, client)
    calls = [row for scope in scopes for row in scope['native_calls']]
    returns = [row for row in calls if row.get('edge') == 'return']
    counts = Counter(row['function'] for row in returns)
    ids = {scope['native_id'] for scope in scopes if scope['native_id'] is not None}
    common = REVIEW.rows(logs / 'events.jsonl')
    events = None if common is None else [row for row in common if row.get('transaction_id') in ids]
    host_rows = REVIEW.rows(logs / 'host-lifecycle.jsonl')
    host_rows = None if host_rows is None else [row for row in host_rows if row.get('transaction_id') in probes]
    return (scopes, calls, returns, counts, events, host_rows)


def observations(root, attempt, prepared, measured):
    logs = root / 'runtime/logs'
    values = {name: observation(None) for name in FIELD_NAMES}
    physical = measured.get('physical_file_supplement')
    if physical and not physical['binding_valid']:
        for value in values.values():
            value['reason'] = 'Physical file receipt binding refused: ' + '; '.join(physical['errors'])
        return values
    (file_execution, client_path, response_path, command_path, client, probes) = client_execution(root, measured, physical)
    (scopes, calls, returns, counts, events, host_rows) = target_native_execution(measured, client, logs, probes)
    nr = reference(logs / 'native-lifecycle.jsonl', 'native_api')
    hr = reference(logs / 'host-lifecycle.jsonl', 'host_callback')
    sink = reference(logs / 'events.jsonl', 'physical_event_sink')
    debug = reference(logs / 'debug.log', 'native_debug')
    wire = reference(response_path, 'client_process')
    cp = reference(client_path, 'client_process')
    bp = reference(root / 'backend.jsonl', 'backend_process')
    cleanup = reference(root / RESULT_RECEIPT, 'cleanup_observer')
    isolation = reference(attempt / 'controller-result.json', 'isolation_receipt')
    framing = measured['clients'].get(str(response_path.relative_to(root)))
    command = physical['command'] if file_execution else REVIEW.read(command_path)
    snapshot = REVIEW.read(root / BEFORE_TARGET)
    source = REVIEW.read(prepared / 'source/.i12-source-export-manifest.json')
    config = root / 'runtime/effective-config/traefik-forwardauth.conf'
    native_present = bool(scopes) and all(scope['allocation_scope_call'] is not None for scope in scopes)

    context = {
        'physical': physical,
        'file_execution': file_execution,
        'probes': probes,
        'client': client,
        'framing': framing,
        'root': root,
        'cp': cp,
        'bp': bp,
        'native_present': native_present,
        'scopes': scopes,
        'calls': calls,
        'counts': counts,
        'returns': returns,
        'events': events,
        'nr': nr,
        'debug': debug,
        'hr': hr,
        'sink': sink,
    }

    def put(name, value, *proofs):
        values[name] = scoped_observation(name, value, *proofs)

    put('product_host_identity', None if snapshot is None else snapshot['processes'],
        reference(root / BEFORE_TARGET, 'loaded_image'), isolation)
    put('source_config_binding', measured['producer'].get('configuration_sha256') if measured['producer'] else None,
        reference(attempt / 'data/acceptance-build.json', 'source_manifest'),
        reference(config, 'effective_configuration'))
    put('capability', {'route': measured['fixture']['route'], 'source_revision': source.get('source_revision') if source else None},
        reference(prepared / 'source/connectors/profile_registry.c', 'source_contract'), hr)
    if file_execution and values['capability']['value'] is not None:
        values['capability']['value'].update(physical_file_supplement=physical,
            file_source_is_not_native_file_api=True, tcp_eof_is_not_native_eos=True)
    client_observations(put, command, command_path, framing, wire)
    backend_observations(put, values, measured, context)
    native_observations(put, values, measured, context)
    put('host_eos', {'actual_host_rows': host_rows, 'actual_native_host_eos_rows': [row for row in calls
        if row.get('function') == 'authorization_request_eos']}, hr)
    put('commit_order', {'actual_host_rows': host_rows, 'actual_client_receipt': client}, hr, cp)
    put('transport_reset_scope', {'actual_client_receipt': client, 'actual_host_rows': host_rows,
        'eof_is_not_reset': True}, cp, hr)
    put('host_action', {'actual_host_rows': host_rows, 'actual_client_framing': framing}, hr, cp)
    put('physical_event_order', events, sink)
    put('cleanup_receipts', {'driver': measured['producer'], 'observer_final': measured['observer_final'],
        'actual_provenance_socket_before': measured['producer'].get('provenance_socket_before') if measured['producer'] else None,
        'actual_provenance_socket_cleanup': measured['producer'].get('provenance_socket_cleanup') if measured['producer'] else None}, cleanup, isolation)
    put('descriptor_cleanup', {'before': snapshot, 'after_target': REVIEW.read(root / 'after-target.json'),
        'after_neighbor': REVIEW.read(root / AFTER_NEIGHBOR)},
        reference(root / BEFORE_TARGET, 'cleanup_observer'), reference(root / AFTER_NEIGHBOR, 'cleanup_observer'))
    put('process_listener_cleanup', measured['producer'], cleanup, isolation)
    put('neighbor_health', {'before': REVIEW.read(root / 'client-before-neighbor.json'),
        'after': REVIEW.read(root / NEIGHBOR_CLIENT), 'actual_backend_rows': measured['backend']},
        reference(root / NEIGHBOR_CLIENT, 'client_process'), bp)
    # Debug bytes are retained as evidence; a MIME verdict requires an explicit
    # source-bound Root decision, not a nonempty log or a delivered-byte counter.
    values['mime_gate'] = observation(None, debug, sink, nr)
    return values


def populate_preallocation(packet, root, preallocation):
    if preallocation:
        def selector(name, role, pointer=''):
            proof = reference(root / name, role)
            return {'reference': proof, 'pointer': pointer} if proof else None
        packet['preallocation_measurements'] = {
            'target_window': selector(TARGET_CLIENT, 'client_process'),
            'before_control': selector('client-before-neighbor.json', 'client_process'),
            'after_control': selector(NEIGHBOR_CLIENT, 'client_process'),
            'target_identity': selector(BEFORE_TARGET, 'loaded_image', ENGINE_POINTER),
            'before_identity': selector('before-target-healthy.json', 'loaded_image', ENGINE_POINTER),
            'after_identity': selector(AFTER_NEIGHBOR, 'loaded_image', ENGINE_POINTER),
            'cleanup': selector(RESULT_RECEIPT, 'cleanup_observer'), 'fault': None,
            'observer_log': reference(root / 'runtime/logs/native-lifecycle.jsonl', 'native_api'),
            'backend_log': reference(root / 'backend.jsonl', 'backend_process'),
            'client_request': reference(root / 'target-0.request.raw', 'client_process'),
            'client_response': reference(root / 'target-0.response.raw', 'client_process')}
        packet['missing_preallocation_approval'] = 'Root must approve actual null-allocation contract/first cause and bind observed image/cleanup fields; this draft makes no absence verdict.'


def parser_observations(command, child, direct, root, measured):
    command_values = command or {}
    child_values = child or {}
    return {'parser_process': {
        'argv': command_values.get('argv'),
        'cwd': child_values.get('cwd'), 'waited_exit': command_values.get('exit_code'),
        'waited_signal': command_values.get('signal'),
        'stdout': (root / PARSER_STDOUT).read_text() if (root / PARSER_STDOUT).is_file() else None,
        'stderr': (root / PARSER_STDERR).read_text() if (root / PARSER_STDERR).is_file() else None,
        'executable_sha256': command.get('executable',{}).get('sha256') if direct else None,
        'pid': command.get('pid') if direct else None,
        'first_cause': command.get('first_cause') if direct else None,
        'physical_process_receipt': command if direct else None},
        'invocation_identity': child,
        'source_config_binding': {'files_before':command['files_before'],'files_after':command['files_after']} if direct else None,
        'cleanup': measured['producer']}


def populate_configuration(packet, root, attempt, config, measured, spec):
    if spec['classification'] == 'config':
        command = REVIEW.read(root / PARSER_COMMAND)
        direct = command is not None and command.get('schema') == 'traefik-auth-parser-process-v1'
        child = next((row for row in command.get('child_receipts', [])
            if row.get('stage') == 'child_pre_exec' and row.get('pid') == command.get('pid')), None) if direct else None
        packet['measurement_evidence'] = [proof for proof in (
            reference(root / PARSER_COMMAND, 'parser_process'),
            reference(root / PARSER_STDOUT, 'parser_stdout'),
            reference(root / PARSER_STDERR, 'parser_stderr'),
            reference(config, 'effective_configuration'),
            reference(root / 'rules.conf', 'rules_file'),
            reference(attempt / 'data/acceptance-build.json', 'source_manifest'),
            reference(root / RESULT_RECEIPT, 'cleanup_observer'),
            reference(attempt / 'controller-result.json', 'isolation_receipt')) if proof is not None]
        packet['actual_observations'] = parser_observations(command, child, direct, root, measured)
        packet['missing_parser_measurements'] = ['Independent source-bound parser diagnostic/first-cause approval']
        if not child or not command.get('executable',{}).get('sha256'):
            packet['missing_parser_measurements'].append('Direct parser cwd/executable identity and full run-bound physical process receipt')
        if not direct:
            packet['missing_parser_measurements'].append('Physical attempted rules-path absence when testing missing rules')


def execution_kind(spec, preallocation):
    if spec['classification'] == 'config':
        return 'configuration_parser'
    return 'host_preallocation_control' if preallocation else 'host_http'


def identity_evidence(identities, source_identities):
    if source_identities is None:
        if identities is not None:
            raise ValueError('retained source identity receipt required')
        return None
    if not isinstance(identities, dict) or REVIEW.read(source_identities) != identities:
        raise ValueError('retained source identity receipt differs')
    return reference(source_identities, 'source_manifest')


def draft_packet(root, attempt, prepared, source, identities, binding, source_identities=None):
    measured = REVIEW.review_case(root, prepared)
    if 'fixture' not in measured:
        return None
    spec = measured['fixture']
    preallocation = spec['classification'] in ('parser', 'adapter-fault') or spec['case_id'] in (
        'early_mapping_failure_cleanup', 'transaction_begin_failure_cleanup')
    native = REVIEW.rows(root / 'runtime/logs/native-lifecycle.jsonl')
    runs = {row['run'] for row in native or [] if row.get('run') is not None}
    packet = {'run_scoped_case_id': spec['id'], 'leg_id': spec['route'],
        'probe_id': spec['probe_id'], 'control_name': spec.get('control_name'),
        'reviewed_by': 'pending_root',
        'execution_observed': (bool(measured.get('physical_file_supplement', {}).get('binding_valid'))
            if measured.get('physical_file_supplement') and spec['classification'] != 'config'
            else (root / TARGET_CLIENT).is_file()) or (
            spec['classification'] == 'config' and (root / PARSER_COMMAND).is_file()),
        'execution_kind': execution_kind(spec, preallocation),
        'run_id': next(iter(runs)) if len(runs) == 1 else None,
        'parent_sha': source['source_revision'],
        'prepared_attempt_binding':binding,
        'physical_file_supplement':measured.get('physical_file_supplement'),
        'framework_sha': source['gitlinks'].get('modules/ModSecurity-test-Framework'),
        'mrts_sha': identities['mrts_revision'] if identities else None, 'effective_config_sha256': None,
        'framework_mrts_source_identity': identity_evidence(identities, source_identities),
        'observations': observations(root, attempt, prepared, measured),
        'original_expected_oracle': spec['original_contract']['expected_oracle'],
        'oracle_evaluated': False, 'outcome': None, 'full_lifecycle_qualified': False,
        'configuration_measurements': None, 'preallocation_contract': None,
        'preallocation_measurements': None,
        'scope_note': 'Physical draft only; Root must bind independent oracle, missing identities, MIME and separate config/preallocation contracts.'}
    config = root / 'runtime/effective-config/traefik-forwardauth.conf'
    if config.is_file():
        packet['effective_config_sha256'] = REVIEW.reference(config)['sha256']
    populate_configuration(packet, root, attempt, config, measured, spec)
    populate_preallocation(packet, root, preallocation)
    return packet


def propose(attempt, prepared, output, source_identities=None):
    binding=validate_attempt_binding(attempt,prepared)
    output = i12_paths.new_directory(output)
    source = REVIEW.read(prepared / 'source/.i12-source-export-manifest.json')
    identities = REVIEW.read(source_identities) if source_identities else None
    framework = source['gitlinks'].get('modules/ModSecurity-test-Framework')
    if identities is not None and (identities.get('framework_revision') != framework or
            not identities.get('mrts_revision') or not identities.get('framework_gitlink_receipt')):
        raise ValueError('actual source-bound Framework gitlink receipt required')
    if identities is not None:
        gitlink = LEDGER.ORACLES.verify_reference(identities['framework_gitlink_receipt'])
        if Path(gitlink['path']).read_text() != '160000 commit ' + identities['mrts_revision'] + '\ttools/MRTS\n':
            raise ValueError('Framework source gitlink does not bind supplied MRTS identity')
    result = []
    for root in sorted((attempt / 'data/cases').iterdir()):
        if not root.is_dir():
            continue
        packet = draft_packet(root, attempt, prepared, source, identities, binding, source_identities)
        if packet is None:
            continue
        path = output / (packet['probe_id'] + '.json')
        with i12_paths.new_text(path) as stream:
            json.dump(packet, stream, indent=2)
            stream.write('\n')
        result.append(path)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('attempt', 'prepared', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--source-identities', type=Path)
    args = parser.parse_args()
    paths = propose(args.attempt, args.prepared, args.output, args.source_identities)
    print(json.dumps({'packets': len(paths), 'reviewed_by': 'pending_root', 'qualification': None}))
