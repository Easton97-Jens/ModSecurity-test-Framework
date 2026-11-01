#!/usr/bin/env python3
"""Assemble actual Stock producer observations for the existing Root qualifier.

This producer never signs Root review and never changes the inherited ledger.
"""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import argparse
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
from types import SimpleNamespace
try:
    from modsecurity_connector_ci.runtime.lifecycle.i12.lighttpd.qualification import EXTERNAL_ROOT, storage_root
except ModuleNotFoundError:
    from modsecurity_connector_ci.runtime.lifecycle.i12.lighttpd.qualification import EXTERNAL_ROOT, storage_root

RUNTIME_CONFIG = 'runtime.conf'
TASK_PREFIX = '/task/'


REPO = connector_root()
EXTERNAL = EXTERNAL_ROOT


def input_file(path):
    path = Path(path).absolute()
    if path.is_relative_to(EXTERNAL):
        storage_root(EXTERNAL)
    roots = (EXTERNAL, REPO, Path('/usr/lib/x86_64-linux-gnu'))
    if '..' in path.parts or not any(path.is_relative_to(root) for root in roots):
        raise ValueError('measurement input outside declared capture/source/library roots')
    if any(part.is_symlink() for part in (*path.parents, path)):
        raise ValueError('measurement input alias forbidden')
    details = path.stat()
    if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
        raise ValueError('measurement requires a regular single-link file')
    return path


def external_path(path):
    storage_root(EXTERNAL)
    path = Path(path).absolute()
    if '..' in path.parts or not path.is_relative_to(EXTERNAL) or path.is_relative_to(EXTERNAL / 'worktrees'):
        raise ValueError('output must remain inside the external task root')
    if any(part.is_symlink() for part in (*path.parents, path)):
        raise ValueError('external path alias forbidden')
    return path


def read(path):
    return json.loads(input_file(path).read_text())


def lines(path):
    return [json.loads(line) for line in input_file(path).read_text().splitlines() if line]


def physical_events(path):
    values, failures = [], []
    for number, line in enumerate(input_file(path).read_bytes().splitlines(), 1):
        if not line:
            continue
        try:
            values.append(json.loads(line))
        except ValueError as error:
            failures.append({'physical_line': number, 'bytes': len(line), 'parse_error_type': type(error).__name__})
    return values, failures


def native_audit_for_id(path, transaction_id):
    selected = []
    for line in input_file(path).read_text().splitlines():
        if transaction_id is None:
            continue
        if '[unique_id "' + transaction_id + '"]' in line:
            selected.append(line)
            continue
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict) and value.get('transaction', {}).get('unique_id') == transaction_id:
            selected.append(line)
    return selected


def native_rule_observed(physical_lines, rule_id):
    for line in physical_lines:
        if '[id "' + str(rule_id) + '"]' in line:
            return True
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if not isinstance(value, dict):
            continue
        messages = value.get('transaction', {}).get('messages', [])
        if any(str(message.get('details', {}).get('ruleId')) == str(rule_id) for message in messages):
            return True
    return False


def sha(path):
    return hashlib.sha256(input_file(path).read_bytes()).hexdigest()


def reference(path, role=None, **metadata):
    value = {'path': str(path), 'sha256': sha(path), **metadata}
    if role:
        value['role'] = role
    return value


def central():
    path = REPO / 'ci/evidence/reports/generate-pr382-i12-lifecycle-ledger.py'
    module = load_source(path)
    return module


def selected_scope(api, before, after, require_join=True):
    candidates = {row['allocation_scope_call'] for row in api
                  if row['function'] == 'runtime_begin_request_stream' and row['edge'] == 'return'
                  and before <= row['monotonic_ns'] <= after
                  and (row.get('allocation_join_verified') is True or not require_join)}
    if len(candidates) != 1:
        raise ValueError('one typed main allocation must be observed independently of neighbors')
    return candidates.pop()


def failed_constructor_absence(returns, scope):
    constructors = [row for row in returns if row['function'] == 'runtime_begin_request_stream']
    if len(constructors) != 1:
        return None
    constructor = constructors[0]
    if (constructor['result'] != 0 or constructor.get('output_argument_present') is not True
            or constructor.get('actual_output_handle_present') is not False):
        return None
    return {'association_kind': 'failed_constructor_observed_absence',
        'actual_returned_handle': None, 'output_argument_present': True,
        'actual_output_handle_present': False, 'constructor_call': scope,
        'actual_constructor_return': 0, 'allocation_join_verified': constructor['allocation_join_verified'],
        'nested_actual_native_ids': sorted({row['transaction_id'] for row in returns
            if row.get('transaction_id_origin') == 'sdk_public_m_id' and row.get('transaction_id')}),
        'cleanup_before_return': [row for row in returns if row['function'] in ('native_cleanup', 'common_cleanup')
            and row['monotonic_ns'] < constructor['monotonic_ns']]}


def _mapped_physical_path(path, namespace_data):
    if path.startswith(TASK_PREFIX):
        return namespace_data / path[len(TASK_PREFIX):]
    if path.startswith(str(EXTERNAL) + '/'):
        return namespace_data / path[len(str(EXTERNAL)) + 1:]
    return Path(path)


def _retained_mapping(line):
    fields = line.split(maxsplit=5)
    if len(fields) != 6 or fields[4] == '0':
        return None
    if not any(token in fields[5] for token in ('/bin/lighttpd', 'lighttpd-stock-sidecar', 'libmodsecurity.so')):
        return None
    return fields


def mapped_images(snapshots, data, namespace_data=None):
    namespace_data = data if namespace_data is None else namespace_data
    found = []
    root = data / 'lighttpd/receipts/before-main'
    for actor in snapshots['processes']:
        for line in (root / (actor + '.maps')).read_text().splitlines():
            fields = _retained_mapping(line)
            if fields is None:
                continue
            path = fields[5]
            physical = _mapped_physical_path(path, namespace_data)
            if not physical.is_file() or physical.stat().st_ino != int(fields[4]):
                raise ValueError('mapped retained image inode identity mismatch: ' + path)
            item = {'actor': actor, 'mapped_path': path, 'physical_path': str(physical),
                    'physical_sha256': sha(physical), 'mapped_inode': int(fields[4]),
                    'physical_inode': physical.stat().st_ino, 'namespace_device': fields[3]}
            if item not in found:
                found.append(item)
    return found


def evaluate_sequence(fixture, data, api, audit_path, observations, checks):
    sequence = fixture.get('sequence_probe')
    if sequence is None:
        return
    label = 'sequence-deny' if sequence == 'allow-deny-allow' else 'sequence-second'
    client_path = data / 'client' / (label + '.receipt.json')
    process_path = data / 'lighttpd' / (label + '.actual-client-process.json')
    client = read(client_path)
    process = read(process_path)
    scope = selected_scope(api, client['started_ns'], client['completed_ns'])
    returns = [row for row in api if row['allocation_scope_call'] == scope and row['edge'] == 'return']
    ids = {row['transaction_id'] for row in returns
        if row.get('transaction_id_origin') == 'sdk_public_m_id' and row.get('transaction_id')}
    main = read(data / 'client/main.receipt.json')
    neighbor = read(data / 'client/neighbor.receipt.json')
    checks['actual_three_process_sequence_order'] = main['completed_ns'] < client['started_ns'] < client['completed_ns'] < neighbor['started_ns']
    checks['actual_sequence_client_status'] = process['actual_waited_return_code'] == 0 and client['status'] == (403 if sequence == 'allow-deny-allow' else 200)
    checks['actual_sequence_native_cleanup_once'] = sum(row['function'] == 'native_cleanup' for row in returns) == 1
    checks['actual_sequence_native_logging_once'] = sum(row['function'] == 'native_process_logging' for row in returns) == 1
    if sequence == 'allow-deny-allow':
        scoped_audit = [line for line in input_file(audit_path).read_text().splitlines()
            if any('[unique_id "' + value + '"]' in line for value in ids)]
        checks['original_rule_observed'] = any('[id "1100001"]' in line for line in scoped_audit)
    observations['finish_calls']['value']['additional_sequence_transaction'] = {
        'actual_scope': scope, 'actual_native_ids': sorted(ids), 'actual_native_returns': returns,
        'actual_client': client, 'actual_waited_process': process}
    observations['finish_calls']['evidence'] += [reference(client_path, 'client_process'), reference(process_path, 'client_process')]


def _evaluate_incomplete_backend(context):
    if context.fixture.get('backend_incomplete'):
        context.effective.update(native_result='upstream_disconnect_before_native_eos', phase=4, rule_id=None, native_response_finalization=0, client_exit=1)
        own_events = [row for row in context.events if row.get('transaction_id') in context.common_ids]
        context.checks['physical_first_cause_upstream_disconnect'] = bool(own_events) and own_events[0]['event'] == 'upstream_disconnect'
        context.checks['actual_framing_incomplete'] = context.client['framing']['complete'] is False and context.client['framing']['encoded_entity_bytes'] == len(bytes.fromhex(context.fixture['response_hex']))
        context.checks['peer_eof_not_native_eos'] = context.client['tcp_eof_observed'] is True and context.counts['native_process_response_body'] == 0
        if context.fixture['case_id'] == 'NEED-first-byte-before-late-error':
            close_boundaries = [row for row in context.backend_physical_rows if row.get('boundary') == 'response_handler_before_return' and row['path'] == context.fixture['path']]
            context.checks['first_entity_before_actual_backend_return'] = len(close_boundaries) == 1 and context.client.get('first_encoded_entity_recv_ns', float('inf')) < close_boundaries[0]['monotonic_ns']
            context.observations['commit_order']['value']['actual_backend_before_return'] = close_boundaries
            context.observations['commit_order']['evidence'] += context.backend_ev

def _evaluate_client_abort(context):
    if context.fixture.get('client_abort_mode'):
        context.effective.update(native_result='actual_client_cancel_after_response_started', phase=4, rule_id=None, native_response_finalization=0, client_abort_mode=context.fixture['client_abort_mode'], client_exit=context.fixture['expected_client_exit'])
        own_events = [row for row in context.events if row.get('transaction_id') in context.common_ids]
        context.checks['actual_local_abort_action'] = context.client.get('local_abort', {}).get('mode') == context.fixture['client_abort_mode'] and context.client['entity_bytes'] > 0 and (context.client['framing']['complete'] is False)
        context.checks['actual_client_cancel_first_cause'] = bool(own_events) and own_events[0]['event'] == 'client_cancel' and (own_events[0]['eos_seen'] is False)
        context.observations['transport_reset_scope']['value']['actual_local_abort'] = context.client.get('local_abort')
        context.observations['client_signal']['value']['rtk_proxy_wait_scope'] = 'Actual RTK-wrapped process wait;143 is retained as proxy exit, not OS waitpid signal15.'

def _evaluate_host_deadline(context):
    if context.fixture.get('backend_delay_before_headers'):
        context.effective.update(native_result='actual_host_deadline_timeout_before_response_headers', phase=2, rule_id=None, native_response_finalization=0, native_sdk_timeout_return_claimed=False)
        own_events = [row for row in context.events if row.get('transaction_id') in context.common_ids]
        context.checks['actual_physical_timeout_first_cause'] = bool(own_events) and own_events[0]['event'] == 'engine_timeout'
        context.checks['no_actual_native_response_before_host_timeout'] = context.counts['native_process_response_headers'] == context.counts['native_process_response_body'] == 0

def _evaluate_response_file(context):
    if context.fixture['case_id'] == 'NEED-response-file':
        response_file_receipt = context.data / 'backend-response-file.json'
        if response_file_receipt.is_file():
            actual_file = read(response_file_receipt)
            context.checks['actual_private_backend_file_read'] = actual_file['mode'] == '0o600' and actual_file['uid'] == 65534 and (actual_file['links'] == 1) and (actual_file['actual_read_sha256'] == context.fixture['expected_response_sha256']) and (len(context.main_backend) == 1) and (context.main_backend[0]['response_source_body_sha256'] == actual_file['actual_read_sha256'])
            context.observations['backend_payload_identity']['value']['actual_response_file_read'] = actual_file
            context.observations['backend_payload_identity']['evidence'].append(reference(response_file_receipt, 'backend_process'))
        else:
            context.checks['actual_private_backend_file_read'] = False

def _evaluate_canonical_oracle(context):
    if context.canonical:
        expected_rule = context.fixture['canonical_expected_rule_id']
        context.checks['original_rule_observed'] = expected_rule is None or native_rule_observed(context.marker_lines, expected_rule)
        original_fields = context.contract['original_oracle'].get('event_fields', [])
        actual_common = [row for row in context.events if row['transaction_id'] in context.common_ids]
        matching_common = [row for row in actual_common if expected_rule is None or str(row.get('rule_id')) == str(expected_rule)]
        context.checks['original_physical_common_event_fields'] = not original_fields or any((all((field in row and row[field] not in (None, '') for field in original_fields)) for row in matching_common))
        if context.fixture['case_id'] in {'event_has_no_request_body_payload', 'phase2_no_payload_event', 'event_has_no_response_body_payload', 'phase4_no_payload_event'}:
            payload = bytes.fromhex(context.fixture['request_hex'] if 'request' in context.fixture['case_id'] or context.fixture['case_id'].startswith('phase2') else context.fixture['response_hex'])
            physical_bytes = input_file(context.events_path).read_bytes()
            context.checks['actual_payload_absent_from_physical_common_event'] = bool(actual_common) and bool(payload) and (payload not in physical_bytes)
        _evaluate_audit_only_oracle(context, expected_rule, actual_common)



def _evaluate_audit_only_oracle(context, expected_rule, actual_common):
    audit_only_cases = {'log_only', 'transaction_id_present', 'transaction_id_generated_or_fallback'}
    audit_expectation = context.fixture.get('original_yaml_audit_expectation')
    if context.fixture['case_id'] in audit_only_cases and audit_expectation and (audit_expectation.get('required') is True) and ('event_jsonl' not in context.fixture.get('original_yaml_required_capabilities', ['event_jsonl'])):
        context.checks['original_physical_common_event_fields'] = context.checks['original_rule_observed']
        context.observations['native_events']['value']['original_event_producer_scope'] = {'source': context.fixture['canonical_source'], 'required_capabilities': context.fixture['original_yaml_required_capabilities'], 'audit_expectation': audit_expectation, 'physical_field_binding': {'rule_id': expected_rule, 'transaction_id': sorted(context.native_ids)}, 'scope': 'These exact original YAMLs require native audit metadata, without event_jsonl capability; other original IDs retain their distinct Common event requirement.', 'observed_common_count': len(actual_common)}
        if context.fixture['case_id'] == 'transaction_id_present':
            supplied = [value for name, value in context.fixture['request_headers'] if name.lower() == 'x-modsec-transaction-id']
            context.checks['original_supplied_native_id_preserved'] = supplied == sorted(context.native_ids) == sorted(context.common_ids)
        if context.fixture['case_id'] == 'transaction_id_generated_or_fallback':
            context.checks['original_generated_native_id_not_caller_override'] = bool(context.native_ids) and all((name.lower() not in ('x-request-id', 'x-modsec-transaction-id') for name, _value in context.fixture['request_headers'])) and ('x-request-id:' not in context.request_header_text.lower())

def _evaluate_response_marker(context):
    if context.fixture['case_id'].startswith('NEED-response-'):
        context.checks['native_P4_selected_oracle'] = any(('[id "91042001"]' in line for line in context.marker_lines)) if context.fixture['response_hex'] else context.counts['native_append_response_body'] == 0

def _evaluate_response_framing(context):
    if context.fixture.get('framing_probe'):
        context.checks['actual_http11_content_length_complete'] = context.client['headers'][0].startswith('HTTP/1.1 ') and context.client['framing']['kind'] == 'content_length' and (context.client['framing']['complete'] is True)

def _evaluate_delivered_profile(context):
    if context.fixture['case_id'].startswith('NEED-profile-'):
        actual_runtime = {key: value for line in (context.root / RUNTIME_CONFIG).read_text().splitlines() if '=' in line for key, value in (line.split('=', 1),)}
        context.checks['actual_selected_phase4_mode'] = actual_runtime['phase4_mode'] == ('strict' if context.fixture['profile'] == 'all' else context.fixture['profile'])
        context.observations['source_config_binding']['value']['actual_selected_phase4_mode'] = actual_runtime['phase4_mode']
        if context.fixture.get('profile_runtime_template'):
            expected_runtime = context.fixture['profile_runtime_template'].replace('/etc/modsecurity/no-crs-baseline.conf', '/task/lighttpd/rules.conf')
            expected_runtime = expected_runtime.replace('/var/log/lighttpd/msconnector-stock-' + context.fixture['profile'] + '-events.jsonl', '/task/lighttpd/events.jsonl')
            if context.data_relative is not None:
                expected_runtime = expected_runtime.replace(TASK_PREFIX, TASK_PREFIX + str(context.data_relative) + '/')
            context.checks['actual_delivered_profile_template'] = (context.root / RUNTIME_CONFIG).read_text() == expected_runtime
            sidecar_argv = context.snapshots['before-main']['processes']['sidecar']['argv']
            context.checks['actual_delivered_technical_arguments'] = all((option in sidecar_argv and sidecar_argv[sidecar_argv.index(option) + 1] == value for option, value in (('--timeout-ms', '10000'), ('--spool-capacity-bytes', '268435456'), ('--spool-free-reserve-bytes', '67108864'))))

def _evaluate_spool_resources(context):
    if context.spool_probe:
        reservation_path = context.root / 'held-reservation.json'
        holder_path = context.root / 'holder-process.json'
        held_path = context.root / 'holder/receipt.json'
        readmission_path = context.data / 'client/readmission.receipt.json'
        reservation = read(reservation_path)
        holder = read(holder_path)
        held = read(held_path)
        readmission = read(readmission_path)
        readmitted_backend = [row for row in context.backend if row['path'] == '/i12/stock/readmitted']
        own_events = [row for row in context.events if row['transaction_id'] in context.common_ids]
        held_size = 33554432 if context.fixture.get('default_capacity_probe') else 4097
        held_count = 8 if context.fixture.get('default_capacity_probe') else 1
        context.checks.update(actual_held_reservation=len(reservation['actual_fds']) == held_count and all((row['size'] == held_size and row['mode'] == '0o600' and (row['uid'] == 65534) and (row['links'] == 0) for row in reservation['actual_fds'])), technical_first_cause=bool(own_events) and own_events[0]['event'] == 'connector_error', no_invented_body_limit=all(('body_limit' not in str(row).lower() for row in own_events)), no_native_body_append=context.counts['native_append_request_body'] == 0, actual_holder_reaped=holder['reaped'] and holder['waited_exit'] == 0, actual_readmission=readmission['status'] == 200 and len(readmitted_backend) == 1 and (readmitted_backend[0]['body_sha256'] == context.fixture['expected_request_sha256']) and (readmitted_backend[0]['monotonic_ns'] > held['local_close_completed_ns']))
        context.observations['descriptor_cleanup']['value']['resource_probe'] = {'reservation': reservation, 'holder': holder, 'held_client': held, 'readmitted_client': readmission, 'readmitted_backend': readmitted_backend}
        context.observations['descriptor_cleanup']['evidence'] += [reference(path, 'cleanup_observer') for path in (reservation_path, holder_path, held_path)]
        context.observations['neighbor_health']['evidence'].append(reference(readmission_path, 'client_process'))
        context.observations['native_events']['value']['actual_main_physical_events'] = own_events
        context.observations['native_events']['value']['first_physical_cause'] = own_events[0] if own_events else None
        _evaluate_default_capacity(context)



def _evaluate_default_capacity(context):
    if context.fixture.get('default_capacity_probe'):
        actual_argv = context.snapshots['before-main']['processes']['sidecar']['argv']
        context.checks['actual_capacity_reserve_defaults_unoverridden'] = not any((option in actual_argv for option in ('--spool-capacity-bytes', '--spool-free-reserve-bytes')))
        if context.reserve_evidence:
            floor = read(context.reserve_evidence)
            context.checks['actual_default_floor_seam'] = floor['compile_exit'] == floor['run_exit'] == 0 and floor['actual_assertion_receipt']['default_reserve'] == 67108864
            context.observations['source_config_binding']['value']['default_reserve_component_boundary'] = floor
            context.observations['source_config_binding']['evidence'].append(reference(context.reserve_evidence, 'source_manifest'))
        else:
            context.observations['source_config_binding']['value']['default_reserve_boundary_missing'] = 'No physical64MiB floor seam receipt supplied; unchanged default flags alone do not exercise reserve enforcement.'

def _evaluate_sink_boundary(context):
    if context.sink_fault:
        fault_path = context.data / 'sink-fault.jsonl'
        faults = lines(fault_path)
        context.effective.update(native_result='event_sink_io_error_after_native_p1_decision', phase=1, rule_id='91042003', native_request_finalization=0, native_response_finalization=0, native_logging=0, native_cleanup=1, injected_io_fault=context.sink_fault)
        io_faults = [row for row in faults if row['operation'] != 'capture_lifetime_accept_stop']
        context.checks['actual_injected_io_callback'] = len(io_faults) == 1 and io_faults[0]['injected_errno'] == 5
        if context.sink_fault == 'close':
            context.effective.update(native_result='runtime_sink_close_after_completed_transactions', phase=5, rule_id=None, native_request_finalization=1, native_response_finalization=1, native_logging=1)
            context.checks['actual_runtime_sink_close'] = io_faults[0]['operation'] == 'fclose' and io_faults[0]['actual_called'] is True and (io_faults[0]['actual_return'] == 0)
        else:
            context.checks['actual_failed_constructor'] = any((row['function'] == 'runtime_begin_request_stream' and row['result'] == 0 for row in context.returns))
        context.observations['native_events']['value'].update(actual_io_fault_attempts=faults, physical_partial_record_details=context.event_parse_failures)
        context.observations['native_events']['evidence'].append(reference(fault_path, 'physical_event_sink'))

def _evaluate_live_spool(context):
    if context.fixture.get('sample_live_spool'):
        private_live = [snapshot for snapshot in context.live_snapshots if snapshot.get('spool_directory_stat') == {'mode': '0o700', 'uid': 65534} and any((detail['mode'] == '0o600' and detail['uid'] == 65534 and (detail['links'] == 0) and (detail['size'] == len(bytes.fromhex(context.fixture['request_hex']))) for process in snapshot['processes'].values() for detail in process.get('fd_details', {}).values()))]
        context.checks['actual_private_live_spool'] = bool(private_live)
        post_main_spool_fds = [detail for process in context.snapshots['after-main']['processes'].values() for detail in process.get('fd_details', {}).values() if '/spool/request-' in detail['target']]
        context.checks['actual_postmain_spool_descriptors_zero'] = len(post_main_spool_fds) == 0
        context.observations['descriptor_cleanup']['value']['postmain_observed_spool_descriptors'] = post_main_spool_fds
        context.checks['backend_after_held_private_spool'] = any((row['monotonic_ns'] > snapshot['monotonic_ns'] for row in context.main_backend for snapshot in private_live))

def _evaluate_replay_boundary(context):
    if context.fixture['case_id'] == 'NEED-replay-only-after-native-p2-allow':
        actual_headers = [row for row in context.backend_physical_rows if row.get('boundary') == 'headers_parsed' and row['path'] == context.fixture['path']]
        phase2_returns = [row for row in context.returns if row['function'] == 'native_process_request_body']
        context.checks['upstream_header_after_actual_native_p2'] = len(actual_headers) == len(phase2_returns) == 1 and actual_headers[0]['monotonic_ns'] > phase2_returns[0]['monotonic_ns']
        context.observations['client_backend_correlation']['value']['actual_backend_header_callbacks'] = actual_headers

def _evaluate_pointer_boundary(context):
    if context.pointer_fault:
        pointer_path = context.data / 'pointer-fault.jsonl'
        pointer_rows = lines(pointer_path)
        context.checks['actual_runtime_pointer_injection'] = len(pointer_rows) == 1 and pointer_rows[0]['boundary'] == context.pointer_fault and (pointer_rows[0]['injected_pointer_null'] is True) and (pointer_rows[0]['actual_input_count'] > 0)
        context.observations['native_intervention_or_first_cause']['value'] = {'actual_native_interventions': context.observations['native_intervention_or_first_cause']['value'], 'actual_runtime_argument_injection': pointer_rows, 'native_sdk_failure_claimed': False}
        context.observations['native_intervention_or_first_cause']['evidence'].append(reference(pointer_path, 'native_api'))


def _add_identity_roles(context):
    context.put('product_host_identity', {'processes': context.snapshots['before-main']['processes'], 'mapped_images': context.images}, [reference(Path(image['physical_path']), 'loaded_image') for image in context.images] + context.isolation_ev + [reference(context.root / 'receipts/before-main' / (actor + '.maps'), 'loaded_image') for actor in context.snapshots['before-main']['processes']])
    context.put('source_config_binding', {'fixture': context.contract, 'compiled_source_bytes_are_explicit': True}, [reference(context.fixture_path, 'source_manifest'), reference(context.inputs / 'artifacts-ledger.json', 'source_manifest')] + [reference(context.root / name, 'effective_configuration') for name in ('rules.conf', RUNTIME_CONFIG, 'lighttpd.conf')])
    context.put('capability', {'original_selected_requirement': context.selected, 'actual_stock_callbacks': context.eos}, [reference(context.fixture_path, 'source_contract')] + context.host_ev)
    context.put('client_exit', context.client_process, [reference(context.client_process_path, 'client_process')])
    context.put('client_signal', {'actual_process_signal': context.client_process['actual_signal'], 'tcp_reset': context.client['tcp_reset_observed']}, context.client_ev)
    context.put('client_headers', {'actual_response': context.client['headers'], 'actual_request': context.request_header_text}, context.client_ev + [reference(context.data / 'client/main.request.raw', 'client_process')])
    context.put('client_bytes', {'request': context.client['request_bytes'], 'response_entity': context.client['entity_bytes']}, context.client_ev)
    context.put('client_sha256', {'request': context.client['request_sha256'], 'response_entity': context.client['entity_sha256']}, context.client_ev)
    context.put('backend_request_count', {'main': len(context.main_backend), 'all_rows': len(context.backend)}, context.backend_ev)
    context.put('backend_payload_identity', {'actual_main_backend': context.main_backend, 'actual_client': context.client}, context.backend_ev + context.client_ev)
    context.put('client_backend_correlation', {'unique_main_method_path': context.fixture['path'], 'actual_backend_rows': context.main_backend, 'actual_client': context.client, 'neighbor_is_distinct_GET': True}, context.backend_ev + context.client_ev)

def _add_native_roles(context):
    context.put('native_events', {'same_native_id_marker_lines': context.marker_lines, 'common_records': context.events}, context.audit_ev + [reference(context.events_path, 'physical_event_sink')])
    context.put('native_api_returns', context.returns, context.api_ev)
    context.put('native_transaction_id', sorted(context.native_ids), context.api_ev)
    if context.before_allocation_absence:
        context.observations['native_transaction_id']['value'] = {'actual_native_transaction_id': None, 'native_constructor_calls': 0, 'actual_allocation_scope': context.scope, 'scope_complete': True, 'actual_failed_constructor': [row for row in context.returns if row['function'] == 'runtime_begin_request_stream']}
    context.put('common_transaction_id', {'raw': sorted(context.common_ids), 'canonical': sorted(context.canonical_ids)}, context.api_ev)
    context.put('observed_handle_association', {'actual_runtime_scope': context.scope, 'typed_constructor_rows': [row for row in context.returns if row['function'] == 'runtime_begin_request_stream'], 'join_proof': 'actual typed Runtime constructor metadata; equal strings are not join proof'}, context.api_ev)
    if context.failed_begin_expected:
        context.observations['observed_handle_association'].update(value=None, reason='Failed runtime constructor cleans native/Common allocations before returning a null handle; collector allocation_join_verified is false. Actual constructor scope and equal IDs are retained but cannot substitute for the missing typed handle association.')
        if context.measured_absence is not None:
            context.observations['observed_handle_association'].update(value=context.measured_absence)
            context.observations['observed_handle_association'].pop('reason', None)
    context.put('native_phases', [row for row in context.returns if row['function'].startswith('native_process_')], context.api_ev)
    context.put('native_body_chunks', [row for row in context.returns if row['function'].startswith('native_append_')], context.api_ev)
    context.put('native_intervention_or_first_cause', [row for row in context.returns if row['function'] == 'native_intervention'], context.api_ev)
    context.put('host_eos', context.eos, context.host_ev)
    context.put('native_eos', {'request_finalization': context.counts['native_process_request_body'], 'response_finalization': context.counts['native_process_response_body'], 'actual_host_finite_EOS': context.eos, 'native_append_has_EOS_argument': False}, context.api_ev + context.host_ev)
    context.put('commit_order', {'host_boundaries': context.eos, 'client_recv_intervals': context.client['actual_socket_recv_chunks'], 'Common_commit_rows': [row for row in context.returns if row['function'] == 'common_set_response_committed'], 'kernel_send_time': None}, context.host_ev + context.client_ev)
    native_mime = [row['native_mime_selection'] for row in context.returns if row['function'] in ('native_process_response_headers', 'native_process_response_body') and row.get('native_mime_selection') is not None]
    context.put('mime_gate', {'actual_response_content_type': context.response_content_types, 'actual_native_selection': native_mime, 'actual_native_snapshot_boundaries': [row['function'] for row in context.returns if row.get('native_mime_selection') is not None], 'same_native_id_rules': context.marker_lines, 'native_phase4': [row for row in context.returns if row['function'] == 'native_process_response_body']}, context.audit_ev + context.debug_ev)
    if native_mime:
        context.observations['mime_gate']['evidence'] = context.api_ev + context.audit_ev
    elif context.response_not_reached and context.counts['native_process_response_body'] == 0:
        context.observations['mime_gate'] = {'applicable': False, 'value': None, 'reason': 'Original request-phase termination occurs before upstream admission and response-body phase; complete selected native trace observes zero response-body calls.', 'capability_proof': [reference(context.fixture_path, 'source_contract'), reference(REPO / 'connectors/lighttpd/stock_sidecar/stock_sidecar.c', 'source_contract')]}
        if context.fixture.get('backend_delay_before_headers'):
            context.observations['mime_gate']['reason'] = 'Actual backend is admitted, but finite host deadline expires before response headers; complete selected native trace contains zero P3/P4 calls, so no actual MIME selection exists.'
    else:
        context.observations['mime_gate'].update(value=None, reason='Existing generic MIME field is null; a P4 marker alone does not establish actual SDK MIME/charset selection.')
    return native_mime

def _add_cleanup_roles(context):
    context.put('finish_calls', {'Common_finish': context.counts['common_finish'], 'native_logging': context.counts['native_process_logging'], 'actual_finalize_and_snapshot': context.counts['runtime_finalize_and_snapshot']}, context.api_ev)
    context.put('finish_transitions', [row for row in context.returns if row['function'] in ('common_complete_phase', 'common_finish', 'common_cleanup')], context.api_ev)
    context.put('native_free_calls', {'native_cleanup': context.counts['native_cleanup'], 'Common_cleanup': context.counts['common_cleanup'], 'actual_finalize_snapshot': [row for row in context.returns if row['function'] == 'runtime_finalize_and_snapshot']}, context.api_ev)
    context.put('cleanup_receipts', {'main_actual_cleanup_rows': [row for row in context.returns if row['function'] in ('native_cleanup', 'common_cleanup', 'runtime_finalize_and_snapshot')], 'process_cleanup': context.execution['cleanup'], 'controller': context.controller}, context.cleanup_ev + context.isolation_ev)
    context.put('descriptor_cleanup', {'actual_snapshots': context.snapshots, 'actual_main_live_snapshots': context.live_snapshots, 'claim': 'FD transitions retained, exact raw FD equality not inferred; actor cleanup also required'}, context.snapshot_ev)
    context.observations['descriptor_cleanup']['evidence'] += [reference(path, 'cleanup_observer') for path in context.live_snapshot_paths]
    context.put('process_listener_cleanup', {'actors': context.execution['cleanup'], 'controller': context.controller}, context.cleanup_ev + context.isolation_ev)
    neighbor_path = context.data / 'client/neighbor.receipt.json'
    neighbor = read(neighbor_path)
    neighbor_backend = [row for row in context.backend if row['method'] == neighbor['method'] and row['path'] == neighbor['path'] and (neighbor['started_ns'] <= row['monotonic_ns'] <= neighbor['completed_ns'])]
    neighbor_scope = selected_scope(context.api, neighbor['started_ns'], neighbor['completed_ns'])
    context.put('neighbor_health', {'client': neighbor, 'backend': neighbor_backend, 'actual_typed_allocation_scope': neighbor_scope}, [reference(neighbor_path, 'client_process')] + context.backend_ev)
    context.put('transport_framing', context.client['framing'], context.client_ev)
    context.put('transport_reset_scope', {key: context.client[key] for key in ('tcp_eof_observed', 'tcp_reset_observed', 'timeout_observed', 'error')}, context.client_ev + context.host_ev)
    context.put('host_action', {'actual_client_status': context.client['status'], 'physical_finite_EOS': context.eos, 'actual_native_returns': context.returns, 'no_alternate_status_inferred': True}, context.host_ev + context.client_ev)
    context.put('physical_event_order', {'same_native_id_rules': context.marker_lines, 'actual_common_records': context.events}, context.audit_ev)
    sink_namespace_path = TASK_PREFIX + str((context.data / 'lighttpd/events.jsonl').relative_to(context.namespace_data))
    context.put('terminal_event_count', {'actual_common_file_count': len(context.events), 'physical_incomplete_or_invalid_lines': context.event_parse_failures, 'actual_open_sink_snapshots': [value['physical_files'].get(sink_namespace_path) for value in context.snapshots.values()], 'scope': 'all actual records retained; independent transaction IDs distinguish selected main, held resource actor and benign followups'}, [reference(context.events_path, 'physical_event_sink')])
    if set(context.observations) != set(context.ledger.ROLES):
        raise ValueError('shared qualifier field contract changed')
    return (neighbor_path, neighbor_backend, neighbor_scope, neighbor)


def _load_packet_contract(context):
    context.output = external_path(context.output)
    context.ledger = central()
    context.fixture_path = context.inputs / 'fixtures/fixture-contract.json'
    if not context.fixture_path.is_file():
        context.fixture_path = context.inputs / 'fixture-contract.json'
    context.contract = read(context.fixture_path)
    context.fixture = context.contract['fixture']
    context.selected = context.contract['original_selected_requirement']
    context.canonical = 'canonical_source' in context.fixture
    context.spool_probe = context.fixture.get('spool_probe') is True
    context.sink_fault = context.fixture.get('sink_fault')
    context.pointer_fault = context.fixture.get('pointer_fault')
    context.preserve_original_oracle = context.canonical or bool(context.pointer_fault) or context.fixture.get('preserve_original_oracle', False)
    context.failed_begin_expected = (context.sink_fault not in (None, 'close') or context.pointer_fault == 'headers_null'
                             or context.fixture.get('diagnostic_boundary_fault') == 'request_headers_error')
    context.early_intervention = (context.canonical and context.fixture['expected_backend_main_count'] == 0) or context.spool_probe or context.failed_begin_expected or bool(context.pointer_fault)
    context.response_not_reached = context.early_intervention or context.fixture.get('expected_response_finalizations') == 0


def _load_allocation_observations(context):
    context.namespace_data = context.attempt / 'data'
    context.data = context.namespace_data if context.data_relative is None else context.namespace_data / context.data_relative
    if '..' in context.data.parts or not context.data.is_relative_to(context.namespace_data):
        raise ValueError('case data must stay within its actual controller namespace')
    context.root = context.data / 'lighttpd'
    context.snapshots = {name: read(context.root / 'receipts' / name / 'snapshot.json')
                 for name in ('before-main', 'after-main', 'after-neighbor')}
    context.live_snapshot_paths = sorted((context.root / 'receipts').glob('during-main-*/snapshot.json'))
    context.live_snapshots = [read(path) for path in context.live_snapshot_paths]
    context.api_path = context.data / 'native-api.jsonl'
    context.api = lines(context.api_path)
    context.scope = selected_scope(context.api, context.snapshots['before-main']['monotonic_ns'], context.snapshots['after-main']['monotonic_ns'], require_join=not context.failed_begin_expected)
    context.main = [row for row in context.api if row.get('allocation_scope_call') == context.scope]
    if any(row['invalid'] for row in context.main):
        raise ValueError('native observer marked selected allocation invalid')
    _bind_allocation_identity(context)
    context.eos_path = context.data / 'host-eos.jsonl'
    context.eos = [row for row in lines(context.eos_path) if row['runtime_allocation_scope_call'] == context.scope]


def _bind_allocation_identity(context):
    context.returns = [row for row in context.main if row['edge'] == 'return']
    context.counts = Counter(row['function'] for row in context.returns)
    context.measured_absence = failed_constructor_absence(context.returns, context.scope)
    context.before_allocation_absence = context.pointer_fault == 'headers_null' and context.measured_absence is not None and context.counts['common_init'] == 0 and context.counts['native_new_with_id'] == 0 and context.counts['native_new'] == 0
    context.native_ids = {row['transaction_id'] for row in context.main
                  if row.get('transaction_id_origin') == 'sdk_public_m_id' and row.get('transaction_id')}
    context.common_ids = {row['transaction_id'] for row in context.main
                  if row.get('transaction_id_origin') == 'common_public_contract' and row.get('transaction_id')}
    context.canonical_ids = {row['canonical_transaction_id'] for row in context.main if row.get('canonical_transaction_id')}
    if not context.before_allocation_absence and (len(context.native_ids) != 1 or len(context.common_ids) != 1 or len(context.canonical_ids) != 1):
        raise ValueError('independent native/Common identity missing')
    context.native_id = next(iter(context.native_ids)) if context.native_ids else None


def _load_host_observations(context):
    context.client_path = context.data / 'client/main.receipt.json'
    context.client = read(context.client_path)
    context.request_header_text = (context.data / 'client/main.request.raw').read_bytes().partition(b'\r\n\r\n')[0].decode('ascii')
    context.response_content_types = [line.partition(':')[2].strip() for line in context.client['headers'][1:]
                              if line.partition(':')[0].lower() == 'content-type']
    context.client_process_path = context.root / 'main.actual-client-process.json'
    context.client_process = read(context.client_process_path)
    context.backend_path = context.data / 'backend.jsonl'
    context.backend_physical_rows = lines(context.backend_path)
    context.backend = [row for row in context.backend_physical_rows if row.get('boundary', 'body_consumed') == 'body_consumed']
    context.main_backend = [row for row in context.backend if row['method'] == context.fixture['method'] and row['path'] == context.fixture['path']
                    and context.client['started_ns'] <= row['monotonic_ns'] <= context.client['completed_ns']]
    context.audit_path = context.root / 'audit/native-audit.log'
    context.debug_path = context.root / 'audit/native-debug.log'
    context.marker_lines = native_audit_for_id(context.audit_path, context.native_id)
    context.events_path = context.root / 'events.jsonl'
    context.events, context.event_parse_failures = physical_events(context.events_path)
    context.execution_path = context.root / 'execution-receipt.json'
    context.execution = read(context.execution_path)
    context.controller_path = context.attempt / 'controller-result.json'
    context.controller = read(context.controller_path)
    context.images = mapped_images(context.snapshots['before-main'], context.data, context.namespace_data)
    context.api_ev = [reference(context.api_path, 'native_api')]
    context.host_ev = [reference(context.eos_path, 'host_callback')]
    context.client_ev = [reference(context.client_path, 'client_process')]
    context.backend_ev = [reference(context.backend_path, 'backend_process')]
    context.audit_ev = [reference(context.audit_path, 'physical_event_sink')]
    context.debug_ev = [reference(context.debug_path, 'native_debug')]
    context.cleanup_ev = [reference(context.execution_path, 'cleanup_observer')]
    context.isolation_ev = [reference(context.controller_path, 'isolation_receipt')]
    context.snapshot_ev = [reference(context.root / 'receipts' / name / 'snapshot.json', 'cleanup_observer') for name in context.snapshots]


def _assemble_observation_roles(context):
    context.observations = {}

    def put(field, value, evidence):
        context.observations[field] = {'applicable': True, 'value': value, 'evidence': evidence}

    context.put = put
    _add_identity_roles(context)
    context.native_mime = _add_native_roles(context)
    context.neighbor_path, context.neighbor_backend, context.neighbor_scope, context.neighbor = _add_cleanup_roles(context)


def _prepare_effective_expectation(context):
    context.effective = {'native_result': 1, 'visible_status': context.fixture['expected_visible_status'], 'phase': 2,
        'rule_id': '91042002', 'physical_evidence_not_projection': True,
        'backend_main_count': context.fixture['expected_backend_main_count'],
        'request_sha256': context.fixture['expected_request_sha256'], 'response_sha256': context.fixture['expected_response_sha256'],
        'native_request_finalization': 1, 'native_response_finalization': 1, 'native_cleanup': 1}
    if context.preserve_original_oracle:
        context.effective.update(context.contract['original_oracle'])
    if context.fixture['case_id'].startswith('NEED-response-'):
        context.effective.update(phase=4, rule_id='91042001' if context.fixture['response_hex'] else None)
    context.expected_request_finalizations = 1
    if context.early_intervention:
        context.expected_request_finalizations = 0 if context.spool_probe or context.sink_fault or context.pointer_fault else int(context.contract['original_oracle']['phase'] == 2)
        context.effective.update(native_request_finalization=context.expected_request_finalizations,
            native_response_finalization=0)
    elif context.response_not_reached:
        context.effective['native_response_finalization'] = 0
    if context.spool_probe:
        context.effective.update(native_result='connector_error', phase=1, rule_id=None,
            technical_capacity_bytes=context.fixture['spool_capacity_bytes'],
            held_reserved_bytes=268435456 if context.fixture.get('default_capacity_probe') else 8192,
            attempted_reserved_bytes=4096,
            native_body_limit_decision=False, readmission_status=200)
    context.minimum_request_appends = _minimum_request_appends(context)
    context.effective['native_request_append_minimum'] = context.minimum_request_appends


def _minimum_request_appends(context):
    if context.spool_probe or context.failed_begin_expected or context.pointer_fault:
        return 0
    if context.fixture['delayed_request']:
        return 2
    return int(bool(context.fixture['request_hex']))


def _native_p2_marker_observed(context):
    return context.canonical or context.spool_probe or bool(context.sink_fault) or bool(context.pointer_fault) or (not context.fixture['request_hex'] and context.counts['native_process_request_body'] == 1 and context.counts['native_append_request_body'] == 0) or native_rule_observed(context.marker_lines, '91042002')


def _check_main_observations(context):
    context.checks = {'independent_client_exit': context.client_process['actual_waited_return_code'] == context.fixture.get('expected_client_exit', 0),
        'actual_neighbor_healthy': context.neighbor['status'] == 200 and len(context.neighbor_backend) == 1 and context.neighbor_scope != context.scope,
        'status': context.client['status'] == (context.fixture['expected_visible_status'] if context.effective['visible_status'] is None else context.effective['visible_status']), 'main_backend_count': len(context.main_backend) == context.fixture['expected_backend_main_count'],
        'client_request_digest': context.client['request_sha256'] == context.effective['request_sha256'],
        'backend_request_digest': not context.main_backend if context.early_intervention else len(context.main_backend) == 1 and context.main_backend[0]['body_sha256'] == context.effective['request_sha256'],
        'client_response_digest': context.effective['response_sha256'] is None or context.client['entity_sha256'] == context.effective['response_sha256'],
        'native_request_finalization': context.counts['native_process_request_body'] == context.expected_request_finalizations,
        'native_response_finalization': context.counts['native_process_response_body'] == (0 if context.response_not_reached else 1),
        'native_cleanup': context.counts['native_cleanup'] == (0 if context.before_allocation_absence else 1),
        'actual_native_chunk_minimum': context.counts['native_append_request_body'] >= context.minimum_request_appends,
        'request_content_type': ('Content-Type: ' + context.fixture['request_content_type']) in context.request_header_text
            if context.fixture['request_content_type'] is not None else 'content-type:' not in context.request_header_text.lower(),
        'native_P2_marker': _native_p2_marker_observed(context),
        'controller_clean': not context.controller['errors'] and not context.controller['surviving_namespace_pids'] and not context.controller['outside_mount_leaks'] and context.controller['resource_violation'] is None}


def _evaluate_case_boundaries(context):
    _evaluate_incomplete_backend(context)
    _evaluate_client_abort(context)
    _evaluate_host_deadline(context)
    _evaluate_response_file(context)
    _evaluate_canonical_oracle(context)
    _evaluate_response_marker(context)
    evaluate_sequence(context.fixture, context.data, context.api, context.audit_path, context.observations, context.checks)
    _evaluate_response_framing(context)
    _evaluate_delivered_profile(context)
    _evaluate_spool_resources(context)
    _evaluate_sink_boundary(context)
    _evaluate_live_spool(context)
    _evaluate_replay_boundary(context)
    context.observed_run_ids = {row['run'] for row in context.main}
    if len(context.observed_run_ids) != 1:
        raise ValueError('same main allocation has inconsistent actual run identity')
    _evaluate_pointer_boundary(context)


def _packet_outcome(context):
    if not (context.native_mime or context.response_not_reached):
        return None
    return 'PASS' if all(context.checks.values()) else 'FAIL'


def _assemble_packet_proposal(context):
    context.qualified_oracle = context.contract['original_oracle'] if context.preserve_original_oracle else context.effective
    context.packet = {'leg_id': 'lighttpd-stock-sidecar', 'run_scoped_case_id': context.selected['run_scoped_case_id'],
        'run_id': context.observed_run_ids.pop(), 'execution_kind': 'host_http',
        'execution_observed': True, 'parent_sha': context.contract.get('actual_checkout_head_at_preparation'),
        'framework_sha': '99a7985c1be92a2297b1b59208f64df6768f2cbf', 'framework_scope': 'not_executed',
        'mrts_sha': '8a6bb546c4c81d8ffc7be801dceac60c6925685f', 'mrts_scope': 'not_executed',
        'effective_config_sha256': sha(context.root / 'lighttpd.conf'), 'rules_sha256': sha(context.root / 'rules.conf'),
        'reviewed_by': 'worker', 'full_lifecycle_qualified': False, 'observations': context.observations,
        'oracle_evaluated': True, 'oracle_sha256': context.ledger.ORACLES.canonical_digest(context.qualified_oracle),
        'outcome': _packet_outcome(context),
        'evaluation_checks': context.checks}
    if context.failed_begin_expected and context.measured_absence is None:
        context.packet['outcome'] = None
        context.packet['qualification_missing_reason'] = context.observations['observed_handle_association']['reason']
    if context.fixture.get('native_audit_format_control'):
        context.packet['outcome'] = None
        context.packet['qualification_missing_reason'] = 'Root must independently decide whether genuine SDK JSONL transaction.messages[*].details.ruleId satisfies the original logical event rule_id contract; Common JSONL remains distinct and no normalized event is manufactured.'
        context.observations['native_events']['value']['actual_native_jsonl_scope'] = {
            'producer': 'ModSecurity SDK JSON audit exporter',
            'physical_main_lines': context.marker_lines,
            'actual_rule_field_path': 'transaction.messages[*].details.ruleId',
            'actual_transaction_field_path': 'transaction.unique_id',
            'common_jsonl_rule_id_claimed': False}


def _write_packet_proposals(context):
    context.output.mkdir(mode=0o700, parents=True)
    context.retest = {**{key: value for key, value in context.packet.items() if key != 'observations'},
        'actual_observations': context.observations, 'measurement_evidence': context.api_ev + context.client_ev + context.backend_ev + context.host_ev + context.audit_ev}
    (context.output / 'retest-proposal.json').write_text(json.dumps(context.retest, indent=2) + '\n')
    context.record = {'reviewed_by': 'worker', 'leg_id': context.packet['leg_id'],
        'run_scoped_case_id': context.packet['run_scoped_case_id'], 'category': 'SOURCE_CONFIRMED_EXPECTATION',
        'interpretation': 'Original null expectation resolved against pre-execution finite fixture/pass rules and independent SDK3.0.14/RFC9110, not observed status.',
        'scope': context.fixture, 'resolved_expectation': context.effective, 'original_oracle': context.contract['original_oracle'],
        'independent_sources': context.contract['independent_sources'],
        'implementation_sources': [reference(context.fixture_path, 'source_contract')],
        'retest': reference(context.output / 'retest-proposal.json')}
    if context.preserve_original_oracle:
        context.record.pop('resolved_expectation')
        context.record['interpretation'] = 'Original existing oracle preserved byte-for-byte; original physical Common event fields are evaluated separately from native audit rule visibility. Additional fixture byte/finalization checks do not replace the oracle.'
    (context.output / 'packet-proposal.json').write_text(json.dumps(context.packet, indent=2) + '\n')
    (context.output / 'oracle-proposal.json').write_text(json.dumps(context.record, indent=2) + '\n')


def assemble(attempt, inputs, output, data_relative=None, reserve_evidence=None):
    context = SimpleNamespace(
        attempt=attempt, inputs=inputs, output=output,
        data_relative=data_relative, reserve_evidence=reserve_evidence)
    _load_packet_contract(context)
    _load_allocation_observations(context)
    _load_host_observations(context)
    _assemble_observation_roles(context)
    _prepare_effective_expectation(context)
    _check_main_observations(context)
    _evaluate_case_boundaries(context)
    _assemble_packet_proposal(context)
    _write_packet_proposals(context)
    return context.packet


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('attempt', 'inputs', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--data-relative', type=Path)
    parser.add_argument('--reserve-evidence', type=Path)
    args = parser.parse_args()
    packet = assemble(args.attempt, args.inputs, args.output, args.data_relative, args.reserve_evidence)
    print(json.dumps({'case': packet['run_scoped_case_id'], 'candidate_outcome': packet['outcome'],
                      'checks': packet['evaluation_checks'], 'root_review_performed': False}))


if __name__ == '__main__':
    main()
