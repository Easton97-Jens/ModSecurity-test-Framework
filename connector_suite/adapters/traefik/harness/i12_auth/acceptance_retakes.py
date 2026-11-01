"""Supplementary bounded transport fixtures; preserve every original oracle."""
import copy
import hashlib
import json


TRANSPORT_CASES = {'response_short_write_resume', 'response_write_would_block_resume'}
RESPONSE_SIZE = 8 * 1024 * 1024
SDK_LIMIT = 16 * 1024 * 1024


def transport_case(case):
    if case['case_id'] not in TRANSPORT_CASES:
        raise ValueError('explicit original transport ID required')
    value = copy.deepcopy(case)
    value['probe_id'] += '-syscall'
    value['original_id'] = case['id']
    value['control_name'] = 'bounded-actual-syscall-backpressure'
    fixture = value['fixture']
    payload = b'i12-benign-response\n'
    payload = (payload * (RESPONSE_SIZE // len(payload) + 1))[:RESPONSE_SIZE]
    remaining = RESPONSE_SIZE - 8192
    fixture['backend'].update(body_hex=payload.hex(),
        chunk_lengths=[8192] + [32768] * (remaining // 32768) + ([remaining % 32768] if remaining % 32768 else []))
    fixture['backend'].pop('barrier_after_bytes', None)
    fixture['backend'].pop('truncate_after_bytes', None)
    fixture['client'] = {'kind': 'ordinary', 'receive_buffer_policy': 'kernel_default_recorded',
        'target_command_deadline_seconds': 120,
        'pause_for_target_eagain': {'nonce': value['probe_id'], 'deadline_seconds': 8}}
    fixture['fault'] = None
    fixture['syscall_observer'] = {'mode': 'auth', 'nonce': value['probe_id'], 'seconds': 180,
                                   'fixed_case': value['probe_id']}
    fixture.pop('fault_scope', None)
    fixture['rules_lines'] = [line for line in fixture['rules_lines']
        if not line.startswith('SecResponseBodyLimit ')] + ['SecResponseBodyLimit ' + str(SDK_LIMIT)]
    fixture['transport_measurement_required'] = (
        'exact child PID/image, client TCP tuple and socket inode; real kernel short write/EAGAIN; '
        'subsequent successful write on same inode; complete client body hash; native EOS and once cleanup')
    value['independent_control_expectation'] = {
        'predeclared_visible_status': 200, 'response_body_bytes': RESPONSE_SIZE,
        'response_body_sha256': hashlib.sha256(payload).hexdigest(),
        'sdk_response_limit': SDK_LIMIT, 'native_inspection_claim': False,
        'original_rule_oracle_preserved': True,
        'original_rule_oracle_satisfied_by_transport_control': False,
        'direct_sdk_control_required_before_host': True,
        'missing_target_eagain': 'bounded release and retain unqualified evidence'}
    value['fixture_sha256'] = hashlib.sha256(json.dumps(fixture, sort_keys=True,
        separators=(',', ':')).encode()).hexdigest()
    value['qualification'] = None
    return value


def original_causal_transport_case(case):
    """A separate fixture version reaches original P4 only after client delivery.

    The fixed tracer accepts the same exact probe in a separate sealed run.
    The benign transport control and this original-rule attempt never share a
    runtime directory or overwrite one another's receipts.
    """
    value = transport_case(case)
    fixture = value['fixture']
    marker = b'no-crs-response-body-marker'
    payload = bytes.fromhex(fixture['backend']['body_hex'])[:-len(marker)] + marker
    fixture['backend'].update(body_hex=payload.hex(), barrier_after_bytes=8192)
    value['control_name'] = 'original-rule-causal-transport-retake'
    value['independent_control_expectation'].update(
        predeclared_native_status=403, predeclared_rule_id=1100301, predeclared_phase=4,
        predeclared_visible_status=200,
        visible_status_source='original phase4 Safe source contract; Root binding required',
        actual_client_delivery_before_p4_required=True,
        source_expected_safe_late_action='log_only',
        response_body_sha256=hashlib.sha256(payload).hexdigest(),
        direct_sdk_control_required_before_host=True)
    value['fixture_sha256'] = hashlib.sha256(json.dumps(fixture, sort_keys=True,
        separators=(',', ':')).encode()).hexdigest()
    return value


def backend_exclusion_retake(value, fixture):
    original_rule='SecAction "id:1999303,phase:1,deny,status:403"'
    if fixture['rules_lines'].count(original_rule)!=1:
        raise ValueError('exact original backend-exclusion proposal rule required')
    target=fixture['request']['uri']
    replacement='SecRule REQUEST_URI_RAW "@streq '+target+'" "id:1999303,phase:1,deny,status:403,log,t:none"'
    fixture['rules_lines']=[replacement if line==original_rule else line for line in fixture['rules_lines']]
    fixture['explicit_target_isolation_revision']={
        'original_rule':original_rule,'effective_rule':replacement,
        'reason':'retain original target deny while allowing distinct readiness/healthy neighbor requests',
        'original_oracle_preserved':True,'independent_sdk_target403_neighbor200_required':True}
    value['control_name']='targeted-backend-exclusion-retake'


def physical_sink_retake(value, fixture, name, case):
    value['control_name']='physical-sink-emission-retake'
    if name.endswith(('write', 'flush', 'close')):
        phase = 1 if case['route'] == 'traefik-forwardauth-request' else 3
        uri = fixture['request']['uri']
        positive_uri = uri + '/sink-recovered'
        for rule_id, target in ((1999398, uri), (1999397, positive_uri)):
            fixture['rules_lines'].append('SecRule REQUEST_URI_RAW "@streq ' + target + '" '
                '"id:' + str(rule_id) + ',phase:' + str(phase) + ',deny,status:403,log,t:none"')
        if not name.endswith('close'):
            fixture['sink_positive_control'] = {'uri': positive_uri,
                'probe_id': value['probe_id'] + '-sink-positive', 'native_status': 403,
                'rule_id': 1999397, 'requires_same_live_engine_pid_and_sink_inode': True}
        value['independent_control_expectation'] = {
            'source': 'exact target conditional disruptive rule forces actual Common event emission',
            'native_status': 403, 'native_phase': phase, 'native_rule_id': 1999398,
            'visible_status': None, 'root_technical_failure_binding_required': True,
            'same_live_pid_successful_sink_event_after_fault_required': not name.endswith('close')}


def evidence_retake_case(case):
    """Narrow retakes whose expected facts still need Root's source binding."""
    value = copy.deepcopy(case)
    value['original_id'] = case['id']
    fixture = value['fixture']
    name = case['case_id']
    if name in ('NEED-backend-excluded-on-deny','NEED-backend-count-exclusion'):
        backend_exclusion_retake(value, fixture)
    elif name == 'NEED-client-exit-signal':
        fixture['client'] = {'kind': 'wait-for-sigterm'}
        fixture['fault'] = None
        fixture['backend'].update(body_hex=(b'x' * 16384).hex(), chunk_lengths=[8192, 8192],
                                  barrier_after_bytes=8192, wait_for_client_termination=True)
        value['independent_control_expectation'] = {
            'source': 'unchanged original client_action exact task-owned waited client PID SIGTERM',
            'waited_client_signal': 15, 'client_entity_bytes_before_signal': 8192,
            'backend_eos_before_client_signal': False, 'native_cleanup_evidence_required': True}
    elif name == 'phase4_deny_after_commit_log_only_safe':
        value['control_name']='causal-8192-byte-supplement'
        payload = b'x' * 8192 + b'no-crs-response-body-marker'
        fixture['backend'].update(body_hex=payload.hex(), chunk_lengths=[8192, len(payload) - 8192],
                                  barrier_after_bytes=8192)
        fixture['client'] = {'kind': 'ordinary'}
        value['independent_control_expectation'] = {
            'source': 'unchanged original rule1100301/P4 Safe contract',
            'native_status': 403, 'native_rule_id': 1100301, 'visible_status': 200,
            'actual_client_8192_entity_delivery_before_final_marker_required': True,
            'physical_late_action_event_required': True}
    elif name.startswith('NEED-physical-event-sink-'):
        physical_sink_retake(value, fixture, name, case)
    elif case['classification'] != 'config' and name != 'phase4_deny_after_commit_log_only_minimal':
        raise ValueError('explicit evidence retake ID required')
    value['fixture_sha256'] = hashlib.sha256(json.dumps(fixture, sort_keys=True,
        separators=(',', ':')).encode()).hexdigest()
    value['qualification'] = None
    return value
