"""Explicit supplementary probes; never create or qualify another original ID."""
import copy
import hashlib
import re


REQUEST_MARKER = 'request-marker.txt'
OUTSIDE_SAMPLE = 'request-outside-sample.txt'
BENIGN_FILE = 'benign.txt'
RESPONSE_MARKER = 'response-marker.txt'

def file_binding(case):
    """Only an explicitly sealed physical-HTTP supplement enables a file reader."""
    binding = case['fixture'].get('physical_file_supplement')
    if binding is None:
        return None
    direction = {'NEED-request-file': 'request', 'NEED-response-file': 'response'}.get(case['case_id'])
    expected_route = 'traefik-forwardauth-' + ('request' if direction == 'request' else 'response-companion')
    route = case.get('route', expected_route)
    names = {'request': (BENIGN_FILE, REQUEST_MARKER, OUTSIDE_SAMPLE),
             'response': (BENIGN_FILE, RESPONSE_MARKER)}
    if (binding.get('schema') != 'traefik-auth-physical-file-http-v1' or direction is None or
            route != expected_route or case['id'] != 'I12::' + expected_route + '::' + case['case_id'] or
            binding.get('direction') != direction or
            binding.get('native_file_api') is not False or binding.get('explicit_original_id') != case['id'] or
            binding.get('fixture') not in names[direction] or
            not re.fullmatch(r'[0-9a-f]{64}', binding.get('manifest_sha256', '')) or
            not re.fullmatch(r'[0-9a-f]{64}', binding.get('rules_source_sha256', '')) or
            binding.get('rules_sha256') != hashlib.sha256(('\n'.join(case['fixture']['rules_lines']) + '\n').encode()).hexdigest() or
            set(binding.get('files', {})) != {BENIGN_FILE, REQUEST_MARKER, OUTSIDE_SAMPLE, RESPONSE_MARKER}):
        raise ValueError('explicit sealed original-ID physical file binding required')
    outside = binding['fixture'] == OUTSIDE_SAMPLE
    if binding.get('host_capacity_control', False) is not outside:
        raise ValueError('only the 4199-byte request file is a host-capacity control')
    return binding


def file_expectation(binding, filename):
    outside = filename == OUTSIDE_SAMPLE
    request_marker = filename == REQUEST_MARKER
    status, rule_id, phase = 200, 1100301, 4
    if request_marker:
        status, rule_id, phase = 403, 1100101, 2
    if outside:
        status, rule_id, phase = 401, None, None
    return {'source': 'explicit physical regular-file HTTP supplement; native file API is not executed',
     'native_file_api': False, 'visible_status': status,
     'visible_body_hex': b'request denied\n'.hex() if request_marker else None,
     'backend_arrivals': 0 if outside or request_marker else 1,
     'authorization_arrivals': 0 if outside else 1,
     'native_transactions': 0 if outside else 1,
     'native_rule_id': rule_id,
     'native_phase': phase,
     'observer_mode': 'default-mrc1' if outside else 'trusted-provenance',
     'outer_provenance_enabled': not outside,
     'native_eos_and_finish_free_required': not outside,
     'actual_commit_and_client_bytes_required': binding['direction'] == 'response'}


def file_controls(binding, add, result):
    if not binding:
        return
    choices = (REQUEST_MARKER, OUTSIDE_SAMPLE) if binding['direction'] == 'request' else (RESPONSE_MARKER,)
    for filename in choices:
        outside = filename == OUTSIDE_SAMPLE
        def select_file(fixture, selected=filename, capacity=outside):
            fixture['physical_file_supplement'].update(fixture=selected, host_capacity_control=capacity)
        add('physical-' + filename.removesuffix('.txt'), select_file, file_expectation(binding, filename))
    if binding['direction'] == 'response':
        add('strict-admission', lambda fixture: fixture['policy'].update(phase4_mode='strict'),
            {'source': 'current ForwardAuth response companion rejects Strict configuration',
             'configuration_rejected_before_traffic': True, 'native_file_api': False})
        result[-1]['classification'] = 'config'


def causal_controls(case, name, add):
    if name == 'phase4_deny_after_commit_log_only_safe':
        literal = bytes.fromhex(case['fixture']['backend']['body_hex'])
        if b'no-crs-response-body-marker' not in literal:
            raise ValueError('original source-bound P4 marker payload required')
        def causal_wire(fixture):
            original_chunks = fixture['backend'].get('chunk_lengths', [len(literal)])
            fixture['explicit_causal_supplement'] = {
                'original_literal_body_sha256': hashlib.sha256(literal).hexdigest(),
                'original_literal_chunk_lengths': list(original_chunks),
                'padding_bytes_before_exact_original_body': 8192,
                'primary_literal_fixture_preserved': True}
            fixture['backend'].update(body_hex=(b'x' * 8192 + literal).hex(),
                chunk_lengths=[8192, *original_chunks], barrier_after_bytes=8192)
        add('wire8192', causal_wire,
            {'source': 'explicit supplement prepends8192benignbytes to exact original P4 Safe body',
             'predeclared_native_status': 403, 'predeclared_rule_id': 1100301, 'predeclared_phase': 4,
             'visible_status': 200, 'actual_client_entity_delivery_before_original_body_required': True,
             'direct_sdk_control_required_before_host': True})


def sink_and_shutdown_controls(case, name, add, result):
    if (case['fixture'].get('fault') or {}).get('driver_kind') == 'sink-open':
        for order in ('before', 'after'):
            def healthy_sink(fixture):
                fixture['fault'] = None
                fixture.pop('fault_scope', None)
            add('healthy-image-' + order, healthy_sink,
                {'source': 'same built engine and instrumentation image, unmodified sink operations',
                 'visible_status': 200, 'backend_arrivals': 1})
            result[-1]['control_order'] = order
    if name == 'clean_shutdown':
        add('strict-admission', lambda f: f['policy'].update(phase4_mode='strict'),
            {'source': 'selected forwardauth route capability strict_post_commit_action',
             'configuration_rejected_before_traffic': True,
             'requires_independent_route_registry_binding': True})
        result[-1]['classification'] = 'config'


def capacity_controls(case, name, add, result):
    if name == 'NEED-host-auth-response-32768-bound':
        for size, status, backend in ((32768, 200, 1), (32769, 401, 0)):
            add('cap' + str(size), lambda f, n=size: f['relay'].update(authorization_body_size=n),
                {'source': 'pinned Traefik forward.go maxResponseBodySize',
                 'native_authorization_status': 200, 'visible_status': status,
                 'backend_arrivals': backend, 'synthetic_relay_body': True,
                 'actual_request_body_bytes':len(bytes.fromhex(case['fixture']['request']['body_hex'])),
                 'observer_mode': 'default-mrc1', 'outer_provenance_enabled': False})
    if name == 'NEED-host-request-buffer-bound':
        for size, status, authorizations in ((4096, 200, 1), (4097, 401, 0)):
            def request_size(fixture, n=size):
                fixture['request'].update(body_hex=(b'A' * n).hex(), chunk_lengths=[n])
            add('sample' + str(size), request_size,
                {'source': 'pinned Traefik forward.go maxBodySize',
                 'visible_status': status, 'authorization_arrivals': authorizations})
            result[-1]['independent_control_expectation'].update(observer_mode='default-mrc1',outer_provenance_enabled=False)


def handle_controls(name, add):
    if name == 'NEED-observer-response-eos':
        for mode in ('missing', 'malformed', 'unknown64hex', 'expired'):
            add('handle-' + mode, lambda f, m=mode: f['relay'].update(handle=m),
                {'source': 'MRC1 claim contract and actual engine expiry',
                 'visible_status': 503, 'original_handle_registered': True,
                 'immediate_per_request_free_required': False})


def original_metadata_controls(name, add):
    if name == 'phase1_allow':
        for label, method, spoof, status in (
                ('post-original', 'POST', 'GET', 403),
                ('get-original', 'GET', 'POST', 200)):
            def method_fixture(fixture, m=method, s=spoof):
                fixture['request'].update(method=m, uri='/i12/original-method',
                    body_hex='', chunk_lengths=[])
                fixture['request']['headers'] = [['X-Forwarded-Method', s]]
                fixture['rules_lines'] += ['SecRule REQUEST_METHOD "@streq POST" '
                    '"id:1999501,phase:1,deny,status:403,log,t:none"']
            add(label, method_fixture,
                {'source': 'pinned forward.go preserveRequestMethod and trustForwardHeader=false',
                 'native_method': method, 'visible_status': status})
        def uri_fixture(fixture):
            fixture['request'].update(method='GET', uri='/i12/original?value=%C3%A4',
                body_hex='', chunk_lengths=[])
            fixture['request']['headers'] = [['X-Forwarded-Uri', '/forged'],
                ['X-Original-Uri', '/also-forged'], ['X_Forwarded_Uri', '/underscore-forged']]
            fixture['rules_lines'] += ['SecRule REQUEST_URI_RAW "@streq /i12/original?value=%C3%A4" '
                '"id:1999502,phase:1,deny,status:403,log,t:none"']
        add('uri-original', uri_fixture,
            {'source': 'pinned forward.go regenerated X-Forwarded-Uri; SDK3.0.14 transaction.cc REQUEST_URI_RAW',
             'native_uri': '/i12/original?value=%C3%A4', 'visible_status': 403})


def controls(case):
    result = []

    def add(label, edit, expected):
        value = copy.deepcopy(case)
        value['probe_id'] += '-' + label
        value['control_name'] = label
        value['original_id'] = case['id']
        edit(value['fixture'])
        if value['fixture'].get('physical_file_supplement'):
            headers = value['fixture']['request']['headers']
            value['fixture']['request']['headers'] = [pair for pair in headers if pair[0].lower() != 'x-i12-acceptance-key'] + [['X-I12-Acceptance-Key', value['probe_id']]]
        value['independent_control_expectation'] = expected
        # No original fixture digest is inherited after a control mutation.
        value['fixture_sha256'] = None
        result.append(value)

    name = case['case_id']
    binding = file_binding(case)
    file_controls(binding, add, result)
    causal_controls(case, name, add)
    sink_and_shutdown_controls(case, name, add, result)
    capacity_controls(case, name, add, result)
    handle_controls(name, add)
    original_metadata_controls(name, add)
    return result
