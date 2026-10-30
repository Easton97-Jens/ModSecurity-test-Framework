"""Bind all original native IDs to explicit stimuli; never qualify a result.

The frozen inventory and independent proposal file are inputs, not generated
expectations from host observations. File-API and other unresolved contracts
remain visible and cannot become a passing HTTP transaction by renaming it.
"""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path

ROUTE = 'traefik-native-uds'
PREFIX = 'I12::' + ROUTE + '::'
ALLOW_URI = '/no-crs/allow'
PLAIN_TYPE = 'text/plain'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def json_digest(value):
    return digest(json.dumps(value, sort_keys=True, separators=(',', ':')).encode())


def rules_block(path):
    text = path.read_text()
    if '\nrules: |\n' not in '\n' + text:
        return None
    tail = ('\n' + text).split('\nrules: |\n', 1)[1]
    lines = []
    for line in tail.splitlines():
        if line and not line.startswith('  '):
            break
        if '@@AUDIT_' not in line:
            lines.append(line[2:] if line.startswith('  ') else '')
    return lines


def default_fixture():
    return {'request': {'method': 'GET', 'uri': ALLOW_URI, 'headers': [],
                        'body_hex': '', 'chunk_lengths': []},
            'backend': {'status': 200, 'headers': [['Content-Type', PLAIN_TYPE]],
                        'body_hex': b'i12-independent-backend-response\n'.hex(), 'chunk_lengths': [7, 12, 14]},
            'policy': {'phase4_mode': 'safe'}, 'fault': None}


def canonical_document(row, chain, request, framework):
    """Read pinned fixture data only; never execute a Framework runner."""
    import yaml
    runner = row['original_contract'].get('runner_case') or request.get('fixture')
    if not runner:
        runner = next((source.get('runner_case') for source in chain if source.get('runner_case')), None)
    if not runner:
        return {}, None
    relative = Path(runner)
    if not relative.is_absolute() and not str(relative).startswith('tests/'):
        relative = Path('tests/cases/no-crs-baseline') / relative
    path = (framework / relative).resolve()
    if not path.is_relative_to(framework.resolve()):
        raise ValueError('canonical fixture escapes read-only Framework root')
    if not path.is_file():
        return {}, None
    raw = path.read_bytes()
    document = yaml.safe_load(raw)
    if not isinstance(document, dict):
        raise ValueError('canonical fixture must be a mapping')
    return document, {'path': str(path), 'sha256': digest(raw)}


def header_pairs(headers):
    if isinstance(headers, dict):
        return [[str(key), str(value)] for key, value in headers.items()]
    return [[str(item['name']), str(item['value'])] for item in headers]


def literal_chunks(body, chunks):
    if chunks is None:
        return [len(body)] if body else []
    encoded = [str(piece).encode() for piece in chunks]
    if b''.join(encoded) != body or any(not piece for piece in encoded):
        raise ValueError('literal YAML chunks do not exactly reproduce the declared body')
    return list(map(len, encoded))


def canonical_wire_fixture(fixture, document, catalog_request):
    request = copy.deepcopy(document.get('request') or {}) | copy.deepcopy(catalog_request)
    body = request.get('body_fixture', request.get('body', ''))
    raw = str(body).encode() if body is not None else b''
    lifecycle = document.get('full_lifecycle') or {}
    fixture['request'].update(method=request.get('method', 'GET'), uri=request.get('path', ALLOW_URI),
        headers=header_pairs(request.get('headers', [])), body_hex=raw.hex(),
        chunk_lengths=literal_chunks(raw, lifecycle['request_chunks']) if 'request_chunks' in lifecycle else [])
    response = copy.deepcopy(document.get('response') or {})
    response_body = request.get('response_body_fixture', response.get('body'))
    if response_body is not None:
        body = str(response_body).encode()
        fixture['backend'].update(body_hex=body.hex(), chunk_lengths=literal_chunks(body, lifecycle.get('response_chunks')))
    if 'headers' in response:
        fixture['backend']['headers'] = header_pairs(response['headers'])
    canonical_content_type(fixture, request, response, lifecycle)
    fixture['backend']['status'] = response.get('status', 200)
    if request.get('response_fixture'):
        name, separator, value = request['response_fixture'].partition(':')
        if not separator:
            raise ValueError('unsupported source response header fixture')
        fixture['backend']['headers'] = [[key, val] for key, val in fixture['backend']['headers'] if key.lower() != name.strip().lower()]
        fixture['backend']['headers'].append([name.strip(), value.strip()])
    fixture['canonical_wire_request'] = copy.deepcopy(request)
    fixture['canonical_yaml_fields'] = {key: copy.deepcopy(document.get(key, {})) for key in ('request', 'response', 'full_lifecycle')}
    return request


def canonical_fixture(row, catalog, framework, baseline):
    case = row['original_catalog_case']
    request = copy.deepcopy(case.get('request', {}))
    visited = {case['case_id']}
    chain = [case]
    while 'reuses' in request:
        name = request.pop('reuses')
        if name in visited or name not in catalog:
            raise ValueError('invalid original request reuse: ' + name)
        visited.add(name)
        chain.append(catalog[name])
        request = copy.deepcopy(catalog[name].get('request', {})) | request
    fixture = default_fixture()
    fixture['resolved_catalog_request'] = copy.deepcopy(request)
    fixture['resolved_catalog_request_sha256'] = json_digest(request)
    fixture['catalog_request_resolution'] = {
        'original_case_id': case['case_id'], 'resolver': 'catalog reuses base request followed by child request overlay',
        'ordered_sources': [{'case_id': source['case_id'], 'catalog_case_sha256': json_digest(source),
            'original_request': copy.deepcopy(source.get('request', {})),
            'original_request_sha256': json_digest(source.get('request', {}))} for source in chain]}
    document, source = canonical_document(row, chain, request, framework)
    request = canonical_wire_fixture(fixture, document, request)
    fixture['rules_lines'] = baseline.splitlines()
    if source:
        exact = rules_block(Path(source['path']))
        if exact:
            fixture['rules_lines'] += exact
        fixture['canonical_rules_composition'] = 'shared no-crs-baseline.conf followed by runner-specific directives; no CRS'
        fixture['canonical_rules_source'] = source
    canonical_stimuli(fixture, case, request, document, source)
    fixture['request']['raw_template'] = request.get('raw_template')
    fixture['request']['adapter_fixture'] = request.get('adapter_fixture')
    return fixture


def constraints(case):
    required = ['waited_client_exit_signal', 'independent_backend_count_and_bytes',
                'actual_host_callbacks', 'native_api_and_host_eos_separate',
                'physical_commit', 'runtime_finish_logging_free_separate',
                'neighbor_control', 'exact_uid_pid_maps_and_cleanup']
    unresolved = []
    if case in ('NEED-request-file', 'NEED-response-file'):
        unresolved.append('Public host streaming route has no file-body callback. Actual native file API '
                          'and independent original-contract applicability review required; ordinary HTTP is insufficient.')
    if case == 'NEED-mrc1-error':
        unresolved.append('Native host route is MSE1; MRC1 belongs to explicit response companion. '
                          'No MSE1 fault may be relabelled MRC1; independent original-contract adjudication required.')
    if case in ('response_short_write_resume', 'response_write_would_block_resume'):
        required += ['actual_host_socket_write_short_or_eagain', 'resume_without_duplicate_native_append']
    if 'charset' in case:
        required += ['actual_non_ascii_client_backend_bytes', 'native_selection_accessor_or_debug']
    if 'mime' in case or 'content-type' in case or case.endswith('-csv'):
        required += ['actual_native_mime_gate']
    if 'stream' in case or 'split_across_chunks' in case:
        required += ['at_least_two_actual_native_append_calls']
    return required, unresolved


def file_supplements(originals):
    """Physical file-backed HTTP contrasts; never promote native File-API IDs."""
    harness = test_root() / 'connector_suite/adapters/traefik/harness'
    manifest_path = harness / 'fixtures/i12-file-source/manifest.json'
    plan_path = harness / 'i12_file/supplement-plan.json'
    contract_path = harness / 'i12_file/acceptance.py'
    contract = load_source(contract_path)
    manifest = json.loads(manifest_path.read_text())
    if manifest.get('schema') != 'traefik-physical-file-fixtures-v1' or manifest.get('native_file_api') is not False:
        raise ValueError('physical HTTP file manifest required')
    files = {entry['relative_path']: entry for entry in manifest['files']}
    if len(files) != len(manifest['files']) or set(files) != set(contract.FIXTURES):
        raise ValueError('all four distinct physical file controls required')
    validate_file_fixtures(files, manifest_path.parent, contract)
    declarations = {(row['id'], row['file_spec']['relative_path']): row for row in contract.cases()}
    supplements = []
    for original in originals:
        name = original['id'].rsplit('::', 1)[-1]
        if name not in ('NEED-request-file', 'NEED-response-file'):
            continue
        response = name == 'NEED-response-file'
        for filename in ('benign.txt', 'response-marker.txt' if response else 'request-marker.txt'):
            variant = file_variant(original, filename, response, declarations, files,
                (manifest_path, plan_path, contract_path), contract)
            supplements.append(variant)
    return supplements


def validate_file_fixtures(files, fixture_root, contract):
    for filename, entry in files.items():
        path = fixture_root / filename
        if ((entry['size'], entry['sha256']) != contract.FIXTURES[filename] or entry['read_size'] != 24 or
                path.is_symlink() or not path.is_file() or path.stat().st_size != entry['size'] or
                digest(path.read_bytes()) != entry['sha256']):
            raise ValueError('exact physical file fixture required: ' + filename)


def build(inventory, proposals, framework, minimal_correction=None):
    rows = [r for r in inventory['rows'] if r['route'] == ROUTE]
    if len(rows) != 118 or len({r['id'] for r in rows}) != 118:
        raise ValueError('exact original native118 inventory required')
    originals = {r['id']: r for r in proposals['rows'] if r['route'] == ROUTE}
    if len(originals) != 55:
        raise ValueError('all original55 native oracle proposals required')
    catalog = {r['original_catalog_case']['case_id']: r['original_catalog_case']
               for r in rows if r.get('original_catalog_case')}
    rules = framework / 'tests/rules/no-crs-baseline.conf'
    baseline = rules.read_text()
    result = []
    for index, row in enumerate(rows):
        name = row['original_contract']['case_id']
        proposal = originals.get(row['id'])
        fixture = copy.deepcopy(proposal['fixture']) if proposal else canonical_fixture(row, catalog, framework, baseline)
        required, unresolved = constraints(name)
        # Proposal faults which need an actual response prefix get a large,
        # explicit stimulus override. Never conceal this as an unchanged SDK fixture.
        overrides = stimulus_overrides(fixture, name, row, minimal_correction)
        key = f'{index:03d}-' + digest(row['id'].encode())[:12]
        expected = copy.deepcopy(proposal['expected'] if proposal else row['original_contract']['expected_oracle'])
        controls = {}
        for stage in ('main-before', 'main-after'):
            control = copy.deepcopy(fixture)
            control['request'].update(uri='/i12/reuse/' + stage + '/' + key,
                raw_template=None, omit_transaction_id=False)
            control['fault'] = None
            controls[stage] = {'request_overrides': control['request'],
                               'fixture_sha256': json_digest(control), 'expected': None,
                               'approval': False, 'qualification': None}
        result.append({'id': row['id'], 'key': key, 'transaction_id': 'tf-a-' + key,
            'neighbor_id': 'tf-n-' + key, 'original_contract': row['original_contract'],
            'positive_control_id': 'tf-c-' + key,
            'sequence_ids': ['tf-s' + str(i) + '-' + key for i in range(3)] if fixture.get('sequence') else [],
            'main_before_id': 'tf-b-' + key, 'main_after_id': 'tf-r-' + key,
            'readiness_ids': ['tf-ready-' + key + '-' + str(i) for i in range(10)],
            'main_controls': controls,
            'classification': row['classification'], 'original124_member': row['original124_member'],
            'fixture': fixture, 'fixture_sha256': json_digest(fixture),
            'independent_proposal_fixture_sha256': json_digest(proposal['fixture']) if proposal else None,
            'explicit_stimulus_overrides': overrides,
            'expected': expected, 'expected_approval': False,
            'required_measurements': required, 'contract_blockers': unresolved,
            'qualification': None, 'runtime_status': 'pending'})
    supplementary = build_supplements(result)
    supplementary += file_supplements(result)
    return {'schema_version': 1, 'route': ROUTE, 'original_id_count': 118,
            'original_oracle_count': 55, 'qualification_promotions': 0,
            'baseline_rules': {'path': str(rules), 'sha256': digest(rules.read_bytes())},
            'cases': result, 'supplementary_executions': supplementary}


def apply_selection(manifest, source_path, kind):
    """Select executions without dropping original inventory or broadening keys."""
    if kind not in ('ids', 'keys'):
        raise ValueError('unknown selection kind')
    raw = source_path.read_bytes()
    selected = json.loads(raw)
    if (not isinstance(selected, list) or not selected
            or any(not isinstance(value, str) or not value for value in selected)
            or len(set(selected)) != len(selected)):
        raise ValueError('Retake selection must be a nonempty unique list of strings')
    executions = manifest['cases'] + manifest['supplementary_executions']
    all_keys = [case['key'] for case in executions]
    if len(set(all_keys)) != len(all_keys):
        raise ValueError('Manifest execution keys must be unique')
    field = 'id' if kind == 'ids' else 'key'
    known = {case[field] for case in (manifest['cases'] if kind == 'ids' else executions)}
    if not set(selected) <= known:
        raise ValueError('Retake selection contains unknown original IDs or execution keys')
    manifest['selected_keys'] = [case['key'] for case in executions if case[field] in selected]
    manifest['selection_source'] = {
        'path': str(source_path), 'sha256': digest(raw), 'kind': kind}


def canonical_content_type(fixture, request, response, lifecycle):
    if 'content_type_variant' in request:
        variant = request['content_type_variant']
        variants = lifecycle.get('variants', {})
        if variant not in variants:
            raise ValueError('unknown canonical Content-Type variant: ' + str(variant))
        response['content_type'] = variants[variant]
    if 'content_type' in response:
        fixture['backend']['headers'] = [[key, value] for key, value in fixture['backend']['headers'] if key.lower() != 'content-type']
        if response['content_type'] is not None:
            fixture['backend']['headers'].append(['Content-Type', str(response['content_type'])])


def canonical_stimuli(fixture, case, request, document, source):
    name = case['case_id']
    phase = case.get('phase')
    if not source and (phase == 4 or 'response-body' in str(request)) and not request.get('response_body_fixture'):
        raw = b'no-crs-response-body-marker'
        fixture['backend'].update(body_hex=raw.hex(), chunk_lengths=[7, 12, len(raw) - 19])
    if not source and name in ('phase2_marker_split_across_chunks',):
        raw = b'no-crs-request-body-marker'
        fixture['request'].update(method='POST', uri='/no-crs/request-body',
            headers=[['Content-Type', PLAIN_TYPE]], body_hex=raw.hex(), chunk_lengths=[7, len(raw)-7])
    synchronized = document.get('full_lifecycle', {}).get('synchronization', {}).get('upstream_waits_for_test_barrier')
    late = document.get('full_lifecycle', {}).get('response_committed_before_marker')
    if synchronized or late:
        raw = bytes.fromhex(fixture['backend']['body_hex'])
        marker = raw.find(b'no-crs-response-body-marker')
        if marker <= 0:
            raise ValueError('source-required prefix barrier has no literal prefix before marker')
        fixture['backend'].update(chunk_lengths=[marker, len(raw) - marker], barrier=True)
    canonical_case_behavior(fixture, name)


def canonical_case_behavior(fixture, name):
    if name in ('event_metadata_truncation', 'event_json_limit'):
        fixture['request']['headers'].append(['X-Modsec-Smoke', 'log-only'])
        fixture['request']['uri'] = '/no-crs/log-only?' + ('metadata=' + 'M' * 1500)
        fixture['event_limit_variants'] = [1024, 16384]
    if name == 'transaction_id_generated_or_fallback':
        fixture['request']['omit_transaction_id'] = True
    if name in ('response_short_write_resume', 'response_write_would_block_resume'):
        raw = b'A' * (2 * 1024 * 1024) + b'no-crs-response-body-marker'
        fixture['backend'].update(body_hex=raw.hex(), chunk_lengths=[8192] * 256 + [len(raw)-2097152])
        fixture['request']['slow_reader'] = True
    if name.startswith('engine_timeout'):
        fixture['fault'] = {'kind': name, 'delay_ms': 5500, 'configured_deadline_ms': 5000}
    if name in ('early_mapping_failure_cleanup', 'transaction_begin_failure_cleanup', 'finish_failure_propagation'):
        fixture['fault'] = {'kind': name}
    if name == 'multiple_sequential_requests':
        fixture['sequence'] = ['allow_without_marker', 'deny_header_marker_403', 'allow_without_marker']
    if name == 'phase4_deny_after_commit_log_only_minimal':
        fixture['policy']['phase4_mode'] = 'minimal'


def physical_sink_override(fixture, name, row, overrides):
    if not name.startswith('NEED-physical-event-sink-'):
        return
    original_fault = copy.deepcopy(fixture.get('fault'))
    operation = name.removeprefix('NEED-physical-event-sink-')
    error_number = {'open': 'EACCES', 'short-write': 'EFBIG'}.get(operation, 'EBADF')
    fault_scope = {'close': 'service_shutdown', 'open': 'service_startup'}.get(operation, 'selected_request')
    fixture['explicit_fault_reconciliation'] = {
        'original_fault': original_fault, 'effective_operation': operation,
        'effective_errno': error_number,
        'independent_source': 'Linux openat/fputs/fflush/fclose with actual inode modes, atomically installed same-inode readonly FD, RLIMIT_FSIZE; fclose only at physically single-thread shutdown',
        'effective_fault_scope': fault_scope,
        'expected_approval': False, 'runtime_qualified': False}
    overrides.append('Physical POSIX fault mechanism made explicit; historical proposed errno preserved, not relabelled')
    target_uri = fixture['request']['uri']
    fixture['rules_lines'].append('SecRule REQUEST_URI "@streq ' + target_uri + '" "id:1999398,phase:1,deny,status:403,log,msg:\'i12 physical sink target\'"')
    if operation in ('write', 'short-write', 'flush'):
        recovery_uri = '/i12/sink-recovery/' + digest(row['id'].encode())[:12]
        fixture['sink_recovery_control'] = {'uri': recovery_uri, 'expected_native_rule_id': 1999397,
            'expected_native_status': 403, 'expected_approval': False}
        fixture['rules_lines'].append('SecRule REQUEST_URI "@streq ' + recovery_uri + '" "id:1999397,phase:1,deny,status:403,log,msg:\'i12 physical sink recovery\'"')
    overrides.append('Target-only native P1 Deny forces real Common event; prior nondisruptive pass/log stimulus never reached sink; host error outcome needs independent source review')


def stimulus_overrides(fixture, name, row, minimal_correction):
    overrides = []
    if name == 'phase4_deny_after_commit_log_only_minimal' and minimal_correction:
        fixture['policy']['phase4_mode'] = 'off'
        fixture['literal_negative_config_modes'] = ['minimal']
        fixture['explicit_contract_correction'] = minimal_correction
        overrides.append('Original minimal ID retained; explicit #376 migration contract proposes current Off fixture; literal minimal remains negative parser control')
    if name in ('NEED-cancel', 'NEED-abort-reset-observation', 'NEED-client-exit-signal', 'NEED-incomplete-framing', 'NEED-no-second-response', 'engine_timeout_after_commit'):
        fixture['backend'].update(body_hex=(b'A' * 16384).hex(), chunk_lengths=[8192, 4096, 4096], barrier=True)
        overrides.append('16384-byte backend, first8192 then delayed suffix for physically active cancellation/postcommit')
    if name in ('response_short_write_resume', 'response_write_would_block_resume'):
        fixture['rules_lines'] += ['SecResponseBodyLimit 4194304', 'SecResponseBodyLimitAction Reject']
        overrides.append('Explicit native response4MiB/Reject policy for2MiB slow-reader stimulus; default partial policy cannot prove tail marker inspection')
    if name == 'NEED-commit-ack-applied':
        fixture['rules_lines'].append('SecAction "id:1999399,phase:1,deny,status:403,log"')
        overrides.append('P1 deny ensures actual AcknowledgeApplied opcode10 is exercised before writer commit')
    physical_sink_override(fixture, name, row, overrides)
    return overrides


def build_supplements(result):
    return capacity_supplements(result) + backpressure_supplements(result) + charset_supplements(result)

def capacity_supplements(result):
    supplementary = []
    for original in result:
        if original['id'].endswith('::event_json_limit'):
            variant = copy.deepcopy(original)
            suffix = '-cap1024'
            variant['key'] += suffix
            for field in ('transaction_id', 'neighbor_id', 'positive_control_id', 'main_before_id', 'main_after_id'):
                variant[field] += suffix
            variant['readiness_ids'] = [value + suffix for value in variant.get('readiness_ids', [])]
            variant['fixture']['max_event_json_bytes'] = 1024
            variant['fixture_sha256'] = json_digest(variant['fixture'])
            variant['supplementary_to_key'] = original['key']
            variant['assertion_scope'] = 'explicit 1024-byte event-capacity contrast; own independent oracle review required'
            variant['expected'] = None
            variant['expected_approval'] = False
            supplementary.append(variant)
    return supplementary

def backpressure_supplements(result):
    supplementary = []
    for original in result:
        if not original['id'].endswith(('::response_short_write_resume', '::response_write_would_block_resume')):
            continue
        variant = copy.deepcopy(original)
        suffix = '-bp8m'
        variant['key'] += suffix
        for field in ('transaction_id', 'neighbor_id', 'positive_control_id', 'main_before_id', 'main_after_id'):
            variant[field] += suffix
        variant['readiness_ids'] = [value + suffix for value in variant.get('readiness_ids', [])]
        end_marker = b'no-crs-response-body-marker'
        payload = b'A' * (8 * 1024 * 1024) + end_marker
        remaining = len(payload) - 8192
        chunks = [8192]
        while remaining:
            size = min(32768, remaining)
            chunks.append(size)
            remaining -= size
        variant['fixture']['backend'].update(body_hex=payload.hex(), chunk_lengths=chunks, barrier=True)
        variant['fixture']['request'].update(slow_reader=False, kernel_backpressure=True)
        variant['fixture']['main_control_backend'] = default_fixture()['backend']
        variant['fixture']['main_control_override_reason'] = 'Explicit33byte healthy control; target8MiB response remains unchanged; same main engine/config/PID'
        variant['fixture']['target_timeout_seconds'] = 120
        variant['fixture']['transport_budget_approval'] = 'pending independent throughput control and Root review'
        lines = variant['fixture']['rules_lines']
        variant['fixture']['rules_lines'] = [line for line in lines if not line.startswith(('SecResponseBodyLimit ', 'SecResponseBodyLimitAction '))] + [
            'SecResponseBodyLimit 16777216', 'SecResponseBodyLimitAction Reject']
        variant['fixture']['syscall_observer'] = {'nonce': variant['key'], 'seconds': 180, 'peer_port': 0,
            'capture': 'own child only; actual tuple and real kernel returns', 'expected_approval': False}
        variant['fixture_sha256'] = json_digest(variant['fixture'])
        variant['supplementary_to_key'] = original['key']
        variant['explicit_stimulus_overrides'] += ['Exact8MiB benignprefix plus originalrule1100301 tailmarker, backendbarrier after8192cliententitybytes, native16MiB Reject limit, unmodified receivebuffer with actual getsockopt receipt, explicit33byte healthy controls, target-only120second budget pending independent calibration, pause after8192actualentitybytes until actualtargettupleEAGAIN or bounded8seconds; drain unthrottled afterward']
        variant['assertion_scope'] = 'Actual kernel shortwrite/EAGAIN and resume; missing kernel result remains unqualified'
        variant['expected'] = None
        variant['expected_approval'] = False
        supplementary.append(variant)
    # These are additional actual-byte experiments under the existing charset
    # IDs. Original fixtures remain unchanged; SDK/source approval precedes use.
    return supplementary

def charset_supplements(result):
    supplementary = []
    for original in result:
        name = original['id'].rsplit('::', 1)[-1]
        if name not in ('NEED-request-charset-present', 'NEED-request-charset-missing',
                        'NEED-response-charset-present', 'NEED-response-charset-missing'):
            continue
        response = name.startswith('NEED-response')
        variants = [('utf8-match', '636166c3a9', 'text/plain; charset=utf-8'),
                    ('latin1-match', '636166e9', 'text/plain; charset=iso-8859-1'),
                    ('utf8-as-latin1', '636166c3a9', 'text/plain; charset=iso-8859-1'),
                    ('latin1-as-utf8', '636166e9', 'text/plain; charset=utf-8')]
        if name.endswith('-missing'):
            variants = [('utf8-missing', '636166c3a9', PLAIN_TYPE),
                        ('latin1-missing', '636166e9', PLAIN_TYPE)]
        for label, body_hex, content_type in variants:
            supplementary.append(charset_variant(original, response, label, body_hex, content_type))
    return supplementary

def charset_variant(original, response, label, body_hex, content_type):
    variant = copy.deepcopy(original)
    suffix = '-cs-' + label
    variant['key'] += suffix
    for field in ('transaction_id', 'neighbor_id', 'positive_control_id', 'main_before_id', 'main_after_id'):
        variant[field] += suffix
    variant['readiness_ids'] = [value + suffix for value in variant.get('readiness_ids', [])]
    side = variant['fixture']['backend' if response else 'request']
    side.update(body_hex=body_hex, chunk_lengths=[len(bytes.fromhex(body_hex))])
    side['headers'] = [[k, v] for k, v in side.get('headers', []) if k.lower() != 'content-type'] + [['Content-Type', content_type]]
    # Identical byte operator across matching, cross-declared and absent
    # charset controls. No inferred decoding or inspection-byte count.
    lines = variant['fixture']['rules_lines']
    variant['fixture']['rules_lines'] = [line for line in lines if not line.startswith('SecRule ')] + [
        'SecRule ' + ('RESPONSE_BODY' if response else 'REQUEST_BODY') +
        ' "@rx \\xE9" "id:1999381,phase:' + ('4' if response else '2') + ',deny,status:403,t:none"']
    variant['fixture_sha256'] = json_digest(variant['fixture'])
    variant['supplementary_to_key'] = original['key']
    variant['explicit_stimulus_overrides'] += ['Actual non-ASCII byte/declared charset contrast with identical raw-byte regex E9; independent SDK expectation review required']
    variant['assertion_scope'] = 'retained SDK bytes plus contrasting rule/intervention; retained length alone does not prove inspection'
    variant['expected'] = None
    variant['expected_approval'] = False
    return variant

def file_variant(original, filename, response, declarations, files, sources, contract):
    manifest_path, plan_path, contract_path = sources
    declared = declarations[(original['id'], filename)]
    variant = copy.deepcopy(original)
    suffix = '-file-' + filename.removesuffix('.txt')
    variant['key'] += suffix
    for field in ('transaction_id', 'neighbor_id', 'positive_control_id', 'main_before_id', 'main_after_id'):
        variant[field] += suffix
    variant['readiness_ids'] = [value + suffix for value in variant.get('readiness_ids', [])]
    variant['fixture']['request'].update(method='GET' if response else 'POST',
        uri=ALLOW_URI if response else '/no-crs/request-body',
        body_hex='', chunk_lengths=[], raw_template=None, omit_transaction_id=False)
    variant['fixture']['request']['headers'] = [['Content-Type', PLAIN_TYPE]]
    variant['fixture']['backend'] = {
        'status': 200, 'headers': [['Content-Type', PLAIN_TYPE]],
        'body_hex': contract.BACKEND_BODY.hex(), 'chunk_lengths': [len(contract.BACKEND_BODY)]}
    variant['fixture']['rules_lines'] = list(declared['rules_lines'])
    variant['fixture']['fault'] = None
    variant['fixture']['policy']['phase4_mode'] = 'safe'
    variant['fixture']['file_supplement'] = {
        'physical_reader': 'backend' if response else 'client', 'fixture': filename,
        'file_spec': copy.deepcopy(files[filename]),
        'manifest_sha256': digest(manifest_path.read_bytes()),
        'supplement_plan_sha256': digest(plan_path.read_bytes()),
        'rules_source_sha256': digest(contract_path.read_bytes()),
        'rules_sha256': declared['rules_sha256'],
        'native_file_api': False, 'backend_exclusion_expected': False,
        'strict_scope': 'separate actual profile-start configuration negative only'}
    variant['fixture_sha256'] = json_digest(variant['fixture'])
    variant['supplementary_to_key'] = original['key']
    variant['assertion_scope'] = 'Physical file-read to HTTP transport; native File-API applicability remains unresolved; native P2 denial may follow backend entry'
    variant['expected'] = None
    variant['expected_approval'] = False
    return variant


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', type=Path, required=True)
    parser.add_argument('--proposals', type=Path, required=True)
    parser.add_argument('--framework', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--minimal-correction', type=Path)
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument('--selected-ids', type=Path)
    selection.add_argument('--selected-keys', type=Path)
    args = parser.parse_args()
    helpers = load_source(Path(__file__).with_name('prepare.py'))
    output = helpers.validate_output(args.output, fresh=True)
    correction = None
    if args.minimal_correction:
        source = json.loads(args.minimal_correction.read_text())
        correction = {'path': str(args.minimal_correction), 'sha256': digest(args.minimal_correction.read_bytes()),
                      'migration_commit': source['migration_commit'], 'qualified': False}
    manifest = build(json.loads(args.inventory.read_text()), json.loads(args.proposals.read_text()), args.framework, correction)
    if args.selected_ids:
        apply_selection(manifest, args.selected_ids, 'ids')
    elif args.selected_keys:
        apply_selection(manifest, args.selected_keys, 'keys')
    manifest['input_bindings'] = {str(p): digest(p.read_bytes()) for p in (args.inventory, args.proposals)}
    output.write_text(json.dumps(manifest, indent=2) + '\n')


if __name__ == '__main__':
    main()
