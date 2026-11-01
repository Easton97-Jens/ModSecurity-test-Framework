#!/usr/bin/env python3
"""Stage selected exact-original Envoy packets; qualification needs individual Root approval.

Remote Process status remains unknown when the physical trace only proves local
HTTP/2 reset 2. That limited closure contract is the previously reviewed scope,
not a successful remote gRPC completion. No shared ledger is written.
"""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_source
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

HERE = Path(__file__).resolve().parent
REPO = connector_root()
CLIENT_RESPONSE_BYTES_ID = 'I12::envoy-ext-proc::NEED-client-response-bytes'
CLIENT_EXIT_SIGNAL_ID = 'I12::envoy-ext-proc::NEED-client-exit-signal'
AUTHZ_CLIENT_RESPONSE_BYTES_ID = 'I12::envoy-ext-authz-request::NEED-client-response-bytes'
AUTHZ_REQUEST_MULTIPLE_CHUNKS_ID = 'I12::envoy-ext-authz-request::NEED-request-multiple-chunks'
ALLOWED = frozenset((
    'I12::envoy-ext-proc::NEED-request-streaming',
    'I12::envoy-ext-proc::NEED-response-streaming',
    'I12::envoy-ext-authz-request::NEED-complete-sample',
    'I12::envoy-ext-authz-response-companion::NEED-allow',
    CLIENT_RESPONSE_BYTES_ID,
    CLIENT_EXIT_SIGNAL_ID,
    AUTHZ_CLIENT_RESPONSE_BYTES_ID,
    AUTHZ_REQUEST_MULTIPLE_CHUNKS_ID,
))

import modsecurity_connector_ci.runtime.lifecycle.i12.envoy.review_runs as REVIEW
import modsecurity_connector_ci.runtime.lifecycle.i12.envoy.evidence_io as EVIDENCE

SHAPE_FILE = 'shape.json'
BACKEND_RECEIPTS = 'backend/receipts.jsonl'
TARGET_CLIENT_RECEIPT = 'client/target.receipt.json'
ENVOY_STDERR = 'envoy.stderr'
REQUEST_HEADERS_COMPLETE = 'request headers complete (end_stream=false):'
REQUEST_END_STREAM = 'request end stream timestamp recorded'
AUTHZ_BUFFERING = 'ext_authz filter is buffering the request'
AUTHZ_BUFFERED = 'ext_authz filter finished buffering the request since stream is ended'
AUTHZ_DISPATCH = "cluster 'msconnector_composite' match for URL '/envoy.service.auth.v3.Authorization/Check'"
AUTHZ_BUFFERING_CHAIN = (
    'decode headers called: filter=envoy.filters.http.header_mutation status=0',
    AUTHZ_BUFFERING, 'setting buffer limit to 4096',
    'decode headers called: filter=envoy.filters.http.ext_authz status=1',
)
STORAGE = EVIDENCE.configured_storage(required=False)
RUNROOT = STORAGE / 'runs/i12-envoy-410-20261015' if STORAGE is not None else None
READ_ROOTS = (REPO, test_root()) + ((RUNROOT, STORAGE / 'runs/e2e/20261014T182400Z-pr410-oracle-lifecycle')
                        if STORAGE is not None else ())


def require_runroot():
    if RUNROOT is None:
        raise ValueError('CODEX_PROJECT_STATE configuration required for Envoy evidence operations')
    return RUNROOT


def shared_validator():
    path = source_path('ci/evidence/reports/generate-pr382-i12-lifecycle-ledger.py', root=REPO)
    module = load_source(path)
    return module


def canonical(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def load(path):
    try:
        return EVIDENCE.read_json(path, roots=READ_ROOTS)
    except (OSError, ValueError):
        raise ValueError('evidence input rejected') from None


def read_bytes(path):
    try:
        return EVIDENCE.read_bytes(path, roots=READ_ROOTS)
    except (OSError, ValueError):
        raise ValueError('evidence input rejected') from None


def reference(path, role=None):
    try:
        result = EVIDENCE.reference(path, roots=READ_ROOTS)
    except (OSError, ValueError):
        raise ValueError('evidence reference rejected') from None
    if role:
        result['role'] = role
    return result


def verify_ref(ref):
    actual = reference(ref['path'], ref.get('role'))
    if actual['sha256'] != ref['sha256'] or ('bytes' in ref and actual['bytes'] != ref['bytes']):
        raise ValueError('physical reference changed: ' + ref['path'])
    return actual


def require_ancestor_owner(directory):
    if os.fstat(directory).st_uid not in (0, os.geteuid()):
        raise ValueError('output authority rejected')


def require_output_directory(directory, private=False):
    status = os.fstat(directory)
    mask = 0o077 if private else 0o022
    if status.st_uid != os.geteuid() or stat.S_IMODE(status.st_mode) & mask:
        message = 'private task output root required' if private else 'output directory authority rejected'
        raise ValueError(message)


def write(path, value):
    runroot = require_runroot()
    target = Path(path)
    try:
        relative = target.relative_to(runroot)
    except ValueError:
        raise ValueError('output must be a new task-owned external file')
    parts = relative.parts
    if not parts or any(not re.fullmatch(r'[A-Za-z0-9._-]+', part) or part in ('.', '..') for part in parts):
        raise ValueError('output must be a new task-owned external file')
    payload = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in runroot.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            os.close(directory)
            directory = child
            require_ancestor_owner(directory)
        require_output_directory(directory, private=True)
        for part in parts[:-1]:
            try:
                os.mkdir(part, mode=0o700, dir_fd=directory)
            except FileExistsError:
                pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            os.close(directory)
            directory = child
            require_output_directory(directory)
        descriptor = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=directory)
        with os.fdopen(descriptor, 'wb') as output:
            output.write(payload)
    except OSError:
        raise ValueError('output authority rejected') from None
    finally:
        os.close(directory)


def identity(record, shape, source_root=None):
    ids = record['case'].get('original_case_ids')
    if not isinstance(ids, list) or len(ids) != 1 or ids[0] not in ALLOWED:
        raise ValueError('only the explicitly selected singleton original IDs are supported')
    original = ids[0]
    route = original.split('::')[1]
    if (shape.get('original_case_ids') != ids or record['case']['route'] != route
            or shape.get('leg') != route or shape.get('case_id') != 'I12-ENVOY-HOST::' + record['case']['label']):
        raise ValueError('original ID or sibling route/alias mapping mismatch')
    review_ref = verify_ref(record['case']['source_review'])
    if shape.get('oracle_review_sha256') != review_ref['sha256'] or record['case']['oracle_review_sha256'] != review_ref['sha256']:
        raise ValueError('executed original oracle review hash mismatch')
    document = load(review_ref['path'])
    matches = [row for row in document.get('records', document.get('rows', []))
               if row['run_scoped_case_id'] == original]
    if len(matches) != 1 or matches[0]['route'] != route:
        raise ValueError('original is absent or duplicated in source review')
    oracle = matches[0]['effective_oracle']
    if (oracle is None or canonical(oracle) != canonical(shape.get('approved_source_oracle'))
            or canonical(oracle) != canonical(record['case'].get('approved_source_oracle'))):
        raise ValueError('independently specified source oracle differs from executed fixture')
    verify_source_refs(matches[0].get('source_refs', []), source_root)
    return original, route, oracle, review_ref


def source_ref_candidates(path, source_root):
    if not path.is_absolute() and ('..' in path.parts or any(
            part in ('.git', '.aws', '.codex', '.agents') for part in path.parts)):
        raise ValueError('source reference path is not a product path')
    candidates = [path] if path.is_absolute() else [REPO / path]
    if not path.is_absolute() and source_root is not None:
        root = Path(source_root)
        if not root.is_absolute() or '..' in root.parts:
            raise ValueError('historical source root must be absolute without traversal')
        historical = root / path
        if historical != candidates[0]:
            candidates.append(historical)
    return candidates


def matching_source_ref(ref, candidates):
    for physical in candidates:
        if not physical.is_file():
            continue
        actual = reference(physical)
        if actual['sha256'] == ref['sha256'] and (
                'bytes' not in ref or actual['bytes'] == ref['bytes']):
            return actual
    raise ValueError('physical reference changed: ' + ref['path'])


def verify_source_refs(refs, source_root=None):
    for ref in refs:
        verified = matching_source_ref(ref, source_ref_candidates(Path(ref['path']), source_root))
        if type(ref.get('line')) is not int or not 1 <= ref['line'] <= len(read_bytes(verified['path']).splitlines()):
            raise ValueError('source reference line is not physically bounded')


def verify_fixture_binding(row, fixture, shape, oracle):
    """A re-sealed run cannot replace the independently reviewed fixture stimulus."""
    binding = row.get('fixture_binding') or {}
    inputs = binding.get('physical_inputs', binding.get('files', []))
    if not inputs:
        raise ValueError('original source oracle lacks physical fixture binding')
    for item in inputs:
        verify_ref(item)
    bound_shapes = [Path(item['path']) for item in inputs if Path(item['path']).name == SHAPE_FILE]
    if len(bound_shapes) != 1:
        raise ValueError('selected original needs exactly one bound fixture shape')
    old_root = bound_shapes[0].parent
    old_shape = load(bound_shapes[0])
    metadata = {'case_id', 'original_case_ids', 'review_sha256', 'oracle_review_sha256',
                'approved_source_oracle', 'expected_status_source', 'expected_source_oracle_proposal_only',
                'host_request_buffer_max_bytes', 'expected_status'}
    if canonical({key: value for key, value in old_shape.items() if key not in metadata}) != canonical(
            {key: value for key, value in shape.items() if key not in metadata}):
        raise ValueError('executed fixture stimulus differs from reviewed original shape')
    expected_status = oracle.get('visible_status')
    if type(expected_status) is int:
        if shape.get('expected_status') != expected_status:
            raise ValueError('executed client expectation differs from fixed source oracle')
    elif shape.get('expected_status') != old_shape.get('expected_status'):
        raise ValueError('unresolved original client expectation was changed')
    old_files = {path.relative_to(old_root): path for path in old_root.rglob('*') if path.is_file()}
    new_files = {path.relative_to(fixture): path for path in fixture.rglob('*') if path.is_file()}
    if set(old_files) != set(new_files):
        raise ValueError('executed fixture membership differs from reviewed source fixture')
    verified = []
    for name, path in old_files.items():
        old_ref, new_ref = reference(path), reference(new_files[name])
        if str(name) != SHAPE_FILE and old_ref['sha256'] != new_ref['sha256']:
            raise ValueError('executed bound fixture bytes differ: ' + str(name))
        verified.extend((old_ref, new_ref))
    return verified


def predicates(summary, oracle):
    """Evaluate only measured facts; unknown values never satisfy a predicate."""
    checks = {}
    def check(name, value):
        checks[name] = value is True
    identity_predicates(summary, check)
    client_predicates(summary, oracle, check)
    body_backend_predicates(summary, oracle, check)
    native_predicates(summary, oracle, check)
    terminal_predicates(summary, oracle, check)
    return checks


def identity_predicates(summary, check):
    check('physical_integrity', summary.get('artifact_integrity_issues') == [])
    check('terminal_runner', summary.get('runner_exit_code') == 0)
    commands = summary.get('command_exit_codes', {})
    check('actual_client_process_exits', all(commands.get(name) == 0 for name in (
        'selected-target-client', 'separate-neighbor-client')))
    check('actual_identity_config_commands', all(commands.get(name) == 0 for name in (
        'host-version', 'go-version', 'sdk-who-compile', 'sdk-who', 'envoy-config-validate')))
    controller = summary.get('controller', {})
    check('controller_cleanup', controller.get('controller_exitcode') == 0
          and controller.get('exitcode') == 0 and controller.get('supervisor_reaped') is True
          and controller.get('error_count') == 0 and controller.get('surviving_namespace_pid_count') == 0
          and controller.get('outside_mount_leak_count') == 0 and controller.get('namespace_pin_verified') is True
          and controller.get('executed_input_hashes_unchanged') is True and controller.get('timeout') is False)
    driver = summary.get('driver') or {}
    check('process_cleanup', driver.get('failure_type') is None
          and driver.get('remaining_owned_process_count') == 0 and len(driver.get('processes', {})) == 3
          and all(item.get('waited_exit_code') == 0 and item.get('forced_kill') is False
                  for item in driver.get('processes', {}).values()))
    source = summary.get('source_equality', {})
    check('complete_source_binding', all(source.get(key) is True for key in (
        'all_rows_verified', 'independent_sealed_baseline_overlay_contract_verified',
        'complete_archived_build_inventory_verified')))
    check('loaded_sdk_host_engine', all(
        snapshot is not None and all(snapshot.get(name, {}).get('matches_build_manifest') is True for name in ('engine', 'envoy'))
        and snapshot['engine'].get('sdk_matches_native_build') is True
        for snapshot in summary.get('loaded_images', {}).values()) and len(summary.get('loaded_images', {})) == 3)


def client_predicates(summary, oracle, check):
    for role in ('target', 'neighbor'):
        client = summary.get('clients', {}).get(role, {})
        check(role + '_client', client.get('process_exit') == 0 and client.get('error_type') is None
              and client.get('http_status') == (oracle['visible_status'] if role == 'target' else 200)
              and client.get('status_agrees_with_raw') is True and client.get('response_body_hash_verified') is True
              and client.get('request_body_hash_verified') is True
              and client.get('independent_raw_response', {}).get('framing_complete') is True)
        process = summary.get('grpc_transport', {}).get(role, {}).get('process', {})
        check(role + '_scoped_local_process_closure', process.get('scope_verified') is True
              and process.get('classification') == 'observed_local_reset' and process.get('local_http2_close_code') == 2
              and process.get('remote_grpc_status') is None and process.get('successful_grpc_completion') is False)
        if summary.get('route') != 'envoy-ext-proc':
            auth = summary.get('grpc_transport', {}).get(role, {}).get('authorization', {})
            check(role + '_explicit_authorization_status', auth.get('remote_grpc_status') == 0
                  and auth.get('successful_grpc_completion') is True)


def body_backend_predicates(summary, oracle, check):
    target = summary.get('clients', {}).get('target', {})
    check('client_exact_body', target.get('actual_request_send_bytes') == oracle['request_bytes']
          and target.get('response_body_bytes') == oracle['response_bytes']
          and target.get('independent_raw_response', {}).get('entity_sha256') == oracle['response_sha256'])
    backend = summary.get('backend', {})
    check('exact_backend_request_count', backend.get('request_count_is_lower_bound') is False
          and backend.get('request_count') == 2 and backend.get('raw_request_role_counts') == {'target': 1, 'neighbor': 1})
    check('backend_payloads', len(backend.get('requests', [])) == 2
          and all(row.get('request_body_hash_verified') is True and row.get('response_body_hash_verified') is True
                  for row in backend.get('requests', [])))


def native_predicates(summary, oracle, check):
    native = summary.get('native', {})
    scopes = native.get('scopes', [])
    check('independent_native_scopes', native.get('verified_allocation_scope_count') == 2 and len(scopes) == 2)
    check('observer_drained', bool(native.get('observer_states')) and all(
        row.get('invalid') is False and row.get('pending_calls') == 0 and row.get('live_mappings') == 0
        for row in native.get('observer_states', [])))
    if scopes:
        native_scope_predicates(scopes[0], summary.get('route'), oracle, check)


def native_scope_predicates(scope, route, oracle, check):
    counts = scope['observed_return_counts']
    check('native_phases_once', all(counts.get('native_process_' + phase) == 1
          for phase in ('request_headers', 'request_body', 'response_headers', 'response_body')))
    check('native_finish_free', all(counts.get(name) == 1 for name in (
        'native_cleanup', 'native_process_logging', 'runtime_destroy', 'runtime_finish', 'common_cleanup'))
          and scope.get('completed_transition_count') == 1 and counts.get('common_finish') == 2)
    returns = scope.get('return_result_counts', {})
    check('no_native_intervention', returns.get('native_intervention') == {'0': counts.get('native_intervention')}
          and isinstance(counts.get('native_intervention'), int) and counts['native_intervention'] > 0)
    for direction, label in ((0, 'request'), (1, 'response')):
        direction_predicates(scope, route, oracle, check, direction, label)
    check('commit_recorded', any(row['state'].get('response_committed') == 1
                                for row in scope.get('contract_state_samples', [])))
    if route != 'envoy-ext-proc':
        check('single_successful_companion_claim', sum(row['operation'] == 12 and row['claim_succeeded'] is True
              for row in scope.get('typed_body_callbacks', [])) == 1)


def direction_predicates(scope, route, oracle, check, direction, label):
    counts = scope['observed_return_counts']
    calls = [row for row in scope.get('typed_body_callbacks', [])
             if row['operation'] == 1 and row['response_direction'] == direction]
    check(label + '_callbacks_bytes_eos', bool(calls)
          and sum(row['body_bytes'] for row in calls) == oracle[label + '_bytes']
          and sum(row['eos_argument'] is True for row in calls) == oracle[label + '_eos_count']
          and calls[-1]['eos_argument'] is True)
    expected_calls = 3 if direction == 1 or route == 'envoy-ext-proc' else 1
    check(label + '_exact_callback_count', len(calls) == expected_calls
          and counts.get('runtime_append_' + label + '_body_chunk') == expected_calls
          and counts.get('native_append_' + label + '_body') == (2 if expected_calls == 3 else 1)
          and all(sum(row['operation'] == operation and row['response_direction'] == direction
                      for row in scope.get('typed_body_callbacks', [])) == 1 for operation in (3, 4)))
    check(label + '_runtime_eos', scope.get('explicit_runtime_eos_handoff_counts', {}).get(label + '_body_finish') == 1)


def terminal_predicates(summary, oracle, check):
    check('positive_source_rule', summary.get('native_logs', {}).get('native-audit', {}).get(
        'logged_numeric_rule_id_counts', {}).get(str(oracle.get('rule_id') or oracle.get('fixture_p2_probe_rule', 1900032))) == 1)
    check('positive_mime_p4_body_rule', summary.get('native_logs', {}).get('native-audit', {}).get(
        'logged_numeric_rule_id_counts', {}).get(str(oracle.get('fixture_p4_probe_rule', 1900034))) == 1)
    after = summary.get('loaded_images', {})
    check('neighbor_stable_descriptors', bool(after.get('after-target')) and bool(after.get('after-neighbor'))
          and all(after['after-target'][name]['fd_count'] == after['after-neighbor'][name]['fd_count']
                  for name in ('backend', 'engine', 'envoy')))


def expected_contract(oracle, shape):
    """Additional body identities come from sealed source fixture bytes, never results."""
    result = dict(oracle)
    for direction in ('request', 'response'):
        raw = bytes.fromhex(shape[direction + '_hex'])
        size = len(raw)
        sha = hashlib.sha256(raw).hexdigest()
        if result.get(direction + '_bytes', size) != size or result.get(direction + '_sha256', sha) != sha:
            raise ValueError('source oracle disagrees with sealed expected body')
        result[direction + '_bytes'] = size
        result[direction + '_sha256'] = sha
        result.setdefault(direction + '_eos_count', 1)
    return result


def fixture_probe_rules(fixture):
    result = {}
    lines = read_bytes(fixture / 'native.rules').decode().splitlines()
    for phase, variable, marker in ((2, 'REQUEST_BODY', 'request-marker'), (4, 'RESPONSE_BODY', 'response-marker')):
        matches = [re.fullmatch(r'SecRule ' + variable + r' "@contains ' + marker
                   + r'" "id:(\d+),phase:' + str(phase) + r",pass,log,t:none,msg:'I12 Envoy P" + str(phase) + r"'\"", line)
                   for line in lines]
        ids = [int(match[1]) for match in matches if match]
        if len(ids) != 1:
            raise ValueError('exact positive native body probe source missing')
        result['fixture_p' + str(phase) + '_probe_rule'] = ids[0]
    return result


def gitlinks(parent):
    def tree(cwd, revision, entry):
        match = re.fullmatch(r'[0-9a-f]{40}', revision) if isinstance(revision, str) else None
        if match is None:
            raise ValueError('exact lowercase Git commit SHA required')
        if (cwd, entry) not in ((REPO, 'modules/ModSecurity-test-Framework'),
            (test_root(), 'tools/MRTS')):
            raise ValueError('Git metadata scope rejected')
        result = subprocess.run(['rtk', 'proxy', 'git', '-C', str(cwd), 'ls-tree', match.group(0), '--', entry],
                                check=True, capture_output=True, text=True)
        parts = result.stdout.split()
        if (len(parts) != 4 or parts[:2] != ['160000', 'commit'] or parts[3] != entry
                or re.fullmatch(r'[0-9a-f]{40}', parts[2]) is None):
            raise ValueError('missing recorded gitlink identity')
        return parts[2]
    framework = tree(REPO, parent, 'modules/ModSecurity-test-Framework')
    mrts = tree(test_root(), framework, 'tools/MRTS')
    return framework, mrts


def event_checks(route, adapter, shape, tids, checks):
    if route == 'envoy-ext-proc':
        selected_events = [row for row in adapter if row.get('transaction_id') == shape['target']]
        checks['physical_terminal_once'] = len(selected_events) == 1 and selected_events[0].get('event') == 'ext_proc_stream_complete'
        event_meta = {'selected_terminal_count': len(selected_events), 'kind': 'ext_proc_stream_complete'}
    else:
        selected_events = [row for row in adapter if row.get('decision_id') in tids]
        checks['physical_terminal_once'] = sum(row.get('phase') == 'terminal' for row in selected_events) == 1
        checks['physical_lease_order'] = [row.get('phase') for row in selected_events] == [
            'P1', 'P2', 'lease', 'claim', 'P3', 'P4', 'neutral_outcome', 'terminal']
        event_meta = {'selected_terminal_count': sum(row.get('phase') == 'terminal' for row in selected_events),
                      'phases': [row.get('phase') for row in selected_events]}
    return event_meta


def client_response_original_checks(summary, expected, data, checks):
    """Bind this exact byte oracle to raw HTTP framing and independently stored entity bytes."""
    raw = REVIEW.raw_response_summary(read_bytes(data / 'client/target.response.raw'))
    body = read_bytes(data / 'client/target.body.raw')
    receipt = load(data / TARGET_CLIENT_RECEIPT)
    client = summary.get('clients', {}).get('target', {})
    size, digest = expected.get('response_bytes'), expected.get('response_sha256')
    checks['original_client_response_bytes'] = (type(size) is int and size >= 0
        and raw.get('framing_complete') is True and raw.get('entity_bytes') == size
        and len(body) == size and receipt.get('bytes') == size and client.get('response_body_bytes') == size)
    checks['original_client_response_sha256'] = (isinstance(digest, str)
        and re.fullmatch(r'[0-9a-f]{64}', digest) is not None
        and raw.get('entity_sha256') == digest and hashlib.sha256(body).hexdigest() == digest
        and receipt.get('sha256') == digest
        and client.get('independent_raw_response', {}).get('entity_sha256') == digest)


def unix_signal(returncode):
    """Decode subprocess.run's negative POSIX returncode; malformed evidence stays unknown."""
    if type(returncode) is not int:
        return 'unknown'
    return -returncode if returncode < 0 else None


def client_termination_evidence(data):
    command = load(data / 'selected-target-client.command.json')
    receipt = load(data / TARGET_CLIENT_RECEIPT)
    actual, proposed = command.get('exit_code'), receipt.get('proposed_process_exit')
    return {'actual_subprocess_exit': actual, 'receipt_proposed_exit': proposed,
            'unix_signal': unix_signal(actual),
            'scope': 'actual subprocess.run returncode; receipt independently records proposed exit'}


def client_termination_original_checks(summary, expected, data, checks):
    evidence = client_termination_evidence(data)
    actual, proposed = evidence['actual_subprocess_exit'], evidence['receipt_proposed_exit']
    success = type(actual) is int and actual == 0 and type(proposed) is int and proposed == 0
    checks['original_client_exit'] = (type(expected.get('client_exit')) is int
        and expected['client_exit'] == 0 and success
        and summary.get('command_exit_codes', {}).get('selected-target-client') == actual
        and summary.get('clients', {}).get('target', {}).get('process_exit') == proposed)
    checks['original_client_unix_signal'] = ('client_signal' in expected and expected['client_signal'] is None
        and success and evidence['unix_signal'] is None)


def client_original_checks(original, summary, expected, data, checks):
    if original in (CLIENT_RESPONSE_BYTES_ID, AUTHZ_CLIENT_RESPONSE_BYTES_ID):
        client_response_original_checks(summary, expected, data, checks)
    elif original == CLIENT_EXIT_SIGNAL_ID:
        client_termination_original_checks(summary, expected, data, checks)


def authz_fragment_event_origin(line, message):
    """Require the retained Envoy logger, component and source line per event."""
    exact = {
        REQUEST_HEADERS_COMPLETE:
            ('debug', 'http', 'source/common/http/conn_manager_impl.cc:1357'),
        REQUEST_END_STREAM:
            ('debug', 'http', 'source/common/http/conn_manager_impl.cc:1340'),
        'setting buffer limit to 4096':
            ('debug', 'http', 'source/common/http/filter_manager.cc:1730'),
        AUTHZ_BUFFERING:
            ('debug', 'ext_authz', 'source/extensions/filters/http/ext_authz/ext_authz.cc:490'),
        AUTHZ_BUFFERED:
            ('debug', 'ext_authz', 'source/extensions/filters/http/ext_authz/ext_authz.cc:516'),
    }
    origin = exact.get(message)
    for beginning, source_line in (
            ('body size=', 'source/common/http/http1/codec_impl.cc:1296'),
            ('decode headers called: filter=', 'source/common/http/filter_manager.cc:651'),
            ('decode data called: filter=', 'source/common/http/filter_manager.cc:799')):
        if message.startswith(beginning):
            origin = ('trace', 'http', source_line)
    if message.startswith("cluster '") and ' match for URL ' in message:
        origin = ('debug', 'router', 'source/common/router/router.cc:586')
    if origin is None:
        return True
    prefix = r'^\[[^\]]+\] \[\d+\] ' + re.escape(' '.join('[' + part + ']' for part in origin))
    return re.match(prefix + r' \[Tags: ', line, flags=re.ASCII) is not None


def authz_fragment_header_block(lines, start):
    block = []
    for header in lines[start:]:
        if not header:
            break
        block.append(header)
    return block


def authz_fragment_header_scope(lines, tagged, worker_at, nonce):
    headers = []
    for index, line in enumerate(lines):
        match = tagged.search(line)
        if not match or match[3] != REQUEST_HEADERS_COMPLETE:
            continue
        block = authz_fragment_header_block(lines, index + 1)
        if "':path', '/" + nonce + "'" in block and "'x-request-id', '" + nonce + "'" in block:
            if not authz_fragment_event_origin(line, match[3]):
                return None
            headers.append((index, match[1], match[2], worker_at(index)))
    if len(headers) != 1 or headers[0][2] is None or headers[0][3] is None:
        return None
    return headers[0]


def authz_fragment_decoders(lines, index, tagged, worker_at, scope):
    _, connection, stream, worker = scope
    for offset, decoder in ((1, 'header_mutation status=0'), (2, 'ext_authz status=1')):
        following = tagged.search(lines[index + offset]) if index + offset < len(lines) else None
        if (following is None or (following[1], following[2]) != (connection, stream)
                or worker_at(index + offset) != worker
                or not authz_fragment_event_origin(lines[index + offset], following[3])
                or following[3] != 'decode data called: filter=envoy.filters.http.' + decoder):
            return False
    return True


def authz_fragment_body(trace, index, match, scope, state):
    lines, tagged, worker_at = trace
    size = re.fullmatch(r'body size=(\d+)', match[3], flags=re.ASCII)
    if (size is None or match[2] is not None or REQUEST_END_STREAM in state['scoped']
            or tuple(value for value in state['scoped'] if value in AUTHZ_BUFFERING_CHAIN) != AUTHZ_BUFFERING_CHAIN
            or not authz_fragment_decoders(lines, index, tagged, worker_at, scope)):
        return False
    state['fragments'].append({'line': index + 1, 'bytes': int(size[1])})
    return True


def authz_fragment_scoped_event(trace, index, match, scope, state):
    lines, _, worker_at = trace
    _, _, stream, worker = scope
    message = match[3]
    if (worker_at(index) != worker or not authz_fragment_event_origin(lines[index], message)
            or message.startswith('request headers complete') or match[2] not in (None, stream)):
        return False
    if message.startswith('body size=') and not authz_fragment_body(
            trace, index, match, scope, state):
        return False
    if match[2] == stream:
        state['scoped'].append(message)
    if message == AUTHZ_BUFFERED:
        if state['finished_index'] is not None:
            return False
        state['finished_index'] = index
    if message == state['upstream_message']:
        if match[2] != stream:
            return False
        state['upstream_index'] = index
    return True


def authz_fragment_events(lines, tagged, worker_at, scope, nonce):
    start, connection, _, worker = scope
    trace = (lines, tagged, worker_at)
    state = {'scoped': [], 'fragments': [], 'dispatches': [], 'finished_index': None,
             'upstream_index': None, 'upstream_message': "cluster 'upstream_service' match for URL '/" + nonce + "'"}
    for index in range(start + 1, len(lines)):
        match = tagged.search(lines[index])
        if not match:
            continue
        if match[3] == AUTHZ_DISPATCH:
            if (worker_at(index) != worker or match[2] is None
                    or not authz_fragment_event_origin(lines[index], match[3])):
                return None
            state['dispatches'].append(index)
        if match[1] != connection:
            continue
        if not authz_fragment_scoped_event(trace, index, match, scope, state):
            return None
        if state['upstream_index'] is not None:
            break
    return state


def authz_fragment_interval_complete(state, expected):
    scoped = state['scoped']
    dispatches = state['dispatches']
    finished_index, upstream_index = state['finished_index'], state['upstream_index']
    return ([row['bytes'] for row in state['fragments']] == [64, 31] and expected.get('request_bytes') == 95
            and scoped.count(REQUEST_END_STREAM) == 1 and scoped.count(AUTHZ_BUFFERED) == 1
            and scoped.index(REQUEST_END_STREAM) < scoped.index(AUTHZ_BUFFERED)
            and tuple(value for value in scoped if value in AUTHZ_BUFFERING_CHAIN) == AUTHZ_BUFFERING_CHAIN
            and len(dispatches) == 1 and finished_index is not None and upstream_index is not None
            and finished_index < dispatches[0] < upstream_index)


def authz_host_fragments(summary, expected, shape, data):
    """Bind two HTTP1 host fragments to one later authorization/native sample.

    Codec lines carry only a connection ID. Their immediate selected-stream
    decoders, worker identity, buffering order and later Check dispatch must all
    agree. Client sends do not establish host receives or native streaming.
    """
    metadata = summary.get('physical_files', {}).get(ENVOY_STDERR, {})
    if not metadata.get('sha256') or type(metadata.get('bytes')) is not int:
        raise ValueError('hash-bound physical Envoy trace required')
    verify_ref(dict(metadata, path=str(data / ENVOY_STDERR)))
    lines = read_bytes(data / ENVOY_STDERR).decode().splitlines()
    nonce = shape.get('target')
    if not isinstance(nonce, str) or not re.fullmatch(r'e-[0-9a-f]{12}', nonce):
        return {}
    tagged = re.compile(r'\[Tags: "ConnectionId":"(\d+)"(?:,"StreamId":"(\d+)")?\] (.*)', re.ASCII)
    worker_tag = re.compile(r'^\[[^\]]+\] \[(\d+)\] ', re.ASCII)
    def worker_at(index):
        tag = worker_tag.match(lines[index])
        return tag[1] if tag else None
    scope = authz_fragment_header_scope(lines, tagged, worker_at, nonce)
    if scope is None:
        return {}
    state = authz_fragment_events(lines, tagged, worker_at, scope, nonce)
    if state is None or not authz_fragment_interval_complete(state, expected):
        return {}
    _, connection, stream, worker = scope
    return {'worker_thread_id': worker, 'connection_id': connection, 'stream_id': stream, 'request_nonce': nonce,
            'fragments': state['fragments'], 'total_bytes': 95, 'host_eos_count': 1,
            'authorization_dispatch_count': 1, 'authorization_dispatch_line': state['dispatches'][0] + 1,
            'scope': 'two Envoy HTTP1 receive fragments; one buffered authorization/native sample; no native streaming claim'}


def authz_fragment_original_checks(summary, expected, shape, data, checks):
    checks['original_authz_multiple_host_fragments'] = bool(authz_host_fragments(summary, expected, shape, data))
    scopes = summary.get('native', {}).get('scopes', [])
    calls = [row for row in (scopes[0].get('typed_body_callbacks', []) if scopes else [])
             if row.get('operation') == 1 and row.get('response_direction') == 0]
    checks['original_authz_single_complete_native_sample'] = (len(calls) == 1
        and calls[0].get('body_bytes') == expected.get('request_bytes') == 95
        and calls[0].get('eos_argument') is True)


def scoped_checks(summary, record, expected, original, shape, native_rows, data):
    checks = predicates(summary, expected)
    client_original_checks(original, summary, expected, data, checks)
    if original == AUTHZ_REQUEST_MULTIPLE_CHUNKS_ID:
        authz_fragment_original_checks(summary, expected, shape, data, checks)
    checks['actual_outer_process_terminal'] = (record.get('process_exit_code') == 0
        and type(record.get('started_ns')) is int and type(record.get('finished_ns')) is int
        and record['finished_ns'] >= record['started_ns'] and all(
            record.get('timeout_state', {}).get(name) is False for name in (
                'outer_timeout', 'cleanup_grace_timeout', 'cleanup_requires_review')))
    scope = summary['native']['scopes'][0]
    scoped = [row for row in native_rows if row.get('allocation_scope_call') == scope['allocation_scope_call']]
    tids = {row['transaction_id'] for row in scoped if row.get('transaction_id')}
    cids = {row['canonical_transaction_id'] for row in scoped if row.get('canonical_transaction_id')}
    checks['single_native_common_identity'] = len(tids) == len(cids) == 1
    client = summary['clients']['target']
    checks['native_selected_client_interval'] = bool(scoped) and all(
        client['started_monotonic_ns'] <= row['monotonic_ns'] <= client['completed_monotonic_ns'] for row in scoped)
    backend = [json.loads(line) for line in read_bytes(data / BACKEND_RECEIPTS).splitlines()]
    selected = [row for row in backend if row.get('request_id') == shape['target'] and row.get('path') == '/' + shape['target']]
    checks['exact_backend_client_payload_correlation'] = len(selected) == 1 and all(
        selected[0].get(field) == expected[field] for field in ('request_bytes', 'request_sha256', 'response_bytes', 'response_sha256'))
    callbacks = scope['typed_body_callbacks']
    if original.endswith(('NEED-request-streaming', 'NEED-response-streaming')):
        direction = 0 if original.endswith('NEED-request-streaming') else 1
        body_calls = [row for row in callbacks if row['operation'] == 1 and row['response_direction'] == direction]
        checks['multiple_native_host_chunks'] = len([row for row in body_calls if row['body_bytes'] > 0]) >= 2
    adapter = [json.loads(line) for line in read_bytes(data / 'runtime/adapter-events.jsonl').splitlines()]
    event_meta = event_checks(summary['route'], adapter, shape, tids, checks)
    checks['no_physical_first_technical_cause'] = all(value.get('first_physical_technical_error') is None
                                                    for value in summary['events'].values())
    return checks, tids, cids, event_meta


def observation_values(summary, checks, tids, cids, event_meta, expected, original=None, data=None):
    scope = summary['native']['scopes'][0]
    route = summary['route']
    client = summary['clients']['target']
    callbacks = scope['typed_body_callbacks']
    values = {
        'product_host_identity': summary['loaded_images'], 'source_config_binding': summary['source_equality'],
        'capability': {'route': route, 'typed_callbacks': scope['typed_host_operation_counts'], 'strict_p4_claimed': False},
        'client_exit': client['process_exit'], 'client_signal': {'observed_error_type': client['error_type']},
        'client_headers': {'status': client['http_status'], 'content_type': client['response_content_type']},
        'client_bytes': client['response_body_bytes'], 'client_sha256': client['independent_raw_response'].get('entity_sha256'),
        'backend_request_count': summary['backend'], 'backend_payload_identity': summary['backend']['requests'],
        'client_backend_correlation': {'exact_target_payload_matches_source': checks['exact_backend_client_payload_correlation']},
        'native_events': event_meta, 'native_api_returns': scope['return_result_counts'],
        'native_transaction_id': {'sha256': canonical(sorted(tids))},
        'common_transaction_id': {'sha256': canonical(sorted(cids))},
        'observed_handle_association': {'pid': scope['pid'], 'allocation_scope_call': scope['allocation_scope_call'],
                                        'verified': checks['single_native_common_identity']},
        'native_phases': scope['observed_return_counts'], 'native_body_chunks': callbacks,
        'native_intervention_or_first_cause': {'intervention_returns': scope['return_result_counts'].get('native_intervention'),
                                              'physical_first_technical_error': None},
        'host_eos': callbacks, 'native_eos': scope['explicit_runtime_eos_handoff_counts'],
        'commit_order': {'contract_samples': scope['contract_state_samples'], 'client_completed_monotonic_ns': client['completed_monotonic_ns'],
                         'scope': 'actual_common_commit_state_and_typed_send; no_kernel_send_timestamp_claim'},
        'mime_gate': {'positive_body_rule': expected['fixture_p4_probe_rule'],
                      'positive_body_rule_observed': checks['positive_mime_p4_body_rule'], 'native_mime_selection': None,
                      'native_charset_selection': None, 'scope': 'positive_P4_RESPONSE_BODY_rule_after_SDK_MIME_gate'},
        'finish_calls': {key: value for key, value in scope['observed_return_counts'].items() if 'finish' in key or 'logging' in key},
        'finish_transitions': scope['completed_transition_count'], 'native_free_calls': scope['observed_return_counts'].get('native_cleanup'),
        'cleanup_receipts': {'observer': summary['native']['observer_states'], 'controller': summary['controller']},
        'descriptor_cleanup': {'after_target': summary['loaded_images']['after-target'], 'after_neighbor': summary['loaded_images']['after-neighbor'],
                               'scope': 'stable_warmed_connection_fds_then_all_processes_reaped'},
        'process_listener_cleanup': {'controller': summary['controller'], 'driver': summary['driver']},
        'neighbor_health': {'client': summary['clients']['neighbor'], 'concurrent': summary['client_time_overlap_observed']},
        'transport_framing': client['independent_raw_response'], 'transport_reset_scope': summary['grpc_transport'],
        'host_action': {'visible_status': client['http_status'], 'typed_callbacks': callbacks},
        'physical_event_order': event_meta, 'terminal_event_count': event_meta,
    }
    if original == CLIENT_EXIT_SIGNAL_ID:
        if data is None:
            raise ValueError('client exit/signal observation requires the physical command and receipt')
        termination = client_termination_evidence(data)
        values['client_exit'] = termination['actual_subprocess_exit']
        values['client_signal'] = termination
    return values


def make_observations(shared, data, fixture, source_ref, values, refs, checks):
    attempt = data.parent
    proof_paths = {
        'loaded_image': data / 'before-request.json', 'isolation_receipt': attempt / 'controller-result.json',
        'source_manifest': data / 'build-manifest.json', 'effective_configuration': fixture / SHAPE_FILE,
        'host_callback': data / 'runtime/host-lifecycle.jsonl', 'source_contract': Path(source_ref['path']),
        'client_process': data / TARGET_CLIENT_RECEIPT, 'backend_process': data / BACKEND_RECEIPTS,
        'physical_event_sink': data / 'runtime/adapter-events.jsonl', 'native_api': data / 'runtime/native-lifecycle.jsonl',
        'native_debug': data / 'runtime/native-debug.log', 'cleanup_observer': data / 'result.json',
    }
    observations = {name: {'applicable': True, 'value': values[name],
        'evidence': [reference(proof_paths[role], role) for role in sorted(roles)]}
        for name, roles in shared.ROLES.items()}
    for name, roles in shared.ROLES.items():
        if 'client_process' in roles:
            observations[name]['evidence'].extend(reference(data / relative, 'client_process') for relative in (
                'selected-target-client.command.json', 'separate-neighbor-client.command.json', 'client/neighbor.receipt.json'))
        if 'backend_process' in roles:
            observations[name]['evidence'].extend(reference(data / relative, 'backend_process') for relative in refs
                if relative.startswith('backend/') and relative != BACKEND_RECEIPTS)
        if 'host_callback' in roles:
            observations[name]['evidence'].append(reference(data / ENVOY_STDERR, 'host_callback'))
    if not checks['exact_backend_request_count']:
        observations['backend_request_count'] = {'applicable': True, 'value': None,
            'reason': 'Only completed backend receipts exist; absent early request-line capture cannot exclude partial upstream requests.'}
    return observations


def stage_one(record, parent, runs_path, helpers, output):
    runroot = require_runroot()
    shared = shared_validator()
    REVIEW.BINDING_CACHE.clear()
    transport, capture, historical_helpers = REVIEW.parser_modules(helpers)
    summary = REVIEW.review_run(record, transport, capture, parent)
    if summary.get('observation_state') != 'driver_result_observed':
        raise ValueError('physical run is not terminal and safely handed back')
    attempt = Path(summary['attempt'])
    data = attempt / 'data'
    spec = load(record['case']['spec'])
    fixture = Path(next(row['source'] for row in spec['bindings'] if row['target'] == '/mnt/fixtures'))
    shape = load(fixture / SHAPE_FILE)
    original, route, oracle, source_ref = identity(record, shape, helpers.parents[1])
    review_document = load(source_ref['path'])
    review_row = next(row for row in review_document.get('records', review_document.get('rows', []))
                      if row['run_scoped_case_id'] == original)
    bound_fixture_refs = verify_fixture_binding(review_row, fixture, shape, oracle)
    native_rows = [json.loads(line) for line in read_bytes(data / 'runtime/native-lifecycle.jsonl').splitlines()]
    build = load(data / 'build-manifest.json')
    if build['case'] != shape['case_id'] or any(row['case'] != shape['case_id'] or row['profile'] != route
                                            or row['run'] != build['run'] for row in native_rows):
        raise ValueError('native alias does not match the sealed singleton original mapping')
    expected = expected_contract(oracle, shape)
    expected.update(fixture_probe_rules(fixture))
    checks, tids, cids, event_meta = scoped_checks(summary, record, expected, original, shape, native_rows, data)
    framework, mrts = gitlinks(parent)
    refs = {name: reference(data / name) for name in summary['physical_files']}
    control = reference(attempt / 'controller-result.json')
    shape_ref = reference(fixture / SHAPE_FILE)
    values = observation_values(summary, checks, tids, cids, event_meta, expected, original, data)
    if original == AUTHZ_REQUEST_MULTIPLE_CHUNKS_ID:
        values['host_action']['request_host_fragments'] = authz_host_fragments(summary, expected, shape, data)
    observations = make_observations(shared, data, fixture, source_ref, values, refs, checks)
    packet = {'schema': 'i12.envoy.original-packet.v1', 'reviewed_by': 'pending_root_review',
        'run_scoped_case_id': original, 'leg_id': route, 'run_id': build['run'], 'parent_sha': parent,
        'framework_sha': framework, 'mrts_sha': mrts, 'effective_config_sha256': shape_ref['sha256'],
        'execution_observed': True, 'execution_kind': 'host_http', 'observations': observations,
        'oracle_evaluated': False, 'oracle_sha256': shared.ORACLES.canonical_digest(oracle), 'effective_oracle': oracle,
        'additional_sealed_expected_contract': expected,
        'outcome': None, 'full_lifecycle_qualified': False, 'predicate_results': checks,
        'approval_ready': all(checks.values()), 'remaining_requirements': [key for key, value in checks.items() if not value],
        'original_mapping': {'native_case_alias': shape['case_id'], 'original_case_ids': [original],
                             'shape': shape_ref, 'source_review': source_ref},
        'historical_helper_sha256': historical_helpers,
        'current_parser_sha256': transport.current_parser_hashes(),
        'physical_refs': list(refs.values()) + bound_fixture_refs + [control, shape_ref, source_ref, reference(record['case']['spec'])]
            + [reference(path) for path in (Path(__file__).resolve(), HERE / 'review_runs.py', HERE / 'transport.py',
                HERE / 'source_inventory.py', HERE / 'evidence_io.py',
                HERE / 'grpc_stream_observations.py', HERE / 'host_log_observations.py',
                source_path('ci/evidence/reports/generate-pr382-i12-lifecycle-ledger.py', root=REPO),
                source_path('ci/evidence/reports/generate-pr382-i12-oracle-reconciliation.py', root=REPO),
                helpers / 'grpc_stream_observations.py', helpers / 'host_log_observations.py', fixture / 'native.rules')],
        'reproduction': {'runs_path': str(runs_path), 'record': record, 'helpers': str(helpers)},
        'closure_contract': 'observed scoped local HTTP2 reset2; remote Process grpcstatus unknown; never remote OK'}
    for name, observation in observations.items():
        shared.measurement(name, observation, Path(output) if output is not None else runroot / 'unwritten-packet.json')
    if output is None:
        return packet
    write(output, packet)
    return {'path': str(output), 'sha256': reference(output)['sha256'], 'run_scoped_case_id': original,
            'approval_ready': packet['approval_ready'], 'remaining_requirements': packet['remaining_requirements']}


def prepare(runs_path, output_root, original_ids=None, helpers=None):
    runroot = require_runroot()
    document = load(runs_path)
    selected = ALLOWED if original_ids is None else frozenset(original_ids)
    if selected - ALLOWED:
        raise ValueError('unapproved original ID scope')
    outputs = []
    seen = set()
    for record in document['runs']:
        ids = record['case'].get('original_case_ids', [])
        if len(ids) != 1 or ids[0] not in selected:
            continue
        if ids[0] in seen:
            raise ValueError('duplicate selected original run')
        seen.add(ids[0])
        output = Path(output_root) / (ids[0].replace('::', '__') + '.json')
        outputs.append(stage_one(record, document['parent_sha'], Path(runs_path),
                                 Path(helpers or runroot / 'native-v2/source/.i12-capture/envoy'), output))
    return {'packets': outputs, 'missing_original_ids': sorted(selected - seen), 'new_lifecycle_pass': 0}


def validate_approved(path):
    """Recheck physical bytes, exact mapping, predicates and the shared 35-role validator."""
    packet = load(path)
    if packet.get('reviewed_by') != 'root' or packet.get('root_approval', {}).get('explicit_original_id') != packet.get('run_scoped_case_id'):
        raise ValueError('individual explicit Root approval missing')
    original = packet['run_scoped_case_id']
    if original not in ALLOWED or packet['leg_id'] != original.split('::')[1]:
        raise ValueError('original or sibling route mismatch')
    for ref in packet['physical_refs']:
        verify_ref(ref)
    mapping = packet['original_mapping']
    verify_ref(mapping['source_review'])
    shape = load(verify_ref(mapping['shape'])['path'])
    record = packet['reproduction']['record']
    helpers = Path(packet['reproduction']['helpers'])
    actual_id, route, oracle, _ = identity(record, shape, helpers.parents[1])
    if actual_id != original or route != packet['leg_id'] or canonical(oracle) != canonical(packet['effective_oracle']):
        raise ValueError('approved original oracle changed')
    REVIEW.BINDING_CACHE.clear()
    transport, capture, _ = REVIEW.parser_modules(helpers)
    summary = REVIEW.review_run(record, transport, capture, packet['parent_sha'])
    expected = expected_contract(oracle, shape)
    expected.update(fixture_probe_rules(Path(mapping['shape']['path']).parent))
    current = predicates(summary, expected)
    if not all(current.values()) or not packet.get('approval_ready') or not all(packet['predicate_results'].values()):
        raise ValueError('physical predicates incomplete')
    staged = load(verify_ref(packet['root_approval']['staged_packet'])['path'])
    if (staged.get('reviewed_by') != 'pending_root_review' or staged.get('outcome') is not None
            or packet['root_approval']['staged_packet']['sha256'] != packet['root_approval']['staged_packet_sha256']):
        raise ValueError('Root approval is not bound to an unqualified staged packet')
    fresh = stage_one(record, packet['parent_sha'], Path(packet['reproduction']['runs_path']),
                      Path(packet['reproduction']['helpers']), None)
    compare_regenerated(packet, staged, fresh)
    shared = shared_validator()
    result = shared.reviewed_packet(reference(path), {'run_scoped_case_id': original, 'leg_id': route}, oracle)
    if not result['full_lifecycle_qualified'] or result['outcome'] != 'PASS':
        raise ValueError('shared lifecycle validator did not qualify PASS')
    return {'run_scoped_case_id': original, 'route': route, 'leg_id': route, 'effective_oracle': oracle,
            'physical_refs': packet['physical_refs'], 'receipt': reference(path),
            'full_lifecycle_qualified': True, 'outcome': 'PASS', 'unknown_fields': result['unknown_fields'],
            'remote_process_grpc_success_claimed': False, 'closure_contract': packet['closure_contract']}


def compare_regenerated(packet, staged, fresh):
    for name in ('observations', 'predicate_results', 'original_mapping', 'effective_oracle',
                 'additional_sealed_expected_contract', 'physical_refs', 'parent_sha', 'framework_sha', 'mrts_sha',
                 'effective_config_sha256', 'run_id', 'closure_contract', 'approval_ready', 'remaining_requirements',
                 'run_scoped_case_id', 'leg_id', 'reproduction',
                 'historical_helper_sha256', 'current_parser_sha256'):
        if canonical(packet[name]) != canonical(fresh[name]) or canonical(staged[name]) != canonical(fresh[name]):
            raise ValueError('approved packet differs from freshly reproduced physical facts: ' + name)


def approve(path, output, original_id, expected_sha256):
    verify_ref({'path': str(Path(path)), 'sha256': expected_sha256})
    packet = load(path)
    if (packet.get('reviewed_by') != 'pending_root_review' or packet.get('run_scoped_case_id') != original_id
            or original_id not in ALLOWED or not packet.get('approval_ready')):
        raise ValueError('staged packet is not individually eligible for approval')
    packet.update(reviewed_by='root', oracle_evaluated=True, outcome='PASS', full_lifecycle_qualified=True)
    packet['root_approval'] = {'explicit_original_id': original_id, 'staged_packet_sha256': expected_sha256,
                               'staged_packet': reference(Path(path)),
                               'protocol': 'individual_root_command_after_physical_review'}
    write(output, packet)
    return validate_approved(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runs', type=Path)
    parser.add_argument('--output-root', type=Path)
    parser.add_argument('--original-id', action='append')
    parser.add_argument('--helpers', type=Path)
    parser.add_argument('--root-approve', type=Path)
    parser.add_argument('--expected-staged-sha256')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--validate-approved', type=Path)
    args = parser.parse_args()
    if args.validate_approved:
        result = validate_approved(args.validate_approved)
    elif args.root_approve:
        if not args.output or not args.original_id or len(args.original_id) != 1 or not args.expected_staged_sha256:
            parser.error('approval requires output, one original ID and expected staged SHA256')
        result = approve(args.root_approve, args.output, args.original_id[0], args.expected_staged_sha256)
    else:
        if not args.runs or not args.output_root:
            parser.error('staging requires runs and output-root')
        result = prepare(args.runs, args.output_root, args.original_id, args.helpers)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
