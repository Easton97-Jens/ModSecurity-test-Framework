#!/usr/bin/env python3
"""Bind current-base native and streaming observations without qualifying IDs."""
import argparse
import json
from pathlib import Path

import modsecurity_connector_ci.runtime.lifecycle.i12.envoy.evidence_io as evidence_io
import modsecurity_connector_ci.runtime.lifecycle.i12.envoy.review_runs as review_runs
import modsecurity_connector_ci.runtime.lifecycle.i12.envoy.source_inventory as source_inventory
from modsecurity_connector_ci.runtime.lifecycle.i12.envoy.transport import paths

HERE = Path(__file__).resolve().parent
PARENT = 'a62296fb57263f9be18c6ac879e36e0ab2a9935c'
CURRENT_PARENT = 'e4c872cde16eb73182de49c09a8ba8ee4219b417'
AFAF_PARENT = 'afaf6305bd55646073c3b40632b52fc4e5edf714'
SCENARIOS = {
    'ext-proc-streaming': 'envoy-ext-proc',
    'ext-authz-request-streaming': 'envoy-ext-authz-request',
    'ext-authz-response-companion-streaming': 'envoy-ext-authz-response-companion',
}
CHECKS = {'source-head', 'source-archive', 'observer', 'accessor', 'observer-archive',
          'go-version', 'sdk-identity-build', 'sdk-identity', 'composite-build',
          'go-native', 'go-race', 'go-vet', 'native-observer-controls'}
ISOLATION_CHECKS = {'go-environment', 'go-compile-version', 'go-link-version'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def bind(path, expected, references):
    ref = evidence_io.reference(path)
    require(ref['sha256'] == expected, 'physical reference changed: ' + str(path))
    references[str(path)] = ref
    return ref


def runner_log_path(snapshot, label, channel):
    """Resolve the two sealed run-ledger names without guessing another file."""
    candidates = [snapshot.parent / (prefix + label + '.' + channel)
                  for prefix in ('runs-', 'host-runs-')]
    present = [path for path in candidates if path.is_file()]
    require(len(present) == 1, 'runner log path is missing or ambiguous')
    return present[0]


def go_provenance(proof, references, allow_legacy=False, require_isolation=True):
    provenance = proof.get('go_provenance')
    if allow_legacy and provenance is None:
        return
    require(isinstance(provenance, dict), 'native Go provenance required')
    expected = 'go version go1.27.2 linux/amd64'
    require(provenance.get('required_version') == '1.27.2'
            and provenance.get('required_identity') == expected
            and provenance.get('actual_identity') == expected
            and provenance.get('verified') is True
            and proof['environment'].get('GOTOOLCHAIN') == 'local',
            'native Go provenance identity or local toolchain differs')
    configured = Path(provenance['configured_path'])
    executable = Path(provenance['executable_path'])
    evidence_io.approved_path(configured, evidence_io.DEFAULT_ROOTS)
    evidence_io.approved_path(executable, evidence_io.DEFAULT_ROOTS)
    require(configured.name == 'go' and configured.resolve(strict=True) == executable,
            'native Go configured/executable path differs')
    for check in proof['checks']:
        if check['label'] in ('go-version', 'go-native', 'go-race', 'go-vet'):
            require(check['argv'][:3] == ['rtk', 'proxy', str(configured)],
                    'native Go check executable differs')
    bind(executable, provenance['executable_sha256'], references)
    if not require_isolation:
        return
    root = executable.parent.parent
    required = {'GOROOT': str(root), 'GOOS': 'linux', 'GOARCH': 'amd64', 'GOVERSION': 'go1.27.2',
                'GOTOOLDIR': str(root / 'pkg/tool/linux_amd64')}
    require(provenance.get('required_environment') == required
            and provenance.get('actual_environment') == required
            and provenance.get('environment_output') == ''.join(value + '\n' for value in required.values())
            and all(proof['environment'].get(key) == required[key] for key in ('GOROOT', 'GOOS', 'GOARCH')),
            'isolated native Go environment differs')
    checks = {check['label']: check for check in proof['checks']}
    require(checks['go-environment']['argv'] == ['rtk', 'proxy', str(configured), 'env', *required],
            'isolated Go environment command differs')
    tools = provenance.get('tools', {})
    require(set(tools) == {'compile', 'link'}, 'both isolated Go tool identities required')
    for name, tool in tools.items():
        tool_path = root / 'pkg/tool/linux_amd64' / name
        expected_identity = name + ' version go1.27.2'
        require(tool.get('path') == str(tool_path)
                and tool.get('required_identity') == expected_identity
                and tool.get('actual_identity') == expected_identity
                and checks['go-' + name + '-version']['argv'] == ['rtk', 'proxy', str(tool_path), '-V'],
                'isolated Go compiler/linker identity differs')
        bind(tool_path, tool['sha256'], references)


def native_evidence(path, references, go_version='1.27.2', allow_legacy=False, parent_sha=PARENT):
    proof = evidence_io.read_json(path)
    bind(path, evidence_io.reference(path)['sha256'], references)
    require(proof.get('actual_source_commit') == parent_sha, 'current-base native revision differs')
    require(proof.get('status') == 'pass' and proof.get('build_ready') is True
            and proof.get('host_launched') is False,
            'current-base native checks must pass')
    expected_checks = CHECKS if allow_legacy else CHECKS | ISOLATION_CHECKS
    require({check['label'] for check in proof['checks']} == expected_checks
            and len(proof['checks']) == len(expected_checks)
            and all(check['exit_code'] == 0 for check in proof['checks']),
            'complete native check set required')
    go_provenance(proof, references, allow_legacy)
    for check in proof['checks']:
        for channel in ('stdout', 'stderr'):
            bind(path.parent / (check['label'] + '.' + channel),
                 check[channel + '_sha256'], references)
    if not allow_legacy:
        provenance = proof['go_provenance']
        require(evidence_io.read_bytes(path.parent / 'go-environment.stdout')
                == provenance['environment_output'].encode(), 'physical Go environment output differs')
        for name, tool in provenance['tools'].items():
            require(evidence_io.read_bytes(path.parent / ('go-' + name + '-version.stdout'))
                    == (tool['actual_identity'] + '\n').encode(), 'physical Go tool identity output differs')
    source = Path(proof['source_copy'])
    require(source_inventory.verify(source, proof) == proof['complete_source_inventory'],
            'native source inventory differs')
    for name, sha in proof['module_inputs'].items():
        bind(source / 'connectors/envoy/ext_proc' / name, sha, references)
    module = evidence_io.read_bytes(source / 'connectors/envoy/ext_proc/go.mod')
    require(b'golang.org/x/net v0.61.0' in module, 'patched x/net identity differs')
    require(evidence_io.read_bytes(path.parent / 'go-version.stdout').strip()
            == ('go version go' + go_version + ' linux/amd64').encode(), 'current Go identity differs')
    require(evidence_io.read_bytes(source / '.go-version').strip() == b'1.27.2',
            'archived Base Go version differs')
    require(evidence_io.read_bytes(path.parent / 'sdk-identity.stdout').strip()
            == b'ModSecurity v3.0.14 (Linux)', 'current SDK identity differs')
    require(proof['sdk_library'] == {
        'path': '/usr/lib/x86_64-linux-gnu/libmodsecurity.so',
        'sha256': '32257230b8f378987ba1204049dcc1e23927fd44c8778e09d41805ad705c3407'},
        'native SDK library identity differs')
    require(len(proof['binaries']) == 2, 'both native host binaries required')
    for name, sha in proof['binaries'].items():
        bind(path.parent / name, sha, references)
        bind(Path(proof['host_ready_binaries']) / Path(name).name, sha, references)
    return proof


def rejected_native_evidence(path, references, parent_sha=PARENT):
    proof = evidence_io.read_json(path)
    receipt = bind(path, evidence_io.reference(path)['sha256'], references)
    require(proof.get('actual_source_commit') == parent_sha and proof.get('host_launched') is False
            and proof.get('status') == 'failed' and 'build_ready' not in proof and 'binaries' not in proof,
            'rejected native must be an exact-base pre-host build failure')
    checks = proof['checks']
    labels = CHECKS - {'go-native', 'go-race', 'go-vet', 'native-observer-controls'}
    require(len(checks) == len(labels) and {check['label'] for check in checks} == labels
            and checks[-1]['label'] == 'composite-build' and checks[-1]['exit_code'] != 0
            and all(check['exit_code'] == 0 for check in checks[:-1]),
            'rejected native must retain sole terminal composite-build failure')
    go_provenance(proof, references, require_isolation=False)
    for check in checks:
        for channel in ('stdout', 'stderr'):
            bind(path.parent / (check['label'] + '.' + channel), check[channel + '_sha256'], references)
    require(evidence_io.read_bytes(path.parent / 'go-version.stdout')
            == b'go version go1.27.2 linux/amd64\n', 'rejected native driver identity differs')
    diagnostic = b'compile: version "go1.27.3" does not match go tool version "go1.27.2"'
    require(diagnostic in evidence_io.read_bytes(path.parent / 'composite-build.stderr'),
            'rejected native lacks physical compiler/tool mismatch')
    require(source_inventory.verify(Path(proof['source_copy']), proof) == proof['complete_source_inventory'],
            'rejected native source inventory differs')
    return {'classification': 'rejected_toolchain_isolation', 'receipt': receipt,
            'host_launched': False, 'status': 'failed', 'failure_check': 'composite-build',
            'driver_go': '1.27.2', 'compiler_go': '1.27.3', 'original_oracle_case_ids': [],
            'oracle_progress_assigned': False, 'new_lifecycle_pass': 0}


def nonqualification(review, parent_sha=PARENT):
    require(review.get('parent_sha') == parent_sha, 'current-base review revision differs')
    require(review.get('host_lifecycle_qualified') is False
            and review.get('oracle_progress_assigned') is False,
            'review cannot qualify original oracles')
    rows = review['scenarios']
    require(len(rows) == 3 and {row['scenario']: row['route'] for row in rows} == SCENARIOS,
            'exactly three current-base route scenarios required')
    require(all(row.get('original_oracle_case_ids') == []
                and row.get('host_lifecycle_qualified') is False for row in rows),
            'original ID injection or lifecycle qualification prohibited')


def shared_observed_contract(row, proof, parent_sha=PARENT, retake=False):
    controller = row['controller']
    require(row['runner_exit_code'] == (77 if retake else 0) and row['observation_state'] == 'driver_result_observed'
            and row['artifact_integrity_issues'] == []
            and controller == {'exitcode': 1 if retake else 0,
                'controller_exitcode': 77 if retake else 0, 'timeout': False,
                'supervisor_reaped': True, 'resource_violation': None, 'namespace_pin_verified': True,
                'error_count': 0, 'surviving_namespace_pid_count': 0,
                'outside_mount_leak_count': 0, 'executed_input_hashes_unchanged': True}
            and row['driver']['remaining_owned_process_count'] == 0,
            'current-base cleanup or physical integrity differs')
    require(row['build']['source_git_baseline'] == parent_sha
            and row['source_equality']['source_contract_parent_sha'] == parent_sha
            and row['source_equality']['complete_archived_build_inventory_verified'] is True
            and row['build']['engine_sha256'] in proof['binaries'].values(),
            'host/native source or binary binding differs')
    images = row['loaded_images']
    require(set(images) == {'before-request', 'after-target', 'after-neighbor'}
        and all(isinstance(snapshot, dict) and {'engine', 'envoy'} <= set(snapshot) and all(
        image.get('matches_build_manifest') is True
        and (name != 'engine' or image.get('sdk_matches_native_build') is True)
        for name, image in snapshot.items() if name in ('engine', 'envoy'))
        for snapshot in images.values()), 'loaded host/native image identity differs')
    versions = row['versions']
    require(versions['go-version']['identity'] == 'go version go1.27.3 linux/amd64'
            and versions['sdk-who']['identity'] == 'ModSecurity v3.0.14 (Linux)'
            and '/1.39.1/Clean/RELEASE/BoringSSL' in versions['host-version']['identity']
            and all(x['command_exit_code'] == 0 for x in versions.values()),
            'current host runtime identities differ')


def observed_contract(row, proof, parent_sha=PARENT):
    shared_observed_contract(row, proof, parent_sha)
    for role, request, response in (('target', 95, 96), ('neighbor', 6, 7)):
        client = row['clients'][role]
        require(client['request_body_bytes'] == request and client['response_body_bytes'] == response
                and client['raw_http_status'] == 200 and client['process_exit'] == 0
                and client['independent_raw_response']['framing_complete'] is True
                and client['request_body_hash_verified'] is True
                and client['response_body_hash_verified'] is True,
                'current-base client bytes or completion differ')
        transport = row['grpc_transport'][role]
        require(transport['process']['remote_grpc_status'] is None
                and transport['process']['successful_grpc_completion'] is False,
                'missing Process status cannot become successful completion')
        authorization = transport['authorization']
        unknown = (authorization['remote_grpc_status'] is None
                   and authorization['successful_grpc_completion'] is False
                   and authorization['classification'] == 'unknown')
        explicit = (row['route'] != 'envoy-ext-proc'
                    and authorization['remote_grpc_status'] == 0
                    and authorization['successful_grpc_completion'] is True
                    and authorization['classification'] == 'explicit_remote_status_and_close')
        require(unknown or explicit,
                'Authorization completion requires its explicit scoped status')
    backend = row['backend']
    require(backend['request_count'] == 2 and backend['request_count_is_lower_bound'] is False
            and backend['completed_receipt_count'] == 2
            and {(x['role'], x['request_body_bytes'], x['response_body_bytes'])
                 for x in backend['requests']} == {('target', 95, 96), ('neighbor', 6, 7)},
            'two independently measured backend requests required')


def retake_clients(row):
    for role, request, response, status, exitcode in (
            ('target', 95, 0, 504, 1), ('neighbor', 6, 7, 200, 0)):
        client = row['clients'][role]
        require(client['request_body_bytes'] == request and client['response_body_bytes'] == response
                and client['raw_http_status'] == status and client['process_exit'] == exitcode
                and client['independent_raw_response']['framing_complete'] is True
                and client['request_body_hash_verified'] is True
                and client['response_body_hash_verified'] is True
                and client['tls_stream_eof_observed'] is True
                and client['tcp_eof_observed'] is True,
                'retake client bytes or completion differ')
        transport = row['grpc_transport'][role]
        require(transport['process']['remote_grpc_status'] is None
                and transport['process']['successful_grpc_completion'] is False
                and transport['authorization']['remote_grpc_status'] is None
                and transport['authorization']['successful_grpc_completion'] is False
                and transport['authorization']['classification'] == 'unknown',
                'retake missing remote status cannot become success')


def retake_adapter_callbacks(adapter, neighbor):
    require(len(adapter) == 2 and all(item.get('event') == 'ext_proc_stream_complete' for item in adapter),
            'retake adapter stream count differs')
    empty = [item for item in adapter if item.get('transaction_id') is None]
    populated = [item for item in adapter if item.get('transaction_id') == neighbor]
    require(len(empty) == len(populated) == 1
            and empty[0].get('close_reason') == 'grpc_context_canceled_unattributed'
            and all(empty[0].get(field) == 0 for field in ('request_header_count',
                'response_header_count', 'request_body_chunks', 'response_body_chunks',
                'request_body_bytes', 'response_body_bytes'))
            and populated[0].get('close_reason') == 'response_end_of_stream'
            and populated[0].get('request_body_bytes') == 6
            and populated[0].get('response_body_bytes') == 7,
            'retake target adapter callbacks must be absent')


def retake_physical_callbacks(row, references, native, scope):
    # Summaries intentionally omit transaction IDs. Join the bound physical logs
    # to the two independently retained client receipts instead of inferring IDs.
    data = Path(row['attempt']) / 'data'
    paths = ('client/target.receipt.json', 'client/neighbor.receipt.json',
             'runtime/native-lifecycle.jsonl', 'runtime/host-lifecycle.jsonl',
             'runtime/adapter-events.jsonl')
    for name in paths:
        bind(data / name, row['physical_files'][name]['sha256'], references)
    target_receipt = evidence_io.read_json(data / paths[0])
    neighbor_receipt = evidence_io.read_json(data / paths[1])
    target = target_receipt['transaction_id']
    neighbor = neighbor_receipt['transaction_id']
    require(isinstance(target, str) and isinstance(neighbor, str) and target != neighbor,
            'retake client transaction identities differ')
    def rows(name):
        return [json.loads(line) for line in evidence_io.read_bytes(data / name).splitlines() if line]
    physical_native, host, adapter = (rows(name) for name in paths[2:])
    require(len(physical_native) == native['row_count'] and len(host) == native['host_row_count']
            and all(item.get(field) in (None, neighbor) for item in physical_native
                    for field in ('transaction_id', 'input_transaction_id'))
            and any(item.get('transaction_id') == neighbor for item in physical_native)
            and all(neighbor_receipt['started_ns'] <= item['monotonic_ns']
                    <= neighbor_receipt['completed_ns'] for item in physical_native
                    if item.get('function') != 'observer')
            and all(item.get('allocation_scope_call') in (None, scope['allocation_scope_call'])
                    for item in physical_native)
            and all(item.get('pid') == scope['pid']
                    and item.get('allocation_scope_call') == scope['allocation_scope_call'] for item in host),
            'retake target native/host callbacks must be absent')
    retake_adapter_callbacks(adapter, neighbor)


def retake_contract(row, proof, references, parent_sha=CURRENT_PARENT):
    """Retain the executed 504 attempt, including absent target callbacks."""
    shared_observed_contract(row, proof, parent_sha, retake=True)
    require(row['scenario'] == 'ext-proc-streaming' and row['route'] == 'envoy-ext-proc'
            and row['driver'].get('failure_type') == 'RuntimeError'
            and set(row['driver'].get('processes', {})) == {'envoy', 'engine', 'backend'}
            and all(process.get('waited_exit_code') == 0
                    and process.get('forced_kill') is False and process.get('signal_sent') == 15
                    for process in row['driver']['processes'].values()),
            'retake process cleanup differs')
    retake_clients(row)
    target_transport = row['grpc_transport']['target']
    require(target_transport['process']['classification'] == 'unknown'
            and target_transport['process']['scope_verified'] is False
            and target_transport['process']['local_http2_close_code'] is None
            and target_transport['received_http2_payload_callback_count'] is None,
            'retake target Process callbacks must remain unobserved')
    backend = row['backend']
    require(backend['request_count'] == 1 and backend['request_count_is_lower_bound'] is False
            and backend['completed_receipt_count'] == 1
            and backend['raw_request_line_count'] == 1
            and backend['raw_request_role_counts'] == {'neighbor': 1}
            and backend['completed_receipt_role_counts'] == {'neighbor': 1}
            and len(backend['requests']) == 1
            and {(x['role'], x['request_body_bytes'], x['response_body_bytes'])
                 for x in backend['requests']} == {('neighbor', 6, 7)},
            'retake requires exactly one neighbor backend request')
    native = row['native']
    require(native['verified_allocation_scope_count'] == 1 and len(native['scopes']) == 1
            and native['host_row_count'] == 7
            and len(native['observer_states']) == 2
            and {state['edge'] for state in native['observer_states']} == {'admitted', 'snapshot'}
            and all(state['invalid'] is False and state['pending_calls'] == 0
                    and state['live_mappings'] == 0 for state in native['observer_states']),
            'retake native observer scope or cleanup differs')
    scope = native['scopes'][0]
    require(scope['observed_return_counts'].get('native_cleanup') == 1
            and scope['observed_return_counts'].get('native_process_logging') == 1
            and scope['observed_return_counts'].get('common_cleanup') == 1,
            'retake neighbor native cleanup differs')
    retake_physical_callbacks(row, references, native, scope)


def bind_executed_review(row, record, references):
    attempt = Path(row['attempt'])
    bind(attempt / 'controller-result.json', row['controller_result_sha256'], references)
    bind(attempt / 'retained-original-ownership.json', row['handoff_receipt_sha256'], references)
    controller = evidence_io.read_json(attempt / 'controller-result.json')
    spec_path = Path(record['case']['spec'])
    bind(spec_path, controller['spec_sha256'], references)
    for name, sha in controller['executed_input_hashes_before'].items():
        # Configuration ownership belongs to the controller; never read private configuration.
        if '.codex' not in Path(name).parts:
            bind(Path(name), sha, references)
    spec = evidence_io.read_json(spec_path)
    for binding in spec['bindings']:
        bind(Path(binding['ledger']), binding['ledger_sha256'], references)
    for name, metadata in row['physical_files'].items():
        bind(attempt / 'data' / name, metadata['sha256'], references)


def bind_current_parsers(review, transport, references):
    current_parsers = transport.current_parser_hashes()
    require(current_parsers == review.get('current_parser_sha256'),
            'current maintained parser identity differs or is missing')
    for name, sha in current_parsers.items():
        bind(HERE / name, sha, references)


def review_evidence(path, proof, admission, references, parent_sha=PARENT, *, retake=False):
    review = evidence_io.read_json(path)
    bind(path, evidence_io.reference(path)['sha256'], references)
    nonqualification(review, parent_sha)
    snapshot = Path(review['runs_snapshot'])
    bind(snapshot, review['runs_sha256'], references)
    runs = evidence_io.read_json(snapshot)
    require(runs['parent_sha'] == parent_sha and len(runs['runs']) == 3,
            'runner source scope differs')
    helpers = Path(proof['source_copy']) / '.i12-capture/envoy'
    transport, capture, hashes = review_runs.parser_modules(helpers)
    require(hashes == review['helper_sha256'], 'capture helper identity differs')
    bind(HERE / 'transport.py', review['transport_wrapper_sha256'], references)
    bind_current_parsers(review, transport, references)
    for name, sha in hashes.items():
        bind(helpers / name, sha, references)
    review_runs.BINDING_CACHE.clear()
    actual = []
    for record in runs['runs']:
        label = record['case']['label']
        for channel in ('stdout', 'stderr'):
            bind(runner_log_path(snapshot, label, channel), record[channel + '_sha256'], references)
        row = review_runs.review_run(record, transport, capture, parent_sha)
        actual.append(row)
        if admission:
            require(row['runner_exit_code'] == 77
                    and row['observation_state'] == 'controller_admission_failed_or_unknown'
                    and 'controller' not in row and 'driver' not in row and 'attempt' not in row,
                    'admission failure cannot claim execution or cleanup')
        else:
            if retake and row['scenario'] == 'ext-proc-streaming':
                retake_contract(row, proof, references, parent_sha)
            else:
                observed_contract(row, proof, parent_sha)
            bind_executed_review(row, record, references)
    require(actual == review['scenarios'], 'physical review differs from independent replay')
    return review


def produce(native, admission_review, review, superseded_native, superseded_review, rejected_native,
            *, parent_sha=PARENT, previous_parent_sha=PARENT, schema_version=1, retake_review=None):
    require((schema_version, parent_sha, previous_parent_sha) in (
        (1, PARENT, PARENT), (2, CURRENT_PARENT, PARENT)),
        'unsupported supplement schema or current/previous revisions')
    require((schema_version == 2 and retake_review is not None)
            or (schema_version == 1 and retake_review is None),
            'v2 requires retake review; v1 cannot add a retake input')
    references = {}
    proof = native_evidence(native, references, parent_sha=parent_sha)
    previous = native_evidence(superseded_native, references, '1.27.3', allow_legacy=True,
                               parent_sha=previous_parent_sha)
    rejected = rejected_native_evidence(rejected_native, references, parent_sha=previous_parent_sha)
    failed = review_evidence(admission_review, previous, True, references, previous_parent_sha)
    superseded = review_evidence(superseded_review, previous, False, references, previous_parent_sha)
    observed = review_evidence(review, proof, False, references, parent_sha)
    result = {'schema': 'i12.envoy.current-base-evidence.v' + str(schema_version), 'parent_sha': parent_sha,
            'host_lifecycle_qualified': False, 'oracle_progress_assigned': False,
            'original_oracle_case_ids': [], 'new_lifecycle_pass': 0,
            'toolchains': {'required_engine_build_go': '1.27.2', 'actual_engine_build_go': '1.27.2',
                'host_environment_go': '1.27.3',
                'host_go_scope': 'installed_host_probe_not_engine_build_toolchain'},
            'route_transport_observations': {row['route']: row['grpc_transport']
                                             for row in observed['scenarios']},
            'inputs': {name: evidence_io.reference(path) for name, path in (
                ('native', native), ('admission_review', admission_review), ('review', review),
                ('superseded_native', superseded_native), ('superseded_review', superseded_review),
                ('rejected_native', rejected_native))},
            'rejected_native': rejected,
            'admission_failures': failed['scenarios'], 'observations': observed['scenarios'],
            'superseded': {'classification': 'wrong_toolchain_nonqualifying',
                'engine_build_go': '1.27.3', 'required_engine_build_go': '1.27.2',
                'host_environment_go': '1.27.3',
                'original_oracle_case_ids': [], 'oracle_progress_assigned': False,
                'new_lifecycle_pass': 0, 'observations': superseded['scenarios']},
            'physical_references': references}
    if schema_version == 2:
        retake = review_evidence(retake_review, proof, False, references, parent_sha, retake=True)
        result['inputs']['retake_review'] = evidence_io.reference(retake_review)
        result.update(current_parent_sha=parent_sha, previous_parent_sha=previous_parent_sha,
            retake={'classification': 'executed_504_nonqualifying', 'new_lifecycle_pass': 0,
                'original_oracle_case_ids': [], 'oracle_progress_assigned': False,
                'observations': retake['scenarios']})
    return result


def produce_v3(native, admission_review, review, previous_supplement):
    """Revalidate the pinned E4 history before adding Afaf observations."""
    previous = evidence_io.read_json(previous_supplement)
    require(previous.get('schema') == 'i12.envoy.current-base-evidence.v2'
            and previous.get('parent_sha') == CURRENT_PARENT
            and previous.get('current_parent_sha') == CURRENT_PARENT
            and previous.get('previous_parent_sha') == PARENT,
            'v3 requires the pinned E4 v2 previous supplement')
    previous = validate(previous_supplement)
    references = {}
    for name, ref in previous['physical_references'].items():
        require(name == ref['path'] and evidence_io.reference(Path(name)) == ref,
                'previous physical reference changed')
        references[name] = ref
    previous_ref = evidence_io.reference(previous_supplement)
    prior = references.get(str(previous_supplement))
    require(prior is None or prior == previous_ref, 'physical reference conflict')
    references[str(previous_supplement)] = previous_ref
    current_references = {}
    proof = native_evidence(native, current_references, parent_sha=AFAF_PARENT)
    failed = review_evidence(admission_review, proof, True, current_references, AFAF_PARENT)
    observed = review_evidence(review, proof, False, current_references, AFAF_PARENT)
    for name, ref in current_references.items():
        require(name not in references or references[name] == ref, 'physical reference conflict')
        references[name] = ref
    return {'schema': 'i12.envoy.current-base-evidence.v3',
            'parent_sha': AFAF_PARENT, 'current_parent_sha': AFAF_PARENT,
            'previous_parent_sha': CURRENT_PARENT,
            'host_lifecycle_qualified': False, 'oracle_progress_assigned': False,
            'original_oracle_case_ids': [], 'new_lifecycle_pass': 0,
            'toolchains': {'required_engine_build_go': '1.27.2', 'actual_engine_build_go': '1.27.2',
                'host_environment_go': '1.27.3',
                'host_go_scope': 'installed_host_probe_not_engine_build_toolchain'},
            'route_transport_observations': {row['route']: row['grpc_transport']
                                             for row in observed['scenarios']},
            'inputs': {name: evidence_io.reference(path) for name, path in (
                ('native', native), ('admission_review', admission_review), ('review', review),
                ('previous_supplement', previous_supplement))},
            'admission_failures': failed['scenarios'], 'observations': observed['scenarios'],
            'previous_supplement': previous_ref, 'physical_references': references}


def validate(path):
    supplement = evidence_io.read_json(path)
    schema = supplement.get('schema')
    if schema == 'i12.envoy.current-base-evidence.v3':
        inputs = supplement['inputs']
        names = ('native', 'admission_review', 'review', 'previous_supplement')
        require(set(inputs) == set(names), 'supplement input set differs')
        for ref in inputs.values():
            require(evidence_io.reference(Path(ref['path'])) == ref, 'supplement input changed')
        actual = produce_v3(*(Path(inputs[name]['path']) for name in names))
        require(supplement == actual, 'current-base supplement differs from fresh validation')
        return actual
    require(schema in ('i12.envoy.current-base-evidence.v1', 'i12.envoy.current-base-evidence.v2'),
            'unsupported supplement schema')
    revision = ({'parent_sha': PARENT, 'previous_parent_sha': PARENT, 'schema_version': 1}
                if schema.endswith('.v1') else
                {'parent_sha': CURRENT_PARENT, 'previous_parent_sha': PARENT, 'schema_version': 2})
    inputs = supplement['inputs']
    required_inputs = {'native', 'admission_review', 'review', 'superseded_native',
                       'superseded_review', 'rejected_native'}
    if schema.endswith('.v2'):
        required_inputs.add('retake_review')
        require('retake_review' in inputs, 'v2 requires retake review input')
        revision['retake_review'] = Path(inputs['retake_review']['path'])
    require(set(inputs) == required_inputs, 'supplement input set differs')
    for ref in inputs.values():
        require(evidence_io.reference(Path(ref['path'])) == ref, 'supplement input changed')
    actual = produce(*(Path(inputs[key]['path']) for key in (
        'native', 'admission_review', 'review', 'superseded_native', 'superseded_review', 'rejected_native')),
        **revision)
    require(supplement == actual, 'current-base supplement differs from fresh validation')
    return actual


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('native', 'admission-review', 'review', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    legacy_required = ('superseded_native', 'superseded_review', 'rejected_native')
    legacy = legacy_required + ('retake_review',)
    for name in legacy:
        parser.add_argument('--' + name.replace('_', '-'), type=Path)
    parser.add_argument('--previous-supplement', type=Path)
    args = parser.parse_args()
    if args.previous_supplement is not None:
        if any(getattr(args, name) is not None for name in legacy):
            parser.error('--previous-supplement is mutually exclusive with legacy evidence options')
        result = produce_v3(args.native, args.admission_review, args.review, args.previous_supplement)
    else:
        if any(getattr(args, name) is None for name in legacy_required):
            parser.error('legacy evidence requires superseded-native, superseded-review and rejected-native')
        inputs = (args.native, args.admission_review, args.review,
                  args.superseded_native, args.superseded_review, args.rejected_native)
        if args.retake_review is None:
            result = produce(*inputs)
        else:
            result = produce(*inputs, parent_sha=CURRENT_PARENT, previous_parent_sha=PARENT,
                             schema_version=2, retake_review=args.retake_review)
    with paths.new_text(args.output) as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'output': str(args.output), 'new_lifecycle_pass': 0}))


if __name__ == '__main__':
    main()
