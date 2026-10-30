"""Negative controls for separate current-base evidence and its accounting."""
import copy
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import modsecurity_connector_ci.runtime.lifecycle.i12.envoy.current_base_evidence as current


def observed():
    return {'runner_exit_code': 0, 'observation_state': 'driver_result_observed',
        'artifact_integrity_issues': [], 'controller': {'exitcode': 0, 'controller_exitcode': 0,
            'timeout': False, 'supervisor_reaped': True, 'resource_violation': None,
            'namespace_pin_verified': True, 'error_count': 0, 'surviving_namespace_pid_count': 0,
            'outside_mount_leak_count': 0, 'executed_input_hashes_unchanged': True},
        'driver': {'remaining_owned_process_count': 0}, 'route': 'envoy-ext-authz-request',
        'build': {'source_git_baseline': current.PARENT, 'engine_sha256': 'engine'},
        'source_equality': {'source_contract_parent_sha': current.PARENT,
            'complete_archived_build_inventory_verified': True},
        'loaded_images': {name: {'engine': {'matches_build_manifest': True,
            'sdk_matches_native_build': True}, 'envoy': {'matches_build_manifest': True}}
            for name in ('before-request', 'after-target', 'after-neighbor')},
        'clients': {role: {'request_body_bytes': request, 'response_body_bytes': response,
            'raw_http_status': 200, 'process_exit': 0,
            'independent_raw_response': {'framing_complete': True},
            'request_body_hash_verified': True, 'response_body_hash_verified': True}
            for role, request, response in (('target', 95, 96), ('neighbor', 6, 7))},
        'grpc_transport': {role: {'process': {'remote_grpc_status': None,
            'successful_grpc_completion': False}, 'authorization': {'remote_grpc_status': 0,
            'successful_grpc_completion': True, 'classification': 'explicit_remote_status_and_close'}}
            for role in ('target', 'neighbor')},
        'backend': {'request_count': 2, 'request_count_is_lower_bound': False,
            'completed_receipt_count': 2, 'requests': [
                {'role': 'target', 'request_body_bytes': 95, 'response_body_bytes': 96},
                {'role': 'neighbor', 'request_body_bytes': 6, 'response_body_bytes': 7}]},
        'versions': {'go-version': {'identity': 'go version go1.27.3 linux/amd64', 'command_exit_code': 0},
            'sdk-who': {'identity': 'ModSecurity v3.0.14 (Linux)', 'command_exit_code': 0},
            'host-version': {'identity': 'envoy/1.39.1/Clean/RELEASE/BoringSSL', 'command_exit_code': 0}}}


def retake_fixture(root):
    row = observed()
    row.update(attempt=str(root), scenario='ext-proc-streaming', route='envoy-ext-proc',
        runner_exit_code=77, physical_files={})
    row['controller'].update(exitcode=1, controller_exitcode=77)
    row['build']['source_git_baseline'] = current.CURRENT_PARENT
    row['source_equality']['source_contract_parent_sha'] = current.CURRENT_PARENT
    row['driver'].update(failure_type='RuntimeError', processes={
        name: {'waited_exit_code': 0, 'forced_kill': False, 'signal_sent': 15}
        for name in ('envoy', 'engine', 'backend')})
    row['clients']['target'].update(raw_http_status=504, process_exit=1, response_body_bytes=0)
    for role in ('target', 'neighbor'):
        row['clients'][role].update(tls_stream_eof_observed=True, tcp_eof_observed=True)
        row['grpc_transport'][role]['authorization'] = {'remote_grpc_status': None,
            'successful_grpc_completion': False, 'classification': 'unknown'}
    row['grpc_transport']['target']['process'].update(classification='unknown', scope_verified=False,
        local_http2_close_code=None)
    row['grpc_transport']['target']['received_http2_payload_callback_count'] = None
    row['backend'].update(request_count=1, completed_receipt_count=1, raw_request_line_count=1,
        raw_request_role_counts={'neighbor': 1}, completed_receipt_role_counts={'neighbor': 1})
    row['backend']['requests'] = row['backend']['requests'][1:]
    row['native'] = {'verified_allocation_scope_count': 1, 'row_count': 1, 'host_row_count': 7,
        'scopes': [{'pid': 10, 'allocation_scope_call': 2, 'observed_return_counts': {
            'native_cleanup': 1, 'native_process_logging': 1, 'common_cleanup': 1}}],
        'observer_states': [{'edge': edge, 'invalid': False, 'pending_calls': 0, 'live_mappings': 0}
                            for edge in ('admitted', 'snapshot')]}
    payloads = {'client/target.receipt.json': {'transaction_id': 'target'},
        'client/neighbor.receipt.json': {'transaction_id': 'neighbor', 'started_ns': 1, 'completed_ns': 9},
        'runtime/native-lifecycle.jsonl': [{'transaction_id': 'neighbor', 'input_transaction_id': None,
            'allocation_scope_call': 2, 'monotonic_ns': 5}],
        'runtime/host-lifecycle.jsonl': [{'pid': 10, 'allocation_scope_call': 2} for _ in range(7)],
        'runtime/adapter-events.jsonl': [
            {'event': 'ext_proc_stream_complete', 'close_reason': 'grpc_context_canceled_unattributed',
             **dict.fromkeys(('request_header_count', 'response_header_count',
                'request_body_chunks', 'response_body_chunks', 'request_body_bytes', 'response_body_bytes'), 0)},
            {'event': 'ext_proc_stream_complete', 'close_reason': 'response_end_of_stream',
             'transaction_id': 'neighbor', 'request_body_bytes': 6, 'response_body_bytes': 7}]}
    for name, payload in payloads.items():
        path = root / 'data' / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(''.join(json.dumps(x) + '\n' for x in payload) if isinstance(payload, list)
                        else json.dumps(payload))
        row['physical_files'][name] = current.evidence_io.reference(path)
    return row


class CurrentBaseControls(unittest.TestCase):
    def setUp(self):
        self.proof = {'binaries': {'engine': 'engine'}}

    def test_current_parser_identity_is_bound_separately(self):
        transport = current.review_runs.maintained_transport
        expected = transport.current_parser_hashes()
        references = {}
        current.bind_current_parsers({'current_parser_sha256': expected}, transport, references)
        self.assertEqual(set(references), {str(current.HERE / name) for name in expected})
        self.assertEqual({Path(name).name: ref['sha256'] for name, ref in references.items()}, expected)

    def test_historical_helper_identity_cannot_replace_current_parser_identity(self):
        transport = current.review_runs.maintained_transport
        review = {'helper_sha256': transport.current_parser_hashes()}
        with self.assertRaisesRegex(ValueError, 'current maintained parser identity'):
            current.bind_current_parsers(review, transport, {})

    def test_streaming_contract_preserves_missing_process_status(self):
        current.observed_contract(observed(), self.proof)

    def test_host_environment_identity_is_separate_from_engine_build_go(self):
        row = observed()
        row['versions']['go-version']['identity'] = 'go version go1.27.2 linux/amd64'
        with self.assertRaisesRegex(ValueError, 'runtime identities differ'):
            current.observed_contract(row, self.proof)

    def test_incomplete_loaded_image_snapshots_are_rejected(self):
        mutations = [lambda images: images.clear(),
            lambda images: images['before-request'].clear(),
            lambda images: images['after-target'].pop('engine'),
            lambda images: images['after-neighbor'].pop('envoy')]
        for mutate in mutations:
            row = observed()
            mutate(row['loaded_images'])
            with self.assertRaisesRegex(ValueError, 'loaded host/native image identity'):
                current.observed_contract(row, self.proof)

    def test_false_process_success_is_rejected(self):
        row = observed()
        row['grpc_transport']['target']['process']['successful_grpc_completion'] = True
        with self.assertRaisesRegex(ValueError, 'missing Process status'):
            current.observed_contract(row, self.proof)

    def test_unknown_authorization_cannot_count_as_success(self):
        row = observed()
        row['grpc_transport']['target']['authorization']['remote_grpc_status'] = None
        with self.assertRaisesRegex(ValueError, 'Authorization completion'):
            current.observed_contract(row, self.proof)

    def test_unscoped_authorization_remains_unknown(self):
        row = observed()
        for transport in row['grpc_transport'].values():
            transport['authorization'] = {'remote_grpc_status': None,
                'successful_grpc_completion': False, 'classification': 'unknown'}
        current.observed_contract(row, self.proof)

    def test_go_provenance_requires_physical_compiler_and_local_identity(self):
        with tempfile.TemporaryDirectory(dir=current.evidence_io.STORAGE) as directory:
            path = Path(directory) / 'bin/go'
            path.parent.mkdir()
            path.write_bytes(b'physical compiler')
            identity = 'go version go1.27.2 linux/amd64'
            proof = {'environment': {'GOTOOLCHAIN': 'local'}, 'checks': [
                {'label': 'go-version', 'argv': ['rtk', 'proxy', str(path), 'version']}],
                'go_provenance': {'required_version': '1.27.2', 'required_identity': identity,
                    'actual_identity': identity, 'verified': True, 'configured_path': str(path),
                    'executable_path': str(path), 'executable_sha256': current.evidence_io.reference(path)['sha256']}}
            root = path.parent.parent
            required = {'GOROOT': str(root), 'GOOS': 'linux', 'GOARCH': 'amd64',
                'GOVERSION': 'go1.27.2', 'GOTOOLDIR': str(root / 'pkg/tool/linux_amd64')}
            proof['environment'].update({key: required[key] for key in ('GOROOT', 'GOOS', 'GOARCH')})
            proof['go_provenance'].update(required_environment=dict(required), actual_environment=dict(required),
                environment_output=''.join(value + '\n' for value in required.values()), tools={})
            proof['checks'].append({'label': 'go-environment',
                'argv': ['rtk', 'proxy', str(path), 'env', *required]})
            proof['go_provenance']['configured_path'] = str(path)
            for name in ('compile', 'link'):
                tool_path = root / 'pkg/tool/linux_amd64' / name
                tool_path.parent.mkdir(parents=True, exist_ok=True)
                tool_path.write_bytes(name.encode())
                tool = {'path': str(tool_path), 'sha256': current.evidence_io.reference(tool_path)['sha256'],
                    'required_identity': name + ' version go1.27.2',
                    'actual_identity': name + ' version go1.27.2'}
                proof['go_provenance']['tools'][name] = tool
                proof['checks'].append({'label': 'go-' + name + '-version',
                    'argv': ['rtk', 'proxy', str(tool_path), '-V']})
            refs = {}
            current.go_provenance(proof, refs)
            self.assertIn(str(path), refs)
            mutations = [lambda p: p.pop('go_provenance'),
                lambda p: p['go_provenance'].update(actual_identity='go version go1.27.3 linux/amd64'),
                lambda p: p['go_provenance'].update(verified=False),
                lambda p: p['environment'].update(GOTOOLCHAIN='auto'),
                lambda p: p['go_provenance'].update(executable_sha256='0' * 64),
                lambda p: p['environment'].update(GOROOT='/different'),
                lambda p: p['go_provenance']['actual_environment'].update(GOVERSION='go1.27.3'),
                lambda p: p['go_provenance']['tools']['compile'].update(actual_identity='compile version go1.27.3'),
                lambda p: p['go_provenance']['tools']['link'].update(path='/different/link'),
                lambda p: p['go_provenance']['tools']['link'].update(sha256='0' * 64),
                lambda p: p['checks'][0]['argv'].__setitem__(2, '/other/go')]
            for mutate in mutations:
                changed = copy.deepcopy(proof)
                mutate(changed)
                with self.assertRaises(ValueError):
                    current.go_provenance(changed, {})
            path.write_bytes(b'changed compiler')
            with self.assertRaisesRegex(ValueError, 'physical reference changed'):
                current.go_provenance(proof, {})

    def test_legacy_go_provenance_allowance_is_explicit(self):
        current.go_provenance({}, {}, allow_legacy=True)
        with self.assertRaisesRegex(ValueError, 'provenance required'):
            current.go_provenance({}, {})

    def test_rejected_native_preserves_only_pre_host_compiler_failure(self):
        with tempfile.TemporaryDirectory(dir=current.evidence_io.STORAGE) as directory:
            root = Path(directory)
            labels = current.CHECKS - {'go-native', 'go-race', 'go-vet', 'native-observer-controls'}
            proof = {'actual_source_commit': current.PARENT, 'host_launched': False,
                'status': 'failed', 'source_copy': str(root / 'source'),
                'complete_source_inventory': {'source': 'hash'}, 'checks': []}
            diagnostic = b'compile: version "go1.27.3" does not match go tool version "go1.27.2"\n'
            for label in sorted(labels - {'composite-build'}) + ['composite-build']:
                check = {'label': label, 'exit_code': int(label == 'composite-build')}
                for channel in ('stdout', 'stderr'):
                    if label == 'composite-build' and channel == 'stderr':
                        data = diagnostic
                    elif label == 'go-version' and channel == 'stdout':
                        data = b'go version go1.27.2 linux/amd64\n'
                    else:
                        data = b''
                    log = root / (label + '.' + channel)
                    log.write_bytes(data)
                    check[channel + '_sha256'] = current.evidence_io.reference(log)['sha256']
                proof['checks'].append(check)
            path = root / 'receipt.json'
            path.write_text(json.dumps(proof))
            with patch.object(current, 'go_provenance'), \
                    patch.object(current.source_inventory, 'verify', return_value=proof['complete_source_inventory']):
                result = current.rejected_native_evidence(path, {})
                self.assertEqual(result['classification'], 'rejected_toolchain_isolation')
                self.assertEqual(result['new_lifecycle_pass'], 0)
                mutations = [lambda p: p.update(host_launched=True),
                    lambda p: p.update(status='pass'), lambda p: p.update(binaries={}),
                    lambda p: p.update(build_ready=True),
                    lambda p: p.update(actual_source_commit='b' * 40),
                    lambda p: p['checks'][0].update(exit_code=1)]
                for mutate in mutations:
                    changed = copy.deepcopy(proof)
                    mutate(changed)
                    path.write_text(json.dumps(changed))
                    with self.assertRaises(ValueError):
                        current.rejected_native_evidence(path, {})
                path.write_text(json.dumps(proof))
                (root / 'composite-build.stderr').write_bytes(b'other failure')
                with self.assertRaisesRegex(ValueError, 'physical reference changed'):
                    current.rejected_native_evidence(path, {})
                proof['checks'][-1]['stderr_sha256'] = current.evidence_io.reference(
                    root / 'composite-build.stderr')['sha256']
                path.write_text(json.dumps(proof))
                with self.assertRaisesRegex(ValueError, 'physical compiler/tool mismatch'):
                    current.rejected_native_evidence(path, {})

    def test_rejected_native_input_is_required(self):
        with self.assertRaises(TypeError):
            current.produce(*(Path('/input') for _ in range(5)))

    def test_cleanup_mutations_are_rejected(self):
        mutations = [lambda row: row['controller'].update(surviving_namespace_pid_count=1),
            lambda row: row['driver'].update(remaining_owned_process_count=1),
            lambda row: row['controller'].update(namespace_pin_verified=False),
            lambda row: row['artifact_integrity_issues'].append({'kind': 'changed'})]
        for mutate in mutations:
            row = observed()
            mutate(row)
            with self.assertRaisesRegex(ValueError, 'cleanup or physical integrity'):
                current.observed_contract(row, self.proof)

    def test_revision_and_original_id_injection_are_rejected(self):
        review = {'parent_sha': current.PARENT, 'host_lifecycle_qualified': False,
            'oracle_progress_assigned': False, 'scenarios': [
                {'scenario': scenario, 'route': route, 'original_oracle_case_ids': [],
                 'host_lifecycle_qualified': False} for scenario, route in current.SCENARIOS.items()]}
        current.nonqualification(review)
        review['parent_sha'] = 'b' * 40
        with self.assertRaisesRegex(ValueError, 'revision differs'):
            current.nonqualification(review)
        review['parent_sha'] = current.PARENT
        review['scenarios'][0]['original_oracle_case_ids'] = ['original']
        with self.assertRaisesRegex(ValueError, 'original ID injection'):
            current.nonqualification(review)

    def test_current_revision_contract_rejects_retained_source_binding(self):
        row = observed()
        row['build']['source_git_baseline'] = current.CURRENT_PARENT
        row['source_equality']['source_contract_parent_sha'] = current.CURRENT_PARENT
        current.observed_contract(row, self.proof, current.CURRENT_PARENT)
        row['source_equality']['source_contract_parent_sha'] = current.PARENT
        with self.assertRaisesRegex(ValueError, 'source or binary binding'):
            current.observed_contract(row, self.proof, current.CURRENT_PARENT)

    def test_v2_separates_current_native_and_review_from_retained_history(self):
        paths = [Path('/' + name) for name in (
            'native', 'admission', 'review', 'superseded-native', 'superseded-review', 'rejected-native')]
        proof = {'identity': 'current'}
        previous = {'identity': 'previous'}
        reviews = [{'scenarios': []} for _ in range(4)]
        with patch.object(current, 'native_evidence', side_effect=[proof, previous]) as native, \
                patch.object(current, 'rejected_native_evidence', return_value={}) as rejected, \
                patch.object(current, 'review_evidence', side_effect=reviews) as review, \
                patch.object(current.evidence_io, 'reference', side_effect=lambda p: {'path': str(p)}):
            result = current.produce(*paths, parent_sha=current.CURRENT_PARENT,
                previous_parent_sha=current.PARENT, schema_version=2,
                retake_review=Path('/retake'))
            self.assertEqual(result['schema'], 'i12.envoy.current-base-evidence.v2')
            self.assertEqual(result['parent_sha'], current.CURRENT_PARENT)
            self.assertEqual(result['current_parent_sha'], current.CURRENT_PARENT)
            self.assertEqual(result['previous_parent_sha'], current.PARENT)
            self.assertEqual(result['original_oracle_case_ids'], [])
            self.assertFalse(result['host_lifecycle_qualified'])
            self.assertFalse(result['oracle_progress_assigned'])
            self.assertEqual(result['new_lifecycle_pass'], 0)
            self.assertEqual(native.call_args_list[0].kwargs, {'parent_sha': current.CURRENT_PARENT})
            self.assertEqual(native.call_args_list[1].kwargs,
                             {'allow_legacy': True, 'parent_sha': current.PARENT})
            self.assertEqual(rejected.call_args.kwargs, {'parent_sha': current.PARENT})
            self.assertEqual([call.args[-1] for call in review.call_args_list],
                             [current.PARENT, current.PARENT, current.CURRENT_PARENT, current.CURRENT_PARENT])
            self.assertIs(review.call_args_list[0].args[1], previous)
            self.assertIs(review.call_args_list[1].args[1], previous)
            self.assertIs(review.call_args_list[2].args[1], proof)
            native.reset_mock(side_effect=True)
            native.side_effect = [proof, previous]
            review.reset_mock(side_effect=True)
            review.side_effect = reviews[:3]
            self.assertEqual(result['inputs']['retake_review'], {'path': '/retake'})
            self.assertEqual(result['retake']['new_lifecycle_pass'], 0)
            self.assertEqual(review.call_args_list, [])
            legacy = current.produce(*paths)
            self.assertEqual(legacy['schema'], 'i12.envoy.current-base-evidence.v1')
            self.assertEqual(legacy['parent_sha'], current.PARENT)
            self.assertNotIn('current_parent_sha', legacy)
            self.assertNotIn('previous_parent_sha', legacy)
            self.assertEqual(native.call_args_list[0].kwargs, {'parent_sha': current.PARENT})
            self.assertEqual([call.args[-1] for call in review.call_args_list], [current.PARENT] * 3)

    def test_unsupported_revision_combinations_fail_before_reading_evidence(self):
        paths = [Path('/input')] * 6
        for kwargs in ({'parent_sha': current.CURRENT_PARENT},
                       {'previous_parent_sha': current.CURRENT_PARENT},
                       {'schema_version': 2}, {'schema_version': 3}):
            with self.assertRaisesRegex(ValueError, 'unsupported supplement'):
                current.produce(*paths, **kwargs)

    def test_retake_exact_semantics_and_cleanup_mutations(self):
        with tempfile.TemporaryDirectory(dir=current.evidence_io.STORAGE) as directory:
            row = retake_fixture(Path(directory))
            refs = {}
            current.retake_contract(row, self.proof, refs)
            self.assertEqual(len(refs), 5)
            mutations = [lambda r: r.update(runner_exit_code=0),
                lambda r: r['controller'].update(exitcode=0),
                lambda r: r['controller'].update(surviving_namespace_pid_count=1),
                lambda r: r['driver']['processes']['engine'].update(forced_kill=True),
                lambda r: r['driver']['processes'].pop('backend'),
                lambda r: r['clients']['target'].update(raw_http_status=200),
                lambda r: r['clients']['target'].update(process_exit=0),
                lambda r: r['clients']['target'].update(response_body_bytes=1),
                lambda r: r['clients']['neighbor'].update(raw_http_status=504),
                lambda r: r['grpc_transport']['target']['process'].update(remote_grpc_status=0),
                lambda r: r['grpc_transport']['neighbor']['process'].update(successful_grpc_completion=True),
                lambda r: r['grpc_transport']['target'].update(received_http2_payload_callback_count=0),
                lambda r: r['backend'].update(request_count=2),
                lambda r: r['backend']['requests'].append(copy.deepcopy(r['backend']['requests'][0])),
                lambda r: r['backend'].update(raw_request_role_counts={'target': 1}),
                lambda r: r['native'].update(verified_allocation_scope_count=2),
                lambda r: r['native']['observer_states'][0].update(live_mappings=1),
                lambda r: r['native']['scopes'][0]['observed_return_counts'].update(native_cleanup=0)]
            for mutate in mutations:
                changed = copy.deepcopy(row)
                mutate(changed)
                with self.assertRaises(ValueError):
                    current.retake_contract(changed, self.proof, {})

    def test_retake_rejects_bound_physical_target_callbacks(self):
        cases = [('runtime/native-lifecycle.jsonl', lambda rows: rows[0].update(transaction_id='target')),
            ('runtime/native-lifecycle.jsonl', lambda rows: rows[0].update(input_transaction_id='target')),
            ('runtime/native-lifecycle.jsonl', lambda rows: rows[0].update(allocation_scope_call=3)),
            ('runtime/native-lifecycle.jsonl', lambda rows: rows[0].update(monotonic_ns=0)),
            ('runtime/host-lifecycle.jsonl', lambda rows: rows[0].update(allocation_scope_call=3)),
            ('runtime/host-lifecycle.jsonl', lambda rows: rows[0].update(pid=11)),
            ('runtime/adapter-events.jsonl', lambda rows: rows[0].update(transaction_id='target')),
            ('runtime/adapter-events.jsonl', lambda rows: rows[0].update(request_header_count=1)),
            ('runtime/adapter-events.jsonl', lambda rows: rows[0].update(request_body_bytes=95)),
            ('runtime/adapter-events.jsonl', lambda rows: rows[1].update(response_body_bytes=0))]
        with tempfile.TemporaryDirectory(dir=current.evidence_io.STORAGE) as directory:
            for name, mutate in cases:
                row = retake_fixture(Path(directory))
                path = Path(directory) / 'data' / name
                rows = [json.loads(line) for line in path.read_text().splitlines()]
                mutate(rows)
                path.write_text(''.join(json.dumps(x) + '\n' for x in rows))
                # Even a self-consistent new hash must not bypass semantic checks.
                row['physical_files'][name] = current.evidence_io.reference(path)
                with self.assertRaisesRegex(ValueError, 'retake target'):
                    current.retake_contract(row, self.proof, {})

    def test_retake_rejects_changed_physical_log_hash(self):
        with tempfile.TemporaryDirectory(dir=current.evidence_io.STORAGE) as directory:
            row = retake_fixture(Path(directory))
            (Path(directory) / 'data/runtime/native-lifecycle.jsonl').write_text('{}\n')
            with self.assertRaisesRegex(ValueError, 'physical reference changed'):
                current.retake_contract(row, self.proof, {})

    def test_v2_requires_retake_before_reading_any_evidence(self):
        with patch.object(current, 'native_evidence') as read:
            with self.assertRaisesRegex(ValueError, 'v2 requires retake'):
                current.produce(*([Path('/input')] * 6), parent_sha=current.CURRENT_PARENT,
                    previous_parent_sha=current.PARENT, schema_version=2)
            read.assert_not_called()
        with self.assertRaisesRegex(ValueError, 'v2 requires retake'):
            current.produce(*([Path('/input')] * 6), parent_sha=current.PARENT,
                previous_parent_sha=current.PARENT, schema_version=1, retake_review=Path('/retake'))

    def test_v2_validation_requires_retake_and_v1_rejects_extra_input(self):
        ref = {'path': '/input', 'sha256': 'sha', 'bytes': 1}
        supplement = {'schema': 'i12.envoy.current-base-evidence.v2', 'inputs': dict.fromkeys(('native', 'admission_review', 'review', 'superseded_native',
                                'superseded_review', 'rejected_native'), ref)}
        with patch.object(current.evidence_io, 'read_json', return_value=supplement):
            with self.assertRaisesRegex(ValueError, 'v2 requires retake review input'):
                current.validate(Path('/supplement'))
            supplement['schema'] = 'i12.envoy.current-base-evidence.v1'
            supplement['inputs']['retake_review'] = ref
            with self.assertRaisesRegex(ValueError, 'supplement input set differs'):
                current.validate(Path('/supplement'))

    def test_changed_file_hash_is_rejected(self):
        with tempfile.TemporaryDirectory(dir=current.evidence_io.STORAGE) as directory:
            path = Path(directory) / 'receipt.json'
            path.write_text('{}')
            original = current.evidence_io.reference(path)
            path.write_text('{"changed":true}')
            with self.assertRaisesRegex(ValueError, 'physical reference changed'):
                current.bind(path, original['sha256'], {})

    def test_runner_log_path_accepts_each_sealed_variant_and_rejects_ambiguity(self):
        with tempfile.TemporaryDirectory(dir=current.evidence_io.STORAGE) as directory:
            root = Path(directory)
            snapshot = root / 'review.runs-input.json'
            for prefix in ('runs-', 'host-runs-'):
                path = root / (prefix + 'route.stdout')
                path.write_text(prefix)
                self.assertEqual(current.runner_log_path(snapshot, 'route', 'stdout'), path)
                path.unlink()
            with self.assertRaisesRegex(ValueError, 'missing or ambiguous'):
                current.runner_log_path(snapshot, 'route', 'stdout')
            for prefix in ('runs-', 'host-runs-'):
                (root / (prefix + 'route.stdout')).write_text(prefix)
            with self.assertRaisesRegex(ValueError, 'missing or ambiguous'):
                current.runner_log_path(snapshot, 'route', 'stdout')

    def test_supplement_requires_admission_input(self):
        inputs = dict(native=Path('/native'), review=Path('/review'),
                      superseded_native=Path('/superseded-native'),
                      superseded_review=Path('/superseded-review'), rejected_native=Path('/rejected-native'))
        with self.assertRaisesRegex(TypeError, "missing 1 required positional argument: 'admission_review'"):
            current.produce(**inputs)

    def test_validation_replays_and_rejects_supplement_mutation(self):
        ref = {'path': '/native', 'sha256': 'native', 'bytes': 1}
        supplement = {'schema': 'i12.envoy.current-base-evidence.v1', 'inputs': {name: dict(ref) for name in (
            'native', 'admission_review', 'review', 'superseded_native', 'superseded_review', 'rejected_native')},
                      'new_lifecycle_pass': 0}
        with patch.object(current.evidence_io, 'read_json', return_value=supplement), \
                patch.object(current.evidence_io, 'reference', return_value=ref), \
                patch.object(current, 'produce', return_value=copy.deepcopy(supplement)) as replay:
            self.assertEqual(current.validate(Path('/supplement')), supplement)
            replay.assert_called_once()
            self.assertEqual(replay.call_args.kwargs, {'parent_sha': current.PARENT,
                'previous_parent_sha': current.PARENT, 'schema_version': 1})
            supplement['new_lifecycle_pass'] = 1
            with self.assertRaisesRegex(ValueError, 'fresh validation'):
                current.validate(Path('/supplement'))

    def test_v2_validation_replays_fixed_revisions_and_rejects_unknown_schema(self):
        ref = {'path': '/native', 'sha256': 'native', 'bytes': 1}
        supplement = {'schema': 'i12.envoy.current-base-evidence.v2',
            'parent_sha': current.CURRENT_PARENT, 'current_parent_sha': current.CURRENT_PARENT,
            'previous_parent_sha': current.PARENT, 'inputs': {name: dict(ref) for name in (
                'native', 'admission_review', 'review', 'superseded_native',
                'superseded_review', 'rejected_native', 'retake_review')}, 'new_lifecycle_pass': 0}
        with patch.object(current.evidence_io, 'read_json', return_value=supplement), \
                patch.object(current.evidence_io, 'reference', return_value=ref), \
                patch.object(current, 'produce', return_value=copy.deepcopy(supplement)) as replay:
            self.assertEqual(current.validate(Path('/supplement')), supplement)
            self.assertEqual(replay.call_args.kwargs, {'parent_sha': current.CURRENT_PARENT,
                'previous_parent_sha': current.PARENT, 'schema_version': 2,
                'retake_review': Path('/native')})
            supplement['previous_parent_sha'] = current.CURRENT_PARENT
            with self.assertRaisesRegex(ValueError, 'fresh validation'):
                current.validate(Path('/supplement'))
            supplement['schema'] = 'i12.envoy.current-base-evidence.v4'
            with self.assertRaisesRegex(ValueError, 'unsupported supplement schema'):
                current.validate(Path('/supplement'))

    def test_v3_revalidates_pinned_history_and_binds_current_routes(self):
        with tempfile.TemporaryDirectory(dir=current.evidence_io.STORAGE) as directory:
            root = Path(directory)
            history_file = root / 'old.log'
            history_file.write_text('history')
            previous_path = root / 'previous.json'
            previous = {'schema': 'i12.envoy.current-base-evidence.v2',
                'parent_sha': current.CURRENT_PARENT, 'current_parent_sha': current.CURRENT_PARENT,
                'previous_parent_sha': current.PARENT,
                'physical_references': {str(history_file): current.evidence_io.reference(history_file)}}
            previous_path.write_text(json.dumps(previous))
            paths = [root / name for name in ('native', 'admission', 'review')]
            for path in paths:
                path.write_text('{}')
            rows = [{'route': route, 'grpc_transport': {'process': {
                'remote_grpc_status': None, 'successful_grpc_completion': False}}}
                for route in current.SCENARIOS.values()]
            proof = {'identity': 'afaf'}
            def native(path, references, **kwargs):
                current.bind(path, current.evidence_io.reference(path)['sha256'], references)
                return proof
            with patch.object(current, 'validate', return_value=previous) as replay, \
                    patch.object(current, 'native_evidence', side_effect=native) as build, \
                    patch.object(current, 'review_evidence', side_effect=[{'scenarios': []}, {'scenarios': rows}]) as review:
                result = current.produce_v3(*paths, previous_path)
            replay.assert_called_once_with(previous_path)
            self.assertEqual(build.call_args.kwargs, {'parent_sha': current.AFAF_PARENT})
            self.assertEqual([call.args[-1] for call in review.call_args_list], [current.AFAF_PARENT] * 2)
            self.assertTrue(all(call.args[1] is proof for call in review.call_args_list))
            self.assertEqual(result['parent_sha'], current.AFAF_PARENT)
            self.assertEqual(result['previous_parent_sha'], current.CURRENT_PARENT)
            self.assertEqual(set(result['inputs']), {'native', 'admission_review', 'review', 'previous_supplement'})
            self.assertEqual(result['new_lifecycle_pass'], 0)
            self.assertEqual(result['original_oracle_case_ids'], [])
            self.assertFalse(result['oracle_progress_assigned'])
            self.assertFalse(result['host_lifecycle_qualified'])
            self.assertEqual(result['toolchains']['actual_engine_build_go'], '1.27.2')
            self.assertEqual(result['toolchains']['host_environment_go'], '1.27.3')
            self.assertEqual(result['physical_references'][str(history_file)], previous['physical_references'][str(history_file)])
            self.assertIn(str(previous_path), result['physical_references'])
            self.assertIn(str(paths[0]), result['physical_references'])
            for observation in result['route_transport_observations'].values():
                self.assertIsNone(observation['process']['remote_grpc_status'])
                self.assertFalse(observation['process']['successful_grpc_completion'])
            # A rehashed history object cannot make changed physical history valid.
            history_file.write_text('tampered')
            with patch.object(current, 'validate', return_value=previous), \
                    self.assertRaisesRegex(ValueError, 'previous physical reference changed'):
                current.produce_v3(*paths, previous_path)

    def test_v3_rejects_wrong_history_schema_revision_and_cycles_before_replay(self):
        previous = {'schema': 'i12.envoy.current-base-evidence.v2',
            'parent_sha': current.CURRENT_PARENT, 'current_parent_sha': current.CURRENT_PARENT,
            'previous_parent_sha': current.PARENT}
        mutations = [lambda p: p.update(schema='i12.envoy.current-base-evidence.v1'),
            lambda p: p.update(schema='i12.envoy.current-base-evidence.v3'),
            lambda p: p.update(parent_sha=current.AFAF_PARENT),
            lambda p: p.update(current_parent_sha=current.PARENT),
            lambda p: p.update(previous_parent_sha=current.CURRENT_PARENT)]
        for mutate in mutations:
            changed = copy.deepcopy(previous)
            mutate(changed)
            with patch.object(current.evidence_io, 'read_json', return_value=changed), \
                    patch.object(current, 'validate') as replay, \
                    self.assertRaisesRegex(ValueError, 'pinned E4 v2'):
                current.produce_v3(*([Path('/input')] * 4))
            replay.assert_not_called()

    def test_v3_rejects_reference_union_conflicts(self):
        with tempfile.TemporaryDirectory(dir=current.evidence_io.STORAGE) as directory:
            path = Path(directory) / 'history'
            path.write_text('{}')
            ref = current.evidence_io.reference(path)
            previous = {'schema': 'i12.envoy.current-base-evidence.v2',
                'parent_sha': current.CURRENT_PARENT, 'current_parent_sha': current.CURRENT_PARENT,
                'previous_parent_sha': current.PARENT, 'physical_references': {str(path): ref}}
            def conflict(_, refs, **kwargs):
                refs[str(path)] = {**ref, 'sha256': '0' * 64}
                return {}
            with patch.object(current.evidence_io, 'read_json', return_value=previous), \
                    patch.object(current, 'validate', return_value=previous), \
                    patch.object(current, 'native_evidence', side_effect=conflict), \
                    patch.object(current, 'review_evidence', return_value={'scenarios': []}), \
                    self.assertRaisesRegex(ValueError, 'physical reference conflict'):
                current.produce_v3(path, path, path, path)

    def test_v3_validation_replays_and_rejects_mutation_and_changed_inputs(self):
        ref = {'path': '/input', 'sha256': 'sha', 'bytes': 1}
        supplement = {'schema': 'i12.envoy.current-base-evidence.v3',
            'inputs': {name: dict(ref) for name in ('native', 'admission_review', 'review', 'previous_supplement')},
            'new_lifecycle_pass': 0}
        with patch.object(current.evidence_io, 'read_json', return_value=supplement), \
                patch.object(current.evidence_io, 'reference', return_value=ref) as reference, \
                patch.object(current, 'produce_v3', return_value=copy.deepcopy(supplement)) as replay:
            self.assertEqual(current.validate(Path('/supplement')), supplement)
            replay.assert_called_once_with(*([Path('/input')] * 4))
            for field, value in (('new_lifecycle_pass', 1), ('parent_sha', current.CURRENT_PARENT),
                                 ('oracle_progress_assigned', True), ('original_oracle_case_ids', ['injected'])):
                changed = copy.deepcopy(supplement)
                changed[field] = value
                with patch.object(current.evidence_io, 'read_json', return_value=changed), \
                        self.assertRaisesRegex(ValueError, 'fresh validation'):
                    current.validate(Path('/supplement'))
            reference.return_value = {**ref, 'sha256': 'changed'}
            with self.assertRaisesRegex(ValueError, 'supplement input changed'):
                current.validate(Path('/supplement'))

    def test_v3_cli_rejects_mixed_or_incomplete_modes_before_reading(self):
        base = ['producer', '--native', '/native', '--admission-review', '/admission',
                '--review', '/review', '--output', '/output']
        for extra in ([], ['--previous-supplement', '/previous', '--retake-review', '/retake']):
            with contextlib.redirect_stderr(io.StringIO()), \
                    patch('sys.argv', base + extra), patch.object(current, 'produce') as legacy, \
                    patch.object(current, 'produce_v3') as v3, self.assertRaises(SystemExit) as error:
                current.main()
            self.assertEqual(error.exception.code, 2)
            legacy.assert_not_called()
            v3.assert_not_called()

    def test_cli_dispatches_both_modes_without_changing_legacy_api(self):
        with tempfile.TemporaryDirectory(dir=current.evidence_io.STORAGE) as directory:
            output = Path(directory) / 'output.json'
            base = ['producer', '--native', '/native', '--admission-review', '/admission',
                    '--review', '/review', '--output', str(output)]
            cases = [(['--previous-supplement', '/previous'], 'produce_v3'),
                (['--superseded-native', '/old-native', '--superseded-review', '/old-review',
                  '--rejected-native', '/rejected'], 'produce'),
                (['--superseded-native', '/old-native', '--superseded-review', '/old-review',
                  '--rejected-native', '/rejected', '--retake-review', '/retake'], 'produce')]
            for extra, selected in cases:
                with contextlib.redirect_stdout(io.StringIO()), patch('sys.argv', base + extra), \
                        patch.object(current, selected, return_value={'new_lifecycle_pass': 0}) as produce:
                    current.main()
                self.assertEqual(json.loads(output.read_text()), {'new_lifecycle_pass': 0})
                self.assertEqual(produce.call_args.args[:3], (Path('/native'), Path('/admission'), Path('/review')))
                if selected == 'produce_v3':
                    self.assertEqual(produce.call_args.args[3:], (Path('/previous'),))
                else:
                    self.assertEqual(produce.call_args.args[3:],
                        (Path('/old-native'), Path('/old-review'), Path('/rejected')))
                    if '--retake-review' in extra:
                        self.assertEqual(produce.call_args.kwargs, {
                            'parent_sha': current.CURRENT_PARENT,
                            'previous_parent_sha': current.PARENT,
                            'schema_version': 2,
                            'retake_review': Path('/retake')})
                    else:
                        self.assertEqual(produce.call_args.kwargs, {})
                output.unlink()



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == '__main__':
    unittest.main()
