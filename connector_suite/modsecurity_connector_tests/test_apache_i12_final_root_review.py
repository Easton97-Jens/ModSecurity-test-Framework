"""Physical-file mutation negatives for the conservative Apache Root procedure."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import base64
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SOURCE = connector_root() / 'reports/audits/apache-i12-20261020/final_review.py'
R = load_source(SOURCE)


def encoded(data):
    return {'encoding': 'base64', 'data': base64.b64encode(data).decode(),
            'bytes': len(data), 'sha256': R.digest(data)}


class FinalReviewTest(unittest.TestCase):
    def setUp(self):
        root = Path('/var/tmp/codex/ModSecurity-conector/runs/apache-final-review-unit')
        root.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=root)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.name = 'NEED-request-single-chunk'
        self.identity = 'I12::apache-native::' + self.name
        self.oracle = {'native_result': 'allow', 'visible_status': 200, 'phase': 2,
                       'rule_id': None, 'event_fields': [], 'physical_evidence_not_projection': True,
                       'unresolved_expected_value_reason': None}
        self.row = {'run_scoped_case_id': self.identity, 'leg_id': 'apache-native',
                    'selected_requirement': {'case_id': self.name, 'expected_oracle': self.oracle}}
        self.plan = {'original_id': self.identity, 'case_id': self.name, 'original_oracle': self.oracle,
                     'execution_kind': 'host_http', 'driver_seams': [], 'fault': None,
                     'request': {'method': 'POST', 'path': '/i12/' + self.name,
                                 'body': encoded(b'Apache-I12-request-payload'),
                                 'headers': [['Content-Type', 'text/plain']],
                                 'framing': 'content_length', 'peer_action': 'normal'},
                     'backend': {'body': encoded(b'Apache I12 healthy body\n'), 'framing': 'content_length'},
                     'candidate_expectation': {'visible_status': 200, 'native_rule_id': 91041950,
                                               'native_phase': 1, 'backend_requests': 1},
                     'controls': [{'label': label, 'path': '/' + label, 'method': 'GET',
                                   'expected_status': 200, 'backend_body': encoded(b'OK\n')}
                                  for label in ('followup', 'neighbor')]}
        self.expected = {'run_id': 'unit-run', 'parent_sha': 'parent', 'framework_sha': 'framework',
                         'mrts_sha': 'mrts', 'apache_sha256': 'apache', 'module_sha256': 'module',
                         'sdk_sha256': 'sdk'}
        self.packet = dict(self.expected, run_scoped_case_id=self.identity, leg_id='apache-native',
                           actual_scenario_variant=self.name, original_selected_requirement=self.row['selected_requirement'],
                           execution_kind='host_http', execution_observed=True, outcome=None,
                           effective_config_sha256='config', review_checks={key: True for key in R.CHECKS},
                           driver_execution={'actual_principal_execution': True, 'executed_case_contract': True,
                                             'missing_operations': [], 'execution_error': None,
                                             'reference': self.write('observation.json', {})}, observations={})
        for name, roles in R.SHARED.ROLES.items():
            refs = [dict(self.write(name + '-' + role + '.txt', 'physical ' + name), role=role)
                    for role in roles]
            self.packet['observations'][name] = {'applicable': True, 'value': 1, 'evidence': refs}
        request_body = b'Apache-I12-request-payload'
        response_body = b'Apache I12 healthy body\n'
        request = ('POST /i12/' + self.name + ' HTTP/1.1\r\nContent-Type: text/plain\r\nContent-Length: 26\r\n\r\n').encode() + request_body
        response = b'HTTP/1.1 200 OK\r\nContent-Length: 24\r\n\r\n' + response_body
        self.put('client_bytes', {'request_wire': len(request), 'response_wire': len(response),
                                  'response_entity': len(response_body)})
        self.packet['observations']['client_bytes']['evidence'] = [
            dict(self.write('request.raw', request), role='client_process'),
            dict(self.write('response.raw', response), role='client_process')]
        self.put('client_sha256', {'request_wire': R.digest(request), 'response_wire': R.digest(response),
                                  'response_entity': R.digest(response_body)})
        self.put('client_exit', 0)
        self.put('client_signal', {'actual_signal': None})
        self.put('client_headers', {'status': 200})
        self.put('transport_framing', {'kind': 'content_length', 'content_lengths': ['24'],
                                       'transfer_encoding': [], 'decoded_entity_bytes': 24})
        self.put('transport_reset_scope', {'tcp_eof_observed': True, 'tcp_reset_observed': False,
                                           'timeout_observed': False, 'error': None})
        self.put('backend_request_count', {'main': 1})
        backend = [{'kind': 'request_arrival', 'request_id': 'main'},
                   {'kind': 'request', 'request_id': 'main', 'uri': self.plan['request']['path'],
                    'method': 'POST', 'body_bytes': len(request_body), 'body_sha256': R.digest(request_body)},
                   {'kind': 'backend_eos_write', 'request_id': 'main', 'body_bytes': len(response_body),
                    'body_sha256': R.digest(response_body)}]
        self.put('backend_payload_identity', {'physical_transcript': backend})
        self.put('native_transaction_id', {'transaction_id': 'native-main'})
        self.put('common_transaction_id', {'transaction_id': 'common-main'})
        functions = ('native_process_request_headers', 'native_process_request_body',
                     'native_process_response_headers', 'native_process_response_body')
        self.put('native_phases', [{'phase': phase, 'result': 1, 'edge': 'return', 'function': function}
                                   for phase, function in enumerate(functions, 1)])
        self.put('native_body_chunks', [{'function': 'native_append_request_body', 'input_size': len(request_body), 'result': 1},
                                        {'function': 'native_append_response_body', 'input_size': len(response_body), 'result': 1}])
        self.put('native_intervention_or_first_cause', {'actual_native_intervention_returns': [{'result': 0}]})
        self.put('native_events', {'native_audit_lines': ['---a---A--\n[time] native-main 1 2 3 4\n---a---H--\n[id "91041950"]\n---a---Z--\n'],
                                   'physical_common_rows': [{'actual_action': 'allow', 'event': 'rule_match',
                                                            'rule_id': '91041950', 'phase': 'request_headers',
                                                            'transaction_id': 'common-main', 'connector': 'apache',
                                                            'integration_mode': 'native-httpd-module', 'method': 'POST',
                                                            'uri': self.plan['request']['path']}],
                                   'common_sink_mode': '0o600'})
        self.put('terminal_event_count', {'actual_common_terminal_subset_count': 0})
        self.put('host_eos', {'actual_apr_eos_rows': [{'kind': kind} for kind in ('actual_request_apr_eos', 'actual_response_apr_eos')]})
        self.put('native_eos', {'native_request_finalization_returns': [{}], 'native_response_finalization_returns': [{}]})
        self.put('finish_calls', {'common_finish': 1, 'native_logging': 1})
        self.put('native_free_calls', {'native_cleanup': 1, 'common_cleanup': 1, 'host_association_retire': 1})
        self.put('finish_transitions', {'completed_status_3_transitions': 1})
        self.put('commit_order', {'physical_socket_observation': {'actual_socket_call_brackets': [
                                      {'entered_ns': 30, 'return_ns': 40, 'result': 80,
                                       'reported_bytes': 80, 'stream_accounted_here': True}]},
                                  'actual_output_handoffs': [
                                      {'kind': 'output_prefix_release_enter', 'sequence': 3,
                                       'monotonic_ns': 17, 'invalid': False, 'response_committed': 1,
                                       'response_eos_released': 0, 'response_body_processed': 0},
                                      {'kind': 'output_prefix_release_return_ok', 'sequence': 4,
                                       'monotonic_ns': 18, 'invalid': False, 'response_committed': 1,
                                       'response_eos_released': 0, 'response_body_processed': 0},
                                      {'kind': 'output_terminal_release_enter', 'sequence': 6,
                                       'monotonic_ns': 22, 'invalid': False, 'response_committed': 1,
                                       'response_eos_released': 1, 'response_body_processed': 1},
                                      {'kind': 'output_terminal_release_return_ok', 'sequence': 7,
                                       'monotonic_ns': 23, 'invalid': False, 'response_committed': 1,
                                       'response_eos_released': 1, 'response_body_processed': 1}],
                                  'native_p4_edges': [{'edge': 'return', 'result': 1, 'monotonic_ns': 20}],
                                  'internal_committed_flag_returns': [
                                      {'result': 0, 'argument_committed': 1, 'invalid': False,
                                       'monotonic_ns': 16, 'contract_state': {'response_committed': 1}}]})
        self.put('process_listener_cleanup', {'supervisor_reaped': True, 'surviving_namespace_pids': [],
                                               'outside_mount_leaks': [], 'errors': [], 'exitcode': 0, 'controller_exitcode': 0})
        self.put('cleanup_receipts', {'actual_native_observer_finals': [
                                          {'pending_calls': 0, 'live_mappings': 0,
                                           'invalid': False, 'monotonic_ns': 100}],
                                      'actual_same_pid_pre_host_observer_finals': [],
                                      'actual_same_pid_in_host_window_observer_finals': [],
                                      'sampler_thread_stopped': True, 'sampler_errors': []})
        self.put('descriptor_cleanup', {'actual_fd_differences': {label: {'added': {}, 'removed': {}, 'changed': {}}
                                                                  for label in ('main', 'neighbor')}})
        self.put('observed_handle_association', {'host_association': {'pid': 123, 'allocation_scope_call': 1}})
        self.put('native_api_returns', [{'run': 'unit-run', 'pid': 123, 'allocation_scope_call': 1,
                                         'allocation_scope_kind': 'host'}])
        self.put('neighbor_health', {'same_native_host_pid': True,
                                     'actual_host_association': {'pid': 123, 'allocation_scope_call': 2},
                                     'separate_actual_client': {'status': 200}, 'actual_waited_process': {'waited_exit': 0},
                                     'independent_backend': [{}]})
        self.put('product_host_identity', {'actual_uid': 65534, 'actual_gid': 65534,
                                           'apache_binary': {'sha256': 'apache'},
                                           'mapped_images': [{'mapped_path': name, 'sha256': sha,
                                                              'admission_sha256_matches': True}
                                                             for name, sha in (('mod_security3.so', 'module'), ('libmodsecurity.so', 'sdk'))]})
        control_rows = []
        for control in self.plan['controls']:
            label = control['label']
            self.write(label + '/receipt.json', {'path': '/' + label, 'method': 'GET', 'status': 200,
                                                 'entity_sha256': R.digest(b'OK\n'), 'started_ns': 50, 'completed_ns': 70})
            self.write(label + '/process.command.json', {'waited_exit': 0})
            self.write(label + '/response.raw', b'HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nOK\n')
            control_rows.append({'kind': 'request', 'uri': '/' + label, 'method': 'GET', 'monotonic_ns': 60})
        self.write('backend/requests.jsonl', '\n'.join(json.dumps(row) for row in control_rows))
        self.add_physical_lifecycle()

    def add_physical_lifecycle(self):
        identity = {'pid': 123, 'run': 'unit-run', 'allocation_scope_call': 1,
                    'allocation_scope_kind': 'host', 'invalid': False}
        operations = (
            ('native_process_request_headers', 1, 5, 1),
            ('native_process_request_body', 2, 10, 1),
            ('native_process_response_headers', 3, 15, 1),
            ('native_process_response_body', 4, 20, 1),
            ('common_finish', 0, 50, 0), ('native_process_logging', 0, 60, 1),
            ('common_cleanup', 0, 70, 0), ('native_cleanup', 0, 80, None),
            ('host_association_retire', 0, 90, 1),
        )
        self.physical_api = []
        for call, (function, phase, timestamp, result) in enumerate(operations, 1):
            self.physical_api.extend([
                dict(identity, function=function, phase=phase, call=call, sequence=call * 2,
                     monotonic_ns=timestamp, edge='enter', result=None),
                dict(identity, function=function, phase=phase, call=call, sequence=call * 2 + 1,
                     monotonic_ns=timestamp + 1, edge='return', result=result)])
        returned = [row for row in self.physical_api if row['edge'] == 'return']
        self.put('native_phases', returned[:4])
        self.put('native_api_returns', returned)
        ref = self.write('native-api.jsonl', '\n'.join(json.dumps(row) for row in self.physical_api))
        self.packet['observations']['native_api_returns']['evidence'] = [dict(ref, role='native_api')]
        self.put('host_eos', {'actual_apr_eos_rows': [
            dict(identity, kind='actual_request_apr_eos', sequence=1, monotonic_ns=9,
                 actual_apr_bucket_is_eos=True, request_body_processed=0,
                 request_eos_released=0),
            dict(identity, kind='actual_response_apr_eos', sequence=2, monotonic_ns=19,
                 actual_apr_bucket_is_eos=True, request_eos_released=1,
                 response_body_processed=0, response_eos_seen=1, response_committed=1)]})
        self.put('native_eos', {'native_request_finalization_returns': [returned[1]],
                                'native_response_finalization_returns': [returned[3]]})
        self.packet['observations']['commit_order']['value']['native_p4_edges'] = [
            row for row in self.physical_api if row['function'] == 'native_process_response_body']

    def write(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(data, bytes):
            path.write_bytes(data)
        else:
            path.write_text(data if isinstance(data, str) else json.dumps(data))
        return R.O.reference(path)

    def put(self, name, value):
        self.packet['observations'][name]['value'] = value

    def evaluate(self, reextracted=None, oracle=True):
        ref = self.write('candidate.json', self.packet)
        return R.evaluate(self.row, self.plan, self.packet, ref, self.expected,
                          copy.deepcopy(self.packet) if reextracted is None else reextracted,
                          self.oracle if oracle else None)

    def test_registered_complete_semantics_can_pass_and_shared_validator_is_real(self):
        decision = self.evaluate()
        self.assertEqual(decision['outcome'], 'PASS', decision['predicates'])
        output = self.root / 'approved'
        output.mkdir()
        ref = R.publish_packet(output, self.packet, decision, self.row, self.oracle)
        self.assertTrue(R.SHARED.reviewed_packet(ref, self.row, self.oracle)['full_lifecycle_qualified'])

    def test_review_procedure_binds_all_direct_validator_sources(self):
        references = R.review_procedure_inventory()
        names = {Path(item['path']).name for item in references}
        self.assertLessEqual(
            {'final_review.py', 'review_batch.py', 'review.py',
             'review_controls.py', 'ledger.py', 'paths.py',
             'generate-pr382-i12-lifecycle-ledger.py',
             'generate-pr382-i12-oracle-reconciliation.py'},
            names,
        )
        self.assertTrue(all(item['role'] == 'review_procedure'
                            and R.O.verify_reference(item) for item in references))

    def test_review_procedure_is_published_in_inventory(self):
        output = self.root / 'results'
        output.mkdir()
        procedure = [dict(self.write('procedure.py', 'loaded source'),
                          role='review_procedure')]
        decisions = [{'registry_inventory': {'category': 'unit'}}]
        with patch('builtins.print'):
            R.write_results(output, {}, procedure, procedure, decisions, [])
        result = json.loads((output / 'decisions.json').read_text())
        self.assertEqual(result['review_procedure'], procedure)
        self.assertEqual(result['physical_input_inventory'], procedure)

    def test_review_source_mutation_during_extraction_prevents_publication(self):
        procedure_path = self.root / 'procedure.py'
        procedure_path.write_text('loaded source')
        input_paths = {}
        for name in ('baseline', 'plan', 'unsigned_index', 'identity', 'spec'):
            path = self.root / (name + '.json')
            path.write_text('{}')
            input_paths[name] = path
        args = SimpleNamespace(
            **input_paths,
            **{name + '_sha256': R.O.reference(path)['sha256']
               for name, path in input_paths.items()},
            attempt=self.root / 'attempt', oracle_reviews=None,
            oracle_reviews_sha256=None, output=self.root / 'must-not-exist',
            approve_supported_families=False)

        def mutate_during_extraction(_attempt, _spec):
            procedure_path.write_text('changed during extraction')
            return []

        with patch.object(R, 'arguments', return_value=args), \
                patch.object(R, 'review_procedure_inventory',
                             side_effect=lambda: [dict(R.O.reference(procedure_path),
                                                       role='review_procedure')]), \
                patch.object(R, 'read_ref', return_value={}), \
                patch.object(R, 'validate_inputs', return_value=[]), \
                patch.object(R, 'validate_expected_identity'), \
                patch.object(R, 'load_candidates', return_value=([], [])), \
                patch.object(R.BATCH, 'extract_all', side_effect=mutate_during_extraction), \
                patch.object(R, 'load_oracle_reviews', return_value={}), \
                patch.object(R, 'evaluate_batch', return_value=([], [])):
            with self.assertRaises(ValueError):
                R.main()
        self.assertFalse(args.output.exists())

    def test_normalized_oracle_retest_measurements_join_frozen_inventory(self):
        measurement = dict(self.write('retest-measurement.json', {'observed': True}),
                           role='independent_host_probe')
        reviews_ref = self.write('oracle-reviews.json', {'records': []})
        args = SimpleNamespace(oracle_reviews=Path(reviews_ref['path']),
                               oracle_reviews_sha256=reviews_ref['sha256'])
        record = {'run_scoped_case_id': self.identity}
        normalized = {'retest': {'measurement_evidence': [measurement]}}
        inventory = []
        inputs = {}
        with patch.object(R, 'read_ref', return_value={'records': [record]}), \
                patch.object(R.O, 'review_record', return_value=normalized):
            actual = R.load_oracle_reviews(args, inputs, [self.row], inventory)
        self.assertEqual(actual, {self.identity: normalized})
        self.assertIn(measurement['path'], {item['path'] for item in inventory})
        self.assertEqual(inputs['oracle_reviews']['sha256'], reviews_ref['sha256'])

    def test_complete35_fields_do_not_override_wrong_semantics(self):
        mutations = (
            ('status', 'client_headers', lambda x: x.update(status=403)),
            ('backend_count', 'backend_request_count', lambda x: x.update(main=2)),
            ('backend_bytes', 'backend_payload_identity', lambda x: x['physical_transcript'][1].update(body_bytes=0)),
            ('wrong_rule', 'native_events', lambda x: x.update(native_audit_lines=[line.replace('91041950', '99999999') for line in x['native_audit_lines']])),
            ('appendbytes', 'native_body_chunks', lambda x: x[0].update(input_size=0)),
            ('phase', 'native_phases', lambda x: x[1].update(result=-1)),
            ('EOS', 'host_eos', lambda x: x['actual_apr_eos_rows'].pop()),
            ('commit', 'commit_order', lambda x: x['physical_socket_observation']['actual_socket_call_brackets'][0].update(entered_ns=1)),
            ('finish', 'finish_calls', lambda x: x.update(common_finish=2)),
            ('free', 'native_free_calls', lambda x: x.update(native_cleanup=0)),
            ('cleanup', 'process_listener_cleanup', lambda x: x.update(surviving_namespace_pids=[9])),
            ('descriptor', 'descriptor_cleanup', lambda x: x['actual_fd_differences']['main']['added'].update({'9': 'socket:[1]'})),
            ('neighbor_pid', 'neighbor_health', lambda x: x['actual_host_association'].update(pid=999)),
            ('neighbor_scope', 'neighbor_health', lambda x: x['actual_host_association'].update(allocation_scope_call=1)),
            ('native_run', 'native_api_returns', lambda x: x[0].update(run='wrong')),
            ('native_pid', 'native_api_returns', lambda x: x[0].update(pid=999)),
            ('native_allocation', 'native_api_returns', lambda x: x[0].update(allocation_scope_call=9)),
            ('common_rule_phase', 'native_events', lambda x: x['physical_common_rows'][0].update(phase='response_body')),
            ('common_transaction_id', 'native_events', lambda x: x['physical_common_rows'][0].update(transaction_id='neighbor')),
            ('committed_argument', 'commit_order', lambda x: x['internal_committed_flag_returns'][0].update(argument_committed=0)),
            ('transport_complete', 'transport_framing', lambda x: x.update(decoded_entity_bytes=0)),
        )
        original = copy.deepcopy(self.packet)
        for label, field, mutate in mutations:
            self.packet = copy.deepcopy(original)
            mutate(self.packet['observations'][field]['value'])
            with self.subTest(label=label):
                self.assertEqual(len(self.packet['observations']), 35)
                result = self.evaluate()
                self.assertIsNone(result['outcome'])
                self.assertTrue(any(item['result'] == 'FAIL' for item in result['predicates']))

    def test_missing_evidence_role_cannot_qualify(self):
        self.packet['observations']['native_phases']['evidence'] = []
        self.assertIsNone(self.evaluate()['outcome'])

    def test_reextraction_mismatch_cannot_qualify(self):
        original = copy.deepcopy(self.packet)
        original['run_id'] = 'another-attempt'
        self.assertIsNone(self.evaluate(reextracted=original)['outcome'])

    def test_exact_sdk_module_run_and_source_identity_required(self):
        original = copy.deepcopy(self.packet)
        for key in ('parent_sha', 'framework_sha', 'mrts_sha', 'run_id'):
            self.packet = copy.deepcopy(original)
            self.packet[key] = 'wrong'
            with self.subTest(key=key):
                self.assertIsNone(self.evaluate()['outcome'])
        for key in ('module_sha256', 'sdk_sha256', 'apache_sha256'):
            before = self.expected[key]
            self.expected[key] = 'wrong'
            with self.subTest(key=key):
                self.assertIsNone(self.evaluate()['outcome'])
            self.expected[key] = before

    def test_unregistered_family_remains_null_even_complete35(self):
        self.plan['case_id'] = 'NEED-response-file'
        self.assertIsNone(self.evaluate()['outcome'])

    def test_missing_oracle_does_not_become_expectation(self):
        self.assertIsNone(self.evaluate(oracle=False)['outcome'])

    def test_unimplemented_oracle_semantic_key_remains_unknown(self):
        self.oracle['native_file_upload_count'] = 1
        result = self.evaluate()
        self.assertIsNone(result['outcome'])
        self.assertIsNone(next(p['result'] for p in result['predicates'] if p['name'] == 'independent_oracle'))

    def test_oracle_phase_must_match_registered_request_body_lifecycle_phase(self):
        self.assertEqual(self.plan['candidate_expectation']['native_phase'], 1)
        self.assertEqual(self.oracle['phase'], 2)
        self.assertEqual(self.evaluate()['outcome'], 'PASS')
        for phase in (1, 3, 4, None):
            self.oracle['phase'] = phase
            with self.subTest(phase=phase):
                self.assertIsNone(self.evaluate()['outcome'])

    def test_registered_p2_requires_actual_native_request_body_return(self):
        self.assertEqual(set(R.ORACLE_LIFECYCLE_PHASE), set(R.SUPPORTED))
        self.assertEqual(set(R.ORACLE_LIFECYCLE_PHASE.values()), {2})
        original = copy.deepcopy(self.packet)
        for change in ({'function': 'native_process_request_headers'}, {'edge': 'enter'}, {'result': 0}):
            self.packet = copy.deepcopy(original)
            self.packet['observations']['native_phases']['value'][1].update(change)
            with self.subTest(change=change):
                result = self.evaluate()
                self.assertIsNone(result['outcome'])
                self.assertEqual(next(p['result'] for p in result['predicates']
                                      if p['name'] == 'registered_oracle_lifecycle_phase'), 'FAIL')

    def test_content_type_and_charset_ids_remain_unqualified_without_native_mapping_proof(self):
        for name in ('NEED-request-content-type-present', 'NEED-request-content-type-missing',
                     'NEED-request-charset-present', 'NEED-request-charset-missing'):
            self.assertNotIn(name, R.SUPPORTED)
            self.assertNotIn(name, R.ORACLE_LIFECYCLE_PHASE)
            plan = dict(self.plan, case_id=name)
            predicates = R.host_predicates(plan, self.packet)
            self.assertEqual(predicates[0]['name'], 'registered_case_semantics')
            self.assertIsNone(predicates[0]['result'])

    def test_nonempty_apr_eos_cannot_follow_native_finalization(self):
        original = copy.deepcopy(self.packet)
        for index, timestamp in ((0, 9999), (1, 10000)):
            self.packet = copy.deepcopy(original)
            self.packet['observations']['host_eos']['value']['actual_apr_eos_rows'][index]['monotonic_ns'] = timestamp
            with self.subTest(index=index):
                result = self.evaluate()
                self.assertIsNone(result['outcome'])
                self.assertEqual(next(p['result'] for p in result['predicates']
                                      if p['name'] == 'physical_apr_eos_native_p2_p4_terminal_finish_free_order'), 'FAIL')

    def test_empty_request_p2_precedes_first_empty_apr_eos(self):
        request = self.packet['observations']['host_eos']['value'][
            'actual_apr_eos_rows'][0]
        request.update(monotonic_ns=12, request_body_processed=1)
        self.assertTrue(R.check_lifecycle_order(
            {'case_id': 'NEED-request-empty'}, self.packet))
        request['request_body_processed'] = 0
        self.assertFalse(R.check_lifecycle_order(
            {'case_id': 'NEED-request-empty'}, self.packet))

    def test_empty_request_eos_must_strictly_follow_p2_return(self):
        request = self.packet['observations']['host_eos']['value'][
            'actual_apr_eos_rows'][0]
        request['request_body_processed'] = 1
        for timestamp in (9, 10, 11):
            request['monotonic_ns'] = timestamp
            with self.subTest(timestamp=timestamp):
                self.assertFalse(R.check_lifecycle_order(
                    {'case_id': 'NEED-request-empty'}, self.packet))

    def test_prefix_delivery_and_physical_socket_write_may_precede_p4(self):
        call = self.packet['observations']['commit_order']['value'][
            'physical_socket_observation']['actual_socket_call_brackets'][0]
        call.update(entered_ns=17, return_ns=18)
        self.assertEqual(self.evaluate()['outcome'], 'PASS')

    def test_terminal_release_must_follow_successful_p4(self):
        handoffs = self.packet['observations']['commit_order']['value'][
            'actual_output_handoffs']
        handoffs[-2]['monotonic_ns'] = 20
        self.assertFalse(R.check_commit(R.values(self.packet)))

    def test_finish_must_follow_late_terminal_release(self):
        handoffs = self.packet['observations']['commit_order']['value'][
            'actual_output_handoffs']
        handoffs[-2]['monotonic_ns'] = 54
        handoffs[-1]['monotonic_ns'] = 55
        self.assertTrue(R.check_commit(R.values(self.packet)))
        self.assertFalse(R.check_lifecycle_order(self.plan, self.packet))

    def test_socket_bracket_and_accounting_mutations_fail(self):
        original = copy.deepcopy(self.packet)
        mutations = (
            {'entered_ns': 41, 'return_ns': 40},
            {'result': 79},
            {'stream_accounted_here': False},
        )
        for changes in mutations:
            self.packet = copy.deepcopy(original)
            call = self.packet['observations']['commit_order']['value'][
                'physical_socket_observation']['actual_socket_call_brackets'][0]
            call.update(changes)
            with self.subTest(changes=changes):
                self.assertFalse(R.check_commit(R.values(self.packet)))
                self.assertIsNone(self.evaluate()['outcome'])

    def test_physical_native_call_sequence_finish_free_and_logging_failure_are_rejected(self):
        mutations = (
            ('request_enter_before_EOS', 'native_process_request_body', 'enter', {'monotonic_ns': 1}),
            ('response_enter_before_EOS', 'native_process_response_body', 'enter', {'monotonic_ns': 1}),
            ('finish_before_commit', 'common_finish', 'enter', {'monotonic_ns': 25}),
            ('cleanup_before_finish', 'native_cleanup', 'enter', {'monotonic_ns': 45}),
            ('logging_failed', 'native_process_logging', 'return', {'result': 0}),
            ('wrong_call', 'common_finish', 'return', {'call': 999}),
            ('reversed_sequence', 'common_cleanup', 'return', {'sequence': 1}),
        )
        for label, function, edge, changes in mutations:
            physical = copy.deepcopy(self.physical_api)
            next(row for row in physical if row['function'] == function and row['edge'] == edge).update(changes)
            ref = self.write('native-api.jsonl', '\n'.join(json.dumps(row) for row in physical))
            self.packet['observations']['native_api_returns']['evidence'] = [dict(ref, role='native_api')]
            with self.subTest(label=label):
                result = self.evaluate()
                self.assertIsNone(result['outcome'])
                self.assertNotEqual(next(p['result'] for p in result['predicates']
                                         if p['name'] == 'physical_apr_eos_native_p2_p4_terminal_finish_free_order'), 'PASS')

    def test_pre_host_same_pid_final_is_preserved_and_must_be_clean(self):
        self.packet['observations']['cleanup_receipts']['value'][
            'actual_same_pid_pre_host_observer_finals'] = [
                {'pending_calls': 1, 'live_mappings': 0, 'invalid': False,
                 'monotonic_ns': 1}]
        result = self.evaluate()
        self.assertIsNone(result['outcome'])
        self.assertEqual(next(p['result'] for p in result['predicates']
                              if p['name'] == 'process_descriptor_cleanup'), 'FAIL')

    def test_in_host_window_or_untimed_final_cannot_qualify(self):
        original = copy.deepcopy(self.packet)
        for value in (50, None, '50', True):
            self.packet = copy.deepcopy(original)
            self.packet['observations']['cleanup_receipts']['value'][
                'actual_same_pid_in_host_window_observer_finals'] = [
                    {'pending_calls': 0, 'live_mappings': 0,
                     'invalid': False, 'monotonic_ns': value}]
            with self.subTest(monotonic_ns=value):
                result = self.evaluate()
                self.assertIsNone(result['outcome'])
                self.assertEqual(next(p['result'] for p in result['predicates']
                                      if p['name'] == 'process_descriptor_cleanup'), 'FAIL')

    def test_unimplemented_scope_semantics_remain_unknown(self):
        self.oracle['scope'] = 'Also prove native multipart upload and streaming'
        result = self.evaluate()
        self.assertIsNone(result['outcome'])
        self.assertIsNone(next(p['result'] for p in result['predicates'] if p['name'] == 'independent_oracle'))
        self.oracle['scope'] = R.SUPPORTED_ORACLE_SCOPE
        self.assertEqual(self.evaluate()['outcome'], 'PASS')

    def test_config_and_pre_native_require_separate_control_path(self):
        self.plan['execution_kind'] = 'configtest'
        self.assertIsNone(self.evaluate()['outcome'])
        self.plan['execution_kind'] = 'host_http'
        self.packet['execution_kind'] = 'host_pre_native_rejection'
        self.assertIsNone(self.evaluate()['outcome'])

    def test_missing_candidate_keeps_original_identity_and_null(self):
        result = R.evaluate(self.row, self.plan, None, None, self.expected, None)
        self.assertEqual(result['run_scoped_case_id'], self.identity)
        self.assertIsNone(result['outcome'])

    def test_plan_expectation_is_not_permission_to_change_fixture(self):
        self.plan['request']['body'] = encoded(b'other')
        self.assertIsNone(self.evaluate()['outcome'])

    def test_followup_physical_failure_not_hidden_by_healthy_neighbor(self):
        self.write('followup/process.command.json', {'waited_exit': 1})
        self.assertIsNone(self.evaluate()['outcome'])

    def test_hash_mismatch_is_rejected(self):
        ref = self.write('bound.json', {'value': 1})
        self.write('bound.json', {'value': 2})
        with self.assertRaises(ValueError):
            R.read_ref(ref)

    def test_reference_inventory_defeats_in_memory_wrapper_bait(self):
        leaf = self.write('leaf.txt', 'leaf observation')
        middle = self.write('middle.json', {'historical_path_record': {
            'path': '/missing/historical-source.c', 'sha256': '4' * 64, 'bytes': 10}})
        wrapper = dict(self.write('wrapper.txt', 'container'), nested=[middle, leaf])
        actual = R.physical_inventory(wrapper)
        self.assertEqual({item['path'] for item in actual},
                         {leaf['path'], middle['path'], wrapper['path']})
        self.write('leaf.txt', 'changed')
        with self.assertRaises(ValueError):
            for ref in actual:
                R.O.verify_reference(ref)

    def test_reference_inventory_ignores_container_path_hash_observations(self):
        logical_observation = {
            'configured': True,
            'path': '/mnt/artifacts/apache-host-io.so',
            'sha256': '0' * 64,
            'marker_sha256': '1' * 64,
        }
        logical_runtime_file = {
            'path': '/var/tmp/codex/ModSecurity-conector/apache-batch-unit/001/events.jsonl',
            'sha256': '2' * 64,
            'bytes': 0,
        }
        leaf = self.write('physical.txt', 'physical observation')
        actual = R.physical_inventory({'logical': logical_observation,
                                       'physical_files': [logical_runtime_file],
                                       'physical': leaf})
        self.assertEqual(actual, [leaf])

    def test_reference_inventory_rejects_malformed_runtime_file_records(self):
        hidden = dict(self.write('hidden.txt', 'must not be hidden'), nested={})
        with self.assertRaisesRegex(ValueError, 'Malformed typed runtime physical_files'):
            R.physical_inventory({'physical_files': [hidden]})

    def test_reference_inventory_treats_referenced_json_as_immutable_leaf(self):
        stale = {'path': '/missing/historical-source.c', 'sha256': '3' * 64, 'bytes': 10}
        plan = self.write('executed-plan.json', {'unrelated_unsupported_case_source': stale})
        leaf = self.write('runtime-evidence.txt', 'runtime evidence')
        actual = R.physical_inventory({'batch_plan_reference': plan, 'physical': leaf})
        self.assertEqual({item['path'] for item in actual}, {plan['path'], leaf['path']})

    def catalog(self):
        rows = []
        for i in range(1484):
            leg = 'apache-native' if i < 155 else 'other-profile'
            identity = 'I12::' + leg + '::case-' + str(i)
            contract = {'case_id': 'case-' + str(i), 'run_scoped_case_id': identity,
                        'expected_oracle': self.oracle}
            rows.append({'run_scoped_case_id': identity, 'leg_id': leg,
                         'required_leg': True, 'selected_requirement': contract})
        ids = [row['run_scoped_case_id'] for row in rows]
        digest_patch = patch.multiple(R.O, ID_SHA256=R.digest(('\n'.join(ids) + '\n').encode()),
                                      CONTRACT_SHA256=R.O.canonical_digest([row['selected_requirement'] for row in rows]))
        digest_patch.start()
        self.addCleanup(digest_patch.stop)
        plan = {'rows': [{'original_id': row['run_scoped_case_id'],
                          'case_id': row['selected_requirement']['case_id'],
                          'execution_kind': 'host_http',
                          'original_contract': row['selected_requirement'],
                          'original_oracle': self.oracle} for row in rows[:155]]}
        index = {'unsigned': True, 'cases': [{'run_scoped_case_id': row['run_scoped_case_id'],
                                             'reference': None} for row in rows[:155]]}
        return {'rows': rows}, plan, index

    def test_all155_missing_candidates_preserve_full_immutable_catalog(self):
        baseline, plan, index = self.catalog()
        selected = R.validate_inputs(baseline, plan, index)
        self.assertEqual(len(selected), 155)
        self.assertTrue(all(item['reference'] is None for item in index['cases']))
        decisions, pending = R.evaluate_batch(selected, {'plan': plan, 'unsigned-index': index,
                                                        'identity': self.expected},
                                              [None] * 155, {}, {}, True)
        self.assertEqual(len(decisions), 155)
        self.assertEqual(pending, [])
        self.assertTrue(all(item['outcome'] is None for item in decisions))

    def test_explicit_approval_switch_is_required_for_complete_positive_case(self):
        ref = self.write('candidate.json', self.packet)
        data = {'plan': {'rows': [self.plan]}, 'identity': self.expected,
                'unsigned-index': {'cases': [{'reference': ref}]}}
        decisions, pending = R.evaluate_batch([self.row], data, [self.packet],
                                               {self.identity: copy.deepcopy(self.packet)}, {}, False)
        self.assertIsNone(decisions[0]['outcome'])
        self.assertEqual(pending, [])
        self.assertEqual(decisions[0]['predicates'][-1]['name'], 'explicit_root_review_invocation')

    def test_catalog_cannot_drop_reorder_or_change_original_contract(self):
        baseline, plan, index = self.catalog()
        mutations = (
            lambda p, i: i['cases'].pop(),
            lambda p, i: i['cases'].reverse(),
            lambda p, i: p['rows'][0].update(case_id='NEED-request-single-chunk'),
            lambda p, i: p['rows'][0].update(original_contract={'expected_oracle': {'visible_status': 200}}),
            lambda p, i: p['rows'][0].update(original_oracle={'visible_status': 200}),
        )
        for mutate in mutations:
            changed_plan, changed_index = copy.deepcopy(plan), copy.deepcopy(index)
            mutate(changed_plan, changed_index)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                R.validate_inputs(baseline, changed_plan, changed_index)

    def test_original_baseline_oracle_mutation_is_rejected(self):
        baseline, plan, index = self.catalog()
        baseline['rows'][0]['selected_requirement']['case_id'] = 'changed'
        with self.assertRaises(ValueError):
            R.validate_inputs(baseline, plan, index)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == '__main__':
    unittest.main()
