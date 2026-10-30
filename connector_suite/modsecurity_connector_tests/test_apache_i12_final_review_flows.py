"""full synthetic Apache final-review joins, with no runtime claim."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = connector_root()
SOURCE = source_path('reports/audits/apache-i12-20261020/final_review.py', root=ROOT)
R = load_source(SOURCE)


def encoded(data):
    return {'encoding': 'base64', 'data': base64.b64encode(data).decode(),
            'bytes': len(data), 'sha256': R.digest(data)}


class FinalFlowTests(unittest.TestCase):
    def setUp(self):
        from modsecurity_connector_ci.lib.active_test_inventory import validate_output_root
        root = validate_output_root(ROOT, Path(os.environ['RUNNER_TEMP']))
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
        run_identity = {key: self.expected[key]
                        for key in ('run_id', 'parent_sha', 'framework_sha', 'mrts_sha')}
        self.packet = dict(run_identity, run_scoped_case_id=self.identity, leg_id='apache-native',
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

    def batch(self, approve=True, reextracted=None):
        reference = self.write('candidate.json', self.packet)
        data = {'plan': {'rows': [self.plan]},
                'unsigned-index': {'cases': [{'reference': reference}]}, 'identity': self.expected}
        extracted = {self.identity: copy.deepcopy(self.packet) if reextracted is None else reextracted}
        return R.evaluate_batch([self.row], data, [self.packet], extracted, {}, approve)

    def assert_unqualified(self, decisions, pending):
        self.assertEqual(pending, [])
        self.assertIsNone(decisions[0]['outcome'])
        self.assertFalse(decisions[0]['full_lifecycle_qualified'])
        self.assertEqual(decisions[0]['run_scoped_case_id'], self.identity)

    def test_synthetic_complete_batch_produces_bound_pending_decision_only(self):
        decisions, pending = self.batch()
        self.assertEqual(len(pending), 1)
        packet, decision, row, oracle = pending[0]
        self.assertEqual(packet, self.packet)
        self.assertEqual(row, self.row)
        self.assertEqual(oracle, self.oracle)
        self.assertEqual(decision['outcome'], 'PASS', decision['predicates'])
        self.assertTrue(all(item['result'] == 'PASS' for item in decisions[0]['predicates']))
        self.assertIsNone(self.packet['outcome'])
        self.assertFalse((self.root / 'approved').exists())

    def test_absent_explicit_approval_removes_qualification(self):
        decisions, pending = self.batch(approve=False)
        self.assert_unqualified(decisions, pending)
        self.assertEqual(decisions[0]['predicates'][-1]['name'], 'explicit_root_review_invocation')

    def test_unresolved_original_oracle_remains_unknown(self):
        self.oracle['unresolved_expected_value_reason'] = 'independent review absent'
        decisions, pending = self.batch()
        self.assert_unqualified(decisions, pending)
        self.assertIsNone(decisions[0]['oracle_decision'])
        self.assertIsNone(decisions[0]['predicates'][-1]['result'])

    def test_reextracted_packet_mismatch_prevents_pending_decision(self):
        changed = copy.deepcopy(self.packet)
        changed['driver_execution']['executed_case_contract'] = False
        decisions, pending = self.batch(reextracted=changed)
        self.assert_unqualified(decisions, pending)
        self.assertEqual(decisions[0]['predicates'][0]['result'], 'FAIL')

    def test_foreign_sdk_identity_prevents_pending_decision(self):
        images = self.packet['observations']['product_host_identity']['value']['mapped_images']
        sdk = next(image for image in images if 'libmodsecurity.so' in image['mapped_path'])
        sdk['sha256'] = 'foreign-sdk'
        decisions, pending = self.batch()
        self.assert_unqualified(decisions, pending)
        rejected = next(item for item in decisions[0]['predicates'] if item['name'] == 'exact_product_run_identity')
        self.assertEqual(rejected['result'], 'FAIL')

    def test_descriptor_leak_prevents_pending_decision(self):
        self.packet['observations']['descriptor_cleanup']['value']['actual_fd_differences']['main']['added']['8'] = 'socket:[888]'
        decisions, pending = self.batch()
        self.assert_unqualified(decisions, pending)
        rejected = next(item for item in decisions[0]['predicates'] if item['name'] == 'process_descriptor_cleanup')
        self.assertEqual(rejected['result'], 'FAIL')

    def test_deleted_physical_response_cannot_be_replaced_by_packet_values(self):
        (self.root / 'response.raw').unlink()
        decisions, pending = self.batch()
        self.assert_unqualified(decisions, pending)
        rejected = next(item for item in decisions[0]['predicates'] if item['name'] == 'all35_physical_roles')
        self.assertEqual(rejected['result'], 'FAIL')

    def test_existing_publication_is_preserved_and_validation_temporary_removed(self):
        decision = self.evaluate()
        self.assertEqual(decision['outcome'], 'PASS', decision['predicates'])
        output = self.root / 'approved'
        output.mkdir()
        existing = output / (self.name + '.reviewed.json')
        existing.write_text('retained prior artifact')
        with self.assertRaisesRegex(ValueError, 'Output already exists'):
            R.publish_packet(output, self.packet, decision, self.row, self.oracle)
        self.assertEqual(existing.read_text(), 'retained prior artifact')
        self.assertFalse((output / (self.name + '.validation.json')).exists())


if os.environ.get('ON_DEMAND_TESTS') != '1':
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == '__main__':
    unittest.main()
