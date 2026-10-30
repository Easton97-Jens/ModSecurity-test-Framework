"""Physical-producer-shaped negative controls; these fixtures are not host evidence."""
from __future__ import annotations
import copy
import json
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from tests import test_i12_lifecycle_ledger as existing
LEDGER = existing.LEDGER

class TraefikPreallocationTests(unittest.TestCase):

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='i12-preallocation-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.case = 'I12::traefik-native-uds::invalid_content_length'
        self.oracle = {'native_result': 'rejected_by_host_before_connector', 'visible_status': 400, 'phase': None, 'rule_id': None, 'physical_evidence_not_projection': True}
        self.row = {'run_scoped_case_id': self.case, 'leg_id': 'traefik-native-uds', 'required_leg': True, 'status': 'NOT_EXECUTED_UNQUALIFIED', 'execution_observed': None, 'selected_requirement': {'case_id': 'invalid_content_length', 'execution_kind': 'host_case_or_missing_fixture', 'expected_oracle': copy.deepcopy(self.oracle)}}
        self.packet = {'reviewed_by': 'root', 'run_scoped_case_id': self.case, 'leg_id': self.row['leg_id'], 'run_id': 'synthetic-run', 'parent_sha': 'synthetic-parent', 'execution_kind': 'host_preallocation_control', 'execution_observed': True, 'full_lifecycle_qualified': False, 'oracle_evaluated': True, 'oracle_sha256': LEDGER.ORACLES.canonical_digest(self.oracle), 'outcome': 'PASS'}
        self.expected = {'reviewed_by': 'root', 'run_scoped_case_id': self.case, 'original_contract_sha256': LEDGER.ORACLES.canonical_digest(self.row['selected_requirement']), 'oracle_sha256': self.packet['oracle_sha256'], 'native_allocation_count': 0, 'failure_class': 'http_parser', 'first_cause': 'host_http_parser_rejection'}
        self.packet['preallocation_contract'] = self.write('expectation', self.expected, 'expectation_source')
        self.packet['preallocation_contract'].update(kind='official_host_contract', revision='synthetic-contract-1')
        self.records = []
        for time, function, edge, result, call in ((100, 'observer', 'admitted', None, 0), (200, 'native_new', 'enter', None, 2), (300, 'native_new', 'return', 1, 2), (400, 'native_cleanup', 'enter', None, 4), (700, 'native_new', 'enter', None, 5), (800, 'native_new', 'return', 1, 5), (900, 'native_cleanup', 'enter', None, 7), (1000, 'observer', 'final', None, 0)):
            self.records.append({'schema': 'native-lifecycle-v1', 'pid': 11, 'uid': 65534, 'sequence': len(self.records) + 1, 'monotonic_ns': time, 'call': call, 'run': self.packet['run_id'], 'profile': self.row['leg_id'], 'function': function, 'edge': edge, 'result': result, 'invalid': False})
        self.bind_observer()
        self.backend = [{'operation': 'headers-arrived', 'key': 'before', 'monotonic_ns': 250}, {'operation': 'headers-arrived', 'key': 'after', 'monotonic_ns': 750}]
        self.bind_backend()
        image = {'run_id': self.packet['run_id'], 'parent_sha': self.packet['parent_sha'], 'pid': 11, 'uid': 65534, 'host_binary_sha256': 'a' * 64, 'module_sha256': 'b' * 64, 'observer_sha256': 'c' * 64}
        self.bindings = {name: self.selector(name, image, 'loaded_image') for name in ('target_identity', 'before_identity', 'after_identity')}
        self.bindings.update({'target_window': self.selector('target-window', {'key': 'target', 'started_ns': 450, 'completed_ns': 650}, 'client_process'), 'before_control': self.selector('before-window', {'key': 'before', 'started_ns': 150, 'completed_ns': 425, 'status': 200}, 'client_process'), 'after_control': self.selector('after-window', {'key': 'after', 'started_ns': 675, 'completed_ns': 950, 'status': 200}, 'client_process'), 'cleanup': self.selector('cleanup', {'run_id': self.packet['run_id'], 'descriptors_remaining': 0, 'sockets_remaining': 0, 'processes_remaining': 0, 'cleanup_calls': 1}, 'cleanup_observer')})
        self.packet['preallocation_measurements'] = self.bindings
        self.packet['client_request'] = self.write('request.raw', b'POST / HTTP/1.1\r\nHost: test\r\nX-I12-Acceptance-Key: target\r\nContent-Length: bad\r\n\r\n', 'client_process')
        self.packet['client_response'] = self.write('response.raw', b'HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n', 'client_process')
        self.packet['observations'] = {}
        for field, roles in LEDGER.ROLES.items():
            if field in LEDGER.PREALLOCATION_NULL_FIELDS:
                self.packet['observations'][field] = {'value': None, 'reason': 'No native transaction was allocated.'}
            else:
                required = LEDGER.REQUIRED_ROLES.get(field, roles)
                evidence = [self.write(field + '-' + role, {'synthetic_producer': role}, role) for role in sorted(required)]
                self.packet['observations'][field] = {'value': 1, 'evidence': evidence}
        self.packet['observations']['backend_request_count']['value'] = 0
        self.packet['observations']['native_api_returns'] = {'value': [], 'evidence': [self.packet['observer_log']]}
        self.packet['observations']['client_sha256']['value'] = hashlib.sha256(b'').hexdigest()
        self.packet['observations']['client_bytes']['value'] = 0
        config = self.write('actual-effective-config', b'synthetic effective config', 'effective_configuration')
        source = self.write('actual-source-manifest', {'parent_sha': self.packet['parent_sha']}, 'source_manifest')
        self.packet['effective_config_sha256'] = config['sha256']
        self.packet['observations']['source_config_binding'] = {
            'value': {'parent_sha': self.packet['parent_sha'], 'effective_config_sha256': config['sha256']},
            'evidence': [source, config]}

    def write(self, name, value, role):
        path = self.root / name
        path.write_bytes(value if isinstance(value, bytes) else json.dumps(value).encode())
        return {**LEDGER.ORACLES.reference(path), 'role': role}

    def selector(self, name, value, role):
        return {'reference': self.write(name, value, role), 'pointer': ''}

    def bind_observer(self):
        raw = ('\n'.join((json.dumps(row) for row in self.records)) + '\n').encode()
        self.packet['observer_log'] = self.write('native-lifecycle.jsonl', raw, 'native_api')
        if 'observations' in self.packet:
            returns = [{'function': row['function'], 'call': row['call'], 'result': row['result']}
                for row in self.records if 450 <= row['monotonic_ns'] <= 650 and row.get('edge') == 'return'
                and row['function'].startswith(('native_', 'runtime_'))]
            self.packet['observations']['native_api_returns'] = {'value': returns, 'evidence': [self.packet['observer_log']]}

    def bind_backend(self):
        raw = ('\n'.join((json.dumps(row) for row in self.backend)) + '\n').encode()
        self.packet['backend_log'] = self.write('backend.jsonl', raw, 'backend_process')

    def rebind_expected(self):
        self.expected.update(run_scoped_case_id=self.packet['run_scoped_case_id'], original_contract_sha256=LEDGER.ORACLES.canonical_digest(self.row['selected_requirement']), oracle_sha256=LEDGER.ORACLES.canonical_digest(self.oracle))
        self.packet['oracle_sha256'] = self.expected['oracle_sha256']
        old = self.packet['preallocation_contract']
        self.packet['preallocation_contract'] = {**self.write('expectation', self.expected, 'expectation_source'), 'kind': old['kind'], 'revision': old['revision']}

    def review(self):
        ref = self.write('packet.json', self.packet, 'reviewed_packet')
        return LEDGER.reviewed_preallocation_packet(ref, self.row, self.oracle)

    def test_exact_parser_control_preserves_nulls_without_claiming_lifecycle(self):
        result = self.review()
        self.assertEqual(result['qualification_scope'], 'preallocation_control')
        self.assertFalse(result['full_lifecycle_qualified'])
        self.assertTrue(result['full_case_qualified'])
        self.assertEqual(result['preallocation_measurements']['native_allocations'], 0)
        self.assertIsNone(result['observations']['native_transaction_id']['value'])
        self.assertIsNone(result['observations']['native_free_calls']['value'])
        self.assertEqual(set(result['observations']), set(LEDGER.ROLES))

    def test_unrelated_id_and_lifecycle_claim_cannot_enter_scope(self):
        self.row['run_scoped_case_id'] = 'I12::traefik-native-uds::allow_without_marker'
        with self.assertRaisesRegex(ValueError, 'Original ID'):
            self.review()
        self.row['run_scoped_case_id'] = self.case
        self.packet['full_lifecycle_qualified'] = True
        with self.assertRaisesRegex(ValueError, 'cannot claim'):
            self.review()

    def test_original_digest_or_independent_source_tamper_fails(self):
        self.expected['original_contract_sha256'] = 'wrong'
        old = self.packet['preallocation_contract']
        self.packet['preallocation_contract'] = {**self.write('expectation', self.expected, 'expectation_source'), 'kind': old['kind'], 'revision': old['revision']}
        with self.assertRaisesRegex(ValueError, 'exact original'):
            self.review()

    def test_missing_zero_observer_is_not_an_absence_proof(self):
        self.records = []
        self.bind_observer()
        with self.assertRaisesRegex(ValueError, 'empty observer'):
            self.review()

    def test_missing_sequence_activation_or_final_fails(self):
        initial = copy.deepcopy(self.records)
        for mutate in (lambda rows: rows.pop(0), lambda rows: rows.pop(), lambda rows: rows[2].update(sequence=88), lambda rows: rows[1].update(invalid=True)):
            with self.subTest(mutate=mutate):
                self.records = copy.deepcopy(initial)
                mutate(self.records)
                self.bind_observer()
                with self.assertRaises(ValueError):
                    self.review()

    def test_native_allocation_in_target_is_not_preallocation(self):
        self.records[4:4] = [dict(self.records[1], monotonic_ns=500), dict(self.records[2], monotonic_ns=600)]
        for i, row in enumerate(self.records, 1):
            row['sequence'] = i
        self.bind_observer()
        with self.assertRaisesRegex(ValueError, 'native allocation'):
            self.review()

    def test_before_and_after_native_controls_are_required(self):
        self.records[2]['result'] = 0
        self.bind_observer()
        with self.assertRaisesRegex(ValueError, 'Healthy controls'):
            self.review()

    def test_backend_header_arrival_before_body_is_not_hidden_by_zero_projection(self):
        self.backend.append({'operation': 'headers-arrived', 'key': 'target', 'monotonic_ns': 500})
        self.bind_backend()
        with self.assertRaisesRegex(ValueError, 'before body'):
            self.review()

    def test_wrong_raw_request_cannot_qualify_parser_case(self):
        self.packet['client_request'] = self.write('request.raw', b'GET / HTTP/1.1\r\nHost: test\r\nX-I12-Acceptance-Key: target\r\n\r\n', 'client_process')
        with self.assertRaisesRegex(ValueError, 'exact original parser'):
            self.review()

    def test_wrong_raw_response_or_changed_digest_fails(self):
        self.packet['observations']['client_sha256']['value'] = 'wrong'
        with self.assertRaisesRegex(ValueError, 'byte count/digest'):
            self.review()

    def test_invented_native_id_and_missing_original_field_fail(self):
        self.packet['observations']['native_transaction_id']['value'] = 'invented'
        with self.assertRaisesRegex(ValueError, 'explicitly null'):
            self.review()
        self.packet['observations'].pop('native_transaction_id')
        with self.assertRaisesRegex(ValueError, '35 original'):
            self.review()

    def test_unfinished_resources_or_multiple_cleanup_fails(self):
        self.bindings['cleanup'] = self.selector('cleanup', {'run_id': self.packet['run_id'], 'descriptors_remaining': 1, 'sockets_remaining': 0, 'processes_remaining': 0, 'cleanup_calls': 1}, 'cleanup_observer')
        with self.assertRaisesRegex(ValueError, 'FD/socket/process'):
            self.review()

    def test_source_copy_null_input_setup_is_not_native_allocation(self):
        case = 'body_size_nonzero_with_null_data'
        self.packet['run_scoped_case_id'] = 'I12::traefik-native-uds::' + case
        self.row['run_scoped_case_id'] = self.packet['run_scoped_case_id']
        self.row['selected_requirement']['case_id'] = case
        self.oracle.update(native_result='mapping_error', visible_status=500)
        self.expected.update(failure_class='mapping_or_begin', operation='native-request-body-null', errno=None, errno_scope='not_an_os_operation', failure_result=0, first_cause='null_body_data')
        self.rebind_expected()
        self.packet['client_response'] = self.write('response.raw', b'HTTP/1.1 500 Internal Error\r\nContent-Length: 0\r\n\r\n', 'client_process')
        self.packet['observations']['client_sha256']['value'] = hashlib.sha256(b'').hexdigest()
        self.packet['client_request'] = self.write('request.raw', b'POST / HTTP/1.1\r\nHost: test\r\nX-I12-Acceptance-Key: target\r\nContent-Length: 0\r\n\r\n', 'client_process')
        self.bindings['fault'] = self.selector('fault', {'operation': 'native-request-body-null', 'input_size': 1, 'body_data_null': True, 'pid': 11, 'monotonic_ns': 550, 'result': 0}, 'host_callback')
        self.records[4:4] = [dict(self.records[1], function='runtime_begin', monotonic_ns=500), dict(self.records[2], function='runtime_begin', monotonic_ns=600, result=0)]
        for i, row in enumerate(self.records, 1):
            row['sequence'] = i
        self.bind_observer()
        result = self.review()
        self.assertEqual(result['preallocation_measurements']['native_constructor_attempts'], 0)
        self.assertEqual(result['preallocation_measurements']['native_runtime_begin_returns'], [0])
        self.assertEqual(result['preallocation_measurements']['native_allocations'], 0)
        self.bindings['fault'] = self.selector('fault', {'operation': 'unrelated_loader', 'errno': 2, 'first_cause': 'module_missing', 'pid': 11, 'monotonic_ns': 550, 'result': -1}, 'host_callback')
        with self.assertRaisesRegex(ValueError, 'actual failing operation'):
            self.review()

    def test_all_eight_original_parser_ids_and_raw_shapes(self):
        samples = {'invalid_content_length': b'Content-Length: bad', 'conflicting_content_length': b'Content-Length: 1\r\nContent-Length: 2', 'duplicate_transfer_encoding': b'Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked', 'content_length_overflow': b'Content-Length: 9223372036854775808'}
        for route in sorted(LEDGER.TRAEFIK_REQUEST_ROUTES):
            for case, header in samples.items():
                with self.subTest(route=route, case=case):
                    self.row.update(leg_id=route, run_scoped_case_id='I12::' + route + '::' + case)
                    self.row['selected_requirement']['case_id'] = case
                    self.packet.update(leg_id=route, run_scoped_case_id=self.row['run_scoped_case_id'])
                    for record in self.records:
                        record['profile'] = route
                    self.bind_observer()
                    self.rebind_expected()
                    self.packet['client_request'] = self.write('request.raw', b'POST / HTTP/1.1\r\nHost: test\r\nX-I12-Acceptance-Key: target\r\n' + header + b'\r\n\r\n', 'client_process')
                    self.assertEqual(self.review()['outcome'], 'PASS')

    def test_service_constructor_failure_uses_separate_same_image_controls(self):
        case = 'NEED-physical-event-sink-open'
        self.row['run_scoped_case_id'] = 'I12::traefik-native-uds::' + case
        self.packet['run_scoped_case_id'] = self.row['run_scoped_case_id']
        self.row['selected_requirement']['case_id'] = case
        self.oracle.update(native_result='service_initialization_failure', visible_status=503)
        self.expected.update(failure_class='service_startup', operation='openat', errno=13, failure_result=-1, process_exit=1, diagnostic_contains='event sink open denied', first_cause='event_sink_open_failure')
        self.rebind_expected()
        self.packet['client_request'] = self.write('request.raw', b'POST / HTTP/1.1\r\nHost: test\r\nX-I12-Acceptance-Key: target\r\nContent-Length: 0\r\n\r\n', 'client_process')
        self.packet['client_response'] = self.write('response.raw', b'HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n', 'client_process')
        identity_ref = self.bindings['target_identity']['reference']
        identity = json.loads(Path(identity_ref['path']).read_text())
        identity['pid'] = 22
        self.bindings['target_identity'] = self.selector('target_identity', identity, 'loaded_image')
        self.records.extend([dict(self.records[0], pid=22, monotonic_ns=450), dict(self.records[-1], pid=22, sequence=2, monotonic_ns=650)])
        self.bind_observer()
        self.bindings['fault'] = self.selector('fault', {'operation': 'openat', 'errno': 13, 'result': -1, 'pid': 22, 'monotonic_ns': 550}, 'host_callback')
        self.bindings['startup_process'] = self.selector('startup-process', {'actual_pid': 22, 'exit_code': 1, 'signal': None}, 'host_callback')
        self.bindings['startup_diagnostic'] = self.selector('startup-diagnostic', 'event sink open denied', 'host_callback')
        result = self.review()
        self.assertEqual(result['preallocation_measurements']['target_window']['pid'], 22)
        self.assertEqual([r['pid'] for r in result['preallocation_measurements']['controls']], [11, 11])
        self.bindings['startup_diagnostic'] = self.selector('startup-diagnostic', 'unrelated module loader failure', 'host_callback')
        with self.assertRaisesRegex(ValueError, 'actual diagnostic'):
            self.review()

    def test_exact_JSONL_selector_and_resource_tamper(self):
        ref = self.write('existing.jsonl', b'{"observed":1}\n{"observed":2}\n', 'host_callback')
        selector = {'reference': ref, 'line': 1, 'pointer': '/observed'}
        self.assertEqual(LEDGER.bound_json(selector, self.root / 'packet.json', {'host_callback'}), 2)
        selector['line'] = 2
        with self.assertRaisesRegex(ValueError, 'JSONL line'):
            LEDGER.bound_json(selector, self.root / 'packet.json', {'host_callback'})

    def test_ledger_keeps_preallocation_out_of_full_lifecycle_counts(self):
        ref = self.write('packet.json', self.packet, 'reviewed_packet')
        reconciliation = {'original_selected_contracts': [self.row['selected_requirement']],
            'oracle_matrix': [{'run_scoped_case_id': self.case, 'effective_oracle': self.oracle}],
            'supplemental_dispositions': [], 'summary': {}}
        with mock.patch.object(LEDGER.ORACLES, 'original_contracts', return_value=[self.row]):
            result = LEDGER.build_ledger({}, {}, reconciliation, [ref])
        self.assertEqual(result['summary']['current_preallocation_pass'], 1)
        self.assertEqual(result['summary']['full_lifecycle_pass'], 0)
        self.assertEqual(result['summary']['required_qualified_pass'], 1)
        self.assertIsNone(result['rows'][0]['current_lifecycle_packet'])
        self.assertTrue(result['rows'][0]['qualified_preallocation_pass'])

    def test_double_response_or_truncated_framing_cannot_pass(self):
        self.packet['client_response'] = self.write('response.raw', b'HTTP/1.1 400 Bad Request\r\n\r\nHTTP/1.1 200 OK\r\n\r\n', 'client_process')
        with self.assertRaisesRegex(ValueError, 'Raw client response'):
            self.review()


    def test_invalid_duplicate_overflowing_or_truncated_response_content_length_fails(self):
        for header in (b'Content-Length: bad', b'Content-Length: -1', b'Content-Length: 0\r\nContent-Length: 0',
                       b'Content-Length: 9223372036854775808', b'Content-Length: 1'):
            with self.subTest(header=header):
                self.packet['client_response'] = self.write('response.raw', b'HTTP/1.1 400 Bad Request\r\n'+header+b'\r\n\r\n', 'client_process')
                with self.assertRaisesRegex(ValueError, 'Content-Length|body framing'):
                    self.review()


class ConfigurationFirstCauseTests(unittest.TestCase):
    setUp = existing.ConfigurationLedgerTests.setUp
    review = existing.ConfigurationLedgerTests.review
    process = existing.ConfigurationLedgerTests.process
    rebind_process = existing.ConfigurationLedgerTests.rebind_process
    bind_rejection_expectation = existing.ConfigurationLedgerTests.bind_rejection_expectation

    def rejected(self):
        self.oracle.update(native_result='config_rejected', visible_status=1)
        self.packet['oracle_sha256'] = LEDGER.ORACLES.canonical_digest(self.oracle)
        self.process()['waited_exit'] = 1
        self.bind_rejection_expectation()

    def test_same_exit_with_unrelated_loader_first_cause_does_not_pass(self):
        self.rejected()
        self.process()['first_cause'] = 'module_loader_failure'
        self.rebind_process()
        with self.assertRaisesRegex(ValueError, 'first cause'):
            self.review()
        self.packet['outcome'] = 'FAIL'
        self.assertEqual(self.review()['outcome'], 'FAIL')

    def test_missing_diagnostic_expectation_does_not_pass_exit_one(self):
        self.rejected()
        ref = next((item for item in self.packet['measurement_evidence'] if item['role'] == 'expectation_source'))
        Path(ref['path']).write_text(json.dumps({'reviewed_by': 'root'}))
        ref.update(LEDGER.ORACLES.reference(Path(ref['path'])))
        with self.assertRaisesRegex(ValueError, 'source-bound diagnostic'):
            self.review()

# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == '__main__':
    unittest.main()
