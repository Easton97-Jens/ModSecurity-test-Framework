"""synthetic physical Apache review flows; no native execution evidence."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = connector_root()


def load(name, relative):
    module = load_source(ROOT / relative)
    return module


REVIEW = load('apache_offline_review_flow', 'ci/runtime/lifecycle/apache-i12/review.py')
BATCH = load('apache_offline_batch_flow', 'ci/runtime/lifecycle/apache-i12/acceptance/review_batch.py')


class PhysicalFixture:
    def setUp(self):
        from modsecurity_connector_ci.lib.active_test_inventory import validate_output_root
        storage = validate_output_root(ROOT, Path(os.environ['RUNNER_TEMP']))
        temporary = tempfile.TemporaryDirectory(prefix='apache-review-flow-', dir=storage)
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        environment = mock.patch.dict(os.environ, {'CODEX_TEMP_ROOT': str(self.base)})
        environment.start()
        self.addCleanup(environment.stop)
        self.attempt = self.base / 'attempt'
        self.data = self.attempt / 'data'
        self.case = 'synthetic-allow'
        self.identity = 'I12::apache-native::' + self.case
        self.contract = {'original_selected_requirement': {'case_id': self.case}}
        self.client = {'method': 'GET', 'path': '/synthetic', 'started_ns': 100,
                       'completed_ns': 200, 'headers': [['X-Synthetic', 'yes']],
                       'request_bytes': 3, 'entity_bytes': 2, 'request_sha256': 'request',
                       'entity_sha256': 'entity', 'tcp_eof_observed': True,
                       'tcp_reset_observed': False, 'timeout_observed': False, 'error': None,
                       'status': 200}
        self.write('fixtures/fixture-contract.json', self.contract)
        self.settings = {'case_id': self.case, 'selected_uri': '/synthetic',
                         'original_selected_id': self.identity}
        self.write('fixtures/settings.json', self.settings)
        binding = {'target': '/mnt/fixtures', 'source': str(self.base / 'fixtures'),
                   'ledger': str(self.base / 'fixture-ledger.json')}
        binding['ledger_sha256'] = self.write('fixture-ledger.json', {'synthetic': True})['sha256']
        self.spec = {'bindings': [binding]}
        self.spec_path = Path(self.write('spec.json', self.spec)['path'])
        self.controller = {'spec_sha256': REVIEW.ORACLES.reference(self.spec_path)['sha256'],
                           'supervisor_reaped': True, 'surviving_namespace_pids': [],
                           'outside_mount_leaks': [], 'errors': [], 'exitcode': 0, 'controller_exitcode': 0}
        self.write('attempt/controller-result.json', self.controller)
        self.write('attempt/admission.original.json', {'synthetic': True})
        self.command = {'environment_overrides': {'MSCONNECTOR_LIFECYCLE_CASE': self.case,
                                                'MSCONNECTOR_LIFECYCLE_RUN': 'synthetic-run'},
                        'sampler_thread_stopped': True, 'native_process_sampler_errors': [],
                        'native_process_snapshots': [
                            {'native_child_pid': 44, 'monotonic_ns': 90, 'starttime': 1, 'files_label': 'before'},
                            {'native_child_pid': 44, 'monotonic_ns': 210, 'starttime': 1, 'files_label': 'after'}]}
        self.write('attempt/data/apache-lifecycle-command.json', self.command)
        self.write('attempt/data/client/main.receipt.json', self.client)
        self.write('attempt/data/client/main.actual-process.json', {'actual_waited_exit_code': 0, 'actual_signal': None})
        self.host = [{'kind': 'host_context_associated', 'request_uri': '/synthetic',
                      'request_method': 'GET', 'monotonic_ns': 110, 'pid': 44,
                      'allocation_scope_call': 7, 'uid': 65534, 'gid': 65534}]
        self.api = [dict(pid=44, allocation_scope_call=7, allocation_scope_kind='host',
                         edge='return', function=function, call=index, monotonic_ns=120 + index,
                         result=1, invalid=False, allocation_join_verified=True,
                         transaction_id='native-id' if function == 'native_new' else 'common-id')
                    for index, function in enumerate(('host_allocation', 'native_new', 'common_init',
                        'native_process_request_body', 'native_process_response_body', 'common_finish',
                        'native_process_logging', 'native_cleanup', 'common_cleanup', 'host_association_retire'))]
        self.api.append({'pid': 44, 'edge': 'final', 'monotonic_ns': 220,
                         'invalid': False, 'pending_calls': 0, 'live_mappings': 0})
        self.write_rows('attempt/data/apache-host-eos.jsonl', self.host)
        self.write_rows('attempt/data/apache-native-api.jsonl', self.api)
        self.write_rows('attempt/data/apache-backend.jsonl', [{'path': '/synthetic', 'monotonic_ns': 150,
            'method': 'GET', 'body_sha256': 'request', 'response_source_body_sha256': 'entity'}])
        self.write('attempt/data/apache-lifecycle/runtime/conf/httpd.conf', '# synthetic Apache config')
        self.write('attempt/data/apache-lifecycle/runtime/conf/modsecurity-smoke.conf', '# synthetic rules')
        self.write('attempt/data/apache-lifecycle/logs/audit.log', '[unique_id "native-id"] synthetic audit')
        self.write_rows('attempt/data/apache-lifecycle/logs/phase4.log', [
            {'transaction_id': 'common-id', 'message_id': 'MSCONN_EVENT_RULE_MATCHED'}])
        self.write('attempt/data/native-process/before.fds.json', {'3': '/synthetic/log'})
        self.write('attempt/data/native-process/after.fds.json', {'3': '/synthetic/log'})

    def write(self, name, value):
        path = self.base / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value if isinstance(value, str) else json.dumps(value))
        return REVIEW.ORACLES.reference(path)

    def write_rows(self, name, rows):
        return self.write(name, '\n'.join(json.dumps(row) for row in rows))

    def extract(self):
        return REVIEW.extract(self.attempt, self.spec_path, self.case)

    def assert_unsigned(self, packet):
        self.assertIsNone(packet['outcome'])
        self.assertIsNone(packet['reviewed_by'])
        self.assertFalse(packet['oracle_evaluated'])
        self.assertFalse(packet['full_lifecycle_qualified'])
        self.assertTrue(packet['candidate_is_not_an_approval'])
        self.assertEqual(set(packet['observations']), set(REVIEW.LEDGER.SHARED.ROLES))


class CandidateFlowTests(PhysicalFixture, unittest.TestCase):
    def test_synthetic_capture_joins_native_events_cleanup_and_retains_unknowns(self):
        packet = self.extract()
        self.assert_unsigned(packet)
        self.assertEqual(packet['run_scoped_case_id'], self.identity)
        self.assertTrue(packet['review_checks']['successful_actual_allocation_join'])
        self.assertTrue(packet['review_checks']['one_clean_native_observer_final'])
        self.assertTrue(packet['review_checks']['controller_cleanup_clean'])
        fields = packet['observations']
        self.assertEqual(fields['native_transaction_id']['value']['transaction_id'], 'native-id')
        self.assertEqual(fields['native_free_calls']['value']['native_cleanup'], 1)
        self.assertEqual(fields['terminal_event_count']['value']['actual_common_terminal_subset_count'], 0)
        self.assertEqual(fields['descriptor_cleanup']['value']['actual_fd_differences']['main']['changed'], {})
        self.assertIsNone(fields['neighbor_health']['value'])
        self.assertIn('neighbor_health', packet['unknown_fields'])
        for item in packet['input_evidence']:
            REVIEW.ORACLES.verify_reference(item)

    def test_changed_admission_spec_is_rejected_before_capture_join(self):
        self.spec_path.write_text('{}')
        with self.assertRaisesRegex(ValueError, 'bind the supplied admission spec'):
            self.extract()

    def test_changed_sealed_fixture_ledger_is_rejected(self):
        (self.base / 'fixture-ledger.json').write_text('changed')
        with self.assertRaisesRegex(ValueError, 'ledger hash changed'):
            self.extract()

    def test_launch_case_mismatch_is_rejected(self):
        self.command['environment_overrides']['MSCONNECTOR_LIFECYCLE_CASE'] = 'foreign'
        self.write('attempt/data/apache-lifecycle-command.json', self.command)
        with self.assertRaisesRegex(ValueError, 'actual launched case'):
            self.extract()

    def test_missing_backend_remains_unknown_instead_of_zero(self):
        (self.data / 'apache-backend.jsonl').unlink()
        packet = self.extract()
        self.assert_unsigned(packet)
        self.assertIsNone(packet['observations']['backend_request_count']['value'])
        self.assertIn('backend_request_count', packet['unknown_fields'])

    def test_final_inside_principal_window_fails_cleanup_without_approval(self):
        self.api[-1]['monotonic_ns'] = 125
        self.write_rows('attempt/data/apache-native-api.jsonl', self.api)
        packet = self.extract()
        self.assert_unsigned(packet)
        self.assertFalse(packet['review_checks']['one_clean_native_observer_final'])
        self.assertFalse(packet['review_checks']['no_observer_final_during_principal_host_window'])
        self.assertEqual(len(packet['observations']['cleanup_receipts']['value'][
            'actual_same_pid_in_host_window_observer_finals']), 1)


class BatchFlowTests(PhysicalFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.case_root = self.base / 'batch' / '000-synthetic-allow'
        self.plan = {'original_id': self.identity, 'case_id': self.case,
                     'original_contract': self.contract['original_selected_requirement'], 'execution_kind': 'host_http'}
        self.observation = {'original_id': self.identity, 'case_id': self.case,
            'actual_principal_execution': True, 'executed_case_contract': True,
            'missing_operations': [], 'execution_error': None,
            'sampler_thread_stopped': True, 'native_process_sampler_errors': []}
        prefix = 'batch/000-synthetic-allow/'
        self.write(prefix + 'observation.json', self.observation)
        self.write(prefix + 'spec.json', self.plan)
        self.write(prefix + 'main/receipt.json', self.client)
        self.write(prefix + 'main/process.command.json', {'waited_exit': 0})
        self.write(prefix + 'main/request.raw', 'GET /synthetic HTTP/1.1\r\n\r\n')
        self.write(prefix + 'main/response.raw', 'HTTP/1.1 200 OK\r\nX-Physical: yes\r\n\r\nOK')
        self.write_rows(prefix + 'host-eos.jsonl', self.host)
        self.write_rows(prefix + 'native-api.jsonl', self.api)
        self.write_rows(prefix + 'backend/requests.jsonl', [
            {'kind': 'request_arrival', 'request_id': 'main', 'uri': '/synthetic', 'monotonic_ns': 150},
            {'kind': 'request', 'request_id': 'main', 'uri': '/synthetic', 'monotonic_ns': 151}])
        self.write(prefix + 'httpd.conf', '# synthetic batch config')
        self.write(prefix + 'rules.conf', '# synthetic batch rules')
        self.write(prefix + 'audit.log', '---main---A--\n[time] native-id 1 2 3 4\n---main---H--\n[id "123"]\n---main---Z--\n')
        self.write_rows(prefix + 'events.jsonl', [{'transaction_id': 'common-id',
            'message_id': 'MSCONN_EVENT_RULE_MATCHED'}])
        self.source_reference = self.write('batch-source/connectors/apache/src/mod_security3.c',
                                           '/* private synthetic Apache source */\n')
        self.source_ledger = self.write('batch-source-ledger.json', {
            'synthetic': True, 'files': [self.source_reference],
            'effective_configuration': [
                REVIEW.ORACLES.reference(self.case_root / name)
                for name in ('httpd.conf', 'rules.conf')]})
        self.batch_bindings = {'/mnt/src': {
            'target': '/mnt/src', 'source': str(self.base / 'batch-source'),
            'ledger': self.source_ledger['path'], 'ledger_sha256': self.source_ledger['sha256']}}
        self.spec['bindings'] = list(self.batch_bindings.values())
        self.write('spec.json', self.spec)
        self.controller['spec_sha256'] = REVIEW.ORACLES.reference(self.spec_path)['sha256']
        self.write('attempt/controller-result.json', self.controller)

    def extract_batch(self):
        extractor = BATCH.BatchExtractor(self.attempt, self.spec_path, self.plan,
                                         self.case_root, self.batch_bindings, self.controller)
        extractor.load_batch_case()
        packet = extractor.packet()
        binding = packet['observations']['source_config_binding']
        self.assertEqual({item['role'] for item in binding['evidence']},
                         {'source_manifest', 'effective_configuration'})
        for item in binding['evidence']:
            REVIEW.ORACLES.verify_reference(item)
            self.assertTrue(Path(item['path']).is_relative_to(self.base))
        ledger = json.loads(Path(self.source_ledger['path']).read_text())
        self.assertEqual(ledger['files'], [self.source_reference])
        REVIEW.ORACLES.verify_reference(ledger['files'][0])
        for item in ledger['effective_configuration']:
            REVIEW.ORACLES.verify_reference(item)
        self.assertEqual(binding['value']['sealed_bindings'], self.batch_bindings)
        self.assertEqual(binding['value']['spec_sha256'],
                         REVIEW.ORACLES.reference(self.spec_path)['sha256'])
        self.assertEqual(binding['value']['actual_effective_config_sha256'],
                         ledger['effective_configuration'][0]['sha256'])
        self.assertEqual(binding['value']['actual_rules_sha256'],
                         ledger['effective_configuration'][1]['sha256'])
        self.assertEqual(next(item['sha256'] for item in binding['evidence']
                              if item['role'] == 'source_manifest'), self.source_ledger['sha256'])
        return packet

    def test_physical_wire_backend_and_native_joins_produce_unsigned_packet(self):
        packet = self.extract_batch()
        self.assert_unsigned(packet)
        self.assertTrue(packet['unsigned'])
        self.assertEqual(packet['main_client_capture']['kind'], 'standard')
        fields = packet['observations']
        self.assertEqual(fields['client_headers']['value']['headers'], [['X-Physical', 'yes']])
        self.assertEqual(fields['backend_request_count']['value']['main'], 1)
        self.assertEqual(len(fields['backend_payload_identity']['value']['physical_transcript']), 2)
        self.assertIsNone(fields['client_backend_correlation']['value']['request_body_hash_equal'])
        self.assertTrue(packet['driver_execution']['executed_case_contract'])
        self.assertEqual(fields['native_events']['value']['native_transaction_id'], 'native-id')

    def test_foreign_observation_identity_rejected(self):
        self.observation['original_id'] = 'I12::apache-native::foreign'
        self.write('batch/000-synthetic-allow/observation.json', self.observation)
        with self.assertRaisesRegex(ValueError, 'observation identity differs'):
            self.extract_batch()

    def test_missing_typed_client_rejected_without_synthetic_fallback(self):
        (self.case_root / 'main/receipt.json').unlink()
        with self.assertRaisesRegex(FileNotFoundError, 'typed principal client'):
            self.extract_batch()

    def test_unidentified_backend_row_is_rejected(self):
        self.write_rows('batch/000-synthetic-allow/backend/requests.jsonl', [
            {'kind': 'request', 'uri': '/synthetic', 'monotonic_ns': 150}])
        with self.assertRaisesRegex(ValueError, 'physical request identity'):
            self.extract_batch()

    def test_empty_response_records_absence_without_status_invention(self):
        (self.case_root / 'main/response.raw').write_bytes(b'')
        packet = self.extract_batch()
        self.assert_unsigned(packet)
        header = packet['observations']['client_headers']['value']
        self.assertIsNone(header['status'])
        self.assertTrue(header['absence_observed'])
        self.assertEqual(header['physical_wire_bytes'], 0)

    def test_missing_process_receipt_preserves_unknown_exit(self):
        (self.case_root / 'main/process.command.json').unlink()
        packet = self.extract_batch()
        self.assert_unsigned(packet)
        self.assertIsNone(packet['observations']['client_exit']['value'])
        self.assertIn('client_exit', packet['unknown_fields'])


if os.environ.get('ON_DEMAND_TESTS') != '1':
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == '__main__':
    unittest.main()
