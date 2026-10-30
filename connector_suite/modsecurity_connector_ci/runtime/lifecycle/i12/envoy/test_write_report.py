"""Controls for route-specific report accounting and original-ID bindings."""
from modsecurity_test_framework.connector_context import load_source
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
writer = load_source(HERE / 'write_report.py')


class ReportControls(unittest.TestCase):
    def test_current_base_supplement_keeps_historical_counts_and_revision(self):
        data = {'parent_sha': 'f27', 'summary': {'lifecycle_pass': 7, 'open': 118},
            'host_measurements': [1] * 86, 'original_id_retakes': {'host_runs': 37},
            'physical_inputs': {}}
        supplement = {'parent_sha': 'a622', 'new_lifecycle_pass': 0,
            'route_transport_observations': {'request': {'target': {'authorization': {
                'remote_grpc_status': None, 'successful_grpc_completion': False}}}}}
        before = json.loads(json.dumps(data))
        with patch.object(writer.current_base_evidence, 'validate', return_value=supplement), \
                patch.object(writer, 'reference', return_value={'sha256': 'supplement'}):
            writer.add_current_base_evidence(data, Path('/supplement.json'))
        for key in ('parent_sha', 'summary', 'host_measurements', 'original_id_retakes'):
            self.assertEqual(data[key], before[key])
        self.assertEqual(data['current_base_evidence'], supplement)
        for german in (False, True):
            findings = '\n'.join(writer.current_base_findings(data, german))
            self.assertIn('`new_lifecycle_pass=0`', findings)
            self.assertIn('| request | target | unknown | false |',
                          findings)
            self.assertIn('`64/31/0-EOS`', findings)
            self.assertIn('`max_request_bytes=4096`', findings)
            self.assertIn('`errno 104`', findings)
            self.assertIn('P3', findings)
            self.assertIn('Commit' if german else 'commit', findings)
            self.assertIn('34 PASS', '\n'.join(writer.verification_limits(german)))
            exclusions = '\n'.join(writer.strict_status_exclusions(german))
            for identity in writer.STRICT_STATUS_EXCLUSIONS:
                self.assertIn(identity, exclusions)

    def test_v3_current_base_does_not_relabel_earlier_transport_or_counts(self):
        supplement = {'schema': 'i12.envoy.current-base-evidence.v3',
            'parent_sha': 'afaf6305bd55646073c3b40632b52fc4e5edf714',
            'new_lifecycle_pass': 0,
            'route_transport_observations': {'envoy-ext-authz-request': {'target': {
                'authorization': {'remote_grpc_status': None,
                                  'successful_grpc_completion': False}}}}}
        data = {'current_base_evidence': supplement}
        before = json.loads(json.dumps(data))
        for german in (False, True):
            findings = '\n'.join(writer.current_base_findings(data, german))
            for marker in ('afaf6305', 'a622', 'e4', 'Go 1.27.2', 'Go 1.27.3',
                           '155', '10', '`new_lifecycle_pass=0`', '95/96', '6/7',
                           '37', '33', '118', '64/31/0-EOS', '64/32/0-EOS',
                           'max_request_bytes=4096', 'P4 Strict',
                           '76672071c3f7665dfde3340bef9e64271d6f6e70'):
                self.assertIn(marker, findings)
            self.assertNotIn('current base' if not german else 'aktuellen Base', findings)
            self.assertIn('| envoy-ext-authz-request | target | unknown | false |', findings)
            self.assertNotIn('errno 104', findings)
        self.assertEqual(data, before)

    def test_absent_current_base_supplement_preserves_report(self):
        data = {'physical_inputs': {}}
        writer.add_current_base_evidence(data, None)
        self.assertEqual(data, {'physical_inputs': {}})
        self.assertEqual(writer.current_base_findings(data, False), [])

    def test_compact_serialization_preserves_unknown_and_nested_evidence(self):
        data = {'status': 'PARTIAL', 'original_ids': [{'id': 'one', 'grpc_status': None}],
                'host_measurements': [{'backend': {'request_count': 0, 'request_count_is_lower_bound': True}}],
                'qualified_originals': [], 'counts': {'open': 119}}
        self.assertEqual(json.loads(writer.encode_report(data)), data)
        originals = [{'run_scoped_case_id': identity}
                     for identity in writer.STRICT_STATUS_EXCLUSIONS]
        strict_data = {'original_ids': originals, 'qualified_originals': []}
        writer.bind_strict_status_exclusions(strict_data)
        exclusions = strict_data['strict_status_exclusions']
        self.assertEqual(exclusions['count'], 4)
        self.assertEqual(exclusions['original_ids'], list(writer.STRICT_STATUS_EXCLUSIONS))
        self.assertEqual(exclusions['qualification_outcome'], 'UNQUALIFIED')
        self.assertIsNone(exclusions['remote_grpc_status'])
        self.assertFalse(exclusions['successful_grpc_completion'])
        strict_data['qualified_originals'] = [
            {'run_scoped_case_id': originals[0]['run_scoped_case_id']}]
        with self.assertRaisesRegex(ValueError, 'unknown Authorization status'):
            writer.bind_strict_status_exclusions(strict_data)

    def test_fault_probe_report_retains_failed_client_finish_and_nonqualification(self):
        target_counts = {'native_process_request_headers': 1, 'native_process_request_body': 1,
            'native_process_response_headers': 1, 'native_process_logging': 1,
            'native_cleanup': 1, 'common_cleanup': 1}
        target = {'completed_transition_count': 0, 'observed_return_counts': target_counts,
            'return_result_counts': {'runtime_finish': {'0': 1}},
            'typed_body_callbacks': [
                {'operation': 1, 'response_direction': 1, 'body_bytes': 64},
                {'operation': 1, 'response_direction': 1, 'body_bytes': 32}]}
        neighbor = {'completed_transition_count': 1,
            'observed_return_counts': {'native_process_response_body': 1},
            'return_result_counts': {'runtime_finish': {'1': 1}}, 'typed_body_callbacks': []}
        fault = {'host_lifecycle_qualified': False, 'new_lifecycle_pass': 0,
            'source_contract_checks': {'drop': True},
            'envoy_received_status': {'grpc_status': 14, 'successful_grpc_completion': False},
            'target': {'remote_wire_status_observed': False},
            'target_client_incomplete_response': {'framing_complete': False,
                'terminal_zero_chunk_observed': False, 'entity_prefix_bytes': 96,
                'complete_chunk_sizes': [64, 32]}}
        probe = {'fault_proxy': fault, 'clients': {
                'target': {'raw_http_status': 200, 'process_exit': 1},
                'neighbor': {'raw_http_status': 200, 'process_exit': 0}},
            'runner_exit_code': 77,
            'controller': {'exitcode': 1, 'surviving_namespace_pid_count': 0,
                'outside_mount_leak_count': 0},
            'driver': {'remaining_owned_process_count': 0},
            'native': {'scopes': [target, neighbor]}}
        lines = writer.fault_probe_findings({'host_measurements': [probe]}, False)
        self.assertIn('`new_lifecycle_pass=0`', '\n'.join(lines))
        self.assertIn('client exit 1', '\n'.join(lines))
        self.assertIn('Runner exit 77, controller exit 1', '\n'.join(lines))
        fault['new_lifecycle_pass'] = 1
        with self.assertRaisesRegex(ValueError, 'lost a required independent physical observation'):
            writer.fault_probe_findings({'host_measurements': [probe]}, False)

    def test_existing_qualification_cannot_be_counted_as_new(self):
        baseline = {'routes': {'request': {'existing_pass_ids': ['same']}}}
        with self.assertRaisesRegex(ValueError, 'existing qualification'):
            writer.add_route_results({}, baseline, [{'route': 'request', 'run_scoped_case_id': 'same'}])

    def test_retaken_original_cannot_claim_sibling_route(self):
        item = {'route': 'response'}
        sources = {'original': {'route': 'request'}}
        with self.assertRaisesRegex(ValueError, 'sibling original ID'):
            writer.add_retaken_ids(item, ['original'], sources, {})

    def test_retaken_original_requires_physical_review_hash(self):
        item = {'route': 'request', 'oracle_review_sha256': 'wrong'}
        sources = {'original': {'route': 'request', 'review_file': '/approved/review.json'}}
        with (
            patch.object(writer, 'reference', return_value={'sha256': 'expected'}),
            self.assertRaisesRegex(ValueError, 'independently verified review'),
        ):
            writer.add_retaken_ids(item, ['original'], sources, {})


    def supplement_fixture(self):
        path = Path('/approved/supplement.json')
        origin = {'path': '/approved/original.json', 'sha256': 'old', 'bytes': 20}
        reviewed = {'path': str(path), 'sha256': 'supplement', 'bytes': 30}
        source_rows = {'original': {'route': 'response', 'review_file': origin['path']},
                       'different': {'route': 'response', 'review_file': origin['path']}}
        supplement = {'schema': 'supplement', 'route': 'response', 'original_id': 'original',
            'review_file': reviewed, 'origin_review': origin,
            'normalized_rows': [{'run_scoped_case_id': 'original', 'route': 'response'}],
            'canonical_resolution_changed': False, 'new_lifecycle_pass': 0}
        refs = {origin['path']: origin, str(path): reviewed}
        return path, source_rows, supplement, refs

    def test_default_empty_supplements_leave_report_structure_unchanged(self):
        data = {'physical_inputs': {}, 'source_oracle_progress': {'reviewed_count': 125}}
        self.assertEqual(writer.add_oracle_supplements(data, [], {}, {}), {})
        self.assertEqual(data, {'physical_inputs': {}, 'source_oracle_progress': {'reviewed_count': 125}})

    def test_supplement_keeps_original_counts_and_requires_fresh_validation(self):
        path, sources, supplement, refs = self.supplement_fixture()
        original_review = {'reviewed_count': 125, 'new_source_proposals': 33}
        data = {'physical_inputs': {}, 'source_oracle_progress': dict(original_review)}
        with (
            patch.object(writer.validate_oracles, 'validate_supplement', return_value=supplement) as validate,
            patch.object(writer, 'reference', side_effect=lambda p: refs[str(p)]),
        ):
            allowed = writer.add_oracle_supplements(data, [path], original_review, sources)
        validate.assert_called_once_with(path, original_review)
        self.assertEqual(allowed, {'original': {'supplement'}})
        self.assertEqual(data['source_oracle_progress'], original_review)
        self.assertNotIn('normalized_rows', data['oracles_supplements'][0])
        self.assertFalse(data['oracles_supplements'][0]['canonical_resolution_changed'])
        self.assertEqual(data['oracles_supplements'][0]['new_lifecycle_pass'], 0)

    def test_supplement_rejects_different_normalized_original_id(self):
        path, sources, supplement, refs = self.supplement_fixture()
        supplement['normalized_rows'][0]['run_scoped_case_id'] = 'different'
        with (
            patch.object(writer, 'reference', side_effect=lambda p: refs[str(p)]),
            self.assertRaisesRegex(ValueError, 'exact original ID'),
        ):
            writer.supplement_binding(supplement, path, sources)

    def test_supplement_rejects_sibling_route(self):
        path, sources, supplement, refs = self.supplement_fixture()
        supplement['route'] = 'request'
        with (
            patch.object(writer, 'reference', side_effect=lambda p: refs[str(p)]),
            self.assertRaisesRegex(ValueError, 'sibling original ID'),
        ):
            writer.supplement_binding(supplement, path, sources)

    def test_duplicate_supplement_cannot_count_twice(self):
        path, sources, supplement, refs = self.supplement_fixture()
        data = {'physical_inputs': {}}
        with (
            patch.object(writer.validate_oracles, 'validate_supplement', return_value=supplement),
            patch.object(writer, 'reference', side_effect=lambda p: refs[str(p)]),
            self.assertRaisesRegex(ValueError, 'duplicate oracle supplement'),
        ):
            writer.add_oracle_supplements(data, [path, path], {}, sources)

    def test_supplement_hash_accepts_only_its_exact_original_id(self):
        _, sources, _, refs = self.supplement_fixture()
        item = {'route': 'response', 'oracle_review_sha256': 'supplement', 'batch': 'retake',
                'scenario': 'new', 'runner_exit_code': 0, 'attempt': '/attempt', 'observation_state': 'observed'}
        allowed = {'original': {'supplement'}}
        with patch.object(writer, 'reference', side_effect=lambda p: refs[str(p)]):
            collected = {}
            writer.add_retaken_ids(item, ['original'], sources, collected, allowed)
            self.assertEqual(list(collected), ['original'])
            with self.assertRaisesRegex(ValueError, 'independently verified review'):
                writer.add_retaken_ids(item, ['different'], sources, {}, allowed)
            item['oracle_review_sha256'] = 'unvalidated'
            with self.assertRaisesRegex(ValueError, 'independently verified review'):
                writer.add_retaken_ids(item, ['original'], sources, {}, allowed)
            item['oracle_review_sha256'] = 'old'
            writer.add_retaken_ids(item, ['original'], sources, collected, allowed)
            self.assertEqual(len(collected['original']), 2)

    def test_old_84_runs_and_one_supplement_keep_unique_id_accounting(self):
        _, sources, _, refs = self.supplement_fixture()
        old = {'route': 'response', 'oracle_review_sha256': 'old', 'batch': 'original',
               'scenario': 'old', 'runner_exit_code': 0, 'attempt': '/attempt',
               'observation_state': 'observed', 'original_oracle_case_ids': ['original']}
        fresh = dict(old, oracle_review_sha256='supplement', batch='retake', scenario='fresh')
        data = {'host_measurements': [dict(old) for _ in range(84)] + [fresh],
                'original_ids': [{'run_scoped_case_id': 'original'}],
                'source_oracle_progress': {'reviewed_count': 125, 'new_source_proposals': 33}}
        with patch.object(writer, 'reference', side_effect=lambda p: refs[str(p)]):
            writer.add_original_retakes(data, sources, {'original': {'supplement'}})
        self.assertEqual(data['original_id_retakes']['host_runs'], 85)
        self.assertEqual(data['original_id_retakes']['unique_original_ids'], 1)
        self.assertEqual(data['source_oracle_progress'], {'reviewed_count': 125, 'new_source_proposals': 33})
        self.assertEqual(len(data['original_ids'][0]['current_task_unqualified_host_runs']), 85)
        self.assertFalse(data['original_id_retakes']['full_lifecycle_qualified'])



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == '__main__':
    unittest.main()
