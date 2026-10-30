"""Source proposals preserve immutable Apache IDs and cannot approve runtime."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import copy
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

ROOT = connector_root()
SOURCE = source_path('ci/runtime/lifecycle/apache-i12/acceptance/oracles.py', root=ROOT)
ORACLES = load_source(SOURCE)


class SourceOracleTests(unittest.TestCase):
    def setUp(self):
        ledger = json.loads((source_path('reports/audits/apache-i12-20261015/case-ledger.json', root=ROOT)).read_text())
        self.inventory, self.plan, self.old = {'rows': []}, {'rows': []}, {'oracle_matrix': []}
        for original in ledger['rows']:
            contract = original['selected_requirement']
            identity = original['run_scoped_case_id']
            self.inventory['rows'].append({
                'original_id': identity, 'case_id': contract['case_id'],
                'original_contract': copy.deepcopy(contract),
                'contract_kind': 'configuration' if contract['execution_kind'] == 'actual_configtest' else 'host',
                'source_bindings': [], 'baseline': {
                    'original54member': original['original_54_oracle_member'],
                    'original_oracle_resolved': False}})
            self.plan['rows'].append({'original_id': identity, 'original_contract': copy.deepcopy(contract)})
            if original['original_54_oracle_member']:
                self.old['oracle_matrix'].append({
                    'run_scoped_case_id': identity, 'leg_id': 'apache-native',
                    'original_selected_requirement': copy.deepcopy(contract),
                    'original_oracle': copy.deepcopy(contract['expected_oracle']),
                    'original_source_revision': {'parent': 'immutable-test-revision'},
                    'original_source_hashes': {'original': 'immutable-test-hash'}})
        self.sources = {'independent': [], 'implementation': [], 'facts': {}}

    def review(self):
        return ORACLES.build_review(self.inventory, self.plan, self.old, self.sources)

    def test_all54_originals_preserved_without_runtime_or_resolution_promotion(self):
        before = copy.deepcopy((self.inventory, self.plan, self.old))
        result = self.review()
        self.assertEqual((result['original155'], result['configuration_contracts'],
                          result['host_contracts'], result['original54']), (155, 10, 145, 54))
        self.assertEqual(result['new_revision_resolved'], 0)
        original = {r['run_scoped_case_id']: r for r in self.old['oracle_matrix']}
        for row in result['rows']:
            self.assertEqual(row['original_oracle'], original[row['original_id']]['original_oracle'])
            self.assertIsNone(row['actual_observations'])
            self.assertIsNone(row['execution_observed'])
            self.assertIsNone(row['outcome'])
            self.assertIsNone(row['reviewed_by'])
            self.assertFalse(row['resolved'])
            self.assertFalse(row['full_lifecycle_qualified'])
        current_inputs = (self.inventory, self.plan, self.old)
        self.assertEqual(current_inputs, before)

    def test_prior_observed_result_is_never_an_oracle_input(self):
        first = self.review()
        for row in self.plan['rows']:
            row['candidate_expectation'] = {'visible_status': 599, 'native_rule_id': 999999}
            row['actual_observations'] = {'status': 599, 'outcome': 'PASS'}
        second = self.review()
        self.assertEqual([r['candidate_effective_oracle'] for r in first['rows']],
                         [r['candidate_effective_oracle'] for r in second['rows']])

    def test_historical_failed_retest_is_retained_without_current_promotion(self):
        old = self.old['oracle_matrix'][0]
        old.update(category='SOURCE_CONFIRMED_EXPECTATION', resolved=True,
                   retest={'outcome': 'FAIL', 'run_id': 'old-execution'}, outcome='FAIL')
        row = next(r for r in self.review()['rows'] if r['original_id'] == old['run_scoped_case_id'])
        self.assertEqual(row['historical_disposition']['retest'], old['retest'])
        self.assertEqual(row['historical_disposition']['outcome'], 'FAIL')
        self.assertFalse(row['resolved'])
        self.assertIsNone(row['outcome'])

    def test_changed_original_contract_and_membership_are_rejected(self):
        self.plan['rows'][0]['original_contract']['expected_oracle']['visible_status'] = 599
        with self.assertRaisesRegex(ValueError, 'original contract'):
            self.review()
        self.plan['rows'][0]['original_contract'] = self.inventory['rows'][0]['original_contract']
        self.old['oracle_matrix'].pop()
        with self.assertRaisesRegex(ValueError, 'original54 membership'):
            self.review()

    def test_abnormal_has_no_fabricated_http_status_or_normal_eos(self):
        for case in ORACLES.ABNORMAL:
            proposal, facts, gaps = ORACLES.source_analysis(case, {})
            self.assertIsNone(proposal)
            self.assertIn('apache_read_error_before_eos', facts)
            self.assertTrue(any('Normal P2/P4/EOS' in item for item in gaps))

    def test_mutating_all_input_copies_does_not_change_the_pinned_contract(self):
        self.inventory['rows'][0]['original_contract']['expected_oracle']['visible_status'] = 599
        self.plan['rows'][0]['original_contract'] = self.inventory['rows'][0]['original_contract']
        with self.assertRaisesRegex(ValueError, 'Immutable original155 contracts'):
            self.review()

    def test_unknown_scenario_does_not_get_a_default_allow_oracle(self):
        with self.assertRaisesRegex(ValueError, 'No independent source treatment'):
            ORACLES.source_analysis('unknown-scenario', {})

    def test_flush_requires_a_real_host_stage_and_partial_write_requires_retry_proof(self):
        _, _, flush = ORACLES.source_analysis('NEED-physical-event-sink-flush', {})
        _, _, short = ORACLES.source_analysis('NEED-physical-event-sink-short-write', {})
        self.assertTrue(any('no flush call' in text for text in flush))
        self.assertTrue(any('retries partial writes' in text for text in short))

    def test_undefined_request_mime_and_former_limit_remain_open(self):
        for case in ORACLES.UNDEFINED:
            proposal, _, gaps = ORACLES.source_analysis(case, {})
            self.assertIsNone(proposal)
            self.assertTrue(gaps)

    def body(self, content):
        return {"data": base64.b64encode(content).decode(), "bytes": len(content),
                "sha256": hashlib.sha256(content).hexdigest()}

    def test_request_mime_is_raw_processor_semantics_without_allowlist_claim(self):
        for suffix, mime in (("in", "text/plain"), ("out", "image/png")):
            plan = {"request": {"headers": [["Content-Type", mime]],
                "body": self.body(b"Apache-I12-request-payload")}}
            proposal, facts, gaps = ORACLES.source_analysis("NEED-request-mime-scope-" + suffix, plan)
            self.assertEqual((proposal['native_result'], proposal['visible_status'], proposal['phase']), ('allow', 200, 2))
            self.assertIsNone(proposal['request_processor_contract']['request_mime_allowlist'])
            self.assertEqual(proposal['request_processor_contract']['selected_body_type'], 'UnknownFormat')
            self.assertIn('sdk_request_unknown_format', facts)
            self.assertTrue(gaps)
            plan['request']['body'] = self.body(b'no-crs-request-body-marker')
            self.assertIsNone(ORACLES.source_analysis("NEED-request-mime-scope-" + suffix, plan)[0])

    def test_declared_payload_hash_tampering_is_not_an_oracle_source(self):
        body = self.body(b'Apache-I12-request-payload')
        body['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'identity mismatch'):
            ORACLES.source_analysis('NEED-request-mime-scope-in',
                {'request': {'headers': [['Content-Type', 'text/plain']], 'body': body}})

    def test_five_sink_proposals_keep_native403_renderer500_and_first_failure_domain(self):
        for case, (mode, stage, code) in ORACLES.SINK_CASES.items():
            plan = {'request': {'path': '/sink-disruptive'}, 'fault': {'kind': mode},
                'rules': 'id:120001,phase:1,pass,log\nid:120016,phase:1,deny,status:403,log'}
            proposal, _, gaps = ORACLES.source_analysis(case, plan)
            self.assertEqual((proposal['native_result'], proposal['native_intervention_status'],
                              proposal['visible_status'], proposal['rule_id']), ('deny', 403, 500, 120016))
            self.assertEqual(proposal['host_result'], 'technical_error')
            self.assertEqual(proposal['sink_first_cause']['errno_or_apr_status'], code)
            self.assertEqual(proposal['sink_first_cause']['operation'], stage)
            self.assertTrue(gaps)
            plan['rules'] = '\n'.join(reversed(plan['rules'].splitlines()))
            self.assertIsNone(ORACLES.source_analysis(case, plan)[0])

    def test_limit_partial_is_not_native_marker_deny_or_incomplete_transport(self):
        plan = {'request': {'body': self.body(b'a' * 17)},
                'rules': 'SecRequestBodyLimit 16\nSecRequestBodyLimitAction ProcessPartial'}
        proposal = ORACLES.limit_source_proposal('phase2_truncated', plan)
        self.assertEqual((proposal['native_result'], proposal['visible_status']), ('allow', 200))
        self.assertIsNone(proposal['rule_id'])
        self.assertFalse(proposal['limit_contract']['transport_incomplete'])
        self.assertFalse(proposal['limit_contract']['marker_present_in_native_buffer'])
        plan['request']['body'] = self.body(b'no-crs-request-body-marker')
        self.assertIsNone(ORACLES.limit_source_proposal('phase2_truncated', plan))

    def test_response_reject_has_no_intrinsic_rule_and_requires_precommit_renderer(self):
        plan = {'backend': {'body': self.body(b'a' * 17)},
                'rules': 'SecResponseBodyLimit 16\nSecResponseBodyLimitAction Reject'}
        proposal = ORACLES.limit_source_proposal('phase4_body_reject', plan)
        self.assertEqual(proposal['native_intervention_status'], 403)
        self.assertIsNone(proposal['rule_id'])
        self.assertTrue(proposal['limit_contract']['response_reject_403_requires_no_prior_commit'])
        self.assertFalse(proposal['limit_contract']['native_limit_has_intrinsic_rule_id'])

    def test_fabricated_nine_object_history_is_rejected_even_with_valid_report_hash(self):
        root = Path(os.environ.get('CODEX_TEST_TMP_ROOT') or os.environ.get('RUNNER_TEMP') or
                    '/var/tmp/codex/ModSecurity-conector/oracle-source-tests')
        root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=root) as temporary:
            history = Path(temporary) / 'history.json'
            history.write_text(json.dumps({'former_limit_history': {
                'default_bytes': 1048576, 'max_config_bytes': 10485760,
                'source_objects': [{'revision': 'fake', 'repository_path': 'fake',
                    'git_blob_oid': str(i), 'sha256': str(i), 'selected_lines': ['fake'],
                    'direction': 'request' if i < 4 else 'response'} for i in range(9)]}}))
            receipt = ORACLES.reference(history, 'unit_validator_input', 'synthetic-not-source-proof')
            plan = {'request': {'body': self.body(b'a')},
                    'former_limit_proof': {'source_history_receipt': receipt}}
            with self.assertRaisesRegex(ValueError, 'nine exact source objects'):
                ORACLES.source_analysis('NEED-request-above-former-connector-limit', plan)
            receipt['sha256'] = '0' * 64
            with self.assertRaisesRegex(ValueError, 'receipt identity mismatch'):
                ORACLES.source_analysis('NEED-request-above-former-connector-limit', plan)

    def test_absence_draft_requires_negative_witnesses_and_never_creates_resolution(self):
        row = next(r for r in self.review()['rows'] if r['case_id'] == 'NEED-cancel')
        draft = row['typed_status_absence_draft']
        self.assertIsNone(row['candidate_effective_oracle'])
        self.assertIsNone(draft['visible_status'])
        self.assertIsNone(draft['shared_schema_binding'])
        self.assertTrue(draft['required_independent_witnesses'])
        self.assertIn('reject', draft['final_HTTP_status_if_observed'])
        self.assertFalse(row['resolved'])

    def test_minimal_mode_has_no_silent_safe_mapping(self):
        plan = {'rows': [{'case_id': 'phase4_deny_after_commit_log_only_minimal',
                         'original_id': 'original-only', 'apache': {'phase4_mode': 'safe'}}]}
        result = ORACLES.minimal_mapping_gap(plan)
        self.assertIsNone(result['candidate_effective_oracle'])
        self.assertIsNone(result['approved_mapping'])
        self.assertIn('No source defines', result['source_gap'])

    def test_static_file_source_does_not_invent_a_proxy_backend_arrival(self):
        proposal, _, _ = ORACLES.source_analysis('NEED-response-file',
            {'backend': {'file': {'serving': 'apache_static_file'}}})
        self.assertEqual(proposal['backend_requests'], 0)
        self.assertIn('runtime predicates', proposal['response_file_contract'])

    def test_phase4_native_deny_is_distinct_from_committed_http200(self):
        result = ORACLES.basic_proposal('E2E-APACHE-P4-STRICT-LATE')
        self.assertEqual((result['native_result'], result['native_intervention_status'],
                          result['visible_status'], result['rule_id']), ('deny', 403, 200, 120015))

    def test_draft_cannot_pass_shared_root_approval_and_unresolved_stays_unresolved(self):
        row = self.review()['rows'][0]
        record = ORACLES.unresolved_record(row)
        shared = ORACLES.load_shared()
        selected = {'leg_id': 'apache-native', 'selected_requirement': row['original_contract']}
        with self.assertRaisesRegex(ValueError, 'Root review'):
            shared.review_record(record, selected)
        record['reviewed_by'] = 'root'
        result = shared.review_record(record, selected)
        self.assertFalse(result['resolved'])
        self.assertEqual(result['effective_oracle'], row['original_oracle'])



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == '__main__':
    unittest.main()
