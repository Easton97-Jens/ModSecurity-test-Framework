"""Typed unsigned control extraction and real shared-validator approval gates."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from modsecurity_connector_tests import test_i12_lifecycle_ledger as shared_fixtures


SOURCE = connector_root() / 'ci/runtime/lifecycle/apache-i12/acceptance/review_controls.py'
CONTROL = load_source(SOURCE)


class ControlReviewTests(unittest.TestCase):
    def setUp(self):
        storage = Path(os.environ.get('CODEX_TEST_TMP_ROOT') or os.environ.get('RUNNER_TEMP') or
                       '/var/tmp/codex/ModSecurity-conector/runs/apache-control-review-tests')
        storage.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=storage)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.environment = patch.dict(os.environ, {'CODEX_TEMP_ROOT': str(storage.resolve())})
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def write(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))
        return path

    def extraction(self, name, kind='host_http', native=None):
        identity = 'I12::apache-native::' + name
        plan = {'original_id': identity, 'case_id': name, 'execution_kind': kind,
                'original_contract': {'case_id': name, 'expected_oracle': {'visible_status': 400}}}
        root = self.root / 'case'
        self.write('case/observation.json', {'original_id': identity, 'case_id': name,
            'actual_principal_execution': True, 'actual_config_execution': kind == 'configtest'})
        spec = self.write('spec.json', {'argv': []})
        self.write('controller-result.json', {'spec_sha256': CONTROL.ORACLES.reference(spec)['sha256']})
        if native is not None:
            (root / 'native-api.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in native))
        packet = CONTROL.candidate(plan, root, self.root, spec, {},
                                   {'spec_sha256': CONTROL.ORACLES.reference(spec)['sha256']})
        return packet

    def test_pre_native_extraction_without_main_native_call_preserves_unknowns(self):
        native = [{'function': 'observer', 'edge': 'admitted', 'profile': 'apache-native',
                   'case': 'invalid_content_length', 'run': 'actual-observer-run', 'pid': 100, 'uid': 65534}]
        packet = self.extraction('invalid_content_length', native=native)
        self.assertEqual(packet['run_id'], 'actual-observer-run')
        self.assertEqual(packet['physical_observations']['host_pid'], 100)
        self.assertIsNone(packet['native_transaction_id'])
        self.assertIsNone(packet['outcome'])
        self.assertIsNone(packet['reviewed_by'])
        self.assertFalse(packet['oracle_evaluated'])
        self.assertFalse(packet['full_case_qualified'])
        self.assertIn('producer:healthy_controls', packet['missing_requirements'])
        self.assertIn('producer:event_observer', packet['missing_requirements'])
        self.assertIn('explicit_root_packet_review', packet['missing_requirements'])

    def test_missing_or_ambiguous_observer_does_not_borrow_control_transaction(self):
        native = [{'function': 'native_new', 'edge': 'return', 'profile': 'apache-native',
                   'case': 'invalid_content_length', 'run': 'neighbor-run', 'transaction_id': 'neighbor'}]
        packet = self.extraction('invalid_content_length', native=native)
        self.assertIsNone(packet['run_id'])
        self.assertIsNone(packet['native_transaction_id'])
        self.assertIn('identity:unique_physical_native_observer_admission', packet['missing_requirements'])

    def test_duplicate_observer_admission_is_explicitly_ambiguous(self):
        admission = {'function': 'observer', 'edge': 'admitted', 'profile': 'apache-native',
                     'case': 'invalid_content_length', 'run': 'physical-run', 'pid': 100, 'uid': 65534}
        packet = self.extraction('invalid_content_length', native=[admission, admission])
        self.assertIsNone(packet['run_id'])
        self.assertIn('identity:unique_physical_native_observer_admission', packet['missing_requirements'])

    def test_all_four_original_pre_native_cases_and_no_additional_case(self):
        self.assertEqual(CONTROL.PRE_NATIVE_CASES, frozenset(('invalid_content_length',
            'conflicting_content_length', 'duplicate_transfer_encoding', 'content_length_overflow')))
        for name in CONTROL.PRE_NATIVE_CASES:
            with self.subTest(name=name):
                packet = self.extraction(name)
                self.assertEqual(packet['execution_kind'], 'host_pre_native_rejection')
                self.assertIsNone(packet['outcome'])
        with self.assertRaisesRegex(ValueError, 'Only original Apache parser controls'):
            self.extraction('missing_eos')

    def test_config_inventory_does_not_invent_process_or_independent_expectation(self):
        packet = self.extraction('valid_rules_file', 'configtest')
        self.assertEqual(packet['control_scope'], 'configuration_control')
        self.assertIsNone(packet['physical_observations']['parser_process'])
        self.assertIsNone(packet['run_id'])
        self.assertIn('producer:expectation_source', packet['missing_requirements'])
        self.assertIn('producer:parser_process', packet['missing_requirements'])
        self.assertFalse(packet['full_lifecycle_qualified'])

    def approval_fixture(self):
        row, packet, _ = shared_fixtures.configuration_control(self.root)
        identity = 'I12::apache-native::valid_rules_file'
        row.update(run_scoped_case_id=identity, leg_id='apache-native')
        packet.update(run_scoped_case_id=identity, leg_id='apache-native', full_lifecycle_qualified=False)
        process_ref = next(ref for ref in packet['measurement_evidence'] if ref['role'] == 'parser_process')
        process_path = Path(process_ref['path'])
        process = json.loads(process_path.read_text())
        process.update(run_scoped_case_id=identity, leg_id='apache-native')
        process_path.write_text(json.dumps(process))
        process_ref.update(CONTROL.ORACLES.reference(process_path))
        candidate = {'unsigned': True, 'run_scoped_case_id': identity, 'leg_id': 'apache-native',
            'execution_kind': 'configuration_parser', 'control_scope': 'configuration_control',
            'original_selected_requirement': row['selected_requirement'],
            'role_evidence': packet['measurement_evidence'], 'physical_captures': []}
        candidate_path = self.write('candidate.json', candidate)
        approval = {'reviewed_by': 'root', 'reason': 'Synthetic explicit review decision for validator test',
                    'candidate': CONTROL.ORACLES.reference(candidate_path), 'packet': packet}
        approval_path = self.write('approval.json', approval)
        return row, candidate_path, approval, approval_path

    def test_real_shared_config_validator_gates_publication_and_revalidation(self):
        row, candidate, _, approval = self.approval_fixture()
        result = CONTROL.approved_packet(candidate, approval, row, self.root / 'reviewed.json')
        self.assertEqual(result['qualification_scope'], 'configuration_control')
        self.assertEqual(result['outcome'], 'PASS')
        self.assertFalse(result['full_lifecycle_qualified'])
        verified = CONTROL.SHARED.reviewed_configuration_packet(
            result['reference'], row, row['selected_requirement']['expected_oracle'])
        self.assertTrue(verified['full_case_qualified'])

    def test_review_batch_nested_candidate_is_directly_approvable(self):
        row, candidate, approval, path = self.approval_fixture()
        inner = json.loads(candidate.read_text())
        candidate.write_text(json.dumps({'unsigned': True, 'run_scoped_case_id': inner['run_scoped_case_id'],
            'leg_id': inner['leg_id'], 'control_candidate': inner}))
        approval['candidate'] = CONTROL.ORACLES.reference(candidate)
        path.write_text(json.dumps(approval))
        result = CONTROL.approved_packet(candidate, path, row, self.root / 'reviewed.json')
        self.assertEqual(result['qualification_scope'], 'configuration_control')

    def test_wrapper_cannot_transfer_a_sibling_control(self):
        _, candidate, _, _ = self.approval_fixture()
        inner = json.loads(candidate.read_text())
        candidate.write_text(json.dumps({'unsigned': True, 'run_scoped_case_id': 'I12::apache-native::sibling',
            'leg_id': inner['leg_id'], 'control_candidate': inner}))
        with self.assertRaisesRegex(ValueError, 'Batch wrapper differs'):
            CONTROL.read_candidate(candidate)

    def test_missing_root_decision_cannot_publish(self):
        row, candidate, approval, path = self.approval_fixture()
        approval['reviewed_by'] = None
        path.write_text(json.dumps(approval))
        output = self.root / 'reviewed.json'
        with self.assertRaisesRegex(ValueError, 'Root approval'):
            CONTROL.approved_packet(candidate, path, row, output)
        self.assertFalse(output.exists())

    def test_changed_candidate_or_physical_producer_cannot_publish(self):
        row, candidate, _, approval = self.approval_fixture()
        candidate.write_text(candidate.read_text() + ' ')
        with self.assertRaises(ValueError):
            CONTROL.approved_packet(candidate, approval, row, self.root / 'reviewed.json')
        self.assertFalse((self.root / 'reviewed.json').exists())

    def test_verdict_mutation_is_rejected_by_real_validator_without_output(self):
        row, candidate, approval, path = self.approval_fixture()
        approval['packet']['actual_observations']['parser_process']['waited_exit'] = 1
        path.write_text(json.dumps(approval))
        with self.assertRaisesRegex(ValueError, 'physical process'):
            CONTROL.approved_packet(candidate, path, row, self.root / 'reviewed.json')
        self.assertFalse((self.root / 'reviewed.json').exists())

    def test_approval_cannot_change_original_expectation(self):
        row, candidate, _, approval = self.approval_fixture()
        row = copy.deepcopy(row)
        row['selected_requirement']['expected_oracle']['visible_status'] = 1
        with self.assertRaisesRegex(ValueError, 'original Apache control contract'):
            CONTROL.approved_packet(candidate, approval, row, self.root / 'reviewed.json')

    def test_uninventoried_packet_evidence_is_rejected(self):
        row, candidate, approval, path = self.approval_fixture()
        replacement = self.write('replacement.json', {'parent_sha': 'control-parent'})
        ref = next(ref for ref in approval['packet']['measurement_evidence'] if ref['role'] == 'source_manifest')
        ref.update(CONTROL.ORACLES.reference(replacement))
        path.write_text(json.dumps(approval))
        with self.assertRaisesRegex(ValueError, 'explicit review inventory'):
            CONTROL.approved_packet(candidate, path, row, self.root / 'reviewed.json')

    def test_existing_output_cannot_be_overwritten(self):
        row, candidate, _, approval = self.approval_fixture()
        output = self.write('reviewed.json', {'existing': 'preserved'})
        with self.assertRaises(FileExistsError):
            CONTROL.approved_packet(candidate, approval, row, output)
        self.assertEqual(json.loads(output.read_text()), {'existing': 'preserved'})

    def pre_native_approval_fixture(self):
        fixture = shared_fixtures.PreNativeRejectionTests(
            'test_separate_pre_native_scope_preserves_native_alternative_and_no_fake_lifecycle')
        with patch.object(tempfile, 'tempdir', str(self.root)):
            fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.bind()
        candidate = {'unsigned': True, 'run_scoped_case_id': fixture.case, 'leg_id': 'apache-native',
            'execution_kind': 'host_pre_native_rejection', 'control_scope': 'host_pre_native_rejection',
            'original_selected_requirement': fixture.row['selected_requirement'],
            'role_evidence': fixture.packet['measurement_evidence'], 'physical_captures': []}
        path = self.write('candidate.json', candidate)
        approval = {'reviewed_by': 'root', 'reason': 'Synthetic explicit host parser review',
                    'candidate': CONTROL.ORACLES.reference(path), 'packet': fixture.packet,
                    'supplemental_evidence': [*fixture.packet['source_approval']['proof'],
                        *[CONTROL.ORACLES.reference(fixture.root / name) for name in
                          ('process-maps', 'process-status', 'sink', 'before-client',
                           'before-process', 'after-client', 'after-process')]]}
        return fixture, path, self.write('approval.json', approval)

    def test_real_pre_native_validator_gates_publication_without_main_native_id(self):
        fixture, candidate, approval = self.pre_native_approval_fixture()
        result = CONTROL.approved_packet(candidate, approval, fixture.row, self.root / 'reviewed.json')
        self.assertEqual(result['qualification_scope'], 'host_pre_native_rejection')
        self.assertEqual(result['outcome'], 'PASS')
        packet = json.loads(Path(result['reference']['path']).read_text())
        self.assertIsNone(packet['native_transaction_id'])
        self.assertFalse(packet['full_lifecycle_qualified'])

    def test_pre_native_positive_control_mutation_leaves_no_output(self):
        fixture, candidate, approval = self.pre_native_approval_fixture()
        native = next(ref for ref in fixture.packet['measurement_evidence'] if ref['role'] == 'native_api')
        Path(native['path']).write_text('')
        with self.assertRaises(ValueError):
            CONTROL.approved_packet(candidate, approval, fixture.row, self.root / 'reviewed.json')
        self.assertFalse((self.root / 'reviewed.json').exists())

    def rewrite_producer(self, candidate_path, approval_path, role, change):
        """Rebind the deliberately changed producer, leaving dependencies explicit."""
        candidate = json.loads(candidate_path.read_text())
        approval = json.loads(approval_path.read_text())
        producer = next(ref for ref in approval['packet']['measurement_evidence'] if ref['role'] == role)
        path = Path(producer['path'])
        document = json.loads(path.read_text())
        change(document)
        path.write_text(json.dumps(document))
        new_reference = CONTROL.ORACLES.reference(path)
        producer.update(new_reference)
        next(ref for ref in candidate['role_evidence'] if ref['role'] == role).update(new_reference)
        candidate_path.write_text(json.dumps(candidate))
        approval['candidate'] = CONTROL.ORACLES.reference(candidate_path)
        approval_path.write_text(json.dumps(approval))

    def assert_inventory_rejected(self, candidate, approval, row):
        output = self.root / 'reviewed.json'
        with self.assertRaisesRegex(ValueError, 'explicit review inventory'):
            CONTROL.approved_packet(candidate, approval, row, output)
        self.assertFalse(output.exists())

    def config_dependency_fixture(self, inventoried):
        row, candidate, _, approval_path = self.approval_fixture()
        dependency = self.write('source-support.json', {'independent_bytes': 'explicit support'})
        reference = CONTROL.ORACLES.reference(dependency)
        self.rewrite_producer(candidate, approval_path, 'source_manifest',
                              lambda document: document.update(supporting_source=reference))
        if inventoried:
            approval = json.loads(approval_path.read_text())
            approval['supplemental_evidence'] = [reference]
            approval_path.write_text(json.dumps(approval))
        return row, candidate, approval_path, dependency

    def test_config_producer_dependency_requires_explicit_inventory(self):
        row, candidate, approval, _ = self.config_dependency_fixture(False)
        self.assert_inventory_rejected(candidate, approval, row)

    def test_config_explicit_dependency_is_accepted_without_recursive_admission(self):
        row, candidate, approval, _ = self.config_dependency_fixture(True)
        result = CONTROL.approved_packet(candidate, approval, row, self.root / 'reviewed.json')
        self.assertEqual(result['qualification_scope'], 'configuration_control')

    def test_config_foreign_transitive_reference_cannot_replace_reviewed_dependency(self):
        row, candidate, approval, _ = self.config_dependency_fixture(True)
        foreign = self.write('foreign-support.json', {'independent_bytes': 'different support'})
        self.rewrite_producer(candidate, approval, 'source_manifest',
            lambda document: document.update(supporting_source=CONTROL.ORACLES.reference(foreign)))
        self.assert_inventory_rejected(candidate, approval, row)

    def test_config_mutated_transitive_bytes_cannot_publish(self):
        row, candidate, approval, dependency = self.config_dependency_fixture(True)
        dependency.write_text('changed after explicit review')
        with self.assertRaises(ValueError):
            CONTROL.approved_packet(candidate, approval, row, self.root / 'reviewed.json')
        self.assertFalse((self.root / 'reviewed.json').exists())

    def test_each_shared_pre_native_transitive_reference_must_be_inventoried(self):
        fixture, candidate, approval_path = self.pre_native_approval_fixture()
        original = json.loads(approval_path.read_text())
        for name in ('process-maps', 'process-status', 'sink', 'before-client',
                     'before-process', 'after-client', 'after-process'):
            with self.subTest(producer=name):
                approval = copy.deepcopy(original)
                approval['supplemental_evidence'] = [ref for ref in approval['supplemental_evidence']
                                                     if ref['path'] != str(fixture.root / name)]
                approval_path.write_text(json.dumps(approval))
                self.assert_inventory_rejected(candidate, approval_path, fixture.row)

    def test_pre_native_foreign_maps_reference_is_rejected_even_with_identical_bytes(self):
        fixture, candidate, approval = self.pre_native_approval_fixture()
        foreign = self.root / 'foreign-maps'
        foreign.write_bytes((fixture.root / 'process-maps').read_bytes())
        self.rewrite_producer(candidate, approval, 'isolation_receipt',
            lambda document: document.update(maps=CONTROL.ORACLES.reference(foreign)))
        self.assert_inventory_rejected(candidate, approval, fixture.row)

    def test_pre_native_mutated_transitive_control_bytes_cannot_publish(self):
        fixture, candidate, approval = self.pre_native_approval_fixture()
        (fixture.root / 'before-process').write_text('changed after explicit review')
        with self.assertRaises(ValueError):
            CONTROL.approved_packet(candidate, approval, fixture.row, self.root / 'reviewed.json')
        self.assertFalse((self.root / 'reviewed.json').exists())

    def test_top_level_reference_bait_cannot_hide_uninventoried_nested_producer(self):
        row, candidate, approval, path = self.approval_fixture()
        allowed = approval['packet']['measurement_evidence'][0]
        approval['packet'].update(path=allowed['path'], sha256=allowed['sha256'])
        foreign = self.write('foreign-manifest.json', {'parent_sha': 'control-parent'})
        source = next(ref for ref in approval['packet']['measurement_evidence'] if ref['role'] == 'source_manifest')
        source.update(CONTROL.ORACLES.reference(foreign))
        path.write_text(json.dumps(approval))
        self.assert_inventory_rejected(candidate, path, row)

    def test_reference_shaped_producer_bait_does_not_hide_transitive_reference(self):
        row, candidate, approval, _ = self.config_dependency_fixture(False)
        permitted = json.loads(candidate.read_text())['role_evidence'][0]
        self.rewrite_producer(candidate, approval, 'source_manifest',
            lambda document: document.update(path=permitted['path'], sha256=permitted['sha256']))
        self.assert_inventory_rejected(candidate, approval, row)

    def test_oracle_review_cannot_read_an_uninventoried_physical_source(self):
        row, candidate, approval, path = self.approval_fixture()
        foreign = self.write('foreign-oracle-source.json', {'independent_source': 'not explicitly reviewed'})
        approval['oracle_review'] = {'proof': [CONTROL.ORACLES.reference(foreign)]}
        path.write_text(json.dumps(approval))
        self.assert_inventory_rejected(candidate, path, row)

    def test_configuration_unparsed_source_bytes_do_not_gain_a_json_requirement(self):
        row, candidate_path, approval, approval_path = self.approval_fixture()
        candidate = json.loads(candidate_path.read_text())
        for role in ('isolation_receipt', 'expectation_source'):
            producer = next(ref for ref in approval['packet']['measurement_evidence'] if ref['role'] == role)
            Path(producer['path']).write_text(role + ': independent physical text without nested references')
            ref = CONTROL.ORACLES.reference(Path(producer['path']))
            producer.update(ref)
            next(item for item in candidate['role_evidence'] if item['role'] == role).update(ref)
        candidate_path.write_text(json.dumps(candidate))
        approval['candidate'] = CONTROL.ORACLES.reference(candidate_path)
        approval_path.write_text(json.dumps(approval))
        result = CONTROL.approved_packet(candidate_path, approval_path, row, self.root / 'reviewed.json')
        self.assertEqual(result['qualification_scope'], 'configuration_control')

    def test_control_oracle_review_excludes_each_indirect_witness_branch(self):
        row, candidate, approval, path = self.approval_fixture()
        for branch in ('retest', 'applicability_receipt', 'expected_absence',
                       'expected_absence_approval', 'visible_status_absence'):
            with self.subTest(branch=branch):
                # Even a physically inventoried root receipt cannot authorize an
                # out-of-scope nested measurement/capability/witness file graph.
                allowed = approval['packet']['measurement_evidence'][0]
                approval['oracle_review'] = {branch: allowed}
                path.write_text(json.dumps(approval))
                with self.assertRaisesRegex(ValueError, 'excludes Oracle retest, applicability and absence'):
                    CONTROL.approved_packet(candidate, path, row, self.root / 'reviewed.json')
                self.assertFalse((self.root / 'reviewed.json').exists())

    def test_oracle_branch_exclusion_survives_wrapper_bait_and_nested_effective_oracle(self):
        row, candidate, approval, path = self.approval_fixture()
        allowed = approval['packet']['measurement_evidence'][0]
        for branch in ('retest', 'applicability_receipt', 'expected_absence', 'expected_absence_approval'):
            with self.subTest(branch=branch):
                approval['oracle_review'] = {**allowed, 'approved_correction': {
                    'expected_oracle': {branch: None}}}
                path.write_text(json.dumps(approval))
                with self.assertRaisesRegex(ValueError, 'excludes Oracle retest, applicability and absence'):
                    CONTROL.approved_packet(candidate, path, row, self.root / 'reviewed.json')
                self.assertFalse((self.root / 'reviewed.json').exists())

    def test_unsupported_capability_category_has_no_control_import_path(self):
        row, candidate, approval, path = self.approval_fixture()
        approval['oracle_review'] = {'category': 'UNSUPPORTED_CAPABILITY'}
        path.write_text(json.dumps(approval))
        with self.assertRaisesRegex(ValueError, 'excludes Oracle retest, applicability and absence'):
            CONTROL.approved_packet(candidate, path, row, self.root / 'reviewed.json')
        self.assertFalse((self.root / 'reviewed.json').exists())

    def test_plain_source_confirmed_oracle_review_still_uses_shared_contract(self):
        row, candidate, approval, path = self.approval_fixture()
        source = next(ref for ref in approval['packet']['measurement_evidence'] if ref['role'] == 'expectation_source')
        approval['oracle_review'] = {'category': 'SOURCE_CONFIRMED_EXPECTATION', 'reviewed_by': 'root',
            'leg_id': 'apache-native', 'interpretation': 'Synthetic source confirms original parser acceptance',
            'scope': 'Only the original valid_rules_file parser contract', 'independent_sources': [source]}
        path.write_text(json.dumps(approval))
        result = CONTROL.approved_packet(candidate, path, row, self.root / 'reviewed.json')
        self.assertEqual(result['qualification_scope'], 'configuration_control')



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == '__main__':
    unittest.main()
