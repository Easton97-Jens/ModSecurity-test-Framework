"""Source-bound absence reviews never fabricate runtime observations."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = connector_root()
ORACLES = load_source(source_path('ci/evidence/reports/generate-pr382-i12-oracle-reconciliation.py', root=ROOT))


class TraefikAbsenceOracleControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='absence-')
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.sources = []
        for name, kind in (('host', 'official_host_contract'), ('protocol', 'protocol_contract')):
            path = root / (name + '.txt')
            path.write_text('Synthetic independent ' + name + ' absence contract.\n')
            self.sources.append({**ORACLES.reference(path), 'kind': kind, 'revision': 'synthetic-control-1'})
        original = {'native_result': None, 'visible_status': None, 'phase': None,
                    'rule_id': None, 'physical_evidence_not_projection': True,
                    'unresolved_expected_value_reason': 'Synthetic unresolved contract'}
        identity = 'I12::traefik-native-uds::NEED-commit-ack-applied'
        self.row = {'run_scoped_case_id': identity, 'leg_id': 'traefik-native-uds',
                    'selected_requirement': {'case_id': 'NEED-commit-ack-applied',
                        'run_scoped_case_id': identity, 'expected_oracle': original}}
        effective = dict(original, native_result='technical_error', phase=1,
                         unresolved_expected_value_reason=None)
        self.record = {'run_scoped_case_id': identity, 'leg_id': self.row['leg_id'],
            'reviewed_by': 'root', 'category': 'HOST_SEMANTICS_CONFIRMED',
            'interpretation': 'Synthetic protocol failure before any complete HTTP status line.',
            'scope': 'Only this exact source-bound synthetic fixture.',
            'independent_sources': self.sources, 'resolved_expectation': effective,
            'expected_absence': {'schema_version': 1, 'reviewed_by': 'root',
                'run_scoped_case_id': identity, 'leg_id': self.row['leg_id'],
                'selected_requirement_sha256': ORACLES.canonical_digest(self.row['selected_requirement']),
                'original_oracle_sha256': ORACLES.canonical_digest(original),
                'fields': {'visible_status': {'kind': 'no_http_response',
                    'reason': 'Synthetic fixture aborts before a complete HTTP status line.',
                    'proof': copy.deepcopy(self.sources)}}}}

    def review(self):
        return ORACLES.review_record(self.record, self.row)

    def test_known_source_absence_keeps_literal_null_and_does_not_qualify_execution(self):
        reviewed = self.review()
        self.assertTrue(reviewed['resolved'])
        self.assertIsNone(reviewed['effective_oracle']['visible_status'])
        self.assertEqual(reviewed['expected_absence']['fields']['visible_status']['kind'], 'no_http_response')
        self.assertFalse(reviewed['full_lifecycle_qualified'])
        self.assertIsNone(reviewed['retest'])
        self.assertIsNone(self.row['selected_requirement']['expected_oracle']['phase'])

    def test_no_allocation_expectation_preserves_absent_native_result_and_phase(self):
        self.record['resolved_expectation'].update(native_result=None, phase=None, visible_status=400)
        fields = self.record['expected_absence']['fields']
        source = fields.pop('visible_status')
        fields.update({field: dict(source, kind=kind) for field, kind in
                       (('native_result', 'no_native_decision'), ('phase', 'no_native_phase'))})
        reviewed = self.review()
        self.assertIsNone(reviewed['effective_oracle']['phase'])
        self.assertIsNone(reviewed['effective_oracle']['native_result'])
        self.assertEqual(reviewed['effective_oracle']['visible_status'], 400)

    def test_missing_absence_or_proof_is_rejected(self):
        original = copy.deepcopy(self.record)
        mutations = (
            lambda: self.record.pop('expected_absence'),
            lambda: self.record['expected_absence']['fields'].clear(),
            lambda: self.record['expected_absence']['fields']['visible_status']['proof'].clear(),
            lambda: self.record['expected_absence']['fields']['visible_status'].update(reason=''),
            lambda: self.record['expected_absence']['fields']['visible_status'].update(kind='EOF_means_success'),
            lambda: self.record['expected_absence'].update(reviewed_by='worker'),
            lambda: self.record['resolved_expectation'].pop('visible_status'),
            lambda: self.record['resolved_expectation'].update(visible_status=200),
        )
        for mutate in mutations:
            self.record = copy.deepcopy(original)
            mutate()
            with self.assertRaises(ValueError):
                self.review()

    def test_cross_case_profile_stale_contract_and_tampered_source_rejected(self):
        original = copy.deepcopy(self.record)
        for key, value in (('run_scoped_case_id', 'I12::traefik-native-uds::other'),
                           ('leg_id', 'traefik-forwardauth-request'),
                           ('selected_requirement_sha256', '0' * 64),
                           ('original_oracle_sha256', '0' * 64)):
            self.record = copy.deepcopy(original)
            self.record['expected_absence'][key] = value
            with self.assertRaises(ValueError):
                self.review()
        self.record = copy.deepcopy(original)
        self.record['expected_absence']['fields']['visible_status']['proof'][0]['sha256'] = '0' * 64
        with self.assertRaises(ValueError):
            self.review()

    def test_measured_probe_cannot_be_sole_expectation_for_absence(self):
        for item in self.record['independent_sources']:
            item['kind'] = 'independent_host_probe'
        self.record['expected_absence']['fields']['visible_status']['proof'] = copy.deepcopy(
            self.record['independent_sources'])
        with self.assertRaises(ValueError):
            self.review()



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == '__main__':
    unittest.main()
