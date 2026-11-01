"""Mutation controls for exact original membership and source-only proposals."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
validator = load_source(HERE / 'validate_oracles.py')


def _private_fixture_root() -> Path:
    from modsecurity_connector_ci.lib.active_test_inventory import validate_output_root

    declared = os.environ.get("I12_TEST_ROOT") or os.environ.get("RUNNER_TEMP")
    if not declared:
        raise RuntimeError("I12_TEST_ROOT or RUNNER_TEMP must name existing private storage")
    return validate_output_root(connector_root(), Path(declared))


class OracleValidationControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix='envoy-oracle-controls-',
            dir=_private_fixture_root())
        self.root = Path(self.temporary.name)
        storage = patch.object(validator, 'STORAGE_ROOTS', (self.root,))
        storage.start()
        self.addCleanup(storage.stop)
        self.source = self.root / 'source.txt'
        self.source.write_text('symbol boundary\nsecond line\n')
        self.reference = {'path': str(self.source),
            'sha256': hashlib.sha256(self.source.read_bytes()).hexdigest(),
            'line': 1, 'symbol': 'boundary', 'claim': 'Independent fixture source boundary.'}
        self.baseline = {'rows': []}
        self.documents = []
        oracle = {'visible_status': None, 'physical_evidence_not_projection': True}
        for index, (route, (total, selected)) in enumerate(validator.ROUTES.items()):
            records = []
            for number in range(total):
                identity = f'I12::{route}::case-{number}'
                existing = number == 0
                original = {'run_scoped_case_id': identity, 'leg_id': route,
                    'original_oracle_member': number < selected,
                    'original_oracle': copy.deepcopy(oracle),
                    'qualified_host_lifecycle_pass': existing,
                    'oracle_review': {'resolved': existing}}
                self.baseline['rows'].append(original)
                if number < selected:
                    records.append({'run_scoped_case_id': identity, 'route': route,
                        'category': 'FIXTURE_PENDING', 'original_oracle': copy.deepcopy(oracle),
                        'source_refs': [copy.deepcopy(self.reference)], 'effective_oracle': None,
                        'fixture_binding': None, 'lifecycle_qualified': False,
                        'remaining_requirements': ['Exact host lifecycle packet remains required.']})
            row = records[1]
            row.update(category='SOURCE_SEMANTICS_CONFIRMED', effective_oracle={'visible_status': 200},
                fixture_binding={'origin': 'new_task_fixture_binding',
                    'original_id': row['run_scoped_case_id'], 'files': [copy.deepcopy(self.reference)]})
            key = 'records' if index == 0 else 'rows'
            self.documents.append({'route': route, key: records})
        self.paths = [self.root / f'review-{number}.json' for number in range(3)]
        self.write_reviews()

    def tearDown(self):
        self.temporary.cleanup()

    def rows(self, index=0):
        document = self.documents[index]
        return document.get('records', document.get('rows'))

    def write_reviews(self):
        for path, document in zip(self.paths, self.documents):
            path.write_text(json.dumps(document))

    def reject(self, pattern):
        self.write_reviews()
        with self.assertRaisesRegex(ValueError, pattern):
            validator.validate(self.baseline, self.paths)

    def test_normalization_preserves_canonical_inventory_and_separates_proposals(self):
        result = validator.validate(self.baseline, self.paths)
        self.assertEqual((result['original_count'], result['reviewed_count']), (125, 125))
        self.assertEqual((result['canonical_resolved'], result['canonical_open']), (3, 122))
        self.assertEqual(result['proposed_new_source_oracles'], 3)
        self.assertEqual(result['new_lifecycle_pass'], 0)
        self.assertEqual(len(result['normalized_rows']), 125)
        self.assertNotIn('symbol boundary', json.dumps(result))
        self.assertTrue(all(row['lifecycle_qualified'] is False for row in result['normalized_rows']))

    def test_changed_original_id_is_rejected(self):
        self.rows()[0]['run_scoped_case_id'] += '-invented'
        self.reject('membership differs')

    def test_changed_original_oracle_is_rejected(self):
        self.rows()[0]['original_oracle']['visible_status'] = 403
        self.reject('original oracle changed')

    def test_boolean_to_integer_oracle_change_is_not_equal(self):
        self.rows()[0]['original_oracle']['physical_evidence_not_projection'] = 1
        self.reject('original oracle changed')

    def test_row_route_change_is_rejected(self):
        self.rows()[0]['route'] = 'envoy-ext-authz-request'
        self.reject('route membership differs')

    def test_duplicate_original_id_is_rejected(self):
        self.rows().append(copy.deepcopy(self.rows()[0]))
        self.reject('duplicate reviewed original ID')

    def test_missing_route_review_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'all three complete route reviews'):
            validator.validate(self.baseline, self.paths[:2])

    def test_changed_physical_reference_is_rejected_on_fresh_validation(self):
        validator.validate(self.baseline, self.paths)
        self.source.write_text('changed physical bytes\n')
        with self.assertRaisesRegex(ValueError, 'reference SHA256 mismatch'):
            validator.validate(self.baseline, self.paths)

    def test_historical_source_root_verifies_relative_review_references(self):
        archive = self.root / 'historical-source'
        source = archive / 'common/runtime/source.c'
        source.parent.mkdir(parents=True)
        source.write_text('historical symbol\n')
        ref = {'path': 'common/runtime/source.c',
            'sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
            'line': 1, 'symbol': 'historical', 'claim': 'Pinned historical source.'}
        checked = validator.References(archive).check(ref, source=True)
        self.assertEqual(checked['sha256'], ref['sha256'])
        source.write_text('changed\n')
        historical_references = validator.References(archive)
        with self.assertRaisesRegex(ValueError, 'reference SHA256 mismatch'):
            historical_references.check(ref, source=True)
        relative_references = validator.References(Path('relative'))
        with self.assertRaisesRegex(ValueError, 'historical source root'):
            relative_references.check(ref, source=True)

    def test_nested_independent_source_hash_is_verified(self):
        bad = copy.deepcopy(self.reference)
        bad['sha256'] = '0' * 64
        self.rows()[0]['fixture_binding'] = {'origin': 'existing_original_fixture_binding',
            'independent_sources': [bad]}
        self.reject('reference SHA256 mismatch')

    def test_false_lifecycle_claim_and_missing_flag_are_rejected(self):
        for value in (True, None, 0):
            with self.subTest(value=value):
                self.rows()[0]['lifecycle_qualified'] = value
                self.reject('lifecycle_qualified must be explicitly false')

    def test_explicit_host_pass_cannot_hide_behind_false_lifecycle_flag(self):
        self.rows()[0]['outcome'] = 'PASS'
        self.reject('cannot assign host PASS')

    def test_source_line_bounds_and_private_reference_paths_are_enforced(self):
        self.rows()[0]['source_refs'][0]['line'] = 99999
        self.reject('source reference line outside file')
        self.rows()[0]['source_refs'][0]['line'] = 1
        self.rows()[0]['source_refs'][0]['path'] = '/etc/hosts'
        self.reject('outside approved storage')

    def test_source_boundary_category_is_not_counted_as_ready_oracle(self):
        row = self.rows()[2]
        row.update(category='SOURCE_SEMANTICS_CONFIRMED', source_oracle_resolved=False)
        self.write_reviews()
        result = validator.validate(self.baseline, self.paths)
        route = result['routes'][self.documents[0]['route']]
        self.assertEqual(route['proposed_new_source_oracles'], 1)
        self.assertEqual(route['source_boundary_only_ids'], [row['run_scoped_case_id']])

    def test_new_binding_must_name_the_same_original_id(self):
        self.rows()[1]['fixture_binding']['original_id'] += '-other'
        self.reject('fixture binding names a different original ID')

    def test_proposed_oracle_requires_new_explicit_fixture_binding(self):
        self.rows()[1]['fixture_binding'] = None
        self.reject('lacks an explicit new fixture binding')

    def physical_ref(self, path):
        raw = path.read_bytes()
        return {'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}

    def supplement_fixture(self):
        fixture = self.root / 'new-fixture'
        fixture.mkdir()
        shape = fixture / 'shape.json'
        shape.write_text(json.dumps({'leg': validator.SUPPLEMENT_ROUTE}))
        rules = fixture / 'native.rules'
        rules.write_text('SecRuleEngine On\n')
        ledger = self.root / 'new-fixture-ledger.json'
        ledger.write_text(json.dumps({'files': {path.name: self.physical_ref(path)['sha256']
                                               for path in (shape, rules)}}))
        admission = self.root / 'new-fixture-admission.json'
        admission.write_text(json.dumps({'bindings': [{'target': '/mnt/fixtures', 'source': str(fixture),
            'ledger': str(ledger), 'ledger_sha256': self.physical_ref(ledger)['sha256']}]}))
        return [self.physical_ref(path) for path in (shape, rules, ledger, admission)]

    def prepare_supplement(self):
        original_row = self.rows(2)[1]
        old_id = original_row['run_scoped_case_id']
        original_row['run_scoped_case_id'] = validator.SUPPLEMENT_ID
        original_row['fixture_binding']['original_id'] = validator.SUPPLEMENT_ID
        for row in self.baseline['rows']:
            if row['run_scoped_case_id'] == old_id:
                row['run_scoped_case_id'] = validator.SUPPLEMENT_ID
        self.write_reviews()
        self.validated = validator.validate(self.baseline, self.paths)
        row = copy.deepcopy(original_row)
        row['fixture_binding'] = {'origin': 'new_task_fixture_binding', 'original_id': validator.SUPPLEMENT_ID,
                                 'files': self.supplement_fixture()}
        self.supplement = {'schema': validator.SUPPLEMENT_SCHEMA, 'route': validator.SUPPLEMENT_ROUTE,
                           'origin_review': self.physical_ref(self.paths[2]), 'rows': [row]}
        self.supplement_path = self.root / 'supplement.json'
        return row

    def write_supplement(self):
        self.supplement_path.write_text(json.dumps(self.supplement))

    def reject_supplement(self, message):
        self.write_supplement()
        with self.assertRaisesRegex(ValueError, message):
            validator.validate_supplement(self.supplement_path, self.validated)

    def test_supplement_preserves_source_and_only_rebinds_physical_fixture(self):
        self.prepare_supplement()
        self.write_supplement()
        result = validator.validate_supplement(self.supplement_path, self.validated)
        self.assertEqual(result['original_id'], validator.SUPPLEMENT_ID)
        self.assertEqual(result['new_lifecycle_pass'], 0)
        self.assertIs(result['canonical_resolution_changed'], False)
        self.assertEqual(result['review_file'], self.physical_ref(self.supplement_path))
        self.assertEqual(result['origin_review'], self.physical_ref(self.paths[2]))
        self.assertEqual(len(result['normalized_rows']), 1)
        self.assertTrue(result['normalized_rows'][0]['source_refs'][0]['verified'])
        self.assertEqual(result['normalized_rows'][0]['source_refs'][0]['bytes'], self.source.stat().st_size)

    def test_supplement_rejects_unknown_original_and_duplicate_rows(self):
        row = self.prepare_supplement()
        row['run_scoped_case_id'] += '-unknown'
        self.reject_supplement('original ID or route is not selected')
        row['run_scoped_case_id'] = validator.SUPPLEMENT_ID
        self.supplement['rows'].append(copy.deepcopy(row))
        self.reject_supplement('exactly one original row')

    def test_supplement_rejects_changed_original(self):
        row = self.prepare_supplement()
        row['original_oracle']['visible_status'] = 403
        self.reject_supplement('original oracle changed')

    def test_supplement_rejects_changed_effective_source_oracle(self):
        row = self.prepare_supplement()
        row['effective_oracle']['visible_status'] = 403
        self.reject_supplement('changed source semantics: effective_source_proposal')

    def test_supplement_rejects_changed_source_claim_and_reference_size(self):
        row = self.prepare_supplement()
        row['source_refs'][0]['claim'] += ' changed'
        self.reject_supplement('changed source semantics: source_refs')
        row['source_refs'][0] = copy.deepcopy(self.reference)
        row['source_refs'][0]['bytes'] = self.source.stat().st_size + 1
        self.reject_supplement('reference byte size mismatch')

    def test_supplement_origin_must_match_normalized_and_physical_review(self):
        self.prepare_supplement()
        self.supplement['origin_review']['path'] = str(self.paths[0])
        self.reject_supplement('origin differs from normalized')
        self.supplement['origin_review'] = self.physical_ref(self.paths[2])
        self.supplement['origin_review']['sha256'] = '0' * 64
        self.reject_supplement('origin differs from validated input')
        self.supplement['origin_review'] = self.physical_ref(self.paths[2])
        self.supplement['origin_review']['bytes'] += 1
        self.reject_supplement('origin physical identity mismatch')

    def test_supplement_cannot_invent_row_or_document_host_pass(self):
        row = self.prepare_supplement()
        row['outcome'] = 'PASS'
        self.reject_supplement('source row cannot assign host PASS')
        row.pop('outcome')
        self.supplement['new_lifecycle_pass'] = 1
        self.reject_supplement('cannot invent lifecycle PASS')

    def test_supplement_rejects_bad_fixture_hash(self):
        row = self.prepare_supplement()
        row['fixture_binding']['files'][0]['sha256'] = '0' * 64
        self.reject_supplement('reference SHA256 mismatch')

    def test_supplement_rejects_incomplete_fixture_inventory(self):
        row = self.prepare_supplement()
        row['fixture_binding']['files'].pop(1)
        self.reject_supplement('ledger member missing or changed')

    def test_supplement_rejects_admission_rebinding_after_validated_hash(self):
        row = self.prepare_supplement()
        admission = self.root / 'new-fixture-admission.json'
        document = json.loads(admission.read_text())
        document['bindings'][0]['source'] = str(self.root / 'other-fixture')
        admission.write_text(json.dumps(document))
        row['fixture_binding']['files'][-1] = self.physical_ref(admission)
        self.reject_supplement('admission fixture binding differs')

    def test_supplement_requires_fresh_validated_origin(self):
        self.prepare_supplement()
        self.paths[2].write_text(self.paths[2].read_text() + '\n')
        self.reject_supplement('origin physical identity mismatch')



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == '__main__':
    unittest.main()
