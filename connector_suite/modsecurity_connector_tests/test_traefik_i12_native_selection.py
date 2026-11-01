"""Exact execution selection must not silently expand supplementary stimuli."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock


REPO = connector_root()
MODULE = REPO / 'connectors/traefik/harness/i12/native/acceptance_plan.py'
EXTERNAL = Path(os.environ.get('CODEX_TEMP_ROOT', '/var/tmp/codex/ModSecurity-conector'))


class NativeSelectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('native_selection_plan', MODULE)
        cls.plan = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.plan)

    def setUp(self):
        EXTERNAL.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix='native-selection-', dir=EXTERNAL)
        self.addCleanup(self.temporary.cleanup)
        self.source = Path(self.temporary.name) / 'selection.json'
        self.manifest = {
            'cases': [{'id': f'id-{index}', 'key': f'key-{index}'} for index in range(118)],
            'supplementary_executions': [
                {'id': 'id-1', 'key': 'key-1-first'},
                {'id': 'id-1', 'key': 'key-1-second'},
                {'id': 'id-2', 'key': 'key-2-file'}]}

    def select(self, values, kind='keys'):
        self.source.write_text(json.dumps(values) + '\n')
        self.plan.apply_selection(self.manifest, self.source, kind)

    def test_exact_keys_do_not_expand_sibling_supplements(self):
        original = copy.deepcopy(self.manifest)
        self.select(['key-2-file', 'key-1-first', 'key-1'])
        self.assertEqual(self.manifest['selected_keys'], ['key-1', 'key-1-first', 'key-2-file'])
        self.assertEqual(self.manifest['cases'], original['cases'])
        self.assertEqual(len(self.manifest['cases']), 118)
        self.assertEqual(self.manifest['supplementary_executions'], original['supplementary_executions'])
        self.assertEqual(self.manifest['selection_source'], {
            'path': str(self.source), 'sha256': hashlib.sha256(self.source.read_bytes()).hexdigest(),
            'kind': 'keys'})

    def test_original_ids_keep_existing_supplement_expansion(self):
        self.select(['id-2', 'id-1'], kind='ids')
        self.assertEqual(self.manifest['selected_keys'],
                         ['key-1', 'key-2', 'key-1-first', 'key-1-second', 'key-2-file'])
        self.assertEqual(self.manifest['selection_source']['kind'], 'ids')

    def test_original_only_and_supplement_only_are_valid(self):
        for keys in (['key-0'], ['key-1-second']):
            with self.subTest(keys=keys):
                self.select(keys)
                self.assertEqual(self.manifest['selected_keys'], keys)

    def test_invalid_selections_fail_before_modifying_manifest(self):
        for values in ([], {}, None, 'key-0', [0], [True], [[]], [{}], [''],
                       ['key-0', 'key-0'], ['missing'], ['id-1'], ['key-0', 'missing']):
            with self.subTest(values=values):
                before = copy.deepcopy(self.manifest)
                with self.assertRaises(ValueError):
                    self.select(values)
                self.assertEqual(self.manifest, before)

    def test_keys_are_not_accepted_as_original_ids(self):
        with self.assertRaises(ValueError):
            self.select(['key-1-first'], kind='ids')

    def test_duplicate_manifest_keys_fail_closed(self):
        self.manifest['supplementary_executions'][0]['key'] = 'key-1'
        with self.assertRaisesRegex(ValueError, 'keys must be unique'):
            self.select(['key-1'])
        self.assertNotIn('selected_keys', self.manifest)

    def test_malformed_json_and_missing_source_fail_closed(self):
        self.source.write_text('["key-1"')
        with self.assertRaises(ValueError):
            self.plan.apply_selection(self.manifest, self.source, 'keys')
        missing_source = self.source.with_name('missing.json')
        with self.assertRaises(FileNotFoundError):
            self.plan.apply_selection(self.manifest, missing_source, 'keys')
        self.assertNotIn('selected_keys', self.manifest)

    def test_unknown_selection_kind_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'unknown selection kind'):
            self.select(['key-1'], kind='other')

    def test_cli_selection_flags_are_mutually_exclusive(self):
        argv = ['acceptance_plan.py', '--inventory', 'inventory.json', '--proposals', 'proposals.json',
                '--framework', 'framework', '--output', 'output.json',
                '--selected-ids', 'ids.json', '--selected-keys', 'keys.json']
        with mock.patch('sys.argv', argv), mock.patch('sys.stderr'):
            with self.assertRaises(SystemExit) as error:
                self.plan.main()
        self.assertEqual(error.exception.code, 2)

    def file_originals(self):
        return [{'id': self.plan.PREFIX + 'NEED-' + direction + '-file',
                 'key': direction, 'transaction_id': 'target-' + direction,
                 'neighbor_id': 'neighbor-' + direction, 'positive_control_id': 'positive-' + direction,
                 'main_before_id': 'before-' + direction, 'main_after_id': 'after-' + direction,
                 'readiness_ids': ['ready-' + direction], 'fixture': self.plan.default_fixture() |
                 {'rules_lines': ['SecRuleEngine On']}}
                for direction in ('request', 'response')]

    def test_file_supplements_bind_frozen_marker_rules_without_qualifying_originals(self):
        originals = self.file_originals()
        before = copy.deepcopy(originals)
        supplements = self.plan.file_supplements(originals)
        self.assertEqual(originals, before)
        self.assertEqual(len(supplements), 4)
        source = REPO / 'connectors/traefik/harness/i12_file/acceptance.py'
        contract = load_source(source)
        declarations = {(row['id'], row['file_spec']['relative_path']): row for row in contract.cases()}
        for case in supplements:
            fixture = case['fixture']
            file = fixture['file_supplement']
            declared = declarations[case['id'], file['fixture']]
            self.assertEqual(fixture['rules_lines'], declared['rules_lines'])
            self.assertEqual(file['rules_sha256'], declared['rules_sha256'])
            self.assertEqual(file['rules_sha256'], hashlib.sha256(
                ('\n'.join(fixture['rules_lines']) + '\n').encode()).hexdigest())
            self.assertEqual(file['rules_source_sha256'], hashlib.sha256(source.read_bytes()).hexdigest())
            self.assertEqual(file['file_spec']['sha256'], declared['file_spec']['sha256'])
            self.assertEqual(fixture['policy']['phase4_mode'], 'safe')
            self.assertEqual(fixture['request']['headers'], [['Content-Type', 'text/plain']])
            self.assertEqual(bytes.fromhex(fixture['backend']['body_hex']), contract.BACKEND_BODY)
            self.assertFalse(file['native_file_api'])
            self.assertFalse(file['backend_exclusion_expected'])
            self.assertIn('configuration negative', file['strict_scope'])
            self.assertIsNone(case['expected'])
            self.assertFalse(case['expected_approval'])
            self.assertEqual(case['fixture_sha256'], self.plan.json_digest(fixture))

    def test_file_supplements_reject_changed_fixture_or_manifest_digest(self):
        harness = Path(self.temporary.name) / 'harness'
        for directory in ('i12_file', 'fixtures/i12-file-source'):
            shutil.copytree(REPO / 'connectors/traefik/harness' / directory, harness / directory)
        mocked_source = harness / 'i12/native/acceptance_plan.py'
        fixture = harness / 'fixtures/i12-file-source/request-marker.txt'
        original_bytes = fixture.read_bytes()
        original_cases = self.file_originals()
        with mock.patch.object(self.plan, '__file__', str(mocked_source)):
            fixture.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'exact physical file fixture'):
                self.plan.file_supplements(original_cases)
            fixture.write_bytes(original_bytes)
            manifest_path = fixture.parent / 'manifest.json'
            manifest = json.loads(manifest_path.read_text())
            manifest['files'][1]['sha256'] = '0' * 64
            manifest_path.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, 'exact physical file fixture'):
                self.plan.file_supplements(original_cases)
            manifest['files'][1]['sha256'] = hashlib.sha256(original_bytes).hexdigest()
            manifest['files'][1]['read_size'] = 25
            manifest_path.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, 'exact physical file fixture'):
                self.plan.file_supplements(original_cases)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == '__main__':
    unittest.main()
