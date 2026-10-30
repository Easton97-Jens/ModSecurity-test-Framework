"""Packaging must preserve original/null contracts and reject invented PASS."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from functools import partial


PATH = connector_root() / "ci/runtime/lifecycle/apache-i12/package.py"
PACKAGE = load_source(PATH)
CONTROLS = load_source(PATH.parents[4] / 'tests/test_i12_lifecycle_ledger.py')


class PackagingTest(unittest.TestCase):
    def setUp(self):
        root = Path(os.environ.get("CODEX_TEST_TMP_ROOT", "/var/tmp/codex/ModSecurity-conector/runs/i12-apache-410-20261015/package-tests"))
        root.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=root)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        unknown = {role: {"value": None, "reason": "No fresh physical packet."} for role in PACKAGE.ROLES}
        rows = []
        for number in range(155):
            identity = "I12::apache-native::fixture-" + str(number)
            oracle = {"visible_status": None, "unresolved_expected_value_reason": "No independently reviewed expectation."}
            rows.append({"run_scoped_case_id": identity, "leg_id": "apache-native", "required_leg": True,
                "selected_requirement": {"run_scoped_case_id": identity, "expected_oracle": copy.deepcopy(oracle)},
                "original_oracle": copy.deepcopy(oracle),
                "historical_result": {"status": "PASS" if number == 0 else "NOT_EXECUTED_UNQUALIFIED",
                    "execution_observed": number == 0,
                    "qualification_scope": "historical_configuration_only" if number == 0 else None},
                "oracle_reconciliation": None, "fresh_packet": None, "fresh_observations": copy.deepcopy(unknown),
                "fresh_execution_observed": False, "fresh_full_lifecycle_qualified": False,
                "fresh_outcome": None, "fresh_qualified_pass": False})
        self.source = {"scope": "apache-native", "rows": rows,
            "original_ordered_id_sha256": PACKAGE.ORACLES.ID_SHA256,
            "original_selected_contract_sha256": PACKAGE.ORACLES.CONTRACT_SHA256,
            "summary": {"original_open_oracle_subset": 155, "resolved_original_oracles": 0, "unresolved_original_oracles": 155}}
        self.source_path = self.root / "ledger.json"
        self.write("candidate-index.json", [])
        self.write("sink-readback.json", {"cases": []})

    def write(self, name, value):
        path = self.root / name
        path.write_text(json.dumps(value))
        return path

    def package(self):
        self.source_path.write_text(json.dumps(self.source))
        return PACKAGE.package(self.source_path, self.root)

    def test_original_oracle_and_null_roles_survive_without_config_promotion(self):
        result = self.package()
        self.assertEqual(len(result["rows"]), 155)
        self.assertEqual(result["summary"]["fresh_full_lifecycle_pass"], 0)
        row = result["rows"][0]
        self.assertTrue(row["historical"]["configuration_pass"])
        self.assertEqual(row["fresh"]["qualification"], "NOT_EXECUTED")
        self.assertEqual(row["selected_requirement"], self.source["rows"][0]["selected_requirement"])
        self.assertEqual(row["original_oracle"], self.source["rows"][0]["original_oracle"])
        self.assertEqual(row["fresh"]["observations"], self.source["rows"][0]["fresh_observations"])
        self.assertEqual(result["source_full_ledger"], PACKAGE.ref(self.source_path))

    def test_no_accepted_packet_cannot_claim_full_pass(self):
        self.source["rows"][0]["fresh_qualified_pass"] = True
        with self.assertRaisesRegex(ValueError, "no fresh qualification"):
            self.package()

    def test_unsigned_candidate_stays_partial_even_when_it_claims_pass(self):
        row = self.source["rows"][0]
        candidate = self.write("candidate.json", {"run_scoped_case_id": row["run_scoped_case_id"],
            "execution_observed": True, "reviewed_by": None, "full_lifecycle_qualified": True,
            "outcome": "PASS", "observations": row["fresh_observations"]})
        self.write("candidate-index.json", [{"case_id": row["run_scoped_case_id"], "candidate": PACKAGE.ref(candidate)}])
        result = self.package()
        fresh = result["rows"][0]["fresh"]
        self.assertTrue(fresh["execution_observed"])
        self.assertEqual(fresh["qualification"], "PARTIAL_HOST_MEASUREMENTS")
        self.assertIsNone(fresh["outcome"])
        self.assertFalse(fresh["qualified_pass"])
        self.assertIsNone(fresh["accepted_packet"])

    def test_packet_lookup_uses_supplied_reference_without_overwriting_acceptance(self):
        first = self.write("first.json", {"run_scoped_case_id": "first"})
        second = self.write("second.json", {"run_scoped_case_id": "second"})
        work = PACKAGE.ApachePackage(None, None, None, None)
        work.packets = {}
        work.supplied = PACKAGE.ref(first)
        work.receipt = None
        work.packet = None
        supplied = PACKAGE.ref(second)
        receipt, packet = work.packet_reference(supplied)
        self.assertEqual(receipt, supplied)
        self.assertEqual(packet["run_scoped_case_id"], "second")
        self.assertIsNone(work.receipt)
        self.assertIsNone(work.packet)

    def test_known_values_reference_exact_packet_without_replacing_nulls(self):
        observations = copy.deepcopy(self.source["rows"][0]["fresh_observations"])
        observations["client_exit"] = {"value": 0, "evidence": []}
        receipt = {"path": "/physical/packet.json", "sha256": "fixture-digest"}
        result = PACKAGE.compact_observations(observations, receipt)
        self.assertEqual(result["client_exit"]["observed_value_reference"],
                         {"packet_sha256": "fixture-digest", "json_pointer": "/observations/client_exit"})
        self.assertIsNone(result["backend_request_count"]["value"])

    def test_mutated_reference_and_foreign_id_rejected(self):
        candidate = self.write("candidate.json", {})
        receipt = PACKAGE.ref(candidate)
        candidate.write_text("changed")
        self.write("candidate-index.json", [{"case_id": self.source["rows"][0]["run_scoped_case_id"], "candidate": receipt}])
        with self.assertRaisesRegex(ValueError, "SHA256"):
            self.package()
        self.write("candidate-index.json", [{"case_id": "I12::nginx-native::foreign", "candidate": None}])
        with self.assertRaisesRegex(ValueError, "foreign"):
            self.package()

    def accepted_control(self, scope):
        row = self.source['rows'][0]
        if scope == 'configuration_control':
            control_row, packet, oracle = CONTROLS.configuration_control(self.root)
            identity = 'I12::apache-native::valid_rules_file'
            control_row.update(run_scoped_case_id=identity, leg_id='apache-native')
            control_row['selected_requirement']['run_scoped_case_id'] = identity
            packet.update(run_scoped_case_id=identity, leg_id='apache-native')
            process_ref = next(item for item in packet['measurement_evidence'] if item['role'] == 'parser_process')
            process_path = Path(process_ref['path'])
            process = json.loads(process_path.read_text())
            process.update(run_scoped_case_id=identity, leg_id='apache-native')
            process_path.write_text(json.dumps(process))
            process_ref.update(PACKAGE.ref(process_path))
            packet_path = self.write('accepted.json', packet)
            reviewer = PACKAGE.LEDGER.SHARED.reviewed_configuration_packet
        else:
            fixture = CONTROLS.PreNativeRejectionTests()
            temporary_directory = tempfile.TemporaryDirectory
            with mock.patch.object(CONTROLS.tempfile, 'TemporaryDirectory', partial(temporary_directory, dir=self.root)):
                fixture.setUp()
            self.addCleanup(fixture.doCleanups)
            receipt = fixture.bind()
            packet_path = Path(receipt['path'])
            control_row, oracle = fixture.row, fixture.oracle
            reviewer = PACKAGE.LEDGER.SHARED.reviewed_pre_native_packet
        row.update(run_scoped_case_id=control_row['run_scoped_case_id'],
                   selected_requirement=copy.deepcopy(control_row['selected_requirement']),
                   original_oracle=copy.deepcopy(oracle))
        validated = reviewer(PACKAGE.ref(packet_path), row, oracle)
        row.update({'fresh_packet': copy.deepcopy(validated), 'fresh_execution_observed': True,
                    'fresh_observations': copy.deepcopy(validated['observations']),
                    'fresh_qualification_scope': scope, 'fresh_case_qualified': True,
                    'fresh_case_outcome': 'PASS', 'fresh_case_qualified_pass': True})
        return row, validated

    def test_reviewed_controls_keep_separate_scope_and_null_lifecycle(self):
        for scope, validator, label in (
                ('configuration_control', 'reviewed_configuration_packet', 'configuration'),
                ('host_pre_native_rejection', 'reviewed_pre_native_packet', 'pre_native')):
            with self.subTest(scope=scope):
                row, validated = self.accepted_control(scope)
                result = self.package()
                fresh = result['rows'][0]['fresh']
                self.assertEqual(fresh['qualification_scope'], scope)
                self.assertEqual(fresh['qualification'], scope.upper())
                self.assertEqual(fresh['case_outcome'], 'PASS')
                self.assertTrue(fresh['case_qualified_pass'])
                self.assertFalse(fresh['full_lifecycle_qualified'])
                self.assertFalse(fresh['qualified_pass'])
                self.assertIsNone(fresh['outcome'])
                if scope == 'configuration_control':
                    packet = json.loads(Path(validated['receipt']['path']).read_text())
                    self.assertEqual(set(fresh['observations']), set(packet['actual_observations']))
                    for name, value in fresh['observations'].items():
                        pointer = value['observed_value_reference']
                        self.assertEqual(pointer['packet_sha256'], validated['receipt']['sha256'])
                        self.assertEqual(pointer['json_pointer'], '/actual_observations/' + name)
                        self.assertEqual(packet['actual_observations'][name], row['fresh_observations'][name])
                else:
                    observed = fresh['observations']
                    self.assertEqual(set(observed), set(validated['observations']))
                    for name, role in (('client_process', 'client_process'), ('client', 'client_receipt')):
                        pointer = observed[name]['observed_value_reference']
                        self.assertEqual(pointer['json_pointer'], '')
                        self.assertEqual(pointer['producer_reference']['role'], role)
                        self.assertEqual(json.loads(Path(pointer['producer_reference']['path']).read_text()),
                                         validated['observations'][name])
                    self.assertIsNone(observed['main_native_transaction_id']['value'])
                    self.assertFalse(observed['main_native_allocation']['value'])
                    binding = observed['main_native_api_calls']['validated_derivation']
                    self.assertEqual(binding['packet_sha256'], validated['receipt']['sha256'])
                    self.assertEqual({ref['role'] for ref in binding['measurement_evidence']},
                                     {'native_api', 'client_receipt', 'host_callback'})
                self.assertEqual(result['summary'][f'fresh_{label}_pass'], 1)
                self.assertEqual(result['summary']['fresh_full_lifecycle_pass'], 0)
                self.assertEqual(result['summary']['fresh_partial_ids'], 0)
                self.assertEqual(result['summary']['missing_fresh_case_qualification'], 154)

    def test_control_adapter_mutations_cannot_promote_or_change_observations(self):
        mutations = (
            ('fresh_case_outcome', 'FAIL'), ('fresh_qualification_scope', 'full_host_lifecycle'),
            ('fresh_case_qualified', False), ('fresh_case_qualified_pass', False),
            ('fresh_outcome', 'PASS'), ('fresh_qualified_pass', True),
            ('fresh_full_lifecycle_qualified', True), ('fresh_execution_observed', False))
        for field, value in mutations:
            with self.subTest(field=field):
                row, validated = self.accepted_control('configuration_control')
                original = copy.deepcopy(row)
                row[field] = value
                with self.assertRaisesRegex(ValueError, 'qualification'):
                    self.package()
                row.clear()
                row.update(original)
        row['fresh_observations']['parser_process']['waited_exit'] = 1
        with self.assertRaisesRegex(ValueError, 'qualification'):
            self.package()

    def test_no_packet_cannot_claim_control_scope_or_case_pass(self):
        for field, value in (('fresh_qualification_scope', 'configuration_control'),
                             ('fresh_case_qualified', True), ('fresh_case_outcome', 'PASS'),
                             ('fresh_case_qualified_pass', True)):
            with self.subTest(field=field):
                row = self.source['rows'][0]
                row[field] = value
                with self.assertRaisesRegex(ValueError, 'case qualification'):
                    self.package()
                del row[field]

    def test_unreviewed_control_candidate_cannot_supply_case_qualification(self):
        row = self.source['rows'][0]
        for scope in ('configuration_control', 'host_pre_native_rejection'):
            with self.subTest(scope=scope):
                packet = self.write('unsigned-control.json', {
                    'run_scoped_case_id': row['run_scoped_case_id'],
                    'execution_observed': True, 'qualification_scope': scope,
                    'full_case_qualified': True, 'outcome': 'PASS',
                    'observations': row['fresh_observations']})
                self.write('candidate-index.json', [{'case_id': row['run_scoped_case_id'],
                                                     'candidate': PACKAGE.ref(packet)}])
                result = self.package()
                fresh = result['rows'][0]['fresh']
                self.assertIsNone(fresh['qualification_scope'])
                self.assertIsNone(fresh['case_outcome'])
                self.assertFalse(fresh['case_qualified'])
                self.assertEqual(fresh['qualification'], 'PARTIAL_HOST_MEASUREMENTS')
                self.assertEqual(result['summary']['fresh_case_qualified_pass'], 0)

    def test_configuration_failure_is_counted_separately_and_packet_scope_is_bound(self):
        row, validated = self.accepted_control('configuration_control')
        validated['outcome'] = 'FAIL'
        row['fresh_packet']['outcome'] = 'FAIL'
        row['fresh_case_outcome'] = 'FAIL'
        row['fresh_case_qualified_pass'] = False
        packet_path = Path(validated['receipt']['path'])
        packet = json.loads(packet_path.read_text())
        packet['outcome'] = 'FAIL'
        packet['actual_observations']['parser_process']['waited_exit'] = 1
        process_ref = next(item for item in packet['measurement_evidence'] if item['role'] == 'parser_process')
        process_path = Path(process_ref['path'])
        process = json.loads(process_path.read_text())
        process['waited_exit'] = 1
        process_path.write_text(json.dumps(process))
        process_ref.update(PACKAGE.ref(process_path))
        packet_path.write_text(json.dumps(packet))
        row['fresh_packet']['receipt'] = PACKAGE.ref(packet_path)
        row['fresh_packet']['observations'] = copy.deepcopy(packet['actual_observations'])
        row['fresh_observations'] = copy.deepcopy(packet['actual_observations'])
        result = self.package()
        self.assertEqual(result['summary']['fresh_configuration_fail'], 1)
        self.assertEqual(result['summary']['fresh_configuration_pass'], 0)
        self.assertEqual(result['summary']['fresh_full_lifecycle_fail'], 0)
        self.assertIsNone(result['rows'][0]['fresh']['outcome'])
        row['fresh_packet']['qualification_scope'] = 'host_pre_native_rejection'
        with self.assertRaisesRegex(ValueError, 'fresh shared validation'):
            self.package()

    def test_control_compaction_rejects_changed_packet_or_derived_values(self):
        for scope, field in (('configuration_control', 'cleanup'),
                             ('host_pre_native_rejection', 'main_native_api_calls')):
            with self.subTest(scope=scope):
                row, validated = self.accepted_control(scope)
                packet = json.loads(Path(validated['receipt']['path']).read_text())
                observed = copy.deepcopy(validated['observations'])
                observed[field] = {'processes_remaining': 1} if scope == 'configuration_control' else 1
                with self.assertRaisesRegex(ValueError, 'physical|validated window'):
                    PACKAGE.compact_observations(observed, validated['receipt'], scope, packet)

    def test_pre_native_physical_producer_mutation_is_rejected(self):
        row, validated = self.accepted_control('host_pre_native_rejection')
        packet = json.loads(Path(validated['receipt']['path']).read_text())
        producer = next(item for item in packet['measurement_evidence'] if item['role'] == 'native_api')
        Path(producer['path']).write_text('changed native producer')
        with self.assertRaisesRegex(ValueError, 'SHA256'):
            self.package()

    def test_unsigned_configuration_uses_real_pointer_without_case_credit(self):
        row, validated = self.accepted_control('configuration_control')
        row.update(fresh_packet=None, fresh_execution_observed=False,
                   fresh_qualification_scope=None, fresh_case_qualified=False,
                   fresh_case_outcome=None, fresh_case_qualified_pass=False)
        packet_path = Path(validated['receipt']['path'])
        packet = json.loads(packet_path.read_text())
        packet['reviewed_by'] = None
        packet_path.write_text(json.dumps(packet))
        self.write('candidate-index.json', [{'case_id': row['run_scoped_case_id'],
                                             'candidate': PACKAGE.ref(packet_path)}])
        result = self.package()
        fresh = result['rows'][0]['fresh']
        self.assertEqual(fresh['qualification'], 'PARTIAL_HOST_MEASUREMENTS')
        self.assertIsNone(fresh['qualification_scope'])
        self.assertIsNone(fresh['case_outcome'])
        self.assertFalse(fresh['case_qualified_pass'])
        self.assertEqual(fresh['observations']['parser_process']['observed_value_reference']['json_pointer'],
                         '/actual_observations/parser_process')
        self.assertEqual(result['summary']['fresh_configuration_pass'], 0)

    def test_lifecycle_role_set_remains_exact(self):
        observations = copy.deepcopy(self.source['rows'][0]['fresh_observations'])
        del observations['client_exit']
        with self.assertRaisesRegex(ValueError, 'All 35'):
            PACKAGE.compact_observations(observations, None)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
