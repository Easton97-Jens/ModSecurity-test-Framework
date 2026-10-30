"""Keep the Traefik original inventory and qualification boundaries explicit."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

ROOT = connector_root()
LEDGER = load_source(source_path('connectors/traefik/harness/i12_ledger.py', root=ROOT))


class TraefikI12LedgerTest(unittest.TestCase):
    def setUp(self):
        self.inventory = json.loads(LEDGER.INVENTORY.read_text())

    def test_exact_original_ids_contracts_and_124_members_are_preserved(self):
        rows = self.inventory['rows']
        ids = '\n'.join(r['run_scoped_case_id'] for r in rows) + '\n'
        self.assertEqual(hashlib.sha256(ids.encode()).hexdigest(),
                         'd42fe8f76bac2b1162ffa91e8aa4f270a6e84c2009029e1e365f3cb4552d08ee')
        self.assertEqual(LEDGER.contracts().ORACLES.canonical_digest(
            [r['selected_requirement'] for r in rows]),
            '94fe75e6ee0154c9a55bca42f1e9d41882655bedbf7425d8fb0731a8016de7f2')
        before = copy.deepcopy(self.inventory)
        result = LEDGER.reconcile(self.inventory)
        self.assertEqual(self.inventory, before)
        for leg, unresolved, config_only in [('traefik-native-uds', 54, 1),
                                             ('traefik-forwardauth-request', 38, 8),
                                             ('traefik-forwardauth-response-companion', 29, 0)]:
            summary = result['summary'][leg]
            self.assertEqual(summary['baseline_lifecycle_pass'], 1)
            self.assertEqual(summary['fresh_lifecycle_pass'], 0)
            self.assertEqual(summary['baseline_config_only_pass'], config_only)
            self.assertEqual(len(summary['unresolved_original_oracle_ids']), unresolved)
            self.assertEqual(len(summary['lifecycle_unqualified_ids']), summary['required_ids']-1)

    def test_duplicate_or_sibling_membership_cannot_qualify(self):
        for mutate in (lambda d:d['rows'].append(copy.deepcopy(d['rows'][0])),
                       lambda d:d['rows'][0].update(leg_id='traefik-forwardauth-request'),
                       lambda d:d['rows'][0].update(required_leg=False)):
            with self.subTest(mutation=mutate):
                bad = copy.deepcopy(self.inventory)
                mutate(bad)
                with self.assertRaises(ValueError):
                    LEDGER.reconcile(bad)

    def test_baseline_pass_and_resolved_dispositions_cannot_be_injected(self):
        bad_pass = copy.deepcopy(self.inventory)
        bad_pass['rows'][0]['qualified_host_lifecycle_pass'] = True
        bad_oracle = copy.deepcopy(self.inventory)
        unresolved = next(r['original_oracle_disposition'] for r in bad_oracle['rows'] if
                          (r.get('original_oracle_disposition') or {}).get('resolved') is False)
        unresolved['resolved'] = True
        for bad in (bad_pass,bad_oracle):
            with self.assertRaisesRegex(ValueError,'baseline inventory changed'):
                LEDGER.reconcile(bad)

    def test_tcp_eof_and_driver_pass_cannot_replace_native_measurements(self):
        contract = LEDGER.contracts()
        row = self.inventory['rows'][0]
        packet = dict(reviewed_by='root',run_scoped_case_id=row['run_scoped_case_id'],
                      leg_id=row['leg_id'],execution_observed=True,execution_kind='host_http',
                      run_id='negative-control',parent_sha=self.inventory['parent_sha'],
                      framework_sha='99a7985c1be92a2297b1b59208f64df6768f2cbf',
                      mrts_sha='8a6bb546c4c81d8ffc7be801dceac60c6925685f',
                      effective_config_sha256='0'*64,oracle_evaluated=False,
                      outcome=None, observations={k:dict(value=None,reason='Not measured in negative control')
                                                 for k in contract.ROLES})
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as temporary:
            path = Path(temporary)/'packet.json'
            client = Path(temporary)/'client.json'
            client.write_text('{"tcp_eof":true,"driver_exit":0}')
            packet['observations']['native_eos'] = dict(value=True,evidence=[
                {**contract.ORACLES.reference(client),'role':'client_process'}])
            path.write_text(json.dumps(packet))
            packet_reference = contract.ORACLES.reference(path)
            with self.assertRaisesRegex(ValueError,'physical producer'):
                LEDGER.reconcile(self.inventory, packets=[packet_reference])

    def test_partial_host_attempt_preserves_unknowns_and_does_not_resolve_oracle(self):
        contract = LEDGER.contracts()
        row = next(r for r in self.inventory['rows'] if
                   (r.get('original_oracle_disposition') or {}).get('resolved') is False)
        packet = dict(reviewed_by='root',run_scoped_case_id=row['run_scoped_case_id'],
                      leg_id=row['leg_id'],execution_observed=True,execution_kind='host_http',
                      run_id='partial-control',parent_sha=self.inventory['parent_sha'],
                      framework_sha='99a7985c1be92a2297b1b59208f64df6768f2cbf',
                      mrts_sha='8a6bb546c4c81d8ffc7be801dceac60c6925685f',
                      effective_config_sha256='0'*64,oracle_evaluated=False,
                      outcome=None, observations={k:dict(value=None,reason='No physical producer for this field')
                                                 for k in contract.ROLES})
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as temporary:
            path = Path(temporary)/'packet.json'
            path.write_text(json.dumps(packet))
            result = LEDGER.reconcile(self.inventory,packets=[contract.ORACLES.reference(path)])
        summary = result['summary'][row['leg_id']]
        self.assertEqual(summary['fresh_partial'],1)
        self.assertEqual(summary['fresh_lifecycle_pass'],0)
        self.assertIn(row['run_scoped_case_id'],summary['unresolved_original_oracle_ids'])
        current = next(r for r in result['rows'] if r.get('fresh_lifecycle'))
        self.assertEqual(current['status'],'PARTIAL_HOST_MEASUREMENTS')
        self.assertEqual(current['baseline_status'],row['status'])
        observation = next(r['fresh_lifecycle'] for r in result['rows'] if r.get('fresh_lifecycle'))
        self.assertEqual(set(observation['unknown_fields']),set(contract.ROLES))

    def test_empty_host_capture_cannot_claim_observed_absence(self):
        contract = LEDGER.contracts()
        row = self.inventory['rows'][0]
        packet = dict(reviewed_by='root',run_scoped_case_id=row['run_scoped_case_id'],
                      leg_id=row['leg_id'],execution_observed=True,execution_kind='host_http',
                      run_id='empty-capture',parent_sha=self.inventory['parent_sha'],
                      framework_sha='99a7985c1be92a2297b1b59208f64df6768f2cbf',
                      mrts_sha='8a6bb546c4c81d8ffc7be801dceac60c6925685f',
                      effective_config_sha256='0'*64,oracle_evaluated=False,outcome=None,
                      observations={k:dict(value=None,reason='Not independently measured') for k in contract.ROLES})
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as temporary:
            path = Path(temporary)/'packet.json'
            host = Path(temporary)/'host.jsonl'
            host.write_text('')
            packet['observations']['host_eos'] = dict(value=[],evidence=[
                {**contract.ORACLES.reference(host),'role':'host_callback'}])
            path.write_text(json.dumps(packet))
            packet_reference = contract.ORACLES.reference(path)
            with self.assertRaisesRegex(ValueError,'empty host callback'):
                LEDGER.reconcile(self.inventory,packets=[packet_reference])

    def test_lossless_provenance_keeps_original_canonical_digest(self):
        normalized = LEDGER.normalized_inventory(self.inventory)
        self.assertEqual(LEDGER.contracts().ORACLES.canonical_digest(normalized),
                         LEDGER.INVENTORY_SHA256)
        for original, restored in zip(self.inventory['original_sources'], normalized['original_sources']):
            self.assertEqual(original['original_source_hashes'],
                             [{'path': path, 'sha256': digest} for path, digest in restored['original_source_hashes'].items()])

    def test_fingerprint_changes_duplicates_and_malformed_provenance_fail_closed(self):
        mutations = (
            lambda records: records[0].update(sha256='0' * 64),
            lambda records: records.append(copy.deepcopy(records[0])),
            lambda records: records[0].update(extra='unexpected'),
            lambda records: records.__setitem__(0, {'path': ['invalid'], 'sha256': '0' * 64}),
            lambda records: records.__setitem__(0, {'path': 'only-path'}),
            lambda records: records.__setitem__(0, None),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                changed = copy.deepcopy(self.inventory)
                mutate(changed['original_sources'][0]['original_source_hashes'])
                with self.assertRaises(ValueError):
                    LEDGER.reconcile(changed)


class TraefikOwnScopeConsumerTest(unittest.TestCase):
    # Producer-shaped synthetic controls exercise the real central validators;
    # they are not physical host evidence or qualification of this repository.
    def setUp(self):
        self.inventory = json.loads(LEDGER.INVENTORY.read_text())
        self.contract = LEDGER.contracts()
        temporary = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def configuration(self):
        from modsecurity_connector_tests.test_i12_lifecycle_ledger import configuration_control
        _, packet, _ = configuration_control(self.root)
        row = next(r for r in self.inventory['rows'] if r['run_scoped_case_id'] ==
                   'I12::traefik-forwardauth-request::valid_rules_file')
        oracle = row['selected_requirement']['expected_oracle']
        packet.update(run_scoped_case_id=row['run_scoped_case_id'], leg_id=row['leg_id'],
                      oracle_sha256=self.contract.ORACLES.canonical_digest(oracle))
        ref = next(r for r in packet['measurement_evidence'] if r['role'] == 'parser_process')
        path = Path(ref['path'])
        actual = json.loads(path.read_text())
        actual.update(run_scoped_case_id=row['run_scoped_case_id'], leg_id=row['leg_id'])
        path.write_text(json.dumps(actual))
        ref.update(self.contract.ORACLES.reference(path))
        return row, packet, oracle

    def packet_reference(self, packet):
        path = self.root / 'packet.json'
        path.write_text(json.dumps(packet))
        return self.contract.ORACLES.reference(path)

    def test_configuration_accepted_centrally_qualifies_only_its_original_scope(self):
        row, packet, oracle = self.configuration()
        ref = self.packet_reference(packet)
        self.assertTrue(self.contract.reviewed_configuration_packet(ref, row, oracle)['full_case_qualified'])
        result = LEDGER.reconcile(self.inventory, packets=[ref])
        current = next(r for r in result['rows'] if r.get('fresh_configuration'))
        self.assertEqual(current['qualification_scope'], 'configuration_control')
        self.assertNotIn('fresh_lifecycle', current)
        self.assertFalse(current['qualified_host_lifecycle_pass'])
        summary = result['summary'][row['leg_id']]
        self.assertEqual(summary['fresh_configuration_pass'], 1)
        self.assertEqual(summary['fresh_lifecycle_pass'], 0)
        self.assertEqual(summary['fresh_host_attempts'], 0)
        self.assertIn(row['run_scoped_case_id'], summary['lifecycle_unqualified_ids'])
        self.assertNotIn(row['run_scoped_case_id'], summary['case_unqualified_ids'])

    def test_configuration_fail_stays_own_scope_without_a_pass_or_unknown_credit(self):
        row, packet, _ = self.configuration()
        packet['outcome'] = 'FAIL'
        process = packet['actual_observations']['parser_process']
        process['waited_exit'] = 1
        ref = next(r for r in packet['measurement_evidence'] if r['role'] == 'parser_process')
        path = Path(ref['path'])
        actual = json.loads(path.read_text())
        actual['waited_exit'] = 1
        path.write_text(json.dumps(actual))
        ref.update(self.contract.ORACLES.reference(path))
        result = LEDGER.reconcile(self.inventory, packets=[self.packet_reference(packet)])
        summary = result['summary'][row['leg_id']]
        self.assertEqual(summary['fresh_configuration_pass'], 0)
        self.assertEqual(summary['fresh_configuration_fail'], 1)
        self.assertEqual(summary['case_qualified_fail'], 1)
        self.assertEqual(summary['case_qualified_pass'], 1)  # One historical lifecycle.
        self.assertEqual(summary['fresh_lifecycle_fail'], 0)
        self.assertIn(row['run_scoped_case_id'], summary['lifecycle_unqualified_ids'])
        self.assertNotIn(row['run_scoped_case_id'], summary['case_unqualified_ids'])

    def test_configuration_scope_cannot_cover_http_or_sibling_id(self):
        _, packet, _ = self.configuration()
        for identity in ('I12::traefik-native-uds::allow_without_marker',
                         'I12::traefik-forwardauth-request::invalid_rule_syntax'):
            with self.subTest(identity=identity):
                packet['run_scoped_case_id'] = identity
                packet['leg_id'] = identity.split('::')[1]
                supplied = self.packet_reference(packet)
                with self.assertRaises(ValueError):
                    LEDGER.reconcile(self.inventory, packets=[supplied])

    def test_missing_configuration_producer_or_invented_lifecycle_is_rejected(self):
        for mutation in ('missing_process', 'lifecycle_claim'):
            with self.subTest(mutation=mutation):
                _, packet, _ = self.configuration()
                if mutation == 'missing_process':
                    packet['measurement_evidence'] = [r for r in packet['measurement_evidence']
                                                      if r['role'] != 'parser_process']
                else:
                    packet['full_lifecycle_qualified'] = True
                supplied = self.packet_reference(packet)
                with self.assertRaises(ValueError):
                    LEDGER.reconcile(self.inventory, packets=[supplied])

    def preallocation(self):
        from modsecurity_connector_tests.test_i12_traefik_preallocation import TraefikPreallocationTests
        fixture = TraefikPreallocationTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        row = copy.deepcopy(next(r for r in self.inventory['rows'] if
                                 r['run_scoped_case_id'] == fixture.case))
        fixture.row = row
        fixture.rebind_expected()
        row['fresh_oracle_review'] = {'resolved': True, 'effective_oracle': fixture.oracle}
        return fixture, row

    def test_preallocation_uses_real_original_contract_without_lifecycle_credit(self):
        fixture, row = self.preallocation()
        ref = fixture.write('packet.json', fixture.packet, 'reviewed_packet')
        self.assertTrue(self.contract.reviewed_preallocation_packet(ref, row, fixture.oracle)['full_case_qualified'])
        rows = copy.deepcopy(self.inventory['rows'])
        by_id = {r['run_scoped_case_id']: r for r in rows}
        by_id[row['run_scoped_case_id']] = row
        rows[rows.index(next(r for r in rows if r['run_scoped_case_id'] == fixture.case))] = row
        LEDGER.apply_packets([ref], by_id, self.contract)
        summary = LEDGER.route_summary(rows, row['leg_id'])
        self.assertIn('fresh_preallocation', row)
        self.assertNotIn('fresh_lifecycle', row)
        self.assertEqual(summary['fresh_preallocation_pass'], 1)
        self.assertEqual(summary['fresh_lifecycle_pass'], 0)
        self.assertIn(fixture.case, summary['lifecycle_unqualified_ids'])
        self.assertNotIn(fixture.case, summary['case_unqualified_ids'])

    def test_preallocation_missing_observer_and_cross_id_are_rejected(self):
        for mutation in ('missing_observer', 'cross_id'):
            with self.subTest(mutation=mutation):
                fixture, row = self.preallocation()
                if mutation == 'missing_observer':
                    fixture.packet.pop('observer_log')
                else:
                    fixture.packet['run_scoped_case_id'] = 'I12::traefik-native-uds::allow_without_marker'
                    row = copy.deepcopy(next(r for r in self.inventory['rows'] if
                        r['run_scoped_case_id'] == fixture.packet['run_scoped_case_id']))
                ref = fixture.write('packet.json', fixture.packet, 'reviewed_packet')
                with self.assertRaises((ValueError, KeyError)):
                    LEDGER.apply_packets([ref], {row['run_scoped_case_id']: row}, self.contract)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == '__main__':
    unittest.main()
