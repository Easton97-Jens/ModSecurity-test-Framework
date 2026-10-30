"""Apache-only I12 acceptance ledger; historical results never become fresh tests.

Packet and oracle review use the existing shared validators unchanged. This
adapter inventories evidence; it does not execute cases or infer observations.
"""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path

# Load the maintained Parent filesystem boundary from this checkout.
import sys as _i12_sys

import modsecurity_connector_ci.lib.i12_path_safety as i12_paths

def load_shared():
    path = source_path('ci') / 'evidence/reports/generate-pr382-i12-lifecycle-ledger.py'
    module = load_source(path)
    return module

def load_paths():
    module = load_source(Path(__file__).with_name('paths.py'))
    return module
PATHS = load_paths()
SHARED = load_shared()
ORACLES = SHARED.ORACLES

def packet_reviewer(row, packet):
    if row['selected_requirement'].get('execution_kind') == 'actual_configtest':
        return SHARED.reviewed_configuration_packet
    if packet.get('execution_kind') == 'host_pre_native_rejection':
        return SHARED.reviewed_pre_native_packet
    return SHARED.reviewed_packet

def effective_oracle(review, original):
    oracle = review.get('effective_oracle') if review else original
    if oracle and oracle.get('unresolved_expected_value_reason'):
        return None
    return oracle

def qualification_scope(fresh, qualified):
    if not fresh:
        return None
    if fresh.get('qualification_scope'):
        return fresh['qualification_scope']
    if qualified:
        return 'full_host_lifecycle'
    return None

def apache_rows(baseline):
    """Check the immutable complete catalog before selecting the Apache slice."""
    rows = baseline['rows']
    ids = [row['run_scoped_case_id'] for row in rows]
    if len(ids) != 1484 or len(set(ids)) != 1484:
        raise ValueError('Baseline requires all 1484 unique original IDs')
    if hashlib.sha256(('\n'.join(ids) + '\n').encode()).hexdigest() != ORACLES.ID_SHA256:
        raise ValueError('Original ordered IDs changed')
    if ORACLES.canonical_digest([row['selected_requirement'] for row in rows]) != ORACLES.CONTRACT_SHA256:
        raise ValueError('Original selected requirements or oracles changed')
    for row in rows:
        if row['run_scoped_case_id'].split('::')[1] != row['leg_id'] or row['selected_requirement']['run_scoped_case_id'] != row['run_scoped_case_id']:
            raise ValueError('Baseline case/profile identity changed')
    selected = [row for row in rows if row['leg_id'] == 'apache-native']
    if len(selected) != 155 or any((row['required_leg'] is not True for row in selected)):
        raise ValueError('Apache requires exactly 155 mandatory cases')
    return selected

class ApacheLedger:

    def __init__(self, baseline, packets, oracle_records, expected_identity):
        self.baseline = baseline
        self.packets = packets
        self.oracle_records = oracle_records
        self.expected_identity = expected_identity

    def load_inputs(self):
        self.original = apache_rows(self.baseline)
        self.by_id = {row['run_scoped_case_id']: row for row in self.original}
        self.reviews = {}

    def review_oracles(self):
        for record in self.oracle_records:
            self.identity = record['run_scoped_case_id']
            if self.identity not in self.by_id or self.identity in self.reviews:
                raise ValueError('Unknown, foreign or duplicate Apache oracle ID')
            self.reviews[self.identity] = ORACLES.review_record(record, self.by_id[self.identity])

    def review_packets(self):
        self.observations = {}
        for supplied in self.packets:
            self.ref = ORACLES.verify_reference(supplied)
            self.packet = json.loads(Path(self.ref['path']).read_text())
            self.identity = self.packet['run_scoped_case_id']
            if self.identity not in self.by_id or self.identity in self.observations:
                raise ValueError('Unknown, foreign or duplicate Apache packet ID')
            for name, value in (self.expected_identity or {}).items():
                if self.packet.get(name) != value:
                    raise ValueError(f'Packet does not bind expected identity: {name}')
            row = self.by_id[self.identity]
            self.review = self.reviews.get(self.identity, row.get('oracle_reconciliation'))
            self.oracle = effective_oracle(self.review, row['selected_requirement']['expected_oracle'])
            reviewer = packet_reviewer(row, self.packet)
            self.observations[self.identity] = reviewer(self.ref, row, self.oracle)

    def collect_rows(self):
        self.rows = []
        for old in self.original:
            self.identity = old['run_scoped_case_id']
            self.fresh = self.observations.get(self.identity)
            self.qualified = self.fresh is not None and self.fresh['full_lifecycle_qualified']
            self.rows.append({'run_scoped_case_id': self.identity, 'leg_id': 'apache-native', 'required_leg': True, 'selected_requirement': copy.deepcopy(old['selected_requirement']), 'original_oracle': copy.deepcopy(old['selected_requirement']['expected_oracle']), 'historical_result': copy.deepcopy(old), 'oracle_reconciliation': copy.deepcopy(self.reviews.get(self.identity, old.get('oracle_reconciliation'))), 'fresh_packet': self.fresh, 'fresh_observations': copy.deepcopy(self.fresh['observations']) if self.fresh else {name: {'value': None, 'reason': 'No newly reviewed Apache host packet for this original ID.'} for name in SHARED.ROLES}, 'fresh_execution_observed': self.fresh is not None, 'fresh_full_lifecycle_qualified': self.qualified, 'fresh_outcome': self.fresh['outcome'] if self.qualified else None, 'fresh_qualified_pass': self.qualified and self.fresh['outcome'] == 'PASS'})

            # Control scopes cannot supply native body/finish/free observations.
            case_qualified = self.qualified or bool(self.fresh and self.fresh.get('full_case_qualified'))
            self.rows[-1].update({
                'fresh_qualification_scope': qualification_scope(self.fresh, self.qualified),
                'fresh_case_qualified': case_qualified,
                'fresh_case_outcome': self.fresh['outcome'] if case_qualified else None,
                'fresh_case_qualified_pass': case_qualified and self.fresh['outcome'] == 'PASS',
            })

    def control_summary(self):
        result = {}
        for label, scope in (('configuration', 'configuration_control'),
                             ('pre_native', 'host_pre_native_rejection')):
            selected = [row for row in self.rows if row['fresh_qualification_scope'] == scope]
            for outcome in ('PASS', 'FAIL'):
                result[f'fresh_{label}_{outcome.lower()}'] = sum(
                    row['fresh_case_outcome'] == outcome for row in selected)
        result['fresh_case_qualified_pass'] = sum(row['fresh_case_qualified_pass'] for row in self.rows)
        result['missing_fresh_case_qualification'] = sum(not row['fresh_case_qualified'] for row in self.rows)
        return result

    def summarize(self):
        self.subset = [row for row in self.rows if row['original_oracle'].get('unresolved_expected_value_reason')]
        self.resolved = sum((bool(row['oracle_reconciliation'] and row['oracle_reconciliation'].get('resolved')) for row in self.subset))
        return {'schema_version': 1, 'scope': 'apache-native', 'i12_complete': False, 'original_ordered_id_sha256': ORACLES.ID_SHA256, 'original_selected_contract_sha256': ORACLES.CONTRACT_SHA256, 'summary': {'required_cases': 155, 'historical_executed': sum((row.get('execution_observed') is True for row in self.original)), 'historical_configuration_pass': sum((row.get('qualification_scope') == 'historical_configuration_only' and row['status'] == 'PASS' for row in self.original)), 'historical_full_lifecycle_pass': sum((row.get('qualification_scope') == 'full_host_lifecycle' and row['status'] == 'PASS' for row in self.original)), 'fresh_executed': sum((row['fresh_execution_observed'] for row in self.rows)), 'fresh_full_lifecycle_pass': sum((row['fresh_qualified_pass'] for row in self.rows)), 'fresh_full_lifecycle_fail': sum((row['fresh_outcome'] == 'FAIL' for row in self.rows)), 'missing_fresh_full_qualification': sum((not row['fresh_full_lifecycle_qualified'] for row in self.rows)), 'original_open_oracle_subset': len(self.subset), 'resolved_original_oracles': self.resolved, 'unresolved_original_oracles': len(self.subset) - self.resolved}, 'rows': self.rows}

def build_ledger(baseline, packets, oracle_records=(), expected_identity=None):
    work = ApacheLedger(baseline, packets, oracle_records, expected_identity)
    work.load_inputs()
    work.review_oracles()
    work.review_packets()
    work.collect_rows()
    result = work.summarize()
    result['summary'].update(work.control_summary())
    return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('baseline-ledger', 'reviewed-packets', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--reviewed-oracles', type=Path)
    parser.add_argument('--expected-run-id')
    parser.add_argument('--expected-parent-sha')
    args = parser.parse_args()
    inputs = [ORACLES.reference(path.absolute()) for path in (args.baseline_ledger, args.reviewed_packets)]
    records = []
    if args.reviewed_oracles:
        inputs.append(ORACLES.reference(args.reviewed_oracles.absolute()))
        records = json.loads(args.reviewed_oracles.read_text())['records']
    expected = {name: value for name, value in (('run_id', args.expected_run_id), ('parent_sha', args.expected_parent_sha)) if value is not None}
    result = build_ledger(json.loads(args.baseline_ledger.read_text()), json.loads(args.reviewed_packets.read_text())['packets'], records, expected)
    result['input_evidence'] = inputs
    with i12_paths.new_text(args.output) as stream:
        json.dump(result, stream, indent=2, ensure_ascii=False)
        stream.write('\n')
    print(json.dumps({'output': ORACLES.reference(args.output.absolute()), 'summary': result['summary']}))
if __name__ == '__main__':
    main()
