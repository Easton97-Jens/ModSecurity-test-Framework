#!/usr/bin/env python3
"""Reconcile Traefik-only receipts without changing the central I12 ledger."""
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

ROOT = connector_root()
INVENTORY = Path(__file__).with_name('fixtures') / 'i12_original_inventory.json'
COUNTS = {'traefik-native-uds': 118, 'traefik-forwardauth-request': 93,
          'traefik-forwardauth-response-companion': 69}
ORACLE_COUNTS = {'traefik-native-uds': 55, 'traefik-forwardauth-request': 39,
                 'traefik-forwardauth-response-companion': 30}
ID_SHA256 = 'd42fe8f76bac2b1162ffa91e8aa4f270a6e84c2009029e1e365f3cb4552d08ee'
CONTRACT_SHA256 = '94fe75e6ee0154c9a55bca42f1e9d41882655bedbf7425d8fb0731a8016de7f2'
INVENTORY_SHA256 = '02b5b6feea0f98dd8c10ebc6db648de9d85fe3046ced3ad9b8750537feb398ee'


def contracts():
    path = source_path('ci/evidence/reports/generate-pr382-i12-lifecycle-ledger.py', root=ROOT)
    module = load_source(path)
    return module


def provenance_mapping(records):
    if not isinstance(records, list):
        raise ValueError('Expected lossless provenance record list')
    mapping = {}
    for record in records:
        if not isinstance(record, dict) or set(record) != {'path', 'sha256'}:
            raise ValueError('Malformed provenance record')
        path, digest = record['path'], record['sha256']
        if not isinstance(path, str) or not isinstance(digest, str) or path in mapping:
            raise ValueError('Malformed or duplicate provenance path')
        mapping[path] = digest
    return mapping


def normalized_inventory(inventory):
    """Restore the historical map before checking its immutable digest."""
    result = copy.deepcopy(inventory)
    for source in result['original_sources']:
        source['original_source_hashes'] = provenance_mapping(source['original_source_hashes'])
    return result


def validate_inventory(inventory, contract):
    if contract.ORACLES.canonical_digest(inventory) != INVENTORY_SHA256:
        raise ValueError('Immutable Traefik baseline inventory changed')
    rows = copy.deepcopy(inventory['rows'])
    by_id = {row['run_scoped_case_id']: row for row in rows}
    if len(rows) != 280 or len(by_id) != 280:
        raise ValueError('Expected exactly 280 unique original Traefik IDs')
    ids = '\n'.join(by_id) + '\n'
    if (hashlib.sha256(ids.encode()).hexdigest() != ID_SHA256 or
            contract.ORACLES.canonical_digest([r['selected_requirement'] for r in rows]) != CONTRACT_SHA256):
        raise ValueError('Original Traefik IDs or selected contracts changed')
    if any(r['run_scoped_case_id'].split('::')[1] != r['leg_id'] for r in rows):
        raise ValueError('Original Traefik case/profile association changed')
    for leg in COUNTS:
        validate_route_membership(rows, leg)
    return rows, by_id


def validate_route_membership(rows, leg):
    selected = [r for r in rows if r['leg_id'] == leg]
    if len(selected) != COUNTS[leg] or any(r['required_leg'] is not True for r in selected):
        raise ValueError('Original required route membership changed')
    if sum(bool((r.get('original_oracle_disposition') or {}).get('original_596_member'))
           for r in selected) != ORACLE_COUNTS[leg]:
        raise ValueError('Original 124-oracle membership changed')


def validate_host_observations(measured):
    for observation in measured['observations'].values():
        if observation.get('value') is not None and any(
                proof.get('role') == 'host_callback' and proof['bytes'] == 0
                for proof in observation.get('evidence', [])):
            raise ValueError('An empty host callback capture cannot establish a measurement')


def apply_reviews(reviews, by_id, contract):
    seen_reviews = set()
    for review in reviews:
        identity = review['run_scoped_case_id']
        if identity not in by_id or identity in seen_reviews:
            raise ValueError('Unknown or duplicate Traefik oracle review')
        seen_reviews.add(identity)
        by_id[identity]['fresh_oracle_review'] = contract.ORACLES.review_record(review, by_id[identity])


def apply_packets(packets, by_id, contract):
    seen_packets = set()
    for supplied in packets:
        verified = contract.ORACLES.verify_reference(supplied)
        packet = json.loads(Path(verified['path']).read_text())
        identity = packet['run_scoped_case_id']
        if identity not in by_id or identity in seen_packets:
            raise ValueError('Unknown or duplicate Traefik lifecycle packet')
        seen_packets.add(identity)
        row = by_id[identity]
        review = row.get('fresh_oracle_review') or row.get('original_oracle_disposition')
        oracle = review.get('effective_oracle') if review else row['selected_requirement']['expected_oracle']
        if oracle and oracle.get('unresolved_expected_value_reason'):
            oracle = None
        if row['selected_requirement'].get('execution_kind') == 'actual_configtest':
            measured = contract.reviewed_configuration_packet(verified, row, oracle)
            row['fresh_configuration'] = measured
        elif packet.get('execution_kind') == 'host_preallocation_control':
            measured = contract.reviewed_preallocation_packet(verified, row, oracle)
            validate_host_observations(measured)
            row['fresh_preallocation'] = measured
        else:
            measured = contract.reviewed_packet(verified, row, oracle)
            validate_host_observations(measured)
            row['fresh_lifecycle'] = measured


def oracle_summary(selected):
    original = [r for r in selected if (r.get('original_oracle_disposition') or {}).get('original_596_member')]
    resolved = [r for r in original if
                (r.get('fresh_oracle_review') or r['original_oracle_disposition']).get('resolved') is True]
    return {'original_oracles': len(original), 'resolved_original_oracles': len(resolved),
            'unresolved_original_oracle_ids': [r['run_scoped_case_id'] for r in original if r not in resolved]}


def full_outcome(fresh, outcome):
    return [r for r in fresh if r['fresh_lifecycle']['full_lifecycle_qualified'] and
            r['fresh_lifecycle']['outcome'] == outcome]


def own_scope_summary(selected, qualified, lifecycle_fail):
    counts = {}
    cases = set(qualified)
    failed = {r["run_scoped_case_id"] for r in lifecycle_fail}
    for scope in ('configuration', 'preallocation'):
        field = 'fresh_' + scope
        measured = [r for r in selected if r.get(field)]
        passed = [r for r in measured if r[field]['full_case_qualified'] and
                  r[field]['outcome'] == 'PASS']
        rejected = [r for r in measured if r[field]['full_case_qualified'] and
                    r[field]['outcome'] == 'FAIL']
        counts[field + '_pass'] = len(passed)
        counts[field + '_fail'] = len(rejected)
        cases.update(r['run_scoped_case_id'] for r in passed)
        failed.update(r['run_scoped_case_id'] for r in rejected)
    cases.difference_update(failed)
    return {**counts, 'case_qualified_pass': len(cases),
            'case_qualified_fail': len(failed),
            'case_unqualified_ids': [r['run_scoped_case_id'] for r in selected
                                     if r['run_scoped_case_id'] not in cases | failed]}


def route_summary(rows, leg):
    selected = [r for r in rows if r['leg_id'] == leg]
    fresh = [r for r in selected if r.get('fresh_lifecycle')]
    full_pass = full_outcome(fresh, 'PASS')
    full_fail = full_outcome(fresh, 'FAIL')
    # A fresh partial attempt does not erase an old complete packet; both
    # remain visible. A fresh qualified FAIL supersedes its old PASS.
    qualified = {r['run_scoped_case_id'] for r in selected if r['qualified_host_lifecycle_pass']}
    qualified.update(r['run_scoped_case_id'] for r in full_pass)
    qualified.difference_update(r['run_scoped_case_id'] for r in full_fail)
    return {'required_ids': len(selected),
                       'baseline_lifecycle_pass': sum(r['qualified_host_lifecycle_pass'] for r in selected),
                       'baseline_config_only_pass': sum(r['qualification_scope'] == 'historical_configuration_only' for r in selected),
                       'fresh_host_attempts': len(fresh), 'fresh_lifecycle_pass': len(full_pass),
                       'fresh_lifecycle_fail': len(full_fail),
                       'fresh_partial': len(fresh)-len(full_pass)-len(full_fail),
                       'lifecycle_pass': len(qualified),
                       'lifecycle_unqualified_ids': [r['run_scoped_case_id'] for r in selected
                                                  if r['run_scoped_case_id'] not in qualified and r not in full_fail],
                       **own_scope_summary(selected, qualified, full_fail),
                       **oracle_summary(selected)}



def reconcile(inventory, reviews=(), packets=()):
    """Keep historical, source-resolved, and freshly qualified counts separate."""
    contract = contracts()
    inventory = normalized_inventory(inventory)
    rows, by_id = validate_inventory(inventory, contract)
    apply_reviews(reviews, by_id, contract)
    apply_packets(packets, by_id, contract)
    result = {leg: route_summary(rows, leg) for leg in COUNTS}
    for row in rows:
        row['baseline_status'] = row['status']
        row['baseline_qualification_scope'] = row['qualification_scope']
        row['baseline_lifecycle_pass'] = row['qualified_host_lifecycle_pass']
        fresh = row.get('fresh_lifecycle')
        if fresh and fresh['full_lifecycle_qualified']:
            row['status'] = fresh['outcome']
            row['qualification_scope'] = 'full_host_lifecycle'
            row['qualified_host_lifecycle_pass'] = fresh['outcome'] == 'PASS'
        elif fresh and not row['qualified_host_lifecycle_pass']:
            row['status'] = 'PARTIAL_HOST_MEASUREMENTS'
        own = row.get('fresh_configuration') or row.get('fresh_preallocation')
        if own and own['full_case_qualified']:
            row['status'] = own['outcome']
            row['qualification_scope'] = own['qualification_scope']
            row['qualified_host_lifecycle_pass'] = False
    return {'schema_version': 1, 'scope': 'traefik-only',
            'source_ledger': inventory['source_ledger'],
            'source_reconciliation': inventory['source_reconciliation'],
            'summary': result, 'rows': rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', type=Path, default=INVENTORY)
    parser.add_argument('--reviews', type=Path)
    parser.add_argument('--packets', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = reconcile(json.loads(args.inventory.read_text()),
                       json.loads(args.reviews.read_text()) if args.reviews else (),
                       json.loads(args.packets.read_text()) if args.packets else ())
    with i12_paths.new_text(args.output) as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')


if __name__ == '__main__':
    main()
