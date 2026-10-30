"""Preserve failed constructor observations and propose typed absence evidence.

This never turns a missing join into a join, and never changes qualification.
"""
import argparse
from collections import Counter
import json
from pathlib import Path

from modsecurity_connector_ci.runtime.lifecycle.i12.lighttpd.stock_packet import lines, read, reference, selected_scope
from modsecurity_connector_ci.runtime.lifecycle.i12.lighttpd.stock_qualification import EXTERNAL

# Load the maintained Parent filesystem boundary from this checkout.
import sys as _i12_sys

import modsecurity_connector_ci.lib.i12_path_safety as i12_paths


def summarize(data, source):
    root = data / 'lighttpd'
    before = read(root / 'receipts/before-main/snapshot.json')['monotonic_ns']
    after = read(root / 'receipts/after-main/snapshot.json')['monotonic_ns']
    api_path = data / 'native-api.jsonl'
    api = lines(api_path)
    scope = selected_scope(api, before, after, require_join=False)
    rows = [row for row in api if row.get('allocation_scope_call') == scope or row['call'] == scope]
    if len(rows) > 1000:
        raise ValueError('bounded constructor sequence exceeded')
    returns = [row for row in rows if row['edge'] == 'return']
    constructors = [row for row in returns if row['function'] == 'runtime_begin_request_stream']
    if len(constructors) != 1 or constructors[0]['result'] != 0 or any(row['invalid'] for row in rows):
        raise ValueError('expected one real failed constructor and valid native observer')
    constructor = constructors[0]
    actual_slot_observed = constructor.get('output_argument_present') is True
    actual_absent = actual_slot_observed and constructor.get('actual_output_handle_present') is False
    counts = Counter(row['function'] for row in returns)
    return {'schema': 'lighttpd-stock-failed-constructor-absence-proposal-v1',
        'run_scoped_case_id': 'I12::lighttpd-stock-sidecar::' + constructor['case'],
        'reviewed_by': 'worker', 'full_lifecycle_qualified': False,
        'subject': 'runtime_output_handle', 'value': None,
        'observation_state': 'observed_absent' if actual_absent else 'unknown',
        'actual_output_argument_observed': actual_slot_observed,
        'actual_output_handle_present': constructor.get('actual_output_handle_present'),
        'missing_reason': None if actual_absent else 'Older collector conditionally derived returned pointer from result==1 and did not read the actual caller output slot after failure.',
        'actual_constructor_return': constructor['result'],
        'actual_runtime_join_verified': constructor['allocation_join_verified'],
        'same_constructor_scope': scope,
        'nested_actual_allocations_and_cleanup': dict(counts),
        'native_id_observed_before_cleanup': sorted({row['transaction_id'] for row in rows
            if row.get('transaction_id_origin') == 'sdk_public_m_id' and row.get('transaction_id')}),
        'common_id_observed_before_cleanup': sorted({row['transaction_id'] for row in rows
            if row.get('transaction_id_origin') == 'common_public_contract' and row.get('transaction_id')}),
        'raw_native_api': reference(api_path, 'native_api'),
        'actual_client': reference(data / 'client/main.receipt.json', 'client_process'),
        'actual_host_process': reference(root / 'receipts/before-main/snapshot.json', 'cleanup_observer'),
        'actual_cleanup': reference(root / 'execution-receipt.json', 'cleanup_observer'),
        'compiled_runtime_source': {**reference(source / 'common/runtime/msconnector_runtime.c', 'source_contract'),
            'symbols': ['transaction_begin_internal', 'abort_transaction_begin', 'msconnector_runtime_transaction_destroy']},
        'compiled_native_cleanup_source': {**reference(source / 'common/src/modsecurity_engine.c', 'source_contract'),
            'symbols': ['msconnector_modsecurity_transaction_cleanup']},
        'raw_constructor_call_sequence': rows,
        'qualification_policy': 'Root must independently review a central typed-absence representation. Null remains null; actual native IDs and constructor scope do not imply a returned Runtime handle.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if '..' in args.output.parts or not args.output.absolute().is_relative_to(EXTERNAL):
        raise ValueError('external output required')
    result = summarize(args.data, args.source)
    with i12_paths.new_text(args.output) as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'case': result['run_scoped_case_id'], 'observation_state': result['observation_state']}))
