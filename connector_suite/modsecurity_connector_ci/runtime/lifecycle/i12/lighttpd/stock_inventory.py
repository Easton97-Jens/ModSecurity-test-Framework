"""Inventory exact original Stock IDs without promoting worker observations."""
import argparse
from collections import Counter
import json
from pathlib import Path

from modsecurity_connector_ci.runtime.lifecycle.i12.lighttpd.stock_packet import external_path, read, reference
from modsecurity_connector_ci.runtime.lifecycle.i12.lighttpd.stock_qualification import FRAMEWORK, REPO


PREFERRED = ('benign-batch03', 'canonical-batch01', 'spool-batch01',
    'additional-benign01', 'metadata-batch01', 'phase3-batch02', 'replay-gate01',
    'default-capacity01', 'sink-batch01', 'delivered-profiles01', 'audit-metadata01',
    'pointer-current01', 'sink-current02', 'mime-current03', 'mime-current05',
    'incomplete-current01', 'file-late-current01', 'abort-current02',
    'phase3-current01', 'limits-current01', 'timeout-current01', 'first-byte-current01',
    'timeout-current02', 'late-current01', 'profiles-multipart-current02', 'mapping-current01',
    'normal-originals-current02')


def rank(path):
    batch = path.parts[-4]
    version = {'review': 1, 'review-v2': 2, 'review-v3': 3, 'review-frozen': 4}.get(path.parts[-3], 0)
    return (PREFERRED.index(batch) + 1 if batch in PREFERRED else 0, version)


def packets(stock):
    grouped = {}
    for path in stock.rglob('packet-proposal.json'):
        packet = read(path)
        case_id = packet['run_scoped_case_id']
        grouped.setdefault(case_id, []).append((path, packet))
    return {case_id: sorted(values, key=lambda pair: rank(pair[0]), reverse=True)
            for case_id, values in grouped.items()}


def process_refs(packet):
    evidence = packet['observations']['client_exit']['evidence']
    refs = [item for item in evidence if item.get('role') == 'client_process']
    raw_refs = packet['observations']['client_signal'].get('evidence', [])
    return refs + [item for item in raw_refs if item not in refs]


def starts_without_http(run):
    found = {}
    for attempt in (run / 'isolation').glob('attempt-*'):
        batch = attempt / 'data/batch-result.json'
        if not batch.is_file():
            continue
        for child in read(batch):
            case = child['case']
            data = attempt / 'data' / case
            receipt = data / 'lighttpd/execution-receipt.json'
            if not receipt.is_file() or (data / 'client/main.receipt.json').exists():
                continue
            case_id = read(receipt)['actual_selected_id']
            if not case_id.startswith('I12::lighttpd-stock-sidecar::'):
                continue
            physical = [reference(receipt), reference(data / 'driver-receipt.json'),
                reference(data / 'driver.stderr'), reference(attempt / 'controller-result.json')]
            if (data / 'sink-fault.jsonl').is_file():
                physical.append(reference(data / 'sink-fault.jsonl'))
            found[case_id] = {'execution_kind': 'host_start_only', 'execution_observed': True,
                'agent_outcome': None, 'host_start_receipts': physical,
                'qualification_missing_reason': 'Actual host/sidecar startup attempted and cleaned; failed before independent HTTP client launch. Startup exit and injected I/O trace do not create a native transaction ID, EOS or host HTTP PASS.'}
    return found


def unassembled_http(run):
    found = {}
    for attempt in (run / 'isolation').glob('attempt-*'):
        for receipt in (attempt / 'data').glob('*/lighttpd/execution-receipt.json'):
            client = receipt.parent / 'main.actual-client-process.json'
            raw = receipt.parent.parent / 'client/main.receipt.json'
            if not client.is_file() or not raw.is_file():
                continue
            case_id = read(receipt)['actual_selected_id']
            if case_id.startswith('I12::lighttpd-stock-sidecar::'):
                found[case_id] = {'execution_kind': 'host_http_unassembled',
                    'execution_observed': True, 'agent_outcome': None,
                    'independently_waited_client_process_receipts': [reference(client, 'client_process'), reference(raw)],
                    'host_start_receipts': [reference(receipt), reference(attempt / 'controller-result.json')],
                    'qualification_missing_reason': 'Actual HTTP client and host execution retained, but no complete reviewed35-role proposal for this exact original is available.'}
    return found


def inventory(run):
    run = external_path(run)
    baseline = REPO / 'reports/testing/lighttpd-i12-20261015/lighttpd-stock-sidecar-cases.json'
    original_rows = read(baseline)['rows']
    source_catalog = FRAMEWORK / 'tests/cases/no-crs-baseline/catalog.json'
    catalog = {row['case_id']: row for row in read(source_catalog)['cases']}
    proposals = packets(run / 'stock')
    starts = starts_without_http(run)
    raw_http = unassembled_http(run)
    results, physical_executions = [], {}
    for original in original_rows:
        case_id = original['run_scoped_case_id']
        selected = original['selected_requirement']
        row = {'run_scoped_case_id': case_id, 'original_row_sha256': original['original_row_sha256'],
            'original_selected_requirement': selected,
            'baseline_reference': reference(baseline),
            'baseline_status_preserved': original['status'],
            'full_lifecycle_qualified': False, 'root_qualification': None,
            'deprecated_alias_for': catalog.get(selected['case_id'], {}).get('deprecated_alias_for'),
            'request_fixture_reuse': catalog.get(selected['case_id'], {}).get('request', {}).get('reuses')}
        values = proposals.get(case_id, [])
        row['all_worker_proposals'] = [reference(path) for path, _packet in values]
        if values:
            path, packet = values[0]
            clients = process_refs(packet)
            identity = tuple(sorted((item['path'], item['sha256']) for item in clients))
            physical_executions.setdefault(identity, []).append(case_id)
            unknown = {field: supplied.get('reason') for field, supplied in packet['observations'].items()
                       if supplied.get('applicable', True) and supplied.get('value') is None}
            row.update(execution_kind='host_http', execution_observed=True,
                preferred_worker_proposal=reference(path), agent_outcome=packet.get('outcome'),
                independently_waited_client_process_receipts=clients,
                missing_measurements=unknown,
                qualification_missing_reason='Independent Root review and central qualification are authoritative; an agent outcome never qualifies this ID.')
        else:
            row.update(execution_kind=None, execution_observed=False, agent_outcome=None,
                independently_waited_client_process_receipts=[], missing_measurements=None,
                qualification_missing_reason='No current exact-ID physical host packet has been assembled. Original contract retained; no environment denial or unsupported capability inferred.')
            if case_id in starts:
                row.update(starts[case_id])
            if case_id in raw_http:
                row.update(raw_http[case_id])
        results.append(row)
    duplicate = [ids for ids in physical_executions.values() if len(ids) != 1]
    if duplicate:
        raise ValueError('One physical client execution attributed to multiple original IDs: ' + str(duplicate))
    if len(results) != 153 or len({row['run_scoped_case_id'] for row in results}) != 153:
        raise ValueError('Original Stock153-ID inventory changed')
    return {'schema': 'lighttpd-stock-original-coverage-v1', 'qualification_authority': 'Root and existing central qualifier',
        'baseline': reference(baseline), 'original_catalog': reference(source_catalog),
        'counts': dict(Counter(row['execution_kind'] or 'not_executed_current' for row in results)),
        'original_ids': len(results), 'distinct_current_client_executions': len(physical_executions),
        'rows': results}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = inventory(args.run)
    with external_path(args.output).open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'original_ids': result['original_ids'], 'counts': result['counts']}))
