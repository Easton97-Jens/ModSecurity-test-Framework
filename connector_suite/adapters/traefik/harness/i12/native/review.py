"""Summarize physical observations without projecting lifecycle qualification."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys


def records(path):
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def review(attempt):
    data = attempt / 'data'
    native = records(data / 'runtime/logs/native-lifecycle.jsonl')
    host = records(data / 'runtime/logs/host-lifecycle.jsonl')
    backend = records(data / 'backend/receipts.jsonl')
    cases = []
    for receipt in sorted((data / 'client').glob('*.receipt.json')):
        client = json.loads(receipt.read_text())
        tx = 'tf-' + client['label']
        direct = [row for row in native if row.get('transaction_id') == tx]
        scopes = {row['allocation_scope_call'] for row in direct
                  if row.get('allocation_join_verified') and row.get('allocation_scope_call') is not None}
        events = [row for row in native if row.get('transaction_id') == tx or
                  (row.get('allocation_join_verified') and row.get('allocation_scope_call') in scopes)]
        counters = Counter(row['function'] for row in events if row['edge'] == 'enter')
        cases.append({'label': client['label'], 'client': client,
                      'independent_backend_request_count': sum(row['request_id'] == tx for row in backend),
                      'native_enter_calls': dict(counters),
                      'verified_runtime_allocation_scopes': sorted(scopes),
                      'native_phases': sorted({row['phase'] for row in events if row.get('phase')}),
                      'native_request_eos_handoffs': sum(row['function'] == 'runtime_finish_request_body' and row['edge'] == 'enter' for row in events),
                      'native_response_eos_handoffs': sum(row['function'] == 'runtime_finish_response_body' and row['edge'] == 'enter' for row in events),
                      'host_records': [row for row in host if row.get('transaction_id') == tx],
                      'full_lifecycle_qualified': False, 'reason': 'measurements require independent original-oracle and full-packet review'})
    physical = [path for path in data.rglob('*') if path.is_file() and
                (path.suffix in ('.raw', '.json', '.jsonl', '.log') or path.name.endswith('.stdout') or path.name.endswith('.stderr'))]
    result = {'attempt': str(attempt), 'cases': cases, 'controller': json.loads((attempt / 'controller-result.json').read_text()),
              'driver': json.loads((data / 'result.json').read_text()) if (data / 'result.json').exists() else None,
              'observer_final': [row for row in native if row['function'] == 'observer' and row['edge'] == 'final'],
              'physical_evidence': {str(path.relative_to(attempt)): {'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'bytes': path.stat().st_size}
                                    for path in sorted(physical)},
              'transport_eof_is_native_eos': False, 'qualification_promoted': False}
    return result


if __name__ == '__main__':
    print(json.dumps(review(Path(sys.argv[1])), indent=2))
