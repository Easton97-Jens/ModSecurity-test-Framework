"""Package the Apache-only I12 ledger without converting partial runs into PASS.

Original contracts remain inline. Large actual observations remain in physical,
SHA256-bound packets and are addressed with JSON pointers. Unknown observations
retain their literal null values and reasons. This is a packaging adapter, not
an independent oracle evaluator or a host runner.
"""
from modsecurity_test_framework.connector_context import load_source
import argparse
import copy
import importlib.util
import json
from pathlib import Path

def load_ledger():
    module = load_source(Path(__file__).with_name('ledger.py'))
    return module
LEDGER = load_ledger()
ORACLES = LEDGER.ORACLES
ROLES = LEDGER.SHARED.ROLES

def read(path):
    return json.loads(LEDGER.PATHS.input_path(path).read_text())

def ref(path):
    return ORACLES.reference(Path(path).resolve(strict=True))

def compact_observations(observations, packet_reference, scope=None, packet=None):
    """Reference actual values rather than copying megabytes of capture rows."""
    if scope == 'configuration_control':
        if packet_reference is None or packet is None or observations != packet.get('actual_observations'):
            raise ValueError('Configuration observations must match the physical actual_observations')
        return {name: {'observed_value_reference': {
            'packet_sha256': packet_reference['sha256'],
            'json_pointer': '/actual_observations/' + name.replace('~', '~0').replace('/', '~1')}}
                for name in observations}
    if scope == 'host_pre_native_rejection':
        return compact_pre_native(observations, packet_reference, packet)
    if set(observations) != set(ROLES):
        raise ValueError('All 35 observation roles must remain explicit')
    result = {}
    for name, item in observations.items():
        if item.get('value') is None:
            result[name] = copy.deepcopy(item)
        else:
            if packet_reference is None:
                raise ValueError('A known observation requires a physical packet reference')
            result[name] = {'observed_value_reference': {'packet_sha256': packet_reference['sha256'], 'json_pointer': '/observations/' + name}, 'applicable': item.get('applicable', True)}
    return result


def compact_pre_native(observations, packet_reference, packet):
    """Bind small validated window conclusions to their physical producers."""
    if packet_reference is None or packet is None:
        raise ValueError('Pre-native observations require a physical reviewed packet')
    producers = {item['role']: ORACLES.verify_reference(item)
                 for item in packet['measurement_evidence']}
    client = read(producers['client_receipt']['path'])
    process = read(producers['client_process']['path'])
    derived = LEDGER.SHARED.pre_native_native_window(packet, producers, client)
    if observations != {'client_process': process, 'client': client, **derived}:
        raise ValueError('Pre-native observations differ from their physical producers or validated window')
    result = {name: {'observed_value_reference': {
        'packet_sha256': packet_reference['sha256'],
        'producer_reference': producers[role], 'json_pointer': ''}}
              for name, role in (('client_process', 'client_process'), ('client', 'client_receipt'))}
    binding = {'validator': 'reviewed_pre_native_packet/pre_native_native_window',
               'packet_sha256': packet_reference['sha256'],
               'measurement_evidence': [producers[role] for role in
                                        ('native_api', 'client_receipt', 'host_callback')]}
    for name, value in derived.items():
        result[name] = {'value': value, 'validated_derivation': copy.deepcopy(binding)}
        if value is None:
            result[name]['reason'] = 'No native transaction was allocated in the validated main request window.'
    return result

def check_rows(source):
    rows = source['rows']
    if source.get('scope') != 'apache-native' or len(rows) != 155:
        raise ValueError('Packaging requires the complete Apache-only 155-row adapter output')
    if source.get('original_ordered_id_sha256') != ORACLES.ID_SHA256 or source.get('original_selected_contract_sha256') != ORACLES.CONTRACT_SHA256:
        raise ValueError('Original catalog digests are missing or changed')
    seen = set()
    for row in rows:
        identity = row['run_scoped_case_id']
        if identity in seen or not identity.startswith('I12::apache-native::') or row['leg_id'] != 'apache-native':
            raise ValueError('Duplicate or foreign Apache ID')
        if row.get('required_leg') is not True or row['selected_requirement']['run_scoped_case_id'] != identity:
            raise ValueError('Selected requirement identity or mandatory membership changed')
        if row['original_oracle'] != row['selected_requirement']['expected_oracle']:
            raise ValueError('Original oracle differs from the preserved selected requirement')
        seen.add(identity)
    return rows

def oracle_summary(review):
    if review is None:
        return None
    keys = ('category', 'resolved', 'interpretation', 'scope', 'effective_oracle', 'independent_sources', 'implementation_sources', 'unsupported_applicability', 'approved_correction', 'retest')
    return {key: copy.deepcopy(review.get(key)) for key in keys}

def qualification(qualified, observed, scope=None):
    if qualified:
        return 'FULL_HOST_LIFECYCLE'
    if scope in ('configuration_control', 'host_pre_native_rejection'):
        return scope.upper()
    if observed:
        return 'PARTIAL_HOST_MEASUREMENTS'
    return 'NOT_EXECUTED'


def qualification_flags_match(row, validated):
    full = validated['full_lifecycle_qualified']
    expected_pass = full and validated['outcome'] == 'PASS'
    return (row['fresh_full_lifecycle_qualified'] == validated['full_lifecycle_qualified']
            and row['fresh_outcome'] == (validated['outcome'] if full else None)
            and row['fresh_qualified_pass'] == expected_pass)


def case_qualification(validated):
    full = validated['full_lifecycle_qualified']
    qualified = full or validated.get('full_case_qualified') is True
    return {
        'fresh_qualification_scope': validated.get('qualification_scope') or ('full_host_lifecycle' if full else None),
        'fresh_case_qualified': qualified,
        'fresh_case_outcome': validated['outcome'] if qualified else None,
        'fresh_case_qualified_pass': qualified and validated['outcome'] == 'PASS',
    }


class ApachePackage:

    def __init__(self, source_path, run_root, candidate_index, sink_readback):
        self.source_path = source_path
        self.run_root = run_root
        self.candidate_index = candidate_index
        self.sink_readback = sink_readback

    def packet_reference(self, supplied):
        receipt = ORACLES.verify_reference(supplied)
        packet = read(receipt['path'])
        digest = receipt['sha256']
        if digest not in self.packets:
            keys = ('run_scoped_case_id', 'actual_scenario_variant', 'reviewed_by', 'execution_observed', 'execution_kind', 'run_id', 'parent_sha', 'evidence_branch_base', 'framework_sha', 'mrts_sha', 'mrts_scope', 'effective_config_sha256', 'rules_sha256', 'actual_attempt', 'oracle_evaluated', 'oracle_sha256', 'outcome', 'full_lifecycle_qualified', 'qualification_scope', 'full_case_qualified', 'review_checks', 'unknown_fields', 'scope_limits')
            self.packets[digest] = {'receipt': receipt, **{key: copy.deepcopy(packet.get(key)) for key in keys}}
        return (receipt, packet)

    def add_attempt(self, path):
        if not path or path in self.attempts:
            return
        controller = Path(path) / 'controller-result.json'
        self.attempts[path] = {'attempt': path, 'controller': ref(controller) if controller.is_file() else None}

    def load_inputs(self):
        self.run_root = Path(self.run_root).resolve(strict=True)
        self.source_path = Path(self.source_path).resolve(strict=True)
        self.source = read(self.source_path)
        self.rows = check_rows(self.source)
        self.by_id = {row['run_scoped_case_id']: row for row in self.rows}
        self.candidate_index = Path(self.candidate_index) if self.candidate_index else self.run_root / 'candidate-index.json'
        self.sink_readback = Path(self.sink_readback) if self.sink_readback else self.run_root / 'sink-readback.json'
        self.candidates = read(self.candidate_index)
        self.sinks = read(self.sink_readback)
        self.packets, self.candidate_by_id, self.sinks_by_id = ({}, {}, {})
        self.attempts, self.run_indices = ({}, [])

    def collect_candidates(self):
        for entry in self.candidates:
            self.identity = entry['case_id']
            if self.identity not in self.by_id:
                raise ValueError('Candidate index contains a foreign or unknown original ID')
            self.compact = {key: copy.deepcopy(entry.get(key)) for key in ('attempt', 'variant', 'controller_exit', 'extraction_error', 'unknown_fields', 'review_checks')}
            self.add_attempt(entry.get('attempt'))
            self.supplied = entry.get('candidate')
            if self.supplied:
                self.receipt, self.packet = self.packet_reference(self.supplied)
                if self.packet['run_scoped_case_id'] != self.identity:
                    raise ValueError('Candidate packet cannot transfer to another selected ID')
                self.compact['candidate'] = self.receipt
                self.compact['actual_execution_observed'] = self.packet.get('execution_observed') is True
                self.compact['unsigned_candidate_does_not_qualify'] = True
            else:
                self.compact['candidate'] = None
                self.compact['actual_execution_observed'] = None
            self.candidate_by_id.setdefault(self.identity, []).append(self.compact)

    def collect_sinks(self):
        for entry in self.sinks['cases']:
            self.identity = entry['case_id']
            if self.identity not in self.by_id:
                raise ValueError('Sink readback contains a foreign or unknown original ID')
            self.evidence = [ORACLES.verify_reference(item) for item in entry.get('evidence', [])]
            self.add_attempt(entry.get('actual_attempt'))
            self.sinks_by_id.setdefault(self.identity, []).append({'fault': entry.get('fault'), 'actual_attempt': entry.get('actual_attempt'), 'controller_exit': entry.get('controller_exit'), 'actual_candidate_exit': entry.get('actual_candidate_exit'), 'full_lifecycle_qualified': entry.get('full_lifecycle_qualified'), 'outcome': entry.get('outcome'), 'source_readback': ref(self.sink_readback), 'json_pointer': '/cases/' + str(self.sinks['cases'].index(entry)), 'actual_clients': [{key: client.get(key) for key in ('role', 'waited_exit', 'actual_signal', 'status', 'entity_bytes', 'entity_sha256', 'backend_requests')} for client in entry.get('clients', [])], 'evidence': self.evidence, 'limitations': copy.deepcopy(entry.get('limitations'))})

    def collect_run_indices(self):
        for path in sorted(self.run_root.glob('*runs/index.json')):
            self.records = read(path)
            self.run_indices.append({'reference': ref(path), 'records': len(self.records)})
            for entry in self.records:
                self.add_attempt(entry.get('attempt'))

    def collect_rows(self):
        self.packaged = []
        for row in self.rows:
            self.collect_row(row)

    def validate_row_packet(self, row):
        self.case_fields = {'fresh_qualification_scope': None, 'fresh_case_qualified': False,
                            'fresh_case_outcome': None, 'fresh_case_qualified_pass': False}
        if self.fresh:
            self.receipt, self.packet = self.packet_reference(self.fresh['receipt'])
            self.review = row.get('oracle_reconciliation')
            self.effective = LEDGER.effective_oracle(self.review, row['original_oracle'])
            reviewer = LEDGER.packet_reviewer(row, self.packet)
            self.validated = reviewer(self.receipt, row, self.effective)
            if any((self.validated.get(key) != self.fresh.get(key) for key in ('execution_observed', 'full_lifecycle_qualified', 'outcome', 'unknown_fields', 'observations', 'qualification_scope', 'full_case_qualified'))):
                raise ValueError("Adapter's accepted packet differs from fresh shared validation")
            if (not qualification_flags_match(row, self.validated)
                    or row['fresh_execution_observed'] != self.validated['execution_observed']
                    or row['fresh_observations'] != self.validated['observations']):
                raise ValueError('Adapter qualification flags do not match its physical packet')
            self.case_fields = case_qualification(self.validated)
            self.add_attempt(self.packet.get('actual_attempt'))
        elif row['fresh_full_lifecycle_qualified'] or row['fresh_qualified_pass'] or row['fresh_outcome'] is not None:
            raise ValueError('No accepted packet means no fresh qualification')
        if any(row.get(key, value) != value for key, value in self.case_fields.items()):
            raise ValueError('Adapter case qualification does not match its physical packet')

    def collect_row(self, row):
        self.identity = row['run_scoped_case_id']
        self.old = row['historical_result']
        self.fresh = row.get('fresh_packet')
        self.receipt, self.packet = (None, None)
        self.validate_row_packet(row)
        self.raw = self.candidate_by_id.get(self.identity, [])
        self.sink_cases = self.sinks_by_id.get(self.identity, [])
        self.observed = row['fresh_execution_observed'] or any((item['actual_execution_observed'] is True for item in self.raw)) or any((item['actual_clients'] for item in self.sink_cases))
        self.qualified = row['fresh_full_lifecycle_qualified']
        self.observations = row['fresh_observations']
        self.observation_receipt = self.receipt
        self.observation_packet = self.packet
        self.observation_scope = self.case_fields['fresh_qualification_scope']
        if not self.fresh:
            self.actual_candidates = [item for item in self.raw if item.get('candidate') and item['actual_execution_observed']]
            if self.actual_candidates:
                self.observation_receipt, self.actual = self.packet_reference(self.actual_candidates[-1]['candidate'])
                self.observation_packet = self.actual
                self.observations = self.actual.get('observations', self.actual.get('actual_observations', self.observations))
                if self.actual.get('execution_kind') == 'configuration_parser':
                    self.observation_scope = 'configuration_control'
        self.packaged.append({'run_scoped_case_id': self.identity, 'leg_id': 'apache-native', 'required_leg': True, 'selected_requirement': copy.deepcopy(row['selected_requirement']), 'original_oracle': copy.deepcopy(row['original_oracle']), 'original_54_oracle_member': bool(row['original_oracle'].get('unresolved_expected_value_reason')), 'oracle_reconciliation': oracle_summary(row.get('oracle_reconciliation')), 'historical': {'status': self.old['status'], 'execution_observed': self.old.get('execution_observed'), 'qualification_scope': self.old.get('qualification_scope'), 'configuration_pass': self.old.get('qualification_scope') == 'historical_configuration_only' and self.old['status'] == 'PASS', 'full_lifecycle_pass': self.old.get('qualification_scope') == 'full_host_lifecycle' and self.old['status'] == 'PASS'}, 'fresh': {'execution_observed': bool(self.observed), 'accepted_execution_observed': row['fresh_execution_observed'], 'full_lifecycle_qualified': self.qualified, 'outcome': row['fresh_outcome'], 'qualified_pass': row['fresh_qualified_pass'], 'qualification': qualification(self.qualified, self.observed), 'accepted_packet': self.receipt, 'observation_packet': self.observation_receipt, 'observations': compact_observations(self.observations, self.observation_receipt, self.observation_scope, self.observation_packet), 'candidate_attempts': self.raw, 'sink_attempts': self.sink_cases}})

        fresh = self.packaged[-1]['fresh']
        fresh.update({key.removeprefix('fresh_'): value for key, value in self.case_fields.items()})
        fresh['qualification'] = qualification(self.qualified, self.observed,
                                               self.case_fields['fresh_qualification_scope'])

    def control_summary(self):
        result = {}
        for label, scope in (('configuration', 'configuration_control'),
                             ('pre_native', 'host_pre_native_rejection')):
            selected = [row['fresh'] for row in self.packaged
                        if row['fresh']['qualification_scope'] == scope]
            for outcome in ('PASS', 'FAIL'):
                result[f'fresh_{label}_{outcome.lower()}'] = sum(
                    row['case_outcome'] == outcome for row in selected)
        result['fresh_case_qualified_pass'] = sum(row['fresh']['case_qualified_pass'] for row in self.packaged)
        result['missing_fresh_case_qualification'] = sum(not row['fresh']['case_qualified'] for row in self.packaged)
        return result

    def summarize(self):
        self.source_summary = copy.deepcopy(self.source['summary'])
        self.result = {'schema_version': 1, 'scope': 'apache-native', 'i12_complete': False, 'packaging_does_not_qualify_runtime': True, 'original_ordered_id_sha256': self.source['original_ordered_id_sha256'], 'original_selected_contract_sha256': self.source['original_selected_contract_sha256'], 'source_full_ledger': ref(self.source_path), 'source_summary': self.source_summary, 'summary': {'required_cases': len(self.packaged), 'fresh_actual_executed_ids_including_unqualified': sum((row['fresh']['execution_observed'] for row in self.packaged)), 'fresh_full_lifecycle_pass': sum((row['fresh']['qualified_pass'] for row in self.packaged)), 'fresh_full_lifecycle_fail': sum((row['fresh']['outcome'] == 'FAIL' for row in self.packaged)), 'fresh_partial_ids': sum((row['fresh']['qualification'] == 'PARTIAL_HOST_MEASUREMENTS' for row in self.packaged)), 'fresh_not_executed_ids': sum((row['fresh']['qualification'] == 'NOT_EXECUTED' for row in self.packaged)), 'raw_attempts': len(self.attempts), 'original_open_oracle_subset': self.source_summary['original_open_oracle_subset'], 'resolved_original_oracles': self.source_summary['resolved_original_oracles'], 'unresolved_original_oracles': self.source_summary['unresolved_original_oracles']}, 'input_evidence': [ref(self.candidate_index), ref(self.sink_readback)], 'run_indices': self.run_indices, 'raw_attempts': list(self.attempts.values()), 'packet_registry': self.packets, 'rows': self.packaged}
        self.result['summary'].update(self.control_summary())
        for name in ('reviewed-packets.json', 'reviewed-oracles.json'):
            path = self.run_root / name
            if path.is_file():
                self.result['input_evidence'].append(ref(path))
        return self.result

def package(source_path, run_root, candidate_index=None, sink_readback=None):
    work = ApachePackage(source_path, run_root, candidate_index, sink_readback)
    work.load_inputs()
    work.collect_candidates()
    work.collect_sinks()
    work.collect_run_indices()
    work.collect_rows()
    return work.summarize()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-root', type=Path, required=True)
    parser.add_argument('--ledger', type=Path, required=True)
    parser.add_argument('--candidate-index', type=Path)
    parser.add_argument('--sink-readback', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = package(args.ledger, args.run_root, args.candidate_index, args.sink_readback)
    with LEDGER.PATHS.new_output(args.output).open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2, ensure_ascii=False)
        stream.write('\n')
    print(json.dumps({'output': ref(args.output), 'summary': result['summary']}))
if __name__ == '__main__':
    main()
