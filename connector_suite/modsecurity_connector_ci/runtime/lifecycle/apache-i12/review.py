"""Extract an unsigned Apache I12 candidate from the existing physical captures.

No expected value becomes an observation, and this command never signs a Root
review or evaluates an oracle. Missing files/joins remain unknown. Root must
inspect the candidate and its physical references before independent approval.
"""
from modsecurity_test_framework.connector_context import load_source
import argparse
import collections
import importlib.util
import json
from pathlib import Path
import subprocess

def load_ledger():
    module = load_source(Path(__file__).with_name('ledger.py'))
    return module
LEDGER = load_ledger()
ORACLES = LEDGER.ORACLES
APACHE_ID_PREFIX = 'I12::apache-native::'

def read(path):
    return json.loads(LEDGER.PATHS.input_path(path).read_text())

def json_lines(path):
    return [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]

def reference(path, role):
    return {**ORACLES.reference(Path(path).resolve(strict=True)), 'role': role}

def associate(host, api, client):
    """Join one actual request to API calls by typed PID/allocation scope."""
    matches = [row for row in host if row.get('kind') == 'host_context_associated' and row.get('request_uri') == client['path'] and (row.get('request_method') == client['method']) and (client['started_ns'] <= row['monotonic_ns'] <= client['completed_ns'])]
    if len(matches) != 1:
        raise ValueError('Actual client needs exactly one timed host association')
    association = matches[0]
    pid, scope = (association['pid'], association['allocation_scope_call'])
    if scope is None:
        raise ValueError('Actual host allocation scope is missing')
    main_host = [row for row in host if row.get('pid') == pid and row.get('allocation_scope_call') == scope]
    main_api = [row for row in api if row.get('pid') == pid and row.get('allocation_scope_call') == scope and (row.get('allocation_scope_kind') == 'host')]
    return (association, main_host, main_api)


def select_main_observer_finals(api, main_api, pid):
    """Separate the host receipt from an earlier configtest PID reuse.

    The batch executes a waited configtest before ``httpd -X``.  Linux may
    reuse that exited parser's PID for the host process, so PID matching alone
    can select two separately admitted observer lifecycles.  The host receipt
    must follow the last API edge for the principal host allocation.  Earlier
    same-PID finals remain explicit evidence.  Finals inside the principal API
    window, or without a usable time, are ambiguous and must fail closed.
    """
    principal_times = [row.get('monotonic_ns') for row in main_api
                       if type(row.get('monotonic_ns')) is int]
    same_pid = [row for row in api
                if row.get('pid') == pid and row.get('edge') == 'final']
    if not principal_times:
        return [], same_pid, []
    start, boundary = min(principal_times), max(principal_times)
    pre_host, in_host_window, host = [], [], []
    for row in same_pid:
        timestamp = row.get('monotonic_ns')
        if type(timestamp) is not int or start <= timestamp <= boundary:
            in_host_window.append(row)
        elif timestamp < start:
            pre_host.append(row)
        else:
            host.append(row)
    return pre_host, in_host_window, host


def clean_observer_final(row):
    return (row.get('invalid') is False and row.get('pending_calls') == 0
            and row.get('live_mappings') == 0)

def choose_clients(data, selected_uri):
    candidates, neighbors = ([], [])
    for path in sorted((data / 'client').glob('*.receipt.json')):
        receipt = read(path)
        process_path = path.with_name(path.name.replace('.receipt.json', '.actual-process.json'))
        process = read(process_path) if process_path.is_file() else None
        item = (path, receipt, process_path, process)
        if process and process.get('role') == 'separate_original_allow_neighbor':
            neighbors.append(item)
        elif receipt.get('path') == selected_uri:
            candidates.append(item)
    if len(candidates) != 1:
        raise ValueError('Need exactly one actual main client for the selected URI')
    main = candidates[0]
    token = main[0].name.removesuffix('.receipt.json')
    neighbors = [item for item in neighbors if item[3].get('main_client_token') == token]
    return (main, neighbors)

def selected_identity(settings, contract, actual_case):
    """Preserve the original ID while naming the one permitted local variant."""
    original = contract.get('original_selected_requirement', {})
    original_name = original.get('case_id') or original.get('name')
    original_id = original.get('run_scoped_case_id')
    if original_id is None and original_name:
        original_id = APACHE_ID_PREFIX + original_name
    selected = settings.get('original_selected_id', original_id)
    if not selected or not selected.startswith(APACHE_ID_PREFIX):
        raise ValueError('Original selected ID must belong to Apache')
    if selected != original_id:
        selected_name = selected.removeprefix(APACHE_ID_PREFIX)
        declarative = {'phase3_deny_before_commit': '7de9543c83206019ae7e77f158dd7325e7713d2c31583daeb0e012bba6d67f37', 'phase3_redirect_before_commit': '61d0423437203ef2731e33b6c10d91abfd78abea59d375139c34a92a1ed8ee50'}
        if not (selected_name in declarative and original_name == selected_name + '_fixture' and (Path(settings.get('original_source_path', '')).name == selected_name + '.yaml') and (settings.get('original_source_sha256') == declarative[selected_name])):
            raise ValueError('Settings selected ID differs from exact original fixture contract')
    selected_name = selected.removeprefix(APACHE_ID_PREFIX)
    if actual_case != selected_name and (selected_name, actual_case) != ('duplicate_header_names', 'duplicate_header_names_apache_core_merged'):
        raise ValueError('Scenario aliases cannot transfer another selected original ID')
    return selected

def fd_difference(before, after):
    return {'added': {key: value for key, value in after.items() if key not in before}, 'removed': {key: value for key, value in before.items() if key not in after}, 'changed': {key: {'before': before[key], 'after': value} for key, value in after.items() if key in before and before[key] != value}, 'before_count': len(before), 'after_count': len(after), 'after_socket_targets': [value for value in after.values() if value.startswith('socket:[')]}

def mrts_gitlink(bindings):
    """Read sealed Framework Git metadata without claiming an MRTS execution."""
    binding = bindings.get('/mnt/git-framework')
    if not binding:
        return None
    result = subprocess.run(['rtk', 'proxy', 'git', '--git-dir=' + binding['source'], 'ls-tree', 'HEAD', 'tools/MRTS'], capture_output=True, text=True, check=False)
    if result.returncode:
        return None
    parts = result.stdout.strip().split()
    if len(parts) == 4 and parts[0:2] == ['160000', 'commit'] and (parts[3] == 'tools/MRTS'):
        return parts[2]
    return None

def mapped_module(line, bindings):
    """Resolve one actual mapped SDK/module image through sealed mount bindings."""
    parts = line.split(maxsplit=5)
    if len(parts) != 6 or not parts[5].startswith('/'):
        return None
    loaded = parts[5]
    if 'libmodsecurity.so' not in loaded and 'test-observed.so' not in loaded:
        return None
    physical = Path(loaded)
    for target, binding in bindings.items():
        if loaded.startswith(target + '/'):
            physical = Path(binding['source']) / loaded.removeprefix(target + '/')
            break
    if not physical.is_file():
        return None
    return {'mapped_path': loaded, **ORACLES.reference(physical.resolve(strict=True))}

class CandidateExtractor:

    def __init__(self, attempt, spec_path, case, oracle_path, evidence_branch_base):
        self.attempt = attempt
        self.spec_path = spec_path
        self.case = case
        self.oracle_path = oracle_path
        self.evidence_branch_base = evidence_branch_base

    def put(self, name, value, *proof):
        self.observations[name] = {'applicable': True, 'value': value, 'evidence': list(proof)}

    def unknown(self, name, reason):
        self.observations[name] = {'value': None, 'reason': reason}

    def load_inputs(self):
        self.attempt, self.spec_path = (Path(self.attempt).resolve(strict=True), Path(self.spec_path).resolve(strict=True))
        self.data = self.attempt / 'data'
        self.controller_path = self.attempt / 'controller-result.json'
        self.controller, self.spec = (read(self.controller_path), read(self.spec_path))
        if self.controller.get('spec_sha256') != ORACLES.reference(self.spec_path)['sha256']:
            raise ValueError('Attempt does not bind the supplied admission spec')
        self.bindings = {item['target']: item for item in self.spec['bindings']}
        for binding in self.bindings.values():
            if ORACLES.reference(Path(binding['ledger']))['sha256'] != binding['ledger_sha256']:
                raise ValueError('Sealed binding ledger hash changed')
        self.fixtures = Path(self.bindings['/mnt/fixtures']['source'])
        self.contract_path = self.fixtures / 'fixture-contract.json'
        self.contract = read(self.contract_path)
        self.settings_path = self.fixtures / 'settings.json'
        self.settings = read(self.settings_path) if self.settings_path.is_file() else {}
        self.load_command_and_clients()

    def collect_client(self):
        self.cr = reference(self.client_path, 'client_process')
        if self.process:
            self.collect_client_process()
        for field, key in (('client_headers', 'headers'), ('transport_framing', 'framing')):
            if self.client.get(key) is not None:
                self.put(field, self.client[key], self.cr)
        if all((self.client.get(key) is not None for key in ('request_bytes', 'entity_bytes'))):
            self.put('client_bytes', {'request': self.client['request_bytes'], 'response_entity': self.client['entity_bytes']}, self.cr)
        if all((self.client.get(key) is not None for key in ('request_sha256', 'entity_sha256'))):
            self.put('client_sha256', {'request': self.client['request_sha256'], 'response_entity': self.client['entity_sha256']}, self.cr)
        if all((key in self.client for key in ('tcp_eof_observed', 'tcp_reset_observed', 'timeout_observed', 'error'))):
            self.put('transport_reset_scope', {key: self.client[key] for key in ('tcp_eof_observed', 'tcp_reset_observed', 'timeout_observed', 'error')}, self.cr)

    def associate_main(self):
        self.association = None
        self.main_host, self.main_api = ([], [])
        try:
            self.association, self.main_host, self.main_api = associate(self.host, self.api, self.client)
            self.checks['one_timed_typed_host_association'] = True
        except ValueError as error:
            self.checks['one_timed_typed_host_association'] = False
            self.unknown('observed_handle_association', str(error))
        self.hr = reference(self.host_path, 'host_callback') if self.host_path.is_file() else None
        self.ar = reference(self.api_path, 'native_api') if self.api_path.is_file() else None
        self.returns = [row for row in self.main_api if row.get('edge') == 'return']
        self.by_function = collections.defaultdict(list)
        for row in self.returns:
            self.by_function[row['function']].append(row)
        self.counts = collections.Counter((row['function'] for row in self.returns))
        self.native_id = self.common_id = None
        for field, function in (('native_transaction_id', 'native_new'), ('common_transaction_id', 'common_init')):
            self.found = self.by_function[function]
            if len(self.found) == 1 and self.found[0].get('transaction_id'):
                self.put(field, {key: self.found[0].get(key) for key in ('transaction_id', 'canonical_transaction_id', 'transaction_id_origin')}, self.ar)
                if field == 'native_transaction_id':
                    self.native_id = self.found[0]['transaction_id']
                else:
                    self.common_id = self.found[0]['transaction_id']

    def collect_native(self):
        if self.association and self.main_api:
            self.joined = self.by_function['host_allocation']
            self.valid_join = len(self.joined) == 1 and self.joined[0].get('allocation_join_verified') is True and (self.joined[0].get('result') == 1)
            self.checks['successful_actual_allocation_join'] = self.valid_join
            if self.valid_join:
                self.put('observed_handle_association', {'host_association': self.association, 'actual_allocation_join': self.joined[0], 'native_transaction_id': self.native_id, 'common_transaction_id': self.common_id, 'retirement': self.by_function['host_association_retire'], 'retirement_is_bookkeeping_not_apr_memory_free': True}, self.ar)
            self.checks['no_invalid_main_observer_rows'] = not any((row.get('invalid') for row in self.main_api + self.main_host))
            self.put('native_api_returns', self.returns, self.ar)
            self.put('native_phases', [row for row in self.returns if row['function'].startswith('native_process_')], self.ar)
            self.put('native_body_chunks', [row for row in self.returns if row['function'].startswith('native_append_')], self.ar)
            self.put('native_intervention_or_first_cause', {'actual_native_intervention_returns': self.by_function['native_intervention'], 'false_return_output_fields_preserved': True}, self.ar)
            self.eos = [row for row in self.main_host if row.get('actual_apr_bucket_is_eos') is True]
            self.put('host_eos', {'actual_apr_eos_rows': self.eos, 'all_main_host_rows': self.main_host}, self.hr)
            self.put('native_eos', {'actual_apr_eos_rows': self.eos, 'native_request_finalization_returns': self.by_function['native_process_request_body'], 'native_response_finalization_returns': self.by_function['native_process_response_body'], 'append_has_no_eos_argument': None, 'semantics': 'Actual APR EOS branches joined to native finalization; no fabricated append EOS argument.'}, self.ar, self.hr)
            self.put('finish_calls', {'common_finish': self.counts['common_finish'], 'native_logging': self.counts['native_process_logging']}, self.ar)
            self.collect_finish()
            self.collect_commit()

    def collect_backend(self):
        self.main_backend = None
        if self.backend is not None:
            self.br = reference(self.backend_path, 'backend_process')
            self.main_backend = [row for row in self.backend if row.get('path') == self.client['path'] and self.client['started_ns'] <= row.get('monotonic_ns', -1) <= self.client['completed_ns']]
            self.put('backend_request_count', {'main': len(self.main_backend), 'whole_transcript': len(self.backend), 'main_rows': self.main_backend, 'selection': 'Exact path and actual client monotonic execution interval'}, self.br)
            if len(self.main_backend) == 1:
                self.actual = self.main_backend[0]
                self.put('backend_payload_identity', self.actual, self.br, self.cr)
                self.put('client_backend_correlation', {'backend': self.actual, 'actual_client_method': self.client['method'], 'actual_client_path': self.client['path'], 'request_body_hash_equal': self.actual.get('body_sha256') == self.client.get('request_sha256'), 'response_body_hash_equal': self.actual.get('response_source_body_sha256') == self.client.get('entity_sha256')}, self.br, self.cr)
            elif not self.main_backend:
                self.unknown('backend_payload_identity', 'No backend request was observed; exact unsupported/nonapplicable disposition needs independent Root review.')
                self.unknown('client_backend_correlation', 'No backend request was observed; client-only execution cannot prove payload correlation.')
        else:
            self.unknown('backend_request_count', 'Physical backend capture file is missing; zero requests cannot be inferred.')

    def collect_config(self):
        self.runtime = self.data / 'apache-lifecycle/runtime/conf'
        self.config_path, self.rules_path = (self.runtime / 'httpd.conf', self.runtime / 'modsecurity-smoke.conf')
        self.source_binding = self.bindings.get('/mnt/src')
        self.config_refs = [reference(path, 'effective_configuration') for path in (self.config_path, self.rules_path) if path.is_file()]
        if self.source_binding and len(self.config_refs) == 2:
            self.manifest_refs = [reference(self.source_binding['ledger'], 'source_manifest')]
            self.artifact_binding = self.bindings.get('/mnt/artifacts')
            if self.artifact_binding:
                self.manifest_refs.append(reference(self.artifact_binding['ledger'], 'source_manifest'))
            self.put('source_config_binding', {'sealed_source_binding': self.source_binding, 'actual_effective_config_sha256': ORACLES.reference(self.config_path)['sha256'], 'actual_rules_sha256': ORACLES.reference(self.rules_path)['sha256'], 'spec_sha256': self.controller['spec_sha256'], 'sealed_fixture_binding': self.bindings['/mnt/fixtures'], 'sealed_artifacts_binding': self.artifact_binding, 'scope': 'Historical product base plus source-copy instrumentation and exact sealed overlays; not current evidence-branch binary identity.'}, *self.manifest_refs, *self.config_refs)
        if self.main_host:
            self.put('capability', {'actual_association': self.association, 'actual_host_callback_kinds': dict(collections.Counter((row['kind'] for row in self.main_host))), 'scope': 'Only this actual selected request; no sibling capability promotion.'}, self.hr, reference(self.contract_path, 'source_contract'))

    def collect_events(self):
        self.audit_path = self.data / 'apache-lifecycle/logs/audit.log'
        self.common_path = self.data / 'apache-lifecycle/logs/phase4.log'
        self.debug_path = self.data / 'apache-lifecycle/logs/audit/native-debug.log'
        self.physical_refs = []
        self.native_lines, self.common_rows = (None, None)
        if self.audit_path.is_file() and self.native_id:
            self.native_lines = [line for line in self.audit_path.read_text().splitlines() if f'[unique_id "{self.native_id}"]' in line]
            self.physical_refs.append(reference(self.audit_path, 'physical_event_sink'))
        if self.common_path.is_file() and self.common_id:
            self.common_rows = [row for row in json_lines(self.common_path) if row.get('transaction_id') == self.common_id]
            self.physical_refs.append(reference(self.common_path, 'physical_event_sink'))
        if self.physical_refs:
            self.collect_physical_events()

    def collect_mime(self):
        if self.debug_path.is_file() and self.native_id:
            self.debug_lines = [line for line in self.debug_path.read_text().splitlines() if f'[{self.native_id}]' in line]
            self.put('mime_gate', {'actual_same_native_id_debug': self.debug_lines, 'actual_native_p4_calls': self.by_function['native_process_response_body'], 'actual_host_mime_values': [row.get('native_mime_selection') for row in self.main_host], 'scope': 'Actual SDK debug and calls; nullable public state is not converted into execution.'}, reference(self.debug_path, 'native_debug'))

    def collect_cleanup(self):
        if self.association:
            self.pid = self.association['pid']
            (self.pre_host_finals, self.in_host_window_finals,
             self.finals) = select_main_observer_finals(
                 self.api, self.main_api, self.pid)
            same_pid_finals = (self.pre_host_finals
                               + self.in_host_window_finals + self.finals)
            self.checks['same_pid_observer_finals_clean'] = (
                bool(same_pid_finals)
                and all(clean_observer_final(row) for row in same_pid_finals))
            self.checks['no_observer_final_during_principal_host_window'] = (
                not self.in_host_window_finals)
            self.checks['one_clean_native_observer_final'] = (
                not self.in_host_window_finals and len(self.finals) == 1
                and clean_observer_final(self.finals[0]))
            if same_pid_finals:
                self.put('cleanup_receipts', {
                    'actual_native_observer_finals': self.finals,
                    'actual_same_pid_pre_host_observer_finals': self.pre_host_finals,
                    'actual_same_pid_in_host_window_observer_finals': self.in_host_window_finals,
                    'selection': 'Host final is after the last principal allocation API edge; earlier same-PID configtest finals remain explicit and in-window or untimed finals fail closed.',
                    'actual_main_host_tail': self.main_host[-1:],
                    'sampler_thread_stopped': self.command.get('sampler_thread_stopped'),
                    'sampler_errors': self.command.get('native_process_sampler_errors')},
                    reference(self.command_path, 'cleanup_observer'),
                    reference(self.controller_path, 'isolation_receipt'),
                    reference(self.api_path, 'cleanup_observer'))
            self.collect_descriptor_snapshots()

    def collect_process_cleanup(self):
        if all((key in self.controller for key in ('supervisor_reaped', 'surviving_namespace_pids', 'outside_mount_leaks', 'errors'))):
            self.put('process_listener_cleanup', {key: self.controller[key] for key in ('supervisor_reaped', 'surviving_namespace_pids', 'outside_mount_leaks', 'errors', 'exitcode', 'controller_exitcode')}, reference(self.controller_path, 'isolation_receipt'), reference(self.command_path, 'cleanup_observer'))
            self.checks['controller_cleanup_clean'] = self.controller['supervisor_reaped'] is True and self.controller['surviving_namespace_pids'] == [] and (self.controller['outside_mount_leaks'] == []) and (self.controller['errors'] == [])

    def metadata_head(self, target):
        binding = self.bindings.get(target)
        path = Path(binding['source']) / 'HEAD' if binding else None
        return path.read_text().strip() if path and path.is_file() else None

    def collect_neighbor(self):
        if len(self.neighbors) == 1 and self.backend is not None:
            self.np, self.neighbor, self.npp, self.nproc = self.neighbors[0]
            self.nb = [row for row in self.backend if row.get('path') == self.neighbor['path'] and self.neighbor['started_ns'] <= row.get('monotonic_ns', -1) <= self.neighbor['completed_ns']]
            try:
                self.na, self._, self._ = associate(self.host, self.api, self.neighbor)
                self.put('neighbor_health', {'separate_actual_client': self.neighbor, 'actual_waited_process': self.nproc, 'independent_backend': self.nb, 'actual_host_association': self.na, 'same_native_host_pid': self.association is not None and self.na['pid'] == self.association['pid'], 'not_another_selected_id_execution': True}, reference(self.np, 'client_process'), reference(self.npp, 'client_process'), reference(self.backend_path, 'backend_process'))
            except ValueError as error:
                self.unknown('neighbor_health', str(error))

    def build_packet(self):
        self.packet = {'run_scoped_case_id': self.selected_id, 'actual_scenario_variant': self.case, 'original_selected_requirement': self.contract.get('original_selected_requirement'), 'leg_id': 'apache-native', 'reviewed_by': None, 'execution_observed': True, 'execution_kind': 'host_http', 'run_id': self.env.get('MSCONNECTOR_LIFECYCLE_RUN'), 'parent_sha': self.metadata_head('/mnt/git'), 'framework_sha': self.metadata_head('/mnt/git-framework'), 'evidence_branch_base': self.evidence_branch_base, 'mrts_sha': mrts_gitlink(self.bindings), 'mrts_scope': 'sealed_Framework_gitlink_metadata_only; MRTS_not_executed', 'effective_config_sha256': ORACLES.reference(self.config_path)['sha256'] if self.config_path.is_file() else None, 'rules_sha256': ORACLES.reference(self.rules_path)['sha256'] if self.rules_path.is_file() else None, 'actual_attempt': str(self.attempt), 'oracle_evaluated': False, 'oracle_sha256': None, 'outcome': None, 'full_lifecycle_qualified': False, 'observations': self.observations, 'review_checks': self.checks, 'unknown_fields': [name for name, item in self.observations.items() if item.get('value') is None], 'candidate_is_not_an_approval': True, 'input_evidence': [ORACLES.reference(self.spec_path), ORACLES.reference(self.controller_path), ORACLES.reference(self.contract_path)]}
        if self.settings_path.is_file():
            self.packet['input_evidence'].append(ORACLES.reference(self.settings_path))
        if self.oracle_path:
            self.packet['candidate_oracle'] = {'reference': ORACLES.reference(Path(self.oracle_path).resolve(strict=True)), 'effective_oracle': read(self.oracle_path), 'evaluated': False}
        for name, item in self.observations.items():
            LEDGER.SHARED.measurement(name, item, Path('unsigned-candidate-not-yet-written'))
        return self.packet

    def collect_finish(self):
        self.transitions = []
        for row in self.main_api:
            if row.get('edge') == 'enter' and row.get('contract_state') is not None:
                self.matched = [item for item in self.returns if item['call'] == row['call'] and item.get('contract_state') is not None]
                if len(self.matched) == 1:
                    self.transitions.append({'function': row['function'], 'call': row['call'], 'before': row['contract_state'], 'after': self.matched[0]['contract_state']})
        self.put('finish_transitions', {'actual_state_transitions': self.transitions, 'completed_status_3_transitions': sum((row['before']['status'] != 3 and row['after']['status'] == 3 for row in self.transitions))}, self.ar)
        self.put('native_free_calls', {'native_cleanup': self.counts['native_cleanup'], 'common_cleanup': self.counts['common_cleanup'], 'host_association_retire': self.counts['host_association_retire']}, self.ar)
        self.checks['native_cleanup_exactly_once'] = self.counts['native_cleanup'] == 1
        self.checks['common_finish_exactly_once'] = self.counts['common_finish'] == 1
        self.checks['common_cleanup_exactly_once'] = self.counts['common_cleanup'] == 1

    def collect_commit(self):
        self.output = [row for row in self.main_host if row['kind'].startswith('output_')]
        self.recv_keys = ('first_response_recv_started_ns', 'first_response_recv_completed_ns', 'headers_complete_recv_ns', 'first_encoded_entity_recv_ns', 'eof_ns', 'actual_socket_recv_chunks')
        if all((key in self.client for key in self.recv_keys)):
            self.put('commit_order', {'actual_output_handoffs': self.output, 'internal_committed_flag_returns': self.by_function['common_set_response_committed'], 'native_p4_edges': [row for row in self.main_api if row['function'] == 'native_process_response_body'], 'actual_client_receives': {key: self.client[key] for key in self.recv_keys}, 'precision': 'Blocking socket recv brackets and actual next-filter callbacks; no exact kernel send time is inferred.'}, self.hr, self.cr)
        self.put('host_action', {'actual_http_status': self.client.get('status'), 'actual_entity_bytes': self.client.get('entity_bytes'), 'host_callbacks': self.main_host, 'native_interventions': self.by_function['native_intervention']}, self.hr, self.cr)

    def collect_descriptor_snapshots(self):
        self.snapshots = [row for row in self.command.get('native_process_snapshots', []) if row.get('native_child_pid') == self.pid]
        self.selected = {}
        for label, event in (('main', self.client), *(('neighbor', item[1]) for item in self.neighbors)):
            self.before = [row for row in self.snapshots if row['monotonic_ns'] < event['started_ns']]
            self.after = [row for row in self.snapshots if row['monotonic_ns'] > event['completed_ns']]
            if self.before and self.after:
                self.selected['before_' + label] = max(self.before, key=lambda row: row['monotonic_ns'])
                self.selected['after_' + label] = min(self.after, key=lambda row: row['monotonic_ns'])
        if 'before_main' in self.selected and 'after_main' in self.selected:
            self.collect_descriptor_tables()

    def collect_descriptor_tables(self):
        self.same_start = len({row['starttime'] for row in self.selected.values()}) == 1
        self.checks['fd_snapshots_same_pid_starttime'] = self.same_start
        self.fd_paths = {label: self.data / 'native-process' / (row['files_label'] + '.fds.json') for label, row in self.selected.items()}
        if self.same_start and all((path.is_file() for path in self.fd_paths.values())):
            self.collect_descriptor_differences()

    def collect_descriptor_differences(self):
        self.fds = {label: read(path) for label, path in self.fd_paths.items()}
        self.differences = {'main': fd_difference(self.fds['before_main'], self.fds['after_main'])}
        if 'before_neighbor' in self.fds and 'after_neighbor' in self.fds:
            self.differences['neighbor'] = fd_difference(self.fds['before_neighbor'], self.fds['after_neighbor'])
        self.put('descriptor_cleanup', {'selected_same_pid_starttime_snapshots': self.selected, 'actual_fd_differences': self.differences, 'raw_fd_tables': self.fds, 'observer_added_fd_classification': 'Root must assess actual added targets; counts are not preset.'}, *(reference(path, 'cleanup_observer') for path in self.fd_paths.values()))
        self.first = self.selected['before_main']
        self.maps_path = self.data / 'native-process' / (self.first['files_label'] + '.maps')
        self.status_path = self.maps_path.with_suffix('.status')
        self.binary = self.data / 'apache-lifecycle/native-bin/apache2'
        if self.maps_path.is_file() and self.status_path.is_file() and self.binary.is_file():
            self.collect_loaded_images()

    def collect_loaded_images(self):
        self.maps = self.maps_path.read_text()
        self.images = []
        for line in self.maps.splitlines():
            entry = mapped_module(line, self.bindings)
            if entry is not None and entry not in self.images:
                self.images.append(entry)
        self.checks['maps_snapshot_hash_matches_sampler'] = ORACLES.reference(self.maps_path)['sha256'] == self.first.get('maps_sha256')
        self.checks['status_snapshot_hash_matches_sampler'] = ORACLES.reference(self.status_path)['sha256'] == self.first.get('status_sha256')
        self.checks['sdk_and_observed_module_loaded'] = any(('libmodsecurity.so' in image['mapped_path'] for image in self.images)) and any(('test-observed.so' in image['mapped_path'] for image in self.images))
        self.put('product_host_identity', {'actual_host_pid': self.pid, 'actual_uid': self.association.get('uid'), 'actual_gid': self.association.get('gid'), 'actual_starttime': self.first['starttime'], 'apache_binary': ORACLES.reference(self.binary), 'mapped_images': self.images, 'actual_proc_status': self.status_path.read_text(), 'instrumented_test_module_is_not_release_byteidentity': True}, reference(self.maps_path, 'loaded_image'), reference(self.status_path, 'loaded_image'), reference(self.attempt / 'admission.original.json', 'isolation_receipt'))

    def load_command_and_clients(self):
        self.command_path = self.data / 'apache-lifecycle-command.json'
        self.command = read(self.command_path)
        self.env = self.command['environment_overrides']
        if self.env.get('MSCONNECTOR_LIFECYCLE_CASE') != self.case:
            raise ValueError('Requested case differs from actual launched case')
        if self.settings and self.settings.get('case_id') != self.case:
            raise ValueError('Prepared settings differ from selected case')
        self.selected_id = selected_identity(self.settings, self.contract, self.case)
        if self.settings.get('original_source_path'):
            if ORACLES.reference(Path(self.settings['original_source_path']))['sha256'] != self.settings.get('original_source_sha256'):
                raise ValueError('Exact original source fixture hash changed')
        self.uri = self.settings.get('selected_uri') or self.contract.get('supplemental_contract', {}).get('request', {}).get('path')
        if not self.uri:
            raise ValueError('No source-bound selected request URI')
        self.main, self.neighbors = choose_clients(self.data, self.uri)
        self.client_path, self.client, self.process_path, self.process = self.main
        self.host_path, self.api_path, self.backend_path = (self.data / name for name in ('apache-host-eos.jsonl', 'apache-native-api.jsonl', 'apache-backend.jsonl'))
        self.host = json_lines(self.host_path) if self.host_path.is_file() else []
        self.api = json_lines(self.api_path) if self.api_path.is_file() else []
        self.backend = json_lines(self.backend_path) if self.backend_path.is_file() else None
        self.observations = {name: {'value': None, 'reason': 'No complete physical observation extracted for this field.'} for name in LEDGER.SHARED.ROLES}
        self.checks = {}

    def collect_client_process(self):
        self.pr = reference(self.process_path, 'client_process')
        if 'actual_waited_exit_code' in self.process and self.process['actual_waited_exit_code'] is not None:
            self.put('client_exit', self.process['actual_waited_exit_code'], self.pr)
        if 'actual_signal' in self.process:
            self.put('client_signal', {'actual_signal': self.process['actual_signal'], 'waited_exit_code': self.process.get('actual_waited_exit_code')}, self.pr)

    def collect_physical_events(self):
        self.event_value = {'native_transaction_id': self.native_id, 'native_audit_lines': self.native_lines, 'common_transaction_id': self.common_id, 'physical_common_rows': self.common_rows, 'common_sink_mode': oct(self.common_path.stat().st_mode & 511) if self.common_path.is_file() else None}
        self.put('native_events', self.event_value, *self.physical_refs)
        self.put('physical_event_order', {**self.event_value, 'actual_host_callbacks': self.main_host, 'actual_backend_rows': self.main_backend, 'timestamp_limit': 'Empty Common timestamps remain empty; no cross-clock ordering inferred.'}, *self.physical_refs)
        if self.common_rows is not None:
            self.terminal = [row for row in self.common_rows if row.get('message_id') != 'MSCONN_EVENT_RULE_MATCHED']
            self.put('terminal_event_count', {'actual_common_scoped_records': len(self.common_rows), 'actual_common_terminal_subset': self.terminal, 'actual_common_terminal_subset_count': len(self.terminal), 'native_audit_line_count': len(self.native_lines) if self.native_lines is not None else None, 'host_terminal_event_attempted': [row.get('terminal_event_attempted') for row in self.main_host], 'host_event_sink_error': [row.get('event_sink_error') for row in self.main_host]}, *self.physical_refs)

def extract(attempt, spec_path, case, oracle_path=None, evidence_branch_base=None):
    extractor = CandidateExtractor(attempt, spec_path, case, oracle_path, evidence_branch_base)
    extractor.load_inputs()
    extractor.collect_client()
    extractor.associate_main()
    extractor.collect_native()
    extractor.collect_backend()
    extractor.collect_config()
    extractor.collect_events()
    extractor.collect_mime()
    extractor.collect_cleanup()
    extractor.collect_process_cleanup()
    extractor.collect_neighbor()
    return extractor.build_packet()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('attempt', 'spec', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--case', required=True)
    parser.add_argument('--oracle', type=Path)
    parser.add_argument('--evidence-branch-base', help='Declared evidence branch base, separate from the actual sealed product source base')
    args = parser.parse_args()
    packet = extract(args.attempt, args.spec, args.case, args.oracle, args.evidence_branch_base)
    with LEDGER.PATHS.new_output(args.output).open('x', encoding='utf-8') as stream:
        json.dump(packet, stream, indent=2, ensure_ascii=False)
        stream.write('\n')
    print(json.dumps({'output': ORACLES.reference(args.output.absolute()), 'unknown_fields': packet['unknown_fields'], 'review_checks': packet['review_checks'], 'outcome': None, 'full_lifecycle_qualified': False}))
if __name__ == '__main__':
    main()
