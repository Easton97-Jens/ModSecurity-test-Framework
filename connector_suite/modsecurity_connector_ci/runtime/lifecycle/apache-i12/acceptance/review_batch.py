"""Translate physical Apache batch captures into unsigned shared-role candidates.

This adapter neither evaluates expectations nor approves execution. All original
IDs are retained, including unexecuted cases and incomplete driver contracts.
"""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import argparse
import collections
import importlib.util
import json
from pathlib import Path
import re
import subprocess


def load_review():
    source = source_path('ci/runtime/lifecycle/apache-i12') / 'review.py'
    module = load_source(source)
    return module


REVIEW = load_review()
CONTROLS = load_source(Path(__file__).with_name('review_controls.py'))
read = REVIEW.read
reference = REVIEW.reference
ROLES = REVIEW.LEDGER.SHARED.ROLES
OBSERVATION_FILE = 'observation.json'
CONFIG_COMMAND_FILE = 'configtest.command.json'
CONTROLLER_RESULT_FILE = 'controller-result.json'


def optional_rows(path):
    return REVIEW.json_lines(path) if path.is_file() else None


def wire_headers(content):
    """Extract only physically present HTTP status/header bytes, even on truncation."""
    head, separator, _ = content.partition(b'\r\n\r\n')
    lines = head.split(b'\r\n')
    match = re.fullmatch(rb'HTTP/1\.[01] (\d{3})(?: .*)?', lines[0], re.ASCII)
    if match is None or not separator:
        return None
    fields = []
    for line in lines[1:]:
        name, colon, value = line.partition(b':')
        if not colon:
            return None
        fields.append([name.decode('latin1'), value.strip().decode('latin1')])
    return {'status': int(match.group(1)), 'headers': fields,
            'header_block_bytes': len(head) + len(separator),
            'entity_framing_complete': None, 'source': 'physical response.raw'}


def audit_records(text, native_id):
    """Match native serial audit A sections, never a configured header ID alone."""
    markers = list(re.finditer(r'^---(.+?)---A--\s*$', text, re.MULTILINE))
    result = []
    for index, marker in enumerate(markers):
        end = markers[index + 1].start() if index + 1 < len(markers) else len(text)
        block = text[marker.start():end]
        first = block.splitlines()[1:2]
        if first and re.search(r'\]\s+' + re.escape(native_id) + r'\s', first[0]):
            result.append({'boundary': marker.group(1), 'physical_text': block,
                           'complete_Z_section': '---' + marker.group(1) + '---Z--' in block,
                           'physical_rule_ids': re.findall(r'\[id "(\d+)"\]', block, re.ASCII)})
    return result


def resolved_metadata_head(bindings, target):
    binding = bindings.get(target)
    if not binding:
        return None
    process = subprocess.run(['rtk', 'proxy', 'git', '--git-dir=' + binding['source'],
                              'rev-parse', '--verify', 'HEAD^{commit}'],
                             capture_output=True, text=True, check=False)
    value = process.stdout.strip()
    return value if process.returncode == 0 and re.fullmatch('[0-9a-f]{40}', value) else None


def mapped_image(line, bindings, admitted):
    fields = line.split(maxsplit=5)
    if len(fields) != 6:
        return None
    loaded = fields[5]
    if not any(name in loaded for name in ('libmodsecurity.so', 'mod_security3.so')):
        return None
    for target, binding in bindings.items():
        if loaded.startswith(target + '/'):
            physical = Path(binding['source']) / loaded.removeprefix(target + '/')
            if physical.is_file():
                record = REVIEW.ORACLES.reference(physical)
                return {'mapped_path': loaded, 'admission_sha256_matches': record['sha256'] == admitted.get(loaded), **record}
    if loaded in admitted and loaded.startswith('/usr/lib/') and Path(loaded).is_file():
        record = REVIEW.ORACLES.reference(Path(loaded).resolve(strict=True))
        if record['sha256'] == admitted[loaded]:
            return {'mapped_path': loaded, 'admission_sha256_matches': True, **record}
    return None


def boundary_captures(root):
    captures = []
    io = root / 'host-io.jsonl'
    if io.is_file():
        captures.append({'reference': REVIEW.ORACLES.reference(io), 'rows': REVIEW.json_lines(io),
            'scope': 'Physical host process transcript; principal association requires independent review'})
    for name in ('host.stderr', 'error.log'):
        path = root / name
        if path.is_file():
            rows = [json.loads(line.partition('I12_APACHE_COMMON ')[2])
                    for line in path.read_text().splitlines() if 'I12_APACHE_COMMON ' in line]
            if rows:
                captures.append({'reference': REVIEW.ORACLES.reference(path), 'common_boundary_rows': rows,
                    'scope': 'Actual Common/POSIX return; not an APR open return'})
    return captures


def principal_socket_capture(rows, association, client):
    """Join successful socket bytes through one actual received request header.

    Observer emission time is after the operation. Keep the real call's entry/
    return bracket instead of treating a subsequent log timestamp as send time.
    """
    if not association:
        return None
    # host_context_associated is keyed by the native allocation scope and does
    # not promise a transport thread ID.  Preserve a captured thread ID when
    # one exists, but otherwise require the PID/method/path/time selection to
    # produce exactly one physical request before joining its socket/sequence.
    association_tid = association.get('tid')
    received = [row for row in rows if row.get('kind') == 'request_headers_received'
        and row.get('pid') == association['pid']
        and (association_tid is None or row.get('tid') == association_tid)
        and row.get('request_uri') == client['path'] and row.get('request_method') == client['method']
        and client['started_ns'] <= row['monotonic_ns'] <= client['completed_ns']
        and row.get('actual_successful_socket_bytes') is True and not row.get('invalid')]
    if len(received) != 1:
        return None
    request = received[0]
    selected = [row for row in rows if row.get('pid') == request['pid']
        and row.get('socket_inode') == request['socket_inode']
        and row.get('request_sequence') == request['request_sequence']
        and row.get('request_uri') == request['request_uri']
        and client['started_ns'] <= row['monotonic_ns'] <= client['completed_ns']
        and not row.get('invalid')]
    sent = [row for row in selected if row.get('kind') in
        ('response_status_line_sent', 'response_headers_sent')
        and row.get('actual_successful_socket_bytes') is True]
    if not sent:
        return None
    calls = [row for row in rows if row.get('kind') == 'transport_return'
        and row.get('pid') == request['pid'] and row.get('socket_inode') == request['socket_inode']
        and row.get('call') in {item['parent_call'] for item in sent}
        and row.get('stream_accounted_here') is True and row.get('reported_bytes', 0) > 0
        and not row.get('invalid')]
    if {row['call'] for row in calls} != {row['parent_call'] for row in sent}:
        return None
    return {'received_request': request, 'actual_sent_headers': sent,
            'actual_socket_call_brackets': calls,
            'precision': 'Successful socket bytes and real call entry/return intervals; emission time is not send time.'}


def backend_arrivals(transcript):
    """Count one physical request, even when arrival and completion are logged."""
    if transcript is None:
        return None
    selected = {}
    for row in transcript:
        if row.get('kind') not in ('request', 'request_arrival'):
            continue
        identity = row.get('request_id')
        if not identity:
            raise ValueError('Backend request lacks its physical request identity')
        if identity not in selected or row.get('kind') == 'request_arrival':
            selected[identity] = dict(row, path=row.get('uri'))
    return list(selected.values())


def sequence_main_client(root):
    """Normalize the principal exchange from the typed keepalive receipt."""
    capture = root / 'main/main'
    receipt_path, request_path = capture / 'receipt.json', capture / 'request.json'
    receipt, request = read(receipt_path), read(request_path)
    response = receipt.get('response')
    identifiers = [value for name, value in request.get('headers', []) if name.lower() == 'x-i12-id']
    socket_observation = receipt.get('socket', {}).get('observed_ns')
    response_completed = response.get('completed_ns') if isinstance(response, dict) else None
    if (response_completed is None and isinstance(response, dict)
            and (response.get('tcp_eof_observed') is True or response.get('tcp_reset_observed') is True)):
        response_completed = response.get('eof_ns')
    if (receipt.get('label') != 'main' or type(receipt.get('pid')) is not int
            or not isinstance(request.get('method'), str) or not isinstance(request.get('path'), str)
            or len(identifiers) != 1
            or receipt.get('request_id') != identifiers[0] or not isinstance(response, dict)
            or not all(type(value) is int for value in
                       (socket_observation, receipt.get('request_send_completed_ns'),
                        response.get('started_ns'), response_completed))
            or not socket_observation <= receipt['request_send_completed_ns'] <= response_completed):
        raise ValueError('Typed keepalive principal receipt is incomplete or inconsistent')
    error = receipt.get('error') or response.get('error')
    client = {
        'pid': receipt.get('pid'), 'started_ns': socket_observation,
        'method': request.get('method'), 'path': request.get('path'),
        'tcp_eof_observed': response.get('tcp_eof_observed'),
        'tcp_reset_observed': response.get('tcp_reset_observed'),
        'timeout_observed': (False if (error is None and response.get('framing_complete') is True)
                             or response.get('tcp_eof_observed') is True
                             or response.get('tcp_reset_observed') is True else None),
        'status': response.get('status'), 'entity_bytes': response.get('entity_bytes'),
        'entity_sha256': response.get('entity_sha256'),
        'framing': {'kind': response.get('framing'),
                    'content_lengths': response.get('content_lengths'),
                    'transfer_encoding': response.get('transfer_encoding'),
                    'encoded_entity_bytes': response.get('entity_bytes'),
                    'decoded_entity_bytes': response.get('entity_bytes'),
                    'framing_complete': response.get('framing_complete')},
        'error': error, 'recv_chunks': response.get('recv_operations'),
        'request_send_completed_ns': receipt.get('request_send_completed_ns'),
        'first_encoded_entity_recv_ns': response.get('first_entity_byte_received_ns'),
        'eof_ns': response.get('eof_ns'), 'headers': response.get('headers'),
        'completed_ns': response_completed,
    }
    return receipt_path, capture, client, root / 'main/sequence-receipt.json'


def terminated_main_client(root):
    """Normalize a signal-terminated client without inventing a response."""
    capture = root / 'main'
    receipt_path, request_path = capture / 'termination.json', capture / 'request.json'
    receipt, request = read(receipt_path), read(request_path)
    progress = receipt.get('send_checkpoint', {}).get('progress', {})
    termination = receipt.get('actual_termination', {})
    started, completed = progress.get('started_ns'), termination.get('waited_monotonic_ns')
    if (receipt.get('requested_action_performed') is not True
            or progress.get('method') != request.get('method') or progress.get('path') != request.get('path')
            or termination.get('signalled') is not True or termination.get('exited') is not False
            or type(termination.get('actual_signal')) is not int or termination.get('exit_code') is not None
            or not all(type(value) is int for value in
                       (started, progress.get('request_send_completed_ns'), completed))
            or not started <= progress['request_send_completed_ns'] <= completed):
        raise ValueError('Typed terminated-client receipt is incomplete or inconsistent')
    client = dict(progress)
    client.update(completed_ns=completed, actual_termination=termination)
    return receipt_path, capture, client, None


def main_client_capture(root):
    """Select one existing typed principal producer; no fallback data is synthesized."""
    standard = root / 'main/receipt.json'
    if standard.is_file():
        return standard, root / 'main', read(standard), None, 'standard'
    sequence = root / 'main/main/receipt.json'
    if sequence.is_file():
        return (*sequence_main_client(root), 'keepalive_sequence')
    termination = root / 'main/termination.json'
    if termination.is_file():
        return (*terminated_main_client(root), 'signal_termination')
    raise FileNotFoundError('No typed principal client receipt exists')


class BatchExtractor(REVIEW.CandidateExtractor):
    def __init__(self, attempt, spec_path, plan, case_root, bindings, controller):
        super().__init__(attempt, spec_path, plan['case_id'], None, None)
        self.attempt, self.spec_path = Path(attempt), Path(spec_path)
        self.data, self.root = self.attempt / 'data', case_root
        self.plan, self.bindings, self.controller = plan, bindings, controller
        self.controller_path = self.attempt / CONTROLLER_RESULT_FILE
        self.contract_path = case_root / 'spec.json'
        self.contract = {'original_selected_requirement': plan['original_contract']}
        self.settings_path = case_root / 'settings.json'
        self.selected_id = plan['original_id']
        self.observations = {name: {'value': None, 'reason': 'Physical observation not extracted.'}
                             for name in ROLES}
        self.checks = {}

    def load_batch_case(self):
        self.command_path = self.root / OBSERVATION_FILE
        self.command = read(self.command_path)
        if self.command['original_id'] != self.selected_id or self.command['case_id'] != self.case:
            raise ValueError('Executed observation identity differs from selected original ID')
        self.env = {}
        self.host_path, self.api_path = self.root / 'host-eos.jsonl', self.root / 'native-api.jsonl'
        self.host, self.api = optional_rows(self.host_path) or [], optional_rows(self.api_path) or []
        self.backend_path = self.root / 'backend/requests.jsonl'
        transcript = optional_rows(self.backend_path)
        self.backend_transcript = transcript
        self.backend = backend_arrivals(transcript)
        self.io_path = self.root / 'host-io.jsonl'
        self.io = optional_rows(self.io_path) or []
        (self.client_path, self.client_capture_root, self.client, self.client_aux_path,
         self.client_capture_kind) = main_client_capture(self.root)
        self.process_path = self.root / 'main/process.command.json'
        self.process = read(self.process_path) if self.process_path.is_file() else None
        self.neighbors = []
        for label in ('neighbor',):
            receipt, process = self.root / label / 'receipt.json', self.root / label / 'process.command.json'
            if receipt.is_file() and process.is_file():
                self.neighbors.append((receipt, read(receipt), process, read(process)))

    def collect_client_process(self):
        proof = reference(self.process_path, 'client_process')
        if self.client_capture_kind == 'signal_termination':
            proof = reference(self.client_path, 'client_process')
            actual = self.client['actual_termination']
            self.put('client_exit', {'exited': actual.get('exited'),
                'exit_code': actual.get('exit_code'), 'raw_wait_status': actual.get('raw_wait_status')}, proof)
            self.put('client_signal', {'signalled': actual.get('signalled'),
                'actual_signal': actual.get('actual_signal')}, proof)
            return
        code = self.process.get('waited_exit')
        if type(code) is int:
            self.put('client_exit', code, proof)
            self.put('client_signal', {'actual_signal': -code if code < 0 else None,
                'waited_exit_code': code, 'scope': 'actual waited RTK client command'}, proof)

    def collect_client(self):
        super().collect_client()
        self.raw_response = self.client_capture_root / 'response.raw'
        request = self.client_capture_root / 'request.raw'
        refs = [reference(path, 'client_process') for path in (request, self.raw_response) if path.is_file()]
        if refs:
            self.put('client_bytes', {'request_wire': request.stat().st_size if request.is_file() else None,
                'response_wire': self.raw_response.stat().st_size if self.raw_response.is_file() else None,
                'response_entity': self.client.get('entity_bytes'), 'scope': 'Wire and parsed entity distinguished'}, *refs)
            self.put('client_sha256', {'request_wire': REVIEW.ORACLES.reference(request)['sha256'] if request.is_file() else None,
                'response_wire': REVIEW.ORACLES.reference(self.raw_response)['sha256'] if self.raw_response.is_file() else None,
                'response_entity': self.client.get('entity_sha256')}, *refs)
        if self.raw_response.is_file():
            parsed = wire_headers(self.raw_response.read_bytes())
            if parsed:
                self.client['status'] = parsed['status']
                self.put('client_headers', parsed, reference(self.raw_response, 'client_process'))
            elif not self.raw_response.stat().st_size:
                self.put('client_headers', {'physical_wire_bytes': 0, 'status': None,
                    'headers': None, 'absence_observed': True}, reference(self.raw_response, 'client_process'))
        # No parsed framing on a malformed/truncated response becomes complete.
        self.client['actual_socket_recv_chunks'] = self.client.get('recv_chunks')

    def associate_main(self):
        super().associate_main()
        constructors = self.by_function['native_new'] + self.by_function['native_new_with_id']
        if len(constructors) == 1 and constructors[0].get('result') == 1:
            actual = constructors[0]
            self.native_id = actual.get('transaction_id')
            if self.native_id:
                self.put('native_transaction_id', {key: actual.get(key) for key in
                    ('transaction_id', 'canonical_transaction_id', 'transaction_id_origin')}, self.ar)

    def collect_backend(self):
        super().collect_backend()
        if self.main_backend and len(self.main_backend) == 1:
            actual = self.main_backend[0]
            emitted = [row for row in self.backend_transcript if row.get('request_id') == actual.get('request_id')]
            self.put('backend_payload_identity', {'actual_request': actual, 'physical_transcript': emitted}, self.br, self.cr)
            self.put('client_backend_correlation', {'backend': actual,
                'actual_client_method': self.client['method'], 'actual_client_path': self.client['path'],
                'request_body_hash_equal': None, 'response_body_hash_equal': None,
                'scope': 'Exact actual path/time join; wire hashes are not entity hashes'}, self.br, self.cr)

    def collect_config(self):
        self.config_path, self.rules_path = self.root / 'httpd.conf', self.root / 'rules.conf'
        refs = [reference(path, 'effective_configuration') for path in (self.config_path, self.rules_path)]
        manifests = [reference(item['ledger'], 'source_manifest') for item in self.bindings.values()]
        self.put('source_config_binding', {'sealed_bindings': self.bindings,
            'actual_effective_config_sha256': REVIEW.ORACLES.reference(self.config_path)['sha256'],
            'actual_rules_sha256': REVIEW.ORACLES.reference(self.rules_path)['sha256'],
            'spec_sha256': self.controller['spec_sha256'],
            'scope': 'Actual batch source copy, instrumented artifacts and runtime configuration; no release binary identity claim'},
            *manifests, *refs)
        if self.association:
            self.put('capability', {'actual_association': self.association,
                'actual_host_callback_kinds': dict(collections.Counter(row['kind'] for row in self.main_host)),
                'scope': 'Only the selected actual principal'}, self.hr, reference(self.contract_path, 'source_contract'))

    def collect_events(self):
        self.audit_path, self.common_path = self.root / 'audit.log', self.root / 'events.jsonl'
        self.debug_path = self.root / 'native-debug.log'
        self.physical_refs, self.native_lines, self.common_rows = [], None, None
        if self.audit_path.is_file() and self.native_id:
            self.audit_blocks = audit_records(self.audit_path.read_text(), self.native_id)
            self.native_lines = [block['physical_text'] for block in self.audit_blocks]
            self.physical_refs.append(reference(self.audit_path, 'physical_event_sink'))
        if self.common_path.is_file() and self.common_id:
            self.common_rows = [row for row in REVIEW.json_lines(self.common_path)
                                if row.get('transaction_id') == self.common_id]
            self.physical_refs.append(reference(self.common_path, 'physical_event_sink'))
        if self.physical_refs:
            self.collect_physical_events()

    def collect_commit(self):
        super().collect_commit()
        actual = principal_socket_capture(self.io, self.association, self.client)
        if actual is not None:
            self.put('commit_order', {'physical_socket_observation': actual,
                'actual_output_handoffs': self.output,
                'internal_committed_flag_returns': self.by_function['common_set_response_committed'],
                'native_p4_edges': [row for row in self.main_api if row['function'] == 'native_process_response_body'],
                'actual_client_receives': self.client.get('recv_chunks')},
                reference(self.io_path, 'host_callback'), self.hr, self.cr)
        value = self.observations['host_action'].get('value')
        if value is not None and self.raw_response.is_file():
            self.observations['host_action']['evidence'].append(reference(self.raw_response, 'client_process'))

    def collect_loaded_images(self):
        self.maps = self.maps_path.read_text()
        self.images = []
        admission_path = self.root.parent / 'admission.json'
        admitted = read(admission_path)['checked_binding']['input_sha256']
        for line in self.maps.splitlines():
            image = mapped_image(line, self.bindings, admitted)
            if image is not None and image not in self.images:
                self.images.append(image)
        self.checks['maps_snapshot_hash_matches_sampler'] = REVIEW.ORACLES.reference(self.maps_path)['sha256'] == self.first.get('maps_sha256')
        self.checks['status_snapshot_hash_matches_sampler'] = REVIEW.ORACLES.reference(self.status_path)['sha256'] == self.first.get('status_sha256')
        self.checks['sdk_and_observed_module_loaded'] = all(any(name in image['mapped_path'] for image in self.images)
            for name in ('libmodsecurity.so', 'mod_security3.so'))
        self.checks['loaded_images_match_actual_admission'] = all(image['admission_sha256_matches'] for image in self.images)
        self.put('product_host_identity', {'actual_host_pid': self.pid,
            'actual_uid': self.association.get('uid'), 'actual_gid': self.association.get('gid'),
            'actual_starttime': self.first['starttime'], 'apache_binary': REVIEW.ORACLES.reference(self.binary),
            'mapped_images': self.images, 'actual_proc_status': self.status_path.read_text(),
            'instrumented_test_module_is_not_release_byteidentity': True},
            reference(self.maps_path, 'loaded_image'), reference(self.status_path, 'loaded_image'),
            reference(self.controller_path, 'isolation_receipt'), reference(admission_path, 'isolation_receipt'))

    def collect_descriptor_differences(self):
        # Reuse existing descriptor comparison; its historical binary path is
        # deliberately absent here. Resolve the actual batch executable below.
        super().collect_descriptor_differences()
        self.first = self.selected['before_main']
        self.maps_path = self.data / 'native-process' / (self.first['files_label'] + '.maps')
        self.status_path = self.maps_path.with_suffix('.status')
        self.binary = self.root.parent / 'native-bin/apache2'
        if all(path.is_file() for path in (self.maps_path, self.status_path, self.binary)):
            self.collect_loaded_images()

    def metadata_head(self, target):
        return resolved_metadata_head(self.bindings, target)

    def packet(self):
        self.collect_client()
        self.associate_main()
        self.collect_native()
        self.collect_backend()
        self.collect_config()
        self.collect_events()
        self.collect_mime()
        self.collect_cleanup()
        self.collect_process_cleanup()
        self.collect_neighbor()
        packet = super().build_packet()
        packet['run_id'] = self.main_api[0].get('run') if self.main_api else None
        packet['driver_execution'] = {'actual_principal_execution': self.command.get('actual_principal_execution'),
            'executed_case_contract': self.command.get('executed_case_contract'),
            'missing_operations': self.command.get('missing_operations'),
            'execution_error': self.command.get('execution_error'),
            'reference': reference(self.command_path, 'host_callback')}
        packet['execution_observed'] = self.command.get('actual_principal_execution') is True
        packet['unsigned'] = True
        packet['physical_boundary_captures'] = boundary_captures(self.root)
        packet['main_client_capture'] = {'kind': self.client_capture_kind,
            'receipt': reference(self.client_path, 'client_process'),
            'auxiliary_receipt': (reference(self.client_aux_path, 'client_process')
                                  if self.client_aux_path and self.client_aux_path.is_file() else None)}
        return packet


def load_admission(attempt, spec_path):
    controller, spec = read(attempt / CONTROLLER_RESULT_FILE), read(spec_path)
    if controller.get('spec_sha256') != REVIEW.ORACLES.reference(spec_path)['sha256']:
        raise ValueError('Supplied admission spec differs from actual attempt')
    bindings = {item['target']: item for item in spec['bindings']}
    for binding in bindings.values():
        if REVIEW.ORACLES.reference(Path(binding['ledger']))['sha256'] != binding['ledger_sha256']:
            raise ValueError('Sealed binding ledger hash changed')
    return controller, spec, bindings


def empty_packet(plan, reason):
    return {'run_scoped_case_id': plan['original_id'], 'leg_id': 'apache-native',
        'actual_scenario_variant': plan['case_id'], 'original_selected_requirement': plan['original_contract'],
        'reviewed_by': None, 'unsigned': True, 'candidate_is_not_an_approval': True,
        'execution_observed': False, 'execution_kind': plan['execution_kind'], 'oracle_evaluated': False,
        'oracle_sha256': None, 'outcome': None, 'full_lifecycle_qualified': False,
        'observations': {name: {'value': None, 'reason': reason} for name in ROLES},
        'unknown_fields': list(ROLES), 'review_checks': {}, 'extraction_missing': reason}


def incomplete_packet(plan, root, reason):
    """Retain an independently captured execution without filling missing roles."""
    packet = empty_packet(plan, reason)
    observation_path = root / OBSERVATION_FILE
    if not observation_path.is_file():
        return packet
    try:
        observation = read(observation_path)
    except (OSError, ValueError, TypeError):
        return packet
    if (observation.get('original_id') != plan['original_id']
            or observation.get('case_id') != plan['case_id']):
        return packet
    key = 'actual_config_execution' if plan['execution_kind'] == 'configtest' else 'actual_principal_execution'
    packet['execution_observed'] = observation.get(key) is True
    packet['driver_execution'] = {
        'actual_principal_execution': observation.get('actual_principal_execution'),
        'actual_config_execution': observation.get('actual_config_execution'),
        'executed_case_contract': observation.get('executed_case_contract'),
        'missing_operations': observation.get('missing_operations'),
        'execution_error': observation.get('execution_error'),
        'reference': reference(observation_path, 'host_callback'),
    }
    return packet


def configuration_candidate(plan, root, attempt, spec_path, bindings, controller):
    packet = empty_packet(plan, 'Configuration-only execution has no host lifecycle observations.')
    observation = read(root / OBSERVATION_FILE)
    command = root / CONFIG_COMMAND_FILE
    paths = [root / name for name in ('httpd.conf', 'rules.conf', CONFIG_COMMAND_FILE,
                                    'configtest.stdout', 'configtest.stderr')]
    packet.update(execution_observed=observation.get('actual_config_execution') is True,
        configuration_candidate={'actual_command': read(command) if command.is_file() else None,
            'physical_files': [REVIEW.ORACLES.reference(path) for path in paths if path.is_file()],
            'sealed_bindings': bindings, 'parser_stdout': (root / 'configtest.stdout').read_text(),
            'parser_stderr': (root / 'configtest.stderr').read_text(),
            'isolation': controller, 'observation': observation, 'reviewed_by': None},
        parent_sha=resolved_metadata_head(bindings, '/mnt/git'),
        framework_sha=resolved_metadata_head(bindings, '/mnt/git-framework'),
        input_evidence=[REVIEW.ORACLES.reference(spec_path),
                        REVIEW.ORACLES.reference(attempt / CONTROLLER_RESULT_FILE)])
    for name in ('binary-identity.json', 'admission.json'):
        path = root.parent / name
        if path.is_file():
            packet['configuration_candidate'][name] = {'reference': REVIEW.ORACLES.reference(path),
                                                       'actual': read(path)}
    packet['control_candidate'] = CONTROLS.candidate(plan, root, attempt, spec_path, bindings, controller)
    return packet


def pre_native_candidate(plan, root, attempt, spec_path, bindings, controller):
    packet = empty_packet(plan, 'Host parser control has no observed main native lifecycle.')
    control = CONTROLS.candidate(plan, root, attempt, spec_path, bindings, controller)
    packet.update(execution_kind=control['execution_kind'], execution_observed=control['execution_observed'],
                  run_id=control['run_id'], native_transaction_id=None, control_candidate=control)
    return packet


def extract_all(attempt, spec_path):
    attempt, spec_path = Path(attempt).resolve(strict=True), Path(spec_path).resolve(strict=True)
    controller, spec, bindings = load_admission(attempt, spec_path)
    plan_path = Path(bindings['/mnt/fixtures']['source']) / 'case-plan.json'
    plans = read(plan_path)['rows']
    ids = [plan['original_id'] for plan in plans]
    if len(ids) != 155 or len(set(ids)) != 155 or any(not item.startswith(REVIEW.APACHE_ID_PREFIX) for item in ids):
        raise ValueError('Batch plan requires all 155 unique Apache IDs')
    argv = spec['argv']
    base = attempt / 'data' / Path(argv[argv.index('--output') + 1]).name
    packets = []
    plan_reference = REVIEW.ORACLES.reference(plan_path)
    for plan in plans:
        matches = list(base.glob('[0-9][0-9][0-9]-' + plan['case_id']))
        if len(matches) > 1:
            raise ValueError('Ambiguous physical case directory')
        root = matches[0] if matches else base / ('missing-' + plan['case_id'])
        try:
            if not (root / OBSERVATION_FILE).is_file():
                packet = empty_packet(plan, 'No actual case observation capture in this attempt.')
            elif plan['execution_kind'] == 'configtest':
                packet = configuration_candidate(plan, root, attempt, spec_path, bindings, controller)
            elif plan['case_id'] in CONTROLS.PRE_NATIVE_CASES:
                packet = pre_native_candidate(plan, root, attempt, spec_path, bindings, controller)
            else:
                extractor = BatchExtractor(attempt, spec_path, plan, root, bindings, controller)
                extractor.load_batch_case()
                packet = extractor.packet()
        except (OSError, ValueError, KeyError, TypeError) as error:
            packet = incomplete_packet(plan, root, type(error).__name__ + ': ' + str(error))
        packet['batch_plan_reference'] = plan_reference
        packets.append(packet)
    return packets


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('attempt', 'spec', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    packets = extract_all(args.attempt, args.spec)
    output = REVIEW.LEDGER.PATHS.new_output(args.output)
    output.mkdir(mode=0o700)
    index = []
    for ordinal, packet in enumerate(packets, 1):
        path = output / ('%03d.json' % ordinal)
        path.write_text(json.dumps(packet, indent=2) + '\n')
        path.chmod(0o600)
        index.append({'run_scoped_case_id': packet['run_scoped_case_id'],
            'reference': REVIEW.ORACLES.reference(path), 'execution_observed': packet['execution_observed'],
            'unknown_fields': packet['unknown_fields'], 'outcome': None,
            'full_lifecycle_qualified': False})
    (output / 'index.json').write_text(json.dumps({'unsigned': True, 'cases': index}, indent=2) + '\n')
    print(json.dumps({'cases': len(index), 'actual_executions': sum(item['execution_observed'] for item in index),
                      'approvals': 0, 'qualified_pass': 0}))


if __name__ == '__main__':
    main()
