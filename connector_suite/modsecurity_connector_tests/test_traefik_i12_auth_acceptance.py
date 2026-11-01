"""Prevent silent fixture omissions before original-ID real-host execution."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import importlib.util
import json
from pathlib import Path
import tempfile
import sys
import types
import copy
import hashlib
import io
import os
from email.message import Message
import socket
import subprocess
import threading
import unittest
from unittest import mock


ROOT = connector_root()

from modsecurity_connector_ci.lib.i12_process_observation import ProcessObservation

HARNESS = source_path('connectors/traefik/harness/i12_auth', root=ROOT)


def load(name):
    value = load_source(HARNESS / (name + '.py'))
    return value


class AcceptanceControls(unittest.TestCase):
    def test_draft_packet_binds_explicit_retained_source_identity_path(self):
        packets = load('acceptance_packets')
        case = self.case('phase1_allow')
        case.update(classification='runtime', route='traefik-forwardauth-request',
                    original_contract={'expected_oracle': {}})
        identities = {'mrts_revision': 'a' * 40}
        source = {'source_revision': 'b' * 40, 'gitlinks': {
            'modules/ModSecurity-test-Framework': 'c' * 40}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'source-identities.json'
            path.write_text(json.dumps(identities))
            measured = {'fixture': case, 'physical_file_supplement': None}
            with mock.patch.object(packets.REVIEW, 'review_case', return_value=measured), \
                    mock.patch.object(packets.REVIEW, 'rows', return_value=[]), \
                    mock.patch.object(packets, 'observations', return_value={}):
                packet = packets.draft_packet(root, root, root, source, identities, {}, path)
                proof = packet['framework_mrts_source_identity']
                self.assertEqual(proof['path'], str(path))
                self.assertEqual(proof['sha256'], hashlib.sha256(path.read_bytes()).hexdigest())
                self.assertEqual(proof['role'], 'source_manifest')
                self.assertIsNone(packet['outcome'])
                with self.assertRaisesRegex(ValueError, 'receipt required'):
                    packets.draft_packet(root, root, root, source, identities, {})
                path.write_text('{}')
                with self.assertRaisesRegex(ValueError, 'receipt differs'):
                    packets.draft_packet(root, root, root, source, identities, {}, path)

    def test_real_rtk_file_backend_pid_is_reused_for_listen_snapshot_and_cleanup(self):
        driver = self.driver()
        owner = ProcessObservation(ROOT)
        native_path = source_path('connectors/traefik/harness/i12/native/acceptance_driver.py', root=ROOT)
        native_spec = importlib.util.spec_from_file_location('auth_real_stop_owner', native_path)
        stopper = importlib.util.module_from_spec(native_spec)
        with mock.patch.dict(sys.modules, {'base_driver': owner}): native_spec.loader.exec_module(stopper)
        external = Path(os.environ.get('CODEX_TEMP_ROOT', '/var/tmp/codex/ModSecurity-conector'))
        with tempfile.TemporaryDirectory(dir=external) as directory:
            root = Path(directory); fixtures = root / 'fixtures'; fixtures.mkdir()
            case = self.file_case('response'); self.bind_file(case, fixtures)
            for name in ('runtime', 'file-source', 'file-evidence'): (root / name).mkdir(mode=0o700)
            owner.TASK = root; handles = []; processes = {}; process = None
            environment = {key: value for key, value in os.environ.items() if key != 'PYTHONPATH'}
            with socket.socket() as reserve:
                reserve.bind(('127.0.0.1', 0)); port = reserve.getsockname()[1]
            try:
                with mock.patch.object(driver, 'base', owner), mock.patch.object(driver, 'FIXTURES', fixtures):
                    receipt = driver.start_file_backend(case, root, port, environment, handles, processes)
                    process, marker = processes['physical-file-backend']
                    self.assertNotEqual(receipt['pid'], process.pid)
                    self.assertEqual(owner.actual_pid(process, marker), receipt['pid'])
                    with self.assertRaises(RuntimeError): owner.actual_pid(process, marker + '-foreign')
                    owner.snapshot('file-backend-pid', processes)
                    snapshot = json.loads((root / 'file-backend-pid.json').read_text())
                    self.assertEqual(snapshot['processes']['physical-file-backend']['pid'], receipt['pid'])
                    cleanup = stopper.stop('physical-file-backend', process, marker)
                    self.assertEqual(cleanup['actual_pid'], receipt['pid'])
                    self.assertIsNotNone(process.poll())
                    with self.assertRaises(RuntimeError): owner.actual_pid(process, marker)
            finally:
                if process is not None and process.poll() is None: stopper.stop('physical-file-backend', process, marker)
                for handle in handles: handle.close()

    def physical_review_fixture(self, directory, direction):
        top = Path(directory); prepared = top / 'prepared'; fixtures = prepared / 'fixtures'; fixtures.mkdir(parents=True)
        case = self.file_case(direction); self.bind_file(case, fixtures)
        root = top / 'cases' / case['probe_id']; root.mkdir(parents=True)
        evidence = root / 'file-evidence'; evidence.mkdir()
        save = lambda path, value: path.write_text(json.dumps(value))
        save(fixtures / 'acceptance-manifest.json', {'cases': [case]})
        save(root / 'case.json', case)
        key = case['probe_id']; expected = case['fixture']['physical_file_supplement']['files']['benign.txt']
        source = {'pid': 42, 'uid': 65534, 'relative_path': 'benign.txt', 'expected_size': 60,
                  'expected_sha256': expected['sha256'], 'bytes': 60, 'sha256': expected['sha256'],
                  'complete': True, 'native_file_api': False, 'close': {'result': 0}, 'root_close': {'result': 0}}
        physical = {'schema': 'traefik-file-http-' + ('client' if direction == 'request' else 'backend') + '-v1',
                    'key': key, 'transaction_id': key, 'pid': 42, 'process': {'pid': 42, 'uid': 65534},
                    'file_source': source, 'native_file_api': False, 'started_ns': 10, 'completed_ns': 20}
        raw = b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok'
        head = ('POST /no-crs/request-body HTTP/1.1\r\nX-Request-Id: ' + key + '\r\nX-I12-Acceptance-Key: ' + key +
                '\r\nX-I12-Probe: ' + key + '\r\nContent-Length: 0\r\n\r\n').encode()
        command = {'started_ns': 1, 'completed_ns': 30, 'exit_code': 0, 'signal': 0}
        if direction == 'request':
            physical.update(client_response_wire_bytes=len(raw), client_response_wire_sha256=hashlib.sha256(raw).hexdigest(),
                            request_head_wire_bytes=len(head), request_head_wire_sha256=hashlib.sha256(head).hexdigest(), peer=['127.0.0.1', 12345])
            reader = evidence / (key + '.client.json'); response = evidence / (key + '.response.raw')
            (evidence / (key + '.request-head.raw')).write_bytes(head)
            driver = self.driver()
            with mock.patch.object(driver, 'FIXTURES', fixtures), mock.patch.object(driver.base, 'digest', side_effect=lambda p: hashlib.sha256(p.read_bytes()).hexdigest(), create=True):
                virtual_root = Path('/task/cases') / key
                argv = list(map(str, driver.file_command(case, virtual_root, 'client', 12345)))
            argv = [value.replace(str(fixtures), '/mnt/fixtures') for value in argv]
            command['argv'] = ['rtk', 'proxy', *argv]
            save(root / 'physical-file-client.command.json', command)
        else:
            source.update(started_ns=15, completed_ns=17, reads=[])
            physical.update(independent_backend_accept_count=1, peer=['127.0.0.1', 12345], local=['127.0.0.1', 12346],
                            started_ns=2, accepted_ns=11, request_http_eos_ns=12,
                            backend_headers_send_started_ns=13, backend_headers_sendall_returned_ns=14,
                            http_terminator_send_started_ns=18, http_terminator_sendall_returned_ns=19,
                            request_wire_bytes=len(head), request_wire_sha256=hashlib.sha256(head).hexdigest(),
                            observed_correlation={name: key for name in ('x-request-id', 'x-i12-acceptance-key', 'x-i12-probe')})
            reader = evidence / (key + '.backend.json'); response = root / 'target-0.response.raw'
            save(evidence / (key + '.backend-accept.json'), dict(physical))
            listen_path = evidence / (key + '.backend-listening.json')
            save(listen_path, {'pid': 42, 'port': 12346, 'monotonic_ns': 3})
            save(root / 'physical-file-backend.launch.json', {'proxy_pid': 41, 'monotonic_ns': 4})
            save(root / 'before-target.json', {'monotonic_ns': 5,
                 'processes': {'physical-file-backend': {'pid': 42, 'proxy_pid': 41}}})
            save(root / 'result.json', {'physical_file_backend_readiness': {'pid': 42, 'wrapper_pid': 41, 'port': 12346,
                 'receipt': '/task/cases/' + key + '/file-evidence/' + key + '.backend-listening.json',
                 'sha256': hashlib.sha256(listen_path.read_bytes()).hexdigest(), 'tcp_readiness_probe_performed': False}})
            (evidence / (key + '.backend-request.raw')).write_bytes(head)
            save(root / 'client-target.json', {'probe': key, 'requests': [{'wire_probe': key, 'raw_bytes': len(raw),
                 'raw_sha256': hashlib.sha256(raw).hexdigest()}], 'monotonic_ns': 10, 'completed_ns': 20})
            save(root / 'client-target.command.json', command)
        save(reader, physical); response.write_bytes(raw)
        return root, prepared, reader, response

    def test_physical_file_review_binds_real_paths_and_refuses_mutated_foreign_or_missing_receipts(self):
        reviewer = load('acceptance_review')
        for direction in ('request', 'response'):
            for mutation in (None, 'key', 'source', 'wire', 'client-wire', 'missing', 'prepared', 'command-window'):
                with self.subTest(direction=direction, mutation=mutation), tempfile.TemporaryDirectory() as directory:
                    root, prepared, reader, response = self.physical_review_fixture(directory, direction)
                    if mutation in ('key', 'source'):
                        value = json.loads(reader.read_text())
                        if mutation == 'key': value['key'] = 'foreign'
                        else: value['file_source']['sha256'] = '0' * 64
                        reader.write_text(json.dumps(value))
                    if mutation == 'wire':
                        if direction == 'request': response.write_bytes(response.read_bytes() + b'foreign')
                        else: (root / 'file-evidence' / (root.name + '.backend-request.raw')).write_bytes(b'foreign')
                    if mutation == 'client-wire': response.write_bytes(response.read_bytes().replace(b'ok', b'NO'))
                    if mutation == 'missing': reader.unlink()
                    if mutation == 'prepared':
                        path = prepared / 'fixtures/i12_file/acceptance.py'; path.write_text(path.read_text() + '\n')
                    if mutation == 'command-window':
                        path = root / ('physical-file-client.command.json' if direction == 'request' else 'client-target.command.json')
                        value = json.loads(path.read_text()); value['completed_ns'] = 15; path.write_text(json.dumps(value))
                    result = reviewer.physical_file_review(root, prepared)
                    self.assertEqual(result['binding_valid'], mutation is None, result)
                    if mutation is None:
                        self.assertEqual(result['paths']['response'], str(response))
                        self.assertEqual(result['client_window'], {'started_ns': 10, 'completed_ns': 20})
                        self.assertTrue(result['source_complete'])
                        self.assertIsNone(result['qualification'])
                    else: self.assertTrue(result['errors'])

    def test_response_file_review_refuses_common_foreign_pid_and_out_of_window_backend_events(self):
        reviewer = load('acceptance_review')
        for mutation in ('foreign-common-pid', 'foreign-port', 'accept-before-client', 'request-after-client',
                         'source-after-client', 'chunk-after-client', 'send-after-client', 'missing-snapshot'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root, prepared, reader, _ = self.physical_review_fixture(directory, 'response')
                def update(path, **changes):
                    value = json.loads(path.read_text()); value.update(changes); path.write_text(json.dumps(value))
                evidence = root / 'file-evidence'
                if mutation == 'foreign-common-pid':
                    for suffix in ('backend.json', 'backend-accept.json', 'backend-listening.json'):
                        path = evidence / (root.name + '.' + suffix)
                        value = json.loads(path.read_text()); value['pid'] = 99
                        if 'process' in value: value['process']['pid'] = 99
                        if 'file_source' in value: value['file_source']['pid'] = 99
                        path.write_text(json.dumps(value))
                    path = root / 'result.json'; value = json.loads(path.read_text())
                    value['physical_file_backend_readiness']['sha256'] = hashlib.sha256((evidence / (root.name + '.backend-listening.json')).read_bytes()).hexdigest()
                    path.write_text(json.dumps(value))
                elif mutation == 'foreign-port':
                    update(evidence / (root.name + '.backend-listening.json'), port=9999)
                    update(reader, local=['127.0.0.1', 9999])
                elif mutation == 'accept-before-client':
                    update(reader, accepted_ns=9); update(evidence / (root.name + '.backend-accept.json'), accepted_ns=9)
                elif mutation == 'request-after-client': update(reader, request_http_eos_ns=21)
                elif mutation == 'source-after-client':
                    value = json.loads(reader.read_text()); value['file_source']['completed_ns'] = 21; reader.write_text(json.dumps(value))
                elif mutation == 'chunk-after-client': update(reader, http_chunks=[{'started_ns': 16, 'sendall_returned_ns': 21}])
                elif mutation == 'send-after-client': update(reader, http_terminator_sendall_returned_ns=21)
                else: (root / 'before-target.json').unlink()
                result = reviewer.physical_file_review(root, prepared)
                self.assertFalse(result['binding_valid'], result)
                self.assertTrue(result['errors'])

    def test_response_file_review_separates_epoch_stat_times_from_monotonic_events(self):
        reviewer = load('acceptance_review')
        with tempfile.TemporaryDirectory() as directory:
            root, prepared, reader, _ = self.physical_review_fixture(directory, 'response')
            value = json.loads(reader.read_text()); source = value['file_source']
            stat_receipt = {'dev': 2049, 'inode': 12345, 'uid': 65534, 'gid': 65534,
                            'mode': 384, 'regular_file': True, 'size': 60, 'nlink': 1,
                            'mtime_ns': 1792600000000000000, 'ctime_ns': 1792600000000000001}
            source.update(root_stat=dict(stat_receipt, mode=448, regular_file=False),
                          pre_stat=stat_receipt, post_stat=dict(stat_receipt),
                          open_started_ns=15, opened_ns=15, eof_read_started_ns=16, eof_read_completed_ns=16,
                          close={'result': 0, 'started_ns': 16, 'completed_ns': 16},
                          root_close={'result': 0, 'started_ns': 16, 'completed_ns': 17},
                          reads=[{'started_ns': 15, 'completed_ns': 16, 'consumer_returned_ns': 16}])
            reader.write_text(json.dumps(value))
            result = reviewer.physical_file_review(root, prepared)
            self.assertTrue(result['binding_valid'], result)
            source['opened_ns'] = stat_receipt['mtime_ns']
            reader.write_text(json.dumps(value))
            self.assertFalse(reviewer.physical_file_review(root, prepared)['binding_valid'])

    def test_physical_file_packets_use_file_client_window_and_refuse_invalid_join(self):
        packets = load('acceptance_packets')
        for direction in ('request', 'response'):
            with tempfile.TemporaryDirectory() as directory:
                root, prepared, reader, response = self.physical_review_fixture(directory, direction)
                logs = root / 'runtime/logs'; logs.mkdir(parents=True)
                for name in ('native-lifecycle.jsonl', 'host-lifecycle.jsonl', 'events.jsonl'): (logs / name).write_text('')
                measured = packets.REVIEW.review_case(root, prepared)
                self.assertTrue(measured['physical_file_supplement']['binding_valid'])
                self.assertIn(str(response.relative_to(root)), measured['clients'])
                values = packets.observations(root, Path(directory) / 'attempt', prepared, measured)
                self.assertEqual(values['client_bytes']['value'], 2)
                self.assertEqual(values['client_sha256']['value'], hashlib.sha256(b'ok').hexdigest())
                if direction == 'response':
                    self.assertEqual(values['backend_request_count']['value'], 1)
                    self.assertTrue(values['client_backend_correlation']['value']['legacy_backend_rows_are_not_relabelled'])
                file_client = {'schema': 'traefik-file-http-client-v1', 'started_ns': 10, 'completed_ns': 20}
                scope = lambda when: {'native_allocation': {'monotonic_ns': when}}
                self.assertEqual(packets.target_scopes({'native_scopes': [scope(9), scope(15), scope(21)]}, file_client), [scope(15)])
                measured['physical_file_supplement'].update(binding_valid=False, errors=['foreign'])
                rejected = packets.observations(root, Path(directory) / 'attempt', prepared, measured)
                self.assertTrue(all(value['value'] is None for value in rejected.values()))

    def test_backend_chunk_parser_retains_exact_entity_and_wire_and_rejects_ambiguity(self):
        headers = Message(); headers['Transfer-Encoding'] = 'chunked'
        wire = b'2\r\nab\r\n1\r\nc\r\n0\r\n\r\n'
        stream = io.BufferedReader(io.BytesIO(wire))
        entity, observed, receipt = self.net.read_backend_body(stream, headers, trailing_check=lambda: bool(stream.peek(1)))
        self.assertEqual((entity, observed), (b'abc', wire))
        self.assertTrue(receipt['complete'])
        self.assertTrue(receipt['http_eos'])
        self.assertEqual([chunk['bytes'] for chunk in receipt['chunks']], [2, 1])
        invalid = [
            ([('Content-Length', '3'), ('Transfer-Encoding', 'chunked')], wire),
            ([('Content-Length', '3'), ('Content-Length', '3')], b'abc'),
            ([('Transfer-Encoding', 'chunked'), ('Transfer-Encoding', 'chunked')], wire),
            ([('Transfer-Encoding', 'chunked, chunked')], wire),
            ([('Content-Length', '-1')], b''),
            ([('Transfer-Encoding', 'chunked')], b'2;bad=1\r\nab\r\n0\r\n\r\n'),
            ([('Transfer-Encoding', 'chunked')], b'2\r\na'),
            ([('Transfer-Encoding', 'chunked')], b'2\r\nabNO0\r\n\r\n'),
            ([('Transfer-Encoding', 'chunked')], b'0\r\nX-Trailer: bad\r\n\r\n'),
            ([('Transfer-Encoding', 'chunked')], wire + b'trailing'),
            ([('Transfer-Encoding', 'chunked')], b'400001\r\n'),
            ([('Content-Length', '4194305')], b''),
            ([('Content-Length', '3')], b'abcTRAILING'),
            ([], b'trailing'),
        ]
        for pairs, raw in invalid:
            selected = Message()
            for name, value in pairs: selected[name] = value
            stream = io.BufferedReader(io.BytesIO(raw))
            trailing_check = lambda: bool(stream.peek(1))
            with self.subTest(headers=pairs, raw=raw[:20]), self.assertRaises(self.net.BackendBodyError) as caught:
                self.net.read_backend_body(stream, selected, trailing_check=trailing_check)
            self.assertFalse(caught.exception.receipt['complete'])
            if raw == b'2\r\na':
                self.assertEqual(caught.exception.entity, b'a')
                self.assertEqual(caught.exception.wire, raw)

    def test_real_file_client_reaches_backend_with_all60_chunked_bytes_and_physical_framing(self):
        driver = self.driver()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); fixtures = root / 'fixtures'; fixtures.mkdir()
            case = self.file_case('request'); self.bind_file(case, fixtures)
            for name in ('file-source', 'file-evidence', 'backend'): (root / name).mkdir(mode=0o700)
            original_env = {key: value for key, value in os.environ.items() if key != 'PYTHONPATH'}
            self.assertNotIn('PYTHONPATH', original_env)
            with mock.patch.object(driver, 'FIXTURES', fixtures), mock.patch.object(driver.base, 'digest', side_effect=lambda p: hashlib.sha256(p.read_bytes()).hexdigest(), create=True):
                stage_argv = driver.file_command(case, root, 'stage')
                child_env = driver.file_environment(original_env)
            self.assertEqual(child_env['PYTHONPATH'], str(fixtures / 'i12_file'))
            self.assertNotIn('PYTHONPATH', original_env)
            self.assertEqual(stage_argv[:3], ['/usr/local/bin/python3', '-P', fixtures / 'i12_file/run.py'])
            staged = subprocess.run(stage_argv, env=child_env, capture_output=True, timeout=10)
            self.assertEqual(staged.returncode, 0, staged.stderr.decode())
            handler = type('PhysicalFileBackend', (self.net.Backend,), {'root': root / 'backend', 'spec': case})
            server = self.net.http.server.ThreadingHTTPServer(('127.0.0.1', 0), handler)
            thread = threading.Thread(target=server.serve_forever); thread.start()
            try:
                with mock.patch.object(driver, 'FIXTURES', fixtures), mock.patch.object(driver.base, 'digest', side_effect=lambda p: hashlib.sha256(p.read_bytes()).hexdigest(), create=True):
                    client_argv = driver.file_command(case, root, 'client', server.server_address[1])
                result = subprocess.run(client_argv, env=child_env, capture_output=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stderr.decode())
            finally:
                server.shutdown(); thread.join(timeout=5); server.server_close()
            expected = (fixtures / 'i12_file/source-fixtures/benign.txt').read_bytes()
            self.assertEqual((root / 'backend/backend-target.request-body.raw').read_bytes(), expected)
            records = [json.loads(line) for line in (root / 'backend/backend.jsonl').read_text().splitlines()]
            request = next(row for row in records if row['event'] == 'request_body')
            self.assertEqual(request['actual_bytes'], 60)
            self.assertEqual(request['sha256'], hashlib.sha256(expected).hexdigest())
            self.assertTrue(request['complete'])
            self.assertTrue(request['framing']['physical_file_exact_match'])
            self.assertEqual(request['framing']['framing'], 'chunked')
            self.assertEqual([chunk['bytes'] for chunk in request['framing']['chunks']], [24, 24, 12])
            raw_head = (root / 'backend/backend-target.request-head.raw').read_bytes()
            self.assertIn(b'Transfer-Encoding: chunked\r\n', raw_head)
            self.assertEqual(request['request_head_wire_sha256'], hashlib.sha256(raw_head).hexdigest())
            self.assertTrue((root / 'backend/backend-target.request-body-wire.raw').read_bytes().endswith(b'0\r\n\r\n'))

    def test_backend_raw_header_receipt_redacts_folded_private_values(self):
        raw = b'POST / HTTP/1.1\r\nX-Msconnector-Response-Handle: secret1\r\n secret2\r\n\tsecret3\r\nOther: public\r\n\r\n'
        redacted = self.net.redacted_backend_head(raw)
        self.assertNotIn(b'secret', redacted)
        self.assertIn(b'Other: public\r\n', redacted)
        self.assertEqual(redacted.count(b'[REDACTED]'), 3)

    def test_native_helper_pin_rejects_old_helper_and_accepts_integrated_file4_helper(self):
        preparer = load('acceptance_prepare')
        observer = (source_path('ci/runtime/lifecycle/native-lifecycle-observer.c', root=ROOT)).read_text()
        with mock.patch.object(preparer, 'sha', return_value='00352468d73dee3b79aafd1e26ca45065e157d1f13d6a5a9785c5ad0db9a056e'):
            with self.assertRaisesRegex(ValueError, 'exact reviewed native acceptance helper'):
                preparer.native_hooks(observer)
        current = source_path('connectors/traefik/harness/i12/native/acceptance_prepare.py', root=ROOT)
        self.assertEqual(preparer.sha(current), 'cdb09aa6ba3318953f745cb3010485313ebbe3f1708b4cc1ac0f6a39f50cab6e')
        instrumented = preparer.native_hooks(observer)
        self.assertIn('i12_acceptance_retained_body(transaction, "transaction_cleanup_before_free", 0);', instrumented)
        self.assertIn('i12_acceptance_native_transaction_result(transaction, "process_request_headers", result)', instrumented)

    def file_case(self, direction):
        case = self.case('NEED-' + direction + '-file')
        case['route'] = 'traefik-forwardauth-' + ('request' if direction == 'request' else 'response-companion')
        case['id'] = 'I12::' + case['route'] + '::' + case['case_id']
        case['classification'] = 'file-capability'
        case['original_contract'] = {}
        rule = ('SecRule REQUEST_BODY "@contains no-crs-request-body-marker" '
                '"id:1100101,phase:2,deny,status:403,log,t:none"' if direction == 'request' else
                'SecRule RESPONSE_BODY "@contains no-crs-response-body-marker" '
                '"id:1100301,phase:4,deny,status:403,log,t:none"')
        case['fixture']['rules_lines'].append(rule)
        return case

    def bind_file(self, case, fixtures):
        return load('acceptance_prepare').bind_file_supplements([case], [case['id']], ROOT, fixtures)

    def test_file_supplements_require_explicit_ids_and_ledger_all_sources(self):
        preparer = load('acceptance_prepare')
        for direction in ('request', 'response'):
            with self.subTest(direction=direction), tempfile.TemporaryDirectory() as directory:
                fixtures = Path(directory)
                case = self.file_case(direction)
                original = copy.deepcopy(case)
                self.assertEqual(preparer.bind_file_supplements([case], None, ROOT, fixtures), [])
                self.assertEqual(case, original)
                self.assertEqual(list(fixtures.iterdir()), [])
                self.assertEqual(self.bind_file(case, fixtures), [case['id']])
                binding = self.controls.file_binding(case)
                self.assertFalse(binding['native_file_api'])
                self.assertEqual(binding['original_fixture_sha256'], original['fixture_sha256'])
                self.assertEqual(binding['fixture'], 'benign.txt')
                staged = fixtures / 'i12_file'
                for filename in ('run.py', 'source.py', 'http_stream.py', 'manifest.json', 'supplement-plan.json'):
                    self.assertTrue((staged / filename).is_file(), filename)
                for filename, spec in binding['files'].items():
                    path = staged / 'source-fixtures' / filename
                    self.assertEqual(path.stat().st_size, spec['size'])
                    self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), spec['sha256'])
                self.assertEqual(hashlib.sha256((staged / 'manifest.json').read_bytes()).hexdigest(), binding['manifest_sha256'])
                self.assertNotEqual(case['fixture_sha256'], original['fixture_sha256'])
                self.assertEqual(case['fixture']['request']['body_hex'], '')

    def test_file_binding_rejects_other_ids_routes_rules_and_mutations(self):
        preparer = load('acceptance_prepare')
        for mutation in ('wrong-id', 'duplicate', 'classification', 'route'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                case = self.file_case('request'); selected = [case['id']]
                if mutation == 'wrong-id': selected = ['missing']
                if mutation == 'duplicate': selected *= 2
                if mutation == 'classification': case['classification'] = 'runtime'
                if mutation == 'route': case['route'] = 'traefik-forwardauth-response-companion'
                root = Path(directory)
                with self.assertRaises(ValueError): preparer.bind_file_supplements([case], selected, ROOT, root)
        with tempfile.TemporaryDirectory() as directory:
            case = self.file_case('request'); self.bind_file(case, Path(directory))
            for changes in ({'native_file_api': True}, {'fixture': 'response-marker.txt'}, {'explicit_original_id': 'different'},
                            {'fixture': 'request-outside-sample.txt'}, {'host_capacity_control': True}):
                mutated = copy.deepcopy(case); mutated['fixture']['physical_file_supplement'].update(changes)
                with self.subTest(changes=changes), self.assertRaises(ValueError): self.controls.file_binding(mutated)

    def test_file_supplement_binds_independent_rules_instead_of_legacy_capability_placeholder(self):
        with tempfile.TemporaryDirectory() as directory:
            case = self.file_case('request')
            case['fixture']['rules_lines'] = list(self.catalog.BASE_RULES)
            self.bind_file(case, Path(directory))
            rules = '\n'.join(case['fixture']['rules_lines']) + '\n'
            binding = self.controls.file_binding(case)
            self.assertIn('id:1100101,phase:2,deny,status:403', rules)
            self.assertIn('id:1100301,phase:4,deny,status:403', rules)
            self.assertEqual(hashlib.sha256(rules.encode()).hexdigest(), binding['rules_sha256'])

    def test_file_controls_separate_host_capacity_native_decision_and_safe_commit(self):
        validator = load('acceptance_validate')
        for direction in ('request', 'response'):
            with tempfile.TemporaryDirectory() as directory:
                case = self.file_case(direction); self.bind_file(case, Path(directory))
                values = self.controls.controls(case)
                self.assertTrue(validator.provenance_mode(case))
                if direction == 'request':
                    self.assertEqual([v['independent_control_expectation']['visible_status'] for v in values], [403, 401])
                    self.assertEqual([validator.provenance_mode(v) for v in values], [True, False])
                    native, host = [v['independent_control_expectation'] for v in values]
                    self.assertEqual(native['visible_body_hex'], b'request denied\n'.hex())
                    self.assertEqual((native['native_rule_id'], native['native_phase'], native['backend_arrivals']), (1100101, 2, 0))
                    self.assertEqual((host['authorization_arrivals'], host['native_transactions'], host['backend_arrivals']), (0, 0, 0))
                else:
                    safe, strict = values
                    self.assertEqual(safe['fixture']['policy']['phase4_mode'], 'safe')
                    self.assertEqual(safe['independent_control_expectation']['visible_status'], 200)
                    self.assertEqual(safe['independent_control_expectation']['native_phase'], 4)
                    self.assertTrue(safe['independent_control_expectation']['actual_commit_and_client_bytes_required'])
                    self.assertEqual(strict['classification'], 'config')
                    self.assertEqual(strict['fixture']['policy']['phase4_mode'], 'strict')
                    self.assertTrue(strict['probe_id'].endswith('-strict-admission'))
                self.assertTrue(all(v['fixture_sha256'] is None for v in values))
                for value in [case, *values]:
                    keys = [v for k, v in value['fixture']['request']['headers'] if k.lower() == 'x-i12-acceptance-key']
                    self.assertEqual(keys, [value['probe_id']])

    def test_file_response_router_is_exclusive_and_neighbors_keep_regular_backend(self):
        import yaml
        validator = load('acceptance_validate')
        driver = self.driver()
        for direction in ('request', 'response'):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory); fixtures = root / 'fixtures'; fixtures.mkdir()
                case = self.file_case(direction); self.bind_file(case, fixtures)
                for part in ('runtime/effective-config', 'runtime/logs', 'sockets'): (root / part).mkdir(parents=True, exist_ok=True)
                helper = load_source(source_path('connectors/traefik/scripts/runtime_smoke.py', root=ROOT))
                _, path = driver.configuration(case, root, helper, 1234, 1235, root / 'sockets/companion.sock', 1236)
                self.assertEqual(validator.validate(path, case)['effective_auth_contract']['maxResponseBodySize'], 32768)
                config = yaml.safe_load(path.read_text())
                self.assertEqual(config['http']['routers']['healthy-neighbor']['service'], 'upstream')
                if direction == 'response':
                    target = config['http']['routers']['physical-file-target']
                    self.assertIn(case['probe_id'], target['rule'])
                    self.assertIn('!Header(`X-I12-Neighbor`, `1`)', target['rule'])
                    self.assertEqual(target['priority'], 200)
                    for mutation in ('rule', 'service', 'priority', 'middlewares', 'entryPoints'):
                        changed = copy.deepcopy(config)
                        changed['http']['routers']['physical-file-target'][mutation] = None
                        path.write_text(yaml.safe_dump(changed))
                        with self.subTest(mutation=mutation), self.assertRaises(ValueError): validator.validate(path, case)
                else:
                    self.assertNotIn('physical-file-target', config['http']['routers'])

    def test_file_reader_commands_pin_manifest_and_do_not_decode_memory_payload(self):
        driver = self.driver()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); fixtures = root / 'fixtures'; fixtures.mkdir()
            case = self.file_case('request'); self.bind_file(case, fixtures)
            with mock.patch.object(driver, 'FIXTURES', fixtures), mock.patch.object(driver.base, 'digest', side_effect=lambda p: hashlib.sha256(p.read_bytes()).hexdigest(), create=True):
                argv = driver.file_command(case, root, 'client', 19876)
                self.assertEqual(argv[:3], ['/usr/local/bin/python3', '-P', fixtures / 'i12_file/run.py'])
                self.assertIn('--private-root', argv)
                self.assertEqual(argv[argv.index('--fixture') + 1], 'benign.txt')
                self.assertNotIn('--body-hex', argv)
                manifest = fixtures / 'i12_file/manifest.json'; manifest.write_text(manifest.read_text() + ' ')
                with self.assertRaisesRegex(ValueError, 'manifest differs'): driver.file_command(case, root, 'client', 19876)

    def test_file_backend_readiness_uses_pid_bound_listen_receipt_without_tcp_probe(self):
        driver = self.driver()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); fixtures = root / 'fixtures'; fixtures.mkdir()
            case = self.file_case('response'); self.bind_file(case, fixtures)
            evidence = root / 'file-evidence'; evidence.mkdir()
            path = evidence / (case['probe_id'] + '.backend-listening.json')
            path.write_text(json.dumps({'pid': 4321, 'port': 19876, 'monotonic_ns': 1}))
            process = types.SimpleNamespace(pid=1234, poll=lambda: None)
            processes = {}
            with mock.patch.object(driver, 'FIXTURES', fixtures), mock.patch.object(driver.base, 'digest', side_effect=lambda p: hashlib.sha256(p.read_bytes()).hexdigest(), create=True), mock.patch.object(driver.base, 'start', return_value=process, create=True), mock.patch.object(driver.base, 'actual_pid', return_value=4321, create=True), mock.patch.object(socket, 'create_connection', side_effect=AssertionError('must not consume target accept')):
                receipt = driver.start_file_backend(case, root, 19876, {}, [], processes)
                self.assertEqual(receipt['pid'], 4321)
                self.assertEqual(receipt['wrapper_pid'], 1234)
                self.assertFalse(receipt['tcp_readiness_probe_performed'])
                self.assertIn('physical-file-backend', processes)
                path.write_text(json.dumps({'pid': 9999, 'port': 19876}))
                with self.assertRaisesRegex(RuntimeError, 'identity differs'): driver.start_file_backend(case, root, 19876, {}, [], {})

    def driver(self):
        with mock.patch.dict(sys.modules, {'base_driver': types.SimpleNamespace()}), mock.patch.object(sys, 'path', [str(HARNESS), *sys.path]):
            return load('acceptance_driver')

    def effective(self, directory, case):
        root = Path(directory)
        (root / 'runtime/effective-config').mkdir(parents=True)
        (root / 'runtime/logs').mkdir()
        (root / 'sockets').mkdir(mode=0o700)
        helper = load_source(source_path('connectors/traefik/scripts/runtime_smoke.py', root=ROOT))
        case['route'] = 'traefik-forwardauth-request'
        _, path = self.driver().configuration(case, root, helper, 1234, 1235, root / 'sockets/companion.sock')
        return path

    def test_provenance_effective_chain_and_atomic_settings(self):
        validator = load('acceptance_validate')
        import yaml
        with tempfile.TemporaryDirectory() as directory:
            case = self.case('phase1_allow')
            path = self.effective(directory, case)
            self.assertEqual(validator.validate(path, case)['observer_mode'], 'trusted-provenance')
            original = yaml.safe_load(path.read_text())
            for route in ('smoke', 'healthy-neighbor'):
                for change in ('missing-inner','duplicate-inner','missing-outer','duplicate-outer','order'):
                    value = copy.deepcopy(original)
                    chain = value['http']['routers'][route]['middlewares']
                    if change == 'missing-inner': chain.pop()
                    if change == 'duplicate-inner': chain.append(chain[-1])
                    if change == 'missing-outer': chain.pop(0)
                    if change == 'duplicate-outer': chain.insert(0,chain[0])
                    if change == 'order': chain.reverse()
                    path.write_text(yaml.safe_dump(value))
                    with self.subTest(route=route, change=change), self.assertRaises(ValueError): validator.validate(path,case)
            for key,value in [('socketPath','/wrong'),('provenanceSocketPath','/wrong'),('runID','wrong'),('transportCaseID','wrong'),('timeoutMillis',0)]:
                changed=copy.deepcopy(original)
                changed['http']['middlewares']['modsecurity-response-observer']['plugin']['modsecurityResponseObserver'][key]=value
                path.write_text(yaml.safe_dump(changed))
                with self.subTest(key=key),self.assertRaises(ValueError):validator.validate(path,case)
            changed=copy.deepcopy(original)
            changed['http']['middlewares']['modsecurity-forwardauth']['forwardAuth']['maxResponseBodySize']=32769
            path.write_text(yaml.safe_dump(changed))
            with self.assertRaises(ValueError):validator.validate(path,case)
            for key,value in [('socketPath','/wrong'),('confirmProvenance',False),('provenanceSocketPath','/unexpected')]:
                changed=copy.deepcopy(original)
                changed['http']['middlewares']['modsecurity-response-observer-confirm']['plugin']['modsecurityResponseObserver'][key]=value
                path.write_text(yaml.safe_dump(changed))
                with self.subTest(inner_key=key),self.assertRaises(ValueError):validator.validate(path,case)
            for names in ([],['X-Msconnector-Trusted-Reservation']*2):
                changed=copy.deepcopy(original)
                auth=changed['http']['middlewares']['modsecurity-forwardauth']['forwardAuth']
                auth['authRequestHeaders']=[name for name in auth['authRequestHeaders'] if name!='X-Msconnector-Trusted-Reservation']+names
                path.write_text(yaml.safe_dump(changed))
                with self.assertRaises(ValueError):validator.validate(path,case)
            for name in ('X-Msconnector-Response-Handle','x-MSCONNECTOR-response-handle'):
                changed=copy.deepcopy(original)
                changed['http']['middlewares']['modsecurity-forwardauth']['forwardAuth']['authRequestHeaders'].append(name)
                path.write_text(yaml.safe_dump(changed))
                with self.assertRaisesRegex(ValueError,'response handle forbidden'):validator.validate(path,case)

    def test_default_handle_controls_cannot_become_provenance(self):
        validator=load('acceptance_validate')
        for mode in ('missing','malformed','unknown64hex','expired'):
            with tempfile.TemporaryDirectory() as directory:
                case=self.case('NEED-observer-response-eos');case['fixture']['relay']['handle']=mode
                path=self.effective(directory,case)
                self.assertEqual(validator.validate(path,case)['observer_mode'],'default-mrc1')
                self.assertNotIn('provenanceSocketPath',path.read_text())
                env=self.driver().case_environment(case,Path(directory),{'MSCONNECTOR_TRAEFIK_PROVENANCE_SOCKET':'stale'},1,2)
                self.assertNotIn('MSCONNECTOR_TRAEFIK_PROVENANCE_SOCKET',env)

    def test_host_limit_controls_retain_default_mrc1_without_outer_attestation(self):
        validator=load('acceptance_validate');controls=load('acceptance_controls')
        for name,statuses in (('NEED-host-request-buffer-bound',[200,401]),('NEED-host-auth-response-32768-bound',[200,401])):
            case=self.case(name);children=controls.controls(case)
            self.assertEqual([child['independent_control_expectation']['visible_status'] for child in children],statuses)
            for selected in [case,*children]:
                with tempfile.TemporaryDirectory() as directory:
                    path=self.effective(directory,selected)
                    self.assertEqual(validator.validate(path,selected)['observer_mode'],'default-mrc1')
                    self.assertNotIn('provenanceSocketPath',path.read_text())
                    self.assertNotIn('confirmProvenance',path.read_text())
                    env=self.driver().case_environment(selected,Path(directory),{'MSCONNECTOR_TRAEFIK_PROVENANCE_SOCKET':'stale'},1,2)
                    self.assertNotIn('MSCONNECTOR_TRAEFIK_PROVENANCE_SOCKET',env)
            self.assertTrue(validator.provenance_mode(self.case('keepalive_allow_allow')))
        for name in validator.HOST_BOUNDARY_CASES:
            with self.subTest(host_boundary=name),tempfile.TemporaryDirectory() as directory:
                case=self.case(name);path=self.effective(directory,case)
                self.assertEqual(validator.validate(path,case)['observer_mode'],'default-mrc1')

    def test_capacity_fixture_uses_actual34_request_and_separate40019_application_body(self):
        for name in ('NEED-host-auth-response-32768-bound','NEED-32768-auth-response-not-application-response'):
            case=self.case(name);case['fixture']['request'].update(body_hex=(b'R'*34).hex(),chunk_lengths=[34])
            fixture=self.catalog.normalize_fault(case['fixture'],name,'traefik-forwardauth-request')
            binding=fixture['explicit_capacity_fixture_binding']
            self.assertEqual(binding['actual_request_body_bytes'],34)
            self.assertEqual(binding['frozen_proposal_declared_request_bytes'],15)
            self.assertIsNone(binding['runtime_inspection_bytes'])
            if name=='NEED-32768-auth-response-not-application-response':
                self.assertEqual(binding['application_response_bytes'],40019)
                self.assertEqual(sum(fixture['backend']['chunk_lengths']),40019)
            else:
                self.assertTrue(all(v['independent_control_expectation']['actual_request_body_bytes']==34
                    for v in self.controls.controls(case)))

    def test_private_headers_redact_duplicates_and_case_without_losing_counts(self):
        token='a'*64
        headers=[('X-Msconnector-Trusted-Reservation',token),('x-MSCONNECTOR-trusted-reservation','bad'),('X-Msconnector-Response-Handle',token),('Other','visible')]
        serialized=json.dumps(self.net.redact_headers(headers))
        self.assertNotIn(token,serialized)
        self.assertNotIn('bad',serialized)
        receipt=self.net.private_header_receipt(headers)
        self.assertEqual(receipt['x-msconnector-trusted-reservation']['count'],2)
        self.assertFalse(receipt['x-msconnector-trusted-reservation']['all_values_valid_64hex'])
        self.assertTrue(all(row['absent'] for row in self.net.private_header_receipt([]).values()))

    def test_same_live_socket_requires_fd_inode_tuple_and_pid(self):
        with socket.socket() as server:
            server.bind(('127.0.0.1',0));server.listen(1)
            with socket.create_connection(server.getsockname()) as client:
                peer,_=server.accept()
                with peer:
                    before=self.net.socket_identity(client);after=self.net.socket_identity(client)
                    self.assertTrue(self.net.same_live_socket(before,after))
                    for key in ('fd','socket_inode','socket_device','local_port','peer_port','pid'):
                        self.assertFalse(self.net.same_live_socket(before,{**after,key:after[key]+1}))
                    result={};self.net.close_client_socket(client,result,1,'test')
                    self.assertEqual(result['connection_ends'][0]['fd_after_close'],-1)
        self.assertFalse(self.net.same_live_socket(before,None))

    def test_private_toolchain_is_internal_and_rejects_environment_and_artifact_tampering(self):
        driver=self.driver();root='/mnt/artifacts/toolchains/go1.27.2'
        inputs={'PATH':driver.CONTROLLER_PATH}
        expected={'GO':root+'/bin/go','GOROOT':root,'PATH':root+'/bin:/opt/controller:/usr/local/bin:/usr/bin:/usr/sbin:/bin','GOTOOLCHAIN':'local'}
        with mock.patch.object(Path,'resolve',lambda path,strict=False:path), mock.patch.object(Path,'read_text',return_value='go1.27.2\ntime 2026-10-01\n'), mock.patch.object(driver.base,'digest',return_value=driver.GO_SHA256,create=True):
            self.assertEqual(driver.toolchain_environment(inputs),expected)
            import shutil
            # The sealed mount supplies RTK only under /opt/controller.
            with mock.patch('shutil.os.path.exists', return_value=True), \
                 mock.patch('shutil.os.path.isdir', return_value=False), \
                 mock.patch('shutil.os.access', side_effect=lambda path, mode: path == '/opt/controller/rtk'):
                self.assertEqual(shutil.which('rtk', path=driver.toolchain_environment(inputs)['PATH']), '/opt/controller/rtk')
            for changes in ({'GOROOT':root},{'GO':root+'/bin/go'},{'GOROOT':'/usr/local/go'},{'GO':'/usr/local/go/bin/go'},
                            {'PATH':'/usr/bin:'+root+'/bin'},{'GOTOOLCHAIN':'auto'},{'GOTOOLCHAIN':'local'}):
                with self.assertRaises(RuntimeError):driver.toolchain_environment({**inputs,**changes})
            with self.assertRaises(RuntimeError):driver.toolchain_environment({})
            with mock.patch.object(driver.base,'digest',return_value='wrong'):
                with self.assertRaises(RuntimeError):driver.toolchain_environment(inputs)
            with mock.patch.object(Path,'read_text',return_value='go1.26.1\n'):
                with self.assertRaises(RuntimeError):driver.toolchain_environment(inputs)
            with mock.patch.object(Path,'resolve',return_value=Path('/usr/local/go')):
                with self.assertRaises(RuntimeError):driver.toolchain_environment(inputs)

    def test_generated_seal_spec_keeps_private_runtime_v5_admission_environment_empty(self):
        with mock.patch.object(sys,'path',[str(HARNESS),*sys.path]):sealer=load('acceptance_seal')
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);prepared=root/'request-v99';isolation=root/'isolation'
            fixtures=prepared/'fixtures';source=prepared/'source'
            fixtures.mkdir(parents=True);source.mkdir();isolation.mkdir()
            (fixtures/'acceptance-manifest.json').write_text(json.dumps({'selected_route':'traefik-forwardauth-request','cases':[{'id':'original-id'}]}))
            (fixtures/'acceptance_validate.py').write_bytes(Path(sealer.acceptance_validate.__file__).read_bytes())
            (source/'.i12-source-export-manifest.json').write_text(json.dumps({'source_revision':'sealed-head'}))
            artifacts=root/'artifacts';toolchain=artifacts/'toolchains/go1.27.2';(toolchain/'bin').mkdir(parents=True)
            (toolchain/'bin/go').write_bytes(b'fixture-go');(toolchain/'VERSION').write_text('go1.27.2\n')
            ledger=root/'artifact-ledger.json';expected_go=self.driver().GO_SHA256
            ledger.write_text(json.dumps({'files':{'toolchains/go1.27.2/bin/go':expected_go}}))
            artifact_binding=root/'artifact-binding.json'
            artifact_binding.write_text(json.dumps({'target':'/mnt/artifacts','source':str(artifacts),'ledger':str(ledger),'ledger_sha256':sealer.sha(ledger)}))
            # Even a stale template must never carry forbidden variables into
            # private-runtime-v5's unchanged read_spec environment allowlist.
            (isolation/'request-v12-spec.json').write_text(json.dumps({'environment':{'GO':'bad','GOROOT':'bad','PATH':'bad','GOTOOLCHAIN':'auto'}}))
            original_sha=sealer.sha
            with mock.patch.object(sealer,'ROOT',root),mock.patch.object(sealer,'ISOLATION',isolation),mock.patch.object(sealer.os,'geteuid',return_value=0),mock.patch.object(sealer,'binding',side_effect=lambda source,label,target:{'target':target}),mock.patch.object(sealer,'sha',side_effect=lambda path:expected_go if path==toolchain/'bin/go' else original_sha(path)):
                receipt=sealer.seal(prepared,artifact_binding)
            spec=json.loads(Path(receipt['spec']).read_text())
            # Exact private-runtime-v5 read_spec allowlist contract. This is a
            # portable regression test; it does not import the private controller.
            allowed={'CONNECTOR_ROOT','FRAMEWORK_ROOT','RUNTIME_ROOT','BUILD_ROOT','VERIFIED_RUN_ROOT','MODSEC_SMOKE_ROOT','LIGHTTPD_PATCHED_ROOT','NGINX_BINARY','APACHE_BINARY','APACHE_MODULE','RULES_FILE','RUN_ID','FIXTURE_ID','FRAMEWORK_OUTPUT_ROOT','PYTHON','TMP_ROOT','EVENT_OUTPUT_ROOT'}
            self.assertEqual(spec['environment'],{})
            self.assertFalse(set(spec['environment'])-allowed)
            self.assertFalse(set(spec['environment'])&{'GO','GOROOT','PATH','GOTOOLCHAIN'})

    def test_private_socket_receipt_requires_socket_owner_and_modes(self):
        driver=self.driver()
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);root.chmod(0o700);path=root/'mtp.sock'
            with socket.socket(socket.AF_UNIX) as listener:
                listener.bind(str(path));path.chmod(0o600)
                receipt=driver.provenance_socket_receipt(path)
                self.assertTrue(receipt['is_socket']);self.assertGreater(receipt['inode'],0)
                self.assertEqual(receipt['parent_observed_by'],'lstat')
                self.assertTrue(receipt['parent_is_directory'])
                self.assertFalse(receipt['parent_is_symlink'])
                self.assertEqual(receipt['parent_uid'],root.lstat().st_uid)
                self.assertEqual(receipt['parent_gid'],root.lstat().st_gid)
                actual_parent=root.lstat();actual_socket=path.lstat()
                for field in ('st_uid','st_gid'):
                    parent_values={key:getattr(actual_parent,key) for key in ('st_mode','st_uid','st_gid','st_ino','st_dev')}
                    parent_values[field]+=1
                    wrong_parent=types.SimpleNamespace(**parent_values)
                    with mock.patch.object(Path,'lstat',lambda item:wrong_parent if item==root else actual_socket):
                        with self.subTest(parent_owner=field),self.assertRaises(RuntimeError):driver.provenance_socket_receipt(path)
                path.chmod(0o666)
                with self.assertRaises(RuntimeError):driver.provenance_socket_receipt(path)
                path.chmod(0o600);root.chmod(0o755)
                with self.assertRaises(RuntimeError):driver.provenance_socket_receipt(path)
                root.chmod(0o700)
            path.unlink();path.write_text('not a socket');path.chmod(0o600)
            with self.assertRaises(RuntimeError):driver.provenance_socket_receipt(path)
            path.unlink()
            with self.assertRaises(FileNotFoundError):driver.provenance_socket_receipt(path)

    def test_private_socket_parent_symlink_is_rejected_without_following_owner(self):
        driver=self.driver()
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);private=root/'private';private.mkdir(mode=0o700)
            alias=root/'alias';alias.symlink_to(private,target_is_directory=True)
            with socket.socket(socket.AF_UNIX) as listener:
                path=private/'mtp.sock';listener.bind(str(path));path.chmod(0o600)
                self.assertTrue(driver.provenance_socket_receipt(path)['parent_is_directory'])
                with self.assertRaises(RuntimeError):driver.provenance_socket_receipt(alias/'mtp.sock')

    def test_packet_provenance_missing_fields_remain_explicitly_missing(self):
        packets=load('acceptance_packets')
        event={'run_id':'physical','connection_reused':False}
        receipt=packets.provenance_events([event])
        self.assertEqual(receipt['actual_events'],[event])
        self.assertNotIn('eos_seen',event)
        self.assertIn('eos_seen',receipt['missing_fields_by_event'][0])
        self.assertIn('cleanup_reason',receipt['missing_fields_by_event'][0])
        self.assertEqual(set(receipt['provenance_fields']),set(packets.PROVENANCE_FIELDS))
        self.assertTrue(receipt['missing_fields_are_not_synthesized'])

    def binding_fixture(self,directory):
        root=Path(directory);prepared=root/'prepared';attempt=root/'attempt'
        source=prepared/'source';fixtures=prepared/'fixtures';originals=attempt/'executed-input-originals'
        for path in (source,fixtures,originals,attempt/'data/cache',attempt/'data/build/service',attempt/'data/cases'):
            path.mkdir(parents=True,exist_ok=True)
        def save(path,value):path.write_text(json.dumps(value))
        def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
        save(source/'.i12-source-export-manifest.json',{'source_revision':'current','gitlinks':{}})
        observer=source/'ci/runtime/lifecycle/native-lifecycle-observer.c';observer.parent.mkdir(parents=True);observer.write_text('observer')
        save(fixtures/'acceptance-manifest.json',{'cases':[],'selected_route':'traefik-forwardauth-request'})
        (fixtures/'acceptance_faults.c').write_text('faults')
        host=attempt/'data/cache/traefik';host.write_bytes(b'host')
        engine=attempt/'data/build/service/traefik-forwardauth';engine.write_bytes(b'engine')
        maps={name:{str(p.relative_to(path)):sha(p) for p in path.rglob('*') if p.is_file()}
              for name,path in (('/mnt/src',source),('/mnt/fixtures',fixtures))}
        maps['/mnt/artifacts']={'traefik/host':sha(host),'toolchains/go1.27.2/bin/go':'go-hash'}
        bindings=[]
        for index,(target,files) in enumerate(maps.items()):
            ledger=originals/('ledger'+str(index));save(ledger,{'files':files})
            bindings.append({'target':target,'source':str(source if target=='/mnt/src' else fixtures if target=='/mnt/fixtures' else root/'artifacts'),'ledger_sha256':sha(ledger)})
        spec=originals/'spec';save(spec,{'source_revision':'current','logical_route':'traefik-forwardauth-request','bindings':bindings})
        controller=originals/'controller';controller.write_text('controller')
        hashes={'spec':sha(spec),'controller':sha(controller)}
        save(attempt/'controller-result.json',{'executed_input_hashes_before':hashes,'executed_input_hashes_after':hashes,
             'spec_sha256':sha(spec),'controller_sha256':sha(controller)})
        build={'source_inputs':maps['/mnt/src'],'fixture_inputs':maps['/mnt/fixtures'],
               'manifest_sha256':maps['/mnt/fixtures']['acceptance-manifest.json'],'host_sha256':sha(host),
               'engine_sha256':sha(engine),'observer_source_sha256':sha(observer),
               'fault_source_sha256':sha(fixtures/'acceptance_faults.c'),'toolchain':{'binary_sha256':'go-hash'}}
        save(attempt/'data/acceptance-build.json',build)
        save(attempt/'data/acceptance-execution-summary.json',{'runtime_source_manifest_sha256':sha(attempt/'data/acceptance-build.json'),
             'route':'traefik-forwardauth-request','original_ids':0})
        return attempt,prepared

    def test_packet_binding_rejects_mixed_or_mutated_prepared_attempt_before_output(self):
        packets=load('acceptance_packets')
        reviewer=load('acceptance_review')
        for mutation in ('new-prepared','source','fixture','manifest','build','host','engine','controller','missing-fixture-attestation','case'):
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as directory:
                attempt,prepared=self.binding_fixture(directory)
                self.assertTrue(packets.validate_attempt_binding(attempt,prepared)['prepared_attempt_bound'])
                if mutation=='new-prepared':
                    import shutil
                    replacement=prepared.with_name('new-prepared');shutil.copytree(prepared,replacement);prepared=replacement
                elif mutation in ('source','fixture','manifest'):
                    path=prepared/({'source':'source/.i12-source-export-manifest.json','fixture':'fixtures/acceptance_faults.c','manifest':'fixtures/acceptance-manifest.json'}[mutation])
                    path.write_text(path.read_text()+' ')
                elif mutation=='case':
                    path=attempt/'data/cases/foreign';path.mkdir();(path/'case.json').write_text('{}')
                else:
                    path=attempt/({'build':'data/acceptance-build.json','host':'data/cache/traefik','engine':'data/build/service/traefik-forwardauth',
                        'controller':'executed-input-originals/controller','missing-fixture-attestation':'data/acceptance-build.json'}[mutation])
                    if mutation=='missing-fixture-attestation':
                        value=json.loads(path.read_text());value.pop('fixture_inputs');path.write_text(json.dumps(value))
                    else:path.write_text(path.read_text()+' ')
                output=Path(directory)/'packets'
                with self.assertRaises(ValueError):packets.propose(attempt,prepared,output)
                self.assertFalse(output.exists())
                review_output=Path(directory)/'review.json'
                with self.assertRaises(ValueError):reviewer.review(attempt,review_output,prepared)
                self.assertFalse(review_output.exists())

    def test_standalone_review_records_same_prepared_attempt_binding_as_packets(self):
        reviewer=load('acceptance_review');packets=load('acceptance_packets')
        with tempfile.TemporaryDirectory() as directory:
            attempt,prepared=self.binding_fixture(directory)
            result=reviewer.review(attempt,Path(directory)/'review.json',prepared)
            self.assertEqual(result['prepared_attempt_binding'], packets.validate_attempt_binding(attempt,prepared))

    def test_readiness_uses_remaining_budget_and_rejects_late_native_success(self):
        driver=self.driver()
        for late_command,late_native in ((True,False),(False,True),(False,False)):
            clock=[0.0];budgets=[]
            with tempfile.TemporaryDirectory() as directory:
                root=Path(directory)
                def execute(*args,**kwargs):
                    budgets.append(args[-1])
                    self.assertEqual(kwargs['absolute_deadline'],0.25)
                    clock[0]+=0.26 if late_command else 0.20
                    (root/'client-readiness-0.json').write_text(json.dumps({'requests':[{'client_framing':{'status':200}}]}))
                    return {'timed_out':False}
                def native(*args, **kwargs):
                    self.assertEqual(kwargs['expected_probe'], self.case('phase1_allow')['probe_id'] + '-ready-0')
                    self.assertEqual(kwargs['command'], {'timed_out': False})
                    clock[0]+=0.06 if late_native else 0.01
                    return {'positive_allocation_finish_free':True}
                with mock.patch.object(driver.time,'monotonic',side_effect=lambda:clock[0]), \
                     mock.patch.object(driver.time,'monotonic_ns',side_effect=lambda:int(clock[0]*1e9)), \
                     mock.patch.object(driver.acceptance_command,'execute',side_effect=execute), \
                     mock.patch.object(driver.acceptance_readiness,'native_receipt',side_effect=native) as observed:
                    if late_command or late_native:
                        case = self.case('phase1_allow')
                        with self.assertRaises(RuntimeError):driver.wait_for_http_ready(case,root,{},1234,seconds=0.25)
                    else:
                        self.assertTrue(driver.wait_for_http_ready(self.case('phase1_allow'),root,{},1234,seconds=0.25)['ready'])
                    self.assertEqual(budgets,[0.25])
                    self.assertEqual(observed.call_count,0 if late_command else 1)
                receipt=json.loads((root/'http-readiness.json').read_text())
                self.assertEqual(receipt['deadline_exceeded'],late_command or late_native)
                self.assertEqual(receipt['ready'],not(late_command or late_native))

    def test_readiness_command_recomputes_wait_after_spawn_and_records_reap(self):
        command=load('acceptance_command');root=Path('/task/cases/fixed')
        argv=['/usr/local/bin/python3','-P','/mnt/fixtures/acceptance_net.py','client',
              '--spec',str(root/'case.json'),'--root',str(root),'--port','1234','--neighbor','--readiness-index','0']
        for spawn_delay in (0.10,0.30):
            process=mock.Mock(pid=44,returncode=0)
            with mock.patch.object(Path,'resolve',lambda item,**kwargs:item), \
                 mock.patch.object(Path,'open',mock.mock_open()), \
                 mock.patch.object(Path,'read_bytes',return_value=b''), \
                 mock.patch.object(Path,'write_text'), \
                 mock.patch.object(command.time,'monotonic',side_effect=[0.0,spawn_delay]), \
                 mock.patch.object(command.subprocess,'Popen',return_value=process), \
                 mock.patch.object(command.os,'killpg') as kill:
                receipt=command.execute(root,'readiness-0',argv,{},0.25,absolute_deadline=0.20)
            if spawn_delay<0.20:
                self.assertAlmostEqual(process.wait.call_args.kwargs['timeout'],0.10)
                self.assertFalse(receipt['timed_out']);self.assertIsNone(receipt['reap_started_ns'])
                kill.assert_not_called()
            else:
                self.assertTrue(receipt['timed_out']);self.assertIsNotNone(receipt['reap_started_ns'])
                self.assertEqual(receipt['reap_deadline_seconds'],6)
                process.wait.assert_called_once_with(timeout=3)
                kill.assert_called_once_with(44,command.signal.SIGTERM)

    def test_readiness_poll_sleeps_stop_at_absolute_deadline(self):
        driver=self.driver();clock=[0.0];sleeps=[]
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            def execute(*args,**kwargs):
                clock[0]+=0.24
                (root/'client-readiness-0.json').write_text(json.dumps({'requests':[{'client_framing':{'status':200}}]}))
                return {'timed_out':False}
            def sleep(seconds):sleeps.append(seconds);clock[0]+=seconds
            case = self.case('phase1_allow')
            with mock.patch.object(driver.time,'monotonic',side_effect=lambda:clock[0]), \
                 mock.patch.object(driver.time,'sleep',side_effect=sleep), \
                 mock.patch.object(driver.acceptance_command,'execute',side_effect=execute) as commands, \
                 mock.patch.object(driver.acceptance_readiness,'native_receipt',return_value={'positive_allocation_finish_free':False}):
                with self.assertRaises(RuntimeError):driver.wait_for_http_ready(case,root,{},1234,seconds=0.25)
            self.assertEqual(commands.call_count,1)
            self.assertAlmostEqual(sum(sleeps),0.01)
            self.assertAlmostEqual(clock[0],0.25)

    def test_readiness_requires_same_allocation_once_finish_and_free(self):
        readiness = load('acceptance_readiness')
        allocation = {'function': 'native_new', 'edge': 'return', 'result': 1,
                      'invalid': False, 'pid': 71, 'allocation_scope_call': 8, 'monotonic_ns': 15}
        logging = {'function': 'native_process_logging', 'edge': 'return',
                   'result': 1, 'invalid': False, 'pid': 71, 'allocation_scope_call': 8}
        cleanup = dict(logging, function='native_cleanup')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'native.jsonl'
            def measured(rows):
                path.write_text(''.join(json.dumps(row) + '\n' for row in rows))
                return readiness.native_receipt(path, {'monotonic_ns': 10, 'completed_ns': 20})
            self.assertFalse(measured([allocation])['positive_allocation_finish_free'])
            self.assertFalse(measured([allocation, logging, dict(cleanup, pid=72)])['positive_allocation_finish_free'])
            self.assertFalse(measured([allocation, logging, cleanup, cleanup])['positive_allocation_finish_free'])
            self.assertTrue(measured([allocation, logging, cleanup])['positive_allocation_finish_free'])
            self.assertFalse(measured([dict(allocation, monotonic_ns=9), logging, cleanup])['positive_allocation_finish_free'])
            for index in range(3):
                original = [allocation, logging, cleanup]
                for change in ({'invalid': True}, {'invalid': None}, {'allocation_scope_call': 9}):
                    with self.subTest(index=index, change=change):
                        rows = original.copy()
                        rows[index] = dict(rows[index], **change)
                        self.assertFalse(measured(rows)['positive_allocation_finish_free'])
                with self.subTest(index=index, duplicate=True):
                    self.assertFalse(measured(original + [original[index]])['positive_allocation_finish_free'])
                with self.subTest(index=index, absent=True):
                    self.assertFalse(measured(original[:index] + original[index + 1:])['positive_allocation_finish_free'])
                with self.subTest(index=index, missing_invalid=True):
                    rows = [dict(row) for row in original]
                    del rows[index]['invalid']
                    self.assertFalse(measured(rows)['positive_allocation_finish_free'])
            for index in (0, 1):
                for result in (0, -1, None):
                    with self.subTest(index=index, result=result):
                        rows = [allocation, logging, cleanup]
                        rows[index] = dict(rows[index], result=result)
                        self.assertFalse(measured(rows)['positive_allocation_finish_free'])
            self.assertFalse(measured([allocation, logging, cleanup, dict(allocation, result=0)])['positive_allocation_finish_free'])

    def test_readiness_public_id_fallback_is_bound_and_unambiguous(self):
        readiness = load('acceptance_readiness')
        probe = 'ac-15a203ded42803005a99-ready-1'
        transaction = probe + '-neighbor'
        command = {'started_ns': 9, 'completed_ns': 21, 'exit_code': 0, 'signal': 0,
                   'timed_out': False, 'wrapper_pid': 1747,
                   'argv': ['--neighbor', '--readiness-index', '1']}
        client = {'probe': probe, 'neighbor': True, 'pid': 1748, 'monotonic_ns': 10, 'completed_ns': 20,
                  'requests': [{'wire_probe': transaction, 'pid': 1748,
                                'client_framing': {'status': 200, 'complete': True}}]}
        returns = [dict(function=function, edge='return', pid=1717, transaction_id=transaction,
                     input_transaction_id=transaction, transaction_id_origin='sdk_public_m_id',
                     allocation_scope_call=None, allocation_join_verified=False, invalid=False,
                     result=result, monotonic_ns=12 + index * 2, sequence=5 + index * 2, call=4 + index * 2)
                for index, (function, result) in enumerate((('native_new_with_id', 1),
                     ('native_process_logging', 1), ('native_cleanup', None)))]
        rows = []
        for index, returned in enumerate(returns):
            entered = dict(returned, edge='enter', result=None,
                           monotonic_ns=returned['monotonic_ns'] - 1,
                           sequence=returned['sequence'] - 1)
            if index == 0:
                entered.update(transaction_id=None, input_transaction_id=None,
                               transaction_id_origin='unknown')
            rows.extend([entered, returned])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'native.jsonl'
            def measured(events=rows, receipt=client, invocation=command, expected=probe):
                path.write_text(''.join(json.dumps(row) + '\n' for row in events))
                return readiness.native_receipt(path, receipt, expected_probe=expected,
                                                command=invocation)['positive_allocation_finish_free']
            self.assertTrue(measured())
            self.assertFalse(measured(rows + [dict(rows[-1], transaction_id='spoof', input_transaction_id='spoof')]))
            events = copy.deepcopy(rows); events[-1]['result'] = 123
            self.assertFalse(measured(events))
            self.assertFalse(measured(expected='other-ready-1'))
            self.assertFalse(measured(invocation=None))
            for change in ({'exit_code': 1}, {'exit_code': False}, {'signal': 1}, {'timed_out': True},
                           {'started_ns': 11}, {'completed_ns': 19}, {'wrapper_pid': None},
                           {'wrapper_pid': True}, {'client_pid': 99}, {'argv': []}):
                self.assertFalse(measured(invocation={**command, **change}))
            self.assertFalse(measured(receipt={**client, 'pid': True}))
            self.assertFalse(measured(receipt={**client, 'pid': 99}))
            for index in range(6):
                for change in ({'pid': 1718}, {'invalid': True}, {'invalid': None},
                               {'transaction_id': 'spoof'}, {'input_transaction_id': 'spoof'},
                               {'transaction_id_origin': None}, {'monotonic_ns': 9},
                               {'monotonic_ns': 21}, {'monotonic_ns': None},
                               {'allocation_scope_call': 8}, {'allocation_join_verified': True},
                               {'call': 0}, {'sequence': 0}):
                    with self.subTest(index=index, change=change):
                        events = copy.deepcopy(rows); events[index].update(change)
                        self.assertFalse(measured(events))
                self.assertFalse(measured(rows + [rows[index]]))
                self.assertFalse(measured(rows + [dict(rows[index], pid=1718)]))
                self.assertFalse(measured(rows[:index] + rows[index + 1:]))
            for field in ('monotonic_ns', 'sequence', 'call'):
                events = copy.deepcopy(rows); events[2][field] = events[1][field]
                self.assertFalse(measured(events))
            for index in (1, 3):
                for value in (0, -1, None, True):
                    events = copy.deepcopy(rows); events[index]['result'] = value
                    self.assertFalse(measured(events))
            for index in (0, 2, 4):
                events = copy.deepcopy(rows); events[index]['call'] += 100
                self.assertFalse(measured(events))
                events = copy.deepcopy(rows); events[index]['result'] = 1
                self.assertFalse(measured(events))
                for field in ('monotonic_ns', 'sequence'):
                    events = copy.deepcopy(rows); events[index][field] = events[index + 1][field]
                    self.assertFalse(measured(events))
            for change in ({'probe': 'other-ready-1'}, {'probe': 'target'}, {'neighbor': False},
                           {'error': 'failed'}, {'requests': []}, {'requests': client['requests'] * 2},
                           {'requests': [{'wire_probe': 'spoof', 'client_framing': {'status': 200, 'complete': True}}]},
                           {'requests': [{'wire_probe': transaction, 'client_framing': {'status': 404, 'complete': True}}]}):
                self.assertFalse(measured(receipt={**client, **change}))

    def test_packet_producer_roles_follow_real_central_measurement_contract(self):
        packets = load('acceptance_packets')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            physical = root / 'actual-receipt.json'
            physical.write_text('{"observed":true}\n')
            candidate = root / 'candidate.json'
            callback = packets.reference(physical, 'host_callback')
            client = packets.reference(physical, 'client_process')
            cleanup = packets.reference(physical, 'cleanup_observer')
            incomplete = packets.scoped_observation('commit_order', {'physical': True}, callback)
            _, known = packets.LEDGER.measurement('commit_order', incomplete, candidate)
            self.assertFalse(known)
            complete = packets.scoped_observation('commit_order', {'physical': True}, callback, client)
            _, known = packets.LEDGER.measurement('commit_order', complete, candidate)
            self.assertTrue(known)
            descriptor = packets.scoped_observation('descriptor_cleanup', {'observed': True}, cleanup, callback)
            self.assertEqual([proof['role'] for proof in descriptor['evidence']], ['cleanup_observer'])
            _, known = packets.LEDGER.measurement('descriptor_cleanup', descriptor, candidate)
            self.assertTrue(known)

    def setUp(self):
        self.catalog = load('acceptance_catalog')
        self.controls = load('acceptance_controls')
        self.net = load('acceptance_net')

    def test_literal_canonical_barrier_is_retained_without_body_padding(self):
        case = self.case('phase4_first_byte_before_response_end')
        fixture = case['fixture']
        payload = b'prefix no-crs-response-body-marker'
        fixture['backend'].update(body_hex=payload.hex(), chunk_lengths=[7, len(payload)-7], barrier=True)
        self.catalog.adapt_canonical({'id': case['id'], 'original_catalog_case': {},
            'original_contract': {'expected_oracle': {}}}, fixture)
        self.assertEqual(bytes.fromhex(fixture['backend']['body_hex']), payload)
        self.assertEqual(fixture['backend']['chunk_lengths'], [7, len(payload)-7])
        self.assertEqual(fixture['backend']['barrier_after_bytes'], 7)
        self.assertTrue(fixture['source_bound_barrier']['deadline_release_is_not_commit_proof'])

    def case(self, name):
        return {'id': 'I12::traefik-forwardauth-request::' + name,
                'case_id': name, 'probe_id': 'ac-01234567890123456789',
                'fixture': self.catalog.default_fixture(name),
                'fixture_sha256': 'original'}

    def test_capacity_controls_keep_native_and_relay_separate(self):
        case = self.case('NEED-host-auth-response-32768-bound')
        values = self.controls.controls(case)
        self.assertEqual([v['fixture']['relay']['authorization_body_size'] for v in values], [32768, 32769])
        self.assertEqual([v['independent_control_expectation']['visible_status'] for v in values], [200, 401])
        self.assertTrue(all(v['independent_control_expectation']['native_authorization_status'] == 200 for v in values))
        self.assertEqual(case['fixture']['relay'], {})
        self.assertTrue(all(v['fixture_sha256'] is None for v in values))

    def test_host_sample_controls_straddle_exact_limit(self):
        values = self.controls.controls(self.case('NEED-host-request-buffer-bound'))
        self.assertEqual([len(bytes.fromhex(v['fixture']['request']['body_hex'])) for v in values], [4096, 4097])
        self.assertEqual([v['independent_control_expectation']['authorization_arrivals'] for v in values], [1, 0])

    def test_handle_controls_include_validly_encoded_unknown(self):
        values = self.controls.controls(self.case('NEED-observer-response-eos'))
        self.assertEqual([v['fixture']['relay']['handle'] for v in values], ['missing', 'malformed', 'unknown64hex', 'expired'])
        self.assertTrue(all(v['original_id'].endswith('NEED-observer-response-eos') for v in values))

    def test_original_method_uri_controls_have_opposing_spoofs(self):
        values = self.controls.controls(self.case('phase1_allow'))
        self.assertEqual([v['fixture']['request']['method'] for v in values[:2]], ['POST', 'GET'])
        self.assertEqual([v['independent_control_expectation']['visible_status'] for v in values[:2]], [403, 200])
        headers = dict(values[-1]['fixture']['request']['headers'])
        self.assertEqual(headers['X_Forwarded_Uri'], '/underscore-forged')
        self.assertNotEqual(headers['X-Forwarded-Uri'], values[-1]['fixture']['request']['uri'])
        self.assertTrue(any(line.startswith('SecRule REQUEST_URI_RAW ') for line in values[-1]['fixture']['rules_lines']))

    def test_sink_open_has_separate_healthy_image_controls(self):
        case = self.case('NEED-physical-event-sink-open')
        case['fixture']['fault'] = {'driver_kind': 'sink-open'}
        values = self.controls.controls(case)
        self.assertEqual([value['control_order'] for value in values], ['before', 'after'])
        self.assertTrue(all(value['fixture']['fault'] is None for value in values))
        self.assertEqual(case['fixture']['fault']['driver_kind'], 'sink-open')

    def test_cleanup_faults_are_bound_to_implemented_hooks(self):
        for name, mode in [('early_mapping_failure_cleanup', 'mapper-headers-null'),
                           ('transaction_begin_failure_cleanup', 'begin-failure'),
                           ('finish_failure_propagation', 'finish-failure')]:
            fixture = self.case(name)['fixture']
            fixture['fault'] = {'kind': name}
            self.catalog.normalize_fault(fixture, name)
            self.assertEqual(fixture['fault']['driver_kind'], mode)

    def test_companion_invalid_return_reaches_response_phase(self):
        for route, expected in [('traefik-forwardauth-request', 'native-invalid-return'),
                                ('traefik-forwardauth-response-companion', 'native-response-invalid-return')]:
            fixture = self.case('NEED-invalid-native-return')['fixture']
            fixture['fault'] = {'kind': 'invalid-native-return'}
            self.catalog.normalize_fault(fixture, 'NEED-invalid-native-return', route)
            self.assertEqual(fixture['fault']['driver_kind'], expected)

    def test_original_rule_cannot_be_silently_dropped_or_duplicated(self):
        row = {'id': 'I12::traefik-forwardauth-request::deny_header_marker_403',
               'original_contract': {'expected_oracle': {'rule_id': 1100001}}}
        fixture = {'rules_lines': ['SecRuleEngine On']}
        with self.assertRaisesRegex(ValueError, 'original expected rule absent'):
            self.catalog.validate_rule_bindings(row, fixture)
        rule = 'SecRule REQUEST_HEADERS:X-Modsec-Smoke "@streq block" "id:1100001,phase:1,deny,status:403"'
        fixture['rules_lines'].append(rule)
        self.catalog.validate_rule_bindings(row, fixture)
        fixture['rules_lines'].append(rule)
        with self.assertRaisesRegex(ValueError, 'duplicate effective rule IDs'):
            self.catalog.validate_rule_bindings(row, fixture)

    def test_chunked_keepalive_requires_final_chunk(self):
        prefix = b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n'
        self.assertFalse(self.net.framing(prefix)['complete'])
        result = self.net.framing(prefix + b'0\r\n\r\n')
        self.assertTrue(result['complete'])
        self.assertEqual(result['entity_bytes'], 3)
        self.assertFalse(self.net.framing(prefix + b'0\r\n')['complete'])

    def test_chunk_framing_without_payload_cannot_release_first_byte_barrier(self):
        prefix = b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2000\r\n'
        self.assertEqual(self.net.received_entity_bytes(prefix), 0)
        self.assertEqual(self.net.received_entity_bytes(prefix + b'x'), 1)
        self.assertEqual(self.net.received_entity_bytes(prefix + b'x' * 8192), 8192)

    def test_truncated_content_length_never_becomes_complete(self):
        result = self.net.framing(b'HTTP/1.1 200 OK\r\nContent-Length: 16384\r\n\r\n' + b'a' * 8192)
        self.assertFalse(result['complete'])
        self.assertEqual(result['entity_bytes'], 8192)

    def test_malformed_http_preserves_original_fixture_request_line(self):
        case = self.case('invalid_content_length')
        case['fixture']['request'].update(method='GET', uri='/original/fixture?x=1')
        case['fixture']['client']['raw_template'] = 'invalid_content_length'
        head, _, _ = self.net.raw_request(case)
        self.assertTrue(head.startswith(b'GET /original/fixture?x=1 HTTP/1.1\r\n'))
        self.assertIn(b'Content-Length: nope\r\n', head)

    def test_healthy_neighbor_cannot_release_target_first_byte_barrier(self):
        class Connection:
            def __init__(self):
                self.chunks = iter([b'HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx', b''])

            def recv(self, _):
                return next(self.chunks)

        class ForbiddenBarrier:
            def __truediv__(self, _):
                raise AssertionError('neighbor attempted to release target barrier')

        _, result = self.net.receive(Connection(), ForbiddenBarrier(), {}, False, False)
        self.assertTrue(result['client_framing']['complete'])
        self.assertFalse(result['native_eos_inferred'])

    def test_packet_scope_uses_physical_target_window(self):
        packets = load('acceptance_packets')
        measured = {'native_scopes': [
            {'native_id': 'healthy-before', 'native_allocation': {'monotonic_ns': 9}},
            {'native_id': 'actual-target', 'native_allocation': {'monotonic_ns': 15}},
            {'native_id': 'healthy-after', 'native_allocation': {'monotonic_ns': 21}}]}
        selected = packets.target_scopes(measured, {'monotonic_ns': 10, 'completed_ns': 20})
        self.assertEqual([scope['native_id'] for scope in selected], ['actual-target'])
        self.assertEqual(packets.target_scopes(measured, None), [])
        self.assertEqual(len(packets.FIELD_NAMES), 35)
        self.assertEqual(len(set(packets.FIELD_NAMES)), 35)

    def test_missing_packet_measurement_is_not_zero(self):
        packets = load('acceptance_packets')
        missing = packets.observation(None)
        self.assertIsNone(missing['value'])
        self.assertTrue(missing['applicable'])
        self.assertIn('reason', missing)

    def test_eagain_release_requires_exact_socket_nonce_and_real_failure(self):
        identity = {'local_address': '127.0.0.1', 'local_port': 45678,
                    'peer_address': '127.0.0.1', 'peer_port': 12345}
        row = {'schema': 'traefik-own-child-syscall-v1', 'nonce': 'original-id',
               'local_address': '127.0.0.1', 'local_port': 12345,
               'peer_address': '127.0.0.1', 'peer_port': 45678,
               'operation': 'writev', 'kernel_result': -11, 'errno': 11,
               'requested_size_known': True, 'requested_bytes': 8192,
               'pid': 1234, 'socket_inode': 5678,
               'fd_identity_unchanged': True, 'exit_monotonic_ns': 20}
        self.assertTrue(self.net.target_eagain(row, identity, 'original-id', 10))
        for edit in ({'nonce': 'neighbor'}, {'peer_port': 45679},
                     {'kernel_result': 0}, {'errno': 0},
                     {'requested_size_known': False}, {'requested_bytes': 0},
                     {'pid': 0}, {'socket_inode': 0},
                     {'fd_identity_unchanged': False}, {'exit_monotonic_ns': 9}):
            self.assertFalse(self.net.target_eagain({**row, **edit}, identity, 'original-id', 10))

    def test_bounded_transport_supplement_preserves_original_oracle(self):
        retakes = load('acceptance_retakes')
        case = self.case('response_write_would_block_resume')
        case['original_contract'] = {'expected_oracle': {'rule_id': 1100301, 'phase': 4}}
        case['original_contract_sha256'] = 'immutable-original'
        value = retakes.transport_case(case)
        fixture = value['fixture']
        self.assertEqual(value['id'], case['id'])
        self.assertEqual(value['original_contract'], case['original_contract'])
        self.assertEqual(value['original_contract_sha256'], 'immutable-original')
        self.assertEqual(len(bytes.fromhex(fixture['backend']['body_hex'])), 8 * 1024 * 1024)
        self.assertIn('SecResponseBodyLimit 16777216', fixture['rules_lines'])
        self.assertNotIn('receive_buffer', fixture['client'])
        self.assertEqual(fixture['client']['receive_buffer_policy'], 'kernel_default_recorded')
        self.assertEqual(fixture['client']['target_command_deadline_seconds'], 120)
        self.assertNotIn('slow_reader', fixture['client'])
        self.assertFalse(value['independent_control_expectation']['original_rule_oracle_satisfied_by_transport_control'])
        self.assertIsNone(value['qualification'])
        self.assertEqual(case['probe_id'], 'ac-01234567890123456789')

    def test_backpressure_pause_counts_entity_and_drains_after_release(self):
        raw = b'HTTP/1.1 200 OK\r\nContent-Length: 8193\r\n\r\n' + b'x' * 8193
        class Connection:
            def __init__(self):
                self.remaining = raw
            def recv(self, size):
                value, self.remaining = self.remaining[:size], self.remaining[size:]
                return value
        barrier = mock.MagicMock()
        identity = {'local_address': '127.0.0.1', 'local_port': 45678,
                    'peer_address': '127.0.0.1', 'peer_port': 12345,
                    'monotonic_ns': 1}
        with mock.patch.object(self.net, 'pause_for_eagain', return_value={'release_reason': 'deadline_without_target_eagain'}) as pause:
            received, result = self.net.receive(Connection(), barrier,
                {'pause_for_target_eagain': {'nonce': 'target', 'deadline_seconds': 0.01},
                 'slow_reader': True}, False, True, identity)
        self.assertEqual(received, raw)
        self.assertTrue(result['client_framing']['complete'])
        self.assertEqual(pause.call_count, 1)
        self.assertEqual(pause.call_args.args[-1], 8192)
        self.assertEqual(result['read_pause']['release_reason'], 'deadline_without_target_eagain')

    def test_parser_preserves_exact_exit_255_and_signal_separately(self):
        parser = load('acceptance_parser')
        exited = parser.decode_wait(255 << 8)
        self.assertEqual(exited['exit_code'], 255)
        self.assertEqual(exited['signal'], 0)
        killed = parser.decode_wait(15)
        self.assertIsNone(killed['exit_code'])
        self.assertEqual(killed['signal'], 15)

    def engine_start_fixture(self, fault):
        driver = self.driver()
        service = types.SimpleNamespace(pid=4321, poll=lambda: 7)
        driver.base.start = mock.Mock(return_value=service)
        helper = types.SimpleNamespace(wait_for_tcp=mock.Mock())
        fault_path = mock.Mock()
        fault_path.read_text.return_value = '{"pid": 4321}\n'
        case = {'probe_id': 'ac-01234567890123456789', 'fixture': {'fault': fault}}
        result = {}
        processes = {}
        arguments = (case, Path('/engine'), Path('/config'), 18123, {}, [], processes,
                     helper, 10, 11, fault_path, result)
        return driver, service, helper, result, processes, arguments

    def test_engine_start_success_returns_registered_service(self):
        driver, service, helper, result, processes, arguments = self.engine_start_fixture(None)
        self.assertIs(driver.start_engine(*arguments), service)
        self.assertEqual(processes['engine'], (service, '/engine'))
        helper.wait_for_tcp.assert_called_once_with(18123, service, 'real current native forwardAuth service')
        self.assertEqual(result, {})

    def test_engine_start_sink_open_failure_retains_window_and_service(self):
        driver, service, helper, result, processes, arguments = self.engine_start_fixture({'driver_kind': 'sink-open'})
        helper.wait_for_tcp.side_effect = RuntimeError('sink could not open')
        self.assertIs(driver.start_engine(*arguments), service)
        self.assertEqual(result['engine_start_failure'], {'type': 'RuntimeError', 'message': 'sink could not open'})
        window = result['engine_start_window']
        self.assertEqual((window['proxy_pid'], window['observed_exit_code'], window['actual_fault_pids']),
                         (4321, 7, [4321]))
        self.assertEqual(window['probe'], arguments[0]['probe_id'])
        self.assertLessEqual(window['start_monotonic_ns'], window['end_monotonic_ns'])
        self.assertEqual(processes['engine'], (service, '/engine'))

    def test_engine_start_failure_without_fault_reraises(self):
        driver, service, helper, result, processes, arguments = self.engine_start_fixture(None)
        failure = RuntimeError('unexpected startup failure')
        helper.wait_for_tcp.side_effect = failure
        with self.assertRaises(RuntimeError) as caught:
            driver.start_engine(*arguments)
        self.assertIs(caught.exception, failure)
        self.assertEqual(result['engine_start_failure']['message'], str(failure))
        self.assertEqual(processes['engine'], (service, '/engine'))

    def test_engine_start_failure_with_other_fault_reraises(self):
        driver, service, helper, result, processes, arguments = self.engine_start_fixture({'driver_kind': 'begin-failure'})
        failure = RuntimeError('unexpected startup failure')
        helper.wait_for_tcp.side_effect = failure
        with self.assertRaises(RuntimeError) as caught:
            driver.start_engine(*arguments)
        self.assertIs(caught.exception, failure)
        self.assertEqual(result['engine_start_failure']['message'], str(failure))
        self.assertEqual(processes['engine'], (service, '/engine'))

    def test_backend_truncated_body_retains_entity_wire_and_error_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            headers = Message()
            headers['X-I12-Probe'] = 'ac-01234567890123456789'
            headers['Content-Length'] = '3'
            handler = types.SimpleNamespace(headers=headers, path='/target', command='POST',
                root=root, spec={'probe_id': headers['X-I12-Probe'], 'fixture': {}},
                request_head_wire=b'POST /target HTTP/1.1\r\nContent-Length: 3\r\n\r\n',
                rfile=io.BytesIO(b'ab'), send_error=mock.Mock(), close_connection=False)
            with mock.patch.object(self.net, 'handler_record') as record:
                self.net.Backend.respond(handler)
            self.assertEqual((root / 'backend-target.request-body.raw').read_bytes(), b'ab')
            self.assertEqual((root / 'backend-target.request-body-wire.raw').read_bytes(), b'ab')
            body_receipt = record.call_args.kwargs
            self.assertEqual(record.call_args.args, (handler, 'request_body'))
            self.assertEqual(body_receipt['actual_bytes'], 2)
            self.assertEqual(body_receipt['sha256'], hashlib.sha256(b'ab').hexdigest())
            self.assertFalse(body_receipt['complete'])
            self.assertFalse(body_receipt['framing']['complete'])
            handler.send_error.assert_called_once_with(400, 'invalid backend request framing')
            self.assertTrue(handler.close_connection)

    def test_parser_child_exec_error_writes_json_receipt_and_exits_127(self):
        parser = load('acceptance_parser')
        argv = ['/engine', '--check-config', '--config', '/config']
        with (mock.patch.object(parser.os, 'close') as close,
              mock.patch.object(parser.os, 'chdir') as chdir,
              mock.patch.object(parser.os, 'dup2') as dup2,
              mock.patch.object(parser.os, 'write') as write,
              mock.patch.object(parser.os, 'execve', side_effect=PermissionError(13, 'denied')) as execute,
              mock.patch.object(parser.os, '_exit', side_effect=SystemExit(127)) as exit_child):
            with self.assertRaises(SystemExit) as caught:
                parser.execute_child(10, argv, 11, 12, 13, 14)
        self.assertEqual(caught.exception.code, 127)
        close.assert_called_once_with(11)
        chdir.assert_called_once_with(parser.SOURCE)
        self.assertEqual(dup2.call_args_list, [mock.call(13, 1), mock.call(14, 2)])
        self.assertEqual(execute.call_args.args[:2], (10, argv))
        self.assertEqual(write.call_count, 2)
        descriptor, encoded = write.call_args.args
        self.assertEqual(descriptor, 12)
        self.assertTrue(encoded.endswith(b'\n'))
        receipt = json.loads(encoded)
        self.assertEqual((receipt['stage'], receipt['errno'], receipt['type']),
                         ('exec_error', 13, 'PermissionError'))
        self.assertIsInstance(receipt['monotonic_ns'], int)
        exit_child.assert_called_once_with(127)

    def test_missing_rules_lstat_is_measured_errno(self):
        parser = load('acceptance_parser')
        path = mock.MagicMock()
        path.lstat.side_effect = FileNotFoundError(2, 'missing')
        receipt = parser.file_identity(path)
        self.assertFalse(receipt['lstat_success'])
        self.assertEqual(receipt['errno'], 2)
        self.assertNotIn('sha256', receipt)

    def test_original_rule_retake_requires_real_delivery_before_final_marker(self):
        retakes = load('acceptance_retakes')
        case = self.case('response_short_write_resume')
        case['original_contract'] = {'expected_oracle': {'rule_id': 1100301, 'phase': 4}}
        case['original_contract_sha256'] = 'unchanged'
        benign = retakes.transport_case(case)
        original = retakes.original_causal_transport_case(case)
        payload = bytes.fromhex(original['fixture']['backend']['body_hex'])
        self.assertEqual(len(payload), 8 * 1024 * 1024)
        self.assertEqual(payload.find(b'no-crs-response-body-marker'), len(payload) - len(b'no-crs-response-body-marker'))
        self.assertEqual(original['fixture']['backend']['barrier_after_bytes'], 8192)
        self.assertNotIn('barrier_after_bytes', benign['fixture']['backend'])
        self.assertEqual(original['original_contract'], case['original_contract'])
        self.assertEqual(original['independent_control_expectation']['predeclared_native_status'], 403)
        self.assertTrue(original['independent_control_expectation']['actual_client_delivery_before_p4_required'])
        self.assertIsNone(original['qualification'])

    def test_signal_retake_uses_waited_child_and_backend_holds_eos(self):
        retakes = load('acceptance_retakes')
        case = self.case('NEED-client-exit-signal')
        value = retakes.evidence_retake_case(case)
        self.assertEqual(value['fixture']['client']['kind'], 'wait-for-sigterm')
        self.assertTrue(value['fixture']['backend']['wait_for_client_termination'])
        self.assertEqual(value['independent_control_expectation']['waited_client_signal'], 15)
        self.assertIsNone(value['fixture']['fault'])

    def test_sink_retake_forces_disruptive_event_and_separate_recovery_uri(self):
        retakes = load('acceptance_retakes')
        for route, phase in [('traefik-forwardauth-request', 1),
                             ('traefik-forwardauth-response-companion', 3)]:
            case = self.case('NEED-physical-event-sink-write')
            case['route'] = route
            value = retakes.evidence_retake_case(case)
            target, positive = value['fixture']['rules_lines'][-2:]
            self.assertIn('phase:' + str(phase) + ',deny,status:403', target)
            self.assertIn('id:1999398', target)
            self.assertIn('id:1999397', positive)
            self.assertNotEqual(value['fixture']['sink_positive_control']['uri'], case['fixture']['request']['uri'])
            self.assertIsNone(value['independent_control_expectation']['visible_status'])

    def test_response_mime_variants_follow_bound_source_not_default_header(self):
        framework = Path('/read-only-framework')
        source = ('full_lifecycle:\n  variants:\n    in_scope: text/plain\n'
                  '    charset: text/plain; charset=utf-8\n'
                  '    out_of_scope: image/png\n    missing: null\n')
        for name, expected in [('phase4_in_scope_content_type', 'text/plain'),
                               ('phase4_content_type_with_charset', 'text/plain; charset=utf-8'),
                               ('phase4_out_of_scope_content_type', 'image/png'),
                               ('phase4_missing_content_type', None)]:
            fixture = self.case(name)['fixture']
            row = {'id': 'I12::traefik-forwardauth-response-companion::' + name}
            with mock.patch.object(Path, 'read_text', return_value=source), mock.patch.object(Path, 'read_bytes', return_value=source.encode()):
                self.catalog.apply_content_type_variant(row, fixture, framework)
            types = [value for key, value in fixture['backend']['headers'] if key.lower() == 'content-type']
            self.assertEqual(types, [expected] if expected is not None else [])
            self.assertEqual(fixture['content_type_variant_source']['literal'], expected)

    def test_readiness_receipts_cannot_alias_qualified_neighbor(self):
        probe = 'ac-01234567890123456789'
        self.assertEqual(self.net.traffic_label(probe + '-ready-0-neighbor', probe, True), 'readiness-0')
        self.assertEqual(self.net.traffic_label(probe + '-ready-9-neighbor', probe, True), 'readiness-9')
        self.assertEqual(self.net.traffic_label(probe + '-before-neighbor', probe, True), 'neighbor')
        self.assertEqual(self.net.traffic_label(probe + '-neighbor', probe, True), 'neighbor')
        self.assertNotEqual(self.net.traffic_label(probe + '-ready-10-neighbor', probe, True), 'readiness-10')

    def test_causal_supplement_preserves_literal_primary_body_and_chunks(self):
        case = self.case('phase4_deny_after_commit_log_only_safe')
        original = b'prefix no-crs-response-body-marker'
        case['fixture']['backend'].update(body_hex=original.hex(), chunk_lengths=[7, 27])
        values = self.controls.controls(case)
        self.assertEqual(len(values), 1)
        supplemental = values[0]
        self.assertEqual(case['fixture']['backend']['body_hex'], original.hex())
        self.assertEqual(case['fixture']['backend']['chunk_lengths'], [7, 27])
        self.assertEqual(bytes.fromhex(supplemental['fixture']['backend']['body_hex']), b'x' * 8192 + original)
        self.assertEqual(supplemental['fixture']['backend']['chunk_lengths'], [8192, 7, 27])
        self.assertEqual(supplemental['original_id'], case['id'])
        self.assertEqual(supplemental['control_name'], 'wire8192')
        self.assertIsNone(supplemental['fixture_sha256'])

    def test_corrupted_physical_jsonl_is_unknown_not_empty_or_silently_resynced(self):
        review = load('acceptance_review')
        path = mock.MagicMock()
        path.is_file.return_value = True
        path.read_bytes.return_value = b'{"ok":1}\n{"malformed"\n'
        decoded = review.jsonl(path)
        self.assertIsNone(decoded['rows'])
        self.assertEqual(decoded['parsed_rows'], [{'ok': 1}])
        self.assertEqual(decoded['decode_errors'][0]['zero_based_line'], 1)
        self.assertEqual(decoded['decode_errors'][0]['byte_offset'], 9)
        self.assertEqual(decoded['raw_bytes'], len(path.read_bytes.return_value))

    def test_literal_correlation_and_http_headers_are_not_duplicated(self):
        case = self.case('phase1_allow')
        case['fixture']['request']['headers'] += [['X-Request-Id', 'literal-original-id'],
            ['Host', 'literal.example'], ['Content-Length', '22'], ['Connection', 'close']]
        head, _, _ = self.net.raw_request(case)
        for name in (b'x-request-id:', b'host:', b'content-length:', b'connection:'):
            self.assertEqual(head.lower().count(name), 1)
        self.assertIn(b'X-Request-Id: literal-original-id\r\n', head)
        self.assertIn(b'Host: literal.example\r\n', head)
        self.assertEqual(self.net.traffic_label(case['probe_id'] + '-seq-2', case['probe_id'], False), 'sequence-2')

    def test_backend_exclusion_retake_records_rule_revision_and_keeps_oracle(self):
        retakes = load('acceptance_retakes')
        case = self.case('NEED-backend-excluded-on-deny')
        case['fixture']['rules_lines'].append('SecAction "id:1999303,phase:1,deny,status:403"')
        case['original_contract'] = {'expected_oracle': {'rule_id': 1999303, 'phase': 1, 'visible_status': 403}}
        value = retakes.evidence_retake_case(case)
        self.assertEqual(value['original_contract'], case['original_contract'])
        self.assertIn('SecAction "id:1999303,phase:1,deny,status:403"', case['fixture']['rules_lines'])
        self.assertTrue(value['fixture']['explicit_target_isolation_revision']['original_oracle_preserved'])
        self.assertIn('@streq ' + case['fixture']['request']['uri'], value['fixture']['rules_lines'][-1])


    def test_network_fixtures_reject_nonliteral_ports_and_authority_targets(self):
        for port in (None, True, False, 0, -1, 65536, '80', 'localhost', '80@remote.test'):
            with self.subTest(port=port), self.assertRaises(ValueError):
                self.net.loopback_port(port)
        for target in ('http://remote.test/path', '//remote.test/path', '/\\remote.test', '/a\r\nHost: remote', '/a\x7f'):
            with self.subTest(target=target), self.assertRaises(ValueError):
                self.net.origin_path(target)
        self.assertEqual(self.net.origin_path('/i12/target?probe=1'), '/i12/target?probe=1')
        with mock.patch.object(self.net.socket, 'socket') as constructor:
            connection = constructor.return_value
            self.assertIs(self.net.client_connection(12345, 2), connection)
            connection.connect.assert_called_once_with(('127.0.0.1', 12345))
            constructor.assert_called_once_with(self.net.socket.AF_INET, self.net.socket.SOCK_STREAM)

    def test_refactored_client_retains_real_wire_and_socket_lifecycle(self):
        case = self.case('allow_without_marker')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backend_root = root / 'backend'
            backend_root.mkdir()
            handler = type('ClientRegressionBackend', (self.net.Backend,), {'root': backend_root, 'spec': case})
            server = self.net.http.server.ThreadingHTTPServer(('127.0.0.1', 0), handler)
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                self.assertEqual(self.net.client(case, root, server.server_port, False), 0)
                measured = json.loads((root / 'client-target.json').read_text())
                self.assertEqual(len(measured['requests']), 1)
                self.assertTrue(measured['requests'][0]['same_live_socket'])
                self.assertTrue(measured['requests'][0]['client_framing']['complete'])
                self.assertFalse(measured['requests'][0]['native_eos_inferred'])
                self.assertEqual(measured['connection_ends'][0]['fd_after_close'], -1)
                self.assertTrue((root / 'target-0.response.raw').read_bytes().startswith(b'HTTP/1.1 200'))
            finally:
                server.shutdown()
                server.server_close()
                worker.join(timeout=2)
            self.assertFalse(worker.is_alive())

    def test_loopback_client_closes_socket_on_invalid_destination(self):
        with mock.patch.object(self.net.socket, 'socket') as constructor:
            with self.assertRaises(ValueError):
                self.net.client_connection('12345', 2)
            constructor.return_value.connect.assert_not_called()
            constructor.return_value.close.assert_called_once()



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == '__main__':
    unittest.main()
