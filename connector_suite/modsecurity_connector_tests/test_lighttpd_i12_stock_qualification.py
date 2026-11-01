"""Boundaries of exact-original Stock fixture and actual typed allocation joins."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest


ROOT = connector_root()


def load(name):
    path = source_path('ci/runtime/lifecycle/i12/lighttpd', root=ROOT) / (name + '.py')
    module = load_source(path)
    return module


FIXTURES = load('stock_qualification')
PACKET = load('stock_packet')


class StockOriginalQualificationTests(unittest.TestCase):
    def test_generated_response_module_decodes_real_chunked_framing(self):
        with tempfile.TemporaryDirectory(prefix='stock-decoder-', dir=FIXTURES.EXTERNAL) as name:
            path = Path(name) / 'lighttpd_capture_response.py'
            path.write_text(FIXTURES.response_helper_text())
            module = load_source(path)
            header = b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n'
            observed, actual_header, entity = module.response_decode(
                header + b'3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n')
            self.assertEqual(actual_header, header)
            self.assertEqual(entity, b'abcde')
            self.assertEqual(observed['entity_bytes'], 5)
            self.assertEqual(observed['framing']['kind'], 'chunked')
            self.assertTrue(observed['framing']['complete'])

    def test_unreviewed_case_cannot_receive_generic_allow_fixture(self):
        with self.assertRaisesRegex(ValueError, 'separately reviewed'):
            FIXTURES.fixture('NEED-invalid-native-return')

    def test_measurement_hash_rejects_outside_source_and_capture_roots(self):
        path = Path('/etc/passwd')
        with self.assertRaisesRegex(ValueError, 'outside declared'):
            PACKET.sha(path)

    def test_fixture_hash_rejects_outside_source_and_capture_roots(self):
        with self.assertRaisesRegex(ValueError, 'outside declared'):
            FIXTURES.sha(Path('/etc/passwd'))

    def test_raw_client_rejects_output_outside_private_task_before_socket(self):
        with tempfile.TemporaryDirectory(prefix='stock-client-path-', dir=FIXTURES.EXTERNAL) as name:
            directory = Path(name)
            source = source_path('ci/runtime/lifecycle/i12/lighttpd/stock_raw_client.py', root=ROOT)
            client = directory / 'client.py'
            client.write_text(source.read_text())
            (directory / 'lighttpd_capture_response.py').write_text(FIXTURES.response_helper_text())
            completed = subprocess.run(['rtk', 'proxy', sys.executable, '-B', str(client),
                '-D', '/etc/passwd'], capture_output=True, timeout=10)
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn(b'private task directory', completed.stderr)

    def test_report_output_rejects_source_checkout(self):
        path = source_path('not-runtime-evidence.json', root=ROOT)
        with self.assertRaisesRegex(ValueError, 'external task root'):
            PACKET.external_path(path)

    def test_native_jsonl_rule_metadata_remains_bound_to_actual_sdk_id(self):
        with tempfile.TemporaryDirectory(prefix='stock-native-json-', dir=FIXTURES.EXTERNAL) as name:
            path = Path(name) / 'audit.jsonl'
            main = json.dumps({'transaction': {'unique_id': 'actual-main',
                'messages': [{'details': {'ruleId': '1100501'}}]}})
            neighbor = json.dumps({'transaction': {'unique_id': 'actual-neighbor',
                'messages': [{'details': {'ruleId': '1100504'}}]}})
            path.write_text(main + '\n' + neighbor + '\n')
            scoped = PACKET.native_audit_for_id(path, 'actual-main')
            self.assertEqual(scoped, [main])
            self.assertTrue(PACKET.native_rule_observed(scoped, 1100501))
            self.assertFalse(PACKET.native_rule_observed(scoped, 1100504))
            self.assertEqual(PACKET.native_audit_for_id(path, None), [])

    def test_spool_exhaustion_is_separate_from_native_limit(self):
        value = FIXTURES.fixture('NEED-resource-exhaustion-technical')
        self.assertTrue(value['spool_probe'])
        self.assertEqual(len(bytes.fromhex(value['request_hex'])), 4096)
        self.assertGreater(4097 + 4096, value['spool_capacity_bytes'])
        self.assertEqual(value['expected_visible_status'], 503)
        self.assertEqual(value['expected_backend_main_count'], 0)

    def test_default_floor_enforcement_uses_actual_product_at_existing_syscall_seam(self):
        if not Path('/usr/include/modsecurity/modsecurity.h').is_file():
            self.skipTest('requires installed native SDK headers')
        with tempfile.TemporaryDirectory(prefix='stock-floor-test-', dir=FIXTURES.EXTERNAL) as name:
            output = Path(name) / 'capture'
            completed = subprocess.run(['rtk', 'proxy', sys.executable, '-B',
                str(source_path('ci/runtime/lifecycle/i12/lighttpd/stock_floor.py', root=ROOT)), '--output', str(output)],
                capture_output=True, text=True, timeout=75)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            receipt = json.loads((output / 'receipt.json').read_text())
            self.assertEqual(receipt['compile_exit'], 0, (output / 'compile.stderr').read_text())
            self.assertEqual(receipt['run_exit'], 0, (output / 'run.stderr').read_text())
            observed = receipt['actual_assertion_receipt']
            self.assertEqual(observed['default_reserve'], 67108864)
            self.assertTrue(observed['exact_floor_accept'])
            self.assertTrue(observed['before_floor_reject'])
            self.assertTrue(observed['after_floor_reject_cleanup'])
            self.assertTrue(observed['readmit'])
            self.assertFalse(receipt['host_disk_exhausted'])

    def test_copy_rejects_directory_symlink_without_following(self):
        with tempfile.TemporaryDirectory(prefix='stock-copy-test-', dir=FIXTURES.EXTERNAL) as name:
            root = Path(name)
            (root / 'source').mkdir()
            (root / 'source/alias').symlink_to(ROOT, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'source tree alias'):
                FIXTURES.copy_input_tree(root / 'source', root / 'target')

    def test_response_status_survives_actual_tcp_reset_without_hiding_exit(self):
        """An actual TCP reset after complete503 preserves both independent facts."""
        with tempfile.TemporaryDirectory(prefix='stock-client-test-', dir=FIXTURES.EXTERNAL) as name:
            directory = Path(name)
            source = source_path('ci/runtime/lifecycle/i12/lighttpd/stock_raw_client.py', root=ROOT)
            client = directory / 'client.py'
            client_source = source.read_text().replace("Path('/task/client')", 'Path(' + repr(str(directory / 'receipts')) + ')')
            client_source = client_source.replace("TASK_ROOT = Path('/task')", 'TASK_ROOT = Path(' + repr(str(directory)) + ')')
            client.write_text(client_source)
            (directory / 'lighttpd_capture_response.py').write_text(FIXTURES.response_helper_text())
            listener = socket.socket()
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)
            listener.settimeout(5)
            failures = []

            def reset_after_response():
                try:
                    connection, _address = listener.accept()
                    with connection:
                        request = b''
                        while b'\r\n\r\n' not in request:
                            request += connection.recv(4096)
                        connection.sendall(b'HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
                        connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
                except Exception as error:
                    failures.append(error)

            worker = threading.Thread(target=reset_after_response)
            worker.start()
            try:
                completed = subprocess.run(['rtk', 'proxy', sys.executable, '-B', str(client),
                    '-sS', '--http1.1', '-D', str(directory / 'headers'), '-X', 'GET',
                    '-o', str(directory / 'body'), '-w', '%{http_code}',
                    f'http://127.0.0.1:{listener.getsockname()[1]}/actual-reset'],
                    env={**os.environ, 'I12_APACHE_CLIENT_TOKEN': 'reset'}, capture_output=True, timeout=10)
            finally:
                listener.close()
                worker.join(timeout=6)
            self.assertFalse(worker.is_alive())
            self.assertEqual(failures, [])
            receipt = json.loads((directory / 'receipts/reset.receipt.json').read_text())
            self.assertEqual(completed.returncode, 1)
            self.assertEqual(completed.stdout, b'503')
            self.assertEqual(receipt['status'], 503)
            self.assertTrue(receipt['tcp_reset_observed'])
            self.assertFalse(receipt['tcp_eof_observed'])
            self.assertEqual(receipt['entity_bytes'], 0)
            self.assertEqual(receipt['error']['type'], 'ConnectionResetError')

    def test_raw_client_records_headers_entity_and_actual_local_abort(self):
        for abort in (None, 'close', 'reset'):
            with self.subTest(abort=abort), tempfile.TemporaryDirectory(
                    prefix='stock-client-chunks-', dir=FIXTURES.EXTERNAL) as name:
                directory = Path(name)
                source = source_path('ci/runtime/lifecycle/i12/lighttpd/stock_raw_client.py', root=ROOT)
                client = directory / 'client.py'
                text = source.read_text().replace("Path('/task/client')",
                    'Path(' + repr(str(directory / 'receipts')) + ')')
                text = text.replace("TASK_ROOT = Path('/task')",
                    'TASK_ROOT = Path(' + repr(str(directory)) + ')')
                client.write_text(text)
                (directory / 'lighttpd_capture_response.py').write_text(FIXTURES.response_helper_text())
                header = b'HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\n'
                wire = header + b'abc'
                requests, failures, peer_outcomes = [], [], []
                with socket.socket() as listener:
                    listener.bind(('127.0.0.1', 0))
                    listener.listen(1)
                    listener.settimeout(5)
                    port = listener.getsockname()[1]

                    def serve():
                        try:
                            connection, _ = listener.accept()
                            with connection:
                                connection.settimeout(5)
                                request = b''
                                while not request.endswith(b'\r\n\r\n'):
                                    fragment = connection.recv(4096)
                                    if not fragment:
                                        raise EOFError('client closed before completing request headers')
                                    request += fragment
                                requests.append(request)
                                connection.sendall(header[:-2])
                                time.sleep(0.05)
                                connection.sendall(header[-2:])
                                time.sleep(0.05)
                                connection.sendall(b'abc')
                                if abort:
                                    try:
                                        remainder = connection.recv(1)
                                    except ConnectionResetError:
                                        peer_outcomes.append('reset')
                                    else:
                                        peer_outcomes.append('eof' if not remainder else 'data')
                        except Exception as error:
                            failures.append(error)

                    worker = threading.Thread(target=serve)
                    worker.start()
                    arguments = ['rtk', 'proxy', sys.executable, '-B', str(client),
                        '-D', str(directory / 'headers'), '-o', str(directory / 'body'),
                        '-w', '%{http_code}', f'http://127.0.0.1:{port}/split']
                    if abort:
                        arguments.extend(['--i12-abort-after-first-entity', abort])
                    try:
                        completed = subprocess.run(arguments, env={**os.environ,
                            'I12_APACHE_CLIENT_TOKEN': 'split'}, capture_output=True, timeout=10)
                    finally:
                        worker.join(timeout=6)
                self.assertFalse(worker.is_alive())
                self.assertEqual(failures, [])
                self.assertEqual(peer_outcomes,
                    [] if abort is None else ['reset' if abort == 'reset' else 'eof'])
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(completed.stdout, b'200')
                self.assertEqual(requests, [f'GET /split HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n'.encode()])
                receipt = json.loads((directory / 'receipts/split.receipt.json').read_text())
                self.assertEqual((directory / 'receipts/split.response.raw').read_bytes(), wire)
                self.assertEqual((directory / 'body').read_bytes(), b'abc')
                chunks = receipt['actual_socket_recv_chunks']
                # TCP may coalesce the deliberately separate server writes.
                self.assertGreaterEqual(len(chunks), 1)
                self.assertLessEqual(receipt['started_ns'], receipt['request_sent_ns'])
                self.assertLessEqual(receipt['request_sent_ns'], chunks[0]['started_ns'])
                prior = 0
                for chunk in chunks:
                    self.assertEqual(chunk['prior_received_bytes'], prior)
                    self.assertLessEqual(chunk['started_ns'], chunk['completed_ns'])
                    prior += chunk['bytes']
                self.assertEqual(prior, len(wire))
                self.assertEqual(receipt['first_response_recv_started_ns'], chunks[0]['started_ns'])
                self.assertEqual(receipt['first_response_recv_completed_ns'], chunks[0]['completed_ns'])
                self.assertEqual(receipt['observed_header_bytes'], len(header))
                self.assertLessEqual(receipt['headers_complete_recv_ns'], receipt['first_encoded_entity_recv_ns'])
                self.assertFalse(receipt['tcp_reset_observed'])
                self.assertIsNone(receipt['error'])
                self.assertEqual(receipt['tcp_eof_observed'], abort is None)
                if abort:
                    self.assertEqual(receipt['local_abort']['mode'], abort)
                    self.assertEqual(receipt['local_abort']['actual_received_entity_bytes'], 3)
                    self.assertFalse(receipt['local_abort']['peer_reset_claimed'])

    def test_original_streaming_has_large_delayed_body_and_default_resource_contract(self):
        fixture = FIXTURES.fixture('NEED-request-streaming')
        self.assertTrue(fixture['delayed_request'])
        self.assertGreater(len(bytes.fromhex(fixture['request_hex'])), 8192)
        self.assertEqual(fixture['spool_capacity_bytes'], 256 * 1024 * 1024)
        self.assertEqual(fixture['spool_free_reserve_bytes'], 64 * 1024 * 1024)
        self.assertIsNone(fixture['native_request_append_count'])

    def test_missing_and_present_content_type_are_distinct_fixture_inputs(self):
        missing = FIXTURES.fixture('NEED-request-content-type-missing')
        present = FIXTURES.fixture('NEED-request-content-type-present')
        self.assertIsNone(missing['request_content_type'])
        self.assertEqual(present['request_content_type'], 'text/plain')
        self.assertNotEqual(missing['path'], present['path'])

    def test_stale_retained_source_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'retained source boundary'):
            FIXTURES.replace_once('two two', 'two', 'three')

    def test_main_allocation_joins_actual_constructor_in_main_window(self):
        rows = [self.constructor(9, 101), self.constructor(50, 201)]
        self.assertEqual(PACKET.selected_scope(rows, 100, 150), 9)

    def test_equal_ids_cannot_replace_typed_native_join(self):
        row = self.constructor(9, 101)
        row.update(allocation_join_verified=False, canonical_transaction_id='same-id')
        with self.assertRaisesRegex(ValueError, 'typed main allocation'):
            PACKET.selected_scope([row], 100, 150)

    def test_multiple_main_allocations_are_rejected(self):
        rows = [self.constructor(9, 101), self.constructor(50, 102)]
        with self.assertRaisesRegex(ValueError, 'one typed main allocation'):
            PACKET.selected_scope(rows, 100, 150)

    def test_failed_constructor_absence_requires_actual_output_scalar(self):
        row = self.constructor(9, 101)
        row.update(result=0, allocation_join_verified=False)
        self.assertIsNone(PACKET.failed_constructor_absence([row], 9))
        row.update(output_argument_present=True, actual_output_handle_present=False)
        actual = PACKET.failed_constructor_absence([row], 9)
        self.assertIsNone(actual['actual_returned_handle'])
        self.assertFalse(actual['allocation_join_verified'])
        self.assertEqual(actual['nested_actual_native_ids'], [])
        row['actual_output_handle_present'] = True
        self.assertIsNone(PACKET.failed_constructor_absence([row], 9))

    def test_abort_fixture_exceeds_actual_stock_read_chunk(self):
        fixture = FIXTURES.fixture('NEED-rst-disconnect')
        self.assertGreater(len(bytes.fromhex(fixture['response_hex'])), 8192)
        self.assertEqual(fixture['backend_split_bytes'], 8192)
        self.assertEqual(fixture['client_abort_mode'], 'reset')
        self.assertEqual(fixture['expected_response_finalizations'], 0)

    def test_incomplete_fixture_does_not_expect_native_eos(self):
        fixture = FIXTURES.fixture('NEED-missing-eos')
        self.assertTrue(fixture['backend_incomplete'])
        self.assertEqual(fixture['expected_client_exit'], 1)
        self.assertEqual(fixture['expected_response_finalizations'], 0)

    def test_existing_boundary_faults_preserve_distinct_commit_expectations(self):
        before = FIXTURES.fixture('transaction_begin_failure_cleanup')
        finish = FIXTURES.fixture('finish_failure_propagation')
        self.assertEqual(before['diagnostic_boundary_fault'], 'request_headers_error')
        self.assertEqual(before['expected_visible_status'], 500)
        self.assertEqual(before['expected_backend_main_count'], 0)
        self.assertEqual(finish['diagnostic_boundary_fault'], 'logging_error')
        self.assertEqual(finish['expected_visible_status'], 200)
        self.assertEqual(finish['expected_backend_main_count'], 1)
        self.assertTrue(before['preserve_original_oracle'])
        self.assertTrue(finish['preserve_original_oracle'])

    def test_event_limit_relocation_remains_valid_launcher_python(self):
        source = FIXTURES._launch_caller_and_transport(
            "config = 'default_error_status=502'",
            {'configured_event_json_limit': 512})
        namespace = {}
        exec(compile(source, '<bounded-event-config>', 'exec'), namespace)
        self.assertEqual(namespace['config'].splitlines(),
                         ['default_error_status=502', 'max_event_json_bytes=512'])

    @staticmethod
    def constructor(scope, time):
        return {'function': 'runtime_begin_request_stream', 'edge': 'return',
                'allocation_scope_call': scope, 'allocation_join_verified': True, 'monotonic_ns': time}



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == '__main__':
    unittest.main()
