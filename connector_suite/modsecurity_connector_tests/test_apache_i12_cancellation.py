"""Synthetic gate controls plus real OS termination; never Apache host PASS."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import socket
import tempfile
import time
import unittest

SOURCE = connector_root() / 'ci/runtime/lifecycle/apache-i12/acceptance/cancellation.py'
cancel = load_source(SOURCE)
IDENTITY = {'run': 'synthetic-unit-only', 'case': 'gate-control', 'transaction_id': 'unit-principal'}


def synthetic_rows():
    """Explicit synthetic validator inputs, not captured native observations."""
    base = {'schema': 'native-lifecycle-v1', 'profile': 'apache-native',
            'run': IDENTITY['run'], 'case': IDENTITY['case'], 'uid': os.geteuid(),
            'pid': 12345, 'invalid': False, 'transaction_id': IDENTITY['transaction_id'],
            'allocation_scope_kind': 'host', 'allocation_scope_call': 2, 'result': 1}
    now = time.monotonic_ns()
    definitions = [('native_new_with_id', 'return', 3), ('host_allocation', 'return', 2),
                   ('native_append_request_body', 'enter', 4), ('native_append_request_body', 'return', 4)]
    rows = [dict(base, function=function, edge=edge, call=call, monotonic_ns=now + index)
            for index, (function, edge, call) in enumerate(definitions)]
    rows[1].update(transaction_id=None, allocation_join_verified=True)
    rows[2]['input_size'] = rows[3]['input_size'] = 7
    return rows


def temporary_directory():
    root = Path(os.environ.get("CODEX_TEST_TMP_ROOT") or os.environ.get("RUNNER_TEMP") or
                "/var/tmp/codex/ModSecurity-conector/cancellation-unit-tests")
    root.mkdir(parents=True, exist_ok=True)
    return tempfile.TemporaryDirectory(dir=root)


def write_rows(path, rows):
    path.write_text(''.join(json.dumps(row) + '\n' for row in rows))


class CancellationTests(unittest.TestCase):
    def test_child_terminal_python_events_are_reaped_as_error_exit(self):
        class ChildTerminalEvent(BaseException):
            """Exercise the direct-fork boundary beyond Exception subclasses."""

        for terminal in (SystemExit(0), KeyboardInterrupt(), GeneratorExit(), ChildTerminalEvent()):
            with self.subTest(event=type(terminal).__name__):
                def wire_child():
                    raise terminal

                child = cancel.OwnedWireChild(wire_child)
                pid, status = os.waitpid(child.pid, 0)
                child.waited = cancel.waited_status(pid, status)
                self.assertEqual(child.waited['exit_code'], 78)
                self.assertFalse(child.waited['signalled'])

    def test_child_success_is_not_changed_by_parent_handled_exception_context(self):
        try:
            raise ValueError("parent-only handled error")
        except ValueError:
            child = cancel.OwnedWireChild(lambda: 0)
            pid, status = os.waitpid(child.pid, 0)
        child.waited = cancel.waited_status(pid, status)
        self.assertEqual(child.waited['exit_code'], 0)
        self.assertFalse(child.waited['signalled'])

    def test_gate_accepts_native_zero_and_one_only(self):
        for result in (0, 1):
            rows = synthetic_rows()
            rows[-1]['result'] = result
            self.assertIsNotNone(cancel.find_native_append(rows, IDENTITY, 0))

    def test_missing_or_foreign_evidence_never_opens_gate(self):
        for field, value in [('transaction_id', 'neighbor'), ('input_size', 0), ('result', -1),
                             ('result', 2), ('invalid', True), ('run', 'foreign'),
                             ('allocation_scope_call', 99), ('pid', 98765)]:
            with self.subTest(field=field, value=value):
                rows = synthetic_rows()
                rows[-1][field] = value
                self.assertIsNone(cancel.find_native_append(rows, IDENTITY, 0))
        self.assertIsNone(cancel.find_native_append(synthetic_rows()[:-1], IDENTITY, 0))
        rows = synthetic_rows()
        rows[1]['allocation_join_verified'] = False
        self.assertIsNone(cancel.find_native_append(rows, IDENTITY, 0))
        rows = synthetic_rows()
        rows[2]['monotonic_ns'] = rows[0]['monotonic_ns'] - 1
        self.assertIsNone(cancel.find_native_append(rows, IDENTITY, 0))

    def test_incomplete_tail_is_not_an_observation(self):
        self.assertEqual(cancel.decode_rows(b'{"edge":"return"}'), [])
        with self.assertRaises(cancel.GateError):
            cancel.decode_rows(b'bad\n')

    def test_gate_timeout_has_no_witness(self):
        with temporary_directory() as directory:
            with self.assertRaises(cancel.GateError):
                cancel.wait_for_append(Path(directory) / 'absent', IDENTITY, 0, .03)

    def supervise(self, directory, action, produce=True):
        root = Path(directory)
        native, ready, termination = (root / name for name in ('native.jsonl', 'ready.json', 'termination.json'))
        read_fd, write_fd = os.pipe()
        producer = os.fork()
        if producer == 0:
            os.close(write_fd)
            selected, _, _ = select.select([read_fd], [], [], 3)
            if selected and os.read(read_fd, 1) == b'1' and produce:
                write_rows(native, synthetic_rows())
            os.close(read_fd)
            os._exit(0)
        os.close(read_fd)

        def wire_child():
            started = time.monotonic_ns()
            # Unit-only checkpoint control. No claim of HTTP traffic is made.
            cancel.publish_send_ready(ready, {'started_ns': started,
                'request_send_completed_ns': time.monotonic_ns(),
                'request_send_operations': [{'bytes': 7}]})
            os.write(write_fd, b'1')
            os.close(write_fd)
            cancel.pause_for_parent()

        try:
            result = cancel.supervise_client(wire_child, native, IDENTITY, ready, termination,
                                             action, timeout=.8 if produce else .05)
        finally:
            os.close(write_fd)
            _, status = os.waitpid(producer, 0)
        self.assertEqual(os.WEXITSTATUS(status), 0)
        self.assertEqual(json.loads(termination.read_text()), result)
        with self.assertRaises(ChildProcessError):
            os.waitpid(result['actual_termination']['pid'], os.WNOHANG)
        return result

    def test_real_sigterm_and_cancel_wait_status_after_synthetic_gate(self):
        for action, expected in cancel.ACTIONS.items():
            with self.subTest(action=action), temporary_directory() as directory:
                result = self.supervise(directory, action)
                self.assertTrue(result['requested_action_performed'])
                self.assertEqual(result['wrapper_exit'], 0)
                self.assertEqual(result['actual_termination']['actual_signal'], expected)
                self.assertIsNotNone(result['native_append_gate'])
                self.assertIsNone(result['cleanup_signal_operation'])

    def test_deadline_cleanup_sigterm_is_not_requested_cancel(self):
        with temporary_directory() as directory:
            result = self.supervise(directory, next(iter(cancel.ACTIONS)), produce=False)
        self.assertFalse(result['requested_action_performed'])
        self.assertEqual(result['wrapper_exit'], 1)
        self.assertIsNone(result['native_append_gate'])
        self.assertEqual(result['actual_termination']['actual_signal'], signal.SIGTERM)
        self.assertIsNotNone(result['failure'])

    def test_real_loopback_reset_after_synthetic_gate(self):
        with temporary_directory() as directory:
            native = Path(directory) / 'native.jsonl'
            write_rows(native, synthetic_rows())
            with socket.socket() as listener, socket.socket() as client:
                listener.bind(('127.0.0.1', 0))
                listener.listen(1)
                client.connect(listener.getsockname())
                server, _ = listener.accept()
                with server:
                    server.settimeout(1)
                    client.sendall(b'partial')
                    self.assertEqual(server.recv(7), b'partial')
                    result = cancel.wait_then_reset(client, native, IDENTITY, 0, .2)
                    with self.assertRaises(ConnectionResetError):
                        server.recv(1)
                self.assertEqual(result['actual_linger_option'], [1, 0])
                self.assertEqual(result['actual_socket_fileno_after_close'], -1)
                self.assertIsNone(result['rst_on_wire_observed'])
                self.assertIsNone(result['server_reset_observed'])
                self.assertFalse(result['is_host_qualification'])

    def test_send_checkpoint_rejects_zero_body_and_reversed_time(self):
        with temporary_directory() as directory:
            for progress in ({'started_ns': 2, 'request_send_completed_ns': 1,
                              'request_send_operations': [{'bytes': 1}]},
                             {'started_ns': 1, 'request_send_completed_ns': 2,
                              'request_send_operations': [{'bytes': 0}]}):
                with self.assertRaises(cancel.GateError):
                    cancel.publish_send_ready(Path(directory) / 'ready', progress)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == '__main__':
    unittest.main()
