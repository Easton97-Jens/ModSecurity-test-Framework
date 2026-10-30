"""Physical file transport contracts; no host lifecycle or oracle qualification."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import contextlib
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

ROOT = connector_root()
HERE = source_path('connectors/traefik/harness/i12_file', root=ROOT)
FIXTURES = source_path('connectors/traefik/harness/fixtures/i12-file-source', root=ROOT)


def load(name):
    spec = importlib.util.spec_from_file_location("file_source_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    # The isolated staged CLI uses these same adjacent module names.
    with mock.patch.dict(sys.modules, {"source": SOURCE} if name != "source" else {}):
        spec.loader.exec_module(module)
    return module


SOURCE = load("source")
HTTP = load("http_stream")
with mock.patch.dict(sys.modules, {"source": SOURCE, "http_stream": HTTP}):
    RUN = load("run")
SDK = load("sdk_capability")
ACCEPTANCE = load("acceptance")


class FileSourceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="traefik-file-test-",
                                                     dir="/var/tmp/codex/ModSecurity-conector")
        self.root = Path(self.temporary.name)
        self.private = self.root / "private"
        self.evidence = self.root / "evidence"
        self.private.mkdir(mode=0o700)
        self.evidence.mkdir(mode=0o700)
        self.manifest = RUN.load_manifest(FIXTURES / "manifest.json")
        RUN.stage(FIXTURES, self.private, self.manifest)
        self.spec = self.manifest["files"][1]

    def tearDown(self):
        self.temporary.cleanup()

    def source_failure(self, spec=None, consume=None):
        with self.assertRaises(SOURCE.SourceFailure) as caught:
            SOURCE.stream_file(self.private, spec or self.spec, consume or (lambda *_: None))
        self.assertFalse(caught.exception.receipt["complete"])
        self.assertIsNone(caught.exception.receipt["native_eos"])
        self.assertFalse(caught.exception.receipt["native_file_api"])
        return caught.exception.receipt

    def test_exact_fixtures_and_marker_spans_two_physical_reads(self):
        for spec in self.manifest["files"]:
            with self.subTest(file=spec["relative_path"]):
                chunks = []
                result = SOURCE.stream_file(self.private, spec, lambda part, event: chunks.append(part))
                body = b"".join(chunks)
                self.assertEqual(hashlib.sha256(body).hexdigest(), spec["sha256"])
                self.assertEqual(result["bytes"], spec["size"])
                self.assertTrue(result["complete"])
                self.assertEqual(result["pre_stat"], result["post_stat"])
                self.assertEqual(result["close"]["result"], 0)
                self.assertEqual(result["root_close"]["result"], 0)
                self.assertEqual(result["eof_read_result"], 0)
                for index, event in enumerate(result["reads"]):
                    self.assertEqual(event["offset"], index * spec["read_size"])
                    self.assertEqual(event["result"], len(chunks[index]))
                    self.assertEqual(event["sha256"], hashlib.sha256(chunks[index]).hexdigest())
                if "marker" in spec:
                    marker = spec["marker"].encode()
                    self.assertEqual(body.find(marker), spec["marker_offset"])
                    self.assertFalse(any(marker in part for part in chunks))
                    offset = spec["marker_offset"] % spec["read_size"]
                    self.assertLessEqual(offset + len(marker), spec["read_size"] * 2)

    def test_outside_sample_is_host_capacity_negative_not_assumed_prefix(self):
        spec = self.manifest["files"][2]
        self.assertGreater(spec["size"], 4096)
        self.assertGreater(spec["marker_offset"], 4096)
        self.assertEqual(spec["pinned_host_maxBodySize"], 4096)
        self.assertNotIn("host_authorization_sample_bytes", spec)

    def test_missing_source(self):
        (self.private / self.spec["relative_path"]).unlink()
        result = self.source_failure()
        self.assertEqual(result["error"]["errno"], errno.ENOENT)
        self.assertIsNone(result["close"])
        self.assertEqual(result["root_close"]["result"], 0)

    def test_symlink_source(self):
        name = self.private / self.spec["relative_path"]
        name.unlink()
        name.symlink_to(FIXTURES / "request-marker.txt")
        self.assertEqual(self.source_failure()["error"]["errno"], errno.ELOOP)

    def test_root_symlink(self):
        alias = self.root / "alias"
        alias.symlink_to(self.private, target_is_directory=True)
        with self.assertRaises(SOURCE.SourceFailure):
            SOURCE.stream_file(alias, self.spec, lambda *_: None)

    def test_nonregular_directory_and_fifo(self):
        name = self.private / self.spec["relative_path"]
        name.unlink()
        name.mkdir()
        self.assertIn("regular file", self.source_failure()["error"]["message"])
        name.rmdir()
        os.mkfifo(name, 0o600)
        self.assertIn("regular file", self.source_failure()["error"]["message"])

    def test_hardlink_rejected(self):
        os.link(self.private / self.spec["relative_path"], self.private / "alias")
        self.assertIn("single-link", self.source_failure()["error"]["message"])

    def test_insecure_root_and_file_modes(self):
        self.private.chmod(0o755)
        self.assertIn("mode0700", self.source_failure()["error"]["message"])
        self.private.chmod(0o700)
        (self.private / self.spec["relative_path"]).chmod(0o644)
        self.assertIn("mode0600", self.source_failure()["error"]["message"])

    def test_same_size_mutation(self):
        def mutate(*_):
            with (self.private / self.spec["relative_path"]).open("r+b") as output:
                output.write(b"X")
        result = self.source_failure(consume=mutate)
        self.assertIn("mutated", result["error"]["message"])
        self.assertNotEqual(result["pre_stat"], result["post_stat"])
        self.assertEqual(result["close"]["result"], 0)

    def test_replaced_path(self):
        def replace(*_):
            target = self.private / self.spec["relative_path"]
            target.rename(self.private / "original")
            target.write_bytes(b"X" * self.spec["size"])
        self.assertIn("mutated or replaced", self.source_failure(consume=replace)["error"]["message"])

    def test_wrong_hash_rejected(self):
        result = self.source_failure(spec=self.spec | {"sha256": "0" * 64})
        self.assertIn("hash mismatch", result["error"]["message"])
        self.assertEqual(result["bytes"], self.spec["size"])

    def test_physical_short_read_recorded(self):
        actual = os.read
        with mock.patch.object(SOURCE.os, "read", side_effect=lambda fd, count: actual(fd, max(0, count - 1))):
            result = self.source_failure()
        self.assertEqual(result["reads"][0]["result"], 23)
        self.assertEqual(result["bytes"], 23)
        self.assertIn("short read", result["error"]["message"])

    def test_read_errno_recorded(self):
        with mock.patch.object(SOURCE.os, "read", side_effect=OSError(errno.EIO, "negative-control")):
            result = self.source_failure()
        self.assertEqual(result["reads"][0]["result"], -1)
        self.assertEqual(result["reads"][0]["errno"], errno.EIO)

    def test_close_error_fail_closed(self):
        actual, count = os.close, 0
        def close(fd):
            nonlocal count
            actual(fd)
            count += 1
            if count == 1:
                raise OSError(errno.EIO, "closed but reported injected error")
        with mock.patch.object(SOURCE.os, "close", side_effect=close):
            result = self.source_failure()
        self.assertEqual(result["close"]["result"], -1)
        self.assertEqual(result["root_close"]["result"], 0)

    def test_consumer_failure_closes_source(self):
        def broken(*_):
            raise BrokenPipeError("planned transport failure")
        result = self.source_failure(consume=broken)
        self.assertEqual(result["close"]["result"], 0)
        self.assertEqual(len(result["reads"]), 1)
        self.assertNotIn("consumer_returned_ns", result["reads"][0])

    def test_manifest_path_and_bounds(self):
        for change in ({"relative_path": "../bad"}, {"relative_path": "/bad"}, {"relative_path": "a/b"},
                       {"relative_path": "."}, {"relative_path": "x\x00"}, {"size": True},
                       {"size": -1}, {"size": 524289}, {"size": 524288, "read_size": 1},
                       {"read_size": 0}, {"read_size": 65537},
                       {"sha256": "F" * 64}):
            with self.subTest(change=change):
                self.assertIn("error", self.source_failure(spec=self.spec | change))

    def test_staging_never_overwrites(self):
        with self.assertRaises(FileExistsError):
            RUN.stage(FIXTURES, self.private, self.manifest)

    def test_actual_reader_child_process_receipt(self):
        command = "import sys,json; sys.path.insert(0,sys.argv[1]); import source; print(json.dumps(source.stream_file(sys.argv[2],json.loads(sys.argv[3]),lambda data,event:None)))"
        process = subprocess.run([sys.executable, "-I", "-c", command, str(HERE), str(self.private), json.dumps(self.spec)],
                                 capture_output=True, text=True, check=True, timeout=10)
        result = json.loads(process.stdout)
        self.assertNotEqual(result["pid"], os.getpid())
        self.assertTrue(result["complete"])
        self.assertEqual(result["bytes"], self.spec["size"])

    def test_actual_reader_child_negative_processes(self):
        command = """import sys,json,os
sys.path.insert(0,sys.argv[1])
import source
from pathlib import Path
root=Path(sys.argv[2]); spec=json.loads(sys.argv[3]); mode=sys.argv[4]
path=root/spec['relative_path']
def consume(data,event):
    if mode=='mutation':
        fd=os.open(path,os.O_WRONLY|os.O_NOFOLLOW)
        try:
            os.write(fd,b'X'); os.fsync(fd)
        finally:
            os.close(fd)
try:
    source.stream_file(root,spec,consume)
except source.SourceFailure as error:
    print(json.dumps(error.receipt)); sys.exit(7)
sys.exit(0)
"""
        path = self.private / self.spec["relative_path"]
        original = path.read_bytes()
        for mode in ("missing", "symlink", "mutation"):
            with self.subTest(mode=mode):
                path.unlink(missing_ok=True)
                if mode == "symlink":
                    path.symlink_to(FIXTURES / self.spec["relative_path"])
                elif mode == "mutation":
                    path.write_bytes(original)
                    path.chmod(0o600)
                process = subprocess.run([sys.executable, "-I", "-c", command, str(HERE), str(self.private),
                                          json.dumps(self.spec), mode], capture_output=True, text=True, timeout=10)
                self.assertEqual(process.returncode, 7, process.stderr)
                receipt = json.loads(process.stdout)
                self.assertFalse(receipt["complete"])
                self.assertNotEqual(receipt["pid"], os.getpid())
                self.assertEqual(receipt["root_close"]["result"], 0)
                if mode == "mutation":
                    self.assertEqual(receipt["close"]["result"], 0)
                    self.assertIn("mutated", receipt["error"]["message"])

    def test_stream_http_chunk_mapping_and_distinct_eos(self):
        class Connection:
            def __init__(self):
                self.data = bytearray()
            def sendall(self, data):
                self.data.extend(data)
        connection, receipt = Connection(), {}
        HTTP.stream_chunks(connection, self.private, self.spec, receipt)
        self.assertTrue(bytes(connection.data).endswith(b"0\r\n\r\n"))
        self.assertIsNone(receipt["file_source"]["native_eos"])
        self.assertGreater(receipt["http_terminator_send_started_ns"], receipt["file_source"]["close"]["completed_ns"])
        self.assertEqual(len(receipt["http_chunks"]), len(receipt["file_source"]["reads"]))
        for read, chunk in zip(receipt["file_source"]["reads"], receipt["http_chunks"]):
            self.assertEqual(read["sha256"], chunk["entity_sha256"])
            self.assertFalse(chunk["remote_delivery_proven"])

    def test_source_failure_omits_http_terminator(self):
        connection = mock.Mock()
        receipt = {}
        with self.assertRaises(SOURCE.SourceFailure):
            HTTP.stream_chunks(connection, self.private, self.spec | {"sha256": "0" * 64}, receipt)
        self.assertFalse(receipt["file_source"]["complete"])
        self.assertNotIn("http_terminator_send_started_ns", receipt)
        self.assertFalse(any(call.args[0] == b"0\r\n\r\n" for call in connection.sendall.call_args_list))

    def test_http_parser_real_socketpair_framing(self):
        with contextlib.ExitStack() as stack:
            sender, receiver = socket.socketpair()
            stack.enter_context(sender)
            stack.enter_context(receiver)
            sender.sendall(b"POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n")
            wire, entity, headers = HTTP.read_request(receiver)
            self.assertEqual(entity, b"abcde")
            self.assertEqual(headers[b"host"], b"example.test")
            self.assertTrue(wire.endswith(b"0\r\n\r\n"))

    def test_http_parser_rejects_ambiguous_or_incomplete(self):
        samples = [b"Transfer-Encoding: chunked\r\nContent-Length: 1\r\n\r\n0\r\n\r\n",
                   b"Content-Length: 10\r\n\r\nshort", b"Host: a\r\nHost: b\r\n\r\n",
                   b"Transfer-Encoding: chunked\r\n\r\n-1\r\n",
                   b"Transfer-Encoding: gzip\r\nContent-Length: 3\r\n\r\nabcEXTRA",
                   b"Transfer-Encoding: gzip\r\n\r\nabc",
                   b"Content-Length: 3\r\nContent-Length: 3\r\n\r\nabc",
                   b"Transfer-Encoding: chunked\r\ntransfer-encoding: chunked\r\n\r\n0\r\n\r\n",
                   b"Content-Length : 3\r\n\r\nabc", b"Content-Length: +3\r\n\r\nabc",
                   b"Content-Length: \x0b3\r\n\r\nabc",
                   b"Content-Length: 3,3\r\n\r\nabc", b"Content-Length: \r\n\r\n",
                   b"Content-Length: 524289\r\n\r\n", b"Content-Length: 3\r\n\r\nabcEXTRA",
                   b"Transfer-Encoding: chunked\r\n\r\n+3\r\nabc\r\n0\r\n\r\n",
                   b"Transfer-Encoding: chunked\r\n\r\n3;ext=1\r\nabc\r\n0\r\n\r\n",
                   b"Transfer-Encoding: chunked\r\n\r\n0\r\nX-Trailer: x\r\n\r\n",
                   b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\nEXTRA"]
        for sample in samples:
            with self.subTest(sample=sample), contextlib.ExitStack() as stack:
                sender, receiver = socket.socketpair()
                stack.enter_context(sender)
                stack.enter_context(receiver)
                sender.sendall(b"POST / HTTP/1.1\r\n" + sample)
                sender.shutdown(socket.SHUT_WR)
                with self.assertRaises(ValueError):
                    HTTP.read_request(receiver)

    def test_http_parser_bodyless_get_does_not_wait_for_peer_eof(self):
        sender, receiver = socket.socketpair()
        with sender, receiver:
            receiver.settimeout(0.1)
            wire = b"GET /no-crs/allow HTTP/1.1\r\nHost: example.test\r\n\r\n"
            sender.sendall(wire)
            # Sender remains open: framing completion does not require TCP EOF.
            actual, entity, _ = HTTP.read_request(receiver)
            self.assertEqual(actual, wire)
            self.assertEqual(entity, b"")
            self.assertEqual(receiver.gettimeout(), 0.1)

    def test_backend_invalid_framing_never_records_http_eos(self):
        sender, receiver = socket.socketpair()
        listener = mock.MagicMock()
        listener.__enter__.return_value = listener
        listener.accept.return_value = receiver, ("127.0.0.1", 23456)
        wire = (b"POST / HTTP/1.1\r\nTransfer-Encoding: gzip\r\nContent-Length: 3\r\n"
                b"X-Request-Id: tf-bad-frame\r\nX-I12-Acceptance-Key: bad-frame\r\n\r\nabcEXTRA")
        with sender:
            sender.sendall(wire)
            with mock.patch.object(HTTP.socket, "socket", return_value=listener):
                result = HTTP.response_backend(23457, "bad-frame", self.private, self.spec,
                                               self.evidence, transaction_id="tf-bad-frame")
        self.assertEqual(result["independent_backend_accept_count"], 1)
        self.assertFalse(result["request_http_framing_valid"])
        self.assertNotIn("request_http_eos_ns", result)
        self.assertNotIn("file_source", result)
        self.assertTrue((self.evidence / "bad-frame.backend-request.raw").read_bytes().startswith(b"POST /"))
        self.assertEqual(result["error"]["type"], "RequestFramingFailure")

    def test_backend_wire_budget_includes_chunk_framing(self):
        wire = bytearray(b"a" * HTTP.MAX_WIRE)
        with self.assertRaises(ValueError):
            HTTP._wire_append(wire, b"x")
        self.assertEqual(len(wire), HTTP.MAX_WIRE)

    def test_client_process_measurement_not_native_eos(self):
        connection = mock.MagicMock()
        connection.__enter__.return_value = connection
        connection.recv.side_effect = [b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n", b""]
        connection.getsockname.return_value = ("127.0.0.1", 12345)
        connection.getpeername.return_value = ("127.0.0.1", 12346)
        with mock.patch.object(HTTP.socket, "create_connection", return_value=connection):
            result = HTTP.request_client(12346, "file-test-1", self.private, self.spec, self.evidence)
        self.assertEqual(result["actual_status"], 403)
        self.assertTrue(result["tcp_eof"])
        self.assertIsNone(result["native_eos"])
        self.assertEqual(result["qualification"], "unqualified")
        self.assertTrue(result["file_source"]["complete"])
        self.assertTrue((self.evidence / "file-test-1.response.raw").is_file())

    def test_backend_persists_accept_before_source_failure(self):
        listener, connection = mock.MagicMock(), mock.MagicMock()
        listener.__enter__.return_value = listener
        listener.accept.return_value = connection, ("127.0.0.1", 23456)
        connection.__enter__.return_value = connection
        (self.private / self.spec["relative_path"]).unlink()
        with mock.patch.object(HTTP.socket, "socket", return_value=listener), mock.patch.object(
                HTTP, "read_request", return_value=(b"raw", b"", {
                    b"x-request-id": b"tf-file-test-2", b"x-i12-acceptance-key": b"file-test-2"})):
            result = HTTP.response_backend(23457, "file-test-2", self.private, self.spec, self.evidence,
                                           transaction_id="tf-file-test-2")
        self.assertEqual(result["independent_backend_accept_count"], 1)
        self.assertTrue((self.evidence / "file-test-2.backend-accept.json").is_file())
        self.assertFalse(result["file_source"]["complete"])
        self.assertNotIn("http_terminator_send_started_ns", result)

    def test_client_preserves_actual_prefix_after_reset(self):
        connection = mock.MagicMock()
        connection.__enter__.return_value = connection
        prefix = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\npart"
        connection.recv.side_effect = [prefix, ConnectionResetError("negative-control-reset")]
        connection.getsockname.return_value = ("127.0.0.1", 12345)
        connection.getpeername.return_value = ("127.0.0.1", 12346)
        with mock.patch.object(HTTP.socket, "create_connection", return_value=connection):
            result = HTTP.request_client(12346, "file-test-reset", self.private, self.spec, self.evidence)
        self.assertEqual(result["actual_status"], 200)
        self.assertFalse(result["tcp_eof"])
        self.assertEqual(result["client_response_wire_bytes"], len(prefix))
        self.assertEqual((self.evidence / "file-test-reset.response.raw").read_bytes(), prefix)
        self.assertEqual(result["error"]["type"], "ConnectionResetError")
        self.assertIsNone(result["native_eos"])

    def test_upload_broken_pipe_still_retains_actual_host_response(self):
        connection = mock.MagicMock()
        connection.__enter__.return_value = connection
        connection.sendall.side_effect = [None, BrokenPipeError("host rejected upload")]
        raw = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n"
        connection.recv.side_effect = [raw, b""]
        connection.getsockname.return_value = ("127.0.0.1", 12345)
        connection.getpeername.return_value = ("127.0.0.1", 12346)
        with mock.patch.object(HTTP.socket, "create_connection", return_value=connection):
            result = HTTP.request_client(12346, "file-upload-rejected", self.private,
                                         self.spec, self.evidence)
        self.assertEqual(result["actual_status"], 401)
        self.assertTrue(result["tcp_eof"])
        self.assertTrue(result["response_http_complete"])
        self.assertEqual(result["client_response_wire_bytes"], len(raw))
        self.assertEqual((self.evidence / "file-upload-rejected.response.raw").read_bytes(), raw)
        self.assertIn("upload_error", result)
        self.assertNotIn("receive_error", result)
        self.assertFalse(result["file_source"]["complete"])
        self.assertEqual(result["file_source"]["error"]["type"], "BrokenPipeError")
        self.assertNotIn("http_terminator_send_started_ns", result)
        self.assertEqual(result["response_receive_budget_seconds"], 15)
        self.assertIsNone(result["native_eos"])

    def test_upload_and_receive_errors_keep_incomplete_host_prefix(self):
        connection = mock.MagicMock()
        connection.__enter__.return_value = connection
        connection.sendall.side_effect = [None, BrokenPipeError("host rejected upload")]
        raw = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 8\r\n\r\npart"
        connection.recv.side_effect = [raw, TimeoutError("bounded negative receive")]
        connection.getsockname.return_value = ("127.0.0.1", 12345)
        connection.getpeername.return_value = ("127.0.0.1", 12346)
        with mock.patch.object(HTTP.socket, "create_connection", return_value=connection):
            result = HTTP.request_client(12346, "file-upload-prefix", self.private,
                                         self.spec, self.evidence)
        self.assertEqual(result["actual_status"], 403)
        self.assertIn("upload_error", result)
        self.assertEqual(result["receive_error"]["type"], "TimeoutError")
        self.assertFalse(result["tcp_eof"])
        self.assertFalse(result["response_http_complete"])
        self.assertNotIn("client_response_entity_bytes", result)
        self.assertEqual((self.evidence / "file-upload-prefix.response.raw").read_bytes(), raw)

    def test_response_receive_total_deadline_bounds_slow_prefix(self):
        connection = mock.Mock()
        connection.recv.return_value = b"prefix"
        received = bytearray()
        with mock.patch.object(HTTP.time, "monotonic", side_effect=[100, 101, 116]):
            with self.assertRaisesRegex(TimeoutError, "deadline expired"):
                HTTP.receive_bounded(connection, received)
        self.assertEqual(received, b"prefix")
        connection.settimeout.assert_called_once_with(14)
        connection.recv.assert_called_once()

    def test_save_exclusive(self):
        HTTP.save_new(self.evidence, "receipt.json", {})
        with self.assertRaises(FileExistsError):
            HTTP.save_new(self.evidence, "receipt.json", {})

    def test_distinct_keys_over_actual_loopback_file_http(self):
        errors, observed = [], {}
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(5)
            def serve():
                try:
                    connection, _ = listener.accept()
                    with connection:
                        connection.settimeout(5)
                        wire, entity, headers = HTTP.read_request(connection)
                        observed.update(wire=wire, entity=entity, headers=headers)
                        connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
                except Exception as error:
                    errors.append(error)
            worker = threading.Thread(target=serve)
            worker.start()
            try:
                result = HTTP.request_client(listener.getsockname()[1], "file-target", self.private,
                                             self.spec, self.evidence, transaction_id="tf-native-target")
            finally:
                worker.join(timeout=6)
            self.assertFalse(worker.is_alive())
        self.assertFalse(errors, errors)
        self.assertEqual(observed["headers"][b"x-request-id"], b"tf-native-target")
        self.assertEqual(observed["headers"][b"x-i12-acceptance-key"], b"file-target")
        self.assertEqual(observed["entity"], (self.private / self.spec["relative_path"]).read_bytes())
        self.assertEqual(result["transaction_id"], "tf-native-target")
        self.assertEqual(result["process"]["pid"], os.getpid())
        self.assertTrue(result["process"]["parent_wait_status_required"])
        self.assertTrue(result["response_http_complete"])
        self.assertEqual(result["client_response_entity_bytes"], 5)
        self.assertEqual((self.evidence / "file-target.response-entity.raw").read_bytes(), b"hello")
        self.assertIsNone(result["native_eos"])

    def test_backend_rejects_key_in_wrong_header_and_retains_wire(self):
        listener, connection = mock.MagicMock(), mock.MagicMock()
        listener.__enter__.return_value = listener
        listener.accept.return_value = connection, ("127.0.0.1", 23456)
        connection.__enter__.return_value = connection
        with mock.patch.object(HTTP.socket, "socket", return_value=listener), mock.patch.object(
                HTTP, "read_request", return_value=(b"wrong-header-wire", b"", {
                    b"x-request-id": b"file-wrong", b"x-i12-probe": b"file-wrong"})):
            result = HTTP.response_backend(23457, "file-wrong", self.private, self.spec, self.evidence,
                                           transaction_id="tf-file-wrong")
        self.assertEqual(result["independent_backend_accept_count"], 1)
        self.assertIn("exact transaction/file-key pair", result["error"]["message"])
        self.assertNotIn("file_source", result)
        self.assertEqual((self.evidence / "file-wrong.backend-request.raw").read_bytes(), b"wrong-header-wire")
        connection.sendall.assert_not_called()

    def test_response_entity_requires_exact_complete_framing(self):
        self.assertEqual(HTTP.response_entity(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"),
                         (b"abc", "chunked"))
        for wire in (b"HTTP/1.1 200 OK\r\n\r\nabc", b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabc",
                     b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\nabc",
                     b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n",
                     b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nextra"):
            with self.subTest(wire=wire), self.assertRaises(ValueError):
                HTTP.response_entity(wire)

    def test_acceptance_preserves_four_ids_and_nine_independent_controls(self):
        contract = ACCEPTANCE.build()
        rows = contract["cases"]
        self.assertEqual(len(rows), 9)
        self.assertEqual(len({row["id"] for row in rows}), 4)
        self.assertEqual(len({row["key"] for row in rows}), 9)
        self.assertEqual(len({row["transaction_id"] for row in rows}), 9)
        self.assertEqual(contract["strict"]["scope"], "configuration-negative-only")
        self.assertFalse(contract["strict"]["runtime_claim"])
        self.assertEqual(contract["qualification_promotions"], 0)
        for row in rows:
            self.assertNotEqual(row["key"], row["transaction_id"])
            fixture = next(spec for spec in self.manifest["files"]
                           if spec["relative_path"] == row["file_spec"]["relative_path"])
            for name, value in row["file_spec"].items():
                self.assertEqual(fixture[name], value)
            self.assertEqual(row["expected_sha256"], ACCEPTANCE.digest(row["expected"]))
            self.assertEqual(row["qualification"], "unqualified")
        # Returning a caller-owned copy must not mutate a later frozen contract.
        rows[0]["rules_lines"].clear()
        self.assertTrue(ACCEPTANCE.cases()[0]["rules_lines"])

    def test_frozen_capacity_and_safe_response_oracles_are_separate(self):
        rows = ACCEPTANCE.cases()
        capacity = next(row for row in rows if row["control"] == "capacity")
        self.assertEqual(capacity["expected"]["client_status"], 401)
        self.assertEqual(capacity["expected"]["authorization_transport"], "default-MRC1")
        self.assertEqual(capacity["expected"]["backend_target_arrivals"], 0)
        self.assertEqual(capacity["expected"]["authorization_sample"], "absent")
        self.assertEqual(capacity["expected"]["native_transaction"], "absent")
        self.assertIsNone(capacity["expected"]["native_rule_id"])
        self.assertEqual(capacity["host_forwardauth"]["maxResponseBodySize"], 32768)
        for row in rows:
            if row["direction"] == "response" and row["control"] == "marker":
                self.assertEqual(row["expected"]["client_status"], 200)
                self.assertEqual(row["expected"]["native_intervention_status"], 403)
                self.assertEqual(row["expected"]["native_phase"], 4)
                self.assertEqual(row["expected"]["client_entity"]["sha256"], row["file_spec"]["sha256"])

    def test_acceptance_rules_are_exact_and_hash_bound(self):
        for row in ACCEPTANCE.cases():
            rules = ("\n".join(row["rules_lines"]) + "\n").encode()
            self.assertEqual(row["rules_sha256"], hashlib.sha256(rules).hexdigest())
            self.assertEqual(row["rules_lines"].count(
                'SecRule REQUEST_BODY "@contains no-crs-request-body-marker" "id:1100101,phase:2,deny,status:403,log,t:none"'), 1)
            self.assertEqual(row["rules_lines"].count(
                'SecRule RESPONSE_BODY "@contains no-crs-response-body-marker" "id:1100301,phase:4,deny,status:403,log,t:none"'), 1)

    def test_native_request_deny_does_not_infer_backend_exclusion(self):
        rows = [row for row in ACCEPTANCE.cases() if row["direction"] == "request" and row["control"] == "marker"]
        native = next(row for row in rows if row["route"] == "traefik-native-uds")
        auth = next(row for row in rows if row["route"] == "traefik-forwardauth-request")
        self.assertEqual(native["expected"]["backend_target_arrivals"], "measure-accept-headers-prefix")
        self.assertFalse(native["expected"]["native_request_backend_exclusion_inferred"])
        self.assertEqual(auth["expected"]["backend_target_arrivals"], 0)

    def test_plan_preserves_four_unqualified_original_ids(self):
        plan = json.loads((HERE / "supplement-plan.json").read_text())
        self.assertEqual(len(plan["routes"]), 4)
        self.assertEqual(len({row["id"] for row in plan["routes"]}), 4)
        self.assertEqual(plan["qualification"], "unqualified")
        self.assertEqual(plan["execution_status"], "not_run")
        self.assertFalse(plan["native_file_api"])
        self.assertTrue(all(row["oracle_status"] == "pending-independent-freeze" for row in plan["routes"]))

    def test_sdk_receipt_reports_exact_C_symbols(self):
        header = self.root / "transaction.h"
        library = self.root / "library.so"
        header.write_text("int msc_request_body_from_file(Transaction *, const char *);\n")
        library.write_bytes(b"test-only-library-placeholder")
        result = subprocess.CompletedProcess([], 0, b"0001 T msc_request_body_from_file\n0002 T msc_append_response_body\n", b"")
        with mock.patch.object(SDK.subprocess, "run", return_value=result) as invoked:
            receipt = SDK.inspect(header, library)
        self.assertEqual(invoked.call_args.args[0],
                         ["/usr/bin/nm", "-D", "--defined-only", "--", str(library)])
        self.assertTrue(receipt["request_file_declared"])
        self.assertTrue(receipt["request_file_exported"])
        self.assertEqual(receipt["response_file_C_declarations"], [])
        self.assertEqual(receipt["response_file_C_exports"], [])
        self.assertFalse(receipt["native_file_api_executed"])

    def test_sdk_receipt_rejects_relative_and_symlink_inputs(self):
        header = self.root / "transaction.h"
        library = self.root / "library.so"
        header.write_text("int msc_request_body_from_file(Transaction *, const char *);\n")
        library.write_bytes(b"test-only-library-placeholder")
        with self.assertRaisesRegex(ValueError, "absolute non-symlink"):
            SDK.inspect(Path("transaction.h"), library)
        alias = self.root / "alias.so"
        alias.symlink_to(library)
        with self.assertRaisesRegex(ValueError, "absolute non-symlink"):
            SDK.inspect(header, alias)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
