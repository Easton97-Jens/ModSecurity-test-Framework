"""Actual original SPOP client windows; no HAProxy runtime is involved."""
from pathlib import Path
import json
import hashlib
import os
import socket
import subprocess
import sys
import signal
import tempfile
import threading
import time
import unittest
from unittest import mock
from modsecurity_connector_tests.test_haproxy_i12_spop_wire import HOST, CASES


class OriginalClientWindow(unittest.TestCase):
    def capture(self, client):
        root=Path(os.environ.get("TMPDIR","/var/tmp/codex/ModSecurity-conector/tmp"))
        root.mkdir(parents=True,exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="spop-client-window-",dir=root) as directory:
            output=Path(directory)
            before_wall,before_mono=time.time_ns(),time.monotonic_ns()
            error=None
            try:
                with mock.patch.object(HOST,"ROOT",output):
                    HOST.capture_original_request(client,CASES.named_profile("NEED-complete-sample"),0,False,1)
            except OSError as exc:
                error=exc
            after_wall,after_mono=time.time_ns(),time.monotonic_ns()
            row=json.loads((output/HOST.CLIENT_FILE).read_text())
            raw=(output/"response-0.raw").read_bytes()
            sent=(output/"request-0.raw").read_bytes()
            self.assertEqual(sent,CASES.profile_wire(CASES.named_profile("NEED-complete-sample")))
            self.assertEqual(row["request_sha256"],hashlib.sha256(sent).hexdigest())
        for clock,lower,upper in (("wall",before_wall,after_wall),("monotonic",before_mono,after_mono)):
            self.assertLessEqual(lower,row["started_"+clock+"_ns"])
            self.assertLessEqual(row["started_"+clock+"_ns"],row["request_send_started_"+clock+"_ns"])
            self.assertLessEqual(row["request_send_started_"+clock+"_ns"],row["completed_"+clock+"_ns"])
            self.assertLessEqual(row["completed_"+clock+"_ns"],upper)
            sent=row["request_send_completed_"+clock+"_ns"]
            if sent is not None:
                self.assertLessEqual(row["request_send_started_"+clock+"_ns"],sent)
                self.assertLessEqual(sent,row["completed_"+clock+"_ns"])
        self.assertEqual(row["pid"],os.getpid())
        return row,raw,error

    def connected(self, respond):
        listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        listener.bind(("127.0.0.1",0));listener.listen(1)
        release=threading.Event();received=[];errors=[];server_received=[]
        def server():
            try:
                with listener.accept()[0] as connection:
                    connection.settimeout(2)
                    data=bytearray()
                    while b"\r\n\r\n" not in data:
                        data.extend(connection.recv(65536))
                    header,_,body=bytes(data).partition(b"\r\n\r\n")
                    length=int(next(line.split(b":",1)[1] for line in header.split(b"\r\n") if line.lower().startswith(b"content-length:")))
                    while len(body)<length:
                        chunk=connection.recv(65536)
                        if not chunk: raise OSError("component request body truncated")
                        data.extend(chunk);body+=chunk
                    server_received.append((time.time_ns(),time.monotonic_ns()))
                    received.append(bytes(data))
                    if respond: connection.sendall(CASES.BACKEND_RESPONSE)
                    else: release.wait(2)
            except OSError as exc: errors.append(exc)
        worker=threading.Thread(target=server);worker.start()
        client=socket.create_connection(listener.getsockname(),timeout=1)
        client.settimeout(1 if respond else .025)
        local,peer=list(client.getsockname()),list(client.getpeername())
        try:
            row,raw,error=self.capture(client)
        finally:
            client.close();release.set();listener.close();worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors,[])
        self.assertEqual(received,[CASES.profile_wire(CASES.named_profile("NEED-complete-sample"))])
        if respond:
            for clock,stamp in zip(("wall","monotonic"),server_received[0]):
                self.assertLessEqual(row["started_"+clock+"_ns"],stamp)
                self.assertLessEqual(stamp,row["completed_"+clock+"_ns"])
        self.assertEqual(row["connection_local"],local)
        self.assertEqual(row["connection_peer"],peer)
        self.assertIsNone(row["connection_local_missing_reason"])
        self.assertIsNone(row["connection_peer_missing_reason"])
        return row,raw,error

    def test_real_client_response_has_actual_ordered_window_and_endpoints(self):
        row,raw,error=self.connected(True)
        self.assertIsNone(error)
        self.assertEqual(raw,CASES.BACKEND_RESPONSE)
        self.assertEqual(row["terminal"],"tcp-eof")
        self.assertIsNone(row["error_type"])
        self.assertTrue(row["measurement"]["complete_length_framing"])

    def test_real_read_timeout_keeps_window_and_socket_observations(self):
        row,raw,error=self.connected(False)
        self.assertIsNone(error) # Existing recv-error behavior is preserved.
        self.assertEqual(raw,b"")
        self.assertEqual(row["terminal"],"TimeoutError")
        self.assertEqual(row["error_type"],"TimeoutError")
        self.assertEqual(row["error_stage"],"response_read")
        self.assertIsNotNone(row["request_send_completed_wall_ns"])

    def test_real_closed_socket_send_error_is_recorded_then_propagated(self):
        client=socket.socket(socket.AF_INET,socket.SOCK_STREAM);client.close()
        row,raw,error=self.capture(client)
        self.assertIsInstance(error,OSError)
        self.assertEqual(raw,b"")
        self.assertEqual(row["error_stage"],"request_send")
        self.assertIsNone(row["request_send_completed_wall_ns"])
        self.assertIsNone(row["request_send_completed_monotonic_ns"])
        self.assertIsNotNone(row["request_send_missing_reason"])
        for field in ("connection_local","connection_peer"):
            self.assertIsNone(row[field]);self.assertEqual(row[field+"_missing_reason"],"OSError")


class OriginalClientProcess(unittest.TestCase):
    def run_child(self, source, timeout=2):
        root=Path(os.environ.get("TMPDIR","/var/tmp/codex/ModSecurity-conector/tmp"))
        root.mkdir(parents=True,exist_ok=True)
        argv=[sys.executable,"-c",source]
        with tempfile.TemporaryDirectory(prefix="spop-client-process-",dir=root) as directory:
            output=Path(directory);failure=None;code=None
            try:
                with mock.patch.object(HOST,"ROOT",output):
                    code=HOST.wait_original_client(argv,timeout=timeout)
            except subprocess.TimeoutExpired as exc:
                failure=exc
            row=json.loads((output/HOST.COMMANDS_FILE).read_text())
            stdout=(output/"client.stdout").read_text()
            stderr=(output/"client.stderr").read_text()
        self.assertEqual(row["argv"],argv)
        self.assertTrue(row["reaped"])
        self.assertEqual(row["parent_pid"],os.getpid())
        self.assertIsNone(row["pid_missing_reason"])
        self.assertEqual(row["pid"],int(stdout.strip()))
        self.assertNotEqual(row["pid"],os.getpid())
        with self.assertRaises(ChildProcessError): os.waitpid(row["pid"],os.WNOHANG)
        return row,code,failure,stderr

    def test_actual_waited_zero_and_nonzero_child_identity(self):
        for status in (0,7):
            with self.subTest(status=status):
                row,code,error,stderr=self.run_child(f"import os,sys; print(os.getpid(),flush=True); print('raw-stderr',file=sys.stderr,flush=True); sys.exit({status})")
                self.assertEqual((row["exit"],code),(status,status))
                self.assertIsNone(error);self.assertFalse(row["timed_out"])
                self.assertIsNone(row["signal"]);self.assertEqual(stderr,"raw-stderr\n")

    def test_actual_signaled_child_is_reaped_and_not_reported_as_success(self):
        row,code,error,_=self.run_child("import os,signal; print(os.getpid(),flush=True); os.kill(os.getpid(),signal.SIGTERM)")
        self.assertEqual(row["signal"],signal.SIGTERM)
        self.assertEqual((row["exit"],code),(-signal.SIGTERM,-signal.SIGTERM))
        self.assertIsNone(error);self.assertFalse(row["timed_out"])

    def test_actual_timeout_kills_waits_and_records_before_propagating(self):
        row,code,error,_=self.run_child("import os,time; print(os.getpid(),flush=True); time.sleep(5)",timeout=.25)
        self.assertIsInstance(error,subprocess.TimeoutExpired)
        self.assertIsNone(code);self.assertTrue(row["timed_out"])
        self.assertEqual(row["signal"],signal.SIGKILL)
        self.assertEqual(row["exit"],-signal.SIGKILL)

    def test_original_launcher_preserves_argv_and_forty_second_timeout(self):
        with mock.patch.object(HOST,"wait_original_client",return_value=0) as waited:
            HOST.run_original_client()
        waited.assert_called_once_with([sys.executable,str(Path(HOST.__file__).resolve()),"--original-client"],timeout=40)
        with mock.patch.object(HOST,"wait_original_client",return_value=7),self.assertRaisesRegex(RuntimeError,"independent original client failed"):
            HOST.run_original_client()

    def test_launch_failure_has_explicit_null_identity_without_fabricated_exit(self):
        root=Path(os.environ.get("TMPDIR","/var/tmp/codex/ModSecurity-conector/tmp"))
        root.mkdir(parents=True,exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="spop-client-launch-",dir=root) as directory:
            output=Path(directory);argv=[str(output/"missing-client")]
            with mock.patch.object(HOST,"ROOT",output),self.assertRaises(FileNotFoundError):
                HOST.wait_original_client(argv)
            row=json.loads((output/HOST.COMMANDS_FILE).read_text())
        self.assertEqual(row["argv"],argv)
        self.assertIsNone(row["pid"]);self.assertEqual(row["pid_missing_reason"],"client-launch-failed")
        self.assertIsNone(row["exit"]);self.assertIsNone(row["signal"])
        self.assertFalse(row["reaped"]);self.assertFalse(row["timed_out"])

# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)
