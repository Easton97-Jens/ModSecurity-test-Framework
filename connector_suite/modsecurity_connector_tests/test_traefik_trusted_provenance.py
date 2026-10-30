"""Real private Traefik MTP1 sockets, atomic claims and reply attestations.

No ModSecurity engine or client HTTP transport is claimed by this fixture.
"""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import json
import os
from pathlib import Path
import select
import shlex
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest

from modsecurity_connector_tests.c_source_contract import function_definition

ROOT = connector_root()
HARNESS = r'''
#define _GNU_SOURCE
#undef poll
#include "connectors/traefik/src/traefik_provenance.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <unistd.h>
#define RUNTIME_PATH_SIZE 4096U
ANCESTORS
static int reject_confirmation;
static int confirmations;
static atomic_int query_wait_armed;
static int fillers[64];
static size_t filler_count;
static int exhaust_descriptors(void) {
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit) != 0) return 0;
    if (limit.rlim_cur > 64U) limit.rlim_cur = 64U;
    if (setrlimit(RLIMIT_NOFILE, &limit) != 0) return 0;
    while (filler_count < sizeof(fillers) / sizeof(fillers[0])) {
        int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (fd < 0) return errno == EMFILE;
        fillers[filler_count++] = fd;
    }
    return 0;
}
int mtp_fixture_poll(struct pollfd *items, nfds_t count, int timeout) {
    if (count == 1U && items[0].events == POLLIN && timeout > 100) {
        if (atomic_exchange(&query_wait_armed, 0)) puts("{\"query_wait\":1}");
    }
    return poll(items, count, timeout);
}
static int confirm_fixture(void *unused, const char *handle, msconnector_error *error) {
    (void)unused; (void)handle; (void)error; ++confirmations; return !reject_confirmation;
}
int main(int argc, char **argv) {
    char command[16], token[256], handle[256];
    int status;
    if (argc != 2) return 2;
    setvbuf(stdout, NULL, _IONBF, 0U);
    int started = msconnector_traefik_provenance_start_with_confirmation(argv[1], confirm_fixture, NULL);
    printf("{\"started\":%d}\n", started);
    if (!started) return 0;
    while (scanf("%15s", command) == 1) {
        if (strcmp(command, "stop") == 0) break;
        if (strcmp(command, "arm-query") == 0) {
            atomic_store(&query_wait_armed, 1); puts("{\"armed\":1}"); continue;
        }
        if (strcmp(command, "exhaust") == 0) {
            printf("{\"exhausted\":%d}\n", exhaust_descriptors()); continue;
        }
        if (strcmp(command, "reject-confirm") == 0) {
            reject_confirmation = 1; puts("{\"reject\":1}"); continue;
        }
        if (strcmp(command, "confirm-count") == 0) {
            printf("{\"confirmations\":%d}\n", confirmations); continue;
        }
        if (scanf("%255s", token) != 1) return 3;
        msconnector_header headers[2] = {
            {MSCONNECTOR_TRAEFIK_PROVENANCE_HEADER, sizeof(MSCONNECTOR_TRAEFIK_PROVENANCE_HEADER)-1U,
             token, strlen(token)}, {0}};
        msconnector_request request = {.headers = headers, .header_count = 1U};
        msconnector_http_authorization_provenance_storage provenance;
        msconnector_error error;
        if (strcmp(command, "missing") == 0) request.header_count = 0U;
        if (strcmp(command, "duplicate") == 0) { headers[1] = headers[0]; request.header_count = 2U; }
        if (strcmp(command, "complete") == 0) {
            if (scanf("%d %255s", &status, handle) != 2) return 4;
            int result = msconnector_traefik_provenance_complete(NULL, &request, status,
                strcmp(handle, "-") == 0 ? NULL : handle, &error);
            printf("{\"result\":%d}\n", result);
        } else {
            int result = msconnector_traefik_provenance_claim(NULL, &request, &provenance, &error);
            printf("{\"result\":%d,\"run\":\"%s\",\"case\":\"%s\",\"connection\":\"%s\",\"reused\":%d}\n",
                result, provenance.run_id, provenance.transport_case_id,
                provenance.connection_id, provenance.connection_reused);
        }
    }
    for (size_t i = 0; i < filler_count; ++i) close(fillers[i]);
    msconnector_traefik_provenance_stop();
    puts("{\"stopped\":1}");
    return 0;
}
'''


class TraefikTrustedProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix="mtp-c-", dir=os.environ.get("RUNNER_TEMP"))
        cls.addClassCleanup(temporary.cleanup)
        cls.directory = Path(temporary.name)
        runtime = (source_path('common/runtime/msconnector_runtime.c', root=ROOT)).read_text()
        fixture = cls.directory / "harness.c"
        fixture.write_text(HARNESS.replace("ANCESTORS", function_definition(runtime,
            "msconnector_runtime_private_directory_ancestors_are_safe")))
        cls.binary = cls.directory / "harness"
        command = shlex.split(os.environ.get("CC", "cc")) + [
            "-std=c17", "-Wall", "-Wextra", "-Werror", "-pthread", "-Dpoll=mtp_fixture_poll",
            "-ffunction-sections", "-Wl,--gc-sections", "-I", str(ROOT),
            "-I", str(source_path('common/include', root=ROOT)), str(fixture),
            str(source_path('connectors/traefik/src/traefik_provenance.c', root=ROOT)),
            str(source_path('common/src/memory.c', root=ROOT)), str(source_path('common/src/error.c', root=ROOT)),
            "-o", str(cls.binary),
        ]
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        if result.returncode:
            raise AssertionError(result.stderr[-6000:])

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="s-", dir=self.directory)
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "p.sock"
        self.process = subprocess.Popen([str(self.binary), str(self.path)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(self.stop)
        self.assertEqual(self.read(), {"started": 1})

    def read(self):
        self.assertTrue(select.select([self.process.stdout], [], [], 3)[0], "fixture response timeout")
        return json.loads(self.process.stdout.readline())

    def command(self, text):
        self.process.stdin.write(text + "\n")
        self.process.stdin.flush()
        return self.read()

    def stop(self):
        if self.process.poll() is None:
            self.process.stdin.write("stop\n")
            self.process.stdin.flush()
            self.process.wait(timeout=4)
        self.process.stdin.close()
        self.process.stdout.close()
        self.process.stderr.close()

    @staticmethod
    def frame(op, payload=b"", version=1):
        return b"MTP1" + bytes([version, op, 0, 0]) + struct.pack("!I", len(payload)) + payload

    def connection(self):
        connection = socket.socket(socket.AF_UNIX)
        connection.settimeout(3)
        connection.connect(str(self.path))
        self.addCleanup(connection.close)
        return connection

    @staticmethod
    def exact(connection, size):
        data = b""
        while len(data) < size:
            part = connection.recv(size - len(data))
            if not part:
                raise EOFError("private peer closed")
            data += part
        return data

    def reserve(self, connection=None, values=(b"run-1", b"case-1", b"opaque-1"), reuse=0):
        connection = connection or self.connection()
        payload = b"".join(struct.pack("!H", len(value)) + value for value in values) + bytes([reuse])
        connection.sendall(self.frame(1, payload))
        header = self.exact(connection, 12)
        self.assertEqual(header, self.frame(128, bytes(65))[:12])
        result = self.exact(connection, 65)
        self.assertEqual(result[0], 0)
        return connection, result[1:].decode()

    def test_atomic_claim_copy_terminal_attestation_and_single_use(self):
        connection, token = self.reserve()
        self.assertEqual(self.command("claim " + token), {
            "result": 1, "run": "run-1", "case": "case-1", "connection": "opaque-1", "reused": 0})
        self.assertEqual(self.command("claim " + token)["result"], 0)
        self.assertEqual(self.command("complete " + token + " 403 -"), {"result": 1})
        self.assertEqual(self.command("complete " + token + " 403 -"), {"result": 0})
        connection.sendall(self.frame(2))
        self.assertEqual(self.exact(connection, 12), self.frame(128, bytes(67))[:12])
        self.assertEqual(self.exact(connection, 67), b"\0" + struct.pack("!H", 403) + bytes(64))
        self.assertEqual(self.command("confirm-count"), {"confirmations": 0})

    def test_allow_handle_is_privately_attested_after_one_time_claim(self):
        connection, token = self.reserve()
        self.assertEqual(self.command("claim " + token)["result"], 1)
        handle = "a" * 64
        self.assertEqual(self.command("complete " + token + " 200 " + handle), {"result": 1})
        connection.sendall(self.frame(2))
        self.exact(connection, 12)
        self.assertEqual(self.exact(connection, 67), b"\0" + struct.pack("!H", 200) + handle.encode())
        self.assertEqual(self.command("confirm-count"), {"confirmations": 1})
        try:
            connection.sendall(self.frame(2))
            self.assertEqual(connection.recv(1), b"")
        except (ConnectionResetError, BrokenPipeError):
            pass
        self.assertEqual(self.command("confirm-count"), {"confirmations": 1})

    def test_partial_query_wait_does_not_block_an_independent_claim(self):
        blocked, blocked_token = self.reserve()
        _, neighbor_token = self.reserve()
        self.assertEqual(self.command("claim " + blocked_token)["result"], 1)
        self.assertEqual(self.command("complete " + blocked_token + " 403 -"), {"result": 1})
        self.assertEqual(self.command("arm-query"), {"armed": 1})
        query = self.frame(2)
        blocked.sendall(query[:1])
        # The test poll wrapper announces the actual partial-query wait. No
        # scheduling sleep or production instrumentation establishes ordering.
        self.assertEqual(self.read(), {"query_wait": 1})
        self.process.stdin.write("claim " + neighbor_token + "\n")
        self.process.stdin.flush()
        self.assertTrue(select.select([self.process.stdout], [], [], 0.5)[0],
                        "partial private query retained the reservation mutex")
        self.assertEqual(self.read()["result"], 1)
        blocked.sendall(query[1:])
        self.assertEqual(self.exact(blocked, 12), self.frame(128, bytes(67))[:12])
        self.assertEqual(self.exact(blocked, 67), b"\0" + struct.pack("!H", 403) + bytes(64))
    def test_forged_missing_duplicate_and_closed_bindings_fail(self):
        self.assertEqual(self.command("claim " + "a" * 64)["result"], 0)
        connection, token = self.reserve()
        self.assertEqual(self.command("duplicate " + token)["result"], 0)
        self.assertEqual(self.command("missing " + token)["result"], 0)
        connection.close()
        self.assertEqual(self.command("claim " + token)["result"], 0)

    def test_confirmation_callback_failure_closes_without_releasing_handle(self):
        connection, token = self.reserve()
        self.assertEqual(self.command("claim " + token)["result"], 1)
        self.assertEqual(self.command("complete " + token + " 200 " + "a" * 64), {"result": 1})
        self.assertEqual(self.command("reject-confirm"), {"reject": 1})
        connection.sendall(self.frame(2))
        self.assertEqual(connection.recv(1), b"")

    def test_expired_binding_fails(self):
        _, token = self.reserve()
        time.sleep(5.1)
        self.assertEqual(self.command("claim " + token)["result"], 0)

    def test_expiry_reaps_slots_without_a_spare_descriptor(self):
        self.reserve()
        self.reserve()
        self.assertEqual(self.command("exhaust"), {"exhausted": 1})
        descriptors = Path(f"/proc/{self.process.pid}/fd")
        before = len(list(descriptors.iterdir()))
        deadline = time.monotonic() + 7
        while len(list(descriptors.iterdir())) > before - 2 and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertLessEqual(len(list(descriptors.iterdir())), before - 2,
                             "expired registry descriptors were retained under EMFILE")
        # Freeing the expired originals permits a new real reservation even
        # while the unrelated filler descriptors remain open.
        self.reserve()

    def test_fixed_capacity_rejects_overflow_without_evicting_neighbor(self):
        reservations = [self.reserve() for _ in range(128)]
        with self.assertRaises((EOFError, ConnectionResetError)):
            self.reserve()
        self.assertEqual(self.command("claim " + reservations[0][1])["result"], 1)
        self.assertEqual(self.command("claim " + reservations[-1][1])["result"], 1)

    def test_foreign_uid_and_gid_are_rejected_even_if_test_path_is_opened(self):
        if os.geteuid() != 0:
            self.skipTest("root is required to exercise real foreign UID/GID peers")
        for ancestor in self.path.parents:
            if ancestor not in (self.path.parent, self.directory) and ancestor.stat().st_mode & 0o001 == 0:
                self.skipTest("configured test root is not searchable by a foreign UID; use a searchable external RUNNER_TEMP")
        # Deliberately open only task-owned fixture paths to isolate SO_PEERCRED
        # from normal private-directory/socket permission rejection.
        original_mode = self.directory.stat().st_mode & 0o777
        self.directory.chmod(0o711)
        self.path.parent.chmod(0o711)
        self.path.chmod(0o666)
        self.addCleanup(self.directory.chmod, original_mode)
        script = r'''
import errno, os, socket, sys
try:
    os.setgid(int(sys.argv[2]))
    os.setuid(int(sys.argv[3]))
except OSError as error:
    if error.errno in (errno.EINVAL, errno.EPERM):
        sys.exit(77)
    raise
s = socket.socket(socket.AF_UNIX)
s.settimeout(3)
s.connect(sys.argv[1])
try:
    s.sendall(b"MTP1\x01\x01\0\0\0\0\0\x0a\0\x01r\0\x01c\0\x01i\0")
    assert s.recv(1) == b""
except (ConnectionResetError, BrokenPipeError):
    pass
s.close()
'''
        for gid, uid in ((65534, 0), (0, 65534)):
            with self.subTest(gid=gid, uid=uid):
                result = subprocess.run([sys.executable, "-I", "-c", script,
                    str(self.path), str(gid), str(uid)], capture_output=True, text=True, timeout=5)
                if result.returncode == 77:
                    self.skipTest("foreign Unix IDs are unavailable in this user namespace")
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_malformed_version_length_reuse_and_duplicate_frames_fail_closed(self):
        malformed = [
            self.frame(1, b"", version=2), self.frame(1, b"x" * 392),
            self.frame(1, b"\0\0"),
            self.frame(1, b"\0\1r\0\1c\0\1i\1"),
            self.frame(1, b"\0\1r\0\1c\0\1i\0extra"),
        ]
        for frame in malformed:
            with self.subTest(frame=frame[:12]):
                connection = self.connection()
                connection.sendall(frame)
                try:
                    self.assertEqual(connection.recv(1), b"")
                except ConnectionResetError:
                    pass
                connection.close()
        connection, token = self.reserve()
        connection.sendall(b"extra")
        self.assertEqual(self.command("claim " + token)["result"], 0)

    def test_stop_removes_only_task_owned_socket(self):
        self.assertEqual(self.command("stop"), {"stopped": 1})
        self.process.wait(timeout=3)
        self.assertFalse(self.path.exists())



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
