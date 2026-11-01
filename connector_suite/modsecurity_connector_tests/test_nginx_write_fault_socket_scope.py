"""Controlled syscall/process outputs exercise the actual fixture socket guard.

These controls never start NGINX and are not native runtime evidence.
"""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = connector_root()
CONTROL = r'''
#define _GNU_SOURCE
#include <stdint.h>
#define getuid controlled_getuid
#define getppid controlled_getppid
#define getsockname controlled_getsockname
#define getpeername controlled_getpeername
#include "nginx_write_fault.c"
#undef getuid
#undef getppid
#undef getsockname
#undef getpeername
static int scenario;
uid_t controlled_getuid(void) { return scenario == 1 ? 0 : 65534; }
pid_t controlled_getppid(void) { return scenario == 2 ? 999 : 123; }
static int address(struct sockaddr *output, socklen_t *length, int peer)
{
    struct sockaddr_in *value = (struct sockaddr_in *)output;
    if (scenario == (peer ? 9 : 3)) return -1;
    if (scenario == (peer ? 14 : 13)) return 0;
    value->sin_family = scenario == (peer ? 11 : 5) ? AF_UNIX : AF_INET;
    if (scenario == (peer ? 16 : 15)) return 0;
    value->sin_addr.s_addr = htonl(scenario == (peer ? 12 : 6)
        ? UINT32_C(0x7f000002) : INADDR_LOOPBACK);
    value->sin_port = htons(peer ? 45001 : scenario == 7 ? 32124 : 32123);
    *length = scenario == (peer ? 10 : 4) ? 1 : sizeof(*value);
    return 0;
}
int controlled_getsockname(int fd, struct sockaddr *output, socklen_t *length)
{ (void)fd; return address(output, length, 0); }
int controlled_getpeername(int fd, struct sockaddr *output, socklen_t *length)
{ (void)fd; return address(output, length, 1); }
int main(int argc, char **argv)
{
    int peer_port = -1;
    if (argc != 2) return 2;
    scenario = atoi(argv[1]);
    master = scenario == 8 ? 0 : 123;
    target_port = 32123;
    int result = owned_socket(17, &peer_port);
    printf("%d %d\n", result, peer_port);
    return 0;
}
'''


class WriteFaultSocketScopeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix="write-fault-scope-", dir=os.environ.get("RUNNER_TEMP"))
        cls.addClassCleanup(temporary.cleanup)
        cls.binary = Path(temporary.name) / "probe"
        source = Path(temporary.name) / "probe.c"
        source.write_text(CONTROL, encoding="utf-8")
        result = subprocess.run(["/usr/bin/cc", "-std=c17", "-Wall", "-Wextra", "-Werror",
            "-I", str(source_path('tests/fixtures', root=ROOT)), str(source),
            "-ldl", "-o", str(cls.binary)], capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise AssertionError(result.stderr)

    def probe(self, scenario):
        environment = dict(os.environ)
        for name in tuple(environment):
            if name.startswith("MSCONNECTOR_OWNED_WRITE_"):
                environment.pop(name)
        result = subprocess.run([str(self.binary), str(scenario)], env=environment,
            capture_output=True, text=True, check=True, timeout=5)
        return result.stdout.strip()

    def test_exact_owned_worker_loopback_and_port_accept_actual_peer(self):
        self.assertEqual(self.probe(0), "1 45001")

    def test_syscall_length_family_address_port_and_role_fail_closed(self):
        for scenario in range(1, 17):
            with self.subTest(scenario=scenario):
                self.assertEqual(self.probe(scenario), "0 -1")

# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)
