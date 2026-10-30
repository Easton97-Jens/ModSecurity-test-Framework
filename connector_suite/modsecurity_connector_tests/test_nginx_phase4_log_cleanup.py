"""Compile the real cycle cleanup; close errors have no request/native result."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

from modsecurity_connector_tests.c_source_contract import function_definition


ROOT = connector_root()
MODULE = source_path('connectors/nginx/src/ngx_http_modsecurity_module.c', root=ROOT)
FUNCTION = "ngx_http_modsecurity_cleanup_phase4_log"
PREAMBLE = r'''
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
typedef int ngx_fd_t;
typedef struct { ngx_fd_t fd; } ngx_open_file_t;
#define NGX_INVALID_FILE (-1)
static ngx_open_file_t *owner;
static int close_calls, invalid_before_close, closed_fd = -1;
static int fail_close, recycled_fd_open, recycled_fd_closes;
static int ngx_close_file(ngx_fd_t fd)
{
    ++close_calls;
    closed_fd = fd;
    invalid_before_close = owner != NULL && owner->fd == NGX_INVALID_FILE;
    if (recycled_fd_open) ++recycled_fd_closes;
    /* A close failure need not mean this descriptor remains owned. Model an
     * immediate reuse of its number, including after an EIO close result. */
    recycled_fd_open = 1;
    if (fail_close) { errno = EIO; return -1; }
    return 0;
}
'''
MAIN = r'''
int main(int argc, char **argv)
{
    if (argc != 3) return 2;
    int mode = atoi(argv[1]);
    fail_close = atoi(argv[2]);
    ngx_open_file_t file = { mode == 1 ? NGX_INVALID_FILE : 47 };
    owner = mode == 0 ? NULL : &file;
    /* This assignment is checked with -Werror: cleanup returns void and has
     * only a cycle resource argument, not an HTTP or native transaction. */
    void (*cleanup)(void *) = ngx_http_modsecurity_cleanup_phase4_log;
    cleanup(owner);
    int first_errno = errno;
    int calls_after_first = close_calls;
    cleanup(owner);
    cleanup(owner);
    printf("{\"calls\":%d,\"calls_after_first\":%d,\"fd\":%d,"
           "\"closed_fd\":%d,\"invalid_before_close\":%d,"
           "\"recycled_fd_open\":%d,\"recycled_fd_closes\":%d,"
           "\"first_errno\":%d,\"eio\":%d}\n",
           close_calls, calls_after_first, file.fd, closed_fd,
           invalid_before_close, recycled_fd_open, recycled_fd_closes,
           first_errno, EIO);
    return 0;
}
'''


class NginxPhase4LogCleanupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.definition = function_definition(MODULE.read_text(), FUNCTION)
        cls.temporary = tempfile.TemporaryDirectory(
            prefix="nginx-phase4-log-cleanup-", dir=os.environ.get("RUNNER_TEMP")
        )
        cls.addClassCleanup(cls.temporary.cleanup)
        directory = Path(cls.temporary.name)
        fixture = directory / "cleanup.c"
        # The shared extractor starts at the function-name line, immediately
        # after the real static void return declaration.
        fixture.write_text(PREAMBLE + "\nstatic void\n" + cls.definition + MAIN)
        cls.binary = directory / "cleanup"
        compiled = subprocess.run(
            shlex.split(os.environ.get("CC", "cc"))
            + ["-std=c17", "-Wall", "-Wextra", "-Werror", str(fixture),
               "-o", str(cls.binary)],
            capture_output=True, text=True, check=False, timeout=30,
        )
        if compiled.returncode:
            raise AssertionError(compiled.stderr)

    def probe(self, mode, fail_close=False):
        result = subprocess.run(
            [str(self.binary), str(mode), str(int(fail_close))],
            capture_output=True, text=True, check=True, timeout=5,
        )
        return json.loads(result.stdout)

    def test_null_and_invalid_resource_never_close(self):
        for mode in (0, 1):
            with self.subTest(mode=mode):
                observed = self.probe(mode)
                self.assertEqual(observed["calls"], 0)
                self.assertEqual(observed["closed_fd"], -1)
                self.assertEqual(observed["recycled_fd_open"], 0)

    def assert_single_invalidating_close(self, observed):
        self.assertEqual(observed["calls_after_first"], 1)
        self.assertEqual(observed["calls"], 1)
        self.assertEqual(observed["closed_fd"], 47)
        self.assertEqual(observed["invalid_before_close"], 1)
        self.assertEqual(observed["fd"], -1)
        self.assertEqual(observed["recycled_fd_open"], 1)
        self.assertEqual(observed["recycled_fd_closes"], 0)

    def test_success_invalidates_owner_before_exactly_one_close(self):
        self.assert_single_invalidating_close(self.probe(2))

    def test_eio_does_not_retry_or_close_recycled_descriptor(self):
        observed = self.probe(2, fail_close=True)
        self.assert_single_invalidating_close(observed)
        self.assertEqual(observed["first_errno"], observed["eio"])

    def test_void_cycle_cleanup_ignores_close_result_without_http_native_propagation(self):
        source = MODULE.read_text()
        self.assertIn("static void\n" + FUNCTION + "(void *data)", source)
        self.assertIn("(void)ngx_close_file(fd);", self.definition)
        # Compilation has no HTTP request/native transaction types or APIs.
        # Both close outcomes finish normally with the same invalidated state;
        # this is a cleanup contract, not an HTTP/native error-propagation PASS.
        success = self.probe(2)
        failure = self.probe(2, fail_close=True)
        for key in ("calls", "calls_after_first", "fd", "closed_fd",
                    "invalid_before_close", "recycled_fd_open", "recycled_fd_closes"):
            self.assertEqual(success[key], failure[key], key)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
