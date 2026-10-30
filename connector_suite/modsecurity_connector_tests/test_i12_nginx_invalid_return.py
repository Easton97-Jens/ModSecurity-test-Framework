"""Compile I12 P2 fixture and check fail-closed process/FD/transaction scopes.

The in-translation-unit identity/SDK seams below are compile-time test seams.
They do not add runtime guard overrides to the preload fixture or prove hosts.
"""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = connector_root()
SOURCE = source_path('ci/runtime/lifecycle/i12/nginx/invalid_return.c', root=ROOT)
HARNESS = r'''
#define _GNU_SOURCE
#include <sys/types.h>
static uid_t fixture_uid;
static pid_t fixture_pid = 4000, fixture_parent = 3999;
#define getuid fixture_getuid
#define geteuid fixture_geteuid
#define getpid fixture_getpid
#define getppid fixture_getppid
#define dlsym fixture_dlsym
#define syscall fixture_syscall
#include "FIXTURE_SOURCE"
#undef getuid
#undef geteuid
#undef getpid
#undef getppid
#undef dlsym
#undef syscall
#include <stdarg.h>
static int native, other, new_calls, process_calls, cleanup_calls, failed_new, short_write;
uid_t fixture_getuid(void) { return fixture_uid; }
uid_t fixture_geteuid(void) { return fixture_uid; }
pid_t fixture_getpid(void) { return fixture_pid; }
pid_t fixture_getppid(void) { return fixture_parent; }
static void *real_new(void *engine, void *rules, char *id, void *opaque) {
    (void)engine; (void)rules; (void)id; (void)opaque; ++new_calls;
    errno = EAGAIN; return failed_new ? NULL : &native;
}
static int real_process(void *transaction) {
    (void)transaction; ++process_calls; errno = ENOSPC; return 1;
}
static void real_cleanup(void *transaction) {
    (void)transaction; ++cleanup_calls; errno = EBUSY;
}
void *fixture_dlsym(void *handle, const char *name) {
    (void)handle; errno = EDOM;
    if (strcmp(name,"msc_new_transaction_with_id") == 0) return (void *)real_new;
    if (strcmp(name,"msc_process_request_body") == 0) return (void *)real_process;
    if (strcmp(name,"msc_transaction_cleanup") == 0) return (void *)real_cleanup;
    return NULL;
}
long fixture_syscall(long number, ...) {
    va_list args;
    int fd;
    const char *line;
    size_t size;
    if (number != SYS_write) abort();
    va_start(args,number); fd=va_arg(args,int); line=va_arg(args,const char *);
    size=va_arg(args,size_t); va_end(args);
    return short_write ? 0 : write(fd,line,size);
}
int main(int argc, char **argv) {
    char id[]="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    void *transaction;
    int first, second, new_errno, process_errno;
    if (argc != 2) return 2;
    fixture_uid=65534; fixture_pid=4001; fixture_parent=4000;
    if (strcmp(argv[1],"wrongtx") == 0) id[0]='b';
    if (strcmp(argv[1],"foreign-parent") == 0) fixture_parent=4999;
    if (strcmp(argv[1],"wrong-worker") == 0) fixture_uid=1000;
    if (strcmp(argv[1],"master") == 0) fixture_uid=0;
    if (strcmp(argv[1],"failed-new") == 0) failed_new=1;
    if (strcmp(argv[1],"short-write") == 0) short_write=1;
    transaction=msc_new_transaction_with_id(NULL,NULL,id,NULL);
    new_errno=errno;
    if (strcmp(argv[1],"cleaned-pointer") == 0) msc_transaction_cleanup(transaction);
    if (strcmp(argv[1],"wrong-pointer") == 0) transaction=&other;
    first=msc_process_request_body(transaction); process_errno=errno;
    second=msc_process_request_body(transaction);
    printf("{\"first\":%d,\"second\":%d,\"new_calls\":%d,\"process_calls\":%d,"
        "\"cleanup_calls\":%d,\"new_errno\":%d,\"process_errno\":%d}\n",
        first,second,new_calls,process_calls,cleanup_calls,new_errno,process_errno);
    return 0;
}
'''


class I12NginxInvalidReturnTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid() != 0:
            raise unittest.SkipTest("private root-owned descriptor controls require root")
        compiler = shutil.which(os.environ.get("CC", "cc"))
        if compiler is None:
            raise RuntimeError("C17 compiler required")
        cls.temporary = tempfile.TemporaryDirectory(
            prefix="i12-nginx-invalid-", dir=os.environ.get("RUNNER_TEMP", "/var/tmp/codex/ModSecurity-conector")
        )
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        harness = cls.directory / "harness.c"
        harness.write_text(HARNESS.replace("FIXTURE_SOURCE", str(SOURCE)))
        cls.binary = cls.directory / "guard-controls"
        for argv in (
            [compiler, "-std=c17", "-Wall", "-Wextra", "-Werror", "-fPIC", "-shared", str(SOURCE), "-ldl", "-o", str(cls.directory / "invalid-return.so")],
            [compiler, "-std=c17", "-Wall", "-Wextra", "-Werror", str(harness), "-o", str(cls.binary)],
        ):
            result = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=60)
            if result.returncode:
                raise AssertionError(result.stderr)

    def probe(self, mode="valid", *, armed=True, append=True, filled=False, permissions=0o600, txid="a" * 32):
        with tempfile.TemporaryDirectory(dir=self.directory) as raw:
            path = Path(raw) / "private.jsonl"
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | (os.O_APPEND if append else 0), 0o600)
            try:
                os.fchmod(fd, permissions)
                if filled:
                    os.write(fd, b"existing\n")
                environment = {key: value for key, value in os.environ.items() if key not in ("MSCONNECTOR_I12_INVALID_TXID", "MSCONNECTOR_I12_INVALID_FD")}
                if armed:
                    environment.update(MSCONNECTOR_I12_INVALID_TXID=txid, MSCONNECTOR_I12_INVALID_FD=str(fd))
                result = subprocess.run([str(self.binary), mode], env=environment, pass_fds=(fd,), capture_output=True, text=True, check=False, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                return json.loads(result.stdout), path.read_text()
            finally:
                os.close(fd)

    def test_actual_sdk_runs_before_one_shot_p2_override_and_errno_survives(self):
        result, raw = self.probe()
        self.assertEqual((result["first"], result["second"]), (-9, 1))
        self.assertEqual((result["new_calls"], result["process_calls"]), (1, 2))
        import errno
        self.assertEqual(result["new_errno"], errno.EAGAIN)
        self.assertEqual(result["process_errno"], errno.ENOSPC)
        lines = raw.splitlines()
        self.assertEqual(len(lines), 1)
        event = json.loads(lines[0])
        self.assertEqual((event["phase"], event["original_result"], event["injected_result"]), (2, 1, -9))
        self.assertEqual((event["worker_uid"], event["worker_pid"], event["master_pid"]), (65534, 4001, 4000))
        self.assertEqual(event["transaction_id"], "a" * 32)

    def test_wrong_transaction_process_pointer_and_unarmed_controls_stay_native(self):
        for mode in ("wrongtx", "foreign-parent", "wrong-worker", "master", "failed-new", "wrong-pointer", "cleaned-pointer", "short-write"):
            with self.subTest(mode=mode):
                result, raw = self.probe(mode)
                self.assertEqual((result["first"], result["second"]), (1, 1))
                self.assertEqual(result["process_calls"], 2)
                self.assertEqual(raw, "")
        result, raw = self.probe(armed=False)
        self.assertEqual((result["first"], result["second"], raw), (1, 1, ""))

    def test_descriptor_and_id_contracts_fail_closed(self):
        for options in ({"append": False}, {"filled": True}, {"permissions": 0o640}, {"txid": "g" * 32}, {"txid": "a" * 31}):
            with self.subTest(options=options):
                result, raw = self.probe(**options)
                self.assertEqual((result["first"], result["second"]), (1, 1))
                self.assertEqual(raw, "existing\n" if options.get("filled") else "")



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
