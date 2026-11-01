"""Attempt-only C17 boundary fixtures; no NGINX runtime or product build."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = connector_root()
STORAGE = "/var/tmp/codex/ModSecurity-conector"
TX = "a" * 32
STUB = r'''
void *msc_new_transaction_with_id(void *engine, void *rules, char *id, void *opaque)
{ (void)engine; (void)rules; (void)id; (void)opaque; return (void *)0x1234; }
'''
HARNESS = r'''
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
void *msc_new_transaction_with_id(void *, void *, char *, void *);
static int probe(char *id, int inject, int worker)
{
    if (worker && (setgid(65534) != 0 || setuid(65534) != 0)) return 70;
    void *first = msc_new_transaction_with_id(0, 0, id, 0);
    void *second = msc_new_transaction_with_id(0, 0, id, 0);
    return second == 0 || (inject ? first != 0 : first == 0) ? 71 : 0;
}
int main(int argc, char **argv)
{
    if (argc != 5) return 72;
    pid_t child = fork();
    if (child < 0) return 73;
    if (child == 0) {
        if (atoi(argv[4])) {
            pid_t grandchild = fork();
            if (grandchild < 0) _exit(74);
            if (grandchild == 0) _exit(probe(argv[1], atoi(argv[2]), atoi(argv[3])));
            int status;
            if (waitpid(grandchild, &status, 0) < 0 || !WIFEXITED(status)) _exit(75);
            _exit(WEXITSTATUS(status));
        }
        _exit(probe(argv[1], atoi(argv[2]), atoi(argv[3])));
    }
    int status;
    if (waitpid(child, &status, 0) < 0 || !WIFEXITED(status)) return 76;
    return WEXITSTATUS(status);
}
'''


@unittest.skipUnless(os.geteuid() == 0 and shutil.which("cc"), "owned root/compiler fixture required")
class BeginLedgerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="begin-ledger-", dir=STORAGE)
        cls.root = Path(cls.directory.name)
        stub, harness = cls.root / "stub.c", cls.root / "harness.c"
        stub.write_text(STUB)
        harness.write_text(HARNESS)
        compiler = shutil.which("cc")
        options = [compiler, "-std=c17", "-Wall", "-Wextra", "-Werror"]
        subprocess.run(options + ["-fPIC", "-shared", str(stub), "-o", str(cls.root / "libstub.so")], check=True, timeout=30)
        subprocess.run(options + [str(harness), "-L" + str(cls.root), "-lstub",
                       "-Wl,-rpath," + str(cls.root), "-o", str(cls.root / "harness")], check=True, timeout=30)
        subprocess.run(options + ["-fPIC", "-shared", str(source_path('tests/fixtures/nginx_transaction_fault.c', root=ROOT)),
                       "-ldl", "-o", str(cls.root / "fault.so")], check=True, timeout=30)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def invoke(self, name, *, target=TX, fd=True, mode=0o600, content=b"", hardlink=False,
               worker=True, foreign_parent=False, descriptor_override=None, readonly=False, injected=False):
        leaf = self.root / (name + ".jsonl")
        leaf.write_bytes(content)
        leaf.chmod(mode)
        if hardlink:
            os.link(leaf, self.root / (name + ".link"))
        descriptor = os.open(leaf, os.O_RDONLY if readonly else os.O_WRONLY)
        environment = dict(os.environ, LD_PRELOAD=str(self.root / "fault.so"),
            MSCONNECTOR_OWNED_BEGIN_FAULT="one-native-allocation-failure", MSCONNECTOR_OWNED_BEGIN_TXID=target)
        environment.pop("MSCONNECTOR_OWNED_BEGIN_FD", None)
        if fd:
            environment["MSCONNECTOR_OWNED_BEGIN_FD"] = str(descriptor) if descriptor_override is None else descriptor_override
        try:
            process = subprocess.Popen([str(self.root / "harness"), TX, str(int(injected)), str(int(worker)), str(int(foreign_parent))],
                env=environment, pass_fds=(descriptor,) if fd else (), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 0, (stdout, stderr))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return leaf.read_bytes(), process.pid

    def test_actual_null_ledger_is_emitted_once_before_return(self):
        raw, master = self.invoke("positive", injected=True)
        rows = [json.loads(line) for line in raw.splitlines()]
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(set(row), {"native_operation", "observed_return", "worker_pid", "worker_uid",
                                   "master_pid", "transaction_id", "injected"})
        self.assertEqual(row["native_operation"], "msc_new_transaction_with_id")
        self.assertIsNone(row["observed_return"])
        self.assertIs(row["injected"], True)
        self.assertEqual(row["transaction_id"], TX)
        self.assertEqual(row["worker_uid"], 65534)
        self.assertEqual(row["master_pid"], master)
        self.assertGreater(row["worker_pid"], 0)
        self.assertNotEqual(row["worker_pid"], master)

    def test_wrong_transaction_or_missing_fd_does_not_inject(self):
        for name, kwargs in (("wrong-tx", {"target": "b" * 32}), ("no-fd", {"fd": False})):
            with self.subTest(name=name):
                raw, _ = self.invoke(name, **kwargs)
                self.assertEqual(raw, b"")

    def test_private_fd_and_own_child_guards_remain_closed(self):
        cases = (("world-readable", {"mode": 0o644}), ("hardlink", {"hardlink": True}),
                 ("nonempty", {"content": b"retained\n"}), ("readonly", {"readonly": True}),
                 ("empty-fd", {"descriptor_override": ""}), ("small-fd", {"descriptor_override": "2"}),
                 ("negative-fd", {"descriptor_override": "-1"}), ("bad-fd", {"descriptor_override": "3x"}),
                 ("root-child", {"worker": False}), ("foreign-parent", {"foreign_parent": True}))
        for name, kwargs in cases:
            with self.subTest(name=name):
                raw, _ = self.invoke(name, **kwargs)
                self.assertEqual(raw, kwargs.get("content", b""))



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
