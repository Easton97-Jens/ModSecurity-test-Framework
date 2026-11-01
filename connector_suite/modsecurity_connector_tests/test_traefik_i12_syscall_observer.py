"""Actual own-child Linux syscall controls; no Traefik host is started.

Run as a non-root UID with all capability sets empty and NoNewPrivs=1.
I12_SYSCALL_TEST_ROOT must name a fresh private directory owned by that UID.
The synthetic child is the observer's own fixed executable, never a supplied
command. These controls establish capture integrity, not I12 qualification.
"""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
import json
import os
from pathlib import Path
import signal
import subprocess
import time
import unittest


class SyscallObserverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        directory = os.environ.get("I12_SYSCALL_TEST_ROOT")
        if not directory or os.getuid() == 0:
            raise unittest.SkipTest("requires explicit private non-root capability-free test root")
        cls.root = Path(directory)
        info = cls.root.stat()
        assert info.st_uid == os.getuid()
        assert info.st_mode & 0o077 == 0
        cls.binary = cls.root / "observer"
        source = connector_root() / "connectors/traefik/harness/i12/native/acceptance_syscalls.c"
        subprocess.run(["gcc", "-std=c17", "-Wall", "-Wextra", "-Werror",
                        "-O2", "-pthread", str(source), "-o", str(cls.binary)], check=True)
        cls.binary.chmod(0o500)

    def output(self, name):
        return self.root / (self._testMethodName + "-" + name)

    def command(self, output, *extra):
        return [str(self.binary), "--self-test", "--output", str(output),
                "--nonce", "i12-own-loopback-controls", "--seconds", "15", *extra]

    def refused(self, output, *extra):
        result = subprocess.run(self.command(output, *extra), capture_output=True, timeout=20)
        self.assertEqual(77, result.returncode, result.stderr)
        self.assertFalse(Path(output).exists())

    def test_actual_kernel_short_block_resume_on_writer_thread(self):
        output = self.output("kernel.jsonl")
        result = subprocess.run(self.command(output), capture_output=True, timeout=20)
        self.assertEqual(0, result.returncode, result.stderr)
        records = [json.loads(row) for row in output.read_text().splitlines()]
        final = records[-1]
        writes = [row for row in records if row["schema"] == "traefik-own-child-syscall-v1"]
        executed = [row for row in records if row["schema"] == "traefik-own-child-exec-v1"]
        self.assertEqual(1, len(executed))
        self.assertEqual(final["child_pid"], executed[0]["child_pid"])
        self.assertEqual(str(self.binary), executed[0]["image"])
        self.assertTrue(executed[0]["opened_image_identity_verified"])
        self.assertEqual("synthetic-native", executed[0]["mode"])
        self.assertTrue(final["capture_complete"])
        self.assertFalse(final["runtime_qualified"])
        self.assertTrue(final["client_receipt_join_required"])
        self.assertEqual(len(writes), final["kernel_records"])
        self.assertGreater(final["short_writes"], 0)
        self.assertGreater(final["would_block"], 0)
        self.assertGreater(final["resumed_same_inode"], 0)
        self.assertFalse(Path(f'/proc/{final["child_pid"]}').exists())
        self.assertTrue(all(row["tid"] != row["pid"] for row in writes), "writer must be a traced clone thread")
        blocked = set()
        resumed = False
        for row in writes:
            self.assertEqual("i12-own-loopback-controls", row["nonce"])
            self.assertEqual(final["known_target_peer_port"], row["peer_port"])
            self.assertEqual("127.0.0.1", row["local_address"])
            self.assertNotIn("payload", row)
            if row["kernel_result"] == -11:
                blocked.add(row["socket_inode"])
            elif row["kernel_result"] > 0 and row["socket_inode"] in blocked:
                resumed = True
        self.assertTrue(resumed)
        # Each transport API separately proves genuine short/block/resume.
        for operation in ("write", "writev"):
            selected = [row for row in writes if row["operation"] == operation and row["requested_size_known"]]
            self.assertTrue(any(0 < row["kernel_result"] < row["requested_bytes"] for row in selected), operation)
            blocked_inodes = set()
            continued = False
            for row in selected:
                if row["kernel_result"] == -11:
                    blocked_inodes.add(row["socket_inode"])
                if row["kernel_result"] > 0 and row["socket_inode"] in blocked_inodes:
                    continued = True
            self.assertTrue(continued, operation)
        unknown = [row for row in writes if not row["requested_size_known"]]
        self.assertEqual(10, len(unknown), "all fixed invalid/unsupported metadata controls must stay unknown")
        self.assertTrue(all(row["operation"] == "writev" and row["requested_bytes"] == -1 for row in unknown))
        self.assertTrue(all(row["kernel_result"] <= 0 for row in unknown))
        self.assertEqual([-14] * 5 + [-22, 0, 0], [row["kernel_result"] for row in unknown[:8]])
        self.assertTrue(any(row["operation"] == "writev" and row["requested_size_known"] and
                            row["requested_bytes"] == 0 and row["kernel_result"] == 0 for row in writes))
        self.assertEqual(sum(0 < row["kernel_result"] < row["requested_bytes"] for row in writes
                             if row["requested_size_known"]), final["short_writes"])

    def test_arbitrary_process_command_and_environment_options_refused(self):
        for index, extra in enumerate((("--pid", "1"), ("--exec", "/bin/true"),
                                       ("--env", "LD_PRELOAD=x"), ("--seconds", "2"),
                                       ("--peer-port", "0", "--peer-port", "0"))):
            with self.subTest(extra=extra):
                self.refused(self.output(str(index)), *extra)

    def test_invalid_nonce_and_bounds_refused(self):
        for index, extra in enumerate((("--nonce", "bad\"nonce"), ("--host-port", "65536"),
                                       ("--peer-port", "-1"), ("--self-test",))):
            with self.subTest(extra=extra):
                self.refused(self.output(str(index)), *extra)

    def test_auth_case_selection_requires_exact_literals_and_nonce(self):
        for index, case in enumerate(("arbitrary", "../runtime", "ac-ef73876b3c669e899482-syscall",
                                      "ac-9528a3f086fca6429a67-syscall")):
            with self.subTest(case=case):
                self.refused(self.output(str(index)), "--auth-case", case)

    def test_each_fixed_auth_selection_uses_only_own_synthetic_child(self):
        for index, case in enumerate(("ac-ef73876b3c669e899482-syscall", "ac-9528a3f086fca6429a67-syscall")):
            with self.subTest(case=case):
                output = self.output(str(index))
                command = self.command(output)
                command[command.index("--nonce") + 1] = case
                result = subprocess.run([*command, "--auth-case", case], capture_output=True, timeout=20)
                self.assertEqual(0, result.returncode, result.stderr)
                rows = [json.loads(row) for row in output.read_text().splitlines()]
                executed = rows[0]
                self.assertEqual("traefik-own-child-exec-v1", executed["schema"])
                self.assertEqual("synthetic-auth", executed["mode"])
                self.assertEqual(str(self.binary), executed["image"])
                self.assertTrue(executed["opened_image_identity_verified"])
                self.assertEqual(case, executed["nonce"])
                self.assertTrue(rows[-1]["capture_complete"])
                self.assertFalse(rows[-1]["runtime_qualified"])
                self.assertFalse(Path(f'/proc/{executed["child_pid"]}').exists())

    def test_existing_file_and_symlink_preserved(self):
        existing = self.output("existing")
        existing.write_text("preserve")
        result = subprocess.run(self.command(existing), capture_output=True, timeout=20)
        self.assertEqual(77, result.returncode)
        self.assertEqual("preserve", existing.read_text())
        link = self.output("link")
        link.symlink_to(existing)
        result = subprocess.run(self.command(link), capture_output=True, timeout=20)
        self.assertEqual(77, result.returncode)
        self.assertEqual("preserve", existing.read_text())

    def test_shared_parent_and_symlink_ancestor_refused(self):
        shared = self.output("shared")
        shared.mkdir(mode=0o755)
        self.refused(shared / "capture")
        link = self.output("linked-parent")
        link.symlink_to(self.root, target_is_directory=True)
        self.refused(link / "capture")

    def test_world_writable_parent_and_dot_components_refused(self):
        shared = self.output("world-writable")
        shared.mkdir(mode=0o777)
        shared.chmod(0o777)
        self.refused(shared / "capture")
        self.refused(str(self.root) + "/./dot-capture")
        self.refused(str(self.root) + "/../parent-capture")
        self.refused(str(self.root) + "//empty-component")

    def test_interruption_never_qualifies_and_reaps_own_child(self):
        output = self.output("interrupted.jsonl")
        process = subprocess.Popen(self.command(output), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 5
            while not output.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.001)
            self.assertTrue(output.exists())
            # Signal only the exact directly spawned observer process.
            process.send_signal(signal.SIGTERM)
            process.communicate(timeout=10)
            self.assertEqual(77, process.returncode)
            final = json.loads(output.read_text().splitlines()[-1])
            self.assertFalse(final["capture_complete"])
            self.assertFalse(final["runtime_qualified"])
            self.assertFalse(Path(f'/proc/{final["child_pid"]}').exists())
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
