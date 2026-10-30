"""Real APR controls for the Apache-only physical sink interposer.

RUNNER_TEMP selects external task storage. I12_APACHE_SINK_EVIDENCE_DIR retains
the loadable library, driver, command receipts and actual native observations.
These controls do not constitute a running Apache lifecycle test.
"""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import errno
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest

ROOT = connector_root()
SOURCE = source_path('ci/runtime/lifecycle/apache-i12/apr_sink_fault.c', root=ROOT)
DRIVER = r'''
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <apr_file_io.h>
#include <apr_general.h>
#include <apr_portable.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(int argc, char **argv) {
    apr_pool_t *pool = NULL;
    if (argc != 4 || apr_initialize() != APR_SUCCESS) return 2;
    if (apr_pool_create(&pool, NULL) != APR_SUCCESS) return 3;
    for (int i = 0; i < atoi(argv[3]); ++i) {
        apr_file_t *file = NULL;
        apr_status_t opened;
        apr_status_t result = -1, flushed = -1, closed = -1;
        apr_size_t written = 0;
        if (atoi(argv[2])) {
            apr_os_file_t fd = open(argv[1], O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
            if (fd < 0) return 4;
            opened = apr_os_file_put(&file, &fd, APR_WRITE | APR_APPEND, pool);
        } else {
            opened = apr_file_open(&file, argv[1], APR_WRITE | APR_CREATE | APR_APPEND,
                APR_FPROT_UREAD | APR_FPROT_UWRITE, pool);
        }
        if (opened == APR_SUCCESS) {
            result = apr_file_write_full(file, "{\"event\":\"control\"}\n", 20, &written);
            flushed = apr_file_flush(file);
            closed = apr_file_close(file);
        }
        printf("{\"index\":%d,\"open\":%d,\"write\":%d,\"bytes\":%zu,"
            "\"flush\":%d,\"close\":%d}\n", i, opened, result, (size_t)written, flushed, closed);
    }
    apr_pool_destroy(pool);
    apr_terminate();
    return 0;
}
'''


class ApacheI12SinkFaultTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shlex.split(os.environ.get("CC", "cc"))
        apr = shutil.which("apr-1-config")
        if not compiler or not shutil.which(compiler[0]) or not apr:
            raise unittest.SkipTest("native C compiler and APR SDK required")
        if not os.environ.get("RUNNER_TEMP"):
            raise unittest.SkipTest("RUNNER_TEMP must select external task storage")
        cls.temporary = tempfile.TemporaryDirectory(prefix="apache-i12-sink-",
                                                     dir=os.environ["RUNNER_TEMP"])
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        cls.library = cls.directory / "apr-sink-fault.so"
        cls.driver = cls.directory / "apr-sink-control"
        driver_source = cls.directory / "control.c"
        driver_source.write_text(DRIVER)
        cls.evidence = None
        if os.environ.get("I12_APACHE_SINK_EVIDENCE_DIR"):
            cls.evidence = Path(os.environ["I12_APACHE_SINK_EVIDENCE_DIR"])
            cls.evidence.mkdir(parents=True, exist_ok=True)

        def flags(*arguments):
            return shlex.split(subprocess.run([apr, *arguments], check=True,
                capture_output=True, text=True, timeout=10).stdout)

        common = [*compiler, "-std=c17", "-Wall", "-Wextra", "-Werror",
                  *flags("--includes", "--cppflags", "--cflags")]
        commands = [common + ["-shared", "-fPIC", "-pthread", str(SOURCE), "-ldl",
                             "-o", str(cls.library)],
                    common + [str(driver_source), *flags("--link-ld", "--libs"),
                              "-o", str(cls.driver)]]
        receipts = []
        for command in commands:
            completed = subprocess.run(command, capture_output=True, text=True, timeout=60)
            receipts.append({"command": command, "exit": completed.returncode,
                             "stdout": completed.stdout, "stderr": completed.stderr})
            if completed.returncode:
                raise AssertionError(completed.stderr)
        if cls.evidence:
            for file in (cls.library, cls.driver, driver_source):
                shutil.copy2(file, cls.evidence / file.name)
            (cls.evidence / "build.json").write_text(json.dumps({
                "commands": receipts,
                "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
                "library_sha256": hashlib.sha256(cls.library.read_bytes()).hexdigest(),
                "control_source_sha256": hashlib.sha256(driver_source.read_bytes()).hexdigest(),
                "driver_sha256": hashlib.sha256(cls.driver.read_bytes()).hexdigest(),
            }, indent=2) + "\n")

    def control(self, mode="observe", *, marker=True, mismatch=False, permissions=0o600,
                adopt=True, missing_parent=False, device=False):
        with tempfile.TemporaryDirectory(dir=self.directory) as temporary:
            directory = Path(temporary)
            target = Path("/dev/full") if device else directory / "events.jsonl"
            if missing_parent:
                target = directory / "missing" / "events.jsonl"
            elif not device:
                target.touch(mode=permissions)
                target.chmod(permissions)
            marker_path = directory / "marker"
            if marker:
                marker_path.write_text("I12_APACHE_SINK_FAULT_V1\n")
                marker_path.chmod(0o600)
            environment = os.environ.copy()
            environment.update(LD_PRELOAD=str(self.library), I12_SINK_FAULT=mode, I12_SINK_ROOT=str(self.directory),
                I12_SINK_PATH=str(directory / "other.jsonl" if mismatch else target),
                I12_SINK_MARKER=str(marker_path))
            command = [str(self.driver), str(target), str(int(adopt)), "2"]
            completed = subprocess.run(command, env=environment, capture_output=True,
                                       text=True, timeout=10)
            observations = [json.loads(line.removeprefix("I12_APACHE_APR "))
                for line in completed.stderr.splitlines() if line.startswith("I12_APACHE_APR ")]
            facts = [json.loads(line) for line in completed.stdout.splitlines()]
            record = {"command": command, "mode": mode, "marker": marker,
                "mismatch": mismatch, "permissions": permissions, "adopt": adopt,
                "exit": completed.returncode, "stdout": completed.stdout,
                "stderr": completed.stderr, "observations": observations,
                "physical_bytes": None if device or not target.is_file() else target.stat().st_size,
                "host_execution": None, "client_execution": None}
            if self.evidence:
                key = self.id().rsplit(".", 1)[-1] + ("-adopt" if adopt else "-open")
                (self.evidence / (key + ".json")).write_text(json.dumps(record, indent=2) + "\n")
            self.assertEqual(completed.returncode, 0, completed.stderr)
            return facts, observations, record

    def test_observe_forwards_success_and_cleanup_without_fault(self):
        for adopt in (False, True):
            facts, observations, record = self.control(adopt=adopt)
            self.assertTrue(all(row["write"] == 0 and row["bytes"] == 20 for row in facts))
            self.assertEqual(record["physical_bytes"], 40)
            self.assertTrue(all(row["action"] == "none" for row in observations))
            closes = [row for row in observations if row["stage"] == "apr_file_close"]
            self.assertEqual(len(closes), 2)
            self.assertTrue(all(row["fd_valid_after"] == 0 for row in closes))

    def assert_fault(self, mode, expected):
        facts, observations, record = self.control(mode)
        writes = [row for row in observations if row["stage"] == "apr_file_write_full"]
        self.assertEqual(facts[0]["write"], expected)
        self.assertEqual(facts[0]["bytes"], 0)
        self.assertEqual(writes[0]["result"], facts[0]["write"])
        self.assertEqual(writes[0]["written_bytes"], facts[0]["bytes"])
        self.assertEqual(writes[0]["action"], mode)
        self.assertGreaterEqual(writes[0]["operation_result"], 0)
        self.assertEqual(writes[0]["operation_errno"], 0)
        self.assertEqual(writes[0]["fd_valid_before"], 1)
        self.assertEqual(facts[1]["write"], 0)
        self.assertEqual(facts[1]["bytes"], 20)
        self.assertEqual(record["physical_bytes"], 20)
        self.assertEqual(writes[1]["action"], "none")
        return facts, writes

    def test_closed_descriptor_real_ebadf_and_next_open_recovers(self):
        facts, writes = self.assert_fault("closed-descriptor", errno.EBADF)
        self.assertEqual(writes[0]["fd_valid_after"], 0)
        self.assertEqual(facts[0]["close"], errno.EBADF)

    def test_dev_full_rebinding_real_enospc_and_next_open_recovers(self):
        _, writes = self.assert_fault("physical-enospc", errno.ENOSPC)
        self.assertEqual(writes[0]["fd_valid_after"], 1)

    def test_missing_marker_does_not_inject_or_observe(self):
        facts, observations, _ = self.control("closed-descriptor", marker=False)
        self.assertEqual(observations, [])
        self.assertTrue(all(row["write"] == 0 for row in facts))

    def test_mismatched_target_does_not_inject_or_observe(self):
        facts, observations, _ = self.control("closed-descriptor", mismatch=True)
        self.assertEqual(observations, [])
        self.assertTrue(all(row["write"] == 0 for row in facts))

    def test_nonprivate_file_is_observed_but_not_faulted(self):
        facts, observations, _ = self.control("physical-enospc", permissions=0o644)
        self.assertTrue(all(row["write"] == 0 for row in facts))
        self.assertTrue(observations)
        self.assertTrue(all(row["action"] == "none" for row in observations))

    def test_real_apr_open_error_is_forwarded(self):
        facts, observations, _ = self.control(adopt=False, missing_parent=True)
        self.assertTrue(all(row["open"] == errno.ENOENT for row in facts))
        self.assertEqual([row["result"] for row in observations], [errno.ENOENT] * 2)
        self.assertTrue(all(row["stage"] == "apr_file_open" for row in observations))

    def test_direct_device_observation_reports_real_enospc_without_injection(self):
        facts, observations, _ = self.control(adopt=False, device=True)
        self.assertTrue(all(row["write"] == errno.ENOSPC for row in facts))
        writes = [row for row in observations if row["stage"] == "apr_file_write_full"]
        self.assertEqual([row["result"] for row in writes], [errno.ENOSPC] * 2)
        self.assertTrue(all(row["action"] == "none" for row in observations))



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
