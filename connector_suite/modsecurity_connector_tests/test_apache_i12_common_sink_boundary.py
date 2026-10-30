"""Genuine Common private-open results through a link-wrapped symbolic DSO."""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
import errno
import json
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = connector_root()
CALLER = '''#include "msconnector/event_jsonl.h"
int fixture_open(const char *path,int *fd) { return msconnector_open_private_event_file(path,fd); }
'''
DRIVER = r'''
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
int fixture_open(const char *,int *);
int main(int argc,char **argv) {
    if(argc<2)return 2;
    int fd=-12345;errno=EDOM;
    int result=fixture_open(argv[1],argc>2 && !strcmp(argv[2],"null")?NULL:&fd);
    int saved=errno;
    int valid=fd>=0 && fcntl(fd,F_GETFD)>=0;
    printf("{\"result\":%d,\"errno\":%d,\"fd\":%d,\"fd_valid\":%d}\n",result,saved,fd,valid);
    if(valid)close(fd);
    return 0;
}
'''

class ApacheCommonSinkBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        base = os.environ.get("CODEX_TEST_TMP_ROOT", os.environ.get("RUNNER_TEMP",
            "/var/tmp/codex/ModSecurity-conector"))
        temporary = tempfile.TemporaryDirectory(prefix="apache-common-boundary-", dir=base)
        cls.addClassCleanup(temporary.cleanup)
        cls.work = Path(temporary.name)
        caller, driver = cls.work / "caller.c", cls.work / "driver.c"
        caller.write_text(CALLER)
        driver.write_text(DRIVER)
        sources = ("transaction_state.c", "decision_action.c", "intervention.c", "block_statuses.c",
            "http_status.c", "rule_id.c", "event.c", "event_jsonl.c", "integrity_event.c",
            "json_escape.c", "status.c", "late_intervention.c")
        cls.commands = []
        cls.binaries = {}
        for wrapped in (False, True):
            library = cls.work / ("libwrapped.so" if wrapped else "libcontrol.so")
            command = ["rtk", "proxy", "cc", "-std=c17", "-Wall", "-Wextra", "-Werror", "-fPIC",
                "-shared", "-Wl,-Bsymbolic-functions", "-I", str(source_path('common/include', root=ROOT)), str(caller),
                *[str(source_path('common/src', root=ROOT) / name) for name in sources], "-o", str(library)]
            if wrapped:
                command += [str(source_path('ci/runtime/lifecycle/apache-i12/acceptance/common_sink_boundary.c', root=ROOT)),
                    "-Wl,--wrap=msconnector_open_private_event_file"]
            result = subprocess.run(command, capture_output=True, text=True)
            cls.commands.append({"command": command, "exit": result.returncode, "stderr": result.stderr})
            if result.returncode:
                raise RuntimeError(result.stderr)
            binary = cls.work / ("wrapped" if wrapped else "control")
            command = ["rtk", "proxy", "cc", "-std=c17", "-Wall", "-Wextra", "-Werror", str(driver),
                str(library), "-Wl,-rpath," + str(cls.work), "-o", str(binary)]
            result = subprocess.run(command, capture_output=True, text=True)
            cls.commands.append({"command": command, "exit": result.returncode, "stderr": result.stderr})
            if result.returncode:
                raise RuntimeError(result.stderr)
            cls.binaries[wrapped] = binary
        cls.evidence = os.environ.get("I12_APACHE_COMMON_BOUNDARY_EVIDENCE_DIR")
        if cls.evidence:
            destination = Path(cls.evidence)
            destination.mkdir(parents=True, exist_ok=True)
            (destination / "build.json").write_text(json.dumps({"commands": cls.commands,
                "common_source_sha256": {name: hashlib.sha256((source_path('common/src', root=ROOT) / name).read_bytes()).hexdigest()
                    for name in sources},
                "wrapper_sha256": hashlib.sha256((source_path('ci/runtime/lifecycle/apache-i12/acceptance/common_sink_boundary.c', root=ROOT)).read_bytes()).hexdigest(),
                "hardening": "-Bsymbolic-functions retained for both genuine Common DSOs"}, indent=2))
            for item in cls.work.iterdir():
                if item.is_file():
                    shutil.copy2(item, destination / item.name)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="case-", dir=self.work)
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.directory.chmod(0o700)
        self.marker = self.directory / "sink.enable"
        self.marker.write_bytes(b"I12_APACHE_SINK_FAULT_V1\n")
        self.marker.chmod(0o600)
        self.attempts = []

    def tearDown(self):
        if self.evidence:
            destination = Path(self.evidence) / self._testMethodName
            destination.mkdir(exist_ok=True)
            (destination / "attempts.json").write_text(json.dumps(self.attempts, indent=2))

    def observe(self, target, *, wrapped=True, admitted=True, null=False, configured_target=None):
        env = os.environ.copy()
        env.update(I12_SINK_ROOT=str(self.directory), I12_SINK_PATH=str(configured_target or target),
            I12_SINK_MARKER=str(self.marker), I12_SINK_FAULT="observe")
        if not admitted:
            env.pop("I12_SINK_ROOT", None)
        command = ["rtk", "proxy", str(self.binaries[wrapped]), str(target)]
        if null:
            command.append("null")
        process = subprocess.run(command, env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual(process.returncode, 0, process.stderr)
        result = json.loads(process.stdout)
        records = [json.loads(line.split(" ", 1)[1]) for line in process.stderr.splitlines()
            if line.startswith("I12_APACHE_COMMON ")]
        self.attempts.append({"command": command, "exit": process.returncode,
            "stdout": process.stdout, "stderr": process.stderr, "observations": records})
        return result, records

    def compare(self, target, expected_result, expected_errno=None):
        control, no_records = self.observe(target, wrapped=False)
        observed, records = self.observe(target)
        self.assertEqual(no_records, [])
        for field in ("result", "errno", "fd_valid"):
            self.assertEqual(control[field], observed[field])
        self.assertEqual(observed["result"], expected_result)
        if expected_errno is not None:
            self.assertEqual(observed["errno"], expected_errno)
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record["result"], observed["result"])
        self.assertEqual(record["errno_at_return"], observed["errno"])
        self.assertEqual(record["fd_valid_after"], bool(observed["fd_valid"]))
        self.assertIsNone(record["fd_valid_before"])
        self.assertIsNone(record["phase"])
        self.assertIsNone(record["allocation_scope_call"])
        self.assertFalse(record["apr_open_observed"])
        self.assertLessEqual(record["entered_ns"], record["return_ns"])
        return observed, record

    def test_genuine_success_preserves_owned_private_descriptor(self):
        target = self.directory / "valid.jsonl"
        self.compare(target, 1)
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_genuine_missing_parent_is_enoent_before_apr(self):
        self.compare(self.directory / "missing/leaf.jsonl", 0, errno.ENOENT)

    def test_genuine_dev_full_is_invalid_file_type_before_apr(self):
        self.compare(Path("/dev/full"), 0, errno.EINVAL)

    def test_genuine_group_writable_parent_policy_is_eacces(self):
        parent = self.directory / "group-writable"
        parent.mkdir(mode=0o777)
        parent.chmod(0o777)
        self.compare(parent / "event.jsonl", 0, errno.EACCES)

    def test_nonroot_readonly_parent_requires_actual_posix_permission_denial(self):
        if os.geteuid() == 0:
            self.skipTest("root DAC override cannot prove an unwritable-parent EACCES; private UID-dropped host run required")
        parent = self.directory / "readonly"
        parent.mkdir(mode=0o500)
        self.addCleanup(lambda: parent.chmod(0o700))
        self.compare(parent / "event.jsonl", 0, errno.EACCES)

    def test_missing_opt_in_keeps_real_result_without_observation(self):
        result, records = self.observe(self.directory / "missing/event.jsonl", admitted=False)
        self.assertEqual((result["result"], result["errno"]), (0, errno.ENOENT))
        self.assertEqual(records, [])

    def test_wrong_marker_and_unselected_path_never_claim_a_call(self):
        self.marker.write_bytes(b"wrong\n")
        self.assertEqual(self.observe(self.directory / "normal.jsonl")[1], [])
        self.marker.write_bytes(b"I12_APACHE_SINK_FAULT_V1\n")
        self.assertEqual(self.observe(self.directory / "normal.jsonl",
            configured_target=self.directory / "different.jsonl")[1], [])

    def test_null_output_pointer_preserves_real_einval_and_unknown_descriptor(self):
        result, records = self.observe(self.directory / "normal.jsonl", null=True)
        self.assertEqual((result["result"], result["errno"]), (0, errno.EINVAL))
        self.assertEqual(len(records), 1)
        self.assertFalse(records[0]["out_fd_present"])
        self.assertIsNone(records[0]["fd_valid_after"])
        self.assertIsNone(records[0]["out_fd"])

    def test_resource_label_is_json_escaped_without_changing_real_path(self):
        target = self.directory / 'quoted"leaf.jsonl'
        _, record = self.compare(target, 1)
        self.assertEqual(record["resource_path"], str(target))

# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)
