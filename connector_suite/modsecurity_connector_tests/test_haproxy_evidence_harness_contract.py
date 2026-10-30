"""Focused contracts for the strict HAProxy runtime evidence receipt seam."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = connector_root()
HARNESS = source_path('connectors/haproxy/harness/run_haproxy_smoke.sh', root=ROOT)


class HaproxyEvidenceHarnessContractTests(unittest.TestCase):
    @staticmethod
    def source() -> str:
        return HARNESS.read_text(encoding="utf-8")

    def test_harness_is_shell_syntax_valid(self) -> None:
        result = subprocess.run(
            ["sh", "-n", str(HARNESS)], check=False, capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_receipt_startup_cleanup_fails_closed_on_a_stale_directory(self) -> None:
        source = self.source()
        cleanup_library = "cleanup_startup_artifacts() {" + source.split(
            "cleanup_startup_artifacts() {", 1
        )[1].split('if [ "$RUN_ONE_CASE" != "1" ]; then', 1)[0]
        receipt_branch = source.split(
            'if [ "$HAPROXY_EVIDENCE_RECEIPT" = "1" ]; then', 1
        )[1].split("else", 1)[0]
        self.assertIn("/bin/rm -f", cleanup_library)
        self.assertNotIn("|| true", cleanup_library)
        self.assertIn("cleanup_startup_artifacts", receipt_branch)
        self.assertIn("cannot clear stale HAProxy artifacts before evidence receipt", receipt_branch)
        self.assertNotIn("|| true", receipt_branch)
        script = r'''
set -eu
library=$1
log_dir=$2
runtime_root=$3
LOG_DIR=$log_dir
RUNTIME_ROOT=$runtime_root
. "$library"
if cleanup_startup_artifacts; then
    exit 1
fi
'''
        with tempfile.TemporaryDirectory(prefix="haproxy-evidence-startup-cleanup-") as directory:
            root = Path(directory)
            library = root / "cleanup-library.sh"
            log_dir = root / "logs"
            runtime_root = root / "runtime"
            library.write_text(cleanup_library, encoding="utf-8")
            (log_dir / "audit" / "stale-directory").mkdir(parents=True)
            (runtime_root / "conf").mkdir(parents=True)
            result = subprocess.run(
                [
                    "sh",
                    "-eu",
                    "-c",
                    script,
                    "sh",
                    str(library),
                    str(log_dir),
                    str(runtime_root),
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_case_result_write_failure_is_not_ignored_before_evidence_cleanup(self) -> None:
        source = self.source()
        result_library = "write_case_result() {" + source.split(
            "write_case_result() {", 1
        )[1].split("enrich_summary_metadata() {", 1)[0]
        success_start = source.index('if ! write_case_result "$TEST_CASE" pass')
        receipt_start = source.index(
            'if [ "$HAPROXY_EVIDENCE_RECEIPT" = "1" ]', success_start
        )
        self.assertNotIn("|| true", result_library)
        self.assertLess(
            success_start,
            receipt_start,
        )
        script = r'''
set -eu
library=$1
failing_python=$2
missing_output_python=$3
successful_python=$4
output=$5
CASE_CLI=case-cli
. "$library"
PYTHON_BIN=$failing_python
if write_case_result example pass 403 "$output"; then
    exit 1
fi
PYTHON_BIN=$missing_output_python
if write_case_result example pass 403 "$output"; then
    exit 1
fi
PYTHON_BIN=$successful_python
write_case_result example pass 403 "$output"
'''
        with tempfile.TemporaryDirectory(prefix="haproxy-evidence-result-write-") as directory:
            root = Path(directory)
            library = root / "result-library.sh"
            failing_python = root / "failing-python"
            missing_output_python = root / "missing-output-python"
            successful_python = root / "successful-python"
            output = root / "result.json"
            library.write_text(result_library, encoding="utf-8")
            failing_python.write_text("#!/bin/sh\nexit 23\n", encoding="utf-8")
            missing_output_python.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            successful_python.write_text(
                "#!/bin/sh\n"
                "if [ \"$2\" = case-info ]; then\n"
                "    shift 2\n"
                "    while [ \"$#\" -gt 0 ]; do\n"
                "        if [ \"$1\" = --output ]; then\n"
                "            printf '%s\\n' '{\"case\":\"example\"}' > \"$2\"\n"
                "            exit 0\n"
                "        fi\n"
                "        shift\n"
                "    done\n"
                "    exit 1\n"
                "fi\n"
                "[ \"$1\" = - ]\n",
                encoding="utf-8",
            )
            failing_python.chmod(0o700)
            missing_output_python.chmod(0o700)
            successful_python.chmod(0o700)
            result = subprocess.run(
                [
                    "sh",
                    "-eu",
                    "-c",
                    script,
                    "sh",
                    str(library),
                    str(failing_python),
                    str(missing_output_python),
                    str(successful_python),
                    str(output),
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_receipt_process_check_rejects_pgrep_inspection_errors(self) -> None:
        source = self.source()
        process_library = "runtime_process_group_running() {" + source.split(
            "runtime_process_group_running() {", 1
        )[1].split("wait_for_runtime_process_group_exit() {", 1)[0]
        process_library += "require_runtime_process_stopped() {" + source.split(
            "require_runtime_process_stopped() {", 1
        )[1].split("cleanup() {", 1)[0]
        script = r'''
set -eu
library=$1
no_process_pgrep=$2
failing_pgrep=$3
. "$library"
sleep 0.01 &
process_pid=$!
wait "$process_pid"
RUNTIME_PGREP_BIN=$no_process_pgrep
require_runtime_process_stopped test "$process_pid"
RUNTIME_PGREP_BIN=$failing_pgrep
if require_runtime_process_stopped test "$process_pid"; then
    exit 1
fi
'''
        with tempfile.TemporaryDirectory(prefix="haproxy-evidence-process-check-") as directory:
            root = Path(directory)
            library = root / "process-library.sh"
            no_process_pgrep = root / "no-process-pgrep"
            failing_pgrep = root / "failing-pgrep"
            library.write_text(process_library, encoding="utf-8")
            no_process_pgrep.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
            failing_pgrep.write_text("#!/bin/sh\nexit 2\n", encoding="utf-8")
            no_process_pgrep.chmod(0o700)
            failing_pgrep.chmod(0o700)
            result = subprocess.run(
                [
                    "sh",
                    "-eu",
                    "-c",
                    script,
                    "sh",
                    str(library),
                    str(no_process_pgrep),
                    str(failing_pgrep),
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("cannot inspect process-group members before evidence receipt", result.stderr)

    def test_receipt_process_tools_ignore_path_shadowing(self) -> None:
        source = self.source()
        process_tool_library = "configure_haproxy_evidence_receipt_process_tools() {" + source.split(
            "configure_haproxy_evidence_receipt_process_tools() {", 1
        )[1].split("cleanup_runtime_process() {", 1)[0]
        script = r'''
set -eu
library=$1
shadow_path=$2
PATH=$shadow_path
RUNTIME_SETSID_BIN=
RUNTIME_PGREP_BIN=
RUNTIME_PS_BIN=
fail() {
    exit 23
}
. "$library"
configure_haproxy_evidence_receipt_process_tools
[ "$RUNTIME_SETSID_BIN" = /usr/bin/setsid ]
[ "$RUNTIME_PGREP_BIN" = /usr/bin/pgrep ]
[ "$RUNTIME_PS_BIN" = /usr/bin/ps ]
'''
        with tempfile.TemporaryDirectory(prefix="haproxy-evidence-process-tools-") as directory:
            root = Path(directory)
            library = root / "process-tools.sh"
            shadow_path = root / "shadow-bin"
            library.write_text(process_tool_library, encoding="utf-8")
            shadow_path.mkdir()
            result = subprocess.run(
                ["sh", "-eu", "-c", script, "sh", str(library), str(shadow_path)],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_receipt_cleanup_uses_fixed_rm_despite_path_shadowing(self) -> None:
        source = self.source()
        cleanup_library = "cleanup() {" + source.split("cleanup() {", 1)[1].split(
            "cleanup_on_exit() {", 1
        )[0]
        self.assertIn("! /bin/rm -f", cleanup_library)
        script = r'''
set -eu
library=$1
shadow_path=$2
runtime_root=$3
shadow_marker=$4
PATH=$shadow_path
export PATH SHADOW_MARKER=$shadow_marker
RUNTIME_ROOT=$runtime_root
HAPROXY_PID=
AGENT_PID=
BACKEND_PID=
RUNTIME_CLEANUP_COMPLETE=0
cleanup_runtime_process() {
    return 0
}
. "$library"
cleanup
[ "$RUNTIME_CLEANUP_COMPLETE" = 1 ]
[ ! -e "$RUNTIME_ROOT/haproxy.pid" ]
[ ! -e "$RUNTIME_ROOT/spoa.pid" ]
[ ! -e "$RUNTIME_ROOT/spoa.port" ]
[ ! -e "$RUNTIME_ROOT/spoa.ready" ]
[ ! -e "$SHADOW_MARKER" ]
'''
        with tempfile.TemporaryDirectory(prefix="haproxy-evidence-cleanup-path-") as directory:
            root = Path(directory)
            library = root / "cleanup-library.sh"
            shadow_path = root / "shadow-bin"
            runtime_root = root / "runtime"
            shadow_marker = root / "shadow-rm-called"
            library.write_text(cleanup_library, encoding="utf-8")
            shadow_path.mkdir()
            runtime_root.mkdir()
            for state_name in ("haproxy.pid", "spoa.pid", "spoa.port", "spoa.ready"):
                (runtime_root / state_name).write_text("stale\n", encoding="utf-8")
            shadow_rm = shadow_path / "rm"
            shadow_rm.write_text(
                "#!/bin/sh\n: > \"$SHADOW_MARKER\"\nexit 0\n", encoding="utf-8"
            )
            shadow_rm.chmod(0o700)
            result = subprocess.run(
                [
                    "sh",
                    "-eu",
                    "-c",
                    script,
                    "sh",
                    str(library),
                    str(shadow_path),
                    str(runtime_root),
                    str(shadow_marker),
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_receipt_path_starts_and_cleans_up_separate_process_groups(self) -> None:
        source = self.source()
        for name in ("BACKEND_PID", "AGENT_PID", "HAPROXY_PID"):
            self.assertIn(f"{name}=", source)
            self.assertIn(f'cleanup_runtime_process', source)
        self.assertIn("RUNTIME_SETSID_BIN", source)
        self.assertIn("RUNTIME_PGREP_BIN", source)
        self.assertIn("RUNTIME_PS_BIN", source)
        self.assertIn('runtime_process_group_running "$process_pid"', source)
        self.assertIn('/bin/kill -TERM -- "-$process_pid"', source)
        self.assertIn('! /bin/kill -TERM "$process_pid"', source)
        self.assertIn('/bin/kill -KILL -- "-$process_pid"', source)
        self.assertIn("signal_runtime_process_group_members", source)
        self.assertIn('signal_runtime_process_group_members "$process_pid" TERM', source)
        self.assertIn('signal_runtime_process_group_members "$process_pid" KILL', source)
        self.assertIn('if wait "$process_pid" >/dev/null 2>&1; then', source)
        self.assertIn("wait_status", source)
        self.assertIn('trap cleanup_on_exit EXIT', source)
        self.assertIn("trap 'exit 130' INT", source)
        self.assertIn("trap 'exit 143' TERM", source)
        cleanup = source.split("cleanup() {", 1)[1].split("cleanup_on_exit() {", 1)[0]
        self.assertNotIn("|| true", cleanup)
        self.assertIn("RUNTIME_CLEANUP_COMPLETE=1", cleanup)
        self.assertIn("RUNTIME_CLEANUP_COMPLETE=0", cleanup)

    @unittest.skipUnless(
        shutil.which("setsid") and shutil.which("pgrep") and shutil.which("ps"),
        "process-group tools are unavailable",
    )
    def test_cleanup_runtime_process_terminates_and_reaps_a_descendant_group(self) -> None:
        source = self.source()
        cleanup_library = "cleanup_runtime_process() {" + source.split(
            "cleanup_runtime_process() {", 1
        )[1].split("write_haproxy_config() {", 1)[0]
        script = r'''
set -eu
library=$1
RUNTIME_SETSID_BIN=$(command -v setsid)
RUNTIME_PGREP_BIN=$(command -v pgrep)
RUNTIME_PS_BIN=$(command -v ps)
RUNTIME_ROOT=
HAPROXY_PID=
AGENT_PID=
BACKEND_PID=
. "$library"
leader=
test_cleanup() {
    if [ -n "$leader" ]; then
        /bin/kill -TERM -- "-$leader" >/dev/null 2>&1 || :
        wait "$leader" >/dev/null 2>&1 || :
    fi
}
trap test_cleanup EXIT INT TERM
setsid sh -c 'sleep 30 & wait' &
leader=$!
sleep 0.1
cleanup_runtime_process test "$leader"
if kill -0 "$leader" >/dev/null 2>&1; then
    exit 1
fi
if "$RUNTIME_PGREP_BIN" -g "$leader" >/dev/null 2>&1; then
    exit 1
fi
trap - EXIT INT TERM
'''
        with tempfile.TemporaryDirectory(prefix="haproxy-evidence-cleanup-") as directory:
            library = Path(directory) / "cleanup-library.sh"
            library.write_text(cleanup_library, encoding="utf-8")
            result = subprocess.run(
                ["sh", "-eu", "-c", script, "sh", str(library)],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @unittest.skipUnless(
        shutil.which("setsid") and shutil.which("pgrep") and shutil.which("ps"),
        "process-group tools are unavailable",
    )
    def test_cleanup_signals_descendant_before_leader_and_reaps_group(self) -> None:
        source = self.source()
        cleanup_library = "cleanup_runtime_process() {" + source.split(
            "cleanup_runtime_process() {", 1
        )[1].split("write_haproxy_config() {", 1)[0]
        script = r'''
set -eu
library=$1
RUNTIME_SETSID_BIN=$(command -v setsid)
RUNTIME_PGREP_BIN=$(command -v pgrep)
RUNTIME_PS_BIN=$(command -v ps)
RUNTIME_ROOT=
HAPROXY_PID=
AGENT_PID=
BACKEND_PID=
. "$library"
leader=
test_cleanup() {
    if [ -n "$leader" ]; then
        /bin/kill -KILL -- "-$leader" >/dev/null 2>&1 || :
        wait "$leader" >/dev/null 2>&1 || :
    fi
}
trap test_cleanup EXIT INT TERM
descendant_marker=$2
leader_marker=${descendant_marker}.leader
DESCENDANT_MARKER=$descendant_marker
LEADER_MARKER=$leader_marker
export DESCENDANT_MARKER LEADER_MARKER
setsid sh -c 'trap '\''test -f "$DESCENDANT_MARKER" || exit 99; : > "$LEADER_MARKER"; exit 0'\'' TERM; (trap '\'' : > "$DESCENDANT_MARKER"; exit 0'\'' TERM; while :; do :; done) & while :; do :; done' &
leader=$!
sleep 0.1
cleanup_runtime_process ordered "$leader"
[ -f "$descendant_marker" ]
[ -f "$leader_marker" ]
if kill -0 "$leader" >/dev/null 2>&1; then
    exit 1
fi
if "$RUNTIME_PGREP_BIN" -g "$leader" >/dev/null 2>&1; then
    exit 1
fi
trap - EXIT INT TERM
'''
        with tempfile.TemporaryDirectory(prefix="haproxy-evidence-order-cleanup-") as directory:
            library = Path(directory) / "cleanup-library.sh"
            marker = Path(directory) / "signal-order.txt"
            library.write_text(cleanup_library, encoding="utf-8")
            result = subprocess.run(
                ["sh", "-eu", "-c", script, "sh", str(library), str(marker)],
                check=False,
                capture_output=True,
                text=True,
                timeout=15,
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @unittest.skipUnless(shutil.which("setsid"), "setsid is unavailable")
    def test_cleanup_fails_closed_when_process_group_inspection_fails(self) -> None:
        source = self.source()
        cleanup_library = "cleanup_runtime_process() {" + source.split(
            "cleanup_runtime_process() {", 1
        )[1].split("write_haproxy_config() {", 1)[0]
        script = r'''
set -eu
library=$1
fake_pgrep=$2
RUNTIME_SETSID_BIN=$(command -v setsid)
RUNTIME_PGREP_BIN=$fake_pgrep
RUNTIME_PS_BIN=/bin/ps
RUNTIME_ROOT=
HAPROXY_PID=
AGENT_PID=
BACKEND_PID=
. "$library"
leader=
test_cleanup() {
    if [ -n "$leader" ]; then
        /bin/kill -KILL -- "-$leader" >/dev/null 2>&1 || :
        wait "$leader" >/dev/null 2>&1 || :
    fi
}
trap test_cleanup EXIT INT TERM
setsid sh -c 'while :; do :; done' &
leader=$!
sleep 0.1
if cleanup_runtime_process inspection-failure "$leader"; then
    exit 1
fi
if ! kill -0 "$leader" >/dev/null 2>&1; then
    exit 1
fi
trap - EXIT INT TERM
test_cleanup
'''
        with tempfile.TemporaryDirectory(prefix="haproxy-evidence-pgrep-failure-") as directory:
            root = Path(directory)
            library = root / "cleanup-library.sh"
            fake_pgrep = root / "failing-pgrep"
            library.write_text(cleanup_library, encoding="utf-8")
            fake_pgrep.write_text("#!/bin/sh\nexit 2\n", encoding="utf-8")
            fake_pgrep.chmod(0o700)
            result = subprocess.run(
                ["sh", "-eu", "-c", script, "sh", str(library), str(fake_pgrep)],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("cannot inspect process-group members during cleanup", result.stderr)

    @unittest.skipUnless(shutil.which("setsid"), "setsid is unavailable")
    def test_cleanup_fails_closed_when_group_wait_inspection_fails(self) -> None:
        source = self.source()
        cleanup_library = "cleanup_runtime_process() {" + source.split(
            "cleanup_runtime_process() {", 1
        )[1].split("write_haproxy_config() {", 1)[0]
        script = r'''
set -eu
library=$1
fake_pgrep=$2
counter=$3
RUNTIME_SETSID_BIN=$(command -v setsid)
RUNTIME_PGREP_BIN=$fake_pgrep
RUNTIME_PS_BIN=/bin/ps
RUNTIME_ROOT=
HAPROXY_PID=
AGENT_PID=
BACKEND_PID=
PGREP_COUNT_FILE=$counter
export PGREP_COUNT_FILE
. "$library"
leader=
test_cleanup() {
    if [ -n "$leader" ]; then
        /bin/kill -KILL -- "-$leader" >/dev/null 2>&1 || :
        wait "$leader" >/dev/null 2>&1 || :
    fi
}
trap test_cleanup EXIT INT TERM
setsid sh -c 'while :; do :; done' &
leader=$!
sleep 0.1
if cleanup_runtime_process wait-inspection-failure "$leader"; then
    exit 1
fi
if ! kill -0 "$leader" >/dev/null 2>&1; then
    exit 1
fi
trap - EXIT INT TERM
test_cleanup
'''
        with tempfile.TemporaryDirectory(prefix="haproxy-evidence-wait-pgrep-") as directory:
            root = Path(directory)
            library = root / "cleanup-library.sh"
            fake_pgrep = root / "sequenced-pgrep"
            counter = root / "pgrep-count"
            library.write_text(cleanup_library, encoding="utf-8")
            fake_pgrep.write_text(
                "#!/bin/sh\n"
                "count=$(cat \"$PGREP_COUNT_FILE\" 2>/dev/null || printf 0)\n"
                "count=$((count + 1))\n"
                "printf '%s\\n' \"$count\" > \"$PGREP_COUNT_FILE\"\n"
                "if [ \"$count\" -eq 1 ]; then\n"
                "    exit 1\n"
                "fi\n"
                "exit 2\n",
                encoding="utf-8",
            )
            fake_pgrep.chmod(0o700)
            result = subprocess.run(
                [
                    "sh",
                    "-eu",
                    "-c",
                    script,
                    "sh",
                    str(library),
                    str(fake_pgrep),
                    str(counter),
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("cannot inspect process-group members during cleanup", result.stderr)

    @unittest.skipUnless(
        shutil.which("setsid") and shutil.which("pgrep") and shutil.which("ps"),
        "process-group tools are unavailable",
    )
    def test_cleanup_runtime_process_escalates_for_a_term_ignoring_descendant(self) -> None:
        source = self.source()
        cleanup_library = "cleanup_runtime_process() {" + source.split(
            "cleanup_runtime_process() {", 1
        )[1].split("write_haproxy_config() {", 1)[0]
        script = r'''
set -eu
library=$1
RUNTIME_SETSID_BIN=$(command -v setsid)
RUNTIME_PGREP_BIN=$(command -v pgrep)
RUNTIME_PS_BIN=$(command -v ps)
RUNTIME_ROOT=
HAPROXY_PID=
AGENT_PID=
BACKEND_PID=
. "$library"
leader=
test_cleanup() {
    if [ -n "$leader" ]; then
        /bin/kill -KILL -- "-$leader" >/dev/null 2>&1 || :
        wait "$leader" >/dev/null 2>&1 || :
    fi
}
trap test_cleanup EXIT INT TERM
setsid sh -c '(trap "" TERM; while :; do /bin/sleep 1; done) & wait' &
leader=$!
sleep 0.1
cleanup_runtime_process stubborn "$leader"
if kill -0 "$leader" >/dev/null 2>&1; then
    exit 1
fi
if "$RUNTIME_PGREP_BIN" -g "$leader" >/dev/null 2>&1; then
    exit 1
fi
trap - EXIT INT TERM
'''
        with tempfile.TemporaryDirectory(prefix="haproxy-evidence-stubborn-cleanup-") as directory:
            library = Path(directory) / "cleanup-library.sh"
            library.write_text(cleanup_library, encoding="utf-8")
            result = subprocess.run(
                ["sh", "-eu", "-c", script, "sh", str(library)],
                check=False,
                capture_output=True,
                text=True,
                timeout=15,
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_receipt_is_fixed_post_cleanup_metadata_not_raw_runtime_result(self) -> None:
        source = self.source()
        receipt = source.split("write_haproxy_evidence_receipt() {", 1)[1].split(
            "write_haproxy_config() {", 1
        )[0]
        self.assertIn('source_root="$LOG_DIR/haproxy-runtime-evidence-source"', receipt)
        self.assertIn('"$RUNTIME_CLEANUP_COMPLETE" = "1"', receipt)
        self.assertIn("require_runtime_process_stopped haproxy", receipt)
        self.assertIn("require_runtime_process_stopped spoa", receipt)
        self.assertIn("require_runtime_process_stopped backend", receipt)
        self.assertIn("1:crs_sqli_anomaly_block:with-crs:no-mrts:403:403", receipt)
        self.assertIn("write-source-receipt", receipt)
        self.assertIn("--expected-parent-sha", receipt)
        self.assertIn("--expected-framework-sha", receipt)
        self.assertIn("--expected-mrts-sha", receipt)
        self.assertIn("require_haproxy_evidence_cell_run_id", receipt)
        self.assertIn("--expected-cell-run-id", receipt)
        self.assertIn('"$CRS_RUNTIME_RUN_ID"', receipt)
        self.assertNotIn("result.json", receipt)
        self.assertNotIn("decision.jsonl", receipt)
        self.assertNotIn("audit", receipt)
        self.assertNotIn("response-body", receipt)
        success = source.split('write_case_result "$TEST_CASE" pass', 1)[1]
        self.assertLess(success.index("if ! cleanup; then"), success.index("write_haproxy_evidence_receipt"))
        self.assertLess(success.index("write_haproxy_evidence_receipt"), success.index("exit 0"))

    def test_receipt_uses_only_the_fixed_unprivileged_projector_and_fails_closed(self) -> None:
        source = self.source()
        receipt = source.split("write_haproxy_evidence_receipt() {", 1)[1].split(
            "write_haproxy_config() {", 1
        )[0]
        self.assertIn("HAPROXY_EVIDENCE_RECEIPT_PROJECTOR", receipt)
        self.assertIn("projector is outside the fixed runtime path", receipt)
        self.assertIn("projector must not be a symlink", receipt)
        self.assertIn(
            '"$PYTHON_BIN" "$HAPROXY_EVIDENCE_RECEIPT_PROJECTOR" write-source-receipt',
            receipt,
        )
        self.assertIn('mkdir -m 700 "$source_root"', receipt)
        self.assertNotIn("HAPROXY_EVIDENCE_RECEIPT_HELPER", receipt)
        self.assertNotIn("seal-helper", receipt)
        self.assertNotIn("sealed helper", receipt)
        self.assertNotIn("sudo", receipt)
        self.assertNotIn("|| true", receipt)
        self.assertNotIn("exit 0", receipt)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
