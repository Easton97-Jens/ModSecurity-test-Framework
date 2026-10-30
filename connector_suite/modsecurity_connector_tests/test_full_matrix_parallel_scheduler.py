from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import json
import os
from pathlib import Path
import re
import select
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from modsecurity_connector_tests.framework_test_trust import trusted_framework_root


ROOT = connector_root()
MATRIX_RUNNER = source_path('ci/runtime/lifecycle/run-full-matrix-parallel.sh', root=ROOT)
PORT_PLANNER = source_path('ci/runtime/lifecycle/plan_full_matrix_ports.py', root=ROOT)
DEFAULT_VARIANTS = (
    "no-crs/no-mrts",
    "no-crs/with-mrts",
    "with-crs/no-mrts",
    "with-crs/with-mrts",
)


class FullMatrixParallelSchedulerTest(unittest.TestCase):
    def planner_command(
        self,
        *,
        span: int = 1000,
        haproxy_spoa_offset: int = 12000,
        haproxy_backend_offset: int = 24000,
        jobs: tuple[str, ...] | None = None,
    ) -> list[str]:
        selected_jobs = jobs or tuple(
            f"{variant}:{connector}"
            for variant in DEFAULT_VARIANTS
            for connector in ("apache", "nginx", "haproxy")
        )
        command = [
            sys.executable,
            str(PORT_PLANNER),
            "--port-span",
            str(span),
            "--haproxy-spoa-offset",
            str(haproxy_spoa_offset),
            "--haproxy-backend-offset",
            str(haproxy_backend_offset),
            "--case-count",
            "apache=64",
            "--case-count",
            "nginx=64",
            "--case-count",
            "haproxy=64",
        ]
        for job in selected_jobs:
            command.extend(("--job", job))
        return command

    @staticmethod
    def planned_intervals(connector: str, base_port: int, *, case_count: int = 64, span: int = 1000) -> list[tuple[int, int]]:
        offsets = (0, 1000) if connector in {"apache", "nginx"} else (0, 12000, 24000)
        width = case_count + (2 * span) - 2
        return [(base_port + offset, base_port + offset + width - 1) for offset in offsets]

    def test_default_full_matrix_port_plan_reserves_disjoint_listener_ranges(self) -> None:
        process = subprocess.run(
            self.planner_command(),
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        planned = [line.split("\t") for line in process.stdout.splitlines() if line]
        self.assertEqual(len(planned), 12)
        self.assertEqual({f"{variant}:{connector}" for variant, connector, _ in planned}, set(self.planner_command_jobs()))

        intervals: list[tuple[str, int, int]] = []
        for variant, connector, base_text in planned:
            for start, end in self.planned_intervals(connector, int(base_text)):
                self.assertGreaterEqual(start, 1024)
                self.assertLessEqual(end, 65000)
                intervals.append((f"{variant}:{connector}", start, end))
        for index, (left_job, left_start, left_end) in enumerate(intervals):
            for right_job, right_start, right_end in intervals[index + 1 :]:
                if left_job == right_job:
                    continue
                self.assertTrue(
                    left_end < right_start or right_end < left_start,
                    f"{left_job} [{left_start}, {left_end}] overlaps {right_job} [{right_start}, {right_end}]",
                )

    @staticmethod
    def planner_command_jobs() -> tuple[str, ...]:
        return tuple(
            f"{variant}:{connector}"
            for variant in DEFAULT_VARIANTS
            for connector in ("apache", "nginx", "haproxy")
        )

    def test_planner_rejects_same_case_listener_overlap_before_runtime(self) -> None:
        process = subprocess.run(
            self.planner_command(span=1001, jobs=("no-crs/no-mrts:apache",)),
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(process.returncode, 2)
        self.assertIn("listener offsets overlap", process.stderr)

    def test_planner_rejects_a_listener_tuple_outside_the_safe_tcp_range(self) -> None:
        process = subprocess.run(
            self.planner_command(
                haproxy_backend_offset=64000,
                jobs=("no-crs/no-mrts:haproxy",),
            ),
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(process.returncode, 2)
        self.assertIn("no safe port range", process.stderr)

    @staticmethod
    def write_executable(path: Path, content: str) -> None:
        path.write_text(content, encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def start_live_matrix_lock_holder(self, lock_path: Path) -> subprocess.Popen[str]:
        holder = subprocess.Popen(
            [
                sys.executable,
                "-c",
                """import fcntl
from pathlib import Path
import sys
import time

lock_path = Path(sys.argv[1])
lock_path.parent.mkdir(parents=True, exist_ok=True)
with lock_path.open(\"a+\", encoding=\"utf-8\") as handle:
    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
    print(\"locked\", flush=True)
    while True:
        time.sleep(1)
""",
                str(lock_path),
            ],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertIsNotNone(holder.stdout)
        self.assertEqual(holder.stdout.readline().strip(), "locked")
        return holder

    def write_fake_make(self, bin_dir: Path) -> None:
        self.write_executable(
            bin_dir / "make",
            """#!/bin/sh
set -eu

case "$*" in
    *smoke-apache*) connector=apache ;;
    *smoke-nginx*) connector=nginx ;;
    *smoke-haproxy*) connector=haproxy ;;
    *) echo "unexpected fake make invocation: $*" >&2; exit 97 ;;
esac

if [ -n "${FAKE_MAKE_PID_FILE:-}" ]; then
    printf '%s\n' "$$" > "$FAKE_MAKE_PID_FILE"
fi

if [ "${FAKE_MAKE_BLOCK:-0}" = "1" ]; then
    exec sleep "${FAKE_MAKE_SLEEP:-30}"
fi

update_activity() {
    "$FAKE_PYTHON" - "$FAKE_STATE_DIR" "$1" "$2" "$connector" "$PORT" <<'PY'
import fcntl
from pathlib import Path
import sys
import time

state = Path(sys.argv[1])
delta = int(sys.argv[2])
event = sys.argv[3]
connector = sys.argv[4]
port = sys.argv[5]
with (state / "guard").open("a+", encoding="utf-8") as guard:
    fcntl.flock(guard.fileno(), fcntl.LOCK_EX)
    active_path = state / "active"
    maximum_path = state / "maximum"
    active = int(active_path.read_text(encoding="utf-8")) + delta
    active_path.write_text(f"{active}\\n", encoding="utf-8")
    maximum = int(maximum_path.read_text(encoding="utf-8"))
    if active > maximum:
        maximum_path.write_text(f"{active}\\n", encoding="utf-8")
    with (state / "events").open("a", encoding="utf-8") as events:
        events.write(f"{time.monotonic_ns()}|{event}|{connector}|{port}\\n")
    fcntl.flock(guard.fileno(), fcntl.LOCK_UN)
PY
}

update_activity 1 start

if [ "${FAKE_MAKE_REFILL_BARRIER:-0}" = "1" ]; then
    if ! "$FAKE_PYTHON" - "$FAKE_STATE_DIR" "$connector" \
        "$MODSECURITY_MRTS_VARIANT" "$FAKE_MAKE_BARRIER_TIMEOUT" <<'PY'
from pathlib import Path
import sys
import time

state = Path(sys.argv[1])
connector, variant = sys.argv[2:4]
timeout = float(sys.argv[4])

def await_marker(name):
    deadline = time.monotonic() + timeout
    while not (state / name).is_file():
        if time.monotonic() >= deadline:
            raise SystemExit("fixture refill barrier timed out: " + name)
        time.sleep(0.01)

if connector == "apache" and variant == "no-mrts":
    (state / "first-apache-started").touch()
    await_marker("queued-apache-started")
elif connector == "nginx" and variant == "no-mrts":
    await_marker("first-apache-started")
elif connector == "apache" and variant == "with-mrts":
    (state / "queued-apache-started").touch()
PY
    then
        update_activity -1 end
        exit 97
    fi
fi

case "$connector" in
    apache) sleep_seconds="${FAKE_MAKE_APACHE_SLEEP:-${FAKE_MAKE_SLEEP:-0.1}}" ;;
    nginx) sleep_seconds="${FAKE_MAKE_NGINX_SLEEP:-${FAKE_MAKE_SLEEP:-0.1}}" ;;
    haproxy) sleep_seconds="${FAKE_MAKE_HAPROXY_SLEEP:-${FAKE_MAKE_SLEEP:-0.1}}" ;;
esac
sleep "$sleep_seconds"

update_activity -1 end
printf '%s|%s\\n' "$connector" "$PORT" >> "$CAPTURE_FILE"
""",
        )

    def matrix_environment(self, root: Path, bin_dir: Path, capture_file: Path) -> dict[str, str]:
        configured_root = Path(
            os.environ.get(
                "PARENT_TEST_FRAMEWORK_ROOT",
                source_path('modules/ModSecurity-test-Framework', root=ROOT),
            )
        )
        framework_root, error = trusted_framework_root(ROOT, configured_root)
        if framework_root is None:
            self.skipTest(error)
        verified_root = root / "verified"
        component_cache = verified_root / "cache-v2" / "shared"
        owner_root = component_cache / "builds" / "connectors"
        apache_build_root = owner_root / "apache" / "cache-key" / "build"
        nginx_build_root = owner_root / "nginx" / "cache-key" / "build"
        apache_build_root.mkdir(parents=True)
        nginx_build_root.mkdir(parents=True)
        artifact_root = root / "artifacts"
        artifact_root.mkdir()
        fake_runtime = artifact_root / "runtime"
        self.write_executable(fake_runtime, "#!/bin/sh\nexit 0\n")
        apache_module = artifact_root / "apache-module.so"
        apache_module.write_text("module", encoding="utf-8")
        apache_lib_dir = artifact_root / "apache-lib"
        apache_lib_dir.mkdir()
        (apache_lib_dir / "libmodsecurity.so").write_text("library", encoding="utf-8")
        nginx_module_dir = artifact_root / "nginx-module"
        nginx_module_dir.mkdir()
        (nginx_module_dir / "ngx_http_modsecurity_module.so").write_text("module", encoding="utf-8")
        nginx_lib_dir = artifact_root / "nginx-lib"
        nginx_lib_dir.mkdir()
        (nginx_lib_dir / "libmodsecurity.so").write_text("library", encoding="utf-8")
        state_dir = root / "state"
        state_dir.mkdir()
        (state_dir / "active").write_text("0\n", encoding="utf-8")
        (state_dir / "maximum").write_text("0\n", encoding="utf-8")

        environment = os.environ.copy()
        environment.update(
            {
                "PATH": f"{bin_dir}{os.pathsep}{environment['PATH']}",
                "CAPTURE_FILE": str(capture_file),
                "FAKE_STATE_DIR": str(state_dir),
                "FAKE_PYTHON": sys.executable,
                "FAKE_MAKE_SLEEP": "0.15",
                "CONNECTOR_ROOT": str(ROOT),
                "FRAMEWORK_ROOT": str(framework_root),
                "VERIFIED_RUN_ROOT": str(verified_root),
                "VERIFIED_BUILD_ROOT": str(verified_root / "build"),
                "BUILD_ROOT": str(verified_root / "build"),
                "TMP_ROOT": str(verified_root / "tmp"),
                "LOG_ROOT": str(verified_root / "logs"),
                "CONNECTOR_COMPONENT_CACHE": str(component_cache),
                "VERIFIED_COMPONENT_CACHE": str(component_cache),
                "MATRIX_ROOT": str(verified_root / "matrix"),
                "MRTS_BUILD_ROOT": str(verified_root / "mrts"),
                "NGINX_HARNESS_PARENT": str(verified_root / "nginx-harness"),
                "FULL_MATRIX_VARIANTS": "no-crs/no-mrts",
                "FULL_MATRIX_CONNECTORS": "apache nginx",
                "FULL_MATRIX_MAX_PARALLEL_JOBS": "2",
                "FULL_MATRIX_SKIP_REPORTS": "1",
                "FULL_MATRIX_REPORT_DIR": str(verified_root / "reports"),
                "FULL_MATRIX_MANIFEST": str(verified_root / "matrix" / "runs.jsonl"),
                "APACHE_BUILD_ROOT": str(apache_build_root),
                "NGINX_BUILD_DIR": str(nginx_build_root),
                "APACHE_HTTPD": str(fake_runtime),
                "APACHE_MODULE": str(apache_module),
                "APACHE_MRTS_MODSECURITY_LIB_DIR": str(apache_lib_dir),
                "MRTS_NATIVE_NGINX_BIN": str(fake_runtime),
                "MRTS_NATIVE_NGINX_MODULE_DIR": str(nginx_module_dir),
                "MRTS_NATIVE_NGINX_MODSECURITY_LIB_DIR": str(nginx_lib_dir),
            }
        )
        return environment

    def assert_scheduler_lock_reusable_after_descendant_exit(
        self,
        environment: dict[str, str],
        *,
        failure_message: str,
    ) -> None:
        control_environment = environment.copy()
        control_environment["FAKE_MAKE_SLEEP"] = "0.01"
        control_environment["FAKE_MAKE_BLOCK"] = "0"
        # Lock reuse is a separate positive control, not another one-second
        # lost-completion fault. Metadata finalization is part of each job.
        control_environment["VERIFIED_RUN_FULL_MATRIX_JOB_TIMEOUT_SECONDS"] = "30"
        deadline = time.monotonic() + 10
        last_output = ""
        while time.monotonic() < deadline:
            candidate = subprocess.run(
                ["sh", str(MATRIX_RUNNER)],
                cwd=ROOT,
                env=control_environment,
                capture_output=True,
                text=True,
                check=False,
            )
            if candidate.returncode == 0:
                return
            last_output = candidate.stdout + candidate.stderr
            self.assertEqual(candidate.returncode, 77, last_output)
            self.assertIn("another full-matrix run owns", candidate.stderr, last_output)
            time.sleep(0.05)
        self.fail(f"{failure_message}\n{last_output}")

    def test_lock_reuse_control_has_its_own_timeout_without_mutating_failure_inputs(self) -> None:
        environment = {
            "VERIFIED_RUN_FULL_MATRIX_JOB_TIMEOUT_SECONDS": "1",
            "FAKE_MAKE_SLEEP": "30",
            "FAKE_MAKE_BLOCK": "1",
        }
        original = environment.copy()
        completed = subprocess.CompletedProcess(["sh"], 0, stdout="", stderr="")
        with mock.patch.object(subprocess, "run", return_value=completed) as run:
            self.assert_scheduler_lock_reusable_after_descendant_exit(
                environment, failure_message="lock unavailable",
            )
        self.assertEqual(environment, original)
        control_environment = run.call_args.kwargs["env"]
        self.assertEqual(control_environment["VERIFIED_RUN_FULL_MATRIX_JOB_TIMEOUT_SECONDS"], "30")
        self.assertEqual(control_environment["FAKE_MAKE_SLEEP"], "0.01")
        self.assertEqual(control_environment["FAKE_MAKE_BLOCK"], "0")

    def test_lock_reuse_control_does_not_retry_a_job_timeout_as_lock_contention(self) -> None:
        timed_out = subprocess.CompletedProcess(
            ["sh"], 77, stdout="", stderr="ERROR: full-matrix job completion timed out\n",
        )
        completed = subprocess.CompletedProcess(["sh"], 0, stdout="", stderr="")
        with mock.patch.object(subprocess, "run", side_effect=(timed_out, completed)) as run:
            with self.assertRaisesRegex(AssertionError, "job completion timed out"):
                self.assert_scheduler_lock_reusable_after_descendant_exit(
                    {}, failure_message="lock unavailable",
                )
        self.assertEqual(run.call_count, 1)

    def test_lock_reuse_control_retries_only_observed_lock_contention(self) -> None:
        locked = subprocess.CompletedProcess(
            ["sh"], 77, stdout="", stderr="ERROR: another full-matrix run owns lock\n",
        )
        completed = subprocess.CompletedProcess(["sh"], 0, stdout="", stderr="")
        with mock.patch.object(subprocess, "run", side_effect=(locked, completed)) as run:
            with mock.patch.object(time, "sleep"):
                self.assert_scheduler_lock_reusable_after_descendant_exit(
                    {}, failure_message="lock unavailable",
                )
        self.assertEqual(run.call_count, 2)

    def test_explicit_cap_runs_all_planned_jobs_without_exceeding_the_cap(self) -> None:
        with tempfile.TemporaryDirectory(prefix="full-matrix-scheduler-") as temporary:
            root = Path(temporary)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            self.write_fake_make(bin_dir)
            capture_file = root / "make-capture.txt"
            environment = self.matrix_environment(root, bin_dir, capture_file)

            process = subprocess.run(
                ["sh", str(MATRIX_RUNNER)],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            run_logs = "\n".join(
                path.read_text(encoding="utf-8")
                for path in sorted((root / "verified" / "matrix").rglob("run.log"))
            )
            self.assertEqual(process.returncode, 0, process.stdout + process.stderr + run_logs)
            self.assertEqual(
                {line.split("|", 1)[0] for line in capture_file.read_text(encoding="utf-8").splitlines()},
                {"apache", "nginx"},
            )
            self.assertEqual((root / "state" / "maximum").read_text(encoding="utf-8").strip(), "2")
            self.assertEqual((root / "state" / "active").read_text(encoding="utf-8").strip(), "0")
            manifest_rows = [
                json.loads(line)
                for line in (root / "verified" / "matrix" / "runs.jsonl").read_text(encoding="utf-8").splitlines()
                if line
            ]
            self.assertEqual(len(manifest_rows), 2)
            self.assertEqual({row["connector"] for row in manifest_rows}, {"apache", "nginx"})
            self.assertTrue((root / "verified" / "matrix" / ".full-matrix-run.lock").is_file())

    def test_parallel_scheduler_refills_a_freed_slot_before_a_slow_sibling_exits(self) -> None:
        with tempfile.TemporaryDirectory(prefix="full-matrix-scheduler-work-conserving-") as temporary:
            root = Path(temporary)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            self.write_fake_make(bin_dir)
            capture_file = root / "make-capture.txt"
            environment = self.matrix_environment(root, bin_dir, capture_file)
            environment["FULL_MATRIX_VARIANTS"] = "no-crs/no-mrts no-crs/with-mrts"
            environment["FULL_MATRIX_MAX_PARALLEL_JOBS"] = "2"
            environment["FAKE_MAKE_APACHE_SLEEP"] = "0"
            environment["FAKE_MAKE_NGINX_SLEEP"] = "0"
            environment["FAKE_MAKE_REFILL_BARRIER"] = "1"
            environment["FAKE_MAKE_BARRIER_TIMEOUT"] = "15"

            process = subprocess.run(
                ["sh", str(MATRIX_RUNNER)],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
                timeout=60,
            )

            self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
            events = [
                (int(timestamp), event, connector, int(port))
                for timestamp, event, connector, port in (
                    line.split("|", 3)
                    for line in (root / "state" / "events").read_text(encoding="utf-8").splitlines()
                    if line
                )
            ]
            starts = sorted(item for item in events if item[1] == "start")
            apache_ends = sorted(item for item in events if item[1] == "end" and item[2] == "apache")
            self.assertEqual(len(starts), 4)
            self.assertEqual(len(apache_ends), 2)
            self.assertEqual(sum(event[1] == "end" for event in events), 4)
            self.assertTrue((root / "state" / "first-apache-started").is_file())
            self.assertTrue((root / "state" / "queued-apache-started").is_file())
            self.assertLess(
                starts[2][0],
                apache_ends[0][0],
                "a queued job did not start before the first slow Apache job exited",
            )
            self.assertEqual((root / "state" / "maximum").read_text(encoding="utf-8").strip(), "2")
            self.assertEqual((root / "state" / "active").read_text(encoding="utf-8").strip(), "0")
            manifest_rows = [
                json.loads(line)
                for line in (root / "verified" / "matrix" / "runs.jsonl").read_text(encoding="utf-8").splitlines()
                if line
            ]
            self.assertEqual(len(manifest_rows), 4)

    def test_refill_barrier_rejects_missing_queued_start_and_cleans_activity(self) -> None:
        with tempfile.TemporaryDirectory(prefix="full-matrix-refill-negative-") as temporary:
            root = Path(temporary)
            self.write_fake_make(root)
            state = root / "state"
            state.mkdir()
            (state / "active").write_text("0\n", encoding="utf-8")
            (state / "maximum").write_text("0\n", encoding="utf-8")
            environment = os.environ.copy()
            environment.update({
                "FAKE_STATE_DIR": str(state), "FAKE_PYTHON": sys.executable,
                "CAPTURE_FILE": str(root / "capture"), "PORT": "29001",
                "MODSECURITY_MRTS_VARIANT": "no-mrts", "FAKE_MAKE_BLOCK": "0",
                "FAKE_MAKE_REFILL_BARRIER": "1", "FAKE_MAKE_BARRIER_TIMEOUT": "0.1",
            })
            process = subprocess.run(
                [str(root / "make"), "smoke-apache"], cwd=ROOT, env=environment,
                capture_output=True, text=True, check=False, timeout=10,
            )
            self.assertEqual(process.returncode, 97, process.stdout + process.stderr)
            self.assertIn("fixture refill barrier timed out: queued-apache-started", process.stderr)
            self.assertTrue((state / "first-apache-started").is_file())
            self.assertFalse((state / "queued-apache-started").exists())
            self.assertEqual((state / "active").read_text(encoding="utf-8").strip(), "0")
            events = (state / "events").read_text(encoding="utf-8").splitlines()
            self.assertEqual([event.split("|")[1] for event in events], ["start", "end"])

    def test_default_cap_uses_the_detected_online_cpu_count(self) -> None:
        with tempfile.TemporaryDirectory(prefix="full-matrix-scheduler-detected-cap-") as temporary:
            root = Path(temporary)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            self.write_fake_make(bin_dir)
            self.write_executable(bin_dir / "nproc", "#!/bin/sh\nprintf '%s\\n' 2\n")
            capture_file = root / "make-capture.txt"
            environment = self.matrix_environment(root, bin_dir, capture_file)
            environment.pop("FULL_MATRIX_MAX_PARALLEL_JOBS")

            process = subprocess.run(
                ["sh", str(MATRIX_RUNNER)],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
            self.assertIn("scheduling up to 2 isolated runtime jobs", process.stdout)
            self.assertIn("source=auto-detected", process.stdout)
            self.assertEqual((root / "state" / "maximum").read_text(encoding="utf-8").strip(), "2")

    def test_parallelism_diagnostic_reports_the_effective_detected_cap_without_runtime_setup(self) -> None:
        with tempfile.TemporaryDirectory(prefix="full-matrix-scheduler-parallelism-diagnostic-") as temporary:
            root = Path(temporary)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            self.write_executable(bin_dir / "nproc", "#!/bin/sh\nprintf '%s\\n' 3\n")
            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{bin_dir}{os.pathsep}{environment['PATH']}",
                    "CONNECTOR_ROOT": str(ROOT),
                }
            )
            environment.pop("FULL_MATRIX_MAX_PARALLEL_JOBS", None)

            process = subprocess.run(
                ["sh", str(MATRIX_RUNNER), "--print-effective-parallelism"],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
            self.assertEqual(
                process.stdout,
                "full-matrix-parallel: effective parallel job cap=3 source=auto-detected\n",
            )
            self.assertEqual(process.stderr, "")

    def test_parallelism_diagnostic_reports_a_normalized_explicit_cap_without_runtime_setup(self) -> None:
        environment = os.environ.copy()
        environment.update(
            {
                "CONNECTOR_ROOT": str(ROOT),
                "FULL_MATRIX_MAX_PARALLEL_JOBS": "003",
            }
        )

        process = subprocess.run(
            ["sh", str(MATRIX_RUNNER), "--print-effective-parallelism"],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertEqual(
            process.stdout,
            "full-matrix-parallel: effective parallel job cap=3 source=explicit\n",
        )
        self.assertEqual(process.stderr, "")

    def test_scheduler_rejects_a_live_full_matrix_lock_owner(self) -> None:
        with tempfile.TemporaryDirectory(prefix="full-matrix-scheduler-live-lock-") as temporary:
            root = Path(temporary)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            self.write_fake_make(bin_dir)
            capture_file = root / "make-capture.txt"
            environment = self.matrix_environment(root, bin_dir, capture_file)
            matrix_root = root / "verified" / "matrix"
            lock_path = matrix_root / ".full-matrix-run.lock"
            owner = self.start_live_matrix_lock_holder(lock_path)
            try:
                process = subprocess.run(
                    ["sh", str(MATRIX_RUNNER)],
                    cwd=ROOT,
                    env=environment,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(process.returncode, 77, process.stdout + process.stderr)
                self.assertIn("another full-matrix run owns", process.stderr)
                self.assertTrue(lock_path.is_file())
                self.assertIsNone(owner.poll())
                self.assertFalse(capture_file.exists())
            finally:
                if owner.poll() is None:
                    owner.kill()
                    owner.wait(timeout=10)
                if owner.stdout is not None:
                    owner.stdout.close()
                if owner.stderr is not None:
                    owner.stderr.close()

    def test_scheduler_times_out_when_a_job_wrapper_dies_before_completion(self) -> None:
        with tempfile.TemporaryDirectory(prefix="full-matrix-scheduler-lost-completion-") as temporary:
            root = Path(temporary)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            self.write_fake_make(bin_dir)
            capture_file = root / "make-capture.txt"
            environment = self.matrix_environment(root, bin_dir, capture_file)
            environment["FULL_MATRIX_CONNECTORS"] = "apache"
            environment["FULL_MATRIX_MAX_PARALLEL_JOBS"] = "1"
            environment["VERIFIED_RUN_FULL_MATRIX_JOB_TIMEOUT_SECONDS"] = "1"
            environment["FAKE_MAKE_SLEEP"] = "30"
            environment["FAKE_MAKE_BLOCK"] = "1"
            make_pid_file = root / "fake-make.pid"
            environment["FAKE_MAKE_PID_FILE"] = str(make_pid_file)
            scheduler = subprocess.Popen(
                ["sh", str(MATRIX_RUNNER)],
                cwd=ROOT,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            child_pid: int | None = None
            try:
                self.assertIsNotNone(scheduler.stdout)
                spawned_line = ""
                match = None
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline and match is None:
                    readable, _, _ = select.select([scheduler.stdout], [], [], 0.1)
                    if not readable:
                        continue
                    spawned_line = scheduler.stdout.readline()
                    match = re.search(r"\bpid=(\d+)\b", spawned_line)
                self.assertIsNotNone(match, spawned_line)
                wrapper_pid = int(match.group(1))

                deadline = time.monotonic() + 10
                while not make_pid_file.exists() and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertTrue(make_pid_file.exists(), "fake make did not start")
                child_pid = int(make_pid_file.read_text(encoding="utf-8").strip())

                os.kill(wrapper_pid, signal.SIGKILL)
                scheduler.wait(timeout=10)
                self.assertEqual(scheduler.returncode, 77)
                self.assertIsNotNone(scheduler.stderr)
                self.assertIn("job completion timed out", scheduler.stderr.read())

                os.kill(child_pid, signal.SIGKILL)
                self.assert_scheduler_lock_reusable_after_descendant_exit(
                    environment,
                    failure_message="scheduler lock was not reusable after the final descendant exited",
                )
            finally:
                if scheduler.poll() is None:
                    scheduler.kill()
                    scheduler.wait(timeout=10)
                if child_pid is not None:
                    try:
                        os.kill(child_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                if scheduler.stdout is not None:
                    scheduler.stdout.close()
                if scheduler.stderr is not None:
                    scheduler.stderr.close()

    def test_scheduler_lock_outlives_a_sigkilled_parent_until_its_job_descendant_exits(self) -> None:
        with tempfile.TemporaryDirectory(prefix="full-matrix-scheduler-stale-lock-") as temporary:
            root = Path(temporary)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            self.write_fake_make(bin_dir)
            capture_file = root / "make-capture.txt"
            environment = self.matrix_environment(root, bin_dir, capture_file)
            environment["FULL_MATRIX_CONNECTORS"] = "apache"
            environment["FULL_MATRIX_MAX_PARALLEL_JOBS"] = "1"
            environment["FAKE_MAKE_SLEEP"] = "30"
            environment["FAKE_MAKE_BLOCK"] = "1"
            make_pid_file = root / "fake-make.pid"
            environment["FAKE_MAKE_PID_FILE"] = str(make_pid_file)
            scheduler = subprocess.Popen(
                ["sh", str(MATRIX_RUNNER)],
                cwd=ROOT,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                deadline = time.monotonic() + 10
                while not make_pid_file.exists() and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertTrue(make_pid_file.exists(), "fake make did not start")
                child_pid = int(make_pid_file.read_text(encoding="utf-8").strip())

                scheduler.kill()
                scheduler.wait(timeout=10)
                if scheduler.stdout is not None:
                    scheduler.stdout.close()
                if scheduler.stderr is not None:
                    scheduler.stderr.close()

                blocked = subprocess.run(
                    ["sh", str(MATRIX_RUNNER)],
                    cwd=ROOT,
                    env=environment,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(blocked.returncode, 77, blocked.stdout + blocked.stderr)
                self.assertIn("another full-matrix run owns", blocked.stderr)

                os.kill(child_pid, signal.SIGKILL)
                self.assert_scheduler_lock_reusable_after_descendant_exit(
                    environment,
                    failure_message="kernel lock did not release after the final descendant exited",
                )
                self.assertTrue(capture_file.exists())
            finally:
                if scheduler.poll() is None:
                    scheduler.kill()
                    scheduler.wait(timeout=10)
                if scheduler.stdout is not None:
                    scheduler.stdout.close()
                if scheduler.stderr is not None:
                    scheduler.stderr.close()

    def test_invalid_parallel_cap_stops_before_any_make_invocation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="full-matrix-scheduler-invalid-cap-") as temporary:
            root = Path(temporary)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            self.write_fake_make(bin_dir)
            capture_file = root / "make-capture.txt"
            environment = self.matrix_environment(root, bin_dir, capture_file)
            environment["FULL_MATRIX_MAX_PARALLEL_JOBS"] = "0"

            process = subprocess.run(
                ["sh", str(MATRIX_RUNNER)],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(process.returncode, 2, process.stdout + process.stderr)
            self.assertIn("FULL_MATRIX_MAX_PARALLEL_JOBS must be a positive", process.stderr)
            self.assertFalse(capture_file.exists())



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
