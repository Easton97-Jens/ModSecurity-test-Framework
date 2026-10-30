from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from copy import deepcopy
from itertools import product
from pathlib import Path
from unittest import mock


ROOT = connector_root()
CHECKER_PATH = source_path('ci/checks/documentation/check-generated-report-layout.py', root=ROOT)
CHECKER = load_source(CHECKER_PATH)
GENERATOR_PATH = source_path('ci/evidence/reports/generate-full-matrix-job-completeness.py', root=ROOT)
GENERATOR = load_source(GENERATOR_PATH)
REFRESH_PATH = source_path('ci/evidence/reports/refresh-connector-reports.py', root=ROOT)
REFRESH = load_source(REFRESH_PATH)
RUNNER_PATH = source_path('ci/runtime/lifecycle/run-verified-report-run.py', root=ROOT)
RUNNER = load_source(RUNNER_PATH)
RECEIPT_PATH = source_path('ci/lib/verified_full_matrix_receipt.py', root=ROOT)
RECEIPT = load_source(RECEIPT_PATH)
STAGER_PATH = source_path('ci/evidence/reports/stage-verified-full-matrix-evidence.py', root=ROOT)
STAGER = load_source(STAGER_PATH)

CONNECTORS = ("apache", "nginx", "haproxy")
CRS_VARIANTS = ("no-crs", "with-crs")
MRTS_VARIANTS = ("no-mrts", "with-mrts")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def replace_raw_matrix_job(
    rows: list[dict[str, object]], matrix_manifest: Path, job: dict[str, object]
) -> None:
    for index, row in enumerate(rows):
        if row.get("job_id") == job["job_id"]:
            rows[index] = job
            matrix_manifest.write_text(
                "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
                encoding="utf-8",
            )
            return
    raise AssertionError(f"raw matrix job not found: {job['job_id']}")


class GeneratedReportEvidenceIntegrityTests(unittest.TestCase):
    def test_strict_gate_follows_runtime_evidence_materialization(self) -> None:
        plan = RUNNER.command_plan(
            runtime_matrix_timeout=1,
            full_matrix_runtime_timeout=1,
            report_refresh_timeout=1,
            native_mrts_timeout=1,
            profile="full",
        )
        targets = [item["logical_target"] for item in plan]
        gate_index = targets.index("verified-report-evidence-gate")
        self.assertGreater(gate_index, targets.index("refresh-all-reports"))
        self.assertGreater(gate_index, targets.index("generate-system-environment-proof"))
        self.assertNotIn("check-generated-report-layout", targets)
        self.assertTrue(plan[gate_index]["required"])
        self.assertFalse(plan[gate_index]["optional"])

    def build_valid_run(self, root: Path) -> tuple[Path, Path, str]:
        connector_root = root / "connector"
        build_root = root / "build"
        run_id = "verified-run-20260718"
        commands_path = build_root / "verified-runs" / run_id / "verified-commands.json"
        commands = {
            "verified_run_id": run_id,
            "commands": [
                {
                    "logical_target": "full-matrix-parallel",
                    "phase": "runtime-producers",
                    "required": True,
                    "return_code": 0,
                    "classification": "success",
                    "runtime_complete": True,
                    "runtime_status": "runtime_completed",
                    "started_at": "2026-07-18T00:00:00Z",
                    "finished_at": "2026-07-18T00:00:01Z",
                }
            ],
        }
        write_json(commands_path, commands)

        rows = []
        matrix_root = build_root / "full-matrix"
        for crs, mrts in product(CRS_VARIANTS, MRTS_VARIANTS):
            for connector in CONNECTORS:
                job_root = matrix_root / crs / mrts / connector
                log_path = job_root / "run.log"
                build_manifest = job_root / "build-manifest.json"
                summary_path = job_root / "results" / "force-all" / f"{connector}-summary.json"
                results_jsonl = job_root / "results" / "force-all" / f"{connector}-results.jsonl"
                log_path.parent.mkdir(parents=True, exist_ok=True)
                log_path.write_text("runtime process and traffic receipt\n", encoding="utf-8")
                write_json(build_manifest, {"connector": connector, "verified_run_id": run_id})
                write_json(summary_path, {connector: {"cases": {"control": {"status": "pass"}}}})
                results_jsonl.write_text(
                    json.dumps({"connector": connector, "verified_run_id": run_id, "status": "pass"}) + "\n",
                    encoding="utf-8",
                )
                job_path = job_root / "job.json"
                job = {
                    "connector": connector,
                    "job_id": f"{connector}:{crs}:{mrts}",
                    "verified_run_id": run_id,
                    "test_variant": crs,
                    "mrts_variant": mrts,
                    "return_code": 0,
                    "status": "completed",
                    "started_at": "2026-07-18T00:00:00Z",
                    "ended_at": "2026-07-18T00:00:01Z",
                    "duration_seconds": 1,
                    "results_dir": str(job_root / "results"),
                    "summary_path": str(summary_path),
                    "log_path": str(log_path),
                    "hashes": {
                        "log": sha256(log_path),
                        "summary": sha256(summary_path),
                        "build_manifest": sha256(build_manifest),
                        "results_jsonl": sha256(results_jsonl),
                    },
                    "inputs": {"build_manifest": str(build_manifest)},
                    "outputs": {
                        "job_json": str(job_path),
                        "log": str(log_path),
                        "summary": str(summary_path),
                        "results_dir": str(job_root / "results"),
                        "results_jsonl": str(results_jsonl),
                    },
                }
                write_json(job_path, job)
                rows.append(job)

        raw_manifest = matrix_root / "full-runtime-matrix-runs.jsonl"
        raw_manifest.parent.mkdir(parents=True, exist_ok=True)
        raw_manifest.write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
            encoding="utf-8",
        )
        self.raw_matrix_rows = rows
        revisions = {
            "connector_sha": "a" * 40,
            "framework_sha": "b" * 40,
            "mrts_sha": "c" * 40,
        }
        aggregate_path = RECEIPT.seal_full_matrix_aggregate_receipt(
            build_root=build_root,
            verified_run_id=run_id,
            profile="full",
            parent_command=commands["commands"][0],
            revisions=revisions,
        )
        verified_manifest = {
            "verified_run_id": run_id,
            "profile": "full",
            **revisions,
            "command_file": {
                "path": str(commands_path),
                "status": "present",
                "sha256": sha256(commands_path),
                "bytes": commands_path.stat().st_size,
            },
            "full_matrix_aggregate_receipt": {
                "path": str(aggregate_path),
                "status": "present",
                "sha256": sha256(aggregate_path),
                "bytes": aggregate_path.stat().st_size,
            },
            "full_matrix_job_completeness": {"complete_jobs": 12, "missing_jobs": []},
        }
        write_json(
            connector_root / "reports/testing/generated/manifest/verified-run-manifest.generated.json",
            verified_manifest,
        )
        return connector_root, build_root, run_id

    def raw_matrix_job(self, job_id: str) -> dict[str, object]:
        for row in self.raw_matrix_rows:
            if row["job_id"] == job_id:
                return deepcopy(row)
        raise AssertionError(f"raw matrix job not found: {job_id}")

    def assert_chain_rejected(self, connector_root: Path, build_root: Path, expected: str) -> None:
        errors: list[str] = []
        CHECKER.check_verified_runtime_artifact_chain(
            connector_root,
            errors,
            build_root=build_root,
        )
        self.assertTrue(errors, "expected strict artifact-chain rejection")
        self.assertTrue(any(expected in error for error in errors), errors)

    def reseal_aggregate_receipt(self, connector_root: Path, build_root: Path, run_id: str) -> Path:
        receipt_path = RECEIPT.aggregate_receipt_path(build_root, run_id)
        receipt_path.unlink()
        commands_path = build_root / "verified-runs" / run_id / "verified-commands.json"
        parent_command = json.loads(commands_path.read_text(encoding="utf-8"))["commands"][-1]
        sealed_path = RECEIPT.seal_full_matrix_aggregate_receipt(
            build_root=build_root,
            verified_run_id=run_id,
            profile="full",
            parent_command=parent_command,
            revisions={"connector_sha": "a" * 40, "framework_sha": "b" * 40, "mrts_sha": "c" * 40},
        )
        manifest_path = connector_root / "reports/testing/generated/manifest/verified-run-manifest.generated.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["full_matrix_aggregate_receipt"].update(
            {"path": str(sealed_path), "sha256": sha256(sealed_path), "bytes": sealed_path.stat().st_size}
        )
        write_json(manifest_path, manifest)
        return sealed_path

    def rewrite_raw_job_row(self, build_root: Path, replacement: dict[str, object]) -> None:
        raw_path = build_root / "full-matrix" / "full-runtime-matrix-runs.jsonl"
        rows = [json.loads(line) for line in raw_path.read_text(encoding="utf-8").splitlines() if line]
        rewritten = [replacement if row.get("job_id") == replacement["job_id"] else row for row in rows]
        raw_path.write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in rewritten),
            encoding="utf-8",
        )

    def prepare_staging_inputs(self, root: Path) -> tuple[Path, Path, str, Path]:
        connector_root, build_root, run_id = self.build_valid_run(root)
        manifest_root = connector_root / "reports/testing/generated/manifest"
        write_json(manifest_root / "report-freshness.generated.json", {"verified_run_id": run_id})
        write_json(manifest_root / "report-refresh-manifest.generated.json", {"verified_run_id": run_id})
        marker = build_root / "verified-runs/current-run-id"
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(f"{run_id}\n", encoding="ascii")
        return connector_root, build_root, run_id, root / "staged-evidence"

    def stage_full_evidence(self, root: Path) -> tuple[Path, Path, str, Path, object]:
        connector_root, build_root, run_id, stage_root = self.prepare_staging_inputs(root)
        staged = RECEIPT.stage_verified_full_matrix_evidence(
            connector_root=connector_root,
            build_root=build_root,
            stage_root=stage_root,
        )
        return connector_root, build_root, run_id, stage_root, staged

    def test_generated_markdown_home_paths_remain_portable(self) -> None:
        local_home_root = "<local-home-root>"
        expected_evidence_path = f"{local_home_root}/work"
        expected_by_raw_path = {
            "/root": local_home_root,
            "/root/work": expected_evidence_path,
            "/home/alice": local_home_root,
            "/home/alice/work": expected_evidence_path,
            "/Users/alice": local_home_root,
            "/Users/alice/work": expected_evidence_path,
            "/home": "/home",
            "relative/path": "relative/path",
        }

        for raw_path, expected_path in expected_by_raw_path.items():
            with self.subTest(raw_path=raw_path):
                self.assertEqual(
                    CHECKER.portable_markdown_text(f"Path: `{raw_path}`"),
                    f"Path: `{expected_path}`",
                )

    def test_generated_markdown_temporary_paths_remain_portable(self) -> None:
        expected_by_raw_path = {
            "/var/tmp/ModSecurity-conector-verified/run-1": "<verified-run-root>/run-1",
            "/tmp/ModSecurity-conector-verified/run-1": "<verified-run-root>/run-1",
            "/var/tmp/scratch/run-1": "<temporary-work-root>/scratch/run-1",
            "/tmp/scratch/run-1": "<temporary-work-root>/scratch/run-1",
        }

        for raw_path, expected_path in expected_by_raw_path.items():
            with self.subTest(raw_path=raw_path):
                self.assertEqual(
                    CHECKER.portable_markdown_text(f"Path: `{raw_path}`"),
                    f"Path: `{expected_path}`",
                )

    def test_registry_generator_provenance_groups_remain_stable(self) -> None:
        expected_keys_by_generator = {
            "ci/evidence/reports/refresh-connector-reports.py": {
                "report_refresh_manifest",
                "report_freshness",
                "merge_readiness_dashboard",
            },
            "ci/evidence/reports/generate-remaining-failure-analysis.py": {
                "full_run_evidence",
                "remaining_failure_analysis",
                "next_fix_plan",
            },
            "framework:ci/reporting/generate-case-matrix.py": {
                "case_matrix",
                "connector_gap_summary",
                "coverage_summary",
                "phase_coverage",
                "xfail_summary",
                "apache_runtime_results",
                "nginx_runtime_results",
                "haproxy_runtime_results",
                "runtime_matrix",
            },
            "framework:ci/reporting/generate-mrts-native-report.py": {
                "mrts_native_full",
                "mrts_native_apache",
                "mrts_native_nginx",
                "mrts_native_summary",
            },
        }

        for generator, expected_keys in expected_keys_by_generator.items():
            with self.subTest(generator=generator):
                actual_keys = {
                    report_key
                    for report_key, report in CHECKER.GENERATED_REPORTS.items()
                    if report.generator == generator
                }
                self.assertSetEqual(actual_keys, expected_keys)

    def test_stage_verified_full_matrix_evidence_copies_exact_allowlist(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            connector_root, build_root, run_id, stage_root, staged = self.stage_full_evidence(root)
            expected_paths = {
                "manifests/verified-run-manifest.generated.json",
                "manifests/report-freshness.generated.json",
                "manifests/report-refresh-manifest.generated.json",
                f"verified-runs/{run_id}/verified-commands.json",
                f"verified-runs/{run_id}/full-matrix-aggregate-receipt.json",
                "full-matrix/full-runtime-matrix-runs.jsonl",
                *{
                    f"full-matrix/{crs}/{mrts}/{connector}/job.json"
                    for crs, mrts, connector in product(CRS_VARIANTS, MRTS_VARIANTS, CONNECTORS)
                },
            }
            self.assertEqual(stage_root.absolute(), staged.stage_root)
            self.assertEqual(run_id, staged.verified_run_id)
            self.assertEqual(RECEIPT.STAGED_EVIDENCE_FILE_COUNT, len(staged.files))
            self.assertEqual(expected_paths, {record.relative_path for record in staged.files})
            for source in RECEIPT._staged_evidence_sources(run_id):
                source_root = connector_root if source.source_root == "connector" else build_root
                source_path = source_root.joinpath(*source.source_components)
                staged_path = stage_root.joinpath(*source.stage_components)
                record = next(item for item in staged.files if item.relative_path == "/".join(source.stage_components))
                self.assertTrue(stat.S_ISREG(os.lstat(staged_path).st_mode))
                self.assertFalse(staged_path.is_symlink())
                self.assertEqual(stat.S_IMODE(os.lstat(staged_path).st_mode), 0o400)
                self.assertEqual(source_path.read_bytes(), staged_path.read_bytes())
                self.assertEqual(sha256(staged_path), record.sha256)
                self.assertEqual(staged_path.stat().st_size, record.bytes)
            self.assertEqual(stat.S_IMODE(stage_root.stat().st_mode), 0o500)
            for directory, _, _ in os.walk(stage_root):
                self.assertEqual(stat.S_IMODE(Path(directory).stat().st_mode), 0o500)
            self.assertFalse(any(path.name == "run.log" for path in stage_root.rglob("*")))
            self.assertFalse(any("results" in path.parts for path in stage_root.rglob("*")))

    def test_stage_rejects_intermediate_source_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            connector_root, build_root, _, stage_root = self.prepare_staging_inputs(root)
            matrix_root = build_root / "full-matrix"
            external_matrix = root / "external-matrix"
            matrix_root.rename(external_matrix)
            matrix_root.symlink_to(external_matrix, target_is_directory=True)

            with self.assertRaisesRegex(RECEIPT.AggregateReceiptError, "directory is unavailable or unsafe"):
                RECEIPT.stage_verified_full_matrix_evidence(
                    connector_root=connector_root,
                    build_root=build_root,
                    stage_root=stage_root,
                )
            self.assertFalse(stage_root.exists())
            self.assertTrue((external_matrix / "full-runtime-matrix-runs.jsonl").is_file())

    def test_stage_rejects_final_source_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            connector_root, build_root, _, stage_root = self.prepare_staging_inputs(root)
            job_path = build_root / "full-matrix/no-crs/no-mrts/apache/job.json"
            external_job = root / "external-job.json"
            job_path.rename(external_job)
            job_path.symlink_to(external_job)

            with self.assertRaisesRegex(RECEIPT.AggregateReceiptError, "file is unavailable or unsafe"):
                RECEIPT.stage_verified_full_matrix_evidence(
                    connector_root=connector_root,
                    build_root=build_root,
                    stage_root=stage_root,
                )
            self.assertFalse(stage_root.exists())
            self.assertEqual(external_job.read_bytes(), (root / "external-job.json").read_bytes())

    def test_stage_uses_buffered_bytes_after_source_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            connector_root, build_root, _, stage_root = self.prepare_staging_inputs(root)
            job_path = build_root / "full-matrix/no-crs/no-mrts/apache/job.json"
            original = job_path.read_bytes()
            original_create = RECEIPT._create_empty_stage_root

            def replace_source_then_create(*args: object, **kwargs: object) -> int:
                job_path.write_text("replaced after source snapshot\n", encoding="utf-8")
                return original_create(*args, **kwargs)

            with mock.patch.object(RECEIPT, "_create_empty_stage_root", side_effect=replace_source_then_create):
                staged = RECEIPT.stage_verified_full_matrix_evidence(
                    connector_root=connector_root,
                    build_root=build_root,
                    stage_root=stage_root,
                )
            staged_path = stage_root / "full-matrix/no-crs/no-mrts/apache/job.json"
            self.assertEqual(original, staged_path.read_bytes())
            self.assertNotEqual(original, job_path.read_bytes())
            record = next(item for item in staged.files if item.relative_path.endswith("no-crs/no-mrts/apache/job.json"))
            self.assertEqual(hashlib.sha256(original).hexdigest(), record.sha256)

    def test_stage_rejects_source_mutated_while_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            connector_root, build_root, _, stage_root = self.prepare_staging_inputs(root)
            job_path = build_root / "full-matrix/no-crs/no-mrts/apache/job.json"
            target = os.stat(job_path)
            original_read = RECEIPT.os.read
            mutated = False

            def mutate_target_while_read(descriptor: int, count: int) -> bytes:
                nonlocal mutated
                chunk = original_read(descriptor, count)
                details = os.fstat(descriptor)
                if not mutated and chunk and (details.st_dev, details.st_ino) == (target.st_dev, target.st_ino):
                    current = os.stat(job_path)
                    os.utime(job_path, ns=(current.st_atime_ns, current.st_mtime_ns + 1_000_000))
                    mutated = True
                return chunk

            with mock.patch.object(RECEIPT.os, "read", side_effect=mutate_target_while_read):
                with self.assertRaisesRegex(RECEIPT.AggregateReceiptError, "file changed while it was read"):
                    RECEIPT.stage_verified_full_matrix_evidence(
                        connector_root=connector_root,
                        build_root=build_root,
                        stage_root=stage_root,
                    )
            self.assertTrue(mutated)
            self.assertFalse(stage_root.exists())

    def test_stage_root_is_never_reused_or_followed(self) -> None:
        for kind in ("directory", "symlink"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                connector_root, build_root, _, stage_root = self.prepare_staging_inputs(root)
                if kind == "directory":
                    stage_root.mkdir()
                    sentinel = stage_root / "sentinel.txt"
                else:
                    external = root / "external-stage"
                    external.mkdir()
                    stage_root.symlink_to(external, target_is_directory=True)
                    sentinel = external / "sentinel.txt"
                sentinel.write_text("must remain untouched\n", encoding="utf-8")

                with self.assertRaisesRegex(RECEIPT.AggregateReceiptError, "staged evidence root already exists"):
                    RECEIPT.stage_verified_full_matrix_evidence(
                        connector_root=connector_root,
                        build_root=build_root,
                        stage_root=stage_root,
                    )
                self.assertEqual(sentinel.read_text(encoding="utf-8"), "must remain untouched\n")

    def test_verify_stage_rejects_post_stage_source_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            connector_root, build_root, _, stage_root, _ = self.stage_full_evidence(root)
            job_path = build_root / "full-matrix/no-crs/no-mrts/apache/job.json"
            job_path.write_text("replacement after staging\n", encoding="utf-8")

            with self.assertRaisesRegex(RECEIPT.AggregateReceiptError, "does not match current source"):
                RECEIPT.verify_staged_full_matrix_evidence(
                    connector_root=connector_root,
                    build_root=build_root,
                    stage_root=stage_root,
                )

    def test_stage_rejects_directory_replacement_before_publication(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            connector_root, build_root, _, stage_root = self.prepare_staging_inputs(root)
            moved_stage = root / "moved-stage"
            original_seal = RECEIPT._seal_staged_directories

            def seal_then_replace(*args: object, **kwargs: object) -> None:
                original_seal(*args, **kwargs)
                stage_root.rename(moved_stage)
                stage_root.mkdir()
                (stage_root / "unexpected.txt").write_text("must not be retained\n", encoding="utf-8")

            with mock.patch.object(RECEIPT, "_seal_staged_directories", side_effect=seal_then_replace):
                with self.assertRaisesRegex(RECEIPT.AggregateReceiptError, "staged evidence root changed while publishing"):
                    RECEIPT.stage_verified_full_matrix_evidence(
                        connector_root=connector_root,
                        build_root=build_root,
                        stage_root=stage_root,
                    )
            self.assertEqual((stage_root / "unexpected.txt").read_text(encoding="utf-8"), "must not be retained\n")
            self.assertTrue(moved_stage.is_dir())

    def test_stage_rejects_parent_writable_by_another_user(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            connector_root, build_root, _, _ = self.prepare_staging_inputs(root)
            unsafe_parent = root / "unsafe-stage-parent"
            unsafe_parent.mkdir()
            unsafe_parent.chmod(0o733)
            with self.assertRaisesRegex(RECEIPT.AggregateReceiptError, "writable by another user"):
                RECEIPT.stage_verified_full_matrix_evidence(
                    connector_root=connector_root,
                    build_root=build_root,
                    stage_root=unsafe_parent / "stage",
                )

    def test_stager_cli_stages_the_explicit_private_root_and_verifies_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            connector_root, build_root, _, _ = self.prepare_staging_inputs(root)
            stage_root = root / "staged-evidence"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout), mock.patch.object(
                sys,
                "argv",
                [
                    str(STAGER_PATH),
                    "stage",
                    "--connector-root",
                    str(connector_root),
                    "--build-root",
                    str(build_root),
                    "--stage-root",
                    str(stage_root),
                ],
            ):
                self.assertEqual(STAGER.main(), 0)
            output = json.loads(stdout.getvalue())
            self.assertEqual(output["stage_root"], str(stage_root))
            self.assertEqual(output["verified_run_id"], "verified-run-20260718")
            with contextlib.redirect_stdout(io.StringIO()), mock.patch.object(
                sys,
                "argv",
                [
                    str(STAGER_PATH),
                    "verify",
                    "--connector-root",
                    str(connector_root),
                    "--build-root",
                    str(build_root),
                    "--stage-root",
                    str(stage_root),
                ],
            ):
                self.assertEqual(STAGER.main(), 0)

    def test_stager_cli_rejects_legacy_github_output_parameter(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            connector_root, build_root, _, _ = self.prepare_staging_inputs(root)
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr), mock.patch.object(
                sys,
                "argv",
                [
                    str(STAGER_PATH),
                    "stage",
                    "--connector-root",
                    str(connector_root),
                    "--build-root",
                    str(build_root),
                    "--stage-root",
                    str(root / "staged-evidence"),
                    "--github-output",
                    str(root / "legacy-output"),
                ],
            ):
                with self.assertRaises(SystemExit) as raised:
                    STAGER.main()
            self.assertEqual(raised.exception.code, 2)
            self.assertIn("--github-output", stderr.getvalue())

    def test_valid_full_matrix_control_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            connector_root, build_root, _ = self.build_valid_run(Path(temporary))
            errors: list[str] = []
            CHECKER.check_verified_runtime_artifact_chain(
                connector_root,
                errors,
                build_root=build_root,
            )
        self.assertEqual(errors, [])

    def test_valid_full_matrix_control_uses_default_runtime_build_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            connector_root, build_root, _ = self.build_valid_run(Path(temporary))
            errors: list[str] = []
            with mock.patch.object(CHECKER, "verified_runtime_paths", return_value={"BUILD_ROOT": str(build_root)}):
                CHECKER.check_verified_runtime_artifact_chain(connector_root, errors)
        self.assertEqual(errors, [])

    def test_main_threads_the_validated_build_root_to_strict_receipt_checks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            connector_root = root / "connector"
            build_root = root / "build"
            connector_root.mkdir()
            build_root.mkdir()
            with contextlib.ExitStack() as stack:
                for name in (
                    "check_registry_paths",
                    "check_no_flat_reports",
                    "check_no_orphan_generated_reports",
                    "check_existing_generated_reports",
                    "check_generated_markdown_portability",
                    "check_verified_runtime_diagnostics",
                    "check_system_environment_proof",
                    "check_no_legacy_references",
                    "check_no_flat_generator_writes",
                    "check_no_runtime_source_url_hardcoding",
                    "check_no_insecure_repo_url_literals",
                ):
                    stack.enter_context(mock.patch.object(CHECKER, name))
                check_manifest = stack.enter_context(mock.patch.object(CHECKER, "check_manifest"))
                check_consistency = stack.enter_context(
                    mock.patch.object(CHECKER, "check_critical_report_run_consistency")
                )
                check_chain = stack.enter_context(mock.patch.object(CHECKER, "check_verified_runtime_artifact_chain"))
                stack.enter_context(
                    mock.patch.object(CHECKER, "verified_runtime_paths", return_value={"BUILD_ROOT": str(build_root)})
                )
                stack.enter_context(
                    mock.patch.object(sys, "argv", ["check-generated-report-layout.py", "--connector-root", str(connector_root)])
                )
                self.assertEqual(CHECKER.main(), 0)

        expected = build_root.absolute()
        self.assertEqual(expected, check_manifest.call_args.kwargs["build_root"])
        self.assertEqual(expected, check_consistency.call_args.kwargs["build_root"])
        self.assertEqual(expected, check_chain.call_args.kwargs["build_root"])

    def test_paired_mutable_result_job_and_raw_forgery_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            connector_root, build_root, _ = self.build_valid_run(Path(temporary))
            job_path = build_root / "full-matrix/no-crs/no-mrts/apache/job.json"
            results_path = build_root / "full-matrix/no-crs/no-mrts/apache/results/force-all/apache-results.jsonl"
            results_path.write_text(
                '{"connector":"apache","status":"pass","forged":true}\n',
                encoding="utf-8",
            )
            job = json.loads(job_path.read_text(encoding="utf-8"))
            job["hashes"]["results_jsonl"] = sha256(results_path)
            write_json(job_path, job)
            self.rewrite_raw_job_row(build_root, job)
            self.assert_chain_rejected(connector_root, build_root, "aggregate receipt")

    def test_post_receipt_validation_artifact_swap_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            connector_root, build_root, _ = self.build_valid_run(Path(temporary))
            original_validate = CHECKER.validate_full_matrix_aggregate_receipt
            validation_calls = 0

            def validate_then_swap(*args: object, **kwargs: object) -> tuple[dict[str, object], list[str]]:
                nonlocal validation_calls
                result = original_validate(*args, **kwargs)
                validation_calls += 1
                if validation_calls == 1:
                    job_path = build_root / "full-matrix/no-crs/no-mrts/apache/job.json"
                    log_path = job_path.parent / "run.log"
                    log_path.write_text("forged after initial receipt validation\n", encoding="utf-8")
                    job = json.loads(job_path.read_text(encoding="utf-8"))
                    job["hashes"]["log"] = sha256(log_path)
                    write_json(job_path, job)
                    self.rewrite_raw_job_row(build_root, job)
                return result

            errors: list[str] = []
            with mock.patch.object(CHECKER, "validate_full_matrix_aggregate_receipt", side_effect=validate_then_swap):
                CHECKER.check_verified_runtime_artifact_chain(
                    connector_root,
                    errors,
                    build_root=build_root,
                )
        self.assertEqual(validation_calls, 2)
        self.assertTrue(any("final aggregate receipt validation failed" in error for error in errors), errors)

    def test_post_validation_command_receipt_swap_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            connector_root, build_root, run_id = self.build_valid_run(Path(temporary))
            original_validate = CHECKER.validate_full_matrix_aggregate_receipt
            validation_calls = 0

            def validate_then_swap_command(*args: object, **kwargs: object) -> tuple[dict[str, object], list[str]]:
                nonlocal validation_calls
                result = original_validate(*args, **kwargs)
                validation_calls += 1
                if validation_calls == 1:
                    commands_path = build_root / "verified-runs" / run_id / "verified-commands.json"
                    commands = json.loads(commands_path.read_text(encoding="utf-8"))
                    commands["commands"][0]["return_code"] = 99
                    write_json(commands_path, commands)
                return result

            errors: list[str] = []
            with mock.patch.object(
                CHECKER,
                "validate_full_matrix_aggregate_receipt",
                side_effect=validate_then_swap_command,
            ):
                CHECKER.check_verified_runtime_artifact_chain(
                    connector_root,
                    errors,
                    build_root=build_root,
                )
        self.assertEqual(validation_calls, 2)
        self.assertTrue(any("verified command receipt hash mismatch" in error for error in errors), errors)

    def test_paired_mutable_job_and_raw_rewrite_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            connector_root, build_root, _ = self.build_valid_run(Path(temporary))
            job_path = build_root / "full-matrix/no-crs/no-mrts/apache/job.json"
            job = json.loads(job_path.read_text(encoding="utf-8"))
            job["untrusted_child_note"] = "forged after the job completed"
            write_json(job_path, job)
            self.rewrite_raw_job_row(build_root, job)
            self.assert_chain_rejected(connector_root, build_root, "aggregate receipt")

    def test_raw_matrix_only_rewrite_is_rejected_by_aggregate_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            connector_root, build_root, _ = self.build_valid_run(Path(temporary))
            raw_path = build_root / "full-matrix/full-runtime-matrix-runs.jsonl"
            rows = [json.loads(line) for line in raw_path.read_text(encoding="utf-8").splitlines() if line]
            raw_path.write_text(
                "".join(json.dumps(row, sort_keys=True) + "\n" for row in reversed(rows)),
                encoding="utf-8",
            )
            self.assert_chain_rejected(connector_root, build_root, "aggregate receipt")

    def test_aggregate_receipt_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            connector_root, build_root, run_id = self.build_valid_run(root)
            receipt_path = RECEIPT.aggregate_receipt_path(build_root, run_id)
            escaped_receipt = root / "escaped-aggregate-receipt.json"
            receipt_path.rename(escaped_receipt)
            receipt_path.symlink_to(escaped_receipt)
            self.assert_chain_rejected(connector_root, build_root, "aggregate receipt")

    def test_intermediate_read_swap_fails_closed_without_hashing_external_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, build_root, run_id = self.build_valid_run(root)
            matrix_root = build_root / "full-matrix"
            external_matrix = root / "external-matrix"
            shutil.copytree(matrix_root, external_matrix)
            external_log = external_matrix / "no-crs/no-mrts/apache/run.log"
            external_log.write_text("external bytes must never be sealed\n", encoding="utf-8")
            external_job_path = external_matrix / "no-crs/no-mrts/apache/job.json"
            external_job = json.loads(external_job_path.read_text(encoding="utf-8"))
            external_job["hashes"]["log"] = sha256(external_log)
            write_json(external_job_path, external_job)
            external_raw_path = external_matrix / "full-runtime-matrix-runs.jsonl"
            external_rows = [
                json.loads(line) for line in external_raw_path.read_text(encoding="utf-8").splitlines() if line
            ]
            for index, row in enumerate(external_rows):
                if row["job_id"] == external_job["job_id"]:
                    external_rows[index] = external_job
                    break
            external_raw_path.write_text(
                "".join(json.dumps(row, sort_keys=True) + "\n" for row in external_rows),
                encoding="utf-8",
            )
            moved_matrix = root / "moved-matrix"
            original_open = RECEIPT.os.open
            swapped = False

            def open_with_read_swap(path: object, flags: int, mode: int = 0o777, *, dir_fd: int | None = None) -> int:
                nonlocal swapped
                if not swapped and Path(path).name == "full-runtime-matrix-runs.jsonl":
                    matrix_root.rename(moved_matrix)
                    matrix_root.symlink_to(external_matrix, target_is_directory=True)
                    swapped = True
                if dir_fd is None:
                    return original_open(path, flags, mode)
                return original_open(path, flags, mode, dir_fd=dir_fd)

            commands_path = build_root / "verified-runs" / run_id / "verified-commands.json"
            parent_command = json.loads(commands_path.read_text(encoding="utf-8"))["commands"][0]
            with mock.patch.object(RECEIPT.os, "open", side_effect=open_with_read_swap):
                with self.assertRaises(RECEIPT.AggregateReceiptError):
                    RECEIPT.build_full_matrix_aggregate_receipt(
                        build_root=build_root,
                        verified_run_id=run_id,
                        profile="full",
                        parent_command=parent_command,
                        revisions={"connector_sha": "a" * 40, "framework_sha": "b" * 40, "mrts_sha": "c" * 40},
                    )
            self.assertTrue(swapped)
            self.assertEqual(external_log.read_text(encoding="utf-8"), "external bytes must never be sealed\n")

    def test_oversized_structured_receipt_input_is_rejected_before_materialization(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _, build_root, run_id = self.build_valid_run(Path(temporary))
            raw_path = build_root / "full-matrix/full-runtime-matrix-runs.jsonl"
            raw_path.write_bytes(b" " * (RECEIPT.MAX_STRUCTURED_RECEIPT_BYTES + 1))
            commands_path = build_root / "verified-runs" / run_id / "verified-commands.json"
            parent_command = json.loads(commands_path.read_text(encoding="utf-8"))["commands"][0]
            with self.assertRaisesRegex(RECEIPT.AggregateReceiptError, "receipt limit"):
                RECEIPT.build_full_matrix_aggregate_receipt(
                    build_root=build_root,
                    verified_run_id=run_id,
                    profile="full",
                    parent_command=parent_command,
                    revisions={"connector_sha": "a" * 40, "framework_sha": "b" * 40, "mrts_sha": "c" * 40},
                )

    def test_verified_runs_publication_swap_fails_closed_without_external_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, build_root, run_id = self.build_valid_run(root)
            receipt_path = RECEIPT.aggregate_receipt_path(build_root, run_id)
            receipt_path.unlink()
            verified_runs = build_root / "verified-runs"
            moved_runs = root / "moved-verified-runs"
            external_runs = root / "external-verified-runs"
            (external_runs / run_id).mkdir(parents=True)
            sentinel = external_runs / "sentinel.txt"
            sentinel.write_text("must remain untouched\n", encoding="utf-8")
            original_open = RECEIPT.os.open
            swapped = False

            def open_with_publication_swap(path: object, flags: int, mode: int = 0o777, *, dir_fd: int | None = None) -> int:
                nonlocal swapped
                if not swapped and Path(path).name == RECEIPT.RECEIPT_FILENAME and flags & os.O_CREAT:
                    verified_runs.rename(moved_runs)
                    verified_runs.symlink_to(external_runs, target_is_directory=True)
                    swapped = True
                if dir_fd is None:
                    return original_open(path, flags, mode)
                return original_open(path, flags, mode, dir_fd=dir_fd)

            commands_path = verified_runs / run_id / "verified-commands.json"
            parent_command = json.loads(commands_path.read_text(encoding="utf-8"))["commands"][0]
            with mock.patch.object(RECEIPT.os, "open", side_effect=open_with_publication_swap):
                with self.assertRaises(RECEIPT.AggregateReceiptError):
                    RECEIPT.seal_full_matrix_aggregate_receipt(
                        build_root=build_root,
                        verified_run_id=run_id,
                        profile="full",
                        parent_command=parent_command,
                        revisions={"connector_sha": "a" * 40, "framework_sha": "b" * 40, "mrts_sha": "c" * 40},
                    )
            self.assertTrue(swapped)
            self.assertFalse((external_runs / run_id / RECEIPT.RECEIPT_FILENAME).exists())
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "must remain untouched\n")

    def test_runner_uses_sealed_descriptor_record_without_path_rehash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            connector_root, build_root, run_id = self.build_valid_run(Path(temporary))
            receipt_path = RECEIPT.aggregate_receipt_path(build_root, run_id)
            receipt_path.unlink()
            commands_path = build_root / "verified-runs" / run_id / "verified-commands.json"
            record = json.loads(commands_path.read_text(encoding="utf-8"))["commands"][0]
            revisions = {"connector_sha": "a" * 40, "framework_sha": "b" * 40, "mrts_sha": "c" * 40}
            with mock.patch.object(RUNNER, "full_matrix_receipt_revisions", return_value=revisions), mock.patch.object(
                RUNNER, "sha256_file", side_effect=AssertionError("aggregate receipt must not be reopened by pathname")
            ):
                self.assertTrue(
                    RUNNER.seal_full_matrix_receipt_for_record(
                        record=record,
                        connector_root=connector_root,
                        framework_root=connector_root / "framework",
                        build_root=build_root,
                        verified_run_id=run_id,
                        profile="full",
                    )
                )
                expected = dict(record["aggregate_receipt"])
                receipt_path.unlink()
                receipt_path.write_text("attacker replacement\n", encoding="utf-8")
                manifest_record = RUNNER.aggregate_receipt_manifest_record(
                    commands=[record],
                    build_root=build_root,
                    verified_run_id=run_id,
                )
            self.assertEqual(manifest_record["status"], "present")
            self.assertEqual(expected["sha256"], manifest_record["sha256"])
            self.assertEqual(expected["bytes"], manifest_record["bytes"])

    def test_aggregate_receipt_revision_binding_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            connector_root, build_root, _ = self.build_valid_run(Path(temporary))
            manifest_path = connector_root / "reports/testing/generated/manifest/verified-run-manifest.generated.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["connector_sha"] = "d" * 40
            write_json(manifest_path, manifest)
            self.assert_chain_rejected(connector_root, build_root, "revision binding")

    def test_incomplete_matrix_cannot_be_sealed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            connector_root, build_root, run_id = self.build_valid_run(Path(temporary))
            receipt_path = RECEIPT.aggregate_receipt_path(build_root, run_id)
            receipt_path.unlink()
            job_path = build_root / "full-matrix/no-crs/no-mrts/apache/job.json"
            job_path.unlink()
            commands_path = build_root / "verified-runs" / run_id / "verified-commands.json"
            parent_command = json.loads(commands_path.read_text(encoding="utf-8"))["commands"][0]
            with self.assertRaises(RECEIPT.AggregateReceiptError):
                RECEIPT.seal_full_matrix_aggregate_receipt(
                    build_root=build_root,
                    verified_run_id=run_id,
                    profile="full",
                    parent_command=parent_command,
                    revisions={"connector_sha": "a" * 40, "framework_sha": "b" * 40, "mrts_sha": "c" * 40},
                )
            self.assert_chain_rejected(connector_root, build_root, "aggregate receipt")

    def test_full_matrix_receipt_seals_only_once_after_completion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _, build_root, run_id = self.build_valid_run(Path(temporary))
            receipt_path = RECEIPT.aggregate_receipt_path(build_root, run_id)
            receipt_path.unlink()
            commands_path = build_root / "verified-runs" / run_id / "verified-commands.json"
            parent_command = json.loads(commands_path.read_text(encoding="utf-8"))["commands"][0]
            parent_command.update({"logical_target": "full-matrix-resume", "phase": "full-matrix-resume"})
            sealed_path = RECEIPT.seal_full_matrix_aggregate_receipt(
                build_root=build_root,
                verified_run_id=run_id,
                profile="full",
                parent_command=parent_command,
                revisions={"connector_sha": "a" * 40, "framework_sha": "b" * 40, "mrts_sha": "c" * 40},
            )
            self.assertEqual(receipt_path, sealed_path)
            self.assertEqual(stat.S_IRUSR, stat.S_IMODE(sealed_path.stat().st_mode))
            with self.assertRaises(RECEIPT.AggregateReceiptError):
                RECEIPT.seal_full_matrix_aggregate_receipt(
                    build_root=build_root,
                    verified_run_id=run_id,
                    profile="full",
                    parent_command=parent_command,
                    revisions={"connector_sha": "a" * 40, "framework_sha": "b" * 40, "mrts_sha": "c" * 40},
                )

    def test_completed_resume_is_accepted_after_an_incomplete_parallel_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            connector_root, build_root, run_id = self.build_valid_run(Path(temporary))
            receipt_path = RECEIPT.aggregate_receipt_path(build_root, run_id)
            receipt_path.unlink()
            commands_path = build_root / "verified-runs" / run_id / "verified-commands.json"
            commands = json.loads(commands_path.read_text(encoding="utf-8"))
            commands["commands"][0].update(
                {
                    "return_code": 1,
                    "classification": "failure",
                    "runtime_complete": False,
                    "runtime_status": "runtime_failed",
                    "started_at": "2026-07-17T00:00:00Z",
                    "finished_at": "2026-07-17T00:00:01Z",
                }
            )
            env = {
                "FULL_MATRIX_MANIFEST": str(build_root / "full-matrix/full-runtime-matrix-runs.jsonl"),
                "VERIFIED_RUN_ID": run_id,
            }
            # This is the same append path that main() takes before it runs a
            # new resume command.  Completed resume rows must not rewrite the
            # historic failed parallel attempt.
            commands["commands"] = RUNNER.normalize_existing_command_records(
                commands["commands"],
                env,
                "full",
            )
            self.assertFalse(commands["commands"][0]["runtime_complete"])
            self.assertEqual(commands["commands"][0]["runtime_status"], "runtime_failed")
            resumed = RUNNER.apply_command_semantics(
                {
                    "logical_target": "full-matrix-resume",
                    "phase": "full-matrix-resume",
                    "required": True,
                    "return_code": 0,
                    "classification": "success",
                    "started_at": "2026-07-18T02:00:00Z",
                    "finished_at": "2026-07-18T02:00:01Z",
                },
                env,
                "full",
            )
            self.assertTrue(resumed["runtime_complete"])
            commands["commands"].append(resumed)
            completed = [
                command
                for command in commands["commands"]
                if command.get("runtime_complete") is True
                and command.get("runtime_status") in {"runtime_completed", "runtime_completed_with_mismatches"}
            ]
            self.assertEqual(len(completed), 1)
            write_json(commands_path, commands)
            receipt_path = RECEIPT.seal_full_matrix_aggregate_receipt(
                build_root=build_root,
                verified_run_id=run_id,
                profile="full",
                parent_command=resumed,
                revisions={"connector_sha": "a" * 40, "framework_sha": "b" * 40, "mrts_sha": "c" * 40},
            )
            manifest_path = connector_root / "reports/testing/generated/manifest/verified-run-manifest.generated.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["command_file"].update({"sha256": sha256(commands_path), "bytes": commands_path.stat().st_size})
            manifest["full_matrix_aggregate_receipt"].update(
                {"sha256": sha256(receipt_path), "bytes": receipt_path.stat().st_size}
            )
            write_json(manifest_path, manifest)
            errors: list[str] = []
            CHECKER.check_verified_runtime_artifact_chain(connector_root, errors, build_root=build_root)
        self.assertEqual(errors, [])

    def test_redundant_resume_is_not_a_second_required_full_matrix_producer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            connector_root, build_root, run_id = self.build_valid_run(Path(temporary))
            commands_path = build_root / "verified-runs" / run_id / "verified-commands.json"
            commands = json.loads(commands_path.read_text(encoding="utf-8"))
            redundant_resume = {
                **commands["commands"][0],
                "logical_target": "full-matrix-resume",
                "phase": "full-matrix-resume",
                "required": False,
                "optional": True,
                "return_code": 77,
                "runtime_complete": False,
                "runtime_status": "runtime_not_required",
            }
            commands["commands"].append(redundant_resume)
            write_json(commands_path, commands)
            manifest_path = connector_root / "reports/testing/generated/manifest/verified-run-manifest.generated.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["command_file"].update({"sha256": sha256(commands_path), "bytes": commands_path.stat().st_size})
            write_json(manifest_path, manifest)
            errors: list[str] = []
            CHECKER.check_verified_runtime_artifact_chain(
                connector_root,
                errors,
                build_root=build_root,
            )
        self.assertTrue(RUNNER.has_completed_full_matrix_producer(commands["commands"]))
        self.assertFalse(RUNNER.qualifies_for_full_matrix_receipt(redundant_resume, "full"))
        self.assertEqual(errors, [])

    def test_resume_completion_uses_all_and_only_current_run_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _, build_root, run_id = self.build_valid_run(Path(temporary))
            raw_path = build_root / "full-matrix/full-runtime-matrix-runs.jsonl"
            record = {"started_at": "2026-07-18T01:00:00Z", "return_code": 0}
            env = {"FULL_MATRIX_MANIFEST": str(raw_path), "VERIFIED_RUN_ID": run_id}
            initial_state = RUNNER.full_matrix_runtime_state(record, env, "full")
            resumed_state = RUNNER.full_matrix_runtime_state(
                record,
                env,
                "full",
                include_existing_run_rows=True,
            )
            self.assertFalse(initial_state["runtime_complete"])
            self.assertTrue(resumed_state["runtime_complete"])
            rows = [json.loads(line) for line in raw_path.read_text(encoding="utf-8").splitlines() if line]
            rows[0]["verified_run_id"] = "foreign-run"
            raw_path.write_text(
                "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
                encoding="utf-8",
            )
            foreign_state = RUNNER.full_matrix_runtime_state(
                record,
                env,
                "full",
                include_existing_run_rows=True,
            )
            self.assertFalse(foreign_state["runtime_complete"])

    def test_parent_runner_seals_only_a_qualified_full_matrix_record(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            connector_root, build_root, run_id = self.build_valid_run(Path(temporary))
            receipt_path = RECEIPT.aggregate_receipt_path(build_root, run_id)
            receipt_path.unlink()
            commands_path = build_root / "verified-runs" / run_id / "verified-commands.json"
            record = json.loads(commands_path.read_text(encoding="utf-8"))["commands"][0]
            revisions = {"connector_sha": "a" * 40, "framework_sha": "b" * 40, "mrts_sha": "c" * 40}
            self.assertTrue(RUNNER.qualifies_for_full_matrix_receipt(record, "full"))
            self.assertFalse(RUNNER.qualifies_for_full_matrix_receipt(record, "smoke"))
            with mock.patch.object(RUNNER, "full_matrix_receipt_revisions", return_value=revisions):
                self.assertTrue(
                    RUNNER.seal_full_matrix_receipt_for_record(
                        record=record,
                        connector_root=connector_root,
                        framework_root=connector_root / "framework",
                        build_root=build_root,
                        verified_run_id=run_id,
                        profile="full",
                    )
                )
            self.assertEqual(record["aggregate_receipt"]["status"], "sealed")
            self.assertTrue(receipt_path.is_file())

    def test_sealed_manifest_rewrite_must_be_byte_identical(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _, build_root, run_id = self.build_valid_run(Path(temporary))
            matrix_root = build_root / "full-matrix"
            raw_path = matrix_root / "full-runtime-matrix-runs.jsonl"
            receipt_path = RECEIPT.aggregate_receipt_path(build_root, run_id)
            original = raw_path.read_text(encoding="utf-8")
            jobs = GENERATOR.collect_jobs(matrix_root, raw_path)
            GENERATOR.rewrite_manifest(raw_path, jobs, sealed_receipt_path=receipt_path)
            self.assertEqual(original, raw_path.read_text(encoding="utf-8"))
            job_path = matrix_root / "no-crs/no-mrts/apache/job.json"
            job = json.loads(job_path.read_text(encoding="utf-8"))
            job["return_code"] = 1
            write_json(job_path, job)
            updated_jobs = GENERATOR.collect_jobs(matrix_root, raw_path)
            with self.assertRaisesRegex(ValueError, "sealed full-matrix manifest"):
                GENERATOR.rewrite_manifest(
                    raw_path,
                    updated_jobs,
                    sealed_receipt_path=receipt_path,
                )

    def test_generator_cannot_select_a_foreign_run_to_rewrite_a_sealed_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            connector_root, build_root, run_id = self.build_valid_run(root)
            raw_path = build_root / "full-matrix/full-runtime-matrix-runs.jsonl"
            receipt_path = RECEIPT.aggregate_receipt_path(build_root, run_id)
            raw_before = raw_path.read_bytes()
            receipt_before = receipt_path.read_bytes()
            job_path = build_root / "full-matrix/no-crs/no-mrts/apache/job.json"
            job = json.loads(job_path.read_text(encoding="utf-8"))
            job["return_code"] = 1
            write_json(job_path, job)
            argv = [
                "generate-full-matrix-job-completeness.py",
                "--connector-root",
                str(connector_root),
                "--build-root",
                str(build_root),
                "--output-dir",
                str(root / "generated"),
                "--verified-run-id",
                "foreign-run",
                "--rewrite-manifest",
            ]
            with mock.patch.object(sys, "argv", argv), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    GENERATOR.main()
            self.assertEqual(raised.exception.code, 2)
            self.assertEqual(raw_before, raw_path.read_bytes())
            self.assertEqual(receipt_before, receipt_path.read_bytes())

    def test_manifest_writer_cannot_mint_an_aggregate_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            connector_root = root / "connector"
            build_root = root / "build"
            build_root.mkdir(parents=True)
            run_id = "verified-run-20260718"
            commands_path = build_root / "verified-runs" / run_id / "verified-commands.json"
            write_json(commands_path, {"verified_run_id": run_id, "commands": []})
            RUNNER.write_verified_manifest(
                connector_root=connector_root,
                framework_root=connector_root / "framework",
                build_root=build_root,
                verified_run_id=run_id,
                started_at="2026-07-18T00:00:00Z",
                finished_at="2026-07-18T00:00:01Z",
                commands=[],
                commands_file=commands_path,
                env={},
                profile="full",
                full_matrix_timeout=1,
                timeout_budgets={},
            )
            self.assertFalse(RECEIPT.aggregate_receipt_path(build_root, run_id).exists())

    def test_aggregate_receipt_has_no_self_reference(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _, build_root, run_id = self.build_valid_run(Path(temporary))
            receipt_path = RECEIPT.aggregate_receipt_path(build_root, run_id)
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertNotIn(RECEIPT.RECEIPT_FILENAME, json.dumps(receipt, sort_keys=True))

    def test_report_without_runtime_manifest_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            connector_root, build_root, _ = self.build_valid_run(Path(temporary))
            (build_root / "full-matrix" / "full-runtime-matrix-runs.jsonl").unlink()
            self.assert_chain_rejected(connector_root, build_root, "file is unavailable")

    def test_tampered_result_file_checksum_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            connector_root, build_root, _ = self.build_valid_run(Path(temporary))
            results = build_root / "full-matrix/no-crs/no-mrts/apache/results/force-all/apache-results.jsonl"
            results.write_text('{"connector":"apache","status":"pass"}\nforged\n', encoding="utf-8")
            self.assert_chain_rejected(connector_root, build_root, "results_jsonl hash mismatch")

    def test_incomplete_run_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            connector_root, build_root, _ = self.build_valid_run(Path(temporary))
            job_path = build_root / "full-matrix/no-crs/no-mrts/apache/job.json"
            job = json.loads(job_path.read_text(encoding="utf-8"))
            job.pop("ended_at")
            write_json(job_path, job)
            self.assert_chain_rejected(connector_root, build_root, "ended_at is missing or invalid")

    def test_foreign_run_id_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            connector_root, build_root, _ = self.build_valid_run(Path(temporary))
            job_path = build_root / "full-matrix/no-crs/no-mrts/apache/job.json"
            job = json.loads(job_path.read_text(encoding="utf-8"))
            job["verified_run_id"] = "foreign-run"
            write_json(job_path, job)
            self.assert_chain_rejected(connector_root, build_root, "verified_run_id")

    def test_copied_connector_result_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            connector_root, build_root, _ = self.build_valid_run(Path(temporary))
            job_path = build_root / "full-matrix/no-crs/no-mrts/apache/job.json"
            job = json.loads(job_path.read_text(encoding="utf-8"))
            job["connector"] = "nginx"
            write_json(job_path, job)
            self.assert_chain_rejected(connector_root, build_root, "connector mismatch")

    def test_copied_profile_result_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            connector_root, build_root, _ = self.build_valid_run(Path(temporary))
            job_path = build_root / "full-matrix/no-crs/no-mrts/apache/job.json"
            job = json.loads(job_path.read_text(encoding="utf-8"))
            job["test_variant"] = "with-crs"
            write_json(job_path, job)
            self.assert_chain_rejected(connector_root, build_root, "test_variant mismatch")

    def test_path_escape_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            connector_root, build_root, _ = self.build_valid_run(root)
            job_path = build_root / "full-matrix/no-crs/no-mrts/apache/job.json"
            job = json.loads(job_path.read_text(encoding="utf-8"))
            escaped = root / "escaped-summary.json"
            write_json(escaped, {"apache": {"cases": {"control": {"status": "pass"}}}})
            job["summary_path"] = str(escaped)
            job["outputs"]["summary"] = str(escaped)
            job["hashes"]["summary"] = sha256(escaped)
            write_json(job_path, job)
            self.assert_chain_rejected(connector_root, build_root, "summary_path is not canonical")

    def test_direct_summary_path_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            connector_root, build_root, _ = self.build_valid_run(root)
            job_path = build_root / "full-matrix/no-crs/no-mrts/apache/job.json"
            direct_summary_path = job_path.parent / "results/apache-summary.json"
            write_json(direct_summary_path, {"apache": {"cases": {"direct": {"status": "pass"}}}})
            job = self.raw_matrix_job("apache:no-crs:no-mrts")
            job["summary_path"] = str(direct_summary_path)
            job["outputs"]["summary"] = str(direct_summary_path)
            job["hashes"]["summary"] = sha256(direct_summary_path)
            write_json(job_path, job)
            replace_raw_matrix_job(
                self.raw_matrix_rows,
                build_root / "full-matrix/full-runtime-matrix-runs.jsonl",
                job,
            )
            self.reseal_aggregate_receipt(connector_root, build_root, "verified-run-20260718")
            errors: list[str] = []
            CHECKER.check_verified_runtime_artifact_chain(
                connector_root,
                errors,
                build_root=build_root,
            )
        self.assertEqual(errors, [])

    def test_force_all_summary_is_selected_when_direct_summary_exists(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            connector_root, build_root, _ = self.build_valid_run(root)
            direct_summary_path = build_root / "full-matrix/no-crs/no-mrts/apache/results/apache-summary.json"
            write_json(direct_summary_path, {"apache": {"cases": {}}})
            errors: list[str] = []
            CHECKER.check_verified_runtime_artifact_chain(
                connector_root,
                errors,
                build_root=build_root,
            )
        self.assertEqual(errors, [])

    def test_summary_hash_mismatch_is_rejected_for_each_canonical_path(self) -> None:
        for location in ("direct", "force-all"):
            with self.subTest(location=location), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                connector_root, build_root, _ = self.build_valid_run(root)
                job_path = build_root / "full-matrix/no-crs/no-mrts/apache/job.json"
                job = self.raw_matrix_job("apache:no-crs:no-mrts")
                if location == "direct":
                    direct_summary_path = job_path.parent / "results/apache-summary.json"
                    write_json(direct_summary_path, {"apache": {"cases": {"direct": {"status": "pass"}}}})
                    job["summary_path"] = str(direct_summary_path)
                    job["outputs"]["summary"] = str(direct_summary_path)
                job["hashes"]["summary"] = "a" * 64
                write_json(job_path, job)
                replace_raw_matrix_job(
                    self.raw_matrix_rows,
                    build_root / "full-matrix/full-runtime-matrix-runs.jsonl",
                    job,
                )
                self.assert_chain_rejected(connector_root, build_root, "summary hash mismatch")

    def test_symlinked_result_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            connector_root, build_root, _ = self.build_valid_run(root)
            results_dir = build_root / "full-matrix/no-crs/no-mrts/apache/results"
            escaped_results = root / "escaped-results"
            results_dir.rename(escaped_results)
            results_dir.symlink_to(escaped_results, target_is_directory=True)
            self.assert_chain_rejected(connector_root, build_root, "directory is unavailable or unsafe")

    def test_intermediate_full_matrix_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            connector_root, build_root, _ = self.build_valid_run(root)
            matrix_root = build_root / "full-matrix"
            escaped_matrix = root / "escaped-matrix"
            matrix_root.rename(escaped_matrix)
            matrix_root.symlink_to(escaped_matrix, target_is_directory=True)
            self.assert_chain_rejected(connector_root, build_root, "directory is unavailable or unsafe")

    def test_intermediate_verified_runs_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            connector_root, build_root, _ = self.build_valid_run(root)
            verified_runs = build_root / "verified-runs"
            escaped_runs = root / "escaped-verified-runs"
            verified_runs.rename(escaped_runs)
            verified_runs.symlink_to(escaped_runs, target_is_directory=True)
            self.assert_chain_rejected(connector_root, build_root, "verified command receipt is missing or unsafe")

    def test_critical_missing_report_input_is_rejected_in_strict_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            connector_root = Path(temporary)
            refresh_manifest = {
                "reports": [
                    {
                        "report_name": "full_runtime_matrix",
                        "status": "generated",
                        "output_files": [],
                        "category": "runtime",
                        "kind": "report",
                        "owner": "parent",
                        "severity": "critical",
                        "input_status": "missing",
                        "inputs": [],
                        "missing_inputs": ["full-runtime-matrix-runs.jsonl"],
                        "empty_inputs": [],
                        "unknown_inputs": [],
                        "stale_inputs": [],
                    }
                ]
            }
            write_json(
                connector_root / "reports/testing/generated/manifest/report-refresh-manifest.generated.json",
                refresh_manifest,
            )
            errors: list[str] = []
            CHECKER.check_manifest(connector_root, errors, strict_evidence=True)
        self.assertTrue(any("has missing input_status" in error for error in errors), errors)

    def test_critical_unrecognized_report_input_status_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            connector_root = Path(temporary)
            refresh_manifest = {
                "reports": [
                    {
                        "report_name": "full_runtime_matrix",
                        "status": "generated",
                        "output_files": [],
                        "category": "runtime",
                        "kind": "report",
                        "owner": "parent",
                        "severity": "critical",
                        "input_status": "forged-success",
                        "inputs": [],
                        "missing_inputs": [],
                        "empty_inputs": [],
                        "unknown_inputs": [],
                        "stale_inputs": [],
                    }
                ]
            }
            write_json(
                connector_root / "reports/testing/generated/manifest/report-refresh-manifest.generated.json",
                refresh_manifest,
            )
            errors: list[str] = []
            CHECKER.check_manifest(connector_root, errors, strict_evidence=True)
        self.assertTrue(any("forged-success input_status" in error for error in errors), errors)

    def test_critical_manifest_unrecognized_input_record_status_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            connector_root = Path(temporary)
            refresh_manifest = {
                "reports": [
                    {
                        "report_name": "full_runtime_matrix",
                        "status": "generated",
                        "output_files": [],
                        "category": "runtime",
                        "kind": "report",
                        "owner": "parent",
                        "severity": "critical",
                        "input_status": "complete",
                        "inputs": [{"path": "forged.json", "status": "forged-success"}],
                        "missing_inputs": [],
                        "empty_inputs": [],
                        "unknown_inputs": [],
                        "stale_inputs": [],
                    }
                ]
            }
            write_json(
                connector_root / "reports/testing/generated/manifest/report-refresh-manifest.generated.json",
                refresh_manifest,
            )
            errors: list[str] = []
            CHECKER.check_manifest(connector_root, errors, strict_evidence=True)
        self.assertTrue(any("critical report input is forged-success" in error for error in errors), errors)

    def test_critical_manifest_present_input_record_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            connector_root = Path(temporary)
            input_path = connector_root / "runtime.json"
            write_json(input_path, {"runtime": "receipt"})
            refresh_manifest = {
                "reports": [
                    {
                        "report_name": "full_runtime_matrix",
                        "status": "generated",
                        "output_files": [],
                        "category": "runtime",
                        "kind": "report",
                        "owner": "parent",
                        "severity": "critical",
                        "input_status": "complete",
                        "inputs": [{"path": "runtime.json", "status": "present", "sha256": sha256(input_path)}],
                        "missing_inputs": [],
                        "empty_inputs": [],
                        "unknown_inputs": [],
                        "stale_inputs": [],
                    }
                ]
            }
            write_json(
                connector_root / "reports/testing/generated/manifest/report-refresh-manifest.generated.json",
                refresh_manifest,
            )
            errors: list[str] = []
            CHECKER.check_manifest(connector_root, errors, strict_evidence=True)
        self.assertEqual(errors, [])

    def test_critical_manifest_present_build_root_input_record_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            connector_root = root / "connector"
            build_root = root / "build"
            input_path = build_root / "runtime-receipt.json"
            write_json(input_path, {"runtime": "receipt"})
            refresh_manifest = {
                "reports": [
                    {
                        "report_name": "full_runtime_matrix",
                        "status": "generated",
                        "output_files": [],
                        "category": "runtime",
                        "kind": "report",
                        "owner": "parent",
                        "severity": "critical",
                        "input_status": "complete",
                        "inputs": [
                            {
                                "path": "BUILD_ROOT:runtime-receipt.json",
                                "status": "present",
                                "sha256": sha256(input_path),
                            }
                        ],
                        "missing_inputs": [],
                        "empty_inputs": [],
                        "unknown_inputs": [],
                        "stale_inputs": [],
                    }
                ]
            }
            write_json(
                connector_root / "reports/testing/generated/manifest/report-refresh-manifest.generated.json",
                refresh_manifest,
            )
            errors: list[str] = []
            CHECKER.check_manifest(connector_root, errors, strict_evidence=True, build_root=build_root)
        self.assertEqual(errors, [])

    def test_german_generated_markdown_metadata_is_checked(self) -> None:
        valid_german_report = (
            "> Generierte Datei – nicht manuell bearbeiten.\n"
            "> Erstellt unter: `2026-07-21T00:00:00Z`\n"
            "> Verifizierte Lauf-ID: `verified-run-20260721`\n"
            "> Datenquellenrichtlinie: `verified-inputs-only`\n\n"
            "# Generierter Bericht\n\n"
            "## Datenquellen\n\n"
            "## Datenverfügbarkeit / fehlende Informationen\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            connector_root = Path(temporary)
            report = connector_root / "reports/testing/generated/runtime/example.generated.de.md"
            report.parent.mkdir(parents=True)
            report.write_text(valid_german_report, encoding="utf-8")
            errors: list[str] = []
            CHECKER.check_existing_generated_reports(connector_root, errors)
            self.assertEqual(errors, [])

            report.write_text(valid_german_report.removeprefix("> Generierte Datei – nicht manuell bearbeiten.\n"), encoding="utf-8")
            errors = []
            CHECKER.check_existing_generated_reports(connector_root, errors)
        self.assertTrue(any("missing generated notice at top" in error for error in errors), errors)

    def test_english_generated_markdown_keeps_the_canonical_first_line_notice(self) -> None:
        valid_english_report = (
            f"> {CHECKER.GENERATED_NOTICE}\n"
            "> Generated at: `2026-07-21T00:00:00Z`\n"
            "> Verified run id: `verified-run-20260721`\n"
            "> Data source policy: `verified-inputs-only`\n\n"
            "# Generated Report\n\n"
            "## Data Sources\n\n"
            "## Data Availability / Missing Information\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            connector_root = Path(temporary)
            report = connector_root / "reports/testing/generated/runtime/example.generated.md"
            report.parent.mkdir(parents=True)
            report.write_text(valid_english_report, encoding="utf-8")
            errors: list[str] = []
            CHECKER.check_existing_generated_reports(connector_root, errors)
            self.assertEqual(errors, [])

            report.write_text("**Language:** English\n\n" + valid_english_report, encoding="utf-8")
            errors = []
            CHECKER.check_existing_generated_reports(connector_root, errors)
        self.assertTrue(any("missing generated notice at top" in error for error in errors), errors)

    def test_registry_requires_the_german_generated_markdown_companion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            connector_root = Path(temporary)
            report = CHECKER.GENERATED_REPORTS["runtime_matrix"]
            english = CHECKER.report_path(connector_root, "runtime_matrix", "md")
            english.parent.mkdir(parents=True)
            english.write_text("generated\n", encoding="utf-8")
            with mock.patch.object(CHECKER, "GENERATED_REPORTS", {"runtime_matrix": report}):
                errors: list[str] = []
                CHECKER.check_registry_paths(connector_root, errors)
                self.assertTrue(any("runtime-matrix.generated.de.md: registry output missing" in error for error in errors), errors)

                CHECKER.german_generated_markdown_path(english).write_text("generated\n", encoding="utf-8")
                errors = []
                CHECKER.check_registry_paths(connector_root, errors)
        self.assertEqual(errors, [])

    def test_orphan_german_generated_report_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            connector_root = Path(temporary)
            orphan = connector_root / "reports/testing/generated/runtime/unregistered.generated.de.md"
            orphan.parent.mkdir(parents=True)
            orphan.write_text("generated\n", encoding="utf-8")
            errors: list[str] = []
            CHECKER.check_no_orphan_generated_reports(connector_root, errors)
        self.assertTrue(any("unregistered.generated.de.md: generated file is not in registry" in error for error in errors), errors)

    def test_critical_manifest_parent_traversal_receipts_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            connector_root = root / "connector"
            build_root = root / "build"
            framework_root = root / "framework"
            external_input = root / "outside-runtime.json"
            connector_root.mkdir()
            build_root.mkdir()
            framework_root.mkdir()
            write_json(external_input, {"runtime": "outside trusted roots"})
            for input_reference in (
                "BUILD_ROOT:../outside-runtime.json",
                "framework:../outside-runtime.json",
                "../outside-runtime.json",
            ):
                with self.subTest(input_reference=input_reference):
                    refresh_manifest = {
                        "reports": [
                            {
                                "report_name": "full_runtime_matrix",
                                "status": "generated",
                                "output_files": [],
                                "category": "runtime",
                                "kind": "report",
                                "owner": "parent",
                                "severity": "critical",
                                "input_status": "complete",
                                "inputs": [
                                    {
                                        "path": input_reference,
                                        "status": "present",
                                        "sha256": sha256(external_input),
                                    }
                                ],
                                "missing_inputs": [],
                                "empty_inputs": [],
                                "unknown_inputs": [],
                                "stale_inputs": [],
                            }
                        ]
                    }
                    write_json(
                        connector_root / "reports/testing/generated/manifest/report-refresh-manifest.generated.json",
                        refresh_manifest,
                    )
                    errors: list[str] = []
                    CHECKER.check_manifest(
                        connector_root,
                        errors,
                        strict_evidence=True,
                        build_root=build_root,
                        framework_root=framework_root,
                    )
                    self.assertTrue(
                        any("input is not a trusted regular file" in error for error in errors),
                        errors,
                    )

    def test_critical_manifest_present_input_hash_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            connector_root = Path(temporary)
            input_path = connector_root / "runtime.json"
            write_json(input_path, {"runtime": "original receipt"})
            declared_hash = sha256(input_path)
            write_json(input_path, {"runtime": "substituted receipt"})
            refresh_manifest = {
                "reports": [
                    {
                        "report_name": "full_runtime_matrix",
                        "status": "generated",
                        "output_files": [],
                        "category": "runtime",
                        "kind": "report",
                        "owner": "parent",
                        "severity": "critical",
                        "input_status": "complete",
                        "inputs": [{"path": "runtime.json", "status": "present", "sha256": declared_hash}],
                        "missing_inputs": [],
                        "empty_inputs": [],
                        "unknown_inputs": [],
                        "stale_inputs": [],
                    }
                ]
            }
            write_json(
                connector_root / "reports/testing/generated/manifest/report-refresh-manifest.generated.json",
                refresh_manifest,
            )
            errors: list[str] = []
            CHECKER.check_manifest(connector_root, errors, strict_evidence=True)
        self.assertTrue(any("critical report input hash mismatch: runtime.json" in error for error in errors), errors)

    def test_critical_manifest_missing_present_input_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            connector_root = Path(temporary)
            refresh_manifest = {
                "reports": [
                    {
                        "report_name": "full_runtime_matrix",
                        "status": "generated",
                        "output_files": [],
                        "category": "runtime",
                        "kind": "report",
                        "owner": "parent",
                        "severity": "critical",
                        "input_status": "complete",
                        "inputs": [{"path": "missing-runtime.json", "status": "present", "sha256": "a" * 64}],
                        "missing_inputs": [],
                        "empty_inputs": [],
                        "unknown_inputs": [],
                        "stale_inputs": [],
                    }
                ]
            }
            write_json(
                connector_root / "reports/testing/generated/manifest/report-refresh-manifest.generated.json",
                refresh_manifest,
            )
            errors: list[str] = []
            CHECKER.check_manifest(connector_root, errors, strict_evidence=True)
        self.assertTrue(any("input is not a trusted regular file" in error for error in errors), errors)

    def test_critical_manifest_empty_input_receipts_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            connector_root = Path(temporary)
            refresh_manifest = {
                "reports": [
                    {
                        "report_name": "full_runtime_matrix",
                        "status": "generated",
                        "output_files": [],
                        "category": "runtime",
                        "kind": "report",
                        "owner": "parent",
                        "severity": "critical",
                        "input_status": "complete",
                        "inputs": [],
                        "missing_inputs": [],
                        "empty_inputs": [],
                        "unknown_inputs": [],
                        "stale_inputs": [],
                    }
                ]
            }
            write_json(
                connector_root / "reports/testing/generated/manifest/report-refresh-manifest.generated.json",
                refresh_manifest,
            )
            errors: list[str] = []
            CHECKER.check_manifest(connector_root, errors, strict_evidence=True)
        self.assertTrue(any("has no direct input receipts" in error for error in errors), errors)

    def test_critical_manifest_symlinked_input_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            connector_root = Path(temporary) / "connector"
            external_input = Path(temporary) / "external-runtime.json"
            write_json(external_input, {"runtime": "receipt"})
            connector_root.mkdir(parents=True)
            (connector_root / "runtime.json").symlink_to(external_input)
            refresh_manifest = {
                "reports": [
                    {
                        "report_name": "full_runtime_matrix",
                        "status": "generated",
                        "output_files": [],
                        "category": "runtime",
                        "kind": "report",
                        "owner": "parent",
                        "severity": "critical",
                        "input_status": "complete",
                        "inputs": [{"path": "runtime.json", "status": "present", "sha256": sha256(external_input)}],
                        "missing_inputs": [],
                        "empty_inputs": [],
                        "unknown_inputs": [],
                        "stale_inputs": [],
                    }
                ]
            }
            write_json(
                connector_root / "reports/testing/generated/manifest/report-refresh-manifest.generated.json",
                refresh_manifest,
            )
            errors: list[str] = []
            CHECKER.check_manifest(connector_root, errors, strict_evidence=True)
        self.assertTrue(any("input is not a trusted regular file" in error for error in errors), errors)

    def test_critical_manifest_non_list_inputs_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            connector_root = Path(temporary)
            refresh_manifest = {
                "reports": [
                    {
                        "report_name": "full_runtime_matrix",
                        "status": "generated",
                        "output_files": [],
                        "category": "runtime",
                        "kind": "report",
                        "owner": "parent",
                        "severity": "critical",
                        "input_status": "complete",
                        "inputs": {"path": "forged.json", "status": "forged-success"},
                        "missing_inputs": [],
                        "empty_inputs": [],
                        "unknown_inputs": [],
                        "stale_inputs": [],
                    }
                ]
            }
            write_json(
                connector_root / "reports/testing/generated/manifest/report-refresh-manifest.generated.json",
                refresh_manifest,
            )
            errors: list[str] = []
            CHECKER.check_manifest(connector_root, errors, strict_evidence=True)
        self.assertTrue(any("inputs must be a list" in error for error in errors), errors)

    def test_critical_manifest_non_list_aggregate_input_array_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            connector_root = Path(temporary)
            refresh_manifest = {
                "reports": [
                    {
                        "report_name": "full_runtime_matrix",
                        "status": "generated",
                        "output_files": [],
                        "category": "runtime",
                        "kind": "report",
                        "owner": "parent",
                        "severity": "critical",
                        "input_status": "complete",
                        "inputs": [],
                        "missing_inputs": {"forged": True},
                        "empty_inputs": [],
                        "unknown_inputs": [],
                        "stale_inputs": [],
                    }
                ]
            }
            write_json(
                connector_root / "reports/testing/generated/manifest/report-refresh-manifest.generated.json",
                refresh_manifest,
            )
            errors: list[str] = []
            CHECKER.check_manifest(connector_root, errors, strict_evidence=True)
        self.assertTrue(any("missing_inputs must be a list" in error for error in errors), errors)

    def test_critical_metadata_unrecognized_input_status_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            connector_root = Path(temporary)
            report_path = CHECKER.report_path(connector_root, "full_runtime_matrix", "json")
            write_json(
                report_path,
                {
                    "metadata": {
                        "verified_run_id": "verified-run-20260718",
                        "connector_sha": "a" * 40,
                        "framework_sha": "b" * 40,
                        "input_status": "forged-success",
                        "inputs": [],
                    }
                },
            )
            errors: list[str] = []
            CHECKER.check_critical_report_run_consistency(connector_root, errors, strict_evidence=True)
        self.assertTrue(any("metadata.input_status is forged-success" in error for error in errors), errors)

    def test_critical_metadata_unrecognized_input_record_status_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            connector_root = Path(temporary)
            report_path = CHECKER.report_path(connector_root, "full_runtime_matrix", "json")
            write_json(
                report_path,
                {
                    "metadata": {
                        "verified_run_id": "verified-run-20260718",
                        "connector_sha": "a" * 40,
                        "framework_sha": "b" * 40,
                        "input_status": "complete",
                        "inputs": [{"path": "runtime-receipt.json", "status": "forged-success"}],
                    }
                },
            )
            errors: list[str] = []
            CHECKER.check_critical_report_run_consistency(connector_root, errors, strict_evidence=True)
        self.assertTrue(any("critical report input is forged-success" in error for error in errors), errors)

    def test_critical_metadata_present_input_record_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            connector_root = Path(temporary)
            input_path = connector_root / "runtime-receipt.json"
            write_json(input_path, {"runtime": "receipt"})
            report_path = CHECKER.report_path(connector_root, "full_runtime_matrix", "json")
            write_json(
                report_path,
                {
                    "metadata": {
                        "verified_run_id": "verified-run-20260718",
                        "connector_sha": "a" * 40,
                        "framework_sha": "b" * 40,
                        "input_status": "complete",
                        "inputs": [{"path": "runtime-receipt.json", "status": "present", "sha256": sha256(input_path)}],
                    }
                },
            )
            errors: list[str] = []
            CHECKER.check_critical_report_run_consistency(connector_root, errors, strict_evidence=True)
        self.assertEqual(errors, [])

    def test_critical_metadata_input_hash_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            connector_root = Path(temporary)
            input_path = connector_root / "runtime-receipt.json"
            write_json(input_path, {"runtime": "receipt"})
            report_path = CHECKER.report_path(connector_root, "full_runtime_matrix", "json")
            write_json(
                report_path,
                {
                    "metadata": {
                        "verified_run_id": "verified-run-20260718",
                        "connector_sha": "a" * 40,
                        "framework_sha": "b" * 40,
                        "input_status": "complete",
                        "inputs": [{"path": "runtime-receipt.json", "status": "present", "sha256": "a" * 64}],
                    }
                },
            )
            errors: list[str] = []
            CHECKER.check_critical_report_run_consistency(connector_root, errors, strict_evidence=True)
        self.assertTrue(any("input hash mismatch" in error for error in errors), errors)

    def test_critical_metadata_non_list_inputs_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            connector_root = Path(temporary)
            report_path = CHECKER.report_path(connector_root, "full_runtime_matrix", "json")
            write_json(
                report_path,
                {
                    "metadata": {
                        "verified_run_id": "verified-run-20260718",
                        "connector_sha": "a" * 40,
                        "framework_sha": "b" * 40,
                        "input_status": "complete",
                        "inputs": {"path": "forged.json", "status": "forged-success"},
                    }
                },
            )
            errors: list[str] = []
            CHECKER.check_critical_report_run_consistency(connector_root, errors, strict_evidence=True)
        self.assertTrue(any("critical report metadata: inputs must be a list" in error for error in errors), errors)

    def test_self_generated_refresh_status_is_the_only_non_complete_exception(self) -> None:
        self.assertFalse(
            CHECKER.is_unverified_critical_input_status(
                "self_generated_no_direct_input",
                report_name="report_refresh_manifest",
            )
        )
        self.assertTrue(
            CHECKER.is_unverified_critical_input_status(
                "self_generated_no_direct_input",
                report_name="full_runtime_matrix",
            )
        )

    def test_full_matrix_job_counts_prefer_summary_and_fall_back_to_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            summary_path = root / "apache-summary.json"
            jsonl_path = root / "apache-results.jsonl"
            write_json(summary_path, {"apache": {"attempted": 1, "cases": {"control": {"status": "pass"}}}})
            jsonl_path.write_text(json.dumps({"status": "fail"}) + "\n", encoding="utf-8")
            summary_counts, selected_summary = GENERATOR.job_case_counts(summary_path, jsonl_path, "apache")
            summary_path.unlink()
            jsonl_counts, selected_jsonl = GENERATOR.job_case_counts(summary_path, jsonl_path, "apache")

        self.assertEqual(summary_path, selected_summary)
        self.assertEqual(summary_counts["source"], "summary_json")
        self.assertEqual(jsonl_path, selected_jsonl)
        self.assertEqual(jsonl_counts["source"], "results_jsonl")

    def test_summary_selector_rejects_external_override(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            job_root = root / "job"
            external = root / "external-summary.json"
            job_root.mkdir()
            write_json(external, {"apache": {"cases": {"external": {"status": "pass"}}}})
            (job_root / "summary.path").write_text(str(external), encoding="utf-8")

            selected = GENERATOR.summary_path(job_root, "apache")

        self.assertEqual(
            selected,
            job_root / "results" / "apache-summary.json",
        )

    def test_summary_selector_rejects_traversal_override(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            job_root = root / "job"
            job_root.mkdir()
            (job_root / "summary.path").write_text("../../outside.json", encoding="utf-8")

            selected = GENERATOR.summary_path(job_root, "apache")

        self.assertEqual(
            selected,
            job_root / "results" / "apache-summary.json",
        )

    def test_summary_selector_keeps_canonical_direct_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            job_root = root / "job"
            direct = job_root / "results" / "apache-summary.json"
            write_json(direct, {"apache": {"cases": {"control": {"status": "pass"}}}})

            selected = GENERATOR.summary_path(job_root, "apache")

        self.assertEqual(selected, direct)

    def test_rewritten_raw_manifest_preserves_identity_and_artifact_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest_path = Path(temporary) / "full-runtime-matrix-runs.jsonl"
            job = {
                "connector": "apache",
                "job_id": "apache:no-crs:no-mrts",
                "verified_run_id": "verified-run-20260718",
                "crs": "no-crs",
                "mrts": "no-mrts",
                "status": "completed",
                "return_code": 0,
                "started_at": "2026-07-18T00:00:00Z",
                "ended_at": "2026-07-18T00:00:01Z",
                "duration_seconds": 1,
                "job_path": str(Path(temporary) / "no-crs/no-mrts/apache/job.json"),
                "summary_path": str(Path(temporary) / "no-crs/no-mrts/apache/results/force-all/apache-summary.json"),
                "log_path": str(Path(temporary) / "no-crs/no-mrts/apache/run.log"),
                "hashes": {"log": "log", "summary": "summary", "build_manifest": "build", "results_jsonl": "results"},
                "inputs": {"build_manifest": str(Path(temporary) / "build-manifest.json")},
                "outputs": {"results_jsonl": str(Path(temporary) / "results.jsonl")},
            }
            GENERATOR.rewrite_manifest(manifest_path, [job])
            row = json.loads(manifest_path.read_text(encoding="utf-8"))

        self.assertEqual(row["verified_run_id"], "verified-run-20260718")
        self.assertEqual(row["job_id"], "apache:no-crs:no-mrts")
        self.assertEqual(job["hashes"], row["hashes"])
        self.assertEqual(job["inputs"], row["inputs"])
        self.assertEqual(job["outputs"], row["outputs"])
        self.assertEqual(row["status"], "completed")

    def test_governance_record_emits_typed_input_status_arrays(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            connector_root = Path(temporary)
            input_path = connector_root / "runtime-input.json"
            input_path.write_text("{}\n", encoding="utf-8")
            record = REFRESH.build_governance_record(
                "full_runtime_matrix",
                connector_root,
                connector_root,
                connector_root / "build",
                "2026-07-18T00:00:00Z",
                (str(input_path),),
            )

        self.assertEqual(record["input_status"], "complete")
        for key in ("missing_inputs", "empty_inputs", "unknown_inputs", "stale_inputs"):
            self.assertIsInstance(record[key], list)

    def test_verified_manifest_does_not_hash_its_own_overwritten_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            connector_root = Path(temporary)
            generated = connector_root / "reports/testing/generated"
            manifest = generated / "manifest"
            manifest.mkdir(parents=True)
            (manifest / "verified-run-manifest.generated.json").write_text("{}\n", encoding="utf-8")
            (manifest / "verified-run-manifest.generated.md").write_text("# stale self record\n", encoding="utf-8")
            detached = generated / "canonical/full-runtime-matrix.generated.json"
            detached.parent.mkdir(parents=True)
            detached.write_text("{}\n", encoding="utf-8")
            records = RUNNER.generated_output_records(connector_root)

        recorded_names = {Path(str(record["path"])).name for record in records}
        self.assertIn("full-runtime-matrix.generated.json", recorded_names)
        self.assertNotIn("verified-run-manifest.generated.json", recorded_names)
        self.assertNotIn("verified-run-manifest.generated.md", recorded_names)

    def test_verified_command_file_is_private_and_rejects_a_final_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime_root = (Path(temporary) / "runtime").resolve()
            runtime_root.mkdir()
            commands_path = runtime_root / "verified-commands.json"
            payload = {"verified_run_id": "verified-run-20260801", "commands": []}

            RUNNER.write_commands_file(runtime_root, commands_path, payload)

            self.assertEqual(payload, json.loads(commands_path.read_text(encoding="utf-8")))
            self.assertEqual(stat.S_IRUSR | stat.S_IWUSR, stat.S_IMODE(commands_path.stat().st_mode))
            victim = Path(temporary) / "victim.json"
            victim.write_text("do not replace\n", encoding="utf-8")
            commands_path.unlink()
            commands_path.symlink_to(victim)
            with self.assertRaisesRegex(ValueError, "below the runtime root|symbolic link|regular file"):
                RUNNER.write_commands_file(runtime_root, commands_path, payload)
            self.assertEqual(victim.read_text(encoding="utf-8"), "do not replace\n")



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
