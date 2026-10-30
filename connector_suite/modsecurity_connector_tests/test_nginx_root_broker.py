"""Focused contracts for the protected NGINX root broker.

These tests exercise the declarative boundary without starting NGINX or
requiring passwordless sudo.  A later protected-master workflow is responsible
for the real root/master/worker runtime proof.
"""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import argparse
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = connector_root()
BROKER_PATH = source_path('ci/runtime/broker/nginx_root_broker.py', root=ROOT)
BROKER = load_source(BROKER_PATH)


BROKER_SHA = "a" * 40
PARENT_SHA = "b" * 40
FRAMEWORK_SHA = "c" * 40


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class TrustedNginxRootBrokerTest(unittest.TestCase):
    def private_dir(self, path: Path) -> Path:
        path.mkdir(parents=True, mode=0o700)
        path.chmod(0o700)
        return path

    def write(self, path: Path, text: str, mode: int = 0o600) -> Path:
        path.write_text(text, encoding="utf-8")
        path.chmod(mode)
        return path

    def write_binary(self, path: Path, source: Path, mode: int = 0o600) -> Path:
        path.write_bytes(source.read_bytes())
        path.chmod(mode)
        return path

    def caller_manifest(self, root: Path, **overrides: object) -> Path:
        payload: dict[str, object] = {
            "schema_version": BROKER.SCHEMA_VERSION,
            "run_id": "broker-run-1",
            "matrix_variant": "no-crs",
            "parent_head_sha": PARENT_SHA,
            "framework_sha": FRAMEWORK_SHA,
            "protected_broker_sha": BROKER_SHA,
        }
        payload.update(overrides)
        path = root / "caller-manifest.json"
        self.write(path, json.dumps(payload) + "\n")
        return path

    def prepare_arguments(self, root: Path, **overrides: object) -> argparse.Namespace:
        build = self.private_dir(root / "trusted-build")
        self.private_dir(build / "nginx" / "sbin")
        self.private_dir(build / "nginx" / "modules")
        binary = self.write(build / "nginx" / "sbin" / "nginx", "trusted binary\n", 0o700)
        module = self.write_binary(build / "nginx" / "modules" / "ngx_http_modsecurity_module.so", Path("/usr/bin/true"))
        library = self.write_binary(build / BROKER.ARTIFACT_LIBRARY_NAME, Path("/usr/bin/true"))
        caller = self.caller_manifest(root)
        values: dict[str, object] = {
            "caller_manifest": str(caller),
            "trusted_build_root": str(build),
            "broker_sha": BROKER_SHA,
            "binary": str(binary),
            "binary_sha256": digest(binary),
            "module": str(module),
            "module_sha256": digest(module),
            "modsecurity_library": str(library),
            "library_sha256": digest(library),
            "nginx_version": "1.31.4",
            "worker_user": "www-data",
            "loopback": "127.0.0.1",
            "port": 18443,
            "expected_parent_head": PARENT_SHA,
            "expected_framework_sha": FRAMEWORK_SHA,
            "expected_run_id": "broker-run-1",
            "expected_matrix_variant": "no-crs",
        }
        values.update(overrides)
        return argparse.Namespace(**values)

    def write_snapshot_provenance(
        self,
        arguments: argparse.Namespace,
        *,
        binary: Path,
        module: Path,
        prefix: Path,
        library: Path,
    ) -> Path:
        def artifact(path: Path) -> dict[str, object]:
            metadata = path.stat()
            return {
                "path": str(path),
                "sha256": digest(path),
                "device": metadata.st_dev,
                "uid": metadata.st_uid,
                "mode": stat.S_IMODE(metadata.st_mode),
                "size": metadata.st_size,
            }

        payload: dict[str, object] = {
            "schema_version": BROKER.NGINX_BROKER_PROVENANCE_SCHEMA_VERSION,
            "producer": {
                "parent_sha": BROKER_SHA,
                "framework_sha": FRAMEWORK_SHA,
                "identity": "",
            },
            "nginx": {
                "version": "1.31.4",
                "release_tag": "release-1.31.4",
                "source_repository": "https://nginx.org/download/nginx-1.31.4.tar.gz",
                "source_sha256": "d" * 64,
                "cache_schema_version": 1,
                "cache_key": "test-cache-key",
                "connector_build_id": "test-build-id",
                "root": str(binary.parents[2]),
                "binary": artifact(binary),
                "module": artifact(module),
            },
            "modsecurity": {"prefix": str(prefix), "library": artifact(library)},
        }
        unsigned = json.loads(json.dumps(payload))
        unsigned["producer"].pop("identity")  # type: ignore[index]
        payload["producer"]["identity"] = BROKER.canonical_json_digest(unsigned)  # type: ignore[index]
        reports = Path(arguments.trusted_build_root) / BROKER.RUNTIME_REPORTS_RELATIVE
        if reports.exists():
            reports.chmod(0o700)
        else:
            self.private_dir(reports)
        return self.write(
            reports / BROKER.NGINX_BROKER_PROVENANCE_FILENAME,
            json.dumps(payload, sort_keys=True) + "\n",
            0o600,
        )

    def refresh_provenance_identity(self, payload: dict[str, object]) -> None:
        unsigned = json.loads(json.dumps(payload))
        unsigned["producer"].pop("identity")  # type: ignore[index]
        payload["producer"]["identity"] = BROKER.canonical_json_digest(unsigned)  # type: ignore[index]

    def test_valid_declarative_manifest_copies_only_verified_build_artifacts(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nginx-root-broker-") as temporary:
            root = Path(temporary)
            arguments = self.prepare_arguments(root)

            candidate_path = BROKER.prepare_candidate(arguments)

            candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
            self.assertEqual(candidate["run_id"], "broker-run-1")
            self.assertEqual(candidate["protected_broker_sha"], BROKER_SHA)
            self.assertEqual(candidate["producer"]["source_commit"], BROKER_SHA)
            self.assertEqual(candidate["artifacts"]["binary"]["sha256"], arguments.binary_sha256)
            self.assertTrue(Path(candidate["artifacts"]["binary"]["path"]).is_file())
            candidate_root = Path(arguments.trusted_build_root) / BROKER.CANDIDATE_DIRECTORY_NAME
            self.assertFalse((candidate_root / "runtime" / BROKER.BROKER_CONFIG_FILENAME).exists())

    def test_empty_or_unknown_caller_manifest_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nginx-root-broker-") as temporary:
            root = Path(temporary)
            arguments = self.prepare_arguments(root)
            Path(arguments.caller_manifest).write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(BROKER.BrokerError, "missing fields"):
                BROKER.prepare_candidate(arguments)

            arguments = self.prepare_arguments(root / "unknown")
            caller = json.loads(Path(arguments.caller_manifest).read_text(encoding="utf-8"))
            caller["command"] = "/bin/sh"
            Path(arguments.caller_manifest).write_text(json.dumps(caller) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(BROKER.BrokerError, "unknown fields"):
                BROKER.prepare_candidate(arguments)

    def test_rejects_untrusted_artifact_paths_and_digest_mismatches(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nginx-root-broker-") as temporary:
            root = Path(temporary)
            arguments = self.prepare_arguments(root)
            outside = self.write(root / "outside-nginx", "outside\n", 0o700)
            arguments.binary = str(outside)
            arguments.binary_sha256 = digest(outside)
            with self.assertRaisesRegex(BROKER.BrokerError, "inside the trusted build root"):
                BROKER.prepare_candidate(arguments)

            arguments = self.prepare_arguments(root / "mismatch")
            arguments.module_sha256 = "0" * 64
            with self.assertRaisesRegex(BROKER.BrokerError, "digest does not match"):
                BROKER.prepare_candidate(arguments)

    def test_rejects_mismatched_caller_head_and_framework_bindings(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nginx-root-broker-") as temporary:
            root = Path(temporary)
            arguments = self.prepare_arguments(root, expected_parent_head="d" * 40)
            with self.assertRaisesRegex(BROKER.BrokerError, "parent_head_sha does not match"):
                BROKER.prepare_candidate(arguments)

            arguments = self.prepare_arguments(root / "framework", expected_framework_sha="d" * 40)
            with self.assertRaisesRegex(BROKER.BrokerError, "framework_sha does not match"):
                BROKER.prepare_candidate(arguments)

            arguments = self.prepare_arguments(root / "run-id", expected_run_id="other-run")
            with self.assertRaisesRegex(BROKER.BrokerError, "run_id does not match"):
                BROKER.prepare_candidate(arguments)

            arguments = self.prepare_arguments(root / "variant", expected_matrix_variant="with-crs")
            with self.assertRaisesRegex(BROKER.BrokerError, "matrix_variant does not match"):
                BROKER.prepare_candidate(arguments)

    def test_rejects_symlinked_artifacts_and_root_worker(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nginx-root-broker-") as temporary:
            root = Path(temporary)
            arguments = self.prepare_arguments(root)
            binary = Path(arguments.binary)
            target = self.write(binary.parent / "real-nginx", "binary\n", 0o700)
            binary.unlink()
            binary.symlink_to(target)
            arguments.binary_sha256 = digest(target)
            with self.assertRaisesRegex(BROKER.BrokerError, "symlink"):
                BROKER.prepare_candidate(arguments)

            arguments = self.prepare_arguments(root / "root-worker", worker_user="root")
            with self.assertRaisesRegex(BROKER.BrokerError, "must not be root"):
                BROKER.prepare_candidate(arguments)

    def test_strict_final_manifest_rejects_broker_digest_and_projection_tampering(self) -> None:
        root = BROKER.ROOT_PARENT / "broker-run-1"
        payload: dict[str, object] = {
            "schema_version": BROKER.SCHEMA_VERSION,
            "run_id": "broker-run-1",
            "matrix_variant": "no-crs",
            "parent_head_sha": PARENT_SHA,
            "framework_sha": FRAMEWORK_SHA,
            "protected_broker_sha": BROKER_SHA,
            "runner_uid": 1000,
            "runner_gid": 1000,
            "worker": {"name": "www-data", "uid": 33, "gid": 33},
            "network": {"address": "127.0.0.1", "port": 18443},
            "broker_root": str(root),
            "artifacts": {
                "binary": {"path": str(root / "artifacts/nginx"), "sha256": "1" * 64},
                "module": {"path": str(root / "artifacts/module.so"), "sha256": "2" * 64},
                "modsecurity_library": {"path": str(root / "artifacts" / BROKER.ARTIFACT_LIBRARY_NAME), "sha256": "3" * 64},
            },
            "nginx_version": "1.31.4",
            "runtime": {
                "root": str(root / "runtime"),
                "config": str(root / "runtime/nginx.conf"),
                "rules": str(root / "runtime/broker-rules.conf"),
                "docroot": str(root / "runtime/docroot"),
                "pid": str(root / "runtime/nginx.pid"),
                "access_log": str(root / "runtime/logs/nginx-access.log"),
                "error_log": str(root / "runtime/logs/nginx-error.log"),
                "state": str(root / "control/state.json"),
            },
            "projection": {
                "source_root": str(root / "evidence-source"),
                "target_root": str(root / "evidence-published"),
            },
            "expected_evidence": list(BROKER.EXPECTED_EVIDENCE),
            "producer": {"source_commit": BROKER_SHA, "workflow_commit": BROKER_SHA},
        }
        records = [dict(name=name, **record) for name, record in payload["artifacts"].items()]  # type: ignore[index,union-attr]
        payload["artifact_digest"] = BROKER.artifact_set_digest(records)

        with tempfile.TemporaryDirectory(prefix="nginx-root-broker-") as temporary:
            path = Path(temporary) / "manifest.json"
            self.write(path, json.dumps(payload) + "\n")
            self.assertEqual(BROKER.validated_final_manifest(path, BROKER_SHA)["run_id"], "broker-run-1")

            payload["protected_broker_sha"] = "d" * 40
            self.write(path, json.dumps(payload) + "\n")
            with self.assertRaisesRegex(BROKER.BrokerError, "mismatch"):
                BROKER.validated_final_manifest(path, BROKER_SHA)

            payload["protected_broker_sha"] = BROKER_SHA
            payload["projection"] = {"source_root": str(root / "evidence-source")}
            self.write(path, json.dumps(payload) + "\n")
            with self.assertRaisesRegex(BROKER.BrokerError, "projection paths"):
                BROKER.validated_final_manifest(path, BROKER_SHA)

            payload["projection"] = {
                "source_root": str(root / "evidence-source"),
                "target_root": str(root / "evidence-published"),
            }
            payload["artifacts"]["binary"]["path"] = str(root / "artifacts" / "other-nginx")  # type: ignore[index]
            self.write(path, json.dumps(payload) + "\n")
            validated = BROKER.validated_final_manifest(path, BROKER_SHA)
            with self.assertRaisesRegex(BROKER.BrokerError, "fixed broker artifact path"):
                BROKER.manifest_paths(validated)

    def test_action_parser_has_no_general_command_surface(self) -> None:
        source = BROKER_PATH.read_text(encoding="utf-8")
        self.assertNotIn("shell=True", source)
        self.assertNotIn("sudo -E", source)
        self.assertNotIn("sudo sh -c", source)
        self.assertNotIn("sudo bash -c", source)
        self.assertIn("choices=sorted(ALLOWED_ACTIONS)", source)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            BROKER.parse_arguments(["action", "--action", "arbitrary-command", "--broker-sha", BROKER_SHA])
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            BROKER.parse_arguments(
                [
                    "action",
                    "--action",
                    "validate-manifest",
                    "--broker-sha",
                    BROKER_SHA,
                    "--candidate",
                    "/tmp/candidate.json",
                    "--broker-parent",
                    "/tmp/attacker-selected-root",
                ]
            )

    def test_runtime_snapshot_is_discovered_only_below_the_trusted_build_root(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nginx-root-broker-") as temporary:
            root = Path(temporary)
            trusted_build = self.private_dir(root / "trusted-build")
            reports = self.private_dir(trusted_build / BROKER.RUNTIME_REPORTS_RELATIVE)
            snapshot = self.write(reports / "runtime-env-snapshot.test.sh", "export NGINX_BINARY='/bin/false'\n")

            self.assertEqual(BROKER.runtime_snapshot_from_trusted_build(trusted_build), snapshot)

            self.write(reports / "runtime-env-snapshot.second.sh", "export NGINX_MODULE='/bin/false'\n")
            with self.assertRaisesRegex(BROKER.BrokerError, "exactly one runtime environment snapshot"):
                BROKER.runtime_snapshot_from_trusted_build(trusted_build)

    def test_prepare_from_snapshot_uses_only_the_fixed_trusted_build_layout(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nginx-root-broker-") as temporary:
            root = Path(temporary)
            arguments = self.prepare_arguments(root)
            trusted_build = Path(arguments.trusted_build_root)
            prefix = self.private_dir(trusted_build / "modsecurity-prefix")
            library_root = self.private_dir(prefix / "lib")
            library = self.write_binary(library_root / BROKER.ARTIFACT_LIBRARY_NAME, Path("/usr/bin/true"))
            reports = self.private_dir(trusted_build / BROKER.RUNTIME_REPORTS_RELATIVE)
            self.write_snapshot_provenance(
                arguments,
                binary=Path(arguments.binary),
                module=Path(arguments.module),
                prefix=prefix,
                library=library,
            )
            self.write(
                reports / "runtime-env-snapshot.test.sh",
                "\n".join(
                    (
                        f"export NGINX_BINARY='{arguments.binary}'",
                        f"export NGINX_MODULE='{arguments.module}'",
                        f"export MODSECURITY_SHARED_PREFIX='{prefix}'",
                        "",
                    )
                ),
            )
            # Direct harness arguments are deliberately ignored by this mode;
            # only the validated record can supply candidate artifact inputs.
            arguments.binary = "/bin/false"
            arguments.binary_sha256 = "0" * 64
            arguments.module = "/bin/false"
            arguments.module_sha256 = "0" * 64
            arguments.modsecurity_library = "/bin/false"
            arguments.library_sha256 = "0" * 64

            candidate_path = BROKER.prepare_candidate_from_snapshot(arguments)

            candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
            self.assertEqual(candidate["artifacts"]["binary"]["sha256"], digest(Path(arguments.binary)))
            self.assertEqual(candidate["artifacts"]["module"]["sha256"], digest(Path(arguments.module)))
            self.assertEqual(candidate["artifacts"]["modsecurity_library"]["sha256"], digest(library))
            self.assertEqual(candidate_path.parent.parent, trusted_build / BROKER.CANDIDATE_DIRECTORY_NAME)
            self.assertEqual(
                Path(candidate["artifacts"]["modsecurity_library"]["path"]).name,
                BROKER.ARTIFACT_LIBRARY_NAME,
            )

    def test_protected_modsecurity_library_has_a_separate_finite_artifact_limit(self) -> None:
        policy_limit = 64 * 1024 * 1024

        def fixture(root: Path, *, library_size: int) -> tuple[argparse.Namespace, Path]:
            arguments = self.prepare_arguments(root)
            trusted_build = Path(arguments.trusted_build_root)
            prefix = self.private_dir(trusted_build / "modsecurity-prefix")
            library_root = self.private_dir(prefix / "lib")
            library = self.write_binary(
                library_root / BROKER.ARTIFACT_LIBRARY_NAME,
                Path("/usr/bin/true"),
            )
            with library.open("r+b") as handle:
                handle.truncate(library_size)
            self.write_snapshot_provenance(
                arguments,
                binary=Path(arguments.binary),
                module=Path(arguments.module),
                prefix=prefix,
                library=library,
            )
            reports = trusted_build / BROKER.RUNTIME_REPORTS_RELATIVE
            self.write(
                reports / "runtime-env-snapshot.test.sh",
                "\n".join(
                    (
                        f"export NGINX_BINARY='{arguments.binary}'",
                        f"export NGINX_MODULE='{arguments.module}'",
                        f"export MODSECURITY_SHARED_PREFIX='{prefix}'",
                        "",
                    )
                ),
                0o600,
            )
            return arguments, library

        for name, size, accepted in (
            ("below evidence limit", BROKER.MAX_EVIDENCE_FILE_BYTES - 1, True),
            ("above evidence limit", BROKER.MAX_EVIDENCE_FILE_BYTES + 1, True),
            ("exact protected library limit", policy_limit, True),
            ("one byte above protected library limit", policy_limit + 1, False),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory(prefix="nginx-root-broker-") as temporary:
                arguments, library = fixture(Path(temporary), library_size=size)
                if accepted:
                    candidate_path = BROKER.prepare_candidate_from_snapshot(arguments)
                    candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
                    self.assertEqual(
                        candidate["artifacts"]["modsecurity_library"]["sha256"],
                        digest(library),
                    )
                else:
                    with self.assertRaisesRegex(BROKER.BrokerError, "accepted range|size limit"):
                        BROKER.prepare_candidate_from_snapshot(arguments)
                    self.assertFalse(
                        (Path(arguments.trusted_build_root) / BROKER.CANDIDATE_DIRECTORY_NAME).exists()
                    )

        for artifact_name in ("binary", "module"):
            with self.subTest(artifact=artifact_name), tempfile.TemporaryDirectory(
                prefix="nginx-root-broker-"
            ) as temporary:
                arguments, library = fixture(
                    Path(temporary), library_size=BROKER.MAX_EVIDENCE_FILE_BYTES - 1
                )
                artifact = Path(str(getattr(arguments, artifact_name)))
                with artifact.open("r+b") as handle:
                    handle.truncate(BROKER.MAX_EVIDENCE_FILE_BYTES + 1)
                self.write_snapshot_provenance(
                    arguments,
                    binary=Path(arguments.binary),
                    module=Path(arguments.module),
                    prefix=library.parents[1],
                    library=library,
                )
                with self.assertRaisesRegex(BROKER.BrokerError, "accepted range"):
                    BROKER.prepare_candidate_from_snapshot(arguments)
                self.assertFalse(
                    (Path(arguments.trusted_build_root) / BROKER.CANDIDATE_DIRECTORY_NAME).exists()
                )

        self.assertEqual(BROKER.MAX_TRUSTED_MODSECURITY_LIBRARY_BYTES, policy_limit)

    def test_candidate_copy_enforces_the_library_limit_on_the_opened_descriptor(self) -> None:
        policy_limit = 64 * 1024 * 1024
        with tempfile.TemporaryDirectory(prefix="nginx-root-broker-") as temporary:
            root = Path(temporary)
            trusted_build = self.private_dir(root / "trusted-build")
            source = self.write_binary(trusted_build / BROKER.ARTIFACT_LIBRARY_NAME, Path("/usr/bin/true"))
            with source.open("r+b") as handle:
                handle.truncate(policy_limit + 1)
            destination = trusted_build / "candidate"
            artifact = BROKER.ArtifactInput(
                "modsecurity_library",
                source,
                digest(source),
                BROKER.ARTIFACT_LIBRARY_NAME,
                maximum_bytes=policy_limit,
            )
            with mock.patch.object(BROKER, "sha256_fd") as hashed:
                with self.assertRaisesRegex(BROKER.BrokerError, "trusted artifact size limit"):
                    BROKER.copy_verified_artifact(artifact, destination, trusted_build)
            hashed.assert_not_called()
            self.assertFalse(destination.exists())

    def test_candidate_copy_rejects_library_growth_after_its_opened_fd_limit_check(self) -> None:
        policy_limit = 64 * 1024 * 1024
        with tempfile.TemporaryDirectory(prefix="nginx-root-broker-") as temporary:
            root = Path(temporary)
            trusted_build = self.private_dir(root / "trusted-build")
            source = self.write_binary(trusted_build / BROKER.ARTIFACT_LIBRARY_NAME, Path("/usr/bin/true"))
            expected_digest = digest(source)
            destination = trusted_build / "candidate"
            original_sha256_fd = BROKER.sha256_fd
            artifact = BROKER.ArtifactInput(
                "modsecurity_library",
                source,
                expected_digest,
                BROKER.ARTIFACT_LIBRARY_NAME,
                maximum_bytes=policy_limit,
            )

            def grow_after_hash(descriptor: int) -> str:
                observed_digest = original_sha256_fd(descriptor)
                with source.open("ab") as handle:
                    handle.write(b"growth-after-opened-fd-check")
                return observed_digest

            with mock.patch.object(BROKER, "sha256_fd", side_effect=grow_after_hash):
                with self.assertRaisesRegex(BROKER.BrokerError, "source changed while being copied"):
                    BROKER.copy_verified_artifact(artifact, destination, trusted_build)
            self.assertGreater(source.stat().st_size, Path("/usr/bin/true").stat().st_size)

    def test_snapshot_bound_library_replacement_is_rejected_before_candidate_manifest(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nginx-root-broker-") as temporary:
            root = Path(temporary)
            arguments = self.prepare_arguments(root)
            trusted_build = Path(arguments.trusted_build_root)
            prefix = self.private_dir(trusted_build / "modsecurity-prefix")
            library_root = self.private_dir(prefix / "lib")
            library = self.write_binary(
                library_root / BROKER.ARTIFACT_LIBRARY_NAME,
                Path("/usr/bin/true"),
            )
            reports = self.private_dir(trusted_build / BROKER.RUNTIME_REPORTS_RELATIVE)
            self.write_snapshot_provenance(
                arguments,
                binary=Path(arguments.binary),
                module=Path(arguments.module),
                prefix=prefix,
                library=library,
            )
            self.write(
                reports / "runtime-env-snapshot.test.sh",
                "\n".join(
                    (
                        f"export NGINX_BINARY='{arguments.binary}'",
                        f"export NGINX_MODULE='{arguments.module}'",
                        f"export MODSECURITY_SHARED_PREFIX='{prefix}'",
                        "",
                    )
                ),
                0o600,
            )

            def replace_library(_: Path, label: str) -> None:
                if label == "ModSecurity shared library":
                    replacement = self.write_binary(library.parent / "replacement", Path("/usr/bin/false"))
                    os.replace(replacement, library)

            with mock.patch.object(BROKER, "reject_dynamic_search_paths", side_effect=replace_library):
                with self.assertRaisesRegex(BROKER.BrokerError, "digest does not match"):
                    BROKER.prepare_candidate_from_snapshot(arguments)
            candidate = Path(arguments.trusted_build_root) / BROKER.CANDIDATE_DIRECTORY_NAME / "control" / "candidate.json"
            self.assertFalse(candidate.exists())

    def test_evidence_file_and_total_limits_remain_bounded(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nginx-root-broker-") as temporary:
            root = Path(temporary)
            source = self.write_binary(root / "oversized-evidence", Path("/usr/bin/true"))
            with source.open("r+b") as handle:
                handle.truncate(BROKER.MAX_EVIDENCE_FILE_BYTES + 1)
            destination = root / "projected-evidence"
            runner_gid = os.getegid()
            allowed_owners = {os.geteuid()}
            expected_device = source.stat().st_dev
            with self.assertRaisesRegex(BROKER.BrokerError, "evidence file size limit"):
                BROKER.copy_evidence_file(
                    source,
                    destination,
                    runner_gid=runner_gid,
                    allowed_owners=allowed_owners,
                    expected_device=expected_device,
                    label="oversized evidence",
                )
            self.assertFalse(destination.exists())

            source_root = self.private_dir(root / "evidence-source")
            broker_root = self.private_dir(root / "broker-root")
            payload = {
                "projection": {
                    "source_root": str(source_root),
                    "target_root": str(root / "projected-evidence-root"),
                },
                "runtime": {
                    "access_log": str(source_root / BROKER.ACCESS_LOG_FILENAME),
                    "error_log": str(source_root / BROKER.ERROR_LOG_FILENAME),
                },
                "worker": {"uid": os.geteuid()},
                "broker_root": str(broker_root),
                "runner_gid": os.getegid(),
            }
            expected_names = (
                BROKER.IDENTITY_EVIDENCE_FILENAME,
                BROKER.RUNTIME_EVIDENCE_FILENAME,
                BROKER.ACCESS_LOG_FILENAME,
                BROKER.ERROR_LOG_FILENAME,
            )
            with (
                mock.patch.object(BROKER, "read_state", return_value={"stopped": True}),
                mock.patch.object(BROKER, "write_runtime_evidence"),
                mock.patch.object(
                    BROKER,
                    "final_manifest_schema_and_profile",
                    return_value=(BROKER.SCHEMA_VERSION_V1, BROKER.POLICY_PROFILE_NO_CRS),
                ),
                mock.patch.object(BROKER, "expected_evidence_for", return_value=expected_names),
                mock.patch.object(BROKER, "directory_metadata", return_value=broker_root.stat()),
                mock.patch.object(
                    BROKER,
                    "copy_evidence_file",
                    return_value=BROKER.MAX_EVIDENCE_TOTAL_BYTES + 1,
                ) as copy_evidence,
            ):
                with self.assertRaisesRegex(BROKER.BrokerError, "total size limit"):
                    BROKER.project_evidence(payload)
            self.assertEqual(copy_evidence.call_count, 1)

    def test_prepare_from_snapshot_rejects_dynamic_loader_redirection_before_candidate_creation(self) -> None:
        def fixture(root: Path) -> argparse.Namespace:
            arguments = self.prepare_arguments(root)
            trusted_build = Path(arguments.trusted_build_root)
            prefix = self.private_dir(trusted_build / "modsecurity-prefix")
            self.private_dir(prefix / "lib")
            library = self.write_binary(prefix / "lib" / BROKER.ARTIFACT_LIBRARY_NAME, Path("/usr/bin/true"))
            self.write_snapshot_provenance(
                arguments,
                binary=Path(arguments.binary),
                module=Path(arguments.module),
                prefix=prefix,
                library=library,
            )
            self.write(
                trusted_build / BROKER.RUNTIME_REPORTS_RELATIVE / "runtime-env-snapshot.test.sh",
                "\n".join(
                    (
                        f"export NGINX_BINARY='{arguments.binary}'",
                        f"export NGINX_MODULE='{arguments.module}'",
                        f"export MODSECURITY_SHARED_PREFIX='{prefix}'",
                        "",
                    )
                ),
            )
            return arguments

        ordinary = b"".join(
            (
                b"Dynamic section at offset 0x0 contains 2 entries:\n",
                b" 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]\n",
                b" 0x000000000000000e (SONAME)             Library soname: [safe.so]\n",
            )
        )
        rejected_entries = {
            "rpath": (
                b" 0x000000000000000f (RPATH)              Library rpath: [/unsafe]\n",
                "must not contain DT_RPATH or DT_RUNPATH",
            ),
            "runpath": (
                b" 0x000000000000001d (RUNPATH)            Library runpath: [/unsafe]\n",
                "must not contain DT_RPATH or DT_RUNPATH",
            ),
            "slash-needed": (
                b" 0x0000000000000001 (NEEDED)             Shared library: [/runner/libevil.so]\n",
                "DT_NEEDED must use a slash-free shared-library name",
            ),
            "malformed-needed": (
                b" 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6\n",
                "unable to interpret .* DT_NEEDED entry",
            ),
            "audit": (
                b" 0x000000006ffffefc (AUDIT)               Audit library: [/runner/audit.so]\n",
                "must not contain DT_AUDIT",
            ),
            "depaudit": (
                b" 0x000000006ffffefb (DEPAUDIT)            Dependency audit library: [audit.so]\n",
                "must not contain DT_DEPAUDIT",
            ),
            "filter": (
                b" 0x000000007fffffff (FILTER)              Filter library: [filter.so]\n",
                "must not contain DT_FILTER",
            ),
            "auxiliary": (
                b" 0x000000007ffffffd (AUXILIARY)           Auxiliary library: [aux.so]\n",
                "must not contain DT_AUXILIARY",
            ),
        }
        cases = [("ordinary", ordinary, ordinary, False, "")]
        for artifact in ("module", "library"):
            for tag, (entry, message) in rejected_entries.items():
                cases.append(
                    (
                        f"{artifact}-{tag}",
                        entry if artifact == "module" else ordinary,
                        entry if artifact == "library" else ordinary,
                        True,
                        message,
                    )
                )
        for name, module_output, library_output, rejected, message in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory(prefix="nginx-root-broker-") as temporary:
                arguments = fixture(Path(temporary))

                def process(output: bytes) -> mock.Mock:
                    value = mock.Mock()
                    value.stdout = tempfile.TemporaryFile()
                    value.stdout.write(output)
                    value.stdout.seek(0)
                    value.args = [BROKER.READELF_EXECUTABLE, "-d", "artifact"]
                    value.poll.return_value = 0
                    value.wait.return_value = 0
                    return value

                def readelf_process(command: list[str], **_kwargs: object) -> mock.Mock:
                    return process(module_output if command[2] == str(Path(arguments.module)) else library_output)

                with mock.patch.object(BROKER.subprocess, "Popen", side_effect=readelf_process) as readelf:
                    if rejected:
                        with self.assertRaisesRegex(BROKER.BrokerError, message):
                            BROKER.prepare_candidate_from_snapshot(arguments)
                        self.assertFalse((Path(arguments.trusted_build_root) / BROKER.CANDIDATE_DIRECTORY_NAME).exists())
                    else:
                        candidate = BROKER.prepare_candidate_from_snapshot(arguments)
                        self.assertTrue(candidate.is_file())
                inspected = [call.args[0][2] for call in readelf.call_args_list]
                expected = [str(Path(arguments.module))]
                if name == "ordinary" or name.startswith("library-"):
                    expected.append(str(Path(arguments.modsecurity_library)))
                self.assertEqual(inspected, expected)
                for call in readelf.call_args_list:
                    self.assertEqual(call.args[0][0], BROKER.READELF_EXECUTABLE)
                    self.assertEqual(call.kwargs["env"]["PATH"], "")
                    self.assertEqual(call.kwargs["env"]["LC_ALL"], "C")
                    self.assertNotIn("shell", call.kwargs)

    def test_dynamic_inspection_is_output_bounded_and_times_out(self) -> None:
        def completed_process(output: bytes) -> mock.Mock:
            value = mock.Mock()
            value.stdout = tempfile.TemporaryFile()
            value.stdout.write(output)
            value.stdout.seek(0)
            value.args = [BROKER.READELF_EXECUTABLE, "-d", "artifact"]
            value.poll.return_value = 0
            value.wait.return_value = 0
            return value

        with mock.patch.object(BROKER, "MAX_READELF_OUTPUT_BYTES", 16), mock.patch.object(
            BROKER.subprocess, "Popen", return_value=completed_process(b"x" * 17)
        ):
            with self.assertRaisesRegex(BROKER.BrokerError, "output exceeds its bound"):
                BROKER.reject_dynamic_search_paths(Path("/trusted/module.so"), "NGINX module")

        real_popen = subprocess.Popen

        def sleeping_process(*_args: object, **_kwargs: object) -> subprocess.Popen[bytes]:
            return real_popen(
                ["/usr/bin/python3", "-c", "import time; time.sleep(30)"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )

        started = BROKER.time.monotonic()
        with mock.patch.object(BROKER, "READELF_TIMEOUT_SECONDS", 0.05), mock.patch.object(
            BROKER.subprocess, "Popen", side_effect=sleeping_process
        ):
            with self.assertRaisesRegex(BROKER.BrokerError, "timed out"):
                BROKER.reject_dynamic_search_paths(Path("/trusted/module.so"), "NGINX module")
        self.assertLess(BROKER.time.monotonic() - started, 1.0)

    def test_dynamic_section_parser_handles_long_malformed_output_without_backtracking(self) -> None:
        malformed = "\n" * (BROKER.MAX_READELF_OUTPUT_BYTES // 4)
        started = BROKER.time.monotonic()
        with self.assertRaisesRegex(BROKER.BrokerError, "DT_RPATH or DT_RUNPATH"):
            BROKER._reject_dynamic_loader_redirection(
                malformed
                + " 0x000000000000000f (RPATH)              Library rpath: [/unsafe]\n",
                "NGINX module",
            )
        self.assertLess(BROKER.time.monotonic() - started, 1.0)

    def test_runtime_snapshot_rejects_duplicate_empty_malformed_and_arbitrary_exports(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nginx-root-broker-") as temporary:
            snapshot = Path(temporary) / "runtime-env-snapshot.test.sh"
            cases = {
                "duplicate": "\n".join(
                    (
                        "export NGINX_BINARY='/trusted/nginx'",
                        "export NGINX_MODULE='/trusted/module.so'",
                        "export NGINX_BINARY='/trusted/replacement'",
                    )
                ),
                "empty": "\n".join(
                    (
                        "export NGINX_BINARY=''",
                        "export NGINX_MODULE='/trusted/module.so'",
                        "export MODSECURITY_SHARED_PREFIX='/trusted/prefix'",
                    )
                ),
                "malformed": "\n".join(
                    (
                        "export NGINX_BINARY='/trusted/nginx'",
                        "NGINX_MODULE='/trusted/module.so'",
                        "export MODSECURITY_SHARED_PREFIX='/trusted/prefix'",
                    )
                ),
                "arbitrary": "\n".join(
                    (
                        "export NGINX_BINARY='/trusted/nginx'",
                        "export NGINX_MODULE='/trusted/module.so'",
                        "export EVIL='/trusted/prefix'",
                    )
                ),
            }
            for name, content in cases.items():
                self.write(snapshot, content + "\n")
                with self.subTest(name=name), self.assertRaises(BROKER.BrokerError):
                    BROKER.parse_runtime_snapshot(snapshot)

    def test_prepare_from_snapshot_rejects_untrusted_provenance_and_snapshot_replacement(self) -> None:
        def fixture(root: Path) -> tuple[argparse.Namespace, Path, Path]:
            arguments = self.prepare_arguments(root)
            trusted_build = Path(arguments.trusted_build_root)
            prefix = self.private_dir(trusted_build / "modsecurity-prefix")
            library_root = self.private_dir(prefix / "lib")
            library = self.write_binary(library_root / BROKER.ARTIFACT_LIBRARY_NAME, Path("/usr/bin/true"))
            record = self.write_snapshot_provenance(
                arguments,
                binary=Path(arguments.binary),
                module=Path(arguments.module),
                prefix=prefix,
                library=library,
            )
            snapshot = self.write(
                trusted_build / BROKER.RUNTIME_REPORTS_RELATIVE / "runtime-env-snapshot.test.sh",
                "\n".join(
                    (
                        f"export NGINX_BINARY='{arguments.binary}'",
                        f"export NGINX_MODULE='{arguments.module}'",
                        f"export MODSECURITY_SHARED_PREFIX='{prefix}'",
                        "",
                    )
                ),
            )
            return arguments, record, snapshot

        def mutate_record(record: Path, mutate: object) -> None:
            payload = json.loads(record.read_text(encoding="utf-8"))
            mutate(payload)
            self.refresh_provenance_identity(payload)
            self.write(record, json.dumps(payload, sort_keys=True) + "\n", 0o600)

        cases = {
            "relative path": lambda payload: payload["nginx"].__setitem__("root", "relative"),
            "system path": lambda payload: payload["nginx"]["binary"].__setitem__("path", "/bin/false"),
            "outside path": lambda payload: payload["nginx"]["binary"].__setitem__("path", "/tmp/outside-nginx"),
            "owner": lambda payload: payload["nginx"]["binary"].__setitem__("uid", os.geteuid() + 1),
            "mode": lambda payload: payload["nginx"]["binary"].__setitem__("mode", 0o600),
            "digest": lambda payload: payload["nginx"]["binary"].__setitem__("sha256", "0" * 64),
            "parent SHA": lambda payload: payload["producer"].__setitem__("parent_sha", "d" * 40),
            "framework SHA": lambda payload: payload["producer"].__setitem__("framework_sha", "d" * 40),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory(prefix="nginx-root-broker-") as temporary:
                arguments, record, _ = fixture(Path(temporary))
                mutate_record(record, mutate)
                with self.assertRaises(BROKER.BrokerError):
                    BROKER.prepare_candidate_from_snapshot(arguments)

        with tempfile.TemporaryDirectory(prefix="nginx-root-broker-") as temporary:
            arguments, record, _ = fixture(Path(temporary))
            record.unlink()
            with self.assertRaises(BROKER.BrokerError):
                BROKER.prepare_candidate_from_snapshot(arguments)

    def test_prepare_from_snapshot_rejects_each_artifact_before_candidate_creation(self) -> None:
        def fixture(root: Path) -> tuple[argparse.Namespace, Path, Path, Path, Path, Path]:
            arguments = self.prepare_arguments(root)
            trusted_build = Path(arguments.trusted_build_root)
            prefix = self.private_dir(trusted_build / "modsecurity-prefix")
            self.private_dir(prefix / "lib")
            library = self.write_binary(prefix / "lib" / BROKER.ARTIFACT_LIBRARY_NAME, Path("/usr/bin/true"))
            record = self.write_snapshot_provenance(
                arguments,
                binary=Path(arguments.binary),
                module=Path(arguments.module),
                prefix=prefix,
                library=library,
            )
            snapshot = trusted_build / BROKER.RUNTIME_REPORTS_RELATIVE / "runtime-env-snapshot.test.sh"
            write_snapshot(snapshot, arguments, prefix)
            return arguments, record, snapshot, Path(arguments.binary), Path(arguments.module), prefix

        def write_snapshot(snapshot: Path, arguments: argparse.Namespace, prefix: Path, *, omit: str = "", empty: str = "", duplicate: str = "", overrides: dict[str, str] | None = None) -> None:
            values = {
                "NGINX_BINARY": str(arguments.binary),
                "NGINX_MODULE": str(arguments.module),
                "MODSECURITY_SHARED_PREFIX": str(prefix),
            }
            values.update(overrides or {})
            lines = [f"export {key}='{value if key != empty else ''}'" for key, value in values.items() if key != omit]
            if duplicate:
                lines.append(f"export {duplicate}='{values[duplicate]}'")
            self.write(snapshot, "\n".join(lines) + "\n", 0o600)

        def mutate_record(record: Path, mutate: object) -> None:
            payload = json.loads(record.read_text(encoding="utf-8"))
            mutate(payload)
            self.refresh_provenance_identity(payload)
            self.write(record, json.dumps(payload, sort_keys=True) + "\n", 0o600)

        def assert_rejected(arguments: argparse.Namespace) -> None:
            with self.assertRaises(BROKER.BrokerError):
                BROKER.prepare_candidate_from_snapshot(arguments)
            self.assertFalse((Path(arguments.trusted_build_root) / BROKER.CANDIDATE_DIRECTORY_NAME).exists())

        for field in ("NGINX_BINARY", "NGINX_MODULE", "MODSECURITY_SHARED_PREFIX"):
            for mutation in ("missing", "empty", "duplicate"):
                with self.subTest(snapshot_field=field, mutation=mutation), tempfile.TemporaryDirectory(
                    prefix="nginx-root-broker-"
                ) as temporary:
                    arguments, _, snapshot, _, _, prefix = fixture(Path(temporary))
                    if mutation == "missing":
                        write_snapshot(snapshot, arguments, prefix, omit=field)
                    elif mutation == "empty":
                        write_snapshot(snapshot, arguments, prefix, empty=field)
                    else:
                        write_snapshot(snapshot, arguments, prefix, duplicate=field)
                    assert_rejected(arguments)

        snapshot_cases = {
            "relative binary": {"NGINX_BINARY": "relative/nginx"},
            "relative module": {"NGINX_MODULE": "relative/module.so"},
            "system binary": {"NGINX_BINARY": "/bin/false"},
        }
        for name, overrides in snapshot_cases.items():
            with self.subTest(snapshot=name), tempfile.TemporaryDirectory(prefix="nginx-root-broker-") as temporary:
                arguments, _, snapshot, _, _, prefix = fixture(Path(temporary))
                write_snapshot(snapshot, arguments, prefix, overrides=overrides)
                assert_rejected(arguments)

        for artifact_name, record_key in (("binary", "binary"), ("module", "module")):
            for mutation in ("digest", "owner", "mode"):
                with self.subTest(artifact=artifact_name, mutation=mutation), tempfile.TemporaryDirectory(
                    prefix="nginx-root-broker-"
                ) as temporary:
                    arguments, record, _, _, _, _ = fixture(Path(temporary))
                    field = {"digest": "sha256", "owner": "uid", "mode": "mode"}[mutation]
                    value: object = {
                        "digest": "0" * 64,
                        "owner": os.geteuid() + 1,
                        "mode": 0o600 if record_key == "binary" else 0o400,
                    }[mutation]
                    mutate_record(record, lambda payload, key=record_key, field=field, value=value: payload["nginx"][key].__setitem__(field, value))
                    assert_rejected(arguments)

        for artifact_name in ("binary", "module"):
            with self.subTest(artifact=artifact_name, mutation="symlink"), tempfile.TemporaryDirectory(
                prefix="nginx-root-broker-"
            ) as temporary:
                arguments, _, _, binary, module, _ = fixture(Path(temporary))
                artifact = binary if artifact_name == "binary" else module
                target = self.write(artifact.parent / f"replacement-{artifact_name}", "replacement\n", 0o700)
                artifact.unlink()
                artifact.symlink_to(target)
                assert_rejected(arguments)

            with self.subTest(artifact=artifact_name, mutation="group-writable"), tempfile.TemporaryDirectory(
                prefix="nginx-root-broker-"
            ) as temporary:
                arguments, _, _, binary, module, _ = fixture(Path(temporary))
                artifact = binary if artifact_name == "binary" else module
                artifact.chmod(0o720)
                assert_rejected(arguments)

        for mutation in (
            "outside",
            "digest",
            "group-writable",
            "other-writable",
            "symlink",
            "hardlink",
            "fifo",
        ):
            with self.subTest(artifact="modsecurity_library", mutation=mutation), tempfile.TemporaryDirectory(
                prefix="nginx-root-broker-"
            ) as temporary:
                arguments, record, _, _, _, prefix = fixture(Path(temporary))
                library = prefix / "lib" / BROKER.ARTIFACT_LIBRARY_NAME
                if mutation == "outside":
                    outside = self.write(Path(temporary) / BROKER.ARTIFACT_LIBRARY_NAME, "outside\n")
                    mutate_record(record, lambda payload: payload["modsecurity"]["library"].__setitem__("path", str(outside)))
                elif mutation == "digest":
                    mutate_record(record, lambda payload: payload["modsecurity"]["library"].__setitem__("sha256", "0" * 64))
                elif mutation == "group-writable":
                    library.chmod(0o620)
                elif mutation == "other-writable":
                    library.chmod(0o602)
                elif mutation == "symlink":
                    target = self.write(library.parent / "replacement-modsecurity", "replacement\n")
                    library.unlink()
                    library.symlink_to(target)
                elif mutation == "hardlink":
                    os.link(library, library.parent / "linked-modsecurity")
                else:
                    library.unlink()
                    os.mkfifo(library)
                assert_rejected(arguments)

        with tempfile.TemporaryDirectory(prefix="nginx-root-broker-") as temporary:
            arguments, _, snapshot, _, _, _ = fixture(Path(temporary))
            snapshot.chmod(0o644)
            assert_rejected(arguments)

        with tempfile.TemporaryDirectory(prefix="nginx-root-broker-") as temporary:
            arguments, record, snapshot, _, _, _ = fixture(Path(temporary))
            snapshot.write_text(
                "\n".join(
                    (
                        "export NGINX_BINARY='/bin/false'",
                        f"export NGINX_MODULE='{arguments.module}'",
                        f"export MODSECURITY_SHARED_PREFIX='{json.loads(record.read_text(encoding='utf-8'))['modsecurity']['prefix']}'",
                        "",
                    )
                ),
                encoding="utf-8",
            )
            snapshot.chmod(0o600)
            assert_rejected(arguments)

        with tempfile.TemporaryDirectory(prefix="nginx-root-broker-") as temporary:
            arguments, _, _, _, _, _ = fixture(Path(temporary))
            binary = Path(arguments.binary)
            target = self.write(binary.parent / "replacement-nginx", "replacement\n", 0o700)
            binary.unlink()
            binary.symlink_to(target)
            assert_rejected(arguments)

    def test_root_creation_rolls_back_when_chown_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nginx-root-broker-") as temporary:
            state_base = self.private_dir(Path(temporary) / "var-lib")
            parent = state_base / BROKER.ROOT_PARENT_NAME
            run_root = parent / "broker-run-1"

            # The production path requires a root-owned state base.  Model that
            # ownership boundary while retaining a real unprivileged temporary
            # tree, so this regression test can exercise both removal paths on
            # an ordinary CI runner.
            original_directory_metadata = BROKER.directory_metadata

            def root_owned_directory_metadata(path: Path, label: str, *, owner: int | None = None) -> os.stat_result:
                metadata = original_directory_metadata(path, label)
                values = list(metadata)
                values[4] = 0
                return os.stat_result(values)

            def root_owned_stat(*args: object, **kwargs: object) -> os.stat_result:
                metadata = original_stat(*args, **kwargs)
                values = list(metadata)
                values[4] = 0
                return os.stat_result(values)

            runner_gid = os.getegid()
            with (
                mock.patch.object(BROKER, "ROOT_STATE_BASE", state_base),
                mock.patch.object(BROKER, "ROOT_PARENT", parent),
                mock.patch.object(BROKER, "directory_metadata", side_effect=root_owned_directory_metadata),
                mock.patch.object(BROKER.os, "chown", side_effect=OSError("fault-injected chown failure")),
            ):
                with self.assertRaisesRegex(OSError, "fault-injected"):
                    BROKER.secure_root_parent(runner_gid)
            self.assertFalse(parent.exists())

            BROKER.safe_mkdir(parent, BROKER.ROOT_PARENT_MODE, "test broker root parent")
            original_stat = os.stat
            with (
                mock.patch.object(BROKER, "ROOT_PARENT", parent),
                mock.patch.object(BROKER, "directory_metadata", side_effect=root_owned_directory_metadata),
                mock.patch.object(BROKER.os, "stat", side_effect=root_owned_stat),
                mock.patch.object(BROKER.os, "chown", side_effect=OSError("fault-injected chown failure")),
            ):
                with self.assertRaisesRegex(OSError, "fault-injected"):
                    BROKER.create_admitted_root(run_root, runner_gid)
            self.assertFalse(run_root.exists())

    def test_descriptor_cleanup_removes_special_entries_without_following_links(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nginx-root-broker-") as temporary:
            root = Path(temporary)
            private = self.private_dir(root / "private")
            outside = self.write(root / "outside", "outside remains\n")
            self.write(private / "regular", "remove me\n")
            (private / "link").symlink_to(outside)
            os.mkfifo(private / "fifo")

            descriptor = os.open(private, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                BROKER.remove_directory_contents_no_follow(
                    descriptor,
                    os.fstat(descriptor).st_dev,
                    "test private root",
                )
            finally:
                os.close(descriptor)
            private.rmdir()
            self.assertFalse(private.exists())
            self.assertEqual(outside.read_text(encoding="utf-8"), "outside remains\n")

    def test_worker_writable_log_layout_is_exact_and_log_files_stay_fail_closed(self) -> None:
        """Only the fixed root-owned worker directory may carry group write."""

        with tempfile.TemporaryDirectory(prefix="nginx-root-broker-") as temporary:
            root = Path(temporary)
            runtime = self.private_dir(root / "runtime")
            logs = runtime / "logs"
            logs.mkdir(mode=0o730)
            logs.chmod(0o730)
            worker_gid = os.getegid()
            owner = os.geteuid()
            access_log = self.write(logs / BROKER.ACCESS_LOG_FILENAME, "access\n", 0o600)
            projection = self.private_dir(root / "projection")
            original_lstat = os.lstat

            def root_owned_log_lstat(path: os.PathLike[str] | str) -> os.stat_result:
                metadata = original_lstat(path)
                if Path(path) == logs:
                    values = list(metadata)
                    values[4] = 0
                    return os.stat_result(values)
                return metadata

            with mock.patch.object(BROKER.os, "lstat", side_effect=root_owned_log_lstat):
                BROKER.require_worker_writable_directory_layout(
                    logs,
                    group=worker_gid,
                    label="broker logs",
                )
                with self.assertRaisesRegex(BROKER.BrokerError, "group- or other-writable"):
                    BROKER.directory_metadata(logs, "generic log directory")
                expected_device = logs.stat().st_dev
                with mock.patch.object(BROKER.os, "fchown"):
                    self.assertEqual(
                        BROKER.copy_evidence_file(
                            access_log,
                            projection / "access.json",
                            runner_gid=worker_gid,
                            allowed_owners={owner},
                            expected_device=expected_device,
                            label="safe access log",
                        ),
                        len("access\n"),
                    )

                for name, mode in (("group-writable", 0o620), ("other-writable", 0o602)):
                    access_log.chmod(mode)
                    with self.subTest(log_mode=name):
                        with self.assertRaisesRegex(
                            BROKER.BrokerError,
                            "group- or other-writable",
                        ):
                            BROKER.copy_evidence_file(
                                access_log,
                                projection / f"{name}.json",
                                runner_gid=worker_gid,
                                allowed_owners={owner},
                                expected_device=expected_device,
                                label=f"{name} log",
                            )
                access_log.chmod(0o600)

                logs.chmod(0o770)
                with self.assertRaisesRegex(BROKER.BrokerError, "ownership or mode changed"):
                    BROKER.require_worker_writable_directory_layout(
                        logs,
                        group=worker_gid,
                        label="broker logs",
                    )
                logs.chmod(0o730)

                logs.chmod(0o732)
                with self.assertRaisesRegex(BROKER.BrokerError, "ownership or mode changed"):
                    BROKER.require_worker_writable_directory_layout(
                        logs,
                        group=worker_gid,
                        label="broker logs",
                    )
                logs.chmod(0o730)
                with self.assertRaisesRegex(BROKER.BrokerError, "ownership or mode changed"):
                    BROKER.require_worker_writable_directory_layout(
                        logs,
                        group=worker_gid + 1,
                        label="broker logs",
                    )

                # A fresh action revalidates the current mode, so a replacement
                # after an earlier successful check is not carried forward.
                BROKER.require_worker_writable_directory_layout(
                    logs,
                    group=worker_gid,
                    label="broker logs",
                )
                logs.chmod(0o750)
                with self.assertRaisesRegex(BROKER.BrokerError, "ownership or mode changed"):
                    BROKER.require_worker_writable_directory_layout(
                        logs,
                        group=worker_gid,
                        label="broker logs",
                    )
                logs.chmod(0o730)

                linked_logs = root / "linked-logs"
                linked_logs.symlink_to(logs, target_is_directory=True)
                with self.assertRaisesRegex(BROKER.BrokerError, "symlink"):
                    BROKER.require_worker_writable_directory_layout(
                        linked_logs,
                        group=worker_gid,
                        label="broker logs",
                    )

            def foreign_owned_log_lstat(path: os.PathLike[str] | str) -> os.stat_result:
                metadata = original_lstat(path)
                if Path(path) == logs:
                    values = list(metadata)
                    values[4] = owner + 1 if owner != 0 else 1
                    return os.stat_result(values)
                return metadata

            with mock.patch.object(BROKER.os, "lstat", side_effect=foreign_owned_log_lstat):
                with self.assertRaisesRegex(BROKER.BrokerError, "ownership or mode changed"):
                    BROKER.require_worker_writable_directory_layout(
                        logs,
                        group=worker_gid,
                        label="broker logs",
                    )

    def test_cleanup_removes_worker_layout_after_failed_config_test(self) -> None:
        """The fail-closed config-test path still reaches descriptor-safe cleanup."""

        with tempfile.TemporaryDirectory(prefix="nginx-root-broker-") as temporary:
            temporary_root = Path(temporary)
            parent = temporary_root / "broker-parent"
            parent.mkdir(mode=0o710)
            parent.chmod(0o710)
            run_id = "broker-run-1"
            root = parent / run_id
            root.mkdir(mode=0o710)
            root.chmod(0o710)
            runner_gid = os.getegid()
            with mock.patch.object(BROKER.os, "chown"):
                layout = BROKER.create_admitted_layout(root, runner_gid, BROKER.POLICY_PROFILE_NO_CRS)
            payload = {
                "run_id": run_id,
                "runner_gid": runner_gid,
                "broker_root": str(root),
                "network": {"address": "127.0.0.1", "port": 18443},
                "runtime": {
                    "state": str(layout["control"] / BROKER.STATE_FILENAME),
                    "pid": str(layout["runtime"] / BROKER.PID_FILENAME),
                },
            }
            original_directory_metadata = BROKER.directory_metadata
            original_stat = os.stat

            def root_owned_parent_metadata(
                path: Path,
                label: str,
                *,
                owner: int | None = None,
            ) -> os.stat_result:
                metadata = original_directory_metadata(path, label)
                if Path(path) == parent:
                    values = list(metadata)
                    values[4] = 0
                    metadata = os.stat_result(values)
                if owner is not None and metadata.st_uid != owner:
                    BROKER.fail(f"{label} has an unexpected owner: {path}")
                return metadata

            def root_owned_run_stat(path: os.PathLike[str] | str, *args: object, **kwargs: object) -> os.stat_result:
                metadata = original_stat(path, *args, **kwargs)
                if kwargs.get("dir_fd") is not None and os.fspath(path) == run_id:
                    values = list(metadata)
                    values[4] = 0
                    return os.stat_result(values)
                return metadata

            with (
                mock.patch.object(BROKER, "ROOT_PARENT", parent),
                mock.patch.object(BROKER, "directory_metadata", side_effect=root_owned_parent_metadata),
                mock.patch.object(BROKER.os, "stat", side_effect=root_owned_run_stat),
                mock.patch.object(BROKER.os, "fchown"),
                mock.patch.object(BROKER, "verify_listener_released"),
                mock.patch.object(BROKER, "validate_runtime_config", side_effect=BROKER.BrokerError("forced config failure")),
            ):
                with self.assertRaisesRegex(BROKER.BrokerError, "forced config failure"):
                    BROKER.config_test(payload)
                BROKER.stop(payload)
                BROKER.cleanup_status(payload)
            self.assertFalse(root.exists())

    def test_projection_rejects_symlink_or_special_inputs_before_copy(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nginx-root-broker-") as temporary:
            root = Path(temporary)
            target = self.write(root / "target", "evidence\n")
            linked = root / "linked-evidence"
            linked.symlink_to(target)
            with self.assertRaisesRegex(BROKER.BrokerError, "single-link regular"):
                BROKER.open_regular_no_follow(linked, "linked evidence")

            fifo = root / "evidence.fifo"
            os.mkfifo(fifo)
            with self.assertRaisesRegex(BROKER.BrokerError, "single-link regular"):
                BROKER.open_regular_no_follow(fifo, "FIFO evidence")

    def test_caller_yaml_contract_accepts_the_exact_two_immutable_broker_jobs(self) -> None:
        raw = (source_path('.github/workflows/run-protected-nginx-root-broker.yml', root=ROOT)).read_bytes()

        document = BROKER.parse_restricted_caller_workflow_yaml(raw)

        BROKER.validate_caller_workflow_document(
            document,
            broker_sha="8ae707d72f1a8acb25d239e55e28a73cbc7522b1",
            framework_sha="99a7985c1be92a2297b1b59208f64df6768f2cbf",
        )

    def test_caller_yaml_contract_accepts_uniform_ubuntu26_runners(self) -> None:
        raw = (source_path('.github/workflows/run-protected-nginx-root-broker.yml', root=ROOT)).read_bytes()
        document = BROKER.parse_restricted_caller_workflow_yaml(raw)
        for name in ("prepare-manifests", "verify-evidence", "result"):
            document["jobs"][name]["runs-on"] = "ubuntu-26.04"
        BROKER.validate_caller_workflow_document(
            document,
            broker_sha="8ae707d72f1a8acb25d239e55e28a73cbc7522b1",
            framework_sha="99a7985c1be92a2297b1b59208f64df6768f2cbf",
        )

    def test_caller_yaml_contract_rejects_mixed_runner_modes(self) -> None:
        raw = (source_path('.github/workflows/run-protected-nginx-root-broker.yml', root=ROOT)).read_bytes()
        names = ("prepare-manifests", "verify-evidence", "result")
        for uniform, differing in (("ubuntu-latest", "ubuntu-26.04"), ("ubuntu-26.04", "ubuntu-latest")):
            for changed_job in names:
                with self.subTest(uniform=uniform, changed_job=changed_job):
                    document = BROKER.parse_restricted_caller_workflow_yaml(raw)
                    for name in names:
                        document["jobs"][name]["runs-on"] = uniform
                    document["jobs"][changed_job]["runs-on"] = differing
                    with self.assertRaisesRegex(BROKER.BrokerError, "uniform runner mode"):
                        BROKER.validate_caller_workflow_document(
                            document,
                            broker_sha="8ae707d72f1a8acb25d239e55e28a73cbc7522b1",
                            framework_sha="99a7985c1be92a2297b1b59208f64df6768f2cbf",
                        )

    def test_caller_yaml_contract_rejects_unknown_and_structured_runners(self) -> None:
        raw = (source_path('.github/workflows/run-protected-nginx-root-broker.yml', root=ROOT)).read_bytes()
        for name in ("prepare-manifests", "verify-evidence", "result"):
            for runner in ("ubuntu-24.04", "self-hosted", ["self-hosted", "linux"], ["ubuntu-26.04"]):
                with self.subTest(job=name, runner=runner):
                    document = BROKER.parse_restricted_caller_workflow_yaml(raw)
                    document["jobs"][name]["runs-on"] = runner
                    with self.assertRaisesRegex(BROKER.BrokerError, "unexpected runner"):
                        BROKER.validate_caller_workflow_document(
                            document,
                            broker_sha="8ae707d72f1a8acb25d239e55e28a73cbc7522b1",
                            framework_sha="99a7985c1be92a2297b1b59208f64df6768f2cbf",
                        )

    def test_broker_workflow_uses_ubuntu26_runner(self) -> None:
        workflow = (source_path('.github/workflows/nginx-root-broker.yml', root=ROOT)).read_text(encoding="utf-8")
        self.assertEqual(workflow.count("    runs-on: ubuntu-26.04\n"), 1)
        self.assertNotIn("runs-on: ubuntu-latest", workflow)

    def test_caller_yaml_contract_rejects_pin_job_variant_permission_and_secret_mutations(self) -> None:
        text = (source_path('.github/workflows/run-protected-nginx-root-broker.yml', root=ROOT)).read_text(
            encoding="utf-8"
        )
        broker_sha = "8ae707d72f1a8acb25d239e55e28a73cbc7522b1"
        framework_sha = "99a7985c1be92a2297b1b59208f64df6768f2cbf"
        extra_broker_job = "\n".join(
            (
                "  run-extra-broker:",
                "    uses: Easton97-Jens/ModSecurity-conector/.github/workflows/nginx-root-broker.yml@"
                + broker_sha,
                "",
            )
        )
        mutations = {
            "mutable broker ref": (f"@{broker_sha}", "@master"),
            "mismatched broker input": (f"protected_broker_sha: {broker_sha}", "protected_broker_sha: " + "0" * 40),
            "missing protected job": ("  run-no-crs-broker:\n", "  run-no-crs-broker-missing:\n"),
            "extra protected job": ("  verify-evidence:\n", extra_broker_job + "  verify-evidence:\n"),
            "swapped variant": ("matrix_variant: no-crs", "matrix_variant: with-crs"),
            "write permission": (
                "      needs.prepare-manifests.result == 'success'\n"
                "    permissions:\n      contents: read\n"
                "    uses: Easton97-Jens/ModSecurity-conector/.github/workflows/nginx-root-broker.yml@",
                "      needs.prepare-manifests.result == 'success'\n"
                "    permissions:\n      contents: write\n"
                "    uses: Easton97-Jens/ModSecurity-conector/.github/workflows/nginx-root-broker.yml@",
            ),
            "secret inheritance": (
                f"    uses: Easton97-Jens/ModSecurity-conector/.github/workflows/nginx-root-broker.yml@{broker_sha}\n",
                "\n".join(
                    (
                        f"    uses: Easton97-Jens/ModSecurity-conector/.github/workflows/nginx-root-broker.yml@{broker_sha}",
                        "    secrets: inherit",
                        "",
                    )
                ),
            ),
            "duplicate uses": (
                f"    uses: Easton97-Jens/ModSecurity-conector/.github/workflows/nginx-root-broker.yml@{broker_sha}\n",
                "\n".join(
                    (
                        f"    uses: Easton97-Jens/ModSecurity-conector/.github/workflows/nginx-root-broker.yml@{broker_sha}",
                        f"    uses: Easton97-Jens/ModSecurity-conector/.github/workflows/nginx-root-broker.yml@{broker_sha}",
                        "",
                    )
                ),
            ),
        }
        for name, (original, replacement) in mutations.items():
            with self.subTest(name=name):
                self.assertIn(original, text)
                mutated = text.replace(original, replacement, 1)
                if name == "duplicate uses":
                    mutated_yaml = mutated.encode("utf-8")
                    with self.assertRaisesRegex(BROKER.BrokerError, r"duplicates mapping key 'uses'"):
                        BROKER.parse_restricted_caller_workflow_yaml(mutated_yaml)
                    continue
                document = BROKER.parse_restricted_caller_workflow_yaml(mutated.encode("utf-8"))
                with self.assertRaises(BROKER.BrokerError):
                    BROKER.validate_caller_workflow_document(
                        document,
                        broker_sha=broker_sha,
                        framework_sha=framework_sha,
                    )

    def test_caller_yaml_contract_rejects_top_level_and_unprivileged_job_mutations(self) -> None:
        raw = (source_path('.github/workflows/run-protected-nginx-root-broker.yml', root=ROOT)).read_bytes()
        broker_sha = "8ae707d72f1a8acb25d239e55e28a73cbc7522b1"
        framework_sha = "99a7985c1be92a2297b1b59208f64df6768f2cbf"

        def add_extra_trigger(document: dict[str, object]) -> None:
            document["on"]["push"] = {}

        def add_extra_input(document: dict[str, object]) -> None:
            document["on"]["workflow_dispatch"]["inputs"]["matrix_variant"] = {
                "required": "true",
                "type": "string",
            }

        def add_top_level_write_permission(document: dict[str, object]) -> None:
            document["permissions"] = {"contents": "write"}

        def weaken_prepare_gate(document: dict[str, object]) -> None:
            document["jobs"]["prepare-manifests"]["if"] = "true"

        def lengthen_prepare_timeout(document: dict[str, object]) -> None:
            document["jobs"]["prepare-manifests"]["timeout-minutes"] = "999"

        def weaken_evidence_gate(document: dict[str, object]) -> None:
            document["jobs"]["verify-evidence"]["if"] = "${{ always() }}"

        def weaken_result_dependencies(document: dict[str, object]) -> None:
            document["jobs"]["result"]["needs"] = ["prepare-manifests"]

        mutations = {
            "extra trigger": add_extra_trigger,
            "extra dispatch input": add_extra_input,
            "top-level write permission": add_top_level_write_permission,
            "weakened preparation gate": weaken_prepare_gate,
            "unexpected preparation timeout": lengthen_prepare_timeout,
            "weakened evidence gate": weaken_evidence_gate,
            "weakened result dependencies": weaken_result_dependencies,
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                document = BROKER.parse_restricted_caller_workflow_yaml(raw)
                mutate(document)
                with self.assertRaises(BROKER.BrokerError):
                    BROKER.validate_caller_workflow_document(
                        document,
                        broker_sha=broker_sha,
                        framework_sha=framework_sha,
                    )

    def test_caller_yaml_contract_rejects_any_weakened_reusable_job_gate(self) -> None:
        raw = (source_path('.github/workflows/run-protected-nginx-root-broker.yml', root=ROOT)).read_bytes()
        broker_sha = "8ae707d72f1a8acb25d239e55e28a73cbc7522b1"
        framework_sha = "99a7985c1be92a2297b1b59208f64df6768f2cbf"
        required_terms = (
            "github.event_name == 'workflow_dispatch'",
            "github.repository == 'Easton97-Jens/ModSecurity-conector'",
            "github.event.repository.fork == false",
            "github.ref == 'refs/heads/master'",
            "github.event.repository.default_branch == 'master'",
            "needs.prepare-manifests.result == 'success'",
        )
        for job_name in BROKER.EXPECTED_CALLER_BROKER_VARIANTS:
            for required_term in required_terms:
                with self.subTest(job_name=job_name, required_term=required_term):
                    document = BROKER.parse_restricted_caller_workflow_yaml(raw)
                    gate = document["jobs"][job_name]["if"]
                    self.assertIsInstance(gate, str)
                    self.assertIn(required_term, gate)
                    document["jobs"][job_name]["if"] = gate.replace(required_term, "true", 1)
                    with self.assertRaisesRegex(BROKER.BrokerError, "exact protected gate"):
                        BROKER.validate_caller_workflow_document(
                            document,
                            broker_sha=broker_sha,
                            framework_sha=framework_sha,
                        )

    def test_caller_yaml_contract_rejects_a_constant_true_reusable_job_gate(self) -> None:
        raw = (source_path('.github/workflows/run-protected-nginx-root-broker.yml', root=ROOT)).read_bytes()
        broker_sha = "8ae707d72f1a8acb25d239e55e28a73cbc7522b1"
        framework_sha = "99a7985c1be92a2297b1b59208f64df6768f2cbf"
        document = BROKER.parse_restricted_caller_workflow_yaml(raw)
        document["jobs"]["run-no-crs-broker"]["if"] = "true"

        with self.assertRaisesRegex(BROKER.BrokerError, "exact protected gate"):
            BROKER.validate_caller_workflow_document(
                document,
                broker_sha=broker_sha,
                framework_sha=framework_sha,
            )

    def test_caller_yaml_contract_preserves_block_scalar_hash_data(self) -> None:
        raw = (source_path('.github/workflows/run-protected-nginx-root-broker.yml', root=ROOT)).read_bytes()
        broker_sha = "8ae707d72f1a8acb25d239e55e28a73cbc7522b1"
        framework_sha = "99a7985c1be92a2297b1b59208f64df6768f2cbf"
        documented = BROKER.parse_restricted_caller_workflow_yaml(b"# ordinary YAML comment\n" + raw)
        BROKER.validate_caller_workflow_document(
            documented,
            broker_sha=broker_sha,
            framework_sha=framework_sha,
        )
        commented_steps = raw.replace(
            b"      - name: Check out protected master caller source\n",
            b"      - name: Check out protected master caller source\n"
            b"      # ordinary list-item comment\n",
            1,
        )
        document = BROKER.parse_restricted_caller_workflow_yaml(commented_steps)
        BROKER.validate_caller_workflow_document(
            document,
            broker_sha=broker_sha,
            framework_sha=framework_sha,
        )
        mutated = raw.replace(
            b"needs.prepare-manifests.result == 'success'",
            b"needs.prepare-manifests.result == 'success' # literal-block-data",
            1,
        )
        document = BROKER.parse_restricted_caller_workflow_yaml(mutated)
        with self.assertRaisesRegex(BROKER.BrokerError, "exact protected gate"):
            BROKER.validate_caller_workflow_document(
                document,
                broker_sha=broker_sha,
                framework_sha=framework_sha,
            )

    def test_restricted_caller_yaml_parser_accepts_only_the_exact_empty_mapping_literal(self) -> None:
        document = BROKER.parse_restricted_caller_workflow_yaml(b"permissions: {}\n")
        self.assertEqual(document, {"permissions": {}})

    def test_caller_top_level_permissions_remain_exactly_deny_default(self) -> None:
        raw = (source_path('.github/workflows/run-protected-nginx-root-broker.yml', root=ROOT)).read_bytes()
        self.assertIn(b"permissions: {}\n", raw)
        for permissions in (
            b"permissions:\n  contents: read\n",
            b"permissions:\n  contents: write\n",
            b"permissions:\n  actions: read\n",
        ):
            with self.subTest(permissions=permissions):
                changed = raw.replace(b"permissions: {}\n", permissions, 1)
                document = BROKER.parse_restricted_caller_workflow_yaml(changed)
                with self.assertRaisesRegex(BROKER.BrokerError, "exactly deny-default"):
                    BROKER.validate_caller_workflow_document(
                        document,
                        broker_sha="8ae707d72f1a8acb25d239e55e28a73cbc7522b1",
                        framework_sha="99a7985c1be92a2297b1b59208f64df6768f2cbf",
                    )

    def test_restricted_caller_yaml_parser_rejects_indirection_duplicates_and_unsafe_encoding(self) -> None:
        invalid_documents = {
            "byte-order mark": b"\xef\xbb\xbfjobs:\n",
            "carriage return": b"jobs:\r\n",
            "tab": b"jobs:\n\trun: value\n",
            "document marker": b"---\njobs:\n",
            "anchor": b"jobs:\n  run: &anchor\n",
            "alias": b"jobs:\n  run: *anchor\n",
            "tag": b"jobs:\n  run: !unsafe value\n",
            "merge": b"jobs:\n  <<: *anchor\n",
            "nonempty flow mapping": b"jobs: {run: value}\n",
            "spaced flow mapping": b"jobs: { }\n",
            "flow list": b"jobs: []\n",
            "tagged empty mapping": b"permissions: !unsafe {}\n",
            "anchored empty mapping": b"permissions: &anchor {}\n",
            "duplicate key": b"jobs:\n  run: one\n  run: two\n",
        }
        for name, raw in invalid_documents.items():
            with self.subTest(name=name), self.assertRaises(BROKER.BrokerError):
                BROKER.parse_restricted_caller_workflow_yaml(raw)

    def test_caller_workflow_is_read_only_from_one_regular_git_blob(self) -> None:
        caller_sha = "d" * 40
        blob_sha = "e" * 64
        expected_entry = (
            f"100644 blob {blob_sha}\t{BROKER.EXPECTED_CALLER_WORKFLOW_PATH}\n".encode("ascii")
        )
        calls: list[tuple[tuple[str, ...], bool]] = []
        with tempfile.TemporaryDirectory(prefix="nginx-root-broker-git-") as temporary:
            repository = Path(temporary) / "broker-src"
            repository.mkdir()

            def protected_git(arguments: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
                calls.append((tuple(arguments), kwargs.get("shell") is False))
                if arguments[-3:] == ["cat-file", "-t", caller_sha]:
                    output = b"commit\n"
                elif arguments[-4:] == [
                    "ls-tree",
                    caller_sha,
                    "--",
                    BROKER.EXPECTED_CALLER_WORKFLOW_PATH,
                ]:
                    output = expected_entry
                elif arguments[-3:] == ["cat-file", "-s", blob_sha]:
                    output = b"9\n"
                elif arguments[-3:] == ["cat-file", "blob", blob_sha]:
                    output = b"jobs: {}\n"
                else:
                    self.fail(f"unexpected Git arguments: {arguments}")
                return subprocess.CompletedProcess(arguments, 0, stdout=output, stderr=b"")

            with mock.patch.object(BROKER.subprocess, "run", side_effect=protected_git):
                raw = BROKER.read_caller_workflow_blob(repository, caller_sha)

        self.assertEqual(raw, b"jobs: {}\n")
        self.assertEqual(
            calls,
            [
                (
                    (
                        BROKER.GIT_EXECUTABLE,
                        BROKER.GIT_WORKTREE_OPTION,
                        str(repository),
                        BROKER.GIT_CAT_FILE_COMMAND,
                        "-t",
                        caller_sha,
                    ),
                    True,
                ),
                (
                    (
                        BROKER.GIT_EXECUTABLE,
                        BROKER.GIT_WORKTREE_OPTION,
                        str(repository),
                        BROKER.GIT_LS_TREE_COMMAND,
                        caller_sha,
                        "--",
                        BROKER.EXPECTED_CALLER_WORKFLOW_PATH,
                    ),
                    True,
                ),
                (
                    (
                        BROKER.GIT_EXECUTABLE,
                        BROKER.GIT_WORKTREE_OPTION,
                        str(repository),
                        BROKER.GIT_CAT_FILE_COMMAND,
                        "-s",
                        blob_sha,
                    ),
                    True,
                ),
                (
                    (
                        BROKER.GIT_EXECUTABLE,
                        BROKER.GIT_WORKTREE_OPTION,
                        str(repository),
                        BROKER.GIT_CAT_FILE_COMMAND,
                        "blob",
                        blob_sha,
                    ),
                    True,
                ),
            ],
        )

    def test_caller_workflow_rejects_a_non_regular_git_tree_entry(self) -> None:
        caller_sha = "d" * 40
        entry = (
            f"120000 blob {'e' * 40}\t{BROKER.EXPECTED_CALLER_WORKFLOW_PATH}\n".encode("ascii")
        )

        with tempfile.TemporaryDirectory(prefix="nginx-root-broker-git-") as temporary:
            repository = Path(temporary) / "broker-src"
            repository.mkdir()

            def protected_git(arguments: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
                if arguments[-3:] == ["cat-file", "-t", caller_sha]:
                    output = b"commit\n"
                elif arguments[-4:] == [
                    "ls-tree",
                    caller_sha,
                    "--",
                    BROKER.EXPECTED_CALLER_WORKFLOW_PATH,
                ]:
                    output = entry
                else:
                    self.fail(f"unexpected Git arguments: {arguments}")
                return subprocess.CompletedProcess(arguments, 0, stdout=output, stderr=b"")

            with mock.patch.object(BROKER.subprocess, "run", side_effect=protected_git):
                with self.assertRaisesRegex(BROKER.BrokerError, "regular Git blob"):
                    BROKER.read_caller_workflow_blob(repository, caller_sha)

    def test_caller_workflow_rejects_argument_injection_before_git(self) -> None:
        malicious_shas = (
            "a" * 39 + ";",
            "-" + "a" * 39,
            "a" * 40 + "^{tree}",
            "a" * 39 + "\n",
        )
        for caller_sha in malicious_shas:
            with self.subTest(caller_sha=caller_sha), mock.patch.object(
                BROKER.subprocess, "run"
            ) as git_run:
                with self.assertRaisesRegex(BROKER.BrokerError, "caller_sha must be a lowercase full Git SHA"):
                    BROKER.read_caller_workflow_blob(Path("/untrusted/broker-src"), caller_sha)
                git_run.assert_not_called()

    def test_git_callers_reject_argument_injection_before_git(self) -> None:
        malicious_shas = (
            "a" * 39 + ";",
            "-" + "a" * 39,
            "a" * 40 + "^{tree}",
            "a" * 39 + "\n",
        )
        operations = (
            BROKER.git_caller_commit_type,
            BROKER.git_caller_workflow_tree_entry,
        )
        for operation in operations:
            for caller_sha in malicious_shas:
                with self.subTest(operation=operation.__name__, caller_sha=caller_sha), mock.patch.object(
                    BROKER.subprocess, "run"
                ) as git_run:
                    with self.assertRaisesRegex(BROKER.BrokerError, "caller_sha must be a lowercase full Git SHA"):
                        operation(Path("/untrusted/broker-src"), caller_sha)
                    git_run.assert_not_called()

    def test_caller_workflow_validates_all_cli_shas_before_any_git_read(self) -> None:
        valid_values = {
            "caller_sha": "d" * 40,
            "broker_sha": "e" * 40,
            "framework_sha": "f" * 40,
        }
        for field in valid_values:
            with self.subTest(field=field):
                values = dict(valid_values)
                values[field] = "not-a-commit"
                arguments = argparse.Namespace(**values)
                with mock.patch.object(BROKER.subprocess, "run") as git_run:
                    with self.assertRaisesRegex(BROKER.BrokerError, "lowercase full Git SHA"):
                        BROKER.validate_caller_workflow(arguments)
                git_run.assert_not_called()

    def git_fixture(self, repository: Path, *arguments: str, input_data: bytes | None = None) -> bytes:
        completed = subprocess.run(
            ["git", "-C", os.fspath(repository), *arguments],
            check=True,
            input=input_data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return completed.stdout

    def commit_caller_workflow_fixture(
        self,
        repository: Path,
        content: bytes | None,
        *,
        mode: int = 0o644,
        symlink: bool = False,
    ) -> str:
        self.git_fixture(repository, "init", "--quiet", "--initial-branch=master")
        self.git_fixture(repository, "config", "user.email", "broker-test@example.invalid")
        self.git_fixture(repository, "config", "user.name", "Broker Test")
        workflow_path = repository / BROKER.EXPECTED_CALLER_WORKFLOW_PATH
        workflow_path.parent.mkdir(parents=True)
        if content is None:
            (repository / "README").write_text("fixture\n", encoding="utf-8")
        elif symlink:
            target = workflow_path.with_name("other.yml")
            target.write_bytes(content)
            workflow_path.symlink_to(target.name)
        else:
            workflow_path.write_bytes(content)
            workflow_path.chmod(mode)
        self.git_fixture(repository, "add", "--all")
        self.git_fixture(repository, "commit", "--quiet", "-m", "caller fixture")
        return self.git_fixture(repository, "rev-parse", "HEAD").decode("ascii").strip()

    def test_caller_workflow_uses_the_committed_blob_not_a_mutable_worktree_copy(self) -> None:
        raw = (source_path('.github/workflows/run-protected-nginx-root-broker.yml', root=ROOT)).read_bytes()
        broker_sha = "8ae707d72f1a8acb25d239e55e28a73cbc7522b1"
        framework_sha = "99a7985c1be92a2297b1b59208f64df6768f2cbf"
        with tempfile.TemporaryDirectory(prefix="nginx-root-broker-git-") as temporary:
            repository = Path(temporary) / "broker-src"
            repository.mkdir()
            caller_sha = self.commit_caller_workflow_fixture(repository, raw)
            mutable_copy = repository / BROKER.EXPECTED_CALLER_WORKFLOW_PATH
            mutable_copy.write_text("jobs: {}\n", encoding="utf-8")

            with mock.patch.object(BROKER.Path, "cwd", return_value=repository):
                BROKER.validate_caller_workflow(
                    argparse.Namespace(
                        caller_sha=caller_sha,
                        broker_sha=broker_sha,
                        framework_sha=framework_sha,
                    )
                )

    def test_caller_workflow_real_git_object_rejections_are_fail_closed(self) -> None:
        valid = (source_path('.github/workflows/run-protected-nginx-root-broker.yml', root=ROOT)).read_bytes()
        mutable_pin = valid.replace(
            b"@8ae707d72f1a8acb25d239e55e28a73cbc7522b1",
            b"@master",
        )
        fixtures = {
            "absent path": (None, 0o644, False, "regular Git blob"),
            "executable workflow": (valid, 0o755, False, "regular Git blob"),
            "symlink workflow": (valid, 0o644, True, "regular Git blob"),
            "oversized workflow": (
                b"#" * (BROKER.MAX_CALLER_WORKFLOW_BYTES + 1),
                0o644,
                False,
                "exceeds the maximum",
            ),
        }
        for name, (content, mode, symlink, message) in fixtures.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory(
                prefix="nginx-root-broker-git-"
            ) as temporary:
                repository = Path(temporary) / "broker-src"
                repository.mkdir()
                caller_sha = self.commit_caller_workflow_fixture(
                    repository,
                    content,
                    mode=mode,
                    symlink=symlink,
                )
                with self.assertRaisesRegex(BROKER.BrokerError, message):
                    BROKER.read_caller_workflow_blob(repository, caller_sha)

        with tempfile.TemporaryDirectory(prefix="nginx-root-broker-git-") as temporary:
            repository = Path(temporary) / "broker-src"
            repository.mkdir()
            caller_sha = self.commit_caller_workflow_fixture(repository, mutable_pin)
            raw = BROKER.read_caller_workflow_blob(repository, caller_sha)
            document = BROKER.parse_restricted_caller_workflow_yaml(raw)
            with self.assertRaisesRegex(BROKER.BrokerError, "immutable protected broker SHA"):
                BROKER.validate_caller_workflow_document(
                    document,
                    broker_sha="8ae707d72f1a8acb25d239e55e28a73cbc7522b1",
                    framework_sha="99a7985c1be92a2297b1b59208f64df6768f2cbf",
                )

        with tempfile.TemporaryDirectory(prefix="nginx-root-broker-git-") as temporary:
            repository = Path(temporary) / "broker-src"
            repository.mkdir()
            self.commit_caller_workflow_fixture(repository, valid)
            non_commit = self.git_fixture(
                repository,
                "hash-object",
                "-w",
                "--stdin",
                input_data=b"not a commit\n",
            ).decode("ascii").strip()
            with self.assertRaisesRegex(BROKER.BrokerError, "does not name a commit"):
                BROKER.read_caller_workflow_blob(repository, non_commit)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
