"""Unit contracts for the protected exact-head NGINX root launcher."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock


ROOT = connector_root()
MODULE_PATH = source_path('ci/runtime/broker/nginx_exact_head_root_launcher.py', root=ROOT)
from modsecurity_connector_ci.runtime.broker import nginx_exact_head_root_launcher as LAUNCHER


HEAD = "a" * 40
BASE = "b" * 40


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")


def dispatcher_payload() -> dict[str, object]:
    return {
        "schema_version": 1,
        "trusted_dispatcher_base_sha": BASE,
        "run_id": "run-20260904-01",
        "pr_number": 354,
        "tested_pr_head": HEAD,
        "tested_pr_head_ref": "review/exact-head",
        "tested_pr_head_repository": "Easton97-Jens/ModSecurity-conector",
        "tested_pr_base": BASE,
        "tested_pr_base_ref": "master",
        "tested_pr_base_repository": "Easton97-Jens/ModSecurity-conector",
        "draft": True,
        "state": "open",
        "merged": False,
    }


def artifact_record(name: str, content: bytes) -> dict[str, object]:
    return {
        "filename": name,
        "sha256": hashlib.sha256(content).hexdigest(),
        "size": len(content),
    }


def candidate_payload(artifacts: dict[str, bytes]) -> dict[str, object]:
    return {
        "schema_version": 1,
        "run_id": "run-20260904-01",
        "tested_pr_head": HEAD,
        "trusted_dispatcher_base_sha": BASE,
        "nginx_version": LAUNCHER.EXPECTED_NGINX_VERSION,
        "nginx_source_digest": LAUNCHER.EXPECTED_NGINX_SOURCE_DIGEST,
        "artifacts": {
            "nginx": artifact_record("nginx", artifacts["nginx"]),
            "module": artifact_record(
                "ngx_http_modsecurity_module.so", artifacts["module"]
            ),
            "library": artifact_record("libmodsecurity.so.3", artifacts["library"]),
        },
        "producer": {
            "kind": "unprivileged-exact-head-build",
            "runner_uid": 1001,
            "runner_gid": 1001,
        },
    }


def event(transaction_id: str) -> str:
    return json.dumps(
        {
            "event": "request_rule_match",
            "connector": "nginx",
            "integration_mode": "native-nginx-http-module",
            "rule_id": "1000001",
            "transaction_id": transaction_id,
            "sequence": 1,
            "previous_event_hash": 2,
            "event_hash": 3,
        },
        separators=(",", ":"),
    ) + "\n"


def write_mode_evidence(cell: Path, mode: str, transaction_id: str) -> None:
    runtime = cell / mode / "runtime"
    logs = cell / mode / "logs"
    runtime.mkdir(parents=True)
    logs.mkdir(parents=True)
    (logs / "events.jsonl").write_text(event(transaction_id), encoding="utf-8")
    (runtime / "http-status.txt").write_text("403\n", encoding="ascii")
    callback = (
        f"modsecurity_transaction_id={transaction_id} rule 1000001\n"
        if mode == "on"
        else "unrelated diagnostic\n"
    )
    (logs / "error.log").write_text(callback, encoding="utf-8")


class RootLauncherContractTests(unittest.TestCase):
    def test_retained_proc_cell_fd_is_a_working_root_side_read_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cell = Path(temporary) / "cell"
            cell.mkdir()
            (cell / "proof.txt").write_bytes(b"original\n")
            descriptor = os.open(cell, os.O_RDONLY | os.O_DIRECTORY)
            try:
                proc_cell = Path(f"/proc/self/fd/{descriptor}")
                self.assertEqual(LAUNCHER.bounded_file(proc_cell / "proof.txt", 64), b"original\n")
                self.assertEqual(
                    LAUNCHER.contained(proc_cell / "proof.txt", proc_cell, "retained cell"),
                    proc_cell / "proof.txt",
                )
                nested_root = proc_cell / "nested"
                (cell / "nested").mkdir()
                self.assertEqual(
                    LAUNCHER.contained(nested_root / "proof.txt", proc_cell, "nested retained cell"),
                    nested_root / "proof.txt",
                )
                with self.assertRaises(LAUNCHER.LauncherError):
                    LAUNCHER.contained(proc_cell / "nested" / ".." / "proof.txt", proc_cell, "escape")
                LAUNCHER.require_root_owned_directory(proc_cell, 0o755, "retained cell")
                LAUNCHER.atomic_json(proc_cell / "control.json", {"safe": True})
                self.assertEqual(json.loads((cell / "control.json").read_text()), {"safe": True})
                for malformed in (Path(f"/proc/self/fd/{descriptor}/../proof.txt"), Path("/proc/self/fd/999999/proof.txt")):
                    with self.subTest(malformed=malformed), self.assertRaises(LAUNCHER.LauncherError):
                        LAUNCHER.bounded_file(malformed, 64)
            finally:
                os.close(descriptor)

    def test_retained_control_parent_rejects_a_symlink_component(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cell = Path(temporary) / "cell"
            outside = Path(temporary) / "outside"
            cell.mkdir()
            outside.mkdir()
            (cell / "escape").symlink_to(outside, target_is_directory=True)
            descriptor = os.open(cell, os.O_RDONLY | os.O_DIRECTORY)
            target = Path(f"/proc/self/fd/{descriptor}") / "escape" / "release.json"
            try:
                with self.assertRaises(LAUNCHER.LauncherError):
                    LAUNCHER.atomic_json(target, {"safe": True})
                self.assertFalse((outside / "release.json").exists())
            finally:
                os.close(descriptor)

    def test_cleanup_replacement_is_rejected_without_deleting_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            original = parent / "owned"
            original.mkdir()
            (original / "safe.txt").write_text("safe", encoding="ascii")
            descriptor = os.open(original, os.O_RDONLY | os.O_DIRECTORY)
            parent_descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                identity = os.fstat(descriptor)
                original.rename(parent / "moved")
                replacement = parent / "owned"
                replacement.mkdir()
                (replacement / "attacker.txt").write_text("keep", encoding="ascii")
                with self.assertRaisesRegex(LAUNCHER.LauncherError, "replaced"):
                    LAUNCHER._remove_tree_at(
                        parent_descriptor, "owned",
                        (identity.st_dev, identity.st_ino),
                    )
                self.assertTrue((replacement / "attacker.txt").exists())
            finally:
                os.close(descriptor)
                os.close(parent_descriptor)

    def test_cleanup_parent_requires_a_private_root_container(self) -> None:
        private = types.SimpleNamespace(
            st_mode=stat.S_IFDIR | 0o700, st_uid=0, st_gid=0
        )
        with mock.patch.object(LAUNCHER.os, "fstat", return_value=private):
            self.assertIsNone(LAUNCHER._require_private_root_cleanup_parent(71))
        for unsafe in (
            types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0),
            types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=1000, st_gid=0),
            types.SimpleNamespace(st_mode=stat.S_IFREG | 0o700, st_uid=0, st_gid=0),
        ):
            with self.subTest(unsafe=unsafe), mock.patch.object(
                LAUNCHER.os, "fstat", return_value=unsafe
            ):
                with self.assertRaisesRegex(
                    LAUNCHER.LauncherError,
                    "private root-owned",
                ):
                    LAUNCHER._require_private_root_cleanup_parent(71)

    def test_cleanup_retains_scratch_when_parent_is_not_private(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary) / "replaceable-parent"
            scratch = parent / LAUNCHER.ROOT_RUN_NAME
            scratch.mkdir(parents=True)
            parent.chmod(0o755)
            state = LAUNCHER.LauncherState(
                scratch_fd=os.open(scratch, os.O_RDONLY | os.O_DIRECTORY),
                scratch_parent_fd=os.open(parent, os.O_RDONLY | os.O_DIRECTORY),
            )
            errors = LAUNCHER._cleanup_launcher(state)
            self.assertEqual(len(errors), 1)
            self.assertIn("private root-owned", errors[0])
            self.assertTrue(scratch.is_dir())

    def test_cleanup_uses_private_container_at_final_sink_and_preserves_runner_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runner_parent = Path(temporary) / "runner-parent"
            container = runner_parent / "root-container"
            scratch = container / LAUNCHER.ROOT_RUN_NAME
            replacement = runner_parent / LAUNCHER.ROOT_RUN_NAME
            scratch.mkdir(parents=True)
            container.chmod(0o700)
            replacement.mkdir()
            (replacement / "attacker.txt").write_text("keep", encoding="ascii")
            container_fd = os.open(container, os.O_RDONLY | os.O_DIRECTORY)
            state = LAUNCHER.LauncherState(
                scratch_fd=os.open(scratch, os.O_RDONLY | os.O_DIRECTORY),
                scratch_parent_fd=os.dup(container_fd),
                scratch_container_fd=container_fd,
                scratch_container_parent_fd=os.open(
                    runner_parent, os.O_RDONLY | os.O_DIRECTORY
                ),
            )
            real_rmdir = os.rmdir
            attack_triggered = False

            def replace_runner_entry_before_final_rmdir(
                name: str, *, dir_fd: int
            ) -> None:
                nonlocal attack_triggered
                if name == LAUNCHER.ROOT_RUN_NAME:
                    self.assertEqual(dir_fd, state.scratch_parent_fd)
                    replacement.rename(runner_parent / "replaced-runner-entry")
                    replacement.mkdir()
                    (replacement / "attacker.txt").write_text(
                        "keep", encoding="ascii"
                    )
                    attack_triggered = True
                real_rmdir(name, dir_fd=dir_fd)

            with mock.patch.object(
                LAUNCHER, "_require_private_root_cleanup_parent"
            ) as require_private_parent, mock.patch.object(
                LAUNCHER.os,
                "rmdir",
                side_effect=replace_runner_entry_before_final_rmdir,
            ):
                self.assertEqual(LAUNCHER._cleanup_launcher(state), [])
            require_private_parent.assert_called_once_with(state.scratch_parent_fd)
            self.assertTrue(attack_triggered)
            self.assertFalse(scratch.exists())
            self.assertTrue((replacement / "attacker.txt").exists())

    def test_scratch_container_name_is_root_selected_and_fresh(self) -> None:
        with mock.patch.object(LAUNCHER.secrets, "token_hex", return_value="a" * 32):
            self.assertEqual(
                LAUNCHER.private_scratch_container_name(),
                LAUNCHER.ROOT_RUN_NAME + "-container-" + "a" * 32,
            )

    def test_identity_cleanup_requires_exact_captured_uid_gid_and_primary_group(self) -> None:
        user = types.SimpleNamespace(pw_uid=2000, pw_gid=2001)
        group = types.SimpleNamespace(gr_gid=2001)
        with mock.patch.object(LAUNCHER.pwd, "getpwnam", return_value=user), mock.patch.object(
            LAUNCHER.grp, "getgrnam", return_value=group
        ), mock.patch.object(LAUNCHER, "run_checked") as run_checked:
            LAUNCHER.cleanup_identity("mscnxw_x", "mscnxg_x", 2000, 2001)
            self.assertEqual(run_checked.call_count, 2)
        for uid, gid in ((None, 2001), (2000, None)):
            with self.subTest(uid=uid, gid=gid), mock.patch.object(LAUNCHER, "run_checked") as run_checked:
                with self.assertRaises(LAUNCHER.LauncherError):
                    LAUNCHER.cleanup_identity("mscnxw_x", "mscnxg_x", uid, gid)
                run_checked.assert_not_called()
        cases = (
            (types.SimpleNamespace(pw_uid=3000, pw_gid=2001), group, "uid"),
            (types.SimpleNamespace(pw_uid=2000, pw_gid=3001), group, "primary gid"),
            (user, types.SimpleNamespace(gr_gid=3001), "group gid"),
        )
        for current_user, current_group, label in cases:
            with self.subTest(label=label), mock.patch.object(
                LAUNCHER.pwd, "getpwnam", return_value=current_user
            ), mock.patch.object(
                LAUNCHER.grp, "getgrnam", return_value=current_group
            ), mock.patch.object(LAUNCHER, "run_checked") as run_checked:
                with self.assertRaisesRegex(LAUNCHER.LauncherError, "replaced"):
                    LAUNCHER.cleanup_identity("mscnxw_x", "mscnxg_x", 2000, 2001)
                run_checked.assert_not_called()

    def test_identity_creation_refuses_group_replacement_during_rollback(self) -> None:
        created = types.SimpleNamespace(gr_gid=2001)
        replacement = types.SimpleNamespace(gr_gid=3001)
        with mock.patch.object(LAUNCHER.pwd, "getpwall", return_value=[]), mock.patch.object(
            LAUNCHER.grp, "getgrall", return_value=[]
        ), mock.patch.object(
            LAUNCHER.grp, "getgrnam", side_effect=(created, replacement)
        ), mock.patch.object(
            LAUNCHER, "run_checked", side_effect=(None, OSError("useradd failed"))
        ) as run_checked:
            with self.assertRaisesRegex(LAUNCHER.LauncherError, "group rollback failed"):
                LAUNCHER.create_identity("abc")
        self.assertEqual(run_checked.call_count, 2)

    def test_subordinate_cleanup_refuses_replaced_runner_identity(self) -> None:
        mapping = LAUNCHER.SubordinateMapping("runner", 1000, 2000, 2001, True, True)
        replacement = types.SimpleNamespace(pw_uid=3000)
        with mock.patch.object(LAUNCHER.pwd, "getpwnam", return_value=replacement), mock.patch.object(
            LAUNCHER, "run_checked"
        ) as run_checked:
            with self.assertRaises(LAUNCHER.LauncherError):
                LAUNCHER.cleanup_subordinate_mapping(mapping)
            run_checked.assert_not_called()

    def test_main_converts_subprocess_timeouts_to_controlled_failure(self) -> None:
        with mock.patch.object(LAUNCHER.os, "geteuid", return_value=0), mock.patch.object(
            LAUNCHER, "parse_args", return_value=mock.Mock()
        ), mock.patch.object(
            LAUNCHER, "_prepare_launcher", side_effect=subprocess.TimeoutExpired("helper", 1)
        ), mock.patch.object(LAUNCHER, "_cleanup_launcher", return_value=[]) as cleanup, mock.patch.object(
            LAUNCHER.sys, "stderr", new_callable=io.StringIO
        ):
            self.assertEqual(LAUNCHER.main(["ignored"]), 1)
        cleanup.assert_called_once()

    def test_wait_mode_uses_nested_retained_fd_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cell = Path(temporary) / "cell"
            (cell / "on" / "control").mkdir(parents=True)
            (cell / "on" / "runtime").mkdir()
            descriptor = os.open(cell, os.O_RDONLY | os.O_DIRECTORY)
            process = mock.Mock()
            process.poll.return_value = None
            (cell / "on" / "runtime" / "ready.json").write_text(
                json.dumps({"mode": "on"}), encoding="ascii"
            )
            try:
                with mock.patch.object(LAUNCHER, "_require_root_control_directory"), mock.patch.object(
                    LAUNCHER, "validate_generated_config"
                ), mock.patch.object(
                    LAUNCHER, "validate_identity", return_value={"master_pidfd": 9}
                ), mock.patch.object(LAUNCHER, "atomic_json") as publish:
                    result = LAUNCHER.wait_mode(
                        Path(f"/proc/self/fd/{descriptor}"), "on",
                        LAUNCHER.IdentityExpectations(1, 1, 2, 2),
                        Path("/candidate/nginx"), {}, Path("/candidate/module"),
                        "worker", "group", process,
                    )
                self.assertEqual(result["master_pidfd"], 9)
                publish.assert_called_once()
            finally:
                os.close(descriptor)

    def test_owned_child_directory_is_created_descriptor_relative_and_verified(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                child = LAUNCHER.create_owned_child_directory(
                    parent, "fresh", os.getuid(), os.getgid(), 0o700,
                    "test child", os.getuid(), os.getgid(), parent_descriptor=descriptor
                )
                self.assertEqual(child, parent / "fresh")
                metadata = child.lstat()
                self.assertTrue(stat.S_ISDIR(metadata.st_mode))
                self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o700)
                user_id = os.getuid()
                group_id = os.getgid()
                with self.assertRaises(LAUNCHER.LauncherError):
                    LAUNCHER.create_owned_child_directory(
                        parent, "fresh", user_id, group_id, 0o700,
                        "duplicate child", user_id, group_id, parent_descriptor=descriptor
                    )
            finally:
                os.close(descriptor)

    def test_owned_child_directory_rejects_unsafe_leaf_before_creation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                user_id = os.getuid()
                group_id = os.getgid()
                for unsafe in ("", ".", "..", "escape/child", "line\nfeed", "\x00", "ä", "a" * 256):
                    with self.subTest(unsafe=repr(unsafe)):
                        with self.assertRaises(LAUNCHER.LauncherError):
                            LAUNCHER.create_owned_child_directory(
                                parent, unsafe, user_id, group_id, 0o700,
                                "unsafe child", user_id, group_id, parent_descriptor=descriptor
                            )
                        self.assertEqual(list(parent.iterdir()), [])
            finally:
                os.close(descriptor)

    def test_root_evidence_path_requires_fixed_protocol_leaf(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            expected = parent / LAUNCHER.ROOT_EVIDENCE_DIRECTORY_NAME
            alternate = str(parent / "other-evidence")
            self.assertEqual(LAUNCHER.root_evidence_path(str(expected)), expected)
            with self.assertRaises(LAUNCHER.LauncherError):
                LAUNCHER.root_evidence_path(alternate)

    def test_owned_child_directory_uses_retained_parent_after_path_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parent = root / "parent"
            parent.mkdir()
            descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
            moved = root / "moved"
            try:
                parent.rename(moved)
                parent.mkdir()
                LAUNCHER.create_owned_child_directory(
                    parent, "fresh", os.getuid(), os.getgid(), 0o700,
                    "retained child", os.getuid(), os.getgid(), parent_descriptor=descriptor
                )
                self.assertTrue((moved / "fresh").is_dir())
                self.assertFalse((parent / "fresh").exists())
            finally:
                os.close(descriptor)

    def test_path_containment_rejects_symlink_escape_and_parent_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "cell"
            outside = base / "outside"
            root.mkdir()
            outside.mkdir()
            (root / "escape").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(LAUNCHER.LauncherError):
                LAUNCHER.contained(root / "escape" / "file", root, "test path")
            with self.assertRaises(LAUNCHER.LauncherError):
                LAUNCHER.contained(root / ".." / "outside" / "file", root, "test path")

    def test_dispatcher_and_candidate_manifest_bind_the_same_exact_head(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            dispatcher_path = root / "dispatcher.json"
            candidate_path = root / "candidate.json"
            artifacts = {"nginx": b"nginx", "module": b"module", "library": b"library"}
            write_json(dispatcher_path, dispatcher_payload())
            dispatcher = LAUNCHER.dispatcher_manifest(dispatcher_path, BASE)
            write_json(candidate_path, candidate_payload(artifacts))
            self.assertEqual(
                LAUNCHER.candidate_manifest(candidate_path, dispatcher)["tested_pr_head"],
                HEAD,
            )
            bad = candidate_payload(artifacts)
            bad["tested_pr_head"] = "c" * 40
            write_json(candidate_path, bad)
            with self.assertRaisesRegex(LAUNCHER.LauncherError, "head"):
                LAUNCHER.candidate_manifest(candidate_path, dispatcher)
            bad_dispatcher = dispatcher_payload()
            bad_dispatcher["draft"] = False
            write_json(dispatcher_path, bad_dispatcher)
            with self.assertRaisesRegex(LAUNCHER.LauncherError, "eligible canonical draft"):
                LAUNCHER.dispatcher_manifest(dispatcher_path, BASE)
            bad_dispatcher = dispatcher_payload()
            bad_dispatcher["schema_version"] = True
            write_json(dispatcher_path, bad_dispatcher)
            with self.assertRaisesRegex(LAUNCHER.LauncherError, "schema is unsupported"):
                LAUNCHER.dispatcher_manifest(dispatcher_path, BASE)
            bad_candidate = candidate_payload(artifacts)
            bad_candidate["schema_version"] = True
            dispatcher = dispatcher_payload()
            write_json(candidate_path, bad_candidate)
            with self.assertRaisesRegex(LAUNCHER.LauncherError, "schema is unsupported"):
                LAUNCHER.candidate_manifest(candidate_path, dispatcher)

    def test_rejects_previous_release_and_crossed_candidate_pins(self) -> None:
        previous_digest = "e951607d534836624bd36b6b45a71dbfb055237deae3738da6bbf3270dada279"
        current_digest = "974ed5298a5e398e008704ed5db284e655fc270c596493dbccada452448fc9f1"
        with tempfile.TemporaryDirectory() as temporary:
            candidate_path = Path(temporary) / "candidate.json"
            artifacts = {"nginx": b"nginx", "module": b"module", "library": b"library"}
            for version, digest in (
                ("1.31.5", previous_digest),
                ("1.31.6", previous_digest),
                ("1.31.5", current_digest),
            ):
                with self.subTest(version=version, digest=digest):
                    candidate = candidate_payload(artifacts)
                    candidate.update(nginx_version=version, nginx_source_digest=digest)
                    write_json(candidate_path, candidate)
                    dispatcher = dispatcher_payload()
                    with self.assertRaisesRegex(LAUNCHER.LauncherError, "does not bind pinned NGINX"):
                        LAUNCHER.candidate_manifest(candidate_path, dispatcher)

    def test_security_identifiers_accept_ascii_digits_only(self) -> None:
        with self.assertRaisesRegex(LAUNCHER.LauncherError, "40-character SHA"):
            LAUNCHER.require_sha40("a" * 39 + "١", "test SHA")
        self.assertIsNone(LAUNCHER.TX_RE.fullmatch("nginx-exact-head-١-1-1"))

    def test_launcher_does_not_catch_process_control_exceptions_broadly(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertNotIn("BaseException", source)

    def test_admission_requires_only_manifested_single_link_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifacts = {
                "nginx": b"native nginx image",
                "module": b"connector module",
                "library": b"modsecurity library",
            }
            names = {
                "nginx": "nginx",
                "module": "ngx_http_modsecurity_module.so",
                "library": "libmodsecurity.so.3",
            }
            for key, name in names.items():
                (root / name).write_bytes(artifacts[key])
            manifest = candidate_payload(artifacts)
            manifest_path = root / "artifact-manifest.json"
            write_json(manifest_path, manifest)
            validated = LAUNCHER.candidate_manifest(manifest_path, dispatcher_payload())
            identities, descriptors = LAUNCHER.admit_candidate_bundle(root, validated)
            try:
                self.assertEqual(
                    identities["module"]["sha256"],
                    manifest["artifacts"]["module"]["sha256"],
                )
                (root / "nginx").write_bytes(b"replacement")
                self.assertNotEqual(
                    identities["nginx"],
                    LAUNCHER.admitted_artifact_identity(descriptors["nginx"], "nginx"),
                )
            finally:
                for descriptor in descriptors.values():
                    LAUNCHER.os.close(descriptor)
            (root / "nginx_exact_head_result_collector.py").write_text(
                "candidate replacement attempt\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(LAUNCHER.LauncherError, "exactly"):
                LAUNCHER.admit_candidate_bundle(root, validated)

    def test_admitted_artifact_rejects_symlink_and_hardlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = root / "library"
            artifact.write_bytes(b"library")
            linked = root / "library-link"
            linked.symlink_to(artifact)
            with self.assertRaises(LAUNCHER.LauncherError):
                LAUNCHER.admitted_artifact(linked, "library")
            hardlinked = root / "library-hardlink"
            hardlinked.hardlink_to(artifact)
            with self.assertRaises(LAUNCHER.LauncherError):
                LAUNCHER.admitted_artifact(artifact, "library")

    def test_replacement_and_metadata_race_of_each_native_artifact_are_detected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("nginx", "ngx_http_modsecurity_module.so", "libmodsecurity.so.3"):
                with self.subTest(name=name):
                    artifact = root / name
                    artifact.write_bytes(f"first-{name}".encode("ascii"))
                    descriptor, original = LAUNCHER.admitted_artifact_descriptor(artifact, name)
                    try:
                        artifact.write_bytes(f"second-{name}".encode("ascii"))
                        self.assertNotEqual(
                            original,
                            LAUNCHER.admitted_artifact_identity(descriptor, name),
                        )
                    finally:
                        LAUNCHER.os.close(descriptor)
            raced = root / "raced"
            raced.write_bytes(b"stable")
            original_stat = raced.stat()
            changed_stat = types.SimpleNamespace(
                st_mode=original_stat.st_mode,
                st_nlink=original_stat.st_nlink,
                st_size=original_stat.st_size,
                st_dev=original_stat.st_dev,
                st_ino=original_stat.st_ino,
                st_mtime_ns=original_stat.st_mtime_ns + 1,
            )
            descriptor = LAUNCHER.open_regular_no_follow(raced, "raced artifact")
            try:
                with mock.patch.object(
                    LAUNCHER.os, "fstat", side_effect=(original_stat, changed_stat)
                ):
                    with self.assertRaisesRegex(LAUNCHER.LauncherError, "changed"):
                        LAUNCHER.admitted_artifact_identity(descriptor, "raced artifact")
            finally:
                LAUNCHER.os.close(descriptor)

    def test_generated_configuration_has_no_include_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cell = Path(temporary)
            mode = cell / "on"
            config_root = mode / "config"
            runtime_root = mode / "runtime"
            logs_root = mode / "logs"
            docroot = config_root / "docroot"
            docroot.mkdir(parents=True)
            runtime_root.mkdir()
            logs_root.mkdir()
            binary = Path("/candidate/nginx")
            module = Path("/candidate/ngx_http_modsecurity_module.so")
            config = config_root / "nginx.conf"
            rules = config_root / "modsecurity.conf"
            pid_path = runtime_root / "nginx.pid"
            pid_path.write_text("55\n", encoding="ascii")
            rules.write_text(
                'SecRuleEngine On\nSecRule REQUEST_URI "@streq /exact-head" '
                '"id:1000001,phase:1,deny,status:403,log"\n',
                encoding="utf-8",
            )
            (docroot / "index.html").write_text("exact-head-ok\n", encoding="utf-8")
            config.write_text(
                "\n".join(
                    (
                        f'load_module "{module}";',
                        "daemon off;",
                        "worker_processes 1;",
                        "user worker worker-group;",
                        f'pid "{pid_path}";',
                        f'error_log "{logs_root / "error.log"}" notice;',
                        "events { worker_connections 32; }",
                        "http { server {",
                        f'access_log "{logs_root / "access.log"}";',
                        "listen 127.0.0.1:18081;",
                        "server_name exact-head.local;",
                        "modsecurity on;",
                        "modsecurity_use_error_log on;",
                        f'modsecurity_rules_file "{rules}";',
                        f'modsecurity_phase4_log "{logs_root / "events.jsonl"}";',
                        'modsecurity_transaction_id "nginx-exact-head-$pid-$connection-$connection_requests";',
                        f'root "{docroot}";',
                        "return 200 exact-head-ok;",
                        "} }",
                    )
                ) + "\n",
                encoding="utf-8",
            )
            ready = {
                "schema_version": 1,
                "binary_path": str(binary),
                "config_path": str(config),
                "pid_path": str(pid_path),
                "master_pid": 55,
            }
            valid_config = config.read_text(encoding="utf-8")
            with mock.patch.object(LAUNCHER, "require_root_owned_directory"), mock.patch.object(
                LAUNCHER, "require_root_owned_file"
            ):
                LAUNCHER.validate_generated_config(
                    ready, cell, "on", binary, module, "worker", "worker-group"
                )
                wrong_version = dict(ready, schema_version=True)
                with self.assertRaisesRegex(LAUNCHER.LauncherError, "readiness"):
                    LAUNCHER.validate_generated_config(
                        wrong_version, cell, "on", binary, module, "worker", "worker-group"
                    )
                config.write_text(
                    config.read_text(encoding="utf-8")
                    + 'include "/etc/nginx/conf.d/*.conf";\n',
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(LAUNCHER.LauncherError, "unsafe runtime directive"):
                    LAUNCHER.validate_generated_config(
                        ready, cell, "on", binary, module, "worker", "worker-group"
                    )
                config.write_text(
                    config.read_text(encoding="utf-8").replace(
                        'include "/etc/nginx/conf.d/*.conf";',
                        'include "../../candidate.conf";',
                    ),
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(LAUNCHER.LauncherError, "unsafe runtime directive"):
                    LAUNCHER.validate_generated_config(
                        ready, cell, "on", binary, module, "worker", "worker-group"
                    )
                config.write_text(valid_config, encoding="utf-8")
                escaped = dict(ready, config_path=str(cell / "outside.conf"))
                with self.assertRaisesRegex(LAUNCHER.LauncherError, "component is missing"):
                    LAUNCHER.validate_generated_config(
                        escaped, cell, "on", binary, module, "worker", "worker-group"
                    )
                other_pid = mode / "other.pid"
                other_pid.write_text("55\n", encoding="ascii")
                wrong_pid = dict(ready, pid_path=str(other_pid))
                with self.assertRaisesRegex(LAUNCHER.LauncherError, "fixed runtime PID path"):
                    LAUNCHER.validate_generated_config(
                        wrong_pid, cell, "on", binary, module, "worker", "worker-group"
                    )

    def test_trusted_cell_generation_uses_real_newlines_and_rejects_nginx_metacharacters(self) -> None:
        writes: dict[str, bytes] = {}
        with mock.patch.object(LAUNCHER, "root_owned_directory") as root_owned_directory, mock.patch.object(
            LAUNCHER, "create_runner_owned_directory"
        ), mock.patch.object(
            LAUNCHER,
            "root_owned_file",
            side_effect=lambda path, content, mode=0o444: writes.__setitem__(
                str(path), content
            ),
        ):
            LAUNCHER.prepare_trusted_cells(
                Path("/task/cell"),
                Path("/candidate/ngx_http_modsecurity_module.so"),
                "mscnxw_abc",
                "mscnxg_abc",
                1000,
                1000,
            )
        root_owned_directory.assert_has_calls(
            [
                mock.call(Path("/task/cell/on/control"), 0o755),
                mock.call(Path("/task/cell/off/control"), 0o755),
            ],
            any_order=True,
        )
        on_config = writes["/task/cell/on/config/nginx.conf"]
        self.assertIn(b"modsecurity_use_error_log on;\n", on_config)
        self.assertIn(
            b'nginx-exact-head-$pid-$connection-$connection_requests',
            on_config,
        )
        self.assertNotIn(b"\\n", on_config)
        self.assertEqual(
            writes["/task/cell/on/config/modsecurity.conf"],
            b"SecRuleEngine On\n"
            b'SecRule REQUEST_URI "@streq /exact-head" '
            b'"id:1000001,phase:1,deny,status:403,log"\n',
        )
        for unsafe in ('/task/has\\slash', '/task/has\nnewline', '/task/has;directive'):
            with self.subTest(unsafe=unsafe):
                with self.assertRaises(LAUNCHER.LauncherError):
                    LAUNCHER.nginx_literal(unsafe, "unsafe test path")

    def test_sandbox_config_uses_fixed_paths_not_host_candidate_or_cell(self) -> None:
        writes: dict[str, bytes] = {}
        with mock.patch.object(LAUNCHER, "root_owned_directory"), mock.patch.object(
            LAUNCHER, "create_runner_owned_directory"
        ), mock.patch.object(
            LAUNCHER, "root_owned_file",
            side_effect=lambda path, content, mode=0o444: writes.__setitem__(str(path), content),
        ):
            LAUNCHER.prepare_trusted_cells(
                Path("/host/cell"), Path("/candidate/ngx_http_modsecurity_module.so"),
                "mscnxw_abc", "mscnxg_abc", 1000, 1000,
                sandbox_cell=LAUNCHER.SANDBOX_CELL_ROOT,
            )
        config = writes["/host/cell/on/config/nginx.conf"].decode("utf-8")
        self.assertIn('load_module "/candidate/ngx_http_modsecurity_module.so";', config)
        self.assertIn('pid "/cell/on/runtime/nginx.pid";', config)
        self.assertNotIn("/host/cell", config)

    def test_wait_mode_validates_before_root_release(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cell = Path(temporary)
            mode = cell / "on"
            (mode / "runtime").mkdir(parents=True)
            control = mode / "control"
            control.mkdir()
            control.chmod(0o755)
            write_json(
                mode / "runtime" / "ready.json",
                {"schema_version": 1, "mode": "on", "master_pid": 55, "worker_pid": 56},
            )
            process = mock.Mock()
            process.poll.return_value = None
            expected = LAUNCHER.IdentityExpectations(1000, 1000, 2000, 2000)
            identity = {
                "master_pid": 100,
                "worker_pid": 101,
                "master_uid": 1000,
                "master_gid": 1000,
                "worker_uid": 2000,
                "worker_gid": 2000,
            }
            with mock.patch.object(LAUNCHER, "validate_generated_config"), mock.patch.object(
                LAUNCHER, "validate_identity", return_value=identity
            ):
                result = LAUNCHER.wait_mode(
                    cell,
                    "on",
                    expected,
                    Path("/candidate/nginx"),
                    {"device": 1, "inode": 2, "sha256": "a" * 64, "size": 1},
                    Path("/candidate/module"),
                    "worker",
                    "worker-group",
                    process,
                )
            self.assertEqual(result["worker_uid"], 2000)
            self.assertEqual((control / "release").stat().st_mode & 0o777, 0o400)

    def test_wait_mode_requires_the_root_control_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cell = Path(temporary)
            mode = cell / "on"
            (mode / "runtime").mkdir(parents=True)
            write_json(
                mode / "runtime" / "ready.json",
                {"schema_version": 1, "mode": "on", "master_pid": 55, "worker_pid": 56},
            )
            process = mock.Mock()
            process.poll.return_value = None
            expected = LAUNCHER.IdentityExpectations(1000, 1000, 2000, 2000)
            with self.assertRaises(LAUNCHER.LauncherError):
                LAUNCHER.wait_mode(
                    cell,
                    "on",
                    expected,
                    Path("/candidate/nginx"),
                    {"device": 1, "inode": 2, "sha256": "a" * 64, "size": 1},
                    Path("/candidate/module"),
                    "worker",
                    "worker-group",
                    process,
                )

    def test_wait_mode_rejects_a_writable_root_control_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cell = Path(temporary)
            mode = cell / "on"
            (mode / "runtime").mkdir(parents=True)
            control = mode / "control"
            control.mkdir()
            control.chmod(0o777)
            process = mock.Mock()
            process.poll.return_value = None
            expected = LAUNCHER.IdentityExpectations(1000, 1000, 2000, 2000)
            with self.assertRaises(LAUNCHER.LauncherError):
                LAUNCHER.wait_mode(
                    cell,
                    "on",
                    expected,
                    Path("/candidate/nginx"),
                    {"device": 1, "inode": 2, "sha256": "a" * 64, "size": 1},
                    Path("/candidate/module"),
                    "worker",
                    "worker-group",
                    process,
                )

    def test_wait_mode_rejects_temporary_release_symlink_substitution(self) -> None:
        """A candidate must not redirect root metadata changes through release."""
        with tempfile.TemporaryDirectory() as temporary:
            cell = Path(temporary)
            mode = cell / "on"
            runtime = mode / "runtime"
            runtime.mkdir(parents=True)
            control = mode / "control"
            control.mkdir()
            write_json(
                runtime / "ready.json",
                {"schema_version": 1, "mode": "on", "master_pid": 55, "worker_pid": 56},
            )
            victim = cell / "host-victim"
            victim.write_text("safe", encoding="ascii")
            victim.chmod(0o644)
            process = mock.Mock()
            process.poll.return_value = None
            expected = LAUNCHER.IdentityExpectations(1000, 1000, 2000, 2000)
            identity = {
                "master_pid": 100,
                "worker_pid": 101,
                "master_uid": 1000,
                "master_gid": 1000,
                "worker_uid": 2000,
                "worker_gid": 2000,
            }
            original_replace = LAUNCHER.os.replace

            def swap_temporary(
                source: str | Path, destination: str | Path, *args: object, **kwargs: object
            ) -> None:
                temporary_path = control / Path(source).name
                if temporary_path.name.startswith(".release.tmp"):
                    temporary_path.unlink()
                    temporary_path.symlink_to(victim)
                original_replace(source, destination, *args, **kwargs)

            with mock.patch.object(LAUNCHER, "_require_root_control_directory"), mock.patch.object(
                LAUNCHER, "validate_generated_config"
            ), mock.patch.object(
                LAUNCHER, "validate_identity", return_value=identity
            ), mock.patch.object(LAUNCHER, "close_identity_pidfd"), mock.patch.object(
                LAUNCHER.os, "replace", side_effect=swap_temporary
            ):
                with self.assertRaises(LAUNCHER.LauncherError):
                    LAUNCHER.wait_mode(
                        cell,
                        "on",
                        expected,
                        Path("/candidate/nginx"),
                        {"device": 1, "inode": 2, "sha256": "a" * 64, "size": 1},
                        Path("/candidate/module"),
                        "worker",
                        "worker-group",
                        process,
                    )
            self.assertEqual(victim.stat().st_mode & 0o777, 0o644)
            self.assertFalse((control / "release").exists())
            self.assertFalse((control / "release").is_symlink())

    def test_mark_request_complete_publishes_a_fresh_fixed_control_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cell = Path(temporary)
            control = cell / "on" / "control"
            control.mkdir(parents=True)
            control.chmod(0o755)
            LAUNCHER.mark_request_complete(cell, "on", 403)
            completion = control / "request-complete.json"
            self.assertTrue(completion.is_file())
            self.assertFalse(completion.is_symlink())
            self.assertEqual(completion.stat().st_mode & 0o777, 0o400)
            self.assertEqual(
                json.loads(completion.read_text(encoding="ascii")),
                {"http_status": 403, "mode": "on"},
            )

    def test_mark_request_complete_requires_the_root_control_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cell = Path(temporary)
            (cell / "on" / "runtime").mkdir(parents=True)
            with self.assertRaises(LAUNCHER.LauncherError):
                LAUNCHER.mark_request_complete(cell, "on", 403)

    def test_mark_request_complete_rejects_a_writable_root_control_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cell = Path(temporary)
            control = cell / "on" / "control"
            control.mkdir(parents=True)
            control.chmod(0o777)
            with self.assertRaises(LAUNCHER.LauncherError):
                LAUNCHER.mark_request_complete(cell, "on", 403)

    def test_mark_request_complete_rejects_temporary_symlink_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cell = Path(temporary)
            control = cell / "on" / "control"
            control.mkdir(parents=True)
            completion = control / "request-complete.json"
            victim = cell / "host-victim"
            victim.write_text("safe", encoding="ascii")
            victim.chmod(0o644)
            original_replace = LAUNCHER.os.replace

            def swap_temporary(
                source: str | Path, destination: str | Path, *args: object, **kwargs: object
            ) -> None:
                temporary_path = control / Path(source).name
                if temporary_path.name.startswith(".request-complete.json.tmp"):
                    temporary_path.unlink()
                    temporary_path.symlink_to(victim)
                original_replace(source, destination, *args, **kwargs)

            with mock.patch.object(LAUNCHER, "_require_root_control_directory"), mock.patch.object(
                LAUNCHER.os, "replace", side_effect=swap_temporary
            ):
                with self.assertRaises(LAUNCHER.LauncherError):
                    LAUNCHER.mark_request_complete(cell, "on", 403)
            self.assertEqual(victim.stat().st_mode & 0o777, 0o644)
            self.assertFalse(completion.exists())
            self.assertFalse(completion.is_symlink())

    def test_identity_parser_checks_roles_and_admitted_inode(self) -> None:
        expected = LAUNCHER.IdentityExpectations(1000, 1000, 2000, 2000)
        master = {
            "ppid": 1,
            "uid_real": 1000,
            "uid_effective": 1000,
            "gid_real": 1000,
            "gid_effective": 1000,
        }
        worker = {
            "ppid": 100,
            "uid_real": 2000,
            "uid_effective": 2000,
            "gid_real": 2000,
            "gid_effective": 2000,
        }
        artifact = mock.Mock(st_dev=7, st_ino=9)
        admitted = {"device": 7, "inode": 9, "sha256": "a" * 64, "size": 1}
        with mock.patch.object(
            LAUNCHER, "host_pid_for_namespace_pid", side_effect=(100, 101)
        ), mock.patch.object(LAUNCHER, "status", side_effect=(master, worker, master, worker)), mock.patch.object(
            LAUNCHER.os, "stat", return_value=artifact
        ), mock.patch.object(
            LAUNCHER.os, "pidfd_open", return_value=77
        ), mock.patch.object(
            LAUNCHER, "namespace_link", side_effect=lambda pid, namespace: f"{pid}-{namespace}"
        ), mock.patch.object(
            LAUNCHER, "apparmor_label", return_value=LAUNCHER.APPARMOR_PROFILE_NAME + " (enforce)"
        ), mock.patch.object(LAUNCHER, "require_sandbox_security_state"), mock.patch.object(
            LAUNCHER, "pidfd_exited", side_effect=(False, False)
        ):
            evidence = LAUNCHER.validate_identity(
                {"master_pid": 100, "worker_pid": 101}, expected, admitted, 42
            )
        self.assertEqual(evidence["worker_uid"], 2000)
        self.assertEqual(evidence["master_pidfd"], 77)
        with mock.patch.object(
            LAUNCHER, "host_pid_for_namespace_pid", side_effect=(100, 101)
        ), mock.patch.object(LAUNCHER, "status", side_effect=(master, dict(worker, ppid=999))), mock.patch.object(
            LAUNCHER.os, "pidfd_open", return_value=77
        ), mock.patch.object(LAUNCHER, "pidfd_exited", return_value=False), mock.patch.object(LAUNCHER.os, "close"):
            with self.assertRaisesRegex(LAUNCHER.LauncherError, "direct child"):
                LAUNCHER.validate_identity(
                    {"master_pid": 100, "worker_pid": 101}, expected, admitted, 42
                )

    def test_mode_evidence_requires_fresh_jsonl_and_callback_separation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cell = Path(temporary)
            on_tx = "nginx-exact-head-700-7-1"
            off_tx = "nginx-exact-head-800-8-1"
            write_mode_evidence(cell, "on", on_tx)
            write_mode_evidence(cell, "off", off_tx)
            on = LAUNCHER.mode_evidence(cell, "on", 403)
            off = LAUNCHER.mode_evidence(cell, "off", 403)
            self.assertTrue(on["callback_observed"])
            self.assertFalse(off["callback_observed"])
            self.assertTrue(on["jsonl_observed"])
            self.assertEqual(
                on["callback_observation_source"], "candidate_scratch_untrusted"
            )
            self.assertEqual(
                on["jsonl_observation_source"], "candidate_scratch_untrusted"
            )
            self.assertEqual(
                on["http_status_observation_source"],
                "root_pidfd_network_namespace",
            )
            self.assertEqual(on["waf_decision"], off["waf_decision"])
            self.assertNotEqual(on["transaction_id"], off["transaction_id"])
            (cell / "off" / "logs" / "error.log").write_text(
                f"modsecurity_transaction_id={off_tx} rule 1000001\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(LAUNCHER.LauncherError, "off mode"):
                LAUNCHER.mode_evidence(cell, "off", 403)
            (cell / "off" / "logs" / "error.log").write_text(
                "::set-output::bad\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(LAUNCHER.LauncherError, "control text"):
                LAUNCHER.mode_evidence(cell, "off", 403)

    def test_mode_evidence_rejects_boolean_integrity_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cell = Path(temporary)
            write_mode_evidence(cell, "off", "nginx-exact-head-900-9-1")
            logs = cell / "off" / "logs"
            logs.joinpath("events.jsonl").write_text(
                event("nginx-exact-head-900-9-1").replace('"sequence":1', '"sequence":true'),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(LAUNCHER.LauncherError, "integrity"):
                LAUNCHER.mode_evidence(cell, "off", 403)

    def test_publish_evidence_contains_only_root_derived_allowlist(self) -> None:
        class Entry:
            def __init__(self, name: str) -> None:
                self.name = name

        class EvidenceRoot:
            def __init__(self) -> None:
                self.calls = 0

            def lstat(self) -> object:
                return type(
                    "Stat",
                    (),
                    {"st_mode": stat.S_IFDIR | 0o700, "st_uid": 0, "st_gid": 0},
                )()

            def iterdir(self) -> list[Entry]:
                self.calls += 1
                if self.calls == 1:
                    return []
                return [Entry(name) for name in LAUNCHER.ROOT_EVIDENCE_FILES]

            def __truediv__(self, name: str) -> Path:
                return Path("/root-evidence") / name

        identities = [
            {"mode": "on", "master_pid": 11, "worker_pid": 12, "master_uid": 1000, "master_gid": 1000, "worker_uid": 2000, "worker_gid": 2000},
            {"mode": "off", "master_pid": 21, "worker_pid": 22, "master_uid": 1000, "master_gid": 1000, "worker_uid": 2000, "worker_gid": 2000},
        ]
        modes = [
            {"mode": "on", "callback_observed": True, "jsonl_observed": True, "http_status": 403, "waf_decision": "deny", "transaction_id": "nginx-exact-head-1100-11-1"},
            {"mode": "off", "callback_observed": False, "jsonl_observed": True, "http_status": 403, "waf_decision": "deny", "transaction_id": "nginx-exact-head-2100-21-1"},
        ]
        writes: dict[str, tuple[dict[str, object], bool]] = {}
        with mock.patch.object(
            LAUNCHER,
            "write_root_owned_json",
            side_effect=lambda path, value, line_delimited=False, **kwargs: writes.__setitem__(
                path.name, (value, line_delimited)
            ),
        ):
            LAUNCHER.publish_evidence(
                EvidenceRoot(),
                dispatcher_payload(),
                LAUNCHER.IdentityExpectations(1000, 1000, 2000, 2000),
                identities,
                {"module": {"sha256": "d" * 64, "size": 7}},
                modes,
            )
        self.assertEqual(set(writes), LAUNCHER.ROOT_EVIDENCE_FILES)
        self.assertTrue(writes["on.jsonl"][1])
        self.assertFalse(writes["off.jsonl"][0]["callback_observed"])
        self.assertEqual(writes["runtime.json"][0]["tested_pr_head"], HEAD)
        self.assertEqual(writes["runtime.json"][0]["tested_pr_base"], BASE)

    def test_root_evidence_write_survives_runner_directory_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            evidence = parent / "evidence"
            outside = parent / "outside"
            evidence.mkdir()
            outside.mkdir()
            evidence_fd = os.open(evidence, os.O_RDONLY | os.O_DIRECTORY)
            try:
                moved = parent / "moved"
                evidence.rename(moved)
                evidence.symlink_to(outside, target_is_directory=True)
                LAUNCHER.write_root_owned_json(
                    evidence / "identity.json", {"safe": True}, directory_fd=evidence_fd
                )
                self.assertTrue((moved / "identity.json").is_file())
                self.assertFalse((outside / "identity.json").exists())
            finally:
                os.close(evidence_fd)

    def test_exit_77_is_a_fatal_runtime_failure(self) -> None:
        with self.assertRaisesRegex(LAUNCHER.LauncherError, "Exit 77"):
            LAUNCHER.validate_exit_status(77)

    def test_checked_commands_reject_shell_syntax_and_relative_executables(self) -> None:
        self.assertEqual(
            LAUNCHER.validated_command([LAUNCHER.HELPERS["curl"], "--fail"]),
            [LAUNCHER.HELPERS["curl"], "--fail"],
        )
        for unsafe in (
            ["curl", "--fail"],
            [LAUNCHER.HELPERS["curl"], "--url", "https://example.invalid/;id"],
            [LAUNCHER.HELPERS["curl"], "--url", "https://example.invalid/$HOME"],
        ):
            with self.subTest(unsafe=unsafe), self.assertRaises(LAUNCHER.LauncherError):
                LAUNCHER.validated_command(unsafe)

    def test_only_fixed_root_client_can_report_the_http_status(self) -> None:
        completed = mock.Mock(stdout="403", returncode=0)
        with mock.patch.object(
            LAUNCHER, "pidfd_exited", return_value=False
        ), mock.patch.object(
            LAUNCHER, "run_checked", return_value=completed
        ) as run_checked:
            self.assertEqual(LAUNCHER.trusted_http_status(1234), 403)
        argv = run_checked.call_args.args[0]
        self.assertEqual(argv[0], LAUNCHER.HELPERS["curl"])
        self.assertIn(LAUNCHER.HELPERS["curl"], argv)
        self.assertNotIn("candidate", " ".join(argv))
        self.assertEqual(run_checked.call_args.kwargs["pass_fds"], (1234,))
        self.assertIsNotNone(run_checked.call_args.kwargs["preexec_fn"])
        with mock.patch.object(
            LAUNCHER, "pidfd_exited", return_value=False
        ), mock.patch.object(
            LAUNCHER, "run_checked", return_value=mock.Mock(stdout="200", returncode=0)
        ):
            with self.assertRaisesRegex(LAUNCHER.LauncherError, "expected 403"):
                LAUNCHER.trusted_http_status(1234)

    def test_pidfd_bound_namespace_client_rejects_exit_and_never_resolves_a_pid(self) -> None:
        completed = mock.Mock(stdout="403", returncode=0)
        with mock.patch.object(
            LAUNCHER, "pidfd_exited", side_effect=(False, True)
        ), mock.patch.object(LAUNCHER, "run_checked", return_value=completed):
            with self.assertRaisesRegex(LAUNCHER.LauncherError, "exited during"):
                LAUNCHER.trusted_http_status(1234)
        source = MODULE_PATH.read_text(encoding="utf-8")
        trusted_client = source[source.index("def trusted_http_status"):source.index("def mark_request_complete")]
        self.assertNotIn("--target", trusted_client)
        self.assertNotIn("nsenter", trusted_client)
        self.assertIn("join_network_namespace_from_pidfd", trusted_client)

    def test_pidfd_namespace_preexec_and_cleanup_are_descriptor_bound(self) -> None:
        setns = mock.Mock(return_value=0)
        libc = mock.Mock(setns=setns)
        with mock.patch.object(LAUNCHER.ctypes, "CDLL", return_value=libc):
            LAUNCHER.join_network_namespace_from_pidfd(71)
        setns.assert_called_once_with(71, 0x40000000)
        identity: dict[str, object] = {"master_pidfd": 71}
        with mock.patch.object(LAUNCHER.os, "close") as close:
            LAUNCHER.close_identity_pidfd(identity)
        close.assert_called_once_with(71)
        self.assertNotIn("master_pidfd", identity)

    def test_launcher_only_executes_the_base_driver_and_fd_bound_artifacts(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertNotIn("shell=True", source)
        self.assertNotIn("|| true", source)
        bridge = (ROOT / "ci/run-trusted-framework.py").read_text(encoding="utf-8")
        self.assertIn("CELLS_SOURCE", bridge)
        self.assertIn("run_nginx_exact_head_cells.sh", bridge)
        self.assertIn("--trusted-cells-source-fd", source)
        self.assertIn('"--ro-bind-fd", str(state.artifact_descriptors["nginx"])', source)
        self.assertIn('"--ro-bind-fd", str(state.artifact_descriptors["module"])', source)
        self.assertIn('"--ro-bind-fd", str(state.artifact_descriptors["library"])', source)
        self.assertIn('"--ro-bind-fd", str(state.artifact_descriptors["manifest"])', source)
        self.assertIn('"--disable-userns", "--assert-userns-disabled"', source)
        self.assertIn('"--unshare-net"', source)
        self.assertIn('"--clearenv"', source)
        self.assertIn("require_sandbox_security_state", source)
        self.assertIn("host_pid_for_namespace_pid", source)
        self.assertIn("admit_trusted_cells_source", source)
        self.assertIn("fcntl.F_GET_SEALS", source)
        self.assertIn("fcntl.F_SEAL_WRITE", source)
        self.assertIn("SANDBOX_BASE_HELPER", source)
        self.assertIn('"--ro-bind-fd", str(state.trusted_base_descriptors["helper"])', source)
        self.assertIn('pass_fds=(state.scratch_fd, state.cell_fd)', source)
        self.assertIn('"root launcher cell"', source)
        self.assertNotIn("create_runner_owned_directory(state.cell", source)
        self.assertIn('env=context["outer_env"]', source)
        self.assertIn("sandbox_env", source)
        self.assertIn("SANDBOX_TMPDIR", source)
        self.assertIn('"TMPDIR": str(SANDBOX_TMPDIR)', source)
        self.assertIn('"--dir", "/run"', source)
        self.assertIn('"--tmpfs", str(SANDBOX_TMPDIR)', source)
        self.assertNotIn('"--dir", "/tmp"', source)
        self.assertNotIn('"--tmpfs", "/tmp"', source)
        self.assertIn("trusted_http_status", source)
        self.assertIn("mark_request_complete", source)
        self.assertNotIn("connectors/nginx/harness", source)

    def test_partial_subordinate_mapping_rolls_back_and_unbound_worker_is_not_signalled(self) -> None:
        mapping = LAUNCHER.SubordinateMapping("runner", 1000, 2000, 2001)
        with mock.patch.object(LAUNCHER, "require_no_subordinate_mapping"), mock.patch.object(
            LAUNCHER, "require_exact_subordinate_mapping"
        ), mock.patch.object(LAUNCHER.pwd, "getpwnam", return_value=types.SimpleNamespace(pw_uid=1000)), mock.patch.object(LAUNCHER, "run_checked", side_effect=(None, RuntimeError("gid update failed"), None)) as run_checked:
            with self.assertRaisesRegex(RuntimeError, "gid update failed"):
                LAUNCHER.establish_subordinate_mapping(mapping)
        self.assertFalse(mapping.uid_added)
        self.assertFalse(mapping.gid_added)
        self.assertEqual(run_checked.call_count, 3)
        with mock.patch.object(
            LAUNCHER, "dedicated_worker_process_ids", return_value=[4321]
        ), mock.patch.object(LAUNCHER.os, "kill") as kill:
            with self.assertRaisesRegex(LAUNCHER.LauncherError, "unbound host process"):
                LAUNCHER.require_no_dedicated_worker_processes(2000)
        kill.assert_not_called()



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
