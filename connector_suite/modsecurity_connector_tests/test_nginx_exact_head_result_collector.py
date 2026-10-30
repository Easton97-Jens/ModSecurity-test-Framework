"""Contract tests for the root-owned exact-head result collector."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import ast
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import types
import unittest
from unittest import mock

from modsecurity_connector_ci.runtime.broker import nginx_exact_head_result_collector as collector
from modsecurity_connector_ci.runtime.broker import protected_nginx_exact_head_builder as builder


SHA = "a" * 40
DIGEST = "b" * 64
REPO = "Easton97-Jens/ModSecurity-conector"


class CollectorPinContractTests(unittest.TestCase):
    def test_pins_match_current_parent_and_exact_head_producer(self) -> None:
        source = source_path("ci/provisioning/components/prepare-runtime-components.py", root=connector_root())
        tree = ast.parse(source.read_text(encoding="utf-8"))
        pins = {
            node.targets[0].id: ast.literal_eval(node.value)
            for node in tree.body if isinstance(node, ast.Assign)
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id in {"NGINX_PINNED_VERSION_READBACK", "NGINX_PINNED_RELEASE_ASSET_SHA256"}
        }
        self.assertEqual(collector.NGINX_VERSION, pins["NGINX_PINNED_VERSION_READBACK"].removeprefix("nginx/"))
        self.assertEqual(collector.NGINX_SOURCE_DIGEST, pins["NGINX_PINNED_RELEASE_ASSET_SHA256"])
        self.assertEqual(collector.NGINX_VERSION, builder.EXPECTED_NGINX_VERSION)
        self.assertEqual(collector.NGINX_SOURCE_DIGEST, builder.EXPECTED_NGINX_SOURCE_SHA256)


class CollectorTests(unittest.TestCase):
    def setUp(self) -> None:
        if os.geteuid() != 0:
            self.skipTest("root-owned evidence contracts require a root test process")
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.runner_uid = os.geteuid()
        self.runner_gid = os.getegid()
        self.worker_uid = 65534
        self.worker_gid = 65534
        if self.worker_uid == self.runner_uid:
            self.worker_uid = 65533
        if self.worker_gid == self.runner_gid:
            self.worker_gid = 65533
        self.manifest = self.root / "inputs" / "dispatcher" / "dispatcher-manifest.json"
        self.manifest.parent.mkdir(mode=0o700, parents=True)
        self.manifest.parent.parent.chmod(0o700)
        self.manifest.parent.chmod(0o700)
        self.evidence = self.root / "launcher-evidence"
        self.evidence.mkdir(mode=0o700)
        self.evidence.chmod(0o700)
        self._write_manifest()
        self._write_valid_evidence()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @property
    def output(self) -> Path:
        return self.root / "exact-head-result.json"

    def _write(self, name: str, value: object, *, jsonl: bool = False) -> None:
        path = self.evidence / name
        path.write_text(
            json.dumps(value, sort_keys=True) + ("\n" if jsonl else ""),
            encoding="utf-8",
        )
        os.chown(path, 0, 0)
        path.chmod(0o600)

    def _write_manifest(self) -> None:
        self.manifest.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "trusted_dispatcher_base_sha": SHA,
                    "run_id": "run-1",
                    "pr_number": 354,
                    "tested_pr_head": SHA,
                    "tested_pr_head_ref": "feature/exact-head",
                    "tested_pr_head_repository": REPO,
                    "tested_pr_base": SHA,
                    "tested_pr_base_ref": "master",
                    "tested_pr_base_repository": REPO,
                    "draft": True,
                    "state": "open",
                    "merged": False,
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )

    def _identity(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "runner_uid": self.runner_uid,
            "runner_gid": self.runner_gid,
            "expected_worker_uid": self.worker_uid,
            "expected_worker_gid": self.worker_gid,
            "on": {
                "master_pid": 100,
                "worker_pid": 101,
                "master_uid": self.runner_uid,
                "master_gid": self.runner_gid,
                "worker_uid": self.worker_uid,
                "worker_gid": self.worker_gid,
            },
            "off": {
                "master_pid": 200,
                "worker_pid": 201,
                "master_uid": self.runner_uid,
                "master_gid": self.runner_gid,
                "worker_uid": self.worker_uid,
                "worker_gid": self.worker_gid,
            },
        }

    def _write_valid_evidence(self) -> None:
        self._write("identity.json", self._identity())
        self._write(
            "runtime.json",
            {
                "schema_version": 1,
                "tested_pr_head": SHA,
                "tested_pr_base": SHA,
                "trusted_dispatcher_base_sha": SHA,
                "candidate_run_id": "run-1",
                "nginx_version": builder.EXPECTED_NGINX_VERSION,
                "nginx_source_digest": builder.EXPECTED_NGINX_SOURCE_SHA256,
                "connector_module_digest": DIGEST,
            },
        )
        self._write("exit.json", {"schema_version": 1, "on_exit": 0, "off_exit": 0})
        self._write(
            "on.jsonl",
            {
                "callback_observed": True,
                "callback_observation_source": "candidate_scratch_untrusted",
                "http_status": 403,
                "http_status_observation_source": "root_pidfd_network_namespace",
                "jsonl_observed": True,
                "jsonl_observation_source": "candidate_scratch_untrusted",
                "mode": "on",
                "transaction_id": "nginx-exact-head-1000-100-1",
                "waf_decision": "deny",
            },
            jsonl=True,
        )
        self._write(
            "off.jsonl",
            {
                "callback_observed": False,
                "callback_observation_source": "candidate_scratch_untrusted",
                "http_status": 403,
                "http_status_observation_source": "root_pidfd_network_namespace",
                "jsonl_observed": True,
                "jsonl_observation_source": "candidate_scratch_untrusted",
                "mode": "off",
                "transaction_id": "nginx-exact-head-2000-200-1",
                "waf_decision": "deny",
            },
            jsonl=True,
        )

    def _collect(self) -> dict[str, object]:
        return collector.collect(
            self.manifest,
            self.evidence,
            self.output,
            self.root,
            self.runner_uid,
            self.runner_gid,
        )

    def test_collects_exact_terminal_result_with_required_fields(self) -> None:
        result = self._collect()
        required = {
            "tested_pr_head",
            "tested_pr_base",
            "trusted_dispatcher_base_sha",
            "nginx_version",
            "nginx_source_digest",
            "connector_module_digest",
            "master_pid",
            "master_uid",
            "master_gid",
            "worker_pid",
            "worker_uid",
            "worker_gid",
            "distinct_identity_verified",
            "on_callback_observed",
            "off_callback_observed",
            "on_jsonl_observed",
            "off_jsonl_observed",
            "on_waf_decision",
            "off_waf_decision",
            "decision_equivalent",
            "trusted_http_status_observed",
            "candidate_sandbox_observations_untrusted",
            "final_exit_code",
        }
        self.assertEqual(result["status"], "validated_observations")
        self.assertTrue(required.issubset(result))
        self.assertEqual(result["tested_pr_base"], SHA)
        self.assertTrue(result["trusted_http_status_observed"])
        self.assertTrue(result["candidate_sandbox_observations_untrusted"])
        self.assertNotIn("transaction_id", result)
        output = self.output.lstat()
        self.assertEqual((output.st_uid, output.st_gid), (self.runner_uid, self.runner_gid))
        self.assertEqual(stat.S_IMODE(output.st_mode), 0o600)

    def test_rejects_old_and_arbitrary_release_pins(self) -> None:
        for version, digest in (
            ("1.31.4", "e6f20b644a17a643f059ae6467a1971fe2811587d025e071068753a1f1e3b3c3"),
            (builder.EXPECTED_NGINX_VERSION, "f" * 64),
            ("99.0.0", builder.EXPECTED_NGINX_SOURCE_SHA256),
        ):
            with self.subTest(version=version, digest=digest):
                runtime = json.loads((self.evidence / "runtime.json").read_text(encoding="utf-8"))
                runtime.update(nginx_version=version, nginx_source_digest=digest)
                self._write("runtime.json", runtime)
                with self.assertRaisesRegex(collector.CollectorError, "runtime identity mismatch"):
                    self._collect()
                self.assertFalse(self.output.exists())

    def test_rejects_previous_release_and_crossed_runtime_pins(self) -> None:
        previous_digest = "e951607d534836624bd36b6b45a71dbfb055237deae3738da6bbf3270dada279"
        current_digest = "974ed5298a5e398e008704ed5db284e655fc270c596493dbccada452448fc9f1"
        for version, digest in (
            ("1.31.5", previous_digest),
            ("1.31.6", previous_digest),
            ("1.31.5", current_digest),
        ):
            with self.subTest(version=version, digest=digest):
                runtime = json.loads((self.evidence / "runtime.json").read_text(encoding="utf-8"))
                runtime.update(nginx_version=version, nginx_source_digest=digest)
                self._write("runtime.json", runtime)
                try:
                    with self.assertRaisesRegex(collector.CollectorError, "runtime identity mismatch"):
                        self._collect()
                    self.assertFalse(self.output.exists())
                finally:
                    self.output.unlink(missing_ok=True)

    def test_rejects_missing_cells_and_invalid_master_or_worker_identity(self) -> None:
        (self.evidence / "off.jsonl").unlink()
        with self.assertRaises(collector.CollectorError):
            self._collect()
        self._write_valid_evidence()
        identity = self._identity()
        identity["on"]["worker_pid"] = identity["on"]["master_pid"]
        self._write("identity.json", identity)
        with self.assertRaisesRegex(collector.CollectorError, "distinct identity"):
            self._collect()
        identity = self._identity()
        identity["on"]["worker_uid"] = 0
        self._write("identity.json", identity)
        with self.assertRaises(collector.CollectorError):
            self._collect()
        identity = self._identity()
        identity["on"]["master_uid"] = self.runner_uid + 1
        self._write("identity.json", identity)
        with self.assertRaisesRegex(collector.CollectorError, "root proof"):
            self._collect()

    def test_rejects_invalid_identity_in_either_execution_cell(self) -> None:
        for mode in ("on", "off"):
            with self.subTest(mode=mode):
                self._write_valid_evidence()
                identity = self._identity()
                identity[mode]["worker_pid"] = identity[mode]["master_pid"]
                self._write("identity.json", identity)
                with self.assertRaisesRegex(collector.CollectorError, "distinct identity"):
                    self._collect()

        for mode in ("on", "off"):
            with self.subTest(mode=f"{mode}-worker-uid"):
                self._write_valid_evidence()
                identity = self._identity()
                identity[mode]["worker_uid"] = 0
                self._write("identity.json", identity)
                with self.assertRaisesRegex(collector.CollectorError, "identity"):
                    self._collect()

    def test_rejects_a_mismatched_two_cell_event(self) -> None:
        for mode, wrong_mode in (("on", "off"), ("off", "on")):
            with self.subTest(mode=mode):
                self._write_valid_evidence()
                event = {
                    "callback_observed": mode == "on",
                    "http_status": 403,
                    "jsonl_observed": True,
                    "mode": wrong_mode,
                    "transaction_id": f"nginx-exact-head-1000-100-{1 if mode == 'on' else 2}",
                    "waf_decision": "deny",
                }
                self._write(f"{mode}.jsonl", event, jsonl=True)
                with self.assertRaisesRegex(collector.CollectorError, f"{mode} JSONL"):
                    self._collect()

    def test_rejects_boolean_schema_versions(self) -> None:
        manifest = json.loads(self.manifest.read_text(encoding="utf-8"))
        manifest["schema_version"] = True
        self.manifest.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
        with self.assertRaisesRegex(collector.CollectorError, "dispatcher identity"):
            self._collect()

        self._write_manifest()
        identity = self._identity()
        identity["schema_version"] = True
        self._write("identity.json", identity)
        with self.assertRaisesRegex(collector.CollectorError, "identity metadata"):
            self._collect()

        self._write_valid_evidence()
        runtime = json.loads((self.evidence / "runtime.json").read_text(encoding="utf-8"))
        runtime["schema_version"] = True
        self._write("runtime.json", runtime)
        with self.assertRaisesRegex(collector.CollectorError, "runtime identity"):
            self._collect()

        self._write_valid_evidence()
        self._write("exit.json", {"schema_version": True, "on_exit": 0, "off_exit": 0})
        with self.assertRaisesRegex(collector.CollectorError, "cell exit status"):
            self._collect()

    def test_rejects_links_duplicate_keys_extra_files_and_nonfresh_output(self) -> None:
        target = self.root / "target.json"
        target.write_text("{}", encoding="utf-8")
        (self.evidence / "runtime.json").unlink()
        (self.evidence / "runtime.json").symlink_to(target)
        with self.assertRaises(collector.CollectorError):
            self._collect()
        (self.evidence / "runtime.json").unlink()
        os.link(target, self.evidence / "runtime.json")
        with self.assertRaises(collector.CollectorError):
            self._collect()
        (self.evidence / "runtime.json").unlink()
        self._write_valid_evidence()
        (self.evidence / "extra").write_text("unexpected", encoding="utf-8")
        with self.assertRaisesRegex(collector.CollectorError, "allowlist"):
            self._collect()
        (self.evidence / "extra").unlink()
        self.output.write_text("existing", encoding="utf-8")
        with self.assertRaisesRegex(collector.CollectorError, "fresh"):
            self._collect()
        self.output.unlink()
        (self.evidence / "runtime.json").write_text(
            '{"schema_version":1,"schema_version":1}',
            encoding="utf-8",
        )
        os.chown(self.evidence / "runtime.json", 0, 0)
        (self.evidence / "runtime.json").chmod(0o600)
        with self.assertRaisesRegex(collector.CollectorError, "duplicate"):
            self._collect()

    def test_rejects_oversized_and_control_injected_jsonl(self) -> None:
        oversized = self.evidence / "on.jsonl"
        oversized.write_bytes(b"x" * (collector.MAX_JSONL + 1))
        os.chown(oversized, 0, 0)
        oversized.chmod(0o600)
        with self.assertRaisesRegex(collector.CollectorError, "not bounded|exceeds limit"):
            self._collect()
        self._write_valid_evidence()
        (self.evidence / "on.jsonl").write_text(
            '{"callback_observed":true} ::set-output::bad\n',
            encoding="utf-8",
        )
        os.chown(self.evidence / "on.jsonl", 0, 0)
        (self.evidence / "on.jsonl").chmod(0o600)
        with self.assertRaisesRegex(collector.CollectorError, "safe event"):
            self._collect()
        self._write_valid_evidence()
        (self.evidence / "off.jsonl").write_bytes(b"\x1b[31m{}\n")
        os.chown(self.evidence / "off.jsonl", 0, 0)
        (self.evidence / "off.jsonl").chmod(0o600)
        with self.assertRaisesRegex(collector.CollectorError, "safe event"):
            self._collect()

    def test_stable_read_detects_metadata_mutation_and_output_escape(self) -> None:
        source = self.root / "source.json"
        source.write_text('{"value":1}', encoding="utf-8")
        descriptor = os.open(source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        before = os.fstat(descriptor)
        after = types.SimpleNamespace(
            st_dev=before.st_dev,
            st_ino=before.st_ino,
            st_size=before.st_size,
            st_mtime_ns=before.st_mtime_ns + 1,
            st_ctime_ns=before.st_ctime_ns,
            st_mode=before.st_mode,
            st_nlink=before.st_nlink,
            st_uid=before.st_uid,
            st_gid=before.st_gid,
        )
        try:
            with mock.patch.object(collector.os, "fstat", side_effect=(before, after)):
                with self.assertRaisesRegex(collector.CollectorError, "changed"):
                    collector._stable_read_descriptor(
                        descriptor, "source", 1024, collector._require_bounded_regular
                    )
        finally:
            os.close(descriptor)
        with self.assertRaisesRegex(collector.CollectorError, "fixed task-root"):
            collector.collect(
                self.manifest,
                self.evidence,
                self.root.parent / "exact-head-result.json",
                self.root,
                self.runner_uid,
                self.runner_gid,
            )

    def test_evidence_path_substitution_cannot_replace_validated_root_evidence(self) -> None:
        """Regression trigger for validation-to-open replacement of evidence_root."""
        replacement = self.root / "replacement-evidence"
        shutil.copytree(self.evidence, replacement)
        runtime_path = replacement / "runtime.json"
        runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
        replacement_digest = "c" * 64
        runtime["connector_module_digest"] = replacement_digest
        runtime_path.write_text(json.dumps(runtime, sort_keys=True), encoding="utf-8")
        os.chown(runtime_path, 0, 0)
        runtime_path.chmod(0o600)
        moved = self.root / "original-evidence"
        listdir = os.listdir
        substituted = False

        def substitute_after_root_open(descriptor: int) -> list[str]:
            nonlocal substituted
            names = listdir(descriptor)
            if not substituted:
                substituted = True
                self.evidence.rename(moved)
                replacement.rename(self.evidence)
            return names

        with mock.patch.object(
            collector.os, "listdir", side_effect=substitute_after_root_open
        ):
            result = self._collect()
        self.assertTrue(substituted)
        self.assertEqual(result["connector_module_digest"], DIGEST)

    def test_rejects_root_owned_evidence_outside_the_fixed_task_leaf(self) -> None:
        outside = self.root.parent / "outside-root-evidence"
        shutil.copytree(self.evidence, outside)
        outside.chmod(0o700)
        try:
            with self.assertRaisesRegex(collector.CollectorError, "fixed task-root"):
                collector.collect(
                    self.manifest,
                    outside,
                    self.output,
                    self.root,
                    self.runner_uid,
                    self.runner_gid,
                )
        finally:
            shutil.rmtree(outside)

    def test_evidence_leaf_replacement_between_stat_and_open_is_rejected(self) -> None:
        task_descriptor = collector._open_task_root(
            self.root, self.runner_uid, self.runner_gid
        )
        root_descriptor = collector._open_root_owned_evidence(task_descriptor)
        replacement = self.root / "replacement-identity.json"
        replacement.write_text(json.dumps(self._identity()), encoding="utf-8")
        os.chown(replacement, 0, 0)
        replacement.chmod(0o600)
        original = self.evidence / "identity.json"
        moved = self.root / "original-identity.json"
        open_file = os.open
        replaced = False

        def replace_before_open(
            name: str | Path, flags: int, *args: object, **kwargs: object
        ) -> int:
            nonlocal replaced
            if name == "identity.json" and kwargs.get("dir_fd") == root_descriptor:
                replaced = True
                original.rename(moved)
                replacement.rename(original)
            return open_file(name, flags, *args, **kwargs)

        try:
            with mock.patch.object(collector.os, "open", side_effect=replace_before_open):
                with self.assertRaisesRegex(collector.CollectorError, "changed while being opened"):
                    collector._open_evidence_file(
                        root_descriptor, "identity.json", "identity", collector.MAX_JSON
                    )
        finally:
            os.close(root_descriptor)
            os.close(task_descriptor)
        self.assertTrue(replaced)

    def test_preseeded_result_temporary_file_fails_closed_without_deletion(self) -> None:
        temporary = self.root / f"{collector.RESULT_TEMPORARY_PREFIX}{os.getpid()}"
        temporary.write_text("attacker-owned", encoding="utf-8")
        temporary.chmod(0o600)
        with self.assertRaisesRegex(collector.CollectorError, "atomically write"):
            self._collect()
        self.assertEqual(temporary.read_text(encoding="utf-8"), "attacker-owned")

    def test_manifest_must_be_the_fixed_task_root_input(self) -> None:
        with self.assertRaisesRegex(collector.CollectorError, "fixed task-root input"):
            collector.collect(
                self.root / "manifest.json",
                self.evidence,
                self.output,
                self.root,
                self.runner_uid,
                self.runner_gid,
            )

    def test_manifest_intermediate_symlink_is_rejected(self) -> None:
        dispatcher = self.manifest.parent
        moved = self.root / "dispatcher-real"
        dispatcher.rename(moved)
        dispatcher.symlink_to(moved, target_is_directory=True)
        with self.assertRaisesRegex(collector.CollectorError, "dispatcher input"):
            self._collect()

    def test_closes_task_descriptor_when_evidence_root_open_fails(self) -> None:
        task_descriptor = 1234
        with mock.patch.object(
            collector, "_open_task_root", return_value=task_descriptor
        ), mock.patch.object(
            collector, "_manifest_from_task_root", return_value={}
        ), mock.patch.object(
            collector,
            "_open_root_owned_evidence",
            side_effect=collector.CollectorError("evidence unavailable"),
        ), mock.patch.object(collector.os, "close") as close:
            with self.assertRaisesRegex(collector.CollectorError, "evidence unavailable"):
                self._collect()
        close.assert_called_once_with(task_descriptor)

    def test_manifest_replacement_between_stat_and_open_is_rejected(self) -> None:
        replacement = self.root / "replacement-manifest.json"
        replacement.write_bytes(self.manifest.read_bytes())
        os.chown(replacement, self.runner_uid, self.runner_gid)
        replacement.chmod(0o600)
        original = self.manifest
        moved = self.root / "original-manifest.json"
        open_file = os.open
        replaced = False

        def replace_before_open(name: str | Path, flags: int, *args: object,
                                **kwargs: object) -> int:
            nonlocal replaced
            if name == "dispatcher-manifest.json":
                replaced = True
                original.rename(moved)
                replacement.rename(original)
            return open_file(name, flags, *args, **kwargs)

        try:
            task_descriptor = collector._open_task_root(
                self.root, self.runner_uid, self.runner_gid
            )
            with mock.patch.object(collector.os, "open", side_effect=replace_before_open):
                with self.assertRaisesRegex(collector.CollectorError, "changed while being opened"):
                    collector._open_task_input_manifest(
                        task_descriptor,
                        self.manifest,
                        self.root,
                        self.runner_uid,
                        self.runner_gid,
                    )
        finally:
            os.close(task_descriptor)
        self.assertTrue(replaced)
        self.assertNotEqual(original.stat().st_ino, moved.stat().st_ino)

    def test_rejects_dispatcher_base_replacement_after_root_attestation(self) -> None:
        """A runner-owned manifest cannot forge the root-attested base SHA."""
        manifest = json.loads(self.manifest.read_text(encoding="utf-8"))
        manifest["tested_pr_base"] = "c" * 40
        self.manifest.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
        self.manifest.chmod(0o600)
        with self.assertRaisesRegex(collector.CollectorError, "runtime identity mismatch"):
            self._collect()
        self.assertFalse(self.output.exists())



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
