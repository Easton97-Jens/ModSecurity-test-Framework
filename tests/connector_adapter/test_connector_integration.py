"""On-demand guards; clean committed-pair acceptance uses the real public CLI."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import sys
import subprocess
import unittest
from unittest.mock import patch

from modsecurity_test_framework import connector_integration as integration


class CleanCombinationGuards(unittest.TestCase):
    def test_revision_rejects_symbolic_or_option_inputs(self):
        with self.assertRaises(integration.IntegrationError):
            integration.exact_revision("HEAD")

    def test_missing_recorded_framework_pin_is_rejected(self):
        with self.assertRaisesRegex(
            integration.IntegrationError, "no Framework gitlink"
        ):
            integration.recorded_framework({})

    def test_regular_tree_entry_cannot_replace_framework_gitlink(self):
        with self.assertRaisesRegex(
            integration.IntegrationError, "no Framework gitlink"
        ):
            integration.recorded_framework({integration.GITLINK: ("40000", "a" * 40)})

    def test_recorded_framework_pin_retains_exact_commit(self):
        self.assertEqual(
            integration.recorded_framework({integration.GITLINK: ("160000", "a" * 40)}),
            "a" * 40,
        )

    def test_object_content_cannot_borrow_another_identity(self):
        value = (
            b"tree " + b"b" * 40
            + b"\nauthor Fixture <fixture@example.invalid> 0 +0000\n"
            + b"committer Fixture <fixture@example.invalid> 0 +0000\n\nmessage\n"
        )
        replies = [
            str(len(value)).encode(),
            b"a" * 40 + b" commit " + str(len(value)).encode() + b"\n" + value + b"\n",
        ]
        with (
            patch.object(integration, "git", side_effect=replies),
            self.assertRaisesRegex(integration.IntegrationError, "do not authenticate"),
        ):
            integration.raw_object(Path("/unused"), "a" * 40, "commit")

    def test_authenticated_object_uses_actual_returned_bytes(self):
        value = (
            b"tree " + b"b" * 40
            + b"\nauthor Fixture <fixture@example.invalid> 0 +0000\n"
            + b"committer Fixture <fixture@example.invalid> 0 +0000\n\nmessage\n"
        )
        identity = "201332972afb6d9cb235ab1761c2776c30119a18"
        replies = [
            str(len(value)).encode(),
            identity.encode()
            + b" commit "
            + str(len(value)).encode()
            + b"\n"
            + value
            + b"\n",
        ]
        with patch.object(integration, "git", side_effect=replies):
            self.assertEqual(
                integration.raw_object(Path("/unused"), identity, "commit"), value
            )

    def test_tree_rejects_parent_traversal_entry(self):
        with self.assertRaisesRegex(integration.IntegrationError, "unsafe"):
            integration.tree_entries(b"100644 ..\0" + b"a" * 20)

    def test_tree_rejects_duplicate_entry(self):
        entry = b"100644 file\0" + b"a" * 20
        with self.assertRaisesRegex(integration.IntegrationError, "duplicate"):
            integration.tree_entries(entry + entry)

    def test_symbolic_output_directory_is_rejected(self):
        declared = os.environ.get("RUNNER_TEMP") or os.environ.get("TMPDIR")
        if not declared:
            raise RuntimeError(
                "RUNNER_TEMP or TMPDIR must explicitly select external test storage"
            )
        with tempfile.TemporaryDirectory(
            prefix="integration-guard-", dir=declared
        ) as temporary:
            root = Path(temporary)
            (root / "real").mkdir(mode=0o700)
            (root / "alias").symlink_to(root / "real", target_is_directory=True)
            with self.assertRaisesRegex(integration.IntegrationError, "symlinks"):
                integration.physical_directory(root / "alias", private=True)

    def test_framework_version_lock_mismatch_is_rejected(self):
        with self.assertRaisesRegex(integration.IntegrationError, "framework_sha"):
            integration.validate_version_lock(
                {"framework_sha": "b" * 40, "mrts_sha": "c" * 40},
                "a" * 40,
                {"tools/MRTS": ("160000", "c" * 40)},
            )

    def test_mrts_version_lock_mismatch_is_rejected(self):
        with self.assertRaisesRegex(integration.IntegrationError, "mrts_sha"):
            integration.validate_version_lock(
                {"framework_sha": "a" * 40, "mrts_sha": "b" * 40},
                "a" * 40,
                {"tools/MRTS": ("160000", "c" * 40)},
            )

    def test_unregistered_framework_gitlink_is_rejected(self):
        with self.assertRaisesRegex(integration.IntegrationError, "exactly"):
            integration.validate_version_lock(
                {"framework_sha": "a" * 40, "mrts_sha": "c" * 40},
                "a" * 40,
                {
                    "tools/MRTS": ("160000", "c" * 40),
                    "vendor/product": ("160000", "d" * 40),
                },
            )

    def test_matching_framework_and_mrts_version_lock_is_retained(self):
        value = {"framework_sha": "a" * 40, "mrts_sha": "c" * 40}
        self.assertEqual(
            integration.validate_version_lock(
                value, "a" * 40, {"tools/MRTS": ("160000", "c" * 40)}
            ),
            value,
        )

    def test_build_and_cache_environment_does_not_repurpose_home(self):
        with (
            patch.object(integration, "git", return_value=b"a" * 40),
            patch.object(integration.shutil, "which", return_value="/usr/bin/cc"),
        ):
            value = integration.isolated_environment(
                Path("/parent"),
                Path("/framework"),
                "b" * 40,
                Path("/external/results"),
                Path(sys.executable),
                "h1",
            )
        self.assertNotIn("HOME", value)
        self.assertEqual(value["BUILD_ROOT"], "/external/results/build")
        self.assertEqual(value["TMP_ROOT"], "/external/results")
        self.assertEqual(value["XDG_CACHE_HOME"], "/external/results/cache")


class RetainedProbeControls(unittest.TestCase):
    def setUp(self):
        declared = os.environ.get("RUNNER_TEMP") or os.environ.get("TMPDIR")
        if not declared:
            raise RuntimeError("explicit external test storage is required")
        self.temporary = tempfile.TemporaryDirectory(
            prefix="probe-controls-", dir=declared
        )
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.engine = self.root / "active-tests-unit"
        self.engine.mkdir(mode=0o700)
        self.expected = {
            "connector_root": "/selected/product",
            "test_root": "/selected/framework",
            "connector_revision": "a" * 40,
            "framework_revision": "b" * 40,
            "inventory_sha256": "c" * 64,
            "source_map_sha256": "d" * 64,
            "selected_case_ids": [integration.EXECUTION + ".case"],
        }
        self.summary = {
            **self.expected,
            "output_directory": str(self.engine),
            "results": [
                {
                    "execution_id": integration.EXECUTION,
                    "case_ids": [integration.EXECUTION + ".case"],
                    "status": "passed",
                    "log": integration.EXECUTION + ".log",
                }
            ],
        }
        (self.engine / (integration.EXECUTION + ".log")).write_bytes(b"")

    def verify(self):
        (self.engine / "summary.json").write_text(json.dumps(self.summary))
        return integration.validated_probe_results(self.root, self.expected)

    def test_exact_probe_summary_is_accepted(self):
        self.assertEqual(self.verify(), self.summary["results"])

    def test_foreign_connector_root_cannot_promote_a_pass(self):
        self.summary["connector_root"] = "/foreign/product"
        with self.assertRaisesRegex(integration.IntegrationError, "another root"):
            self.verify()

    def test_foreign_framework_root_cannot_promote_a_pass(self):
        self.summary["test_root"] = "/foreign/framework"
        with self.assertRaisesRegex(integration.IntegrationError, "another root"):
            self.verify()

    def test_foreign_connector_revision_cannot_promote_a_pass(self):
        self.summary["connector_revision"] = "e" * 40
        with self.assertRaisesRegex(integration.IntegrationError, "another root"):
            self.verify()

    def test_foreign_framework_revision_cannot_promote_a_pass(self):
        self.summary["framework_revision"] = "e" * 40
        with self.assertRaisesRegex(integration.IntegrationError, "another root"):
            self.verify()

    def test_foreign_inventory_cannot_promote_a_pass(self):
        self.summary["inventory_sha256"] = "e" * 64
        with self.assertRaisesRegex(integration.IntegrationError, "another root"):
            self.verify()

    def test_foreign_source_map_cannot_promote_a_pass(self):
        self.summary["source_map_sha256"] = "e" * 64
        with self.assertRaisesRegex(integration.IntegrationError, "another root"):
            self.verify()

    def test_extra_result_cannot_promote_a_pass(self):
        self.summary["results"].append(dict(self.summary["results"][0]))
        with self.assertRaisesRegex(integration.IntegrationError, "exact successful"):
            self.verify()

    def test_symbolic_summary_file_is_rejected(self):
        (self.root / "foreign.json").write_text(json.dumps(self.summary))
        (self.engine / "summary.json").symlink_to(self.root / "foreign.json")
        with self.assertRaisesRegex(integration.IntegrationError, "physical"):
            integration.validated_probe_results(self.root, self.expected)

    def test_symbolic_summary_directory_is_rejected(self):
        (self.root / "active-tests-linked").symlink_to(
            self.engine, target_is_directory=True
        )
        with self.assertRaisesRegex(integration.IntegrationError, "physical"):
            integration.validated_probe_results(self.root, self.expected)

    def test_oversized_summary_file_is_rejected_before_parsing(self):
        with (self.engine / "summary.json").open("wb") as stream:
            stream.truncate(16 * 1024 * 1024 + 1)
        with self.assertRaisesRegex(integration.IntegrationError, "bounded"):
            integration.validated_probe_results(self.root, self.expected)

    def test_real_child_failure_propagates(self):
        with self.assertRaisesRegex(integration.IntegrationError, "exit 17"):
            integration.run_logged(
                [sys.executable, "-I", "-c", "raise SystemExit(17)"],
                self.root,
                dict(os.environ),
                self.root,
                "child-failure",
            )

    def test_timeout_reaps_setsid_grandchild_and_preserves_unrelated_process(self):
        sentinel = subprocess.Popen(
            [sys.executable, "-I", "-c", "import time; time.sleep(30)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        try:
            script = (
                "import subprocess,sys; child=subprocess.Popen([sys.executable,'-I','-c',"
                "'import os,time; os.setsid(); print(os.getpid(),flush=True); time.sleep(30)']); child.wait()"
            )
            with self.assertRaisesRegex(integration.IntegrationError, "process failed"):
                integration.run_logged(
                    [sys.executable, "-I", "-c", script],
                    self.root,
                    dict(os.environ),
                    self.root,
                    "owned-timeout",
                    timeout_seconds=2,
                )
            grandchild = int(
                (self.root / "owned-timeout.stdout.log").read_text().strip()
            )
            identity = Path("/proc") / str(grandchild) / "stat"
            if identity.exists():
                self.assertEqual(identity.read_text().rsplit(")", 1)[1].split()[0], "Z")
            self.assertIsNone(sentinel.poll())
        finally:
            if sentinel.poll() is None:
                sentinel.terminate()
            sentinel.wait(timeout=10)


class CleanRecordedCombination(unittest.TestCase):
    def test_actual_recorded_framework_pin_runs_parent_common_execution(self):
        from modsecurity_test_framework.connector_context import ConnectorContext

        context = ConnectorContext.from_environment()
        output = Path(
            tempfile.mkdtemp(prefix="clean-pair-acceptance-", dir=context.output)
        )
        receipt = integration.verify_combination(
            connector_source=context.connector,
            framework_source=context.tests,
            connector_revision=context.revision,
            output_root=output,
            python=Path(sys.executable),
            profile=context.profile,
        )
        record = json.loads(receipt.read_text())
        self.assertEqual(record["status"], "passed")
        self.assertEqual(record["mode"], "recorded-pin")
        self.assertTrue(record["standard_combination"])
        self.assertEqual(
            record["selected_framework_revision"], record["recorded_framework_revision"]
        )
        self.assertEqual(record["clean_before"], {"connector": True, "framework": True})
        self.assertEqual(record["clean_after"], {"connector": True, "framework": True})
        self.assertEqual(
            [row["execution_id"] for row in record["execution_results"]],
            ["common.header-valid-length"],
        )


if os.environ.get("ON_DEMAND_TESTS") != "1":

    def load_tests(loader, tests, pattern):
        return unittest.TestSuite()


if __name__ == "__main__":
    unittest.main()
