"""Keep maintenance test metadata generation and candidate trust boundaries closed."""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "maintenance_test_views", ROOT / "ci/tools/sync-maintenance-test-views.py"
)
TOOL = importlib.util.module_from_spec(spec)
spec.loader.exec_module(TOOL)


def compact(value):
    return (
        json.dumps(value, separators=(",", ":"), ensure_ascii=False) + "\n"
    ).encode()


class MaintenanceTestViewsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=os.environ.get("RUNNER_TEMP"))
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.git("init", "--quiet")
        self.write(TOOL.COMMON, b"CI_CANONICAL_PYTHON_VERSION=3.15.1\n")
        self.write(".python-version", b"3.15.1\n")
        self.inventory = {
            "schema_version": 5,
            "executions": [{"id": "unchanged", "cases": ["same"]}],
            "source_bindings": [
                {"path": TOOL.COMMON_BINDING, "sha256": self.digest(TOOL.COMMON)},
                {"path": "untouched", "sha256": "a" * 64},
            ],
        }
        self.write(TOOL.INVENTORY, compact(self.inventory))
        self.archive = {
            "schema_version": 2,
            "inventory_sha256": self.digest(TOOL.INVENTORY),
            "sources": [{"path": "retained", "definitions": ["unchanged"]}],
        }
        self.write(TOOL.ARCHIVE, TOOL.archive_bytes(self.archive))
        self.base = self.commit("base")

    def git(self, *arguments):
        return (
            subprocess.check_output(
                ["git", "-C", str(self.root), *arguments], stderr=subprocess.DEVNULL
            )
            .decode()
            .strip()
        )

    def write(self, path, data):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    def digest(self, path):
        return hashlib.sha256((self.root / path).read_bytes()).hexdigest()

    def commit(self, message):
        self.git("add", ".")
        self.git(
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "--quiet",
            "-m",
            message,
        )
        return self.git("rev-parse", "HEAD")

    def candidate(self):
        self.write(TOOL.COMMON, b"CI_CANONICAL_PYTHON_VERSION=3.15.2\n")
        self.write(".python-version", b"3.15.2\n")
        inventory = json.loads(json.dumps(self.inventory))
        inventory["source_bindings"][0]["sha256"] = self.digest(TOOL.COMMON)
        self.write(TOOL.INVENTORY, compact(inventory))
        archive = json.loads(json.dumps(self.archive))
        archive["inventory_sha256"] = self.digest(TOOL.INVENTORY)
        self.write(TOOL.ARCHIVE, TOOL.archive_bytes(archive))

    def test_exact_candidate_is_verified_without_checkout_or_head_execution(self):
        self.candidate()
        head = self.commit("candidate")
        self.write(
            "ci/tools/sync-maintenance-test-views.py",
            b"raise RuntimeError('never execute candidate')\n",
        )
        with (
            contextlib.redirect_stdout(io.StringIO()),
            mock.patch.dict(os.environ, {"GIT_DIR": "/foreign"}),
        ):
            TOOL.verify_python_candidate(self.root, self.base, head)
        self.assertEqual(self.git("rev-parse", "HEAD"), head)
        self.assertIn(
            "never execute",
            (self.root / "ci/tools/sync-maintenance-test-views.py").read_text(),
        )

    def test_selection_extra_source_or_wrong_digest_is_rejected(self):
        for mutation in ("selection", "extra", "digest", "foreign-digest"):
            with self.subTest(mutation=mutation):
                self.candidate()
                inventory = json.loads((self.root / TOOL.INVENTORY).read_bytes())
                if mutation == "selection":
                    inventory["executions"][0]["cases"].append("extra")
                elif mutation == "extra":
                    inventory["source_bindings"].append(
                        {"path": "foreign", "sha256": "f" * 64}
                    )
                elif mutation == "foreign-digest":
                    inventory["source_bindings"][1]["sha256"] = "0" * 64
                else:
                    inventory["source_bindings"][0]["sha256"] = "0" * 64
                self.write(TOOL.INVENTORY, compact(inventory))
                head = self.commit(mutation)
                with self.assertRaisesRegex(ValueError, "inventory must change only"):
                    TOOL.verify_python_candidate(self.root, self.base, head)

    def test_archive_metadata_or_wrong_inventory_digest_is_rejected(self):
        for mutation in ("sources", "inventory_sha256"):
            with self.subTest(mutation=mutation):
                self.candidate()
                archive = json.loads((self.root / TOOL.ARCHIVE).read_bytes())
                archive[mutation] = [] if mutation == "sources" else "0" * 64
                self.write(TOOL.ARCHIVE, TOOL.archive_bytes(archive))
                head = self.commit(mutation)
                with self.assertRaisesRegex(ValueError, "archive must change only"):
                    TOOL.verify_python_candidate(self.root, self.base, head)

    def test_non_native_format_is_rejected(self):
        for path in (TOOL.INVENTORY, TOOL.ARCHIVE):
            with self.subTest(path=path):
                self.candidate()
                value = json.loads((self.root / path).read_bytes())
                self.write(path, json.dumps(value).encode())
                head = self.commit("format")
                with self.assertRaises(ValueError):
                    TOOL.verify_python_candidate(self.root, self.base, head)

    def test_mode_change_or_symlink_is_rejected(self):
        self.candidate()
        self.git("config", "core.filemode", "true")
        (self.root / TOOL.INVENTORY).chmod(0o755)
        head = self.commit("mode")
        with self.assertRaisesRegex(ValueError, "file mode"):
            TOOL.verify_python_candidate(self.root, self.base, head)
        (self.root / TOOL.INVENTORY).unlink()
        (self.root / TOOL.INVENTORY).symlink_to("../../../ci/lib/common.sh")
        head = self.commit("symlink")
        with self.assertRaisesRegex(ValueError, "regular Git blobs"):
            TOOL.verify_python_candidate(self.root, self.base, head)

    def test_oversized_blob_is_rejected_before_content_capture(self):
        identity = "a" * 40
        row = ("100644 blob " + identity + "\t" + TOOL.INVENTORY + "\0").encode()
        with mock.patch.object(
            TOOL, "git", side_effect=[row, str(TOOL.LIMIT + 1).encode()]
        ) as git:
            with self.assertRaisesRegex(ValueError, "blob exceeds"):
                TOOL.blob(self.root, self.base, TOOL.INVENTORY)
        self.assertEqual(
            git.call_args_list,
            [
                mock.call(self.root, "ls-tree", "-z", self.base, "--", TOOL.INVENTORY),
                mock.call(self.root, "cat-file", "-s", identity),
            ],
        )

    def test_wrong_python_selector_is_rejected_before_metadata_admission(self):
        self.candidate()
        self.write(".python-version", b"3.15.3\n")
        head = self.commit("wrong selector")
        with self.assertRaisesRegex(ValueError, "selector must match"):
            TOOL.verify_python_candidate(self.root, self.base, head)

    def test_duplicate_or_non_ascii_python_assignment_is_rejected(self):
        for common in (
            b"CI_CANONICAL_PYTHON_VERSION=3.15.2\nCI_CANONICAL_PYTHON_VERSION=3.15.2\n",
            'CI_CANONICAL_PYTHON_VERSION="3.15.２"\n'.encode(),
            b"CI_CANONICAL_PYTHON_VERSION=3.16.0\n",
        ):
            with self.subTest(common=common):
                self.candidate()
                self.write(TOOL.COMMON, common)
                head = self.commit("invalid assignment")
                with self.assertRaisesRegex(ValueError, "literal ASCII Python 3.15"):
                    TOOL.verify_python_candidate(self.root, self.base, head)

    def test_option_shaped_revision_cannot_become_a_git_option(self):
        with self.assertRaises(subprocess.CalledProcessError):
            TOOL.verify_python_candidate(self.root, "--help", "HEAD")

    def test_explicit_root_and_local_context_do_not_inherit_product_selection(self):
        self.assertEqual(TOOL.validate_root(ROOT), ROOT)
        with self.assertRaises(ValueError):
            TOOL.validate_root(self.root)
        with mock.patch.dict(
            os.environ,
            {
                "CONNECTOR_ROOT": "/foreign",
                "TEST_ROOT": "/foreign",
                "PYTHONPATH": "/foreign",
                "GIT_DIR": "/foreign",
            },
        ):
            with TOOL.local_context(ROOT):
                self.assertNotIn("CONNECTOR_ROOT", os.environ)
                self.assertNotIn("GIT_DIR", os.environ)
                self.assertEqual(os.environ["TEST_ROOT"], str(ROOT))
                self.assertEqual(
                    os.environ["PYTHONPATH"],
                    str(ROOT) + os.pathsep + str(ROOT / "connector_suite"),
                )
            self.assertEqual(os.environ["CONNECTOR_ROOT"], "/foreign")

    def native_mocks(self, changed):
        original = (self.root / TOOL.INVENTORY).read_bytes()
        updated = original.replace(b'"same"', b'"updated"') if changed else original
        events = []

        def replace(root, before, after):
            self.assertEqual(before, original)
            events.append("inventory-written")
            self.write(TOOL.INVENTORY, after)

        def archive():
            events.append("archive-read")
            self.assertEqual((self.root / TOOL.INVENTORY).read_bytes(), updated)
            return {"inventory_sha256": hashlib.sha256(updated).hexdigest()}

        bindings = SimpleNamespace(
            planned=mock.Mock(
                return_value=(original, updated, ["source"] if changed else [])
            ),
            atomic_write=mock.Mock(side_effect=replace),
            inventory=SimpleNamespace(
                _read_regular_source=lambda root, path: (root / path).read_bytes()
            ),
        )
        return bindings, SimpleNamespace(archive=archive), events, updated

    def test_write_refreshes_inventory_before_archive_then_check_is_clean(self):
        bindings, archive, events, updated = self.native_mocks(True)
        with (
            mock.patch.object(TOOL, "native_tool", side_effect=[bindings, archive]),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            TOOL.sync(self.root, write=True)
        self.assertEqual(events, ["inventory-written", "archive-read"])
        bindings.planned.return_value = (updated, updated, [])
        bindings.atomic_write.reset_mock()
        events.clear()
        with (
            mock.patch.object(TOOL, "native_tool", side_effect=[bindings, archive]),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            TOOL.sync(self.root, write=False)
        bindings.atomic_write.assert_not_called()
        self.assertEqual(events, ["archive-read"])

    def test_check_rejects_drift_without_any_write_or_archive_generation(self):
        bindings, archive, events, _ = self.native_mocks(True)
        before = (self.root / TOOL.ARCHIVE).read_bytes()
        with (
            mock.patch.object(TOOL, "native_tool", side_effect=[bindings, archive]),
            self.assertRaises(ValueError),
        ):
            TOOL.sync(self.root, write=False)
        bindings.atomic_write.assert_not_called()
        self.assertEqual(events, [])
        self.assertEqual((self.root / TOOL.ARCHIVE).read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
