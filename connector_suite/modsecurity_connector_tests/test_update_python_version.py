from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import io
import json
import os
import tempfile
import unittest
import urllib.error
import urllib.parse
from pathlib import Path
from unittest import mock

from modsecurity_connector_tests.version_updater_test_support import FakeOpener, load_updater, response_factory, uses_shared_core

from modsecurity_connector_tests.version_updater_test_support import write_project_pins

SCRIPT = connector_root() / "scripts" / "update-python-version.py"
updater = load_updater("update_python_version", SCRIPT)
FakeResponse = response_factory(updater.CANONICAL_RELEASE_API_URL)


def release(name: str, *, published: bool = True, prerelease: bool = False) -> dict[str, object]:
    return {
        "name": name,
        "is_published": published,
        "pre_release": prerelease,
    }


class UpdatePythonVersionTests(unittest.TestCase):
    def test_spec_loaded_adapter_uses_shared_core(self) -> None:
        self.assertTrue(uses_shared_core(updater))

    def _root_with_version(self, root: Path, version: str = "3.15.6") -> Path:
        root.mkdir(parents=True, exist_ok=True)
        (root / ".python-version").write_text(f"{version}\n", encoding="utf-8")
        write_project_pins(root, python_version=version)
        return root

    def _run_cli(
        self,
        root: Path,
        argv: list[str],
        *,
        opener: FakeOpener | None = None,
        metadata=updater._UNSET,
    ) -> tuple[int, dict[str, object]]:
        output = io.StringIO()
        result = updater.main(argv, root=root, opener=opener, metadata=metadata, output=output)
        return result, json.loads(output.getvalue())

    def test_selects_highest_stable_patch_while_ignoring_prerelease_and_wrong_minor(self):
        metadata = [
            release("Python 3.15.0"),
            release("Python 3.15.6"),
            release("Python 3.15.99rc1", prerelease=True),
            release("Python 3.16.99"),
            release("Python 3.14.99"),
            release("Python 3.15.8"),
        ]
        self.assertEqual(str(updater.resolve_latest_stable_version(metadata=metadata)), "3.15.8")

    def test_zero_patch_is_a_valid_canonical_stable_version(self):
        metadata = [release("Python 3.15.0")]
        self.assertEqual(str(updater.resolve_latest_stable_version(metadata=metadata)), "3.15.0")

        with tempfile.TemporaryDirectory() as temporary:
            root = self._root_with_version(Path(temporary), "3.15.0")
            result, record = self._run_cli(
                root,
                ["--update", "--expected-version", "3.15.0", "--json"],
                metadata=metadata,
            )

        self.assertEqual(result, 0)
        self.assertEqual(record["status"], "current")
        self.assertEqual(record["latest_version"], "3.15.0")
        self.assertIs(record["update_available"], False)
        self.assertIs(record["changed"], False)

    def test_check_reports_update_available_in_stable_json(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root_with_version(Path(temporary), "3.15.6")
            result, record = self._run_cli(
                root,
                ["--check", "--json"],
                metadata=[release("Python 3.15.7")],
            )

        self.assertEqual(result, 0)
        self.assertEqual(record["status"], "update_available")
        self.assertEqual(record["current_version"], "3.15.6")
        self.assertEqual(record["latest_version"], "3.15.7")
        self.assertIs(record["update_available"], True)
        self.assertNotIn("changed", record)

    def test_check_reports_current_in_stable_json(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root_with_version(Path(temporary), "3.15.7")
            result, record = self._run_cli(
                root,
                ["--check", "--json"],
                metadata=[release("Python 3.15.7")],
            )

        self.assertEqual(result, 0)
        self.assertEqual(record["status"], "current")
        self.assertEqual(record["current_version"], "3.15.7")
        self.assertEqual(record["latest_version"], "3.15.7")
        self.assertIs(record["update_available"], False)

    def test_update_replaces_version_atomically_and_reports_changed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root_with_version(Path(temporary), "3.15.6")
            target = root / ".python-version"
            original_mode = target.stat().st_mode & 0o777
            result, record = self._run_cli(
                root,
                ["--update", "--expected-version", "3.15.7", "--json"],
                metadata=[release("Python 3.15.7")],
            )
            content = target.read_text(encoding="utf-8")
            updated_mode = target.stat().st_mode & 0o777

        self.assertEqual(result, 0)
        self.assertEqual(record["status"], "update_available")
        self.assertIs(record["update_available"], True)
        self.assertIs(record["changed"], True)
        self.assertEqual(content, "3.15.7\n")
        self.assertEqual(updated_mode, original_mode)

    def test_update_is_idempotent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root_with_version(Path(temporary), "3.15.7")
            target = root / ".python-version"
            before = target.stat()
            result, record = self._run_cli(
                root,
                ["--update", "--expected-version", "3.15.7", "--json"],
                metadata=[release("Python 3.15.7")],
            )
            after = target.stat()

        self.assertEqual(result, 0)
        self.assertEqual(record["status"], "current")
        self.assertIs(record["update_available"], False)
        self.assertIs(record["changed"], False)
        self.assertEqual((after.st_ino, after.st_mtime_ns), (before.st_ino, before.st_mtime_ns))

    def test_leading_zero_current_version_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root_with_version(Path(temporary), "3.15.00")
            result, record = self._run_cli(
                root,
                ["--check", "--json"],
                metadata=[release("Python 3.15.7")],
            )
            content = (root / ".python-version").read_text(encoding="utf-8")

        self.assertEqual(result, 1)
        self.assertEqual(record["status"], "error")
        self.assertEqual(content, "3.15.00\n")

    def test_update_rejects_downgrade(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root_with_version(Path(temporary), "3.15.7")
            result, record = self._run_cli(
                root,
                ["--update", "--expected-version", "3.15.6", "--json"],
                metadata=[release("Python 3.15.6")],
            )
            content = (root / ".python-version").read_text(encoding="utf-8")

        self.assertEqual(result, 1)
        self.assertEqual(record["status"], "error")
        self.assertEqual(content, "3.15.7\n")

    def test_expected_version_mismatch_rejects_update_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root_with_version(Path(temporary), "3.15.6")
            result, record = self._run_cli(
                root,
                ["--update", "--expected-version", "3.15.8", "--json"],
                metadata=[release("Python 3.15.7")],
            )
            content = (root / ".python-version").read_text(encoding="utf-8")

        self.assertEqual(result, 1)
        self.assertEqual(record["status"], "error")
        self.assertEqual(content, "3.15.6\n")

    def test_expected_version_must_be_an_exact_supported_series(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root_with_version(Path(temporary))
            opener = FakeOpener(FakeResponse(b"[]"))
            result, record = self._run_cli(
                root,
                ["--update", "--expected-version", "3.16.1", "--json"],
                opener=opener,
            )

        self.assertEqual(result, 1)
        self.assertEqual(record["status"], "error")
        self.assertEqual(opener.requests, [])

    def test_expected_version_rejects_a_leading_zero_patch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root_with_version(Path(temporary))
            opener = FakeOpener(FakeResponse(b"[]"))
            result, record = self._run_cli(
                root,
                ["--update", "--expected-version", "3.15.00", "--json"],
                opener=opener,
            )

        self.assertEqual(result, 1)
        self.assertEqual(record["status"], "error")
        self.assertEqual(opener.requests, [])

    def test_exact_version_parsers_reject_non_ascii_digits(self):
        non_ascii_patch = "3.15.\u0661"
        malformed_release = release("Python 3.15.\u0661")

        with self.assertRaises(updater.VersionError):
            updater.parse_stable_version(non_ascii_patch)
        with self.assertRaises(updater.MetadataError):
            updater._parse_content_length("\u0661")
        with self.assertRaises(updater.MetadataError):
            updater.resolve_latest_stable_version(metadata=[malformed_release])

    def test_stable_version_parser_regression_matrix(self) -> None:
        for value in ("3.15.1", "3.15.6", "3.15.7"):
            with self.subTest(value=value):
                self.assertEqual(str(updater.parse_stable_version(value)), value)

        for value in ("3.15.06", "3.15.-1", "3.16.0", "3.14.9", "3.15.\u0661"):
            with self.subTest(value=value), self.assertRaises(updater.VersionError):
                updater.parse_stable_version(value)

    def test_malformed_json_is_rejected(self):
        self._assert_metadata_failure(FakeResponse(b"{"))

    def test_nonstandard_json_constants_are_rejected(self) -> None:
        for payload in (b'{"value":NaN}', b'{"value":Infinity}', b'{"value":-Infinity}'):
            with self.subTest(payload=payload), self.assertRaises(updater.MetadataError):
                updater._decode_metadata(payload)

    def test_metadata_body_larger_than_two_mib_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root_with_version(Path(temporary))
            opener = FakeOpener(FakeResponse(b" " * ((2 * 1024 * 1024) + 1)))
            result, record = self._run_cli(root, ["--check", "--json"], opener=opener)

        self.assertEqual(result, 1)
        self.assertEqual(record["status"], "error")
        self.assertTrue(opener.requests)

    def test_truncated_metadata_is_rejected(self):
        self._assert_metadata_failure(FakeResponse(b"[]", content_length=3))

    def test_non_json_body_is_rejected(self):
        self._assert_metadata_failure(FakeResponse(b"<html>not-json</html>"))

    def test_bad_content_type_is_rejected(self):
        self._assert_metadata_failure(FakeResponse(b"[]", content_type="text/html"))

    def test_redirect_is_rejected(self):
        self._assert_metadata_failure(FakeResponse(b"[]", url="https://mirror.invalid/releases"))

    def test_network_error_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root_with_version(Path(temporary))
            result, record = self._run_cli(
                root,
                ["--check", "--json"],
                opener=FakeOpener(error=urllib.error.URLError("offline")),
            )

        self.assertEqual(result, 1)
        self.assertEqual(record["status"], "error")

    def test_noncanonical_metadata_url_is_rejected_before_opening(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root_with_version(Path(temporary))
            opener = FakeOpener(FakeResponse(b"[]"))
            invalid_url = urllib.parse.urlunsplit(
                ("http", "www.python.org", "/api/v2/downloads/release/", "is_published=true", "")
            )
            with mock.patch.object(updater, "RELEASE_API_URL", invalid_url):
                result, record = self._run_cli(root, ["--check", "--json"], opener=opener)

        self.assertEqual(result, 1)
        self.assertEqual(record["status"], "error")
        self.assertEqual(opener.requests, [])

    def test_schema_with_unpublished_or_malformed_records_is_rejected(self):
        with self.subTest("unpublished"):
            unpublished_release = release("Python 3.15.7", published=False)
            with self.assertRaises(updater.MetadataError):
                updater.resolve_latest_stable_version(metadata=[unpublished_release])
        with self.subTest("non-array"):
            with self.assertRaises(updater.MetadataError):
                updater.resolve_latest_stable_version(metadata={"objects": []})
        with self.subTest("bad-boolean"):
            with self.assertRaises(updater.MetadataError):
                updater.resolve_latest_stable_version(
                    metadata=[{"name": "Python 3.15.7", "is_published": "true", "pre_release": False}]
                )

    def test_symlink_target_is_refused_without_touching_its_destination(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = root / "outside-version"
            destination.write_text("3.15.6\n", encoding="utf-8")
            (root / ".python-version").symlink_to(destination)
            result, record = self._run_cli(
                root,
                ["--update", "--expected-version", "3.15.7", "--json"],
                metadata=[release("Python 3.15.7")],
            )
            destination_content = destination.read_text(encoding="utf-8")

        self.assertEqual(result, 1)
        self.assertEqual(record["status"], "error")
        self.assertEqual(destination_content, "3.15.6\n")

    def test_symlinked_root_path_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            real_root = self._root_with_version(parent / "real")
            root_link = parent / "root-link"
            root_link.symlink_to(real_root, target_is_directory=True)
            result, record = self._run_cli(
                root_link,
                ["--check", "--json"],
                metadata=[release("Python 3.15.7")],
            )

        self.assertEqual(result, 1)
        self.assertEqual(record["status"], "error")

    def _assert_metadata_failure(self, response: object) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root_with_version(Path(temporary))
            result, record = self._run_cli(root, ["--check", "--json"], opener=FakeOpener(response))

        self.assertEqual(result, 1)
        self.assertEqual(record["status"], "error")



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
