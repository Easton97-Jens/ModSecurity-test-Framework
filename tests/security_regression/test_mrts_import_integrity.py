"""On-demand MRTS import boundary regressions; no connector runtime claims."""

from __future__ import annotations

import base64
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from tests.security_regression.test_import_mrts_cases_sonar import ROOT, load_importer


class MrtsImportIntegrityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.importer = load_importer("mrts_import_integrity")

    def import_fixture(self, root: Path, headers: object, *, invalid_second: bool = False) -> Path:
        ftw = root / "ftw"
        rules = root / "rules"
        ftw.mkdir(exist_ok=True)
        rules.mkdir(exist_ok=True)
        test = {
            "test_title": "header_roundtrip", "ruleid": 42,
            "stages": [{"input": {"method": "GET", "uri": "/", "headers": headers},
                        "output": {"status": 403}}],
        }
        tests = [test]
        if invalid_second:
            tests.append({**test, "test_title": "invalid", "stages": [
                {"input": {"headers": {"bad name": "invalid"}}, "output": {"status": 403}}
            ]})
        (ftw / "headers.yaml").write_text(yaml.safe_dump({"tests": tests}), encoding="utf-8")
        (rules / "headers.conf").write_text(
            'SecRule REQUEST_HEADERS "@rx match" "id:42,phase:1,deny,status:403"\n',
            encoding="utf-8",
        )
        self.importer.import_cases(
            ROOT, ftw, rules, root / "catalog", root / "absent-classifications.yaml",
            mrts_corpus="synthetic", source_definition_dirs=[], upstream_ftw_dir=None,
            case_status="computed", pending_reason="",
        )
        return next((root / "catalog").glob("*.yaml"))

    def test_numeric_header_name_survives_full_import_and_runner_load(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case_path = self.import_fixture(Path(temporary), {"2": "on"})
            from runner_core import load_case
            self.assertEqual(load_case(case_path)["request"]["headers"], {"2": "on"})

    def test_observed_mrts_pass_preserves_catalog_nonpromotion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case_path = self.import_fixture(Path(temporary), {"2": "safe"})
            from runner_core import case_info, load_case
            from msconnector_models import connector_summary
            info = case_info(load_case(case_path), case_path, "apache", "pass", 403)
            self.assertTrue(info["live_executed"])
            self.assertFalse(info["runtime_verified"])
            summary = connector_summary(connector="apache", entries=[info])
            self.assertEqual(summary["summary"]["pass"], 1)
            self.assertEqual(summary["verified_variables"], [])

    def test_string_keys_and_values_preserve_exact_yaml_content(self) -> None:
        values = ["2", "02", "-1", "1e4", "1.0", "yes", "NO", "on", "off", "null", "~",
                  ".nan", "2026-10-28", "#text", "a: b", "*alias", "!tag", "[x]", "{x}",
                  "", " leading ", "quote\"slash\\", "line\n\n", "cr\r\ntab\t", "\x00", "ü", "😀", "\u0085", "\u2028", "\u2029"]
        original = {value: value for value in values}
        self.assertEqual(yaml.safe_load("\n".join(self.importer.render_yaml(original))), original)

    def test_repeated_header_order_survives_import_and_encoded_request(self) -> None:
        headers = [{"name": "X-Z", "value": "first"}, {"name": "2", "value": "02"},
                   {"name": "x-z", "value": "second"}]
        with tempfile.TemporaryDirectory() as temporary:
            case_path = self.import_fixture(Path(temporary), headers)
            from runner_core import load_case, request_header_entries
            case = load_case(case_path)
            self.assertEqual(request_header_entries(case), [(x["name"], x["value"]) for x in headers])
        raw = b"GET / HTTP/1.1\r\nX-Z: first\r\n2: 02\r\nx-z: second\r\n\r\n"
        request, reliable = self.importer.request_from_encoded(base64.b64encode(raw).decode("ascii"))
        self.assertTrue(reliable)
        self.assertEqual(request["headers"], headers)

    def test_invalid_header_name_and_control_values_still_fail(self) -> None:
        for headers in ({"bad name": "x"}, {"X-Test": "bad\r\nInjected: yes"}, {"X-Test": "nul\x00"}):
            with self.subTest(headers=headers), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                with self.assertRaisesRegex(ValueError, "request.headers"):
                    self.import_fixture(root, headers)
                self.assertFalse((root / "catalog").exists())

    def test_failed_second_case_does_not_publish_partial_or_replace_previous_catalog(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(ValueError, "request.headers"):
                self.import_fixture(root, {"2": "safe"}, invalid_second=True)
            self.assertFalse((root / "catalog").exists())
            original = self.import_fixture(root, {"2": "original"})
            expected = original.read_bytes()
            with self.assertRaisesRegex(ValueError, "request.headers"):
                self.import_fixture(root, {"2": "new"}, invalid_second=True)
            self.assertEqual(original.read_bytes(), expected)
            self.assertEqual(list((root / "catalog").iterdir()), [original])
            self.assertEqual(list(root.glob(".catalog.import-*")), [])

    def test_writer_failure_keeps_previous_catalog(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self.import_fixture(root, {"2": "original"})
            expected = original.read_bytes()
            write_case = self.importer.write_case

            def failing_writer(path: Path, case: object) -> None:
                write_case(path, case)
                raise OSError("synthetic disk write failure")

            with patch.object(self.importer, "write_case", side_effect=failing_writer):
                with self.assertRaisesRegex(OSError, "disk write failure"):
                    self.import_fixture(root, {"2": "new"})
            self.assertEqual(original.read_bytes(), expected)
            self.assertEqual(list(root.glob(".catalog.import-*")), [])

    def test_empty_import_is_an_error_without_a_published_catalog(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ftw = root / "ftw"
            ftw.mkdir()
            with self.assertRaisesRegex(ValueError, "empty catalog"):
                self.importer.import_cases(
                    ROOT, ftw, root / "rules", root / "catalog", root / "absent.yaml",
                    mrts_corpus="synthetic", source_definition_dirs=[], upstream_ftw_dir=None,
                    case_status="computed", pending_reason="",
                )
            self.assertFalse((root / "catalog").exists())


if __name__ == "__main__":
    unittest.main()
