from __future__ import annotations

import base64
import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "ci/provisioning/import-mrts-cases.py"


def load_importer(name: str):
    spec = importlib.util.spec_from_file_location(name, SOURCE)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {SOURCE}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class ImportMrtsCasesSonarTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.importer = load_importer("import_mrts_cases_sonar_test")

    @staticmethod
    def synthetic_inputs(root: Path) -> tuple[Path, Path]:
        ftw_dir = root / "ftw"
        rules_dir = root / "rules"
        ftw_dir.mkdir()
        rules_dir.mkdir()
        (ftw_dir / "synthetic.yaml").write_text(
            "\n".join(
                [
                    "tests:",
                    "  - test_title: synthetic",
                    "    ruleid: 42",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        (rules_dir / "synthetic.conf").write_text(
            'SecRule ARGS "@rx safe" "id:42,phase:2,deny,status:403"\n',
            encoding="utf-8",
        )
        return ftw_dir, rules_dir

    def test_rendering_and_definition_index_preserve_contract(self) -> None:
        rendered = self.importer.render_yaml(
            {
                "rules": "SecRuleEngine On\n",
                "nested": {"enabled": True},
                "items": [{"name": "value"}, ["child"], "plain"],
            }
        )
        self.assertEqual(
            rendered,
            [
                "rules: |",
                "  SecRuleEngine On",
                "nested:",
                "  enabled: true",
                "items:",
                "  - name: value",
                "  -",
                "    - child",
                "  - plain",
            ],
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            definitions = Path(temporary_directory) / "definitions"
            definitions.mkdir()
            definition = definitions / "synthetic.yaml"
            definition.write_text(
                "testfile: synthetic-test.yaml\nrulefile: synthetic-rule.conf\n",
                encoding="utf-8",
            )
            index = self.importer.source_definition_index([definitions])
            for alias in (
                "synthetic.yaml",
                "synthetic",
                "synthetic-test.yaml",
                "synthetic-test",
                "synthetic-rule.conf",
                "synthetic-rule",
            ):
                self.assertEqual(definition, index[alias])

    def test_encoded_and_stage_requests_reject_malformed_input_and_keep_valid_data(self) -> None:
        payload = (
            b"POST /upload HTTP/1.1\r\n"
            b"Host: ignored.example\r\n"
            b"Content-Type: multipart/form-data; boundary=synthetic\r\n\r\n"
            b"--synthetic\r\n"
            b"Content-Disposition: form-data; name=\"field\"; filename=\"sample.txt\"\r\n"
            b"Content-Type: text/plain\r\n\r\n"
            b"payload\r\n"
            b"--synthetic--\r\n"
        )
        request, reliable = self.importer.request_from_encoded(
            base64.b64encode(payload).decode("ascii")
        )
        self.assertTrue(reliable)
        self.assertEqual(request["method"], "POST")
        self.assertEqual(request["path"], "/upload")
        self.assertEqual(
            request["multipart"],
            {
                "boundary": "synthetic",
                "parts": [
                    {
                        "name": "field",
                        "body": "payload",
                        "filename": "sample.txt",
                        "content_type": "text/plain",
                    }
                ],
            },
        )

        malformed, malformed_reliable = self.importer.request_from_encoded("not base64")
        self.assertFalse(malformed_reliable)
        self.assertEqual(malformed, {"method": "GET", "path": "/"})

        request, reliable = self.importer.request_from_stage(
            {
                "input": {
                    "method": "GET",
                    "uri": "/search",
                    "headers": [
                        {"name": "Host", "value": "ignored.example"},
                        {"name": "X-Synthetic", "value": "accepted"},
                    ],
                    "data": "term=safe",
                }
            }
        )
        self.assertTrue(reliable)
        self.assertEqual(request["path"], "/search?term=safe")
        self.assertEqual(request["headers"], {"X-Synthetic": "accepted"})

    def test_build_case_keeps_status_and_rule_identity(self) -> None:
        case = self.importer.build_case(
            Path("/synthetic/source.yaml"),
            {
                "test_title": "case",
                "ruleid": "42",
                "stages": [
                    {
                        "input": {"method": "GET", "uri": "/safe"},
                        "output": {"status": 403},
                    }
                ],
            },
            'SecRule ARGS "@rx safe" "id:42,phase:2,deny,status:403"\n',
            Path("/synthetic/rules.conf"),
            {},
            {},
            framework_root=Path("/synthetic"),
            mrts_corpus="synthetic",
            source_definition=None,
            upstream_file=None,
            generated_ftw_file=Path("/synthetic/generated.yaml"),
            case_status="computed",
            pending_reason="",
        )
        self.assertEqual(case["status"], "active")
        self.assertEqual(case["expect"]["rule_id"], 42)
        self.assertEqual(case["metadata"]["mrts_rule_id"], 42)
        self.assertEqual(case["request"]["path"], "/safe")

    def test_private_roots_reject_public_or_symlink_output_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            private_root = root / "private"
            private_root.mkdir(mode=0o700)
            public_root = root / "public"
            public_root.mkdir()
            public_root.chmod(0o777)
            outside_root = root / "outside"
            outside_root.mkdir(mode=0o700)
            link = private_root / "linked-output"
            link.symlink_to(outside_root, target_is_directory=True)

            self.assertEqual(
                private_root.resolve(),
                self.importer.private_runtime_root(private_root, "private output"),
            )
            with self.assertRaisesRegex(ValueError, "publicly writable"):
                self.importer.private_runtime_root(public_root, "public output")
            with self.assertRaisesRegex(ValueError, "symlink"):
                self.importer.private_runtime_root(link, "linked output")
            with self.assertRaises(ValueError):
                self.importer.safe_corpus_component("../outside")

            with patch.dict(os.environ, {"TMPDIR": str(public_root)}, clear=True):
                self.assertIsNone(self.importer.configured_mrts_build_root("", ""))

    def test_main_rejects_shared_temp_fallback_without_writing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            public_root = root / "public"
            public_root.mkdir()
            public_root.chmod(0o777)
            environment = dict(os.environ)
            for name in (
                "VERIFIED_RUN_ROOT",
                "BUILD_ROOT",
                "MRTS_BUILD_ROOT",
                "MRTS_ROOT",
            ):
                environment.pop(name, None)
            environment["TMPDIR"] = str(public_root)
            environment["RUNNER_TEMP"] = str(public_root)
            result = subprocess.run(
                [sys.executable, str(SOURCE), "--framework-root", str(ROOT)],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                env=environment,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("MRTS build root is required", result.stderr)
            self.assertFalse((public_root / "ModSecurity-conector-verified").exists())

    def test_main_imports_to_a_private_synthetic_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            ftw_dir, rules_dir = self.synthetic_inputs(root)
            output_dir = root / "output"
            classifications = root / "classifications.yaml"
            environment = dict(os.environ)
            for name in (
                "VERIFIED_RUN_ROOT",
                "BUILD_ROOT",
                "MRTS_BUILD_ROOT",
                "MRTS_ROOT",
            ):
                environment.pop(name, None)
            result = subprocess.run(
                [
                    sys.executable,
                    str(SOURCE),
                    "--framework-root",
                    str(ROOT),
                    "--mrts-ftw-dir",
                    str(ftw_dir),
                    "--mrts-rules-dir",
                    str(rules_dir),
                    "--output-dir",
                    str(output_dir),
                    "--classifications-file",
                    str(classifications),
                    "--mrts-corpus",
                    "synthetic",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                env=environment,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            generated = list(output_dir.glob("*.yaml"))
            self.assertEqual(len(generated), 1)
            generated_case = self.importer.load_yaml(generated[0])
            self.assertEqual(generated_case["status"], "pending")
            self.assertEqual(generated_case["expect"]["rule_id"], 42)


if __name__ == "__main__":
    unittest.main()
