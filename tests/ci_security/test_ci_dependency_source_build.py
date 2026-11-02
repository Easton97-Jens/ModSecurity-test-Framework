"""Provenance and isolation boundaries of the CPython 3.15 source installer."""

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "source_dependency_installer",
    ROOT / "ci/tools/install_hash_locked_ci_dependencies.py",
)
assert SPEC is not None and SPEC.loader is not None
INSTALLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSTALLER)


class Response(io.BytesIO):
    status = 200

    def geturl(self):
        return "https://files.pythonhosted.org/packages/aa/bb/test.tar.gz"


class SourceDependencyBuildTests(unittest.TestCase):
    def test_runtime_admits_venv_and_verified_actions_setup_python(self):
        with patch.object(INSTALLER.sys, "base_prefix", "/different-base"):
            INSTALLER.require_runtime_environment()
        with tempfile.TemporaryDirectory() as temporary:
            prefix = Path(temporary)
            executable = prefix / "bin/python"
            executable.parent.mkdir()
            executable.write_text("fixture")
            with (
                patch.object(INSTALLER.sys, "prefix", str(prefix)),
                patch.object(INSTALLER.sys, "base_prefix", str(prefix)),
                patch.object(INSTALLER.sys, "executable", str(executable)),
                patch.dict(
                    os.environ,
                    {"GITHUB_ACTIONS": "true", "pythonLocation": str(prefix)},
                    clear=True,
                ),
            ):
                INSTALLER.require_runtime_environment()
                for overrides in (
                    {"GITHUB_ACTIONS": "false", "pythonLocation": str(prefix)},
                    {"pythonLocation": str(prefix)},
                    {"GITHUB_ACTIONS": "true"},
                    {"GITHUB_ACTIONS": "true", "pythonLocation": str(prefix.parent)},
                ):
                    with (
                        self.subTest(overrides=overrides),
                        patch.dict(os.environ, overrides, clear=True),
                    ):
                        with self.assertRaises(INSTALLER.InstallError):
                            INSTALLER.require_runtime_environment()
                with patch.object(INSTALLER.sys, "executable", "/usr/bin/python3"):
                    with self.assertRaises(INSTALLER.InstallError):
                        INSTALLER.require_runtime_environment()

    def test_only_fixed_official_file_urls_are_accepted(self):
        self.assertEqual(
            INSTALLER.artifact_name(
                "https://files.pythonhosted.org/packages/aa/bb/test.tar.gz"
            ),
            "test.tar.gz",
        )
        for url in (
            "http://files.pythonhosted.org/packages/aa/file.whl",
            "https://files.pythonhosted.org.evil.invalid/packages/aa/file.whl",
            "https://user:secret@files.pythonhosted.org/packages/aa/file.whl",
            "https://files.pythonhosted.org/packages/aa/../file.whl",
            "https://files.pythonhosted.org/packages/aa/file.whl?token=secret",
        ):
            with self.subTest(url=url), self.assertRaises(INSTALLER.InstallError):
                INSTALLER.artifact_name(url)

    def test_hash_is_checked_before_file_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            opener = unittest.mock.Mock()
            opener.open.return_value = Response(b"unverified source")
            with patch.object(INSTALLER.request, "build_opener", return_value=opener):
                with self.assertRaisesRegex(INSTALLER.InstallError, "SHA-256 mismatch"):
                    INSTALLER.download_verified(
                        Response().geturl(), "0" * 64, directory
                    )
            self.assertEqual(list(directory.iterdir()), [])
            opener.open.return_value = Response(b"verified source")
            with patch.object(INSTALLER.request, "build_opener", return_value=opener):
                result = INSTALLER.download_verified(
                    Response().geturl(),
                    hashlib.sha256(b"verified source").hexdigest(),
                    directory,
                )
            self.assertEqual(result.read_bytes(), b"verified source")

    def test_redirect_handler_fails_closed(self):
        with self.assertRaisesRegex(INSTALLER.InstallError, "redirects"):
            INSTALLER.NoRedirect().redirect_request(
                None, None, 302, "", {}, "https://evil.invalid"
            )

    def test_source_archive_rejects_traversal_links_and_devices(self):
        for name, kind in (
            ("../escape", tarfile.REGTYPE),
            ("/absolute", tarfile.REGTYPE),
            ("pyyaml-6.0.3/link", tarfile.SYMTYPE),
            ("pyyaml-6.0.3/hardlink", tarfile.LNKTYPE),
            ("pyyaml-6.0.3/device", tarfile.CHRTYPE),
            ("different-root/file", tarfile.REGTYPE),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                archive = directory / "pyyaml-6.0.3.tar.gz"
                with tarfile.open(archive, "w:gz") as stream:
                    entry = tarfile.TarInfo(name)
                    entry.type = kind
                    entry.linkname = "../../outside"
                    stream.addfile(entry)
                output = directory / "output"
                output.mkdir()
                with self.assertRaisesRegex(INSTALLER.InstallError, "unsafe member"):
                    INSTALLER.extract_source(archive, output)
                self.assertEqual(list(output.iterdir()), [])

    def test_build_environment_has_no_inherited_credentials_or_python_overrides(self):
        with patch.dict(
            os.environ,
            {
                "GITHUB_TOKEN": "secret",
                "HTTPS_PROXY": "https://secret.invalid",
                "PIP_INDEX_URL": "https://secret.invalid",
                "PYTHONPATH": "/untrusted",
                "PYYAML_FORCE_LIBYAML": "1",
            },
        ):
            environment = INSTALLER.clean_environment(Path("/build"))
        for name in ("GITHUB_TOKEN", "HTTPS_PROXY", "PIP_INDEX_URL", "PYTHONPATH"):
            self.assertNotIn(name, environment)
        self.assertEqual(environment["PYYAML_FORCE_LIBYAML"], "0")
        self.assertEqual(environment["PIP_NO_INDEX"], "1")
        self.assertEqual(environment["PIP_CONFIG_FILE"], os.devnull)

    def test_build_lock_must_be_complete_unique_and_match_source(self):
        values = INSTALLER.PINS.canonical_values(ROOT / "ci/lib/common.sh", ROOT)
        document = json.loads(INSTALLER.BUILD_LOCK.read_text())
        source, wheels = INSTALLER.validated_build_lock(values)
        self.assertEqual(len(wheels), 4)
        self.assertEqual(
            INSTALLER.artifact_name(source), values["CI_CANONICAL_PYYAML_ARTIFACT"]
        )
        for mutation in ("duplicate", "missing", "source", "hash"):
            with self.subTest(mutation=mutation):
                changed = json.loads(json.dumps(document))
                if mutation == "duplicate":
                    changed["wheels"][1] = changed["wheels"][0]
                elif mutation == "missing":
                    changed["wheels"].pop()
                elif mutation == "source":
                    changed["source_url"] = source.replace("6.0.3", "6.0.2")
                else:
                    changed["wheels"][0]["sha256"] = "invalid"
                with patch.object(
                    INSTALLER.PINS, "read_utf8", return_value=json.dumps(changed)
                ):
                    with self.assertRaises(INSTALLER.InstallError):
                        INSTALLER.validated_build_lock(values)

    def test_no_builder_runs_if_source_verification_fails(self):
        values = INSTALLER.PINS.canonical_values(ROOT / "ci/lib/common.sh", ROOT)
        with tempfile.TemporaryDirectory() as temporary:
            with (
                patch.object(
                    INSTALLER,
                    "download_verified",
                    side_effect=INSTALLER.InstallError("bad digest"),
                ),
                patch.object(INSTALLER, "run") as run,
                self.assertRaisesRegex(INSTALLER.InstallError, "bad digest"),
            ):
                INSTALLER.source_install(values, Path(temporary))
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
