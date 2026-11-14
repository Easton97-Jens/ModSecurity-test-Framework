"""Private immutable HTTPD checksum-cache controls; never synthetic remote proof."""
from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from modsecurity_test_framework.connector_context import load_source, test_root

HELPER = load_source(test_root() / "ci/provisioning/httpd-checksum-cache.py")
URL, _ = HELPER.approved_contract()
PAYLOAD = b"controlled source archive fixture"
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()


class HttpdChecksumCacheTests(unittest.TestCase):
    def fixture(self, root):
        archive = root / "httpd-2.4.69.tar.bz2"
        checksum = root / "httpd.sha256"
        archive.write_bytes(PAYLOAD)
        checksum.write_text(DIGEST + " *" + archive.name + "\n")
        archive.chmod(0o600)
        checksum.chmod(0o600)
        return archive, checksum

    def verify(self, archive, checksum, **overrides):
        arguments = dict(archive=archive, checksum=checksum, source_url=URL,
                         checksum_url=URL + ".sha256", expected_sha=DIGEST)
        arguments.update(overrides)
        metadata = DIGEST + " *httpd-2.4.69.tar.bz2\n"
        with mock.patch.object(HELPER, "approved_contract", return_value=(URL, DIGEST)), \
                mock.patch.object(HELPER, "HTTPD_METADATA_SHA256", hashlib.sha256(metadata.encode()).hexdigest()):
            return HELPER.verify_cache(**arguments)

    def test_valid_private_cache_rechecks_actual_bytes_without_network(self):
        with tempfile.TemporaryDirectory(prefix="httpd-checksum-valid-") as temporary:
            archive, checksum = self.fixture(Path(temporary))
            result = self.verify(archive, checksum)
            self.assertEqual(result["provenance"], "cached_verified_metadata")
            self.assertEqual(result["archive_sha256"], DIGEST)
            self.assertEqual(result["checksum_sha256"], hashlib.sha256(checksum.read_bytes()).hexdigest())

    def test_wrong_provider_pin_or_filename_cannot_authorize_cache_reuse(self):
        for changed in (dict(source_url=URL.replace("downloads.apache.org", "foreign.invalid")),
                        dict(checksum_url=URL + ".sha512"), dict(expected_sha="0" * 64)):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory(prefix="httpd-checksum-identity-") as temporary:
                archive, checksum = self.fixture(Path(temporary))
                with self.assertRaises(ValueError):
                    self.verify(archive, checksum, **changed)

    def test_wrong_actual_source_or_cached_checksum_fails(self):
        for changed in ("archive", "checksum", "filename"):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory(prefix="httpd-checksum-content-") as temporary:
                archive, checksum = self.fixture(Path(temporary))
                if changed == "archive":
                    archive.write_bytes(PAYLOAD + b"changed")
                elif changed == "checksum":
                    checksum.write_text("0" * 64 + " *" + archive.name + "\n")
                else:
                    checksum.write_text(DIGEST + " *foreign.tar.bz2\n")
                with self.assertRaises(ValueError):
                    self.verify(archive, checksum)

    def test_immutable_source_is_exact_current_release_and_cannot_be_replaced(self):
        approved_url, approved_sha = HELPER.approved_contract()
        self.assertEqual(HELPER.metadata_source(approved_url, approved_url + ".sha256", approved_sha),
                         HELPER.HTTPD_METADATA_URL)
        for changes in ((approved_url.replace("2.4.69", "2.4.70"), approved_url + ".sha256", approved_sha),
                        (approved_url, approved_url + ".sha256?mirror=foreign", approved_sha),
                        (approved_url, approved_url + ".sha256", "0" * 64)):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                HELPER.metadata_source(*changes)
        for changed_url in (approved_url.replace("downloads.apache.org", "foreign.invalid"),
                            approved_url.replace("https://", "http://"),
                            approved_url.replace("downloads.apache.org", "downloads.apache.org:443"),
                            approved_url + "?mirror=other", approved_url + "#fragment",
                            approved_url.replace("/httpd/", "/other/"),
                            approved_url.replace("2.4.69", "2.4.70")):
            with self.subTest(changed_url=changed_url), \
                    mock.patch.object(HELPER, "approved_contract", return_value=(changed_url, approved_sha)), \
                    self.assertRaises(ValueError):
                HELPER.metadata_source(changed_url, changed_url + ".sha256", approved_sha)

    def test_downloaded_object_requires_exact_source_and_independent_metadata_digest(self):
        with tempfile.TemporaryDirectory(prefix="httpd-metadata-object-") as temporary:
            archive, checksum = self.fixture(Path(temporary))
            metadata_sha = hashlib.sha256(checksum.read_bytes()).hexdigest()
            with mock.patch.object(HELPER, "approved_contract", return_value=(URL, DIGEST)), \
                    mock.patch.object(HELPER, "HTTPD_METADATA_SHA256", metadata_sha):
                for source in (HELPER.HTTPD_METADATA_URL.replace("dist.apache.org", "foreign.invalid"),
                               HELPER.HTTPD_METADATA_URL.replace("89000", "89001"),
                               HELPER.HTTPD_METADATA_URL.replace("2.4.69", "2.4.70")):
                    with self.subTest(source=source), self.assertRaises(ValueError):
                        HELPER.verify_cache(archive, checksum, URL, URL + ".sha256", DIGEST, source)
                result = HELPER.verify_cache(archive, checksum, URL, URL + ".sha256", DIGEST,
                                             HELPER.HTTPD_METADATA_URL)
                self.assertEqual(result["downloaded_from"], HELPER.HTTPD_METADATA_URL)
                # Same parsed pin/filename is insufficient: object bytes are pinned independently.
                checksum.write_bytes(checksum.read_bytes() + b"\n")
                for downloaded_from in (None, HELPER.HTTPD_METADATA_URL):
                    with self.subTest(downloaded_from=downloaded_from), self.assertRaises(ValueError):
                        HELPER.verify_cache(archive, checksum, URL, URL + ".sha256", DIGEST, downloaded_from)

    def test_shell_download_failure_and_redirect_do_not_reach_metadata_verifier(self):
        source = (test_root() / "ci/provisioning/prepare-apache-build.sh").read_text()
        function = source[source.index("verify_sha256_url() {"):source.index("\nverify_apr_util_sha256_url()")]
        for mode in ("failure", "redirect"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix="httpd-download-negative-") as temporary:
                root = Path(temporary)
                python = root / "python"
                python.write_text(
                    '#!/bin/sh\ncase "$*" in\n'
                    ' *--print-download-url*) echo "' + HELPER.HTTPD_METADATA_URL + '";;\n'
                    ' *--downloaded-from*) touch "$LOG_DIR/unexpected-verifier";;\n'
                    ' *) exit 1;;\nesac\n'
                )
                python.chmod(0o700)
                environment = dict(os.environ, PYTHON=str(python), FRAMEWORK_ROOT=str(test_root()),
                                   DOWNLOAD_DIR=str(root), LOG_DIR=str(root), HTTPD_SOURCE_URL=URL,
                                   HTTPD_SHA256=DIGEST, ARTIFACTS_FILE=str(root / "artifacts"),
                                   STATUS_FILE=str(root / "status"))
                downloader = ("return 77" if mode == "failure" else
                              "RUNTIME_COMPONENT_HTTP_STATUS=302; RUNTIME_COMPONENT_REDIRECTS=0; return 0")
                script = ('blocked() { echo "$*"; exit 77; }\n'
                          'download_runtime_artifact_without_redirects_under_root() { ' + downloader + '; }\n'
                          + function + '\nverify_sha256_url httpd "$DOWNLOAD_DIR/archive" "' + URL + '.sha256"\n')
                result = subprocess.run(["sh", "-c", script], env=environment, capture_output=True, text=True,
                                        check=False)
                self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
                self.assertFalse((root / "unexpected-verifier").exists())
                self.assertFalse((root / "status").exists())

    def test_symlink_hardlink_fifo_and_public_files_are_rejected(self):
        for changed in ("symlink", "hardlink", "fifo", "public"):
            for target in ("archive", "checksum"):
                with self.subTest(changed=changed, target=target), tempfile.TemporaryDirectory(prefix="httpd-checksum-files-") as temporary:
                    root = Path(temporary)
                    archive, checksum = self.fixture(root)
                    path = archive if target == "archive" else checksum
                    if changed == "public":
                        path.chmod(0o644)
                    else:
                        saved = root / "saved"
                        path.rename(saved)
                        if changed == "symlink":
                            path.symlink_to(saved)
                        elif changed == "hardlink":
                            os.link(saved, path)
                        else:
                            os.mkfifo(path)
                    with self.assertRaises((OSError, ValueError)):
                        self.verify(archive, checksum)

    def test_symlinked_ancestor_does_not_redirect_private_cache_read(self):
        with tempfile.TemporaryDirectory(prefix="httpd-checksum-ancestor-") as temporary:
            root = Path(temporary)
            actual = root / "actual"
            actual.mkdir()
            archive, checksum = self.fixture(actual)
            alias = root / "alias"
            alias.symlink_to(actual, target_is_directory=True)
            with self.assertRaises(OSError):
                self.verify(alias / archive.name, alias / checksum.name)


if __name__ == "__main__":
    unittest.main()
