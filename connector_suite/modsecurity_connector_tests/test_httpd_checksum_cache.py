"""Private immutable HTTPD checksum-cache controls; never synthetic remote proof."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from modsecurity_test_framework.connector_context import load_source, test_root

HELPER = load_source(test_root() / "ci/provisioning/httpd-checksum-cache.py")
URL = "https://downloads.apache.org/httpd/httpd-2.4.69.tar.bz2"
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
        with mock.patch.object(HELPER, "approved_contract", return_value=(URL, DIGEST)):
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
