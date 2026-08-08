"""Regression coverage for the fail-closed APR-util provenance boundary."""

from __future__ import annotations

import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
COMMON = ROOT / "ci" / "lib" / "common.sh"
PREPARE_APACHE = ROOT / "ci" / "provisioning" / "prepare-apache-build.sh"
PINNED = {
    "APR_UTIL_VERSION": "1.6.4",
    "APR_UTIL_SOURCE_URL": "https://downloads.apache.org/apr/apr-util-1.6.4.tar.bz2",
    "APR_UTIL_SHA256": "3e2ae08f40efa0c3701e54a954cefa08242de22a69f91a8ae44fc1e624ba309b",
    "APR_UTIL_SHA256_URL": "https://downloads.apache.org/apr/apr-util-1.6.4.tar.bz2.sha256",
}


class AprUtilProvenanceTests(unittest.TestCase):
    maxDiff = None

    def run_guard(self, overrides: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        for name in PINNED:
            environment.pop(name, None)
        if overrides:
            environment.update(overrides)
        return subprocess.run(
            [
                "sh",
                "-eu",
                "-c",
                f'. "{COMMON}"\nci_require_apr_util_pinned_provenance',
            ],
            cwd=ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )

    def write_executable(self, path: Path, contents: str) -> None:
        path.write_text(textwrap.dedent(contents).lstrip(), encoding="utf-8")
        path.chmod(0o755)

    def test_current_central_tuple_is_exact_and_accepted(self):
        source = COMMON.read_text(encoding="utf-8")
        for name, expected in PINNED.items():
            with self.subTest(name=name):
                self.assertIn(f'{name.replace("APR_UTIL_", "APR_UTIL_PINNED_")}="{expected}"', source)

        completed = self.run_guard()

        self.assertEqual(completed.returncode, 0, completed.stdout)

    def test_noncanonical_runtime_values_fail_closed(self):
        invalid_values = {
            "stale-version": {"APR_UTIL_VERSION": "1.6.3"},
            "foreign-host": {
                "APR_UTIL_SOURCE_URL": "https://mirror.example.invalid/apr-util-1.6.4.tar.bz2"
            },
            "wrong-asset": {
                "APR_UTIL_SOURCE_URL": "https://downloads.apache.org/apr/apr-util-1.6.3.tar.bz2"
            },
            "wrong-path": {
                "APR_UTIL_SOURCE_URL": "https://downloads.apache.org/other/apr-util-1.6.4.tar.bz2"
            },
            "missing-digest": {"APR_UTIL_SHA256": ""},
            "malformed-digest": {"APR_UTIL_SHA256": "not-a-sha256"},
            "mismatched-digest": {"APR_UTIL_SHA256": "0" * 64},
            "missing-checksum-url": {"APR_UTIL_SHA256_URL": ""},
            "wrong-checksum-url": {
                "APR_UTIL_SHA256_URL": "https://downloads.apache.org/apr/other.sha256"
            },
        }
        for case, overrides in invalid_values.items():
            with self.subTest(case=case):
                completed = self.run_guard(overrides)

                self.assertEqual(completed.returncode, 77, completed.stdout)
                self.assertIn("BLOCKED:", completed.stdout)

    def test_invalid_tuple_stops_the_real_preparer_before_network_commands(self):
        temporary_root = os.environ.get("TEST_TMPDIR")
        with tempfile.TemporaryDirectory(prefix="apr-util-provenance-", dir=temporary_root) as temporary:
            root = Path(temporary)
            fake_bin = root / "fake-bin"
            fake_bin.mkdir()
            marker = root / "network-command-invoked"
            for command in ("curl", "git", "tar", "sha256sum"):
                self.write_executable(
                    fake_bin / command,
                    """
                    #!/bin/sh
                    printf '%s\\n' "$0" >> "$MARKER"
                    exit 99
                    """,
                )

            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{fake_bin}{os.pathsep}{environment['PATH']}",
                    "MARKER": str(marker),
                    "FRAMEWORK_ROOT": str(ROOT),
                    "CI_ROOT": str(ROOT / "ci"),
                    "CONNECTOR_ROOT": str(ROOT),
                    "VERIFIED_RUN_ROOT": str(root / "verified"),
                    "BUILD_ROOT": str(root / "build"),
                    "APACHE_BUILD_ROOT": str(root / "build" / "apache-build"),
                    "APACHE_DOWNLOAD_DIR": str(root / "build" / "downloads"),
                    "MODSECURITY_V3_SOURCE_DIR": str(root / "missing-v3"),
                    "MODSECURITY_APACHE_SOURCE_DIR": str(root / "missing-apache"),
                    "AUTO_FETCH_SMOKE_SOURCES": "0",
                    "APR_UTIL_SOURCE_URL": "https://mirror.example.invalid/apr-util-1.6.4.tar.bz2",
                }
            )
            completed = subprocess.run(
                ["sh", str(PREPARE_APACHE)],
                cwd=ROOT,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )
            network_command_invoked = marker.exists()

        self.assertEqual(completed.returncode, 77, completed.stdout)
        self.assertIn("APR_UTIL_SOURCE_URL override is not permitted", completed.stdout)
        self.assertFalse(network_command_invoked, completed.stdout)

    def test_literal_digest_guard_precedes_apr_util_extraction(self):
        source = PREPARE_APACHE.read_text(encoding="utf-8")
        build_start = source.index("build_httpd_from_source()")
        build_end = source.index("resolve_apache_tools()", build_start)
        apache_build = source[build_start:build_end]

        self.assertIn("download_apr_util_file apr-util", apache_build)
        self.assertIn("verify_required_apr_util_sha256", apache_build)
        self.assertIn("verify_apr_util_sha256_url", apache_build)
        self.assertNotIn("download_file apr-util", apache_build)
        self.assertNotIn("verify_sha256_literal apr-util", apache_build)
        self.assertLess(
            apache_build.index("verify_required_apr_util_sha256"),
            apache_build.index("extract_tar_strip apr-util"),
        )
        guard_index = source.index("ci_require_apr_util_pinned_provenance || blocked")
        self.assertLess(guard_index, source.index("ensure_modsecurity_v3_source", guard_index))

    def test_apr_util_download_does_not_follow_unreviewed_redirects(self):
        source = PREPARE_APACHE.read_text(encoding="utf-8")
        helper_start = source.index("download_apr_util_file()")
        helper_end = source.index("verify_sha256_url()", helper_start)
        helper = source[helper_start:helper_end]

        self.assertIn("ci_require_apr_util_pinned_provenance", helper)
        self.assertIn("--proto '=https' --proto-redir '=https' --max-redirs 0", helper)
        self.assertNotIn("curl -L", helper)


if __name__ == "__main__":
    unittest.main()
