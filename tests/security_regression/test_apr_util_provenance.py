"""Regression coverage for the fail-closed APR-util provenance boundary."""

from __future__ import annotations

import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

from tests.security_regression.common_version_fixture_support import (
    write_common_fixture,
)


ROOT = Path(__file__).resolve().parents[2]
COMMON_SOURCE = ROOT / "ci" / "lib" / "common.sh"
PREPARE_APACHE = ROOT / "ci" / "provisioning" / "prepare-apache-build.sh"
RUNTIME_COMPONENT_HELPER = ROOT / "ci" / "lib" / "runtime-component-common.sh"
PINNED = {
    "APR_UTIL_VERSION": "1.6.5",
    "APR_UTIL_SHA256": "a" * 64,
}


class AprUtilProvenanceTests(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        temporary_root = os.environ.get("TEST_TMPDIR")
        self.temporary = tempfile.TemporaryDirectory(
            prefix="apr-util-provenance-", dir=temporary_root
        )
        self.fixture_root = Path(self.temporary.name) / "framework-fixture"
        self.common = write_common_fixture(
            self.fixture_root,
            COMMON_SOURCE.read_text(encoding="utf-8"),
            PINNED,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_guard(
        self, overrides: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        return self.run_shell(
            '. "$COMMON_SH"\nci_require_apr_util_pinned_provenance', overrides
        )

    def run_shell(
        self, script: str, overrides: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        for name in (
            "APR_UTIL_VERSION",
            "APR_UTIL_SOURCE_URL",
            "APR_UTIL_SHA256",
            "APR_UTIL_SHA256_URL",
        ):
            environment.pop(name, None)
        environment["COMMON_SH"] = str(self.common)
        if overrides:
            environment.update(overrides)
        return subprocess.run(
            ["sh", "-eu", "-c", script],
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

    def write_preparer_fixture(self) -> Path:
        fixture_prepare = self.fixture_root / "ci" / "provisioning" / "prepare-apache-build.sh"
        fixture_path_bootstrap = self.fixture_root / "ci" / "lib" / "path-bootstrap.sh"
        fixture_path_helper = self.fixture_root / "ci" / "lib" / "path.sh"
        fixture_runtime_component_helper = self.fixture_root / "ci" / "lib" / "runtime-component-common.sh"
        fixture_prepare.parent.mkdir(parents=True, exist_ok=True)
        fixture_prepare.write_text(PREPARE_APACHE.read_text(encoding="utf-8"), encoding="utf-8")
        fixture_path_bootstrap.write_text(
            (ROOT / "ci" / "lib" / "path-bootstrap.sh").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        fixture_path_helper.write_text(
            (ROOT / "ci" / "lib" / "path.sh").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        fixture_runtime_component_helper.write_text(
            RUNTIME_COMPONENT_HELPER.read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        (self.fixture_root / "Makefile").write_text("# test fixture\n", encoding="utf-8")
        (self.fixture_root / "tests").mkdir(exist_ok=True)
        return fixture_prepare

    def run_preparer_with_fake_network(
        self, argv: list[str], environment_overrides: dict[str, str]
    ) -> tuple[subprocess.CompletedProcess[str], bool]:
        temporary_root = os.environ.get("TEST_TMPDIR")
        with tempfile.TemporaryDirectory(
            prefix="apr-util-provenance-", dir=temporary_root
        ) as temporary:
            root = Path(temporary)
            fake_bin = root / "fake-bin"
            fake_bin.mkdir()
            marker = root / "network-command-invoked"
            for fake_command in ("curl", "git", "tar", "sha256sum"):
                self.write_executable(
                    fake_bin / fake_command,
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
                    "VERIFIED_RUN_ROOT": str(root / "verified"),
                    "BUILD_ROOT": str(root / "build"),
                    "APACHE_BUILD_ROOT": str(root / "build" / "apache-build"),
                    "APACHE_DOWNLOAD_DIR": str(root / "build" / "downloads"),
                    "MODSECURITY_V3_SOURCE_DIR": str(root / "missing-v3"),
                    "MODSECURITY_APACHE_SOURCE_DIR": str(root / "missing-apache"),
                    "AUTO_FETCH_SMOKE_SOURCES": "0",
                }
            )
            environment.update(environment_overrides)
            completed = subprocess.run(
                argv,
                cwd=ROOT,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )
            network_command_invoked = marker.exists()

        return completed, network_command_invoked

    def test_offline_reviewed_tuple_is_derived_and_accepted(self):
        source = self.common.read_text(encoding="utf-8")
        for name, expected in PINNED.items():
            with self.subTest(name=name):
                self.assertIn(f'{name}="{expected}"', source)
        self.assertIn(
            'APR_UTIL_SOURCE_URL="https://downloads.apache.org/apr/$APR_UTIL_ARCHIVE_NAME"',
            source,
        )
        self.assertIn('APR_UTIL_SHA256_URL="$APR_UTIL_SOURCE_URL.sha256"', source)
        self.assertNotIn("APR_UTIL_PINNED_", source)

        completed = self.run_guard()

        self.assertEqual(completed.returncode, 0, completed.stdout)

    def test_re_source_and_exported_reviewed_tuple_are_accepted(self):
        completed = self.run_shell(
            "\n".join(
                (
                    '. "$COMMON_SH"',
                    "ci_require_apr_util_pinned_provenance",
                    '. "$COMMON_SH"',
                    "ci_require_apr_util_pinned_provenance",
                    "export APR_UTIL_VERSION APR_UTIL_SOURCE_URL APR_UTIL_SHA256 APR_UTIL_SHA256_URL",
                    "sh -eu -c '. \"$COMMON_SH\"; ci_require_apr_util_pinned_provenance'",
                )
            )
        )

        self.assertEqual(completed.returncode, 0, completed.stdout)

    def test_exported_reviewed_tuple_reaches_child_preparer_provenance_guard(self):
        fixture_prepare = self.write_preparer_fixture()
        completed, network_command_invoked = self.run_preparer_with_fake_network(
            [
                "sh",
                "-eu",
                "-c",
                "\n".join(
                    (
                        '. "$COMMON_SH"',
                        "ci_require_apr_util_pinned_provenance",
                        "export APR_UTIL_VERSION APR_UTIL_SOURCE_URL APR_UTIL_SHA256 APR_UTIL_SHA256_URL",
                        'sh "$PREPARE_APACHE"',
                    )
                ),
            ],
            {
                "COMMON_SH": str(self.common),
                "PREPARE_APACHE": str(fixture_prepare),
                "FRAMEWORK_ROOT": str(ROOT),
                "CONNECTOR_ROOT": str(ROOT),
            },
        )

        self.assertEqual(completed.returncode, 77, completed.stdout)
        self.assertIn("missing MODSECURITY_V3_SOURCE_DIR", completed.stdout)
        self.assertNotIn("APR_UTIL_", completed.stdout)
        self.assertFalse(network_command_invoked, completed.stdout)

    def test_environment_tuple_overrides_fail_closed(self):
        invalid_values = {
            "stale-version": {"APR_UTIL_VERSION": "1.6.3"},
            "empty-version": {"APR_UTIL_VERSION": ""},
            "empty-source-url": {"APR_UTIL_SOURCE_URL": ""},
            "foreign-host": {
                "APR_UTIL_SOURCE_URL": (
                    "https://mirror.example.invalid/apr-util-"
                    f"{PINNED['APR_UTIL_VERSION']}.tar.bz2"
                )
            },
            "wrong-asset": {
                "APR_UTIL_SOURCE_URL": "https://downloads.apache.org/apr/apr-util-1.6.8999.tar.bz2"
            },
            "wrong-path": {
                "APR_UTIL_SOURCE_URL": (
                    "https://downloads.apache.org/other/apr-util-"
                    f"{PINNED['APR_UTIL_VERSION']}.tar.bz2"
                )
            },
            "missing-digest": {"APR_UTIL_SHA256": ""},
            "malformed-digest": {"APR_UTIL_SHA256": "not-a-sha256"},
            "mismatched-digest": {"APR_UTIL_SHA256": "0" * 64},
            "missing-checksum-url": {"APR_UTIL_SHA256_URL": ""},
            "wrong-checksum-url": {
                "APR_UTIL_SHA256_URL": "https://downloads.apache.org/apr/other.sha256"
            },
            "self-consistent-replacement": {
                "APR_UTIL_VERSION": "1.6.999",
                "APR_UTIL_SOURCE_URL": (
                    "https://downloads.apache.org/apr/apr-util-1.6.999.tar.bz2"
                ),
                "APR_UTIL_SHA256": "b" * 64,
                "APR_UTIL_SHA256_URL": (
                    "https://downloads.apache.org/apr/apr-util-1.6.999.tar.bz2.sha256"
                ),
            },
        }
        for case, overrides in invalid_values.items():
            with self.subTest(case=case):
                completed = self.run_guard(overrides)

                self.assertEqual(completed.returncode, 77, completed.stdout)
                self.assertIn("BLOCKED:", completed.stdout)

    def test_only_a_complete_canonical_inherited_tuple_is_accepted(self):
        canonical_tuple = {
            "APR_UTIL_VERSION": PINNED["APR_UTIL_VERSION"],
            "APR_UTIL_SOURCE_URL": (
                "https://downloads.apache.org/apr/apr-util-"
                f"{PINNED['APR_UTIL_VERSION']}.tar.bz2"
            ),
            "APR_UTIL_SHA256": PINNED["APR_UTIL_SHA256"],
            "APR_UTIL_SHA256_URL": (
                "https://downloads.apache.org/apr/apr-util-"
                f"{PINNED['APR_UTIL_VERSION']}.tar.bz2.sha256"
            ),
        }

        accepted = self.run_guard(canonical_tuple)
        partial = self.run_guard(
            {"APR_UTIL_VERSION": PINNED["APR_UTIL_VERSION"]}
        )

        self.assertEqual(accepted.returncode, 0, accepted.stdout)
        self.assertEqual(partial.returncode, 77, partial.stdout)
        self.assertIn("BLOCKED:", partial.stdout)

    def test_post_source_mutations_fail_closed(self):
        replacement_digest = "b" * 64
        mutations = {
            "version": 'APR_UTIL_VERSION="1.6.999"',
            "source-url": (
                'APR_UTIL_SOURCE_URL="https://downloads.apache.org/apr/'
                'apr-util-1.6.999.tar.bz2"'
            ),
            "sha256": f'APR_UTIL_SHA256="{replacement_digest}"',
            "sha256-url": (
                'APR_UTIL_SHA256_URL="https://downloads.apache.org/apr/'
                'apr-util-1.6.999.tar.bz2.sha256"'
            ),
        }
        for case, mutation in mutations.items():
            with self.subTest(case=case):
                completed = self.run_shell(
                    "\n".join(
                        (
                            '. "$COMMON_SH"',
                            mutation,
                            "ci_require_apr_util_pinned_provenance",
                        )
                    )
                )

                self.assertEqual(completed.returncode, 77, completed.stdout)
                self.assertIn("BLOCKED:", completed.stdout)

    def test_post_source_self_consistent_replacement_and_re_source_fail_closed(self):
        replacement_digest = "b" * 64
        completed = self.run_shell(
            "\n".join(
                (
                    '. "$COMMON_SH"',
                    'APR_UTIL_VERSION="1.6.999"',
                    'APR_UTIL_SOURCE_URL="https://downloads.apache.org/apr/apr-util-$APR_UTIL_VERSION.tar.bz2"',
                    f'APR_UTIL_SHA256="{replacement_digest}"',
                    'APR_UTIL_SHA256_URL="$APR_UTIL_SOURCE_URL.sha256"',
                    '. "$COMMON_SH"',
                    "ci_require_apr_util_pinned_provenance",
                )
            )
        )

        self.assertEqual(completed.returncode, 77, completed.stdout)
        self.assertIn("BLOCKED:", completed.stdout)

    def test_invalid_internal_snapshot_fails_closed_without_readonly(self):
        completed = self.run_shell(
            "\n".join(
                (
                    '. "$COMMON_SH"',
                    "unset CI_APR_UTIL_SHA256_WAS_SET",
                    "ci_require_apr_util_pinned_provenance",
                )
            )
        )

        self.assertEqual(completed.returncode, 77, completed.stdout)
        self.assertIn("APR-util inherited-state snapshot is invalid", completed.stdout)

    def test_invalid_derived_source_or_checksum_url_fails_closed(self):
        source = self.common.read_text(encoding="utf-8")
        invalid_fixtures = {
            "foreign-source": source.replace(
                'APR_UTIL_SOURCE_URL="https://downloads.apache.org/apr/$APR_UTIL_ARCHIVE_NAME"',
                'APR_UTIL_SOURCE_URL="https://mirror.example.invalid/apr/$APR_UTIL_ARCHIVE_NAME"',
            ),
            "wrong-checksum-url": source.replace(
                'APR_UTIL_SHA256_URL="$APR_UTIL_SOURCE_URL.sha256"',
                'APR_UTIL_SHA256_URL="https://downloads.apache.org/apr/other.sha256"',
            ),
            "malformed-digest": source.replace(
                f'APR_UTIL_SHA256="{PINNED["APR_UTIL_SHA256"]}"',
                'APR_UTIL_SHA256="not-a-sha256"',
            ),
        }
        for case, fixture in invalid_fixtures.items():
            with self.subTest(case=case):
                self.common.write_text(fixture, encoding="utf-8")
                completed = self.run_guard()

                self.assertEqual(completed.returncode, 77, completed.stdout)
                self.assertIn("BLOCKED:", completed.stdout)

    def test_invalid_tuple_stops_the_real_preparer_before_network_commands(self):
        completed, network_command_invoked = self.run_preparer_with_fake_network(
            ["sh", str(PREPARE_APACHE)],
            {
                "FRAMEWORK_ROOT": str(ROOT),
                "CI_ROOT": str(self.fixture_root / "ci"),
                "CONNECTOR_ROOT": str(ROOT),
                "APR_UTIL_SOURCE_URL": (
                    "https://mirror.example.invalid/apr-util-"
                    f"{PINNED['APR_UTIL_VERSION']}.tar.bz2"
                ),
            },
        )

        self.assertEqual(completed.returncode, 77, completed.stdout)
        self.assertIn("APR_UTIL_SOURCE_URL override is not permitted", completed.stdout)
        self.assertFalse(network_command_invoked, completed.stdout)

    def test_post_source_mutation_stops_the_real_preparer_before_network_commands(self):
        source = self.common.read_text(encoding="utf-8")
        replacement_digest = "b" * 64
        self.common.write_text(
            source
            + "\nAPR_UTIL_VERSION=\"1.6.999\"\n"
            + "APR_UTIL_SOURCE_URL=\"https://downloads.apache.org/apr/apr-util-$APR_UTIL_VERSION.tar.bz2\"\n"
            + f"APR_UTIL_SHA256=\"{replacement_digest}\"\n"
            + "APR_UTIL_SHA256_URL=\"$APR_UTIL_SOURCE_URL.sha256\"\n",
            encoding="utf-8",
        )
        fixture_prepare = self.write_preparer_fixture()
        completed, network_command_invoked = self.run_preparer_with_fake_network(
            ["sh", str(fixture_prepare)],
            {
                "FRAMEWORK_ROOT": str(self.fixture_root),
                "CONNECTOR_ROOT": str(ROOT),
            },
        )

        self.assertEqual(completed.returncode, 77, completed.stdout)
        self.assertIn("APR_UTIL_VERSION must remain the canonical reviewed value", completed.stdout)
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
        self.assertLess(
            guard_index, source.index("ensure_modsecurity_v3_source", guard_index)
        )

    def test_apr_util_download_does_not_follow_unreviewed_redirects(self):
        source = PREPARE_APACHE.read_text(encoding="utf-8")
        helper_start = source.index("download_apr_util_file()")
        helper_end = source.index("verify_sha256_url()", helper_start)
        helper = source[helper_start:helper_end]

        self.assertIn("ci_require_apr_util_pinned_provenance", helper)
        self.assertIn("download_runtime_artifact_without_redirects_under_root", helper)
        self.assertNotIn("curl -L", helper)
        runtime_helper = RUNTIME_COMPONENT_HELPER.read_text(encoding="utf-8")
        self.assertIn("--proto =https --proto-redir =https", runtime_helper)
        self.assertIn('--max-redirs "$rc_curl_max_redirects"', runtime_helper)


if __name__ == "__main__":
    unittest.main()
