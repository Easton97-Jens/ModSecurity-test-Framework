"""Regression coverage for common-version checker provenance controls.

All HTTP interactions use in-memory fixtures, and each writable path is owned
by a ``TemporaryDirectory`` created for the individual test.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[2]
CHECKER_PATH = ROOT / "ci/tools/check-common-versions.py"
CHECKSUM = "a" * 64
TARBALL_EXTENSION = ".tar.gz"
SHA256_SUFFIX = ".sha256"
OFFICIAL_TARBALL_HOST = "downloads.example.invalid"
TEMP_PREFIX = "common-versions-provenance-"
FIXTURE_NAME = "fixture.sh"
COMMON_SH_NAME = "common.sh"


def load_checker():
    spec = importlib.util.spec_from_file_location("check_common_versions", CHECKER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load the common-version checker")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


CHECKER = load_checker()


class FixtureHttpClient:
    """In-memory response provider that records every attempted HTTP lookup."""

    def __init__(self, responses: dict[str, str]) -> None:
        self.responses = responses
        self.urls: list[str] = []

    def get_text(self, url: str, accept: str | None = None) -> str:
        del accept
        self.urls.append(url)
        try:
            return self.responses[url]
        except KeyError as exc:
            raise AssertionError(f"unexpected HTTP lookup: {url}") from exc


class NoNetworkClient:
    """Fails if a rejected configuration attempts a remote lookup."""

    def __init__(self) -> None:
        self.urls: list[str] = []

    def get_text(self, url: str, accept: str | None = None) -> str:
        del accept
        self.urls.append(url)
        raise AssertionError(f"rejected configuration attempted HTTP lookup: {url}")


class CommonVersionProvenanceTests(unittest.TestCase):
    @staticmethod
    def parse_fixture(path: Path, source: str):
        path.write_text(source, encoding="utf-8")
        return CHECKER.parse_common(path)

    @staticmethod
    def tarball_fixture(source_url: str, checksum_url: str) -> str:
        return "\n".join(
            [
                'VERSION="${VERSION:-1.2.3}"',
                f'SOURCE_URL="${{SOURCE_URL:-{source_url}}}"',
                f'SHA256="${{SHA256:-{CHECKSUM}}}"',
                f'SHA_URL="${{SHA_URL:-{checksum_url}}}"',
                "",
            ]
        )

    @staticmethod
    def tarball_check(entries, client):
        return CHECKER.official_tarball_check(
            "fixture tarball",
            entries,
            client,
            version_var="VERSION",
            source_url_var="SOURCE_URL",
            sha_var="SHA256",
            sha_url_var="SHA_URL",
            filename_prefix="package",
            extension=TARBALL_EXTENSION,
            allowed_host=OFFICIAL_TARBALL_HOST,
            restrict_to_current_series=False,
        )

    @staticmethod
    def haproxy_fixture(version: str, source_url: str, checksum: str) -> str:
        return "\n".join(
            [
                f'HAPROXY_VERSION="${{HAPROXY_VERSION:-{version}}}"',
                f'HAPROXY_SOURCE_URL="${{HAPROXY_SOURCE_URL:-{source_url}}}"',
                f'HAPROXY_SHA256_URL="${{HAPROXY_SHA256_URL:-{source_url}{SHA256_SUFFIX}}}"',
                f'HAPROXY_SHA256="${{HAPROXY_SHA256:-{checksum}}}"',
                "",
            ]
        )

    def test_shell_variable_expansion_accepts_ascii_names_and_rejects_invalid_names(self):
        self.assertEqual(
            "resolved",
            CHECKER.resolve_value("${FOO_1:-fallback}", {"FOO_1": "resolved"}),
        )
        self.assertEqual(
            "fallback",
            CHECKER.resolve_value("${MISSING:-fallback}", {}),
        )
        self.assertEqual(
            "plain-value",
            CHECKER.resolve_value("$FOO_1", {"FOO_1": "plain-value"}),
        )
        self.assertEqual("${1BAD:-fallback}", CHECKER.resolve_value("${1BAD:-fallback}", {}))
        self.assertEqual("${é:-fallback}", CHECKER.resolve_value("${é:-fallback}", {}))

    def test_parse_common_resolves_modsecurity_v3_approved_literals_before_aliases(self):
        approved_repo = "https://github.com/owasp-modsecurity/ModSecurity.git"
        approved_commit = "0fb4aff98b4980cf6426697d5605c424e3d5bb60"
        release_tag = "v3.0.15"
        fixture_source = "\n".join(
            [
                f'MODSECURITY_V3_APPROVED_REPO_URL="{approved_repo}"',
                f'MODSECURITY_V3_APPROVED_COMMIT="{approved_commit}"',
                f'MODSECURITY_V3_RELEASE_TAG="{release_tag}"',
                'MODSECURITY_REPO_URL="${MODSECURITY_REPO_URL:-$MODSECURITY_V3_APPROVED_REPO_URL}"',
                'MODSECURITY_GIT_REF="${MODSECURITY_GIT_REF:-$MODSECURITY_V3_RELEASE_TAG}"',
                'MODSECURITY_V3_GIT_URL="${MODSECURITY_V3_GIT_URL:-$MODSECURITY_V3_APPROVED_REPO_URL}"',
                'MODSECURITY_V3_GIT_REF="${MODSECURITY_V3_GIT_REF:-$MODSECURITY_V3_RELEASE_TAG}"',
                "",
            ]
        )
        missing_anchor_source = "\n".join(fixture_source.splitlines()[3:]) + "\n"

        with tempfile.TemporaryDirectory(prefix=TEMP_PREFIX) as temporary:
            fixture = Path(temporary) / FIXTURE_NAME
            _, entries = self.parse_fixture(fixture, fixture_source)
            _, missing_entries = self.parse_fixture(fixture, missing_anchor_source)

        self.assertEqual(approved_repo, CHECKER.value(entries, "MODSECURITY_V3_APPROVED_REPO_URL"))
        self.assertEqual(approved_commit, CHECKER.value(entries, "MODSECURITY_V3_APPROVED_COMMIT"))
        self.assertEqual(release_tag, CHECKER.value(entries, "MODSECURITY_V3_RELEASE_TAG"))
        self.assertEqual(approved_repo, CHECKER.value(entries, "MODSECURITY_REPO_URL"))
        self.assertEqual(release_tag, CHECKER.value(entries, "MODSECURITY_GIT_REF"))
        self.assertEqual(approved_repo, CHECKER.value(entries, "MODSECURITY_V3_GIT_URL"))
        self.assertEqual(release_tag, CHECKER.value(entries, "MODSECURITY_V3_GIT_REF"))
        self.assertEqual([], CHECKER.validate_entries(entries))
        self.assertIsNone(
            CHECKER.parse_common_assignment(
                'UNRELATED_APPROVED_REPO_URL="https://example.invalid/unrelated.git"'
            )
        )
        self.assertEqual(
            [
                "MODSECURITY_REPO_URL",
                "MODSECURITY_GIT_REF",
                "MODSECURITY_V3_GIT_URL",
                "MODSECURITY_V3_GIT_REF",
            ],
            CHECKER.validate_entries(missing_entries),
        )

    def test_modsecurity_v3_release_requires_reviewed_tag_and_commit_pair(self):
        class FakeGitHubClient:
            def __init__(self) -> None:
                self.urls: list[str] = []

            def get_json(self, url: str) -> dict[str, str]:
                self.urls.append(url)
                return {"tag_name": "v3.0.16"}

        _, entries = CHECKER.parse_common(ROOT / "ci/lib/common.sh")
        client = FakeGitHubClient()

        result = CHECKER.check_modsecurity_v3_release_provenance(entries, client)

        self.assertEqual(CHECKER.STATUS_UNKNOWN, result.status)
        self.assertEqual([], result.updates)
        self.assertEqual(0, CHECKER.exit_code([result]))
        self.assertEqual("v3.0.16", result.latest)
        self.assertEqual(
            [
                "MODSECURITY_V3_APPROVED_REPO_URL",
                "MODSECURITY_V3_RELEASE_TAG",
                "MODSECURITY_V3_APPROVED_COMMIT",
                "MODSECURITY_REPO_URL",
                "MODSECURITY_GIT_REF",
                "MODSECURITY_V3_GIT_URL",
                "MODSECURITY_V3_GIT_REF",
            ],
            result.variables,
        )
        self.assertEqual(
            "update MODSECURITY_V3_RELEASE_TAG and MODSECURITY_V3_APPROVED_COMMIT together after commit provenance review",
            result.details["reason"],
        )
        self.assertEqual(
            ["https://api.github.com/repos/owasp-modsecurity/ModSecurity/releases/latest"],
            client.urls,
        )

    def test_dotted_version_parser_keeps_legacy_match_boundaries_without_regex_backtracking(self):
        self.assertEqual((1, 2, 3), CHECKER.version_tuple("release-1.2.3"))
        self.assertEqual((1, 2), CHECKER.version_tuple("release-1.2..3"))
        self.assertEqual((5, 6), CHECKER.version_tuple("build-123-release-5.6"))
        with self.assertRaises(CHECKER.UpstreamUnknown):
            CHECKER.version_tuple("release-without-a-dotted-version")

    def test_trusted_https_path_prefix_preserves_dynamic_value_forms(self):
        for path, expected_prefix in (
            ("/releases/${VERSION}/package.tar.gz", "/releases/"),
            ("/releases/$VERSION/package.tar.gz", "/releases/"),
            ("/releases/$VERSION_2/package.tar.gz", "/releases/"),
            ("/releases/1.2.3/package.tar.gz", "/releases/"),
            ("/releases/١.٢/package.tar.gz", "/releases/"),
            ("/releases/static/package.tar.gz", "/releases/static/"),
        ):
            with self.subTest(path=path):
                self.assertEqual(expected_prefix, CHECKER.trusted_https_path_prefix(path))

    def test_unofficial_tarball_host_is_rejected_before_any_http_lookup(self):
        with tempfile.TemporaryDirectory(prefix=TEMP_PREFIX) as temporary:
            fixture = Path(temporary) / FIXTURE_NAME
            _, entries = self.parse_fixture(
                fixture,
                self.tarball_fixture(
                    f"https://untrusted.example.invalid/package-1.2.3{TARBALL_EXTENSION}",
                    (
                        f"https://untrusted.example.invalid/package-1.2.3"
                        f"{TARBALL_EXTENSION}{SHA256_SUFFIX}"
                    ),
                ),
            )
            client = NoNetworkClient()

            result = self.tarball_check(entries, client)

        self.assertEqual(CHECKER.STATUS_UNKNOWN, result.status)
        self.assertIn("expected official tarball URL", result.details["reason"])
        self.assertEqual([], client.urls)

    def test_official_tarball_host_and_checksum_are_checked_with_fixture_responses(self):
        listing_url = f"https://{OFFICIAL_TARBALL_HOST}/releases/"
        source_url = f"{listing_url}package-1.2.3{TARBALL_EXTENSION}"
        checksum_url = source_url + SHA256_SUFFIX
        with tempfile.TemporaryDirectory(prefix=TEMP_PREFIX) as temporary:
            fixture = Path(temporary) / FIXTURE_NAME
            _, entries = self.parse_fixture(fixture, self.tarball_fixture(source_url, checksum_url))
            client = FixtureHttpClient(
                {
                    listing_url: (
                        f'<a href="package-1.2.3{TARBALL_EXTENSION}">'
                        f"package-1.2.3{TARBALL_EXTENSION}</a>"
                    ),
                    checksum_url: f"{CHECKSUM}  package-1.2.3{TARBALL_EXTENSION}\n",
                }
            )

            result = self.tarball_check(entries, client)

        self.assertEqual(CHECKER.STATUS_CURRENT, result.status)
        self.assertEqual(CHECKSUM, result.details["official_sha256"])
        self.assertEqual([listing_url, checksum_url, checksum_url], client.urls)

    def test_outdated_tarball_only_plans_an_update_until_update_mode_is_requested(self):
        listing_url = f"https://{OFFICIAL_TARBALL_HOST}/releases/"
        latest_checksum_url = f"{listing_url}package-1.2.4{TARBALL_EXTENSION}{SHA256_SUFFIX}"
        source_template = f"{listing_url}package-$VERSION{TARBALL_EXTENSION}"
        listing_text = f"package-1.2.3{TARBALL_EXTENSION} package-1.2.4{TARBALL_EXTENSION}"
        with tempfile.TemporaryDirectory(prefix=TEMP_PREFIX) as temporary:
            fixture = Path(temporary) / FIXTURE_NAME
            original = "\n".join(
                [
                    'VERSION="${VERSION:-1.2.3}"',
                    f'SOURCE_URL="${{SOURCE_URL:-{source_template}}}"',
                    f'SHA256="${{SHA256:-{CHECKSUM}}}"',
                    f'SHA_URL="${{SHA_URL:-$SOURCE_URL{SHA256_SUFFIX}}}"',
                    "",
                ]
            )
            _, entries = self.parse_fixture(fixture, original)
            client = FixtureHttpClient(
                {
                    listing_url: listing_text,
                    latest_checksum_url: f"{CHECKSUM}  package-1.2.4{TARBALL_EXTENSION}\n",
                }
            )

            result = self.tarball_check(entries, client)

            self.assertEqual(CHECKER.STATUS_OUTDATED, result.status)
            self.assertTrue(result.updates)
            self.assertNotIn("SOURCE_URL", [update.variable for update in result.updates])
            self.assertNotIn("SHA_URL", [update.variable for update in result.updates])
            self.assertEqual(original, fixture.read_text(encoding="utf-8"))

    def test_haproxy_rejects_mismatched_pin_before_any_http_lookup(self):
        with tempfile.TemporaryDirectory(prefix=TEMP_PREFIX) as temporary:
            fixture = Path(temporary) / FIXTURE_NAME
            _, entries = self.parse_fixture(
                fixture,
                self.haproxy_fixture(
                    "2.8.1",
                    f"https://www.haproxy.org/download/2.8/src/haproxy-2.8.2{TARBALL_EXTENSION}",
                    CHECKSUM,
                ),
            )
            client = NoNetworkClient()

            result = CHECKER.check_haproxy(entries, client)

        self.assertEqual(CHECKER.STATUS_UNKNOWN, result.status)
        self.assertIn("expected official HAProxy tarball URL", result.details["reason"])
        self.assertEqual([], client.urls)

    def test_haproxy_requires_a_checksum_before_any_http_lookup(self):
        with tempfile.TemporaryDirectory(prefix=TEMP_PREFIX) as temporary:
            fixture = Path(temporary) / FIXTURE_NAME
            _, entries = self.parse_fixture(
                fixture,
                self.haproxy_fixture(
                    "2.8.1",
                    f"https://www.haproxy.org/download/2.8/src/haproxy-2.8.1{TARBALL_EXTENSION}",
                    "",
                ),
            )
            client = NoNetworkClient()

            result = CHECKER.check_haproxy(entries, client)

        self.assertEqual(CHECKER.STATUS_BLOCKED, result.status)
        self.assertIn("HAPROXY_SHA256 is required", result.message)
        self.assertEqual([], client.urls)

    def test_check_mode_does_not_apply_a_planned_update(self):
        with tempfile.TemporaryDirectory(prefix=TEMP_PREFIX) as temporary:
            fixture = Path(temporary) / FIXTURE_NAME
            original = 'VERSION="${VERSION:-1.0}"\n'
            lines, entries = self.parse_fixture(fixture, original)
            update = CHECKER.plan_update(entries, "VERSION", "2.0")
            self.assertIsNotNone(update)
            result = CHECKER.ComponentResult(
                component="fixture",
                status=CHECKER.STATUS_OUTDATED,
                message="fixture is outdated",
                variables=["VERSION"],
                updates=[update],
            )

            with patch.object(CHECKER, "apply_updates") as apply_updates:
                rc, applied, _, _ = CHECKER.apply_requested_updates(
                    False,
                    1,
                    fixture,
                    lines,
                    entries,
                    [result],
                )

            self.assertEqual(1, rc)
            self.assertEqual([], applied)
            apply_updates.assert_not_called()
            self.assertEqual(original, fixture.read_text(encoding="utf-8"))

    def test_update_allows_only_a_common_sh_fixture_below_build_root(self):
        with tempfile.TemporaryDirectory(prefix=TEMP_PREFIX) as temporary:
            temporary_path = Path(temporary)
            build_root = temporary_path / "build"
            fixture = build_root / "fixtures" / COMMON_SH_NAME
            fixture.parent.mkdir(parents=True)
            lines, entries = self.parse_fixture(fixture, 'VERSION="${VERSION:-1.0}"\n')
            update = CHECKER.plan_update(entries, "VERSION", "2.0")
            self.assertIsNotNone(update)

            with patch.dict(os.environ, {"BUILD_ROOT": str(build_root)}, clear=False):
                CHECKER.apply_updates(fixture, lines, [update])

            self.assertEqual('VERSION="${VERSION:-2.0}"\n', fixture.read_text(encoding="utf-8"))

    def test_update_accepts_strict_version_sha_and_https_url_values(self):
        listing_url = f"https://{OFFICIAL_TARBALL_HOST}/releases/"
        source_url = f"{listing_url}package-1.2.3{TARBALL_EXTENSION}"
        checksum_url = source_url + SHA256_SUFFIX
        updated_source_url = f"{listing_url}package-1.2.4{TARBALL_EXTENSION}"
        updated_checksum_url = updated_source_url + SHA256_SUFFIX
        updated_checksum = "b" * 64
        with tempfile.TemporaryDirectory(prefix=TEMP_PREFIX) as temporary:
            temporary_path = Path(temporary)
            build_root = temporary_path / "build"
            fixture = build_root / "fixtures" / COMMON_SH_NAME
            fixture.parent.mkdir(parents=True)
            lines, entries = self.parse_fixture(fixture, self.tarball_fixture(source_url, checksum_url))
            updates = [
                CHECKER.plan_update(entries, "VERSION", "1.2.4"),
                CHECKER.plan_update(entries, "SOURCE_URL", updated_source_url),
                CHECKER.plan_update(entries, "SHA256", updated_checksum),
                CHECKER.plan_update(entries, "SHA_URL", updated_checksum_url),
            ]
            valid_updates = [update for update in updates if update is not None]

            self.assertEqual(4, len(valid_updates))
            with patch.dict(os.environ, {"BUILD_ROOT": str(build_root)}, clear=False):
                CHECKER.apply_updates(fixture, lines, valid_updates)

            updated = fixture.read_text(encoding="utf-8")
        self.assertIn('VERSION="${VERSION:-1.2.4}"', updated)
        self.assertIn(f'SOURCE_URL="${{SOURCE_URL:-{updated_source_url}}}"', updated)
        self.assertIn(f'SHA256="${{SHA256:-{updated_checksum}}}"', updated)
        self.assertIn(f'SHA_URL="${{SHA_URL:-{updated_checksum_url}}}"', updated)

    def test_update_rejects_invalid_network_values_without_mutating_target(self):
        listing_url = f"https://{OFFICIAL_TARBALL_HOST}/releases/"
        source_url = f"{listing_url}package-1.2.3{TARBALL_EXTENSION}"
        checksum_url = source_url + SHA256_SUFFIX
        with tempfile.TemporaryDirectory(prefix=TEMP_PREFIX) as temporary:
            temporary_path = Path(temporary)
            build_root = temporary_path / "build"
            fixture = build_root / "fixtures" / COMMON_SH_NAME
            fixture.parent.mkdir(parents=True)
            original = self.tarball_fixture(source_url, checksum_url)
            lines, entries = self.parse_fixture(fixture, original)
            candidate_source_url = f"{listing_url}package-1.2.4{TARBALL_EXTENSION}"
            insecure_source_url = (
                urlsplit(candidate_source_url)._replace(scheme="http").geturl()
            )
            self.assertEqual("http", urlsplit(insecure_source_url).scheme)

            for variable, invalid_value in (
                ("VERSION", "1.2.4;touch"),
                ("SHA256", "not-a-sha256"),
                ("SOURCE_URL", insecure_source_url),
                ("SOURCE_URL", f"https://foreign.example.invalid/package-1.2.4{TARBALL_EXTENSION}"),
                ("SOURCE_URL", f"https://{OFFICIAL_TARBALL_HOST}/other/package-1.2.4{TARBALL_EXTENSION}"),
                ("SOURCE_URL", f"https://{OFFICIAL_TARBALL_HOST}/releases/../package-1.2.4{TARBALL_EXTENSION}"),
                ("SHA_URL", f"https://{OFFICIAL_TARBALL_HOST}/package-1.2.4{TARBALL_EXTENSION}?redirect=1"),
            ):
                with self.subTest(variable=variable):
                    with self.assertRaises(CHECKER.UpstreamError):
                        CHECKER.plan_update(entries, variable, invalid_value)

            for invalid_source_url in (
                f"https://foreign.example.invalid/package-1.2.4{TARBALL_EXTENSION}",
                f"https://{OFFICIAL_TARBALL_HOST}/other/package-1.2.4{TARBALL_EXTENSION}",
            ):
                with self.subTest(write_sink=invalid_source_url):
                    updates = [
                        CHECKER.UpdateChange("VERSION", entries["VERSION"].line, "1.2.3", "1.2.4"),
                        CHECKER.UpdateChange(
                            "SOURCE_URL",
                            entries["SOURCE_URL"].line,
                            source_url,
                            invalid_source_url,
                        ),
                    ]
                    with patch.dict(os.environ, {"BUILD_ROOT": str(build_root)}, clear=False):
                        with self.assertRaises(CHECKER.UpstreamError):
                            CHECKER.apply_updates(fixture, lines, updates)

                    self.assertEqual(original, fixture.read_text(encoding="utf-8"))

    def test_update_rejects_a_common_sh_path_outside_build_root_without_writing(self):
        with tempfile.TemporaryDirectory(prefix=TEMP_PREFIX) as temporary:
            temporary_path = Path(temporary)
            build_root = temporary_path / "build"
            rejected_fixture = temporary_path / "outside" / COMMON_SH_NAME
            rejected_fixture.parent.mkdir()
            original = 'VERSION="${VERSION:-1.0}"\n'
            lines, entries = self.parse_fixture(rejected_fixture, original)
            update = CHECKER.plan_update(entries, "VERSION", "2.0")
            self.assertIsNotNone(update)

            with patch.dict(os.environ, {"BUILD_ROOT": str(build_root)}, clear=False):
                with self.assertRaises(CHECKER.UpstreamError):
                    CHECKER.apply_updates(rejected_fixture, lines, [update])

            self.assertEqual(original, rejected_fixture.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
