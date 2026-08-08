"""Regression coverage for common-version checker provenance controls.

All HTTP interactions use in-memory fixtures, and each writable path is owned
by a ``TemporaryDirectory`` created for the individual test.
"""

from __future__ import annotations

import dataclasses
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
APR_UTIL_VERSION = "1.6.4"
APR_UTIL_SHA256 = "3e2ae08f40efa0c3701e54a954cefa08242de22a69f91a8ae44fc1e624ba309b"
APR_UTIL_SOURCE_URL = (
    f"https://downloads.apache.org/apr/apr-util-{APR_UTIL_VERSION}.tar.bz2"
)
APR_UTIL_SHA256_URL = f"{APR_UTIL_SOURCE_URL}.sha256"


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
    def apr_util_fixture(
        *,
        runtime_version: str = "$APR_UTIL_PINNED_VERSION",
        runtime_source_url: str = "$APR_UTIL_PINNED_SOURCE_URL",
        runtime_sha256: str = "$APR_UTIL_PINNED_SHA256",
        runtime_sha256_url: str = "$APR_UTIL_PINNED_SHA256_URL",
    ) -> str:
        return "\n".join(
            [
                f'APR_UTIL_PINNED_VERSION="{APR_UTIL_VERSION}"',
                f'APR_UTIL_PINNED_SOURCE_URL="{APR_UTIL_SOURCE_URL}"',
                f'APR_UTIL_PINNED_SHA256="{APR_UTIL_SHA256}"',
                f'APR_UTIL_PINNED_SHA256_URL="{APR_UTIL_SHA256_URL}"',
                f'APR_UTIL_VERSION="${{APR_UTIL_VERSION-{runtime_version}}}"',
                f'APR_UTIL_SOURCE_URL="${{APR_UTIL_SOURCE_URL-{runtime_source_url}}}"',
                f'APR_UTIL_SHA256="${{APR_UTIL_SHA256-{runtime_sha256}}}"',
                f'APR_UTIL_SHA256_URL="${{APR_UTIL_SHA256_URL-{runtime_sha256_url}}}"',
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

    @staticmethod
    def modsecurity_review_required(entries):
        return CHECKER.ComponentResult(
            component=CHECKER.MODSECURITY_V3_COMPONENT,
            status=CHECKER.STATUS_REVIEW_REQUIRED,
            message="manual immutable-provenance review is required",
            variables=list(
                CHECKER.MANUAL_REVIEW_VARIABLES[CHECKER.MODSECURITY_V3_COMPONENT]
            ),
            current=CHECKER.value(entries, "MODSECURITY_V3_RELEASE_TAG"),
            latest="v3.0.16",
            source=CHECKER.value(entries, "MODSECURITY_V3_APPROVED_REPO_URL"),
            details={
                "reason": "test-only reviewed atomic transition",
                "manual_variables": list(
                    CHECKER.MANUAL_REVIEW_VARIABLES[CHECKER.MODSECURITY_V3_COMPONENT]
                ),
            },
        )

    @staticmethod
    def haproxy_safe_update(entries):
        version_update = CHECKER.plan_update(entries, "HAPROXY_VERSION", "3.2.22")
        checksum_update = CHECKER.plan_update(entries, "HAPROXY_SHA256", "b" * 64)
        if version_update is None or checksum_update is None:
            raise AssertionError(
                "test fixture must produce a complete HAProxy update plan"
            )
        return CHECKER.ComponentResult(
            component="HAProxy",
            status=CHECKER.STATUS_OUTDATED,
            message="complete trusted HAProxy version and digest update",
            variables=[
                "HAPROXY_VERSION",
                "HAPROXY_SOURCE_URL",
                "HAPROXY_SHA256_URL",
                "HAPROXY_SHA256",
            ],
            current=CHECKER.value(entries, "HAPROXY_VERSION"),
            latest="3.2.22",
            updates=[version_update, checksum_update],
        )

    def test_shell_variable_expansion_accepts_ascii_names_and_rejects_invalid_names(
        self,
    ):
        self.assertEqual(
            CHECKER.resolve_value("${FOO_1:-fallback}", {"FOO_1": "resolved"}),
            "resolved",
        )
        self.assertEqual(
            CHECKER.resolve_value("${MISSING:-fallback}", {}),
            "fallback",
        )
        self.assertEqual(
            CHECKER.resolve_value("$FOO_1", {"FOO_1": "plain-value"}),
            "plain-value",
        )
        self.assertEqual(
            CHECKER.resolve_value("${1BAD:-fallback}", {}), "${1BAD:-fallback}"
        )
        self.assertEqual(CHECKER.resolve_value("${é:-fallback}", {}), "${é:-fallback}")

    def test_parse_common_resolves_modsecurity_v3_approved_literals_before_aliases(
        self,
    ):
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

        self.assertEqual(
            CHECKER.value(entries, "MODSECURITY_V3_APPROVED_REPO_URL"), approved_repo
        )
        self.assertEqual(
            CHECKER.value(entries, "MODSECURITY_V3_APPROVED_COMMIT"), approved_commit
        )
        self.assertEqual(
            CHECKER.value(entries, "MODSECURITY_V3_RELEASE_TAG"), release_tag
        )
        self.assertEqual(CHECKER.value(entries, "MODSECURITY_REPO_URL"), approved_repo)
        self.assertEqual(CHECKER.value(entries, "MODSECURITY_GIT_REF"), release_tag)
        self.assertEqual(
            CHECKER.value(entries, "MODSECURITY_V3_GIT_URL"), approved_repo
        )
        self.assertEqual(CHECKER.value(entries, "MODSECURITY_V3_GIT_REF"), release_tag)
        self.assertEqual(CHECKER.validate_entries(entries), [])
        self.assertIsNone(
            CHECKER.parse_common_assignment(
                'UNRELATED_APPROVED_REPO_URL="https://example.invalid/unrelated.git"'
            )
        )
        self.assertEqual(
            CHECKER.validate_entries(missing_entries),
            [
                "MODSECURITY_REPO_URL",
                "MODSECURITY_GIT_REF",
                "MODSECURITY_V3_GIT_URL",
                "MODSECURITY_V3_GIT_REF",
            ],
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

        self.assertEqual(CHECKER.STATUS_REVIEW_REQUIRED, result.status)
        self.assertEqual(result.updates, [])
        self.assertEqual(CHECKER.exit_code([result]), 2)
        self.assertEqual(
            CHECKER.exit_code(
                [result],
                entries,
                defer_reviewed_provenance=True,
            ),
            0,
        )
        self.assertEqual(result.latest, "v3.0.16")
        self.assertEqual(
            result.variables,
            [
                "MODSECURITY_V3_APPROVED_REPO_URL",
                "MODSECURITY_V3_RELEASE_TAG",
                "MODSECURITY_V3_APPROVED_COMMIT",
                "MODSECURITY_REPO_URL",
                "MODSECURITY_GIT_REF",
                "MODSECURITY_V3_GIT_URL",
                "MODSECURITY_V3_GIT_REF",
            ],
        )
        self.assertEqual(
            result.details["reason"],
            "update MODSECURITY_V3_RELEASE_TAG and MODSECURITY_V3_APPROVED_COMMIT together after commit provenance review",
        )
        self.assertEqual(
            result.details["manual_variables"],
            list(CHECKER.MANUAL_REVIEW_VARIABLES[CHECKER.MODSECURITY_V3_COMPONENT]),
        )
        self.assertEqual(
            client.urls,
            [
                "https://api.github.com/repos/owasp-modsecurity/ModSecurity/releases/latest"
            ],
        )

    def test_unknown_results_fail_closed_while_local_policy_entries_are_not_applicable(
        self,
    ):
        unknown = CHECKER.unknown_component(
            "unresolved source",
            {},
            [],
            "trusted upstream provenance is incomplete",
        )
        not_applicable = CHECKER.not_applicable_component(
            "local policy default",
            {},
            [],
            "the entry has no automated updater contract",
        )

        self.assertEqual(CHECKER.STATUS_UNKNOWN, unknown.status)
        self.assertEqual(CHECKER.STATUS_NOT_APPLICABLE, not_applicable.status)
        self.assertEqual(CHECKER.exit_code([unknown]), 2)
        self.assertEqual(CHECKER.exit_code([not_applicable]), 0)

    def test_modsecurity_v3_release_blocks_missing_or_malformed_immutable_anchor(self):
        source_lines = [
            'MODSECURITY_V3_APPROVED_REPO_URL="https://github.com/owasp-modsecurity/ModSecurity.git"',
            'MODSECURITY_V3_RELEASE_TAG="v3.0.15"',
            'MODSECURITY_REPO_URL="${MODSECURITY_REPO_URL:-$MODSECURITY_V3_APPROVED_REPO_URL}"',
            'MODSECURITY_GIT_REF="${MODSECURITY_GIT_REF:-$MODSECURITY_V3_RELEASE_TAG}"',
            'MODSECURITY_V3_GIT_URL="${MODSECURITY_V3_GIT_URL:-$MODSECURITY_V3_APPROVED_REPO_URL}"',
            'MODSECURITY_V3_GIT_REF="${MODSECURITY_V3_GIT_REF:-$MODSECURITY_V3_RELEASE_TAG}"',
        ]

        class UnexpectedNetworkClient:
            def get_json(self, url: str) -> dict[str, str]:
                raise AssertionError(
                    f"provenance check must block before network access: {url}"
                )

        for anchor in (None, "not-a-commit"):
            with self.subTest(anchor=anchor):
                lines = list(source_lines)
                if anchor is not None:
                    lines.insert(2, f'MODSECURITY_V3_APPROVED_COMMIT="{anchor}"')
                with tempfile.TemporaryDirectory(prefix=TEMP_PREFIX) as temporary:
                    fixture = Path(temporary) / FIXTURE_NAME
                    _, entries = self.parse_fixture(fixture, "\n".join(lines) + "\n")
                result = CHECKER.check_modsecurity_v3_release_provenance(
                    entries, UnexpectedNetworkClient()
                )
                self.assertEqual(CHECKER.STATUS_BLOCKED, result.status)
                self.assertIn("MODSECURITY_V3_APPROVED_COMMIT", result.message)

    def test_dotted_version_parser_keeps_legacy_match_boundaries_without_regex_backtracking(
        self,
    ):
        self.assertEqual(CHECKER.version_tuple("release-1.2.3"), (1, 2, 3))
        self.assertEqual(CHECKER.version_tuple("release-1.2..3"), (1, 2))
        self.assertEqual(CHECKER.version_tuple("build-123-release-5.6"), (5, 6))
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
                self.assertEqual(
                    expected_prefix, CHECKER.trusted_https_path_prefix(path)
                )

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
        self.assertEqual(client.urls, [])

    def test_official_tarball_host_and_checksum_are_checked_with_fixture_responses(
        self,
    ):
        listing_url = f"https://{OFFICIAL_TARBALL_HOST}/releases/"
        source_url = f"{listing_url}package-1.2.3{TARBALL_EXTENSION}"
        checksum_url = source_url + SHA256_SUFFIX
        with tempfile.TemporaryDirectory(prefix=TEMP_PREFIX) as temporary:
            fixture = Path(temporary) / FIXTURE_NAME
            _, entries = self.parse_fixture(
                fixture, self.tarball_fixture(source_url, checksum_url)
            )
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
        self.assertEqual(client.urls, [listing_url, checksum_url, checksum_url])

    def test_apr_util_pinned_tuple_uses_the_official_asset_and_checksum(self):
        listing_url = "https://downloads.apache.org/apr/"
        with tempfile.TemporaryDirectory(prefix=TEMP_PREFIX) as temporary:
            fixture = Path(temporary) / COMMON_SH_NAME
            _, entries = self.parse_fixture(fixture, self.apr_util_fixture())
            client = FixtureHttpClient(
                {
                    listing_url: f'<a href="apr-util-{APR_UTIL_VERSION}.tar.bz2">asset</a>',
                    APR_UTIL_SHA256_URL: f"{APR_UTIL_SHA256}  apr-util-{APR_UTIL_VERSION}.tar.bz2\n",
                }
            )

            result = CHECKER.check_apr_util_release_provenance(entries, client)

        self.assertEqual(CHECKER.STATUS_CURRENT, result.status)
        self.assertEqual(result.current, APR_UTIL_VERSION)
        self.assertEqual(result.details["official_sha256"], APR_UTIL_SHA256)
        self.assertEqual(
            client.urls, [listing_url, APR_UTIL_SHA256_URL, APR_UTIL_SHA256_URL]
        )

    def test_apr_util_rejects_any_runtime_tuple_mismatch_before_http_lookup(self):
        mismatches = {
            "stale-version": {"runtime_version": "1.6.3"},
            "foreign-host": {
                "runtime_source_url": "https://mirror.example.invalid/apr-util-1.6.4.tar.bz2"
            },
            "wrong-path": {
                "runtime_source_url": "https://downloads.apache.org/apr/other-apr-util-1.6.4.tar.bz2"
            },
            "missing-digest": {"runtime_sha256": ""},
            "malformed-digest": {"runtime_sha256": "not-a-sha256"},
            "mismatched-digest": {"runtime_sha256": "0" * 64},
            "wrong-checksum-url": {
                "runtime_sha256_url": "https://downloads.apache.org/apr/other.sha256"
            },
        }
        for case, kwargs in mismatches.items():
            with self.subTest(case=case):
                with tempfile.TemporaryDirectory(prefix=TEMP_PREFIX) as temporary:
                    fixture = Path(temporary) / COMMON_SH_NAME
                    _, entries = self.parse_fixture(
                        fixture, self.apr_util_fixture(**kwargs)
                    )
                    client = NoNetworkClient()

                    result = CHECKER.check_apr_util_release_provenance(entries, client)

                self.assertEqual(CHECKER.STATUS_UNKNOWN, result.status)
                self.assertEqual(client.urls, [])

    def test_outdated_tarball_only_plans_an_update_until_update_mode_is_requested(self):
        listing_url = f"https://{OFFICIAL_TARBALL_HOST}/releases/"
        latest_checksum_url = (
            f"{listing_url}package-1.2.4{TARBALL_EXTENSION}{SHA256_SUFFIX}"
        )
        source_template = f"{listing_url}package-$VERSION{TARBALL_EXTENSION}"
        listing_text = (
            f"package-1.2.3{TARBALL_EXTENSION} package-1.2.4{TARBALL_EXTENSION}"
        )
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
            self.assertNotIn(
                "SOURCE_URL", [update.variable for update in result.updates]
            )
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
        self.assertEqual(client.urls, [])

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
        self.assertEqual(client.urls, [])

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

            self.assertEqual(rc, 1)
            self.assertEqual(applied, [])
            apply_updates.assert_not_called()
            self.assertEqual(fixture.read_text(encoding="utf-8"), original)

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

            self.assertEqual(
                fixture.read_text(encoding="utf-8"), 'VERSION="${VERSION:-2.0}"\n'
            )

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
            lines, entries = self.parse_fixture(
                fixture, self.tarball_fixture(source_url, checksum_url)
            )
            updates = [
                CHECKER.plan_update(entries, "VERSION", "1.2.4"),
                CHECKER.plan_update(entries, "SOURCE_URL", updated_source_url),
                CHECKER.plan_update(entries, "SHA256", updated_checksum),
                CHECKER.plan_update(entries, "SHA_URL", updated_checksum_url),
            ]
            valid_updates = [update for update in updates if update is not None]

            self.assertEqual(len(valid_updates), 4)
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
            self.assertEqual(urlsplit(insecure_source_url).scheme, "http")

            for variable, invalid_value in (
                ("VERSION", "1.2.4;touch"),
                ("SHA256", "not-a-sha256"),
                ("SOURCE_URL", insecure_source_url),
                (
                    "SOURCE_URL",
                    f"https://foreign.example.invalid/package-1.2.4{TARBALL_EXTENSION}",
                ),
                (
                    "SOURCE_URL",
                    f"https://{OFFICIAL_TARBALL_HOST}/other/package-1.2.4{TARBALL_EXTENSION}",
                ),
                (
                    "SOURCE_URL",
                    f"https://{OFFICIAL_TARBALL_HOST}/releases/../package-1.2.4{TARBALL_EXTENSION}",
                ),
                (
                    "SHA_URL",
                    f"https://{OFFICIAL_TARBALL_HOST}/package-1.2.4{TARBALL_EXTENSION}?redirect=1",
                ),
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
                        CHECKER.UpdateChange(
                            "VERSION", entries["VERSION"].line, "1.2.3", "1.2.4"
                        ),
                        CHECKER.UpdateChange(
                            "SOURCE_URL",
                            entries["SOURCE_URL"].line,
                            source_url,
                            invalid_source_url,
                        ),
                    ]
                    with patch.dict(
                        os.environ, {"BUILD_ROOT": str(build_root)}, clear=False
                    ):
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

            self.assertEqual(rejected_fixture.read_text(encoding="utf-8"), original)

    def test_maintenance_mode_classifies_all_permitted_outcomes(self):
        _, entries = CHECKER.parse_common(ROOT / "ci/lib/common.sh")
        manual = self.modsecurity_review_required(entries)
        safe = self.haproxy_safe_update(entries)
        current = CHECKER.ComponentResult(
            component="current fixture",
            status=CHECKER.STATUS_CURRENT,
            message="current",
            variables=[],
        )

        cases = (
            ("no-updates", [current], CHECKER.MAINTENANCE_OUTCOME_NO_UPDATES, False),
            (
                "manual-only",
                [manual],
                CHECKER.MAINTENANCE_OUTCOME_MANUAL_REVIEW_ONLY,
                False,
            ),
            ("safe-only", [safe], CHECKER.MAINTENANCE_OUTCOME_SAFE_UPDATES, True),
            (
                "safe-with-manual",
                [manual, safe],
                CHECKER.MAINTENANCE_OUTCOME_SAFE_UPDATES_WITH_MANUAL_REVIEW,
                True,
            ),
        )
        for name, results, expected_outcome, expected_safe_updates in cases:
            with self.subTest(name=name):
                disposition = CHECKER.maintenance_disposition(
                    results,
                    entries,
                    defer_reviewed_provenance=True,
                )
                self.assertEqual(disposition.outcome, expected_outcome)
                self.assertEqual(
                    disposition.safe_updates_available,
                    expected_safe_updates,
                )
                self.assertEqual(
                    disposition.manual_review_required,
                    manual in results,
                )

        strict = CHECKER.maintenance_disposition(
            [manual, safe],
            entries,
            defer_reviewed_provenance=False,
        )
        self.assertEqual(strict.outcome, CHECKER.MAINTENANCE_OUTCOME_FATAL)
        self.assertIn(CHECKER.MODSECURITY_V3_COMPONENT, strict.fatal_components)

    def test_safe_partial_update_preserves_all_manual_provenance_lines_and_revalidates(
        self,
    ):
        source = (ROOT / "ci/lib/common.sh").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory(prefix=TEMP_PREFIX) as temporary:
            temporary_path = Path(temporary)
            build_root = temporary_path / "build"
            fixture = build_root / COMMON_SH_NAME
            fixture.parent.mkdir(parents=True)
            lines, entries = self.parse_fixture(fixture, source)
            manual = self.modsecurity_review_required(entries)
            safe = self.haproxy_safe_update(entries)
            manual_before = CHECKER.manual_review_pin_values([manual], entries)

            def revalidate(candidate_entries):
                return [self.modsecurity_review_required(candidate_entries)]

            with patch.dict(os.environ, {"BUILD_ROOT": str(build_root)}, clear=False):
                rc, applied, _, updated_entries = CHECKER.apply_requested_updates(
                    True,
                    CHECKER.exit_code(
                        [manual, safe],
                        entries,
                        defer_reviewed_provenance=True,
                    ),
                    fixture,
                    lines,
                    entries,
                    [manual, safe],
                    defer_reviewed_provenance=True,
                    revalidate=revalidate,
                )

        self.assertEqual(rc, 0)
        self.assertEqual(
            [update.variable for update in applied],
            ["HAPROXY_VERSION", "HAPROXY_SHA256"],
        )
        self.assertEqual(CHECKER.value(updated_entries, "HAPROXY_VERSION"), "3.2.22")
        self.assertEqual(CHECKER.value(updated_entries, "HAPROXY_SHA256"), "b" * 64)
        CHECKER.require_manual_review_pins_unchanged(manual_before, updated_entries)
        self.assertEqual(
            CHECKER.manual_review_pin_digest([manual], updated_entries),
            CHECKER.manual_review_pin_digest([manual], entries),
        )

    def test_post_write_validation_failure_rolls_back_through_safe_update_path(self):
        source = (ROOT / "ci/lib/common.sh").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory(prefix=TEMP_PREFIX) as temporary:
            temporary_path = Path(temporary)
            build_root = temporary_path / "build"
            fixture = build_root / COMMON_SH_NAME
            fixture.parent.mkdir(parents=True)
            lines, entries = self.parse_fixture(fixture, source)
            manual = self.modsecurity_review_required(entries)
            safe = self.haproxy_safe_update(entries)
            original = fixture.read_text(encoding="utf-8")

            with patch.dict(os.environ, {"BUILD_ROOT": str(build_root)}, clear=False):
                with patch.object(
                    CHECKER,
                    "parse_common",
                    side_effect=CHECKER.UpstreamError("forced post-write verification"),
                ):
                    outcome = CHECKER.apply_requested_updates(
                        True,
                        CHECKER.exit_code(
                            [manual, safe],
                            entries,
                            defer_reviewed_provenance=True,
                        ),
                        fixture,
                        lines,
                        entries,
                        [manual, safe],
                        defer_reviewed_provenance=True,
                    )

            restored = fixture.read_text(encoding="utf-8")

        self.assertIsNone(outcome)
        self.assertEqual(restored, original)

    def test_markdown_summary_preserves_manual_and_fatal_sections(self):
        summary = {
            "generated_at": "2026-08-08T00:00:00Z",
            "common_sh": "/safe/build/common.sh",
            "maintenance_outcome": CHECKER.MAINTENANCE_OUTCOME_FATAL,
            "components": [
                {
                    "component": "manual component",
                    "current": "1.0",
                    "latest": "1.1",
                    "status": CHECKER.STATUS_REVIEW_REQUIRED,
                    "updates": [],
                    "details": {"reason": "review immutable commit"},
                },
                {
                    "component": "safe component",
                    "current": "2.0",
                    "latest": "2.1",
                    "status": CHECKER.STATUS_OUTDATED,
                    "updates": [{"variable": "SAFE_VERSION"}],
                    "details": {},
                },
            ],
            "missing_required": ["REQUIRED_VALUE"],
            "manual_review_components": ["manual component"],
            "fatal_components": ["fatal component"],
            "updates_applied": [
                {
                    "variable": "SAFE_VERSION",
                    "line": 7,
                    "old": "2.0",
                    "new": "2.1",
                }
            ],
            "inventory": [{"name": "SAFE_VERSION", "line": 7, "resolved": "2.1"}],
        }

        markdown = CHECKER.markdown_summary(summary)

        self.assertIn(
            "| manual component | 1.0 | 1.1 | `review_required` | review immutable commit |",
            markdown,
        )
        self.assertIn("## Missing required values", markdown)
        self.assertIn("## Manual provenance review required", markdown)
        self.assertIn("## Fatal components", markdown)
        self.assertIn("| SAFE_VERSION | 7 | `2.0` | `2.1` |", markdown)
        self.assertIn("| SAFE_VERSION | 7 | `2.1` |", markdown)
        self.assertLess(
            markdown.index("## Missing required values"),
            markdown.index("## Manual provenance review required"),
        )
        self.assertLess(
            markdown.index("## Manual provenance review required"),
            markdown.index("## Fatal components"),
        )

    def test_maintenance_rejects_a_nonreversible_automatic_source_value(self):
        with tempfile.TemporaryDirectory(prefix=TEMP_PREFIX) as temporary:
            temporary_path = Path(temporary)
            build_root = temporary_path / "build"
            fixture = build_root / COMMON_SH_NAME
            fixture.parent.mkdir(parents=True)
            original = 'VERSION="${VERSION:-1.0;unsafe}"\n'
            lines, entries = self.parse_fixture(fixture, original)
            unsafe_update = CHECKER.UpdateChange(
                variable="VERSION",
                line=entries["VERSION"].line,
                old="1.0;unsafe",
                new="2.0",
            )
            unsafe_result = CHECKER.ComponentResult(
                component="unsafe rollback fixture",
                status=CHECKER.STATUS_OUTDATED,
                message="must not write an irreversible candidate",
                variables=["VERSION"],
                updates=[unsafe_update],
            )

            disposition = CHECKER.maintenance_disposition(
                [unsafe_result],
                entries,
                defer_reviewed_provenance=True,
            )
            with patch.dict(os.environ, {"BUILD_ROOT": str(build_root)}, clear=False):
                rc, applied, _, _ = CHECKER.apply_requested_updates(
                    True,
                    1,
                    fixture,
                    lines,
                    entries,
                    [unsafe_result],
                    defer_reviewed_provenance=True,
                )
            unchanged = fixture.read_text(encoding="utf-8")

        self.assertEqual(disposition.outcome, CHECKER.MAINTENANCE_OUTCOME_FATAL)
        self.assertEqual(rc, 2)
        self.assertEqual(applied, [])
        self.assertEqual(unchanged, original)

    def test_maintenance_mode_rejects_fatal_statuses_and_variable_overlap_without_writing(
        self,
    ):
        source = (ROOT / "ci/lib/common.sh").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory(prefix=TEMP_PREFIX) as temporary:
            temporary_path = Path(temporary)
            build_root = temporary_path / "build"
            fixture = build_root / COMMON_SH_NAME
            fixture.parent.mkdir(parents=True)
            lines, entries = self.parse_fixture(fixture, source)
            manual = self.modsecurity_review_required(entries)
            original = fixture.read_text(encoding="utf-8")

            for status in (
                CHECKER.STATUS_UNKNOWN,
                CHECKER.STATUS_BLOCKED,
                CHECKER.STATUS_ERROR,
            ):
                with self.subTest(fatal_status=status):
                    fatal = CHECKER.ComponentResult(
                        component=f"{status} fixture",
                        status=status,
                        message="fatal fixture",
                        variables=[],
                    )
                    disposition = CHECKER.maintenance_disposition(
                        [manual, fatal],
                        entries,
                        defer_reviewed_provenance=True,
                    )
                    self.assertEqual(
                        disposition.outcome, CHECKER.MAINTENANCE_OUTCOME_FATAL
                    )
                    self.assertIn(fatal.component, disposition.fatal_components)

            overlap_update = CHECKER.plan_update(
                entries,
                "MODSECURITY_V3_RELEASE_TAG",
                "v3.0.16",
            )
            self.assertIsNotNone(overlap_update)
            overlap = CHECKER.ComponentResult(
                component="unsafe overlapping updater",
                status=CHECKER.STATUS_OUTDATED,
                message="must not touch manual provenance",
                variables=["MODSECURITY_V3_RELEASE_TAG"],
                updates=[overlap_update],
            )
            disposition = CHECKER.maintenance_disposition(
                [manual, overlap],
                entries,
                defer_reviewed_provenance=True,
            )
            self.assertEqual(disposition.outcome, CHECKER.MAINTENANCE_OUTCOME_FATAL)
            self.assertIn(overlap.component, disposition.fatal_components)

            with patch.dict(os.environ, {"BUILD_ROOT": str(build_root)}, clear=False):
                rc, applied, _, _ = CHECKER.apply_requested_updates(
                    True,
                    2,
                    fixture,
                    lines,
                    entries,
                    [manual, overlap],
                    defer_reviewed_provenance=True,
                )
            unchanged = fixture.read_text(encoding="utf-8")

        self.assertEqual(rc, 2)
        self.assertEqual(applied, [])
        self.assertEqual(unchanged, original)

    def test_manual_review_classification_requires_fixed_identity_and_byte_exact_pins(
        self,
    ):
        source = (ROOT / "ci/lib/common.sh").read_text(encoding="utf-8")

        class NoReleaseLookup:
            def get_json(self, url):
                raise AssertionError(
                    f"unsafe configuration reached release lookup: {url}"
                )

        invalid_cases = (
            (
                "foreign-modsecurity-repository",
                'MODSECURITY_V3_APPROVED_REPO_URL="https://github.com/attacker/ModSecurity.git"',
            ),
            (
                "branch-like-modsecurity-tag",
                'MODSECURITY_V3_RELEASE_TAG="main"',
            ),
            (
                "malformed-crs-commit",
                'CRS_APPROVED_COMMIT="not-an-immutable-commit"',
            ),
        )
        for name, replacement in invalid_cases:
            with self.subTest(name=name):
                if name == "malformed-crs-commit":
                    original = (
                        'CRS_APPROVED_COMMIT="55b09f5acfd16413e7b31041100711ceb7adc89c"'
                    )
                    check = CHECKER.check_crs_release_provenance
                    expected_status = CHECKER.STATUS_BLOCKED
                else:
                    original = (
                        'MODSECURITY_V3_APPROVED_REPO_URL="https://github.com/'
                        'owasp-modsecurity/ModSecurity.git"'
                        if name == "foreign-modsecurity-repository"
                        else 'MODSECURITY_V3_RELEASE_TAG="v3.0.15"'
                    )
                    check = CHECKER.check_modsecurity_v3_release_provenance
                    expected_status = CHECKER.STATUS_UNKNOWN
                with tempfile.TemporaryDirectory(prefix=TEMP_PREFIX) as temporary:
                    fixture = Path(temporary) / COMMON_SH_NAME
                    _, invalid_entries = self.parse_fixture(
                        fixture,
                        source.replace(original, replacement, 1),
                    )
                    result = check(invalid_entries, NoReleaseLookup())
                self.assertEqual(result.status, expected_status)

        _, entries = CHECKER.parse_common(ROOT / "ci/lib/common.sh")
        manual = self.modsecurity_review_required(entries)
        before = CHECKER.manual_review_pin_values([manual], entries)
        changed_entries = dict(entries)
        changed_entries["MODSECURITY_V3_RELEASE_TAG"] = dataclasses.replace(
            changed_entries["MODSECURITY_V3_RELEASE_TAG"],
            raw='MODSECURITY_V3_RELEASE_TAG="v3.0.16"',
        )
        with self.assertRaises(CHECKER.UpstreamError):
            CHECKER.require_manual_review_pins_unchanged(before, changed_entries)


if __name__ == "__main__":
    unittest.main()
