"""Regression coverage for common-version checker provenance controls.

All HTTP interactions use in-memory fixtures, and each writable path is owned
by a ``TemporaryDirectory`` created for the individual test.
"""

from __future__ import annotations

import contextlib
import dataclasses
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import patch
from urllib.parse import urlsplit

from tests.security_regression.common_version_fixture_support import (
    rewrite_common_assignments,
)


ROOT = Path(__file__).resolve().parents[2]
CHECKER_PATH = ROOT / "ci/tools/check-common-versions.py"
CHECKSUM = "a" * 64
TARBALL_EXTENSION = ".tar.gz"
SHA256_SUFFIX = ".sha256"
OFFICIAL_TARBALL_HOST = "downloads.example.invalid"
TEMP_PREFIX = "common-versions-provenance-"
FIXTURE_NAME = "fixture.sh"
COMMON_SH_NAME = "common.sh"
APR_UTIL_VERSION = "1.6.9000"
APR_UTIL_SHA256 = "a" * 64
APR_UTIL_SOURCE_URL = (
    f"https://downloads.apache.org/apr/apr-util-{APR_UTIL_VERSION}.tar.bz2"
)
APR_UTIL_SHA256_URL = f"{APR_UTIL_SOURCE_URL}.sha256"
TEST_HAPROXY_BASELINE_VERSION = "3.2.9000"
TEST_HAPROXY_TARGET_VERSION = "3.2.9001"
TEST_HAPROXY_BASELINE_SHA256 = "a" * 64
TEST_HAPROXY_TARGET_SHA256 = "b" * 64
RUN_17_HAPROXY_VERSION = "3.2.22"
RUN_17_HAPROXY_SHA256 = (
    "afca3a26d573df53d0e1fc475dcd743ec5875e038e1476c80e871d70228ca2da"
)
FOCUSED_PUBLISHER_TEST_MODULES = (
    "tests.security_regression.test_common_versions_sonar_provenance",
    "tests.security_regression.test_nginx_release_provenance",
    "tests.security_regression.test_crs_git_ref_provenance",
    "tests.security_regression.test_modsecurity_v3_git_ref_provenance",
    "tests.security_regression.test_apr_util_provenance",
)


def load_checker():
    spec = importlib.util.spec_from_file_location("check_common_versions", CHECKER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load the common-version checker")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


CHECKER = load_checker()


@dataclasses.dataclass
class AppliedHaproxyUpdateFixture:
    """One temporary safe-plus-manual update application for regression tests."""

    source: str
    temporary_path: Path
    build_root: Path
    fixture: Path
    lines: list[str]
    entries: dict[str, Any]
    manual_source_lines: dict[str, str]
    manual: Any
    manual_before: dict[str, str]
    result: tuple[int, list[Any], list[str], dict[str, Any]] | None


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
    def manual_pin_source_lines(
        lines: list[str], entries: dict[str, object]
    ) -> dict[str, str]:
        """Capture each manual pin's exact source line for fixture invariants."""

        names = tuple(
            dict.fromkeys(
                name
                for variables in CHECKER.MANUAL_REVIEW_VARIABLES.values()
                for name in variables
            )
        )
        pin_lines: dict[str, str] = {}
        for name in names:
            entry = entries.get(name)
            if entry is None:
                raise AssertionError(f"test fixture is missing manual pin {name}")
            line = getattr(entry, "line", None)
            if not isinstance(line, int) or not 1 <= line <= len(lines):
                raise AssertionError(f"test fixture has invalid manual pin line {name}")
            pin_lines[name] = lines[line - 1]
        return pin_lines

    @staticmethod
    def _single_assignment_index(lines: list[str], variable: str) -> int:
        indexes = [
            index
            for index, line in enumerate(lines)
            if (assignment := CHECKER.parse_common_assignment(line)) is not None
            and assignment[1] == variable
        ]
        if len(indexes) != 1:
            raise AssertionError(
                f"test fixture must contain exactly one {variable} assignment"
            )
        return indexes[0]

    @classmethod
    def build_common_fixture_with_haproxy_baseline(
        cls,
        build_root: Path,
        source_text: str,
        baseline_version: str = TEST_HAPROXY_BASELINE_VERSION,
        baseline_sha256: str = TEST_HAPROXY_BASELINE_SHA256,
    ) -> tuple[Path, list[str], dict[str, object], dict[str, str]]:
        """Build a parser-checked fixture with only HAProxy defaults normalized."""

        fixture = build_root / COMMON_SH_NAME
        fixture.parent.mkdir(parents=True, exist_ok=True)
        fixture.write_text(source_text, encoding="utf-8")
        original_lines, original_entries = CHECKER.parse_common(fixture)
        manual_before = cls.manual_pin_source_lines(original_lines, original_entries)
        changed_lines = list(original_lines)
        requested = {
            "HAPROXY_VERSION": baseline_version,
            "HAPROXY_SHA256": baseline_sha256,
        }
        assignment_indexes: set[int] = set()
        expected_changed_indexes: set[int] = set()
        for variable, replacement in requested.items():
            index = cls._single_assignment_index(original_lines, variable)
            entry = original_entries.get(variable)
            if entry is None or getattr(entry, "line", None) != index + 1:
                raise AssertionError(
                    f"test fixture parser did not bind {variable} to its only assignment"
                )
            assignment_indexes.add(index)
            if CHECKER.value(original_entries, variable) != replacement:
                expected_changed_indexes.add(index)
            changed_lines[index] = CHECKER.replace_default_line(
                original_lines[index], variable, replacement
            )

        actual_changed = {
            index
            for index, (before, after) in enumerate(zip(original_lines, changed_lines))
            if before != after
        }
        if actual_changed != expected_changed_indexes:
            raise AssertionError(
                "test fixture changed a line outside the HAProxy tuple"
            )
        if not actual_changed.issubset(assignment_indexes):
            raise AssertionError(
                "test fixture changed a line outside the HAProxy tuple"
            )

        fixture.write_text("\n".join(changed_lines) + "\n", encoding="utf-8")
        fixture_lines, fixture_entries = CHECKER.parse_common(fixture)
        if CHECKER.value(fixture_entries, "HAPROXY_VERSION") != baseline_version:
            raise AssertionError(
                "test fixture did not set the HAProxy baseline version"
            )
        if CHECKER.value(fixture_entries, "HAPROXY_SHA256") != baseline_sha256:
            raise AssertionError("test fixture did not set the HAProxy baseline digest")
        for name, expected_line in manual_before.items():
            entry = fixture_entries.get(name)
            if (
                entry is None
                or fixture_lines[getattr(entry, "line") - 1] != expected_line
            ):
                raise AssertionError(f"test fixture changed manual pin {name}")
        return fixture, fixture_lines, fixture_entries, manual_before

    @contextlib.contextmanager
    def applied_haproxy_update_fixture(
        self,
    ) -> Iterator[AppliedHaproxyUpdateFixture]:
        """Yield the common safe-update path with manual provenance revalidation."""

        source = (ROOT / "ci/lib/common.sh").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory(prefix=TEMP_PREFIX) as temporary:
            temporary_path = Path(temporary)
            build_root = temporary_path / "build"
            fixture, lines, entries, manual_source_lines = (
                self.build_common_fixture_with_haproxy_baseline(build_root, source)
            )
            manual = self.modsecurity_review_required(entries)
            safe = self.haproxy_safe_update(entries)
            manual_before = CHECKER.manual_review_pin_values([manual], entries)

            def revalidate(candidate_entries):
                return [self.modsecurity_review_required(candidate_entries)]

            with patch.dict(os.environ, {"BUILD_ROOT": str(build_root)}, clear=False):
                result = CHECKER.apply_requested_updates(
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
            yield AppliedHaproxyUpdateFixture(
                source,
                temporary_path,
                build_root,
                fixture,
                lines,
                entries,
                manual_source_lines,
                manual,
                manual_before,
                result,
            )

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
            latest="v3.900.1",
            source=CHECKER.value(entries, "MODSECURITY_V3_APPROVED_REPO_URL"),
            details={
                "reason": "test-only reviewed atomic transition",
                "manual_variables": list(
                    CHECKER.MANUAL_REVIEW_VARIABLES[CHECKER.MODSECURITY_V3_COMPONENT]
                ),
            },
        )

    @staticmethod
    def haproxy_safe_update(
        entries,
        target_version: str = TEST_HAPROXY_TARGET_VERSION,
        target_sha256: str = TEST_HAPROXY_TARGET_SHA256,
    ):
        version_update = CHECKER.plan_update(entries, "HAPROXY_VERSION", target_version)
        checksum_update = CHECKER.plan_update(entries, "HAPROXY_SHA256", target_sha256)
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
            latest=target_version,
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
        approved_commit = "c" * 40
        release_tag = "v3.900.0"
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
        approved_repo = "https://github.com/owasp-modsecurity/ModSecurity.git"
        approved_commit = "c" * 40
        reviewed_tag = "v3.900.0"
        newer_tag = "v3.900.1"

        class FakeGitHubClient:
            def __init__(self) -> None:
                self.urls: list[str] = []

            def get_json(self, url: str) -> dict[str, str]:
                self.urls.append(url)
                return {"tag_name": newer_tag}

        fixture_source = "\n".join(
            [
                f'MODSECURITY_V3_APPROVED_REPO_URL="{approved_repo}"',
                f'MODSECURITY_V3_APPROVED_COMMIT="{approved_commit}"',
                f'MODSECURITY_V3_RELEASE_TAG="{reviewed_tag}"',
                'MODSECURITY_REPO_URL="${MODSECURITY_REPO_URL:-$MODSECURITY_V3_APPROVED_REPO_URL}"',
                'MODSECURITY_GIT_REF="${MODSECURITY_GIT_REF:-$MODSECURITY_V3_RELEASE_TAG}"',
                'MODSECURITY_V3_GIT_URL="${MODSECURITY_V3_GIT_URL:-$MODSECURITY_V3_APPROVED_REPO_URL}"',
                'MODSECURITY_V3_GIT_REF="${MODSECURITY_V3_GIT_REF:-$MODSECURITY_V3_RELEASE_TAG}"',
                "",
            ]
        )
        with tempfile.TemporaryDirectory(prefix=TEMP_PREFIX) as temporary:
            fixture = Path(temporary) / FIXTURE_NAME
            _, entries = self.parse_fixture(fixture, fixture_source)
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
        self.assertEqual(result.latest, newer_tag)
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
            'MODSECURITY_V3_RELEASE_TAG="v3.900.0"',
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
            "stale-version": {"runtime_version": "1.6.8999"},
            "foreign-host": {
                "runtime_source_url": (
                    "https://mirror.example.invalid/"
                    f"apr-util-{APR_UTIL_VERSION}.tar.bz2"
                )
            },
            "wrong-path": {
                "runtime_source_url": (
                    "https://downloads.apache.org/apr/"
                    f"other-apr-util-{APR_UTIL_VERSION}.tar.bz2"
                )
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

    def test_apr_util_164_to_165_is_one_offline_atomic_update(self):
        old_sha = "3e2ae08f40efa0c3701e54a954cefa08242de22a69f91a8ae44fc1e624ba309b"
        new_sha = "96de1dd6f6a0476d2d2e7964926d8c1ddc3bb0e210e1b1812d3ba5a454a392e2"
        source = self.apr_util_fixture().replace(APR_UTIL_VERSION, "1.6.4").replace(APR_UTIL_SHA256, old_sha)
        listing = "https://downloads.apache.org/apr/"
        checksum_url = listing + "apr-util-1.6.5.tar.bz2.sha256"
        with tempfile.TemporaryDirectory(prefix=TEMP_PREFIX) as temporary:
            _, entries = self.parse_fixture(Path(temporary) / COMMON_SH_NAME, source)
            client = FixtureHttpClient({
                listing: '<a href="apr-util-1.6.4.tar.bz2">old</a><a href="apr-util-1.6.5.tar.bz2">new</a>',
                checksum_url: f"{new_sha}  apr-util-1.6.5.tar.bz2\n",
            })
            result = CHECKER.check_apr_util_release_provenance(entries, client)
        self.assertEqual(CHECKER.STATUS_OUTDATED, result.status)
        self.assertEqual("1.6.5", result.latest)
        self.assertEqual(
            {"APR_UTIL_PINNED_VERSION": "1.6.5", "APR_UTIL_PINNED_SHA256": new_sha},
            {update.variable: update.new for update in result.updates},
        )

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
        source = (ROOT / "ci/lib/common.sh").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory(prefix=TEMP_PREFIX) as temporary:
            build_root = Path(temporary) / "build"
            _, _, entries, _ = self.build_common_fixture_with_haproxy_baseline(
                build_root, source
            )
            manual = self.modsecurity_review_required(entries)
            safe = self.haproxy_safe_update(entries)
            current = CHECKER.ComponentResult(
                component="current fixture",
                status=CHECKER.STATUS_CURRENT,
                message="current",
                variables=[],
            )

            cases = (
                (
                    "no-updates",
                    [current],
                    CHECKER.MAINTENANCE_OUTCOME_NO_UPDATES,
                    False,
                ),
                (
                    "manual-only",
                    [manual],
                    CHECKER.MAINTENANCE_OUTCOME_MANUAL_REVIEW_ONLY,
                    False,
                ),
                (
                    "safe-only",
                    [safe],
                    CHECKER.MAINTENANCE_OUTCOME_SAFE_UPDATES,
                    True,
                ),
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
        with self.applied_haproxy_update_fixture() as state:
            result = state.result
            self.assertIsNotNone(result)
            if result is None:
                return
            rc, applied, updated_lines, updated_entries = result

            self.assertEqual(rc, 0)
            self.assertEqual(
                [update.variable for update in applied],
                ["HAPROXY_VERSION", "HAPROXY_SHA256"],
            )
            self.assertEqual(
                CHECKER.value(updated_entries, "HAPROXY_VERSION"),
                TEST_HAPROXY_TARGET_VERSION,
            )
            self.assertEqual(
                CHECKER.value(updated_entries, "HAPROXY_SHA256"),
                TEST_HAPROXY_TARGET_SHA256,
            )
            CHECKER.require_manual_review_pins_unchanged(
                state.manual_before, updated_entries
            )
            self.assertEqual(
                CHECKER.manual_review_pin_digest([state.manual], updated_entries),
                CHECKER.manual_review_pin_digest([state.manual], state.entries),
            )
            for name, expected_line in state.manual_source_lines.items():
                self.assertEqual(
                    updated_lines[updated_entries[name].line - 1], expected_line
                )

    def test_post_write_validation_failure_rolls_back_through_safe_update_path(self):
        source = (ROOT / "ci/lib/common.sh").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory(prefix=TEMP_PREFIX) as temporary:
            temporary_path = Path(temporary)
            build_root = temporary_path / "build"
            fixture, lines, entries, _ = (
                self.build_common_fixture_with_haproxy_baseline(build_root, source)
            )
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

    def test_complete_haproxy_update_becomes_a_noop_when_already_applied(self):
        source = (ROOT / "ci/lib/common.sh").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory(prefix=TEMP_PREFIX) as temporary:
            build_root = Path(temporary) / "build"
            fixture, _, entries, _ = self.build_common_fixture_with_haproxy_baseline(
                build_root,
                source,
                TEST_HAPROXY_TARGET_VERSION,
                TEST_HAPROXY_TARGET_SHA256,
            )
            original = fixture.read_text(encoding="utf-8")
            self.assertIsNone(
                CHECKER.plan_update(
                    entries, "HAPROXY_VERSION", TEST_HAPROXY_TARGET_VERSION
                )
            )
            self.assertIsNone(
                CHECKER.plan_update(
                    entries, "HAPROXY_SHA256", TEST_HAPROXY_TARGET_SHA256
                )
            )
            self.assertEqual(fixture.read_text(encoding="utf-8"), original)

    def test_common_version_regressions_are_invariant_after_candidate_application(
        self,
    ):
        with self.applied_haproxy_update_fixture() as state:
            result = state.result
            self.assertIsNotNone(result)
            if result is None:
                return
            rc, applied, updated_lines, updated_entries = result
            self.assertEqual(rc, 0)
            self.assertEqual(
                [update.variable for update in applied],
                ["HAPROXY_VERSION", "HAPROXY_SHA256"],
            )
            CHECKER.require_manual_review_pins_unchanged(
                state.manual_before, updated_entries
            )
            for name, expected_line in state.manual_source_lines.items():
                self.assertEqual(
                    updated_lines[updated_entries[name].line - 1], expected_line
                )

            self.assertEqual(
                [
                    CHECKER.plan_update(
                        updated_entries,
                        "HAPROXY_VERSION",
                        TEST_HAPROXY_TARGET_VERSION,
                    ),
                    CHECKER.plan_update(
                        updated_entries,
                        "HAPROXY_SHA256",
                        TEST_HAPROXY_TARGET_SHA256,
                    ),
                ],
                [None, None],
            )
            post_apply_manual = self.modsecurity_review_required(updated_entries)
            post_apply_disposition = CHECKER.maintenance_disposition(
                [post_apply_manual],
                updated_entries,
                defer_reviewed_provenance=True,
            )
            self.assertEqual(
                post_apply_disposition.outcome,
                CHECKER.MAINTENANCE_OUTCOME_MANUAL_REVIEW_ONLY,
            )
            unchanged = state.fixture.read_text(encoding="utf-8")
            with patch.dict(
                os.environ, {"BUILD_ROOT": str(state.build_root)}, clear=False
            ):
                no_op_result = CHECKER.apply_requested_updates(
                    True,
                    CHECKER.exit_code(
                        [post_apply_manual],
                        updated_entries,
                        defer_reviewed_provenance=True,
                    ),
                    state.fixture,
                    updated_lines,
                    updated_entries,
                    [post_apply_manual],
                    defer_reviewed_provenance=True,
                )
            self.assertIsNotNone(no_op_result)
            no_op_rc, no_op_updates, _, _ = no_op_result
            self.assertEqual(no_op_rc, 0)
            self.assertEqual(no_op_updates, [])
            self.assertEqual(state.fixture.read_text(encoding="utf-8"), unchanged)

            _, _, future_entries, _ = self.build_common_fixture_with_haproxy_baseline(
                state.temporary_path / "future-build",
                state.source,
                "3.2.9100",
                "c" * 64,
            )
            future_safe = self.haproxy_safe_update(
                future_entries,
                target_version="3.2.9101",
                target_sha256="d" * 64,
            )
            self.assertEqual(
                [update.variable for update in future_safe.updates],
                ["HAPROXY_VERSION", "HAPROXY_SHA256"],
            )

        self.assertEqual(
            (ROOT / "ci/lib/common.sh").read_text(encoding="utf-8"), state.source
        )

    @unittest.skipIf(
        os.environ.get("COMMON_VERSION_POST_APPLY_META_CHILD") == "1",
        "nested publisher-state runner",
    )
    def test_publisher_focused_suite_accepts_real_and_synthetic_applied_tuples(self):
        """Run the publisher's focused modules in a disposable post-apply copy."""

        scenarios = (
            ("run-17", RUN_17_HAPROXY_VERSION, RUN_17_HAPROXY_SHA256),
            (
                "synthetic-future",
                TEST_HAPROXY_TARGET_VERSION,
                TEST_HAPROXY_TARGET_SHA256,
            ),
        )
        for name, version, digest in scenarios:
            with self.subTest(name=name):
                with tempfile.TemporaryDirectory(prefix=TEMP_PREFIX) as temporary:
                    temporary_path = Path(temporary)
                    source_copy = temporary_path / "framework-source"
                    shutil.copytree(
                        ROOT,
                        source_copy,
                        ignore=shutil.ignore_patterns(
                            ".codex",
                            ".git",
                            ".mypy_cache",
                            ".ruff_cache",
                            ".venv",
                            "__pycache__",
                            "MRTS",
                        ),
                    )
                    copied_common = source_copy / "ci/lib/common.sh"
                    copied_common.write_text(
                        rewrite_common_assignments(
                            copied_common.read_text(encoding="utf-8"),
                            {
                                "HAPROXY_VERSION": version,
                                "HAPROXY_SHA256": digest,
                            },
                        ),
                        encoding="utf-8",
                    )
                    child_tmp = temporary_path / "child-tmp"
                    child_tmp.mkdir()
                    environment = os.environ.copy()
                    environment.update(
                        {
                            "COMMON_VERSION_POST_APPLY_META_CHILD": "1",
                            "PYTHONDONTWRITEBYTECODE": "1",
                            "PYTHONPYCACHEPREFIX": str(child_tmp / "pycache"),
                            "TEST_TMPDIR": str(child_tmp),
                            "TMP_ROOT": str(child_tmp / "tmp"),
                            "BUILD_ROOT": str(child_tmp / "build"),
                            "XDG_STATE_HOME": str(child_tmp / "state"),
                        }
                    )
                    completed = subprocess.run(
                        [
                            sys.executable,
                            "-m",
                            "unittest",
                            *FOCUSED_PUBLISHER_TEST_MODULES,
                        ],
                        cwd=source_copy,
                        env=environment,
                        text=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=300,
                    )
                    self.assertEqual(
                        completed.returncode,
                        0,
                        completed.stdout + completed.stderr,
                    )

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
        source = rewrite_common_assignments(
            source,
            {
                "MODSECURITY_V3_APPROVED_COMMIT": "c" * 40,
                "MODSECURITY_V3_RELEASE_TAG": "v3.900.0",
            },
        )
        with tempfile.TemporaryDirectory(prefix=TEMP_PREFIX) as temporary:
            temporary_path = Path(temporary)
            build_root = temporary_path / "build"
            fixture, lines, entries, _ = (
                self.build_common_fixture_with_haproxy_baseline(build_root, source)
            )
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
                "v3.900.1",
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
        source = rewrite_common_assignments(
            (ROOT / "ci/lib/common.sh").read_text(encoding="utf-8"),
            {
                "MODSECURITY_V3_APPROVED_COMMIT": "c" * 40,
                "MODSECURITY_V3_RELEASE_TAG": "v3.900.0",
                "CRS_APPROVED_COMMIT": "d" * 40,
                "CRS_RELEASE_TAG": "v4.900.0",
            },
        )

        class NoReleaseLookup:
            def get_json(self, url):
                raise AssertionError(
                    f"unsafe configuration reached release lookup: {url}"
                )

        invalid_cases = (
            (
                "foreign-modsecurity-repository",
                "MODSECURITY_V3_APPROVED_REPO_URL",
                "https://github.com/attacker/ModSecurity.git",
                CHECKER.check_modsecurity_v3_release_provenance,
                CHECKER.STATUS_UNKNOWN,
            ),
            (
                "branch-like-modsecurity-tag",
                "MODSECURITY_V3_RELEASE_TAG",
                "main",
                CHECKER.check_modsecurity_v3_release_provenance,
                CHECKER.STATUS_UNKNOWN,
            ),
            (
                "malformed-crs-commit",
                "CRS_APPROVED_COMMIT",
                "not-an-immutable-commit",
                CHECKER.check_crs_release_provenance,
                CHECKER.STATUS_BLOCKED,
            ),
        )
        for name, variable, replacement, check, expected_status in invalid_cases:
            with self.subTest(name=name):
                with tempfile.TemporaryDirectory(prefix=TEMP_PREFIX) as temporary:
                    fixture = Path(temporary) / COMMON_SH_NAME
                    _, invalid_entries = self.parse_fixture(
                        fixture,
                        rewrite_common_assignments(source, {variable: replacement}),
                    )
                    result = check(invalid_entries, NoReleaseLookup())
                self.assertEqual(result.status, expected_status)

        with tempfile.TemporaryDirectory(prefix=TEMP_PREFIX) as temporary:
            fixture = Path(temporary) / COMMON_SH_NAME
            _, entries = self.parse_fixture(fixture, source)
            manual = self.modsecurity_review_required(entries)
            before = CHECKER.manual_review_pin_values([manual], entries)
            changed_entries = dict(entries)
            changed_entries["MODSECURITY_V3_RELEASE_TAG"] = dataclasses.replace(
                changed_entries["MODSECURITY_V3_RELEASE_TAG"],
                raw='MODSECURITY_V3_RELEASE_TAG="v3.900.1"',
            )
            with self.assertRaises(CHECKER.UpstreamError):
                CHECKER.require_manual_review_pins_unchanged(before, changed_entries)


if __name__ == "__main__":
    unittest.main()
