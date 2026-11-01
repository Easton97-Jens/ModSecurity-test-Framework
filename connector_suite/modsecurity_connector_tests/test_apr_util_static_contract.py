"""Reject unreviewed Parent copies of the Framework-owned APR-util tuple."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import re
import subprocess
import unittest
from pathlib import Path


ROOT = connector_root()
FRAMEWORK_ROOT = source_path('modules/ModSecurity-test-Framework', root=ROOT)
ALLOWLIST_PATH = source_path('tests/fixtures/apr-util-static-allowlist.txt', root=ROOT)

STATIC_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "APR_UTIL_VERSION pin",
        re.compile(
            r"(?:['\"]?APR_UTIL_VERSION['\"]?)\s*(?::=|\?=|\+=|=|:)\s*['\"]?\d+(?:\.\d+)+",
            re.IGNORECASE,
        ),
    ),
    (
        "APR_UTIL_SHA256 pin",
        re.compile(
            r"(?:['\"]?APR_UTIL_SHA256['\"]?)\s*(?::=|\?=|\+=|=|:)\s*['\"]?[0-9a-f]{64}\b",
            re.IGNORECASE,
        ),
    ),
    (
        "APR_UTIL_SOURCE_URL pin",
        re.compile(
            r"(?:['\"]?APR_UTIL_SOURCE_URL['\"]?)\s*(?::=|\?=|\+=|=|:)\s*['\"]?https?://",
            re.IGNORECASE,
        ),
    ),
    (
        "APR_UTIL_SHA256_URL pin",
        re.compile(
            r"(?:['\"]?APR_UTIL_SHA256_URL['\"]?)\s*(?::=|\?=|\+=|=|:)\s*['\"]?https?://",
            re.IGNORECASE,
        ),
    ),
    (
        "versioned APR-util archive",
        re.compile(r"\bapr-util-\d+(?:\.\d+)+\.tar\.bz2(?:\.sha256)?\b", re.IGNORECASE),
    ),
    (
        "legacy APR-util pin alias",
        re.compile(
            r"\bAPR_UTIL_PINNED_(?:VERSION|SOURCE_URL|SHA256|SHA256_URL|URL)\b",
            re.IGNORECASE,
        ),
    ),
)


def static_hits(text: str) -> list[str]:
    """Return the static APR-util pin categories found in one text payload."""

    return [label for label, pattern in STATIC_PATTERNS if pattern.search(text)]


def approved_paths() -> dict[str, str]:
    """Load exact historical-record exceptions with their review rationale."""

    entries: dict[str, str] = {}
    for raw_line in ALLOWLIST_PATH.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        relative_path, separator, rationale = line.partition(" | ")
        if not separator or not rationale.strip():
            raise AssertionError(f"invalid APR-util allowlist entry: {raw_line!r}")
        candidate = Path(relative_path)
        if candidate.is_absolute() or ".." in candidate.parts or any(token in relative_path for token in "*?["):
            raise AssertionError(f"allowlist entry must name one exact Parent file: {relative_path}")
        if relative_path in entries:
            raise AssertionError(f"duplicate APR-util allowlist entry: {relative_path}")
        entries[relative_path] = rationale.strip()
    return entries


def iter_parent_text_files() -> list[Path]:
    """Inspect every deliverable Parent file, including untracked candidates.

    Git's tracked-plus-unignored candidate set keeps machine-local ignored
    control-plane evidence out of the delivery contract without exempting any
    hidden source directory.  Tracked `.github`, `.codex` (if ever versioned),
    and other dotfiles remain subject to the same fail-closed scan.
    """

    result = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    files: list[Path] = []
    for raw_path in result.stdout.split(b"\0"):
        if not raw_path:
            continue
        relative_path = Path(raw_path.decode("utf-8", errors="strict"))
        if relative_path.is_absolute() or ".." in relative_path.parts:
            raise AssertionError(f"Git returned unsafe Parent candidate path: {relative_path}")
        path = ROOT / relative_path
        if not path.is_file() or "__pycache__" in relative_path.parts:
            continue
        try:
            path.relative_to(FRAMEWORK_ROOT)
        except ValueError:
            files.append(path)
    return files


class AprUtilStaticContractTests(unittest.TestCase):
    def test_scanner_recognizes_each_prohibited_static_form(self) -> None:
        version = "9.8.7"
        digest = "a" * 64
        version_key = "APR_UTIL_" + "VERSION"
        sha256_key = "APR_UTIL_" + "SHA256"
        source_url_key = "APR_UTIL_" + "SOURCE_URL"
        sha256_url_key = "APR_UTIL_" + "SHA256_URL"
        pinned_version_key = "APR_UTIL_" + "PINNED_" + "VERSION"
        sample = "\n".join(
            (
                version_key + " = '" + version + "'",
                sha256_key + " = '" + digest + "'",
                source_url_key + " = '" + "https://fixture.invalid/apr-util-" + version + ".tar.bz2'",
                sha256_url_key + " = '" + "https://fixture.invalid/apr-util-" + version + ".tar.bz2.sha256'",
                "https://fixture.invalid/apr-util-" + version + ".tar.bz2.sha256",
                pinned_version_key,
            )
        )
        self.assertEqual(
            static_hits(sample),
            [
                "APR_UTIL_VERSION pin",
                "APR_UTIL_SHA256 pin",
                "APR_UTIL_SOURCE_URL pin",
                "APR_UTIL_SHA256_URL pin",
                "versioned APR-util archive",
                "legacy APR-util pin alias",
            ],
        )

    def test_scanner_recognizes_makefile_assignment_variants(self) -> None:
        digest = "b" * 64
        version = "9.8" + ".7"
        version_key = "APR_UTIL_" + "VERSION"
        sha256_key = "APR_UTIL_" + "SHA256"
        source_url_key = "APR_UTIL_" + "SOURCE_URL"
        sha256_url_key = "APR_UTIL_" + "SHA256_URL"
        for operator in ("=", ":=", "?=", "+="):
            with self.subTest(operator=operator):
                sample = "\n".join(
                    (
                        f"{version_key} {operator} {version}",
                        f"{sha256_key} {operator} {digest}",
                        f"{source_url_key} {operator} https://fixture.invalid/apr-util-{version}.tar.bz2",
                        f"{sha256_url_key} {operator} https://fixture.invalid/apr-util-{version}.tar.bz2.sha256",
                    )
                )
                self.assertEqual(
                    static_hits(sample),
                    [
                        "APR_UTIL_VERSION pin",
                        "APR_UTIL_SHA256 pin",
                        "APR_UTIL_SOURCE_URL pin",
                        "APR_UTIL_SHA256_URL pin",
                        "versioned APR-util archive",
                    ],
                )

    def test_scanner_recognizes_yaml_json_and_python_mapping_forms(self) -> None:
        version = "9.8.7"
        digest = "c" * 64
        version_key = "APR_UTIL_" + "VERSION"
        sha256_key = "APR_UTIL_" + "SHA256"
        source_url_key = "APR_UTIL_" + "SOURCE_URL"
        sha256_url_key = "APR_UTIL_" + "SHA256_URL"
        pinned_keys = tuple(
            "APR_UTIL_" + "PINNED_" + suffix
            for suffix in ("VERSION", "SOURCE_URL", "SHA256", "SHA256_URL")
        )
        source_url = f"https://fixture.invalid/apr-util-{version}.tar.bz2"
        sha256_url = source_url + ".sha256"
        forms = (
            "\n".join(
                (
                    f"{version_key}: {version}",
                    f"{sha256_key}: {digest}",
                    f"{source_url_key}: {source_url}",
                    f"{sha256_url_key}: {sha256_url}",
                    *(f"{key}: retained" for key in pinned_keys),
                )
            ),
            "{" + ", ".join(
                (
                    f'\"{version_key}\": \"{version}\"',
                    f'\"{sha256_key}\": \"{digest}\"',
                    f'\"{source_url_key}\": \"{source_url}\"',
                    f'\"{sha256_url_key}\": \"{sha256_url}\"',
                    *(f'\"{key}\": \"retained\"' for key in pinned_keys),
                )
            ) + "}",
            "{" + ", ".join(
                (
                    f"'{version_key}': '{version}'",
                    f"'{sha256_key}': '{digest}'",
                    f"'{source_url_key}': '{source_url}'",
                    f"'{sha256_url_key}': '{sha256_url}'",
                    *(f"'{key}': 'retained'" for key in pinned_keys),
                )
            ) + "}",
        )
        expected = [
            "APR_UTIL_VERSION pin",
            "APR_UTIL_SHA256 pin",
            "APR_UTIL_SOURCE_URL pin",
            "APR_UTIL_SHA256_URL pin",
            "versioned APR-util archive",
            "legacy APR-util pin alias",
        ]
        for form in forms:
            with self.subTest(form=form):
                self.assertEqual(static_hits(form), expected)

    def test_scanner_regression_fixture_does_not_detect_itself(self) -> None:
        self.assertEqual(static_hits(Path(__file__).read_text(encoding="utf-8")), [])

    def test_allowlist_is_exact_existing_historical_evidence(self) -> None:
        for relative_path, rationale in approved_paths().items():
            with self.subTest(path=relative_path):
                path = ROOT / relative_path
                self.assertTrue(path.is_file(), f"allowlisted path is missing: {relative_path}")
                self.assertGreaterEqual(len(rationale), 20)
                self.assertTrue(
                    static_hits(path.read_text(encoding="utf-8", errors="replace")),
                    f"allowlisted path no longer contains a static APR-util record: {relative_path}",
                )

    def test_scan_uses_git_delivery_candidates_without_hidden_directory_exemptions(self) -> None:
        candidates = {path.relative_to(ROOT).as_posix() for path in iter_parent_text_files()}
        self.assertIn("tests/test_apr_util_static_contract.py", candidates)
        self.assertIn("tests/fixtures/apr-util-static-allowlist.txt", candidates)
        self.assertIn(".github/workflows/ci-security-workflow-lint.yml", candidates)

    def test_parent_has_no_unapproved_static_apr_util_tuple(self) -> None:
        approved = approved_paths()
        violations: list[str] = []
        for path in iter_parent_text_files():
            relative_path = path.relative_to(ROOT).as_posix()
            hits = static_hits(path.read_text(encoding="utf-8", errors="replace"))
            if hits and relative_path not in approved:
                violations.append(f"{relative_path}: {', '.join(hits)}")
        self.assertEqual(
            violations,
            [],
            "Parent APR-util pins must be Framework-owned; add only an exact historical "
            "record to the reviewed allowlist when retention is required.",
        )



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
