"""Regression coverage for the reviewed NGINX release tag/asset/digest tuple."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

from tests.security_regression.common_version_fixture_support import (
    write_common_fixture,
)


ROOT = Path(__file__).resolve().parents[2]
CHECKER_PATH = ROOT / "ci/tools/check-common-versions.py"
REPOSITORY = "nginx/nginx"
RELEASE_TAG = "release-9.900.1"
ASSET_NAME = "nginx-9.900.1.tar.gz"
PUBLISHED_SHA256 = "a" * 64


def load_checker():
    spec = importlib.util.spec_from_file_location("check_common_versions", CHECKER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load the common-version checker")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


CHECKER = load_checker()


def release_payload(tag: str, digest: str = PUBLISHED_SHA256) -> dict[str, object]:
    asset_name = f"nginx-{tag.removeprefix('release-')}.tar.gz"
    return {
        "tag_name": tag,
        "assets": [
            {
                "name": asset_name,
                "browser_download_url": f"https://github.com/{REPOSITORY}/releases/download/{tag}/{asset_name}",
                "digest": f"sha256:{digest}",
            }
        ],
    }


class FakeGitHubClient:
    def __init__(self, current_release: dict[str, object]) -> None:
        self.current_release = current_release
        self.urls: list[str] = []

    def get_json(self, url: str) -> dict[str, object]:
        self.urls.append(url)
        if url == f"https://api.github.com/repos/{REPOSITORY}/releases/latest":
            return self.current_release
        raise AssertionError(f"unexpected GitHub API URL: {url}")


class NginxReleaseProvenanceTests(unittest.TestCase):
    def entries(self, tag: str = RELEASE_TAG, *, dynamic_aliases: bool = True):
        asset_name = f"nginx-{tag.removeprefix('release-')}.tar.gz"
        fixture_source = "\n".join(
            [
                'NGINX_SOURCE_MODE="github-release"',
                'NGINX_SOURCE_REPO_URL="https://github.com/nginx/nginx"',
                'NGINX_GITHUB_REPO="https://github.com/nginx/nginx"',
                f'NGINX_RELEASE_TAG="{tag}"',
                f'NGINX_SOURCE_GIT_REF="{tag}"',
                f'NGINX_RELEASE_ASSET_NAME="{asset_name}"',
                f'NGINX_DOWNLOAD_URL="https://github.com/{REPOSITORY}/releases/download/{tag}/{asset_name}"',
                f'NGINX_SHA256_REQUESTED="${{NGINX_SHA256_REQUESTED:-{PUBLISHED_SHA256}}}"',
                f'NGINX_SHA256="${{NGINX_SHA256:-{PUBLISHED_SHA256}}}"',
                "",
            ]
        )
        with tempfile.TemporaryDirectory(
            prefix="nginx-release-provenance-"
        ) as temporary:
            fixture = write_common_fixture(Path(temporary), fixture_source, {})
            _, parsed = CHECKER.parse_common(fixture)
        return parsed

    def test_current_release_asset_and_digest_are_verified_together(self):
        client = FakeGitHubClient(release_payload(RELEASE_TAG))
        result = CHECKER.check_nginx_release_provenance(
            self.entries(),
            client,
        )

        self.assertEqual(CHECKER.STATUS_CURRENT, result.status)
        self.assertEqual(result.updates, [])
        self.assertEqual(result.details["official_asset_sha256"], PUBLISHED_SHA256)
        self.assertEqual(
            result.details["official_asset_url"],
            f"https://github.com/{REPOSITORY}/releases/download/{RELEASE_TAG}/{ASSET_NAME}",
        )
        self.assertEqual(
            client.urls,
            [f"https://api.github.com/repos/{REPOSITORY}/releases/latest"],
        )

    def test_provenance_check_uses_only_the_official_latest_release_endpoint(self):
        client = FakeGitHubClient(release_payload(RELEASE_TAG))
        result = CHECKER.check_nginx_release_provenance(
            self.entries(),
            client,
        )

        self.assertEqual(CHECKER.STATUS_CURRENT, result.status)
        self.assertEqual(
            client.urls,
            [f"https://api.github.com/repos/{REPOSITORY}/releases/latest"],
        )
        self.assertNotIn("/releases/tags/", "\n".join(client.urls))

    def test_digest_mismatch_generates_only_a_complete_atomic_repair_plan(self):
        client = FakeGitHubClient(release_payload(RELEASE_TAG, "b" * 64))
        result = CHECKER.check_nginx_release_provenance(
            self.entries(),
            client,
        )

        self.assertEqual(CHECKER.STATUS_OUTDATED, result.status)
        self.assertEqual(
            {update.variable for update in result.updates},
            {"NGINX_SHA256"},
        )
        self.assertIn("differs", result.message)
        self.assertEqual(
            client.urls,
            [f"https://api.github.com/repos/{REPOSITORY}/releases/latest"],
        )

    def test_newer_release_updates_tag_ref_asset_and_digest_as_one_group(self):
        previous_tag = "release-9.900.0"
        result = CHECKER.check_all(
            self.entries(previous_tag, dynamic_aliases=False),
            FakeGitHubClient(release_payload(RELEASE_TAG, "b" * 64)),
            ("NGINX",),
        )[0]

        self.assertEqual(CHECKER.STATUS_OUTDATED, result.status)
        self.assertEqual(
            {update.variable: update.new for update in result.updates},
            {
                "NGINX_RELEASE_TAG": RELEASE_TAG,
                "NGINX_SOURCE_GIT_REF": RELEASE_TAG,
                "NGINX_RELEASE_ASSET_NAME": ASSET_NAME,
                "NGINX_SHA256": "b" * 64,
            },
        )
        self.assertEqual(
            result.details["atomic_expected_values"],
            {update.variable: update.new for update in result.updates},
        )


if __name__ == "__main__":
    unittest.main()
