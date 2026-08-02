"""Regression coverage for the reviewed NGINX release tag/asset/digest tuple."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CHECKER_PATH = ROOT / "ci/tools/check-common-versions.py"
REPOSITORY = "nginx/nginx"
RELEASE_TAG = "release-1.31.3"
ASSET_NAME = "nginx-1.31.3.tar.gz"
PUBLISHED_SHA256 = "a7657c50811c2d92d9895395e8b873ef60398142c4db21eb647811c38f6dd525"


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
        if url == f"https://api.github.com/repos/{REPOSITORY}/releases/tags/{RELEASE_TAG}":
            return self.current_release
        if url.endswith("/releases/latest"):
            raise AssertionError("NGINX provenance must never query GitHub's floating latest endpoint")
        raise AssertionError(f"unexpected GitHub API URL: {url}")


class NginxReleaseProvenanceTests(unittest.TestCase):
    def entries(self):
        _, parsed = CHECKER.parse_common(ROOT / "ci/lib/common.sh")
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
            [f"https://api.github.com/repos/{REPOSITORY}/releases/tags/{RELEASE_TAG}"],
        )

    def test_provenance_check_uses_only_the_configured_fixed_tag_endpoint(self):
        client = FakeGitHubClient(release_payload(RELEASE_TAG))
        result = CHECKER.check_nginx_release_provenance(
            self.entries(),
            client,
        )

        self.assertEqual(CHECKER.STATUS_CURRENT, result.status)
        self.assertEqual(
            client.urls,
            [f"https://api.github.com/repos/{REPOSITORY}/releases/tags/{RELEASE_TAG}"],
        )
        self.assertNotIn("/releases/latest", "\n".join(client.urls))

    def test_digest_mismatch_never_generates_an_automatic_update(self):
        client = FakeGitHubClient(release_payload(RELEASE_TAG, "b" * 64))
        result = CHECKER.check_nginx_release_provenance(
            self.entries(),
            client,
        )

        self.assertEqual(CHECKER.STATUS_UNKNOWN, result.status)
        self.assertEqual(result.updates, [])
        self.assertIn("does not match", result.message)
        self.assertEqual(
            client.urls,
            [f"https://api.github.com/repos/{REPOSITORY}/releases/tags/{RELEASE_TAG}"],
        )


if __name__ == "__main__":
    unittest.main()
