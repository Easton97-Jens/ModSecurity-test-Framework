"""Regression coverage for the reviewed NGINX release tag/asset/digest tuple."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CHECKER_PATH = ROOT / "ci/tools/check-common-versions.py"
REPOSITORY = "nginx/nginx"
RELEASE_TAG = "release-1.31.2"
ASSET_NAME = "nginx-1.31.2.tar.gz"
PUBLISHED_SHA256 = "af2a957c41da636ddc4f883e4523c6d140b4784dbce42000c364ae5092aa473c"


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
    def __init__(self, current_release: dict[str, object], latest_release: dict[str, object]) -> None:
        self.current_release = current_release
        self.latest_release = latest_release

    def get_json(self, url: str) -> dict[str, object]:
        if url == f"https://api.github.com/repos/{REPOSITORY}/releases/tags/{RELEASE_TAG}":
            return self.current_release
        if url == f"https://api.github.com/repos/{REPOSITORY}/releases/latest":
            return self.latest_release
        raise AssertionError(f"unexpected GitHub API URL: {url}")


class NginxReleaseProvenanceTests(unittest.TestCase):
    def entries(self):
        _, parsed = CHECKER.parse_common(ROOT / "ci/lib/common.sh")
        return parsed

    def test_current_release_asset_and_digest_are_verified_together(self):
        result = CHECKER.check_nginx_release_provenance(
            self.entries(),
            FakeGitHubClient(release_payload(RELEASE_TAG), release_payload(RELEASE_TAG)),
        )

        self.assertEqual(CHECKER.STATUS_CURRENT, result.status)
        self.assertEqual([], result.updates)
        self.assertEqual(PUBLISHED_SHA256, result.details["official_asset_sha256"])
        self.assertEqual(
            f"https://github.com/{REPOSITORY}/releases/download/{RELEASE_TAG}/{ASSET_NAME}",
            result.details["official_asset_url"],
        )

    def test_newer_release_requires_a_reviewed_atomic_tuple_change(self):
        result = CHECKER.check_nginx_release_provenance(
            self.entries(),
            FakeGitHubClient(release_payload(RELEASE_TAG), release_payload("release-1.31.3")),
        )

        self.assertEqual(CHECKER.STATUS_UNKNOWN, result.status)
        self.assertEqual("release-1.31.3", result.latest)
        self.assertEqual([], result.updates)
        self.assertIn("atomically", result.message)

    def test_digest_mismatch_never_generates_an_automatic_update(self):
        result = CHECKER.check_nginx_release_provenance(
            self.entries(),
            FakeGitHubClient(release_payload(RELEASE_TAG, "b" * 64), release_payload(RELEASE_TAG)),
        )

        self.assertEqual(CHECKER.STATUS_UNKNOWN, result.status)
        self.assertEqual([], result.updates)
        self.assertIn("does not match", result.message)


if __name__ == "__main__":
    unittest.main()
