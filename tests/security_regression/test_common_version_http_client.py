"""Focused transport and credential-scope tests for the common-version client."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
CHECKER_PATH = ROOT / "ci/tools/check-common-versions.py"


def load_checker():
    spec = importlib.util.spec_from_file_location(
        "check_common_versions_http_client", CHECKER_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {CHECKER_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


CHECKER = load_checker()


class CommonVersionHttpClientTests(unittest.TestCase):
    def test_github_token_is_sent_only_to_https_repository_api(self) -> None:
        client = CHECKER.HttpClient(timeout=1)
        with patch.dict(os.environ, {"GITHUB_TOKEN": "read-only-token"}, clear=True):
            api_headers = client._headers(
                "https://api.github.com/repos/example/project/releases?per_page=100",
                "application/json",
            )
            http_headers = client._headers(
                "http://api.github.com/repos/example/project/releases",
                "application/json",
            )
            foreign_headers = client._headers(
                "https://github.com/repos/example/project/releases",
                "application/json",
            )

        self.assertEqual(api_headers["Authorization"], "Bearer read-only-token")
        self.assertEqual(api_headers["X-GitHub-Api-Version"], "2022-11-28")
        self.assertNotIn("Authorization", http_headers)
        self.assertNotIn("Authorization", foreign_headers)
        self.assertNotIn("X-GitHub-Api-Version", http_headers)
        self.assertNotIn("X-GitHub-Api-Version", foreign_headers)

    def test_missing_github_token_does_not_add_authentication_headers(self) -> None:
        client = CHECKER.HttpClient(timeout=1)
        with patch.dict(os.environ, {}, clear=True):
            headers = client._headers(
                "https://api.github.com/repos/example/project/releases"
            )
        self.assertNotIn("Authorization", headers)
        self.assertNotIn("X-GitHub-Api-Version", headers)

    def test_control_characters_in_github_token_are_rejected_without_echoing(
        self,
    ) -> None:
        client = CHECKER.HttpClient(timeout=1)
        token = "read-only-token\r\nX-Leak: value"
        with patch.dict(os.environ, {"GITHUB_TOKEN": token}, clear=True):
            with self.assertRaises(CHECKER.UpstreamUnknown) as captured:
                client._headers("https://api.github.com/repos/example/project/releases")
        self.assertIn("prohibited control characters", str(captured.exception))
        self.assertNotIn(token, str(captured.exception))

    def test_repository_api_scope_rejects_path_tricks_before_token_use(self) -> None:
        client = CHECKER.HttpClient(timeout=1)
        with patch.dict(os.environ, {"GITHUB_TOKEN": "read-only-token"}, clear=True):
            for url in (
                "https://api.github.com/repos/../example/project/releases",
                "https://api.github.com/repos/example/project;param/releases",
                "https://api.github.com.evil.example/repos/example/project/releases",
            ):
                with self.subTest(url=url):
                    headers = client._headers(url)
                    self.assertNotIn("Authorization", headers)
                    self.assertNotIn("X-GitHub-Api-Version", headers)


if __name__ == "__main__":
    unittest.main()
