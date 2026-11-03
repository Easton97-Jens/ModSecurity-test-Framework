"""Explicit inventory output identities and incomplete-scope/error contracts."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "ci/tools/export-component-sbom.py"
SPEC = importlib.util.spec_from_file_location("component_sbom", TOOL)
SBOM = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SBOM)


class ComponentSbomTests(unittest.TestCase):
    def test_current_runtime_lock_identities_and_release_hash_semantics(self):
        lock = json.loads(
            (ROOT / "ci/provisioning/runtime-component-lock.json").read_text()
        )
        actual = SBOM.source_components(lock)
        self.assertEqual(
            {(row["name"], row["version"]) for row in actual},
            {
                ("nginx", "1.31.8"),
                ("haproxy", "3.2.26"),
                ("envoy", "1.40.2"),
                ("traefik", "3.7.17"),
                ("lighttpd", "1.4.85"),
            },
        )
        self.assertEqual(len(actual), 8)
        self.assertNotIn("hashes", actual[0])
        self.assertEqual(
            actual[0]["externalReferences"][0]["hashes"][0]["content"],
            "0652b760b3b772d2ec17b47c2fc15d9a95e6fe35cd5b877eadc1a62d9bc75af1",
        )

    def test_go_stream_preserves_independent_expected_module_identities(self):
        rows = (
            b'{"Path":"example.test/connector","Main":true}\n'
            b'{"Path":"golang.org/x/net","Version":"v0.61.0","Indirect":true}\n'
        )
        actual = SBOM.go_components(rows)
        self.assertEqual(
            [(item["name"], item["version"]) for item in actual],
            [("example.test/connector", "unreleased"), ("golang.org/x/net", "v0.61.0")],
        )
        self.assertNotIn("hashes", actual[1])  # Go h1 sums are not raw file SHA-256.

    def test_git_source_commit_is_not_misrepresented_as_a_file_hash(self):
        actual = SBOM.source_components(
            {
                "components": [
                    {
                        "name": "ModSecurity",
                        "version": "v3.0.17",
                        "repository_url": "https://github.com/owasp-modsecurity/ModSecurity.git",
                        "commit": "1925753989ccce977cdaae417b55c9726c7cf02c",
                    }
                ]
            }
        )
        self.assertEqual(actual[0]["externalReferences"][0]["type"], "vcs")
        self.assertNotIn("hashes", actual[0]["externalReferences"][0])

    def test_unresolved_or_replaced_go_modules_fail(self):
        for row in (
            {"Path": "x", "Error": {"Err": "unavailable"}},
            {"Path": "x", "Replace": {"Dir": "../unbound"}},
            {"Path": "x"},
        ):
            with self.subTest(row=row), self.assertRaises(ValueError):
                SBOM.go_components(json.dumps(row).encode())

    def test_python_environment_identities_do_not_claim_product_linkage(self):
        actual = SBOM.python_components([{"name": "PyYAML", "version": "6.0.3"}])
        self.assertEqual((actual[0]["name"], actual[0]["version"]), ("PyYAML", "6.0.3"))
        self.assertIn(
            {"name": "modsecurity:origin", "value": "python-selected-environment"},
            actual[0]["properties"],
        )

    def test_artifact_observes_exact_bytes_and_keeps_build_assertions_separate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "connector.so").write_bytes(b"actual artifact\x00bytes")
            actual = SBOM.artifact_components(
                [
                    {
                        "path": "connector.so",
                        "name": "connector",
                        "version": "dev",
                        "profile": "nginx-h2",
                        "build": {"compiler": "gcc fixture"},
                    }
                ],
                root,
            )
            self.assertEqual(
                actual[0]["hashes"],
                [
                    {
                        "alg": "SHA-256",
                        "content": hashlib.sha256(
                            b"actual artifact\x00bytes"
                        ).hexdigest(),
                    }
                ],
            )
            self.assertNotIn("dependencies", actual[0])
            self.assertIn(
                "supplied-build-description", actual[0]["properties"][-1]["name"]
            )

    def test_special_files_symlinks_hardlinks_and_oversized_inputs_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            normal = root / "normal"
            normal.write_bytes(b"x")
            (root / "symbolic").symlink_to(normal)
            os.link(normal, root / "hard")
            os.mkfifo(root / "fifo")
            for name in ("symbolic", "hard", "fifo"):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    SBOM.regular_bytes(root / name)
            large = root / "large"
            large.write_bytes(b"xx")
            with self.assertRaises(ValueError):
                SBOM.regular_bytes(large, limit=1)

    def test_bad_source_digest_and_credential_url_fail(self):
        row = {
            "name": "lib",
            "version": "1",
            "download_url": "https://example.test/lib",
            "sha256": "f" * 64,
        }
        for change in (
            {"sha256": "invalid"},
            {"download_url": "https://user:secret@example.test/lib"},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                SBOM.source_components({"components": [{**row, **change}]})

    def test_cli_determinism_revisions_duplicates_dirty_state_and_no_overwrite(self):
        import sys

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()

            def git(*args):
                return (
                    subprocess.check_output(
                        ["git", "-C", str(repo), *args], stderr=subprocess.DEVNULL
                    )
                    .decode()
                    .strip()
                )

            git("init", "--initial-branch=fixture")
            git(
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.test",
                "commit",
                "--allow-empty",
                "-m",
                "fixture",
            )
            sha = git("rev-parse", "HEAD")
            packages = root / "packages.json"
            packages.write_text('[{"name":"PyYAML","version":"6.0.3"}]')
            command = [
                sys.executable,
                str(TOOL),
                "--parent-root",
                str(repo),
                "--framework-root",
                str(repo),
                "--parent-revision",
                sha,
                "--framework-revision",
                sha,
                "--python",
                str(packages),
            ]
            first, second = root / "one.json", root / "two.json"

            def run(extra, output=first):
                return subprocess.run(
                    [*command, *extra, "--output", str(output)],
                    capture_output=True,
                    text=True,
                )

            self.assertEqual(run([]).returncode, 0)
            self.assertEqual(run([], second).returncode, 0)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            document = json.loads(first.read_text())
            self.assertEqual(document["compositions"], [{"aggregate": "incomplete"}])
            self.assertEqual(document["components"][0]["name"], "PyYAML")
            self.assertNotIn("dependencies", document)
            self.assertEqual(run([]).returncode, 77)
            self.assertEqual(
                run(["--parent-revision", "0" * 40], root / "stale").returncode, 77
            )
            self.assertEqual(
                run(["--python", str(packages)], root / "duplicate").returncode, 77
            )
            other_environment = root / "other-packages.json"
            other_environment.write_bytes(packages.read_bytes())
            shared = root / "shared.json"
            self.assertEqual(
                run(["--python", str(other_environment)], shared).returncode, 0
            )
            self.assertEqual(len(json.loads(shared.read_text())["components"]), 1)
            (repo / "untracked").write_text("development")
            self.assertEqual(run([], root / "dirty").returncode, 77)
            dirty = root / "explicit-dirty"
            self.assertEqual(run(["--allow-dirty"], dirty).returncode, 0)
            self.assertIn("dirty-development", dirty.read_text())
            self.assertFalse((root / "stale").exists())
            self.assertFalse((root / "duplicate").exists())
            self.assertEqual(run(["--allow-dirty"], repo / "inside").returncode, 77)
            self.assertFalse((repo / "inside").exists())


if __name__ == "__main__":
    unittest.main()
