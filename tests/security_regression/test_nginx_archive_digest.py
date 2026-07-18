"""Regression coverage for the NGINX GitHub release archive trust boundary.

The test invokes the real preparation entry point with only deterministic local
archives and command shims. The shims make archive URL and cache decisions
observable while the real ``tar`` program performs the successful extraction.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import os
import shutil
import subprocess
import tarfile
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "ci/provisioning/prepare-nginx-build.sh"
FIXTURES = ROOT / "tests/fixtures/nginx-archive-digest"


class NginxArchiveDigestRegressionTests(unittest.TestCase):
    maxDiff = None

    def fixture_text(self, name: str) -> str:
        return (FIXTURES / name).read_text(encoding="utf-8")

    def write_archive(self, path: Path, payload: str) -> None:
        """Create a deterministic, local stand-in for an NGINX tag archive."""

        entries = (
            ("nginx-fixture/configure", b"#!/bin/sh\nexit 0\n", 0o755),
            ("nginx-fixture/README.fixture", payload.encode("utf-8"), 0o644),
        )
        with path.open("wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.GNU_FORMAT) as archive:
                    for name, content, mode in entries:
                        member = tarfile.TarInfo(name)
                        member.size = len(content)
                        member.mode = mode
                        member.mtime = 0
                        member.uid = 0
                        member.gid = 0
                        member.uname = ""
                        member.gname = ""
                        archive.addfile(member, io.BytesIO(content))

    def write_executable(self, path: Path, contents: str) -> None:
        path.write_text(textwrap.dedent(contents).lstrip(), encoding="utf-8")
        path.chmod(0o755)

    def make_harness(self) -> dict[str, Path | dict[str, str]]:
        root = Path(tempfile.mkdtemp(prefix="nginx-archive-digest-"))
        tools_dir = root / "tools"
        tools_dir.mkdir()
        archive = root / "good.tar.gz"
        replacement = root / "replacement.tar.gz"
        self.write_archive(archive, self.fixture_text("archive-good.payload"))
        self.write_archive(replacement, self.fixture_text("archive-replacement.payload"))

        build_root = root / "build-root"
        v3 = build_root / "v3"
        v3.mkdir(parents=True)
        cache = build_root / "cache"
        cache.mkdir()
        shared_prefix = build_root / "shared"
        (shared_prefix / "include/modsecurity").mkdir(parents=True)
        (shared_prefix / "include/modsecurity/modsecurity.h").write_text("fixture\n", encoding="utf-8")
        (shared_prefix / "lib").mkdir()
        (shared_prefix / "lib/libmodsecurity.so").write_text("fixture\n", encoding="utf-8")

        curl_log = root / "curl.log"
        tar_log = root / "tar.log"
        swap_marker = root / "archive-swapped"
        latest = FIXTURES / "latest-release.json"
        real_tar = shutil.which("tar")
        real_sha256sum = shutil.which("sha256sum")
        self.assertIsNotNone(real_tar)
        self.assertIsNotNone(real_sha256sum)

        self.write_executable(
            tools_dir / "curl",
            """
            #!/bin/sh
            set -eu
            output=
            url=
            while [ "$#" -gt 0 ]; do
                case "$1" in
                    -o)
                        output=$2
                        shift 2
                        ;;
                    *)
                        url=$1
                        shift
                        ;;
                esac
            done
            printf '%s\\n' "$url" >> "$CURL_LOG"
            if [ "$url" = "$LATEST_URL" ]; then
                [ "${CURL_LATEST_FAIL:-0}" = "1" ] && exit 22
                cp "$FIXTURE_LATEST" "$output"
                exit 0
            fi
            cp "$FIXTURE_ARCHIVE" "$output"
            """,
        )
        self.write_executable(
            tools_dir / "tar",
            """
            #!/bin/sh
            set -eu
            printf '%s\\n' "$*" >> "$TAR_LOG"
            exec "$REAL_TAR" "$@"
            """,
        )
        self.write_executable(
            tools_dir / "sha256sum",
            """
            #!/bin/sh
            set -eu
            if [ "${SWAP_AFTER_FIRST_HASH:-0}" = "1" ] && \
                [ "${1:-}" = "$NGINX_ARCHIVE_EXPECTED" ] && \
                [ ! -e "$SWAP_MARKER" ]; then
                "$REAL_SHA256SUM" "$@"
                cp "$REPLACEMENT_ARCHIVE" "$1"
                : > "$SWAP_MARKER"
                exit 0
            fi
            exec "$REAL_SHA256SUM" "$@"
            """,
        )
        self.write_executable(
            tools_dir / "make",
            """
            #!/bin/sh
            set -eu
            if [ "${1:-}" = "install" ]; then
                mkdir -p "$NGINX_PREFIX/sbin"
                printf '#!/bin/sh\\nexit 0\\n' > "$NGINX_PREFIX/sbin/nginx"
                chmod 755 "$NGINX_PREFIX/sbin/nginx"
                exit 0
            fi
            mkdir -p objs
            : > objs/ngx_http_modsecurity_module.so
            """,
        )
        self.write_executable(
            tools_dir / "cc",
            """
            #!/bin/sh
            exit 0
            """,
        )

        nginx_build = build_root / "nginx-build"
        nginx_prefix = build_root / "nginx-prefix"
        tag = "fixture-release"
        candidate = cache / f"nginx-{tag}.tar.gz"
        environment = {
            "PATH": f"{tools_dir}{os.pathsep}{os.environ['PATH']}",
            "AUTO_FETCH_SMOKE_SOURCES": "0",
            "BUILD_ROOT": str(build_root),
            "MODSECURITY_V3_SOURCE_DIR": str(v3),
            "MODSECURITY_SHARED_PREFIX": str(shared_prefix),
            "NGINX_BUILD_DIR": str(nginx_build),
            "NGINX_PREFIX": str(nginx_prefix),
            "NGINX_DOWNLOAD_DIR": str(cache),
            "NGINX_RELEASE_TAG": tag,
            "NGINX_SOURCE_MODE": "github-release",
            "NGINX_PROTOCOL_PROFILE": "h1",
            "FIXTURE_ARCHIVE": str(archive),
            "FIXTURE_LATEST": str(latest),
            "LATEST_URL": "https://api.github.com/repos/nginx/nginx/releases/latest",
            "CURL_LOG": str(curl_log),
            "TAR_LOG": str(tar_log),
            "REAL_TAR": str(real_tar),
            "REAL_SHA256SUM": str(real_sha256sum),
            "REPLACEMENT_ARCHIVE": str(replacement),
            "SWAP_MARKER": str(swap_marker),
            "NGINX_ARCHIVE_EXPECTED": str(candidate),
            "SWAP_AFTER_FIRST_HASH": "0",
            "CURL_LATEST_FAIL": "0",
        }
        return {
            "root": root,
            "archive": archive,
            "replacement": replacement,
            "cache": cache,
            "candidate": candidate,
            "curl_log": curl_log,
            "tar_log": tar_log,
            "environment": environment,
        }

    def remove_harness(self, harness: dict[str, Path | dict[str, str]]) -> None:
        shutil.rmtree(harness["root"])

    def run_prepare(
        self,
        harness: dict[str, Path | dict[str, str]],
        digest: str,
        **overrides: str,
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.update(harness["environment"])
        environment["NGINX_SHA256"] = digest
        environment.update(overrides)
        return subprocess.run(
            ["sh", str(SCRIPT)],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            check=False,
        )

    def tar_invocations(self, harness: dict[str, Path | dict[str, str]]) -> list[str]:
        log = harness["tar_log"]
        if not log.exists():
            return []
        return [line for line in log.read_text(encoding="utf-8").splitlines() if line]

    def archive_digest(self, harness: dict[str, Path | dict[str, str]]) -> str:
        return hashlib.sha256(harness["archive"].read_bytes()).hexdigest()

    def test_empty_whitespace_and_invalid_digests_stop_before_network_or_tar(self):
        cases = {
            "empty": self.fixture_text("digest-empty.txt"),
            "whitespace": self.fixture_text("digest-whitespace.txt").rstrip("\n").encode("ascii").decode("unicode_escape"),
            "invalid": self.fixture_text("digest-invalid.txt"),
        }
        for label, digest in cases.items():
            with self.subTest(label=label):
                harness = self.make_harness()
                try:
                    result = self.run_prepare(harness, digest)
                    self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
                    self.assertIn("NGINX_SHA256 must be a pinned 64-character SHA-256 value", result.stdout)
                    self.assertEqual(self.tar_invocations(harness), [])
                    self.assertFalse(harness["curl_log"].exists(), "invalid digest reached curl")
                finally:
                    self.remove_harness(harness)

        harness = self.make_harness()
        try:
            result = self.run_prepare(harness, f"{self.archive_digest(harness)}\n")
            self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
            self.assertIn("NGINX_SHA256 must be a pinned 64-character SHA-256 value", result.stdout)
            self.assertEqual(self.tar_invocations(harness), [])
            self.assertFalse(harness["curl_log"].exists(), "trailing whitespace reached curl")
        finally:
            self.remove_harness(harness)

    def test_mismatch_is_blocked_before_tar(self):
        harness = self.make_harness()
        try:
            result = self.run_prepare(harness, self.fixture_text("digest-mismatch.txt").strip())
            self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
            self.assertIn("NGINX_SHA256 mismatch", result.stdout)
            self.assertEqual(self.tar_invocations(harness), [])
        finally:
            self.remove_harness(harness)

    def test_matching_digest_extracts_only_a_verified_private_archive(self):
        harness = self.make_harness()
        try:
            result = self.run_prepare(harness, self.archive_digest(harness).upper())
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            invocations = self.tar_invocations(harness)
            self.assertEqual(len(invocations), 1, invocations)
            self.assertIn("verified-archives", invocations[0])
            self.assertNotIn(str(harness["candidate"]), invocations[0])
        finally:
            self.remove_harness(harness)

    def test_archive_replacement_after_first_hash_is_rechecked_before_tar(self):
        harness = self.make_harness()
        try:
            result = self.run_prepare(
                harness,
                self.archive_digest(harness),
                SWAP_AFTER_FIRST_HASH="1",
            )
            self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
            self.assertIn("NGINX_SHA256 mismatch", result.stdout)
            self.assertTrue((harness["root"] / "archive-swapped").exists())
            self.assertEqual(self.tar_invocations(harness), [])
            self.assertEqual(
                hashlib.sha256(harness["candidate"].read_bytes()).hexdigest(),
                hashlib.sha256(harness["replacement"].read_bytes()).hexdigest(),
            )
        finally:
            self.remove_harness(harness)

    def test_latest_resolution_uses_cached_metadata_but_still_requires_digest(self):
        harness = self.make_harness()
        try:
            latest_cache = harness["cache"] / "nginx-latest-release.json"
            shutil.copy2(FIXTURES / "latest-release.json", latest_cache)
            latest_candidate = harness["cache"] / "nginx-fixture-latest.tar.gz"
            result = self.run_prepare(
                harness,
                self.archive_digest(harness),
                NGINX_RELEASE_TAG="latest",
                NGINX_SOURCE_GIT_REF="latest",
                NGINX_ARCHIVE_EXPECTED=str(latest_candidate),
                CURL_LATEST_FAIL="1",
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            urls = harness["curl_log"].read_text(encoding="utf-8")
            self.assertIn("https://api.github.com/repos/nginx/nginx/releases/latest", urls)
            self.assertIn("https://github.com/nginx/nginx/archive/refs/tags/fixture-latest.tar.gz", urls)
            self.assertEqual(len(self.tar_invocations(harness)), 1)
        finally:
            self.remove_harness(harness)

    def test_release_and_source_overrides_select_the_expected_local_archive_path(self):
        harness = self.make_harness()
        try:
            result = self.run_prepare(
                harness,
                self.archive_digest(harness),
                NGINX_RELEASE_TAG="fixture-override",
                NGINX_SOURCE_GIT_REF="fixture-override",
                NGINX_SOURCE_REPO_URL="https://github.com/fixture-owner/fixture-nginx",
                NGINX_ARCHIVE_EXPECTED=str(harness["cache"] / "nginx-fixture-override.tar.gz"),
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            urls = harness["curl_log"].read_text(encoding="utf-8")
            self.assertIn(
                "https://github.com/fixture-owner/fixture-nginx/archive/refs/tags/fixture-override.tar.gz",
                urls,
            )
            self.assertEqual(len(self.tar_invocations(harness)), 1)
        finally:
            self.remove_harness(harness)

        compatibility = self.make_harness()
        try:
            result = self.run_prepare(
                compatibility,
                self.archive_digest(compatibility),
                NGINX_RELEASE_TAG="fixture-compat",
                NGINX_SOURCE_GIT_REF="fixture-compat",
                NGINX_SOURCE_REPO_URL="",
                NGINX_GITHUB_REPO="https://github.com/fixture-owner/compat-nginx",
                NGINX_ARCHIVE_EXPECTED=str(compatibility["cache"] / "nginx-fixture-compat.tar.gz"),
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            urls = compatibility["curl_log"].read_text(encoding="utf-8")
            self.assertIn(
                "https://github.com/fixture-owner/compat-nginx/archive/refs/tags/fixture-compat.tar.gz",
                urls,
            )
            self.assertEqual(len(self.tar_invocations(compatibility)), 1)
        finally:
            self.remove_harness(compatibility)

    def test_existing_archive_is_revalidated_and_refresh_replaces_it(self):
        cached = self.make_harness()
        try:
            shutil.copy2(cached["replacement"], cached["candidate"])
            result = self.run_prepare(cached, self.archive_digest(cached))
            self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
            self.assertIn("NGINX_SHA256 mismatch", result.stdout)
            self.assertEqual(self.tar_invocations(cached), [])
            self.assertFalse(cached["curl_log"].exists(), "pre-existing archive was not reused")
        finally:
            self.remove_harness(cached)

        refreshed = self.make_harness()
        try:
            shutil.copy2(refreshed["replacement"], refreshed["candidate"])
            result = self.run_prepare(refreshed, self.archive_digest(refreshed), REFRESH="1")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            urls = refreshed["curl_log"].read_text(encoding="utf-8")
            self.assertIn("https://github.com/nginx/nginx/archive/refs/tags/fixture-release.tar.gz", urls)
            self.assertEqual(len(self.tar_invocations(refreshed)), 1)
        finally:
            self.remove_harness(refreshed)


if __name__ == "__main__":
    unittest.main()
