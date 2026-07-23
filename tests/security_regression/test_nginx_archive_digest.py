"""Regression coverage for the NGINX GitHub release archive trust boundary.

The test invokes an exact temporary copy of the real preparation entry point
with deterministic local archives and command shims. Its copied common helper
uses a test-local host-Git function override so the NGINX archive boundary can
consume an approved fake V3 topology without weakening production provenance.
The shims make archive URL and cache decisions observable while the real
``tar`` program performs the successful extraction.
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

from git_provenance_test_support import (
    create_approved_modsecurity_v3_topology,
    fake_git_script,
)


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "ci/provisioning/prepare-nginx-build.sh"
FIXTURES = ROOT / "tests/fixtures/nginx-archive-digest"
APPROVED_MODSECURITY_V3_REPO = "https://github.com/owasp-modsecurity/ModSecurity.git"
APPROVED_MODSECURITY_V3_COMMIT = "0fb4aff98b4980cf6426697d5605c424e3d5bb60"


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

    def make_test_framework_copy(self, root: Path) -> Path:
        """Copy only the sourced entrypoint dependencies into task-local test state."""

        framework_root = root / "framework-copy"
        (framework_root / "ci/lib").mkdir(parents=True)
        (framework_root / "ci/provisioning").mkdir(parents=True)
        (framework_root / "tests").mkdir()
        (framework_root / "Makefile").write_text("# test-only framework root\n", encoding="utf-8")
        shutil.copy2(ROOT / "ci/lib/path.sh", framework_root / "ci/lib/path.sh")
        shutil.copy2(
            ROOT / "ci/lib/path-bootstrap.sh", framework_root / "ci/lib/path-bootstrap.sh"
        )
        shutil.copy2(SCRIPT, framework_root / "ci/provisioning/prepare-nginx-build.sh")
        common_source = (ROOT / "ci/lib/common.sh").read_text(encoding="utf-8")
        (framework_root / "ci/lib/common.sh").write_text(
            common_source
            + "\n# Test-only host-Git override; production common.sh has no such escape.\n"
            + "ci_modsecurity_v3_require_host_git() {\n"
            + "    ci_v3_host_git_bin=$FAKE_GIT_BIN\n"
            + "    return 0\n"
            + "}\n",
            encoding="utf-8",
        )
        return framework_root / "ci/provisioning/prepare-nginx-build.sh"

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
        create_approved_modsecurity_v3_topology(v3)
        framework_script = self.make_test_framework_copy(root)
        nginx_adapter = root / "nginx-adapter"
        (nginx_adapter / "src").mkdir(parents=True)
        (nginx_adapter / "src/ddebug.h").write_text("fixture\n", encoding="utf-8")
        cache = build_root / "cache"
        cache.mkdir()
        shared_prefix = build_root / "shared"
        (shared_prefix / "include/modsecurity").mkdir(parents=True)
        (shared_prefix / "include/modsecurity/modsecurity.h").write_text("fixture\n", encoding="utf-8")
        (shared_prefix / "lib").mkdir()
        (shared_prefix / "lib/libmodsecurity.so").write_text("fixture\n", encoding="utf-8")

        curl_log = root / "curl.log"
        tar_log = root / "tar.log"
        git_log = root / "git.log"
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
            protocol=
            redirect_protocol=
            while [ "$#" -gt 0 ]; do
                case "$1" in
                    -o)
                        output=$2
                        shift 2
                        ;;
                    --proto)
                        protocol=$2
                        shift 2
                        ;;
                    --proto-redir)
                        redirect_protocol=$2
                        shift 2
                        ;;
                    *)
                        url=$1
                        shift
                        ;;
                esac
            done
            if [ "${CURL_REQUIRE_HTTPS_REDIRECTS:-0}" = "1" ]; then
                [ "$protocol" = "=https" ] || exit 91
                [ "$redirect_protocol" = "=https" ] || exit 92
            fi
            printf '%s|%s|%s\\n' "$protocol" "$redirect_protocol" "$url" >> "$CURL_LOG"
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
        self.write_executable(
            tools_dir / "git",
            fake_git_script(APPROVED_MODSECURITY_V3_REPO, APPROVED_MODSECURITY_V3_COMMIT),
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
            "MODSECURITY_NGINX_SOURCE_DIR": str(nginx_adapter),
            "MODSECURITY_SHARED_PREFIX": str(shared_prefix),
            "NGINX_BUILD_DIR": str(nginx_build),
            "NGINX_PREFIX": str(nginx_prefix),
            "NGINX_DOWNLOAD_DIR": str(cache),
            "NGINX_RELEASE_TAG": tag,
            "NGINX_RELEASE_ASSET_NAME": f"nginx-{tag}.tar.gz",
            "NGINX_SOURCE_MODE": "github-release",
            "NGINX_PROTOCOL_PROFILE": "h1",
            "FIXTURE_ARCHIVE": str(archive),
            "FIXTURE_LATEST": str(latest),
            "LATEST_URL": "https://api.github.com/repos/nginx/nginx/releases/latest",
            "CURL_LOG": str(curl_log),
            "TAR_LOG": str(tar_log),
            "FAKE_GIT_LOG": str(git_log),
            "FAKE_GIT_ROOT": str(v3),
            "FAKE_GIT_BIN": str(tools_dir / "git"),
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
            "script": framework_script,
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
            ["sh", str(harness["script"])],
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
        expected_candidate = str(harness["candidate"])
        return [
            line
            for line in log.read_text(encoding="utf-8").splitlines()
            if "verified-archives/" in line or expected_candidate in line
        ]

    def archive_digest(self, harness: dict[str, Path | dict[str, str]]) -> str:
        return hashlib.sha256(harness["archive"].read_bytes()).hexdigest()

    def test_default_release_provenance_is_a_complete_release_asset_sha_tuple(self):
        environment = os.environ.copy()
        for name in (
            "NGINX_RELEASE_TAG",
            "NGINX_SOURCE_GIT_REF",
            "NGINX_RELEASE_ASSET_NAME",
            "NGINX_SHA256",
        ):
            environment.pop(name, None)
        result = subprocess.run(
            [
                "sh",
                "-c",
                '. "$1"; printf "%s\\n%s\\n%s\\n%s\\n" "$NGINX_RELEASE_TAG" "$NGINX_SOURCE_GIT_REF" "$NGINX_RELEASE_ASSET_NAME" "$NGINX_SHA256"',
                "sh",
                str(ROOT / "ci/lib/common.sh"),
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            result.stdout.splitlines(),
            [
                "release-1.31.2",
                "release-1.31.2",
                "nginx-1.31.2.tar.gz",
                "af2a957c41da636ddc4f883e4523c6d140b4784dbce42000c364ae5092aa473c",
            ],
        )

    def test_empty_whitespace_and_invalid_digests_stop_before_network_or_tar(self):
        cases = {
            "empty": (
                self.fixture_text("digest-empty.txt").strip(),
                "NGINX_SHA256 must not be explicitly empty",
            ),
            "whitespace": (
                self.fixture_text("digest-whitespace.txt").rstrip("\n").encode("ascii").decode("unicode_escape"),
                "NGINX_SHA256 must be a pinned 64-character SHA-256 value",
            ),
            "invalid": (
                self.fixture_text("digest-invalid.txt"),
                "NGINX_SHA256 must be a pinned 64-character SHA-256 value",
            ),
        }
        for label, (digest, expected_message) in cases.items():
            with self.subTest(label=label):
                harness = self.make_harness()
                try:
                    result = self.run_prepare(harness, digest)
                    self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
                    self.assertIn(expected_message, result.stdout)
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

    def test_fixed_release_tuple_mismatches_stop_before_network_or_tar(self):
        for label, overrides, message in (
            (
                "source-ref",
                {"NGINX_SOURCE_GIT_REF": "fixture-other-ref"},
                "NGINX_SOURCE_GIT_REF must equal NGINX_RELEASE_TAG",
            ),
            (
                "asset-name",
                {"NGINX_RELEASE_ASSET_NAME": "nginx-fixture-other.tar.gz"},
                "NGINX_RELEASE_ASSET_NAME must bind NGINX_RELEASE_TAG",
            ),
        ):
            with self.subTest(label=label):
                harness = self.make_harness()
                try:
                    result = self.run_prepare(harness, self.archive_digest(harness), **overrides)
                    self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
                    self.assertIn(message, result.stdout)
                    self.assertEqual(self.tar_invocations(harness), [])
                    self.assertFalse(harness["curl_log"].exists(), "tuple mismatch reached curl")
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

    def test_tar_observation_identifies_direct_use_of_candidate_archive(self):
        harness = self.make_harness()
        try:
            direct_candidate_invocation = f"-xf {harness['candidate']} -C {harness['root']}"
            harness["tar_log"].write_text(f"{direct_candidate_invocation}\n", encoding="utf-8")
            self.assertEqual(self.tar_invocations(harness), [direct_candidate_invocation])
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
            self.assertIn(
                "https://github.com/nginx/nginx/releases/download/fixture-latest/nginx-fixture-latest.tar.gz",
                urls,
            )
            self.assertEqual(len(self.tar_invocations(harness)), 1)
        finally:
            self.remove_harness(harness)

    def test_latest_and_release_downloads_require_https_only_redirects(self):
        harness = self.make_harness()
        try:
            latest_candidate = harness["cache"] / "nginx-fixture-latest.tar.gz"
            result = self.run_prepare(
                harness,
                self.archive_digest(harness),
                NGINX_RELEASE_TAG="latest",
                NGINX_SOURCE_GIT_REF="latest",
                NGINX_ARCHIVE_EXPECTED=str(latest_candidate),
                CURL_REQUIRE_HTTPS_REDIRECTS="1",
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            curl_calls = harness["curl_log"].read_text(encoding="utf-8").splitlines()
            self.assertEqual(
                curl_calls,
                [
                    "=https|=https|https://api.github.com/repos/nginx/nginx/releases/latest",
                    "=https|=https|https://github.com/nginx/nginx/releases/download/fixture-latest/nginx-fixture-latest.tar.gz",
                ],
            )
            self.assertEqual(len(self.tar_invocations(harness)), 1)
        finally:
            self.remove_harness(harness)

    def test_all_redirecting_curl_commands_limit_protocols_to_https(self):
        curl_calls = [
            line.strip()
            for line in SCRIPT.read_text(encoding="utf-8").splitlines()
            if line.lstrip().startswith(("curl ", "if curl "))
        ]
        self.assertEqual(len(curl_calls), 3)
        for call in curl_calls:
            self.assertIn("curl --proto =https --proto-redir =https", call)

    def test_release_and_source_overrides_select_the_expected_local_archive_path(self):
        harness = self.make_harness()
        try:
            result = self.run_prepare(
                harness,
                self.archive_digest(harness),
                NGINX_RELEASE_TAG="fixture-override",
                NGINX_SOURCE_GIT_REF="fixture-override",
                NGINX_RELEASE_ASSET_NAME="nginx-fixture-override.tar.gz",
                NGINX_SOURCE_REPO_URL="https://github.com/fixture-owner/fixture-nginx",
                NGINX_ARCHIVE_EXPECTED=str(harness["cache"] / "nginx-fixture-override.tar.gz"),
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            urls = harness["curl_log"].read_text(encoding="utf-8")
            self.assertIn(
                "https://github.com/fixture-owner/fixture-nginx/releases/download/fixture-override/nginx-fixture-override.tar.gz",
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
                NGINX_RELEASE_ASSET_NAME="nginx-fixture-compat.tar.gz",
                NGINX_SOURCE_REPO_URL="",
                NGINX_GITHUB_REPO="https://github.com/fixture-owner/compat-nginx",
                NGINX_ARCHIVE_EXPECTED=str(compatibility["cache"] / "nginx-fixture-compat.tar.gz"),
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            urls = compatibility["curl_log"].read_text(encoding="utf-8")
            self.assertIn(
                "https://github.com/fixture-owner/compat-nginx/releases/download/fixture-compat/nginx-fixture-compat.tar.gz",
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
            self.assertIn(
                "https://github.com/nginx/nginx/releases/download/fixture-release/nginx-fixture-release.tar.gz",
                urls,
            )
            self.assertEqual(len(self.tar_invocations(refreshed)), 1)
        finally:
            self.remove_harness(refreshed)


if __name__ == "__main__":
    unittest.main()
