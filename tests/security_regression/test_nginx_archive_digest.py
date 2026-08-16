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
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import textwrap
import unittest
from pathlib import Path

from tests.security_regression.git_provenance_test_support import (
    create_approved_modsecurity_v3_topology,
    fake_git_script,
)
from tests.security_regression.common_version_fixture_support import (
    rewrite_common_assignments,
)


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "ci/provisioning/prepare-nginx-build.sh"
RUNTIME_COMPONENT_HELPER = ROOT / "ci/lib/runtime-component-common.sh"
FIXTURES = ROOT / "tests/fixtures/nginx-archive-digest"
APPROVED_MODSECURITY_V3_REPO = "https://github.com/owasp-modsecurity/ModSecurity.git"
APPROVED_MODSECURITY_V3_COMMIT = "c" * 40
APPROVED_MODSECURITY_V3_RELEASE_TAG = "v3.900.0"
TEST_NGINX_RELEASE_TAG = "release-9.900.1"
TEST_NGINX_RELEASE_ASSET_NAME = "nginx-9.900.1.tar.gz"
TEST_NGINX_SHA256 = "a" * 64


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
            with gzip.GzipFile(
                filename="", mode="wb", fileobj=raw, mtime=0
            ) as compressed:
                with tarfile.open(
                    fileobj=compressed, mode="w", format=tarfile.GNU_FORMAT
                ) as archive:
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

    def nginx_archive_cache_key(
        self,
        *,
        source_repository: str,
        source_mode: str,
        release_tag: str,
        source_ref: str,
        asset_name: str,
        digest: str,
    ) -> str:
        """Match the NUL-delimited full-tuple cache identity in the shell entrypoint."""

        values = (
            source_repository,
            source_mode,
            release_tag,
            source_ref,
            asset_name,
            digest.lower(),
        )
        payload = b"".join(value.encode("utf-8") + b"\0" for value in values)
        return hashlib.sha256(payload).hexdigest()

    def write_cache_manifest(
        self,
        harness: dict[str, Path | dict[str, str]],
        *,
        release_tag: str = TEST_NGINX_RELEASE_TAG,
        source_ref: str = TEST_NGINX_RELEASE_TAG,
        asset_name: str = TEST_NGINX_RELEASE_ASSET_NAME,
        digest: str | None = None,
    ) -> None:
        """Create the exact trusted cache-manifest payload for a test fixture."""

        cache = harness["cache"]
        candidate = harness["candidate"]
        manifest = harness["cache_manifest"]
        self.assertIsInstance(cache, Path)
        self.assertIsInstance(candidate, Path)
        self.assertIsInstance(manifest, Path)
        if digest is None:
            digest = self.archive_digest(harness)
        source_repository = "https://github.com/nginx/nginx"
        source_mode = "github-release"
        cache_key = self.nginx_archive_cache_key(
            source_repository=source_repository,
            source_mode=source_mode,
            release_tag=release_tag,
            source_ref=source_ref,
            asset_name=asset_name,
            digest=digest,
        )
        self.assertEqual(candidate.parent.name, cache_key)
        candidate.parent.mkdir(parents=True, exist_ok=True)
        manifest.write_text(
            "\n".join(
                (
                    "schema=nginx-archive-cache-v2",
                    f"source_repository={source_repository}",
                    f"source_mode={source_mode}",
                    f"release_tag={release_tag}",
                    f"source_ref={source_ref}",
                    f"release_asset_name={asset_name}",
                    f"expected_sha256={digest.lower()}",
                    f"cache_key={cache_key}",
                    "",
                )
            ),
            encoding="utf-8",
        )

    def write_test_runtime_lock(
        self,
        framework_root: Path,
        *,
        release_tag: str,
        asset_name: str,
        digest: str,
        source_ref: str | None = None,
    ) -> None:
        """Synchronize the copied common defaults and lock for one fixture tuple.

        Archive-boundary cases deliberately use several safe, test-only release
        tuples.  Keep the copied production entrypoint's lock enforcement active
        by making that tuple canonical only inside the disposable fixture.
        """

        common_source = rewrite_common_assignments(
            (ROOT / "ci/lib/common.sh").read_text(encoding="utf-8"),
            {
                "MODSECURITY_V3_APPROVED_COMMIT": APPROVED_MODSECURITY_V3_COMMIT,
                "MODSECURITY_V3_RELEASE_TAG": APPROVED_MODSECURITY_V3_RELEASE_TAG,
                "NGINX_RELEASE_TAG": release_tag,
                "NGINX_SOURCE_GIT_REF": release_tag if source_ref is None else source_ref,
                "NGINX_RELEASE_ASSET_NAME": asset_name,
                "NGINX_SHA256": digest,
            },
        )
        (framework_root / "ci/lib/common.sh").write_text(
            common_source
            + "\n# Test-only host-Git override; production common.sh has no such escape.\n"
            + "ci_modsecurity_v3_require_host_git() {\n"
            + "    ci_v3_host_git_bin=$FAKE_GIT_BIN\n"
            + "    return 0\n"
            + "}\n",
            encoding="utf-8",
        )

        lock_path = framework_root / "ci/provisioning/runtime-component-lock.json"
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        nginx_profile = next(
            profile for profile in lock["profiles"] if profile["id"] == "nginx-h1"
        )
        nginx_profile.update(
            {
                "version": release_tag.removeprefix("release-"),
                "asset_name": asset_name,
                "download_url": (
                    "https://github.com/nginx/nginx/releases/download/"
                    f"{release_tag}/{asset_name}"
                ),
                "sha256": digest.lower(),
                "source_provenance": f"github-release:{release_tag}",
            }
        )
        lock_path.write_text(json.dumps(lock), encoding="utf-8")

    def rewrite_test_common(
        self, framework_root: Path, assignments: dict[str, str]
    ) -> None:
        """Change only the disposable common.sh authority for a fixture case."""

        common_path = framework_root / "ci/lib/common.sh"
        common_source = rewrite_common_assignments(
            common_path.read_text(encoding="utf-8"), assignments
        )
        common_path.write_text(common_source, encoding="utf-8")

    def make_test_framework_copy(self, root: Path) -> Path:
        """Copy only the sourced entrypoint dependencies into task-local test state."""

        framework_root = root / "framework-copy"
        (framework_root / "ci/lib").mkdir(parents=True)
        (framework_root / "ci/provisioning").mkdir(parents=True)
        (framework_root / "ci/tools").mkdir(parents=True)
        (framework_root / "tests").mkdir()
        (framework_root / "Makefile").write_text(
            "# test-only framework root\n", encoding="utf-8"
        )
        shutil.copy2(ROOT / "ci/lib/path.sh", framework_root / "ci/lib/path.sh")
        shutil.copy2(
            ROOT / "ci/lib/path-bootstrap.sh",
            framework_root / "ci/lib/path-bootstrap.sh",
        )
        shutil.copy2(
            ROOT / "ci/lib/runtime-component-common.sh",
            framework_root / "ci/lib/runtime-component-common.sh",
        )
        shutil.copy2(SCRIPT, framework_root / "ci/provisioning/prepare-nginx-build.sh")
        shutil.copy2(
            ROOT / "ci/tools/check-runtime-component-lock.py",
            framework_root / "ci/tools/check-runtime-component-lock.py",
        )
        shutil.copy2(
            ROOT / "ci/tools/sync-runtime-components.py",
            framework_root / "ci/tools/sync-runtime-components.py",
        )
        shutil.copy2(
            ROOT / "ci/provisioning/runtime-components.manifest.json",
            framework_root / "ci/provisioning/runtime-components.manifest.json",
        )
        lock = json.loads(
            (ROOT / "ci/provisioning/runtime-component-lock.json").read_text(
                encoding="utf-8"
            )
        )
        nginx_profile = next(
            profile for profile in lock["profiles"] if profile["id"] == "nginx-h1"
        )
        nginx_profile.update(
            {
                "version": TEST_NGINX_RELEASE_TAG.removeprefix("release-"),
                "asset_name": TEST_NGINX_RELEASE_ASSET_NAME,
                "download_url": (
                    "https://github.com/nginx/nginx/releases/download/"
                    f"{TEST_NGINX_RELEASE_TAG}/{TEST_NGINX_RELEASE_ASSET_NAME}"
                ),
                "sha256": TEST_NGINX_SHA256,
                "source_provenance": f"github-release:{TEST_NGINX_RELEASE_TAG}",
            }
        )
        (framework_root / "ci/provisioning/runtime-component-lock.json").write_text(
            json.dumps(lock), encoding="utf-8"
        )
        self.write_test_runtime_lock(
            framework_root,
            release_tag=TEST_NGINX_RELEASE_TAG,
            asset_name=TEST_NGINX_RELEASE_ASSET_NAME,
            digest=TEST_NGINX_SHA256,
        )
        return framework_root / "ci/provisioning/prepare-nginx-build.sh"

    def make_harness(self) -> dict[str, Path | dict[str, str]]:
        root = Path(
            tempfile.mkdtemp(
                prefix="nginx-archive-digest-",
                dir=os.environ.get("TEST_TMPDIR"),
            )
        )
        tools_dir = root / "tools"
        tools_dir.mkdir()
        archive = root / "good.tar.gz"
        replacement = root / "replacement.tar.gz"
        self.write_archive(archive, self.fixture_text("archive-good.payload"))
        self.write_archive(
            replacement, self.fixture_text("archive-replacement.payload")
        )

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
        (shared_prefix / "include/modsecurity/modsecurity.h").write_text(
            "fixture\n", encoding="utf-8"
        )
        (shared_prefix / "lib").mkdir()
        (shared_prefix / "lib/libmodsecurity.so").write_text(
            "fixture\n", encoding="utf-8"
        )

        curl_log = root / "curl.log"
        tar_log = root / "tar.log"
        git_log = root / "git.log"
        swap_marker = root / "archive-swapped"
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
            case "$url" in
                */releases/latest) exit 94 ;;
            esac
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
            if [ "${FAKE_SHA256SUM_MODE:-}" = "approve-wrong" ]; then
                printf '%s  %s\n' "$NGINX_SHA256" "${1:-}"
                exit 0
            fi
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
            fake_git_script(
                APPROVED_MODSECURITY_V3_REPO, APPROVED_MODSECURITY_V3_COMMIT
            ),
        )

        nginx_build = build_root / "nginx-build"
        nginx_prefix = build_root / "nginx-prefix"
        tag = TEST_NGINX_RELEASE_TAG
        source_repository = "https://github.com/nginx/nginx"
        source_mode = "github-release"
        asset_name = TEST_NGINX_RELEASE_ASSET_NAME
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        cache_key = self.nginx_archive_cache_key(
            source_repository=source_repository,
            source_mode=source_mode,
            release_tag=tag,
            source_ref=tag,
            asset_name=asset_name,
            digest=digest,
        )
        cache_directory = cache / "nginx-archives" / cache_key
        candidate = cache_directory / asset_name
        cache_manifest = cache_directory / "nginx-archive-cache.manifest"
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
            "NGINX_RELEASE_ASSET_NAME": asset_name,
            "NGINX_SOURCE_MODE": source_mode,
            "NGINX_PROTOCOL_PROFILE": "h1",
            "FIXTURE_ARCHIVE": str(archive),
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
        }
        return {
            "root": root,
            "archive": archive,
            "replacement": replacement,
            "cache": cache,
            "cache_key": cache_key,
            "cache_manifest": cache_manifest,
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
        synchronize_runtime_lock: bool = True,
        strip_canonical_env: bool = True,
        **overrides: str | None,
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.update(harness["environment"])
        environment["NGINX_SHA256"] = digest
        for name, value in overrides.items():
            if value is None:
                environment.pop(name, None)
            else:
                environment[name] = value
        if synchronize_runtime_lock:
            script = harness["script"]
            self.assertIsInstance(script, Path)
            self.write_test_runtime_lock(
                script.parents[2],
                release_tag=environment.get("NGINX_RELEASE_TAG", TEST_NGINX_RELEASE_TAG),
                asset_name=environment.get(
                    "NGINX_RELEASE_ASSET_NAME", TEST_NGINX_RELEASE_ASSET_NAME
                ),
                digest=environment.get("NGINX_SHA256", TEST_NGINX_SHA256),
                source_ref=environment.get("NGINX_SOURCE_GIT_REF", TEST_NGINX_RELEASE_TAG),
            )
        # The disposable copied common.sh is the canonical fixture authority.
        # Most cases intentionally remove inherited values to exercise that
        # authority.  Override-specific cases retain them to prove the
        # production inherited-environment guard fails closed.
        if strip_canonical_env:
            for name in (
                "NGINX_SOURCE_MODE",
                "NGINX_SOURCE_REPO_URL",
                "NGINX_GITHUB_REPO",
                "NGINX_RELEASE_TAG",
                "NGINX_SOURCE_GIT_REF",
                "NGINX_RELEASE_ASSET_NAME",
                "NGINX_DOWNLOAD_URL",
                "NGINX_SHA256",
            ):
                environment.pop(name, None)
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

    def assert_no_nginx_source_io(
        self, harness: dict[str, Path | dict[str, str]]
    ) -> None:
        """Assert a rejected tuple cannot allocate a new cache or consume an archive."""

        cache = harness["cache"]
        curl_log = harness["curl_log"]
        self.assertIsInstance(cache, Path)
        self.assertIsInstance(curl_log, Path)
        self.assertEqual(self.tar_invocations(harness), [])
        self.assertFalse(curl_log.exists(), "invalid NGINX provenance reached curl")
        self.assertFalse(
            (cache / "nginx-archives").exists(),
            "invalid NGINX provenance allocated a full-tuple cache directory",
        )

    def archive_digest(self, harness: dict[str, Path | dict[str, str]]) -> str:
        return hashlib.sha256(harness["archive"].read_bytes()).hexdigest()

    def test_default_release_provenance_is_a_complete_release_asset_sha_tuple(self):
        root = Path(
            tempfile.mkdtemp(
                prefix="nginx-archive-default-provenance-",
                dir=os.environ.get("TEST_TMPDIR"),
            )
        )
        environment = os.environ.copy()
        for name in (
            "NGINX_SOURCE_MODE",
            "NGINX_SOURCE_REPO_URL",
            "NGINX_GITHUB_REPO",
            "NGINX_RELEASE_TAG",
            "NGINX_SOURCE_GIT_REF",
            "NGINX_RELEASE_ASSET_NAME",
            "NGINX_SHA256",
        ):
            environment.pop(name, None)
        try:
            fixture_script = self.make_test_framework_copy(root)
            result = subprocess.run(
                [
                    "sh",
                    "-c",
                    '. "$1"; printf "%s\\n%s\\n%s\\n%s\\n%s\\n%s\\n" "$NGINX_SOURCE_MODE" "$NGINX_SOURCE_REPO_URL" "$NGINX_RELEASE_TAG" "$NGINX_SOURCE_GIT_REF" "$NGINX_RELEASE_ASSET_NAME" "$NGINX_SHA256"',
                    "sh",
                    str(fixture_script.parents[1] / "lib/common.sh"),
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
                    "github-release",
                    "https://github.com/nginx/nginx",
                    TEST_NGINX_RELEASE_TAG,
                    TEST_NGINX_RELEASE_TAG,
                    TEST_NGINX_RELEASE_ASSET_NAME,
                    TEST_NGINX_SHA256,
                ],
            )
        finally:
            shutil.rmtree(root)

    def test_explicit_empty_release_tag_stops_before_cache_network_or_extraction(self):
        harness = self.make_harness()
        try:
            result = self.run_prepare(
                harness,
                self.archive_digest(harness),
                strip_canonical_env=False,
                NGINX_RELEASE_TAG="",
            )
            self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
            self.assertIn(
                "NGINX_RELEASE_TAG contains unsafe characters",
                result.stdout,
            )
            self.assert_no_nginx_source_io(harness)
        finally:
            self.remove_harness(harness)

    def test_unset_runtime_tag_uses_only_the_reviewed_static_default(self):
        harness = self.make_harness()
        try:
            result = self.run_prepare(
                harness,
                self.archive_digest(harness),
                NGINX_RELEASE_TAG=None,
                NGINX_SOURCE_GIT_REF=None,
                NGINX_RELEASE_ASSET_NAME=TEST_NGINX_RELEASE_ASSET_NAME,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            calls = harness["curl_log"].read_text(encoding="utf-8").splitlines()
            self.assertEqual(
                calls,
                [
                    "=https|=https|https://github.com/nginx/nginx/releases/download/"
                    f"{TEST_NGINX_RELEASE_TAG}/{TEST_NGINX_RELEASE_ASSET_NAME}"
                ],
            )
            self.assertEqual(len(self.tar_invocations(harness)), 1)
        finally:
            self.remove_harness(harness)

    def test_effective_tuple_outside_the_lock_is_blocked_before_network_or_tar(self):
        harness = self.make_harness()
        try:
            script = harness["script"]
            self.assertIsInstance(script, Path)
            self.rewrite_test_common(
                script.parents[2],
                {"NGINX_SHA256": self.archive_digest(harness)},
            )
            result = self.run_prepare(
                harness,
                self.archive_digest(harness),
                synchronize_runtime_lock=False,
            )
            self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
            self.assertIn(
                "NGINX runtime configuration does not match the reviewed component lock",
                result.stdout,
            )
            self.assertIn("nginx-h1 SHA-256 drift", result.stderr)
            self.assert_no_nginx_source_io(harness)
        finally:
            self.remove_harness(harness)

    def test_empty_whitespace_and_invalid_digests_stop_before_network_or_tar(self):
        cases = {
            "empty": (
                self.fixture_text("digest-empty.txt").strip(),
                "NGINX_SHA256 must be a pinned 64-character SHA-256 value",
            ),
            "whitespace": (
                self.fixture_text("digest-whitespace.txt")
                .rstrip("\n")
                .encode("ascii")
                .decode("unicode_escape"),
                "NGINX_SHA256 must be a pinned 64-character SHA-256 value",
            ),
            "invalid": (
                self.fixture_text("digest-invalid.txt"),
                "NGINX_SHA256 must be a pinned 64-character SHA-256 value",
            ),
            "short": (
                "a" * 63,
                "NGINX_SHA256 must be a pinned 64-character SHA-256 value",
            ),
            "long": (
                "a" * 65,
                "NGINX_SHA256 must be a pinned 64-character SHA-256 value",
            ),
        }
        for label, (digest, expected_message) in cases.items():
            with self.subTest(label=label):
                harness = self.make_harness()
                try:
                    result = self.run_prepare(harness, digest)
                    self.assertEqual(
                        result.returncode, 77, result.stdout + result.stderr
                    )
                    self.assertIn(expected_message, result.stdout)
                    self.assert_no_nginx_source_io(harness)
                finally:
                    self.remove_harness(harness)

        harness = self.make_harness()
        try:
            result = self.run_prepare(harness, f"{self.archive_digest(harness)}\n")
            self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
            self.assertIn(
                "NGINX_SHA256 must be a pinned 64-character SHA-256 value",
                result.stdout,
            )
            self.assert_no_nginx_source_io(harness)
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
                    result = self.run_prepare(
                        harness,
                        self.archive_digest(harness),
                        strip_canonical_env=False,
                        **overrides,
                    )
                    self.assertEqual(
                        result.returncode, 77, result.stdout + result.stderr
                    )
                    self.assertIn(message, result.stdout)
                    self.assert_no_nginx_source_io(harness)
                finally:
                    self.remove_harness(harness)

    def test_latest_tag_or_ref_is_rejected_before_cache_network_or_extraction(self):
        cases = (
            (
                "release-tag",
                {"NGINX_RELEASE_TAG": "latest"},
                "NGINX_RELEASE_TAG must be an explicit reviewed release tag",
            ),
            (
                "source-ref",
                {"NGINX_SOURCE_GIT_REF": "latest"},
                "NGINX_SOURCE_GIT_REF must be an explicit reviewed source ref",
            ),
        )
        for label, overrides, message in cases:
            with self.subTest(label=label):
                harness = self.make_harness()
                try:
                    cache = harness["cache"]
                    self.assertIsInstance(cache, Path)
                    legacy_metadata = cache / "nginx-latest-release.json"
                    legacy_archive = cache / "nginx-fixture-latest.tar.gz"
                    legacy_metadata.write_text(
                        '{"tag_name":"fixture-latest"}\n', encoding="utf-8"
                    )
                    shutil.copy2(harness["replacement"], legacy_archive)

                    result = self.run_prepare(
                        harness,
                        self.archive_digest(harness),
                        strip_canonical_env=False,
                        **overrides,
                    )

                    self.assertEqual(
                        result.returncode, 77, result.stdout + result.stderr
                    )
                    self.assertIn(message, result.stdout)
                    self.assert_no_nginx_source_io(harness)
                    self.assertTrue(legacy_metadata.is_file())
                    self.assertEqual(
                        legacy_archive.read_bytes(),
                        harness["replacement"].read_bytes(),
                    )
                finally:
                    self.remove_harness(harness)

    def test_mismatch_is_blocked_before_tar(self):
        harness = self.make_harness()
        try:
            result = self.run_prepare(
                harness, self.fixture_text("digest-mismatch.txt").strip()
            )
            self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
            self.assertIn("nginx SHA256 verification failed", result.stdout)
            self.assertEqual(self.tar_invocations(harness), [])
        finally:
            self.remove_harness(harness)

    def test_tar_observation_identifies_direct_use_of_candidate_archive(self):
        harness = self.make_harness()
        try:
            direct_candidate_invocation = (
                f"-xf {harness['candidate']} -C {harness['root']}"
            )
            harness["tar_log"].write_text(
                f"{direct_candidate_invocation}\n", encoding="utf-8"
            )
            self.assertEqual(
                self.tar_invocations(harness), [direct_candidate_invocation]
            )
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

    def test_path_shadowed_sha256sum_cannot_approve_a_wrong_nginx_archive(self):
        harness = self.make_harness()
        try:
            environment = harness["environment"]
            self.assertIsInstance(environment, dict)
            environment["FIXTURE_ARCHIVE"] = str(harness["replacement"])
            result = self.run_prepare(
                harness,
                self.archive_digest(harness),
                FAKE_SHA256SUM_MODE="approve-wrong",
            )
            self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
            self.assertIn("nginx SHA256 verification failed", result.stdout)
            self.assertFalse((harness["root"] / "archive-swapped").exists())
            self.assertEqual(self.tar_invocations(harness), [])
        finally:
            self.remove_harness(harness)

    def test_fixed_release_download_requires_https_only_redirects_and_never_latest(
        self,
    ):
        harness = self.make_harness()
        try:
            result = self.run_prepare(
                harness,
                self.archive_digest(harness),
                CURL_REQUIRE_HTTPS_REDIRECTS="1",
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            curl_calls = harness["curl_log"].read_text(encoding="utf-8").splitlines()
            self.assertEqual(
                curl_calls,
                [
                    "=https|=https|https://github.com/nginx/nginx/releases/download/"
                    f"{TEST_NGINX_RELEASE_TAG}/{TEST_NGINX_RELEASE_ASSET_NAME}",
                ],
            )
            self.assertEqual(len(self.tar_invocations(harness)), 1)
        finally:
            self.remove_harness(harness)

    def test_all_redirecting_curl_commands_limit_protocols_to_https(self):
        curl_calls = [
            line.strip()
            for line in RUNTIME_COMPONENT_HELPER.read_text(encoding="utf-8").splitlines()
            if line.lstrip().startswith(("curl ", "if curl "))
        ]
        self.assertEqual(len(curl_calls), 2)
        for call in curl_calls:
            self.assertIn("curl --disable --proto =https --proto-redir =https", call)
        self.assertNotIn("/releases/latest", SCRIPT.read_text(encoding="utf-8"))

    def test_noncanonical_source_repository_is_rejected_before_network_or_tar(self):
        cases = (
            (
                "direct-override",
                {
                    "NGINX_SOURCE_REPO_URL": "https://github.com/fixture-owner/fixture-nginx"
                },
            ),
            (
                "legacy-alias",
                {
                    "NGINX_SOURCE_REPO_URL": "",
                    "NGINX_GITHUB_REPO": "https://github.com/fixture-owner/compat-nginx",
                },
            ),
        )
        for label, overrides in cases:
            with self.subTest(label=label):
                harness = self.make_harness()
                try:
                    result = self.run_prepare(
                        harness,
                        self.archive_digest(harness),
                        strip_canonical_env=False,
                        **overrides,
                    )
                    self.assertEqual(
                        result.returncode, 77, result.stdout + result.stderr
                    )
                    self.assertIn(
                        "NGINX_SOURCE_REPO_URL override is not permitted",
                        result.stdout,
                    )
                    self.assert_no_nginx_source_io(harness)
                finally:
                    self.remove_harness(harness)

    def test_full_tuple_cache_identity_separates_fixed_release_tuples(self):
        harness = self.make_harness()
        try:
            digest = self.archive_digest(harness)
            result = self.run_prepare(harness, digest)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

            cache = harness["cache"]
            default_candidate = harness["candidate"]
            default_manifest = harness["cache_manifest"]
            self.assertIsInstance(cache, Path)
            self.assertIsInstance(default_candidate, Path)
            self.assertIsInstance(default_manifest, Path)
            self.assertTrue(default_candidate.is_file())
            self.assertTrue(default_manifest.is_file())

            alternate_tag = "release-9.900.2"
            alternate_asset = "nginx-9.900.2.tar.gz"
            alternate_key = self.nginx_archive_cache_key(
                source_repository="https://github.com/nginx/nginx",
                source_mode="github-release",
                release_tag=alternate_tag,
                source_ref=alternate_tag,
                asset_name=alternate_asset,
                digest=digest,
            )
            alternate_dir = cache / "nginx-archives" / alternate_key
            alternate_candidate = alternate_dir / alternate_asset
            alternate_manifest = alternate_dir / "nginx-archive-cache.manifest"

            script = harness["script"]
            self.assertIsInstance(script, Path)
            self.write_test_runtime_lock(
                script.parents[2],
                release_tag=alternate_tag,
                asset_name=alternate_asset,
                digest=digest,
            )
            result = self.run_prepare(
                harness,
                digest,
                synchronize_runtime_lock=False,
                REFRESH="1",
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertNotEqual(default_candidate.parent, alternate_dir)
            self.assertTrue(alternate_candidate.is_file())
            self.assertTrue(alternate_manifest.is_file())
            self.assertEqual(
                harness["curl_log"].read_text(encoding="utf-8").splitlines(),
                [
                    "=https|=https|https://github.com/nginx/nginx/releases/download/"
                    f"{TEST_NGINX_RELEASE_TAG}/{TEST_NGINX_RELEASE_ASSET_NAME}",
                    "=https|=https|https://github.com/nginx/nginx/releases/download/"
                    "release-9.900.2/nginx-9.900.2.tar.gz",
                ],
            )
        finally:
            self.remove_harness(harness)

    def test_legacy_latest_cache_cannot_be_reused_by_a_fixed_tuple(self):
        harness = self.make_harness()
        try:
            cache = harness["cache"]
            candidate = harness["candidate"]
            self.assertIsInstance(cache, Path)
            self.assertIsInstance(candidate, Path)
            legacy_metadata = cache / "nginx-latest-release.json"
            legacy_archive = cache / "nginx-fixture-latest.tar.gz"
            legacy_metadata.write_text(
                '{"tag_name":"fixture-latest"}\n', encoding="utf-8"
            )
            shutil.copy2(harness["replacement"], legacy_archive)

            result = self.run_prepare(harness, self.archive_digest(harness))

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(
                harness["curl_log"].read_text(encoding="utf-8").splitlines(),
                [
                    "=https|=https|https://github.com/nginx/nginx/releases/download/"
                    f"{TEST_NGINX_RELEASE_TAG}/{TEST_NGINX_RELEASE_ASSET_NAME}"
                ],
            )
            self.assertTrue(candidate.is_file())
            self.assertEqual(
                hashlib.sha256(candidate.read_bytes()).hexdigest(),
                self.archive_digest(harness),
            )
            self.assertEqual(
                legacy_archive.read_bytes(),
                harness["replacement"].read_bytes(),
            )
            self.assertTrue(legacy_metadata.is_file())
            self.assertEqual(len(self.tar_invocations(harness)), 1)
        finally:
            self.remove_harness(harness)

    def test_trusted_manifest_cache_is_revalidated_and_refresh_replaces_it(self):
        cached = self.make_harness()
        try:
            self.write_cache_manifest(cached)
            shutil.copy2(cached["replacement"], cached["candidate"])
            result = self.run_prepare(cached, self.archive_digest(cached))
            self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
            self.assertIn("NGINX_SHA256 mismatch", result.stdout)
            self.assertEqual(self.tar_invocations(cached), [])
            self.assertFalse(
                cached["curl_log"].exists(), "pre-existing archive was not reused"
            )
        finally:
            self.remove_harness(cached)

        refreshed = self.make_harness()
        try:
            self.write_cache_manifest(refreshed)
            shutil.copy2(refreshed["replacement"], refreshed["candidate"])
            result = self.run_prepare(
                refreshed, self.archive_digest(refreshed), REFRESH="1"
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            urls = refreshed["curl_log"].read_text(encoding="utf-8")
            self.assertIn(
                "https://github.com/nginx/nginx/releases/download/"
                f"{TEST_NGINX_RELEASE_TAG}/{TEST_NGINX_RELEASE_ASSET_NAME}",
                urls,
            )
            self.assertEqual(len(self.tar_invocations(refreshed)), 1)
        finally:
            self.remove_harness(refreshed)

    def test_cache_backed_refresh_accepts_an_explicit_cache_owner_root(self):
        harness = self.make_harness()
        try:
            root = harness["root"]
            environment = harness["environment"]
            self.assertIsInstance(root, Path)
            self.assertIsInstance(environment, dict)
            component_cache = root / "component-cache"
            owner_root = component_cache / "builds" / "connectors"
            nginx_build = owner_root / "nginx" / "cache-key" / "build"
            nginx_build.mkdir(parents=True)
            environment.update(
                {
                    "CONNECTOR_COMPONENT_CACHE": str(component_cache),
                    "NGINX_BUILD_DIR": str(nginx_build),
                    "NGINX_BUILD_OWNER_ROOT": str(owner_root),
                }
            )

            result = self.run_prepare(
                harness, self.archive_digest(harness), REFRESH="1"
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue(nginx_build.is_dir())
            self.assertEqual(len(self.tar_invocations(harness)), 1)
        finally:
            self.remove_harness(harness)

    def test_cache_backed_refresh_rejects_outside_owner_and_symlink_targets(self):
        for case, target_is_symlink in (("outside-owner", False), ("symlink", True)):
            with self.subTest(case=case):
                harness = self.make_harness()
                try:
                    root = harness["root"]
                    environment = harness["environment"]
                    self.assertIsInstance(root, Path)
                    self.assertIsInstance(environment, dict)
                    component_cache = root / "component-cache"
                    owner_root = component_cache / "builds" / "connectors"
                    outside_target = (
                        component_cache
                        / "builds"
                        / "not-connectors"
                        / "nginx"
                        / "cache-key"
                        / "build"
                    )
                    outside_target.mkdir(parents=True)
                    nginx_build = outside_target
                    if target_is_symlink:
                        nginx_build = owner_root / "nginx" / "cache-key" / "build"
                        nginx_build.parent.mkdir(parents=True)
                        nginx_build.symlink_to(outside_target, target_is_directory=True)
                    environment.update(
                        {
                            "CONNECTOR_COMPONENT_CACHE": str(component_cache),
                            "NGINX_BUILD_DIR": str(nginx_build),
                            "NGINX_BUILD_OWNER_ROOT": str(owner_root),
                        }
                    )

                    result = self.run_prepare(
                        harness, self.archive_digest(harness), REFRESH="1"
                    )

                    self.assertEqual(
                        result.returncode, 77, result.stdout + result.stderr
                    )
                    self.assertIn(
                        "NGINX REFRESH target remove target outside owner root",
                        result.stdout,
                    )
                    self.assertTrue(outside_target.is_dir())
                    self.assertFalse(harness["curl_log"].exists())
                finally:
                    self.remove_harness(harness)

    def test_archive_cache_rejects_symlinked_cache_key_directory(self):
        harness = self.make_harness()
        try:
            root = harness["root"]
            cache = harness["cache"]
            cache_key = harness["cache_key"]
            self.assertIsInstance(root, Path)
            self.assertIsInstance(cache, Path)
            self.assertIsInstance(cache_key, str)
            outside = root / "outside-archive-cache"
            outside.mkdir()
            archive_cache_root = cache / "nginx-archives"
            archive_cache_root.mkdir()
            (archive_cache_root / cache_key).symlink_to(
                outside, target_is_directory=True
            )

            result = self.run_prepare(harness, self.archive_digest(harness))

            self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
            self.assertIn("must stay under", result.stdout)
            self.assertEqual(list(outside.iterdir()), [])
        finally:
            self.remove_harness(harness)

    def test_explicit_nginx_build_owner_root_must_be_an_absolute_safe_path(self):
        harness = self.make_harness()
        try:
            result = self.run_prepare(
                harness,
                self.archive_digest(harness),
                NGINX_BUILD_OWNER_ROOT="relative-owner-root",
            )

            self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
            self.assertIn(
                "NGINX_BUILD_OWNER_ROOT must be an absolute generated path",
                result.stdout,
            )
            self.assertEqual(self.tar_invocations(harness), [])
        finally:
            self.remove_harness(harness)


if __name__ == "__main__":
    unittest.main()
