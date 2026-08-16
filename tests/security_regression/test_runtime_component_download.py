from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[2]
HAPROXY_PREPARER = ROOT / "ci/provisioning/prepare-haproxy-runtime.sh"
APACHE_PREPARER = ROOT / "ci/provisioning/prepare-apache-build.sh"
TRAEFIK_PREPARER = ROOT / "ci/provisioning/prepare-traefik-runtime.sh"
LIGHTTPD_PREPARER = ROOT / "ci/provisioning/prepare-lighttpd-runtime.sh"


FAKE_CURL = """#!/bin/sh
set -eu
printf '%s\\n' "$@" > "$FAKE_CURL_ARGS"
destination=
while [ "$#" -gt 0 ]; do
    if [ "$1" = "-o" ]; then
        destination=$2
        shift 2
        continue
    fi
    shift
done
case "$FAKE_CURL_MODE" in
    success)
        printf 'verified-artifact' > "$destination"
        printf '200|0|17|0.01\\n'
        ;;
    redirect)
        printf 'verified-artifact' > "$destination"
        printf '200|1|17|0.01\\n'
        ;;
    zero)
        : > "$destination"
        printf '200|0|0|0.01\\n'
        ;;
    partial)
        printf 'partial' > "$destination"
        printf '000|0|7|0.02\\n'
        exit 28
        ;;
    dns)
        printf '000|0|0|0.01\\n'
        exit 6
        ;;
    connect)
        printf '000|0|0|0.01\\n'
        exit 7
        ;;
    total_timeout)
        printf '000|0|0|0.02\\n'
        exit 28
        ;;
    tls)
        printf '000|0|0|0.01\\n'
        exit 60
        ;;
    http404|http403|http429|http500|http503)
        status=${FAKE_CURL_MODE#http}
        printf '%s|0|0|0.01\\n' "$status"
        exit 22
        ;;
    *)
        exit 99
        ;;
esac
"""


class RuntimeComponentDownloadTests(unittest.TestCase):
    def make_fake_curl(self, root: Path) -> tuple[Path, Path]:
        fake_bin = root / "bin"
        fake_bin.mkdir()
        curl = fake_bin / "curl"
        curl.write_text(FAKE_CURL, encoding="utf-8")
        curl.chmod(0o755)
        args = root / "curl-args.txt"
        return fake_bin, args

    def run_helper(
        self,
        mode: str,
        action: str = "download",
        expected: str | None = None,
        extra_environment: dict[str, str] | None = None,
    ) -> tuple[subprocess.CompletedProcess[str], Path, Path]:
        temporary = tempfile.TemporaryDirectory(prefix="runtime-download-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        cache = root / "cache"
        destination = cache / "downloads" / "artifact.bin"
        fake_bin, args = self.make_fake_curl(root)
        expected = expected or hashlib.sha256(b"verified-artifact").hexdigest()
        script = textwrap.dedent(
            """
            set -u
            . "$1/ci/lib/common.sh"
            . "$1/ci/lib/runtime-component-common.sh"
            CONNECTOR_COMPONENT_CACHE=$2
            destination=$3
            case "$4" in
                download)
                    download_runtime_artifact fixture https://example.test/runtime "$destination"
                    ;;
                verify)
                    artifact=$(download_runtime_artifact fixture https://example.test/runtime "$destination") || exit $?
                    verify_runtime_artifact_sha256 fixture "$5" "$artifact"
                    ;;
                stage)
                    artifact=$(download_runtime_artifact fixture https://example.test/runtime "$destination") || exit $?
                    verify_runtime_artifact_sha256 fixture "$5" "$artifact" || exit $?
                    stage_executable_binary fixture "$artifact" "$2/bin/fixture"
                    ;;
                diagnostic)
                    runtime_component_diagnostic fixture download curl_failed "$destination" 'https://user:secret@example.test/runtime?token=hidden' 0 0 0 0 retry_transient_network_failure not_attempted
                    ;;
                invalid_url)
                    download_runtime_artifact fixture 'http://user:secret@example.test/runtime?token=hidden' "$destination"
                    ;;
                no_redirect)
                    download_runtime_artifact_without_redirects_under_root fixture https://example.test/runtime "$destination" "$2"
                    ;;
            esac
            """
        )
        environment = os.environ.copy()
        environment.update(
            {
                "FAKE_CURL_MODE": mode,
                "FAKE_CURL_ARGS": str(args),
                "PATH": f"{fake_bin}{os.pathsep}{environment['PATH']}",
                "PYTHONDONTWRITEBYTECODE": "1",
            }
        )
        if extra_environment:
            environment.update(extra_environment)
        result = subprocess.run(
            ["sh", "-c", script, "sh", str(ROOT), str(cache), str(destination), action, expected],
            cwd=ROOT,
            text=True,
            capture_output=True,
            env=environment,
            check=False,
        )
        return result, destination, args

    def assert_no_temporary_artifacts(self, destination: Path) -> None:
        self.assertFalse(destination.exists(), destination)
        leftovers = list(destination.parent.glob(".*")) if destination.parent.exists() else []
        self.assertEqual(leftovers, [], leftovers)

    def test_successful_download_verifies_and_stages_only_after_integrity_check(self):
        result, destination, arguments = self.run_helper("success", "stage")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(destination.is_file())
        self.assertEqual((destination.parent.parent / "bin" / "fixture").read_bytes(), b"verified-artifact")
        argument_list = arguments.read_text(encoding="utf-8").splitlines()
        self.assertEqual(argument_list[0], "--disable")
        self.assertIn("--disable", argument_list)
        self.assertIn("--connect-timeout", argument_list)
        self.assertIn("--max-time", argument_list)
        self.assertIn("--retry-max-time", argument_list)
        self.assertIn("--proto", argument_list)
        self.assertIn("--proto-redir", argument_list)
        self.assertNotIn("--insecure", argument_list)
        self.assertNotIn("-k", argument_list)
        self.assertNotIn("--retry-all-errors", argument_list)

    def test_timeout_policy_rejects_zero_and_unbounded_values_before_curl(self):
        cases = (
            {"RUNTIME_DOWNLOAD_CONNECT_TIMEOUT": "0"},
            {"RUNTIME_DOWNLOAD_CONNECT_TIMEOUT": "61"},
            {"RUNTIME_DOWNLOAD_MAX_TIME": "0"},
            {"RUNTIME_DOWNLOAD_MAX_TIME": "901"},
            {"RUNTIME_DOWNLOAD_RETRY_MAX_TIME": "301"},
            {
                "RUNTIME_DOWNLOAD_MAX_TIME": "60",
                "RUNTIME_DOWNLOAD_RETRY_MAX_TIME": "61",
            },
        )
        for extra_environment in cases:
            with self.subTest(extra_environment=extra_environment):
                result, destination, arguments = self.run_helper(
                    "success", extra_environment=extra_environment
                )
                self.assertEqual(result.returncode, 77)
                self.assertIn("reason_code=timeout_policy_invalid", result.stderr)
                self.assertFalse(arguments.exists())
                self.assert_no_temporary_artifacts(destination)

    def test_redirect_is_a_valid_transferred_artifact(self):
        result, destination, _ = self.run_helper("redirect", "verify")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(destination.is_file())

    def test_direct_download_mode_forbids_redirects(self):
        result, destination, arguments = self.run_helper("success", "no_redirect")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(destination.is_file())
        argument_list = arguments.read_text(encoding="utf-8").splitlines()
        max_redirect_index = argument_list.index("--max-redirs")
        self.assertEqual(argument_list[max_redirect_index + 1], "0")

    def test_empty_partial_and_bad_sha_artifacts_are_removed(self):
        zero, zero_destination, _ = self.run_helper("zero")
        self.assertEqual(zero.returncode, 77)
        self.assertIn("reason_code=empty_artifact", zero.stderr)
        self.assert_no_temporary_artifacts(zero_destination)

        partial, partial_destination, _ = self.run_helper("partial")
        self.assertEqual(partial.returncode, 77)
        self.assertIn("reason_code=transfer_timeout", partial.stderr)
        self.assert_no_temporary_artifacts(partial_destination)

        wrong_sha, wrong_sha_destination, _ = self.run_helper("success", "verify", "0" * 64)
        self.assertEqual(wrong_sha.returncode, 77)
        self.assertIn("reason_code=sha256_mismatch", wrong_sha.stderr)
        self.assert_no_temporary_artifacts(wrong_sha_destination)

    def test_path_shadowed_sha256sum_cannot_approve_an_arbitrary_artifact(self):
        with tempfile.TemporaryDirectory(prefix="runtime-download-sha-path-") as temporary:
            root = Path(temporary)
            artifact = root / "artifact.bin"
            artifact.write_bytes(b"unreviewed-artifact")
            fake_bin = root / "bin"
            fake_bin.mkdir()
            marker = root / "shadowed-sha256sum-used"
            shadowed_sha256sum = fake_bin / "sha256sum"
            shadowed_sha256sum.write_text(
                "#!/bin/sh\nprintf used > \"$FAKE_SHA256SUM_MARKER\"\nexit 0\n",
                encoding="utf-8",
            )
            shadowed_sha256sum.chmod(0o755)
            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{fake_bin}{os.pathsep}{environment['PATH']}",
                    "FAKE_SHA256SUM_MARKER": str(marker),
                    "PYTHONDONTWRITEBYTECODE": "1",
                }
            )
            result = subprocess.run(
                [
                    "sh",
                    "-eu",
                    "-c",
                    '. "$1/ci/lib/common.sh"\n'
                    '. "$1/ci/lib/runtime-component-common.sh"\n'
                    'verify_runtime_artifact_sha256 fixture "$2" "$3"',
                    "sh",
                    str(ROOT),
                    "0" * 64,
                    str(artifact),
                ],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertFalse(marker.exists(), result.stdout + result.stderr)
        self.assertFalse(artifact.exists())
        self.assertIn("SHA256 verification failed", result.stdout + result.stderr)

    def test_apache_and_haproxy_preparers_never_resolve_sha256sum_from_path(self):
        """Integrity paths must use the fixed trusted helper, not PATH tools."""
        for preparer in (APACHE_PREPARER, HAPROXY_PREPARER):
            with self.subTest(preparer=preparer.name):
                source = preparer.read_text(encoding="utf-8")
                self.assertNotIn("command -v sha256sum", source)
                self.assertNotIn("sha256sum \"", source)
                self.assertIn("ci_trusted_sha256_file", source)

    def test_network_tls_and_http_failures_are_bounded_and_classified(self):
        cases = {
            "dns": "dns_resolution_failed",
            "connect": "connect_failed",
            "total_timeout": "transfer_timeout",
            "tls": "tls_verification_failed",
            "http404": "http_404",
            "http403": "http_403",
            "http429": "http_429",
            "http500": "http_500",
            "http503": "http_503",
        }
        for mode, reason in cases.items():
            with self.subTest(mode=mode):
                result, destination, _ = self.run_helper(mode)
                self.assertEqual(result.returncode, 77)
                self.assertIn(f"reason_code={reason}", result.stderr)
                self.assertIn("status=BLOCKED", result.stderr)
                expected_tls = {
                    "tls": "failed",
                    "http404": "verified",
                    "http403": "verified",
                    "http429": "verified",
                    "http500": "verified",
                    "http503": "verified",
                }.get(mode, "not_confirmed")
                self.assertIn(f"tls_verification={expected_tls}", result.stderr)
                self.assert_no_temporary_artifacts(destination)

    def test_diagnostics_have_the_required_safe_fields_and_redact_url_secrets(self):
        result, _, _ = self.run_helper("success", "diagnostic")
        self.assertEqual(result.returncode, 0, result.stderr)
        for field in (
            "component=fixture",
            "phase=download",
            "status=BLOCKED",
            "reason_code=curl_failed",
            "exit_code=77",
            "http_status=0",
            "redirects=0",
            "bytes=0",
            "duration_s=0",
            "tls_verification=not_attempted",
            "artifact_id=cleaned:artifact.bin",
            "remediation=retry_transient_network_failure",
        ):
            self.assertIn(field, result.stderr)
        self.assertNotIn("secret", result.stderr)
        self.assertNotIn("token=hidden", result.stderr)

    def test_rejected_url_diagnostics_redact_userinfo_and_query(self):
        result, destination, _ = self.run_helper("success", "invalid_url")
        self.assertEqual(result.returncode, 77)
        self.assertIn("host=example.test", result.stdout)
        self.assertNotIn("secret", result.stdout)
        self.assertNotIn("token=hidden", result.stdout)
        self.assert_no_temporary_artifacts(destination)

    def test_haproxy_preparer_uses_the_shared_bounded_verified_downloader(self):
        source = HAPROXY_PREPARER.read_text(encoding="utf-8")
        self.assertIn('"$CI_ROOT/lib/runtime-component-common.sh"', source)
        self.assertIn("download_runtime_artifact_under_root haproxy", source)
        self.assertIn("verify_runtime_artifact_sha256 haproxy", source)
        self.assertNotIn("curl -fsSL --retry", source)
        self.assertNotIn("curl -L --fail --retry", source)

    def test_haproxy_build_does_not_consume_reusable_shared_source_cache(self):
        """A cache writer must not be able to alter the source reaching make."""
        source = HAPROXY_PREPARER.read_text(encoding="utf-8")
        self.assertIn(
            'makefile="$HAPROXY_RUNTIME_BUILD_WORKTREE/Makefile"', source
        )
        self.assertIn("haproxy-source-extract-private", source)
        self.assertIn('tar -xf "$VERIFIED_ARCHIVE_PATH"', source)
        self.assertIn("private HAProxy archive copy sha256 mismatch", source)
        self.assertNotIn("run_logged haproxy-source-copy", source)

    def test_apache_preparer_uses_shared_bounded_downloaders(self):
        source = APACHE_PREPARER.read_text(encoding="utf-8")
        self.assertIn('"$CI_ROOT/lib/runtime-component-common.sh"', source)
        self.assertIn("download_runtime_artifact_under_root", source)
        self.assertIn("download_runtime_artifact_without_redirects_under_root", source)
        self.assertIn("verify_runtime_artifact_sha256", source)

    def test_traefik_extracts_only_from_private_rehashed_archive(self):
        source = TRAEFIK_PREPARER.read_text(encoding="utf-8")
        self.assertIn("runtime_component_stage_verified_archive", source)
        self.assertIn('verified_archive="$TRAEFIK_BUILD_ROOT/verified-archives/', source)
        self.assertIn('"$TRAEFIK_BUILD_ROOT")', source)
        self.assertNotIn('verified_archive="$TRAEFIK_COMPONENT_ROOT/', source)
        self.assertIn('extract_single_binary_from_tar traefik "$verified_archive"', source)
        self.assertNotIn('extract_single_binary_from_tar traefik "$archive"', source)

    def test_lighttpd_extracts_only_from_private_rehashed_archive(self):
        source = LIGHTTPD_PREPARER.read_text(encoding="utf-8")
        self.assertIn("runtime_component_stage_verified_archive", source)
        self.assertIn('verified_archive="$LIGHTTPD_CONNECTOR_BUILD_ROOT/verified-archives/', source)
        self.assertIn('"$LIGHTTPD_CONNECTOR_BUILD_ROOT")', source)
        self.assertNotIn('verified_archive="$LIGHTTPD_BUILD_ROOT/', source)
        self.assertIn('extract_runtime_source_tar lighttpd "$verified_archive"', source)
        self.assertNotIn('extract_runtime_source_tar lighttpd "$archive"', source)

    def test_private_archive_handoff_survives_shared_source_replacement(self):
        """A cache replacement after the first check cannot alter the handoff."""
        with tempfile.TemporaryDirectory(prefix="runtime-archive-handoff-") as temporary:
            root = Path(temporary)
            source = root / "cache" / "shared.tar.gz"
            destination = root / "build" / "verified" / "shared.tar.gz"
            source.parent.mkdir(parents=True)
            source.write_bytes(b"trusted-archive")
            expected = hashlib.sha256(b"trusted-archive").hexdigest()
            fake_bin = root / "bin"
            fake_bin.mkdir()
            fake_cp = fake_bin / "cp"
            fake_cp.write_text(
                "#!/bin/sh\n"
                "set -eu\n"
                "/bin/cp \"$@\"\n"
                "printf '%s' replaced-by-cache-writer > \"$RACE_SOURCE\"\n",
                encoding="utf-8",
            )
            fake_cp.chmod(0o755)
            script = textwrap.dedent(
                """
                set -eu
                . "$1/ci/lib/common.sh"
                . "$1/ci/lib/runtime-component-common.sh"
                CONNECTOR_COMPONENT_CACHE=$2/cache
                runtime_component_stage_verified_archive fixture "$5" "$3" "$4" "$2/build"
                """
            )
            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{fake_bin}{os.pathsep}{environment['PATH']}",
                    "RACE_SOURCE": str(source),
                    "PYTHONDONTWRITEBYTECODE": "1",
                }
            )
            result = subprocess.run(
                [
                    "sh", "-c", script, "sh", str(ROOT), str(root),
                    str(source), str(destination), expected,
                ],
                cwd=ROOT, text=True, capture_output=True, env=environment, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(destination.read_bytes(), b"trusted-archive")
            self.assertEqual(source.read_bytes(), b"replaced-by-cache-writer")

    def test_private_source_extract_and_binary_stage_accept_explicit_task_root(self):
        with tempfile.TemporaryDirectory(prefix="runtime-private-root-") as temporary:
            root = Path(temporary)
            archive = root / "cache" / "lighttpd.tar.gz"
            source = root / "payload" / "lighttpd-1.4.85" / "src" / "lighttpd"
            source.parent.mkdir(parents=True)
            source.write_bytes(b"private-source")
            archive.parent.mkdir(parents=True)
            with tarfile.open(archive, "w:gz") as tar:
                tar.add(source.parent.parent, arcname="lighttpd-1.4.85")
            script = textwrap.dedent(
                """
                set -eu
                . "$1/ci/lib/common.sh"
                . "$1/ci/lib/runtime-component-common.sh"
                CONNECTOR_COMPONENT_CACHE=$2/cache
                private_root=$2/build/private
                source_dir=$(extract_runtime_source_tar lighttpd "$3" "$private_root/src" lighttpd-1.4.85 "$private_root")
                mkdir -p "$private_root/bin"
                printf '%s' binary > "$private_root/bin/source-binary"
                chmod +x "$private_root/bin/source-binary"
                stage_executable_binary lighttpd "$private_root/bin/source-binary" "$private_root/bin/lighttpd" "$private_root"
                test -f "$source_dir/src/lighttpd"
                test -x "$private_root/bin/lighttpd"
                """
            )
            result = subprocess.run(
                ["sh", "-c", script, "sh", str(ROOT), str(root), str(archive)],
                cwd=ROOT, text=True, capture_output=True,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
