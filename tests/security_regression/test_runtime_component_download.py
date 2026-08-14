from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[2]
HAPROXY_PREPARER = ROOT / "ci/provisioning/prepare-haproxy-runtime.sh"
APACHE_PREPARER = ROOT / "ci/provisioning/prepare-apache-build.sh"


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

    def test_apache_preparer_uses_shared_bounded_downloaders(self):
        source = APACHE_PREPARER.read_text(encoding="utf-8")
        self.assertIn('"$CI_ROOT/lib/runtime-component-common.sh"', source)
        self.assertIn("download_runtime_artifact_under_root", source)
        self.assertIn("download_runtime_artifact_without_redirects_under_root", source)
        self.assertIn("verify_runtime_artifact_sha256", source)


if __name__ == "__main__":
    unittest.main()
