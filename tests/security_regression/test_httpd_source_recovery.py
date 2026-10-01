"""Exercise Apache source recovery through real provenance/download helpers."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from tests.security_regression.common_version_fixture_support import write_common_fixture

ROOT = Path(__file__).resolve().parents[2]
PREPARER = ROOT / "ci/provisioning/prepare-apache-build.sh"
PAYLOAD = b"reviewed HTTPD test archive\n"
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()
ARCHIVE_NAME = "httpd-2.4.999.tar.bz2"
SOURCE_URL = f"https://downloads.apache.org/httpd/{ARCHIVE_NAME}"
BASELINE_COMMIT = "9181dc77dfb0685d87fa109e6800dc6052d77cc9"


class HttpdSourceRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="httpd-recovery-")
        self.root = Path(self.temporary.name)
        self.common = write_common_fixture(
            self.root / "fixture",
            (ROOT / "ci/lib/common.sh").read_text(),
            {"HTTPD_VERSION": "2.4.999", "HTTPD_SHA256": DIGEST},
        )
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.network = self.root / "network.txt"
        self.payload = self.root / "payload"
        self.payload.write_bytes(PAYLOAD)
        self.metadata = self.root / "metadata"
        self.metadata.write_text(DIGEST + "  httpd-test.tar.bz2\n")
        self.downloads = self.root / "build/downloads"
        self.downloads.mkdir(parents=True)
        self.archive = self.downloads / ARCHIVE_NAME
        curl = self.bin / "curl"
        curl.write_text("""#!/bin/sh
out=
previous=
for arg do
    if [ "$previous" = -o ]; then out=$arg; fi
    previous=$arg
    url=$arg
done
printf '%s\\n' "$url" >> "$NETWORK"
case "$url" in
    *.sha256)
        if [ "$METADATA_MODE" = unavailable ]; then
            printf '403|0|0|0.1\\n'; exit 22
        fi
        if [ -n "$SOURCE_REPLACEMENT" ] && [ "$url" = "$HTTPD_METADATA_URL" ]; then
            rm -f "$CACHE_ARCHIVE"
            ln -s "$SOURCE_REPLACEMENT" "$CACHE_ARCHIVE"
        fi
        cp "$METADATA" "$out"; printf '200|1|100|0.1\\n'; exit 0 ;;
    https://downloads.apache.org/apr/*) mode=200 ;;
    https://archive.apache.org/*) mode=$ALTERNATE_MODE ;;
    *) mode=$PRIMARY_MODE ;;
esac
case "$mode" in
    200) cp "$PAYLOAD" "$out"; printf '200|0|30|0.1\\n'; exit 0 ;;
    empty) : > "$out"; printf '200|0|0|0.1\\n'; exit 0 ;;
    timeout404) printf '404|0|0|0.1\\n'; exit 28 ;;
    tls404) printf '404|0|0|0.1\\n'; exit 60 ;;
    redirect404) printf '404|1|0|0.1\\n'; exit 22 ;;
    *) printf '%s|0|0|0.1\\n' "$mode"; exit 22 ;;
esac
""")
        curl.chmod(0o755)
        # Extract the function section only; retain real common/download/hash
        # collaborators, avoiding unrelated compiler/runtime bootstrap work.
        source = PREPARER.read_text()
        if os.environ.get("HTTPD_RECOVERY_BASELINE") == "1":
            source = subprocess.check_output(
                ["git", "show", f"{BASELINE_COMMIT}:ci/provisioning/prepare-apache-build.sh"],
                cwd=ROOT, text=True,
            )
        functions = source[source.index("blocked() {"):source.index("resolve_apache_tools() {")]
        self.functions = self.root / "functions.sh"
        self.functions.write_text(functions)

    def tearDown(self):
        self.temporary.cleanup()

    def run_helper(self, before="", *, primary="404", alternate="200", dest=None,
                   metadata=False, build=False, source_replacement=None,
                   metadata_mode="200"):
        env = os.environ.copy()
        for key in tuple(env):
            if key.startswith(("HTTPD_", "CI_ACTIVE_PIN_", "CI_INHERITED_")):
                env.pop(key)
        env.update({
            "PATH": f"{self.bin}:{env['PATH']}", "NETWORK": str(self.network),
            "PAYLOAD": str(self.payload), "METADATA": str(self.metadata),
            "PRIMARY_MODE": primary, "ALTERNATE_MODE": alternate,
            "BUILD_ROOT": str(self.root / "build"), "TMP_ROOT": str(self.root / "tmp"),
            "LOG_ROOT": str(self.root / "logs"), "VERIFIED_RUN_ROOT": str(self.root),
            "FRAMEWORK_ROOT": str(ROOT), "CONNECTOR_ROOT": str(ROOT),
            "COMMON_SH": str(self.common), "FUNCTIONS": str(self.functions),
            "DOWNLOAD_DIR": str(self.downloads), "APACHE_BUILD_ROOT": str(self.root / "build/apache"),
            "LOG_DIR": str(self.root / "logs"), "STATUS_FILE": str(self.root / "status"),
            "ARTIFACTS_FILE": str(self.root / "artifacts"), "DEST": str(dest or self.archive),
            "SOURCE_REPLACEMENT": str(source_replacement or ""),
            "CACHE_ARCHIVE": str(self.archive), "HTTPD_METADATA_URL": SOURCE_URL + ".sha256",
            "METADATA_MODE": metadata_mode,
        })
        # The legacy function call ensures both primary regressions fail on
        # the original implementation for its actual fresh-download defect.
        script = f'''. "$COMMON_SH"
. "{ROOT}/ci/lib/runtime-component-common.sh"
. "$FUNCTIONS"
mkdir -p "$LOG_DIR"
{before}
if command -v download_httpd_source_archive >/dev/null 2>&1; then
    download_httpd_source_archive "$DEST"
else
    download_file httpd "$HTTPD_SOURCE_URL" "$DEST"
fi
'''
        if metadata:
            script += 'verify_sha256_url httpd "$DEST" "$HTTPD_SHA256_URL"\necho extraction-permitted\n'
        if build:
            # Keep the production HTTPD download/metadata/private staging
            # chain. Unrelated compilers and APR dependencies are boundary
            # fakes; stop at the first real HTTPD extraction invocation.
            script = script[:script.index('if command -v download_httpd_source_archive')]
            script += '''
HTTPD_BUILD_DIR="$APACHE_BUILD_ROOT/httpd"
HTTPD_SOURCE_DIR="$APACHE_BUILD_ROOT/httpd-src"
HTTPD_PREFIX="$APACHE_BUILD_ROOT/httpd-prefix"
REFRESH=0
require_command() { :; }
require_c_header() { :; }
resolve_pcre_config() { :; }
verify_sha256_literal() { :; }
download_apr_util_file() { :; }
verify_required_apr_util_sha256() { :; }
verify_apr_util_sha256_url() { :; }
extract_tar_strip() {
    echo "extraction-permitted:$2"
    exit 0
}
build_httpd_from_source
'''
        return subprocess.run(["sh", "-eu", "-c", script], env=env, cwd=ROOT,
                              capture_output=True, text=True, timeout=15)

    def urls(self):
        return self.network.read_text().splitlines() if self.network.exists() else []

    def test_fresh_primary_404_recovers_identical_reviewed_release(self):
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual(self.archive.read_bytes(), PAYLOAD)
        self.assertEqual(self.urls(), [
            SOURCE_URL,
            f"https://archive.apache.org/dist/httpd/{ARCHIVE_NAME}",
        ])

    def test_verified_cache_survives_without_network(self):
        self.archive.write_bytes(PAYLOAD)
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual(self.archive.read_bytes(), PAYLOAD)
        self.assertEqual(self.urls(), [])
        self.assertIn("httpd_download_status=cached", (self.root / "artifacts").read_text())
        self.assertNotIn("httpd_download_url=", (self.root / "artifacts").read_text())

    def test_primary_success_does_not_use_archive(self):
        result = self.run_helper(primary="200")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.urls()), 1)
        self.assertIn("httpd_download_url=https://downloads.apache.org/", (self.root / "artifacts").read_text())

    def test_only_direct_http_404_from_curl_22_permits_recovery(self):
        for mode in ("403", "500", "timeout404", "tls404", "redirect404", "empty"):
            with self.subTest(mode=mode):
                self.network.unlink(missing_ok=True)
                result = self.run_helper(primary=mode)
                self.assertEqual(result.returncode, 77, result.stderr)
                self.assertEqual(len(self.urls()), 1)
                self.assertFalse(self.archive.exists())

    def test_primary_stage_failure_never_reuses_stale_404_metrics(self):
        result = self.run_helper('RUNTIME_COMPONENT_HTTP_STATUS=404\nrc_curl_exit=22\nRUNTIME_DOWNLOAD_CONNECT_TIMEOUT=0')
        self.assertEqual(result.returncode, 77, result.stderr)
        self.assertEqual(self.urls(), [])

    def test_unreviewed_tuple_rejected_before_network_or_cache_mutation(self):
        overrides = ('HTTPD_SHA256=', 'HTTPD_SHA256=bad', 'HTTPD_SHA256=' + 'b' * 64,
                     f'HTTPD_SOURCE_URL=https://example.invalid/{ARCHIVE_NAME}',
                     'HTTPD_SHA256_URL=https://example.invalid/checksum',
                     'HTTPD_ARCHIVE_NAME=other.tar.bz2', 'HTTPD_VERSION=2.4.998')
        for override in overrides:
            with self.subTest(override=override):
                self.archive.write_bytes(PAYLOAD)
                result = self.run_helper(override)
                self.assertEqual(result.returncode, 77, result.stderr)
                self.assertEqual(self.archive.read_bytes(), PAYLOAD)
                self.assertEqual(self.urls(), [])

    def test_canonical_fixture_with_invalid_literal_is_rejected_before_io(self):
        for digest in ("", "bad", "g" * 64):
            with self.subTest(digest=digest):
                write_common_fixture(self.root / "fixture",
                    (ROOT / "ci/lib/common.sh").read_text(),
                    {"HTTPD_VERSION": "2.4.999", "HTTPD_SHA256": digest})
                self.archive.write_bytes(PAYLOAD)
                result = self.run_helper()
                self.assertEqual(result.returncode, 77, result.stderr)
                self.assertEqual(self.archive.read_bytes(), PAYLOAD)
                self.assertEqual(self.urls(), [])

    def test_wrong_or_empty_cached_archive_fails_without_download(self):
        for payload in (b"wrong", b""):
            with self.subTest(payload=payload):
                self.archive.write_bytes(payload)
                result = self.run_helper()
                self.assertEqual(result.returncode, 77, result.stderr)
                self.assertEqual(self.urls(), [])
                self.assertFalse(self.archive.exists())

    def test_symlink_directory_and_outside_destinations_rejected(self):
        outside = self.root / "outside" / ARCHIVE_NAME
        outside.parent.mkdir()
        outside.write_bytes(PAYLOAD)
        self.archive.symlink_to(outside)
        result = self.run_helper()
        self.assertEqual(result.returncode, 77, result.stderr)
        self.assertTrue(self.archive.is_symlink())
        self.assertEqual(outside.read_bytes(), PAYLOAD)
        self.archive.unlink()
        self.archive.mkdir()
        self.assertEqual(self.run_helper().returncode, 77)
        self.assertEqual(self.run_helper(dest=outside).returncode, 77)
        self.assertEqual(self.urls(), [])

    def test_failed_alternate_leaves_no_archive_or_temporary_files(self):
        for mode in ("500", "empty", "redirect404"):
            with self.subTest(mode=mode):
                self.network.unlink(missing_ok=True)
                result = self.run_helper(alternate=mode)
                self.assertEqual(result.returncode, 77, result.stderr)
                self.assertEqual(len(self.urls()), 2)
                self.assertEqual(list(self.downloads.iterdir()), [])

    def test_wrong_alternate_digest_fails_closed(self):
        self.payload.write_bytes(b"unreviewed archive")
        result = self.run_helper()
        self.assertEqual(result.returncode, 77, result.stderr)
        self.assertFalse(self.archive.exists())

    def test_wrong_primary_digest_does_not_try_alternate(self):
        self.payload.write_bytes(b"unreviewed primary archive")
        result = self.run_helper(primary="200")
        self.assertEqual(result.returncode, 77, result.stderr)
        self.assertEqual(self.urls(), [SOURCE_URL])
        self.assertFalse(self.archive.exists())

    def test_metadata_remains_required_even_for_cached_archive(self):
        self.archive.write_bytes(PAYLOAD)
        self.metadata.write_text('b' * 64 + "  httpd.tar.bz2\n")
        result = self.run_helper(build=True)
        self.assertEqual(result.returncode, 77, result.stderr)
        self.assertNotIn("extraction-permitted", result.stdout)
        self.assertEqual(self.urls(), [SOURCE_URL + ".sha256"])
        self.assertFalse((self.root / "build/apache/verified-archives").exists())

    def test_metadata_success_accepts_verified_cache(self):
        self.archive.write_bytes(PAYLOAD)
        result = self.run_helper(metadata=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("extraction-permitted", result.stdout)

    def test_missing_malformed_and_unavailable_metadata_cannot_reach_extraction(self):
        for contents, mode in (("", "200"), ("not-a-digest\n", "200"),
                               (DIGEST + "\n", "unavailable")):
            with self.subTest(contents=contents, mode=mode):
                self.archive.write_bytes(PAYLOAD)
                self.metadata.write_text(contents)
                result = self.run_helper(build=True, metadata_mode=mode)
                self.assertEqual(result.returncode, 77, result.stderr)
                self.assertNotIn("extraction-permitted", result.stdout)
                self.assertFalse((self.root / "build/apache/verified-archives" / ARCHIVE_NAME).exists())

    def test_actual_build_extracts_private_copy_only_after_metadata(self):
        self.archive.write_bytes(PAYLOAD)
        result = self.run_helper(build=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        private = self.root / "build/apache/verified-archives" / self.archive.name
        self.assertIn(f"extraction-permitted:{private}", result.stdout)
        self.assertEqual(private.read_bytes(), PAYLOAD)
        private.write_bytes(b"private changed")
        self.assertEqual(self.archive.read_bytes(), PAYLOAD)

    def test_cache_replaced_with_symlink_during_metadata_cannot_be_extracted(self):
        self.archive.write_bytes(PAYLOAD)
        replacement = self.root / "outside-archive"
        replacement.write_bytes(PAYLOAD)
        result = self.run_helper(build=True, source_replacement=replacement)
        self.assertEqual(result.returncode, 77, result.stderr)
        self.assertNotIn("extraction-permitted", result.stdout)
        self.assertEqual(replacement.read_bytes(), PAYLOAD)
        self.assertFalse((self.root / "build/apache/verified-archives" / ARCHIVE_NAME).exists())

    def test_build_consumes_private_verified_archive_before_extraction(self):
        source = PREPARER.read_text()
        build = source[source.index("build_httpd_from_source() {"):source.index("resolve_apache_tools() {")]
        self.assertIn('download_httpd_source_archive "$httpd_archive"', build)
        self.assertIn('httpd_archive=$(runtime_component_stage_verified_archive', build)
        self.assertLess(build.index("verify_sha256_url httpd"), build.index("extract_tar_strip httpd"))
        self.assertLess(build.index("verify_sha256_url httpd"), build.index("runtime_component_stage_verified_archive"))
        self.assertIn("download_apr_util_file apr-util", build)


if __name__ == "__main__":
    unittest.main()
