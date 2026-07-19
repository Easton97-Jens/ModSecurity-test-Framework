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


ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = ROOT / "tests" / "fixtures" / "pcre2-digest"
PREPARE_SCRIPT = ROOT / "ci" / "provisioning" / "prepare-apache-build.sh"


class Pcre2ArchiveDigestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads((FIXTURE_ROOT / "cases.json").read_text(encoding="utf-8"))
        cls.real_tar = shutil.which("tar")
        if cls.real_tar is None:
            raise unittest.SkipTest("tar is required for the isolated archive fixture")

    def _write_executable(self, path, content):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(content).lstrip(), encoding="utf-8")
        path.chmod(0o755)

    def _build_archive(self, workspace):
        archive = workspace / self.fixture["archive_file"]
        configure = (FIXTURE_ROOT / self.fixture["archive_root"] / "configure").read_bytes()
        info = tarfile.TarInfo(f"{self.fixture['archive_root']}/configure")
        info.mode = 0o755
        info.mtime = 0
        info.size = len(configure)
        with tarfile.open(archive, "w:bz2") as tar:
            tar.addfile(info, io.BytesIO(configure))
        return archive

    def _create_adapter_source(self, workspace):
        adapter = workspace / "apache-adapter"
        self._write_executable(adapter / "autogen.sh", """
            #!/bin/sh
            exit 0
        """)
        self._write_executable(adapter / "configure", """
            #!/bin/sh
            exit 0
        """)
        return adapter

    def _create_fake_tools(self, workspace):
        fake_bin = workspace / "fake-bin"
        self._write_executable(fake_bin / "curl", """
            #!/bin/sh
            set -eu
            output=
            url=
            while [ "$#" -gt 0 ]; do
                if [ "$1" = "-o" ]; then
                    output=$2
                    shift 2
                    continue
                fi
                url=$1
                shift
            done
            [ -n "$output" ]
            case "$url" in
                *.sha256|*.sha256sum)
                    printf '%s  fixture\n' "$FIXTURE_SHA256" > "$output"
                    ;;
                *)
                    cp "$PCRE2_FIXTURE_ARCHIVE" "$output"
                    ;;
            esac
        """)
        self._write_executable(fake_bin / "tar", """
            #!/bin/sh
            set -eu
            for argument in "$@"; do
                if [ "$argument" = "$PCRE2_ARCHIVE_PATH" ]; then
                    printf '%s\n' "$argument" >> "$PCRE2_TAR_LOG"
                fi
            done
            exec "$REAL_TAR" "$@"
        """)
        self._write_executable(fake_bin / "cc", """
            #!/bin/sh
            exit 0
        """)
        self._write_executable(fake_bin / "perl", """
            #!/bin/sh
            exit 0
        """)
        self._write_executable(fake_bin / "make", """
            #!/bin/sh
            set -eu
            if [ "${1:-}" = "install" ]; then
                mkdir -p "$PCRE2_PREFIX/bin" "$HTTPD_PREFIX/bin" "$FAKE_MODULE_DIR"
                printf '%s\n' '#!/bin/sh' 'exit 0' > "$PCRE2_PREFIX/bin/pcre2-config"
                printf '%s\n' '#!/bin/sh' 'exit 0' > "$HTTPD_PREFIX/bin/apxs"
                printf '%s\n' '#!/bin/sh' 'exit 0' > "$HTTPD_PREFIX/bin/httpd"
                chmod +x "$PCRE2_PREFIX/bin/pcre2-config" "$HTTPD_PREFIX/bin/apxs" "$HTTPD_PREFIX/bin/httpd"
            fi
            mkdir -p "$FAKE_MODULE_DIR"
            : > "$FAKE_MODULE_PATH"
            exit 0
        """)
        return fake_bin

    def _run_case(self, digest):
        temporary_root = os.environ.get("TEST_TMPDIR")
        with tempfile.TemporaryDirectory(dir=temporary_root) as temporary:
            workspace = Path(temporary)
            archive = self._build_archive(workspace)
            adapter = self._create_adapter_source(workspace)
            fake_bin = self._create_fake_tools(workspace)
            verified = workspace / "verified"
            build_root = verified / "build"
            shared_prefix = verified / "shared"
            (shared_prefix / "include" / "modsecurity").mkdir(parents=True)
            (shared_prefix / "include" / "modsecurity" / "modsecurity.h").write_text(
                "/* local fixture */\n", encoding="utf-8"
            )
            (shared_prefix / "lib").mkdir(parents=True)
            (shared_prefix / "lib" / "libmodsecurity.so").write_text("fixture\n", encoding="utf-8")
            v3_source = workspace / "v3-source"
            v3_source.mkdir()
            connector_root = workspace / "connector"
            connector_root.mkdir()
            module_path = verified / "apache-build" / "ModSecurity-apache" / "src" / ".libs" / "mod_security3.so"
            tar_log = workspace / "pcre2-tar.log"
            digest_value = hashlib.sha256(archive.read_bytes()).hexdigest()
            if digest is None:
                digest = digest_value
            environment = os.environ.copy()
            environment.update(
                {
                    "FRAMEWORK_ROOT": str(ROOT),
                    "CI_ROOT": str(ROOT / "ci"),
                    "CONNECTOR_ROOT": str(connector_root),
                    "VERIFIED_RUN_ROOT": str(verified),
                    "BUILD_ROOT": str(build_root),
                    "SOURCE_ROOT": str(verified / "sources"),
                    "TMP_ROOT": str(verified / "tmp"),
                    "LOG_ROOT": str(verified / "logs"),
                    "XDG_STATE_HOME": str(verified / "state"),
                    "APACHE_BUILD_ROOT": str(verified / "apache-build"),
                    "APACHE_BUILD_OWNER_ROOT": str(verified),
                    "APACHE_DOWNLOAD_DIR": str(verified / "downloads"),
                    "HTTPD_BUILD_DIR": str(verified / "httpd-build"),
                    "HTTPD_SOURCE_DIR": str(verified / "httpd-src"),
                    "HTTPD_PREFIX": str(verified / "httpd"),
                    "PCRE2_SOURCE_DIR": str(verified / "pcre2-src"),
                    "PCRE2_PREFIX": str(verified / "pcre2"),
                    "MODSECURITY_SHARED_PREFIX": str(shared_prefix),
                    "MODSECURITY_V3_SOURCE_DIR": str(v3_source),
                    "MODSECURITY_APACHE_SOURCE_DIR": str(adapter),
                    "BUILD_HTTPD_FROM_SOURCE": "1",
                    "BUILD_PCRE2_FROM_SOURCE": "1",
                    "AUTO_FETCH_SMOKE_SOURCES": "0",
                    "MAKE_JOBS": "1",
                    "PCRE2_SOURCE_URL": "https://fixture.invalid/pcre2.tar.bz2",
                    "PCRE2_SHA256": digest,
                    "PCRE2_SHA256_URL": "",
                    "HTTPD_SOURCE_URL": "https://fixture.invalid/httpd.tar.bz2",
                    "APR_SOURCE_URL": "https://fixture.invalid/apr.tar.bz2",
                    "APR_UTIL_SOURCE_URL": "https://fixture.invalid/apr-util.tar.bz2",
                    "HTTPD_SHA256": digest_value,
                    "APR_SHA256": digest_value,
                    "APR_UTIL_SHA256": digest_value,
                    "HTTPD_SHA256_URL": "https://fixture.invalid/httpd.sha256",
                    "APR_SHA256_URL": "https://fixture.invalid/apr.sha256",
                    "APR_UTIL_SHA256_URL": "https://fixture.invalid/apr-util.sha256",
                    "PCRE2_FIXTURE_ARCHIVE": str(archive),
                    "PCRE2_ARCHIVE_PATH": str(verified / "downloads" / self.fixture["archive_file"]),
                    "PCRE2_TAR_LOG": str(tar_log),
                    "FIXTURE_SHA256": digest_value,
                    "REAL_TAR": self.real_tar,
                    "FAKE_MODULE_PATH": str(module_path),
                    "FAKE_MODULE_DIR": str(module_path.parent),
                    "PATH": f"{fake_bin}:{environment['PATH']}",
                }
            )
            completed = subprocess.run(
                ["sh", str(PREPARE_SCRIPT)],
                cwd=workspace,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            log_contents = tar_log.read_text(encoding="utf-8") if tar_log.exists() else ""
            status_file = build_root / "logs" / "apache" / "status.txt"
            status_contents = status_file.read_text(encoding="utf-8") if status_file.exists() else ""
            pcre2_config_exists = (verified / "pcre2" / "bin" / "pcre2-config").is_file()
            return completed, log_contents, status_contents, pcre2_config_exists

    def test_invalid_digests_never_reach_pcre2_tar(self):
        for case, digest in self.fixture["negative_digests"].items():
            with self.subTest(case=case):
                completed, tar_log, status, _ = self._run_case(digest)
                self.assertEqual(77, completed.returncode, completed.stdout + completed.stderr)
                self.assertEqual("", tar_log)
                if case == "empty":
                    self.assertIn("missing required SHA256 digest for pcre2", status)
                elif case == "wrong":
                    self.assertIn("SHA256 mismatch for pcre2", status)
                elif case == "invalid":
                    self.assertEqual(64, len(digest))
                    self.assertIn("invalid SHA256 digest for pcre2", status)
                else:
                    self.assertIn("invalid SHA256 digest for pcre2", status)

    def test_matching_digest_reaches_pcre2_tar_after_verification(self):
        completed, tar_log, status, pcre2_config_exists = self._run_case(None)
        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
        self.assertEqual(1, len(tar_log.splitlines()))
        self.assertIn("pass: pcre2 sha256 verified", status)
        self.assertTrue(pcre2_config_exists)

    def test_pcre2_guard_precedes_extraction_without_url_fallback(self):
        script = PREPARE_SCRIPT.read_text(encoding="utf-8")
        build_start = script.index("build_pcre2_from_source()")
        build_end = script.index("resolve_pcre_config()", build_start)
        pcre2_build = script[build_start:build_end]
        self.assertLess(
            pcre2_build.index("verify_required_pcre2_sha256"),
            pcre2_build.index("extract_tar_strip pcre2"),
        )
        self.assertNotIn("verify_sha256_url pcre2", pcre2_build)


if __name__ == "__main__":
    unittest.main()
