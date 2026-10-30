"""Regression coverage for the bounded NGINX Functional-A evidence writer."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import importlib.util
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml


ROOT = connector_root()
WRITER = source_path('ci/runtime/lifecycle/write-nginx-functional-a-evidence.py', root=ROOT)
PARENT_SHA = "a" * 40
NGINX_ARCHIVE_SHA256 = "b" * 64


def load_writer_module():
    module = load_source(WRITER)
    return module


WRITER_MODULE = load_writer_module()


class NginxFunctionalEvidenceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="nginx-functional-evidence-")
        self.root = Path(self.temporary.name)
        self.connector_root = self.root / "connector"
        self.connector_root.mkdir(mode=0o700)
        self.functional_root = self.root / "functional"
        self.functional_root.mkdir(mode=0o711)
        self.functional_root.chmod(0o711)
        self.evidence_root = self.root / "evidence"
        self.evidence_root.mkdir(mode=0o700)
        self.evidence_root.chmod(0o700)
        self.owner_uid = os.geteuid()
        self.owner_gid = os.getegid()
        self.identity = self._identity_bytes()
        (self.functional_root / "artifact-identity.start.sha256").write_bytes(self.identity)
        (self.functional_root / "artifact-identity.start.sha256").chmod(0o600)
        for mode in ("on", "off"):
            self._write_mode(mode)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _identity_bytes(self) -> bytes:
        return b"".join(
            f"{character * 64}  /private/input-{index}\n".encode("ascii")
            for index, character in enumerate("abcdef0", start=1)
        )

    def _write_private(self, path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(0o600)

    def _write_mode(self, mode: str) -> None:
        phase4 = self.functional_root / mode / "phase4"
        for phase in ("before", "after"):
            self._write_private(
                self.functional_root / mode / f"artifact-identity.{phase}.sha256",
                self.identity,
            )
        record = {
            "event_hash": 2,
            "previous_event_hash": 1,
            "redacted": True,
            "rule_id": "1100301",
            "sequence": 3,
            "transaction_id": f"transaction-{mode}",
            "truncated": False,
            "uri": "/no-crs/response-body?<redacted>",
        }
        jsonl = (json.dumps(record, sort_keys=True) + "\n").encode("utf-8")
        self._write_private(phase4 / "logs" / "phase4.log", jsonl)
        self._write_private(phase4 / "logs" / "phase4-before-usr1.log", jsonl)
        lifecycle = b"\n".join(WRITER_MODULE.LIFECYCLE_MARKERS.values()) + b"\n"
        self._write_private(phase4 / "logs" / "nginx-lifecycle.txt", lifecycle)
        self._write_private(phase4 / "logs" / "nginx-version.log", b"nginx version: nginx/1.31.6\n")
        self._write_private(
            self.functional_root / mode / "allow" / "logs" / "observed-status.txt",
            b"200\n",
        )
        server_logs = phase4 / "harness" / "server-logs" / "nginx_phase4_deny_after_commit_log_only"
        self._write_private(server_logs / "access.log", WRITER_MODULE.QUERY_CANARY + b"\n")
        error = b"1100301 callback\n" if mode == "on" else b"no callback marker\n"
        self._write_private(server_logs / "error.log", error)

    def collect(self, observed_head: str = PARENT_SHA) -> dict:
        original_lstat = Path.lstat

        def root_owned_functional_lstat(path: Path) -> os.stat_result:
            details = original_lstat(path)
            if path == self.functional_root:
                values = list(details)
                values[4] = 0
                return os.stat_result(values)
            return details

        with (
            mock.patch.object(WRITER_MODULE, "_resolve_exact_head", return_value=observed_head),
            mock.patch.object(Path, "lstat", new=root_owned_functional_lstat),
        ):
            return WRITER_MODULE.collect_evidence(
                self.connector_root,
                self.functional_root,
                PARENT_SHA,
                NGINX_ARCHIVE_SHA256,
            )

    def test_collects_only_bounded_sanitized_on_off_facts(self) -> None:
        document = self.collect()
        WRITER_MODULE.publish_one_shot(
            self.evidence_root,
            self.owner_uid,
            self.owner_gid,
            document,
        )
        result = self.evidence_root / "result.json"
        self.assertTrue(result.is_file())
        self.assertEqual(stat.S_IMODE(result.stat().st_mode), 0o600)
        raw = result.read_bytes()
        self.assertNotIn(WRITER_MODULE.QUERY_CANARY, raw)
        self.assertNotIn(str(self.functional_root).encode("utf-8"), raw)
        self.assertNotIn(b"transaction-on", raw)
        self.assertNotIn(b"/private/input-", raw)
        observed = json.loads(raw)
        self.assertEqual(observed["parent_sha"], PARENT_SHA)
        self.assertEqual(observed["nginx_version"], "1.31.6")
        self.assertEqual(observed["nginx_archive_sha256"], NGINX_ARCHIVE_SHA256)
        self.assertEqual(observed["status"], "PASS")
        self.assertEqual(set(observed["modes"]), {"on", "off"})
        self.assertTrue(observed["modes"]["on"]["callback_marker_observed"])
        self.assertFalse(observed["modes"]["off"]["callback_marker_observed"])
        for mode in ("on", "off"):
            self.assertTrue(observed["modes"][mode]["raw_waf_uri_observed"])
            self.assertEqual(observed["modes"][mode]["allow_control_status"], 200)
            self.assertTrue(observed["modes"][mode]["query_canary_absent_from_jsonl"])
            self.assertTrue(all(observed["modes"][mode]["lifecycle"].values()))

    def test_writer_version_matches_the_exact_head_workflow(self) -> None:
        workflow = yaml.safe_load(
            (source_path('.github/workflows/test-nginx-exact-head.yml', root=ROOT)).read_text(encoding="utf-8")
        )
        release = workflow["jobs"]["nginx-exact-head"]["env"]["NGINX_RELEASE_TAG"]
        self.assertEqual(release, "release-1.31.6")
        self.assertEqual(WRITER_MODULE.EXPECTED_NGINX_VERSION, release.removeprefix("release-"))

    def test_unreviewed_nginx_version_blocks_collection(self) -> None:
        for mode in ("on", "off"):
            for version in ("1.31.5", "1.31.7", "1.31.60", "1.31.6.1", "1.31.6-unreviewed"):
                with self.subTest(mode=mode, version=version):
                    self._write_mode("on")
                    self._write_mode("off")
                    target = self.functional_root / mode / "phase4" / "logs" / "nginx-version.log"
                    self._write_private(target, f"nginx version: nginx/{version}\n".encode("ascii"))
                    with self.assertRaisesRegex(WRITER_MODULE.EvidenceError, "did not use NGINX"):
                        self.collect()
                    self.assertFalse((self.evidence_root / "result.json").exists())

    def test_malformed_or_conflicting_version_readback_is_rejected(self) -> None:
        for payload in (
            b"prefix nginx/1.31.6\n",
            b"nginx version: nginx/1.31.6\nnginx version: nginx/1.31.5\n",
            b"nginx version: nginx/1.31.6\nnginx version: nginx/1.31.6\n",
        ):
            with self.subTest(payload=payload):
                self._write_mode("on")
                target = self.functional_root / "on" / "phase4" / "logs" / "nginx-version.log"
                self._write_private(target, payload)
                with self.assertRaisesRegex(WRITER_MODULE.EvidenceError, "did not use NGINX"):
                    self.collect()
                self.assertFalse((self.evidence_root / "result.json").exists())

    def test_verbose_nginx_readback_preserves_sanitized_evidence(self) -> None:
        # The harness records -V, which appends build metadata to the version.
        for metadata in (
            b"built by gcc 13.3.0 (Ubuntu)\nconfigure arguments: --with-compat\n",
            b"built by clang 20.1.0\nbuilt with OpenSSL 4.0.2"
            b" (running with OpenSSL 4.0.2)\nTLS SNI support enabled\n"
            b"configure arguments: --prefix=/private/build --with-http_ssl_module\n",
        ):
            with self.subTest(metadata=metadata):
                payload = b"nginx version: nginx/1.31.6\n" + metadata
                for mode in ("on", "off"):
                    target = self.functional_root / mode / "phase4" / "logs" / "nginx-version.log"
                    self._write_private(target, payload)
                document = self.collect()
                self.assertEqual(document["nginx_version"], "1.31.6")
                serialized = json.dumps(document).encode("utf-8")
                self.assertNotIn(metadata, serialized)
                self.assertNotIn(b"/private/build", serialized)

    def test_verbose_readback_rejects_invalid_version_and_metadata(self) -> None:
        valid = b"nginx version: nginx/1.31.6\n"
        metadata = b"built by gcc 13.3.0\nconfigure arguments: --with-compat\n"
        for payload in (
            metadata,
            metadata + valid,
            b"nginx version: nginx/1.31.60\n" + metadata,
            b"nginx version: nginx/1.31.6.1\n" + metadata,
            b"nginx version: nginx/1.31.7\n" + metadata,
            valid + metadata + valid,
            valid + metadata + b"nginx version: nginx/1.31.5\n",
            valid + metadata + b"unknown diagnostic\n",
            valid + b"built by gcc\x00forged\n",
            valid + b"configure arguments: --prefix=\x1b[31m/private\n",
        ):
            with self.subTest(payload=payload):
                for mode in ("on", "off"):
                    self._write_mode("on")
                    self._write_mode("off")
                    target = self.functional_root / mode / "phase4" / "logs" / "nginx-version.log"
                    self._write_private(target, payload)
                    with self.assertRaisesRegex(WRITER_MODULE.EvidenceError, "did not use NGINX"):
                        self.collect()
                    self.assertFalse((self.evidence_root / "result.json").exists())

    def test_canary_in_jsonl_blocks_publication(self) -> None:
        jsonl = self.functional_root / "on" / "phase4" / "logs" / "phase4.log"
        jsonl.write_bytes(WRITER_MODULE.QUERY_CANARY + b"\n")
        jsonl.chmod(0o600)
        with self.assertRaisesRegex(WRITER_MODULE.EvidenceError, "contains the query canary"):
            self.collect()
        self.assertFalse((self.evidence_root / "result.json").exists())

    def test_inconsistent_identity_blocks_publication(self) -> None:
        target = self.functional_root / "off" / "artifact-identity.after.sha256"
        target.write_bytes(b"b" * 64 + b"  /private/tampered\n")
        target.chmod(0o600)
        with self.assertRaisesRegex(WRITER_MODULE.EvidenceError, "identities are inconsistent"):
            self.collect()
        self.assertFalse((self.evidence_root / "result.json").exists())

    def test_existing_result_is_not_overwritten(self) -> None:
        result = self.evidence_root / "result.json"
        result.write_text("stale\n", encoding="utf-8")
        result.chmod(0o600)
        document = self.collect()
        with self.assertRaisesRegex(WRITER_MODULE.EvidenceError, "already exists"):
            WRITER_MODULE.publish_one_shot(
                self.evidence_root,
                self.owner_uid,
                self.owner_gid,
                document,
            )
        self.assertEqual(result.read_text(encoding="utf-8"), "stale\n")

    def test_fsync_failure_leaves_no_result_or_temporary_file(self) -> None:
        document = self.collect()
        with mock.patch.object(WRITER_MODULE.os, "fsync", side_effect=OSError("injected fsync failure")):
            with self.assertRaisesRegex(OSError, "injected fsync failure"):
                WRITER_MODULE.publish_one_shot(
                    self.evidence_root,
                    self.owner_uid,
                    self.owner_gid,
                    document,
                )
        self.assertFalse((self.evidence_root / "result.json").exists())
        self.assertEqual(list(self.evidence_root.iterdir()), [])

    def test_wrong_exact_head_blocks_publication(self) -> None:
        with self.assertRaisesRegex(WRITER_MODULE.EvidenceError, "does not match"):
            self.collect(observed_head="b" * 40)
        self.assertFalse((self.evidence_root / "result.json").exists())



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
