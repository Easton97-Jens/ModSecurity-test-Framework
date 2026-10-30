"""Native context preparation fails before importing unverified host headers."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, source_path, load_source

import errno
import hashlib
import io
from pathlib import Path
import tarfile
import tempfile
import ssl
import urllib.error
import unittest
from unittest import mock


ROOT = connector_root()
NATIVE = load_source(source_path('ci/checks/analysis/prepare-sonar-native-context.py', root=ROOT))


class SonarNativeContextTests(unittest.TestCase):
    def test_contract_versions_remain_ascii_after_concise_regex_change(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            nginx = root / "framework/connector_suite/modsecurity_connector_ci/provisioning/components/prepare-runtime-components.py"
            haproxy = root / "connectors/haproxy/htx-overlay/version-contract.json"
            lighttpd = root / "connectors/lighttpd/lighttpd-version.contract"
            for path in (nginx, haproxy, lighttpd):
                path.parent.mkdir(parents=True, exist_ok=True)
            haproxy.write_text(
                '{"version":"3.2.25","source_url":"https://example.invalid/haproxy.tar.gz",'
                '"sha256":"' + "0" * 64 + '"}')
            lighttpd.write_text(
                "LIGHTTPD_VERSION=1.4.85\nLIGHTTPD_DOWNLOAD_URL=https://example.invalid/lighttpd.tar.gz\n"
                "LIGHTTPD_SHA256=" + "0" * 64 + "\nLIGHTTPD_PATCH_FILENAME=fixture.patch\n")
            for version, allowed in (("1.31.6", True), ("1.٣١.6", False), ("1.31.６", False)):
                pins = {
                    "NGINX_PINNED_VERSION_READBACK": "nginx/" + version,
                    "NGINX_PINNED_SOURCE_REPOSITORY": "https://example.invalid/nginx",
                    "NGINX_PINNED_RELEASE_TAG": "fixture",
                    "NGINX_PINNED_RELEASE_ASSET_NAME": "fixture.tar.gz",
                    "NGINX_PINNED_RELEASE_ASSET_SHA256": "0" * 64,
                }
                nginx.write_text("\n".join(f"{key} = {value!r}" for key, value in pins.items()))
                with self.subTest(version=version), mock.patch.object(NATIVE, "ROOT", root), \
                        mock.patch.object(NATIVE, "source_path", side_effect=lambda name, *, root: (
                            nginx if name == "ci/provisioning/components/prepare-runtime-components.py"
                            else root / name)):
                    if allowed:
                        self.assertEqual(NATIVE.contracts()["nginx"]["version"], version)
                    else:
                        with self.assertRaisesRegex(ValueError, "directory is invalid"):
                            NATIVE.contracts()

    def test_framework_modsecurity_identity_is_passive_and_complete(self) -> None:
        identity = (
            'MODSECURITY_V3_APPROVED_REPO_URL="https://github.com/owasp-modsecurity/ModSecurity.git"\n'
            'MODSECURITY_V3_APPROVED_COMMIT="1925753989ccce977cdaae417b55c9726c7cf02c"\n'
            'MODSECURITY_V3_RELEASE_TAG="v3.0.17"\n')
        self.assertEqual(NATIVE.modsecurity_contract(identity.encode())["version"], "3.0.17")
        invalid = (
            identity.replace("owasp-modsecurity/ModSecurity", "unapproved/source"),
            identity.replace("1925753989ccce977cdaae417b55c9726c7cf02c", "main"),
            identity.replace("v3.0.17", "v3.٠.17"),
            identity.replace("v3.0.17", "v3.0.$(touch sentinel)"),
            identity.replace('"v3.0.17"', 'str("v3.0.17")'),
            identity.replace('"v3.0.17"', '"unterminated'),
            identity + 'MODSECURITY_V3_RELEASE_TAG="v3.0.18"\n',
            identity.replace('MODSECURITY_V3_RELEASE_TAG="v3.0.17"\n', ""),
        )
        for value in invalid:
            encoded = value.encode()
            with self.subTest(value=value), self.assertRaises(ValueError):
                NATIVE.modsecurity_contract(encoded)

    def test_framework_gitlink_mismatch_is_rejected_before_network(self) -> None:
        unused = Path("/unused")
        with mock.patch.object(NATIVE, "load_framework_revision_pins", return_value={"framework_sha": "1" * 40}), \
                mock.patch.object(NATIVE, "git_output", return_value=b"160000 commit different\tframework\n"), \
                mock.patch.object(NATIVE, "pinned_git_repository") as network:
            with self.assertRaisesRegex(ValueError, "disagrees with the Parent gitlink"):
                NATIVE.framework_modsecurity_contract(unused, unused)
        network.assert_not_called()

    def test_bad_cached_checksum_cannot_reach_extraction(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "host.tar.gz"
            archive.write_bytes(b"unapproved replacement")
            item = {"url": "https://example.invalid/host.tar.gz", "sha256": "0" * 64}
            with mock.patch.object(NATIVE.urllib.request, "urlopen") as network:
                with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                    NATIVE.verified_archive(item, root, root)
            network.assert_not_called()
            self.assertEqual(sorted(p.name for p in root.iterdir()), ["host.tar.gz"])

    def test_verified_cached_archive_is_read_without_mutation_or_network(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "host.tar.gz"
            data = b"reviewed archive control"
            archive.write_bytes(data)
            item = {"url": "https://example.invalid/host.tar.gz", "sha256": hashlib.sha256(data).hexdigest()}
            with mock.patch.object(NATIVE.urllib.request, "urlopen") as network:
                selected = NATIVE.verified_archive(item, root / "unused", root)
            self.assertEqual(selected, archive)
            self.assertEqual(archive.read_bytes(), data)
            network.assert_not_called()

    @staticmethod
    def archive_response(data: bytes = b"reviewed archive control", *, url: str = "https://example.invalid/host.tar.gz"):
        response = io.BytesIO(data)
        response.geturl = lambda: url
        return response

    @staticmethod
    def archive_item() -> dict[str, str]:
        return {"url": "https://example.invalid/host.tar.gz",
                "sha256": hashlib.sha256(b"reviewed archive control").hexdigest()}

    def test_archive_transport_recovers_after_network_unreachable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.object(NATIVE.urllib.request, "urlopen", side_effect=[
                    urllib.error.URLError(OSError(errno.ENETUNREACH, "unreachable")),
                    self.archive_response()]) as network, \
                    mock.patch.object(NATIVE.time, "sleep") as delay, \
                    mock.patch.object(NATIVE.sys, "stderr", new_callable=io.StringIO) as diagnostic:
                archive = NATIVE.verified_archive(self.archive_item(), root, None)
            self.assertEqual(archive.read_bytes(), b"reviewed archive control")
            self.assertEqual(network.call_count, 2)
            delay.assert_called_once_with(1)
            self.assertIn('"errno": 101', diagnostic.getvalue())
            self.assertIn('"stage": "native-archive-download"', diagnostic.getvalue())

    def test_archive_transport_exhaustion_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            error = urllib.error.URLError(OSError(errno.ENETUNREACH, "secret-proxy-token"))
            with mock.patch.object(NATIVE.urllib.request, "urlopen", side_effect=error) as network, \
                    mock.patch.object(NATIVE.time, "sleep") as delay, \
                    mock.patch.object(NATIVE.sys, "stderr", new_callable=io.StringIO) as diagnostic:
                with self.assertRaises(urllib.error.URLError):
                    NATIVE.verified_archive(self.archive_item(), root, None)
            self.assertEqual(network.call_count, 3)
            self.assertEqual(delay.call_args_list, [mock.call(1), mock.call(2)])
            self.assertNotIn("secret-proxy-token", diagnostic.getvalue())
            self.assertEqual(list(root.iterdir()), [])

    def test_archive_transport_retries_partial_timeout_without_stale_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            broken = mock.MagicMock()
            broken.__enter__.return_value = broken
            broken.geturl.return_value = self.archive_item()["url"]
            broken.read.side_effect = [b"stale partial bytes", TimeoutError("read timed out")]
            with mock.patch.object(NATIVE.urllib.request, "urlopen", side_effect=[
                    broken, self.archive_response()]) as network, \
                    mock.patch.object(NATIVE.time, "sleep") as delay:
                archive = NATIVE.verified_archive(self.archive_item(), root, None)
            self.assertEqual(archive.read_bytes(), b"reviewed archive control")
            self.assertEqual(network.call_count, 2)
            delay.assert_called_once_with(1)

    def test_archive_transport_retries_temporary_http_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            error = urllib.error.HTTPError(self.archive_item()["url"], 503, "unavailable", {}, None)
            with mock.patch.object(NATIVE.urllib.request, "urlopen", side_effect=[
                    error, self.archive_response()]) as network, \
                    mock.patch.object(NATIVE.time, "sleep") as delay:
                archive = NATIVE.verified_archive(self.archive_item(), Path(temporary), None)
            self.assertEqual(archive.read_bytes(), b"reviewed archive control")
            self.assertEqual(network.call_count, 2)
            delay.assert_called_once_with(1)

    def test_archive_transport_does_not_retry_permanent_http_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            error = urllib.error.HTTPError(self.archive_item()["url"], 404, "not found", {}, None)
            with mock.patch.object(NATIVE.urllib.request, "urlopen", side_effect=error) as network, \
                    mock.patch.object(NATIVE.time, "sleep") as delay:
                with self.assertRaises(urllib.error.HTTPError):
                    NATIVE.verified_archive(self.archive_item(), Path(temporary), None)
            network.assert_called_once()
            delay.assert_not_called()
            self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_archive_transport_does_not_retry_tls_verification_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            error = urllib.error.URLError(ssl.SSLCertVerificationError("untrusted certificate"))
            with mock.patch.object(NATIVE.urllib.request, "urlopen", side_effect=error) as network, \
                    mock.patch.object(NATIVE.time, "sleep") as delay:
                with self.assertRaises(urllib.error.URLError):
                    NATIVE.verified_archive(self.archive_item(), Path(temporary), None)
            network.assert_called_once()
            delay.assert_not_called()
            self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_downloaded_checksum_failure_is_not_retried(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch.object(NATIVE.urllib.request, "urlopen", return_value=self.archive_response(b"wrong")) as network, \
                    mock.patch.object(NATIVE.time, "sleep") as delay:
                with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                    NATIVE.verified_archive(self.archive_item(), Path(temporary), None)
            network.assert_called_once()
            delay.assert_not_called()

    def test_download_redirect_cannot_downgrade_https(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch.object(NATIVE.urllib.request, "urlopen", return_value=self.archive_response(url="http://example.invalid/host.tar.gz")) as network, \
                    mock.patch.object(NATIVE.time, "sleep") as delay:
                with self.assertRaisesRegex(ValueError, "redirected away from HTTPS"):
                    NATIVE.verified_archive(self.archive_item(), Path(temporary), None)
            network.assert_called_once()
            delay.assert_not_called()
            self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_download_failure_preserves_preexisting_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "host.tar.gz"
            archive.write_bytes(b"preexisting sentinel")
            with mock.patch.object(NATIVE.urllib.request, "urlopen", return_value=self.archive_response()) as network, \
                    mock.patch.object(NATIVE.time, "sleep") as delay:
                with self.assertRaises(FileExistsError):
                    NATIVE.verified_archive(self.archive_item(), root, None)
            self.assertEqual(archive.read_bytes(), b"preexisting sentinel")
            network.assert_called_once()
            delay.assert_not_called()

    def test_archive_cannot_escape_its_expected_source_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "host.tar.gz"
            with tarfile.open(archive, "w:gz") as output:
                member = tarfile.TarInfo("host-1.2.3/../../outside")
                member.size = 8
                output.addfile(member, io.BytesIO(b"sentinel"))
            sources = root / "sources"
            sources.mkdir()
            with self.assertRaisesRegex(ValueError, "unexpected top-level"):
                NATIVE.unpack(archive, sources, "host-1.2.3")
            self.assertFalse((root / "outside").exists())

    def test_output_roots_reject_source_reuse_and_symlink_redirection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            existing = parent / "existing"
            existing.mkdir()
            (parent / "redirect").symlink_to(existing, target_is_directory=True)
            for candidate in ("/", str(source_path('context-output', root=ROOT)), str(existing), str(parent / "redirect/child")):
                with self.subTest(candidate=candidate):
                    with self.assertRaises(ValueError):
                        NATIVE.fresh_root(candidate)
            self.assertFalse((source_path('context-output', root=ROOT)).exists())
            self.assertFalse((existing / "child").exists())
            output = NATIVE.fresh_root(str(parent / "new-private-context"))
            self.assertTrue(output.is_dir())
            self.assertEqual(output.stat().st_mode & 0o777, 0o700)

    def test_output_root_rejects_shared_ancestor_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            shared = Path(temporary) / "shared"
            shared.mkdir(mode=0o777)
            shared.chmod(0o777)
            destination = shared / "new-context"
            with self.assertRaisesRegex(ValueError, "untrusted shared writes"):
                NATIVE.fresh_root(str(destination))
            self.assertFalse(destination.exists())
            self.assertEqual(shared.stat().st_mode & 0o777, 0o777)

    def test_required_generated_artifacts_must_be_regular_and_nonempty(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            header = root / "config.h"
            with self.assertRaisesRegex(ValueError, "missing or invalid"):
                NATIVE.required_files([header])
            header.touch()
            with self.assertRaisesRegex(ValueError, "missing or invalid"):
                NATIVE.required_files([header])
            header.write_bytes(b"fixture feature configuration")
            linked = root / "linked.h"
            linked.symlink_to(header)
            with self.assertRaisesRegex(ValueError, "missing or invalid"):
                NATIVE.required_files([linked])
            self.assertEqual(NATIVE.required_files([header]), {str(header): hashlib.sha256(header.read_bytes()).hexdigest()})

    def test_include_manifest_uses_only_existing_configured_host_directories(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "host"
            (source / "objs").mkdir(parents=True)
            (source / "src/core").mkdir(parents=True)
            (source / "objs/Makefile").write_text(
                "ALL_INCS = -I src/core \\\n\t-I objs \\\n\t-I /unrelated/build-context\n\nCFLAGS = -O\n")
            includes = NATIVE.nginx_includes(source)
            self.assertEqual(includes, [source / "src/core", source / "objs"])
            self.assertEqual(NATIVE.include_value(includes), f"{source}/src/core,{source}/objs")
            with self.assertRaisesRegex(ValueError, "must exist"):
                NATIVE.include_value(includes + [source / "missing"])
            bad = source / "comma,path"
            bad.mkdir()
            with self.assertRaisesRegex(ValueError, "unambiguous"):
                NATIVE.include_value([bad])

    def test_nginx_generated_includes_accept_joined_and_quoted_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("objs", "src/core", "src/with space"):
                (root / name).mkdir(parents=True)
            (root / "objs/Makefile").write_text(
                "ALL_INCS\t =\t-Isrc/core -I 'src/with space' \\\n\t-I objs\n")
            self.assertEqual(NATIVE.nginx_includes(root), [
                root / "src/core", root / "src/with space", root / "objs"])

    def test_nginx_generated_includes_do_not_backtrack_across_near_matches(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "objs").mkdir()
            (root / "objs/Makefile").write_text(
                "ALL_INCS" + " " * 65536 + "not-an-assignment\nALL_INCS = -I objs\n")
            self.assertEqual(NATIVE.nginx_includes(root), [root / "objs"])


# Parent discovery remains inventory-bound; only an explicit selected Master
# assessment may opt into the complete module without importing helpers eagerly.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)


if __name__ == "__main__":
    unittest.main()
