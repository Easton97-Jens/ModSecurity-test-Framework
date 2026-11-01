from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = connector_root()

components = load_source(source_path('ci/provisioning/components/prepare-runtime-components.py', root=ROOT))


class RuntimeComponentCacheIdentityTest(unittest.TestCase):
    def connector_plan(
        self,
        env: dict[str, str],
        archives: list[dict[str, str]],
        *,
        connector: str = "apache",
        modsecurity_build_id: str = "modsecurity-build",
    ) -> dict:
        with tempfile.TemporaryDirectory(prefix="connector-cache-identity-") as temporary:
            root = Path(temporary)
            connector_root = root / "connector"
            framework_root = root / "framework"
            cache_root = root / "cache"
            (connector_root / f"connectors/{connector}").mkdir(parents=True)
            (connector_root / "common/include").mkdir(parents=True)
            (connector_root / "common/src").mkdir(parents=True)
            (framework_root / "ci").mkdir(parents=True)
            (connector_root / f"connectors/{connector}/input.c").write_text("int x;\n", encoding="utf-8")
            (framework_root / f"ci/provisioning/prepare-{connector}-build.sh").parent.mkdir(parents=True, exist_ok=True)
            (framework_root / f"ci/provisioning/prepare-{connector}-build.sh").write_text("#!/bin/sh\n", encoding="utf-8")
            if connector == "nginx":
                (framework_root / "ci/lib/common.sh").parent.mkdir(parents=True, exist_ok=True)
                (framework_root / "ci/lib/common.sh").write_text("#!/bin/sh\n", encoding="utf-8")
            compiler = mock.patch.object(
                components,
                "compiler_identity",
                return_value={"cc": "/usr/bin/cc", "cc_version": "cc test", "cxx": "", "cxx_version": ""},
            )
            source_hash = mock.patch.object(components, "hash_input_paths", return_value="source-hash")
            with compiler, source_hash:
                return components.connector_plan(
                    connector_root,
                    framework_root,
                    cache_root,
                    env,
                    connector,
                    {"build_id": modsecurity_build_id, "prefix": "/cache/modsecurity"},
                    {"build_id": "expat-build", "prefix": "/cache/expat"},
                    archives,
                )

    def test_connector_id_changes_with_archive_content_hash(self) -> None:
        env = {"HTTPD_VERSION": "2.4.68"}
        first = self.connector_plan(env, [{"name": "httpd", "url": "https://example/httpd", "sha256": "a"}])
        second = self.connector_plan(env, [{"name": "httpd", "url": "https://example/httpd", "sha256": "b"}])
        self.assertNotEqual(first["connector_build_id"], second["connector_build_id"])

    def test_connector_id_changes_with_pcre2_digest(self) -> None:
        env = {
            "PCRE2_VERSION": "10.47",
            "PCRE2_SOURCE_URL": "https://example.invalid/pcre2-10.47.tar.bz2",
        }
        first = self.connector_plan(
            env,
            [{"name": "pcre2", "url": env["PCRE2_SOURCE_URL"], "expected_sha256": "a" * 64}],
        )
        second = self.connector_plan(
            env,
            [{"name": "pcre2", "url": env["PCRE2_SOURCE_URL"], "expected_sha256": "b" * 64}],
        )
        self.assertNotEqual(first["connector_build_id"], second["connector_build_id"])

    def test_connector_id_changes_with_apr_version(self) -> None:
        first = self.connector_plan({"APR_VERSION": "1.7.5"}, [])
        second = self.connector_plan({"APR_VERSION": "1.7.6"}, [])
        self.assertNotEqual(first["connector_build_id"], second["connector_build_id"])

    def test_nginx_protocol_profile_and_pinned_quic_tls_inputs_change_cache_identity(self) -> None:
        h1 = self.connector_plan({"NGINX_PROTOCOL_PROFILE": "h1"}, [], connector="nginx")
        h2 = self.connector_plan({"NGINX_PROTOCOL_PROFILE": "h1-h2"}, [], connector="nginx")
        h3 = self.connector_plan({"NGINX_PROTOCOL_PROFILE": "h1-h2-h3-quic"}, [], connector="nginx")
        changed_tls = self.connector_plan(
            {
                "NGINX_PROTOCOL_PROFILE": "h1-h2-h3-quic",
                "NGINX_QUIC_TLS_SOURCE_SHA256": "f" * 64,
            },
            [],
            connector="nginx",
        )

        self.assertNotEqual(h1["cache_key"], h2["cache_key"])
        self.assertNotEqual(h2["cache_key"], h3["cache_key"])
        self.assertNotEqual(h3["cache_key"], changed_tls["cache_key"])
        self.assertEqual(
            h3["cache_identity"]["configuration_flags"]["NGINX_PROTOCOL_CONFIGURE_FLAGS"],
            "--with-http_ssl_module --with-http_v2_module --with-http_v3_module",
        )
        self.assertEqual(h3["nginx_protocol_build"]["tls_library"], "openssl")

    def test_nginx_pinned_release_tuple_changes_archive_cache_identity(self) -> None:
        provenance = components.nginx_pinned_provenance(
            {
                "NGINX_SOURCE_MODE": "github-release",
                "NGINX_SOURCE_REPO_URL": "https://github.com/nginx/nginx",
                "NGINX_RELEASE_TAG": "release-1.31.6",
                "NGINX_SOURCE_GIT_REF": "release-1.31.6",
                "NGINX_RELEASE_ASSET_NAME": "nginx-1.31.6.tar.gz",
                "NGINX_SHA256": "974ed5298a5e398e008704ed5db284e655fc270c596493dbccada452448fc9f1",
            }
        )
        baseline = components.nginx_pinned_archive_cache_identity(provenance)

        self.assertEqual(
            baseline["source_tuple"],
            {
                "mode": "github-release",
                "repo": "https://github.com/nginx/nginx",
                "tag": "release-1.31.6",
                "ref": "release-1.31.6",
                "asset": "nginx-1.31.6.tar.gz",
                "sha256": "974ed5298a5e398e008704ed5db284e655fc270c596493dbccada452448fc9f1",
            },
        )

        for field, changed_value in {
            "mode": "github-release-other",
            "repository": "https://github.com/example/nginx",
            "release_tag": "release-1.31.2",
            "source_ref": "release-1.31.2",
            "release_asset_name": "nginx-1.31.2.tar.gz",
            "sha256": "0" * 64,
        }.items():
            with self.subTest(field=field):
                changed = dict(provenance)
                changed[field] = changed_value
                self.assertNotEqual(
                    baseline["cache_key"],
                    components.nginx_pinned_archive_cache_identity(changed)["cache_key"],
                )

    def test_expat_reuse_requires_full_build_identity(self) -> None:
        with tempfile.TemporaryDirectory(prefix="expat-cache-identity-") as temporary:
            root = Path(temporary)
            cache = root / "cache"
            prefix = cache / "prefix/expat"
            (prefix / "include").mkdir(parents=True)
            (prefix / "lib").mkdir(parents=True)
            (prefix / "include/expat.h").write_text("/* expat */\n", encoding="utf-8")
            (prefix / "lib/libexpat.so").write_text("library\n", encoding="utf-8")
            components.write_json(
                prefix / "component-manifest.json",
                {"actual_head": "same-source", "build_id": "different-toolchain"},
            )
            source = root / "source"
            source.mkdir()
            with mock.patch.object(
                components,
                "compiler_identity",
                return_value={"cc": "/usr/bin/cc", "cc_version": "new compiler", "cxx": "", "cxx_version": ""},
            ):
                result = components.prepare_expat(
                    {"EXPAT_PREFIX": str(prefix), "EXPAT_BUILD_DIR": str(cache / "build/expat")},
                    cache,
                    root / "build",
                    {
                        "status": "present",
                        "actual_head": "same-source",
                        "path": str(source),
                        "submodule_status_clean": True,
                    },
                )
            self.assertNotEqual(result["status"], "present")

    def test_modsecurity_identity_uses_immutable_expat_identity_not_mutable_manifest_tree(self) -> None:
        """A completed Expat prefix must not churn the shared ModSecurity key.

        Expat stores its own component manifest under the installed prefix.
        That manifest is updated at publication time, so its byte count is
        deliberately not a ModSecurity dependency.  The Cache-v2 identity is
        the immutable invalidation boundary instead.
        """
        git_record = {
            "url": "https://example.invalid/modsecurity.git",
            "expected_ref": "v3",
            "actual_head": "modsecurity-source",
            "submodule_status": "clean-submodules",
        }
        expat = {
            "actual_head": "expat-source",
            "cache_key": "expat-cache-key",
            "prefix": "/cache/builds/expat/expat-cache-key/prefix",
            "tree": {"exists": True, "file_count": 17, "total_size": 100},
            "cache_identity": {
                "cache_schema_version": 2,
                "component": "expat",
                "source_sha256": "expat-source",
                "cache_key": "expat-cache-key",
            },
        }
        later_expat = dict(expat)
        later_expat["tree"] = {
            "exists": True,
            "file_count": 18,
            "total_size": 4096,
            "sha256_manifest": "component-manifest-was-written",
        }
        toolchain = {"cc": "cc", "cc_version": "cc test", "cxx": "c++", "cxx_version": "c++ test"}
        with mock.patch.object(components, "toolchain_identity", return_value=toolchain), mock.patch.object(
            components, "patchset_identity", return_value={"sha256": "patchset", "files": []}
        ):
            first = components.modsecurity_build_inputs({}, git_record, expat, ROOT)
            second = components.modsecurity_build_inputs({}, git_record, later_expat, ROOT)

        self.assertEqual(first["dependency_hash"], second["dependency_hash"])
        self.assertEqual(first["cache_key"], second["cache_key"])

        changed_expat = dict(expat)
        changed_expat["cache_identity"] = {
            **expat["cache_identity"],
            "source_sha256": "changed-expat-source",
            "cache_key": "changed-expat-cache-key",
        }
        with mock.patch.object(components, "toolchain_identity", return_value=toolchain), mock.patch.object(
            components, "patchset_identity", return_value={"sha256": "patchset", "files": []}
        ):
            changed = components.modsecurity_build_inputs({}, git_record, changed_expat, ROOT)
        self.assertNotEqual(first["cache_key"], changed["cache_key"])


    def _upgrade_modsecurity_inputs(self, record, env=None):
        expat = {
            "actual_head": "expat-source", "prefix": "/cache/expat",
            "cache_key": "expat-key",
            "cache_identity": {"cache_key": "expat-key", "source_sha256": "expat-source"},
        }
        with mock.patch.object(components, "toolchain_identity", return_value={"cc": "cc"}), \
             mock.patch.object(components, "patchset_identity", return_value={"sha256": "patchset", "files": []}):
            return components.modsecurity_build_inputs(env or {}, record, expat, ROOT)

    def test_modsecurity_upgrade_changes_source_submodule_and_flag_cache_identity(self) -> None:
        record = {
            "url": "https://github.com/owasp-modsecurity/ModSecurity.git",
            "expected_ref": "fixture-release", "actual_head": "a" * 40,
            "submodule_status": "fixture-submodules-a",
        }
        baseline = self._upgrade_modsecurity_inputs(record)
        for field, value in (("actual_head", "b" * 40),
                             ("expected_ref", "fixture-next-release"),
                             ("submodule_status", "fixture-submodules-b")):
            with self.subTest(field=field):
                changed = self._upgrade_modsecurity_inputs({**record, field: value})
                self.assertNotEqual(baseline["cache_key"], changed["cache_key"])
        changed_flags = self._upgrade_modsecurity_inputs(record, {"CXXFLAGS": "-O0"})
        self.assertNotEqual(baseline["cache_key"], changed_flags["cache_key"])

    def test_connector_is_rebuilt_for_a_different_modsecurity_build(self) -> None:
        for connector in ("apache", "nginx"):
            with self.subTest(connector=connector):
                before = self.connector_plan({}, [], connector=connector)
                after = self.connector_plan({}, [], connector=connector,
                                            modsecurity_build_id="next-modsecurity-build")
                self.assertNotEqual(before["connector_build_id"], after["connector_build_id"])

    def test_modsecurity_runtime_aliases_allow_changed_v3_terminal_suffix(self) -> None:
        # Synthetic filenames, not a claim that a corresponding release exists.
        for suffix in ("0.16", "99.99"):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                terminal = root / f"libmodsecurity.so.3.{suffix}"
                terminal.write_bytes(b"fixture-library")
                terminal.chmod(0o644)
                (root / "libmodsecurity.so.3").symlink_to(terminal.name)
                (root / "libmodsecurity.so").symlink_to("libmodsecurity.so.3")
                descriptor, details = components._verified_modsecurity_runtime_library(root)
                try:
                    self.assertEqual(os.read(descriptor, 128), b"fixture-library")
                    self.assertEqual(details.st_ino, terminal.stat().st_ino)
                finally:
                    os.close(descriptor)

    def test_unreviewed_modsecurity_soname_is_not_silently_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            terminal = root / "libmodsecurity.so.4.0.0"
            terminal.write_bytes(b"unreviewed-layout")
            terminal.chmod(0o644)
            (root / "libmodsecurity.so.3").symlink_to(terminal.name)
            (root / "libmodsecurity.so").symlink_to("libmodsecurity.so.3")
            with self.assertRaisesRegex(RuntimeError, "terminal_name_invalid"):
                components._verified_modsecurity_runtime_library(root)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
