from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tarfile
import urllib.response
import unittest
from unittest import mock

from modsecurity_connector_tests.framework_test_trust import trusted_framework_root


ROOT = connector_root()
LEGACY_FRAMEWORK_HAPROXY_CACHE_SHA = "784977615acfc55567e37b863309abc4a38ac877"
PINNED_EXPAT_COMMIT = "c61098da494eea1cbd091118118dcee417faacea"
PINNED_NGINX_RELEASE_TUPLE = {
    "NGINX_SOURCE_MODE": "github-release",
    "NGINX_SOURCE_REPO_URL": "https://github.com/nginx/nginx",
    "NGINX_RELEASE_TAG": "release-1.31.6",
    "NGINX_SOURCE_GIT_REF": "release-1.31.6",
    "NGINX_RELEASE_ASSET_NAME": "nginx-1.31.6.tar.gz",
    "NGINX_SHA256": "974ed5298a5e398e008704ed5db284e655fc270c596493dbccada452448fc9f1",
}
PINNED_NGINX_RELEASE_ASSET_URL = (
    "https://github.com/nginx/nginx/releases/download/release-1.31.6/nginx-1.31.6.tar.gz"
)
TEST_HAPROXY_LOCKED_VERSION = "3.2.25"
TEST_HAPROXY_LOCKED_SOURCE_URL = "https://www.haproxy.org/download/3.2/src/haproxy-3.2.25.tar.gz"
TEST_HAPROXY_LOCKED_SHA256 = "d59a68d0daef7b5c596b019b742089788ff1748513ef96e71fe7b3943577866e"
TEST_HAPROXY_UNAPPROVED_FUTURE_VERSION = "3.2.9001"
TEST_HAPROXY_UNAPPROVED_FUTURE_SOURCE_URL = (
    "https://www.haproxy.org/download/3.2/src/haproxy-3.2.9001.tar.gz"
)
TEST_HAPROXY_UNAPPROVED_FUTURE_SHA256 = "b" * 64


def load_parent_prepare_runtime_components():
    """Load the migrated provisioner under its collision-free Framework name."""
    return load_source(source_path('ci/provisioning/components/prepare-runtime-components.py', root=ROOT))

components = load_parent_prepare_runtime_components()


class PrepareRuntimeComponentsTest(unittest.TestCase):
    def test_nginx_build_environment_preserves_canonical_non_h3_quic_pins(self) -> None:
        canonical_quic_tls = {
            "NGINX_QUIC_TLS_LIBRARY": "openssl",
            "NGINX_QUIC_TLS_VERSION": "4.0.1",
            "NGINX_QUIC_TLS_SOURCE_URL": (
                "https://github.com/openssl/openssl/releases/download/"
                "openssl-4.0.1/openssl-4.0.1.tar.gz"
            ),
            "NGINX_QUIC_TLS_SOURCE_SHA256": (
                "2db3f3a0d6ea4b59e1f094ace2c8cd536dffb87cdc39084c5afa1e6f7f37dd09"
            ),
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            context = {
                "nginx_build_root": root / "nginx-build",
                "nginx_prefix": root / "nginx",
                "local_nginx_bin": root / "nginx/sbin/nginx",
                "local_module": root / "nginx/modules/ngx_http_modsecurity_module.so",
            }

            def child_environment(
                base_env: dict[str, str],
                protocol_inputs: dict[str, object],
            ) -> dict[str, str]:
                return components.nginx_build_environment(
                    base_env,
                    components.NginxBuildEnvironmentInputs(
                        connector_root=root / "connector",
                        framework_root=root / "framework",
                        cache_root=root / "cache",
                        build_root=root / "work",
                        sources_root=root / "sources",
                        archives_root=root / "archives",
                        modsecurity={
                            "prefix": str(root / "modsecurity"),
                            "build_id": "modsecurity",
                        },
                        protocol_inputs=protocol_inputs,
                        protocol_profile=str(protocol_inputs["profile"]),
                        quic_tls_archive=str(root / "archives/nginx/openssl-4.0.1.tar.gz"),
                        common_build_source_root=root / "common-src",
                        profile_registry_build_root=root / "profile-registry",
                        context=context,
                    ),
                )

            for profile in ("h1", "h1-h2"):
                with self.subTest(profile=profile):
                    protocol_inputs = components.nginx_protocol_build_inputs(
                        {"NGINX_PROTOCOL_PROFILE": profile}
                    )
                    child_env = child_environment(
                        {
                            **canonical_quic_tls,
                            "MSCONNECTOR_PROFILE_REGISTRY_ROOT": "/untrusted/profile-registry",
                            "TAR_OPTIONS": "--same-owner",
                        },
                        protocol_inputs,
                    )
                    self.assertFalse(protocol_inputs["quic_enabled"])
                    self.assertEqual(
                        {key: child_env[key] for key in canonical_quic_tls},
                        canonical_quic_tls,
                    )
                    self.assertEqual(
                        child_env["MSCONNECTOR_PROFILE_REGISTRY_ROOT"],
                        str(root / "profile-registry"),
                    )
                    self.assertEqual(child_env["TAR_OPTIONS"], "--no-same-owner")

            h3_inputs = components.nginx_protocol_build_inputs(
                {"NGINX_PROTOCOL_PROFILE": "h1-h2-h3-quic", **canonical_quic_tls}
            )
            h3_child_env = child_environment(
                {
                    "NGINX_QUIC_TLS_LIBRARY": "hostile-library",
                    "NGINX_QUIC_TLS_VERSION": "0.0.0",
                    "NGINX_QUIC_TLS_SOURCE_URL": "https://example.invalid/hostile.tar.gz",
                    "NGINX_QUIC_TLS_SOURCE_SHA256": "f" * 64,
                    "MSCONNECTOR_PROFILE_REGISTRY_ROOT": "/untrusted/profile-registry",
                    "TAR_OPTIONS": "--same-owner",
                },
                h3_inputs,
            )
            self.assertTrue(h3_inputs["quic_enabled"])
            self.assertEqual(
                {key: h3_child_env[key] for key in canonical_quic_tls},
                canonical_quic_tls,
            )
            self.assertEqual(
                h3_child_env["MSCONNECTOR_PROFILE_REGISTRY_ROOT"],
                str(root / "profile-registry"),
            )
            self.assertEqual(h3_child_env["TAR_OPTIONS"], "--no-same-owner")

            protocol_cases = (
                ("h1", components.nginx_protocol_build_inputs({"NGINX_PROTOCOL_PROFILE": "h1"})),
                (
                    "h1-h2",
                    components.nginx_protocol_build_inputs(
                        {"NGINX_PROTOCOL_PROFILE": "h1-h2"}
                    ),
                ),
                ("h1-h2-h3-quic", h3_inputs),
            )
            for inherited_tar_options in (
                "--same-owner --warning=no-unknown-keyword",
                None,
            ):
                for profile, protocol_inputs in protocol_cases:
                    with self.subTest(
                        child_sink_profile=profile,
                        inherited_tar_options=inherited_tar_options,
                    ):
                        base_env = {}
                        if inherited_tar_options is not None:
                            base_env["TAR_OPTIONS"] = inherited_tar_options
                        completed = subprocess.CompletedProcess(
                            args=["prepare-nginx-build.sh"],
                            returncode=0,
                            stdout="",
                            stderr="",
                        )
                        record: dict[str, object] = {}
                        sink_context = {**context, "local_artifacts": {}}
                        with (
                            mock.patch.object(
                                components,
                                "copy_nginx_common_sources",
                                return_value=root / "common-src",
                            ),
                            mock.patch.object(
                                components,
                                "copy_nginx_profile_registry_sources",
                                return_value=root / "profile-registry",
                            ),
                            mock.patch.object(components, "run_build", return_value=completed) as run_build,
                            mock.patch.object(components, "nginx_refresh_build_artifacts"),
                            mock.patch.object(
                                components, "artifact_status", return_value=(True, [])
                            ),
                        ):
                            ready, missing, built = components.build_nginx_source(
                                base_env,
                                root / "connector",
                                root / "framework",
                                root / "cache",
                                root / "work",
                                root / "sources",
                                root / "archives",
                                {
                                    "prefix": str(root / "modsecurity"),
                                    "build_id": "modsecurity",
                                },
                                {},
                                protocol_inputs,
                                str(root / "archives/nginx/openssl-4.0.1.tar.gz"),
                                sink_context,
                                record,
                            )

                        self.assertTrue(ready)
                        self.assertEqual(missing, [])
                        self.assertTrue(built)
                        run_build.assert_called_once()
                        child_env = run_build.call_args.args[1]
                        self.assertEqual(child_env["TAR_OPTIONS"], "--no-same-owner")

    def test_nginx_staged_make_log_diagnostics_requires_current_managed_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache_root = root / "cache"
            components.ensure_managed_cache_root(cache_root)
            staging_root = cache_root / "builds/connectors/nginx/.capture"
            cache_key = "nginx-make-log-capture"
            components.mark_managed_cache_entry(
                staging_root,
                cache_root,
                component="connector:nginx",
                cache_key=cache_key,
            )
            staging_root.mkdir(parents=True)
            make_log = staging_root / components.NGINX_STAGED_MAKE_LOG_RELATIVE_PATH
            make_log.parent.mkdir(parents=True)
            make_log.write_text("compiler failure: missing symbol\n", encoding="utf-8")
            outer_log = root / "build/logs/runtime-components/nginx-build.log"
            outer_log.parent.mkdir(parents=True)
            outer_log.write_text("wrapper output\n", encoding="utf-8")
            plan = {
                "root": str(staging_root),
                "cache_key": cache_key,
                "build_root": str(staging_root / "build"),
            }
            context = {"nginx_build_root": staging_root / "build"}

            components.append_nginx_staged_make_log_diagnostics(
                outer_log,
                plan,
                cache_root,
                context,
            )
            captured = outer_log.read_text(encoding="utf-8")
            self.assertIn("inner_make_log_tail_truncated=false", captured)
            self.assertIn("compiler failure: missing symbol", captured)

            outer_log.write_text("", encoding="utf-8")
            make_log.unlink()
            components.append_nginx_staged_make_log_diagnostics(
                outer_log,
                plan,
                cache_root,
                context,
            )
            missing = outer_log.read_text(encoding="utf-8")
            self.assertIn("inner_make_log_unavailable=inner_make_log_missing", missing)

            outer_log.write_text("", encoding="utf-8")
            context["nginx_build_root"] = root / "outside"
            make_log.write_text("outside-build-root-canary\n", encoding="utf-8")
            components.append_nginx_staged_make_log_diagnostics(
                outer_log,
                plan,
                cache_root,
                context,
            )
            rejected = outer_log.read_text(encoding="utf-8")
            self.assertIn("inner_make_log_unavailable=staging_identity", rejected)
            self.assertNotIn("outside-build-root-canary", rejected)

            loop = root / "nginx-build-loop"
            loop.symlink_to(loop.name)
            context["nginx_build_root"] = loop
            outer_log.write_text("", encoding="utf-8")
            components.append_nginx_staged_make_log_diagnostics(
                outer_log,
                plan,
                cache_root,
                context,
            )
            loop_rejected = outer_log.read_text(encoding="utf-8")
            self.assertIn("inner_make_log_unavailable=staging_identity", loop_rejected)
            self.assertNotIn("outside-build-root-canary", loop_rejected)

    def test_nginx_staged_make_log_diagnostics_bounds_and_rejects_links(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache_root = root / "cache"
            components.ensure_managed_cache_root(cache_root)
            staging_root = cache_root / "builds/connectors/nginx/.capture"
            cache_key = "nginx-make-log-adversarial"
            components.mark_managed_cache_entry(
                staging_root,
                cache_root,
                component="connector:nginx",
                cache_key=cache_key,
            )
            staging_root.mkdir(parents=True)
            make_log = staging_root / components.NGINX_STAGED_MAKE_LOG_RELATIVE_PATH
            make_log.parent.mkdir(parents=True)
            make_log.write_bytes(
                b"discarded-line\n"
                + b"x" * (70 * 1024)
                + b"\n::warning:: \x1b[31mcompiler failure "
                + b"z" * 1024
                + b"\n"
            )
            outer_log = root / "build/logs/runtime-components/nginx-build.log"
            outer_log.parent.mkdir(parents=True)
            outer_log.write_text("wrapper output\n", encoding="utf-8")
            plan = {
                "root": str(staging_root),
                "cache_key": cache_key,
                "build_root": str(staging_root / "build"),
            }
            context = {"nginx_build_root": staging_root / "build"}

            components.append_nginx_staged_make_log_diagnostics(
                outer_log,
                plan,
                cache_root,
                context,
            )
            bounded = outer_log.read_text(encoding="utf-8")
            self.assertIn("inner_make_log_tail_truncated=true", bounded)
            self.assertIn(": :warning: : ?[31mcompiler failure", bounded)
            self.assertNotIn("\x1b", bounded)
            staged_log_lines = [
                line
                for line in bounded.splitlines()
                if line.startswith(components.NGINX_STAGED_MAKE_LOG_LINE_PREFIX)
            ]
            self.assertEqual(len(staged_log_lines), 1)
            self.assertEqual(len(staged_log_lines[0]), 512)

            outside = root / "outside"
            outside.write_text("outside-canary\n", encoding="utf-8")
            make_log.unlink()
            make_log.symlink_to(outside)
            outer_log.write_text("", encoding="utf-8")
            components.append_nginx_staged_make_log_diagnostics(
                outer_log,
                plan,
                cache_root,
                context,
            )
            symlink_rejected = outer_log.read_text(encoding="utf-8")
            self.assertIn("inner_make_log_unavailable=inner_make_log_symlink", symlink_rejected)
            self.assertNotIn("outside-canary", symlink_rejected)

            make_log.unlink()
            os.link(outside, make_log)
            outer_log.write_text("", encoding="utf-8")
            components.append_nginx_staged_make_log_diagnostics(
                outer_log,
                plan,
                cache_root,
                context,
            )
            hardlink_rejected = outer_log.read_text(encoding="utf-8")
            self.assertIn("inner_make_log_unavailable=inner_make_log_hardlink", hardlink_rejected)
            self.assertNotIn("outside-canary", hardlink_rejected)

    def test_nginx_failed_build_preserves_primary_result_after_diagnostic_append(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build_root = root / "build"
            cache_root = root / "cache"
            plan = {"cache_key": "nginx-primary-failure"}
            context = {"local_artifacts": {}}
            record: dict[str, object] = {}
            failed = subprocess.CompletedProcess(
                args=["prepare-nginx-build.sh"],
                returncode=2,
                stdout="src/module.c:1: error: missing symbol\n",
                stderr="",
            )

            with (
                mock.patch.object(components, "copy_nginx_common_sources", return_value=root / "common"),
                mock.patch.object(
                    components,
                    "copy_nginx_profile_registry_sources",
                    return_value=root / "profile-registry",
                ),
                mock.patch.object(components, "nginx_build_environment", return_value={}),
                mock.patch.object(components, "run_build", return_value=failed),
                mock.patch.object(components, "append_nginx_staged_make_log_diagnostics") as append,
                mock.patch.object(components, "nginx_refresh_build_artifacts"),
                mock.patch.object(
                    components,
                    "artifact_status",
                    return_value=(False, ["nginx_bin"]),
                ),
            ):
                ready, missing, built = components.build_nginx_source(
                    {},
                    root / "connector",
                    root / "framework",
                    cache_root,
                    build_root,
                    root / "sources",
                    root / "archives",
                    {},
                    plan,
                    {"profile": "h1"},
                    "",
                    context,
                    record,
                )

        self.assertFalse(ready)
        self.assertEqual(missing, ["nginx_bin"])
        self.assertFalse(built)
        self.assertEqual(record["build_exit_code"], 2)
        self.assertEqual(record["status"], "failed")
        self.assertEqual(record["blocker_reason"], "nginx_connector_build_failed")
        self.assertEqual(record["build_log"], str(build_root / "logs/runtime-components/nginx-build.log"))
        append.assert_called_once_with(
            build_root / "logs/runtime-components/nginx-build.log",
            plan,
            cache_root,
            context,
        )

    def test_nginx_common_source_staging_includes_required_private_header(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            connector_root = Path(temporary) / "connector"
            common_source_root = connector_root / "common" / "src"
            common_source_root.mkdir(parents=True)
            (common_source_root / "request_helpers.c").write_text(
                '#include "header_validation_internal.h"\n',
                encoding="utf-8",
            )
            (common_source_root / "header_validation_internal.h").write_text(
                "#pragma once\n",
                encoding="utf-8",
            )
            (common_source_root / "not-a-build-input.txt").write_text(
                "must not be staged\n",
                encoding="utf-8",
            )

            staged = components.copy_nginx_common_sources(
                connector_root,
                {"root": str(Path(temporary) / "build")},
            )

            self.assertEqual(
                (staged / "request_helpers.c").read_text(encoding="utf-8"),
                '#include "header_validation_internal.h"\n',
            )
            self.assertEqual(
                (staged / "header_validation_internal.h").read_text(encoding="utf-8"),
                "#pragma once\n",
            )
            self.assertFalse((staged / "not-a-build-input.txt").exists())

    def test_nginx_profile_registry_staging_is_regular_and_scoped(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            connector_root = Path(temporary) / "connector"
            registry_source_root = connector_root / "connectors"
            registry_source_root.mkdir(parents=True)
            (registry_source_root / "profile_registry.c").write_text(
                "const char *profile_registry(void) { return \"nginx\"; }\n",
                encoding="utf-8",
            )
            (registry_source_root / "profile_registry.h").write_text(
                "#pragma once\n",
                encoding="utf-8",
            )
            (registry_source_root / "unrelated.c").write_text("int unrelated;\n", encoding="utf-8")
            plan_root = Path(temporary) / "build"
            plan_root.mkdir()
            plan = {"root": str(plan_root)}

            staged = components.copy_nginx_profile_registry_sources(connector_root, plan)

            self.assertEqual(
                (staged / "connectors/profile_registry.c").read_text(encoding="utf-8"),
                "const char *profile_registry(void) { return \"nginx\"; }\n",
            )
            self.assertEqual(
                (staged / "connectors/profile_registry.h").read_text(encoding="utf-8"),
                "#pragma once\n",
            )
            self.assertFalse((staged / "connectors/unrelated.c").exists())

            (registry_source_root / "profile_registry.c").unlink()
            (registry_source_root / "profile_registry.c").symlink_to("profile_registry.h")
            with self.assertRaisesRegex(RuntimeError, "nginx_profile_registry_source_unsafe"):
                components.copy_nginx_profile_registry_sources(connector_root, plan)

    def test_nginx_profile_registry_staging_rejects_source_replacement_race(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            connector_root = Path(temporary) / "connector"
            registry_source_root = connector_root / "connectors"
            registry_source_root.mkdir(parents=True)
            source = registry_source_root / "profile_registry.c"
            source.write_text("const char *profile = \"trusted\";\n", encoding="utf-8")
            (registry_source_root / "profile_registry.h").write_text("#pragma once\n", encoding="utf-8")
            replacement = registry_source_root / "replacement.c"
            replacement.write_text("const char *profile = \"replacement\";\n", encoding="utf-8")
            plan_root = Path(temporary) / "build"
            plan_root.mkdir()
            original_open = components.os.open
            replaced = False

            def replace_source_before_open(
                path: object,
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                nonlocal replaced
                if not replaced and path == "profile_registry.c" and dir_fd is not None:
                    os.replace(replacement, source)
                    replaced = True
                return original_open(path, flags, mode, dir_fd=dir_fd)

            with mock.patch.object(components.os, "open", side_effect=replace_source_before_open):
                with self.assertRaisesRegex(RuntimeError, "nginx_profile_registry_source_changed"):
                    components.copy_nginx_profile_registry_sources(
                        connector_root,
                        {"root": str(plan_root)},
                    )

            self.assertTrue(replaced)
            self.assertEqual(source.read_text(encoding="utf-8"), "const char *profile = \"replacement\";\n")

    def test_nginx_profile_registry_staging_rejects_hardlinked_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            connector_root = Path(temporary) / "connector"
            registry_source_root = connector_root / "connectors"
            registry_source_root.mkdir(parents=True)
            source = registry_source_root / "profile_registry.c"
            source.write_text("const char *profile = \"nginx\";\n", encoding="utf-8")
            os.link(source, registry_source_root / "profile_registry.alias.c")
            (registry_source_root / "profile_registry.h").write_text("#pragma once\n", encoding="utf-8")
            plan_root = Path(temporary) / "build"
            plan_root.mkdir()

            with self.assertRaisesRegex(RuntimeError, "nginx_profile_registry_source_unsafe"):
                components.copy_nginx_profile_registry_sources(
                    connector_root,
                    {"root": str(plan_root)},
                )

            self.assertFalse((plan_root / "profile-registry/connectors/profile_registry.c").exists())

    def test_nginx_profile_registry_staging_rejects_destination_directory_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            connector_root = Path(temporary) / "connector"
            registry_source_root = connector_root / "connectors"
            registry_source_root.mkdir(parents=True)
            (registry_source_root / "profile_registry.c").write_text("const char *profile;\n", encoding="utf-8")
            (registry_source_root / "profile_registry.h").write_text("#pragma once\n", encoding="utf-8")
            plan_root = Path(temporary) / "build"
            plan_root.mkdir()
            outside = Path(temporary) / "outside"
            outside.mkdir()
            sentinel = outside / "sentinel"
            sentinel.write_text("outside\n", encoding="utf-8")
            (plan_root / "profile-registry").symlink_to(outside, target_is_directory=True)

            with self.assertRaisesRegex(
                RuntimeError,
                "nginx_profile_registry_destination_directory_unsafe",
            ):
                components.copy_nginx_profile_registry_sources(
                    connector_root,
                    {"root": str(plan_root)},
                )

            self.assertEqual(sentinel.read_text(encoding="utf-8"), "outside\n")
            self.assertFalse((outside / "connectors").exists())

    def test_nginx_profile_registry_staging_replaces_destination_file_symlink_atomically(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            connector_root = Path(temporary) / "connector"
            registry_source_root = connector_root / "connectors"
            registry_source_root.mkdir(parents=True)
            expected_source = "const char *profile = \"nginx\";\n"
            (registry_source_root / "profile_registry.c").write_text(expected_source, encoding="utf-8")
            (registry_source_root / "profile_registry.h").write_text("#pragma once\n", encoding="utf-8")
            plan_root = Path(temporary) / "build"
            staged_connectors = plan_root / "profile-registry/connectors"
            staged_connectors.mkdir(parents=True)
            outside = Path(temporary) / "outside-canary.c"
            outside.write_text("outside\n", encoding="utf-8")
            destination = staged_connectors / "profile_registry.c"
            destination.symlink_to(outside)

            components.copy_nginx_profile_registry_sources(
                connector_root,
                {"root": str(plan_root)},
            )

            self.assertFalse(destination.is_symlink())
            self.assertEqual(destination.read_text(encoding="utf-8"), expected_source)
            self.assertEqual(outside.read_text(encoding="utf-8"), "outside\n")
            self.assertFalse(any(path.name.endswith(".tmp") for path in staged_connectors.iterdir()))

    def test_nginx_profile_registry_staging_keeps_temporary_descriptor_for_close_failure_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            connector_root = Path(temporary) / "connector"
            registry_source_root = connector_root / "connectors"
            registry_source_root.mkdir(parents=True)
            (registry_source_root / "profile_registry.c").write_text(
                "const char *profile = \"nginx\";\n",
                encoding="utf-8",
            )
            (registry_source_root / "profile_registry.h").write_text(
                "#pragma once\n",
                encoding="utf-8",
            )
            plan_root = Path(temporary) / "build"
            plan_root.mkdir()
            staged_connectors = plan_root / "profile-registry/connectors"

            with mock.patch.object(
                components,
                "_close_nginx_profile_registry_temporary_descriptor",
                side_effect=RuntimeError("nginx_profile_registry_destination_write_failed"),
            ):
                with self.assertRaisesRegex(
                    RuntimeError,
                    "nginx_profile_registry_destination_write_failed",
                ):
                    components.copy_nginx_profile_registry_sources(
                        connector_root,
                        {"root": str(plan_root)},
                    )

            self.assertTrue(staged_connectors.is_dir())
            self.assertFalse(any(path.name.endswith(".tmp") for path in staged_connectors.iterdir()))

    def test_nginx_profile_registry_staging_rejects_destination_directory_replacement_race(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            connector_root = Path(temporary) / "connector"
            registry_source_root = connector_root / "connectors"
            registry_source_root.mkdir(parents=True)
            (registry_source_root / "profile_registry.c").write_text("const char *profile;\n", encoding="utf-8")
            (registry_source_root / "profile_registry.h").write_text("#pragma once\n", encoding="utf-8")
            plan_root = Path(temporary) / "build"
            plan_root.mkdir()
            outside = Path(temporary) / "outside"
            outside.mkdir()
            sentinel = outside / "sentinel"
            sentinel.write_text("outside\n", encoding="utf-8")
            original_open = components.os.open
            replaced = False

            def replace_destination_before_open(
                path: object,
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                nonlocal replaced
                staged_registry = plan_root / "profile-registry"
                if (
                    not replaced
                    and path == "connectors"
                    and dir_fd is not None
                    and staged_registry.is_dir()
                    and os.fstat(dir_fd).st_ino == staged_registry.stat().st_ino
                ):
                    staged_connectors = staged_registry / "connectors"
                    os.rmdir(staged_connectors)
                    staged_connectors.symlink_to(outside, target_is_directory=True)
                    replaced = True
                return original_open(path, flags, mode, dir_fd=dir_fd)

            with mock.patch.object(
                components.os,
                "open",
                side_effect=replace_destination_before_open,
            ):
                with self.assertRaisesRegex(
                    RuntimeError,
                    "nginx_profile_registry_destination_directory_unsafe",
                ):
                    components.copy_nginx_profile_registry_sources(
                        connector_root,
                        {"root": str(plan_root)},
                    )

            self.assertTrue(replaced)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "outside\n")
            self.assertFalse((outside / "profile_registry.c").exists())

    def test_nginx_profile_registry_inputs_change_source_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            connector_root = Path(temporary) / "connector"
            framework_root = Path(temporary) / "framework"
            (connector_root / "connectors/nginx").mkdir(parents=True)
            (connector_root / "common/include").mkdir(parents=True)
            (connector_root / "common/src").mkdir(parents=True)
            registry_root = connector_root / "connectors"
            (registry_root / "profile_registry.c").write_text("const char *profile = \"one\";\n", encoding="utf-8")
            (registry_root / "profile_registry.h").write_text("#pragma once\n", encoding="utf-8")

            source_paths = components.connector_input_paths(connector_root, framework_root, "nginx")
            baseline = components.hash_input_paths(source_paths)
            (registry_root / "profile_registry.c").write_text("const char *profile = \"two\";\n", encoding="utf-8")
            after_source_change = components.hash_input_paths(source_paths)
            (registry_root / "profile_registry.h").write_text("#define PROFILE_REGISTRY 1\n", encoding="utf-8")
            after_header_change = components.hash_input_paths(source_paths)

            self.assertNotEqual(baseline, after_source_change)
            self.assertNotEqual(after_source_change, after_header_change)

    def test_require_staging_path_rejects_absence_and_preserves_path(self) -> None:
        staging_path = Path("staging")

        self.assertEqual(staging_path, components.require_staging_path(staging_path))
        with self.assertRaisesRegex(RuntimeError, "staging cache entry is required"):
            components.require_staging_path(None)

    def test_require_full_immutable_git_commit_accepts_only_full_commit_ids(self) -> None:
        self.assertEqual(
            components.require_full_immutable_git_commit(PINNED_EXPAT_COMMIT, "EXPAT_GIT_REF"),
            PINNED_EXPAT_COMMIT,
        )
        sha256_commit = "A" * 64
        self.assertEqual(
            components.require_full_immutable_git_commit(sha256_commit, "EXPAT_GIT_REF"),
            sha256_commit,
        )
        for mutable_or_abbreviated_ref in (
            "master",
            "R_2_8_2",
            "refs/tags/R_2_8_2",
            "c61098d",
            "a" * 41,
            "b" * 63,
        ):
            with self.subTest(ref=mutable_or_abbreviated_ref):
                with self.assertRaisesRegex(RuntimeError, "full immutable Git commit ID"):
                    components.require_full_immutable_git_commit(
                        mutable_or_abbreviated_ref,
                        "EXPAT_GIT_REF",
                    )

    def test_github_repo_url_config_preserves_canonical_and_rejection_policy(self) -> None:
        github = "https://github.com"
        repo = "owner/repo"
        canonical = f"{github}/{repo}"

        self.assertEqual(
            components.require_https_github_repo_url(f" {canonical}.git "),
            canonical,
        )
        components.validate_https_url_config({"CRS_REPO_URL": canonical})

        for invalid_url in (
            f"http://github.com/{repo}",
            f"https://example.invalid/{repo}",
            f"{github}:443/{repo}",
            f"{canonical}?ref=main",
            f"{canonical}#release",
            f"{github}/owner",
            f"{canonical}/extra",
        ):
            with self.subTest(url=invalid_url):
                with self.assertRaises(RuntimeError):
                    components.validate_https_url_config({"CRS_REPO_URL": invalid_url})

        unused_nginx_urls = {
            "CRS_REPO_URL": canonical,
            "NGINX_SOURCE_REPO_URL": f"http://github.com/{repo}",
            "NGINX_QUIC_TLS_SOURCE_URL": "http://example.invalid/quic.tar.gz",
        }
        for target in ("shared", "apache", "haproxy"):
            with self.subTest(target=target):
                components.validate_https_url_config(unused_nginx_urls, target)
        for target in ("all", "nginx"):
            with self.subTest(nginx_target=target):
                with self.assertRaises(RuntimeError):
                    components.validate_https_url_config(unused_nginx_urls, target)

    def test_required_runtime_component_sources_scope_all_and_nginx_only_inputs(self) -> None:
        """Unrelated NGINX and optional-tool pins cannot block selected hosts."""

        non_nginx_env = {
            "EXPAT_SOURCE_URL": "https://github.com/libexpat/libexpat",
            "EXPAT_GIT_REF": PINNED_EXPAT_COMMIT,
            **PINNED_NGINX_RELEASE_TUPLE,
            "NGINX_RELEASE_TAG": "release-1.31.3",
            "NGINX_SOURCE_GIT_REF": "release-1.31.3",
        }
        all_env = {
            **non_nginx_env,
            "GO_FTW_SOURCE_URL": "https://github.com/example/go-ftw",
            "GO_FTW_PROMPT_EXPECTED_LATEST": "v1.0.0",
            "ALBEDO_SOURCE_URL": "https://github.com/example/albedo",
            "ALBEDO_PROMPT_EXPECTED_LATEST": "v1.0.0",
        }

        with (
            mock.patch.object(components, "validate_https_url_config"),
            mock.patch.object(components, "require_apr_util_pinned_provenance", return_value={}),
        ):
            for target_connector in ("shared", "apache", "haproxy"):
                with self.subTest(target_connector=target_connector):
                    values = components.required_runtime_component_sources(
                        non_nginx_env,
                        target_connector=target_connector,
                    )
                    self.assertEqual(values["expat_git_ref"], PINNED_EXPAT_COMMIT)
                    self.assertNotIn("nginx_pinned_provenance", values)
                    self.assertNotIn("go_ftw_source_url", values)
                    self.assertNotIn("albedo_source_url", values)

                    with self.assertRaisesRegex(RuntimeError, "full immutable Git commit ID"):
                        components.required_runtime_component_sources(
                            {
                                **non_nginx_env,
                                "EXPAT_GIT_REF": "master",
                            },
                            target_connector=target_connector,
                        )

            with self.assertRaisesRegex(RuntimeError, "nginx_pinned_provenance_ref_mismatch"):
                components.required_runtime_component_sources(
                    non_nginx_env,
                    target_connector="nginx",
                )
            with self.assertRaisesRegex(RuntimeError, "nginx_pinned_provenance_ref_mismatch"):
                components.required_runtime_component_sources(
                    all_env,
                    target_connector="all",
                )

        with (
            mock.patch.object(components, "validate_https_url_config"),
            mock.patch.object(components, "require_apr_util_pinned_provenance", return_value={}),
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "missing required runtime component config: GO_FTW_SOURCE_URL",
            ):
                components.required_runtime_component_sources(
                    {
                        "EXPAT_SOURCE_URL": "https://github.com/libexpat/libexpat",
                        "EXPAT_GIT_REF": PINNED_EXPAT_COMMIT,
                    },
                    target_connector="all",
                )

    def test_required_runtime_component_sources_keeps_global_url_guard_for_every_target(self) -> None:
        """Target scoping never bypasses the common source URL trust boundary."""

        for target_connector in ("shared", "apache", "haproxy", "nginx", "all"):
            with self.subTest(target_connector=target_connector):
                with mock.patch.object(
                    components,
                    "validate_https_url_config",
                    side_effect=RuntimeError("invalid_runtime_source_url"),
                ):
                    with self.assertRaisesRegex(RuntimeError, "invalid_runtime_source_url"):
                        components.required_runtime_component_sources(
                            {},
                            target_connector=target_connector,
                        )

    def test_pinned_nginx_release_tuple_uses_only_the_direct_release_asset(self) -> None:
        archive_root = Path("cache/archives")
        cache_root = Path("cache")
        prepared = {
            "name": "nginx",
            "url": PINNED_NGINX_RELEASE_ASSET_URL,
            "expected_sha256": PINNED_NGINX_RELEASE_TUPLE["NGINX_SHA256"],
            "status": "present",
            "checksum_status": "PASS",
        }
        with (
            mock.patch.object(components, "urlopen_bytes") as network,
            mock.patch.object(components, "prepare_archive", return_value=prepared) as prepare_archive,
        ):
            records = components.nginx_archive_records(
                dict(PINNED_NGINX_RELEASE_TUPLE),
                archive_root,
                cache_root,
            )

        network.assert_not_called()
        prepare_archive.assert_called_once()
        args, _kwargs = prepare_archive.call_args
        self.assertEqual(args[0], "nginx")
        self.assertEqual(args[1], PINNED_NGINX_RELEASE_ASSET_URL)
        self.assertEqual(args[2], PINNED_NGINX_RELEASE_TUPLE["NGINX_SHA256"])
        self.assertNotIn("/releases/latest", args[1])
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["status"], "present")
        self.assertEqual(records[0]["url"], PINNED_NGINX_RELEASE_ASSET_URL)
        self.assertEqual(records[0]["release_tag"], "release-1.31.6")
        self.assertEqual(records[0]["source_ref"], "release-1.31.6")
        self.assertEqual(records[0]["release_asset_name"], "nginx-1.31.6.tar.gz")
        self.assertEqual(
            records[0]["expected_sha256"],
            PINNED_NGINX_RELEASE_TUPLE["NGINX_SHA256"],
        )

    @staticmethod
    def httpd_fixture_archive() -> bytes:
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:bz2") as archive:
            content = b"approved HTTPD source\n"
            member = tarfile.TarInfo("httpd-2.4.68/README")
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
        return stream.getvalue()

    @staticmethod
    def httpd_transport(requested: list[str], responses: dict[str, object]):
        """Use the real urllib opener/redirect handlers with offline HTTPS I/O."""
        def transport(request):
            url = request.full_url
            requested.append(url)
            response = responses[url]
            if isinstance(response, BaseException):
                raise response
            if isinstance(response, tuple):
                code, headers, payload = response
            else:
                code, headers, payload = 200, {}, response
            result = urllib.response.addinfourl(io.BytesIO(payload), headers, url, code)
            result.msg = "fixture response"
            return result
        return transport

    def prepare_httpd_fixture(self, root: Path, expected_sha: str, *, url: str | None = None):
        source_url = url or "https://downloads.apache.org/httpd/httpd-2.4.68.tar.bz2"
        return components.prepare_archive(
            "httpd", source_url, expected_sha, source_url + ".sha256",
            root / "cache/archives/apache", root / "cache",
            required_literal_sha256=True,
            verify_digest_before_archive_list=True,
            allow_httpd_source_recovery=True,
        )

    def test_httpd_direct_404_recovers_verified_archive_with_canonical_cache_identity(self) -> None:
        source_url = "https://downloads.apache.org/httpd/httpd-2.4.68.tar.bz2"
        archived_url = "https://archive.apache.org/dist/httpd/httpd-2.4.68.tar.bz2"
        payload = self.httpd_fixture_archive()
        digest = hashlib.sha256(payload).hexdigest()
        requests: list[str] = []
        responses = {source_url: (404, {}, b"not found"), archived_url: payload}
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            with mock.patch.object(
                components.urllib.request.HTTPSHandler, "https_open",
                side_effect=self.httpd_transport(requests, responses),
            ), mock.patch.object(components, "expected_sha_from_url") as digest_lookup:
                record = self.prepare_httpd_fixture(root, digest)
            self.assertEqual(record["status"], "present", record)
            self.assertEqual(requests, [source_url, archived_url])
            self.assertEqual(record["url"], source_url)
            self.assertEqual(record["download_url"], archived_url)
            self.assertEqual(record["source_recovery"], "official_httpd_archive_after_direct_404")
            self.assertEqual(record["checksum_status"], "PASS")
            self.assertEqual(record["expected_sha256"], digest)
            expected_identity = components.archive_cache_identity("httpd", source_url, digest, source_url + ".sha256")
            marker = components.read_json(components.cache_entry_marker_path(Path(record["path"]), root / "cache"))
            self.assertEqual(marker["cache_key"], expected_identity["cache_key"])
            self.assertEqual(Path(record["path"]).read_bytes(), payload)
            digest_lookup.assert_not_called()
            with mock.patch.object(components.urllib.request.HTTPSHandler, "https_open") as network:
                cached = self.prepare_httpd_fixture(root, digest)
            self.assertEqual(cached["status"], "present", cached)
            marker_after = components.read_json(components.cache_entry_marker_path(Path(cached["path"]), root / "cache"))
            self.assertEqual(marker_after["cache_key"], expected_identity["cache_key"])
            network.assert_not_called()

    def test_httpd_recovery_rejects_redirects_non404_and_foreign404(self) -> None:
        source_url = "https://downloads.apache.org/httpd/httpd-2.4.68.tar.bz2"
        archived_url = "https://archive.apache.org/dist/httpd/httpd-2.4.68.tar.bz2"
        for label, response in (
            ("redirect", (302, {"Location": archived_url}, b"")),
            ("authentication", (403, {}, b"forbidden")),
            ("server error", (503, {}, b"unavailable")),
            ("timeout", TimeoutError("timeout")),
            ("foreign404", components.urllib.error.HTTPError("https://foreign.invalid/not-found", 404, "not found", {}, None)),
        ):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as raw:
                requested: list[str] = []
                with mock.patch.object(
                    components.urllib.request.HTTPSHandler, "https_open",
                    side_effect=self.httpd_transport(requested, {source_url: response}),
                ):
                    record = self.prepare_httpd_fixture(Path(raw), "a" * 64)
                self.assertEqual(record["status"], "blocked", record)
                self.assertEqual(requested, [source_url])
                self.assertNotIn("source_recovery", record)

    def test_httpd_recovery_rejects_archived_redirect_and_corruption_before_archive_listing(self) -> None:
        source_url = "https://downloads.apache.org/httpd/httpd-2.4.68.tar.bz2"
        archived_url = "https://archive.apache.org/dist/httpd/httpd-2.4.68.tar.bz2"
        payload = self.httpd_fixture_archive()
        digest = hashlib.sha256(payload).hexdigest()
        for label, response, expected_sha, expected_status, inspect_calls in (
            ("archive redirect", (302, {"Location": source_url}, b""), digest, "blocked", 0),
            ("archive auth", (403, {}, b""), digest, "blocked", 0),
            ("digest mismatch", payload + b"changed", digest, "corrupt", 0),
            ("corrupt tar", b"not a tar archive", hashlib.sha256(b"not a tar archive").hexdigest(), "corrupt", 1),
        ):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as raw:
                requested: list[str] = []
                with mock.patch.object(
                    components.urllib.request.HTTPSHandler, "https_open",
                    side_effect=self.httpd_transport(requested, {source_url: (404, {}, b""), archived_url: response}),
                ), mock.patch.object(components, "archive_can_list", wraps=components.archive_can_list) as inspect_archive:
                    record = self.prepare_httpd_fixture(Path(raw), expected_sha)
                self.assertEqual(record["status"], expected_status, record)
                self.assertEqual(requested, [source_url, archived_url])
                self.assertEqual(inspect_archive.call_count, inspect_calls)
                self.assertFalse(Path(record["path"]).exists())

    def test_httpd_recovery_rejects_noncanonical_or_unpinned_inputs_before_side_effects(self) -> None:
        source_url = "https://downloads.apache.org/httpd/httpd-2.4.68.tar.bz2"
        for url, digest in (
            ("https://archive.apache.org/dist/httpd/httpd-2.4.68.tar.bz2", "a" * 64),
            ("https://downloads.apache.org/httpd/httpd-2.4.68.tar.bz2?mirror=other", "a" * 64),
            ("https://foreign.invalid/httpd/httpd-2.4.68.tar.bz2", "a" * 64),
            ("https://downloads.apache.org/httpd/httpd-٢.4.68.tar.bz2", "a" * 64),
            ("https://downloads.apache.org/httpd/httpd-2.４.68.tar.bz2", "a" * 64),
            ("https://downloads.apache.org/httpd/httpd-2.4.６８.tar.bz2", "a" * 64),
            (source_url, ""), (source_url, "not-a-digest"),
        ):
            with self.subTest(url=url, digest=digest), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                with mock.patch.object(components.urllib.request.HTTPSHandler, "https_open") as network:
                    record = self.prepare_httpd_fixture(root, digest, url=url)
                self.assertEqual(record["status"], "blocked", record)
                network.assert_not_called()
                self.assertFalse((root / "cache").exists())

    def test_httpd_source_recovery_is_an_explicit_single_component_policy(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            with mock.patch.object(components, "prepare_archive", return_value={}) as prepare, mock.patch.object(
                components, "apr_util_archive_cache_identity", return_value={}
            ):
                components.apache_archive_records({}, root / "archives", root / "cache")
            calls = prepare.call_args_list
            self.assertEqual(calls[0].args[0], "httpd")
            self.assertTrue(calls[0].kwargs["allow_httpd_source_recovery"])
            self.assertTrue(calls[0].kwargs["required_literal_sha256"])
            self.assertTrue(calls[0].kwargs["verify_digest_before_archive_list"])
            self.assertTrue(all(not call.kwargs.get("allow_httpd_source_recovery") for call in calls[1:]))
            with mock.patch.object(components.urllib.request.HTTPSHandler, "https_open") as network:
                record = components.prepare_archive(
                    "apr", "https://downloads.apache.org/httpd/httpd-2.4.68.tar.bz2", "a" * 64, "",
                    root / "archives", required_literal_sha256=True,
                    verify_digest_before_archive_list=True, allow_httpd_source_recovery=True,
                )
            self.assertEqual(record["status"], "blocked", record)
            network.assert_not_called()

    def test_nginx_archive_records_reject_invalid_provenance_before_side_effects(self) -> None:
        invalid_cases: dict[str, dict[str, str]] = {
            "source_mode": {"NGINX_SOURCE_MODE": "git"},
            "missing_release_tag": {"NGINX_RELEASE_TAG": ""},
            "missing_source_ref": {"NGINX_SOURCE_GIT_REF": ""},
            "tag_latest": {"NGINX_RELEASE_TAG": "latest"},
            "ref_latest": {"NGINX_SOURCE_GIT_REF": "latest"},
            "missing_sha256": {"NGINX_SHA256": ""},
            "empty_sha256": {"NGINX_SHA256": ""},
            "whitespace_sha256": {"NGINX_SHA256": "   "},
            "malformed_sha256": {"NGINX_SHA256": "not-a-sha256"},
            "tag_ref_mismatch": {"NGINX_SOURCE_GIT_REF": "release-1.31.2"},
            "asset_mismatch": {"NGINX_RELEASE_ASSET_NAME": "nginx-1.31.2.tar.gz"},
            "wrong_repo": {"NGINX_SOURCE_REPO_URL": "https://github.com/example/nginx"},
            "github_repo_alias_mismatch": {"NGINX_GITHUB_REPO": "https://github.com/example/nginx"},
        }

        for name, overrides in invalid_cases.items():
            with self.subTest(case=name):
                env = dict(PINNED_NGINX_RELEASE_TUPLE)
                env.update(overrides)
                if name == "missing_release_tag":
                    env.pop("NGINX_RELEASE_TAG")
                if name == "missing_source_ref":
                    env.pop("NGINX_SOURCE_GIT_REF")
                if name == "missing_sha256":
                    env.pop("NGINX_SHA256")
                with (
                    mock.patch.object(components, "urlopen_bytes") as network,
                    mock.patch.object(components, "download") as download,
                    mock.patch.object(components, "prepare_archive") as prepare_archive,
                    mock.patch.object(components, "mark_managed_cache_entry") as mark_cache,
                    mock.patch.object(
                        components, "write_cache_entry_completion"
                    ) as complete_cache,
                    mock.patch.object(components, "archive_can_list") as inspect_archive,
                ):
                    records = components.nginx_archive_records(
                        env,
                        Path("cache/archives"),
                        Path("cache"),
                    )

                self.assertEqual(len(records), 1)
                self.assertEqual(records[0]["status"], "blocked")
                self.assertTrue(records[0]["blocker_reason"])
                network.assert_not_called()
                download.assert_not_called()
                prepare_archive.assert_not_called()
                mark_cache.assert_not_called()
                complete_cache.assert_not_called()
                inspect_archive.assert_not_called()

    def test_required_runtime_component_sources_scopes_nginx_preflight_to_nginx_targets(
        self,
    ) -> None:
        def required_source_value(_: dict[str, str], key: str) -> str:
            return PINNED_EXPAT_COMMIT if key == "EXPAT_GIT_REF" else "required-source"

        mismatched_nginx = dict(PINNED_NGINX_RELEASE_TUPLE)
        mismatched_nginx.update(
            {
                "NGINX_RELEASE_TAG": "release-1.31.3",
                "NGINX_SOURCE_GIT_REF": "release-1.31.3",
            }
        )
        with self.assertRaisesRegex(RuntimeError, "unsupported_runtime_component_target:unknown"):
            components.required_runtime_component_sources(
                {},
                target_connector="unknown",
            )
        for target in ("shared", "apache", "haproxy"):
            with self.subTest(target=target):
                with (
                    mock.patch.object(components, "validate_https_url_config"),
                    mock.patch.object(
                        components,
                        "require_apr_util_pinned_provenance",
                        return_value={"component": "apr-util"},
                    ),
                    mock.patch.object(components, "require_env_value", side_effect=required_source_value),
                    mock.patch.object(
                        components,
                        "nginx_protocol_build_inputs",
                        side_effect=AssertionError(
                            "non-NGINX target must not read NGINX protocol inputs"
                        ),
                    ) as nginx_protocol,
                ):
                    values = components.required_runtime_component_sources(
                        mismatched_nginx,
                        target_connector=target,
                    )

            self.assertNotIn("nginx_pinned_provenance", values)
            self.assertNotIn("nginx_require_pinned_provenance", values)
            nginx_protocol.assert_not_called()

        for target in ("all", "nginx"):
            with self.subTest(target=target):
                with (
                    mock.patch.object(components, "validate_https_url_config"),
                    mock.patch.object(
                        components,
                        "require_apr_util_pinned_provenance",
                        return_value={"component": "apr-util"},
                    ),
                    mock.patch.object(components, "require_env_value", side_effect=required_source_value),
                    mock.patch.object(components, "nginx_protocol_build_inputs") as nginx_protocol,
                ):
                    with self.assertRaisesRegex(RuntimeError, "nginx_pinned_provenance_ref_mismatch"):
                        components.required_runtime_component_sources(
                            mismatched_nginx,
                            target_connector=target,
                        )

            nginx_protocol.assert_not_called()

        for target in ("all", "nginx"):
            with self.subTest(protocol_target=target):
                with (
                    mock.patch.object(components, "validate_https_url_config"),
                    mock.patch.object(
                        components,
                        "require_apr_util_pinned_provenance",
                        return_value={"component": "apr-util"},
                    ),
                    mock.patch.object(components, "require_env_value", side_effect=required_source_value),
                    mock.patch.object(
                        components,
                        "nginx_protocol_build_inputs",
                        side_effect=RuntimeError("nginx_protocol_validation"),
                    ),
                ):
                    with self.assertRaisesRegex(RuntimeError, "nginx_protocol_validation"):
                        components.required_runtime_component_sources(
                            dict(PINNED_NGINX_RELEASE_TUPLE),
                            target_connector=target,
                        )

    def test_prepare_native_component_records_builds_nginx_plan_only_for_nginx_target(
        self,
    ) -> None:
        paths = {
            "sources_root": Path("cache/sources"),
            "archives_root": Path("cache/archives"),
        }
        for target, expects_nginx_plan in (
            ("shared", False),
            ("apache", False),
            ("haproxy", False),
            ("all", True),
            ("nginx", True),
        ):
            context = {
                "env": {},
                "cache_root": Path("cache"),
                "build_root": Path("build"),
                "connector_root": ROOT,
                "framework_root": ROOT,
                "target_connector": target,
            }
            with self.subTest(target=target):
                with (
                    mock.patch.object(components, "prepare_expat", return_value={"status": "present"}),
                    mock.patch.object(
                        components,
                        "prepare_shared_modsecurity",
                        return_value={"status": "present", "build_id": "modsecurity"},
                    ),
                    mock.patch.object(
                        components,
                        "connector_plan",
                        side_effect=lambda *args: {"connector": args[4]},
                    ) as connector_plan,
                    mock.patch.object(
                        components, "prepare_apache_httpd", return_value={"status": "present"}
                    ),
                    mock.patch.object(
                        components, "prepare_nginx_runtime", return_value={"status": "present"}
                    ),
                    mock.patch.object(
                        components, "prepare_haproxy_runtime", return_value={"status": "present"}
                    ),
                    mock.patch.object(components, "prepare_go_tool", return_value={"status": "present"}),
                ):
                    records = components.prepare_native_component_records(context, paths, [], [])

            planned_connectors = [call.args[4] for call in connector_plan.call_args_list]
            self.assertEqual("nginx" in planned_connectors, expects_nginx_plan)
            if expects_nginx_plan:
                self.assertEqual(records["nginx_plan"]["connector"], "nginx")
            else:
                self.assertEqual(records["nginx_plan"], {})

    def test_runtime_component_report_describes_immutable_expat_and_cache_fsck_accurately(self) -> None:
        report = components.markdown_report(
            {
                "generated_at": "2026-07-26T00:00:00Z",
                "cache_root": "/tmp/runtime-components",
                "git_components": [],
                "archives": [],
                "dependencies": [],
            }
        )

        self.assertIn(
            "go-ftw and albedo use release-tag resolution; Expat always uses its configured immutable commit.",
            report,
        )
        self.assertIn(
            "RUNTIME_COMPONENT_STRICT_VERIFY=1` requires a fresh-clone or prior-cache full git fsck PASS",
            report,
        )
        self.assertNotIn("go-ftw, albedo, and expat are prepared from explicit release-tag sources.", report)
        self.assertNotIn("forces full git fsck", report)

    def test_immutable_expat_rejects_mutable_ref_before_git_or_release_lookup(self) -> None:
        with (
            mock.patch.object(components, "prepare_git_component") as prepare_git,
            mock.patch.object(components, "resolve_latest_github_release_tag") as resolve_latest,
        ):
            record = components.prepare_immutable_git_component(
                "expat",
                "https://github.com/libexpat/libexpat",
                "master",
                Path("cache/git/libexpat"),
                {},
                strict=True,
            )

        self.assertEqual(record["status"], "blocked")
        self.assertIn("full immutable Git commit ID", record["blocker_reason"])
        self.assertFalse(record["immutable_commit_verified"])
        prepare_git.assert_not_called()
        resolve_latest.assert_not_called()

    def test_immutable_expat_uses_pinned_commit_without_latest_release_lookup(self) -> None:
        prepared_record = {
            "name": "expat",
            "url": "https://github.com/libexpat/libexpat",
            "expected_ref": PINNED_EXPAT_COMMIT,
            "actual_head": PINNED_EXPAT_COMMIT,
            "status": "present",
        }
        with (
            mock.patch.object(components, "prepare_git_component", return_value=prepared_record) as prepare_git,
            mock.patch.object(components, "resolve_latest_github_release_tag") as resolve_latest,
        ):
            record = components.prepare_immutable_git_component(
                "expat",
                "https://github.com/libexpat/libexpat",
                PINNED_EXPAT_COMMIT,
                Path("cache/git/libexpat"),
                {},
                strict=True,
            )

        prepare_git.assert_called_once_with(
            "expat",
            "https://github.com/libexpat/libexpat",
            PINNED_EXPAT_COMMIT,
            Path("cache/git/libexpat"),
            {},
            True,
            cache_root=None,
        )
        resolve_latest.assert_not_called()
        self.assertEqual(record["status"], "present")
        self.assertEqual(record["expected_ref"], PINNED_EXPAT_COMMIT)
        self.assertEqual(record["actual_head"], PINNED_EXPAT_COMMIT)
        self.assertTrue(record["immutable_commit_verified"])
        self.assertEqual(record["release_lookup_status"], "not_applicable_immutable_commit")

    def test_immutable_expat_blocks_checkout_record_for_a_different_commit(self) -> None:
        different_commit = "f" * 40
        with mock.patch.object(
            components,
            "prepare_git_component",
            return_value={
                "name": "expat",
                "url": "https://github.com/libexpat/libexpat",
                "expected_ref": PINNED_EXPAT_COMMIT,
                "actual_head": different_commit,
                "status": "present",
            },
        ):
            record = components.prepare_immutable_git_component(
                "expat",
                "https://github.com/libexpat/libexpat",
                PINNED_EXPAT_COMMIT,
                Path("cache/git/libexpat"),
                {},
                strict=True,
            )

        self.assertEqual(record["status"], "blocked")
        self.assertEqual(record["blocker_reason"], "immutable_git_checkout_record_mismatch")
        self.assertFalse(record["immutable_commit_verified"])

    def test_strict_expat_path_uses_only_the_immutable_component_preparer(self) -> None:
        with (
            mock.patch.object(
                components,
                "prepare_immutable_git_component",
                return_value={"status": "present", "immutable_commit_verified": True},
            ) as prepare_immutable,
            mock.patch.object(components, "prepare_release_git_component") as prepare_release,
        ):
            record = components.prepare_expat_git_component(
                "https://github.com/libexpat/libexpat",
                PINNED_EXPAT_COMMIT,
                Path("cache/git/libexpat"),
                {},
                strict=True,
            )

        prepare_immutable.assert_called_once_with(
            "expat",
            "https://github.com/libexpat/libexpat",
            PINNED_EXPAT_COMMIT,
            Path("cache/git/libexpat"),
            {},
            True,
            cache_root=None,
        )
        prepare_release.assert_not_called()
        self.assertTrue(record["immutable_commit_verified"])

    def test_non_strict_expat_path_uses_only_the_immutable_component_preparer(self) -> None:
        with (
            mock.patch.object(
                components,
                "prepare_immutable_git_component",
                return_value={"status": "present", "immutable_commit_verified": True},
            ) as prepare_immutable,
            mock.patch.object(components, "prepare_release_git_component") as prepare_release,
        ):
            record = components.prepare_expat_git_component(
                "https://github.com/libexpat/libexpat",
                PINNED_EXPAT_COMMIT,
                Path("cache/git/libexpat"),
                {},
                strict=False,
            )

        prepare_immutable.assert_called_once_with(
            "expat",
            "https://github.com/libexpat/libexpat",
            PINNED_EXPAT_COMMIT,
            Path("cache/git/libexpat"),
            {},
            False,
            cache_root=None,
        )
        prepare_release.assert_not_called()
        self.assertTrue(record["immutable_commit_verified"])

    def test_non_strict_expat_path_rejects_mutable_ref_before_git_or_release_lookup(self) -> None:
        with (
            mock.patch.object(components, "prepare_git_component") as prepare_git,
            mock.patch.object(components, "resolve_latest_github_release_tag") as resolve_latest,
        ):
            record = components.prepare_expat_git_component(
                "https://github.com/libexpat/libexpat",
                "master",
                Path("cache/git/libexpat"),
                {},
                strict=False,
            )

        self.assertEqual(record["status"], "blocked")
        self.assertIn("full immutable Git commit ID", record["blocker_reason"])
        prepare_git.assert_not_called()
        resolve_latest.assert_not_called()

    def test_optional_release_components_still_resolve_the_latest_release(self) -> None:
        for name in ("go-ftw", "albedo"):
            with self.subTest(component=name):
                prepared_record = {
                    "name": name,
                    "url": f"https://github.com/coreruleset/{name}",
                    "expected_ref": "v1.2.3",
                    "actual_head": PINNED_EXPAT_COMMIT,
                    "status": "present",
                }
                with (
                    mock.patch.object(
                        components,
                        "resolve_latest_github_release_tag",
                        return_value=("v1.2.3", "https://example.invalid/release", "network"),
                    ) as resolve_latest,
                    mock.patch.object(
                        components,
                        "prepare_git_component",
                        return_value=prepared_record,
                    ) as prepare_git,
                ):
                    record = components.prepare_release_git_component(
                        name,
                        f"https://github.com/coreruleset/{name}",
                        "v1.0.0",
                        Path(f"cache/git/{name}"),
                        {},
                        strict=True,
                        optional=True,
                    )

                resolve_latest.assert_called_once()
                prepare_git.assert_called_once_with(
                    name,
                    f"https://github.com/coreruleset/{name}",
                    "v1.2.3",
                    Path(f"cache/git/{name}"),
                    {},
                    True,
                    cache_root=None,
                )
                self.assertEqual(record["release_lookup_status"], "network")
                self.assertTrue(record["optional"])

    def test_apache_blocker_does_not_misclassify_expat_include_path(self) -> None:
        compiler_error = (
            "gcc -I/cache/builds/expat/cache-key/prefix/include -c src/msc_filters.c\n"
            "src/msc_filters.c:51:9: error: implicit declaration of function 'helper'\n"
        )

        self.assertEqual(
            components.map_apache_blocker(compiler_error, ["module_file:/cache/module.so"]),
            "apache_connector_build_failed",
        )

    def test_apache_blocker_detects_a_real_missing_expat_header(self) -> None:
        compiler_error = "src/parser.c:7:10: fatal error: expat.h: No such file or directory\n"

        self.assertEqual(
            components.map_apache_blocker(compiler_error, []),
            "missing_expat_headers",
        )

    def test_apache_blocker_keeps_profile_registry_compile_failure_distinct_from_libmodsecurity(self) -> None:
        compiler_error = (
            "gcc -L/cache/modsecurity/lib -lmodsecurity -c src/mod_security3.c\n"
            "src/mod_security3.c:14:10: fatal error: connectors/profile_registry.h: "
            "No such file or directory\n"
        )

        self.assertEqual(
            components.map_apache_blocker(compiler_error, []),
            "apache_connector_build_failed",
        )

    def test_apache_blocker_detects_a_real_missing_libmodsecurity_linker_error(self) -> None:
        compiler_error = "/usr/bin/ld: cannot find -lmodsecurity\n"

        self.assertEqual(
            components.map_apache_blocker(compiler_error, []),
            "missing_libmodsecurity_build",
        )

    def test_apache_build_environment_disables_archive_owner_restoration(self) -> None:
        environment = components.apache_build_environment(
            {"TAR_OPTIONS": "--same-owner"},
            Path("/connector"),
            Path("/framework"),
            Path("/cache"),
            Path("/build"),
            Path("/sources"),
            Path("/archives"),
            {"prefix": "/modsecurity-prefix", "build_id": "modsecurity-build"},
            {
                "expat_lib_dir": "/expat/lib",
                "expat_pkg_config_path": "/expat/lib/pkgconfig",
                "apache_build_root": Path("/apache-build"),
                "httpd_prefix": Path("/httpd-prefix"),
                "expat_cppflags": "-I/expat/include",
                "expat_ldflags": "-L/expat/lib",
                "apache_libs": "-lexpat",
                "crypt_link_arg": "-lcrypt",
            },
        )

        self.assertEqual(environment["TAR_OPTIONS"], "--no-same-owner")

    def assert_modsecurity_preflight_statuses(self, preflight, *args) -> None:
        non_ready_statuses = (
            ("blocked", "shared_modsecurity_blocked"),
            ("failed", "shared_modsecurity_failed"),
            ("unknown", "shared_modsecurity_unknown"),
            ("corrupt", "shared_modsecurity_corrupt"),
            ("blocked_optional", "shared_modsecurity_optional"),
            ("not_selected", ""),
            (None, ""),
        )
        for status, blocker_reason in non_ready_statuses:
            with self.subTest(status=status):
                modsecurity: dict[str, object] = {
                    "build_id": "modsecurity-build",
                    "blocker_reason": blocker_reason,
                }
                if status is not None:
                    modsecurity["status"] = status
                record: dict[str, object] = {}

                self.assertTrue(preflight(record, modsecurity, *args))
                self.assertEqual(record["status"], "blocked")
                self.assertEqual(
                    record["blocker_reason"],
                    blocker_reason or "modsecurity_build_failed",
                )
        for status in components.READY_COMPONENT_STATUSES:
            with self.subTest(status=status):
                self.assertFalse(preflight({}, {"status": status}, *args))

    def test_apache_preflight_blocks_non_ready_modsecurity_statuses(self) -> None:
        self.assert_modsecurity_preflight_statuses(components.apache_preflight_blocked, "")

    def test_nginx_preflight_blocks_non_ready_modsecurity_statuses(self) -> None:
        context = {
            "require_pinned_provenance": False,
            "override_bin": "",
            "override_module_dir": "",
            "managed_local_artifacts_match_plan": True,
        }
        self.assert_modsecurity_preflight_statuses(components.nginx_preflight_blocked, context)

    def test_apache_failed_modsecurity_stops_before_host_build(self) -> None:
        record: dict[str, object] = {}
        modsecurity = {
            "status": "failed",
            "build_id": "modsecurity-build",
            "blocker_reason": "modsecurity_build_failed",
        }
        with tempfile.TemporaryDirectory(prefix="apache-failed-modsecurity-") as temporary:
            root = Path(temporary)
            with mock.patch.object(
                components,
                "apache_runtime_context",
                return_value={"override_apachectl": ""},
            ), mock.patch.object(
                components,
                "apache_runtime_record",
                return_value=record,
            ), mock.patch.object(components, "build_apache_source") as build:
                result = components._prepare_apache_httpd_for_plan(
                    {},
                    ROOT,
                    ROOT,
                    root / "cache",
                    root / "build",
                    root / "sources",
                    root / "archives",
                    {},
                    modsecurity,
                    {},
                )

        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["blocker_reason"], "modsecurity_build_failed")
        build.assert_not_called()

    def test_nginx_failed_modsecurity_stops_before_host_build(self) -> None:
        record: dict[str, object] = {}
        modsecurity = {
            "status": "failed",
            "build_id": "modsecurity-build",
            "blocker_reason": "modsecurity_build_failed",
        }
        context = {
            "require_pinned_provenance": False,
            "override_bin": "",
            "override_module_dir": "",
            "managed_local_artifacts_match_plan": True,
        }
        with tempfile.TemporaryDirectory(prefix="nginx-failed-modsecurity-") as temporary:
            root = Path(temporary)
            with mock.patch.object(components, "nginx_pinned_provenance"), mock.patch.object(
                components,
                "nginx_pinned_provenance_required",
                return_value=False,
            ), mock.patch.object(
                components,
                "nginx_protocol_context",
                return_value=({}, "h1", "", ""),
            ), mock.patch.object(
                components,
                "nginx_runtime_context",
                return_value=context,
            ), mock.patch.object(
                components,
                "nginx_runtime_record",
                return_value=record,
            ), mock.patch.object(
                components,
                "nginx_archive_preflight_blocked",
                return_value=False,
            ), mock.patch.object(components, "nginx_prepare_or_reuse_runtime") as prepare:
                result = components._prepare_nginx_runtime_for_plan(
                    {},
                    ROOT,
                    ROOT,
                    root / "cache",
                    root / "build",
                    root / "sources",
                    root / "archives",
                    modsecurity,
                    {},
                )

        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["blocker_reason"], "modsecurity_build_failed")
        prepare.assert_not_called()

    def test_expat_autotools_stops_when_autoreconf_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="expat-autoreconf-") as temporary:
            root = Path(temporary)
            source_dir = root / "source"
            source_dir.mkdir()
            with mock.patch.object(components, "run_expat_build_step", return_value=False) as run_step:
                result = components.run_expat_autotools_build(
                    source_dir,
                    root / "build",
                    root / "prefix",
                    {},
                    [],
                    root / "build.log",
                    {},
                )

        self.assertFalse(result)
        run_step.assert_called_once()
        self.assertEqual(run_step.call_args.args[0], "expat-autoreconf")

    def test_nginx_blocker_reports_connector_compile_error_before_missing_outputs(self) -> None:
        compiler_error = "src/module.c:123:28: error: field 'phase' has incomplete type\n"

        self.assertEqual(
            components.map_nginx_blocker(compiler_error, ["module_file:/cache/module.so"]),
            "nginx_connector_build_failed",
        )

    def test_shared_modsecurity_blocks_before_build_sinks_when_framework_guard_rejects(self) -> None:
        with tempfile.TemporaryDirectory(prefix="modsecurity-provenance-guard-") as temporary:
            root = Path(temporary)
            cache_root = components.ensure_managed_cache_root(root / "cache")
            source = root / "source"
            source.mkdir()
            git_record = {
                "status": "present",
                "path": str(source),
                "url": "https://github.com/example/modsecurity",
                "expected_ref": "v3",
                "actual_head": "deadbeef",
                "submodule_status": "",
                "submodule_status_clean": True,
            }
            toolchain = {"cc": "cc", "cc_version": "cc test", "cxx": "", "cxx_version": ""}
            provenance = {
                "status": "blocked",
                "blocker_reason": "framework_modsecurity_v3_provenance_guard_rejected",
                "details": "BLOCKED: unexpected immutable checkout",
            }
            with mock.patch.object(components, "toolchain_identity", return_value=toolchain), mock.patch.object(
                components,
                "verify_framework_approved_modsecurity_v3_checkout",
                return_value=provenance,
            ), mock.patch.object(components.shutil, "copytree") as copytree, mock.patch.object(
                components, "run_env"
            ) as run_env, mock.patch.object(components, "copy_modsecurity_outputs") as copy_outputs, mock.patch.object(
                components, "atomic_publish_dir"
            ) as publish:
                record = components.prepare_shared_modsecurity(
                    {},
                    cache_root,
                    root / "work",
                    git_record,
                    {},
                    framework_root=root / "framework",
                )

            self.assertEqual(record["status"], "blocked")
            self.assertEqual(record["blocker_reason"], "modsecurity_v3_provenance_guard_failed")
            self.assertEqual(provenance, record["provenance_verification"])
            self.assertFalse(Path(str(record["build_root"])).exists())
            self.assertFalse(Path(str(record["prefix"])).exists())
            copytree.assert_not_called()
            run_env.assert_not_called()
            copy_outputs.assert_not_called()
            publish.assert_not_called()

    def test_shared_modsecurity_allows_normal_preflight_after_framework_guard_passes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="modsecurity-provenance-guard-") as temporary:
            root = Path(temporary)
            cache_root = components.ensure_managed_cache_root(root / "cache")
            source = root / "source"
            source.mkdir()
            framework_root = root / "framework"
            git_record = {
                "status": "present",
                "path": str(source),
                "url": "https://github.com/example/modsecurity",
                "expected_ref": "v3",
                "actual_head": "deadbeef",
                "submodule_status": "",
                "submodule_status_clean": True,
            }
            toolchain = {"cc": "cc", "cc_version": "cc test", "cxx": "", "cxx_version": ""}
            with mock.patch.object(components, "toolchain_identity", return_value=toolchain), mock.patch.object(
                components,
                "verify_framework_approved_modsecurity_v3_checkout",
                return_value={"status": "passed"},
            ) as provenance_guard, mock.patch.object(
                components, "first_missing_tool", return_value="missing_make"
            ), mock.patch.object(components, "resolve_compiler", return_value="/usr/bin/cc"), mock.patch.object(
                components.shutil, "copytree"
            ) as copytree:
                record = components.prepare_shared_modsecurity(
                    {},
                    cache_root,
                    root / "work",
                    git_record,
                    {},
                    framework_root=framework_root,
                )

            self.assertEqual(record["status"], "blocked")
            self.assertEqual(record["blocker_reason"], "missing_modsecurity_dependency")
            provenance_guard.assert_called_once_with({}, framework_root, source.resolve())
            copytree.assert_not_called()

    def test_framework_modsecurity_guard_passes_paths_as_positional_arguments(self) -> None:
        with tempfile.TemporaryDirectory(prefix="modsecurity-provenance-guard-") as temporary:
            root = Path(temporary)
            framework_root = root / "framework"
            common = framework_root / "ci/lib/common.sh"
            common.parent.mkdir(parents=True)
            common.write_text("# tested through a mocked subprocess\n", encoding="utf-8")
            source = root / "source;not-shell"
            source.mkdir()
            completed = subprocess.CompletedProcess([], 0, "", "")
            with mock.patch.object(components, "run_env", return_value=completed) as run_env:
                result = components.verify_framework_approved_modsecurity_v3_checkout(
                    {
                        "MODSECURITY_V3_GIT_URL": "https://github.com/owasp-modsecurity/ModSecurity.git",
                        "PATH": str(root / "attacker-controlled-path"),
                        "ENV": str(root / "attacker-shell-hook"),
                        "BASH_ENV": str(root / "attacker-bash-hook"),
                    },
                    framework_root,
                    source,
                )

            self.assertEqual(result["status"], "passed")
            run_env.assert_called_once()
            command = run_env.call_args.args[0]
            self.assertEqual(
                command,
                [
                    str(
                        components.verified_host_guard_executable(
                            components._TRUSTED_FRAMEWORK_GUARD_SHELL,
                            "framework_guard_shell",
                        )
                    ),
                    "-c",
                    components._FRAMEWORK_MODSECURITY_V3_GUARD,
                    "framework-modsecurity-v3-provenance-guard",
                    str(common),
                    str(source),
                ],
            )
            self.assertEqual(framework_root, run_env.call_args.kwargs["cwd"])
            self.assertEqual(str(source), run_env.call_args.kwargs["env"]["MODSECURITY_V3_SOURCE_DIR"])
            self.assertEqual(
                components._TRUSTED_FRAMEWORK_GUARD_PATH,
                run_env.call_args.kwargs["env"]["PATH"],
            )
            self.assertNotIn("ENV", run_env.call_args.kwargs["env"])
            self.assertNotIn("BASH_ENV", run_env.call_args.kwargs["env"])

    def test_framework_modsecurity_guard_keeps_only_original_pin_inputs(self) -> None:
        """A re-sourced Framework guard must not inherit its own pin exports."""
        with tempfile.TemporaryDirectory(prefix="modsecurity-provenance-guard-") as temporary:
            root = Path(temporary)
            framework_root = root / "framework"
            common = framework_root / "ci/lib/common.sh"
            common.parent.mkdir(parents=True)
            common.write_text("# tested through a mocked subprocess\n", encoding="utf-8")
            source = root / "source"
            source.mkdir()
            completed = subprocess.CompletedProcess([], 0, "", "")
            loaded_framework_environment = {
                "CONNECTOR_ROOT": str(root / "connector"),
                "FRAMEWORK_ROOT": str(framework_root),
                "VERIFIED_RUN_ROOT": str(root / "verified-run"),
                "ENVOY_VERSION": "1.39.0",
                "TRAEFIK_VERSION": "3.7.10",
                "LIGHTTPD_VERSION": "1.4.85",
                "CI_INHERITED_UPSTREAM_ENV": "ENVOY_VERSION=1.39.0",
            }
            with mock.patch.dict(
                os.environ,
                {"ENVOY_VERSION": "caller-override"},
                clear=True,
            ), mock.patch.object(components, "run_env", return_value=completed) as run_env:
                result = components.verify_framework_approved_modsecurity_v3_checkout(
                    loaded_framework_environment,
                    framework_root,
                    source,
                )

            self.assertEqual(result["status"], "passed")
            guard_env = run_env.call_args.kwargs["env"]
            self.assertEqual(guard_env["ENVOY_VERSION"], "caller-override")
            self.assertNotIn("TRAEFIK_VERSION", guard_env)
            self.assertNotIn("LIGHTTPD_VERSION", guard_env)
            self.assertNotIn("CI_INHERITED_UPSTREAM_ENV", guard_env)
            self.assertEqual(guard_env["CONNECTOR_ROOT"], str(root / "connector"))
            self.assertEqual(guard_env["FRAMEWORK_ROOT"], str(framework_root))
            self.assertEqual(guard_env["VERIFIED_RUN_ROOT"], str(root / "verified-run"))
            self.assertEqual(guard_env["MODSECURITY_V3_SOURCE_DIR"], str(source))

    def test_framework_modsecurity_provisioning_bridge_passes_destination_as_positional_argument(self) -> None:
        with tempfile.TemporaryDirectory(prefix="modsecurity-provisioning-bridge-") as temporary:
            root = Path(temporary)
            framework_root = root / "framework"
            common = framework_root / "ci/lib/common.sh"
            common.parent.mkdir(parents=True)
            common.write_text("# tested through a mocked subprocess\n", encoding="utf-8")
            destination = root / "source;not-shell"
            completed = subprocess.CompletedProcess([], 0, "", "")
            with mock.patch.object(components, "run_env", return_value=completed) as run_env:
                result = components.provision_framework_approved_modsecurity_v3_checkout(
                    {
                        "PATH": str(root / "attacker-controlled-path"),
                        "ENV": str(root / "attacker-shell-hook"),
                        "BASH_ENV": str(root / "attacker-bash-hook"),
                    },
                    framework_root,
                    destination,
                )

            self.assertEqual(result["status"], "passed")
            run_env.assert_called_once()
            command = run_env.call_args.args[0]
            self.assertEqual(
                command,
                [
                    str(
                        components.verified_host_guard_executable(
                            components._TRUSTED_FRAMEWORK_GUARD_SHELL,
                            "framework_guard_shell",
                        )
                    ),
                    "-c",
                    components._FRAMEWORK_MODSECURITY_V3_PROVISIONING_BRIDGE,
                    "framework-modsecurity-v3-provisioning-bridge",
                    str(common),
                    str(destination),
                ],
            )
            self.assertEqual(framework_root, run_env.call_args.kwargs["cwd"])
            self.assertEqual(str(destination), run_env.call_args.kwargs["env"]["MODSECURITY_V3_SOURCE_DIR"])
            self.assertEqual(
                components._TRUSTED_FRAMEWORK_GUARD_PATH,
                run_env.call_args.kwargs["env"]["PATH"],
            )
            self.assertNotIn("ENV", run_env.call_args.kwargs["env"])
            self.assertNotIn("BASH_ENV", run_env.call_args.kwargs["env"])

    def test_framework_modsecurity_metadata_uses_trusted_git_with_scrubbed_environment(self) -> None:
        with tempfile.TemporaryDirectory(prefix="modsecurity-provenance-metadata-") as temporary:
            source = Path(temporary) / "source;not-shell"
            completed = subprocess.CompletedProcess([], 0, "approved-head\n", "")
            with mock.patch.dict(
                os.environ,
                {
                    "GIT_CONFIG_COUNT": "7",
                    "GIT_DIR": str(source / "attacker-git-dir"),
                    "LD_PRELOAD": str(source / "attacker-loader"),
                },
            ), mock.patch.object(components, "run_env", return_value=completed) as run_env:
                output = components.trusted_framework_modsecurity_v3_git_output(source, "rev-parse", "HEAD")

            self.assertEqual(output, "approved-head")
            self.assertEqual(
                run_env.call_args.args[0],
                [
                    str(
                        components.verified_host_guard_executable(
                            components._TRUSTED_FRAMEWORK_GUARD_GIT,
                            "framework_guard_git",
                        )
                    ),
                    "-c",
                    "core.hooksPath=/dev/null",
                    "-c",
                    "core.fsmonitor=false",
                    "-c",
                    "core.useBuiltinFSMonitor=false",
                    "-C",
                    str(source),
                    "rev-parse",
                    "HEAD",
                ],
            )
            self.assertEqual(
                run_env.call_args.kwargs["env"],
                {
                    "PATH": components._TRUSTED_FRAMEWORK_GUARD_PATH,
                    "LC_ALL": "C",
                    "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_CONFIG_GLOBAL": os.devnull,
                    "GIT_CONFIG_COUNT": "0",
                    "GIT_OPTIONAL_LOCKS": "0",
                    "GIT_ATTR_NOSYSTEM": "1",
                    "GIT_NO_REPLACE_OBJECTS": "1",
                },
            )

    def test_modsecurity_source_configuration_guard_blocks_before_git_preparation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="modsecurity-provenance-guard-") as temporary:
            root = Path(temporary)
            expected_configuration = {
                "status": "blocked",
                "blocker_reason": "framework_modsecurity_v3_provenance_guard_rejected",
                "details": "BLOCKED: immutable source configuration mismatch",
            }
            with mock.patch.object(
                components,
                "verify_framework_approved_modsecurity_v3_provenance",
                return_value=expected_configuration,
            ), mock.patch.object(
                components, "provision_framework_approved_modsecurity_v3_checkout"
            ) as bridge, mock.patch.object(components, "prepare_git_component") as prepare_git:
                record = components.prepare_framework_approved_modsecurity_v3_source(
                    {
                        "MODSECURITY_V3_GIT_URL": "https://github.com/example/unapproved",
                        "MODSECURITY_V3_GIT_REF": "mutable-ref",
                    },
                    root / "framework",
                    root / "source",
                    cache_root=root / "cache",
                )

            self.assertEqual(record["status"], "blocked")
            self.assertEqual(record["blocker_reason"], "modsecurity_v3_provenance_configuration_failed")
            self.assertEqual(expected_configuration, record["provenance_configuration"])
            bridge.assert_not_called()
            prepare_git.assert_not_called()

    def test_modsecurity_source_uses_framework_bridge_and_records_approved_provenance(self) -> None:
        with tempfile.TemporaryDirectory(prefix="modsecurity-provenance-guard-") as temporary:
            root = Path(temporary)
            cache_root = components.ensure_managed_cache_root(root / "cache")
            source = cache_root / "sources" / "modsecurity-v3"
            expected_head = "a" * 40
            configuration = {"status": "passed", "details": "approved source configuration"}
            provisioned_paths: list[Path] = []

            def provision(
                _env: dict[str, str],
                _framework_root: Path,
                destination: Path,
            ) -> dict[str, object]:
                self.assertFalse(destination.exists())
                self.assertFalse(destination.is_symlink())
                self.assertTrue(destination.name.startswith(".modsecurity-v3.tmp-"))
                provisioned_paths.append(destination)
                destination.mkdir()
                return {"status": "passed", "source_path": str(destination)}

            def git_metadata(path: Path, *args: str) -> str:
                self.assertEqual(provisioned_paths[0], path)
                if args == ("rev-parse", "HEAD"):
                    return expected_head
                if args == components.GIT_STATUS_SHORT_ARGS:
                    return ""
                if args == components.GIT_SUBMODULE_STATUS_RECURSIVE_ARGS:
                    return ""
                self.fail(f"unexpected local Git metadata request: {args}")

            with mock.patch.object(
                components,
                "verify_framework_approved_modsecurity_v3_provenance",
                return_value=configuration,
            ), mock.patch.object(
                components,
                "provision_framework_approved_modsecurity_v3_checkout",
                side_effect=provision,
            ) as bridge, mock.patch.object(
                components,
                "verify_framework_approved_modsecurity_v3_checkout",
                side_effect=lambda _env, _framework_root, checkout: {
                    "status": "passed",
                    "source_path": str(checkout),
                },
            ) as verification, mock.patch.object(
                components, "trusted_framework_modsecurity_v3_git_output", side_effect=git_metadata
            ), mock.patch.object(components, "prepare_git_component") as prepare_git:
                record = components.prepare_framework_approved_modsecurity_v3_source(
                    {
                        "MODSECURITY_V3_GIT_URL": "https://github.com/owasp-modsecurity/ModSecurity.git",
                        "MODSECURITY_V3_GIT_REF": "v3.0.15",
                    },
                    root / "framework",
                    source,
                    cache_root=cache_root,
                )

            bridge.assert_called_once_with(
                {
                    "MODSECURITY_V3_GIT_URL": "https://github.com/owasp-modsecurity/ModSecurity.git",
                    "MODSECURITY_V3_GIT_REF": "v3.0.15",
                },
                root / "framework",
                provisioned_paths[0],
            )
            verification.assert_called_once_with(
                {
                    "MODSECURITY_V3_GIT_URL": "https://github.com/owasp-modsecurity/ModSecurity.git",
                    "MODSECURITY_V3_GIT_REF": "v3.0.15",
                },
                root / "framework",
                provisioned_paths[0],
            )
            prepare_git.assert_not_called()
            self.assertEqual(record["status"], "present")
            self.assertEqual(record["approved_acquisition"], "framework_approved_v3_bridge")
            self.assertEqual(source, Path(str(record["path"])))
            self.assertTrue(source.is_dir())
            self.assertFalse(provisioned_paths[0].exists())
            self.assertEqual(expected_head, record["actual_head"])
            self.assertEqual(record["git_fsck"], "PASS")
            self.assertTrue(record["submodule_status_clean"])
            self.assertEqual(configuration, record["provenance_configuration"])
            self.assertEqual(record["provenance_provisioning"]["status"], "passed")
            self.assertEqual(record["provenance_verification"]["status"], "passed")
            self.assertIn("cache_identity", record)
            self.assertIn("cache_key", record)

    def test_modsecurity_source_reuses_only_a_framework_revalidated_complete_cache_entry(self) -> None:
        with tempfile.TemporaryDirectory(prefix="modsecurity-provenance-cache-reuse-") as temporary:
            root = Path(temporary)
            cache_root = components.ensure_managed_cache_root(root / "cache")
            source = cache_root / "sources" / "modsecurity-v3"
            environment = {
                "MODSECURITY_V3_GIT_URL": "https://github.com/owasp-modsecurity/ModSecurity.git",
                "MODSECURITY_V3_GIT_REF": "v3.0.15",
            }
            expected_head = "b" * 40
            identity = components.source_cache_identity(
                "modsecurity-v3",
                environment["MODSECURITY_V3_GIT_URL"],
                environment["MODSECURITY_V3_GIT_REF"],
                expected_head,
            )
            components.mark_managed_cache_entry(
                source,
                cache_root,
                component="source:modsecurity-v3",
                cache_key=str(identity["cache_key"]),
            )
            source.parent.mkdir(parents=True)
            source.mkdir()
            components.write_cache_entry_completion(
                source,
                cache_root,
                component="source:modsecurity-v3",
                cache_key=str(identity["cache_key"]),
                cache_identity=identity,
            )

            def git_metadata(path: Path, *args: str) -> str:
                self.assertEqual(path, source)
                if args == ("rev-parse", "HEAD"):
                    return expected_head
                if args == components.GIT_STATUS_SHORT_ARGS:
                    return ""
                if args == components.GIT_SUBMODULE_STATUS_RECURSIVE_ARGS:
                    return ""
                self.fail(f"unexpected local Git metadata request: {args}")

            verification = {"status": "passed", "source_path": str(source)}
            with mock.patch.object(
                components,
                "verify_framework_approved_modsecurity_v3_provenance",
                return_value={"status": "passed"},
            ), mock.patch.object(
                components,
                "verify_framework_approved_modsecurity_v3_checkout",
                return_value=verification,
            ) as checkout_verification, mock.patch.object(
                components,
                "trusted_framework_modsecurity_v3_git_output",
                side_effect=git_metadata,
            ), mock.patch.object(
                components,
                "provision_framework_approved_modsecurity_v3_checkout",
            ) as bridge, mock.patch.object(components, "prepare_git_component") as prepare_git:
                record = components.prepare_framework_approved_modsecurity_v3_source(
                    environment,
                    root / "framework",
                    source,
                    cache_root=cache_root,
                )

            checkout_verification.assert_called_once_with(environment, root / "framework", source)
            bridge.assert_not_called()
            prepare_git.assert_not_called()
            self.assertEqual(record["status"], "present")
            self.assertEqual(record["approved_acquisition"], "framework_approved_v3_cache_reuse")
            self.assertEqual(record["provenance_verification"], verification)
            self.assertEqual(record["cache_key"], identity["cache_key"])
            self.assertTrue(components.cache_entry_complete(
                source,
                cache_root,
                component="source:modsecurity-v3",
                cache_key=str(identity["cache_key"]),
                cache_identity=identity,
            ))

    def test_modsecurity_source_bridge_failure_preserves_published_cache_without_generic_fallback(self) -> None:
        with tempfile.TemporaryDirectory(prefix="modsecurity-provenance-guard-") as temporary:
            root = Path(temporary)
            cache_root = components.ensure_managed_cache_root(root / "cache")
            source = cache_root / "sources" / "modsecurity-v3"
            components.mark_managed_cache_entry(
                source,
                cache_root,
                component="source:modsecurity-v3",
                cache_key="published-cache-entry",
            )
            source.parent.mkdir(parents=True)
            source.mkdir()
            sentinel = source / "preserve-on-bridge-failure"
            sentinel.write_text("published cache must remain untouched", encoding="utf-8")
            bridge_failure = {
                "status": "blocked",
                "blocker_reason": "framework_modsecurity_v3_provenance_guard_rejected",
                "details": "BLOCKED: bridge could not provision source",
            }
            with mock.patch.object(
                components,
                "verify_framework_approved_modsecurity_v3_provenance",
                return_value={"status": "passed"},
            ), mock.patch.object(
                components,
                "verify_framework_approved_modsecurity_v3_checkout",
                return_value={"status": "blocked"},
            ), mock.patch.object(
                components,
                "provision_framework_approved_modsecurity_v3_checkout",
                return_value=bridge_failure,
            ) as bridge, mock.patch.object(components, "prepare_git_component") as prepare_git:
                record = components.prepare_framework_approved_modsecurity_v3_source(
                    {
                        "MODSECURITY_V3_GIT_URL": "https://github.com/owasp-modsecurity/ModSecurity.git",
                        "MODSECURITY_V3_GIT_REF": "v3.0.15",
                    },
                    root / "framework",
                    source,
                    cache_root=cache_root,
                )

            bridge.assert_called_once()
            prepare_git.assert_not_called()
            self.assertEqual(record["status"], "blocked")
            self.assertEqual(record["blocker_reason"], "modsecurity_v3_framework_provisioning_failed")
            self.assertEqual(bridge_failure, record["provenance_provisioning"])
            self.assertTrue(sentinel.is_file())
            self.assertTrue(components.cache_entry_marker_valid(source, cache_root))
            self.assertEqual(list(source.parent.glob(".modsecurity-v3.tmp-*")), [])

            with mock.patch.object(
                components,
                "toolchain_identity",
                return_value={"cc": "cc", "cc_version": "cc test", "cxx": "", "cxx_version": ""},
            ), mock.patch.object(components.shutil, "copytree") as copytree, mock.patch.object(
                components, "run_env"
            ) as run_env, mock.patch.object(components, "copy_modsecurity_outputs") as copy_outputs, mock.patch.object(
                components, "atomic_publish_dir"
            ) as publish:
                build_record = components.prepare_shared_modsecurity(
                    {},
                    cache_root,
                    root / "work",
                    record,
                    {},
                    framework_root=root / "framework",
                )

            self.assertEqual(build_record["status"], "blocked")
            self.assertEqual(build_record["blocker_reason"], "modsecurity_v3_framework_provisioning_failed")
            copytree.assert_not_called()
            run_env.assert_not_called()
            copy_outputs.assert_not_called()
            publish.assert_not_called()

    def test_modsecurity_source_post_provision_guard_failure_preserves_published_cache_without_publish_or_generic_fallback(
        self,
    ) -> None:
        """A rejected post-provision guard must discard only the staging checkout."""
        with tempfile.TemporaryDirectory(prefix="modsecurity-provenance-guard-") as temporary:
            root = Path(temporary)
            cache_root = components.ensure_managed_cache_root(root / "cache")
            source = cache_root / "sources" / "modsecurity-v3"
            component = "source:modsecurity-v3"
            environment = {
                "MODSECURITY_V3_GIT_URL": "https://github.com/owasp-modsecurity/ModSecurity.git",
                "MODSECURITY_V3_GIT_REF": "v3.0.15",
            }
            published_identity = components.source_cache_identity(
                "modsecurity-v3",
                environment["MODSECURITY_V3_GIT_URL"],
                environment["MODSECURITY_V3_GIT_REF"],
            )
            components.mark_managed_cache_entry(
                source,
                cache_root,
                component=component,
                cache_key=str(published_identity["cache_key"]),
            )
            source.parent.mkdir(parents=True)
            source.mkdir()
            sentinel = source / "preserve-on-post-provision-guard-failure"
            sentinel.write_text("published cache must remain untouched", encoding="utf-8")
            components.write_cache_entry_completion(
                source,
                cache_root,
                component=component,
                cache_key=str(published_identity["cache_key"]),
                cache_identity=published_identity,
            )
            self.assertTrue(
                components.cache_entry_complete(
                    source,
                    cache_root,
                    component=component,
                    cache_key=str(published_identity["cache_key"]),
                    cache_identity=published_identity,
                )
            )

            staging_paths: list[Path] = []
            cache_reuse_rejection = {
                "status": "blocked",
                "blocker_reason": "framework_modsecurity_v3_provenance_guard_rejected",
                "details": "BLOCKED: existing cache needs replacement",
            }
            post_provision_rejection = {
                "status": "blocked",
                "blocker_reason": "framework_modsecurity_v3_provenance_guard_rejected",
                "details": "BLOCKED: bridge-created checkout failed Framework verification",
            }

            def provision(
                _env: dict[str, str],
                _framework_root: Path,
                destination: Path,
            ) -> dict[str, object]:
                self.assertFalse(destination.exists())
                self.assertFalse(destination.is_symlink())
                self.assertTrue(components.cache_entry_marker_valid(destination, cache_root))
                staging_marker = components.read_json(components.cache_entry_marker_path(destination, cache_root))
                self.assertEqual(staging_marker["component"], component)
                self.assertEqual(str(published_identity["cache_key"]), staging_marker["cache_key"])
                self.assertNotEqual(staging_marker.get("status"), "complete")
                destination.mkdir()
                (destination / "bridge-created-partial-checkout").write_text("partial", encoding="utf-8")
                staging_paths.append(destination)
                return {"status": "passed", "source_path": str(destination)}

            with mock.patch.object(
                components,
                "verify_framework_approved_modsecurity_v3_provenance",
                return_value={"status": "passed"},
            ), mock.patch.object(
                components,
                "provision_framework_approved_modsecurity_v3_checkout",
                side_effect=provision,
            ) as bridge, mock.patch.object(
                components,
                "verify_framework_approved_modsecurity_v3_checkout",
                side_effect=[cache_reuse_rejection, post_provision_rejection],
            ) as verification, mock.patch.object(
                components, "write_cache_entry_completion"
            ) as completion, mock.patch.object(components, "atomic_publish_dir") as publish, mock.patch.object(
                components, "prepare_git_component"
            ) as prepare_git:
                record = components.prepare_framework_approved_modsecurity_v3_source(
                    environment,
                    root / "framework",
                    source,
                    cache_root=cache_root,
                )

            bridge.assert_called_once_with(environment, root / "framework", staging_paths[0])
            self.assertEqual(
                verification.call_args_list,
                [
                    mock.call(environment, root / "framework", source),
                    mock.call(environment, root / "framework", staging_paths[0]),
                ],
            )
            completion.assert_not_called()
            publish.assert_not_called()
            prepare_git.assert_not_called()
            self.assertEqual(record["status"], "blocked")
            self.assertEqual(record["blocker_reason"], "modsecurity_v3_provenance_guard_failed")
            self.assertEqual(post_provision_rejection, record["provenance_verification"])
            self.assertTrue(sentinel.is_file())
            self.assertTrue(
                components.cache_entry_complete(
                    source,
                    cache_root,
                    component=component,
                    cache_key=str(published_identity["cache_key"]),
                    cache_identity=published_identity,
                )
            )
            self.assertFalse(staging_paths[0].exists())
            self.assertFalse(staging_paths[0].is_symlink())
            self.assertFalse(components.cache_entry_marker_path(staging_paths[0], cache_root).exists())
            self.assertEqual(list(source.parent.glob(".modsecurity-v3.tmp-*")), [])

    def prepare_haproxy_with(self, returncode: int, output: str) -> dict[str, object]:
        with tempfile.TemporaryDirectory(prefix="haproxy-prepare-") as temporary:
            base = Path(temporary)
            cache = base / "cache"
            components.ensure_managed_cache_root(cache)
            build = base / "build"
            sources = cache / "sources"
            archives = cache / "archives"
            connector_build = cache / "builds/connectors/haproxy/test-build"
            cache_identity_payload = {
                "cache_schema_version": components.CACHE_SCHEMA_VERSION,
                "component": "haproxy",
                "extra_inputs": {"connector_source_hash": "source-hash"},
            }
            cache_key = components.stable_hash(cache_identity_payload)
            cache_identity = {**cache_identity_payload, "cache_key": cache_key}
            plan = {
                "connector": "haproxy",
                "connector_build_id": cache_key,
                "cache_key": cache_key,
                "cache_identity": cache_identity,
                "cache_root": str(cache),
                "root": str(connector_build),
                "modsecurity_build_id": "modsecurity-build",
                "source_hash": "source-hash",
                "build_flags": "{}",
                "build_root": str(connector_build),
                "manifest": str(connector_build / "manifest.json"),
                "output_paths": {},
            }
            completed = subprocess.CompletedProcess(
                args=["prepare-haproxy-runtime.sh"],
                returncode=returncode,
                stdout=output,
                stderr="",
            )
            with mock.patch.object(components, "run_build", return_value=completed):
                record = components.prepare_haproxy_runtime(
                    {},
                    ROOT,
                    source_path('modules/ModSecurity-test-Framework', root=ROOT),
                    cache,
                    build,
                    sources,
                    archives,
                    {"status": "built", "build_id": "modsecurity-build"},
                    plan,
                )
            self.assertFalse(connector_build.exists())
            self.assertFalse(any(path.name.startswith(f".{cache_key}.tmp-") for path in connector_build.parent.iterdir()))
            return record

    def prepare_haproxy_binding_failure_with(
        self,
        returncode: int,
        output: str,
    ) -> tuple[dict[str, object], str, tuple[tuple[Path, bool], ...]]:
        with tempfile.TemporaryDirectory(prefix="haproxy-binding-failure-") as temporary:
            root = Path(temporary)
            cache = root / "cache"
            components.ensure_managed_cache_root(cache)
            plan = self.haproxy_runtime_plan(cache)
            prep = subprocess.CompletedProcess(
                args=["prepare-haproxy-runtime.sh"],
                returncode=0,
                stdout="haproxy_prepare: ready\n",
                stderr="",
            )
            binding = subprocess.CompletedProcess(
                args=["make"],
                returncode=returncode,
                stdout="",
                stderr=output,
            )

            def prepare_with_runtime_binary(
                _script: Path,
                environment: dict[str, str],
                _cwd: Path,
                _log_path: Path,
            ) -> subprocess.CompletedProcess[str]:
                binary = Path(environment["HAPROXY_BIN"])
                binary.parent.mkdir(parents=True, exist_ok=True)
                binary.write_text("#!/bin/sh\n", encoding="utf-8")
                binary.chmod(0o700)
                return prep

            with mock.patch.object(components, "run_build", side_effect=prepare_with_runtime_binary), mock.patch.object(
                components, "run_haproxy_binding_build", return_value=binding
            ), mock.patch.object(components, "safe_remove_dir", wraps=components.safe_remove_dir) as cleanup, mock.patch(
                "sys.stderr", new_callable=io.StringIO
            ) as stderr:
                record = components.prepare_haproxy_runtime(
                    {},
                    ROOT,
                    source_path('modules/ModSecurity-test-Framework', root=ROOT),
                    cache,
                    root / "build",
                    cache / "sources",
                    cache / "archives",
                    {"status": "built", "build_id": "modsecurity-build"},
                    plan,
                )
                diagnostic = stderr.getvalue()
                cleanup_observations = tuple(
                    (Path(call.args[0]), Path(call.args[0]).exists())
                    for call in cleanup.call_args_list
                )
        return record, diagnostic, cleanup_observations

    def haproxy_runtime_plan(
        self,
        cache_root: Path,
        *,
        source_hash: str = "source-hash",
    ) -> dict[str, object]:
        cache_identity_payload = {
            "cache_schema_version": components.CACHE_SCHEMA_VERSION,
            "component": "haproxy",
            "extra_inputs": {"connector_source_hash": source_hash},
        }
        cache_key = components.stable_hash(cache_identity_payload)
        cache_identity = {**cache_identity_payload, "cache_key": cache_key}
        cache_entry = cache_root / "builds" / "connectors" / "haproxy" / cache_key
        return {
            "connector": "haproxy",
            "connector_build_id": cache_key,
            "cache_key": cache_key,
            "cache_identity": cache_identity,
            "cache_root": str(cache_root),
            "root": str(cache_entry),
            "build_root": str(cache_entry),
            "manifest": str(cache_entry / "manifest.json"),
            "source_hash": source_hash,
            "output_paths": {},
        }

    def test_haproxy_runtime_context_contains_all_mutable_outputs_under_invocation_build_root(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="haproxy-runtime-context-") as temporary:
            root = Path(temporary)
            cache_root = root / "cache"
            build_root = root / "invocation-build"
            plan = self.haproxy_runtime_plan(cache_root)

            context = components.haproxy_runtime_context(plan, build_root)
            prep_env = components.haproxy_prepare_environment(
                {},
                ROOT,
                source_path('modules/ModSecurity-test-Framework', root=ROOT),
                cache_root,
                build_root,
                cache_root / "sources",
                cache_root / "archives",
                context,
            )

            expected_root = (
                build_root
                / "runtime-components"
                / "haproxy"
                / str(plan["cache_key"])
            ).resolve()
            self.assertEqual(context["root"], expected_root)
            self.assertEqual(prep_env["BUILD_ROOT"], str(build_root.resolve()))
            self.assertEqual(prep_env["LOG_DIR"], str(context["framework_log_dir"]))
            self.assertEqual(
                components.connector_output_layout(
                    "haproxy",
                    Path(str(plan["root"])),
                )["output_paths"],
                {},
            )
            mutable_paths = (
                context["root"],
                context["haproxy_runtime_build_dir"],
                context["haproxy_runtime_build_worktree"],
                context["haproxy_runtime_dir"],
                context["haproxy_bin"],
                context["binding_dir"],
                context["spoa_dir"],
                context["spoa_bin"],
                context["paths_env"],
                context["log_path"],
                context["framework_log_dir"],
                context["framework_build_log"],
            )
            for path in mutable_paths:
                with self.subTest(path=path):
                    self.assertNotEqual(path, build_root.resolve())
                    self.assertTrue(components.is_within(path, build_root))
                    self.assertFalse(components.is_within(path, cache_root))
            self.assertEqual(
                prep_env["HAPROXY_RUNTIME_BUILD_WORKTREE"],
                str(context["haproxy_runtime_build_worktree"]),
            )
            self.assertEqual(
                components.haproxy_runtime_context(plan, build_root)["root"],
                expected_root,
            )

    def test_haproxy_runtime_context_rejects_cache_owned_mutable_output_root(self) -> None:
        with tempfile.TemporaryDirectory(prefix="haproxy-cache-output-rejection-") as temporary:
            cache_root = Path(temporary) / "cache"
            plan = self.haproxy_runtime_plan(cache_root)

            with self.assertRaisesRegex(
                RuntimeError,
                "haproxy_runtime_output_overlaps_component_cache",
            ):
                components.haproxy_runtime_context(plan, cache_root / "mutable-build")

    def test_haproxy_runtime_preclaim_allows_incomplete_runtime_cleanup(self) -> None:
        with tempfile.TemporaryDirectory(prefix="haproxy-runtime-preclaim-") as temporary:
            root = Path(temporary)
            plan = self.haproxy_runtime_plan(root / "cache")
            context = components.haproxy_runtime_context(plan, root / "build")
            self.assertEqual(components.claim_haproxy_runtime_entry(plan, context), "")
            marker = components.read_json(
                components.cache_entry_marker_path(context["root"], context["build_root"])
            )
            self.assertEqual(marker["component"], "runtime:haproxy")
            self.assertEqual(marker["cache_key"], plan["cache_key"])
            self.assertTrue(context["root"].is_dir())
            self.assertFalse(context["root"].is_symlink())

            record: dict[str, object] = {}
            self.assertEqual(
                components.reconcile_haproxy_cached_entry(plan, context, record),
                "",
            )
            self.assertFalse(context["root"].exists())
            self.assertEqual(record["invalidation_reason"], "missing_or_incomplete_haproxy_runtime")

    def test_haproxy_runtime_preclaim_rejects_a_concurrently_created_root(self) -> None:
        with tempfile.TemporaryDirectory(prefix="haproxy-runtime-race-") as temporary:
            root = Path(temporary)
            plan = self.haproxy_runtime_plan(root / "cache")
            context = components.haproxy_runtime_context(plan, root / "build")
            original_mark = components.mark_managed_cache_entry

            def mark_then_create(*args: object, **kwargs: object) -> None:
                original_mark(*args, **kwargs)
                context["root"].mkdir(parents=True)

            with mock.patch.object(
                components,
                "mark_managed_cache_entry",
                side_effect=mark_then_create,
            ):
                error = components.claim_haproxy_runtime_entry(plan, context)

            self.assertEqual(error, f"haproxy_runtime_root_already_exists: {context['root']}")
            self.assertFalse(
                components.cache_entry_marker_valid(context["root"], context["build_root"])
            )

    def test_haproxy_runtime_reuse_requires_a_preclaimed_runtime_entry(self) -> None:
        with tempfile.TemporaryDirectory(prefix="haproxy-runtime-unowned-reuse-") as temporary:
            root = Path(temporary)
            plan = self.haproxy_runtime_plan(root / "cache")
            context = components.haproxy_runtime_context(plan, root / "build")
            for executable_path in (context["haproxy_bin"], context["spoa_bin"]):
                executable_path.parent.mkdir(parents=True, exist_ok=True)
                executable_path.write_text("#!/bin/sh\n", encoding="utf-8")
                executable_path.chmod(0o700)
            context["paths_env"].parent.mkdir(parents=True, exist_ok=True)
            context["paths_env"].write_text("HAPROXY_BIN=unused\n", encoding="utf-8")

            with mock.patch.object(components, "connector_manifest_ready", return_value=True):
                self.assertFalse(components.haproxy_cached_entry_reusable(plan, context))

    def test_haproxy_runtime_context_rejects_build_key_path_escape(self) -> None:
        with tempfile.TemporaryDirectory(prefix="haproxy-build-key-escape-") as temporary:
            root = Path(temporary)
            plan = self.haproxy_runtime_plan(root / "cache")
            plan["connector_build_id"] = "../escape"
            plan["cache_key"] = "../escape"
            plan["cache_identity"]["cache_key"] = "../escape"  # type: ignore[index]

            with self.assertRaisesRegex(RuntimeError, "unsafe_haproxy_runtime_build_key"):
                components.haproxy_runtime_context(plan, root / "build")

    def test_haproxy_runtime_context_rejects_source_build_key_mismatch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="haproxy-build-key-mismatch-") as temporary:
            root = Path(temporary)
            for field, different_value in (
                ("connector_build_id", "different-build-key"),
                ("source_hash", "different-source-hash"),
            ):
                with self.subTest(field=field):
                    plan = self.haproxy_runtime_plan(root / "cache")
                    plan[field] = different_value
                    with self.assertRaisesRegex(
                        RuntimeError,
                        "haproxy_source_build_key_mismatch",
                    ):
                        components.haproxy_runtime_context(plan, root / "build")

    def test_haproxy_build_failure_returning_77_is_execution_failure(self) -> None:
        record = self.prepare_haproxy_with(
            77,
            "haproxy_prepare: running haproxy-build\n"
            "haproxy_prepare: blocked command failed: make\n",
        )
        self.assertEqual(record["status"], "failed")
        self.assertEqual(record["build_exit_code"], 77)

    def test_haproxy_preflight_blocks_non_ready_modsecurity_statuses(self) -> None:
        with tempfile.TemporaryDirectory(prefix="haproxy-non-ready-modsecurity-") as temporary:
            root = Path(temporary)
            cache = root / "cache"
            components.ensure_managed_cache_root(cache)
            plan = self.haproxy_runtime_plan(cache)
            context = components.haproxy_runtime_context(plan, root / "build")
            non_ready_statuses = (
                ("blocked", "shared_modsecurity_blocked"),
                ("failed", "shared_modsecurity_failed"),
                ("unknown", "shared_modsecurity_unknown"),
                ("corrupt", "shared_modsecurity_corrupt"),
                ("blocked_optional", "shared_modsecurity_optional"),
                ("not_selected", ""),
                (None, ""),
            )
            for status, blocker_reason in non_ready_statuses:
                with self.subTest(status=status):
                    modsecurity: dict[str, object] = {
                        "build_id": "modsecurity-build",
                        "blocker_reason": blocker_reason,
                    }
                    if status is not None:
                        modsecurity["status"] = status
                    record = components.haproxy_runtime_record(plan, modsecurity, context)

                    self.assertTrue(
                        components.haproxy_preflight_blocked(record, modsecurity, cache, context)
                    )
                    self.assertEqual(record["status"], "blocked")
                    self.assertEqual(
                        record["blocker_reason"],
                        blocker_reason or "modsecurity_build_failed",
                    )
            for status in components.READY_COMPONENT_STATUSES:
                with self.subTest(status=status):
                    modsecurity = {"status": status, "build_id": "modsecurity-build"}
                    record = components.haproxy_runtime_record(plan, modsecurity, context)

                    self.assertFalse(
                        components.haproxy_preflight_blocked(record, modsecurity, cache, context)
                    )

    def test_haproxy_failed_modsecurity_stops_before_host_build(self) -> None:
        with tempfile.TemporaryDirectory(prefix="haproxy-failed-modsecurity-") as temporary:
            root = Path(temporary)
            cache = root / "cache"
            components.ensure_managed_cache_root(cache)
            plan = self.haproxy_runtime_plan(cache)
            modsecurity = {
                "status": "failed",
                "build_id": "modsecurity-build",
                "blocker_reason": "modsecurity_build_failed",
            }
            with mock.patch.object(components, "run_build") as prepare, mock.patch.object(
                components, "run_haproxy_binding_build"
            ) as binding, mock.patch.object(
                components,
                "write_haproxy_record",
                side_effect=lambda _plan, record: record,
            ):
                record = components.prepare_haproxy_runtime(
                    {},
                    ROOT,
                    source_path('modules/ModSecurity-test-Framework', root=ROOT),
                    cache,
                    root / "build",
                    cache / "sources",
                    cache / "archives",
                    modsecurity,
                    plan,
                    _transactional=True,
                )

            self.assertEqual(record["status"], "blocked")
            self.assertEqual(record["blocker_reason"], "modsecurity_build_failed")
            prepare.assert_not_called()
            binding.assert_not_called()

    def test_haproxy_binding_failure_diagnostic_is_bounded_and_opaque(self) -> None:
        proc = subprocess.CompletedProcess(
            args=["make"],
            returncode=2,
            stdout=(
                "cc1: fatal error: modsecurity/transaction.h: No such file or directory "
                "Authorization: Bearer hidden\x1b[31m\N{RIGHT-TO-LEFT OVERRIDE}\n"
                "FAIL: binding compile failed error: -DAPI_SECRET=super-secret-token "
                "body=must-not-appear https://example.invalid/private\x00\n"
            ),
            stderr="FAIL: HAProxy ModSecurity binding source did not compile\n",
        )

        diagnostics = components.haproxy_failure_diagnostic_lines(proc)
        rendered = "\n".join(diagnostics)

        self.assertIn("classification=compiler_fatal_error", rendered)
        self.assertIn("missing_header=transaction.h", rendered)
        self.assertIn("classification=compiler_error", rendered)
        self.assertIn("build_step=modsecurity_binding_source_compile", rendered)
        self.assertNotIn("super-secret-token", rendered)
        self.assertNotIn("must-not-appear", rendered)
        self.assertNotIn("https://example.invalid/private", rendered)
        self.assertNotIn("hidden", rendered)
        self.assertNotIn("\x1b", rendered)
        self.assertNotIn("\N{RIGHT-TO-LEFT OVERRIDE}", rendered)
        self.assertNotIn("\x00", rendered)
        self.assertLessEqual(len(diagnostics), components.HAPROXY_FAILURE_DIAGNOSTIC_MAX_LINES)

    def test_haproxy_binding_failure_preserves_status_and_emits_safe_summary(self) -> None:
        record, diagnostic, _ = self.prepare_haproxy_binding_failure_with(
            23,
            "FAIL: HAProxy ModSecurity binding self-test source did not compile\n"
            "Authorization: Bearer hidden \x1b[31mhttps://example.invalid/private"
            "\N{RIGHT-TO-LEFT OVERRIDE}\n",
        )
        self.assertEqual(record["status"], "failed")
        self.assertEqual(record["blocker_reason"], "haproxy_connector_build_failed")
        self.assertEqual(record["build_exit_code"], 23)
        self.assertIn("target=build-modsecurity-binding build-spoa-runtime", diagnostic)
        self.assertIn("build_log=private_task_owned_haproxy-build.log", diagnostic)
        self.assertIn("build_step=modsecurity_binding_self_test_source_compile", diagnostic)
        self.assertNotIn("hidden", diagnostic)
        self.assertNotIn("https://example.invalid/private", diagnostic)
        self.assertNotIn("\x1b", diagnostic)
        self.assertNotIn("\N{RIGHT-TO-LEFT OVERRIDE}", diagnostic)

    def test_haproxy_binding_missing_artifacts_remain_failure(self) -> None:
        record, diagnostic, _ = self.prepare_haproxy_binding_failure_with(0, "unclassified output\n")

        self.assertEqual(record["status"], "failed")
        self.assertEqual(record["blocker_reason"], "haproxy_connector_build_failed")
        self.assertEqual(record["build_exit_code"], 0)
        self.assertIn("missing_artifact=spoa_runtime_binary", diagnostic)
        self.assertIn("missing_artifact=modsecurity_binding_paths", diagnostic)
        self.assertNotIn("unclassified output", diagnostic)

    def test_haproxy_binding_failure_cleans_transactional_staging(self) -> None:
        record, _, cleanup_observations = self.prepare_haproxy_binding_failure_with(
            2,
            "fatal error: required-header.h: No such file or directory\n",
        )

        self.assertEqual(record["status"], "failed")
        self.assertEqual(len(cleanup_observations), 1)
        cleanup_path, exists_after_cleanup = cleanup_observations[0]
        self.assertIn(".tmp-", cleanup_path.name)
        self.assertFalse(exists_after_cleanup)

    def test_haproxy_binding_failure_diagnostic_limits_classifications_and_handles_empty_output(self) -> None:
        proc = subprocess.CompletedProcess(
            args=["make"],
            returncode=2,
            stdout=(
                "fatal error: modsecurity/modsecurity.h: No such file or directory\n"
                "fatal error: modsecurity/rules_set.h: No such file or directory\n"
                "fatal error: modsecurity/transaction.h: No such file or directory\n"
                "FAIL: HAProxy ModSecurity binding source did not compile\n"
                "FAIL: HAProxy ModSecurity binding self-test source did not compile\n"
                "FAIL: HAProxy ModSecurity binding self-test did not link\n"
            ),
            stderr=None,
        )

        diagnostics = components.haproxy_failure_diagnostic_lines(proc)

        self.assertEqual(len(diagnostics), components.HAPROXY_FAILURE_DIAGNOSTIC_MAX_LINES)
        self.assertEqual(diagnostics[-1], "[classification list truncated]")
        self.assertEqual(
            components.haproxy_failure_diagnostic_lines(
                subprocess.CompletedProcess(args=["make"], returncode=2, stdout=None, stderr=None)
            ),
            [],
        )

    def test_haproxy_binding_failure_diagnostic_keeps_order_at_exact_limit(self) -> None:
        proc = subprocess.CompletedProcess(
            args=["make"],
            returncode=2,
            stdout=(
                "fatal error: modsecurity/modsecurity.h: No such file or directory\n"
                "fatal error: modsecurity/rules_set.h: No such file or directory\n"
                "fatal error: modsecurity/transaction.h: No such file or directory\n"
                "FAIL: HAProxy ModSecurity binding source did not compile for diagnostic SPOP runtime\n"
                "FAIL: HAProxy ModSecurity SPOA runtime source did not compile\n"
                "FAIL: HAProxy ModSecurity binding source did not compile\n"
            ),
            stderr=None,
        )

        self.assertEqual(
            components.haproxy_failure_diagnostic_lines(proc),
            [
                components.HAPROXY_DIAGNOSTIC_COMPILER_FATAL_ERROR,
                "missing_header=modsecurity.h",
                "missing_header=rules_set.h",
                "missing_header=transaction.h",
                components.HAPROXY_DIAGNOSTIC_COMPILER_ERROR,
                "build_step=spoa_binding_source_compile",
                "build_step=spoa_runtime_source_compile",
                "build_step=modsecurity_binding_source_compile",
            ],
        )

    def test_haproxy_binding_failure_diagnostic_accepts_known_stdout_or_stderr_only(self) -> None:
        known_message = "FAIL: HAProxy ModSecurity SPOA runtime source did not compile\n"
        expected = {"classification=compiler_error", "build_step=spoa_runtime_source_compile"}

        for output_name in ("stdout", "stderr"):
            with self.subTest(output_name=output_name):
                proc = subprocess.CompletedProcess(
                    args=["make"],
                    returncode=2,
                    stdout=known_message if output_name == "stdout" else "",
                    stderr=known_message if output_name == "stderr" else "",
                )
                self.assertEqual(set(components.haproxy_failure_diagnostic_lines(proc)), expected)

        rejected = subprocess.CompletedProcess(
            args=["make"],
            returncode=2,
            stdout=(
                "FAIL: build https://example.invalid/Authorization: Bearer hidden\n"
                "error: body=must-not-appear API_SECRET=super-secret-token\n"
            ),
            stderr=None,
        )
        self.assertEqual(components.haproxy_failure_diagnostic_lines(rejected), [])

    def test_haproxy_binding_build_replaces_invalid_tool_output_without_broadening_run_env(self) -> None:
        command = [
            sys.executable,
            "-c",
            "import sys; sys.stderr.buffer.write(bytes([255]) + b'\\nFAIL: HAProxy Common SDK source did not compile: /private/source.c\\n'); raise SystemExit(2)",
        ]

        with self.assertRaises(UnicodeDecodeError):
            components.run_env(command)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tools = root / "tools"
            tools.mkdir()
            fake_make = tools / "make"
            fake_make.write_text(
                "#!" + sys.executable + "\n" + command[2] + "\n",
                encoding="utf-8",
            )
            fake_make.chmod(0o700)
            log_path = root / "private-build.log"

            proc = components.run_haproxy_binding_build(
                root / "connector",
                {"PATH": str(tools)},
                log_path,
            )
            logged_output = log_path.read_text(encoding="utf-8")

        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stdout, "")
        self.assertEqual(proc.stderr, "\ufffd\nFAIL: HAProxy Common SDK source did not compile: /private/source.c\n")
        self.assertIn("\ufffd", logged_output)
        self.assertEqual(
            components.haproxy_failure_diagnostic_lines(proc),
            [
                components.HAPROXY_DIAGNOSTIC_COMPILER_ERROR,
                "build_step=modsecurity_common_sdk_source_compile",
            ],
        )

    def test_haproxy_binding_failure_diagnostic_scans_stderr_before_stdout_with_fixed_values(self) -> None:
        proc = subprocess.CompletedProcess(
            args=["make"],
            returncode=2,
            stdout=(
                "FAIL: HAProxy ModSecurity SPOA runtime did not link with libmodsecurity\n"
                "Authorization: Bearer hidden\n"
            ),
            stderr=(
                "BLOCKED: HAProxy libModSecurity resolver: /private/resolver-token\n"
                "FAIL: HAProxy Common SDK source did not compile: /private/source.c\n"
            ),
        )

        diagnostics = components.haproxy_failure_diagnostic_lines(proc)

        self.assertEqual(
            diagnostics,
            [
                components.HAPROXY_DIAGNOSTIC_RESOLVER_ERROR,
                "build_step=modsecurity_resolver",
                components.HAPROXY_DIAGNOSTIC_COMPILER_ERROR,
                "build_step=modsecurity_common_sdk_source_compile",
                components.HAPROXY_DIAGNOSTIC_LINKER_ERROR,
                "build_step=spoa_runtime_link",
            ],
        )
        rendered = "\n".join(diagnostics)
        self.assertNotIn("/private", rendered)
        self.assertNotIn("hidden", rendered)

    def test_haproxy_binding_failure_diagnostic_maps_only_exact_resolver_sentinel_on_stderr(self) -> None:
        generic_resolver_diagnostics = [
            components.HAPROXY_DIAGNOSTIC_RESOLVER_ERROR,
            "build_step=modsecurity_resolver",
        ]

        for exact_sentinel, exact_diagnostics in (
            components.HAPROXY_RESOLVER_SENTINEL_DIAGNOSTICS.items()
        ):
            expected_exact_diagnostics = list(exact_diagnostics)
            cases = (
                ("exact_stderr", "", exact_sentinel, expected_exact_diagnostics),
                ("crlf_stderr", "", exact_sentinel + "\r\n", expected_exact_diagnostics),
                (
                    "double_cr_suffix",
                    "",
                    exact_sentinel + "\r\r\n",
                    generic_resolver_diagnostics,
                ),
                (
                    "untrusted_suffix",
                    "",
                    exact_sentinel + " Authorization: Bearer hidden body=private",
                    generic_resolver_diagnostics,
                ),
                ("exact_stdout", exact_sentinel, "", generic_resolver_diagnostics),
                (
                    "unknown_stderr",
                    "",
                    "BLOCKED: HAProxy libModSecurity resolver: /private/resolver-token",
                    generic_resolver_diagnostics,
                ),
            )

            for name, stdout, stderr, expected in cases:
                with self.subTest(sentinel=exact_sentinel, name=name):
                    diagnostics = components.haproxy_failure_diagnostic_lines(
                        subprocess.CompletedProcess(
                            args=["make"], returncode=77, stdout=stdout, stderr=stderr
                        )
                    )

                    self.assertEqual(diagnostics, expected)
                    rendered = "\n".join(diagnostics)
                    self.assertNotIn("hidden", rendered)
                    self.assertNotIn("private", rendered)

    def test_haproxy_resolver_cause_diagnostics_rejects_unknown_cause(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown HAProxy resolver diagnostic cause"):
            components.haproxy_resolver_cause_diagnostics("untrusted-cause")

    def test_haproxy_multi_header_resolver_sentinels_are_exact_and_fixed(self) -> None:
        causes = (
            "headers_modsecurity_h_and_rules_set_h_missing",
            "headers_modsecurity_h_and_transaction_h_missing",
            "headers_rules_set_h_and_transaction_h_missing",
            "headers_modsecurity_h_and_rules_set_h_and_transaction_h_missing",
        )
        for cause in causes:
            with self.subTest(cause=cause):
                sentinel = components.HAPROXY_RESOLVER_SENTINEL_PREFIX + cause
                self.assertEqual(
                    components.HAPROXY_RESOLVER_SENTINEL_DIAGNOSTICS[sentinel],
                    (
                        components.HAPROXY_DIAGNOSTIC_RESOLVER_ERROR,
                        "build_step=modsecurity_resolver",
                        f"resolver_cause={cause}",
                    ),
                )

    def test_haproxy_binding_failure_diagnostic_emits_only_safe_resolver_annotation(self) -> None:
        exact_sentinel, exact_diagnostics = next(
            iter(components.HAPROXY_RESOLVER_SENTINEL_DIAGNOSTICS.items())
        )
        expected_annotation = (
            "::error title=HAProxy resolver diagnostic::" f"{exact_diagnostics[-1]}"
        )
        cases = (
            (
                "exact_stderr",
                "",
                exact_sentinel + "\nBLOCKED: HAProxy libModSecurity resolver: /private/detail",
                True,
            ),
            (
                "suffix_stderr",
                "",
                exact_sentinel + " Authorization: Bearer hidden body=private",
                False,
            ),
            ("stdout_only", exact_sentinel, "", False),
            (
                "unknown_stderr",
                "",
                "BLOCKED: HAProxy libModSecurity resolver: /private/resolver-token",
                False,
            ),
            (
                "overlong_stderr",
                "",
                exact_sentinel + "x" * components.HAPROXY_FAILURE_DIAGNOSTIC_MAX_LINE_CHARS,
                False,
            ),
        )

        for name, stdout, stderr, expect_annotation in cases:
            with self.subTest(name=name):
                proc = subprocess.CompletedProcess(
                    args=["make"], returncode=77, stdout=stdout, stderr=stderr
                )
                with mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}):
                    with mock.patch.object(components.sys, "stderr", new_callable=io.StringIO) as output:
                        components.emit_haproxy_binding_failure_diagnostic(proc, ())
                rendered = output.getvalue()

                if expect_annotation:
                    self.assertIn(expected_annotation, rendered)
                    self.assertEqual(rendered.count("::error title=HAProxy resolver diagnostic::"), 1)
                else:
                    self.assertNotIn("::error title=HAProxy resolver diagnostic::", rendered)
                self.assertNotIn("hidden", rendered)
                self.assertNotIn("/private", rendered)
                self.assertNotIn("resolver-token", rendered)

    def test_haproxy_binding_failure_diagnostic_stops_after_bounded_untrusted_output(self) -> None:
        proc = subprocess.CompletedProcess(
            args=["make"],
            returncode=2,
            stdout="FAIL: HAProxy Common SDK source did not compile: /private/stdout-source.c\n",
            stderr=(
                "Authorization: Bearer hidden\n"
                * components.HAPROXY_FAILURE_DIAGNOSTIC_SCAN_MAX_LINES
                + "FAIL: HAProxy Common SDK source did not compile: /private/source.c\n"
            ),
        )

        diagnostics = components.haproxy_failure_diagnostic_lines(proc)

        self.assertEqual(
            diagnostics,
            [
                components.HAPROXY_DIAGNOSTIC_COMPILER_ERROR,
                "build_step=modsecurity_common_sdk_source_compile",
            ],
        )
        self.assertNotIn("hidden", "\n".join(diagnostics))

    def test_haproxy_binding_failure_diagnostic_accepts_maximum_line_and_stops_on_overlong_line(self) -> None:
        marker = "FAIL: HAProxy Common SDK source did not compile: /private/source.c\n"
        maximum_line = "x" * components.HAPROXY_FAILURE_DIAGNOSTIC_MAX_LINE_CHARS
        expected = [
            components.HAPROXY_DIAGNOSTIC_COMPILER_ERROR,
            "build_step=modsecurity_common_sdk_source_compile",
        ]

        accepted = subprocess.CompletedProcess(
            args=["make"], returncode=2, stdout="", stderr=f"{maximum_line}\n{marker}"
        )
        rejected = subprocess.CompletedProcess(
            args=["make"], returncode=2, stdout="", stderr=f"{maximum_line}x\n{marker}"
        )

        self.assertEqual(components.haproxy_failure_diagnostic_lines(accepted), expected)
        self.assertEqual(components.haproxy_failure_diagnostic_lines(rejected), [])

    def test_haproxy_binding_failure_footer_emits_first_allowlisted_target(self) -> None:
        proc = subprocess.CompletedProcess(
            args=["make"],
            returncode=2,
            stdout=(
                "make: *** [Makefile:12: build-spoa-runtime] Error 2\n"
            ),
            stderr=(
                "make[1]: *** [build-modsecurity-binding] Error 2\n"
                "make: *** [Makefile:13: build-spoa-runtime] Error 2\n"
            ),
        )

        self.assertEqual(
            components.haproxy_failure_target_from_footers(proc),
            "build-modsecurity-binding",
        )
        self.assertIn(
            "target_failure=build-modsecurity-binding",
            components.haproxy_failure_diagnostic_lines(proc),
        )

    def test_haproxy_binding_failure_footer_accepts_exact_make_grammar(self) -> None:
        expected_target_paths = {
            "build-modsecurity-binding": "/task/haproxy-modsecurity-binding-self-test",
            "build-spoa-runtime": "/task/haproxy-modsecurity-spoa",
        }
        cases = (
            ("make: *** [build-modsecurity-binding] Error 2", "build-modsecurity-binding"),
            ("make[001]: *** [Makefile:7:\tbuild-spoa-runtime] Error 12", "build-spoa-runtime"),
            (
                "make[0]: *** [Makefile:224:/task/haproxy-modsecurity-binding-self-test] Error 2",
                "build-modsecurity-binding",
            ),
            ("make: *** [Makefile:198:/task/haproxy-modsecurity-spoa] Error 2", "build-spoa-runtime"),
        )

        for footer, expected_target in cases:
            with self.subTest(footer=footer):
                proc = subprocess.CompletedProcess(
                    args=["make"], returncode=2, stdout="", stderr=f"{footer}\n"
                )
                self.assertEqual(
                    components.haproxy_failure_target_from_footers(proc, expected_target_paths),
                    expected_target,
                )

    def test_haproxy_binding_failure_footer_rejects_malformed_or_adversarial_grammar(self) -> None:
        adversarial_prefix = "location:1:" * 2048
        footers = (
            "make[one]: *** [build-modsecurity-binding] Error 2",
            "make[１２]: *** [build-modsecurity-binding] Error 2",
            "make: *** [build-modsecurity-binding] Error ٢",
            "make: *** [build-modsecurity-binding] Error",
            "make: *** [build-modsecurity-binding] Error 2 unexpected",
            f"make: *** [{adversarial_prefix}build-modsecurity-binding Error 2",
        )

        for footer in footers:
            with self.subTest(footer=footer[:80]):
                proc = subprocess.CompletedProcess(
                    args=["make"], returncode=2, stdout="", stderr=f"{footer}\n"
                )
                self.assertIsNone(components.haproxy_failure_target_from_footers(proc))
                self.assertNotIn("target_failure=", components.haproxy_failure_diagnostic_lines(proc))

    def test_haproxy_binding_failure_footer_maps_only_the_expected_output_path(self) -> None:
        expected_target_paths = {
            "build-modsecurity-binding": "/task/build/haproxy-modsecurity-binding/"
            "haproxy-modsecurity-binding-self-test",
            "build-spoa-runtime": "/task/build/haproxy-spoa-runtime/haproxy-modsecurity-spoa",
        }
        proc = subprocess.CompletedProcess(
            args=["make"],
            returncode=2,
            stdout="",
            stderr=(
                "make: *** [Makefile:224: /task/build/haproxy-modsecurity-binding/"
                "haproxy-modsecurity-binding-self-test] Error 2\n"
            ),
        )
        spoa = subprocess.CompletedProcess(
            args=["make"],
            returncode=2,
            stdout="",
            stderr=(
                "make: *** [Makefile:198: /task/build/haproxy-spoa-runtime/"
                "haproxy-modsecurity-spoa] Error 2\n"
            ),
        )
        ordered = subprocess.CompletedProcess(
            args=["make"],
            returncode=2,
            stdout="",
            stderr=proc.stderr + spoa.stderr,
        )
        rejected = subprocess.CompletedProcess(
            args=["make"],
            returncode=2,
            stdout="",
            stderr=(
                "make: *** [Makefile:224: /other/build/haproxy-modsecurity-binding/"
                "haproxy-modsecurity-binding-self-test] Error 2\n"
            ),
        )

        self.assertEqual(
            components.haproxy_failure_target_from_footers(proc, expected_target_paths),
            "build-modsecurity-binding",
        )
        self.assertIn(
            "target_failure=build-modsecurity-binding",
            components.haproxy_failure_diagnostic_lines(proc, expected_target_paths),
        )
        self.assertIsNone(
            components.haproxy_failure_target_from_footers(rejected, expected_target_paths)
        )
        self.assertNotIn(
            "target_failure=",
            components.haproxy_failure_diagnostic_lines(rejected, expected_target_paths),
        )
        self.assertEqual(
            components.haproxy_failure_target_from_footers(spoa, expected_target_paths),
            "build-spoa-runtime",
        )
        self.assertEqual(
            components.haproxy_failure_target_from_footers(ordered, expected_target_paths),
            "build-modsecurity-binding",
        )

    def test_haproxy_binding_failure_footer_ignores_stdout_target_like_text(self) -> None:
        proc = subprocess.CompletedProcess(
            args=["make"],
            returncode=2,
            stdout="make: *** [Makefile:12: build-modsecurity-binding] Error 2\n",
            stderr="compiler output only\n",
        )

        self.assertIsNone(components.haproxy_failure_target_from_footers(proc))
        self.assertNotIn(
            "target_failure=",
            components.haproxy_failure_diagnostic_lines(proc),
        )

    def test_haproxy_binding_failure_footer_rejects_unallowlisted_or_hostile_target(self) -> None:
        proc = subprocess.CompletedProcess(
            args=["make"],
            returncode=2,
            stdout="make: *** [Makefile:11: build-spoa-runtime] Error 2\n",
            stderr=(
                "make: *** [Makefile:12: not-allowlisted] Error 2\n"
                "make: *** [Makefile:13: build-modsecurity-binding; touch /tmp/pwned] Error 2\n"
            ),
        )

        self.assertIsNone(components.haproxy_failure_target_from_footers(proc))
        self.assertNotIn(
            "target_failure=",
            components.haproxy_failure_diagnostic_lines(proc),
        )

    def test_haproxy_binding_failure_footer_keeps_failed_status_exit_and_safe_summary(self) -> None:
        record, diagnostic, _ = self.prepare_haproxy_binding_failure_with(
            17,
            "make: *** [Makefile:24: build-modsecurity-binding] Error 2\n"
            "Authorization: Bearer hidden\n",
        )

        self.assertEqual(record["status"], "failed")
        self.assertEqual(record["build_exit_code"], 17)
        self.assertIn("target_failure=build-modsecurity-binding", diagnostic)
        self.assertNotIn("Makefile:24", diagnostic)
        self.assertNotIn("hidden", diagnostic)

    def test_haproxy_missing_prerequisite_remains_blocked(self) -> None:
        record = self.prepare_haproxy_with(
            77,
            "haproxy_prepare: blocked missing required command for build HAProxy: make\n",
        )
        self.assertEqual(record["status"], "blocked")
        self.assertNotIn("build_exit_code", record)

    def haproxy_prepare_framework_root(self) -> Path:
        configured_root = os.environ.get("MODSECURITY_FRAMEWORK_TEST_ROOT")
        framework_root = (
            Path(configured_root)
            if configured_root
            else source_path('modules/ModSecurity-test-Framework', root=ROOT)
        )
        trusted_root, error = trusted_framework_root(ROOT, framework_root)
        if trusted_root is None:
            self.skipTest(error)
        script = trusted_root / "ci" / "provisioning" / "prepare-haproxy-runtime.sh"
        if not script.is_file():
            self.fail(
                "HAProxy prepare framework source is unavailable; initialize the checked-out "
                "submodule or set MODSECURITY_FRAMEWORK_TEST_ROOT to a reviewed read-only source"
            )
        return trusted_root

    def haproxy_prepare_enforces_split_build_root_containment(self, framework_root: Path) -> bool:
        script = framework_root / "ci" / "provisioning" / "prepare-haproxy-runtime.sh"
        source = script.read_text(encoding="utf-8")
        return all(
            f'require_under_build_root "${name}" {name}' in source
            for name in (
                "HAPROXY_RUNTIME_BUILD_DIR",
                "HAPROXY_RUNTIME_BUILD_WORKTREE",
                "HAPROXY_RUNTIME_DIR",
                "HAPROXY_BIN",
            )
        )

    def haproxy_prepare_framework_revision(self, framework_root: Path) -> str:
        result = subprocess.run(
            ["git", "-C", str(framework_root), "rev-parse", "HEAD"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        revision = result.stdout.strip()
        if result.returncode != 0 or len(revision) != 40:
            self.fail(
                "HAProxy prepare Framework source must expose a checked-out revision for "
                f"the split-BUILD_ROOT containment control: {result.stderr}"
            )
        return revision

    def managed_haproxy_cache_environment(
        self,
        root: Path,
        *,
        managed: bool,
        separate_build_root: bool = False,
        haproxy_version: str = TEST_HAPROXY_LOCKED_VERSION,
        haproxy_source_url: str = TEST_HAPROXY_LOCKED_SOURCE_URL,
        haproxy_sha256: str = TEST_HAPROXY_LOCKED_SHA256,
    ) -> dict[str, str]:
        cache_root = root / "cache-v2" / "shared"
        cache_root.mkdir(parents=True)
        identity = {
            "cache_schema_version": 2,
            "component": "haproxy",
            "configuration_flags": {},
        }
        cache_key = hashlib.sha256(
            json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        identity["cache_key"] = cache_key
        entry = cache_root / "builds" / "connectors" / "haproxy" / cache_key
        runtime_build = entry / "haproxy-runtime-build"
        runtime_worktree = runtime_build / "worktree"
        runtime_dir = entry / "haproxy-runtime" / "haproxy"
        binary = runtime_dir / "sbin" / "haproxy"
        runtime_worktree.mkdir(parents=True)
        binary.parent.mkdir(parents=True)
        binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        binary.chmod(0o755)
        binary_sha256 = hashlib.sha256(binary.read_bytes()).hexdigest()
        (runtime_dir / "haproxy.provenance").write_text(
            "\n".join(
                (
                    f"haproxy_version={haproxy_version}",
                    f"haproxy_source_url={haproxy_source_url}",
                    f"haproxy_sha256={haproxy_sha256}",
                    f"haproxy_binary_sha256={binary_sha256}",
                    "",
                )
            ),
            encoding="utf-8",
        )
        (entry / "manifest.json").write_text(
            json.dumps(
                {
                    "status": "complete",
                    "cache_schema_version": 2,
                    "connector": "haproxy",
                    "build_root": str(entry),
                    "connector_build_id": cache_key,
                    "cache_key": cache_key,
                    "cache_identity": identity,
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )

        if managed:
            (cache_root / ".msconnector-runtime-cache-root.json").write_text(
                json.dumps(
                    {
                        "kind": "msconnector-runtime-cache-root",
                        "schema_version": 2,
                        "cache_root": str(cache_root),
                    },
                    sort_keys=True,
                ),
                encoding="utf-8",
            )
            marker_key = hashlib.sha256(
                json.dumps({"entry_path": str(entry)}, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            marker_dir = cache_root / ".msconnector-runtime-cache-entries"
            marker_dir.mkdir()
            (marker_dir / f"{marker_key}.json").write_text(
                json.dumps(
                    {
                        "kind": "msconnector-runtime-cache-entry",
                        "schema_version": 2,
                        "cache_root": str(cache_root),
                        "entry_path": str(entry),
                        "component": "connector:haproxy",
                        "cache_key": cache_key,
                        "cache_identity": identity,
                        "status": "complete",
                    },
                    sort_keys=True,
                ),
                encoding="utf-8",
            )

        build_root = root / "connector-run" / "build" if separate_build_root else entry
        return {
            "CONNECTOR_ROOT": str(ROOT),
            "FRAMEWORK_ROOT": str(self.haproxy_prepare_framework_root()),
            "VERIFIED_RUN_ROOT": str(root / "connector-run"),
            "CACHE_ROOT": str(cache_root.parent),
            "VERIFIED_COMPONENT_CACHE": str(cache_root),
            "CONNECTOR_COMPONENT_CACHE": str(cache_root),
            "SOURCE_ROOT": str(cache_root / "sources"),
            "BUILD_ROOT": str(build_root),
            "TMP_ROOT": str(build_root / "tmp"),
            "LOG_ROOT": str(build_root / "logs"),
            "LOG_DIR": str(build_root / "logs" / "haproxy-prepare"),
            "HAPROXY_SOURCE_ROOT": str(cache_root / "sources" / "haproxy"),
            "HAPROXY_DOWNLOAD_DIR": str(cache_root / "archives" / "haproxy"),
            "HAPROXY_VERSION": haproxy_version,
            "HAPROXY_SOURCE_URL": haproxy_source_url,
            "HAPROXY_SHA256_URL": f"{haproxy_source_url}.sha256",
            "HAPROXY_SHA256": haproxy_sha256,
            "HAPROXY_SOURCE_DIR": str(cache_root / "sources" / "haproxy" / f"haproxy-{haproxy_version}"),
            "HAPROXY_RUNTIME_BUILD_DIR": str(runtime_build),
            "HAPROXY_RUNTIME_BUILD_WORKTREE": str(runtime_worktree),
            "HAPROXY_RUNTIME_DIR": str(runtime_dir),
            "HAPROXY_BIN": str(binary),
            "PYTHON": sys.executable,
        }

    def run_haproxy_prepare_with_shared_cache(self, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
        framework_root = Path(env["FRAMEWORK_ROOT"])
        return subprocess.run(
            ["sh", str(framework_root / "ci" / "provisioning" / "prepare-haproxy-runtime.sh")],
            cwd=ROOT,
            env={**os.environ, **env},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_haproxy_prepare_reuses_complete_managed_shared_cache_entry(self) -> None:
        with tempfile.TemporaryDirectory(prefix="haproxy-managed-cache-") as temporary:
            result = self.run_haproxy_prepare_with_shared_cache(
                self.managed_haproxy_cache_environment(Path(temporary), managed=True)
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ready existing provenance-verified binary", result.stdout)

    def test_haproxy_prepare_reuses_complete_entry_without_cache_marker(self) -> None:
        with tempfile.TemporaryDirectory(prefix="haproxy-unmanaged-cache-") as temporary:
            result = self.run_haproxy_prepare_with_shared_cache(
                self.managed_haproxy_cache_environment(Path(temporary), managed=False)
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ready existing provenance-verified binary", result.stdout)

    def test_haproxy_prepare_does_not_rebuild_a_verified_runtime_binary(self) -> None:
        with tempfile.TemporaryDirectory(prefix="haproxy-verified-runtime-") as temporary:
            env = self.managed_haproxy_cache_environment(Path(temporary), managed=True)
            result = self.run_haproxy_prepare_with_shared_cache(env)
            self.assertFalse((Path(env["HAPROXY_RUNTIME_BUILD_WORKTREE"]) / "Makefile").exists())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ready existing provenance-verified binary", result.stdout)

    def test_haproxy_prepare_rejects_unapproved_future_provenance_before_runtime_lock(self) -> None:
        with tempfile.TemporaryDirectory(prefix="haproxy-future-pin-") as temporary:
            env = self.managed_haproxy_cache_environment(
                Path(temporary),
                managed=True,
                haproxy_version=TEST_HAPROXY_UNAPPROVED_FUTURE_VERSION,
                haproxy_source_url=TEST_HAPROXY_UNAPPROVED_FUTURE_SOURCE_URL,
                haproxy_sha256=TEST_HAPROXY_UNAPPROVED_FUTURE_SHA256,
            )
            result = self.run_haproxy_prepare_with_shared_cache(env)
            self.assertEqual(env["HAPROXY_VERSION"], TEST_HAPROXY_UNAPPROVED_FUTURE_VERSION)
            self.assertEqual(env["HAPROXY_SOURCE_URL"], TEST_HAPROXY_UNAPPROVED_FUTURE_SOURCE_URL)
            self.assertEqual(env["HAPROXY_SHA256"], TEST_HAPROXY_UNAPPROVED_FUTURE_SHA256)
            self.assertEqual(
                Path(env["HAPROXY_SOURCE_DIR"]).name,
                f"haproxy-{TEST_HAPROXY_UNAPPROVED_FUTURE_VERSION}",
            )
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertIn(
            "BLOCKED: HAPROXY_VERSION override is not permitted",
            result.stdout + result.stderr,
        )
        self.assertNotIn("runtime-component-lock:", result.stdout + result.stderr)

    def test_haproxy_prepare_rejects_shared_cache_runtime_with_separate_build_root(self) -> None:
        framework_root = self.haproxy_prepare_framework_root()
        if not self.haproxy_prepare_enforces_split_build_root_containment(framework_root):
            revision = self.haproxy_prepare_framework_revision(framework_root)
            if revision == LEGACY_FRAMEWORK_HAPROXY_CACHE_SHA:
                self.skipTest(
                    "the current Parent gitlink predates the candidate split-BUILD_ROOT containment "
                    "control; the Update submodules candidate must exercise this negative control"
                )
            self.fail(
                "selected Framework revision lacks required split-BUILD_ROOT HAProxy containment: "
                f"{revision}"
            )
        with tempfile.TemporaryDirectory(prefix="haproxy-split-build-root-") as temporary:
            env = self.managed_haproxy_cache_environment(
                Path(temporary),
                managed=True,
                separate_build_root=True,
            )
            result = self.run_haproxy_prepare_with_shared_cache(env)
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertIn(
            "HAPROXY_RUNTIME_BUILD_DIR must be under BUILD_ROOT",
            result.stdout + result.stderr,
        )



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
