from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from modsecurity_connector_tests.framework_test_trust import trusted_framework_root


ROOT = connector_root()
FRAMEWORK_ROOT = Path(
    os.environ.get(
        "PARENT_TEST_FRAMEWORK_ROOT",
        source_path('modules/ModSecurity-test-Framework', root=ROOT),
    )
)
PREPARE_PATH = source_path('ci/provisioning/components/prepare-runtime-components.py', root=ROOT)
RESERVE_PATH = source_path('ci/runtime/lifecycle/reserve-runtime-env-snapshot.sh', root=ROOT)
NATIVE_COMPARISON_PATH = source_path('ci/runtime/lifecycle/run-native-case-comparison.py', root=ROOT)

components = load_source(PREPARE_PATH)
native_comparison = load_source(NATIVE_COMPARISON_PATH)
MISMATCH_PATH = source_path('ci/evidence/reports/generate-verified-runtime-mismatch-analysis.py', root=ROOT)
runtime_mismatch = load_source(MISMATCH_PATH)


class RuntimeEnvironmentSnapshotContractTest(unittest.TestCase):
    def setUp(self) -> None:
        framework_root, error = trusted_framework_root(ROOT, FRAMEWORK_ROOT)
        if framework_root is None:
            self.skipTest(error)
        self.framework_root = framework_root

    def trusted_framework_environment(self) -> dict[str, str]:
        """Bind every Framework-executing child to the validated test root."""

        environment = os.environ.copy()
        environment["FRAMEWORK_ROOT"] = str(self.framework_root)
        return environment

    def test_child_environment_replaces_an_ambient_framework_root(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"FRAMEWORK_ROOT": "/untrusted/framework-root"},
            clear=False,
        ):
            environment = self.trusted_framework_environment()

        self.assertEqual(environment["FRAMEWORK_ROOT"], str(self.framework_root))

    def test_native_summary_and_mismatch_helpers_keep_outputs_with_reduced_context_parameters(self) -> None:
        with tempfile.TemporaryDirectory(prefix="native-summary-signatures-") as temporary:
            self.enterContext(mock.patch.object(runtime_mismatch, "INPUTS", runtime_mismatch.EvidenceInputs((ROOT, Path(temporary)))))
            root = Path(temporary)
            with (
                mock.patch.object(native_comparison, "build_metadata", return_value={}),
                mock.patch.object(native_comparison, "generated_json_text", return_value="{}\n"),
                mock.patch.object(native_comparison, "generated_markdown_text", return_value="# test\n"),
            ):
                summary = native_comparison.write_summary_report(
                    ROOT,
                    FRAMEWORK_ROOT,
                    root / "verified-runs",
                    (),
                    [],
                    root / "summary",
                )

            inventory = native_comparison.inventory()
            self.assertEqual(summary["payload"]["tool_inventory"], inventory)
            self.assertTrue(Path(summary["json"]).is_file())
            self.assertTrue(Path(summary["md"]).is_file())

            matrix_root = root / "matrix"
            job_path = matrix_root / "no-crs" / "no-mrts" / "apache" / "job.json"
            job_path.parent.mkdir(parents=True)
            job_path.write_text(
                json.dumps(
                    {
                        "connector": "apache",
                        "test_variant": "no-crs",
                        "mrts_variant": "no-mrts",
                        "return_code": 1,
                        "status": "blocked",
                        "summary_path": "",
                    }
                ),
                encoding="utf-8",
            )
            incomplete = runtime_mismatch.collect_incomplete_jobs(matrix_root, root / "build", None)
            self.assertEqual(len(incomplete), 1)
            self.assertEqual(incomplete[0]["connector"], "apache")
            self.assertEqual(incomplete[0]["variant"], "no-crs/no-mrts")
            self.assertEqual(
                runtime_mismatch.variant_from_result_path(
                    matrix_root / "with-crs" / "with-mrts" / "nginx" / "nginx-summary.json",
                    matrix_root,
                    "full_matrix",
                ),
                "with-crs/with-mrts",
            )

    def test_ready_nginx_snapshot_values_bind_the_parent_common_source_root(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-env-nginx-common-source-") as temporary:
            root = Path(temporary)
            connector_root = root / "connector"
            common_source_root = connector_root / "common" / "src"
            common_source_root.mkdir(parents=True)
            cache_root = root / "cache-v2" / "shared"

            with mock.patch.dict(os.environ, {"MSCONNECTOR_COMMON_SRC": "/untrusted/job/path"}):
                values = components.nginx_runtime_environment(
                    connector_root,
                    cache_root,
                    {
                        "status": "reused",
                        "nginx_bin": "/runtime/nginx",
                        "module_dir": "/runtime/modules",
                        "module_file": "/runtime/modules/ngx_http_modsecurity_module.so",
                        "modsecurity_lib_dir": "/runtime/modsecurity/lib",
                        "build_path": "/runtime/nginx-build",
                        "nginx_prefix": "/runtime/prefix",
                        "connector_build_id": "cache-key",
                        "protocol_profile": "h1",
                    },
                )

            self.assertEqual(str(common_source_root), values["MSCONNECTOR_COMMON_SRC"])
            self.assertEqual(
                str(cache_root / "builds" / "connectors"),
                values["NGINX_BUILD_OWNER_ROOT"],
            )

    def test_unready_nginx_does_not_publish_runtime_snapshot_values(self) -> None:
        values = components.nginx_runtime_environment(
            Path("/connector"),
            Path("/cache"),
            {"status": "blocked"},
        )
        self.assertEqual(values, {})

    def test_full_smoke_nginx_snapshot_fails_closed_without_a_valid_managed_contract(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-env-nginx-contract-") as temporary:
            root = Path(temporary)
            connector_root = root / "connector"
            cache_root = root / "cache"
            ready_nginx = {
                "status": "built",
                "require_pinned_provenance": True,
                "nginx_bin": str(cache_root / "builds/connectors/nginx/cache-key/nginx/sbin/nginx"),
                "module_dir": str(cache_root / "builds/connectors/nginx/cache-key/nginx/modules"),
                "module_file": str(
                    cache_root / "builds/connectors/nginx/cache-key/nginx/modules/ngx_http_modsecurity_module.so"
                ),
                "modsecurity_lib_dir": str(cache_root / "modsecurity/lib"),
                "build_path": str(cache_root / "builds/connectors/nginx/cache-key/build"),
                "nginx_prefix": str(cache_root / "builds/connectors/nginx/cache-key/nginx"),
                "connector_build_id": "cache-key",
                "protocol_profile": "h1",
            }

            self.assertEqual(
                components.nginx_runtime_environment(connector_root, cache_root, ready_nginx),
                {},
            )
            self.assertEqual(
                components.nginx_runtime_environment(
                    connector_root,
                    cache_root,
                    {**ready_nginx, "runtime_contract_valid": False},
                ),
                {},
            )

            values = components.nginx_runtime_environment(
                connector_root,
                cache_root,
                {**ready_nginx, "runtime_contract_valid": True},
            )
            self.assertEqual(values["MRTS_NATIVE_NGINX_BIN"], ready_nginx["nginx_bin"])
            self.assertEqual(values["NGINX_PREFIX"], ready_nginx["nginx_prefix"])
            self.assertEqual(
                values["MSCONNECTOR_COMMON_SRC"],
                str(connector_root / "common" / "src"),
            )

    def test_snapshot_is_unique_local_atomic_and_keeps_shared_compatibility_export(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-env-snapshot-") as temporary:
            root = Path(temporary)
            cache_root = root / "cache-v2" / "shared"
            output_root = root / "build" / "nginx" / "run-1" / "runtime-component-reports"
            cache_root.mkdir(parents=True)
            shared_env = cache_root / "runtime-env.sh"
            shared_env.write_text("export COMPATIBILITY_ONLY='preserved'\n", encoding="utf-8")

            first = subprocess.run(
                ["sh", str(RESERVE_PATH), str(output_root)],
                cwd=ROOT,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            second = subprocess.run(
                ["sh", str(RESERVE_PATH), str(output_root)],
                cwd=ROOT,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(second.returncode, 0, second.stderr)
            first_snapshot = Path(first.stdout.strip())
            second_snapshot = Path(second.stdout.strip())
            self.assertNotEqual(first_snapshot, second_snapshot)
            self.assertTrue(first_snapshot.is_file())
            self.assertTrue(second_snapshot.is_file())

            components.write_runtime_env_snapshot(
                {
                    "CONNECTOR_COMPONENT_CACHE": str(cache_root),
                    "MODSECURITY_INCLUDE_DIR": "/runtime/modsecurity/include",
                    "MODSECURITY_LIB_DIR": "/runtime/modsecurity/lib",
                },
                snapshot_path=first_snapshot,
                output_root=output_root,
                target_connector="nginx",
                cache_root=cache_root,
            )

            # The mutable shared export stays untouched for reports and legacy
            # consumers.  The runner-only metadata exists only in the local
            # snapshot that replaced its placeholder atomically.
            self.assertEqual(
                shared_env.read_text(encoding="utf-8"),
                "export COMPATIBILITY_ONLY='preserved'\n",
            )
            self.assertFalse(list(output_root.glob(".runtime-env-snapshot.*.tmp-*")))
            loaded = subprocess.run(
                [
                    "sh",
                    "-c",
                    '. "$1"; printf "%s|%s|%s|%s" "$RUNTIME_COMPONENT_ENV_SNAPSHOT_TARGET" "$RUNTIME_COMPONENT_ENV_SNAPSHOT_CACHE" "$RUNTIME_COMPONENT_ENV_SNAPSHOT_SCHEMA" "$MODSECURITY_INCLUDE_DIR"',
                    "sh",
                    str(first_snapshot),
                ],
                cwd=ROOT,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(loaded.returncode, 0, loaded.stderr)
            self.assertEqual(
                loaded.stdout,
                f"nginx|{cache_root}|1|/runtime/modsecurity/include",
            )

    def test_snapshot_writer_rejects_a_path_outside_the_invocation_report_root(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-env-snapshot-") as temporary:
            root = Path(temporary)
            output_root = root / "connector-build" / "runtime-component-reports"
            with self.assertRaisesRegex(RuntimeError, "outside_output_root"):
                components.write_runtime_env_snapshot(
                    {},
                    snapshot_path=root / "other-run" / "runtime-env.sh",
                    output_root=output_root,
                    target_connector="shared",
                    cache_root=root / "cache-v2" / "shared",
                )

    def test_protected_nginx_broker_snapshot_uses_only_canonical_plan_outputs(self) -> None:
        with tempfile.TemporaryDirectory(prefix="protected-nginx-broker-snapshot-") as temporary:
            root = Path(temporary)
            cache_root = root / "cache-v2" / "shared"
            plan_root = cache_root / "builds" / "connectors" / "nginx" / "cache-key"
            binary = plan_root / "nginx" / "sbin" / "nginx"
            module = plan_root / "nginx" / "modules" / components.NGINX_MODULE_FILENAME
            prefix = cache_root / "prefix" / "modsecurity" / "modsecurity-build"
            for path, contents, mode in (
                (binary, "#!/bin/sh\nexit 0\n", 0o755),
                (module, "module\n", 0o644),
                (prefix / "lib" / components.MODSECURITY_LIBRARY_FILENAME, "library\n", 0o644),
                (prefix / "lib" / components.MODSECURITY_RUNTIME_LIBRARY_FILENAME, "runtime library\n", 0o644),
                (prefix / "include" / "modsecurity" / "modsecurity.h", "header\n", 0o644),
                (prefix / "include" / "modsecurity" / "rules_set.h", "header\n", 0o644),
                (prefix / "include" / "modsecurity" / "transaction.h", "header\n", 0o644),
            ):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(contents, encoding="utf-8")
                path.chmod(mode)
            output_root = root / "build" / "runtime-component-reports"
            snapshot = output_root / "runtime-env-snapshot.protected.sh"
            plan = {
                "root": str(plan_root),
                "manifest": str(plan_root / "manifest.json"),
                "output_paths": {"binary": str(binary), "module": str(module)},
                "cache_schema_version": components.CACHE_SCHEMA_VERSION,
                "cache_key": "cache-key",
                "connector_build_id": "cache-key",
                "build_flags": json.dumps(
                    {
                        "NGINX_RELEASE_TAG": components.NGINX_PINNED_RELEASE_TAG,
                        "NGINX_SOURCE_REPO_URL": components.NGINX_PINNED_SOURCE_REPOSITORY,
                        "NGINX_SHA256": components.NGINX_PINNED_RELEASE_ASSET_SHA256,
                    }
                ),
            }
            components.write_json(plan_root / "manifest.json", {"build_flags": plan["build_flags"]})
            context = {
                "target_connector": "nginx",
                "cache_root": cache_root,
                "connector_root": root / "connector",
                "framework_root": root / "framework",
                "output_root": output_root,
                "requested_runtime_env_snapshot": snapshot,
                "runtime_env_snapshot_contract": components.PROTECTED_NGINX_BROKER_SNAPSHOT_CONTRACT,
                "env": {
                    "NGINX_SOURCE_MODE": "github-release",
                    "NGINX_RELEASE_TAG": components.NGINX_PINNED_RELEASE_TAG,
                    "NGINX_SOURCE_REPO_URL": components.NGINX_PINNED_SOURCE_REPOSITORY,
                    "NGINX_SHA256": components.NGINX_PINNED_RELEASE_ASSET_SHA256,
                    # These must not influence the fixed snapshot values.
                    "NGINX_BINARY": "/ambient/nginx",
                    "NGINX_MODULE": "/ambient/module.so",
                    "MRTS_NATIVE_NGINX_BIN": "/ambient/mrts-nginx",
                    "MRTS_NATIVE_NGINX_MODULE_DIR": "/ambient/mrts-modules",
                },
            }
            component_records = {
                "nginx": {"status": "reused", "nginx_bin": "/ambient/nginx"},
                "nginx_plan": plan,
                "modsecurity": {"status": "reused", "build_id": "modsecurity-build", "prefix": str(prefix)},
            }
            context["components"] = component_records
            with (
                mock.patch.object(components, "connector_manifest_ready", return_value=True),
                mock.patch.object(components, "git_revision", side_effect=["b" * 40, "c" * 40]),
            ):
                written = components.write_runtime_environment_exports(
                    context,
                    {"UNRELATED_GENERIC_EXPORT": "must-not-appear"},
                )

            self.assertEqual(written, snapshot)
            self.assertEqual(
                snapshot.read_text(encoding="utf-8"),
                "export MODSECURITY_SHARED_PREFIX='{}'\n"
                "export NGINX_BINARY='{}'\n"
                "export NGINX_MODULE='{}'\n".format(prefix, binary, module),
            )
            provenance_path = output_root / components.TRUSTED_NGINX_BROKER_PROVENANCE_FILENAME
            record = json.loads(provenance_path.read_text(encoding="utf-8"))
            self.assertEqual(set(record), {"schema_version", "producer", "nginx", "modsecurity"})
            self.assertEqual(record["nginx"]["binary"]["path"], str(binary))
            self.assertEqual(record["nginx"]["module"]["path"], str(module))
            self.assertEqual(record["modsecurity"]["prefix"], str(prefix))
            self.assertEqual(
                record["modsecurity"]["library"]["path"],
                str(prefix / "lib" / components.MODSECURITY_RUNTIME_LIBRARY_FILENAME),
            )
            self.assertFalse(Path(record["modsecurity"]["library"]["path"]).is_symlink())
            self.assertIsInstance(record["nginx"]["binary"]["mode"], int)
            self.assertEqual(provenance_path.stat().st_mode & 0o777, 0o600)
            unsigned = json.loads(json.dumps(record))
            identity = unsigned["producer"].pop("identity")
            self.assertEqual(identity, components.stable_hash(unsigned))

            # A record or snapshot is never published from an ambient or
            # otherwise noncanonical plan output path.
            rejected_snapshot = output_root / "runtime-env-snapshot.rejected.sh"
            plan["output_paths"]["binary"] = "/ambient/nginx"
            context["requested_runtime_env_snapshot"] = rejected_snapshot
            with (
                mock.patch.object(components, "connector_manifest_ready", return_value=True),
                mock.patch.object(components, "git_revision", side_effect=["b" * 40, "c" * 40]),
                self.assertRaisesRegex(RuntimeError, "plan_output_paths_not_canonical"),
            ):
                components.write_runtime_environment_exports(context, {})
            self.assertFalse(rejected_snapshot.exists())

    def test_with_runner_consumes_the_prepared_snapshot_without_reading_shared_env(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-env-snapshot-") as temporary:
            root = Path(temporary)
            build_root = root / "build"
            cache_root = root / "cache-v2" / "shared"
            output_root = build_root / "runtime-component-reports"
            cache_root.mkdir(parents=True)
            # If the wrapper reopened this compatibility export, this sentinel
            # would replace the snapshot value asserted below.
            (cache_root / "runtime-env.sh").write_text(
                "export MODSECURITY_INCLUDE_DIR='/wrong/shared/value'\n",
                encoding="utf-8",
            )
            snapshot = output_root / "runtime-env-snapshot.prepared.sh"
            components.write_runtime_env_snapshot(
                {
                    "CONNECTOR_COMPONENT_CACHE": str(cache_root),
                    "MODSECURITY_INCLUDE_DIR": "/correct/invocation/value",
                },
                snapshot_path=snapshot,
                output_root=output_root,
                target_connector="shared",
                cache_root=cache_root,
            )

            result = subprocess.run(
                [
                    "sh",
                    str(source_path('ci/provisioning/cache/with-runtime-components.sh', root=ROOT)),
                    "sh",
                    "-c",
                    'printf "%s|%s" "$MODSECURITY_INCLUDE_DIR" "$RUNTIME_COMPONENT_ENV_SNAPSHOT"',
                ],
                cwd=ROOT,
                env={
                    **os.environ,
                    "CONNECTOR_ROOT": str(ROOT),
                    "FRAMEWORK_ROOT": str(FRAMEWORK_ROOT),
                    "VERIFIED_RUN_ROOT": str(root),
                    "VERIFIED_BUILD_ROOT": str(build_root),
                    "BUILD_ROOT": str(build_root),
                    "CACHE_ROOT": str(cache_root.parent),
                    "VERIFIED_COMPONENT_CACHE": str(cache_root),
                    "CONNECTOR_COMPONENT_CACHE": str(cache_root),
                    "RUNTIME_REPORT_OUTPUT_ROOT": str(output_root),
                    "RUNTIME_COMPONENT_TARGET": "shared",
                    "RUNTIME_COMPONENT_ENV_SNAPSHOT": str(snapshot),
                    "SKIP_RUNTIME_COMPONENT_PREPARE": "1",
                },
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout, f"/correct/invocation/value|{snapshot}")

    def test_native_comparison_uses_the_wrapper_snapshot_not_shared_env(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-env-snapshot-") as temporary:
            root = Path(temporary)
            cache_root = root / "cache-v2" / "shared"
            output_root = root / "build" / "runtime-component-reports"
            cache_root.mkdir(parents=True)
            (cache_root / "runtime-env.sh").write_text(
                "export MODSECURITY_INCLUDE_DIR='/wrong/shared/value'\n",
                encoding="utf-8",
            )
            snapshot = output_root / "runtime-env-snapshot.native-case.sh"
            components.write_runtime_env_snapshot(
                {
                    "CONNECTOR_COMPONENT_CACHE": str(cache_root),
                    "MODSECURITY_INCLUDE_DIR": "/correct/native-case/value",
                },
                snapshot_path=snapshot,
                output_root=output_root,
                target_connector="all",
                cache_root=cache_root,
            )

            with mock.patch.dict(
                os.environ,
                {
                    "VERIFIED_RUN_ROOT": str(root),
                    "VERIFIED_BUILD_ROOT": str(root / "build"),
                    "BUILD_ROOT": str(root / "build"),
                    "CACHE_ROOT": str(cache_root.parent),
                    "VERIFIED_COMPONENT_CACHE": str(cache_root),
                    "CONNECTOR_COMPONENT_CACHE": str(cache_root),
                    "RUNTIME_REPORT_OUTPUT_ROOT": str(output_root),
                    "RUNTIME_COMPONENT_ENV_SNAPSHOT": str(snapshot),
                },
                clear=False,
            ):
                loaded = native_comparison.load_runtime_env()
            self.assertEqual(loaded["MODSECURITY_INCLUDE_DIR"], "/correct/native-case/value")

    def test_native_comparison_does_not_fallback_to_shared_env_for_an_invalid_snapshot(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-env-snapshot-") as temporary:
            root = Path(temporary)
            cache_root = root / "cache-v2" / "shared"
            output_root = root / "build" / "runtime-component-reports"
            cache_root.mkdir(parents=True)
            (cache_root / "runtime-env.sh").write_text(
                "export MODSECURITY_INCLUDE_DIR='/wrong/shared/value'\n",
                encoding="utf-8",
            )
            outside_snapshot = root / "other-invocation" / "runtime-env.sh"

            with mock.patch.dict(
                os.environ,
                {
                    "VERIFIED_RUN_ROOT": str(root),
                    "VERIFIED_BUILD_ROOT": str(root / "build"),
                    "BUILD_ROOT": str(root / "build"),
                    "CACHE_ROOT": str(cache_root.parent),
                    "VERIFIED_COMPONENT_CACHE": str(cache_root),
                    "CONNECTOR_COMPONENT_CACHE": str(cache_root),
                    "RUNTIME_REPORT_OUTPUT_ROOT": str(output_root),
                    "RUNTIME_COMPONENT_ENV_SNAPSHOT": str(outside_snapshot),
                },
                clear=False,
            ):
                loaded = native_comparison.load_runtime_env()
            self.assertNotEqual(loaded.get("MODSECURITY_INCLUDE_DIR"), "/wrong/shared/value")

    def test_central_runners_use_the_exact_local_snapshot_not_shared_runtime_env(self) -> None:
        with_runner = (source_path('ci/provisioning/cache/with-runtime-components.sh', root=ROOT)).read_text(encoding="utf-8")
        remaining_runner = (source_path('ci/runtime/lifecycle/run-remaining-connector-target.sh', root=ROOT)).read_text(
            encoding="utf-8"
        )
        canonical_runner = (source_path('ci/runtime/lifecycle/run-no-crs-baseline.sh', root=ROOT)).read_text(
            encoding="utf-8"
        )
        stage_runner = (source_path('ci/runtime/lifecycle/run-connector-stage.sh', root=ROOT)).read_text(encoding="utf-8")

        for source in (with_runner, remaining_runner, canonical_runner):
            self.assertIn("runtime_env=$RUNTIME_COMPONENT_ENV_SNAPSHOT", source)
        self.assertNotIn('runtime_env="$CONNECTOR_COMPONENT_CACHE/runtime-env.sh"', with_runner)
        self.assertNotIn('runtime_env="$CONNECTOR_COMPONENT_CACHE/runtime-env.sh"', remaining_runner)
        self.assertNotIn("runtime_env=$CONNECTOR_COMPONENT_CACHE/runtime-env.sh", canonical_runner)

        self.assertIn(
            "RUNTIME_REPORT_OUTPUT_ROOT=$CONNECTOR_BUILD_ROOT/runtime-component-reports",
            canonical_runner,
        )
        self.assertIn(
            'RUNTIME_COMPONENT_ENV_SNAPSHOT="$RUNTIME_COMPONENT_ENV_SNAPSHOT"',
            canonical_runner,
        )
        self.assertIn(
            "modsecurity_prefix=$CONNECTOR_COMPONENT_CACHE/prefix/modsecurity/$modsecurity_build_id",
            canonical_runner,
        )
        self.assertNotIn(
            "modsecurity_prefix=$CACHE_ROOT/prefix/modsecurity/$modsecurity_build_id",
            canonical_runner,
        )
        self.assertIn(
            'host_binary=$("$PYTHON" "$TRAEFIK_HOST_BINARY_RESOLVER" \\',
            canonical_runner,
        )
        self.assertIn(
            "LIGHTTPD_HOST_BINARY_RESOLVER=$CONNECTOR_ROOT/ci/runtime/lifecycle/resolve-lighttpd-host-binary.py",
            canonical_runner,
        )
        self.assertIn(
            "\n".join(
                (
                    'host_binary=$("$PYTHON" "$LIGHTTPD_HOST_BINARY_RESOLVER" \\',
                    '                --build-root "$CONNECTOR_BUILD_ROOT")',
                )
            ),
            canonical_runner,
        )
        self.assertIn("inherited LIGHTTPD_BIN values", canonical_runner)
        self.assertNotIn(
            "host_binary=$CONNECTOR_COMPONENT_CACHE/lighttpd/bin/lighttpd",
            canonical_runner,
        )
        self.assertIn(
            'RUNTIME_COMPONENT_ENV_SNAPSHOT="${RUNTIME_COMPONENT_ENV_SNAPSHOT:-}"',
            stage_runner,
        )
        self.assertIn(
            "--runtime-env-snapshot \"$RUNTIME_COMPONENT_ENV_SNAPSHOT\"",
            (source_path('ci/provisioning/components/prepare-runtime-components.sh', root=ROOT)).read_text(encoding="utf-8"),
        )
        native_runner = NATIVE_COMPARISON_PATH.read_text(encoding="utf-8")
        self.assertIn("snapshot_value = env.get(\"RUNTIME_COMPONENT_ENV_SNAPSHOT\"", native_runner)
        self.assertIn("if snapshot_value:", native_runner)

    def test_full_smoke_matrix_pins_the_complete_nginx_release_tuple_for_both_variants(self) -> None:
        """The job-level NGINX tuple applies equally to both CRS variants.

        Keeping the assertion at the workflow boundary prevents a later matrix
        edit from silently reintroducing a floating NGINX source for one
        full-smoke variant while the other remains pinned.
        """
        workflow = (source_path('.github/workflows/test-full-smoke-sequential.yml', root=ROOT)).read_text(
            encoding="utf-8"
        )
        matrix_start = workflow.index("      matrix:\n        variant:\n")
        env_start = workflow.index("    env:\n", matrix_start)
        steps_start = workflow.index("    steps:\n", env_start)
        matrix_block = workflow[matrix_start:env_start]
        nginx_env = workflow[env_start:steps_start]

        for variant in ("no-crs", "with-crs"):
            with self.subTest(variant=variant):
                self.assertIn(f"          - {variant}\n", matrix_block)
                self.assertIn('BUILD_NGINX_FROM_SOURCE: "1"', nginx_env)
                self.assertIn("NGINX_SOURCE_MODE: github-release", nginx_env)
                self.assertIn("NGINX_SOURCE_REPO_URL: https://github.com/nginx/nginx", nginx_env)
                self.assertIn("NGINX_RELEASE_TAG: release-1.31.6", nginx_env)
                self.assertIn("NGINX_SOURCE_GIT_REF: release-1.31.6", nginx_env)
                self.assertIn("NGINX_RELEASE_ASSET_NAME: nginx-1.31.6.tar.gz", nginx_env)
                self.assertIn(
                    "NGINX_SHA256: 974ed5298a5e398e008704ed5db284e655fc270c596493dbccada452448fc9f1",
                    nginx_env,
                )
                self.assertIn('NGINX_REQUIRE_PINNED_PROVENANCE: "1"', nginx_env)

        self.assertNotIn("NGINX_RELEASE_TAG: latest", nginx_env)
        self.assertNotIn("NGINX_SOURCE_GIT_REF: latest", nginx_env)
        self.assertNotIn("NGINX_GITHUB_REPO:", nginx_env)
        self.assertNotRegex(
            nginx_env,
            r"""(?m)^\s*(?:["']MODSECURITY_GIT_REF["']|MODSECURITY_GIT_REF)\s*:""",
        )

    def test_with_crs_replaces_the_cache_owned_source_with_a_fresh_run_source(self) -> None:
        helper = source_path('ci/runtime/lifecycle/prepare-fresh-crs-source.sh', root=ROOT)
        makefile = (source_path('Makefile', root=ROOT)).read_text(encoding="utf-8")
        target_start = makefile.index("test-with-crs: check-framework prepare-runtime-components")
        target_end = makefile.index("\n\nmrts-generate:", target_start)
        target = makefile[target_start:target_end]

        self.assertIn("prepare-fresh-crs-source.sh", target)
        self.assertLess(
            target.index("prepare-fresh-crs-source.sh"),
            target.index("fetch-crs.sh"),
        )
        no_crs_start = makefile.index("test-no-crs: check-framework prepare-runtime-components")
        no_crs_end = makefile.index("\n\ntest-with-crs:", no_crs_start)
        self.assertNotIn("prepare-fresh-crs-source.sh", makefile[no_crs_start:no_crs_end])

        apache_start = makefile.index("verified-apache-case: check-framework prepare-runtime-components")
        apache_end = makefile.index("\n\nverified-haproxy-case:", apache_start)
        apache_target = makefile[apache_start:apache_end]
        self.assertIn('SOURCE_ROOT="$(SOURCE_ROOT)"', apache_target)
        self.assertIn('CRS_SOURCE_DIR="$(CRS_SOURCE_DIR)"', apache_target)

        haproxy_start = makefile.index("verified-haproxy-case: check-framework prepare-runtime-components")
        haproxy_end = makefile.index("\n\nverified-full-matrix-resume:", haproxy_start)
        haproxy_target = makefile[haproxy_start:haproxy_end]
        self.assertIn('SOURCE_ROOT="$${SOURCE_ROOT}"', haproxy_target)
        self.assertIn('CRS_SOURCE_DIR="$${CRS_SOURCE_DIR}"', haproxy_target)
        self.assertNotIn('SOURCE_ROOT="$(SOURCE_ROOT)"', haproxy_target)
        self.assertNotIn('CRS_SOURCE_DIR="$(CRS_SOURCE_DIR)"', haproxy_target)

        hostile_source_root = '/tmp/fresh"; printf injected >&2; #'
        hostile_crs_source = '/tmp/fresh/coreruleset"; printf injected >&2; #'
        forwarding = subprocess.run(
            [
                "sh",
                "-eu",
                "-c",
                'env SOURCE_ROOT="${SOURCE_ROOT}" CRS_SOURCE_DIR="${CRS_SOURCE_DIR}" '
                'sh -c \'printf "%s|%s" "$SOURCE_ROOT" "$CRS_SOURCE_DIR"\'',
            ],
            env={
                **os.environ,
                "SOURCE_ROOT": hostile_source_root,
                "CRS_SOURCE_DIR": hostile_crs_source,
            },
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(forwarding.returncode, 0, forwarding.stdout + forwarding.stderr)
        self.assertEqual(forwarding.stdout, f"{hostile_source_root}|{hostile_crs_source}")
        self.assertEqual(forwarding.stderr, "")

        with tempfile.TemporaryDirectory(prefix="fresh-crs-source-") as temporary:
            root = Path(temporary)
            verified_root = root / "verified"
            component_cache = verified_root / "component-cache"
            verified_root.mkdir(mode=0o700)
            component_cache.mkdir(mode=0o700)
            environment = {
                **os.environ,
                "CONNECTOR_ROOT": str(ROOT),
                "FRAMEWORK_ROOT": str(FRAMEWORK_ROOT),
                "REPO_ROOT": str(ROOT),
                "VERIFIED_RUN_ROOT": str(verified_root),
                "VERIFIED_SOURCE_ROOT": str(verified_root / "src"),
                "BUILD_ROOT": str(verified_root / "build"),
                "TMP_ROOT": str(verified_root / "tmp"),
                "LOG_ROOT": str(verified_root / "logs"),
                "CACHE_ROOT": str(verified_root / "cache-v2"),
                "VERIFIED_COMPONENT_CACHE": str(component_cache),
                "CONNECTOR_COMPONENT_CACHE": str(component_cache),
                # Model the cache-owned path emitted by the component snapshot.
                "SOURCE_ROOT": str(component_cache / "sources"),
                "CRS_SOURCE_DIR": str(component_cache / "sources" / "coreruleset"),
                "XDG_STATE_HOME": str(verified_root / "state"),
            }
            command = (
                '. "$1"; . "$2"; printf "%s|%s" "$SOURCE_ROOT" "$CRS_SOURCE_DIR"'
            )
            result = subprocess.run(
                [
                    "sh",
                    "-eu",
                    "-c",
                    command,
                    "sh",
                    str(FRAMEWORK_ROOT / "ci" / "lib" / "common.sh"),
                    str(helper),
                ],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            expected_root = verified_root / "crs-fresh-source"
            expected_source = expected_root / "coreruleset"
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout.rsplit("\n", 1)[-1], f"{expected_root}|{expected_source}")
            self.assertFalse(expected_root.exists())
            self.assertFalse(expected_source.exists())
            self.assertNotEqual(expected_root, component_cache)
            self.assertNotIn(f"{component_cache}/", f"{expected_root}/")

            expected_root.mkdir(mode=0o700)
            rejected = subprocess.run(
                [
                    "sh",
                    "-eu",
                    "-c",
                    '. "$1"; . "$2"',
                    "sh",
                    str(FRAMEWORK_ROOT / "ci" / "lib" / "common.sh"),
                    str(helper),
                ],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(rejected.returncode, 77, rejected.stdout + rejected.stderr)
            self.assertIn(
                "fresh CRS source root must not exist before fetch",
                rejected.stdout + rejected.stderr,
            )

    def test_with_crs_fresh_source_rejects_component_cache_overlap(self) -> None:
        helper = source_path('ci/runtime/lifecycle/prepare-fresh-crs-source.sh', root=ROOT)
        with tempfile.TemporaryDirectory(prefix="fresh-crs-source-") as temporary:
            root = Path(temporary)
            component_cache = root / "component-cache"
            component_cache.mkdir(mode=0o700)
            environment = {
                **os.environ,
                "CONNECTOR_ROOT": str(ROOT),
                "FRAMEWORK_ROOT": str(FRAMEWORK_ROOT),
                "REPO_ROOT": str(ROOT),
                "VERIFIED_RUN_ROOT": str(component_cache),
                "VERIFIED_SOURCE_ROOT": str(component_cache / "src"),
                "BUILD_ROOT": str(component_cache / "build"),
                "TMP_ROOT": str(component_cache / "tmp"),
                "LOG_ROOT": str(component_cache / "logs"),
                "CACHE_ROOT": str(component_cache / "cache-v2"),
                "VERIFIED_COMPONENT_CACHE": str(component_cache),
                "CONNECTOR_COMPONENT_CACHE": str(component_cache),
                "XDG_STATE_HOME": str(component_cache / "state"),
            }
            result = subprocess.run(
                [
                    "sh",
                    "-eu",
                    "-c",
                    '. "$1"; . "$2"',
                    "sh",
                    str(FRAMEWORK_ROOT / "ci" / "lib" / "common.sh"),
                    str(helper),
                ],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
            self.assertIn(
                "fresh CRS source root must not be inside CONNECTOR_COMPONENT_CACHE",
                result.stdout + result.stderr,
            )

    def test_make_does_not_materialize_an_empty_nginx_github_repo_alias(self) -> None:
        environment = self.trusted_framework_environment()
        environment.pop("NGINX_GITHUB_REPO", None)
        result = subprocess.run(
            [
                "make",
                "--no-print-directory",
                "--silent",
                "--eval=assert-nginx-github-repo-is-unset: ; @printenv NGINX_GITHUB_REPO >/dev/null; test $$? -eq 1; FRAMEWORK_ROOT=\"$$FRAMEWORK_ROOT\" NGINX_SOURCE_REPO_URL=https://github.com/nginx/nginx sh -eu -c '. \"$$FRAMEWORK_ROOT/ci/lib/common.sh\"; test \"$$NGINX_GITHUB_REPO\" = \"$$NGINX_SOURCE_REPO_URL\"'",
                "assert-nginx-github-repo-is-unset",
            ],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_make_prints_the_guarded_framework_apr_util_tuple_without_parent_overrides(self) -> None:
        environment = self.trusted_framework_environment()
        for variable in (
            "APR_UTIL_VERSION",
            "APR_UTIL_SOURCE_URL",
            "APR_UTIL_SHA256",
            "APR_UTIL_SHA256_URL",
        ):
            environment.pop(variable, None)
        result = subprocess.run(
            [
                "make",
                "--no-print-directory",
                "--silent",
                "framework-apr-util-env",
            ],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        values = dict(line.split("=", 1) for line in result.stdout.splitlines() if line)
        self.assertEqual(set(values), {
            "APR_UTIL_VERSION",
            "APR_UTIL_SOURCE_URL",
            "APR_UTIL_SHA256",
            "APR_UTIL_SHA256_URL",
        })
        unquoted = {key: value[1:-1] for key, value in values.items()}
        self.assertEqual(values["APR_UTIL_SOURCE_URL"], f"'{components.require_apr_util_pinned_provenance(unquoted)['APR_UTIL_SOURCE_URL']}'")

    def test_make_accepts_a_complete_canonical_apr_util_tuple(self) -> None:
        environment = self.trusted_framework_environment()
        for variable in components.FRAMEWORK_APR_UTIL_ENV_KEYS:
            environment.pop(variable, None)
        initial = subprocess.run(
            ["make", "--no-print-directory", "--silent", "framework-apr-util-env"],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(initial.returncode, 0, initial.stderr)
        canonical = {
            key: value[1:-1]
            for key, value in (
                line.split("=", 1) for line in initial.stdout.splitlines() if line
            )
        }
        inherited = dict(environment)
        inherited.update(canonical)
        repeated = subprocess.run(
            ["make", "--no-print-directory", "--silent", "framework-apr-util-env"],
            cwd=ROOT,
            env=inherited,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(repeated.returncode, 0, repeated.stderr)
        self.assertEqual(repeated.stdout, initial.stdout)

    def test_make_forwards_an_explicit_empty_apr_util_override_to_the_guard(self) -> None:
        for variable in (
            "APR_UTIL_VERSION",
            "APR_UTIL_SOURCE_URL",
            "APR_UTIL_SHA256",
            "APR_UTIL_SHA256_URL",
        ):
            with self.subTest(variable=variable):
                environment = self.trusted_framework_environment()
                environment[variable] = ""
                result = subprocess.run(
                    [
                        "make",
                        "--no-print-directory",
                        "--silent",
                        "framework-apr-util-env",
                    ],
                    cwd=ROOT,
                    env=environment,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertNotEqual(result.returncode, 0, result.stderr)
                self.assertIn(
                    "APR-util inherited tuple must set all four canonical fields or none",
                    result.stderr,
                )
                self.assertIn("Error 77", result.stderr)

    def test_make_forwards_a_mismatched_apr_util_override_to_the_guard(self) -> None:
        for variable in (
            "APR_UTIL_VERSION",
            "APR_UTIL_SOURCE_URL",
            "APR_UTIL_SHA256",
            "APR_UTIL_SHA256_URL",
        ):
            with self.subTest(variable=variable):
                environment = self.trusted_framework_environment()
                environment[variable] = "untrusted-value"
                result = subprocess.run(
                    [
                        "make",
                        "--no-print-directory",
                        "--silent",
                        "framework-apr-util-env",
                    ],
                    cwd=ROOT,
                    env=environment,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertNotEqual(result.returncode, 0, result.stderr)
                self.assertIn(
                    "APR-util inherited tuple must set all four canonical fields or none",
                    result.stderr,
                )
                self.assertIn("Error 77", result.stderr)

    def test_full_smoke_cleanup_is_opt_in_and_skipping_it_keeps_the_matrix_eligible(self) -> None:
        workflow = (source_path('.github/workflows/test-full-smoke-sequential.yml', root=ROOT)).read_text(
            encoding="utf-8"
        )
        dispatch_start = workflow.index("  workflow_dispatch:\n")
        permissions_start = workflow.index("\npermissions:", dispatch_start)
        dispatch = workflow[dispatch_start:permissions_start]
        cleanup_start = workflow.index("  cleanup-artifacts:\n")
        matrix_start = workflow.index("  manual-heavy-runtime-validation:\n", cleanup_start)
        cleanup_job = workflow[cleanup_start:matrix_start]
        matrix_job = workflow[matrix_start:]

        self.assertIn("cleanup_artifacts:\n", dispatch)
        self.assertIn("required: false", dispatch)
        self.assertIn("default: false", dispatch)
        self.assertIn("type: boolean", dispatch)
        self.assertIn("if: ${{ inputs.cleanup_artifacts }}", cleanup_job)
        self.assertIn("needs: cleanup-artifacts", matrix_job)
        self.assertIn("if: ${{ always() }}", matrix_job)

    def test_full_smoke_variants_use_isolated_verified_state_and_pycache_roots(self) -> None:
        workflow = (source_path('.github/workflows/test-full-smoke-sequential.yml', root=ROOT)).read_text(
            encoding="utf-8"
        )
        paths_start = workflow.index("      - name: Initialize paths\n")
        next_step = workflow.index("\n      - name: Lint and py-compile\n", paths_start)
        initialize_paths = workflow[paths_start:next_step]

        self.assertIn('functional_job_root="$(/usr/bin/sudo -n /usr/bin/mktemp -d /tmp/ModSecurity-conector-nginx-functional-root.XXXXXX)"', initialize_paths)
        for fragment in (
            'test "$(/usr/bin/stat -c \'%u:%g:%a\' "$functional_job_root")" = 0:0:700',
            '/usr/bin/sudo -n /bin/chmod 711 "$functional_job_root"',
            'test "$(/usr/bin/stat -c \'%u:%g:%a\' "$functional_job_root")" = 0:0:711',
            'verified_root="$functional_job_root/ModSecurity-conector-nginx-exact-head"',
            'functional_parent="$functional_job_root/ModSecurity-conector-nginx-functional-parent"',
            '/usr/bin/sudo -n /bin/chown "$runner_uid:$runner_gid" "$verified_root"',
            '/usr/bin/sudo -n /bin/chmod 700 "$verified_root"',
            'test "$(/usr/bin/stat -c \'%u:%g:%a\' "$verified_root")" = "$runner_uid:$runner_gid:700"',
            'test "$(/usr/bin/stat -c \'%u:%g:%a\' "$functional_parent")" = 0:0:711',
            'test "$worker_uid" -ne 0', 'test "$worker_gid" -ne 0',
            'echo "XDG_STATE_HOME=$verified_root/state"',
            'echo "PYTHONPYCACHEPREFIX=$verified_root/python-pycache"',
        ):
            self.assertIn(fragment, initialize_paths)
        guard = initialize_paths.split('if /usr/bin/sudo -n /usr/sbin/runuser -u "$NGINX_FUNCTIONAL_WORKER_USER" -- /usr/bin/test -x "$verified_root"; then', 1)[1].split('\n          fi', 1)[0]
        self.assertIn("exit 1", guard)
        self.assertNotIn('verified_root="$RUNNER_TEMP/ModSecurity-conector-verified"', initialize_paths)

    def test_legacy_collector_retains_current_normalized_result_without_cache_trees(self) -> None:
        workflow = (source_path('.github/workflows/open-connectors-smoke.yml', root=ROOT)).read_text()
        initialize = workflow.split("      - name: Initialize runtime paths\n", 1)[1].split("\n      - name:", 1)[0]
        self.assertIn('echo "RUNTIME_EVIDENCE_ROOT=$verified_root/evidence/runtime-evidence"', initialize)
        step = workflow.split("      - name: Collect smoke evidence\n", 1)[1].split("\n      - name:", 1)[0]
        shell = "\n".join(line[10:] for line in step.split("        run: |\n", 1)[1].splitlines())
        with tempfile.TemporaryDirectory(prefix="legacy-evidence-collector-") as temporary:
            base = Path(temporary)
            verified = base / "verified"
            evidence = verified / "evidence/runtime-evidence"
            result = evidence / "no-crs/parent/framework/traefik/run/result.json"
            result.parent.mkdir(parents=True)
            payload = {"connector": "traefik", "status": "FAIL", "host_version": "not_provisioned",
                       "pass_gate_failures": ["PASS requires a concrete host version"]}
            result.write_text(json.dumps(payload))
            for tree in ("component-cache", "src", "build/cache"):
                sentinel = verified / tree / "excluded-sentinel.txt"
                sentinel.parent.mkdir(parents=True, exist_ok=True)
                sentinel.write_text("must remain outside uploaded evidence")
            env = {**os.environ, "VERIFIED_RUN_ROOT": str(verified), "BUILD_ROOT": str(verified / "build"),
                   "LOG_ROOT": str(verified / "logs"), "RUNTIME_EVIDENCE_ROOT": str(evidence)}
            completed = subprocess.run(["sh", "-eu", "-c", shell], cwd=base, env=env,
                                       capture_output=True, text=True, timeout=30)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            bundle = base / "ci-artifacts/open-connectors"
            retained = bundle / "normalized-runtime-evidence/no-crs/parent/framework/traefik/run/result.json"
            self.assertEqual(json.loads(retained.read_text()), payload)
            self.assertFalse(list(bundle.rglob("excluded-sentinel.txt")))
            self.assertFalse((bundle / "README.txt").exists())




# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
