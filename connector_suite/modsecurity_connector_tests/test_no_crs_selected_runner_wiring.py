from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

from pathlib import Path
import os
import subprocess
import tempfile
import unittest


ROOT = connector_root()
CONSUMER = source_path('ci/runtime/lifecycle/consume-no-crs-selected-cases.sh', root=ROOT)


class NoCrsSelectedRunnerWiringTest(unittest.TestCase):
    def consume(self, connector: str, selected_cases: str) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["NO_CRS_SELECTED_CASES"] = selected_cases
        return subprocess.run(
            [str(CONSUMER), connector],
            cwd=ROOT,
            env=environment,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def test_consumer_requires_the_capability_selected_core_cases(self) -> None:
        result = self.consume("envoy", "allow_without_marker.yaml")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("deny_header_marker_403.yaml", result.stderr)

    def test_consumer_receipt_does_not_claim_unrun_selected_cases_passed(self) -> None:
        result = self.consume(
            "traefik",
            " ".join(
                (
                    "allow_without_marker.yaml",
                    "deny_header_marker_403.yaml",
                    "deny_with_alternative_status.yaml",
                    "transaction_id_present.yaml",
                    "log_only.yaml",
                )
            ),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("selected=", result.stdout)
        self.assertIn("unrun_selected_runner_cases=deny_with_alternative_status.yaml", result.stdout)
        self.assertNotIn("PASS", result.stdout)

    def test_consumer_accepts_the_canonical_full_lifecycle_namespace(self) -> None:
        result = self.consume(
            "lighttpd",
            " ".join(
                (
                    "allow_without_marker.yaml",
                    "deny_header_marker_403.yaml",
                    "full-lifecycle/phase3_deny_before_commit.yaml",
                )
            ),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("full-lifecycle/phase3_deny_before_commit.yaml", result.stdout)

    def test_consumer_rejects_full_lifecycle_traversal(self) -> None:
        result = self.consume(
            "lighttpd",
            "allow_without_marker.yaml deny_header_marker_403.yaml full-lifecycle/../escape.yaml",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsafe characters", result.stderr)

    def test_stage_rejects_missing_selected_cases_and_preserves_dispatch_controls(self) -> None:
        stage_runner = source_path('ci/runtime/lifecycle/run-connector-stage.sh', root=ROOT)
        missing_cases_message = "FAIL: capability-selected No-CRS runner cases are missing"
        with tempfile.TemporaryDirectory(prefix="msconnector-no-crs-stage-") as temporary_directory:
            temporary_root = Path(temporary_directory)
            framework_root = temporary_root / "framework"
            framework_common = framework_root / "ci" / "lib" / "common.sh"
            framework_common.parent.mkdir(parents=True)
            framework_common.write_text("# hermetic framework presence marker\n", encoding="utf-8")
            connector_root = temporary_root / "connector"
            target_runner = (
                connector_root
                / "ci"
                / "runtime"
                / "lifecycle"
                / "run-remaining-connector-target.sh"
            )
            target_runner.parent.mkdir(parents=True)
            target_runner.write_text(
                "#!/bin/sh\n"
                "printf 'target=%s connector=%s selected=%s\\n' \"$2\" \"$1\" \"${NO_CRS_SELECTED_CASES:-}\"\n",
                encoding="utf-8",
            )
            environment = os.environ.copy()
            environment.update(
                {
                    "CONNECTOR_ROOT": str(connector_root),
                    "FRAMEWORK_ROOT": str(framework_root),
                    "VERIFIED_RUN_ROOT": str(temporary_root / "verified"),
                    "BUILD_ROOT": str(temporary_root / "build"),
                    "NO_CRS_ARTIFACT_PROFILE": "generic",
                }
            )
            environment.pop("NO_CRS_SELECTED_CASES", None)

            for connector in ("haproxy", "apache", "nginx", "envoy", "traefik", "lighttpd"):
                with self.subTest(connector=connector):
                    result = subprocess.run(
                        ["sh", str(stage_runner), connector, "no_crs_baseline"],
                        cwd=ROOT,
                        env=environment,
                        check=False,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(result.stderr, f"{missing_cases_message}\n")

            generic_environment = environment.copy()
            generic_environment["NO_CRS_SELECTED_CASES"] = "allow_without_marker.yaml"
            generic_result = subprocess.run(
                ["sh", str(stage_runner), "envoy", "no_crs_baseline"],
                cwd=ROOT,
                env=generic_environment,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(generic_result.returncode, 0, generic_result.stderr)
            self.assertEqual(generic_result.stderr, "")
            self.assertEqual(
                generic_result.stdout,
                "target=no-crs-baseline-envoy connector=envoy selected=allow_without_marker.yaml\n",
            )

            full_lifecycle_environment = environment.copy()
            full_lifecycle_environment.update(
                {
                    "NO_CRS_ARTIFACT_PROFILE": "full_lifecycle",
                    "FULL_LIFECYCLE_HOST_PROFILE": "ext_proc",
                    "FULL_LIFECYCLE_EXECUTED_TARGET": "full-lifecycle-envoy-ext-proc",
                }
            )
            full_lifecycle_result = subprocess.run(
                ["sh", str(stage_runner), "envoy", "no_crs_baseline"],
                cwd=ROOT,
                env=full_lifecycle_environment,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(full_lifecycle_result.returncode, 0, full_lifecycle_result.stderr)
            self.assertEqual(full_lifecycle_result.stderr, "")
            self.assertEqual(
                full_lifecycle_result.stdout,
                "target=runtime-smoke-envoy-ext-proc connector=envoy selected=\n",
            )

    def test_closed_profile_rejects_future_profiles_and_nginx_before_runtime_setup(self) -> None:
        runner = source_path('ci/runtime/lifecycle/run-no-crs-baseline.sh', root=ROOT)
        with tempfile.TemporaryDirectory(prefix="msconnector-closed-profile-") as temporary:
            temporary_root = Path(temporary)
            for connector, profile, expected_error in (
                ("apache", "with-crs", "invalid choice"),
                ("nginx", "no-crs", "closed no-crs profile"),
            ):
                with self.subTest(connector=connector, profile=profile):
                    environment = os.environ.copy()
                    environment.update(
                        {
                            "CONNECTOR_ROOT": str(ROOT),
                            "FRAMEWORK_ROOT": str(temporary_root / "missing-framework"),
                            "FIVE_CONNECTOR_PROFILE": profile,
                            "NO_CRS_ARTIFACT_PROFILE": "generic",
                            "NO_CRS_RUN_ID": "closed-profile-101",
                            "VERIFIED_RUN_ROOT": str(temporary_root / f"verified-{connector}"),
                        }
                    )
                    result = subprocess.run(
                        ["sh", str(runner), connector, "minimal_runtime_smoke"],
                        cwd=ROOT,
                        env=environment,
                        check=False,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn(expected_error, result.stderr)
                    self.assertFalse(
                        Path(environment["VERIFIED_RUN_ROOT"]).exists(),
                        "closed-profile rejection must precede runtime root creation",
                    )

    def test_closed_profile_stage_uses_the_resolver_canonical_capability_manifest(self) -> None:
        stage_runner = source_path('ci/runtime/lifecycle/run-connector-stage.sh', root=ROOT)
        with tempfile.TemporaryDirectory(prefix="msconnector-closed-profile-stage-") as temporary:
            temporary_root = Path(temporary)
            connector_root = temporary_root / "connector"
            connector_root.mkdir()
            (connector_root / "ci").symlink_to(source_path('ci', root=ROOT), target_is_directory=True)
            framework_common = temporary_root / "framework" / "ci" / "lib" / "common.sh"
            framework_common.parent.mkdir(parents=True)
            framework_common.write_text("# hermetic framework presence marker\n", encoding="utf-8")
            environment = os.environ.copy()
            environment.update(
                {
                    "CONNECTOR_ROOT": str(connector_root),
                    "FRAMEWORK_ROOT": str(temporary_root / "framework"),
                    "VERIFIED_RUN_ROOT": str(temporary_root / "verified"),
                    "FIVE_CONNECTOR_PROFILE": "no-crs",
                    "NO_CRS_ARTIFACT_PROFILE": "generic",
                }
            )
            environment.pop("NO_CRS_SELECTED_CASES", None)
            result = subprocess.run(
                ["sh", str(stage_runner), "apache", "no_crs_baseline"],
                cwd=ROOT,
                env=environment,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertEqual(
            result.stderr,
            "FAIL: capability-selected No-CRS runner cases are missing\n",
        )

    def test_remaining_connectors_keep_compatibility_and_native_targets_distinct(self) -> None:
        stage = (source_path('ci/runtime/lifecycle/run-connector-stage.sh', root=ROOT)).read_text(encoding="utf-8")
        for connector, native_target, compatibility_target in (
            ("envoy", "runtime-smoke-envoy-ext-proc", "no-crs-baseline-envoy"),
            ("traefik", "runtime-smoke-traefik-native", "no-crs-baseline-traefik"),
            ("lighttpd", "runtime-smoke-lighttpd-patched", "no-crs-baseline-lighttpd"),
        ):
            with self.subTest(connector=connector):
                self.assertIn(f"{connector}:no_crs_baseline)", stage)
                self.assertIn(f"run_remaining_connector {native_target}", stage)
                self.assertIn(f"run_remaining_connector {compatibility_target}", stage)
        self.assertIn("run_full_lifecycle_haproxy_htx", stage)
        self.assertIn("runtime-smoke-haproxy-htx", stage)
        self.assertNotIn("compatibility SPOE/SPOP runner is forbidden", stage)
        self.assertIn("capability-selected No-CRS runner cases are missing", stage)

        target_runner = (source_path('ci/runtime/lifecycle/run-remaining-connector-target.sh', root=ROOT)).read_text(
            encoding="utf-8"
        )
        self.assertIn("no-crs-baseline-*", target_runner)
        self.assertIn("EXT_PROC_RUNTIME_ROOT", target_runner)
        self.assertIn("TRAEFIK_NATIVE_RUNTIME_ROOT", target_runner)
        self.assertNotIn('TRAEFIK_ENGINE_SOCKET_PARENT="${TRAEFIK_ENGINE_SOCKET_PARENT:-}"', target_runner)
        self.assertNotIn('TRAEFIK_BIN="$TRAEFIK_BIN"', target_runner)
        self.assertNotIn(
            'TRAEFIK_NATIVE_RUNTIME_ROOT="$traefik_native_runtime_root"',
            target_runner,
        )
        self.assertIn("export TRAEFIK_BIN TRAEFIK_NATIVE_RUNTIME_ROOT", target_runner)
        self.assertIn(
            "export MODSECURITY_INCLUDE_DIR MODSECURITY_LIB_DIR MODSECURITY_PREFIX",
            target_runner,
        )
        for variable in (
            "BUILD_ROOT",
            "MODSECURITY_INCLUDE_DIR",
            "MODSECURITY_LIB_DIR",
            "MODSECURITY_PREFIX",
        ):
            with self.subTest(lifecycle_environment_variable=variable):
                self.assertNotIn(f'{variable}="${{{variable}}}"', target_runner)
        self.assertIn("LIGHTTPD_PATCHED_SMOKE_DIR", target_runner)

        self.assertIn(
            'TRAEFIK_ENGINE_SOCKET_PARENT="${TRAEFIK_ENGINE_SOCKET_PARENT:-}"',
            stage,
        )
        native_makefile = (source_path('connectors/traefik/Makefile', root=ROOT)).read_text(encoding="utf-8")
        native_recipe = native_makefile.split("runtime-smoke-traefik-native:\n", 1)[1].split(
            "\n\nno-crs-baseline-traefik",
            1,
        )[0]
        for variable in (
            "TRAEFIK_BIN",
            "TRAEFIK_NATIVE_RUNTIME_ROOT",
            "TRAEFIK_ENGINE_SOCKET_PARENT",
            "TRAEFIK_ENGINE_SOCKET_TEST_PARENT",
            "PYTHON",
            "BUILD_ROOT",
            "MODSECURITY_INCLUDE_DIR",
            "MODSECURITY_LIB_DIR",
            "MODSECURITY_PREFIX",
        ):
            with self.subTest(variable=variable):
                self.assertIn(f"override {variable} := $(value {variable})", native_makefile)
                self.assertNotIn(f'{variable}="$({variable})"', native_recipe)
        self.assertIn(
            "ifeq ($(origin TRAEFIK_NATIVE_RUNTIME_ROOT), undefined)",
            native_makefile,
        )
        self.assertIn(
            "TRAEFIK_NATIVE_RUNTIME_ROOT := $(value BUILD_ROOT)/traefik-native-middleware/runtime-smoke",
            native_makefile,
        )
        self.assertIn("override BUILD_ROOT := $(value BUILD_ROOT)", native_makefile)
        self.assertIn(
            "export BUILD_ROOT MODSECURITY_INCLUDE_DIR MODSECURITY_LIB_DIR MODSECURITY_PREFIX",
            native_makefile,
        )
        self.assertIn(
            "export TRAEFIK_BIN TRAEFIK_NATIVE_RUNTIME_ROOT TRAEFIK_ENGINE_SOCKET_PARENT TRAEFIK_ENGINE_SOCKET_TEST_PARENT PYTHON",
            native_makefile,
        )
        self.assertEqual(native_recipe, "\tsh scripts/runtime-native-middleware.sh")
        engine_service_recipe = native_makefile.split("test-engine-service:\n", 1)[1].split(
            "\n\nclean:",
            1,
        )[0]
        self.assertNotIn('PYTHON="$(PYTHON)"', engine_service_recipe)
        self.assertEqual(
            engine_service_recipe,
            "\tbuild/build-engine-service.sh test\n\tbuild/test-engine-service-runtime.sh",
        )
        temporary_directory = tempfile.TemporaryDirectory(
            prefix="msconnector-traefik-make-values-"
        )
        self.addCleanup(temporary_directory.cleanup)
        temporary_root = Path(temporary_directory.name)
        safe_parent = str(temporary_root / "traefik-private-parent")
        show_exported_parent = (
            "--eval=show-exported-parent:; @printf '%s\\n' \"$$TRAEFIK_ENGINE_SOCKET_PARENT\""
        )
        exported_parent = subprocess.run(
            [
                "make",
                "-s",
                "-C",
                str(source_path('connectors/traefik', root=ROOT)),
                show_exported_parent,
                f"TRAEFIK_ENGINE_SOCKET_PARENT={safe_parent}",
                "show-exported-parent",
            ],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(exported_parent.returncode, 0, exported_parent.stderr)
        self.assertEqual(safe_parent, exported_parent.stdout.strip())
        expected_build_root = str(temporary_root / "expected-traefik-build-root")
        show_exported_default_root = (
            "--eval=show-exported-default-root:; @printf '%s\\n' \"$$TRAEFIK_NATIVE_RUNTIME_ROOT\""
        )
        default_environment = os.environ.copy()
        default_environment.pop("TRAEFIK_NATIVE_RUNTIME_ROOT", None)
        exported_default_root = subprocess.run(
            [
                "make",
                "-s",
                "-C",
                str(source_path('connectors/traefik', root=ROOT)),
                f"BUILD_ROOT={expected_build_root}",
                show_exported_default_root,
                "show-exported-default-root",
            ],
            cwd=ROOT,
            env=default_environment,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(exported_default_root.returncode, 0, exported_default_root.stderr)
        self.assertEqual(
            exported_default_root.stdout.strip(),
            f"{expected_build_root}/traefik-native-middleware/runtime-smoke",
        )
        hostile_build_root = (
            f"{temporary_root}/$(shell printf BUILD_ROOT_MAKE_INJECTION_REACHED >&2)"
        )
        hostile_default_root = subprocess.run(
            [
                "make",
                "-s",
                "-C",
                str(source_path('connectors/traefik', root=ROOT)),
                f"BUILD_ROOT={hostile_build_root}",
                show_exported_default_root,
                "show-exported-default-root",
            ],
            cwd=ROOT,
            env=default_environment,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(hostile_default_root.returncode, 0, hostile_default_root.stderr)
        self.assertEqual(
            hostile_default_root.stdout.strip(),
            f"{hostile_build_root}/traefik-native-middleware/runtime-smoke",
        )
        self.assertNotIn("BUILD_ROOT_MAKE_INJECTION_REACHED", hostile_default_root.stderr)
        make_function_values = (
            (
                "TRAEFIK_BIN",
                f"{temporary_root}/$(shell printf MAKE_BIN_INJECTION_REACHED >&2)",
            ),
            (
                "TRAEFIK_NATIVE_RUNTIME_ROOT",
                f"{temporary_root}/$(shell printf MAKE_ROOT_INJECTION_REACHED >&2)",
            ),
            (
                "TRAEFIK_ENGINE_SOCKET_PARENT",
                f"{temporary_root}/$(shell printf MAKE_PARENT_INJECTION_REACHED >&2)",
            ),
            (
                "TRAEFIK_ENGINE_SOCKET_TEST_PARENT",
                f"{temporary_root}/$(shell printf MAKE_TEST_PARENT_INJECTION_REACHED >&2)",
            ),
            (
                "PYTHON",
                f"{temporary_root}/$(shell printf MAKE_PYTHON_INJECTION_REACHED >&2)",
            ),
            (
                "MODSECURITY_INCLUDE_DIR",
                f"{temporary_root}/$(shell printf MAKE_INCLUDE_INJECTION_REACHED >&2)",
            ),
            (
                "MODSECURITY_LIB_DIR",
                f"{temporary_root}/$(shell printf MAKE_LIBRARY_INJECTION_REACHED >&2)",
            ),
            (
                "MODSECURITY_PREFIX",
                f"{temporary_root}/$(shell printf MAKE_PREFIX_INJECTION_REACHED >&2)",
            ),
        )
        show_exported_values = (
            "--eval=show-exported-values:; @printf '%s\\n' \"$$TRAEFIK_BIN\"; "
            "printf '%s\\n' \"$$TRAEFIK_NATIVE_RUNTIME_ROOT\"; "
            "printf '%s\\n' \"$$TRAEFIK_ENGINE_SOCKET_PARENT\"; "
            "printf '%s\\n' \"$$TRAEFIK_ENGINE_SOCKET_TEST_PARENT\"; "
            "printf '%s\\n' \"$$PYTHON\"; "
            "printf '%s\\n' \"$$MODSECURITY_INCLUDE_DIR\"; "
            "printf '%s\\n' \"$$MODSECURITY_LIB_DIR\"; "
            "printf '%s\\n' \"$$MODSECURITY_PREFIX\""
        )
        function_command = [
            "make",
            "-s",
            "-C",
            str(source_path('connectors/traefik', root=ROOT)),
            show_exported_values,
        ]
        function_command.extend(
            f"{variable}={value}" for variable, value in make_function_values
        )
        function_command.append("show-exported-values")
        function_values = subprocess.run(
            function_command,
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(function_values.returncode, 0, function_values.stderr)
        self.assertEqual(
            [value for _, value in make_function_values],
            function_values.stdout.splitlines(),
        )
        for marker in (
            "MAKE_BIN_INJECTION_REACHED",
            "MAKE_ROOT_INJECTION_REACHED",
            "MAKE_PARENT_INJECTION_REACHED",
            "MAKE_TEST_PARENT_INJECTION_REACHED",
            "MAKE_PYTHON_INJECTION_REACHED",
            "MAKE_INCLUDE_INJECTION_REACHED",
            "MAKE_LIBRARY_INJECTION_REACHED",
            "MAKE_PREFIX_INJECTION_REACHED",
        ):
            self.assertNotIn(marker, function_values.stderr)
        python_recipe_payload = (
            f'{temporary_root}/unsafe"; printf PYTHON_RECIPE_INJECTION_REACHED; #'
        )
        engine_service_dry_run = subprocess.run(
            [
                "make",
                "-n",
                "-C",
                str(source_path('connectors/traefik', root=ROOT)),
                f"PYTHON={python_recipe_payload}",
                "test-engine-service",
            ],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        engine_service_output = engine_service_dry_run.stdout + engine_service_dry_run.stderr
        self.assertEqual(engine_service_dry_run.returncode, 0, engine_service_output)
        self.assertNotIn("PYTHON_RECIPE_INJECTION_REACHED", engine_service_output)
        self.assertNotIn(python_recipe_payload, engine_service_output)
        with tempfile.TemporaryDirectory(prefix="msconnector-traefik-make-test-") as temporary:
            runtime_root = Path(temporary) / "runtime"
            shell_sentinel = Path(temporary) / "shell-injection-sentinel"
            injected_parent = f'{Path(temporary) / "unsafe"}"; : > "{shell_sentinel}"; #'
            native_make_dry_run = subprocess.run(
                [
                    "make",
                    "-n",
                    "-C",
                    str(source_path('connectors/traefik', root=ROOT)),
                    "TRAEFIK_BIN=/bin/true",
                    f"TRAEFIK_NATIVE_RUNTIME_ROOT={runtime_root}",
                    f"TRAEFIK_ENGINE_SOCKET_PARENT={injected_parent}",
                    "runtime-smoke-traefik-native",
                ],
                cwd=ROOT,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(native_make_dry_run.returncode, 0, native_make_dry_run.stderr)
            self.assertFalse(shell_sentinel.exists())
            native_make_runtime = subprocess.run(
                [
                    "make",
                    "-s",
                    "-C",
                    str(source_path('connectors/traefik', root=ROOT)),
                    "TRAEFIK_BIN=/bin/true",
                    f"TRAEFIK_NATIVE_RUNTIME_ROOT={runtime_root}",
                    f"TRAEFIK_ENGINE_SOCKET_PARENT={injected_parent}",
                    "runtime-smoke-traefik-native",
                ],
                cwd=ROOT,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            native_make_output = native_make_runtime.stdout + native_make_runtime.stderr
            self.assertEqual(native_make_runtime.returncode, 2, native_make_output)
            self.assertIn("BLOCKED: TRAEFIK_ENGINE_SOCKET_PARENT is unavailable", native_make_output)
            self.assertIn("Error 77", native_make_output)
            self.assertIn(injected_parent, native_make_output)
            self.assertFalse(shell_sentinel.exists())
            self.assertFalse(runtime_root.exists())
        self.assertNotIn("traefik-engine-socket-parent.XXXXXX", target_runner)

    def test_each_connector_baseline_target_enables_the_selection_consumer(self) -> None:
        contracts = {
            "envoy": (
                source_path('connectors/envoy/Makefile', root=ROOT),
                source_path('connectors/envoy/harness/run_envoy_connector_runtime.sh', root=ROOT),
                "no-crs-baseline-envoy",
            ),
            "traefik": (
                source_path('connectors/traefik/Makefile', root=ROOT),
                source_path('connectors/traefik/scripts/runtime_smoke.py', root=ROOT),
                "no-crs-baseline-traefik",
            ),
            "lighttpd": (
                source_path('connectors/lighttpd/Makefile', root=ROOT),
                source_path('connectors/lighttpd/harness/runtime_lighttpd_smoke.sh', root=ROOT),
                "no-crs-baseline-lighttpd",
            ),
        }
        for connector, (makefile, harness, target) in contracts.items():
            with self.subTest(connector=connector):
                make_text = makefile.read_text(encoding="utf-8")
                harness_text = harness.read_text(encoding="utf-8")
                self.assertIn(f"{target}: export MSCONNECTOR_NO_CRS_BASELINE := 1", make_text)
                self.assertIn("consume-no-crs-selected-cases.sh", harness_text)

    def test_apache_maps_selected_late_phase4_cases_to_real_host_fixtures(self) -> None:
        harness = (
            source_path('connectors/apache/harness/run_apache_smoke.sh', root=ROOT)
        ).read_text(encoding="utf-8")
        self.assertIn("append_selected_phase4_fixtures", harness)
        self.assertIn("phase4_deny_after_commit_log_only", harness)
        self.assertIn("apache_phase4_deny_after_commit_log_only", harness)
        self.assertIn("phase4_deny_after_commit_abort", harness)
        self.assertIn("apache_phase4_deny_after_commit_abort", harness)
        for fixture in (
            "apache_phase4_deny_after_commit_log_only.yaml",
            "apache_phase4_deny_after_commit_abort.yaml",
        ):
            with self.subTest(fixture=fixture):
                self.assertTrue(
                    (
                        source_path('modules/ModSecurity-test-Framework/tests/cases/connector-specific/apache', root=ROOT)
                        / fixture
                    ).is_file()
                )

    def test_lighttpd_runner_uses_the_checkout_root_and_haproxy_preserves_status(self) -> None:
        lighttpd_harness = (
            source_path('connectors/lighttpd/harness/runtime_lighttpd_smoke.sh', root=ROOT)
        ).read_text(encoding="utf-8")
        self.assertIn('cd "$SCRIPT_DIR/../../.."', lighttpd_harness)

        haproxy_harness = (
            source_path('connectors/haproxy/harness/run_haproxy_smoke.sh', root=ROOT)
        ).read_text(encoding="utf-8")
        for scope in ("http-request", "http-response"):
            status_429 = haproxy_harness.index(
                f"{scope} deny status 429 if {{ var(txn.modsec.status) -m int 429 }}"
            )
            fallback_403 = haproxy_harness.index(
                f"{scope} deny status 403 if {{ var(txn.modsec.blocked) -m bool }}"
            )
            self.assertLess(status_429, fallback_403)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
